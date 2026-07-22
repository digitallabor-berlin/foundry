//! X.509 parsing, inspection, and (DN-based) trust-path validation.

use crate::error::TrustError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;

pub use x509_cert::Certificate;

/// Parse a single PEM-encoded certificate.
pub fn parse_cert_pem(pem: &[u8]) -> Result<Certificate, TrustError> {
    Certificate::from_pem(pem).map_err(|e| TrustError::Parse(e.to_string()))
}

/// A certificate is self-signed when its subject DN equals its issuer DN.
pub fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate().subject() == cert.tbs_certificate().issuer()
}

/// (not_before, not_after) as unix seconds.
pub fn validity_window(cert: &Certificate) -> (u64, u64) {
    let validity = cert.tbs_certificate().validity();
    (
        validity.not_before.to_unix_duration().as_secs(),
        validity.not_after.to_unix_duration().as_secs(),
    )
}

/// All dNSName entries from the SubjectAltName extension (empty if none).
pub fn san_dns_names(cert: &Certificate) -> Result<Vec<String>, TrustError> {
    let mut names = Vec::new();
    if let Some(extensions) = cert.tbs_certificate().extensions() {
        for ext in extensions.iter() {
            if ext.extn_id == SubjectAltName::OID {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| TrustError::Parse(e.to_string()))?;
                for name in san.0.iter() {
                    if let GeneralName::DnsName(dns) = name {
                        names.push(dns.to_string());
                    }
                }
            }
        }
    }
    Ok(names)
}

/// Build an `x5c` array (base64 DER per cert). Order is preserved:
/// callers pass leaf..intermediate (trust anchor excluded) per HAIP §6.1.1.
pub fn build_x5c(chain_pems: &[Vec<u8>]) -> Result<Vec<String>, TrustError> {
    if chain_pems.is_empty() {
        return Err(TrustError::EmptyChain);
    }
    let mut out = Vec::with_capacity(chain_pems.len());
    for pem in chain_pems {
        let cert = parse_cert_pem(pem)?;
        let der = cert
            .to_der()
            .map_err(|e| TrustError::Parse(e.to_string()))?;
        out.push(B64.encode(&der));
    }
    Ok(out)
}

/// Rebuild a PEM certificate from a single `x5c` entry (base64-STANDARD DER),
/// as found in a JOSE header per RFC 7515 §4.1.6.
pub fn x5c_entry_to_pem(standard_b64: &str) -> Result<Vec<u8>, TrustError> {
    let der = B64
        .decode(standard_b64)
        .map_err(|e| TrustError::Parse(format!("x5c base64 decode: {e}")))?;
    let re_b64 = B64.encode(&der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut i = 0;
    while i < re_b64.len() {
        let end = (i + 64).min(re_b64.len());
        pem.push_str(&re_b64[i..end]);
        pem.push('\n');
        i = end;
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem.into_bytes())
}

/// A set of trust-anchor certificates.
pub struct TrustStore {
    anchors: Vec<Certificate>,
}

impl TrustStore {
    pub fn from_pems(pems: &[Vec<u8>]) -> Result<Self, TrustError> {
        let mut anchors = Vec::with_capacity(pems.len());
        for pem in pems {
            anchors.push(parse_cert_pem(pem)?);
        }
        Ok(Self { anchors })
    }

    pub fn from_config(anchors: &[crate::config::TrustAnchor]) -> Result<Self, TrustError> {
        let mut pems = Vec::new();
        for anchor in anchors {
            for block in anchor.certs.split("-----BEGIN CERTIFICATE-----") {
                let trimmed = block.trim();
                if !trimmed.is_empty() {
                    let pem = format!("-----BEGIN CERTIFICATE-----\n{}", trimmed);
                    pems.push(pem.into_bytes());
                }
            }
        }
        Self::from_pems(&pems)
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

fn assert_in_window(cert: &Certificate, now_unix: u64) -> Result<(), TrustError> {
    let (nb, na) = validity_window(cert);
    if now_unix < nb || now_unix > na {
        return Err(TrustError::Expired);
    }
    Ok(())
}

/// Validate a leaf (+ optional intermediates) against the trust store.
///
/// v1 scope: reject self-signed leaf, check validity windows, and build a
/// DN-based path from the leaf up to a configured anchor.
/// TODO(trust-hardening): x509-cert 0.3 cannot verify signatures. A later pass
/// MUST cryptographically verify each link (issuer SPKI over tbs_certificate)
/// via rustls-webpki or p256/ecdsa. This function's signature will not change.
pub fn validate_chain(
    leaf_pem: &[u8],
    intermediates: &[Vec<u8>],
    store: &TrustStore,
    now_unix: u64,
) -> Result<(), TrustError> {
    let leaf = parse_cert_pem(leaf_pem)?;
    if is_self_signed(&leaf) {
        return Err(TrustError::SelfSignedLeaf);
    }
    assert_in_window(&leaf, now_unix)?;

    let mut inter_parsed = Vec::with_capacity(intermediates.len());
    for pem in intermediates {
        inter_parsed.push(parse_cert_pem(pem)?);
    }

    // Walk from the leaf's issuer DN upward through intermediates.
    let mut current_issuer = leaf.tbs_certificate().issuer().clone();
    for inter in &inter_parsed {
        if inter.tbs_certificate().subject() == &current_issuer {
            assert_in_window(inter, now_unix)?;
            current_issuer = inter.tbs_certificate().issuer().clone();
        }
    }

    // The remaining issuer DN must match a trust anchor's subject.
    for anchor in &store.anchors {
        if anchor.tbs_certificate().subject() == &current_issuer {
            assert_in_window(anchor, now_unix)?;
            return Ok(());
        }
    }

    Err(TrustError::UntrustedChain)
}

/// Whether the leaf certificate asserts `expected_dns` as a dNSName SAN.
pub fn match_san_dns(leaf_pem: &[u8], expected_dns: &str) -> Result<bool, TrustError> {
    let leaf = parse_cert_pem(leaf_pem)?;
    Ok(san_dns_names(&leaf)?.iter().any(|n| n == expected_dns))
}

/// Raw (x, y) EC public-key coordinates from a certificate's SubjectPublicKeyInfo.
/// Assumes an uncompressed EC point (0x04 || X || Y), which is what this
/// project's ECDSA (P-256/384/521) certificates carry.
pub fn cert_ec_public_coords(cert: &Certificate) -> Result<(Vec<u8>, Vec<u8>), TrustError> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| TrustError::Parse("SPKI bit string not byte-aligned".into()))?;
    if point.first() != Some(&0x04) {
        return Err(TrustError::Parse(
            "expected uncompressed EC point (0x04 prefix)".into(),
        ));
    }
    let coord_len = (point.len() - 1) / 2;
    let x = point[1..1 + coord_len].to_vec();
    let y = point[1 + coord_len..].to_vec();
    Ok((x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBgTCCASagAwIBAgIUMuXzxAQ2jbmV3Vl23cKzyjjrQXswCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTRm91bmRyeSBEZXYgUm9vdCBDQTAeFw0yNjA3MjAwOTMyMzBa
Fw0zNjA3MTcwOTMyMzBaMB4xHDAaBgNVBAMME0ZvdW5kcnkgRGV2IFJvb3QgQ0Ew
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQX5bSK9rymRHCiOHPFqYxAFMWMibvT
83zroR2k3euLLkzBlUHndEKBVlesake2CdC0+eD+Sn5jIVtAEcd1QJUBo0IwQDAO
BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFOh1OqjnYe/4I4EdxK3uwbJ5xE4WMA8G
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAJRps/NQx/LiLodmMHnx
/hEpxeuUJbNw9hL5cRskcp7cAiEAm4XCO5qfzHVm+DT1uFcKPcSRZx3VstuUjW70
Hx2Z6f4=
-----END CERTIFICATE-----
";

    const LEAF_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBajCCARCgAwIBAgIURWe+XknN8BJ1cxSddzvuo58nky8wCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTRm91bmRyeSBEZXYgUm9vdCBDQTAeFw0yNjA3MjAwOTMyMzBa
Fw0zNjA3MTcwOTMyMzBaMBsxGTAXBgNVBAMMEGlzc3Vlci5kZXYubG9jYWwwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAATl55Pkho1O7vCodjCN5Pg0bLD0Enq2NHB+
CQtZzhVZZ2J9pnrpNhec+4pvhEiSoDnHbDO1hCVo9j7Y6MLy2pbJoy8wLTAbBgNV
HREEFDASghBpc3N1ZXIuZGV2LmxvY2FsMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjO
PQQDAgNIADBFAiAiUDy4sT+j71gmXiB4w+UOhfaA02IuOiuwqdRflDGd2wIhAILW
vP5vWUL28PymIi7FZin3ExljHeW+S4QiHVbOkeJ0
-----END CERTIFICATE-----
";

    #[test]
    fn parses_and_detects_self_signed_ca() {
        let ca = parse_cert_pem(CA_CERT_PEM).unwrap();
        assert!(is_self_signed(&ca));
    }

    #[test]
    fn leaf_is_not_self_signed_and_links_to_ca() {
        let ca = parse_cert_pem(CA_CERT_PEM).unwrap();
        let leaf = parse_cert_pem(LEAF_CERT_PEM).unwrap();
        assert!(!is_self_signed(&leaf));
        // leaf.issuer == ca.subject → genuine CA-signed chain link
        assert_eq!(
            leaf.tbs_certificate().issuer(),
            ca.tbs_certificate().subject()
        );
    }

    #[test]
    fn extracts_san_dns_names() {
        let leaf = parse_cert_pem(LEAF_CERT_PEM).unwrap();
        let names = san_dns_names(&leaf).unwrap();
        assert_eq!(names, vec!["issuer.dev.local".to_string()]);
    }

    #[test]
    fn validity_window_is_ordered() {
        let leaf = parse_cert_pem(LEAF_CERT_PEM).unwrap();
        let (nb, na) = validity_window(&leaf);
        assert!(nb < na);
    }

    #[test]
    fn rejects_garbage_pem() {
        let err = parse_cert_pem(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
            .unwrap_err();
        assert!(matches!(err, crate::error::TrustError::Parse(_)));
    }

    use crate::pki::{issue_leaf, new_ca};

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn build_x5c_encodes_each_cert() {
        let x5c = build_x5c(&[LEAF_CERT_PEM.to_vec()]).unwrap();
        assert_eq!(x5c.len(), 1);
        // Valid base64 that decodes to non-empty DER.
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let der = B64.decode(&x5c[0]).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn build_x5c_rejects_empty() {
        let err = build_x5c(&[]).unwrap_err();
        assert!(matches!(err, crate::error::TrustError::EmptyChain));
    }

    #[test]
    fn valid_leaf_against_anchor_passes() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "issuer.dev.local",
            &["issuer.dev.local".to_string()],
            365,
        )
        .unwrap();
        let store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        assert!(!store.is_empty());
        validate_chain(leaf.cert_pem.as_bytes(), &[], &store, now_secs()).unwrap();
    }

    #[test]
    fn self_signed_leaf_is_rejected() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let store = TrustStore::from_pems(&[ca.cert_pem.clone().into_bytes()]).unwrap();
        // Feed the self-signed CA as if it were the leaf.
        let err = validate_chain(ca.cert_pem.as_bytes(), &[], &store, now_secs()).unwrap_err();
        assert!(matches!(err, crate::error::TrustError::SelfSignedLeaf));
    }

    #[test]
    fn expired_leaf_is_rejected() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "issuer.dev.local",
            &["issuer.dev.local".to_string()],
            365,
        )
        .unwrap();
        let store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        // now far in the future → outside the 365-day window.
        let future = now_secs() + 400 * 24 * 3600;
        let err = validate_chain(leaf.cert_pem.as_bytes(), &[], &store, future).unwrap_err();
        assert!(matches!(err, crate::error::TrustError::Expired));
    }

    #[test]
    fn untrusted_anchor_is_rejected() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "issuer.dev.local",
            &["issuer.dev.local".to_string()],
            365,
        )
        .unwrap();
        let other = new_ca("Some Other CA", 3650).unwrap();
        let store = TrustStore::from_pems(&[other.cert_pem.into_bytes()]).unwrap();
        let err = validate_chain(leaf.cert_pem.as_bytes(), &[], &store, now_secs()).unwrap_err();
        assert!(matches!(err, crate::error::TrustError::UntrustedChain));
    }

    #[test]
    fn san_matching_works() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "issuer.dev.local",
            &["issuer.dev.local".to_string()],
            365,
        )
        .unwrap();
        assert!(match_san_dns(leaf.cert_pem.as_bytes(), "issuer.dev.local").unwrap());
        assert!(!match_san_dns(leaf.cert_pem.as_bytes(), "attacker.example.com").unwrap());
    }

    #[test]
    fn x5c_entry_to_pem_round_trips_a_cert() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let der_b64 = &build_x5c(&[ca.cert_pem.clone().into_bytes()]).unwrap()[0];
        let pem = x5c_entry_to_pem(der_b64).unwrap();
        let reparsed = parse_cert_pem(&pem).unwrap();
        assert!(is_self_signed(&reparsed));
    }
}
