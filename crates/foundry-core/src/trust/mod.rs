//! X.509 parsing, inspection, and (DN-based) trust-path validation.

use crate::error::TrustError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL_NOPAD;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509StoreContext, X509 as OsslX509};
use sha2::{Digest, Sha256};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;

pub use x509_cert::Certificate;

// OpenSSL verification result codes, from `include/openssl/x509_vfy.h`. These
// are a stable part of OpenSSL's ABI. Declared locally rather than pulling in
// `openssl-sys` as a second direct dependency; `X509VerifyResult::from_raw` is
// `unsafe`, so classification reads `as_raw()` and compares integers instead.
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: i32 = 2;
const X509_V_ERR_CERT_SIGNATURE_FAILURE: i32 = 7;
const X509_V_ERR_CERT_NOT_YET_VALID: i32 = 9;
const X509_V_ERR_CERT_HAS_EXPIRED: i32 = 10;
const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: i32 = 18;
const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: i32 = 19;
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: i32 = 20;
const X509_V_ERR_INVALID_CA: i32 = 24;
const X509_V_ERR_PATH_LENGTH_EXCEEDED: i32 = 25;
const X509_V_ERR_KEYUSAGE_NO_CERTSIGN: i32 = 32;

/// Parse a single PEM-encoded certificate.
pub fn parse_cert_pem(pem: &[u8]) -> Result<Certificate, TrustError> {
    Certificate::from_pem(pem).map_err(|e| TrustError::Parse(e.to_string()))
}

/// The `x509_hash` Client Identifier value for a leaf certificate.
///
/// OpenID4VP 1.0, Defined Client Identifier Prefixes / `x509_hash` (L616): "The
/// value of `x509_hash` is the base64url-encoded value of the SHA-256 hash of the
/// DER-encoded X.509 certificate."
///
/// Returns the value **without** the `x509_hash:` prefix, so callers compose the
/// Client Identifier themselves. This is the only place the value is computed:
/// the Request Object's `client_id` (request.rs) and the expected KB-JWT audience
/// (verify.rs) must both call it, or the two sides drift apart silently.
pub fn x509_hash_client_id_value(leaf_pem: &[u8]) -> Result<String, TrustError> {
    let cert = parse_cert_pem(leaf_pem)?;
    let der = cert
        .to_der()
        .map_err(|e| TrustError::Parse(e.to_string()))?;
    Ok(B64URL_NOPAD.encode(Sha256::digest(&der)))
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
///
/// Holds the raw anchor certificates rather than a single pre-built
/// `openssl::x509::store::X509Store`: OpenSSL exposes no supported way to
/// change a store's verification *time* per call (there is no
/// `X509StoreContextRef::verify_param_mut`, and `X509_STORE_CTX_set_time` is
/// not bound by the `openssl` crate at all -- only `X509_VERIFY_PARAM_set_time`,
/// which applies to a `X509VerifyParam` set on the *store builder* before
/// `.build()`). Since `validate_chain`'s `now_unix` must never be the system
/// clock (callers pass synthetic times in tests), each call builds a fresh
/// `X509Store` from these anchors with that call's time baked in.
///
/// `X509` is `Send + Sync` and `Clone` (both declared via
/// `foreign_type_and_impl_send_sync!` / `impl Clone for X509` in
/// `openssl::x509`), which this type relies on: `TrustStore` is held across
/// `.await` points in `foundry-issuer`'s `token.rs` and `credential.rs`.
pub struct TrustStore {
    anchors: Vec<OsslX509>,
}

impl TrustStore {
    pub fn from_pems(pems: &[Vec<u8>]) -> Result<Self, TrustError> {
        let mut anchors = Vec::with_capacity(pems.len());
        for pem in pems {
            // Parse with x509-cert first so malformed input yields the same
            // TrustError::Parse it always has.
            parse_cert_pem(pem)?;
            let cert = OsslX509::from_pem(pem).map_err(|e| TrustError::Parse(e.to_string()))?;
            anchors.push(cert);
        }
        Ok(Self { anchors })
    }

    pub fn from_config(anchors: &[crate::config::TrustAnchor]) -> Result<Self, TrustError> {
        let mut pems = Vec::new();
        for anchor in anchors {
            let content =
                std::fs::read_to_string(&anchor.certs).map_err(|e| TrustError::CertRead {
                    path: anchor.certs.clone(),
                    source: e,
                })?;
            for block in content.split("-----BEGIN CERTIFICATE-----") {
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

    /// Build a fresh `X509Store` from this store's anchors, with `now_unix`
    /// baked in as the verification time.
    fn build_ossl_store(&self, now_unix: u64) -> Result<X509Store, TrustError> {
        let mut param = X509VerifyParam::new().map_err(|e| TrustError::Parse(e.to_string()))?;
        param.set_time(now_unix as i64);
        // A configured anchor may be an intermediate rather than a self-signed
        // root -- foundry has always allowed this. PARTIAL_CHAIN is what lets
        // OpenSSL stop at such an anchor instead of insisting on reaching a
        // self-signed certificate. Empirically required: pinning the P-384
        // Android TEE intermediate as the sole anchor fails without this flag.
        param
            .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
            .map_err(|e| TrustError::Parse(e.to_string()))?;

        let mut builder = X509StoreBuilder::new().map_err(|e| TrustError::Parse(e.to_string()))?;
        builder
            .set_param(&param)
            .map_err(|e| TrustError::Parse(e.to_string()))?;
        for anchor in &self.anchors {
            builder
                .add_cert(anchor.clone())
                .map_err(|e| TrustError::Parse(e.to_string()))?;
        }
        Ok(builder.build())
    }
}

/// Validate a leaf (+ optional intermediates) against the trust store.
///
/// Every link's signature is verified and RFC 5280 CA constraints are enforced
/// by OpenSSL: `basicConstraints: CA:TRUE` and `keyUsage: keyCertSign` on every
/// non-leaf, `pathLenConstraint`, validity windows, and Authority/Subject Key
/// Identifier path building.
///
/// Verification purpose is deliberately **not** set. Setting one enables
/// Extended Key Usage checks, and Android key-attestation certificates carry no
/// EKU at all -- setting a purpose here would reject every Google Wallet chain.
pub fn validate_chain(
    leaf_pem: &[u8],
    intermediates: &[Vec<u8>],
    store: &TrustStore,
    now_unix: u64,
) -> Result<(), TrustError> {
    // Retained ahead of OpenSSL: HAIP-0040/0080/0085 assert this specific
    // variant, and OpenSSL reports the case with a less specific code.
    let leaf = parse_cert_pem(leaf_pem)?;
    if is_self_signed(&leaf) {
        return Err(TrustError::SelfSignedLeaf);
    }

    let leaf_ossl = OsslX509::from_pem(leaf_pem).map_err(|e| TrustError::Parse(e.to_string()))?;

    let mut chain: Stack<OsslX509> = Stack::new().map_err(|e| TrustError::Parse(e.to_string()))?;
    for pem in intermediates {
        let parsed = parse_cert_pem(pem)?;
        // A presented root is never trusted: the anchor must come from
        // configuration. This is defence-in-depth -- OpenSSL already refuses to
        // bootstrap trust from a self-signed certificate in the untrusted set
        // (X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) -- but dropping it here makes
        // the intent explicit and yields a more accurate error when no anchor is
        // configured. Google Wallet transmits the Android root inside the chain.
        if is_self_signed(&parsed) {
            continue;
        }
        let cert = OsslX509::from_pem(pem).map_err(|e| TrustError::Parse(e.to_string()))?;
        chain
            .push(cert)
            .map_err(|e| TrustError::Parse(e.to_string()))?;
    }

    // Validity is evaluated at the caller's instant, never the system clock:
    // callers pass synthetic times (see `expired_leaf_is_rejected`). Baked into
    // a freshly built store -- see `TrustStore::build_ossl_store` for why.
    let ossl_store = store.build_ossl_store(now_unix)?;

    let mut ctx = X509StoreContext::new().map_err(|e| TrustError::Parse(e.to_string()))?;
    let verified = ctx
        .init(&ossl_store, &leaf_ossl, &chain, |ctx| {
            let ok = ctx.verify_cert()?;
            Ok((ok, ctx.error().as_raw()))
        })
        .map_err(|e| TrustError::Parse(e.to_string()))?;

    match verified {
        (true, _) => Ok(()),
        (false, code) => Err(map_verify_error(code)),
    }
}

/// Translate an OpenSSL verification result code into a `TrustError`.
fn map_verify_error(code: i32) -> TrustError {
    match code {
        X509_V_ERR_CERT_HAS_EXPIRED | X509_V_ERR_CERT_NOT_YET_VALID => TrustError::Expired,
        X509_V_ERR_CERT_SIGNATURE_FAILURE => TrustError::InvalidSignature,
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
        | X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        | X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        | X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        | X509_V_ERR_INVALID_CA
        | X509_V_ERR_PATH_LENGTH_EXCEEDED
        | X509_V_ERR_KEYUSAGE_NO_CERTSIGN => TrustError::UntrustedChain,
        _ => TrustError::UntrustedChain,
    }
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
    fn from_config_reads_certs_as_a_file_path_not_literal_pem() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("root.pem");
        std::fs::write(&cert_path, CA_CERT_PEM).unwrap();

        let anchors = vec![crate::config::TrustAnchor {
            name: "test_ca".to_string(),
            certs: cert_path.to_str().unwrap().to_string(),
        }];

        let store = TrustStore::from_config(&anchors).unwrap();
        assert!(!store.is_empty());
    }

    #[test]
    fn x5c_entry_to_pem_round_trips_a_cert() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let der_b64 = &build_x5c(&[ca.cert_pem.clone().into_bytes()]).unwrap()[0];
        let pem = x5c_entry_to_pem(der_b64).unwrap();
        let reparsed = parse_cert_pem(&pem).unwrap();
        assert!(is_self_signed(&reparsed));
    }

    #[test]
    fn x509_hash_client_id_value_is_base64url_sha256_of_the_der() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL_NOPAD;
        use sha2::{Digest, Sha256};

        let value = x509_hash_client_id_value(LEAF_CERT_PEM).unwrap();

        // build_x5c already yields base64-STANDARD DER for the same cert, so it is
        // an independent route to the bytes that must be hashed.
        let der = B64
            .decode(&build_x5c(&[LEAF_CERT_PEM.to_vec()]).unwrap()[0])
            .unwrap();
        assert_eq!(value, B64URL_NOPAD.encode(Sha256::digest(&der)));

        // OpenID4VP L616: base64url; SHA-256 is 32 bytes -> 43 unpadded chars.
        assert_eq!(value.len(), 43);
        assert!(!value.contains('='), "must be unpadded: {value}");
        assert!(
            !value.contains('+') && !value.contains('/'),
            "must be base64URL: {value}"
        );
    }

    #[test]
    fn x509_hash_client_id_value_differs_per_certificate() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let a = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "a.dev.local",
            &["a.dev.local".to_string()],
            365,
        )
        .unwrap();
        let b = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "b.dev.local",
            &["b.dev.local".to_string()],
            365,
        )
        .unwrap();
        assert_ne!(
            x509_hash_client_id_value(a.cert_pem.as_bytes()).unwrap(),
            x509_hash_client_id_value(b.cert_pem.as_bytes()).unwrap()
        );
    }

    #[test]
    fn x509_hash_client_id_value_rejects_garbage_pem() {
        assert!(x509_hash_client_id_value(b"not a certificate").is_err());
    }
}
