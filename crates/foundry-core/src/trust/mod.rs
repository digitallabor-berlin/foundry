//! X.509 parsing, inspection, and (DN-based) trust-path validation.

use crate::error::TrustError;
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, DecodePem};
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
}
