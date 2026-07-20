//! Dev-PKI generation helpers (keys, CAs, leaf certificates).

use crate::crypto::SignatureAlgorithm;
use crate::error::CryptoError;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::{Jwk, KeyPair as _};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

/// A freshly generated EC key pair as PEM strings (PKCS#8 private + SPKI public).
pub struct KeyMaterial {
    pub private_pem: String,
    pub public_pem: String,
}

/// Generate an EC key pair for the given algorithm's curve.
pub fn generate_ec_key(alg: SignatureAlgorithm) -> Result<KeyMaterial, CryptoError> {
    let curve = match alg {
        SignatureAlgorithm::Es256 => EcCurve::P256,
        SignatureAlgorithm::Es384 => EcCurve::P384,
        SignatureAlgorithm::Es512 => EcCurve::P521,
    };
    let jwk = Jwk::generate_ec_key(curve).map_err(|e| CryptoError::Generation(e.to_string()))?;
    let kp = EcKeyPair::from_jwk(&jwk).map_err(|e| CryptoError::Generation(e.to_string()))?;
    let private_pem = String::from_utf8(kp.to_pem_private_key())
        .map_err(|e| CryptoError::Generation(e.to_string()))?;
    let public_pem = String::from_utf8(kp.to_pem_public_key())
        .map_err(|e| CryptoError::Generation(e.to_string()))?;
    Ok(KeyMaterial {
        private_pem,
        public_pem,
    })
}

/// A generated certificate plus its own private key, as PEM strings.
pub struct CertMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a self-signed CA certificate (BasicConstraints CA; keyCertSign + cRLSign).
pub fn new_ca(common_name: &str, days: i64) -> Result<CertMaterial, CryptoError> {
    let key = KeyPair::generate().map_err(|e| CryptoError::Generation(e.to_string()))?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(days);

    let cert = params
        .self_signed(&key)
        .map_err(|e| CryptoError::Generation(e.to_string()))?;

    Ok(CertMaterial {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Issue an end-entity certificate signed by an existing CA (loaded from PEM).
/// The returned `key_pem` is the leaf's own freshly generated key.
pub fn issue_leaf(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    common_name: &str,
    dns_sans: &[String],
    days: i64,
) -> Result<CertMaterial, CryptoError> {
    let ca_key = KeyPair::from_pem(ca_key_pem).map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
    // Requires rcgen feature "x509-parser"; signing key is moved in by value.
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key)
        .map_err(|e| CryptoError::Generation(e.to_string()))?;

    let leaf_key = KeyPair::generate().map_err(|e| CryptoError::Generation(e.to_string()))?;

    // CertificateParams::new adds the SANs; we set CN + usages explicitly.
    let mut params = CertificateParams::new(dns_sans.to_vec())
        .map_err(|e| CryptoError::Generation(e.to_string()))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(days);

    let leaf = params
        .signed_by(&leaf_key, &issuer)
        .map_err(|e| CryptoError::Generation(e.to_string()))?;

    Ok(CertMaterial {
        cert_pem: leaf.pem(),
        key_pem: leaf_key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use crate::trust::{is_self_signed, parse_cert_pem, san_dns_names};

    #[test]
    fn generates_loadable_es256_key() {
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        assert!(km.private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(km.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));

        // The generated key must be usable by the file signer.
        let signer = FileSigner::from_pem(km.private_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let sig = signer.sign(b"data").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn generates_es384_and_es512_keys() {
        let k384 = generate_ec_key(SignatureAlgorithm::Es384).unwrap();
        let s384 = FileSigner::from_pem(k384.private_pem.as_bytes(), SignatureAlgorithm::Es384).unwrap();
        assert_eq!(s384.sign(b"x").unwrap().len(), 96);

        let k512 = generate_ec_key(SignatureAlgorithm::Es512).unwrap();
        let s512 = FileSigner::from_pem(k512.private_pem.as_bytes(), SignatureAlgorithm::Es512).unwrap();
        assert_eq!(s512.sign(b"x").unwrap().len(), 132);
    }

    #[test]
    fn new_ca_is_self_signed_pem() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        assert!(ca.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(ca.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let cert = parse_cert_pem(ca.cert_pem.as_bytes()).unwrap();
        assert!(is_self_signed(&cert));
    }

    #[test]
    fn issue_leaf_is_ca_signed_with_san() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "issuer.dev.local",
            &["issuer.dev.local".to_string()],
            365,
        )
        .unwrap();

        let leaf_cert = parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
        let ca_cert = parse_cert_pem(ca.cert_pem.as_bytes()).unwrap();

        // Not self-signed, and genuinely chained to the CA.
        assert!(!is_self_signed(&leaf_cert));
        assert_eq!(
            leaf_cert.tbs_certificate().issuer(),
            ca_cert.tbs_certificate().subject()
        );
        // SAN carries the requested DNS name.
        assert_eq!(
            san_dns_names(&leaf_cert).unwrap(),
            vec!["issuer.dev.local".to_string()]
        );
    }
}
