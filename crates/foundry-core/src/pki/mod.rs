//! Dev-PKI generation helpers (keys, CAs, leaf certificates).

use crate::crypto::SignatureAlgorithm;
use crate::error::CryptoError;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::{Jwk, KeyPair as _};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FileSigner, SignatureAlgorithm, Signer};

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
}
