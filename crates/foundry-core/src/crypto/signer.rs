//! File-based `Signer` implementation over josekit.

use crate::crypto::{SignatureAlgorithm, Signer};
use crate::error::CryptoError;
use josekit::jwk::KeyPair as _;
use josekit::jwk::alg::ec::EcKeyPair;
use josekit::jws::{ES256, ES384, ES512, JwsSigner};

/// A `Signer` backed by an EC private key loaded from a PKCS#8 PEM.
#[derive(Debug)]
pub struct FileSigner {
    algorithm: SignatureAlgorithm,
    signer: Box<dyn JwsSigner>,
    public_jwk: serde_json::Value,
}

impl FileSigner {
    /// Load a signer from an in-memory PKCS#8 PEM.
    pub fn from_pem(pem: &[u8], algorithm: SignatureAlgorithm) -> Result<Self, CryptoError> {
        let signer: Box<dyn JwsSigner> = match algorithm {
            SignatureAlgorithm::Es256 => Box::new(
                ES256
                    .signer_from_pem(pem)
                    .map_err(|e| CryptoError::KeyLoad(e.to_string()))?,
            ),
            SignatureAlgorithm::Es384 => Box::new(
                ES384
                    .signer_from_pem(pem)
                    .map_err(|e| CryptoError::KeyLoad(e.to_string()))?,
            ),
            SignatureAlgorithm::Es512 => Box::new(
                ES512
                    .signer_from_pem(pem)
                    .map_err(|e| CryptoError::KeyLoad(e.to_string()))?,
            ),
        };

        // Curve is auto-detected from the PKCS#8 structure (None).
        let key_pair =
            EcKeyPair::from_pem(pem, None).map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
        let public_jwk = serde_json::to_value(key_pair.to_jwk_public_key())
            .map_err(|e| CryptoError::KeyLoad(e.to_string()))?;

        Ok(Self {
            algorithm,
            signer,
            public_jwk,
        })
    }

    /// Load a signer from a PEM file on disk.
    pub fn from_pem_file(path: &str, algorithm: SignatureAlgorithm) -> Result<Self, CryptoError> {
        let pem = std::fs::read(path).map_err(|source| CryptoError::KeyRead {
            path: path.to_string(),
            source,
        })?;
        Self::from_pem(&pem, algorithm)
    }
}

impl Signer for FileSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer
            .sign(message)
            .map_err(|e| CryptoError::Sign(e.to_string()))
    }

    fn public_jwk(&self) -> Result<serde_json::Value, CryptoError> {
        Ok(self.public_jwk.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SignatureAlgorithm, Signer};
    use josekit::jwk::Jwk;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};

    fn generate_p256_pkcs8_pem() -> Vec<u8> {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        kp.to_pem_private_key()
    }

    #[test]
    fn es256_signs_and_exports_public_jwk() {
        let pem = generate_p256_pkcs8_pem();
        let signer = FileSigner::from_pem(&pem, SignatureAlgorithm::Es256).unwrap();

        assert_eq!(signer.algorithm(), SignatureAlgorithm::Es256);

        // josekit ES256 produces a raw r||s JOSE signature = 64 bytes for P-256.
        let sig = signer.sign(b"payload-to-sign").unwrap();
        assert_eq!(sig.len(), 64);

        let jwk = signer.public_jwk().unwrap();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
    }

    #[test]
    fn from_pem_file_round_trips() {
        let pem = generate_p256_pkcs8_pem();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.pem");
        std::fs::write(&path, &pem).unwrap();

        let signer =
            FileSigner::from_pem_file(path.to_str().unwrap(), SignatureAlgorithm::Es256).unwrap();
        let sig = signer.sign(b"hi").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn wrong_pem_is_a_key_load_error() {
        let err = FileSigner::from_pem(b"not a pem", SignatureAlgorithm::Es256).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::KeyLoad(_)));
    }
}
