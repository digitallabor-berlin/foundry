use crate::error::CryptoError;

pub mod signer;
pub use signer::FileSigner;

/// Supported JOSE ECDSA signature algorithms (HAIP: ES256 default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Es256,
    Es384,
    Es512,
}

impl SignatureAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Es256 => "ES256",
            SignatureAlgorithm::Es384 => "ES384",
            SignatureAlgorithm::Es512 => "ES512",
        }
    }
}

impl std::str::FromStr for SignatureAlgorithm {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "ES256" => Ok(SignatureAlgorithm::Es256),
            "ES384" => Ok(SignatureAlgorithm::Es384),
            "ES512" => Ok(SignatureAlgorithm::Es512),
            other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Abstraction over a signing key. The file-based implementation lives in
/// `signer.rs`; a KMS/HSM backend can implement this trait later without
/// touching issuer/verifier logic.
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn public_jwk(&self) -> Result<serde_json::Value, CryptoError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_known_algorithms_case_insensitively() {
        assert_eq!(SignatureAlgorithm::from_str("ES256").unwrap(), SignatureAlgorithm::Es256);
        assert_eq!(SignatureAlgorithm::from_str("es384").unwrap(), SignatureAlgorithm::Es384);
        assert_eq!(SignatureAlgorithm::from_str("Es512").unwrap(), SignatureAlgorithm::Es512);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let err = SignatureAlgorithm::from_str("RS256").unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn as_str_and_display_round_trip() {
        assert_eq!(SignatureAlgorithm::Es256.as_str(), "ES256");
        assert_eq!(format!("{}", SignatureAlgorithm::Es512), "ES512");
    }
}