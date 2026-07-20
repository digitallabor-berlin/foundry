use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config ({format}): {message}")]
    Parse { format: String, message: String },
    #[error("config validation failed: {0}")]
    Validation(String),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("record not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("failed to read key file {path}: {source}")]
    KeyRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unsupported signature algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    #[error("failed to load signing key: {0}")]
    KeyLoad(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("key or certificate generation failed: {0}")]
    Generation(String),
}

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("failed to read certificate file {path}: {source}")]
    CertRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse certificate: {0}")]
    Parse(String),
    #[error("certificate chain is empty")]
    EmptyChain,
    #[error("leaf certificate must not be self-signed (HAIP §6.1.1)")]
    SelfSignedLeaf,
    #[error("certificate is outside its validity window")]
    Expired,
    #[error("no configured trust anchor matches the certificate chain")]
    UntrustedChain,
    #[error("DNS SAN mismatch: certificate does not assert '{0}'")]
    SanMismatch(String),
}

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization or parsing failed: {0}")]
    Deserialization(String),
    #[error("invalid credential structure: {0}")]
    InvalidStructure(String),
    #[error("cryptographic verification failed: {0}")]
    SignatureVerification(String),
    #[error("holder key binding verification failed: {0}")]
    KeyBinding(String),
    #[error("credential has expired or is not yet valid")]
    Expired,
    #[error("unsupported algorithm or key type: {0}")]
    Unsupported(String),
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error(transparent)]
    Format(#[from] FormatError),
}

pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation_error_displays_message() {
        let e = ConfigError::Validation("missing key 'issuer_sdjwt'".into());
        assert_eq!(
            e.to_string(),
            "config validation failed: missing key 'issuer_sdjwt'"
        );
    }

    #[test]
    fn core_error_wraps_storage_not_found() {
        let e: CoreError = StorageError::NotFound("tx-123".into()).into();
        assert_eq!(e.to_string(), "record not found: tx-123");
    }

    #[test]
    fn crypto_unsupported_alg_displays() {
        let e = CryptoError::UnsupportedAlgorithm("RS256".into());
        assert_eq!(e.to_string(), "unsupported signature algorithm 'RS256'");
    }

    #[test]
    fn trust_self_signed_leaf_displays() {
        let e = TrustError::SelfSignedLeaf;
        assert_eq!(
            e.to_string(),
            "leaf certificate must not be self-signed (HAIP §6.1.1)"
        );
    }

    #[test]
    fn core_error_wraps_crypto_and_trust() {
        let c: CoreError = CryptoError::Sign("boom".into()).into();
        assert_eq!(c.to_string(), "signing failed: boom");
        let t: CoreError = TrustError::UntrustedChain.into();
        assert_eq!(
            t.to_string(),
            "no configured trust anchor matches the certificate chain"
        );
    }

    #[test]
    fn format_error_serialization_displays() {
        let e = FormatError::Serialization("JSON drift".into());
        assert_eq!(e.to_string(), "serialization failed: JSON drift");
    }

    #[test]
    fn core_error_wraps_format_error() {
        let c: CoreError = FormatError::Expired.into();
        assert_eq!(c.to_string(), "credential has expired or is not yet valid");
    }
}
