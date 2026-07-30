use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("verification request not found: {0}")]
    NotFound(String),

    #[error("invalid verification state: {0}")]
    InvalidState(String),

    #[error("dcql error: {0}")]
    Dcql(String),

    /// A caller-supplied request parameter is structurally invalid. Maps to HTTP
    /// 400 on the admin API (see AGENTS.md §4.3).
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("verification failed: {0}")]
    Failed(String),

    #[error("status list unavailable: {0}")]
    StatusUnavailable(String),

    #[error(transparent)]
    Storage(#[from] foundry_core::error::StorageError),

    #[error(transparent)]
    CoreCrypto(#[from] foundry_core::error::CryptoError),

    #[error(transparent)]
    Trust(#[from] foundry_core::error::TrustError),

    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VerificationError::NotFound("tx-123".to_string());
        assert_eq!(err.to_string(), "verification request not found: tx-123");

        let err = VerificationError::InvalidState("pending".to_string());
        assert_eq!(err.to_string(), "invalid verification state: pending");

        let err = VerificationError::Dcql("invalid query".to_string());
        assert_eq!(err.to_string(), "dcql error: invalid query");

        let err = VerificationError::InvalidRequest("bad transaction_data".to_string());
        assert_eq!(err.to_string(), "invalid request: bad transaction_data");

        let err = VerificationError::Crypto("key error".to_string());
        assert_eq!(err.to_string(), "crypto error: key error");

        let err = VerificationError::Decryption("bad payload".to_string());
        assert_eq!(err.to_string(), "decryption failed: bad payload");

        let err = VerificationError::Failed("mismatch".to_string());
        assert_eq!(err.to_string(), "verification failed: mismatch");

        let err = VerificationError::Serialization("json fail".to_string());
        assert_eq!(err.to_string(), "serialization error: json fail");

        let err = VerificationError::StatusUnavailable("network".to_string());
        assert_eq!(err.to_string(), "status list unavailable: network");
    }
}
