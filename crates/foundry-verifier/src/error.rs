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

impl VerificationError {
    /// A stable, low-cardinality name for this variant, for the `error.kind` log
    /// field.
    ///
    /// Operators group and alert on this, so it must stay decoupled from the
    /// `Display` text — which is prose and may be reworded — and must never
    /// include the error's detail.
    ///
    /// Deliberately exhaustive with no catch-all arm: a new variant should be a
    /// compile error here, not a log line labelled `"unknown"`.
    pub fn kind(&self) -> &'static str {
        match self {
            VerificationError::NotFound(_) => "not_found",
            VerificationError::InvalidState(_) => "invalid_state",
            VerificationError::Dcql(_) => "dcql",
            VerificationError::InvalidRequest(_) => "invalid_request",
            VerificationError::Crypto(_) => "crypto",
            VerificationError::Decryption(_) => "decryption",
            VerificationError::Failed(_) => "failed",
            VerificationError::StatusUnavailable(_) => "status_unavailable",
            VerificationError::Storage(_) => "storage",
            VerificationError::CoreCrypto(_) => "core_crypto",
            VerificationError::Trust(_) => "trust",
            VerificationError::Serialization(_) => "serialization",
        }
    }
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

    /// One assertion per variant. `kind()` is exhaustive with no catch-all arm,
    /// so a newly added variant is a compile error here rather than a log line
    /// silently labelled "unknown".
    #[test]
    fn kind_is_a_stable_name_for_every_variant() {
        let s = || "x".to_string();
        let cases: Vec<(VerificationError, &str)> = vec![
            (VerificationError::NotFound(s()), "not_found"),
            (VerificationError::InvalidState(s()), "invalid_state"),
            (VerificationError::Dcql(s()), "dcql"),
            (VerificationError::InvalidRequest(s()), "invalid_request"),
            (VerificationError::Crypto(s()), "crypto"),
            (VerificationError::Decryption(s()), "decryption"),
            (VerificationError::Failed(s()), "failed"),
            (
                VerificationError::StatusUnavailable(s()),
                "status_unavailable",
            ),
            (
                VerificationError::Storage(foundry_core::error::StorageError::NotFound(s())),
                "storage",
            ),
            (
                VerificationError::CoreCrypto(
                    foundry_core::error::CryptoError::UnsupportedAlgorithm(s()),
                ),
                "core_crypto",
            ),
            (VerificationError::Serialization(s()), "serialization"),
        ];

        for (err, expected) in cases {
            assert_eq!(err.kind(), expected, "for {err:?}");
        }
    }

    /// `kind()` must never carry the error's *detail* — it is the low-cardinality
    /// field operators group and alert on.
    #[test]
    fn kind_does_not_include_the_detail() {
        let err = VerificationError::Decryption("a-very-specific-secret".to_string());
        assert_eq!(err.kind(), "decryption");
        assert!(!err.kind().contains("secret"));
    }
}
