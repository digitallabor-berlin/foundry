use thiserror::Error;

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid grant: {0}")]
    InvalidGrant(String),
    #[error("invalid proof: {0}")]
    InvalidProof(String),
    #[error("unknown credential_type_id '{0}'")]
    UnknownCredentialType(String),
    #[error("claim validation failed: {0}")]
    ClaimValidation(String),
    /// Client-authentication failures per RFC 6749 sect-5.2: an absent, malformed,
    /// unsigned, expired, replayed, or otherwise unverifiable Wallet Attestation
    /// or Client Attestation PoP JWT (ABCA draft -07). Deliberately distinct from
    /// `InvalidRequest`, which is for malformed *request parameters*, not a
    /// failed client-auth mechanism -- GAP-VCI-14.
    #[error("invalid client: {0}")]
    InvalidClient(String),
    #[error("status list exhausted while allocating an index for credential_type '{0}'")]
    StatusListExhausted(String),
    #[error(transparent)]
    Storage(#[from] foundry_core::error::StorageError),
    #[error(transparent)]
    Crypto(#[from] foundry_core::error::CryptoError),
    #[error(transparent)]
    Trust(#[from] foundry_core::error::TrustError),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
}

impl IssuanceError {
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
            IssuanceError::InvalidRequest(_) => "invalid_request",
            IssuanceError::InvalidGrant(_) => "invalid_grant",
            IssuanceError::InvalidProof(_) => "invalid_proof",
            IssuanceError::UnknownCredentialType(_) => "unknown_credential_type",
            IssuanceError::ClaimValidation(_) => "claim_validation",
            IssuanceError::InvalidClient(_) => "invalid_client",
            IssuanceError::StatusListExhausted(_) => "status_list_exhausted",
            IssuanceError::Storage(_) => "storage",
            IssuanceError::Crypto(_) => "crypto",
            IssuanceError::Trust(_) => "trust",
            IssuanceError::Internal(_) => "internal",
            IssuanceError::Serialization(_) => "serialization",
            IssuanceError::Deserialization(_) => "deserialization",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_credential_type_displays_the_id() {
        let e = IssuanceError::UnknownCredentialType("pid".to_string());
        assert_eq!(e.to_string(), "unknown credential_type_id 'pid'");
    }

    #[test]
    fn storage_error_wraps_transparently() {
        let e: IssuanceError = foundry_core::error::StorageError::NotFound("tx-1".into()).into();
        assert_eq!(e.to_string(), "record not found: tx-1");
    }

    /// One assertion per variant. `kind()` is exhaustive with no catch-all arm,
    /// so a newly added variant is a compile error here rather than a log line
    /// silently labelled "unknown".
    #[test]
    fn kind_is_a_stable_name_for_every_variant() {
        let s = || "x".to_string();
        let cases: Vec<(IssuanceError, &str)> = vec![
            (IssuanceError::InvalidRequest(s()), "invalid_request"),
            (IssuanceError::InvalidGrant(s()), "invalid_grant"),
            (IssuanceError::InvalidProof(s()), "invalid_proof"),
            (
                IssuanceError::UnknownCredentialType(s()),
                "unknown_credential_type",
            ),
            (IssuanceError::ClaimValidation(s()), "claim_validation"),
            (IssuanceError::InvalidClient(s()), "invalid_client"),
            (
                IssuanceError::StatusListExhausted(s()),
                "status_list_exhausted",
            ),
            (
                IssuanceError::Storage(foundry_core::error::StorageError::NotFound(s())),
                "storage",
            ),
            (
                IssuanceError::Crypto(foundry_core::error::CryptoError::UnsupportedAlgorithm(s())),
                "crypto",
            ),
            (IssuanceError::Internal(s()), "internal"),
            (IssuanceError::Serialization(s()), "serialization"),
            (IssuanceError::Deserialization(s()), "deserialization"),
        ];

        for (err, expected) in cases {
            assert_eq!(err.kind(), expected, "for {err:?}");
        }
    }

    /// `kind()` must never carry the error's *detail* — it is the low-cardinality
    /// field operators group and alert on.
    #[test]
    fn kind_does_not_include_the_detail() {
        let err = IssuanceError::InvalidProof("a-very-specific-secret".to_string());
        assert_eq!(err.kind(), "invalid_proof");
        assert!(!err.kind().contains("secret"));
    }

    /// GAP-VCI-14: a failed Client Attestation PoP JWT never leaks into the
    /// `Display` text either -- the detail string is operator-facing, not the
    /// raw JWT.
    #[test]
    fn invalid_client_does_not_leak_a_raw_jwt_in_display() {
        let err = IssuanceError::InvalidClient("pop jti already claimed".to_string());
        assert_eq!(err.kind(), "invalid_client");
        assert_eq!(err.to_string(), "invalid client: pop jti already claimed");
    }
}
