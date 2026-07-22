use thiserror::Error;

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error("unknown credential_type_id '{0}'")]
    UnknownCredentialType(String),
    #[error("claim validation failed: {0}")]
    ClaimValidation(String),
    #[error("status list exhausted for credential_type '{0}'")]
    StatusListExhausted(String),
    #[error(transparent)]
    Storage(#[from] foundry_core::error::StorageError),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
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
}