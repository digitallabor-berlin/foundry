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
pub enum CoreError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Storage(#[from] StorageError),
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
}
