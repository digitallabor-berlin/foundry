//! Wallet-wide error type. Every fallible operation in `actions/`, `storage/`,
//! and `http/` returns `WalletResult<T>`; headless subcommands serialize a
//! failing `WalletError` to `{"error": "<message>", "kind": "<kind>"}` on
//! stderr (see `cli.rs`/`main.rs`).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("http {status} from {url}: {body}")]
    HttpStatus {
        status: u16,
        url: String,
        body: String,
    },
    #[error("storage error at {path}: {source}")]
    Storage {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("config error: {0}")]
    Config(String),
    #[error("malformed credential offer: {0}")]
    MalformedOffer(String),
    #[error("malformed request object: {0}")]
    MalformedRequestObject(String),
    #[error("trust validation failed: {0}")]
    TrustValidation(String),
    #[error("no matching credential for the requested DCQL query")]
    NoMatchingCredential,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

pub type WalletResult<T> = Result<T, WalletError>;

impl WalletError {
    /// Machine-readable discriminant for headless JSON error output.
    pub fn kind(&self) -> &'static str {
        match self {
            WalletError::Http(_) => "http",
            WalletError::HttpStatus { .. } => "http_status",
            WalletError::Storage { .. } => "storage",
            WalletError::Config(_) => "config",
            WalletError::MalformedOffer(_) => "malformed_offer",
            WalletError::MalformedRequestObject(_) => "malformed_request_object",
            WalletError::TrustValidation(_) => "trust_validation",
            WalletError::NoMatchingCredential => "no_matching_credential",
            WalletError::Json(_) => "json",
            WalletError::Yaml(_) => "yaml",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_is_stable_per_variant() {
        assert_eq!(
            WalletError::NoMatchingCredential.kind(),
            "no_matching_credential"
        );
        assert_eq!(WalletError::Config("x".into()).kind(), "config");
    }
}
