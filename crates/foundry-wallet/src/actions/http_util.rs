//! Small helpers shared by `actions::issuance` and `actions::verification`:
//! building a `TrustStore` from `WalletConfig`'s configured anchors, and
//! checking an HTTP response status is 2xx. Extracted after Task 13's review
//! found both functions duplicated verbatim across the two action modules.

use crate::config::WalletConfig;
use crate::error::{WalletError, WalletResult};
use foundry_core::trust::TrustStore;

/// Build a `TrustStore` from every anchor cert file listed in
/// `config.trust.anchors`.
pub fn build_trust_store(config: &WalletConfig) -> WalletResult<TrustStore> {
    let mut pems = Vec::new();
    for anchor in &config.trust.anchors {
        let content = std::fs::read_to_string(&anchor.certs).map_err(|e| WalletError::Storage {
            path: anchor.certs.display().to_string(),
            source: e,
        })?;
        pems.push(content.into_bytes());
    }
    TrustStore::from_pems(&pems).map_err(|e| WalletError::TrustValidation(e.to_string()))
}

/// Turn a non-2xx HTTP response into a `WalletError::HttpStatus`.
pub fn ensure_2xx(status: u16, url: &str, body: &str) -> WalletResult<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(WalletError::HttpStatus {
            status,
            url: url.to_string(),
            body: body.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_2xx_accepts_the_full_2xx_range() {
        assert!(ensure_2xx(200, "http://x", "").is_ok());
        assert!(ensure_2xx(204, "http://x", "").is_ok());
        assert!(ensure_2xx(299, "http://x", "").is_ok());
    }

    #[test]
    fn ensure_2xx_rejects_non_2xx_with_status_and_body() {
        let err = ensure_2xx(404, "http://x/y", "not found").unwrap_err();
        match err {
            WalletError::HttpStatus { status, url, body } => {
                assert_eq!(status, 404);
                assert_eq!(url, "http://x/y");
                assert_eq!(body, "not found");
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }
}
