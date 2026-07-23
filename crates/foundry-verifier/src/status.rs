//! Token Status List revocation checking (draft-ietf-oauth-status-list-14).
//!
//! After a credential's claims are disclosed, if it carries a
//! `status.status_list` claim we resolve the referenced Status List Token,
//! verify it against the configured trust anchors, and read the credential's
//! index bit. A revoked/suspended (non-`Valid`) status yields a failed
//! `status_check` (making the overall result `verified: false`); an IO/network
//! failure fetching the token is a clean, recoverable `VerificationError`.

use crate::error::VerificationError;
use crate::transaction::CheckResult;
use foundry_core::status_list::{verify_status_list_token, StatusValue};
use foundry_core::trust::TrustStore;
use serde_json::Value;
use std::time::Duration;

/// Resolves a Status List Token (compact JWS string) from its `uri`.
#[async_trait::async_trait]
pub trait StatusListResolver: Send + Sync {
    async fn fetch(&self, uri: &str) -> Result<String, VerificationError>;
}

/// Production resolver: HTTP GET the `uri`, expecting a `statuslist+jwt` body.
pub struct HttpStatusListResolver {
    client: reqwest::Client,
}

impl HttpStatusListResolver {
    /// Build a resolver with a 10s request timeout. Returns an error (never
    /// panics) if the HTTP/TLS backend cannot be initialized.
    pub fn new() -> Result<Self, VerificationError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| VerificationError::StatusUnavailable(format!("http client init: {e}")))?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl StatusListResolver for HttpStatusListResolver {
    async fn fetch(&self, uri: &str) -> Result<String, VerificationError> {
        let resp = self
            .client
            .get(uri)
            .send()
            .await
            .map_err(|e| VerificationError::StatusUnavailable(format!("fetch {uri}: {e}")))?;
        if !resp.status().is_success() {
            return Err(VerificationError::StatusUnavailable(format!(
                "fetch {uri}: HTTP {}",
                resp.status()
            )));
        }
        resp.text()
            .await
            .map_err(|e| VerificationError::StatusUnavailable(format!("read {uri}: {e}")))
    }
}

fn passed(detail: &str) -> CheckResult {
    CheckResult {
        check: "status_check".to_string(),
        passed: true,
        detail: Some(detail.to_string()),
    }
}

fn failed(detail: String) -> CheckResult {
    CheckResult {
        check: "status_check".to_string(),
        passed: false,
        detail: Some(detail),
    }
}

/// Check the disclosed credential's Token Status List status.
///
/// A missing `status.status_list` claim passes (the credential is not
/// revocable). A revoked/suspended index, a malformed status claim, or a
/// Status List Token failing trust-anchor/`sub`/`exp` verification is a
/// **failed** check. Only an IO/network failure fetching the token is a hard
/// `Err(VerificationError::StatusUnavailable)`.
pub async fn check_status(
    disclosed_claims: &Value,
    trust_store: &TrustStore,
    resolver: &dyn StatusListResolver,
    now_unix: u64,
) -> Result<CheckResult, VerificationError> {
    let status_list = match disclosed_claims
        .get("status")
        .and_then(|s| s.get("status_list"))
    {
        Some(sl) => sl,
        None => return Ok(passed("no status list claim present")),
    };

    let uri = match status_list.get("uri").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => {
            return Ok(failed(
                "status_list.uri missing or not a string".to_string(),
            ))
        }
    };
    let idx = match status_list.get("idx").and_then(|v| v.as_u64()) {
        Some(i) => i,
        None => {
            return Ok(failed(
                "status_list.idx missing or not an integer".to_string(),
            ))
        }
    };

    // IO: fetch the token. A network failure is a hard, recoverable error.
    let token = resolver.fetch(uri).await?;

    // Per draft-ietf-oauth-status-list-14 §5.1 the token's `sub` MUST equal the
    // referenced token's `uri`, so we verify against `uri` as the expected sub.
    let verified = match verify_status_list_token(&token, trust_store, uri, now_unix) {
        Ok(v) => v,
        Err(e) => {
            return Ok(failed(format!(
                "status list token verification failed: {e}"
            )))
        }
    };

    match verified.status_at(idx) {
        Ok(StatusValue::Valid) => Ok(passed(&format!("index {idx} is valid"))),
        Ok(other) => Ok(failed(format!(
            "credential status at index {idx} is {other:?}"
        ))),
        Err(e) => Ok(failed(format!("status lookup failed at index {idx}: {e}"))),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A resolver returning a fixed token, or an error if `token` is `None`.
    pub struct MockResolver {
        pub token: Option<String>,
    }

    #[async_trait::async_trait]
    impl StatusListResolver for MockResolver {
        async fn fetch(&self, _uri: &str) -> Result<String, VerificationError> {
            match &self.token {
                Some(t) => Ok(t.clone()),
                None => Err(VerificationError::StatusUnavailable(
                    "mock resolver has no token".to_string(),
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockResolver;
    use super::*;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::status_list::{build_status_list_token, StatusList, StatusListTokenClaims};
    use foundry_core::trust::{build_x5c, TrustStore};
    use serde_json::json;

    const URI: &str = "https://issuer.example/statuslists/1";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // A (trust_store, token) pair whose status list marks `revoked_idx` Invalid.
    fn token_with_revoked(revoked_idx: usize, sub: &str) -> (TrustStore, String) {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        let signer =
            FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let x5c = build_x5c(&[leaf.cert_pem.into_bytes()]).unwrap();
        let trust_store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();

        let mut values = vec![0u8; revoked_idx + 1];
        values[revoked_idx] = 1; // Invalid
        let list = StatusList::build(&values, 2, None).unwrap();
        let n = now() as i64;
        let claims = StatusListTokenClaims {
            sub: sub.to_string(),
            iat: n - 100,
            exp: Some(n + 3600),
            ttl: None,
        };
        let token = build_status_list_token(claims, &list, &signer, Some(x5c)).unwrap();
        (trust_store, token)
    }

    #[tokio::test]
    async fn no_status_claim_passes() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let trust_store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        let resolver = MockResolver { token: None };
        let claims = json!({ "vct": "x", "given_name": "Alice" });
        let r = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap();
        assert!(r.passed);
        assert_eq!(r.check, "status_check");
    }

    #[tokio::test]
    async fn valid_index_passes() {
        let (trust_store, token) = token_with_revoked(7, URI);
        let resolver = MockResolver { token: Some(token) };
        let claims = json!({ "status": { "status_list": { "idx": 3, "uri": URI } } });
        let r = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap();
        assert!(r.passed, "detail={:?}", r.detail);
    }

    #[tokio::test]
    async fn revoked_index_fails() {
        let (trust_store, token) = token_with_revoked(7, URI);
        let resolver = MockResolver { token: Some(token) };
        let claims = json!({ "status": { "status_list": { "idx": 7, "uri": URI } } });
        let r = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap();
        assert!(!r.passed);
        assert!(r.detail.unwrap().contains("Invalid"));
    }

    #[tokio::test]
    async fn network_failure_is_hard_error() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let trust_store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        let resolver = MockResolver { token: None }; // errors on fetch
        let claims = json!({ "status": { "status_list": { "idx": 1, "uri": URI } } });
        let err = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::StatusUnavailable(_)));
    }

    #[tokio::test]
    async fn subject_mismatch_fails_check() {
        // Token sub differs from the credential's uri -> verification fails -> failed check.
        let (trust_store, token) =
            token_with_revoked(2, "https://issuer.example/statuslists/OTHER");
        let resolver = MockResolver { token: Some(token) };
        let claims = json!({ "status": { "status_list": { "idx": 0, "uri": URI } } });
        let r = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap();
        assert!(!r.passed);
    }
}
