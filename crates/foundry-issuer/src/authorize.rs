//! `GET /authorize` request handling for the authorization_code grant.
//!
//! Resolves the wallet's `issuer_state` back to the pre-created
//! `IssuanceTransaction` (`create_offer`'s `redirect_uri`-set branch),
//! validates the OAuth 2.0 + PKCE parameters, mints a single-use
//! authorization code, and reports how the caller should respond —
//! there is no real user login/consent step here: the claims were already
//! fixed by the admin at `create_offer` time.

use crate::error::IssuanceError;
use crate::offer::generate_pre_authorized_code;
use crate::transaction::{
    load_transaction_by_issuer_state, save_transaction_with_auth_code, IssuanceState,
};
use foundry_core::storage::Storage;

/// Single-use authorization code TTL (RFC 6749 §4.1.2: codes MUST be
/// short-lived). 5 minutes.
pub const AUTH_CODE_TTL_SECS: u64 = 300;

/// Parsed `GET /authorize` query parameters.
#[derive(Debug, Clone)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub issuer_state: String,
    /// HAIP OpenID4VCI L209: the `scope` parameter communicates the Credential Type
    /// to be issued. Optional here -- the mandate is that the Issuer publish a scope
    /// (L186) and honour it when sent, not that a Wallet must send one;
    /// `issuer_state` remains the authoritative binding.
    pub scope: Option<String>,
}

/// The result of processing an `/authorize` request. The HTTP layer
/// (`foundry::server`) maps each variant to the appropriate response: a
/// redirect for `Success`/`ErrorRedirect`, a direct JSON error body (no
/// redirect) for `DirectError`.
///
/// `Success` and `ErrorRedirect` both carry `iss` (RFC 9207 §2: "In
/// authorization responses to the client, including error responses ...
/// MUST indicate its identity by including the iss parameter") -- GAP-HAIP-02.
/// `DirectError` renders as a JSON error body, not a redirect, so RFC 9207 §2
/// does not reach it.
#[derive(Debug)]
pub enum AuthorizeOutcome {
    Success {
        redirect_uri: String,
        code: String,
        state: Option<String>,
        iss: String,
    },
    ErrorRedirect {
        redirect_uri: String,
        error: String,
        state: Option<String>,
        iss: String,
    },
    DirectError(IssuanceError),
}

/// RFC 7636 §4.1: `code_challenge` must be 43-128 characters of unreserved
/// base64url-alphabet characters.
fn is_valid_code_challenge(code_challenge: &str) -> bool {
    let len = code_challenge.len();
    (43..=128).contains(&len)
        && code_challenge
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
}

/// Handle a `GET /authorize` request. `tx_ttl_secs` is the same
/// `cfg.storage.transaction_ttl_secs` used at `create_offer` time — the
/// `Storage` trait does not expose a stored row's original `expires_at`, so
/// re-saving the transaction (to persist the minted `authorization_code`)
/// requires the caller to supply the TTL again, exactly as `create_offer`
/// and `/token` already do.
///
/// `issuer_identifier` is `config.issuer.credential_issuer`, threaded in as
/// an explicit parameter (rather than appended by the HTTP layer) so the
/// `iss` value lives on `AuthorizeOutcome` itself and is testable from this
/// crate's own suite, not only through the HTTP layer -- RFC 9207 §2,
/// GAP-HAIP-02.
///
/// `skip_all` is mandatory: `params` carries `issuer_state` and the redirect
/// parameters.
#[tracing::instrument(skip_all)]
pub async fn handle_authorize_request(
    storage: &dyn Storage,
    params: &AuthorizeParams,
    issuer_identifier: &str,
    tx_ttl_secs: u64,
    now_unix: i64,
    // Resolved scope -> credential type id, per HAIP OpenID4VCI L209. Passed in
    // rather than taking `&Config`: this function needs the mapping, nothing else.
    scopes: &std::collections::BTreeMap<String, String>,
) -> AuthorizeOutcome {
    let iss = issuer_identifier.to_string();

    let tx = match load_transaction_by_issuer_state(storage, &params.issuer_state).await {
        Ok(Some(tx)) => tx,
        Ok(None) => {
            return AuthorizeOutcome::DirectError(IssuanceError::InvalidRequest(
                "unknown or expired issuer_state".to_string(),
            ))
        }
        Err(e) => return AuthorizeOutcome::DirectError(e),
    };

    // redirect_uri is not yet trusted: it must match what was pinned to this
    // transaction at create_offer time before we treat it as a valid
    // redirect target for any subsequent error.
    let expected_redirect_uri = match tx.redirect_uri.clone() {
        Some(uri) => uri,
        None => {
            return AuthorizeOutcome::DirectError(IssuanceError::InvalidRequest(
                "transaction has no redirect_uri configured for the authorization_code grant"
                    .to_string(),
            ))
        }
    };
    if params.redirect_uri != expected_redirect_uri {
        return AuthorizeOutcome::DirectError(IssuanceError::InvalidRequest(
            "redirect_uri does not match the offer".to_string(),
        ));
    }

    // Past this point, redirect_uri is trusted: errors go back to the
    // wallet via redirect, per RFC 6749 §4.1.2.1.
    let redirect_uri = expected_redirect_uri;
    let state = params.state.clone();

    // HAIP OpenID4VCI L209: the `scope` parameter MUST be used to communicate the
    // Credential Type(s) to be issued and the value MUST map to a specific
    // Credential Type. When a Wallet sends one it must name the same type the
    // transaction was bound to at create_offer time; a mismatch is a conflicting
    // request, not a silently-ignored hint.
    if let Some(scope) = params.scope.as_deref() {
        let names_this_transaction = scopes
            .get(scope)
            .is_some_and(|credential_type_id| *credential_type_id == tx.credential_type_id);
        if !names_this_transaction {
            return AuthorizeOutcome::ErrorRedirect {
                redirect_uri,
                error: "invalid_scope".to_string(),
                state,
                iss,
            };
        }
    }

    if params.response_type != "code"
        || params.client_id.trim().is_empty()
        || params.code_challenge_method != "S256"
        || !is_valid_code_challenge(&params.code_challenge)
    {
        return AuthorizeOutcome::ErrorRedirect {
            redirect_uri,
            error: "invalid_request".to_string(),
            state,
            iss,
        };
    }

    if tx.state == IssuanceState::Issued {
        return AuthorizeOutcome::ErrorRedirect {
            redirect_uri,
            error: "access_denied".to_string(),
            state,
            iss,
        };
    }

    let code = generate_pre_authorized_code();
    let mut tx = tx;
    tx.authorization_code = Some(code.clone());
    tx.code_challenge = Some(params.code_challenge.clone());
    tx.code_challenge_method = Some(params.code_challenge_method.clone());

    if let Err(e) =
        save_transaction_with_auth_code(storage, &tx, tx_ttl_secs, AUTH_CODE_TTL_SECS, now_unix)
            .await
    {
        return AuthorizeOutcome::DirectError(e);
    }

    AuthorizeOutcome::Success {
        redirect_uri,
        code,
        state,
        iss,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{save_transaction_with_indices, IssuanceTransaction};
    use foundry_core::storage::SqliteStorage;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("a.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    const REDIRECT_URI: &str = "eudi-openid4ci://authorize";
    const ISSUER_STATE: &str = "issuer-state-abc";
    const ISSUER_IDENTIFIER: &str = "https://issuer.example.com";
    // 43 chars, valid RFC 7636 unreserved charset.
    const VALID_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn sample_tx(state: IssuanceState) -> IssuanceTransaction {
        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));
        IssuanceTransaction {
            transaction_id: "tx-authz-1".to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: None,
            tx_code: None,
            status_list_index: None,
            access_token: None,
            state,
            created_at: 1_700_000_000,
            redirect_uri: Some(REDIRECT_URI.to_string()),
            issuer_state: Some(ISSUER_STATE.to_string()),
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
        }
    }

    fn valid_params() -> AuthorizeParams {
        AuthorizeParams {
            response_type: "code".to_string(),
            client_id: "wallet-dev".to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            state: Some("xyz-state".to_string()),
            code_challenge: VALID_CHALLENGE.to_string(),
            code_challenge_method: "S256".to_string(),
            issuer_state: ISSUER_STATE.to_string(),
            scope: None,
        }
    }

    #[tokio::test]
    async fn valid_request_mints_a_code_and_persists_pkce_fields() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let params = valid_params();
        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_010,
            &std::collections::BTreeMap::new(),
        )
        .await;

        match outcome {
            AuthorizeOutcome::Success {
                redirect_uri,
                code,
                state,
                ..
            } => {
                assert_eq!(redirect_uri, REDIRECT_URI);
                assert!(!code.is_empty());
                assert_eq!(state, Some("xyz-state".to_string()));

                let loaded =
                    crate::transaction::load_transaction_by_authorization_code(&storage, &code)
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(loaded.code_challenge, Some(VALID_CHALLENGE.to_string()));
                assert_eq!(loaded.code_challenge_method, Some("S256".to_string()));
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// RFC 9207 §2, GAP-HAIP-02: a successful Authorization Response MUST
    /// carry `iss`, equal to the issuer identifier.
    #[tokio::test]
    async fn success_outcome_carries_iss() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let params = valid_params();
        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_010,
            &std::collections::BTreeMap::new(),
        )
        .await;

        match outcome {
            AuthorizeOutcome::Success { iss, .. } => assert_eq!(iss, ISSUER_IDENTIFIER),
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// RFC 9207 §2, GAP-HAIP-02: "In authorization responses to the client,
    /// including error responses" -- an ErrorRedirect MUST carry `iss` too,
    /// not only the success path.
    #[tokio::test]
    async fn error_redirect_outcome_carries_iss() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut params = valid_params();
        params.response_type = "token".to_string(); // forces ErrorRedirect

        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;

        match outcome {
            AuthorizeOutcome::ErrorRedirect { iss, error, .. } => {
                assert_eq!(iss, ISSUER_IDENTIFIER);
                assert_eq!(error, "invalid_request");
            }
            other => panic!("expected ErrorRedirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unresolvable_issuer_state_is_a_direct_error() {
        let storage = test_storage().await;
        let mut params = valid_params();
        params.issuer_state = "no-such-state".to_string();

        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert!(matches!(outcome, AuthorizeOutcome::DirectError(_)));
    }

    #[tokio::test]
    async fn mismatched_redirect_uri_is_a_direct_error_not_a_redirect() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut params = valid_params();
        params.redirect_uri = "https://evil.example.com/callback".to_string();

        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert!(matches!(outcome, AuthorizeOutcome::DirectError(_)));
    }

    #[tokio::test]
    async fn wrong_code_challenge_method_is_an_error_redirect() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut params = valid_params();
        params.code_challenge_method = "plain".to_string();

        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;
        match outcome {
            AuthorizeOutcome::ErrorRedirect {
                redirect_uri,
                error,
                ..
            } => {
                assert_eq!(redirect_uri, REDIRECT_URI);
                assert_eq!(error, "invalid_request");
            }
            other => panic!("expected ErrorRedirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_code_challenge_is_an_error_redirect() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut params = valid_params();
        params.code_challenge = "too-short".to_string();

        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert!(matches!(outcome, AuthorizeOutcome::ErrorRedirect { .. }));
    }

    #[tokio::test]
    async fn wrong_response_type_is_an_error_redirect() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut params = valid_params();
        params.response_type = "token".to_string();

        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert!(matches!(outcome, AuthorizeOutcome::ErrorRedirect { .. }));
    }

    #[tokio::test]
    async fn empty_client_id_is_an_error_redirect() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut params = valid_params();
        params.client_id = "".to_string();

        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert!(matches!(outcome, AuthorizeOutcome::ErrorRedirect { .. }));
    }

    #[tokio::test]
    async fn already_issued_transaction_is_access_denied_redirect() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Issued);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let params = valid_params();
        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;
        match outcome {
            AuthorizeOutcome::ErrorRedirect { error, .. } => {
                assert_eq!(error, "access_denied");
            }
            other => panic!("expected ErrorRedirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn state_is_omitted_when_absent_from_the_request() {
        let storage = test_storage().await;
        let tx = sample_tx(IssuanceState::Offered);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut params = valid_params();
        params.state = None;

        let outcome = handle_authorize_request(
            &storage,
            &params,
            ISSUER_IDENTIFIER,
            600,
            1_700_000_000,
            &std::collections::BTreeMap::new(),
        )
        .await;
        match outcome {
            AuthorizeOutcome::Success { state, .. } => assert_eq!(state, None),
            other => panic!("expected Success, got {other:?}"),
        }
    }
}
