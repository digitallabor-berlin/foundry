//! Token request handling for OpenID4VCI pre-authorized code and
//! authorization_code flows.

use crate::attestation::{DefaultAttestationVerifier, WalletAttestationVerifier};
use crate::error::IssuanceError;
use crate::transaction::{
    invalidate_authorization_code, load_transaction_by_access_token,
    load_transaction_by_authorization_code, load_transaction_by_pre_auth_code,
    save_transaction_with_indices, IssuanceState, IssuanceTransaction,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use foundry_core::config::Mode;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    pub tx_code: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}

pub async fn handle_token_request(
    storage: &dyn Storage,
    req: &TokenRequest,
    attestation_mode: Mode,
    attestation_header: Option<&str>,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let verifier = DefaultAttestationVerifier;
    verifier.verify_wallet_attestation(attestation_mode, attestation_header)?;

    match req.grant_type.as_str() {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
            handle_pre_authorized_code_grant(storage, req, now_unix).await
        }
        "authorization_code" => handle_authorization_code_grant(storage, req, now_unix).await,
        _ => Err(IssuanceError::InvalidGrant(
            "unsupported_grant_type".to_string(),
        )),
    }
}

async fn handle_pre_authorized_code_grant(
    storage: &dyn Storage,
    req: &TokenRequest,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let code = req
        .pre_authorized_code
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing pre-authorized_code".to_string()))?;

    let tx = load_transaction_by_pre_auth_code(storage, code)
        .await?
        .ok_or_else(|| {
            IssuanceError::InvalidGrant("invalid or expired pre-authorized_code".to_string())
        })?;

    if tx.state == IssuanceState::Issued {
        return Err(IssuanceError::InvalidGrant(
            "credential offer has already been claimed".to_string(),
        ));
    }

    if let Some(ref expected_tx_code) = tx.tx_code {
        match req.tx_code.as_deref() {
            Some(supplied) if supplied == expected_tx_code => {}
            _ => return Err(IssuanceError::InvalidGrant("invalid tx_code".to_string())),
        }
    }

    mint_and_save_tokens(storage, tx, now_unix).await
}

/// RFC 7636 §4.6: `code_challenge == BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`.
/// The issuer only ever stores `code_challenge_method: "S256"` (enforced at
/// `/authorize` time), so this is the only comparison needed here.
fn code_verifier_matches(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == code_challenge
}

async fn handle_authorization_code_grant(
    storage: &dyn Storage,
    req: &TokenRequest,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let code = req
        .code
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing code".to_string()))?;

    let tx = load_transaction_by_authorization_code(storage, code)
        .await?
        .ok_or_else(|| IssuanceError::InvalidGrant("invalid or expired code".to_string()))?;

    if tx.state == IssuanceState::Issued {
        return Err(IssuanceError::InvalidGrant(
            "credential offer has already been claimed".to_string(),
        ));
    }

    if req.redirect_uri.as_deref() != tx.redirect_uri.as_deref() {
        return Err(IssuanceError::InvalidGrant(
            "redirect_uri does not match the authorization request".to_string(),
        ));
    }

    let code_challenge = tx
        .code_challenge
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing code_challenge".to_string()))?;
    let code_verifier = req
        .code_verifier
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing code_verifier".to_string()))?;
    if !code_verifier_matches(code_verifier, code_challenge) {
        return Err(IssuanceError::InvalidGrant(
            "code_verifier does not match code_challenge".to_string(),
        ));
    }

    // Only invalidate the code once it has fully passed validation: an
    // attacker probing with a wrong code_verifier must not be able to burn
    // the legitimate holder's code.
    invalidate_authorization_code(storage, code).await?;

    let mut tx = tx;
    tx.authorization_code = None;

    mint_and_save_tokens(storage, tx, now_unix).await
}

/// Shared by both grant branches: mint a fresh access_token/c_nonce pair,
/// persist them on `tx`, and return the wire `TokenResponse`. Identical
/// `TokenResponse` shape regardless of which grant produced it.
async fn mint_and_save_tokens(
    storage: &dyn Storage,
    mut tx: IssuanceTransaction,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let access_token = format!("at_{}", Uuid::new_v4().simple());
    let c_nonce = format!("cn_{}", Uuid::new_v4().simple());
    let expires_in = 600u64;
    let c_nonce_expires_in = 600u64;

    tx.access_token = Some(access_token.clone());
    tx.c_nonce = Some(c_nonce.clone());
    tx.c_nonce_expires_at = Some(now_unix + c_nonce_expires_in as i64);

    save_transaction_with_indices(storage, &tx, expires_in, now_unix).await?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        c_nonce,
        c_nonce_expires_in,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct NonceResponse {
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}

/// Mint a fresh c_nonce for an already-authorized transaction (identified by its
/// bearer access_token) and persist it so a subsequent `/credential` call using
/// that nonce in its proof JWT is accepted.
///
/// Returns `IssuanceError::InvalidGrant` if the access_token is unknown/expired
/// or the underlying transaction has already been issued.
pub async fn refresh_c_nonce(
    storage: &dyn Storage,
    access_token: &str,
    now_unix: i64,
) -> Result<NonceResponse, IssuanceError> {
    let mut tx = load_transaction_by_access_token(storage, access_token)
        .await?
        .ok_or_else(|| {
            IssuanceError::InvalidGrant("invalid or expired access_token".to_string())
        })?;

    if tx.state == IssuanceState::Issued {
        return Err(IssuanceError::InvalidGrant(
            "credential offer has already been claimed".to_string(),
        ));
    }

    let c_nonce = format!("cn_{}", Uuid::new_v4().simple());
    let c_nonce_expires_in = 600u64;

    tx.c_nonce = Some(c_nonce.clone());
    tx.c_nonce_expires_at = Some(now_unix + c_nonce_expires_in as i64);

    save_transaction_with_indices(storage, &tx, 600, now_unix).await?;

    Ok(NonceResponse {
        c_nonce,
        c_nonce_expires_in,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{load_transaction, IssuanceState, IssuanceTransaction};
    use foundry_core::storage::SqliteStorage;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    fn sample_tx(id: &str) -> IssuanceTransaction {
        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));
        IssuanceTransaction {
            transaction_id: id.to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            status_list_index: Some(7),
            access_token: None,
            c_nonce: None,
            c_nonce_expires_at: None,
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
        }
    }

    #[tokio::test]
    async fn handles_valid_token_request_and_issues_access_token_and_nonce() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-tok-1");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
        };

        let res = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap();

        assert_eq!(res.token_type, "Bearer");
        assert!(!res.access_token.is_empty());
        assert!(!res.c_nonce.is_empty());

        let updated_tx = load_transaction(&storage, "tx-tok-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_tx.access_token.unwrap(), res.access_token);
        assert_eq!(updated_tx.c_nonce.unwrap(), res.c_nonce);
    }

    #[tokio::test]
    async fn rejects_invalid_tx_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-tok-2");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("wrong".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
        };

        let err = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn rejects_token_request_for_already_issued_transaction() {
        let storage = test_storage().await;
        let mut tx = sample_tx("tx-tok-issued");
        tx.state = IssuanceState::Issued;
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
        };

        let err = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
        assert!(err.to_string().contains("already been claimed"));
    }

    #[tokio::test]
    async fn refresh_c_nonce_mints_and_persists_a_new_nonce() {
        let storage = test_storage().await;
        let mut tx = sample_tx("tx-nonce-1");
        tx.access_token = Some("at_existing_token".to_string());
        tx.c_nonce = Some("cn_stale".to_string());
        tx.c_nonce_expires_at = Some(1_700_000_100);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let res = refresh_c_nonce(&storage, "at_existing_token", 1_700_000_050)
            .await
            .unwrap();

        assert!(!res.c_nonce.is_empty());
        assert_ne!(res.c_nonce, "cn_stale");
        assert_eq!(res.c_nonce_expires_in, 600);

        let updated_tx = load_transaction(&storage, "tx-nonce-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_tx.c_nonce.unwrap(), res.c_nonce);
        assert_eq!(updated_tx.c_nonce_expires_at.unwrap(), 1_700_000_050 + 600);
    }

    #[tokio::test]
    async fn refresh_c_nonce_rejects_unknown_access_token() {
        let storage = test_storage().await;

        let err = refresh_c_nonce(&storage, "at_does_not_exist", 1_700_000_050)
            .await
            .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
    }

    const REDIRECT_URI: &str = "eudi-openid4ci://authorize";
    const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn s256_code_challenge(verifier: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use sha2::{Digest, Sha256};
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    fn sample_auth_code_tx(id: &str) -> IssuanceTransaction {
        let mut tx = sample_tx(id);
        tx.pre_authorized_code = None;
        tx.tx_code = None;
        tx.redirect_uri = Some(REDIRECT_URI.to_string());
        tx.issuer_state = Some("issuer-state-tok".to_string());
        tx.authorization_code = Some("authz-code-xyz".to_string());
        tx.code_challenge = Some(s256_code_challenge(CODE_VERIFIER));
        tx.code_challenge_method = Some("S256".to_string());
        tx
    }

    fn auth_code_req() -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            pre_authorized_code: None,
            tx_code: None,
            code: Some("authz-code-xyz".to_string()),
            redirect_uri: Some(REDIRECT_URI.to_string()),
            client_id: Some("wallet-dev".to_string()),
            code_verifier: Some(CODE_VERIFIER.to_string()),
        }
    }

    #[tokio::test]
    async fn authorization_code_grant_happy_path_issues_tokens_and_burns_the_code() {
        let storage = test_storage().await;
        let tx = sample_auth_code_tx("tx-authz-tok-1");
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let req = auth_code_req();
        let res = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap();

        assert_eq!(res.token_type, "Bearer");
        assert!(!res.access_token.is_empty());
        assert!(!res.c_nonce.is_empty());

        let updated_tx = load_transaction(&storage, "tx-authz-tok-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_tx.access_token.unwrap(), res.access_token);
        assert!(updated_tx.authorization_code.is_none());

        // Replay: the code must no longer resolve to any transaction.
        let replay_err = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_020)
            .await
            .unwrap_err();
        assert!(matches!(replay_err, IssuanceError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_wrong_code_verifier() {
        let storage = test_storage().await;
        let tx = sample_auth_code_tx("tx-authz-tok-2");
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let mut req = auth_code_req();
        req.code_verifier = Some("totally-wrong-verifier-value-1234567890".to_string());

        let err = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidGrant(_)));

        // The code must still be usable afterward: a failed PKCE check must
        // not burn a legitimate holder's code.
        let good_req = auth_code_req();
        handle_token_request(&storage, &good_req, Mode::Disabled, None, 1_700_000_020)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_mismatched_redirect_uri() {
        let storage = test_storage().await;
        let tx = sample_auth_code_tx("tx-authz-tok-3");
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let mut req = auth_code_req();
        req.redirect_uri = Some("https://evil.example.com/callback".to_string());

        let err = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_unknown_code() {
        let storage = test_storage().await;

        let mut req = auth_code_req();
        req.code = Some("no-such-code".to_string());

        let err = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_already_issued_transaction() {
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-authz-tok-4");
        tx.state = IssuanceState::Issued;
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let req = auth_code_req();
        let err = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
        assert!(err.to_string().contains("already been claimed"));
    }

    #[tokio::test]
    async fn pre_authorized_code_regression_still_passes_with_the_shared_helper() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-tok-regression");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
        };

        let res = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap();
        assert!(!res.access_token.is_empty());
    }
}
