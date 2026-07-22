//! Token request handling for OpenID4VCI pre-authorized code flow.

use crate::attestation::{DefaultAttestationVerifier, WalletAttestationVerifier};
use crate::error::IssuanceError;
use crate::transaction::{load_transaction_by_pre_auth_code, save_transaction_with_indices};
use foundry_core::config::Mode;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    pub tx_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    if req.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
        return Err(IssuanceError::InvalidGrant("unsupported_grant_type".to_string()));
    }

    let verifier = DefaultAttestationVerifier;
    verifier.verify_wallet_attestation(attestation_mode, attestation_header)?;

    let code = req
        .pre_authorized_code
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing pre-authorized_code".to_string()))?;

    let mut tx = load_transaction_by_pre_auth_code(storage, code)
        .await?
        .ok_or_else(|| IssuanceError::InvalidGrant("invalid or expired pre-authorized_code".to_string()))?;

    if let Some(ref expected_tx_code) = tx.tx_code {
        match req.tx_code.as_deref() {
            Some(supplied) if supplied == expected_tx_code => {}
            _ => return Err(IssuanceError::InvalidGrant("invalid tx_code".to_string())),
        }
    }

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
            pre_authorized_code: "code-123".to_string(),
            tx_code: Some("4242".to_string()),
            status_list_index: Some(7),
            access_token: None,
            c_nonce: None,
            c_nonce_expires_at: None,
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
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
        };

        let res = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap();

        assert_eq!(res.token_type, "Bearer");
        assert!(!res.access_token.is_empty());
        assert!(!res.c_nonce.is_empty());

        let updated_tx = load_transaction(&storage, "tx-tok-1").await.unwrap().unwrap();
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
        };

        let err = handle_token_request(&storage, &req, Mode::Disabled, None, 1_700_000_010)
            .await
            .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
    }
}
