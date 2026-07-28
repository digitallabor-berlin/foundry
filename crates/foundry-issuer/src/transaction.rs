//! Issuance transaction model and `Storage`-backed persistence.

use crate::error::IssuanceError;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};

const NAMESPACE: &str = "issuance_tx";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuanceTransaction {
    pub transaction_id: String,
    pub credential_type_id: String,
    pub claims: serde_json::Map<String, serde_json::Value>,
    pub pre_authorized_code: Option<String>,
    pub tx_code: Option<String>,
    pub status_list_index: Option<u64>,
    pub access_token: Option<String>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_at: Option<i64>,
    pub state: IssuanceState,
    pub created_at: i64,
    /// Redirect URI pinned at `create_offer` time for the authorization_code
    /// grant. `None` for pre-authorized_code offers.
    pub redirect_uri: Option<String>,
    /// Opaque value handed to the wallet in `grants.authorization_code.issuer_state`,
    /// used to resolve this transaction from `/authorize`.
    pub issuer_state: Option<String>,
    /// Single-use authorization code minted by `/authorize`, consumed by `/token`.
    pub authorization_code: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    Offered,
    Issued,
}

/// Persist a transaction with a TTL relative to `now_unix`.
pub async fn save_transaction(
    storage: &dyn Storage,
    tx: &IssuanceTransaction,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    let value =
        serde_json::to_string(tx).map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    let expires_at = now_unix + ttl_secs as i64;
    storage
        .put_kv(NAMESPACE, &tx.transaction_id, &value, Some(expires_at))
        .await?;
    Ok(())
}

/// Load a transaction by id, if present and not yet expired/purged.
pub async fn load_transaction(
    storage: &dyn Storage,
    transaction_id: &str,
) -> Result<Option<IssuanceTransaction>, IssuanceError> {
    let raw = storage.get_kv(NAMESPACE, transaction_id).await?;
    match raw {
        Some(s) => {
            let tx = serde_json::from_str(&s)
                .map_err(|e| IssuanceError::Deserialization(e.to_string()))?;
            Ok(Some(tx))
        }
        None => Ok(None),
    }
}

const PRE_AUTH_NS: &str = "tx_pre_auth";
const ACCESS_TOKEN_NS: &str = "tx_access_token";
const ISSUER_STATE_NS: &str = "tx_issuer_state";
const AUTH_CODE_NS: &str = "tx_auth_code";

/// Persist a transaction along with secondary lookup indices for
/// `pre_authorized_code` (if set), `issuer_state` (if set), and
/// `access_token` (if set).
pub async fn save_transaction_with_indices(
    storage: &dyn Storage,
    tx: &IssuanceTransaction,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    save_transaction(storage, tx, ttl_secs, now_unix).await?;
    let expires_at = now_unix + ttl_secs as i64;
    if let Some(ref code) = tx.pre_authorized_code {
        storage
            .put_kv(PRE_AUTH_NS, code, &tx.transaction_id, Some(expires_at))
            .await?;
    }
    if let Some(ref issuer_state) = tx.issuer_state {
        storage
            .put_kv(
                ISSUER_STATE_NS,
                issuer_state,
                &tx.transaction_id,
                Some(expires_at),
            )
            .await?;
    }
    if let Some(ref token) = tx.access_token {
        storage
            .put_kv(ACCESS_TOKEN_NS, token, &tx.transaction_id, Some(expires_at))
            .await?;
    }
    Ok(())
}

/// Persist a transaction (at its own, unchanged `tx_ttl_secs`) along with a
/// secondary lookup index for `authorization_code` at its own, independent
/// (typically much shorter) TTL — minting a code never shortens the parent
/// transaction's lifetime.
pub async fn save_transaction_with_auth_code(
    storage: &dyn Storage,
    tx: &IssuanceTransaction,
    tx_ttl_secs: u64,
    auth_code_ttl_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    save_transaction(storage, tx, tx_ttl_secs, now_unix).await?;
    if let Some(ref code) = tx.authorization_code {
        let expires_at = now_unix + auth_code_ttl_secs as i64;
        storage
            .put_kv(AUTH_CODE_NS, code, &tx.transaction_id, Some(expires_at))
            .await?;
    }
    Ok(())
}

pub async fn load_transaction_by_pre_auth_code(
    storage: &dyn Storage,
    code: &str,
) -> Result<Option<IssuanceTransaction>, IssuanceError> {
    if let Some(tx_id) = storage.get_kv(PRE_AUTH_NS, code).await? {
        load_transaction(storage, &tx_id).await
    } else {
        Ok(None)
    }
}

pub async fn load_transaction_by_access_token(
    storage: &dyn Storage,
    token: &str,
) -> Result<Option<IssuanceTransaction>, IssuanceError> {
    if let Some(tx_id) = storage.get_kv(ACCESS_TOKEN_NS, token).await? {
        load_transaction(storage, &tx_id).await
    } else {
        Ok(None)
    }
}

pub async fn load_transaction_by_issuer_state(
    storage: &dyn Storage,
    issuer_state: &str,
) -> Result<Option<IssuanceTransaction>, IssuanceError> {
    if let Some(tx_id) = storage.get_kv(ISSUER_STATE_NS, issuer_state).await? {
        load_transaction(storage, &tx_id).await
    } else {
        Ok(None)
    }
}

pub async fn load_transaction_by_authorization_code(
    storage: &dyn Storage,
    code: &str,
) -> Result<Option<IssuanceTransaction>, IssuanceError> {
    if let Some(tx_id) = storage.get_kv(AUTH_CODE_NS, code).await? {
        load_transaction(storage, &tx_id).await
    } else {
        Ok(None)
    }
}

/// Delete the single-use authorization-code secondary index, so a replayed
/// `code` can no longer resolve to this transaction.
pub async fn invalidate_authorization_code(
    storage: &dyn Storage,
    code: &str,
) -> Result<(), IssuanceError> {
    storage.delete_kv(AUTH_CODE_NS, code).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::storage::SqliteStorage;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        // Leak the tempdir so the file isn't removed before the async test body runs.
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

    fn sample_auth_code_tx(id: &str) -> IssuanceTransaction {
        let mut tx = sample_tx(id);
        tx.pre_authorized_code = None;
        tx.tx_code = None;
        tx.redirect_uri = Some("eudi-openid4ci://authorize".to_string());
        tx.issuer_state = Some("issuer-state-xyz".to_string());
        tx
    }

    #[tokio::test]
    async fn save_and_load_round_trips() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-1");
        save_transaction(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let loaded = load_transaction(&storage, "tx-1").await.unwrap().unwrap();
        assert_eq!(loaded, tx);
    }

    #[tokio::test]
    async fn load_missing_transaction_returns_none() {
        let storage = test_storage().await;
        let loaded = load_transaction(&storage, "does-not-exist").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn lookup_by_pre_auth_code_and_access_token_round_trips() {
        let storage = test_storage().await;
        let mut tx = sample_tx("tx-auth-1");
        tx.access_token = Some("bearer-token-xyz".to_string());
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let loaded_by_code = load_transaction_by_pre_auth_code(&storage, "code-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded_by_code.transaction_id, "tx-auth-1");

        let loaded_by_token = load_transaction_by_access_token(&storage, "bearer-token-xyz")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded_by_token.transaction_id, "tx-auth-1");
    }

    #[tokio::test]
    async fn lookup_by_issuer_state_round_trips_for_authorization_code_offers() {
        let storage = test_storage().await;
        let tx = sample_auth_code_tx("tx-authz-1");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let loaded = load_transaction_by_issuer_state(&storage, "issuer-state-xyz")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.transaction_id, "tx-authz-1");
        assert_eq!(
            loaded.redirect_uri,
            Some("eudi-openid4ci://authorize".to_string())
        );
    }

    #[tokio::test]
    async fn lookup_by_issuer_state_returns_none_for_unknown_value() {
        let storage = test_storage().await;
        let loaded = load_transaction_by_issuer_state(&storage, "no-such-state")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn save_transaction_with_indices_does_not_index_absent_pre_auth_code() {
        let storage = test_storage().await;
        let tx = sample_auth_code_tx("tx-authz-2");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        // No pre_authorized_code was set, so there is nothing to look up by
        // the sample pre-auth code value used elsewhere in this file.
        let loaded = load_transaction_by_pre_auth_code(&storage, "code-123")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn lookup_by_authorization_code_round_trips() {
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-authz-3");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        tx.authorization_code = Some("authz-code-abc".to_string());
        tx.code_challenge = Some("challenge-abc".to_string());
        tx.code_challenge_method = Some("S256".to_string());
        save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_100)
            .await
            .unwrap();

        let loaded = load_transaction_by_authorization_code(&storage, "authz-code-abc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.transaction_id, "tx-authz-3");
        assert_eq!(loaded.code_challenge, Some("challenge-abc".to_string()));
    }

    #[tokio::test]
    async fn invalidate_authorization_code_removes_the_lookup_index() {
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-authz-4");
        tx.authorization_code = Some("authz-code-def".to_string());
        save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        invalidate_authorization_code(&storage, "authz-code-def")
            .await
            .unwrap();

        let loaded = load_transaction_by_authorization_code(&storage, "authz-code-def")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn minting_an_auth_code_does_not_shorten_the_parent_transactions_ttl() {
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-authz-5");
        let now = 1_700_000_000;
        // Main transaction created with a long TTL...
        save_transaction_with_indices(&storage, &tx, 10_000, now)
            .await
            .unwrap();

        // ...then, later, an authorization code is minted with a short TTL.
        tx.authorization_code = Some("authz-code-ghi".to_string());
        save_transaction_with_auth_code(&storage, &tx, 10_000, 300, now)
            .await
            .unwrap();

        // Advance past the auth-code TTL but well before the transaction TTL.
        storage.purge_expired(now + 301).await.unwrap();

        let by_id = load_transaction(&storage, "tx-authz-5").await.unwrap();
        assert!(
            by_id.is_some(),
            "parent transaction must survive past the short auth-code TTL"
        );

        let by_code = load_transaction_by_authorization_code(&storage, "authz-code-ghi")
            .await
            .unwrap();
        assert!(
            by_code.is_none(),
            "the short-lived auth-code index must be purged"
        );
    }
}
