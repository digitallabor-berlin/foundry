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
    pub pre_authorized_code: String,
    pub tx_code: Option<String>,
    pub status_list_index: Option<u64>,
    pub access_token: Option<String>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_at: Option<i64>,
    pub state: IssuanceState,
    pub created_at: i64,
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

/// Persist a transaction along with secondary lookup indices for pre_authorized_code and access_token.
pub async fn save_transaction_with_indices(
    storage: &dyn Storage,
    tx: &IssuanceTransaction,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    save_transaction(storage, tx, ttl_secs, now_unix).await?;
    let expires_at = now_unix + ttl_secs as i64;
    storage
        .put_kv(
            PRE_AUTH_NS,
            &tx.pre_authorized_code,
            &tx.transaction_id,
            Some(expires_at),
        )
        .await?;
    if let Some(ref token) = tx.access_token {
        storage
            .put_kv(ACCESS_TOKEN_NS, token, &tx.transaction_id, Some(expires_at))
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
}
