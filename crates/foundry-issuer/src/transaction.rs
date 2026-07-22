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
        let loaded = load_transaction(&storage, "does-not-exist")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }
}