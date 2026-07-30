use crate::error::VerificationError;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};

const NAMESPACE: &str = "verification_tx";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Pending,
    Verified,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CheckResult {
    pub check: String,
    pub passed: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VerificationResult {
    pub verified: bool,
    pub checks: Vec<CheckResult>,
    pub claims: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VerificationTransaction {
    pub id: String,
    pub state: VerificationState,
    pub nonce: String,
    pub dcql_query: serde_json::Value,
    pub transport: String,
    pub response_mode: String,
    pub ephem_private_jwk: serde_json::Value,
    pub ephem_public_jwk: serde_json::Value,
    /// `transaction_data` entries **already base64url-encoded** per OpenID4VP
    /// v1.0 §8.4, exactly as advertised to the wallet. Stored encoded so that a
    /// `transaction_data_hashes` check hashes the same bytes that were sent.
    pub transaction_data: Option<Vec<String>>,
    pub result: Option<VerificationResult>,
    pub created_at: i64,
}

pub async fn save_verification_transaction(
    storage: &dyn Storage,
    tx: &VerificationTransaction,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<(), VerificationError> {
    let value =
        serde_json::to_string(tx).map_err(|e| VerificationError::Serialization(e.to_string()))?;
    let expires_at = now_unix + ttl_secs as i64;
    storage
        .put_kv(NAMESPACE, &tx.id, &value, Some(expires_at))
        .await?;
    Ok(())
}

pub async fn load_verification_transaction(
    storage: &dyn Storage,
    id: &str,
) -> Result<Option<VerificationTransaction>, VerificationError> {
    let raw = storage.get_kv(NAMESPACE, id).await?;
    match raw {
        Some(s) => {
            let tx = serde_json::from_str(&s)
                .map_err(|e| VerificationError::Serialization(e.to_string()))?;
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
        let db = dir.path().join("verifier_test.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    fn sample_tx(id: &str) -> VerificationTransaction {
        VerificationTransaction {
            id: id.to_string(),
            state: VerificationState::Pending,
            nonce: "nonce-12345".to_string(),
            dcql_query: serde_json::json!({
                "credentials": [{"id": "c1", "format": "mso_mdoc"}]
            }),
            transport: "direct_post".to_string(),
            response_mode: "direct_post".to_string(),
            ephem_private_jwk: serde_json::json!({"kty": "EC", "crv": "P-256", "d": "test"}),
            ephem_public_jwk: serde_json::json!({"kty": "EC", "crv": "P-256", "x": "test", "y": "test"}),
            transaction_data: Some(vec!["eyJ0eXBlIjoicGF5bWVudCJ9".to_string()]),
            result: None,
            created_at: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn test_save_and_load_verification_transaction_round_trip() {
        let storage = test_storage().await;
        let mut tx = sample_tx("vtx-1");

        save_verification_transaction(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let loaded = load_verification_transaction(&storage, "vtx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded, tx);

        // Update state and result, then save again
        tx.state = VerificationState::Verified;
        tx.result = Some(VerificationResult {
            verified: true,
            checks: vec![CheckResult {
                check: "signature".to_string(),
                passed: true,
                detail: Some("valid signature".to_string()),
            }],
            claims: serde_json::json!({"given_name": "Alice"}),
        });

        save_verification_transaction(&storage, &tx, 600, 1_700_000_005)
            .await
            .unwrap();

        let loaded_updated = load_verification_transaction(&storage, "vtx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded_updated, tx);
        assert_eq!(loaded_updated.state, VerificationState::Verified);
        assert!(loaded_updated.result.unwrap().verified);
    }

    #[tokio::test]
    async fn test_load_non_existent_transaction_returns_none() {
        let storage = test_storage().await;
        let loaded = load_verification_transaction(&storage, "non-existent")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_verification_state_serde() {
        let json_pending = serde_json::to_string(&VerificationState::Pending).unwrap();
        assert_eq!(json_pending, "\"pending\"");

        let json_verified = serde_json::to_string(&VerificationState::Verified).unwrap();
        assert_eq!(json_verified, "\"verified\"");

        let json_failed = serde_json::to_string(&VerificationState::Failed).unwrap();
        assert_eq!(json_failed, "\"failed\"");

        let parsed: VerificationState = serde_json::from_str("\"pending\"").unwrap();
        assert_eq!(parsed, VerificationState::Pending);
    }
}
