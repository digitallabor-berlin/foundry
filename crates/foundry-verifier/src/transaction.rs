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

/// One credential presented in a `vp_token`, with the checks run against it and
/// the claims it disclosed.
///
/// Claims are held **per credential** and never merged into a single map.
/// Merging is not a presentation choice but a correctness bug: `check_status`
/// reads `status.status_list` out of the map it is handed, so a merged map lets
/// one credential's `status` claim displace another's and runs a revocation
/// check against the wrong status list -- silently, with a passing
/// `status_check`. Two credentials disclosing the same claim name collide the
/// same way.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PresentedCredential {
    /// The DCQL credential query id this presentation answered
    /// (OpenID4VP 1.0 L1166).
    pub query_id: String,
    /// The credential format the answered query **declared**: `dc+sd-jwt` or
    /// `mso_mdoc`. Never inferred from the payload's JSON type.
    pub format: String,
    /// The credential type the presentation **asserts**: `vct` for `dc+sd-jwt`
    /// (IETF SD-JWT VC), `docType` for `mso_mdoc` (ISO/IEC 18013-5).
    ///
    /// Extracted BEFORE the format-specific signature check, so it survives a
    /// failure -- a failed credential an operator cannot name is the defect this
    /// field exists to fix. It is therefore only *authenticated* when that check
    /// passed, exactly the caveat that already governs `claims`; on the mdoc
    /// success path it is replaced with the MSO's authenticated `docType`.
    ///
    /// `None` when the presentation could not be decoded far enough to read a
    /// type at all.
    pub credential_type: Option<String>,
    /// This credential's disclosed claims only.
    pub claims: serde_json::Value,
    /// Checks scoped to this credential: its format-specific signature check,
    /// `dcql_match`, `status_check`, and `transaction_data_binding` when the
    /// request carried `transaction_data`.
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VerificationResult {
    pub verified: bool,
    /// **Cross-cutting checks only** -- `jwe_decryption` and
    /// `requested_credentials_answered`. Per-credential checks live in
    /// `credentials[i].checks`.
    pub checks: Vec<CheckResult>,
    /// One entry per credential the `vp_token` answered, in DCQL declaration
    /// order (not `vp_token` key order, which depends on serde_json's map type).
    pub credentials: Vec<PresentedCredential>,
}

impl VerificationResult {
    /// Every `CheckResult` in this result: the top-level `checks` followed by
    /// each credential's `checks`.
    ///
    /// Root AGENTS.md §4.2 requires `verified` to be the conjunction over **all**
    /// of these. Iterating only `self.checks` is satisfiable while a
    /// per-credential check fails, so use this rather than `self.checks` anywhere
    /// the question is "did everything pass".
    pub fn all_checks(&self) -> impl Iterator<Item = &CheckResult> {
        self.checks
            .iter()
            .chain(self.credentials.iter().flat_map(|c| c.checks.iter()))
    }

    /// The §4.2 verdict, derived. Never assign `verified` a literal; assign this.
    pub fn derive_verified(&self) -> bool {
        self.all_checks().all(|c| c.passed)
    }
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
            credentials: vec![PresentedCredential {
                query_id: "c1".to_string(),
                format: "dc+sd-jwt".to_string(),
                // A real value, not a reflexive `None`: this asserts the new
                // field survives a storage round trip.
                credential_type: Some("https://example.test/vct/pid".to_string()),
                claims: serde_json::json!({"given_name": "Alice"}),
                checks: Vec::new(),
            }],
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

    /// Root AGENTS.md §4.2 after multi-credential support: `verified` MUST equal
    /// the conjunction over EVERY `CheckResult` in the result -- the top-level
    /// `checks` AND every `credentials[i].checks` entry. Checking only
    /// `self.checks` is satisfiable while a per-credential check fails, which is
    /// precisely the defect these helpers exist to make unrepresentable.
    #[test]
    fn all_checks_spans_both_levels_and_derives_the_verdict() {
        let pass = |name: &str| CheckResult {
            check: name.to_string(),
            passed: true,
            detail: None,
        };

        let mut result = VerificationResult {
            verified: false,
            checks: vec![pass("jwe_decryption")],
            credentials: vec![
                PresentedCredential {
                    query_id: "pid".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    credential_type: Some("https://example.test/vct/pid".to_string()),
                    claims: serde_json::json!({"given_name": "Alice"}),
                    checks: vec![pass("sd_jwt_vc_signature_and_kb_jwt"), pass("dcql_match")],
                },
                PresentedCredential {
                    query_id: "mdl".to_string(),
                    format: "mso_mdoc".to_string(),
                    credential_type: Some("org.iso.18013.5.1.mDL".to_string()),
                    claims: serde_json::json!({}),
                    checks: vec![pass("mdoc_issuer_auth_and_device_signature")],
                },
            ],
        };

        assert_eq!(
            result.all_checks().count(),
            4,
            "all_checks must span the top level and every credential"
        );
        assert!(result.derive_verified(), "every check passed");

        // A failure buried in the SECOND credential must still sink the verdict.
        // A top-level-only `all(passed)` would report this result as verified.
        result.credentials[1].checks[0].passed = false;
        assert!(
            !result.derive_verified(),
            "a failed per-credential check must sink the overall verdict"
        );
        assert!(
            result.checks.iter().all(|c| c.passed),
            "and it must do so even though every TOP-LEVEL check still passes -- \
             this is the case a single-level all(passed) gets wrong"
        );
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
