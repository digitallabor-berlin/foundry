//! Matches stored SD-JWT VC credentials against a DCQL query's
//! `credentials[]` entries, reusing the verifier's own satisfaction-checking
//! logic (`foundry_verifier::check_dcql_match`) so wallet-side "will this
//! request succeed" matches server-side "did this presentation satisfy the
//! query" exactly.

use crate::error::{WalletError, WalletResult};
use crate::storage::credential_store::{list_credentials, load_payload};
use foundry_verifier::{check_dcql_match, PresentedFormat};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct MatchedCredential {
    pub query_id: String,
    pub credential_id: String,
    pub disclosed_claims: serde_json::Value,
}

/// For each `dcql_query.credentials[]` entry, find the most-recently-received
/// stored credential whose disclosed claims satisfy it (per
/// `check_dcql_match`). Errors if any entry has no match.
pub fn match_credentials(
    data_dir: &Path,
    dcql_query: &serde_json::Value,
) -> WalletResult<Vec<MatchedCredential>> {
    let entries = dcql_query
        .get("credentials")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            WalletError::MalformedRequestObject(
                "dcql_query.credentials is missing or not an array".to_string(),
            )
        })?;

    // Newest-first so the first satisfying credential found per entry is the
    // most recently received one.
    let mut stored = list_credentials(data_dir)?;
    stored.reverse();

    let mut out = Vec::new();
    for entry in entries {
        let query_id = entry
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let single_entry_query = serde_json::json!({ "credentials": [entry] });

        let mut found = None;
        for metadata in &stored {
            let payload = load_payload(data_dir, &metadata.credential_id)?;
            // `check_dcql_match` expects the FULL merged claims set (matching
            // what the real verifier passes it: the issuer JWT payload's
            // always-disclosed claims, e.g. `vct`, merged with every
            // selectively-disclosed claim) — not just the selectively
            // disclosed subset. Start from the issuer JWT payload and overlay
            // the selectively-disclosed claims on top, mirroring
            // `foundry_verifier::verify::verify_vp_response`'s construction of
            // `claims_value`.
            let mut merged_claims = payload
                .get("payload")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            if let (Some(base), Some(disclosed)) = (
                merged_claims.as_object_mut(),
                payload.get("disclosed_claims").and_then(|v| v.as_object()),
            ) {
                for (k, v) in disclosed {
                    base.insert(k.clone(), v.clone());
                }
            }
            let disclosed_claims = merged_claims;
            let result = check_dcql_match(
                &single_entry_query,
                PresentedFormat::SdJwtVc,
                &disclosed_claims,
                None,
            );
            if result.passed {
                found = Some(MatchedCredential {
                    query_id: query_id.clone(),
                    credential_id: metadata.credential_id.clone(),
                    disclosed_claims,
                });
                break;
            }
        }

        match found {
            Some(m) => out.push(m),
            None => return Err(WalletError::NoMatchingCredential),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::credential_store::{store_credential, CredentialMetadata, NewCredential};

    fn store_test_credential(
        data_dir: &Path,
        id: &str,
        received_at: &str,
        vct: &str,
        mut claims: serde_json::Value,
    ) {
        // Ensure vct is in disclosed_claims (required for DCQL validation)
        if let Some(obj) = claims.as_object_mut() {
            obj.insert(
                "vct".to_string(),
                serde_json::Value::String(vct.to_string()),
            );
        }

        let payload = serde_json::json!({
            "header": {"alg": "ES256"},
            "payload": {"vct": vct},
            "disclosed_claims": claims,
        });
        let metadata = CredentialMetadata {
            credential_id: id.to_string(),
            vct: vct.to_string(),
            issuer: "https://issuer.example.com".to_string(),
            received_at: received_at.to_string(),
            status_list_uri: None,
            status_list_idx: None,
            disclosed_claims: claims
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default(),
            trust_valid: Some(true),
            holder_key_path: "holder_key.pem".to_string(),
        };
        store_credential(
            data_dir,
            &NewCredential {
                credential_id: id,
                compact_sdjwt: "x",
                decoded_payload: &payload,
                holder_key_pem: b"key",
                metadata: &metadata,
            },
        )
        .unwrap();
    }

    fn sample_query() -> serde_json::Value {
        serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://issuer.example.com/vct/pid"] },
                "claims": [{ "path": ["given_name"] }]
            }]
        })
    }

    #[test]
    fn matches_a_stored_credential_satisfying_the_query() {
        let dir = tempfile::tempdir().unwrap();
        store_test_credential(
            dir.path(),
            "cred_1",
            "2026-07-24T10:00:00Z",
            "https://issuer.example.com/vct/pid",
            serde_json::json!({"given_name": "Alice"}),
        );

        let matches = match_credentials(dir.path(), &sample_query()).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].query_id, "c1");
        assert_eq!(matches[0].credential_id, "cred_1");
    }

    #[test]
    fn picks_the_most_recently_received_match() {
        let dir = tempfile::tempdir().unwrap();
        store_test_credential(
            dir.path(),
            "cred_old",
            "2026-07-24T09:00:00Z",
            "https://issuer.example.com/vct/pid",
            serde_json::json!({"given_name": "Alice"}),
        );
        store_test_credential(
            dir.path(),
            "cred_new",
            "2026-07-24T11:00:00Z",
            "https://issuer.example.com/vct/pid",
            serde_json::json!({"given_name": "Bob"}),
        );

        let matches = match_credentials(dir.path(), &sample_query()).unwrap();
        assert_eq!(matches[0].credential_id, "cred_new");
    }

    #[test]
    fn errors_with_no_matching_credential_when_vct_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        store_test_credential(
            dir.path(),
            "cred_1",
            "2026-07-24T10:00:00Z",
            "https://issuer.example.com/vct/other",
            serde_json::json!({"given_name": "Alice"}),
        );

        let err = match_credentials(dir.path(), &sample_query()).unwrap_err();
        assert_eq!(err.kind(), "no_matching_credential");
    }

    #[test]
    fn errors_with_no_matching_credential_when_claim_missing() {
        let dir = tempfile::tempdir().unwrap();
        store_test_credential(
            dir.path(),
            "cred_1",
            "2026-07-24T10:00:00Z",
            "https://issuer.example.com/vct/pid",
            serde_json::json!({"family_name": "Smith"}),
        );

        let err = match_credentials(dir.path(), &sample_query()).unwrap_err();
        assert_eq!(err.kind(), "no_matching_credential");
    }
}
