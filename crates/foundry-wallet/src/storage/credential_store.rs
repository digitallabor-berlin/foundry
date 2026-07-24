//! Per-credential on-disk storage: `credentials/<id>/{credential.sdjwt,
//! payload.json, holder_key.pem, metadata.json}`.

use crate::error::{WalletError, WalletResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub vct: String,
    pub issuer: String,
    pub received_at: String,
    pub status_list_uri: Option<String>,
    pub status_list_idx: Option<u64>,
    pub disclosed_claims: Vec<String>,
    pub trust_valid: Option<bool>,
    pub holder_key_path: String,
}

pub struct NewCredential<'a> {
    pub credential_id: &'a str,
    pub compact_sdjwt: &'a str,
    /// `{"header": ..., "payload": ..., "disclosed_claims": {"given_name": "Alice", ...}}`
    pub decoded_payload: &'a serde_json::Value,
    pub holder_key_pem: &'a [u8],
    pub metadata: &'a CredentialMetadata,
}

fn credential_dir(data_dir: &Path, credential_id: &str) -> PathBuf {
    data_dir.join("credentials").join(credential_id)
}

fn write_file(path: &Path, bytes: &[u8]) -> WalletResult<()> {
    std::fs::write(path, bytes).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })
}

fn read_to_string(path: &Path) -> WalletResult<String> {
    std::fs::read_to_string(path).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })
}

pub fn store_credential(data_dir: &Path, new: &NewCredential<'_>) -> WalletResult<()> {
    let dir = credential_dir(data_dir, new.credential_id);
    std::fs::create_dir_all(&dir).map_err(|e| WalletError::Storage {
        path: dir.display().to_string(),
        source: e,
    })?;
    write_file(&dir.join("credential.sdjwt"), new.compact_sdjwt.as_bytes())?;
    write_file(
        &dir.join("payload.json"),
        serde_json::to_string_pretty(new.decoded_payload)?.as_bytes(),
    )?;
    write_file(&dir.join("holder_key.pem"), new.holder_key_pem)?;
    write_file(
        &dir.join("metadata.json"),
        serde_json::to_string_pretty(new.metadata)?.as_bytes(),
    )?;
    Ok(())
}

pub fn load_metadata(data_dir: &Path, credential_id: &str) -> WalletResult<CredentialMetadata> {
    let text = read_to_string(&credential_dir(data_dir, credential_id).join("metadata.json"))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn load_payload(data_dir: &Path, credential_id: &str) -> WalletResult<serde_json::Value> {
    let text = read_to_string(&credential_dir(data_dir, credential_id).join("payload.json"))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn load_holder_key_pem(data_dir: &Path, credential_id: &str) -> WalletResult<Vec<u8>> {
    let path = credential_dir(data_dir, credential_id).join("holder_key.pem");
    std::fs::read(&path).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })
}

pub fn load_compact_sdjwt(data_dir: &Path, credential_id: &str) -> WalletResult<String> {
    read_to_string(&credential_dir(data_dir, credential_id).join("credential.sdjwt"))
}

/// All stored credentials' metadata, oldest-`received_at`-first.
pub fn list_credentials(data_dir: &Path) -> WalletResult<Vec<CredentialMetadata>> {
    let creds_dir = data_dir.join("credentials");
    let mut out = Vec::new();
    if !creds_dir.exists() {
        return Ok(out);
    }
    let entries = std::fs::read_dir(&creds_dir).map_err(|e| WalletError::Storage {
        path: creds_dir.display().to_string(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| WalletError::Storage {
            path: creds_dir.display().to_string(),
            source: e,
        })?;
        if entry.path().is_dir() {
            if let Some(id) = entry.file_name().to_str() {
                out.push(load_metadata(data_dir, id)?);
            }
        }
    }
    out.sort_by(|a, b| a.received_at.cmp(&b.received_at));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata(id: &str, received_at: &str) -> CredentialMetadata {
        CredentialMetadata {
            credential_id: id.to_string(),
            vct: "https://issuer.example.com/vct/pid".to_string(),
            issuer: "https://issuer.example.com".to_string(),
            received_at: received_at.to_string(),
            status_list_uri: Some("https://issuer.example.com/statuslists/1".to_string()),
            status_list_idx: Some(0),
            disclosed_claims: vec!["given_name".to_string()],
            trust_valid: Some(true),
            holder_key_path: "holder_key.pem".to_string(),
        }
    }

    #[test]
    fn store_then_load_round_trips_all_four_files() {
        let dir = tempfile::tempdir().unwrap();
        let metadata = sample_metadata("cred_1", "2026-07-24T10:00:00Z");
        let payload = serde_json::json!({
            "header": {"alg": "ES256"},
            "payload": {"vct": metadata.vct},
            "disclosed_claims": {"given_name": "Alice"}
        });
        let new = NewCredential {
            credential_id: "cred_1",
            compact_sdjwt: "abc.def.ghi~disclosure~",
            decoded_payload: &payload,
            holder_key_pem: b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
            metadata: &metadata,
        };
        store_credential(dir.path(), &new).unwrap();

        assert_eq!(
            load_compact_sdjwt(dir.path(), "cred_1").unwrap(),
            "abc.def.ghi~disclosure~"
        );
        assert_eq!(load_payload(dir.path(), "cred_1").unwrap(), payload);
        assert_eq!(
            load_holder_key_pem(dir.path(), "cred_1").unwrap(),
            new.holder_key_pem
        );
        assert_eq!(load_metadata(dir.path(), "cred_1").unwrap(), metadata);
    }

    #[test]
    fn list_credentials_sorts_by_received_at_and_is_empty_when_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(list_credentials(dir.path()).unwrap().is_empty());

        let payload = serde_json::json!({});
        for (id, ts) in [
            ("cred_b", "2026-07-24T11:00:00Z"),
            ("cred_a", "2026-07-24T09:00:00Z"),
        ] {
            let metadata = sample_metadata(id, ts);
            store_credential(
                dir.path(),
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
        let list = list_credentials(dir.path()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].credential_id, "cred_a");
        assert_eq!(list[1].credential_id, "cred_b");
    }

    #[test]
    fn load_metadata_on_missing_credential_errors_as_storage() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_metadata(dir.path(), "nonexistent").unwrap_err();
        assert_eq!(err.kind(), "storage");
    }
}
