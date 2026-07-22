//! Orchestrates offer creation: claim validation, status-index allocation,
//! pre-auth code/tx_code generation, transaction persistence, and offer
//! construction.

use crate::error::IssuanceError;
use crate::offer::{
    build_offer_uri, generate_pre_authorized_code, generate_tx_code, CredentialOffer,
    CredentialOfferGrants, PreAuthorizedCodeGrant, TxCodeDefinition,
};
use crate::status_index::allocate_status_index;
use crate::transaction::{save_transaction, IssuanceState, IssuanceTransaction};
use foundry_core::config::Config;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOfferRequest {
    pub credential_type_id: String,
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub tx_code_required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateOfferResponse {
    pub transaction_id: String,
    pub credential_offer: CredentialOffer,
    pub credential_offer_uri: String,
}

/// Default tx_code length when `tx_code_required` is set (HAIP-typical 4 digits).
const DEFAULT_TX_CODE_LENGTH: usize = 4;

pub async fn create_offer(
    cfg: &Config,
    storage: &dyn Storage,
    req: CreateOfferRequest,
    now_unix: i64,
) -> Result<CreateOfferResponse, IssuanceError> {
    let ct = cfg
        .credential_types
        .iter()
        .find(|c| c.id == req.credential_type_id)
        .ok_or_else(|| IssuanceError::UnknownCredentialType(req.credential_type_id.clone()))?;

    // Every non-selectively-disclosable claim's top-level path segment must
    // be present (nested-path validation is a follow-up — see plan Non-Goals).
    for claim_def in &ct.claims {
        if claim_def.selectively_disclosable {
            continue;
        }
        let top = claim_def.path.first().ok_or_else(|| {
            IssuanceError::ClaimValidation(format!(
                "credential_type '{}' has a claim with an empty path",
                ct.id
            ))
        })?;
        if !req.claims.contains_key(top) {
            return Err(IssuanceError::ClaimValidation(format!(
                "missing required claim '{top}' for credential_type '{}'",
                ct.id
            )));
        }
    }

    let transaction_id = generate_pre_authorized_code();
    let pre_authorized_code = generate_pre_authorized_code();
    let tx_code = if req.tx_code_required {
        Some(generate_tx_code(DEFAULT_TX_CODE_LENGTH))
    } else {
        None
    };

    let status_list_index = if cfg.issuer.status_list.enabled {
        let list_size = cfg.issuer.status_list.list_size.unwrap_or(1_048_576);
        Some(allocate_status_index(storage, &ct.id, list_size).await?)
    } else {
        None
    };

    let tx = IssuanceTransaction {
        transaction_id: transaction_id.clone(),
        credential_type_id: ct.id.clone(),
        claims: req.claims,
        pre_authorized_code: pre_authorized_code.clone(),
        tx_code: tx_code.clone(),
        status_list_index,
        state: IssuanceState::Offered,
        created_at: now_unix,
    };
    save_transaction(storage, &tx, cfg.storage.transaction_ttl_secs, now_unix).await?;

    let offer = CredentialOffer {
        credential_issuer: cfg
            .issuer
            .credential_issuer
            .trim_end_matches('/')
            .to_string(),
        credential_configuration_ids: vec![ct.id.clone()],
        grants: CredentialOfferGrants {
            pre_authorized_code: PreAuthorizedCodeGrant {
                pre_authorized_code,
                tx_code: tx_code.map(|_| TxCodeDefinition {
                    input_mode: "numeric".to_string(),
                    length: DEFAULT_TX_CODE_LENGTH,
                }),
            },
        },
    };
    let credential_offer_uri = build_offer_uri(&offer)?;

    Ok(CreateOfferResponse {
        transaction_id,
        credential_offer: offer,
        credential_offer_uri,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::load_transaction;
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, IssuerConfig, Mode, ServerConfig,
        StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
    };
    use foundry_core::storage::SqliteStorage;
    use std::collections::BTreeMap as StdBTreeMap;

    fn test_config() -> Config {
        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://issuer.example.com".to_string(),
                    bind: "0.0.0.0:8443".to_string(),
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:9000".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "./foundry.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys: StdBTreeMap::new(),
            trust_anchors: Vec::new(),
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                wallet_attestation: AttestationMode {
                    mode: Mode::Optional,
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                },
                status_list: StatusListConfig {
                    enabled: true,
                    signing_key: None,
                    list_size: Some(1024),
                    public_base_url: None,
                },
            },
            credential_types: vec![CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://issuer.example.com/vct/pid".to_string()),
                doctype: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![
                    ClaimDef {
                        path: vec!["birthdate".to_string()],
                        selectively_disclosable: false,
                        display: vec![],
                    },
                    ClaimDef {
                        path: vec!["given_name".to_string()],
                        selectively_disclosable: true,
                        display: vec![],
                    },
                ],
            }],
            verifier: VerifierConfig {
                client_id_scheme: "x509_san_dns".to_string(),
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec![],
                named_queries: vec![],
                webhook: None,
            },
        }
    }

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("c.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn creates_offer_persists_transaction_and_allocates_status_index() {
        let cfg = test_config();
        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

        let req = CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: true,
        };
        let resp = create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        assert_eq!(
            resp.credential_offer.credential_configuration_ids,
            vec!["pid".to_string()]
        );
        assert!(resp
            .credential_offer_uri
            .starts_with("openid-credential-offer://"));

        let tx = load_transaction(&storage, &resp.transaction_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tx.credential_type_id, "pid");
        assert!(tx.status_list_index.is_some());
        assert!(tx.tx_code.is_some());
        assert_eq!(tx.state, IssuanceState::Offered);
    }

    #[tokio::test]
    async fn rejects_unknown_credential_type() {
        let cfg = test_config();
        let storage = test_storage().await;
        let req = CreateOfferRequest {
            credential_type_id: "does-not-exist".to_string(),
            claims: serde_json::Map::new(),
            tx_code_required: false,
        };
        let err = create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::UnknownCredentialType(_)));
    }

    #[tokio::test]
    async fn rejects_missing_required_claim() {
        let cfg = test_config();
        let storage = test_storage().await;
        // `birthdate` is not selectively_disclosable, so it's required and omitted here.
        let req = CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims: serde_json::Map::new(),
            tx_code_required: false,
        };
        let err = create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::ClaimValidation(_)));
    }

    #[tokio::test]
    async fn skips_status_index_allocation_when_disabled() {
        let mut cfg = test_config();
        cfg.issuer.status_list.enabled = false;
        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));
        let req = CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: false,
        };
        let resp = create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap();
        let tx = load_transaction(&storage, &resp.transaction_id)
            .await
            .unwrap()
            .unwrap();
        assert!(tx.status_list_index.is_none());
        assert!(tx.tx_code.is_none());
    }
}
