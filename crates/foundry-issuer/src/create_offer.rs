//! Orchestrates offer creation: claim validation, status-index allocation,
//! pre-auth code/tx_code generation, transaction persistence, and offer
//! construction.

use crate::error::IssuanceError;
use crate::offer::{
    build_dc_api_offer, build_offer_uri, generate_pre_authorized_code, generate_tx_code,
    AuthorizationCodeGrant, CredentialOffer, CredentialOfferGrants, PreAuthorizedCodeGrant,
    TxCodeDefinition,
};
use crate::status_index::allocate_status_index;
use crate::transaction::{save_transaction_with_indices, IssuanceState, IssuanceTransaction};
use foundry_core::config::Config;
use foundry_core::status_list::{load_status_list, save_status_list, PersistentStatusList};
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateOfferRequest {
    pub credential_type_id: String,
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub tx_code_required: bool,
    /// When set, requests an `authorization_code` grant offer (mutually
    /// exclusive with `tx_code_required`) bound to this exact redirect URI.
    /// When `None` (default), the existing `pre-authorized_code` grant is
    /// used, unchanged.
    #[serde(default)]
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateOfferResponse {
    pub transaction_id: String,
    pub credential_offer: CredentialOffer,
    pub credential_offer_uri: String,
    /// The same offer rendered for the W3C Digital Credentials API
    /// (`navigator.credentials.create()`, protocol `openid4vci-v1`) — see
    /// [`build_dc_api_offer`].
    ///
    /// Not `Option`, unlike the verifier's `dc_api_request`: issuance has no
    /// transport fork, so this is always derivable from the offer that was just
    /// built. The caller picks a transport by choosing which field to use.
    #[schema(value_type = Object)]
    pub dc_api_offer: serde_json::Value,
}

/// Default tx_code length when `tx_code_required` is set (HAIP-typical 4 digits).
const DEFAULT_TX_CODE_LENGTH: usize = 4;

/// `skip_all` is mandatory: `req` carries the claim values to be issued and the
/// optional transaction code.
#[tracing::instrument(
    skip_all,
    fields(
        credential_type_id = %req.credential_type_id,
        tx_code_required = req.tx_code_required,
        // A redirect URI means an authorization_code grant; the URI itself is
        // caller-supplied, so only its presence is recorded.
        authorization_code_grant = req.redirect_uri.is_some(),
    )
)]
pub async fn create_offer(
    cfg: &Config,
    storage: &dyn Storage,
    req: CreateOfferRequest,
    now_unix: i64,
) -> Result<CreateOfferResponse, IssuanceError> {
    if req.redirect_uri.is_some() && req.tx_code_required {
        return Err(IssuanceError::InvalidRequest(
            "tx_code_required is only valid for the pre-authorized_code grant".to_string(),
        ));
    }

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

    let status_list_index = if cfg.issuer.status_list.enabled {
        let list_size = cfg.issuer.status_list.list_size.unwrap_or(1_048_576);
        // The embedded status URI is always ".../1" (see credential.rs) regardless
        // of credential_type_id — every credential type shares this one physical
        // list. Ensure the backing PersistentStatusList exists under that same
        // literal key "1" before any credential can reference it.
        // TODO(concurrency): this check-then-create is not atomic, matching the
        // same class of race already documented in allocate_status_index below;
        // acceptable for this phase's single-process dev deployment.
        const STATUS_LIST_ID: &str = "1";
        if load_status_list(storage, STATUS_LIST_ID).await?.is_none() {
            let fresh = PersistentStatusList::new(STATUS_LIST_ID, list_size, 2);
            save_status_list(storage, &fresh).await?;
        }
        // HAIP SD-JWT VC Profile (L329): dedup scope must equal the physical
        // list scope, not credential_type_id — see status_index.rs.
        Some(allocate_status_index(storage, STATUS_LIST_ID, &ct.id, list_size).await?)
    } else {
        None
    };

    let (tx, grants) = if let Some(redirect_uri) = req.redirect_uri {
        let issuer_state = generate_pre_authorized_code();
        let tx = IssuanceTransaction {
            transaction_id: transaction_id.clone(),
            credential_type_id: ct.id.clone(),
            claims: req.claims,
            pre_authorized_code: None,
            tx_code: None,
            status_list_index,
            access_token: None,
            state: IssuanceState::Offered,
            created_at: now_unix,
            redirect_uri: Some(redirect_uri),
            issuer_state: Some(issuer_state.clone()),
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
        };
        let grants = CredentialOfferGrants {
            pre_authorized_code: None,
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some(issuer_state),
            }),
        };
        (tx, grants)
    } else {
        let pre_authorized_code = generate_pre_authorized_code();
        let tx_code = if req.tx_code_required {
            Some(generate_tx_code(DEFAULT_TX_CODE_LENGTH))
        } else {
            None
        };
        let tx = IssuanceTransaction {
            transaction_id: transaction_id.clone(),
            credential_type_id: ct.id.clone(),
            claims: req.claims,
            pre_authorized_code: Some(pre_authorized_code.clone()),
            tx_code: tx_code.clone(),
            status_list_index,
            access_token: None,
            state: IssuanceState::Offered,
            created_at: now_unix,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
        };
        let grants = CredentialOfferGrants {
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code,
                tx_code: tx_code.map(|_| TxCodeDefinition {
                    input_mode: "numeric".to_string(),
                    length: DEFAULT_TX_CODE_LENGTH,
                }),
            }),
            authorization_code: None,
        };
        (tx, grants)
    };
    save_transaction_with_indices(storage, &tx, cfg.storage.transaction_ttl_secs, now_unix).await?;

    let offer = CredentialOffer {
        credential_issuer: cfg
            .issuer
            .credential_issuer
            .trim_end_matches('/')
            .to_string(),
        credential_configuration_ids: vec![ct.id.clone()],
        grants,
    };
    let credential_offer_uri = build_offer_uri(&offer)?;
    let dc_api_offer = build_dc_api_offer(cfg, &offer)?;

    Ok(CreateOfferResponse {
        transaction_id,
        credential_offer: offer,
        credential_offer_uri,
        dc_api_offer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::load_transaction;
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, DpopConfig, IssuerConfig,
        LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
        WalletFacingConfig,
    };
    use foundry_core::storage::SqliteStorage;
    use std::collections::BTreeMap as StdBTreeMap;

    fn test_config() -> Config {
        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://issuer.example.com".to_string(),
                    bind: "0.0.0.0:8443".to_string(),
                    swagger_ui_enabled: true,
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:9000".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                    console_enabled: true,
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
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                },
                status_list: StatusListConfig {
                    enabled: true,
                    signing_key: None,
                    list_size: Some(1024),
                    public_base_url: None,
                },
                dpop: DpopConfig::default(),
            },
            credential_types: vec![CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://issuer.example.com/vct/pid".to_string()),
                doctype: None,
                scope: None,
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
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec![],
                named_queries: vec![],
                webhook: None,
                dc_api_expected_origins: Vec::new(),
            },
            logging: LoggingConfig::default(),
        }
    }

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("c.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    /// `test_config()` plus a second credential type.
    ///
    /// Load-bearing for the narrowing assertion: with only one configured
    /// credential type, "filtered to the offered id" and "not filtered at all"
    /// produce identical output, so the test could not fail.
    fn test_config_two_types() -> Config {
        let mut cfg = test_config();
        cfg.credential_types.push(CredentialType {
            id: "mdl".to_string(),
            format: "mso_mdoc".to_string(),
            vct: None,
            doctype: Some("org.iso.18013.5.1.mDL".to_string()),
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["family_name".to_string()],
                selectively_disclosable: true,
                display: vec![],
            }],
        });
        cfg
    }

    /// The DC API payload must carry the offer's own three members verbatim,
    /// so a wallet reading `dc_api_offer` sees exactly the offer that
    /// `credential_offer_uri` encodes.
    #[tokio::test]
    async fn dc_api_offer_carries_the_offer_and_both_metadata_objects() {
        let cfg = test_config();
        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

        let res = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims,
                tx_code_required: false,
                redirect_uri: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();

        let dc = &res.dc_api_offer;

        assert_eq!(dc["credential_issuer"], "https://issuer.example.com");
        assert_eq!(
            dc["credential_configuration_ids"],
            serde_json::json!(["pid"])
        );
        assert!(
            dc["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
                ["pre-authorized_code"]
                .is_string(),
            "dc_api_offer must carry the pre-authorized_code grant, got: {dc}"
        );
        assert_eq!(
            dc["authorization_server_metadata"]["token_endpoint"],
            "https://issuer.example.com/token"
        );
        assert_eq!(
            dc["credential_issuer_metadata"]["credential_endpoint"],
            "https://issuer.example.com/credential"
        );
    }

    /// `credential_issuer_metadata.credential_configurations_supported` must be
    /// narrowed to the offered ids: the wallet renders its consent screen from
    /// it, and shipping every configured type leaves it guessing which one the
    /// offer is about.
    #[tokio::test]
    async fn dc_api_offer_narrows_credential_configurations_to_the_offered_ids() {
        let cfg = test_config_two_types();
        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

        let res = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims,
                tx_code_required: false,
                redirect_uri: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();

        let configs = res.dc_api_offer["credential_issuer_metadata"]
            ["credential_configurations_supported"]
            .as_object()
            .expect("credential_configurations_supported must be an object");

        assert_eq!(
            configs.len(),
            1,
            "expected only the offered configuration, got keys: {:?}",
            configs.keys().collect::<Vec<_>>()
        );
        assert!(
            configs.contains_key("pid"),
            "expected the offered id 'pid', got keys: {:?}",
            configs.keys().collect::<Vec<_>>()
        );
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
            redirect_uri: None,
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
            redirect_uri: None,
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
            redirect_uri: None,
        };
        let err = create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::ClaimValidation(_)));
    }

    #[tokio::test]
    async fn creates_the_backing_status_list_when_missing() {
        let cfg = test_config();
        let storage = test_storage().await;

        assert!(load_status_list(&storage, "1").await.unwrap().is_none());

        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));
        let req = CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: false,
            redirect_uri: None,
        };
        create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let list = load_status_list(&storage, "1").await.unwrap();
        assert!(
            list.is_some(),
            "PersistentStatusList for key \"1\" should now exist"
        );
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
            redirect_uri: None,
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

    fn req_with_redirect_uri(redirect_uri: &str) -> CreateOfferRequest {
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));
        CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: false,
            redirect_uri: Some(redirect_uri.to_string()),
        }
    }

    #[tokio::test]
    async fn redirect_uri_produces_an_authorization_code_grant_offer() {
        let cfg = test_config();
        let storage = test_storage().await;
        let req = req_with_redirect_uri("eudi-openid4ci://authorize");

        let resp = create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        assert!(resp.credential_offer.grants.pre_authorized_code.is_none());
        let grant = resp
            .credential_offer
            .grants
            .authorization_code
            .as_ref()
            .expect("authorization_code grant must be present");
        assert!(grant.issuer_state.is_some());

        let tx = load_transaction(&storage, &resp.transaction_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tx.redirect_uri,
            Some("eudi-openid4ci://authorize".to_string())
        );
        assert_eq!(tx.issuer_state, grant.issuer_state);
        assert!(tx.pre_authorized_code.is_none());
        assert!(tx.tx_code.is_none());
    }

    #[tokio::test]
    async fn redirect_uri_offer_uri_still_uses_the_credential_offer_scheme() {
        let cfg = test_config();
        let storage = test_storage().await;
        let req = req_with_redirect_uri("eudi-openid4ci://authorize");

        let resp = create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        assert!(resp
            .credential_offer_uri
            .starts_with("openid-credential-offer://"));
    }

    #[tokio::test]
    async fn rejects_redirect_uri_combined_with_tx_code_required() {
        let cfg = test_config();
        let storage = test_storage().await;
        let mut req = req_with_redirect_uri("eudi-openid4ci://authorize");
        req.tx_code_required = true;

        let err = create_offer(&cfg, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }
}
