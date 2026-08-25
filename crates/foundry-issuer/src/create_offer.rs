//! Orchestrates offer creation: claim validation, status-index allocation,
//! pre-auth code/tx_code generation, transaction persistence, and offer
//! construction.

use crate::display_metadata::{DisplayStage, validate_display};
use crate::error::IssuanceError;
use crate::offer::{
    AuthorizationCodeGrant, CredentialOffer, CredentialOfferGrants, PreAuthorizedCodeGrant,
    TxCodeDefinition, build_dc_api_offer, build_offer_uri, build_offer_uri_by_reference,
    generate_offer_id, generate_pre_authorized_code, generate_tx_code,
};
use crate::offer_ref::save_offer_by_reference;
use crate::status_index::allocate_status_index;
use crate::transaction::{IssuanceState, IssuanceTransaction, save_transaction_with_indices};
use foundry_core::config::Config;
use foundry_core::status_list::{PersistentStatusList, load_status_list, save_status_list};
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
    /// EMVCo DPC display metadata for the **Credential Offer**.
    ///
    /// Validated with `DisplayStage::Offer`, which treats `last_four` and
    /// `card_art` as optional. That is deliberate: the Schema Framework's
    /// offer-stage guidance says PII-type data should not appear on an offer,
    /// while its schema marks both members required. See design §1.3.
    ///
    /// Accepted only for the `com.emvco.dpc.card` credential type.
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub offer_display: Option<Vec<serde_json::Value>>,
    /// EMVCo DPC display metadata for the **Credential Response**.
    ///
    /// Validated with `DisplayStage::CredentialResponse`, which requires
    /// `last_four` and `card_art`. Persisted on the `IssuanceTransaction` and
    /// echoed at `/credential`.
    ///
    /// Accepted only for the `com.emvco.dpc.card` credential type.
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub credential_response_display: Option<Vec<serde_json::Value>>,
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

/// The canonical EMVCo Digital Payment Credential type identifier.
///
/// Behaviour keyed on this constant is justified **only** by the EMV® Digital
/// Payment Credential Specification — Schema Framework, an external-reference
/// document rather than a standards-track specification (root AGENTS.md §4.4,
/// external-reference rule; the stub is
/// `docs/specs/emvco-dpc-schema-framework.md`).
///
/// Confining display metadata to this one `vct` is what keeps a member
/// OpenID4VCI 1.0 does not define off every other credential type's offer and
/// response. The mdoc binding is unimplemented, so only `vct` is consulted.
const DPC_VCT: &str = "com.emvco.dpc.card";

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
        // Presence only, never contents: these objects carry `last_four`, a
        // cardholder-recognisable alias and possibly personalised art URLs, all
        // of which are on root AGENTS.md §4.5's never-logged list.
        offer_display_present = req.offer_display.is_some(),
        credential_response_display_present = req.credential_response_display.is_some(),
    )
)]
pub async fn create_offer(
    cfg: &Config,
    storage: &dyn Storage,
    mut req: CreateOfferRequest,
    now_unix: i64,
    request_decryption_keys: &[foundry_core::crypto::jwe::DecryptionKey],
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

    // Gate, then validate -- in that order, and both before any state is
    // mutated, so a rejected request allocates no status index and writes no
    // transaction.
    if (req.offer_display.is_some() || req.credential_response_display.is_some())
        && ct.vct.as_deref() != Some(DPC_VCT)
    {
        return Err(IssuanceError::InvalidRequest(format!(
            "display metadata is only supported for the '{DPC_VCT}' credential \
             type; credential_type '{}' declares vct {:?}",
            ct.id, ct.vct
        )));
    }
    if let Some(display) = req.offer_display.as_deref() {
        validate_display(display, DisplayStage::Offer)?;
    }
    if let Some(display) = req.credential_response_display.as_deref() {
        validate_display(display, DisplayStage::CredentialResponse)?;
    }

    // Every required claim's top-level path segment must be present.
    //
    // "Required" is `ClaimDef::is_required()`, not `!selectively_disclosable`:
    // a claim can be mandatory in a credential's own schema and still be
    // selectively disclosable in the SD-JWT, and conflating the two meant such
    // a claim was never validated at all.
    // (Nested-path validation is still a follow-up — see GAP-VCI-13.)
    for claim_def in &ct.claims {
        if !claim_def.is_required() {
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

    // Bound before the branches below move the rest of `req`.
    let offer_display = req.offer_display.take();
    let credential_response_display = req.credential_response_display.take();

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
            credential_response_display: credential_response_display.clone(),
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
            credential_response_display: credential_response_display.clone(),
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
        display: offer_display,
    };
    // OpenID4VCI §4.2 (L432-L452): deliver the offer by reference when
    // configured, inline otherwise. L374-L375 make the two parameters mutually
    // exclusive, which is why this is an either/or and not an addition.
    //
    // The offer row is written ONLY on the by-reference branch: with the toggle
    // off nothing addresses it, so persisting it would store a
    // `pre-authorized_code` at a second location for no reader.
    let credential_offer_uri = if cfg.issuer.offer_by_reference {
        let offer_id = generate_offer_id();
        save_offer_by_reference(
            storage,
            &offer_id,
            &offer,
            cfg.storage.transaction_ttl_secs,
            now_unix,
        )
        .await?;
        build_offer_uri_by_reference(&format!(
            "{}/credential-offer/{offer_id}",
            cfg.server
                .wallet_facing
                .public_base_url
                .trim_end_matches('/')
        ))
    } else {
        build_offer_uri(&offer)?
    };
    // Deliberately unaffected by the toggle: the DC API hands the offer to the
    // wallet in-process, so it has neither a QR rendering nor a size limit.
    let dc_api_offer = build_dc_api_offer(cfg, &offer, request_decryption_keys)?;

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
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                status_list: StatusListConfig {
                    enabled: true,
                    signing_key: None,
                    list_size: Some(1024),
                    public_base_url: None,
                },
                dpop: DpopConfig::default(),
                request_encryption: None,
                response_encryption: None,
                encrypted_pre_authorized_code: Default::default(),
                access_token_ttl_secs: 600,
                offer_by_reference: false,
                paso_metadata: Default::default(),
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
                        required: None,
                        selectively_disclosable: false,
                        display: vec![],
                    },
                    ClaimDef {
                        path: vec!["given_name".to_string()],
                        required: None,
                        selectively_disclosable: true,
                        display: vec![],
                    },
                ],
                validity_seconds: None,
                transaction_data_types: None,
            }],
            verifier: VerifierConfig {
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec![],
                named_queries: vec![],
                webhook: None,
                dc_api_expected_origins: Vec::new(),
                dc_api_accept_legacy_web_origin_audience: false,
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
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
            validity_seconds: None,
            transaction_data_types: None,
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
                offer_display: None,
                credential_response_display: None,
            },
            1_700_000_000,
            &[],
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

    /// Regression: the DC API offer's embedded issuer metadata MUST carry the
    /// request-decryption JWKs.
    ///
    /// That embedded object is the ONLY issuer metadata a DC API wallet sees --
    /// the platform hands it the offer in-process, so there is no well-known
    /// document to fall back on. Building it with an empty key slice published
    /// `credential_request_encryption.jwks.keys: []` next to
    /// `encryption_required: true`, which cannot be satisfied: OpenID4VCI
    /// L871/L873 require the Client to encrypt the Credential Request "using the
    /// parameters from the `credential_request_encryption` object in the
    /// Credential Issuer Metadata".
    ///
    /// Observed in interop against Google's CMWallet sample, which aborted
    /// before ever reaching `/credential`: with no key of `alg: ECDH-ES` in the
    /// embedded `jwks`, it had nothing to encrypt to.
    #[tokio::test]
    async fn dc_api_offer_embeds_the_request_encryption_jwks() {
        let mut cfg = test_config();
        cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
            keys: vec!["issuer_request_enc".to_string()],
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: true,
        });
        let storage = test_storage().await;

        let km =
            foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
                .unwrap();
        let key =
            foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes()).unwrap();
        let expected_kid = key.kid().to_string();

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
                offer_display: None,
                credential_response_display: None,
            },
            1_700_000_000,
            std::slice::from_ref(&key),
        )
        .await
        .unwrap();

        let enc = &res.dc_api_offer["credential_issuer_metadata"]["credential_request_encryption"];
        assert_eq!(enc["encryption_required"], serde_json::json!(true));

        let keys = enc["jwks"]["keys"]
            .as_array()
            .expect("embedded credential_request_encryption.jwks.keys must be an array");
        assert_eq!(
            keys.len(),
            1,
            "embedded jwks must carry the configured decryption key, got: {enc}"
        );
        assert_eq!(keys[0]["kid"], serde_json::json!(expected_kid));
        assert_eq!(keys[0]["alg"], serde_json::json!("ECDH-ES"));
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
                offer_display: None,
                credential_response_display: None,
            },
            1_700_000_000,
            &[],
        )
        .await
        .unwrap();

        let configs =
            res.dc_api_offer["credential_issuer_metadata"]["credential_configurations_supported"]
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
            offer_display: None,
            credential_response_display: None,
        };
        let resp = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
            .await
            .unwrap();

        assert_eq!(
            resp.credential_offer.credential_configuration_ids,
            vec!["pid".to_string()]
        );
        assert!(
            resp.credential_offer_uri
                .starts_with("openid-credential-offer://")
        );

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
            offer_display: None,
            credential_response_display: None,
        };
        let err = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
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
            offer_display: None,
            credential_response_display: None,
        };
        let err = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
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
            offer_display: None,
            credential_response_display: None,
        };
        create_offer(&cfg, &storage, req, 1_700_000_000, &[])
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
            offer_display: None,
            credential_response_display: None,
        };
        let resp = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
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
            offer_display: None,
            credential_response_display: None,
        }
    }

    #[tokio::test]
    async fn redirect_uri_produces_an_authorization_code_grant_offer() {
        let cfg = test_config();
        let storage = test_storage().await;
        let req = req_with_redirect_uri("eudi-openid4ci://authorize");

        let resp = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
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

        let resp = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
            .await
            .unwrap();

        assert!(
            resp.credential_offer_uri
                .starts_with("openid-credential-offer://")
        );
    }

    #[tokio::test]
    async fn rejects_redirect_uri_combined_with_tx_code_required() {
        let cfg = test_config();
        let storage = test_storage().await;
        let mut req = req_with_redirect_uri("eudi-openid4ci://authorize");
        req.tx_code_required = true;

        let err = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// A claim that is BOTH required and selectively disclosable. Before
    /// `ClaimDef::is_required` existed, `create_offer` skipped presence
    /// validation for every selectively-disclosable claim, so this offer was
    /// accepted and issued a credential missing a schema-mandatory claim.
    #[tokio::test]
    async fn a_required_selectively_disclosable_claim_must_be_supplied() {
        let mut cfg = test_config();
        cfg.credential_types[0].claims = vec![ClaimDef {
            path: vec!["credential_id".to_string()],
            required: Some(true),
            selectively_disclosable: true,
            display: vec![],
        }];
        let storage = test_storage().await;

        let err = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims: serde_json::Map::new(),
                tx_code_required: false,
                redirect_uri: None,
                offer_display: None,
                credential_response_display: None,
            },
            1_700_000_000,
            &[],
        )
        .await
        .expect_err("an offer omitting a required claim must be rejected");

        assert!(
            matches!(err, IssuanceError::ClaimValidation(_)),
            "expected ClaimValidation, got {err:?}"
        );
    }

    /// The counterpart: a claim that is only selectively disclosable stays
    /// optional, so `pid`-style configurations keep working unchanged.
    #[tokio::test]
    async fn an_optional_selectively_disclosable_claim_may_be_omitted() {
        let mut cfg = test_config();
        cfg.credential_types[0].claims = vec![ClaimDef {
            path: vec!["card_id".to_string()],
            required: None,
            selectively_disclosable: true,
            display: vec![],
        }];
        let storage = test_storage().await;

        create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims: serde_json::Map::new(),
                tx_code_required: false,
                redirect_uri: None,
                offer_display: None,
                credential_response_display: None,
            },
            1_700_000_000,
            &[],
        )
        .await
        .expect("an offer omitting an optional claim must be accepted");
    }

    /// `test_config()` plus the DPC credential type, so gating has something to
    /// accept as well as something to reject.
    fn test_config_with_dpc() -> Config {
        let mut cfg = test_config();
        cfg.credential_types.push(CredentialType {
            id: "com.emvco.dpc.card".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("com.emvco.dpc.card".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![
                ClaimDef {
                    path: vec!["credential_id".to_string()],
                    required: Some(true),
                    selectively_disclosable: true,
                    display: vec![],
                },
                ClaimDef {
                    path: vec!["network".to_string()],
                    required: Some(true),
                    selectively_disclosable: true,
                    display: vec![],
                },
            ],
            validity_seconds: None,
            transaction_data_types: None,
        });
        cfg
    }

    fn dpc_claims() -> serde_json::Map<String, serde_json::Value> {
        let mut claims = serde_json::Map::new();
        claims.insert("credential_id".to_string(), serde_json::json!("cred-1"));
        claims.insert("network".to_string(), serde_json::json!("example_network"));
        claims
    }

    fn offer_stage_display() -> Vec<serde_json::Value> {
        vec![serde_json::json!({
            "locale": "en-US",
            "card": {
                "type": { "code": "CREDIT", "label": "Credit Card" },
                "network_branding": [
                    { "network": "example_network", "branding": { "name": "Example Network" } }
                ]
            }
        })]
    }

    fn response_stage_display() -> Vec<serde_json::Value> {
        vec![serde_json::json!({
            "locale": "en-US",
            "card": {
                "last_four": "4444",
                "alias": "Platinum Credit Card",
                "card_art": [
                    { "theme": "DEFAULT", "image_url": "https://bank.example/card.png" }
                ]
            }
        })]
    }

    fn dpc_request() -> CreateOfferRequest {
        CreateOfferRequest {
            credential_type_id: "com.emvco.dpc.card".to_string(),
            claims: dpc_claims(),
            tx_code_required: false,
            redirect_uri: None,
            offer_display: Some(offer_stage_display()),
            credential_response_display: Some(response_stage_display()),
        }
    }

    #[tokio::test]
    async fn a_dpc_offer_carries_the_offer_stage_display_and_persists_the_response_stage_one() {
        let cfg = test_config_with_dpc();
        let storage = test_storage().await;

        let res = create_offer(&cfg, &storage, dpc_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        let display = res
            .credential_offer
            .display
            .as_ref()
            .expect("the offer must carry the offer-stage display array");
        assert_eq!(display[0]["card"]["type"]["code"], "CREDIT");
        assert!(
            display[0]["card"].get("last_four").is_none(),
            "the offer must carry the offer-stage object, not the response-stage one"
        );

        let tx = load_transaction(&storage, &res.transaction_id)
            .await
            .unwrap()
            .unwrap();
        let persisted = tx
            .credential_response_display
            .as_ref()
            .expect("the response-stage display must be persisted on the transaction");
        assert_eq!(persisted[0]["card"]["last_four"], "4444");
    }

    /// The DC API payload is built by serialising the offer, so the two
    /// transports cannot disagree about `display`. This test is what keeps that
    /// true if someone later hand-builds the payload.
    #[tokio::test]
    async fn the_dc_api_offer_carries_the_offer_stage_display() {
        let cfg = test_config_with_dpc();
        let storage = test_storage().await;

        let res = create_offer(&cfg, &storage, dpc_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        assert_eq!(
            res.dc_api_offer["display"][0]["card"]["type"]["code"], "CREDIT",
            "dc_api_offer is built by serialising the offer, so it must inherit display"
        );
    }

    /// The gate of design §3.5: a non-OpenID4VCI member must not appear on any
    /// credential type except the one whose governing document asks for it.
    #[tokio::test]
    async fn display_metadata_is_rejected_for_a_non_dpc_credential_type() {
        let cfg = test_config_with_dpc();
        let storage = test_storage().await;

        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

        let err = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims,
                tx_code_required: false,
                redirect_uri: None,
                offer_display: Some(offer_stage_display()),
                credential_response_display: None,
            },
            1_700_000_000,
            &[],
        )
        .await
        .expect_err("display metadata on a non-DPC credential type must be rejected");

        match err {
            IssuanceError::InvalidRequest(m) => assert!(
                m.contains("com.emvco.dpc.card"),
                "the rejection should name the only credential type that may carry it, got: {m}"
            ),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    /// A rejected request must not leave a transaction or a consumed status
    /// index behind: the gate runs before any state is mutated.
    #[tokio::test]
    async fn a_rejected_display_request_persists_nothing() {
        let cfg = test_config_with_dpc();
        let storage = test_storage().await;

        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

        let _ = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims,
                tx_code_required: false,
                redirect_uri: None,
                offer_display: Some(offer_stage_display()),
                credential_response_display: None,
            },
            1_700_000_000,
            &[],
        )
        .await;

        assert!(
            load_status_list(&storage, "1").await.unwrap().is_none(),
            "no status list should have been created for a rejected request"
        );
    }

    /// Structural validation runs at the admin boundary, and the two stages use
    /// different rules: an object missing `last_four` is fine on the offer and
    /// invalid on the response.
    #[tokio::test]
    async fn a_response_stage_object_missing_last_four_is_rejected() {
        let cfg = test_config_with_dpc();
        let storage = test_storage().await;

        let mut req = dpc_request();
        req.credential_response_display = Some(offer_stage_display());

        let err = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
            .await
            .expect_err("a response-stage object without last_four must be rejected");

        match err {
            IssuanceError::InvalidRequest(m) => assert!(m.contains("last_four"), "got: {m}"),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_offer_stage_object_missing_last_four_is_accepted() {
        let cfg = test_config_with_dpc();
        let storage = test_storage().await;

        let mut req = dpc_request();
        req.credential_response_display = None;

        create_offer(&cfg, &storage, req, 1_700_000_000, &[])
            .await
            .expect("the offer stage must accept an object without last_four");
    }

    #[tokio::test]
    async fn a_structurally_invalid_display_object_is_rejected() {
        let cfg = test_config_with_dpc();
        let storage = test_storage().await;

        let mut req = dpc_request();
        req.offer_display = Some(vec![serde_json::json!({
            "locale": "en-US",
            "card": { "type": { "code": "CHARGE" } }
        })]);

        let err = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
            .await
            .expect_err("an invalid type.code must be rejected");

        match err {
            IssuanceError::InvalidRequest(m) => assert!(m.contains("type.code"), "got: {m}"),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    /// A DPC offer that supplies no display metadata must still serialise
    /// without the key -- the gate must not force the member into existence.
    #[tokio::test]
    async fn a_dpc_offer_without_display_still_omits_the_key() {
        let cfg = test_config_with_dpc();
        let storage = test_storage().await;

        let res = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "com.emvco.dpc.card".to_string(),
                claims: dpc_claims(),
                tx_code_required: false,
                redirect_uri: None,
                offer_display: None,
                credential_response_display: None,
            },
            1_700_000_000,
            &[],
        )
        .await
        .unwrap();

        let value = serde_json::to_value(&res.credential_offer).unwrap();
        assert!(
            !value.as_object().unwrap().contains_key("display"),
            "got: {value}"
        );
    }

    // -----------------------------------------------------------------------
    // By-reference offer delivery (OpenID4VCI §4.2, L432) --
    // `issuer.offer_by_reference`.
    // -----------------------------------------------------------------------

    fn by_reference_config() -> Config {
        let mut cfg = test_config();
        cfg.issuer.offer_by_reference = true;
        cfg
    }

    /// Recover the URL the wallet would GET from the deep link, undoing
    /// `build_offer_uri_by_reference`'s percent-encoding.
    fn referenced_url(offer_uri: &str) -> String {
        let encoded = offer_uri
            .strip_prefix("openid-credential-offer://?credential_offer_uri=")
            .expect("a by-reference link carries exactly this prefix");
        percent_encoding::percent_decode_str(encoded)
            .decode_utf8()
            .expect("the encoded URL is valid UTF-8")
            .to_string()
    }

    fn offer_id_from(offer_uri: &str) -> String {
        referenced_url(offer_uri)
            .rsplit('/')
            .next()
            .expect("the URL ends in the offer id")
            .to_string()
    }

    fn plain_request() -> CreateOfferRequest {
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));
        CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: false,
            redirect_uri: None,
            offer_display: None,
            credential_response_display: None,
        }
    }

    /// The no-regression assertion for every deployment that has not opted in:
    /// the link must still inline the offer, and no offer row may be written.
    #[tokio::test]
    async fn with_the_toggle_off_the_offer_is_still_delivered_inline() {
        let cfg = test_config();
        let storage = test_storage().await;
        let resp = create_offer(&cfg, &storage, plain_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        assert_eq!(
            resp.credential_offer_uri
                .matches("credential_offer=")
                .count(),
            1
        );
        assert!(!resp.credential_offer_uri.contains("credential_offer_uri="));
    }

    /// OpenID4VCI L374-L375: the two delivery parameters are mutually exclusive.
    #[tokio::test]
    async fn with_the_toggle_on_the_offer_is_delivered_by_reference_only() {
        let cfg = by_reference_config();
        let storage = test_storage().await;
        let resp = create_offer(&cfg, &storage, plain_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        assert_eq!(
            resp.credential_offer_uri
                .matches("credential_offer_uri=")
                .count(),
            1
        );
        assert_eq!(
            resp.credential_offer_uri
                .matches("credential_offer=")
                .count(),
            0
        );
    }

    /// The referenced URL must address this deployment's wallet-facing listener
    /// under the route `crates/foundry/src/server.rs` actually serves.
    #[tokio::test]
    async fn the_referenced_url_is_the_wallet_facing_credential_offer_route() {
        let cfg = by_reference_config();
        let storage = test_storage().await;
        let resp = create_offer(&cfg, &storage, plain_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        let url = referenced_url(&resp.credential_offer_uri);
        assert!(
            url.starts_with("https://issuer.example.com/credential-offer/"),
            "got: {url}"
        );
    }

    /// The offer served by reference must be byte-identical to the one returned
    /// to the admin caller -- a wallet and the operator must not see two
    /// different offers.
    #[tokio::test]
    async fn the_referenced_offer_is_persisted_and_matches_the_response() {
        let cfg = by_reference_config();
        let storage = test_storage().await;
        let resp = create_offer(&cfg, &storage, plain_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        let stored = crate::offer_ref::load_offer_by_reference(
            &storage,
            &offer_id_from(&resp.credential_offer_uri),
        )
        .await
        .unwrap()
        .expect("the referenced offer must be fetchable");

        assert_eq!(
            serde_json::to_value(&stored).unwrap(),
            serde_json::to_value(&resp.credential_offer).unwrap()
        );
    }

    /// The security-critical assertion. `GET /admin/issuance/offers/{id}` is
    /// keyed by `transaction_id` and deliberately withholds
    /// `pre_authorized_code`; the by-reference resource hands the code out in
    /// full. Addressing both by the same id would make knowing a transaction id
    /// enough to redeem the offer.
    #[tokio::test]
    async fn the_offer_id_is_not_the_transaction_id() {
        let cfg = by_reference_config();
        let storage = test_storage().await;
        let resp = create_offer(&cfg, &storage, plain_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        assert_ne!(
            offer_id_from(&resp.credential_offer_uri),
            resp.transaction_id
        );
    }

    /// Two offers must never share a reference URL (L436: a unique URI per
    /// Credential Offer).
    #[tokio::test]
    async fn two_offers_get_distinct_reference_urls() {
        let cfg = by_reference_config();
        let storage = test_storage().await;
        let a = create_offer(&cfg, &storage, plain_request(), 1_700_000_000, &[])
            .await
            .unwrap();
        let b = create_offer(&cfg, &storage, plain_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        assert_ne!(a.credential_offer_uri, b.credential_offer_uri);
    }

    /// The DPC display metadata is the reason this mode exists, so it must reach
    /// the wallet through the referenced document.
    #[tokio::test]
    async fn a_by_reference_dpc_offer_serves_its_display_metadata() {
        let mut cfg = test_config_with_dpc();
        cfg.issuer.offer_by_reference = true;
        let storage = test_storage().await;
        let resp = create_offer(&cfg, &storage, dpc_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        let stored = crate::offer_ref::load_offer_by_reference(
            &storage,
            &offer_id_from(&resp.credential_offer_uri),
        )
        .await
        .unwrap()
        .expect("the referenced offer must be fetchable");

        let display = stored.display.expect("the offer-stage display array");
        assert_eq!(display[0]["card"]["type"]["code"], "CREDIT");
    }

    /// The DC API is handed the offer in-process, so it has no QR and no size
    /// limit. The toggle must not touch it.
    #[tokio::test]
    async fn the_dc_api_offer_still_inlines_the_offer_under_the_toggle() {
        let cfg = by_reference_config();
        let storage = test_storage().await;
        let resp = create_offer(&cfg, &storage, plain_request(), 1_700_000_000, &[])
            .await
            .unwrap();

        assert_eq!(
            resp.dc_api_offer["credential_configuration_ids"],
            serde_json::json!(["pid"])
        );
        assert!(resp.dc_api_offer["credential_issuer_metadata"].is_object());
    }
}
