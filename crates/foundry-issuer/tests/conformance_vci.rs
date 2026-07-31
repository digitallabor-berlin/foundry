//! OpenID4VCI + HAIP conformance evidence for the Credential Offer (VCI §4)
//! and the issuer-initiated / `authorization_code`-grant HAIP requirements
//! filed under "Credential Offer" in the clause inventory (Task 6 of the
//! OpenID4VC conformance audit).
//!
//! See `docs/conformance/openid4vc-conformance.md` for the full clause
//! inventory and the verdicts these tests are cited as evidence for.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, Mode,
    ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use foundry_issuer::{
    build_authorization_server_metadata, build_issuer_metadata, create_offer,
    handle_authorize_request, handle_token_request, AuthorizeOutcome, AuthorizeParams,
    CreateOfferRequest, TokenRequest,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
        keys: BTreeMap::new(),
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://issuer.example.com".to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
            },
            status_list: StatusListConfig {
                enabled: false,
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
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                selectively_disclosable: true,
                display: vec![],
            }],
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
    let db = dir.path().join("conformance_vci.db");
    // Leak the tempdir so the file survives for the life of the test process;
    // the OS reclaims it, matching the pattern already used by this crate's
    // unit tests (see create_offer.rs, metadata.rs).
    std::mem::forget(dir);
    SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
}

fn claims_with(field: &str, value: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert(field.to_string(), serde_json::json!(value));
    m
}

fn offer_request(redirect_uri: Option<&str>) -> CreateOfferRequest {
    CreateOfferRequest {
        credential_type_id: "pid".to_string(),
        claims: claims_with("given_name", "Alice"),
        tx_code_required: false,
        redirect_uri: redirect_uri.map(|s| s.to_string()),
    }
}

// ---------------------------------------------------------------------------
// VCI-0004 / VCI-0005 — OpenID4VCI §4 (Credential Offer Parameters, L374-375):
// `credential_offer` and `credential_offer_uri` MUST be mutually exclusive.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0004_0005_offer_uri_carries_exactly_one_delivery_parameter() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();

    let occurrences = resp
        .credential_offer_uri
        .matches("credential_offer=")
        .count();
    assert_eq!(
        occurrences, 1,
        "the offer URI must carry the offer via exactly one `credential_offer` parameter"
    );
    assert!(
        !resp.credential_offer_uri.contains("credential_offer_uri="),
        "foundry never offers by reference, so `credential_offer_uri` must never appear"
    );
}

// ---------------------------------------------------------------------------
// VCI-0006 — OpenID4VCI §4 (Credential Offer Parameters, L383): `credential_issuer`
// is REQUIRED.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0006_credential_issuer_is_always_present_and_matches_config() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();

    assert_eq!(
        resp.credential_offer.credential_issuer,
        "https://issuer.example.com"
    );
}

// ---------------------------------------------------------------------------
// VCI-0007 — OpenID4VCI §4 (Credential Offer Parameters, L384):
// `credential_configuration_ids` is REQUIRED, non-empty, and its entries MUST
// resolve against `credential_configurations_supported`.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0007_credential_configuration_ids_are_nonempty_and_resolve_against_metadata() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let metadata = build_issuer_metadata(&cfg);

    assert!(!resp
        .credential_offer
        .credential_configuration_ids
        .is_empty());
    for id in &resp.credential_offer.credential_configuration_ids {
        assert!(
            metadata
                .credential_configurations_supported
                .contains_key(id),
            "offered configuration id `{id}` must be keyed into issuer metadata"
        );
    }
}

// ---------------------------------------------------------------------------
// VCI-0012 — OpenID4VCI §4 (Credential Offer Parameters, L396): `pre-authorized_code`
// is REQUIRED and MUST be short lived and single use.
//
// Presence and per-offer distinctness are conforming (below). Single use is
// not — see the ignored test below, registered as GAP-VCI-01.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0012_pre_authorized_code_is_present_and_distinct_per_offer() {
    let cfg = test_config();
    let storage = test_storage().await;

    let resp_a = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code_a = resp_a
        .credential_offer
        .grants
        .pre_authorized_code
        .as_ref()
        .expect("pre-authorized_code grant must be present")
        .pre_authorized_code
        .clone();
    assert!(!code_a.is_empty());

    let resp_b = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code_b = resp_b
        .credential_offer
        .grants
        .pre_authorized_code
        .as_ref()
        .expect("pre-authorized_code grant must be present")
        .pre_authorized_code
        .clone();

    assert_ne!(
        code_a, code_b,
        "each offer must mint its own pre-authorized_code"
    );
}

#[tokio::test]
#[ignore = "GAP-VCI-01: OpenID4VCI Credential Offer (L396) — pre-authorized_code MUST be single use"]
async fn vci_0012_pre_authorized_code_grant_rejects_replay_after_token_issuance() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code = resp
        .credential_offer
        .grants
        .pre_authorized_code
        .unwrap()
        .pre_authorized_code;

    let token_req = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        pre_authorized_code: Some(code),
        tx_code: None,
        code: None,
        redirect_uri: None,
        client_id: None,
        code_verifier: None,
    };

    handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_010)
        .await
        .expect("first redemption must succeed");

    let replay =
        handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_020).await;
    assert!(
        replay.is_err(),
        "a second /token call with the same pre-authorized_code must be rejected"
    );
}

// ---------------------------------------------------------------------------
// HAIP-0010 — HAIP OpenID4VCI (L173): if Issuer-initiated flows are supported
// they MUST use the Credential Offer (OpenID4VCI §4.1).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn haip_0010_issuer_initiated_flow_always_produces_a_credential_offer() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();

    // foundry's only issuer-initiated issuance entry point is `create_offer`,
    // and it always produces a well-formed CredentialOffer plus its deep-link.
    assert!(!resp
        .credential_offer
        .credential_configuration_ids
        .is_empty());
    assert!(resp
        .credential_offer_uri
        .starts_with("openid-credential-offer://"));
}

// ---------------------------------------------------------------------------
// HAIP-0022 — HAIP OpenID4VCI (L198): Grant Type `authorization_code` MUST be
// supported.
// ---------------------------------------------------------------------------
fn s256_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[tokio::test]
async fn haip_0022_authorization_code_grant_type_is_supported_end_to_end() {
    let cfg = test_config();
    let storage = test_storage().await;

    // The Authorization Server metadata must advertise the grant.
    let as_metadata = build_authorization_server_metadata(&cfg);
    assert!(as_metadata
        .grant_types_supported
        .contains(&"authorization_code".to_string()));

    // And the flow must actually work end to end: offer -> authorize -> token.
    let redirect_uri = "eudi-openid4ci://authorize";
    let resp = create_offer(
        &cfg,
        &storage,
        offer_request(Some(redirect_uri)),
        1_700_000_000,
    )
    .await
    .unwrap();
    let issuer_state = resp
        .credential_offer
        .grants
        .authorization_code
        .as_ref()
        .expect("authorization_code grant must be present")
        .issuer_state
        .clone()
        .expect("issuer_state must be present");

    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let params = AuthorizeParams {
        response_type: "code".to_string(),
        client_id: "wallet-dev".to_string(),
        redirect_uri: redirect_uri.to_string(),
        state: None,
        code_challenge: s256_code_challenge(code_verifier),
        code_challenge_method: "S256".to_string(),
        issuer_state,
    };
    let outcome = handle_authorize_request(
        &storage,
        &params,
        cfg.storage.transaction_ttl_secs,
        1_700_000_005,
    )
    .await;
    let code = match outcome {
        AuthorizeOutcome::Success { code, .. } => code,
        other => panic!("expected AuthorizeOutcome::Success, got {other:?}"),
    };

    let token_req = TokenRequest {
        grant_type: "authorization_code".to_string(),
        pre_authorized_code: None,
        tx_code: None,
        code: Some(code),
        redirect_uri: Some(redirect_uri.to_string()),
        client_id: Some("wallet-dev".to_string()),
        code_verifier: Some(code_verifier.to_string()),
    };
    handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_010)
        .await
        .expect("authorization_code grant must issue an access token");
}

// ---------------------------------------------------------------------------
// HAIP-0023 — HAIP OpenID4VCI (L199): for Grant Type `authorization_code` the
// Issuer MUST include a scope value so the Wallet can identify the desired
// Credential Type.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-HAIP-01: HAIP OpenID4VCI (L199) — the Issuer MUST include a scope value for the authorization_code grant"]
async fn haip_0023_credential_configuration_metadata_carries_a_scope_value() {
    let cfg = test_config();
    let metadata = build_issuer_metadata(&cfg);
    let pid = metadata
        .credential_configurations_supported
        .get("pid")
        .unwrap();
    let json = serde_json::to_value(pid).unwrap();

    assert!(
        json.as_object().unwrap().contains_key("scope"),
        "HAIP requires a scope value the Wallet can use to identify the Credential Type"
    );
}

// ---------------------------------------------------------------------------
// HAIP-0025 — HAIP OpenID4VCI (L204): both Issuer and Wallet MUST support the
// Credential Offer in same-device and cross-device flows.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn haip_0025_credential_offer_uri_format_is_transport_agnostic() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();

    // The offer is a self-contained deep link with no device-mode signal, so
    // the identical value serves a QR-scanned cross-device flow and a
    // directly-opened same-device flow alike.
    assert!(resp
        .credential_offer_uri
        .starts_with("openid-credential-offer://?credential_offer="));
}
