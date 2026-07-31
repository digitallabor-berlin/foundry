//! HTTP-layer OpenID4VCI + HAIP conformance evidence.
//!
//! Home for clauses whose enforcement point is the HTTP request/response
//! boundary in `crates/foundry/src/server.rs` rather than `foundry-issuer`'s
//! domain API — see `docs/conformance/openid4vc-conformance.md`. Task 18
//! ("Adjudicate & test — HTTP layer") owns this file going forward; Task 7
//! seeds it with the two clauses discovered during Authorization Endpoint
//! adjudication whose evidence can only be produced at this layer:
//!
//! - VCI-0030 (unrecognized Authorization Request parameters must be
//!   ignored) — the ignoring happens in `AuthorizeQuery`'s `serde`
//!   deserialization, which `foundry-issuer`'s `AuthorizeParams` never sees.
//! - HAIP-0008 (the Authorization Response MUST carry `iss` per RFC9207) —
//!   `AuthorizeOutcome::Success` has no `iss` field, so the gap is only
//!   observable in the redirect `Location` header this crate builds.
//!
//! Same test-harness pattern as `authorization_code_flow.rs`
//! (`admin_router`/`wallet_router` + `tower::ServiceExt::oneshot`); helpers
//! are duplicated rather than imported, per this run's Global Constraint that
//! new conformance tests live in new files and never modify existing ones.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, Mode,
    ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

const REDIRECT_URI: &str = "eudi-openid4ci://authorize";
const CLIENT_ID: &str = "wallet-dev";
const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn code_challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn urlencoding_encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

async fn setup_test_app() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://issuer.example.com".to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: true,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: Some("test-admin-key".to_string()),
                api_key_env: None,
                swagger_ui_enabled: true,
                console_enabled: true,
            },
        },
        storage: StorageConfig {
            path: db_path.to_str().unwrap().to_string(),
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
                list_size: None,
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
    };

    let state = AppState::new(Arc::new(storage), Arc::new(config));

    (state, dir)
}

/// Create an `authorization_code`-grant offer via the Admin API and return
/// its `issuer_state`.
async fn create_authz_code_offer_issuer_state(state: &AppState) -> String {
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": { "given_name": "Alice" },
        "tx_code_required": false,
        "redirect_uri": REDIRECT_URI,
    });

    let offer_req = Request::builder()
        .method("POST")
        .uri("/admin/issuance/offers")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(offer_req_body.to_string()))
        .unwrap();

    let offer_res = admin_app.oneshot(offer_req).await.unwrap();
    assert_eq!(offer_res.status(), StatusCode::OK);

    let offer_bytes = axum::body::to_bytes(offer_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let offer_json: serde_json::Value = serde_json::from_slice(&offer_bytes).unwrap();
    offer_json["credential_offer"]["grants"]["authorization_code"]["issuer_state"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------
// VCI-0030 — OpenID4VCI Authorization Request (L574): the Authorization
// Server MUST ignore unrecognized Authorization Request parameters.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0030_authorize_ignores_unrecognized_query_parameters() {
    let (state, _dir) = setup_test_app().await;
    let issuer_state = create_authz_code_offer_issuer_state(&state).await;

    let wallet_app = wallet_router(state.clone());
    let code_challenge = code_challenge_for(CODE_VERIFIER);
    // `some_unknown_param` and `another_bogus_one` are not defined by
    // OpenID4VCI, OpenID4VP, or this crate's `AuthorizeQuery` — a conformant
    // Authorization Server ignores them rather than rejecting the request.
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={}\
         &state=xyz-state&code_challenge={code_challenge}&code_challenge_method=S256\
         &issuer_state={issuer_state}&some_unknown_param=whatever&another_bogus_one=123",
        urlencoding_encode(REDIRECT_URI),
    );
    let authorize_req = Request::builder()
        .method("GET")
        .uri(authorize_uri)
        .body(Body::empty())
        .unwrap();

    let authorize_res = wallet_app.oneshot(authorize_req).await.unwrap();

    assert_eq!(
        authorize_res.status(),
        StatusCode::SEE_OTHER,
        "unrecognized query parameters must not cause the request to be rejected"
    );
    let location = authorize_res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with(REDIRECT_URI));
}

// ---------------------------------------------------------------------------
// HAIP-0008 — HAIP OpenID4VCI (L159): MUST return the `iss` value in the
// Authorization response per RFC9207.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-HAIP-02: HAIP OpenID4VCI (L159) — the Authorization response MUST include `iss` per RFC9207"]
async fn haip_0008_authorization_response_includes_iss() {
    let (state, _dir) = setup_test_app().await;
    let issuer_state = create_authz_code_offer_issuer_state(&state).await;

    let wallet_app = wallet_router(state.clone());
    let code_challenge = code_challenge_for(CODE_VERIFIER);
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={}\
         &state=xyz-state&code_challenge={code_challenge}&code_challenge_method=S256\
         &issuer_state={issuer_state}",
        urlencoding_encode(REDIRECT_URI),
    );
    let authorize_req = Request::builder()
        .method("GET")
        .uri(authorize_uri)
        .body(Body::empty())
        .unwrap();

    let authorize_res = wallet_app.oneshot(authorize_req).await.unwrap();
    assert_eq!(authorize_res.status(), StatusCode::SEE_OTHER);
    let location = authorize_res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    assert!(
        location.contains("iss="),
        "RFC9207 requires the `iss` parameter in a successful Authorization Response; got {location}"
    );
}
