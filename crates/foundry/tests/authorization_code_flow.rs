//! End-to-end HTTP coverage for the OAuth 2.0 Authorization Code + PKCE
//! grant bound to admin-precreated offers (Task 6 of
//! docs/superpowers/plans/2026-07-28-authz-code-flow-plan.md).
//!
//! Exercises the full round trip through the real axum routers (same
//! test-harness pattern as wallet_issuance.rs/wallet_metadata.rs):
//! POST /admin/issuance/offers (redirect_uri set) -> GET /authorize
//! (real PKCE pair) -> POST /token (grant_type=authorization_code).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, LoggingConfig,
    Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
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
                pop_max_age_secs: 300,
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
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
            dc_api_expected_origins: Vec::new(),
        },
        logging: LoggingConfig::default(),
    };

    let state = AppState::new(Arc::new(storage), Arc::new(config));

    (state, dir)
}

/// Create an authorization_code-grant offer via the Admin API and return the
/// offer JSON body.
async fn create_authz_code_offer(state: &AppState) -> serde_json::Value {
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
    serde_json::from_slice(&offer_bytes).unwrap()
}

#[tokio::test]
async fn full_authorization_code_flow_end_to_end() {
    let (state, _dir) = setup_test_app().await;

    // 1. Create an authorization_code-grant offer via the Admin API.
    let offer_json = create_authz_code_offer(&state).await;
    assert!(
        offer_json["credential_offer"]["grants"]
            ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
            .is_null(),
        "an authorization_code offer must not also carry a pre-authorized_code grant"
    );
    let issuer_state = offer_json["credential_offer"]["grants"]["authorization_code"]
        ["issuer_state"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!issuer_state.is_empty());

    // 2. GET /authorize with a real PKCE pair and that issuer_state.
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
    // The issuer redirects via axum::response::Redirect::to, which uses
    // 303 See Other (not 302 Found) — see crates/foundry/src/server.rs.
    assert_eq!(authorize_res.status(), StatusCode::SEE_OTHER);
    let location = authorize_res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(REDIRECT_URI));
    let (code, wallet_state) = parse_code_and_state(&location);
    assert!(!code.is_empty());
    assert_eq!(wallet_state.as_deref(), Some("xyz-state"));

    // 3. POST /token with grant_type=authorization_code.
    let wallet_app = wallet_router(state.clone());
    let token_form_body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={CLIENT_ID}&code_verifier={CODE_VERIFIER}",
        urlencoding_encode(REDIRECT_URI),
    );
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(token_form_body))
        .unwrap();

    let token_res = wallet_app.oneshot(token_req).await.unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);

    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    assert_eq!(token_json["token_type"], "Bearer");
    assert!(!token_json["access_token"].as_str().unwrap().is_empty());
    // OpenID4VCI 1.0 moved challenge issuance out of the Token Response and
    // into the Nonce Endpoint (Section 7), so `c_nonce` must not appear here.
    assert!(token_json.get("c_nonce").is_none());
}

#[tokio::test]
async fn authorize_with_wrong_redirect_uri_returns_400_not_a_redirect() {
    let (state, _dir) = setup_test_app().await;

    let offer_json = create_authz_code_offer(&state).await;
    let issuer_state = offer_json["credential_offer"]["grants"]["authorization_code"]
        ["issuer_state"]
        .as_str()
        .unwrap()
        .to_string();

    let wallet_app = wallet_router(state.clone());
    let code_challenge = code_challenge_for(CODE_VERIFIER);
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={}\
         &state=xyz-state&code_challenge={code_challenge}&code_challenge_method=S256\
         &issuer_state={issuer_state}",
        urlencoding_encode("https://evil.example.com/callback"),
    );
    let authorize_req = Request::builder()
        .method("GET")
        .uri(authorize_uri)
        .body(Body::empty())
        .unwrap();

    let authorize_res = wallet_app.oneshot(authorize_req).await.unwrap();
    assert_eq!(authorize_res.status(), StatusCode::BAD_REQUEST);
    assert!(
        authorize_res.headers().get(header::LOCATION).is_none(),
        "an untrusted redirect_uri must never be redirected to"
    );

    let body_bytes = axum::body::to_bytes(authorize_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "invalid_request");
}

/// Minimal application/x-www-form-urlencoded-safe percent-encoding for the
/// small set of characters that appear in the custom-scheme redirect_uri
/// values used in these tests (`:`, `/`).
fn urlencoding_encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Extract and percent-decode the `code` and `state` query parameters from a
/// redirect Location header produced by `append_query` in server.rs, which
/// percent-encodes every non-alphanumeric character (including `-`) via
/// `NON_ALPHANUMERIC`.
fn parse_code_and_state(location: &str) -> (String, Option<String>) {
    let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = String::new();
    let mut state = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap();
        let decoded = percent_encoding::percent_decode_str(value)
            .decode_utf8()
            .unwrap()
            .to_string();
        match key {
            "code" => code = decoded,
            "state" => state = Some(decoded),
            _ => {}
        }
    }
    (code, state)
}
