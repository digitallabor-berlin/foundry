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
use josekit::jwk::alg::ec::EcKeyPair;
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
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

    // A real signing key is required to reach the /credential happy path
    // (VCI-0064/0067/0078); authorization_code_flow.rs's copy of this fixture
    // never needs one because it stops at /token.
    let key_path = dir.path().join("issuer.pem");
    let km = foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
        .unwrap();
    std::fs::write(&key_path, km.private_pem).unwrap();
    let mut keys = BTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        foundry_core::config::KeyEntry {
            private_key: key_path.to_str().unwrap().to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );

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
        keys,
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

/// A `POST /admin/issuance/offers` (pre-authorized_code grant) followed by a
/// `POST /token` exchange, exactly as `wallet_issuance.rs`'s
/// `issue_offer_and_get_access_token` does — duplicated here rather than
/// imported, per this run's Global Constraint that new conformance tests live
/// in new files.
async fn issue_pre_auth_offer_and_get_access_token(state: &AppState) -> String {
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": { "given_name": "Alice" },
        "tx_code_required": false,
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
    let pre_auth_code = offer_json["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .unwrap();

    let wallet_app = wallet_router(state.clone());
    let token_form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
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
    token_json["access_token"].as_str().unwrap().to_string()
}

async fn mint_c_nonce(state: &AppState) -> String {
    let wallet_app = wallet_router(state.clone());
    let nonce_req = Request::builder()
        .method("POST")
        .uri("/nonce")
        .body(Body::empty())
        .unwrap();
    let nonce_res = wallet_app.oneshot(nonce_req).await.unwrap();
    assert_eq!(nonce_res.status(), StatusCode::OK);
    let nonce_bytes = axum::body::to_bytes(nonce_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let nonce_json: serde_json::Value = serde_json::from_slice(&nonce_bytes).unwrap();
    nonce_json["c_nonce"].as_str().unwrap().to_string()
}

/// A proof-of-possession JWT with a bare `jwk` header, exactly as
/// `wallet_issuance.rs`'s `create_proof` builds one.
fn create_proof(c_nonce: &str, issuer: &str) -> String {
    let keypair = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(issuer)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

// ---------------------------------------------------------------------------
// VCI-0062 — OpenID4VCI Credential Request (L875): an unencrypted Credential
// Request MUST use media type `application/json`.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0062_credential_request_requires_json_content_type() {
    let (state, _dir) = setup_test_app().await;
    let access_token = issue_pre_auth_offer_and_get_access_token(&state).await;

    let wallet_app = wallet_router(state.clone());
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from("not json at all"))
        .unwrap();

    let cred_res = wallet_app.oneshot(cred_req).await.unwrap();

    assert_eq!(
        cred_res.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "a Credential Request whose Content-Type is not application/json must be rejected"
    );
}

// ---------------------------------------------------------------------------
// VCI-0064 / VCI-0067 — OpenID4VCI Credential Response (L966, L971): on
// immediate issuance the Credential Issuer MUST respond with HTTP 200, and an
// unencrypted Credential Response MUST use media type `application/json`.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0064_0067_credential_response_uses_http_200_and_json_content_type() {
    let (state, _dir) = setup_test_app().await;
    let access_token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let c_nonce = mint_c_nonce(&state).await;
    let proof_jwt = create_proof(&c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });
    let wallet_app = wallet_router(state.clone());
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(cred_req_body.to_string()))
        .unwrap();

    let cred_res = wallet_app.oneshot(cred_req).await.unwrap();

    assert_eq!(cred_res.status(), StatusCode::OK);
    assert_eq!(
        cred_res
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );
}

// ---------------------------------------------------------------------------
// VCI-0078 — OpenID4VCI Credential Error Response (L1041): payload-related
// errors MUST use the specific error codes of this section (e.g.
// `invalid_nonce`) rather than a less specific code.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-VCI-04: OpenID4VCI Credential Error Response (L1041) — a proof rejected solely for an invalid/expired c_nonce MUST report `invalid_nonce`, not the generic `invalid_proof`"]
async fn vci_0078_expired_nonce_reports_invalid_nonce_not_invalid_proof() {
    let (state, _dir) = setup_test_app().await;
    let access_token = issue_pre_auth_offer_and_get_access_token(&state).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let c_nonce = foundry_issuer::issue_nonce(
        state.nonce_secret.as_ref(),
        now - foundry_issuer::C_NONCE_TTL_SECS as i64 - 10,
    )
    .unwrap()
    .c_nonce;
    let proof_jwt = create_proof(&c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });
    let wallet_app = wallet_router(state.clone());
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(cred_req_body.to_string()))
        .unwrap();

    let cred_res = wallet_app.oneshot(cred_req).await.unwrap();
    assert_eq!(cred_res.status(), StatusCode::BAD_REQUEST);
    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();

    assert_eq!(
        cred_json["error"], "invalid_nonce",
        "an expired c_nonce is the invalid_nonce case, not generic invalid_proof"
    );
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
