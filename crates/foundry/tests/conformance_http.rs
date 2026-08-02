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
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, LoggingConfig,
    Mode, ServerConfig, StatusListConfig, StorageConfig, TrustAnchor, VerifierConfig,
    WalletFacingConfig,
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

// ---------------------------------------------------------------------------
// VCI-0032 — OpenID4VCI Authorization Error Response (L632): the
// Authorization Error Response MUST be made as defined in RFC6749.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0032_authorize_error_redirect_encodes_error_per_rfc6749() {
    let (state, _dir) = setup_test_app().await;
    let issuer_state = create_authz_code_offer_issuer_state(&state).await;

    let wallet_app = wallet_router(state.clone());
    let code_challenge = code_challenge_for(CODE_VERIFIER);
    // `redirect_uri` and `issuer_state` are both valid and trusted here, so
    // the rejected `code_challenge_method` (RFC6749/PKCE requires S256, not
    // `plain`) surfaces via `AuthorizeOutcome::ErrorRedirect`, not
    // `DirectError` — exactly the same domain-level path already proven by
    // foundry-issuer's `wrong_code_challenge_method_is_an_error_redirect`;
    // this test captures the HTTP-level rendering of that outcome.
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={}\
         &state=xyz-state&code_challenge={code_challenge}&code_challenge_method=plain\
         &issuer_state={issuer_state}",
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
        "RFC6749 SS4.1.2.1 delivers an Authorization Error Response via redirect, not a direct error body"
    );
    let location = authorize_res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with(REDIRECT_URI));
    // `append_query` (server.rs) percent-encodes every parameter value with
    // `NON_ALPHANUMERIC`, which also escapes `_` and `-` (%5F / %2D) -- so
    // `error`/`state` are asserted against their encoded form here rather
    // than the plain ASCII a human would type.
    assert!(
        location.contains("error=invalid%5Frequest"),
        "RFC6749 SS4.1.2.1 requires the `error` parameter on the redirect; got {location}"
    );
    assert!(
        location.contains("state=xyz%2Dstate"),
        "RFC6749 SS4.1.2.1 requires echoing `state` on the redirect when the client sent one; got {location}"
    );
}

// ---------------------------------------------------------------------------
// VCI-0117 / VCI-0119 — OpenID4VCI Credential Issuer Metadata (L1320, L1325):
// the Credential Issuer MUST respond with HTTP 200 and the metadata
// parameters, and MUST indicate the media type via the `Content-Type` header.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0117_0119_issuer_metadata_endpoint_returns_http_200_and_json_content_type() {
    let (state, _dir) = setup_test_app().await;
    let wallet_app = wallet_router(state.clone());

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/openid-credential-issuer")
        .body(Body::empty())
        .unwrap();
    let res = wallet_app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );
}

// ---------------------------------------------------------------------------
// GAP-VCI-11 — OpenID4VCI Credential Issuer Metadata (L1312): Issuers
// publishing metadata MUST make it available at the path formed by inserting
// `/.well-known/openid-credential-issuer` into the Credential Issuer
// Identifier *between the host and path components* — per the spec's own
// worked example (L1314), a Credential Issuer Identifier of
// `https://issuer.example.com/tenant1` must serve its metadata from
// `https://issuer.example.com/.well-known/openid-credential-issuer/tenant1`.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-VCI-11: OpenID4VCI Credential Issuer Metadata (L1312) — when config.issuer.credential_issuer carries a path component, the well-known metadata document is never reachable at the spec-mandated location: wallet_router (server.rs) always registers the endpoint at the literal root path '/.well-known/openid-credential-issuer', with no logic that inserts any path segment from config"]
async fn gap_vci_11_well_known_metadata_ignores_credential_issuer_path_component() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");
    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://issuer.example.com/tenant1".to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: false,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: Some("test-admin-key".to_string()),
                api_key_env: None,
                swagger_ui_enabled: false,
                console_enabled: false,
            },
        },
        storage: StorageConfig {
            path: db_path.to_str().unwrap().to_string(),
            transaction_ttl_secs: 600,
        },
        keys: BTreeMap::new(),
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://issuer.example.com/tenant1".to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Disabled,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
            },
            key_attestation: AttestationMode {
                mode: Mode::Disabled,
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
        credential_types: vec![],
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
    let wallet_app = wallet_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/openid-credential-issuer/tenant1")
        .body(Body::empty())
        .unwrap();
    let res = wallet_app.oneshot(req).await.unwrap();

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the well-known metadata document MUST be reachable at the path formed by inserting \
         /.well-known/openid-credential-issuer between the host and path components of the \
         Credential Issuer Identifier"
    );
}

// ---------------------------------------------------------------------------
// Shared harness for VP-0134 and the AGENTS.md Sec4.3 HTTP-layer mapping
// check — a full OpenID4VP `direct_post.jwt` round trip exercised through
// the real HTTP routers (GET /vp/request/:id, POST /vp/response/:id), so
// response headers (not just status codes) can be asserted directly. Closely
// modeled on crates/foundry/tests/wallet_verification.rs's `setup_test_app` /
// `full_verification_flow_end_to_end` / `run_status_flow`; duplicated rather
// than imported, per this run's Global Constraint that new conformance tests
// live in new files and never modify existing ones.
// ---------------------------------------------------------------------------
async fn setup_verifier_flow_app() -> (AppState, tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");
    let issuer_key_path = dir.path().join("issuer.pem");
    let verifier_key_path = dir.path().join("verifier.pem");

    let root = foundry_core::pki::new_ca("Foundry Task18 Test Root CA", 365).unwrap();
    let issuer_leaf = foundry_core::pki::issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();
    std::fs::write(&issuer_key_path, &issuer_leaf.key_pem).unwrap();

    let verifier_km =
        foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
            .unwrap();
    std::fs::write(&verifier_key_path, &verifier_km.private_pem).unwrap();

    let trust_root_path = dir.path().join("trust_root.pem");
    std::fs::write(&trust_root_path, &root.cert_pem).unwrap();

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let mut keys = BTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        foundry_core::config::KeyEntry {
            private_key: issuer_key_path.to_str().unwrap().to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );
    keys.insert(
        "verifier_signing".to_string(),
        foundry_core::config::KeyEntry {
            private_key: verifier_key_path.to_str().unwrap().to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://localhost:8443".to_string(),
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
        trust_anchors: vec![foundry_core::config::TrustAnchor {
            name: "test_ca".to_string(),
            certs: trust_root_path.to_str().unwrap().to_string(),
        }],
        issuer: IssuerConfig {
            credential_issuer: "https://localhost:8443".to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Disabled,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
            },
            key_attestation: AttestationMode {
                mode: Mode::Disabled,
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
            vct: Some("https://localhost:8443/vct/pid".to_string()),
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

    (state, dir, issuer_leaf.cert_pem, issuer_leaf.key_pem)
}

fn der_b64_for_x5c(pem_bytes: &[u8]) -> String {
    std::str::from_utf8(pem_bytes)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

/// Create a verification request and GET /vp/request/:id, returning the
/// verification id plus the fields a holder needs to build a Presentation:
/// `client_id`, `nonce`, and the ephemeral encryption JWK.
async fn begin_verification_request(
    state: &AppState,
) -> (String, String, String, serde_json::Value) {
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    let create_req_body = serde_json::json!({
        "dcql_query": {
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
            }]
        },
        "transport": "request_uri"
    });
    let create_req = Request::builder()
        .method("POST")
        .uri("/admin/verification/requests")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(create_req_body.to_string()))
        .unwrap();
    let create_res = admin_app.oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: foundry_verifier::CreateVerificationResponse =
        serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.oneshot(get_req).await.unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    (verification_id, client_id, nonce, ephem_public_jwk)
}

/// Build a KB-JWT-bound SD-JWT VC presentation for the `pid` credential type,
/// signed by a fresh holder key and the harness's issuer leaf certificate.
/// `status_list` is `(index, uri)` when the credential should carry a
/// `status.status_list` claim.
fn build_presentation(
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
    client_id: &str,
    nonce: &str,
    status_list: Option<(u64, String)>,
) -> String {
    let holder_kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer = foundry_core::crypto::FileSigner::from_pem(
        &holder_kp.to_pem_private_key(),
        foundry_core::crypto::SignatureAlgorithm::Es256,
    )
    .unwrap();
    let issuer_signer = foundry_core::crypto::FileSigner::from_pem(
        issuer_key_pem.as_bytes(),
        foundry_core::crypto::SignatureAlgorithm::Es256,
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut select = serde_json::Map::new();
    select.insert("given_name".to_string(), serde_json::json!("Alice"));

    let (status_list_index, status_list_uri) = match status_list {
        Some((idx, uri)) => (Some(idx), Some(uri)),
        None => (None, None),
    };

    let claims = foundry_sd_jwt_vc::builder::IssuerClaims {
        iss: "localhost".to_string(),
        sub: "did:example:holder".to_string(),
        iat: (now - 100) as i64,
        exp: (now + 3600) as i64,
        vct: "https://localhost:8443/vct/pid".to_string(),
        cnf_jwk: holder_pub_jwk,
        status_list_index,
        status_list_uri,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };
    let issuer_pres = foundry_sd_jwt_vc::builder::build_sd_jwt_vc(
        claims,
        &issuer_signer,
        Some(vec![der_b64_for_x5c(issuer_cert_pem.as_bytes())]),
    )
    .unwrap();

    foundry_sd_jwt_vc::builder::attach_kb_jwt(issuer_pres, &holder_signer, client_id, nonce)
        .unwrap()
}

// ---------------------------------------------------------------------------
// VP-0134 — OpenID4VP Response / Response Mode `direct_post` (L1276): on
// successful processing the Response URI MUST respond with HTTP 200,
// `Content-Type: application/json`, and a JSON object body.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vp_0134_response_on_success_is_http_200_with_json_content_type() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_verifier_flow_app().await;
    let (verification_id, client_id, nonce, ephem_public_jwk) =
        begin_verification_request(&state).await;

    let presentation =
        build_presentation(&issuer_cert_pem, &issuer_key_pem, &client_id, &nonce, None);
    let jwe_str = foundry_core::crypto::jwe::encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    let wallet_app = wallet_router(state.clone());
    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();
    let post_resp_res = wallet_app.oneshot(post_resp_req).await.unwrap();

    assert_eq!(post_resp_res.status(), StatusCode::OK);
    assert_eq!(
        post_resp_res
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json",
        "VP-0134: a successful Response URI response MUST use Content-Type: application/json"
    );

    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_result: foundry_verifier::VerificationResult =
        serde_json::from_slice(&verify_bytes).unwrap();
    assert!(verify_result.verified);
}

// ---------------------------------------------------------------------------
// AGENTS.md Sec4.3 — Network status-fetch unavailability MUST surface as
// HTTP 502 (BAD_GATEWAY), not a policy verdict, all the way through the real
// `POST /vp/response/:id` HTTP endpoint — extending Task 16's
// `vp_0152_status_endpoint_unreachable_is_a_hard_error_through_full_verification`
// (foundry-verifier library level) with HTTP-layer evidence for VP-0152.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vp_0152_status_fetch_network_failure_maps_to_http_502() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_verifier_flow_app().await;
    let (verification_id, client_id, nonce, ephem_public_jwk) =
        begin_verification_request(&state).await;

    // Bind a listener to reserve a port, then drop it immediately without
    // ever serving anything: connecting to that port now fails fast with
    // connection-refused, a genuine (and quick) network failure rather than
    // a slow timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let dead_status_uri = format!("http://{addr}/statuslists/1");

    let presentation = build_presentation(
        &issuer_cert_pem,
        &issuer_key_pem,
        &client_id,
        &nonce,
        Some((0, dead_status_uri)),
    );
    let jwe_str = foundry_core::crypto::jwe::encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    let wallet_app = wallet_router(state.clone());
    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();
    let post_resp_res = wallet_app.oneshot(post_resp_req).await.unwrap();

    assert_eq!(
        post_resp_res.status(),
        StatusCode::BAD_GATEWAY,
        "AGENTS.md Sec4.3: a Status List fetch network failure MUST surface as HTTP 502, not a policy verdict"
    );
    let body_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "status_unavailable");
}

// ---------------------------------------------------------------------------
// Task 10 (GAP-VCI-14): server.rs's /token handler wiring for the Client
// Attestation PoP JWT (ABCA draft -07 sect-5.2/sect-6.2/sect-6.3) -- reading the
// OAuth-Client-Attestation-PoP header alongside the existing attestation
// header, and sourcing the expected `aud` from the published AS metadata's
// own `issuer` field (not re-derived from config) so the two can never drift.
// ---------------------------------------------------------------------------

const POP_TEST_WALLET_SUB: &str = "https://wallet.example.org";

/// Real wall-clock time -- pki::new_ca/pki::issue_leaf stamp validity windows
/// using now_utc(), not an injectable clock, so a fixed fixture timestamp
/// would spuriously fail chain validation.
fn pop_test_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A validly signed Wallet Attestation JWT (chained to a fresh CA) plus a
/// Client Attestation PoP JWT that verifies against its `cnf.jwk` (ABCA
/// sect-5.2 r3). Returns `(attestation_jwt, pop_jwt, ca_cert_pem)`.
fn signed_attestation_and_pop(now: i64, aud: &str, jti: &str) -> (String, String, String) {
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::build_x5c;
    use josekit::jws::JwsSigner;

    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let mut cnf_jwk = kp.to_jwk_public_key();
    cnf_jwk.set_algorithm("ES256");
    let pop_signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();

    let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "wallet-provider.example.com",
        &["wallet-provider.example.com".to_string()],
        365,
    )
    .unwrap();
    let x5c = build_x5c(&[leaf.cert_pem.clone().into_bytes()]).unwrap();

    let header = serde_json::json!({
        "typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": x5c,
    });
    let payload = serde_json::json!({
        "iss": "https://wallet-provider.example.com",
        "sub": POP_TEST_WALLET_SUB,
        "exp": now + 100_000,
        "cnf": { "jwk": cnf_jwk },
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let leaf_signer =
        FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
    let sig_b64 = URL_SAFE_NO_PAD.encode(leaf_signer.sign(signing_input.as_bytes()).unwrap());
    let attestation_jwt = format!("{signing_input}.{sig_b64}");

    let pop_header = serde_json::json!({
        "typ": "oauth-client-attestation-pop+jwt", "alg": "ES256",
    });
    let pop_payload = serde_json::json!({
        "iss": POP_TEST_WALLET_SUB, "aud": aud, "jti": jti, "iat": now,
    });
    let pop_header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&pop_header).unwrap());
    let pop_payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&pop_payload).unwrap());
    let pop_signing_input = format!("{pop_header_b64}.{pop_payload_b64}");
    let pop_sig_b64 =
        URL_SAFE_NO_PAD.encode(pop_signer.sign(pop_signing_input.as_bytes()).unwrap());
    let pop_jwt = format!("{pop_signing_input}.{pop_sig_b64}");

    (attestation_jwt, pop_jwt, ca.cert_pem)
}

/// Same shape as `setup_test_app`, but with `wallet_attestation: Mode::Required`
/// pointed at `ca_pem` (written to a temp file -- `TrustStore::from_config`
/// reads `certs` from disk).
async fn setup_pop_test_app(ca_pem: &str) -> (AppState, tempfile::TempDir, tempfile::TempDir) {
    setup_pop_test_app_with_mode(ca_pem, Mode::Required).await
}

/// As above, but with the wallet-attestation `mode` chosen by the caller.
///
/// `Mode::Optional` is the only setting under which "no attestation presented"
/// is an *accepted* outcome, which makes it the only setting that can
/// distinguish "header rejected as malformed" from "header silently degraded to
/// absent". A test of that distinction run under `Mode::Required` passes either
/// way and proves nothing.
async fn setup_pop_test_app_with_mode(
    ca_pem: &str,
    wallet_attestation_mode: Mode,
) -> (AppState, tempfile::TempDir, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");
    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

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

    let ca_dir = tempfile::tempdir().unwrap();
    let ca_path = ca_dir.path().join("wallet-provider-ca.pem");
    std::fs::write(&ca_path, ca_pem).unwrap();

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
                mode: wallet_attestation_mode,
                trusted_anchors: vec![TrustAnchor {
                    name: "wallet-provider-ca".to_string(),
                    certs: ca_path.to_str().unwrap().to_string(),
                }],
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
    (state, dir, ca_dir)
}

/// Creates a `pre-authorized_code` offer via the Admin API and returns its
/// code, without redeeming it -- the caller drives the `/token` request
/// itself so it can attach the attestation/pop headers.
async fn create_pre_auth_offer(state: &AppState) -> String {
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
    offer_json["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn gap_vci_14_token_request_with_attestation_and_matching_pop_is_accepted() {
    let now = pop_test_now_secs();
    let (attestation_jwt, pop_jwt, ca_pem) =
        signed_attestation_and_pop(now, "https://issuer.example.com", "jti-http-happy-1");
    let (state, _dir, _ca_dir) = setup_pop_test_app(&ca_pem).await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    let wallet_app = wallet_router(state.clone());
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("OAuth-Client-Attestation", &attestation_jwt)
        .header("OAuth-Client-Attestation-PoP", &pop_jwt)
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();

    assert_eq!(
        token_res.status(),
        StatusCode::OK,
        "a valid attestation + matching pop must be accepted"
    );
}

#[tokio::test]
async fn gap_vci_14_token_request_with_attestation_but_no_pop_is_rejected_as_invalid_client() {
    let now = pop_test_now_secs();
    let (attestation_jwt, _pop_jwt, ca_pem) =
        signed_attestation_and_pop(now, "https://issuer.example.com", "jti-http-nopop-1");
    let (state, _dir, _ca_dir) = setup_pop_test_app(&ca_pem).await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    let wallet_app = wallet_router(state.clone());
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("OAuth-Client-Attestation", &attestation_jwt)
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();

    assert_eq!(token_res.status(), StatusCode::BAD_REQUEST);
    let body_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "invalid_client");
}

/// ABCA sect-6.1: the `OAuth-Client-Attestation-PoP` header MUST be read
/// case-insensitively. A lower-case wire header name must still be found.
#[tokio::test]
async fn gap_vci_14_pop_header_is_read_case_insensitively() {
    let now = pop_test_now_secs();
    let (attestation_jwt, pop_jwt, ca_pem) =
        signed_attestation_and_pop(now, "https://issuer.example.com", "jti-http-case-1");
    let (state, _dir, _ca_dir) = setup_pop_test_app(&ca_pem).await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    let wallet_app = wallet_router(state.clone());
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("oauth-client-attestation", &attestation_jwt)
        .header("oauth-client-attestation-pop", &pop_jwt)
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();

    assert_eq!(
        token_res.status(),
        StatusCode::OK,
        "a lower-case wire header name must still be recognised as the PoP header"
    );
}

/// Proves the wiring passes the issuer identifier -- not the token endpoint
/// URL or any other AS-metadata URL -- as the PoP's expected `aud`.
#[tokio::test]
async fn gap_vci_14_pop_aud_as_token_endpoint_url_is_rejected() {
    let now = pop_test_now_secs();
    let (attestation_jwt, pop_jwt, ca_pem) = signed_attestation_and_pop(
        now,
        "https://issuer.example.com/token",
        "jti-http-wrongaud-1",
    );
    let (state, _dir, _ca_dir) = setup_pop_test_app(&ca_pem).await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    let wallet_app = wallet_router(state.clone());
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("OAuth-Client-Attestation", &attestation_jwt)
        .header("OAuth-Client-Attestation-PoP", &pop_jwt)
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();

    assert_eq!(
        token_res.status(),
        StatusCode::BAD_REQUEST,
        "a pop whose aud is the token endpoint URL rather than the issuer identifier must be rejected"
    );
    let body_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "invalid_client");
}

// ---------------------------------------------------------------------------
// ABCA draft -07 §6.2 rules 1 and 2: there MUST be *precisely one* of each
// client-attestation header. `HeaderMap::get` yields only the first of several,
// so without an explicit count check a duplicated header would be silently
// processed against whichever copy happened to arrive first -- the classic
// request-smuggling shape, where two intermediaries disagree about which value
// is authoritative. Both directions are pinned below, plus the adjacent
// non-UTF-8 case, where a present-but-unreadable header must NOT degrade into
// "absent" (which `Mode::Optional` would then wave through unexamined).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gap_vci_14_duplicate_pop_header_is_rejected_per_abca_6_2_rule_2() {
    let now = pop_test_now_secs();
    let (attestation_jwt, pop_jwt, ca_pem) =
        signed_attestation_and_pop(now, "https://issuer.example.com", "jti-http-duppop-1");
    let (state, _dir, _ca_dir) = setup_pop_test_app(&ca_pem).await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    let wallet_app = wallet_router(state.clone());
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("OAuth-Client-Attestation", &attestation_jwt)
        // The *same*, entirely valid PoP sent twice. Note this would be
        // accepted by a first-value-wins reader, which is exactly the point:
        // the rejection must come from the count, not from the content.
        .header("OAuth-Client-Attestation-PoP", &pop_jwt)
        .header("OAuth-Client-Attestation-PoP", &pop_jwt)
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();

    assert_eq!(
        token_res.status(),
        StatusCode::BAD_REQUEST,
        "a duplicated OAuth-Client-Attestation-PoP header must be rejected even when both copies are valid"
    );
    let body_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "invalid_client");
}

#[tokio::test]
async fn gap_vci_14_duplicate_attestation_header_is_rejected_per_abca_6_2_rule_1() {
    let now = pop_test_now_secs();
    let (attestation_jwt, pop_jwt, ca_pem) =
        signed_attestation_and_pop(now, "https://issuer.example.com", "jti-http-dupatt-1");
    let (state, _dir, _ca_dir) = setup_pop_test_app(&ca_pem).await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    let wallet_app = wallet_router(state.clone());
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("OAuth-Client-Attestation", &attestation_jwt)
        .header("OAuth-Client-Attestation", &attestation_jwt)
        .header("OAuth-Client-Attestation-PoP", &pop_jwt)
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();

    assert_eq!(
        token_res.status(),
        StatusCode::BAD_REQUEST,
        "a duplicated OAuth-Client-Attestation header must be rejected even when both copies are valid"
    );
    let body_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "invalid_client");
}

/// A present-but-non-UTF-8 attestation header must be rejected, not silently
/// treated as absent.
///
/// Two setup choices here are load-bearing, and getting either wrong makes the
/// test pass vacuously — both mistakes were made and caught while writing it:
///
/// 1. **`Mode::Optional`, not `Required`.** Under `Required`, a header that
///    degrades to `None` is rejected anyway because absence is itself an error,
///    so the assertion holds with or without the fix.
/// 2. **No PoP header at all.** With a PoP present but the attestation degraded
///    to `None`, the mode matrix rejects the request for an unrelated reason (a
///    PoP with no attestation has no `cnf.jwk` to verify against) — again 400
///    either way.
///
/// With `Optional` *and* no PoP, absent+absent is an accepted combination that
/// returns HTTP 200. So 400 can only mean the malformed attestation header was
/// actually noticed rather than silently swallowed. Confirmed by reverting the
/// fix and watching this fail.
#[tokio::test]
async fn gap_vci_14_non_utf8_attestation_header_is_rejected_not_treated_as_absent() {
    let now = pop_test_now_secs();
    let (_attestation_jwt, _pop_jwt, ca_pem) =
        signed_attestation_and_pop(now, "https://issuer.example.com", "jti-http-nonutf8-1");
    let (state, _dir, _ca_dir) = setup_pop_test_app_with_mode(&ca_pem, Mode::Optional).await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    // 0xFF is never valid UTF-8, and `HeaderValue::from_bytes` accepts it
    // (HTTP header values are opaque octets), so this reaches the handler.
    let bad_value = axum::http::HeaderValue::from_bytes(b"eyJhbGc\xffiJFUzI1NiJ9.e30.sig")
        .expect("0xFF is a legal header octet even though it is not UTF-8");

    let wallet_app = wallet_router(state.clone());
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("OAuth-Client-Attestation", bad_value)
        // Deliberately NO PoP header -- see the doc comment.
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();

    assert_eq!(
        token_res.status(),
        StatusCode::BAD_REQUEST,
        "a non-UTF-8 attestation header must be rejected as malformed, not silently \
         treated as 'no attestation presented' (which Mode::Optional would allow)"
    );
    let body_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "invalid_client");
}
