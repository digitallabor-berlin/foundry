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
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
    LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, TrustAnchor,
    VerifierConfig, WalletFacingConfig,
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
                enabled: false,
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://issuer.example.com/vct/pid".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
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
    // `append_query` percent-encodes with NON_ALPHANUMERIC, which also escapes
    // `:` and `/` -- assert against the encoded form of the configured
    // credential_issuer, matching the pattern vci_0032 already uses for `error`.
    assert!(
        location.contains("iss=https%3A%2F%2Fissuer%2Eexample%2Ecom"),
        "iss must equal the configured issuer.credential_issuer, percent-encoded; got {location}"
    );
}

// ---------------------------------------------------------------------------
// RFC 9207 §2, GAP-HAIP-02: "In authorization responses to the client,
// including error responses, an authorization server ... MUST indicate its
// identity by including the iss parameter" -- the error redirect path must
// carry iss too, not only the success path haip_0008 above covers.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn gap_haip_02_error_redirect_also_includes_iss() {
    let (state, _dir) = setup_test_app().await;
    let issuer_state = create_authz_code_offer_issuer_state(&state).await;

    let wallet_app = wallet_router(state.clone());
    let code_challenge = code_challenge_for(CODE_VERIFIER);
    // code_challenge_method=plain forces AuthorizeOutcome::ErrorRedirect, the
    // same trick vci_0032_authorize_error_redirect_encodes_error_per_rfc6749
    // already uses.
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
    assert_eq!(authorize_res.status(), StatusCode::SEE_OTHER);
    let location = authorize_res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // `append_query` percent-encodes with NON_ALPHANUMERIC, which also escapes
    // `_` (%5F) -- see vci_0032_authorize_error_redirect_encodes_error_per_rfc6749.
    assert!(
        location.contains("error=invalid%5Frequest"),
        "expected the ErrorRedirect path (invalid_request), got: {location}"
    );
    assert!(
        location.contains("iss=https%3A%2F%2Fissuer%2Eexample%2Ecom"),
        "RFC9207 s2 requires iss on error responses too, not only success; got {location}"
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

/// Same shape as `setup_test_app`, but with `issuer.wallet_attestation.challenge_mode`
/// overridden. `Config` derives `Clone`, so the fixture is rebuilt rather than
/// mutated in place -- `AppState.config` is an `Arc<Config>`.
async fn setup_test_app_with_challenge_mode(mode: Mode) -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_test_app().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.wallet_attestation.challenge_mode = mode;
    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    (state, dir)
}

// ---------------------------------------------------------------------------
// ABCA draft -07 §8: the Challenge Endpoint. Task 5 of the ABCA
// challenge-retrieval / DPoP-nonce plan
// (docs/superpowers/plans/2026-08-04-abca-challenge-and-dpop-nonce-plan.md).
// ---------------------------------------------------------------------------

/// ABCA §8: "The Authorization Server MUST make the response uncacheable by
/// adding a Cache-Control header field including the value no-store."
#[tokio::test]
async fn challenge_endpoint_mints_a_challenge_when_enabled() {
    let (state, _dir) = setup_test_app_with_challenge_mode(Mode::Optional).await;
    let wallet_app = wallet_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/challenge")
        .body(Body::empty())
        .unwrap();
    let res = wallet_app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(axum::http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!body["attestation_challenge"]
        .as_str()
        .expect("attestation_challenge")
        .is_empty());
}

/// The route is not registered when the mechanism is disabled, so a wallet
/// cannot be misled into thinking ABCA §8 is supported.
#[tokio::test]
async fn challenge_endpoint_is_absent_when_disabled() {
    let (state, _dir) = setup_test_app().await; // challenge_mode: Mode::Disabled (the default)
    let wallet_app = wallet_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/challenge")
        .body(Body::empty())
        .unwrap();
    let res = wallet_app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// ABCA §8 unpredictability, exercised at the HTTP layer.
#[tokio::test]
async fn successive_challenges_differ() {
    let (state, _dir) = setup_test_app_with_challenge_mode(Mode::Optional).await;

    let fetch = || {
        let wallet_app = wallet_router(state.clone());
        async move {
            let req = Request::builder()
                .method("POST")
                .uri("/challenge")
                .body(Body::empty())
                .unwrap();
            let res = wallet_app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
            body["attestation_challenge"].as_str().unwrap().to_string()
        }
    };

    let a = fetch().await;
    let b = fetch().await;
    assert_ne!(a, b);
}

/// The route's registration and the metadata field's presence must never
/// disagree -- either both signal support, or neither does.
#[tokio::test]
async fn metadata_and_route_availability_agree() {
    for mode in [Mode::Optional, Mode::Disabled] {
        let (state, _dir) = setup_test_app_with_challenge_mode(mode.clone()).await;
        let wallet_app = wallet_router(state.clone());

        let meta_req = Request::builder()
            .method("GET")
            .uri("/.well-known/oauth-authorization-server")
            .body(Body::empty())
            .unwrap();
        let meta_res = wallet_app.oneshot(meta_req).await.unwrap();
        assert_eq!(meta_res.status(), StatusCode::OK);
        let meta_bytes = axum::body::to_bytes(meta_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let meta_json: serde_json::Value = serde_json::from_slice(&meta_bytes).unwrap();
        let metadata_advertises = meta_json.get("challenge_endpoint").is_some();

        let wallet_app = wallet_router(state.clone());
        let challenge_req = Request::builder()
            .method("POST")
            .uri("/challenge")
            .body(Body::empty())
            .unwrap();
        let challenge_res = wallet_app.oneshot(challenge_req).await.unwrap();
        let route_exists = challenge_res.status() == StatusCode::OK;

        assert_eq!(
            metadata_advertises, route_exists,
            "metadata and route availability disagree for {mode:?}: \
             advertises={metadata_advertises}, route_exists={route_exists}"
        );
        match mode {
            Mode::Optional => assert!(route_exists, "expected the route to exist under Optional"),
            Mode::Disabled => assert!(
                !route_exists,
                "expected the route to be absent under Disabled"
            ),
            Mode::Required => unreachable!("not exercised by this test"),
        }
    }
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
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            key_attestation: AttestationMode {
                mode: Mode::Disabled,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
        },
        credential_types: vec![],
        verifier: VerifierConfig {
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

    // HAIP OpenID4VP L256: x509_hash requires a certificate to hash, so the
    // verifier signing key needs a leaf certificate now, not a bare key pair.
    let verifier_leaf = foundry_core::pki::issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();
    std::fs::write(&verifier_key_path, &verifier_leaf.key_pem).unwrap();
    let verifier_cert_path = dir.path().join("verifier_leaf_cert.pem");
    std::fs::write(&verifier_cert_path, &verifier_leaf.cert_pem).unwrap();

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
            x5c: Some(verifier_cert_path.to_str().unwrap().to_string()),
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
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            key_attestation: AttestationMode {
                mode: Mode::Disabled,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://localhost:8443/vct/pid".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
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
        sub: None,
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

    foundry_sd_jwt_vc::builder::attach_kb_jwt(issuer_pres, &holder_signer, client_id, nonce, None)
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
    signed_attestation_and_pop_with_challenge(now, aud, jti, None)
}

/// As `signed_attestation_and_pop`, but with an optional ABCA §5.2/§8 `challenge`
/// claim on the Client Attestation PoP JWT. Composes `build_wallet_attestation`
/// and `sign_pop` -- callers that need multiple PoPs bound to the *same*
/// attestation (e.g. a challenge-retry round trip) should call those two
/// directly instead, since each call to this function mints an unrelated CA
/// and key.
fn signed_attestation_and_pop_with_challenge(
    now: i64,
    aud: &str,
    jti: &str,
    challenge: Option<&str>,
) -> (String, String, String) {
    let (attestation_jwt, ca_pem, kp) = build_wallet_attestation(now);
    let pop_jwt = sign_pop(&kp, aud, jti, now, challenge);
    (attestation_jwt, pop_jwt, ca_pem)
}

/// Builds a Wallet Attestation JWT (ABCA §6.1) chained to a fresh CA. Returns
/// the JWT, the CA's cert PEM (for the trust anchor config), and the EC key
/// pair whose public JWK is embedded in the attestation's `cnf.jwk` -- sign a
/// matching Client Attestation PoP JWT against that same key with `sign_pop`.
///
/// Split out from `signed_attestation_and_pop_with_challenge` for Task 6 of the
/// ABCA/DPoP plan: some tests (a successful-response header, a challenge-retry
/// round trip) need two *different* PoP JWTs that both verify against one
/// attestation's `cnf.jwk` -- which requires reusing the same key pair, not
/// minting a fresh CA and key for each PoP.
fn build_wallet_attestation(now: i64) -> (String, String, EcKeyPair) {
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::build_x5c;

    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let mut cnf_jwk = kp.to_jwk_public_key();
    cnf_jwk.set_algorithm("ES256");

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

    (attestation_jwt, ca.cert_pem, kp)
}

/// Signs a Client Attestation PoP JWT (ABCA §5.2) against `kp`, the key
/// returned by `build_wallet_attestation`. `challenge` is the optional ABCA
/// §5.2/§8 `challenge` claim (Task 6 of the ABCA/DPoP plan).
fn sign_pop(kp: &EcKeyPair, aud: &str, jti: &str, iat: i64, challenge: Option<&str>) -> String {
    use josekit::jws::JwsSigner;

    let pop_signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
    let pop_header = serde_json::json!({
        "typ": "oauth-client-attestation-pop+jwt", "alg": "ES256",
    });
    let mut pop_payload = serde_json::json!({
        "iss": POP_TEST_WALLET_SUB, "aud": aud, "jti": jti, "iat": iat,
    });
    if let Some(c) = challenge {
        pop_payload["challenge"] = serde_json::json!(c);
    }
    let pop_header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&pop_header).unwrap());
    let pop_payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&pop_payload).unwrap());
    let pop_signing_input = format!("{pop_header_b64}.{pop_payload_b64}");
    let pop_sig_b64 =
        URL_SAFE_NO_PAD.encode(pop_signer.sign(pop_signing_input.as_bytes()).unwrap());
    format!("{pop_signing_input}.{pop_sig_b64}")
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
    setup_pop_test_app_with_modes(ca_pem, wallet_attestation_mode, Mode::Disabled).await
}

/// As above, but with `wallet_attestation.challenge_mode` also chosen by the
/// caller -- Task 6 of the ABCA challenge-retrieval / DPoP-nonce plan needs a
/// harness that can turn challenge verification on.
async fn setup_pop_test_app_with_modes(
    ca_pem: &str,
    wallet_attestation_mode: Mode,
    challenge_mode: Mode,
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
                challenge_mode,
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
                enabled: false,
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://issuer.example.com/vct/pid".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
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

// ---------------------------------------------------------------------------
// Task 8 of the ABCA challenge-retrieval / DPoP-nonce plan
// (docs/superpowers/plans/2026-08-04-abca-challenge-and-dpop-nonce-plan.md):
// DPoP-Nonce response wiring (RFC 9449 §8/§9) at /token (400) and /credential
// (401).
// ---------------------------------------------------------------------------

/// As `setup_test_app`, but with `issuer.dpop` overridden.
async fn setup_test_app_with_dpop(dpop: DpopConfig) -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_test_app().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.dpop = dpop;
    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    (state, dir)
}

/// Both knobs at once. The `/challenge` route exists only when
/// `wallet_attestation.challenge_mode` is not `Disabled`, and the `DPoP-Nonce`
/// header is emitted only when `dpop.nonce_mode` is not `Disabled`. Neither
/// existing helper sets both, and setting only one yields a 404 rather than a
/// missing header.
async fn setup_test_app_with_dpop_and_challenge_mode(
    dpop: DpopConfig,
    challenge_mode: Mode,
) -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_test_app().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.dpop = dpop;
    cfg.issuer.wallet_attestation.challenge_mode = challenge_mode;
    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    (state, dir)
}

/// A DPoP proof JWT (RFC 9449 §4.2), with an optional `nonce` claim (§8/§9,
/// Tasks 7-8 of the ABCA/DPoP-nonce plan) and an optional `ath` claim (§7, for
/// /credential presentations -- `access_token` is what gets hashed into it).
fn create_dpop_proof(
    kp: &EcKeyPair,
    method: &str,
    htu: &str,
    jti: &str,
    iat: i64,
    access_token: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("dpop+jwt");
    header.set_jwk(kp.to_jwk_public_key());

    let mut payload = JwtPayload::new();
    payload.set_claim("htm", Some(method.into())).unwrap();
    payload.set_claim("htu", Some(htu.into())).unwrap();
    payload.set_claim("iat", Some(iat.into())).unwrap();
    payload.set_claim("jti", Some(jti.into())).unwrap();
    if let Some(at) = access_token {
        let ath = foundry_issuer::access_token_hash(at);
        payload.set_claim("ath", Some(ath.into())).unwrap();
    }
    if let Some(n) = nonce {
        payload.set_claim("nonce", Some(n.into())).unwrap();
    }

    let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

async fn post_token_with_dpop(
    state: &AppState,
    pre_auth_code: &str,
    proof: &str,
) -> axum::http::Response<Body> {
    let wallet_app = wallet_router(state.clone());
    let token_form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
    );
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("DPoP", proof)
        .body(Body::from(token_form_body))
        .unwrap();
    wallet_app.oneshot(token_req).await.unwrap()
}

/// Mints a fresh `c_nonce` and holder proof internally, so each call is
/// independent -- no jti/nonce replay concerns between successive calls in
/// the same test.
async fn post_credential_with_dpop(
    state: &AppState,
    access_token: &str,
    proof: &str,
) -> axum::http::Response<Body> {
    let c_nonce = mint_c_nonce(state).await;
    let holder_proof = create_proof(&c_nonce, "https://issuer.example.com");
    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [holder_proof] },
    });
    let wallet_app = wallet_router(state.clone());
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
        .header("DPoP", proof)
        .body(Body::from(cred_req_body.to_string()))
        .unwrap();
    wallet_app.oneshot(cred_req).await.unwrap()
}

/// Drives the /token nonce handshake end-to-end (dpop.mode=Required,
/// dpop.nonce_mode=Required): a first request with no `nonce` claim is
/// rejected per RFC 9449 §8 and returns a fresh `DPoP-Nonce`; a second
/// request, re-signed with that nonce and a fresh `jti` (claim_dpop_jti burned
/// the first), succeeds. Returns the resulting DPoP-bound access token and the
/// keypair it is bound to. Assumes the caller's `state` already has
/// dpop.mode/nonce_mode set to Required.
async fn issue_bound_token_via_nonce_handshake(state: &AppState) -> (String, EcKeyPair) {
    let pre_auth_code = create_pre_auth_offer(state).await;
    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let now = pop_test_now_secs();
    let htu = "https://issuer.example.com/token";

    let first_proof = create_dpop_proof(&kp, "POST", htu, "jti-handshake-1", now, None, None);
    let first_res = post_token_with_dpop(state, &pre_auth_code, &first_proof).await;
    assert_eq!(first_res.status(), StatusCode::BAD_REQUEST);
    let nonce = first_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("first /token attempt must supply a DPoP-Nonce to retry with")
        .to_string();

    let second_proof =
        create_dpop_proof(&kp, "POST", htu, "jti-handshake-2", now, None, Some(&nonce));
    let second_res = post_token_with_dpop(state, &pre_auth_code, &second_proof).await;
    assert_eq!(second_res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(second_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        json["token_type"], "DPoP",
        "RFC 9449 §5: a key-bound token MUST be signalled with token_type DPoP"
    );
    (json["access_token"].as_str().unwrap().to_string(), kp)
}

/// RFC 9449 §8: an AS "responds to requests that do not include a nonce with
/// an HTTP 400 (Bad Request) error response ... using use_dpop_nonce as the
/// error code value. The authorization server includes a DPoP-Nonce HTTP
/// header in the response supplying a nonce value to be used when sending the
/// subsequent request."
#[tokio::test]
async fn the_token_endpoint_demands_a_nonce_and_supplies_one() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Required,
        ..DpopConfig::default()
    })
    .await;
    let pre_auth_code = create_pre_auth_offer(&state).await;
    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let now = pop_test_now_secs();
    let proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/token",
        "jti-nonce-demand-1",
        now,
        None,
        None,
    );
    let res = post_token_with_dpop(&state, &pre_auth_code, &proof).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let nonce = res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("§8 requires a DPoP-Nonce header on this error")
        .to_string();
    assert!(!nonce.is_empty());
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "use_dpop_nonce");
}

/// §8: "the client is expected to retry its token request using a DPoP proof
/// including the supplied nonce value in the nonce claim." The loop must
/// close -- `issue_bound_token_via_nonce_handshake` performs and asserts
/// exactly this retry.
#[tokio::test]
async fn a_wallet_can_retry_the_token_request_with_the_supplied_nonce() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Required,
        ..DpopConfig::default()
    })
    .await;
    let (access_token, _kp) = issue_bound_token_via_nonce_handshake(&state).await;
    assert!(!access_token.is_empty());
}

/// §9 / §7.1: at a protected resource the answer is 401 with a
/// WWW-Authenticate challenge, not the §8 400.
#[tokio::test]
async fn the_credential_endpoint_demands_a_nonce_with_a_401_challenge() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Required,
        ..DpopConfig::default()
    })
    .await;
    let (access_token, kp) = issue_bound_token_via_nonce_handshake(&state).await;
    let now = pop_test_now_secs();
    let proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/credential",
        "jti-cred-nonce-1",
        now,
        Some(&access_token),
        None,
    );
    let res = post_credential_with_dpop(&state, &access_token, &proof).await;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let www = res
        .headers()
        .get(axum::http::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .expect("§7.1 requires a WWW-Authenticate challenge")
        .to_string();
    assert!(www.contains(r#"error="use_dpop_nonce""#), "got: {www}");
    assert!(www.contains(r#"algs="ES256""#), "got: {www}");
    assert!(res.headers().get("DPoP-Nonce").is_some());
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "use_dpop_nonce");
}

#[tokio::test]
async fn a_wallet_can_retry_the_credential_request_with_the_supplied_nonce() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Required,
        ..DpopConfig::default()
    })
    .await;
    let (access_token, kp) = issue_bound_token_via_nonce_handshake(&state).await;
    let now = pop_test_now_secs();
    let htu = "https://issuer.example.com/credential";

    let first_proof = create_dpop_proof(
        &kp,
        "POST",
        htu,
        "jti-cred-retry-1",
        now,
        Some(&access_token),
        None,
    );
    let first_res = post_credential_with_dpop(&state, &access_token, &first_proof).await;
    assert_eq!(first_res.status(), StatusCode::UNAUTHORIZED);
    let nonce = first_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("must supply a nonce to retry with")
        .to_string();

    let second_proof = create_dpop_proof(
        &kp,
        "POST",
        htu,
        "jti-cred-retry-2",
        now,
        Some(&access_token),
        Some(&nonce),
    );
    let second_res = post_credential_with_dpop(&state, &access_token, &second_proof).await;
    assert_eq!(
        second_res.status(),
        StatusCode::OK,
        "a retry using the supplied nonce must succeed"
    );
}

/// §8.2 permits supplying a nonce on any response. Doing so on success means a
/// wallet never needs a rejection round-trip after its first request.
#[tokio::test]
async fn successful_responses_carry_a_dpop_nonce_when_enabled() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Optional,
        ..DpopConfig::default()
    })
    .await;
    let pre_auth_code = create_pre_auth_offer(&state).await;
    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let now = pop_test_now_secs();

    // No nonce claim: Optional accepts absence.
    let token_proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/token",
        "jti-optional-token-1",
        now,
        None,
        None,
    );
    let token_res = post_token_with_dpop(&state, &pre_auth_code, &token_proof).await;
    assert_eq!(token_res.status(), StatusCode::OK);
    assert!(token_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| !s.is_empty()));
    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    let cred_proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/credential",
        "jti-optional-cred-1",
        now,
        Some(&access_token),
        None,
    );
    let cred_res = post_credential_with_dpop(&state, &access_token, &cred_proof).await;
    assert_eq!(cred_res.status(), StatusCode::OK);
    assert!(cred_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| !s.is_empty()));
}

/// §8: "there MUST NOT be more than one DPoP-Nonce header."
#[tokio::test]
async fn exactly_one_dpop_nonce_header_is_emitted() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Required,
        ..DpopConfig::default()
    })
    .await;
    let pre_auth_code = create_pre_auth_offer(&state).await;
    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let now = pop_test_now_secs();
    let htu = "https://issuer.example.com/token";

    let first_proof = create_dpop_proof(&kp, "POST", htu, "jti-single-1", now, None, None);
    let first_res = post_token_with_dpop(&state, &pre_auth_code, &first_proof).await;
    assert_eq!(first_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(first_res.headers().get_all("DPoP-Nonce").iter().count(), 1);
    let nonce = first_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    let second_proof = create_dpop_proof(&kp, "POST", htu, "jti-single-2", now, None, Some(&nonce));
    let second_res = post_token_with_dpop(&state, &pre_auth_code, &second_proof).await;
    assert_eq!(second_res.status(), StatusCode::OK);
    assert_eq!(second_res.headers().get_all("DPoP-Nonce").iter().count(), 1);
}

/// Under the default nothing changes for an existing deployment.
#[tokio::test]
async fn no_dpop_nonce_header_is_emitted_when_nonce_mode_is_disabled() {
    // setup_test_app()'s default DpopConfig: mode Optional, nonce_mode Disabled.
    let (state, _dir) = setup_test_app().await;
    let pre_auth_code = create_pre_auth_offer(&state).await;
    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let now = pop_test_now_secs();

    let token_proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/token",
        "jti-disabled-token-1",
        now,
        None,
        None,
    );
    let token_res = post_token_with_dpop(&state, &pre_auth_code, &token_proof).await;
    assert_eq!(token_res.status(), StatusCode::OK);
    assert!(token_res.headers().get("DPoP-Nonce").is_none());
    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    let cred_proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/credential",
        "jti-disabled-cred-1",
        now,
        Some(&access_token),
        None,
    );
    let cred_res = post_credential_with_dpop(&state, &access_token, &cred_proof).await;
    assert_eq!(cred_res.status(), StatusCode::OK);
    assert!(cred_res.headers().get("DPoP-Nonce").is_none());

    // The default posture must also hold at the unauthenticated freshness
    // endpoint: enabling nothing means emitting nothing, anywhere.
    let wallet_app = wallet_router(state.clone());
    let nonce_req = Request::builder()
        .method("POST")
        .uri("/nonce")
        .body(Body::empty())
        .unwrap();
    let nonce_res = wallet_app.oneshot(nonce_req).await.unwrap();
    assert_eq!(nonce_res.status(), StatusCode::OK);
    assert!(nonce_res.headers().get("DPoP-Nonce").is_none());
}

// ---------------------------------------------------------------------------
// Google Wallet vendor profile (docs/specs/google-wallet-openid4vci-profile.md),
// "Credential Endpoint": "DPoP Nonce is expected to be returned from the c_nonce
// endpoint." No pinned specification requires this; OpenID4VCI 1.1 WG draft
// §8.2-4 standardises it and this repository pins 1.0. See
// docs/superpowers/specs/2026-08-04-dpop-nonce-freshness-endpoints-design.md.
// ---------------------------------------------------------------------------

/// The primary behaviour, under both enabled modes.
#[tokio::test]
async fn the_nonce_endpoint_supplies_a_dpop_nonce_when_enabled() {
    for nonce_mode in [Mode::Optional, Mode::Required] {
        let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
            mode: Mode::Required,
            nonce_mode: nonce_mode.clone(),
            ..DpopConfig::default()
        })
        .await;
        let wallet_app = wallet_router(state.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/nonce")
            .body(Body::empty())
            .unwrap();
        let res = wallet_app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK, "nonce_mode: {nonce_mode:?}");
        assert!(
            res.headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| !s.is_empty()),
            "nonce_mode {nonce_mode:?}: /nonce must supply a DPoP-Nonce"
        );
        // RFC 9449 §8: never more than one.
        assert_eq!(res.headers().get_all("DPoP-Nonce").iter().count(), 1);
        // OpenID4VCI §7.2 must survive the return-type change.
        assert_eq!(
            res.headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }
}

/// The header must carry a *usable* nonce, not merely a well-formed one: the
/// value taken from `/nonce` is accepted by the very next `/token` DPoP proof
/// under `nonce_mode: required`, which is the whole point of emitting it.
/// This is the test that would catch a wrong `Domain` or a wrong TTL.
#[tokio::test]
async fn a_nonce_from_the_nonce_endpoint_is_accepted_at_the_token_endpoint() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Required,
        ..DpopConfig::default()
    })
    .await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    let wallet_app = wallet_router(state.clone());
    let nonce_req = Request::builder()
        .method("POST")
        .uri("/nonce")
        .body(Body::empty())
        .unwrap();
    let nonce_res = wallet_app.oneshot(nonce_req).await.unwrap();
    assert_eq!(nonce_res.status(), StatusCode::OK);
    let dpop_nonce = nonce_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("/nonce must supply a DPoP-Nonce to retry with")
        .to_string();

    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/token",
        "jti-nonce-endpoint-1",
        pop_test_now_secs(),
        None,
        Some(&dpop_nonce),
    );
    let res = post_token_with_dpop(&state, &pre_auth_code, &proof).await;

    // No `use_dpop_nonce` round trip: the first attempt succeeds.
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a nonce minted by /nonce must satisfy nonce_mode: required at /token"
    );
}

/// Google Wallet vendor profile, "Token Endpoint": "DPoP Nonce is expected to be
/// returned from the Challenge endpoint header. Note: this is not standardized."
/// Standardised nowhere indeed -- ABCA draft -07 §8, which defines this
/// endpoint and which this repository pins, mentions no DPoP interaction at all.
#[tokio::test]
async fn the_challenge_endpoint_supplies_a_dpop_nonce_when_enabled() {
    for nonce_mode in [Mode::Optional, Mode::Required] {
        let (state, _dir) = setup_test_app_with_dpop_and_challenge_mode(
            DpopConfig {
                mode: Mode::Required,
                nonce_mode: nonce_mode.clone(),
                ..DpopConfig::default()
            },
            Mode::Optional,
        )
        .await;
        let wallet_app = wallet_router(state.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/challenge")
            .body(Body::empty())
            .unwrap();
        let res = wallet_app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK, "nonce_mode: {nonce_mode:?}");
        assert!(
            res.headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| !s.is_empty()),
            "nonce_mode {nonce_mode:?}: /challenge must supply a DPoP-Nonce"
        );
        // RFC 9449 §8: never more than one.
        assert_eq!(res.headers().get_all("DPoP-Nonce").iter().count(), 1);
        // ABCA §8 must survive the return-type change.
        assert_eq!(
            res.headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        // The body is still the §8 document, unchanged.
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!body["attestation_challenge"]
            .as_str()
            .expect("attestation_challenge must be a string")
            .is_empty());
    }
}

/// The negative control for this endpoint: the challenge endpoint enabled but
/// server-provided nonces off must emit no nonce header.
#[tokio::test]
async fn the_challenge_endpoint_emits_no_dpop_nonce_when_nonce_mode_is_disabled() {
    let (state, _dir) = setup_test_app_with_dpop_and_challenge_mode(
        DpopConfig {
            mode: Mode::Required,
            nonce_mode: Mode::Disabled,
            ..DpopConfig::default()
        },
        Mode::Optional,
    )
    .await;
    let wallet_app = wallet_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/challenge")
        .body(Body::empty())
        .unwrap();
    let res = wallet_app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().get("DPoP-Nonce").is_none());
}

/// A nonce-less proof must NOT be turned into a nonce error when the real
/// problem is elsewhere -- otherwise a wallet retries forever.
#[tokio::test]
async fn a_bad_ath_is_still_invalid_token_not_use_dpop_nonce() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Required,
        ..DpopConfig::default()
    })
    .await;
    let (access_token, kp) = issue_bound_token_via_nonce_handshake(&state).await;
    let now = pop_test_now_secs();
    let nonce = foundry_issuer::mint_dpop_nonce(
        state.nonce_secret.as_ref(),
        state.config.issuer.dpop.max_age_secs,
        now,
    )
    .unwrap();

    // A valid nonce is present (§8/§9's precondition is satisfied), but the
    // proof's `ath` binds to a *different* token than the one being presented
    // -- this must surface as invalid_token, not use_dpop_nonce.
    let bad_ath_proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/credential",
        "jti-bad-ath-1",
        now,
        Some("not-the-real-access-token"),
        Some(&nonce),
    );
    let res = post_credential_with_dpop(&state, &access_token, &bad_ath_proof).await;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "invalid_token");
}

// ---------------------------------------------------------------------------
// Task 6 of the ABCA challenge-retrieval / DPoP-nonce plan
// (docs/superpowers/plans/2026-08-04-abca-challenge-and-dpop-nonce-plan.md):
// `use_attestation_challenge` status mapping and the ABCA §8.1
// `OAuth-Client-Attestation-Challenge` response header on `/token`.
// ---------------------------------------------------------------------------

/// Fetches a fresh ABCA §8 attestation challenge via `POST /challenge`.
async fn mint_attestation_challenge(state: &AppState) -> String {
    let wallet_app = wallet_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/challenge")
        .body(Body::empty())
        .unwrap();
    let res = wallet_app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["attestation_challenge"].as_str().unwrap().to_string()
}

/// ABCA §6.2: "use_attestation_challenge MUST be used when the Client
/// Attestation PoP JWT is not using an expected server-provided challenge. When
/// used this error code MUST be accompanied by the
/// OAuth-Client-Attestation-Challenge HTTP header field parameter."
///
/// Both halves are asserted here: a generic `invalid_client` with no header
/// would satisfy neither.
#[tokio::test]
async fn a_pop_without_a_challenge_is_rejected_with_a_fresh_challenge_header() {
    let now = pop_test_now_secs();
    let (attestation_jwt, pop_jwt, ca_pem) =
        signed_attestation_and_pop(now, "https://issuer.example.com", "jti-challenge-missing-1");
    let (state, _dir, _ca_dir) =
        setup_pop_test_app_with_modes(&ca_pem, Mode::Required, Mode::Required).await;
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

    assert_eq!(token_res.status(), StatusCode::BAD_REQUEST);
    let challenge = token_res
        .headers()
        .get("OAuth-Client-Attestation-Challenge")
        .and_then(|v| v.to_str().ok())
        .expect("§6.2 requires the challenge header to accompany this error")
        .to_string();
    assert!(!challenge.is_empty());
    let body_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "use_attestation_challenge");
}

/// ABCA §8.1: "The Authorization Server MAY provide a fresh Challenge with any
/// HTTP response." Emitting it on success is what spares a conformant wallet a
/// `/challenge` round-trip before every subsequent token request.
#[tokio::test]
async fn a_successful_token_response_carries_a_fresh_challenge_header() {
    let now = pop_test_now_secs();
    let (attestation_jwt, ca_pem, kp) = build_wallet_attestation(now);
    let (state, _dir, _ca_dir) =
        setup_pop_test_app_with_modes(&ca_pem, Mode::Required, Mode::Required).await;
    let challenge = mint_attestation_challenge(&state).await;
    let pop_jwt = sign_pop(
        &kp,
        "https://issuer.example.com",
        "jti-challenge-success-1",
        now,
        Some(&challenge),
    );
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

    assert_eq!(token_res.status(), StatusCode::OK);
    let challenge_hdr = token_res
        .headers()
        .get("OAuth-Client-Attestation-Challenge")
        .and_then(|v| v.to_str().ok())
        .expect("§8.1 permits a fresh challenge on any response, including success");
    assert!(!challenge_hdr.is_empty());
}

/// The retry loop that §6.2's error code exists to enable must actually close.
/// This is the test that proves the feature is usable, not merely conformant.
#[tokio::test]
async fn a_wallet_can_retry_with_the_challenge_from_the_rejection_header() {
    let now = pop_test_now_secs();
    let (attestation_jwt, ca_pem, kp) = build_wallet_attestation(now);
    let (state, _dir, _ca_dir) =
        setup_pop_test_app_with_modes(&ca_pem, Mode::Required, Mode::Required).await;
    let pre_auth_code = create_pre_auth_offer(&state).await;
    let pop_jwt = sign_pop(
        &kp,
        "https://issuer.example.com",
        "jti-challenge-retry-1",
        now,
        None,
    );

    // 1. POST /token with no `challenge` -> 400; capture the header value.
    let wallet_app = wallet_router(state.clone());
    let first_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("OAuth-Client-Attestation", &attestation_jwt)
        .header("OAuth-Client-Attestation-PoP", &pop_jwt)
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let first_res = wallet_app.oneshot(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::BAD_REQUEST);
    let challenge = first_res
        .headers()
        .get("OAuth-Client-Attestation-Challenge")
        .and_then(|v| v.to_str().ok())
        .expect("the rejection must carry a fresh challenge to retry with")
        .to_string();

    // 2. Re-sign the PoP with `challenge` = that value AND a fresh `jti`
    //    (claim_pop_jti burned the first one, so reusing it would fail for an
    //    unrelated reason and mask what this test is checking). Reuses the
    //    same attestation JWT and key -- only a fresh PoP is needed.
    let pop_jwt_2 = sign_pop(
        &kp,
        "https://issuer.example.com",
        "jti-challenge-retry-2",
        now,
        Some(&challenge),
    );

    // 3. POST /token again -> 200.
    let wallet_app = wallet_router(state.clone());
    let second_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("OAuth-Client-Attestation", &attestation_jwt)
        .header("OAuth-Client-Attestation-PoP", &pop_jwt_2)
        .body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
        )))
        .unwrap();
    let second_res = wallet_app.oneshot(second_req).await.unwrap();

    assert_eq!(
        second_res.status(),
        StatusCode::OK,
        "a retry using the challenge from the rejection header must succeed"
    );
}

/// Under the default nothing changes for an existing deployment.
#[tokio::test]
async fn no_challenge_header_is_emitted_when_challenge_mode_is_disabled() {
    let now = pop_test_now_secs();
    let (attestation_jwt, pop_jwt, ca_pem) = signed_attestation_and_pop(
        now,
        "https://issuer.example.com",
        "jti-challenge-disabled-1",
    );
    // setup_pop_test_app defaults challenge_mode to Mode::Disabled.
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

    assert_eq!(token_res.status(), StatusCode::OK);
    assert!(
        token_res
            .headers()
            .get("OAuth-Client-Attestation-Challenge")
            .is_none(),
        "no challenge header must be emitted when challenge_mode is Disabled"
    );
}

/// A challenge that verifies but belongs to a different domain must still be
/// refused at the HTTP layer, not only in the unit test.
#[tokio::test]
async fn a_c_nonce_presented_as_a_challenge_is_rejected_at_the_token_endpoint() {
    let now = pop_test_now_secs();
    let (attestation_jwt, ca_pem, kp) = build_wallet_attestation(now);
    let (state, _dir, _ca_dir) =
        setup_pop_test_app_with_modes(&ca_pem, Mode::Required, Mode::Required).await;
    let c_nonce = mint_c_nonce(&state).await;
    let pop_jwt = sign_pop(
        &kp,
        "https://issuer.example.com",
        "jti-challenge-cnonce-1",
        now,
        Some(&c_nonce),
    );
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

    assert_eq!(token_res.status(), StatusCode::BAD_REQUEST);
    let body_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "use_attestation_challenge");
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

// ---------------------------------------------------------------------------
// OpenID4VCI Credential Request/Response encryption — the HTTP rejection
// matrix. `setup_test_app` above stays untouched by this section; every helper
// here is new and scoped to encryption.
// ---------------------------------------------------------------------------

/// As `setup_test_app`, plus a generated request-decryption key and both
/// encryption blocks enabled with the given advertised `enc` lists and
/// `encryption_required`.
///
/// Parameterized (rather than building one fixed `setup_with_encryption` and
/// mutating its config afterward) because `DecryptionKey` is deliberately not
/// `Clone` -- a clonable private key is a footgun -- so a config change that
/// needs a fresh `AppState` cannot reuse a previously loaded key; it has to
/// build the whole state, including a fresh key, from scratch.
async fn setup_with_encryption_enc(
    request_enc: Vec<String>,
    response_enc: Vec<String>,
    required: bool,
) -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_test_app().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
        keys: vec!["issuer_request_enc".to_string()],
        enc_values_supported: request_enc,
        encryption_required: required,
    });
    cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
        enc_values_supported: response_enc,
        encryption_required: required,
    });
    let km = foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
        .unwrap();
    let key =
        foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes()).unwrap();
    let state =
        AppState::new(state.storage.clone(), Arc::new(cfg)).with_request_decryption_keys(vec![key]);
    (state, dir)
}

/// As `setup_with_encryption_enc`, with both `enc` lists at the full supported
/// set and `encryption_required: false` -- the common case most tests below
/// want.
async fn setup_with_encryption() -> (AppState, tempfile::TempDir) {
    setup_with_encryption_enc(
        vec!["A128GCM".to_string(), "A256GCM".to_string()],
        vec!["A128GCM".to_string(), "A256GCM".to_string()],
        false,
    )
    .await
}

async fn body_json(res: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// POST a body to `/credential` with the given Content-Type.
async fn post_credential(
    state: &AppState,
    access_token: &str,
    content_type: &str,
    body: impl Into<axum::body::Bytes>,
) -> axum::http::Response<Body> {
    wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, content_type)
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(body.into()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Encrypt `body` to the issuer's published request-encryption key.
async fn encrypt_to_issuer(state: &AppState, body: &serde_json::Value, enc: &str) -> String {
    let meta = foundry_issuer::build_issuer_metadata(&state.config, &state.request_decryption_keys);
    let json = serde_json::to_value(meta).unwrap();
    let jwk = json["credential_request_encryption"]["jwks"]["keys"][0].clone();
    let kid = jwk["kid"].as_str().unwrap().to_string();
    foundry_core::crypto::jwe::encrypt_compact_with_kid(body, &jwk, "ECDH-ES", enc, Some(&kid))
        .unwrap()
}

fn wallet_enc_jwk_json() -> serde_json::Value {
    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let mut jwk = serde_json::to_value(kp.to_jwk_public_key()).unwrap();
    if let Some(o) = jwk.as_object_mut() {
        o.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    }
    jwk
}

// ---------------------------------------------------------------------------
// VCI-0098 — OpenID4VCI Encrypted Messages (L1186): the media type of an
// encrypted message MUST be `application/jwt`. Anything else is refused before
// parsing, which is also what keeps VCI-0062 true.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0098_text_plain_is_still_415_with_encryption_enabled() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(&state, &token, "text/plain", "not json at all").await;
    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ---------------------------------------------------------------------------
// VCI-0100 — Encrypted Messages (L1188): the JWE `alg` MUST equal the `alg` of
// the chosen JWK, which is always ECDH-ES.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0100_a_non_ecdh_es_alg_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    // Hand-build a header claiming RSA-OAEP over an otherwise well-formed shape.
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"RSA-OAEP","enc":"A128GCM","kid":"x"}"#);
    let bogus = format!("{header_b64}.e.i.c.t");
    let res = post_credential(&state, &token, "application/jwt", bogus).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = body_json(res).await;
    assert_eq!(
        body["error"],
        serde_json::json!("invalid_credential_request")
    );
}

// ---------------------------------------------------------------------------
// VCI-0101 — Encrypted Messages (L1188): the JWE MUST carry the selected key's
// `kid`. Every published key has one, so an absent or unknown `kid` is refused
// rather than triggering trial decryption.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0101_a_missing_kid_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let meta = serde_json::to_value(foundry_issuer::build_issuer_metadata(
        &state.config,
        &state.request_decryption_keys,
    ))
    .unwrap();
    let jwk = meta["credential_request_encryption"]["jwks"]["keys"][0].clone();
    // The four-argument form deliberately writes no `kid`.
    let jwe = foundry_core::crypto::jwe::encrypt_compact(
        &serde_json::json!({ "credential_configuration_id": "pid" }),
        &jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// VCI-0135 — Credential Issuer Metadata (L1374): only advertised `enc` values
// are accepted on the Credential Request.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0135_an_unadvertised_request_enc_is_rejected() {
    let (state, _dir) =
        setup_with_encryption_enc(vec!["A128GCM".into()], vec!["A128GCM".into()], false).await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let jwe = encrypt_to_issuer(
        &state,
        &serde_json::json!({ "credential_configuration_id": "pid" }),
        "A256GCM",
    )
    .await;
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// VCI-0063 — Credential Request (L960): Credential Request encryption MUST be
// used whenever `credential_response_encryption` is included, to prevent
// substitution.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0063_response_encryption_over_plaintext_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let body = serde_json::json!({
        "credential_configuration_id": "pid",
        "credential_response_encryption": { "jwk": wallet_enc_jwk_json(), "enc": "A128GCM" },
    });
    let res = post_credential(
        &state,
        &token,
        "application/json",
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = body_json(res).await;
    assert_eq!(
        body["error"],
        serde_json::json!("invalid_credential_request")
    );
}

// ---------------------------------------------------------------------------
// VCI-0054 — Credential Request (L854): `credential_response_encryption.jwk` is
// REQUIRED, and Encrypted Messages (L1188) requires an `alg` on it.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0054_a_response_jwk_without_alg_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let mut jwk = wallet_enc_jwk_json();
    if let Some(o) = jwk.as_object_mut() {
        o.remove("alg");
    }
    let jwe = encrypt_to_issuer(
        &state,
        &serde_json::json!({
            "credential_configuration_id": "pid",
            "credential_response_encryption": { "jwk": jwk, "enc": "A128GCM" },
        }),
        "A128GCM",
    )
    .await;
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// VCI-0055 — Credential Request (L855): `credential_response_encryption.enc` is
// REQUIRED, and only advertised values are honoured (L1379).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0055_an_unadvertised_response_enc_is_rejected() {
    let (state, _dir) =
        setup_with_encryption_enc(vec!["A128GCM".into()], vec!["A128GCM".into()], false).await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let jwe = encrypt_to_issuer(
        &state,
        &serde_json::json!({
            "credential_configuration_id": "pid",
            "credential_response_encryption": { "jwk": wallet_enc_jwk_json(), "enc": "A256GCM" },
        }),
        "A128GCM",
    )
    .await;
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// VCI-0056 — Credential Request (L856): if `zip` is absent, compression MUST
// NOT be used. foundry advertises no `zip_values_supported`, so a present `zip`
// is refused rather than silently ignored.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0056_a_present_zip_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let jwe = encrypt_to_issuer(
        &state,
        &serde_json::json!({
            "credential_configuration_id": "pid",
            "credential_response_encryption": {
                "jwk": wallet_enc_jwk_json(), "enc": "A128GCM", "zip": "DEF",
            },
        }),
        "A128GCM",
    )
    .await;
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// OpenID4VCI Encrypted Messages (L1192): when encryption was required but the
// received message is unencrypted, it is rejected.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn required_request_encryption_rejects_a_plaintext_request() {
    let (state, _dir) = setup_with_encryption_enc(
        vec!["A128GCM".into(), "A256GCM".into()],
        vec!["A128GCM".into(), "A256GCM".into()],
        true,
    )
    .await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        "application/json",
        r#"{"credential_configuration_id":"pid"}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = body_json(res).await;
    assert_eq!(
        body["error"],
        serde_json::json!("invalid_credential_request")
    );
}
