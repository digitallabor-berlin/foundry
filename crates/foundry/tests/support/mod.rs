//! Shared setup for the credential-encryption test binary.
//!
//! Copied (not imported) from `conformance_http.rs`'s `setup_test_app` and its
//! helpers, per this repository's convention that test-fixture helpers are
//! duplicated across test binaries rather than shared through the crate's own
//! public API. Renamed `setup_test_app` -> `setup_without_encryption` to make
//! the pairing with `setup_with_encryption` below explicit.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
    LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
    WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use josekit::jwk::alg::ec::EcKeyPair;
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

pub async fn setup_without_encryption() -> (AppState, tempfile::TempDir) {
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

/// A `POST /admin/issuance/offers` (pre-authorized_code grant) followed by a
/// `POST /token` exchange, exactly as `conformance_http.rs`'s copy does.
pub async fn issue_pre_auth_offer_and_get_access_token(state: &AppState) -> String {
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

/// Mint a real MAC-authenticated `c_nonce` exactly as `POST /nonce` would.
pub async fn mint_c_nonce(state: &AppState) -> String {
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
/// `conformance_http.rs`'s `create_proof` builds one.
pub fn create_proof(c_nonce: &str, issuer: &str) -> String {
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

pub async fn body_json(res: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// As `setup_without_encryption`, plus a generated request-decryption key and
/// both encryption blocks enabled with `encryption_required: false`.
pub async fn setup_with_encryption() -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_without_encryption().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
        keys: vec!["issuer_request_enc".to_string()],
        enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
        encryption_required: false,
    });
    cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
        enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
        encryption_required: false,
    });
    let km = foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
        .unwrap();
    let key =
        foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes()).unwrap();
    let state = AppState::new(state.storage.clone(), std::sync::Arc::new(cfg))
        .with_request_decryption_keys(vec![key]);
    (state, dir)
}
