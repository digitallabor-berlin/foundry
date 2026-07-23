use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, KeyEntry, Mode,
    ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::storage::SqliteStorage;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use std::collections::BTreeMap as StdBTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

async fn setup_test_app() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");
    let key_path = dir.path().join("issuer.pem");

    let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
    std::fs::write(&key_path, km.private_pem).unwrap();

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let mut keys = StdBTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
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
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: Some("test-admin-key".to_string()),
                api_key_env: None,
                swagger_ui_enabled: true,
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
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
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

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
    };

    (state, dir)
}

fn create_proof(c_nonce: &str, issuer: &str) -> (serde_json::Value, EcKeyPair) {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
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
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    (
        serde_json::json!({
            "proof_type": "jwt",
            "jwt": jwt_str,
        }),
        keypair,
    )
}

#[tokio::test]
async fn full_issuance_flow_end_to_end() {
    let (state, _dir) = setup_test_app().await;

    // 1. Create offer via Admin API
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": {
            "given_name": "Alice"
        },
        "tx_code_required": false
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

    // 2. Exchange pre-authorized_code at POST /token
    let wallet_app = wallet_router(state.clone());
    let token_form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={}",
        pre_auth_code
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

    let access_token = token_json["access_token"].as_str().unwrap();

    // 3. Call POST /nonce with the access_token to mint a fresh c_nonce, and prove
    // that nonce is subsequently accepted by /credential.
    let wallet_app = wallet_router(state.clone());
    let nonce_req = Request::builder()
        .method("POST")
        .uri("/nonce")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();

    let nonce_res = wallet_app.oneshot(nonce_req).await.unwrap();
    assert_eq!(nonce_res.status(), StatusCode::OK);

    let nonce_bytes = axum::body::to_bytes(nonce_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let nonce_json: serde_json::Value = serde_json::from_slice(&nonce_bytes).unwrap();
    let c_nonce = nonce_json["c_nonce"].as_str().unwrap();

    // 4. Construct holder proof and request credential at POST /credential
    let (proof_json, _keypair) = create_proof(c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proof": proof_json,
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

    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();

    let credential_str = cred_json["credential"].as_str().unwrap();
    assert!(!credential_str.is_empty());
    assert!(credential_str.contains('~')); // SD-JWT VC format contains ~ separators
}
