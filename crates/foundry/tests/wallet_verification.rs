use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, IssuerConfig, KeyEntry, Mode, ServerConfig,
    StatusListConfig, StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
};
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::storage::SqliteStorage;
use foundry_sd_jwt_vc::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
use foundry_verifier::{
    CreateVerificationResponse, VerificationResult, VerificationState, VerificationTransaction,
};
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use openid4vp::core::jwe::JweBuilder;
use std::collections::BTreeMap as StdBTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

fn der_b64(pem_bytes: &[u8]) -> String {
    std::str::from_utf8(pem_bytes)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

async fn setup_test_app() -> (AppState, tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");
    let issuer_key_path = dir.path().join("issuer.pem");
    let verifier_key_path = dir.path().join("verifier.pem");

    let root = new_ca("Foundry Test Root CA", 365).unwrap();
    let issuer_leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();
    let verifier_leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();

    std::fs::write(&issuer_key_path, &issuer_leaf.key_pem).unwrap();
    std::fs::write(&verifier_key_path, &verifier_leaf.key_pem).unwrap();

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let mut keys = StdBTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            private_key: issuer_key_path.to_str().unwrap().to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );
    keys.insert(
        "verifier_key".to_string(),
        KeyEntry {
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
        trust_anchors: vec![TrustAnchor {
            name: "test_ca".to_string(),
            certs: root.cert_pem.clone(),
        }],
        issuer: IssuerConfig {
            credential_issuer: "https://localhost:8443".to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Disabled,
            },
            key_attestation: AttestationMode {
                mode: Mode::Disabled,
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: vec![],
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "verifier_key".to_string(),
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

    (
        state,
        dir,
        issuer_leaf.cert_pem,
        issuer_leaf.key_pem,
    )
}

#[tokio::test]
async fn full_verification_flow_end_to_end() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;

    // 1. Setup admin and wallet apps
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    // 2. Admin POST /admin/verification/requests
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

    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);

    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse =
        serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    // 3. Wallet GET /vp/request/{id}
    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();

    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    assert_eq!(
        get_res.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/oauth-authz-req+jwt"
    );

    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();

    // Parse payload from JWS string
    let parts: Vec<&str> = jws_str.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    // 4. Issue SD-JWT VC to holder key pair and create KB-JWT
    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(&holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer =
        FileSigner::from_pem(&holder_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut select = serde_json::Map::new();
    select.insert("given_name".to_string(), serde_json::json!("Alice"));

    let claims = IssuerClaims {
        iss: "localhost".to_string(),
        sub: "did:example:holder".to_string(),
        iat: (now - 100) as i64,
        exp: (now + 3600) as i64,
        vct: "https://localhost:8443/vct/pid".to_string(),
        cnf_jwk: holder_pub_jwk,
        status_list_index: None,
        status_list_uri: None,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };

    let issuer_pres = build_sd_jwt_vc(
        claims,
        &issuer_signer,
        Some(vec![der_b64(issuer_cert_pem.as_bytes())]),
    )
    .unwrap();

    let sd_jwt_vc_presentation =
        attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &nonce).unwrap();

    // 5. Encrypt presentation into JWE
    let jwe_str = JweBuilder::new()
        .payload(serde_json::json!({ "vp_token": sd_jwt_vc_presentation }))
        .recipient_key_json(&ephem_public_jwk)
        .unwrap()
        .alg("ECDH-ES")
        .enc("A128GCM")
        .build()
        .unwrap();

    // 6. Wallet POST /vp/response/{id}
    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(jwe_str))
        .unwrap();

    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);

    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_result: VerificationResult = serde_json::from_slice(&verify_bytes).unwrap();

    assert!(verify_result.verified);
    assert_eq!(verify_result.claims["given_name"], "Alice");

    // 7. Admin GET /admin/verification/requests/{id}
    let get_tx_req = Request::builder()
        .method("GET")
        .uri(format!("/admin/verification/requests/{verification_id}"))
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::empty())
        .unwrap();

    let get_tx_res = admin_app.clone().oneshot(get_tx_req).await.unwrap();
    assert_eq!(get_tx_res.status(), StatusCode::OK);

    let tx_bytes = axum::body::to_bytes(get_tx_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx: VerificationTransaction = serde_json::from_slice(&tx_bytes).unwrap();

    assert_eq!(tx.state, VerificationState::Verified);
    let tx_res = tx.result.expect("result should be present");
    assert!(tx_res.verified);
    assert_eq!(tx_res.claims["given_name"], "Alice");
}
