use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, IssuerConfig, KeyEntry, LoggingConfig, Mode,
    ServerConfig, StatusListConfig, StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
};
use foundry_core::crypto::jwe::encrypt_compact;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::status_list::{build_status_list_token, StatusList, StatusListTokenClaims};
use foundry_core::storage::SqliteStorage;
use foundry_core::trust::build_x5c;
use foundry_mdoc::builder::{build_mdoc, MdocClaims};
use foundry_mdoc::types::{build_session_transcript, SessionTranscriptParams};
use foundry_sd_jwt_vc::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
use foundry_verifier::{
    CreateVerificationResponse, VerificationResult, VerificationState, VerificationTransaction,
};
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use std::collections::BTreeMap as StdBTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

/// Build a signed Status List Token (compact JWS, `statuslist+jwt`) whose list
/// marks `revoked_idx` (if any) Invalid and everything else Valid, signed by
/// the issuer leaf so it chains to the test root trust anchor. `sub == uri`.
fn build_status_token(
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
    sub: &str,
    len: usize,
    revoked_idx: Option<u64>,
) -> String {
    let signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
    let x5c = build_x5c(&[issuer_cert_pem.as_bytes().to_vec()]).unwrap();
    let mut values = vec![0u8; len];
    if let Some(i) = revoked_idx {
        values[i as usize] = 1; // Invalid
    }
    let list = StatusList::build(&values, 2, None).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = StatusListTokenClaims {
        sub: sub.to_string(),
        iat: now - 100,
        exp: Some(now + 3600),
        ttl: None,
    };
    build_status_list_token(claims, &list, &signer, Some(x5c)).unwrap()
}

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

    // HAIP OpenID4VP L256: x509_hash requires a certificate to hash, so the
    // verifier's leaf certificate (already generated above, SAN "localhost"
    // matching public_base_url) must be persisted and wired into x5c.
    let verifier_cert_path = dir.path().join("verifier_leaf_cert.pem");
    std::fs::write(&verifier_cert_path, &verifier_leaf.cert_pem).unwrap();

    let trust_root_path = dir.path().join("trust_root.pem");
    std::fs::write(&trust_root_path, &root.cert_pem).unwrap();

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
        trust_anchors: vec![TrustAnchor {
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
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: vec![],
        verifier: VerifierConfig {
            signing_key: "verifier_key".to_string(),
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
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
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
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
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
    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [sd_jwt_vc_presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    // 6. Wallet POST /vp/response/{id}
    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
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

#[tokio::test]
async fn resubmitting_a_verification_response_is_rejected() {
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
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    // 3. Wallet GET /vp/request/{id}
    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();

    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);

    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();

    let parts: Vec<&str> = jws_str.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    // 4. Issue SD-JWT VC to holder key pair and create KB-JWT
    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
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
    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [sd_jwt_vc_presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    // 6. First submission of the verification response succeeds
    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);

    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_result: VerificationResult = serde_json::from_slice(&verify_bytes).unwrap();
    assert!(verify_result.verified);

    // 7. Resubmitting a response to the same verification_id (even the identical JWE) must be
    // rejected instead of silently re-verifying and overwriting the stored result.
    let replay_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let replay_res = wallet_app.clone().oneshot(replay_req).await.unwrap();
    assert_eq!(replay_res.status(), StatusCode::BAD_REQUEST);

    let replay_bytes = axum::body::to_bytes(replay_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let replay_json: serde_json::Value = serde_json::from_slice(&replay_bytes).unwrap();
    assert_eq!(replay_json["error"], "invalid_request");

    // 8. The stored transaction must remain in the Verified state from the first submission,
    // proving the replayed response was rejected before it could overwrite the result.
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
}

#[tokio::test]
async fn tampered_jwe_body_is_rejected_cleanly() {
    let (state, _dir, _issuer_cert_pem, _issuer_key_pem) = setup_test_app().await;

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

    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);

    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    // Not a valid JWE at all — must not panic, must return a clean error response.
    let garbage_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("response=this-is-not-a-jwe-at-all"))
        .unwrap();

    let garbage_res = wallet_app.clone().oneshot(garbage_req).await.unwrap();
    assert_eq!(garbage_res.status(), StatusCode::BAD_REQUEST);

    let garbage_bytes = axum::body::to_bytes(garbage_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let garbage_json: serde_json::Value = serde_json::from_slice(&garbage_bytes).unwrap();
    assert_eq!(garbage_json["error"], "invalid_request");
}

#[tokio::test]
async fn presentation_from_untrusted_issuer_is_rejected() {
    let (state, _dir, _issuer_cert_pem, _issuer_key_pem) = setup_test_app().await;

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

    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);

    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();

    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);

    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();

    let parts: Vec<&str> = jws_str.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    // Build an ENTIRELY SEPARATE, untrusted CA/leaf pair (not in the configured trust_anchors)
    // and sign the presentation with it instead of the trusted issuer key.
    let untrusted_root = new_ca("Untrusted Root CA", 365).unwrap();
    let untrusted_leaf = issue_leaf(
        &untrusted_root.cert_pem,
        &untrusted_root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();

    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer =
        FileSigner::from_pem(&holder_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let untrusted_issuer_signer =
        FileSigner::from_pem(untrusted_leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();

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
        &untrusted_issuer_signer,
        Some(vec![der_b64(untrusted_leaf.cert_pem.as_bytes())]),
    )
    .unwrap();

    let sd_jwt_vc_presentation =
        attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &nonce).unwrap();

    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [sd_jwt_vc_presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "invalid_request");
}

#[tokio::test]
async fn response_for_unknown_transaction_id_returns_404() {
    let (state, _dir, _issuer_cert_pem, _issuer_key_pem) = setup_test_app().await;
    let wallet_app = wallet_router(state.clone());

    let unknown_id = uuid::Uuid::new_v4().to_string();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{unknown_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("response=irrelevant-body"))
        .unwrap();

    let res = wallet_app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dcql_vct_mismatch_is_rejected() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    // Request vct "pid" ...
    let create_req_body = serde_json::json!({
        "dcql_query": { "credentials": [{
            "id": "c1", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
        }]},
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
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    // ... but issue a credential with a DIFFERENT vct.
    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
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
        vct: "https://localhost:8443/vct/OTHER".to_string(),
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
    let presentation = attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &nonce).unwrap();
    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();
    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);
    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_result: VerificationResult = serde_json::from_slice(&verify_bytes).unwrap();

    assert!(!verify_result.verified, "DCQL vct mismatch must not verify");
    assert!(verify_result
        .checks
        .iter()
        .any(|c| c.check == "dcql_match" && !c.passed));
}

/// Run the full SD-JWT VC verification flow issuing a credential whose
/// `status.status_list` points at an in-process status server. Returns the
/// decoded `VerificationResult`.
async fn run_status_flow(revoked_idx: Option<u64>, credential_idx: u64) -> VerificationResult {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    let create_req_body = serde_json::json!({
        "dcql_query": { "credentials": [{
            "id": "c1", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
        }]},
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
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    // Status server: bind first to learn the port, so the token's `sub` can
    // equal the credential's `uri` (draft-ietf-oauth-status-list-14 §5.1).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let uri = format!("http://{addr}/statuslists/1");
    let token = build_status_token(&issuer_cert_pem, &issuer_key_pem, &uri, 128, revoked_idx);
    let app = axum::Router::new().route(
        "/statuslists/1",
        get(move || {
            let token = token.clone();
            async move { token }
        }),
    );
    let _server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
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
        status_list_index: Some(credential_idx),
        status_list_uri: Some(uri),
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };
    let issuer_pres = build_sd_jwt_vc(
        claims,
        &issuer_signer,
        Some(vec![der_b64(issuer_cert_pem.as_bytes())]),
    )
    .unwrap();
    let presentation = attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &nonce).unwrap();
    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();
    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);
    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&verify_bytes).unwrap()
}

#[tokio::test]
async fn revoked_credential_is_rejected() {
    // Credential at index 5; the status list marks index 5 revoked.
    let result = run_status_flow(Some(5), 5).await;
    assert!(!result.verified, "revoked credential must not verify");
    assert!(result
        .checks
        .iter()
        .any(|c| c.check == "status_check" && !c.passed));
}

#[tokio::test]
async fn valid_non_revoked_credential_succeeds() {
    // Credential at index 5; nothing is revoked.
    let result = run_status_flow(None, 5).await;
    assert!(result.verified, "checks={:?}", result.checks);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check == "status_check" && c.passed));
    assert!(result
        .checks
        .iter()
        .any(|c| c.check == "dcql_match" && c.passed));
    assert_eq!(result.claims["given_name"], "Alice");
}

#[tokio::test]
async fn mdoc_presentation_is_accepted() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    let create_req_body = serde_json::json!({
        "dcql_query": { "credentials": [{
            "id": "c1", "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
            "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
        }]},
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
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();
    let response_uri = format!("https://localhost:8443/vp/response/{verification_id}");

    // Device key + issued mdoc.
    let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
    let d_signer =
        FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut elements = std::collections::BTreeMap::new();
    elements.insert("given_name".to_string(), serde_json::json!("John"));
    let mut namespaces = std::collections::BTreeMap::new();
    namespaces.insert("org.iso.18013.5.1".to_string(), elements);
    let mdoc_claims = MdocClaims {
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
        namespaces,
        device_key_jwk: d_jwk_pub,
        signed_at: (now - 100) as i64,
        valid_until: (now + 3600) as i64,
    };
    let mdoc_bytes = build_mdoc(
        mdoc_claims,
        &issuer_signer,
        Some(vec![der_b64(issuer_cert_pem.as_bytes())]),
    )
    .unwrap();

    // Detached DeviceAuth over the reconstructed SessionTranscript.
    //
    // This transaction uses `transport: request_uri`, so the OpenID4VP
    // "Invocation via Redirects" Handover applies (L2829-L2873); the response
    // is encrypted (`direct_post.jwt`), so the third `OpenID4VPHandoverInfo`
    // element is the RFC 7638 thumbprint of the Verifier's encryption key
    // (L2870).
    //
    // The thumbprint is derived here from the key the *request object*
    // advertised, while the verifier derives it from the key stored on the
    // transaction. That the round-trip succeeds is the end-to-end evidence
    // that a wallet and this verifier independently compute the same
    // transcript bytes -- which is exactly what GAP-VP-06 recorded as broken.
    let jwk_thumbprint = foundry_core::obs::thumbprint_bytes(&ephem_public_jwk).unwrap();
    let transcript = build_session_transcript(&SessionTranscriptParams::Redirect {
        client_id: client_id.clone(),
        nonce: nonce.clone(),
        jwk_thumbprint: Some(jwk_thumbprint),
        response_uri: response_uri.clone(),
    })
    .unwrap();
    let protected = coset::HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::ES256)
        .build();
    let partial = coset::CoseSign1Builder::new()
        .protected(protected.clone())
        .build();
    let d_tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        partial.protected.clone(),
        None,
        &[],
        &transcript,
    );
    let sig = {
        use foundry_core::crypto::Signer as _;
        d_signer.sign(&d_tbs).unwrap()
    };
    let d_sign = coset::CoseSign1Builder::new()
        .protected(protected)
        .signature(sig)
        .build();
    let d_sig_bytes = coset::CborSerializable::to_vec(d_sign).unwrap();

    let vp_token = serde_json::json!({
        "mdoc": B64URL.encode(&mdoc_bytes),
        "device_signature": B64URL.encode(&d_sig_bytes),
    });
    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [vp_token] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();
    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);
    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_result: VerificationResult = serde_json::from_slice(&verify_bytes).unwrap();

    assert!(verify_result.verified, "checks={:?}", verify_result.checks);
    assert_eq!(
        verify_result.claims["org.iso.18013.5.1"]["given_name"],
        "John"
    );
    assert!(verify_result
        .checks
        .iter()
        .any(|c| c.check == "mdoc_issuer_auth_and_device_signature" && c.passed));
}

// ---------------------------------------------------------------------------
// OpenID4VP `direct_post.jwt` response shape
//
// foundry advertises `response_mode: direct_post.jwt`, which per OpenID4VP 1.0
// §8.2/§8.3 obliges the wallet to POST `application/x-www-form-urlencoded` with
// the JWE carried in a `response` parameter. These tests pin that wire format.
// ---------------------------------------------------------------------------

/// Drive a verification to the point where a wallet holds a valid JWE: create
/// the request, fetch and parse the request object, issue an SD-JWT VC to a
/// fresh holder key, attach the KB-JWT, and encrypt to the verifier's ephemeral
/// key. Returns the wallet router, the verification id, the JWE compact
/// serialization, and the `TempDir` (which the caller must keep alive — dropping
/// it deletes the SQLite file out from under the running app).
async fn pending_verification_with_jwe() -> (axum::Router, String, String, tempfile::TempDir) {
    pending_verification_with_vp_token(|presentation| serde_json::json!({ "c1": [presentation] }))
        .await
}

/// As `pending_verification_with_jwe`, but lets the caller decide the `vp_token`
/// shape, so non-conformant envelopes can be driven through the real server
/// instead of only through unit tests.
async fn pending_verification_with_vp_token(
    make_vp_token: impl FnOnce(String) -> serde_json::Value,
) -> (axum::Router, String, String, tempfile::TempDir) {
    let (state, dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;

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

    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
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
    let presentation = attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &nonce).unwrap();

    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": make_vp_token(presentation) }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    (wallet_app, verification_id, jwe_str, dir)
}

/// foundry's pre-fix SD-JWT VC shape: `vp_token` as a bare string. OpenID4VP 1.0
/// section 8.1 requires an object keyed by DCQL credential query id, so no
/// conformant wallet sends this. Before the envelope fix it returned
/// `200 verified:true`, which is exactly why the bug survived the suite.
#[tokio::test]
async fn bare_string_vp_token_is_rejected() {
    let (wallet_app, verification_id, jwe_str, _dir) =
        pending_verification_with_vp_token(serde_json::Value::String).await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the pre-fix bare-string vp_token must be rejected: {body}"
    );
    assert!(
        body.contains("must be a JSON object"),
        "the message should name the expected shape: {body}"
    );
}

/// A conformant envelope that answers a credential query this request never
/// asked for must be rejected, not silently credited to the real query.
#[tokio::test]
async fn vp_token_naming_an_unrequested_query_is_rejected() {
    let (wallet_app, verification_id, jwe_str, _dir) = pending_verification_with_vp_token(
        |presentation| serde_json::json!({ "not-requested": [presentation] }),
    )
    .await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(body.contains("not-requested"), "body: {body}");
    assert!(body.contains("c1"), "must name the expected id: {body}");
}

/// Read a response's status and body together, so a failing assertion can show
/// the error payload instead of only a bare status code.
async fn status_and_body(res: axum::response::Response) -> (StatusCode, String) {
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The conformant OpenID4VP shape. This is the regression test for the defect
/// reported against the eudi-pal wallet, which failed with
/// `Invalid JWE format: Invalid symbol 61, offset 8` — the `=` at index 8 of
/// the literal `response=` parameter name, fed to a base64url decoder.
#[tokio::test]
async fn form_encoded_response_parameter_is_accepted() {
    let (wallet_app, verification_id, jwe_str, _dir) = pending_verification_with_jwe().await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "conformant direct_post.jwt response was rejected: {body}"
    );

    let result: VerificationResult = serde_json::from_str(&body).unwrap();
    assert!(result.verified, "expected a verified result, got: {body}");
    assert_eq!(result.claims["given_name"], "Alice");

    // Assert the named checks, not just `verified`. Per root AGENTS.md §4.2 an
    // omitted CheckResult silently drops out of `all(passed)` and can turn a
    // failure into a pass, so `verified: true` alone cannot detect a lost check.
    let names: Vec<&str> = result.checks.iter().map(|c| c.check.as_str()).collect();
    for expected in [
        "jwe_decryption",
        "sd_jwt_vc_signature_and_kb_jwt",
        "dcql_match",
        "status_check",
    ] {
        assert!(
            names.contains(&expected),
            "missing check '{expected}' in {names:?}"
        );
    }
    assert!(result.checks.iter().all(|c| c.passed));
}

/// The pre-fix convention — a bare JWE as the whole request body — is no longer
/// accepted. Keeping it working would preserve exactly the client/server
/// symmetry that let the defect hide behind a green suite.
#[tokio::test]
async fn raw_jwe_request_body_is_rejected() {
    let (wallet_app, verification_id, jwe_str, _dir) = pending_verification_with_jwe().await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(jwe_str))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a bare JWE body must be rejected, got: {body}"
    );

    let err: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(err["error"], "invalid_request");
}

/// A syntactically valid form body that omits `response`. The assertion targets
/// the parse-failure description rather than the bare status: before the fix
/// this path also returned 400, but via the decryption error, so a status-only
/// assertion would pass for the wrong reason.
#[tokio::test]
async fn form_body_without_response_parameter_is_rejected() {
    let (wallet_app, verification_id, _jwe_str, _dir) = pending_verification_with_jwe().await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("state=abc"))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");

    let err: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(err["error"], "invalid_request");
    let description = err["error_description"].as_str().unwrap_or_default();
    assert!(
        description.contains("response"),
        "error must name the missing `response` parameter, not report a decryption \
         failure; got: {description}"
    );
}

/// OpenID4VP permits additional members in the response. Rejecting them would
/// break conformant wallets, so the form struct must not use
/// `deny_unknown_fields`.
#[tokio::test]
async fn extra_form_parameters_are_tolerated() {
    let (wallet_app, verification_id, jwe_str, _dir) = pending_verification_with_jwe().await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}&state=abc")))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unknown `state` parameter must be ignored, not rejected: {body}"
    );

    let result: VerificationResult = serde_json::from_str(&body).unwrap();
    assert!(result.verified);
}
