use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{AppState, admin_router, wallet_router};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
    KeyEntry, LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
    WalletFacingConfig,
};
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::storage::SqliteStorage;
use josekit::jwk::KeyPair as _;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jws::{ES256, JwsHeader};
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
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
            encrypted_pre_authorized_code: Default::default(),
            access_token_ttl_secs: 600,
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
            validity_seconds: None,
        }],
        verifier: VerifierConfig {
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
            dc_api_expected_origins: Vec::new(),
            dc_api_accept_legacy_web_origin_audience: false,
        },
        logging: LoggingConfig::default(),
    };

    let state = AppState::new(Arc::new(storage), Arc::new(config));

    (state, dir)
}

fn create_proof(c_nonce: &str, issuer: &str) -> (String, EcKeyPair) {
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

    (jwt_str, keypair)
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

    let transaction_id = offer_json["transaction_id"].as_str().unwrap().to_string();

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
    let (proof_jwt, _keypair) = create_proof(c_nonce, "https://issuer.example.com");

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

    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();

    let credential_str = cred_json["credentials"][0]["credential"].as_str().unwrap();
    assert!(!credential_str.is_empty());
    assert!(credential_str.contains('~')); // SD-JWT VC format contains ~ separators

    // 5. The admin status endpoint must now report the transaction as issued —
    // this is what the console polls to show a real outcome rather than just
    // "an offer was created".
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let status_req = Request::builder()
        .method("GET")
        .uri(format!("/admin/issuance/offers/{transaction_id}"))
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::empty())
        .unwrap();

    let status_res = admin_app.oneshot(status_req).await.unwrap();
    assert_eq!(status_res.status(), StatusCode::OK);

    let status_bytes = axum::body::to_bytes(status_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let status_json: serde_json::Value = serde_json::from_slice(&status_bytes).unwrap();
    assert_eq!(status_json["state"], "issued");
}

#[tokio::test]
async fn token_request_with_wrong_pre_auth_code_is_rejected() {
    let (state, _dir) = setup_test_app().await;

    let wallet_app = wallet_router(state.clone());
    let token_form_body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=does-not-exist";

    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(token_form_body))
        .unwrap();

    let token_res = wallet_app.oneshot(token_req).await.unwrap();
    assert_eq!(token_res.status(), StatusCode::BAD_REQUEST);

    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    assert_eq!(token_json["error"], "invalid_grant");
}

#[tokio::test]
async fn token_request_with_wrong_tx_code_is_rejected() {
    let (state, _dir) = setup_test_app().await;

    // 1. Create offer requiring a tx_code via Admin API
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": {
            "given_name": "Alice"
        },
        "tx_code_required": true
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

    // 2. Attempt to exchange with the wrong tx_code
    let wallet_app = wallet_router(state.clone());
    let token_form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={}&tx_code=0000",
        pre_auth_code
    );

    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(token_form_body))
        .unwrap();

    let token_res = wallet_app.oneshot(token_req).await.unwrap();
    assert_eq!(token_res.status(), StatusCode::BAD_REQUEST);

    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    assert_eq!(token_json["error"], "invalid_grant");
}

async fn issue_offer_and_get_access_token(state: &AppState) -> String {
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

    token_json["access_token"].as_str().unwrap().to_string()
}

/// Fetches a `c_nonce` the way a conformant wallet does: a bare `POST /nonce`
/// with **no** `Authorization` header (OpenID4VCI Section 7.1 — the Nonce
/// Endpoint is not a protected resource).
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

#[tokio::test]
async fn nonce_endpoint_requires_no_access_token_and_is_uncacheable() {
    // Regression test for the interop break this replaced: requiring a bearer
    // token here made conformant wallets (which send none) fail to obtain a
    // challenge, so their proof JWT carried no `nonce` claim at all and the
    // credential request was rejected as `invalid_proof`.
    let (state, _dir) = setup_test_app().await;
    let wallet_app = wallet_router(state.clone());

    let res = wallet_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    // Section 7.2 MUST: the response is uncacheable.
    assert_eq!(
        res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!json["c_nonce"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn credential_request_with_proof_aud_mismatch_is_rejected() {
    let (state, _dir) = setup_test_app().await;
    let access_token = issue_offer_and_get_access_token(&state).await;
    let c_nonce = mint_c_nonce(&state).await;

    // Build a proof whose `aud` doesn't match the configured issuer.
    let (proof_jwt, _keypair) = create_proof(&c_nonce, "https://wrong-issuer.example.com");

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
    assert_eq!(cred_json["error"], "invalid_proof");
}

#[tokio::test]
async fn credential_request_with_proof_nonce_mismatch_is_rejected() {
    let (state, _dir) = setup_test_app().await;
    let access_token = issue_offer_and_get_access_token(&state).await;
    let _c_nonce = mint_c_nonce(&state).await;

    // Build a proof carrying a nonce that does not match the transaction's c_nonce.
    // This is a *present but invalid* c_nonce, so it reports invalid_nonce
    // (GAP-VCI-04), not invalid_proof.
    let (proof_jwt, _keypair) = create_proof("not-the-real-nonce", "https://issuer.example.com");

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
    assert_eq!(cred_json["error"], "invalid_nonce");
}

#[tokio::test]
async fn credential_request_with_expired_c_nonce_is_rejected() {
    let (state, _dir) = setup_test_app().await;
    let access_token = issue_offer_and_get_access_token(&state).await;
    // Expiry now lives inside the nonce itself rather than on the transaction,
    // so backdate the minting clock by more than the TTL: `issue_nonce` stamps
    // `exp = now + TTL`, making this nonce already expired when it is issued.
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

    let (proof_jwt, _keypair) = create_proof(&c_nonce, "https://issuer.example.com");

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
    assert_eq!(cred_json["error"], "invalid_nonce");
}

#[tokio::test]
async fn second_credential_request_with_same_access_token_is_rejected() {
    let (state, _dir) = setup_test_app().await;
    let access_token = issue_offer_and_get_access_token(&state).await;
    let c_nonce = mint_c_nonce(&state).await;

    let (proof_jwt, _keypair) = create_proof(&c_nonce, "https://issuer.example.com");
    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });

    // First request succeeds and moves the transaction to IssuanceState::Issued.
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

    // Second request with the same access_token must be rejected end-to-end over HTTP
    // because the underlying transaction is now IssuanceState::Issued. Reuse the same
    // (already-consumed) proof/nonce here: /nonce itself now also rejects an Issued
    // transaction, so re-minting a nonce is not a viable path for this attempt anyway.
    let (proof_jwt_2, _keypair_2) = create_proof(&c_nonce, "https://issuer.example.com");
    let cred_req_body_2 = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt_2] },
    });

    let wallet_app = wallet_router(state.clone());
    let cred_req_2 = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(cred_req_body_2.to_string()))
        .unwrap();

    let cred_res_2 = wallet_app.oneshot(cred_req_2).await.unwrap();
    assert_eq!(cred_res_2.status(), StatusCode::BAD_REQUEST);

    let cred_bytes_2 = axum::body::to_bytes(cred_res_2.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json_2: serde_json::Value = serde_json::from_slice(&cred_bytes_2).unwrap();
    assert_eq!(cred_json_2["error"], "invalid_grant");
}

#[tokio::test]
async fn full_issuance_flow_with_kid_key_attestation_proof() {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::parse_cert_pem;

    let (mut state, dir) = setup_test_app().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Configure a Wallet Provider trust anchor and require key attestation.
    let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "wallet-provider.example.com",
        &["wallet-provider.example.com".to_string()],
        365,
    )
    .unwrap();
    let ca_path = dir.path().join("wallet-provider-ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).unwrap();

    let mut config = (*state.config).clone();
    config.issuer.key_attestation.mode = foundry_core::config::Mode::Required;
    config.issuer.key_attestation.trusted_anchors = vec![foundry_core::config::TrustAnchor {
        name: "wallet-provider-ca".to_string(),
        certs: ca_path.to_str().unwrap().to_string(),
    }];
    state.config = Arc::new(config);

    let access_token = issue_offer_and_get_access_token(&state).await;
    let c_nonce = mint_c_nonce(&state).await;

    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut holder_pub = keypair.to_jwk_public_key();
    holder_pub.set_algorithm("ES256");

    let leaf_der = {
        let cert = parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
        use x509_cert::der::Encode;
        cert.to_der().unwrap()
    };
    let x5c = vec![B64STD.encode(&leaf_der)];
    let attestation_header =
        serde_json::json!({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c});
    let attestation_payload = serde_json::json!({
        "iss": "https://wallet-provider.example.com",
        "iat": now,
        "exp": now + 100_000,
        "nonce": c_nonce,
        "attested_keys": [serde_json::to_value(&holder_pub).unwrap()],
    });
    let h_b64 = B64URL.encode(serde_json::to_vec(&attestation_header).unwrap());
    let p_b64 = B64URL.encode(serde_json::to_vec(&attestation_payload).unwrap());
    let signing_input = format!("{h_b64}.{p_b64}");
    let leaf_signer = foundry_core::crypto::FileSigner::from_pem(
        leaf.key_pem.as_bytes(),
        foundry_core::crypto::SignatureAlgorithm::Es256,
    )
    .unwrap();
    let sig_b64 = B64URL.encode(
        foundry_core::crypto::Signer::sign(&leaf_signer, signing_input.as_bytes()).unwrap(),
    );
    let attestation_jwt = format!("{signing_input}.{sig_b64}");

    let mut proof_header = JwsHeader::new();
    proof_header.set_token_type("openid4vci-proof+jwt");
    proof_header
        .set_claim("kid", Some(serde_json::json!("0")))
        .unwrap();
    proof_header
        .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
        .unwrap();
    let mut proof_payload = JwtPayload::new();
    proof_payload
        .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
        .unwrap();
    proof_payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();
    let private_jwk = keypair.to_jwk_private_key();
    let proof_signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let proof_jwt = jwt::encode_with_signer(&proof_payload, &proof_header, &proof_signer).unwrap();

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

    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();
    let credential_str = cred_json["credentials"][0]["credential"].as_str().unwrap();
    assert!(!credential_str.is_empty());
}

/// Mint a DPoP proof JWT for `method $htu`, optionally binding it to an access
/// token via `ath` (RFC 9449 §4.2, §7). Reuses `kp` so a caller can prove
/// possession of the same key at `/token` and then at `/credential`.
fn create_dpop_proof(
    kp: &EcKeyPair,
    method: &str,
    htu: &str,
    jti: &str,
    access_token: Option<&str>,
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("dpop+jwt");
    let public = kp.to_jwk_public_key();
    header.set_jwk(public);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut payload = JwtPayload::new();
    payload.set_claim("htm", Some(method.into())).unwrap();
    payload.set_claim("htu", Some(htu.into())).unwrap();
    payload.set_claim("iat", Some(now.into())).unwrap();
    payload.set_claim("jti", Some(jti.into())).unwrap();
    if let Some(at) = access_token {
        // §7: "The DPoP proof MUST include the ath claim with a valid hash of
        // the associated access token."
        let ath = foundry_issuer::access_token_hash(at);
        payload.set_claim("ath", Some(ath.into())).unwrap();
    }

    let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

/// Like `issue_offer_and_get_access_token`, but presents a DPoP proof at
/// `/token` so the returned token is key-bound. Returns the token and the
/// keypair it is bound to, and asserts §5's `token_type: DPoP`.
async fn issue_offer_and_get_dpop_bound_access_token(state: &AppState) -> (String, EcKeyPair) {
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": { "given_name": "Alice" },
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

    let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/token",
        "dpop-token-1",
        None,
    );

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

    let token_res = wallet_router(state.clone())
        .oneshot(token_req)
        .await
        .unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    assert_eq!(
        token_json["token_type"], "DPoP",
        "RFC 9449 §5: a key-bound token MUST be signalled with token_type DPoP"
    );

    (token_json["access_token"].as_str().unwrap().to_string(), kp)
}

/// RFC 9449 §7.2: "such a protected resource MUST reject a DPoP-bound access
/// token received as a bearer token." §7.1 makes that rejection a 401 with a
/// `WWW-Authenticate: DPoP` challenge whose `algs` tells the wallet what to
/// sign with -- not the 400 the Bearer paths use.
#[tokio::test]
async fn credential_endpoint_rejects_a_downgraded_dpop_token_with_a_401_challenge() {
    let (state, _dir) = setup_test_app().await;
    let (access_token, _kp) = issue_offer_and_get_dpop_bound_access_token(&state).await;
    let c_nonce = mint_c_nonce(&state).await;
    let (proof_jwt, _) = create_proof(&c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });

    // Deliberately downgraded: a bound token presented with the Bearer scheme.
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(cred_req_body.to_string()))
        .unwrap();

    let cred_res = wallet_router(state.clone())
        .oneshot(cred_req)
        .await
        .unwrap();
    assert_eq!(
        cred_res.status(),
        StatusCode::UNAUTHORIZED,
        "§7.1: a DPoP binding failure is a 401, not a 400"
    );
    let challenge = cred_res
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("§7.1 requires a WWW-Authenticate challenge")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        challenge.starts_with("DPoP"),
        "§7.1: the scheme name is DPoP, got: {challenge}"
    );
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "got: {challenge}"
    );
    assert!(challenge.contains(r#"algs="ES256""#), "got: {challenge}");
}

/// The full RFC 9449 flow over HTTP: a DPoP proof at `/token` yields a bound
/// token with `token_type: DPoP` (§5), and `/credential` then accepts it when
/// presented with the `DPoP` scheme plus a second proof carrying `ath` (§7).
#[tokio::test]
async fn full_dpop_issuance_flow_over_http() {
    let (state, _dir) = setup_test_app().await;

    // 1. Offer -> /token with a DPoP proof -> a key-bound access token.
    //    (the token_type == "DPoP" assertion lives in the helper)
    let (access_token, kp) = issue_offer_and_get_dpop_bound_access_token(&state).await;

    // 2. c_nonce for the holder proof (unrelated to DPoP -- OpenID4VCI §7).
    let c_nonce = mint_c_nonce(&state).await;
    let (holder_proof, _holder_kp) = create_proof(&c_nonce, "https://issuer.example.com");

    // 3. A *fresh* DPoP proof for this endpoint, bound to the access token via
    //    ath. A distinct jti from the /token one, since §11.1 makes each
    //    single-use, and a distinct htu, which §4.3 check 9 requires.
    let cred_dpop = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/credential",
        "dpop-credential-1",
        Some(&access_token),
    );

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [holder_proof] },
    });
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        // §7.1: a bound token is presented with the DPoP scheme, not Bearer.
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
        .header("DPoP", cred_dpop)
        .body(Body::from(cred_req_body.to_string()))
        .unwrap();

    let cred_res = wallet_router(state.clone())
        .oneshot(cred_req)
        .await
        .unwrap();
    assert_eq!(cred_res.status(), StatusCode::OK);

    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();
    let credential_str = cred_json["credentials"][0]["credential"].as_str().unwrap();
    assert!(!credential_str.is_empty());
    // SD-JWT VC concatenates disclosures with `~`.
    assert!(credential_str.contains('~'));
}

/// RFC 9449 §4.3 check 1: "There is not more than one DPoP HTTP request header
/// field." Unreachable from the engine's unit tests, which take a single &str --
/// this is the only test that covers it.
#[tokio::test]
async fn two_dpop_headers_at_the_token_endpoint_are_rejected() {
    let (state, _dir) = setup_test_app().await;

    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("DPoP", "first")
        .header("DPoP", "second")
        .body(Body::from(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code",
        ))
        .unwrap();

    let res = wallet_router(state.clone())
        .oneshot(token_req)
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Rejected on the duplicate header alone, before the grant is even looked
    // at -- so it must not surface as invalid_grant.
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_ne!(json["error"], "invalid_grant", "got: {json}");
}

/// RFC 9449 §4.3 check 1 again, at the protected resource.
#[tokio::test]
async fn two_dpop_headers_at_the_credential_endpoint_are_rejected() {
    let (state, _dir) = setup_test_app().await;
    let (access_token, _kp) = issue_offer_and_get_dpop_bound_access_token(&state).await;

    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
        .header("DPoP", "first")
        .header("DPoP", "second")
        .body(Body::from(
            serde_json::json!({
                "credential_configuration_id": "pid",
                "format": "dc+sd-jwt",
            })
            .to_string(),
        ))
        .unwrap();

    let res = wallet_router(state.clone())
        .oneshot(cred_req)
        .await
        .unwrap();
    // exactly_one_header's duplicate-header rejection is InvalidClient (the
    // same structural-request-error family ABCA's identical guard uses), not
    // InvalidDpopProof -- the 401 + WWW-Authenticate: DPoP challenge is
    // reserved for an actual binding failure, so this is a 400 like every
    // other malformed-header case at this endpoint.
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// `setup_test_app()` plus the EMVCo DPC credential type.
///
/// Extends the config rather than editing `setup_test_app` itself: that harness
/// backs every other test in this file, and the DPC type is needed by exactly
/// one of them. The `DPC_VCT` gate keys on `vct`, so that field is what matters
/// here.
async fn setup_test_app_with_dpc() -> (AppState, tempfile::TempDir) {
    let (base, dir) = setup_test_app().await;
    let mut cfg = (*base.config).clone();
    cfg.credential_types.push(CredentialType {
        id: "com.emvco.dpc.card".to_string(),
        format: "dc+sd-jwt".to_string(),
        vct: Some("com.emvco.dpc.card".to_string()),
        doctype: None,
        scope: None,
        cryptographic_holder_binding: true,
        display: vec![],
        claims: vec![
            ClaimDef {
                path: vec!["credential_id".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
            ClaimDef {
                path: vec!["network".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
        ],
        validity_seconds: None,
    });
    (AppState::new(base.storage.clone(), Arc::new(cfg)), dir)
}

/// The property the whole branch exists for: display metadata supplied once at
/// offer creation reaches the wallet twice -- on the offer for consent, and on
/// the credential response for rendering -- with the offer-stage and
/// response-stage objects kept distinct.
#[tokio::test]
async fn display_metadata_flows_from_offer_creation_through_to_the_credential_response() {
    let (state, _dir) = setup_test_app_with_dpc().await;

    // 1. Create a DPC offer carrying both display objects. The offer-stage
    //    object is deliberately non-PII; the response-stage one carries
    //    last_four and card_art, which the schema requires.
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "com.emvco.dpc.card",
        "claims": { "credential_id": "cred-1", "network": "example_network" },
        "tx_code_required": false,
        "offer_display": [{
            "locale": "en-US",
            "card": { "type": { "code": "CREDIT", "label": "Credit Card" } }
        }],
        "credential_response_display": [{
            "locale": "en-US",
            "card": {
                "last_four": "4444",
                "alias": "Platinum Credit Card",
                "card_art": [
                    { "theme": "DEFAULT", "image_url": "https://bank.example/card.png" }
                ]
            }
        }]
    });

    let offer_res = admin_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer test-admin-key")
                .body(Body::from(offer_req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(offer_res.status(), StatusCode::OK);
    let offer_bytes = axum::body::to_bytes(offer_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let offer_json: serde_json::Value = serde_json::from_slice(&offer_bytes).unwrap();

    // 2. The offer carries the offer-stage object and NOT the response-stage one.
    assert_eq!(
        offer_json["credential_offer"]["display"][0]["card"]["type"]["code"],
        "CREDIT"
    );
    assert!(
        offer_json["credential_offer"]["display"][0]["card"]
            .get("last_four")
            .is_none(),
        "the offer must not carry the response-stage object: the annex's \
         offer-stage guidance excludes PII-type members"
    );

    let pre_auth_code = offer_json["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .unwrap();

    // 3. Redeem the pre-authorized code, mint a c_nonce, build a holder proof.
    let token_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    let access_token = token_json["access_token"].as_str().unwrap();

    let c_nonce = mint_c_nonce(&state).await;
    let (proof_jwt, _keypair) = create_proof(&c_nonce, "https://issuer.example.com");

    let cred_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(
                    serde_json::json!({
                        "credential_configuration_id": "com.emvco.dpc.card",
                        "format": "dc+sd-jwt",
                        "proofs": { "jwt": [proof_jwt] },
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cred_res.status(), StatusCode::OK);
    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();

    // 4. The credential response carries the response-stage object.
    assert_eq!(cred_json["display"][0]["card"]["last_four"], "4444");
    assert_eq!(
        cred_json["display"][0]["card"]["card_art"][0]["theme"],
        "DEFAULT"
    );

    // 5. And the credential itself was still issued.
    let credential_str = cred_json["credentials"][0]["credential"].as_str().unwrap();
    assert!(credential_str.contains('~'));
}
