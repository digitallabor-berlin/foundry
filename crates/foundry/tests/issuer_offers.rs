use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, LoggingConfig,
    Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn test_config(status_list_enabled: bool) -> Config {
    Config {
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
            path: "./foundry.db".to_string(),
            transaction_ttl_secs: 600,
        },
        keys: BTreeMap::new(),
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://localhost:8443".to_string(),
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
                enabled: status_list_enabled,
                signing_key: None,
                list_size: Some(1024),
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
            transaction_data_hashes_alg: Vec::new(),
            named_queries: Vec::new(),
            webhook: None,
            dc_api_expected_origins: Vec::new(),
        },
        logging: LoggingConfig::default(),
    }
}

async fn test_app(status_list_enabled: bool) -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("o.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(status_list_enabled));
    std::mem::forget(dir);
    admin_router(
        AppState::new(storage, config),
        AdminApiKey(Some("test-admin-key".to_string())),
    )
}

#[tokio::test]
async fn creates_an_offer_with_valid_bearer_token() {
    let app = test_app(true).await;
    let body =
        serde_json::json!({ "credential_type_id": "pid", "claims": {}, "tx_code_required": false });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer test-admin-key")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["transaction_id"].is_string());
    assert!(json["credential_offer_uri"]
        .as_str()
        .unwrap()
        .starts_with("openid-credential-offer://"));
}

#[tokio::test]
async fn rejects_offer_creation_without_bearer_token() {
    let app = test_app(true).await;
    let body = serde_json::json!({ "credential_type_id": "pid", "claims": {} });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_offer_creation_with_wrong_bearer_token() {
    let app = test_app(true).await;
    let body = serde_json::json!({ "credential_type_id": "pid", "claims": {} });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer wrong-key")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn returns_bad_request_for_unknown_credential_type() {
    let app = test_app(true).await;
    let body = serde_json::json!({ "credential_type_id": "does-not-exist", "claims": {} });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer test-admin-key")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["error"].as_str().unwrap().contains("does-not-exist"));
}
