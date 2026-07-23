use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, IssuerConfig, Mode, ServerConfig, StatusListConfig,
    StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn test_config(swagger_ui_enabled: bool) -> Config {
    Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://localhost:8443".to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: true,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: None,
                api_key_env: None,
                swagger_ui_enabled,
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
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: Vec::new(),
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: Vec::new(),
            named_queries: Vec::new(),
            webhook: None,
        },
    }
}

fn wallet_facing_test_config(swagger_ui_enabled: bool) -> Config {
    let mut cfg = test_config(true);
    cfg.server.wallet_facing.swagger_ui_enabled = swagger_ui_enabled;
    cfg
}

#[tokio::test]
async fn openapi_json_endpoint_returns_valid_spec() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "Content-Type should be application/json, got '{content_type}'"
    );

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json_val: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("Response body should be valid JSON");

    assert!(
        json_val.get("openapi").is_some(),
        "OpenAPI spec must contain 'openapi' field"
    );
    assert!(
        json_val.get("paths").is_some(),
        "OpenAPI spec must contain 'paths' field"
    );
}

#[tokio::test]
async fn swagger_ui_endpoint_returns_html_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);
    assert!(
        html.contains("swagger-ui") || html.contains("html") || html.contains("SwaggerUI"),
        "Swagger UI endpoint should return HTML content, got: {html}"
    );
}

#[tokio::test]
async fn swagger_ui_endpoint_returns_404_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(false));
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn wallet_openapi_json_endpoint_returns_valid_spec() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(wallet_facing_test_config(true));
    let app = wallet_router(AppState { storage, config });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json_val: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("Response body should be valid JSON");

    assert!(json_val.get("openapi").is_some());
    let paths = json_val
        .get("paths")
        .and_then(|p| p.as_object())
        .expect("paths should be an object");
    for expected in [
        "/.well-known/openid-credential-issuer",
        "/.well-known/oauth-authorization-server",
        "/token",
        "/nonce",
        "/credential",
        "/vp/request/{id}",
        "/vp/response/{id}",
    ] {
        assert!(
            paths.contains_key(expected),
            "wallet OpenAPI spec should document {expected}"
        );
    }
}

#[tokio::test]
async fn wallet_swagger_ui_endpoint_returns_html_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(wallet_facing_test_config(true));
    let app = wallet_router(AppState { storage, config });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);
    assert!(
        html.contains("swagger-ui") || html.contains("html") || html.contains("SwaggerUI"),
        "Wallet Swagger UI endpoint should return HTML content, got: {html}"
    );
}

#[tokio::test]
async fn wallet_swagger_ui_endpoint_returns_404_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(wallet_facing_test_config(false));
    let app = wallet_router(AppState { storage, config });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
