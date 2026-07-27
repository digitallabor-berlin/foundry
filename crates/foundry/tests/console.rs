use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, IssuerConfig, Mode, ServerConfig, StatusListConfig,
    StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn test_config(console_enabled: bool) -> Config {
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
                swagger_ui_enabled: true,
                console_enabled,
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

#[tokio::test]
async fn console_endpoint_returns_html_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
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
        content_type.starts_with("text/html"),
        "Content-Type should be text/html, got '{content_type}'"
    );

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);
    assert!(
        html.contains("Foundry Admin Test Console"),
        "console page should contain its title marker"
    );
}

#[tokio::test]
async fn console_endpoint_returns_404_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(false));
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn console_qr_svg_css_sets_explicit_dimensions() {
    // Regression test for a Safari-only bug: the vendored QR library's
    // createSvgTag({ scalable: true }) omits width/height attributes on the
    // generated <svg>, relying only on its viewBox. Chrome falls back to a
    // usable default size for a viewBox-only SVG; Safari's replaced-element
    // sizing algorithm collapses it to near-zero ("a little white box")
    // unless the page's own CSS sets an explicit width/height. This test
    // ensures `.qr-wrap svg` always carries that explicit sizing.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);

    let selector = ".qr-wrap svg {";
    let selector_start = html
        .find(selector)
        .expect("console.html should style `.qr-wrap svg`");
    let rule_start = selector_start + selector.len();
    let rule_end = html[rule_start..]
        .find('}')
        .map(|i| rule_start + i)
        .expect("`.qr-wrap svg` CSS rule should be closed with `}`");
    let rule_body = &html[rule_start..rule_end];

    assert!(
        rule_body.contains("width") && rule_body.contains("height"),
        "`.qr-wrap svg` must set explicit width/height (or aspect-ratio-based \
         sizing) so Safari doesn't collapse the QR SVG to near-zero size; \
         rule body was: {rule_body:?}"
    );
}
