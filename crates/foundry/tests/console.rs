use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{AppState, admin_router};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, DpopConfig, IssuerConfig, LoggingConfig, Mode,
    ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
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
        credential_types: Vec::new(),
        verifier: VerifierConfig {
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

#[tokio::test]
async fn console_endpoint_returns_html_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

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
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

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
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

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

#[tokio::test]
async fn console_has_open_in_wallet_links_for_same_device_flow() {
    // Same-device flow support: alongside the existing QR + Copy button, the
    // console must offer a tappable deep link so that opening the console on
    // the phone that has the wallet installed can launch it directly,
    // without needing a second device to scan the QR.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

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

    assert!(
        html.contains(r#"id="offer-open"#),
        "console page should have an offer-open link for the same-device issuance flow"
    );
    assert!(
        html.contains(r#"id="verification-open"#),
        "console page should have a verification-open link for the same-device verification flow"
    );
}

#[tokio::test]
async fn console_has_digital_credentials_api_trigger_for_dc_api_transport() {
    // The console must offer a real way to invoke the dc_api transport in the
    // browser it's running in, not just print a static "use it directly"
    // string: a transport <select> (not free text) with both options, and a
    // button that JS wires to navigator.credentials.get().
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

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

    assert!(
        html.contains(r#"<select id="transport">"#),
        "console page should render `transport` as a <select>, not a free-text input"
    );
    assert!(
        html.contains(r#"<option value="request_uri""#),
        "console `transport` select should offer request_uri"
    );
    assert!(
        html.contains(r#"<option value="dc_api">"#),
        "console `transport` select should offer dc_api"
    );
    assert!(
        html.contains(r#"id="verification-dc-api-btn""#),
        "console page should have a button to trigger the Digital Credentials API for dc_api transport"
    );
}

#[tokio::test]
async fn console_has_digital_credentials_api_trigger_for_issuance() {
    // Chrome 143 added navigator.credentials.create() for credential issuance.
    // The console must expose it alongside the existing QR / deep-link
    // affordances, and must be able to report a real outcome (offered ->
    // issued) rather than only that an offer was created.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

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

    assert!(
        html.contains(r#"id="offer-dc-api-btn""#),
        "console page should have a button to add the offer to a wallet via the Digital Credentials API"
    );
    assert!(
        html.contains(r#"id="issuance-status""#),
        "console page should have an issuance status badge so the operator sees whether the credential was issued"
    );
    assert!(
        html.contains(r#"id="issuance-tx-code""#),
        "console page should have a place to display the tx_code the wallet will prompt for"
    );
    assert!(
        html.contains("navigator.credentials.create"),
        "console JS should invoke navigator.credentials.create for issuance"
    );
    assert!(
        html.contains("openid4vci-v1"),
        "console JS should use the openid4vci-v1 DC API protocol identifier"
    );
}

#[tokio::test]
async fn console_styles_the_issuance_badge_states() {
    // The stylesheet historically defined only the verification states
    // (pending / verified / failed). The issuance card reports `offered` and
    // `issued`, and renders the server's state name verbatim as the class —
    // so both need rules, or the badge renders unstyled.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

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

    assert!(
        html.contains(".badge.offered"),
        "console CSS must style the `offered` issuance state"
    );
    assert!(
        html.contains(".badge.issued"),
        "console CSS must style the `issued` issuance state"
    );
}

#[tokio::test]
async fn console_has_transaction_data_input_for_verification() {
    // OpenID4VP `transaction_data` is implemented end-to-end in the verifier
    // (validated and encoded by `encode_transaction_data`, bound by
    // `check_transaction_data_binding`) but was unreachable from the console:
    // the verification card had no input for it. The field is a raw JSON
    // textarea inside a collapsed disclosure -- entry bodies are type-specific
    // and open-ended, so a structured form would encode a partial schema the
    // console has no business owning.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

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

    assert!(
        html.contains(r#"id="transaction-data-json"#),
        "console page should have a transaction_data textarea"
    );
    assert!(
        html.contains("Transaction data (optional)"),
        "the transaction_data textarea should sit behind a labelled disclosure"
    );
    assert!(
        html.contains("opt-disclosure"),
        "the disclosure should use its own class, not the QR block's \
         (whose summary is display:none above 641px)"
    );
    assert!(
        html.contains("payload.transaction_data"),
        "the create-verification handler should put the parsed entries on the payload"
    );
}
