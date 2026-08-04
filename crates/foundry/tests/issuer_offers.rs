use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
    LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
    WalletFacingConfig,
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
                challenge_mode: Mode::Disabled,
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
                challenge_mode: Mode::Disabled,
            },
            status_list: StatusListConfig {
                enabled: status_list_enabled,
                signing_key: None,
                list_size: Some(1024),
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
                selectively_disclosable: true,
                display: vec![],
            }],
        }],
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
async fn create_offer_response_carries_a_dc_api_offer() {
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

    let dc = &json["dc_api_offer"];
    assert!(
        dc.is_object(),
        "dc_api_offer must be present on the create-offer response, got: {json}"
    );
    assert_eq!(dc["credential_issuer"], "https://localhost:8443");
    assert_eq!(
        dc["credential_configuration_ids"],
        serde_json::json!(["pid"])
    );
    assert!(
        dc["authorization_server_metadata"]["token_endpoint"].is_string(),
        "dc_api_offer must inline authorization_server_metadata"
    );
    assert!(
        dc["credential_issuer_metadata"]["credential_configurations_supported"]["pid"].is_object(),
        "dc_api_offer must inline credential_issuer_metadata for the offered id"
    );
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

/// Helper: create an offer and return the parsed response body.
async fn create_offer_json(app: &axum::Router, tx_code_required: bool) -> serde_json::Value {
    let body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": {},
        "tx_code_required": tx_code_required
    });
    let res = app
        .clone()
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
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: GET the status endpoint, returning (status, parsed body).
async fn get_offer_status(app: &axum::Router, id: &str) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/issuance/offers/{id}"))
                .header(AUTHORIZATION, "Bearer test-admin-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn offer_status_reports_offered_for_a_fresh_offer() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, false).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let (status, json) = get_offer_status(&app, id).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["transaction_id"], id);
    assert_eq!(json["credential_type_id"], "pid");
    assert_eq!(json["state"], "offered");
    assert!(json["created_at"].is_i64());
}

/// The security property from the design doc: `IssuanceTransaction` holds
/// `pre_authorized_code` and `access_token`, which are live bearer credentials
/// against the wallet-facing listener. Returning them would let any admin-key
/// holder redeem an offer intended for a wallet, so the endpoint returns a
/// narrow projection rather than the transaction.
#[tokio::test]
async fn offer_status_never_returns_bearer_credentials_or_claims() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, false).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let (status, json) = get_offer_status(&app, id).await;
    assert_eq!(status, StatusCode::OK);

    let obj = json.as_object().expect("status response must be an object");
    for forbidden in [
        "pre_authorized_code",
        "access_token",
        "authorization_code",
        "code_challenge",
        "code_challenge_method",
        "dpop_jkt",
        "claims",
        "redirect_uri",
        "issuer_state",
    ] {
        assert!(
            !obj.contains_key(forbidden),
            "offer status must not expose '{forbidden}'; body was: {json}"
        );
    }
}

/// `tx_code` is generated and persisted but surfaced nowhere else, which makes
/// `tx_code_required: true` untestable through the console. Its whole purpose
/// is out-of-band relay to the person completing the flow, and the
/// authenticated operator who created the offer is that channel.
#[tokio::test]
async fn offer_status_returns_the_tx_code_when_one_was_generated() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, true).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let (status, json) = get_offer_status(&app, id).await;

    assert_eq!(status, StatusCode::OK);
    let tx_code = json["tx_code"]
        .as_str()
        .expect("tx_code must be present when tx_code_required was set");
    assert_eq!(tx_code.len(), 4, "default tx_code length is 4 digits");
    assert!(tx_code.chars().all(|c| c.is_ascii_digit()));
}

#[tokio::test]
async fn offer_status_omits_the_tx_code_when_none_was_generated() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, false).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let (_, json) = get_offer_status(&app, id).await;

    assert!(
        json.get("tx_code").is_none(),
        "tx_code must be omitted when the offer needs none; body was: {json}"
    );
}

#[tokio::test]
async fn offer_status_returns_404_for_an_unknown_transaction_id() {
    let app = test_app(true).await;
    let (status, _) = get_offer_status(&app, "no-such-transaction").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn offer_status_requires_the_admin_bearer_token() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, false).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/issuance/offers/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
