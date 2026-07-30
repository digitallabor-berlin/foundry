use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry::server::{wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, IssuerConfig, KeyEntry, Mode, ServerConfig,
    StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::status_list::{save_status_list, PersistentStatusList, StatusValue};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap as StdBTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

async fn setup(status_list_enabled: bool) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");
    let key_path = dir.path().join("statuslist.pem");
    let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
    std::fs::write(&key_path, &km.private_pem).unwrap();

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let mut keys = StdBTreeMap::new();
    keys.insert(
        "statuslist_signer".to_string(),
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
                api_key: None,
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
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
            },
            status_list: StatusListConfig {
                enabled: status_list_enabled,
                signing_key: Some("statuslist_signer".to_string()),
                list_size: Some(128),
                public_base_url: Some("https://issuer.example.com/statuslists".to_string()),
            },
        },
        credential_types: vec![],
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "statuslist_signer".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
        },
    };

    (
        AppState {
            storage: Arc::new(storage),
            config: Arc::new(config),
        },
        dir,
    )
}

#[tokio::test]
async fn statuslists_route_returns_signed_token_for_existing_list() {
    let (state, _dir) = setup(true).await;

    let mut list = PersistentStatusList::new("1", 128, 2);
    list.set_status(5, StatusValue::Invalid).unwrap();
    save_status_list(state.storage.as_ref(), &list)
        .await
        .unwrap();

    let app = wallet_router(state.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/statuslists/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/statuslist+jwt"
    );

    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let token = String::from_utf8(body.to_vec()).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(payload["sub"], "https://issuer.example.com/statuslists/1");
}

#[tokio::test]
async fn statuslists_route_404s_for_unknown_id() {
    let (state, _dir) = setup(true).await;
    let app = wallet_router(state.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/statuslists/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn statuslists_route_404s_when_status_list_disabled() {
    let (state, _dir) = setup(false).await;

    let list = PersistentStatusList::new("1", 128, 2);
    save_status_list(state.storage.as_ref(), &list)
        .await
        .unwrap();

    let app = wallet_router(state.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/statuslists/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
