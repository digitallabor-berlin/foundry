use axum::body::Body;
use axum::http::{Request, StatusCode};
use foundry::server::{AppState, wallet_router};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
    KeyEntry, LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
    WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn test_config() -> Config {
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
            encrypted_pre_authorized_code: Default::default(),
            access_token_ttl_secs: 600,
            offer_by_reference: false,
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
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
            validity_seconds: None,
        }],
        verifier: VerifierConfig {
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: Vec::new(),
            named_queries: Vec::new(),
            webhook: None,
            dc_api_expected_origins: Vec::new(),
            dc_api_accept_legacy_web_origin_audience: false,
        },
        logging: LoggingConfig::default(),
    }
}

async fn test_app() -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("w.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config());
    std::mem::forget(dir);
    wallet_router(AppState::new(storage, config))
}

/// Both Credential Format profiles' algorithm registries, in one served
/// document.
///
/// OpenID4VCI 1.0 L1393 makes the identifier type a property of the Credential
/// Format: L2223 puts `mso_mdoc` in the **numeric COSE** registry (the values
/// securing the `IssuerAuth` COSE structure), while L2265 puts SD-JWT VC in the
/// **string JOSE** registry. A single hardcoded `["ES256"]` satisfied neither
/// requirement honestly — it was simply the JOSE spelling applied to everything,
/// and a conformant wallet rejected the mdoc configuration for it.
///
/// Pinned at the HTTP layer, not only in `foundry-issuer`'s unit tests, because
/// what a wallet parses is this response body — after serde's untagged
/// serialisation and the router. Asserting both configurations together is the
/// point: it shows the choice is made per format, not once per document.
#[tokio::test]
async fn issuer_metadata_uses_each_formats_own_algorithm_registry() {
    let mut cfg = test_config();
    cfg.keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            // Never opened: metadata reads `alg` and does no filesystem I/O.
            private_key: "unused-by-metadata.pem".to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );
    // The EUDI Proof of Age attestation shipped in config.yaml, and the only
    // mso_mdoc type foundry mints (docs/specs/eu-age-verification-annex-a-av-profile.md).
    cfg.credential_types.push(CredentialType {
        id: "eu.europa.ec.av.1".to_string(),
        format: "mso_mdoc".to_string(),
        vct: None,
        doctype: Some("eu.europa.ec.av.1".to_string()),
        scope: None,
        cryptographic_holder_binding: true,
        display: vec![],
        claims: vec![ClaimDef {
            path: vec!["age_over_18".to_string()],
            required: None,
            selectively_disclosable: true,
            display: vec![],
        }],
        validity_seconds: None,
    });

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("w.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    std::mem::forget(dir);
    let app = wallet_router(AppState::new(storage, Arc::new(cfg)));
    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let configs = &json["credential_configurations_supported"];

    // L2223: numeric COSE identifier. -7 is ECDSA with SHA-256, the label
    // foundry-mdoc writes into the IssuerAuth COSE header for an ES256 key.
    let mdoc_algs = &configs["eu.europa.ec.av.1"]["credential_signing_alg_values_supported"];
    assert_eq!(configs["eu.europa.ec.av.1"]["format"], "mso_mdoc");
    assert_eq!(
        *mdoc_algs,
        serde_json::json!([-7]),
        "mso_mdoc must advertise the numeric COSE identifier (L2223): {mdoc_algs}"
    );
    assert!(
        mdoc_algs[0].is_number(),
        "a JOSE name string here is what a conformant wallet rejects: {mdoc_algs}"
    );

    // L2265: JOSE Algorithm Name, in the same document, from the same key.
    let sd_jwt_algs = &configs["pid"]["credential_signing_alg_values_supported"];
    assert_eq!(configs["pid"]["format"], "dc+sd-jwt");
    assert_eq!(*sd_jwt_algs, serde_json::json!(["ES256"]));
    assert!(
        sd_jwt_algs[0].is_string(),
        "dc+sd-jwt stays in the JOSE registry: {sd_jwt_algs}"
    );
}

#[tokio::test]
async fn serves_credential_issuer_metadata() {
    let app = test_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["credential_issuer"], "https://localhost:8443");
    assert!(json["credential_configurations_supported"]["pid"].is_object());
}

#[tokio::test]
async fn serves_authorization_server_metadata() {
    let app = test_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["issuer"], "https://localhost:8443");
    assert_eq!(json["token_endpoint"], "https://localhost:8443/token");

    // RFC 9449 §5.1 -- HAIP OpenID4VCI L163 requires DPoP support, and this
    // field is how a wallet discovers it. The harness builds the default
    // config, so mode is Optional here (Task 1) and the field must be present.
    assert_eq!(
        json["dpop_signing_alg_values_supported"],
        serde_json::json!(["ES256"])
    );
}

#[tokio::test]
async fn metadata_omits_encryption_objects_when_unconfigured() {
    let app = test_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // The zero-blast-radius guarantee: an unconfigured deployment's document is
    // exactly what it was before encryption existed.
    assert!(json.get("credential_request_encryption").is_none());
    assert!(json.get("credential_response_encryption").is_none());
}
