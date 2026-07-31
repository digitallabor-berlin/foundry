//! Shared in-process test harness for foundry-wallet's integration tests:
//! boots the real `foundry` admin + wallet axum routers on ephemeral real
//! TCP ports (backed by a temp SQLite DB and a temp dev PKI), so
//! `foundry-wallet`'s HTTP client exercises the genuine wire format without
//! subprocess/binary-path complexity. Adapted from
//! `crates/foundry/tests/wallet_verification.rs::setup_test_app`.

use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, KeyEntry,
    LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, TrustAnchor,
    VerifierConfig, WalletFacingConfig,
};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap as StdBTreeMap;
use std::sync::Arc;

pub const ADMIN_API_KEY: &str = "test-admin-key";
pub const ISSUER_BASE: &str = "https://issuer.example.com";
pub const VCT_PID: &str = "https://issuer.example.com/vct/pid";

#[allow(dead_code)] // wallet_base/root_cert_pem are consumed by Task 12/13 integration tests
pub struct TestServer {
    pub admin_base: String,
    pub wallet_base: String,
    /// PEM of the dev root CA both the issuer and verifier leaf certs chain to.
    pub root_cert_pem: String,
    _storage_dir: tempfile::TempDir,
}

/// Boot a real admin-facing + wallet-facing server pair in-process, each on
/// its own ephemeral `127.0.0.1` port, with one `pid` credential type and a
/// verifier configured with `x509_san_dns` client_id_scheme (matching the
/// dev-PKI leaf certs' SAN).
pub async fn spawn_test_server() -> TestServer {
    let dir = tempfile::tempdir().expect("create tempdir");
    let db_path = dir.path().join("foundry.db");

    let root = new_ca("Foundry Wallet Test Root CA", 365).expect("new_ca");
    let issuer_leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .expect("issue_leaf issuer");
    let verifier_leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .expect("issue_leaf verifier");

    let issuer_key_path = dir.path().join("issuer.pem");
    let verifier_key_path = dir.path().join("verifier.pem");
    std::fs::write(&issuer_key_path, &issuer_leaf.key_pem).unwrap();
    std::fs::write(&verifier_key_path, &verifier_leaf.key_pem).unwrap();
    let issuer_cert_path = dir.path().join("issuer_cert.pem");
    std::fs::write(&issuer_cert_path, &issuer_leaf.cert_pem).unwrap();
    let verifier_cert_path = dir.path().join("verifier_cert.pem");
    std::fs::write(&verifier_cert_path, &verifier_leaf.cert_pem).unwrap();
    let trust_root_path = dir.path().join("trust_root.pem");
    std::fs::write(&trust_root_path, &root.cert_pem).unwrap();

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .expect("connect sqlite");

    let mut keys = StdBTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            private_key: issuer_key_path.to_str().unwrap().to_string(),
            x5c: Some(issuer_cert_path.to_str().unwrap().to_string()),
            alg: "ES256".to_string(),
        },
    );
    keys.insert(
        "verifier_signing".to_string(),
        KeyEntry {
            private_key: verifier_key_path.to_str().unwrap().to_string(),
            x5c: Some(verifier_cert_path.to_str().unwrap().to_string()),
            alg: "ES256".to_string(),
        },
    );

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: ISSUER_BASE.to_string(),
                bind: "127.0.0.1:0".to_string(),
                swagger_ui_enabled: false,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:0".to_string(),
                api_key: Some(ADMIN_API_KEY.to_string()),
                api_key_env: None,
                swagger_ui_enabled: false,
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
            credential_issuer: ISSUER_BASE.to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some(VCT_PID.to_string()),
            doctype: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![
                ClaimDef {
                    path: vec!["given_name".to_string()],
                    selectively_disclosable: true,
                    display: vec![],
                },
                ClaimDef {
                    path: vec!["birthdate".to_string()],
                    selectively_disclosable: true,
                    display: vec![],
                },
            ],
        }],
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
        },
        logging: LoggingConfig::default(),
    };

    let state = AppState::new(Arc::new(storage), Arc::new(config));

    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin listener");
    let admin_addr = admin_listener.local_addr().unwrap();
    let admin_app = admin_router(state.clone(), AdminApiKey(Some(ADMIN_API_KEY.to_string())));
    tokio::spawn(async move {
        axum::serve(admin_listener, admin_app).await.unwrap();
    });

    let wallet_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wallet listener");
    let wallet_addr = wallet_listener.local_addr().unwrap();
    let wallet_app = wallet_router(state);
    tokio::spawn(async move {
        axum::serve(wallet_listener, wallet_app).await.unwrap();
    });

    TestServer {
        admin_base: format!("http://{admin_addr}"),
        wallet_base: format!("http://{wallet_addr}"),
        root_cert_pem: root.cert_pem,
        _storage_dir: dir,
    }
}
