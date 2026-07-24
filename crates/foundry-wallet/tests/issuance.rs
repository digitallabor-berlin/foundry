mod support;

use foundry_core::trust::TrustStore;
use foundry_wallet::actions::issuance::run_issuance;
use foundry_wallet::config::{
    EndpointsConfig, IssuancePreset, TrustAnchorConfig, TrustConfig, TrustValidationMode,
    WalletConfig,
};
use std::collections::BTreeMap;
use support::spawn_test_server;

fn wallet_config(
    data_dir: std::path::PathBuf,
    server: &support::TestServer,
    trust_anchor_path: std::path::PathBuf,
) -> WalletConfig {
    let mut issuance_presets = BTreeMap::new();
    issuance_presets.insert(
        "pid".to_string(),
        IssuancePreset {
            credential_type_id: "pid".to_string(),
            claims: BTreeMap::from([
                ("given_name".to_string(), serde_json::json!("Alice")),
                ("birthdate".to_string(), serde_json::json!("1990-01-01")),
            ]),
            tx_code_required: false,
        },
    );
    WalletConfig {
        data_dir,
        endpoints: EndpointsConfig {
            admin_base_url: server.admin_base.clone(),
            wallet_base_url: server.wallet_base.clone(),
            admin_api_key: Some(support::ADMIN_API_KEY.to_string()),
            admin_api_key_env: None,
        },
        trust: TrustConfig {
            validation: TrustValidationMode::Enabled,
            anchors: vec![TrustAnchorConfig {
                certs: trust_anchor_path,
            }],
        },
        issuance_presets,
        verification_presets: BTreeMap::new(),
    }
}

#[tokio::test]
async fn issuance_with_matching_trust_anchor_stores_a_valid_credential() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();

    let config = wallet_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    let outcome = run_issuance(&config, Some("pid"), None, None)
        .await
        .unwrap();
    assert_eq!(outcome.vct, support::VCT_PID);
    assert_eq!(outcome.trust_valid, Some(true));

    let stored = foundry_wallet::storage::credential_store::load_metadata(
        &config.data_dir,
        &outcome.credential_id,
    )
    .unwrap();
    assert_eq!(stored.vct, support::VCT_PID);
    assert!(stored.disclosed_claims.contains(&"given_name".to_string()));

    let payload = foundry_wallet::storage::credential_store::load_payload(
        &config.data_dir,
        &outcome.credential_id,
    )
    .unwrap();
    assert_eq!(payload["disclosed_claims"]["given_name"], "Alice");
    assert_eq!(payload["disclosed_claims"]["birthdate"], "1990-01-01");

    // Full request/response logging happened (no redaction).
    let events = foundry_wallet::storage::event_log::read_events(&config.data_dir).unwrap();
    assert!(events
        .iter()
        .any(|e| e["kind"] == "http_request" && e["method"] == "POST"));
}

#[tokio::test]
async fn issuance_with_unrelated_trust_anchor_stores_but_flags_trust_invalid() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    // An unrelated root that does NOT chain to the issuer's leaf.
    let unrelated_root = foundry_core::pki::new_ca("Unrelated Root", 365).unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &unrelated_root.cert_pem).unwrap();

    let config = wallet_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    // Storage is never blocked, per the design doc's asymmetric rule.
    let outcome = run_issuance(&config, Some("pid"), None, None)
        .await
        .unwrap();
    assert_eq!(outcome.trust_valid, Some(false));
}

#[tokio::test]
async fn unknown_preset_errors_with_config_kind() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config = wallet_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    let err = run_issuance(&config, Some("nonexistent"), None, None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "config");
    let _ = TrustStore::from_pems(&[]); // keep TrustStore import used if unused elsewhere
}
