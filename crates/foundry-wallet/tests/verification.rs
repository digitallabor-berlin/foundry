mod support;

use foundry_wallet::actions::issuance::run_issuance;
use foundry_wallet::actions::verification::{run_verification, Consent, VerificationOutcome};
use foundry_wallet::config::{
    EndpointsConfig, IssuancePreset, TrustAnchorConfig, TrustConfig, TrustValidationMode,
    VerificationPreset, WalletConfig,
};
use std::collections::BTreeMap;
use support::spawn_test_server;

fn base_config(
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
    let mut verification_presets = BTreeMap::new();
    verification_presets.insert(
        "dcql1".to_string(),
        VerificationPreset {
            dcql_query: serde_json::json!({
                "credentials": [{
                    "id": "c1",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": [support::VCT_PID] },
                    "claims": [{ "path": ["given_name"] }, { "path": ["birthdate"] }]
                }]
            }),
            transport: "request_uri".to_string(),
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
        verification_presets,
    }
}

#[tokio::test]
async fn accepted_verification_with_matching_credential_succeeds() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config = base_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    run_issuance(&config, Some("pid"), None, None)
        .await
        .unwrap();

    let outcome = run_verification(&config, Some("dcql1"), None, Consent::Accept)
        .await
        .unwrap();
    match outcome {
        VerificationOutcome::Verified(result) => {
            assert!(result.verified, "checks: {:?}", result.checks);
        }
        VerificationOutcome::Declined => panic!("expected Verified"),
    }
}

#[tokio::test]
async fn declined_verification_never_calls_the_response_endpoint() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config = base_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    run_issuance(&config, Some("pid"), None, None)
        .await
        .unwrap();

    let outcome = run_verification(&config, Some("dcql1"), None, Consent::Decline)
        .await
        .unwrap();
    assert!(matches!(outcome, VerificationOutcome::Declined));

    let events = foundry_wallet::storage::event_log::read_events(&config.data_dir).unwrap();
    let posted_response = events.iter().any(|e| {
        e["kind"] == "http_request" && e["url"].as_str().unwrap_or("").contains("/vp/response/")
    });
    assert!(
        !posted_response,
        "declined flow must never POST /vp/response/:id"
    );
}

#[tokio::test]
async fn untrusted_request_object_aborts_before_any_credential_is_touched() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    // Unrelated root: the verifier's request object won't chain to it.
    let unrelated_root = foundry_core::pki::new_ca("Unrelated Root", 365).unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &unrelated_root.cert_pem).unwrap();
    let config = base_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    run_issuance(&config, Some("pid"), None, None)
        .await
        .unwrap();

    let err = run_verification(&config, Some("dcql1"), None, Consent::Accept)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "trust_validation");
}
