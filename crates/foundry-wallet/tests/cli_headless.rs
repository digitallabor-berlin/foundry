mod support;

use assert_cmd::Command;
use std::io::Write;
use support::spawn_test_server;

fn write_wallet_config(
    path: &std::path::Path,
    data_dir: &std::path::Path,
    server: &support::TestServer,
    trust_anchor_path: &std::path::Path,
) {
    let yaml = format!(
        r#"
data_dir: {data_dir}
endpoints:
  admin_base_url: {admin_base}
  wallet_base_url: {wallet_base}
  admin_api_key: {api_key}
trust:
  validation: enabled
  anchors:
    - certs: {trust_anchor}
issuance_presets:
  pid:
    credential_type_id: pid
    claims:
      given_name: Alice
      birthdate: "1990-01-01"
    tx_code_required: false
verification_presets:
  dcql1:
    dcql_query:
      credentials:
        - id: c1
          format: dc+sd-jwt
          meta: {{ vct_values: ["{vct}"] }}
          claims:
            - path: ["given_name"]
    transport: request_uri
"#,
        data_dir = data_dir.display(),
        admin_base = server.admin_base,
        wallet_base = server.wallet_base,
        api_key = support::ADMIN_API_KEY,
        trust_anchor = trust_anchor_path.display(),
        vct = support::VCT_PID,
    );
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(yaml.as_bytes()).unwrap();
}

// Uses assert_cmd's blocking `Command::output()` to spawn a real CLI
// subprocess against the in-process test server. On the default
// current-thread `#[tokio::test]` runtime, that blocking wait starves the
// only worker thread, so the `tokio::spawn`-ed axum servers in
// `spawn_test_server()` never get polled to respond — the CLI subprocess
// then hangs forever waiting for an HTTP response. A multi-thread runtime
// keeps a worker free to poll the servers while this thread blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue_then_verify_accept_via_headless_subcommands() {
    let server = spawn_test_server().await;
    let workdir = tempfile::tempdir().unwrap();
    let data_dir = workdir.path().join("wallet-data");
    let trust_anchor_path = workdir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config_path = workdir.path().join("wallet.yaml");
    write_wallet_config(&config_path, &data_dir, &server, &trust_anchor_path);

    let issue_output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "issue",
            "--preset",
            "pid",
        ])
        .output()
        .unwrap();
    assert!(
        issue_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&issue_output.stderr)
    );
    let issue_json: serde_json::Value = serde_json::from_slice(&issue_output.stdout).unwrap();
    assert_eq!(issue_json["trust_valid"], true);

    let verify_output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "verify",
            "--preset",
            "dcql1",
            "--consent",
            "accept",
        ])
        .output()
        .unwrap();
    assert!(
        verify_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_json: serde_json::Value = serde_json::from_slice(&verify_output.stdout).unwrap();
    assert_eq!(verify_json["verified"], true);
}

// See comment on `issue_then_verify_accept_via_headless_subcommands` above:
// this test also blocks the test thread via `Command::output()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_decline_exits_zero_with_declined_json() {
    let server = spawn_test_server().await;
    let workdir = tempfile::tempdir().unwrap();
    let data_dir = workdir.path().join("wallet-data");
    let trust_anchor_path = workdir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config_path = workdir.path().join("wallet.yaml");
    write_wallet_config(&config_path, &data_dir, &server, &trust_anchor_path);

    Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "issue",
            "--preset",
            "pid",
        ])
        .assert()
        .success();

    let verify_output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "verify",
            "--preset",
            "dcql1",
            "--consent",
            "decline",
        ])
        .output()
        .unwrap();
    assert!(verify_output.status.success());
    let verify_json: serde_json::Value = serde_json::from_slice(&verify_output.stdout).unwrap();
    assert_eq!(verify_json["consent"], "declined");
}

#[test]
fn issue_with_unknown_preset_exits_nonzero_with_error_json() {
    let workdir = tempfile::tempdir().unwrap();
    let data_dir = workdir.path().join("wallet-data");
    let trust_anchor_path = workdir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, "not-a-real-cert").unwrap();
    let config_path = workdir.path().join("wallet.yaml");
    let yaml = format!(
        "data_dir: {}\nendpoints:\n  admin_base_url: http://127.0.0.1:1\n  wallet_base_url: http://127.0.0.1:1\n  admin_api_key: k\ntrust:\n  validation: disabled\n",
        data_dir.display()
    );
    std::fs::write(&config_path, yaml).unwrap();

    let output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "issue",
            "--preset",
            "nonexistent",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let err_json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err_json["kind"], "config");
}

#[test]
fn credentials_list_on_empty_wallet_returns_empty_json_array() {
    let workdir = tempfile::tempdir().unwrap();
    let data_dir = workdir.path().join("wallet-data");
    let config_path = workdir.path().join("wallet.yaml");
    let yaml = format!(
        "data_dir: {}\nendpoints:\n  admin_base_url: http://127.0.0.1:1\n  wallet_base_url: http://127.0.0.1:1\n  admin_api_key: k\ntrust:\n  validation: disabled\n",
        data_dir.display()
    );
    std::fs::write(&config_path, yaml).unwrap();

    let output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "credentials",
            "list",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 0);
}
