use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_status_list_set_get_and_token() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_foundry.db");
    let db_str = db_path.to_str().unwrap();

    let binary_path = env!("CARGO_BIN_EXE_foundry");

    // 1. Set status bit at index 42 to revoked
    let set_output = Command::new(binary_path)
        .args([
            "status-list",
            "set",
            "--db",
            db_str,
            "--credential-type",
            "pid",
            "--index",
            "42",
            "--status",
            "revoked",
        ])
        .output()
        .expect("Failed to execute foundry status-list set");

    assert!(
        set_output.status.success(),
        "foundry status-list set failed: stderr = {}",
        String::from_utf8_lossy(&set_output.stderr)
    );

    // 2. Get status value at index 42
    let get_output = Command::new(binary_path)
        .args([
            "status-list",
            "get",
            "--db",
            db_str,
            "--credential-type",
            "pid",
            "--index",
            "42",
        ])
        .output()
        .expect("Failed to execute foundry status-list get");

    assert!(
        get_output.status.success(),
        "foundry status-list get failed: stderr = {}",
        String::from_utf8_lossy(&get_output.stderr)
    );

    let stdout = String::from_utf8_lossy(&get_output.stdout);
    assert!(
        stdout.contains("revoked"),
        "Expected stdout to contain 'revoked', got: {stdout}"
    );

    // 3. Quickstart to generate dev keys/config
    let qs_output = Command::new(binary_path)
        .args([
            "quickstart",
            "--dir",
            dir.path().to_str().unwrap(),
            "--out-config",
            dir.path().join("config.yaml").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute foundry quickstart");

    assert!(
        qs_output.status.success(),
        "foundry quickstart failed: stderr = {}",
        String::from_utf8_lossy(&qs_output.stderr)
    );

    // Point storage.path in config.yaml to db_str
    let config_path = dir.path().join("config.yaml");
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    let updated_config = config_content.replace("./foundry.db", db_str);
    std::fs::write(&config_path, updated_config).unwrap();

    // 4. Generate status list token JWT
    let token_output = Command::new(binary_path)
        .args([
            "status-list",
            "token",
            "--config",
            config_path.to_str().unwrap(),
            "--credential-type",
            "pid",
        ])
        .output()
        .expect("Failed to execute foundry status-list token");

    assert!(
        token_output.status.success(),
        "foundry status-list token failed: stderr = {}",
        String::from_utf8_lossy(&token_output.stderr)
    );

    let token_jwt = String::from_utf8_lossy(&token_output.stdout).trim().to_string();
    assert_eq!(
        token_jwt.split('.').count(),
        3,
        "Expected status-list token to be compact JWS (3 parts), got: {token_jwt}"
    );
}
