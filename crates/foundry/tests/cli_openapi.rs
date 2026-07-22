use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn test_cli_openapi_subcommand() {
    let temp_file = NamedTempFile::new().unwrap();
    let temp_path = temp_file.path().to_str().unwrap().to_string();

    let binary_path = env!("CARGO_BIN_EXE_foundry");
    let output = Command::new(binary_path)
        .args(["openapi", "--out", &temp_path])
        .output()
        .expect("Failed to execute foundry binary");

    assert!(
        output.status.success(),
        "foundry openapi command failed: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&temp_path).expect("Failed to read openapi output file");
    assert!(!content.is_empty(), "Exported OpenAPI spec should not be empty");

    let json: serde_json::Value =
        serde_json::from_str(&content).expect("Exported content should be valid JSON");

    let openapi_ver = json
        .get("openapi")
        .and_then(|v| v.as_str())
        .expect("OpenAPI spec should contain 'openapi' version field");

    assert!(
        openapi_ver.starts_with("3."),
        "Expected OpenAPI version 3.x, got '{openapi_ver}'"
    );

    let paths = json
        .get("paths")
        .and_then(|p| p.as_object())
        .expect("OpenAPI spec should contain 'paths' object");

    assert!(
        paths.contains_key("/admin/issuance/offers"),
        "OpenAPI spec paths missing '/admin/issuance/offers'"
    );

    assert!(
        paths.contains_key("/admin/verification/requests"),
        "OpenAPI spec paths missing '/admin/verification/requests'"
    );
}
