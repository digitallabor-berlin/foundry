use foundry_core::config::Config;
use std::path::Path;

#[test]
fn loads_minimal_yaml_and_validates() {
    let cfg = Config::load(Path::new("tests/fixtures/minimal.yaml")).expect("should load");
    assert_eq!(cfg.issuer.credential_issuer, "https://issuer.example.com");
    assert_eq!(cfg.credential_types.len(), 1);
    assert_eq!(cfg.credential_types[0].id, "pid");
    cfg.validate().expect("minimal config should be valid");
}

#[test]
fn rejects_unresolvable_key_reference() {
    let cfg =
        Config::load(Path::new("tests/fixtures/bad-missing-keyref.yaml")).expect("should parse");
    let err = cfg.validate().expect_err("should fail validation");
    let msg = err.to_string();
    assert!(
        msg.contains("signing_key") && msg.contains("nonexistent_key"),
        "unexpected error: {msg}"
    );
}
