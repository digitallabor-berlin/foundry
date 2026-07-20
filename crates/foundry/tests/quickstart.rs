use foundry::commands;
use foundry_core::config::Config;

#[test]
fn quickstart_emits_valid_pki_and_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("config.yaml");
    commands::quickstart(dir.path(), &cfg_path).unwrap();

    // Files exist.
    for rel in [
        "trust/root.pem",
        "keys/issuer_sdjwt.pem",
        "keys/issuer_sdjwt-chain.pem",
        "keys/verifier_signing.pem",
        "keys/verifier_signing-chain.pem",
        "keys/statuslist_signer.pem",
        "keys/statuslist_signer-chain.pem",
    ] {
        assert!(dir.path().join(rel).exists(), "missing {rel}");
    }

    // Config parses and passes structural validation.
    let cfg = Config::load(&cfg_path).unwrap();
    cfg.validate().unwrap();

    // Key material resolves relative to the config directory (Task 10 API).
    // NOTE: `validate_key_material` is added in Task 10. Commented out here so
    // Task 9 compiles and passes independently; re-enabled in Task 10 Step 1.
    // cfg.validate_key_material(dir.path()).unwrap();
}