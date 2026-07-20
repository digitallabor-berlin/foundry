use foundry_core::config::Config;
use foundry_core::pki::{issue_leaf, new_ca};
use std::fs;

/// Build a temp dir with a real dev PKI + a config that references it, then
/// assert validate_key_material accepts it and rejects a self-signed x5c leaf.
fn write_pki(dir: &std::path::Path) {
    fs::create_dir_all(dir.join("keys")).unwrap();
    fs::create_dir_all(dir.join("trust")).unwrap();
    let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
    fs::write(dir.join("trust/root.pem"), &root.cert_pem).unwrap();
    let leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();
    fs::write(dir.join("keys/issuer_sdjwt.pem"), &leaf.key_pem).unwrap();
    fs::write(dir.join("keys/issuer_sdjwt-chain.pem"), &leaf.cert_pem).unwrap();
    // Also stash the self-signed root as a key so we can test the negative path.
    fs::write(dir.join("keys/selfsigned-chain.pem"), &root.cert_pem).unwrap();
    fs::write(dir.join("keys/selfsigned.pem"), &leaf.key_pem).unwrap();
}

const CONFIG_TMPL: &str = r#"server:
  wallet_facing: { public_base_url: https://localhost:8443, bind: 0.0.0.0:8443 }
  admin: { bind: 127.0.0.1:9000, api_key: dev }
storage: { path: ./foundry.db, transaction_ttl_secs: 600 }
keys:
  issuer_sdjwt:
    private_key: ./keys/issuer_sdjwt.pem
    x5c: ./keys/issuer_sdjwt-chain.pem
    alg: ES256
trust_anchors:
  - name: root
    certs: ./trust/root.pem
issuer:
  credential_issuer: https://localhost:8443
  wallet_attestation: { mode: optional }
  key_attestation: { mode: optional }
  status_list: { enabled: false }
credential_types: []
verifier:
  client_id_scheme: x509_san_dns
  signing_key: issuer_sdjwt
  transaction_data_hashes_alg: [sha-256]
  named_queries: []
"#;

#[test]
fn accepts_valid_key_material() {
    let dir = tempfile::tempdir().unwrap();
    write_pki(dir.path());
    let cfg_path = dir.path().join("config.yaml");
    fs::write(&cfg_path, CONFIG_TMPL).unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    cfg.validate().unwrap();
    cfg.validate_key_material(dir.path()).unwrap();
}

#[test]
fn rejects_self_signed_x5c_leaf() {
    let dir = tempfile::tempdir().unwrap();
    write_pki(dir.path());
    // Point the x5c at the self-signed root.
    let bad = CONFIG_TMPL.replace(
        "x5c: ./keys/issuer_sdjwt-chain.pem",
        "x5c: ./keys/selfsigned-chain.pem",
    );
    let cfg_path = dir.path().join("config.yaml");
    fs::write(&cfg_path, bad).unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    let err = cfg.validate_key_material(dir.path()).unwrap_err();
    assert!(err.to_string().contains("self-signed"));
}

#[test]
fn rejects_key_cert_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    // Build a fresh PKI here (rather than write_pki) so we retain the CA key
    // and can issue two distinct leaves from the same root: only the
    // key<->cert mismatch should trigger failure (not self-signed, not
    // untrusted, not missing-file).
    fs::create_dir_all(dir.path().join("keys")).unwrap();
    fs::create_dir_all(dir.path().join("trust")).unwrap();
    let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
    fs::write(dir.path().join("trust/root2.pem"), &root.cert_pem).unwrap();
    let leaf_a = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "leaf-a.local",
        &["leaf-a.local".to_string()],
        365,
    )
    .unwrap();
    let leaf_b = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "leaf-b.local",
        &["leaf-b.local".to_string()],
        365,
    )
    .unwrap();
    fs::write(dir.path().join("keys/leaf_a.pem"), &leaf_a.key_pem).unwrap();
    fs::write(dir.path().join("keys/leaf_a-chain.pem"), &leaf_a.cert_pem).unwrap();
    fs::write(dir.path().join("keys/leaf_b-chain.pem"), &leaf_b.cert_pem).unwrap();

    // Point the key entry's private_key at leaf A's key, but x5c at leaf B's chain.
    let bad = CONFIG_TMPL
        .replace(
            "private_key: ./keys/issuer_sdjwt.pem",
            "private_key: ./keys/leaf_a.pem",
        )
        .replace(
            "x5c: ./keys/issuer_sdjwt-chain.pem",
            "x5c: ./keys/leaf_b-chain.pem",
        )
        .replace("certs: ./trust/root.pem", "certs: ./trust/root2.pem");
    let cfg_path = dir.path().join("config.yaml");
    fs::write(&cfg_path, bad).unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    let err = cfg.validate_key_material(dir.path()).unwrap_err();
    assert!(
        err.to_string().contains("does not match"),
        "unexpected error: {err}"
    );
}

#[test]
fn reports_missing_key_file() {
    let dir = tempfile::tempdir().unwrap();
    // No PKI written → files absent.
    let cfg_path = dir.path().join("config.yaml");
    fs::write(&cfg_path, CONFIG_TMPL).unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    assert!(cfg.validate_key_material(dir.path()).is_err());
}
