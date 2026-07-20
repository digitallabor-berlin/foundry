use foundry::commands;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
use foundry_core::trust::{is_self_signed, match_san_dns, parse_cert_pem};

#[test]
fn keys_generate_writes_loadable_key() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("issuer.pem");
    commands::keys_generate("ES256", &out).unwrap();

    let signer =
        FileSigner::from_pem_file(out.to_str().unwrap(), SignatureAlgorithm::Es256).unwrap();
    assert_eq!(signer.sign(b"x").unwrap().len(), 64);
}

#[test]
fn cert_new_ca_then_issue_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let ca_cert = dir.path().join("root.pem");
    let ca_key = dir.path().join("root-key.pem");
    commands::cert_new_ca("Foundry Dev Root CA", &ca_cert, &ca_key, 3650).unwrap();

    let ca = parse_cert_pem(&std::fs::read(&ca_cert).unwrap()).unwrap();
    assert!(is_self_signed(&ca));

    let leaf_cert = dir.path().join("issuer-chain.pem");
    let leaf_key = dir.path().join("issuer.pem");
    commands::cert_issue(
        &ca_cert,
        &ca_key,
        "issuer.dev.local",
        &["issuer.dev.local".to_string()],
        &leaf_cert,
        &leaf_key,
        365,
    )
    .unwrap();

    let leaf_pem = std::fs::read(&leaf_cert).unwrap();
    assert!(!is_self_signed(&parse_cert_pem(&leaf_pem).unwrap()));
    assert!(match_san_dns(&leaf_pem, "issuer.dev.local").unwrap());
    // Leaf key is usable as a signer.
    let signer =
        FileSigner::from_pem_file(leaf_key.to_str().unwrap(), SignatureAlgorithm::Es256).unwrap();
    assert_eq!(signer.sign(b"x").unwrap().len(), 64);
}
