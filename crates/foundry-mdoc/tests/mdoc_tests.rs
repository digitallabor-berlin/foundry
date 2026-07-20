use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::trust::TrustStore;
use foundry_mdoc::builder::{build_mdoc, MdocClaims};
use foundry_mdoc::verifier::verify_mdoc;
use foundry_mdoc::FormatError;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();
    (
        root.cert_pem.into_bytes(),
        leaf.cert_pem.into_bytes(),
        leaf.key_pem.into_bytes(),
    )
}

fn encode_der(pem_bytes: &[u8]) -> String {
    std::str::from_utf8(pem_bytes)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

fn device_jwk() -> serde_json::Value {
    let jwk = josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    serde_json::to_value(&jwk).unwrap()
}

#[test]
fn rejects_expired_mdoc() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();

    let now = now_secs();
    // MSO expired 1800s ago; the issuer cert is still valid at `now`, so validate_chain
    // passes and the MSO validity check is what rejects the credential.
    let claims = MdocClaims {
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
        namespaces: BTreeMap::new(),
        device_key_jwk: device_jwk(),
        signed_at: (now - 3600) as i64,
        valid_until: (now - 1800) as i64,
    };
    let mdoc_bytes = build_mdoc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();

    // Expiry is checked before device-signature binding, so an empty device sig is fine.
    let err = verify_mdoc(
        &mdoc_bytes,
        &trust_store,
        Some("client".to_string()),
        Some("uri".to_string()),
        "nonce".to_string(),
        &[],
        now,
    )
    .unwrap_err();
    assert!(matches!(err, FormatError::Expired));
}

#[test]
fn rejects_untrusted_anchor_mdoc() {
    let (_root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    // A DIFFERENT root that did not sign the leaf.
    let other = new_ca("Other Root", 3650).unwrap();
    let trust_store = TrustStore::from_pems(&[other.cert_pem.into_bytes()]).unwrap();

    let now = now_secs();
    let claims = MdocClaims {
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
        namespaces: BTreeMap::new(),
        device_key_jwk: device_jwk(),
        signed_at: (now - 3600) as i64,
        valid_until: (now + 3600) as i64,
    };
    let mdoc_bytes = build_mdoc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();

    let err = verify_mdoc(
        &mdoc_bytes,
        &trust_store,
        Some("client".to_string()),
        Some("uri".to_string()),
        "nonce".to_string(),
        &[],
        now,
    )
    .unwrap_err();
    assert!(matches!(err, FormatError::SignatureVerification(_)));
}
