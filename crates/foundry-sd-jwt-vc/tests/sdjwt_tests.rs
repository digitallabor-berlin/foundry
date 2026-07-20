use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::trust::TrustStore;
use foundry_sd_jwt_vc::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
use foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc;
use foundry_sd_jwt_vc::FormatError;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::{Jwk, KeyPair as _};
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

fn holder() -> (FileSigner, serde_json::Value) {
    let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    let kp = EcKeyPair::from_jwk(&jwk).unwrap();
    let signer = FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let pubjwk = signer.public_jwk().unwrap();
    (signer, pubjwk)
}

fn encode_der(pem_bytes: &[u8]) -> String {
    std::str::from_utf8(pem_bytes)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

fn make_claims(cnf: serde_json::Value, iat: i64, exp: i64) -> IssuerClaims {
    let mut select = serde_json::Map::new();
    select.insert("name".to_string(), serde_json::json!("Bob"));
    IssuerClaims {
        iss: "localhost".to_string(),
        sub: "did:example:bob".to_string(),
        iat,
        exp,
        vct: "vct".to_string(),
        cnf_jwk: cnf,
        status_list_index: None,
        status_list_uri: None,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    }
}

#[test]
fn verifies_selective_claims() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let now = now_secs();
    let claims = make_claims(h_pub, (now - 3600) as i64, (now + 3600) as i64);
    let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce").unwrap();
    let res = verify_sd_jwt_vc(&pres, &trust_store, "aud", "nonce", now).unwrap();
    assert_eq!(res.claims["name"], "Bob");
}

#[test]
fn rejects_expired_sd_jwt() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let now = now_secs();
    // Credential expired 1800s ago; the issuer cert itself is still valid at `now`.
    let claims = make_claims(h_pub, (now - 3600) as i64, (now - 1800) as i64);
    let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce").unwrap();
    let err = verify_sd_jwt_vc(&pres, &trust_store, "aud", "nonce", now).unwrap_err();
    assert!(matches!(err, FormatError::Expired));
}

#[test]
fn rejects_untrusted_anchor() {
    let (_root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    // A DIFFERENT root that did not sign the leaf.
    let other = new_ca("Other Root", 3650).unwrap();
    let trust_store = TrustStore::from_pems(&[other.cert_pem.into_bytes()]).unwrap();
    let (h_signer, h_pub) = holder();

    let now = now_secs();
    let claims = make_claims(h_pub, (now - 3600) as i64, (now + 3600) as i64);
    let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce").unwrap();
    let err = verify_sd_jwt_vc(&pres, &trust_store, "aud", "nonce", now).unwrap_err();
    assert!(matches!(err, FormatError::SignatureVerification(_)));
}

#[test]
fn rejects_kb_audience_mismatch() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let now = now_secs();
    let claims = make_claims(h_pub, (now - 3600) as i64, (now + 3600) as i64);
    let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    // KB-JWT bound to the wrong audience.
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "WRONG_AUD", "nonce").unwrap();
    let err = verify_sd_jwt_vc(&pres, &trust_store, "aud", "nonce", now).unwrap_err();
    assert!(matches!(err, FormatError::KeyBinding(_)));
}

#[test]
fn rejects_tampered_disclosure() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let now = now_secs();
    let claims = make_claims(h_pub, (now - 3600) as i64, (now + 3600) as i64);
    let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce").unwrap();

    // Flip a character in the first disclosure segment. The KB-JWT's sd_hash was
    // computed over the original presentation, so tampering yields a KeyBinding failure.
    let mut segs: Vec<String> = pres.split('~').map(str::to_string).collect();
    let d = &mut segs[1];
    let last = d.pop().unwrap();
    d.push(if last == 'A' { 'B' } else { 'A' });
    let tampered = segs.join("~");

    let err = verify_sd_jwt_vc(&tampered, &trust_store, "aud", "nonce", now).unwrap_err();
    assert!(matches!(err, FormatError::KeyBinding(_)));
}
