use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::trust::TrustStore;
use foundry_sd_jwt_vc::FormatError;
use foundry_sd_jwt_vc::builder::{IssuerClaims, attach_kb_jwt, build_sd_jwt_vc};
use foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc;
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
        sub: None,
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
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce", None).unwrap();
    let res = verify_sd_jwt_vc(&pres, &trust_store, &["aud".to_string()], "nonce", now).unwrap();
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
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce", None).unwrap();
    let err =
        verify_sd_jwt_vc(&pres, &trust_store, &["aud".to_string()], "nonce", now).unwrap_err();
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
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce", None).unwrap();
    let err =
        verify_sd_jwt_vc(&pres, &trust_store, &["aud".to_string()], "nonce", now).unwrap_err();
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
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "WRONG_AUD", "nonce", None).unwrap();
    let err =
        verify_sd_jwt_vc(&pres, &trust_store, &["aud".to_string()], "nonce", now).unwrap_err();
    assert!(matches!(err, FormatError::KeyBinding(_)));
}

/// An audience mismatch must name **both** sides of the comparison it just
/// failed. The bare "KB-JWT audience mismatch" this used to return told an
/// operator only that two values differed, not which two -- diagnosing a real
/// one (a wallet on OpenID4VP draft 24 sending `web-origin:` where 1.0 says
/// `origin:`) required enabling sensitive payload logging at `trace` on a live
/// deployment just to read the `aud` back out of the decrypted `vp_token`.
///
/// Both values are public identifiers -- an Origin or a Client Identifier --
/// so neither is on root AGENTS.md §4.5's never-log list.
#[test]
fn kb_audience_mismatch_names_both_the_presented_and_the_expected_audiences() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let now = now_secs();
    let claims = make_claims(h_pub, (now - 3600) as i64, (now + 3600) as i64);
    let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(
        issuer_pres,
        &h_signer,
        "web-origin:https://presented.example",
        "nonce",
        None,
    )
    .unwrap();

    let err = verify_sd_jwt_vc(
        &pres,
        &trust_store,
        &[
            "origin:https://expected-a.example".to_string(),
            "origin:https://expected-b.example".to_string(),
        ],
        "nonce",
        now,
    )
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("web-origin:https://presented.example"),
        "the message must name what the wallet actually presented: {msg}"
    );
    assert!(
        msg.contains("origin:https://expected-a.example")
            && msg.contains("origin:https://expected-b.example"),
        "the message must name every audience that would have been accepted: {msg}"
    );
}

/// The presented `aud` is wallet-controlled and reaches both a log record and
/// an HTTP error body, so it must not be interpolated raw: a newline in it
/// would let a caller forge log lines. Debug-formatting escapes it.
#[test]
fn kb_audience_mismatch_escapes_a_wallet_controlled_audience() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let now = now_secs();
    let claims = make_claims(h_pub, (now - 3600) as i64, (now + 3600) as i64);
    let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(
        issuer_pres,
        &h_signer,
        "origin:https://x.example\nERROR forged log line",
        "nonce",
        None,
    )
    .unwrap();

    let err = verify_sd_jwt_vc(
        &pres,
        &trust_store,
        &["origin:https://y.example".to_string()],
        "nonce",
        now,
    )
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        !msg.contains('\n'),
        "a newline in the presented audience must be escaped, not emitted raw: {msg:?}"
    );
    assert!(
        msg.contains("\\n"),
        "the newline should survive as an escape sequence so the value stays readable: {msg:?}"
    );
}

/// A deployment may configure many Origins, and the accepted-audience list is
/// doubled when the draft-24 `web-origin:` accommodation is on. The message
/// bounds how many it names so the presented value -- the part an operator
/// actually needs -- is never the part that gets truncated away downstream.
#[test]
fn kb_audience_mismatch_bounds_a_long_expected_audience_list() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let now = now_secs();
    let claims = make_claims(h_pub, (now - 3600) as i64, (now + 3600) as i64);
    let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(
        issuer_pres,
        &h_signer,
        "origin:https://nope.example",
        "nonce",
        None,
    )
    .unwrap();

    let expected: Vec<String> = (0..20)
        .map(|i| format!("origin:https://site-{i}.example"))
        .collect();
    let err = verify_sd_jwt_vc(&pres, &trust_store, &expected, "nonce", now).unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("origin:https://nope.example"),
        "the presented audience must survive the bound: {msg}"
    );
    assert!(
        msg.contains("more"),
        "a truncated expected list must say so rather than silently omit: {msg}"
    );
    assert!(
        !msg.contains("origin:https://site-19.example"),
        "the list must actually be bounded: {msg}"
    );
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
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce", None).unwrap();

    // Flip a character in the first disclosure segment. The KB-JWT's sd_hash was
    // computed over the original presentation, so tampering yields a KeyBinding failure.
    let mut segs: Vec<String> = pres.split('~').map(str::to_string).collect();
    let d = &mut segs[1];
    let last = d.pop().unwrap();
    d.push(if last == 'A' { 'B' } else { 'A' });
    let tampered = segs.join("~");

    let err =
        verify_sd_jwt_vc(&tampered, &trust_store, &["aud".to_string()], "nonce", now).unwrap_err();
    assert!(matches!(err, FormatError::KeyBinding(_)));
}
