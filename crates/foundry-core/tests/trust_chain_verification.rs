//! Behavioural tests for cryptographic X.509 chain verification.
//!
//! Design: docs/superpowers/specs/2026-08-04-trust-chain-signature-verification-design.md
//!
//! These are integration tests (not unit tests in `src/trust/mod.rs`) because
//! several of them load PEM fixtures from `tests/fixtures/`.

use foundry_core::error::TrustError;
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::trust::{validate_chain, TrustStore};

/// Wall-clock now, for chains generated during the test run.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

/// Re-encode `pem` with one byte of the subject Common Name flipped.
///
/// The mutation is inside `tbsCertificate` and is length-preserving, so the DER
/// still parses; only the issuer's signature over the body no longer matches.
/// This is what makes the expected error specifically `InvalidSignature` rather
/// than a path-building failure.
fn corrupt_subject_cn(pem: &[u8], cn: &str) -> Vec<u8> {
    let cert = openssl::x509::X509::from_pem(pem).expect("fixture parses");
    let mut der = cert.to_der().expect("cert re-encodes to DER");
    let needle = cn.as_bytes();
    let pos = der
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the Common Name must appear verbatim in the DER");
    // Flip one character of the CN, preserving length.
    der[pos] = if der[pos] == b'z' { b'y' } else { b'z' };
    openssl::x509::X509::from_der(&der)
        .expect("mutated DER still parses")
        .to_pem()
        .expect("mutated cert re-encodes to PEM")
}

#[test]
fn tampered_certificate_body_is_rejected_as_invalid_signature() {
    let ca = new_ca("Foundry Test Root CA", 3650).expect("generate CA");
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "zzz.test.local",
        &["zzz.test.local".to_string()],
        365,
    )
    .expect("issue leaf");
    let store = TrustStore::from_pems(&[ca.cert_pem.clone().into_bytes()]).expect("build store");

    // Positive control: the untouched chain must validate. Without this, a
    // rejection below would prove only that *something* is broken.
    validate_chain(leaf.cert_pem.as_bytes(), &[], &store, now_secs())
        .expect("the genuine chain must validate");

    let tampered = corrupt_subject_cn(leaf.cert_pem.as_bytes(), "zzz.test.local");
    let err = validate_chain(&tampered, &[], &store, now_secs())
        .expect_err("a tampered certificate body must be rejected");
    assert!(
        matches!(err, TrustError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn leaf_signed_by_an_impostor_ca_with_an_identical_dn_is_rejected() {
    // This is the vulnerability this work closes. Two CAs share a Distinguished
    // Name but hold different keys. The pre-change `validate_chain` walked DN
    // strings only, so impersonating an anchor required nothing but spelling
    // its DN correctly.
    let genuine = new_ca("Foundry Dev Root CA", 3650).expect("generate genuine CA");
    let impostor = new_ca("Foundry Dev Root CA", 3650).expect("generate impostor CA");

    let forged = issue_leaf(
        &impostor.cert_pem,
        &impostor.key_pem,
        "forged.test.local",
        &["forged.test.local".to_string()],
        365,
    )
    .expect("issue forged leaf");

    let store = TrustStore::from_pems(&[genuine.cert_pem.clone().into_bytes()]).expect("store");

    let err = validate_chain(forged.cert_pem.as_bytes(), &[], &store, now_secs())
        .expect_err("a leaf signed by an impostor CA must be rejected");
    // `issue_leaf` sets an Authority Key Identifier, so OpenSSL cannot even
    // select the genuine CA as a candidate issuer; the failure surfaces as a
    // path-building error rather than a signature error. Either is a correct
    // rejection.
    assert!(
        matches!(
            err,
            TrustError::UntrustedChain | TrustError::InvalidSignature
        ),
        "expected UntrustedChain or InvalidSignature, got {err:?}"
    );

    // Positive control: a leaf genuinely signed by the trusted CA validates.
    let good = issue_leaf(
        &genuine.cert_pem,
        &genuine.key_pem,
        "good.test.local",
        &["good.test.local".to_string()],
        365,
    )
    .expect("issue genuine leaf");
    validate_chain(good.cert_pem.as_bytes(), &[], &store, now_secs())
        .expect("a genuinely signed leaf must validate");
}
