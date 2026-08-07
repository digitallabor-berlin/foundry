//! Behavioural tests for cryptographic X.509 chain verification.
//!
//! Design: docs/superpowers/specs/2026-08-04-trust-chain-signature-verification-design.md
//!
//! These are integration tests (not unit tests in `src/trust/mod.rs`) because
//! several of them load PEM fixtures from `tests/fixtures/`.

use foundry_core::error::TrustError;
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::trust::{TrustStore, validate_chain};

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

/// A real Android Keystore attestation chain, captured from Google Wallet.
///
/// Structure (verified with `openssl verify`):
///   leaf            CN=Android Keystore Key   EC P-256, sig ecdsa-with-SHA256
///   intermediate-1  title=TEE, serial=58eb..  EC P-256, sig ecdsa-with-SHA256
///   intermediate-2  title=TEE, serial=3fb6..  EC P-384, sig sha256WithRSAEncryption
///   root            serial=f92009e853b6b045   RSA 4096, self-signed
///
/// Note intermediate-1 carries a P-256 key but is signed by intermediate-2's
/// P-384 key using SHA-256 -- the digest is not derivable from the key curve.
const ANDROID_LEAF: &[u8] = include_bytes!("fixtures/android-attestation/leaf.pem");
const ANDROID_INT_P256: &[u8] =
    include_bytes!("fixtures/android-attestation/intermediate-tee-p256.pem");
const ANDROID_INT_P384: &[u8] =
    include_bytes!("fixtures/android-attestation/intermediate-tee-p384.pem");
const ANDROID_ROOT: &[u8] = include_bytes!("fixtures/android-attestation/root-rsa4096.pem");

/// 2026-01-01T00:00:00Z. Pinned so the fixture assertions cannot rot: both TEE
/// intermediates are valid 2022-03-20 -> 2032-03-17.
const ANDROID_PINNED_NOW: u64 = 1_767_225_600;

/// The chain exactly as Google transmits it: leaf first, root included last.
fn android_presented_intermediates() -> Vec<Vec<u8>> {
    vec![
        ANDROID_INT_P256.to_vec(),
        ANDROID_INT_P384.to_vec(),
        ANDROID_ROOT.to_vec(),
    ]
}

#[test]
fn real_android_attestation_chain_validates_against_the_configured_google_root() {
    let store = TrustStore::from_pems(&[ANDROID_ROOT.to_vec()]).expect("build store");
    validate_chain(
        ANDROID_LEAF,
        &android_presented_intermediates(),
        &store,
        ANDROID_PINNED_NOW,
    )
    .expect("the real Android attestation chain must validate");
}

#[test]
fn presented_android_root_grants_nothing_without_a_configured_anchor() {
    // The full chain is presented, root included -- but the only configured
    // anchor is unrelated. Trust must not be bootstrappable from a certificate
    // the caller supplied.
    let unrelated = new_ca("Unrelated Root CA", 3650).expect("generate unrelated CA");
    let store = TrustStore::from_pems(&[unrelated.cert_pem.into_bytes()]).expect("store");

    let err = validate_chain(
        ANDROID_LEAF,
        &android_presented_intermediates(),
        &store,
        ANDROID_PINNED_NOW,
    )
    .expect_err("a presented root must not establish trust");
    assert!(
        matches!(err, TrustError::UntrustedChain),
        "expected UntrustedChain, got {err:?}"
    );
}

#[test]
fn android_chain_is_rejected_outside_the_intermediate_validity_window() {
    // 2035-01-01T00:00:00Z -- past both TEE intermediates' 2032 notAfter,
    // though still inside the leaf's absurd 2106 window. Proves the whole path
    // is time-checked, not just the leaf.
    const AFTER_INTERMEDIATES_EXPIRE: u64 = 2_051_222_400;
    let store = TrustStore::from_pems(&[ANDROID_ROOT.to_vec()]).expect("build store");
    let err = validate_chain(
        ANDROID_LEAF,
        &android_presented_intermediates(),
        &store,
        AFTER_INTERMEDIATES_EXPIRE,
    )
    .expect_err("an expired intermediate must be rejected");
    assert!(
        matches!(err, TrustError::Expired),
        "expected Expired, got {err:?}"
    );
}

#[test]
fn a_non_ca_certificate_cannot_act_as_an_intermediate() {
    // `issue_leaf` emits IsCa::NoCa with keyUsage: DigitalSignature only. Using
    // it to sign another certificate is the privilege escalation that DN-only
    // path building permitted: any holder of a chained leaf could mint leaves.
    let root = new_ca("Escalation Test Root CA", 3650).expect("generate root");
    let non_ca = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "notaca.test.local",
        &["notaca.test.local".to_string()],
        3650,
    )
    .expect("issue non-CA certificate");

    let forged = issue_leaf(
        &non_ca.cert_pem,
        &non_ca.key_pem,
        "escalated.test.local",
        &["escalated.test.local".to_string()],
        365,
    )
    .expect("issue leaf under the non-CA certificate");

    let store = TrustStore::from_pems(&[root.cert_pem.clone().into_bytes()]).expect("store");

    let err = validate_chain(
        forged.cert_pem.as_bytes(),
        &[non_ca.cert_pem.clone().into_bytes()],
        &store,
        now_secs(),
    )
    .expect_err("a chain through a non-CA certificate must be rejected");
    assert!(
        matches!(err, TrustError::UntrustedChain),
        "expected UntrustedChain, got {err:?}"
    );

    // Positive control: a leaf signed directly by the real CA validates against
    // the same store. Without this, the rejection above could be caused by
    // anything.
    let legitimate = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "legit.test.local",
        &["legit.test.local".to_string()],
        365,
    )
    .expect("issue legitimate leaf");
    validate_chain(legitimate.cert_pem.as_bytes(), &[], &store, now_secs())
        .expect("a leaf signed by the real CA must validate");
}

#[test]
fn an_intermediate_pinned_as_the_anchor_validates_the_leaf() {
    // foundry has always allowed a configured anchor to be a non-self-signed
    // certificate. This is what X509VerifyFlags::PARTIAL_CHAIN buys; without it
    // OpenSSL insists on reaching a self-signed root and this test fails.
    //
    // The real Android chain provides a ready-made three-level path: pin the
    // P-384 TEE intermediate as the sole anchor and present only the P-256 one.
    let store = TrustStore::from_pems(&[ANDROID_INT_P384.to_vec()]).expect("store");
    validate_chain(
        ANDROID_LEAF,
        &[ANDROID_INT_P256.to_vec()],
        &store,
        ANDROID_PINNED_NOW,
    )
    .expect("an intermediate pinned as the anchor must validate the leaf");
}

/// Build a self-signed CA and a leaf it signs, both keyed on `alg`.
///
/// Driven through `rcgen` directly rather than `foundry_core::pki`, because
/// `pki::new_ca`/`issue_leaf` call `KeyPair::generate()`, which is hardcoded to
/// `PKCS_ECDSA_P256_SHA256`. Returns `(ca_pem, leaf_pem)`.
fn ca_and_leaf_on(alg: &'static rcgen::SignatureAlgorithm, cn: &str) -> (String, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use time::{Duration, OffsetDateTime};

    let now = OffsetDateTime::now_utc();

    let ca_key = KeyPair::generate_for(alg).expect("generate CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, format!("{cn} Root CA"));
    ca_params.distinguished_name = ca_dn;
    ca_params.not_before = now - Duration::days(1);
    ca_params.not_after = now + Duration::days(3650);
    let ca_pem = ca_params.self_signed(&ca_key).expect("self-sign CA").pem();

    // `Issuer::from_ca_cert_pem` takes the signing key by value.
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).expect("build issuer");
    let leaf_key = KeyPair::generate_for(alg).expect("generate leaf key");
    let mut leaf_params = CertificateParams::new(vec![cn.to_string()]).expect("leaf params");
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, cn);
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - Duration::days(1);
    leaf_params.not_after = now + Duration::days(365);
    let leaf_pem = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign leaf")
        .pem();

    (ca_pem, leaf_pem)
}

#[test]
fn chains_on_p256_and_p384_validate() {
    // P-521 is intentionally absent: rcgen's PKCS_ECDSA_P521_SHA512 requires the
    // aws_lc_rs backend and foundry builds rcgen with default features (ring).
    // OpenSSL verifies P-521 natively, so this is a fixture limitation only.
    for (label, alg) in [
        ("p256", &rcgen::PKCS_ECDSA_P256_SHA256),
        ("p384", &rcgen::PKCS_ECDSA_P384_SHA384),
    ] {
        let cn = format!("{label}.curve.test.local");
        let (ca_pem, leaf_pem) = ca_and_leaf_on(alg, &cn);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()])
            .unwrap_or_else(|e| panic!("build store for {label}: {e}"));
        validate_chain(leaf_pem.as_bytes(), &[], &store, now_secs())
            .unwrap_or_else(|e| panic!("{label} chain must validate: {e}"));
    }
}
