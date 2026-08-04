//! Android Key Attestation extension parsing.
//!
//! Design: docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md
//!
//! An integration test rather than a unit test in `src/`: most cases load the
//! real Android chain from `tests/fixtures/android-attestation/`.

use foundry_core::error::TrustError;
use foundry_core::trust::android_attestation::{
    decode_key_description, find_attestation_cert, parse_key_description, SecurityLevel,
    VerifiedBootState,
};
use foundry_core::trust::parse_cert_pem;

const LEAF: &[u8] = include_bytes!("fixtures/android-attestation/leaf.pem");
const INT_P256: &[u8] = include_bytes!("fixtures/android-attestation/intermediate-tee-p256.pem");
const INT_P384: &[u8] = include_bytes!("fixtures/android-attestation/intermediate-tee-p384.pem");
const ROOT: &[u8] = include_bytes!("fixtures/android-attestation/root-rsa4096.pem");

/// The real Google chain, leaf-first, as the vendor profile transmits it.
fn real_chain() -> Vec<x509_cert::Certificate> {
    [LEAF, INT_P256, INT_P384, ROOT]
        .iter()
        .map(|pem| parse_cert_pem(pem).expect("fixture parses"))
        .collect()
}

// --- minimal DER encoder for synthetic KeyDescriptions ---------------------
//
// Deliberately duplicated in `crates/foundry-issuer/src/keystore_proof.rs`'s
// test module, which needs whole chains rather than single structures. The
// design doc records why a public encoder in foundry-core was rejected: it
// would be production-shaped code no production path calls.

fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn integer(v: i64) -> Vec<u8> {
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    tlv(&[0x02], &bytes)
}

fn enumerated(v: u8) -> Vec<u8> {
    tlv(&[0x0a], &[v])
}

fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(&[0x04], bytes)
}

fn boolean(v: bool) -> Vec<u8> {
    tlv(&[0x01], &[if v { 0xff } else { 0x00 }])
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &parts.concat())
}

/// Constructed context-specific tag, using X.690 §8.1.2.4 multi-byte form when
/// the number exceeds 30 — which every Keymaster tag above `ecCurve` does.
fn ctx(number: u32, inner: &[u8]) -> Vec<u8> {
    let mut tag: Vec<u8> = Vec::new();
    if number <= 30 {
        tag.push(0xa0 | (number as u8));
    } else {
        tag.push(0xbf);
        let mut septets = Vec::new();
        let mut n = number;
        while n > 0 {
            septets.push((n & 0x7f) as u8);
            n >>= 7;
        }
        septets.reverse();
        let last = septets.len() - 1;
        for (i, s) in septets.iter().enumerate() {
            tag.push(if i == last { *s } else { *s | 0x80 });
        }
    }
    tlv(&tag, inner)
}

fn key_description(
    version: i64,
    attestation_level: u8,
    key_mint_level: u8,
    challenge: &[u8],
    hardware_entries: &[Vec<u8>],
) -> Vec<u8> {
    sequence(&[
        integer(version),
        enumerated(attestation_level),
        integer(41),
        enumerated(key_mint_level),
        octet_string(challenge),
        octet_string(&[]),
        sequence(&[]),
        sequence(hardware_entries),
    ])
}

// --- tests ----------------------------------------------------------------

#[test]
fn real_fixture_leaf_parses_to_the_expected_key_description() {
    let leaf = parse_cert_pem(LEAF).expect("fixture parses");
    let kd = parse_key_description(&leaf)
        .expect("extension parses")
        .expect("the real Android leaf carries the attestation extension");

    assert_eq!(kd.attestation_version, 3);
    assert_eq!(
        kd.attestation_security_level,
        SecurityLevel::TrustedEnvironment
    );
    assert_eq!(kd.key_mint_version, 41);
    assert_eq!(
        kd.key_mint_security_level,
        SecurityLevel::TrustedEnvironment
    );
    // The challenge holds the UTF-8 bytes of the c_nonce string Google's issuer
    // minted, not raw nonce bytes -- the finding the whole binding rests on.
    assert_eq!(
        kd.attestation_challenge,
        b"MHMvK0dES1B1N3JwdlFoUjZCRG5QVFZjRTM1bXNYOHR2Ky9HTEpLbEdVST0=".to_vec()
    );
    assert!(kd.unique_id.is_empty());
}

#[test]
fn real_fixture_hardware_enforced_root_of_trust_decodes() {
    let leaf = parse_cert_pem(LEAF).expect("fixture parses");
    let kd = parse_key_description(&leaf)
        .expect("parses")
        .expect("present");
    let rot = kd
        .hardware_enforced
        .root_of_trust
        .expect("the real fixture carries rootOfTrust in hardwareEnforced");
    // Readable but deliberately unenforced: the deferred device-integrity
    // policy follow-on consumes exactly these two fields.
    assert!(rot.device_locked);
    assert_eq!(rot.verified_boot_state, VerifiedBootState::Verified);
}

#[test]
fn certificate_without_the_extension_yields_none() {
    let ca = foundry_core::pki::new_ca("No Attestation Extension CA", 365).expect("generate CA");
    let cert = parse_cert_pem(ca.cert_pem.as_bytes()).expect("parses");
    assert!(parse_key_description(&cert).expect("no error").is_none());
}

#[test]
fn truncated_extension_content_is_rejected_without_panicking() {
    let full = key_description(3, 1, 1, b"nonce", &[]);
    // Every proper prefix must be a clean error, never a panic: the cheap
    // stand-in for fuzzing an ASN.1 parser fed attacker-controlled bytes.
    for cut in 0..full.len() {
        assert!(
            decode_key_description(&full[..cut]).is_err(),
            "prefix of {cut} bytes must not parse"
        );
    }
    assert!(
        decode_key_description(&full).is_ok(),
        "the whole structure parses"
    );
}

#[test]
fn security_level_outside_the_enumeration_is_a_parse_error() {
    let der = key_description(3, 7, 1, b"nonce", &[]);
    let err = decode_key_description(&der).expect_err("level 7 must not parse");
    assert!(matches!(err, TrustError::Parse(_)), "got {err:?}");
}

#[test]
fn strongbox_and_software_levels_decode_and_order() {
    let sb = decode_key_description(&key_description(300, 2, 2, b"n", &[])).expect("parses");
    assert_eq!(sb.attestation_security_level, SecurityLevel::StrongBox);
    let sw = decode_key_description(&key_description(1, 0, 0, b"n", &[])).expect("parses");
    assert_eq!(sw.key_mint_security_level, SecurityLevel::Software);
    assert!(SecurityLevel::Software < SecurityLevel::TrustedEnvironment);
    assert!(SecurityLevel::TrustedEnvironment < SecurityLevel::StrongBox);
}

#[test]
fn unknown_authorization_list_tags_are_skipped_not_rejected() {
    // 719 (bootPatchLevel) and 720 (deviceUniqueAttestation) are outside the
    // decoded set; a future KeyMint tag must behave the same way.
    let entries = vec![
        ctx(503, &tlv(&[0x05], &[])),
        ctx(719, &integer(20240905)),
        ctx(720, &tlv(&[0x05], &[])),
    ];
    let kd = decode_key_description(&key_description(400, 1, 1, b"n", &entries)).expect("parses");
    assert!(kd.hardware_enforced.no_auth_required);
    assert_eq!(kd.hardware_enforced.os_patch_level, None);
}

#[test]
fn authorization_list_decodes_the_documented_tag_set() {
    let entries = vec![
        ctx(1, &tlv(&[0x31], &[integer(2), integer(3)].concat())),
        ctx(2, &integer(3)),
        ctx(3, &integer(256)),
        ctx(10, &integer(1)),
        ctx(504, &integer(2)),
        ctx(701, &integer(1700000000000)),
        ctx(702, &integer(0)),
        ctx(
            704,
            &sequence(&[
                octet_string(&[0xaa; 32]),
                boolean(true),
                enumerated(0),
                octet_string(&[0xbb; 32]),
            ]),
        ),
        ctx(705, &integer(140000)),
        ctx(706, &integer(202409)),
    ];
    let kd = decode_key_description(&key_description(300, 1, 1, b"n", &entries)).expect("parses");
    let al = kd.hardware_enforced;
    assert_eq!(al.purpose, vec![2, 3]);
    assert_eq!(al.algorithm, Some(3));
    assert_eq!(al.key_size, Some(256));
    assert_eq!(al.ec_curve, Some(1));
    assert_eq!(al.user_auth_type, Some(2));
    assert_eq!(al.creation_date_time, Some(1700000000000));
    assert_eq!(al.origin, Some(0));
    assert_eq!(al.os_version, Some(140000));
    assert_eq!(al.os_patch_level, Some(202409));
    assert!(!al.no_auth_required);
    let rot = al.root_of_trust.expect("rootOfTrust decoded");
    assert_eq!(rot.verified_boot_key, vec![0xaa; 32]);
    assert!(rot.device_locked);
    assert_eq!(rot.verified_boot_state, VerifiedBootState::Verified);
    assert_eq!(rot.verified_boot_hash, vec![0xbb; 32]);
}

#[test]
fn find_attestation_cert_returns_the_leaf_of_the_real_chain() {
    let chain = real_chain();
    let (idx, kd) = find_attestation_cert(&chain).expect("the real chain carries an extension");
    assert_eq!(idx, 0);
    assert_eq!(kd.attestation_version, 3);
}

#[test]
fn a_chain_with_no_extension_anywhere_is_an_error() {
    let ca = foundry_core::pki::new_ca("Plain CA", 365).expect("generate CA");
    let chain = vec![parse_cert_pem(ca.cert_pem.as_bytes()).expect("parses")];
    assert!(find_attestation_cert(&chain).is_err());
}
