//! Verifies foundry's mdoc parsing against a real wallet's presentation.
//!
//! Every other mdoc test in this workspace round-trips foundry's own builder
//! through its own verifier, which proves only that the two agree with each
//! other. This file is the only one that checks foundry against bytes it did not
//! produce, and it is what four format defects survived the absence of.
//!
//! Trust validation and the device signature are both deliberately out of scope
//! here — see `tests/fixtures/README.md`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use foundry_mdoc::types::{IssuerSignedItem, MobileSecurityObject, tag24_unwrap};
use sha2::{Digest, Sha256};

const CAPTURE_B64: &str = include_str!("fixtures/av_device_response.b64");
const AV_NAMESPACE: &str = "eu.europa.ec.av.1";

fn capture() -> Vec<u8> {
    B64URL
        .decode(CAPTURE_B64.trim())
        .expect("fixture is base64url")
}

fn lookup<'a>(value: &'a ciborium::Value, key: &str) -> &'a ciborium::Value {
    value
        .as_map()
        .expect("map")
        .iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == key))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("missing {key}"))
}

fn device_response() -> ciborium::Value {
    ciborium::from_reader(capture().as_slice()).expect("DeviceResponse CBOR")
}

fn document() -> ciborium::Value {
    let dr = device_response();
    lookup(&dr, "documents").as_array().expect("documents")[0].clone()
}

/// Re-encode a `Value` to CBOR bytes.
fn encode(value: &ciborium::Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("re-encodes");
    bytes
}

/// The `MobileSecurityObject` the wallet's issuer actually signed.
fn real_mso() -> MobileSecurityObject {
    let issuer_signed = lookup(&document(), "issuerSigned").clone();
    let payload = issuer_auth_payload(&issuer_signed);
    let wrapper: ciborium::Value = ciborium::from_reader(payload.as_slice()).expect("payload CBOR");
    ciborium::from_reader(tag24_unwrap(&wrapper).expect("tag-24 unwraps")).expect("real MSO parses")
}

fn issuer_auth_payload(issuer_signed: &ciborium::Value) -> Vec<u8> {
    let issuer_auth = lookup(issuer_signed, "issuerAuth");
    <coset::CoseSign1 as coset::CborSerializable>::from_slice(&encode(issuer_auth))
        .expect("issuerAuth is a COSE_Sign1")
        .payload
        .expect("IssuerAuth payload")
}

#[test]
fn the_capture_has_the_shape_openid4vp_requires() {
    let dr = device_response();
    assert_eq!(
        lookup(&dr, "version").as_text(),
        Some("1.0"),
        "DeviceResponse.version"
    );
    assert_eq!(
        lookup(&dr, "status").as_integer(),
        Some(0.into()),
        "DeviceResponse.status must be 0"
    );
    assert_eq!(
        lookup(&dr, "documents")
            .as_array()
            .expect("documents")
            .len(),
        1,
        "one document per DeviceResponse"
    );
    assert_eq!(lookup(&document(), "docType").as_text(), Some(AV_NAMESPACE));
}

#[test]
fn the_real_mso_parses_after_tag24_unwrapping() {
    let issuer_signed = lookup(&document(), "issuerSigned").clone();
    let payload = issuer_auth_payload(&issuer_signed);

    // Defect 3: this is tag-24, so a direct struct parse cannot work. foundry used
    // to attempt one and failed with "invalid type: bytes, expected map".
    assert_eq!(&payload[..2], &[0xd8, 0x18], "payload is tag-24");

    let mso = real_mso();
    assert_eq!(mso.version, "1.0");
    assert_eq!(mso.digest_algorithm, "SHA-256");
    assert_eq!(mso.doc_type, AV_NAMESPACE);

    // Task 4: tag-0 tdate values, and `validFrom` is present — a member foundry
    // did not model at all until this change.
    assert_eq!(mso.validity_info.signed.0, "2026-08-13T00:00:00Z");
    assert_eq!(mso.validity_info.valid_from.0, "2026-08-13T00:00:00Z");
    assert_eq!(mso.validity_info.valid_until.0, "2027-08-13T00:00:00Z");

    // Six digests committed, one element disclosed — ordinary selective disclosure.
    assert_eq!(
        mso.value_digests[AV_NAMESPACE].len(),
        6,
        "valueDigests commits to every element, disclosed or not"
    );
}

/// The proof behind defect 4, against bytes foundry did not produce.
#[test]
fn the_real_element_digest_matches_the_full_tag24_encoding() {
    let issuer_signed = lookup(&document(), "issuerSigned").clone();
    let namespaces = lookup(&issuer_signed, "nameSpaces");
    let items = lookup(namespaces, AV_NAMESPACE).as_array().expect("items");
    assert_eq!(items.len(), 1, "one element disclosed");

    let item = &items[0];
    let tagged = encode(item);
    let inner = tag24_unwrap(item).expect("item is tag-24");

    let parsed: IssuerSignedItem = ciborium::from_reader(inner).expect("IssuerSignedItem");
    assert_eq!(parsed.element_identifier, "age_over_18");
    assert_eq!(parsed.element_value, ciborium::Value::Bool(true));

    let expected = &real_mso().value_digests[AV_NAMESPACE][&parsed.digest_id];
    assert_eq!(
        Sha256::digest(&tagged).to_vec(),
        *expected,
        "valueDigests commits to the FULL tag-24 encoding"
    );
    assert_ne!(
        Sha256::digest(inner).to_vec(),
        *expected,
        "hashing the inner CBOR is what foundry used to do; it must not match"
    );
}

/// Re-encoding a decoded `ciborium::Value` must reproduce the wallet's exact
/// bytes.
///
/// Both the verifier's digest check and `DeviceAuthentication` assembly re-encode
/// values decoded from the wire rather than slicing the original buffer. That is
/// only sound while the wallet's encoding is canonical. If a wallet ever ships
/// non-canonical CBOR — an oversized length header, say — this assumption breaks
/// silently and every digest stops matching, so it is asserted explicitly here
/// rather than left implicit in the tests above.
#[test]
fn re_encoding_the_capture_is_byte_identical() {
    let original = capture();
    assert_eq!(
        encode(&device_response()),
        original,
        "the wallet's CBOR must survive a decode/re-encode round trip unchanged"
    );
}
