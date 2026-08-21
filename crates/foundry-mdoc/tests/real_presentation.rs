//! Verifies foundry's mdoc parsing against a real wallet's presentation.
//!
//! Every other mdoc test in this workspace round-trips foundry's own builder
//! through its own verifier, which proves only that the two agree with each
//! other. This file is the only one that checks foundry against bytes it did not
//! produce, and it is what four format defects survived the absence of.
//!
//! Trust validation is deliberately out of scope here — the capture's chain is
//! unanchored and expired by design. The **device signature** is in scope, and
//! is the one half of mdoc verification a capture can exercise without PKI; see
//! `tests/fixtures/README.md`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use foundry_core::trust::TrustStore;
use foundry_mdoc::types::{IssuerSignedItem, MobileSecurityObject, tag24_unwrap};
use foundry_mdoc::verifier::{
    decode_device_response, parse_device_response, verify_device_auth, verify_issuer_signed,
};
use sha2::{Digest, Sha256};

const CAPTURE_B64: &str = include_str!("fixtures/av_device_response.b64");
/// The `SessionTranscript` this capture's Device Signature actually covers.
const TRANSCRIPT_HEX: &str = include_str!("fixtures/av_session_transcript.hex");
/// The other Origin's candidate from the same run — a transcript the wallet did
/// **not** sign over.
const OTHER_TRANSCRIPT_HEX: &str = include_str!("fixtures/av_session_transcript_other_origin.hex");
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

/// Decode a captured `SessionTranscript` hex fixture into the `Value` form
/// `verify_device_auth` splices into `DeviceAuthentication`.
fn transcript(hex_fixture: &str) -> ciborium::Value {
    let bytes = hex::decode(hex_fixture.trim()).expect("fixture is hex");
    ciborium::from_reader(bytes.as_slice()).expect("SessionTranscript CBOR")
}

/// The holder key's EC coordinates, read straight out of the MSO's `deviceKey`
/// COSE_Key (labels -2 and -3).
///
/// `verify_issuer_signed` normally supplies these, but it cannot run against
/// this capture — the chain is unanchored and expired. Reading them here is what
/// makes the device-signature test PKI-free. It is not a weaker binding: the
/// coordinates still come from the MSO the issuer signed, byte-identical to the
/// ones the production path would have used.
fn device_key_coords() -> (Vec<u8>, Vec<u8>) {
    let device_key = real_mso().device_key_info.device_key;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    for (label, value) in device_key.as_map().expect("deviceKey is a COSE_Key map") {
        let Some(label) = label.as_integer() else {
            continue;
        };
        if label == ciborium::value::Integer::from(-2) {
            x = value.as_bytes().cloned();
        } else if label == ciborium::value::Integer::from(-3) {
            y = value.as_bytes().cloned();
        }
    }
    (x.expect("deviceKey x"), y.expect("deviceKey y"))
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

    // Ground truth for the `bstr` typing of `random`, against bytes foundry did
    // not produce: a real wallet encodes it as a CBOR byte string (major type 2).
    // foundry emitted an array of integers here until this was pinned — and the
    // defect survived precisely because `ciborium` reads both shapes, so no
    // round-trip assertion could catch it.
    let raw_item: ciborium::Value = ciborium::from_reader(inner).expect("item as Value");
    let raw_random = raw_item
        .as_map()
        .expect("item is a map")
        .iter()
        .find(|(k, _)| k.as_text() == Some("random"))
        .map(|(_, v)| v)
        .expect("random member");
    assert!(
        matches!(raw_random, ciborium::Value::Bytes(_)),
        "a conformant wallet encodes random as a bstr, got {raw_random:?}"
    );

    let expected = &real_mso().value_digests[AV_NAMESPACE][&parsed.digest_id];
    assert_eq!(
        Sha256::digest(&tagged).as_slice(),
        expected.as_slice(),
        "valueDigests commits to the FULL tag-24 encoding"
    );
    assert_ne!(
        Sha256::digest(inner).as_slice(),
        expected.as_slice(),
        "hashing the inner CBOR is what foundry used to do; it must not match"
    );
}

/// Ground truth for the `bstr` typing of `valueDigests`' `Digest`, the sibling of
/// the `random` assertion above.
///
/// Read as an untyped `ciborium::Value` deliberately: `MobileSecurityObject`'s
/// typed field goes through `Bstr`, which accepts a byte string *or* an array on
/// read, so parsing the capture into the typed struct cannot distinguish the two
/// and would prove nothing about what the wallet actually sent.
#[test]
fn the_real_value_digests_are_cbor_byte_strings() {
    let issuer_signed = lookup(&document(), "issuerSigned").clone();
    let payload = issuer_auth_payload(&issuer_signed);
    let wrapper: ciborium::Value = ciborium::from_reader(payload.as_slice()).expect("payload CBOR");
    let mso: ciborium::Value =
        ciborium::from_reader(tag24_unwrap(&wrapper).expect("tag-24 unwraps")).expect("MSO CBOR");

    let digests = lookup(lookup(&mso, "valueDigests"), AV_NAMESPACE)
        .as_map()
        .expect("DigestIDs is a map")
        .clone();
    assert!(
        !digests.is_empty(),
        "the capture must commit to some digests"
    );

    for (digest_id, digest) in &digests {
        let bytes = match digest {
            ciborium::Value::Bytes(b) => b,
            other => panic!(
                "a conformant wallet encodes each Digest as a bstr; digestID {digest_id:?} \
                 is {other:?}"
            ),
        };
        assert_eq!(
            bytes.len(),
            32,
            "digestID {digest_id:?} must be a SHA-256 digest"
        );
    }
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

/// A timestamp inside the capture's MSO validity window (2026-08-13 ..
/// 2027-08-13). Chain validation is reached first, so this does not decide the
/// outcome; it only keeps the scenario honest.
const NOW_INSIDE_MSO_WINDOW: u64 = 1_787_097_600;

/// RFC 9360 §2 (`x5chain`, COSE header label 33) keys the encoding to
/// cardinality: "If a single certificate is conveyed, it is placed in a CBOR
/// byte string." Its CDDL — `COSE_X509 = bstr / [ 2*certs: bstr ]` — puts the
/// array form's lower bound at two, so for exactly one certificate the bare byte
/// string is the encoding the RFC prescribes, not an alternative to an array.
///
/// This wallet uses that form -- the capture's unprotected header is
/// `a1 1821 5902b2 ...`, label 33 followed by a bare 690-byte string. foundry
/// required an array, so `as_array()` returned `None`, the `&&` short-circuited,
/// the header was skipped, and a chain that was *present* was reported as
/// `issuerAuth missing x5c`. Every foundry-built test round-tripped fine because
/// foundry's builder emits the array form -- the same writer/reader blind spot
/// that hid the tag-24 digest defect.
///
/// The assertion is about how FAR verification gets, not that it succeeds. This
/// capture's chain cannot validate here (its root is not a trust anchor and its
/// DS certificate expired 2025-09-17), so reaching the chain check is precisely
/// what proves extraction handed a leaf onward.
#[test]
fn the_real_x5chain_is_a_bare_byte_string_and_is_still_extracted() {
    let bytes = capture();
    let value = decode_device_response(&bytes).expect("the capture decodes");
    let resp = parse_device_response(&value).expect("the capture parses");
    let empty_anchors = TrustStore::from_pems(&[]).expect("an empty trust store builds");

    // `IssuerVerified` is not `Debug`, so `expect_err` is unavailable here.
    let err = match verify_issuer_signed(&resp, &empty_anchors, NOW_INSIDE_MSO_WINDOW) {
        Ok(_) => panic!("the capture's issuer chain must not validate in this workspace"),
        Err(e) => e,
    };
    let rendered = format!("{err:?}");

    assert!(
        !rendered.contains("missing x5c"),
        "the x5chain header IS present, as a bare byte string; reporting it missing \
         means extraction silently skipped it again, got: {rendered}"
    );
    assert!(
        rendered.contains("issuer cert validation"),
        "extraction must succeed and hand a leaf certificate to chain validation, \
         got: {rendered}"
    );
}

/// **The interop proof.** A real wallet's `DeviceSignature`, verified against the
/// `SessionTranscript` foundry itself derived for that transaction.
///
/// Everything else in this workspace proves foundry agrees with foundry. This is
/// the only assertion that a *third-party* wallet and foundry agree on the
/// `DeviceAuthentication` structure — the tag-24 wrapping, the transcript spliced
/// in bare rather than tag-24 wrapped, the `docType`, the byte-preserved
/// `DeviceNameSpacesBytes`, the detached payload in the `Sig_structure`, and the
/// empty `external_aad`. Those facts were previously *derived* from two
/// independent implementations agreeing (design doc §2.1); this makes them
/// **proven**. If any one of them were wrong, ECDSA would reject.
///
/// PKI-free on purpose: `verify_device_auth` takes no trust store, so the
/// capture's unanchored and expired issuer chain (design doc §8) is irrelevant
/// here.
#[test]
fn the_real_device_signature_verifies_over_the_captured_session_transcript() {
    let bytes = capture();
    let value = decode_device_response(&bytes).expect("the capture decodes");
    let resp = parse_device_response(&value).expect("the capture parses");
    let (x, y) = device_key_coords();

    verify_device_auth(&resp, &transcript(TRANSCRIPT_HEX), &x, &y)
        .expect("a real wallet's device signature must verify");
}

/// The transcript is load-bearing, not decorative.
///
/// The same run produced one candidate transcript per configured Origin, and only
/// one of them is the one the wallet signed. Verifying against the other must
/// fail — otherwise the test above would pass for a `DeviceAuthentication`
/// assembly that ignored the transcript entirely, which is exactly the defect
/// design doc §1.5 recorded.
#[test]
fn the_other_origins_candidate_transcript_does_not_verify() {
    let bytes = capture();
    let value = decode_device_response(&bytes).expect("the capture decodes");
    let resp = parse_device_response(&value).expect("the capture parses");
    let (x, y) = device_key_coords();

    let err = verify_device_auth(&resp, &transcript(OTHER_TRANSCRIPT_HEX), &x, &y)
        .expect_err("a transcript the wallet never signed must be rejected");
    assert!(
        format!("{err:?}").contains("device signature invalid"),
        "expected a key-binding failure, got: {err:?}"
    );
}
