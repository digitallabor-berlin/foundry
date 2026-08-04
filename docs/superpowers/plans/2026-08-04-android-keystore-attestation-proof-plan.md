# `android_keystore_attestation` Proof Type Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accept Google Wallet's `android_keystore_attestation` proof type — arrays of X.509 certificate chains carrying Android Keystore attestations — as an opt-in second proof type at the Credential Endpoint, binding each attested hardware key to a foundry-minted `c_nonce` and to a configured minimum hardware security level.

**Architecture:** A pure-parsing module in `foundry-core` (`trust/android_attestation.rs`) decodes the `1.3.6.1.4.1.11129.2.1.17` `KeyDescription` extension. A module in `foundry-issuer` (`keystore_proof.rs`) applies protocol binding and policy on top of it, reusing `validate_chain`, `verify_nonce` and `cert_ec_public_coords`, and returns the existing `VerifiedProof`. `ProofsRequest` becomes a two-member structure enforcing OpenID4VCI's "exactly one proof type" rule. Everything is off by default.

**Tech Stack:** Rust; `x509-cert` 0.3 / `der` 0.8 (DER decoding); OpenSSL via `foundry_core::trust::validate_chain` (chain verification); `josekit` (JWK); `rcgen` 0.14 (synthetic test chains); `axum` + `tower` (integration tests).

**Design:** `docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md` — read it before Task 1. Its "Deviations and known limitations" section is implemented as documentation in Task 7 and must not be silently dropped.

## Global Constraints

- **Read the crate's `AGENTS.md` before touching files in it.** Root `AGENTS.md`, then `crates/foundry-core/AGENTS.md` (Tasks 1–2), `crates/foundry-issuer/AGENTS.md` (Tasks 3–5), `crates/foundry/AGENTS.md` + `crates/foundry/tests/AGENTS.md` (Task 6).
- **No `.unwrap()`, `.expect()`, `panic!()`, `unreachable!()`, or panicking indexing in non-test code** (root §4.1). This code parses attacker-controlled DER; every length and tag read returns a typed error.
- **Every `#[tracing::instrument]` carries `skip_all`** (root §4.5). Fields are opt-in.
- **Never log** the `attestationChallenge` (it is a `c_nonce`), the `uniqueId`, or raw certificates. Public keys appear only as RFC 7638 thumbprints via `foundry_core::obs::thumbprint`.
- **Scoped verification gate only** (root §5.1): `cargo test -p <crate>` for each crate touched plus affected dependents, `cargo clippy -p <crate> --all-targets -- -D warnings`, `cargo fmt --check`. **Never run `cargo test --workspace`** — the full gate of §5.3 runs once at the end of the branch.
- **Cite sources in comments.** Protocol behaviour cites the pinned spec `docs/specs/openid-4-verifiable-credential-issuance-1_0.md` by line (L852, L862, L1395, L2612). Behaviour justified only by Google's documentation names the vendor profile `docs/specs/google-wallet-openid4vci-profile.md` (root §4.4).
- **Exact OID:** `1.3.6.1.4.1.11129.2.1.17`.
- **Security-level ordering:** `Software(0) < TrustedEnvironment(1) < StrongBox(2)`. Default minimum `TrustedEnvironment`.
- **Default posture:** `issuer.key_attestation.android.mode` defaults to `Disabled`; no existing deployment changes behaviour.
- Commit after every task, prefix `feat:` / `test:` / `docs:`.

---

### Task 1: `KeyDescription` extension parser in `foundry-core`

**Files:**
- Create: `crates/foundry-core/src/trust/android_attestation.rs`
- Modify: `crates/foundry-core/src/trust/mod.rs` (module declaration)
- Create: `crates/foundry-core/tests/android_attestation.rs`

**Interfaces:**
- Consumes: `crate::error::TrustError`; `x509_cert::Certificate`; `x509_cert::der::{asn1::AnyRef, oid::ObjectIdentifier, Reader, SliceReader, Tag, Tagged}`; fixtures at `crates/foundry-core/tests/fixtures/android-attestation/{leaf,intermediate-tee-p256,intermediate-tee-p384,root-rsa4096}.pem`.
- Produces, for Tasks 2, 3, 6 (module path `foundry_core::trust::android_attestation`):
  - `SecurityLevel` — `enum { Software, TrustedEnvironment, StrongBox }`, `Copy + PartialEq + Eq + PartialOrd + Ord + Deserialize`, plus `pub fn as_str(self) -> &'static str` returning `"Software" | "TrustedEnvironment" | "StrongBox"`.
  - `VerifiedBootState` — `enum { Verified, SelfSigned, Unverified, Failed }`, `Copy + PartialEq + Eq`.
  - `RootOfTrust { verified_boot_key: Vec<u8>, device_locked: bool, verified_boot_state: VerifiedBootState, verified_boot_hash: Vec<u8> }`.
  - `AuthorizationList { purpose: Vec<i64>, algorithm: Option<i64>, key_size: Option<i64>, ec_curve: Option<i64>, no_auth_required: bool, user_auth_type: Option<i64>, creation_date_time: Option<i64>, origin: Option<i64>, root_of_trust: Option<RootOfTrust>, os_version: Option<i64>, os_patch_level: Option<i64> }` + `Default`.
  - `KeyDescription { attestation_version: i64, attestation_security_level: SecurityLevel, key_mint_version: i64, key_mint_security_level: SecurityLevel, attestation_challenge: Vec<u8>, unique_id: Vec<u8>, software_enforced: AuthorizationList, hardware_enforced: AuthorizationList }`.
  - `pub fn parse_key_description(cert: &Certificate) -> Result<Option<KeyDescription>, TrustError>`
  - `pub fn decode_key_description(der: &[u8]) -> Result<KeyDescription, TrustError>`
  - `pub fn find_attestation_cert(chain: &[Certificate]) -> Result<(usize, KeyDescription), TrustError>`

- [ ] **Step 1: Write the failing test file**

Create `crates/foundry-core/tests/android_attestation.rs`:

```rust
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
    assert_eq!(kd.attestation_security_level, SecurityLevel::TrustedEnvironment);
    assert_eq!(kd.key_mint_version, 41);
    assert_eq!(kd.key_mint_security_level, SecurityLevel::TrustedEnvironment);
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
    let kd = parse_key_description(&leaf).expect("parses").expect("present");
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
    assert!(decode_key_description(&full).is_ok(), "the whole structure parses");
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p foundry-core --test android_attestation`
Expected: FAIL to compile — `could not find android_attestation in trust`.

- [ ] **Step 3: Write the parser**

Create `crates/foundry-core/src/trust/android_attestation.rs`:

```rust
//! Android Key Attestation extension (`1.3.6.1.4.1.11129.2.1.17`) parsing.
//!
//! Parsing only: no policy, no protocol binding, no network. Policy lives in
//! `foundry-issuer`'s `keystore_proof.rs`, where the `c_nonce`, configuration
//! and `IssuanceError` are.
//!
//! Schema: <https://source.android.com/docs/security/features/keystore/attestation>
//! Consumed by Google Wallet's `android_keystore_attestation` proof type; see
//! `docs/specs/google-wallet-openid4vci-profile.md`.
//!
//! The outer `KeyDescription` SEQUENCE is byte-identical across every published
//! attestation version (1-4, 100-500); only `AuthorizationList` gains tags. So
//! the outer structure is parsed strictly and version-agnostically, while
//! `AuthorizationList` decodes a documented tag set and skips the rest.
//!
//! No `.unwrap()`/`panic!()` below: these bytes are attacker-controlled
//! (root AGENTS.md §4.1).

use crate::error::TrustError;
use serde::Deserialize;
use x509_cert::der::asn1::AnyRef;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Reader, SliceReader, Tag, Tagged};
use x509_cert::Certificate;

/// OID of the Android Key Attestation extension.
///
/// `new_unwrap` in a `const` item is evaluated at compile time, so a malformed
/// OID is a build failure rather than a runtime panic.
pub const KEY_ATTESTATION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

/// `SecurityLevel ::= ENUMERATED { Software(0), TrustedEnvironment(1), StrongBox(2) }`
///
/// `Ord` is derived in ascending strength, so a policy minimum is a `>=`
/// comparison. The variant names are also the strings Google's issuer metadata
/// uses, so `Deserialize` needs no rename attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

impl SecurityLevel {
    fn from_enumerated(value: i64) -> Result<Self, TrustError> {
        match value {
            0 => Ok(Self::Software),
            1 => Ok(Self::TrustedEnvironment),
            2 => Ok(Self::StrongBox),
            // A level foundry cannot rank is a level it cannot apply a `>=`
            // policy to. Failing is the only honest option.
            other => Err(TrustError::Parse(format!(
                "Android key attestation: unknown SecurityLevel {other}"
            ))),
        }
    }

    /// The spelling Google's issuer metadata uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "Software",
            Self::TrustedEnvironment => "TrustedEnvironment",
            Self::StrongBox => "StrongBox",
        }
    }
}

/// `VerifiedBootState ::= ENUMERATED { Verified(0), SelfSigned(1), Unverified(2), Failed(3) }`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBootState {
    Verified,
    SelfSigned,
    Unverified,
    Failed,
}

impl VerifiedBootState {
    fn from_enumerated(value: i64) -> Result<Self, TrustError> {
        match value {
            0 => Ok(Self::Verified),
            1 => Ok(Self::SelfSigned),
            2 => Ok(Self::Unverified),
            3 => Ok(Self::Failed),
            other => Err(TrustError::Parse(format!(
                "Android key attestation: unknown VerifiedBootState {other}"
            ))),
        }
    }
}

/// `RootOfTrust`, tag `[704]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    /// Empty for attestation versions below 3, where the field is absent.
    pub verified_boot_hash: Vec<u8>,
}

/// The decoded subset of `AuthorizationList`.
///
/// Deliberately wider than the enforced policy: every field here is what one of
/// the design's named follow-ons (`user_auth_types`,
/// `verifiedBootState`/`deviceLocked`) needs, so adding a policy check later
/// does not re-touch this parser. Tags outside the set are skipped rather than
/// retained in a generic map — a generic map invites callers to reach for tags
/// whose semantics nobody has decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizationList {
    /// `[1]` purpose
    pub purpose: Vec<i64>,
    /// `[2]` algorithm
    pub algorithm: Option<i64>,
    /// `[3]` keySize
    pub key_size: Option<i64>,
    /// `[10]` ecCurve
    pub ec_curve: Option<i64>,
    /// `[503]` noAuthRequired — NULL-typed; presence means true.
    pub no_auth_required: bool,
    /// `[504]` userAuthType
    pub user_auth_type: Option<i64>,
    /// `[701]` creationDateTime
    pub creation_date_time: Option<i64>,
    /// `[702]` origin
    pub origin: Option<i64>,
    /// `[704]` rootOfTrust
    pub root_of_trust: Option<RootOfTrust>,
    /// `[705]` osVersion
    pub os_version: Option<i64>,
    /// `[706]` osPatchLevel
    pub os_patch_level: Option<i64>,
}

/// The `KeyDescription` carried by the attestation extension.
///
/// `unique_id` is a privacy-sensitive hardware device identifier that survives
/// factory reset (root AGENTS.md §4.5): never log it, never persist it, never
/// return it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescription {
    pub attestation_version: i64,
    pub attestation_security_level: SecurityLevel,
    pub key_mint_version: i64,
    pub key_mint_security_level: SecurityLevel,
    pub attestation_challenge: Vec<u8>,
    pub unique_id: Vec<u8>,
    pub software_enforced: AuthorizationList,
    pub hardware_enforced: AuthorizationList,
}

/// The certificate's `KeyDescription`, or `Ok(None)` when it carries no
/// attestation extension. A *present but malformed* extension is an error.
pub fn parse_key_description(cert: &Certificate) -> Result<Option<KeyDescription>, TrustError> {
    let Some(extensions) = cert.tbs_certificate().extensions() else {
        return Ok(None);
    };
    for ext in extensions.iter() {
        if ext.extn_id == KEY_ATTESTATION_OID {
            return Ok(Some(decode_key_description(ext.extn_value.as_bytes())?));
        }
    }
    Ok(None)
}

/// The extension-bearing certificate **nearest the root**, and its
/// `KeyDescription`.
///
/// Nearest-the-root, not `chain[0]`: Google's procedure (step 6 of "Retrieve and
/// verify a hardware-backed key pair") warns that lower instances of the
/// extension "have not been issued by the secure hardware and might have been
/// issued by an attacker extending the chain while attempting to create fake
/// attestations for untrusted keys". An attacker appending a certificate below a
/// genuine keystore leaf therefore ends up with the credential bound to the
/// genuine hardware key rather than theirs.
///
/// `chain` is leaf-first, so the walk is reversed.
pub fn find_attestation_cert(chain: &[Certificate]) -> Result<(usize, KeyDescription), TrustError> {
    for (idx, cert) in chain.iter().enumerate().rev() {
        if let Some(kd) = parse_key_description(cert)? {
            return Ok((idx, kd));
        }
    }
    Err(TrustError::Parse(
        "Android key attestation: no certificate in the chain carries the attestation extension"
            .into(),
    ))
}

/// Decode a `KeyDescription` from the extension's DER content.
pub fn decode_key_description(der: &[u8]) -> Result<KeyDescription, TrustError> {
    let outer = read_one(der)?;
    expect_tag(&outer, Tag::Sequence, "KeyDescription")?;
    let mut r = SliceReader::new(outer.value()).map_err(der_err)?;

    let attestation_version = read_int(&mut r)?;
    let attestation_security_level = SecurityLevel::from_enumerated(read_enumerated(&mut r)?)?;
    let key_mint_version = read_int(&mut r)?;
    let key_mint_security_level = SecurityLevel::from_enumerated(read_enumerated(&mut r)?)?;
    let attestation_challenge = read_octet_string(&mut r)?;
    let unique_id = read_octet_string(&mut r)?;
    let software_enforced = read_authorization_list(&mut r)?;
    let hardware_enforced = read_authorization_list(&mut r)?;

    Ok(KeyDescription {
        attestation_version,
        attestation_security_level,
        key_mint_version,
        key_mint_security_level,
        attestation_challenge,
        unique_id,
        software_enforced,
        hardware_enforced,
    })
}

// --- DER helpers ----------------------------------------------------------

fn der_err(e: x509_cert::der::Error) -> TrustError {
    TrustError::Parse(format!("Android key attestation: {e}"))
}

/// Decode exactly one TLV from the head of `bytes`.
fn read_one(bytes: &[u8]) -> Result<AnyRef<'_>, TrustError> {
    let mut r = SliceReader::new(bytes).map_err(der_err)?;
    r.decode::<AnyRef>().map_err(der_err)
}

fn next<'a>(r: &mut SliceReader<'a>) -> Result<AnyRef<'a>, TrustError> {
    r.decode::<AnyRef>().map_err(der_err)
}

fn expect_tag(any: &AnyRef<'_>, want: Tag, what: &str) -> Result<(), TrustError> {
    if any.tag() != want {
        return Err(TrustError::Parse(format!(
            "Android key attestation: {what}: expected {want:?}, found {:?}",
            any.tag()
        )));
    }
    Ok(())
}

/// Two's-complement big-endian INTEGER, capped at 8 bytes.
fn int_from_der(value: &[u8]) -> Result<i64, TrustError> {
    let Some(first) = value.first() else {
        return Err(TrustError::Parse(
            "Android key attestation: empty INTEGER".into(),
        ));
    };
    if value.len() > 8 {
        return Err(TrustError::Parse(format!(
            "Android key attestation: INTEGER of {} bytes exceeds i64",
            value.len()
        )));
    }
    let mut acc: i64 = if first & 0x80 != 0 { -1 } else { 0 };
    for byte in value {
        acc = (acc << 8) | i64::from(*byte);
    }
    Ok(acc)
}

fn read_int(r: &mut SliceReader<'_>) -> Result<i64, TrustError> {
    let any = next(r)?;
    expect_tag(&any, Tag::Integer, "INTEGER")?;
    int_from_der(any.value())
}

fn read_enumerated(r: &mut SliceReader<'_>) -> Result<i64, TrustError> {
    let any = next(r)?;
    expect_tag(&any, Tag::Enumerated, "ENUMERATED")?;
    int_from_der(any.value())
}

fn read_octet_string(r: &mut SliceReader<'_>) -> Result<Vec<u8>, TrustError> {
    let any = next(r)?;
    expect_tag(&any, Tag::OctetString, "OCTET STRING")?;
    Ok(any.value().to_vec())
}

fn read_boolean(r: &mut SliceReader<'_>) -> Result<bool, TrustError> {
    let any = next(r)?;
    expect_tag(&any, Tag::Boolean, "BOOLEAN")?;
    match any.value() {
        [byte] => Ok(*byte != 0),
        other => Err(TrustError::Parse(format!(
            "Android key attestation: BOOLEAN of {} bytes",
            other.len()
        ))),
    }
}

fn read_authorization_list(r: &mut SliceReader<'_>) -> Result<AuthorizationList, TrustError> {
    let any = next(r)?;
    expect_tag(&any, Tag::Sequence, "AuthorizationList")?;
    decode_authorization_list(any.value())
}

fn decode_authorization_list(bytes: &[u8]) -> Result<AuthorizationList, TrustError> {
    let mut out = AuthorizationList::default();
    if bytes.is_empty() {
        return Ok(out);
    }
    let mut r = SliceReader::new(bytes).map_err(der_err)?;
    while !r.is_finished() {
        let entry = next(&mut r)?;
        let number = match entry.tag() {
            Tag::ContextSpecific { number, .. } => number.value(),
            other => {
                return Err(TrustError::Parse(format!(
                    "Android key attestation: AuthorizationList: unexpected tag {other:?}"
                )))
            }
        };
        // Every entry is EXPLICIT, so the context-specific wrapper's content is
        // one nested TLV. Tag 503 wraps a NULL: its presence *is* the value, so
        // the inner TLV is deliberately not inspected.
        match number {
            1 => out.purpose = decode_int_set(entry.value())?,
            2 => out.algorithm = Some(decode_single_int(entry.value())?),
            3 => out.key_size = Some(decode_single_int(entry.value())?),
            10 => out.ec_curve = Some(decode_single_int(entry.value())?),
            503 => out.no_auth_required = true,
            504 => out.user_auth_type = Some(decode_single_int(entry.value())?),
            701 => out.creation_date_time = Some(decode_single_int(entry.value())?),
            702 => out.origin = Some(decode_single_int(entry.value())?),
            704 => out.root_of_trust = Some(decode_root_of_trust(entry.value())?),
            705 => out.os_version = Some(decode_single_int(entry.value())?),
            706 => out.os_patch_level = Some(decode_single_int(entry.value())?),
            // Outside the decoded set by design: skipped, not rejected, so a
            // future KeyMint tag needs no code change here.
            _ => {}
        }
    }
    Ok(out)
}

fn decode_single_int(explicit: &[u8]) -> Result<i64, TrustError> {
    let mut r = SliceReader::new(explicit).map_err(der_err)?;
    read_int(&mut r)
}

fn decode_int_set(explicit: &[u8]) -> Result<Vec<i64>, TrustError> {
    let any = read_one(explicit)?;
    expect_tag(&any, Tag::Set, "SET OF INTEGER")?;
    let mut out = Vec::new();
    let mut r = SliceReader::new(any.value()).map_err(der_err)?;
    while !r.is_finished() {
        out.push(read_int(&mut r)?);
    }
    Ok(out)
}

fn decode_root_of_trust(explicit: &[u8]) -> Result<RootOfTrust, TrustError> {
    let any = read_one(explicit)?;
    expect_tag(&any, Tag::Sequence, "RootOfTrust")?;
    let mut r = SliceReader::new(any.value()).map_err(der_err)?;
    let verified_boot_key = read_octet_string(&mut r)?;
    let device_locked = read_boolean(&mut r)?;
    let verified_boot_state = VerifiedBootState::from_enumerated(read_enumerated(&mut r)?)?;
    // verifiedBootHash is absent for attestation versions below 3.
    let verified_boot_hash = if r.is_finished() {
        Vec::new()
    } else {
        read_octet_string(&mut r)?
    };
    Ok(RootOfTrust {
        verified_boot_key,
        device_locked,
        verified_boot_state,
        verified_boot_hash,
    })
}
```

- [ ] **Step 4: Declare the module**

In `crates/foundry-core/src/trust/mod.rs`, immediately after the existing `pub use x509_cert::Certificate;` line:

```rust
pub mod android_attestation;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p foundry-core --test android_attestation`
Expected: PASS, 9 tests.

If the challenge assertion fails, print the value with `String::from_utf8_lossy` before editing the expectation — it was read off the fixture with an independent decoder and is correct.

- [ ] **Step 6: Scoped gate**

```bash
cargo test -p foundry-core
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt && cargo fmt --check
```

Expected: green. Do **not** run `cargo test --workspace`.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-core/src/trust/android_attestation.rs \
        crates/foundry-core/src/trust/mod.rs \
        crates/foundry-core/tests/android_attestation.rs
git commit -m "feat(core): parse the Android key attestation extension"
```
---

### Task 2: Configuration and fail-closed validation

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs` (add `AndroidKeystoreConfig`, wire it into `AttestationMode`, update the hand-written `Default`)
- Modify: `crates/foundry-core/src/config/validate.rs` (fail-closed check + tests)

**Interfaces:**
- Consumes: `SecurityLevel` (Task 1); existing `Mode`, `default_disabled()`, `AttestationMode`, `ConfigError::Validation`.
- Produces, for Tasks 3, 5, 6:
  - `foundry_core::config::AndroidKeystoreConfig { pub mode: Mode, pub key_mint_security_level: SecurityLevel }` — `Debug + Clone + Deserialize + PartialEq + Eq + Default`; default is `Mode::Disabled` + `SecurityLevel::TrustedEnvironment`.
  - `AttestationMode::android: AndroidKeystoreConfig`.

- [ ] **Step 1: Write the failing tests**

Append inside the `mod tests` block at the bottom of `crates/foundry-core/src/config/validate.rs`:

```rust
    #[test]
    fn android_keystore_attestation_requires_trust_anchors() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.android.mode = Mode::Optional;
        cfg.issuer.key_attestation.trusted_anchors = Vec::new();
        let err = cfg
            .validate()
            .expect_err("enabling the proof type with no anchors must fail at load time");
        let msg = err.to_string();
        assert!(
            msg.contains("android") && msg.contains("trusted_anchors"),
            "the message must name both fields, got: {msg}"
        );
    }

    #[test]
    fn android_keystore_attestation_disabled_needs_no_anchors() {
        let cfg = test_config();
        assert_eq!(
            cfg.issuer.key_attestation.android.mode,
            Mode::Disabled,
            "the default must be Disabled so no deployment changes behaviour on upgrade"
        );
        cfg.validate().expect("the default configuration stays valid");
    }

    #[test]
    fn android_key_mint_security_level_defaults_to_trusted_environment() {
        let cfg = test_config();
        assert_eq!(
            cfg.issuer.key_attestation.android.key_mint_security_level,
            crate::trust::android_attestation::SecurityLevel::TrustedEnvironment
        );
    }
```

If `test_config()` (same file) builds `AttestationMode` with struct literals rather than `..Default::default()`, add `android: Default::default(),` to each literal so the file compiles. If `Mode` is not already imported in this file, add it to the `use super::model::...` line.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p foundry-core --lib config`
Expected: FAIL to compile — no field `android` on `AttestationMode`.

- [ ] **Step 3: Add the config model**

In `crates/foundry-core/src/config/model.rs`, immediately after the `impl Default for AttestationMode { ... }` block:

```rust
/// Google Wallet's `android_keystore_attestation` proof type.
///
/// Vendor profile: `docs/specs/google-wallet-openid4vci-profile.md`. Design:
/// `docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md`.
///
/// Consulted **only** for `issuer.key_attestation` -- `AttestationMode` is
/// shared with `issuer.wallet_attestation`, which has no such proof type and
/// never reads this field. Same restriction as `pop_max_age_secs` and
/// `challenge_mode`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AndroidKeystoreConfig {
    /// - `disabled` (default) — an `android_keystore_attestation` member in a
    ///   Credential Request is rejected, and the proof type is absent from
    ///   issuer metadata. Reproduces pre-support behaviour exactly.
    /// - `optional` — accepted alongside the `jwt` proof type.
    /// - `required` — accepted, and a `jwt` proofs member is rejected: a
    ///   Google-Wallet-only deployment.
    ///
    /// Deliberately `default_disabled()` rather than `#[serde(default)]`:
    /// `Mode::default()` is `Optional`, which would silently start accepting a
    /// proof type that carries no proof of possession of the attested key.
    #[serde(default = "default_disabled")]
    pub mode: Mode,
    /// Minimum accepted hardware security level, compared against **both**
    /// `attestationSecurityLevel` and `keyMintSecurityLevel` under
    /// `Software < TrustedEnvironment < StrongBox`.
    ///
    /// Advertised in issuer metadata as `proof_types_supported`
    /// `.android_keystore_attestation.key_attestations_required`
    /// `.key_mint_security_level`.
    #[serde(default = "default_key_mint_security_level")]
    pub key_mint_security_level: crate::trust::android_attestation::SecurityLevel,
}

fn default_key_mint_security_level() -> crate::trust::android_attestation::SecurityLevel {
    crate::trust::android_attestation::SecurityLevel::TrustedEnvironment
}

// Hand-written for the same reason `AttestationMode`'s is: a derived `Default`
// would give `mode` the `Mode::default()` value (`Optional`) and silently enable
// the proof type for any code path using `..Default::default()`.
impl Default for AndroidKeystoreConfig {
    fn default() -> Self {
        Self {
            mode: default_disabled(),
            key_mint_security_level: default_key_mint_security_level(),
        }
    }
}
```

Add the field to `AttestationMode`, after `challenge_mode`:

```rust
    /// Google Wallet's `android_keystore_attestation` proof type. Consulted
    /// **only** for `issuer.key_attestation`.
    #[serde(default)]
    pub android: AndroidKeystoreConfig,
```

And inside `impl Default for AttestationMode`, add the field:

```rust
            android: AndroidKeystoreConfig::default(),
```

- [ ] **Step 4: Add the fail-closed validation**

In `crates/foundry-core/src/config/validate.rs`, inside `impl Config { pub fn validate(&self) ... }`, immediately before its final `Ok(())`:

```rust
        // Fail closed at load time. With the proof type enabled and no anchors
        // every attestation chain would be rejected at request time -- a silent
        // total outage. Failing here makes it a legible misconfiguration.
        if self.issuer.key_attestation.android.mode != Mode::Disabled
            && self.issuer.key_attestation.trusted_anchors.is_empty()
        {
            return Err(ConfigError::Validation(
                "issuer.key_attestation.android.mode is enabled but \
                 issuer.key_attestation.trusted_anchors is empty: every \
                 android_keystore_attestation chain would be rejected"
                    .into(),
            ));
        }
```

- [ ] **Step 5: Run to verify the tests pass**

Run: `cargo test -p foundry-core --lib config`
Expected: PASS, including the three new tests.

- [ ] **Step 6: Scoped gate**

`foundry-core::config` is consumed by every crate, so the affected set widens per root §5.2:

```bash
cargo test -p foundry-core
cargo test -p foundry-issuer
cargo test -p foundry-verifier
cargo test -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt && cargo fmt --check
```

Expected: green. Any failure will be a struct literal missing the new field — add `android: Default::default(),`.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-core/src/config/model.rs crates/foundry-core/src/config/validate.rs
git commit -m "feat(core): configure the android_keystore_attestation proof type"
```

---

### Task 3: The `keystore_proof` verifier in `foundry-issuer`

**Files:**
- Create: `crates/foundry-issuer/src/keystore_proof.rs`
- Modify: `crates/foundry-issuer/src/lib.rs` (`pub mod keystore_proof;`)
- Modify: `crates/foundry-issuer/Cargo.toml` (`rcgen` dev-dependency)

**Interfaces:**
- Consumes: `AndroidKeystoreConfig`, `SecurityLevel` (Tasks 2, 1); `find_attestation_cert` (Task 1); existing `foundry_core::trust::{x5c_entry_to_pem, parse_cert_pem, validate_chain, cert_ec_public_coords, TrustStore}`, `crate::nonce::{verify_nonce, NonceSecret}`, `crate::proof::VerifiedProof`, `crate::error::IssuanceError`, `foundry_core::config::Mode`, `foundry_core::obs::thumbprint`.
- Produces, for Task 4:
  - `pub fn verify_android_keystore_proofs(chains: &[Vec<String>], cfg: &AndroidKeystoreConfig, trust_store: &TrustStore, nonce_secret: &NonceSecret, now_unix: i64) -> Result<Vec<VerifiedProof>, IssuanceError>` — one `VerifiedProof` per chain, in request order.

- [ ] **Step 1: Add the dev-dependency and declare the module**

In `crates/foundry-issuer/Cargo.toml`, under `[dev-dependencies]`:

```toml
rcgen = { workspace = true }
```

In `crates/foundry-issuer/src/lib.rs`, alongside the other `pub mod` declarations:

```rust
pub mod keystore_proof;
```

- [ ] **Step 2: Write the failing tests**

Create `crates/foundry-issuer/src/keystore_proof.rs` with **only** this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::config::Mode;
    use foundry_core::trust::android_attestation::SecurityLevel;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };

    // --- synthetic Android-shaped chains ---------------------------------
    //
    // The real Google fixture can never pass a happy-path test: its
    // attestationChallenge is Google's c_nonce, which cannot verify against
    // foundry's per-process MAC secret, and a static fixture cannot carry an
    // unexpired nonce. Chains are therefore minted at run time.
    //
    // The DER builder is deliberately duplicated from
    // `crates/foundry-core/tests/android_attestation.rs`; the design doc's
    // Testing section records why a public encoder in foundry-core was rejected.

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

    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &parts.concat())
    }

    /// `KeyDescription` DER (attestation version 3) with the given levels and
    /// challenge, and empty authorization lists.
    fn key_description(attestation_level: u8, key_mint_level: u8, challenge: &[u8]) -> Vec<u8> {
        sequence(&[
            integer(3),
            enumerated(attestation_level),
            integer(41),
            enumerated(key_mint_level),
            octet_string(challenge),
            octet_string(&[]),
            sequence(&[]),
            sequence(&[]),
        ])
    }

    struct SyntheticChain {
        /// Base64-STANDARD DER, leaf first — the wire form of one chain.
        chain: Vec<String>,
        /// The root's PEM, for the `TrustStore`.
        root_pem: String,
        /// The leaf's public JWK as JSON, for asserting the derived holder key.
        leaf_public_jwk: serde_json::Value,
    }

    /// A root CA plus a leaf carrying `key_description_der` in the Android
    /// attestation extension. `leaf_alg` selects the leaf's key algorithm so the
    /// non-P-256 rejection path is testable.
    fn synthetic_chain(
        key_description_der: &[u8],
        leaf_alg: &'static rcgen::SignatureAlgorithm,
    ) -> SyntheticChain {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut root_dn = DistinguishedName::new();
        root_dn.push(DnType::CommonName, "Synthetic Android Attestation Root");
        root_params.distinguished_name = root_dn;
        let root = root_params.self_signed(&root_key).expect("root cert");
        let root_pem = root.pem();

        let issuer = Issuer::from_ca_cert_pem(&root_pem, root_key).expect("issuer");

        let leaf_key = KeyPair::generate_for(leaf_alg).expect("leaf key");
        let mut leaf_params = CertificateParams::default();
        let mut leaf_dn = DistinguishedName::new();
        leaf_dn.push(DnType::CommonName, "Android Keystore Key");
        leaf_params.distinguished_name = leaf_dn;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                key_description_der.to_vec(),
            ));
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf cert");

        let leaf_pem = leaf.pem();
        let leaf_cert = parse_cert_pem(leaf_pem.as_bytes()).expect("leaf parses");
        let leaf_public_jwk = match cert_ec_public_coords(&leaf_cert) {
            Ok((x, y)) => serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": B64URL.encode(x),
                "y": B64URL.encode(y),
            }),
            // Only the non-P-256 rejection test produces a leaf this fails on,
            // and it never reads this field.
            Err(_) => serde_json::Value::Null,
        };

        let chain = foundry_core::trust::build_x5c(&[
            leaf_pem.clone().into_bytes(),
            root_pem.clone().into_bytes(),
        ])
        .expect("base64 DER chain");

        SyntheticChain {
            chain,
            root_pem,
            leaf_public_jwk,
        }
    }

    fn store_for(root_pem: &str) -> TrustStore {
        TrustStore::from_pems(&[root_pem.as_bytes().to_vec()]).expect("trust store")
    }

    fn cfg(mode: Mode, level: SecurityLevel) -> AndroidKeystoreConfig {
        AndroidKeystoreConfig {
            mode,
            key_mint_security_level: level,
        }
    }

    fn secret() -> NonceSecret {
        NonceSecret::from_bytes([42u8; 32])
    }

    fn now() -> i64 {
        1_800_000_000
    }

    /// A live, unexpired, MAC-authenticated `c_nonce`, exactly as `POST /nonce`
    /// mints one.
    fn fresh_nonce(secret: &NonceSecret) -> String {
        crate::nonce::issue_nonce(secret, now())
            .expect("mint nonce")
            .c_nonce
    }

    // --- tests ----------------------------------------------------------

    #[test]
    fn accepts_a_valid_chain_and_binds_the_attested_key() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );

        let proofs = verify_android_keystore_proofs(
            &[sc.chain.clone()],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect("a genuine chain must be accepted");

        assert_eq!(proofs.len(), 1);
        let derived = serde_json::to_value(&proofs[0].holder_jwk).expect("jwk serializes");
        assert_eq!(derived["kty"], sc.leaf_public_jwk["kty"]);
        assert_eq!(derived["crv"], sc.leaf_public_jwk["crv"]);
        assert_eq!(derived["x"], sc.leaf_public_jwk["x"]);
        assert_eq!(derived["y"], sc.leaf_public_jwk["y"]);
    }

    #[test]
    fn issues_one_proof_per_chain_in_request_order() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let first = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let proofs = verify_android_keystore_proofs(
            &[first.chain.clone(), first.chain.clone()],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&first.root_pem),
            &secret,
            now(),
        )
        .expect("both chains accepted");
        assert_eq!(proofs.len(), 2);
        let a = serde_json::to_value(&proofs[0].holder_jwk).expect("jwk");
        let b = serde_json::to_value(&proofs[1].holder_jwk).expect("jwk");
        assert_eq!(a["x"], first.leaf_public_jwk["x"]);
        assert_eq!(a["x"], b["x"], "the same chain twice yields the same key");
    }

    #[test]
    fn rejects_a_challenge_that_is_not_an_issuer_minted_nonce() {
        let secret = secret();
        let sc = synthetic_chain(
            &key_description(1, 1, b"not-a-real-c-nonce"),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("a forged challenge must be rejected");
        assert!(
            matches!(err, IssuanceError::InvalidNonce(ref m)
                if m.contains("android_keystore_attestation")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_an_expired_nonce() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            // Far beyond any plausible c_nonce lifetime.
            now() + 86_400,
        )
        .expect_err("an expired challenge must be rejected");
        assert!(matches!(err, IssuanceError::InvalidNonce(_)), "got {err:?}");
    }

    #[test]
    fn rejects_a_non_utf8_challenge() {
        let secret = secret();
        let sc = synthetic_chain(
            &key_description(1, 1, &[0xff, 0xfe, 0xfd]),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("a non-UTF-8 challenge must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_a_security_level_below_the_configured_minimum() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        // Software-backed key against the default TrustedEnvironment policy.
        let sc = synthetic_chain(
            &key_description(0, 0, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("a software-backed key must be rejected under the default policy");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn strongbox_policy_rejects_a_trusted_environment_key() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::StrongBox),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("TEE must not satisfy a StrongBox minimum");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn each_security_level_is_checked_independently() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        // attestationSecurityLevel satisfies the policy, keyMintSecurityLevel
        // does not. A verifier checking only the metadata-named field would
        // wrongly accept this.
        let sc = synthetic_chain(
            &key_description(1, 0, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("both levels must meet the minimum");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn an_unanchored_chain_is_invalid_proof_not_trust() {
        // The regression test for a 500-instead-of-400 response: an untrusted
        // holder chain is a client fault, but `IssuanceError::Trust` falls
        // through `wallet_error_response`'s catch-all arm to HTTP 500.
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let unrelated = foundry_core::pki::new_ca("Unrelated Root", 3650).expect("CA");
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&unrelated.cert_pem),
            &secret,
            now(),
        )
        .expect_err("a chain reaching no configured anchor must be rejected");
        assert!(
            matches!(err, IssuanceError::InvalidProof(_)),
            "must be InvalidProof (HTTP 400), got {err:?}"
        );
    }

    #[test]
    fn rejects_a_non_p256_attested_key() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("a P-384 attested key must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_a_chain_with_no_attestation_extension() {
        let secret = secret();
        let ca = foundry_core::pki::new_ca("Plain Root", 3650).expect("CA");
        let leaf = foundry_core::pki::issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "plain.test.local",
            &["plain.test.local".to_string()],
            365,
        )
        .expect("leaf");
        let chain = foundry_core::trust::build_x5c(&[
            leaf.cert_pem.clone().into_bytes(),
            ca.cert_pem.clone().into_bytes(),
        ])
        .expect("chain");
        let err = verify_android_keystore_proofs(
            &[chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&ca.cert_pem),
            &secret,
            now(),
        )
        .expect_err("a chain with no attestation extension must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_everything_when_the_mode_is_disabled() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Disabled, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("the default configuration must reject this proof type");
        assert!(
            matches!(err, IssuanceError::InvalidProof(ref m)
                if m.contains("unsupported proof type")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_an_empty_chain_list_and_an_empty_chain() {
        let secret = secret();
        let ca = foundry_core::pki::new_ca("R", 3650).expect("CA");
        let store = store_for(&ca.cert_pem);
        let c = cfg(Mode::Optional, SecurityLevel::TrustedEnvironment);
        assert!(
            verify_android_keystore_proofs(&[], &c, &store, &secret, now()).is_err(),
            "an empty chain list must be rejected"
        );
        assert!(
            verify_android_keystore_proofs(&[vec![]], &c, &store, &secret, now()).is_err(),
            "an empty chain must be rejected"
        );
    }

    #[test]
    fn rejects_a_chain_entry_that_is_not_base64_der() {
        let secret = secret();
        let ca = foundry_core::pki::new_ca("R", 3650).expect("CA");
        let err = verify_android_keystore_proofs(
            &[vec!["not base64!".to_string()]],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&ca.cert_pem),
            &secret,
            now(),
        )
        .expect_err("garbage must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p foundry-issuer keystore_proof`
Expected: FAIL to compile — `verify_android_keystore_proofs` not found.

- [ ] **Step 4: Write the verifier**

Prepend to `crates/foundry-issuer/src/keystore_proof.rs`, above the test module:

```rust
//! Google Wallet's `android_keystore_attestation` proof type: arrays of X.509
//! certificate chains carrying Android Keystore attestations.
//!
//! Vendor profile: `docs/specs/google-wallet-openid4vci-profile.md` and
//! <https://developer.android.com/identity/digital-credentials/credential-issuer/keystore-attestation>.
//! Design: `docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md`.
//!
//! This is **not** OpenID4VCI Appendix D key attestation: there is no JWT, no
//! claim set, and no signature by the attested key. Do not route it through
//! `attestation.rs`'s `verify_key_attestation_jwt`.
//!
//! Two properties the `jwt` proof type has and this one structurally cannot
//! (both recorded as conformance gap rows):
//!
//! * **No audience binding.** The format carries no Credential Issuer
//!   Identifier, so OpenID4VCI L862's mechanism is unmet. The property it exists
//!   for still holds: the `c_nonce` is MAC'd with this issuer's secret, so
//!   another issuer's nonce does not verify here.
//! * **No proof of possession** of the attested key — the same posture as
//!   OpenID4VCI's own `attestation` proof type (L2612). The hardware statement
//!   substitutes.
//!
//! Certificate validity contributes no freshness: real Android leaves are valid
//! 1970-2106. The `attestationChallenge` binding is the only replay defence,
//! which is why it is checked unconditionally and never made optional.

use crate::error::IssuanceError;
use crate::nonce::{verify_nonce, NonceSecret};
use crate::proof::VerifiedProof;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::config::{AndroidKeystoreConfig, Mode};
use foundry_core::trust::android_attestation::find_attestation_cert;
use foundry_core::trust::{
    cert_ec_public_coords, parse_cert_pem, validate_chain, x5c_entry_to_pem, TrustStore,
};
use josekit::jwk::Jwk;

/// Verify every chain in a `proofs.android_keystore_attestation` array.
///
/// Returns one `VerifiedProof` per chain, in request order, so the caller binds
/// the Nth issued credential to the Nth attested key exactly as it does for the
/// `jwt` proof array.
///
/// `skip_all` is mandatory: `chains` carries certificates and `nonce_secret` is
/// the process MAC secret.
#[tracing::instrument(skip_all, fields(chain_count = chains.len()))]
pub fn verify_android_keystore_proofs(
    chains: &[Vec<String>],
    cfg: &AndroidKeystoreConfig,
    trust_store: &TrustStore,
    nonce_secret: &NonceSecret,
    now_unix: i64,
) -> Result<Vec<VerifiedProof>, IssuanceError> {
    if cfg.mode == Mode::Disabled {
        return Err(IssuanceError::InvalidProof(
            "android_keystore_attestation is an unsupported proof type for this issuer".into(),
        ));
    }
    if chains.is_empty() {
        return Err(IssuanceError::InvalidProof(
            "android_keystore_attestation must contain at least one certificate chain".into(),
        ));
    }
    chains
        .iter()
        .map(|chain| verify_one_chain(chain, cfg, trust_store, nonce_secret, now_unix))
        .collect()
}

#[tracing::instrument(skip_all)]
fn verify_one_chain(
    chain: &[String],
    cfg: &AndroidKeystoreConfig,
    trust_store: &TrustStore,
    nonce_secret: &NonceSecret,
    now_unix: i64,
) -> Result<VerifiedProof, IssuanceError> {
    if chain.is_empty() {
        return Err(IssuanceError::InvalidProof(
            "android_keystore_attestation: certificate chain is empty".into(),
        ));
    }

    // Google transmits "Base64-NoWrap padded DER", which is exactly the `x5c`
    // entry encoding of RFC 7515 §4.1.6, so the existing converter applies.
    let pems: Vec<Vec<u8>> = chain
        .iter()
        .map(|entry| {
            x5c_entry_to_pem(entry).map_err(|e| {
                IssuanceError::InvalidProof(format!(
                    "android_keystore_attestation: certificate is not base64 DER: {e}"
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    let now_u64 = u64::try_from(now_unix)
        .map_err(|_| IssuanceError::Internal("current time is before the unix epoch".into()))?;

    // Every failure here is a client fault. `IssuanceError::Trust` would fall
    // through `wallet_error_response`'s catch-all arm to HTTP 500, turning "your
    // chain reaches no anchor I trust" into an apparent server outage -- so the
    // TrustError is wrapped, never propagated with `?`.
    //
    // Google's format includes its own root as the last element.
    // `validate_chain` discards self-signed presented certificates, so the
    // transmitted root grants nothing and trust must reach a configured anchor.
    validate_chain(&pems[0], &pems[1..], trust_store, now_u64).map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "android_keystore_attestation: certificate chain validation failed: {e}"
        ))
    })?;

    let certs = pems
        .iter()
        .map(|pem| {
            parse_cert_pem(pem).map_err(|e| {
                IssuanceError::InvalidProof(format!(
                    "android_keystore_attestation: certificate does not parse: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (attesting_idx, key_description) = find_attestation_cert(&certs)
        .map_err(|e| IssuanceError::InvalidProof(format!("android_keystore_attestation: {e}")))?;

    // The attestationChallenge holds the UTF-8 bytes of the c_nonce string as
    // transmitted, not raw nonce bytes -- established from the real Android
    // chain in `crates/foundry-core/tests/fixtures/android-attestation/`.
    let challenge = std::str::from_utf8(&key_description.attestation_challenge).map_err(|_| {
        IssuanceError::InvalidProof(
            "android_keystore_attestation: attestationChallenge is not valid UTF-8".into(),
        )
    })?;

    // Never log `challenge`: it is a c_nonce (root AGENTS.md §4.5). The prefix
    // mirrors `attestation.rs`'s `key_attestation:` so an operator can tell
    // which nonce-consuming path rejected the request.
    verify_nonce(nonce_secret, challenge, now_unix).map_err(|e| match e {
        IssuanceError::InvalidNonce(msg) => {
            IssuanceError::InvalidNonce(format!("android_keystore_attestation: {msg}"))
        }
        other => other,
    })?;

    // Both levels, not just the one Google's metadata names:
    // attestationSecurityLevel is where the key lives, keyMintSecurityLevel is
    // the implementation making the statement. A policy satisfied by only one of
    // them is not the policy the operator configured.
    let minimum = cfg.key_mint_security_level;
    if key_description.attestation_security_level < minimum
        || key_description.key_mint_security_level < minimum
    {
        return Err(IssuanceError::InvalidProof(format!(
            "android_keystore_attestation: security level below the configured minimum {}",
            minimum.as_str()
        )));
    }

    let attesting_cert = certs.get(attesting_idx).ok_or_else(|| {
        IssuanceError::Internal("attestation certificate index out of range".into())
    })?;
    let (x, y) = cert_ec_public_coords(attesting_cert).map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "android_keystore_attestation: attested key is not an EC public key: {e}"
        ))
    })?;
    // The attested key becomes the credential's holder key, and every credential
    // format foundry issues binds P-256. Google's metadata schema requires
    // `proof_signing_alg_values_supported`, which is read as constraining this
    // key even though nothing here is signed by it.
    if x.len() != 32 || y.len() != 32 {
        return Err(IssuanceError::InvalidProof(
            "android_keystore_attestation: attested key is not on P-256".into(),
        ));
    }
    let holder_jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": B64URL.encode(&x),
        "y": B64URL.encode(&y),
    }))
    .map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "android_keystore_attestation: attested key is not a usable JWK: {e}"
        ))
    })?;

    // Fields are opt-in, and `attestationChallenge` and `uniqueId` are never
    // among them (root AGENTS.md §4.5).
    let jwk_json =
        serde_json::to_value(&holder_jwk).map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    tracing::debug!(
        attestation_version = key_description.attestation_version,
        attestation_security_level = key_description.attestation_security_level.as_str(),
        key_mint_security_level = key_description.key_mint_security_level.as_str(),
        attested_key = %foundry_core::obs::thumbprint(&jwk_json),
        "android_keystore_attestation proof accepted"
    );

    Ok(VerifiedProof { holder_jwk })
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer keystore_proof`
Expected: PASS, 13 tests.

Likely first-run fixes, in order of probability:
1. `NonceResponse`'s nonce field name — confirm it is `c_nonce` in `crates/foundry-issuer/src/nonce.rs`.
2. `rcgen::KeyPair::generate_for(&SignatureAlgorithm)` — if 0.14 spells it differently, check `KeyPair`'s inherent methods; `foundry_core::pki` only ever calls the no-argument `generate()`.
3. `Issuer::from_ca_cert_pem` takes the key **by value** — follow `foundry_core::pki::issue_leaf`'s call exactly.

- [ ] **Step 6: Scoped gate**

```bash
cargo test -p foundry-issuer
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt && cargo fmt --check
```

`foundry` is not yet affected: nothing calls this function until Task 4.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-issuer/src/keystore_proof.rs crates/foundry-issuer/src/lib.rs \
        crates/foundry-issuer/Cargo.toml
git commit -m "feat(issuer): verify android_keystore_attestation certificate chains"
```

---

### Task 4: `proofs` request shape and Credential Endpoint dispatch

**Files:**
- Modify: `crates/foundry-issuer/src/proof.rs` (`ProofsRequest`, `ResolvedProofs`, `resolve`, `from_jwts`, tests)
- Modify: `crates/foundry-issuer/src/credential.rs` (the proof-extraction block at ~281-304, plus the `ProofsRequest` construction sites in its test module at ~629, ~778, ~876)

**Interfaces:**
- Consumes: `verify_android_keystore_proofs` (Task 3), `AndroidKeystoreConfig` (Task 2).
- Produces:
  - `ProofsRequest { pub jwt: Option<Vec<String>>, pub android_keystore_attestation: Option<Vec<Vec<String>>> }`, `#[serde(deny_unknown_fields)]`, still `Deserialize + Serialize + utoipa::ToSchema`.
  - `pub fn ProofsRequest::from_jwts(jwts: Vec<String>) -> Self`
  - `#[derive(Debug)] pub enum ResolvedProofs<'a> { Jwt(&'a [String]), AndroidKeystoreAttestation(&'a [Vec<String>]) }`
  - `pub fn ProofsRequest::resolve(&self) -> Result<ResolvedProofs<'_>, IssuanceError>`

- [ ] **Step 1: Write the failing tests**

Append inside the `#[cfg(test)] mod tests` block of `crates/foundry-issuer/src/proof.rs`:

```rust
    #[test]
    fn resolves_a_jwt_only_proofs_object() {
        let p = ProofsRequest::from_jwts(vec!["a".into(), "b".into()]);
        match p.resolve().expect("resolves") {
            ResolvedProofs::Jwt(jwts) => assert_eq!(jwts.len(), 2),
            other => panic!("expected Jwt, got {other:?}"),
        }
    }

    #[test]
    fn resolves_an_android_only_proofs_object() {
        let p: ProofsRequest = serde_json::from_value(serde_json::json!({
            "android_keystore_attestation": [["MII"], ["MII"]]
        }))
        .expect("deserializes");
        match p.resolve().expect("resolves") {
            ResolvedProofs::AndroidKeystoreAttestation(chains) => assert_eq!(chains.len(), 2),
            other => panic!("expected AndroidKeystoreAttestation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_two_proof_types_at_once() {
        // OpenID4VCI Credential Request (L852): "The proofs parameter contains
        // exactly one parameter named as the proof type".
        let p: ProofsRequest = serde_json::from_value(serde_json::json!({
            "jwt": ["a"],
            "android_keystore_attestation": [["MII"]]
        }))
        .expect("deserializes");
        let err = p.resolve().expect_err("two proof types must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_an_empty_proofs_object() {
        let p: ProofsRequest = serde_json::from_value(serde_json::json!({})).expect("deserializes");
        let err = p.resolve().expect_err("no proof type must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_an_empty_proof_array() {
        let p = ProofsRequest::from_jwts(Vec::new());
        let err = p.resolve().expect_err("an empty jwt array must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
        let p: ProofsRequest = serde_json::from_value(serde_json::json!({
            "android_keystore_attestation": []
        }))
        .expect("deserializes");
        assert!(p.resolve().is_err(), "an empty chain array must be rejected");
    }

    #[test]
    fn rejects_an_unknown_proof_type_name() {
        // A strictness gain over the previous shape, where serde ignored the
        // unknown key and the request then failed as "missing jwt". L1395 lets
        // an issuer accept proof-type names beyond the registry, but not ones it
        // has never heard of.
        let err = serde_json::from_value::<ProofsRequest>(serde_json::json!({
            "di_vp": ["something"]
        }))
        .expect_err("an unknown proof type must not deserialize");
        assert!(err.to_string().contains("di_vp"), "got {err}");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p foundry-issuer --lib proof`
Expected: FAIL to compile — no `from_jwts`, no `ResolvedProofs`.

- [ ] **Step 3: Reshape `ProofsRequest`**

In `crates/foundry-issuer/src/proof.rs`, replace the existing `ProofsRequest` definition and its doc comment with:

```rust
/// Wire shape of the OpenID4VCI `proofs` request member.
///
/// OpenID4VCI Credential Request (L852): "The `proofs` parameter contains
/// exactly one parameter named as the proof type" -- enforced by
/// [`ProofsRequest::resolve`], not by the type, because "exactly one of two
/// optional members" is not expressible in a serde-derived struct.
///
/// Two proof types are accepted:
///
/// * `jwt` -- OpenID4VCI's own (L2610), the only path
///   `eudi-lib-jvm-openid4vci-kt`'s `ProofsSpecification.JwtProofs` emits.
/// * `android_keystore_attestation` -- Google Wallet's, an array of X.509
///   certificate chains (see `crate::keystore_proof`). A proof-type name beyond
///   the registry, which Credential Issuer Metadata (L1395) explicitly permits.
///
/// `di_vp` and the top-level `attestation` proof type remain unaccepted;
/// `deny_unknown_fields` makes that an explicit rejection rather than a silently
/// ignored member.
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<Vec<String>>,
    /// One entry per attested key; each entry is a certificate chain, leaf
    /// first, each certificate base64-STANDARD DER.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android_keystore_attestation: Option<Vec<Vec<String>>>,
}

/// The single proof type a `proofs` member resolved to.
#[derive(Debug)]
pub enum ResolvedProofs<'a> {
    Jwt(&'a [String]),
    AndroidKeystoreAttestation(&'a [Vec<String>]),
}

impl ProofsRequest {
    /// A `jwt`-only `proofs` member. Keeps call sites that predate the second
    /// proof type readable.
    pub fn from_jwts(jwts: Vec<String>) -> Self {
        Self {
            jwt: Some(jwts),
            android_keystore_attestation: None,
        }
    }

    /// Resolve to exactly one non-empty proof type, per L852.
    ///
    /// An empty array is treated as absence, preserving the pre-existing
    /// "missing proof in credential request" message for that case.
    pub fn resolve(&self) -> Result<ResolvedProofs<'_>, IssuanceError> {
        let jwt = self.jwt.as_deref().filter(|j| !j.is_empty());
        let android = self
            .android_keystore_attestation
            .as_deref()
            .filter(|a| !a.is_empty());
        match (jwt, android) {
            (Some(j), None) => Ok(ResolvedProofs::Jwt(j)),
            (None, Some(a)) => Ok(ResolvedProofs::AndroidKeystoreAttestation(a)),
            (Some(_), Some(_)) => Err(IssuanceError::InvalidProof(
                "proofs must contain exactly one proof type, found both jwt and \
                 android_keystore_attestation"
                    .into(),
            )),
            (None, None) => Err(IssuanceError::InvalidProof(
                "missing proof in credential request".into(),
            )),
        }
    }
}
```

- [ ] **Step 4: Run the proof tests**

Run: `cargo test -p foundry-issuer --lib proof`
Expected: the six new tests PASS. `credential.rs` will not compile yet — that is Step 5.

- [ ] **Step 5: Dispatch in `credential.rs`**

Replace the block that currently reads `req.proofs`, builds the trust store, and maps `verify_holder_proof` over `proof_jwts` (around lines 281-304) with:

```rust
    let proofs = req.proofs.as_ref().ok_or_else(|| {
        IssuanceError::InvalidProof("missing proof in credential request".into())
    })?;

    let key_attestation_trust_store = foundry_core::trust::TrustStore::from_config(
        &config.issuer.key_attestation.trusted_anchors,
    )?;

    let verified_proofs = match proofs.resolve()? {
        ResolvedProofs::Jwt(proof_jwts) => {
            // `android.mode: required` makes this issuer accept only Google
            // Wallet's proof type. The parent `key_attestation.mode` continues
            // to govern the jwt path's own key-source rules.
            if config.issuer.key_attestation.android.mode == foundry_core::config::Mode::Required {
                return Err(IssuanceError::InvalidProof(
                    "the jwt proof type is not accepted: this issuer requires \
                     android_keystore_attestation"
                        .into(),
                ));
            }
            proof_jwts
                .iter()
                .map(|jwt_str| {
                    verify_holder_proof(
                        jwt_str,
                        &config.issuer.credential_issuer,
                        nonce_secret,
                        now_unix,
                        config.issuer.key_attestation.mode.clone(),
                        &key_attestation_trust_store,
                    )
                })
                .collect::<Result<Vec<_>, IssuanceError>>()?
        }
        ResolvedProofs::AndroidKeystoreAttestation(chains) => {
            crate::keystore_proof::verify_android_keystore_proofs(
                chains,
                &config.issuer.key_attestation.android,
                &key_attestation_trust_store,
                nonce_secret,
                now_unix,
            )?
        }
    };
```

Update the import at the top of `credential.rs` from `use crate::proof::{verify_holder_proof, ProofsRequest};` to also bring in `ResolvedProofs`.

Then fix the three `ProofsRequest { jwt: vec![...] }` literals in this file's test module: replace each with `ProofsRequest::from_jwts(vec![...])`.

- [ ] **Step 6: Add the mode-matrix test in `credential.rs`**

Copy the nearest existing test in `credential.rs`'s test module that drives `handle_credential_request` with a `jwt` proof (the first `ProofsRequest` construction site, around line 629) and adapt it:

```rust
    #[tokio::test]
    async fn required_android_mode_rejects_a_jwt_proof() {
        // Same setup as the neighbouring happy-path jwt test, with the android
        // proof type made mandatory.
        // ... build config, storage, transaction and a valid jwt proof exactly
        // as that test does, then before calling handle_credential_request:
        //     config.issuer.key_attestation.android.mode = Mode::Required;
        //     config.issuer.key_attestation.trusted_anchors = vec![TrustAnchor {
        //         name: "android".into(),
        //         certs: <any readable PEM path this test already has>,
        //     }];
        // and assert:
        //     let err = handle_credential_request(...).await.expect_err("...");
        //     assert!(matches!(err, IssuanceError::InvalidProof(ref m)
        //         if m.contains("requires android_keystore_attestation")));
    }
```

Write it out fully against whatever that neighbouring test's harness actually provides — the comment block above is the diff from it, not a substitute for real code. The assertion is the point: `Mode::Required` must reject a `jwt` proofs member with a message naming the required proof type.

- [ ] **Step 7: Run the tests**

Run: `cargo test -p foundry-issuer`
Expected: PASS, including the new dispatch test and every pre-existing `credential.rs` test.

- [ ] **Step 8: Scoped gate**

```bash
cargo test -p foundry-issuer
cargo test -p foundry
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt && cargo fmt --check
```

`foundry` is affected now: `ProofsRequest`'s shape is part of the Credential Request schema its route deserializes. A `foundry` test failure here means a request-body fixture needs `jwt` where it previously relied on the required field — fix the fixture, not the type.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry-issuer/src/proof.rs crates/foundry-issuer/src/credential.rs
git commit -m "feat(issuer): accept android_keystore_attestation in the proofs member"
```

---

### Task 5: Advertise the proof type in issuer metadata

**Files:**
- Modify: `crates/foundry-issuer/src/metadata.rs` (the `proof_types_supported` map and its tests)

**Interfaces:**
- Consumes: `AndroidKeystoreConfig` (Task 2), `SecurityLevel::as_str` (Task 1), the existing `ProofTypeSupported`.
- Produces: a second `proof_types_supported` entry, keyed `android_keystore_attestation`, present only when `issuer.key_attestation.android.mode != Disabled`.

- [ ] **Step 1: Write the failing tests**

Append inside `crates/foundry-issuer/src/metadata.rs`'s test module:

```rust
    #[test]
    fn android_proof_type_is_absent_when_disabled() {
        let cfg = test_config();
        let md = build_issuer_metadata(&cfg, "https://issuer.example.com");
        let pid = md
            .credential_configurations_supported
            .values()
            .next()
            .expect("at least one credential configuration");
        assert!(pid.proof_types_supported.contains_key("jwt"));
        assert!(
            !pid.proof_types_supported
                .contains_key("android_keystore_attestation"),
            "a disabled proof type must not be advertised"
        );
    }

    #[test]
    fn android_proof_type_is_advertised_with_the_configured_level() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.android.mode = Mode::Optional;
        cfg.issuer.key_attestation.android.key_mint_security_level =
            foundry_core::trust::android_attestation::SecurityLevel::StrongBox;
        let md = build_issuer_metadata(&cfg, "https://issuer.example.com");
        let pid = md
            .credential_configurations_supported
            .values()
            .next()
            .expect("at least one credential configuration");
        let entry = pid
            .proof_types_supported
            .get("android_keystore_attestation")
            .expect("advertised when enabled");
        assert_eq!(entry.proof_signing_alg_values_supported, vec!["ES256"]);
        let required = entry
            .key_attestations_required
            .as_ref()
            .expect("key_attestations_required is always present for this proof type");
        assert_eq!(required["key_mint_security_level"], "StrongBox");
        // user_auth_types is deliberately absent: advertising a requirement
        // foundry does not enforce is the failure mode the design rejects.
        assert!(required.get("user_auth_types").is_none());
    }
```

Adjust `build_issuer_metadata`'s call shape and the `test_config()` helper name to match what the neighbouring tests in this file already use.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p foundry-issuer --lib metadata`
Expected: FAIL — the second test finds no `android_keystore_attestation` entry.

- [ ] **Step 3: Emit the entry**

In `crates/foundry-issuer/src/metadata.rs`, replace the `proof_types_supported: BTreeMap::from([(...)])` initialiser with a mutable map built in two steps:

```rust
                proof_types_supported: {
                    let mut types = BTreeMap::from([(
                        "jwt".to_string(),
                        ProofTypeSupported {
                            proof_signing_alg_values_supported: vec!["ES256".to_string()],
                            key_attestations_required: if cfg.issuer.key_attestation.mode
                                == foundry_core::config::Mode::Required
                            {
                                Some(serde_json::json!({}))
                            } else {
                                None
                            },
                        },
                    )]);
                    // Google Wallet's proof type, advertised only when enabled.
                    // Vendor profile: docs/specs/google-wallet-openid4vci-profile.md.
                    //
                    // Two vendor readings, both deliberate:
                    //
                    // * `proof_signing_alg_values_supported` is REQUIRED by
                    //   Google's schema even though nothing in this proof type
                    //   is signed by the attested key. It is read as
                    //   constraining the *attested key's* algorithm, which is
                    //   what `keystore_proof.rs` enforces (P-256 only).
                    // * `key_attestations_required` here carries Google's field
                    //   names (`key_mint_security_level`), not OpenID4VCI's own
                    //   `key_storage`/`user_authentication` shape. The name
                    //   collision with the spec parameter is the vendor's.
                    //
                    // Unlike the `jwt` entry, this one is unconditional when the
                    // proof type is enabled: a minimum security level is always
                    // enforced, so a key attestation requirement always exists.
                    if cfg.issuer.key_attestation.android.mode
                        != foundry_core::config::Mode::Disabled
                    {
                        types.insert(
                            "android_keystore_attestation".to_string(),
                            ProofTypeSupported {
                                proof_signing_alg_values_supported: vec!["ES256".to_string()],
                                key_attestations_required: Some(serde_json::json!({
                                    "key_mint_security_level": cfg
                                        .issuer
                                        .key_attestation
                                        .android
                                        .key_mint_security_level
                                        .as_str(),
                                })),
                            },
                        );
                    }
                    types
                },
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p foundry-issuer --lib metadata`
Expected: PASS, including the pre-existing `key_attestations_required_absent_when_mode_optional_or_disabled`, which must stay green — the `jwt` entry's behaviour is unchanged.

- [ ] **Step 5: Scoped gate**

```bash
cargo test -p foundry-issuer
cargo test -p foundry
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt && cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/metadata.rs
git commit -m "feat(issuer): advertise android_keystore_attestation in issuer metadata"
```

---

### Task 6: End-to-end flow, rejection matrix, redaction, OpenAPI

**Files:**
- Modify: `crates/foundry/tests/support/mod.rs` (synthetic chain builder + a setup with the proof type enabled)
- Modify: `crates/foundry/Cargo.toml` (`rcgen` dev-dependency)
- Create: `crates/foundry/tests/keystore_attestation_proof.rs`
- Modify: `crates/foundry/tests/logging_redaction.rs` (one new test)
- Modify: `openapi.json`, `openapi-wallet.json` (regenerated)

**Interfaces:**
- Consumes everything from Tasks 1–5, plus the existing `support::{setup_without_encryption, issue_pre_auth_offer_and_get_access_token, mint_c_nonce, create_proof, body_json}` and `AppState::new`.
- Produces, in `support`:
  - `pub fn synthetic_android_chain(ca: &foundry_core::pki::CertMaterial, challenge: &[u8]) -> Vec<String>` — a leaf carrying an Android attestation extension whose `attestationChallenge` is `challenge`, signed by `ca`, returned leaf-first as base64-STANDARD DER with the root appended.
  - `pub async fn setup_with_android_keystore(anchor_cert_pem: &str) -> (AppState, tempfile::TempDir)`.

The split matters: the **anchor is created first**, so a test can build its `AppState` from the anchor, mint a `c_nonce` from *that* state, and only then build a chain around the minted nonce. Returning the root from the chain builder would force the reverse order and a state rebuild.

- [ ] **Step 1: Add the dev-dependency**

In `crates/foundry/Cargo.toml`, under `[dev-dependencies]`:

```toml
rcgen = { workspace = true }
```

- [ ] **Step 2: Extend the shared test support**

Append to `crates/foundry/tests/support/mod.rs`:

```rust
/// A synthetic Android-shaped attestation chain: a leaf carrying the Android
/// key attestation extension with `challenge` as its `attestationChallenge`,
/// signed by `ca`, returned as `[leaf, root]` in base64-STANDARD DER.
///
/// Runtime-generated rather than a fixture: the real Google chain's challenge is
/// Google's `c_nonce`, which can never verify against foundry's MAC secret, and
/// a static chain cannot carry an unexpired one. The DER builder is deliberately
/// duplicated from `crates/foundry-issuer/src/keystore_proof.rs`'s tests -- see
/// the design doc's Testing section.
pub fn synthetic_android_chain(
    ca: &foundry_core::pki::CertMaterial,
    challenge: &[u8],
) -> Vec<String> {
    use rcgen::{
        CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

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
    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &parts.concat())
    }

    // Attestation version 3, TrustedEnvironment for both security levels.
    let key_description = sequence(&[
        integer(3),
        enumerated(1),
        integer(41),
        enumerated(1),
        octet_string(challenge),
        octet_string(&[]),
        sequence(&[]),
        sequence(&[]),
    ]);

    let ca_key = KeyPair::from_pem(&ca.key_pem).expect("CA key parses");
    let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, ca_key).expect("issuer");

    // rcgen's default KeyPair is ECDSA P-256, which is what the attested key
    // must be.
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::default();
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, "Android Keystore Key");
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description,
        ));
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf cert");

    // The root is included, exactly as Google transmits it: `validate_chain`
    // discards self-signed presented certificates, so it grants nothing.
    foundry_core::trust::build_x5c(&[
        leaf.pem().into_bytes(),
        ca.cert_pem.clone().into_bytes(),
    ])
    .expect("base64 DER chain")
}

/// As `setup_without_encryption`, plus `android_keystore_attestation` enabled at
/// `optional` with `anchor_cert_pem` as the only configured trust anchor.
pub async fn setup_with_android_keystore(
    anchor_cert_pem: &str,
) -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_without_encryption().await;
    let anchor_path = dir.path().join("android-root.pem");
    std::fs::write(&anchor_path, anchor_cert_pem).expect("write anchor");

    let mut cfg = (*state.config).clone();
    cfg.issuer.key_attestation.trusted_anchors = vec![foundry_core::config::TrustAnchor {
        name: "android-test-root".to_string(),
        certs: anchor_path.to_str().expect("utf-8 path").to_string(),
    }];
    cfg.issuer.key_attestation.android = foundry_core::config::AndroidKeystoreConfig {
        mode: Mode::Optional,
        key_mint_security_level:
            foundry_core::trust::android_attestation::SecurityLevel::TrustedEnvironment,
    };
    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    (state, dir)
}
```

- [ ] **Step 3: Write the failing integration tests**

Create `crates/foundry/tests/keystore_attestation_proof.rs`:

```rust
//! Google Wallet's `android_keystore_attestation` proof type, end to end through
//! the wallet-facing router.
//!
//! Design: docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md
//!
//! Every test follows the same order, and the order is load-bearing: create the
//! anchor, build the `AppState` from it, mint a `c_nonce` from *that* state, then
//! build a chain whose `attestationChallenge` is that nonce. Minting before the
//! final state exists risks a nonce the state cannot verify.

mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use foundry::server::{wallet_router, AppState};
use support::{
    body_json, create_proof, issue_pre_auth_offer_and_get_access_token, mint_c_nonce,
    setup_with_android_keystore, setup_without_encryption, synthetic_android_chain,
};
use tower::ServiceExt;

const ISSUER: &str = "https://issuer.example.com";

async fn post_credential(
    state: &AppState,
    access_token: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    let app = wallet_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(body.to_string()))
        .expect("request builds");
    app.oneshot(req).await.expect("response")
}

async fn get_json(state: &AppState, uri: &str) -> serde_json::Value {
    let app = wallet_router(state.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("response");
    body_json(res).await
}

#[tokio::test]
async fn issues_a_credential_bound_to_the_attested_hardware_key() {
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&ca.cert_pem).await;
    let nonce = mint_c_nonce(&state).await;
    let chain = synthetic_android_chain(&ca, nonce.as_bytes());

    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({ "proofs": { "android_keystore_attestation": [chain] } }),
    )
    .await;

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a genuine chain anchored on a configured root must be accepted"
    );
    let json = body_json(res).await;
    assert_eq!(
        json["credentials"].as_array().map(Vec::len),
        Some(1),
        "one chain yields one credential: {json}"
    );
}

#[tokio::test]
async fn two_chains_yield_two_credentials() {
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&ca.cert_pem).await;
    let nonce = mint_c_nonce(&state).await;
    let first = synthetic_android_chain(&ca, nonce.as_bytes());
    let second = synthetic_android_chain(&ca, nonce.as_bytes());

    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({
            "proofs": { "android_keystore_attestation": [first, second] }
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let json = body_json(res).await;
    assert_eq!(json["credentials"].as_array().map(Vec::len), Some(2), "{json}");
}

#[tokio::test]
async fn the_default_configuration_rejects_the_proof_type() {
    // `setup_without_encryption` leaves `android.mode` at its `disabled` default.
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_without_encryption().await;
    let nonce = mint_c_nonce(&state).await;
    let chain = synthetic_android_chain(&ca, nonce.as_bytes());
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({ "proofs": { "android_keystore_attestation": [chain] } }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_proof");
}

#[tokio::test]
async fn an_unanchored_chain_is_400_invalid_proof_never_500() {
    // The HTTP half of the regression test for `IssuanceError::Trust` falling
    // through `wallet_error_response`'s catch-all arm to 500: the chain is
    // signed by a CA the issuer does not trust.
    let trusted = foundry_core::pki::new_ca("Trusted Root", 3650).expect("CA");
    let impostor = foundry_core::pki::new_ca("Impostor Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&trusted.cert_pem).await;
    let nonce = mint_c_nonce(&state).await;
    let chain = synthetic_android_chain(&impostor, nonce.as_bytes());

    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({ "proofs": { "android_keystore_attestation": [chain] } }),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "an untrusted chain is a client fault, not a server error"
    );
    assert_eq!(body_json(res).await["error"], "invalid_proof");
}

#[tokio::test]
async fn a_forged_challenge_is_400_invalid_nonce() {
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&ca.cert_pem).await;
    let chain = synthetic_android_chain(&ca, b"not-a-minted-c-nonce");
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({ "proofs": { "android_keystore_attestation": [chain] } }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["error"],
        "invalid_nonce",
        "a present-but-unauthentic challenge is invalid_nonce, not invalid_proof"
    );
}

#[tokio::test]
async fn two_proof_types_in_one_request_are_rejected() {
    // OpenID4VCI Credential Request (L852): exactly one proof type.
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&ca.cert_pem).await;
    let nonce = mint_c_nonce(&state).await;
    let chain = synthetic_android_chain(&ca, nonce.as_bytes());
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({
            "proofs": {
                "jwt": [create_proof(&nonce, ISSUER)],
                "android_keystore_attestation": [chain],
            }
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_proof");
}

#[tokio::test]
async fn metadata_advertises_the_proof_type_only_when_enabled() {
    let (off, _d1) = setup_without_encryption().await;
    let json = get_json(&off, "/.well-known/openid-credential-issuer").await;
    let configs = json["credential_configurations_supported"]
        .as_object()
        .expect("configurations");
    assert!(!configs.is_empty(), "the fixture config has credential types");
    for (id, cfg) in configs {
        assert!(
            cfg["proof_types_supported"]["android_keystore_attestation"].is_null(),
            "{id} must not advertise a disabled proof type"
        );
    }

    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (on, _d2) = setup_with_android_keystore(&ca.cert_pem).await;
    let json = get_json(&on, "/.well-known/openid-credential-issuer").await;
    let configs = json["credential_configurations_supported"]
        .as_object()
        .expect("configurations");
    for (id, cfg) in configs {
        let entry = &cfg["proof_types_supported"]["android_keystore_attestation"];
        assert_eq!(
            entry["proof_signing_alg_values_supported"][0], "ES256",
            "{id}"
        );
        assert_eq!(
            entry["key_attestations_required"]["key_mint_security_level"],
            "TrustedEnvironment",
            "{id}"
        );
    }
}
```

- [ ] **Step 4: Run the integration tests**

Run: `cargo test -p foundry --test keystore_attestation_proof`
Expected: PASS, 7 tests.

If the happy path returns 400 `invalid_nonce`, the `c_nonce` minted from `state` is not verifiable by the same `state` — check whether `AppState::new` derives a fresh `NonceSecret`, and if so mint and verify within one state (the order above already does this; the failure would then point at `verify_nonce`'s clock, not the ordering).

- [ ] **Step 5: Add the redaction test**

Append to `crates/foundry/tests/logging_redaction.rs`, following the shape of `issuance_never_logs_codes_tokens_nonces_or_claims`:

```rust
/// An `android_keystore_attestation` issuance must never log the
/// `attestationChallenge` (it is a `c_nonce`) or the `uniqueId` (a
/// privacy-sensitive hardware device identifier) -- root AGENTS.md §4.5.
///
/// The positive control for this harness already exists in this binary
/// (`the_capture_harness_would_catch_a_leaked_challenge`), so the absence
/// assertions below are trustworthy.
#[tokio::test]
async fn android_keystore_issuance_never_logs_the_challenge_or_unique_id() {
    let _guard = lock_flag().await;
    let (_capture_guard, capture) = capture_at_trace();

    // Drive one android-proof issuance: create a CA, build the state with
    // `android.mode = Optional` and that CA as the only anchor, mint a nonce,
    // build a chain around it, POST /credential. Assert 200 first -- a rejected
    // request would make the absence assertions vacuous.
    // ... then:
    let logs = capture.contents();
    assert!(
        !logs.contains(&nonce),
        "the c_nonce used as attestationChallenge must never appear in logs"
    );
    assert!(
        !logs.contains("unique_id") && !logs.contains("uniqueId"),
        "uniqueId must never be logged, not even as a field name"
    );
}
```

Write the body out fully against this file's own harness (`lock_flag`, `capture_at_trace`, its local `setup`) and its `Mode`/`TrustAnchor` imports. Two requirements the sketch above encodes and the implementation must keep: the issuance **must succeed** before the absence assertions run, and the nonce must be captured in a variable so the assertion tests the real value rather than a literal.

- [ ] **Step 6: Confirm instrumentation hygiene**

Run: `cargo test -p foundry --test instrumentation_hygiene`
Expected: PASS with no edits — the test walks the workspace sources itself, so the new `#[tracing::instrument(skip_all)]` attributes are covered automatically. If it fails, a new attribute is missing `skip_all`; fix the attribute, never the test.

- [ ] **Step 7: Regenerate the OpenAPI specs**

`ProofsRequest`'s schema changed (two optional members instead of one required one) and it is part of the Credential Request body, so both specs must be regenerated (root §6):

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json   # confirm the flag name at crates/foundry/src/cli.rs:110
git diff --stat openapi.json openapi-wallet.json
cargo test -p foundry --test cli_openapi
```

Expected: the diff touches only the `ProofsRequest` schema; `cli_openapi` passes.

- [ ] **Step 8: Scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt && cargo fmt --check
```

Do **not** run the `#[ignore]`d `e2e_full_flow` suite here — it belongs to the full gate at the end of the branch.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry/Cargo.toml crates/foundry/tests/support/mod.rs \
        crates/foundry/tests/keystore_attestation_proof.rs \
        crates/foundry/tests/logging_redaction.rs \
        openapi.json openapi-wallet.json
git commit -m "test(foundry): android_keystore_attestation issuance, rejection matrix, redaction"
```

### Task 7: Documentation, conformance rows, AGENTS.md updates

**Files:**
- Modify: `docs/conformance/openid4vc-conformance.md` (gap rows + affected clause rows)
- Modify: `README.md` (config block)
- Modify: `AGENTS.md` (root §4.5 never-logged list)
- Modify: `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md` (module maps + gotchas)
- Create: `docs/superpowers/changes/2026-08-04-android-keystore-attestation-proof.md`

**Interfaces:** none — documentation only. Read the design doc's "Deviations and known limitations" and "Documentation" sections first; this task implements them.

- [ ] **Step 1: Add the conformance gap rows**

In `docs/conformance/openid4vc-conformance.md`, following the existing `GAP-*` row format (ID, severity, clause, requirement, evidence, test), add six rows. Use the next free `GAP-VCI-*` numbers and keep the severity judgements below:

| Gap | Severity | Substance |
|---|---|---|
| audience binding | Minor | OpenID4VCI L862 requires a proof to incorporate the Credential Issuer Identifier. The `android_keystore_attestation` format carries none, so the mechanism is unmet. The property holds anyway: the `attestationChallenge` must be a `c_nonce` MAC'd with this issuer's per-process secret, so another issuer's nonce does not verify (`keystore_proof.rs`). Record both halves — mechanism absent, property present. |
| proof of possession | Minor | Nothing in the proof is signed by the attested key; the hardware statement substitutes. The same posture OpenID4VCI defines for its own `attestation` proof type (L2612), so this is a property of the format, not a defect in the implementation. |
| revocation | Important | Google's guidance asks issuers to check `https://android.googleapis.com/attestation/status`. Not implemented; a revoked attestation key is accepted. Named follow-on sub-project. |
| `user_auth_types` | Minor | Neither enforced nor advertised. Google's schema is self-contradictory about whether `[]` means "no constraint" or "the key MUST carry `noAuthRequired`"; the parser decodes `userAuthType` and `noAuthRequired` so the check is additive when the semantics are settled. |
| device integrity | Important | `rootOfTrust.verifiedBootState` and `deviceLocked` are decoded but unenforced, so a chain from an unlocked-bootloader device with a genuine TEE key is accepted. Deferred because rejecting those devices is an operator policy call needing its own config knob. |
| expired factory keys | Minor | Google states pre-2021 devices' attestation certificates stay trustworthy after expiry unless revoked; `validate_chain` enforces validity windows via OpenSSL and rejects them. Not relaxed: suppressing time checks interacts with RKP certificates whose short validity is deliberate. |

Each row must name `crates/foundry-issuer/src/keystore_proof.rs` (or `crates/foundry-core/src/trust/android_attestation.rs`) as the evidence location and cite the test that demonstrates the current behaviour where one exists.

- [ ] **Step 2: Check the clause rows this work touches**

Re-read these existing rows and update any that are now inaccurate, per the report's "living document" rule:

- **VCI-0198 / VCI-0222 / VCI-0223** (top-level `attestation` proof type) — still `not-implemented`. Their evidence says `ProofsRequest` has "only a `jwt: Vec<String>` field", which is no longer true. Rewrite the evidence to name the two accepted members and `deny_unknown_fields`, keeping the verdict.
- **VCI-0149** (`key_attestations_required` MUST NOT be present when key attestation is not required) — unchanged for the `jwt` entry; add a sentence noting the `android_keystore_attestation` entry always carries it because a minimum security level is always enforced when that proof type is enabled.
- Any row whose evidence quotes the old `ProofsRequest` shape — grep for `jwt: Vec<String>` in the report.

- [ ] **Step 3: Document the configuration in `README.md`**

In the issuer configuration section, alongside the existing `key_attestation` documentation, add the block and the operator-facing consequences:

```yaml
issuer:
  key_attestation:
    trusted_anchors:
      - name: google-android-root
        certs: /etc/foundry/android-attestation-roots.pem
    android:
      mode: optional                              # disabled (default) | optional | required
      key_mint_security_level: TrustedEnvironment  # Software | TrustedEnvironment | StrongBox
```

State plainly: `disabled` by default; `required` rejects the `jwt` proof type entirely; enabling it with an empty `trusted_anchors` is a startup error; the anchors are Google's attestation roots from
<https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate>; and revocation is **not** checked (link the gap row). No new log field names, so the Logging & Observability section needs no change.

- [ ] **Step 4: Update root `AGENTS.md` §4.5**

Add `uniqueId` to the never-logged list, in the same sentence as the other never-logged values, phrased so its reason survives: "the Android key attestation `uniqueId` (a privacy-sensitive hardware device identifier that survives factory reset)".

- [ ] **Step 5: Update the two crate `AGENTS.md` files**

`crates/foundry-core/AGENTS.md`:
- Module map: `trust/android_attestation.rs` — "Android Key Attestation extension (`1.3.6.1.4.1.11129.2.1.17`) `KeyDescription` parsing; parsing only, no policy".
- Gotcha: the attesting certificate is selected **nearest the root**, not `chain[0]`, and why (an attacker extending the chain below a genuine keystore leaf). Also: the outer `KeyDescription` is version-stable, `AuthorizationList` is not, hence strict-outer/permissive-inner; an unknown `SecurityLevel` is a hard error.

`crates/foundry-issuer/AGENTS.md`:
- Module map: `keystore_proof.rs` — "Google Wallet `android_keystore_attestation` proof type: chain validation, `attestationChallenge` ↔ `c_nonce` binding, security-level policy, holder-key derivation".
- Gotchas:
  1. **Now four similarly-named attestation things** — extend the existing three-item list with `keystore_proof::verify_android_keystore_proofs` (live, called from `credential.rs`) and state explicitly that it is not Appendix D key attestation and shares no wire format with `verify_key_attestation_jwt`.
  2. **`validate_chain` failures must be wrapped into `InvalidProof`**, never propagated as `IssuanceError::Trust`, which `wallet_error_response` maps to HTTP 500.
  3. **`android.mode: required` rejects the `jwt` proof type**, and the parent `key_attestation.mode` still governs only the `jwt` path.
  4. **No audience binding and no proof of possession** in this proof type; the `c_nonce` MAC is what bounds replay, so the challenge check is never optional.

- [ ] **Step 6: Write the change record**

Create `docs/superpowers/changes/2026-08-04-android-keystore-attestation-proof.md` following the format of the existing files in that directory: what changed, why, the design and plan links, the tasks as executed, the gate that was run, and the six known limitations with their gap IDs.

- [ ] **Step 7: Verify the documentation is accurate**

```bash
cargo test -p foundry --test conformance_report
cargo test -p foundry --test conformance_http
```

`conformance_report` machine-checks the report's structure and any gap-ID references in `#[ignore]` attributes; a malformed row fails it.

- [ ] **Step 8: Commit**

```bash
git add docs/conformance/openid4vc-conformance.md README.md AGENTS.md \
        crates/foundry-core/AGENTS.md crates/foundry-issuer/AGENTS.md \
        docs/superpowers/changes/2026-08-04-android-keystore-attestation-proof.md
git commit -m "docs: conformance rows, operator docs, and AGENTS updates for android_keystore_attestation"
```

---

## End-of-branch full gate

Run **once**, after Task 7, per root `AGENTS.md` §5.3 — and per §5.6, capture to disk rather than trusting a truncated tail:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace 2>&1 | tee /tmp/test-output.log
grep -c "FAILED" /tmp/test-output.log        # expect 0 / no output
grep "^test result:" /tmp/test-output.log    # one line per binary, all ok
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee /tmp/clippy.log
grep -c "^error" /tmp/clippy.log             # expect 0
```

Then request the final whole-branch review (`final-reviewer`).

## Plan self-review

Checked against the design doc:

- **Spec coverage.** Parser → Task 1. Config + fail-closed validation → Task 2. Chain validation, challenge binding, security-level policy, holder-key derivation → Task 3. `proofs` exactly-one rule and dispatch → Task 4. Metadata → Task 5. Flow, rejection matrix, redaction, OpenAPI → Task 6. Conformance rows, README, AGENTS, change record → Task 7. Every "Deviations and known limitations" entry has a Task 7 row.
- **Two known soft spots, deliberately left as instructions rather than fabricated code**, both in existing test harnesses this plan does not otherwise touch: the `credential.rs` mode-matrix test (Task 4 Step 6) and the `logging_redaction.rs` test (Task 6 Step 5). Each names the neighbouring test to copy, the exact delta from it, and the assertion that must hold. Implementers must write real code there; a stubbed body is a task failure.
- **Type consistency.** `SecurityLevel` (Task 1) is consumed by `AndroidKeystoreConfig` (Task 2), `keystore_proof` (Task 3) and `metadata.rs` (Task 5) under one name. `verify_android_keystore_proofs`'s signature is identical in Task 3's definition and Task 4's call. `ProofsRequest::from_jwts` / `resolve` / `ResolvedProofs` are used exactly as declared in Task 4's Interfaces block. `synthetic_android_chain(&CertMaterial, &[u8]) -> Vec<String>` is used with that signature in its definition and in all seven integration tests; the anchor comes from `foundry_core::pki::new_ca`, whose `CertMaterial` carries both `cert_pem` and `key_pem`.
- **One defect found and fixed during this review.** The first draft of Task 6 returned the root *from* the chain builder, which forced tests to mint a nonce before the final `AppState` existed and left three redundant setup/mint/rebuild rounds in the happy path, with a note telling the implementer to delete them. Instructing cleanup instead of writing correct code is a plan failure. The helper now takes the anchor as an argument, so the correct order — anchor, state, nonce, chain — is the only order the API allows.
