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
use x509_cert::Certificate;
use x509_cert::der::asn1::AnyRef;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Reader, SliceReader, Tag, Tagged};

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
                )));
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
