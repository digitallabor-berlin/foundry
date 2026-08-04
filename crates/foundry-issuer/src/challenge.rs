//! Domain-separated stateless MAC primitive backing every issuer-minted
//! opaque freshness value.
//!
//! Three protocols each need the issuer to hand a client a short-lived,
//! unpredictable, server-authenticated string:
//!
//! - OpenID4VCI §7 `c_nonce` (see [`crate::nonce`])
//! - ABCA §8 `attestation_challenge` (see [`crate::attestation`])
//! - RFC 9449 §8/§9 DPoP `nonce` (see [`crate::dpop`])
//!
//! All three share one wire format and one process secret:
//!
//! ```text
//! value = base64url( exp:i64be(8) || salt(16) || HMAC-SHA256(secret, label || 0x00 || exp || salt)[..16] )
//! ```
//!
//! **The `label` is what makes this module necessary.** Without it all three
//! kinds would be byte-compatible and mutually interchangeable: a wallet could
//! present a `c_nonce` where a DPoP nonce is required and be accepted, which
//! defeats the point of RFC 9449 §8 (the nonce must be one the server issued
//! *for this purpose*). Mixing the label into the MAC input makes a
//! cross-domain presentation indistinguishable from a forgery.
//!
//! Statelessness is what keeps the minting endpoints safe to leave
//! unauthenticated: no request writes a row, so an anonymous caller cannot
//! grow the database.

use crate::error::IssuanceError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub(crate) const EXP_LEN: usize = 8;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const PAYLOAD_LEN: usize = EXP_LEN + SALT_LEN;
pub(crate) const VALUE_LEN: usize = PAYLOAD_LEN + TAG_LEN;

/// Which protocol a value was minted for. Mixed into the MAC input so a value
/// minted for one domain cannot verify in another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Domain {
    /// OpenID4VCI 1.0 §7 `c_nonce`.
    CNonce,
    /// ABCA draft -07 §8 `attestation_challenge`.
    AttestationChallenge,
    /// RFC 9449 §8/§9 DPoP `nonce`.
    DpopNonce,
}

impl Domain {
    /// The domain-separation label. Versioned so a future format change can
    /// invalidate outstanding values deliberately rather than by accident.
    /// Contains no NUL byte, which is what makes `label || 0x00 || payload` an
    /// unambiguous encoding.
    fn label(self) -> &'static [u8] {
        match self {
            Domain::CNonce => b"foundry/c_nonce/v1",
            Domain::AttestationChallenge => b"foundry/attestation_challenge/v1",
            Domain::DpopNonce => b"foundry/dpop_nonce/v1",
        }
    }
}

/// Why a [`verify`] call failed.
///
/// Deliberately **not** an [`IssuanceError`]: each protocol maps these to its
/// own spec-mandated error code — `invalid_nonce` for `c_nonce` (OpenID4VCI
/// L1050), `use_attestation_challenge` for ABCA (§6.2), `use_dpop_nonce` for
/// DPoP (RFC 9449 §8) — with its own wording. Choosing the variant here would
/// force all three to share one.
#[derive(Debug)]
pub(crate) enum ChallengeFailure {
    NotBase64Url,
    WrongLength,
    /// Forged, tampered with, minted for a different [`Domain`], or minted by a
    /// previous process lifetime. Deliberately indistinguishable to the caller:
    /// telling a client *which* applied would be an oracle.
    NotIssuedHere,
    Expired,
    Internal(String),
}

/// Secret keying every domain's MAC.
///
/// Generated once per process by [`NonceSecret::random`]. Outstanding values
/// therefore do not survive a restart: a wallet mid-flow sees its challenge or
/// nonce rejected and must fetch a fresh one — which ABCA §8.1 and RFC 9449
/// §8.2 both make cheap, since a fresh value rides on the next response. The
/// exposed window is milliseconds, an acceptable trade for requiring no key
/// management and no persisted secret.
#[derive(Clone)]
pub struct NonceSecret([u8; 32]);

impl std::fmt::Debug for NonceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key material, even into logs or panic output.
        f.write_str("NonceSecret(redacted)")
    }
}

impl NonceSecret {
    /// Generate a fresh random secret. Call once at startup.
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    /// Construct from caller-supplied key material (used by tests, and by any
    /// future configuration-driven secret).
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }

    fn hmac(&self) -> Result<HmacSha256, IssuanceError> {
        HmacSha256::new_from_slice(&self.0)
            .map_err(|e| IssuanceError::Internal(format!("unable to key the challenge MAC: {e}")))
    }
}

/// MAC input: `label || 0x00 || payload`.
fn mac_input(domain: Domain, payload: &[u8]) -> Vec<u8> {
    let label = domain.label();
    let mut input = Vec::with_capacity(label.len() + 1 + payload.len());
    input.extend_from_slice(label);
    input.push(0u8);
    input.extend_from_slice(payload);
    input
}

/// Mint a value for `domain`, valid for `ttl_secs`.
///
/// `skip_all` is mandatory: the arguments include the process MAC secret, and
/// the minted value is itself a freshness secret (root `AGENTS.md` §4.5) — only
/// the fact that one was issued is logged, never the value.
#[tracing::instrument(skip_all, fields(domain = ?domain, ttl_secs = ttl_secs))]
pub(crate) fn mint(
    secret: &NonceSecret,
    domain: Domain,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<String, IssuanceError> {
    // Saturating: a caller-supplied ttl must never wrap the expiry backwards.
    let exp = now_unix.saturating_add(i64::try_from(ttl_secs).unwrap_or(i64::MAX));

    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..EXP_LEN].copy_from_slice(&exp.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut payload[EXP_LEN..]);

    let mut mac = secret.hmac()?;
    mac.update(&mac_input(domain, &payload));
    let full = mac.finalize().into_bytes();

    let mut raw = [0u8; VALUE_LEN];
    raw[..PAYLOAD_LEN].copy_from_slice(&payload);
    raw[PAYLOAD_LEN..].copy_from_slice(&full[..TAG_LEN]);

    tracing::debug!("minted a server-provided freshness value");
    Ok(B64URL.encode(raw))
}

/// Verify a value for `domain`: authentic MAC first, then expiry.
///
/// The MAC is checked before the embedded expiry is read, because until the MAC
/// verifies, that expiry is attacker-supplied.
///
/// `skip_all` is mandatory: the arguments are the MAC secret and the presented
/// value, both secrets per root `AGENTS.md` §4.5.
#[tracing::instrument(skip_all, fields(domain = ?domain))]
pub(crate) fn verify(
    secret: &NonceSecret,
    domain: Domain,
    value: &str,
    now_unix: i64,
) -> Result<(), ChallengeFailure> {
    let raw = B64URL
        .decode(value)
        .map_err(|_| ChallengeFailure::NotBase64Url)?;

    if raw.len() != VALUE_LEN {
        return Err(ChallengeFailure::WrongLength);
    }

    let (payload, tag) = raw.split_at(PAYLOAD_LEN);

    let mut mac = secret
        .hmac()
        .map_err(|e| ChallengeFailure::Internal(e.to_string()))?;
    mac.update(&mac_input(domain, payload));
    if mac.verify_truncated_left(tag).is_err() {
        return Err(ChallengeFailure::NotIssuedHere);
    }

    let mut exp_bytes = [0u8; EXP_LEN];
    exp_bytes.copy_from_slice(&payload[..EXP_LEN]);
    if now_unix > i64::from_be_bytes(exp_bytes) {
        return Err(ChallengeFailure::Expired);
    }

    Ok(())
}

/// Wire shape of the ABCA §8 challenge endpoint response.
///
/// §8 defines exactly one member: "attestation_challenge: REQUIRED if the
/// authorization server supports Client Attestations and server provided
/// challenges as described in this document." §8 also permits the server to
/// "add additional challenges or data"; foundry adds none, so a wallet sees a
/// minimal, unambiguous document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct ChallengeResponse {
    pub attestation_challenge: String,
}

/// Mint an ABCA §8 `attestation_challenge`.
///
/// `ttl_secs` is the caller's `issuer.wallet_attestation.pop_max_age_secs`: a
/// challenge outliving the window in which its PoP would be accepted anyway is
/// useless, so the two are deliberately the same number rather than two knobs
/// an operator must keep aligned.
///
/// `skip_all` is mandatory: the argument is the process MAC secret and the
/// result is a freshness secret (root `AGENTS.md` §4.5).
#[tracing::instrument(skip_all)]
pub fn issue_attestation_challenge(
    secret: &NonceSecret,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<ChallengeResponse, IssuanceError> {
    Ok(ChallengeResponse {
        attestation_challenge: mint(secret, Domain::AttestationChallenge, ttl_secs, now_unix)?,
    })
}

/// Mint an RFC 9449 §8/§9 server-provided DPoP `nonce`.
///
/// Returns the bare string rather than a wrapper type: unlike the ABCA
/// challenge, a DPoP nonce is delivered only in a header, never in a JSON body,
/// so there is no wire shape to model.
///
/// `skip_all` is mandatory: the argument is the process MAC secret and the
/// result is a freshness secret (root `AGENTS.md` §4.5).
#[tracing::instrument(skip_all)]
pub fn mint_dpop_nonce(
    secret: &NonceSecret,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<String, IssuanceError> {
    mint(secret, Domain::DpopNonce, ttl_secs, now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;
    const TTL: u64 = 300;

    fn secret() -> NonceSecret {
        NonceSecret::from_bytes([7u8; 32])
    }

    #[test]
    fn a_minted_value_verifies_in_its_own_domain() {
        let s = secret();
        let v = mint(&s, Domain::DpopNonce, TTL, NOW).unwrap();
        assert!(verify(&s, Domain::DpopNonce, &v, NOW).is_ok());
        assert!(verify(&s, Domain::DpopNonce, &v, NOW + TTL as i64 - 1).is_ok());
    }

    /// The reason this module exists: a value minted for one purpose must not
    /// be accepted for another, or a wallet could present a `c_nonce` where
    /// RFC 9449 §8 requires a nonce the server issued for *that* purpose.
    #[test]
    fn a_c_nonce_is_rejected_as_a_dpop_nonce() {
        let s = secret();
        let v = mint(&s, Domain::CNonce, TTL, NOW).unwrap();
        assert!(matches!(
            verify(&s, Domain::DpopNonce, &v, NOW),
            Err(ChallengeFailure::NotIssuedHere)
        ));
    }

    #[test]
    fn a_dpop_nonce_is_rejected_as_an_attestation_challenge() {
        let s = secret();
        let v = mint(&s, Domain::DpopNonce, TTL, NOW).unwrap();
        assert!(matches!(
            verify(&s, Domain::AttestationChallenge, &v, NOW),
            Err(ChallengeFailure::NotIssuedHere)
        ));
    }

    #[test]
    fn an_attestation_challenge_is_rejected_as_a_c_nonce() {
        let s = secret();
        let v = mint(&s, Domain::AttestationChallenge, TTL, NOW).unwrap();
        assert!(matches!(
            verify(&s, Domain::CNonce, &v, NOW),
            Err(ChallengeFailure::NotIssuedHere)
        ));
    }

    #[test]
    fn a_value_past_its_ttl_is_expired() {
        let s = secret();
        let v = mint(&s, Domain::AttestationChallenge, TTL, NOW).unwrap();
        assert!(matches!(
            verify(&s, Domain::AttestationChallenge, &v, NOW + TTL as i64 + 1),
            Err(ChallengeFailure::Expired)
        ));
    }

    #[test]
    fn a_value_from_another_secret_is_rejected() {
        let v = mint(&secret(), Domain::DpopNonce, TTL, NOW).unwrap();
        let other = NonceSecret::from_bytes([9u8; 32]);
        assert!(matches!(
            verify(&other, Domain::DpopNonce, &v, NOW),
            Err(ChallengeFailure::NotIssuedHere)
        ));
    }

    /// The MAC must be checked before the embedded expiry is trusted: until the
    /// MAC verifies, that expiry is attacker-supplied.
    #[test]
    fn a_tampered_expiry_is_rejected_as_unissued_not_accepted() {
        let s = secret();
        let v = mint(&s, Domain::DpopNonce, TTL, NOW).unwrap();
        let mut raw = B64URL.decode(&v).unwrap();
        raw[..EXP_LEN].copy_from_slice(&i64::MAX.to_be_bytes());
        let forged = B64URL.encode(&raw);
        assert!(matches!(
            verify(&s, Domain::DpopNonce, &forged, NOW),
            Err(ChallengeFailure::NotIssuedHere)
        ));
    }

    #[test]
    fn malformed_values_are_rejected() {
        let s = secret();
        assert!(matches!(
            verify(&s, Domain::DpopNonce, "!!!not base64!!!", NOW),
            Err(ChallengeFailure::NotBase64Url)
        ));
        assert!(matches!(
            verify(&s, Domain::DpopNonce, "", NOW),
            Err(ChallengeFailure::WrongLength)
        ));
        assert!(matches!(
            verify(&s, Domain::DpopNonce, &B64URL.encode([0u8; 8]), NOW),
            Err(ChallengeFailure::WrongLength)
        ));
    }

    /// OpenID4VCI §7.2 / ABCA §8: challenge values must be unpredictable.
    #[test]
    fn successive_mints_differ_within_the_same_second() {
        let s = secret();
        let a = mint(&s, Domain::AttestationChallenge, TTL, NOW).unwrap();
        let b = mint(&s, Domain::AttestationChallenge, TTL, NOW).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_secret_never_renders_its_key_material() {
        assert_eq!(format!("{:?}", secret()), "NonceSecret(redacted)");
    }
}
