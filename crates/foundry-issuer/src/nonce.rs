//! Stateless `c_nonce` minting and verification for the OpenID4VCI Nonce
//! Endpoint (OpenID4VCI 1.0, Section 7).
//!
//! Section 7.1 makes the Nonce Endpoint explicitly unauthenticated — "The
//! Nonce Endpoint is not a protected resource, meaning the Wallet does not
//! need to supply an access token to access it" — so the issuer has no
//! transaction context when minting a nonce and cannot persist it against
//! one. Nonces are therefore self-contained and authenticated by a MAC
//! instead of being looked up in storage:
//!
//! ```text
//! c_nonce = base64url( exp:i64be(8) || salt(16) || HMAC-SHA256(secret, exp||salt)[..16] )
//! ```
//!
//! Statelessness is what makes leaving the endpoint unauthenticated safe: no
//! request writes a row, so an anonymous caller cannot grow the database.
//! That is precisely the denial-of-service objection raised against the
//! unprotected endpoint in OpenID4VCI issue #461. The 16-byte random salt
//! satisfies Section 7.2's requirement that challenge values be unpredictable.
//!
//! Single-use semantics come from the transaction lifecycle rather than from
//! nonce bookkeeping: `handle_credential_request` rejects any transaction
//! whose state is not `Offered`, so the access token a nonce is presented
//! alongside can be redeemed at most once however often the nonce is replayed.

use crate::error::IssuanceError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Validity window of a minted `c_nonce`, in seconds.
pub const C_NONCE_TTL_SECS: u64 = 600;

const EXP_LEN: usize = 8;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const PAYLOAD_LEN: usize = EXP_LEN + SALT_LEN;
const NONCE_LEN: usize = PAYLOAD_LEN + TAG_LEN;

/// Wire shape of the Nonce Endpoint response (OpenID4VCI 1.0 Section 7.2).
///
/// `c_nonce` is the only member the specification defines; `c_nonce_expires_in`
/// is emitted as a non-normative convenience so clients can avoid presenting a
/// nonce they already know to be stale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct NonceResponse {
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}

/// Secret keying the `c_nonce` MAC.
///
/// Generated once per process by [`NonceSecret::random`]. Outstanding nonces
/// therefore do not survive a restart: a wallet that fetched a nonce and is
/// interrupted by a restart before reaching `/credential` sees `invalid_proof`
/// and must restart issuance. The exposed window is the few milliseconds
/// between `/nonce` and `/credential`, which is an acceptable trade for
/// requiring no key management and no persisted secret.
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
            .map_err(|e| IssuanceError::Internal(format!("unable to key the c_nonce MAC: {e}")))
    }

    fn tag(&self, payload: &[u8]) -> Result<[u8; TAG_LEN], IssuanceError> {
        let mut mac = self.hmac()?;
        mac.update(payload);
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&full[..TAG_LEN]);
        Ok(tag)
    }

    /// Constant-time check that `tag` is this secret's MAC over `payload`.
    fn tag_matches(&self, payload: &[u8], tag: &[u8]) -> Result<bool, IssuanceError> {
        let mut mac = self.hmac()?;
        mac.update(payload);
        Ok(mac.verify_truncated_left(tag).is_ok())
    }
}

/// Mint a fresh `c_nonce` valid for [`C_NONCE_TTL_SECS`].
/// `skip_all` is mandatory: the argument is the process's `c_nonce` MAC secret.
/// The minted nonce is likewise never logged — only that one was issued.
#[tracing::instrument(skip_all)]
pub fn issue_nonce(secret: &NonceSecret, now_unix: i64) -> Result<NonceResponse, IssuanceError> {
    tracing::debug!(ttl_secs = C_NONCE_TTL_SECS, "issuing c_nonce");
    let exp = now_unix + C_NONCE_TTL_SECS as i64;

    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..EXP_LEN].copy_from_slice(&exp.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut payload[EXP_LEN..]);

    let mut raw = [0u8; NONCE_LEN];
    raw[..PAYLOAD_LEN].copy_from_slice(&payload);
    raw[PAYLOAD_LEN..].copy_from_slice(&secret.tag(&payload)?);

    Ok(NonceResponse {
        c_nonce: B64URL.encode(raw),
        c_nonce_expires_in: C_NONCE_TTL_SECS,
    })
}

/// Verify a `c_nonce` presented in a holder proof: authentic MAC, then expiry.
///
/// The MAC is checked before the embedded expiry is trusted, because that
/// expiry is attacker-supplied until the MAC proves this issuer minted it.
/// `skip_all` is mandatory: the arguments are the MAC secret and the `c_nonce`
/// value itself.
#[tracing::instrument(skip_all)]
pub fn verify_nonce(
    secret: &NonceSecret,
    c_nonce: &str,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    let raw = B64URL
        .decode(c_nonce)
        .map_err(|_| IssuanceError::InvalidProof("c_nonce is not valid base64url".into()))?;

    if raw.len() != NONCE_LEN {
        return Err(IssuanceError::InvalidProof(
            "c_nonce has an unexpected length".into(),
        ));
    }

    let (payload, tag) = raw.split_at(PAYLOAD_LEN);

    if !secret.tag_matches(payload, tag)? {
        // Forged, tampered with, or minted by a previous process lifetime.
        return Err(IssuanceError::InvalidProof(
            "c_nonce was not issued by this issuer".into(),
        ));
    }

    let mut exp_bytes = [0u8; EXP_LEN];
    exp_bytes.copy_from_slice(&payload[..EXP_LEN]);
    let exp = i64::from_be_bytes(exp_bytes);
    if now_unix > exp {
        return Err(IssuanceError::InvalidProof("c_nonce has expired".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> NonceSecret {
        NonceSecret::from_bytes([7u8; 32])
    }

    #[test]
    fn minted_nonce_verifies_within_its_ttl() {
        let s = secret();
        let now = 1_700_000_000;
        let res = issue_nonce(&s, now).unwrap();

        assert_eq!(res.c_nonce_expires_in, C_NONCE_TTL_SECS);
        assert!(verify_nonce(&s, &res.c_nonce, now).is_ok());
        assert!(verify_nonce(&s, &res.c_nonce, now + C_NONCE_TTL_SECS as i64 - 1).is_ok());
    }

    #[test]
    fn rejects_nonce_past_its_expiry() {
        let s = secret();
        let now = 1_700_000_000;
        let res = issue_nonce(&s, now).unwrap();

        let err = verify_nonce(&s, &res.c_nonce, now + C_NONCE_TTL_SECS as i64 + 1)
            .expect_err("expired nonce must be rejected");
        assert!(err.to_string().contains("expired"), "got: {err}");
    }

    #[test]
    fn rejects_nonce_minted_under_a_different_secret() {
        let res = issue_nonce(&secret(), 1_700_000_000).unwrap();
        let other = NonceSecret::from_bytes([9u8; 32]);

        let err = verify_nonce(&other, &res.c_nonce, 1_700_000_000)
            .expect_err("nonce from another issuer must be rejected");
        assert!(
            err.to_string().contains("not issued by this issuer"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_nonce_with_a_tampered_expiry() {
        let s = secret();
        let now = 1_700_000_000;
        let res = issue_nonce(&s, now).unwrap();

        // Push the embedded expiry far into the future without re-MACing it.
        let mut raw = B64URL.decode(&res.c_nonce).unwrap();
        raw[..EXP_LEN].copy_from_slice(&i64::MAX.to_be_bytes());
        let forged = B64URL.encode(&raw);

        let err = verify_nonce(&s, &forged, now).expect_err("tampered nonce must be rejected");
        assert!(
            err.to_string().contains("not issued by this issuer"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_malformed_nonces() {
        let s = secret();
        let now = 1_700_000_000;

        // An opaque string that was never minted here — the shape of nonce the
        // transaction-bound implementation used to hand out.
        assert!(verify_nonce(&s, "cn_deadbeef", now).is_err());
        assert!(verify_nonce(&s, "!!!not base64!!!", now).is_err());
        assert!(verify_nonce(&s, "", now).is_err());
        // Well-formed base64url, wrong length.
        assert!(verify_nonce(&s, &B64URL.encode([0u8; 8]), now).is_err());
    }

    #[test]
    fn successive_nonces_differ() {
        let s = secret();
        let a = issue_nonce(&s, 1_700_000_000).unwrap().c_nonce;
        let b = issue_nonce(&s, 1_700_000_000).unwrap().c_nonce;
        // Same second, so only the random salt distinguishes them — this is
        // Section 7.2's "MUST be unpredictable" property.
        assert_ne!(a, b);
    }
}
