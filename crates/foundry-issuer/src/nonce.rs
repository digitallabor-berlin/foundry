//! Stateless `c_nonce` minting and verification for the OpenID4VCI Nonce
//! Endpoint (OpenID4VCI 1.0, Section 7).
//!
//! Section 7.1 makes the Nonce Endpoint explicitly unauthenticated — "The
//! Nonce Endpoint is not a protected resource, meaning the Wallet does not
//! need to supply an access token to access it" — so the issuer has no
//! transaction context when minting a nonce and cannot persist it against
//! one. Nonces are therefore self-contained and authenticated by a MAC
//! instead of being looked up in storage.
//!
//! The wire format and its domain separation live in [`crate::challenge`].
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

use crate::challenge::{ChallengeFailure, Domain};
use crate::error::IssuanceError;
use serde::{Deserialize, Serialize};

/// Re-exported so `foundry_issuer::nonce::NonceSecret` keeps resolving; the
/// type now lives in [`crate::challenge`] because all three freshness domains
/// share it.
pub use crate::challenge::NonceSecret;

/// Validity window of a minted `c_nonce`, in seconds.
pub const C_NONCE_TTL_SECS: u64 = 600;

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

/// Mint a fresh `c_nonce` valid for [`C_NONCE_TTL_SECS`].
/// `skip_all` is mandatory: the argument is the process's `c_nonce` MAC secret.
/// The minted nonce is likewise never logged — only that one was issued.
#[tracing::instrument(skip_all)]
pub fn issue_nonce(secret: &NonceSecret, now_unix: i64) -> Result<NonceResponse, IssuanceError> {
    tracing::debug!(ttl_secs = C_NONCE_TTL_SECS, "issuing c_nonce");
    Ok(NonceResponse {
        c_nonce: crate::challenge::mint(secret, Domain::CNonce, C_NONCE_TTL_SECS, now_unix)?,
        c_nonce_expires_in: C_NONCE_TTL_SECS,
    })
}

/// Verify a `c_nonce` presented in a holder proof: authentic MAC, then expiry.
///
/// `skip_all` is mandatory: the arguments are the MAC secret and the `c_nonce`
/// value itself.
#[tracing::instrument(skip_all)]
pub fn verify_nonce(
    secret: &NonceSecret,
    c_nonce: &str,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    // OpenID4VCI 1.0 Credential Error Response (L1050): every failure below is
    // a *present* c_nonce that is invalid (malformed, forged, or expired), so
    // each reports `InvalidNonce` rather than `InvalidProof` -- the L1049
    // clause-3 "missing c_nonce" case lives at the proof-payload level
    // (proof.rs), one layer above this function, and stays `InvalidProof`.
    //
    // Messages are preserved verbatim from the pre-`challenge.rs`
    // implementation: existing tests assert on them, and GAP-VCI-04 requires
    // `InvalidNonce` to stay a distinct variant.
    crate::challenge::verify(secret, Domain::CNonce, c_nonce, now_unix).map_err(|f| match f {
        ChallengeFailure::NotBase64Url => {
            IssuanceError::InvalidNonce("c_nonce is not valid base64url".into())
        }
        ChallengeFailure::WrongLength => {
            IssuanceError::InvalidNonce("c_nonce has an unexpected length".into())
        }
        ChallengeFailure::NotIssuedHere => {
            IssuanceError::InvalidNonce("c_nonce was not issued by this issuer".into())
        }
        ChallengeFailure::Expired => IssuanceError::InvalidNonce("c_nonce has expired".into()),
        ChallengeFailure::Internal(e) => IssuanceError::Internal(e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;

    const EXP_LEN: usize = crate::challenge::EXP_LEN;

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
