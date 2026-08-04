# ABCA Challenge Retrieval and DPoP Server-Provided Nonces — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add config-gated, default-off support for ABCA §8 challenge retrieval and RFC 9449 §8/§9 server-provided DPoP nonces, so a wallet that requires server-supplied freshness values (e.g. Google Wallet) can complete issuance.

**Architecture:** One new domain-separated MAC primitive (`challenge.rs`) mints and verifies all three kinds of issuer-minted opaque freshness value (`c_nonce`, ABCA `attestation_challenge`, DPoP `nonce`). Two new `Mode` config toggles gate the two mechanisms independently; each gets its own spec-mandated error code plus a response header carrying a fresh value so a wallet can retry.

**Tech Stack:** Rust, axum, `hmac`/`sha2`, `josekit`, `utoipa`, `serde`.

**Spec:** [`docs/superpowers/specs/2026-08-04-abca-challenge-and-dpop-nonce-design.md`](../specs/2026-08-04-abca-challenge-and-dpop-nonce-design.md)

## Global Constraints

- **Read `crates/<x>/AGENTS.md` before editing files under `crates/<x>/`.** It is not auto-loaded.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` in request paths** (root `AGENTS.md` §4.1). Permitted only in `#[cfg(test)]` and `tests/`.
- **Every `#[tracing::instrument]` MUST carry `skip_all`** (§4.5).
- **Never log, at any level, under any flag:** attestation challenges, DPoP nonces, `c_nonce` values, the nonce secret, access tokens, holder proofs, PoP JWTs, `jti` values.
- **Cite the spec in code comments** for every protocol-facing change (§4.4): `// ABCA §9 rule 8 — ...`, `// RFC 9449 §4.3 check 10 — ...`.
- **Scoped gate only** (§5.1): `cargo test -p foundry-issuer -p foundry`, `cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings`, `cargo fmt --check`. **Do NOT run `cargo test --workspace`.** Tasks touching `foundry-core` config additionally run `-p foundry-core`.
- **Both features default to `Mode::Disabled`.** `Mode::default()` is `Optional`, so `#[serde(default)]` alone is a bug — use the explicit `default_disabled` fn.
- **Regression discipline:** no existing test's *assertions or expected outcomes* may change. Mechanical signature-propagation edits (appending an argument at an existing call site) are expected and fine. If an existing test's expected status code, error code, or body must change to stay green, that is a defect — stop and report it.
- **Match surrounding style.** Before writing a test, read the nearest existing test in that file and reuse its helpers and construction shape rather than inventing new ones.

---

### Task 1: Domain-separated MAC primitive

**Files:**
- Create: `crates/foundry-issuer/src/challenge.rs`
- Modify: `crates/foundry-issuer/src/nonce.rs` (delegate to the primitive)
- Modify: `crates/foundry-issuer/src/lib.rs` (declare the module)
- Test: unit tests inside `crates/foundry-issuer/src/challenge.rs`

**Interfaces:**
- Consumes: nothing — this is the foundation task.
- Produces:
  - `pub(crate) enum Domain { CNonce, AttestationChallenge, DpopNonce }`
  - `pub(crate) enum ChallengeFailure { NotBase64Url, WrongLength, NotIssuedHere, Expired, Internal(String) }`
  - `pub(crate) fn mint(secret: &NonceSecret, domain: Domain, ttl_secs: u64, now_unix: i64) -> Result<String, IssuanceError>`
  - `pub(crate) fn verify(secret: &NonceSecret, domain: Domain, value: &str, now_unix: i64) -> Result<(), ChallengeFailure>`
  - `pub struct NonceSecret` **moves here** from `nonce.rs`; `nonce.rs` re-exports it so both `foundry_issuer::NonceSecret` and `foundry_issuer::nonce::NonceSecret` still resolve.
  - `pub(crate) const EXP_LEN / SALT_LEN / TAG_LEN / PAYLOAD_LEN / VALUE_LEN: usize`

`verify` returns `ChallengeFailure`, **not** `IssuanceError`. Each caller maps it to its own spec-mandated error variant with its own wording — that is what lets `verify_nonce` keep its exact existing `InvalidNonce` messages (GAP-VCI-04 requires that variant stay distinct).

- [ ] **Step 1: Write the failing tests**

Create `crates/foundry-issuer/src/challenge.rs` containing only this test module. It will not compile until Step 3 — that is the failure signal.

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib challenge
```

Expected: compilation failure — `module 'challenge' not found` (until Step 3 adds the `pub mod` line), then `cannot find function 'mint'` / `cannot find type 'Domain'`.

- [ ] **Step 3: Write the primitive**

Add `pub mod challenge;` to `crates/foundry-issuer/src/lib.rs`, keeping the list alphabetical (after `pub mod authorize;`, before `pub mod create_offer;`).

Put this **above** the test module in `crates/foundry-issuer/src/challenge.rs`:

```rust
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
```

`Serialize`/`Deserialize` are imported here for `ChallengeResponse`, added in Task 5. If clippy flags them as unused at this step, leave the import out and add it in Task 5.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib challenge
```

Expected: all 10 tests PASS.

- [ ] **Step 5: Rewire `nonce.rs` onto the primitive**

In `crates/foundry-issuer/src/nonce.rs`, replace the imports and constants:

```rust
use crate::challenge::{ChallengeFailure, Domain};
use crate::error::IssuanceError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Re-exported so `foundry_issuer::nonce::NonceSecret` keeps resolving; the
/// type now lives in [`crate::challenge`] because all three freshness domains
/// share it.
pub use crate::challenge::NonceSecret;

/// Validity window of a minted `c_nonce`, in seconds.
pub const C_NONCE_TTL_SECS: u64 = 600;

// Byte layout lives in `challenge.rs`; aliased here so this module's existing
// tests, which poke at the raw encoding, keep their current names.
const EXP_LEN: usize = crate::challenge::EXP_LEN;
const NONCE_LEN: usize = crate::challenge::VALUE_LEN;
```

Delete from `nonce.rs`: the `HmacSha256` alias, `SALT_LEN`, `TAG_LEN`, `PAYLOAD_LEN`, the whole `pub struct NonceSecret` block with its `impl Debug` and `impl NonceSecret` (moved in Step 3), and the now-unused `hmac` / `rand` / `sha2` imports.

Replace both public function bodies:

```rust
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
```

Also update `nonce.rs`'s module doc: the ASCII-art format block now lives in `challenge.rs`, so replace it with a pointer line — ``//! The wire format and its domain separation live in [`crate::challenge`].``

- [ ] **Step 6: Prove the refactor is behaviour-preserving**

```bash
cargo test -p foundry-issuer
```

Expected: PASS, including every pre-existing `nonce` test (`minted_nonce_verifies_within_its_ttl`, `rejects_nonce_past_its_expiry`, `rejects_nonce_minted_under_a_different_secret`, `rejects_nonce_with_a_tampered_expiry`, `rejects_malformed_nonces`, `successive_nonces_differ`) **with no edits to those tests**. If any needed editing, stop and report — the refactor changed behaviour.

- [ ] **Step 7: Lint and format**

```bash
cargo fmt
cargo clippy -p foundry-issuer --all-targets -- -D warnings
```

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-issuer/src/challenge.rs crates/foundry-issuer/src/nonce.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): domain-separated MAC primitive for freshness values"
```

---

### Task 2: Config toggles

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs`
- Test: the existing test module in `crates/foundry-core/src/config/model.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `AttestationMode.challenge_mode: Mode` — read **only** for `issuer.wallet_attestation`.
  - `DpopConfig.nonce_mode: Mode`
  - `fn default_disabled() -> Mode`
  - Both fields default to `Mode::Disabled`.

- [ ] **Step 1: Write the failing tests**

```rust
/// Both new toggles default to `Disabled`, not to `Mode::default()`
/// (`Optional`). A wrong default would silently turn on ABCA challenge
/// retrieval and DPoP nonces for every existing deployment.
#[test]
fn challenge_and_nonce_modes_default_to_disabled() {
    let attestation: AttestationMode = serde_json::from_str("{}").expect("attestation");
    assert_eq!(attestation.challenge_mode, Mode::Disabled);
    // The pre-existing default is unchanged.
    assert_eq!(attestation.mode, Mode::Optional);

    let dpop: DpopConfig = serde_json::from_str("{}").expect("dpop");
    assert_eq!(dpop.nonce_mode, Mode::Disabled);
    assert_eq!(dpop.mode, Mode::Optional);
}

/// `Default::default()` must agree with serde's default, or a `..Default::default()`
/// struct literal anywhere in the codebase would enable the features silently.
#[test]
fn the_default_impls_agree_with_serde() {
    assert_eq!(AttestationMode::default().challenge_mode, Mode::Disabled);
    assert_eq!(DpopConfig::default().nonce_mode, Mode::Disabled);
}

#[test]
fn challenge_and_nonce_modes_are_settable() {
    let attestation: AttestationMode =
        serde_json::from_str(r#"{"challenge_mode":"required"}"#).expect("attestation");
    assert_eq!(attestation.challenge_mode, Mode::Required);

    let dpop: DpopConfig =
        serde_json::from_str(r#"{"nonce_mode":"optional"}"#).expect("dpop");
    assert_eq!(dpop.nonce_mode, Mode::Optional);
}
```

`Mode` already derives `PartialEq`, so these assertions need no new derive on the containing structs.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-core --lib config
```

Expected: `no field 'challenge_mode' on type 'AttestationMode'`.

- [ ] **Step 3: Add the fields**

In `pub struct AttestationMode`, after `pop_max_age_secs`:

```rust
    /// ABCA draft -07 §8 challenge retrieval.
    ///
    /// - `disabled` (default) — no `/challenge` route, `challenge_endpoint` is
    ///   absent from AS metadata, and a `challenge` claim in a Client
    ///   Attestation PoP is ignored. Reproduces pre-challenge behaviour exactly.
    /// - `optional` — the route is served and advertised, but a PoP without a
    ///   `challenge` claim is still accepted. The migration rung: wallets adopt
    ///   at their own pace.
    /// - `required` — the route is served and advertised, and a PoP with no
    ///   `challenge` claim is rejected with `use_attestation_challenge` (§6.2).
    ///
    /// Consulted **only** for `issuer.wallet_attestation` -- `AttestationMode`
    /// is shared with `issuer.key_attestation`, which has no PoP and therefore
    /// no challenge mechanism, and never reads this field. Same restriction as
    /// `pop_max_age_secs` above.
    #[serde(default = "default_disabled")]
    pub challenge_mode: Mode,
```

In `pub struct DpopConfig`, after `max_age_secs`:

```rust
    /// RFC 9449 §8 (authorization server) and §9 (resource server)
    /// server-provided nonce.
    ///
    /// - `disabled` (default) — no `DPoP-Nonce` header is ever emitted and a
    ///   `nonce` claim is ignored, so §11.3 is satisfied vacuously (the
    ///   pre-nonce behaviour recorded in the 2026-08-03 DPoP design §2.2).
    /// - `optional` — a `DPoP-Nonce` is supplied and a presented `nonce` is
    ///   verified, but a proof without one is still accepted.
    /// - `required` — a proof without a valid `nonce` is rejected with
    ///   `use_dpop_nonce` plus a fresh `DPoP-Nonce` header. This is what closes
    ///   §11.2 (proof pre-generation).
    #[serde(default = "default_disabled")]
    pub nonce_mode: Mode,
```

Add next to `default_dpop_max_age_secs`:

```rust
/// Both ABCA challenge retrieval and DPoP nonces default to **off**.
///
/// Deliberately not `#[serde(default)]`: `Mode::default()` is `Optional`, which
/// would silently enable both mechanisms on every existing deployment.
fn default_disabled() -> Mode {
    Mode::Disabled
}
```

Extend `impl Default for DpopConfig` with `nonce_mode: default_disabled(),`.

`AttestationMode` currently *derives* `Default`, which would give `challenge_mode` the value `Mode::default()` (`Optional`). Remove `Default` from its `#[derive(...)]` and add:

```rust
// Hand-written rather than derived: the derive would give `challenge_mode` the
// `Mode::default()` value (`Optional`), silently enabling ABCA challenge
// retrieval for any code path building this struct with `..Default::default()`.
impl Default for AttestationMode {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            trusted_anchors: Vec::new(),
            pop_max_age_secs: default_pop_max_age_secs(),
            challenge_mode: default_disabled(),
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-core --lib config
```

Expected: all three new tests PASS.

- [ ] **Step 5: Fix the struct-literal fallout in dependents**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
```

Expected: PASS. Any compilation error here is an exhaustive-struct-literal error in a test fixture (e.g. `metadata.rs`'s test module and fixtures under `crates/foundry/tests/`). Fix each by adding `challenge_mode: Mode::Disabled` / `nonce_mode: Mode::Disabled`, or by switching to `..Default::default()` where the surrounding code already does. These are mechanical additions — no assertion may change.

- [ ] **Step 6: Lint, format, commit**

```bash
cargo fmt
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
git add -A
git commit -m "feat(core): config toggles for ABCA challenge retrieval and DPoP nonces"
```

---

### Task 3: Spec-mandated error variants

**Files:**
- Modify: `crates/foundry-issuer/src/error.rs`
- Test: the existing test module in `crates/foundry-issuer/src/error.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `IssuanceError::UseAttestationChallenge(String)` → `kind() == "use_attestation_challenge"`
  - `IssuanceError::UseDpopNonce(String)` → `kind() == "use_dpop_nonce"`

- [ ] **Step 1: Write the failing test**

The existing test module has a table pairing each variant with its wire code (see the `(IssuanceError::InvalidDpopProof(s()), "invalid_dpop_proof")` entry). Add the two new pairs to that table, and add:

```rust
/// ABCA §6.2 and RFC 9449 §8 each mandate a *specific* error code that a wallet
/// keys its retry logic on. Collapsing either into a generic `invalid_client` /
/// `invalid_dpop_proof` would leave a compliant wallet unable to tell a
/// retriable condition from a permanent failure.
#[test]
fn challenge_and_nonce_errors_carry_their_own_wire_codes() {
    assert_eq!(
        IssuanceError::UseAttestationChallenge("x".into()).kind(),
        "use_attestation_challenge"
    );
    assert_eq!(
        IssuanceError::UseDpopNonce("x".into()).kind(),
        "use_dpop_nonce"
    );
    assert_ne!(
        IssuanceError::UseDpopNonce("x".into()).kind(),
        IssuanceError::InvalidDpopProof("x".into()).kind()
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p foundry-issuer --lib error
```

Expected: `no variant named 'UseAttestationChallenge'`.

- [ ] **Step 3: Add the variants**

Add to `pub enum IssuanceError` next to `InvalidDpopProof`. Copy the `#[error("...")]` `thiserror` attribute shape from the neighbouring `InvalidDpopProof` variant.

```rust
    /// ABCA draft -07 §6.2: "use_attestation_challenge MUST be used when the
    /// Client Attestation PoP JWT is not using an expected server-provided
    /// challenge. When used this error code MUST be accompanied by the
    /// OAuth-Client-Attestation-Challenge HTTP header field parameter."
    ///
    /// Distinct from `InvalidClient` deliberately: this condition is *retriable*
    /// once the wallet picks up the fresh challenge the response carries, and
    /// only a distinct code tells it so.
    UseAttestationChallenge(String),

    /// RFC 9449 §8/§9: the error code accompanying a `DPoP-Nonce` header when a
    /// proof carried no nonce, or one that did not match.
    ///
    /// Distinct from `InvalidDpopProof` deliberately, for the same reason as
    /// `UseAttestationChallenge`: §8 states the client "will typically retry the
    /// request with the new nonce value supplied upon receiving a
    /// use_dpop_nonce error".
    UseDpopNonce(String),
```

And in `kind()`:

```rust
            IssuanceError::UseAttestationChallenge(_) => "use_attestation_challenge",
            IssuanceError::UseDpopNonce(_) => "use_dpop_nonce",
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p foundry-issuer --lib error
```

- [ ] **Step 5: Confirm nothing else breaks — and do NOT map the status codes yet**

```bash
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
```

`server.rs`'s `wallet_error_response` has a `_ =>` catch-all, so this compiles — the new variants currently fall to `INTERNAL_SERVER_ERROR`. Leave it: Tasks 6 and 8 introduce the status code together with the mandatory header, so the two can never ship apart. Record that in the commit message.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/error.rs
git commit -m "feat(issuer): add use_attestation_challenge and use_dpop_nonce error variants

HTTP status and header mapping follow in the tasks that wire the challenge
and nonce responses; until then both fall to the server_error catch-all in
wallet_error_response."
```
---

### Task 4: ABCA challenge verification in the PoP (check 9)

**Files:**
- Modify: `crates/foundry-issuer/src/attestation.rs` (the `WalletAttestationVerifier` trait, `DefaultAttestationVerifier`'s impl, `validate_client_attestation_pop_jwt`)
- Modify: `crates/foundry-issuer/src/token.rs` (`handle_token_request`'s signature and the `verify_wallet_attestation` call site, ~line 76)
- Modify: `crates/foundry/src/server.rs` (`token_handler`'s call to `handle_token_request`)
- Test: unit tests inside `crates/foundry-issuer/src/attestation.rs`

**Interfaces:**
- Consumes: `challenge::{mint, verify, Domain, NonceSecret}` (Task 1), `AttestationMode.challenge_mode` (Task 2), `IssuanceError::UseAttestationChallenge` (Task 3).
- Produces:
  - `validate_client_attestation_pop_jwt` gains two trailing parameters: `challenge_mode: Mode`, `nonce_secret: &crate::challenge::NonceSecret`.
  - `WalletAttestationVerifier::verify_wallet_attestation` gains the same two trailing parameters.
  - `handle_token_request` gains `nonce_secret: &crate::challenge::NonceSecret`, positioned directly after `dpop: &DpopPresentation<'_>`.

- [ ] **Step 1: Write the failing tests**

Add to the test module in `crates/foundry-issuer/src/attestation.rs`. **First read the existing `rejects_pop_missing_jti` and `rejects_pop_with_non_string_jti` tests** and copy their construction shape exactly — they build a payload via `pop_payload(iss, aud, jti, iat)`, mutate it, sign it against a test attestation, then call `validate_client_attestation_pop_jwt`. Do not invent a new helper.

Two new helpers:

```rust
    fn challenge_secret() -> crate::challenge::NonceSecret {
        crate::challenge::NonceSecret::from_bytes([3u8; 32])
    }

    /// A challenge minted the way `POST /challenge` mints one.
    fn fresh_challenge(now: i64) -> String {
        crate::challenge::mint(
            &challenge_secret(),
            crate::challenge::Domain::AttestationChallenge,
            300,
            now,
        )
        .expect("mint challenge")
    }
```

Then these twelve tests. Each body follows the shape above: build the PoP payload, optionally set `payload["challenge"]`, sign, and call
`validate_client_attestation_pop_jwt(&pop, &attestation, POP_TEST_AUD, now, 300, mode, &challenge_secret())`.

| Test name | Setup | Assertion |
|---|---|---|
| `disabled_challenge_mode_accepts_a_pop_without_a_challenge` | `Mode::Disabled`, no `challenge` claim | `is_ok()` |
| `disabled_challenge_mode_ignores_a_garbage_challenge_claim` | `Mode::Disabled`, `challenge: "not-a-real-challenge"` | `is_ok()` — ABCA §5.2 rule 1: a claim we never asked for "MUST be ignored" |
| `optional_challenge_mode_accepts_a_pop_without_a_challenge` | `Mode::Optional`, no claim | `is_ok()` |
| `optional_challenge_mode_verifies_a_present_challenge` | `Mode::Optional`, `challenge: fresh_challenge(now)` | `is_ok()` |
| `optional_challenge_mode_rejects_a_bad_present_challenge` | `Mode::Optional`, `challenge: "garbage"` | `matches!(err, IssuanceError::UseAttestationChallenge(_))` |
| `required_challenge_mode_rejects_a_pop_without_a_challenge` | `Mode::Required`, no claim | `matches!(..UseAttestationChallenge(_))` **and** `err.kind() == "use_attestation_challenge"` |
| `required_challenge_mode_accepts_a_fresh_challenge` | `Mode::Required`, `challenge: fresh_challenge(now)` | `is_ok()` |
| `an_expired_challenge_is_rejected` | `challenge: fresh_challenge(now)`, verified at `now + 301` | `matches!(..UseAttestationChallenge(_))` |
| `a_challenge_from_another_issuer_is_rejected` | challenge minted under `NonceSecret::from_bytes([4u8; 32])` | `matches!(..UseAttestationChallenge(_))` |
| `a_c_nonce_is_not_accepted_as_an_attestation_challenge` | `challenge` = a `Domain::CNonce` mint under the **same** secret | `matches!(..UseAttestationChallenge(_))` |
| `a_non_string_challenge_claim_is_rejected` | `challenge: 12345` (a JSON number) | `matches!(..UseAttestationChallenge(_))` — §5.2: "MUST specify a String value" |
| `a_stale_iat_is_reported_as_stale_not_as_a_challenge_problem` | `Mode::Required`, valid challenge, `iat = now - 10_000` | the error is **not** `UseAttestationChallenge` — Check 8 must run first |

Write the domain-separation case out in full, since it is the security-relevant one and must not be paraphrased:

```rust
    /// The domain-separation guard at this layer: a `c_nonce` is a structurally
    /// valid MAC under the very same process secret, and must still be refused
    /// here. Without `challenge.rs`'s domain label this test would fail.
    #[test]
    fn a_c_nonce_is_not_accepted_as_an_attestation_challenge() {
        let now = 1_700_000_000;
        let c_nonce = crate::challenge::mint(
            &challenge_secret(),
            crate::challenge::Domain::CNonce,
            300,
            now,
        )
        .expect("mint c_nonce");
        // ... build a PoP with `challenge` = c_nonce, sign it, then verify
        // under Mode::Required, binding the error to `err` ...
        assert!(matches!(err, IssuanceError::UseAttestationChallenge(_)));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib attestation
```

Expected: compilation failure — `this function takes 5 arguments but 7 arguments were supplied`.

- [ ] **Step 3: Add check 9**

Extend `validate_client_attestation_pop_jwt`'s signature:

```rust
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
fn validate_client_attestation_pop_jwt(
    pop_jwt: &str,
    attestation: &ValidatedAttestation,
    expected_aud: &str,
    now_unix: i64,
    max_age_secs: u64,
    challenge_mode: Mode,
    nonce_secret: &crate::challenge::NonceSecret,
) -> Result<PopClaims, IssuanceError> {
```

Insert this block **after** the existing Check 8 (`iat`) block and before the function builds its `PopClaims` return value. Order matters: a stale PoP must be reported as stale, not as a challenge problem — that is what the last test in Step 1 pins.

```rust
    // Check 9 (ABCA §9 rule 8, §5.2, §8): the `challenge` claim.
    //
    // §5.2 makes the claim OPTIONAL at the *format* level. What makes it
    // mandatory is §8: "If the Authorization Server offers a challenge
    // endpoint, the Client MUST retrieve a challenge and MUST use this
    // challenge in the OAuth-Attestation-PoP." `challenge_mode` is exactly that
    // condition -- see the design doc §4.1.
    //
    // §9 rule 9 ("creation time ... as determined by either the iat claim or a
    // server managed timestamp via the challenge claim") is satisfied on both
    // paths at once: Check 8's iat window still applies, and a verified
    // challenge additionally carries a server-minted expiry.
    match (challenge_mode, payload.get("challenge")) {
        // No challenge endpoint is offered, so §9 rule 8's precondition ("If
        // the server provided a challenge value to the client") is false. Per
        // §5.2 rule 1, a claim we did not ask for "MUST be ignored".
        (Mode::Disabled, _) => {}

        // Advertised but not yet mandatory: a wallet mid-migration is accepted.
        (Mode::Optional, None) => {}

        // §6.2: "use_attestation_challenge MUST be used when the Client
        // Attestation PoP JWT is not using an expected server-provided
        // challenge."
        (Mode::Required, None) => {
            tracing::warn!("client attestation pop carried no challenge claim");
            return Err(IssuanceError::UseAttestationChallenge(
                "client attestation pop: a server-provided challenge claim is required".into(),
            ));
        }

        (Mode::Optional | Mode::Required, Some(value)) => {
            // §5.2: the claim "MUST specify a String value", so a non-string is
            // a rejection, not an ignore.
            let challenge = value.as_str().ok_or_else(|| {
                IssuanceError::UseAttestationChallenge(
                    "client attestation pop: challenge claim is not a string".into(),
                )
            })?;
            crate::challenge::verify(
                nonce_secret,
                crate::challenge::Domain::AttestationChallenge,
                challenge,
                now_unix,
            )
            .map_err(|_| {
                // Never echoes the presented value: a challenge is a freshness
                // secret (root `AGENTS.md` §4.5). The distinct failure reasons
                // are collapsed deliberately too -- telling a client which one
                // applied would be an oracle.
                tracing::warn!("client attestation pop carried an unusable challenge");
                IssuanceError::UseAttestationChallenge(
                    "client attestation pop: challenge is malformed, expired, or was not issued by this issuer"
                        .into(),
                )
            })?;
        }
    }
```

- [ ] **Step 4: Thread the parameters through the trait and its callers**

Extend the `WalletAttestationVerifier` trait method:

```rust
    #[allow(clippy::too_many_arguments)]
    fn verify_wallet_attestation(
        &self,
        mode: Mode,
        attestation_header: Option<&str>,
        pop_header: Option<&str>,
        trust_store: &TrustStore,
        expected_aud: &str,
        now_unix: i64,
        max_age_secs: u64,
        challenge_mode: Mode,
        nonce_secret: &crate::challenge::NonceSecret,
    ) -> Result<Option<PopClaims>, IssuanceError>;
```

Update `DefaultAttestationVerifier`'s impl to accept both and forward them to `validate_client_attestation_pop_jwt`. Its `Mode::Disabled` arm returns `Ok(None)` before reaching the PoP path, so that arm needs no change.

In `crates/foundry-issuer/src/token.rs`, add one parameter to `handle_token_request`, directly after `dpop: &DpopPresentation<'_>` so the freshness/DPoP arguments stay adjacent:

    nonce_secret: &crate::challenge::NonceSecret,

Then pass both new values at the `verify_wallet_attestation` call around line 76. **Read the current call first** and mirror exactly how it passes `wallet_attestation.mode` (by value or `.clone()`) rather than guessing:

```rust
            wallet_attestation.pop_max_age_secs,
            wallet_attestation.challenge_mode.clone(),
            nonce_secret,
```

Then fix the callers:

- `crates/foundry/src/server.rs`'s `token_handler` — pass `state.nonce_secret.as_ref()`.
- any `#[cfg(test)]` caller inside `token.rs` — pass a `crate::challenge::NonceSecret::from_bytes([5u8; 32])`.

`foundry_issuer::NonceSecret` already resolves via `nonce.rs`'s re-export, so `lib.rs` needs no change in this task.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib attestation
cargo test -p foundry-issuer
```

Expected: the twelve new tests PASS; every pre-existing attestation and token test still passes with only mechanical argument additions.

- [ ] **Step 6: Run the dependent crate**

```bash
cargo test -p foundry
```

Expected: PASS. `foundry`'s fixtures default `challenge_mode` to `Disabled`, so no behaviour changes.

- [ ] **Step 7: Lint, format, commit**

```bash
cargo fmt
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
git add -A
git commit -m "feat(issuer): verify the ABCA challenge claim in the Client Attestation PoP"
```

---

### Task 5: `/challenge` endpoint and metadata advertisement

**Files:**
- Modify: `crates/foundry-issuer/src/challenge.rs` (public response type + handler-facing mint fn)
- Modify: `crates/foundry-issuer/src/lib.rs` (exports)
- Modify: `crates/foundry-issuer/src/metadata.rs` (`challenge_endpoint` field + builder)
- Modify: `crates/foundry/src/server.rs` (conditional route + handler)
- Modify: `crates/foundry/src/openapi.rs` (register the path and schema)
- Modify: `openapi.json`, `openapi-wallet.json` (regenerated, never hand-edited)
- Test: `crates/foundry-issuer/src/metadata.rs` unit tests; `crates/foundry/tests/conformance_http.rs`

**Interfaces:**
- Consumes: `challenge::{mint, Domain, NonceSecret}` (Task 1), `AttestationMode.challenge_mode` (Task 2).
- Produces:
  - `pub struct ChallengeResponse { pub attestation_challenge: String }`
  - `pub fn issue_attestation_challenge(secret: &NonceSecret, ttl_secs: u64, now_unix: i64) -> Result<ChallengeResponse, IssuanceError>`
  - `AuthorizationServerMetadata.challenge_endpoint: Option<String>`
  - Route `POST /challenge` on the wallet-facing router, registered only when enabled.

- [ ] **Step 1: Write the failing tests**

In `crates/foundry-issuer/src/metadata.rs`'s test module — **read `omits_dpop_signing_algs_when_dpop_is_disabled` first** and mirror its config-fixture helper and issuer URL; `test_config()` below is a placeholder for whatever that test actually uses.

```rust
/// ABCA §8: the metadata entry's *presence* is the support signal, and its
/// presence is what makes the `challenge` claim mandatory for clients.
/// Advertising it while ignoring every challenge would tell a wallet something
/// false -- the same reasoning already recorded for
/// `dpop_signing_alg_values_supported`.
#[test]
fn advertises_challenge_endpoint_when_challenge_mode_is_enabled() {
    let mut cfg = test_config();
    cfg.issuer.wallet_attestation.challenge_mode = Mode::Optional;
    let base = cfg.issuer.credential_issuer.trim_end_matches('/').to_string();
    let meta = build_authorization_server_metadata(&cfg);
    assert_eq!(
        meta.challenge_endpoint.as_deref(),
        Some(format!("{base}/challenge").as_str())
    );

    cfg.issuer.wallet_attestation.challenge_mode = Mode::Required;
    assert!(build_authorization_server_metadata(&cfg)
        .challenge_endpoint
        .is_some());
}

#[test]
fn omits_challenge_endpoint_when_challenge_mode_is_disabled() {
    let mut cfg = test_config();
    cfg.issuer.wallet_attestation.challenge_mode = Mode::Disabled;
    let meta = build_authorization_server_metadata(&cfg);
    assert!(meta.challenge_endpoint.is_none());

    let json = serde_json::to_value(&meta).expect("serialize");
    assert!(
        json.get("challenge_endpoint").is_none(),
        "the field must be absent from the wire form, not null"
    );
}
```

In `crates/foundry/tests/conformance_http.rs` — **read its existing router / `AppState` setup helper first** and reuse it rather than building a new one. Four tests:

| Test name | What it does | Assertion |
|---|---|---|
| `challenge_endpoint_mints_a_challenge_when_enabled` | `challenge_mode = Optional`; `POST /challenge` | 200, `Cache-Control: no-store` (a §8 **MUST**), non-empty `attestation_challenge` in the body |
| `challenge_endpoint_is_absent_when_disabled` | `challenge_mode = Disabled` (the default); `POST /challenge` | 404 — the route is not registered, so a wallet cannot be misled into thinking §8 is supported |
| `successive_challenges_differ` | two `POST /challenge` calls with `challenge_mode = Optional` | the two `attestation_challenge` values differ (§8 unpredictability) |
| `metadata_and_route_availability_agree` | for each of `Optional` and `Disabled`: `GET /.well-known/oauth-authorization-server` **and** `POST /challenge` | `Optional` → `challenge_endpoint` present **and** route 200; `Disabled` → field absent **and** route 404. The two must never disagree |

Write the first one out in full so the header assertion is unambiguous:

```rust
/// ABCA §8: "The Authorization Server MUST make the response uncacheable by
/// adding a Cache-Control header field including the value no-store."
#[tokio::test]
async fn challenge_endpoint_mints_a_challenge_when_enabled() {
    // build state with issuer.wallet_attestation.challenge_mode = Mode::Optional
    let res = /* POST /challenge on the wallet router */;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(axum::http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let body = body_json(res).await;
    assert!(!body["attestation_challenge"]
        .as_str()
        .expect("attestation_challenge")
        .is_empty());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib metadata
cargo test -p foundry --test conformance_http challenge
```

Expected: `no field 'challenge_endpoint'`; the HTTP tests 404.

- [ ] **Step 3: Add the response type and mint fn**

Append to `crates/foundry-issuer/src/challenge.rs`, above the test module:

```rust
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
```

In `crates/foundry-issuer/src/lib.rs`, add an export line to the alphabetical `pub use` list (between the `authorize` and `create_offer` entries):

```rust
pub use challenge::{issue_attestation_challenge, ChallengeResponse, NonceSecret};
```

and **remove `NonceSecret`** from the existing `pub use nonce::{...}` line, or the two exports collide:

```rust
pub use nonce::{issue_nonce, verify_nonce, NonceResponse, C_NONCE_TTL_SECS};
```

- [ ] **Step 4: Add the metadata field**

In `pub struct AuthorizationServerMetadata`, after `dpop_signing_alg_values_supported`:

```rust
    /// ABCA draft -07 §10.1: "URL of the authorization servers challenge
    /// endpoint which is used to obtain a fresh challenge for usage in the
    /// Client Attestation PoP JWT."
    ///
    /// Omitted entirely when `issuer.wallet_attestation.challenge_mode` is
    /// `Disabled`. Per §8, publishing this field is what obliges a client to
    /// fetch and use a challenge -- so advertising it while ignoring every
    /// challenge would be actively misleading. Same reasoning as
    /// `dpop_signing_alg_values_supported` above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_endpoint: Option<String>,
```

In `build_authorization_server_metadata`'s struct literal:

```rust
        challenge_endpoint: if cfg.issuer.wallet_attestation.challenge_mode == Mode::Disabled {
            None
        } else {
            Some(format!("{base}/challenge"))
        },
```

- [ ] **Step 5: Add the route and handler**

In `crates/foundry/src/server.rs`, next to `nonce_handler`:

```rust
/// Challenge Endpoint (ABCA draft -07 §8).
///
/// Registered only when `issuer.wallet_attestation.challenge_mode` is
/// `optional` or `required`; under `disabled` the route does not exist, so a
/// wallet cannot mistake foundry for a server that supports §8.
///
/// Deliberately **unauthenticated**, like `/nonce`: §8's request example carries
/// no credentials, and a client needs a challenge *before* it can authenticate.
/// Minting is stateless, so an anonymous caller cannot grow storage.
#[utoipa::path(
    post,
    path = "/challenge",
    responses(
        (status = 200, body = ChallengeResponse,
         description = "ABCA §8 challenge. Uncacheable per §8 (`Cache-Control: no-store`)."),
    )
)]
async fn challenge_handler(
    State(state): State<AppState>,
) -> Result<
    (
        [(axum::http::HeaderName, &'static str); 1],
        Json<foundry_issuer::ChallengeResponse>,
    ),
    (StatusCode, Json<serde_json::Value>),
> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::issue_attestation_challenge(
        state.nonce_secret.as_ref(),
        state.config.issuer.wallet_attestation.pop_max_age_secs,
        now,
    )
    .map_err(|e| wallet_error_response(&e))?;

    // §8: "The Authorization Server MUST make the response uncacheable by
    // adding a Cache-Control header field including the value no-store."
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(res),
    ))
}
```

Register it conditionally. The wallet router is currently one chained `.route(...)` expression ending at `/statuslists/:id`; bind that to a `let mut router = ...` and add:

```rust
    // ABCA §8: the route exists only when the mechanism is enabled, so its
    // absence and the absent `challenge_endpoint` metadata entry always agree.
    if config.issuer.wallet_attestation.challenge_mode != foundry_core::config::Mode::Disabled {
        router = router.route("/challenge", post(challenge_handler));
    }
```

Read the enclosing function's signature first to use the right binding for the config (`config` vs `state.config`), and mirror the conditional-registration style already used for `/api-docs/openapi.json` and `/console` around lines 57-61.

- [ ] **Step 6: Register in OpenAPI**

In `crates/foundry/src/openapi.rs`, add `challenge_handler` to the wallet-facing `paths(...)` list and `foundry_issuer::ChallengeResponse` to `components(schemas(...))`, following the existing `nonce_handler` / `NonceResponse` entries.

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib metadata
cargo test -p foundry --test conformance_http challenge
cargo test -p foundry-issuer -p foundry
```

- [ ] **Step 8: Regenerate the OpenAPI specs**

Use the regeneration command documented in `crates/foundry/AGENTS.md` — **read it, do not guess**. Then confirm the path landed:

```bash
grep -c '"/challenge"' openapi-wallet.json
```

Expected: `1`.

- [ ] **Step 9: Lint, format, commit**

```bash
cargo fmt
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
git add -A
git commit -m "feat(issuer): ABCA challenge endpoint and challenge_endpoint metadata"
```---

### Task 6: `use_attestation_challenge` status mapping and the §8.1 header

**Files:**
- Modify: `crates/foundry/src/server.rs` (`wallet_error_response`, new `attestation_challenge_header` + `token_error_response`, `token_handler`)
- Test: `crates/foundry/tests/conformance_http.rs`

**Interfaces:**
- Consumes: `IssuanceError::UseAttestationChallenge` (Task 3), check 9 (Task 4), `issue_attestation_challenge` (Task 5).
- Produces:
  - `fn attestation_challenge_header(state: &AppState, now_unix: i64) -> Option<(axum::http::HeaderName, axum::http::HeaderValue)>`
  - `fn token_error_response(state: &AppState, now_unix: i64, e: &foundry_issuer::IssuanceError) -> (StatusCode, HeaderMap, Json<serde_json::Value>)`
  - `token_handler`'s success type becomes `(HeaderMap, Json<TokenResponse>)`; its error type becomes `(StatusCode, HeaderMap, Json<serde_json::Value>)`.

Note: `token_handler`'s return type changes in **both** arms. That is unavoidable — ABCA §8.1 attaches the header to successful responses too, and axum needs the `HeaderMap` in the success tuple to emit it. `credential_handler` already uses exactly this `(StatusCode, HeaderMap, Json<..>)` error shape, so this makes the two handlers consistent rather than divergent.

- [ ] **Step 1: Write the failing tests**

In `crates/foundry/tests/conformance_http.rs`. **Read the existing helper that drives a `/token` request carrying a Wallet Attestation and PoP** and reuse it — do not rebuild the attestation/PoP signing machinery. (`crates/foundry/tests/logging_redaction.rs` has `setup_with_required_attestation` and `drive_token_with_attestation_and_pop`; `conformance_http.rs` has its own equivalent near the `vci_0232_*` test.)

```rust
/// ABCA §6.2: "use_attestation_challenge MUST be used when the Client
/// Attestation PoP JWT is not using an expected server-provided challenge. When
/// used this error code MUST be accompanied by the
/// OAuth-Client-Attestation-Challenge HTTP header field parameter."
///
/// Both halves are asserted here: a generic `invalid_client` with no header
/// would satisfy neither.
#[tokio::test]
async fn a_pop_without_a_challenge_is_rejected_with_a_fresh_challenge_header() {
    // wallet_attestation.mode = Required, challenge_mode = Required.
    // POST /token with a valid attestation + PoP carrying no `challenge` claim.
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let challenge = res
        .headers()
        .get("OAuth-Client-Attestation-Challenge")
        .and_then(|v| v.to_str().ok())
        .expect("§6.2 requires the challenge header to accompany this error");
    assert!(!challenge.is_empty());
    let body = body_json(res).await;
    assert_eq!(body["error"], "use_attestation_challenge");
}

/// ABCA §8.1: "The Authorization Server MAY provide a fresh Challenge with any
/// HTTP response." Emitting it on success is what spares a conformant wallet a
/// `/challenge` round-trip before every subsequent token request.
#[tokio::test]
async fn a_successful_token_response_carries_a_fresh_challenge_header() {
    // challenge_mode = Required; PoP carries a challenge fetched from
    // POST /challenge. Assert 200 and a present, non-empty
    // OAuth-Client-Attestation-Challenge header.
}

/// The retry loop that §6.2's error code exists to enable must actually close.
/// This is the test that proves the feature is usable, not merely conformant.
#[tokio::test]
async fn a_wallet_can_retry_with_the_challenge_from_the_rejection_header() {
    // 1. POST /token with no `challenge` -> 400; capture the header value.
    // 2. Re-sign the PoP with `challenge` = that value AND a fresh `jti`
    //    (claim_pop_jti burned the first one, so reusing it would fail for an
    //    unrelated reason and mask what this test is checking).
    // 3. POST /token again -> 200.
}

/// Under the default nothing changes for an existing deployment.
#[tokio::test]
async fn no_challenge_header_is_emitted_when_challenge_mode_is_disabled() {
    // challenge_mode = Disabled; a successful /token response must carry no
    // OAuth-Client-Attestation-Challenge header at all.
}

/// A challenge that verifies but belongs to a different domain must still be
/// refused at the HTTP layer, not only in the unit test.
#[tokio::test]
async fn a_c_nonce_presented_as_a_challenge_is_rejected_at_the_token_endpoint() {
    // challenge_mode = Required; fetch a c_nonce from POST /nonce and put it in
    // the PoP's `challenge` claim. Assert 400 + error == "use_attestation_challenge".
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry --test conformance_http challenge
```

Expected: the first test sees 500 `server_error` (Task 3 deliberately left the variant in the catch-all) and no header; the header tests find no header.

- [ ] **Step 3: Map the error code**

In `wallet_error_response`'s match, next to the `InvalidDpopProof` arm:

```rust
        // ABCA §6.2's error codes are returned "in either Authorization Server
        // authenticated endpoint error responses (as defined in Section 5.2 of
        // [RFC6749])" -- the same 400 shape as `invalid_client`. The mandatory
        // OAuth-Client-Attestation-Challenge header is added by
        // `token_error_response`, the only mapper on a route that can produce
        // this error.
        UseAttestationChallenge(_) => (StatusCode::BAD_REQUEST, "use_attestation_challenge"),
```

- [ ] **Step 4: Add the header helper**

```rust
/// A freshly-minted ABCA §8.1 `OAuth-Client-Attestation-Challenge` header, or
/// `None` when challenge retrieval is disabled.
///
/// §8.1 permits attaching a fresh challenge to *any* response; §6.2 *requires*
/// it alongside a `use_attestation_challenge` error. One helper serves both, so
/// the two paths can never disagree about the header's name or format.
///
/// A minting failure yields `None` rather than propagating: the challenge is an
/// optimisation on a success path and a mandatory extra on an already-failing
/// one, and in neither case should it become a *different* error. The failure is
/// already logged inside `challenge::mint`.
fn attestation_challenge_header(
    state: &AppState,
    now_unix: i64,
) -> Option<(axum::http::HeaderName, axum::http::HeaderValue)> {
    if state.config.issuer.wallet_attestation.challenge_mode
        == foundry_core::config::Mode::Disabled
    {
        return None;
    }
    let res = foundry_issuer::issue_attestation_challenge(
        state.nonce_secret.as_ref(),
        state.config.issuer.wallet_attestation.pop_max_age_secs,
        now_unix,
    )
    .ok()?;
    // Lowercase literal: axum normalises header names per RFC 9110, and
    // `from_static` requires lowercase input.
    let name = axum::http::HeaderName::from_static("oauth-client-attestation-challenge");
    // The value is base64url, so `from_str` cannot fail in practice; `ok()?`
    // rather than an unwrap because root `AGENTS.md` §4.1 forbids one here.
    let value = axum::http::HeaderValue::from_str(&res.attestation_challenge).ok()?;
    Some((name, value))
}
```

- [ ] **Step 5: Add the token error mapper and rewire `token_handler`**

```rust
/// Error mapper for the Token Endpoint.
///
/// Wraps `wallet_error_response` and attaches the response headers ABCA §8.1
/// and RFC 9449 §8 put on `/token` responses. `wallet_error_response` still
/// emits the single log record (root `AGENTS.md` §4.5) -- this function adds no
/// second one.
fn token_error_response(
    state: &AppState,
    now_unix: i64,
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    let (status, body) = wallet_error_response(e);
    let mut headers = HeaderMap::new();
    // §6.2 makes this mandatory on a `use_attestation_challenge` error; §8.1
    // permits it on any other. Attaching it unconditionally (when enabled)
    // satisfies both without a branch that could get the mandatory case wrong.
    if let Some((name, value)) = attestation_challenge_header(state, now_unix) {
        headers.insert(name, value);
    }
    (status, headers, body)
}
```

Then change `token_handler`'s signature and tail. The `now` value it already computes is reused, so the challenge on the response and the window a PoP is checked against come from one clock reading:

```rust
async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<
    (HeaderMap, Json<TokenResponse>),
    (StatusCode, HeaderMap, Json<serde_json::Value>),
> {
```

Every existing `.map_err(|e| wallet_error_response(&e))?` inside `token_handler` becomes `.map_err(|e| token_error_response(&state, now, &e))?`. The two request-parsing `map_err`s at the top run **before** `now` is computed — move the `now` binding above them so all error paths can use it.

The tail becomes:

```rust
    let res = foundry_issuer::handle_token_request(
        state.storage.as_ref(),
        &req,
        &state.config.issuer.wallet_attestation,
        attestation_hdr,
        pop_hdr,
        &state.config.issuer.dpop,
        &dpop_presentation,
        state.nonce_secret.as_ref(),
        &issuer_identifier,
        now,
    )
    .await
    .map_err(|e| token_error_response(&state, now, &e))?;

    // ABCA §8.1: a fresh challenge on the success response too, so a wallet
    // never needs a second `/challenge` call.
    let mut out = HeaderMap::new();
    if let Some((name, value)) = attestation_challenge_header(&state, now) {
        out.insert(name, value);
    }
    Ok((out, Json(res)))
```

Update the `#[utoipa::path]` `responses(...)` block on `token_handler` to document the new 400 error code (`use_attestation_challenge`) and the `OAuth-Client-Attestation-Challenge` response header.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test -p foundry --test conformance_http challenge
cargo test -p foundry
```

Expected: the five new tests PASS, and every pre-existing `/token` test still passes. Existing tests read `res.status()` and the body, both unchanged under the default `Disabled` — if any needed an assertion change, stop and report.

- [ ] **Step 7: Regenerate OpenAPI, lint, format, commit**

```bash
# regeneration command per crates/foundry/AGENTS.md
cargo fmt
cargo clippy -p foundry --all-targets -- -D warnings
git add -A
git commit -m "feat(server): use_attestation_challenge mapping and the ABCA 8.1 challenge header"
```

---

### Task 7: DPoP nonce verification (check 10)

**Files:**
- Modify: `crates/foundry-issuer/src/dpop.rs` (module doc, `verify_dpop_proof`, new `DpopNoncePolicy`)
- Modify: `crates/foundry-issuer/src/token.rs` (the `verify_dpop_proof` call at ~line 135)
- Modify: `crates/foundry-issuer/src/credential.rs` (the `verify_dpop_proof` call in the `(Some(bound_jkt), true)` arm)
- Modify: `crates/foundry-issuer/src/lib.rs` (export `DpopNoncePolicy`)
- Modify: `crates/foundry-issuer/tests/conformance_vci.rs` (call site at line 95)
- Test: unit tests inside `crates/foundry-issuer/src/dpop.rs`

**Interfaces:**
- Consumes: `challenge::{mint, verify, Domain, NonceSecret}` (Task 1), `DpopConfig.nonce_mode` (Task 2), `IssuanceError::UseDpopNonce` (Task 3).
- Produces:
  - `pub struct DpopNoncePolicy<'a> { pub mode: Mode, pub secret: &'a NonceSecret }`
  - `verify_dpop_proof` gains a trailing `nonce_policy: Option<&DpopNoncePolicy<'_>>`. `None` means "no nonce was ever provided to this client", i.e. the pre-nonce behaviour.

Bundling the two values into `DpopNoncePolicy` keeps `verify_dpop_proof` at seven parameters instead of eight, and gives the `None` case a name that reads correctly at every existing call site.

- [ ] **Step 1: Write the failing tests**

Add to the test module in `crates/foundry-issuer/src/dpop.rs`. It already has `valid(&kp)`, `HTU`, `NOW`, `MAX_AGE`, and a keypair helper — **read `rejects_iat_older_than_the_window` first** and copy its construction shape. There is an existing helper that builds a proof with mutated claims; reuse it to plant a `nonce` claim.

```rust
    fn nonce_secret() -> crate::challenge::NonceSecret {
        crate::challenge::NonceSecret::from_bytes([11u8; 32])
    }

    fn fresh_dpop_nonce(now: i64) -> String {
        crate::challenge::mint(
            &nonce_secret(),
            crate::challenge::Domain::DpopNonce,
            MAX_AGE,
            now,
        )
        .expect("mint dpop nonce")
    }

    fn policy(mode: Mode) -> crate::dpop::DpopNoncePolicy<'static> {
        // A leaked box keeps the borrow simple in tests; production code holds
        // the secret in `AppState` for the process lifetime.
        crate::dpop::DpopNoncePolicy {
            mode,
            secret: Box::leak(Box::new(nonce_secret())),
        }
    }
```

Then these ten tests, each calling
`verify_dpop_proof(&proof, "POST", HTU, None, NOW, MAX_AGE, Some(&policy(mode)))`:

| Test name | Setup | Assertion |
|---|---|---|
| `no_nonce_policy_accepts_a_proof_without_a_nonce` | `nonce_policy: None` | `is_ok()` — the pre-nonce path, unchanged |
| `no_nonce_policy_ignores_a_garbage_nonce_claim` | `nonce_policy: None`, `nonce: "garbage"` | `is_ok()` — the server never supplied one, so §4.3 check 10's precondition is false |
| `disabled_nonce_mode_accepts_a_proof_without_a_nonce` | `Mode::Disabled` | `is_ok()` |
| `optional_nonce_mode_accepts_a_proof_without_a_nonce` | `Mode::Optional`, no claim | `is_ok()` |
| `optional_nonce_mode_verifies_a_present_nonce` | `Mode::Optional`, `nonce: fresh_dpop_nonce(NOW)` | `is_ok()` |
| `required_nonce_mode_rejects_a_proof_without_a_nonce` | `Mode::Required`, no claim | `matches!(err, IssuanceError::UseDpopNonce(_))` **and** `err.kind() == "use_dpop_nonce"` |
| `required_nonce_mode_accepts_a_fresh_nonce` | `Mode::Required`, `nonce: fresh_dpop_nonce(NOW)` | `is_ok()` |
| `an_expired_dpop_nonce_is_rejected` | `nonce: fresh_dpop_nonce(NOW)`, verified at `NOW + MAX_AGE as i64 + 1` | `matches!(..UseDpopNonce(_))` |
| `a_c_nonce_is_not_accepted_as_a_dpop_nonce` | `nonce` = a `Domain::CNonce` mint under the same secret | `matches!(..UseDpopNonce(_))` |
| `a_non_string_nonce_claim_is_rejected` | `nonce: 12345` | `matches!(..UseDpopNonce(_))` |

Plus one ordering test:

```rust
    /// §11.3's nonce check must not mask a structurally invalid proof: a wrong
    /// `typ` is still `InvalidDpopProof`, not `UseDpopNonce`, so a client is not
    /// told to retry with a nonce when the retry cannot possibly succeed.
    #[test]
    fn a_structurally_invalid_proof_is_not_reported_as_a_nonce_problem() {
        // proof with typ != "dpop+jwt", Mode::Required, no nonce claim
        assert!(matches!(err, IssuanceError::InvalidDpopProof(_)));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib dpop
```

Expected: compilation failure — `verify_dpop_proof` takes 6 arguments, 7 supplied; `DpopNoncePolicy` not found.

- [ ] **Step 3: Add the policy type and check 10**

In `crates/foundry-issuer/src/dpop.rs`, add near `VerifiedDpopProof`:

```rust
/// RFC 9449 §8/§9 server-provided nonce policy.
///
/// Passed as `Option` at every call site: `None` means "this server has never
/// supplied a nonce to this client", which is precisely §4.3 check 10's
/// precondition being false, and reproduces foundry's pre-nonce behaviour.
pub struct DpopNoncePolicy<'a> {
    pub mode: foundry_core::config::Mode,
    /// The process MAC secret that minted the nonce. Never logged.
    pub secret: &'a crate::challenge::NonceSecret,
}
```

Extend the signature:

```rust
#[allow(clippy::too_many_arguments)]
pub fn verify_dpop_proof(
    proof_jwt: &str,
    htm: &str,
    htu: &str,
    expected_ath: Option<&str>,
    now_unix: i64,
    max_age_secs: u64,
    nonce_policy: Option<&DpopNoncePolicy<'_>>,
) -> Result<VerifiedDpopProof, IssuanceError> {
```

Insert check 10 **after** the check-9 (`htu`) block and **before** the check-11 (`iat`) block, matching the RFC's own ordering. Add `use foundry_core::config::Mode;` to `dpop.rs`'s imports.

```rust
    // Check 10: "If the server provided a nonce value to the client, the nonce
    // claim matches the server-provided nonce value." `nonce_policy` models the
    // "if" -- see §8 (authorization server) and §9 (resource server). A `None`
    // policy means no nonce was ever provided, so the precondition is false and
    // §11.3 does not bind.
    //
    // Reaching this point means the proof is structurally sound and correctly
    // signed, so a `use_dpop_nonce` here genuinely means "retry with a nonce",
    // never "your proof was malformed".
    if let Some(policy) = nonce_policy {
        match (policy.mode.clone(), payload.get("nonce")) {
            // No nonce is supplied under this mode, so there is nothing for the
            // claim to match; a stray claim is ignored rather than rejected.
            (Mode::Disabled, _) => {}

            // Supplied but not yet mandatory: a wallet mid-migration is accepted.
            (Mode::Optional, None) => {}

            // §8: respond with `use_dpop_nonce` and a fresh `DPoP-Nonce` header
            // (added by the HTTP layer) so the client can retry.
            (Mode::Required, None) => {
                tracing::warn!("dpop proof carried no nonce claim");
                return Err(IssuanceError::UseDpopNonce(
                    "a server-provided nonce claim is required in the DPoP proof".into(),
                ));
            }

            (Mode::Optional | Mode::Required, Some(value)) => {
                // §8.1's nonce syntax is `1*NQCHAR`, i.e. a string; a non-string
                // is malformed rather than merely mismatched.
                let nonce = value.as_str().ok_or_else(|| {
                    IssuanceError::UseDpopNonce("nonce claim is not a string".into())
                })?;
                crate::challenge::verify(
                    policy.secret,
                    crate::challenge::Domain::DpopNonce,
                    nonce,
                    now_unix,
                )
                .map_err(|_| {
                    // §8: on a mismatch the server "MAY include a DPoP-Nonce HTTP
                    // header providing a new nonce value" -- the same response
                    // path as an absent nonce, so one error variant covers both.
                    // Never echoes the presented value (root `AGENTS.md` §4.5).
                    tracing::warn!("dpop proof carried an unusable nonce");
                    IssuanceError::UseDpopNonce(
                        "nonce is malformed, expired, or was not issued by this issuer".into(),
                    )
                })?;
            }
        }
    }
```

Note the `if let` wrapper rather than matching on `nonce_policy` itself: a single flat match over `Option<&DpopNoncePolicy>` cannot bind the policy in the "Some, but no claim" arm without an `.expect()`, and root `AGENTS.md` §4.1 forbids one in a request path.

- [ ] **Step 4: Rewrite the stale module documentation**

`dpop.rs`'s module doc currently claims check 10 is vacuous. That is now false. Replace the second bullet of the "Two of §4.3's twelve checks are deliberately not here" list — and fix the list's opening line, since only **one** check is now absent:

```rust
//! **One of §4.3's twelve checks is not here:**
//!
//! - **Check 1** ("not more than one DPoP HTTP request header field") needs the
//!   header map, which this module never sees — it takes a single `&str`. It is
//!   enforced in `crates/foundry/src/server.rs` via `exactly_one_header`.
//!
//! **Check 10** (`nonce` matches a server-supplied nonce) *is* implemented, as
//! of the ABCA-challenge/DPoP-nonce change: it is gated on
//! `issuer.dpop.nonce_mode`, which is `disabled` by default. Under `disabled` no
//! nonce is ever supplied, so §11.3 ("MUST NOT accept any DPoP proofs without
//! the nonce claim when a DPoP nonce has been provided") is satisfied
//! vacuously; under `optional`/`required` it is actively enforced. See
//! `docs/superpowers/specs/2026-08-04-abca-challenge-and-dpop-nonce-design.md`.
```

Also delete the now-false sentence in `VerifiedDpopProof`'s or `verify_dpop_proof`'s doc comment if either repeats the vacuity claim. Grep for it:

```bash
grep -rn "vacuous\|§2.2" crates/foundry-issuer/src/dpop.rs
```

Every hit must either be corrected or be a deliberate reference to the historical decision.

- [ ] **Step 5: Update the call sites**

Export the new type from `crates/foundry-issuer/src/lib.rs`:

```rust
pub use dpop::{access_token_hash, verify_dpop_proof, DpopNoncePolicy, DpopPresentation, VerifiedDpopProof};
```

**Production call sites** — build a real policy:

- `crates/foundry-issuer/src/token.rs` ~line 135. `handle_token_request` already received `nonce_secret` in Task 4, and has `dpop_cfg`:

```rust
            let nonce_policy = DpopNoncePolicy {
                mode: dpop_cfg.nonce_mode.clone(),
                secret: nonce_secret,
            };
            let verified = verify_dpop_proof(
                proof_jwt,
                dpop.htm,
                dpop.htu,
                dpop.ath,
                now_unix,
                dpop_cfg.max_age_secs,
                Some(&nonce_policy),
            )?;
```

- `crates/foundry-issuer/src/credential.rs`, the `(Some(bound_jkt), true)` arm. `handle_credential_request` already takes `nonce_secret: &NonceSecret` and `cfg: &Config`, so both halves are in scope — build the same `DpopNoncePolicy` from `cfg.issuer.dpop.nonce_mode` and `nonce_secret`.

**Test call sites** — pass `None`, which reads as "no nonce was provided":

- every existing `verify_dpop_proof(...)` in `crates/foundry-issuer/src/dpop.rs`'s test module (~22 sites)
- `crates/foundry-issuer/src/token.rs` line ~406 (a `#[cfg(test)]` helper)
- `crates/foundry-issuer/tests/conformance_vci.rs` line 95

These are mechanical single-argument additions. No assertion changes.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib dpop
cargo test -p foundry-issuer
cargo test -p foundry
```

Expected: the eleven new tests PASS; every pre-existing DPoP test passes with only the appended `None`.

- [ ] **Step 7: Lint, format, commit**

```bash
cargo fmt
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
git add -A
git commit -m "feat(issuer): implement RFC 9449 check 10, the server-provided DPoP nonce"
```---

### Task 8: `DPoP-Nonce` response wiring at `/token` and `/credential`

**Files:**
- Modify: `crates/foundry/src/server.rs` (`wallet_error_response`, `dpop_nonce_header`, `token_error_response`, `credential_error_response`, `token_handler`, `credential_handler`)
- Test: `crates/foundry/tests/conformance_http.rs`

**Interfaces:**
- Consumes: `IssuanceError::UseDpopNonce` (Task 3), check 10 (Task 7), `token_error_response` + `attestation_challenge_header` (Task 6).
- Produces:
  - `fn dpop_nonce_header(state: &AppState, now_unix: i64) -> Option<(axum::http::HeaderName, axum::http::HeaderValue)>`
  - `credential_error_response` gains `state: &AppState` and `now_unix: i64` parameters.
  - `credential_handler`'s success type becomes `(HeaderMap, Json<CredentialResponse>)`.

The 400-vs-401 split is not a choice: RFC 9449 §8 governs the authorization server (`/token`) and §9 governs the protected resource (`/credential`), which per §7.1 answers with 401 and `WWW-Authenticate`.

| Endpoint | Failure | Success |
|---|---|---|
| `/token` (§8) | 400 `{"error":"use_dpop_nonce", …}` + `DPoP-Nonce` | 200 + `DPoP-Nonce` |
| `/credential` (§9) | 401 + `WWW-Authenticate: DPoP error="use_dpop_nonce", algs="ES256"` + `DPoP-Nonce` | 200 + `DPoP-Nonce` |

- [ ] **Step 1: Write the failing tests**

In `crates/foundry/tests/conformance_http.rs`. **Read the existing DPoP HTTP tests first** — `credential_endpoint_rejects_a_downgraded_dpop_token_with_a_401_challenge` and `a_bound_token_with_a_matching_proof_is_accepted` already build DPoP proofs and drive both endpoints; reuse their helpers.

```rust
/// RFC 9449 §8: an AS "responds to requests that do not include a nonce with an
/// HTTP 400 (Bad Request) error response ... using use_dpop_nonce as the error
/// code value. The authorization server includes a DPoP-Nonce HTTP header in the
/// response supplying a nonce value to be used when sending the subsequent
/// request."
#[tokio::test]
async fn the_token_endpoint_demands_a_nonce_and_supplies_one() {
    // dpop.mode = Required, dpop.nonce_mode = Required.
    // POST /token with a valid DPoP proof carrying no `nonce` claim.
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let nonce = res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("§8 requires a DPoP-Nonce header on this error");
    assert!(!nonce.is_empty());
    assert_eq!(body_json(res).await["error"], "use_dpop_nonce");
}

/// §8: "the client is expected to retry its token request using a DPoP proof
/// including the supplied nonce value in the nonce claim." The loop must close.
#[tokio::test]
async fn a_wallet_can_retry_the_token_request_with_the_supplied_nonce() {
    // 1. POST /token, no nonce -> 400, capture DPoP-Nonce.
    // 2. Re-sign the proof with `nonce` = that value AND a fresh `jti`
    //    (claim_dpop_jti burned the first).
    // 3. POST /token again -> 200, and token_type == "DPoP".
}

/// §9 / §7.1: at a protected resource the answer is 401 with a
/// WWW-Authenticate challenge, not the §8 400.
#[tokio::test]
async fn the_credential_endpoint_demands_a_nonce_with_a_401_challenge() {
    // nonce_mode = Required; obtain a bound access token (with a nonce, so
    // /token succeeds), then POST /credential with a proof carrying no nonce.
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let www = res
        .headers()
        .get(axum::http::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .expect("§7.1 requires a WWW-Authenticate challenge");
    assert!(www.contains(r#"error="use_dpop_nonce""#), "got: {www}");
    assert!(www.contains(r#"algs="ES256""#), "got: {www}");
    assert!(res.headers().get("DPoP-Nonce").is_some());
    assert_eq!(body_json(res).await["error"], "use_dpop_nonce");
}

#[tokio::test]
async fn a_wallet_can_retry_the_credential_request_with_the_supplied_nonce() {
    // Same shape as the /token retry test, against /credential.
}

/// §8.2 permits supplying a nonce on any response. Doing so on success means a
/// wallet never needs a rejection round-trip after its first request.
#[tokio::test]
async fn successful_responses_carry_a_dpop_nonce_when_enabled() {
    // nonce_mode = Optional: assert a successful /token AND a successful
    // /credential each carry a non-empty DPoP-Nonce header.
}

/// §8: "there MUST NOT be more than one DPoP-Nonce header."
#[tokio::test]
async fn exactly_one_dpop_nonce_header_is_emitted() {
    // nonce_mode = Required; on both the 400 and the 200 path assert
    // res.headers().get_all("DPoP-Nonce").iter().count() == 1.
}

/// Under the default nothing changes for an existing deployment.
#[tokio::test]
async fn no_dpop_nonce_header_is_emitted_when_nonce_mode_is_disabled() {
    // nonce_mode = Disabled (the default): neither a successful /token nor a
    // successful /credential carries a DPoP-Nonce header.
}

/// A nonce-less proof must NOT be turned into a nonce error when the real
/// problem is elsewhere -- otherwise a wallet retries forever.
#[tokio::test]
async fn a_bad_ath_is_still_invalid_token_not_use_dpop_nonce() {
    // nonce_mode = Required; /credential with a valid nonce but a wrong `ath`.
    // Assert 401 and error == "invalid_token", NOT "use_dpop_nonce".
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry --test conformance_http dpop_nonce
cargo test -p foundry --test conformance_http nonce
```

Expected: 500 `server_error` where 400/401 is wanted; no `DPoP-Nonce` headers anywhere.

- [ ] **Step 3: Map the error code and add the header helper**

In `wallet_error_response`'s match, next to the `UseAttestationChallenge` arm added in Task 6:

```rust
        // RFC 9449 §8: "an HTTP 400 (Bad Request) error response ... using
        // use_dpop_nonce as the error code value". The accompanying DPoP-Nonce
        // header is added by `token_error_response`; the §9 (401) form for the
        // Credential Endpoint is in `credential_error_response`.
        UseDpopNonce(_) => (StatusCode::BAD_REQUEST, "use_dpop_nonce"),
```

Add the helper next to `attestation_challenge_header`:

```rust
/// A freshly-minted RFC 9449 §8/§8.2 `DPoP-Nonce` header, or `None` when
/// server-provided nonces are disabled.
///
/// One helper for every emission point — §8's 400, §9's 401, and §8.2's
/// piggyback on a success — so §8's "there MUST NOT be more than one DPoP-Nonce
/// header" holds structurally: each response inserts from here exactly once.
///
/// A minting failure yields `None` for the same reason as
/// `attestation_challenge_header`: it must not convert one error into another.
fn dpop_nonce_header(
    state: &AppState,
    now_unix: i64,
) -> Option<(axum::http::HeaderName, axum::http::HeaderValue)> {
    if state.config.issuer.dpop.nonce_mode == foundry_core::config::Mode::Disabled {
        return None;
    }
    // TTL is `dpop.max_age_secs`: a nonce outliving the window in which the
    // proof carrying it would be accepted anyway is useless (design doc §3).
    let nonce = foundry_issuer::mint_dpop_nonce(
        state.nonce_secret.as_ref(),
        state.config.issuer.dpop.max_age_secs,
        now_unix,
    )
    .ok()?;
    let name = axum::http::HeaderName::from_static("dpop-nonce");
    let value = axum::http::HeaderValue::from_str(&nonce).ok()?;
    Some((name, value))
}
```

`mint_dpop_nonce` does not exist yet — `challenge::mint` is `pub(crate)`. Add a thin public wrapper to `crates/foundry-issuer/src/challenge.rs`, mirroring `issue_attestation_challenge`, and export it from `lib.rs`:

```rust
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
```

```rust
pub use challenge::{
    issue_attestation_challenge, mint_dpop_nonce, ChallengeResponse, NonceSecret,
};
```

- [ ] **Step 4: Wire `/token`**

In `token_error_response` (added in Task 6), add the nonce header alongside the challenge header:

```rust
    // RFC 9449 §8 requires DPoP-Nonce alongside `use_dpop_nonce`; §8.2 permits
    // it on any other response. Unconditional (when enabled) for the same
    // reason as the ABCA challenge above.
    if let Some((name, value)) = dpop_nonce_header(state, now_unix) {
        headers.insert(name, value);
    }
```

And in `token_handler`'s success tail, next to the challenge header:

```rust
    if let Some((name, value)) = dpop_nonce_header(&state, now) {
        out.insert(name, value);
    }
```

`HeaderMap::insert` replaces rather than appends, which is what §8's "MUST NOT be more than one" wants — do **not** use `append` here.

- [ ] **Step 5: Wire `/credential`**

`credential_error_response` needs the state and clock. Change its signature and extend its DPoP branch to distinguish the two error codes:

```rust
fn credential_error_response(
    state: &AppState,
    now_unix: i64,
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    use foundry_issuer::IssuanceError::{InvalidDpopProof, UseDpopNonce};

    // RFC 9449 §9 + §7.1: at a protected resource both DPoP failure families
    // answer 401 with a WWW-Authenticate challenge, but with *different* error
    // codes -- §8's `use_dpop_nonce` is retriable, `invalid_token` is not.
    let dpop_error = match e {
        UseDpopNonce(_) => Some("use_dpop_nonce"),
        InvalidDpopProof(_) => Some("invalid_token"),
        _ => None,
    };

    if let Some(code) = dpop_error {
        log_typed_error("wallet", e.kind(), e, StatusCode::UNAUTHORIZED);
        let mut headers = HeaderMap::new();
        // §7.1: scheme name DPoP, an `error` parameter, and an `algs` parameter
        // "to signal to the client the JWS algorithms that are acceptable for
        // the DPoP proof JWT".
        let description = match code {
            "use_dpop_nonce" => "a server-provided DPoP nonce is required",
            _ => "DPoP binding check failed",
        };
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!(
            r#"DPoP error="{code}", error_description="{description}", algs="ES256""#
        )) {
            headers.insert(axum::http::header::WWW_AUTHENTICATE, v);
        }
        // §9: the nonce the client needs in order to retry.
        if let Some((name, value)) = dpop_nonce_header(state, now_unix) {
            headers.insert(name, value);
        }
        return (
            StatusCode::UNAUTHORIZED,
            headers,
            Json(serde_json::json!({
                "error": code,
                "error_description": e.to_string(),
            })),
        );
    }

    let (status, body) = wallet_error_response(e);
    (status, HeaderMap::new(), body)
}
```

The existing `invalid_token` behaviour is preserved exactly — same status, same header shape, same body — so the pre-existing 401 tests keep passing unchanged. Only the new `use_dpop_nonce` branch is additive.

Then rewire `credential_handler`. Its `now` is currently computed **after** the two early `map_err`s for the missing/unparseable `Authorization` header; move the `now` binding to the top of the function so every error path can pass it:

```rust
async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Result<
    (HeaderMap, Json<CredentialResponse>),
    (StatusCode, HeaderMap, Json<serde_json::Value>),
> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // ... existing body, with every
    //   .map_err(|e| credential_error_response(&e))
    // becoming
    //   .map_err(|e| credential_error_response(&state, now, &e))
    // ... and the tail becoming:

    let res = foundry_issuer::handle_credential_request(
        &state.config,
        state.storage.as_ref(),
        access_token,
        &req,
        state.nonce_secret.as_ref(),
        &dpop,
        now,
    )
    .await
    .map_err(|e| credential_error_response(&state, now, &e))?;

    // §8.2: supply a nonce on success too, so the wallet holds a usable one
    // before its next request.
    let mut out = HeaderMap::new();
    if let Some((name, value)) = dpop_nonce_header(&state, now) {
        out.insert(name, value);
    }
    Ok((out, Json(res)))
}
```

Update both handlers' `#[utoipa::path]` `responses(...)` blocks to document `use_dpop_nonce` and the `DPoP-Nonce` response header.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test -p foundry --test conformance_http
cargo test -p foundry
```

Expected: the eight new tests PASS. Every pre-existing DPoP HTTP test — notably `credential_endpoint_rejects_a_downgraded_dpop_token_with_a_401_challenge`, `a_bound_token_presented_as_bearer_is_rejected`, `an_unbound_token_with_the_dpop_scheme_is_rejected` — must pass **unchanged**, since `nonce_mode` defaults to `Disabled` and the `invalid_token` branch is untouched.

- [ ] **Step 7: Regenerate OpenAPI, lint, format, commit**

```bash
# regeneration command per crates/foundry/AGENTS.md
cargo fmt
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
git add -A
git commit -m "feat(server): emit DPoP-Nonce and use_dpop_nonce at /token and /credential"
```

---

### Task 9: Observability — challenges and nonces join the never-logged list

**Files:**
- Modify: `AGENTS.md` (root, §4.5)
- Modify: `crates/foundry/tests/logging_redaction.rs`
- Test: `crates/foundry/tests/logging_redaction.rs`, `crates/foundry/tests/instrumentation_hygiene.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–8.
- Produces: no code interface — a documented invariant plus its enforcing test.

A challenge or DPoP nonce is exactly the value an attacker needs to complete an otherwise-unforgeable PoP or proof. Logging one is as bad as logging a `c_nonce`, which §4.5 already forbids.

- [ ] **Step 1: Write the failing test**

`crates/foundry/tests/logging_redaction.rs` already has an `IssuanceSecrets` struct and an assertion table in `issuance_never_logs_codes_tokens_nonces_or_claims` that threads `("c_nonce", &secrets.c_nonce)`. Extend both.

Add fields to `IssuanceSecrets`:

```rust
    attestation_challenge: String,
    dpop_nonce: String,
```

Add a driver that exercises the enabled paths — the existing `drive_issuance` runs with both features off, so it would never see these values:

```rust
/// Drives issuance with ABCA challenge retrieval and DPoP nonces **enabled**,
/// so the new secrets actually flow through the request path this test then
/// scans. Running the default (disabled) config here would make the assertions
/// vacuously true.
async fn drive_issuance_with_challenge_and_nonce(state: &AppState) -> IssuanceSecrets {
    // Mirror `drive_issuance`, but: build the state with
    //   wallet_attestation.challenge_mode = Mode::Required
    //   dpop.mode = Mode::Required, dpop.nonce_mode = Mode::Required
    // fetch a challenge from POST /challenge, obtain a DPoP-Nonce from the
    // /token 400, and record both in the returned struct.
}

/// Both new freshness values are secrets: leaking one hands an attacker what it
/// needs to complete a forged PoP or DPoP proof. Root `AGENTS.md` §4.5.
#[tokio::test]
async fn issuance_never_logs_challenges_or_dpop_nonces() {
    let _guard = lock_flag().await;
    let (_sub, capture) = capture_at_trace();
    // ... drive_issuance_with_challenge_and_nonce ...
    for (label, secret) in [
        ("attestation_challenge", &secrets.attestation_challenge),
        ("dpop_nonce", &secrets.dpop_nonce),
    ] {
        assert!(
            !capture.contains(secret),
            "{label} leaked into the logs at TRACE"
        );
    }
}
```

Mirror the exact capture/assertion idiom of the existing `issuance_never_logs_codes_tokens_nonces_or_claims` — read it first; `capture.contains` above is a placeholder for whatever accessor `CaptureHandle` actually exposes.

Also add a **positive control**, matching the file's existing `payload_logging_really_unlocks_the_payload_when_enabled` pattern, so a silently-broken capture cannot make this test pass vacuously:

```rust
/// Positive control: proves the capture harness would have caught a leak. If
/// this fails, the assertions above are meaningless.
#[tokio::test]
async fn the_capture_harness_would_catch_a_leaked_challenge() {
    let _guard = lock_flag().await;
    let (_sub, capture) = capture_at_trace();
    let planted = "planted-challenge-value-must-be-visible";
    tracing::trace!(planted = planted, "deliberate leak");
    assert!(capture.contains(planted));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry --test logging_redaction
```

Expected: compilation failure on the new `IssuanceSecrets` fields until the driver is written. If the redaction assertions then **fail**, that is a real leak — find and fix the offending log statement rather than weakening the test.

- [ ] **Step 3: Fix any leak the test finds**

Every `tracing::` call added in Tasks 1–8 was written to log only *that* a value was minted or rejected, never the value. If the test fails, the likely culprits are a `#[tracing::instrument]` missing `skip_all` (also caught structurally by `instrumentation_hygiene.rs`) or a `fields(...)` entry capturing an argument. Fix at the source.

- [ ] **Step 4: Update root `AGENTS.md` §4.5**

Replace the never-logged bullet (currently at ~line 148) so the new values are named:

```markdown
- **Never logged, at any level, under any flag:** private and ephemeral JWKs,
  signer keys, the admin API key, access tokens, `c_nonce` values, ABCA
  `attestation_challenge` values, DPoP `nonce` values, the nonce secret,
  pre-authorized codes, authorization codes, transaction codes. Public keys
  appear only as RFC 7638 thumbprints (`foundry_core::obs::thumbprint`).
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p foundry --test logging_redaction
cargo test -p foundry --test instrumentation_hygiene
```

Expected: PASS, including the positive control.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "test(obs): challenges and DPoP nonces are never logged"
```

---

### Task 10: Conformance report, README, and crate guides

**Files:**
- Modify: `docs/conformance/openid4vc-conformance.md`
- Modify: `README.md`
- Modify: `crates/foundry-issuer/AGENTS.md`
- Modify: `crates/foundry/AGENTS.md`
- Modify: `crates/foundry/tests/AGENTS.md`

**Interfaces:**
- Consumes: every prior task, and the test names they produced.
- Produces: no code — documentation that must match the code that now exists.

Per root `AGENTS.md` §8, closing a conformance gap means updating the report, not only the code. Every row below must cite **real test names** from Tasks 1–9; a row citing a test that does not exist is worse than no row.

- [ ] **Step 1: Update `RFC-9449-0008`**

The row currently reads `not-implemented` with evidence explaining the deferral. Rewrite verdict and evidence:

- Verdict: `conforming`
- Evidence must state plainly that it is **config-gated and `disabled` by default**, name `verify_dpop_proof`'s check 10 and `dpop_nonce_header` (server.rs), give the 400 (§8) / 401 (§9) split, and note that under `disabled` the original §11.3-is-vacuous reasoning still holds.
- Test column: the `/token` and `/credential` nonce tests from Task 8 plus the `dpop.rs` unit tests from Task 7.

Do **not** delete the old reasoning about short-lived tokens — reframe it: it remains the compensating control under `disabled`, and is superseded by the nonce under `required`.

- [ ] **Step 2: Add the new RFC 9449 rows**

Append to `## Clause Inventory — RFC 9449 (DPoP)`, continuing the existing ID sequence (the last is `RFC-9449-0013`, so start at `RFC-9449-0014`). Follow the seven-column format exactly: `ID | § | Requirement | Applies to | Verdict | Evidence | Test`.

| § | Requirement | Verdict |
|---|---|---|
| §4.3 check 10 | If the server provided a nonce, the `nonce` claim matches it | `conforming` |
| §8.1 | Nonce syntax is `1*NQCHAR` | `conforming` — a non-string claim is rejected |
| §8.2 | The server MAY supply a new nonce value on any response | `conforming` — emitted on success as well as failure |
| §9 | A resource server MAY require a nonce, answering per §7.1 | `conforming` |
| §11.2 | Proof pre-generation is mitigated by the server-provided nonce | `conforming` under `required`; the short-lived-token compensating control still applies under `disabled` |
| §11.3 | A server MUST NOT accept proofs without the `nonce` claim once a nonce has been provided | `conforming` — enforced under `required`, vacuous under `disabled` |
| §8 (CORS note) | Browser-based apps need `DPoP-Nonce` in `Access-Control-Expose-Headers` | `out-of-scope` — foundry has no CORS layer at all (`grep -rn CorsLayer crates/foundry/src/` finds nothing), so there is no preflight surface to expose a header on. Recorded rather than left silent |

- [ ] **Step 3: Add the ABCA clause inventory section**

Add a new section after `## Clause Inventory — RFC 9449 (DPoP)`, in the same seven-column format, with IDs `ABCA-0001`..`ABCA-0005`:

```markdown
## Clause Inventory — ABCA (Challenge Retrieval)

Scoped deliberately to the §8 challenge mechanism added 2026-08-04. ABCA's other
clauses are adjudicated inside the OpenID4VCI inventory — see `VCI-0232`, which
covers §5.1, §5.2, §6.1, §6.2 and §9 rules 1-13 — since OpenID4VCI Appendix E
incorporates ABCA by reference. A complete standalone ABCA inventory is not in
scope for this change.
```

| ID | § | Requirement | Verdict |
|---|---|---|---|
| `ABCA-0001` | §8 | An AS MAY offer a challenge endpoint; a request is `POST` and the 200 response carries `attestation_challenge` and `Cache-Control: no-store` | `conforming` |
| `ABCA-0002` | §8 / §10.1 | If the AS supports RFC 8414 metadata it MUST signal support via `challenge_endpoint` | `conforming` — advertised iff `challenge_mode != disabled`, so the route and the metadata never disagree |
| `ABCA-0003` | §9 rule 8 | If the server provided a challenge, the `challenge` claim is present and matches | `conforming` |
| `ABCA-0004` | §6.2 | `use_attestation_challenge` MUST be used when the PoP is not using an expected server-provided challenge, accompanied by the `OAuth-Client-Attestation-Challenge` header | `conforming` |
| `ABCA-0005` | §8.1 | The AS MAY provide a fresh challenge on any response via `OAuth-Client-Attestation-Challenge` | `conforming` — emitted on `/token` success and error |

Also add a line to `VCI-0232`'s evidence noting that §9 rule 8 is now enforced too, cross-referencing `ABCA-0003`.

- [ ] **Step 4: Update the Summary table**

The `## Summary` section counts clauses per spec. Adding an ABCA section and seven RFC 9449 rows changes those totals. **Recount rather than estimate** — a wrong count erodes trust in the whole document:

```bash
grep -c '^| RFC-9449-' docs/conformance/openid4vc-conformance.md
grep -c '^| ABCA-' docs/conformance/openid4vc-conformance.md
```

Then update the Summary row for RFC 9449 and add one for ABCA, with per-verdict counts derived the same way.

- [ ] **Step 5: Update `README.md`**

In the configuration section, document both keys with their defaults and their effect:

- `issuer.wallet_attestation.challenge_mode` — `disabled` (default) / `optional` / `required`. When not `disabled`, `POST /challenge` is served and `challenge_endpoint` is advertised in AS metadata.
- `issuer.dpop.nonce_mode` — `disabled` (default) / `optional` / `required`. When not `disabled`, responses carry `DPoP-Nonce`.

In the endpoints section, add `POST /challenge`. Note that both default to off, so upgrading changes nothing until an operator opts in.

The "Logging & Observability" section lists never-logged values as operator-facing documentation — add challenges and DPoP nonces there so it matches root `AGENTS.md` §4.5 (Task 9).

- [ ] **Step 6: Update the crate guides**

- `crates/foundry-issuer/AGENTS.md`: add `challenge.rs` to the module map (the domain-separated MAC primitive shared by `nonce.rs`, `attestation.rs` and `dpop.rs`); note in the module map that `NonceSecret` now lives there; add a Gotchas entry that all three freshness domains share one secret and that **any new kind of issuer-minted opaque value MUST add a `Domain` variant** rather than reusing an existing one.
- `crates/foundry/AGENTS.md`: add `POST /challenge` to the route list, marked as conditionally registered.
- `crates/foundry/tests/AGENTS.md`: note which file now covers the challenge and nonce HTTP behaviour (`conformance_http.rs`) and the redaction guarantees (`logging_redaction.rs`).

- [ ] **Step 7: Verify every cited test name exists**

```bash
# For each test name cited in a new or edited conformance row:
grep -rn "fn <test_name>" crates/
```

Expected: a hit for every one. A row citing a nonexistent test is a documentation defect — fix the row or write the test.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "docs: record ABCA challenge retrieval and DPoP nonce conformance"
```

---

## Final Gate (run once, after Task 10)

Only now, per root `AGENTS.md` §5.3, and only because the branch is complete:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets -- -D warnings
```

Then request the whole-branch review (`final-reviewer`). Do not re-run this gate after merging (§5.4).

## Plan Self-Review Notes

Spec coverage check — every design-doc section maps to a task:

| Spec § | Task |
|---|---|
| §3 domain-separated primitive | 1 |
| §4 configuration + mode semantics | 2 |
| §5.1 `/challenge` | 5 |
| §5.2 metadata | 5 |
| §5.3 PoP check 9 | 4 |
| §5.4 `use_attestation_challenge` | 3 (variant), 6 (status + header) |
| §5.5 §8.1 header | 6 |
| §6.1 DPoP check 10 + stale docs | 7 |
| §6.2 `use_dpop_nonce` | 3 (variant), 8 (status + header) |
| §6.3 response wiring | 8 |
| §6.4 what §11.2 closes | 10 (conformance rows) |
| §7 observability | 9 |
| §8 documentation | 10 |
| §9 testing | distributed across 1, 4, 5, 6, 7, 8, 9 |
| §10 risks | mitigations embedded in 1 (domain tests), 2 (default tests), 7 (doc rewrite) |