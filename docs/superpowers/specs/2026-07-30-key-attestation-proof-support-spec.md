# Key Attestation & Full Proof-Type Support for the Credential Endpoint

**Status:** Design (proposed — pending approval)
**Date:** 2026-07-30
**Author:** flo@digitallabor.berlin (investigation + spec by agent)

## 1. Problem

`foundry-issuer::proof::verify_holder_proof` (`crates/foundry-issuer/src/proof.rs`)
implements only the `jwk`-embedded variant of the OpenID4VCI 1.0 `jwt` proof
type. Per the final spec (Appendix F.1), the proof JWT's JOSE header MUST
carry exactly **one** of `kid`, `jwk`, or `x5c` to identify the signing key,
and MAY additionally carry `key_attestation` alongside `kid`. Our code
hard-requires `jwk` and has no path for `kid`, `x5c`, or `key_attestation` at
all.

Confirmed by reading the reference wallet library
(`eudi-lib-jvm-openid4vci-kt`'s `JwtProofSigners.kt`): its `jwt` proof
construction *always* emits `kid` (a stringified index into an attestation's
`attested_keys`) plus `key_attestation` (a nested key-attestation JWT) —
never a bare `jwk`. This is not wallet non-conformance; it is mandated by the
governing profile: **HAIP 1.0 final §4.5.1, "Wallets MUST support key
attestations."** Our issuer therefore rejects every proof from any
HAIP/EUDI-conformant wallet with `invalid_proof` ("missing jwk in proof
header"), which is the reported issuance failure.

Reproduced directly against `verify_holder_proof` with a spec-legal
`kid`+`key_attestation` header (throwaway test, not committed): confirmed
rejection.

## 2. Goal / Non-Goals

### Goal

- Support all JOSE-header key-identification paths for the `jwt` proof type
  that HAIP requires: `jwk` (existing, unchanged), and `kid` + `key_attestation`
  (new).
- Verify key-attestation JWTs per Appendix D.1 + HAIP §4.5.1: x5c signature
  chain against a configured Wallet-Provider trust-anchor list, non-self-signed
  signing certificate, expiry, and — since Foundry's issuer always exposes a
  Nonce Endpoint — the attestation's `nonce` claim bound to the current
  `c_nonce`.
- Advertise `key_attestations_required` in issuer metadata when
  `key_attestation.mode != Disabled`, per the spec's own requirement that an
  issuer "MUST communicate the need to evaluate key attestations through its
  metadata or via an out-of-band mechanism" (Appendix D).
- Preserve today's `jwk`-only proofs working unchanged — no regression for
  `foundry-wallet` (debug client) or existing tests.

### Non-Goals (this fix)

- **`attestation` proof type** (bare key attestation, no proof-of-possession).
  Not exercised by the reported bug. The attestation-verification core this
  spec adds is reusable for it later.
- **`x5c` header** for the `jwt` proof type (holder key identified directly by
  certificate, no attestation). Not exercised by the reported bug; rejected
  explicitly with a clear "not yet supported" error rather than silently
  mishandled.
- **`trust_chain` header** (OpenID Federation). Not used by this ecosystem.
- **Cryptographic per-link X.509 signature verification** in
  `foundry_core::trust::validate_chain`. This is a pre-existing, already
  documented gap (`TODO(trust-hardening)`: DN-path validation only, no
  issuer-SPKI-over-tbs-certificate check). This fix inherits that limitation
  unchanged; hardening it is a separate piece of work.
- **`kid` as a DID URL** or any bare, non-attested `kid` (spec allows `kid` to
  reference a previously-registered key, e.g. via DID). Foundry has no key
  registry; a `kid` without an accompanying `key_attestation` is rejected with
  an explicit, documented error rather than silently accepted or crashing.
- **Batch-issuance key-attestation sharing** (HAIP: "all public keys used in a
  Credential Request SHOULD be attested within a single key attestation").
  Each proof in `proofs.jwt` is already verified independently today
  (`credential.rs`'s `.map(...)` loop); this fix keeps that shape — each
  proof's `key_attestation` (even if it duplicates the same JWT across
  multiple proofs) is verified independently. Functionally correct; a shared
  single-parse optimization is a later, non-behavior-changing improvement.

## 3. Approach

Extend `verify_holder_proof` to branch on which of `jwk`/`kid`/`x5c` is
present (mutually exclusive per spec), add a new key-attestation verification
function, wire a new Wallet-Provider trust-anchor config list scoped under
`issuer.key_attestation`, and declare `key_attestations_required` in issuer
metadata when applicable.

### Rejected alternatives

1. **Wrap `crates/oid4vci::proof::jwt::JwtProofVerifier` instead of extending
   our own `josekit`-based code.** Rejected: read it in full — it supports
   `jwk` and `kid`-via-pluggable-resolver, but has **zero `key_attestation`
   support** (its match arm only inspects `header.jwk`/`header.key_id`).
   Wrapping it would not remove the new-code requirement this bug needs, and
   would add an `ssi::jwk::JWK` ⇄ `josekit::jwk::Jwk` adapter layer for the one
   path (`jwk`) that already works correctly — net more code and more type
   friction for a partial win (a `kid`-without-attestation resolver path this
   spec explicitly marks a non-goal). This reverses a documented plan
   decision (see `docs/superpowers/plans/2026-07-22-foundry-plan-5-issuer-metadata-and-offers.md`,
   which called for reusing `JwtProofVerifier`) without re-adopting it,
   because the reason for that plan's exception (no metadata mismatch) turns
   out not to extend to `key_attestation`, the part actually needed here.
   Revisit if Foundry ever needs DID-`kid` resolution.
2. **Treat key-attestation trust as presence-only** (extend today's stub:
   if `key_attestation.mode == Required`, just check some header exists).
   Rejected: this is exactly today's behavior and it is not HAIP-conformant —
   HAIP mandates cryptographic x5c-chain verification, not presence. It is
   also insecure: an attacker could forge an unsigned or self-issued
   "attestation."
3. **Reuse the existing top-level `trust_anchors` config list** for
   key-attestation trust too. Rejected: `trust_anchors` is already
   semantically scoped to *credential-issuer* trust chains — today it is used
   only by `foundry-verifier::verify_vp_response` to validate a *presented
   VC's issuer* x5c chain. Wallet Provider CAs are a distinct trust domain in
   any real deployment (an issuer's trusted issuer-CA list is not necessarily
   its trusted wallet-provider-CA list). A separate, purpose-scoped list keeps
   these decoupled and matches how `AttestationMode` is already scoped under
   `issuer.key_attestation` in config.

## 4. Design

### 4.1 Config — `foundry-core::config::model`

```rust
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AttestationMode {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub trusted_anchors: Vec<TrustAnchor>, // new — Wallet Provider CAs for key_attestation
}
```

Reuses the existing `TrustAnchor { name, certs }` struct verbatim (no new
type). Both `wallet_attestation` and `key_attestation` share the
`AttestationMode` type today; only `key_attestation.trusted_anchors` is
populated/consumed by this fix (`wallet_attestation`'s field stays unused,
which is harmless — same struct, different config sections).

### 4.2 `attestation.rs` — real key-attestation verification

Replace the presence-only key-attestation check (that stub stays for the
unrelated wallet-level `OAuth-Client-Attestation` header check — untouched)
with a new function:

```rust
pub struct KeyAttestationClaims {
    pub attested_keys: Vec<josekit::jwk::Jwk>,
}

pub fn verify_key_attestation_jwt(
    key_attestation_jwt: &str,
    trust_store: &foundry_core::trust::TrustStore,
    expected_c_nonce: &str,
    now_unix: i64,
) -> Result<KeyAttestationClaims, IssuanceError>
```

Steps (Appendix D.1 + HAIP §4.5.1):

1. Split into 3 dot-separated parts; base64url-decode header/payload as JSON
   (same pattern already used in `proof.rs` for the outer proof JWT).
2. `typ` MUST be `key-attestation+jwt`.
3. `alg` MUST NOT be `none` or a symmetric (`HS*`) algorithm.
4. Header MUST carry `x5c` (v1 scope — `kid`/`trust_chain` header
   alternatives for the attestation itself are out of scope, see §2).
5. Extract leaf + intermediates from `x5c` via
   `foundry_core::trust::x5c_entry_to_pem`; verify the JWS signature against
   the leaf's public key (same pattern as
   `foundry-wallet::actions::trust::validate_jws_x5c_chain`'s
   `ES256.verifier_from_pem` off the re-encoded leaf SPKI).
6. `foundry_core::trust::validate_chain(leaf_pem, intermediates, trust_store, now_unix)`
   — already enforces "leaf not self-signed" and "chain resolves to a
   configured anchor not itself present in the chain," which is exactly
   HAIP's two x5c rules for key attestations. No new trust-anchor-exclusion
   logic needed.
7. Payload `exp` REQUIRED (per spec, mandatory when used with the `jwt` proof
   type) — reject if missing or expired against `now_unix`.
8. Payload `attested_keys` REQUIRED, non-empty JWK array — parse each entry
   into `josekit::jwk::Jwk`; reject on empty array or parse failure.
9. Payload `nonce` MUST equal `expected_c_nonce` (Foundry's issuer always runs
   a Nonce Endpoint, so this check is unconditional, not optional).

### 4.3 `proof.rs` — header branching

Replace the current unconditional "require `jwk`" block with a resolution
step. This is the one place `cfg.issuer.key_attestation.mode` actually gates
behavior — the config knob was previously unused for this purpose (only fed
to the dead `KeyAttestationVerifier` stub, see §4.5):

- Read `jwk`, `kid`, `x5c` header claims. Exactly one of the three must be
  present — zero or more-than-one is
  `InvalidProof("exactly one of jwk, kid, x5c header claims is required")`.
- **`jwk` present:**
  - `Mode::Required`: rejected —
    `InvalidProof("key attestation is required for this credential type")`
    (a bare `jwk` proof carries no attestation, so it cannot satisfy
    `Required`).
  - `Mode::Optional` / `Mode::Disabled`: existing path, byte-for-byte
    unchanged.
- **`kid` present + `key_attestation` present:**
  - `Mode::Disabled`: rejected —
    `InvalidProof("key attestation is disabled by issuer configuration")`
    (the issuer has not provisioned a Wallet-Provider trust store for this,
    so accepting one silently would be a false sense of verification).
  - `Mode::Required` / `Mode::Optional`: parse `kid` as a `usize` index
    (`InvalidProof("kid header must be a valid attested-key index")` on parse
    failure); call `attestation::verify_key_attestation_jwt(...)` with the
    `key_attestation` header's JWT string, the request's configured
    key-attestation `TrustStore`, the transaction's `c_nonce`, and `now_unix`;
    resolve `holder_jwk = attested_keys[kid_index]`
    (`InvalidProof("kid index out of bounds for attested_keys")` if out of
    range); use that key in place of the header's own `jwk` for the *outer*
    proof JWT's signature verification (same ES256-from-JWK verify call as
    today, just fed a resolved key).
- **`kid` present, no `key_attestation`:**
  `InvalidProof("kid header without key_attestation is not supported")` —
  explicit, per the documented non-goal, not a silent fallthrough or panic
  (applies regardless of mode — Foundry never supports bare `kid`).
- **`x5c` present:**
  `InvalidProof("x5c header for the jwt proof type is not yet supported")`
  (applies regardless of mode, per the non-goal).

`typ`, `aud`, `nonce` (on the *outer* proof JWT) validation is unchanged and
applies identically regardless of which key-source path resolved the key.

`verify_holder_proof`'s signature gains two new parameters:
`key_attestation_mode: foundry_core::config::Mode` and
`key_attestation_trust_store: &foundry_core::trust::TrustStore`.

### 4.4 `metadata.rs` — `key_attestations_required`

```rust
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub key_attestations_required: Option<serde_json::Value>,
}
```

When `cfg.issuer.key_attestation.mode != Mode::Disabled`, set
`key_attestations_required` to `Some(json!({}))` (an empty object — no
per-algorithm/security-level sub-requirements in v1, a documented follow-up,
not a silent omission); otherwise `None` (field omitted from the JSON
output).

### 4.5 `credential.rs` — wiring

`handle_credential_request` builds
`foundry_core::trust::TrustStore::from_config(&cfg.issuer.key_attestation.trusted_anchors)`
once per request (mirrors `foundry-verifier::verify_vp_response`'s existing
`TrustStore::from_config(&config.trust_anchors)` pattern) and passes it into
each `verify_holder_proof(...)` call in the existing `proof_jwts.iter().map(...)`
loop.

**Correction from the investigation checkpoint:** `KeyAttestationVerifier::
verify_key_attestation` (the presence-only stub in `attestation.rs`) is, on
closer inspection while writing this spec, **not called from any production
code path at all** — only `WalletAttestationVerifier::verify_wallet_attestation`
is wired, in `crates/foundry/src/server.rs`. `KeyAttestationVerifier` is dead
code today. This fix does not call or extend it: the real, cryptographic
key-attestation enforcement this spec adds lives entirely inside
`verify_holder_proof`'s new branch (§4.3), driven by `cfg.issuer.key_attestation.mode`
directly (skip the new branch's requirement when `Disabled`; when `Required`,
a `kid`-without-`key_attestation` or missing-attestation proof is rejected as
described in §4.3 regardless of the dead trait). Removing the now-redundant
`KeyAttestationVerifier` trait is a reasonable follow-up cleanup but is left
out of this fix's scope to keep the diff focused on the reported bug; it is
harmless dead code in the meantime, not a conflicting code path.

### 4.6 Error handling

All new failure paths return `IssuanceError::InvalidProof(String)` —
consistent with the existing taxonomy (root `AGENTS.md` §4.3: proof failures
are policy/structural failures that stay in the existing `invalid_proof` /
400 bucket; no new HTTP status is introduced). `TrustError` surfaced by
`validate_chain`/cert parsing propagates via the existing
`IssuanceError::Trust(#[from] TrustError)` variant when the failure is a pure
chain/parse error; failures specific to the proof-verification flow (missing
claims, index out of bounds, nonce mismatch) are wrapped as
`InvalidProof(format!("..."))`, matching `proof.rs`'s existing style of
wrapping library errors with human-readable context.

## 5. Global Constraints

- Spec compliance target: OpenID4VCI 1.0 final Appendix D ("Key
  Attestations") and Appendix F.1 ("`jwt` Proof Type"); HAIP 1.0 final §4.5.1
  ("Key Attestation").
- No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` outside
  `#[cfg(test)]` (root `AGENTS.md` §4.1).
- `foundry-issuer` must not gain a dependency on `foundry-verifier` or
  `crates/foundry` (root `AGENTS.md` §3) — all new trust logic goes through
  `foundry_core::trust`, an already-permitted downward dependency.
- Any endpoint/metadata shape change must be reflected in `openapi.json`
  (root `AGENTS.md` §6) — `ProofTypeSupported` gains a field.
- `crates/oid4vci` remains untouched — vendored crate rule ("prefer wrapping
  over editing"), and per rejected-alternative #1 above, not wrapped for this
  fix either.
- Backward compatibility: existing `jwk`-only proofs (used by
  `foundry-wallet`'s debug client and `crates/foundry/tests/e2e_full_flow.rs`)
  must keep passing unmodified.
- Gates before completion: `cargo test --workspace`, `cargo clippy
  --workspace --all-targets -- -D warnings`, `cargo fmt --check` (root
  `AGENTS.md` §5), plus `openapi.json` regenerated.

## 6. Testing Strategy

- `proof.rs` unit tests: exactly-one-of-`jwk`/`kid`/`x5c` enforcement (each
  violation shape — none present, two present, all three present); the
  `kid`+`key_attestation` happy path end-to-end (attested key resolves,
  outer-JWT signature verifies); out-of-bounds `kid` index; malformed
  (non-numeric) `kid`; bare `kid` without `key_attestation` rejected;
  `x5c`-only rejected with the "not yet supported" message; **mode
  conditioning** — `Mode::Required` rejects a bare-`jwk` proof,
  `Mode::Disabled` rejects a `kid`+`key_attestation` proof, `Mode::Optional`
  accepts both.
- `attestation.rs` unit tests for `verify_key_attestation_jwt`: self-signed
  leaf rejected; leaf chain not resolving to a configured anchor rejected;
  expired attestation rejected; missing/mismatched `nonce` rejected; wrong
  `typ` rejected; `alg: none`/symmetric rejected; happy path returns the
  correct `attested_keys` list.
- `metadata.rs` unit test: `key_attestations_required` present (`{}`) when
  mode `Required`, absent when `Optional`/`Disabled`.
- Integration: extend `crates/foundry/tests/wallet_issuance.rs` (per its
  documented role in `crates/foundry/tests/AGENTS.md`) with one full
  `/credential` round trip using a `kid`+`key_attestation` proof (built with a
  freshly generated, self-signed-CA-issued Wallet Provider certificate chain),
  alongside the existing `jwk`-based test — both must pass.

## 7. Open Questions

None — all design questions raised during investigation (attestation trust
model, vendored-crate reuse, config placement) are resolved above.