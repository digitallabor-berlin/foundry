# Android Keystore Attestation Proof Type (Google Wallet `android_keystore_attestation`)

**Date:** 2026-08-05
**Type:** feat
**Branch:** feature/android-keystore-attestation-proof
**Spec:** docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md
**Plan:** docs/superpowers/plans/2026-08-04-android-keystore-attestation-proof-plan.md

## Why

Roadmap item **D** for Google Wallet compatibility. Google Wallet issuance
sends a `proofs.android_keystore_attestation` member — an array of X.509
certificate chains carrying an Android Keystore hardware attestation — instead
of (or alongside) the `jwt` proof type. foundry had no code path that accepted
this at all: `ProofsRequest` had a single required `jwt: Vec<String>` field, so
a Google Wallet-shaped Credential Request was rejected outright before this
change. This is **not** OpenID4VCI Appendix D key attestation (a signed JWT);
it is a distinct, Google-defined wire format, so `verify_key_attestation_jwt`
was never the right entry point to extend.

## Approach

Three scope decisions were resolved during brainstorming (see the design doc
for the full option analysis):

1. **Scope = parsing + challenge binding + security-level policy now;
   revocation deferred** to its own follow-on sub-project. Checking Google's
   revocation status list is a network dependency with its own caching,
   availability, and failure-mode design that does not belong in this branch.
2. **Config = a nested, opt-in `issuer.key_attestation.android` block**
   (`mode`, `key_mint_security_level`), sharing the parent's
   `trusted_anchors`. `mode` defaults to `disabled`; `required` rejects the
   `jwt` proof type entirely. Fail-closed startup validation: enabling the
   proof type with empty `trusted_anchors` is a configuration error, mirroring
   `wallet_attestation`'s and `key_attestation`'s own existing rule.
3. **Enforcement = both `attestationSecurityLevel` and `keyMintSecurityLevel`
   checked independently** against the configured minimum (default
   `TrustedEnvironment`). `user_auth_types`, `verifiedBootState`, and
   `deviceLocked` are decoded but deliberately not enforced yet — recorded as
   known limitations, not defects.

**Attesting certificate is selected from the root end of the chain**, not
`chain[0]`: Google's own guidance warns that an attacker can append extra
certificates below a genuine hardware-attested leaf, so `find_attestation_cert`
walks the chain reversed and returns the first certificate (nearest the root)
carrying the extension.

**`attestationChallenge` is treated as the UTF-8 bytes of the `c_nonce`
string** and validated via the existing `verify_nonce` — the same MAC-based
freshness mechanism the `jwt` proof type's `nonce` claim uses, just applied to
a byte string embedded in an X.509 extension instead of a JWT claim.

## What Changed

**`foundry-core` (`trust/android_attestation.rs`, `config/`):**

- New module `trust/android_attestation.rs`: `KEY_ATTESTATION_OID`
  (`1.3.6.1.4.1.11129.2.1.17`), `SecurityLevel` (`Software` <
  `TrustedEnvironment` < `StrongBox`, `Ord`-derived), `VerifiedBootState`,
  `RootOfTrust`, `AuthorizationList` (tags 1, 2, 3, 10, 503, 504, 701, 702,
  704, 705, 706 decoded; unrecognised tags skipped, not rejected), and
  `KeyDescription`. `parse_key_description(cert) -> Result<Option<KeyDescription>, TrustError>`
  and `find_attestation_cert(chain) -> Result<(usize, KeyDescription), TrustError>`.
  An unrecognised `SecurityLevel` enumeration value is a hard parse error — the
  parser cannot safely rank a level it does not know. Hand-rolled DER TLV
  reader over `der`/`x509-cert`'s primitives; no `.unwrap()`/`panic!()`
  anywhere outside `#[cfg(test)]`.
- `AndroidKeystoreConfig { mode: Mode, key_mint_security_level: SecurityLevel }`
  nested into `AttestationMode.android`, with a hand-written (not derived)
  `Default` — a derived impl would give `mode` the value `Mode::default()`
  (`Optional`), silently enabling the proof type wherever `..Default::default()`
  is used. `Config::validate()` gained the same fail-closed rule
  `wallet_attestation`/`key_attestation` already enforce: `android.mode !=
  Disabled` with empty `trusted_anchors` is a startup `ConfigError`.

**`foundry-issuer` (`keystore_proof.rs`, `proof.rs`, `credential.rs`,
`metadata.rs`):**

- New module `keystore_proof.rs`:
  `verify_android_keystore_proofs(chains, cfg, trust_store, nonce_secret,
  now_unix) -> Result<Vec<VerifiedProof>, IssuanceError>`. For each chain:
  validates the X.509 chain against the trust store (wrapping any
  `TrustError` into `InvalidProof`, never propagating `Trust` — that variant
  has no HTTP mapping and falls through to 500); locates and parses the
  attestation extension; checks `attestationSecurityLevel` and
  `keyMintSecurityLevel` independently against the configured minimum;
  validates `attestationChallenge` as a `c_nonce` via `verify_nonce`
  (challenge failures map to `InvalidNonce`, not `InvalidProof`); requires the
  attested key to be P-256; derives the holder-binding JWK from the leaf's
  public key. Never logs the nonce/challenge or `uniqueId`.
- `ProofsRequest` (proof.rs) reshaped to two optional members —
  `jwt: Option<Vec<String>>` and
  `android_keystore_attestation: Option<Vec<Vec<String>>>` — with
  `#[serde(deny_unknown_fields)]`, plus a `ResolvedProofs` enum and
  `ProofsRequest::resolve()` enforcing OpenID4VCI's "exactly one proof type"
  rule (L852): both present, neither present, or an unknown member name are
  all rejected. `ProofsRequest::from_jwts()` keeps the common construction
  path readable at existing call sites.
- `credential.rs` dispatches on `proofs.resolve()`: the `Jwt` arm additionally
  rejects the request when `issuer.key_attestation.android.mode ==
  Mode::Required` (that mode makes `jwt` unacceptable); the
  `AndroidKeystoreAttestation` arm calls `verify_android_keystore_proofs`.
- `metadata.rs`'s `proof_types_supported` conditionally advertises an
  `"android_keystore_attestation"` entry — only when `android.mode !=
  Disabled` — with `proof_signing_alg_values_supported: ["ES256"]` and
  `key_attestations_required.key_mint_security_level` always populated
  (Google's own field-naming convention, not OpenID4VCI's Appendix D shape).

**`crates/foundry` (tests only):**

- `tests/support/mod.rs` gained `synthetic_android_chain(ca, challenge) ->
  Vec<String>` (a runtime-built Android-shaped attestation chain via `rcgen`
  plus a small duplicated DER encoder — the real Google chain's challenge is
  Google's own `c_nonce` and can never verify against foundry's MAC secret, so
  fixtures cannot be static) and `setup_with_android_keystore(anchor_cert_pem)`.
  The module gained `#![allow(dead_code)]`: it is compiled separately into
  each test binary that declares `mod support;`, and no single binary calls
  every helper (`credential_encryption.rs` never calls
  `synthetic_android_chain`; `keystore_attestation_proof.rs` never calls
  `setup_with_encryption`).
- New `tests/keystore_attestation_proof.rs`: 7 end-to-end tests over the real
  wallet router (single chain, two chains, disabled-by-default rejection, an
  untrusted chain returning 400 `invalid_proof` never 500, a forged challenge
  returning 400 `invalid_nonce`, two proof types in one request rejected,
  metadata advertising the proof type only when enabled).
- `tests/logging_redaction.rs` gained `setup_with_android_keystore_attestation`
  and `android_keystore_issuance_never_logs_the_challenge_or_unique_id`,
  reusing `support::synthetic_android_chain` (`mod support;` added to this
  binary) rather than a fourth copy of the DER encoder.
- `openapi.json`/`openapi-wallet.json` regenerated for the `ProofsRequest`
  schema change (no diff beyond what Task 4 had already produced).

**Documentation:**

- `docs/conformance/openid4vc-conformance.md`: VCI-0198's evidence rewritten
  to name the two current `ProofsRequest` members instead of the stale
  `jwt: Vec<String>` text; VCI-0149 gained a sentence noting the
  `android_keystore_attestation` metadata entry always carries
  `key_attestations_required`; VCI-0057's evidence gained a paragraph
  explaining that `android_keystore_attestation` has no `aud`-equivalent
  field but satisfies the same anti-replay property via the `c_nonce`-MAC
  binding on `attestationChallenge`.
- `README.md` gained an "Android Keystore Attestation" configuration section
  (config block, per-mode behaviour, the fail-closed anchor rule, the link to
  Google's published root certificates, and the revocation limitation).
- Root `AGENTS.md` §4.5's never-logged list gained the Android key attestation
  `uniqueId`.
- `crates/foundry-core/AGENTS.md`: module-map row for
  `trust/android_attestation.rs`; Gotchas for the root-end certificate
  selection and the strict-outer/permissive-inner `KeyDescription` parse.
- `crates/foundry-issuer/AGENTS.md`: module-map row for `keystore_proof.rs`;
  the "similarly-named attestation things" list extended from three to four;
  Gotchas for the `Trust`-vs-`InvalidProof` wrapping rule, the independent
  `android.mode`/`key_attestation.mode` knobs, and the no-audience-binding/
  no-PoP property of the format.

## What Is Knowingly Not Implemented

- **Revocation.** Google's guidance asks issuers to check a presented
  attestation certificate against
  `https://android.googleapis.com/attestation/status`. Not implemented;
  named as its own follow-on sub-project, not a defect in this branch.
- **`user_auth_types` / `noAuthRequired`.** Decoded (`AuthorizationList.
  user_auth_type`, `.no_auth_required`) but never enforced. Google's own
  schema documentation is ambiguous about whether an empty `userAuthType` set
  means "no constraint" or "MUST carry `noAuthRequired`"; enforcing an
  unsettled semantic risks rejecting legitimately-configured genuine keys.
- **Device integrity (`rootOfTrust.verifiedBootState`, `.deviceLocked`).**
  Decoded but unenforced. Rejecting devices with an unlocked bootloader is an
  operator policy decision some deployments deliberately do not want made for
  them; it needs its own config knob, not a hardcoded default.
- **Expired pre-2021 factory attestation certificates are rejected, not
  exempted.** Google states these remain trustworthy indefinitely absent
  revocation, but `validate_chain`'s validity-window enforcement has no
  per-certificate-era carve-out, and adding one would also loosen validity
  enforcement for RKP certificates, whose short validity windows are a
  deliberate security property foundry cannot distinguish from the accommodation
  case at the certificate level alone.
- **No audience binding, no proof of possession.** Properties of the format
  Google chose, not gaps in this implementation — see VCI-0057's amended
  evidence and `keystore_proof.rs`'s own doc comments for the accounting of
  what does and does not hold, and why.

None of the four Google-profile-specific items above (revocation,
`user_auth_types`, device integrity, expired-certificate handling) were added
to the mechanically-enforced Gap Register: that register's own consistency
test (`conformance_report.rs`) requires every entry to be bidirectionally
referenced by a `gap`-verdict row in one of the three audited spec inventories
(OpenID4VCI/OpenID4VP/HAIP) and to name a real `#[ignore]`d regression test.
These four are Google Wallet vendor-profile behaviours, not clauses in the
pinned IETF/OpenID specifications — root `AGENTS.md` §4.4's vendor-profile rule
treats that distinction as load-bearing, not incidental — so they are recorded
here and in the two crates' `AGENTS.md` Gotchas instead, matching the existing
precedent at `RFC-9449-0008`'s evidence prose for the Google-profile-only
`/nonce`/`/challenge` `DPoP-Nonce` behaviour.

## Testing

Scoped gate run after every task (`cargo nextest run -p <touched crate>` plus
affected dependents per root `AGENTS.md` §5.2; `cargo clippy -p <crate>
--all-targets -- -D warnings`; `cargo fmt --check`), never `--workspace`
between tasks, per §5.1. New coverage:

- `foundry-core::trust::android_attestation`: 10 tests (real-fixture leaf
  parse and `rootOfTrust` decode, no-extension → `None`, truncated-content
  rejection without panicking, unknown `SecurityLevel` → parse error,
  StrongBox/Software `Ord`, unknown `AuthorizationList` tags skipped, the full
  documented tag set decoded, `find_attestation_cert` on a real 4-certificate
  chain, a chain with no extension anywhere).
- `foundry-core::config::validate`: 3 tests (android mode requires trust
  anchors, disabled needs none, `key_mint_security_level` defaults to
  `TrustedEnvironment`).
- `foundry-issuer::keystore_proof`: 14 tests (happy path with holder-key
  binding, request-order preservation across multiple chains, a forged
  challenge, an expired nonce, a security level below the minimum, StrongBox
  policy rejecting a TrustedEnvironment key, each security level checked
  independently, an untrusted chain surfacing as `InvalidProof` not `Trust`, a
  non-P-256 attested key rejected, no attestation extension, `mode: Disabled`
  rejecting everything, empty chain list, empty single chain).
- `foundry-issuer::proof`: 6 tests on `ProofsRequest::resolve()` (both types
  present, neither present, an unknown member name, the two happy-path
  resolutions).
- `foundry-issuer::credential`: 1 new test (`required` android mode rejecting
  a `jwt`-only request).
- `foundry-issuer::metadata`: 2 new tests (proof type absent when disabled,
  advertised with the configured level when enabled).
- `crates/foundry/tests/keystore_attestation_proof.rs`: 7 end-to-end tests, as
  listed above.
- `crates/foundry/tests/logging_redaction.rs`: 1 new behavioural test proving
  a real android-proof issuance never logs the `c_nonce`/challenge or
  `uniqueId` field name, alongside the existing positive control that proves
  the capture harness would actually catch a leak if one occurred.

Full gate (root `AGENTS.md` §5.3) to be run once at the end of the branch,
before requesting final review, per the plan's "End-of-branch full gate"
section: `cargo fmt` (apply) → `cargo fmt --check` → `cargo test --workspace`
→ `cargo test -p foundry --test e2e_full_flow -- --ignored` → `cargo clippy
--workspace --all-targets -- -D warnings` — captured to disk and grepped per
§5.6.

## Follow-ups / Known Limitations

- **Revocation checking** against Google's attestation status list — named
  above as a deferred sub-project, not tracked as a Gap Register row (see
  rationale above).
- **`user_auth_types` enforcement** once Google's schema documentation
  resolves its own internal ambiguity.
- **Device integrity policy** (`verifiedBootState`/`deviceLocked`) — needs its
  own config knob before it can be enforced by default.
- Roadmap item **E** for Google Wallet compatibility remains.