# AGENTS.md — `crates/foundry-sd-jwt-vc`

## Purpose

Builds and verifies **SD-JWT VC** (Selective Disclosure JWT Verifiable Credential) format, following draft-ietf-oauth-sd-jwt-vc-17. The crate handles issuer-signed JWT payloads with selectively disclosed claims, holder key-binding JWTs, disclosure digest computation and matching, and claim reconstruction.

**NOT owned by this crate**: OpenID4VCI/VP protocol flow (that's `foundry-issuer`/`foundry-verifier`), trust-anchor policy evaluation, or Token Status List fetching (that's `foundry-core`/`foundry-verifier`).

---

## Position in the Dependency Graph

Depends exclusively on `foundry-core` (crypto signers, PKI, trust stores, error types). Consumed by `foundry-issuer` (issuance) and `foundry-verifier` (verification).

**Critical invariant**: this crate MUST NOT depend on `foundry-mdoc` or the protocol engines. If both format crates need shared behaviour, it belongs in `foundry-core`. — See root [AGENTS.md](../../AGENTS.md) §3.

---

## Module Map

| File | Purpose |
| --- | --- |
| `lib.rs` | Public re-exports: `builder`, `verifier`, `error` modules and `FormatError`. |
| `builder.rs` | Issuer-side: `IssuerClaims` struct, `build_sd_jwt_vc()` (JWT + salts + _sd digests), `build_kb_jwt()` (holder key-binding), `attach_kb_jwt()` (combine). |
| `verifier.rs` | Verification, in this exact order: split the `~`-separated presentation; parse the issuer JWS header/payload; check the **validity window** (`exp` in the past or `iat` in the future → `Expired`); validate the `x5c` chain via `foundry_core::trust::validate_chain`; verify the issuer JWS against the leaf cert's EC coords; extract holder `cnf.jwk`; **verify the KB-JWT** (before parsing individual disclosures, so `sd_hash` tampering surfaces as `KeyBinding` rather than a confusing parse error); then reconstruct disclosed claims by matching disclosure digests against `_sd`. Returns `VerificationResult`. |
| `error.rs` | Re-exports `FormatError` from `foundry-core`. |
| `tests/sdjwt_tests.rs` | Integration tests: valid presentation, expiry rejection, untrusted anchor, KB audience/nonce/sd_hash mismatches, disclosure tampering. |

---

## Key Public Types & Entry Points

- **`FormatError`** (re-exported from `foundry-core::error`) — all verification errors.
- **Builder API**:
  - `IssuerClaims` — issuer, **optional** subject (`Option<String>`, omitted by default), iat/exp, vct, cnf_jwk, status_list fields, always_disclosed/selectively_disclosable maps.
  - `build_sd_jwt_vc(claims, signer, x5c?) → String` — returns issuer presentation ending with `~`.
  - `build_kb_jwt(holder_signer, aud, nonce, sd_hash) → String` — holder key-binding JWT.
  - `attach_kb_jwt(presentation, holder_signer, aud, nonce) → String` — appends KB-JWT.
- **Verifier API**:
  - `verify_sd_jwt_vc(presentation_str, trust_store, aud, nonce, now_unix) → Result<VerificationResult>`.
  - `VerificationResult` — `claims` (reconstructed object), `holder_jwk` (from cnf.jwk), `issuer_x5c`.

---

## Binding Invariants

- No panics in verification: return typed `FormatError` rather than `.unwrap()` — root [AGENTS.md](../../AGENTS.md) §4.1.
- Verification must never report success for a step it did not perform. The `sd_jwt_vc_signature_and_kb_jwt` check result in `foundry-verifier` consumes this crate's output; every successful `verify_sd_jwt_vc()` call must have validated issuer signature + KB-JWT binding — root [AGENTS.md](../../AGENTS.md) §4.2.
- No upward/sideways dependency on engines or mdoc — root [AGENTS.md](../../AGENTS.md) §3.

---

## Tests

**Inline** (`src/builder.rs`, `src/verifier.rs` `#[cfg(test)]` modules):

- Builder: salt randomness, SD-JWT structure (h.p.s.~d~...~d~).
- Verifier: valid parse, KB-JWT rejection on nonce/audience/sd_hash mismatch, issuer cert trust validation.

**Integration** (`tests/sdjwt_tests.rs`):

- Selective claim reconstruction.
- Expiry rejection.
- Untrusted root rejection.
- KB audience mismatch.
- Disclosure tampering (detected via sd_hash).

**Run**: `cargo nextest run -p foundry-sd-jwt-vc` while iterating. The gate is
always the whole workspace — `cargo nextest run --workspace --no-fail-fast
--status-level fail` — per root [AGENTS.md](../../AGENTS.md) §5. Do not use
`cargo test`.

---

## Gotchas

- **`IssuerClaims.sub` is optional and omitted by default.** A synthesised
  per-transaction `sub` is a unique, static, always-disclosed identifier that
  rides along in every presentation to every verifier and that nothing in this
  workspace reads. `build_sd_jwt_vc` emits the payload key only when the field is
  `Some`. Do not reintroduce an unconditional `sub`. The `Some` path is covered
  end to end by `verifier.rs`'s `parses_and_verifies_valid_presentation`, which
  is deliberately the only fixture in that file setting it.
- **KB-JWT sd_hash computation**: hashed over the issuer presentation STRING (everything up to and including the final `~` before the KB-JWT itself), not a computed value. Tampering with any disclosure segment invalidates the hash, raising `KeyBinding` error *before* the crate tries to parse the corrupted disclosure — so malformed disclosure JSON never surfaces as an unrelated parse error.
- **Disclosure digest matching**: _sd array holds SHA-256(disclosure_b64); each disclosure is [salt, name, value]. Names from disclosures are injected into the payload only if their digest appears in _sd. Order matters for determinism but not validation.
- **KB-JWT typ field**: MUST be "kb+jwt" (verified strictly, not just suggested).
- **A KB-JWT is mandatory.** A bare issuer presentation (one ending in `~` with nothing after it) fails with `KeyBinding("KB-JWT missing from presentation")`. There is no "issuer-only" verification mode.
- **An `x5c` header is mandatory.** A missing or empty `x5c`, or a non-string element, fails with `SignatureVerification` — the issuer key is only ever taken from the certificate chain, never from an embedded JWK.
- **`iat` in the future is rejected as `Expired`**, the same error used for a past `exp`; the variant name does not distinguish the two directions.
- **Salts are 16 bytes of CSPRNG entropy**, URL-safe base64 unpadded (`generate_salt`). `attach_kb_jwt` computes `sd_hash` as base64url(SHA-256(entire issuer presentation string, trailing `~` included)).
