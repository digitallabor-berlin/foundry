# Plural `proofs`/`credentials` Credential Endpoint

**Date:** 2026-07-30
**Type:** bugfix
**Track:** A/B hybrid — design+plan pre-existed this session (authored under `superpowers`), executed here via `superlight` Phase 4 (inline TDD, no subagents) per user instruction
**Branch:** superlight/2026-07-30-plural-proofs-credential-issuance
**Spec:** n/a — no separate spec was written; root cause and design were confirmed/approved inline (see plan's Global Constraints preamble)
**Plan:** docs/superpowers/plans/2026-07-30-plural-proofs-credential-issuance.md

## Problem

`POST /credential` used the singular `proof`/`credential` wire shape. Wallets
built against `eudi-lib-jvm-openid4vci-kt` (and any wallet following the
current OpenID4VCI draft's batch-shaped wire format) send/expect the plural
`proofs`/`credentials` shape instead, so issuance failed end-to-end against
those wallets with `invalid proof: missing proof in credential request`.

## Approach

Option A (no dual-path support): remove the singular shape entirely rather
than supporting both. Every producer/consumer of `/credential` in this repo
(vendored debug wallet, both HTTP test suites) was updated in lockstep in the
same branch. Rejected alternative: supporting both shapes simultaneously —
adds permanent complexity for a wire format this issuer never needs to speak
in its singular form again.

## Changes

- `crates/foundry-issuer/src/proof.rs` — `ProofObject` replaced by
  `ProofsRequest { jwt: Vec<String> }`; `verify_holder_proof` now verifies one
  raw JWT string at a time (batch looping moved to the caller).
- `crates/foundry-issuer/src/credential.rs` — `CredentialRequest.proofs:
  Option<ProofsRequest>` (was `.proof`); new `IssuedCredential { credential:
  String }`; `CredentialResponse { credentials: Vec<IssuedCredential>,
  notification_id: Option<String> }` (was `{ credential, c_nonce,
  c_nonce_expires_in }`); `handle_credential_request` verifies every JWT in
  `proofs.jwt` and issues one credential per verified proof.
- `crates/foundry-issuer/src/lib.rs` — re-export list updated
  (`ProofObject` → `ProofsRequest`; `IssuedCredential` added).
- `crates/foundry/src/openapi.rs` — `WalletApiDoc` schema list swaps
  `ProofObject` for `ProofsRequest`, adds `IssuedCredential`.
- `crates/foundry-wallet/src/actions/proof.rs` — `HolderProof.jwt: String`
  (was `proof_json: serde_json::Value`).
- `crates/foundry-wallet/src/actions/issuance.rs` — sends
  `"proofs": {"jwt": [proof.jwt]}`; parses
  `cred_json["credentials"][0]["credential"]`.
- `crates/foundry/tests/wallet_issuance.rs` — `create_proof` returns a raw
  JWT string; all 6 call sites and the one response assertion updated to the
  plural shape.
- `crates/foundry/tests/e2e_full_flow.rs` — same updates, one call site
  (this suite stays `#[ignore]`d; verified compile-only).
- `openapi.json` — regenerated; no schema-shape diff (admin surface
  untouched).
- `openapi-wallet.json` — regenerated; `/credential` request/response
  schemas updated as described above.

## Tests

- `crates/foundry-issuer/src/proof.rs` — `verifies_valid_proof_jwt`,
  `rejects_mismatched_nonce` (updated for the raw-JWT signature).
- `crates/foundry-issuer/src/credential.rs` —
  `issues_sd_jwt_vc_credential_successfully` (asserts exactly one credential
  issued for one proof).
- `crates/foundry-wallet/src/actions/proof.rs` —
  `builds_a_proof_jwt_bound_to_nonce_and_aud`,
  `each_call_generates_a_distinct_key`.
- `crates/foundry/tests/wallet_issuance.rs` — all 7 tests (full flow,
  aud/nonce mismatch, expired nonce, replay rejection) against the new wire
  shape.
- `crates/foundry/tests/e2e_full_flow.rs` — compiles; `#[ignore]`d as before,
  out of scope for automated execution.
- `crates/foundry-wallet` integration suite — `issuance_with_matching_trust_anchor_stores_a_valid_credential`
  independently exercises the full wallet→issuer flow over the new wire shape
  live and passed.

Full workspace gate run and green: `cargo test --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.

## Review

Phase 5 review (inline, no subagent) found one Important issue: Task 4's
plan-specified full-file replacement of `actions/proof.rs` silently dropped a
`private_key_pem` format assertion and the `each_call_generates_a_distinct_key`
test — unrelated to the wire-shape change, lost only because the plan's
literal replacement text wasn't in sync with the file's current test suite.
Restored both; full gate re-verified green. No other findings.

Task 8's optional manual smoke test against the real `eudipal-android` app
was not performed (no device/app available in this environment); the
automated `full_issuance_flow_end_to_end` and the wallet's own live-server
issuance test cover the same path.