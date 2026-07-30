# Spec-Compliant `direct_post.jwt` Response Parsing at `POST /vp/response/{id}`

**Date:** 2026-07-30
**Type:** bugfix
**Track:** C (investigate) → B (spec + plan for the fix)
**Branch:** superlight/2026-07-30-vp-response-form-parsing
**Spec:** docs/superlight/specs/2026-07-30-vp-response-form-parsing-spec.md
**Plan:** docs/superlight/plans/2026-07-30-vp-response-form-parsing-plan.md

## Problem

Presenting a credential from the eudi-pal wallet failed. The wallet surfaced:

```
invalid_request
error_description: decryption failed: Invalid JWE format: Invalid symbol 61, offset 8
```

Every foundry test was green, and foundry's own debug wallet completed the same
flow without complaint.

## Root Cause

**`POST /vp/response/{id}` consumed the entire raw HTTP body as the JWE compact
serialization** (`crates/foundry/src/server.rs`, `encrypted_jwe_str: String` — a
bare `String` extractor), while the verifier's own signed request object
advertises `"response_mode": "direct_post.jwt"`
(`crates/foundry-verifier/src/request.rs:371`).

Per OpenID4VP 1.0 §8.2/§8.3 that response mode obliges the wallet to POST
`application/x-www-form-urlencoded` with the JWE in a **`response`** parameter.
A conformant wallet therefore sent `response=eyJhbGciOiJFQ0RILUVTIiwi…`, and
foundry handed that whole string to `josekit::jwt::decode_with_decrypter`. josekit
splits on `.` and base64url-decodes segment 0 — a segment beginning with the
literal parameter name. `"response"` is 8 characters, so the `=` sits at index 8
and the decode fails.

### Evidence

1. `"Invalid JWE format: …"` appears nowhere in foundry — it is
   `josekit::JoseError::InvalidJweFormat` (josekit 0.10.3). Its inner text
   `"Invalid symbol 61, offset 8."` is verbatim `base64` 0.22.1's
   `DecodeError::InvalidByte` Display (`decode.rs:36`), which prints the **byte
   value** (61 = `=`) and the **index**. The error originated inside foundry;
   the wallet only displayed it.
2. `jwe_context.rs:848-895` splits on `.` and decodes each segment with
   `decode_base64_urlsafe_no_pad` (`util.rs:68-72`) — the `URL_SAFE_NO_PAD`
   engine, whose alphabet treats `=` as invalid rather than as padding.
3. eudi-pal delegates presentation to `EudiWalletKit` →
   `eudi-lib-ios-siop-openid4vp-swift` (0.32.1). Its encrypted-response branch
   builds `formData: ["response": joseResponse]`
   (`AuthorisationService.swift:117-125`) and posts it as
   `application/x-www-form-urlencoded` via `VerifierFormPost`.
4. Reproduced byte-identically with a throwaway `base64` 0.22 program:
   `response=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSJ9` →
   `Invalid symbol 61, offset 8.`
5. **Why the suite never caught it:** client and server shared the same
   non-conformant convention. The debug wallet posted `text/plain` with the bare
   JWE, and all 10 integration-test call sites hardcoded that shape. Green tests,
   broken protocol.

### Hypotheses rejected

- **Wallet produced a malformed JWE (stray base64 padding)** — impossible at index 8 of a real header segment (`eyJhbGciOi…`), and the error arises in foundry's Rust stack, not Swift.
- **Wallet posted JSON `{"response":"…"}`** — would fail at offset 0 on `{`, not offset 8.
- **ECDH-ES key / ephemeral JWK mismatch** — surfaces as an AEAD tag failure, never as a base64 format error, and only after successful parsing.
- **Parameter was `vp_token=` (also 8 characters, same offset)** — ruled out by reading the reference library: the `directPostJWT` branch uses `"response"`.
- **Percent-encoding mangled the JWE** — the decode dies inside the literal parameter name, before any JWE byte is reached.

## Approach

**Strict spec-only.** The handler parses the body as form-encoded and requires a
`response` parameter; anything else is HTTP 400 `invalid_request`. foundry's debug
wallet and every integration-test call site migrated to the conformant shape in
the same change.

Rationale: the raw-body convention was never a deliberate feature — it *is* the
defect. Its only two consumers lived in this repository. Keeping it alive would
have preserved exactly the client/server symmetry that let the bug hide.

### Rejected alternatives

- **Content-type dispatch** (form → parse `response`; otherwise raw body), mirroring `token_handler` — would have kept the debug wallet and tests untouched, but makes a non-standard path permanent and doubles the shapes under test, for compatibility no external caller needs.
- **Dispatch now, deprecate later** behind a `tracing::warn!` — same objection, absent any known external caller.
- **`axum::Form<VpResponseForm>`** — its rejection emits a plain-text 415/422, breaking this endpoint's OAuth-shaped `{error, error_description}` contract.

## Changes

- `crates/foundry/src/server.rs` — added `VpResponseForm { response: String }`;
  `post_response_handler` now takes `axum::body::Bytes` and parses with
  `serde_html_form`, matching the `token_handler` precedent. Deliberately **not**
  `deny_unknown_fields` — OpenID4VP §8 permits extra members such as `state`.
  `#[utoipa::path]` updated to a form-encoded request body.
- `crates/foundry/src/openapi.rs` — registered `VpResponseForm` in `WalletApiDoc`.
- `crates/foundry-wallet/src/actions/verification.rs` — posts
  `response=<jwe>` via `post_form` instead of the bare JWE via `post_text`.
- `crates/foundry-wallet/src/http/mod.rs` — removed `post_text`; it had no
  remaining caller.
- `crates/foundry/tests/wallet_verification.rs` — 9 call sites migrated, 4 tests added.
- `crates/foundry/tests/e2e_full_flow.rs` — 1 call site migrated.
- `crates/foundry/tests/openapi_endpoints.rs` — asserts the documented content type.
- `openapi-wallet.json` — regenerated.
- `crates/foundry/AGENTS.md` — gotcha recording the body contract and the exact
  failure signature, so the handler is not reverted to a raw `String` extractor.

### Deliberate behaviour changes beyond the reported bug

- **Parsing runs before the transaction lookup.** A malformed body is malformed
  regardless of whether the transaction exists, so the 400 is now deterministic
  instead of 400-or-404 depending on the id.
- **A malformed envelope no longer consumes the transaction.** `verify_vp_response`
  sets `tx.state = Failed` on any error (`verify.rs:29-32`); since a parse failure
  now returns before the tx is loaded, the transaction stays `Pending` and remains
  retryable. Previously any garbage body burned it. Replay protection is unchanged
  for anything that reaches verification.
- Consequently `response_for_unknown_transaction_id_returns_404` posts a
  well-formed envelope, which narrows it to the path it actually names.

## Tests

- `crates/foundry/tests/wallet_verification.rs`
  - `form_encoded_response_parameter_is_accepted` — the conformant shape returns
    200 / `verified: true`, asserting the four named `CheckResult`s. **This is the
    regression test:** before the fix it failed with the exact production error
    `Invalid symbol 61, offset 8`.
  - `raw_jwe_request_body_is_rejected` — the old shape returns 400. Before the fix
    it returned `200 verified:true`.
  - `form_body_without_response_parameter_is_rejected` — asserts the parse-failure
    *description*, not just the status; a status-only assertion passed for the
    wrong reason (via the decryption path) before the fix.
  - `extra_form_parameters_are_tolerated` — `response=<jwe>&state=abc` returns 200.
  - 9 existing call sites migrated with assertions unchanged, which is what proves
    the migration preserved behaviour.
- `crates/foundry/tests/openapi_endpoints.rs` —
  `wallet_openapi_documents_vp_response_as_form_encoded`; the pre-existing
  `wallet_openapi_spec_all_refs_resolve` stays green, guarding the dotted-`$ref`
  regression from `09b0bb0`.

Verified: `cargo test --workspace` exit 0 (40 binaries, 332 tests),
`cargo clippy --workspace --all-targets -- -D warnings` exit 0 with zero warnings,
`cargo fmt --check` exit 0.

## Review

**Important (found and fixed, `a319019`).** The happy-path test asserted
`verified: true` and a claim but omitted the four `CheckResult` names the spec
required. Load-bearing rather than cosmetic: per root `AGENTS.md` §4.2 an omitted
`CheckResult` silently drops out of `all(passed)`, so a lost check can turn a
failure into a pass while `verified: true` still holds.

**Minor, left with reasoning.**

- The transaction-retention change above is a semantic change the spec did not
  describe; judged an improvement and recorded here rather than silently absorbed.
- **No drift test exists for `openapi-wallet.json`** — verified, not assumed. The
  file was regenerated through `generate_wallet_openapi_spec()`, the same function
  `serve()` calls, and the diff inspected by hand. A drift test is worth its own
  work item; no test coverage is claimed for it.
- The debug wallet builds `format!("response={jwe_str}")` without percent-encoding.
  Correct by construction — a JWE compact serialization is base64url
  (`A-Z a-z 0-9 - _`) plus `.` separators, all RFC 3986 unreserved — and recorded
  as a code comment rather than a silent assumption.

**Confirmed clean:** no leftover TODOs, debug output or dead code; no `.unwrap()`
in the request path; `verified = all(passed)` untouched; naming consistent; the
generated `$ref` is the plain `#/components/schemas/VpResponseForm`.

**No `dc_api` regression** — checked rather than assumed: `console.html` never
posts to `/vp/response`, and no other in-repo client exists. The `text/plain`
entries in `wallet-data/log/events.jsonl` are stale runtime logs from a 2026-07-24
run of the old debug wallet, not a live caller.

## Known follow-ups (out of scope)

- foundry answers this endpoint with the full `VerificationResult` (`verified`,
  `checks`, `claims`) rather than OpenID4VP's `{"redirect_uri": …}`. Verified
  non-fatal — `Poster.check` (`Poster.swift:105-120`) derives success from the HTTP
  status alone and maps a missing `redirect_uri` to `accepted(redirectURI: nil)` —
  but it is non-standard and echoes the verifier's internal check records back to
  the wallet.
- No drift test for the committed OpenAPI specs.