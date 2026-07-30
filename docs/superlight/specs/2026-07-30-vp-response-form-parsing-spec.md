# Spec-Compliant `direct_post.jwt` Response Parsing at `POST /vp/response/{id}`

**Date:** 2026-07-30
**Status:** approved

## Problem

`POST /vp/response/{id}` consumes the **entire raw HTTP body** as the JWE compact
serialization:

```rust
// crates/foundry/src/server.rs:577-581
async fn post_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    encrypted_jwe_str: String,        // ← bare String extractor = raw body
)
```

But foundry's own signed request object advertises
`"response_mode": "direct_post.jwt"` (`crates/foundry-verifier/src/request.rs:371`).
Per OpenID4VP 1.0 §8.2/§8.3 that obliges the wallet to POST
`application/x-www-form-urlencoded` with the JWE carried in a **`response`**
form parameter.

A conformant wallet therefore sends `response=eyJhbGciOiJFQ0RILUVTIiwi…`.
foundry hands that whole string to `josekit::jwt::decode_with_decrypter`
(`crates/foundry-verifier/src/verify.rs:53`), which splits on `.` and
base64url-decodes segment 0 — a segment that begins with the literal parameter
name. `"response"` is 8 characters, so the `=` sits at index 8 and the decode
fails.

Observed against the eudi-pal wallet:

```
invalid_request
error_description: decryption failed: Invalid JWE format: Invalid symbol 61, offset 8
```

### Root cause evidence

1. `"Invalid JWE format: …"` exists nowhere in foundry — it is
   `josekit::JoseError::InvalidJweFormat` (josekit 0.10.3,
   `jwe_context.rs:275/580/816/960/1226`). Its inner text
   `"Invalid symbol 61, offset 8."` is verbatim `base64` 0.22.1's
   `DecodeError::InvalidByte` Display (`decode.rs:36`), which prints the **byte
   value** (61 = `=`) and the **index**. The error originates inside foundry;
   the wallet only surfaced it.
2. `jwe_context.rs:848-895` splits on `.`, requires exactly four dots, then
   decodes each segment with `util::decode_base64_urlsafe_no_pad`
   (`util.rs:68-72`) — the `URL_SAFE_NO_PAD` engine, whose alphabet treats `=`
   as invalid rather than as padding.
3. eudi-pal delegates presentation entirely to `EudiWalletKit` →
   `eudi-lib-ios-siop-openid4vp-swift` (pinned 0.32.1 in `Package.resolved`).
   Its encrypted-response branch builds `formData: ["response": joseResponse]`
   (`AuthorisationService.swift:117-125`) and posts it with
   `ContentType.form` = `application/x-www-form-urlencoded` via
   `VerifierFormPost` (`VerifierFormPost.swift:31-46`).
4. Reproduced byte-identically with a throwaway `base64` 0.22 program:
   `segment0 = response=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSJ9` →
   `decode error: Invalid symbol 61, offset 8.`
5. foundry's suite never caught it because client and server share the same
   non-conformant convention: the debug wallet posts `content-type: text/plain`
   with the bare JWE (`foundry-wallet/src/actions/verification.rs:170` →
   `http/mod.rs:112-127`), and every integration-test call site hardcodes the
   same shape. Green tests, broken protocol.

## Goal / Non-Goals

### Goal

`POST /vp/response/{id}` accepts the OpenID4VP `direct_post.jwt` response shape:
an `application/x-www-form-urlencoded` body whose `response` parameter carries
the JWE compact serialization. Conformant third-party wallets complete a
presentation against foundry without modification.

### Non-Goals

- **Backwards compatibility with the raw-body shape.** Explicitly rejected (see
  Approach). The old shape must return HTTP 400.
- **Changing the response body foundry returns.** foundry answers with
  `VerificationResult` rather than OpenID4VP's `{"redirect_uri": …}`. This is
  non-standard, but verified non-fatal: `Poster.check`
  (`Poster.swift:105-120`) derives success from the HTTP status alone and maps
  a missing `redirect_uri` to `accepted(redirectURI: nil)`. Deferred to its own
  piece of work.
- **`dc_api.jwt` transport.** Its response never reaches this endpoint.
- **Unencrypted `direct_post`.** `request.rs:255-258` maps every non-`dc_api`
  transport to `direct_post.jwt`; there is no plaintext `vp_token` form variant
  to support.
- **Any change to verification semantics** — decryption, DCQL, status checks and
  the `verified` computation are untouched.

## Approach

**Chosen: strict spec-only.** Require form-encoded input with a `response`
parameter; anything else is HTTP 400 `invalid_request`. foundry's own debug
wallet and all integration-test call sites migrate to the conformant shape in
the same change.

Rationale: the raw-body convention was never a deliberate feature — it *is* the
defect. Its only two consumers live in this repository and are fixed alongside
it. Keeping it alive would preserve exactly the client/server symmetry that let
this bug hide behind a green suite.

### Rejected alternatives

- **Content-type dispatch (form → parse `response`; otherwise raw body).**
  Mirrors `token_handler`'s JSON/form dispatch and would keep the debug wallet
  and tests untouched. Rejected: it makes a non-standard path permanent and
  doubles the shapes under test, for compatibility nobody outside this repo
  needs.
- **Dispatch now, deprecate later** (fallback retained behind a `tracing::warn!`).
  Rejected for the same reason, absent any known external caller.
- **`axum::Form<VpResponseForm>` extractor.** Rejected: its rejection emits a
  plain-text 415/422, breaking this endpoint's OAuth-shaped
  `{error, error_description}` contract.

## Design

### Components

| Component | Change |
|---|---|
| `crates/foundry/src/server.rs` | New `VpResponseForm` struct; `post_response_handler` parses the body instead of consuming it raw; `#[utoipa::path]` request-body annotation updated |
| `crates/foundry/src/openapi.rs` | Register `VpResponseForm` in `WalletApiDoc`'s `components(schemas(...))` |
| `crates/foundry-wallet/src/actions/verification.rs` | Post the conformant form body instead of `post_text` |
| `crates/foundry-wallet/src/http/mod.rs` | Remove `post_text` if it becomes unused (clippy gate) |
| `crates/foundry/tests/wallet_verification.rs` | Migrate 9 call sites; add 4 new tests |
| `crates/foundry/tests/e2e_full_flow.rs` | Migrate 1 call site |
| `crates/foundry/tests/openapi_endpoints.rs` | Assert the request body advertises the form content type |
| `openapi-wallet.json` | Regenerated |

### Interface

```rust
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct VpResponseForm {
    /// JWE compact serialization of the VP Token response.
    response: String,
}

async fn post_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body_bytes: axum::body::Bytes,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)>
```

`&form.response` replaces `&encrypted_jwe_str` at the `verify_vp_response` call
site. Everything downstream of that call is unchanged.

### Data flow

```
wallet
  └─ POST /vp/response/{id}
     Content-Type: application/x-www-form-urlencoded
     response=<JWE compact serialization>
        └─ axum Bytes
           └─ serde_html_form::from_bytes::<VpResponseForm>
              └─ form.response  ──►  verify_vp_response(…)
                                        └─ josekit decrypt → format verify → DCQL → status
```

### Design decisions

- **`Bytes` + `serde_html_form`, not `axum::Form`.** Keeps every parse failure on
  the single 400 `invalid_request` path and preserves the endpoint's error
  contract. This mirrors the existing `token_handler` precedent
  (`server.rs:342-364`), which already takes `Bytes` and parses with
  `serde_html_form`.
- **No separate `Content-Type` gate.** A raw JWE body is not valid form data
  containing a `response` key, so it already fails to 400. Adding a content-type
  check would introduce a second rejection path returning a different status for
  the same underlying mistake.
- **Unknown form parameters are ignored.** No `deny_unknown_fields`. A wallet
  that also sends `state` (permitted by OpenID4VP) must not be rejected.
- **No percent-encoding call needed on the wallet side.** The JWE alphabet is
  base64url (`A–Z a–z 0–9 - _`) plus `.` separators — every character is RFC 3986
  unreserved, so `format!("response={jwe}")` is already correct. The server side
  percent-decodes via `serde_html_form` regardless, so a wallet that *does*
  encode also works. This reasoning is recorded as a code comment rather than
  left as a silent assumption.

### Error handling

| Condition | Status | Body |
|---|---|---|
| Body is not valid form-urlencoded, or has no `response` parameter | 400 | `{"error":"invalid_request","error_description":"expected application/x-www-form-urlencoded body with a `response` parameter: …"}` |
| Unknown transaction id | 404 | `{"error":"not_found",…}` (unchanged) |
| Transaction not `Pending` | 400 | `{"error":"invalid_request",…}` (unchanged) |
| Decryption / structural failure | 400 | via `verifier_wallet_error_response` (unchanged) |
| DCQL mismatch, revoked status | 200 | `verified: false` + check records (unchanged) |
| Status list unreachable | 502 | `status_unavailable` (unchanged) |

The new 400 is a structural failure, consistent with root `AGENTS.md` §4.3.

## Global Constraints

- Verification gates: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` — all three must pass clean.
- No `.unwrap()`, `.expect()`, `panic!()` or `unreachable!()` in request-handling paths (root `AGENTS.md` §4.1); permitted only under `#[cfg(test)]` and in `tests/`.
- `VerificationResult.verified` MUST remain `checks.iter().all(|c| c.passed)` (§4.2) — this change must not touch that computation.
- Structural/crypto errors → HTTP 400; policy failures → HTTP 200 with `verified: false`; status-fetch unavailability → HTTP 502 (§4.3).
- Endpoint changes MUST be reflected in `openapi-wallet.json` (§6).
- `#[utoipa::path]` attributes MUST reference schema types by **unqualified** name — a qualified path generates a dotted `$ref` that never resolves against `components.schemas` (regression fixed in commit `09b0bb0`).
- The form parameter name is exactly `response` (OpenID4VP 1.0 §8.3).
- Unknown form parameters MUST be ignored; never add `deny_unknown_fields`.
- No new workspace dependencies. `serde_html_form = "0.2"` is already a dependency of `crates/foundry` (`Cargo.toml:28`).
- Dependency layering is one-directional: `foundry-core` → format crates → engines → `foundry` → `foundry-wallet`. No upward or sideways edges.
- `openapi-wallet.json` is regenerated by running `serve`; the `foundry openapi` CLI subcommand writes the **admin** spec only.

## Testing Strategy

TDD throughout: one failing test per behavior, verified failing for the right
reason, before any implementation.

### New tests (`crates/foundry/tests/wallet_verification.rs`)

1. **Conformant form response is accepted.** POST
   `Content-Type: application/x-www-form-urlencoded`, body `response=<jwe>` →
   200 with `verified: true` and the four expected `CheckResult` names. This is
   the regression test for the reported defect; it must fail before the fix.
2. **Legacy raw-body shape is rejected.** POST the bare JWE →
   400 with `error: "invalid_request"`. Locks in the strict-only decision.
3. **Missing `response` parameter is rejected.** POST a well-formed but
   irrelevant form body (e.g. `state=abc`) → 400 `invalid_request`.
4. **Extra parameters are tolerated.** POST `response=<jwe>&state=abc` → 200,
   proving `deny_unknown_fields` was not introduced.

### Migrated tests

The 9 existing `text/plain` call sites in `wallet_verification.rs`
(lines 298, 448, 466, 537, 670, 694, 791, 913, 1068) and the 1 in
`e2e_full_flow.rs` (line 446) move to the form shape. Their assertions are
unchanged — they must keep passing, which is what proves the migration
preserved behaviour rather than merely relocating it.

### OpenAPI

`crates/foundry/tests/openapi_endpoints.rs:190-204` already asserts
`/vp/response/{id}` is present in the wallet spec, but does not assert its
content type. Add that assertion: the generated wallet spec's request body for
this path must advertise `application/x-www-form-urlencoded`.

The existing `wallet_openapi_spec_all_refs_resolve`
(`openapi_endpoints.rs:326`, via `assert_all_refs_resolve` at line 286) already
guards the dotted-`$ref` regression from `09b0bb0` and must stay green once
`VpResponseForm` is registered — it is the test that catches a qualified type
name in the `#[utoipa::path]` attribute.

### End-to-end

`cargo test --workspace` plus the three gates. Manual confirmation against the
eudi-pal wallet is the acceptance signal but is not automatable here.

## Open Questions

None.