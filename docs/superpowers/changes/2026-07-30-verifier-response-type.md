# Verifier: emit the REQUIRED `response_type=vp_token` parameter

> Migrated from `docs/superpowers/changes/2026-07-30-verifier-response-type.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Date:** 2026-07-30
**Type:** bugfix
**Track:** C (investigate) → A (direct)
**Branch:** `superlight/2026-07-30-verifier-response-type`
**Spec:** n/a — Track A/C
**Plan:** n/a — Track A/C

## Problem

After deploying the client-metadata fix
(`docs/superpowers/changes/2026-07-30-verifier-encryption-jwk-metadata.md`), the
EUDI iOS wallet stopped complaining about client metadata and instead reported:

```
Invalid DCQL query: .missingResponseType
```

Same misleading `"Invalid DCQL query"` prefix as before —
`eudi-lib-ios-wallet-kit` (`OpenId4VpService.swift:110`) labels *every* failed
request resolution as a DCQL error. The DCQL query was again never parsed.

## Root Cause

**foundry's verifier never emitted the `response_type` Authorization Request
parameter, on either transport.** OpenID4VP v1.0 §5 marks it REQUIRED, and
`vp_token` is the only value defined for a presentation request.

Confirmed absent, not merely mis-valued:

```
$ grep -rn 'response_type' crates/foundry-verifier --include='*.rs' | wc -l
0
```

The wallet enforces it as a hard gate, positioned **immediately after** client
metadata validation and **before** anything touches DCQL
(`AuthorizationRequestResolver.swift:123-133`):

```swift
guard
  let unvalidatedResponseType = authorizedRequest.requestObject.responseType,
  let responseType = ResponseType(rawValue: unvalidatedResponseType)
else {
  return .invalidResolution(error: ValidationError.missingResponseType, ...)
}
```

It is read from the JAR payload as `json["response_type"].string`
(`RequestAuthenticator.swift:52`) and must parse into `ResponseType`, whose only
case is `case vpToken = "vp_token"` (`ResponseType.swift:20`).

That gate ordering explains the symptom sequence exactly: while the encryption
JWK was unusable, resolution died one step earlier, masking this defect.

**Not a regression.** `git log -S 'response_type' -- crates/foundry-verifier/`
returns no commits — the parameter was never present at any point in history.

**Why the test suite never caught it:** the same lenient-consumer blind spot as
the JWK bug. foundry's Rust debug wallet
(`crates/foundry-wallet/src/actions/verification.rs`) and
`crates/foundry/tests/wallet_verification.rs` read the fields they need directly
and never assert on `response_type`, so E2E tests passed against a request
object no EUDI reference wallet would accept.

## Approach

Emit `"response_type": "vp_token"` from both client-facing emitters, via a
single named constant carrying the rationale so it is not "tidied" away.

Rather than fix one gate per redeploy cycle (this was the third device failure),
the **entire** wallet resolution path was audited first to find every remaining
required-field gate:

| Gate (in order) | Source | foundry emits | Status |
|---|---|---|---|
| JAR fetch + x5c signature | `ClientAuthenticator` / `AccessValidator` | request object | already passing |
| `client_metadata` → encryption JWK filter | `ClientMetaDataValidator:~70` | `kid`/`use`/`alg` | fixed in `9515566` |
| **`response_type`** | `AuthorizationRequestResolver:123` | **nothing** | **fixed here** |
| `nonce` | `AuthorizationRequestResolver:~137` | `nonce` | ok |
| `response_mode` + `response_uri` | `ResponseMode.init` | both | ok |
| `dcql_query` non-empty | `parseQuerySource` → `Credentials.ensureValid` | `dcql_query` | fixed in manifest |
| final resolution | `ResolvedRequestData.init` | — | no further required-field guards |

`response_type` was the only remaining blocker.

## Changes

- `crates/foundry-verifier/src/request.rs`
  - new `const RESPONSE_TYPE_VP_TOKEN: &str = "vp_token"`, documented with the
    wallet-side gate and its ordering (why omission surfaces as a DCQL error).
  - `dc_api` inline request object now carries `response_type`.
  - `build_signed_request_object` inserts `response_type` as the first payload
    entry.

Three production lines; the change is purely additive (+85/−0 including tests).

## Tests

- `test_authorization_request_advertises_response_type_vp_token` — asserts
  `response_type == "vp_token"` on **both** transports (inline `dc_api` object
  and the decoded signed request-object payload).

Confirmed RED before implementing, for the right reason (`left: Null` — absent,
not mis-valued).

Verified: `cargo test --workspace` (417 passed, 0 failed),
`cargo clippy --workspace --all-targets -- -D warnings` (clean),
`cargo fmt --check` (clean).

The full emitted request-object payload was additionally dumped via a throwaway
test (not committed) and inspected end-to-end:

```json
{
  "response_type": "vp_token",
  "client_id": "x509_san_dns:verifier.example.com",
  "response_uri": "https://…/vp/response/v_0ab8d1…",
  "response_mode": "direct_post.jwt",
  "nonce": "vn_2b51bc…",
  "state": "v_0ab8d1…",
  "dcql_query": { "credentials": [ { "id": "pid", "format": "dc+sd-jwt", … } ] },
  "client_metadata": {
    "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "x": …, "y": …,
                          "kid": "1964841a-…", "use": "enc", "alg": "ECDH-ES" } ] },
    "encrypted_response_enc_values_supported": ["A128GCM"],
    "vp_formats_supported": { "dc+sd-jwt": {…}, "mso_mdoc": {…} }
  }
}
```

Every field the wallet's `UnvalidatedRequestObject` requires on this path is now
present.

## Follow-ups (not done here)

- **`transaction_data` type mismatch (latent, real).** foundry types it
  `Option<Vec<serde_json::Value>>` (objects) — `request.rs:22`,
  `transaction.rs:39` — but OpenID4VP defines it as an array of base64url-encoded
  strings, and the wallet decodes it as `[String]`
  (`json["transaction_data"].arrayObject as? [String]`). Objects yield `nil` and
  are **silently dropped**, with no error. Not hit today because the deployed
  named query supplies no transaction data, but any future transaction-data use
  will fail quietly. Worth its own fix.
- foundry does not validate `named_queries` DCQL shape at config load
  (`Vec<serde_json::Value>`), so `config validate` cannot catch a malformed or
  empty named query.
- Startup validation (or support) for non-`ECDH-ES`
  `verifier.response_encryption.alg`; `verify.rs:49` still hardcodes
  `josekit::jwe::ECDH_ES`.
- Consider asserting the full request-object contract in
  `crates/foundry/tests/wallet_verification.rs` so a strict-wallet regression
  fails in CI rather than on a device. This class of bug has now cost three
  redeploy cycles.

## Requires redeploy

This is code, not config — a foundry rebuild and redeploy is required.
