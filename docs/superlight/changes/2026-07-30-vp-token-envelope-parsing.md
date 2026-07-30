# OpenID4VP-Conformant `vp_token` Envelope Parsing (+ DCQL Hardening)

**Date:** 2026-07-30
**Type:** bugfix (protocol conformance) + hardening
**Track:** C (investigate) → B (spec + plan), scope expanded at the Phase 3 gate
**Branch:** superlight/2026-07-30-vp-token-envelope-parsing
**Spec:** docs/superlight/specs/2026-07-30-vp-token-envelope-parsing-spec.md
**Plan:** docs/superlight/plans/2026-07-30-vp-token-envelope-parsing-plan.md
**Predecessor:** docs/superlight/changes/2026-07-30-vp-response-form-parsing.md

## Problem

With the `direct_post.jwt` form-body defect fixed, the eudi-pal iOS wallet
decrypted successfully and failed one layer deeper:

```
invalid_request
error_description: verification failed: mdoc vp_token missing 'mdoc'
```

The credential presented was **SD-JWT VC**. The word "mdoc" was foundry
mislabelling its own branch.

## Root Cause

foundry dispatched on the **JSON type** of `vp_token` and accepted exactly two
shapes:

| Shape accepted | Interpreted as |
|---|---|
| a bare JSON **string** | SD-JWT VC |
| `{"mdoc": …, "device_signature": …}` | mdoc |

OpenID4VP 1.0 §8.1 defines `vp_token` as a JSON **object keyed by DCQL credential
query id**, whose values are **arrays** of presentations — *the same shape for
both formats*. The reference library does exactly that (`VPContent.swift:24-44`):

```swift
components[key.value] = JSON(jsonArray)   // { "<QueryId>": [ <presentation>, … ] }
```

So the wallet sent `{"<query_id>": ["<sd-jwt+kb>"]}`. The `as_str()` test failed
(it is an object), control fell into the `as_object()` branch which **assumes
object ⇒ mdoc**, and no key named `mdoc` was found.

**Type-sniffing was the defect, not merely the key names.** Because a conformant
envelope is an object for *both* formats, every conformant SD-JWT VC presentation
was reported as an mdoc error — the message actively misdirected diagnosis.

### Why the suite never caught it

The same reason as the predecessor defect: **foundry's tests constructed the
bespoke shape themselves.** `verify.rs` and `wallet_verification.rs` both built
`{"mdoc": …, "device_signature": …}` by hand, and the SD-JWT fixtures passed a
bare string. The debug wallet could not catch it either — it only ever presents
SD-JWT VC, so foundry's mdoc path had never been exercised by any client. Green
tests proved self-consistency, not conformance.

### Hypotheses rejected

- **The wallet sent a malformed `vp_token`** — the reference library's encoder is
  unambiguous and conformant; foundry was the non-conformant side.
- **The wallet presented an mdoc** — plausible from the error text, and the reason
  the credential format had to be *confirmed with the human partner* rather than
  inferred. Both formats land in the same branch, so the message carries no
  information about which was presented.
- **Only the mdoc key names were wrong** — renaming keys would have left SD-JWT VC
  broken, since its conformant envelope is also an object.

## Approach

**Strict spec-only, both formats.** `select_presentation` in
`crates/foundry-verifier/src/verify.rs` implements §8.1 selection and returns an
**already-destructured, typed payload**, so no verification arm can re-derive or
guess the format. The credential format comes from the `format` **declared by the
answered credential query** — never from the JSON shape.

Rejected: dual-shape acceptance. The bespoke envelope *is* the defect, and its
only consumers (debug wallet, fixtures) are in-repo and migrated in the same
commit.

## Changes

### The fix (`c9ffeff`)

- `foundry-verifier/src/verify.rs` — `select_presentation` + `SelectedPresentation`;
  the `as_str()`/`as_object()` block replaced by a `match` on the typed payload.
  All shape validation lives in one place; every failure names what arrived versus
  what was expected and is structural (HTTP 400).
- `foundry-verifier/src/dcql.rs` — **`check_dcql_match` is now bound to the
  answered query id** (D4). It previously accepted *any* credential query of the
  presented format, so a presentation could be credited to a query it did not
  answer.
- `foundry-wallet` — posts `{ "<query_id>": [presentation] }` using
  `MatchedCredential.query_id`; `match_credentials` passes its `query_id` through.
- 12 fixture call sites migrated (4 in `verify.rs`, 7 in `wallet_verification.rs`,
  1 in `e2e_full_flow.rs`); assertions unchanged, which is what proves behaviour
  was preserved.

### Hardening, added at the human partner's request (spec §12)

- **D3 (`6baa7ba`)** — `create_verification_request` validates `dcql_query` before
  persisting. Previously a broken query was stored, advertised to a wallet, and
  surfaced at verification time as a presentation failure rather than as the
  operator's mistake.
- **D5 (`5163a08`)** — `openapi.json` and `openapi-wallet.json` are compared
  against generator output, closing the gap the predecessor change had to report
  as "no test coverage claimed".
- **Docs (`25812e7`)** — two existing gotchas were left *actively wrong* by this
  branch and were rewritten, not appended to.

### Deliberate behaviour changes

- A `vp_token` that is a bare string, a legacy top-level mdoc envelope, an array,
  a multi-key object, or a non-single-element array is now **400** rather than
  accepted or misreported.
- `dcql_match` binds to the answered query id, so a presentation satisfying a
  *different* query now fails where it previously passed.
- A malformed or empty `dcql_query` now fails the **operator's create request**.
- A credential query naming a format foundry does not implement
  (`CredentialFormat::Other`) is a structural 400 once answered.

## Defects found while fixing this, and fixed

None of these were in the original spec; all surfaced during implementation.

1. **`CredentialFormat` has a third variant, `Other(String)`.** The spec assumed
   two. Caught by the compiler. `Other` is deliberate — an unimplemented format
   parses so it can *fail to match* inside a multi-credential query — but once
   answered there is no verifier to dispatch to, so it needs its own rejection.
2. **The `quickstart` config scaffold emitted `dcql: { credentials: [] }`**, which
   is a DCQL parse error, so *every generated config* shipped an unusable named
   query. The plan only knew about `config.yaml`; the scaffold in `commands.rs` is
   the tracked source that generates it.
3. **A test asserted that an empty `dcql_query` SUCCEEDS**
   (`test_create_verification_request_dc_api`).
4. **`dcql_model.rs` already documented defect 2** in a test comment — the
   codebase had noticed it and never repaired it. That comment now describes the
   fixed state.
5. **No CLI path existed to regenerate `openapi-wallet.json`.**
   `foundry openapi --out` only ever emitted the admin spec, which is why the
   predecessor change needed a throwaway file. A `--wallet` flag closes it; both
   flags reproduce the committed files byte-identically.

## Tests

- **`verify.rs`** — 11 unit tests on `select_presentation`, with no JWE, keys or
  trust store, so a failure points at the envelope rather than at crypto. They
  cover both conformant envelopes, both legacy shapes, an unknown query id, an
  envelope answering several queries, non-array and wrong-arity values, payloads
  contradicting the declared format, an unusable `dcql_query`, and an unimplemented
  format. There is deliberately **no** duplicate-id test — see the duplicate-id
  limitation under Review.
- **`dcql.rs`** — `presentation_answering_one_query_is_not_credited_to_another`
  asserts the D4 change directly: the same claims fail the query they answer and
  pass a laxer one, which is exactly what the old any-query loop would have
  latched onto.
- **`wallet_verification.rs`** — `bare_string_vp_token_is_rejected` (the pre-fix
  shape now 400s where it returned `200 verified:true`) and
  `vp_token_naming_an_unrequested_query_is_rejected`. The helper was
  parameterised so non-conformant envelopes can be driven through the real server
  rather than only through unit tests.
- **`request.rs`** — malformed and empty `dcql_query` rejected at creation.
- **`quickstart.rs`** — every scaffolded named query must be parseable DCQL.
- **`openapi_endpoints.rs`** — both committed specs must match generator output.

**Verified red-green, not assumed:** reverting the `quickstart` scaffold makes the
named-query guard fail naming `over18`; perturbing `openapi-wallet.json` makes the
drift guard fail naming `["paths"]`. Both were restored.

**Gates:** `cargo test --workspace` exit 0 (**352 tests**, zero failures),
`cargo clippy --workspace --all-targets -- -D warnings` exit 0 with zero warnings,
`cargo fmt --check` exit 0.

**End-to-end:** `cargo test -p foundry --test e2e_full_flow -- --ignored` passes —
a real server subprocess driven by the real wallet code through
issue → verify → revoke → re-verify. This test is `#[ignore]`d, so it is **not**
part of the default suite; it was run explicitly because it is the only automated
check that the wallet and server agree on the new envelope.

## Review

- **`verified` stays `checks.iter().all(|c| c.passed)`** (`verify.rs:359`,
  untouched) — root `AGENTS.md` §4.2.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** in any
  production path touched; verified per file, not assumed.
- **Every `check_dcql_match` call site** was located and updated.

**Minor, deliberately left:**

- **Duplicate DCQL credential query ids are not rejected.** OpenID4VP §6.1
  requires uniqueness; `DcqlQuery` does not enforce it. A duplicate-id query would
  now produce the *multi-credential* error, which is misleading for what is really
  a malformed query. Pre-existing, and validating uniqueness belongs with D3's
  creation-time validation in its own change.
- **`meta.doctype` vs the spec's `meta.doctype_value`.** `dcql.rs` reads
  `doctype_value` (correct per Appendix B.2.3), but the `sample_config` fixture
  writes `doctype`, so that query's doctype constraint would be silently ignored
  at match time. Confined to `#[cfg(test)]` code — no shipped config uses the
  wrong key — so it is a misleading fixture, not a live defect.
- **The 0-match error echoes wallet-supplied keys** back to that same wallet,
  unbounded in length. Not a disclosure risk (the wallet sent them), but it would
  bloat logs if logged.

## Known limitations carried forward

- **mdoc is NOT interoperable with real wallets** — the *envelope* is now
  conformant, the *payload* is not. Two independent divergences, both mdoc-only:
  `verify_mdoc` never reads `deviceSigned` (it takes the device signature as a
  separate argument and looks up only `issuerSigned`), and
  `serialize_session_transcript` is not the spec `OpenID4VPHandover`
  (`["OpenID4VPHandover", bstr(SHA-256(cbor([clientId, nonce, jwkThumbprint,
  responseUri])))]` — different order, no label, no hash, no thumbprint).
  **Deliberately deferred for unverifiability, not difficulty:** no RFC 7638
  thumbprint implementation exists in the workspace and `foundry-wallet` has no
  mdoc support at all, so any test would have foundry both generating *and*
  verifying the `DeviceResponse` against one reading of the spec — the exact
  self-consistency trap that produced these defects. **Unblocking condition:** a
  captured real mdoc presentation from eudi-pal, or an official test vector,
  committed as a fixture.
- **`config.yaml` is gitignored** and therefore not part of this change. Its
  `over18` entry was fixed locally for convenience; the tracked fix is the
  scaffold. An earlier draft of the guard test read `../../config.yaml` and would
  have failed in any fresh clone — removed.
- **foundry answers `/vp/response/{id}` with the full `VerificationResult`**
  rather than OpenID4VP's `{"redirect_uri": …}`. Verified non-fatal for the
  reference wallet, but non-standard, and it echoes internal check records back.
  Inherited from the predecessor change.
- **Confirmation against the live eudi-pal wallet is not automated** and remains
  the human partner's acceptance step.