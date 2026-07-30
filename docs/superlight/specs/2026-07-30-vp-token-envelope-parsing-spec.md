# Spec — OpenID4VP-Conformant `vp_token` Envelope Parsing

**Date:** 2026-07-30
**Type:** bugfix (protocol conformance)
**Track:** C (investigate) → B (spec + plan)
**Branch:** superlight/2026-07-30-vp-token-envelope-parsing
**Predecessor:** docs/superlight/changes/2026-07-30-vp-response-form-parsing.md
**Revised:** 2026-07-30 — scope expanded at the Phase 3 gate; see §12.

---

## 1. Problem

With the `direct_post.jwt` form-body defect fixed, the eudi-pal iOS wallet now
decrypts successfully and fails one layer deeper:

```
invalid_request
error_description: verification failed: mdoc vp_token missing 'mdoc'
```

The word "mdoc" in that message is foundry mislabeling its own branch, not a
statement about the presented credential. The credential actually presented was
**SD-JWT VC**.

## 2. Root Cause

foundry's `vp_token` envelope is bespoke. `crates/foundry-verifier/src/verify.rs`
dispatches on the **JSON type** of `vp_token` and accepts exactly two shapes:

| Shape foundry accepts | Interpreted as |
|---|---|
| a bare JSON **string** | SD-JWT VC |
| `{"mdoc": "<b64url>", "device_signature": "<b64url>"}` | mdoc |

OpenID4VP 1.0 §8.1 defines `vp_token` as a JSON **object keyed by DCQL
credential query id**, whose values are **arrays** of presentations. The
reference wallet library does exactly that — `VPContent.swift:24-44`:

```swift
components[key.value] = JSON(jsonArray)   // { "<QueryId>": [ <presentation>, … ] }
```

A conformant wallet therefore sends `{"<query_id>": ["<sd-jwt+kb>"]}`. foundry's
`as_str()` test fails (it is an object), control falls into the `as_object()`
branch which **assumes object ⇒ mdoc**, looks for a key literally named `mdoc`,
and does not find one.

### Why the test suite never caught it

The same reason as the predecessor defect: **foundry's tests construct the
bespoke shape themselves.** `verify.rs:631-634` and
`wallet_verification.rs:1054` both build `{"mdoc": …, "device_signature": …}` by
hand, and the SD-JWT tests pass a bare string. The suite proves foundry is
self-consistent, not that it is conformant. The debug wallet could not catch it
either — it only ever presents SD-JWT VC (`presentation = attach_kb_jwt(…)`, a
string), so foundry's mdoc path has never been exercised by any client.

### Consequence of type-sniffing

Because a conformant `vp_token` is an object for **both** formats, an SD-JWT VC
presentation lands in the mdoc branch and reports a misleading mdoc error. The
error message actively misdirects diagnosis. Dispatching on the JSON type is
the defect, not merely the key names.

## 3. Goals

- `POST /vp/response/{id}` accepts the OpenID4VP 1.0 §8.1 `vp_token` envelope
  for **both** `dc+sd-jwt` and `mso_mdoc`.
- Credential format is determined by the **DCQL query's declared format**, never
  inferred from the JSON shape.
- Failures name what was received and what was expected.
- The in-repo debug wallet and every test fixture use the conformant envelope.

## 4. Non-Goals

Explicitly **out of scope**, deferred to their own runs and to be recorded as
known limitations:

- **Defect 2 — mdoc presentation payload.** For `mso_mdoc`, OpenID4VP Annex B
  requires the presentation to be a base64url-encoded ISO 18013-5
  `DeviceResponse`, with `deviceSigned.deviceAuth.deviceSignature` nested inside
  each document. foundry's `verify_mdoc` takes the device signature as a
  **separate argument** and never reads `deviceSigned` (`verifier.rs:134-140`
  looks up only `issuerSigned`). `grep DeviceResponse` across the workspace
  returns nothing.
- **Defect 3 — SessionTranscript.** `foundry-mdoc/src/types.rs:49` self-documents
  `TODO(interop): simplified handover; not the hashed OID4VPHandover`. foundry
  builds `[null, null, [client_id, response_uri, nonce]]`; the wallet builds
  `[null, null, ["OpenID4VPHandover", bstr(SHA256(cbor([clientId, nonce,
  jwkThumbprint, responseUri])))]]` (`Openid4VpUtils.swift:48-53`). Different
  member order, no label, no hash, and no JWK thumbprint — which is mandatory
  under `direct_post.jwt`. Real mdoc device signatures cannot verify.
- The response body shape (`VerificationResult` vs `{"redirect_uri": …}`),
  already recorded as a follow-up by the predecessor change.

**This change fixes the envelope for both formats. For `mso_mdoc` the envelope
becomes conformant while the payload stays bespoke — mdoc remains
non-interoperable with real wallets.** That must be documented at the dispatch
site and in the crate's `AGENTS.md` so a green mdoc test is not misread as
interop.

## 5. Wire Contract

Accepted, inside the decrypted JWE payload:

```json
{
  "vp_token": {
    "<dcql credential query id>": [ <presentation> ]
  }
}
```

Per-format presentation payload:

| DCQL `format` | Presentation element | Conformant? |
|---|---|---|
| `dc+sd-jwt` | JSON string — SD-JWT VC compact serialization with KB-JWT | yes |
| `mso_mdoc` | JSON object `{"mdoc": "<b64url>", "device_signature": "<b64url>"}` | **no** — bespoke, see §4 |

Rejected (strict spec-only, per D1):

- a bare JSON string `"vp_token": "eyJ…"` — the previous SD-JWT VC shape
- a top-level `"vp_token": {"mdoc": …, "device_signature": …}` — the previous
  mdoc shape. Note this is now *ambiguous by construction* with a conformant
  envelope answering a credential query whose id happens to be `mdoc`; strict
  rejection of the old shape resolves it, since `mdoc` would then have to map
  to an array.

## 6. Design

Replace the type-sniffing dispatch in `verify.rs` with an explicit selection
step, extracted as a private helper so it is unit-testable without building a
JWE:

```
select_presentation(vp_token: &Value, dcql_query: &Value)
    -> Result<(query_id: String, format: PresentedFormat, presentation: &Value), VerificationError>
```

Algorithm:

1. `vp_token` MUST be a JSON object. Otherwise → structural error naming the
   actual JSON type.
2. Parse `dcql_query` into `DcqlQuery`. Unparseable → structural error (D3).
3. Intersect the `vp_token` keys with the DCQL credential query ids.
   - **0 matches** → structural error listing received keys and expected ids.
   - **>1 match** → structural error: multi-credential presentations are
     unsupported (already scoped out at `dcql.rs:9`).
4. The matched value MUST be a JSON array of **exactly one** element. Empty
   array and >1 element are both structural errors — foundry verifies one
   presentation per query, and silently taking `[0]` would under-report.
5. Dispatch on the matched credential query's **declared** `format`:
   - `CredentialFormat::DcSdJwt` → element MUST be a string → existing
     `verify_sd_jwt_vc` call, unchanged.
   - `CredentialFormat::MsoMdoc` → element MUST be an object carrying `mdoc` and
     `device_signature` → existing `verify_mdoc` call, unchanged.
   - A type mismatch here is a structural error naming both the declared format
     and the received JSON type.
6. The `PresentedFormat` **and the matched query id** are passed to
   `check_dcql_match`, which now requires that specific query to be satisfied
   (D4).

Note on step 6: deriving the format from the DCQL query makes
`check_dcql_match`'s old format-matching arm non-discriminating, because the
format now comes from the very query being checked. Rather than leave a
vestigial check, D4 replaces "any query of this format" with "this query, by
id" — strictly stronger, and the shape protection remains at step 5 where it
produces a clearer error.

`check_dcql_match` is `pub` and also called by the debug wallet's
`match_credentials`, which already tracks `query_id` per entry
(`MatchedCredential.query_id`); that call site is updated in the same change.

## 7. Decisions

- **D1 — Strict spec-only.** Reject both previous shapes; no content-negotiation
  or dual-shape acceptance. The bespoke envelope *is* the defect, and its only
  two consumers (debug wallet, tests) are in-repo and migrated in the same
  change. Consistent with the predecessor change's D1.
- **D2 — Validate the key against DCQL ids.** Rather than accepting whatever
  single entry arrives. Required to determine the format anyway, and it binds
  the response to the request.
- **D3 — Unparseable `dcql_query` is a structural error at verification, and is
  now also rejected at creation.** `create_verification_request` stores
  `dcql_query` as an opaque `serde_json::Value` without validating it
  (`request.rs:208-273`), so today a broken query reaches the wallet and only
  surfaces as `200 verified:false` via `check_dcql_match` (`dcql.rs:52`).
  Verification keeps the hard error — we cannot know which format to verify, and
  *inferring it from shape is precisely the bug class being removed* — and
  creation-time validation makes that error unreachable in practice by failing
  the operator's request instead of the wallet's presentation. **Blast radius,
  accepted deliberately:** `DcqlQuery` requires non-empty `credentials`
  (`dcql_model.rs:65`), so two existing artifacts become invalid and are fixed
  as part of this change — the shipped `over18` named query in `config.yaml`
  (`credentials: []`) and `test_create_verification_request_dc_api`
  (`request.rs:580-596`), which currently asserts that an empty query *succeeds*.
  Both are latent defects: an empty DCQL query asks for nothing, and a wallet
  receiving one cannot present anything.
- **D4 — `dcql_match` is tightened to the answered query id.** The wallet states
  which credential query each presentation answers; matching "any query of the
  presented format" discards that. `check_dcql_match` gains an
  `answered_query_id` parameter and requires *that* query to be satisfied. This
  also removes the need for `select_presentation` to hide its query id, so the
  two changes are implemented together (see §12).
- **D5 — OpenAPI specs get a drift test.** Inherited gap from the predecessor
  change: nothing asserted that the committed `openapi.json` /
  `openapi-wallet.json` match generator output.
  `generate_admin_openapi_spec()` and `generate_wallet_openapi_spec()`
  (`openapi.rs:32,70`) are already public, so the test is a direct comparison.

## 8. Error Taxonomy

All new failures are **structural** → `VerificationError::Failed` → HTTP 400
`invalid_request`, consistent with root `AGENTS.md` §4.3. None are policy
failures, so none produce `200 verified:false`.

| Condition | Message shape |
|---|---|
| `vp_token` not an object | names the received JSON type |
| `dcql_query` unparseable | names the parse error |
| no key matches a DCQL id | lists received keys **and** expected ids |
| more than one key matches | states multi-credential is unsupported |
| value not a 1-element array | names the received length/type |
| element type ≠ declared format | names declared format and received type |

Messages must not echo credential contents — only shapes, keys, and types.

## 9. Testing Strategy

Every test below must **fail before the change** for the stated reason.

**Unit (`foundry-verifier/src/verify.rs`)** — against `select_presentation`,
which needs no JWE:

- conformant SD-JWT envelope → returns the query id, `SdJwtVc`, and the string
- conformant mdoc envelope → returns `MsoMdoc` and the object
- bare string `vp_token` → rejected (**the reported bug**)
- top-level `{"mdoc":…,"device_signature":…}` → rejected
- key not in the DCQL query → rejected, message names both received and expected
- two matching keys → rejected as multi-credential
- empty array, and 2-element array → both rejected
- `dc+sd-jwt` query answered with an object, and `mso_mdoc` answered with a
  string → both rejected, message names the declared format
- unparseable `dcql_query` → rejected

**Unit — D4 (`foundry-verifier/src/dcql.rs`)**

- a presentation answering query `a` that satisfies only query `b` now **fails**,
  where it previously passed by matching `b`. This is the behaviour change D4
  buys and must be asserted directly.
- an `answered_query_id` absent from the query → failed check (fail-closed),
  since the wallet-side caller can pass an arbitrary id.

**Unit — D3 (`foundry-verifier/src/request.rs`)**

- `create_verification_request` rejects a malformed `dcql_query`.
- it rejects `{"credentials": []}` — the case `test_create_verification_request_dc_api`
  currently asserts succeeds; that test is rewritten around a valid query.
- a valid query still succeeds, for every transport.

**Drift — D5 (`foundry/tests/`)**

- committed `openapi.json` equals `generate_admin_openapi_spec()`.
- committed `openapi-wallet.json` equals `generate_wallet_openapi_spec()`.
- Compared as parsed JSON so the assertion tracks *content* drift rather than
  serializer whitespace, and the failure message must name the regeneration
  command.

**Integration (`foundry/tests/wallet_verification.rs`)**

- SD-JWT happy path via the conformant envelope, asserting `verified: true`
  **and the four named `CheckResult`s** (root `AGENTS.md` §4.2 — an omitted
  check silently drops out of `all(passed)`, so `verified` alone cannot detect
  a lost check).
- mdoc happy path via the conformant envelope (bespoke payload).
- the bare-string envelope returns 400, not 200.
- the four existing SD-JWT failure-mode tests (revoked, tampered, replay,
  unknown tx) keep their existing assertions, migrated only in envelope shape —
  unchanged assertions are what prove the migration preserved behaviour.

**End-to-end (`foundry/tests/e2e_full_flow.rs`)** — the debug wallet drives a
real in-process server; its migration to the conformant envelope is the only
test that proves client and server agree.

## 10. Global Constraints

- No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` in the request
  path (root `AGENTS.md` §4.1); unwraps only under `#[cfg(test)]` and in
  `tests/`.
- `VerificationResult.verified` stays `checks.iter().all(|c| c.passed)` (§4.2).
- Structural → 400, policy → `200 verified:false`, status-fetch → 502 (§4.3).
- Dependency layering unchanged; no new workspace dependencies.
- Gates: `cargo test --workspace`, `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo fmt --check` — all clean.
- **No OpenAPI change expected**, since `vp_token` lives inside the encrypted
  JWE and appears in no documented schema. To be **verified, not assumed**; if
  a schema does reference it, `openapi.json` / `openapi-wallet.json` must be
  regenerated (§6).

## 11. Acceptance

1. The reported error is gone: a conformant SD-JWT VC envelope verifies.
2. All three gates clean.
3. The bespoke shapes are rejected with actionable messages.
4. mdoc's remaining non-conformance (§4) is documented in code and
   `AGENTS.md` — not left implicit behind a green test.
5. A malformed or empty `dcql_query` fails the operator's create request (D3).
6. `dcql_match` binds to the answered query id (D4).
7. OpenAPI drift is caught by a test (D5).

---

## 12. Revision — Scope Expansion

The original spec deferred four known limitations. At the Phase 3 gate the human
partner asked whether they could be fixed in this run. Assessment:

| Limitation | Decision | Reason |
|---|---|---|
| OpenAPI drift test | **in scope** (D5) | generators already public; ~20 lines, near-zero risk |
| `dcql_match` any-query matching | **in scope** (D4) | strictly stronger, and *simplifies* the design — folded into the same task as the parser since it changes `select_presentation`'s signature |
| `dcql_query` unvalidated at creation | **in scope** (D3) | closes the hole properly; surfaces two further latent defects, fixed here |
| mdoc payload + SessionTranscript (defects 2–3) | **still deferred** | see below |

**Why mdoc interop stays out.** Not difficulty — unverifiability. Two facts:

1. No RFC 7638 JWK thumbprint implementation exists anywhere in the workspace
   (`grep -rn 'thumbprint\|7638'` finds only unrelated literals in
   `foundry-issuer/src/proof.rs`), so byte-exact canonicalisation would be
   written from scratch.
2. `foundry-wallet` has **no** mdoc support at all (`grep 'mso_mdoc\|mdoc'`
   across the crate returns nothing), so no in-repo client can produce a real
   `DeviceResponse`.

Any test would therefore have foundry generating the `DeviceResponse` *and*
verifying it, against one author's reading of the spec on both sides — the exact
self-consistency trap that produced defects 1, 2, and 3. A green test would
manufacture false confidence, which is worse than a documented limitation.

**Unblocking condition:** one captured real mdoc presentation from eudi-pal, or
an official ISO/OpenID test vector, committed as a fixture. With that it becomes
a normal TDD task.