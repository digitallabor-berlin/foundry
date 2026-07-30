# Spec — OpenID4VP-Conformant `vp_token` Envelope Parsing

**Date:** 2026-07-30
**Type:** bugfix (protocol conformance)
**Track:** C (investigate) → B (spec + plan)
**Branch:** superlight/2026-07-30-vp-token-envelope-parsing
**Predecessor:** docs/superlight/changes/2026-07-30-vp-response-form-parsing.md

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
- Validating `dcql_query` at transaction-creation time (see §7 D3).
- Tightening `dcql_match` to the specifically answered query id (see §7 D4).
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
6. The resulting `PresentedFormat` is passed to `check_dcql_match` exactly as
   today.

Note on step 6: deriving the format from the DCQL query makes
`check_dcql_match`'s own format-matching arm non-discriminating **for the
matched query**. The protection is not lost — it moves to step 5, earlier and
with a clearer error — and the arm still filters when several credential
queries of differing formats exist. This is a deliberate relocation, not a
removal.

## 7. Decisions

- **D1 — Strict spec-only.** Reject both previous shapes; no content-negotiation
  or dual-shape acceptance. The bespoke envelope *is* the defect, and its only
  two consumers (debug wallet, tests) are in-repo and migrated in the same
  change. Consistent with the predecessor change's D1.
- **D2 — Validate the key against DCQL ids.** Rather than accepting whatever
  single entry arrives. Required to determine the format anyway, and it binds
  the response to the request.
- **D3 — Unparseable `dcql_query` is a structural error.** Today that yields
  `200 verified:false` through `check_dcql_match` (`dcql.rs:52`), because
  `create_verification_request` stores `dcql_query` as an opaque
  `serde_json::Value` without validating it (`request.rs:208-273`). We cannot
  determine which format to verify, and *inferring it from shape is precisely
  the bug class being removed*. **Honest consequence:** the "not a valid DCQL
  query" branch of `check_dcql_match` remains unit-tested but becomes
  unreachable from the request path. The real fix — validating at creation time
  — is a follow-up, not this run.
- **D4 — `dcql_match` semantics unchanged.** It still requires *some* credential
  query of the presented format to be satisfied, rather than specifically the
  answered query id. Tightening it is a genuine improvement and explicit scope
  creep; deferred.

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