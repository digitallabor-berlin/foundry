# Admin Test Console — Transaction Data Support

**Date:** 2026-08-06
**Status:** Approved
**Scope:** `crates/foundry-verifier/src/request.rs`,
`crates/foundry/assets/console.html`, `README.md`,
`docs/conformance/openid4vc-conformance.md`

---

## 1. Problem

The Admin Test Console (`GET /console`, served from the embedded
`crates/foundry/assets/console.html`) cannot exercise OpenID4VP's
`transaction_data` parameter. Its Verification card offers only a DCQL mode
toggle (`named_query_ref` / raw `dcql_query`) and a `transport` selector; there
is no `transaction_data` input anywhere on the page.

The backend, by contrast, already supports the feature:

| Capability | Location |
|---|---|
| `transaction_data: Option<Vec<serde_json::Value>>` on the admin request body | `foundry-verifier/src/request.rs:23` |
| Per-entry validation (object, non-empty `type`, non-empty `credential_ids`, every id resolvable against the DCQL query) | `encode_transaction_data`, `request.rs:130` |
| `transaction_data_hashes_alg` injection + base64url encoding per OpenID4VP §8.4 | `encode_transaction_data`, `request.rs:189`–`:202` |
| Emission in the signed Request Object (`request_uri` transport) | `build_signed_request_object`, `request.rs:483` |
| `transaction_data_hashes` binding verification | `check_transaction_data_binding`, `verify.rs` |
| Admin `CreateVerificationRequest` schema, including `transaction_data` | `openapi.json` (already current) |

So the gap is purely one of **input**: there is no way to reach an implemented
feature from the console.

### 1.1 A second, adjacent gap

Investigating the above surfaced a genuine defect in `foundry-verifier`.
`create_verification_request` validates and persists `transaction_data` for
**both** transports (`request.rs:280`–`:301`), but only the `request_uri` path
actually advertises it. The `transport == "dc_api"` branch builds `dc_api_obj`
(`request.rs:325`–`:336`) with exactly five keys — `response_type`,
`response_mode`, `dcql_query`, `nonce`, `client_metadata` — so
**`transaction_data` is silently dropped.**

OpenID4VP 1.0 §A.3 (`#dc_api_request`, L2421–L2431) lists `transaction_data`
among the Authorization Request parameters supported over the W3C Digital
Credentials API. The omission carries no comment marking it deliberate, so per
root `AGENTS.md` §4.4 it is a silent divergence, not a documented limitation.

This is not merely adjacent — it would corrupt the feature being added here.
The console's `transport` selector offers `dc_api`. Filling in a new
`transaction_data` field and selecting `dc_api` would produce:

1. a transaction whose `transaction_data` is `Some`, so
   `check_transaction_data_binding` **is** pushed;
2. a request the wallet receives **without** `transaction_data`, so it returns
   no `transaction_data_hashes`;
3. therefore a failed check — for a constraint that was never communicated.

The console would report a verification failure for a request it never made.
Adding the input without fixing the emission manufactures a false negative, so
both changes belong in this one piece of work.

## 2. Non-Goals

- **No structured entry builder.** The input is a raw JSON textarea. Entry
  bodies are `type`-specific and open-ended — OpenID4VP defines only `type`,
  `credential_ids` and `transaction_data_hashes_alg`; everything else comes from
  the type's own specification. A textarea stays correct as types are added; a
  form would encode a partial schema the console has no business owning.
- **No client-side replication of `encode_transaction_data`'s validation.**
  That validator is load-bearing and lives in `foundry-verifier` deliberately.
  Two copies would drift.
- **No echo of the advertised entries in the result panel.** The
  `transaction_data_binding` check line already reports pass/fail, and
  `renderVerificationResult` renders it generically today with no changes.
  Decoding the stored base64url strings back to JSON for display is a distinct
  debugging concern, better added on its own if a hash mismatch ever needs
  diagnosing.
- **No signed DC API requests.** Out of scope and unrelated; VP-0197 / VP-0200 /
  VP-0202 remain `not-implemented`.

## 3. Design

### 3.1 `foundry-verifier` — advertise `transaction_data` over the DC API

In `create_verification_request`, the `dc_api` branch gains a conditional key.
The key is present **only** when the operator supplied entries, so an unsigned
request that does not use the feature keeps its current shape byte-for-byte:

```rust
let mut dc_api_obj = serde_json::json!({ /* unchanged five keys */ });

// OpenID4VP 1.0 §A.3 (DC API / Request) lists `transaction_data` among the
// Authorization Request parameters supported over the W3C Digital Credentials
// API. The *encoded* entries are emitted -- the same bytes the request_uri
// transport advertises via build_signed_request_object -- so a wallet hashes
// identical input into `transaction_data_hashes` on either transport.
if let (Some(obj), Some(td)) = (dc_api_obj.as_object_mut(), encoded_transaction_data.as_ref()) {
    obj.insert("transaction_data".to_string(), serde_json::json!(td));
}
```

Two decisions inside this:

- **Emit `encoded_transaction_data`, never `req.transaction_data`.** This is the
  load-bearing detail. Encoding — including `transaction_data_hashes_alg`
  injection — happens once, above, precisely so that what is advertised and what
  a wallet hashes are the same bytes. Re-deriving or passing the unencoded
  objects here would break that guarantee on the DC API transport only, which is
  the hardest class of bug to observe.
- **Mutate the `json!` literal via `as_object_mut` rather than building a
  `serde_json::Map` field by field.** Smaller diff, and the five-key literal
  stays readable as a single expression that mirrors the spec's non-normative
  example.

### 3.2 Console — markup and CSS

A new disclosure block in the Verification card, positioned **after** the
`transport` select and immediately before the `Create Verification Request`
button: the field is optional and advanced, so it comes last, and it reads
naturally after the DCQL query whose `credential_ids` it references.

```html
<details class="opt-disclosure">
  <summary>Transaction data (optional)</summary>
  <div class="field">
    <label for="transaction-data-json">transaction_data (JSON array)</label>
    <textarea id="transaction-data-json"
      placeholder='[{"type": "…", "credential_ids": ["…"]}]'></textarea>
  </div>
</details>
```

**The disclosure uses a new `opt-disclosure` class, not the existing
`qr-disclosure`.** Reusing the latter would be a defect: `.qr-disclosure >
summary` is `display: none` above 641px (`console.html:98`), because the QR
block is intentionally always-`open` on desktop and renders as a plain
container. Our summary would therefore disappear on desktop with the textarea
permanently expanded, and `initQrDisclosure` would additionally force-close the
block on mobile.

```css
.opt-disclosure > summary {
  cursor: pointer; font-size: 13px; color: var(--muted); padding: 4px 0 10px;
}
```

The summary is visible at every width; the block ships **closed**; no
JavaScript participates.

This inverts the QR block's ship-`open`-and-close-on-mobile arrangement, and
that is correct here. The comment above `initQrDisclosure` explains its reason:
`open` is an HTML attribute CSS cannot set, so shipping closed would leave the
QR unreachable behind a CSS-hidden `<summary>` if the script failed. Our summary
is *never* CSS-hidden, so shipping closed degrades to "collapsed, one click to
open" — always reachable, script or no script.

The textarea reuses the card's existing `.field` styling, so it inherits the
mono font, sizing and `min-height: 90px` that `dcql_query` already uses.

**Placeholder, not a default value.** The textarea must start empty, because
emptiness is the signal for "no transaction data" (§3.3). The placeholder shows
the minimal shape — array wrapper, `type`, `credential_ids` — with `…` ellipses
that make it obviously a template. It names no concrete `type`, and no concrete
`credential_ids`: those must match ids in the operator's own DCQL query, so any
concrete value would be wrong more often than right.

### 3.3 Console — payload wiring and validation

Inside the existing `create-verification-btn` click handler in
`initVerification`, after the DCQL mode block and before the `adminFetch` call:

```js
const txDataRaw = document.getElementById('transaction-data-json').value;
if (txDataRaw.trim()) {
  let parsed;
  try {
    parsed = JSON.parse(txDataRaw);
  } catch (e) {
    showError(errorEl, new Error('transaction_data is not valid JSON: ' + e.message));
    return;
  }
  if (!Array.isArray(parsed)) {
    showError(errorEl, new Error('transaction_data must be a JSON array of objects.'));
    return;
  }
  payload.transaction_data = parsed;
}
```

Three properties this guarantees:

1. **Empty or whitespace-only ⇒ the key is absent from the payload.** Behaviour
   is unchanged for every operator who ignores the field. There is no second
   piece of state (no checkbox) that could disagree with the textarea's
   contents, so there is no checked-but-empty ambiguity to resolve.
2. **The parse-failure message mirrors the existing `dcql_query` wording**, so
   the two textareas fail the same way.
3. **The `Array.isArray` guard closes one specific rough edge.** Pasting a
   single entry `{…}` instead of `[{…}]` would otherwise be rejected by serde at
   the `Vec<serde_json::Value>` boundary, before `encode_transaction_data` runs
   — yielding a generic deserialization message instead of that function's
   precise per-index text. Three lines convert it into a clear local error.

Everything beyond shape stays server-side. `verifier_admin_error_response`
already returns `{"error": "<detail>", …}` with HTTP 400 for
`VerificationError::InvalidRequest`, and `showError` already renders
`err.body.error`, so a bad entry surfaces in the existing error banner as e.g.:

> Request failed (400). invalid request: transaction_data[0] references
> credential id 'x' which is not present in the DCQL query

No new error plumbing is required.

### 3.4 Result rendering — unchanged

`renderVerificationResult` iterates `tx.result.checks` generically, creating one
`<li>` per `CheckResult` with its `check` name and optional `detail`. The fifth
check, `transaction_data_binding`, therefore renders with no changes the moment
a request carries transaction data.

## 4. Data Flow

```
console textarea (JSON array of objects)
  → POST /admin/verification/requests { transaction_data: [...] }
  → create_verification_request
      → encode_transaction_data: validate, inject transaction_data_hashes_alg,
        base64url-encode                              [existing]
      → persist encoded strings on VerificationTransaction   [existing]
      ├─ transport=request_uri → build_signed_request_object inserts
      │    `transaction_data` into the Request Object payload   [existing]
      └─ transport=dc_api      → dc_api_obj gains `transaction_data`  [NEW]
  → wallet hashes each advertised string → transaction_data_hashes in KB-JWT
  → verify_vp_response → check_transaction_data_binding          [existing]
  → GET /admin/verification/requests/:id → console renders the check [existing]
```

## 5. Error Handling

| Failure | Where detected | Surfaced as |
|---|---|---|
| Textarea is not valid JSON | Console, before `fetch` | Local error banner, no request sent |
| Parsed JSON is not an array | Console, before `fetch` | Local error banner, no request sent |
| Entry is not an object / `type` missing or empty / `credential_ids` missing, empty, non-string, or naming an id absent from the DCQL query | `encode_transaction_data` | HTTP 400 `InvalidRequest`, rendered by `showError` from `err.body.error` |
| Wallet omits or mis-computes `transaction_data_hashes` | `check_transaction_data_binding` | HTTP 200, `verified: false`, failed `transaction_data_binding` check in the checks list (root `AGENTS.md` §4.3 — a policy outcome) |

No new `VerificationError` variant is introduced, so
`verifier_admin_error_response`'s match is unaffected.

## 6. Testing

| Test | Location | Asserts |
|---|---|---|
| DC API request advertises encoded transaction data | `foundry-verifier/tests/conformance_vp.rs` (new) | With `transport: "dc_api"` and one valid entry, `dc_api_request["transaction_data"]` is a one-element array of strings, and base64url-decoding element 0 yields a JSON object carrying the injected `transaction_data_hashes_alg` — proving both transports advertise identical bytes |
| DC API shape unchanged when unused | `foundry-verifier/src/request.rs` unit test (new) | With `transport: "dc_api"` and `transaction_data: None`, the `transaction_data` key is absent from `dc_api_request` |
| Console exposes the input | `foundry/tests/console.rs` (new) | Served `/console` HTML contains `id="transaction-data-json"`, the `opt-disclosure` summary, and the placeholder |

`vp_0198_0201_dc_api_unsigned_request_shape` continues to pass: it asserts
`client_id` is absent and `response_mode == "dc_api.jwt"`, not an exhaustive key
set.

**Gate** — root `AGENTS.md` §5.1, scoped to the touched crate plus its affected
dependent:

```bash
cargo test -p foundry-verifier -p foundry
cargo clippy -p foundry-verifier -p foundry --all-targets -- -D warnings
cargo fmt --check
```

The E2E suite and `cargo test --workspace` are **not** part of this gate (§5.1,
§5.3).

## 7. Documentation Impact

- **`README.md`** — the "Admin Test Console" Verification bullet gains a mention
  of the optional transaction data field.
- **`docs/conformance/openid4vc-conformance.md`** — VP-0198's evidence prose
  currently states that `dc_api_obj` "carries only `response_type`,
  `response_mode`, `dcql_query`, `nonce`, and `client_metadata` -- there is no
  `client_id` key in the object literal at all". The first half becomes false.
  Replace the evidence cell's text with wording that rests on `client_id`'s
  absence rather than on an exhaustive key list, e.g.:

  > The `dc_api_obj` JSON built in `create_verification_request` (request.rs)
  > for `transport: "dc_api"` has no `client_id` key in the object literal at
  > all, and none is inserted afterwards -- the only key added conditionally is
  > `transaction_data`, when the request carried it

  **No verdict changes** (VP-0198 stays `conforming`, same test reference). No gap ID is
  closed or opened: §A.3's parameter list is phrased as "the following are
  supported", not as a MUST, so it has no clause row of its own — which is
  exactly why the omission escaped the audit.
- **`docs/superpowers/changes/2026-08-06-admin-console-transaction-data.md`** —
  change record.
- **`openapi.json` / `openapi-wallet.json`** — no regeneration. No endpoint's
  path, method, request shape, response shape, or status codes change;
  `transaction_data` is already present in the committed
  `CreateVerificationRequest` schema.
- **No crate `AGENTS.md` edits** — no new module, no new public entry point, no
  new invariant, and no new deliberate deviation to record.