# Admin Console Transaction Data Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator supply OpenID4VP `transaction_data` from the admin test console, and make the verifier actually advertise it on both transports.

**Architecture:** Two source changes. In `foundry-verifier`, the `dc_api` branch of `create_verification_request` gains a conditional `transaction_data` key carrying the already-encoded entries (today it silently drops them, while the `request_uri` branch emits them correctly). In the console asset, the Verification card gains a collapsed disclosure holding a raw-JSON textarea whose contents become `payload.transaction_data` when non-empty. All validation beyond "is a JSON array" stays server-side in the existing `encode_transaction_data`.

**Tech Stack:** Rust (Axum, serde_json, tokio, utoipa), vanilla HTML/CSS/JS in a single embedded asset file, `cargo test` / `cargo clippy` / `cargo fmt`.

**Spec:** `docs/superpowers/specs/2026-08-06-admin-console-transaction-data-design.md`

## Global Constraints

- **Read `crates/<x>/AGENTS.md` before editing files under `crates/<x>/`.** Root `AGENTS.md` routes; nested files are not auto-loaded.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** in production request paths (`foundry-verifier`, `foundry::server`). Permitted only inside `#[cfg(test)]` and files under `tests/`. Root `AGENTS.md` §4.1.
- **Cite the spec in code comments** for protocol-facing logic: name the document and section, e.g. `// OpenID4VP 1.0 §A.3 (DC API / Request)`. Root `AGENTS.md` §4.4.
- **The pinned spec text is `docs/specs/openid-4-verifiable-presentations-1_0.md`.** The relevant clause is the DC API supported-parameter list at L2421–L2431, which includes `transaction_data`. Do not consult a newer draft online.
- **The gate for every task is the SCOPED gate** — root `AGENTS.md` §5.1:
  ```bash
  cargo test -p foundry-verifier -p foundry
  cargo clippy -p foundry-verifier -p foundry --all-targets -- -D warnings
  cargo fmt --check
  ```
  **Do NOT run `cargo test --workspace`** and do NOT run the `#[ignore]`d `e2e_full_flow` suite. Narrow with `--test <file>` while iterating.
- **Do not regenerate `openapi.json` or `openapi-wallet.json`.** No endpoint's path, method, request shape, response shape, or status codes change; `transaction_data` is already in the committed `CreateVerificationRequest` schema. Note: running `foundry serve` or the E2E tests from the repo root rewrites both files as a side effect — if either shows up as a diff, revert it.
- **Do not add a `transaction_data` echo to the console's result panel**, do not build a structured entry form, and do not replicate `encode_transaction_data`'s validation in JavaScript. All three are explicit non-goals in the spec.
- **Do not edit any `AGENTS.md`.** This work adds no module, no public entry point, no invariant, and no deliberate spec deviation — the three triggers in root `AGENTS.md` §8 that would require one.

---

### Task 1: Advertise `transaction_data` in the DC API request object

**Files:**
- Modify: `crates/foundry-verifier/src/request.rs:324-336` (the `if transport_str == "dc_api"` branch) and its `#[cfg(test)] mod tests`
- Test: `crates/foundry-verifier/tests/conformance_vp.rs` (new test appended)
- Modify: `docs/conformance/openid4vc-conformance.md` (VP-0198 evidence cell, line 583)

**Interfaces:**
- Consumes: `encoded_transaction_data: Option<Vec<String>>`, a local already bound at `request.rs:282` — the base64url-encoded entries produced by `encode_transaction_data`, with `transaction_data_hashes_alg` already injected.
- Produces: `CreateVerificationResponse.dc_api_request` gains an optional `transaction_data` member whose value is a JSON array of base64url strings. Task 2 relies on nothing from this task; they are independent.

**Context you need:** `create_verification_request` builds `dc_api_obj` as an immutable `serde_json::json!` literal with exactly five keys. The `else` branch (`request_uri` transport) does not need touching — `build_signed_request_object` at `request.rs:483` already inserts `transaction_data` into the Request Object payload. The whole point of emitting `encoded_transaction_data` rather than the caller's raw objects is that a wallet must hash byte-identical input on both transports.

- [ ] **Step 1: Write the failing conformance test**

Append to `crates/foundry-verifier/tests/conformance_vp.rs`. `B64URL`, `Engine`, `load_verification_transaction` and `CreateVerificationRequest` are already imported at the top of that file; `test_storage()` and `sample_config(key_path, x5c_path)` are existing helpers in it.

```rust
/// OpenID4VP 1.0 §A.3 (DC API / Request, L2421-L2431) lists `transaction_data`
/// among the Authorization Request parameters supported over the W3C Digital
/// Credentials API. The bytes advertised must be the same base64url strings
/// persisted on the transaction -- which are also what the `request_uri`
/// transport emits -- so a wallet hashes identical input on either transport.
#[tokio::test]
async fn dc_api_request_advertises_encoded_transaction_data() {
    let storage = test_storage().await;
    let config = sample_config("/tmp/fake_key.pem", None);

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "dc_api".to_string(),
        transaction_data: Some(vec![serde_json::json!({
            "type": "qes_authorization",
            "credential_ids": ["c1"]
        })]),
    };

    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();

    let verification_id = res.verification_id.clone();
    let dc_req = res.dc_api_request.unwrap();

    let entries = dc_req["transaction_data"]
        .as_array()
        .unwrap_or_else(|| panic!("dc_api_request must carry transaction_data, got: {dc_req}"));
    assert_eq!(entries.len(), 1, "one requested entry must yield one advertised entry");

    let encoded = entries[0]
        .as_str()
        .expect("each transaction_data entry must be a base64url string, not an object");

    let decoded: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(encoded).unwrap()).unwrap();
    assert_eq!(decoded["type"], "qes_authorization");
    assert_eq!(decoded["credential_ids"], serde_json::json!(["c1"]));
    assert_eq!(
        decoded["transaction_data_hashes_alg"],
        serde_json::json!(["sha-256"]),
        "transaction_data_hashes_alg must be injected before encoding (OpenID4VP L3142)"
    );

    let tx = load_verification_transaction(&storage, &verification_id)
        .await
        .unwrap()
        .expect("transaction must be persisted");
    assert_eq!(
        tx.transaction_data.as_deref(),
        Some(&[encoded.to_string()][..]),
        "the advertised bytes must be exactly the bytes stored for the hash check"
    );
}
```

- [ ] **Step 2: Write the failing unit test for the unused case**

Append inside the existing `#[cfg(test)] mod tests` in `crates/foundry-verifier/src/request.rs`, next to `test_create_verification_request_dc_api` (line 753). Note the in-crate `sample_config` takes **one** argument, unlike the integration-test helper.

```rust
    /// A DC API request that does not use transaction data must keep its
    /// previous five-key shape exactly -- the key is conditional, not
    /// unconditionally present-and-null.
    #[tokio::test]
    async fn test_dc_api_request_omits_transaction_data_when_absent() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "dc_api".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let dc_req = res.dc_api_request.unwrap();
        assert!(
            dc_req.as_object().unwrap().get("transaction_data").is_none(),
            "an unsigned DC API request without transaction data must not carry the key: {dc_req}"
        );
    }
```

- [ ] **Step 3: Run both tests to verify they fail**

```bash
cargo test -p foundry-verifier --test conformance_vp dc_api_request_advertises_encoded_transaction_data
cargo test -p foundry-verifier --lib test_dc_api_request_omits_transaction_data_when_absent
```

Expected: the first FAILS with a panic message beginning `dc_api_request must carry transaction_data, got: {"client_metadata":…}` (the key is absent today). The second PASSES already — it is a regression guard for the change you are about to make, not a red test. That asymmetry is expected; do not "fix" it by making the second test fail.

- [ ] **Step 4: Implement the conditional key**

In `crates/foundry-verifier/src/request.rs`, change the `dc_api` branch. Replace:

```rust
    if transport_str == "dc_api" {
        let dc_api_obj = serde_json::json!({
```

with:

```rust
    if transport_str == "dc_api" {
        let mut dc_api_obj = serde_json::json!({
```

then, immediately after the closing `});` of that literal and before the `Ok(CreateVerificationResponse {` that follows it, insert:

```rust
        // OpenID4VP 1.0 §A.3 (DC API / Request, L2421-L2431) lists
        // `transaction_data` among the Authorization Request parameters
        // supported over the W3C Digital Credentials API. The *encoded* entries
        // are emitted -- the same bytes `build_signed_request_object` advertises
        // on the `request_uri` transport -- so a wallet hashes identical input
        // into `transaction_data_hashes` whichever transport it was invoked
        // over. The key is conditional: a request that does not use the feature
        // keeps the unsigned-request shape VP-0198 documents.
        if let (Some(obj), Some(td)) = (
            dc_api_obj.as_object_mut(),
            encoded_transaction_data.as_ref(),
        ) {
            obj.insert("transaction_data".to_string(), serde_json::json!(td));
        }
```

Two details, both deliberate: the tuple `if let` avoids `clippy::collapsible_if` on nested `if let`s, and `as_object_mut()` avoids `dc_api_obj["transaction_data"] = …` — index-assignment on a `serde_json::Value` panics if the value is not an object, which §4.1 forbids in a request path even where it is statically unreachable.

- [ ] **Step 5: Run both tests to verify they pass**

```bash
cargo test -p foundry-verifier --test conformance_vp dc_api_request_advertises_encoded_transaction_data
cargo test -p foundry-verifier --lib test_dc_api_request_omits_transaction_data_when_absent
```

Expected: both PASS.

- [ ] **Step 6: Verify the pre-existing DC API shape tests still pass**

```bash
cargo test -p foundry-verifier --test conformance_vp vp_0198_0201_dc_api_unsigned_request_shape
cargo test -p foundry-verifier --lib test_create_verification_request_dc_api
```

Expected: both PASS. Neither asserts an exhaustive key set — the first checks `client_id` is absent and `response_mode == "dc_api.jwt"`, the second checks `response_mode`, `nonce` and `client_metadata.jwks.keys`. If either fails, you changed more than the one key.

- [ ] **Step 7: Update the VP-0198 conformance evidence**

`docs/conformance/openid4vc-conformance.md` line 583 currently asserts an exhaustive key list that is now false. In that row's evidence cell, replace:

> The `dc_api_obj` JSON built in `create_verification_request` (request.rs) for `transport: "dc_api"` carries only `response_type`, `response_mode`, `dcql_query`, `nonce`, and `client_metadata` -- there is no `client_id` key in the object literal at all

with:

> The `dc_api_obj` JSON built in `create_verification_request` (request.rs) for `transport: "dc_api"` has no `client_id` key in the object literal at all, and none is inserted afterwards -- the only key added conditionally is `transaction_data`, when the request carried it

Change nothing else in that row: the verdict stays `conforming` and the test reference stays `vp_0198_0201_dc_api_unsigned_request_shape`. Do not add, remove, or renumber any row, and do not open a `GAP-` id — §A.3's parameter list is phrased "the following are supported", not as a MUST, so it has no clause row of its own.

- [ ] **Step 8: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-verifier -p foundry
cargo clippy -p foundry-verifier -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: all green. `cargo fmt` first so the suite runs on a formatted tree. **Do not run `cargo test --workspace`.**

- [ ] **Step 9: Commit**

```bash
git add crates/foundry-verifier/src/request.rs \
        crates/foundry-verifier/tests/conformance_vp.rs \
        docs/conformance/openid4vc-conformance.md
git commit -m "fix(verifier): advertise transaction_data over the DC API transport

create_verification_request validated and persisted transaction_data for
both transports but only emitted it on request_uri, so a dc_api request
silently dropped it while still getting a transaction_data_binding check
pushed -- a failed check for a constraint never communicated to the
wallet. OpenID4VP 1.0 §A.3 lists transaction_data among the parameters
supported over the W3C Digital Credentials API.

Emits the already-encoded entries so both transports advertise
byte-identical input for transaction_data_hashes."
```

---

### Task 2: Add the `transaction_data` input to the console

**Files:**
- Modify: `crates/foundry/assets/console.html` — CSS after line 98, markup before line 228, JS inside `initVerification`
- Test: `crates/foundry/tests/console.rs` (new test appended)
- Modify: `README.md:271-275` (the "Verification" bullet under "Admin Test Console")

**Interfaces:**
- Consumes: nothing from Task 1 — these tasks are independent and may be done in either order.
- Produces: a new element id `transaction-data-json` and a new CSS class `opt-disclosure`, both asserted by the test in this task. No Rust signatures change.

**Context you need:** `console.html` is a single self-contained asset embedded via `include_str!` at `crates/foundry/src/server.rs:204` and served by `console_handler`. There is no build step; editing the file is the whole deployment. The verification form is submitted by the `create-verification-btn` click handler inside `initVerification` (around line 3006), which builds a `payload` object and posts it with `adminFetch`.

**Why a new CSS class rather than reusing `qr-disclosure`:** `.qr-disclosure > summary` is `display: none` above 641px (line 98) because the QR block is intentionally always-`open` on desktop and renders as a plain container; `initQrDisclosure` then force-closes it on mobile. Reusing that class would make our summary vanish on desktop with the textarea permanently expanded. Our block ships **closed** with an always-visible summary and no JS involvement — safe because our summary is never CSS-hidden, so a failed script degrades to "collapsed, one click to open".

- [ ] **Step 1: Write the failing console test**

Append to `crates/foundry/tests/console.rs`, following the existing style of `console_has_open_in_wallet_links_for_same_device_flow` (line 181). All imports and the `test_config(bool)` helper already exist in that file.

```rust
#[tokio::test]
async fn console_has_transaction_data_input_for_verification() {
    // OpenID4VP `transaction_data` is implemented end-to-end in the verifier
    // (validated and encoded by `encode_transaction_data`, bound by
    // `check_transaction_data_binding`) but was unreachable from the console:
    // the verification card had no input for it. The field is a raw JSON
    // textarea inside a collapsed disclosure -- entry bodies are type-specific
    // and open-ended, so a structured form would encode a partial schema the
    // console has no business owning.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);

    assert!(
        html.contains(r#"id="transaction-data-json"#),
        "console page should have a transaction_data textarea"
    );
    assert!(
        html.contains("Transaction data (optional)"),
        "the transaction_data textarea should sit behind a labelled disclosure"
    );
    assert!(
        html.contains("opt-disclosure"),
        "the disclosure should use its own class, not the QR block's \
         (whose summary is display:none above 641px)"
    );
    assert!(
        html.contains("payload.transaction_data"),
        "the create-verification handler should put the parsed entries on the payload"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p foundry --test console console_has_transaction_data_input_for_verification
```

Expected: FAIL on the first assertion — `console page should have a transaction_data textarea`.

- [ ] **Step 3: Add the CSS rule**

In `crates/foundry/assets/console.html`, insert after line 98 (the `@media (min-width: 641px) { .qr-disclosure > summary { display: none; } }` line) and before `pre.json {`:

```css
  /* Optional-input disclosure. Unlike `.qr-disclosure` this ships CLOSED with a
     summary visible at every width: the summary is never CSS-hidden, so a page
     whose script failed still degrades to "collapsed, one click to open". */
  .opt-disclosure > summary { cursor: pointer; font-size: 13px; color: var(--muted); padding: 4px 0 10px; }
```

- [ ] **Step 4: Add the markup**

In the same file, insert immediately **before** the line
`    <button class="primary" id="create-verification-btn">Create Verification Request</button>`
(line 228 — the `id` makes it unique; the issuance card's button is `create-offer-btn`):

```html
    <details class="opt-disclosure">
      <summary>Transaction data (optional)</summary>
      <div class="field">
        <label for="transaction-data-json">transaction_data (JSON array)</label>
        <textarea id="transaction-data-json" placeholder='[{"type": "…", "credential_ids": ["…"]}]'></textarea>
      </div>
    </details>
```

The `placeholder` uses single quotes so the JSON's double quotes need no escaping. It shows the minimal shape only — array wrapper, `type`, `credential_ids` — and names no concrete type or credential id, because `credential_ids` must match ids in the operator's own DCQL query.

- [ ] **Step 5: Add the payload wiring**

In the `create-verification-btn` click handler inside `initVerification`, the DCQL mode `if/else` block ends with a line containing only `      }`, followed by a blank line and then `      btn.disabled = true;`. Insert the following between that closing brace and `btn.disabled = true;` (this is the `btn.disabled = true;` inside `initVerification`, not the identical line in `initIssuance`):

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

Three properties this must preserve, in order of importance:

1. **Blank or whitespace-only leaves the key absent from `payload`** — behaviour is byte-identical to today for anyone who ignores the field. Do not send `null`, `[]`, or `""`.
2. **The `Array.isArray` guard stays.** Pasting a single entry `{…}` instead of `[{…}]` would otherwise be rejected by serde at the `Vec<serde_json::Value>` boundary with a generic deserialization message, never reaching `encode_transaction_data`'s precise per-index text.
3. **Nothing beyond shape is checked here.** `type`, `credential_ids`, and cross-referencing the DCQL query are `encode_transaction_data`'s job. Its failures return HTTP 400 with `{"error": "<detail>"}`, and the existing `showError` already renders `err.body.error`, so e.g. *"Request failed (400). invalid request: transaction_data[0] references credential id 'x' which is not present in the DCQL query"* appears in the existing banner with no new plumbing.

- [ ] **Step 6: Run the test to verify it passes**

```bash
cargo test -p foundry --test console
```

Expected: PASS — the new test plus every pre-existing test in the file.

- [ ] **Step 7: Update the README**

In `README.md`, replace the "Verification" bullet under `#### Admin Test Console` (lines 271–275) with:

```markdown
- **Verification**: pick a named query (`named_query_ref`) or paste raw
  `dcql_query` JSON, optionally paste a `transaction_data` JSON array under
  "Transaction data (optional)", click "Create Verification Request" — get back
  the `openid4vp_uri`/`request_uri` as copyable text and as a QR code. The page
  auto-polls the request's status and shows `verified`, each check's
  pass/fail, and the disclosed claims once the wallet responds. When
  `transaction_data` was requested, the checks list gains a
  `transaction_data_binding` entry reporting whether the wallet hashed the
  advertised entries into its Key Binding JWT.
```

- [ ] **Step 8: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-verifier -p foundry
cargo clippy -p foundry-verifier -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: all green. **Do not run `cargo test --workspace`.** If `openapi.json` or `openapi-wallet.json` shows as modified, `git checkout` it — the test run rewrote it as a side effect and this change alters neither spec.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry/assets/console.html crates/foundry/tests/console.rs README.md
git commit -m "feat(console): add a transaction_data input to the verification card

The verifier has supported OpenID4VP transaction_data end-to-end for some
time -- validated and base64url-encoded by encode_transaction_data, bound
by check_transaction_data_binding -- but it was unreachable from the
console, which offered no input for it.

Adds a collapsed 'Transaction data (optional)' disclosure holding a raw
JSON textarea. Entry bodies are type-specific and open-ended, so the
console parses shape only (valid JSON, is an array) and leaves every
per-entry rule to the server, whose 400 detail the existing error banner
already renders. An empty textarea omits the key entirely, so behaviour
is unchanged when the field is ignored."
```

---

### Task 3: Record the change

**Files:**
- Create: `docs/superpowers/changes/2026-08-06-admin-console-transaction-data.md`

**Interfaces:**
- Consumes: the finished state of Tasks 1 and 2. Do this task last.
- Produces: nothing consumed by code.

- [ ] **Step 1: Write the change record**

Create `docs/superpowers/changes/2026-08-06-admin-console-transaction-data.md` with exactly this content:

```markdown
# Admin Console — Transaction Data Support

**Date:** 2026-08-06
**Spec:** `docs/superpowers/specs/2026-08-06-admin-console-transaction-data-design.md`
**Plan:** `docs/superpowers/plans/2026-08-06-admin-console-transaction-data-plan.md`

## What Changed

Two source files: `crates/foundry-verifier/src/request.rs` (a bugfix) and
`crates/foundry/assets/console.html` (the feature). No endpoint changes and no
OpenAPI changes — `transaction_data` was already in the committed
`CreateVerificationRequest` schema.

- **`foundry-verifier`, `create_verification_request`:** the `dc_api` branch now
  inserts a conditional `transaction_data` key into `dc_api_obj`, carrying the
  already-encoded entries. Previously the function validated and persisted
  `transaction_data` for both transports but only `build_signed_request_object`
  (the `request_uri` path) advertised it, so a DC API request silently dropped
  it. OpenID4VP 1.0 §A.3 (L2421–L2431) lists `transaction_data` among the
  parameters supported over the W3C Digital Credentials API.
- **`console.html`:** the Verification card gains a collapsed
  `opt-disclosure` block holding a `transaction_data (JSON array)` textarea
  (`id="transaction-data-json"`). Non-empty contents are parsed and set as
  `payload.transaction_data`; blank leaves the key absent.

## Why the Bugfix Was In Scope

The console's transport selector offers `dc_api`. Shipping the input without
fixing the emission would have produced a transaction whose `transaction_data`
is `Some` — so `check_transaction_data_binding` is pushed — for a request the
wallet received without `transaction_data`, and therefore a failed check for a
constraint never communicated. The console would have reported a verification
failure for a request it never made.

## Validation Split

The console checks shape only: valid JSON, and a JSON array. Everything
per-entry — object-ness, non-empty `type`, non-empty `credential_ids`, every id
resolvable against the DCQL query — stays in `encode_transaction_data`, which
returns HTTP 400 with a per-index detail that the console's existing
`showError` already renders from `err.body.error`. Replicating that validator in
JavaScript was rejected: it is load-bearing and two copies would drift.

## Deliberately Not Done

- No structured entry builder. Entry bodies are `type`-specific and open-ended;
  OpenID4VP defines only `type`, `credential_ids` and
  `transaction_data_hashes_alg`.
- No echo of the advertised entries in the result panel. The
  `transaction_data_binding` check already reports pass/fail, and
  `renderVerificationResult` renders it generically with no changes.
- No signed DC API requests. VP-0197 / VP-0200 / VP-0202 remain
  `not-implemented`.

## Tests

- `dc_api_request_advertises_encoded_transaction_data`
  (`foundry-verifier/tests/conformance_vp.rs`) — the advertised array holds the
  base64url strings persisted on the transaction, and decoding one yields the
  injected `transaction_data_hashes_alg`.
- `test_dc_api_request_omits_transaction_data_when_absent`
  (`foundry-verifier/src/request.rs`) — the key is conditional, so an unused
  request keeps its prior shape.
- `console_has_transaction_data_input_for_verification`
  (`foundry/tests/console.rs`) — the served HTML carries the textarea, the
  disclosure, and the payload wiring.

## Conformance Report

VP-0198's evidence prose was reworded: it had asserted that `dc_api_obj`
"carries only" five named keys, which is no longer true. It now rests on
`client_id`'s absence instead of an exhaustive key list. No verdict changed and
no gap id was opened — §A.3's parameter list is phrased "the following are
supported", not as a MUST, so it has no clause row of its own, which is why the
omission escaped the original audit.
```

- [ ] **Step 2: Confirm no unintended files are dirty**

```bash
git status --porcelain
```

Expected: only `docs/superpowers/changes/2026-08-06-admin-console-transaction-data.md` as untracked. If `openapi.json` or `openapi-wallet.json` appears, `git checkout` it — a `serve` or E2E run rewrote it and this work changes neither spec.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/changes/2026-08-06-admin-console-transaction-data.md
git commit -m "docs: change record for admin console transaction data support"
```

---

## Final Gate (once, at the end of the branch — not per task)

Per root `AGENTS.md` §5.3, run this **only** when every task above is done and you are about to open a PR or request the final whole-branch review:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace 2>&1 | tee /tmp/test-output.log
grep -c "FAILED" /tmp/test-output.log
grep "^test result:" /tmp/test-output.log
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets -- -D warnings
```

The `tee`-then-`grep` pattern is required, not optional: a full-workspace run exceeds the agent harness's output truncation limit, so a bare `tail` can silently drop an earlier binary's `FAILED` off the top (§5.6). `grep "^test result:"` gives one short line per test binary.

After the E2E run, check `git status` — `openapi.json` and `openapi-wallet.json` are rewritten on server startup, and neither should be part of this branch.