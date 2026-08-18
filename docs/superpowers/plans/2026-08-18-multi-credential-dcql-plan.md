# Multi-Credential DCQL Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let foundry's verifier verify a `vp_token` that answers N DCQL credential queries, instead of rejecting anything beyond one credential with HTTP 400.

**Architecture:** `VerificationResult` gains `credentials: Vec<PresentedCredential>` and loses its flat `claims` field, because merging N credentials' claims into one map makes `check_status` read the wrong credential's status list. `select_presentation` becomes `select_presentations`, returning every answered credential in DCQL declaration order; the orchestrator's linear flow becomes a verify-all loop that collects per-credential checks without early return. A missing credential is a policy verdict (HTTP 200, `verified: false`); an unreachable status list keeps its HTTP 502 but travels beside the result so the operator keeps the other credentials' verdicts.

**Tech Stack:** Rust (Cargo workspace), `serde_json`, `josekit`, `utoipa` (OpenAPI generation), `cargo-nextest` (test runner), vanilla JS + HTML for the admin console.

**Spec:** [`docs/superpowers/specs/2026-08-18-multi-credential-dcql-design.md`](../specs/2026-08-18-multi-credential-dcql-design.md)

## Global Constraints

Every task's requirements implicitly include this section.

- **Test runner is `cargo nextest run`, never `cargo test`.** The gate is the whole workspace; there is no scoped or cheaper tier.
- **The gate**, run before marking any task complete:

  ```bash
  cargo fmt
  cargo nextest run --workspace --no-fail-fast --status-level fail
  cargo clippy --workspace --all-targets -- -D warnings
  ```

  A green run prints roughly ten lines ending in `Summary [ <elapsed>] <N> tests run: <N> passed, <M> skipped`. Quote that line when reporting.
- **No `.unwrap()`, `.expect()`, `panic!()`, or `unreachable!()`** outside `#[cfg(test)]` code. Return `VerificationError` (root `AGENTS.md` §4.1).
- **`verified` is always derived, never assigned a literal.** After this plan it equals the conjunction over the top-level `checks` **and** every `credentials[i].checks` entry (root `AGENTS.md` §4.2, as amended by Task 7).
- **Policy vs. structural (root `AGENTS.md` §4.3):** policy failure → `Ok` with `CheckResult { passed: false }` → HTTP 200 `verified: false`. Structural/crypto → `Err(Failed | Decryption | Serialization)` → HTTP 400. Network status-fetch failure → `Err(StatusUnavailable)` → HTTP 502.
- **Every `#[tracing::instrument]` MUST carry `skip_all`** (root `AGENTS.md` §4.5), enforced by `crates/foundry/tests/instrumentation_hygiene.rs`.
- **Never log** disclosed claims, private/ephemeral JWKs, access tokens, nonces, or raw JWEs. DCQL credential query ids and claim paths **are** loggable: they are operator-authored request structure, not holder values.
- **Spec citations are mandatory** in new protocol-facing code (root `AGENTS.md` §4.4). The pinned text is `docs/specs/openid-4-verifiable-presentations-1_0.md`. Cite by line: **L745-746** (credential query `id` uniqueness), **L993** (all credentials requested when `credential_sets` absent), **L1007-1008** (a wallet that cannot deliver all non-optional credentials MUST NOT return any), **L1166** (`vp_token` shape; exactly one presentation when `multiple` is omitted/false).
- **Non-goals — do not implement:** `credential_sets`, `multiple: true`. The exactly-one-presentation-per-entry guard **stays**.
- **Commit after every task.** Each task must leave the workspace compiling with a green gate.

---

## Task 1: Reject duplicate credential query ids at request creation

Closes conformance row **VP-0094**. Independent of every other task — no shared types — so it can be done first or in parallel.

**Why this is in scope at all:** under single-credential verification, two credential queries sharing an `id` was a bounded operator misconfiguration, because every lookup resolved to the first match. Under multi-credential verification it is *ambiguous*: Task 3's `select_presentations` matches each credential query against `vp_token`'s keys, so two queries sharing an id both match the **same** entry — one presentation would be verified twice under two different queries and appear as two `credentials` entries with identical `query_id`s and possibly opposite `dcql_match` verdicts. There is no correct behaviour to choose.

**Files:**

- Modify: `crates/foundry-verifier/src/request.rs:244-246` (the existing validate-before-persist block)
- Test: `crates/foundry-verifier/src/request.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: nothing from other tasks.
- Produces: nothing other tasks depend on. Behaviour only: `create_verification_request` now returns `VerificationError::Dcql` for a query with repeated credential query ids.

- [ ] **Step 1: Write the failing test**

Add to the inline `mod tests` in `crates/foundry-verifier/src/request.rs`, next to `create_rejects_empty_credentials_dcql_query`:

```rust
    /// OpenID4VP 1.0 L745-746: "Within the Authorization Request, the same `id`
    /// MUST NOT be present more than once."
    ///
    /// Unvalidated, this was a bounded operator misconfiguration -- every lookup
    /// resolved to the first match. Multi-credential verification makes it
    /// ambiguous: `select_presentations` matches each credential query against
    /// `vp_token`'s keys, so two queries sharing an id both match the SAME entry
    /// and one presentation would be verified twice under contradictory queries.
    /// There is no correct behaviour available, so the request is refused before
    /// it is persisted.
    #[tokio::test]
    async fn create_rejects_duplicate_credential_query_ids() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [
                    {"id": "pid", "format": "dc+sd-jwt"},
                    {"id": "pid", "format": "mso_mdoc"}
                ]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let err = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            matches!(err, VerificationError::Dcql(_)),
            "a repeated credential query id is the operator's error, so it must be \
             Dcql (HTTP 400 on the admin API), got: {err}"
        );
        assert!(
            msg.contains("pid"),
            "the message must name the repeated id so the operator can find it: {msg}"
        );
    }

    /// Distinct ids remain acceptable -- this is the case the feature exists for.
    #[tokio::test]
    async fn create_accepts_multiple_distinct_credential_queries() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [
                    {"id": "pid", "format": "dc+sd-jwt"},
                    {"id": "mdl", "format": "mso_mdoc"}
                ]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .expect("a multi-credential query with distinct ids must be accepted");
    }
```

- [ ] **Step 2: Run the tests to verify the first fails**

```bash
cargo nextest run -p foundry-verifier create_rejects_duplicate_credential_query_ids
```

Expected: FAIL — the request is accepted, so `unwrap_err()` panics with `called Result::unwrap_err() on an Ok value`.

Also run the second test; it should already PASS (multi-credential requests are already accepted):

```bash
cargo nextest run -p foundry-verifier create_accepts_multiple_distinct_credential_queries
```

- [ ] **Step 3: Write the implementation**

In `crates/foundry-verifier/src/request.rs`, replace the existing validation block:

```rust
    // Validate before persisting. An unusable dcql_query would otherwise be
    // stored, advertised to a wallet, and only surface at verification time --
    // presenting the operator's configuration mistake as a presentation failure.
    // `Dcql` maps to HTTP 400 on the admin API (`verifier_admin_error_response`).
    serde_json::from_value::<crate::dcql_model::DcqlQuery>(dcql.clone()).map_err(|e| {
        VerificationError::Dcql(format!("dcql_query is not a valid DCQL query: {e}"))
    })?;
```

with:

```rust
    // Validate before persisting. An unusable dcql_query would otherwise be
    // stored, advertised to a wallet, and only surface at verification time --
    // presenting the operator's configuration mistake as a presentation failure.
    // `Dcql` maps to HTTP 400 on the admin API (`verifier_admin_error_response`).
    let parsed: crate::dcql_model::DcqlQuery =
        serde_json::from_value(dcql.clone()).map_err(|e| {
            VerificationError::Dcql(format!("dcql_query is not a valid DCQL query: {e}"))
        })?;

    // OpenID4VP 1.0 L745-746: "Within the Authorization Request, the same `id`
    // MUST NOT be present more than once."
    //
    // This is checked here rather than at deserialization because it is the
    // operator's error, and this is where operator errors become HTTP 400
    // instead of a later presentation failure that reads as the wallet's fault.
    // It is load-bearing for multi-credential verification: `select_presentations`
    // matches each credential query against `vp_token`'s keys, so two queries
    // sharing an id both match the SAME entry -- one presentation would be
    // verified twice under contradictory queries, with no correct outcome to pick.
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for cq in parsed.credentials() {
        if !seen.insert(cq.id()) {
            return Err(VerificationError::Dcql(format!(
                "dcql_query repeats credential query id '{}'; OpenID4VP 1.0 requires \
                 each credential query id to appear at most once",
                cq.id()
            )));
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier create_rejects_duplicate_credential_query_ids create_accepts_multiple_distinct_credential_queries
```

Expected: PASS, 2 tests.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Quote the nextest summary line.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-verifier/src/request.rs
git commit -m "feat(verifier): reject duplicate DCQL credential query ids

OpenID4VP 1.0 L745-746 requires each credential query id to appear at most
once. Unvalidated this was a bounded operator misconfiguration, because
every lookup resolved to the first match. Multi-credential verification
makes it ambiguous instead: selection matches each credential query against
the vp_token's keys, so two queries sharing an id both match the same entry
and one presentation would be verified twice under contradictory queries.

Rejected at request creation, where operator errors already become HTTP 400
rather than a later presentation failure that reads as the wallet's fault.

Closes conformance row VP-0094."
```

---

## Task 2: Reshape `VerificationResult` into per-credential records

Pure reshaping — **no behaviour change**. The existing single-credential flow produces exactly one `PresentedCredential`. Every gate stays green, so the branch is never in a half-migrated state.

**Files:**

- Modify: `crates/foundry-verifier/src/transaction.rs` (add `PresentedCredential`, change `VerificationResult`, add the two-level check helpers)
- Modify: `crates/foundry-verifier/src/lib.rs` (export `PresentedCredential`)
- Modify: `crates/foundry-verifier/src/verify.rs` (build one record at the success path ~line 827; `credentials: Vec::new()` at the error path ~line 294; 3 test assertions)
- Modify: `crates/foundry/src/openapi.rs:27-30,72-73` (register the new schema)
- Modify: `crates/foundry/assets/console.html` (DOM at ~line 265, `renderVerificationResult` at ~line 2814, the hide-on-reset block at ~line 3137)
- Modify: `crates/foundry/tests/wallet_verification.rs` (6 `.claims` assertions at lines 330, 351, 475, 1246, 1396, 1616)
- Regenerate: `openapi-wallet.json`, `openapi.json`

**Interfaces:**

- Consumes: nothing from other tasks.
- Produces, relied on by Tasks 3-6:
  - `pub struct PresentedCredential { pub query_id: String, pub format: String, pub claims: serde_json::Value, pub checks: Vec<CheckResult> }`
  - `pub struct VerificationResult { pub verified: bool, pub checks: Vec<CheckResult>, pub credentials: Vec<PresentedCredential> }`
  - `impl VerificationResult { pub fn all_checks(&self) -> impl Iterator<Item = &CheckResult>; pub fn derive_verified(&self) -> bool }`

- [ ] **Step 1: Write the failing test**

Add to the inline `mod tests` in `crates/foundry-verifier/src/transaction.rs`:

```rust
    /// Root AGENTS.md §4.2 after multi-credential support: `verified` MUST equal
    /// the conjunction over EVERY `CheckResult` in the result -- the top-level
    /// `checks` AND every `credentials[i].checks` entry. Checking only
    /// `self.checks` is satisfiable while a per-credential check fails, which is
    /// precisely the defect these helpers exist to make unrepresentable.
    #[test]
    fn all_checks_spans_both_levels_and_derives_the_verdict() {
        let pass = |name: &str| CheckResult {
            check: name.to_string(),
            passed: true,
            detail: None,
        };

        let mut result = VerificationResult {
            verified: false,
            checks: vec![pass("jwe_decryption")],
            credentials: vec![
                PresentedCredential {
                    query_id: "pid".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    claims: serde_json::json!({"given_name": "Alice"}),
                    checks: vec![pass("sd_jwt_vc_signature_and_kb_jwt"), pass("dcql_match")],
                },
                PresentedCredential {
                    query_id: "mdl".to_string(),
                    format: "mso_mdoc".to_string(),
                    claims: serde_json::json!({}),
                    checks: vec![pass("mdoc_issuer_auth_and_device_signature")],
                },
            ],
        };

        assert_eq!(
            result.all_checks().count(),
            4,
            "all_checks must span the top level and every credential"
        );
        assert!(result.derive_verified(), "every check passed");

        // A failure buried in the SECOND credential must still sink the verdict.
        // A top-level-only `all(passed)` would report this result as verified.
        result.credentials[1].checks[0].passed = false;
        assert!(
            !result.derive_verified(),
            "a failed per-credential check must sink the overall verdict"
        );
        assert!(
            result.checks.iter().all(|c| c.passed),
            "and it must do so even though every TOP-LEVEL check still passes -- \
             this is the case a single-level all(passed) gets wrong"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo nextest run -p foundry-verifier all_checks_spans_both_levels
```

Expected: FAIL to **compile** — `cannot find struct PresentedCredential`, `no field credentials on VerificationResult`, `no method named all_checks`.

- [ ] **Step 3: Add the types**

In `crates/foundry-verifier/src/transaction.rs`, replace the `VerificationResult` struct with:

```rust
/// One credential presented in a `vp_token`, with the checks run against it and
/// the claims it disclosed.
///
/// Claims are held **per credential** and never merged into a single map.
/// Merging is not a presentation choice but a correctness bug: `check_status`
/// reads `status.status_list` out of the map it is handed, so a merged map lets
/// one credential's `status` claim displace another's and runs a revocation
/// check against the wrong status list -- silently, with a passing
/// `status_check`. Two credentials disclosing the same claim name collide the
/// same way.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PresentedCredential {
    /// The DCQL credential query id this presentation answered
    /// (OpenID4VP 1.0 L1166).
    pub query_id: String,
    /// The credential format the answered query **declared**: `dc+sd-jwt` or
    /// `mso_mdoc`. Never inferred from the payload's JSON type.
    pub format: String,
    /// This credential's disclosed claims only.
    pub claims: serde_json::Value,
    /// Checks scoped to this credential: its format-specific signature check,
    /// `dcql_match`, `status_check`, and `transaction_data_binding` when the
    /// request carried `transaction_data`.
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VerificationResult {
    pub verified: bool,
    /// **Cross-cutting checks only** -- `jwe_decryption` and
    /// `requested_credentials_answered`. Per-credential checks live in
    /// `credentials[i].checks`.
    pub checks: Vec<CheckResult>,
    /// One entry per credential the `vp_token` answered, in DCQL declaration
    /// order (not `vp_token` key order, which depends on serde_json's map type).
    pub credentials: Vec<PresentedCredential>,
}

impl VerificationResult {
    /// Every `CheckResult` in this result: the top-level `checks` followed by
    /// each credential's `checks`.
    ///
    /// Root AGENTS.md §4.2 requires `verified` to be the conjunction over **all**
    /// of these. Iterating only `self.checks` is satisfiable while a
    /// per-credential check fails, so use this rather than `self.checks` anywhere
    /// the question is "did everything pass".
    pub fn all_checks(&self) -> impl Iterator<Item = &CheckResult> {
        self.checks
            .iter()
            .chain(self.credentials.iter().flat_map(|c| c.checks.iter()))
    }

    /// The §4.2 verdict, derived. Never assign `verified` a literal; assign this.
    pub fn derive_verified(&self) -> bool {
        self.all_checks().all(|c| c.passed)
    }
}
```

- [ ] **Step 4: Export it**

In `crates/foundry-verifier/src/lib.rs`, change the `transaction` re-export:

```rust
pub use transaction::{
    CheckResult, PresentedCredential, VerificationResult, VerificationState,
    VerificationTransaction, load_verification_transaction, save_verification_transaction,
};
```

- [ ] **Step 5: Update the round-trip test's literal in `transaction.rs`**

At `crates/foundry-verifier/src/transaction.rs:124`, replace the `claims` field:

```rust
        tx.result = Some(VerificationResult {
            verified: true,
            checks: vec![CheckResult {
                check: "signature".to_string(),
                passed: true,
                detail: Some("valid signature".to_string()),
            }],
            credentials: vec![PresentedCredential {
                query_id: "c1".to_string(),
                format: "dc+sd-jwt".to_string(),
                claims: serde_json::json!({"given_name": "Alice"}),
                checks: Vec::new(),
            }],
        });
```

- [ ] **Step 6: Update `verify.rs`'s success path**

At `crates/foundry-verifier/src/verify.rs`, the tail of `do_verify_vp_response` currently reads:

```rust
    // 6. Overall verdict is the AND of every check performed.
    let verified = checks.iter().all(|c| c.passed);
    Ok(VerificationResult {
        verified,
        checks,
        claims: claims_value,
    })
```

Replace with a single-credential record. `answered_query_id` and `presented_format` are already in scope:

```rust
    // 6. One credential per `vp_token` today; Task 4 turns this into a loop.
    //    Every check above is scoped to this credential, so it belongs in the
    //    record rather than at the top level -- only `jwe_decryption` is
    //    cross-cutting.
    let jwe_check_count = 1;
    let per_credential_checks = checks.split_off(jwe_check_count);

    let credential = PresentedCredential {
        query_id: answered_query_id,
        format: match presented_format {
            PresentedFormat::SdJwtVc => "dc+sd-jwt".to_string(),
            PresentedFormat::MsoMdoc => "mso_mdoc".to_string(),
        },
        claims: claims_value,
        checks: per_credential_checks,
    };

    let mut result = VerificationResult {
        verified: false,
        checks,
        credentials: vec![credential],
    };
    // Derived, never assigned (root AGENTS.md §4.2).
    result.verified = result.derive_verified();
    Ok(result)
```

Add `PresentedCredential` to the `crate::transaction` import at the top of `verify.rs`:

```rust
use crate::transaction::{
    CheckResult, PresentedCredential, VerificationResult, VerificationState,
    VerificationTransaction,
};
```

> **Note on `split_off`:** `checks` is seeded with exactly one `jwe_decryption`
> record at the top of `do_verify_vp_response` and everything pushed afterwards
> is per-credential, so index 1 is the boundary. Task 4 removes this splitting
> entirely by building the two lists separately from the start — it exists only
> to keep this task behaviour-preserving. `checks` must be declared `let mut`
> (it already is).

- [ ] **Step 7: Update `verify.rs`'s error path**

At `crates/foundry-verifier/src/verify.rs:288-299`, replace the error-arm result:

```rust
            let checks = vec![CheckResult {
                check: check_name_for(&err).to_string(),
                passed: false,
                detail: Some(foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX)),
            }];
            let mut result = VerificationResult {
                verified: false,
                checks,
                // Nothing was verified, so there is no credential to report.
                credentials: Vec::new(),
            };
            // Still derived: one check, not passed (root AGENTS.md §4.2).
            result.verified = result.derive_verified();
            tx.result = Some(result);
```

- [ ] **Step 8: Update the 3 `.claims` assertions in `verify.rs` tests**

`res.claims[..]` becomes `res.credentials[0].claims[..]`:

- Line ~1084: `assert_eq!(res.claims["given_name"], "Alice");` → `assert_eq!(res.credentials[0].claims["given_name"], "Alice");`
- Line ~2187: `assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");` → `assert_eq!(res.credentials[0].claims["org.iso.18013.5.1"]["given_name"], "John");`

Then find any remaining `res.claims` / `result.claims` in the file and apply the same change:

```bash
grep -n "res\.claims\|result\.claims" crates/foundry-verifier/src/verify.rs
```

- [ ] **Step 9: Update the 6 `.claims` assertions in `wallet_verification.rs`**

In `crates/foundry/tests/wallet_verification.rs`, at lines 330, 351, 475, 1246, 1396, 1616, insert `.credentials[0]`:

```rust
    assert_eq!(verify_result.credentials[0].claims["given_name"], "Alice");
    assert_eq!(tx_res.credentials[0].claims["given_name"], "Alice");
    assert_eq!(
        verify_result.credentials[0].claims["org.iso.18013.5.1"]["given_name"],
        "Alice"
    );
```

Also change the top-level-only conjunction assertion at line ~1633 to walk both levels:

```rust
    assert!(result.all_checks().all(|c| c.passed));
```

Find them all with:

```bash
grep -n "\.claims\[\|checks\.iter()\.all" crates/foundry/tests/wallet_verification.rs
```

- [ ] **Step 10: Register the OpenAPI schema**

In `crates/foundry/src/openapi.rs`, add `foundry_verifier::PresentedCredential` beside the existing `VerificationResult` / `CheckResult` entries in **both** `components(schemas(...))` lists (around lines 27-30 and 72-73):

```rust
        foundry_verifier::VerificationResult,
        foundry_verifier::PresentedCredential,
        foundry_verifier::CheckResult,
```

> **Do not** write `body = foundry_verifier::PresentedCredential` in any
> `#[utoipa::path]` attribute. utoipa generates the `$ref` name literally from
> the attribute's spelling, so a qualified path produces
> `foundry_verifier.PresentedCredential`, which never matches the plain name
> `components(schemas(...))` registers. That exact mistake produced the
> resolver-error bug fixed in commit `09b0bb0`, and
> `crates/foundry/tests/` has a regression test asserting every `$ref` resolves.

- [ ] **Step 11: Render per-credential in the console**

In `crates/foundry/assets/console.html`, replace the claims `<pre>` in the DOM (around line 265):

```html
      <ul class="checks hidden" id="verification-checks"></ul>
      <div class="credentials hidden" id="verification-credentials"></div>
```

Add styles next to the existing `.checks` rules (around line 121):

```css
  .credentials.hidden { display: none; }
  .credential { border-top: 1px solid var(--border); margin-top: 12px; padding-top: 8px; }
  .credential h4 { font-size: 13px; margin: 0 0 4px; }
  .credential h4 .fmt { font-weight: 400; opacity: 0.7; margin-left: 6px; }
```

Replace `renderVerificationResult` (around line 2814) with a version that stacks one section per credential. Stacked sections rather than accordions or tabs: both of those hide a *failing* credential behind a collapsed control, and showing failures without a click is the whole job of this panel.

```js
  function appendChecksTo(listEl, checks) {
    checks.forEach(function (check) {
      const li = document.createElement('li');
      li.className = check.passed ? 'pass' : 'fail';

      const mark = document.createElement('span');
      mark.className = 'mark';
      mark.textContent = check.passed ? '\u2713' : '\u2717';
      li.appendChild(mark);

      const label = check.detail ? check.check + ' \u2014 ' + check.detail : check.check;
      li.appendChild(document.createTextNode(' ' + label));

      listEl.appendChild(li);
    });
  }

  function renderVerificationResult(tx) {
    const statusEl = document.getElementById('verification-status');
    const checksEl = document.getElementById('verification-checks');
    const credsEl = document.getElementById('verification-credentials');

    statusEl.textContent = tx.state;
    statusEl.className = 'badge ' + tx.state;

    if (tx.result) {
      // Cross-cutting checks only: jwe_decryption, requested_credentials_answered.
      checksEl.innerHTML = '';
      appendChecksTo(checksEl, tx.result.checks);
      checksEl.classList.remove('hidden');

      // One stacked section per credential, in the order the server sent
      // (DCQL declaration order).
      credsEl.innerHTML = '';
      (tx.result.credentials || []).forEach(function (cred) {
        const wrap = document.createElement('div');
        wrap.className = 'credential';

        const h = document.createElement('h4');
        h.textContent = cred.query_id;
        const fmt = document.createElement('span');
        fmt.className = 'fmt';
        fmt.textContent = cred.format;
        h.appendChild(fmt);
        wrap.appendChild(h);

        const ul = document.createElement('ul');
        ul.className = 'checks';
        appendChecksTo(ul, cred.checks);
        wrap.appendChild(ul);

        const pre = document.createElement('pre');
        pre.className = 'json';
        pre.textContent = JSON.stringify(cred.claims, null, 2);
        wrap.appendChild(pre);

        credsEl.appendChild(wrap);
      });
      credsEl.classList.remove('hidden');
    }
  }
```

Update the reset block that hides these elements (around lines 3137-3138):

```js
        document.getElementById('verification-checks').classList.add('hidden');
        document.getElementById('verification-credentials').classList.add('hidden');
```

Confirm no other reference to the removed id remains:

```bash
grep -n "verification-claims" crates/foundry/assets/console.html
```

Expected: no output.

- [ ] **Step 12: Regenerate the OpenAPI specs**

```bash
cargo run -p foundry -- openapi
git diff --stat openapi.json openapi-wallet.json
```

Expected: `openapi-wallet.json` gains a `PresentedCredential` schema and `VerificationResult.claims` is replaced by `VerificationResult.credentials`.

- [ ] **Step 13: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass, including the new `all_checks_spans_both_levels_and_derives_the_verdict` and the `$ref` resolution regression test.

- [ ] **Step 14: Commit**

```bash
git add crates/foundry-verifier/src/transaction.rs crates/foundry-verifier/src/lib.rs \
        crates/foundry-verifier/src/verify.rs crates/foundry/src/openapi.rs \
        crates/foundry/assets/console.html crates/foundry/tests/wallet_verification.rs \
        openapi.json openapi-wallet.json
git commit -m "refactor(verifier): per-credential VerificationResult records

VerificationResult gains credentials: Vec<PresentedCredential> and loses its
flat claims field. Merging N credentials' claims is a correctness bug rather
than a presentation choice: check_status reads status.status_list out of the
map it is handed, so a merged map lets one credential's status claim displace
another's and runs a revocation check against the wrong status list.

all_checks() and derive_verified() make root AGENTS.md 4.2's conjunction span
both levels, so a failure buried in a credential cannot be masked by a
top-level all(passed).

No behaviour change: the single-credential flow produces exactly one record.
Console renders one stacked section per credential; OpenAPI regenerated."
```

---

## Task 3: `select_presentations` — plural selection

Selection only. The orchestrator still consumes one credential, so behaviour is unchanged for a conformant single-credential response; what changes is that a multi-credential `vp_token` no longer dies here, and unknown/absent ids get their correct classifications.

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs:78-209` (`select_presentation` → `select_presentations`)
- Modify: `crates/foundry-verifier/src/verify.rs:606` (call site — adapt to the `Vec`)
- Test: `crates/foundry-verifier/src/verify.rs` inline tests (~lines 2210-2344)

**Interfaces:**

- Consumes: `PresentedCredential` from Task 2 (indirectly — the call site already builds one).
- Produces, relied on by Task 4:
  - `fn select_presentations<'a>(vp_token: &'a Value, dcql_query: &Value) -> Result<Vec<(String, SelectedPresentation<'a>)>, VerificationError>` — entries in **DCQL declaration order**.

- [ ] **Step 1: Write the failing tests**

In `crates/foundry-verifier/src/verify.rs`, update the test helper and add tests. First change `rejection_of` to call the new name:

```rust
    /// Assert rejection and hand back the message, so each test can check that the
    /// message actually says something actionable.
    fn rejection_of(vp_token: Value, dcql_query: &Value) -> String {
        match select_presentations(&vp_token, dcql_query) {
            Ok(selected) => {
                let ids: Vec<&str> = selected.iter().map(|(id, _)| id.as_str()).collect();
                panic!("expected rejection, but selected {ids:?}")
            }
            Err(e) => e.to_string(),
        }
    }

    fn two_credential_dcql() -> Value {
        serde_json::json!({"credentials": [
            {"id": "pid", "format": "dc+sd-jwt"},
            {"id": "mdl", "format": "mso_mdoc"}
        ]})
    }
```

Then **replace** `select_presentation_rejects_multiple_answered_queries` — the guard it asserted is the feature being built — with its inverse, and add the rest:

```rust
    /// The inverse of the guard this feature removes. A `vp_token` answering
    /// several credential queries is the point, not an error.
    #[test]
    fn select_presentations_accepts_several_answered_queries() {
        let vp = serde_json::json!({
            "pid": ["header.body.sig~disclosure~kb"],
            "mdl": [{"mdoc": "AAAA", "device_signature": "BBBB"}]
        });
        let selected = select_presentations(&vp, &two_credential_dcql()).unwrap();

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0, "pid");
        assert_eq!(selected[1].0, "mdl");
        assert!(matches!(selected[0].1, SelectedPresentation::SdJwtVc(_)));
        assert!(matches!(selected[1].1, SelectedPresentation::MsoMdoc { .. }));
    }

    /// Declaration order, not `vp_token` key order. Depending on the wallet's
    /// serialization -- or on whether serde_json is built with `preserve_order`
    /// -- would make the operator-visible output non-deterministic.
    #[test]
    fn select_presentations_follows_dcql_declaration_order() {
        // `mdl` first in the vp_token, `pid` first in the query.
        let vp = serde_json::json!({
            "mdl": [{"mdoc": "AAAA", "device_signature": "BBBB"}],
            "pid": ["header.body.sig~disclosure~kb"]
        });
        let selected = select_presentations(&vp, &two_credential_dcql()).unwrap();

        let ids: Vec<&str> = selected.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["pid", "mdl"],
            "order must follow the DCQL query, not the vp_token"
        );
    }

    /// A subset is a wallet MUST-violation (OpenID4VP L1007-1008) but a
    /// well-formed one, so selection must NOT reject it: it is a policy verdict
    /// decided later by `requested_credentials_answered` (root AGENTS.md §4.3).
    #[test]
    fn select_presentations_accepts_a_subset_and_leaves_the_verdict_to_policy() {
        let vp = serde_json::json!({"pid": ["header.body.sig~disclosure~kb"]});
        let selected = select_presentations(&vp, &two_credential_dcql()).unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, "pid");
    }

    /// An id the request never asked for is structural: there is no credential
    /// query to verify it against, so no verdict can be attributed to it.
    #[test]
    fn select_presentations_rejects_an_id_that_was_never_requested() {
        let vp = serde_json::json!({
            "pid": ["header.body.sig~disclosure~kb"],
            "surprise": ["x"]
        });
        let msg = rejection_of(vp, &two_credential_dcql());
        assert!(msg.contains("surprise"), "must name the unexpected id: {msg}");
        assert!(msg.contains("did not ask for"), "{msg}");
    }

    #[test]
    fn select_presentations_rejects_an_empty_vp_token() {
        let msg = rejection_of(serde_json::json!({}), &two_credential_dcql());
        assert!(msg.contains("no credential query"), "{msg}");
    }
```

Finally, update `select_presentation_accepts_conformant_sd_jwt_envelope` and `select_presentation_accepts_conformant_mdoc_envelope` to the plural API:

```rust
    #[test]
    fn select_presentations_accepts_conformant_sd_jwt_envelope() {
        let vp = serde_json::json!({"c1": ["header.body.sig~disclosure~kb"]});
        let selected = select_presentations(&vp, &sd_jwt_dcql()).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, "c1");
        match &selected[0].1 {
            SelectedPresentation::SdJwtVc(s) => assert_eq!(*s, "header.body.sig~disclosure~kb"),
            other => panic!("expected SdJwtVc, got {other:?}"),
        }
    }

    #[test]
    fn select_presentations_accepts_conformant_mdoc_envelope() {
        let vp = serde_json::json!({"c1": [{"mdoc": "AAAA", "device_signature": "BBBB"}]});
        let selected = select_presentations(&vp, &mdoc_dcql()).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, "c1");
        match &selected[0].1 {
            SelectedPresentation::MsoMdoc {
                mdoc_b64,
                device_signature_b64,
            } => {
                assert_eq!(*mdoc_b64, "AAAA");
                assert_eq!(*device_signature_b64, "BBBB");
            }
            other => panic!("expected MsoMdoc, got {other:?}"),
        }
    }
```

And `select_presentation_rejects_legacy_top_level_mdoc_envelope` now trips the unknown-id rule, so its assertion changes:

```rust
    /// foundry's old mdoc shape put these keys at the top level of `vp_token`.
    /// They now read as credential query ids that were never requested.
    #[test]
    fn select_presentations_reject_legacy_top_level_mdoc_envelope() {
        let msg = rejection_of(
            serde_json::json!({"mdoc": "AAAA", "device_signature": "BBBB"}),
            &mdoc_dcql(),
        );
        assert!(msg.contains("did not ask for"), "{msg}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier select_presentations
```

Expected: FAIL to compile — `cannot find function select_presentations`.

- [ ] **Step 3: Write the implementation**

In `crates/foundry-verifier/src/verify.rs`, replace `select_presentation` (its doc comment and body, lines ~64-209) with:

```rust
/// Select every presentation to verify from an OpenID4VP 1.0 `vp_token`
/// (L1161, `vp_token` at L1166).
///
/// `vp_token` is a JSON object keyed by DCQL credential query id whose values are
/// **arrays** of presentations — the same shape for every credential format. The
/// format therefore *cannot* be read off the JSON type of the payload; it is
/// whatever the answered credential query declared. Inferring it from the shape
/// is exactly what made a conformant SD-JWT VC presentation report the
/// misleading `mdoc vp_token missing 'mdoc'`.
///
/// Returns one entry per answered credential query, in **DCQL declaration
/// order** — never `vp_token` key order, which depends on the wallet's
/// serialization and on whether `serde_json` was built with `preserve_order`.
///
/// Every failure here is structural (HTTP 400), never a policy verdict. In
/// particular a `vp_token` answering only *some* of the requested credential
/// queries is **accepted** here: it violates L1007-1008, but it is well-formed,
/// so the verdict belongs to `check_requested_credentials_answered`
/// (root AGENTS.md §4.3).
fn select_presentations<'a>(
    vp_token: &'a Value,
    dcql_query: &Value,
) -> Result<Vec<(String, SelectedPresentation<'a>)>, VerificationError> {
    let entries = vp_token.as_object().ok_or_else(|| {
        VerificationError::Failed(format!(
            "vp_token must be a JSON object keyed by DCQL credential query id \
             (OpenID4VP 1.0 L1166), got {}",
            json_type_name(vp_token)
        ))
    })?;

    // The declared format is the only trustworthy source of the credential
    // format, so an unusable dcql_query is fatal rather than a failed check.
    let query: DcqlQuery = serde_json::from_value(dcql_query.clone()).map_err(|e| {
        VerificationError::Failed(format!(
            "cannot determine the requested credential format: this transaction's \
             dcql_query is not a valid DCQL query: {e}"
        ))
    })?;

    let requested: Vec<&str> = query.credentials().iter().map(|cq| cq.id()).collect();

    // An id the request never asked for is a contract violation with no possible
    // verdict attached: there is no credential query to verify it against, so it
    // cannot be reported as a policy outcome the way a *missing* one can.
    for key in entries.keys() {
        if !requested.contains(&key.as_str()) {
            return Err(VerificationError::Failed(format!(
                "vp_token names credential query '{}', which this request did not ask \
                 for; expected one of [{}]",
                key,
                requested.join(", ")
            )));
        }
    }

    let mut selected = Vec::with_capacity(requested.len());
    for cq in query.credentials() {
        let Some(value) = entries.get(cq.id()) else {
            // Not answered. Whether that is acceptable is a POLICY question
            // (L1007-1008 makes it a wallet violation), decided by
            // `check_requested_credentials_answered` -- not a structural one.
            continue;
        };

        let presentations = value.as_array().ok_or_else(|| {
            VerificationError::Failed(format!(
                "vp_token['{}'] must be an array of presentations \
                 (OpenID4VP 1.0 L1166), got {}",
                cq.id(),
                json_type_name(value)
            ))
        })?;

        // L1166: "When `multiple` is omitted, or set to `false`, the array MUST
        // contain only one Presentation." foundry ignores `multiple` (an unknown
        // property per VP-0090), so it never requests more than one and the
        // one-presentation rule always applies. Silently taking [0] of a longer
        // array would verify part of a presentation set while reporting the
        // whole set as satisfied.
        let presentation = match presentations.as_slice() {
            [single] => single,
            other => {
                return Err(VerificationError::Failed(format!(
                    "vp_token['{}'] must contain exactly one presentation, got {}",
                    cq.id(),
                    other.len()
                )));
            }
        };

        let payload = match cq.format() {
            CredentialFormat::DcSdJwt => {
                SelectedPresentation::SdJwtVc(presentation.as_str().ok_or_else(|| {
                    VerificationError::Failed(format!(
                        "credential query '{}' declares format dc+sd-jwt, so its \
                         presentation must be an SD-JWT VC string, got {}",
                        cq.id(),
                        json_type_name(presentation)
                    ))
                })?)
            }
            CredentialFormat::MsoMdoc => {
                let obj = presentation.as_object().ok_or_else(|| {
                    VerificationError::Failed(format!(
                        "credential query '{}' declares format mso_mdoc, so its \
                         presentation must be an object, got {}",
                        cq.id(),
                        json_type_name(presentation)
                    ))
                })?;
                let mdoc_b64 = obj.get("mdoc").and_then(|v| v.as_str()).ok_or_else(|| {
                    VerificationError::Failed(format!(
                        "mdoc presentation for credential query '{}' is missing 'mdoc'",
                        cq.id()
                    ))
                })?;
                let device_signature_b64 = obj
                    .get("device_signature")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        VerificationError::Failed(format!(
                            "mdoc presentation for credential query '{}' is missing \
                             'device_signature'",
                            cq.id()
                        ))
                    })?;
                SelectedPresentation::MsoMdoc {
                    mdoc_b64,
                    device_signature_b64,
                }
            }
            // `CredentialFormat::Other` exists so that an unimplemented format inside
            // a multi-credential query simply fails to match rather than invalidating
            // the whole query (see `dcql_model`). Once a wallet has *answered* such a
            // query there is nothing to fall back to: no verifier for the format
            // exists, so this is a request the verifier cannot service.
            CredentialFormat::Other(other) => {
                return Err(VerificationError::Failed(format!(
                    "credential query '{}' requests credential format '{}', which this \
                     verifier does not implement",
                    cq.id(),
                    other
                )));
            }
        };

        selected.push((cq.id().to_string(), payload));
    }

    if selected.is_empty() {
        return Err(VerificationError::Failed(format!(
            "vp_token answers no credential query from this request: expected one of [{}]",
            requested.join(", ")
        )));
    }

    Ok(selected)
}
```

- [ ] **Step 4: Adapt the call site**

At `crates/foundry-verifier/src/verify.rs:606`, replace:

```rust
    let (answered_query_id, selected) = select_presentation(vp_token, &tx.dcql_query)?;
```

with a temporary single-credential adaptation. Task 4 replaces this with the real loop:

```rust
    // Task 4 turns this into a loop over every entry. Taking the first keeps
    // this task's diff to selection alone.
    let mut selected_all = select_presentations(vp_token, &tx.dcql_query)?;
    let (answered_query_id, selected) = selected_all.remove(0);
```

> `selected_all` is non-empty: `select_presentations` returns
> `Err` rather than an empty `Vec`. Do not add an `.unwrap()` or an
> `expect` here — `remove(0)` on a guaranteed-non-empty `Vec` is the
> panic-free form, and Task 4 deletes this line anyway.

- [ ] **Step 5: Run the tests**

```bash
cargo nextest run -p foundry-verifier select_presentations
```

Expected: PASS — 8 tests (2 envelope-acceptance, 1 legacy-envelope rejection, 5 new).

- [ ] **Step 6: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. No behaviour change for conformant single-credential responses.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs
git commit -m "feat(verifier): select every answered presentation from a vp_token

select_presentation becomes select_presentations, returning one entry per
answered DCQL credential query in declaration order -- not vp_token key
order, which depends on the wallet's serialization and on whether serde_json
was built with preserve_order.

Classification follows root AGENTS.md 4.3. A subset vp_token is ACCEPTED
here: it violates OpenID4VP L1007-1008 but is well-formed, so the verdict
belongs to policy, not to a structural 400. An id the request never asked
for stays structural -- there is no credential query to verify it against,
so no verdict can be attributed to it.

The exactly-one-presentation-per-entry guard stays and now cites L1166,
which mandates it whenever multiple is omitted or false. foundry ignores
multiple, so it always applies.

The orchestrator still consumes one credential; Task 4 adds the loop."
```

---

## Task 4: Per-credential verification loop

Where multi-credential verification actually starts working, and where the two collision bugs get fixed.

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs` — extract `verify_one_credential`, add `check_requested_credentials_answered`, rewrite the tail of `do_verify_vp_response`
- Test: `crates/foundry-verifier/src/verify.rs` inline tests

**Interfaces:**

- Consumes: `PresentedCredential`, `VerificationResult::derive_verified` (Task 2); `select_presentations` (Task 3).
- Produces, relied on by Tasks 5-6:
  - `struct CredentialVerifyCtx<'a> { config: &'a Config, tx: &'a VerificationTransaction, trust_store: &'a TrustStore, expected_audiences: &'a [String], now_unix: u64 }`
  - `async fn verify_one_credential(ctx: &CredentialVerifyCtx<'_>, query_id: &str, selected: SelectedPresentation<'_>, resolver: &dyn StatusListResolver) -> Result<(PresentedCredential, Option<String>), VerificationError>` — the `Option<String>` is a status-fetch-unavailable detail, deliberately **not** an `Err`, so the loop can keep going. Task 5 turns it into the 502.
  - `fn check_requested_credentials_answered(dcql_query: &Value, answered: &[PresentedCredential]) -> CheckResult`

- [ ] **Step 1: Write the failing tests**

Add to the inline `mod tests` in `crates/foundry-verifier/src/verify.rs`. These use the existing helpers `test_pki`, `test_config`, `holder`, `der_b64`, `sample_tx`, `expected_client_id`, `encrypt_compact`, `MockResolver`, and `build_sd_jwt_vc` / `attach_kb_jwt` from `foundry_sd_jwt_vc`.

```rust
    /// Build an SD-JWT VC presentation disclosing `claims`, bound to `tx`'s
    /// nonce and the redirect-transport audience.
    fn sd_jwt_presentation_for(
        config: &Config,
        tx: &VerificationTransaction,
        leaf_cert: &[u8],
        issuer_signer: &FileSigner,
        disclose: &[(&str, serde_json::Value)],
    ) -> String {
        let (holder_signer, holder_pub) = holder();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut select = serde_json::Map::new();
        for (k, v) in disclose {
            select.insert((*k).to_string(), v.clone());
        }

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: None,
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };

        let issuer_pres =
            build_sd_jwt_vc(claims, issuer_signer, Some(vec![der_b64(leaf_cert)])).unwrap();
        let client_id = expected_client_id(config);
        attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &tx.nonce, None).unwrap()
    }

    fn two_sd_jwt_tx() -> (VerificationTransaction, Jwk) {
        let (mut tx, pub_jwk) = sample_tx();
        tx.dcql_query = serde_json::json!({"credentials": [
            {"id": "pid", "format": "dc+sd-jwt"},
            {"id": "diploma", "format": "dc+sd-jwt"}
        ]});
        (tx, pub_jwk)
    }

    /// Two credentials in one `vp_token` both verify, and each appears as its own
    /// record in DCQL declaration order.
    #[tokio::test]
    async fn verifies_two_credentials_in_one_vp_token() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let pid = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );
        let diploma = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("degree", serde_json::json!("MSc"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid], "diploma": [diploma]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .unwrap();

        assert!(res.verified, "both credentials are valid: {:?}", res.checks);
        assert_eq!(res.credentials.len(), 2);
        assert_eq!(res.credentials[0].query_id, "pid");
        assert_eq!(res.credentials[1].query_id, "diploma");
        assert_eq!(res.credentials[0].claims["given_name"], "Alice");
        assert_eq!(res.credentials[1].claims["degree"], "MSc");
        assert_eq!(tx.state, VerificationState::Verified);
    }

    /// The claim-collision bug, pinned. Two credentials disclosing the SAME claim
    /// name must not overwrite each other -- a single flat claims map reported one
    /// value as if both credentials agreed on it.
    #[tokio::test]
    async fn per_credential_claims_do_not_collide_on_a_shared_claim_name() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let first = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );
        let second = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Bob"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [first], "diploma": [second]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .unwrap();

        assert_eq!(res.credentials[0].claims["given_name"], "Alice");
        assert_eq!(
            res.credentials[1].claims["given_name"], "Bob",
            "each credential keeps its own value; a merged map would report one twice"
        );
    }

    /// A subset `vp_token` violates OpenID4VP L1007-1008 but is well-formed, so
    /// it is a policy verdict (HTTP 200, verified: false), not a structural 400
    /// (root AGENTS.md §4.3). The credential that DID arrive is still verified.
    ///
    /// This is deliberately **non-conformant wallet input**: a wallet that cannot
    /// deliver all non-optional credentials is required to return none at all.
    #[tokio::test]
    async fn a_subset_vp_token_is_a_policy_verdict_naming_the_missing_credential() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let pid = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .expect("a subset is a policy verdict, not a structural error");

        assert!(!res.verified, "a missing requested credential is a failure");

        let answered = res
            .checks
            .iter()
            .find(|c| c.check == "requested_credentials_answered")
            .expect("the set-level check must be recorded");
        assert!(!answered.passed);
        let detail = answered.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("diploma"),
            "must name the credential query that went unanswered: {detail}"
        );

        // The credential that arrived is still fully verified and reported.
        assert_eq!(res.credentials.len(), 1);
        assert_eq!(res.credentials[0].query_id, "pid");
        assert!(
            res.credentials[0].checks.iter().all(|c| c.passed),
            "the answered credential's own checks all pass: {:?}",
            res.credentials[0].checks
        );
    }

    /// `check_requested_credentials_answered` is fail-closed and never errors,
    /// matching `check_dcql_match`'s contract.
    #[test]
    fn requested_credentials_answered_passes_when_every_query_is_answered() {
        let query = serde_json::json!({"credentials": [
            {"id": "pid", "format": "dc+sd-jwt"},
            {"id": "mdl", "format": "mso_mdoc"}
        ]});
        let answered = vec![
            PresentedCredential {
                query_id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                claims: serde_json::json!({}),
                checks: Vec::new(),
            },
            PresentedCredential {
                query_id: "mdl".to_string(),
                format: "mso_mdoc".to_string(),
                claims: serde_json::json!({}),
                checks: Vec::new(),
            },
        ];

        let check = check_requested_credentials_answered(&query, &answered);
        assert_eq!(check.check, "requested_credentials_answered");
        assert!(check.passed);
    }

    #[test]
    fn requested_credentials_answered_fails_closed_on_an_unreadable_query() {
        let check = check_requested_credentials_answered(&serde_json::json!({}), &[]);
        assert!(
            !check.passed,
            "an unreadable query must fail closed, never pass"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier verifies_two_credentials_in_one_vp_token per_credential_claims_do_not_collide a_subset_vp_token_is_a_policy_verdict requested_credentials_answered
```

Expected: FAIL to compile — `cannot find function check_requested_credentials_answered`. Once that compiles, `verifies_two_credentials_in_one_vp_token` still fails because only the first credential is verified.

- [ ] **Step 3: Add `check_requested_credentials_answered`**

In `crates/foundry-verifier/src/verify.rs`, add next to `check_transaction_data_binding`:

```rust
/// Did the wallet answer every credential query the request asked for?
///
/// OpenID4VP 1.0 L993: with `credential_sets` absent — the only case foundry
/// implements — "the Verifier requests presentations for all Credentials in
/// `credentials`", so every credential query is non-optional. L1007-1008: "If
/// the Wallet cannot deliver all non-optional Credentials requested by the
/// Verifier according to these rules, it MUST NOT return any Credential(s)."
///
/// A subset `vp_token` is therefore a **wallet MUST-violation**. It is
/// nonetheless reported as a policy verdict (HTTP 200, `verified: false`) rather
/// than a structural 400: the spec constrains the wallet here, not the
/// verifier's status code; the response is well-formed, so root AGENTS.md §4.3's
/// structural category does not fit; and naming the missing credential query is
/// far more actionable for whoever has to diagnose the wallet than an opaque
/// `invalid_request`.
///
/// Never returns `Err` — fail-closed, matching `check_dcql_match`.
fn check_requested_credentials_answered(
    dcql_query: &Value,
    answered: &[PresentedCredential],
) -> CheckResult {
    const CHECK: &str = "requested_credentials_answered";

    let query: DcqlQuery = match serde_json::from_value(dcql_query.clone()) {
        Ok(q) => q,
        // Not reachable through the request path -- `select_presentations` has
        // already parsed this query successfully, and `create_verification_request`
        // validated it before persisting. Fail closed rather than pass on a query
        // this function cannot read.
        Err(e) => {
            let reason = format!("dcql_query is not a valid DCQL query: {e}");
            tracing::warn!(check = CHECK, reason = %reason, "cannot evaluate requested credentials");
            return CheckResult {
                check: CHECK.to_string(),
                passed: false,
                detail: Some(reason),
            };
        }
    };

    let missing: Vec<&str> = query
        .credentials()
        .iter()
        .map(|cq| cq.id())
        .filter(|id| !answered.iter().any(|c| c.query_id == *id))
        .collect();

    if missing.is_empty() {
        return CheckResult {
            check: CHECK.to_string(),
            passed: true,
            detail: None,
        };
    }

    // Attribute the fault to the wallet. Without this an operator reads the
    // failure as foundry having asked for something unusual, when in fact
    // L1007-1008 required the wallet to return nothing at all rather than a
    // partial set. Credential query ids are operator-authored request structure,
    // not holder values, so naming them is safe (root AGENTS.md §4.5).
    let reason = format!(
        "wallet returned no presentation for credential query [{}]; OpenID4VP 1.0 \
         requires a wallet that cannot deliver all non-optional Credentials to \
         return none at all, so this response is not conformant",
        missing.join(", ")
    );
    tracing::warn!(check = CHECK, reason = %reason, "not every requested credential was answered");
    CheckResult {
        check: CHECK.to_string(),
        passed: false,
        detail: Some(reason),
    }
}
```

- [ ] **Step 4: Extract `verify_one_credential`**

Move the existing per-credential work — the `match selected { .. }` block, the `transaction_data_binding` push, `check_dcql_match`, and `check_status` — out of `do_verify_vp_response` into a new function placed immediately before it. The body is the existing code with two changes: `checks` is local to the credential, and `check_status`'s error is **returned rather than propagated**.

```rust
/// Inputs shared by every credential in one `vp_token`, computed once.
struct CredentialVerifyCtx<'a> {
    config: &'a Config,
    tx: &'a VerificationTransaction,
    trust_store: &'a TrustStore,
    expected_audiences: &'a [String],
    now_unix: u64,
}

/// Verify one credential from a `vp_token` and collect its checks.
///
/// Returns the credential record plus, when the status-list fetch was
/// unavailable, its detail message. That is deliberately **not** an `Err`: the
/// caller verifies every credential before deciding anything (a bad signature on
/// one credential must not hide another's verdict), and a network fault still
/// has to become HTTP 502 afterwards rather than a policy `passed: false` —
/// "I could not determine whether this is revoked" is not "this is revoked".
async fn verify_one_credential(
    ctx: &CredentialVerifyCtx<'_>,
    query_id: &str,
    selected: SelectedPresentation<'_>,
    resolver: &dyn StatusListResolver,
) -> Result<(PresentedCredential, Option<String>), VerificationError> {
    let presented_format = selected.format();
    let mut checks: Vec<CheckResult> = Vec::new();
    let mut disclosed_claims = serde_json::Map::new();
    let mut kb_jwt_payload: Option<Value> = None;

    // <<< The existing `let doc_type: Option<String> = match selected { .. };`
    //     block moves here VERBATIM, except that every `tx.` becomes `ctx.tx.`,
    //     `config.` becomes `ctx.config.`, `&trust_store` becomes
    //     ctx.trust_store, `&expected_audiences` becomes ctx.expected_audiences,
    //     and `now_unix` becomes `ctx.now_unix`. Do not rewrite its logic. >>>

    let claims_value = Value::Object(disclosed_claims);

    // Transaction Data binding (OpenID4VP L1523/L3144), only when the Verifier
    // requested transaction_data for this transaction. Already multi-credential
    // aware: it filters entries by whether their `credential_ids` array contains
    // this credential's query id, so an entry scoped elsewhere imposes nothing here.
    if let Some(ref entries) = ctx.tx.transaction_data {
        match &kb_jwt_payload {
            Some(kb_payload) => {
                checks.push(check_transaction_data_binding(entries, query_id, kb_payload));
            }
            // mdoc: no KB-JWT exists to carry the binding. The Verifier asked
            // for one it cannot confirm, so this must not report success.
            None => {
                checks.push(CheckResult {
                    check: "transaction_data_binding".to_string(),
                    passed: false,
                    detail: Some("mdoc transaction_data binding is not implemented".to_string()),
                });
            }
        }
    }

    // DCQL satisfaction, bound to the credential query this presentation
    // ANSWERED -- not to any query of the presented format, so a presentation
    // cannot be credited against a query it does not answer.
    checks.push(check_dcql_match(
        &ctx.tx.dcql_query,
        query_id,
        presented_format,
        &claims_value,
        doc_type.as_deref(),
    ));

    // Token Status List revocation, against THIS credential's claims. Handing it
    // a map merged across credentials would read one credential's
    // `status.status_list` while reporting another's verdict.
    let status_unavailable = match check_status(
        &claims_value,
        ctx.trust_store,
        resolver,
        ctx.now_unix,
    )
    .await
    {
        Ok(check) => {
            checks.push(check);
            None
        }
        Err(VerificationError::StatusUnavailable(detail)) => Some(detail),
        Err(other) => return Err(other),
    };

    let credential = PresentedCredential {
        query_id: query_id.to_string(),
        format: match presented_format {
            PresentedFormat::SdJwtVc => "dc+sd-jwt".to_string(),
            PresentedFormat::MsoMdoc => "mso_mdoc".to_string(),
        },
        claims: claims_value,
        checks,
    };

    Ok((credential, status_unavailable))
}
```

- [ ] **Step 5: Rewrite the tail of `do_verify_vp_response`**

Replace everything from the `select_presentations` call (the Task 3 adaptation) to the end of the function with the loop. `checks` now holds **only** cross-cutting records, so the `split_off` from Task 2 disappears:

```rust
    // 3. Per-credential verification. Verify-all, never fail-fast: root
    //    AGENTS.md §4.2 defines `verified` as the conjunction of the checks
    //    performed, which is only meaningful when they were all performed, and
    //    "PID signature bad, mDL fine" is a far more useful operator verdict
    //    than "PID signature bad, mDL unknown".
    let selected = select_presentations(vp_token, &tx.dcql_query)?;
    let ctx = CredentialVerifyCtx {
        config,
        tx,
        trust_store: &trust_store,
        expected_audiences: &expected_audiences,
        now_unix,
    };

    let mut credentials = Vec::with_capacity(selected.len());
    let mut deferred: Option<VerificationError> = None;

    for (query_id, payload) in selected {
        let (credential, status_unavailable) =
            verify_one_credential(&ctx, &query_id, payload, resolver).await?;

        // First unavailability wins; the rest of the loop still runs so the
        // operator keeps every other credential's verdict. Naming the credential
        // matters: with N credentials a bare "status list unreachable" does not
        // say whose.
        if deferred.is_none() {
            if let Some(detail) = status_unavailable {
                deferred = Some(VerificationError::StatusUnavailable(format!(
                    "credential query '{query_id}': {detail}"
                )));
            }
        }

        credentials.push(credential);
    }

    // 4. Set-level policy: did every requested credential query get answered?
    checks.push(check_requested_credentials_answered(
        &tx.dcql_query,
        &credentials,
    ));

    // 5. Overall verdict: the conjunction over EVERY check, at both levels.
    let mut result = VerificationResult {
        verified: false,
        checks,
        credentials,
    };
    result.verified = result.derive_verified();
    Ok(result)
```

> `deferred` is unused this task — Task 5 consumes it. Add
> `#[allow(unused_variables)]`? **No.** Instead, keep this task honest by
> returning it immediately as an `Err` so behaviour matches today exactly, and
> let Task 5 replace that with the non-lossy path:
>
> ```rust
>     // Today's behaviour: propagate. Task 5 makes this non-lossy by carrying
>     // the partial result alongside the error.
>     if let Some(err) = deferred {
>         return Err(err);
>     }
> ```
>
> Place this immediately before step 4's `checks.push(..)`.

- [ ] **Step 6: Run the new tests**

```bash
cargo nextest run -p foundry-verifier verifies_two_credentials_in_one_vp_token per_credential_claims_do_not_collide a_subset_vp_token_is_a_policy_verdict requested_credentials_answered
```

Expected: PASS, 5 tests.

- [ ] **Step 7: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Existing single-credential tests still pass — one credential produces one record and one `requested_credentials_answered: passed` check.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs
git commit -m "feat(verifier): verify every credential in a multi-credential vp_token

The orchestrator's linear flow becomes a verify-all loop over every answered
credential query. No early return: root AGENTS.md 4.2 defines verified as the
conjunction of the checks performed, which is only meaningful when they were
all performed, and 'PID signature bad, mDL fine' is a more useful verdict
than 'PID signature bad, mDL unknown'.

Fixes two collisions that a single flat claims map hid:
- check_status now reads each credential's OWN status.status_list, instead of
  whichever credential's status claim happened to land in the merged map last
- two credentials disclosing the same claim name no longer overwrite each
  other and report one value as if both agreed

Adds requested_credentials_answered. OpenID4VP L993 makes every credential
query non-optional when credential_sets is absent, and L1007-1008 requires a
wallet that cannot deliver them all to return none -- so a subset is a wallet
MUST-violation. It is reported as a policy verdict naming the missing query
rather than a 400, because the response is well-formed and naming the gap is
what makes the wallet's fault diagnosable."
```

---

## Task 5: Non-lossy HTTP 502 for an unavailable status list

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs` — add `VerifyOutcome`, change `do_verify_vp_response`'s return type and the `verify_vp_response` wrapper
- Test: `crates/foundry-verifier/src/verify.rs` inline tests

**Interfaces:**

- Consumes: the loop and `deferred` from Task 4.
- Produces: `struct VerifyOutcome { result: VerificationResult, deferred: Option<VerificationError> }`; `do_verify_vp_response` now returns `Result<VerifyOutcome, VerificationError>`. `verify_vp_response`'s public signature is **unchanged**.

- [ ] **Step 1: Write the failing test**

`MockResolver` needs an unavailable mode. Check its current definition and add a variant if needed:

```bash
grep -n "struct MockResolver" -A 20 crates/foundry-verifier/src/verify.rs
```

Add a resolver that always fails, then the test:

```rust
    /// A resolver whose fetch always fails, standing in for an unreachable
    /// status-list endpoint.
    struct UnavailableResolver;

    #[async_trait::async_trait]
    impl StatusListResolver for UnavailableResolver {
        async fn resolve(&self, uri: &str) -> Result<String, VerificationError> {
            Err(VerificationError::StatusUnavailable(format!(
                "connection refused fetching {uri}"
            )))
        }
    }

    /// An unreachable status list keeps its HTTP 502 -- "I could not determine
    /// whether this is revoked" is not "this is revoked", and collapsing the two
    /// would invite a relying party to treat an unreachable list as a clean bill
    /// of health (root AGENTS.md §4.3).
    ///
    /// But it must not be lossy: `tx.result` has to retain the OTHER credential's
    /// verdict, which is the entire reason for keeping the 502 precise. And the
    /// persisted `verified` must be `false` -- the trap here is that an
    /// unavailable status pushes NO `status_check` record, so a naive
    /// `all(passed)` computes `true` and persists `verified: true` on a
    /// transaction that just returned 502.
    #[tokio::test]
    async fn an_unavailable_status_list_returns_502_without_discarding_other_credentials() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();

        // `pid` carries a status claim, so its check hits the failing resolver.
        let (holder_signer, holder_pub) = holder();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let pid_claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: None,
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: Some(7),
            status_list_uri: Some("https://localhost:8443/statuslist/1".to_string()),
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let pid_issuer =
            build_sd_jwt_vc(pid_claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let client_id = expected_client_id(&config);
        let pid =
            attach_kb_jwt(pid_issuer, &holder_signer, &client_id, &tx.nonce, None).unwrap();

        // `diploma` carries no status claim, so its own checks all pass.
        let diploma = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("degree", serde_json::json!("MSc"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid], "diploma": [diploma]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let err = verify_vp_response(&config, &mut tx, &jwe, &UnavailableResolver)
            .await
            .expect_err("an unreachable status list is a network fault, so HTTP 502");

        assert!(
            matches!(err, VerificationError::StatusUnavailable(_)),
            "must stay StatusUnavailable so the HTTP layer maps it to 502, got: {err}"
        );
        assert!(
            err.to_string().contains("pid"),
            "must name WHICH credential's status list was unreachable: {err}"
        );

        // Non-lossy: the operator keeps the other credential's verdict.
        let persisted = tx.result.as_ref().expect(
            "the error path must populate tx.result, or the admin console shows a \
             bare red failure with no explanation",
        );
        assert_eq!(tx.state, VerificationState::Failed);
        assert!(
            !persisted.verified,
            "verified must be false on a transaction that returned 502 -- an \
             unavailable status pushes no status_check, so a naive all(passed) \
             would have computed true here"
        );
        assert_eq!(
            persisted.credentials.len(),
            2,
            "both credentials' records survive: {:?}",
            persisted.credentials
        );
        let diploma_record = persisted
            .credentials
            .iter()
            .find(|c| c.query_id == "diploma")
            .expect("the healthy credential must still be reported");
        assert!(
            diploma_record.checks.iter().all(|c| c.passed),
            "the healthy credential's own checks all passed: {:?}",
            diploma_record.checks
        );
        assert!(
            persisted
                .checks
                .iter()
                .any(|c| c.check == "status_check" && !c.passed),
            "the fault is recorded as a check so the verdict stays derived: {:?}",
            persisted.checks
        );
    }
```

> If `StatusListResolver`'s trait method has a different name or signature than
> `resolve(&self, uri: &str)`, read it first and match it exactly:
> `grep -n "trait StatusListResolver" -A 10 crates/foundry-verifier/src/status.rs`.
> Match the existing `MockResolver`'s `impl` block rather than guessing.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo nextest run -p foundry-verifier an_unavailable_status_list_returns_502
```

Expected: FAIL — `tx.result` holds only the single synthesized error check with `credentials: []`, so `persisted.credentials.len()` is 0, not 2.

- [ ] **Step 3: Add `VerifyOutcome`**

In `crates/foundry-verifier/src/verify.rs`, add above `do_verify_vp_response`:

```rust
/// What `do_verify_vp_response` produces: always a result, plus optionally an
/// error that still has to reach the wallet as a status code.
///
/// A status-list fetch failure is a network fault, so root AGENTS.md §4.3 makes
/// it HTTP 502 rather than a policy `passed: false`. Propagating it with `?` from
/// inside the per-credential loop would throw away every check already
/// collected, and the wrapper's `Err` arm would rebuild `tx.result` from
/// scratch — leaving the operator with none of the other credentials' verdicts,
/// which is the whole reason a precise 502 is worth having. So the error travels
/// beside the result instead of replacing it.
struct VerifyOutcome {
    result: VerificationResult,
    /// Only ever `StatusUnavailable`. Every other error still returns `Err`
    /// directly, because nothing partial is worth reporting for those.
    deferred: Option<VerificationError>,
}
```

- [ ] **Step 4: Change `do_verify_vp_response`**

Its signature becomes:

```rust
async fn do_verify_vp_response(
    config: &Config,
    tx: &VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
) -> Result<VerifyOutcome, VerificationError> {
```

Replace Task 4's temporary early return and the tail with:

```rust
    // 4. Set-level policy: did every requested credential query get answered?
    checks.push(check_requested_credentials_answered(
        &tx.dcql_query,
        &credentials,
    ));

    // 5. A credential whose status fetch was unavailable pushed NO status_check
    //    record, because unavailability is not a policy failure. On its own that
    //    leaves the conjunction computing `true` and persists `verified: true` on
    //    a transaction that returned 502 -- a lie the admin console would render
    //    faithfully. Record the fault as a check so the verdict stays derived and
    //    honest, exactly as the wrapper's error arm already does.
    if let Some(ref err) = deferred {
        checks.push(CheckResult {
            check: check_name_for(err).to_string(),
            passed: false,
            detail: Some(foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX)),
        });
    }

    // 6. Overall verdict: the conjunction over EVERY check, at both levels.
    let mut result = VerificationResult {
        verified: false,
        checks,
        credentials,
    };
    result.verified = result.derive_verified();

    Ok(VerifyOutcome { result, deferred })
```

- [ ] **Step 5: Change the `verify_vp_response` wrapper**

In the `Ok` arm, unpack the outcome and re-raise the deferred error **after** persisting:

```rust
    match do_verify_vp_response(config, tx, encrypted_jwe_str, resolver).await {
        Ok(outcome) => {
            let VerifyOutcome { result, deferred } = outcome;

            tx.state = if result.verified {
                VerificationState::Verified
            } else {
                VerificationState::Failed
            };

            // <<< the existing per-check logging loop and the
            //     info!/warn! verdict block stay here unchanged; Task 6
            //     updates them to span both check levels >>>

            tx.result = Some(result.clone());

            match deferred {
                None => Ok(result),
                // The result is already persisted, so the operator keeps every
                // other credential's verdict while the wallet still gets the
                // retryable status code.
                Some(err) => {
                    tx.state = VerificationState::Failed;
                    Err(err)
                }
            }
        }
        Err(err) => {
            // <<< unchanged >>>
        }
    }
```

- [ ] **Step 6: Run the test**

```bash
cargo nextest run -p foundry-verifier an_unavailable_status_list_returns_502
```

Expected: PASS.

- [ ] **Step 7: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass, including any existing single-credential `StatusUnavailable` test — it still gets `Err(StatusUnavailable)` and therefore still maps to 502.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs
git commit -m "fix(verifier): keep the other credentials' verdicts on a 502

An unreachable status list still returns HTTP 502 -- 'I could not determine
whether this is revoked' is not 'this is revoked', and collapsing the two
would let a relying party read an unreachable list as a clean bill of health
(root AGENTS.md 4.3).

But propagating it with ? from inside the per-credential loop discarded every
check already collected, and the wrapper's error arm rebuilt tx.result from
scratch -- so the operator lost the 'the other credential was fine' half that
makes a precise 502 worth having. The error now travels beside the result in
a VerifyOutcome: the result is persisted first, then the error is re-raised.

The error also names which credential's status list was unreachable, which
with N credentials is the difference between an actionable log line and a
guess.

Closes the trap this creates: an unavailable status pushes no status_check
record, so the conjunction would have computed true and persisted
verified: true on a transaction that just returned 502. The fault is recorded
as a check instead, keeping the verdict derived."
```

---

## Task 6: Observability across both check levels

Mostly mechanical. Read the coverage note at Step 3 before starting — it explains why this task adds no new behavioural test, and what that leaves uncovered.

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs` — the per-check logging loop and the verdict event inside `verify_vp_response`

**Interfaces:**

- Consumes: `VerificationResult::all_checks` (Task 2), `VerifyOutcome` (Task 5).
- Produces: no new types. New log fields: `credential` on per-credential check records, `credentials_requested` and `credentials_answered` on the verdict event.

- [ ] **Step 1: Update the per-check logging loop**

In `crates/foundry-verifier/src/verify.rs`, the `Ok` arm of `verify_vp_response` currently logs one record per top-level check:

```rust
            // One record per check, so an operator can see which stage rejected a
            // presentation without reading the JSON verdict.
            for check in &result.checks {
                if check.passed {
                    tracing::info!(check = %check.check, passed = true, "verification check");
                } else {
                    // ... the existing warn! arm
                }
            }
```

After Task 4 most checks are per-credential, so this loop now walks both levels and names the credential for the second. Replace it with:

```rust
            // One record per check, so an operator can see which stage rejected a
            // presentation without reading the JSON verdict.
            //
            // Both levels, and per-credential records name their credential:
            // with N credentials `check=dcql_match passed=false` alone does not
            // say whose. A DCQL credential query id is operator-authored request
            // structure, not a holder value, so naming it is safe -- the same
            // reasoning `dcql.rs` records for naming claim paths in a mismatch
            // (root AGENTS.md §4.5).
            for check in &result.checks {
                if check.passed {
                    tracing::info!(check = %check.check, passed = true, "verification check");
                } else {
                    tracing::warn!(
                        check = %check.check,
                        passed = false,
                        detail = %check
                            .detail
                            .as_deref()
                            .map(|d| foundry_core::obs::truncate(d, DETAIL_MAX))
                            .unwrap_or_default(),
                        "verification check failed"
                    );
                }
            }
            for credential in &result.credentials {
                for check in &credential.checks {
                    if check.passed {
                        tracing::info!(
                            credential = %credential.query_id,
                            check = %check.check,
                            passed = true,
                            "verification check"
                        );
                    } else {
                        tracing::warn!(
                            credential = %credential.query_id,
                            check = %check.check,
                            passed = false,
                            detail = %check
                                .detail
                                .as_deref()
                                .map(|d| foundry_core::obs::truncate(d, DETAIL_MAX))
                                .unwrap_or_default(),
                            "verification check failed"
                        );
                    }
                }
            }
```

> Match the existing `warn!` arm's field set exactly rather than copying the
> block above verbatim — read lines ~248-258 first and keep whatever fields are
> already there, adding only `credential`. Renaming or dropping an existing field
> is a breaking change for whoever is watching the logs (root `AGENTS.md` §4.5).

- [ ] **Step 2: Update the verdict event**

The verdict event currently counts only top-level checks, so after Task 4 it would report `failed_checks = 0` for a presentation whose `dcql_match` failed — the count would be silently wrong in exactly the case an operator cares about:

```rust
                tracing::warn!(
                    verified = false,
                    failed_checks = result.checks.iter().filter(|c| !c.passed).count(),
                    "vp response not verified"
                );
```

Replace both arms of that block with:

```rust
            // `credentials_requested` / `credentials_answered` are COUNTS, never
            // identifiers, so they carry no request structure at all. The count
            // pair is what makes a subset response visible at a glance.
            let credentials_requested = serde_json::from_value::<DcqlQuery>(tx.dcql_query.clone())
                .map(|q| q.credentials().len())
                .unwrap_or(0);
            let credentials_answered = result.credentials.len();

            if result.verified {
                tracing::info!(
                    verified = true,
                    credentials_requested,
                    credentials_answered,
                    "vp response verified"
                );
            } else {
                tracing::warn!(
                    verified = false,
                    // BOTH levels: after multi-credential support most checks are
                    // per-credential, so a top-level-only count under-reports and
                    // would read as zero failures on a failed verification.
                    failed_checks = result.all_checks().filter(|c| !c.passed).count(),
                    credentials_requested,
                    credentials_answered,
                    "vp response not verified"
                );
            }
```

- [ ] **Step 3: Coverage note — read before running the gate**

This task deliberately adds **no new test**, and that is a considered decision rather than an omission:

- `crates/foundry/tests/logging_redaction.rs` is the only harness that captures tracing output, but every verification it drives uses a junk JWE and fails structurally at decryption (HTTP 400). Such a flow never produces per-credential checks, so it cannot assert on the new `credential` field or on the corrected `failed_checks` count.
- Building a *successful* multi-credential verification inside that harness would mean reproducing the SD-JWT VC issuance and JWE construction that `wallet_verification.rs` already owns — a large amount of test scaffolding for one log field.
- The logic that could get this wrong — the two-level traversal — is `VerificationResult::all_checks`, and Task 2 already tests it directly, including the exact case a single-level count gets wrong.

**What this leaves uncovered:** that the emitting *sites* actually call `all_checks()` rather than `checks`, and that `credential` is populated. Both are single-expression changes visible in review.

**Follow-up worth filing separately:** a `drive_successful_verification` helper in `logging_redaction.rs`, reusing `wallet_verification.rs`'s presentation builders, which would let the redaction suite assert on per-credential log records — and would also close the gap that no test currently proves a *disclosed claim value* stays out of the log on a **successful** verification. Today's `PLANTED_CLAIM` assertion covers issuance only.

- [ ] **Step 4: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. In particular `instrumentation_hygiene.rs` (every `#[tracing::instrument]` still carries `skip_all`) and the whole of `logging_redaction.rs` including its positive control.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs
git commit -m "feat(verifier): log checks at both levels and name the credential

After multi-credential support most checks are per-credential, so the
verdict event's failed_checks count -- which walked only the top-level list
-- would have read as zero failures on a failed verification. It now spans
both levels via all_checks().

Per-credential check records carry a credential field: with N credentials,
check=dcql_match passed=false does not say whose. A DCQL credential query id
is operator-authored request structure rather than a holder value, so naming
it is safe under root AGENTS.md 4.5 -- the same reasoning dcql.rs already
records for naming claim paths in a mismatch.

The verdict event also carries credentials_requested and credentials_answered
as counts, never identifiers, which makes a subset response visible at a
glance.

No new test: the only tracing-capture harness drives structurally-failing
verifications (junk JWE, HTTP 400) that never produce per-credential checks,
and the two-level traversal itself is already covered by Task 2's
all_checks test. See the plan's Task 6 Step 3 for the follow-up this leaves
open."
```

---

## Task 7: Documentation, conformance, and the change record

The last task. No code changes — but the §4.2 amendment is normative, so this is not optional polish.

**Files:**

- Modify: `AGENTS.md` (root) — §4.2
- Modify: `crates/foundry-verifier/AGENTS.md` — module map, key types, binding invariants, gotchas
- Modify: `docs/conformance/openid4vc-conformance.md` — VP-0094, VP-0093/GAP-VP-03, VP-0103, VP-0104, HAIP-0070
- Modify: `README.md` — only if it documents the verification result shape
- Create: `docs/superpowers/changes/2026-08-18-multi-credential-dcql.md`

**Interfaces:**

- Consumes: everything from Tasks 1-6.
- Produces: nothing consumed by code.

- [ ] **Step 1: Amend root `AGENTS.md` §4.2**

Find the current wording:

```bash
grep -n "checks.iter().all" AGENTS.md
```

Replace the bullet that reads

> - In `foundry-verifier`, `VerificationResult.verified` MUST equal
>   `checks.iter().all(|c| c.passed)`.

with:

```markdown
- In `foundry-verifier`, `VerificationResult.verified` MUST equal the
  conjunction over **every** `CheckResult` in the result — the top-level
  `checks` **and** every `credentials[i].checks` entry. Use
  `VerificationResult::all_checks()`; `checks.iter().all(..)` alone is
  satisfiable while a per-credential check fails, which is the whole defect
  this rule exists to prevent.
```

In the same section, extend the check-name vocabulary. The current sentence enumerates six names; it becomes two levels:

```markdown
- Every verification step pushes a named `CheckResult`, at one of two levels.
  **Cross-cutting** (`result.checks`): `jwe_decryption`,
  `requested_credentials_answered`. **Per-credential**
  (`result.credentials[i].checks`): `sd_jwt_vc_signature_and_kb_jwt` or
  `mdoc_issuer_auth_and_device_signature` (mutually exclusive, chosen by the
  answered credential query's declared format), `dcql_match`, `status_check`,
  and `transaction_data_binding` (only when the request carried
  `transaction_data`).
```

- [ ] **Step 2: Update `crates/foundry-verifier/AGENTS.md`**

Five edits:

1. **Module map**, `verify.rs` row — mention the loop and the outcome type:

   > `verify.rs` | The orchestrator: JWE decrypt → `select_presentations` → a per-credential verify-all loop (`verify_one_credential`) → `requested_credentials_answered`, then computes `verified` as the conjunction over **both** check levels. Returns a `VerifyOutcome` internally so an unavailable status list can become HTTP 502 without discarding the other credentials' checks. Also flips `tx.state` and stores `tx.result`

2. **Key Public Types** — the `VerificationResult` line becomes:

   > `VerificationResult { verified, checks, credentials }`,
   > `PresentedCredential { query_id, format, claims, checks }`,
   > `CheckResult { check, passed, detail }`. `VerificationResult::all_checks()`
   > yields every check at both levels; `derive_verified()` is the §4.2 verdict.

3. **Binding invariants** — replace the `verified` bullet:

   > - **`verified` MUST equal the conjunction over EVERY check, at both levels** —
   >   use `all_checks()` / `derive_verified()`, never `checks.iter().all(..)`,
   >   which passes while a per-credential check fails. Never hardcode
   >   `verified: true`. Full rule: root [AGENTS.md](../../AGENTS.md) §4.2.

   And the check-vocabulary bullet: the six names split across the two levels
   exactly as in root §4.2, with `requested_credentials_answered` added.

4. **Gotchas — the single-credential entry inverts.** Replace the
   *"`vp_token` is an OpenID4VP 1.0 §8.1 object keyed by DCQL credential query
   id, with ARRAY values"* bullet's single-credential claims with:

   ```markdown
   - **A `vp_token` may answer SEVERAL credential queries**, and each answered
     query becomes one `PresentedCredential` in **DCQL declaration order** — not
     `vp_token` key order, which depends on the wallet's serialization and on
     whether `serde_json` was built with `preserve_order`. `select_presentations`
     performs the selection.
   - **Each entry's array still holds exactly one presentation.** OpenID4VP
     L1166: "When `multiple` is omitted, or set to `false`, the array MUST contain
     only one Presentation." foundry ignores `multiple` (VP-0090), so it never
     requests more than one and the rule always applies. If `multiple: true` is
     ever honoured, this guard must move behind that flag in the same change.
   - **Claims are per credential and MUST NOT be merged.** `check_status` reads
     `status.status_list` out of the map it is handed, so a merged map runs one
     credential's revocation check against another's status list — silently, with
     a passing `status_check`. Two credentials disclosing the same claim name
     collide the same way.
   - **A subset `vp_token` is a POLICY verdict, not a 400.** It violates
     OpenID4VP L1007-1008 (a wallet that cannot deliver all non-optional
     Credentials MUST NOT return any), but it is well-formed, so it yields
     HTTP 200 + `verified: false` with a failed `requested_credentials_answered`
     naming the unanswered ids — and the detail attributes the fault to the
     wallet. An id the request never asked for stays structural (400): there is
     no credential query to attribute a verdict to.
   - **An unavailable status list still returns 502, but must not be lossy.**
     `do_verify_vp_response` returns `VerifyOutcome { result, deferred }`; the
     wrapper persists `result` first, then re-raises. It also pushes a top-level
     failed `status_check` — without it, an unavailable status pushes no check at
     all and the conjunction computes `true`, persisting `verified: true` on a
     transaction that just returned 502.
   ```

5. **Gotchas — duplicate ids.** Add:

   ```markdown
   - **Duplicate credential query ids are rejected at request creation**
     (`create_verification_request`, OpenID4VP L745-746). This is load-bearing,
     not cosmetic: `select_presentations` matches each credential query against
     `vp_token`'s keys, so two queries sharing an id both match the same entry
     and one presentation would be verified twice under contradictory queries.
   ```

- [ ] **Step 3: Update the conformance report**

In `docs/conformance/openid4vc-conformance.md`:

1. **VP-0094** — `gap` → `conforming`. Evidence: *"`create_verification_request` (request.rs) rejects a `dcql_query` whose `credentials` repeat an `id`, raising `VerificationError::Dcql` (HTTP 400 on the admin API) before the transaction is persisted; multi-credential verification is unsound without it, because `select_presentations` would match two queries to the same `vp_token` entry."* Test: `create_rejects_duplicate_credential_query_ids`.

2. **GAP-VP-03** — narrow the register entry: it currently claims `id` uniqueness among the unvalidated constraints. Remove uniqueness from its list and from **VP-0094**'s cross-reference, leaving VP-0093 (charset), VP-0096 (`meta` required), and VP-0097 (duplicate claim pointers).

3. **VP-0103, VP-0104** — stay `not-implemented`. Rewrite the evidence so it cites the non-goal rather than the single-credential design, which no longer exists: *"`credential_sets` is not modelled by `dcql_model.rs`; it deserializes as an ignored unknown property (VP-0090). foundry implements the conjunctive DCQL case only — with `credential_sets` absent every credential query is non-optional (L993) — and `credential_sets` alternatives/optionality are an explicit non-goal of the multi-credential design."*

4. **HAIP-0070** — stays `not-implemented`, but its root cause changes. Replace *"Same root cause as VP-0103: foundry presents exactly one credential per `vp_token` by design"* with: *"foundry now verifies several credentials per `vp_token`, so the multi-mdoc scenario does arise. This clause is still unmet for a different reason: it requires each mdoc in a separate `DeviceResponse`, and foundry's mdoc payload is the bespoke `{mdoc, device_signature}` pair rather than a `DeviceResponse` at all — see `crates/foundry-mdoc/AGENTS.md`."*

> **Do not** mark HAIP-0070 `conforming`. Lifting the single-credential limit
> removes the *stated* cause but not the actual blocker, and a row that claims
> conformance it does not have is worse than an honest `not-implemented`.

- [ ] **Step 4: Check `README.md`**

```bash
grep -n "\"claims\"\|verified.*checks\|VerificationResult" README.md
```

If any example response body shows a flat `claims` object, update it to the `credentials` array. If nothing matches, make no change — do not invent documentation.

- [ ] **Step 5: Write the change record**

Create `docs/superpowers/changes/2026-08-18-multi-credential-dcql.md` following the shape of `2026-08-18-kb-jwt-audience-mismatch-names-both-values.md`: **Motivation**, **Change**, **Why this is not a §4.5 leak** (the `credential` log field and the count pair), **Files** table, **Tests**, **Note**. It must record:

- that a conformant wallet answering a multi-credential request previously received HTTP 400, even though the request side already accepted such queries;
- the two collision bugs a flat `claims` map hid, with the status collision named as the security-relevant one;
- the L1007-1008 finding and that the policy-verdict classification rests on the four grounds in the design's §5, **not** on VP-0117 (which an earlier draft misread);
- the deliberate non-goals (`credential_sets`, `multiple: true`) and that the exactly-one guard is now spec-cited rather than merely conservative;
- HAIP-0070's re-grounded evidence and why it did **not** become conforming;
- Task 6's coverage limitation and the follow-up it leaves open.

- [ ] **Step 6: Run the gate and the E2E suite**

Docs-only, but run the gate anyway — a stale doc example can be inside a doctest, and `cargo nextest run` does **not** run doctests:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Then, because this is the end of the branch (root `AGENTS.md` §5.2):

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

- [ ] **Step 7: Commit**

```bash
git add AGENTS.md crates/foundry-verifier/AGENTS.md \
        docs/conformance/openid4vc-conformance.md \
        docs/superpowers/changes/2026-08-18-multi-credential-dcql.md README.md
git commit -m "docs: multi-credential DCQL verification

Root AGENTS.md 4.2 now defines verified as the conjunction over every check
at BOTH levels, because the old single-list all(passed) is satisfiable while
a per-credential check fails. The check vocabulary is split into
cross-cutting and per-credential, with requested_credentials_answered added.

Verifier AGENTS.md: the single-credential gotcha inverts. Records that
claims MUST NOT be merged (the status-list collision), that a subset vp_token
is a policy verdict rather than a 400, that the exactly-one-presentation
guard is mandated by L1166 rather than merely conservative, and why duplicate
credential query ids are rejected at request creation.

Conformance: VP-0094 closed. GAP-VP-03 narrowed to the constraints still
unvalidated. VP-0103/VP-0104 re-grounded on the credential_sets non-goal
rather than the single-credential design, which no longer exists. HAIP-0070
re-grounded too but deliberately NOT marked conforming -- lifting the
single-credential limit removes its stated cause, not its actual blocker,
which is the bespoke mdoc envelope."
```

---

## Self-Review

Run after the plan is written, before execution.

**1. Spec coverage.** Every section of the design maps to a task:

| Design section | Task |
| --- | --- |
| §1 Context / §1.1 spec requirements | Cited throughout; the exactly-one guard's L1166 citation lands in Task 3 |
| §2 Scope and non-goals | Global Constraints (non-goals) + Task 3 (guard retained) |
| §2.1 Duplicate credential query ids | **Task 1** |
| §3 Data model / §3.1 collisions / §3.2 ordering | **Task 2** (model), **Task 4** (collisions fixed + tested), **Task 3** (ordering) |
| §4 Orchestrator control flow / §4.1 structural / §4.2 per-credential / §4.3 verdict | **Task 3** (§4.1), **Task 4** (§4.2, §4.3) |
| §5 Error classification | **Task 3** (selection accepts a subset) + **Task 4** (`requested_credentials_answered`, wallet-attributing detail) |
| §6 Check vocabulary / §6.1 §4.2 amendment | **Task 4** (new name), **Task 2** (`all_checks`/`derive_verified`), **Task 7** (the amendment itself) |
| §7 Deferred 502 / §7.1 the trap | **Task 5** |
| §8 Observability | **Task 6** |
| §9 Testing | Distributed across Tasks 1-5; Task 6's gap is documented at its Step 3 |
| §10.1 Documentation | **Task 2** (OpenAPI, console), **Task 7** (AGENTS.md, README, change record) |
| §10.2 Conformance | **Task 7** |
| §11 Files touched | Union of all tasks; `request.rs` added by §2.1 |
| §12 Settled decisions | **Task 1** (duplicate ids), **Task 2** (stacked console sections) |

No design requirement is unassigned.

**2. Placeholder scan.** No `TBD`, `TODO`, or "implement later". Three constructs deserve a note, none of which is a placeholder:

- Task 4 Step 4's `<<< ... >>>` marker instructs the implementer to **move existing code verbatim** and lists the exact substitutions. Reproducing ~200 lines of `SessionTranscriptParams` candidate logic here would risk transcription drift in the one place the plan cannot afford it.
- Task 5 Step 5's `<<< unchanged >>>` marks blocks that must not be touched.
- Task 6 Step 3 documents a **deliberate** absence of a new test, with its reasoning and the follow-up it leaves open.

**3. Type consistency.** Checked across tasks:

- `PresentedCredential { query_id, format, claims, checks }` — identical in Tasks 2, 4, 5.
- `VerificationResult { verified, checks, credentials }` and `all_checks()` / `derive_verified()` — Task 2 defines, Tasks 4/5/6 consume.
- `select_presentations(&Value, &Value) -> Result<Vec<(String, SelectedPresentation<'a>)>, VerificationError>` — Task 3 defines, Task 4 consumes with matching destructuring.
- `verify_one_credential(..) -> Result<(PresentedCredential, Option<String>), VerificationError>` — Task 4 defines and consumes; the `Option<String>` becomes `VerificationError::StatusUnavailable` at the call site, matching Task 5's `deferred` type.
- `check_requested_credentials_answered(&Value, &[PresentedCredential]) -> CheckResult` — Task 4 defines, consumed in Tasks 4 and 5.
- Check-name strings — `requested_credentials_answered` spelled identically in Tasks 4, 6, 7 and root §4.2.
- `CredentialVerifyCtx` field names match between its definition and its construction in Task 4 Step 5.

**Ordering constraint:** Tasks 2 → 3 → 4 → 5 are strictly sequential (each consumes the previous task's types). **Task 1 is independent** and may run first or in parallel. Task 6 requires Task 5. Task 7 is last.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-18-multi-credential-dcql-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task with review between tasks, and fast iteration. Given this plan's sequential type dependencies, Task 1 can be dispatched in parallel with Task 2; Tasks 3-7 must run in order. Role mapping per root `AGENTS.md` §7: Tasks 1 and 6 suit `mechanical-implementer`; Tasks 2, 3, 4, 5 need `integration-implementer` (multi-file, or non-trivial control-flow restructuring); Task 7 suits `mechanical-implementer`. Per-task review by `task-reviewer`, then one `final-reviewer` pass over the whole branch including the §5.2 E2E suite.

**2. Inline Execution** — execute the tasks in this session with checkpoints for review.

Which approach?
