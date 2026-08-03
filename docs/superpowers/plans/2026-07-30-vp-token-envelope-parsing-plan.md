# Plan — OpenID4VP-Conformant `vp_token` Envelope Parsing

> Migrated from `docs/superpowers/plans/2026-07-30-vp-token-envelope-parsing-plan.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Spec:** docs/superpowers/specs/2026-07-30-vp-token-envelope-parsing-spec.md
**Branch:** superlight/2026-07-30-vp-token-envelope-parsing
**Base:** main @ 4511acb
**Revised:** 2026-07-30 — scope expanded per spec §12 (D3, D4, D5 now in scope).

---

## Task Decomposition Rationale

**Four tasks.**

**Task 1 cannot be split.** `crates/foundry/tests/wallet_verification.rs` and
`crates/foundry/tests/e2e_full_flow.rs` exercise a **real in-process server**
(`support::spawn_test_server()`, `foundry` as dev-dependency). Changing the
verifier's accepted envelope without simultaneously migrating the debug wallet
client and every test call site would leave `cargo test --workspace` red across
a commit, which the gates forbid.

**D4 is folded into Task 1, not a separate task.** Tightening `dcql_match` to the
answered query id changes what `select_presentation` must return. Doing it
separately would mean building a workaround (returning no query id, to dodge
`dead_code` under `clippy -D warnings`) and then immediately deleting it. One
commit, no churn.

**Tasks 2 and 3 are independent** of Task 1 and of each other. **Task 4 is last**
so the documentation describes the final state rather than an intermediate one.

---

## Task 1 — Conformant `vp_token` parsing + query-id-bound DCQL match

**Files:** `crates/foundry-verifier/src/verify.rs`,
`crates/foundry-verifier/src/dcql.rs`,
`crates/foundry-wallet/src/actions/verification.rs`,
`crates/foundry-wallet/src/actions/match_credentials.rs`,
`crates/foundry/tests/wallet_verification.rs`,
`crates/foundry/tests/e2e_full_flow.rs`

### 1.1 Selection helper (`foundry-verifier/src/verify.rs`)

- [x] Private `fn select_presentation<'a>(vp_token: &'a Value, dcql_query: &Value) -> Result<(String, PresentedFormat, &'a Value), VerificationError>` returning `(query_id, format, presentation)`.
- [x] Algorithm per spec §6, in order: object check → `DcqlQuery` parse → key
      intersection (0 / >1) → exactly-one-element array → format dispatch with
      element type check.
- [x] Every failure is `VerificationError::Failed(..)` → HTTP 400
      `invalid_request` (spec §8). Messages name received vs expected and must
      **not** echo credential contents.
- [x] No `.unwrap()` / `.expect()` / `panic!()` (root `AGENTS.md` §4.1).

### 1.2 Wire into `do_verify_vp_response`

- [x] Replace the `as_str()` / `as_object()` block (≈ `verify.rs:89-165`) with a
      `select_presentation` call plus a `match` on `PresentedFormat`.
- [x] `SdJwtVc` arm: `verify_sd_jwt_vc` call and
      `sd_jwt_vc_signature_and_kb_jwt` check push unchanged.
- [x] `MsoMdoc` arm: `verify_mdoc` call and
      `mdoc_issuer_auth_and_device_signature` check push unchanged; `mdoc` /
      `device_signature` extraction keeps its own missing-key errors.
- [x] Comment at the mdoc arm: envelope is conformant, **payload is still
      bespoke and non-interoperable** (spec §4 defects 2–3).

### 1.3 D4 — bind `dcql_match` to the answered query id (`dcql.rs`)

- [x] `check_dcql_match` gains an `answered_query_id: &str` parameter.
- [x] Look the credential query up **by id** and require *that* query to be
      satisfied, replacing the "any query of the presented format" loop.
- [x] Unknown id → failed check, fail-closed (never an error, never a panic) —
      `check_dcql_match` is `pub` and the wallet can pass an arbitrary id.
- [x] Pass the id through from `do_verify_vp_response`.
- [x] Update the wallet call site in `match_credentials.rs`, which already has
      `query_id` per entry.
- [x] Update existing `dcql.rs` unit tests for the new signature; assertions
      unchanged except where D4 deliberately changes the verdict.

### 1.4 Unit tests — `select_presentation` (`verify.rs`, `#[cfg(test)]`)

Each must fail before 1.1/1.2. Per spec §9:

- [x] conformant SD-JWT envelope → `SdJwtVc` + the string, and the right query id
- [x] conformant mdoc envelope → `MsoMdoc` + the object
- [x] bare string `vp_token` → rejected (**the reported bug**)
- [x] top-level `{"mdoc":…,"device_signature":…}` → rejected
- [x] key absent from the DCQL query → rejected; message names received **and** expected
- [x] two matching keys → rejected as multi-credential
- [x] empty array → rejected; 2-element array → rejected
- [x] `dc+sd-jwt` answered with an object → rejected, message names the declared format
- [x] `mso_mdoc` answered with a string → rejected, message names the declared format
- [x] unparseable `dcql_query` → rejected

### 1.5 Unit tests — D4 (`dcql.rs`)

- [x] answering query `a` while satisfying only query `b` now **fails** (it
      previously passed). This is the behaviour change D4 buys — assert it
      directly, not incidentally.
- [x] `answered_query_id` not present in the query → failed check.

### 1.6 Migrate the in-crate fixtures (`verify.rs`)

- [x] Sites ≈ 369, 470, 534 (SD-JWT bare string) and ≈ 636 (hand-built mdoc
      envelope) → conformant envelope.
- [x] Use each fixture's **own** DCQL credential query id; do not assume `c1`.
- [x] Assertions otherwise unchanged — that is what proves behaviour preserved.

### 1.7 Migrate the debug wallet (`foundry-wallet/src/actions/verification.rs`)

- [x] Replace `json!({ "vp_token": presentation })` (≈ line 161) with a
      `serde_json::Map` keyed by `matched.query_id`, value `[presentation]`.
      A dynamic key cannot be a `json!` key literal — build the map explicitly.
- [x] Comment naming OpenID4VP 1.0 §8.1.
- [x] `WalletResult` / `WalletError` only; no unwraps (root §4.1).

### 1.8 Migrate the integration tests

- [x] `wallet_verification.rs` — every `json!({ "vp_token": … })` site,
      **including the mdoc envelope at ≈ 1054**. Read each test's own DCQL id;
      no search-and-replace.
- [x] `e2e_full_flow.rs` — the single site.
- [x] New test: the bare-string envelope returns **400** (it returned
      `200 verified:true` before).
- [x] SD-JWT happy path asserts `verified: true` **and the four named
      `CheckResult`s** (root §4.2 — an omitted check drops out of `all(passed)`,
      so `verified` alone cannot detect a lost check).
- [x] Existing failure-mode tests (revoked, tampered, replay, unknown tx) keep
      their assertions; only the envelope shape changes.

### 1.9 Verify and commit

- [x] `cargo test --workspace` exit 0, zero non-`0 failed` lines.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` exit 0.
- [x] `cargo fmt --check` exit 0.
- [x] Read real exit codes; never pipe through `head`, which reports `head`'s status.
- [x] Commit.

---

## Task 2 — D3: validate `dcql_query` at transaction-creation time

**Files:** `crates/foundry-verifier/src/request.rs`, `config.yaml`

- [x] In `create_verification_request`, after resolving `dcql` (inline or via
      `named_query_ref`) and **before** persisting, parse it into `DcqlQuery` and
      return `VerificationError::Dcql` naming the parse error on failure.
- [x] Confirm how `VerificationError::Dcql` maps to an HTTP status in
      `crates/foundry/src/server.rs` — it must be a 4xx client error, since this
      is an operator input mistake. **Verify, do not assume.**
- [x] Fix `config.yaml` `named_queries[over18]`: `credentials: []` is invalid
      (`dcql_model.rs:65` requires non-empty) and semantically empty. Replace
      with a real over-18 query.
- [x] Rewrite `test_create_verification_request_dc_api` (`request.rs:580-596`),
      which currently asserts an **empty** query succeeds, to use a valid query;
      its `dc_api` assertions are unaffected and must be preserved.
- [x] Grep the whole workspace for other `"credentials": []` / empty-DCQL
      fixtures and fix each. Do not assume the two known sites are the only ones.
- [x] New tests: malformed `dcql_query` rejected at creation; `{"credentials": []}`
      rejected at creation; a valid query still succeeds per transport.
- [x] Note in the changelog that D3's verification-time hard error is now
      practically unreachable but retained as defence in depth.
- [x] Re-run all three gates. Commit.

---

## Task 3 — D5: OpenAPI drift tests

**Files:** `crates/foundry/tests/` (new or existing `openapi_endpoints.rs`)

- [x] Test: committed `openapi.json` equals `generate_admin_openapi_spec()`.
- [x] Test: committed `openapi-wallet.json` equals `generate_wallet_openapi_spec()`.
- [x] Resolve paths from `CARGO_MANIFEST_DIR` (the `foundry` crate is at
      `crates/foundry`, so the specs are two levels up), not from the process CWD.
- [x] Compare **parsed JSON**, so the assertion tracks content drift rather than
      serializer whitespace.
- [x] Failure message must name the regeneration command from
      `crates/foundry/AGENTS.md`, so the next person can act on it.
- [x] Confirm both tests pass at current HEAD; if either fails, the committed
      spec is already stale and regenerating it is part of this task.
- [x] Re-run all three gates. Commit.

---

## Task 4 — Documentation

**Files:** `crates/foundry-verifier/AGENTS.md`, `crates/foundry-mdoc/AGENTS.md`

- [x] `foundry-verifier/AGENTS.md` Gotcha: `vp_token` is an OpenID4VP §8.1 object
      keyed by DCQL credential query id with **array** values; format comes from
      the **declared** DCQL format, never the JSON shape. Record the historical
      signature `mdoc vp_token missing 'mdoc'` and note that type-sniffing
      misreports an SD-JWT VC presentation as an mdoc error. Note `dcql_match`
      binds to the answered query id, and that `dcql_query` is validated at
      creation.
- [x] `foundry-mdoc/AGENTS.md` Gotcha: the mdoc presentation payload is
      **bespoke** (`{mdoc, device_signature}`, not a base64url `DeviceResponse`)
      and `serialize_session_transcript` is **not** the spec `OpenID4VPHandover`.
      mdoc is **not** interoperable with real wallets; a green mdoc test proves
      self-consistency only. Reference spec §4 defects 2–3 and §12's unblocking
      condition.
- [x] Follow root `AGENTS.md` §8: no line counts or test counts in any AGENTS.md.
- [x] Re-run all three gates. Commit.

---

## Deviations

Record any departure from this plan here, with reasoning, before proceeding.

- **Scope expanded after the Phase 3 gate** (spec §12): D3, D4, D5 moved from
  "known limitations" into scope on the human partner's request. D4 folded into
  Task 1 rather than made its own task, to avoid building and then deleting a
  `dead_code` workaround.

- **Task 1 — `CredentialFormat` has a third variant, `Other(String)`.** The spec
  and plan both assumed the enum was exhaustively `DcSdJwt | MsoMdoc`; the
  compiler rejected the match. `Other` is deliberate (`dcql_model.rs`): an
  unimplemented format parses so it can simply *fail to match* inside a
  multi-credential query rather than invalidating the whole query. But once a
  wallet has *answered* such a query there is no verifier to dispatch to, so it
  gets its own structural 400 naming the format. Covered by
  `select_presentation_rejects_unimplemented_credential_format`.

- **Task 1 — `doc_type` is assigned from the `match` expression**, not
  late-initialised, because `clippy::needless_late_init` rejected the plan's
  shape.

- **Task 2 — three empty-DCQL sites, not two, and `config.yaml` is gitignored.**
  The plan named `config.yaml` and one test. The real tracked source is the
  **`quickstart` config scaffold in `crates/foundry/src/commands.rs`**, which
  *generates* `config.yaml` — and `config.yaml` itself is gitignored, so it is a
  local artifact and not part of this change. An earlier draft of the guard test
  read `../../config.yaml`, which would have failed in any fresh clone or CI;
  that test was removed and the guard now targets the scaffold. Proven red-green
  by reverting the scaffold.

- **Task 2 — `dcql_model.rs` already documented this defect.** Its
  `rejects_empty_credentials` test carried a comment noting that `config.yaml`
  shipped `dcql: { credentials: [] }`. The codebase had noticed the defect and
  never repaired it; the comment now describes the fixed state.

- **Task 3 — added `foundry openapi --wallet` (beyond plan scope).** The plan
  required the drift failure to "name the regeneration command", but no such
  command existed for the wallet spec: `foundry openapi --out` only ever emitted
  the admin doc, which is why the predecessor change had to use a throwaway test
  file. A drift test that cannot tell you how to fix the drift is half a guard.
  Both flags were verified to reproduce the committed files byte-identically.

## Discovered, Deliberately Not Fixed

- **`meta.doctype` vs the spec's `meta.doctype_value`.** `dcql.rs` reads
  `doctype_value` (correct per OpenID4VP Appendix B.2.3), but the `sample_config`
  fixture in `request.rs` writes `meta: { doctype: ... }`, so that query's doctype
  constraint would be silently ignored at match time. It is confined to
  `#[cfg(test)]` code — no shipped config uses the wrong key — so it is a
  misleading fixture rather than a live defect. Fixing it means changing a test's
  assertion, which belongs in its own change rather than buried here.

---

## Known Limitations Carried Forward

To be restated in the changelog, not silently dropped:

- **mdoc remains non-interoperable** — envelope fixed; payload and
  SessionTranscript are not (spec §4 defects 2–3). Blocked on a captured real
  mdoc presentation or an official test vector (spec §12).
- **Confirmation against the live eudi-pal wallet is not automated** and remains
  the human partner's acceptance step.
