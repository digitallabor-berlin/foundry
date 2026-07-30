# Plan — OpenID4VP-Conformant `vp_token` Envelope Parsing

**Spec:** docs/superlight/specs/2026-07-30-vp-token-envelope-parsing-spec.md
**Branch:** superlight/2026-07-30-vp-token-envelope-parsing
**Base:** main @ 4511acb

---

## Task Decomposition Rationale

**Two tasks, and Task 1 cannot be split further.**

`crates/foundry/tests/wallet_verification.rs` and
`crates/foundry/tests/e2e_full_flow.rs` exercise a **real in-process server**
(`support::spawn_test_server()`, with `foundry` as a dev-dependency). Changing
the verifier's accepted envelope without simultaneously migrating the debug
wallet client and every test call site would leave `cargo test --workspace` red
across a commit — which the verification gates forbid.

Splitting "add the helper" from "wire the helper" is also rejected: an unwired
private helper used only from `#[cfg(test)]` code trips `dead_code` under
`clippy -D warnings` in the non-test build.

So Task 1 is one atomic commit: parser + dispatch + client + all fixtures.
Task 2 is documentation-only.

---

## Task 1 — Conformant `vp_token` parsing, both formats, all call sites

**Files:** `crates/foundry-verifier/src/verify.rs`,
`crates/foundry-wallet/src/actions/verification.rs`,
`crates/foundry/tests/wallet_verification.rs`,
`crates/foundry/tests/e2e_full_flow.rs`

### 1.1 Add the selection helper (`foundry-verifier/src/verify.rs`)

- [ ] Add a private `fn select_presentation<'a>(vp_token: &'a Value, dcql_query: &Value) -> Result<(PresentedFormat, &'a Value), VerificationError>`.
- [ ] **Return only `(PresentedFormat, &Value)` — deliberately not the query id.**
      The id is needed *inside* the helper for error messages, but nothing
      downstream consumes it (spec D4 leaves `check_dcql_match` unchanged).
      Returning it would be a field read only under `#[cfg(test)]`, which
      `dead_code` flags under `-D warnings`.
- [ ] Implement the algorithm in spec §6, in order: object check → `DcqlQuery`
      parse → key intersection (0 / >1) → exactly-one-element array → format
      dispatch with element type check.
- [ ] Every failure is `VerificationError::Failed(..)` (→ HTTP 400
      `invalid_request`, spec §8). Messages name received vs expected, and must
      not echo credential contents.
- [ ] No `.unwrap()` / `.expect()` / `panic!()` (root `AGENTS.md` §4.1).

### 1.2 Wire it into `do_verify_vp_response`

- [ ] Replace the `if let Some(jwt_str) = vp_token.as_str() { … } else if let Some(obj) = vp_token.as_object() { … } else { … }` block (≈ `verify.rs:89-165`) with a `select_presentation` call followed by a `match` on `PresentedFormat`.
- [ ] `SdJwtVc` arm: unchanged `verify_sd_jwt_vc` call and unchanged
      `sd_jwt_vc_signature_and_kb_jwt` check push.
- [ ] `MsoMdoc` arm: unchanged `verify_mdoc` call and unchanged
      `mdoc_issuer_auth_and_device_signature` check push. `mdoc` /
      `device_signature` extraction moves behind the helper's object check but
      keeps its own missing-key errors.
- [ ] Add a doc comment at the mdoc arm stating the payload is **still bespoke
      and non-interoperable** (spec §4 defects 2–3) — the envelope is
      conformant, the payload is not.
- [ ] `presented_format` / `doc_type` / `check_dcql_match` call unchanged.

### 1.3 Unit tests for the helper (`verify.rs`, `#[cfg(test)]`)

Each must fail before 1.1/1.2 land. Cover, per spec §9:

- [ ] conformant SD-JWT envelope → `SdJwtVc` + the string element
- [ ] conformant mdoc envelope → `MsoMdoc` + the object element
- [ ] bare string `vp_token` → rejected (**the reported bug**)
- [ ] top-level `{"mdoc":…,"device_signature":…}` → rejected
- [ ] key absent from the DCQL query → rejected; assert the message names both
      the received key and the expected id
- [ ] two matching keys → rejected as multi-credential
- [ ] empty array → rejected; 2-element array → rejected
- [ ] `dc+sd-jwt` answered with an object → rejected, message names the declared format
- [ ] `mso_mdoc` answered with a string → rejected, message names the declared format
- [ ] unparseable `dcql_query` → rejected (spec D3)

### 1.4 Migrate the four in-crate fixtures (`verify.rs`)

- [ ] Sites ≈ 369, 470, 534 (`json!({ "vp_token": presentation })`, SD-JWT) and
      ≈ 636 (the hand-built mdoc envelope) → conformant envelope.
- [ ] Use each test's **own** DCQL credential query id — do not assume `c1`;
      read each fixture's `dcql_query`.
- [ ] Assertions otherwise unchanged: unchanged assertions are what prove the
      migration preserved behaviour.

### 1.5 Migrate the debug wallet (`foundry-wallet/src/actions/verification.rs`)

- [ ] Replace `json!({ "vp_token": presentation })` (≈ line 161) with a
      `serde_json::Map` keyed by `matched.query_id`, value `[presentation]`.
      A dynamic key cannot be a `json!` key literal, so build the map explicitly.
- [ ] Add a brief comment naming OpenID4VP 1.0 §8.1 as the reason for the shape.
- [ ] Return `WalletResult`/`WalletError` only; no unwraps (root §4.1).
- [ ] Note: `match_credentials` defaults a missing DCQL `id` to `""`
      (`match_credentials.rs`), but `DcqlCredentialQuery.id` has no serde
      default, so such a query fails `DcqlQuery` parsing and is already a D3
      structural error. No extra handling needed — confirm, do not assume.

### 1.6 Migrate the integration tests

- [ ] `crates/foundry/tests/wallet_verification.rs` — every
      `json!({ "vp_token": … })` call site, **including the mdoc envelope at
      ≈ 1054**. Per-site: read that test's DCQL id rather than search-replacing.
- [ ] `crates/foundry/tests/e2e_full_flow.rs` — the single call site.
- [ ] Add a test asserting the **bare-string** envelope now returns **400**
      (it returned `200 verified:true` before).
- [ ] The SD-JWT happy-path test must assert `verified: true` **and the four
      named `CheckResult`s** (root §4.2 — an omitted check drops out of
      `all(passed)`, so `verified` alone cannot detect a lost check).
- [ ] Existing failure-mode tests (revoked, tampered, replay, unknown tx) keep
      their assertions; only the envelope shape changes.

### 1.7 Verify and commit

- [ ] `cargo test --workspace` — exit 0, zero non-`0 failed` lines.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` — exit 0.
- [ ] `cargo fmt --check` — exit 0.
- [ ] Read real exit codes; do **not** pipe through `head`, which reports
      `head`'s status.
- [ ] Commit.

---

## Task 2 — Documentation and OpenAPI confirmation

**Files:** `crates/foundry-verifier/AGENTS.md`, `crates/foundry-mdoc/AGENTS.md`,
possibly `openapi*.json`

- [ ] `crates/foundry-verifier/AGENTS.md` — Gotcha: `vp_token` is an OpenID4VP
      §8.1 object keyed by DCQL credential query id with array values; format
      comes from the **declared** DCQL format, never the JSON shape. Record the
      exact historical failure signature `mdoc vp_token missing 'mdoc'` so a
      future reader recognises a regression, and state that type-sniffing
      misreports SD-JWT VC as an mdoc error.
- [ ] `crates/foundry-mdoc/AGENTS.md` — Gotcha: the mdoc presentation payload is
      **bespoke** (`{mdoc, device_signature}`, not a base64url `DeviceResponse`)
      and `serialize_session_transcript` is **not** the spec `OpenID4VPHandover`.
      mdoc is not interoperable with real wallets; a green mdoc test proves
      self-consistency only. Name spec §4 defects 2–3.
- [ ] **Verify** whether any OpenAPI schema references the `vp_token` payload
      (grep `openapi.json` / `openapi-wallet.json`). Expected: no. If found,
      regenerate per `crates/foundry/AGENTS.md` (root §6).
- [ ] Re-run all three gates.
- [ ] Commit.

---

## Deviations

Record any departure from this plan here, with reasoning, before proceeding.

- *(none yet)*

---

## Known Limitations Carried Forward

To be restated in the changelog, not silently dropped:

- **mdoc remains non-interoperable** — envelope fixed, payload and
  SessionTranscript not (spec §4 defects 2–3).
- **`check_dcql_match`'s invalid-query branch becomes unreachable from the
  request path** (spec D3); still unit-tested. Real fix: validate `dcql_query`
  at transaction-creation time.
- **`dcql_match` still matches any query of the presented format**, not the
  specifically answered id (spec D4).
- **No drift test for the committed OpenAPI specs** — inherited from the
  predecessor change.