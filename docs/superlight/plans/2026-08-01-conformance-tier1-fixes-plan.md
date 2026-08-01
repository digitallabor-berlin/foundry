# Conformance Tier 1 Gap Fixes — Implementation Plan

**Spec:** [`docs/superlight/specs/2026-08-01-conformance-tier1-fixes-spec.md`](../specs/2026-08-01-conformance-tier1-fixes-spec.md)
**Branch:** `superlight/2026-08-01-conformance-tier1-fixes`
**Executed with:** superlight Phase 4 (TDD, inline, no subagents by default)

**Goal:** Close the five Tier 1 conformance gaps (GAP-HAIP-04, GAP-VCI-03,
GAP-VCI-01, GAP-HAIP-06, GAP-VP-07) and reconcile the conformance report with
the resulting code.

**Architecture:** Five independent fixes across `foundry-issuer` (three),
`foundry-verifier` + `foundry-core` + `foundry-sd-jwt-vc` (one), and a
cross-cutting bookkeeping obligation folded into every task. Each gap already
has an `#[ignore]`d test asserting the correct behaviour; those tests are the
green targets. Because `conformance_report.rs`'s consistency checks assert
bidirectionally and run on every commit, each task must land its code change,
its clause-verdict flip, its register-row deletion, its `#[ignore]` removal and
its Summary-count update **as one atomic commit**.

**Global Constraints** (copied verbatim from the spec):

- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside
  `#[cfg(test)]` in `foundry-issuer`, `foundry-verifier`, `foundry::server`
  (root `AGENTS.md` §4.1).
- **Every `#[tracing::instrument]` MUST carry `skip_all`** (root `AGENTS.md`
  §4.5); enforced by `crates/foundry/tests/instrumentation_hygiene.rs`.
- **Never log** attestation JWTs, private/ephemeral JWKs, access tokens,
  `c_nonce` values, pre-authorized codes or transaction codes. Public keys only
  as RFC 7638 thumbprints (root `AGENTS.md` §4.5); enforced by
  `crates/foundry/tests/logging_redaction.rs`.
- **`verified` MUST equal `checks.iter().all(|c| c.passed)`** — never hardcoded
  (root `AGENTS.md` §4.2).
- **Policy vs structural vs network** error classification unchanged: policy →
  HTTP 200 `verified: false`; structural/crypto → 400; network → 502 (root
  `AGENTS.md` §4.3). A new `IssuanceError`/`VerificationError` variant without a
  matching arm in `crates/foundry/src/server.rs` silently yields HTTP 500.
- **Dependency layering** is one-directional; `foundry-core` depends on no
  `foundry-*` crate (root `AGENTS.md` §3).
- **Protocol changes cite their spec section in a code comment** (root
  `AGENTS.md` §4.4). Governing texts: OpenID4VCI L396 (single-use
  pre-authorized code), L976 (base64url binary credential), L2555 + Appendix E
  L2564/L2600 (Wallet Attestation), HAIP L225 (x5c), HAIP L329 (unique status
  index), OpenID4VP L618/L2543/L3179 (DC API Origin audience).
- **`conformance_report.rs`'s 11 consistency checks stay green** at every commit
  — not only at the end.
- **Existing audit gap tests are un-`#[ignore]`d, never rewritten.**
  *Amended in Task 3 — see the note there; the one forced exception is scoped
  and justified.*
- **OpenAPI:** `openapi.json` / `openapi-wallet.json` regenerated if any
  endpoint shape changes (root `AGENTS.md` §6). No endpoint shape change is
  expected; this is a verification step, not a deliverable.
- **Gates:** `cargo test --workspace`, `cargo test --workspace --no-fail-fast --
  --ignored` (only still-open gaps may fail), `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo fmt --check` (root `AGENTS.md` §5).

## File Structure

| Path | Responsibility in this work |
|---|---|
| `crates/foundry-issuer/src/credential.rs` | Task 1 — the `mso_mdoc` arm's base64 engine (`:208`) |
| `crates/foundry-issuer/src/transaction.rs` | Task 2 — new `invalidate_pre_authorized_code` beside `invalidate_authorization_code` (`:177`) |
| `crates/foundry-issuer/src/token.rs` | Task 2 — burn the code in `handle_pre_authorized_code_grant` (`:77`); Task 4 — attestation plumbing in `handle_token_request` (`:46`) |
| `crates/foundry-issuer/src/status_index.rs` | Task 3 — `allocate_status_index` keyed on list id; the misleading unit test at `:82` |
| `crates/foundry-issuer/src/create_offer.rs` | Task 3 — pass the list id at `:106` |
| `crates/foundry-issuer/src/attestation.rs` | Task 4 — `WalletAttestationVerifier` trait + real validation, modelled on `verify_key_attestation_jwt` (`:47`) |
| `crates/foundry/src/server.rs` | Task 4 — pass `&config.issuer.wallet_attestation` at `:435` |
| `crates/foundry-core/src/config/model.rs` | Task 5 — `verifier.dc_api_expected_origins` on `VerifierConfig` (`:284`) |
| `crates/foundry-sd-jwt-vc/src/verifier.rs` | Task 5 — `verify_sd_jwt_vc` audience becomes a slice (`:88`) |
| `crates/foundry-verifier/src/verify.rs` | Task 5 — transport-dependent expected audience (`:384`) |
| `docs/conformance/openid4vc-conformance.md` | Every task — clause verdicts, register rows, Summary counts |
| `crates/foundry-issuer/tests/conformance_vci.rs` | Tasks 1–4 — un-`#[ignore]` the VCI/HAIP gap tests; new GAP-VCI-14 test |
| `crates/foundry-verifier/src/verify.rs` (inline `#[cfg(test)]`) | Task 5 — **this is where the GAP-VP-07 test lives** (`:1625`), not in `conformance_vp.rs`; it reuses that module's fixture harness |
| `crates/foundry-verifier/tests/conformance_vp.rs` | Task 5 — optional home for the new transport-matrix tests if they do not need `verify.rs`'s private fixtures |
| `config.yaml`, `README.md` | Task 5 — document the new verifier setting |

---

### Task 1: GAP-VCI-03 — base64url-encode the mdoc credential

Deliberately first: the smallest possible code change, so it proves the
per-task bookkeeping loop (verdict flip + register deletion + un-ignore +
Summary recount, all in one commit) works before a larger fix depends on it.

**Files:** modify `crates/foundry-issuer/src/credential.rs` (`:208`),
`docs/conformance/openid4vc-conformance.md`;
test `crates/foundry-issuer/tests/conformance_vci.rs` (`:586`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: the established bookkeeping recipe every later task repeats.

**Behaviors to test:**
- An issued `mso_mdoc` credential string decodes under `URL_SAFE_NO_PAD` — happy path
- The string contains none of `+`, `/`, `=` — edge case (the characters that break a base64url-only decoder)

**Report bookkeeping:** VCI-0071, VCI-0176 → `conforming` (cite the code and the
now-passing test); delete the GAP-VCI-03 register row; remove the `#[ignore]`
from `vci_0071_mdoc_credential_string_is_base64url_encoded`; recount the
OpenID4VCI Summary row.

**Verify:** `cargo test -p foundry-issuer && cargo test -p foundry --test conformance_report`

- [ ] Red — un-`#[ignore]` the gap test, confirm it fails on the standard-base64 output
- [ ] Green — switch the encoder to `B64URL`, with a comment citing OpenID4VCI L976
- [ ] Refactor — clean while green
- [ ] Bookkeeping — verdicts, register row, Summary counts, in this same change
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 2: GAP-VCI-01 — make the pre-authorized code single-use

**Files:** modify `crates/foundry-issuer/src/transaction.rs` (new
`invalidate_pre_authorized_code`), `crates/foundry-issuer/src/token.rs`
(`handle_pre_authorized_code_grant`),
`docs/conformance/openid4vc-conformance.md`;
test `crates/foundry-issuer/tests/conformance_vci.rs` (`:237`), plus inline
`#[cfg(test)]` in `token.rs`

**Interfaces:**
- Consumes: the Task 1 bookkeeping recipe.
- Produces: `pub async fn invalidate_pre_authorized_code(storage: &dyn Storage, code: &str) -> Result<(), IssuanceError>` — exported from `transaction.rs`, mirroring `invalidate_authorization_code`.

**Behaviors to test:**
- A first `/token` call with a valid `pre-authorized_code` succeeds — happy path
- A second call with the same code fails with `InvalidGrant` — the gap
- A call with the **wrong** `tx_code` does not burn the code, and the legitimate holder still succeeds afterwards — edge case, mirrors the existing `authorization_code` reasoning at `token.rs:158`
- `tx.pre_authorized_code` is `None` after minting, so `save_transaction_with_indices` cannot resurrect the `PRE_AUTH_NS` index — edge case

**Report bookkeeping:** VCI-0003, VCI-0012 → `conforming`; delete the
GAP-VCI-01 register row; remove the `#[ignore]` from
`vci_0012_pre_authorized_code_grant_rejects_replay_after_token_issuance`;
recount OpenID4VCI.

**Verify:** `cargo test -p foundry-issuer && cargo test -p foundry --test conformance_report`

- [ ] Red — un-`#[ignore]` the gap test; add the wrong-`tx_code`-does-not-burn test and confirm both fail for the right reasons
- [ ] Green — add `invalidate_pre_authorized_code`, call it after `tx_code` validation, clear the field
- [ ] Refactor — clean while green
- [ ] Bookkeeping — verdicts, register row, Summary counts
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 3: GAP-HAIP-06 — deduplicate status indices against the physical list

**Files:** modify `crates/foundry-issuer/src/status_index.rs`,
`crates/foundry-issuer/src/create_offer.rs` (`:106`),
`docs/conformance/openid4vc-conformance.md`;
test `crates/foundry-issuer/tests/conformance_vci.rs` (`:1941`), plus inline
`#[cfg(test)]` in `status_index.rs`

**Interfaces:**
- Consumes: the Task 1 bookkeeping recipe.
- Produces: `allocate_status_index(storage: &dyn Storage, list_id: &str, credential_type_id: &str, list_size: u64) -> Result<u64, IssuanceError>` — the used-marker key becomes `{list_id}:{idx}`; `credential_type_id` is retained for the `tracing` field and the `StatusListExhausted` payload only.

**Two traps this task must handle — do not skip either:**

1. **A live test currently asserts the bug.**
   `status_index.rs`'s `different_credential_types_do_not_collide` (`:82`) is
   **not** `#[ignore]`d and asserts `pid_idx == 0 && mdl_idx == 0`, with a
   comment claiming "no cross-type collision" because the key includes
   `credential_type_id`. That is precisely the defect. The test must be
   rewritten and renamed to assert the post-fix invariant; leaving it would
   simply fail, and "fixing" it by loosening the assertion would re-enshrine the
   bug.

2. **The GAP-HAIP-06 test cannot pass as literally written.** It calls
   `allocate_status_index(.., 1)` twice and `.unwrap()`s both, then asserts
   `assert_ne!(pid_idx, mdl_idx)`. Once both draws share one list of size 1,
   the *second* call correctly returns `StatusListExhausted` and the `.unwrap()`
   panics — the test fails even though the code is right. This is the scoped
   exception to the "never rewrite a gap test" constraint: change `list_size`
   from `1` to `2` and pass the shared list id, so both allocations succeed and
   the `assert_ne!` still measures exactly what it was written to measure. The
   assertion and its intent are preserved; only the arguments change, and the
   change is forced by the signature. Record the reason in the test's doc
   comment.

**Behaviors to test:**
- Two different `credential_type_id`s allocating against the same list receive **different** indices — the gap
- With `list_size = 1`, a second allocation against the same list exhausts rather than colliding — edge case
- A single allocation still lands within `[0, list_size)` — happy path, existing coverage
- `list_size = 0` still errors — edge case, existing coverage

**Report bookkeeping:** HAIP-0081 → `conforming`; delete the GAP-HAIP-06
register row; remove the `#[ignore]` from
`gap_haip_06_status_index_can_collide_across_credential_types_sharing_one_list`;
recount the HAIP Summary row.

**Verify:** `cargo test -p foundry-issuer && cargo test -p foundry --test conformance_report`

- [ ] Red — un-`#[ignore]` the gap test with corrected arguments; confirm it fails on the shared-list collision
- [ ] Green — key the used-marker on `list_id`; pass `"1"` from `create_offer`
- [ ] Rewrite `different_credential_types_do_not_collide` to assert the post-fix invariant, renamed accordingly
- [ ] Refactor — reword `StatusListExhausted` so it no longer implies a per-type list
- [ ] Bookkeeping — verdict, register row, Summary counts
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 4: GAP-HAIP-04 — cryptographically validate the Wallet Attestation

The largest task, and the only one whose signature change ripples widely:
`handle_token_request` has **22 call sites**, one in production
(`server.rs:435`) and the rest in tests across `token.rs` and
`conformance_vci.rs`. Budget for that churn rather than being surprised by it.

**Files:** modify `crates/foundry-issuer/src/attestation.rs`,
`crates/foundry-issuer/src/token.rs`, `crates/foundry/src/server.rs` (`:435`),
`docs/conformance/openid4vc-conformance.md`;
test `crates/foundry-issuer/tests/conformance_vci.rs` (`:787`), plus inline
`#[cfg(test)]` in `attestation.rs`

**Interfaces:**
- Consumes: the Task 1 bookkeeping recipe.
- Produces:
  - `WalletAttestationVerifier::verify_wallet_attestation(&self, mode: Mode, attestation_header: Option<&str>, trust_store: &TrustStore, now_unix: i64) -> Result<(), IssuanceError>`
  - `handle_token_request(storage, req, wallet_attestation: &AttestationMode, attestation_header, now_unix)` — the `attestation_mode: Mode` parameter is replaced.
  - A test helper for constructing an `AttestationMode` from a bare `Mode`, so the 21 test call sites stay readable.

**Behaviors to test:**
- A validly signed, trust-anchored attestation is accepted — happy path
- An arbitrary non-JWT string is rejected — the gap (this is the bypass)
- A JWT signed by an untrusted anchor is rejected — edge case
- `alg: none` and `alg: HS256` are rejected — edge case
- A missing or empty `x5c` header is rejected — edge case (HAIP L225)
- A wrong `typ` is rejected — edge case
- An expired attestation is rejected — edge case
- `Mode::Optional` validates a present header but tolerates absence — edge case
- `Mode::Disabled` skips both — edge case
- `Mode::Required` still rejects absence — existing coverage, must not regress

**Report bookkeeping:** HAIP-0031 → `conforming`. **HAIP-0088 stays `gap`**,
re-cited to the new GAP-VCI-14. Append **VCI-0231** (L2555, issuer MUST verify
the attestation is signed by a trusted issuer) → `conforming`, and **VCI-0232**
(issuer-side PoP verification) → `gap` → new **GAP-VCI-14** (Important) with a
new `#[ignore]`d test. Delete the GAP-HAIP-04 register row, add the GAP-VCI-14
row. Add the Identifiers note that late-added clauses append rather than
renumber. Recount the OpenID4VCI and HAIP Summary rows (VCI total 230 → 232).

**Verify:** `cargo test -p foundry-issuer && cargo test -p foundry && cargo test -p foundry --test conformance_report`

- [ ] Red — un-`#[ignore]` the gap test, confirm the arbitrary-string bypass
- [ ] Green — implement validation modelled on `verify_key_attestation_jwt`; thread `&AttestationMode` through `handle_token_request` and `server.rs`
- [ ] Refactor — factor whatever `verify_key_attestation_jwt` and the new path genuinely share; do not force a shared abstraction where the claim sets differ
- [ ] Add the GAP-VCI-14 `#[ignore]`d PoP test
- [ ] Bookkeeping — verdicts, two new clauses, register add + delete, Identifiers note, Summary counts
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 5: GAP-VP-07 — accept the Origin-prefixed audience over the DC API

**Files:** modify `crates/foundry-core/src/config/model.rs` (`:284`),
`crates/foundry-sd-jwt-vc/src/verifier.rs` (`:88`),
`crates/foundry-verifier/src/verify.rs` (`:384`), `config.yaml`, `README.md`,
`docs/conformance/openid4vc-conformance.md`;
test `crates/foundry-verifier/src/verify.rs` inline `#[cfg(test)]` (`:1625`)

**Interfaces:**
- Consumes: the Task 1 bookkeeping recipe.
- Produces:
  - `VerifierConfig.dc_api_expected_origins: Vec<String>` (`#[serde(default)]`).
  - `verify_sd_jwt_vc(presentation, trust_store, expected_audiences: &[String], expected_nonce, now_unix)` — audience becomes a slice; the eight existing call sites pass a one-element slice.

**Behaviors to test:**
- A `dc_api` presentation whose KB-JWT `aud` is `origin:` + a configured origin verifies — the gap
- With no configured origins, the `public_base_url`-derived origin is accepted — happy path fallback
- Trailing-slash and no-trailing-slash `aud` forms both match — edge case (the spec/RFC 6454 discrepancy)
- A `request_uri` transport still requires `x509_san_dns:<host>` and rejects an Origin-prefixed audience — edge case, guards against over-broadening
- A `dc_api` presentation with an audience matching *neither* the configured origins nor the fallback is rejected — edge case

**Report bookkeeping:** VP-0265 → `conforming`. **VP-0209 stays `gap`**,
re-cited to GAP-VP-06 with its `Test` column repointed to that gap's handover
test, because it covers all DC API responses and mdoc's binding is still broken.
Delete the GAP-VP-07 register row; remove the `#[ignore]` from
`gap_vp_07_dc_api_transport_never_accepts_origin_prefixed_kb_jwt_audience`;
recount the OpenID4VP Summary row.

**Verify:** `cargo test --workspace && cargo test -p foundry --test conformance_report`

- [ ] Red — un-`#[ignore]` the gap test, confirm the Origin-prefixed audience is rejected
- [ ] Green — add the config field, widen the audience to a slice, branch on `tx.transport`, normalize trailing slashes with a comment citing OpenID4VP L2543
- [ ] Refactor — clean while green; log the fallback so it is diagnosable
- [ ] Document the new setting in `config.yaml` and `README.md`
- [ ] Bookkeeping — verdicts, register row, Summary counts
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 6: Reconciliation

**Files:** verify only; modify `openapi.json` / `openapi-wallet.json` and
`docs/conformance/openid4vc-conformance.md` only if the checks below say so

**Interfaces:**
- Consumes: every preceding task.
- Produces: the evidence Phase 5 reports against.

**Behaviors to test:**
- The four gates all pass — happy path
- `cargo test --workspace --no-fail-fast -- --ignored` fails on **exactly** the expected set and nothing else — edge case; a gap test that now passes while still `#[ignore]`d is a bookkeeping error, not a bonus

**The expected `--ignored` arithmetic, stated so it can be checked rather than
eyeballed.** Gaps and gap *tests* are not 1:1 — GAP-VCI-05 is cited by two
tests. Before this work: 26 gaps, 27 failing gap tests. This work closes five
gaps (one test each: `haip_0031_…`, `vci_0071_…`, `vci_0012_…`,
`gap_haip_06_…`, `gap_vp_07_…`) and adds one (`GAP-VCI-14`). So the end state is
**22 open gaps and 23 still-`#[ignore]`d failing gap tests**. Separately,
`full_flow_issue_verify_revoke_reverify` is an unrelated pre-existing
`#[ignore]`d E2E test that *passes* under `--ignored`; it is not a gap test and
must not be counted as one.
- The OpenAPI specs are unchanged, or regenerated if a schema moved — edge case (`Config` gained a field; no endpoint shape should have changed)
- The report's Status line and gap counts read correctly for a 22-gap register

**Verify:** `cargo test --workspace && cargo test --workspace --no-fail-fast -- --ignored && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

- [ ] Run all four gates, capture the output
- [ ] Confirm the still-failing `--ignored` set is exactly the expected 22
- [ ] Verify the OpenAPI specs
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

## Progress Log

*Append one line per completed task: date, task, commit SHA.*

- 2026-08-01 — Spec — `2ec0acb`