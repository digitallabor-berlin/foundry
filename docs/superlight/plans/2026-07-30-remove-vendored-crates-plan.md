# Remove the Vendored `oid4vci` / `openid4vp` Crates — Implementation Plan

**Spec:** docs/superlight/specs/2026-07-30-remove-vendored-crates-spec.md
**Branch:** superlight/2026-07-30-remove-vendored-crates
**Executed with:** superlight Phase 4 (TDD, inline, no subagents by default)

**Goal:** Delete all three vendored crates, replacing the three `openid4vp`
items foundry actually uses with clean-room foundry-owned code, with no
observable behaviour change.

**Architecture:** Two new foundry-owned units replace the used surface — a
`josekit`-backed JWE encryption helper in `foundry-core` (mirroring the
verifier's existing decrypt path) and a crate-private DCQL wire model in
`foundry-verifier`. Once both are in place and every call site is migrated, the
three vendored directories and their workspace-member entries are removed, then
documentation catches up. Order is strictly replace-then-delete: the workspace
stays green and committable at every task boundary.

## Global Constraints

Copied verbatim from the spec:

- Rust edition 2021, `rust-version = "1.97"` (root `[workspace.package]`).
- No new dependency may be added to any crate. `josekit` (workspace `0.10`),
  `serde`, `serde_json` are all already present where needed.
- Workspace dependency pins are authoritative: `base64 = "0.22"`,
  `josekit = "0.10"`, `thiserror = "2"`, `axum = "0.7"`, `rand = "0.8"`.
- No new error enum anywhere; exactly one new variant (`CryptoError::Jwe`).
- `dcql_model` is declared crate-private (`mod`, not `pub mod`).
- Implementers MUST NOT read `crates/openid4vp/src/core/jwe.rs`,
  `crates/openid4vp/src/core/dcql_query.rs`, or
  `crates/openid4vp/src/core/credential_format/mod.rs`. Requirements come from
  foundry's consuming code, foundry's tests, and OpenID4VP 1.0 §6.
- Public accessor names on the new DCQL types MUST match the names listed in
  spec Component 2 exactly.
- No `serde(deny_unknown_fields)` on any DCQL type.
- `CredentialFormat` MUST have an `Other(String)` catch-all.
- No panics/unwraps in request paths outside `#[cfg(test)]` (root `AGENTS.md`
  §4.1).
- Dependency layering (root `AGENTS.md` §3) must be preserved:
  `foundry-core` depends on no `foundry-*` crate.
- Verification gates, all three, must pass cleanly before completion:
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check`.
- Every task ends on a green workspace test suite and its own commit. The
  workspace must never be left red between task commits.
- Branch: `superlight/2026-07-30-remove-vendored-crates`. No commits to `main`.

**Measured baseline (this branch, commit `c7d6ef4`):** `cargo test --workspace`
→ exit 0, **420 passed, 0 failed**, 46 `test result: ok` lines.
`grep -c '^name = ' Cargo.lock` → **743**.

## File Structure

Created:
- `crates/foundry-core/src/crypto/jwe.rs` — ECDH-ES JWE compact encryption over `josekit`
- `crates/foundry-verifier/src/dcql_model.rs` — DCQL wire model (crate-private)
- `LICENSE` — Apache-2.0 text (severable; see Task 5)

Modified:
- `crates/foundry-core/src/error.rs` — add `CryptoError::Jwe(String)`
- `crates/foundry-core/src/crypto/mod.rs` — register `pub mod jwe;`
- `crates/foundry-wallet/src/actions/verification.rs` — 1 production call site
- `crates/foundry-verifier/src/verify.rs` — 5 test call sites
- `crates/foundry/tests/wallet_verification.rs` — 6 test call sites
- `crates/foundry/tests/e2e_full_flow.rs` — 1 test call site
- `crates/foundry-verifier/src/dcql.rs` — `use` lines + one integer cast
- `crates/foundry-verifier/src/lib.rs` — register `mod dcql_model;`
- `Cargo.toml`, `Cargo.lock`, and 3 crate manifests — dependency/member removal
- 5 `AGENTS.md` files, `README.md`

Deleted:
- `crates/oid4vci/`, `crates/openid4vp/`, `crates/openid4vp-frontend/`
- `docs/VENDORING.md`

---

### Task 1: `foundry-core` JWE encryption helper

**Files:**
- create `crates/foundry-core/src/crypto/jwe.rs`
- modify `crates/foundry-core/src/crypto/mod.rs` (add `pub mod jwe;` beside the
  existing `pub mod signer;` at line 3)
- modify `crates/foundry-core/src/error.rs` (add one variant to `CryptoError`,
  whose existing variants are `KeyRead`, `UnsupportedAlgorithm`, `KeyLoad`,
  `Sign`, `Generation`)

**Interfaces:**
- Consumes: `josekit` (already a `foundry-core` dependency), `serde_json`.
- Produces — later tasks depend on these exact names:
  ```rust
  // crates/foundry-core/src/crypto/jwe.rs
  pub fn encrypt_compact(
      payload: &serde_json::Value,
      recipient_public_jwk: &serde_json::Value,
      alg: &str,
      enc: &str,
  ) -> Result<String, crate::error::CryptoError>

  // crates/foundry-core/src/error.rs, added to CryptoError
  #[error("JWE encryption failed: {0}")]
  Jwe(String),
  ```

**Implementation note (not a spec deviation, a pointer):** the inverse operation
already exists at `crates/foundry-verifier/src/verify.rs:49-53` —
`josekit::jwe::ECDH_ES.decrypter_from_jwk(&jwk)` then
`josekit::jwt::decode_with_decrypter(...)`. Build the encrypt side from the
symmetric pair (`ECDH_ES.encrypter_from_jwk`, `jwt::encode_with_encrypter`) with
`alg` and `enc` set on the JWE header.

**Behaviors to test:**
- Round-trip against the real key shapes — happy path, and the one that matters.
  Generate a P-256 keypair; annotate the **public** JWK with `kid`, `use: "enc"`
  and `alg` exactly as `crates/foundry-verifier/src/request.rs:92-102` does;
  leave the **private** JWK bare; `encrypt_compact(payload, public, "ECDH-ES",
  "A128GCM")`; decrypt with `ECDH_ES.decrypter_from_jwk(bare_private)` +
  `jwt::decode_with_decrypter`; assert the payload survives intact. A
  `kid`-related mismatch here is the single most likely failure mode of this
  whole plan — see spec Component 1.
- Unsupported `enc` value (e.g. `"A999GCM"`) — returns `Err(CryptoError::Jwe)`,
  does not panic.
- Malformed recipient JWK (e.g. `json!({"kty":"EC"})` with no curve/coords) —
  returns `Err`, does not panic.
- Payload with nested JSON survives the round-trip unchanged (guards against
  claim-set flattening).

**Verify:** `cargo test -p foundry-core && cargo clippy -p foundry-core --all-targets -- -D warnings && cargo fmt --check`

- [x] Red — failing test per behavior above
- [x] Green — minimal implementation
- [x] Refactor — clean while green
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 2: Migrate all 13 JWE call sites; drop `openid4vp` from two manifests

**Files:**
- modify `crates/foundry-wallet/src/actions/verification.rs` — line 21 (`use`),
  lines 156-163 (production call site). Preserve both error mappings verbatim:
  `WalletError::MalformedRequestObject(format!("invalid ephemeral jwk: {e}"))`
  and `...(format!("JWE build failed: {e}"))`. The single `encrypt_compact` call
  now covers what were two fallible builder steps, so one of these two messages
  must be chosen for the combined failure — pick `"JWE build failed: {e}"` and
  leave a comment noting the collapse, since `encrypt_compact` no longer
  separates JWK parsing from encryption.
- modify `crates/foundry-verifier/src/verify.rs` — line 206 (`use`), call sites
  at lines 368, 402, 471, 536, 639
- modify `crates/foundry/tests/wallet_verification.rs` — line 25 (`use`), call
  sites at lines 286, 437, 661, 783, 906, 1062
- modify `crates/foundry/tests/e2e_full_flow.rs` — line 25 (`use`), call site at
  line 436
- modify `crates/foundry-wallet/Cargo.toml` — remove `openid4vp` (line 21)
- modify `crates/foundry/Cargo.toml` — remove `openid4vp` from
  `[dev-dependencies]` (line 41)

**Do NOT** remove `openid4vp` from `crates/foundry-verifier/Cargo.toml:12` in
this task — the verifier still needs it for DCQL until Task 3.

**Interfaces:**
- Consumes: `foundry_core::crypto::jwe::encrypt_compact` from Task 1. All three
  affected crates already depend on `foundry-core` (`foundry/Cargo.toml:17`,
  `foundry-verifier/Cargo.toml:9`, `foundry-wallet/Cargo.toml:17`), so no
  manifest additions are needed.
- Produces: nothing new.

Every one of the 13 sites is the same shape and becomes a single call:
```rust
let jwe_str = encrypt_compact(&json!({ "vp_token": presentation }), &ephem_public_jwk, "ECDH-ES", "A128GCM")?;   // or .unwrap() in tests
```

**Behaviors to test:**
- No new tests. The **12 migrated test call sites are themselves the test** —
  every assertion in those tests must pass **unmodified**. Only the JWE
  construction expression changes; if any assertion or expectation needs
  touching, stop: `encrypt_compact` is wire-incompatible and that is a Task 1
  defect, not a test-maintenance chore.
- Confirm `cargo tree -i -p openid4vp` afterwards lists only `foundry-verifier`
  (and `foundry-wallet` transitively through it), no longer `foundry-wallet`
  directly nor `foundry` as a dev-dependency.

**⚠ One of the 13 sites is not covered by the default test run.**
`crates/foundry/tests/e2e_full_flow.rs:483` is annotated `#[ignore]` — it is the
only ignored test in the entire workspace — so `cargo test --workspace` reports
`e2e_full_flow -> 0 passed; 1 ignored` and never executes the JWE call site at
line 436. Migrating that site and running only the default suite would leave it
**unverified**. The verify command below therefore runs the ignored test
explicitly. It spawns a real server on free ports, so it is slower and may need
network-local permissions; if it cannot run in this environment, that is a
**blocker to report**, not a step to skip — say so and stop rather than
claiming 13/13 migrated when only 12 were proven.

**Verify:**
```
cargo test --workspace \
  && cargo test -p foundry --test e2e_full_flow -- --ignored \
  && cargo clippy --workspace --all-targets -- -D warnings \
  && cargo fmt --check
```

- [x] Red — N/A (migration; the 12 existing tests are the guard, and they are
      already green before the change — run them first to confirm the starting
      point, then confirm again after)
- [x] Green — all 13 sites migrated, both manifests trimmed
- [x] Refactor — clean while green
- [x] Verify — run the command, pristine output; 420 passed, 0 failed in the
      default run, **plus** `full_flow_issue_verify_revoke_reverify` passing in
      the `--ignored` run
- [x] Commit

---

### Task 3: DCQL wire model, `dcql.rs` switch, and verifier manifest trim

**Why these are one task, not three:** a crate-private `mod dcql_model` with no
consumers trips `dead_code` under `clippy -D warnings`, so the model cannot be
committed green on its own. Model, call-site switch, and dependency removal
land together.

**Files:**
- create `crates/foundry-verifier/src/dcql_model.rs`
- modify `crates/foundry-verifier/src/lib.rs` — add `mod dcql_model;`
  (crate-private; the existing `pub mod` list is lines 1-6). Do **not** add it
  to the `pub use` block at lines 8-19.
- modify `crates/foundry-verifier/src/dcql.rs` — four edits, and only these:
  1. `use` lines 15-16 → the new `crate::dcql_model` types.
  2. `PresentedFormat::matches` arms at lines 30-31 — the variant rename
     `ClaimFormatDesignation::MsoMDoc` → `CredentialFormat::MsoMdoc` (note the
     lower-case `d`) and `ClaimFormatDesignation::DcSdJwt` →
     `CredentialFormat::DcSdJwt`.
  3. The inline `use ... as V` at line 121 → `ClaimValue as V`, and the integer
     comparison becomes `found.as_i64() == Some(*i)` (no `as i64` cast, since
     `ClaimValue::Integer` is `i64`).
  4. The three `match` arms in `resolve_path` (lines ~148-155) and `path_debug`
     (lines ~159-168) — variant renames `String` → `String`, `Integer` →
     `Index`, `Null` → `Wildcard`.

  Nothing else in this file changes: no logic, no error strings, no test
  fixtures.
- modify `crates/foundry-verifier/Cargo.toml` — remove `openid4vp` (line 12)

**Interfaces:**
- Consumes: `serde`, `serde_json` (both already dependencies).
- Produces — these names are consumed by `dcql.rs` and MUST match:
  ```rust
  DcqlQuery::credentials(&self) -> &[DcqlCredentialQuery]
  DcqlCredentialQuery::id(&self) -> &str
  DcqlCredentialQuery::format(&self) -> &CredentialFormat
  DcqlCredentialQuery::meta(&self) -> &serde_json::Value   // Value::Null when absent
  DcqlCredentialQuery::claims(&self) -> Option<&Vec<DcqlClaimsQuery>>
  DcqlClaimsQuery::path(&self) -> &[ClaimsPathSegment]
  DcqlClaimsQuery::values(&self) -> Option<&Vec<ClaimValue>>
  enum CredentialFormat  { DcSdJwt, MsoMdoc, Other(String) }        // "dc+sd-jwt", "mso_mdoc"
  enum ClaimsPathSegment { String(String), Index(u64), Wildcard }   // untagged
  enum ClaimValue        { String(String), Integer(i64), Boolean(bool) } // untagged
  ```
  `dcql.rs` currently matches `DcqlCredentialClaimsQueryPath::{String, Integer,
  Null}`; the replacement variant names are `String`, `Index`, `Wildcard`, so
  the three `match` arms in `resolve_path` and `path_debug` are renamed
  accordingly. `Wildcard` keeps today's fail-closed behaviour: `resolve_path`
  returns `None`.

**Behaviors to test:**
- The existing `#[cfg(test)] mod tests` block in `dcql.rs` (lines ~175-248,
  real DCQL JSON fixtures) passes **unmodified**. This is the conformance
  guard — if a fixture needs editing, the model is wrong.
- `format: "some+unknown-format"` deserializes to `CredentialFormat::Other` and
  causes that credential query to be **skipped**, yielding
  `"no credential query in the DCQL query matches the presented credential
  format"` — *not* a deserialization failure. Regression guard for the most
  dangerous possible slip in this task.
- Unknown object members anywhere in the query are ignored, not rejected.
- `ClaimsPathSegment` round-trips all three JSON shapes: `"name"`, `0`, `null`.
- `ClaimValue` round-trips `"x"`, `42`, `true`; integer comparison matches an
  `i64` claim value.
- Credential query with no `claims` member deserializes; with no `meta` member
  deserializes and `meta()` yields `Value::Null` so `.get(..)` returns `None`.
- A `values` constraint that does not match yields the existing
  `"value ... not in requested values"` failure detail.

**Verify:** `cargo test -p foundry-verifier && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

- [x] Red — failing test per behavior above
- [x] Green — minimal implementation
- [x] Refactor — clean while green
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 4: Delete the three vendored crates

**Files:**
- modify `Cargo.toml` — remove members `"crates/oid4vci"`,
  `"crates/openid4vp"`, `"crates/openid4vp-frontend"` (lines 4-6 of the
  `members` array)
- delete `crates/oid4vci/`, `crates/openid4vp/`, `crates/openid4vp-frontend/`
  (use `git rm -r`)
- regenerate `Cargo.lock`

**Interfaces:** none produced or consumed. By this point no `foundry-*` crate
references any vendored crate.

**Behaviors to test:** no new unit tests — this task's verification is the
compiler and the dependency graph. Required evidence, all four:
- `cargo test --workspace` green with **0 failed**. The total pass count drops
  below 420 because the vendored crates' own tests go away with them — that is
  expected and correct. The invariant that matters is stricter and must be
  checked directly: **no foundry-owned test target's pass count changes.**
  Compare per-target counts against the baseline rather than eyeballing the
  total, e.g.
  `cargo test --workspace 2>&1 | grep -B1 'test result:'` before and after, and
  confirm every `foundry*` target is identical. A foundry test silently
  disappearing (e.g. a whole test file failing to compile and being skipped) is
  exactly the failure this check exists to catch, and a shrinking total would
  otherwise hide it. Record the new total in the Progress Log.
- `cargo tree -i -p ssi`, `cargo tree -i -p oid4vci`, `cargo tree -i -p open-auth2`
  each fail with "package ... not found".
- `grep -c '^name = ' Cargo.lock` is materially below **743**. Record the number.
- `grep -rn 'oid4vci\|openid4vp' --include='*.rs' crates/` returns hits only
  inside `openid4vp://` URI string literals
  (`crates/foundry-verifier/src/request.rs:316,516`,
  `crates/foundry-wallet/src/actions/request_source.rs`).
- The `#[ignore]`d e2e test still passes when run explicitly (it exercises the
  full issue → verify → revoke → reverify path across both replacements).

**Expected total after deletion:** 420 − 24 (`oid4vci`) − 86 (`openid4vp`) − 3
(`openid4vp` doc-tests) = **307 passed**. A different number is not
automatically wrong, but it must be explained against the per-target baseline
below before the task is called done.

**Verify:**
```
cargo test --workspace \
  && cargo test -p foundry --test e2e_full_flow -- --ignored \
  && cargo clippy --workspace --all-targets -- -D warnings \
  && cargo fmt --check
```

- [x] Red — N/A (deletion; the gates and the four evidence checks are the test)
- [x] Green — members trimmed, directories deleted, lockfile regenerated
- [x] Refactor — N/A
- [x] Verify — run the command plus all four evidence checks, record the numbers
- [x] Commit

---

### Task 5: Documentation, routing tables, and LICENSE

**Files:**
- modify root `AGENTS.md` — delete the three vendored rows from the §2 routing
  table (lines 35-37) and the vendored-crates paragraph in §3 (line 63)
- modify `README.md` — delete the three vendored crate rows (lines 18-20).
  **Leave line 269 alone**: `openid4vp_uri`/`request_uri` is protocol
  vocabulary, not a crate reference.
- modify `crates/foundry-core/AGENTS.md` — add `crypto/jwe.rs` to the module map
- modify `crates/foundry-verifier/AGENTS.md` — line 18 currently names
  `openid4vp` "(for `DcqlQuery` / `ClaimFormatDesignation`)"; replace with the
  crate-private `dcql_model` module and add it to the module map
- modify `crates/foundry-wallet/AGENTS.md` — line 22, drop `vendored openid4vp`
- modify `crates/foundry/AGENTS.md` — line 20, drop `vendored openid4vp`
- modify `crates/foundry/tests/AGENTS.md` — line 59, drop `vendored openid4vp`
  from the dev-dependency list and name `foundry_core::crypto::jwe` instead
- modify `crates/foundry-issuer/src/metadata.rs:3` — **added during Task 4**:
  a stale doc comment still refers to "the vendored `oid4vci` crate's generic
  types". Reword to drop the reference to a crate that no longer exists.
- delete `docs/VENDORING.md`
- create `LICENSE` — Apache License 2.0 text, matching
  `license = "Apache-2.0"` in `[workspace.package]`.
  **Severable:** if the user has dropped this, skip it and note the skip in the
  Progress Log; nothing else in this task depends on it.

**Interfaces:** none.

**Behaviors to test:** documentation, so verification is grep-based rather than
test-based:
- `grep -rn 'oid4vci\|openid4vp' --include='*.md' .` returns hits only in
  `docs/superpowers/plans/*.md` (historical records, deliberately untouched),
  `docs/superlight/**` (this spec/plan/changelog, which discuss them by
  necessity), and any `openid4vp://` protocol-URI mentions.
- `grep -rn 'VENDORING' .` returns no live references outside
  `docs/superlight/**`.
- Every `AGENTS.md` link target still resolves (no link to a deleted
  `crates/oid4vci/AGENTS.md` or `crates/openid4vp/AGENTS.md`).

**Verify:** `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check` plus the three grep checks above

- [ ] Red — N/A (documentation)
- [ ] Green — all files updated, `docs/VENDORING.md` deleted, `LICENSE` added
- [ ] Refactor — N/A
- [ ] Verify — gates plus the three grep checks
- [ ] Commit

---

## Appendix — Per-target test baseline

Measured on this branch at commit `c7d6ef4`, before any change. Task 4's
invariant is that **every `foundry*` row below is unchanged** after the vendored
crates are deleted; only the three vendored rows disappear.

| Target | Passed |
|---|---|
| `foundry` (lib) | 12 |
| `foundry` (main) | 0 |
| `authorization_code_flow` | 2 |
| `cli_openapi` | 1 |
| `cli_pki` | 2 |
| `cli_status_list` | 1 |
| `console` | 3 |
| `e2e_full_flow` | 0 (**1 ignored** — see Task 2) |
| `health` | 1 |
| `issuer_offers` | 4 |
| `openapi_endpoints` | 8 |
| `quickstart` | 1 |
| `sweeper` | 1 |
| `wallet_issuance` | 9 |
| `wallet_metadata` | 2 |
| `wallet_status_list_route` | 3 |
| `wallet_verification` | 9 |
| `foundry_core` (lib) | 58 |
| `config_load` | 2 |
| `storage_sqlite` | 1 |
| `validate_key_material` | 4 |
| `foundry_issuer` (lib) | 76 |
| `foundry_mdoc` (lib) | 2 |
| `mdoc_tests` | 2 |
| `foundry_sd_jwt_vc` (lib) | 4 |
| `sdjwt_tests` | 5 |
| `foundry_verifier` (lib) | 35 |
| `foundry_wallet` (lib) | 48 |
| `foundry_wallet` (main) | 0 |
| `cli_headless` | 4 |
| `issuance` | 3 |
| `support_smoke` | 1 |
| `verification` | 3 |
| ~~`oid4vci`~~ | ~~24~~ — removed by Task 4 |
| ~~`openid4vp`~~ | ~~86~~ — removed by Task 4 |
| ~~`openid4vp_frontend`~~ | ~~0~~ — removed by Task 4 |
| ~~`openid4vp` doc-tests~~ | ~~3~~ — removed by Task 4 |
| **Total** | **420** |

All other doc-test targets contribute 0.

## Progress Log

Append one line per completed task: date, task, commit SHA.

- 2026-07-30 — Task 1 (`foundry-core` JWE helper) — commit `ba50ebb`.
  Added `CryptoError::Jwe(String)` and `foundry_core::crypto::jwe::encrypt_compact`
  (7 new tests). **The feared `kid` asymmetry is a non-issue:** encrypting to
  the annotated public JWK (with `kid`/`use`/`alg`) and decrypting with the bare
  private JWK round-trips cleanly — now proven by
  `round_trips_annotated_public_to_bare_private` rather than assumed.
  Design decision made during implementation: `encrypt_compact` **validates**
  `alg == "ECDH-ES"` and rejects anything else, rather than accepting the
  parameter and emitting a header that misdescribes the ciphertext. `enc` is
  passed through to josekit, which rejects unknown values.
  Gates: `cargo test -p foundry-core` 65 passed / 0 failed;
  `cargo clippy -p foundry-core --all-targets -- -D warnings` 0 warnings;
  `cargo fmt --check` clean; `cargo test --workspace` **427 passed / 0 failed**
  (baseline 420 + 7 new).
- 2026-07-30 — Task 2 (migrate all 13 JWE call sites) — commit `03b3a4a`.
  12 test sites migrated by a script with hard per-file `assert n == expected`
  counts (verify.rs 5, wallet_verification.rs 6, e2e_full_flow.rs 1); the 1
  production site (`foundry-wallet/src/actions/verification.rs:156`) by hand
  because its error mapping differs. `openid4vp` dropped from
  `foundry-wallet/Cargo.toml` and `foundry/Cargo.toml`; still present in
  `foundry-verifier/Cargo.toml` until Task 3.
  **Deviation from the plan, deliberate:** the wallet's two distinct error
  messages (`"invalid ephemeral jwk: {e}"` on JWK parse, `"JWE build failed:
  {e}"` on build) collapse into the latter, since `encrypt_compact` performs
  both steps. josekit's inner message still names the real cause; a code comment
  records the collapse. Splitting `encrypt_compact` in two to preserve both
  strings was judged not worth it for one call site.
  **No test assertion was altered** — the guard held, which is the actual
  evidence that `encrypt_compact` is wire-compatible with the verifier's
  unmodified josekit decrypt path.
  Gates: `cargo test --workspace` **427 passed / 0 failed**, per-target counts
  identical to the baseline table below (`wallet_verification` 9,
  `foundry_verifier` 35, `foundry_wallet` 48, `foundry_core` 65);
  `cargo test -p foundry --test e2e_full_flow -- --ignored` **1 passed** (the
  sole coverage of the 13th call site — it exercises issue → verify → revoke →
  reverify over real HTTP); `cargo clippy --workspace --all-targets -- -D
  warnings` 0 diagnostics; `cargo fmt --check` clean.
- 2026-07-30 — Task 3 (clean-room DCQL model + `dcql.rs` switch) — commit
  `9f912f7`. `foundry-verifier` no longer depends on `openid4vp`, so **no
  foundry crate does**. Clean-room honoured: the vendored `dcql_query.rs` /
  `credential_format/mod.rs` were not opened; requirements came from
  `dcql.rs`, our fixtures, and OpenID4VP 1.0 §6/§7 (fetched and indexed).
  **Three additions the plan did not specify**, each found by reading our own
  fixtures rather than assumed, each spec-mandated and fail-closed:
  non-empty `credentials`, non-empty `claims[].path`, non-empty
  `claims[].values`. The first is the important one — `dcql.rs`'s
  `unparseable_query_fails_closed` test carries the comment "NonEmptyVec
  rejects empty -> parse error" and `config.yaml:56` ships
  `dcql: { credentials: [] }`, so a plain `Vec` would have kept the assertion
  true while silently changing the failure mode from *parse error* to *matched
  nothing*. RED was taken on exactly these three before adding validation.
  Two further implementation decisions: `ClaimValue` declares `Boolean` before
  `Integer` before `String` because `serde(untagged)` resolves in declaration
  order and JSON booleans must not be coerced (guarded by
  `boolean_claim_value_is_not_coerced`); `ClaimsPathSegment::Index` is `u64`
  so `resolve_path` casts with `*i as usize` for `serde_json`'s `Index` impl.
  **The 7 existing `dcql.rs` conformance tests pass unmodified** — verified by
  grepping the diff for changed assertion/fixture lines and finding none.
  13 new model tests, including both OpenID4VP Appendix D examples verbatim.
  Gates: `cargo test --workspace` **440 passed / 0 failed** (427 + 13);
  `cargo test -p foundry --test e2e_full_flow -- --ignored` **1 passed**;
  `cargo clippy --workspace --all-targets -- -D warnings` 0 diagnostics;
  `cargo fmt --check` clean.
- 2026-07-30 — Task 4 (delete the three vendored crates) — commit `89f89e6`.
  All four required evidence checks recorded:
  1. `cargo test --workspace` **327 passed / 0 failed**. Every foundry-owned
     target matches the per-target baseline below except the two deliberately
     grown (`foundry_core` 58→65, `foundry_verifier` 35→48). Arithmetic is
     exact: 440 − 24 − 86 − 3 = 327.
  2. `cargo tree -i -p <x>` reports "did not match any packages" for **all** of
     `ssi`, `oid4vci`, `openid4vp`, `openid4vp-frontend`, `open-auth2`,
     `json-ld`, `isomdl`, `jiff`, `dashmap`, `qrcode`.
  3. `Cargo.lock` **743 → 385 packages (−358, −48%)**.
  4. No `.rs` reference outside `openid4vp://` URI literals and the
     `openid4vp_uri` response field — **with one exception found here**: a
     stale doc comment at `crates/foundry-issuer/src/metadata.rs:3` referring
     to "the vendored `oid4vci` crate's generic types". Carried into Task 5.
  Plus the `#[ignore]`d e2e test still passing.
  Gates: `cargo clippy --workspace --all-targets -- -D warnings` 0
  diagnostics; `cargo fmt --check` clean.