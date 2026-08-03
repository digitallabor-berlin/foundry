# Remove the Vendored `oid4vci` / `openid4vp` / `openid4vp-frontend` Crates

> Migrated from `docs/superpowers/changes/2026-07-30-remove-vendored-crates.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Date:** 2026-07-30
**Type:** refactor
**Branch:** `superlight/2026-07-30-remove-vendored-crates` (14 commits, base `6820119`)
**Spec:** [`docs/superpowers/specs/2026-07-30-remove-vendored-crates-spec.md`](../specs/2026-07-30-remove-vendored-crates-spec.md)
**Plan:** [`docs/superpowers/plans/2026-07-30-remove-vendored-crates-plan.md`](../plans/2026-07-30-remove-vendored-crates-plan.md)

## Problem

The workspace vendored three crates copied from Spruce upstream on 2026-07-17 —
~13,568 lines of third-party code. An analysis of what they actually bought us
found:

1. **`oid4vci` (6,383 lines, 51 files) had zero consumers.** No `foundry-*`
   crate declared it; `cargo tree -i -p oid4vci` returned only the crate itself.
   Its single textual trace in the whole repository was a doc comment noting
   that `foundry-issuer` defines its own metadata types *instead of* using it.
   It nonetheless compiled and ran its 24 tests on every
   `cargo test --workspace`.
2. **`openid4vp` (7,135 lines) was used for exactly three things:**
   `core::jwe::JweBuilder`, `core::credential_format::ClaimFormatDesignation`
   (two variants), and four `core::dcql_query` types — roughly 1,500 of its
   lines, supporting 248 lines of foundry code.
3. **`ssi 0.16` and `json-ld` were *normal* dependencies of `openid4vp`**, hence
   linked into **production** `foundry-verifier` and `foundry-wallet` builds.
4. **Two unauditable git-revision pins** came in transitively: `open-auth2`
   (rev `5d653ea`) and `isomdl` (rev `7608053`).
5. **Version skew:** the vendored crates pinned `axum 0.8`, `thiserror 1`,
   `rand 0.9`, `base64 0.21` against the workspace's `0.7`/`2`/`0.8`/`0.22`.
6. **No `LICENSE` file existed**, while `[workspace.package]` declared
   `license = "Apache-2.0"` and the repo redistributed Spruce's
   `MIT OR Apache-2.0` code with no top-level attribution.

Driver priority, set by the user: **(a) supply-chain / audit surface** for an
eIDAS-adjacent service that may face certification, then **(b) build and CI
cost**, then **(c) direct control over protocol-model correctness**.

## Approach

**Clean-room reimplementation of the used surface, then deletion.**

Requirements were derived from foundry's own consuming code, its test fixtures,
and the OpenID4VP 1.0 specification (§6 DCQL, §7 Claims Path Pointer,
Appendix B format identifiers, Appendix D examples) — deliberately **not** from
reading `openid4vp/src/core/{jwe,dcql_query,credential_format}.rs`. Copying
upstream's implementation would have left third-party code in place under a new
path and forfeited the audit-surface reduction that motivated the work.

Note honestly: this is an attestation about process, not a property provable
from the artifact — and the vendored source is now deleted, so it cannot be
diffed against even in principle.

### Rejected alternatives

- **Copy the three modules in with attribution.** Same dependency-graph win at
  near-zero behavioural risk, but third-party code and the attribution
  obligation would remain — precisely what driver (a) was buying out.
- **Hybrid: clean-room the JWE helper, copy the DCQL types, tighten later.**
  Sequences the risk more gently; rejected by the user in favour of doing it
  once.
- **Delete only `oid4vci`.** Captures the free win but leaves `ssi`/`json-ld` in
  production builds.
- **Re-add as crates.io dependencies.** Reduces in-repo lines but *increases*
  supply-chain exposure and re-introduces the git-rev transitive pins.

## Changes

- `crates/foundry-core/src/crypto/jwe.rs` — **new.**
  `encrypt_compact(payload, recipient_public_jwk, alg, enc)`: ECDH-ES JWE
  compact serialization over `josekit`, the exact inverse of the verifier's
  pre-existing decrypt path. Same JOSE library on both ends, so wire
  compatibility is structural rather than hoped-for. Validates
  `alg == "ECDH-ES"` rather than emitting a protected header that misdescribes
  the ciphertext.
- `crates/foundry-core/src/error.rs` — one new variant, `CryptoError::Jwe`. No
  new enum. None of the existing variants fitted: reusing `UnsupportedAlgorithm`
  would have rendered as "unsupported **signature** algorithm 'A128GCM'".
- `crates/foundry-verifier/src/dcql_model.rs` — **new, crate-private.** DCQL
  wire model per OpenID4VP 1.0 §6/§7. A net *reduction* in public API surface,
  since the types previously arrived via a public dependency.
- `crates/foundry-verifier/src/dcql.rs` — `use` lines, two match arms, two
  signatures, one removed cast. **No logic, error-string or test change.**
- `crates/foundry-wallet/src/actions/verification.rs` — the single production
  JWE call site.
- `crates/foundry-verifier/src/verify.rs`, `crates/foundry/tests/wallet_verification.rs`,
  `crates/foundry/tests/e2e_full_flow.rs` — 12 test JWE call sites.
- `Cargo.toml`, three crate manifests — dependency and workspace-member removal.
- `crates/oid4vci/`, `crates/openid4vp/`, `crates/openid4vp-frontend/`,
  `docs/VENDORING.md` — **deleted.**
- `AGENTS.md`, `README.md`, and five crate `AGENTS.md` files — vendored-crate
  references removed; `crypto/jwe.rs` and `dcql_model.rs` added to module maps.
- `crates/foundry-issuer/src/metadata.rs` — stale doc comment referring to "the
  vendored `oid4vci` crate's generic types" reworded.
- `docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md` — superseding
  note. It is linked from `AGENTS.md` §8 as live rationale but referenced
  `docs/VENDORING.md` and two deleted files, so it was a dangling link out of
  live guidance. Annotated rather than rewritten.
- `LICENSE` — **new**, verbatim Apache-2.0 (11,358 bytes), closing the gap in
  item 6 above.

### Outcome

| Metric | Before | After |
|---|---|---|
| Vendored third-party lines | ~13,568 | **0** |
| `Cargo.lock` packages | 743 | **385** (−358, −48%) |
| `ssi`, `json-ld` in production builds | yes | **no** |
| Unauditable git-rev pins | 2 (`open-auth2`, `isomdl`) | **0** |
| Workspace members | 10 | 7 |
| Foundry-owned replacement code | — | 593 lines (176 + 417) |

## Design decisions worth carrying forward

Three are **load-bearing, not stylistic** — a future change that "simplifies"
any of them would reintroduce a defect:

1. **`CredentialFormat::Other(String)` is mandatory.** Without a catch-all, a
   DCQL query naming a format foundry does not implement fails
   *deserialization*, so `check_dcql_match` reports `"dcql_query is not a valid
   DCQL query"` instead of `"no credential query … matches the presented
   credential format"`. That is a behaviour change inside a security check.
2. **Never add `serde(deny_unknown_fields)`.** OpenID4VP §6: "Implementations
   MUST ignore any unknown properties."
3. **`ClaimValue` declares `Boolean` before `Integer` before `String`.**
   `serde(untagged)` resolves in declaration order; reordering would coerce JSON
   booleans. Guarded by `boolean_claim_value_is_not_coerced`.

Plus three spec-mandated non-empty constraints, each fail-closed and each
enforced at deserialization: `credentials` (§6), `claims[].path` (§6.3),
`claims[].values` (§6.3). The first was nearly missed — see below.

## Tests

- `crates/foundry-core/src/crypto/jwe.rs` — 7 new tests. The load-bearing one,
  `round_trips_annotated_public_to_bare_private`, encrypts to the annotated
  public JWK (carrying `kid`/`use`/`alg`, as the verifier advertises it) and
  decrypts with the **bare** private JWK (as the verifier stores it). That
  asymmetry was the plan's identified top risk; it round-trips cleanly, and is
  now proven rather than assumed. Also: unsupported `alg`, unsupported `enc`,
  malformed JWK, non-object payload, nested-JSON survival.
- `crates/foundry-verifier/src/dcql_model.rs` — 13 new tests, including both
  OpenID4VP Appendix D examples verbatim, the unknown-format-is-skipped
  regression guard, untagged-variant coverage, and the three non-empty
  rejections.
- **12 migrated JWE test call sites and the 7 pre-existing `dcql.rs` conformance
  tests pass unmodified.** No assertion was relaxed or expectation edited to
  make anything green — that is the actual evidence of behavioural equivalence.
- Verified: `cargo test --workspace` **327 passed / 0 failed**;
  `cargo test -p foundry --test e2e_full_flow -- --ignored` **1 passed**;
  `cargo clippy --workspace --all-targets -- -D warnings` **0 diagnostics**;
  `cargo fmt --check` clean.

### Behaviour deltas (the honest list)

The spec promised no observable behaviour change. Two exceptions:

- The wallet's two error messages (`"invalid ephemeral jwk: {e}"`,
  `"JWE build failed: {e}"`) collapse into the latter, because
  `encrypt_compact` parses the JWK and encrypts in one step. josekit's inner
  message still names the real cause; commented at the call site.
- `"values": null` is now rejected where `Option<NonEmptyVec>` treated it as
  absent. Stricter, not looser; nothing in foundry emits it.

## Review

**Two Important findings, both introduced by this branch, both invisible to the
test suite, both fixed before reporting** (commit `32fa6a5`):

1. `dcql.rs`'s `resolve_path` doc comment still described `Integer` and `Null`
   segments after the rename to `Index` and `Wildcard` — a comment naming
   identifiers that no longer compile, on a fail-closed security check.
2. `crates/foundry-verifier/AGENTS.md` still asserted that
   `PresentedFormat::MsoMdoc` matches `ClaimFormatDesignation::MsoMDoc`, a type
   deleted with the vendored crate. Worse than the comment, because `AGENTS.md`
   is normative agent guidance. Now names
   `dcql_model::CredentialFormat::MsoMdoc` and flags the `MsoMDoc` → `MsoMdoc`
   casing change explicitly.

**Four Minor findings, reported and deliberately left:** `"values": null` now
errors; empty `id` accepted though §6.1 says MUST be non-empty; duplicate `id`s
accepted though §6.1 says MUST NOT repeat; `u64 as usize` path-index cast
(theoretical 32-bit truncation, and `Value::get` returns `None` anyway). The
`id` constraints are non-security — `id` surfaces only in the `detail` string —
and enforcing them would breach the spec's own non-goal of not changing which
DCQL features foundry supports.

**One pre-existing observation, out of scope, recommended as a follow-up:**
`crates/foundry-verifier/src/verify.rs:53` discards the JWE protected header
(`let (jwt_payload, _header) = …`), so the verifier never checks that the wallet
used the `alg`/`enc` it advertised in `client_metadata`. Not introduced here,
but it is a genuine protocol-correctness gap and driver (c) was exactly that.

### Process notes against myself

- The spec initially undercounted the JWE call sites as 5; they are **13**.
  Caught during planning, not implementation.
- `crates/foundry/tests/e2e_full_flow.rs:483` is `#[ignore]`d — the only ignored
  test in the workspace — so its JWE call site is **not** exercised by
  `cargo test --workspace`. Caught only by capturing a per-target test baseline.
  Without that, Task 2 would have migrated 13 sites, verified 12, and reported
  success. Both spec and plan were amended to mandate an explicit `--ignored`
  run.
- The non-empty `credentials` constraint was **not** in the plan. It surfaced
  from `dcql.rs`'s own test comment ("NonEmptyVec rejects empty → parse error")
  plus `config.yaml:56` shipping `dcql: { credentials: [] }`. A plain `Vec`
  would have kept the assertion passing while silently changing the failure mode
  from *parse error* to *matched nothing*.
- I amended the Task 1 commit to fold in its ledger entry, which changed the SHA
  and left the ledger citing an unreachable commit. Fixed in `e8e0415`; Tasks
  2–5 used separate ledger commits instead.
