# Design: Hierarchical AGENTS.md for Agent Discovery

**Date:** 2026-07-28
**Status:** Approved — **partially superseded 2026-07-30**
**Scope:** Documentation only — no source or build changes.

> **Superseding note (2026-07-30).** The vendored `oid4vci`, `openid4vp` and
> `openid4vp-frontend` crates were removed from the workspace (see
> `docs/superpowers/changes/2026-07-30-remove-vendored-crates.md`). Consequently
> the "vendor guard" rows below, `crates/oid4vci/AGENTS.md`,
> `crates/openid4vp/AGENTS.md` and `docs/VENDORING.md` no longer exist. The
> hierarchical-AGENTS.md design this document describes is otherwise unchanged
> and still in force; only the vendored-crate portions are historical.

---

## 1. Problem

`foundry` has a single root `AGENTS.md` (74 lines) covering a 10-crate workspace
(~30k LoC). Two failure modes result:

1. **Context bloat** — adding per-crate detail to the root file would make it
   grow without bound, and every agent (including subagents that only touch one
   crate) pays the full token cost.
2. **Discovery / orientation cost** — an agent with fresh context (especially a
   subagent) must grep to learn where a concern lives, which invariants bind it,
   and which test file covers it. Turns are wasted landing in the wrong file.

Goal: root becomes a **thin router + normative global invariants**; each crate
carries its own **map and crate-local rules**.

## 2. Critical mechanical constraint

pi (and Codex) load `AGENTS.md` only from:

- the global dir (`~/.pi/agent/AGENTS.md`),
- parent directories walking up from cwd,
- the current directory.

**Nested `crates/*/AGENTS.md` files are NOT auto-discovered.** (Claude Code
lazily loads nested `CLAUDE.md` when it touches a file in that directory; pi does
not.) Therefore per-crate files only pay off if the **root file explicitly
routes to them**. Without that directive they are dead files.

This constraint is load-bearing for the whole design: the root routing table
carries an explicit instruction to open the nested file before working in a
crate.

## 3. Architecture

### 3.1 Root `AGENTS.md` (~90 lines)

| # | Section | Content |
|---|---|---|
| 1 | What foundry is | 2 lines + link to `README.md` for build/run instructions (link, do not restate) |
| 2 | Crate map & routing table | One row per crate: path, one-line purpose, AGENTS.md path — with an explicit directive to open the nested file before reading/editing in that crate |
| 3 | Dependency layering rule | Allowed direction: `core → formats → engines → binary → wallet`. Stated once at root because it is cross-crate. |
| 4 | Global invariants | Normative and full: no-unwrap in request paths, honest `verified` verdict, policy-vs-structural HTTP mapping. Numbered (§4.1–§4.3) so crate files can point at them. |
| 5 | Verification gates | The three workspace gates, plus the per-crate fast loop (`cargo test -p <crate>`); workspace gates must pass before task completion. |
| 6 | OpenAPI rule | Endpoint changes must be reflected in `openapi.json` / `openapi-wallet.json`. |
| 7 | SDD role→agent mapping + pi-tasks tracking | Retained from the current file. |
| 8 | Maintenance rule | Adding a crate requires a routing row + a crate `AGENTS.md`; changing a module's purpose requires updating that crate's module map. |

The routing directive reads, verbatim in intent:

> **Before reading or editing files under `crates/<x>/`, first read
> `crates/<x>/AGENTS.md`.** These nested files are NOT auto-loaded — you must
> open them.

### 3.2 Per-crate file template (7 sections)

Every crate file uses the same section set, sized ~40–70 lines:

1. **Purpose** — what the crate is responsible for, and explicitly what it is *not*.
2. **Position in the dependency graph** — what it depends on, what depends on it.
   Prevents accidental upward dependencies (e.g. `foundry-core` must never
   depend on `foundry-issuer`).
3. **Module map** — one line per source file: name + description. **No LoC
   counts** (they drift on every commit and stale numbers erode trust in the
   whole file).
4. **Key public types / entry points** — the `pub use` surface, so callers are
   found in one hop.
5. **Binding invariants** — one-line actionable reminders plus a pointer to the
   root section holding the full normative rule.
6. **Tests** — where tests live for this crate (inline `#[cfg(test)]` vs
   `tests/`) and the exact single-crate command.
7. **Gotchas** — crate-specific traps discovered in practice.

### 3.3 Duplication policy

**Pointer + one-line reminder.** Crate files list the invariants that bind them
as short actionable summaries, each with a pointer to the root section for the
full rule. Example:

> `verified` MUST equal `checks.iter().all(|c| c.passed)` — never hardcode
> `true`. Full rule: root `AGENTS.md` §4.2.

Rationale: the failure mode that matters is a fresh-context subagent violating an
invariant it never read. A one-line reminder is enough to act on and enough to
prompt a root lookup, while the root remains the single normative source. Full
verbatim duplication was rejected (drift risk in two places); strict DRY was
rejected (a subagent handed only the crate file would see no invariants).

## 4. File inventory (11 files)

| Path | Kind |
|---|---|
| `AGENTS.md` | rewritten root router |
| `crates/foundry-core/AGENTS.md` | crate |
| `crates/foundry-sd-jwt-vc/AGENTS.md` | crate |
| `crates/foundry-mdoc/AGENTS.md` | crate |
| `crates/foundry-issuer/AGENTS.md` | crate |
| `crates/foundry-verifier/AGENTS.md` | crate |
| `crates/foundry/AGENTS.md` | crate |
| `crates/foundry/tests/AGENTS.md` | test map |
| `crates/foundry-wallet/AGENTS.md` | crate |
| `crates/oid4vci/AGENTS.md` | vendor guard |
| `crates/openid4vp/AGENTS.md` | vendor guard |

`crates/openid4vp-frontend` (50 LoC) gets **no** file — it is covered by a line
in the root routing table alongside the other vendored crates.

### 4.1 `crates/foundry/tests/AGENTS.md`

A test-file → coverage map for the 14 integration test files, plus how to run
one (`cargo test -p foundry --test e2e_full_flow`):

`e2e_full_flow`, `quickstart`, `sweeper`, `wallet_issuance`,
`wallet_verification`, `wallet_metadata`, `wallet_status_list_route`,
`issuer_offers`, `openapi_endpoints`, `cli_openapi`, `cli_pki`,
`cli_status_list`, `console`, `health`.

### 4.2 Vendor guards

`crates/oid4vci/AGENTS.md` and `crates/openid4vp/AGENTS.md` are short (~15 lines)
and state: these are **vendored owned copies**, not upstream dependencies; do not
restructure or reformat them; record any change per `docs/VENDORING.md`; prefer
wrapping behaviour in a `foundry-*` crate over editing vendored code; never
re-add as a crates.io dependency.

Rationale: these are the two largest crates in the repo by LoC (6.4k and 7.1k)
and are exactly where an agent could "helpfully" refactor upstream code.

## 5. Non-goals

- No restatement of README content (build, run, CLI, Docker, wallet usage). Root
  AGENTS.md links to `README.md`.
- No changes to source, tests, config, or CI.
- No LoC counts, test counts, or other numbers that drift per-commit.

## 6. Maintenance

- **New crate** → add a routing table row in root + create the crate
  `AGENTS.md` from the 7-section template.
- **New/renamed/repurposed module** → update that crate's module map.
- **New global invariant** → add to root §4 with a number; add a one-line
  reminder to each crate file it binds.
- **Endpoint change** → update the OpenAPI specs (root §6) and, if it changes
  routing, `crates/foundry/AGENTS.md`.

## 7. Verification

Documentation-only change, so the code gates are unaffected but must still be
clean:

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`

Additional doc-specific checks:

- Every path mentioned in any AGENTS.md exists.
- Every crate in `Cargo.toml` `members` appears in the root routing table.
- Every routing row that names an AGENTS.md path resolves to a real file.
- Every root invariant pointer (`§N.M`) resolves to a real root section.