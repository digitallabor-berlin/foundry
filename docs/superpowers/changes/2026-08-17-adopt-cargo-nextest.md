# Adopt `cargo nextest run` as the Test Runner, and Collapse the Tiered Gate

**Date:** 2026-08-17
**Trigger:** user request — "instead of the default cargo test runner use `cargo nextest run`"
**Method:** `superpowers:brainstorming`, bounded path (no design/plan doc; a
convention change, not a feature)

## What changed

`cargo nextest run` replaces `cargo test` as this repository's test runner,
everywhere it is documented or invoked: the root and per-crate `AGENTS.md`
files, `README.md`, the conformance report's self-check note, and the CI
workflow.

The larger consequence is that root `AGENTS.md` §5 lost three of its six
subsections. It is now: one gate, the E2E suite, the honesty rule, and a
gotchas list.

## Why the tiered gate went away

§5's entire structure was downstream of one premise, stated in its first
sentence: *"The workspace suite is deliberately slow."* That premise was true
under `cargo test` and is false under nextest. Measured on this branch, warm
cache, same 942 tests:

| | `cargo test --workspace` | `cargo nextest run --workspace` |
| --- | --- | --- |
| Wall time | 1m 51s | 3.3s |
| Passed / skipped | 942 / 12 | 942 / 12 |
| Output | 45 `test result:` lines buried in ~2000 | 10 lines with `--status-level fail` |

nextest is faster here because `cargo test` runs one test *binary* at a time
(39 of them) and only parallelises threads within each, while nextest schedules
every test across every binary against the whole machine. This workspace is
mostly I/O-bound tests — SQLite, port binds, status-list fixtures — which is the
shape that benefits most.

At three seconds, these subsections were not merely obsolete but actively
harmful, since each one instructed an agent to run *less* than the full suite:

- **§5.1's scoped gate** and **§5.2's affected-crates table** existed to compute
  the minimum safe subset of crates to test. Testing a subset now buys nothing
  and costs coverage.
- **§5.3's two-trigger full gate** rationed a run that no longer needs
  rationing.
- **§5.4 ("never re-run the full suite after merging")** protected against
  "re-pay[ing] the most expensive gate in the repository". It is no longer
  expensive.
- **§5.6's `tee`-to-disk-then-`grep` procedure** existed because a full
  `cargo test` run overflows the agent harness's ~2000-line output truncation,
  and a bare `tail` had already silently hidden a `FAILED` in this repository.
  `--status-level fail` renders a green workspace run in about ten lines, so
  there is nothing left to truncate.

Keeping the scaffolding while swapping the command would have left a document
telling agents to carefully conserve time that no longer exists.

The §3 dependency-layering diagram is untouched. It still governs *dependencies*
— it just no longer doubles as a test-scoping rule.

## Command translation

| Before | After |
| --- | --- |
| `cargo test --workspace` | `cargo nextest run --workspace --no-fail-fast --status-level fail` |
| `cargo test -p foundry-issuer` | `cargo nextest run -p foundry-issuer` |
| `cargo test -p foundry --test wallet_issuance foo` | same, positionally — **no `--` separator** |
| `cargo test -p foundry --test e2e_full_flow -- --ignored` | `cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only` |
| `cargo test --workspace -- --ignored` | `cargo nextest run --workspace --run-ignored ignored-only` |
| the four `conformance_*` suites, `&&`-chained | `cargo nextest run -E 'binary(/^conformance_/)'` |
| `--nocapture` | `--no-capture` |

## Two things nextest does not do

Both are recorded in root `AGENTS.md` §5.4 rather than left to be discovered.

- **It does not run doctests.** Nothing is lost today: the workspace has no Rust
  doctests, only ` ```text ` and ` ```cddl ` blocks in doc comments
  (`foundry-issuer/src/jose.rs`, `foundry-issuer/src/challenge.rs`,
  `foundry-mdoc/src/types.rs`), which rustdoc never compiles. Verified with
  `cargo test --workspace --doc` → 0 tests. Anyone adding a real doctest must
  run `cargo test --doc` themselves; nothing else will.
- **It does not echo `#[ignore = "..."]` reason strings.** `cargo test` printed
  them next to each skipped test, which `README.md` relied on for reviewing the
  conformance Gap Register without running it. Replaced with
  `cargo nextest list --workspace --run-ignored ignored-only` for the names, and
  `rg -n '#\[ignore = ' crates/*/tests/ crates/foundry/tests/` for the reasons.
  This is a genuine, if small, regression; it is documented rather than papered
  over.

## An incidental benefit

nextest runs every test in its own process. That structurally eliminates the
bug class recorded in
[`2026-08-02-tracing-callsite-interest-flake.md`](2026-08-02-tracing-callsite-interest-flake.md),
where `server::tests::detail_is_length_capped` failed ~15% of the time because
tracing's *process-global* callsite-interest cache had been poisoned by a
sibling test in the same binary. The converse also holds: a test that silently
depended on a sibling initialising shared state would now fail honestly. The
suite is green under nextest, so no test in the workspace had such a dependency.

## Files touched

- `AGENTS.md` — §5 rewritten (six subsections to four); §7's subagent-gate
  paragraph rewritten, since there is no longer a scoped/full distinction to
  brief a subagent on
- `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md`,
  `crates/foundry-verifier/AGENTS.md`, `crates/foundry/AGENTS.md`,
  `crates/foundry-mdoc/AGENTS.md`, `crates/foundry-sd-jwt-vc/AGENTS.md` — gate
  paragraphs and command examples
- `crates/foundry/tests/AGENTS.md` — the Running block
- `README.md` — the Testing section (now leads with the nextest install line),
  the CI description, both E2E invocations, the conformance table and combined
  run, and the gap-register recipes
- `docs/conformance/openid4vc-conformance.md` — the self-check note naming the
  run that enforces it
- `.github/workflows/docker-publish.yml` — added `taiki-e/install-action@nextest`
  (prebuilt binary; compiling nextest from source would cost more than the suite
  it runs), swapped the `cargo test` step
- `crates/foundry/tests/e2e_full_flow.rs` — the `Run with:` doc comment
- `Cargo.toml` — a profile comment that named `cargo test`

Deliberately **not** touched: `docs/superpowers/changes/**`,
`docs/superpowers/specs/**`, and `docs/superpowers/plans/**`. Those are records
of what was planned and run at the time, including their references to §5.1–§5.6
as those sections then stood. Rewriting them would falsify the record.

## Prerequisite

`cargo nextest` is not part of a stock Rust toolchain. Install it with
`cargo install cargo-nextest --locked`, or see <https://nexte.st/docs/installation/>.
CI installs it via `taiki-e/install-action@nextest`.

## Verification

`cargo fmt`, then
`cargo nextest run --workspace --no-fail-fast --status-level fail`, then
`cargo clippy --workspace --all-targets -- -D warnings` — the gate this change
itself introduces. The E2E suite was additionally run under its new invocation,
and `conformance_report` (which parses the conformance Markdown and enforces its
internal consistency) covers the edit to that document.
