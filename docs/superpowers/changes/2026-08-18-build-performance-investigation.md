# 2026-08-18 — `target/` accumulation was throttling every rebuild; rust-analyzer was competing for the build lock

## Symptom

Ordinary agent tool calls were taking minutes to return. A representative one,
from the 2026-08-18 10:02 session:

```bash
cargo nextest run -p foundry-verifier select_presentations > /tmp/red.txt 2>&1
```

**109 seconds.** Not an outlier — from pi's session logs for this repository:

```text
217s  cargo nextest run -p foundry-sd-jwt-vc kb_audience_mismatch
211s  cargo nextest run -p foundry-verifier web_origin
211s  cargo clippy --workspace --all-targets -- -D warnings
172s  cargo clippy --workspace --all-targets -- -D warnings
148s  cargo check --workspace --all-targets
147s  cargo nextest run --workspace
```

The initial suspicion was overhead in the agent harness. It was not.

## What was ruled out first

Harness overhead was measured directly from pi's own session logs, which
timestamp every tool call, across **5,751 pure-`bash` tool turns in 86 sessions**
for this repository:

| metric | value |
| --- | --- |
| median bash round-trip | **0.04 s** |
| trivial calls (`echo`, `git status`, `ls`) | 0.0–0.1 s |
| long calls | fully accounted for by the inner command's own `date`-measured duration |

A 1,197 s round-trip was a 1,197 s `cargo clean`; an 83 s round-trip was five
cargo invocations summing to 83 s. There is no per-call tax, no hook tax, and no
output-processing tax. The time was real compile work.

## Root cause

`target/` had grown to **113 GB**, and the cost lands on cargo's *write* path.

State before the clean:

```text
113 GB   target/
 71 GB   target/debug/deps          <- 1,051,965 .o files (1,072,866 entries)
 40 GB   target/debug/incremental   <- 3,092 session directories
          target/debug/.fingerprint <- 8,907 directories
```

The decisive measurement is the **same cold command on both trees**:

| identical cold command | 113 GB tree | clean tree | ratio |
| --- | --- | --- | --- |
| `cargo clippy --workspace --lib --bins` | 146 s | **3 s** | **49×** |
| `cargo check --workspace` | 29 s | **2 s** | **15×** |
| `cargo build --workspace --all-targets` (everything, from scratch) | — | **26 s** | — |

### The mechanism, precisely

There are two paths, and the accumulation only penalises one. Getting this
distinction wrong is what made the problem survive an earlier analysis pass:

- **Read/stat path — no-op invocations — UNAFFECTED.** With all 1,051,965 `.o`
  files present, a no-op `cargo check --workspace --all-targets` took
  **208–615 ms**. Cargo stats a bounded set of fingerprints for the units in the
  current dependency graph (~369 of them), not the whole tree. Any claim that
  cargo must "stat and hash-check the tree before rustc compiles a line" is
  wrong, and measuring only no-ops makes the problem invisible.
- **Write path — any real rebuild — CATASTROPHICALLY AFFECTED.** Creating new
  artifact files inside a directory holding 1,072,866 entries is where the cost
  lands; APFS directory-insertion cost grows with directory size. Corroborating
  evidence: `cargo clean` needed **1,197 s (20 minutes)** to remove
  1,369,632 files / 181.8 GiB.

Because every call made during active development triggers a rebuild, essentially
every slow call was on the penalised path. This is also why the slowness was
intermittent-looking: no-op re-runs of the same command returned instantly, which
made it seem unrelated to `target/`.

### Why it accumulated

Cargo caches **each distinct unit configuration separately and never evicts**.
Nothing invalidates anything — `check --all-targets`, `check`, `clippy
--all-targets`, `clippy --lib --bins` and nextest's test-binary build were all
measured warm *simultaneously*. That is a feature, but it means every command
shape ever used is retained forever. The session logs show **123 distinct cargo
invocation shapes** used against this repository, including:

```text
313x  cargo test -p foundry
250x  cargo test --workspace
142x  cargo test -p foundry-issuer
 89x  cargo test --lib -p foundry-issuer
 34x  cargo test -p -p -p foundry foundry-core foundry-issuer   (malformed)
```

Multiply 123 shapes by six crates, 39 targets, and months of changing dependency
hashes and toolchains, and 8,907 fingerprint directories is the arithmetic
result, not an anomaly.

Note that `cargo test` — 934 invocations against 69 for `cargo nextest run` — was
already eliminated by [`2026-08-17-adopt-cargo-nextest.md`](2026-08-17-adopt-cargo-nextest.md);
the session logs show a clean switchover (2026-08-18: 0 `cargo test`, 31 nextest).
Shape discipline is what §5.1's "one gate, no tiers" rule buys, and it is now
also a cache-hygiene rule, not only a coverage rule.

## Secondary root cause: rust-analyzer competes for the build lock

VS Code's rust-analyzer was running with **all-default settings**, meaning
`checkOnSave: true` and `cargo.targetDir: null` — so its flycheck

```bash
cargo check --quiet --workspace --message-format=json --all-targets --keep-going
```

shared `target/` with the shell. Reproduced directly:

```text
concurrent cargo check while another cargo process ran: 8s
    Blocking waiting for file lock on build directory
```

rust-analyzer documents this itself, under *"Rust Analyzer and Cargo compete over
the build lock"*:

> Rust Analyzer invokes Cargo in the background, and it can thus block manually
> executed `cargo` commands from making progress (or vice-versa). In some cases,
> this can also cause unnecessary recompilations caused by cache thrashing.

This is the mechanism behind the "*sometimes* it takes very long" character of the
symptom: it fires when a save has just happened in the editor. It also meant
flycheck artifacts were landing in `target/debug/deps`, feeding the accumulation
above.

## Change

1. **`cargo clean`** — reclaimed 181.8 GiB / 1,369,632 files. `target/` went from
   113 GB to 2.6 GB; fingerprint directories 8,907 → 413; incremental sessions
   3,092 → 46. Volume usage 80 % → 67 % (188 GiB → 301 GiB free). Full cold
   rebuild to restore everything: **26 s**.
2. **`.vscode/settings.json`** (new) — `"rust-analyzer.cargo.targetDir": true`,
   the documented remedy, moving flycheck into its own subdirectory. Costs a few
   GB of duplicated artifacts; buys no lock stall on save and no flycheck
   pollution of `target/debug/deps`. Kept as strict JSON with no comments (VS
   Code accepts JSONC, but the repository's tooling lints `.json` strictly) —
   which is why the rationale lives here instead.
3. **`cargo-sweep` v0.8.0 installed**, and `AGENTS.md` §5.5 added to record the
   hygiene requirement, since the corrective `cargo clean` costs 20 minutes once
   the tree is bad.

## Result

| loop (measured after the clean, on deliberately dirtied source) | time |
| --- | --- |
| edit leaf crate (`foundry-verifier`) → `nextest run --workspace` | 6 s |
| edit deepest crate (`foundry-core`) → `nextest run --workspace` | 7 s |
| `+ cargo clippy --workspace --all-targets -- -D warnings` | 2 s |
| the 109 s command from the Symptom section | **1–2 s** |
| full warm gate (§5.1) | ~4 s, 951 tests |

`AGENTS.md` §5's claim that the workspace suite "runs in seconds" is accurate; it
had simply stopped being true in practice, for a reason outside the test suite.

## Rejected after measurement

Recorded so the same ground is not re-covered. Each of these was a plausible
recommendation that measurement refuted:

| Proposal | Verdict |
| --- | --- |
| Separate `CARGO_TARGET_DIR` for clippy, because clippy and nextest invalidate each other's workspace artifacts | **Refuted.** They coexist. Measured on both trees: clippy-after-nextest 0.5 s, nextest-after-clippy 2–3 s. The `RUSTC_WORKSPACE_WRAPPER` fingerprint difference produces a *different hash*, not an eviction. |
| `CARGO_INCREMENTAL=0` on the gate | Unnecessary; the warm gate is already ~4 s. |
| Split the gate (`clippy --lib --bins`) for a faster inner loop | **Counterproductive**, and forbidden by §5.1. Introducing that shape cost a 146 s cold build to save 0.5 s. |
| Drop `sqlx`'s `macros` feature (no `query!` macros in the workspace) | **Refuted.** `sqlx::migrate!` is a compile-time macro and is used at `crates/foundry-core/src/storage/sqlite.rs:22`. Only `any` is droppable, which is marginal. |
| Feature-gate `utoipa-swagger-ui` to remove `tower-http` (12.42 s unit) | **Partly refuted.** `tower-http` arrives via `reqwest` → `foundry-verifier`, a real production dependency, and survives the gate. Only the duplicate `sha2 0.11` crypto cluster (`rust-embed-utils` → `rust-embed` → `utoipa-swagger-ui`) is attributable, worth a couple of seconds on a 26 s cold build. |

## Open item

A flaky test was observed during this work, unrelated to build performance:

```text
FAIL [0.018s] foundry-issuer attestation::tests::returns_the_attestations_sub_and_a_usable_cnf_jwk
```

It failed once and passed on the identical immediate re-run and in every other
run (951 tests, 12 skipped, otherwise green). This is the second flake recorded
for this repository; the first was `crates/foundry/tests/cli_openapi.rs` in July.
Not investigated here — it needs its own root-cause pass.

## Measurement log

The full command-by-command timing log, including the pre-clean baseline and the
superseded intermediate conclusions, is at `/tmp/foundry-build-baseline.md` (not
committed; regenerable from the procedure above).
