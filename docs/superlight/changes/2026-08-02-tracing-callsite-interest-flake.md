# Capture subscribers silenced by tracing's global callsite-interest cache

**Date:** 2026-08-02
**Type:** bugfix
**Track:** C (investigate) → A (direct fix)
**Branch:** superlight/2026-08-02-tracing-callsite-interest-flake
**Spec:** n/a — Track A
**Plan:** n/a — Track A

## Problem

`server::tests::detail_is_length_capped` failed on roughly 15% of process
starts under parallel execution:

```
panicked at crates/foundry/src/server.rs:1162:28:
index out of bounds: the len is 0 but the index is 0
```

The name misleads: nothing about length capping was broken. `events` was
**empty** — the capture layer received no event at all.

Measured baseline on unmodified `main`: 6/40 full lib-test binary runs, 2–3/30
with only `server::tests`, **0/30** with the test alone, **0/15** with
`--test-threads=1`.

## Root Cause

`tracing-core` caches `Interest` **per callsite in a process-global slot**,
computed once on the callsite's first use by `rebuild_callsite_interest`
(tracing-core 0.1.36, `callsite.rs:505`):

```rust
let interest = interest.unwrap_or_else(Interest::never);
callsite.set_interest(interest)
```

The dispatcher set it folds over comes from `Dispatchers::rebuilder()`, which
has a fast path:

```rust
if self.has_just_one.load(SeqCst) { return Rebuilder::JustOne; }
...
Rebuilder::JustOne => { dispatcher::get_default(f); return; }
```

`has_just_one` is set from `dispatchers.len() <= 1`. So while at most one
dispatcher is registered, a callsite's first registration is resolved against
**the registering thread's own default subscriber** rather than the registry.

Three tests in `server::tests` call the error mappers *without* installing a
subscriber — `status_mapping_is_unchanged_by_logging`,
`invalid_client_wire_body_is_rfc6749_shaped`,
`invalid_client_is_not_special_cased_on_the_admin_surface`. When one of those
threads is first to touch the `warn!` callsite in `log_typed_error`, its
default is `NoSubscriber`, which answers `Interest::never()` — and that verdict
is cached **for every thread**. A sibling test sitting inside `with_default`
with a live TRACE capture subscriber then loses its event: the `event!` macro
short-circuits on the cached interest before consulting any subscriber.

The next dispatcher registration rebuilds the cache, which is exactly why this
presented as a rare flake and why an immediate retry always succeeded. It is a
once-per-process cold-start race, which is also why only ever one test failed
per run.

### Evidence

- At the failing emit, `level_enabled!(WARN) == true` and
  `LevelFilter::current() == TRACE` — the global *level* gate was open.
- A control event at a fresh callsite, same subscriber, same instant: captured.
- An immediate retry of the *identical* production callsite: captured.
- Deterministic staged reproduction (dispatch registered before the callsite
  exists, then entered with `dispatcher::with_default`, which does not
  re-register): **30/30** failures.

### Rejected hypotheses

- *Shared tracing subscriber state* (the original theory) — `with_default` is
  thread-local and each `captured()` builds its own registry and buffer.
- *Mismatched filter levels between tests* — reproduces with only
  `server::tests`, all of which use `LevelFilter::TRACE`.
- *Generic scoped-subscriber race* — synthetic repro, 8 threads × 500
  iterations all holding subscribers: 0 misses in 4000.
- *A bare hit permanently poisons a callsite* — recovers cleanly when serial.
- *Global max-level filter closing* — measured open at the moment of loss.
- *`obs::set_sensitive` / env-var cross-talk* — `error.detail` is unconditional
  in `log_typed_error`.

## Approach

`capture_layer()` now keeps **two** dispatchers registered for the life of the
process, via a `OnceLock`. Two rather than one because `has_just_one` is
`dispatchers.len() <= 1` — a single keep-alive would leave the fast path armed.
Because both are held forever, the `retain` inside `register_dispatch` can
never drop the count back to one.

Their subscriber (`AlwaysAsk`) answers `Interest::sometimes()`, which defers
every decision to `enabled()` on whichever dispatcher is current — the only
answer that stays correct when subscribers are per-thread. It records nothing.

Registering them also rebuilds the interest cache for all known callsites, so a
callsite poisoned before the first capture is repaired at that point.

Rejected alternatives:

- `--test-threads=1` — hides other races and slows the suite.
- A retry loop inside `captured()` — would mask the exact "no record emitted"
  regression these tests exist to catch (root AGENTS.md §4.5).
- A serialising mutex around every capture — wider, and does not remove the
  window, since subscriber-less tests still run concurrently.

## Changes

- `crates/foundry/src/log_capture.rs` — added `AlwaysAsk` and
  `keep_interest_cache_resolvable()`; `capture_layer()` calls it before
  returning. Every scoped-subscriber user in the workspace (`server.rs`,
  `http_log.rs`, `tests/logging_redaction.rs`) obtains its layer here, so all
  are covered by the one change.
- `crates/foundry/AGENTS.md` — Gotchas entry warning against deleting the
  keep-alive as inert code.

## Tests

- `crates/foundry/src/log_capture.rs` —
  `a_subscriberless_thread_cannot_silence_a_capture`: stages the cold-start
  ordering deterministically. Fails 30/30 with the fix removed, passes with it.

## Review

- **Fixed a false-negative risk, not just a flake.** `tests/logging_redaction.rs`
  asserts a planted secret appears nowhere in the capture buffer. An empty
  buffer passed that assertion vacuously, so the same defect could have hidden
  a real leak (root AGENTS.md §4.5).
- **Known limitation, accepted:** the regression guard is deterministic when run
  alone (30/30) but only ~10% likely to fail inside a full parallel run, because
  another test's live dispatcher can disarm the fast path incidentally. Making
  it deterministic under parallelism would require serialising global tracing
  state across the binary — disproportionate. A bisect or targeted rerun, which
  is how this guard would actually be exercised, runs it alone.
- Workspace scanned for the same pattern: no other crate has a capture helper or
  uses `with_default`/`set_default`.

### Verification

Scoped gate (root AGENTS.md §5.1/§5.2 — touched `foundry`, dependent
`foundry-wallet`):

```
cargo test -p foundry              # lib 56 passed; all integration suites passed
cargo test -p foundry-wallet       # all passed
cargo clippy -p foundry --all-targets -- -D warnings          # clean
cargo clippy -p foundry-wallet --all-targets -- -D warnings   # clean
cargo fmt --check                                             # clean
```

Flake-specific, post-fix:

```
full lib binary:      0/100 failed   (baseline 6/40)
server::tests only:   0/100 failed   (baseline 2-3/30)
```