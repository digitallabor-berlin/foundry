# Remove the `foundry-wallet` Debug Wallet Crate

**Date:** 2026-08-03
**Type:** removal
**Branch:** `remove-foundry-wallet` (base `a73ee22`)
**Spec / Plan:** none — scope was fully enumerable up front (one leaf crate, no
dependents), so the work was agreed conversationally and executed in a single
commit rather than routed through the spec → plan → subagent cycle.

## Problem

`foundry-wallet` was a debug EUDI wallet CLI/TUI added on 2026-07-24 to drive
and inspect foundry's issuance and verification flows end-to-end. It is no
longer needed: the flows it exercised are covered independently by the
integration suite in `crates/foundry/tests/`, and hand-driven exploration is
served by the admin test console plus a real wallet app.

Keeping it carried ongoing cost with no remaining benefit:

- It was a **workspace member**, so it compiled and ran its tests on every
  `cargo test --workspace` and every CI run.
- It was the **sole consumer** of the `ratatui` and `crossterm` workspace
  dependencies, and pulled `reqwest`, `assert_cmd`, and `uuid` into the lock
  file for nothing else.
- It appeared in the **dependency-layering rule** (root `AGENTS.md` §3) and in
  five crate `AGENTS.md` "Consumed by" lists, widening the mental model every
  agent and contributor has to hold.

## Approach

Straight deletion. `foundry-wallet` was a clean leaf — no crate depended on it;
it dev-depended on `foundry` (not the reverse) purely to spawn a real server in
its own tests. Nothing needed to be rehomed.

### Coverage check performed before deleting

The one real risk was losing protocol coverage. It was not lost —
`crates/foundry/tests/` already exercises the same ground without the wallet:

| Wallet test | Equivalent already in `crates/foundry/tests/` |
|---|---|
| `tests/issuance.rs` | `wallet_issuance.rs` — `/token` → `/credential` with a holder proof |
| `tests/verification.rs` | `wallet_verification.rs` — `/vp/request/:id` → `/vp/response/:id`, including a revoked Status List Token |
| `tests/cli_headless.rs` | `e2e_full_flow.rs` — boots the real binary and drives both flows over HTTP as a wallet: issue → verify → revoke → re-verify |

### Rejected alternatives

- **Leave the crate but drop it from `[workspace] members`.** Stops the CI cost
  but leaves 3,765 lines of unbuilt, unlinted, silently-rotting code in the
  tree — worse than either keeping or deleting it.
- **Scrub the historical `docs/` record too.** Rejected: the ~25 files under
  `docs/superlight/**` and `docs/superpowers/**` that mention `foundry-wallet`
  are dated records of what was true when written. Rewriting them would falsify
  history to tidy a grep.

## Changes

**Deleted**

- `crates/foundry-wallet/` — 34 files, 3,765 lines.
- `wallet.yaml` — the crate's example configuration (tracked).
- `wallet-data/` — local runtime store (untracked; was gitignored).

**Build**

- `Cargo.toml` — dropped the workspace member, plus the now-orphaned `ratatui`
  and `crossterm` `[workspace.dependencies]` entries.
- `Cargo.lock` — regenerated: 385 → 347 packages (−38).
- `.gitignore` — dropped `/wallet-data`.
- `.dockerignore` — dropped `wallet-data/` and `wallet.yaml`.

**Documentation**

- `README.md` — removed the crate-table row and the §"Debug Wallet CLI/TUI"
  section (93 lines); promoted the orphaned §"End-to-End Test" from `###` to
  `##`, since its parent heading no longer exists; dropped the
  `foundry-wallet issue --offer-uri` aside from the admin-console bullet; added
  a short paragraph to §"Admin Test Console" naming the console + a real wallet
  as the supported hand-driven path and `cargo test -p foundry --test
  e2e_full_flow -- --ignored` as the scripted one, so the deletion does not
  leave a "how do I drive a flow?" gap.
- `AGENTS.md` — §1 (no longer "plus a debug wallet client"), §2 routing table,
  §3 layering diagram, §4.1 (`WalletResult`/`WalletError` bullet), §5.2
  affected-crates table (2 rows removed, 1 reworded).
- `crates/foundry/AGENTS.md` — "Consumed by" is now *nothing*; scoped gate no
  longer mentions `-p foundry-wallet`.
- `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md`,
  `crates/foundry-verifier/AGENTS.md` — consumer / must-never-depend-on lists.
- `docs/conformance/openid4vc-conformance.md` — removed the `foundry-wallet`
  row from the out-of-scope table. The adjacent "Wallet-side and third-party
  obligations" row is unaffected and still governs wallet-role clauses.

**Deliberately untouched**

`openapi-wallet.json`, `config.yaml`'s `server.wallet_facing.*` and
`issuer.wallet_attestation.*`, and `crates/foundry/tests/wallet_*.rs` — all
name the server's *wallet-facing* surface, which has nothing to do with this
crate. Historical specs, plans, and change records under `docs/` likewise stay
as written.

## Tests

Scoped gate per root `AGENTS.md` §5.1. Nothing depended on the deleted crate,
so the blast radius is the workspace build plus `foundry`:

- `cargo build --workspace` — clean.
- `cargo test -p foundry` — green.
- `cargo clippy -p foundry --all-targets -- -D warnings` — 0 diagnostics.
- `cargo fmt --check` — clean.

A `grep` for `foundry-wallet`, `foundry_wallet`, `wallet.yaml`, and
`wallet-data` across everything except `Cargo.lock` and the historical `docs/`
record returns no matches.