# End-to-End Test (real subprocess, issue → verify → revoke → re-verify)

A full end-to-end test spawns the real `foundry` binary (`quickstart` then
`serve`, on dynamically-selected free ports) and drives it purely over HTTP:
creates a credential offer, issues an SD-JWT VC `pid` credential, verifies it
via OpenID4VP (happy path), revokes it via `foundry status-list set`, and
re-verifies to confirm `verified: false` with `status_check` failing. It is
`#[ignore]`d, so it is excluded from the default `cargo nextest run --workspace`
run (slower, binds real OS ports) — run it explicitly:

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

See `docs/superpowers/specs/2026-07-23-foundry-e2e-full-flow-design.md` for
the design rationale.
