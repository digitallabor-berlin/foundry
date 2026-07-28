# AGENTS.md — `crates/openid4vp` (VENDORED)

## ⚠️ This is a vendored owned copy, not upstream code you should refactor

Vendored from [`spruceid/openid4vp`](https://github.com/spruceid/openid4vp) at
commit `d2847dfcd07d1ea70ffc0c713ad650519d424a82` (2026-07-17). It provides the
OpenID4VP protocol baseline models used by `foundry-verifier` and
`foundry-wallet`.

Has a path dependency on the sibling `crates/openid4vp-frontend` (also vendored
from the same upstream commit, subdirectory `openid4vp-frontend/`). The path was
rewritten from `path = "openid4vp-frontend"` to `path = "../openid4vp-frontend"`
during vendoring — do not "fix" it back.

## Rules

1. **Do not restructure, rename, reformat, or "clean up" this crate.** No
   drive-by clippy fixes, no module reorganisation, no rustfmt-only churn. Every
   gratuitous diff makes future upstream cherry-picks harder.
2. **Prefer wrapping over editing.** If you need different behaviour, implement
   it in `foundry-verifier` or `foundry-core` and leave the vendored code alone.
   Only edit here when the protocol model itself is wrong or missing.
3. **Record every intentional change** per [`docs/VENDORING.md`](../../docs/VENDORING.md).
   Upstream fixes are pulled by diffing against the recorded commit and
   cherry-picking manually.
4. **Never re-add this as a crates.io dependency.** We own this copy.
5. **Never add a dependency on any `foundry-*` crate.** Vendored crates sit
   outside the workspace dependency hierarchy (root `AGENTS.md` §3).

Global invariants and verification gates: root [`AGENTS.md`](../../AGENTS.md)
§4, §5.