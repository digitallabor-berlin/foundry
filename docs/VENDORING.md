# Vendored Crates

These crates are **owned copies**, not upstream dependencies. We control the
protocol implementation directly.

| Crate | Upstream | Commit vendored | Date |
|-------|----------|-----------------|------|
| oid4vci | https://github.com/spruceid/oid4vci-rs | 7cfd5a012229de08aac363b27a41e226b494f9cc | 2026-07-17 |
| openid4vp | https://github.com/spruceid/openid4vp | d2847dfcd07d1ea70ffc0c713ad650519d424a82 | 2026-07-17 |
| openid4vp-frontend | https://github.com/spruceid/openid4vp (subdirectory `openid4vp-frontend/`) | d2847dfcd07d1ea70ffc0c713ad650519d424a82 | 2026-07-17 |

## Layout notes

- `oid4vci-rs` is a single crate at the repo root (package `oid4vci`). Vendored
  as-is into `crates/oid4vci`. The `[[example]]` entries were removed since
  their source files (`examples/...`) were not vendored (only `src/`,
  `Cargo.toml`, `README.md` were copied per policy); the crate does not depend
  on them to build as a library.
- `openid4vp` is a Cargo workspace-free crate at the repo root (package
  `openid4vp`) with a path-dependency on a sibling crate `openid4vp-frontend`
  living in `openid4vp/openid4vp-frontend/`. Because the library crate has a
  path dependency on this sibling, it was vendored too, into
  `crates/openid4vp-frontend`. The path reference in
  `crates/openid4vp/Cargo.toml` was updated from `path = "openid4vp-frontend"`
  to `path = "../openid4vp-frontend"` to reflect its new location as a
  sibling workspace member instead of a nested directory.
- Neither upstream repo declares a `[workspace]` table in the vendored
  `Cargo.toml`, so no workspace-table removal or `xxx.workspace = true`
  rewriting was needed. All dependencies in both crates were already pinned to
  concrete versions (or git revisions for `open-auth2` and `isomdl` in
  `oid4vci`, and `josekit` in `openid4vp` — left as-is, since these are
  upstream's own pinned external git dependencies, not workspace-inheritance
  artifacts).

## Update policy
Changes are made directly in `crates/`. To pull upstream fixes, diff against the
recorded commit and cherry-pick manually. Never re-add as a crates.io dependency.