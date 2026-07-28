# Add Dockerfile for building and deploying the foundry server

**Date:** 2026-07-28
**Type:** small-feature

## Problem
The `foundry` binary crate had no container packaging — no way to build a
production image or deploy the server via Docker/Podman.

## Approach
A multi-stage Dockerfile: a `rust:1.97-slim-bookworm` builder stage (matching
`rust-toolchain.toml` exactly) with `pkg-config`/`libssl-dev` installed
(required because `josekit` pulls in a dynamically-linked, non-vendored
`openssl-sys` v0.9.117 — confirmed via `cargo tree -i openssl`), and a
`debian:bookworm-slim` runtime stage with `ca-certificates`/`libssl3` and a
non-root `foundry` user. Considered `cargo-chef` for smarter layer caching;
rejected for now as unnecessary complexity (YAGNI) for a first pass.

Default `CMD` is `serve --config /app/config.yaml`; config, keys, trust
anchors, and the SQLite storage path are expected to be bind-mounted as
volumes rather than baked into the image (they're already gitignored and
config-driven via relative paths resolved from the config file's directory).

## Changes
- `Dockerfile` — multi-stage build (builder + runtime), non-root user,
  `EXPOSE 8443 9000` (wallet-facing + admin listeners), volume-friendly
  layout.
- `.dockerignore` — excludes `target/`, `.git/`, key/trust/db material, and
  other local-only artifacts from the build context.

## Tests
No unit tests apply to a Dockerfile. Verified manually via Podman
(`podman machine start` + `podman build`):
- `podman build` completes successfully end-to-end.
- `foundry --help` runs correctly from the built image.
- `foundry quickstart --dir /out --out-config /out/config.yaml` (bind-mounted
  volume, run as `--user "$(id -u):$(id -g)"` to work around bind-mount
  UID/GID mismatch with the image's fixed non-root `foundry` user, uid 999)
  generates a dev PKI + config successfully.
- `foundry serve --config /app/config.yaml` boots both listeners
  (`admin bind=0.0.0.0:9000`, `wallet-facing bind=0.0.0.0:8443` — TLS is
  terminated externally, not by the app itself, per `server.rs`).
- `GET /health` on the admin port returns `200 ok`; the wallet-facing port
  responds (404 for the unrouted path, confirming the listener is live —
  `/health` only exists on the admin router).