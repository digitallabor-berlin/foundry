# Foundry

**Foundry** is a modular, high-performance Digital Credential Issuing & Verification Service written in Rust. It implements standards including OpenID for Verifiable Credential Issuance (OpenID4VCI), OpenID for Verifiable Presentations (OpenID4VP), W3C SD-JWT VC (`dc+sd-jwt`), ISO/IEC 18013-5 mdoc, and IETF Token Status Lists.

---

## Workspace Architecture

Foundry is structured as a Rust cargo workspace comprising several modular crates:

| Crate | Path | Description |
|---|---|---|
| `foundry` | `crates/foundry` | Main binary & HTTP service providing server startup, admin API, wallet endpoints, and PKI CLI commands. |
| `foundry-core` | `crates/foundry-core` | Core data models, YAML configuration parser/validator, SQLite storage driver, PKI/cert handling, trust anchor validation, and Token Status List generation/verification. |
| `foundry-issuer` | `crates/foundry-issuer` | Framework-agnostic OpenID4VCI business logic: metadata builders, transaction lifecycle, CSPRNG status-list index allocation, and offer creation. |
| `foundry-sd-jwt-vc` | `crates/foundry-sd-jwt-vc` | SD-JWT VC issuing, disclosure calculation, holder binding (KB-JWT), and verification. |
| `foundry-mdoc` | `crates/foundry-mdoc` | ISO/IEC 18013-5 mdoc / CBOR / COSE IssuerAuth builder and DeviceAuth verifier. |
| `oid4vci` | `crates/oid4vci` | Vendored OpenID4VCI protocol models and proof verifier. |
| `openid4vp` | `crates/openid4vp` | Vendored OpenID4VP protocol types and verifier engine. |
| `openid4vp-frontend` | `crates/openid4vp-frontend` | Frontend helpers for presentation flows. |
| `foundry-wallet` | `crates/foundry-wallet` | Debug EUDI wallet CLI/TUI for exercising and inspecting `foundry`'s OpenID4VCI issuance and OpenID4VP verification flows end-to-end. See [Debug Wallet CLI/TUI](#debug-wallet-clitui-foundry-wallet) below. |

---

## Prerequisites

- **Rust:** Version 1.97 or later (edition 2021). See `rust-toolchain.toml`.
- **Cargo:** Included with Rust installation (`rustup`).

---

## Building the Project

To build the entire workspace:

```bash
cargo build --workspace
```

To build in release mode:

```bash
cargo build --workspace --release
```

To build only the `foundry` binary CLI tool:

```bash
cargo build -p foundry
```

---

## Docker

A multi-stage `Dockerfile` at the repo root builds and packages the `foundry` server binary. The builder stage uses `rust:1.97-slim-bookworm` (matching `rust-toolchain.toml`) with `pkg-config`/`libssl-dev` installed, since `josekit` depends on a dynamically linked `openssl-sys`. The runtime stage is `debian:bookworm-slim` with `ca-certificates`/`libssl3` and runs as a non-root `foundry` user.

### Building the image

```bash
docker build -t foundry:latest .
```

(Podman works as a drop-in replacement: `podman build -t foundry:latest .`)

### Running the image

The image expects `config.yaml`, the key material, and trust anchors it references to be bind-mounted rather than baked in (they're config-driven via paths relative to the config file, and already gitignored). The default entrypoint runs `foundry`, with `CMD` set to `serve --config /app/config.yaml`:

```bash
docker run --rm \
  -v $PWD/config.yaml:/app/config.yaml \
  -v $PWD/keys:/app/keys \
  -v $PWD/trust:/app/trust \
  -v $PWD/foundry.db:/app/foundry.db \
  -p 8443:8443 -p 9000:9000 \
  foundry:latest
```

The wallet-facing (`8443`) and admin (`9000`) listeners are both plain HTTP inside the container — TLS is expected to be terminated externally (e.g. a reverse proxy), same as when running the binary directly.

Other CLI subcommands work the same way by overriding the default command, e.g. to run `quickstart` against a mounted output directory:

```bash
docker run --rm -v $PWD/dev:/app/dev foundry:latest quickstart --dir /app/dev --out-config /app/dev/config.yaml
```

*Note: the image runs as a fixed non-root user (uid 999). If a bind-mounted host directory isn't writable by that uid, pass `--user "$(id -u):$(id -g)"` to run as your own user instead.*

---

## Running the Project

Foundry includes CLI commands for setting up a development environment, managing keys and certificates, validating configuration files, and running the HTTP service.

### 1. Quickstart (Development Setup)

Generate a self-signed dev PKI (Root CA + leaf certificates for issuer, verifier, and status list) along with a ready-to-run `config.yaml`:

```bash
cargo run -p foundry -- quickstart
```

*Note: The quickstart command is for development/testing only.*

### 2. Validating Configuration

Validate your YAML configuration file against key files and trust anchors:

```bash
cargo run -p foundry -- config validate --config config.yaml
```

### 3. Running the HTTP Server

Boot the dual-listener HTTP service (Admin API on `127.0.0.1:9000` and Wallet-facing API on `0.0.0.0:8443` by default):

```bash
cargo run -p foundry -- serve --config config.yaml
```

#### Exposed Endpoints

**Wallet-facing Server (`0.0.0.0:8443`):**
- `GET /.well-known/openid-credential-issuer` — OpenID4VCI Credential Issuer Metadata
- `GET /.well-known/oauth-authorization-server` — OAuth 2.0 Authorization Server Metadata
- `GET /api-docs` — Interactive OpenAPI/Swagger UI for the wallet-facing (OpenID4VCI/OpenID4VP) endpoints
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON) for the wallet-facing endpoints

**Admin Server (`127.0.0.1:9000`):**
- `GET /health` — Health check endpoint
- `GET /ready` — Readiness check endpoint (verifies storage connectivity)
- `GET /api-docs` — Interactive OpenAPI/Swagger UI (enabled by default; see [API Documentation](#api-documentation-openapi--swagger-ui) below)
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON)
- `GET /console` — Embedded HTML/JS test console for triggering issuance/verification flows (enabled by default; see [Admin Test Console](#admin-test-console) below)
- `POST /admin/issuance/offers` — Create credential offers (requires Bearer token if `admin.api_key` is set)

#### API Documentation (OpenAPI / Swagger UI)

Foundry auto-generates **two independent** OpenAPI 3.x specifications — one for the admin API, one for the wallet-facing OpenID4VCI/OpenID4VP protocol endpoints — each served from its own listener.

**Admin API** (`127.0.0.1:9000` by default):
- Swagger UI: `http://127.0.0.1:9000/api-docs`
- Raw spec: `http://127.0.0.1:9000/api-docs/openapi.json`
- Toggle: `server.admin.swagger_ui_enabled` (default `true`)
- Startup file: `openapi.json`

**Wallet-facing API** (`0.0.0.0:8443` by default):
- Swagger UI: `http://localhost:8443/api-docs`
- Raw spec: `http://localhost:8443/api-docs/openapi.json`
- Toggle: `server.wallet_facing.swagger_ui_enabled` (default `true`)
- Startup file: `openapi-wallet.json`

All four docs endpoints are unauthenticated, served alongside `/health`/`/ready` on the admin listener and alongside the protocol endpoints on the wallet-facing listener. Since the wallet-facing listener binds `0.0.0.0` by default (publicly reachable), set `server.wallet_facing.swagger_ui_enabled: false` in production if you don't want the docs UI exposed on the public interface — the raw JSON spec at `/api-docs/openapi.json` remains available either way (it does not carry secrets, only route/schema shapes).

Both `openapi.json` and `openapi-wallet.json` are written to the working directory on every `serve` startup — convenient for generating client SDKs or importing into tools like Postman/Insomnia.

#### Example: Creating an Offer via Admin API

```bash
curl -X POST http://127.0.0.1:9000/admin/issuance/offers \
  -H "Authorization: Bearer dev-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type_id": "pid",
    "claims": {
      "given_name": "Alice",
      "birthdate": "1990-01-01"
    },
    "tx_code_required": false
  }'
```

#### Admin Test Console

`foundry` serves a self-contained HTML/JS test console at `GET /console` on
the Admin listener (`http://127.0.0.1:9000/console` by default) — no build
step, no external dependencies (a small QR-code library is vendored inline).
It lets you trigger the two admin flows from a browser instead of hand-rolling
`curl` calls, and produces a QR code a real wallet app can scan:

- **Issuance**: enter a `credential_type_id` and `claims` JSON, click
  "Create Offer" — get back the `credential_offer_uri` as copyable text and
  as a QR code. Scan it with a real wallet (or feed it to `foundry-wallet
  issue --offer-uri <uri>`) to complete the flow.
- **Verification**: pick a named query (`named_query_ref`) or paste raw
  `dcql_query` JSON, click "Create Verification Request" — get back the
  `openid4vp_uri`/`request_uri` as copyable text and as a QR code. The page
  auto-polls the request's status and shows `verified`, each check's
  pass/fail, and the disclosed claims once the wallet responds.

The console only calls the existing Admin API (same endpoints as the `curl`
example above) — paste your Admin API key into the field at the top of the
page; it is remembered in the browser's `localStorage` for convenience,
since the Admin listener is loopback-only by default. Disable it entirely
with `server.admin.console_enabled: false` if you don't want it exposed;
like Swagger UI, this only affects the Admin listener.

### 4. Key & Certificate Management CLI

Foundry provides built-in tools for generating EC private keys (PKCS#8 PEM) and issuing X.509 certificates.

#### Generate an EC Private Key (ES256 / P-256)
```bash
cargo run -p foundry -- keys generate --alg ES256 --out private_key.pem
```

#### Create a Root CA
```bash
cargo run -p foundry -- cert new-ca --cn "My Root CA" --out-cert ca.pem --out-key ca-key.pem --days 3650
```

#### Issue a Leaf Certificate
```bash
cargo run -p foundry -- cert issue \
  --ca ca.pem \
  --key ca-key.pem \
  --cn "Issuer Service" \
  --san localhost \
  --out-cert leaf.pem \
  --out-key leaf-key.pem \
  --days 365
```

---

## Debug Wallet CLI/TUI (`foundry-wallet`)

`foundry-wallet` is a debug EUDI wallet used to drive and inspect `foundry`'s
OpenID4VCI issuance and OpenID4VP verification flows end-to-end, either
interactively (a `ratatui` terminal UI) or headlessly (JSON-in/JSON-out CLI
subcommands, suitable for scripts and AI agents). v1 scope is SD-JWT VC only
(mdoc support is future work), with coarse accept/decline consent (no
fine-grained claim selection yet).

All credentials, keys, certificates, and an append-only event log are stored
as plain files under a configurable `wallet-data/` directory so they can be
inspected directly while debugging:

```
wallet-data/
├── keys/                          # unbound/global keys
├── credentials/
│   └── <credential_id>/
│       ├── credential.sdjwt       # compact SD-JWT VC
│       ├── payload.json           # decoded header/payload/disclosed claims
│       ├── holder_key.pem         # key bound to this credential
│       └── metadata.json          # vct, issuer, trust_valid, ...
├── trust/                         # trust anchor certs
└── log/
    └── events.jsonl                # append-only log of every step taken
```

### Configuration

`foundry-wallet` is configured entirely via a YAML file; `--config` is
required on every invocation (there is no default path):

```bash
cargo run -p foundry-wallet -- --config wallet.yaml <subcommand>
```

The config declares the issuer/verifier admin & wallet-facing base URLs,
named issuance/verification presets (for one-command "create and offer" /
"create and request" flows against the admin API), and trust validation
settings — including a toggle to disable X.509 trust validation entirely
(useful when deliberately debugging an untrusted issuer/verifier; when
disabled, a warning is logged and the flow proceeds anyway).

Trust validation, when enabled, is deliberately **asymmetric**: a failed
check on an *issuer's* credential never blocks storage (the credential is
still saved with `trust_valid: false` recorded, so a broken issuer's output
can still be inspected), but a failed check on a *verifier's* signed request
object **does** block the whole flow (there's no artifact worth keeping if
the request itself can't be trusted).

All HTTP requests and responses — including bearer tokens and full bodies —
are logged verbatim to `log/events.jsonl` with **no redaction**; this is a
deliberate debugging feature, not an oversight.

### Interactive TUI

```bash
cargo run -p foundry-wallet -- --config wallet.yaml tui
# or simply omit the subcommand:
cargo run -p foundry-wallet -- --config wallet.yaml
```

Navigate the main menu (Trigger Issuance / Trigger Verification / Browse
Credentials / Event Log / Quit) with the arrow keys and Enter; on the
verification preset screen, `a` accepts and `d` declines the request.

### Headless CLI

Every subcommand prints machine-readable JSON to stdout and exits `0` on
success, or `{"error": ..., "kind": ...}` to stderr and exits `1` on
failure:

```bash
# Issue a credential from a named preset (or --offer-uri <deep-link>)
cargo run -p foundry-wallet -- --config wallet.yaml issue --preset pid

# Respond to a verification request from a named preset (or --request-uri)
cargo run -p foundry-wallet -- --config wallet.yaml verify --preset dcql1 --consent accept

# Inspect stored credentials
cargo run -p foundry-wallet -- --config wallet.yaml credentials list
cargo run -p foundry-wallet -- --config wallet.yaml credentials show --id <credential_id>

# Tail the event log
cargo run -p foundry-wallet -- --config wallet.yaml events tail --n 20
```

See `docs/superpowers/specs/2026-07-24-foundry-wallet-cli-design.md` for the
full design rationale and `docs/superpowers/plans/2026-07-24-foundry-wallet-cli.md`
for the implementation plan.

---

### End-to-End Test (real subprocess, issue → verify → revoke → re-verify)

A full end-to-end test spawns the real `foundry` binary (`quickstart` then
`serve`, on dynamically-selected free ports) and drives it purely over HTTP:
creates a credential offer, issues an SD-JWT VC `pid` credential, verifies it
via OpenID4VP (happy path), revokes it via `foundry status-list set`, and
re-verifies to confirm `verified: false` with `status_check` failing. It is
excluded from the default `cargo test --workspace` run (slower, binds real OS
ports) — run it explicitly:

```bash
cargo test -p foundry --test e2e_full_flow -- --ignored
```

See `docs/superpowers/specs/2026-07-23-foundry-e2e-full-flow-design.md` for
the design rationale.

## Testing

Run all unit and integration tests across the workspace:

```bash
cargo test --workspace
```

Run tests for a specific crate:

```bash
cargo test -p foundry-issuer
cargo test -p foundry-sd-jwt-vc
cargo test -p foundry-mdoc
cargo test -p foundry-core
cargo test -p foundry
```

Run code formatting and linter checks:

```bash
# Check formatting
cargo fmt --all -- --check

# Run Clippy
cargo clippy --workspace --all-targets -- -D warnings
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) or `Cargo.toml` for details.
