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

**Building for a different target architecture (e.g. deploying to an amd64
cluster from an Apple Silicon / arm64 machine):** a plain `docker build` always
targets the *host's* architecture and gives no warning when that doesn't match
where the image will run — the mismatch only surfaces at container start as an
`exec format error` (or an equivalent silent failure, depending on the runtime).
The naive fix is to force the target platform with `buildx`:

```bash
docker buildx build --platform linux/amd64 -t foundry:latest --load .
```

**This reliably segfaults `rustc` on Apple Silicon.** `--platform linux/amd64`
does not cross-compile — it runs the *entire* amd64 toolchain, including
`rustc`/LLVM, under QEMU's user-mode CPU emulation, and rustc crashes under
that emulation on M-series Macs (`rustc -vV` or even a bare `rustc` invocation
segfaults, signal 11, before any of your code is even touched). This is a
currently open upstream issue — see
[rust-lang/rust#147026](https://github.com/rust-lang/rust/issues/147026) and
[rust-lang/rustup#3902](https://github.com/rust-lang/rustup/issues/3902) — not
something wrong with this Dockerfile or your Docker setup, and there is no
reliable QEMU flag that fixes it.

Two real ways around it:

1. **Build on a native amd64 host** (a cloud VM, a GitHub Actions `ubuntu-latest`
   runner, etc.) instead of emulating locally. No Dockerfile or command changes
   needed — just run the same `docker build`/`docker buildx build --platform
   linux/amd64 --push .` on an amd64 machine, where it's a native build rather
   than an emulated one. `.github/workflows/docker-publish.yml` already does
   exactly this on every push/tag — see [CI](#ci-automated-build--push) below
   — so in practice you shouldn't need to build+push manually at all.
2. **True cross-compilation**, if you need to keep building on Apple Silicon.
   This means rustc runs *natively* (arm64) and targets amd64 without ever
   executing amd64 machine code, so QEMU emulation of the compiler itself is
   avoided entirely. The standard tool for this in a Dockerfile is
   [`tonistiigi/xx`](https://github.com/tonistiigi/xx) (its `xx-cargo` wrapper
   handles the target triple, C toolchain and `pkg-config` setup, which matters
   here since `josekit` needs `openssl-sys` to link dynamically against the
   *target* architecture's `libssl-dev`, not the host's). This is a real
   rewrite of the builder stage of this Dockerfile — it hasn't been done here
   yet; happy to do it on request, but it needs validating against an actual
   `docker buildx` environment before trusting it in CI.

Once you have a genuinely `amd64` image (built either way), verify it before
pushing:

```bash
docker inspect foundry:latest --format '{{.Architecture}}'   # must print: amd64
```

### CI: automated build & push

`.github/workflows/docker-publish.yml` builds and pushes
`containers.digitallabor.dev/foundry/foundry` on a GitHub-hosted
`ubuntu-latest` runner — genuinely amd64, not emulated, which is exactly why
this exists (see the segfault discussion above). It runs `cargo fmt --check` +
`cargo clippy --workspace --all-targets -- -D warnings` + `cargo test
--workspace` first and only builds/pushes if those pass — mirroring the
workspace-wide gates this repo requires before any change is considered done
(see the root `AGENTS.md`).

| Trigger | Tags produced |
|---|---|
| push to `main` | `:latest`, `:sha-<short-sha>` |
| push tag `vX.Y.Z` | `:vX.Y.Z`, `:X.Y`, `:X`, `:sha-<short-sha>` |
| manual (`workflow_dispatch`) | whatever the current ref would produce |

It intentionally does **not** use `docker/setup-qemu-action` — adding it back
would reintroduce the segfault this workflow exists to avoid; if you ever need
multi-arch (`linux/amd64,linux/arm64`) images, that requires the
`tonistiigi/xx`-based cross-compilation rewrite discussed above, not QEMU.

**One-time repo setup** — two secrets under *Settings → Secrets and
variables → Actions*, matching the credentials already in
`~/dev/dl-infra-k8s/foundry/regcred.yaml` for `containers.digitallabor.dev`:

| Secret | Value |
|---|---|
| `REGISTRY_USERNAME` | the registry username (`capmin`) |
| `REGISTRY_PASSWORD` | the registry password |

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

## Wallet Attestation & Client Attestation Proof-of-Possession

Foundry gates `POST /token` on `issuer.wallet_attestation.mode`
(`disabled` / `optional` / `required`), configured per-issuer:

```yaml
issuer:
  wallet_attestation:
    mode: required
    trusted_anchors:
      - name: wallet-provider-ca
        certs: /path/to/wallet-provider-ca.pem
    pop_max_age_secs: 300   # optional; default shown
```

- `mode: disabled` — no attestation is required or checked, even if a wallet
  sends one.
- `mode: optional` — a wallet may omit the `OAuth-Client-Attestation` header
  entirely; but if it sends one, the attestation (and, since the field below,
  its accompanying proof-of-possession) MUST be valid.
- `mode: required` — a wallet MUST send `OAuth-Client-Attestation`.
- `pop_max_age_secs` (`u64`, default `300`) — the ABCA (Attestation-Based
  Client Authentication) draft's sliding-window staleness bound for the
  Client Attestation PoP JWT's `iat` claim, per `draft-ietf-oauth-
  attestation-based-client-auth` §10.6/§12.1.

**Behaviour change:** as of this release, whenever a Wallet Attestation JWT
(`OAuth-Client-Attestation`) is presented — under **both** `optional` and
`required` mode — the request MUST also carry a matching
`OAuth-Client-Attestation-PoP` header: a JWT proving possession of the
private key the attestation's `cnf.jwk` claim attests to, per
`draft-ietf-oauth-attestation-based-client-auth` §5.2/§6.2. A Wallet
Attestation presented with no PoP is now rejected with HTTP 400
`{"error": "invalid_client"}`, where previously it was accepted outright
(GAP-VCI-14). **Deployments running `wallet_attestation.mode: required` (or
`optional` with wallets that send an attestation) must upgrade their wallet
client to send the PoP header before upgrading the issuer**, or existing
wallets will start failing `/token` requests.

The PoP's `jti` is claimed exactly once via an atomic anti-replay check
(`Storage::insert_kv_if_absent`), so a captured-and-resent PoP is rejected on
its second use even if it is otherwise perfectly valid and unexpired.

---

## Logging & Observability

Every HTTP request on both listeners produces one structured log record, and
every typed error produces exactly one — so an operator can follow both what
happened and why it failed.

### Choosing a level

Three sources can set the log level. They are resolved in this order, highest
priority first:

| Priority | Source | Example |
|---|---|---|
| 1 | `RUST_LOG` environment variable | `RUST_LOG=info,foundry_verifier=debug` |
| 2 | `--log-level` CLI flag | `foundry --log-level debug serve --config config.yaml` |
| 3 | `logging.level` in the config file | see below |
| 4 | built-in default | `info` |

The same ladder applies to the output format (`--log-format` /
`logging.format`, no environment tier) and to payload logging
(`--log-sensitive` / `logging.sensitive_payloads`).

```bash
# Everything at info, but verbose verification internals
RUST_LOG=info,foundry_verifier=debug foundry serve --config config.yaml

# JSON output for a log shipper
foundry --log-format json serve --config config.yaml
```

> **A silent log usually means a typo, not a bug.** `RUST_LOG` accepts any
> target name, so a misspelled level such as `RUST_LOG=infoo` builds a valid
> filter that matches nothing — and the process then logs nothing at all, with
> no warning. Only a *syntactically* invalid directive is reported and downgraded
> to `info`.

### Configuration file

All three settings can live in `config.yaml`. The whole section is optional; a
config without it behaves exactly as before.

```yaml
logging:
  level: info                  # any EnvFilter directive
  format: human                # human | json
  sensitive_payloads: false    # DEV/TEST ONLY — see the warning below
```

### Following a request

Every access record carries these fields. They are stable names — alerting and
log queries can rely on them:

| Field | Meaning |
|---|---|
| `request_id` | Random per request; also returned in the `x-request-id` response header |
| `method` | HTTP method |
| `route` | The route **template** (`/vp/response/:id`), never the concrete path |
| `listener` | `admin` or `wallet` — the two listeners bind different ports |
| `http.status` | Response status |
| `latency_ms` | Time to produce the response |
| `error.kind` | Stable error-variant name, on failure records |
| `error.detail` | Human-readable reason, length-capped |

The level follows the status class: 2xx/3xx at `info`, 4xx at `warn`, 5xx at
`error`.

**To reconstruct one wallet interaction**, grep the domain transaction id
(`tx_id`) rather than `request_id`. A presentation spans three requests across
both listeners — `POST /admin/verification/requests`, then the wallet's
`GET /vp/request/:id` and `POST /vp/response/:id` — and `tx_id` is what ties them
together:

```bash
# Whole flow for one transaction
foundry serve --config config.yaml 2>&1 | grep 'v_1a2b3c'

# Or, if a wallet reported a failure, start from the header it saw
foundry serve --config config.yaml 2>&1 | grep '<the x-request-id value>'
```

A failed verification records which stage rejected the presentation, using the
same check names the successful path reports — `jwe_decryption`,
`sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`,
`dcql_match`, `status_check` — and the reason is also persisted on the
transaction, so it appears in the admin API and the test console rather than only
in the log.

### `sensitive_payloads` — development only

> **Do not enable this in production.** With `sensitive_payloads: true` (or
> `--log-sensitive`), `debug` and `trace` records may include raw JWEs,
> `vp_token` values, decrypted response payloads and disclosed claim values —
> that is, holder personal data. The process prints a `WARN` on startup whenever
> the flag is on.

Without the flag, no payload is logged at any level. Regardless of the flag,
these are **never** logged: private and ephemeral JWKs, the admin API key,
access tokens, `c_nonce` values and the nonce secret, pre-authorized codes,
authorization codes and transaction codes. Public keys appear only as RFC 7638
thumbprints. This is enforced by tests
(`crates/foundry/tests/logging_redaction.rs`), not by convention.

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

### Conformance Test Suite

Foundry carries a spec-conformance audit of the three protocol texts pinned in
[`docs/specs/`](docs/specs/). Every mandatory clause is adjudicated in
[`docs/conformance/openid4vc-conformance.md`](docs/conformance/openid4vc-conformance.md),
and the verdicts are backed by four test suites:

| Command | Covers |
|---|---|
| `cargo test -p foundry-issuer --test conformance_vci` | OpenID4VCI issuance engine (offers, `/token`, `/nonce`, `/credential`, holder proofs, attestations, issuer metadata) |
| `cargo test -p foundry-verifier --test conformance_vp` | OpenID4VP verification engine (request objects, client identifier prefixes, DCQL, response encryption) |
| `cargo test -p foundry --test conformance_http` | HTTP boundary in `crates/foundry/src/server.rs` (status codes, `Content-Type`, redirects, error bodies) |
| `cargo test -p foundry --test conformance_report` | The report itself — parses the Markdown and enforces its internal consistency |

All four are ordinary integration tests, so `cargo test --workspace` already
includes them. To run just the conformance suites:

```bash
cargo test -p foundry-issuer   --test conformance_vci \
  && cargo test -p foundry-verifier --test conformance_vp \
  && cargo test -p foundry          --test conformance_http \
  && cargo test -p foundry          --test conformance_report
```

#### Known gaps are `#[ignore]`d and expected to fail

Each open finding in the report's Gap Register has a test that reproduces it,
marked `#[ignore]` with a reason string citing its gap ID:

```rust
#[ignore = "GAP-VCI-03: OpenID4VCI Credential Response (L976) — binary Credential Formats MUST be base64url-encoded"]
```

These are **deliberately failing tests describing behaviour foundry does not yet
have** — not broken tests. A default `cargo test` run skips them, which is why
the suite is green. Running them surfaces the open gaps, and they *should* fail:

```bash
# Expect failures — at least one per unclosed gap
cargo test --workspace -- --ignored
```

To review the open gaps *without* running them, note that a normal (green) run
already prints each reason string next to the skipped test:

```bash
cargo test --workspace 2>&1 | grep 'ignored,'
```

Two things to know when reading those results:

- **A gap can have more than one failing test.** Where a single gap spans two
  code paths — e.g. `GAP-VCI-05`, a missing `iat` check in both `attestation.rs`
  and `proof.rs` — it is reproduced by one test per site.
- **Not every `#[ignore]`d test is a conformance gap.**
  `full_flow_issue_verify_revoke_reverify` in
  `crates/foundry/tests/e2e_full_flow.rs` carries a bare `#[ignore]` because it
  is slow, not because anything is non-conformant — it *passes* when run. Gap
  tests always carry a reason string naming their gap ID, which is exactly what
  the `grep` above filters on.

The `conformance_report` suite keeps this honest in CI: it asserts that every
gap-register entry names a test that exists, that each such test is actually
`#[ignore]`d citing its own gap ID (so an open gap can never masquerade as
passing), and that the summary counts match the clause inventory.

#### Closing a gap

1. Fix the behaviour in the relevant crate.
2. Remove the `#[ignore]` attribute — the test should now pass.
3. Update that clause's row and the summary counts in
   `docs/conformance/openid4vc-conformance.md`, and drop its Gap Register entry.
4. Run `cargo test -p foundry --test conformance_report` to confirm the report is
   still self-consistent.

The report is a living document, not a historical record — see
[`AGENTS.md`](AGENTS.md) §8.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) or `Cargo.toml` for details.
