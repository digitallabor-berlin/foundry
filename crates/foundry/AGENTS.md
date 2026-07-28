# AGENTS.md — `crates/foundry`

## Purpose

The **binary and wiring layer**: the `foundry` CLI, the Axum HTTP server with
its two independent listeners (admin + wallet-facing), OpenAPI spec generation,
admin bearer-token auth, logging setup, and the background status-list sweeper.

**Not** in scope here: protocol logic (`foundry-issuer`, `foundry-verifier`),
credential format encoding (`foundry-sd-jwt-vc`, `foundry-mdoc`), and
storage/config/crypto primitives (`foundry-core`). This crate only wires those
together and maps their errors onto HTTP.

Build/run/CLI usage is documented in [`README.md`](../../README.md) — not
restated here.

## Position in the Dependency Graph

- **Depends on:** `foundry-core`, `foundry-issuer`, `foundry-verifier`,
  `foundry-sd-jwt-vc`, `foundry-mdoc`, vendored `openid4vp`, plus `axum`,
  `tokio`, `clap`, `utoipa`.
- **Consumed by:** `foundry-wallet` — for real-subprocess E2E tests only.
- **Must never be depended on** by any engine or format crate.

Full layering rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
|---|---|
| `lib.rs` | Declares `admin_auth`, `cli`, `commands`, `logging`, `openapi`, `server`; re-exports the OpenAPI surface |
| `main.rs` | `#[tokio::main]`; parses `Cli`, calls `logging::init`, then **dispatches the `Command` match inline** (there is no `commands::execute`) |
| `cli.rs` | Clap definitions: `Cli`, `LogFormat`, `Command`, and the sub-action enums `ConfigAction`, `KeysAction`, `CertAction`, `StatusListCommands` |
| `commands.rs` | Non-serve command implementations: `keys_generate`, `cert_new_ca`, `cert_issue`, `quickstart`, `status_list_get`, `status_list_set`, `status_list_token` |
| `server.rs` | `AppState`, both routers, every handler, all four error mappers, `spawn_sweeper`, and `serve` |
| `admin_auth.rs` | `AdminApiKey` (resolved from config literal or env var) and the `require_api_key` middleware |
| `openapi.rs` | `AdminApiDoc` / `WalletApiDoc` (`utoipa::OpenApi`) and `generate_admin_openapi_spec` / `generate_wallet_openapi_spec` |
| `logging.rs` | `init(level, format)` — tracing subscriber, human or JSON |

### Route table — admin listener (`admin_router`, binds `server.admin.bind`)

| Path | Method | Auth | Calls |
|---|---|---|---|
| `/health` | GET | none | `health` — static OK |
| `/ready` | GET | none | `ready` → `storage.purge_expired(0)`; 200 or 503 |
| `/api-docs`, `/api-docs/openapi.json` | GET | none | Swagger UI if `admin.swagger_ui_enabled`, else `openapi_json_handler` (`AdminApiDoc`) |
| `/console` | GET | none | `console_handler` — **only mounted when `admin.console_enabled`** |
| `/admin/issuance/offers` | POST | **Bearer** | `create_offer_handler` → `foundry_issuer::create_offer` |
| `/admin/verification/requests` | POST | **Bearer** | `create_verification_handler` → `foundry_verifier::create_verification_request` |
| `/admin/verification/requests/:id` | GET | **Bearer** | `get_verification_handler` → `foundry_verifier::load_verification_transaction` |

### Route table — wallet-facing listener (`wallet_router`, binds `server.wallet_facing.bind`)

| Path | Method | Calls |
|---|---|---|
| `/.well-known/openid-credential-issuer` | GET | `foundry_issuer::build_issuer_metadata` |
| `/.well-known/oauth-authorization-server` | GET | `foundry_issuer::build_authorization_server_metadata` |
| `/token` | POST | `foundry_issuer::handle_token_request` |
| `/nonce` | POST | `foundry_issuer::refresh_c_nonce` |
| `/credential` | POST | `foundry_issuer::handle_credential_request` |
| `/vp/request/:id` | GET | `foundry_verifier::build_signed_request_object` |
| `/vp/response/:id` | POST | `foundry_verifier::verify_vp_response` |
| `/statuslists/:id` | GET | `foundry_core::status_list` (signed Status List Token) |
| `/api-docs/openapi.json` | GET | Swagger UI or `wallet_openapi_json_handler` (`WalletApiDoc`) |

No admin route is mounted on the wallet router, and vice versa.

## Key Public Types & Entry Points

- **`server::serve(cfg: Config) -> anyhow::Result<()>`** — the real server entry
  point: writes both OpenAPI specs, connects storage, spawns the sweeper,
  resolves the admin key, builds both routers, binds both listeners, and
  `tokio::try_join!`s them.
- `server::AppState { storage: Arc<dyn Storage>, config: Arc<Config> }`
- `server::admin_router(state, api_key) -> Router`, `server::wallet_router(state) -> Router`
- `server::spawn_sweeper(storage, interval_secs) -> JoinHandle<()>`
- `admin_auth::AdminApiKey(pub Option<String>)` + `AdminApiKey::resolve(&AdminConfig)`,
  `admin_auth::require_api_key`
- `openapi::{AdminApiDoc, WalletApiDoc, generate_admin_openapi_spec, generate_wallet_openapi_spec}`
- `cli::{Cli, Command, LogFormat, ConfigAction, KeysAction, CertAction, StatusListCommands}`
- `logging::init(level: &str, format: LogFormat)`
- Error mappers in `server.rs`: `admin_error_response`, `wallet_error_response`,
  `verifier_admin_error_response`, `verifier_wallet_error_response`

## Binding Invariants

- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` in handlers.**
  `foundry::server` is named explicitly in the rule; return Axum error responses
  — full rule: root [AGENTS.md](../../AGENTS.md) §4.1.
- **The policy-vs-structural HTTP contract is implemented HERE**, in
  `verifier_wallet_error_response`: `Decryption | Failed | Serialization` → 400
  `invalid_request`; `StatusUnavailable` → 502 `status_unavailable`; everything
  else → 500. Policy failures never reach it — they return 200 with
  `verified: false`. Editing this `match`, or adding a `VerificationError`
  variant without extending it, silently violates the contract — full rule: root
  [AGENTS.md](../../AGENTS.md) §4.3.
- **Issuance mapping** lives in `wallet_error_response` (`InvalidGrant` /
  `InvalidProof` / `InvalidRequest` → 400, `StatusListExhausted` → 503, else
  500) and `admin_error_response` (`UnknownCredentialType` / `ClaimValidation`
  → 400, `StatusListExhausted` → 503, else 500).
- **Admin routes stay on the admin listener behind `require_api_key`.** Never
  mount an `/admin/*` route on `wallet_router`, and never add a route inside the
  `authenticated` group's `route_layer` without intending auth.
- **Every endpoint change must be reflected in the OpenAPI specs** via `utoipa`
  annotations in `openapi.rs` — full rule: root [AGENTS.md](../../AGENTS.md) §6.
- **Gates:** `cargo test --workspace`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo fmt --check` — root [AGENTS.md](../../AGENTS.md) §5.

## Tests

Inline `#[cfg(test)]` modules live in `openapi.rs`, `admin_auth.rs`, and
`cli.rs`. Everything else is covered by the integration suite under `tests/` —
see [`tests/AGENTS.md`](tests/AGENTS.md) for the per-file coverage map.

```bash
cargo test -p foundry
cargo test -p foundry --test e2e_full_flow
```

## Gotchas

- **Admin auth is `Authorization: Bearer <key>`, not an `x-api-key` header.**
  See `require_api_key`.
- **If no admin key is configured, auth is a silent no-op.**
  `AdminApiKey::resolve` returns `None` when both `admin.api_key` and
  `admin.api_key_env` are unset/unresolvable, and `require_api_key` then passes
  every request through. `serve` only logs a warning
  ("admin endpoints are UNAUTHENTICATED (dev only)"). Never rely on the
  middleware being active without checking config.
- **`serve()` overwrites `openapi.json` and `openapi-wallet.json` in the process
  working directory on every startup.** Running the server from the repo root
  therefore mutates two tracked files. This — not the CLI — is what actually
  keeps the specs current, and it is why a stale spec shows up as a spurious
  diff after any local `serve` or E2E test run.
- **The `openapi` CLI subcommand writes only the ADMIN spec.**
  `foundry openapi --out <path>` calls `generate_admin_openapi_spec` alone; it
  does not emit `openapi-wallet.json`. To refresh both, run `serve` (or write
  the wallet spec explicitly).
- **The sweeper IS a background daemon.** `serve` calls
  `spawn_sweeper(storage, 60)`, so expired rows are purged every 60 seconds for
  the process lifetime. `/ready` additionally calls `purge_expired(0)`. Its
  `JoinHandle` is bound to `_sweeper` and never awaited — it dies with the
  process.
- **`/console` and Swagger UI are config-gated and change the route table.**
  `admin.console_enabled` and `admin.swagger_ui_enabled` decide whether
  `/console` exists at all and whether `/api-docs/openapi.json` is served by
  Swagger UI or the plain handler. Tests must set these explicitly.
- **`assets/console.html` embeds a vendored QR library with a provenance
  comment.** Do not delete that comment, and do not reintroduce a CDN
  dependency (it exists for air-gapped deployment) or dynamic `innerHTML` (prior
  fixes deliberately removed it).
- **Both listeners must bind successfully** — `serve` binds them sequentially
  and propagates a bind error via `?`, so a port clash on either one aborts
  startup with an error (it does not panic, and it does not fall back to a
  single listener).