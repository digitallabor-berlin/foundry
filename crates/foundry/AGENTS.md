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
  `foundry-sd-jwt-vc`, `foundry-mdoc`, plus `axum`, `tokio`, `clap`, `utoipa`.
- **Consumed by:** nothing — this is the top of the dependency graph.
- **Must never be depended on** by any engine or format crate.

Full layering rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
|---|---|
| `lib.rs` | Declares `admin_auth`, `cli`, `commands`, `http_log`, `log_capture`, `logging`, `openapi`, `server`; re-exports the OpenAPI surface |
| `main.rs` | `#[tokio::main]`; parses `Cli`, **best-effort-loads the config to shape the subscriber**, calls `logging::init`, then **dispatches the `Command` match inline** (there is no `commands::execute`) |
| `cli.rs` | Clap definitions: `Cli`, `LogFormat` (+ `From` into the core `LogFormat`), `Command::config_path`, and the sub-action enums `ConfigAction`, `KeysAction`, `CertAction`, `StatusListCommands` |
| `commands.rs` | Non-serve command implementations: `keys_generate`, `cert_new_ca`, `cert_issue`, `quickstart`, `status_list_get`, `status_list_set`, `status_list_token` |
| `server.rs` | `AppState`, both routers, every handler, all four error mappers, `spawn_sweeper`, and `serve` |
| `admin_auth.rs` | `AdminApiKey` (resolved from config literal or env var) and the `require_api_key` middleware |
| `openapi.rs` | `AdminApiDoc` / `WalletApiDoc` (`utoipa::OpenApi`) and `generate_admin_openapi_spec` / `generate_wallet_openapi_spec` |
| `logging.rs` | `resolve_level` / `resolve_format` / `resolve_sensitive` (precedence `RUST_LOG` > CLI > config > default), `build_filter`, and `init` |
| `http_log.rs` | `with_access_log(router, listener)` — per-request correlation span and one access record; sets `x-request-id` |
| `log_capture.rs` | Capturing `tracing` layer used by tests to assert on what was logged |

### Route table — admin listener (`admin_router`, binds `server.admin.bind`)

| Path | Method | Auth | Calls |
|---|---|---|---|
| `/health` | GET | none | `health` — static OK |
| `/ready` | GET | none | `ready` → `storage.purge_expired(0)`; 200 or 503 |
| `/api-docs`, `/api-docs/openapi.json` | GET | none | Swagger UI if `admin.swagger_ui_enabled`, else `openapi_json_handler` (`AdminApiDoc`) |
| `/console` | GET | none | `console_handler` — **only mounted when `admin.console_enabled`** |
| `/admin/issuance/offers` | POST | **Bearer** | `create_offer_handler` → `foundry_issuer::create_offer` |
| `/admin/issuance/offers/:id` | GET | **Bearer** | `get_issuance_offer_handler` → `foundry_issuer::load_transaction`, projected to `AdminIssuanceStatus` |
| `/admin/verification/requests` | POST | **Bearer** | `create_verification_handler` → `foundry_verifier::create_verification_request` |
| `/admin/verification/requests/:id` | GET | **Bearer** | `get_verification_handler` → `foundry_verifier::load_verification_transaction` |

### Route table — wallet-facing listener (`wallet_router`, binds `server.wallet_facing.bind`)

| Path | Method | Calls |
|---|---|---|
| `/.well-known/openid-credential-issuer` | GET | `foundry_issuer::build_issuer_metadata` |
| `/.well-known/oauth-authorization-server` | GET | `foundry_issuer::build_authorization_server_metadata` |
| `/token` | POST | `foundry_issuer::handle_token_request` |
| `/nonce` | POST | `foundry_issuer::issue_nonce` — **unauthenticated** (OpenID4VCI §7.1); responds with `Cache-Control: no-store` (§7.2) |
| `/challenge` | POST | `foundry_issuer::issue_attestation_challenge` — **unauthenticated** (mirrors `/nonce`), **conditionally registered**: only mounted when `issuer.wallet_attestation.challenge_mode != Disabled` (ABCA §8); responds with `Cache-Control: no-store` |
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
- **Gates are scoped by default:** per task, run `cargo test -p foundry`, plus
  `cargo clippy -p foundry --all-targets -- -D warnings` and
  `cargo fmt --check`. Save `cargo test --workspace` for the end of a
  development cycle or when unsure of the blast radius — **not** between tasks.
  Full rule: root [AGENTS.md](../../AGENTS.md) §5.

## Tests

Inline `#[cfg(test)]` modules live in `openapi.rs`, `admin_auth.rs`, `cli.rs`,
`logging.rs`, `http_log.rs`, `log_capture.rs`, and `server.rs`. Everything else
is covered by the integration suite under `tests/` — see
[`tests/AGENTS.md`](tests/AGENTS.md) for the per-file coverage map.

```bash
cargo test -p foundry
cargo test -p foundry --test e2e_full_flow
```

## Gotchas

- **`AdminIssuanceStatus` is a deliberate narrowing, not laziness.**
  `get_issuance_offer_handler` must never return `pre_authorized_code` or
  `access_token`: both are live bearer credentials against the wallet-facing
  listener, so echoing them would let an admin-key holder redeem an offer meant
  for a wallet. `tx_code` *is* returned on purpose — it is surfaced nowhere else,
  and out-of-band relay to the operator is its entire function. Enforced by
  `offer_status_never_returns_bearer_credentials_or_claims` in
  `tests/issuer_offers.rs`. Note the contrasting older precedent:
  `get_verification_handler` still returns its whole `VerificationTransaction`,
  `ephem_private_jwk` included — a known wart, not a pattern to copy.
- **`POST /vp/response/:id` takes a form-encoded body, NOT a bare JWE.** The
  verifier advertises `response_mode: direct_post.jwt`, so per OpenID4VP 1.0
  §8.2/§8.3 the wallet sends `application/x-www-form-urlencoded` with the JWE in
  a **`response`** parameter; `post_response_handler` parses it with
  `serde_html_form` into `VpResponseForm`. Never revert this to a bare `String`
  body extractor: consuming the raw body feeds `response=eyJhbGci…` straight to
  josekit, which base64url-decodes the literal parameter name and fails with
  `Invalid JWE format: Invalid symbol 61, offset 8` (`'='` at index 8 — the
  ninth byte of `response=`). Parsing happens **before** the transaction lookup,
  so a malformed body is a deterministic 400 rather than 400-or-404 by id. The
  form struct must never gain `deny_unknown_fields` — §8 permits extra members
  such as `state`.
- **Admin auth is `Authorization: Bearer <key>`, not an `x-api-key` header.**
  See `require_api_key`.
- **If no admin key is configured, auth is a silent no-op.**
  `AdminApiKey::resolve` returns `None` when both `admin.api_key` and
  `admin.api_key_env` are unset/unresolvable, and `require_api_key` then passes
  every request through. `serve` only logs a warning
  ("admin endpoints are UNAUTHENTICATED (dev only)"). Never rely on the
  middleware being active without checking config.
- **`log_capture.rs` is deliberately `pub`, not `#[cfg(test)]`.** Integration
  tests under `tests/` link the library compiled *without* `cfg(test)`, so a
  gated helper would be invisible to them — including the redaction suite, which
  is the only test proving no secret reaches the log. Moving it behind
  `cfg(test)` silently disables that guarantee.
- **`main.rs` loads the config twice, on purpose.** The subscriber must exist
  before anything worth logging happens, but `logging:` lives in the config file.
  So `main` best-effort-loads it (discarding the error) to choose log settings,
  and the matched arm reuses that value where it succeeded. The authoritative
  load still runs in the arm, so a broken config still fails with its typed
  `ConfigError`.
- **`logging::init` must be called exactly once per process** —
  `tracing_subscriber`'s `init()` panics on a second call. Tests use
  `log_capture::capture_layer` with a scoped subscriber instead.
- **Do not delete `log_capture::keep_interest_cache_resolvable` — it looks inert
  and is not.** `tracing-core` caches `Interest` per callsite in a
  process-global slot, and while at most one dispatcher is registered it
  computes that verdict from *the registering thread's own* subscriber. A test
  that calls a logging code path without installing a subscriber then caches
  `Interest::never()` for every thread, silently emptying a concurrent test's
  capture buffer. The two permanently-registered dispatchers keep that fast path
  disarmed. Removing them reintroduces a ~15%-per-process flake in
  `server::tests` *and* makes the `logging_redaction.rs` "secret appears
  nowhere" assertions pass vacuously. Guarded by
  `log_capture::tests::a_subscriberless_thread_cannot_silence_a_capture`, which
  is deterministic when run alone.
- **Error logging lives inside the four mappers, never at their call sites.**
  Every typed error passes through exactly one mapper exactly once, so that
  placement is what makes coverage complete and double-logging impossible. A
  handler that returns a bare `StatusCode` must call `internal_error(..)`; a test
  asserts no `map_err(|_| StatusCode::…)` survives in this file.
- **`serve()` overwrites `openapi.json` and `openapi-wallet.json` in the process
  working directory on every startup.** Running the server from the repo root
  therefore mutates two tracked files. This — not the CLI — is what actually
  keeps the specs current, and it is why a stale spec shows up as a spurious
  diff after any local `serve` or E2E test run.
- **The `openapi` CLI subcommand defaults to the ADMIN spec; pass `--wallet` for
  the wallet-facing one.** `foundry openapi --out openapi.json` calls
  `generate_admin_openapi_spec`; `foundry openapi --wallet --out
  openapi-wallet.json` calls `generate_wallet_openapi_spec`. Both are verified to
  reproduce the committed files byte-identically.
- **Both committed specs are drift-tested.**
  `tests/openapi_endpoints.rs` compares `openapi.json` and `openapi-wallet.json`
  against generator output as parsed JSON, and the failure message names the
  regeneration command. A change to any `#[utoipa::path]` annotation that is not
  accompanied by regenerated specs now fails the suite instead of drifting
  silently.
- **The sweeper IS a background daemon.** `serve` calls
  `spawn_sweeper(storage, 60)`, so expired rows are purged every 60 seconds for
  the process lifetime. `/ready` additionally calls `purge_expired(0)`. Its
  `JoinHandle` is bound to `_sweeper` and never awaited — it dies with the
  process.
- **`/console` and Swagger UI are config-gated and change the route table.**
  `admin.console_enabled` and `admin.swagger_ui_enabled` decide whether
  `/console` exists at all and whether `/api-docs/openapi.json` is served by
  Swagger UI or the plain handler. Tests must set these explicitly.
- **`/challenge` is config-gated and changes the route table too.**
  `issuer.wallet_attestation.challenge_mode != Disabled` is what mounts it on
  `wallet_router`; the same condition also gates `challenge_endpoint` in
  `AuthorizationServerMetadata`, so a route and an advertised capability can
  never disagree — see `metadata_and_route_availability_agree`
  (`conformance_http.rs`). `issuer.dpop.nonce_mode` follows the identical
  pattern one level down: it never changes the route table, but it gates
  whether `DPoP-Nonce` is ever emitted at `/token`/`/credential`.
- **`attestation_challenge_header` and `dpop_nonce_header` are each a single
  emission point, called from both the success and error tails of
  `token_handler`/`credential_handler`.** Never construct either header
  inline at a second call site — RFC 9449 §8's "MUST NOT be more than one
  `DPoP-Nonce` header" and ABCA §6.2's mandatory-on-error / §8.1's
  permitted-on-success shape both depend on there being exactly one place
  that decides whether and how to attach them.
- **`assets/console.html` embeds a vendored QR library with a provenance
  comment.** Do not delete that comment, and do not reintroduce a CDN
  dependency (it exists for air-gapped deployment) or dynamic `innerHTML` (prior
  fixes deliberately removed it).
- **Both listeners must bind successfully** — `serve` binds them sequentially
  and propagates a bind error via `?`, so a port clash on either one aborts
  startup with an error (it does not panic, and it does not fall back to a
  single listener).