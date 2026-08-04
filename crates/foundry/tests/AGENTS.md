# AGENTS.md — `crates/foundry/tests`

## Purpose

The workspace's **integration / end-to-end suite**. `foundry-issuer` and
`foundry-verifier` have no `tests/` directory of their own, so all OpenID4VCI
and OpenID4VP *flow* coverage lives here alongside the HTTP, CLI, and OpenAPI
tests. If you changed an engine and want to know whether a flow still works,
this directory is where you look.

## Running

```bash
cargo test -p foundry                                  # whole suite
cargo test -p foundry --test wallet_issuance           # one file
cargo test -p foundry --test wallet_issuance full_issuance_flow_end_to_end
cargo test --workspace                                 # full gate — end of cycle only (root AGENTS.md §5)
```

## Coverage Map

| File | Covers | Exercises |
|---|---|---|
| `health.rs` | `/health` and `/ready` both return 200 | `server::health`, `server::ready` |
| `console.rs` | `/console` returns HTML when enabled, 404 when disabled; QR SVG has explicit dimensions; the DC API trigger buttons and issuance status badge are present, and `.badge.offered` / `.badge.issued` are styled | `server::console_handler`, `admin.console_enabled` |
| `issuer_offers.rs` | `POST /admin/issuance/offers` succeeds with a valid Bearer token, rejected without one; the response carries a `dc_api_offer` with inlined metadata; `GET /admin/issuance/offers/:id` reports `offered`, returns the `tx_code`, 404s on an unknown id, and **never** returns `pre_authorized_code` / `access_token` / `claims` | `server::create_offer_handler`, `server::get_issuance_offer_handler`, `require_api_key`, `foundry_issuer::create_offer` |
| `wallet_metadata.rs` | Both `.well-known` metadata documents | `foundry_issuer::build_issuer_metadata`, `build_authorization_server_metadata` |
| `wallet_issuance.rs` | Full `/token` → `/credential` flow with a holder proof; wrong pre-auth code rejected | `foundry_issuer::handle_token_request`, `handle_credential_request`, `verify_holder_proof` |
| `wallet_verification.rs` | Full `/vp/request/:id` → `/vp/response/:id` flow, including a locally built signed Status List Token that marks an index revoked | `foundry_verifier::build_signed_request_object`, `verify_vp_response`, `check_status` |
| `wallet_status_list_route.rs` | `GET /statuslists/:id` returns a signed token; 404 for unknown id and when status lists are disabled | `server::status_list_handler`, `foundry_core::status_list` |
| `sweeper.rs` | Expired rows are actually purged | `foundry_core::storage::Storage::purge_expired`, `server::spawn_sweeper` |
| `openapi_endpoints.rs` | Both specs are valid, every `$ref` resolves (collected recursively), Swagger UI serves HTML when enabled | `openapi::generate_admin_openapi_spec`, `generate_wallet_openapi_spec` |
| `cli_openapi.rs` | `foundry openapi --out` writes a valid spec | `Command::Openapi` |
| `cli_pki.rs` | `keys generate` produces a loadable key; `cert new-ca` then `cert issue` chain | `commands::keys_generate`, `cert_new_ca`, `cert_issue` |
| `cli_status_list.rs` | `status-list set` → `get` → `token` round-trip | `commands::status_list_{set,get,token}` |
| `quickstart.rs` | `quickstart` emits a valid dev PKI and a loadable config | `commands::quickstart` |
| `e2e_full_flow.rs` | Boots the real binary (`quickstart`, then `serve`) and drives it over HTTP as a wallet: issue → verify → revoke → re-verify | the whole stack |
| `conformance_http.rs` | HTTP-layer OpenID4VCI/HAIP conformance evidence, including the ABCA `/challenge` endpoint and `challenge_endpoint` metadata (Task 5), `use_attestation_challenge` + `OAuth-Client-Attestation-Challenge` at `/token` (Task 6), and RFC 9449 `DPoP-Nonce` + `use_dpop_nonce` at both `/token` (400) and `/credential` (401) (Task 8) — see `docs/conformance/openid4vc-conformance.md`'s ABCA section and `RFC-9449-0008`/`0014`-`0019` | `server::challenge_handler`, `attestation_challenge_header`, `dpop_nonce_header`, `token_error_response`, `credential_error_response`, `foundry_issuer::validate_client_attestation_pop_jwt`'s check 10, `verify_dpop_proof`'s check 10 |
| `logging_redaction.rs` | Drives real issuance and presentation flows with planted secrets and asserts none reaches the log at any level; includes the positive control proving `sensitive_payloads` actually unlocks payloads, that one `tx_id` threads a whole flow, and — since 2026-08-04 — that an ABCA `attestation_challenge` and an RFC 9449 DPoP `nonce` are equally never logged, with their own positive control | `http_log`, the four error mappers, `foundry_core::obs`, engine instrumentation |
| `instrumentation_hygiene.rs` | Structural guards: every `#[tracing::instrument]` carries `skip_all`, the documented field names are still emitted, payload fields are gated on `obs::sensitive_enabled()` | all instrumented crates |

## Shared Setup Patterns

There is **no shared `support/` module** — each file defines its own local
helpers (commonly `fn test_config()`, `async fn test_app()` / `setup_test_app()`).
Two distinct styles are in use:

1. **Router injection (most files).** Build an `AppState` over a real SQLite
   database in a `tempfile::tempdir()` via
   `SqliteStorage::connect(db_path).await`, construct `admin_router(...)` or
   `wallet_router(...)`, and drive it with `tower::ServiceExt::oneshot` — no
   ports are bound and no process is spawned. Note this uses a **temp-file**
   database, not `:memory:`.
2. **Real subprocess.** `cli_openapi.rs`, `cli_pki.rs`, `cli_status_list.rs`,
   `quickstart.rs`, and `e2e_full_flow.rs` execute the compiled binary via
   `env!("CARGO_BIN_EXE_foundry")` (Cargo builds it for them — do *not* shell out
   to `cargo run`). `e2e_full_flow.rs` additionally picks a free port, wraps the
   child in a `ServerGuard` with a `Drop` impl, dumps logs on failure, and waits
   for a log line before proceeding.

Dev-dependencies available here: `tempfile`, `tower` (`util`), `reqwest`,
`josekit`, `base64`, `coset`, plus the format crates, for constructing
credentials and Status List Tokens by hand. Encrypted OpenID4VP responses are
built with `foundry_core::crypto::jwe::encrypt_compact`.

## When Adding a Test

- **New HTTP endpoint** → add a router-injection test to the file matching its
  surface (`issuer_offers.rs` for admin issuance, `wallet_*.rs` for
  wallet-facing), then add the `utoipa` annotation in
  `crates/foundry/src/openapi.rs` — `openapi_endpoints.rs` validates that every
  `$ref` in the generated specs resolves, so an incomplete annotation fails there.
- **New CLI command** → extend the matching `cli_*.rs`, invoking the binary
  through `env!("CARGO_BIN_EXE_foundry")`.
- **New cross-cutting flow behaviour** (revocation, expiry, replay) → extend
  `e2e_full_flow.rs`; it is the only test that proves the assembled binary works.
- **Careful with `serve`-based tests:** `server::serve` rewrites `openapi.json`
  and `openapi-wallet.json` into the process working directory, so a subprocess
  test that runs `serve` from the repo root will modify tracked files. Run it in
  a `TempDir` working directory, or expect the diff.
- **Unwraps are allowed here.** Integration test files under `tests/` are exempt
  from the no-panic rule — root [AGENTS.md](../../../AGENTS.md) §4.1. Use them
  freely for setup; keep assertions meaningful rather than unwrap-driven.
- **Name tests after the behaviour they prove**, matching existing style:
  `health_and_ready_return_200`, `rejects_offer_creation_without_bearer_token`,
  `statuslists_route_404s_when_status_list_disabled`.