# AGENTS.md — `crates/foundry-wallet`

## Purpose

A **debug EUDI wallet** (CLI + TUI) for exercising and inspecting Foundry's
OpenID4VCI issuance and OpenID4VP verification flows end to end. Credentials,
holder keys, trust material, and an append-only event log are stored as plain
files so a human can read them mid-flow.

Format scope: **SD-JWT VC only** — there is no mdoc code path in this crate.

**Not** a production wallet: no hardened key storage, no server-side
responsibilities, no protocol implementation of its own (it drives
`foundry-issuer` / `foundry-verifier` types over real HTTP).

Usage, config reference, and TUI walkthrough: [`README.md`](../../README.md)
("Debug Wallet CLI/TUI") and the example [`wallet.yaml`](../../wallet.yaml).

## Position in the Dependency Graph

- **Depends on:** `foundry-core`, `foundry-issuer`, `foundry-verifier`,
  `foundry-sd-jwt-vc`, **and `crates/foundry` itself** —
  the latter because the integration tests boot the real `admin_router` /
  `wallet_router` in-process (see Tests).
- **Top of the stack: nothing depends on this crate.** No `foundry-*` crate may
  ever depend on it — that would create a cycle through `crates/foundry`.

Full layering rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
|---|---|
| `lib.rs` | Declares `actions`, `cli`, `config`, `error`, `http`, `storage`, `tui` |
| `main.rs` | Entry point; parses `Cli`, loads `WalletConfig`, dispatches to a headless command or the TUI |
| `cli.rs` | Clap surface: `Cli`, `Command`, `ConsentArg`, `CredentialsAction`, `EventsAction` |
| `config.rs` | `wallet.yaml` model: `WalletConfig`, `EndpointsConfig` (+ `resolve_admin_api_key`), `TrustConfig`, `TrustValidationMode`, `TrustAnchorConfig`, `IssuancePreset`, `VerificationPreset` |
| `error.rs` | `WalletError` and `WalletResult<T>` |
| `actions/issuance.rs` | Drives the OpenID4VCI flow (offer → `/token` → proof → `/credential`); returns `IssuanceOutcome` |
| `actions/verification.rs` | Drives the OpenID4VP flow (fetch request object → match → consent → submit); `VerificationOutcome`, `Consent` |
| `actions/offer_source.rs` | `OfferSource` + `parse_offer_deep_link` — resolves a preset vs. an offer deep link |
| `actions/request_source.rs` | `parse_request_deep_link` — resolves a verification request URI |
| `actions/match_credentials.rs` | `match_credentials` / `MatchedCredential` — selects stored credentials satisfying a DCQL query |
| `actions/proof.rs` | `build_proof_jwt` / `HolderProof` — holder proof-of-possession JWT |
| `actions/trust.rs` | `validate_jws_x5c_chain` / `TrustOutcome` — real X.509 validation, honouring the config toggle |
| `actions/http_util.rs` | `build_trust_store`, `ensure_2xx` |
| `storage/mod.rs` | `ensure_data_dir_layout`, `now_rfc3339` |
| `storage/credential_store.rs` | `CredentialMetadata`, `NewCredential`, `store_credential`, `load_metadata`, `load_payload`, `load_holder_key_pem`, `load_compact_sdjwt`, `list_credentials` |
| `storage/event_log.rs` | `append_event`, `read_events`, `tail_events` |
| `http/mod.rs` | `LoggingHttpClient` — HTTP client that logs requests/responses verbatim |
| `tui/app.rs` | `run(&WalletConfig)` — the event loop |
| `tui/state.rs` | `AppState`, `Screen`, `TuiCommand`, `Consent` |
| `tui/screens/` | Per-screen renderers: `main_menu.rs`, `issuance.rs`, `verification.rs`, `credentials.rs`, `event_log.rs` |

## Key Public Types & Entry Points

- **CLI:** `cli::Cli { config, command: Option<Command> }`; `Command` is `Tui`
  (the default when no subcommand is given), `Issue { preset, offer_uri, tx_code }`,
  `Verify { preset, request_uri, consent }`,
  `Credentials { List | Show { id } }`, `Events { Tail { n } }`.
- **TUI:** `tui::app::run(&WalletConfig) -> anyhow::Result<()>`.
- **Flows:** `actions::run_issuance` → `IssuanceOutcome`,
  `actions::run_verification` → `VerificationOutcome`.
- **Config:** `WalletConfig` (`data_dir`, `endpoints`, `trust`,
  `issuance_presets`, `verification_presets`).
- **Storage:** free functions over a `data_dir` path (there is no
  `CredentialStore` / `EventLog` struct) plus the `CredentialMetadata` and
  `NewCredential` types.
- **Errors:** `WalletError`, `WalletResult<T>`.

## Binding Invariants

- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` in `actions/`,
  `storage/`, `http/`, or `tui/`** — these modules are named explicitly in the
  rule; always return `WalletResult` / `WalletError`. Permitted only in
  `#[cfg(test)]` and in files under `tests/` — full rule: root
  [AGENTS.md](../../AGENTS.md) §4.1.
- **Nothing may depend on this crate** — root [AGENTS.md](../../AGENTS.md) §3.
- **This crate owns no HTTP endpoints**, so `openapi-wallet.json` describes the
  *server's* wallet-facing routes, not anything here. Changing this crate never
  requires a spec update — but relying on a route shape does mean a server-side
  change can break it silently.
- **Gates are scoped by default:** nothing depends on this crate, so per task
  `cargo test -p foundry-wallet` plus `cargo clippy -p foundry-wallet
  --all-targets -- -D warnings` and `cargo fmt --check` is the whole gate. Save
  `cargo test --workspace` for the end of a development cycle or when unsure of
  the blast radius — **not** between tasks. Full rule: root
  [AGENTS.md](../../AGENTS.md) §5.

## Tests

Inline `#[cfg(test)]` modules are present in most modules. Integration tests:

| File | Covers |
|---|---|
| `tests/issuance.rs` | OpenID4VCI flow against a real server |
| `tests/verification.rs` | OpenID4VP flow against a real server |
| `tests/cli_headless.rs` | Headless CLI commands end to end |
| `tests/support_smoke.rs` | Sanity check that the harness itself boots |
| `tests/support/mod.rs` | The harness: `spawn_test_server()` / `TestServer` |

**The harness boots the real `foundry` admin + wallet Axum routers in-process**
on ephemeral `127.0.0.1` ports, over a temp SQLite DB and a temp dev PKI
(`new_ca` + `issue_leaf`). It deliberately does **not** spawn the binary as a
subprocess — that is why this crate depends on `crates/foundry`. Constants:
`ADMIN_API_KEY`, `ISSUER_BASE`, `VCT_PID`.

```bash
cargo test -p foundry-wallet
cargo test -p foundry-wallet --test verification
```

## Gotchas

- **Plaintext on-disk storage is intentional.** Under `data_dir` (default
  `./wallet-data`) the layout is `credentials/cred_<hex>/`, `keys/`, `trust/`,
  and `log/events.jsonl` — deliberately human-readable and unencrypted for
  inspection. Do not "harden" it, and do not restructure it for abstraction.
  Note it is **not** `~/.eudiw-wallet/`; the location comes from config.
- **Unredacted HTTP logging is intentional.** `LoggingHttpClient` logs bodies
  verbatim — tokens, proofs, and nonces are visible on purpose. Do not add
  redaction.
- **`trust.validation: disabled` proceeds anyway.** The X.509 validation is real
  and applies to both the issuer's credential-signing JWT and the verifier's
  signed request object, but setting the mode to `disabled` logs a warning and
  continues the flow rather than failing. Do not remove the toggle, and do not
  change its default without review.
- **`resolve_admin_api_key` errors when neither key source is configured** —
  inline `admin_api_key` wins over `admin_api_key_env`, and an unset env var is
  an error, not a silent fallback to unauthenticated.
- **`Command` is optional and defaults to the TUI**, so `foundry-wallet --config
  wallet.yaml` with no subcommand launches the interactive UI. `--config` itself
  is required.
- **The event log is append-only JSON Lines** (`log/events.jsonl`). Never edit or
  truncate it; readers should tolerate a malformed trailing line from an
  interrupted write.
- **The TUI must restore the terminal on every exit path**, including errors —
  check `tui/app.rs` before adding an early return, or a failed run leaves the
  user's terminal in raw mode.
- **Presets vs. URIs are two distinct entry paths.** `Issue`/`Verify` accept
  either a named preset (which calls the *admin* API to mint an offer/request
  first) or an externally supplied `--offer-uri` / `--request-uri`. The preset
  path needs a working admin key; the URI path does not.