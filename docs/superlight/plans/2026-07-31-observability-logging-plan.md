# Foundry Observability: Structured Logging — Implementation Plan

**Spec:** docs/superlight/specs/2026-07-31-observability-logging-spec.md
**Branch:** superlight/2026-07-31-observability-logging
**Executed with:** superlight Phase 4 (TDD, inline, no subagents by default)

**Goal:** Make every HTTP request, every typed error, and every issuer/verifier
protocol decision observable in the foundry log, with a production-safe `info`
tier and a dev-only payload tier — and stop discarding the verification failure
reason.

**Architecture:** Four layers, bottom-up. `foundry_core::obs` holds the
sensitive-payload flag and redaction helpers. `foundry-core`'s config gains a
`logging:` block; `crates/foundry` resolves it against `RUST_LOG` and the CLI
and installs the subscriber. A hand-rolled axum middleware establishes a
correlation span per request on both routers. The four existing error mappers in
`server.rs` become the single place every typed error is logged. The engines
emit protocol events into whatever span is active.

**Global Constraints:** copied verbatim from the spec —

- **`#[tracing::instrument]` MUST always carry `skip_all`.** Without it, every
  argument is `Debug`-formatted into the span — including `Config`,
  `VerificationTransaction` (which holds `ephem_private_jwk`) and raw JWE
  strings. Fields are opt-in, always, in every crate.
- **Never log a value from the "never recorded" list in spec Design §7**, at any
  level, under any flag.
- **Payload fields MUST be gated on `foundry_core::obs::sensitive_enabled()`
  AND emitted at `debug`/`trace`** — both conditions, never one alone.
- **`verified == checks.iter().all(|c| c.passed)`** must continue to hold
  everywhere `VerificationResult` is constructed (root `AGENTS.md` §4.2).
  Never hardcode `verified: true`.
- **HTTP status mapping is unchanged.** The policy-vs-structural contract in
  root `AGENTS.md` §4.3 and `crates/foundry/AGENTS.md` must behave identically
  before and after this work.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside
  `#[cfg(test)]`, per root `AGENTS.md` §4.1.
- **No new third-party crates enter the workspace.** Every crate used is
  already a `[workspace.dependencies]` entry. Two per-crate `Cargo.toml`
  additions are required and are the only ones permitted:
  `sha2` → `foundry-core`, `tracing` → `foundry-issuer`. Adding `tower-http`
  or `tracing-test` is explicitly out of scope.
- **Dependency layering is one-directional** (root `AGENTS.md` §3).
  `foundry-core` gains no `foundry-*` dependency; the engines gain only the
  `tracing` facade.
- **Existing config files must keep loading.** A config with no `logging:`
  block must parse and yield the documented defaults.
- **`logging::init` is called exactly once per process.** A second call panics
  inside `tracing_subscriber`.
- **Log field names are stable API for operators.** Use
  `request_id`, `tx_id`, `route`, `method`, `listener`, `http.status`,
  `latency_ms`, `error.kind`, `error.detail`. Do not rename them ad hoc between
  tasks.
- **Gates** (root `AGENTS.md` §5), all three clean before completion:
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check`.
- **OpenAPI** — `openapi.json` and `openapi-wallet.json` must be regenerated
  and committed if annotations change (root `AGENTS.md` §6). Note that
  `serve()` rewrites both on startup in the process working directory.

## Refinements to the spec (deliberate, recorded here)

Two points where this plan narrows spec intent. Both are visible so a reviewer
can reject them rather than discover them in a diff:

1. **The capture helper is a `pub` module in the `foundry` lib, not
   `#[cfg(test)]`.** Rust integration tests link the library compiled *without*
   `cfg(test)`, so a `#[cfg(test)]` helper is invisible to
   `crates/foundry/tests/`. Making it unconditionally `pub` keeps it usable from
   both unit and integration tests without adding `tracing-subscriber` as a
   dev-dependency to the engine crates — which the Global Constraints forbid.
   Cost: ~30 lines of test utility ship in the binary.
2. **`x-request-id` is documented in `README.md` and
   `crates/foundry/AGENTS.md`, not in per-path `utoipa` response-header
   annotations.** Spec §9 says "annotations"; replicating a header that is
   present on *every* response across ~15 `#[utoipa::path]` macros is churn
   with no reader benefit. No OpenAPI **schema** changes either way, so
   `openapi.json` / `openapi-wallet.json` are expected to regenerate byte
   identical — Task 12 verifies that rather than assuming it.

## File Structure

- `crates/foundry-core/Cargo.toml` — add `sha2`
- `crates/foundry-core/src/obs.rs` — **new**: sensitive flag + `truncate` + `thumbprint`
- `crates/foundry-core/src/lib.rs` — declare `obs`
- `crates/foundry-core/src/config/model.rs` — `LoggingConfig`, serde `LogFormat`, `Config::logging`
- `crates/foundry/src/cli.rs` — `log_level`/`log_format` become `Option`, add `--log-sensitive`, add `Command::config_path()`
- `crates/foundry/src/logging.rs` — `resolve_*` pure functions, rewritten `init`
- `crates/foundry/src/main.rs` — load config before `logging::init`
- `crates/foundry/src/log_capture.rs` — **new**: capturing `tracing` layer for tests
- `crates/foundry/src/http_log.rs` — **new**: access-log middleware
- `crates/foundry/src/lib.rs` — declare `http_log`, `log_capture`
- `crates/foundry/src/server.rs` — layer the middleware onto both routers; log in the four error mappers; log in the three error-discarding handlers; log the `save_verification_transaction` failure
- `crates/foundry-verifier/src/error.rs` — `VerificationError::kind()`
- `crates/foundry-verifier/src/verify.rs` — `check_name_for`, populate `tx.result` on the error path, protocol step events
- `crates/foundry-verifier/src/request.rs`, `status.rs`, `dcql.rs` — protocol events
- `crates/foundry-issuer/Cargo.toml` — add `tracing`
- `crates/foundry-issuer/src/error.rs` — `IssuanceError::kind()`
- `crates/foundry-issuer/src/{token,credential,nonce,proof,attestation,authorize,create_offer,status_index}.rs` — protocol events
- `README.md`, `crates/foundry/AGENTS.md`, `crates/foundry-verifier/AGENTS.md`, `crates/foundry-issuer/AGENTS.md` — documentation

**Fast loop while iterating:** the per-task `Verify` command.
**Before marking any task complete:** that command must show pristine output.
**Before Phase 5:** all three gates from Global Constraints.

Tasks 1, 2 and 6 are mutually independent and may be reordered. Everything from
Task 5 onward depends on Task 4.

---

### Task 1: `foundry_core::obs` — sensitive flag and redaction helpers

**Files:** create `crates/foundry-core/src/obs.rs`; modify
`crates/foundry-core/src/lib.rs`, `crates/foundry-core/Cargo.toml`

**Interfaces:**
- Consumes: nothing (leaf module)
- Produces:
  - `pub fn set_sensitive(enabled: bool)`
  - `pub fn sensitive_enabled() -> bool`
  - `pub fn truncate(s: &str, max: usize) -> String`
  - `pub fn thumbprint(jwk: &serde_json::Value) -> String`

**Behaviors to test:**
- `sensitive_enabled()` is `false` before any `set_sensitive` call — happy path
- `set_sensitive(true)` then `sensitive_enabled()` is `true`; `set_sensitive(false)` returns it
- `truncate` leaves a string shorter than `max` unchanged
- `truncate` caps a string longer than `max` and marks it as truncated
- `truncate` at exactly `max` — boundary
- `truncate` does not split a multi-byte UTF-8 character — edge case
- `thumbprint` is stable across calls for the same JWK
- `thumbprint` differs for two different JWKs
- `thumbprint` returns a placeholder rather than panicking for a malformed
  (non-object, or missing required members) JWK — edge case

**Notes:** the flag is a `static AtomicBool`; ordering `Relaxed` is sufficient
(it is set once at startup, read many times, and a stale read has no safety
consequence — but it must never be `unsafe`). `thumbprint` must be infallible:
no `unwrap`, no `Result`.

**Verify:** `cargo test -p foundry-core`

- [x] Red — failing test per behavior above
- [x] Green — minimal implementation
- [x] Refactor — clean while green
- [x] Verify — run the command, pristine output
- [x] Commit

**Outcome:** 13 tests. Added beyond the plan: an RFC 7638 §3.1 known-answer
vector (without it the thumbprint tests were only self-consistent), a
member-order/extra-member invariance test, an RSA+OKP key-type test, a
`max = 0` boundary case, and a direct assertion that a thumbprint contains no
key material. Flag behaviour is one test, not several, because the flag is
process-global and concurrent `#[test]` functions would race on it.

---

### Task 2: `LoggingConfig` in the core config model

**Files:** modify `crates/foundry-core/src/config/model.rs`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `pub struct LoggingConfig { pub level: String, pub format: LogFormat, pub sensitive_payloads: bool }`
  - `pub enum LogFormat { Human, Json }` with `#[serde(rename_all = "snake_case")]`
  - `Config::logging: LoggingConfig`, carrying `#[serde(default)]`
  - `impl Default for LoggingConfig` (or `default_*` fns) yielding
    `level = "info"`, `format = Human`, `sensitive_payloads = false`

**Behaviors to test:**
- A YAML config containing a full `logging:` block parses with all three values —
  happy path
- A YAML config with **no** `logging:` block parses and yields the documented
  defaults — the backward-compatibility guarantee
- A `logging:` block with only `level` set defaults the other two
- `format: json` and `format: human` both parse; an unknown format value is a
  parse error rather than a silent default — edge case
- The repository's own `config.yaml` still loads (regression guard against the
  real file)

**Notes:** do not add `#[serde(deny_unknown_fields)]` anywhere. `foundry-core`
must not gain a `clap` dependency — this `LogFormat` is serde-only and distinct
from the clap enum in `cli.rs`.

**Verify:** `cargo test -p foundry-core`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 3: CLI options, precedence resolution, and startup ordering

**Files:** modify `crates/foundry/src/cli.rs`, `crates/foundry/src/logging.rs`,
`crates/foundry/src/main.rs`

**Interfaces:**
- Consumes: `foundry_core::config::{Config, LoggingConfig, LogFormat}` (Task 2),
  `foundry_core::obs::set_sensitive` (Task 1)
- Produces:
  - `cli::Cli { log_level: Option<String>, log_format: Option<cli::LogFormat>, log_sensitive: bool, .. }`
  - `impl From<cli::LogFormat> for foundry_core::config::LogFormat`
  - `cli::Command::config_path(&self) -> Option<&std::path::Path>`
  - `logging::resolve_level(env: Option<&str>, cli: Option<&str>, cfg: Option<&LoggingConfig>) -> String`
  - `logging::resolve_format(cli: Option<cli::LogFormat>, cfg: Option<&LoggingConfig>) -> config::LogFormat`
  - `logging::resolve_sensitive(cli: bool, cfg: Option<&LoggingConfig>) -> bool`
  - `logging::init(level: &str, format: config::LogFormat, sensitive: bool)`

**Behaviors to test:**
- `resolve_level`: env set, CLI set, config set → env wins
- `resolve_level`: env unset, CLI set, config set → CLI wins
- `resolve_level`: env and CLI unset, config set → config wins
- `resolve_level`: all unset → `"info"`
- `resolve_format` and `resolve_sensitive`: the same precedence ladder
  (no env tier for these two)
- `Command::config_path` returns `Some` for `Serve` and for
  `Config { action: Validate }`, and `None` for `Keys`, `Cert`, `Quickstart`,
  `Openapi`, `StatusList` — one assertion per variant, so a new subcommand
  fails the test rather than silently losing config-driven logging
- `--log-sensitive` parses as a flag defaulting to `false`
- Existing regression: parsing `--log-level debug --log-format json` yields
  `Some("debug")` / `Some(Json)` (this updates the current assertion at
  `cli.rs:181`)
- An unparseable level directive falls back to `info` rather than failing
  startup — edge case, preserving today's tolerant behaviour

**Notes:** `resolve_level` takes the environment as a **parameter**; it must not
read `std::env` internally, so the precedence table is testable without mutating
process environment. `main.rs` best-effort-loads the config **only** to choose
log settings and deliberately discards that error; the authoritative
`Config::load(&config)?` inside the matched arm still propagates `ConfigError`,
and where the best-effort load succeeded the arm reuses it instead of reading
the file twice. `logging::init` calls `obs::set_sensitive` and emits the
`warn!` when the flag is on.

**Verify:** `cargo test -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 4: capturing `tracing` layer for tests

**Files:** create `crates/foundry/src/log_capture.rs`; modify
`crates/foundry/src/lib.rs`

**Interfaces:**
- Consumes: `tracing`, `tracing_subscriber` (both already dependencies of
  `crates/foundry`)
- Produces:
  - `pub struct CapturedEvent { pub level: tracing::Level, pub target: String, pub message: String, pub fields: std::collections::BTreeMap<String, String> }`
  - `pub struct CaptureHandle` with `pub fn events(&self) -> Vec<CapturedEvent>`
    and a convenience `pub fn contains_value(&self, needle: &str) -> bool` that
    searches message **and** all field values across **all** events
  - `pub fn capture_layer() -> (L, CaptureHandle)` where `L` is the layer to
    compose into a `tracing_subscriber` registry (concrete type chosen at
    implementation time; it must implement `Layer<Registry>`)

**Behaviors to test:**
- A single `info!` emitted under the layer is captured with its level, message
  and fields — happy path
- An event's structured fields are captured as key/value pairs, not only
  rendered into the message
- Fields inherited from an enclosing span are visible on the captured event
  (this is what makes the `request_id` / `tx_id` correlation assertions possible)
- Events below the active filter are not captured — edge case
- `contains_value` finds a needle appearing only in a field value, and only in a
  message, and returns `false` when absent — this is the primitive the redaction
  test in Task 11 depends on, so it must be proven here

**Notes:** this module is unconditionally `pub` rather than `#[cfg(test)]` — see
"Refinements to the spec". Document that in a module-level comment so a future
reader does not "tidy" it behind `cfg(test)` and silently break the integration
tests. Uses `tracing::subscriber::with_default` / `set_default` at the call
site; the module itself installs nothing globally.

**Verify:** `cargo test -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 5: HTTP access-log middleware

**Files:** create `crates/foundry/src/http_log.rs`; modify
`crates/foundry/src/lib.rs`, `crates/foundry/src/server.rs` (layer onto
`admin_router` and `wallet_router`)

**Interfaces:**
- Consumes: `log_capture` (Task 4, tests only), `axum::middleware`,
  `axum::extract::MatchedPath`, `uuid`
- Produces:
  - `pub fn layer(listener: &'static str) -> impl Layer` — an axum layer usable
    as `.layer(http_log::layer("admin"))` and
    `.layer(http_log::layer("wallet"))` (concrete `FromFnLayer` type chosen at
    implementation time)
  - Span `"http"` with fields `request_id`, `method`, `route`, `listener`
  - One event per response with `http.status` and `latency_ms`
  - Response header `x-request-id`

**Behaviors to test:**
- A 200 request produces exactly **one** access event, at `INFO`, carrying
  `request_id`, `method`, `route`, `listener`, `http.status`, `latency_ms` —
  happy path
- A 4xx response is logged at `WARN`; a 5xx at `ERROR`
- `route` is the route **template** (`/vp/response/:id`), not the concrete path
  containing the id
- A request to an unrouted path records `route = "<unmatched>"`, returns 404,
  and does not panic — edge case
- The `x-request-id` response header is present and equals the logged
  `request_id`
- A request with a query string (`?foo=SECRETVALUE`) produces no captured event
  containing `SECRETVALUE` at `info` — the field-level leak guard
- Both routers carry the layer, with the correct `listener` value each
- The middleware does not alter status or body for a successful request —
  behaviour-neutrality check

**Notes:** read `MatchedPath` from request extensions; never format the raw
`Uri`. Latency from `std::time::Instant`. No `unwrap` — a missing `MatchedPath`
degrades to `"<unmatched>"`.

**Verify:** `cargo test -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 6: stable `kind()` on both error enums

**Files:** modify `crates/foundry-verifier/src/error.rs`,
`crates/foundry-issuer/src/error.rs`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `impl VerificationError { pub fn kind(&self) -> &'static str }`
  - `impl IssuanceError { pub fn kind(&self) -> &'static str }`

**Behaviors to test:**
- One assertion per `VerificationError` variant mapping to its expected stable
  string (`NotFound`, `InvalidState`, `Dcql`, `InvalidRequest`, `Crypto`,
  `Decryption`, `Failed`, `StatusUnavailable`, `Storage`, `CoreCrypto`, `Trust`,
  `Serialization`)
- One assertion per `IssuanceError` variant, enumerated from the actual enum at
  implementation time
- `kind()` is exhaustive with no catch-all `_ =>` arm, so adding a variant is a
  compile error rather than a silently mislabelled log line — this is the point
  of the task and must be visible in the code

**Notes:** no `tracing` dependency needed for this task; these are pure
functions. Do not change any `#[error(...)]` message.

**Verify:** `cargo test -p foundry-verifier -p foundry-issuer`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 7: error logging at the four mappers and the discarding handlers

**Files:** modify `crates/foundry/src/server.rs`

**Interfaces:**
- Consumes: `VerificationError::kind()` / `IssuanceError::kind()` (Task 6),
  `obs::truncate` (Task 1), `log_capture` (Task 4, tests only)
- Produces: no new public API; one log event inside each of
  `admin_error_response` (`:194`), `wallet_error_response` (`:209`),
  `verifier_admin_error_response` (`:468`), `verifier_wallet_error_response`
  (`:482`), plus events in `status_list_handler` (`:682`, three sites),
  `get_verification_handler` (`:527`), `get_request_object_handler` (`:548`)

**Behaviors to test:**
- Each of the four mappers, for a representative variant, emits exactly one
  event carrying `error.kind`, `error.detail`, `http.status` — happy path ×4
- Level follows status: a 500-mapped variant logs at `ERROR`; a 400-mapped
  variant at `WARN`; `StatusUnavailable` (502) at `WARN`
- An error travelling through a handler and its mapper is logged **exactly
  once**, not twice — the anti-double-logging guarantee
- `status_list_handler`'s storage failure is logged before being collapsed to
  `500` — it currently discards the error entirely
- `get_verification_handler` and `get_request_object_handler` likewise
- `error.detail` is length-capped via `obs::truncate`
- **HTTP status codes are unchanged** for every variant already covered by the
  existing mapper tests — regression guard on root `AGENTS.md` §4.3

**Notes:** the events go **inside** the mappers, not at the call sites, so
coverage is total and duplication impossible. Do not restructure the `match`
arms or alter any mapped status.

**Verify:** `cargo test -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 8: stop discarding the verification failure reason

**Files:** modify `crates/foundry-verifier/src/verify.rs`,
`crates/foundry/src/server.rs` (the `let _ = save_verification_transaction` at
`:660`)

**Interfaces:**
- Consumes: `VerificationError::kind()` (Task 6), `obs::truncate` (Task 1)
- Produces:
  - `fn check_name_for(err: &VerificationError) -> &'static str` (crate-private
    is fine; expose only if a test needs it directly)
  - `verify_vp_response`'s `Err` arm now sets `tx.result = Some(..)` before
    returning the error
  - a `DETAIL_MAX` cap constant

**Behaviors to test:**
- A response whose JWE cannot be decrypted ⇒ `tx.state == Failed`,
  `tx.result == Some`, exactly one check named `jwe_decryption`,
  `passed == false`, non-empty `detail`, and `verified == false` — happy path
  for the fix
- `check_name_for`: `Decryption` → `jwe_decryption`,
  `StatusUnavailable` → `status_check`, `Dcql` → `dcql_match`, another variant →
  `verification_error` — one assertion each
- `verified == checks.iter().all(|c| c.passed)` holds for the newly constructed
  result — root `AGENTS.md` §4.2
- `detail` is length-capped
- All seven existing state assertions in `verify.rs` still pass
  (`:559` `Verified`; `:824`, `:839`, `:892`, `:956`, `:1062`, `:1128` `Failed`).
  Verified precondition: none of them asserts `tx.result.is_none()`, so this
  change is additive
- `crates/foundry/tests/wallet_verification.rs:330`
  (`tx.result.expect("result should be present")`) still passes
- **The wallet still receives HTTP 400** for a structural failure and 502 for
  `StatusUnavailable` — root `AGENTS.md` §4.3 unchanged
- A storage failure in `save_verification_transaction` is logged at `ERROR`
  instead of being swallowed by `let _ =`

**Notes:** `detail` is served over the admin API and rendered in a browser —
while implementing, read the `Display` strings of the variants being surfaced
and confirm none embeds key material or payload bytes. If one does, redact at
this boundary rather than widening the cap.

**Verify:** `cargo test -p foundry-verifier -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 9: verifier protocol instrumentation

**Files:** modify `crates/foundry-verifier/src/verify.rs`, `request.rs`,
`status.rs`, `dcql.rs`

**Interfaces:**
- Consumes: `obs::sensitive_enabled` / `truncate` / `thumbprint` (Task 1),
  `VerificationError::kind()` (Task 6), `log_capture` (Task 4, from
  `crates/foundry` tests)
- Produces: spans on `create_verification_request`,
  `build_signed_request_object`, `verify_vp_response`, `check_status`; step
  events named to match the existing `CheckResult` names

**Behaviors to test:**
- The `Err` arm of `verify_vp_response` emits one `WARN` carrying `error.kind`
  and `error.detail` — the record whose absence caused this whole piece of work
- A successful verification emits one event per step
  (`jwe_decryption`, the credential-format check, `dcql_match`, `status_check`)
- A DCQL mismatch emits an event naming the credential query or claim path that
  missed, and **still** returns HTTP 200 with `verified: false` — policy
  failures stay policy failures (root `AGENTS.md` §4.3)
- A status-list revocation emits an event naming the verdict
- `tx_id` is present on verifier events, so one grep threads the flow across
  `/vp/request/:id` and `/vp/response/:id`
- With `sensitive_payloads = false`, no event contains the raw JWE, the
  `vp_token`, or any disclosed claim value
- Every `#[tracing::instrument]` added carries `skip_all` — assert by grep in
  the task's own check, and by the Task 11 redaction suite behaviourally

**Notes:** event assertions live in `crates/foundry` tests (the capture helper is
there); pure-logic assertions stay in-crate. Do not change any control flow,
return type, or status mapping in this task — instrumentation only.

**Verify:** `cargo test -p foundry-verifier -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 10: issuer protocol instrumentation

**Files:** modify `crates/foundry-issuer/Cargo.toml` (add `tracing`), and
`crates/foundry-issuer/src/{token,credential,nonce,proof,attestation,authorize,create_offer,status_index}.rs`

**Interfaces:**
- Consumes: `obs::{sensitive_enabled, truncate, thumbprint}` (Task 1),
  `IssuanceError::kind()` (Task 6), `log_capture` (Task 4, from
  `crates/foundry` tests)
- Produces: spans and events on `handle_token_request`,
  `handle_credential_request`, `verify_holder_proof`,
  `verify_key_attestation_jwt`, `issue_nonce`, `verify_nonce`,
  `handle_authorize_request`, `create_offer`, `allocate_status_index`

**Behaviors to test:**
- A successful token exchange emits an event naming the grant type and the
  accepted-code outcome, and **never the code value itself**
- A rejected pre-authorized code emits a `WARN` naming the reason, without the
  code
- A successful credential issuance emits an event with credential
  configuration id, format, proof type, and the holder-key **thumbprint** —
  and no raw holder key
- A rejected holder proof emits a `WARN` with the rejection reason
- `issue_nonce` / `verify_nonce` emit outcome events containing **no** nonce
  value
- With `sensitive_payloads = false`, no event contains an access token, a
  `c_nonce`, a pre-authorized code, or a transaction code
- Every `#[tracing::instrument]` added carries `skip_all`

**Notes:** instrumentation only — no control-flow, signature, or status-mapping
changes. `handle_credential_request` handles plural proofs; log the count, not
each proof's contents.

**Verify:** `cargo test -p foundry-issuer -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 11: redaction gate — the cross-cutting negative suite

**Files:** create a test module/file under `crates/foundry/tests/` (name it for
what it guards, e.g. `logging_redaction.rs`)

**Interfaces:**
- Consumes: `log_capture::CaptureHandle::contains_value` (Task 4), the
  instrumentation from Tasks 5, 7, 8, 9, 10
- Produces: no production code — this task adds only tests. If it finds a leak,
  the fix belongs in the task that introduced it

**Behaviors to test:**
- **Issuance flow, `sensitive_payloads = false`:** drive a real issuance through
  the routers with uniquely identifiable planted secrets (access token,
  `c_nonce`, pre-authorized code, transaction code) and assert **no** captured
  event anywhere contains any of them — asserted across the whole buffer at
  `trace` level, not per-event
- **Presentation flow, `sensitive_payloads = false`:** same, planting a
  recognizable claim value and using a known `vp_token` / JWE; assert absence
- **`ephem_private_jwk` never appears** in either flow, in either flag state —
  the one value that must never be logged even in dev
- **`sensitive_payloads = true` at `debug`:** the payload field **is** present,
  proving the switch is live and not vestigially disabled — without this, all
  the negative assertions above could pass trivially
- Field names match the documented stable set (`request_id`, `tx_id`, `route`,
  `method`, `listener`, `http.status`, `latency_ms`, `error.kind`,
  `error.detail`) — a rename guard, since operators grep these

**Notes:** run the capture at `trace` so the assertions cover every level, not
just the ones enabled by default. If any assertion fails, that is a real leak —
fix the emitting site, never weaken the assertion.

**Verify:** `cargo test -p foundry --test logging_redaction`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 12: documentation, OpenAPI verification, and full gates

**Files:** modify `README.md`, `crates/foundry/AGENTS.md`,
`crates/foundry-verifier/AGENTS.md`, `crates/foundry-issuer/AGENTS.md`;
verify `openapi.json`, `openapi-wallet.json`

**Interfaces:**
- Consumes: everything from Tasks 1–11
- Produces: documentation only

**Behaviors to test:** (documentation task — verification is the gates plus
explicit checks)
- `README.md` documents: log levels, the precedence ladder
  (`RUST_LOG` > CLI > config > default), the `logging:` config block, the
  `x-request-id` header, how to thread a flow by `tx_id`, and a clear
  **dev/test only** warning on `sensitive_payloads`
- `crates/foundry/AGENTS.md` module map gains `http_log.rs` and
  `log_capture.rs`, and its Gotchas note that `log_capture` is deliberately not
  `#[cfg(test)]`
- `crates/foundry-verifier/AGENTS.md` and `crates/foundry-issuer/AGENTS.md`
  carry the `#[instrument(skip_all)]` rule and the redaction tiers as one-line
  reminders pointing at the spec
- No AGENTS.md gains a line count, test count, or other per-commit-drifting
  number (root `AGENTS.md` §8)
- `openapi.json` and `openapi-wallet.json` regenerate **byte identical**
  (no schema change is expected — if they differ, stop and explain why before
  committing)
- `docs/conformance/openid4vc-conformance.md` is **unchanged** — no
  spec-governed behaviour moved

**Verify:**
`cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

## Closing check (Phase 5, not a task)

The spec's manual verification step belongs to Phase 5 review, not to any task:
re-run the wallet presentation that prompted this work and confirm the log now
shows the request arriving, each verification step, and the failure reason — and
that the admin console displays that reason. This requires the live wallet and
the separately-running foundry instance, so it is the user's action to perform,
not something a test can assert.

## Progress Log

Append one line per completed task: date, task, commit SHA.

- 2026-07-31 — Phase 2 spec committed — cff20ec
- 2026-07-31 — Phase 3 plan committed — 842c37d
- 2026-07-31 — Task 1 (foundry_core::obs) — 718b2e6
