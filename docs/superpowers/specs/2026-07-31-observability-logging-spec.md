# Foundry Observability: Structured Logging for Every Action and Every Error

> Migrated from `docs/superpowers/specs/2026-07-31-observability-logging-spec.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Date:** 2026-07-31
**Status:** approved

## Problem

Foundry emits effectively no operational logs. While testing an OpenID4VP
presentation from a real wallet through the admin test console, the console
reported `failed` while the wallet reported success, and the foundry process
printed **nothing at all** — leaving no way to tell whether the wallet's
`POST /vp/response/:id` ever arrived, let alone why verification failed.

Investigation established three independent causes (the full record, including
rejected hypotheses, is written to
`docs/superpowers/changes/2026-07-31-observability-logging.md` when this work
completes):

1. **`RUST_LOG` is silently ignored.** `crates/foundry/src/logging.rs:5` builds
   its filter with `EnvFilter::try_new(level)` from the `--log-level` CLI
   argument, not `try_from_default_env()`. The environment variable every Rust
   operator reaches for first has no effect whatsoever.

2. **There is no HTTP access log.** No `TraceLayer` is installed and
   `tower-http` is not a dependency (`crates/foundry/Cargo.toml` carries only
   `tower` with `features = ["util"]`, and only as a dev-dependency). No
   request line, path, status code, or latency is ever recorded for any
   request on either listener.

3. **Almost nothing is instrumented.** The entire workspace contains 14
   `tracing::` statements, all in `crates/foundry`, and none on a request path:

   | Crate | log statements |
   |---|---|
   | `foundry-core` | 0 |
   | `foundry-issuer` | 0 |
   | `foundry-verifier` | 0 |
   | `foundry-sd-jwt-vc` | 0 |
   | `foundry-mdoc` | 0 |
   | `foundry-wallet` | 0 |
   | `foundry` | 14 — startup/listening, sweeper, OpenAPI write, PKI CLI, config-valid |

   Consequently no log level, including `trace`, produces any request-path
   output. The absence of output carries no diagnostic information.

A fourth, related defect compounds the invisibility. On the structural-error
path, `crates/foundry-verifier/src/verify.rs:217-219` sets
`tx.state = Failed` but leaves `tx.result = None`. The failure reason exists
only inside the returned `Err`, which
`crates/foundry/src/server.rs:600-671` converts into an HTTP 400 body sent to
**the wallet**. The admin console (`crates/foundry/assets/console.html:2652-2657`)
renders its checks list only `if (tx.result)`, so an operator sees a bare red
`failed` badge with no reason. Additionally `server.rs:660` persists the
transaction with `let _ = save_verification_transaction(...)`, discarding even a
storage failure. The diagnostic detail is generated and then thrown away at
three separate points.

## Goal / Non-Goals

### Goals

- Every HTTP request on both listeners produces a structured log record:
  method, route template, status, latency, correlation id, listener.
- Every typed error produces exactly one log record naming a stable error kind
  and its detail — never zero, never duplicated.
- Every protocol decision in `foundry-issuer` and `foundry-verifier` produces
  an event, so an operator can follow a flow step by step.
- A single log field value (the domain transaction id) reconstructs an entire
  presentation or issuance flow across multiple requests and both listeners.
- Two clearly separated tiers: an `info` tier that is safe to retain in
  production, and a `debug`/`trace` tier, gated behind an explicit opt-in, that
  exposes payloads for local debugging.
- `RUST_LOG` works.
- A verification that fails structurally records **why** in `tx.result`, so the
  admin console and admin API show the reason rather than a bare `failed`.

### Non-Goals

- No metrics, no tracing exporters (OTLP/Jaeger), no log shipping. Structured
  `tracing` events on stdout only, human or JSON.
- No instrumentation of `foundry-core` internals (storage, crypto, PKI, trust,
  status-list bitsets) or of the credential-format crates
  (`foundry-sd-jwt-vc`, `foundry-mdoc`). See Approach for the single, narrow
  exception.
- No instrumentation of `foundry-wallet`.
- No change to any wire format, endpoint path, HTTP status code, or
  spec-governed behaviour. This work is invisible to OpenID4VCI, OpenID4VP and
  HAIP conformance.
- No change to the admin console's HTML/JS. It already renders `tx.result`
  when present; populating that field is sufficient.
- Not an investigation of the original presentation failure. This work makes
  that failure observable; diagnosing it is separate follow-up work.

## Approach

**Chosen: layered `tracing` instrumentation with a hand-rolled access-log
middleware, engine-level protocol events, and a central error choke point.**

Four coordinated pieces:

1. **Configuration** — a `logging:` section in the config file, plus a working
   `RUST_LOG`, with an explicit precedence chain.
2. **Transport layer** — one `axum::middleware::from_fn` on each router,
   establishing a correlation span and emitting one access record per request.
3. **Error layer** — the four existing error mappers in `server.rs` become the
   single place every typed error is logged, plus the handful of handlers that
   currently discard errors without passing through a mapper.
4. **Protocol layer** — `#[tracing::instrument(skip_all, ...)]` and explicit
   events at decision points in `foundry-issuer` and `foundry-verifier`.

A cross-cutting **redaction discipline** (Design §7) governs all four, enforced
by a negative test rather than by convention alone.

### Rejected alternatives

| Rejected | Reason |
|---|---|
| `tower-http`'s `TraceLayer` | Its default `MakeSpan` records the full request URI **including the query string**. `/authorize` and `/token` carry sensitive parameters, so `MakeSpan` and `OnResponse` would both need overriding — which is most of the code the hand-rolled middleware needs anyway, in exchange for a new dependency. |
| `#[tracing::instrument]` without `skip_all` | The default records every argument via `Debug`. In these engines the arguments are `Config`, `VerificationTransaction` (which holds `ephem_private_jwk`) and raw JWE strings. This would write private key material to the log by default. `skip_all` with opt-in fields is the only safe form. |
| Logging each error at its `?` site | One error would be reported three or four times as it propagates. The four mappers are the exact points each typed error passes through once and only once. |
| Instrumenting `foundry-core` and the format crates | Log statements inside CBOR and base64 loops; a `put_kv` record per request adds noise without information a failing query would not already surface. |
| A `tracing-test` dev-dependency | A ~30-line capturing `Layer` in a test helper achieves the same and keeps the dependency set unchanged. |
| Duplicating the sensitive-payload flag in each engine | Two sources of truth for a security-relevant switch. See the narrow `foundry-core` exception below. |

### Deliberate deviation: a small addition to `foundry-core`

The stated scope is "engines only, leave `foundry-core` alone". One narrow
exception is required: the sensitive-payload switch must be readable by
`foundry-issuer`, `foundry-verifier` **and** `foundry`, and per root
`AGENTS.md` §3 shared behaviour between same-layer crates belongs in
`foundry-core`.

A new `foundry_core::obs` module therefore holds the process-global flag and
the redaction helpers. It contains **no log statements** — `foundry-core`
already declares `tracing` as a dependency today but never uses it, and that
stays true. It does require adding `sha2 = { workspace = true }` to
`crates/foundry-core/Cargo.toml` for `thumbprint` (`sha2` is already a
workspace dependency, used by `foundry-issuer`; `foundry-core` does not
currently list it). The alternative, duplicating a security-relevant flag per
engine, is worse.

## Design

### 1. Configuration surface and precedence

New `LoggingConfig` in `crates/foundry-core/src/config/model.rs`, reached as
`Config::logging`:

```yaml
logging:
  level: info                  # EnvFilter directive, e.g. "info,foundry_verifier=debug"
  format: human                # human | json
  sensitive_payloads: false    # DEV/TEST ONLY — unlocks payload fields at debug/trace
```

The field carries `#[serde(default)]` and each member a `default_*` function,
matching the established pattern (`model.rs:8,10,13,28,52`). `Config` has no
`#[serde(deny_unknown_fields)]`, so **existing config files without a
`logging:` block continue to load unchanged** — a required property, verified
by test.

`LoggingConfig::format` is a serde-only `LogFormat` enum defined in
`foundry-core` (`#[serde(rename_all = "snake_case")]`). It is distinct from the
clap `ValueEnum` of the same name in `crates/foundry/src/cli.rs`, because
`foundry-core` must not depend on `clap`; `cli.rs` provides the `From`
conversion.

**Precedence, highest first:**

1. `RUST_LOG` environment variable
2. `--log-level` / `--log-format` / `--log-sensitive` CLI arguments, when
   explicitly supplied
3. the `logging:` section of the config file
4. built-in defaults: `info`, `human`, `false`

To distinguish "supplied" from "defaulted", `cli.rs` changes
`log_level: String` → `Option<String>` and `log_format: LogFormat` →
`Option<LogFormat>` (dropping their `default_value`s), and gains
`log_sensitive: bool` as a `--log-sensitive` flag.

Resolution is expressed as **pure functions** in
`crates/foundry/src/logging.rs`:

```rust
pub fn resolve_level(env: Option<&str>, cli: Option<&str>, cfg: Option<&LoggingConfig>) -> String
pub fn resolve_format(cli: Option<LogFormat>, cfg: Option<&LoggingConfig>) -> LogFormat
pub fn resolve_sensitive(cli: bool, cfg: Option<&LoggingConfig>) -> bool
```

taking the environment as a parameter rather than reading it internally, so the
precedence table is unit-testable without mutating process environment.

`logging::init` then:

- builds `EnvFilter` from the resolved level string, falling back to `info` on
  an unparseable directive (preserving today's tolerant behaviour),
- installs the `human` or `json` formatter,
- calls `foundry_core::obs::set_sensitive(resolved)`,
- emits `warn!("sensitive payload logging ENABLED — dev/test only")` when the
  flag is on, mirroring the existing unauthenticated-admin-key warning in
  `server.rs:795`.

### 2. Startup ordering in `main.rs`

`main.rs:9` currently calls `logging::init` **before** any config is loaded
(`Config::load` first appears at line 15/24). Config-driven logging therefore
requires reordering:

```rust
let cli = Cli::parse();
let cfg_path = cli.command.config_path();                    // new helper on Command
let preloaded = cfg_path.and_then(|p| Config::load(p).ok()); // best-effort, for log settings only
logging::init(
    &logging::resolve_level(std::env::var("RUST_LOG").ok().as_deref(),
                            cli.log_level.as_deref(),
                            preloaded.as_ref().map(|c| &c.logging)),
    logging::resolve_format(cli.log_format, preloaded.as_ref().map(|c| &c.logging)),
    logging::resolve_sensitive(cli.log_sensitive, preloaded.as_ref().map(|c| &c.logging)),
);
```

`Command::config_path(&self) -> Option<&Path>` returns `Some` for
`Command::Serve` and `Command::Config { action: Validate }`, `None` otherwise.

The best-effort load discards its error **only for the purpose of choosing log
settings**. The authoritative load still happens inside the matched arm and
still propagates its typed `ConfigError`, so no configuration error is lost or
downgraded. Where `preloaded` is already `Some`, the arm reuses it rather than
reading the file twice.

`logging::init` must remain called exactly once per process:
`tracing_subscriber`'s `init()` panics on a second call.

### 3. HTTP access log middleware

New module `crates/foundry/src/http_log.rs`, declared in `lib.rs`, layered onto
both `admin_router` and `wallet_router`.

Per request:

- Generate `request_id` as a UUID v4 (`uuid` is already a dependency of
  `crates/foundry`).
- Enter `tracing::info_span!("http", request_id = %id, method = %method, route = %route, listener = %listener)`
  for the duration of the request, so **every** downstream event — handler,
  error mapper, engine — inherits these fields automatically.
- `route` is the **route template** obtained from
  `req.extensions().get::<axum::extract::MatchedPath>()` (e.g.
  `/vp/response/:id`), never the raw URI. Falls back to the literal string
  `"<unmatched>"` when no route matched (404s). This is the structural
  guarantee that path parameters and query strings cannot leak through this
  field.
- The query string is **never** recorded at `info`. At `debug`, only an
  allowlist of non-sensitive parameter names is recorded.
- After `next.run(req)`, emit one event with `http.status` and `latency_ms`:
  `info!` for 1xx–3xx, `warn!` for 4xx, `error!` for 5xx.
- Set an `x-request-id` response header carrying the same id, so a wallet,
  console, or human can quote the identifier that ties their failure to the
  server-side records.

`listener` is `"admin"` or `"wallet"`, supplied when the layer is constructed,
because the two routers bind separate ports and mount disjoint route sets.

### 4. Error logging: the four mappers as choke point

Every typed error in the HTTP layer already funnels through exactly one of the
four mappers in `server.rs`:

| Function | Error type | Listener |
|---|---|---|
| `admin_error_response` (`:194`) | `IssuanceError` | admin |
| `wallet_error_response` (`:209`) | `IssuanceError` | wallet |
| `verifier_admin_error_response` (`:468`) | `VerificationError` | admin |
| `verifier_wallet_error_response` (`:482`) | `VerificationError` | wallet |

Each gains exactly one event immediately before returning, carrying:

- `error.kind` — the variant name, from a new
  `fn kind(&self) -> &'static str` on `VerificationError`
  (`crates/foundry-verifier/src/error.rs`) and `IssuanceError`
  (`foundry-issuer`). A stable, matchable field, so operators never have to
  parse a `Display` string that may be reworded later.
- `error.detail` — `e.to_string()`, length-capped via
  `foundry_core::obs::truncate`.
- `http.status` — the mapped status code.

Level follows the status: `error!` for 5xx, `warn!` for 4xx and 502. This
placement yields complete coverage with no double-logging, and inherits
`request_id`, `route` and `tx_id` from the enclosing span at no cost.

**Handlers that bypass the mappers must be fixed too.** These currently
discard the error object entirely and are therefore unloggable:

- `status_list_handler` (`server.rs:682`) — three
  `map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)` sites
- `get_verification_handler` (`server.rs:527`) — one such site
- `get_request_object_handler` (`server.rs:548`) — same pattern

Each must log the error before collapsing it to a bare `StatusCode`.

### 5. Protocol instrumentation in the engines

Dependency state as it actually stands: `foundry-verifier` **already** declares
`tracing = { workspace = true }` (currently unused), as does `foundry-core`.
Only `crates/foundry-issuer/Cargo.toml` needs the line added. `tracing` is a
facade — the engines emit, the binary decides what is recorded — so this
introduces no upward dependency and does not violate root `AGENTS.md` §3.

Public entry points carry `#[tracing::instrument(skip_all, fields(...))]` with
explicitly chosen fields. **`skip_all` is mandatory**, not stylistic — see
Global Constraints.

**`foundry-verifier`:**

- `create_verification_request` — `tx_id`, credential format(s) requested,
  response mode.
- `build_signed_request_object` — `tx_id`, signing algorithm.
- `verify_vp_response` / `do_verify_vp_response` — `tx_id`, plus one event per
  protocol step, named to match the existing `CheckResult` names:
  `jwe_decryption`, `sd_jwt_vc_signature_and_kb_jwt`,
  `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check`. A
  failing `dcql_match` records **which** credential query or claim path
  missed. A failing `status_check` records the status verdict.
- The `Err` arm of `verify_vp_response` (`verify.rs:217`) emits
  `warn!(error.kind, error.detail, "vp response verification failed")`. This
  single record is the one whose absence made the original defect invisible.
- `check_status` — the resolved status list URI and verdict.

**`foundry-issuer`:**

- `handle_token_request` — grant type, whether the pre-authorized code or
  authorization code was accepted (**never the code itself**).
- `handle_credential_request` — credential configuration id, format, proof
  type, holder-key **thumbprint** (never the key), and the outcome.
- `verify_holder_proof`, `verify_key_attestation_jwt` — accepted or rejected,
  and the reason on rejection.
- `issue_nonce`, `verify_nonce` — issued/verified outcome, never the nonce
  value.
- `handle_authorize_request` — the request's disposition.
- `create_offer` — credential type and offer id.
- `allocate_status_index` — allocated index and list id.

Level guidance: `info` for the outcome of a protocol step, `warn` for a
rejection attributable to the client, `error` for an internal failure, `debug`
for step-by-step interior detail, `trace` for payloads under the sensitive
flag.

### 6. Persisting the discarded verification failure

In `verify_vp_response` (`crates/foundry-verifier/src/verify.rs:217-221`), the
`Err` arm additionally populates `tx.result`:

```rust
Err(err) => {
    tx.state = VerificationState::Failed;
    tx.result = Some(VerificationResult {
        verified: false,
        checks: vec![CheckResult {
            check: check_name_for(&err).to_string(),
            passed: false,
            detail: Some(foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX)),
        }],
        claims: serde_json::Value::Null,
    });
    Err(err)
}
```

`check_name_for` maps the error variant onto the stage that aborted:
`Decryption` → `jwe_decryption`, `StatusUnavailable` → `status_check`,
`Dcql` → `dcql_match`, everything else → `verification_error`.

Invariants preserved:

- Root `AGENTS.md` §4.2 — `verified == checks.iter().all(|c| c.passed)` holds:
  one check, `passed: false`, `verified: false`. The flag remains derived, never
  hardcoded.
- Root `AGENTS.md` §4.3 — HTTP mapping is untouched. Structural and crypto
  errors still return 400, `StatusUnavailable` still 502, policy failures still
  return 200 with `verified: false`. The only change is that the reason is now
  also persisted rather than discarded.

`detail` must be operator-safe: it is served over the admin API and rendered in
a browser. It is length-capped, and the underlying `Display` strings are
reviewed during implementation to confirm they carry no key material or
payload bytes.

Separately, `server.rs:660`'s
`let _ = foundry_verifier::save_verification_transaction(...)` becomes a
match that emits `error!` on failure. Silently losing the persisted verdict is
its own defect: it makes the admin API disagree with what actually happened.

### 7. Redaction discipline

**Never recorded, at any level, under any flag:**

- private and ephemeral JWKs (`VerificationTransaction::ephem_private_jwk`),
  signer private keys
- the admin API key, bearer tokens, access tokens
- `c_nonce` values and the nonce HMAC secret
- pre-authorized codes, authorization codes, transaction codes

**Recorded only when `sensitive_payloads == true`, and only at `debug` or
`trace`:**

- raw JWE compact serializations, `vp_token` values, SD-JWT VC strings
- decrypted response payloads, disclosed claim values, mdoc namespace contents

**Safe at `info` (the production tier):**

- transaction ids, request ids, credential *configuration/type* ids
- credential formats, JOSE/COSE algorithm names
- check names, error kinds, HTTP statuses, latencies, counts, booleans
- public key **thumbprints** (RFC 7638-style SHA-256 over the JWK) in place of
  keys

Supporting module `foundry_core::obs`:

```rust
pub fn set_sensitive(enabled: bool);          // called once from logging::init
pub fn sensitive_enabled() -> bool;           // AtomicBool load
pub fn truncate(s: &str, max: usize) -> String;
pub fn thumbprint(jwk: &serde_json::Value) -> String;   // sha2, base64url
```

No log statements in `foundry-core`. Requires `sha2 = { workspace = true }`
added to `crates/foundry-core/Cargo.toml`.

### 8. Error handling within the observability code itself

Logging must never change request behaviour or introduce a failure path:

- The middleware must not short-circuit a request on any internal problem; a
  missing `MatchedPath` degrades to `"<unmatched>"`.
- Root `AGENTS.md` §4.1 applies to every file touched: no `.unwrap()`,
  `.expect()`, `panic!()` or `unreachable!()` in `foundry::server`,
  `foundry::http_log`, or the engines. Unwraps remain permitted only under
  `#[cfg(test)]`.
- `thumbprint` and `truncate` are infallible by construction (they return a
  placeholder string rather than an error).

## Global Constraints

- **`#[tracing::instrument]` MUST always carry `skip_all`.** Without it, every
  argument is `Debug`-formatted into the span — including `Config`,
  `VerificationTransaction` (which holds `ephem_private_jwk`) and raw JWE
  strings. Fields are opt-in, always, in every crate.
- **Never log a value from the "never recorded" list in Design §7**, at any
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
- **Documentation** — `README.md` gains a logging section (levels, precedence,
  `RUST_LOG`, the `sensitive_payloads` warning); `crates/foundry/AGENTS.md`
  gains `http_log.rs` in its module map, and the two engine `AGENTS.md` files
  note the `skip_all` rule.

## Testing Strategy

Test-driven per task: a failing test for each behaviour before the
implementation that satisfies it.

**Test infrastructure.** A capturing `tracing_subscriber::Layer` (~30 lines) in
a shared test helper, collecting each event's level, message, and fields into
`Arc<Mutex<Vec<CapturedEvent>>>`, installed per-test with
`tracing::subscriber::with_default`. No new dependency.

**Unit tests:**

- `resolve_level`, `resolve_format`, `resolve_sensitive` — full precedence
  table, including the "CLI flag absent vs. explicitly supplied" distinction.
- A `logging:` block parses with all three fields; a config **without** a
  `logging:` block parses and yields defaults (backward-compatibility
  guarantee).
- `obs::truncate` at, below and above the cap; `obs::thumbprint` stable for a
  known JWK.
- `VerificationError::kind()` and `IssuanceError::kind()` — one assertion per
  variant, so a newly added variant fails the test rather than logging
  `"unknown"` silently.
- `check_name_for` — one assertion per mapped variant.

**HTTP-layer tests** (`tower::ServiceExt::oneshot`, already a dev-dependency):

- One request produces exactly one access-log event carrying `request_id`,
  `route`, `method`, `listener`, `http.status`, `latency_ms`.
- Level follows status: 2xx → `INFO`, 4xx → `WARN`, 5xx → `ERROR`.
- `route` records the **template** (`/vp/response/:id`), not the concrete path;
  an unmatched request records `"<unmatched>"` and does not panic.
- The `x-request-id` response header is present and matches the logged id.
- A request with a query string produces no log record containing the query
  value at `info`.

**Error-mapper tests:**

- Each of the four mappers, for a representative variant, emits exactly one
  event at the expected level with the expected `error.kind` and `http.status`.
- Exactly one event per error — an error traversing a handler and its mapper is
  not logged twice.
- The bare-`StatusCode` handlers (`status_list_handler`,
  `get_verification_handler`, `get_request_object_handler`) log before
  discarding.

**Verifier behaviour tests:**

- A `vp_token` response whose JWE cannot be decrypted ⇒ `tx.state == Failed`,
  `tx.result == Some`, exactly one check named `jwe_decryption` with
  `passed: false` and a non-empty `detail`, and `verified == false`.
- The same case emits a `WARN` event with `error.kind = "Decryption"`.
- All seven existing state assertions in `verify.rs` (one `Verified` at `:559`,
  six `Failed` at `:824,:839,:892,:956,:1062,:1128`) must continue to pass
  unchanged. Verified precondition: **none of them asserts
  `tx.result.is_none()`**, so populating `tx.result` on the error path is purely
  additive and cannot break them.
- `crates/foundry/tests/wallet_verification.rs:330` does
  `tx.result.expect("result should be present")` on the success path and must
  keep passing.
- A policy failure (DCQL mismatch) still returns HTTP 200 with
  `verified: false`, and its `dcql_match` event names the missing claim.
- A storage failure on save emits `error!` rather than being swallowed.

**Redaction tests (the load-bearing ones):**

- With `sensitive_payloads = false`, a request carrying a planted, unique
  secret string produces **no** captured event containing that string, at any
  level — asserted over the whole captured buffer, not one event.
- With `sensitive_payloads = true` at `debug`, the payload field **is** present
  (proving the switch is real and not vestigially disabled).
- `ephem_private_jwk` material never appears in captured output in either mode.

**Regression:** the existing `cli.rs` test asserting `cli.log_level == "debug"`
is updated for the `Option<String>` change.

**Manual verification, once implemented:** re-run the wallet presentation that
prompted this work and confirm the log shows the request arriving, each
verification step, and the failure reason — and that the console now displays
that reason.

## Open Questions

None.
