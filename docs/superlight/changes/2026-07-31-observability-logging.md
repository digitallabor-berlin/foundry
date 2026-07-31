# Foundry Observability: Structured Logging — Change Record

**Date:** 2026-07-31
**Branch:** `superlight/2026-07-31-observability-logging`
**Spec:** [`../specs/2026-07-31-observability-logging-spec.md`](../specs/2026-07-31-observability-logging-spec.md)
**Plan:** [`../plans/2026-07-31-observability-logging-plan.md`](../plans/2026-07-31-observability-logging-plan.md)

## Why

A real wallet completed an OpenID4VP presentation. The wallet reported success,
the admin console reported a bare red `failed`, and the foundry process printed
**nothing at all** — so there was no way to tell whether the wallet's
`POST /vp/response/:id` had even arrived, let alone why verification failed.

Investigation found four independent causes, none of them the one that gets
guessed first:

1. **`RUST_LOG` was silently ignored.** `logging::init` built its filter from the
   `--log-level` CLI argument via `EnvFilter::try_new(level)`, never consulting
   the environment.
2. **There was no HTTP access log.** No request line, path, status or latency was
   recorded for any request on either listener.
3. **Almost nothing was instrumented.** The whole workspace had 14 `tracing::`
   statements, all in `crates/foundry`, none on a request path. `foundry-core`,
   `foundry-issuer`, `foundry-verifier`, `foundry-sd-jwt-vc`, `foundry-mdoc` and
   `foundry-wallet` had zero each. **No log level, including `trace`, produced
   any request-path output** — so the absence of output carried no diagnostic
   information.
4. **The verification failure reason was generated and then thrown away**, at
   three separate points.

Rejected during investigation, with evidence: "log level too low" (nothing was
instrumented at any level), "the console misreads the state enum"
(`#[serde(rename_all = "snake_case")]` matches the JS exactly), "console polling
timed out" (that path calls `showError()` and leaves the badge `pending`).

## What Changed

### Configuration and startup

- New optional `logging:` block in the config file — `level` (any `EnvFilter`
  directive), `format` (`human`/`json`), `sensitive_payloads`.
- Settings resolve **`RUST_LOG` > CLI flags > config file > defaults**. The
  `resolve_*` functions take every source as a parameter rather than reading the
  environment, so the precedence table is unit-tested without touching process
  state.
- `--log-level` / `--log-format` became `Option` with no clap default, because
  "not supplied" has to be distinguishable from "supplied as `info`" or the
  config block could never take effect. New `--log-sensitive` flag.
- `main.rs` now best-effort-loads the config *before* installing the subscriber,
  and reuses that load in the `Serve` and `Config::Validate` arms. The
  authoritative load still runs in the arm, so a broken config still fails with
  its typed `ConfigError`.
- `Command::config_path()` is exhaustive with no catch-all, so a new subcommand
  carrying a config cannot silently lose config-driven logging.

### Transport layer

- New `http_log.rs`: one `axum::middleware::from_fn` on each router that
  establishes a correlation span and emits exactly one access record per request
  with `request_id`, `method`, `route`, `listener`, `http.status`, `latency_ms`.
- `route` is always the `MatchedPath` **template** (`/vp/response/:id`), never
  the concrete URI — a structural guarantee that path parameters cannot leak
  through that field. Unrouted requests record the literal `<unmatched>` rather
  than echoing attacker-controlled input. Query strings are never recorded.
- `x-request-id` response header, so a wallet, console or human can quote the
  identifier that ties their failure to the server-side records.

### Error layer

- Each of the four error mappers in `server.rs` emits exactly one record with
  `error.kind`, `error.detail`, `http.status`. Placed **inside** the mappers, not
  at their call sites: every typed error passes through exactly one mapper
  exactly once, so coverage is complete and double-logging is impossible.
- New `kind()` on `VerificationError` and `IssuanceError` — a stable,
  low-cardinality name per variant, decoupled from the `Display` prose. Both are
  exhaustive with no catch-all arm, so a new variant is a compile error rather
  than a log line labelled `"unknown"`.
- **Nine** sites that discarded the error object entirely were fixed (the plan
  anticipated five): seven `map_err(|_| INTERNAL_SERVER_ERROR)` plus two
  `.ok_or(INTERNAL_SERVER_ERROR)`. The two extra are misconfiguration paths in
  `status_list_handler` where a request would 500 with no explanation anywhere;
  they now name the missing key.
- `let _ = save_verification_transaction(..)` became a logged failure. Losing
  that write made the admin API disagree with what actually happened.

### Protocol layer

- Spans and events across `foundry-verifier` (`verify_vp_response`,
  `do_verify_vp_response`, `create_verification_request`,
  `build_signed_request_object`, `check_status`, DCQL matching) and
  `foundry-issuer` (token, credential, nonce, proof, attestation, authorize,
  offer, status index).
- `tx_id` is recorded on the span, so **one grep threads a whole presentation
  across three requests on two listeners**.
- Level reflects meaning, not volume: a DCQL mismatch or revoked credential is a
  policy outcome that still returns HTTP 200 with `verified: false`, so it logs
  at `warn`; `error` is reserved for actual faults.

### The failure reason (the visible symptom)

- The error path of `verify_vp_response` now populates `tx.result` with a single
  failed `CheckResult` naming the stage that aborted, using the same vocabulary
  the success path emits. `verified` stays derived, never hardcoded.
- The admin API and console therefore show *why* a presentation failed instead
  of a bare red `failed`.

### Redaction discipline

- New `foundry_core::obs`: the process-global sensitive-payload flag plus
  `truncate` and `thumbprint` (RFC 7638). No log statements in `foundry-core`.
- Payload fields require **both** `obs::sensitive_enabled()` **and** a
  `debug`/`trace` level — a level alone is not authorisation, since
  `RUST_LOG=debug` is ordinary in production.
- Private/ephemeral JWKs, the admin key, access tokens, `c_nonce` values and the
  nonce secret, pre-authorized/authorization/transaction codes are never logged
  at any level under any flag.

## Verification

All three gates clean: **485 tests pass**, `clippy --all-targets -D warnings`
silent, `fmt --check` clean.

Claims were checked rather than asserted:

| Claim | How it was verified |
|---|---|
| `RUST_LOG` now works | Against the built binary: `RUST_LOG=error` suppresses the `info` line and beats an explicit `--log-level trace` |
| Requests are logged | Against a running server: 200/200/404/401 each produced one correctly-levelled record; `x-request-id` matched the logged `request_id` |
| `thumbprint` is RFC 7638 | Known-answer vector from RFC 7638 §3.1, not just self-consistency |
| The `tx.result` fix works | **Mutation**: reverting the assignment fails all three new tests; restoring it passes them |
| No secret is logged | **Mutation**: logging the access token fails the redaction suite with "access token leaked into the log" |
| The payload switch is real | **Positive control**, itself mutation-tested: making `sensitive_enabled()` return `false` fails it with "the switch is inert" |
| `skip_all` everywhere | Structural test, mutation-verified against a synthetic offender |
| End-to-end payoff | A broken presentation driven over real HTTP: log shows the full flow under one `tx_id` with `error.kind="decryption"`, and the admin API returns `result.checks[0].detail` |
| No OpenAPI drift | `openapi.json` and `openapi-wallet.json` regenerate **byte identical**; drift test passes |
| Conformance untouched | `docs/conformance/` unchanged — logging is outside OpenID4VCI/VP/HAIP scope |

Two new test files carry the load-bearing guarantees:
`tests/logging_redaction.rs` (behavioural, with a positive control) and
`tests/instrumentation_hygiene.rs` (structural).

## Deviations From the Plan

All deliberate, all recorded in the plan's per-task Outcome notes:

- **`foundry_core::obs` exists at all** — the stated scope was "engines only".
  The sensitive-payload flag must be readable by both engines and the binary, and
  root `AGENTS.md` §3 puts shared same-layer behaviour in `foundry-core`. The
  alternative was duplicating a security-relevant switch.
- **502 and 503 log at `error`, not `warn`.** The plan said `warn` for 502, but
  the access log already uses "level follows status class" and two rules for one
  class invites confusion.
- **`log_capture` is `pub`, not `#[cfg(test)]`** — integration tests link the
  library compiled without `cfg(test)`, and the alternative (a `tracing-test`
  dev-dependency) was forbidden by the no-new-crates constraint.
- **`x-request-id` is documented in prose**, not replicated across ~15 `utoipa`
  path macros. No schema change either way.
- **Root `AGENTS.md` §4.5 was added**, which the plan did not list. Root §8
  requires a new global invariant to be registered in §4.
- Two plan-level field names were wrong and corrected against the real structs
  (`credential_type_id`; `credential_configuration_id` is an `Option`).

Exactly two per-crate `Cargo.toml` lines were added — `sha2` → `foundry-core`,
`tracing` → `foundry-issuer`. No new crate entered the workspace.

## Follow-Ups

### 1. The ephemeral private key is served over the admin API — pre-existing, out of scope

Found while verifying the `tx.result` fix end-to-end.
`GET /admin/verification/requests/:id` returns the whole
`VerificationTransaction`, and `VerificationTransaction::ephem_private_jwk` has
no `#[serde(skip_serializing)]`, so the response includes:

```json
"ephem_private_jwk":{"kty":"EC","crv":"P-256","d":"4OnDi7wDExx9KQ6..."}
```

`console.html` fetches that endpoint, so the key reaches a browser. This is
**pre-existing** — identical on `main`, untouched by this branch — and is an API
serialization issue rather than a logging one, so it was deliberately not fixed
here.

It is not a one-line change: `save_verification_transaction` persists the same
struct via `serde_json::to_string(tx)` and `verify_vp_response` needs
`tx.ephem_private_jwk` back to decrypt the wallet's response. A naive
`skip_serializing` would break decryption after reload. The fix needs a separate
admin-facing DTO (or split storage/API serialization) — a design decision worth
its own change.

### 2. Diagnose the original presentation failure

This work makes that failure observable; it does not explain it. Re-run the
wallet presentation and read the log — the reason will now be recorded, and the
console will show it.

### 3. Deprioritised environment anomalies

Excluded at the user's direction ("forget the db, the instance is running
somewhere else"): the stale `./foundry.db` (zero `verification_tx` rows) and
`config.yaml`'s `public_base_url: http://localhost:8443`.