# Design — Verifier Artifact Webhook

**Date:** 2026-08-28
**Status:** Draft (design). Awaiting review; implementation plan pending.
**Scope:** Deliver verification events — the verdict, and optionally the verbatim
protocol artifacts (the Request Object served to the wallet and the decrypted
`vp_token` it returned) — to an operator-configured HTTP endpoint. Foundry
retains nothing.

**Supersedes:** the local-persistence design first drafted under this date, kept
here as §10 with the reasoning that rejected it.

---

## 1. Problem

When a wallet rejects a presentation request, or returns a presentation foundry
rejects, the bytes involved cannot be reconstructed after the fact: the nonce
and the ephemeral key are per transaction, and the `vp_token` exists only as a
local variable inside `do_verify_vp_response`.

Foundry already records these bytes — but **only to the log stream**, and only
under `--log-sensitive` at `trace` level
(`docs/manual/verification/request-diagnostics.md`). That has three limits:

1. **It is not addressable.** Diagnosing transaction `v_1a2b3c` means grepping a
   log stream that may be shipped elsewhere, rotated, or not captured at all.
2. **It must be enabled before the failure.** `--log-sensitive` is a process-start
   flag, so a failure seen without it is unreproducible.
3. **Its retention is the log system's, not the operator's.** Holder PII in a log
   stream inherits whatever the aggregator applies.

The consuming system is an **operator-owned service** — an audit log, SIEM, or
compliance store — which wants the data **pushed** to it and owns retention
itself. That makes this a delivery problem, not a storage problem: foundry's job
is to emit the event, not to hold it.

## 2. Decisions

| # | Decision | Rejected alternative |
| --- | --- | --- |
| D1 | **Push to a configured endpoint; foundry retains nothing.** No new storage row, no TTL | Persist locally and expose on `GET /admin/verification/requests/{id}` — see §10 |
| D2 | Delivery is **best-effort, at-most-once**. Dispatch is `tokio::spawn`ed; a failure is one `warn` and is never retried | At-least-once with durable retry state; in-memory retry with backoff |
| D3 | **Two event types**, because the Request Object is served at a different moment than the response is verified and nothing persists it in between | One combined event at verification time (cannot carry the Request Object); rebuilding the Request Object to combine them |
| D4 | The **presence of `verifier.webhook`** is the enable flag; a nested `include_raw_artifacts` (default `false`) separately gates PII egress | A single boolean conflating "webhook on" with "send holder PII" |
| D5 | `presentation_request_delivered` fires **per delivery**, so a wallet that fetches `GET /vp/request/:id` twice produces two events | Dedupe to one event per transaction — which requires remembering what was sent, i.e. storage |
| D6 | Authenticated with **HMAC-SHA256 over the exact response body**, `X-Foundry-Signature: sha256=<hex>` | A static bearer token; relying on TLS alone |
| D7 | `WebhookSink` is a **trait** with an HTTP implementation, mirroring `StatusListResolver` | A concrete `reqwest` call inline at each site, requiring a mock HTTP server in tests |
| D8 | **`VerificationTransaction` is not modified.** The `vp_token` reaches the event through an out-param and is never a field on a persisted type | Carrying it on the transaction and stripping it before serialization |
| D9 | **All dispatch call sites live in `crates/foundry/src/server.rs`.** `foundry-verifier` gains the types and one out-param, no other signature changes | Firing events from inside `create_verification_request` and `verify_vp_response`, changing both public signatures |
| D10 | The event body carries the **`VerificationResult` verdict unconditionally**; artifacts only under D4 | Artifacts-only events, leaving the verdict available solely by polling |

## 3. Verified Technical Facts

Verified against this repository on 2026-08-28. Each constrains a decision above.

- **`verifier.webhook` already exists and is entirely inert.** Declared
  `pub webhook: Option<serde_json::Value>` at
  `crates/foundry-core/src/config/model.rs:980`, set to `None` in 24 test
  fixtures, and **read by zero lines of production code**. The original
  2026-07-17 design specified it (`webhook: { url, secret_env }`, line 342) and
  named it as a delivery channel for verification results beside the admin GET
  (line 270). This design implements what was specified and never built; D4
  replaces the untyped `Value` with a struct.
- **`hmac = "0.12"` is already a workspace dependency** (`Cargo.toml:39`), used
  by `foundry-issuer`. `foundry-verifier` has `sha2` but not `hmac`, so D6 costs
  one line in `crates/foundry-verifier/Cargo.toml` — not a new dependency.
- **`foundry-verifier`'s `reqwest` has no `json` feature**
  (`crates/foundry-verifier/Cargo.toml:23`: `default-features = false`,
  `features = ["rustls-tls"]`). This is *convenient rather than limiting*: D6
  requires signing the exact bytes transmitted, so the body must be serialized
  once to a `String`, signed, and sent via `.body(..)`. A `json` feature would
  re-serialize and could produce different bytes than were signed.
- **`StatusListResolver` is the precedent for D7** — an `#[async_trait]` trait
  with `HttpStatusListResolver` holding a `reqwest::Client` built with an
  explicit timeout and returning an error rather than panicking on init failure
  (`crates/foundry-verifier/src/status.rs:25-40`). `async_trait` is already a
  `foundry-verifier` dependency.
- **`api_key` / `api_key_env` is the precedent for the secret**
  (`crates/foundry/src/admin_auth.rs:18-35`): literal takes precedence over an
  environment variable name, and the env lookup is *injected* (`resolve_with`)
  so tests exercise it without mutating process-global state — `std::env::set_var`
  became `unsafe` in edition 2024 because the harness is multi-threaded.
- **ECDSA signing is randomized.** HAIP mandates ES256, so two builds of the
  same Request Object differ in signature. This is what makes D5 correct: each
  delivery genuinely *is* different bytes, and an event claiming to reproduce
  "what the wallet received" must be emitted at the moment of serving.
- **`HttpStatusListResolver::new()` is called per request**
  (`crates/foundry/src/server.rs:1683`), rebuilding a `reqwest::Client` each
  time. The webhook sink deliberately does **not** copy this: a `Client` owns a
  connection pool, and rebuilding it per delivery defeats keep-alive. It is
  constructed once and held in `AppState` (§4.4).
- **`do_verify_vp_response` is crate-private**
  (`crates/foundry-verifier/src/verify.rs:1281`) and returns
  `VerifyOutcome { result, deferred }` (`verify.rs:1267`). Adding an out-param is
  an internal change. `verify_vp_response` is public and gains one parameter.
- **`create_verification_handler` already holds everything event 1 needs.**
  `CreateVerificationResponse` carries `verification_id` and `dc_api_request`,
  and for `dc_api_signed` the JWS is `dc_api_request["request"]`
  (`crates/foundry-verifier/src/request.rs:463`). D9 is therefore free — the
  handler needs no new data from `create_verification_request`, whose signature
  is unchanged.
- **Root AGENTS.md §4.3 forbids an outbound call from altering the wallet's
  response.** A structural error is 400, a policy verdict is 200, a status-fetch
  outage is 502; "our webhook endpoint was down" is none of these. This is what
  forces D2's fire-and-forget dispatch.

## 4. Design

### 4.1 Configuration

`VerifierConfig.webhook` becomes a typed struct. Absent (the default) means the
feature is entirely off and no code path changes.

```yaml
verifier:
  webhook:
    url: https://app.example.com/vp-callback
    secret_env: FOUNDRY_WEBHOOK_SECRET   # or literal `secret:`, mirroring api_key/api_key_env
    timeout_secs: 5                      # default
    include_raw_artifacts: false         # default
```

`include_raw_artifacts` is the PII gate, deliberately separate from the enable
flag (D4). Left `false`, the webhook is a verdict feed with **no holder PII
egress at all**; setting it `true` is a recorded operator decision to transmit
disclosed claims to another system.

`Config::validate()` gains: `url` must parse and must be `https`, unless its host
is a loopback address — `localhost`, `127.0.0.0/8`, or `::1`. An operator-owned
sink receiving holder PII over plaintext is a configuration error; loopback is
the exception that keeps dev and tests workable without weakening the rule for
any routable address. When `include_raw_artifacts` is `true` and no secret is configured,
emit a startup `warn`: unsigned PII delivery is permitted (the receiver may be
on a trusted network) but should be a visible choice.

### 4.2 Events

Both are `POST <url>` with `Content-Type: application/json`,
`X-Foundry-Event: <type>`, and `X-Foundry-Signature: sha256=<hex>` (D6).

**`presentation_request_delivered`** — emitted at the moment bytes go to the
wallet:

```json
{
  "event": "presentation_request_delivered",
  "tx_id": "v_1a2b3c",
  "transport": "request_uri",
  "request_object_jws": "eyJ0eXAi..."
}
```

`request_object_jws` is populated for the signed transports (`request_uri`,
`dc_api_signed`); `dc_api_request` carries the unsigned object for the `dc_api`
transport. Exactly one of the two is ever present, chosen by the transport.

Both carry `#[serde(skip_serializing_if = "Option::is_none")]`, so with
`include_raw_artifacts` off the key is **absent rather than `null`** — the event
degrades to a PII-free record that a request was delivered, and a receiver can
test key presence rather than distinguishing "not collected" from "collected as
null".

**`verification_completed`** — emitted on **both** the `Ok` and `Err` paths of
`verify_vp_response`, because a failed verification is the case the feed exists
for:

```json
{
  "event": "verification_completed",
  "tx_id": "v_1a2b3c",
  "state": "failed",
  "result": { "verified": false, "checks": [...], "credentials": [...] },
  "vp_token": { "pid": ["eyJ..."] }
}
```

`result` is the full `VerificationResult` and is unconditional (D10). `vp_token`
appears only under `include_raw_artifacts`.

Timestamps are deliberately **not** included: the receiver stamps arrival, and a
sender-side timestamp would have to be threaded through as a parameter (the
codebase reads the clock at handler entry, not in library code).

### 4.3 The sink

```rust
#[async_trait::async_trait]
pub trait WebhookSink: Send + Sync {
    async fn deliver(&self, event: &WebhookEvent) -> Result<(), VerificationError>;
}
```

`HttpWebhookSink` holds a `reqwest::Client` built once with `timeout_secs`,
the resolved secret, and the URL. `deliver` serializes the event to a `String`,
computes the HMAC over exactly those bytes, and sends them as the body (§3).
A non-2xx response is an error, matching `HttpStatusListResolver`'s treatment.

Tests use a recording fake implementing the same trait, so **no mock HTTP server
is required** anywhere in the suite (D7).

### 4.4 Dispatch

The sink is constructed once in `serve()` and held in `AppState` as
`Option<Arc<dyn WebhookSink>>` — `None` when unconfigured, which makes "webhook
off" a cheap `is_none()` check rather than a config re-read per request.

Every call site is a small helper in `server.rs` that clones the `Arc`, builds
the event, and `tokio::spawn`s the delivery. The spawned task logs the outcome
and returns; nothing awaits it, so no handler's latency or status depends on the
endpoint (D2, §4.3 of root AGENTS.md).

| Site | Fires |
| --- | --- |
| `create_verification_handler` | `presentation_request_delivered` for `dc_api` and `dc_api_signed`, reading the JWS/object out of the `CreateVerificationResponse` it is about to return |
| `get_request_object_handler` | `presentation_request_delivered` for `request_uri`, with the JWS it just built — once per fetch (D5) |
| `submit_vp_response` | `verification_completed`, after `verify_vp_response` returns, on both arms |

### 4.5 Capturing the `vp_token`

`do_verify_vp_response` gains `captured_vp_token: &mut Option<serde_json::Value>`
and assigns it immediately after extraction (`verify.rs:1318`), before any check
runs, so a structural failure later still yields the token. `verify_vp_response`
gains the same out-param and passes it through; `submit_vp_response` owns the
local and reads it on both arms.

The assignment is gated on `include_raw_artifacts`, so an unconfigured
deployment does not even clone the value.

**`VerificationTransaction` is untouched** (D8). Because the token is never a
field on a persisted type, it *cannot* reach storage — the invariant is
structural rather than a discipline someone must remember at each save site.

### 4.6 Logging

Per delivery attempt, one record: `event`, `tx_id`, `http.status`, `latency_ms`;
on failure `error.kind` and `error.detail`. A failed delivery is `warn` — it is a
degraded diagnostic feed, not a service fault (root AGENTS.md §4.5).

**Never logged:** the event body (it is the PII), the webhook secret, the
computed signature. The URL is operator-authored configuration and is safe.

New field names are operator-facing API and go in
`docs/manual/reference/log-fields.md`.

### 4.7 Relationship to the existing log diagnostics

Unchanged and not replaced. The same bytes, three channels:

| | Log diagnostics | Artifact webhook |
| --- | --- | --- |
| Enabled by | `--log-sensitive` + `RUST_LOG=trace` | `verifier.webhook` + `include_raw_artifacts` |
| Delivered to | the local log stream | an operator-owned HTTP endpoint |
| Covers | Request Object (all transports) + `decrypted_response` | Request Object (all transports) + `vp_token` + the verdict |
| Retention | the log aggregator's | the receiver's |
| Loss | none (synchronous) | possible, at-most-once (D2) |

## 5. Security & Privacy

- `include_raw_artifacts` creates a **PII egress path**: disclosed claims leave
  the process to another system. This is why it is separate from the enable flag
  (D4), why §4.1 requires `https` for non-loopback URLs, and why an unsigned
  artifact-bearing configuration warns at startup.
- HMAC-SHA256 over the exact body (D6) lets the receiver establish authenticity
  independently of transport, so a leaked URL alone does not let a third party
  forge audit records.
- The secret follows `api_key` / `api_key_env` (§3) and is never logged.
- **No new read surface.** Unlike the rejected §10 design, nothing is exposed on
  any HTTP route and nothing is stored, so there is no new at-rest footprint and
  the admin API is unchanged.
- Root AGENTS.md **§4.5 holds**: the only new log records are the delivery
  outcome (§4.6) and the §4.1 startup warning, neither carrying an artifact.

## 6. Testing Strategy

TDD throughout; the gate is root AGENTS.md §5.1 (`cargo fmt`;
`cargo nextest run --workspace --no-fail-fast --status-level fail`;
`cargo clippy --workspace --all-targets -- -D warnings`), plus
`mkdocs build --strict` for doc changes. The recording fake sink (D7) means every
case below is a unit or integration test with no network and no mock server.

| Area | Test | Location |
| --- | --- | --- |
| Config | `https` enforced for non-loopback; loopback `http` accepted; unsigned + artifacts warns | `foundry-core` config tests |
| Secret | literal beats `secret_env`; env path resolves through the injected lookup | `foundry-verifier` |
| D6 | the signature verifies against the exact transmitted bytes, and changing one byte breaks it | `foundry-verifier` |
| D10 | `verification_completed` carries the full `VerificationResult` with `include_raw_artifacts` off | `crates/foundry/tests/` |
| D4 | `vp_token` and `request_object_jws` are absent with the flag off, present with it on | `crates/foundry/tests/` |
| **The point** | `verification_completed` fires on a **failed** verification, carrying the `vp_token` | `crates/foundry/tests/` |
| D2 | a sink that errors, and a sink that hangs past `timeout_secs`, both leave the wallet's HTTP status and body byte-identical | `crates/foundry/tests/wallet_verification.rs` |
| D5 | two fetches of `GET /vp/request/:id` produce two events | `crates/foundry/tests/wallet_verification.rs` |
| D3 | `dc_api` emits an event carrying `dc_api_request`; `dc_api_signed` one carrying `request_object_jws` | `crates/foundry/tests/wallet_verification.rs` |
| §4.6 | no event body, secret, or signature appears in any log record at trace level | `crates/foundry/tests/logging_redaction.rs` |
| Off by default | with no `webhook` config, no sink is constructed and no behaviour changes | `crates/foundry/tests/` |

## 7. Open Questions

**O1 — Does `presentation_request_delivered` fire when `include_raw_artifacts`
is off?** §4.2 says yes, as a PII-free record that a request was served.
**Recommendation: keep it.** It is the only signal distinguishing "the wallet
never fetched the request" from "the wallet fetched it and abandoned the flow",
which is a common interop failure. The counter-argument is event volume for a
consumer that only wants verdicts; a future `events:` allow-list would address
that and is out of scope here.

**O2 — Should the verdict event include the DCQL query?** The receiver gets
`result.credentials[].query_id` but not the query those ids refer to, so an audit
record is not self-contained without correlating to the creation call.
**Recommendation: defer.** It is operator-authored, non-PII, and cheap to add,
but it widens the event contract before there is a consumer to validate it
against.

**O3 — Timestamp in the payload.** §4.2 omits it deliberately. If the receiver
needs send-time rather than arrival-time (clock skew in an audit trail), it must
be threaded in as a parameter from each handler, which reads the clock already.
Flagged rather than decided.

## 8. Files Touched

| File | Change |
| --- | --- |
| `crates/foundry-core/src/config/model.rs` | `WebhookConfig` struct replacing `Option<serde_json::Value>` |
| `crates/foundry-core/src/config/validate.rs` | `https`/loopback rule; unsigned-artifacts warning |
| `crates/foundry-verifier/Cargo.toml` | `hmac = { workspace = true }` |
| `crates/foundry-verifier/src/webhook.rs` | **New** — `WebhookEvent`, `WebhookSink`, `HttpWebhookSink`, secret resolution |
| `crates/foundry-verifier/src/lib.rs` | Module declaration + `pub use` |
| `crates/foundry-verifier/src/verify.rs` | `captured_vp_token` out-param on `verify_vp_response` and `do_verify_vp_response` |
| `crates/foundry/src/server.rs` | Sink in `AppState`; three dispatch sites; construction in `serve()` |
| `crates/foundry/src/commands.rs` | Sample-config block for the webhook |
| 24 `VerifierConfig` literals | `webhook: None` already present — typed change may need no edit |
| `docs/manual/reference/configuration.md` | The `webhook` block |
| `docs/manual/reference/log-fields.md` | Delivery field names |
| `docs/manual/verification/request-diagnostics.md` | §4.7's three-channel comparison |
| `crates/foundry-verifier/AGENTS.md` | Module map row; Gotchas for D2, D5, D8 |

`openapi.json` is **not** regenerated: no HTTP route, request shape, or response
shape changes.

## 9. Out of Scope

- Retries, dead-lettering, or any durable delivery state (D2).
- An `events:` allow-list letting a consumer subscribe to a subset (O1).
- Delivering issuance events; this is verifier-only.
- Any change to the existing log-diagnostics behaviour or to root AGENTS.md §4.5.
- Exposing artifacts on `GET /admin/verification/requests/{id}` — see §10.

## 10. Rejected Alternative — Local Persistence

The first draft of this design stored both artifacts in a `verification_raw`
storage row under its own TTL (default 900 s) and hydrated them onto
`GET /admin/verification/requests/{id}`. It was rejected once the consumer was
identified as an operator-owned service rather than a human reading the admin
API. Recorded because the reasoning constrains any future revival:

- **It answered a different question.** Storage serves *pull* by a human; the
  stated need is *push* to a system. A webhook does not serve the admin API and
  the storage design does not serve a SIEM.
- **The TTL was harder than it looked.** `get_kv` does not filter on
  `expires_at` (`crates/foundry-core/src/storage/sqlite.rs:53`); expiry is
  enforced solely by `purge_expired`, swept every 60 s
  (`server.rs:1913`). A TTL therefore means "deleted within ~60 s of expiry",
  not "unreadable at expiry".
- **The defaults conflicted.** `storage.transaction_ttl_secs` defaults to 600 s
  (`model.rs:109`), shorter than the requested 900 s, so stock configuration put
  artifacts outliving the transaction addressing them — requiring a startup
  warning for a state an operator never chose.
- **ECDSA forced awkward machinery.** Because signing is randomized, a stored
  Request Object built eagerly is not the one served later, which forced
  `GET /vp/request/:id` to serve-stored-then-fall-back. Emitting at the moment
  of delivery removes the problem rather than working around it.
- **It required a breaking API change.** `save_verification_transaction` would
  have taken a TTL parameter and stripped fields before serializing, so that
  holder PII could not leak into the transaction row — an invariant maintained by
  discipline. D8 achieves the same guarantee structurally, by never putting the
  token on a persisted type.

Should local retention be wanted **in addition** later, it is additive: the
capture point (§4.5) and the config gate (§4.1) are shared, and only a storage
row and an admin-side hydration would be new.
