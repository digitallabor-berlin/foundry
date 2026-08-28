# Verifier — Verification Events Delivered to an Operator Webhook

**Date:** 2026-08-28
**Spec:** [`2026-08-28-verifier-artifact-webhook-design.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/superpowers/specs/2026-08-28-verifier-artifact-webhook-design.md)
**Plan:** [`2026-08-28-verifier-artifact-webhook.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/superpowers/plans/2026-08-28-verifier-artifact-webhook.md)

## What Changed

Verification events — the verdict, and optionally the verbatim Request Object
and the decrypted `vp_token` — are now `POST`ed to an operator-configured HTTP
endpoint. Foundry stores none of it.

Two events:

| `event` | Fires | Carries |
| --- | --- | --- |
| `presentation_request_delivered` | Per `GET /vp/request/:id` fetch, and per DC API request creation | `tx_id`, `transport`, and with artifacts on `request_object_jws` or `dc_api_request` |
| `verification_completed` | Per submitted response, whether it verified or **failed** | `tx_id`, `state`, the full `result`, and with artifacts on `vp_token` |

Configured under `verifier.webhook`; its *presence* is the enable flag.
`include_raw_artifacts` is a second, nested gate — off by default — because it
is the one that authorises holder PII to leave the process. Conflating the two
would make a verdict feed and a PII egress the same decision.

Operator documentation:
[Request Diagnostics](https://github.com/digitallabor-berlin/foundry/blob/main/docs/manual/verification/request-diagnostics.md).

## Design Decisions Worth Re-reading

- **Dispatch is fire-and-forget.** `dispatch_webhook` (`server.rs`)
  `tokio::spawn`s and never joins. Root AGENTS.md §4.3 classifies an HTTP
  outcome by what the *protocol* did, and "the operator's audit sink was down"
  is none of those outcomes. Awaiting would let a slow endpoint add latency to
  a wallet's request and a dead one change its status code. Delivery is
  best-effort and at-most-once; a failure is a `warn`, not a retry. Pinned by
  `a_failing_sink_does_not_change_the_wallet_response`, which runs the same
  flow twice — with and without a failing sink — and compares the responses
  rather than asserting a hardcoded shape.
- **The `vp_token` travels through an out-param, not a field.**
  `verify_vp_response` gained a fifth parameter,
  `captured_vp_token: &mut Option<serde_json::Value>`, populated at extraction
  *before any check runs*. Two consequences: a failed verification still yields
  the bytes that explain it (the case the feed exists for), and because
  `VerificationTransaction` is serialized wholesale into storage, keeping the
  token off that type means it *cannot* reach storage — structural, not a
  discipline someone must remember at each save site.
- **The HMAC covers the exact transmitted bytes.**
  `build_signed_request_parts` returns `(body, signature)` and
  `HttpWebhookSink::deliver` sends that `String` with `.body(..)`. `.json(..)`
  would re-serialize and could transmit bytes the signature does not cover.
  This is why `foundry-verifier`'s `reqwest` has no `json` feature.
- **`WebhookError` is deliberately not a `VerificationError` variant.** It never
  reaches the HTTP error mappers, and adding a variant they do not handle is how
  an unmapped error silently becomes a 500.
- **Request events fire per fetch, not per transaction.** ECDSA signing is
  randomized, so each served copy genuinely is different bytes and the event's
  contract is "these exact bytes went out now". Deduping would require
  remembering what was sent, i.e. storage.

## Deviations From the Plan

Three, all recorded here rather than silently absorbed:

1. **`is_loopback_host` was reused, not re-added.** The plan's Task 1 supplied a
   new loopback predicate accepting any `Ipv4Addr::is_loopback()`.
   `config/validate.rs` already had one — exact four forms
   (`localhost`, `127.0.0.1`, `::1`, `[::1]`), documented against GAP-VCI-08 —
   and defining a second would have meant two functions answering "is this host
   loopback" differently for no stated reason. The existing one is stricter,
   which is the right direction for a PII egress.
2. **`async-trait` was not added to `foundry`'s `[dev-dependencies]`.** Task 5
   said to add it if absent; it is already a normal `[dependencies]` entry, which
   integration tests see.
3. **Task 4 needed 46 unlisted call-site updates.** The plan named only the sole
   production call site; `verify.rs`'s own test module holds 46 more. The
   temporary `let _ = &captured_vp_token;` the plan offered for a green
   intermediate gate proved unnecessary — a `&mut` borrow counts as a use, so no
   unused-variable warning ever appeared.

One test was strengthened beyond the plan. The plan's redaction test asserted
the event body never reaches a log by searching for the fixture's `given_name`.
`logging_redaction.rs`'s own fixture has empty `trust_anchors`, so no fully
trusted presentation can run there. Instead the test encrypts a **planted
string** to the transaction's ephemeral key — decryption succeeds, the token is
captured, and the SD-JWT format check then fails — so the probe is provably in
the event body. It ships as two tests: one at the most permissive setting
(`TRACE` + sensitive payloads) proving the secret and signature are unreachable
rather than merely gated, and one with sensitive payloads off proving the body
itself is not logged. The second could not run at the permissive setting,
because `verify_vp_response`'s own gated `decrypted_response` diagnostic
legitimately reproduces the planted value there — so the sensitive-on test
asserts the value *is* present, which is what makes the sensitive-off test's
absence assertion mean something.

## Deferred (Design §7)

- **O1 — request events when artifacts are off.** Kept, as §7 recommends: it is
  the only signal distinguishing "the wallet never fetched the request" from
  "the wallet fetched it and abandoned the flow". Pinned by
  `a_request_event_fires_without_artifacts_when_they_are_disabled`. A future
  `events:` allow-list would address volume for verdict-only consumers.
- **O2 — DCQL query in the verdict event.** Deferred. Operator-authored and
  non-PII, but it widens the event contract before a consumer exists to
  validate it against.
- **O3 — payload timestamp.** Deferred. Send-time rather than arrival-time
  would have to be threaded in from each handler.

## Verification

```text
cargo nextest run --workspace --no-fail-fast --status-level fail
     Summary [   2.427s] 1196 tests run: 1196 passed, 11 skipped
cargo clippy --workspace --all-targets -- -D warnings   # clean
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
     Summary [   0.420s] 2 tests run: 2 passed, 0 skipped
mkdocs build --strict                                    # clean
git diff --exit-code openapi.json openapi-wallet.json    # unchanged
```

`openapi.json` and `openapi-wallet.json` are byte-identical: no route, request
shape, or response shape changed. The webhook adds an *outbound* call only.
