# Log Fields

The structured fields foundry's log records carry.

> These names are operator-facing API. Renaming one is a breaking change for
> anyone consuming the logs, and `crates/foundry/tests/instrumentation_hygiene.rs`
> asserts that each is still emitted somewhere in the source tree.

## Access records

Carried by the per-request record on both listeners.

| Field |
| --- |
| `request_id` |
| `tx_id` |
| `route` |
| `method` |
| `listener` |
| `http.status` |
| `latency_ms` |
| `error.kind` |
| `error.detail` |

## Per-credential verification records

| Field |
| --- |
| `credential` |
| `credential_type` |
| `format` |
| `check` |
| `passed` |
| `checks` |
| `checks_passed` |

## Verdict record

| Field |
| --- |
| `credentials_requested` |
| `credentials_answered` |
| `credentials_failed` |

## Webhook delivery records

Emitted once per attempted delivery of a verification event, when
`verifier.webhook` is configured. A successful delivery is `debug`; a failed
one is `warn`.

| Field |
| --- |
| `event` |
| `tx_id` |
| `http.status` |
| `latency_ms` |
| `error.kind` |
| `error.detail` |

`event` is the event type — `presentation_request_delivered` or
`verification_completed` — and is the same value the delivered body's `event`
member and the `X-Foundry-Event` header carry. `http.status` and `latency_ms`
appear on the success record; `error.kind` and `error.detail` on the failure
one. The event **body** is never logged, at any level, in any mode: it is the
payload the feature exists to move and it carries holder PII. Neither the
webhook secret nor the computed signature is ever logged.

What each field means, and how to use them to reconstruct one wallet
interaction, is on [Following a Request](../operating/following-a-request.md).
How to select levels, formats and payload logging is on
[Logging](../operating/logging.md).
