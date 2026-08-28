# Presentation Request Diagnostics

## The presentation request as sent to the wallet

A wallet that rejects a presentation request rarely says why, and the request
cannot be reconstructed after the fact — the nonce and the ephemeral key are
per transaction. Foundry therefore records the request it actually sent, on
every transport:

| Field | Transport | Meaning |
| --- | --- | --- |
| `alg` / `jws_len` | `request_uri`, `dc_api_signed` | Always on, at `debug`: a Request Object was signed and served, under this algorithm and of this length. Carries none of its contents. |
| `request_object_jws` | `request_uri`, `dc_api_signed` | The compact JWS byte-for-byte as the wallet received it — paste into any JWT decoder, or replay against the wallet |
| `request_object_header` / `request_object_payload` | `request_uri`, `dc_api_signed` | The same object decoded, for reading at a glance |
| `dc_api_request` | `dc_api` | The request object handed to the invoking page. This transport has no signed form, so there is a JSON record only |
| `dc_api_request.request` | `dc_api_signed` | The signed Request Object (JWS Compact) handed to the invoking page, paired with `protocol: "openid4vp-v1-signed"` |

The three payload fields are `trace`-level **and** require
`sensitive_payloads` — the request object commits to the transaction nonce and
carries the ephemeral **public** JWK, so a level alone is not authorisation.
The ephemeral **private** key is never logged in either mode. Grep `tx_id` to
pair the request with the response it produced:

```bash
RUST_LOG=foundry_verifier=trace foundry --log-sensitive serve --config config.yaml \
  2>&1 | grep 'v_1a2b3c'
```

Without the flag, no payload is logged at any level. Regardless of the flag,
these are **never** logged: private and ephemeral JWKs, the admin API key,
access tokens, `c_nonce` values, ABCA `attestation_challenge` values, DPoP
`nonce` values, the nonce secret, pre-authorized codes, authorization codes,
transaction codes, the raw compact JWE of an encrypted Credential Request, the
decrypted Credential Request, the plaintext Credential Response when
encryption was requested, and the wallet's `credential_response_encryption.jwk`.
Public keys appear only as RFC 7638 thumbprints, the sole exception being the
verbatim presentation-request dumps above, where the ephemeral public JWK is
part of the object being reproduced. This is enforced by tests
(`crates/foundry/tests/logging_redaction.rs`), not by convention.

## The verification event webhook

The log diagnostics above deliver to the local log stream. Where the same
artifacts are wanted **off the box** — in an audit store, a fraud pipeline, a
support tool — configure `verifier.webhook` and foundry `POST`s a JSON event
to that endpoint instead. Foundry stores none of it.

```yaml
verifier:
  webhook:
    url: https://audit.example.com/vp-callback
    secret_env: FOUNDRY_WEBHOOK_SECRET
    timeout_secs: 5
    include_raw_artifacts: false
```

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | *(required)* | Destination. Must be `https`, unless the host is a loopback address (`localhost`, `127.0.0.1`, `::1`) — rejected at startup otherwise, because the body may carry holder PII |
| `secret` | *(none)* | HMAC key, literal. Takes precedence over `secret_env` |
| `secret_env` | *(none)* | Name of an environment variable holding the HMAC key |
| `timeout_secs` | `5` | Per-delivery HTTP timeout. Bounds the background task only; no wallet-facing request ever waits on it |
| `include_raw_artifacts` | `false` | Also transmit the verbatim Request Object and the decrypted `vp_token`. **Holder PII in the clear** |

The presence of `webhook` is the enable flag; `include_raw_artifacts` is a
second, separate gate. Without it the events still fire, carrying the verdict
and the transaction id but no holder data — a PII-free audit trail.

### Events

| `event` | Fires | Carries |
| --- | --- | --- |
| `presentation_request_delivered` | Once per `GET /vp/request/:id` fetch, and once per DC API request creation | `tx_id`, `transport`, and with artifacts on `request_object_jws` (signed transports) or `dc_api_request` (unsigned `dc_api`) |
| `verification_completed` | Once per submitted response, whether it verified or **failed** | `tx_id`, `state`, the full `result` verdict, and with artifacts on the decrypted `vp_token` |

A failed verification is the case this feed exists for: the `vp_token` is
captured at extraction, before any check runs, so it survives the failure that
made it interesting. The request event fires **per fetch**, not per
transaction — a wallet that retries produces two events, and because ECDSA
signing is randomized each carries genuinely different bytes.

With artifacts off, an absent artifact key is **absent, not null**, so a
receiver can test key presence rather than distinguish "not collected" from
"collected as null".

### Verifying an event

Each request carries `Content-Type: application/json`, `X-Foundry-Event` (the
same value as the body's `event` member), and — when a secret is configured —
`X-Foundry-Signature: sha256=<hex>`, an HMAC-SHA256 over the **exact** request
body bytes. Verify against the raw body, before parsing: re-serializing the
JSON will not reproduce the signed bytes.

Configuring `include_raw_artifacts` with no secret is permitted — the receiver
may be on a trusted network — but logs a warning at startup, because without
one the receiver cannot establish that an audit record came from this verifier.

### Delivery guarantees

Delivery is **best-effort and at-most-once**. Foundry spawns it and does not
wait: a slow endpoint adds no latency to a wallet's request, a dead one
changes no status code, and there is no retry and no queue. A failed delivery
appears only as a `warn` record (see
[Log Fields](../reference/log-fields.md)) — the event itself is gone.

That is a deliberate trade. A verification outcome is a protocol result; the
health of an operator's audit sink is not, and foundry has no HTTP status that
means "the webhook was down". If you need guaranteed delivery, terminate the
webhook at a queue you control.

### The same bytes, three channels

| | Log diagnostics | Artifact webhook |
| --- | --- | --- |
| Enabled by | `--log-sensitive` + `RUST_LOG=trace` | `verifier.webhook` + `include_raw_artifacts` |
| Delivered to | the local log stream | an operator-owned HTTP endpoint |
| Covers | Request Object (all transports) + `decrypted_response` | Request Object (all transports) + `vp_token` + the verdict |
| Retention | the log aggregator's | the receiver's |
| Loss | none (synchronous) | possible, at-most-once |

The webhook neither replaces nor disables the log diagnostics; the two are
independent.

---
