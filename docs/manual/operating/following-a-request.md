# Following a Request

## Following a request

Every access record carries these fields. They are stable names — alerting and
log queries can rely on them:

| Field | Meaning |
| --- | --- |
| `request_id` | Random per request; also returned in the `x-request-id` response header |
| `method` | HTTP method |
| `route` | The route **template** (`/vp/response/:id`), never the concrete path |
| `listener` | `admin` or `wallet` — the two listeners bind different ports |
| `http.status` | Response status |
| `latency_ms` | Time to produce the response |
| `error.kind` | Stable error-variant name, on failure records |
| `error.detail` | Human-readable reason, length-capped |
| `request_encrypted` | Whether the Credential Request arrived as a decrypted `application/jwt` JWE, on `handle_credential_request`'s span |

The level follows the status class: 2xx/3xx at `info`, 4xx at `warn`, 5xx at
`error`.

**To reconstruct one wallet interaction**, grep the domain transaction id
(`tx_id`) rather than `request_id`. A presentation spans three requests across
both listeners — `POST /admin/verification/requests`, then the wallet's
`GET /vp/request/:id` and `POST /vp/response/:id` — and `tx_id` is what ties them
together:

```bash
# Whole flow for one transaction
foundry serve --config config.yaml 2>&1 | grep 'v_1a2b3c'

# Or, if a wallet reported a failure, start from the header it saw
foundry serve --config config.yaml 2>&1 | grep '<the x-request-id value>'
```

A failed verification records which stage rejected the presentation, using the
same check names the successful path reports, at two levels. **Cross-cutting**:
`jwe_decryption`, plus exactly one of `requested_credentials_answered` (DCQL
query without `credential_sets`) or `credential_sets_satisfied` (with
`credential_sets`) — mutually exclusive. **Per-credential**:
`sd_jwt_vc_signature_and_kb_jwt` or `mdoc_issuer_auth_and_device_signature`,
`dcql_match`, `status_check`, `transaction_data_binding` (only present when the
request carried `transaction_data`). The reason is also persisted on the
transaction, so it appears in the admin API and the test console rather than only
in the log.

Because one `vp_token` may answer several DCQL credential queries, a
per-credential check record additionally carries `credential` — the DCQL
credential query id it belongs to — so `check=dcql_match passed=false` says
*whose*. The final verdict record carries `credentials_requested` and
`credentials_answered`, which are **counts, never identifiers**: a wallet that
returned fewer credentials than were asked for is visible at a glance, and the
failed `requested_credentials_answered` check names the missing query ids — or,
for a `credential_sets` request, the failed `credential_sets_satisfied` check
names the unsatisfied set and the options that would have satisfied it.

Each credential also gets one **roll-up record** — `credential verified` at
`INFO`, or `credential failed` at `WARN` — carrying `credential` (the DCQL query
id), `format`, `credential_type` (the `vct` for SD-JWT VC, the `docType` for
mdoc), and the `checks` / `checks_passed` counts. That record is the one to read;
the per-check records above are the drill-down. `credential_type` is the type the
presentation *asserted*, and is authenticated only when that credential's format
check passed — the same caveat that governs its claims.

Because a failure in one credential no longer abandons the others, a mixed
verdict is fully reported: the `vp response not verified` record carries
`credentials_failed` alongside `credentials_requested` and
`credentials_answered`, and every credential appears in the admin API and test
console with its own checks — including the ones that failed. A credential whose
format check failed carries **only** that check: `dcql_match` and `status_check`
are not run against claims that were never obtained, so one fault is reported
once rather than three times.
