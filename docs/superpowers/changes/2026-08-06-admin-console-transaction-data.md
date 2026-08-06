# Admin Console — Transaction Data Support

**Date:** 2026-08-06
**Spec:** `docs/superpowers/specs/2026-08-06-admin-console-transaction-data-design.md`
**Plan:** `docs/superpowers/plans/2026-08-06-admin-console-transaction-data-plan.md`

## What Changed

Two source files: `crates/foundry-verifier/src/request.rs` (a bugfix) and
`crates/foundry/assets/console.html` (the feature). No endpoint changes and no
OpenAPI changes — `transaction_data` was already in the committed
`CreateVerificationRequest` schema.

- **`foundry-verifier`, `create_verification_request`:** the `dc_api` branch now
  inserts a conditional `transaction_data` key into `dc_api_obj`, carrying the
  already-encoded entries. Previously the function validated and persisted
  `transaction_data` for both transports but only `build_signed_request_object`
  (the `request_uri` path) advertised it, so a DC API request silently dropped
  it. OpenID4VP 1.0 §A.3 (L2421–L2431) lists `transaction_data` among the
  parameters supported over the W3C Digital Credentials API.
- **`console.html`:** the Verification card gains a collapsed
  `opt-disclosure` block holding a `transaction_data (JSON array)` textarea
  (`id="transaction-data-json"`). Non-empty contents are parsed and set as
  `payload.transaction_data`; blank leaves the key absent.

## Why the Bugfix Was In Scope

The console's transport selector offers `dc_api`. Shipping the input without
fixing the emission would have produced a transaction whose `transaction_data`
is `Some` — so `check_transaction_data_binding` is pushed — for a request the
wallet received without `transaction_data`, and therefore a failed check for a
constraint never communicated. The console would have reported a verification
failure for a request it never made.

## Validation Split

The console checks shape only: valid JSON, and a JSON array. Everything
per-entry — object-ness, non-empty `type`, non-empty `credential_ids`, every id
resolvable against the DCQL query — stays in `encode_transaction_data`, which
returns HTTP 400 with a per-index detail that the console's existing
`showError` already renders from `err.body.error`. Replicating that validator in
JavaScript was rejected: it is load-bearing and two copies would drift.

## Deliberately Not Done

- No structured entry builder. Entry bodies are `type`-specific and open-ended;
  OpenID4VP defines only `type`, `credential_ids` and
  `transaction_data_hashes_alg`.
- No echo of the advertised entries in the result panel. The
  `transaction_data_binding` check already reports pass/fail, and
  `renderVerificationResult` renders it generically with no changes.
- No signed DC API requests. VP-0197 / VP-0200 / VP-0202 remain
  `not-implemented`.

## Tests

- `dc_api_request_advertises_encoded_transaction_data`
  (`foundry-verifier/tests/conformance_vp.rs`) — the advertised array holds the
  base64url strings persisted on the transaction, and decoding one yields the
  injected `transaction_data_hashes_alg`.
- `test_dc_api_request_omits_transaction_data_when_absent`
  (`foundry-verifier/src/request.rs`) — the key is conditional, so an unused
  request keeps its prior shape.
- `console_has_transaction_data_input_for_verification`
  (`foundry/tests/console.rs`) — the served HTML carries the textarea, the
  disclosure, and the payload wiring.

## Conformance Report

VP-0198's evidence prose was reworded: it had asserted that `dc_api_obj`
"carries only" five named keys, which is no longer true. It now rests on
`client_id`'s absence instead of an exhaustive key list. No verdict changed and
no gap id was opened — §A.3's parameter list is phrased "the following are
supported", not as a MUST, so it has no clause row of its own, which is why the
omission escaped the original audit.