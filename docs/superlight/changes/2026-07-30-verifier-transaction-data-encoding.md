# Verifier: encode `transaction_data` as base64url strings and validate entries

**Date:** 2026-07-30
**Type:** bugfix
**Track:** C (investigate) → A (direct)
**Branch:** `superlight/2026-07-30-verifier-response-type`
**Spec:** n/a — Track A/C
**Plan:** n/a — Track A/C

## Problem

Found while auditing the wallet's request-resolution path for the
`response_type` fix, not reported from a device.

foundry emitted `transaction_data` as an array of **raw JSON objects**:

```rust
pub transaction_data: Option<Vec<serde_json::Value>>,   // request.rs:22, transaction.rs:39
payload_map.insert("transaction_data".to_string(), serde_json::json!(td));
```

OpenID4VP v1.0 §8.4 defines each entry as a **base64url-encoded (unpadded) JSON
object**. The EUDI iOS wallet decodes accordingly:

```swift
let transactionData = json["transaction_data"].arrayObject as? [String]
// RequestAuthenticator.swift:48
```

An array of objects fails that cast, yielding `nil`. `parseTransactionData` then
short-circuits on `guard let data = transactionData else { return nil }`, so the
transaction data was **silently discarded with no error on either side**.

This is the worst failure shape available: the relying party believes it bound
the presentation to a transaction, the wallet never shows or signs it, and
nothing anywhere reports a problem.

Not currently triggered in production — the deployed `over18` named query sends
no transaction data — but it would fail quietly the first time it was used.

## Root Cause

Wrong wire type: object where the spec (and every wallet) requires a
base64url-encoded string. foundry had no encoding step at all.

## Approach

Encode at request-creation time, and **validate before encoding**.

The validation is the non-obvious half, and the reason a naive fix would have
been worse than the bug. A wallet does not skip an entry it dislikes — it aborts
the whole presentation:

```swift
return try data.compactMap { item in
  try TransactionData.parse(item, supportedTypes: ..., presentationQuery: ...).get()
}   // ResolvedRequestData.parseTransactionData — .get() throws
```

and `TransactionData.parse` enforces that the entry's `type` is supported and
that every `credential_ids` element names a credential present in the DCQL query
(`hasCorrectIds`). So blindly base64-encoding whatever the admin API was handed
would have converted today's silent drop into a **hard, opaque device-side
failure**. Validating at creation time turns that into a precise HTTP 400 for
whoever built the request.

Rejected alternatives:

- *Change the admin API to accept pre-encoded strings.* Rejected: it pushes
  base64 plumbing onto every relying party and breaks the documented request
  schema. `CreateVerificationRequest.transaction_data` still accepts objects; its
  OpenAPI schema is unchanged.
- *Accept objects **or** pre-encoded strings.* Rejected: a bare string cannot be
  validated without decoding it, so it would reintroduce an unvalidated path
  straight to the wallet. Non-objects are now rejected explicitly.
- *Reuse `VerificationError::Dcql` for the new failures.* Rejected as dishonest
  labelling — "dcql error: transaction_data[0] requires ... 'type'" misdirects.
  Added `VerificationError::InvalidRequest` instead.
- *Inject `transaction_data_hashes_alg` from `verifier.transaction_data_hashes_alg`.*
  Deliberately not done: it would change the bytes being hashed, and the config
  field is unused everywhere else. Left as a follow-up rather than smuggled in.

## Changes

- `crates/foundry-verifier/src/request.rs`
  - new `encode_transaction_data(entries, dcql)`: validates each entry is an
    object with a non-empty string `type` and a non-empty `credential_ids` array
    of strings, that every id exists in the DCQL query, then base64url-encodes
    (unpadded) the entry's JSON.
  - `create_verification_request` validates + encodes **before** persisting, so a
    bad entry fails the request instead of reaching a wallet.
- `crates/foundry-verifier/src/transaction.rs`
  - `VerificationTransaction.transaction_data` is now `Option<Vec<String>>`,
    storing the encoded form actually advertised — so a future
    `transaction_data_hashes` check hashes byte-identical input.
- `crates/foundry-verifier/src/error.rs`
  - new `InvalidRequest(String)` variant ("invalid request: {0}").
- `crates/foundry/src/server.rs`
  - `verifier_admin_error_response` maps `InvalidRequest` → **400**. Required
    explicitly: the match has a `_ =>` catch-all, so a new variant would
    otherwise have silently become a 500 (root AGENTS.md §4.3).
- `openapi.json` — regenerated via `cargo run -p foundry -- openapi --out openapi.json`.
  Only `VerificationTransaction.transaction_data` changed (`items: {}` →
  `items: {type: string}`). `openapi-wallet.json` does not reference the schema
  and is untouched.

## Tests

All three confirmed RED first, for the right reasons (objects emitted; `Ok`
where an error was required).

- `test_transaction_data_is_emitted_as_base64url_strings` — the emitted entry is
  a string, and base64url-decodes back to exactly the caller-supplied object.
- `test_transaction_data_requires_type_and_credential_ids` — missing `type`,
  missing `credential_ids`, and a non-object entry each yield
  `InvalidRequest` with a message naming the offending field.
- `test_transaction_data_credential_ids_must_exist_in_dcql` — an id absent from
  the DCQL query is rejected and named in the error.

Two pre-existing tests asserted the old wire shape and were updated
deliberately, not to make the suite pass: `test_create_verification_request_named_query`
and `test_build_signed_request_object_and_verify_jws` now supply valid entries
(`credential_ids: ["c1"]`, matching the `over18` fixture) and the latter decodes
the base64url string before asserting on `amount`.

Verified: `cargo test --workspace` (420 passed, 0 failed),
`cargo clippy --workspace --all-targets -- -D warnings` (clean),
`cargo fmt --check` (clean).

## Deployment note

`VerificationTransaction` is persisted as JSON, so this changes the stored shape.
A transaction written by the previous build **with** non-null `transaction_data`
would fail to deserialize after deploy. In practice the impact is nil: the
deployed configuration sends no transaction data, and `null` deserializes into
`None` unchanged. Transaction TTL is 600s regardless.

## Follow-ups (not done here)

- **foundry never verifies `transaction_data_hashes` at all.** `verify.rs` does
  not read the KB-JWT claim, and `verifier.transaction_data_hashes_alg` is
  config-only — never referenced by any verification logic. So transaction data
  is advertised, and now correctly advertised, but the binding is still
  **unenforced**: a wallet could omit or forge `transaction_data_hashes` and
  verification would pass. This fix makes the request side correct; it does not
  make the feature trustworthy. That is the more important piece of work.
- Optionally populate each entry's `transaction_data_hashes_alg` from config.