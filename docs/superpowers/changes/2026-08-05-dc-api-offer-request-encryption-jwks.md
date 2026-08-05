# DC API offer must embed the request-encryption JWKs

**Date:** 2026-08-05
**Crates:** `foundry-issuer`, `foundry`
**Kind:** Bug fix (interop-blocking)

## Symptom

Google's CMWallet sample completed `/challenge`, `/token` (DPoP accepted) and
`/nonce`, then stopped. `POST /credential` never reached foundry, so foundry's
logs showed nothing after `/nonce` and the admin console eventually surfaced a
`Request failed (404)` — the console polling an offer that had passed
`transaction_ttl_secs`. Both were downstream symptoms.

## Root cause

`build_dc_api_offer` (`crates/foundry-issuer/src/offer.rs`) called
`build_issuer_metadata(cfg, &[])` — an empty request-decryption key slice — on
the reasoning recorded in the removed comment: *"Credential offers carry no
encryption metadata; wallets read it from the well-known document."*

That premise is false for the DC API offer. The offer **embeds**
`credential_issuer_metadata`, and a DC API wallet is handed it in-process; it
never fetches `GET /.well-known/openid-credential-issuer`. CMWallet deserializes
the embedded copy directly (`CredentialOfferEndpoint.kt:226`).

So the wallet received:

```json
"credential_request_encryption": {
  "enc_values_supported": ["A128GCM","A256GCM"],
  "encryption_required": true,
  "jwks": { "keys": [] }
}
```

`encryption_required: true` with no key to encrypt to. OpenID4VCI L871/L873
require the Client to encrypt the Credential Request "using the parameters from
the `credential_request_encryption` object in the Credential Issuer Metadata"
(L1372 defines that object), so the mandated behaviour is unperformable and a
conformant wallet can only abort. CMWallet's
`getCredentialRequestEncryptionKey()` throws
`UnsupportedOperationException("No supported encryption key")` — before any
network call, which is why `/credential` never appeared in the logs.

The well-known endpoint was always correct (`server.rs` passes
`&state.request_decryption_keys`); only the offer-embedded copy was empty.

## Fix

Thread the keys through instead of defaulting:

- `build_dc_api_offer(cfg, offer, request_decryption_keys)`
- `create_offer(cfg, storage, req, now_unix, request_decryption_keys)`
- `create_offer_handler` passes `&state.request_decryption_keys`

## Verification

- New regression test `dc_api_offer_embeds_the_request_encryption_jwks`
  (`create_offer.rs`), confirmed to **fail** against the pre-fix code with the
  exact payload the wallet saw, and pass after.
- Live probe against the deployed `foundry_config.yml`: the offer's embedded
  `jwks` now carries the ECDH-ES P-256 key and is **identical** to the
  well-known document's.
- Scoped gate (root AGENTS.md §5.1): `cargo test -p foundry-issuer -p foundry`
  green, `cargo clippy -p foundry-issuer -p foundry --all-targets -D warnings`
  clean, `cargo fmt --check` clean.

## Generalisation recorded

`crates/foundry-issuer/AGENTS.md` Gotchas now states that the embedded metadata
is the only metadata a DC API wallet sees, so **any** member sourced from
runtime state (loaded keys, not just `Config`) must be threaded in. Narrowing
`credential_configurations_supported` to the offered ids remains the sole
intended difference from the well-known document.
