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

---
