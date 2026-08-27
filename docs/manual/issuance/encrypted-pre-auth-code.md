# Encrypted Pre-Authorized Code (Google Wallet extension)

Google Wallet's OpenID4VCI profile defines an `encrypted_pre-authorized_code`
Token Request parameter: the pre-authorized code carried as a JWS nested inside
a JWE instead of as a plaintext string. **This is a vendor profile, not a
specification** — no OpenID4VCI, HAIP or OAuth document defines it — so it is
off by default and a deployment that never mentions it behaves exactly as
before.

```yaml
issuer:
  encrypted_pre_authorized_code:
    mode: disabled       # disabled (default) | optional | required
    max_age_secs: 300    # how old the envelope's `iat` may be

  # Access-token lifetime, in seconds. Default 600.
  access_token_ttl_secs: 600
```

- **`mode: disabled`** (the default) — the parameter is **rejected** if
  present, never silently ignored. Ignoring it would let a wallet believe its
  code was protected when it was not.
- **`mode: optional`** — either form is accepted, but **exactly one** must be
  present. A request carrying both is rejected rather than resolved by
  precedence: two codes in one request is a client bug, and picking a winner
  hides it. This is the migration rung.
- **`mode: required`** — the encrypted form is mandatory and a plaintext
  `pre-authorized_code` is **rejected**. Without that rule `required` would be
  advisory; it is the same anti-downgrade posture RFC 9449 §7.2 takes for a
  DPoP-bound token presented as Bearer.

Enabling the extension (`optional` or `required`) requires, and
`Config::validate()` enforces at startup:

- `issuer.wallet_attestation.mode` other than `disabled` — the envelope's inner
  JWS is verified against the Client Attestation's `cnf.jwk`, so without a
  verified attestation there is no key to check it with; and
- `issuer.request_encryption` with at least one key — the profile reuses those
  very keys ("the same key used to encrypt the request to the Credential
  Endpoint"), so there is deliberately no second key list to configure or to
  drift.

`access_token_ttl_secs` is independent of the extension and applies to every
grant. It drives both the `expires_in` on the wire and the lifetime of the
transaction row that access token addresses — one value, so the record can
never expire out from under a token still nominally valid. It is **not** the
same knob as `storage.transaction_ttl_secs`, which bounds how long an *offer*
stays redeemable before `/token` is ever called.

---
