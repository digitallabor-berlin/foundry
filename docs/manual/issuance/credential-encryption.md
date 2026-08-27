# Credential Request / Response Encryption

On top of TLS, `POST /credential` can decrypt an encrypted Credential Request
and/or encrypt its Credential Response, per OpenID4VCI's Credential Request,
Credential Response, and Encrypted Messages sections. Both directions are
gated independently and **default to off** — an unconfigured deployment's
wire behaviour and metadata document are byte-identical to a build without
this feature.

```yaml
issuer:
  request_encryption:
    keys: [issuer_request_enc]               # required; names entries in the top-level `keys:` map
    enc_values_supported: [A128GCM, A256GCM] # required, non-empty, subset of {A128GCM, A256GCM}
    encryption_required: false               # default false — reject an unencrypted request when true
  response_encryption:
    enc_values_supported: [A128GCM, A256GCM] # required, non-empty, subset of {A128GCM, A256GCM}
    encryption_required: false               # default false — requires request_encryption to also be set when true
```

- **`request_encryption.keys`** — one or more names from the top-level
  `keys:` map. Each entry must set `alg: ES256` — naming the *key material*,
  not the JOSE algorithm: `Config::validate_key_material` parses every
  `keys:` entry's `alg` as a signature algorithm, so `ECDH-ES` there would fail
  startup. The entry does not need an `x5c`: it is never read for a
  request-encryption key, since an ECDH-ES key-agreement key is not a signing
  key and has no certificate chain. The *published* JWK's own `alg` is always
  `"ECDH-ES"`, stamped by `DecryptionKey::published_jwk`, independent of the
  `keys:` entry's `alg`. Listing more than one key enables zero-downtime
  rotation: publish the new key alongside the old one, let in-flight wallets
  keep using the old `kid`, then remove the old key once traffic has drained.
- **`kid`** is not configurable. It is derived as the RFC 7638 JWK thumbprint
  of each key's public component, so it is stable across restarts and
  collision-free by construction.
- **`enc_values_supported`** (both blocks) — the AEAD content-encryption
  algorithms this issuer will accept/produce. Must be non-empty and a subset
  of `{A128GCM, A256GCM}`. `alg` itself is always `ECDH-ES` (fixed, not
  configurable), and `zip` (compression) is never advertised or accepted.
- **`encryption_required`** (both blocks, default `false`) — when `true` on
  `request_encryption`, an unencrypted Credential Request is rejected
  outright (Encrypted Messages: reject unencrypted when required). When
  `true` on `response_encryption`, `request_encryption` must also be
  configured — `Config::validate()` rejects a config that sets one without
  the other, since a request carrying `credential_response_encryption` must
  itself arrive encrypted (Credential Request, substitution prevention).

`foundry quickstart` always generates a `keys/issuer_request_enc.pem` ECDH-ES
key, so enabling encryption later needs no separate key-generation step —
uncomment the two blocks above (shipped commented out) in the generated
`config.yaml`.

A wallet discovers the issuer's public encryption key(s) and both blocks'
capabilities from `.well-known/openid-credential-issuer`'s
`credential_request_encryption`/`credential_response_encryption` objects,
each present only when the corresponding config block is set.

---
