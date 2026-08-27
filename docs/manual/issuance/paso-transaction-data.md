# PaSO Transaction Data Metadata

foundry can act as a **PaSO Attestation Provider**: publishing signed metadata
that describes the transaction data a credential can be used to authorize, so a
Wallet can render a meaningful consent screen for a payment or other SCA flow.
Governed by [`docs/specs/paso-core.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/paso-core.md) and
[`docs/specs/paso-proof-metadata.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/paso-proof-metadata.md).

The feature is **entirely config-driven and defaults to off**. A credential type
becomes a PaSO Credential type by declaring `transaction_data_types` — presence
alone is the switch. A deployment with no such type produces byte-identical wire
output to a build without this feature.

```yaml
credential_types:
  - id: com.emvco.dpc.card
    format: dc+sd-jwt
    vct: com.emvco.dpc.card
    # Declaring this makes the type a PaSO Credential type. It turns on the
    # `credential_metadata_uri` in Issuer Metadata and the wallet-facing
    # GET /credential-metadata/com.emvco.dpc.card route.
    transaction_data_types:
      # PaSO Core §5.2: urn:paso:sca:<domain>:<suffix>:<version>, where the
      # version is a positive integer without leading zeros and is the final
      # segment. Validated at startup, so a typo fails the boot rather than a
      # wallet request.
      "urn:paso:sca:global:payment:1":
        claims:                                  # REQUIRED, non-empty (§3)
          - path: [transaction_id]
            mandatory: true
          - path: [amount]
            mandatory: true
            value_type: iso_currency_amount      # §3.1: only with a `display` array
            display:
              - { locale: en, name: Amount }
              - { locale: de, name: Betrag }
        ui_labels:                               # OPTIONAL (§3.2)
          affirmative_action_label:
            - { locale: en, value: Confirm Payment }

issuer:
  paso_metadata:
    ttl_secs: 86400        # default; `exp` of a signed credential metadata JWT (§4)
    adhoc_ttl_secs: 300    # default; `exp` of an ad-hoc metadata JWT (§5.2)
```

**Requirements.** The credential signing key must carry an `x5c` certificate
chain — §4 puts that chain in the metadata JWT's header, and §7 binds it to the
credential's own. A deployment declaring `transaction_data_types` without one is
rejected at startup rather than failing per request. foundry implements the
`x5c` branch only; §4's alternative `kid`/key-set identification is a documented
unimplemented optional path.

**Serving it.** `GET /credential-metadata/:credential_configuration_id` content-
negotiates on `Accept`:

```bash
# Signed form (PaSO Proof Metadata §4) -- a compact JWS, typ credential-metadata+jwt
curl -s -H 'Accept: application/jwt' \
  https://localhost:8443/credential-metadata/com.emvco.dpc.card

# Plain form (§2) -- the bare credential_metadata object, no JWT envelope
curl -s -H 'Accept: application/json' \
  https://localhost:8443/credential-metadata/com.emvco.dpc.card
```

A Wallet **SHALL NOT** use unsigned metadata for a PaSO Credential (§3), so the
JSON form is for inspection and debugging; the JWT is the one that counts. Both
representations are built from the same object, so they cannot disagree. Each
JWT is minted per request and never cached, which satisfies §4's "rotate before
`exp`" by construction.

**Ad-hoc metadata.** §5.1 leaves the mechanism by which a Relying Party obtains
transaction-specific metadata out of scope. foundry's answer is an operator
endpoint on the admin listener:

```bash
curl -s -X POST http://127.0.0.1:9000/admin/paso/ad-hoc-metadata \
  -H 'Authorization: Bearer <admin.api_key>' \
  -H 'Content-Type: application/json' \
  -d '{
        "credential_type_id": "com.emvco.dpc.card",
        "transaction_data_type": "urn:paso:sca:global:payment:1"
      }'
# -> { "jwt": "<adhoc-transaction-metadata+jwt>", "exp": 1710000300 }
```

An optional `metadata` member overrides the configured entry for that one
artifact, and an optional `ttl_secs` overrides `adhoc_ttl_secs`. Per §5.4 an
override may name a transaction data type this issuer has **not** configured —
a valid ad-hoc JWT makes the type supported even when it is absent from the
signed credential metadata. Overrides are held to exactly the same structural
rules as configuration, so the two channels cannot diverge.

---
