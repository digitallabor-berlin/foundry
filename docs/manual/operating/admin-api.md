# Admin API

### Example: Creating an Offer via Admin API

```bash
curl -X POST http://127.0.0.1:9000/admin/issuance/offers \
  -H "Authorization: Bearer dev-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type_id": "pid",
    "claims": {
      "given_name": "Alice",
      "birthdate": "1990-01-01"
    },
    "tx_code_required": false
  }'
```

### Example: A DPC Offer With Display Metadata

For the EMVCo Digital Payment Credential type (`vct` `com.emvco.dpc.card`) the
offer may additionally carry **display metadata** — presentation data such as
card art, issuer branding and the last four PAN digits, which is *not* part of
the signed credential.

Two independent fields exist because the governing annex applies different rules
at the two protocol stages: `card.last_four` and `card.card_art` are required on
the Credential Response, but the same annex says PII-type data should not appear
on a Credential Offer. `offer_display` therefore omits them; only
`credential_response_display` carries them.

Both fields are accepted **only** for a credential type whose `vct` is
`com.emvco.dpc.card`; supplying either for any other type is rejected with
`400 invalid_request`.

```bash
curl -X POST http://127.0.0.1:9000/admin/issuance/offers \
  -H "Authorization: Bearer dev-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type_id": "com.emvco.dpc.card",
    "claims": {
      "credential_id": "urn:uuid:9f2b7a2e-3b74-4a0d-9b1a-0e6a91f5d2c8",
      "network": "example_network"
    },
    "tx_code_required": false,
    "offer_display": [
      {
        "locale": "en-US",
        "card": {
          "type": { "code": "CREDIT", "label": "Credit Card" },
          "network_branding": [
            {
              "network": "example_network",
              "branding": { "name": "Example Network" }
            }
          ]
        }
      }
    ],
    "credential_response_display": [
      {
        "locale": "en-US",
        "card": {
          "type": { "code": "CREDIT", "label": "Credit Card" },
          "last_four": "4444",
          "alias": "Platinum Credit Card",
          "card_art": [
            {
              "theme": "DEFAULT",
              "image_url": "https://bank.example/card.png"
            }
          ],
          "issuer": {
            "branding": { "name": "Example Bank" },
            "country": "DE"
          }
        }
      }
    ]
  }'
```

`offer_display` is echoed on the Credential Offer (and on the Digital
Credentials API rendering of it); `credential_response_display` is persisted on
the transaction and echoed on the Credential Response at `/credential`. Neither
member is defined by OpenID4VCI 1.0 — see
[`docs/specs/emvco-dpc-schema-framework.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/emvco-dpc-schema-framework.md)
for the deviation record.
