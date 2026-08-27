# By-Reference Credential Offers

By default a Credential Offer is delivered **by value**: the whole offer object
is percent-encoded into the `credential_offer` parameter of the
`openid-credential-offer://` deep link. That link therefore grows with the
offer's contents, and OpenID4VCI §4.2 notes that a QR rendering "would usually
contain the Credential Offer by reference due to the size limitations of the QR
codes".

Setting `issuer.offer_by_reference` switches delivery to the by-reference form:

```yaml
issuer:
  # false (default) — inline the offer as `credential_offer=...`
  # true            — hand out `credential_offer_uri=...` instead
  offer_by_reference: false
```

With it enabled, `POST /admin/issuance/offers` stores the rendered offer and
returns a `credential_offer_uri` pointing at
`GET /credential-offer/<id>` on the **wallet-facing** listener, which serves the
offer as `application/json`. The wallet fetches it and proceeds exactly as
before — nothing else about the protocol changes.

Why it matters in practice: a `com.emvco.dpc.card` offer carrying display
metadata (logo and card-art URLs) is several times the size of a plain one, and
the resulting QR is dense enough that phone cameras struggle. A reference is a
fixed ~150 characters regardless of what the offer contains.

Operational notes:

- **The offer id is a bearer credential.** The served document contains the
  `pre-authorized_code`, so anyone who learns the id can redeem the offer. It is
  a fresh 32-byte CSPRNG value, deliberately **not** the transaction id that
  `GET /admin/issuance/offers/{id}` uses — that endpoint withholds the
  `pre-authorized_code` precisely so an admin-key holder cannot redeem a
  wallet's offer. Foundry never logs the id.
- **Lifetime** is `storage.transaction_ttl_secs`: the offer stops being
  fetchable exactly when it stops being redeemable.
- **Fetching is repeatable** until that TTL elapses, so a dropped connection or
  a wallet retry does not destroy the offer. Single-use-ness belongs to the
  `pre-authorized_code` inside it.
- **The route is always mounted**, whether or not the flag is set, so turning
  the flag off does not strand offers already in a wallet's hands.
- **`dc_api_offer` is unaffected.** The Digital Credentials API receives the
  offer in-process, where there is no QR and no size limit.
- It is **opt-in** because by-reference delivery requires the wallet to fetch
  the offer over HTTPS; a wallet that does not implement the parameter cannot
  fall back on its own. Confirm your target wallets support it before enabling.

---
