# Admin Test Console

`foundry` serves a self-contained HTML/JS test console at `GET /console` on
the Admin listener (`http://127.0.0.1:9000/console` by default) — no build
step, no external dependencies (a small QR-code library is vendored inline).
It lets you trigger the two admin flows from a browser instead of hand-rolling
`curl` calls, and produces a QR code a real wallet app can scan:

- **Issuance**: enter a `credential_type_id` and `claims` JSON, click
  "Create Offer" — get back the `credential_offer_uri` as copyable text and
  as a QR code. Scan it with a real wallet, tap **Open in Wallet** on the same
  device, or use **Add to Wallet (Digital Credentials API)** to hand the offer
  to the platform's wallet picker (see below). The page polls the transaction
  and shows `offered` → `issued`, plus the transaction code when
  `tx_code_required` is set. An optional collapsed **DPC display metadata**
  disclosure holds two JSON textareas (`offer_display`,
  `credential_response_display`); both are empty by default, since display
  metadata is accepted only for the `com.emvco.dpc.card` credential type and
  the field defaults to `pid`.
- **Verification**: pick a named query (`named_query_ref`) or paste raw
  `dcql_query` JSON, optionally paste a `transaction_data` JSON array under
  "Transaction data (optional)", click "Create Verification Request" — get back
  the `openid4vp_uri`/`request_uri` as copyable text and as a QR code. The page
  auto-polls the request's status and shows `verified`, each check's
  pass/fail, and the disclosed claims once the wallet responds. When
  `transaction_data` was requested, the checks list gains a
  `transaction_data_binding` entry reporting whether the wallet hashed the
  advertised entries into its Key Binding JWT. The same disclosure also holds
  the PaSO ad-hoc metadata minter described below.

The console only calls the existing Admin API (same endpoints as the `curl`
example above) — paste your Admin API key into the field at the top of the
page; it is remembered in the browser's `localStorage` for convenience,
since the Admin listener is loopback-only by default. Disable it entirely
with `server.admin.console_enabled: false` if you don't want it exposed;
like Swagger UI, this only affects the Admin listener.

## PaSO Ad-Hoc Transaction Data Metadata

The "Transaction data (optional)" disclosure in the Verification card also mints
an ad-hoc transaction data metadata JWT (PaSO Proof Metadata §5.2) and splices
it into the entry it belongs to. It sits there rather than in a card of its own
because §5.1 makes the artifact a `metadata` member of a `transaction_data`
entry — it has no other use.

Fill in `credential_type_id` and `transaction_data_type`, optionally a
`metadata` override and a `ttl_secs`, and click **Mint ad-hoc metadata JWT**.
The console POSTs to `/admin/paso/ad-hoc-metadata` and shows the compact JWT
(copyable) plus its `exp`, both as an absolute timestamp and as seconds
remaining.

Both text inputs ship **empty**. A mint is only accepted for a credential type
that declares `transaction_data_types` — that declaration is what makes a type a
PaSO Credential type (§3) — and the shipped `config.yaml` declares none, so a
prefilled default would be a value that always fails. Supplying a `metadata`
override is the way to exercise the endpoint on such an instance: §5.4 lets an
override name a transaction data type the issuer has not configured, and a valid
ad-hoc JWT makes that type supported for the transaction it accompanies.

**The splice is keyed on the type.** On success the console parses the
`transaction_data` textarea and writes the JWT to the `metadata` member of every
entry whose `type` equals the minted `transaction_data_type`, then rewrites the
textarea pretty-printed. That is not a convenience: §5.2 requires the JWT's
`transaction_data_type` to equal the `type` of the enclosing entry, and §5.3
step 7 makes a wallet reject the entry outright when they differ — so matching
on `type` is the spec's own binding rule, and the console cannot produce a
mismatched pair.

When the textarea is empty, unparsable, not an array, or has no entry of that
type, the JWT is still shown for manual use and a line under it says what was
**not** spliced and why. There is no silent no-op — that would read as success
while sending an entry carrying no metadata at all.

For the endpoint itself, its configuration, and the `curl` equivalent, see
[PaSO Transaction Data](../issuance/paso-transaction-data.md).

## Digital Credentials API prerequisites

Both "Add to Wallet (Digital Credentials API)" (issuance,
`navigator.credentials.create()`) and "Trigger via Digital Credentials API"
(presentation, `navigator.credentials.get()`) invoke a browser API with
platform requirements the console cannot satisfy on your behalf:

- Chrome 143 or later, and Google Play services 24.0 or later on the Android
  device.
- `chrome://flags/#web-identity-digital-credentials-creation` enabled (issuance
  is an origin trial; `foundry` embeds no origin-trial token, since the console
  is a local testing tool rather than a deployed origin).
- A supported wallet app installed on the Android device.
- **`issuer.credential_issuer` must be reachable from the Android device.** A
  `localhost` or `127.0.0.1` issuer URL fails the cross-device flow even though
  the QR scans correctly and the handoff appears to succeed — the wallet
  resolves `credential_issuer` itself when it calls `/token`. Use a
  LAN-reachable host or a tunnel. This is the failure mode most likely to be
  misread as a `foundry` bug.
- **`verifier.dc_api_expected_origins` must list the origin the console is
  served from** — see [DC API Expected Origins](../verification/dc-api-origins.md) below.
  This is the presentation-side equivalent of the previous bullet, and the
  second most likely thing to be misread as a `foundry` bug.

The console never gates the buttons on browser sniffing: it always offers them
and reports an unsupported browser at the point of use.

The console is responsive and usable from a phone, which is the expected setup
for driving a Digital Credentials API flow: below 640px the DC API button becomes
the first, full-width action in the result block, and the QR code collapses
behind a `QR code` disclosure — it is unscannable on the device displaying it,
and one tap reopens it. Desktop layout is unchanged.

Note that the Digital Credentials API is a **platform handoff channel, not a
protocol**. The payload handed to the wallet is the same OpenID4VCI Credential
Offer the deep link carries, so `/token` and `/credential` behave identically
regardless of which affordance you used.

## Wallets Still on OpenID4VP draft 24 (`web-origin:`)

The same `KB-JWT audience mismatch` also appears when the Origin is **already
correct**, because the wallet spells the prefix the old way.

OpenID4VP **draft 24**, Appendix A.2 composed the effective Client Identifier of
an unsigned DC API request from "a synthetic Client Identifier Scheme of
`web-origin` and the Origin itself", and the KB-JWT `aud` was that Client
Identifier — so a draft-24 wallet signs `web-origin:https://site.example`.
OpenID4VP **1.0** renamed the prefix to `origin:`. foundry implements 1.0 and
rejects the draft-24 spelling by default.

Real Google Wallet (observed 2026-08) accepts the `openid4vp-v1-unsigned`
protocol the console requests and then answers with a draft-24 audience. To
interoperate with it, opt in:

```yaml
verifier:
  dc_api_expected_origins: ["https://verifier-site.example"]
  dc_api_accept_legacy_web_origin_audience: true
```

This relaxes the **prefix only**. The Origin half is still matched against
`dc_api_expected_origins`, so no additional Origin becomes acceptable and the
audience binding OpenID4VP requires is preserved. Both spellings are accepted
while it is on, so a 1.0-conformant wallet is unaffected. Every presentation
accepted on the legacy prefix logs:

```text
WARN KB-JWT bound to the superseded OpenID4VP draft 24 `web-origin:` audience prefix …
```

Watch for that line disappearing — that is when the wallets in play have caught
up and the flag can go back off. It is off by default because accepting a
superseded draft's audience unconditionally would make every deployment deviate
from OpenID4VP 1.0 silently.

The console plus a real wallet app is the supported way to drive an issuance
or presentation by hand — foundry ships no wallet client of its own. For a
scripted equivalent that needs no wallet at all, the end-to-end test boots the
real binary and drives both flows over HTTP:

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

See [End-to-End Test](../development/end-to-end.md)
below for what it covers.
