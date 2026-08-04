# Admin Console: issue credentials via the Digital Credentials API

Date: 2026-08-04
Status: Approved

## Problem

The admin test console (`crates/foundry/assets/console.html`, served at
`GET /console`) can create a credential offer via
`POST /admin/issuance/offers` and render it two ways: as a
`openid-credential-offer://` deep link, and as a QR code for a wallet on
another device to scan. Both paths hand the offer to a wallet the same way —
through a URI the operator or a camera has to carry.

Chrome 143 added a third way. `navigator.credentials.create()` with a
`digital` member lets an issuer website hand a credential offer to the
platform, which enumerates the wallets installed on the device and mediates
user consent — the "push provisioning" model, without every issuer having to
integrate every wallet's custom URI scheme by hand. It works same-device on
Android and cross-device from desktop (Chrome renders the QR itself and the
platform-mediated flow runs on the phone). See
<https://developer.chrome.com/blog/digital-credentials-api-143-issuance-ot>.

The console has no way to invoke it. It also cannot tell the operator whether
a credential was ever actually issued: there is no admin endpoint that reads
an `IssuanceTransaction`, so the issuance card renders the offer and then goes
silent, while the verification card polls and shows pass/fail.

### Why the prior DC API work scoped this out, and why that no longer holds

`docs/superpowers/specs/2026-08-03-admin-console-dc-api-design.md` added the
presentation half of this — `navigator.credentials.get()` with protocol
`openid4vp-v1-unsigned`, plus
`POST /admin/verification/requests/:id/dc-api-response` to relay the wallet's
encrypted response. That spec explicitly excluded issuance:

> There is no DC API concept anywhere in the pinned OpenID4VCI spec: issuance
> has, and will continue to have, only the `credential_offer_uri` deep link.

The first clause is still true. Neither pinned spec mentions the DC API in an
issuance context: `docs/specs/openid-4-verifiable-credential-issuance-1_0.md`
contains no DC API reference at all, and HAIP's only DC API section
(`#oid4vp-dc-api`, L281-287) is presentation-scoped — Wallet Invocation,
`dc_api.jwt` response mode, OpenID4VP Appendix A.

The second clause was an over-reach. The DC API is not a protocol; it is a
**platform handoff channel**. The `data` member Chrome expects for protocol
`openid4vci-v1` is a plain OpenID4VCI Credential Offer object, augmented with
inline metadata. Nothing about the OpenID4VCI wire protocol changes: the same
`pre-authorized_code` grant, the same `POST /token`, the same
`POST /credential`. Only the mechanism by which the offer reaches the wallet
differs. So this work adds a transport rendering, and §4.4 conformance is not
in play — there is no pinned text to conform to or deviate from.

`openid4vci-v1` is an **origin-trial protocol identifier**, not a pinned
specification. It is cited here from Chrome's documentation, which is the only
normative source that currently exists for it. This is recorded as a
deliberate, documented departure from the usual rule of implementing only
against `docs/specs/` (root AGENTS.md §4.4) — the feature is a testing
affordance on an admin-only surface, and the payload it emits is composed
entirely from objects foundry already builds and already serves at its
`/.well-known/*` endpoints.

## Goal

Give the admin console a working "Add to Wallet" path that invokes the
Digital Credentials API for issuance, and — for the first time — show the
operator whether the credential was actually issued.

## Non-goals

- **No origin-trial token embedded in `console.html`.** The console is a
  local testing tool, not a deployed origin; operators enable
  `chrome://flags/#web-identity-digital-credentials-creation` instead. This is
  documented in `README.md` rather than shipped in markup.
- **No change to the `credential_offer_uri` deep link, the QR, or the
  "Open in Wallet" link.** They keep working exactly as today.
- **No `transport` parameter on `CreateOfferRequest`.** See "Why no transport
  parameter" below.
- **No browser or device gating.** Following the precedent set by the prior
  DC API spec: the console always offers the button and reports an unsupported
  browser honestly at the point of use.
- **No narrowing of `get_verification_handler`'s response.** It currently
  returns the whole `VerificationTransaction`, including `ephem_private_jwk`.
  That is a real leak and worth fixing, but it is a breaking change to an
  existing admin endpoint with its own OpenAPI churn, and does not belong
  inside a DC API feature. Recorded as a follow-up below.
- **No nested-claim or display-metadata authoring UI.** The console sends the
  claims JSON the operator types, unchanged.

## Design

### Why no transport parameter

The verification card needed one: `transport: "dc_api"` changes the OpenID4VP
wire — `response_mode` becomes `dc_api.jwt`, the request object is unsigned
and inline rather than fetched from a `request_uri` — so it must be chosen at
create time, and `CreateVerificationResponse.dc_api_request` is
correspondingly `Option`, `None` for `request_uri` transport.

Issuance has no such fork. The offer, the pre-authorized code, the
transaction, `/token` and `/credential` are byte-identical regardless of how
the offer reaches the wallet. The deep-link URI and the DC API payload are two
renderings of one already-constructed offer. So `dc_api_offer` is a plain
required field, always populated, and no request parameter selects between
them — the console shows both affordances and the operator picks one by
clicking.

### `foundry-issuer`: composing the DC API offer

`CreateOfferResponse` (`crates/foundry-issuer/src/create_offer.rs`) gains:

```rust
pub dc_api_offer: serde_json::Value,
```

Not `Option` — per the previous section.

A new function in `offer.rs`, sibling to `build_offer_uri`. The two are the
same kind of thing, and belong next to each other: given a `CredentialOffer`,
render it for one wallet-facing transport.

```rust
pub fn build_dc_api_offer(
    cfg: &Config,
    offer: &CredentialOffer,
) -> Result<serde_json::Value, IssuanceError>
```

Implementation:

1. `serde_json::to_value(offer)?` — `CredentialOffer`'s existing `Serialize`
   impl already emits `credential_issuer`, `credential_configuration_ids`, and
   `grants` with the correct wire names, including the serde-renamed
   `urn:ietf:params:oauth:grant-type:pre-authorized_code` key and the
   hyphenated `pre-authorized_code` inside it. Do not hand-build this object;
   duplicating those renames is how they drift.
2. Insert `authorization_server_metadata`:
   `build_authorization_server_metadata(cfg)`, verbatim. No narrowing applies
   — it is issuer-wide.
3. Insert `credential_issuer_metadata`: `build_issuer_metadata(cfg)`, with
   `credential_configurations_supported` retained down to exactly the ids
   present in `offer.credential_configuration_ids`.

Every `serde_json` failure maps to `IssuanceError::Serialization`. No
`.unwrap()` / `.expect()` outside `#[cfg(test)]` (root AGENTS.md §4.1) —
including the "obviously safe" `as_object_mut()` on a value just serialized
from a struct; return `Serialization` there rather than asserting.

Resulting shape:

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["pid"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "...",
      "tx_code": { "input_mode": "numeric", "length": 4 }
    }
  },
  "authorization_server_metadata": { "issuer": "...", "token_endpoint": "...", "...": "..." },
  "credential_issuer_metadata": {
    "credential_endpoint": "...",
    "credential_configurations_supported": { "pid": { "...": "..." } }
  }
}
```

#### Why the metadata is narrowed

Chrome's documented example inlines exactly one entry in
`credential_configurations_supported` — the one being issued — carrying its
`display` and `claims`. That is what the wallet renders its consent screen
from.

`build_issuer_metadata` returns every configured credential type, because
that is correct for `GET /.well-known/openid-credential-issuer`. Embedding it
whole would ship `mdl` and `diploma` alongside an offer for `pid` and leave
the wallet to infer which one the offer is about. Narrowing is a filter over
the same builder's output, so the per-configuration content stays
byte-identical to what the metadata endpoint serves — only the set of keys
differs, and it differs to match the offer.

`dc_api_offer` embeds the `pre-authorized_code`. It is therefore a secret with
exactly the same handling rules as `credential_offer` and
`credential_offer_uri`, which already embed it: never logged, at any level,
under any flag (root AGENTS.md §4.5).

### `GET /admin/issuance/offers/:id`

Added to the authenticated admin router in `crates/foundry/src/server.rs` —
same API-key middleware as every other `/admin/*` route, no new auth code.

Response type, defined in `server.rs` alongside the existing admin-only
`AdminDcApiResponseBody` (admin HTTP projections live in the binary, not the
engine):

```rust
pub struct AdminIssuanceStatus {
    pub transaction_id: String,
    pub credential_type_id: String,
    pub state: IssuanceState,        // Offered | Issued
    pub created_at: i64,
    pub status_list_index: Option<u64>,
    pub tx_code: Option<String>,
}
```

Handler: `foundry_issuer::load_transaction(storage, &id)` → `404 NOT_FOUND`
when `None`, otherwise project the loaded transaction into the struct above.
Storage errors go through the existing `internal_error` mapper.
`#[tracing::instrument(skip_all)]`, mandatory (root AGENTS.md §4.5) — the
loaded transaction holds the access token, the pre-authorized code, and the
claim values.

`IssuanceState` currently derives `Serialize`/`Deserialize` but **not**
`utoipa::ToSchema`, so it must gain that derive for `AdminIssuanceStatus` to
derive `ToSchema` (root AGENTS.md §6). This mirrors `VerificationState`, which
already carries it. `#[serde(rename_all = "snake_case")]` is already present,
so the wire values are `"offered"` and `"issued"`.

#### Why a projection and not the whole transaction

`get_verification_handler` returns its entire `VerificationTransaction`,
`ephem_private_jwk` included. Mirroring that here would be worse, not merely
equally bad: `IssuanceTransaction` holds `pre_authorized_code` and
`access_token`, which are **live bearer credentials against the wallet-facing
listener**, not just key material. Returning them would let any admin-key
holder redeem an offer intended for a wallet — turning a read endpoint into a
credential-exfiltration endpoint.

Deliberately excluded, and commented as such in the code:
`pre_authorized_code`, `access_token`, `authorization_code`, `code_challenge`,
`code_challenge_method`, `dpop_jkt`, `claims`, `redirect_uri`, `issuer_state`.

#### Why `tx_code` *is* included

`tx_code` is generated in `create_offer` and persisted on the transaction, but
surfaced nowhere: `CreateOfferResponse` has no field for it and no endpoint
reads it back. So `tx_code_required: true` is currently untestable through the
console — the wallet prompts for a code the operator has no way to learn.

The transaction code's entire purpose is to be communicated out-of-band to the
person completing the flow. Returning it to the already-authenticated
operator who created the offer is that channel, not a leak. Root AGENTS.md
§4.5 forbids *logging* transaction codes; that is a different surface with
different threat model, and it continues to apply unchanged here.

This is a small scope addition beyond DC API support, justified because the
endpoint being added is exactly the right place for it and because omitting it
would leave a documented flow untestable.

### Console UI

The issuance result row gains a button, and the card gains a status line
mirroring the verification card:

```html
<button class="open-btn hidden" id="offer-dc-api-btn">Add to Wallet (Digital Credentials API)</button>
```

```html
<p>Status: <span class="badge offered" id="issuance-status">offered</span></p>
<p class="hint hidden" id="issuance-tx-code"></p>
```

A `<button>`, not an `<a>` — it runs JS rather than navigating — styled with
the existing `.open-btn` class and toggled with the existing `.hidden`
convention, exactly as `#verification-dc-api-btn` is.

The stylesheet defines only `.badge.pending`, `.badge.verified`, and
`.badge.failed` — the verification states. Two rules are added for the
issuance states, reusing the same two colour variables:

```css
.badge.offered { background: rgba(224,168,63,0.18); color: var(--amber); }
.badge.issued  { background: rgba(53,192,122,0.18); color: var(--green); }
```

The alternative — mapping `offered → pending` and `issued → verified` in JS so
the existing classes apply — is rejected: it would make the rendered class
name disagree with the state the server reported, which is exactly the kind of
silent translation that makes a debugging tool untrustworthy. The badge text
and the badge class both say what the transaction actually is.

Polling starts unconditionally after every successful create, matching how
`initVerification` calls `pollVerification` unconditionally. The QR and
deep-link paths therefore gain outcome feedback too; this is not gated on the
DC API being used.

### Console JS

Three changes to the existing DC API helper block, which was written for
presentation:

- **`prepareDcApiRequest(dcApiRequestData, protocol)`** — gains a `protocol`
  parameter. The existing verification call site passes
  `'openid4vp-v1-unsigned'`; the new issuance call site passes
  `'openid4vci-v1'`.

- **`invokeDcCreate(req)`** — new, and deliberately *not* symmetric with
  `invokeDc`:

  ```js
  // No return-shape assertion, unlike invokeDc: Chrome's documented example
  // for issuance ignores create()'s return value entirely, so asserting
  // `constructor?.name === 'DigitalCredential'` would manufacture failures on
  // a successful handoff. Non-throw is the success signal.
  //
  // Same transient-activation constraint as invokeDc: no await may land
  // between the click and navigator.credentials.create().
  async function invokeDcCreate(req) {
    await navigator.credentials.create(req);
  }
  ```

- **`initIssuanceDcApiTrigger()`** — mirrors `initDcApiTrigger`. The support
  check is `supportsDcApi('create', 'openid4vci-v1')` and is synchronous, so
  it does not consume the click's transient activation; the handler's first
  `await` is inside `invokeDcCreate`, on `create()` itself. On
  `isDcApiNotSupportedError(err)` it reports the unsupported-browser message,
  otherwise it surfaces the error verbatim.

Reused unchanged: `hasDigitalCredentialSupport`, `supportsDcApi`,
`isDcApiNotSupportedError`.

New polling function `pollIssuance(id, errorEl)`, structurally parallel to
`pollVerification` (same `POLL_INTERVAL_MS`, same `MAX_POLL_FAILURES`, same
"hard error stops, soft error retries" split) but with its **own** timer
variable `issuancePollTimer` and its own `stopIssuancePolling()`. Sharing
`pollTimer` between the two cards would let creating a verification request
silently cancel issuance polling. It stops when `state` is no longer
`offered`.

Reset discipline on each create — hide `#offer-dc-api-btn`, null
`lastDcApiOffer` and `lastIssuanceId`, call `stopIssuancePolling()`, and
re-hide `#issuance-tx-code`. The prior two console specs each flagged a
re-hiding gap; this one does not repeat it.

`tx_code` rendering: when the status response carries one, show
`#issuance-tx-code` with the code and a label explaining the wallet will
prompt for it. When absent, keep it hidden.

### Rejected approach: compose the DC API payload in the browser

The console could have fetched `/.well-known/openid-credential-issuer` and
`/.well-known/oauth-authorization-server` in JS and assembled the payload
client-side from the `credential_offer` the create response already returns.

Rejected for the same reason the prior spec rejected a direct browser POST to
the wallet listener: those two endpoints live on the **wallet-facing**
listener, while `/console` and `/admin/*` live on the admin listener. Fetching
them cross-origin would require enabling CORS on real protocol endpoints whose
only callers today are native wallet apps that do not need it — a permanent
security-surface change to production routes to serve a testing convenience.
Composing server-side needs no CORS, keeps the narrowing logic in the crate
that owns the metadata builders, and makes the payload testable in Rust.

## Testing

`crates/foundry/tests/console.rs` — extend the existing structural regression
tests: the served `/console` HTML contains `id="offer-dc-api-btn"` and
`id="issuance-status"`.

`crates/foundry/tests/issuer_offers.rs`:

- `dc_api_offer` carries `credential_issuer`, a `credential_configuration_ids`
  array, a `grants` object with the pre-authorized-code grant key, and
  `authorization_server_metadata.token_endpoint`.
- **Narrowing**, against a config with at least two credential types:
  `dc_api_offer.credential_issuer_metadata.credential_configurations_supported`
  has exactly one key, the offered id. A single-type fixture cannot fail this
  assertion, so the extra type is load-bearing.
- `GET /admin/issuance/offers/:id` → `200`, `state == "offered"`, and — as a
  **negative assertion** — the response object contains no
  `pre_authorized_code` and no `access_token` key. The exclusion in §"Why a
  projection" is a security property; it needs a test, not just a comment.
- `GET /admin/issuance/offers/:id` for an unknown id → `404`.
- With `tx_code_required: true`, the status response carries a `tx_code`.

`crates/foundry/tests/wallet_issuance.rs` — after the existing
token → credential flow completes, the status endpoint reports
`state == "issued"`.

Scoped gate (root AGENTS.md §5.1, dependents per §5.2 — this touches
`foundry-issuer`, so `foundry` is included):

```
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```

The full gate of §5.3, including `e2e_full_flow`, runs once at the end of the
branch — not per task.

## OpenAPI

`openapi.json` only; `openapi-wallet.json` is unaffected, as neither change is
wallet-facing. Via `utoipa` annotations (root AGENTS.md §6):

- the new `GET /admin/issuance/offers/{id}` path,
- the `AdminIssuanceStatus` schema,
- the new `dc_api_offer` field on the existing `CreateOfferResponse` schema.

## Documentation

`README.md` gains operator prerequisites for the issuance DC API path:

- Chrome 143 or later; Google Play services 24.0 or later on the Android
  device.
- `chrome://flags/#web-identity-digital-credentials-creation` enabled.
- A supported wallet app installed on the device.
- **`issuer.credential_issuer` must be reachable from the Android device.** A
  `localhost` issuer URL fails the cross-device flow even though the QR scans
  correctly and the handoff appears to succeed — the wallet resolves
  `credential_issuer` itself when it calls `/token`. This is the failure mode
  most likely to be misread as a foundry bug.

Per root AGENTS.md §8: `crates/foundry-issuer/AGENTS.md` module map and public
surface gain `build_dc_api_offer`; `crates/foundry/AGENTS.md` gains the new
admin route; `crates/foundry/tests/AGENTS.md` records the new coverage.

## Follow-ups (not in this change)

- `get_verification_handler` returns `ephem_private_jwk` to any admin-key
  holder. Narrow it to a projection, as `AdminIssuanceStatus` does here. This
  is a breaking change to an existing admin response shape and needs its own
  change record and OpenAPI update.
- `openid4vci-v1` is an origin-trial identifier with no pinned spec. When the
  OpenID Foundation publishes a DC API issuance profile, reconcile
  `build_dc_api_offer` against it and add the spec file to the §4.4 table.