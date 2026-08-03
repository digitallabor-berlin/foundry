# Admin Console: trigger presentation via the Digital Credentials API

Date: 2026-08-03
Status: Approved

## Problem

The admin test console (`crates/foundry/assets/console.html`, served at
`GET /console`) can already create a verification request with
`transport: "dc_api"` — `foundry-verifier`'s `create_verification_request`
fully builds the unsigned OpenID4VP-over-DC-API request object
(`response_mode: "dc_api.jwt"`, inline `dcql_query`, `nonce`,
`client_metadata`) and returns it as `dc_api_request` on
`CreateVerificationResponse` (`crates/foundry-verifier/src/request.rs`).

But the console has no way to actually *invoke* that transport. Today it only
prints a static string — "(dc_api transport has no scannable URI; use the
Digital Credentials API request object returned by the admin endpoint
directly)" — and stops there (see
`docs/superpowers/specs/2026-08-03-admin-console-open-in-wallet-link-design.md`,
which explicitly scoped DC API out). There is no browser-side call to
`navigator.credentials.get()`, and no path for the resulting encrypted wallet
response to reach `verify_vp_response`.

Per the pinned specs, the Digital Credentials API (DC API) is a
**presentation-only** mechanism — OpenID4VP 1.0 Appendix A defines "OpenID4VP
over the Digital Credentials API"; HAIP §oid4vp-dc-api narrows it further.
There is no DC API concept anywhere in the pinned OpenID4VCI spec: issuance
has, and will continue to have, only the `credential_offer_uri` deep link.
This work is therefore scoped to verification/presentation only; the
issuance card is untouched.

## Goal

Give the admin console a working, same-browser way to exercise the `dc_api`
transport end-to-end: create a `dc_api` verification request, invoke the
Digital Credentials API in the browser the console is running in, submit the
resulting encrypted response for verification, and see the same
pass/fail/claims result the console already renders for `request_uri`
transport.

## Non-goals

- No change to the `request_uri` / custom-URL-scheme flow, the "Open in
  Wallet" link, or QR rendering — those are unaffected and continue to work
  exactly as today.
- No CORS changes to the wallet-facing listener. See "Rejected approach"
  below.
- No device/browser sniffing or UX gating (no "only show this button on
  Chrome desktop" logic) — the console is a protocol-testing tool; it always
  offers the option when `transport` is `dc_api` and reports unsupported
  browsers honestly at the point of use.
- No issuance-side DC API support (see Problem — not a concept the pinned
  specs define).

## Design

### Backend: new admin endpoint

`POST /admin/verification/requests/:id/dc-api-response`, added to the
existing authenticated admin router in `crates/foundry/src/server.rs` — same
API-key auth as every other `/admin/*` route, no new auth code.

Request body (JSON, new type `AdminDcApiResponseBody { response: String }`):

```json
{ "response": "<jwe-compact-serialization>" }
```

This mirrors `VpResponseForm.response` (the field `post_response_handler`
already parses out of the real wallet's `application/x-www-form-urlencoded`
body) but as JSON, because the DC API delivers the wallet's response as a JS
object property (`credentialResponse.data.response`), not a URL-encoded form
body. `foundry-verifier`'s `create_verification_request` always sets
`response_mode: "dc_api.jwt"` for `transport: "dc_api"` (never plaintext
`dc_api`), so the response is always the encrypted-JWE shape — there is no
un-encrypted variant to additionally support here.

**Shared handler core.** Extract the existing body of `post_response_handler`
(minus its form-parsing step) into a helper:

```rust
async fn submit_vp_response(
    state: &AppState,
    id: &str,
    encrypted_jwe_str: &str,
    source: &'static str,   // "wallet" | "admin" — log label only
) -> Result<VerificationResult, (StatusCode, Json<serde_json::Value>)>
```

Behavior (unchanged from today's `post_response_handler`): load the
transaction (404 if missing) → reject if not `VerificationState::Pending`
(400) → call `foundry_verifier::verify_vp_response` → persist the transaction
(log-only on save failure, exactly as today, so a storage write failure never
changes the response returned to the caller) → map the `Result`:

- `Ok(result)` → `Ok(Json(result))`.
- `Err(e)` → `Err(verifier_wallet_error_response(&e))`.

Error/status-code classification is **unchanged** from what
`post_response_handler` already does today — decryption/crypto failures →
400, status-list unavailability → 502, per root AGENTS.md §4.3. That
classification is a property of the OpenID4VP response itself (what went
wrong verifying it), not of which HTTP route received it, so both callers
must produce identical status codes for identical failures. The only thing
that varies between the two callers is the `source` value threaded into
`log_typed_error` inside the error mapper, so admin-console-driven test
traffic is labeled `admin` in logs rather than `wallet` (root AGENTS.md §4.5:
log field values are operator-facing, and conflating real wallet traffic with
console-driven test traffic in logs would be a regression, not a
simplification). Implementing this requires either parameterizing
`verifier_wallet_error_response` with a `source` argument or giving the new
route its own thin wrapper around the same status/code match arms — the
exact shape is an implementation detail for the plan, not fixed here, but the
status-code table itself must not diverge between the two routes.

`post_response_handler` becomes a thin wrapper: parse the
`x-www-form-urlencoded` body into `VpResponseForm` (unchanged), then call
`submit_vp_response(&state, &id, &form.response, "wallet")`. Its behavior
towards real wallets does not change.

The new `post_admin_dc_api_response_handler` parses the JSON body into
`AdminDcApiResponseBody`, then calls
`submit_vp_response(&state, &id, &body.response, "admin")`.

Every `#[tracing::instrument]` on the new handler carries `skip_all` (root
AGENTS.md §4.5), matching the existing instrumentation on
`post_response_handler`. No new sensitive-data surface is introduced: the
JSON body's `response` field is the same JWE the wallet-facing endpoint
already receives and already handles under the existing
`sensitive_enabled()` + debug/trace gating inside `verify_vp_response` — this
endpoint does not add any additional logging of that value.

### Rejected approach: direct browser POST to the wallet listener

`foundry` runs two listeners (`crates/foundry/src/server.rs`): `/console` and
`/admin/*` are served on the **admin** listener; `/vp/request/:id` and
`/vp/response/:id` are served on the separate **wallet-facing** listener,
normally called only by native wallet apps. An alternative design would have
had the backend return a `response_uri` alongside `dc_api_request` and let
the console's browser JS `fetch()` it directly, cross-origin.

This was rejected: it would require enabling CORS on `/vp/response/:id` — a
real protocol endpoint whose only callers today are native apps that don't
need CORS at all — purely to serve the test console's convenience. That is a
permanent security-surface change to production code for a testing feature,
and it does not even match how a real DC-API Verifier is built: a real
Verifier's own backend receives the browser's DC API response and relays it
server-side to wherever verification happens. Routing the console's response
through a new **admin** endpoint (Approach A above) mirrors that real
architecture faithfully, with foundry's admin API standing in for "the
Verifier's backend" — and needs no CORS at all, since `/console` and the new
`/admin/*` route already share an origin.

### Console UI: `transport` becomes a `<select>`

Replace the free-text `<input type="text" id="transport" value="request_uri">`
with:

```html
<select id="transport">
  <option value="request_uri" selected>request_uri (deep link / QR)</option>
  <option value="dc_api">dc_api (Digital Credentials API)</option>
</select>
```

The existing JS line reading the transport value
(`document.getElementById('transport').value.trim() || 'request_uri'`) needs
no change — a `<select>`'s `.value` is a plain string, same as before.

### Console UI: the "Trigger via Digital Credentials API" button

In `#verification-result`'s `.uri-row`, alongside the existing "Open in
Wallet" anchor:

```html
<button class="open-btn hidden" id="verification-dc-api-btn">Trigger via Digital Credentials API</button>
```

A `<button>`, not an `<a>`, since it runs JS rather than navigating —
visually consistent via the existing `.open-btn` class, and using the same
`.hidden` toggle convention as `#verification-open`.

Extend the existing success-handler branch in `initVerification()`: when
`body.dc_api_request` is present, hide `#verification-uri` / the QR / the
existing `#verification-open` link (as today), and additionally store the
prepared DC API request and the transaction id, then reveal
`#verification-dc-api-btn`. When switching back to `request_uri` transport
and re-submitting, `#verification-dc-api-btn` must be explicitly hidden again
— the same re-hiding gap already called out for `#verification-open` in the
prior deep-link spec applies symmetrically here.

### Console JS: aligned with `eudipay-frontend/src/dcApi.js`

`eudipay-frontend/src/dcApi.js` is a proven, already-shipped integration of
the same browser API against a different backend (EUDIPLO). Its function
names and the one hard-won runtime constraint it documents are carried over
directly; only the "how do we get the request object" step differs, because
foundry's backend already returns the request inline (see below).

```js
function hasDigitalCredentialSupport(protocol) {
  if (typeof window === 'undefined' || !window.isSecureContext) return false;
  const dc = window.DigitalCredential;
  if (!dc) return false;
  if (typeof dc.userAgentAllowsProtocol === 'function') {
    try { return Boolean(dc.userAgentAllowsProtocol(protocol)); }
    catch { return false; }
  }
  return true;
}

function supportsDcApi(method, protocol) {
  if (typeof navigator === 'undefined' || !('credentials' in navigator)) return false;
  if (typeof navigator.credentials[method] !== 'function') return false;
  return hasDigitalCredentialSupport(protocol);
}

function isDcApiNotSupportedError(error) {
  const name = error && error.name ? String(error.name) : '';
  const message = error && error.message ? String(error.message) : '';
  return name === 'NotSupportedError'
    || (name === 'TypeError' && /not supported/i.test(message))
    || /CredentialContainer/i.test(message);
}

// No fetch step: unlike eudipay-frontend's prepareDcRequest (which must fetch
// a signed request_uri to get an inline JWT), foundry's dc_api_request is
// already the full inline, unsigned request body — this is a synchronous wrap.
function prepareDcApiRequest(dcApiRequestData) {
  return { digital: { requests: [{ protocol: 'openid4vp-v1-unsigned', data: dcApiRequestData }] } };
}

// Must be invoked with no preceding await once the click handler starts —
// Chrome consumes the click's transient activation if any await lands
// between the click and navigator.credentials.get(). (Same constraint
// eudipay-frontend/src/dcApi.js documents on its own invokeDc.)
async function invokeDc(req) {
  const credentialResponse = await navigator.credentials.get(req);
  if (!credentialResponse || credentialResponse.constructor?.name !== 'DigitalCredential') {
    throw new Error('No DigitalCredential returned from navigator.credentials.get');
  }
  return credentialResponse.data;
}
```

Wiring: on a successful `dc_api` create-request response, set
`lastDcApiRequest = prepareDcApiRequest(body.dc_api_request)` and
`lastVerificationId = body.verification_id` in variables scoped to the
verification section's IIFE (paralleling how `main.js` in eudipay-frontend
closes over its pre-fetched request before wiring the button), then reveal
`#verification-dc-api-btn`. Because `prepareDcApiRequest` is synchronous here
(no fetch), there is no need to eagerly call it before the button is shown
the way eudipay-frontend's `main.js` does — it is simply called once, inline,
in the same success handler that already sets up the other result fields.

The button's click handler:

```js
dcApiBtn.addEventListener('click', async function () {
  if (!supportsDcApi('get', 'openid4vp-v1-unsigned')) {
    showError(errorEl, new Error('This browser does not support the Digital Credentials API.'));
    return;
  }
  dcApiBtn.disabled = true;
  try {
    const data = await invokeDc(lastDcApiRequest);
    await adminFetch('/admin/verification/requests/' + encodeURIComponent(lastVerificationId) + '/dc-api-response', {
      method: 'POST',
      body: JSON.stringify({ response: data.response })
    });
    // The pollVerification loop already running since "Create Verification
    // Request" was clicked will pick up the Verified/Failed state on its
    // next tick — no separate render path is introduced here.
  } catch (err) {
    showError(errorEl, isDcApiNotSupportedError(err)
      ? new Error('This browser does not support the Digital Credentials API.')
      : err);
  } finally {
    dcApiBtn.disabled = false;
  }
});
```

The `supportsDcApi(...)` check preceding `invokeDc` is synchronous (no
`await`), so it does not consume the click's transient activation; the first
`await` the handler performs is inside `invokeDc`, on
`navigator.credentials.get()` itself.

No new polling logic is introduced: `initVerification()` already calls
`pollVerification(body.verification_id, errorEl)` unconditionally right after
every successful create-request call, including for `dc_api` transport today
(it just never observes a state change, since nothing currently drives the
transaction out of `Pending`). Once the DC API button successfully submits a
response, the already-running poll loop's next tick observes the updated
state and renders it exactly as it does for `request_uri` transport.

### Testing

- `crates/foundry/tests/console.rs`: extend the existing structural
  regression test (in the style of
  `console_qr_svg_css_sets_explicit_dimensions`) to assert the served
  `/console` HTML contains `id="verification-dc-api-btn"` and that
  `<select id="transport">` contains both an `option value="request_uri"` and
  an `option value="dc_api"`.
- New integration test(s) for
  `POST /admin/verification/requests/:id/dc-api-response`, colocated with
  wherever the existing `dc_api` transport is already exercised end-to-end
  in `crates/foundry/tests/` (reusing whatever helper already builds a valid
  `dc_api.jwt`-encrypted response for those tests):
  - Happy path: create a `dc_api` verification request, submit a validly
    encrypted response to the new endpoint, assert `200`,
    `verified: true`, and that the transaction has moved to `Verified`.
  - `404` for an unknown transaction id.
  - `400` for resubmitting against a transaction that is no longer `Pending`.
  - These mirror the equivalent cases that already exist for
    `post_response_handler`; the goal is parity, not new coverage of
    `verify_vp_response` itself (unchanged).
- Scoped gate per root AGENTS.md §5.1: this work touches only `crates/foundry`
  (`server.rs`, `openapi.rs`, `assets/console.html`, `tests/console.rs`, plus
  whichever existing integration test file gets the new
  `dc-api-response` cases). No `foundry-verifier` or `foundry-issuer` change
  is introduced, so per §5.2 the gate is:
  ```
  cargo test -p foundry
  cargo clippy -p foundry --all-targets -- -D warnings
  cargo fmt --check
  ```

### OpenAPI

The new path and the `AdminDcApiResponseBody` schema are added to
`openapi.json` only, via `utoipa` annotations in
`crates/foundry/src/openapi.rs` and on the new handler
(root AGENTS.md §6). `openapi-wallet.json` is unaffected — this is not a
wallet-facing route.