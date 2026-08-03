# Admin Console: "Open in Wallet" deep links (same-device flow)

Date: 2026-08-03
Status: Approved

## Problem

The admin test console (`crates/foundry/assets/console.html`, served at
`GET /console`) already returns and displays true deep links for both flows:

- Issuance: `POST /admin/issuance/offers` returns `credential_offer_uri`, an
  `openid-credential-offer://?credential_offer=...` URI
  (`crates/foundry-issuer/src/offer.rs`).
- Verification: `POST /admin/verification/requests` returns `openid4vp_uri`,
  an `openid4vp://?client_id=...&request_uri=...` URI, for every transport
  except `dc_api` (`crates/foundry-verifier/src/request.rs`).

The console renders each URI as plain text (`<span class="uri-text">`) plus a
"Copy" button and a QR code. This supports **cross-device** testing (scan the
QR with a phone while the console runs on a desktop) but not **same-device**
testing: opening the console itself on the phone that has the wallet
installed gives no way to invoke the wallet — the QR can't be scanned by the
device displaying it, and the copy button has nowhere useful to paste into.

## Goal

Add a tappable link, alongside the existing QR and Copy button, that invokes
the OS's custom-URL-scheme handler directly when the console is opened on the
same device as the wallet.

## Non-goals

- No backend or API changes. Both endpoints already emit fully-formed deep
  links; this is a presentational change over data already returned.
- No change to QR rendering, response shapes, or OpenAPI specs.
- No new transport for `dc_api` verification requests — that transport has no
  scannable/tappable URI today (it returns a Digital Credentials API request
  object instead) and this change doesn't alter that.

## Design

### HTML

In both result panels (`#issuance-result` and `#verification-result`), add a
new anchor immediately after the existing "Copy" button, inside the same
`.uri-row`:

```html
<div class="uri-row">
  <span class="uri-text" id="offer-uri"></span>
  <button class="copy-btn" data-copy-target="offer-uri">Copy</button>
  <a class="open-btn hidden" id="offer-open" target="_self">Open in Wallet</a>
</div>
```

and the mirror for verification:

```html
<div class="uri-row">
  <span class="uri-text" id="verification-uri"></span>
  <button class="copy-btn" data-copy-target="verification-uri">Copy</button>
  <a class="open-btn hidden" id="verification-open" target="_self">Open in Wallet</a>
</div>
```

Both links start `hidden` (matching the existing `.hidden` utility class
already used throughout the page) and are only revealed once a URI is
actually set, so a stale/empty `href` is never clickable.

### CSS

Add an `.open-btn` rule sized like `.copy-btn` but visually distinct (accent
color) so it reads as the primary same-device action next to the passive
Copy button and the QR:

```css
.open-btn {
  display: inline-block;
  background: var(--accent); color: #fff; text-decoration: none;
  border-radius: 6px; padding: 4px 10px; font-size: 11px; font-weight: 600;
  margin-left: 8px; cursor: pointer;
}
.open-btn:hover { background: var(--accent-dark); }
.open-btn.hidden { display: none; }
```

(`.hidden { display: none; }` already exists globally; the `.open-btn.hidden`
override is only needed because `.open-btn`'s own `display: inline-block`
would otherwise take precedence in a plain CSS cascade — kept explicit for
clarity.)

### JS

In `initIssuance()`'s success handler, alongside the existing
`offer-uri`/`offer-qr` population:

```js
const openEl = document.getElementById('offer-open');
openEl.href = body.credential_offer_uri;
openEl.classList.remove('hidden');
```

(`credential_offer_uri` is always present on a successful response, so no
conditional is needed here — matches the existing unconditional QR render.)

In `initVerification()`'s success handler, alongside the existing
`uri`/`verification-qr` population, extend the existing `if (uri) { ... }`
branch:

```js
const openEl = document.getElementById('verification-open');
if (uri) {
  uriEl.textContent = uri;
  renderQr(qrEl, uri);
  openEl.href = uri;
  openEl.classList.remove('hidden');
} else {
  openEl.classList.add('hidden');
  if (body.dc_api_request) {
    uriEl.textContent = '(dc_api transport has no scannable URI; use the Digital Credentials API request object returned by the admin endpoint directly)';
  } else {
    uriEl.textContent = '';
  }
}
```

The `else` branch also needs to explicitly hide `verification-open` on each
new request, since a prior `request_uri`-transport result could have left it
visible before the user switches to `dc_api` and re-submits.

### Behavior

A plain `<a href="openid-credential-offer://...">` / `<a
href="openid4vp://...">` is sufficient: browsers natively hand off navigation
to a registered custom URL scheme to the OS, which launches the wallet app if
one is registered, or no-ops (or shows a native "no app found" prompt) if
not. No `window.location` assignment or click-interception JS is needed.
`target="_self"` avoids opening a blank new tab/window as a side effect of
the failed navigation attempt on browsers where no handler is registered.

## Testing

Extend `crates/foundry/tests/console.rs` with a structural assertion — in the
same style as the existing `console_qr_svg_css_sets_explicit_dimensions`
regression test — that the served `/console` HTML contains both
`id="offer-open"` and `id="verification-open"` anchor elements. This guards
against a future edit silently dropping either link, the same way the
existing test guards the QR `<svg>` sizing rule.

No new Rust logic is introduced (no `foundry-issuer` / `foundry-verifier`
changes), so the scoped gate for this task is:

```
cargo test -p foundry --test console
cargo fmt --check
```