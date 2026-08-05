# Admin Test Console — Responsive Layout for Mobile Devices

**Date:** 2026-08-05
**Status:** Approved
**Scope:** `crates/foundry/assets/console.html`, `README.md`

---

## 1. Problem

The Admin Test Console (`GET /console`, served from the embedded
`crates/foundry/assets/console.html`) is hard to use on a phone. The file already
carries `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
and one media query:

```css
@media (max-width: 860px) { main { grid-template-columns: 1fr; } }
```

So the two cards do stack. Nothing else adapts. The concrete defects:

| # | Defect | Location |
|---|---|---|
| 1 | `body { padding: 32px }` consumes 64px of a 375px viewport, never reduced | `console.html:28` |
| 2 | `.uri-row` is a four-item non-wrapping flex row (URI text, `Copy`, `Open in Wallet`, `Add to Wallet (Digital Credentials API)`); the last label alone exceeds a phone's width | `console.html:88` |
| 3 | `.key-bar` is a non-wrapping flex row with a `white-space: nowrap` label and a nowrap "remembered" badge, collapsing the API-key input to a sliver | `console.html:33` |
| 4 | Form controls are `font-size: 13px`; below 16px, iOS Safari force-zooms the page on every field focus | `console.html:57`–`:59` |
| 5 | `.copy-btn` and `.open-btn` are `4px 8px` padding at 11px font — far below a ~44px touch target | `console.html:72`, `:77` |
| 6 | `.radio-group` is also `display: flex` with no wrap | `console.html:64` |

## 2. Usage Context

The operator uses the console **on the phone that is also the wallet device**, to
trigger the Digital Credentials API flow. The QR code is therefore near-useless
on that screen — you cannot scan your own display — while the DC API button is
the entire point of the visit. Today that button is the smallest, least tappable
element on the page and the third item in an overflowing flex row.

This drives the priority ordering below. It is a usage fact, not a general
statement about the console: on a desktop driving a separate wallet phone, the
QR remains primary, so the desktop layout is left alone.

## 3. Goals and Non-Goals

**Goals**

- The console is comfortable to operate one-handed on a ~375px-wide viewport.
- The DC API trigger is the visually primary action on small screens.
- Desktop rendering is unchanged.
- No new runtime dependency; the file stays self-contained and buildless.

**Non-Goals**

- No CSS framework. `crates/foundry/AGENTS.md` forbids reintroducing a CDN
  dependency (the console must work air-gapped) and there is no build step, so
  Tailwind/Bootstrap are out.
- No redesign of the console's information architecture, no new features, no
  changes to which admin endpoints it calls.
- No automated layout testing (see §8).

## 4. Approach

**Targeted breakpoint patch.** The existing inline stylesheet
(`console.html:7`–`:125`) remains the desktop baseline; a new
`@media (max-width: 640px)` block overrides only what is genuinely
size-conditional. Desktop rendering is unchanged by construction.

Two alternatives were considered and rejected:

- **Mobile-first rewrite** (invert the cascade; base rules become the narrow
  layout, `min-width: 641px` layers desktop back on). Structurally cleaner, but
  it rewrites nearly every rule in the stylesheet and requires re-verifying
  desktop as well as mobile. The payoff does not cover the risk at this size.
- **Purely fluid CSS, no new breakpoint** (`flex-wrap`, `clamp()`,
  `repeat(auto-fit, minmax())`). Cannot deliver the requirement: collapsing the
  QR and promoting the DC API button is a change in element *priority*
  conditional on screen size, and there is no fluid expression of that.

Techniques from the fluid approach are still used where they are unconditionally
correct — see §5.1.

## 5. Design

### 5.1 Base rules (all viewport widths)

These are defects at every width, not only below 640px, so they belong in the
base rules rather than the media query:

```css
.key-bar       { flex-wrap: wrap; }
.key-bar input { flex: 1 1 220px; }   /* was `flex: 1`, which could collapse to a sliver */
.uri-row       { flex-wrap: wrap; }
.radio-group   { flex-wrap: wrap; }
```

### 5.2 Breakpoints

Two breakpoints with distinct jobs, deliberately not merged:

- **`max-width: 860px`** (existing, unchanged) — the two-column card grid stops
  fitting and becomes one column.
- **`max-width: 640px`** (new) — the phone treatment: spacing, touch targets,
  iOS zoom prevention, QR collapse, DC API promotion.

Merging them into a single threshold would either cramp tablets or start the
phone treatment too early.

### 5.3 The 640px block

Spacing and density:

- `body` padding `32px` → `16px`
- `.card` padding `20px` → `14px`, `border-radius` `12px` → `10px`
- `main` gap `20px` → `14px`

Touch targets and iOS zoom:

- `.field input[type=text]`, `.field textarea`, `.field select` →
  `font-size: 16px` and `padding: 10px 12px`. The 16px floor is what prevents
  iOS Safari from force-zooming on focus; it is a functional fix, not cosmetic.
- `button.primary` → full width, `font-size: 16px`, `padding: 14px 18px`
- `.copy-btn`, `.open-btn` → `font-size: 14px`, `padding: 10px 14px`

### 5.4 Reprioritisation inside `.uri-row`

These rules live in the same `max-width: 640px` block as §5.3; they are separated
here only because they serve a different purpose. `.uri-row` is already a flex
container, so the DC API button can be promoted without reordering the DOM:

```css
@media (max-width: 640px) {
  .uri-text { flex-basis: 100%; }
  .copy-btn, .open-btn { flex-basis: 100%; margin-left: 0; text-align: center; }
  #offer-dc-api-btn, #verification-dc-api-btn { order: -1; }
}
```

`order: -1` lifts the DC API button to the top of the result block — directly
below `Create Offer` / `Create Verification Request` — and `flex-basis: 100%`
makes it full width. It is already `var(--accent)`-coloured, so it reads as the
primary action without a new colour rule.

### 5.5 Binding constraint: never override `display` on these controls

The DC API buttons are shown and hidden by JS via `classList`
(`console.html:2694`, `:3022`), guarded by `.open-btn.hidden { display: none }`.

An override such as `#offer-dc-api-btn { display: block }` inside the media query
would win on ID specificity and **permanently un-hide a button that JS intends to
be hidden**. The design therefore forbids any `display` declaration in
`.open-btn` / `.copy-btn` overrides. `width`, `flex-basis`, `order`, `padding`,
`font-size` and `margin` achieve the full effect and are inert on a
`display: none` element.

### 5.6 QR disclosure

At `console.html:165` and `:203`, each `.qr-wrap` div is wrapped. The ids stay on
the inner divs, so `renderQr(document.getElementById('offer-qr'), …)` (`:2686`)
and `document.getElementById('verification-qr')` (`:3004`) are unaffected:

```html
<details class="qr-disclosure" open>
  <summary>QR code</summary>
  <div class="qr-wrap" id="offer-qr"></div>
</details>
```

```css
.qr-disclosure > summary { cursor: pointer; font-size: 13px; color: var(--muted); padding: 10px 0; }
@media (min-width: 641px) { .qr-disclosure > summary { display: none; } }
```

```js
function initQrDisclosure() {
  if (!window.matchMedia('(max-width: 640px)').matches) return;
  document.querySelectorAll('.qr-disclosure').forEach(function (d) { d.open = false; });
}
```

Registered alongside the existing init functions in the `DOMContentLoaded`
handler at `console.html:3043`.

**The markup ships `open` and JS closes it on small screens — not the reverse.**
`open` is an HTML attribute that CSS cannot set, so a closed-by-default
`<details>` would need JS to open it on desktop; if that JS ever failed to run,
desktop would show a collapsed disclosure whose `<summary>` is hidden by CSS,
making the QR unreachable. Shipping `open` and closing it on mobile degrades
instead to exactly today's behaviour — QR visible at every size.

The browser's default disclosure triangle is kept on mobile so open/closed state
is self-evident and the summary text can remain the static string `QR code`, with
no JS-driven label swapping.

## 6. Preserved Invariants

- **No CDN, no build step, no `innerHTML`** — `crates/foundry/AGENTS.md`. The
  change adds only CSS, wrapper markup, and one `matchMedia` function that
  assigns the `open` property. The vendored QR library and its provenance
  comment are untouched.
- **`.qr-wrap svg` keeps declaring `width` and `height`** — asserted by
  `console_qr_svg_css_sets_explicit_dimensions` in
  `crates/foundry/tests/console.rs:134`. The rule is not modified.
- **Element ids and CSS class names asserted by tests are preserved** —
  `id="offer-open"`, `id="verification-open"`, `<select id="transport">`,
  `id="verification-dc-api-btn"`, `id="offer-dc-api-btn"`,
  `id="issuance-status"`, `id="issuance-tx-code"`, `.badge.offered`,
  `.badge.issued`, and the string `navigator.credentials.create`.

## 7. Documentation

- `README.md`, Admin Test Console section: note that the console is usable on a
  phone and that the QR collapses behind a disclosure below 640px.
- Change record: `docs/superpowers/changes/2026-08-05-admin-console-responsive.md`.
- No OpenAPI change — no endpoint's path, method, or shape is touched.

## 8. Verification

No automated tests are added. This is a deliberate choice with a known cost: a
future edit to the `<style>` block can undo this work silently, and nothing will
fail. Recorded here so the tradeoff is visible rather than accidental.

The scoped gate (`AGENTS.md` §5.1) for a change confined to `crates/foundry`:

```bash
cargo test -p foundry --test console
cargo test -p foundry
cargo fmt --check
```

Nothing depends on `foundry` in the §3 layering, so that is the complete affected
set — no `--workspace` run.

Acceptance is manual: load `http://127.0.0.1:9000/console` on the phone used to
drive the DC API flow and confirm that the API-key field is usable, focusing a
field does not zoom the page, the DC API button is the first and full-width
action in the result block, and the QR is collapsed.