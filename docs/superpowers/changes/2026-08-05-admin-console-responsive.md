# Admin Console — Responsive Layout for Mobile Devices

**Date:** 2026-08-05
**Spec:** `docs/superpowers/specs/2026-08-05-admin-console-responsive-design.md`
**Plan:** `docs/superpowers/plans/2026-08-05-admin-console-responsive-plan.md`

## What Changed

`crates/foundry/assets/console.html` only — no Rust source changes, no endpoint
changes, no OpenAPI changes.

- **Base CSS:** `flex-wrap: wrap` on `.key-bar`, `.radio-group`, and `.uri-row`;
  `flex: 1 1 220px` on the API key input. These rows overflowed at every
  viewport width, so the fix is unconditional rather than breakpoint-gated.
- **New `@media (max-width: 640px)` block:** reduced page and card padding;
  `font-size: 16px` on all form controls (below 16px, iOS Safari force-zooms the
  page on field focus); full-width primary buttons; enlarged `.copy-btn` /
  `.open-btn` touch targets; `order: -1` and `flex-basis: 100%` promoting the DC
  API button to the first, full-width action inside `.uri-row`.
- **QR disclosure:** each `.qr-wrap` is wrapped in `<details class="qr-disclosure" open>`
  with a `QR code` summary that is hidden above 640px. `initQrDisclosure()`
  closes it on small viewports.

The existing `@media (max-width: 860px)` two-column collapse is unchanged, as is
desktop rendering.

## Why the QR Disclosure Ships `open`

`open` is an HTML attribute CSS cannot set. A closed-by-default `<details>` would
need JS to open it on desktop, and if that JS failed, the QR would be unreachable
behind a CSS-hidden `<summary>`. Shipping `open` and closing on mobile degrades
instead to the pre-existing behaviour — QR visible at every size.

## Constraint Discovered During Design

The DC API buttons are shown and hidden by JS via `classList`, guarded by
`.open-btn.hidden { display: none }`. Any `display` declaration in an
`.open-btn` / `.copy-btn` rule inside the new media query would win on
specificity and permanently un-hide a button the JS intends to hide. The
media query therefore contains no `display` declaration at all; the layout
effect is achieved with `flex-basis`, `order`, `width`, `padding`, `font-size`,
`margin` and `text-align`, all of which are inert on a hidden element.

## The Four `innerHTML` Uses Are Untouched

`AGENTS.md` forbids reintroducing dynamic `innerHTML` here. Four uses already
exist (`renderQr`'s clear and `createSvgTag` insertion, the checks-list clear,
and the verification QR clear); this change adds none, and because the
`.qr-wrap` divs keep their ids inside the new `<details>` wrappers, every one of
them still resolves to the same element.

## Verification

No automated tests were added — the change is CSS layout and the workspace has no
browser-test infrastructure; adding one for a single-file test console was judged
disproportionate (spec §3, §8). The known cost is that a future edit to the
`<style>` block can undo this silently.

Scoped gate (`AGENTS.md` §5.1):

- `cargo test -p foundry` — green
- `cargo fmt --check` — clean

Manual acceptance on the phone used to drive the DC API flow.