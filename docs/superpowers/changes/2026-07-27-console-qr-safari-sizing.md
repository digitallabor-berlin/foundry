# Fix QR codes rendering as a tiny/blank box in Safari on the Admin Test Console

**Date:** 2026-07-27
**Type:** bugfix

## Problem

The Admin Test Console (`GET /console`, `crates/foundry/assets/console.html`)
correctly renders the issuance/verification QR codes in Chrome, but in
Safari the QR area shows only a small white box with no visible code.

## Approach

Root cause (found via `superpowers:systematic-debugging`): the vendored QR
library's `qr.createSvgTag({ scalable: true })` call intentionally omits
`width`/`height` attributes on the generated `<svg>`, relying only on its
`viewBox` so the SVG can be sized via CSS. The page's only rule for it,
`.qr-wrap svg { background: #fff; padding: 10px; border-radius: 8px; }`,
never set an explicit size. Chrome falls back to a usable default size for
a viewBox-only SVG; Safari's replaced-element sizing algorithm collapses it
to near-zero instead.

Fix: give `.qr-wrap svg` an explicit CSS size (`width: 100%; max-width:
220px; height: auto; aspect-ratio: 1 / 1;`) so the rendered size no longer
depends on each browser's differing intrinsic-size fallback for
viewBox-only SVGs. Rejected alternative: passing `cellSize`/`margin`
arguments to `createSvgTag()` instead of `{ scalable: true }` so the
library bakes in explicit width/height itself — rejected because it's a JS
behavior change rather than a CSS fix, and the CSS-only fix preserves the
existing "scalable" sizing intent.

No headless-browser tooling (Playwright/Puppeteer/jsdom-with-layout) is
available in this environment to assert the actual rendered pixel size, so
verification of the real Safari behavior change is manual (see below); the
automated test instead pins the CSS source itself so this regression can't
silently reappear.

## Changes
- `crates/foundry/assets/console.html` — added `width: 100%; max-width:
  220px; height: auto; aspect-ratio: 1 / 1;` to the `.qr-wrap svg` rule.

## Tests
- `crates/foundry/tests/console.rs::console_qr_svg_css_sets_explicit_dimensions` —
  new regression test asserting the served `/console` page's `.qr-wrap svg`
  CSS rule contains explicit `width`/`height` declarations (RED before the
  fix, GREEN after).
- Manual verification recommended: reload `/console` in Safari and confirm
  both the issuance and verification QR codes render at full size (not a
  tiny white box).