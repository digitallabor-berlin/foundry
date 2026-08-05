# Admin Console Responsive Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Admin Test Console usable on a phone, with the Digital Credentials API trigger as the primary action on small screens.

**Architecture:** All work happens in one self-contained file, `crates/foundry/assets/console.html`, which is `include_str!`-embedded into the binary at `crates/foundry/src/server.rs:204` and served at `GET /console`. Unconditional overflow fixes go into the existing base CSS rules; everything genuinely size-conditional goes into one new `@media (max-width: 640px)` block appended just before `</style>`. The QR code is wrapped in a `<details>` element that ships `open` and is closed by JavaScript only on small viewports.

**Tech Stack:** Hand-written CSS and vanilla ES5-style JavaScript inside a single HTML file. No build step, no package manager, no CSS framework, no CDN.

**Spec:** `docs/superpowers/specs/2026-08-05-admin-console-responsive-design.md`

## Global Constraints

- **No CDN and no build step.** `crates/foundry/AGENTS.md` requires the console to work air-gapped. Do not add a stylesheet link, a script `src`, or a package dependency. CSS stays inside the existing `<style>` block; JS stays inside the existing `<script>` block.
- **No `innerHTML`.** Prior fixes deliberately removed dynamic `innerHTML` from this file. Use DOM properties and `document.createElement` / `createTextNode`.
- **Do not delete the vendored QR library's provenance comment.**
- **No `display` declaration may appear in any `.open-btn` or `.copy-btn` rule you add.** Those buttons are shown/hidden by JS via `classList`, guarded by `.open-btn.hidden { display: none }` at `console.html:85`. An override with ID or equal-plus-later specificity would permanently un-hide a button the JS intends to hide. Use `width`, `flex-basis`, `order`, `padding`, `font-size`, `margin` and `text-align` only. (Spec §5.5.)
- **Do not modify the `.qr-wrap svg` rule at `console.html:94`.** `console_qr_svg_css_sets_explicit_dimensions` (`crates/foundry/tests/console.rs:134`) parses that rule and asserts it declares both `width` and `height`.
- **Preserve every element id and class name the tests assert:** `id="offer-open"`, `id="verification-open"`, `<select id="transport">`, `id="verification-dc-api-btn"`, `id="offer-dc-api-btn"`, `id="issuance-status"`, `id="issuance-tx-code"`, `.badge.offered`, `.badge.issued`, and the literal string `navigator.credentials.create`.
- **Two breakpoints, kept separate:** the existing `max-width: 860px` (two columns → one) is not modified; the new one is `max-width: 640px`.
- **Desktop rendering must not change.** Every new declaration is either inside the `max-width: 640px` block, or a `flex-wrap` / `flex-basis` change that is inert at desktop widths.

## Testing Approach — read this before Task 1

**This plan writes no new tests, and that is a deliberate, approved decision** recorded in spec §8. The normal test-first cycle does not apply here, for a concrete reason: the change is CSS layout and there is no browser-test infrastructure in this workspace (no Playwright, no headless Chrome, no Node toolchain). A "failing test" for *"the tap target is too small"* cannot be written without adding a browser runtime, which spec §3 rules out as disproportionate for a single-file test console.

What replaces it:

1. **The existing console test suite is the regression guard.** `crates/foundry/tests/console.rs` asserts on served-HTML substrings and on the `.qr-wrap svg` CSS rule. Every task below runs it. It will catch an accidentally renamed id, a deleted class, or a broken QR rule — it will not catch "the layout looks wrong".
2. **Manual acceptance on the target device is the real gate**, performed by the human at the end (Task 5).

Do not add tests to `console.rs` unless the human asks. Do not skip running it.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/foundry/assets/console.html` | The entire console: markup, inline CSS, inline JS | Modified — CSS base rules, one new media query, QR wrapper markup, one new JS init function |
| `README.md` | Operator documentation | Modified — one bullet in the Admin Test Console section |
| `docs/superpowers/changes/2026-08-05-admin-console-responsive.md` | Change record | Created |

No file is created in `crates/`, and no Rust source changes at all. `crates/foundry/src/server.rs` needs no edit — it embeds the asset by path, so editing the HTML is sufficient.

---

### Task 1: Unconditional wrap fixes in the base CSS rules

These four rows overflow at *every* viewport width, not only on phones, so they are fixed in the base rules rather than in a media query. (Spec §5.1.)

**Files:**
- Modify: `crates/foundry/assets/console.html:33-34` (`.key-bar`), `:39-40` (`.key-bar input`), `:64` (`.radio-group`), `:88` (`.uri-row`)
- Test: `crates/foundry/tests/console.rs` (existing, unchanged)

**Interfaces:**
- Consumes: nothing — this is the first task.
- Produces: `.uri-row` becomes a *wrapping* flex container. Task 2 depends on this: its `flex-basis: 100%` overrides only push children onto their own lines because `flex-wrap: wrap` is set here. Task 2 will not work correctly if this task is skipped.

- [ ] **Step 1: Make `.key-bar` wrap**

Replace lines 33-34. Current text:

```css
  .key-bar {
    display: flex; gap: 8px; align-items: center;
```

New text:

```css
  .key-bar {
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
```

- [ ] **Step 2: Give the API key input a minimum flex basis**

The label (`white-space: nowrap`) and the "remembered" badge (`white-space: nowrap`) sit in the same row, so a bare `flex: 1` lets the input collapse to a sliver. A `220px` basis makes it wrap onto its own line instead.

Replace line 40. Current text:

```css
    flex: 1; background: #0c101a; border: 1px solid var(--panel-border);
```

New text:

```css
    flex: 1 1 220px; background: #0c101a; border: 1px solid var(--panel-border);
```

- [ ] **Step 3: Make `.radio-group` wrap**

Replace line 64. Current text:

```css
  .radio-group { display: flex; gap: 16px; margin-bottom: 10px; font-size: 13px; }
```

New text:

```css
  .radio-group { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 10px; font-size: 13px; }
```

- [ ] **Step 4: Make `.uri-row` wrap**

This is the row holding the URI text, `Copy`, `Open in Wallet`, and the DC API button — four items with no wrap today.

Replace line 88. Current text:

```css
  .uri-row { display: flex; align-items: center; gap: 6px; margin-bottom: 12px; }
```

New text:

```css
  .uri-row { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-bottom: 12px; }
```

- [ ] **Step 5: Confirm no `display` declaration was added to a button rule**

Run: `grep -n 'display' crates/foundry/assets/console.html | grep 'btn'`

Expected: exactly two lines, both pre-existing and both unchanged by this task —
`.open-btn { display: inline-block; ... }` (line 78) and
`.open-btn.hidden { display: none; }` (line 85). Any third line is one you
introduced; remove it (Global Constraints).

- [ ] **Step 6: Run the console tests**

Run: `cargo test -p foundry --test console`

Expected: PASS, all tests. These assert on ids, class names, and the `.qr-wrap svg` rule — none of which this task touches, so a failure here means you edited the wrong line.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/assets/console.html
git commit -m "fix(console): let the key bar, radio group, and URI row wrap"
```

---

### Task 2: The 640px phone treatment

One new media query carrying spacing, touch targets, iOS zoom prevention, and the DC API button promotion. (Spec §5.2, §5.3, §5.4, §5.5.)

**Files:**
- Modify: `crates/foundry/assets/console.html` — insert a block immediately before `</style>` at line 125
- Test: `crates/foundry/tests/console.rs` (existing, unchanged)

**Interfaces:**
- Consumes: `flex-wrap: wrap` on `.uri-row` from Task 1. The `flex-basis: 100%` declarations below only force items onto their own lines because that wrap is in place.
- Produces: an `@media (max-width: 640px)` block as the last rule in the stylesheet. Task 3 adds a *separate* `@media (min-width: 641px)` rule for the disclosure summary; the two must not be merged.

- [ ] **Step 1: Insert the media query before the closing `</style>` tag**

Line 124 is currently `  .hidden { display: none; }` and line 125 is `</style>`. Insert the following between them:

```css
  /* Small-screen (phone) treatment. The operator drives this console from the
     same phone that holds the wallet, to trigger the Digital Credentials API
     flow — so the DC API button is promoted to the primary action and the QR
     code (unscannable on the device displaying it) collapses. See
     docs/superpowers/specs/2026-08-05-admin-console-responsive-design.md. */
  @media (max-width: 640px) {
    body { padding: 16px; }
    main { gap: 14px; }
    .card { border-radius: 10px; padding: 14px; }
    .key-bar { padding: 10px 12px; }
    /* 16px is the threshold below which iOS Safari force-zooms the page on
       field focus. This is a functional fix, not a cosmetic one. */
    .key-bar input,
    .field input[type=text], .field textarea, .field select {
      font-size: 16px; padding: 10px 12px;
    }
    button.primary { width: 100%; padding: 14px 18px; font-size: 16px; }
    /* No `display` declaration belongs in the two rules below: the DC API and
       "Open in Wallet" buttons are hidden by JS via `.open-btn.hidden`, and an
       override here would win on specificity and strand them visible. */
    .uri-text { flex-basis: 100%; font-size: 13px; }
    .copy-btn, .open-btn {
      flex-basis: 100%; margin-left: 0; text-align: center;
      padding: 10px 14px; font-size: 14px;
    }
    #offer-dc-api-btn, #verification-dc-api-btn { order: -1; }
  }
```

- [ ] **Step 2: Verify the block contains no `display` declaration**

Run:

```bash
awk '/@media \(max-width: 640px\)/,/^  \}$/' crates/foundry/assets/console.html | grep -c 'display'
```

Expected: `0`. Any other number violates a Global Constraint — remove the declaration.

- [ ] **Step 3: Verify the `.qr-wrap svg` rule is untouched**

Run: `grep -n '.qr-wrap svg' crates/foundry/assets/console.html`

Expected: one line, still containing both `width: 100%` and `height: auto`.

- [ ] **Step 4: Run the console tests**

Run: `cargo test -p foundry --test console`

Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry/assets/console.html
git commit -m "feat(console): add a 640px breakpoint promoting the DC API action"
```

---

### Task 3: Collapse the QR code behind a disclosure on small screens

(Spec §5.6.)

**Files:**
- Modify: `crates/foundry/assets/console.html` — the two `.qr-wrap` divs (markup), the CSS immediately after the `.qr-wrap svg` rule, and the `DOMContentLoaded` handler (JS)
- Test: `crates/foundry/tests/console.rs` (existing, unchanged)

> **Line numbers in this task are from the pre-Task-2 file.** Task 2 inserts ~25
> lines before `</style>`, so everything below the stylesheet — all the markup and
> all the JS — has shifted down. **Locate each edit site with `grep -n`, not by
> line number.** The one exception is the CSS in Step 3, which sits above Task 2's
> insertion point and is therefore still at its original line.

**Interfaces:**
- Consumes: nothing from Tasks 1-2; this task is independent of them.
- Produces: elements matching `.qr-disclosure`, each wrapping an existing `.qr-wrap` div whose id is unchanged. A new function `initQrDisclosure()` taking no arguments and returning nothing.

- [ ] **Step 1: Wrap the issuance QR container**

Locate it: `grep -n 'id="offer-qr"' crates/foundry/assets/console.html` — one hit, originally line 165. Replace that line. Current text:

```html
      <div class="qr-wrap" id="offer-qr"></div>
```

New text:

```html
      <details class="qr-disclosure" open>
        <summary>QR code</summary>
        <div class="qr-wrap" id="offer-qr"></div>
      </details>
```

The `id="offer-qr"` stays on the inner div, so `renderQr(document.getElementById('offer-qr'), …)` at line 2686 keeps working unchanged.

- [ ] **Step 2: Wrap the verification QR container**

Locate it: `grep -n 'id="verification-qr"' crates/foundry/assets/console.html` — two hits; you want the markup one (`<div class="qr-wrap" …>`), not the `getElementById` call in the script. Originally line 203, now shifted by Task 2's insertion *and* by the 3 lines Step 1 added. Replace that line. Current text:

```html
      <div class="qr-wrap" id="verification-qr"></div>
```

New text:

```html
      <details class="qr-disclosure" open>
        <summary>QR code</summary>
        <div class="qr-wrap" id="verification-qr"></div>
      </details>
```

The `id="verification-qr"` stays on the inner div, so `document.getElementById('verification-qr')` at line 3004 keeps working unchanged.

- [ ] **Step 3: Add the disclosure CSS**

Insert immediately after the `.qr-wrap svg` rule — still at line 94, because Task 2 inserted its block further down. **Do not modify line 94 itself** (Global Constraints):

```css
  .qr-disclosure > summary { cursor: pointer; font-size: 13px; color: var(--muted); padding: 10px 0; }
  /* Desktop has room for the QR, so the disclosure affordance disappears
     entirely and the (always-`open`) details renders as a plain container. */
  @media (min-width: 641px) { .qr-disclosure > summary { display: none; } }
```

The browser's default disclosure triangle is intentionally kept on mobile, so open/closed state is visible without a JS-driven label swap.

- [ ] **Step 4: Add the `initQrDisclosure` function**

Locate the anchor: `grep -n "DOMContentLoaded" crates/foundry/assets/console.html` — one hit, originally line 3043. Insert the function immediately before it, after the blank line that precedes it.

The `querySelectorAll(...).forEach(function (x) { … })` shape below deliberately matches the existing convention in this file (see `setupCopyButtons` at line 2599) rather than introducing arrow functions or `for...of`:

```js
  /* The markup ships `open` and this closes it on small screens, rather than
     shipping closed and opening on desktop. `open` is an HTML attribute CSS
     cannot set, so the reverse arrangement would leave the QR unreachable
     behind a CSS-hidden <summary> on any desktop where this script failed to
     run. Closing-on-mobile degrades instead to the pre-existing behaviour. */
  function initQrDisclosure() {
    if (!window.matchMedia('(max-width: 640px)').matches) return;
    document.querySelectorAll('.qr-disclosure').forEach(function (d) {
      d.open = false;
    });
  }
```

- [ ] **Step 5: Register it on `DOMContentLoaded`**

Replace the handler body. Current text:

```js
  document.addEventListener('DOMContentLoaded', function () {
    initApiKey();
    initIssuance();
    initVerification();
    setupCopyButtons();
  });
```

New text:

```js
  document.addEventListener('DOMContentLoaded', function () {
    initApiKey();
    initIssuance();
    initVerification();
    setupCopyButtons();
    initQrDisclosure();
  });
```

- [ ] **Step 6: Verify no `innerHTML` was introduced**

Run: `grep -c 'innerHTML' crates/foundry/assets/console.html`

Expected: `0`. A non-zero count violates a Global Constraint.

- [ ] **Step 7: Verify both QR ids survived the wrapping**

Run: `grep -n 'id="offer-qr"\|id="verification-qr"\|qr-disclosure' crates/foundry/assets/console.html`

Expected: both ids present exactly once each, still on `div class="qr-wrap"` elements, plus two `<details class="qr-disclosure" open>` lines and one `.qr-disclosure > summary` CSS rule and one `min-width: 641px` rule.

- [ ] **Step 8: Run the console tests**

Run: `cargo test -p foundry --test console`

Expected: PASS, all tests — in particular `console_qr_svg_css_sets_explicit_dimensions`, which is the one most exposed to this task.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry/assets/console.html
git commit -m "feat(console): collapse the QR code behind a disclosure on phones"
```

---

### Task 4: Documentation

(Spec §7.)

**Files:**
- Modify: `README.md` — the Admin Test Console section (begins at the `#### Admin Test Console` heading)
- Create: `docs/superpowers/changes/2026-08-05-admin-console-responsive.md`

**Interfaces:**
- Consumes: the finished behaviour from Tasks 1-3.
- Produces: nothing consumed by later tasks.

> **Note on repo state:** `README.md` may carry unrelated uncommitted work about `verifier.dc_api_expected_origins`. Do not stage or revert it. Add only your own bullet, and stage `README.md` knowing the human will separate the changes if needed — if `git diff README.md` shows edits you did not make, tell the human rather than committing them.

- [ ] **Step 1: Add the README bullet**

In the Admin Test Console section of `README.md`, immediately after the paragraph beginning "The console never gates the buttons on browser sniffing", add:

```markdown
The console is responsive and usable from a phone, which is the expected setup
for driving a Digital Credentials API flow: below 640px the DC API button becomes
the first, full-width action in the result block, and the QR code collapses
behind a `QR code` disclosure — it is unscannable on the device displaying it,
and one tap reopens it. Desktop layout is unchanged.
```

- [ ] **Step 2: Write the change record**

Create `docs/superpowers/changes/2026-08-05-admin-console-responsive.md`:

```markdown
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

## Verification

No automated tests were added — the change is CSS layout and the workspace has no
browser-test infrastructure; adding one for a single-file test console was judged
disproportionate (spec §3, §8). The known cost is that a future edit to the
`<style>` block can undo this silently.

Scoped gate (`AGENTS.md` §5.1):

- `cargo test -p foundry` — green
- `cargo fmt --check` — clean

Manual acceptance on the phone used to drive the DC API flow.
```

- [ ] **Step 3: Run the scoped gate in full**

Per `AGENTS.md` §5.1 and §5.2, `crates/foundry` is the top of the dependency chain, so nothing else is affected. Do **not** run `cargo test --workspace`.

```bash
cargo test -p foundry
cargo fmt --check
```

Expected: tests PASS, `fmt --check` silent. No Rust source changed, so clippy has nothing new to judge; run `cargo clippy -p foundry --all-targets -- -D warnings` if you want the confirmation — it should be a no-op.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/superpowers/changes/2026-08-05-admin-console-responsive.md
git commit -m "docs: record the responsive admin console layout"
```

---

### Task 5: Manual acceptance (human)

This task is **not** for a subagent. It is the acceptance gate the automated suite cannot provide, and the reason spec §8 accepts having no new tests.

**Files:** none.

- [ ] **Step 1: Start the server**

```bash
cargo run -p foundry -- serve --config config.yaml
```

If you have no `config.yaml` yet, generate one first with `cargo run -p foundry -- quickstart`.

- [ ] **Step 2: Open the console on the phone used for the DC API flow**

Navigate to the admin listener's `/console` — `http://127.0.0.1:9000/console` by default, or the LAN-reachable host the phone can actually resolve.

- [ ] **Step 3: Confirm each acceptance criterion**

- The `Admin API key` field is wide enough to type into, wrapping below its label rather than collapsing beside it.
- Focusing any field does **not** zoom the page (iOS Safari).
- `Create Offer` is a full-width, comfortably tappable button.
- After creating an offer, the `Add to Wallet (Digital Credentials API)` button is the **first** element of the result block and spans the full width.
- The QR code is collapsed, showing a `QR code` disclosure, and one tap opens it.
- Nothing overflows horizontally; no sideways page scroll.

- [ ] **Step 4: Confirm desktop is unchanged**

Load the same URL on a desktop browser. The two-column layout, spacing, small `Copy` buttons, and always-visible QR (with no disclosure triangle) should look exactly as before.

- [ ] **Step 5: Report**

Report any criterion that fails, with the viewport width. Then finish the branch per `superpowers:finishing-a-development-branch`.