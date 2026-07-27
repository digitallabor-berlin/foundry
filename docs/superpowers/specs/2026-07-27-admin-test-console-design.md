# Foundry Admin Test Console — Design

## 1. Overview

`foundry` currently requires either `curl`/Swagger UI against the Admin API
plus a separate wallet (the `foundry-wallet` CLI/TUI, or a real EUDI wallet
app) to exercise an OpenID4VCI issuance or OpenID4VP verification flow
end-to-end. There is no quick way to trigger these flows from a browser and
hand the result to a **real wallet app** (e.g. on a phone) for testing.

This feature adds a single embedded HTML/JS page — the **Admin Test
Console** — served by `foundry` itself at `GET /console` on the Admin
listener. It lets a developer:

- Create a credential offer (issuance) and get the `credential_offer_uri`
  as both copyable text and a scannable QR code.
- Create a verification request and get the `openid4vp_uri`/`request_uri`
  as both copyable text and a scannable QR code.
- Watch a verification request's status update live (auto-polling) and see
  the final `verified` outcome, per-check results, and disclosed claims.

The console is a **trigger UI only** — it never performs wallet-side crypto
(no holder keys, no proof JWTs, no SD-JWT/mdoc parsing). That role stays
with `foundry-wallet` or a real wallet app. The console exists purely to
kick off the two admin-side flows without hand-rolling `curl` calls, and to
produce a QR code a real wallet can scan.

## 2. Architecture

- **Serving**: one self-contained static HTML file, embedded into the
  `foundry` binary via `include_str!`, served via a new `GET /console`
  route registered in the *unauthenticated* section of `admin_router`
  (alongside `/health`, `/ready`, `/api-docs`) in `crates/foundry/src/server.rs`.
  Same-origin as the Admin API it calls (127.0.0.1:9000 by default), so no
  CORS is needed for the `fetch()` calls it makes to `/admin/issuance/offers`,
  `/admin/verification/requests`, and `/admin/verification/requests/:id`.
- **No new runtime dependencies**: no static-file-serving crate, no CDN
  fetches. The page is one HTML file with inline `<style>` and `<script>`,
  including a vendored public-domain QR-encoding JS library
  (`qrcode-generator` by Kazuhiko Arase, MIT licensed, single-file,
  dependency-free) inlined directly in the `<script>` block. QR rendering
  happens entirely client-side from the URI strings the admin API already
  returns — no extra server round-trip and no new server-side QR
  generation code.
- **Config gate**: a new `console_enabled: bool` field on `AdminConfig`
  (`crates/foundry-core/src/config/model.rs`), default `true`, following
  the exact existing pattern of `swagger_ui_enabled`. When `false`, the
  route is not registered (mirrors how the Swagger UI route is conditionally
  merged today) — the console never becomes an admin API route replacement,
  and `console_enabled: false` fully removes it (404, not just hidden).
- **Auth model**: the page itself is unauthenticated (like `/health`), but
  every `fetch()` it makes to `/admin/*` carries `Authorization: Bearer
  <api_key>` from a value the user pastes into a field in the page. The key
  is persisted to the browser's `localStorage` (key:
  `foundry_console_admin_api_key`) so it survives reloads — acceptable
  because the Admin listener binds to loopback (`127.0.0.1`) by default and
  this is a developer-facing dev tool, not a production surface.

## 3. New/changed files

| File | Change |
|---|---|
| `crates/foundry-core/src/config/model.rs` | Add `console_enabled: bool` (default `true`) to `AdminConfig`. |
| `crates/foundry/assets/console.html` | New — the entire console page (HTML + inline CSS + inline JS + vendored QR lib). |
| `crates/foundry/src/server.rs` | Add `console_handler` (returns `Html`), register `GET /console` in `admin_router`'s unauthenticated section, conditional on `state.config.server.admin.console_enabled`. |
| `crates/foundry/tests/*.rs` | New integration test(s) — see §7. |
| `README.md` | New short section documenting `GET /console`. |

No changes to `foundry-issuer`, `foundry-verifier`, or any wallet-facing
route. The console calls existing Admin API endpoints exactly as they exist
today — no new request/response shapes.

## 4. Page layout & UX

A single responsive page, two side-by-side cards on desktop (stacked on
narrow viewports): **Issuance** and **Verification**. Hand-written CSS
(no framework, no CDN) but with real visual design attention — this is a
dev tool but must not look like unstyled default form elements:

- Consistent spacing/typography scale, a small neutral color palette, card
  surfaces with subtle borders/shadows, monospace panels for JSON/URI
  output with a "Copy" button, and color-coded status badges (`Pending` =
  amber, `Verified` = green, `Failed` = red).
- An API key field at the top of the page (shared by both panels), with a
  "remembered" indicator when a key is loaded from `localStorage`.

### Issuance panel
- Inputs: `credential_type_id` (text), `claims` (JSON textarea, pretty
  default placeholder), `tx_code_required` (checkbox).
- Button: "Create Offer" → `POST /admin/issuance/offers`.
- Output: `transaction_id`, `credential_offer_uri` (copyable text + QR
  code), raw `credential_offer` JSON (collapsible/pretty-printed).

### Verification panel
- Mode toggle: "Named query" (text input for `named_query_ref`) vs. "Raw
  DCQL" (JSON textarea for `dcql_query`) — mutually exclusive, only one is
  sent.
- Transport select (`request_uri` default; free-text override allowed for
  other supported values).
- Button: "Create Verification Request" → `POST /admin/verification/requests`.
- Output: `verification_id`, `openid4vp_uri`/`request_uri` (copyable text +
  QR), status badge, and — once resolved — the full result: `verified`
  (bool), each `CheckResult` (name + pass/fail + detail), and the disclosed
  `claims` JSON.
- **Auto-polling**: starts immediately after creation, `GET
  /admin/verification/requests/:id` every 2s, updates the status badge live,
  stops on any terminal state (`Verified`/`Failed`) or on a hard error
  (e.g. 404 = transaction expired/not found). Transient network errors do
  not stop polling outright — retried up to a bounded count (10) before
  surfacing a fatal error banner.

## 5. Data flow

1. Browser loads `GET /console` (unauthenticated, same origin as
   `/admin/*`).
2. User pastes/confirms the Admin API key (persisted to `localStorage`).
3. **Issuance**: form → client-side `JSON.parse` validation of `claims` →
   `fetch('/admin/issuance/offers', {method: 'POST', headers: {Authorization:
   'Bearer ' + key, 'Content-Type': 'application/json'}, body})` → render
   response fields + QR generated client-side from `credential_offer_uri`.
   A real wallet scans the QR and completes the OpenID4VCI flow directly
   against the wallet-facing listener — the console has no further role.
4. **Verification**: same request pattern against
   `/admin/verification/requests` → render `verification_id` +
   URI/QR → begin polling `GET /admin/verification/requests/:id` → render
   live status → render final `VerificationResult` once terminal.

## 6. Error handling

- **Client-side validation**: JSON textareas are `JSON.parse`-checked
  before any network call; invalid JSON is flagged inline and nothing is
  sent.
- **Non-2xx admin responses**: shown as an inline error banner with the
  HTTP status and the server's JSON error body (`error`/`kind` fields, same
  shape `foundry-wallet` already logs verbatim). A `401` gets an additional
  specific hint: "Check your Admin API key."
- **Polling**: stops on `Verified`/`Failed` state, or on a non-network hard
  error (404/500). Bounded retry (10 attempts, 2s apart) on transient
  network failures before giving up with an error banner — polling is
  never unbounded/infinite.
- No secrets beyond the Admin API key are ever handled differently than
  today's `curl` workflow — the key the user pastes is exactly what they'd
  already need for a `curl -H "Authorization: Bearer ..."` call.

## 7. Testing strategy

- **Rust integration test** (new, in `crates/foundry/tests/`): boots the
  app router with a test `AppState`/`AdminApiKey` (following the existing
  test harness pattern in this crate), asserts:
  - `GET /console` → `200`, `content-type` starts with `text/html`, body
    contains a recognizable marker (e.g. a `<title>` string or
    `id="app"`).
  - With `console_enabled: false` in the test config, `GET /console` →
    `404`.
- **No JS test framework** is introduced — this is a dev-only tool with no
  build step. Manual verification path: `foundry quickstart` → `foundry
  serve` → open `http://127.0.0.1:9000/console` → run an issuance against
  `foundry-wallet` (or a real wallet on a phone via QR) → run a
  verification the same way → confirm the console shows `verified: true`
  with the expected disclosed claims.
- Standard workspace gates apply per `AGENTS.md`: `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt
  --check`.

## 8. OpenAPI note (AGENTS.md §5 compliance)

`AGENTS.md` requires HTTP endpoints to be reflected in the exposed OpenAPI
spec. `GET /console` returns static `text/html`, not a JSON API resource —
there is no meaningful request/response schema to document, exactly like
the existing `/api-docs` Swagger UI route itself, which is also not part of
the generated `AdminApiDoc`/`utoipa::OpenApi` schema. `GET /console` is
therefore deliberately excluded from the OpenAPI spec for the same reason;
this is a documented, intentional exception, not an oversight.

## 9. Non-goals / future work

- No in-browser wallet simulation (no holder keys, no proof-of-possession
  JWTs, no SD-JWT/mdoc parsing, no JWE decryption). That remains
  `foundry-wallet`'s job.
- No dynamic credential-type/claims form built from
  `/.well-known/openid-credential-issuer` metadata, and no named-query
  listing endpoint — claims and DCQL input stay freeform JSON (YAGNI; adding
  either would require new CORS allowances or a new admin listing endpoint
  for a dev-only tool).
- No authentication for the `GET /console` page load itself (only the
  admin API calls it makes are authenticated) — acceptable given the
  loopback-only default bind of the Admin listener.
- No persistence of issuance/verification history across page reloads
  beyond the remembered API key (each reload starts a fresh session; the
  underlying transactions are still inspectable via the Admin API directly
  if needed).