# Admin Console: Trigger Presentation via the Digital Credentials API

Date: 2026-08-03

## What changed

The admin test console can now exercise the `dc_api` verification transport
end-to-end in the browser it's running in, instead of only printing the raw
`dc_api_request` object as text:

- `transport` in the Verification card is now a `<select>` (`request_uri` /
  `dc_api`) instead of a free-text input.
- Selecting `dc_api` and creating a request reveals a "Trigger via Digital
  Credentials API" button that calls `navigator.credentials.get()` in the
  browser, aligned with the proven patterns in
  `eudipay-frontend/src/dcApi.js`.
- A new admin-authenticated endpoint,
  `POST /admin/verification/requests/:id/dc-api-response`, accepts the
  resulting encrypted JWE as JSON and shares its verification core
  (`submit_vp_response`) with the existing wallet-facing
  `POST /vp/response/:id` — identical HTTP status/error-code classification,
  distinguished only by the `surface` log label (`admin` vs `wallet`).

Issuance is unaffected: the DC API is a presentation-only mechanism in the
pinned OpenID4VP/HAIP specs, with no equivalent in OpenID4VCI.

## Spec and plan

- `docs/superpowers/specs/2026-08-03-admin-console-dc-api-design.md`
- `docs/superpowers/plans/2026-08-03-admin-console-dc-api.md`

## Verification

Scoped gate (root AGENTS.md §5.1), run at each task boundary throughout:
`cargo test -p foundry`, `cargo clippy -p foundry --all-targets -- -D warnings`,
`cargo fmt --check`. No `foundry-verifier` or `foundry-issuer` change was
introduced, so no wider dependent set applied per §5.2.