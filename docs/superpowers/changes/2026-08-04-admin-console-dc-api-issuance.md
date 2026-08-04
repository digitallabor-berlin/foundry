# Admin Console: Issue Credentials via the Digital Credentials API

Date: 2026-08-04

## What changed

The admin test console can now hand a credential offer to a wallet through
the W3C Digital Credentials API's issuance path (Chrome 143+,
`navigator.credentials.create()`), and — for the first time — shows whether a
credential was actually issued rather than only that an offer was created:

- `foundry_issuer::create_offer` now returns `dc_api_offer` on
  `CreateOfferResponse`: the same `CredentialOffer` already carried by
  `credential_offer` / `credential_offer_uri`, rendered as the `data` payload
  Chrome's `openid4vci-v1` protocol expects, with `authorization_server_metadata`
  taken verbatim from `build_authorization_server_metadata` and
  `credential_issuer_metadata` narrowed — via the new
  `foundry_issuer::build_dc_api_offer` — to only the credential configuration(s)
  actually named in the offer.
- A new admin-authenticated endpoint, `GET /admin/issuance/offers/:id`, returns
  `AdminIssuanceStatus`: `transaction_id`, `credential_type_id`, `state`
  (`offered` / `issued`), `created_at`, `status_list_index`, and — new to any
  endpoint — `tx_code`, which was previously generated and persisted but never
  surfaced anywhere. The projection deliberately omits `pre_authorized_code`,
  `access_token`, and every other transaction field that would let an
  admin-key holder redeem a wallet's offer.
- The console's issuance card gained an "Add to Wallet (Digital Credentials
  API)" button (`navigator.credentials.create()` with protocol
  `openid4vci-v1`), a status badge (`offered` → `issued`), and a `tx_code`
  display when the offer required one. Polling now runs unconditionally after
  every "Create Offer" click, so the QR / deep-link path also gets outcome
  feedback, not only the DC API path.

**This corrects a claim made in the prior change record**
(`docs/superpowers/changes/2026-08-03-admin-console-dc-api.md`), which stated:
"Issuance is unaffected: the DC API is a presentation-only mechanism in the
pinned OpenID4VCI/HAIP specs, with no equivalent in OpenID4VCI." That remains
true of the *pinned specs* — neither OpenID4VCI nor HAIP's DC API section
mentions issuance — but it is no longer true of the *platform*: Chrome 143
added `navigator.credentials.create()` as an issuance handoff channel, which is
additive to the transport layer rather than a protocol change. `/token` and
`/credential` behave identically regardless of which affordance handed the
offer to the wallet.

`openid4vci-v1` is a Chrome origin-trial protocol identifier with no pinned
specification in `docs/specs/`. This is a deliberate, documented departure
from root AGENTS.md §4.4 — recorded in the spec and in
`crates/foundry-issuer/AGENTS.md`'s Gotchas.

## Spec and plan

- `docs/superpowers/specs/2026-08-04-admin-console-dc-api-issuance-design.md`
- `docs/superpowers/plans/2026-08-04-admin-console-dc-api-issuance.md`

## Follow-ups (not in this change)

- `get_verification_handler` still returns its whole `VerificationTransaction`,
  `ephem_private_jwk` included, to any admin-key holder — a known wart
  predating this change, deliberately left alone here since narrowing it is a
  breaking change to an existing admin response shape with its own OpenAPI
  churn.
- Reconcile `build_dc_api_offer` against a pinned OpenID4VCI DC API profile if
  and when the OpenID Foundation publishes one, and add the spec file to the
  §4.4 table at that point.

## Verification

Scoped gate (root AGENTS.md §5.1), run per task boundary throughout implementation:

```
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings   (deferred; see note)
cargo fmt --check                                                        (deferred; see note)
```

Note: at the user's explicit direction during this session, the full
per-task `cargo clippy`/`cargo fmt --check` gate was deferred until all five
tasks were implemented rather than re-run after every task; targeted
`cargo test` runs (per new/changed test file) were used as the per-task
verification instead. `cargo test -p foundry-issuer -p foundry` was run in
full at least twice during implementation and passed. The deferred
`clippy`/`fmt --check` portion of the scoped gate, plus the one-time Full
Gate (root AGENTS.md §5.3) — including `cargo fmt`, `cargo test --workspace`,
and the ignored `e2e_full_flow` — are run once at the end of the branch per
`finishing-a-development-branch`, not repeated here.