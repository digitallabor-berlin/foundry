# EMVCo DPC Display Metadata on the Credential Offer and Credential Response

**Date:** 2026-08-13
**Branch:** `feat/emvco-dpc-display-metadata`
**Design:** [`docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md`](../specs/2026-08-13-emvco-dpc-display-metadata-design.md)
**Plan:** [`docs/superpowers/plans/2026-08-13-emvco-dpc-display-metadata-plan.md`](../plans/2026-08-13-emvco-dpc-display-metadata-plan.md)

## Why

foundry could issue a `com.emvco.dpc.card` SD-JWT VC but could convey nothing
about how the card should *look*. A wallet received three disclosable claims —
`credential_id`, `network`, `card_id` — and no card art, issuer branding,
last-four digits or human-readable alias. There was nothing to render.

The EMVCo Schema Framework addresses this with a **second** schema,
`com.emvco.dpc.card.meta`, deliberately outside the signed credential, and
proposes carrying it in a locale-keyed `display` array on the Credential Offer
(for consent) and the Credential Response (for rendering).

This closes open issue **2** of
[`2026-08-05-emvco-dpc-credential-type-design.md`](../specs/2026-08-05-emvco-dpc-credential-type-design.md)
§8, which excluded the work and recorded that it needed its own spec, plan and
review cycle. That §2.1 is now marked superseded rather than deleted: it records
*why* the split was right.

## What shipped

| Area | Change |
|---|---|
| `foundry-issuer/src/display_metadata.rs` | **New.** `DisplayStage` (`Offer` \| `CredentialResponse`) and `validate_display`, plus the private per-node validators |
| `foundry-issuer/src/offer.rs` | `CredentialOffer.display: Option<Vec<Value>>` |
| `foundry-issuer/src/credential.rs` | `CredentialResponse.display`, populated from the transaction |
| `foundry-issuer/src/transaction.rs` | `IssuanceTransaction.credential_response_display` |
| `foundry-issuer/src/create_offer.rs` | `offer_display` / `credential_response_display` request fields, the `DPC_VCT` gate, stage-specific validation, span presence fields |
| `foundry/assets/console.html` | Collapsed "DPC display metadata" disclosure with two empty JSON textareas |
| `openapi.json`, `openapi-wallet.json` | Regenerated — five new members, no other schema touched |

## The five design decisions

1. **Both stages, not just the offer.** Shipping only the offer half would give a
   wallet recognisable card art during consent and then lose it at the moment it
   stores the credential — the case the annex cares most about.
2. **Two request fields, not one.** Forced by the contradiction below: no single
   object can be both schema-valid and compliant with the offer-stage privacy
   guidance.
3. **Open-world validation, not a closed Rust model.** The governing document is
   a draft under Associate Review; a model pinned to it would make every
   revision a breaking change to foundry's admin API.
4. **Gated on the DPC `vct`.** Confines a non-OpenID4VCI member to the one
   credential type whose governing document asks for it, by construction rather
   than by operator discipline.
5. **Per-offer only.** A config-level default with per-offer override would
   require deciding merge semantics over a locale-keyed array of open-world
   objects — its own design, deferred until a deployment reports the repetition
   as a real cost.

## A third contradiction in the draft

The predecessor recorded two. This work found a third, now in the stub:

**The offer-stage guidance forbids `last_four`, the display-metadata schema
requires it, and the annex's own offer-stage example includes it.** All three
appear in A.5. No `card` object can satisfy all of them, so foundry validates
each protocol stage against the rule that applies to it — `last_four` and
`card_art` required on a Credential Response, optional on a Credential Offer.
This is the *whole reason* the admin API takes two display fields.

## Deviations, all deliberate and tested

| Deviation | From | Why |
|---|---|---|
| Unknown members accepted at every depth | A.5.1's `additionalProperties: false` | Draft instability; a closed world makes each revision a breaking API change. Pinned by `unknown_members_are_accepted_at_every_depth` |
| `last_four` / `card_art` required only on the response | A.5.1's unconditional `required` | The contradiction above. Pinned by `last_four_and_card_art_are_optional_at_the_offer_stage_only` |
| URI/email syntax unvalidated | `format` keywords | JSON Schema `format` is an annotation, not an assertion. Pinned by `uri_and_email_syntax_is_deliberately_not_validated` |
| A `display` member at all | OpenID4VCI 1.0 | The annex's non-normative proposal. Recorded in the conformance report's Audit Boundary, **not** the Gap Register — see below |

## Why this is not a Gap Register entry

The Gap Register is for *unmet* mandatory requirements. Its machinery requires
every entry to be cited by a clause with verdict `gap` and covered by an
`#[ignore]`d test, so that an open gap cannot appear to pass. An implemented,
tested, deliberate **extension** filed there would have required writing a
permanently-failing ignored test for working behaviour, corrupting the
register's meaning. It is recorded in the **Audit Boundary** instead, whose
stated purpose is that "silence is never mistaken for a pass".

## No behaviour change for anything else

Both wire members are `Option` with `skip_serializing_if`. A credential type
carrying no display metadata serialises to **exactly the bytes it did before** —
asserted on the serialised object's keys rather than a round-tripped `Option`,
because a `display: null` would pass the weaker check and still change every
wallet's input.

`IssuanceTransaction.credential_response_display` carries `#[serde(default)]`,
so KV rows written by a pre-upgrade binary still deserialize. The existing
pre-DPoP legacy-row test was extended rather than duplicated.

## Things found while implementing that the plan had wrong

1. **14 struct literals, not 9.** The plan's table missed `credential.rs`'s five
   `IssuanceTransaction` literals — the `rg` used to build it had been truncated.
   The compiler-driven sweep the plan mandated is what caught them.
2. **A near-miss the sweep would not have caught.** `authorize.rs` has an
   `AuthorizeParams` literal whose field list ends in `dpop_jkt: None` exactly
   like the transaction literals; a pattern-based edit would have inserted the
   new field into the wrong struct. Each site was verified before editing.
3. **15 `CreateOfferRequest` literals, not 13** — four live in
   `crates/foundry-issuer/tests/conformance_vci.rs`, an integration test the
   plan did not know existed.
4. **OpenAPI regeneration had to move from Task 6 to Task 3.** Tasks 2–3 change
   three schemas, so deferring it left `cargo test -p foundry` red across three
   tasks, which would have masked real failures.
5. **The planned redaction positive control asserts something that was never
   true.** It wanted the `create_offer` span's `offer_display_present` /
   `credential_response_display_present` fields to appear in the log. But
   `create_offer` emits no tracing event of its own, so nothing is recorded
   inside its span and none of its fields reach any log record — pre-existing,
   and equally true of `credential_type_id`, `tx_code_required` and
   `authorization_code_grant`. The fields remain correct per `AGENTS.md` §4.5
   (presence only, never contents); they are simply unobservable today. The
   control now asserts the capture window covered the request, which is what
   makes the negative assertions non-vacuous.
6. **The console's request object could not be called `body`.** The existing
   handler already binds `body` to the *response* in seven places. The plan
   proposed renaming all seven; naming the request `requestBody` was the smaller
   diff.

## A defect the spec review caught before any code was written

The design's first draft had both console textareas pre-filled with worked
examples. That would have broken the console's default flow outright: the
default `credential_type_id` is `pid`, and the `DPC_VCT` gate rejects display
metadata for any other type, so the out-of-the-box "Create Offer" click would
have returned `400`. The textareas ship empty with placeholders instead, and the
worked examples moved to `README.md`. Recorded in the design at §3.7 rather than
silently fixed, and the covering test asserts the *absence* of a pre-filled
value.

## Conformance

No clause verdict changed. The new `display` member is recorded as a deliberate
extension in the Audit Boundary of
[`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md).
`GAP-VCI-10` — the absence of structural validation on the *issuer metadata*
display arrays — is untouched; the per-locale uniqueness rule added here applies
only to the new fields.

## Open issues carried forward

1. **Config-level display defaults and merge semantics** — deferred, see design §4.
2. **`GAP-VCI-10`** — issuer-metadata display arrays remain unvalidated.
3. **URI/email syntax validation** of `website_url`, `image_url`,
   `support_email`.
4. **mdoc binding** — predecessor open issue 3, unchanged.
5. **DCQL / verifier configuration for DPC** — predecessor open issue 1,
   unchanged; display metadata is issuance-only.
6. **Whether any shipping wallet reads the member** — unverified. Google's
   profile does not mention it; the annex marks the transport non-normative.
7. **`create_offer`'s span fields are unobservable** — see finding 5. Emitting
   an event inside the span would fix it, but that is a production logging
   change outside this branch's approved scope.
