# EMV® Digital Payment Credential Specification — Schema Framework

**This file is a reference stub, not a copy of the specification.**

|---|---|
|---|---|
| Document | EMV® Digital Payment Credential Specification — Schema Framework |
| Version | v1.0 |
| Revision implemented against | **DRAFT — Associate Review 2**, dated 8 May 2026 |
| Publisher | EMVCo, LLC |
| Obtain from | <https://www.emvco.com> — EMVCo publishes its specifications there; draft review copies are distributed to Associates under the applicable EMVCo agreement |

## Why no verbatim copy is in this directory

Every other file in `docs/specs/` is an IETF or OpenID Foundation text that
carries redistribution permission. This one does not. Its legal notice states:

> © 2026 EMVCo, LLC. All rights reserved. Reproduction, distribution and other
> use of this document is permitted only pursuant to the applicable agreement
> between the user and EMVCo.

It is additionally an unpublished draft. This repository is Apache-2.0 licensed,
so committing the document would purport to convey redistribution rights the
project does not hold. **A reader verifying foundry's behaviour against this
specification must obtain their own copy.**

## What foundry implements from it

Only the SD-JWT VC binding of the DPC **card** credential. The facts below are
interface information — claim names, JSON types and inclusion requirements —
restated rather than quoted.

**Canonical credential type identifier:** `com.emvco.dpc.card`. The
specification uses this single string as the logical credential type, the SD-JWT
`vct`, the mdoc `docType`, the mdoc namespace, and the payload schema `$id`.

**Credential meta-attributes → SD-JWT claims**

| Meta-attribute | Claim | Type |
|---|---|---|
| Credential Type | `vct` | string, constant `com.emvco.dpc.card` |
| Credential Issuer | `iss` | string (URI) |
| User Binding Key | `cnf` | object carrying a `jwk` |
| Issuance Time | `iat` | number (Unix time) |
| Expiration Time | `exp` | number (Unix time) |

**Disclosable attributes**

| Claim | Type | Required |
|---|---|---|
| `credential_id` | string | yes |
| `network` | string, or array of string (co-badged cards) | yes |
| `card_id` | string | no |

The payload schema declares `additionalProperties: false` and requires `vct`,
`iss`, `cnf`, `credential_id` and `network`. All three disclosable attributes are
top-level: **the credential has no nested claims**, so foundry's top-level-only
claim addressing is sufficient for it.

The shipped configuration is in `QUICKSTART_CONFIG`
(`crates/foundry/src/commands.rs`); its shape is pinned by
`crates/foundry/tests/quickstart_config.rs`.

### Display metadata (`com.emvco.dpc.card.meta`)

Also implemented, since 2026-08-13. This is the annex's **second** schema and is
deliberately *not* part of the signed credential: it is presentation data,
carried alongside the credential. The annex proposes transporting it inside a
locale-keyed `display` array on the Credential Offer and on the Credential
Response, and marks both of its examples non-normative.

The facts below are interface information — member names, JSON types and
inclusion requirements — restated rather than quoted.

| Path | Type | Required |
|---|---|---|
| `card` | object | yes |
| `card.last_four` | string, four ASCII digits | yes (see contradiction 3) |
| `card.card_art` | array of `LogoImg`, at least one element | yes (see contradiction 3) |
| `card.type` | object | no |
| `card.type.code` | string, one of `CREDIT`, `DEBIT`, `PREPAID` | yes, within `type` |
| `card.type.label` | string | no |
| `card.alias` | string | no |
| `card.issuer` | object | no |
| `card.issuer.branding` | `Branding` | yes, within `issuer` |
| `card.issuer.country` | string, two ASCII uppercase letters | no |
| `card.issuer.website_url` | string, URI | no |
| `card.issuer.support_email` | string, email | no |
| `card.issuer.support_phone` | string | no |
| `card.co_branding` | `Branding` | no |
| `card.network_branding` | array of objects | no |
| `card.network_branding[].network` | string | yes, within the element |
| `card.network_branding[].branding` | `Branding` | yes, within the element |

`LogoImg` is `{ theme, image_url }`, both required; `theme` is one of `DEFAULT`,
`LIGHT`, `DARK`; `image_url` is a URI which may be a data URL. `Branding` is
`{ name, logo? }` where `name` is a non-empty string and `logo`, when present,
is a non-empty array of `LogoImg`. Every object in the schema declares
`additionalProperties: false`.

Validation lives in `crates/foundry-issuer/src/display_metadata.rs`; the objects
are supplied per-offer through `POST /admin/issuance/offers`
(`offer_display`, `credential_response_display`) and are accepted **only** for a
credential type whose `vct` is `com.emvco.dpc.card`. Design:
[`docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md`](../superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md).

#### foundry's deviations from A.5.1

All three are deliberate and tested, so that a reader can tell them from defects:

1. **Unknown members are accepted at every depth**, though every object in the
   schema declares `additionalProperties: false`. This is a draft under
   Associate Review; a closed model would make each revision a breaking change
   to foundry's admin API. Pinned by
   `unknown_members_are_accepted_at_every_depth`.
2. **`last_four` and `card_art` are required only on the Credential Response.**
   See contradiction 3 below — the two rules cannot both be satisfied, so each
   protocol stage is validated against the rule that applies to it. Pinned by
   `last_four_and_card_art_are_optional_at_the_offer_stage_only`.
3. **`format` keywords are not enforced.** `website_url`, `image_url` and
   `support_email` are checked to be strings; their URI/email *syntax* is not
   validated, because JSON Schema `format` is an annotation rather than an
   assertion. Pinned by `uri_and_email_syntax_is_deliberately_not_validated`.

A fourth deviation is from OpenID4VCI rather than from EMVCo: **`display` is not
a member OpenID4VCI 1.0 defines on either a Credential Offer or a Credential
Response.** foundry emits it anyway, per this annex's proposal, but only for the
`com.emvco.dpc.card` `vct` and only when an operator supplies it — both members
are `Option` with `skip_serializing_if`, so every other credential type's wire
output is unchanged byte-for-byte.

## Known contradictions in the reviewed draft

Recorded so that a later review round can be checked against them, and so that
foundry's deviations are not mistaken for defects:

1. **The payload schema forbids additional properties, yet the specification's
   own sample credentials carry `_sd` and `_sd_alg`.** No real SD-JWT can
   satisfy the schema as literally written, so it is read as describing the
   known claim *vocabulary* rather than a closed world.
2. **The security section requires implementers to "implement status check
   mechanisms", but the payload schema has no room for a `status` claim.**
   foundry keeps Token Status List support enabled and accepts the resulting
   extra claim; dropping a working revocation mechanism to satisfy a schema that
   the same document's security section contradicts would be the wrong trade.
3. **The offer-stage guidance forbids `last_four`, the display-metadata schema
   requires it, and the annex's own offer-stage example includes it.** All three
   appear in A.5. No `card` object can be simultaneously schema-valid and
   compliant with the offer-stage guidance, so foundry validates each protocol
   stage against the rule that applies to it: `last_four` and `card_art` are
   required on a Credential Response and optional on a Credential Offer. This is
   why the admin API takes **two** display fields rather than one — a single
   field cannot express the compliant configuration.

## What foundry does not implement

- The **mdoc binding** (`docType` and namespace `com.emvco.dpc.card`).
- The **DCQL query patterns**, including whether a `values` filter matches an
  array-valued `network`.

See
[`docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md`](../superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md)
§8 for the full reasoning and what closing each would require. That document's
§2.1 also argued for excluding **display metadata**; it is superseded — the work
was done on 2026-08-13, and each of its three objections is answered in §2 of
[`2026-08-13-emvco-dpc-display-metadata-design.md`](../superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md).
