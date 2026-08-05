# EMV® Digital Payment Credential Specification — Schema Framework

**This file is a reference stub, not a copy of the specification.**

| | |
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

## What foundry does not implement

- The **display-metadata schema** (`com.emvco.dpc.card.meta`) and its `card`
  object. The specification *proposes* carrying it in a `display` array on the
  Credential Offer and the Credential Response; OpenID4VCI 1.0 defines no
  `display` member on either, and the data is per-credential-instance
  (`last_four`, `alias`, card art) whereas foundry's `display` is per-credential
  *type*.
- The **mdoc binding** (`docType` and namespace `com.emvco.dpc.card`).
- The **DCQL query patterns**, including whether a `values` filter matches an
  array-valued `network`.

See
[`docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md`](../superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md)
§2.1 and §8 for the full reasoning and what closing each would require.