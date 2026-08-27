# Credential Types & Claim Configuration

Each entry under `credential_types` defines one Credential Configuration. Beyond
`id`, `format`, `vct`/`doctype`, `scope` and `display`, two keys control claim
handling and credential lifetime.

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `validity_seconds` | no | `31536000` (365 days) | Credential lifetime in seconds. The issued credential's `exp` is its `iat` plus this value — for SD-JWT VC, and for the mdoc MSO's `validUntil`. Must be non-zero: a credential whose `exp` equals its `iat` is rejected at startup. |
| `claims[].required` | no | `!selectively_disclosable` | Whether an offer must supply a value for this claim. Omit it to keep the historical rule — non-disclosable claims mandatory, disclosable ones optional. Set it explicitly for a claim that is **both** mandatory and selectively disclosable. |

`required` exists because "mandatory" and "selectively disclosable" are different
properties. A credential schema can require a claim to be present while the
SD-JWT still discloses it selectively; before this key existed such a claim was
never validated, and an offer omitting it issued an incomplete credential.

A claim's `path` must be a non-empty array — an empty path addresses nothing, so
no supplied value could satisfy it, and it is rejected at startup.

Note that issued credentials do **not** carry a `sub` claim. A per-transaction
`sub` is a static, always-disclosed identifier that rides along in every
presentation, and nothing consumes it; it is omitted deliberately.

## The three shipped credential types

`foundry quickstart` generates all three:

- **`pid`** — a Person ID with `given_name` and `birthdate`, both selectively
  disclosable, on the default 365-day lifetime.
- **`com.emvco.dpc.card`** — an EMVCo Digital Payment Credential: `credential_id`
  and `network` (mandatory *and* selectively disclosable), plus an optional
  `card_id`, on a 12-hour lifetime, with display metadata in three locales.
  `network` may be a single string or an array of strings for co-badged cards.
  Its `vct` is a reverse-DNS identifier rather than a URL.
- **`eu.europa.ec.av.1`** — the EUDI Proof of Age attestation, and the only
  `mso_mdoc` type foundry ships: a mandatory `age_over_18` plus an optional
  `age_over_16`, both booleans, on a 90-day lifetime. Its attribute set is
  fixed by the profile rather than by preference — see below.

The DPC credential's shape is governed by the EMV® Digital Payment Credential
Specification — Schema Framework, which is **not** vendored into this repository
because it is all-rights-reserved and unpublished. See
[`docs/specs/emvco-dpc-schema-framework.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/emvco-dpc-schema-framework.md)
for the reference, the claim set foundry relies on, and what parts of that
specification are deliberately not implemented.

An `mso_mdoc` credential type is identified by **`doctype`**, and must not set
`vct`: that is an SD-JWT-VC identifier with no meaning for an mdoc, and a type
carrying both is rejected at startup (OpenID4VCI's mdoc Format Profile,
L2235). There is no `namespace` key — the namespace an mdoc's data elements
belong to is derived from the doctype, because the mapping is a property of the
credential type rather than a deployment choice: ISO mDL carries its elements
in `org.iso.18013.5.1` under doctype `org.iso.18013.5.1.mDL`, while every EUDI
attestation uses its doctype verbatim.

The Proof of Age credential's shape is governed by the EU Age Verification
Solution Technical Specification, Annex A, which **is** vendored here — it is
CC BY 4.0, so redistribution with attribution is permitted. Annex A §4.1.2
defines exactly two attributes and then closes the set: a Proof of Age
Attestation SHALL NOT include any other attribute. foundry enforces that at
config load, so adding an `issue_date` or an `issuing_country` to this type is
a startup failure rather than a silently non-conformant credential. See
[`docs/specs/eu-age-verification-annex-a-av-profile.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/eu-age-verification-annex-a-av-profile.md).

---
