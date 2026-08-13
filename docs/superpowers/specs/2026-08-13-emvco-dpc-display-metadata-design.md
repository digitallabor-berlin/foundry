# EMVCo DPC Display Metadata — Credential Offer and Credential Response

**Predecessor:** closes open issue **2** of
[`2026-08-05-emvco-dpc-credential-type-design.md`](2026-08-05-emvco-dpc-credential-type-design.md)
§8, which excluded display metadata from that branch and recorded that it "needs
its own spec, plan and review cycle". This is that cycle. The reasoning in that
document's §2.1 is the starting point, not something this design overturns — §2
below answers each of its three objections rather than ignoring them.

**Date:** 2026-08-13

**Governing document:** EMV® Digital Payment Credential Specification — Schema
Framework, v1.0 **DRAFT Associate Review 2**, Annex A.5 and A.5.1. Not present
in this repository; see
[`docs/specs/emvco-dpc-schema-framework.md`](../../specs/emvco-dpc-schema-framework.md)
and root `AGENTS.md` §4.4's external-reference rule. Every fact about the
document below is a **restatement** of interface information — member names,
JSON types, inclusion requirements — never a quotation.

---

## 1. Problem

foundry can issue a `com.emvco.dpc.card` SD-JWT VC, but it can convey nothing
about how the card should *look*. A wallet receiving the credential gets three
disclosable claims — `credential_id`, `network`, `card_id` — and no card art, no
issuer branding, no last-four digits, no human-readable alias. There is nothing
to render.

The specification addresses this with a **second schema**, `$id`
`com.emvco.dpc.card.meta`, which is deliberately *not* part of the signed
credential. It is presentation data: locale-aware, issuer-provided, and carried
alongside the credential rather than inside it. A.5's "Protocol Alignment"
subsection proposes transporting it inside a `display` array on two OpenID4VCI
structures — the Credential Offer (so the wallet can show a recognisable card
during consent) and the Credential Response (so the wallet can render the stored
credential immediately).

foundry currently emits neither.

### 1.1 What the schema requires

`com.emvco.dpc.card.meta` is an object whose only member is `card`, which is
required. Restated:

| Path | Type | Required |
| --- | --- | --- |
| `card` | object | yes |
| `card.last_four` | string, four ASCII digits | **yes** |
| `card.card_art` | array of `LogoImg`, at least one element | **yes** |
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

### 1.2 The transport proposal

Each entry of the proposed `display` array pairs a `locale` with a `card`
object, following the existing OpenID4VCI convention of a locale-keyed display
array. The same entry shape is proposed on the Credential Offer and on the
Credential Response. Both examples in that subsection are marked
**non-normative**.

### 1.3 The offer-stage contradiction

The specification states, in the same subsection, that the cardholder may not be
sufficiently authenticated at the point of the Credential Offer, and that
PII-type data — it names `last_four`, `alias` and personalised card art — should
not be included at that stage.

That is irreconcilable with A.5.1 three ways over:

1. The schema makes `card.last_four` and `card.card_art` **required**. A `card`
   object without them is schema-invalid.
2. The prose forbids exactly those members at the offer stage.
3. The non-normative offer example in that same subsection **includes**
   `last_four` and `alias`.

So the document forbids, requires, and demonstrates the same member at the same
protocol stage. No implementation can satisfy all three. This is recorded as the
**third** known contradiction in the spec stub, alongside the two the
predecessor design already found.

---

## 2. Answering the predecessor's objections

§2.1 of the predecessor gave three reasons to exclude this work. None has
dissolved; each is now answered by a design decision rather than by deferral.

**(a) "Neither structure has a `display` member, and OpenID4VCI 1.0 defines
none."** True, and unchanged. This design does extend two wire structures beyond
the pinned specification. Two things bound the damage. The member is
`Option`-typed with `skip_serializing_if`, so an offer that does not carry
display metadata serialises to **exactly the bytes it does today** — the
deviation is opt-in on the wire, not merely gated in code. And it is confined by
construction to the one credential type whose governing document asks for it
(§3.5), so foundry's EUDI/PID conformance surface is untouched. The deviation is
recorded in the conformance register and in the spec stub rather than left
implicit; that is what §4.4 requires of a deliberate divergence.

**(b) "The data is per-instance, foundry's `display` is per-type."** Correct, and
this is why the data does **not** go in issuer metadata. It is supplied
per-offer through the admin API and, for the response half, persisted on the
`IssuanceTransaction` next to `claims` — which is already per-instance data with
exactly this lifecycle. `CredentialType.display` is not touched.

**(c) "It is unstable."** The mitigation is §3.4's open-world validation: the
structural rules foundry enforces are the ones unlikely to move, and unknown
members are passed through rather than rejected. A closed Rust model pinned to
Associate Review 2 would turn every subsequent revision into a breaking change
to foundry's admin API. Deliberately diverging from `additionalProperties:
false` is the cheaper error.

---

## 3. Design

### 3.1 Wire model

`CredentialOffer` (`foundry-issuer/src/offer.rs`) and `CredentialResponse`
(`foundry-issuer/src/credential.rs`) each gain:

```rust
/// EMVCo DPC Schema Framework A.5 "Protocol Alignment" — the non-normative
/// proposal to carry a `com.emvco.dpc.card.meta` `card` object inside a
/// locale-keyed `display` array. OpenID4VCI 1.0 defines no `display` member on
/// this structure; see docs/specs/emvco-dpc-schema-framework.md and
/// docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md.
#[serde(skip_serializing_if = "Option::is_none", default)]
pub display: Option<Vec<serde_json::Value>>,
```

`skip_serializing_if` is load-bearing, not cosmetic: it is what makes every
existing offer and credential response byte-identical to today's output. A test
asserts the absence of the key, not merely a `null` value (§6).

The Digital Credentials API transport needs **no** change.
`build_dc_api_offer` (`offer.rs`) constructs its payload by
`serde_json::to_value(offer)` rather than hand-building the object — a decision
its own comment justifies as drift-avoidance — so the new member is inherited
automatically and the deep-link and DC API transports cannot disagree.

### 3.2 Persistence

`IssuanceTransaction` (`foundry-issuer/src/transaction.rs`) gains **one** field:

```rust
#[serde(default)]
pub credential_response_display: Option<Vec<serde_json::Value>>,
```

Only the response-stage object needs to survive offer creation; the offer-stage
object is consumed while building the `CredentialOffer` and never read again.

`#[serde(default)]` is mandatory. Transactions are persisted as JSON in the KV
store, so a row written before this field existed must still deserialize after a
rolling restart — the same constraint already documented on `dpop_jkt`, and a
test covers it directly.

### 3.3 Admin API

`CreateOfferRequest` (`foundry-issuer/src/create_offer.rs`) gains two
independent optional fields:

```rust
#[serde(default)]
pub offer_display: Option<Vec<serde_json::Value>>,
#[serde(default)]
pub credential_response_display: Option<Vec<serde_json::Value>>,
```

**Why two and not one.** Because of §1.3. A single field cannot express the
compliant configuration: any object rich enough to satisfy A.5.1 at the response
stage carries members the prose forbids at the offer stage. Two fields let an
operator put card art and network branding on the offer and add `last_four` and
`alias` only on the response.

**Why foundry does not derive one from the other.** The obvious alternative —
accept one object and strip PII automatically before putting it on the offer —
was rejected. "Personalised card art" is not machine-decidable: a card-art URL
is a string, and nothing distinguishes a generic product image from one
rendered for this cardholder. Silently mutating operator-supplied data to
produce a plausible-looking result is precisely what §4.4's "prefer a typed
unsupported error over a non-conformant response" exists to prevent. The
operator makes the privacy decision; foundry validates and transmits it.

### 3.4 Validation

New module `foundry-issuer/src/display_metadata.rs`:

```rust
pub enum DisplayStage {
    Offer,
    CredentialResponse,
}

pub fn validate_display(
    display: &[serde_json::Value],
    stage: DisplayStage,
) -> Result<(), IssuanceError>;
```

Every failure is `IssuanceError::InvalidRequest` carrying a message that names
the offending JSON path (e.g. `display[0].card.card_art[1].theme`) so an
operator can fix the input without guessing. No `unwrap`, `expect`, `panic!` or
`unreachable!` anywhere in the module's non-test code (§4.1).

**Enforced:**

- the array is non-empty, and every entry is an object carrying a `card` object
- **at most one entry per `locale`**; entries with no `locale` collapse to a
  single distinct key, so two locale-less entries are also a rejection
- `card.last_four`, when present, is exactly four ASCII digits
- `card.card_art`, when present, is a non-empty array, and each element carries
  `theme` ∈ {`DEFAULT`, `LIGHT`, `DARK`} and a string `image_url`
- `card.type.code`, when `type` is present, ∈ {`CREDIT`, `DEBIT`, `PREPAID`}
- `card.issuer.country`, when present, is exactly two ASCII uppercase letters
- every `Branding` — `card.issuer.branding`, `card.co_branding`, and each
  `card.network_branding[].branding` — carries a non-empty string `name`, and a
  `logo`, when present, is a non-empty array of valid `LogoImg`
- `card.issuer.branding` is required when `card.issuer` is present; `network`
  and `branding` are both required in every `card.network_branding` element

**Stage-dependent:** `card.last_four` and `card.card_art` are **required at
`CredentialResponse`** and **optional at `Offer`**.

**Not enforced, deliberately:**

- **Unknown members, at any depth.** The schema declares
  `additionalProperties: false`; foundry accepts extras. Rationale in §2(c).
- **`website_url` / `image_url` URI syntax and `support_email` email syntax.**
  The schema's `format` keywords are annotations, not assertions, and adding a
  URI/email validator here would be a new dependency enforcing a rule the
  document itself does not assert. Type (`string`) is checked; syntax is not.

Both `format`-related omissions and the `additionalProperties` divergence are
recorded in the spec stub, so a reader can distinguish a deliberate choice from
an oversight.

**Pattern checks are hand-rolled.** The workspace has no `regex` dependency and
this design does not introduce one: "four ASCII digits" and "two ASCII uppercase
letters" are three-line predicates.

### 3.5 Gating

`create_offer` rejects display metadata for any credential type other than the
DPC one:

```rust
/// The canonical DPC credential type identifier. Behaviour keyed on this
/// constant is justified only by the EMVCo Schema Framework — an
/// external-reference document, not a standards-track specification (root
/// AGENTS.md §4.4). Confining it to this one `vct` is what keeps a
/// non-OpenID4VCI `display` member off every other credential type's offer.
const DPC_VCT: &str = "com.emvco.dpc.card";
```

If either display field is `Some` and the resolved `CredentialType`'s `vct` is
not `DPC_VCT`, the result is `IssuanceError::InvalidRequest`. This check runs
after credential-type resolution and before any state is mutated — no status
index is allocated and no transaction is written for a rejected request.

The mdoc binding is out of scope (it is unimplemented; see the stub), so the
gate keys on `vct` only and does not consult `doctype`.

### 3.6 Flow

Offer creation, in `create_offer`:

1. resolve the credential type (existing)
2. **gate** — reject display for a non-DPC type (§3.5)
3. **validate** `offer_display` with `DisplayStage::Offer` and
   `credential_response_display` with `DisplayStage::CredentialResponse`
4. required-claim validation, status-index allocation (existing)
5. persist the transaction, now carrying `credential_response_display`
6. build the `CredentialOffer` with `display: offer_display`
7. derive `credential_offer_uri` and `dc_api_offer` from it (existing;
   both inherit `display`)

Issuance, in `credential.rs`: the `CredentialResponse` is constructed with
`display: tx.credential_response_display.clone()`. Validation is **not**
repeated there — the value was validated at the admin boundary and has been
inert in storage since. Re-validating would mean a stored-object defect
surfaces as a wallet-facing `/credential` failure rather than as an admin-facing
rejection, which inverts where the error belongs.

When the wallet requested Credential Response encryption, the display object is
inside the encrypted payload like every other member; no special handling.

### 3.7 Admin console

`crates/foundry/assets/console.html`, Issuance card, below `claims (JSON)`: a
`<details>` group labelled for DPC display metadata, **collapsed by default** so
the PID flow's UI is visually unchanged.

Two textareas, `offer_display (JSON, optional)` and
`credential_response_display (JSON, optional)`, each pre-filled with a worked
example. The offer example is deliberately **non-PII** — `type`, `card_art` and
`network_branding`, with no `last_four` and no `alias` — so the shipped default
demonstrates the privacy posture of §1.3 rather than the schema's `required`
list. The response example is the full object.

A blank textarea omits the field from the request body entirely; it does not
send `null` or `[]`. Parse failures surface through the same `showError` path
`claims` already uses, with the field name in the message.

### 3.8 Observability

Per §4.5. `create_offer`'s `#[tracing::instrument]` already carries `skip_all`;
its `fields(...)` list gains `offer_display_present` and
`credential_response_display_present`, both `bool`. Nothing else about the
objects is recorded at any level under any flag.

The display objects join the never-logged list in root `AGENTS.md` §4.5: they
carry `card.last_four`, a cardholder-recognisable `alias`, and card-art URLs
that may be personalised. `crates/foundry/tests/logging_redaction.rs` gains a
case asserting a distinctive `last_four` value never appears in captured log
output, alongside the existing positive control.

---

## 4. What this design does not do

- **No issuer-metadata change.** `CredentialType.display` and the
  `credential_configurations_supported` display arrays are untouched.
  `GAP-VCI-10` — the absence of structural validation on those arrays — is not
  closed by this work. The per-locale uniqueness rule of §3.4 applies to the new
  fields only.
- **No config-level display defaults.** The constant half of the object
  (`issuer.branding`, `co_branding`, `network_branding`) is re-sent on every
  offer. A config default with per-offer override would require deciding
  merge semantics over a locale-keyed array of open-world objects — deep merge,
  whole-array replace, or per-locale merge — which is its own design. Deferred
  until a deployment reports the repetition as a real cost. The console template
  of §3.7 is the interim ergonomic answer.
- **No display metadata on any other credential type**, by construction (§3.5).
- **No mdoc binding**, unchanged from the predecessor's open issue 3.
- **No verifier-side use.** Display metadata is issuance-only; nothing in
  `foundry-verifier` reads it.
- **No URI or email syntax validation** (§3.4).

---

## 5. Files touched

| File | Change |
| --- | --- |
| `crates/foundry-issuer/src/display_metadata.rs` | **new** — `DisplayStage`, `validate_display` |
| `crates/foundry-issuer/src/lib.rs` | declare and re-export the module |
| `crates/foundry-issuer/src/offer.rs` | `CredentialOffer.display` |
| `crates/foundry-issuer/src/credential.rs` | `CredentialResponse.display`; populate from the transaction |
| `crates/foundry-issuer/src/transaction.rs` | `IssuanceTransaction.credential_response_display` |
| `crates/foundry-issuer/src/create_offer.rs` | two request fields, `DPC_VCT` gate, validation calls, span fields, transaction construction |
| `crates/foundry/assets/console.html` | collapsed display-metadata field group + request wiring |
| `openapi.json`, `openapi-wallet.json` | regenerated |
| `crates/foundry/tests/logging_redaction.rs` | `last_four` redaction case |
| `docs/specs/emvco-dpc-schema-framework.md` | implemented/not-implemented move; third contradiction; deviations |
| `docs/conformance/openid4vc-conformance.md` | rows for the non-standard `display` member |
| `docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md` | §8 item 2 marked closed, pointing here |
| `AGENTS.md` | §4.5 never-logged list |
| `crates/foundry-issuer/AGENTS.md` | module map + gotcha for the deviation |
| `README.md` | two places, both confirmed present: the `POST /admin/issuance/offers` `curl` example under "Creating an Offer via Admin API", and the "Issuance" bullet of the Admin Test Console section |

`crates/foundry/src/openapi.rs` is deliberately **not** in that list.
`CreateOfferRequest`, `CredentialOffer` and `CredentialResponse` are already
registered in its `components(schemas(...))`, and `DisplayStage` /
`validate_display` are not wire types, so nothing needs registering. The utoipa
work is field-level instead: each new field carries a
`#[schema(value_type = ...)]` annotation in the module that declares it — the
same accommodation `CreateOfferResponse.dc_api_offer` already uses for a
`serde_json::Value`.

Every touched crate stays within the §3 layering: `foundry-issuer` gains no new
dependency, and nothing is added to `foundry-core`.

---

## 6. Testing

**`foundry-issuer` unit tests.**

- `validate_display` accept/reject matrix: a minimal valid object at each stage;
  `last_four` and `card_art` omitted — accepted at `Offer`, rejected at
  `CredentialResponse`; `last_four` of wrong length and with a non-digit; empty
  `card_art`; bad `theme`; bad `type.code`; bad `issuer.country`; empty
  `Branding.name`; `network_branding` element missing `network`; duplicate
  `locale`; two locale-less entries; empty array; entry with no `card`.
- Unknown members at three depths are **accepted** — this pins the deliberate
  divergence from `additionalProperties: false`, so a later revision that
  reinstates strictness is a visible test change rather than a silent one.
- Gating: display supplied for a non-DPC credential type is `InvalidRequest`,
  and no transaction is persisted as a side effect.
- **No-regression:** an offer created without display serialises with **no
  `display` key present** — asserted on the serialised JSON object's keys, not
  on a deserialized `Option`, since a `null` would pass the weaker check.
- The same assertion for `dc_api_offer`, and its converse: when display *is*
  supplied, `dc_api_offer` carries it, proving the two transports agree.
- Transaction round-trip of `credential_response_display`.
- A persisted transaction JSON literal **without** the new field deserializes
  successfully with `None`.
- `/credential` echoes the stored object; a transaction with `None` produces a
  response with no `display` key.

**`foundry` integration.** One flow test: create a DPC offer carrying both
display fields, redeem it through `/token` and `/credential`, and assert the
offer carries the offer-stage object and the credential response carries the
response-stage object.

**Gate.** Scoped, per root `AGENTS.md` §5.1: `cargo test -p foundry-issuer -p
foundry`, `cargo clippy -p foundry-issuer -p foundry --all-targets -- -D
warnings`, `cargo fmt --check`. `foundry` is the affected dependent per §5.2.
The full gate of §5.3 runs **once**, at the end of the branch.

---

## 7. Risks

**The draft moves.** Associate Review 3 may rename members, change the
transport, or drop the `display`-array proposal entirely. Mitigated by
open-world validation (§3.4) and by the deviation being opt-in on the wire
(§3.1) — a revision that removes the proposal costs foundry the removal of one
optional field, not a migration.

**The transport is non-normative even within the draft.** A wallet has no
obligation to read a `display` member on either structure, and Google's profile
does not mention one. The feature's value is contingent on a wallet choosing to
honour it. This is accepted: the alternative is conveying no presentation data
at all.

**An operator puts PII on the offer.** foundry validates structure, not
appropriateness, and will transmit a `last_four` on an offer if asked (§3.3).
The console's shipped default demonstrates the safe shape, and the spec stub
records the prose guidance, but the choice is the operator's. Enforcing it would
require rejecting `last_four` at the offer stage outright — which the
specification's own non-normative example would then fail.

---

## 8. Open issues left after this branch

1. **Config-level display defaults and merge semantics** — §4.
2. **`GAP-VCI-10`** — structural validation of the *issuer metadata* display
   arrays remains open; this work does not touch them.
3. **URI/email syntax validation** of `website_url`, `image_url` and
   `support_email` — §3.4.
4. **mdoc binding** — the predecessor's open issue 3, unchanged.
5. **DCQL / verifier configuration for DPC** — the predecessor's open issue 1,
   unchanged; display metadata is issuance-only and does not touch it.
6. **Whether any shipping wallet reads the member** — unverified; see §7.
