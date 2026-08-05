# EMVCo Digital Payment Credential — Credential-Type Shape

**Roadmap item:** Google Wallet compatibility, item **E** — the last of the A–E
decomposition recorded in
[`2026-08-04-dpop-nonce-freshness-endpoints-design.md`](2026-08-04-dpop-nonce-freshness-endpoints-design.md)
§10. Items A–D are merged.

**Date:** 2026-08-05

---

## 1. Problem

The Google Wallet vendor profile
([`docs/specs/google-wallet-openid4vci-profile.md`](../../specs/google-wallet-openid4vci-profile.md))
names exactly one credential type in its "VCI Issuance" table:

> DPC Type | SD-JWT, VCT = `com.emvco.dpc.card`

That identifier is defined by the *EMV® Digital Payment Credential
Specification — Schema Framework*, which was not available to this repository
when items A–D were designed. Item E was therefore recorded as "the
credential-type shape" with no further detail, and the assumption carried in the
earlier design docs was that it would be substantial work.

With the specification now in hand, that assumption is **wrong in both
directions**:

- The credential is far smaller than expected — three disclosable claims, all
  top-level, no nesting. foundry's existing `ClaimDef.path: Vec<String>` with
  top-level-only semantics is sufficient. The nested-selective-disclosure work
  that looked like item E's core is not needed.
- But foundry cannot issue a schema-valid DPC credential today, for three
  reasons that have nothing to do with EMVCo and everything to do with
  pre-existing gaps in foundry's own SD-JWT VC issuance path.

### 1.1 What the specification requires

Annex A.2.3 / A.3.1 define the SD-JWT binding. Restated (see §5 on why this is a
restatement rather than a quotation):

| Claim | JSON type | Required | Disclosable |
|---|---|---|---|
| `credential_id` | `string` | yes | yes |
| `network` | `string` **or** `array of string` | yes | yes |
| `card_id` | `string` | no | yes |

Credential meta-attributes map to `vct` (constant `com.emvco.dpc.card`), `iss`,
`cnf` (holder JWK), `iat` and `exp`. The payload schema declares
`additionalProperties: false` with `required: ["vct", "iss", "cnf",
"credential_id", "network"]`.

Both of the specification's own sample credentials place all three disclosable
claims — including the two schema-**required** ones — inside `_sd`.

### 1.2 The three gaps this exposes

**(a) `sub` is emitted unconditionally and is not in the schema.**
`crates/foundry-issuer/src/credential.rs:398` synthesises
`sub: format!("sub_{}", tx.transaction_id)`, and
`crates/foundry-sd-jwt-vc/src/builder.rs:11` types the field `sub: String` —
required, not optional. The DPC schema lists no `sub` and forbids additional
properties; neither sample payload carries one.

This is not merely a schema-compliance issue. `sub_<transaction_id>` is a
**unique, static, always-disclosed identifier present in every credential
foundry issues.** It is never selectively disclosable, so it rides along in
every presentation to every verifier, for the life of the credential. That is
the correlation handle the DPC specification's §6 explicitly warns against
("Correlation Risk: Avoid over-disclosure of static identifiers"), and it is a
privacy defect independent of EMVCo.

It also carries no function. Nothing in foundry reads it: `verify_sd_jwt_vc`
never inspects `sub`, and no clause in
[`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md)
depends on it — every `sub` row in that report concerns a *different* JWT
(signed issuer metadata VCI-0124, Verifier Attestation VP-0055/VP-0163, Wallet
Attestation HAIP-0035, and the Status List Token's own `sub`). SD-JWT VC format
internals are explicitly out of the conformance audit boundary because the IETF
defining spec is not vendored under root `AGENTS.md` §4.4, so no pinned text
makes `sub` mandatory either.

**(b) "required" and "selectively disclosable" are conflated.**
`crates/foundry-issuer/src/create_offer.rs:84-100` validates claim presence like
this:

```rust
for claim_def in &ct.claims {
    if claim_def.selectively_disclosable {
        continue;
    }
    // ... require the top-level path segment to be present in req.claims
}
```

Presence is enforced only for claims that are *not* selectively disclosable. The
DPC shape needs `credential_id` and `network` to be **both** required and
selectively disclosable — a combination foundry's configuration cannot express
and its validation cannot enforce. Today an offer omitting `credential_id` is
accepted and issues a schema-invalid credential. This is the one genuine defect
of the three.

**(c) `exp` is hardcoded.** `credential.rs:400` sets
`exp: now_unix + 86400 * 365` for every credential type. The DPC sample shows a
validity window of roughly twelve hours, and §5.2 of the specification is
explicit that credential expiry is an independent lifecycle concern. There is no
configuration knob.

---

## 2. Scope

**In scope.** Three generic code changes to close 1.2(a)–(c), the DPC credential
type expressed purely as configuration, tests, and documentation.

**None of the code changes mentions EMVCo, DPC, or Google.** Each closes a gap
in foundry's general SD-JWT VC issuance that any ecosystem would hit; the DPC
credential merely happens to be the first configured type that exposes all
three. The EMVCo-specific knowledge lives entirely in configuration and in
documentation.

**Out of scope**, each recorded in §8 rather than silently dropped:

- **Verifier / DCQL** — a `com.emvco.dpc.card` named-query fixture, and the
  question of whether a DCQL `values` filter matches an array-valued `network`.
- **Display metadata** — the specification's second schema
  (`com.emvco.dpc.card.meta`) and its `card` object on the Credential Offer and
  Credential Response.
- **mdoc binding** — `docType` and namespace `com.emvco.dpc.card`. EMVCo defines
  it; the Google profile does not ask for it.

### 2.1 Why display metadata is excluded

This is the largest piece of the specification and the most tempting to fold in,
so the reasoning is recorded explicitly.

Annex A.5's "Protocol Alignment" section **proposes** carrying a `card` object
inside a `display` array on both the Credential Response (post-issuance) and the
Credential Offer (pre-issuance), and marks its examples non-normative. Three
things follow:

1. **Neither structure has a `display` member, and OpenID4VCI 1.0 defines
   none.** `CredentialResponse` (`credential.rs:127`) is
   `{ credentials, notification_id }`; `CredentialOffer` (`offer.rs:28`) is
   `{ credential_issuer, credential_configuration_ids, grants }`. Implementing
   this means extending two wire structures beyond the pinned specification on
   the strength of a vendor-adjacent proposal — precisely the situation root
   `AGENTS.md` §4.4's vendor-profile rule constrains.
2. **The data is per-instance, foundry's `display` is per-type.** The metadata
   schema marks `card.last_four` and `card.card_art` as required. `last_four` is
   this holder's card; `CredentialType.display` appears once in issuer metadata,
   identical for every holder. A schema-valid `card` object therefore *cannot*
   live in issuer metadata — which is exactly why EMVCo puts it on the offer and
   the response instead. Supporting it properly means plumbing per-instance
   display data through the offer admin API, the `IssuanceTransaction`, and the
   credential response.
3. **It is unstable.** A non-normative proposal inside a draft under Associate
   Review is the least safe thing in the document to build against.

It needs its own spec, plan and review cycle.

---

## 3. Design

### 3.1 `foundry-sd-jwt-vc` — optional `sub`

`IssuerClaims.sub` becomes `Option<String>`, and `build_sd_jwt_vc` inserts the
`sub` payload key only when it is `Some`.

This is the only change in this branch that alters foundry's existing output:
every credential type, `pid` included, stops carrying `sub`. That is intended,
per the reasoning in §1.2(a) — the claim is a gratuitous correlation identifier
with no reader. The `Option` is retained rather than removing the field outright
so that a deployment with a genuine need can still set one, and so the builder
remains a general SD-JWT VC library rather than one with a policy baked in.

### 3.2 `foundry-core` — two additive configuration fields

Both follow the precedent already set by `CredentialType::resolved_scope()` in
`config/model.rs`: an `Option` field plus a resolver method, so an omitted value
reproduces today's behaviour exactly and the default lives in one place.

```rust
// ClaimDef
pub required: Option<bool>,

/// Whether a value for this claim must be supplied when an offer is created.
///
/// Absent resolves to `!selectively_disclosable`, which is exactly the rule
/// `create_offer` applied before this field existed: non-disclosable claims
/// were implicitly mandatory, disclosable ones implicitly optional. Setting it
/// explicitly decouples the two, which the EMVCo DPC shape requires — its
/// `credential_id` and `network` are both mandatory and selectively
/// disclosable.
pub fn is_required(&self) -> bool {
    self.required.unwrap_or(!self.selectively_disclosable)
}

// CredentialType
pub validity_seconds: Option<u64>,

/// Credential lifetime. Absent resolves to 365 days, the value
/// `handle_credential_request` hardcoded before this field existed.
pub fn resolved_validity_seconds(&self) -> u64 {
    self.validity_seconds.unwrap_or(31_536_000)
}
```

The `Option<bool>` on `required` is load-bearing, not stylistic. A plain `bool`
defaulting to `false` would silently stop enforcing today's non-disclosable
claims; defaulting to `true` would make `pid`'s disclosable `given_name` and
`birthdate` abruptly mandatory and break the shipped configuration. Only a
three-state field can express "unspecified, so keep the historical rule".

### 3.3 `foundry-core` — validation

`Config::validate()` gains two rejections:

- `validity_seconds: Some(0)` — a credential whose `exp` equals its `iat` is a
  configuration error, not a policy.
- `path: []` — an empty claims path pointer. This is currently caught only at
  offer time, per request, by `create_offer`'s own
  `IssuanceError::ClaimValidation`. Moving it to startup is worth doing here
  because §3.2's `required` flag makes an empty path newly consequential: a
  claim marked `required: true` with no path can never be satisfied.

The second rejection closes **half** of `GAP-VCI-13`, whose register entry cites
both the emptiness problem and the separate fact that `Vec<String>` cannot
represent the `null` and integer path segments the OpenID4VCI claims path
pointer grammar defines. The typing half remains open, so the gap row is
**narrowed, not removed**, and the `#[ignore]`d
`gap_vci_13_claims_path_pointer_emptiness_and_shape_are_never_validated` test is
revised to cover only the surviving half.

### 3.4 `foundry-issuer` — consume both

`handle_credential_request` passes `sub: None` and computes
`exp: now_unix + cred_type.resolved_validity_seconds() as i64`.

`create_offer` replaces its `selectively_disclosable` guard with
`if !claim_def.is_required() { continue; }` — a one-line change that is the
entire fix for §1.2(b).

Validation stays **offer-time only**. A transaction's claims are fixed when the
offer is created and cannot change before `/credential`, so a second gate at
issuance could only fire on a state offer-time validation already made
unreachable. Adding one would be redundant code that no test can honestly
exercise.

---

## 4. The DPC credential type — configuration, not code

Added to `QUICKSTART_CONFIG` (`crates/foundry/src/commands.rs:260`)
**alongside** `pid`, not replacing it: `e2e_full_flow` issues `pid` from this
config, and two configured types exercise the multi-type issuer-metadata path
that one type cannot.

```yaml
  # EMVCo Digital Payment Credential. See docs/specs/emvco-dpc-schema-framework.md
  # for the specification reference; the claim set below is the SD-JWT binding of
  # its Annex A.2.3 disclosable attributes.
  - id: com.emvco.dpc.card
    format: dc+sd-jwt
    # Note: unlike `pid` above, this `vct` is a reverse-DNS identifier, not a URL.
    # The specification fixes this exact string as the canonical credential type.
    vct: com.emvco.dpc.card
    cryptographic_holder_binding: true
    # 12 hours, matching the specification's own sample. Credential expiry is
    # independent of card expiry.
    validity_seconds: 43200
    display:
      - { locale: en-US, name: "Payment Card",       background_color: "#1A1A2E", text_color: "#FFFFFF" }
      - { locale: de-DE, name: "Zahlungskarte",      background_color: "#1A1A2E", text_color: "#FFFFFF" }
      - { locale: fr-FR, name: "Carte de paiement",  background_color: "#1A1A2E", text_color: "#FFFFFF" }
    claims:
      # Mandatory per the DPC payload schema AND selectively disclosable, which is
      # why `required` exists as a field separate from `selectively_disclosable`.
      - path: [credential_id]
        required: true
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Credential ID" }
          - { locale: de-DE, name: "Credential-ID" }
      - path: [network]
        required: true
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Payment Network" }
          - { locale: de-DE, name: "Zahlungsnetzwerk" }
      # Optional. A single string for one network, or an array for co-badged cards.
      - path: [card_id]
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Card Identifier" }
          - { locale: de-DE, name: "Karten-ID" }
```

`scope` is left unset, so `resolved_scope()` yields `com.emvco.dpc.card` — the
`id`. That is a legitimate scope string and satisfies HAIP OpenID4VCI
L186/L199/L209 without an explicit value.

### 4.1 The `status` claim, deliberately left in place

The quickstart config sets `status_list.enabled: true`, so credentials issued
from it carry a `status` claim. The DPC payload schema does not list `status` and
declares `additionalProperties: false` — yet the same specification's §6 says
"Revocation: Implement status check mechanisms."

That contradiction is the draft's, not foundry's. Status lists stay enabled:
disabling a working revocation mechanism to flatter a schema that its own
specification's security section contradicts would be the wrong trade. Recorded
in §8 and noted in the config.

The same schema also omits `_sd` and `_sd_alg` while both of its sample payloads
carry them, which is independent evidence that
`additionalProperties: false` describes the *known claim vocabulary* rather than
a literal closed-world constraint on an SD-JWT payload.

---

## 5. Specification handling — reference, not copy

The EMVCo document is **not** vendored into `docs/specs/`, breaking the pattern
set by the five files already there. Its legal notice states:

> © 2026 EMVCo, LLC. All rights reserved. Reproduction, distribution and other
> use of this document is permitted only pursuant to the applicable agreement
> between the user and EMVCo.

It is additionally an unpublished draft — "DRAFT Associate Review 2". This
repository is Apache-2.0 licensed; committing an all-rights-reserved,
unpublished third-party document into it would purport to convey redistribution
rights the project does not hold. The other five files in `docs/specs/` are
IETF and OpenID Foundation texts that carry redistribution permission.

Instead:

- **`docs/specs/emvco-dpc-schema-framework.md`** is a *stub*: the exact
  document title, version and review round; EMVCo's legal notice; where a reader
  obtains their own copy; and the derived interface facts restated in foundry's
  own words — the three-claim table of §1.1 and the meta-attribute mapping.
  Claim names, JSON types and required flags are factual interface information,
  not expressive content; restating them is materially different from
  reproducing the document.
- **Root `AGENTS.md` §4.4** gains a row for the stub under a third category,
  distinct from both standards-track specifications and vendor profiles: an
  **external non-redistributable reference**. It is normative for the DPC
  credential shape only, and the row states plainly that no verbatim copy is
  in-tree and why, so a future reader does not assume the file was simply
  forgotten.

This also gives the draft-instability problem a home: the stub records *which*
review round the implementation was built against, so a later round's changes
can be diffed against a recorded baseline rather than against memory.

---

## 6. Testing

Scoped gate per root `AGENTS.md` §5.1 — `foundry-sd-jwt-vc`, `foundry-core`,
`foundry-issuer`, `foundry`. The §5.3 full gate runs once, at the end of the
branch.

**`foundry-sd-jwt-vc`**
- `sub` is absent from the payload when `IssuerClaims.sub` is `None`.
- `sub` is present and correct when `Some`, so the capability is not lost.

**`foundry-core`**
- `is_required()` resolution matrix: `required` absent / `Some(true)` /
  `Some(false)`, crossed with `selectively_disclosable` true / false.
- `resolved_validity_seconds()` default and explicit value.
- `Config::validate()` rejects `validity_seconds: Some(0)`.
- `Config::validate()` rejects `path: []` — a **new passing** test, since this
  half of `GAP-VCI-13` is now closed.
- The existing `#[ignore]`d
  `gap_vci_13_claims_path_pointer_emptiness_and_shape_are_never_validated` is
  narrowed to the surviving typing half and renamed accordingly, so its
  `#[ignore]` reason no longer asserts something that is now false. Per root
  `AGENTS.md` §8 the `#[ignore]` is *not* removed — the gap is half-closed, not
  closed.

**`foundry-issuer`**
- **The defect's regression test:** an offer omitting a claim that is
  `required: true, selectively_disclosable: true` is rejected; one omitting a
  claim that is only `selectively_disclosable: true` is accepted.
- A DPC credential issues with `vct == "com.emvco.dpc.card"`, **no `sub`**,
  `exp == iat + 43200`, and `credential_id` / `network` present as disclosures
  rather than as payload claims.
- `card_id` is absent from the credential entirely when no value is supplied.
- `network` round-trips both as a single string and as an array of strings —
  the co-badged case, and the only place the DPC type's JSON is non-scalar.
- Issuer metadata advertises the DPC configuration with every configured locale.

**`foundry`**
- The generated quickstart config parses and the server boots with both types.
- `e2e_full_flow` is unchanged and still passes — the regression guard for
  dropping `sub` from `pid`.

---

## 7. Documentation

- `docs/specs/emvco-dpc-schema-framework.md` — the stub of §5.
- Root `AGENTS.md` §4.4 — the external-non-redistributable-reference row.
- `README.md` — `required` and `validity_seconds` in the configuration
  reference; the DPC type in the quickstart section.
- `crates/foundry-sd-jwt-vc/AGENTS.md` — `IssuerClaims.sub` is optional and
  omitted by default; why (correlation identifier with no reader).
- `crates/foundry-core/AGENTS.md` — the two resolver methods and their defaults.
- `crates/foundry-issuer/AGENTS.md` — gotcha: "required" is no longer the same
  thing as "not selectively disclosable"; `create_offer` gates on
  `is_required()`.
- `docs/conformance/openid4vc-conformance.md` — narrow the `GAP-VCI-13` row to
  the typing half. No clause verdict changes as a result of dropping `sub`; that
  was verified against every `sub` row in the report, all of which concern other
  JWTs.
- `openapi.json` / `openapi-wallet.json` — no diff expected, since
  `CredentialType` and `ClaimDef` are configuration types rather than HTTP
  schemas. To be **verified by regenerating**, not assumed.
- `docs/superpowers/changes/2026-08-05-emvco-dpc-credential-type.md` on
  completion.

---

## 8. Open issues this branch deliberately leaves

In the order they would block a full DPC deployment:

1. **Verifier / DCQL.** No `com.emvco.dpc.card` named query is shipped, and one
   real semantic question is unanswered: the specification's co-badged Sample 2
   filters on `network` with `values: ["example_network",
   "example_network_2"]` against a claim whose value is itself an array.
   Whether foundry's DCQL `values` matching handles an array-valued claim is
   **unverified** — it may match, may not, or may match only by accident.
   Deciding the intended semantics is a prerequisite to shipping a DPC verifier
   configuration.
2. **Display metadata** (`com.emvco.dpc.card.meta`) — the `card` object on the
   Credential Offer and Credential Response. See §2.1 for the full reasoning.
   Needs per-instance display plumbing and an extension to two wire structures
   that OpenID4VCI 1.0 does not define.
3. **mdoc binding** — `docType` and namespace `com.emvco.dpc.card`, with
   `credential_id` / `network` / `card_id` as namespace data elements.
   `MdocClaims.namespaces` is already a `BTreeMap<String, ...>`, so the
   namespace is parameterisable; this is unstarted rather than blocked.
4. **The draft contradicts itself in two places**, recorded so that a later
   review round can be checked against them: `additionalProperties: false`
   alongside samples carrying `_sd` / `_sd_alg`; and §6's mandate to implement
   status checks against a schema with no room for a `status` claim.
5. **Draft instability.** This is Associate Review 2. The canonical `vct` is
   stated as stable across formats; individual claim definitions may move. The
   §5 stub records the baseline.
6. **`vct` is never validated as a URI.** `validate.rs:29` checks presence only.
   The DPC value is a reverse-DNS string and the shipped `pid` value is an https
   URL, so foundry now carries both shapes with no stated rule. Harmless today;
   worth a decision before a third form appears.
7. **Google issuer onboarding.** The Google profile states that Google
   hard-codes issuer metadata on its backend and must be sent the metadata
   document before onboarding starts. Operational, unchanged by this work, and
   still gating the integration.

---

## 9. Why this is safe

Every code change is additive or removes an unread claim:

- `sub` becoming `Option` cannot break a consumer inside this repository —
  nothing reads it, no conformance clause depends on it, and the verifier
  ignores it. The risk is confined to an out-of-tree consumer keying off
  `sub_<transaction_id>`; none is known, and the value it exposed was an
  internal transaction identifier that should not have been load-bearing for
  anyone.
- `required` and `validity_seconds` are `Option` fields whose absent state
  resolves to precisely today's behaviour, so every existing configuration file
  — including both shipped ones — keeps its current semantics without edit.
- The two new validation rejections can only fire on configurations that are
  already broken: a zero-length credential lifetime, or a claim that can never
  be addressed.
- The DPC credential type is data. A deployment that does not want it deletes
  one block of YAML; nothing in the binary knows it existed.