# Credential Configuration `display` and `claims` — nesting under `credential_metadata`

**Date:** 2026-08-24

**Governing document:** OpenID for Verifiable Credential Issuance 1.0,
[`docs/specs/openid-4-verifiable-credential-issuance-1_0.md`](../../specs/openid-4-verifiable-credential-issuance-1_0.md),
"Credential Issuer Metadata Parameters" (L1400–L1412) and "Claims Description
for Issuer Metadata" (L2315–L2340). A standards-track specification, so root
`AGENTS.md` §4.4 applies in full: this document cites line numbers in the pinned
copy, not a newer draft found online.

**Origin:** a real wallet, not a code review. An `eu.europa.ec.av.1` credential
issued to a wallet built on `eudi-lib-jvm-openid4vci-kt` v0.11.0 rendered with
no name and a hash-derived placeholder colour, despite `config.yaml` declaring
`display: [{ name: "Proof of Age", locale: en-US }, { name: "Altersnachweis",
locale: de-DE }]`. The wallet was conformant; foundry was not.

---

## 1. Problem

OpenID4VCI 1.0 places a Credential Configuration's display and claims metadata
inside a nested `credential_metadata` object:

```text
L1400:   * `credential_metadata`: OPTIONAL. Object containing information
                                  relevant to the usage and display of issued
                                  Credentials …
L1401:     * `display`:  OPTIONAL. A non-empty array of objects …
L1412:     * `claims`:   OPTIONAL. A non-empty array of claims description
                         objects as defined in (#claims-description-issuer-metadata)
```

Both members are two levels deep, inside each value of
`credential_configurations_supported`. There is no top-level `display` or
`claims` on a Credential Configuration in 1.0. The only top-level `display` the
specification defines (L1384) is **issuer**-level — a sibling of
`credential_endpoint`, describing the Credential Issuer rather than a credential.

foundry emits both members flat, as siblings of `format`, `scope` and `vct` —
the pre-1.0 draft shape. `grep -rn "credential_metadata" crates/` returns zero
hits: the parameter does not exist anywhere in this repository.

### 1.1 Why this is silent rather than an error

L1422–L1423 requires the opposite of a diagnostic:

> Additional Credential Issuer metadata parameters MAY be defined and used.
> The Wallet MUST ignore any unrecognized parameters.

So a conformant wallet is *obliged* to discard foundry's flat `display`. Nothing
is logged, no error is returned, and the credential arrives renderable but
unrendered. The failure surfaces only as a visual defect on a device, which is
why it survived a conformance report that covers the surrounding clauses.

The wallet-side path was verified against the library at the exact tag,
`eudi-lib-jvm-openid4vci-kt` **v0.11.0**,
`internal/http/CredentialIssuerMetadataJsonParser.kt`:

- `MsdMdocCredentialTO` (L152) declares `@SerialName("credential_metadata")` at
  L162 and has **no** top-level `display` or `claims` member. The same holds for
  `SdJwtVcCredentialTO` (L199/L209) and the three W3C variants.
- `CredentialMetadataTO` (L98–L100) is the **only** reader of a Credential
  Configuration's `display` and `claims`.
- The two other `@SerialName("display")` occurrences are
  `CredentialIssuerMetadataTO` (L436, issuer-level) and `ClaimTO` (L596,
  nested inside a claims description). Neither is a fallback path.

There is therefore no code path by which a flat `display` reaches that wallet.

### 1.2 Why mdoc makes this total rather than partial

L1400's own text frames `credential_metadata` as a fallback:

> Format-specific mechanisms, such as SD-JWT VC display metadata are always
> preferred by the Wallet over the information in this object, which serves as
> the default fallback.

That framing understates the impact for `eu.europa.ec.av.1`, which is
`mso_mdoc` (`config.yaml:73`). The format-specific mechanism the sentence refers
to is the SD-JWT VC VCT document. **mdoc has no format-specific display
mechanism at all.** For an mdoc credential, `credential_metadata.display` is not
a fallback — it is the only channel that exists. The loss is total.

The same sentence independently confirms that a wallet preferring a VCT document
over issuer metadata is spec-correct, so the wallet's precedence logic was never
in question.

### 1.3 Scope: every credential type, not just `av`

All three configured credential types declare `display`:

| Config id | Format | Has `display` | Has `claims` |
| --- | --- | --- | --- |
| `pid` | `dc+sd-jwt` | yes (`config.yaml:47`) | yes |
| `com.emvco.dpc.card` | `dc+sd-jwt` | yes (`config.yaml:58`) | yes |
| `eu.europa.ec.av.1` | `mso_mdoc` | yes (`config.yaml:85`) | yes |

The two SD-JWT VC types can recover display from a VCT document; the mdoc type
cannot. `claims` is lost for all three regardless of format.

### 1.4 Two further defects in the same object

Moving the `claims` array exposes two independent conformance defects in its
*contents*. L2321–L2338 defines a claims description object for Issuer Metadata
as exactly three members — `path` (REQUIRED), `mandatory` (OPTIONAL), `display`
(OPTIONAL). `metadata.rs:208–219` emits:

```rust
serde_json::json!({
    "path": c.path,
    "selectively_disclosable": c.selectively_disclosable,
    "display": c.display,
})
```

**(a) `selectively_disclosable` is not an OpenID4VCI parameter.** It is a
foundry config field name leaking onto the wire. It conveys nothing a wallet can
use: for SD-JWT VC the wallet learns disclosability from the credential's own
disclosures, and for mdoc every `IssuerSignedItem` is inherently selectively
disclosable — as `config.yaml:93` already notes, which is why `av` deliberately
leaves the flag unset. Nothing in this repository reads the emitted value back;
every other occurrence of the identifier is a struct literal in config or test
code.

**(b) `mandatory` is absent, and `display` is emitted as `[]`.** L2326 defines
`mandatory` as "the Credential Issuer will always include this claim in the
issued Credential" — information foundry has and does not publish.
Independently, `"display": c.display` inside a `json!` macro is not subject to
`skip_serializing_if`, so a claim with no configured display emits
`"display": []`, contradicting L2332's "A non-empty array of objects".
`eu.europa.ec.av.1`'s two claims both hit this today.

### 1.5 The conformance report inherited the mis-nesting

`docs/conformance/openid4vc-conformance.md` GAP-VCI-10 cites L1402, L1403,
L1405, L1409 and L1410 — every one of those lines sits *inside*
`credential_metadata` → `display`. The report was written against the nested
text while the code implemented the flat shape, and the level was never
reconciled. VCI-0181 and VCI-0182 carry the same inherited evidence.

Neither L1400 (`credential_metadata` itself) nor L2326 (`mandatory`) has a
conformance row at all, so closing this needs **new** rows, not only corrected
evidence.

---

## 2. Design

### 2.1 Wire model

A new type in `crates/foundry-issuer/src/metadata.rs`:

```rust
/// OpenID4VCI L1400 — `credential_metadata`, the nested object carrying a
/// Credential Configuration's display and claims metadata.
///
/// Until 2026-08-24 foundry emitted `display` and `claims` as flat siblings of
/// `format`/`scope` — the pre-1.0 draft shape. A 1.0 wallet finds no
/// `credential_metadata`, and L1423 ("The Wallet MUST ignore any unrecognized
/// parameters") then obliges it to discard the flat copies, so the credential
/// arrives renderable but unrendered.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialMetadata {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub claims: Vec<serde_json::Value>,
}
```

On `CredentialConfigurationSupported`, the flat `display` and `claims` fields
are **deleted** and replaced by one member:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub credential_metadata: Option<CredentialMetadata>,
```

`Option` rather than an always-present struct, and `skip_serializing_if` rather
than an emitted `{}`: L1400 is OPTIONAL, and a credential type with neither
display nor claims must not acquire a `"credential_metadata": {}` key. An empty
object is not "information relevant to the usage and display of issued
Credentials"; emitting one would replace the defect this design removes with a
smaller one. `build_issuer_metadata` therefore constructs `Some(..)` only when
at least one of the two vectors is non-empty.

The element type stays `Vec<serde_json::Value>` — untyped passthrough,
unchanged from today. Typing it is GAP-VCI-10 and is deliberately out of scope
(§3).

`CredentialMetadata` joins `CredentialConfigurationSupported` in the crate's
public re-exports, because it appears in that type's public signature.

### 2.2 Claims description contents

The `json!` block becomes an explicitly built map, so an absent member is
genuinely absent rather than an empty array:

```rust
// OpenID4VCI L2321-L2338 — a claims description object for Issuer Metadata
// defines exactly `path`, `mandatory` and `display`.
// `selectively_disclosable` was never an OpenID4VCI parameter: a wallet
// learns disclosability from the SD-JWT's own disclosures, and for mdoc every
// IssuerSignedItem is inherently disclosable, so it conveyed nothing at
// either format.
let mut claim = serde_json::Map::new();
claim.insert("path".into(), serde_json::json!(c.path));
// L2326: `mandatory` — "the Credential Issuer will always include this claim
// in the issued Credential". That is exactly `ClaimDef::is_required()`, the
// same predicate `create_offer` (create_offer.rs:145-151) uses to decide
// whether a value must be supplied when an offer is created.
claim.insert("mandatory".into(), serde_json::json!(c.is_required()));
// L2332: "A non-empty array of objects" — so omitted when empty, never `[]`.
if !c.display.is_empty() {
    claim.insert("display".into(), serde_json::json!(c.display));
}
```

**Why `is_required()` maps onto `mandatory`.** `ClaimDef::is_required()`
(`foundry-core/src/config/model.rs:564`) is
`self.required.unwrap_or(!self.selectively_disclosable)`, and `create_offer`
uses it to reject an offer that omits a value for the claim. So
`is_required() == true` means a value is always supplied, hence the claim is
always present — L2327. `is_required() == false` means the claim appears only
when the offer supplied a value, which is L2328–L2331's "not included if the
wallet did not request the inclusion of the claim, and/or if the Credential
Issuer chose to not include the claim". The mapping is exact, not approximate.

**`mandatory` is emitted unconditionally**, including when `false`, even though
L2331 makes absence default to `false`. `is_required()` is always determinate,
so obliging the wallet to infer the value from absence adds nothing, and the
explicit member records the issuer's intent rather than leaving it to a default.

### 2.3 Resulting wire shape

For `eu.europa.ec.av.1`, before:

```json
{
  "format": "mso_mdoc",
  "scope": "eu.europa.ec.av.1",
  "doctype": "eu.europa.ec.av.1",
  "display": [ { "name": "Proof of Age", "locale": "en-US" }, … ],
  "claims": [ { "path": ["age_over_18"], "selectively_disclosable": false, "display": [] }, … ]
}
```

After:

```json
{
  "format": "mso_mdoc",
  "scope": "eu.europa.ec.av.1",
  "doctype": "eu.europa.ec.av.1",
  "credential_metadata": {
    "display": [ { "name": "Proof of Age", "locale": "en-US" }, … ],
    "claims": [ { "path": ["age_over_18"], "mandatory": true }, … ]
  }
}
```

---

## 3. What this design does not do

**It does not close GAP-VCI-10.** `ct.display` stays untyped
`Vec<serde_json::Value>`, so `Config::validate()` still never checks that a
display object carries `name`, that locales do not duplicate, or that `logo` and
`background_image` carry `uri`. VCI-0150–0154, VCI-0181 and VCI-0182 remain
`gap`, and `vci_0150_0151_0152_0153_0154_credential_display_objects_are_not_structurally_validated`
stays `#[ignore]`d.

This is a deliberate boundary, and the argument against it deserves recording:
an untyped `Vec<serde_json::Value>` is *precisely why* the mis-nesting survived.
Nobody had to think about the shape of a field with no shape. Typing it is the
change that would have prevented this defect, which makes GAP-VCI-10 the natural
sequel — but coupling it here would bury an urgent wire-format correction inside
a large mechanical diff. Typing `ct.display` and `ClaimDef` ripples into every
struct literal that builds one: `foundry-core/src/config/validate.rs`,
`foundry-core/src/config/mdoc.rs`, `crates/foundry/tests/logging_redaction.rs`,
`authorization_code_flow.rs` and `wallet_issuance.rs` all construct them. That
belongs in its own branch, with its own review, and with the `#[ignore]` removal
that §8 of root `AGENTS.md` obliges.

**It does not add a compatibility mode.** Wallets on OpenID4VCI draft 13/14 read
the flat members and will lose credential display metadata. This is accepted
deliberately: the flat shape has never worked for any 1.0 wallet, so nothing
currently working depends on it. Emitting both shapes was rejected because a
flat `display` has no governing document to cite — unlike the EMVCo `display`
members, which a pinned external reference justifies, "an old draft" is not a
document in `docs/specs/`, so the deviation comment §4.4 requires would have
nothing to name. A config flag was rejected as config surface for a wallet not
yet observed; if one appears, adding the flag then is a small additive change
with real evidence behind it.

**It does not touch issuer-level `display`.** `CredentialIssuerMetadata.display`
stays hardcoded `Vec::new()`; VCI-0141 and VCI-0142 are unchanged.

**It does not touch GAP-VCI-13.** `ClaimDef.path` stays `Vec<String>` and still
cannot express the `null` or integer segments the claims path pointer grammar
allows.

**It does not touch the EMVCo DPC `display` members.** Those live on the
Credential Offer and the Credential Response — different structures, governed by
an external reference, and confined to `com.emvco.dpc.card`. The identically
named field is a coincidence of vocabulary, and a mechanical rename that catches
them would be a defect. `wallet_issuance.rs:1156` and `:1225` assert them and
must keep passing unchanged.

---

## 4. Files touched

| File | Change |
| --- | --- |
| `crates/foundry-issuer/src/metadata.rs` | New `CredentialMetadata` type; `CredentialConfigurationSupported` loses flat `display`/`claims`, gains `credential_metadata`; `build_issuer_metadata` rebuilds the claims map per §2.2 |
| `crates/foundry-issuer/src/lib.rs` | Re-export `CredentialMetadata` |
| `crates/foundry-issuer/tests/conformance_vci.rs` | Rewrite `vci_0155_…`; new coverage per §5 |
| `crates/foundry/src/openapi.rs` | Register `CredentialMetadata` in `components(schemas(..))` |
| `openapi.json`, `openapi-wallet.json` | Regenerated (§6 of root `AGENTS.md`) |
| `docs/conformance/openid4vc-conformance.md` | Two new rows; corrected evidence on GAP-VCI-10, VCI-0150–0154, VCI-0181, VCI-0182, VCI-0155 |
| `crates/foundry-issuer/AGENTS.md` | Gotcha: display/claims live under `credential_metadata`; flat was the pre-1.0 draft shape |
| `docs/superpowers/changes/2026-08-24-credential-metadata-nesting.md` | Change record |

`config.yaml` is **not** touched. This is purely an emission change; no
configuration is renamed, added or migrated.

---

## 5. Testing

Written failing first, per the TDD skill.

**New, in `metadata.rs` `#[cfg(test)]`:**

| Test | Asserts |
| --- | --- |
| `credential_metadata_nests_display_and_claims` | Serialised JSON has `["credential_metadata"]["display"]` **and** no top-level `["display"]` or `["claims"]`. The regression test for the reported defect — the absence half is the load-bearing half |
| `credential_metadata_is_absent_when_neither_display_nor_claims_configured` | No `credential_metadata` key at all, not `{}` |
| `claims_description_emits_mandatory_and_not_selectively_disclosable` | `mandatory` present and equal to `is_required()` for both a required and a non-required claim; `selectively_disclosable` absent |
| `claims_description_omits_display_when_none_configured` | No `"display"` key on a claim with empty configured display — specifically not `[]` |

**Modified:**

- `credential_configuration_display_carries_every_configured_locale`
  (`metadata.rs:953`) — reads through `credential_metadata`. Its doc comment
  currently says "opaque passthrough into
  `credential_configurations_supported[].display`" and must be corrected, or it
  documents the defect as the design.
- `vci_0155_credential_configuration_claims_reveal_disclosed_paths`
  (`conformance_vci.rs:2450`) — currently asserts
  `pid.claims[0]["selectively_disclosable"]`, so it actively pins the non-spec
  key. Rewritten to read `credential_metadata.claims[0]` and assert `path` plus
  `mandatory`. Its clause — the Authorization Server must be able to determine
  the disclosed claims from Issuer metadata — is better served afterwards, since
  `mandatory` is the specification's own vehicle for it.

**Deliberately untouched:** `builds_issuer_metadata_from_credential_types`
(never asserts display or claims), `vci_0141` (issuer-level display), and every
EMVCo `offer_display` / `credential_response_display` assertion in
`wallet_issuance.rs`.

**Gate:** root `AGENTS.md` §5.1, unmodified —

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Then, because both OpenAPI documents change, `cargo nextest run -p foundry
--test e2e_full_flow --run-ignored ignored-only` before the branch is merged
(§5.2).

---

## 6. Risks

| Risk | Assessment |
| --- | --- |
| Draft-13/14 wallets lose display metadata | Accepted, deliberately (§3). No such wallet is tested against, and the flat shape has never worked for a 1.0 wallet |
| A mechanical rename catches the EMVCo offer/response `display` | Named explicitly in §3 and guarded by the existing `wallet_issuance.rs` assertions, which must pass unchanged |
| `openapi.json` drifts from the code | Both documents are regenerated in the same change and covered by `openapi_endpoints.rs` / `cli_openapi.rs` |
| Dropping `selectively_disclosable` breaks external tooling | No consumer exists in this repository. Confirmed acceptable when the decision was taken; recorded here as the one wire removal with no in-tree evidence either way |

---

## 7. Open issues left after this branch

1. **GAP-VCI-10** — type `ct.display` and `ClaimDef.display`, validate the
   structural MUSTs at L1402/L1403/L1405/L1409/L1410 and L2338, and remove the
   `#[ignore]`. §3 argues this is the natural sequel.
2. **VCI-0182** — `Config::validate()` still does not reject two `ClaimDef`s
   addressing the same `path`.
3. **GAP-VCI-13** — `ClaimDef.path` still cannot express `null` or integer
   claims-path-pointer segments.
4. **Issuer-level `display`** (VCI-0141, VCI-0142) is still not configurable.
