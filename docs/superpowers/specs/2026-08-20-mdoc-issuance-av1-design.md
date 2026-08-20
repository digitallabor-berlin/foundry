# mdoc issuance — `eu.europa.ec.av.1` Proof of Age — Design

**Date:** 2026-08-20
**Status:** approved (design); implementation plan not yet written
**Crates:** `foundry-mdoc`, `foundry-core`, `foundry-issuer`, `foundry` (config,
tests, docs)
**Governing specs:**
`docs/specs/openid-4-verifiable-credential-issuance-1_0.md` (OpenID4VCI 1.0),
Format Profile / mdoc (L2235, L2249);
`docs/specs/eu-age-verification-annex-a-av-profile.md` (EU Age Verification
Solution Technical Specification, Annex A — **added by this change**, see §1);
`docs/specs/iso-18013-5-device-auth.md` (reference stub, unchanged).

**Closes:** GAP-VCI-12, GAP-VCI-16.

---

## 1. Why

foundry already contains mdoc issuance code, and it has never been used.

| Area | State before this change |
| --- | --- |
| `foundry-issuer/src/credential.rs` `"mso_mdoc"` arm | Exists — builds `MdocClaims`, calls `build_mdoc`, base64url-encodes the result |
| `foundry-mdoc/src/builder.rs` `build_mdoc` | Exists — tag-24 `IssuerSignedItem`s, tag-24 MSO, `tdate` validity, ES256 IssuerAuth, RFC 9360 `x5chain` cardinality all correct |
| `config.yaml` | **No `mso_mdoc` credential type at all** — two `dc+sd-jwt` types only |
| Workspace tests | **No mdoc issuance coverage.** `wallet_issuance.rs` never mentions mdoc; only `wallet_verification.rs` does |
| Conformance register | Two open gaps against the mdoc format profile: GAP-VCI-12, GAP-VCI-16 |

So the code path compiles, is reachable in principle, and is exercised by
nothing an operator could run. "Add mdoc issuance" therefore means: make the
existing path conformant, make it configured, and make it covered — with one
real credential type as the proof.

The credential type is the **EUDI Proof of Age attestation**, doctype
`eu.europa.ec.av.1`.

### 1.1 What the request was, and why it changed

The driving request named six claims:

```json
{
  "issue_date": "2026-03-18",
  "expiry_date": "2028-12-31",
  "issuing_authority": "digitallabor.berlin",
  "issuing_country": "Deutschland",
  "age_over_16": true,
  "age_over_18": true
}
```

Annex A §4.1.2 admits **two** attributes in this namespace, both `bool`, and
then closes the set:

> A Proof of Age Attestation SHALL NOT include any other attribute.

| Requested claim | Disposition |
| --- | --- |
| `age_over_18: true` | Mandatory attribute — issued |
| `age_over_16: true` | Valid `age_over_NN` — issued |
| `issue_date` | Not an attribute. The concept lives in the MSO's `validityInfo.validFrom` |
| `expiry_date` | Not an attribute. The concept lives in the MSO's `validityInfo.validUntil` |
| `issuing_authority` | No such element. Issuer identity is carried in the `IssuerAuth` X.509 chain (COSE unprotected label 33) |
| `issuing_country` | No such element. Where ISO 18013-5 does define it elsewhere, it is an ISO 3166-1 alpha-2 code (`DE`), not a country name |

Issuing the four rejected claims as namespace attributes was explicitly
considered and **rejected**: it violates a `SHALL NOT`, so a conformant verifier
may reject the whole attestation, and unlike foundry's EMVCo and Google
accommodations there is no vendor profile to cite as justification. Root
`AGENTS.md` §4.4 admits unimplemented optional features, not incorrect
implementations.

The two date concepts are therefore carried by the MSO validity window, which
`build_mdoc` already emits correctly as `tdate` (tag 0) — Annex A's own worked
example agrees (`"validFrom": 0("2025-06-20T08:45:29Z")`). Per the requester's
instruction to follow the spec rather than the sample values, the window stays
**relative** (`validity_seconds`, `validFrom == signed`), which is also the shape
of Annex A §A.11's example. No absolute-date config field and no per-offer
validity parameter is introduced.

---

## 2. Decisions

Six decisions were settled during brainstorming. Each records the rejected
alternative, because each is the kind of choice a later reader will otherwise
re-litigate.

### 2.1 Vendor Annex A, pinned by release

**Decided:** commit a copy of Annex A to `docs/specs/`, pinned to release
**1.0.9**, commit `5eb8a033bf41179a83c27a5df47ff8fdde388bf8` (2026-03-19).

**Rejected:** an external-reference stub in the manner of
`iso-18013-5-device-auth.md` or `emvco-dpc-schema-framework.md`. Those exist
because their sources cannot be redistributed. This one can: the specification
is *"licensed under Attribution 4.0 International"* (CC BY 4.0). §4.4's
external-reference rule is a fallback for undistributable documents, not a
default — where a verbatim copy is permitted, the verbatim copy is strictly
better evidence.

Only **Annex A** is vendored. The wider specification covers wallet
architecture, app UX and transport concerns foundry does not implement; vendoring
it whole would misrepresent how much of it governs this repository.

### 2.2 Follow the closed attribute set, and enforce it at config load

**Decided:** `validate.rs` rejects a `eu.europa.ec.av.1` credential type unless
all three hold: every declared claim is a single-segment path; every claim name
is `age_over_18` or `age_over_<integer>`; and `age_over_18` is both **present**
and **`required: true`**. Annex A §4.1.2 records it as *Mandatory* in issuance,
so a config that declares it optional describes a credential the spec does not
admit — presence alone is not enough.

**Rejected — a generic `allowed_elements` config list.** Self-certifying: an
operator who mistypes the list gets no error, so the spec's closed set becomes
documentation rather than enforcement. Also pure config surface for one
credential type.

**Rejected — no enforcement, ship a correct `config.yaml` and trust it.** The
only thing then standing between foundry and a `SHALL NOT` violation is a YAML
file nobody validates. foundry's posture throughout (§4.1, §4.2) is that a check
not performed must not be reported as passed.

Keying validation on a known type identifier has precedent: `create_offer.rs`'s
`DPC_VCT` does exactly this for the EMVCo type, with the same obligation to cite
the governing document in a comment so a reader can tell conformance from magic.

The `age_over_NN` check is a **real integer parse** of the suffix, not a prefix
match — `age_over_banana` must fail.

### 2.3 The credential is a bare `IssuerSigned` (closes GAP-VCI-16)

**Decided:** `build_mdoc` returns the bare `IssuerSigned` map,
`{nameSpaces, issuerAuth}`.

OpenID4VCI L2249 requires the `credential` claim to be the base64url-encoded
CBOR `IssuerSigned` structure. `build_mdoc` returned a `DeviceResponse`-shaped
wrapper — `{version, documents: [{docType, issuerSigned}]}` — so an issued
credential carried one layer more than the clause allows, and a wallet following
L2249 literally would fail to parse it. Annex A §A.11's own worked example is
`IssuerSigned`-shaped (`{issuerAuth, nameSpaces}`), independently corroborating
the fix direction.

**Rejected — keep the wrapper and document the divergence.** The wrapper was
already recorded as a gap rather than a deviation, precisely because nothing
justifies it; it was an artifact of `build_mdoc` and `build_device_response`
having been written together.

### 2.4 doctype resolution is `doctype`-only (closes GAP-VCI-12)

**Decided:** two changes, together. `validate.rs` rejects `vct` on an
`mso_mdoc` credential type; and `credential.rs`'s
`vct → doctype → credential_type_id` fallback chain is **deleted**, not
reordered.

`vct` is an SD-JWT-VC identifier (typically an HTTPS URL) with no relationship
to ISO 18013-5's reverse-DNS `docType` convention. Preferring it produced a
non-conformant docType from a config state that was entirely legal.

**Rejected — reorder the chain to `doctype → vct → credential_type_id`.** That
picks a winner inside an ambiguous state instead of removing the state. The
`vct` would then be silently ignored rather than reported.

**Rejected — reject at load but keep the chain.** With the load-time rejection
in place the chain can only ever return `doctype`, so it is dead code that
documents a precedence rule which no longer exists — an invitation to
reintroduce the bug. A resolution with one possible source should say so.

Absence of `doctype` at request time is a typed `IssuanceError`, never an
unwrap (§4.1), even though §2.2's validation makes it unreachable.

### 2.5 Offer-supplied claims are filtered through the config's claim list

**Decided:** the mdoc arm iterates `cred_type.claims` and looks each up in
`tx.claims`, exactly as the SD-JWT VC arm does.

This is not on either gap register — it was found while reading the code for
this design. The mdoc arm did:

```rust
for (k, v) in &tx.claims {
    elem_map.insert(k.clone(), v.clone());
}
```

That emits **whatever the offer supplied**, ignoring `cred_type.claims`
entirely. So an operator creating an offer could inject arbitrary attributes
into a `eu.europa.ec.av.1` credential at offer time, and §2.2's config-load
validation would never see them — config-time enforcement of a closed attribute
set is worthless without this. The two format arms disagreeing about whether
config or offer defines the claim set is itself the defect; they are made to
agree.

### 2.6 Namespace is configurable, defaulting to doctype

**Decided:** `CredentialType` gains an optional `namespace`, defaulting to
`doctype`.

Namespace-equals-doctype is **correct** for EUDI attestations — Annex A §4.1.2:
*"All attributes belong to namespace `eu.europa.ec.av.1`"* — and **wrong** for
ISO mDL, where doctype `org.iso.18013.5.1.mDL` carries elements in namespace
`org.iso.18013.5.1`. `build_mdoc`'s caller hardcoded the former. An `mdl`
credential type with the ISO doctype already exists in test configs
(`create_offer.rs`'s `test_config_two_types`, `conformance_vci.rs`), so the wrong
namespace is one config entry away from being emitted.

**Rejected — record mDL's namespace as a new conformance gap.** §4.4 admits
unimplemented optional features but not incorrect implementations, and emitting
mDL elements under the doctype as namespace is the second kind. The fix is one
optional field and one line at the call site; deferring it would bank a known
wrong wire format to save less work than writing the gap row.

This is the only *additive* config surface in this change. It is not
mdoc-specific in name, but it is mdoc-only in effect: `dc+sd-jwt` has no
namespaces.

---

## 3. Changes by crate

### 3.1 `docs/specs/` — the vendored spec

New file `docs/specs/eu-age-verification-annex-a-av-profile.md`: a verbatim copy
of Annex A, opening with a provenance header that carries the CC BY 4.0
attribution notice verbatim (as the licence requires), the upstream repository
and path, the pinned release and commit SHA, and the retrieval date.

Root `AGENTS.md` §4.4 gains a row in the **pinned specifications** table — not
the vendor-profile table and not the external-reference table. It is publicly
redistributable and standards-shaped, profiling ISO/IEC 18013-5 and ISO/IEC
23220-2. Its authority is scoped in the row itself: it governs the
`eu.europa.ec.av.1` doctype only, and where it is stricter than ISO 18013-5 for
that doctype, it wins.

Bumping the pin later is a deliberate change, exactly as for the other pinned
specs.

### 3.2 `foundry-mdoc`

`build_mdoc` returns the bare `IssuerSigned` map. Its doc comment loses the
"remaining known divergence is the outer envelope" paragraph, which is no longer
true.

`build_device_response` becomes simpler, not more complex: its
`documents[0].issuerSigned` traversal is deleted and it wraps the value it is
handed — which is what a wallet actually does with a credential it received.

`MdocClaims` gains no new field for the namespace; the namespace is already a key
of `MdocClaims::namespaces`, and §2.6's change is entirely in the caller.

### 3.3 `foundry-core`

`config/model.rs`: `CredentialType` gains `namespace: Option<String>` with
`#[serde(default)]`, plus a `resolved_namespace()` accessor in the manner of
`resolved_scope()` / `resolved_validity_seconds()`, returning `doctype` when
unset.

`config/validate.rs`, `"mso_mdoc"` arm: `doctype` still required; `vct` newly
rejected; and for `doctype == "eu.europa.ec.av.1"`, the closed attribute set
enforced per §2.2. A module constant names the doctype, with the Annex A citation
on it.

### 3.4 `foundry-issuer`

`credential.rs`, `"mso_mdoc"` arm only:

- doctype from `cred_type.doctype`, no fallback, typed error on absence (§2.4);
- namespace from `cred_type.resolved_namespace()` (§2.6);
- elements built by iterating `cred_type.claims` (§2.5);
- each change carrying its spec citation in a comment.

Every claim value in this credential type is a JSON boolean, which
`json_to_cbor_value` already maps to a CBOR `bool`. No claim-typing machinery
(`cbor_type` declarations, name-based inference, or a per-doctype type table) is
introduced — it would have no user until foundry issues a credential with a
`full-date` or `bstr` element, and speculative encoding machinery is exactly the
kind of thing that is wrong when it finally acquires one.

No MSO `status` embedding is introduced either: Annex A lists *"Proof of Age
attestation re-issuance (using refresh tokens) and revocation"* as out of scope,
and no MSO example contains a `status` element.

### 3.5 `foundry` (binary)

`config.yaml` gains the credential type:

```yaml
  - id: eu.europa.ec.av.1
    format: mso_mdoc
    doctype: eu.europa.ec.av.1
    cryptographic_holder_binding: true
    validity_seconds: 7776000   # 90 days — Annex A §A.11's example window
    display: [{ name: "Proof of Age", locale: en-US }]
    claims:
      - path: [age_over_18]
        required: true
      - path: [age_over_16]
        required: false
```

`selectively_disclosable` is deliberately unset on both claims: every
`IssuerSignedItem` is inherently selectively disclosable, so the flag has no
meaning for mdoc. That is why `required` is stated explicitly rather than left
to `ClaimDef::is_required()`'s `!selectively_disclosable` default — relying on
that default here would make the mandatory/optional distinction depend on a flag
that does not apply to the format.

`verifier.named_queries` gains an `over18_mdoc` entry (format `mso_mdoc`,
`meta.doctype_value: eu.europa.ec.av.1`, claim path
`[eu.europa.ec.av.1, age_over_18]`) so the end-to-end test can verify what it
issued through foundry's own verifier.

---

## 4. Tests

| Where | What |
| --- | --- |
| `foundry-mdoc/src/builder.rs` | **Byte-level, verifier-free:** decode `build_mdoc`'s output and assert the top-level map keys are exactly `nameSpaces` and `issuerAuth`, with no `documents` or `version` |
| `foundry-mdoc` existing tests | Updated for the new return shape |
| `foundry-core` validate tests | `vct` on `mso_mdoc` rejected; a foreign attribute on av.1 rejected; missing `age_over_18` rejected; `age_over_banana` rejected; the shipped `config.yaml` accepted |
| `foundry-issuer/tests/conformance_vci.rs` | Both `#[ignore]`s removed, and both tests renamed — they now assert conformance rather than record a gap. `gap_vci_16_mdoc_credential_is_not_a_bare_issuer_signed` → `vci_0176_mdoc_credential_is_a_bare_issuer_signed`; `gap_vci_12_mdoc_doc_type_prefers_vct_over_doctype_when_both_configured` → `vci_0175_mdoc_doc_type_comes_from_doctype`. Note the first inverts its assertion, not just its name |
| `foundry-issuer/src/credential.rs` | An offer-supplied claim absent from `cred_type.claims` is **not** emitted (§2.5) |
| `crates/foundry/tests/wallet_issuance.rs` | Full flow: offer → `/token` → `/credential` → base64url-decode → parse as a bare `IssuerSigned` → `verify_issuer_signed`; then build a device response and run `verify_mdoc`, mirroring `wallet_verification.rs` |
| `crates/foundry/tests/quickstart_config.rs` | `quickstart_config_carries_both_credential_types` → `quickstart_config_carries_all_credential_types`, asserting all three ids. Renamed because "both" becomes false, and a test whose name contradicts its body is how the next person is misled |

The `foundry-mdoc` test is byte-level **by design**, not by preference. That
crate's `AGENTS.md` records that five format defects survived a green suite
because every test round-tripped foundry's builder through foundry's own
verifier; the verifier is being changed here too, so a round trip would agree
with itself about the envelope. The guard mirrors
`single_certificate_x5chain_is_a_bare_byte_string`, which reads CBOR directly and
deliberately does not call the verifier.

**Stretch, not a requirement:** Annex A §A.11 publishes a worked `IssuerSigned`
example. Decoding it to assert foundry's *shape* agrees would be third-party
evidence rather than self-agreement, in the spirit of
`tests/real_presentation.rs`. To be attempted, and dropped without ceremony if
the published example is truncated or elided.

### 4.1 Gate

Per root `AGENTS.md` §5.1, unchanged and without tiers:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

`cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only`
before the branch is opened as a PR, since `config.yaml` changes and
`e2e_full_flow` loads it.

---

## 5. Documentation fallout

- `docs/conformance/openid4vc-conformance.md`: VCI-0175 and VCI-0176 move
  `gap` → `conforming`, with the renamed tests as evidence; the GAP-VCI-12 and
  GAP-VCI-16 rows leave the gap register. The report is a living document, so
  this is part of the change, not a follow-up.
- Root `AGENTS.md`: the §4.4 spec row (§3.1 above).
- `crates/foundry-mdoc/AGENTS.md`: the "remaining known non-conformance is the
  OpenID4VCI credential envelope" gotcha is rewritten as closed — stated as a
  property of the current code, per that file's own warning about overstating —
  and gains the namespace-versus-doctype note.
- `crates/foundry-core/AGENTS.md`: the av.1 validation and the `namespace` field.
- `crates/foundry-issuer/AGENTS.md`: doctype resolution, config-filtered claims.
- `README.md` (`credential_types` section): the new credential type and the
  `namespace` field.
- **No OpenAPI regeneration.** No endpoint path, method, request/response shape
  or status code changes; `CreateOfferRequest` is untouched because validity is
  relative and claims are already carried there.

---

## 6. Out of scope

Recorded so a later reader can tell a decision from an omission.

- **Claim CBOR typing** (`full-date` tag 1004, `bstr`, `tdate` as *element*
  values). av.1 is booleans only. See §3.4.
- **MSO `status` / token status list embedding.** Out of scope in Annex A itself.
- **`keyAuthorizations` and `deviceKeyInfo.keyInfo`.** Modelled by isomdl,
  unused by this credential type, and absent from Annex A's examples.
- **`expectedUpdate`** in `validityInfo`. Optional in ISO 18013-5, unused here.
- **Absolute or per-offer validity windows.** Explicitly declined; see §1.1.
- **Shipping an `org.iso.18013.5.1.mDL` credential type.** §2.6 makes its
  namespace expressible; issuing one would additionally require the claim-typing
  machinery this design declines.
- **ISO/IEC 23220-3.** Annex A lists *"Profile of OpenID4VCI to issue ISO mDoc
  [ISO.18013-5]"* as out of its scope, deferring to 23220-3, which is neither
  vendored nor consulted here. foundry's OpenID4VCI behaviour continues to be
  governed by OpenID4VCI 1.0 and HAIP.

---

## 7. Reference implementation used

`isomdl` (`/Users/senexi/dev/eudiw/isomdl`) was surveyed as a **reference only**
and is deliberately **not** a dependency — root `AGENTS.md` §3's layering rules
and the workspace's no-vendored-protocol-crates posture both apply. What it
confirmed: the `Mso` field set, `ValidityInfo` as tag-0 `tdate` with
`validFrom` and optional `expectedUpdate`, `Tag24<T>` embedding for
`IssuerSignedItem`s and the MSO, `IssuerSigned` as `{nameSpaces, issuerAuth}`,
and that it models no status list and no OpenID4VCI. Those agreements are
corroboration of structures foundry already had; none of its code is copied.
