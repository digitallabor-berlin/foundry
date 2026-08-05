# EMVCo DPC Credential Type (roadmap item E)

**Date:** 2026-08-05
**Branch:** `feature/emvco-dpc-credential-type`
**Design:** [`docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md`](../specs/2026-08-05-emvco-dpc-credential-type-design.md)
**Plan:** [`docs/superpowers/plans/2026-08-05-emvco-dpc-credential-type-plan.md`](../plans/2026-08-05-emvco-dpc-credential-type-plan.md)

## Why

The Google Wallet vendor profile names one credential type — SD-JWT VC with
`vct = com.emvco.dpc.card` — and that was the last open item (**E**) of the A–E
Google Wallet compatibility roadmap. Items A–D are merged.

With the EMV® Digital Payment Credential Schema Framework finally available, the
assumption carried by the earlier design docs turned out wrong in both
directions. The credential is *smaller* than expected — three disclosable
claims, all top-level, no nesting — so the nested-selective-disclosure work that
looked like item E's core was not needed at all. But foundry could not issue a
schema-valid DPC credential, for three reasons that had nothing to do with
EMVCo and everything to do with pre-existing gaps in its own SD-JWT VC issuance
path.

## What shipped

Three vendor-neutral code changes, then the credential type as pure
configuration. **No code in the tree names EMVCo, DPC or Google.**

| | Change | Why it is not EMVCo-specific |
|---|---|---|
| 1 | `IssuerClaims.sub` is `Option<String>`, omitted by default | `sub_<transaction_id>` was a unique, static, always-disclosed correlation identifier in every credential foundry issued, leaking an internal transaction id to every verifier, read by nothing |
| 2 | `ClaimDef.required: Option<bool>` + `is_required()`, resolving to `!selectively_disclosable` | "mandatory" and "selectively disclosable" are different properties; conflating them meant a claim that is both was never validated |
| 3 | `CredentialType.validity_seconds: Option<u64>` + `resolved_validity_seconds()`, default `31_536_000` | a credential's lifecycle is independent of whatever it attests; `exp` was hardcoded to a year |
| 4 | `Config::validate()` rejects `validity_seconds: 0` and an empty claim `path` | both describe configurations that can never work |
| 5 | `com.emvco.dpc.card` in `QUICKSTART_CONFIG`, alongside `pid` | data, not code |

## The one behaviour change external consumers will notice

**Issued credentials no longer carry a `sub` claim** — for *every* credential
type, `pid` included, not just DPC. Nothing in this workspace read it, no
conformance clause depends on it (every `sub` row in the conformance report
concerns a different JWT), and `verify_sd_jwt_vc` ignores it. An out-of-tree
consumer keying off `sub_<transaction_id>` would break; none is known, and the
value was an internal transaction identifier that should not have been
load-bearing for anyone.

The capability is retained: setting `IssuerClaims.sub` to `Some(..)` still emits
the claim, and `foundry-sd-jwt-vc`'s `parses_and_verifies_valid_presentation`
keeps that path covered end to end.

## Signature change

`foundry_sd_jwt_vc::builder::IssuerClaims.sub` changed from `String` to
`Option<String>`. Any external caller constructing `IssuerClaims` must update.

## Conformance

`GAP-VCI-13` is **half-closed and narrowed, not removed.** Its emptiness half
(a claims path pointer must be non-empty) is now enforced by `Config::validate()`;
its typing half (`ClaimDef.path` is `Vec<String>`, so `null` and integer path
segments are unrepresentable) remains open. The register row, `VCI-0180` and
`VCI-0183` all record which half moved, and the `#[ignore]`d test is renamed to
`gap_vci_13_claims_path_pointer_cannot_express_null_or_index_segments` and
rewritten to cover only the surviving half.

No other clause verdict changed. OpenAPI specs are unchanged (verified by
regenerating, not assumed).

## The specification is deliberately not vendored

`docs/specs/emvco-dpc-schema-framework.md` is a **reference stub**, not a copy.
The EMVCo document is all-rights-reserved and an unpublished draft ("Associate
Review 2"); this repository is Apache-2.0, so committing it would purport to
convey redistribution rights the project does not hold. The stub records the
exact title, version and revision, the legal notice, where a reader obtains a
copy, and the interface facts foundry relies on — restated rather than quoted.

This introduced a third category in root `AGENTS.md` §4.4 alongside
standards-track specifications and vendor profiles, with an **external-reference
rule**: a stub records *which* revision the code was built against, never
substitutes for the text, and never acquires standards-track precedence.

## Things found while implementing that the plan had wrong

Recorded because each cost time and would cost it again:

1. **A test *does* assert on a credential's `sub`.** The plan claimed none did.
   `foundry-sd-jwt-vc`'s `parses_and_verifies_valid_presentation` pins the
   round-trip invariant that a *configured* `sub` survives verification. That
   site kept `Some` and its assertion rather than losing the coverage.
2. **The mdoc branch had its own hardcoded validity.** Applying
   `validity_seconds` to only the `dc+sd-jwt` branch would have shipped a config
   key that silently does nothing for half the supported formats. mdoc's MSO
   `validUntil` now uses the same resolver — but no test issues an mdoc through
   `handle_credential_request` and decodes MSO `validityInfo`, so that branch is
   covered only by the shared resolver's unit tests.
3. **`QUICKSTART_CONFIG` is a Rust raw string**, so `"#` terminates it.
   Double-quoted hex colours (`"#1A1A2E"`) do not compile; the shipped colours
   are single-quoted YAML, with a comment saying why — and the comment itself had
   to be reworded to avoid the same sequence.
4. **The gap-register table is parsed by splitting on `|`.** An escaped pipe
   inside an evidence cell silently shifts every later column, and the register's
   Test column must name exactly *one* ignored test, unlike clause rows, which
   accept a comma-separated list. `conformance_report.rs` caught both.
5. **Struct-literal blast radius**: 31 `IssuerClaims`, 17 `ClaimDef` and 25
   `CredentialType` sites — the plan's counts (32/18/28) had included struct
   definitions, `impl` blocks and one `..ct` update form.
6. **`foundry-verifier` is an affected crate** — its test module builds 17
   `IssuerClaims` fixtures. The design's original gate list omitted it.
7. **The README had no credential-type config table** to extend, so the
   documentation landed as a new prose section in the style of the surrounding
   feature sections.

## Open issues carried forward

Unchanged from the design doc's §8, none of them started:

1. **Verifier / DCQL** — no `com.emvco.dpc.card` named query ships, and whether a
   DCQL `values` filter matches an *array-valued* `network` is still unverified.
   Issuance now definitively preserves both the string and array forms verbatim
   (both are tested), so the remaining question is purely about matching.
2. **Display metadata** (`com.emvco.dpc.card.meta`) — the `card` object on the
   Credential Offer and Credential Response. Needs per-instance display plumbing
   and an extension to two wire structures OpenID4VCI 1.0 does not define.
3. **mdoc binding** — `docType` and namespace `com.emvco.dpc.card`.
4. **Two contradictions inside the draft** — `additionalProperties: false`
   alongside samples carrying `_sd`/`_sd_alg`; and a security section mandating
   status checks against a schema with no room for a `status` claim. foundry keeps
   status lists enabled and the quickstart config says so.
5. **Draft instability** — Associate Review 2. The canonical `vct` is stated as
   stable; individual claim definitions may move.
6. **`vct` is never validated as a URI.** foundry now ships both a URL (`pid`)
   and a reverse-DNS identifier (DPC) with no stated rule.
7. **Google issuer onboarding** — Google hard-codes issuer metadata and must be
   sent the metadata document first. Operational, still gating.