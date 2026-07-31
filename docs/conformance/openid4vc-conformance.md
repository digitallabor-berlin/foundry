# OpenID4VC Conformance Report

**Status:** in progress
**Scope:** `foundry-issuer`, `foundry-verifier`, and the protocol HTTP routes in `crates/foundry/src/server.rs`

This is a **living document**. It is not a snapshot of one audit run: later work
that closes a gap edits the affected rows in place. Do not duplicate its
contents into a changelog or a run artifact — link to it instead.

Its internal consistency is enforced mechanically by
`crates/foundry/tests/conformance_report.rs`, which runs as part of
`cargo test --workspace`. Edits that break the cross-references below will fail
that test.

## Specifications Under Audit

The authoritative texts are the pinned copies in [`docs/specs/`](../specs/), per
[`AGENTS.md`](../../AGENTS.md) §4.4 — not any newer draft published elsewhere.

| Short name | File | Pinned version |
|---|---|---|
| OpenID4VCI | [`openid-4-verifiable-credential-issuance-1_0.md`](../specs/openid-4-verifiable-credential-issuance-1_0.md) | `openid-4-verifiable-credential-issuance-1_0-17` |
| OpenID4VP | [`openid-4-verifiable-presentations-1_0.md`](../specs/openid-4-verifiable-presentations-1_0.md) | `openid-4-verifiable-presentations-1_0-30` |
| HAIP | [`openid4vc-high-assurance-interoperability-profile-1_0.md`](../specs/openid4vc-high-assurance-interoperability-profile-1_0.md) | `openid4vc-high-assurance-interoperability-profile-1_0-06` |

Where HAIP is stricter than OpenID4VCI or OpenID4VP, **HAIP wins**.

## Audit Boundary

**In scope**

- `foundry-issuer`, all modules.
- `foundry-verifier`, all modules.
- The protocol routes in `crates/foundry/src/server.rs`: `/token`, `/authorize`,
  `/nonce`, `/credential`, `/vp/request/:id`, `/vp/response/:id`,
  `/statuslists/:id`, and the `.well-known` metadata routes.

**Clause selection.** Mandatory clauses only — MUST, MUST NOT, REQUIRED, SHALL,
SHALL NOT — over features foundry implements. Per `AGENTS.md` §4.4,
unimplemented *optional* features are acceptable and are recorded as
`not-implemented`. SHOULD and RECOMMENDED clauses may carry a verdict but are
not systematically inventoried.

**Out of scope**, recorded explicitly so that silence is never mistaken for a
pass:

| Area | Reason |
|---|---|
| `foundry-wallet` | Debug client, not part of the issuer/verifier surface |
| SD-JWT VC format internals (disclosure encoding, KB-JWT structure) | Defining spec (IETF SD-JWT VC) not vendored under §4.4 |
| mdoc format internals (CBOR structure, MSO layout) | Defining spec (ISO/IEC 18013-5) not vendored and not vendorable — paid standard |
| Token Status List bitstring encoding | Defining spec not vendored |
| Wallet-side and third-party obligations | Recorded with `Applies to = wallet` / `other` and verdict `out-of-scope` |

What *is* in scope for the credential formats is what the three vendored specs
say about their **usage**: which formats must be supported, required algorithms,
key binding requirements, and the profile's constraints on `vct` and doctype
handling. That a status check happens and is honoured is in scope; whether the
bitset is decoded correctly is not.

## Legend — Verdicts

| Verdict | Meaning |
|---|---|
| `conforming` | Implemented and correct; `Evidence` cites code, `Test` cites the proving test |
| `gap` | Implemented incorrectly, or mandatory and absent; has a row in the gap register |
| `not-implemented` | Optional feature foundry does not offer; permitted by `AGENTS.md` §4.4. Rationale required |
| `not-unit-testable` | Transport, deployment, or operational requirement. Rationale required |
| `out-of-scope` | Outside the audit boundary above. Rationale required |
| `ambiguous` | Examined, but genuinely readable two ways. Terminal — makes no conformance claim, does not block completion. Listed under Unresolved Ambiguities |
| `unverified` | Not yet adjudicated. The remaining-work marker; must be zero when the audit is complete |

## Legend — Severity

| Severity | Meaning |
|---|---|
| `Critical` | Accepts something it must reject — a forged, replayed, or unauthorized credential or presentation |
| `Important` | A conformant counterparty fails to interoperate |
| `Minor` | No functional consequence — wording, ordering, or a redundant field |

## Identifiers

Clause identifiers are `VCI-NNNN`, `VP-NNNN`, `HAIP-NNNN`, zero-padded to four
digits, sequential in document order within each spec. Gap identifiers are
`GAP-VCI-NN`, `GAP-VP-NN`, `GAP-HAIP-NN`, `GAP-HTTP-NN`.

**Identifiers are never renumbered.** They are cited by `#[ignore]` reason
strings, commit messages, and follow-up work.

## Summary

| Spec | Total | conforming | gap | not-implemented | not-unit-testable | out-of-scope | ambiguous | unverified |
|---|---|---|---|---|---|---|---|---|
| OpenID4VCI | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| OpenID4VP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| HAIP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Gap Register

| ID | Severity | Spec § | Requirement | Impact | Test |
|---|---|---|---|---|---|

## Clause Inventory — OpenID4VCI

| ID | § | Requirement | Applies to | Verdict | Evidence | Test |
|---|---|---|---|---|---|---|

## Clause Inventory — OpenID4VP

| ID | § | Requirement | Applies to | Verdict | Evidence | Test |
|---|---|---|---|---|---|---|

## Clause Inventory — HAIP

| ID | § | Requirement | Applies to | Verdict | Evidence | Test |
|---|---|---|---|---|---|---|

## Unresolved Ambiguities

| ID | Spec § | Reading A | Reading B | Why it matters |
|---|---|---|---|---|