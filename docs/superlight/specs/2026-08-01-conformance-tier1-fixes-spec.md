# Conformance Tier 1 — Close the Five Highest-Priority Audit Gaps

**Date:** 2026-08-01
**Status:** approved

## Problem

The OpenID4VC conformance audit completed 2026-07-31
([`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md))
adjudicated 592 clauses across OpenID4VCI, OpenID4VP and HAIP, and filed **26
gaps** — 2 Critical, 14 Important, 10 Minor. Every gap carries an `#[ignore]`d
test that fails for the documented reason; none has been fixed.

A triage on 2026-08-01 re-verified the audit (the 11 `conformance_report.rs`
consistency checks pass; all 27 gap tests still fail as designed) and sorted the
register into fix tiers. **Tier 1** is the five gaps that combine high
consequence with contained blast radius:

| Gap | Severity | One-line problem |
|---|---|---|
| GAP-HAIP-04 | Critical | `DefaultAttestationVerifier::verify_wallet_attestation` only checks that the `OAuth-Client-Attestation` header is *present*. Any arbitrary non-JWT string is accepted even with `mode = Required` — a full client-authentication bypass. |
| GAP-VCI-03 | Important | The `mso_mdoc` branch of `handle_credential_request` encodes the CBOR credential with base64 **standard**, not base64url, so the `credential` string can contain `+`, `/` and `=` and is rejected by a conformant base64url-only decoder. |
| GAP-VCI-01 | Important | `handle_pre_authorized_code_grant` never invalidates the `pre-authorized_code`, so it can be redeemed for unlimited fresh access tokens until the credential is claimed. |
| GAP-HAIP-06 | Important | `allocate_status_index` deduplicates per `credential_type_id`, but every credential type shares one physical status list, so two credentials of different types can be allocated the same index — revoking one silently revokes the other. |
| GAP-VP-07 | Important | `do_verify_vp_response` always expects the `x509_san_dns` Client Identifier as the KB-JWT audience, so it rejects every conformant wallet's `dc_api` presentation, which the spec requires to be bound to the Origin. |

Left unfixed, three of these are interoperability blockers against any real
wallet, one is a security bypass, and one is a status-integrity defect that can
revoke an unrelated credential.

## Goal / Non-Goals

### Goal

Close GAP-HAIP-04, GAP-VCI-03, GAP-VCI-01, GAP-HAIP-06 and GAP-VP-07, and bring
the conformance report into agreement with the resulting code — flipping the
affected clause verdicts, removing the `#[ignore]` from every test that cites a
now-closed gap, and keeping `conformance_report.rs`'s 11 consistency checks
green throughout.

### Non-Goals

Stated explicitly so they do not look accidentally handled:

- **Client Attestation PoP verification.** The complete client-authentication
  mechanism of `draft-ietf-oauth-attestation-based-client-auth` also requires an
  `OAuth-Client-Attestation-PoP` JWT proving possession of the attested key.
  This work validates the attestation JWT only. The PoP absence is filed as a
  new tracked gap, **GAP-VCI-14** (Important), with its own `#[ignore]`d test.
- **The `status_index.rs` `TODO(concurrency)`.** The CSPRNG draw plus
  get-then-put check-and-set is not atomic; concurrent allocators can still race
  onto the same index regardless of the key shape. Fixing it needs a
  compare-and-swap primitive on `foundry_core::storage::Storage`, and
  `crates/foundry-issuer/AGENTS.md` explicitly warns against fixing it locally.
  Untouched here.
- **mdoc binding over the DC API.** GAP-VP-07's fix corrects the SD-JWT VC
  KB-JWT audience only. An mdoc presentation binds through the
  `SessionTranscript`, which is GAP-VP-06 (Critical, Tier 2). mdoc over `dc_api`
  remains broken after this work, and clause VP-0209 therefore stays `gap`.
- **Per-credential-type status lists.** Considered and rejected — see Approach.
- **Tiers 2–5 of the triage** (GAP-VP-06 mdoc handover; the cheap-win sweep;
  DPoP, `x509_hash`, `scope`, `transaction_data_hashes`; the Minor batch).

## Approach

Five independent fixes plus one bookkeeping change. Each fix already has a
failing test in the workspace asserting the *correct* behaviour, written during
the audit and verified genuinely red at that time. **Those tests are the green
targets** — they are not to be rewritten, only un-`#[ignore]`d. That is the
strongest available evidence that what gets fixed is what the audit actually
found.

### Rejected alternatives

- **GAP-HAIP-04 — implement the PoP JWT in this run.** Rejected: it is a
  separate mechanism needing a `jti` replay store and an `aud` decision, roughly
  doubling the work and mixing a new subsystem into five otherwise-contained
  fixes. The register's Critical finding is specifically the presence-only
  check, which the attestation-JWT validation closes on its own.
- **GAP-HAIP-06 — give each credential type its own physical status list.**
  Rejected: it would make `PersistentStatusList.credential_type` and the
  `foundry status-list` CLI flag honest (today the field holds a *list id* and
  is hardcoded to `"1"`), and the `/statuslists/:id` route already takes the
  parameter — but it invalidates the `.../1` URI embedded in every
  already-issued credential, and it shrinks the per-list anonymity set, which is
  a holder-privacy regression the Token Status List specification cares about.
  Status-list topology is its own design change; the audit's finding is
  precisely that dedup scope ≠ list scope, which the chosen fix corrects
  directly.
- **GAP-VP-07 — derive the expected Origin solely from `public_base_url`.**
  Rejected as the *only* mechanism: the Origin is the origin of the page that
  invoked the DC API, which need not be foundry's API origin, and per OpenID4VP
  L618 the Origin binding is what replaces Client Identifier authentication on
  this transport. Guessing it wrong fails closed and looks like a wallet bug.
  Retained only as the fallback when no origin is configured.
- **GAP-VP-07 — carry the Origin per request** (a field on
  `CreateVerificationRequest`, persisted on the transaction). Rejected for now:
  more precise for a multi-front-end deployment, but it expands the admin API
  and `openapi.json` for a case no current deployment has.
- **Report bookkeeping — record the PoP deferral in the changelog only.**
  Rejected. `conformance_report.rs` refuses a register entry that no
  `gap`-verdict clause cites, so tracking the PoP as a gap requires a clause to
  exist. The clause set is also genuinely incomplete here (see Design), and an
  audit whose value is completeness should fix that rather than route around it.

## Design

### 1. GAP-HAIP-04 — validate the Wallet Attestation JWT

`crates/foundry-issuer/src/attestation.rs`, `token.rs`; `crates/foundry/src/server.rs`.

The trait gains the inputs real validation needs:

```rust
fn verify_wallet_attestation(
    &self,
    mode: Mode,
    attestation_header: Option<&str>,
    trust_store: &TrustStore,
    now_unix: i64,
) -> Result<(), IssuanceError>;
```

`handle_token_request`'s `attestation_mode: Mode` parameter becomes
`wallet_attestation: &AttestationMode`; token.rs builds the `TrustStore` from
its `.trusted_anchors`, mirroring how `credential.rs` sources the *key*
attestation store from `config.issuer.key_attestation.trusted_anchors`.
`server.rs` passes `&state.config.issuer.wallet_attestation`.

Validation mirrors the existing `verify_key_attestation_jwt` in the same file:

1. Three-part JWS split.
2. `typ` header MUST be `oauth-client-attestation+jwt`
   (OpenID4VCI Appendix E, L2564).
3. `alg` MUST NOT be `none` or symmetric (`HS*`).
4. `x5c` header REQUIRED and non-empty (HAIP L225).
5. Signature verified with ES256 against the leaf certificate's SPKI.
6. `validate_chain(leaf, intermediates, trust_store, now)` against the
   configured Wallet-Provider anchors (OpenID4VCI L2555 — the Authorization
   Server MUST verify the attestation is signed by an issuer it trusts).
7. `exp` REQUIRED and unexpired; `nbf` honoured when present.
8. `cnf.jwk` and `sub` REQUIRED (OpenID4VCI Appendix E) — extracted and
   returned so the deferred PoP work has them available.

**Mode semantics.** `Disabled` skips entirely. `Required` errors on absence,
then validates. `Optional` validates **whenever a header is present** and errors
only on invalidity, never on absence. Presence-vs-validity is the distinction
the audit found collapsed; mode governs only whether absence is tolerated.

### 2. GAP-VCI-03 — base64url-encode the mdoc credential

`crates/foundry-issuer/src/credential.rs`. The `mso_mdoc` arm's
`B64STD.encode(cbor_bytes)` becomes `B64URL` (`URL_SAFE_NO_PAD`), per
OpenID4VCI Credential Response L976. No downstream decoder changes: the
remaining `B64STD` uses are x5c entries, which are correctly base64-standard per
RFC 7515.

### 3. GAP-VCI-01 — burn the pre-authorized code

`crates/foundry-issuer/src/transaction.rs`, `token.rs`. Add
`invalidate_pre_authorized_code`, a twin of the existing
`invalidate_authorization_code`, deleting the `PRE_AUTH_NS` lookup entry. In
`handle_pre_authorized_code_grant`, call it **after** the `tx_code` check
passes, then set `tx.pre_authorized_code = None` before minting.

Both steps are load-bearing: `save_transaction_with_indices` re-writes the
`PRE_AUTH_NS` entry whenever `tx.pre_authorized_code` is `Some`, so deleting
without clearing the field would resurrect the index. Burning only after full
validation matches the reasoning already recorded in the `authorization_code`
branch — an attacker probing with a wrong `tx_code` must not be able to destroy
the legitimate holder's code (OpenID4VCI Credential Offer L396).

### 4. GAP-HAIP-06 — deduplicate against the physical list

`crates/foundry-issuer/src/status_index.rs`, `create_offer.rs`.
`allocate_status_index` takes the **status list id** it is allocating within and
keys its used-marker on `{list_id}:{idx}`. `create_offer` passes the same `"1"`
literal it already uses when creating the backing `PersistentStatusList`, so
allocation scope and physical-list scope become identical by construction.

`credential_type_id` is retained as a `tracing` field and in the
`StatusListExhausted` payload for diagnostics; its message is reworded so it no
longer implies a per-type list.

### 5. GAP-VP-07 — Origin-prefixed audience over the DC API

`crates/foundry-core/src/config/model.rs`,
`crates/foundry-verifier/src/verify.rs`,
`crates/foundry-sd-jwt-vc` (verifier signature).

New optional config `verifier.dc_api_expected_origins: Vec<String>`, defaulted
empty. In `do_verify_vp_response` the expected audience becomes a set:

- `tx.transport == "dc_api"` → each configured origin prefixed with `origin:`;
  when the list is empty, fall back to the origin derived from
  `server.wallet_facing.public_base_url`, and record that fallback in a log
  field so it is diagnosable.
- otherwise → the existing single `x509_san_dns:<host>` Client Identifier.

`foundry-sd-jwt-vc`'s `verify_sd_jwt_vc` takes a slice of acceptable audiences
instead of a single `&str`; existing call sites pass a one-element slice.

**Trailing-slash deviation.** OpenID4VP's own examples write
`origin:https://verifier.example.com/` (L618, L2543) while RFC 6454 origin
serialization carries no trailing slash. Both the configured value and the
received `aud` are normalized by stripping one trailing slash before comparison.
This is a deliberate leniency and carries an inline comment citing the spec
section, per root `AGENTS.md` §4.4.

### 6. Report bookkeeping

`docs/conformance/openid4vc-conformance.md` and the tests that cite it.

Clause verdicts flipping `gap` → `conforming`, each with the `#[ignore]` removed
from the test named in the register (root `AGENTS.md` §8):

| Gap | Clauses affected |
|---|---|
| GAP-HAIP-04 | HAIP-0031 → `conforming`. **HAIP-0088 stays `gap`**, re-cited to GAP-VCI-14: its text is "ES256 for validating Wallet Attestations *including proof of possession*". |
| GAP-VCI-01 | VCI-0003, VCI-0012 → `conforming` |
| GAP-VCI-03 | VCI-0071, VCI-0176 → `conforming` |
| GAP-HAIP-06 | HAIP-0081 → `conforming` |
| GAP-VP-07 | VP-0265 → `conforming`. **VP-0209 stays `gap`**, re-cited to GAP-VP-06 with its `Test` column repointed to that gap's handover test: VP-0209 covers *all* DC API responses and mdoc's binding remains broken. |

**Closing a gap deletes its register row.** This is not optional bookkeeping —
`gap_clauses_and_gap_register_reference_each_other` asserts in both directions,
so once the last clause citing a gap flips to `conforming`, the orphaned
register entry fails the check. GAP-HAIP-04, GAP-VCI-01, GAP-VCI-03,
GAP-HAIP-06 and GAP-VP-07 are therefore removed from the register, and
GAP-VCI-14 is added. The register shrinks from 26 rows to 22.

Correspondingly, `every_ignored_gap_citation_is_registered` forces the
`#[ignore]` attributes citing the five closed gaps to be removed in the *same*
commit that deletes their register rows — a test still claiming
`#[ignore = "GAP-VCI-01: ..."]` after that row is gone fails the check. The two
edits are one atomic change, not a cleanup pass.

Two clauses are appended to the OpenID4VCI inventory:

- **VCI-0231** — OpenID4VCI Wallet Attestation (L2555), "The Authorization
  Server MUST verify that the Wallet Attestation is signed by an issuer that the
  Credential Issuer trusts for this purpose", scope `issuer`. This is an
  extraction miss from the original audit: an unambiguous issuer obligation with
  no clause ID anywhere in the inventory. Verdict `conforming` once Design §1
  lands.
- **VCI-0232** — issuer-side verification of the Client Attestation PoP JWT
  (OpenID4VCI L2600 read against the issuer, complementing the existing
  wallet-scoped VCI-0195), scope `issuer`. Verdict `gap` → **GAP-VCI-14**.

Both append at the end of the VCI inventory rather than renumbering, per the
report's existing "identifiers are never renumbered" policy; a one-line note is
added to the Identifiers section recording that late-added clauses append and so
may sit out of spec-line order.

All three Summary rows change, not only OpenID4VCI's: the VCI total goes
230 → 232 with `conforming` and `gap` both moving, OpenID4VP's `conforming`/`gap`
split shifts by one (VP-0265), and HAIP's shifts by two (HAIP-0031, HAIP-0081).
`summary_counts_match_the_inventories` recomputes them from the tables, so the
numbers must be derived from the final inventory rather than hand-adjusted.

## Global Constraints

- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside
  `#[cfg(test)]` in `foundry-issuer`, `foundry-verifier`, `foundry::server`
  (root `AGENTS.md` §4.1).
- **Every `#[tracing::instrument]` MUST carry `skip_all`** (root `AGENTS.md`
  §4.5); enforced by `crates/foundry/tests/instrumentation_hygiene.rs`.
- **Never log** attestation JWTs, private/ephemeral JWKs, access tokens,
  `c_nonce` values, pre-authorized codes or transaction codes. Public keys only
  as RFC 7638 thumbprints (root `AGENTS.md` §4.5); enforced by
  `crates/foundry/tests/logging_redaction.rs`.
- **`verified` MUST equal `checks.iter().all(|c| c.passed)`** — never hardcoded
  (root `AGENTS.md` §4.2).
- **Policy vs structural vs network** error classification unchanged: policy →
  HTTP 200 `verified: false`; structural/crypto → 400; network → 502 (root
  `AGENTS.md` §4.3). A new `IssuanceError`/`VerificationError` variant without a
  matching arm in `crates/foundry/src/server.rs` silently yields HTTP 500.
- **Dependency layering** is one-directional; `foundry-core` depends on no
  `foundry-*` crate (root `AGENTS.md` §3).
- **Protocol changes cite their spec section in a code comment** (root
  `AGENTS.md` §4.4). Governing texts: OpenID4VCI L396 (single-use
  pre-authorized code), L976 (base64url binary credential), L2555 + Appendix E
  L2564/L2600 (Wallet Attestation), HAIP L225 (x5c), HAIP L329 (unique status
  index), OpenID4VP L618/L2543/L3179 (DC API Origin audience).
- **`conformance_report.rs`'s 11 consistency checks stay green** at every commit
  — not only at the end.
- **Existing audit gap tests are un-`#[ignore]`d, never rewritten.**
- **OpenAPI:** `openapi.json` / `openapi-wallet.json` regenerated if any
  endpoint shape changes (root `AGENTS.md` §6). No endpoint shape change is
  expected; this is a verification step, not a deliverable.
- **Gates:** `cargo test --workspace`, `cargo test --workspace --no-fail-fast --
  --ignored` (only still-open gaps may fail), `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo fmt --check` (root `AGENTS.md` §5).

## Testing Strategy

TDD per fix. The workspace has a working test suite, so the Phase 4 test-suite
precondition is satisfied and TDD is mandatory.

For each gap the cycle is inverted from the usual red step, because the red test
already exists: remove the `#[ignore]`, confirm it fails for the documented
reason, implement minimally, confirm green.

Additional behaviours to cover:

- **GAP-HAIP-04** — a validly signed, trust-anchored attestation is accepted;
  an arbitrary non-JWT string is rejected; a JWT signed by an untrusted anchor
  is rejected; `alg: none` and `HS256` are rejected; a missing `x5c` is
  rejected; an expired attestation is rejected; `Optional` mode validates a
  present header but tolerates absence; `Disabled` skips both.
- **GAP-VCI-03** — the issued `mso_mdoc` credential string decodes under
  base64url and contains none of `+`, `/`, `=`.
- **GAP-VCI-01** — a second `/token` call with the same `pre-authorized_code`
  fails; a call with a *wrong* `tx_code` does **not** burn the code, and the
  legitimate holder still succeeds afterwards.
- **GAP-HAIP-06** — two different `credential_type_id`s allocating against the
  same list with `list_size = 1` cannot both succeed.
- **GAP-VP-07** — a `dc_api` presentation whose KB-JWT `aud` is the
  Origin-prefixed configured value verifies; the `public_base_url` fallback
  works when no origin is configured; trailing-slash and no-trailing-slash forms
  both match; a `request_uri` transport still requires the `x509_san_dns`
  Client Identifier and rejects an Origin-prefixed audience.
- **GAP-VCI-14** — a new `#[ignore]`d test asserting that a Wallet Attestation
  presented without a valid `OAuth-Client-Attestation-PoP` is rejected, citing
  GAP-VCI-14.

## Open Questions

None.