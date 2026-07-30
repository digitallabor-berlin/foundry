# Remove the Vendored `oid4vci` / `openid4vp` / `openid4vp-frontend` Crates

**Date:** 2026-07-30
**Status:** approved

## Problem

The workspace vendors three crates copied from Spruce upstream on 2026-07-17
(`docs/VENDORING.md`): `oid4vci` (6,383 lines / 51 files), `openid4vp` (7,135
lines / 29 files) and `openid4vp-frontend` (50 lines / 1 file) — ~13,568 lines
of third-party code in total.

Measured facts establishing the problem (all verified via `cargo metadata`,
`cargo tree -i` and full-text grep, not assumption):

1. **`oid4vci` has zero consumers.** No `foundry-*` crate declares it as a
   dependency. `cargo tree -i -p oid4vci` returns only the crate itself (as its
   own dev-dependency). The single textual reference anywhere in the repository
   is a doc comment at `crates/foundry-issuer/src/metadata.rs:3` noting that
   foundry defines its own metadata types *"from the vendored `oid4vci` crate's
   generic types"* — i.e. the replacement already exists and is in use. The
   crate is nonetheless a workspace member, so it compiles and runs its 24
   tests on every `cargo test --workspace` and is linted on every
   `cargo clippy --workspace --all-targets`.

2. **`openid4vp` is used for exactly three things**, ~1,500 of its 7,135 lines:

   | Item | Upstream module size | Consumers |
   |---|---|---|
   | `core::jwe::JweBuilder` | 484 lines | **13 call sites.** Production ×1: `crates/foundry-wallet/src/actions/verification.rs:156`. Tests ×12: `crates/foundry-verifier/src/verify.rs` lines 368, 402, 471, 536, 639; `crates/foundry/tests/wallet_verification.rs` lines 286, 437, 661, 783, 906, 1062; `crates/foundry/tests/e2e_full_flow.rs` line 436 |
   | `core::credential_format::ClaimFormatDesignation` | 277 lines | `crates/foundry-verifier/src/dcql.rs` — two variants only (`DcSdJwt`, `MsoMDoc`) |
   | `core::dcql_query::{DcqlQuery, DcqlCredentialQuery, DcqlCredentialClaimsQueryPath, DcqlCredentialClaimsQueryValue}` | 738 lines | `crates/foundry-verifier/src/dcql.rs` (248 lines) |

   Nothing from `verifier/`, `wallet.rs`, `authorization_request/`, `metadata/`,
   `response/`, `object/`, `iso_18013_7/` or `utils` is referenced. Foundry
   hand-rolled all of that behaviour already.

3. **`openid4vp` puts `ssi 0.16` and `json-ld` into production builds.** They
   are *normal* (not dev) dependencies of `openid4vp`, which is a normal
   dependency of `foundry-verifier` and `foundry-wallet`. Its dev-dependencies
   additionally pull `qrcode`, `image`, `did-method-key`, `rcgen 0.13` and
   `tower-http` into `cargo test --workspace`.

4. **21 crates in the workspace graph are reachable only via the vendored
   crates**, including two git-revision pins (`open-auth2` at rev `5d653ea`,
   `isomdl` at rev `7608053`) which cannot be audited or verified through
   crates.io. `Cargo.lock` holds 743 packages.

5. **Duplicate dependency versions.** `oid4vci` pins `axum 0.8`, `thiserror 1`,
   `rand 0.9`, `base64 0.21`; `openid4vp` pins `base64 0.21`. The workspace
   pins `axum 0.7`, `thiserror 2`, `rand 0.8`, `base64 0.22`.

6. **`openid4vp-frontend`** exposes two enums (`Status`, `Outcome`) and is
   referenced by no `foundry-*` crate; it exists solely because `openid4vp`
   path-depends on it.

7. **Licensing gap.** The repository has no `LICENSE` file, while the workspace
   `Cargo.toml` declares `license = "Apache-2.0"` and currently redistributes
   ~13,568 lines of Spruce's `MIT OR Apache-2.0` code with no top-level
   attribution.

The driver, in priority order, is **(a) supply-chain / audit surface** for an
eIDAS-adjacent service that may face certification, then **(b) build and CI
cost**, then **(c) direct control over protocol-model correctness**.

## Goal / Non-Goals

### Goal

Remove all three vendored crates from the workspace, replacing the three
`openid4vp` items that are genuinely used with clean-room foundry-owned code,
with **no change in observable behaviour**.

### Non-Goals

- No change to *which* DCQL features foundry supports. Array-wildcard path
  segments and `credential_sets` remain unsupported and fail-closed, exactly as
  today.
- No restructuring of `crates/foundry-verifier/src/dcql.rs`'s satisfaction
  logic. Only its `use` lines and one integer cast change.
- No new OpenID4VCI protocol-model layer to replace `oid4vci`. Foundry already
  owns its issuance types; `oid4vci` is deleted with nothing put in its place.
- No dependency-version-skew cleanup beyond what falls out of the deletion.
- No HTTP endpoint changes, therefore no OpenAPI shape changes.

## Approach

**Chosen: clean-room reimplementation of the used surface, then deletion.**

"Clean-room" is load-bearing here, not decorative. Requirements are derived
from (i) foundry's own consuming code, (ii) the OpenID4VP 1.0 specification,
and (iii) foundry's existing tests — **not** from reading
`crates/openid4vp/src/core/*.rs`. Copying upstream's implementation would leave
third-party code in place under a different path and forfeit the audit-surface
reduction that motivates the work. Implementers MUST NOT open the vendored
source files of the modules they are replacing.

### Rejected alternatives

- **Copy the three modules into foundry with attribution.** Cuts ~13,568 lines
  to ~1,500 and removes `ssi`/`json-ld`/`open-auth2` just as effectively, with
  near-zero behavioural risk. Rejected because third-party code — and the
  attribution obligation — would remain, which is precisely what driver (a) is
  buying out. Also inherits upstream's model shape instead of choosing it.
- **Hybrid: clean-room the JWE builder, copy the DCQL types, tighten later.**
  Sequences the risk more gently. Rejected by the user in favour of doing it
  once, properly.
- **Keep `openid4vp`, delete only `oid4vci`.** Captures the free win but leaves
  `ssi` and `json-ld` in production builds and 7,135 lines of third-party code
  supporting ~1,500 used lines. Insufficient for driver (a).
- **Re-add as crates.io dependencies instead of vendoring.** Reduces the
  in-repo line count but *increases* supply-chain exposure (upstream can
  change) and re-introduces the git-rev transitive pins. Contrary to driver (a).

## Design

### Component 1 — `foundry_core::crypto::jwe` (new)

New file `crates/foundry-core/src/crypto/jwe.rs`, registered in
`crates/foundry-core/src/crypto/mod.rs`.

```rust
pub fn encrypt_compact(
    payload: &serde_json::Value,
    recipient_public_jwk: &serde_json::Value,
    alg: &str,   // e.g. "ECDH-ES"
    enc: &str,   // e.g. "A128GCM"
) -> Result<String, CryptoError>
```

A free function, not a builder: all 13 call sites (1 production, 12 test) pass
the same four inputs in the same order — `payload`, recipient JWK, `"ECDH-ES"`,
`"A128GCM"`. A builder would exist only to mirror a general-purpose library's
ergonomics, and would make the 13 mechanical rewrites longer rather than
shorter.

Implementation uses `josekit` directly:
`josekit::jwe::ECDH_ES.encrypter_from_jwk(&jwk)` plus
`josekit::jwt::encode_with_encrypter(&payload, &header, &encrypter)`, with
`alg` and `enc` set on the JWE header. This is the exact inverse of the
verifier's existing decrypt path at `crates/foundry-verifier/src/verify.rs:49-53`
(`josekit::jwe::ECDH_ES.decrypter_from_jwk` +
`josekit::jwt::decode_with_decrypter`). Because both ends use the same JOSE
library, compact-serialization compatibility is structural rather than
empirical.

**Placement rationale.** Consumed by `foundry-wallet` (production) and by
`foundry-verifier` and `crates/foundry/tests` (tests) — two crates at different
layers, so root `AGENTS.md` §3 puts it in `foundry-core`. `foundry-core`
already depends on `josekit` (workspace pin `0.10`) and already performs JOSE
work in `crypto/signer.rs`; no new dependency is introduced anywhere.

**Error type.** Returns `crate::error::CryptoError`, the same error type
`crypto/signer.rs` uses. **No new error enum** — but exactly one new *variant*
is required and permitted:

```rust
#[error("JWE encryption failed: {0}")]
Jwe(String),
```

None of the existing variants fits: `UnsupportedAlgorithm` renders as
"unsupported **signature** algorithm '{0}'" (wrong noun for a JWE `enc` value),
`Generation` is documented as key/certificate generation, and `Sign`/`KeyLoad`
describe different operations. Emitting a misleading message to avoid adding a
variant would be the wrong trade.

The wallet call site maps the error into
`WalletError::MalformedRequestObject`, preserving today's error text shape
(`"invalid ephemeral jwk: {e}"` / `"JWE build failed: {e}"`).

**Known asymmetry that must be tested, not assumed.**
`crates/foundry-verifier/src/request.rs:92-102` deliberately annotates the
*public* ephemeral JWK with `kid`, `use: "enc"` and `alg`, while storing the
*private* JWK **bare**, so that josekit's decrypter carries no key id and does
not require the wallet to echo `kid` back in the JWE header. josekit's
`encrypter_from_jwk` may propagate that `kid` into the header. The first test
written MUST therefore be the full asymmetric round-trip — encrypt with the
annotated public JWK, decrypt with the bare private JWK, assert payload
equality — not a smoke test that a string is produced.

### Component 2 — `foundry_verifier::dcql_model` (new)

New file `crates/foundry-verifier/src/dcql_model.rs`, registered in
`crates/foundry-verifier/src/lib.rs` as **`mod dcql_model;` (crate-private)**.
No public signature exposes these types — `check_dcql_match(&Value,
PresentedFormat, &Value, Option<&str>)` takes raw JSON, and
`PresentedFormat::matches` is a private fn — so this is a net *reduction* in
public API surface versus today, where the types arrived via a public
dependency. Promote to `pub mod` only if an external consumer actually appears.
Written from OpenID4VP 1.0 §6 (Digital
Credentials Query Language), covering exactly the surface
`crates/foundry-verifier/src/dcql.rs` consumes:

```
DcqlQuery            { credentials: Vec<DcqlCredentialQuery> }
DcqlCredentialQuery  { id: String,
                       format: CredentialFormat,
                       meta: Option<serde_json::Value>,
                       claims: Option<Vec<DcqlClaimsQuery>> }
DcqlClaimsQuery      { path: Vec<ClaimsPathSegment>,
                       values: Option<Vec<ClaimValue>> }
ClaimsPathSegment    = String(String) | Index(u64) | Wildcard      (untagged)
ClaimValue           = String(String) | Integer(i64) | Boolean(bool) (untagged)
CredentialFormat     = DcSdJwt | MsoMdoc | Other(String)
```

Binding design decisions:

- **`meta` is an opaque `serde_json::Value`.** `dcql.rs` already reads it
  untyped (`cq.meta().get("vct_values")`, `cq.meta().get("doctype_value")`).
  Per-format typing is scope creep. The accessor returns `&Value`, defaulting
  to `Value::Null` when absent, so `.get(..)` keeps working unchanged
  (`Value::Null.get(..)` yields `None`).
- **`CredentialFormat::Other(String)` is mandatory.** Without a catch-all
  variant, a DCQL query naming any format foundry does not implement fails
  *deserialization*, so `check_dcql_match` would return
  `"dcql_query is not a valid DCQL query"` instead of
  `"no credential query in the DCQL query matches the presented credential
  format"`. That is an observable behaviour change in a security check.
  Today's semantics — an unknown format causes that credential query to be
  *skipped* — MUST be preserved.
- **No `serde(deny_unknown_fields)` anywhere.** DCQL is extensible; unknown
  members MUST be ignored rather than rejected.
- **Accessor names are preserved exactly**: `DcqlQuery::credentials()`,
  `DcqlCredentialQuery::{id, format, meta, claims}()`,
  `DcqlClaimsQuery::{path, values}()`. Consequently `dcql.rs` changes only its
  two `use` lines, the inline `use ... as V` at line 121, and one cast: the
  integer comparison becomes `found.as_i64() == Some(*i)` because
  `ClaimValue::Integer` is typed `i64` directly rather than requiring
  `*i as i64`.
- **Placement rationale.** Only `foundry-verifier` deserializes DCQL.
  `foundry-wallet`'s `actions/match_credentials.rs` operates on raw
  `serde_json::Value` and delegates to `foundry_verifier::check_dcql_match`, so
  it is unaffected and needs no DCQL types of its own. Putting the model in
  `foundry-core` would be speculative generality.

### Component 3 — Removal

1. Drop `openid4vp = { path = "../openid4vp" }` from
   `crates/foundry-verifier/Cargo.toml:12`,
   `crates/foundry-wallet/Cargo.toml:21`, and
   `crates/foundry/Cargo.toml:41` (the latter is a `[dev-dependencies]` entry).
2. Remove `crates/oid4vci`, `crates/openid4vp`, `crates/openid4vp-frontend`
   from `[workspace.members]` in the root `Cargo.toml`.
3. `git rm -r` the three directories.
4. Regenerate `Cargo.lock`.

Step 3 is the point at which the "`oid4vci` is unused" claim is *proven* by the
compiler rather than asserted from static analysis.

### Component 4 — Documentation and licensing

- Delete `docs/VENDORING.md`; its historical content is carried forward by the
  Phase 6 changelog entry.
- Delete `crates/oid4vci/AGENTS.md` and `crates/openid4vp/AGENTS.md` with their
  crates.
- Root `AGENTS.md`: remove the three vendored rows from the §2 routing table
  (currently lines 35-37) and the vendored-crates paragraph in §3 (line 63).
- `README.md`: remove the three vendored crate rows (currently lines 18-20).
  Line 269's `openid4vp://` URI reference is protocol vocabulary, not a crate
  reference, and stays.
- `crates/foundry-verifier/AGENTS.md:18`: replace the `openid4vp` dependency
  note with the new `dcql_model` module and add it to the module map.
- `crates/foundry-wallet/AGENTS.md:22` and `crates/foundry/AGENTS.md:20`:
  remove `vendored openid4vp` from the dependency lists.
- `crates/foundry/tests/AGENTS.md:59`: remove `vendored openid4vp` from the
  dev-dependency list and name `foundry_core::crypto::jwe` instead.
- `crates/foundry-core/AGENTS.md`: add `crypto/jwe.rs` to the module map.
- Add a root `LICENSE` file containing the Apache License 2.0, matching
  `license = "Apache-2.0"` in `[workspace.package]`. This is severable: it is
  the one element not strictly required by de-vendoring, and may be dropped
  without affecting any other task.
- Historical plans under `docs/superpowers/plans/*.md` are records of past
  work, not live guidance, and are left untouched.

### Data flow (unchanged)

The wallet builds a presentation, encrypts `{"vp_token": <presentation>}` to
the verifier's ephemeral public JWK, and POSTs the compact JWE to
`/vp/response/{id}`. The verifier decrypts with the stored bare private JWK,
extracts `vp_token`, verifies signatures and key binding, then calls
`check_dcql_match` with the merged disclosed claims. Only the *implementations*
of the encrypt step and of the DCQL deserialization change; the wire format,
the sequence, and the check names are identical.

### Error handling

- No new error *enums* in any crate. Exactly one new variant is added —
  `CryptoError::Jwe(String)` in `crates/foundry-core/src/error.rs` — for the
  reason given in Component 1. The DCQL model adds none: deserialization
  failures are already absorbed by `check_dcql_match`'s fail-closed path.
  Error-message shapes at all existing call sites are preserved.
- `check_dcql_match` remains fail-closed and infallible in signature: it
  returns a `CheckResult { check: "dcql_match", .. }` and never propagates an
  error, including on malformed DCQL input.
- Global invariant §4.1 (no `unwrap`/`expect`/`panic!` in request paths) applies
  to both new modules; `unwrap` is permitted only inside `#[cfg(test)]`.
- Global invariant §4.2 (`verified == checks.iter().all(|c| c.passed)`) is
  untouched by this work and must remain true.

## Global Constraints

- Rust edition 2021, `rust-version = "1.97"` (root `[workspace.package]`).
- No new dependency may be added to any crate. `josekit` (workspace `0.10`),
  `serde`, `serde_json` are all already present where needed.
- No new error enum anywhere; exactly one new variant (`CryptoError::Jwe`).
- `dcql_model` is declared crate-private (`mod`, not `pub mod`).
- Workspace dependency pins are authoritative: `base64 = "0.22"`,
  `josekit = "0.10"`, `thiserror = "2"`, `axum = "0.7"`, `rand = "0.8"`.
- Implementers MUST NOT read `crates/openid4vp/src/core/jwe.rs`,
  `crates/openid4vp/src/core/dcql_query.rs`, or
  `crates/openid4vp/src/core/credential_format/mod.rs`. Requirements come from
  foundry's consuming code, foundry's tests, and OpenID4VP 1.0 §6.
- Public accessor names on the new DCQL types MUST match the names listed in
  Component 2 exactly.
- No `serde(deny_unknown_fields)` on any DCQL type.
- `CredentialFormat` MUST have an `Other(String)` catch-all.
- No panics/unwraps in request paths outside `#[cfg(test)]` (root `AGENTS.md`
  §4.1).
- Dependency layering (root `AGENTS.md` §3) must be preserved:
  `foundry-core` depends on no `foundry-*` crate.
- Verification gates, all three, must pass cleanly before completion:
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check`.
- Every task ends on a green workspace test suite and its own commit. The
  workspace must never be left red between task commits.
- Branch: `superlight/2026-07-30-remove-vendored-crates`. No commits to `main`.

## Testing Strategy

**Baseline, measured on this branch before any change:** `cargo test
--workspace` → exit 0, 420 passed, 0 failed, 46 `test result: ok` lines.
`Cargo.lock` → 743 packages.

- **JWE round-trip (new, `foundry-core`).** Generate a P-256 keypair; annotate
  the public JWK with `kid`/`use`/`alg` exactly as
  `foundry-verifier/src/request.rs:92-102` does; keep the private JWK bare;
  `encrypt_compact` with the public JWK; decrypt with
  `josekit::jwe::ECDH_ES.decrypter_from_jwk` + `jwt::decode_with_decrypter`;
  assert the payload survives. Plus: unsupported `alg`/`enc` returns `Err`, not
  a panic; malformed recipient JWK returns `Err`.
- **JWE integration guard (existing).** All **12 test call sites** currently
  construct JWEs with the vendored builder:
  `crates/foundry-verifier/src/verify.rs` (5: lines 368, 402, 471, 536, 639),
  `crates/foundry/tests/wallet_verification.rs` (6: lines 286, 437, 661, 783,
  906, 1062), `crates/foundry/tests/e2e_full_flow.rs` (1: line 436). Every one
  is switched to `encrypt_compact`; each MUST otherwise pass **unmodified** —
  no assertion relaxation, no changed expectations. This is the real proof of
  wire compatibility, and its breadth is why it is the guard rather than the
  new unit test.
- **The e2e call site is `#[ignore]`d and needs an explicit run.**
  `crates/foundry/tests/e2e_full_flow.rs:483` is the only `#[ignore]`d test in
  the workspace, so `cargo test --workspace` never executes the JWE call site
  at line 436. Verification MUST additionally run
  `cargo test -p foundry --test e2e_full_flow -- --ignored`, or 1 of the 13
  migrated sites is unproven. If that test cannot run in the environment, that
  is a blocker to report, not a step to skip.
- **DCQL conformance guard (existing).** The `#[cfg(test)] mod tests` block in
  `crates/foundry-verifier/src/dcql.rs` (lines 175-248) exercises real DCQL
  JSON. It MUST pass **unmodified** against the rewritten model. If any of
  those tests need editing, the model is wrong — not the test.
- **DCQL model unit tests (new).** Unknown `format` value deserializes to
  `Other` and causes that credential query to be skipped rather than the query
  to be rejected; unknown object members are ignored; both untagged enums round
  trip (`ClaimsPathSegment::{String,Index,Wildcard}`,
  `ClaimValue::{String,Integer,Boolean}`); absent `claims` and absent `meta`
  both deserialize; `meta` accessor yields `Value::Null` when absent.
- **De-vendoring proof.** After Component 3: `cargo tree -i -p ssi`,
  `cargo tree -i -p oid4vci` and `cargo tree -i -p open-auth2` must all fail
  with "package not found"; `grep -c '^name = ' Cargo.lock` must be materially
  below 743; `grep -rn 'oid4vci\|openid4vp' --include='*.rs' crates/` must
  return no hits outside `openid4vp://` URI string literals.
- **Full gates** as listed in Global Constraints, run and observed before any
  completion claim — plus the `--ignored` e2e run noted above.
- **Expected post-deletion total:** 420 − 24 (`oid4vci`) − 86 (`openid4vp`) − 3
  (`openid4vp` doc-tests) = **307 passed**. The stronger invariant is that no
  `foundry*` test target's count changes; the plan carries the per-target
  baseline table for that comparison.

## Open Questions

None.