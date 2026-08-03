# Conformance Tier 4 — Three Important Gap Closures (`x509_hash`, `scope`, `transaction_data_hashes`)

**Date:** 2026-08-03
**Status:** approved
**Branch:** `conformance-tier4-fixes` (base: `main`)

## Problem

The 2026-08-01 conformance triage
([`2026-08-01-conformance-tier1-fixes-spec.md`](2026-08-01-conformance-tier1-fixes-spec.md),
"Non-goals") sorted the audit's gap register into five fix tiers. Tiers 1–3 have
landed. **Tier 4** was defined as "DPoP, `x509_hash`, `scope`,
`transaction_data_hashes`" — the four remaining `Important` gaps.

DPoP (GAP-HAIP-03) is deliberately **excluded** from this spec: it is a new
subsystem (proof-header verification, `jkt` access-token binding, a `jti` replay
store, a `DPoP-Nonce` decision) whose weight exceeds the other three combined,
and this repository's precedent is that architectural additions get their own
cycle — GAP-VCI-14's Client Attestation PoP JWT was split out of Tier 1 for
exactly this reason. It follows immediately after, with `docs/specs/rfc9449-dpop.txt`
(already fetched, currently untracked) pinned as part of *that* work.

This spec covers the remaining three:

| Gap | Severity | Site | Cause (per register) |
|---|---|---|---|
| GAP-HAIP-05 | Important | `foundry-verifier/src/request.rs` | `build_signed_request_object` always emits `client_id: "x509_san_dns:<host>"`; HAIP mandates the `x509_hash` Client Identifier Prefix for signed requests |
| GAP-HAIP-01 | Important | `foundry-issuer/src/metadata.rs`, `authorize.rs`; `foundry-core/src/config/` | No `scope` anywhere: `CredentialConfigurationSupported` has no field, `AuthorizeParams` has no parameter |
| GAP-VP-04 | Important | `foundry-verifier/src/verify.rs`, `request.rs`; `foundry-sd-jwt-vc/src/builder.rs` | `transaction_data_hashes` is never emitted, read, or checked; a presentation with no transaction binding verifies as if it had one |

Each gap already has a named `#[ignore]`d test in the workspace, written during
the audit and verified genuinely red at that time. **Those tests are the green
targets.** They are not to be rewritten — only un-`#[ignore]`d — except where
this spec explicitly says otherwise.

## Goal / Non-Goals

**Goal.** Move all three gaps from `gap` to `conforming` in
[`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md),
with each formerly-`#[ignore]`d test passing and the **scoped** gates of
`AGENTS.md` §5.1 clean per task.

**Non-goals.**

- **DPoP / sender-constrained access tokens** (GAP-HAIP-03). Its own cycle; see
  above. `docs/specs/rfc9449-dpop.txt` stays untracked here and is **not** added
  to the `AGENTS.md` §4.4 table by this work.
- **mdoc transaction-data binding.** OpenID4VP L3144 is the *IETF SD-JWT VC*
  profile's mechanism (`transaction_data_hashes` in the KB-JWT). An mdoc
  presentation binds through `SessionTranscript`, a different mechanism, and no
  register row demands it here. GAP-VP-04's own test is SD-JWT VC only.
- **The nine `Minor` gaps** (GAP-VCI-05/06/07/10/11/12/13, GAP-VP-03/05). Tier 5.
  Their `#[ignore]`s stay.
- **The `validate_chain` trust-anchor ambiguity** (HAIP-0039 / HAIP-0079 /
  HAIP-0084). One shared fix closes all three rows, but the two readings are
  genuinely open and listed under Unresolved Ambiguities; resolving them is a
  deliberate decision, not a bug fix. Untouched.
- **PAR** (HAIP-0007, `ambiguous`). Architectural addition pending a reading
  decision. Untouched.
- **A configurable Client Identifier Prefix.** Rejected — see Decision 1.

## Approach

Three independent fixes. Five decisions were genuinely open; the pinned specs
and the existing tests did not settle them, and they were decided as follows.

### Decision 1 — GAP-HAIP-05 swaps the prefix unconditionally (chosen: **a**)

- **(a) Unconditional swap.** Every signed request emits
  `x509_hash:<base64url(SHA-256(DER leaf))>`; `x509_san_dns` disappears from the
  codebase. **Chosen.**
- **(b) Configurable prefix with `x509_hash` as the default.** Rejected: HAIP is
  a profile foundry claims to implement, and per `AGENTS.md` §4.4 "where HAIP is
  stricter, HAIP wins". A toggle that lets an operator turn *off* profile
  conformance adds a branch to every dependent check (the SAN cross-check, the
  `response_uri` same-origin check) and would force every affected conformance
  row to carry a "conforming only when configured per HAIP" caveat.
- **(c) Emit both prefixes.** Not viable: `client_id` is a single string, and VP
  L616 requires all Verifier metadata other than the public key to come from
  `client_metadata`.

### Decision 2 — `verifier.client_id_scheme` is deleted, not narrowed (chosen: **b**)

The field (`foundry-core/src/config/model.rs`, `VerifierConfig.client_id_scheme`)
is **dead**: declared, documented in `config.yaml` as `x509_san_dns`, set in
every test fixture and in the `commands.rs` init template — and never read by any
production code path. `build_signed_request_object` hardcodes the prefix and
ignores it.

- **(a) Make it authoritative, restricted to `x509_hash`.** `Config::validate()`
  would reject any other value. Rejected: given Decision 1, the field would have
  exactly one legal value, which is not configuration but a required incantation
  — and it would force every existing `config.yaml` to be edited or the server
  refuses to start.
- **(b) Delete it.** **Chosen.** The config structs carry **no**
  `#[serde(deny_unknown_fields)]`, so an existing `config.yaml` that still lists
  `client_id_scheme` keeps loading — serde ignores the unknown key. Removal is
  therefore silently backward-compatible, and it eliminates a field that
  documents a choice foundry does not offer.

**Note for spec review:** this deletes a documented config key. If preserving it
for operator familiarity matters more than removing a knob that never worked,
(a) is the fallback — but then `config.yaml`, `commands.rs`'s template, and every
fixture must move to `x509_hash` in the same change.

### Decision 3 — `x5c` becomes mandatory for signed requests (chosen: **a**)

- **(a) Absent `x5c` is a configuration error.** **Chosen.** Under `x509_hash`
  the Client Identifier *is* a hash of the leaf certificate; without a
  certificate there is no identifier to emit. `build_signed_request_object`
  returns `VerificationError::Crypto` naming the missing
  `keys.<verifier.signing_key>.x5c`. This is a config fault surfaced at
  request-build time, not a request-path panic — `AGENTS.md` §4.1 is satisfied
  because it is a typed `Result`, not an `unwrap`.
- **(b) Fall back to `x509_san_dns` when `x5c` is absent.** Rejected: that is
  Decision 1(b) reintroduced through the back door, and it makes conformance
  depend on whether a certificate happens to be configured.

### Decision 4 — GAP-HAIP-01 closes all four rows, with a config-authored scope defaulting to the credential-type `id` (chosen: **b**)

- **(a) Derive the scope from `ct.id` with no config surface.** Rejected: it
  hardcodes the assumption that foundry's internal `id` is an acceptable public
  scope string. Ecosystems hand deployments fixed scope values; retrofitting one
  later means changing a *published* metadata value, which breaks every wallet
  that cached it.
- **(b) Optional `credential_types[].scope`, defaulting to `ct.id`.**
  **Chosen.** The derivation still happens with nothing configured, so the common
  case costs no configuration, but an operator can publish an ecosystem-mandated
  value from the start.
- **(c) Metadata-only, leaving HAIP-0027/0028 open.** Rejected: it turns the named
  test green without making the profile claim true. Per `AGENTS.md` §4.4, an
  incorrect implementation is worse than an absent one.

### Decision 5 — GAP-VP-04 gets its own named check plus builder support (chosen: **a**)

- **(a) New `transaction_data_binding` `CheckResult`, `attach_kb_jwt` gains an
  optional parameter, and a new positive test is added.** **Chosen.**
- **(b) Fold the check into `sd_jwt_vc_signature_and_kb_jwt`.** Rejected: it
  files a *policy* failure under a *structural/crypto* check name, colliding with
  `AGENTS.md` §4.3 — and the error-stage mapper in `verify.rs` names stages after
  check names, so an operator could not distinguish "the wallet did not bind the
  transaction" from "the KB-JWT signature is bad".
- **(c) Negative test only, no builder change.** Rejected: the existing
  `#[ignore]`d test is negative (it asserts a presentation *without* a binding
  fails). A blanket "reject every presentation whenever `transaction_data` was
  requested" implementation also passes it. Without the builder change nothing in
  the workspace can construct a *correctly* bound presentation, so the property
  that makes these ignored tests trustworthy — verified red against *correct*
  behaviour — would be lost.

## Design

### Fix 1 — GAP-HAIP-05: the `x509_hash` Client Identifier Prefix

**Spec basis.** HAIP OpenID4VP L256 ("For signed requests, the Verifier MUST use
... the Client Identifier Prefix `x509_hash`"), narrowing OpenID4VP §5.9.3;
OpenID4VP L616 defines the value as "the base64url-encoded value of the SHA-256
hash of the DER-encoded X.509 certificate".

**Changes in `crates/foundry-verifier/src/request.rs`:**

1. `build_signed_request_object`: read the configured `x5c` PEM **first** (it is
   now required) and build `client_id = format!("x509_hash:{value}")`.

   **The hash computation goes in `foundry-core`, not the verifier.** Add
   `pub fn x509_hash_client_id_value(leaf_pem: &[u8]) -> Result<String, TrustError>`
   to `crates/foundry-core/src/trust/mod.rs`: `parse_cert_pem` → `cert.to_der()`
   → SHA-256 → base64url-unpadded. Two reasons this belongs there and not in
   `request.rs`: that module already owns every PEM/DER/`x5c` operation
   (`build_x5c`, `match_san_dns`, `x5c_entry_to_pem` all take or return exactly
   these shapes and follow the `leaf_pem: &[u8]` signature convention), and
   **`foundry-verifier` has no `sha2` dependency** while `foundry-core` already
   does. Note `foundry-core`'s `trust` module aliases `B64` to base64
   **STANDARD** (for `x5c` per RFC 7515), whereas this value is base64url
   **unpadded** per VP L616 — the helper must not reuse that alias.
2. **Re-anchor GAP-VP-02's SAN cross-check.** It currently derives the host from
   `client_id` and compares it to the leaf's dNSName SAN. The host is no longer
   present in `client_id`, so it compares `dns_host_only(public_base_url)` — the
   actual source of truth, and already the value the old code derived — against
   the leaf SAN. Same check, same failure message, better anchor. **The check is
   not removed:** it is what makes a misconfigured `public_base_url`/certificate
   pairing fail loudly instead of silently signing a Request Object the wallet
   will reject.
3. The unsigned `openid4vp://` URI path (the `client_id` built alongside
   `request_uri`) uses the same prefix, so both transports agree.
4. Absent `x5c` → `VerificationError::Crypto` (Decision 3).

**Changes in `crates/foundry-core/src/config/`:** delete
`VerifierConfig.client_id_scheme` (Decision 2), and remove it from `config.yaml`,
from the `commands.rs` init template, and from every test fixture that sets it.

**Tests.**

- Un-`#[ignore]` `gap_haip_05_signed_request_object_never_uses_x509_hash_prefix`
  (inline `#[cfg(test)]` module in `request.rs`).
- **Update, do not delete, two currently-passing tests** that assert the old
  prefix: `test_build_signed_request_object_and_verify_jws` (asserts
  `payload["client_id"] == "x509_san_dns:verifier.example.com"`) and
  `vp_0128_0130_0132_response_uri_present_no_redirect_uri_same_origin_as_client_id`
  (uses `client_id.strip_prefix("x509_san_dns:")` to recover the host for its
  same-origin assertion). The latter must now derive the expected host from
  `public_base_url`, since the host is no longer recoverable from `client_id` —
  the property it tests (same-origin `response_uri`) is unchanged.
- Add a test that a signed request with no configured `x5c` is a typed error.

**Conformance rows.** `HAIP-0043` (`gap` → `conforming`), `VP-0068` and `VP-0069`
(`not-implemented` → `conforming`), and `HAIP-0045` (trust anchor MUST NOT be in
`x5c`) must be **re-adjudicated**: `build_x5c` is called with the leaf PEM only,
so no anchor is included, which likely makes it `conforming` — but the verdict
must be re-derived from the code as it lands, not assumed. `HAIP-0055`'s evidence
mentions the prefix and needs updating.

### Fix 2 — GAP-HAIP-01: the `scope` parameter and metadata value

**Spec basis.** HAIP OpenID4VCI L186 (metadata MUST include a scope for every
Credential Configuration), L199 (for `authorization_code` the Issuer MUST include
a scope value; "The Wallet MUST use that value in the `scope` Authorization
parameter"), L209 (the `scope` parameter MUST be used to communicate Credential
Types; the value MUST map to a specific Credential Type).

**Changes:**

1. `foundry-core/src/config/model.rs` — `CredentialType` gains
   `#[serde(default)] pub scope: Option<String>`.
2. `foundry-core/src/config/validate.rs` — the **resolved** scope of every
   credential type (explicit `scope`, else `id`) MUST be unique across
   `credential_types`. Without this, HAIP-0028's "maps to a *specific* Credential
   Type" is unsatisfiable. Also reject an explicitly configured empty/whitespace
   scope.
3. `foundry-issuer/src/metadata.rs` — `CredentialConfigurationSupported` gains
   `pub scope: String` (**not** `Option`, **no** `skip_serializing_if`: HAIP-0014
   requires it on *every* configuration), populated as
   `ct.scope.clone().unwrap_or_else(|| ct.id.clone())`.
4. `foundry-issuer/src/authorize.rs` — `AuthorizeParams` gains
   `pub scope: Option<String>`. In `handle_authorize_request`, the check goes
   **after** `redirect_uri` has been validated against the transaction, so a bad
   scope returns via `AuthorizeOutcome::ErrorRedirect` (RFC 6749 §4.1.2.1) rather
   than a direct error — matching the existing ordering in that function. When
   `scope` is present it MUST resolve to a configured credential type **and**
   agree with the type bound to the transaction via `issuer_state`; otherwise
   `invalid_scope`. When absent, behaviour is unchanged and `issuer_state`
   remains the authoritative binding — foundry does not *require* `scope`,
   because the mandate is on the Issuer to *publish and accept* it.
   `handle_authorize_request` currently takes
   `(storage, params, issuer_identifier, tx_ttl_secs, now_unix)` and has no view
   of `Config`. Give it exactly what it needs and nothing more: a
   `scopes: &BTreeMap<String, String>` mapping **resolved scope → credential type
   id**, built once by the caller in `crates/foundry/src/server.rs`. Do not widen
   the signature to `&Config`.
5. `crates/foundry/src/server.rs` — the `/authorize` query struct gains `scope`
   and passes it through. All fields there are already optional by design so that
   a malformed request produces a protocol error rather than an axum 422.
6. `config.yaml` and the `commands.rs` init template — document `scope` on the
   shipped `pid` type (commented out, showing the defaulting behaviour).

**Tests.** Un-`#[ignore]` `haip_0023_credential_configuration_metadata_carries_a_scope_value`
(`foundry-issuer/tests/conformance_vci.rs`). Add: an explicit config `scope`
overrides the `id` default; duplicate resolved scopes fail `Config::validate()`;
`/authorize` with a matching `scope` succeeds; `/authorize` with a scope naming a
different credential type than `issuer_state` is an `invalid_scope` error
redirect; `/authorize` with no `scope` still succeeds.

**Conformance rows.** `HAIP-0014`, `HAIP-0023`, `HAIP-0027`, `HAIP-0028`
(`gap` → `conforming`). `VCI-0145` ("the Authorization Server MUST be able to
uniquely identify the Credential Issuer from the `scope` value", currently
`not-implemented` because no `scope` existed) must be **re-adjudicated** against
what lands.

### Fix 3 — GAP-VP-04: `transaction_data_hashes` validation

**Spec basis.** OpenID4VP L1523 (Verifiers MUST check that the set of
Presentations satisfies all requirements of the request); L3142
(`transaction_data_hashes_alg`, default `sha-256`, `sha-256` MUST be supported);
L3144 (each hash is computed "over the string received in the `transaction_data`
request parameter — base64url decoding is **not** performed before hashing");
L3145 (`transaction_data_hashes_alg` is REQUIRED in the response when it was
present in the request).

**Changes:**

1. `foundry-verifier/src/request.rs`, `encode_transaction_data` — when
   `config.verifier.transaction_data_hashes_alg` is non-empty, inject it into
   each entry **before** base64url encoding, so the advertised bytes and the
   hashed bytes are identical (the guarantee this function's doc comment already
   promises). Per L3142 the field belongs inside each `transaction_data` entry,
   not in `client_metadata`. This field is currently declared and documented but
   never read; wiring it is in scope because the verification rule below refers
   to the request's advertised values.
2. **`crates/foundry-verifier/Cargo.toml` gains `sha2 = { workspace = true }`.**
   The check recomputes SHA-256 over the stored entries and the crate does not
   currently depend on `sha2`. This is a one-line addition of an existing
   workspace dependency (`sha2 = "0.10"`, already used by `foundry-core` and
   `foundry-sd-jwt-vc`), not a new third-party crate entering the tree.
3. `foundry-sd-jwt-vc/src/builder.rs`, `attach_kb_jwt` — gains
   `transaction_data_hashes: Option<&[String]>` and, when `Some`, emits the
   `transaction_data_hashes` claim in the KB-JWT payload (and
   `transaction_data_hashes_alg` when the request specified one). Layering-legal:
   an optional parameter on a lower-layer crate, no new dependency, no upward
   reference. Every existing caller passes `None`.
4. `foundry-verifier/src/verify.rs` — a new `transaction_data_binding`
   `CheckResult`, pushed **only** when `tx.transaction_data.is_some()`, placed
   after the format/signature check and before `dcql_match`. It:
   - reads `transaction_data_hashes` (and `transaction_data_hashes_alg`) from the
     verified KB-JWT payload;
   - rejects an algorithm not among the request's advertised values, defaulting
     to `sha-256` when the request advertised none (L3142);
   - recomputes the hash of each stored `tx.transaction_data` entry **as the
     stored base64url string, without decoding** (L3144);
   - requires that every entry whose `credential_ids` includes
     `answered_query_id` has its hash present. `select_presentation` already
     guarantees exactly one answered credential query per `vp_token`, so there is
     no multi-credential fan-out; entries scoped to *other* credential ids are
     not required.
   - **Failure is a policy outcome**, per `AGENTS.md` §4.3: the check records
     `passed: false`, `verified` becomes `false` by §4.2's invariant, HTTP stays
     200, and the log record is `warn` — not an `Err`, not a 400.

**Governing-document updates (required, not optional).** `AGENTS.md` §4.2
enumerates the check names; the list grows to six with
`transaction_data_binding`. `crates/foundry-verifier/AGENTS.md`'s module map must
gain the new check and — because of Fix 1 — its `request.rs` row must stop
describing `client_id` as `x509_san_dns:<host>`.

**Tests.**

- Un-`#[ignore]` `gap_vp_04_transaction_data_hashes_never_validated`
  (`foundry-verifier/src/verify.rs`, inline). It asserts `!res.verified` for a
  presentation built with no binding — it must keep passing **unchanged** except
  for the `attach_kb_jwt` call gaining a `None` argument.
- **Add a positive test:** a presentation whose KB-JWT carries the correct
  `transaction_data_hashes` verifies successfully (`res.verified == true`). This
  is what distinguishes a correct check from a blanket refusal.
- Add: a hash that does not match any requested entry fails; an unsupported
  `transaction_data_hashes_alg` fails; a request with **no** `transaction_data`
  pushes **no** `transaction_data_binding` check at all (so existing
  verification results are unchanged in shape for the common case).

**Conformance rows.** `VP-0153` (`gap` → `conforming`), `VP-0254` and `VP-0256`
(`not-implemented` → `conforming`). The adjacent transaction-data rows
`VP-0253`, `VP-0255`, `VP-0257`, `VP-0258`, `VP-0259` must be **re-checked** —
some may move — and `VP-0005`/`VP-0006`/`VP-0145`/`VP-0146`/`VP-0223` mention
`transaction_data` and should be reviewed for stale evidence.

## Verification

**Per-task scoped gate (`AGENTS.md` §5.1). Do NOT run `cargo test --workspace`
per task.**

| Fix | Scoped gate |
|---|---|
| GAP-HAIP-05 | `cargo test -p foundry-core -p foundry-verifier -p foundry` |
| GAP-HAIP-01 | `cargo test -p foundry-core -p foundry-issuer -p foundry` |
| GAP-VP-04 | `cargo test -p foundry-sd-jwt-vc -p foundry-verifier -p foundry` |

Plus, per task: `cargo clippy -p <crate> --all-targets -- -D warnings` and
`cargo fmt --check` (cheap, kept workspace-wide).

`foundry-core` appears in Fix 1's gate because deleting `client_id_scheme` is a
`foundry-core` config change; `foundry` appears in all three because the
integration suite and `conformance_report.rs` live there.

**Full gate (`AGENTS.md` §5.3) exactly once**, at the end of the branch, before
the final review / PR:

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

**`conformance_report.rs` is the bookkeeping gate.** Its 11 self-consistency
tests enforce that every gap-register entry names an existing `#[ignore]`d test
citing its own gap id, that every `#[ignore = "GAP-..."]` cites a registered gap,
and that the Summary counts equal the actual row counts. Removing the three gap
rows and un-`#[ignore]`ing their tests must happen together, and the per-spec
Summary table must be recomputed — `conforming` up, `gap` down, `not-implemented`
down for the rows that move out of it.

## Other Required Updates

- `docs/conformance/openid4vc-conformance.md` — remove the three gap-register
  rows; update every clause row named above; recompute the Summary.
- `openapi.json` — the `/authorize` `scope` query parameter and
  `CredentialConfigurationSupported.scope`. Regenerate per
  `crates/foundry/AGENTS.md`; do not hand-edit.
- `config.yaml` and `crates/foundry/src/commands.rs` init template — drop
  `client_id_scheme`, document `credential_types[].scope`.
- `README.md` — only if a documented config key or endpoint parameter it shows
  changes.
- `docs/superpowers/changes/2026-08-03-conformance-tier4-fixes.md` — the change
  record, written at the end.

## Risks

- **The prefix swap is wire-visible.** Any wallet or test fixture outside this
  repository pinned to `x509_san_dns` will stop matching. This is intended (HAIP
  mandates it) but is the one change here an integrator would notice.
- **Deleting `client_id_scheme` is a documented-key removal.** Safe at load time
  (no `deny_unknown_fields`), but an operator reading a diff of `config.yaml`
  should find it in the change record.
- **`transaction_data_hashes_alg` injection changes the request-object bytes**
  for deployments that configure it (the shipped `config.yaml` sets
  `[sha-256]`). Since nothing consumed it before, no existing wallet can regress
  on a field it never received — but the request object's `transaction_data`
  entries are no longer byte-identical to what a pre-change build produced.
- **Fix 2 touches `handle_authorize_request`, which Tier 3 changed** for
  GAP-HAIP-02 (RFC 9207 `iss`). The `AuthorizeOutcome` variants and their `iss`
  handling must not regress; `authorization_code_flow.rs` covers that path.