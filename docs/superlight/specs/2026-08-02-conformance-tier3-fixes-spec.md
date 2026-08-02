# Conformance Tier 3 — Seven Important-or-Adjacent Gap Closures

**Date:** 2026-08-02
**Status:** approved

## Problem

Seven entries in [`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md)'s
Gap Register are open, each with a confirmed root cause and a named
`#[ignore]`d test already committed in the workspace. None is architectural;
none requires a new subsystem. They are open because the code was never
written, not because the design was unclear.

| Gap | Severity | Site | Cause (per register) |
|---|---|---|---|
| GAP-VP-01 | Important | `foundry-verifier/src/request.rs` | `build_signed_request_object` never inserts an `aud` claim |
| GAP-VP-02 | Important | `foundry-verifier/src/request.rs` | `client_id` host never cross-checked against the `x5c` leaf's dNSName SAN, though `foundry_core::trust::match_san_dns` already exists |
| GAP-VCI-09 | Important | `foundry-core/src/config/validate.rs` | `Config::validate()` never checks `issuer.credential_issuer` against `server.wallet_facing.public_base_url` |
| GAP-VCI-08 | Minor | `foundry-core/src/config/validate.rs` | `Config::validate()` never checks the scheme of `issuer.credential_issuer` |
| GAP-HAIP-02 | Important | `foundry-issuer/src/authorize.rs`, `foundry/src/server.rs` | Authorization Response carries no `iss` (RFC 9207) |
| GAP-VCI-04 | Important | `foundry-issuer/src/nonce.rs` | `IssuanceError` has no `InvalidNonce` variant; every nonce failure reports `invalid_proof` |
| GAP-VCI-02 | Important | `foundry-issuer/src/credential.rs` | `handle_credential_request` never reads `req.credential_configuration_id` |

The register and the test suite are mutually enforcing:
`crates/foundry/tests/conformance_report.rs` asserts **in both directions** that
every gap-register entry names an existing `#[ignore]`d test, and that every
`#[ignore = "GAP-..."]` cites a registered gap. Closing a gap therefore *must*
update the register in the same commit that removes the `#[ignore]`, or the
workspace suite fails. This is the enforcement mechanism, not bookkeeping.

## Goal / Non-Goals

**Goal.** Move all seven gaps from `gap` to `conforming` in the register, with
each formerly-`#[ignore]`d test passing, and the workspace gates
(`cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo fmt --check`) clean.

**Non-goals.**

- **`req.format` validation.** `format` is not a Credential Request parameter in
  OpenID4VCI 1.0 (L849–L856 defines only `credential_identifier`,
  `credential_configuration_id`, `proofs`, `credential_response_encryption`).
  Every existing caller including `foundry-wallet` sends it; rejecting or
  requiring it buys no conformance and breaks callers. It stays ignored.
- **The other open gaps.** GAP-HAIP-01/03/05, GAP-VP-03/04/05,
  GAP-VCI-05/06/07/10/11/12/13 are out of scope and their `#[ignore]`s stay.
- **`x509_hash` Client Identifier Prefix** (GAP-HAIP-05). GAP-VP-02 validates
  the `x509_san_dns` prefix foundry actually emits; it does not change the
  prefix.
- **DPoP / sender-constrained access tokens** (GAP-HAIP-03). RFC 9207's `iss`
  is one FAPI 2.0 provision; DPoP is a separate one and stays open.
- **Introducing the `url` crate.** The workspace has no URL-parsing dependency
  and handles hosts with small string helpers (`dns_host_only`,
  `trim_end_matches('/')`). This work follows that house style rather than
  adding a dependency for two checks.

## Approach

Each gap is fixed at the site the register names, using the mechanism the
register identifies. Four decisions were genuinely open — the pinned specs and
the existing tests did not settle them — and were decided as follows.

### Decision 1 — GAP-VCI-08 exempts loopback hosts (chosen: **b**)

OpenID4VCI L1368/L1369 make `https` a MUST for `credential_endpoint` and
`nonce_endpoint`, both derived from `issuer.credential_issuer`, with no loopback
exemption. But the repository's own `config.yaml` uses `http://localhost:8443`,
so unconditional enforcement makes the shipped dev config fail to boot.

**Chosen:** exempt loopback hosts (`localhost`, `127.0.0.1`, `::1`, `[::1]`);
enforce `https` for everything else.

**Rejected:**
- *Strict `https`, migrate `config.yaml` to match the `init` template
  (`commands.rs:276`, which already emits `https://localhost:8443`).* Cleanest
  conformance, but forces every local HTTP dev setup to front itself with TLS.
- *An `issuer.allow_insecure_http` opt-out.* Adds config surface whose only
  real consumer is local dev, which the exemption already covers.

**This is a deliberate deviation from a MUST** and is therefore governed by
AGENTS.md §4.4: it requires an inline comment at the check naming the clause and
the reason, plus a Gotchas entry in `crates/foundry-core/AGENTS.md`. Without
those, a future reader will read the exemption as a defect and remove it.

**Known consequence:** RFC 9207 §2 requires the `iss` value to be an `https`
URL. Under this exemption a loopback deployment emits a non-conformant `http://`
`iss` (Decision 2). That is an accepted consequence of the exemption, not a
separate defect, and belongs in the same Gotchas note.

### Decision 2 — GAP-HAIP-02 closes RFC 9207 fully (chosen: **a**)

The register describes only "`iss` in the Authorization response", and
`haip_0008_authorization_response_includes_iss` only asserts `iss=` on the
**success** redirect. RFC 9207 (fetched from the RFC Editor; not vendored in
`docs/specs/`) is broader:

- **§2:** "In authorization responses to the client, **including error
  responses**, an authorization server supporting this specification MUST
  indicate its identity by including the `iss` parameter in the response."
- **§2.3:** the server "MUST indicate its support for the `iss` parameter by
  setting the metadata parameter
  `authorization_response_iss_parameter_supported` … to `true`."

**Chosen:** `iss` on both the success and error redirects, plus the metadata
flag. HAIP L159 incorporates RFC 9207 wholesale via FAPI 2.0, and the register's
clause row (HAIP-0008) cites the whole provision — closing it narrowly would
make the register misreport a partial fix as `conforming`.

**Rejected:**
- *Both redirects, skip the metadata flag.* The mix-up defence works, but the
  flag is one `bool` and its absence leaves §2.3 unmet.
- *Success redirect only.* Exactly what the test demands and nothing more;
  leaves §2 unmet for error responses.

**Threading:** `handle_authorize_request` takes no `Config`, so the issuer
identifier is passed in as an explicit `issuer_identifier: &str` parameter and
`iss` is carried on both `AuthorizeOutcome` variants — rather than appended in
`server.rs`. This keeps the outcome self-describing and testable inside
`foundry-issuer`'s own suite instead of only through the HTTP layer.

### Decision 3 — GAP-VCI-04 propagates `InvalidNonce` from key attestation (chosen: **b**)

OpenID4VCI L1049/L1050 partition the two codes by cause:

- `invalid_proof` — "(1) if the field is missing, or (2) one of the provided key
  proofs is invalid, or (3) **if at least one of the key proofs does not contain
  a `c_nonce` value**"
- `invalid_nonce` — "at least one of the key proofs **contains an invalid
  `c_nonce` value**. The wallet should retrieve a new `c_nonce` value"

So a *missing* nonce claim stays `invalid_proof` (clause 3); a *present but
invalid* one becomes `invalid_nonce`. `attestation.rs:634` is the open question:
it verifies the Key Attestation JWT's own `nonce` and explicitly re-wraps the
result as `InvalidProof`, which would override a new variant.

**Chosen:** drop the wrap's variant override (keeping the `key_attestation:`
message prefix) so `InvalidNonce` propagates. The spec's test is whether a key
proof contains an invalid `c_nonce`; it does not care which nested JWT carried
it, and the wallet's recovery ("fetch a fresh nonce and retry") is identical
either way.

**Rejected:** *leave the wrap*, so key-attestation nonce failures keep reporting
`invalid_proof`. Defensible (the failing artifact is the Key Attestation JWT),
but it gives a wallet two different error codes for one recoverable condition
depending on which JWT held the nonce.

### Decision 4 — GAP-VCI-02 uses the full three-way error split (chosen: **a**)

Because foundry never returns `authorization_details`/`credential_identifiers`,
L851's "REQUIRED if a `credential_identifiers` parameter was not returned" means
**always required**. L1041 forbids collapsing payload errors onto generic codes
— the same rule that motivates GAP-VCI-04 — so `InvalidRequest` is specifically
the wrong variant.

**Chosen:** three cases, two new error variants.

| Case | Error code |
|---|---|
| absent | `invalid_credential_request` (missing required parameter) |
| present, is a configured type, but ≠ the Access Token's bound type | `invalid_credential_request` (unsupported parameter *value*) |
| present, not in `credential_configurations_supported` at all | `unknown_credential_configuration` |

**Rejected:**
- *Two-way* (only `InvalidCredentialRequest`, reusing `UnknownCredentialType`
  for an unknown id). One fewer variant, but a wallet cannot distinguish
  "unknown configuration" from "not the configuration your token is for" — the
  first means re-read metadata, the second means fix the request.
- *One-way* (a single variant, always `invalid_credential_request`). Closes the
  gap with a deliberately less specific code, which is self-defeating for a gap
  whose defect *is* "the specific code is not used".

## Design

### Component 1 — `foundry-core`: host helper + two `Config::validate()` checks

**`dns_host_only` hoisted to `foundry-core`.** Currently `pub(crate)` in
`foundry-verifier/src/request.rs`. Moves to `foundry-core` as `pub`;
`foundry-verifier` calls the core version. A legal downward move per AGENTS.md
§3, and it means one host extractor rather than two divergent copies.

Behaviour is unchanged and preserved exactly: strip `https://` then `http://`,
truncate at the first `/`, truncate at the first `:`.

**`is_loopback_host(host: &str) -> bool`** — private to `validate.rs`. True for
`localhost`, `127.0.0.1`, `::1`, `[::1]`.

**Check A (GAP-VCI-08).** `issuer.credential_issuer` MUST begin with `https://`
unless `dns_host_only` of it is a loopback host. Failure →
`ConfigError::Validation`.

**Check B (GAP-VCI-09).** `issuer.credential_issuer` MUST equal
`server.wallet_facing.public_base_url`, byte-exact. L1366 mandates "a simple
string comparison with no normalization", so no trailing-slash or case
tolerance; the error message states this explicitly, because a trailing slash is
the failure an operator will actually hit.

**Ordering:** A before B, so a config wrong in both ways reports the scheme
problem first (the more fundamental one).

Both checks live in the existing `Config::validate()`, which runs at startup
(`crates/foundry/src/main.rs:38,50`).

### Component 2 — `foundry-verifier`: Request Object

Both changes are inside `build_signed_request_object` (`request.rs`).

**GAP-VP-01.** Insert `"aud": "https://self-issued.me/v2"` into `payload_map`.
OpenID4VP L536: the `aud` claim MUST be that value when Static Discovery
metadata is used, which is the only branch foundry ever takes (it performs no
Dynamic Discovery — `openid_federation` is unimplemented, VP-0041/VP-0048).

**GAP-VP-02.** The host derivation (`dns_host_only(base_url)`) moves above the
`x5c` block so the host is available there. Inside the existing
`if let Some(ref path) = key_entry.x5c` branch — where the leaf PEM is already
read for `build_x5c` — call `foundry_core::trust::match_san_dns(&pem_bytes, &host)`;
on `Ok(false)` return `VerificationError::Crypto` naming both the `client_id`
host and the mismatch. Only checked when `x5c` is configured: no certificate
means no `x509_san_dns` claim to contradict.

`match_san_dns(leaf_pem: &[u8], expected_dns: &str) -> Result<bool, TrustError>`
already exists in `foundry-core/src/trust/mod.rs:177`; `TrustError` already
converts into `VerificationError` via `#[from]`.

### Component 3 — `foundry-issuer`: three changes

**GAP-VCI-04.** New `IssuanceError::InvalidNonce(String)`; `kind()` arm
`"invalid_nonce"`. All four `verify_nonce` failure paths in `nonce.rs` switch to
it (bad base64url, unexpected length, MAC mismatch, expired) — each is a
present-but-invalid `c_nonce`. `proof.rs`'s "missing or non-string nonce claim"
stays `InvalidProof` per L1049 clause 3. `attestation.rs`'s `map_err` keeps the
`key_attestation:` prefix but stops overriding the variant.

**GAP-VCI-02.** New `IssuanceError::InvalidCredentialRequest(String)` and
`IssuanceError::UnknownCredentialConfiguration(String)`, with `kind()` arms
`"invalid_credential_request"` and `"unknown_credential_configuration"`.

In `handle_credential_request`, validation is placed **after** the transaction
loads (it needs `tx.credential_type_id`) and **before** proof verification, so a
misaddressed request fails on cheap checks rather than after signature work:

```
match req.credential_configuration_id {
    None                                        => InvalidCredentialRequest
    Some(id) if id == tx.credential_type_id     => proceed
    Some(id) if config.credential_types has id  => InvalidCredentialRequest
    Some(id)                                    => UnknownCredentialConfiguration
}
```

`error.kind()` is deliberately exhaustive with no catch-all arm
(`error.rs:46–47`), so the compiler enforces that every new variant is handled.

**GAP-HAIP-02.** `AuthorizeOutcome::Success` and `AuthorizeOutcome::ErrorRedirect`
each gain an `iss: String` field. `handle_authorize_request` gains an
`issuer_identifier: &str` parameter and populates `iss` on both variants.
`AuthorizationServerMetadata` (`metadata.rs:50`) gains
`authorization_response_iss_parameter_supported: bool`, set to `true` in
`build_authorization_server_metadata`.

### Component 4 — `foundry`: wiring

- `authorize_handler` passes `state.config.issuer.credential_issuer` as
  `issuer_identifier`.
- Both `append_query` call sites (`server.rs:382`, `server.rs:391`) add
  `("iss", iss.as_str())`. `append_query` already percent-encodes values, so the
  `https://…` identifier is encoded correctly with no change to that helper.
- `wallet_error_response` gains three arms:
  `InvalidNonce → (400, "invalid_nonce")`,
  `InvalidCredentialRequest → (400, "invalid_credential_request")`,
  `UnknownCredentialConfiguration → (400, "unknown_credential_configuration")`.
  Placed before the `_ =>` catch-all so they are not swallowed as 500s.
- `openapi-wallet.json` regenerates: `AuthorizationServerMetadata` gains a
  required field (AGENTS.md §6).

### Error handling

All new failure paths return typed errors — `ConfigError::Validation`,
`VerificationError::Crypto`, `IssuanceError::*` — with no `unwrap`, `expect`, or
`panic!` in request paths (AGENTS.md §4.1). Every new `IssuanceError` variant is
logged exactly once, inside `wallet_error_response`, which already calls
`log_typed_error` (AGENTS.md §4.5).

Per AGENTS.md §4.3 these are all structural/parameter failures → HTTP 400, not
policy outcomes; none touches `VerificationResult.verified`.

### Data flow

No storage schema change, no transaction-shape change, no new persisted state.
`AuthorizeOutcome` grows a field but is an in-process value, not a stored one.

### Blast radius of the two new `Config::validate()` checks (verified)

`validate()` runs at startup, so a new check can break existing configs. Every
caller and fixture was enumerated and checked against both Check A (https) and
Check B (identity). **All pass unchanged; no fixture needs editing.**

| Caller / fixture | `credential_issuer` | `public_base_url` | A | B |
|---|---|---|---|---|
| `config.yaml` (committed) | `http://localhost:8443` | `http://localhost:8443` | exempt (loopback) | equal |
| `QUICKSTART_CONFIG` template (`commands.rs`) → `quickstart.rs:59` | `https://localhost:8443` | `https://localhost:8443` | pass | equal |
| `fixtures/minimal.yaml` → `config_load.rs:18` | `https://issuer.example.com` | `https://issuer.example.com` | pass | equal |
| `fixtures/bad-missing-keyref.yaml` → `config_load.rs:25` | `https://issuer.example.com` | `https://issuer.example.com` | pass | equal (fails earlier on keyref, as intended) |
| `validate_key_material.rs:60` | `https://localhost:8443` | `https://localhost:8443` | pass | equal |
| `conformance_vci.rs` `test_config()` | `https://issuer.example.com` | `https://issuer.example.com` | pass | equal |

Two consequences worth stating explicitly:

- **`config.yaml` is NOT modified by this work.** Migrating it to `https` was
  rejected option (a) of Decision 1. It is a stale `foundry quickstart` artifact
  — its own header says so — generated before the template moved to `https`;
  that drift is pre-existing and out of scope here.
- The two verifier fixtures (`foundry-verifier/src/request.rs`,
  `foundry-verifier/tests/conformance_vp.rs`) deliberately pair
  `credential_issuer: https://issuer.example.com` with
  `public_base_url: https://verifier.example.com`. They would **fail Check B** —
  but neither calls `validate()`, and must not start doing so. GAP-VP-02's test
  depends on that divergence.

## Global Constraints

- **`aud` literal:** exactly `https://self-issued.me/v2` (OpenID4VP L536).
- **`credential_issuer` vs `public_base_url`:** byte-exact equality, no
  normalization (OpenID4VCI L1366).
- **Loopback exemption set:** `localhost`, `127.0.0.1`, `::1`, `[::1]` — nothing
  else. Not private ranges, not `*.local`.
- **`iss` value:** `issuer.credential_issuer`, on both success and error
  redirects, plus `authorization_response_iss_parameter_supported: true`
  (RFC 9207 §2, §2.3).
- **Missing nonce claim stays `invalid_proof`;** only present-but-invalid
  becomes `invalid_nonce` (OpenID4VCI L1049 clause 3 vs L1050).
- **`req.format` is never validated or required.**
- **No new workspace dependency.** No `url` crate.
- **Spec citations are mandatory** on every new protocol-facing branch
  (AGENTS.md §4.4): the spec name and clause/line, e.g.
  `// OpenID4VP §5.10 (L536) — aud under Static Discovery`.
- **`#[tracing::instrument]` additions, if any, carry `skip_all`**
  (AGENTS.md §4.5). No new field may log a nonce, token, or key.
- **Register and tests move together.** Removing an `#[ignore]` without
  flipping its register row (or vice versa) fails
  `crates/foundry/tests/conformance_report.rs`.
- **No upward or sideways crate dependencies** (AGENTS.md §3). The
  `dns_host_only` hoist is downward (`foundry-verifier` → `foundry-core`) and
  therefore legal.

## Testing Strategy

**The seven `#[ignore]`d tests are the primary contract.** Each is removed from
`#[ignore]` and must pass unmodified — they were written against the register's
root-cause analysis and are the acceptance criteria:

| Test | File |
|---|---|
| `vp_0042_request_object_missing_aud_claim` | `foundry-verifier/tests/conformance_vp.rs:299` |
| `vp_0063_client_id_host_not_validated_against_x5c_certificate_san` | `foundry-verifier/tests/conformance_vp.rs:346` |
| `vci_0130_0131_config_validation_does_not_enforce_https_scheme_for_issuer_urls` | `foundry-issuer/tests/conformance_vci.rs:1932` |
| `vci_0128_config_validation_does_not_enforce_credential_issuer_identity_match` | `foundry-issuer/tests/conformance_vci.rs:1968` |
| `haip_0008_authorization_response_includes_iss` | `foundry/tests/conformance_http.rs:438` |
| `vci_0078_expired_nonce_reports_invalid_nonce_not_invalid_proof` | `foundry/tests/conformance_http.rs:347` |
| `vci_0052_credential_configuration_id_mismatch_is_rejected` | `foundry-issuer/tests/conformance_vci.rs:599` |

**Two existing tests flip and must be updated** — these are corrections, not
regressions, and each flip is an assertion of the new intended behaviour:

- `wallet_issuance.rs:506` `credential_request_with_proof_nonce_mismatch_is_rejected`
  — passes `"not-the-real-nonce"`, which fails base64url/length →
  `invalid_proof` becomes `invalid_nonce`.
- `wallet_issuance.rs:551` `credential_request_with_expired_c_nonce_is_rejected`
  — `invalid_proof` becomes `invalid_nonce`.

`wallet_issuance.rs:472` (`proof_aud_mismatch`) is unaffected and must keep
asserting `invalid_proof` — it is the positive control proving the two codes
stay distinguished.

**New behaviours requiring new tests**, none of which any existing test covers:

- Loopback `http://` config **accepted** (the exemption's positive case).
- Non-loopback `http://` config **rejected** (already covered by
  `vci_0130_0131`, whose fixture is `http://issuer.example.com`).
- `credential_issuer` differing from `public_base_url` only by a trailing slash
  **rejected** (pins the no-normalization constraint).
- `iss` present on the **error** redirect (`AuthorizeOutcome::ErrorRedirect`).
- `authorization_response_iss_parameter_supported == true` in served AS
  metadata.
- `credential_configuration_id` **absent** → `invalid_credential_request`.
- `credential_configuration_id` naming a **configured but unbound** type →
  `invalid_credential_request`.
- `credential_configuration_id` naming an **unknown** id →
  `unknown_credential_configuration`.
- `build_signed_request_object` **succeeds** when the `x5c` leaf's SAN does
  match the `public_base_url` host (positive control for GAP-VP-02, so the check
  is not passing merely because the function now always errors).
- Key-attestation nonce failure surfaces `invalid_nonce` with the
  `key_attestation:` prefix retained (Decision 3).

**Gates** (AGENTS.md §5), all three required clean before completion:

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

`crates/foundry/tests/conformance_report.rs` and
`crates/foundry/tests/instrumentation_hygiene.rs` both run inside
`cargo test --workspace` and will catch a register/test mismatch or a missing
`skip_all` without any extra step.

## Documentation Impact

- **`docs/conformance/openid4vc-conformance.md`** — seven Gap Register rows
  removed, and **eight** clause rows flipped `gap` → `conforming` with fresh
  evidence (eight, not seven: GAP-VCI-08 spans two clauses, VCI-0130 and
  VCI-0131):

  | Spec | Clause rows flipping | `conforming` | `gap` |
  |---|---|---|---|
  | OpenID4VCI | VCI-0052, VCI-0078, VCI-0128, VCI-0130, VCI-0131 | 71 → 76 | 23 → 18 |
  | OpenID4VP | VP-0042, VP-0063 | 85 → 87 | 11 → 9 |
  | HAIP | HAIP-0008 | 46 → 47 | 8 → 7 |

  Totals (232 / 266 / 96) are unchanged — rows change verdict, none are added.
  Per AGENTS.md §8 this is part of closing a gap, not a follow-up.
- **`crates/foundry-core/AGENTS.md`** — Gotchas: the loopback `https` exemption
  (Decision 1) and its RFC 9207 `iss` consequence; `dns_host_only` now lives
  here.
- **`crates/foundry-issuer/AGENTS.md`** — Gotchas: `InvalidNonce` vs
  `InvalidProof` split (missing vs invalid nonce), the three new error variants,
  and `handle_authorize_request`'s new `issuer_identifier` parameter.
- **`crates/foundry-verifier/AGENTS.md`** — Gotchas: `build_signed_request_object`
  now fails when the `x5c` SAN and `public_base_url` host disagree, which turns
  a previously silent misconfiguration into a startup-adjacent hard error.
- **`openapi-wallet.json`** — regenerated (AGENTS.md §6).
- **`README.md`** — no change: no new log field names, no new operator-facing
  config key (the loopback exemption adds no key).

## Open Questions

None. All four open decisions were resolved before this spec was written
(Approach, Decisions 1–4).