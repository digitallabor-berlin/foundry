# Conformance Tier 3 — Implementation Plan

**Spec:** docs/superlight/specs/2026-08-02-conformance-tier3-fixes-spec.md
**Branch:** superlight/2026-08-02-conformance-tier3-fixes
**Executed with:** superlight Phase 4 (TDD, inline, no subagents by default)

**Goal:** Close GAP-VP-01, GAP-VP-02, GAP-VCI-02, GAP-VCI-04, GAP-VCI-08,
GAP-VCI-09 and GAP-HAIP-02 — un-`#[ignore]`ing their seven committed tests and
flipping the eight corresponding clause rows to `conforming`.

**Architecture:** Five independent edit sites, one per task: `Config::validate()`
in `foundry-core`, `build_signed_request_object` in `foundry-verifier`, and three
separate concerns in `foundry-issuer` (`IssuanceError` nonce variant, Credential
Request validation, RFC 9207 `iss`). Nothing new is introduced beyond one
`foundry-core` module for a hoisted host helper and five `IssuanceError`/outcome
fields. No storage, schema, or dependency change.

## Global Constraints

Copied verbatim from the spec — these bind every task:

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
  (AGENTS.md §4.4): the spec name and clause/line.
- **`#[tracing::instrument]` additions, if any, carry `skip_all`**
  (AGENTS.md §4.5). No new field may log a nonce, token, or key.
- **Register and tests move together.** Removing an `#[ignore]` without
  flipping its register row (or vice versa) fails
  `crates/foundry/tests/conformance_report.rs`.
- **No upward or sideways crate dependencies** (AGENTS.md §3).

### Two constraints that are easy to violate

1. **`conformance_report.rs` machine-checks the Summary counts** (`:15` — "the
   summary counts equal the actual row counts"). Every task that un-`#[ignore]`s
   a test MUST, in the same commit: remove its Gap Register row(s), flip its
   clause row(s) to `conforming` with fresh evidence, **and** adjust the Summary
   table. A task that skips the Summary arithmetic fails the workspace suite.
2. **The two verifier fixtures must keep their URL divergence.**
   `foundry-verifier/src/request.rs` and
   `foundry-verifier/tests/conformance_vp.rs` pair
   `credential_issuer: https://issuer.example.com` with
   `public_base_url: https://verifier.example.com`. They would fail Task 1's
   Check B — but neither calls `validate()`, and must not start. GAP-VP-02's
   test depends on that divergence. **Do not "fix" them.**

### Register bookkeeping ledger

Cumulative per-task Summary deltas. After the final task the table must read
exactly the "after" row.

| Task | Gap rows removed | Clause rows → `conforming` | VCI conf/gap | VP conf/gap | HAIP conf/gap |
|---|---|---|---|---|---|
| (start) | — | — | 71 / 23 | 85 / 11 | 46 / 8 |
| 1 | GAP-VCI-08, GAP-VCI-09 | VCI-0128, VCI-0130, VCI-0131 | 74 / 20 | 85 / 11 | 46 / 8 |
| 2 | GAP-VP-01, GAP-VP-02 | VP-0042, VP-0063 | 74 / 20 | 87 / 9 | 46 / 8 |
| 3 | GAP-VCI-04 | VCI-0078 | 75 / 19 | 87 / 9 | 46 / 8 |
| 4 | GAP-VCI-02 | VCI-0052 | 76 / 18 | 87 / 9 | 46 / 8 |
| 5 | GAP-HAIP-02 | HAIP-0008 | 76 / 18 | 87 / 9 | 47 / 7 |
| (after) | 7 rows | 8 rows | **76 / 18** | **87 / 9** | **47 / 7** |

Totals (232 / 266 / 96) never change.

## File Structure

- `crates/foundry-core/src/url.rs` — **new**: `pub fn dns_host_only`, hoisted
  from `foundry-verifier`. One host extractor for the whole workspace.
- `crates/foundry-core/src/lib.rs` — register `pub mod url;`
- `crates/foundry-core/src/config/validate.rs` — the two new `Config::validate()`
  checks + private `is_loopback_host`
- `crates/foundry-verifier/src/request.rs` — `aud` claim, SAN cross-check, drop
  the local `dns_host_only`
- `crates/foundry-issuer/src/error.rs` — three new `IssuanceError` variants + their
  `kind()` arms
- `crates/foundry-issuer/src/nonce.rs` — four `verify_nonce` failures → `InvalidNonce`
- `crates/foundry-issuer/src/attestation.rs` — drop the `map_err` variant override
- `crates/foundry-issuer/src/credential.rs` — `credential_configuration_id` validation
- `crates/foundry-issuer/src/authorize.rs` — `iss` on both `AuthorizeOutcome` variants,
  new `issuer_identifier` parameter
- `crates/foundry-issuer/src/metadata.rs` — `authorization_response_iss_parameter_supported`
- `crates/foundry/src/server.rs` — three `wallet_error_response` arms, `iss` on both
  redirects, pass `issuer_identifier`
- `docs/conformance/openid4vc-conformance.md` — register rows + Summary (every task)
- `crates/foundry-{core,issuer,verifier}/AGENTS.md` — Gotchas
- `openapi-wallet.json` — regenerated in Task 5

---

### Task 1: `Config::validate()` — https scheme + issuer identity (GAP-VCI-08, GAP-VCI-09)

**Files:**
- create `crates/foundry-core/src/url.rs`
- modify `crates/foundry-core/src/lib.rs` (add `pub mod url;`)
- modify `crates/foundry-core/src/config/validate.rs` (inside existing `Config::validate`)
- modify `crates/foundry-core/AGENTS.md` (module map row + Gotchas)
- modify `docs/conformance/openid4vc-conformance.md`
- test: un-`#[ignore]` `crates/foundry-issuer/tests/conformance_vci.rs:1931,1967`;
  new tests in `crates/foundry-core/src/config/validate.rs`'s `mod tests`

**Interfaces:**
- Produces: `pub fn foundry_core::url::dns_host_only(base_url: &str) -> String` —
  behaviour preserved byte-for-byte from the current `foundry-verifier` private
  copy: strip `https://`, then `http://`, truncate at first `/`, truncate at
  first `:`. Task 2 consumes this.
- Produces: two new `ConfigError::Validation` failure modes from the existing
  `Config::validate(&self) -> Result<(), ConfigError>`. Signature unchanged.
- Private: `fn is_loopback_host(host: &str) -> bool` in `validate.rs`.

**Order inside `validate()`:** append both checks **after** the existing
`verifier.signing_key` and `issuer.status_list.signing_key` checks, so a config
that deliberately trips the keyref check still trips that one first
(`fixtures/bad-missing-keyref.yaml` via `config_load.rs:25` asserts on it).
Within the new pair, Check A (scheme) precedes Check B (identity), so a config
wrong in both ways reports the more fundamental problem.

**Behaviors to test:**
- `http://issuer.example.com` credential_issuer → rejected — happy path for
  Check A (already asserted by `vci_0130_0131...`)
- `http://localhost:8443` (matching `public_base_url`) → **accepted** — the
  loopback exemption's positive case, and the reason `config.yaml` still boots
- `http://127.0.0.1:8443` → accepted — second loopback form
- `https://issuer.example.com` vs `public_base_url:
  https://different-host.example.com` → rejected — Check B (already asserted by
  `vci_0128...`)
- `https://issuer.example.com` vs `https://issuer.example.com/` → rejected —
  pins "no normalization"; a trailing slash is the failure operators hit
- `minimal_config()` unmodified → still accepted — regression guard that neither
  check fires on a well-formed config

**Docs in this task:**
- Inline comment at Check A naming OpenID4VCI L1368/L1369 **and** the loopback
  deviation with its reason (AGENTS.md §4.4 requires both).
- `crates/foundry-core/AGENTS.md`: new `url.rs` row in the module map; Gotchas
  entry for the loopback exemption *and* its consequence (a loopback deployment
  emits a non-conformant `http://` `iss`, RFC 9207 §2 — see Task 5).
- Register: remove GAP-VCI-08 + GAP-VCI-09 rows; flip VCI-0128, VCI-0130,
  VCI-0131 to `conforming`; Summary VCI → 74 / 20.

**Verify:** `cargo test -p foundry-core && cargo test -p foundry-issuer --test conformance_vci && cargo test -p foundry --test conformance_report --test quickstart`

- [x] Red — failing test per behavior above
- [x] Green — minimal implementation
- [x] Refactor — clean while green
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 2: Request Object `aud` + `x5c` SAN cross-check (GAP-VP-01, GAP-VP-02)

**Files:**
- modify `crates/foundry-verifier/src/request.rs` (`build_signed_request_object`)
- modify `crates/foundry-verifier/AGENTS.md` (Gotchas)
- modify `docs/conformance/openid4vc-conformance.md`
- test: un-`#[ignore]` `crates/foundry-verifier/tests/conformance_vp.rs:298,345`;
  new positive-control test in the same file

**Interfaces:**
- Consumes: `foundry_core::url::dns_host_only` (Task 1). Delete the `pub(crate)`
  copy in `request.rs` and update its two in-crate call sites (`:309` region and
  `:380` region) — `grep -n dns_host_only crates/foundry-verifier/src/` to find
  them all.
- Consumes: `foundry_core::trust::match_san_dns(leaf_pem: &[u8], expected_dns: &str) -> Result<bool, TrustError>`
  (already exists, `trust/mod.rs:177`). `TrustError` already converts via
  `#[from]` on `VerificationError::Trust`.
- Produces: `build_signed_request_object` signature unchanged
  (`(&Config, &VerificationTransaction) -> Result<String, VerificationError>`);
  gains one new `Err(VerificationError::Crypto(..))` failure mode.

**Implementation notes:**
- The host derivation currently sits *below* the `x5c` block. Move
  `let host = dns_host_only(base_url);` (and the `base_url` binding it needs)
  **above** the `if let Some(ref path) = key_entry.x5c` block so the host is in
  scope there. Do not duplicate the derivation.
- Perform the SAN check inside the existing `x5c` branch, reusing the
  `pem_bytes` already read for `build_x5c` — do not read the file twice.
- No `x5c` configured ⇒ no check. There is no certificate for the `client_id` to
  contradict.

**Behaviors to test:**
- `aud` == `https://self-issued.me/v2` in the signed payload — happy path
  (already asserted by `vp_0042...`)
- leaf SAN `other-host.example.com` vs `public_base_url` host
  `verifier.example.com` → `Err` (already asserted by `vp_0063...`)
- **leaf SAN matching the `public_base_url` host → `Ok`** — mandatory positive
  control, otherwise `vp_0063` also passes if the function merely always errors
- `x5c: None` → `Ok`, no SAN check attempted — guards the no-certificate path
- the existing `request.rs` inline test asserting
  `client_id == "x509_san_dns:verifier.example.com"` still passes — proves the
  `dns_host_only` hoist changed no behaviour

**Docs in this task:**
- `crates/foundry-verifier/AGENTS.md` Gotchas: `build_signed_request_object` now
  hard-fails when the `x5c` leaf's dNSName SAN and the `public_base_url` host
  disagree — a previously silent misconfiguration. Update the existing
  "`client_id` is derived, not configured" bullet, which currently says such a
  mismatch merely "breaks audience binding".
- Register: remove GAP-VP-01 + GAP-VP-02; flip VP-0042, VP-0063 to
  `conforming`; Summary VP → 87 / 9.

**Verify:** `cargo test -p foundry-verifier && cargo test -p foundry --test conformance_report`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 3: `IssuanceError::InvalidNonce` (GAP-VCI-04)

**Files:**
- modify `crates/foundry-issuer/src/error.rs` (variant + `kind()` arm + its own test)
- modify `crates/foundry-issuer/src/nonce.rs` (four failure paths)
- modify `crates/foundry-issuer/src/attestation.rs` (`map_err` at ~`:634`)
- modify `crates/foundry/src/server.rs` (`wallet_error_response` arm)
- modify `crates/foundry-issuer/AGENTS.md` (Gotchas)
- modify `docs/conformance/openid4vc-conformance.md`
- test: un-`#[ignore]` `crates/foundry/tests/conformance_http.rs:346`; update
  `crates/foundry/tests/wallet_issuance.rs:506,551`

**Interfaces:**
- Produces: `IssuanceError::InvalidNonce(String)`, `kind()` → `"invalid_nonce"`,
  mapper → `(StatusCode::BAD_REQUEST, "invalid_nonce")`.
- `verify_nonce(&NonceSecret, &str, i64) -> Result<(), IssuanceError>` signature
  unchanged; four of its `Err` variants change type.

**Exact scope — this is the constraint most likely to be got wrong:**

| Site | Failure | Variant |
|---|---|---|
| `nonce.rs` | not valid base64url | `InvalidNonce` |
| `nonce.rs` | unexpected length | `InvalidNonce` |
| `nonce.rs` | MAC mismatch (forged/foreign) | `InvalidNonce` |
| `nonce.rs` | expired | `InvalidNonce` |
| `proof.rs` | **missing or non-string `nonce` claim** | **stays `InvalidProof`** (L1049 clause 3) |
| `attestation.rs` | missing `nonce` claim | stays `InvalidProof` |
| `attestation.rs` | `verify_nonce` failed | `InvalidNonce`, keep the `key_attestation:` message prefix |

`error.kind()` has no catch-all arm by design (`error.rs:46-47`), so the compiler
will point at every site that needs updating. `wallet_error_response`'s new arm
must sit **before** the `_ =>` catch-all or it silently becomes a 500.

**Behaviors to test:**
- expired `c_nonce` at `/credential` → HTTP 400 `"invalid_nonce"` — happy path
  (already asserted by `vci_0078...`)
- structurally invalid `c_nonce` (`"not-the-real-nonce"`) → `"invalid_nonce"` —
  the `wallet_issuance.rs:506` flip
- **proof with a *missing* `nonce` claim → still `"invalid_proof"`** — the
  boundary case that makes the split meaningful
- proof `aud` mismatch → still `"invalid_proof"` (`wallet_issuance.rs:472`
  unchanged) — positive control that the two codes stay distinguished
- key-attestation nonce failure → `"invalid_nonce"`, `error_description` still
  carrying `key_attestation:`
- `IssuanceError::InvalidNonce(..).kind() == "invalid_nonce"` and the variant's
  detail never appears in `kind()` — matches the existing `error.rs` test pattern

**Docs in this task:**
- `crates/foundry-issuer/AGENTS.md` Gotchas: the `InvalidNonce` / `InvalidProof`
  split is by **cause** (present-but-invalid vs missing), not by call site, and
  `attestation.rs` deliberately propagates `InvalidNonce` while keeping its
  message prefix.
- Register: remove GAP-VCI-04; flip VCI-0078 to `conforming`; Summary VCI → 75 / 19.

**Verify:** `cargo test -p foundry-issuer && cargo test -p foundry --test conformance_http --test wallet_issuance --test conformance_report --test logging_redaction`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 4: `credential_configuration_id` validation (GAP-VCI-02)

**Files:**
- modify `crates/foundry-issuer/src/error.rs` (two variants + `kind()` arms)
- modify `crates/foundry-issuer/src/credential.rs` (`handle_credential_request`)
- modify `crates/foundry/src/server.rs` (two `wallet_error_response` arms)
- modify `crates/foundry-issuer/AGENTS.md` (Gotchas)
- modify `docs/conformance/openid4vc-conformance.md`
- test: un-`#[ignore]` `crates/foundry-issuer/tests/conformance_vci.rs:598`;
  new tests in the same file

**Interfaces:**
- Produces: `IssuanceError::InvalidCredentialRequest(String)` → `kind()`
  `"invalid_credential_request"` → `(400, "invalid_credential_request")`.
- Produces: `IssuanceError::UnknownCredentialConfiguration(String)` → `kind()`
  `"unknown_credential_configuration"` → `(400, "unknown_credential_configuration")`.
- `handle_credential_request` signature unchanged.

**Placement:** after the transaction loads and its `Offered` state is checked (it
needs `tx.credential_type_id`), and **before** `verify_holder_proof` runs — a
misaddressed request must fail on cheap checks, not after signature work.

**Decision table (spec Decision 4):**

| `req.credential_configuration_id` | Outcome |
|---|---|
| `None` | `InvalidCredentialRequest` — L851 makes it REQUIRED here |
| `Some(id)` where `id == tx.credential_type_id` | proceed |
| `Some(id)` present in `config.credential_types` but ≠ bound type | `InvalidCredentialRequest` — unsupported parameter *value* |
| `Some(id)` absent from `config.credential_types` | `UnknownCredentialConfiguration` |

`req.format` is **not** read, validated, or required.

**Behaviors to test:**
- id matching the bound type → issuance succeeds — happy path; the existing
  passing tests (e.g. `vci_0071...`) already cover it and must stay green
- id naming an unknown configuration → `Err` (already asserted by
  `vci_0052...`); assert the variant is `UnknownCredentialConfiguration`
- id absent (`None`) → `InvalidCredentialRequest`
- id naming a *configured* credential type that the access token was not issued
  for (e.g. `"mdl"` on a `"pid"` token) → `InvalidCredentialRequest` — the case
  that distinguishes the two new variants
- rejection happens **before** proof verification — pass a syntactically broken
  proof together with a bad id and assert the error is the config-id one, not a
  proof error
- HTTP surface: both codes emerge as 400 with the right `error` string

**Docs in this task:**
- `crates/foundry-issuer/AGENTS.md` Gotchas: `credential_configuration_id` is now
  validated against the access token's bound type with a three-way split, and
  `format` is deliberately still ignored (not a 1.0 Credential Request parameter).
- Register: remove GAP-VCI-02; flip VCI-0052 to `conforming`; Summary VCI → 76 / 18.

**Verify:** `cargo test -p foundry-issuer && cargo test -p foundry --test conformance_http --test wallet_issuance --test e2e_full_flow --test conformance_report`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 5: RFC 9207 `iss` in the Authorization Response (GAP-HAIP-02)

**Files:**
- modify `crates/foundry-issuer/src/authorize.rs` (`AuthorizeOutcome`, `handle_authorize_request`)
- modify `crates/foundry-issuer/src/metadata.rs` (`AuthorizationServerMetadata`, builder)
- modify `crates/foundry/src/server.rs` (`authorize_handler`, both `append_query` calls)
- modify `crates/foundry-issuer/AGENTS.md` (Gotchas)
- modify `docs/conformance/openid4vc-conformance.md`
- regenerate `openapi-wallet.json`
- test: un-`#[ignore]` `crates/foundry/tests/conformance_http.rs:437`; new tests in
  `conformance_http.rs`, `authorize.rs`'s inline `mod tests` (`:150`) and
  `metadata.rs`'s inline `mod tests` (`:139`)

**Interfaces:**
- Changed: `handle_authorize_request(storage: &dyn Storage, params: &AuthorizeParams, tx_ttl_secs: u64, now_unix: i64) -> AuthorizeOutcome`
  gains `issuer_identifier: &str` (insert it after `params`).
  **There are 13 call sites, not one** — budget for this rather than discovering
  it mid-edit:
  - `crates/foundry/src/server.rs:374` (the only production caller)
  - `crates/foundry-issuer/tests/conformance_vci.rs:374`, `:1017`
  - **ten** inside `authorize.rs`'s own `#[cfg(test)] mod tests` (`:150`),
    at `:210`, `:240`, `:255`, `:270`, `:295`, `:310`, `:325`, `:338`, `:358`

  `grep -rn handle_authorize_request --include='*.rs' crates/` before starting.
- Changed: `AuthorizeOutcome::Success { redirect_uri, code, state }` and
  `AuthorizeOutcome::ErrorRedirect { redirect_uri, error, state }` each gain
  `iss: String`. `DirectError(IssuanceError)` is unchanged — it renders as a JSON
  error body, not a redirect, so RFC 9207 §2 does not reach it.
- Changed: `AuthorizationServerMetadata` gains
  `authorization_response_iss_parameter_supported: bool`, set `true` by
  `build_authorization_server_metadata(cfg: &Config)`. It is a plain required
  field (no `skip_serializing_if`) — §2.3 wants it present and `true`.
- `foundry/src/server.rs`: `authorize_handler` passes
  `state.config.issuer.credential_issuer`. `append_query` itself needs **no**
  change — it already percent-encodes values.

**Behaviors to test:**
- success redirect carries `iss=` — happy path (already asserted by `haip_0008...`)
- **error redirect carries `iss=`** — RFC 9207 §2 "including error responses";
  drive it through the same untrusted-`redirect_uri`/bad-request path that
  `vci_0032_authorize_error_redirect_encodes_error_per_rfc6749` uses
- `iss` value equals `config.issuer.credential_issuer`, percent-encoded, and
  `state` is still present alongside it — guards against clobbering the existing
  parameters
- `DirectError` responses are unaffected (still a JSON 400, no redirect)
- served AS metadata has `authorization_response_iss_parameter_supported == true`
  at `/.well-known/oauth-authorization-server`
- `AuthorizeOutcome::Success.iss` is populated at the engine level — asserted in
  `foundry-issuer`'s own test module, not only through HTTP

**Docs in this task:**
- `crates/foundry-issuer/AGENTS.md` Gotchas: `handle_authorize_request` now takes
  `issuer_identifier`; both redirect outcomes carry `iss`; `DirectError`
  deliberately does not.
- Register: remove GAP-HAIP-02; flip HAIP-0008 to `conforming`; Summary HAIP → 47 / 7.
- `openapi-wallet.json`: regenerate per the command in
  `crates/foundry/AGENTS.md` (§OpenAPI). Note the gotcha there — `serve()`
  rewrites both spec files into the process working directory on startup — so
  confirm with `git diff --stat openapi.json openapi-wallet.json` that only the
  intended `AuthorizationServerMetadata` change landed.

**Verify:** `cargo test -p foundry-issuer && cargo test -p foundry && git diff --stat openapi.json openapi-wallet.json`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

## Final gate (Phase 5 — not a task)

After Task 5, before the review report:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Then confirm no `#[ignore]` for the seven closed gaps survives anywhere:

```bash
grep -rn '#\[ignore' --include='*.rs' crates/ \
  | grep -E 'GAP-VP-01|GAP-VP-02|GAP-VCI-02|GAP-VCI-04|GAP-VCI-08|GAP-VCI-09|GAP-HAIP-02'
```

This must return nothing. Note it greps **`#[ignore]` attributes only**, not any
mention: `conformance_report.rs` scans only those attributes, so a plain comment
citing a now-closed gap id is legal and often useful (it records what the test
now guards). A bare `grep` for the gap ids would produce false alarms.

Finally eyeball the Summary table — it must read 76 / 18, 87 / 9, 47 / 7 with
unchanged totals 232 / 266 / 96:

```bash
sed -n '112,117p' docs/conformance/openid4vc-conformance.md
```

## Progress Log

Append one line per completed task: date, task, commit SHA.

- 2026-08-02 — Task 1 (GAP-VCI-08, GAP-VCI-09) — `6e41ae2`