# GAP-VCI-14 — Client Attestation PoP JWT Verification — Implementation Plan

**Spec:** docs/superlight/specs/2026-08-01-gap-vci-14-client-attestation-pop-spec.md
**Branch:** superlight/2026-08-01-gap-vci-14-client-attestation-pop
**Executed with:** superlight Phase 4 (TDD, inline, no subagents by default)

**Goal:** Verify the `OAuth-Client-Attestation-PoP` JWT at `POST /token` per
Attestation-Based Client Authentication draft -07, with atomic `(iss, jti)`
replay detection bounded by an `iat` sliding window, closing GAP-VCI-14.

**Architecture:** A pure synchronous validator
(`validate_client_attestation_pop_jwt`) performs every cryptographic and claim
check against the `cnf.jwk` of the already-validated Wallet Attestation, and
returns `PopClaims`. A separate `.await`ed step (`claim_pop_jti`) atomically
claims `(iss, jti)` in the KV store via a new `Storage::insert_kv_if_absent`.
Storage never enters the verifier, so every crypto check is unit-testable
without a database.

## Global Constraints

Copied verbatim from the spec:

- **Spec pin:** Attestation-Based Client Authentication **draft -07**, as named
  by OpenID4VCI 1.0 L1600. The checked-in `docs/specs/` copy is the source of
  truth, not any newer draft found online.
- **Signature algorithm:** `ES256` only, for both the attestation JWT and the
  PoP JWT.
- **`aud` value:** exact match against `build_authorization_server_metadata(cfg).issuer`,
  which is `cfg.issuer.credential_issuer` with trailing slashes trimmed. String
  or array form; an array matches iff it contains that exact value. No
  substring, prefix, or case-insensitive matching.
- **Config default:** `pop_max_age_secs = 300`.
- **Clock skew:** `POP_CLOCK_SKEW_SECS = 60`, applied to future-dated `iat` and
  `nbf` only — never to widen the past-age window.
- **KV namespace:** `client_attestation_pop_jti`.
- **Error code:** `invalid_client`, HTTP 400, for every attestation and PoP
  failure.
- **No panics in request paths** (AGENTS.md §4.1).
- **`skip_all` on every `#[tracing::instrument]`** (AGENTS.md §4.5).
- **Dependency layering** (AGENTS.md §3): `foundry-core` gains no dependency on
  any `foundry-*` crate. No new third-party dependencies — `sha2` and `base64`
  are already dependencies of `foundry-issuer`.

There is deliberately **no `exp` check** on the PoP JWT: ABCA removed `exp`
from it in draft -06. A PoP carrying `exp` anyway is accepted (§5.2 rule 1 —
unknown claims MUST be ignored).

## File Structure

| Path | Responsibility |
|---|---|
| `docs/specs/draft-ietf-oauth-attestation-based-client-auth-07.txt` | **New.** Pinned normative text for the PoP JWT |
| `AGENTS.md` | §4.4 spec table gains the ABCA row |
| `crates/foundry-core/src/storage/mod.rs` | `Storage::insert_kv_if_absent` trait method |
| `crates/foundry-core/src/storage/sqlite.rs` | Its `INSERT … ON CONFLICT DO NOTHING` implementation |
| `crates/foundry-core/tests/storage_sqlite.rs` | Atomic-claim behaviour |
| `crates/foundry-core/src/config/model.rs` | `AttestationMode.pop_max_age_secs` + its serde default |
| *(20 files, 47 literals)* | Mechanical `AttestationMode { … }` ripple — see Task 3 |
| `crates/foundry-issuer/src/error.rs` | `IssuanceError::InvalidClient` + `kind()` arm |
| `crates/foundry-issuer/src/attestation.rs` | `ValidatedAttestation`, `PopClaims`, the PoP validator, `claim_pop_jti`, the mode matrix |
| `crates/foundry-issuer/src/token.rs` | `handle_token_request` params, claim call, §6.3 `client_id` cross-check |
| `crates/foundry-issuer/tests/conformance_vci.rs` | The un-`#[ignore]`d gap test + PoP fixtures |
| `crates/foundry/src/server.rs` | Reads the PoP header; supplies `issuer_identifier`; maps `InvalidClient` → 400 |
| `crates/foundry/tests/conformance_http.rs` | HTTP-level `invalid_client` assertion |
| `docs/conformance/openid4vc-conformance.md` | VCI-0232 + HAIP-0088 → `conforming`; GAP-VCI-14 row deleted |
| `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md`, `README.md` | Module map, config field, behaviour-break note |

## Task Dependency Order

```
1 (spec)      ── independent, do first: every later task cites it
2 (storage)   ──┐
6 (validator) ──┼─→ 7 (replay claim) ─→ 8 (mode matrix) ─→ 9 (token) ─→ 10 (server) ─→ 11 (docs)
3 (config)    ──┘                            ↑
4 (error) ─→ 5 (ValidatedAttestation) ───────┘
```

---

### Task 1: Vendor ABCA draft -07 as a pinned spec

**Files:**
- create `docs/specs/draft-ietf-oauth-attestation-based-client-auth-07.txt`
- modify `AGENTS.md` (§4.4 table)

Source: `https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.txt`, committed **verbatim** — no reformatting, no conversion to Markdown. Verbatim fidelity is the point of a pinned spec.

**Interfaces:**
- Produces: the file path above, cited by every subsequent task's code comments.

**Behaviors to test:** none — this task is documentation. Its verification is
structural, not behavioural, and the plan says so rather than inventing a test.

**Verify:**
```bash
grep -q 'oauth-client-attestation-pop+jwt' docs/specs/draft-ietf-oauth-attestation-based-client-auth-07.txt \
  && grep -q 'draft-ietf-oauth-attestation-based-client-auth-07' AGENTS.md \
  && cargo fmt --check
```
The §4.4 table must list four spec rows, and the new row must state that where
OpenID4VCI Appendix E defers to ABCA §5.1/§5.2, ABCA governs.

- [x] Red — n/a (documentation task; no behaviour to fail)
- [x] Green — file vendored verbatim, AGENTS.md §4.4 row added
- [x] Refactor — n/a
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 2: `Storage::insert_kv_if_absent`

**Files:**
- modify `crates/foundry-core/src/storage/mod.rs`
- modify `crates/foundry-core/src/storage/sqlite.rs`
- modify `crates/foundry-core/tests/storage_sqlite.rs`

**Interfaces:**
- Produces:
  ```rust
  async fn insert_kv_if_absent(
      &self,
      namespace: &str,
      key: &str,
      value: &str,
      expires_at: Option<i64>,
  ) -> Result<bool, StorageError>;
  ```
  `true` = this caller claimed the key; `false` = it was already held.
  SQLite: `INSERT INTO kv (namespace, key, value, expires_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(namespace, key) DO NOTHING`, returning `rows_affected() == 1`.

`SqliteStorage` is the only implementor of `Storage` in the workspace.
`put_kv`'s upsert semantics are **not** touched — existing callers must be
unaffected.

**Behaviors to test:**
- first call for a `(namespace, key)` returns `true` — happy path
- second call for the same `(namespace, key)` returns `false`
- a `false` return leaves the existing `value` **and** `expires_at` untouched
  (it is `DO NOTHING`, not an upsert) — the check that distinguishes this from `put_kv`
- the same `key` under a different `namespace` still returns `true`
- a subsequent `put_kv` on a claimed key still overwrites (no regression)

**Verify:** `cargo test -p foundry-core`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 3: `AttestationMode.pop_max_age_secs` + workspace literal ripple

**Files:**
- modify `crates/foundry-core/src/config/model.rs`
- modify the **47** `AttestationMode { … }` struct literals across these 20 files:
  `foundry-core/src/config/{validate,model}.rs`;
  `foundry/tests/{logging_redaction,openapi_endpoints,authorization_code_flow,health,wallet_issuance,wallet_verification,wallet_metadata,console,issuer_offers,conformance_http,wallet_status_list_route}.rs`;
  `foundry-wallet/tests/support/mod.rs`;
  `foundry-issuer/tests/conformance_vci.rs`;
  `foundry-issuer/src/{create_offer,metadata,token,credential}.rs`;
  `foundry-verifier/src/verify.rs`

**Interfaces:**
- Produces: `AttestationMode.pop_max_age_secs: u64`, `#[serde(default = "default_pop_max_age")]`, `fn default_pop_max_age() -> u64 { 300 }`.

Doc comment must state the field is consulted **only** for
`issuer.wallet_attestation`, never for `issuer.key_attestation` — the two share
this struct.

This task is deliberately isolated: it is pure mechanical churn across five
crates, and folding it into a semantic task would bury that task's real diff.
Chosen over a bare constant with the trade-off understood (see spec, Q7 in the
Phase 3 record) — operator tunability was worth the 47 edits.

**Behaviors to test:**
- a config omitting `pop_max_age_secs` deserializes to `300` — happy path
- a config setting it explicitly honours that value
- a config setting it to `0` still parses (whether to validate the value is a
  separate decision — do not silently clamp)

**Verify:** `cargo test --workspace` — this is the ripple task; the whole
workspace must compile and stay green before moving on.

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 4: `IssuanceError::InvalidClient` + HTTP mapping

**Files:**
- modify `crates/foundry-issuer/src/error.rs`
- modify `crates/foundry/src/server.rs` (`wallet_error_response` only)

**Interfaces:**
- Produces: `IssuanceError::InvalidClient(String)`, `#[error("invalid client: {0}")]`, `kind() == "invalid_client"`.
- Consumes: nothing.

`kind()`'s match is exhaustive with no catch-all, so the new variant is a
compile error until its arm exists — that is intended and must not be
circumvented with a wildcard.

**Behaviors to test:**
- `InvalidClient(_).kind() == "invalid_client"` — added to the existing
  `kind_is_a_stable_name_for_every_variant` case list
- `kind()` does not leak the detail string
- `wallet_error_response(&InvalidClient(_))` yields HTTP 400 and
  `{"error": "invalid_client"}`
- `admin_error_response` treats it as 500 (it is not an admin-surface error) —
  assert the existing catch-all still holds

**Verify:** `cargo test -p foundry-issuer -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 5: `ValidatedAttestation` + migrate attestation failures to `InvalidClient`

**Files:**
- modify `crates/foundry-issuer/src/attestation.rs` (22 `InvalidRequest` sites in production code, 8 more in its `#[cfg(test)]` module at line 398+)
- modify `crates/foundry-issuer/src/token.rs` (the single `validate_wallet_attestation_jwt` caller)

**Interfaces:**
- Consumes: `IssuanceError::InvalidClient` (Task 4).
- Produces:
  ```rust
  pub struct ValidatedAttestation {
      pub sub: String,
      pub cnf_jwk: josekit::jwk::Jwk,
  }
  fn validate_wallet_attestation_jwt(
      attestation_jwt: &str,
      trust_store: &TrustStore,
      now_unix: i64,
  ) -> Result<ValidatedAttestation, IssuanceError>;
  ```

`sub` and `cnf.jwk` are already parsed and discarded today — the existing
comment at attestation.rs:171-174 says they are kept "available for a future PoP
implementation (GAP-VCI-14)". Delete that comment and the one at line 48-53 as
part of this task; they describe a state that no longer exists.

**Behaviors to test:**
- a valid attestation returns its `sub` and a `cnf_jwk` usable as a verification key — happy path
- every existing attestation rejection test still rejects, now asserting
  `InvalidClient` rather than `InvalidRequest`
- an attestation whose `cnf.jwk` is structurally valid but not an EC P-256
  public key is rejected (it must be usable as an ES256 verification key)

**Verify:** `cargo test -p foundry-issuer`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 6: `validate_client_attestation_pop_jwt`

**Files:**
- modify `crates/foundry-issuer/src/attestation.rs`

**Interfaces:**
- Consumes: `ValidatedAttestation` (Task 5).
- Produces:
  ```rust
  pub struct PopClaims { pub iss: String, pub jti: String, pub iat: i64 }
  const POP_CLOCK_SKEW_SECS: i64 = 60;
  fn validate_client_attestation_pop_jwt(
      pop_jwt: &str,
      attestation: &ValidatedAttestation,
      expected_aud: &str,
      now_unix: i64,
      max_age_secs: u64,
  ) -> Result<PopClaims, IssuanceError>;
  ```

Each of the nine checks carries a code comment naming its ABCA clause — see the
spec's check table. Every failure is `IssuanceError::InvalidClient`.
`#[tracing::instrument(skip_all)]` is mandatory: the argument is the PoP JWT.

**Behaviors to test:**
- a valid PoP returns `PopClaims` — happy path
- not three dot-separated parts; header or payload not base64url
- `typ` absent; `typ` present but not `oauth-client-attestation-pop+jwt`
- `alg: none`
- `alg: HS256` on a genuinely HS256-signed JWT — proves the check is enforced by
  attempted verification, not assumed because every fixture happens to be ES256
- signature made by a key other than the attestation's `cnf.jwk`
- `iss` absent; `iss` present but ≠ attestation `sub`
- `aud` absent; `aud` a wrong string
- `aud` an array **containing** `expected_aud` (accept)
- `aud` an array **not** containing it (reject)
- `aud` matching only as a prefix or by case-insensitive comparison (reject —
  guards the "exact match" constraint)
- `jti` absent; `jti` an empty string; `jti` not a string
- `iat` absent; `iat` not an integer
- `iat` older than `max_age_secs` (reject)
- `iat` more than `POP_CLOCK_SKEW_SECS` in the future (reject)
- `iat` slightly in the future, within skew (accept)
- `nbf` present and beyond `now + skew` (reject)
- an unrecognised extra claim present (accept — §5.2 rule 1)
- an `exp` claim present and already past (**accept** — ABCA has no `exp` on the
  PoP JWT; this test pins the deliberate omission so a future reader does not
  "fix" it)

**Verify:** `cargo test -p foundry-issuer`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 7: `claim_pop_jti` — atomic replay detection

**Files:**
- modify `crates/foundry-issuer/src/attestation.rs`

**Interfaces:**
- Consumes: `PopClaims` (Task 6); `Storage::insert_kv_if_absent` (Task 2).
- Produces:
  ```rust
  const POP_JTI_NAMESPACE: &str = "client_attestation_pop_jti";
  pub(crate) async fn claim_pop_jti(
      storage: &dyn Storage,
      claims: &PopClaims,
      max_age_secs: u64,
  ) -> Result<(), IssuanceError>;
  ```

Key: base64url-no-pad of `SHA-256(iss ‖ 0x00 ‖ jti)`. Value `"1"`.
`expires_at = claims.iat + max_age_secs + POP_CLOCK_SKEW_SECS`.
No `now_unix` parameter — the TTL derives from the PoP's own `iat`, which
Task 6 has already bounded against `now`; passing `now` again would create a
second source of truth for the same fact.

`insert_kv_if_absent` returning `false` ⇒ `InvalidClient`.

**Behaviors to test:**
- first claim for a `(iss, jti)` succeeds — happy path
- an immediate second claim of the same `(iss, jti)` is rejected
- a different `jti` under the same `iss` succeeds
- the **same** `jti` under a different `iss` succeeds — proves `(iss, jti)`
  keying rather than bare `jti`, i.e. one wallet cannot deny service to another
- the stored row's `expires_at` is `iat + max_age + skew`, not `now + …`
- the stored key is not the raw `jti` (assert the raw `jti` string does not
  appear as a key) — the anti-log-leak property

**Verify:** `cargo test -p foundry-issuer`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 8: `verify_wallet_attestation` mode matrix

**Files:**
- modify `crates/foundry-issuer/src/attestation.rs` (the `WalletAttestationVerifier` trait and `DefaultAttestationVerifier`)

**Interfaces:**
- Consumes: `PopClaims`, `validate_client_attestation_pop_jwt` (Task 6); `AttestationMode.pop_max_age_secs` (Task 3).
- Produces:
  ```rust
  fn verify_wallet_attestation(
      &self,
      mode: Mode,
      attestation_header: Option<&str>,
      pop_header: Option<&str>,
      trust_store: &TrustStore,
      expected_aud: &str,
      now_unix: i64,
      max_age_secs: u64,
  ) -> Result<Option<PopClaims>, IssuanceError>;
  ```

Stays **synchronous** and takes no `Storage` — the replay claim is Task 9's
separate step. Making this async would force a database into every crypto unit
test for no gain.

**Behaviors to test:** all nine rows of the matrix —

| `Mode` | Attestation | PoP | Expected |
|---|---|---|---|
| `Disabled` | any | any | `Ok(None)`, no validation performed |
| `Required` | absent | absent | reject |
| `Required` | absent | present | reject |
| `Required` | present | absent | reject (ABCA §6.2 rule 2) |
| `Required` | present | present | `Ok(Some(claims))` |
| `Optional` | absent | absent | `Ok(None)` |
| `Optional` | absent | present | reject (no `cnf` key to verify against) |
| `Optional` | present | absent | reject (ABCA §6.2 rule 2) |
| `Optional` | present | present | `Ok(Some(claims))` |

Plus: in `Disabled` mode a **structurally invalid** attestation and PoP are
both ignored (proves no validation runs at all, not that validation happens to
pass).

**Verify:** `cargo test -p foundry-issuer`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 9: `handle_token_request` wiring, §6.3 `client_id`, and the gap test

**Files:**
- modify `crates/foundry-issuer/src/token.rs` (16 `handle_token_request(` occurrences, incl. its `#[cfg(test)]` module)
- modify `crates/foundry-issuer/tests/conformance_vci.rs` (11 occurrences + the `#[ignore]`d gap test at line ~1176)

**Interfaces:**
- Consumes: `verify_wallet_attestation` (Task 8), `claim_pop_jti` (Task 7).
- Produces:
  ```rust
  pub async fn handle_token_request(
      storage: &dyn Storage,
      req: &TokenRequest,
      wallet_attestation: &AttestationMode,
      attestation_header: Option<&str>,
      pop_header: Option<&str>,
      issuer_identifier: &str,
      now_unix: i64,
  ) -> Result<TokenResponse, IssuanceError>;
  ```

Order of operations after a successful verification returning `Some(claims)`:
1. `claim_pop_jti(...)` — replay rejected here, before any grant work.
2. ABCA §6.3: if `req.client_id` is `Some(id)`, `id` MUST equal the
   attestation's `sub` **and** the PoP's `iss`. Assert both comparisons even
   though Task 6 already proved them equal — the spec names both, and the
   redundancy is the point.

Add `pop_present = pop_header.is_some()` to the existing
`tracing::info!` fields. `skip_all` stays.

The gap test `vci_0232_wallet_attestation_pop_jwt_is_never_verified` is
un-`#[ignore]`d and **renamed** to
`vci_0232_rejects_a_wallet_attestation_presented_without_a_pop_jwt` — its
current name asserts the bug rather than the requirement. Task 11 updates the
two register rows that cite the old name.

**Behaviors to test:**
- attestation + valid PoP → token issued — happy path
- attestation with **no** PoP → rejected (this is the un-`#[ignore]`d gap test)
- the same PoP replayed on a second token request → rejected
- `req.client_id` present and equal to `sub`/`iss` → accepted
- `req.client_id` present and different → rejected (ABCA §6.3)
- `req.client_id` absent → accepted (the check is conditional)
- replay is rejected **before** the grant is consumed — a replayed PoP must not
  burn the pre-authorized code

**Verify:** `cargo test -p foundry-issuer`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 10: HTTP wiring in `server.rs`

**Files:**
- modify `crates/foundry/src/server.rs` (the token handler, ~line 426)
- modify `crates/foundry/tests/conformance_http.rs`

**Interfaces:**
- Consumes: `handle_token_request`'s new signature (Task 9); `IssuanceError::InvalidClient` mapping (Task 4).
- Produces: no new public API.

Reads `OAuth-Client-Attestation-PoP` alongside the existing header. Supplies
`issuer_identifier` from
`foundry_issuer::build_authorization_server_metadata(&state.config).issuer` —
**not** re-derived from `config.issuer.credential_issuer` — so the value
published at `/.well-known/oauth-authorization-server` and the value checked
cannot drift apart.

**Behaviors to test:**
- a token request with both headers and a valid pair → 200
- a token request with only `OAuth-Client-Attestation` → 400 `{"error": "invalid_client"}`
- the PoP header is read case-insensitively (`oauth-client-attestation-pop`)
  — ABCA §6.1 / RFC 9110
- a PoP whose `aud` is the **token endpoint URL** rather than the issuer
  identifier → 400, proving the wiring passes the issuer identifier and not
  some other URL

Also extend `crates/foundry/tests/logging_redaction.rs`. AGENTS.md §4.5 makes
redaction a *behavioural* requirement with a positive control, and this work
introduces two new secret-bearing values; without these assertions the
invariant is enforced only by code review:

- the raw PoP JWT never appears in captured log output, with
  `sensitive_enabled()` both on and off
- the raw `jti` never appears in captured log output
- the existing positive control still fires, so a passing redaction assertion
  cannot be vacuous

**Verify:** `cargo test -p foundry`

- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

### Task 11: Conformance register and documentation

**Files:**
- modify `docs/conformance/openid4vc-conformance.md`
- modify `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md`
- modify `README.md`

**Interfaces:** none — documentation only.

Register changes:
- **VCI-0232** `gap` → `conforming`; evidence rewritten to describe
  `validate_client_attestation_pop_jwt` + `claim_pop_jti`; test reference
  updated to the renamed test.
- **HAIP-0088** `gap` → `conforming` — "ES256 for validating Wallet
  Attestations **including proof of possession**" is now true.
- **GAP-VCI-14** row **deleted**. Register: 21 rows → **20**.
- VCI and HAIP summary counts recounted from the file, not carried over.

Docs:
- `crates/foundry-core/AGENTS.md` — `Storage` gained `insert_kv_if_absent`;
  `AttestationMode` gained `pop_max_age_secs`.
- `crates/foundry-issuer/AGENTS.md` — `attestation.rs` now also verifies the
  PoP JWT and owns the `client_attestation_pop_jti` namespace.
- `README.md` — the new config field **and** an explicit note that deployments
  on `wallet_attestation.mode = required` now also require the
  `OAuth-Client-Attestation-PoP` header. This is a behaviour break and must not
  arrive as a surprise.
- `openapi.json` — **verify** whether regeneration is needed. Expectation: no,
  the 400 body shape is unchanged and only the `error` string value differs.
  Confirm rather than assume; regenerate if the diff says otherwise.

**Behaviors to test:** none — documentation. Verified structurally.

**Verify:**
```bash
! grep -q 'GAP-VCI-14' docs/conformance/openid4vc-conformance.md \
  && [ "$(grep -c '^| GAP-' docs/conformance/openid4vc-conformance.md)" = "20" ] \
  && ! grep -rq 'vci_0232_wallet_attestation_pop_jwt_is_never_verified' . \
  && cargo test --workspace \
  && cargo clippy --workspace --all-targets -- -D warnings \
  && cargo fmt --check
```

- [ ] Red — n/a (documentation task)
- [ ] Green — register and docs updated
- [ ] Refactor — n/a
- [ ] Verify — run the command, pristine output
- [ ] Commit

---

## Progress Log

Append one line per completed task: date, task, commit SHA.

- 2026-08-01 — Task 1 (vendored ABCA draft -07 verbatim to `docs/specs/`; AGENTS.md §4.4 gained its row) — `a5fea96`
