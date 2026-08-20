# AGENTS.md — `crates/foundry-verifier`

## Purpose

The **OpenID4VP verification engine**: builds and signs authorization request
objects, decrypts the wallet's JWE (ECDH-ES) response, delegates credential
verification to the format crates, matches DCQL, and checks Token Status List
revocation/suspension. Produces a `VerificationResult` whose `verified` verdict
is computed from named `CheckResult` records.

**Not** in scope here: HTTP routing and status-code mapping (that is
`crates/foundry`), credential-format cryptography (delegated to
`foundry-sd-jwt-vc` / `foundry-mdoc`), and issuance (`foundry-issuer`).

## Position in the Dependency Graph

- **Depends on:** `foundry-core`, `foundry-sd-jwt-vc`, `foundry-mdoc`. The DCQL
  wire model is foundry-owned (`dcql_model.rs`) — there is no protocol-library
  dependency.
- **Consumed by:** `crates/foundry` (HTTP handlers).
- **Must never depend on:** `foundry-issuer` or `crates/foundry`.

Full layering rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
| --- | --- |
| `lib.rs` | Module declarations and the `pub use` surface |
| `request.rs` | Creates a verification request (`create_verification_request`), generates the nonce + ephemeral ECDH key pair, and builds the signed Request Object JWT (`build_signed_request_object`); derives `client_id` as `x509_hash:<base64url(SHA-256(DER leaf))>` via `foundry_core::trust::x509_hash_client_id_value` (HAIP OpenID4VP L256) |
| `verify.rs` | The orchestrator: JWE decrypt → `select_presentations` → a per-credential verify-all loop (`verify_one_credential`, which returns **no `Result`**) → `requested_credentials_answered`, then computes `verified` as the conjunction over **both** check levels. Returns a `VerifyOutcome` internally so a per-credential failure can become HTTP 400/502 without discarding the other credentials' checks. Also flips `tx.state` to `Verified`/`Failed` and stores `tx.result` |
| `dcql.rs` | `PresentedFormat` (`SdJwtVc` \| `MsoMdoc`) and `check_dcql_match`, which returns a `CheckResult` and **never errors** (fail-closed) |
| `credential_sets.rs` | **Crate-private** DCQL Credential Set Query satisfaction — which *combinations* of answered credential queries answer the request (`check_credential_sets_satisfied`, OpenID4VP 1.0 L879-L894, L989-L1008). Pure, total, fail-closed like `check_dcql_match`: a required set is satisfied when at least one of its `options` is a subset of the answered credential query ids |
| `dcql_model.rs` | **Crate-private** DCQL wire model per OpenID4VP 1.0 §6/§7: `DcqlQuery`, `DcqlCredentialQuery`, `DcqlClaimsQuery`, `DcqlCredentialSetQuery`, `ClaimsPathSegment`, `ClaimValue`, `CredentialFormat`. Five spec non-empty constraints are enforced at deserialization (`credentials`, `credential_sets`, `options` and each individual option, `claims[].path`, `claims[].values`) because each is fail-closed. `CredentialFormat::Other(String)` is **required**, not cosmetic: without it an unimplemented format would fail parsing and be reported as a malformed query instead of simply not matching. Never add `deny_unknown_fields` — §6 requires unknown properties to be ignored |
| `status.rs` | `StatusListResolver` trait + `HttpStatusListResolver` (10s timeout); `check_status` resolves the Status List Token, verifies it against the trust store, and reads the credential's status bit |
| `transaction.rs` | `VerificationTransaction`, `VerificationState`, `CheckResult`, `VerificationResult`, and `Storage`-backed persistence (namespace `verification_tx`) — **note: the result/check types live here, not in `error.rs`** |
| `error.rs` | The `VerificationError` enum only |

## Key Public Types & Entry Points

- **`verify_vp_response(&Config, &mut VerificationTransaction, encrypted_jwe_str, &dyn StatusListResolver) -> Result<VerificationResult, VerificationError>`**
  — the main entry point, driven by `POST /vp/response/:id`.
- **Request:** `create_verification_request`, `build_signed_request_object`,
  `CreateVerificationRequest`, `CreateVerificationResponse` — driven by
  `POST /admin/verification/requests` and `GET /vp/request/:id`.
- **DCQL:** `check_dcql_match(dcql_query, format, disclosed_claims, doc_type) -> CheckResult`,
  `PresentedFormat`.
- **Transaction Data:** `check_transaction_data_binding(requested_entries, answered_query_id, kb_payload) -> CheckResult`
  (`verify.rs`) — pushed only when `tx.transaction_data` is `Some`; never errors
  (fail-closed), matching `check_dcql_match`'s contract.
- **Status:** `check_status(disclosed_claims, trust_store, resolver, now_unix) -> Result<CheckResult, VerificationError>`,
  `StatusListResolver`, `HttpStatusListResolver`.
- **Transaction / results:** `VerificationTransaction` (fields include `id`,
  `state`, `nonce`, `dcql_query`, `transport`, `response_mode`,
  `ephem_private_jwk`, `ephem_public_jwk`, `transaction_data`, `result`,
  `created_at`), `VerificationState` (`Pending` | `Verified` | `Failed`),
  `VerificationResult { verified, checks, credentials }`,
  `PresentedCredential { query_id, format, credential_type, claims, checks }`
  (`credential_type` is the ASSERTED `vct`/`docType` — authenticated only when
  that credential's format check passed, the same caveat as `claims`),
  `CheckResult { check, passed, detail }`. `VerificationResult::all_checks()`
  yields every check at both levels; `derive_verified()` is the §4.2 verdict.
  Also `save_verification_transaction`, `load_verification_transaction`.
- **Errors:** `VerificationError` — `NotFound`, `InvalidState`, `Dcql`,
  `Crypto`, `Decryption`, `Failed`, `StatusUnavailable`, `Storage`,
  `CoreCrypto`, `Trust`, `Serialization`.

## Binding Invariants

- **Every `#[tracing::instrument]` in this crate MUST carry `skip_all`.** Without
  it every argument is `Debug`-formatted into the span — including `Config` and
  `VerificationTransaction`, which holds `ephem_private_jwk`, plus raw JWE
  strings. Fields are opt-in, always. Enforced by
  `crates/foundry/tests/instrumentation_hygiene.rs`.
- **Payload-bearing log fields require BOTH `obs::sensitive_enabled()` AND a
  `debug`/`trace` level.** A level alone is not authorisation — `RUST_LOG=debug`
  is ordinary in production. Never log an ephemeral or private JWK at all.
  Redaction tiers: see the "Logging & Observability" section of the root
  [README.md](../../README.md).
- **A policy failure logs at `warn`, not `error`.** A DCQL mismatch or a revoked
  credential is a correct outcome that still returns HTTP 200 with
  `verified: false` (root [AGENTS.md](../../AGENTS.md) §4.3); reserve `error` for
  actual faults such as an unreachable status list.
- **`verified` MUST equal the conjunction over EVERY check, at both levels** —
  use `all_checks()` / `derive_verified()`, never `checks.iter().all(..)`,
  which passes while a per-credential check fails. Never hardcode
  `verified: true`; it is computed once at the end of `do_verify_vp_response`.
  Full rule: root [AGENTS.md](../../AGENTS.md) §4.2.
- **Every verification step must push a named `CheckResult`, at one of two
  levels.** **Cross-cutting** (`result.checks`): `jwe_decryption`,
  `requested_credentials_answered`. **Per-credential**
  (`result.credentials[i].checks`): `sd_jwt_vc_signature_and_kb_jwt` or
  `mdoc_issuer_auth_and_device_signature` — mutually exclusive, chosen by the
  answered credential query's **declared format**, never by the JSON type of
  the payload — plus `dcql_match`, `status_check`, and
  `transaction_data_binding` only when `tx.transaction_data` is `Some`. An mdoc
  presentation with `transaction_data` requested still gets that check pushed,
  recorded as a hard `passed: false` (no KB-JWT exists to bind it) — full rule:
  root [AGENTS.md](../../AGENTS.md) §4.2.
- **The error path of `verify_vp_response` MUST populate `tx.result`.** Setting
  only `tx.state = Failed` leaves the reason inside the returned `Err`, which the
  HTTP layer sends to the *wallet* — so the admin console renders a bare red
  "failed" with no explanation (it shows its checks list only when `tx.result` is
  present). `check_name_for` maps the aborting variant onto the same check
  vocabulary the success path uses.
- **Never skip a push on a failure path.** An omitted `CheckResult` silently
  disappears from `all(passed)` and can turn a failure into a pass — root
  [AGENTS.md](../../AGENTS.md) §4.2.
- **Policy vs. structural classification is split across two crates.** This crate
  encodes it in the return type; `crates/foundry/src/server.rs` maps it to a
  status code in `verifier_wallet_error_response`:
  - **Policy** → return `Ok` with a `CheckResult { passed: false }`, giving
    HTTP 200 + `verified: false`. This is what `dcql_match` failures and
    revoked/suspended/malformed-status outcomes do.
  - **Structural / crypto** → `Decryption(_)` / `Failed(_)` / `Serialization(_)`
    → HTTP **400** `invalid_request`.
  - **Network** → `StatusUnavailable(_)` → HTTP **502** `status_unavailable`.
  - Anything else falls through to HTTP 500, so **adding a new
    `VerificationError` variant without updating that handler silently produces
    a 500** — full rule: root [AGENTS.md](../../AGENTS.md) §4.3.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside
  `#[cfg(test)]`; return `VerificationError` — root
  [AGENTS.md](../../AGENTS.md) §4.1.
- **`VerificationResult` and friends are `utoipa::ToSchema`** — changing them
  changes `openapi-wallet.json` — root [AGENTS.md](../../AGENTS.md) §6.
- **One gate, always the whole workspace:** `cargo fmt`, then
  `cargo nextest run --workspace --no-fail-fast --status-level fail`, then
  `cargo clippy --workspace --all-targets -- -D warnings`. There is no scoped
  tier — the suite runs in seconds, so running less than all of it only reduces
  coverage. It also means this crate's flow coverage in `crates/foundry/tests`
  is never something you have to remember to include. **Do not use
  `cargo test`.** Full rule: root [AGENTS.md](../../AGENTS.md) §5.

## Tests

No `tests/` directory. Unit coverage is inline `#[cfg(test)]` in `dcql.rs`,
`error.rs`, `request.rs`, `status.rs`, `transaction.rs`, `verify.rs` (including
positive, DCQL-mismatch, and revocation cases). Flow coverage lives in
`crates/foundry/tests/` — see [`../foundry/tests/AGENTS.md`](../foundry/tests/AGENTS.md);
most relevant: `wallet_verification.rs`, `e2e_full_flow.rs`,
`wallet_status_list_route.rs`.

```bash
cargo nextest run --workspace --no-fail-fast --status-level fail  # the gate (§5.1)
cargo nextest run -p foundry-verifier                             # unit loop, while iterating
cargo nextest run -p foundry --test wallet_verification           # verification flow only
```

## Gotchas

- **`check_status` treats a missing status claim as a PASS.** A credential with
  no `status.status_list` claim is considered non-revocable and the check passes.
  Only a revoked/suspended index, a malformed status claim, or a Status List
  Token that fails trust-anchor/`sub`/`exp` verification produce
  `passed: false`; only an IO/network failure returns
  `Err(VerificationError::StatusUnavailable)`. Do not "tighten" the missing-claim
  case without checking the callers.
- **`check_dcql_match` never returns `Err`** — it always yields a `CheckResult`
  and is deliberately fail-closed (an unparseable `dcql_query` becomes
  `passed: false` with a reason). Do not convert it to a `Result`.
- **`check_dcql_match` is bound to the credential query the presentation
  ANSWERS**, via its `answered_query_id` argument — not to "any credential query
  of the presented format". A presentation must satisfy the query it was keyed
  under, so it cannot be credited to a different query it happens to satisfy.
  An `answered_query_id` absent from the query is a failed check, never an error.
- **`dcql_query` is validated when the request is CREATED**, in
  `create_verification_request`, before the transaction is persisted. An
  unusable query is the operator's `VerificationError::Dcql` (HTTP 400) rather
  than a wallet-visible presentation failure. The fail-closed branch inside
  `check_dcql_match` therefore stays as defence in depth but is not normally
  reachable via the request path.
- **Single-use enforcement is in the HTTP handler, not this crate.**
  `post_response_handler` rejects any transaction whose state is not `Pending`
  with 400 `invalid_request`. `verify_vp_response` itself does not check prior
  state — it only writes the new one.
- **`verify_vp_response` mutates the transaction but does not persist it.** It
  sets `tx.state` and `tx.result`; the caller must call
  `save_verification_transaction` afterwards (the handler does this even on the
  error path).
- **`jwe_decryption` is seeded as `passed: true`, never as a failure.** JWE
  failure is an early `Err(Decryption(..))` → 400, so a `verified: false` result
  will never carry a failed `jwe_decryption` record.
- **The DC API audience prefix has two accepted spellings, and only one is
  on by default.** OpenID4VP 1.0 (L618, L2543) mandates `origin:<origin>`;
  OpenID4VP **draft 24** Appendix A.2 spelled the same thing
  `web-origin:<origin>` (it was the "synthetic Client Identifier Scheme" of an
  unsigned DC API request, and the KB-JWT `aud` was that Client Identifier).
  Wallets still implementing draft 24 are in the field — real Google Wallet as
  of 2026-08 — so `verifier.dc_api_accept_legacy_web_origin_audience` adds the
  legacy spelling to `expected_audiences`. It is **opt-in and defaults to
  false**: accepting a superseded draft's audience unconditionally would turn
  VP-0265 into a silent deviation for every deployment. It relaxes the
  **prefix only** — the Origin half is still matched against
  `dc_api_expected_origins`, so the flag never widens the set of acceptable
  Origins, and `do_verify_vp_response` emits a `warn` naming the audience each
  time a presentation is accepted on it. Do not "simplify" this by always
  pushing both prefixes.
- **`client_id` is derived, not configured:** `x509_hash:<base64url(SHA-256(DER leaf))>`
  (HAIP OpenID4VP L256 / OpenID4VP L616), computed by
  `foundry_core::trust::x509_hash_client_id_value` and re-derived independently by
  both `build_signed_request_object` and `do_verify_vp_response` so the two sides
  cannot drift. GAP-VP-02's SAN cross-check is anchored on
  `server.wallet_facing.public_base_url`'s host, not on the client_id (which no
  longer carries a hostname): `build_signed_request_object` **hard-fails** on a
  mismatch between that host and the configured `x5c` leaf's dNSName SAN entries
  (`foundry_core::trust::match_san_dns`) — what used to be a silent
  audience-binding break for both formats is now a `VerificationError::Crypto`
  raised before the Request Object is ever signed. `x5c` is mandatory for signed
  requests (the identifier *is* the certificate hash), so this check is always
  attempted.
- **`vp_token` is an OpenID4VP 1.0 §8.1 object keyed by DCQL credential query id,
  with ARRAY values** — `{ "<query id>": [ <presentation> ] }` — and that is the
  same shape for **both** credential formats. The credential format comes from
  the `format` **declared by the answered credential query**, never from the JSON
  type of the payload. `select_presentations` (in `verify.rs`) performs the
  selection and returns already-destructured payloads, so no verification arm
  can re-derive the format.
  Never restore type-sniffing (`vp_token.as_str()` ⇒ SD-JWT, `as_object()` ⇒
  mdoc): because a conformant SD-JWT VC envelope is *also* an object, that logic
  routed real SD-JWT presentations into the mdoc branch and reported the
  misleading `mdoc vp_token missing 'mdoc'`. A bare-string `vp_token` was
  foundry's own pre-fix shape and no conformant wallet sends it.
  Per-format payloads: `dc+sd-jwt` → the SD-JWT VC string; `mso_mdoc` → the
  base64url of an ISO/IEC 18013-5 `DeviceResponse` (OpenID4VP L2825-L2828).
  **Both formats are therefore JSON strings**, which is why the format must come
  from the declared query and never from the payload's JSON type.
  `mso_mdoc` previously carried a foundry-invented
  `{ "mdoc": …, "device_signature": … }` object that no wallet ever sent; it is
  now rejected outright rather than accepted alongside the conformant shape. The
  remaining mdoc non-conformance is on the **issuance** side — the OpenID4VCI
  credential envelope — not here; see `crates/foundry-mdoc/AGENTS.md`.
  A credential query whose `format` this verifier does not implement
  (`CredentialFormat::Other`) is a structural 400 once answered, even though it
  parses fine so it can simply fail to match inside a multi-credential query.
- **`PresentedFormat::MsoMdoc`** is the variant name (not `Mdoc`), matching
  `dcql_model::CredentialFormat::MsoMdoc` (note: lower-case `d` in `Mdoc` —
  the removed vendored type spelled it `MsoMDoc`).
- **A `vp_token` may answer SEVERAL credential queries**, and each answered
  query becomes one `PresentedCredential` in **DCQL declaration order** — not
  `vp_token` key order, which depends on the wallet's serialization and on
  whether `serde_json` was built with `preserve_order`. `select_presentations`
  performs the selection.
- **Each entry's array still holds exactly one presentation.** OpenID4VP
  L1166: "When `multiple` is omitted, or set to `false`, the array MUST contain
  only one Presentation." foundry ignores `multiple` (VP-0090), so it never
  requests more than one and the rule always applies. If `multiple: true` is
  ever honoured, this guard must move behind that flag in the same change.
- **Claims are per credential and MUST NOT be merged.** `check_status` reads
  `status.status_list` out of the map it is handed, so a merged map runs one
  credential's revocation check against another's status list — silently, with
  a passing `status_check`. Two credentials disclosing the same claim name
  collide the same way.
- **A subset `vp_token` is a POLICY verdict, not a 400.** It violates
  OpenID4VP L1007-1008 (a wallet that cannot deliver all non-optional
  Credentials MUST NOT return any), but it is well-formed, so it yields
  HTTP 200 + `verified: false` with a failed `requested_credentials_answered`
  naming the unanswered ids — and the detail attributes the fault to the
  wallet. An id the request never asked for stays structural (400): there is
  no credential query to attribute a verdict to.
- **The two completeness checks are mutually exclusive, and which one applies
  is decided by the query.** `verify::check_response_completeness` parses
  `dcql_query` once and emits `requested_credentials_answered` when
  `credential_sets` is ABSENT (OpenID4VP L993 — every credential query is then
  non-optional) or `credential_sets_satisfied` when it is PRESENT (L995-L997 —
  the sets decide which combinations answer the request). Never both: emitting
  both would fail the conjunctive check every time a wallet correctly omitted
  an optional credential. Check names are operator-facing API (root
  [AGENTS.md](../../AGENTS.md) §4.2/§4.5), so adding a third emitter, renaming
  one, or changing which branch emits which name is a breaking change. The
  parse-failure branch keeps the LEGACY name deliberately — without a parsed
  query there is no way to know which algebra was intended.
- **Set satisfaction is defined on PRESENCE, not validity.** A revoked or
  otherwise failing credential still satisfies its option; the verdict still
  goes to `false` via §4.2's conjunction over that credential's own
  `status_check`. Making the set check validity-aware would make one revoked
  credential produce two failed checks reporting the same fact, and would
  yield a `credential_sets_satisfied: false` that does not actually mean the
  combination was wrong. An unsatisfied REQUIRED set is policy (HTTP 200 +
  `verified: false`); an unsatisfied OPTIONAL set can never fail the check and
  is reported in `detail` only.
- **An unavailable status list still returns 502, but must not be lossy.**
  `do_verify_vp_response` returns `VerifyOutcome { result, deferred }`; the
  wrapper persists `result` first, then re-raises. It also pushes a top-level
  failed `status_check` — without it, an unavailable status pushes no check at
  all and the conjunction computes `true`, persisting `verified: true` on a
  transaction that just returned 502.
- **`verify_one_credential` returns no `Result`, on purpose.** It returns
  `(PresentedCredential, Option<VerificationError>)` so the per-credential loop
  cannot `?` out of itself. It previously returned `Result` and the loop used
  `?`, which meant the first credential's failure abandoned every credential
  after it — while the comment above the loop claimed verify-all. The type won
  the argument with the comment. If you find yourself wanting a `Result` here,
  you are re-introducing that bug. The format-specific stage lives in
  `verify_credential_payload`, which *does* return `Result`, so exactly one place
  converts that `Err` into a failed `CheckResult`.
- **A failed format check short-circuits that credential's remaining checks.**
  No `dcql_match` and no `status_check` are recorded for it, and its `claims` is
  an empty object. Running those against claims that were never obtained would
  report three failures where one occurred, two of them misattributed — "DCQL
  mismatch" when the truth is "we never obtained claims".
- **Recording a fault and choosing the response status are SEPARATE steps, and
  must stay separate.** The loop collects *every* per-credential error into
  `faults`. Step 5 then pushes one top-level `status_check` per
  `StatusUnavailable`, and step 5b reduces `faults` to the single error the
  wallet is told about (crypto/structural 400 outranks unavailable 502, because a
  bad signature is deterministic and a 502 would invite the wallet to retry
  something that can never succeed; within one class the incumbent wins, so DCQL
  declaration order decides). Collapsing these back into one `deferred` slot
  chosen by precedence is what the first attempt did, and it made an
  unavailability vanish entirely whenever a crypto failure outranked it: it has
  no per-credential record by design, so the top-level one is the *only* place it
  can appear. Pinned by
  `a_crypto_failure_outranks_an_unreachable_status_list`.
- **The top-level fault record is `StatusUnavailable`-only.** Every other
  per-credential failure already has a per-credential record from
  `verify_one_credential`, so a top-level copy would double-count one fault and
  inflate `failed_checks`. Pinned by
  `a_failed_format_check_short_circuits_without_double_counting`.
- **`verify_vp_response`'s `Err` arm reports no credentials because there are
  none.** It is reachable only by transaction-level failures — JWE decryption, a
  missing `vp_token`, trust-store construction, `select_presentations` — all of
  which precede any credential examination. A per-credential failure no longer
  arrives there.
- **`with_credential_context` cannot prefix the three `#[error(transparent)]`
  variants.** `Storage`, `CoreCrypto` and `Trust` wrap a foreign error whose
  `Display` is the whole message, with no string field to prefix. Rewrapping one
  as `Failed` to gain a field would change `error.kind`, which root
  [AGENTS.md](../../AGENTS.md) §4.5 makes operator-facing API, so they are
  returned unchanged — the per-credential roll-up log record names the credential
  in those cases instead.
- **Duplicate credential query ids are rejected at request creation**
  (`create_verification_request`, OpenID4VP L745-746). This is load-bearing,
  not cosmetic: `select_presentations` matches each credential query against
  `vp_token`'s keys, so two queries sharing an id both match the same entry
  and one presentation would be verified twice under contradictory queries.
- **`response_uri` for mdoc device binding is reconstructed**, not stored:
  `{public_base_url}/vp/response/{tx.id}`. Changing the route shape in
  `crates/foundry` silently breaks the device signature check.
- **The mdoc issuer half runs ONCE; only the Device Signature is retried per
  candidate Origin.** `verify_issuer_signed` validates the certificate chain, the
  IssuerAuth signature, MSO validity and the element digests, none of which
  depend on the Origin. Only `verify_device_auth` commits to a
  `SessionTranscript`. Do not collapse this back into one `verify_mdoc` call
  inside the loop: that re-ran full chain validation once per configured Origin
  purely to retry a single signature.
- **The presentation request is logged verbatim at `trace`, gated on
  `obs::sensitive_enabled()`, on BOTH transports.** `build_signed_request_object`
  emits `request_object_jws` / `request_object_header` /
  `request_object_payload` at the point the JWS is served, and the `dc_api`
  branch of `create_verification_request` emits `dc_api_request` *after* the
  conditional `transaction_data` member is inserted — logging it earlier would
  record a prefix of the request rather than the request. Both are doubly gated
  because the object commits to `tx.nonce` and carries the ephemeral **public**
  JWK; a `debug`/`trace` level alone is not authorisation (root
  [AGENTS.md](../../AGENTS.md) §4.5, whose thumbprint-only rule for public keys
  names these fields as its one exception). The always-on companion at `debug`
  carries `alg` and `jws_len` only — no contents. Pinned by
  `the_request_object_served_to_the_wallet_stays_locked_by_default` and
  `payload_logging_unlocks_the_request_object_served_to_the_wallet` (plus the
  DC API pair) in `crates/foundry/tests/logging_redaction.rs`.
- **The candidate `SessionTranscript` is logged at `trace`, gated on
  `obs::sensitive_enabled()`.** It commits to `tx.nonce`, so per root
  `AGENTS.md` §4.5 it requires BOTH the flag and the level — a level alone is not
  authorisation. It exists because a real wallet's Device Signature cannot be
  reproduced offline without the exact transcript bytes, which is what blocked
  capturing an interop fixture.
  **It is emitted before `verify_issuer_signed`, and never from inside the
  candidate loop.** The presentations that most need reproducing offline are the
  ones that *fail* — a test-PKI or expired issuer chain — and those return from
  `verify_issuer_signed` before the loop is entered, so an emission inside the
  loop is suppressed by exactly the verdict it exists to explain. That is not a
  hypothetical: it is why the golden fixture could not be captured from the AV
  wallet. Pinned by
  `the_session_transcript_diagnostic_survives_an_issuer_trust_failure` (positive)
  and `..._stays_locked_by_default` (negative control), both inline in
  `verify.rs`.
