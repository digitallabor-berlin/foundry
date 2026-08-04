# Credential Request / Response Encryption (OpenID4VCI Encrypted Messages)

**Date:** 2026-08-04
**Type:** feat
**Branch:** feature/credential-request-response-encryption
**Spec:** docs/superpowers/specs/2026-08-04-credential-request-response-encryption-design.md
**Plan:** docs/superpowers/plans/2026-08-04-credential-request-response-encryption-plan.md

## Why

Roadmap item **C** for Google Wallet compatibility: `POST /credential` could
neither accept an encrypted Credential Request nor produce an encrypted
Credential Response, so foundry could not participate in an OpenID4VCI 1.0
flow whose Credential Issuer Metadata advertises either capability — a
precondition several wallet ecosystems, including Google Wallet, require.
Sixteen OpenID4VCI clauses (VCI-0054…0139, listed below) sat at
`not-implemented` for exactly this reason.

## Approach

Five scope decisions were resolved during brainstorming:

1. **Both directions in scope.** OpenID4VCI §Credential Request L960 requires
   Credential Request encryption whenever `credential_response_encryption` is
   present, so shipping response-only encryption would be knowingly
   non-conformant the moment a wallet used it.
2. **Default-off, opt-in.** `issuer.request_encryption` and
   `issuer.response_encryption` are both `Option<...>`, `None` by default —
   an unconfigured deployment's wire behaviour and
   `.well-known/openid-credential-issuer` document are byte-identical to a
   build without this feature. `encryption_required` on each block defaults to
   `false`.
3. **Keys live in the existing `keys:` map, referenced by name.** Survives
   restarts and multi-replica deployments, reuses the existing key-loading and
   validation machinery, and a multi-entry `keys` list gives zero-downtime
   rotation. `kid` is derived (RFC 7638 JWK thumbprint), not configurable, so
   it is stable and collision-free by construction.
4. **A narrow algorithm surface.** `alg` is always `ECDH-ES` (no RSA JOSE
   anywhere in the workspace); `enc` is `A128GCM` or `A256GCM`; `zip`
   (compression) is never advertised or accepted — omitting
   `zip_values_supported` is conformance by L856/L1379, not a gap.
5. **All three test layers.** Unit tests, in-process HTTP/conformance tests,
   one `#[ignore]`d real-subprocess E2E case, and a behavioural logging-
   redaction test — a decrypt path handling never-loggable data needs the
   last of these, not only a code review.

**Deliberate deviation, stricter than the specification:** `check_encryption_policy`
rejects a `credential_response_encryption` request when `issuer.response_encryption`
is unconfigured, rather than silently answering in plaintext. The specification
does not require this; refusing outright rather than surprising the wallet with
an unencrypted response to what it believed was an encrypted request is the
safer failure mode.

## What Changed

**`foundry-core` (`crypto/jwe.rs`, `config/`):**

- `DecryptionKey` (`from_pem`/`from_pem_file`, `kid()`, `published_jwk()`) and
  `decrypt_compact(jwe, keys, allowed_enc) -> Result<Value, CryptoError>` — the
  Credential Request decrypt path. Pre-decryption checks: `alg` must be
  `ECDH-ES`, `enc` must be in the caller's allow-list, and a `kid` must be
  present and match a loaded key.
- `encrypt_compact` is unchanged (no `kid`, preserving OpenID4VP's exact wire
  shape); the new `encrypt_compact_with_kid(payload, jwk, alg, enc, kid: Option<&str>)`
  is the `kid`-echoing sibling the Credential Response needs (L1188).
- `kid` derivation uses `obs::thumbprint_bytes` (fail-closed) rather than
  `obs::thumbprint` (which degrades to a placeholder string on error and exists
  only for logging).
- `RequestEncryptionConfig`, `ResponseEncryptionConfig`,
  `SUPPORTED_ENC_VALUES = ["A128GCM", "A256GCM"]` on `IssuerConfig`.
  `Config::validate()` gained four rules: `request_encryption.keys` must be
  non-empty and every name must resolve; an encryption key must not also be
  `verifier.signing_key` or `issuer.status_list.signing_key`;
  `response_encryption.encryption_required: true` requires
  `request_encryption` to be present; both blocks' `enc_values_supported` must
  be non-empty and a subset of `SUPPORTED_ENC_VALUES`.
- `Config::load_request_decryption_keys(base_dir) -> Result<Vec<DecryptionKey>, ConfigError>`.

**`foundry-issuer` (`metadata.rs`, `credential.rs`):**

- `CredentialRequestEncryption { jwks, enc_values_supported, encryption_required }`
  and `CredentialResponseEncryption { alg_values_supported, enc_values_supported, encryption_required }`,
  both `Option` fields on `CredentialIssuerMetadata`, omitted entirely when
  unconfigured. `build_issuer_metadata` gained a
  `request_decryption_keys: &[DecryptionKey]` parameter.
- `CredentialResponseEncryptionParams` (`jwk`, `enc`, `zip`) and
  `CredentialRequest.credential_response_encryption: Option<...>`.
- `check_encryption_policy(cfg, req, request_was_encrypted) -> Result<(), IssuanceError>`
  — the single gate for L960 (response encryption requires an encrypted
  request), L969/the deliberate deviation above, L1192 (reject unencrypted
  when required), and L1188/L855/L856 (the wallet's response JWK must carry
  `alg`, its `enc` must be advertised, `zip` must be absent).
  `handle_credential_request` gained a trailing `request_was_encrypted: bool`
  parameter and calls this gate first, before any other request handling.

**`crates/foundry` (`extract.rs`, `server.rs`, `commands.rs`, `main.rs`):**

- New `extract.rs`: `MaybeEncrypted<T>` — a `FromRequest<AppState>` extractor
  accepting `application/json` or `application/jwt`, decrypting the latter via
  `decrypt_compact` and setting `was_encrypted`; `MaybeEncryptedRejection`
  (415 for an unsupported media type or an unconfigured/keyless issuer, or the
  engine's own `IssuanceError` delegated through `wallet_error_response`); and
  `CredentialResponseBody` (`Json` | `Jwt`, the latter setting
  `Content-Type: application/jwt` on the raw compact JWE).
- `AppState` gained `request_decryption_keys: Arc<Vec<DecryptionKey>>` and a
  `with_request_decryption_keys` builder. `credential_handler` now takes
  `MaybeEncrypted<CredentialRequest>` and returns
  `(HeaderMap, CredentialResponseBody)`; when the wallet requested response
  encryption it encrypts via `encrypt_compact_with_kid` after
  `handle_credential_request` returns.
- `server::serve` gained a second parameter,
  `request_decryption_keys: Vec<DecryptionKey>`; `main.rs`'s `Command::Serve`
  arm loads it via `Config::load_request_decryption_keys` before calling
  `serve`.
- `commands::quickstart` now also generates `keys/issuer_request_enc.pem` (an
  ECDH-ES key, no `x5c`) and the generated `config.yaml` ships both encryption
  blocks **commented out**, so enabling them later needs no separate
  key-generation step.

**Two signature changes an external caller of these crates would notice:**
`build_issuer_metadata(&Config)` → `build_issuer_metadata(&Config, &[DecryptionKey])`,
and `handle_credential_request(..., now_unix)` →
`handle_credential_request(..., now_unix, request_was_encrypted: bool)`.

**Documentation:** `docs/conformance/openid4vc-conformance.md` — sixteen rows
(VCI-0054, 0055, 0056, 0063, 0066, 0097–0101, 0134–0139) flipped from
`not-implemented` to `conforming`; the OpenID4VCI summary row updated
(78→94 conforming, 76→60 not-implemented, total unchanged at 232). VCI-0084 and
each `not-implemented` row in VCI-0085…0096 (excluding the `out-of-scope`
wallet-obligation rows 0088/0089/0094, left unchanged) had their Evidence
amended to name the actual blocker explicitly: the absent Deferred Credential
Endpoint, not encryption. `README.md` gained a "Credential Request / Response
Encryption" configuration section and three additions to the never-logged
list. Root `AGENTS.md` §4.5, `crates/foundry-core/AGENTS.md`,
`crates/foundry-issuer/AGENTS.md`, `crates/foundry/AGENTS.md`, and
`crates/foundry/tests/AGENTS.md` all updated (module maps, entry-point
signatures, new Gotchas). `openapi-wallet.json` regenerated (new schemas;
`openapi.json` unaffected — the admin API surface did not change).

## What Is Knowingly Not Implemented

- **The Deferred Credential Endpoint does not exist in foundry at all**
  (VCI-0084, VCI-0088–0096 stay `not-implemented`/`out-of-scope` as
  applicable) — unrelated prior-existing scope, now explicitly documented as
  *not* blocked by this change.
- **RSA JOSE** — the workspace carries no RSA JOSE algorithm anywhere;
  `alg` is `ECDH-ES` only, by design (decision 4 above).
- **Compression (`zip`)** — never advertised or accepted, by design.

## Testing

Scoped gate run after every task (`cargo test -p foundry-core`,
`-p foundry-issuer -p foundry` as each crate was touched; `cargo clippy ...
-D warnings`; `cargo fmt --check`), per root `AGENTS.md` §5.1 — never
`--workspace` between tasks. New coverage:

- `foundry-core::crypto::jwe`: 12 new unit tests (`kid` derivation, round-trip,
  multi-key selection, missing/unknown `kid`, unsupported `enc`, tampered
  ciphertext, non-compact input, no-keys-configured, and a regression guard
  proving the 4-arg `encrypt_compact` never gains a `kid`).
- `foundry-core::config::validate`: 9 new tests (key resolution, non-empty
  checks, signing-key-reuse rejection on both paths, required-response-needs-
  request, `enc` value validation, key loading with distinct `kid`s,
  empty-when-off, YAML default fixture).
- `foundry-issuer::metadata`: 3 new tests (both objects omitted when
  unconfigured, the published JWKS carries annotated `kid`s, response
  encryption always advertises `ECDH-ES` only).
- `foundry-issuer::credential`: 8 new tests covering every branch of
  `check_encryption_policy`.
- `crates/foundry/tests/conformance_http.rs`: 9 new rows — unsupported media
  type with encryption enabled, a non-`ECDH-ES` `alg`, a missing `kid`, an
  unadvertised `enc` on either side, response encryption over a plaintext
  request, an absent `alg`/present `zip` on the wallet's response JWK, and
  `encryption_required` rejecting a plaintext request.
- New `crates/foundry/tests/credential_encryption.rs` (with its own
  `support/mod.rs` fixture module): a full encrypted round trip over the real
  routers, a plaintext request still getting a plaintext response with
  encryption enabled, and `application/jwt` being 415 when the feature is off.
- `crates/foundry/tests/quickstart.rs`: the generated key exists and the
  emitted config still parses/validates with both blocks commented out.
- `crates/foundry/tests/wallet_metadata.rs`: both encryption objects are
  absent from metadata when unconfigured.
- `crates/foundry/tests/logging_redaction.rs`: two new behavioural tests
  proving an encrypted issuance never logs the wallet's ephemeral
  response-encryption JWK or the decrypted credential — including with
  `sensitive_payloads` enabled, since key material is never unlocked by that
  flag.
- `crates/foundry/tests/e2e_full_flow.rs`: one new `#[ignore]`d case booting
  the real binary with both encryption blocks uncommented (a string
  substitution on the `quickstart`-emitted file, proving the shipped commented
  block is syntactically correct once enabled) and driving an encrypted
  `/credential` round trip using the `kid` the server actually loaded from
  disk — the one layer that exercises `quickstart`'s generated key,
  `Config::load_request_decryption_keys`, and startup validation together.

Full gate (root `AGENTS.md` §5.3), run once at the end of the branch: `cargo
fmt` (apply) → `cargo fmt --check` → `cargo test --workspace` → `cargo test -p
foundry --test e2e_full_flow -- --ignored` → `cargo clippy --workspace
--all-targets -- -D warnings` — captured to disk and grepped per §5.6.

## Follow-ups / Known Limitations

- **A structurally-valid-but-unusable wallet response JWK burns the offer.**
  `check_encryption_policy` validates that `credential_response_encryption.jwk`
  *has* an `alg` member (L1188) but does not verify the JWK is a usable EC
  public key. Response encryption then happens in `credential_handler`
  **after** `handle_credential_request` has already marked the transaction
  `Issued` (credential.rs), so a wallet sending e.g. `kty: RSA`, an unknown
  `crv`, or a JWK missing `x`/`y` passes the gate, consumes its single-use
  offer, and receives a 500 `server_error` from
  `encrypt_compact_with_kid` → `IssuanceError::Crypto` → `wallet_error_response`'s
  catch-all arm. The credential is then unrecoverable.

  Not a security defect — the failure is fail-closed (nothing is disclosed in
  plaintext) and only a wallet's own offer is affected, so there is no
  cross-tenant impact. But it is both a robustness wart and a status
  misclassification: an unusable client-supplied JWK is a client error (400
  `invalid_credential_request`), not a server fault. The fix is to move the
  usability check into `check_encryption_policy` — attempt to build the
  encrypter, or at minimum require `kty: "EC"` with `crv`/`x`/`y` present —
  so it runs *before* any transaction state mutation. Deferred rather than
  patched at the end of this branch because it needs its own test to be worth
  having.
- One pre-existing, confirmed-unrelated intermittent failure in a
  `foundry-verifier` trust-chain-validity-window test was observed during this
  branch's scoped gates; reproduced independently against the unmodified
  baseline via `git stash`, so it predates this change and is not tracked
  here.
- Roadmap items **D** and **E** for Google Wallet compatibility remain.