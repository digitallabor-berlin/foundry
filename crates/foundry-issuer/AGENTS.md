# AGENTS.md — `crates/foundry-issuer`

## Purpose

The **OpenID4VCI issuance engine**: credential offers with pre-authorized codes,
token exchange, `c_nonce` minting, holder-proof verification, and credential
issuance (SD-JWT VC and mdoc), plus issuer/authorization-server metadata
construction and status-list index allocation.

**Not** in scope here: HTTP routing and Axum wiring (that is `crates/foundry`),
credential format encoding/signing (`foundry-sd-jwt-vc`, `foundry-mdoc`),
OpenID4VP verification (`foundry-verifier`), and storage/crypto/config
primitives (`foundry-core`).

## Position in the Dependency Graph

- **Depends on:** `foundry-core`, `foundry-sd-jwt-vc`, `foundry-mdoc`.
- **Consumed by:** `crates/foundry` (HTTP handlers).
- **Must never depend on:** `foundry-verifier` or `crates/foundry`.

Full layering rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
|---|---|
| `lib.rs` | Module declarations and the `pub use` surface (see below) |
| `offer.rs` | Offer **primitives**: `CredentialOffer` and its grant structs, `generate_pre_authorized_code()`, `generate_tx_code()`, `build_offer_uri()`, `build_dc_api_offer()` |
| `create_offer.rs` | Offer **orchestration**: takes a `CreateOfferRequest`, allocates a status index, persists an `IssuanceTransaction`, returns the offer + URI |
| `token.rs` | `POST /token` logic (pre-authorized-code and authorization-code grants → access token) |
| `challenge.rs` | The domain-separated MAC primitive shared by `nonce.rs`, `attestation.rs`, and `dpop.rs`: `NonceSecret` (moved here from `nonce.rs`), `Domain` (`CNonce` \| `AttestationChallenge` \| `DpopNonce`), `mint`/`verify`. Also the ABCA §8 challenge endpoint's own logic: `ChallengeResponse`, `issue_attestation_challenge`, and RFC 9449's `mint_dpop_nonce` |
| `dpop.rs` | RFC 9449 DPoP: proof JWT validation (§4.3 checks 2-9, 11-12, plus check 10 — the server-provided `nonce`, gated on `issuer.dpop.nonce_mode` and implemented via `challenge.rs`'s `Domain::DpopNonce`), `htu` normalisation, RFC 7638 `jkt` computation, and `jti` replay claiming (§11.1) under KV namespace `dpop_jti` |
| `nonce.rs` | `POST /nonce` logic: stateless MAC-authenticated `c_nonce` minting (`issue_nonce`) and verification (`verify_nonce`), plus `NonceResponse`. Delegates its MAC work to `challenge.rs`, which is also where `NonceSecret` now lives (re-exported here for source compatibility) |
| `transaction.rs` | `IssuanceTransaction` model, `IssuanceState`, and `Storage`-backed load/save (namespace `issuance_tx`, TTL-based), including lookup by pre-auth code and by access token |
| `credential.rs` | `POST /credential` logic: `check_encryption_policy` gate, access-token lookup, single-use state check, proof verification, then delegation to `build_sd_jwt_vc` / `build_mdoc`. Also defines `CredentialResponseEncryptionParams` (the wallet's `credential_response_encryption` request field) |
| `proof.rs` | Holder proof-of-possession JWT verification (`typ`, embedded `jwk` or `kid`+`key_attestation`, `aud`, `nonce`) |
| `attestation.rs` | `WalletAttestationVerifier` / `KeyAttestationVerifier` traits + `DefaultAttestationVerifier`, gated by `foundry_core::config::Mode`. Also verifies the Client Attestation PoP JWT (`draft-ietf-oauth-attestation-based-client-auth` §5.2, GAP-VCI-14) via `validate_client_attestation_pop_jwt` — including, since 2026-08-04, ABCA §9 rule 8's `challenge` claim (check 10), gated on `issuer.wallet_attestation.challenge_mode` and implemented via `challenge.rs`'s `Domain::AttestationChallenge` — and owns anti-replay claiming of the PoP's `jti` via `claim_pop_jti` under KV namespace `client_attestation_pop_jti` |
| `metadata.rs` | Builds `CredentialIssuerMetadata` and `AuthorizationServerMetadata` from `Config`; `build_issuer_metadata` also takes the loaded request-decryption keys and populates `credential_request_encryption`/`credential_response_encryption` (both `Option`, omitted entirely when their config block is absent) |
| `keystore_proof.rs` | Google Wallet `android_keystore_attestation` proof type: chain validation, `attestationChallenge` ↔ `c_nonce` binding, security-level policy, holder-key derivation |
| `status_index.rs` | CSPRNG + check-and-set allocation of a status-list index |
| `error.rs` | The `IssuanceError` enum (no HTTP mapping here — that lives in `crates/foundry`) |

## Key Public Types & Entry Points

Entry point → the endpoint that drives it (routes defined in
`crates/foundry/src/server.rs`):

| Entry point | Endpoint | Listener |
|---|---|---|
| `create_offer(CreateOfferRequest) -> CreateOfferResponse` | `POST /admin/issuance/offers` | admin (API-key protected) |
| `handle_token_request(storage, &TokenRequest, &AttestationMode, attestation_header, pop_header, &DpopConfig, &DpopPresentation, &NonceSecret, issuer_identifier, now_unix) -> TokenResponse` | `POST /token` | wallet-facing |
| `issue_nonce(&NonceSecret, now) -> NonceResponse` | `POST /nonce` | wallet-facing, **unauthenticated** |
| `issue_attestation_challenge(&NonceSecret, ttl_secs, now_unix) -> ChallengeResponse` | `POST /challenge` | wallet-facing, **unauthenticated**, registered only when `challenge_mode != Disabled` |
| `handle_credential_request(&Config, storage, access_token, &CredentialRequest, &NonceSecret, &DpopPresentation, now_unix, request_was_encrypted: bool) -> CredentialResponse` | `POST /credential` | wallet-facing |
| `build_issuer_metadata(&Config, request_decryption_keys: &[foundry_core::crypto::jwe::DecryptionKey]) -> CredentialIssuerMetadata` | `GET /.well-known/openid-credential-issuer` | wallet-facing |
| `build_authorization_server_metadata(&Config) -> AuthorizationServerMetadata` | `GET /.well-known/oauth-authorization-server` | wallet-facing |

Other public surface:

- **Offer:** `CredentialOffer`, `CredentialOfferGrants`, `PreAuthorizedCodeGrant`,
  `TxCodeDefinition`, `build_offer_uri`, `build_dc_api_offer`,
  `generate_pre_authorized_code`, `generate_tx_code`.
- **Transaction:** `IssuanceTransaction`, `IssuanceState` (`Offered` | `Issued`),
  `save_transaction`, `save_transaction_with_indices`, `load_transaction`,
  `load_transaction_by_pre_auth_code`, `load_transaction_by_access_token`.
- **Proof:** `verify_holder_proof`, `ProofObject`, `VerifiedProof`.
- **Metadata:** `CredentialConfigurationSupported`, `ProofTypeSupported`,
  `CredentialRequestEncryption`, `CredentialResponseEncryption`.
- **Encryption policy:** `check_encryption_policy(&Config, &CredentialRequest,
  request_was_encrypted: bool) -> Result<(), IssuanceError>`,
  `CredentialResponseEncryptionParams`.
- **Status:** `allocate_status_index(&dyn Storage, credential_type_id, list_size) -> Result<u64, IssuanceError>`.
- **DPoP (RFC 9449):** `verify_dpop_proof`, `VerifiedDpopProof`, `DpopPresentation`,
  `DpopNoncePolicy`, `access_token_hash`.
- **Challenge (`challenge.rs`):** `NonceSecret`, `ChallengeResponse`,
  `issue_attestation_challenge`, `mint_dpop_nonce`.
- **Errors:** `IssuanceError` — `InvalidRequest`, `InvalidGrant`, `InvalidProof`,
  `UnknownCredentialType`, `ClaimValidation`, `StatusListExhausted`,
  `InvalidDpopProof`, `UseAttestationChallenge`, `UseDpopNonce`, plus transparent
  wraps of `StorageError` / `CryptoError` / `TrustError`, and `Serialization` /
  `Deserialization`.

## Binding Invariants

- **Every `#[tracing::instrument]` in this crate MUST carry `skip_all`.** These
  functions take the bearer `access_token`, holder proof JWTs, the `c_nonce` MAC
  secret and the whole `Config` as arguments, so the default would `Debug`-format
  all of it into the span. Fields are opt-in, always. Enforced by
  `crates/foundry/tests/instrumentation_hygiene.rs`.
- **Never log a credential-issuance secret.** Not the pre-authorized code, the
  authorization code, the transaction code, the access token, a `c_nonce` value,
  the nonce secret, or a holder proof JWT. Log the *shape* of the exchange
  (grant type, configuration id, format, outcome) and public keys only as RFC 7638
  thumbprints. Redaction tiers: see the "Logging & Observability" section of the
  root [README.md](../../README.md); enforced by
  `crates/foundry/tests/logging_redaction.rs`.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** anywhere
  outside `#[cfg(test)]` — this crate is named explicitly in the rule; always
  return `IssuanceError` — full rule: root [AGENTS.md](../../AGENTS.md) §4.1.
- **Error → HTTP status classification lives in `crates/foundry`, not here.**
  Return the semantically correct `IssuanceError` variant and let the handler
  map it; do not smuggle status codes into error strings — full rule: root
  [AGENTS.md](../../AGENTS.md) §4.3.
- **Endpoint shape changes must be mirrored in `openapi.json`.** Request/response
  structs here carry `utoipa::ToSchema`; changing a field changes the spec —
  full rule: root [AGENTS.md](../../AGENTS.md) §6.
- **No upward or sideways dependencies** (never `foundry-verifier` or
  `crates/foundry`) — full rule: root [AGENTS.md](../../AGENTS.md) §3.
- **Gates are scoped by default:** per task, run `cargo test -p foundry-issuer
  -p foundry` (the integration suite lives in `crates/foundry/tests`), plus
  `cargo clippy -p foundry-issuer --all-targets -- -D warnings` and
  `cargo fmt --check`. Save `cargo test --workspace` for the end of a
  development cycle or when unsure of the blast radius — **not** between tasks.
  Full rule: root [AGENTS.md](../../AGENTS.md) §5.

## Tests

This crate has **no `tests/` directory**.

- **Unit coverage:** inline `#[cfg(test)]` modules in every module —
  `attestation.rs`, `challenge.rs`, `create_offer.rs`, `credential.rs`,
  `dpop.rs`, `error.rs`, `metadata.rs`, `nonce.rs`, `offer.rs`, `proof.rs`,
  `status_index.rs`, `token.rs`, `transaction.rs`.
- **Flow coverage** lives in `crates/foundry/tests/` — see
  [`../foundry/tests/AGENTS.md`](../foundry/tests/AGENTS.md). Most relevant:
  `issuer_offers.rs` (offer creation via the admin API), `wallet_issuance.rs`
  (token → credential), `e2e_full_flow.rs` (issue → verify → revoke →
  re-verify), `wallet_metadata.rs` (metadata endpoints).

```bash
cargo test -p foundry-issuer                      # fast unit loop
cargo test -p foundry --test wallet_issuance      # issuance flow
```

## Gotchas

- **`build_dc_api_offer` is the one place in this crate implemented against
  vendor documentation rather than `docs/specs/`.** The `openid4vci-v1`
  protocol identifier is a Chrome origin-trial identifier with no pinned
  specification; the payload shape follows
  <https://developer.chrome.com/blog/digital-credentials-api-143-issuance-ot>.
  A documented deviation from root AGENTS.md §4.4 — see
  `docs/superpowers/specs/2026-08-04-admin-console-dc-api-issuance-design.md`.
  It narrows `credential_configurations_supported` to the offered ids, so it is
  deliberately *not* byte-identical to `GET /.well-known/openid-credential-issuer`.
  Its output embeds the `pre-authorized_code`: never log it.
- **Offers are single-use, enforced by transaction state.**
  `handle_credential_request` rejects anything whose `IssuanceState` is not
  `Offered` with `InvalidGrant("credential offer has already been claimed")`.
  A retry after a successful issuance is a failure, not an idempotent replay.
- **Status-index allocation is not atomic — there is a known `TODO(concurrency)`
  in `status_index.rs`.** It does a CSPRNG draw plus a get-then-put check-and-set
  against the `status_index_used` namespace, so concurrent allocators can race
  on the same index. Do not assume uniqueness under real concurrency, and do not
  "fix" it locally without adding a compare-and-swap primitive to
  `foundry_core::storage::Storage`.
- **Allocated status indices are never released** — the "used" marker is written
  with no TTL. Exhaustion after `MAX_ATTEMPTS` draws yields
  `StatusListExhausted`, so a small configured `list_size` will start failing
  long before the list is genuinely full.
- **`DefaultAttestationVerifier::verify_wallet_attestation` fully verifies the
  Wallet Attestation JWT** (signature, `x5c` chain against `trusted_anchors`,
  `exp`/`nbf`, `cnf.jwk`/`sub` presence) **and, since GAP-VCI-14's closure, the
  accompanying Client Attestation PoP JWT** (ABCA draft -07 §5.2 — 9 checks,
  `validate_client_attestation_pop_jwt`), returning `Result<Option<PopClaims>,
  IssuanceError>`. Under both `Mode::Required` and `Mode::Optional`, a present
  attestation without a PoP is rejected (ABCA §6.2 rule 2) — see the 9-row mode
  matrix in `attestation.rs`'s own tests.
- **Four similarly-named attestation things in this crate; three are live.** Do
  not reason about one and change another:
  - `WalletAttestationVerifier::verify_wallet_attestation` — **live**, called by
    `handle_token_request`. Full crypto + PoP verification, as above.
  - `verify_key_attestation_jwt` (free function, `attestation.rs`) — **live**,
    called from `proof.rs` for OpenID4VCI Appendix D credential-key
    attestation. Genuinely verifies the key attestation JWT. Unrelated to OAuth
    client authentication.
  - `keystore_proof::verify_android_keystore_proofs` — **live**, called from
    `credential.rs`'s `ResolvedProofs::AndroidKeystoreAttestation` arm. This is
    Google Wallet's `android_keystore_attestation` proof type: an array of
    X.509 certificate chains carrying an Android Keystore hardware attestation.
    It is **not** OpenID4VCI Appendix D key attestation and shares no wire
    format with `verify_key_attestation_jwt` — there is no JWT anywhere in this
    path.
  - `KeyAttestationVerifier::verify_key_attestation` (trait method) — **dead**:
    no caller anywhere in the workspace. Still only checks presence and still
    returns `InvalidRequest` rather than `InvalidClient`. Deliberately left
    untouched by GAP-VCI-14; do not cite it as evidence of what key attestation
    does, and do not "fix" its error type without first giving it a caller.
- **`verify_android_keystore_proofs`'s `validate_chain` failures MUST be
  wrapped into `InvalidProof`, never propagated as `IssuanceError::Trust`.**
  `Trust` has no HTTP mapping in `wallet_error_response` and falls through to
  a 500 — an untrusted or malformed Android attestation chain is a client
  fault (root AGENTS.md §4.3), not a server error. Covered by
  `an_unanchored_chain_is_invalid_proof_not_trust`.
- **`issuer.key_attestation.android.mode: Required` rejects the `jwt` proof
  type entirely**, checked in `credential.rs`'s `ResolvedProofs::Jwt` arm. The
  parent `key_attestation.mode` continues to govern only the `jwt` path's own
  Appendix D key-attestation-JWT support (`verify_key_attestation_jwt`); the
  two `mode` fields are independent knobs over independent proof types that
  happen to share one `trusted_anchors` list.
- **`android_keystore_attestation` has no audience binding and no proof of
  possession of the attested key.** There is no `aud`-equivalent field in the
  `KeyDescription` extension, and the wallet is never asked to sign anything
  with the attested key — the hardware attestation statement substitutes for a
  PoP entirely, the same posture OpenID4VCI's own `attestation` proof type
  documents (L2612). The `c_nonce`-as-`attestationChallenge` check is
  therefore never optional: it is the only replay/binding control this proof
  type has. See VCI-0057 in the conformance report for the full accounting.
- **`claim_pop_jti` is the sole anti-replay mechanism for the PoP's `jti`.** It
  is keyed on a hash of `(iss, jti)`, not bare `jti` — a bare-`jti` namespace
  would let one wallet pre-claim `jti` values and deny service to another.
  `handle_token_request` calls it strictly before any grant work, so a replayed
  PoP can never burn a legitimate holder's `pre-authorized_code`.
- **Only the pre-authorized-code grant is supported.** `handle_token_request`
  rejects any `grant_type` other than
  `urn:ietf:params:oauth:grant-type:pre-authorized_code` with
  `InvalidGrant("unsupported_grant_type")`.
- **`c_nonce` is stateless and NOT transaction-scoped.** The Nonce Endpoint is
  unauthenticated (OpenID4VCI Section 7.1: "not a protected resource"), so the
  issuer has no transaction context when minting and nothing is persisted.
  `verify_nonce` validates an HMAC-SHA256 tag and an embedded expiry instead of
  comparing against stored state. Never reintroduce a bearer-token requirement
  on `/nonce`: conformant wallets send none, get no challenge, and their proof
  JWT then carries no `nonce` claim at all.
- **Nonce replay is bounded by the transaction, not the nonce.**
  `handle_credential_request` rejects any transaction whose state is not
  `Offered`, so an access token is redeemable once however often its nonce is
  reused. Do not assume `verify_nonce` provides single-use semantics.
- **`NonceSecret` is per-process.** Nonces do not survive a restart; that is
  deliberate (no key management, no persisted secret) and safe because the
  `/nonce` → `/credential` window is milliseconds.
- **The `pre-authorized_code` field is serde-renamed** (hyphen, not underscore)
  in `TokenRequest`. Renaming the Rust field without preserving `#[serde(rename)]`
  silently breaks wallet compatibility.
- **`IssuanceError::InvalidNonce` vs `InvalidProof` splits by cause, not by call
  site** (OpenID4VCI L1049 clause 3 vs L1050; GAP-VCI-04). All four
  `verify_nonce` (nonce.rs) failure modes -- malformed, forged, or expired -- are
  `InvalidNonce`: the `c_nonce` is *present but invalid*. A *missing* `nonce`
  claim stays `InvalidProof`, at both call sites that check for it (`proof.rs`'s
  outer proof payload and `attestation.rs`'s Key Attestation JWT payload). Don't
  reason from "nonce-related" to "must be InvalidNonce" — check whether the
  claim was absent or merely invalid.
- **`attestation.rs` deliberately propagates `InvalidNonce` from the Key
  Attestation JWT's own nonce check**, keeping a `key_attestation:` message
  prefix rather than collapsing it back to `InvalidProof`. The wallet's
  recovery ("fetch a fresh `c_nonce` and retry") is identical regardless of
  which nested JWT carried the invalid nonce.
- **`handle_credential_request` validates `credential_configuration_id`
  against `tx.credential_type_id` before proof verification** (GAP-VCI-02,
  OpenID4VCI L851): absent, or naming a *configured* Credential Type the
  Access Token was not issued for, is `InvalidCredentialRequest`; naming a
  Credential Type this issuer does not have configured at all is
  `UnknownCredentialConfiguration` -- a Wallet needs to tell "fix your
  request" apart from "re-read metadata". `req.format` is deliberately never
  read: it is not a Credential Request parameter in OpenID4VCI 1.0 §7.2, and
  every existing caller sends it regardless.
- **`handle_authorize_request` takes an explicit `issuer_identifier: &str`
  parameter** (inserted after `params`), and both `AuthorizeOutcome::Success`
  and `AuthorizeOutcome::ErrorRedirect` carry the resulting `iss` field --
  RFC 9207 §2 requires `iss` "including error responses", not only success
  (GAP-HAIP-02). `AuthorizeOutcome::DirectError` deliberately does not: it
  renders as a JSON error body, not a redirect, so RFC 9207 §2 never reaches
  it. `AuthorizationServerMetadata.authorization_response_iss_parameter_supported`
  is hardcoded `true` per RFC 9207 §2.3.
- **`issuer.dpop.mode: Disabled` ignores the `DPoP` header; it does not reject
  it.** RFC 9449 §10.1 encourages clients that attach `DPoP` to every AS call,
  and §5 provides `token_type: Bearer` precisely to signal non-binding.
  Rejecting would hard-fail a conformant wallet.
- **`IssuanceTransaction.dpop_jkt` is written at two stages and means the same
  thing at both** — "the key this flow is pinned to". `/authorize` writes the
  §10 request parameter; `/token` overwrites it with the verified proof's
  thumbprint (having first proved them equal). Not two overloaded uses of one
  field.
- **`/credential` never consults `issuer.dpop.mode`.** The binding is a
  property of the already-issued token, so flipping config to `Disabled` must
  not retroactively let bound tokens be presented as Bearer. `tx.dpop_jkt` is
  the only authority.
- **An unbound token presented with the `DPoP` scheme is rejected — a
  deliberate deviation.** RFC 9449 leaves the case undefined; accepting it
  would let a wallet believe it has sender-constraining when the token has no
  bound key. Fail-closed, approved in the design doc's §5.3.
- **One of §4.3's checks is not in `dpop.rs` and that is correct.** Check 1
  (single `DPoP` header) needs the header map and lives in `server.rs`'s
  `exactly_one_header`. Check 10 (`nonce`) **is** implemented, as of
  2026-08-04, gated on `issuer.dpop.nonce_mode` — it is only vacuous under the
  default `Disabled`, where no nonce is ever supplied and §11.3 is satisfied
  by construction; under `Optional`/`Required` it actively verifies the claim
  via `challenge::verify(Domain::DpopNonce, ...)`.
- **`check_encryption_policy` (credential.rs) is the single gate for all three
  Credential Request/Response encryption rules** — OpenID4VCI L960 (a
  `credential_response_encryption` request must itself have arrived
  encrypted), L969/§5.3's stricter-than-spec check (response encryption may
  not be requested when `issuer.response_encryption` is unconfigured), and
  L1192 (reject an unencrypted request when `encryption_required` is `true`).
  It also enforces L1188's per-field checks on the wallet's
  `credential_response_encryption.jwk`/`enc`/`zip`. Do not duplicate any of
  these checks at a second call site; `handle_credential_request` calls it
  exactly once, at the top, before any other request handling, driven by the
  `request_was_encrypted` flag its caller (`crates/foundry`'s `MaybeEncrypted`
  extractor) supplies — that flag cannot be spoofed by the request body
  itself, only by the transport the wallet actually used.
- **Every issuer-minted opaque freshness value shares one MAC secret, split
  only by `challenge::Domain`.** `c_nonce` (`Domain::CNonce`), the ABCA
  challenge (`Domain::AttestationChallenge`), and the DPoP nonce
  (`Domain::DpopNonce`) are minted and verified by the same `mint`/`verify`
  pair in `challenge.rs`, keyed off one `NonceSecret`. **Any new kind of
  issuer-minted opaque value MUST add its own `Domain` variant** rather than
  reusing an existing one — the domain label is mixed into the MAC input
  specifically so a value minted for one purpose can never verify as another,
  and reusing a variant silently defeats that guarantee. See `challenge.rs`'s
  own cross-domain-rejection tests for the property this protects.