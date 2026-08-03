# Verifier client metadata: selectable encryption JWK + advertised formats

> Migrated from `docs/superpowers/changes/2026-07-30-verifier-encryption-jwk-metadata.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Date:** 2026-07-30
**Type:** bugfix
**Track:** C (investigate) → A (direct)
**Branch:** `superlight/2026-07-30-verifier-encryption-jwk-metadata`
**Spec:** n/a — Track A/C
**Plan:** n/a — Track A/C

## Problem

During verification, the EUDI iOS wallet (`eudi-pal` / BankingPal-Pocket) aborted
with:

```
Invalid DCQL query: .invalidClientMetadata
```

The message is doubly misleading and cost most of the investigation:

- **"Invalid DCQL query"** — `eudi-lib-ios-wallet-kit`
  (`OpenId4VpService.swift:110`) labels *every* failed request resolution as a
  DCQL error, whatever actually failed. The DCQL query was never parsed.
- **`.invalidClientMetadata`** — `AuthorizationRequestResolver.swift:~100`
  catches the real error and **discards** it, substituting this generic case.
  Its `errorDescription` is the literal string `".invalidClientMetadata"`.

The genuine error, never shown to the user, was:

```
No encryption JWKs were advertised by the Verifier in his Client Metadata
```

## Root Cause

**foundry's verifier advertised its ephemeral response-encryption key as a bare
JWK with no `kid`, no `alg` and no `use`. The wallet filters candidate
encryption keys on `kid` and `alg` being present and non-empty, so foundry's
only key was discarded, leaving zero encryption keys — a fatal condition
because `direct_post.jwt` mandates response encryption.**

Chain of events:

1. `crates/foundry-verifier/src/request.rs` emitted
   `client_metadata: { jwks: { keys: [ephem_public_jwk] } }` and nothing else.
2. The JWK came from josekit's `EcKeyPair::to_jwk_public_key()`, whose `to_jwk`
   (`josekit-0.10.3/src/jwk/alg/ec.rs:318`) sets `kid`/`alg` **only if the
   keypair already carries them** — and `EcKeyPair::generate` sets neither.
   Verified empirically: `{"kty":"EC","crv":"P-256","x":…,"y":…}`,
   `has_kid=false has_alg=false has_use=false`.
3. `response_mode` is `direct_post.jwt`, and `ResponseMode.requiresEncryption()`
   returns `true` for `.directPostJWT` (`ResponseMode.swift:117-120`), so the
   encryption branch is not optional.
4. `ClientMetaDataValidator.swift:~70` filters:
   ```swift
   keySet.keys.filter { !(key.kid?.isEmpty ?? true) && !(key.alg?.isEmpty ?? true) }
   ```
   With `kid == nil`, `nil?.isEmpty ?? true` is `true`, so `!true` is `false` —
   the key is dropped and the candidate list is empty.
5. `createResponseEncryptionSpecification` throws; the resolver replaces the
   message with `.invalidClientMetadata`.

**Why the test suite never caught it:** every foundry-side consumer reads the
key positionally and ignores its metadata —
`crates/foundry-wallet/src/actions/verification.rs:108` and all six sites in
`crates/foundry/tests/wallet_verification.rs` use
`["client_metadata"]["jwks"]["keys"][0]`. The Rust debug wallet is lenient
exactly where the iOS wallet is strict, so E2E tests passed against a request
object no EUDI reference wallet would accept.

### Hypotheses rejected

- *Empty `credentials: []` in the deployed `over18` named query* — a real
  second bug (fixed below), but client-metadata validation runs strictly before
  DCQL parsing, so the request died first.
- *Missing `vp_formats_supported`* — `ClientMetaData.init` is lenient (`try?` →
  `nil`) and the validator substitutes an empty set. Not the trigger; addressed
  separately below as spec compliance.
- *Missing `encrypted_response_enc_values_supported`* —
  `responseEncryptionMethodsSupported()` returns `nil` without throwing, and the
  validator falls back to `DEFAULT_RESPONSE_ENCRYPTION_METHODS` (includes
  A128GCM).
- *Malformed jwks* — `extractKeySet` succeeded; the JWK was valid, just
  under-annotated.
- *`client_id_scheme` / x5c trust failure* — would surface as a different
  `ValidationError`, and authentication completed without complaint.

## Approach

Annotate the ephemeral **public** JWK with `kid`, `use: "enc"` and `alg`, and
advertise both `encrypted_response_enc_values_supported` and
`vp_formats_supported`, in **both** client-metadata emitters (the `dc_api`
branch and the signed request object).

`use: "enc"` is not cosmetic: `OpenId4VpService.swift:120` locates the reader
key via `keys.first(where: { $0.use == "enc" })` to derive `eReaderPub` for mdoc
session transcripts.

Rejected alternatives:

- *Annotate the private JWK too, for symmetry* — rejected. josekit's
  `encrypter_from_jwk` propagates `kid` into the JWE header
  (`jwe_context.rs:211-213`), and the kid check at `jwe_context.rs:932` only
  fires when the **decrypter** carries a key id. Leaving the private JWK bare
  means foundry never requires the wallet to echo `kid` back.
- *Hardcode `alg`/`enc`* — rejected in favour of reading
  `verifier.response_encryption`, which until now was parsed and never used
  anywhere in the codebase.
- *Advertise `"mso_mdoc": {}` for brevity* — rejected, and it would have been a
  regression: wallets intersect advertised formats by **exact structural
  equality** (`VpFormatsSupported.common`), so `msoMdoc(nil, nil)` ≠
  `msoMdoc([-7], [-7])` and mdoc would have been silently dropped.

## Changes

- `crates/foundry-verifier/src/request.rs`
  - new `response_encryption_params()` — reads `alg`/`enc` from
    `verifier.response_encryption`, defaulting to `ECDH-ES` / `A128GCM`.
  - new `annotate_encryption_jwk()` — adds `kid` (UUID), `use: "enc"` and `alg`
    to the ephemeral public JWK, with the wallet-side rationale documented so
    the next reader does not "simplify" it away.
  - new `vp_formats_supported()` — OpenID4VP v1.0 shape for the formats foundry
    actually verifies (SD-JWT VC and mdoc, ES256 / COSE -7), with the
    exact-equality hazard documented.
  - both client-metadata emitters now include
    `encrypted_response_enc_values_supported` and `vp_formats_supported`.
- `dl-infra-k8s/foundry/manifest.yml` *(separate repo, config only)*
  - the `over18` named query had `dcql: { credentials: [] }`. An empty
    `credentials` array is hard-rejected by the wallet's DCQL parser —
    `Credentials.ensureValid()`: `guard !isEmpty else { throw
    DCQLError.emptyCredentials }` — so this would have been the next failure.
    Replaced with a real SD-JWT VC query on the `pid` credential.

## Tests

- `crates/foundry-verifier/src/request.rs`
  - `test_dc_api_client_metadata_encryption_jwk_is_wallet_selectable` — `kid`
    non-empty, `alg == "ECDH-ES"`, `use == "enc"`, plus advertised enc methods.
  - `test_signed_request_object_encryption_jwk_is_wallet_selectable` — same
    contract inside the signed request object, and asserts the advertised key is
    still the transaction's ephemeral key material (`x`/`y` match).
  - `test_client_metadata_response_encryption_honours_config` — values come from
    `verifier.response_encryption`, not hardcoded.
  - `test_client_metadata_advertises_vp_formats_supported` — exact format/algorithm
    values on both transports.

Regression safety for the JWE round trip is carried by the pre-existing
`crates/foundry/tests/wallet_verification.rs` (9 tests), which encrypt with the
now-annotated public JWK and decrypt on foundry's side.

Verified: `cargo test --workspace` (416 passed, 0 failed),
`cargo clippy --workspace --all-targets -- -D warnings` (clean),
`cargo fmt --check` (clean).

The deployed `over18` query was additionally verified semantically against
foundry's own matcher via a throwaway test (not committed): it matches a `pid`
presenting `birthdate`, and fails closed when `birthdate` is withheld or the
`vct` differs.

## Review

- **Fixed during review (Minor):** `annotate_encryption_jwk` took its JWK by
  value then rebound it; now takes `mut jwk` directly.
- **Left deliberately — configured `alg` vs. hardcoded decrypt path.**
  `response_encryption_params` reads `verifier.response_encryption.alg`, but
  `verify.rs:49` uses `josekit::jwe::ECDH_ES` unconditionally. Configuring e.g.
  `ECDH-ES+A128KW` would advertise a key foundry cannot then decrypt with. This
  is pre-existing (the config was previously ignored entirely) and the deployed
  manifest uses the defaults, so nothing regressed. Proper fix is startup config
  validation in `foundry-core` — outside this change's scope.
- **Left deliberately — `annotate_encryption_jwk` silently no-ops on a
  non-object JWK.** Unreachable today (`serde_json::to_value` of a josekit `Jwk`
  is always an object) and covered by the new tests if that ever changes; a
  typed error path for an impossible state was judged to be noise.
- **`vp_formats_supported` was not the reported bug.** The iOS lib substitutes
  `VpFormatsSupported.default()` when the verifier advertises an empty set
  (`RequestAuthenticator.createVpToken`), and that default equals what
  `EudiWalletKit` configures, so the intersection was already correct. It is
  implemented for spec compliance and for stricter wallets that do not default;
  for this wallet the behavioural change is nil by construction.

## Follow-ups (not done here)

- Startup validation (or support) for non-`ECDH-ES` `verifier.response_encryption.alg`.
- foundry does not validate `named_queries` DCQL shape at config load
  (`named_queries: Vec<serde_json::Value>`), so `config validate` cannot catch a
  malformed or empty named query. Worth adding.
- foundry's DCQL has no age-predicate/range support, so `over18` necessarily
  discloses `birthdate` and the relying party derives the age.
- Requires a foundry rebuild + redeploy; the JWK fix cannot be applied from the
  ConfigMap.
