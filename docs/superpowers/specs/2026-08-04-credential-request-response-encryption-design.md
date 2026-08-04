# Credential Request and Response Encryption

**Date:** 2026-08-04
**Status:** approved
**Roadmap item:** Google Wallet compatibility, item **C**
**Specs:** OpenID4VCI 1.0 §Credential Request (L848, L853–856, L871–875), §Credential
Response (L960, L969), §Encrypted Credential Requests and Responses (L1183–L1192),
§Credential Issuer Metadata (L1373–L1381) · RFC 7516 (JWE) · RFC 7518 (JWA) ·
RFC 7638 (JWK Thumbprint)

---

## 1. Problem

foundry's Credential Endpoint speaks plaintext JSON in both directions. OpenID4VCI
defines an optional layer of JWE encryption on top of TLS for the Credential
Endpoint, and Google Wallet's OpenID4VCI implementation requires it. Sixteen
clauses in
[`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md)
sit at `not-implemented` for this single reason: VCI-0054, 0055, 0056, 0063, 0066,
0097–0101, and 0134–0139.

The two directions are **not independent**. §L960 states:

> Credential Request encryption MUST be used if the `credential_response_encryption`
> parameter is included, to prevent it being substituted by an attacker.

So an issuer that encrypts responses but cannot decrypt requests can only ever serve
a client that is violating the specification. Implementing response encryption alone
would ship a knowingly non-conformant endpoint whose stated purpose is a security
property (§L960's substitution guard) that it does not provide. Both directions are
therefore in scope, together.

## 2. Scope

**In scope.** Credential Request decryption and Credential Response encryption at
`POST /credential`; the `credential_request_encryption` and
`credential_response_encryption` Credential Issuer Metadata objects; the §L1183–1192
Encrypted Messages rules (JWT encoding, `application/jwt` media type, `alg`/`kid`
selection); configuration, key management, and startup validation for the issuer's
long-lived request-decryption keys.

**Out of scope.**

- **The Deferred Credential Endpoint** (§L1081–1112). foundry has no such endpoint at
  all — VCI-0084 and the VCI-0088…0096 family are `not-implemented` for that reason,
  not because of encryption. They stay as they are; the conformance report says so
  explicitly rather than leaving a reader to infer it.
- **Compression (`zip`).** §L856 and §L1379 make compression opt-in, and absence
  means "MUST NOT be used", so omitting it is conformance by design. See §5.3.
- **Key-wrapping algorithms** (`ECDH-ES+A128KW`, `ECDH-ES+A256KW`) and **RSA**
  key management. `ECDH-ES` only. RSA JOSE is explicitly not wanted in this
  repository (see
  [`2026-08-04-trust-chain-signature-verification-design.md`](2026-08-04-trust-chain-signature-verification-design.md)).
- **Wallet-side obligations** (VCI-0060, 0061, 0088, 0089) — `out-of-scope` in the
  conformance report and unchanged by this work.

**Rollout posture: config-gated, default-off.** Both metadata objects are absent
unless configured, and `encryption_required` defaults to `false` on both. An
unconfigured deployment's metadata document is byte-identical to today's and its
`/credential` behaviour is unchanged. This matches the precedent set by roadmap item
B (ABCA challenge retrieval and DPoP nonces).

## 3. Configuration and key management

### 3.1 Config shape

Two new optional blocks under `issuer:`, named to mirror the specification's two
metadata objects so a reviewer can diff configuration directly against §L1373–1381:

```yaml
keys:
  issuer_request_enc:
    private_key: ./keys/issuer_request_enc.pem
    alg: ES256                      # names the key material (P-256); no x5c
issuer:
  request_encryption:               # absent => feature off, metadata omitted
    keys: [issuer_request_enc]      # ordered, non-empty
    enc_values_supported: [A128GCM, A256GCM]   # default
    encryption_required: false                 # default
  response_encryption:              # absent => feature off, metadata omitted
    enc_values_supported: [A128GCM, A256GCM]   # default
    encryption_required: false                 # default
```

`response_encryption` has no `keys`: the wallet supplies its own public JWK in each
request. It also has no configurable `alg_values_supported` — that value is fixed at
`["ECDH-ES"]` because `foundry_core::crypto::jwe::encrypt_compact` rejects every
other key-management algorithm. Making it configurable would only permit advertising
something the code cannot do.

`request_encryption.keys` is an ordered list to support rotation without downtime:
add the new key, redeploy (both keys are published and both decrypt), remove the old
one on a later deploy.

### 3.2 Why the encryption key's `alg` says `ES256`

`Config::validate_key_material` iterates **every** entry in the `keys:` map and calls
`SignatureAlgorithm::from_str(&entry.alg)`, which accepts only `ES256`, `ES384`, and
`ES512`. A `keys:` entry written as `alg: ECDH-ES` therefore fails startup
validation.

The `alg` field consequently names the **key material** (`ES256` ⇒ a P-256 EC key),
and `alg: "ECDH-ES"` is stamped onto the *published* JWK at metadata-build time. This
is the pattern `foundry-verifier`'s `annotate_encryption_jwk` already uses for the
ephemeral response-encryption key it offers in `client_metadata`, so it is a reuse of
an established convention rather than a new one.

The cost of reusing the `keys:` map is that nothing structurally prevents an operator
from also naming that key as a signing key. §3.4 rule 2 forbids it explicitly.

### 3.3 `DecryptionKey` and startup loading

Keys load once at process start, never per request. A new type in
`foundry_core::crypto::jwe`:

```rust
pub struct DecryptionKey {
    pub kid: String,                 // RFC 7638 thumbprint of `public_jwk`
    pub public_jwk: serde_json::Value,   // published in metadata
    private_jwk: serde_json::Value,      // bare; feeds `ECDH_ES.decrypter_from_jwk`
}
```

built over `josekit::jwk::alg::ec::EcKeyPair::from_pem` (curve auto-detected, as in
`FileSigner::from_pem`) and `KeyPair::{to_jwk_public_key, to_jwk_private_key}`.

`kid` is **derived**, not configured: `foundry_core::obs::thumbprint(&public_jwk)`.
§L1373 requires every JWK in the published set to carry a unique `kid`; a derived
thumbprint is unique by construction, stable across restarts and replicas, and cannot
drift from the key it names. A hand-written `kid` would need its own uniqueness
validation and could be edited without changing the key.

The private JWK is deliberately **bare** — no `kid`, no `use`, no `alg`. This mirrors
`foundry-verifier`'s existing asymmetry (annotated public JWK out, bare private JWK
for the decrypter) which `jwe.rs`'s own
`round_trips_annotated_public_to_bare_private` test already pins.

`AppState` gains `request_decryption_keys: Arc<Vec<DecryptionKey>>`, empty when
`issuer.request_encryption` is absent.

### 3.4 Startup validation

Four new rules in `crates/foundry-core/src/config/validate.rs`. Each rejects a
configuration that would otherwise boot into a state that cannot serve a request:

1. **Resolution and non-emptiness.** Every name in `request_encryption.keys` must
   resolve in the `keys:` map, and the list must be non-empty. §L1373 makes `jwks`
   REQUIRED, and an empty JWKS is unservable metadata.
2. **No cross-purpose reuse.** A key named in `request_encryption.keys` must not also
   be `verifier.signing_key` or `issuer.status_list.signing_key`. Using one EC key for
   both ECDSA signing and ECDH key agreement is cross-algorithm key reuse; §3.2's
   choice to share the `keys:` map makes this the only place it can be prevented.
3. **Satisfiable response-encryption requirement.**
   `response_encryption.encryption_required: true` requires `request_encryption` to be
   present with keys. §L960 requires a request carrying `credential_response_encryption`
   to itself be encrypted, so demanding the former while supporting no request
   decryption describes a deployment no conformant wallet can use.
4. **Advertised algorithms are implementable.** `enc_values_supported` on either block
   must be non-empty and a subset of `{A128GCM, A256GCM}` — anything else would be
   advertised in metadata and then rejected at request time.

Error messages name the offending key or field, matching the existing convention in
that file.

### 3.5 `foundry quickstart`

`quickstart` generates `keys/issuer_request_enc.pem` alongside the existing keys but
emits both `issuer.request_encryption` and `issuer.response_encryption` **commented
out**. The dev config's behaviour is therefore unchanged (§2, default-off), while an
operator enabling the feature does not have to generate a key by hand.

## 4. Metadata

`CredentialIssuerMetadata` gains two fields, both
`Option` + `skip_serializing_if = "Option::is_none"`:

```jsonc
"credential_request_encryption": {
  "jwks": { "keys": [ { /* public EC JWK; kid=<thumbprint>, use:"enc", alg:"ECDH-ES" */ } ] },
  "enc_values_supported": ["A128GCM", "A256GCM"],
  "encryption_required": false
},
"credential_response_encryption": {
  "alg_values_supported": ["ECDH-ES"],
  "enc_values_supported": ["A128GCM", "A256GCM"],
  "encryption_required": false
}
```

`skip_serializing_if` is what mechanically guarantees §2's zero-blast-radius claim:
with neither block configured the serialised document is byte-identical to today's,
and `wallet_metadata.rs` asserts it.

`zip_values_supported` is omitted from both objects. Per §L856 and §L1379 its absence
means compression MUST NOT be used, so this is a conformant configuration rather than
an unclosed gap.

`build_issuer_metadata` gains a second parameter, `&[DecryptionKey]`, rather than
loading key files itself: metadata is served on every wallet request and must not do
filesystem I/O. Two call sites change — the `issuer_metadata` handler and the OpenAPI
generator.

This closes VCI-0134 through VCI-0139.

## 5. Request path

### 5.1 The `MaybeEncrypted` extractor

A new module `crates/foundry/src/extract.rs`:

```rust
pub struct MaybeEncrypted<T> { pub value: T, pub was_encrypted: bool }
```

implementing `FromRequest<AppState>`. It consumes the body, so it must be the **last**
argument of `credential_handler`. Its logic is a three-way switch on `Content-Type`:

| `Content-Type` | Behaviour |
|---|---|
| `application/json` (parameters tolerated) | delegate to `Json::<T>::from_request`; `was_encrypted = false` |
| `application/jwt` | body as `String` → `decrypt_compact` → `serde_json::from_value::<T>`; `was_encrypted = true` |
| anything else | **415 Unsupported Media Type** |

The third row is what preserves VCI-0062 and keeps
`vci_0062_credential_request_requires_json_content_type` — which posts `text/plain`
and asserts 415 — passing unchanged.

When `issuer.request_encryption` is absent, `application/jwt` also yields **415**. An
issuer that accepted the media type and then failed would be indistinguishable from
one that supports the mechanism.

### 5.2 `decrypt_compact`

The crypto primitive is new in `foundry_core::crypto::jwe`, alongside the
`encrypt_compact` it inverts:

```rust
pub fn decrypt_compact(
    jwe: &str,
    keys: &[DecryptionKey],
    allowed_enc: &[String],
) -> Result<serde_json::Value, CryptoError>
```

It is built on `josekit::jwt::decode_with_decrypter_selector`, whose selector closure
receives `&JweHeader` **before** any decryption occurs. Three header checks run inside
that closure, each a named conformance clause:

- **`alg` must equal `"ECDH-ES"`** — §L1188: *"The JWE `alg` algorithm used MUST be
  equal to the `alg` value of the chosen JWK."* Every published JWK carries
  `alg: "ECDH-ES"` (VCI-0100).
- **`kid` must be present and resolve to one of `keys`** — §L1188 requires the `kid`
  header when the selected public key has one, and every published key does
  (VCI-0101). A missing `kid` is a rejection, not a fall back to trying every key:
  trial decryption would reduce `kid` to decoration and hide a wallet bug.
- **`enc` must be a member of `allowed_enc`** — the set advertised per VCI-0135.

Performing these checks in the selector means an unsupported header is refused before
any key agreement runs. It also mirrors `encrypt_compact`, which already validates
`alg` up front, so both directions of the module enforce their own invariants rather
than trusting callers.

The decrypted JWT claims set **is** the Credential Request object: §L1186 requires the
message contents to be encoded as a JWT, and `encrypt_compact` symmetrically places a
JSON object directly into the claims set.

Together §5.1 and §5.2 close VCI-0097 (JWT encoding), VCI-0098 on the request side
(`application/jwt` media type), VCI-0099, VCI-0100, and VCI-0101.

### 5.3 Policy checks in `foundry-issuer`

`handle_credential_request` gains a `request_was_encrypted: bool` argument and
performs four checks. They live in the engine, not the extractor, so a future second
call site cannot bypass them:

1. `request_encryption.encryption_required == true` and `!request_was_encrypted` →
   reject. §L1192: *"When encryption of a message was required but the received
   message is unencrypted, it SHOULD be rejected."*
2. `credential_response_encryption` present and `!request_was_encrypted` → reject.
   §L960, the substitution guard — the coupling described in §1.
3. `credential_response_encryption` present while `issuer.response_encryption` is
   absent from configuration → reject. §L969's MUST cannot be honoured, and silently
   answering in plaintext would deliver the credential unencrypted to a wallet that
   asked for encryption. **This is stricter than the specification demands** — the
   specification does not contemplate the case — and is a deliberate choice: a
   security feature must fail loudly rather than degrade silently.
4. `credential_response_encryption.jwk` must be an EC JWK carrying `alg` (§L1188
   makes `alg` mandatory); `enc` must be in the advertised set; `zip` must be absent
   (VCI-0056 — no `zip_values_supported` is advertised).

These close VCI-0054, 0055, 0056, and 0063.

## 6. Response path

`IntoResponse` cannot fail and encryption can, so the fallible work happens in the
handler where it becomes a typed error, and the response wrapper is a dumb carrier:

```rust
pub enum CredentialResponseBody {
    Json(CredentialResponse),   // Content-Type: application/json
    Jwt(String),                // Content-Type: application/jwt
}
```

`credential_handler`'s return type moves from `(HeaderMap, Json<CredentialResponse>)`
to `(HeaderMap, CredentialResponseBody)`. The `HeaderMap` stays: roadmap item B
attaches `DPoP-Nonce` on the success path.

When `req.credential_response_encryption` is `Some(params)` the body is
`encrypt_compact(&to_value(&res)?, &params.jwk, "ECDH-ES", &params.enc)`, served as
`application/jwt` with the compact JWE as the **raw** body — not a JSON-quoted string.
Otherwise it is `Json(res)`, byte-identical to today, which keeps
`vci_0064_0067_credential_response_uses_http_200_and_json_content_type` green.

`params.enc` is used verbatim rather than a configured default: §L969 requires
encoding *"using the parameters from the `credential_response_encryption` object"*, so
the wallet selects `enc` from the advertised set and foundry honours that selection.
§5.3 check 4 is what makes trusting the value safe.

This closes VCI-0066 and VCI-0098 on the response side.

## 7. Errors

### 7.1 Policy failures — 400 `invalid_credential_request`

The four §5.3 checks produce `IssuanceError::InvalidCredentialRequest(detail)`, which
`wallet_error_response` already maps to 400 `invalid_credential_request`. No new
variant and no new match arm; the variant's doc comment gains a line recording that it
now also covers encryption policy.

The detail string reaches the wire as `error_description` and therefore names only the
structural defect — e.g. `"credential_response_encryption.enc 'A192GCM' is not
supported"` — never key material. This is the constraint already documented on
`InvalidDpopProof`.

### 7.2 Structural failures — a second, deliberate error mapper

Extractor rejections occur before the handler runs and so never reach
`credential_error_response`. Root [`AGENTS.md`](../../../AGENTS.md) §4.5 requires
exactly one log record per typed error, emitted in the relevant error mapper, so the
extractor gets one:

```rust
enum MaybeEncryptedRejection {
    UnsupportedMediaType,                            // 415 — VCI-0062
    Issuance(foundry_issuer::IssuanceError),         // 400 — bad alg/enc/kid, undecryptable
    Json(axum::extract::rejection::JsonRejection),   // delegate, unchanged
}
```

Its `IntoResponse` emits exactly one `log_typed_error("wallet", …)` per rejection and
delegates the `Issuance` arm to `wallet_error_response`, so the response body and log
shape are identical whether a rejection originated in the extractor or in the engine.

A second mapper is how §4.5's "one record, in one place" invariant gets quietly broken;
this is the part of the change most deserving of review attention.

An undecryptable JWE is **400, not 500**. Ciphertext foundry cannot open is a bad
request, not a server fault. Routing it through `IssuanceError::Crypto` would have
produced a 500 — the trap the dedicated `Issuance` arm exists to avoid.

## 8. Observability

**Never logged, at any level, under any flag** (added to root `AGENTS.md` §4.5): the
raw compact JWE request body; the decrypted Credential Request JSON; the plaintext
`CredentialResponse` when encryption was requested; the wallet's
`credential_response_encryption.jwk`; the loaded private decryption JWKs. The wallet's
JWK appears only as `foundry_core::obs::thumbprint`.

**Safe to log.** foundry's own decryption `kid`s are published metadata, and logging
them is what makes a `kid` mismatch diagnosable in production. One `info` record at
startup names how many request-decryption keys loaded and their `kid`s.

**New span fields** on the `/credential` path, all non-sensitive: `request_encrypted`
(bool), `response_encrypted` (bool), `enc` (negotiated content-encryption algorithm),
`request_kid` (foundry's own key).

Every new `#[tracing::instrument]` carries `skip_all` — mandatory per §4.5 and
especially load-bearing here, where arguments include the JWE and the decrypted
request.

Level follows meaning: a policy rejection is `warn` (client error, retriable after a
fix); a startup key-load failure is `error`.

## 9. Testing

- **`foundry-core`.** `decrypt_compact` round-trips against `encrypt_compact`; rejects
  a wrong `alg`, an unsupported `enc`, an absent `kid`, an unknown `kid`, and tampered
  ciphertext. `DecryptionKey::kid` equals the RFC 7638 thumbprint of its own public
  JWK. The four §3.4 validation rules, each asserting the message names the offending
  key or field.
- **`foundry-issuer`.** The §5.3 policy matrix — all four checks, each in both the
  accepting and the rejecting direction.
- **`crates/foundry/tests/wallet_metadata.rs`.** Metadata is byte-identical to today
  when unconfigured; correctly shaped when configured, including `zip_values_supported`
  being absent.
- **`crates/foundry/tests/conformance_http.rs`.** The rejection matrix — 415 for
  `application/jwt` when the feature is off, 415 for `text/plain` always, 400 for each
  policy failure — plus the happy path: an encrypted request yields an
  `application/jwt` response that decrypts to the same `CredentialResponse` a plaintext
  request would have produced.
- **`crates/foundry/tests/wallet_issuance.rs`.** The encrypted happy path through the
  wallet router.
- **`crates/foundry/tests/e2e_full_flow.rs`.** One new `#[ignore]`d real-subprocess
  case with both blocks configured, proving config → key file → published JWKS → wire.
  This is the only layer that exercises `quickstart`-generated key material and
  startup validation.
- **`crates/foundry/tests/logging_redaction.rs`.** The decrypted request and the
  wallet's ephemeral JWK never appear in a TRACE capture, with the sensitive flag both
  off and on. The file's existing positive control already proves the harness is not
  inert.

The integration tests are the client: there is no `foundry-wallet` crate, and
`e2e_full_flow.rs` already builds JWEs itself with `encrypt_compact` for the OpenID4VP
response leg. An encrypted `/credential` round trip is written the same way.

## 10. Verification gate

Per-task: the **scoped** gate of root `AGENTS.md` §5.1 — the touched crate plus its
dependents per §5.2. The **full** gate of §5.3, including
`cargo test -p foundry --test e2e_full_flow -- --ignored`, runs exactly once, at the
end of the branch, before the whole-branch review.

## 11. Documentation

- [`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md) —
  flip VCI-0054, 0055, 0056, 0063, 0066, 0097–0101, 0134–0139 to `conforming` with
  evidence and test names. Record explicitly that the deferred-endpoint family
  (VCI-0084, 0088–0096) remains `not-implemented` because foundry has no Deferred
  Credential Endpoint, not because of encryption. No new GAP entries: omitting
  `zip_values_supported` is conformance by §L856/L1379.
- `openapi-wallet.json` — `/credential` gains `application/jwt` as an alternative
  request and response content type; the issuer-metadata schema gains both objects.
  Regenerate with the command documented in
  [`crates/foundry/AGENTS.md`](../../../crates/foundry/AGENTS.md); do not guess it.
- `README.md` — configuration reference for both blocks, and the new fields in the
  "Logging & Observability" list.
- Root [`AGENTS.md`](../../../AGENTS.md) §4.5 — the never-logged additions from §8.
- `crates/foundry-core/AGENTS.md` — `crypto/jwe.rs` gains decryption and
  `DecryptionKey`; the §3.2 `alg`-names-the-key-material convention belongs in its
  Gotchas.
- `crates/foundry-issuer/AGENTS.md` — the `request_was_encrypted` argument and the
  §5.3 policy checks.
- `crates/foundry/AGENTS.md` — the new `extract.rs` module and its rejection mapper.

## 12. Risks

- **A second error mapper (§7.2)** is the highest-risk element: it is the mechanism by
  which §4.5's single-log-record invariant could regress. `instrumentation_hygiene.rs`
  will **not** catch it — that test enforces `skip_all` and payload-flag gating, not
  record counts. The mitigations are structural: the `Issuance` arm delegates to
  `wallet_error_response` rather than reimplementing it, so the log record is emitted
  by the same code as before; and the extractor itself never logs outside its
  `IntoResponse`.
- **Extractor ordering.** `MaybeEncrypted` consumes the body and must be the final
  handler argument. Getting this wrong is a compile error, not a runtime bug.
- **Cross-purpose key reuse (§3.2).** Sharing the `keys:` map trades a structural
  guarantee for a validation rule (§3.4 rule 2). If a third consumer of `keys:` is
  added later, that rule must be extended too.
- **Strictness of §5.3 check 3.** Rejecting a response-encryption request when the
  feature is configured off is stricter than the specification requires. A deployment
  that enables `request_encryption` but not `response_encryption` will refuse a wallet
  asking for an encrypted response. Accepted deliberately; recorded here so it is not
  mistaken for an oversight.