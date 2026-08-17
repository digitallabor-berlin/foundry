# Encrypted Pre-Authorized Code — Design

**Date:** 2026-08-17
**Status:** Approved for planning
**Scope:** `foundry-core`, `foundry-issuer`, `foundry`

---

## 1. Context

Google Wallet's *"Google Wallet VCI 1.0 Profile"* proposes a custom OpenID4VCI
extension for the pre-authorized code flow: a new Token Request parameter
carrying the pre-authorized code as a **JWS nested inside a JWE**, replacing the
plaintext `pre-authorized_code` parameter.

Google's stated motivation, verbatim from the profile's feature table:

> *we see this as essential to make sure wallet server cannot steal and save
> preauth code*

The threat model is specific. In Google's architecture the wallet **client**
(on-device) talks to a Google Wallet **server**, and that server relays the
Token Request to the issuer. A plaintext `pre-authorized_code` traverses
Google's own infrastructure in the clear. Encrypting it to the issuer's public
key, and signing it with the on-device client instance key, means the relay can
neither read nor forge it.

This design covers **only** that extension plus a directly-coupled
configuration gap (a hardcoded access-token lifetime). It is deliberately
narrower than "make foundry compatible with the Google Wallet profile" — see
§8 for what is excluded and why.

### 1.1 Why this is worth doing despite being non-standard

foundry's governing rule for vendor behaviour (root `AGENTS.md` §4.4) is that a
vendor profile is normative *only* for what foundry does when accommodating that
vendor, never grounds for violating a standards-track MUST. This extension sits
comfortably inside that rule:

- OpenID4VCI defines `pre-authorized_code` as a Token Request parameter but does
  not forbid additional parameters. Adding one is an extension, not a violation.
- The feature is **off by default**. A deployment that does not enable it
  behaves exactly as it does today, byte for byte.
- Under `optional` the standard plaintext parameter continues to work.

Behaviour whose only justification is the vendor profile carries a code comment
naming it, per §4.4.

---

## 2. Governing Sources & Precedence

| Source | Governs | Precedence |
| --- | --- | --- |
| `docs/specs/openid-4-verifiable-credential-issuance-1_0.md` | Token Endpoint, pre-authorized code grant, `credential_request_encryption` metadata and keys | Standards-track — wins |
| `docs/specs/draft-ietf-oauth-attestation-based-client-auth-07.txt` | The Client Attestation JWT whose `cnf.jwk` anchors the inner JWS | Standards-track — wins |
| `docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md` | Algorithm constraints (ES256) | Standards-track, stricter — wins |
| Google Wallet VCI 1.0 Profile, §"token request field signing & encryption" | The extension's existence, parameter name, payload shape, and the 8-step validation algorithm | **Vendor profile** — accommodation only |

The profile revision this design is written against is the one delivered
2026-08-14 (*"Google Wallet VCI 1.0 Profile"*), which is a **newer and broader
revision** than the copy currently pinned at
`docs/specs/google-wallet-openid4vci-profile.md`. Pinning it is tracked
separately (§9.1); this design does not depend on that landing first, but the
code comments it mandates will cite whichever path the pinned revision ends up
at.

### 2.1 The profile's validation algorithm, restated

The profile specifies, verbatim:

1. (… previous token request processing steps as normal …)
2. if `encrypted_pre-authorized_code` is present in the request, follow next steps.
   1. otherwise, continue processing the request as normal
3. retrieve private key associated with the `credential_request_encryption` from issuer metadata
4. decrypt the JWE using that key
5. locate `cnf.jwk` from verified `OAuth-Client-Attestation` JWT
6. verify the nested JWS using that key
7. extract pre-auth code
8. (… continue token request processing as normal …)

This design implements all eight steps, and adds claim validation the profile
omits (§5.4) — the profile's own worked example carries `iss`, `sub`, `aud`,
`jti`, `iat` and `exp`, so validating them is honouring the format it
documents, not inventing policy.

---

## 3. Findings That Shape the Design

Three properties of the current codebase determine the work. Each was verified
by reading the code, not inferred.

### 3.1 `cnf.jwk` is parsed but discarded

The profile's step 5 requires the `cnf.jwk` of the verified Client Attestation
JWT. foundry verifies that JWT and does parse `cnf.jwk` into
`ValidatedAttestation` (`crates/foundry-issuer/src/attestation.rs:57`) — but
that type is internal to `verify_wallet_attestation`, and what escapes to the
caller is:

```rust
// crates/foundry-issuer/src/attestation.rs:251
pub struct PopClaims {
    pub iss: String,
    pub jti: String,
    pub iat: i64,
}
```

The key needed for step 6 is thrown away. `PopClaims` must carry it.

This is not merely plumbing: it changes what a *verified attestation* means to
downstream code, from "these claims were proved" to "these claims were proved
and here is the key that proved them". That is the correct meaning — the PoP
signature was already verified against exactly this key
(`attestation.rs:329`, check 4) — so exposing it asserts nothing new.

### 3.2 `decrypt_compact` requires a JSON plaintext

`crates/foundry-core/src/crypto/jwe.rs:136` performs three conformance header
checks (`alg`, `enc`, `kid`) and then:

```rust
// crates/foundry-core/src/crypto/jwe.rs:189
let (payload, _header) = josekit::jwt::decode_with_decrypter(jwe, &decrypter)?;
serde_json::to_value(payload.claims_set())
```

`josekit::jwt::decode_with_decrypter` parses the decrypted plaintext as a **JWT
claims set**. Google's plaintext is a compact **JWS string**
(`eyJ….eyJ….sig`), which is not JSON and will not parse.

The three header checks are correct and wanted for this path too. So the fix is
extraction, not duplication: a new `decrypt_compact_to_bytes` performs the
header checks and returns raw plaintext via `josekit::jwe::deserialize_compact`;
`decrypt_compact` becomes a thin JSON-parsing wrapper over it. No existing
caller changes behaviour.

### 3.3 The Token Endpoint has no access to config or decryption keys

```rust
// crates/foundry-issuer/src/token.rs:57
pub async fn handle_token_request(
    storage, req, wallet_attestation, attestation_header, pop_header,
    dpop_cfg, dpop, nonce_secret, issuer_identifier, now_unix,
) -> Result<TokenResponse, IssuanceError>
```

Neither the issuer's `request_decryption_keys` (needed for step 3/4) nor any
access-token lifetime knob is reachable. Both additions to this signature happen
**once**, in one task, rather than twice.

`AppState` already holds the keys
(`crates/foundry/src/server.rs:36`, `request_decryption_keys: Arc<Vec<DecryptionKey>>`),
loaded once at startup — so the HTTP layer has them and only needs to pass them.

---

## 4. Configuration Surface

### 4.1 New block: `issuer.encrypted_pre_authorized_code`

```yaml
issuer:
  encrypted_pre_authorized_code:
    mode: disabled          # disabled (default) | optional | required
    max_age_secs: 300       # inner-JWS `iat` sliding window, and jti replay TTL
```

Modelled as a struct rather than a bare `Mode` for consistency with
`AndroidKeystoreConfig` (`crates/foundry-core/src/config/model.rs:226`), which
established the "mode plus its own policy knobs" pattern.

**The default MUST be `Disabled`, explicitly.** `Mode`'s own `Default` is
`Optional` (`model.rs:385-390`), so a bare `#[serde(default)]` would silently
switch the feature *on* for every existing deployment. A dedicated
`default_disabled()` function is required.

### 4.2 Mode semantics

| Mode | `encrypted_pre-authorized_code` present | Plaintext `pre-authorized_code` present |
| --- | --- | --- |
| `disabled` | **Rejected** (`invalid_request`) | Required, as today |
| `optional` | Accepted | Accepted — **exactly one** of the two |
| `required` | Required | **Rejected** (`invalid_request`) |

Two of these deserve justification.

**`disabled` rejects rather than ignores.** Silently ignoring the member and
falling back to a plaintext parameter would be a downgrade attack surface
against the exact property the feature exists to provide. This mirrors how
foundry already handles an unsupported `zip` on a Credential Request
(`credential.rs`: rejected, not ignored) rather than the permissive
"ignore unknown claims" posture ABCA §5.2 rule 1 mandates for *JWT claims*.

**`required` rejects plaintext.** This is the anti-downgrade rule, structurally
identical to RFC 9449 §7.2's rule that a DPoP-bound token presented as Bearer
must be rejected — already implemented in `credential.rs`. Without it, `required`
would be advisory.

Under `optional`, presenting **both** is rejected rather than resolved by
precedence. Two codes in one request is a client bug, and picking a winner
hides it.

### 4.3 Validation rules (`Config::validate()`)

Two fail-closed rules, following the pattern already established at
`crates/foundry-core/src/config/validate.rs:207` for
`key_attestation.android.mode`:

1. `encrypted_pre_authorized_code.mode != Disabled` **requires**
   `wallet_attestation.mode != Disabled`.
   *Rationale:* with wallet attestation disabled there is no verified Client
   Attestation JWT, therefore no `cnf.jwk`, therefore step 6 can never succeed.
   Every request would fail at request time — a silent total outage of the
   Token Endpoint. Failing at load time makes it a legible misconfiguration.

2. `encrypted_pre_authorized_code.mode != Disabled` **requires**
   `issuer.request_encryption` to be present with at least one key.
   *Rationale:* identical — step 3/4 has nothing to decrypt with.

**Deliberately NOT a rule:** `encrypted_pre_authorized_code.mode: required`
combined with `wallet_attestation.mode: optional` is legal. It means a wallet
presenting no attestation is rejected at the encrypted-code step rather than at
the attestation step. That is coherent and is the same "one knob strengthens
another, it does not replace it" relationship `AttestationMode.challenge_mode`
already documents at `model.rs:179-185`. It is documented, not prevented.

### 4.4 New knob: `issuer.access_token_ttl_secs`

```yaml
issuer:
  access_token_ttl_secs: 600    # default preserves today's hardcoded value
```

`mint_and_save_tokens` (`token.rs:325`) hardcodes `let expires_in = 600u64;` and
uses that single value for **two** purposes:

```rust
// crates/foundry-issuer/src/token.rs:325-340
let expires_in = 600u64;
save_transaction_with_indices(storage, &tx, expires_in, now_unix).await?;  // row TTL
Ok(TokenResponse { access_token, token_type, expires_in })                  // wire value
```

The coupling is **correct and preserved**: the transaction row must outlive the
access token that addresses it, and equal lifetimes is the tightest correct
choice. One knob therefore drives both.

This is distinct from the existing `storage.transaction_ttl_secs`
(`model.rs:106`, default 600), which bounds how long an **offer** stays
redeemable before `/token` is ever called (`create_offer.rs:258`). The two
measure different phases and are deliberately separate knobs; the doc comment
must say so, because the similar names invite conflation.

Google's example token response shows `"expires_in": 86400`. This knob is the
honest partial answer: an operator can now configure that. It is *not* full
parity — Google also expects a `refresh_token`, which is out of scope (§8.2).

---

## 5. The Extension

### 5.1 Parameter name

**Canonical: `encrypted_pre-authorized_code`.**

The profile is internally inconsistent. Its prose says:

> a new field in the token request (`encrypted_pre-authorized_code`)

Its worked Token Request example says:

> `&encrypted_pre-authorization_code: eyJ...`

Prose wins: it is the normative statement, the example is illustrative, and
`pre-authorized_code` matches the OpenID4VCI parameter it replaces (`authorized`,
not `authorization`). The example's spelling is almost certainly a typo.

**Only the canonical name is accepted.** Accepting both doubles the wire surface
and, under `optional`, creates a third "both present" case to define. The
discrepancy is recorded as a gotcha in `crates/foundry-issuer/AGENTS.md` and
raised with Google (§9.2).

### 5.2 Wire format

```text
encrypted_pre-authorized_code = JWE( JWS( claims ) )
```

**Outer JWE.** Encrypted to the issuer's `credential_request_encryption` public
JWKS — the same keys, and the same published `kid`s, that already protect the
Credential Request. Reusing them is the profile's explicit instruction
("This is the same key used to encrypt the request to the Credential Endpoint")
and requires no new metadata, no new key material, and no new rotation story.

Constraints are inherited unchanged from `decrypt_compact_to_bytes`:
`alg` MUST be `ECDH-ES`; `enc` MUST be one of
`issuer.request_encryption.enc_values_supported`; `kid` MUST be present and
MUST match a configured key. All three already carry OpenID4VCI conformance
citations (L1188 / VCI-0100 / VCI-0101 / VCI-0135).

**Inner JWS.** Compact serialization. `alg` MUST be `ES256` — HAIP-0088 requires
issuers to support ES256 for wallet attestations "including proof of
possession", the signing key here **is** the attestation's `cnf.jwk`, and
foundry already pins ES256 for both the PoP JWT (`attestation.rs:311`) and DPoP
proofs (`dpop.rs:180`). A third algorithm policy would be an inconsistency, not
a feature.

**Payload claims**, per the profile's worked example:

```json
{
  "iss": "my_client_id",
  "sub": "my_client_id",
  "aud": "https://authorization-server.example.com/token",
  "jti": "unique-assertion-id-abc123",
  "iat": 1678886400,
  "exp": 1678886700,
  "pre-authorized_code": "..."
}
```

### 5.3 Placement in `handle_token_request`

The existing function establishes a deliberate ordering, documented in place:
attestation verification → `claim_pop_jti` → DPoP verification → grant dispatch.
Both the PoP `jti` claim and the DPoP verification sit *before* grant work with
an explicit comment saying why:

> Deliberately before any grant work — like `claim_pop_jti` above — so a
> replayed or forged proof can never burn a legitimate holder's
> pre-authorized or authorization code.

Resolution of the encrypted code **must** happen after attestation verification
(it consumes `cnf.jwk`) and before the pre-authorized code is looked up. It is
therefore placed at the **top of `handle_pre_authorized_code_grant`**, not in
`handle_token_request`'s pre-dispatch section, for one reason: the extension is
defined by the profile only for the pre-authorized code grant. The profile does
gesture at an encrypted `code` for the authorization code flow (its auth-code
example annotates `code=` as *"encrypted_by_key_from_credential_request_encryption"*),
but that annotation is the document's only mention of it — there is no prose,
no claim set and no algorithm — so it is out of scope (§8.1). Scoping the
resolution to the one grant that defines it prevents the other grant silently
inheriting half a feature.

The same anti-code-burning property still holds: resolution fails before
`load_transaction_by_pre_auth_code` is ever called, so a forged or replayed
envelope cannot reach the transaction lookup.

### 5.4 Validation pipeline

New module: `crates/foundry-issuer/src/encrypted_pre_auth.rs`.

The module owns exactly one public entry point and no other responsibility.
Its input is the raw parameter plus the material needed to judge it; its output
is a plain `String` — the pre-authorized code — which the existing grant handler
consumes unchanged. The grant handler does not learn that encryption happened.

Steps, in order, each failing closed:

| # | Check | Source | Failure |
| --- | --- | --- | --- |
| 1 | Outer JWE `alg` == `ECDH-ES` | OpenID4VCI L1188 | `InvalidRequest` |
| 2 | Outer JWE `enc` ∈ advertised | VCI-0135 | `InvalidRequest` |
| 3 | Outer JWE `kid` present and known | L1188 / VCI-0101 | `InvalidRequest` |
| 4 | JWE decrypts | Profile step 4 | `InvalidRequest` |
| 5 | Plaintext is a 3-part compact JWS | Profile step 6 | `InvalidRequest` |
| 6 | Inner JWS `alg` == `ES256` | HAIP-0088 | `InvalidClient` |
| 7 | Inner JWS signature verifies against `cnf.jwk` | Profile steps 5-6 | `InvalidClient` |
| 8 | `iss` non-empty and == `sub` | Profile example | `InvalidClient` |
| 9 | `iss` == the verified attestation's `sub` (i.e. `PopClaims.iss`) | Profile: *"must match the 'sub' in the attestation"* | `InvalidClient` |
| 10 | `aud` == the Token Endpoint URL | Profile example | `InvalidClient` |
| 11 | `jti` present, non-empty string | Profile example | `InvalidClient` |
| 12 | `iat` present, integer, within `max_age_secs` past / clock skew future | Profile: *"short-lived"* | `InvalidClient` |
| 13 | `exp` present, integer, not in the past | Profile example | `InvalidClient` |
| 14 | `jti` not previously claimed | Anti-replay | `InvalidClient` |
| 15 | `pre-authorized_code` present, a non-empty string | Profile step 7 | `InvalidClient` |

**Check 9 is the load-bearing one.** Without it, any wallet holding *any* valid
client attestation could submit a code envelope claiming to be a different
client. Binding the envelope's `iss` to the attestation that authenticated the
request is what makes the signature mean something. The profile states the
requirement inline in its example (`// The client ID, must match the 'sub' in
the attestation`) rather than in its numbered algorithm; it is honoured
regardless.

**Check 10 uses the Token Endpoint URL, not the issuer identifier.** The
profile's example is explicit: `"aud": "https://authorization-server.example.com/token"`
with the trailing comment `// Token endpoint`. This deliberately differs from
the Client Attestation PoP's `aud`, which ABCA §9 rule 10 binds to the AS's
*issuer identifier* and which foundry checks at `attestation.rs:370`. Two
different audiences for two different artifacts is what both documents say;
conflating them would break interop with the profile as written.

**Check 12's `exp` handling.** `exp` is validated (check 13) but is *not*
sufficient on its own — a client may set an arbitrarily distant `exp`. The
`max_age_secs` window on `iat` is the issuer-controlled bound, exactly as
`pop_max_age_secs` is for the PoP JWT. Both apply.

**Check 14's replay store.** `claim_pop_jti` (`attestation.rs:540`) already
implements precisely this pattern: SHA-256 of `(iss, 0x00, jti)` as the key,
`insert_kv_if_absent` for atomicity, `expires_at = iat + max_age + skew`, and a
test asserting the raw `jti` never appears as a storage key. The encrypted-code
`jti` needs the same treatment in a **separate namespace** — sharing one would
let a PoP `jti` and a code-envelope `jti` collide and deny service across
artifacts. The existing function is `pub(crate)` and keyed on `PopClaims`; the
new module needs its own thin equivalent over its own claims type and namespace
constant. Duplicating ~15 lines of well-tested arithmetic is the right call
against generalizing a function whose signature and namespace are both
artifact-specific.

### 5.5 Error mapping rationale

The split at check 5/6 is deliberate:

- **Checks 1-5 → `InvalidRequest`.** These are malformed *parameter values*. The
  client sent something that is not a well-formed envelope. RFC 6749 §5.2's
  `invalid_request` is exactly this.
- **Checks 6-15 → `InvalidClient`.** Past decryption, the artifact is signed by
  the client instance key and its claims assert client identity. A failure here
  is a failed client-authentication mechanism, which is what `IssuanceError::
  InvalidClient` was introduced for (see its doc comment, `error.rs:37-43`,
  added under GAP-VCI-14 for exactly the ABCA PoP path this mirrors).

No new `IssuanceError` variant is introduced. Both variants already map to HTTP
responses and both already log with a stable `error.kind` (`invalid_request`,
`invalid_client`).

### 5.6 Observability

Root `AGENTS.md` §4.5 binds this module completely. Additions to the
never-logged list, none of which are currently enumerated there because none
currently exist:

- the raw `encrypted_pre-authorized_code` parameter value (a JWE)
- the decrypted inner JWS, in compact or parsed form
- the extracted pre-authorized code (already covered — pre-authorized codes are
  named in §4.5 — but it now arrives by a second route)
- the envelope's `jti`

Every `#[tracing::instrument]` in the new module carries `skip_all`, as
mandated. The permitted fields are: the resolved `mode`, whether the member was
present, and the `kid` that selected a decryption key (a public thumbprint —
`DecryptionKey::kid()` is the RFC 7638 thumbprint of the public JWK, so it is
loggable on the same basis `dpop.rs` logs `jkt`).

`§4.5`'s one-log-record rule is unaffected: these errors surface as existing
variants and are logged by the existing mapper in `crates/foundry/src/server.rs`.

---

## 6. File Structure

| File | Change | Responsibility |
| --- | --- | --- |
| `crates/foundry-core/src/crypto/jwe.rs` | Modify | Add `decrypt_compact_to_bytes`; refactor `decrypt_compact` to wrap it |
| `crates/foundry-core/src/config/model.rs` | Modify | `EncryptedPreAuthCodeConfig`; `IssuerConfig.encrypted_pre_authorized_code`; `IssuerConfig.access_token_ttl_secs` |
| `crates/foundry-core/src/config/validate.rs` | Modify | The two fail-closed rules of §4.3 |
| `crates/foundry-issuer/src/attestation.rs` | Modify | `PopClaims.cnf_jwk` |
| `crates/foundry-issuer/src/encrypted_pre_auth.rs` | **Create** | The whole §5.4 pipeline; one public entry point |
| `crates/foundry-issuer/src/lib.rs` | Modify | Register + re-export the module |
| `crates/foundry-issuer/src/token.rs` | Modify | Signature additions; call the resolver; honour `access_token_ttl_secs` |
| `crates/foundry/src/server.rs` | Modify | Pass `request_decryption_keys` and config through |
| `crates/foundry/AGENTS.md`, `crates/foundry-issuer/AGENTS.md` | Modify | Module map + gotchas |
| `README.md` | Modify | Operator-facing config documentation |

The new module is deliberately its own file rather than a section of
`token.rs` (already 1801 lines). It has one responsibility, a narrow interface,
and can be tested without a Token Endpoint.

---

## 7. Testing Strategy

The repository's conformance suites are the model to follow. Unit tests live
beside the code in `#[cfg(test)]`; cross-crate behaviour goes to
`crates/foundry/tests/`.

**Positive control is mandatory.** The single most valuable test in this
feature is one that proves the happy path works — a genuinely
ECDH-ES-encrypted, genuinely ES256-signed envelope, built with real keys,
resolving to the expected code and issuing a token. Without it, every negative
test could pass against a function that rejects everything.

Required coverage:

- **Mode matrix** — all three modes × (member present, plaintext present, both,
  neither). Twelve cases; several share an expected outcome but each is a
  distinct configuration a deployment can actually be in.
- **Each of checks 1-15 fails closed**, one test per check, each mutating
  exactly one property of an otherwise-valid envelope. A test that mutates two
  things proves nothing about either.
- **Check 9 specifically** — an envelope whose `iss` names a *different* client
  than the attestation that authenticated the request must be rejected even
  though its signature is valid. This is the impersonation test.
- **Check 14 replay** — the same envelope twice; second is rejected. Plus: a
  code-envelope `jti` and a PoP `jti` with the same value do not collide
  (proves namespace separation).
- **Anti-code-burning** — a rejected envelope must leave the transaction
  redeemable. `token.rs` already has this test shape for `tx_code`
  (`token.rs:540`) and for `code_verifier` (`token.rs:299`); this is the third
  instance of the same property and must be tested the same way.
- **Regression: `decrypt_compact` is unchanged** — the existing Credential
  Request decryption tests must pass untouched after the §3.2 refactor.
- **Config validation** — both rules of §4.3 reject at load time; the legal
  `required` + `optional` combination of §4.3 loads successfully.
- **Default is off** — a config with no `encrypted_pre_authorized_code` block
  produces `Mode::Disabled`, not `Mode::Optional`. This guards the §4.1 trap
  directly.
- **Logging redaction** — the existing behavioural suite
  (`crates/foundry/tests/logging_redaction.rs`) gains cases for the new
  secrets of §5.6, with a positive control, matching how that file already works.

### 7.1 Verification gate

Per root `AGENTS.md` §5.1-5.2, this touches `foundry-core` (`crypto/` and
`config/`), `foundry-issuer`, and `foundry`. The scoped gate is therefore:

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```

`foundry-verifier` is included because the changed `foundry-core` module is
`crypto/`, whose §5.2 row names both engines. The full gate of §5.3 runs once,
at the end of the branch.

---

## 8. Out of Scope

### 8.1 Encrypted authorization code

The profile's authorization-code Token Request example annotates
`code="authcode from PAR and encrypted_by_key_from_credential_request_encryption"`.
There is no prose, no claim set, and no validation algorithm for it anywhere in
the document. It is also part of the authorization code flow, which the
currently-pinned profile revision states Google does not yet support. Excluded
until specified.

### 8.2 `refresh_token`

Originally scoped into this work and **removed after reading the code**. The
profile expects a `refresh_token` with one-year validity, whose purpose is
background credential refresh. foundry cannot deliver that meaning today:

```rust
// crates/foundry-issuer/src/transaction.rs:63
pub enum IssuanceState { Offered, Issued }        // Issued is terminal
// crates/foundry-issuer/src/credential.rs:173
if tx.state != IssuanceState::Offered { ...reject... }
// crates/foundry-issuer/src/token.rs:332
save_transaction_with_indices(storage, &tx, expires_in, now_unix).await?;
```

A transaction is redeemable exactly once, and the row is garbage-collected
`expires_in` seconds after the token is minted. A one-year refresh token
pointing at it would mint access tokens against a transaction that died in ten
minutes and could never issue a second credential regardless.

Delivering `refresh_token` requires a **re-issuance model**: a non-terminal
issuance state, a row lifetime decoupled from the access-token lifetime, and a
decision on whether a refresh reuses the credential's Token Status List index or
allocates a new one (which determines whether the old credential is revoked on
refresh). That is new subsystem behaviour and gets its own design round.

`access_token_ttl_secs` (§4.4) is in scope because it is a one-line hardcode
with no such dependency, and because it is a genuine prerequisite: there is no
point issuing a refresh token against a 600-second access token whose lifetime
an operator cannot change.

### 8.3 Also excluded

- **PAR, PKCE, `/authorize`, `authorization_details`** — authorization code flow.
- **`credential_identifier` at the Credential Endpoint** — coupled to
  `authorization_details`; blocked on the same design round.
- **HTTP Message Signatures** (`Content-Digest` / `Signature` / `Signature-Input`)
  — appear only in a profile example with no prose. Blocked on §9.2 Q3.
- **Deferred credential, issuer→wallet notifications** — issuer's choice per the
  profile; not a pre-auth blocker.
- **PoP `nonce` vs `challenge` claim name** — a genuine interop risk (the
  profile lists `nonce`; ABCA -07 §5.2 renamed it to `challenge`, which is what
  foundry reads at `attestation.rs:468`) but an *independent* one-line question,
  not part of this feature. Blocked on §9.2 Q1.

---

## 9. Follow-Ups

### 9.1 Pinning the profile revision

The delivered revision is broader than, and in places contradicts, the pinned
`docs/specs/google-wallet-openid4vci-profile.md` — most sharply on
authorization-code support. The pinned file is also cited from fourteen places
including load-bearing code comments (`server.rs:930-941`, `keystore_proof.rs:4`,
`foundry-core/src/trust/android_attestation.rs`, `config/model.rs`,
`metadata.rs`), so a blind replace would orphan justifications for shipped
behaviour.

The recommended resolution is **two pinned files**: the existing
current-behaviour profile stays authoritative and unchanged, and the new
revision lands beside it explicitly marked non-normative (it says of itself
*"we don't have full implementations done yet — so please don't rely on them for
any tests"*). That keeps §4.4's precedence story honest — a *proposed* profile
cannot justify shipped behaviour — and makes promotion a clean single edit when
Google ships.

Tracked separately from this design. This feature's code comments cite the
profile section by name, so they remain correct under either resolution.

### 9.2 Open questions for Google

1. **PoP claim name** — the profile's Client Attestation section lists a `nonce`
   claim; ABCA draft-07 §5.2 (line 458) defines `challenge`, and the draft's own
   changelog (line 1486) records *"rename nonce to challenge"*. Which does Google
   send? foundry reads `challenge`.
2. **Parameter spelling** — prose says `encrypted_pre-authorized_code`, the
   worked example says `encrypted_pre-authorization_code`. Confirmed as prose
   (§5.1); a correction to the example would close it.
3. **HTTP Message Signatures** — normative on the Credential Request, or example
   residue? If normative: signing key and covered-components list.
4. **`aud`** — confirm the inner JWS `aud` is the Token Endpoint URL
   (per the example) and not the AS issuer identifier (as ABCA uses for the PoP).
5. **`tx_code`** — marked *required* in the feature table but the section is
   `TBD`. Is OpenID4VCI's standard `tx_code` acceptable meanwhile? foundry
   implements it today.

None block implementation of this design. Q1 and Q3 block other work.

---

## 10. Conformance & Documentation Impact

- **`docs/conformance/openid4vc-conformance.md`** — this feature closes no
  existing gap row (it is an extension, not a conformance fix), but the
  `credential_request_encryption` key-reuse gains a second consumer, and any row
  asserting those keys are used *only* for the Credential Request needs
  re-reading. No new gap is introduced: the extension is off by default and
  additive when on.
- **`crates/foundry-issuer/AGENTS.md`** — module map gains
  `encrypted_pre_auth.rs`; Gotchas gains the §5.1 parameter-name discrepancy and
  the §4.1 default-must-be-explicit trap.
- **`crates/foundry/AGENTS.md`** — no routing change (`/token` is unchanged as a
  route), but the `token_handler` argument list changes.
- **`README.md`** — the two new config blocks, documented for operators,
  including the §4.4 distinction from `storage.transaction_ttl_secs`.
- **OpenAPI (§6)** — `TokenRequest` gains an optional member, so `openapi.json`
  and `openapi-wallet.json` must be regenerated.
