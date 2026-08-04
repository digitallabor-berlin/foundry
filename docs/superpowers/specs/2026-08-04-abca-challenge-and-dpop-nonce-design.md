# ABCA Challenge Retrieval and DPoP Server-Provided Nonces

**Date:** 2026-08-04
**Status:** approved
**Roadmap item:** Google Wallet compatibility, item **B**
**Specs:** `draft-ietf-oauth-attestation-based-client-auth-07` §5.2, §6.2, §8, §8.1, §9, §10.1 · RFC 9449 §4.3 check 10, §8, §8.1, §8.2, §9, §11.2, §11.3

---

## 1. Problem

Foundry authenticates wallets with Attestation-Based Client Authentication and
issues DPoP sender-constrained access tokens. Both mechanisms currently rely on
*client-chosen* freshness values — the Client Attestation PoP JWT's `jti` and
the DPoP proof's `jti`, each with an `iat` window and a storage-backed replay
guard.

Both specs define a second, stronger mechanism in which the **server** supplies
the freshness value, and neither is implemented:

- **ABCA §8 (Challenge Retrieval).** An Authorization Server MAY offer a
  challenge endpoint and advertise it as `challenge_endpoint` in RFC 8414
  metadata. Once advertised, "the Client **MUST** retrieve a challenge and
  **MUST** use this challenge in the OAuth-Attestation-PoP". Foundry offers no
  such endpoint and ignores the `challenge` claim entirely.
- **RFC 9449 §8/§9 (server-provided nonce).** An AS or resource server MAY
  reject a nonce-less DPoP proof with `use_dpop_nonce` plus a `DPoP-Nonce`
  header, forcing the nonce into subsequent proofs. This was **deliberately
  deferred** in `2026-08-03-dpop-sender-constrained-tokens-design.md` §2.2 and
  recorded as conformance row `RFC-9449-0008` = `not-implemented`.

Both are `MAY`s at the spec level, so foundry is not non-conformant today. They
matter because a wallet may *require* them, and because they close RFC 9449
§11.2 — proof **pre-generation**, which the RFC states the server-provided nonce
is the only real defence against.

## 2. Scope

**In scope:** ABCA §8 challenge endpoint, its §10.1 metadata advertisement, the
§8.1 response header, the §6.2 `use_attestation_challenge` error code, and §9
rule 8 verification. RFC 9449 §4.3 check 10, §8 (AS/`/token`), §8.2, and §9
(RS/`/credential`).

**Out of scope:** a full ABCA clause inventory in the conformance report (only
the challenge-mechanism clauses are added); implementing RFC 9449 §8's
`Access-Control-Expose-Headers` guidance, which presupposes a CORS layer foundry
does not have (it is still *recorded* — see §8); ABCA's other two §6.2 error
codes (`use_fresh_attestation`, `invalid_client_attestation`); roadmap items C,
D, E.

Both features are **config-gated and default-off.** No existing deployment or
test changes behaviour when this ships.

## 3. Shared primitive — domain-separated MAC

Three kinds of issuer-minted opaque token will be in flight: the OpenID4VCI
`c_nonce`, the ABCA `attestation_challenge`, and the DPoP `nonce`. All three are
stateless MACs derived from the same per-process `NonceSecret`.

Without domain separation, a value minted for one purpose would verify for
another — a wallet could present a `c_nonce` as a DPoP nonce and be accepted.
That is a real confusion vulnerability, not a theoretical one, and it is created
by this change: today only one kind exists.

New module `crates/foundry-issuer/src/challenge.rs` holds the primitive, lifted
out of `nonce.rs`:

```rust
pub(crate) enum Domain { CNonce, AttestationChallenge, DpopNonce }

pub(crate) fn mint(secret: &NonceSecret, domain: Domain, ttl_secs: u64, now_unix: i64)
    -> Result<String, IssuanceError>;

pub(crate) fn verify(secret: &NonceSecret, domain: Domain, value: &str, now_unix: i64)
    -> Result<(), IssuanceError>;
```

The wire format is unchanged from `nonce.rs` — `base64url(be_i64(exp) ||
salt(16) || truncated_hmac_tag)` — except that the **domain label is mixed into
the MAC input**. `verify` checks the MAC before trusting the embedded expiry,
preserving the existing invariant that an attacker-supplied expiry is never read
until the MAC proves this issuer minted the value.

`nonce.rs` keeps its public `issue_nonce` / `verify_nonce` API and delegates
with `Domain::CNonce`. Changing the MAC input breaks nothing: the secret is
per-process random, nothing is persisted, and these values live for seconds.

**TTLs are derived, not configured.** The ABCA challenge TTL is
`issuer.wallet_attestation.pop_max_age_secs`; the DPoP nonce TTL is
`issuer.dpop.max_age_secs`. A challenge outliving the window in which its PoP
would be accepted anyway is useless, and deriving the TTL keeps the two windows
consistent by construction rather than by an operator remembering to align two
numbers.

## 4. Configuration

Two new fields, both defaulting to `Mode::Disabled`:

```rust
// foundry_core::config::AttestationMode
#[serde(default = "default_disabled")]
pub challenge_mode: Mode,

// foundry_core::config::DpopConfig
#[serde(default = "default_disabled")]
pub nonce_mode: Mode,
```

`Mode::default()` is `Optional`, so a bare `#[serde(default)]` would silently
enable both features on every existing deployment. The explicit
`default_disabled` fn is load-bearing, not stylistic.

`challenge_mode` lives on `AttestationMode`, which is shared with
`issuer.key_attestation`. Like the existing `pop_max_age_secs`, it is read
**only** for `issuer.wallet_attestation` and must be documented as such —
key attestations have no PoP and no challenge mechanism.

### 4.1 Mode semantics

Identical for both features:

| Mode | Endpoint / metadata | Claim absent | Claim present |
|---|---|---|---|
| `disabled` | not routed, not advertised | accept | ignored entirely |
| `optional` | routed and advertised | accept | must verify |
| `required` | routed and advertised | **reject** | must verify |

`optional` is the migration rung: the server publishes the mechanism so wallets
can adopt it, while still accepting wallets that have not. It is deliberately
lenient relative to ABCA §8's "the Client MUST retrieve a challenge" — that
sentence binds *clients*, and server-side leniency during a migration window
does not violate it.

## 5. ABCA challenge

### 5.1 `POST /challenge`

Registered **only** when `challenge_mode != Disabled`. Unauthenticated, like
`/nonce` — §8's request example carries no credentials. ABCA §8's non-normative
example path is `/as/challenge`; foundry uses `/challenge` to match its existing
flat route layout (`/token`, `/nonce`, `/credential`), which §8 permits since
the path is discovered from metadata.

```
POST /challenge HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{ "attestation_challenge": "..." }
```

`Cache-Control: no-store` is a §8 **MUST**, not a nicety.

### 5.2 Metadata

ABCA §10.1 registers `challenge_endpoint` as "URL of the authorization servers
challenge endpoint which is used to obtain a fresh challenge".
`AuthorizationServerMetadata` gains:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub challenge_endpoint: Option<String>,
```

`Some` only when `challenge_mode != Disabled`. This mirrors the reasoning
already recorded for `dpop_signing_alg_values_supported`: the field's
**presence is the support signal**, and under §8 its presence is what makes the
`challenge` claim mandatory for clients. Advertising it while ignoring every
challenge would tell a wallet something false.

### 5.3 PoP verification — check 9

`validate_client_attestation_pop_jwt` gains a check citing ABCA §9 rule 8 ("If
the server provided a challenge value to the client, the `challenge` claim is
present in the Client Attestation PoP JWT and matches the server-provided
challenge value") and two parameters: `challenge_mode: &Mode` and
`nonce_secret: &NonceSecret`. It follows §4.1's matrix.

Per ABCA §5.2 the `challenge` claim is `OPTIONAL` and, when present, "MUST
specify a String value that is provided by the authorization server" — so a
non-string `challenge` is a rejection, not an ignore.

The existing `jti` replay store is **unchanged**. Per §10.6 it remains the
uniqueness guard; the challenge adds server-controlled freshness on top. §9 rule
9 ("creation time … as determined by either the `iat` claim or a server managed
timestamp via the `challenge` claim") is satisfied by both paths at once: the
`iat` window still applies, and the challenge's embedded expiry is a
server-managed timestamp.

### 5.4 Error surface — `use_attestation_challenge`

ABCA §6.2 makes this mandatory:

> `use_attestation_challenge` **MUST** be used when the Client Attestation PoP
> JWT is not using an expected server-provided challenge. When used this error
> code **MUST** be accompanied by the `OAuth-Client-Attestation-Challenge` HTTP
> header field parameter (as described in Section 8.1).

So a challenge failure is **not** `invalid_client`. New variant:

```rust
IssuanceError::UseAttestationChallenge(String)   // kind() => "use_attestation_challenge"
```

Its response MUST carry a fresh `OAuth-Client-Attestation-Challenge` header —
that pairing is what makes the wallet's retry succeed. A generic
`invalid_client` would leave a compliant wallet unable to tell that a retry is
even possible.

This is structurally the same shape as RFC 9449's `use_dpop_nonce` (this
document, §6.2): a dedicated error code plus a header carrying the value needed
to retry.

### 5.5 §8.1 — challenge on ordinary responses

> The Authorization Server MAY provide a fresh Challenge with any HTTP response
> … The Client MUST use this new Challenge for the next OAuth-Client-
> Attestation-PoP.

When `challenge_mode != Disabled`, `/token` responses carry
`OAuth-Client-Attestation-Challenge: <fresh>` on **success and on error**. A
wallet therefore never needs a second `/challenge` round-trip after its first
`/token` call.

## 6. DPoP server-provided nonce

### 6.1 `verify_dpop_proof` — check 10

Gains `nonce_mode: &Mode` and `nonce_secret: &NonceSecret`, and implements RFC
9449 §4.3 check 10 ("If the server provided a nonce value to the client, the
`nonce` claim matches the server-provided nonce value") per §4.1's matrix.

`dpop.rs`'s module doc comment currently states check 10 is *vacuous* and that
§11.3 is "satisfied by construction". Both sentences become false with this
change and **must be rewritten**, not left in place. Likewise the `VerifiedDpopProof`
docs and the design-doc cross-references to §2.2 of the DPoP design.

### 6.2 Error surface — `use_dpop_nonce`

```rust
IssuanceError::UseDpopNonce(String)   // kind() => "use_dpop_nonce"
```

Distinct from `InvalidDpopProof` deliberately: §8 names `use_dpop_nonce`
specifically, and a wallet keys its retry logic on that exact string. Reusing
`invalid_dpop_proof` would make a retriable condition indistinguishable from a
permanent failure.

### 6.3 Response wiring

| Endpoint | Failure | Success |
|---|---|---|
| `/token` (§8) | 400 `{"error":"use_dpop_nonce", "error_description": …}` + `DPoP-Nonce: <fresh>` | 200 + `DPoP-Nonce: <fresh>` |
| `/credential` (§9) | 401 + `WWW-Authenticate: DPoP error="use_dpop_nonce", algs="ES256"` + `DPoP-Nonce: <fresh>` | 200 + `DPoP-Nonce: <fresh>` |

The 400-vs-401 split is not a choice: §8 governs the authorization server and
§9 governs the protected resource, which per §7.1 answers with 401 and
`WWW-Authenticate`. `credential_error_response` already special-cases
`InvalidDpopProof` into exactly that shape, so the new variant extends that
branch rather than introducing a second mechanism.

Per §8, a nonce **mismatch** also supplies a new nonce — the same path as a
missing nonce, so no separate branch is needed.

`DPoP-Nonce` rides on **successful** responses too, which §8.2 permits. After
its first request a wallet always holds a usable nonce and never needs a
rejection round-trip. §8's "there MUST NOT be more than one `DPoP-Nonce` header"
is satisfied structurally: one insertion point per response.

### 6.4 What this closes

RFC 9449 §11.2 (proof pre-generation) was left open by the 2026-08-03 design,
mitigated only by 600-second non-renewable access tokens. With `nonce_mode`
enabled it is genuinely closed: a proof cannot be minted before the server has
issued the nonce it must carry. §11.3 ("a server MUST NOT accept any DPoP proofs
without the `nonce` claim when a DPoP nonce has been provided to the client")
stops being vacuous and becomes actively enforced under `required`.

Under `disabled` — the default — the previous reasoning stands unchanged.

## 7. Observability

Challenges and DPoP nonces are freshness secrets: logging one hands an attacker
the value needed to complete a forged PoP or proof. They join the never-logged
list.

- Root `AGENTS.md` §4.5's "Never logged, at any level, under any flag" list gains
  attestation challenges and DPoP nonces alongside `c_nonce`.
- `crates/foundry/tests/logging_redaction.rs` gains both values to its
  `issuance_never_logs_*` assertion table, which already threads `("c_nonce", …)`
  in exactly this way.
- New `#[tracing::instrument]` attributes carry `skip_all`; the existing
  `instrumentation_hygiene.rs` test enforces this structurally.
- A challenge or nonce **failure** is a client-correctable protocol condition,
  not a server fault: log at `warn`, and emit exactly one record per error from
  the error mapper in `server.rs`, never at the call site (§4.5).

## 8. Documentation

**Conformance report** (`docs/conformance/openid4vc-conformance.md`):

- `RFC-9449-0008` flips `not-implemented` → `conforming`, with evidence stating
  plainly that it is config-gated and default-off.
- New RFC 9449 rows for §8.2, §9, §4.3 check 10, and §11.3 (no longer vacuous).
- An `out-of-scope` row for §8's `Access-Control-Expose-Headers` note, citing the
  absence of any CORS layer in `crates/foundry/src/` — recorded rather than left
  silent.
- A new `## Clause Inventory — ABCA (Challenge Retrieval)` section for §8, §8.1,
  §10.1, §6.2's `use_attestation_challenge`, and §9 rule 8, cross-referencing
  `VCI-0232`. A complete ABCA inventory is explicitly not in scope.

**OpenAPI** (§6 of root `AGENTS.md`): `/challenge` added to `openapi.json` and
`openapi-wallet.json` via `utoipa` annotations, then regenerated.

**README:** the two new config keys, their default-off semantics, and the new
endpoint.

**Crate guides:** `challenge.rs` into `crates/foundry-issuer/AGENTS.md`'s module
map; `/challenge` into `crates/foundry/AGENTS.md`'s route list.

## 9. Testing

Scoped gate per root `AGENTS.md` §5.1: `cargo test -p foundry-issuer -p foundry`,
`cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings`,
`cargo fmt --check`. No `--workspace` run per task; the full gate of §5.3 runs
once at the end of the branch.

**`challenge.rs`** — the domain-separation tests are what earn the primitive:

- a `c_nonce` is rejected when presented as a DPoP nonce
- a DPoP nonce is rejected when presented as an attestation challenge
- an attestation challenge is rejected when presented as a `c_nonce`
- expiry, tampered embedded expiry, foreign secret, malformed input
- successive mints differ (unpredictability)

**`attestation.rs`** — three modes × {absent, valid, expired, forged,
cross-domain, non-string}, plus: a `Disabled` server ignores a present
`challenge`; a `Required` rejection is `UseAttestationChallenge`, never
`InvalidClient`.

**`dpop.rs`** — the same matrix for the `nonce` claim, asserting `UseDpopNonce`.

**`crates/foundry/tests/`** — HTTP level:

- `/challenge` returns 200 + `Cache-Control: no-store` when enabled; 404 when disabled
- metadata advertises `challenge_endpoint` only when enabled
- `/token` rejects a nonce-less proof with 400 `use_dpop_nonce` + `DPoP-Nonce`,
  then succeeds when the wallet retries with the supplied nonce
- `/credential` likewise, with the 401 + `WWW-Authenticate` shape
- a `use_attestation_challenge` response carries the
  `OAuth-Client-Attestation-Challenge` header (§6.2's MUST)
- `/token` carries `OAuth-Client-Attestation-Challenge` on success (§8.1)
- exactly one `DPoP-Nonce` header per response

**Regression guard.** Every existing test must pass **untouched**, because both
toggles default to `Disabled`. If an existing test needs editing to stay green,
that is evidence the default leaked into an enabled path — treat it as a defect
in this change, not as a test to update.

## 10. Risks

| Risk | Mitigation |
|---|---|
| Cross-purpose token confusion between the three MAC domains | Domain separation is in the primitive itself, with a test per ordered pair |
| A default silently flipping the features on | Explicit `default_disabled` fn; regression guard in §9 |
| Stale doc comments asserting check 10 is vacuous | Named explicitly in §6.1 as required edits |
| Per-process secret means challenges die on restart | Already the accepted trade for `c_nonce`; a wallet retries and gets a fresh one via §8.1 / §8.2 headers |
| `challenge_mode` read from the shared `AttestationMode` and wrongly applied to key attestations | Documented wallet-only, as `pop_max_age_secs` already is |