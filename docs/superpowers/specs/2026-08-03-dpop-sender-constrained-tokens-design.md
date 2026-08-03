# DPoP Sender-Constrained Access Tokens — Design

**Date:** 2026-08-03
**Gap closed:** `GAP-HAIP-03` (Important)
**Governing spec:** [`docs/specs/rfc9449-dpop.txt`](../../specs/rfc9449-dpop.txt) — RFC 9449, *OAuth 2.0 Demonstrating Proof of Possession (DPoP)*, September 2023
**Mandating clause:** HAIP OpenID4VCI L163 — *"Sender-constrained access token: MUST support DPoP as defined in [@!RFC9449]."*

---

## 1. Problem

`GAP-HAIP-03` records that foundry's access tokens are bearer-only:

- `mint_and_save_tokens` (`crates/foundry-issuer/src/token.rs`) hardcodes
  `token_type: "Bearer"`.
- `credential_handler` (`crates/foundry/src/server.rs`) hardcodes
  `strip_prefix("Bearer ")`.
- `IssuanceTransaction` carries no key-binding field.
- `AuthorizationServerMetadata` carries no
  `dpop_signing_alg_values_supported`.
- No DPoP proof verification exists anywhere in the workspace.

A stolen access token is therefore fully replayable by whoever holds the
bytes. HAIP L163 requires sender-constraining via DPoP, and RFC 9449 §10
additionally imposes a MUST on any authorization server that receives a
`dpop_jkt` authorization-request parameter — a MUST foundry currently
violates silently, because it ignores the parameter entirely.

RFC 9449 is checked into `docs/specs/` but is **not yet listed** in the root
`AGENTS.md` §4.4 pinned-spec table. This design adds that row.

## 2. Scope decisions

Four decisions were taken during design, each with the rejected
alternatives recorded so a future reader can see what was considered.

### 2.1 Enforcement model — config tri-state, default `Optional`

RFC 9449 §5 permits an AS to issue plain Bearer tokens when no proof is
presented; §5.2's `dpop_bound_access_tokens: true` is the switch that makes
proofs mandatory. HAIP requires the issuer to *support* DPoP, not to
*refuse* Bearer.

**Chosen:** a `issuer.dpop.mode` tri-state reusing the existing
`foundry_core::config::Mode` enum, defaulting to `Optional`.

- `Optional` — proof present ⇒ DPoP-bound token and `token_type: "DPoP"`;
  proof absent ⇒ Bearer, exactly as today.
- `Required` — a token request without a `DPoP` header is rejected
  (§5.2).
- `Disabled` — the header is **ignored** and Bearer is always issued.

**Rejected:** presence-driven with no config (a deployment could never
enforce sender-constraining, so the FAPI-2 posture HAIP wants would be
inexpressible); always-required (breaks every existing wallet flow and test,
and RFC 9449 does not require it).

**Note on `Disabled`.** An earlier draft of this decision had `Disabled`
*reject* any `DPoP` header. That was changed deliberately: §10.1 explicitly
encourages clients that *"blindly attach the DPoP header to all calls to the
authorization server"*, and §5 states an AS *"MAY elect to issue access
tokens that are not DPoP bound, which is signaled to the client with a value
of `Bearer`."* Rejecting would hard-fail a wallet doing precisely what the
RFC recommends; ignoring lets the wallet read `token_type` and decide for
itself per §5.

### 2.2 Server-provided DPoP nonce (§8, §9) — out of scope

**Chosen:** not implemented this cycle. No `DPoP-Nonce` response header, no
`use_dpop_nonce` error, no `nonce` claim required.

This is normatively permitted: §8 says an AS *MAY* supply a nonce,
OpenID4VCI L809 says the Credential Issuer *MAY* provide one, and HAIP's
L163 note places the obligation on *wallets* to cope with a nonce, not on
the issuer to send one. §11.3 (*"a server MUST NOT accept any DPoP proofs
without the `nonce` claim when a DPoP nonce has been provided to the
client"*) is satisfied vacuously — we never provide one.

The consequence is stated honestly in §6.2 below and recorded as a
MAY-not-implemented row in the conformance report.

**Rejected:** config-gated-default-off (doubles the state machine on two
endpoints, with every branch needing tests, for a path no deployment would
switch on yet); always-on (forces a mandatory extra round trip on every
wallet, including those that do not implement it).

### 2.3 `dpop_jkt` at the Authorization Endpoint (§10) — accept and enforce

foundry implements the authorization code flow, so §10 applies. The
asymmetry matters: *sending* `dpop_jkt` is OPTIONAL for the client, but once
sent, *honouring* it is a MUST for the AS — *"If they do not match, it MUST
reject the request."*

**Chosen:** accept `dpop_jkt` on `/authorize`, persist it on the
transaction, and at `/token` require the verified proof's thumbprint to
equal it. Absent ⇒ no constraint (unchanged behaviour).

**Rejected:** deferring it (would leave a MUST open in the very cycle
dedicated to DPoP, and a wallet sending `dpop_jkt` would get silent
non-enforcement — worse than not advertising DPoP at all); requiring
`dpop_jkt` under `mode: Required` (stricter than §10, which is explicitly
OPTIONAL for clients, and would break conformant wallets using the DPoP
header alone).

§10.1 (PAR) does not bind us: foundry has no `/par` endpoint — that is
`HAIP-0007`, tracked separately as `ambiguous`.

### 2.4 Access-token key binding — `jkt` on the transaction

§6 requires the resource server to *"reliably identify whether an access
token is DPoP-bound and ascertain sufficient information to verify the
binding."* It names two mechanisms — `cnf.jkt` in a JWT access token (§6.1)
and token introspection (§6.2) — then explicitly allows others: *"Other
methods of associating a public key with an access token are possible per an
agreement by the authorization server and the protected resource."*

foundry's access tokens are opaque (`at_<uuid>`), and the AS and the
resource server are **the same process sharing one `Storage`** — so that
agreement is internal, and the third path is the natural fit.

**Chosen:** store the thumbprint on `IssuanceTransaction`.
`handle_credential_request` already resolves the transaction by access token
via `load_transaction_by_access_token`, so the bound key arrives for free
with the lookup. §7.2 (reject a DPoP-bound token presented as Bearer) falls
out as a trivial consequence.

**Rejected:** JWT access tokens with `cnf.jkt` (replaces foundry's entire
access-token format, needs an issuer signing key wired into `/token`, and
changes every existing issuance test — large blast radius, no functional
gain in a single-process deployment); an RFC 7662 `/introspect` endpoint
(exists to serve a *remote* resource server, which we do not have).

## 3. Architecture

### 3.1 New module — `crates/foundry-issuer/src/dpop.rs`

Owns the whole of RFC 9449 §4.2/§4.3 — parsing and validating a DPoP proof
JWT — and nothing else. Modelled on `attestation.rs`'s
`validate_client_attestation_pop_jwt`: split a compact JWS, decode the
header, reject `alg: none` and symmetric algorithms, verify against the
embedded public JWK, then check payload claims.

Public surface:

```rust
/// The outcome of a successful §4.3 validation. Carries only what a caller
/// still needs; every other claim was checked here and has no consumer above.
pub struct VerifiedDpopProof {
    /// RFC 7638 JWK SHA-256 thumbprint, base64url — the §6.1 `jkt` value.
    pub jkt: String,
    /// Retained solely so the caller can hand it to `claim_dpop_jti`; never
    /// logged (§4.5).
    pub jti: String,
}

pub fn verify_dpop_proof(
    proof_jwt: &str,
    htm: &str,                    // §4.3 check 8  — actual HTTP method
    htu: &str,                    // §4.3 check 9  — actual target URI, query/fragment stripped
    expected_ath: Option<&str>,   // §4.3 check 12 — Some at /credential, None at /token
    now_unix: i64,
    max_age_secs: u64,            // §4.3 check 11 / §11.1 acceptance window
) -> Result<VerifiedDpopProof, IssuanceError>;

/// §11.1 single-use enforcement. Returns `Ok(())` on a first sighting and
/// `Err(InvalidDpopProof)` on a replay. `normalized_htu` must be the value
/// `verify_dpop_proof` compared against, not the raw claim.
pub(crate) async fn claim_dpop_jti(
    storage: &dyn Storage,
    jkt: &str,
    normalized_htu: &str,
    jti: &str,
    max_age_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError>;

/// What the HTTP layer observed about a request's DPoP presentation. A struct
/// rather than five more positional parameters on two already-long functions.
pub struct DpopPresentation<'a> {
    /// `true` when the `Authorization` scheme was `DPoP`; `false` for `Bearer`.
    /// Only meaningful at `/credential`.
    pub scheme_is_dpop: bool,
    /// The raw `DPoP` header value, `None` when absent.
    pub proof_jwt: Option<&'a str>,
    pub htm: &'a str,
    pub htu: &'a str,
    /// `base64url(SHA-256(access_token))` — `None` at `/token`, where no
    /// access token is being presented (§4.3 check 12 does not apply).
    pub ath: Option<&'a str>,
}
```

`verify_dpop_proof` deliberately takes six positional parameters rather than a
struct: they are all scalars the validator needs simultaneously, and at six it
sits under clippy's `too_many_arguments` threshold of seven — so unlike
`handle_token_request` it needs no `#[allow]`.

**Why a separate module and not an extension of `attestation.rs`:** they are
different mechanisms answering to different specs — ABCA client
*authentication* versus RFC 9449 sender-*constraining* — and
`attestation.rs` is already the crate's largest file with three
confusingly-similar entry points (its own `AGENTS.md` carries a gotcha about
exactly that). A fourth would make it worse.

**No new crypto.** `foundry_core::obs::thumbprint_bytes` is already a
fail-closed RFC 7638 SHA-256 implementation with known-answer tests, and is
exactly the `jkt` primitive both §6.1 and §10 need. Verified during design:
RFC 9449 Figure 9's published `jkt` value
(`0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I`) reproduces exactly under
that function's canonicalisation.

The **fail-closed** variant is the required one. The infallible
`thumbprint` degrades a malformed JWK to a placeholder string, which would
then compare unequal to every real `jkt` — turning a parse error into a
confusing binding mismatch.

**Layering** is unchanged: `dpop.rs` depends only on `foundry-core`
(`obs`, `storage`, `config`) plus `josekit` and `sha2`, exactly as
`attestation.rs` does. No new crate, no new `Cargo.toml` dependency.

### 3.2 Call sites

| Site | Layer | Responsibility |
|---|---|---|
| `token.rs::handle_token_request` | issuer | pass the `DPoP` header plus `htm`/`htu` down; on success record `jkt` on the transaction and set `token_type: "DPoP"`; enforce `tx.dpop_jkt` (§10) |
| `server.rs::credential_handler` | binary | parse the `Authorization` scheme (`DPoP` vs `Bearer`), compute `ath`, hand both to `handle_credential_request` |

**HTTP-facing values are supplied by the caller, never inferred.** `htm` and
`htu` must be the real method and URI of the request being authenticated,
which only `crates/foundry` knows — so they are parameters and `dpop.rs`
never guesses. `htu` is derived from the configured
`issuer.credential_issuer` plus the route path, **not** from a
client-controlled `Host` header: trusting `Host` would let an attacker
replay a proof minted for a different origin.

## 4. Configuration & data model

### 4.1 `foundry-core/src/config/model.rs`

```rust
pub struct IssuerConfig {
    // ...existing...
    #[serde(default)]
    pub dpop: DpopConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DpopConfig {
    /// RFC 9449 §5 / §5.2. `Optional` (the default): a valid proof yields a
    /// DPoP-bound token, its absence yields Bearer. `Required`: equivalent
    /// to `dpop_bound_access_tokens: true` — a token request without a DPoP
    /// header is rejected. `Disabled`: the header is ignored, Bearer always.
    #[serde(default)]
    pub mode: Mode,
    /// RFC 9449 §4.3 check 11 / §11.1: how far from `now` an `iat` may sit,
    /// in either direction (§11.1 permits accepting a near-future `iat` to
    /// absorb clock skew).
    #[serde(default = "default_dpop_max_age_secs")]
    pub max_age_secs: u64,
}

fn default_dpop_max_age_secs() -> u64 { 300 }
```

Reuses the existing `Mode` tri-state verbatim — no new enum. `300 s` matches
the house default already used for `pop_max_age_secs` and sits inside
§11.1's *"on the order of seconds or minutes."*

Defaults are chosen so **every existing config file and fixture keeps
working untouched**: `dpop` absent ⇒ `Optional` ⇒ no proof sent ⇒ Bearer ⇒
current behaviour.

### 4.2 `foundry-issuer/src/transaction.rs`

```rust
/// RFC 9449 §6: the RFC 7638 thumbprint of the DPoP key this access token
/// is bound to. `Some` ⇒ the token is DPoP-bound and MUST be presented with
/// the `DPoP` scheme plus a matching proof; `None` ⇒ plain Bearer.
/// Doubles as the §10 `dpop_jkt` carrier between /authorize and /token.
#[serde(default)]
pub dpop_jkt: Option<String>,
```

`#[serde(default)]` is load-bearing, not decorative: transactions are
persisted as JSON in the KV store, so a row written before this change must
still deserialize after a rolling restart.

One field serves both §10 (written by `/authorize`, checked at `/token`) and
§6 (written by `/token`, checked at `/credential`). Its meaning is *"the key
this flow is pinned to"* at every stage, so this is one concept, not an
overloaded field.

`Config::validate()` additionally rejects `max_age_secs == 0`: a zero window
makes every proof unacceptable the instant it is minted, which is a
misconfiguration that would otherwise surface only as blanket
`invalid_dpop_proof` responses at runtime.

### 4.3 `authorize.rs` / `server.rs`

`AuthorizeParams` and `AuthorizeQuery` each gain
`dpop_jkt: Option<String>`, threaded into the transaction.

`handle_token_request` gains one parameter — the presentation struct, inserted
after `pop_header` so the existing attestation arguments stay adjacent:

```rust
pub async fn handle_token_request(
    storage: &dyn Storage,
    req: &TokenRequest,
    wallet_attestation: &AttestationMode,
    attestation_header: Option<&str>,
    pop_header: Option<&str>,
    dpop: &DpopConfig,
    dpop_presentation: &DpopPresentation<'_>,
    issuer_identifier: &str,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError>;
```

The existing `#[allow(clippy::too_many_arguments)]` already on this function
covers the addition. `crates/foundry-issuer/AGENTS.md`'s entry-point table
records this signature and must be updated with it.

### 4.4 `metadata.rs` — RFC 9449 §5.1

```rust
#[serde(skip_serializing_if = "Vec::is_empty")]
pub dpop_signing_alg_values_supported: Vec<String>,
```

`["ES256"]` when `mode != Disabled`, empty (hence omitted) under `Disabled`
— the field's presence *is* the support signal, so advertising it while
ignoring proofs would be a lie.

`ES256` only: it is what `josekit` verification is wired for throughout this
crate, and HAIP's crypto-suites section mandates it.

### 4.5 OpenAPI (root `AGENTS.md` §6)

`openapi.json` needs regeneration: `AuthorizationServerMetadata` gains a
property and `/authorize` gains a query parameter. `TokenResponse`'s shape
is unchanged (`token_type` was always a `String`), but its doc comment must
stop implying `Bearer` is the only value.

## 5. Data flow

### 5.1 Verification — the twelve §4.3 checks

| §4.3 | Check | Where |
|---|---|---|
| 1 | not more than one `DPoP` header field | **`server.rs`** — `headers.get_all("dpop").count() > 1` ⇒ reject. Cannot live in `dpop.rs`, which receives a single `&str` |
| 2 | single well-formed JWT | 3 dot-separated parts; header and payload decode as JSON |
| 3 | all required claims present | `jti`, `htm`, `htu`, `iat` (plus `ath` when `expected_ath.is_some()`) |
| 4 | `typ == "dpop+jwt"` | exact string |
| 5 | `alg` registered, asymmetric, not `none`, supported | allowlist: `ES256` only |
| 6 | signature verifies with the header's `jwk` | `josekit` ES256 verifier |
| 7 | `jwk` contains no private key | reject any of `d`, `p`, `q`, `dp`, `dq`, `qi`, `k` — the guard `attestation.rs` already applies to `cnf.jwk` |
| 8 | `htm` matches the request method | case-sensitive, per RFC 9110 |
| 9 | `htu` matches the request URI, query/fragment ignored | see normalisation below |
| 10 | `nonce` matches a server-supplied nonce | **vacuous** — we never supply one (§2.2). §11.3 therefore satisfied by construction |
| 11 | `iat` within an acceptable window | `abs(now - iat) <= max_age_secs`; §11.1 explicitly permits a near-future `iat` to absorb clock skew, so the window is symmetric |
| 12 | `ath` equals the hash of the access token, and the token's bound key matches the proof key | `ath` compared here; **key match is the caller's job** — `dpop.rs` knows nothing about transactions |

**`htu` normalisation** (§4.3's SHOULD on RFC 3986 §6.2.2/§6.2.3): strip
query and fragment, lowercase scheme and host, drop an explicitly-written
default port (`:443` for `https`), then compare byte-for-byte.

Deliberately **no** path normalisation beyond that: collapsing `..`
segments is a security-relevant transformation on a value used for an
equality check, and neither side of the comparison should contain them.

**Replay — `claim_dpop_jti`** (§11.1): namespace `dpop_jti`, key =
`base64url(SHA-256(jkt ‖ 0x00 ‖ normalized_htu ‖ 0x00 ‖ jti))`, written via
the atomic `insert_kv_if_absent`, with `expires_at = now + max_age_secs`.

Three deliberate choices:

- **Per target URI**, because §11.1 scopes single-use *"in the context of
  the target URI"*.
- **Per `jkt`**, so one wallet cannot pre-claim `jti` values and deny
  service to another — the same reasoning `claim_pop_jti`'s gotcha already
  records.
- **Hashed**, because §11.1 says to *"store only a hash thereof"* to bound
  memory against exhaustion attacks.

TTL equals the acceptance window, so the store self-purges to the size of
that window.

### 5.2 `POST /token`

```
1. §4.3 check 1 (single header)                      ← server.rs
2. Wallet Attestation + PoP jti claim                ← unchanged, still first
3. match (dpop.mode, dpop_header):
     (Disabled, _)          → jkt = None
     (Optional, None)       → jkt = None
     (Required, None)       → Err(InvalidDpopProof)          §5.2
     (Optional|Required, Some(p)) →
         verify_dpop_proof(p, "POST", "<issuer>/token", None, ...)?
         claim_dpop_jti(...)?                                 §11.1
         jkt = Some(proof.jkt)
4. grant handler (pre-auth or authorization_code):
     load tx
     if let Some(pinned) = tx.dpop_jkt {                      §10
         jkt == Some(pinned) or Err(InvalidDpopProof)
     }
     ...existing PKCE / tx_code / redirect_uri checks...
     invalidate the code                    ← still only after everything passes
5. mint_and_save_tokens(.., jkt):
     tx.dpop_jkt = jkt.clone()
     token_type = if jkt.is_some() { "DPoP" } else { "Bearer" }   §5
```

Two ordering invariants, both inherited from the existing code's reasoning
rather than invented here:

- Proof verification and `jti` claiming happen **before any grant work**, so
  a replayed or forged proof can never burn a legitimate holder's code.
- The §10 `dpop_jkt` comparison happens **after** the transaction loads but
  **before** the code is invalidated, for the same reason. This is why the
  verified `jkt` is threaded *into* the grant handlers rather than the
  comparison being hoisted out of them.

### 5.3 `POST /credential`

`server.rs` parses the scheme instead of hardcoding `strip_prefix("Bearer ")`:

```
scheme, token = parse_authorization(header)?         // "DPoP" | "Bearer" | else reject
ath            = base64url(SHA-256(token.as_bytes()))
→ handle_credential_request(.., DpopPresentation {
      scheme_is_dpop, proof_jwt, htm: "POST", htu: "<issuer>/credential", ath
  })
```

and inside, after `load_transaction_by_access_token`:

| `tx.dpop_jkt` | Presented scheme | Outcome |
|---|---|---|
| `None` | `Bearer` | accept — today's path, unchanged |
| `Some(jkt)` | `Bearer` | **reject** — §7.2: *"MUST reject a DPoP-bound access token received as a bearer token"* |
| `Some(jkt)` | `DPoP` + proof | verify with `expected_ath = Some(ath)`, claim `jti`, then `proof.jkt == jkt` or reject — §7.1 + §4.3 check 12 |
| `Some(_)` | `DPoP`, no proof | reject — §7 |
| `None` | `DPoP` | **reject** — deliberate deviation, see below |

Any scheme that is neither `DPoP` nor `Bearer` — and a header with no scheme
at all — is rejected before the transaction is even looked up, preserving the
current behaviour for malformed `Authorization` headers.

**Deliberate deviation (approved during design).** The last row is stricter
than RFC 9449, which leaves the case undefined. Accepting it would let a
wallet conclude it has sender-constraining when the token has no bound key
at all — the same false assurance §5's *"the client MUST discard the
response"* language exists to prevent. Fail-closed.

## 6. Error handling & security boundaries

### 6.1 Failure taxonomy

Every DPoP failure is a **structural / crypto** failure, never a policy
outcome — so every one is a 4xx with a typed error, and none produces a 200
with a failed-check record. Root `AGENTS.md` §4.3's split maps cleanly:
`verified: false`-style reporting belongs to the verifier crate's
presentation checks and has no analogue on the issuance side.

| Condition | `/token` | `/credential` |
|---|---|---|
| >1 `DPoP` header | 400 `invalid_dpop_proof` | 401 `invalid_token` |
| malformed JWT / bad `typ` / bad `alg` / bad signature | 400 | 401 |
| private key in `jwk` | 400 | 401 |
| `htm` / `htu` mismatch | 400 | 401 |
| `iat` outside window | 400 | 401 |
| `jti` replay | 400 | 401 |
| `mode: Required`, no header | 400 | — |
| `dpop_jkt` (§10) mismatch | 400 | — |
| `ath` mismatch | — | 401 |
| bound token, `Bearer` scheme (§7.2) | — | 401 |
| unbound token, `DPoP` scheme | — | 401 |

**One new variant**, `IssuanceError::InvalidDpopProof(String)`, with
`kind() == "invalid_dpop_proof"` — the code RFC 9449 §5 mandates and §12.2
registers.

One variant, not eleven: RFC 9449 defines exactly one error code for proof
failures, and the distinguishing detail belongs in the `Display` string, not
in the type. That `Display` text reaches `error_description`, so it must
name the *structural* defect (`"htu claim does not match the request URI"`)
and never echo the proof, the token, or key material.

**`/credential` 401 handling is scoped strictly to DPoP-related failures**
(§7.1's `WWW-Authenticate: DPoP error="invalid_token", algs="ES256"`). The
existing Bearer paths keep their current 400 mapping. `/credential`
returning 400 for a missing `Authorization` header is a pre-existing
question RFC 9449 does not reach; widening it here would break unrelated
tests for no conformance gain.

**No `.unwrap()` / `.expect()` / `panic!()`** anywhere in `dpop.rs` outside
`#[cfg(test)]` (root `AGENTS.md` §4.1): every decode, JSON access and
base64 step returns `InvalidDpopProof`.

**Logging (root `AGENTS.md` §4.5):** exactly one record per error, emitted
in `server.rs`'s mapper, never at the call site. Never logged: the proof
JWT, the access token, `ath`, `jti`. Logged: `error.kind`, and `jkt` —
already an RFC 7638 thumbprint, the one form §4.5 permits for public keys.
Any new `#[tracing::instrument]` carries `skip_all`.

### 6.2 What this achieves, and what it does not

**Achieved.** An access token is cryptographically bound to a key the wallet
proved possession of; a stolen token is useless without the private key (§6,
§7.1). A harvested authorization code cannot be redeemed under an attacker's
key when the wallet used `dpop_jkt` (§10, §11.9). A captured proof cannot be
replayed at the same endpoint within its window (§11.1), moved to a
different endpoint (`htm`/`htu`), or paired with a different access token
(`ath`, §11.5). A DPoP-bound token cannot be downgraded to Bearer usage
(§7.2).

**Not achieved, by decision.** Proof **pre-generation** (§11.2) remains
possible: an attacker controlling the wallet can mint proofs with future
`iat` values and exfiltrate them. The RFC's only real defence is the
server-provided nonce, deferred per §2.2. Its named compensating control —
*"prefer instead to use short-lived access tokens"* — holds here: foundry's
are fixed at 600 s and never renewable (no refresh tokens, no `/token`
re-redemption; the transaction flips to `Issued` and is single-use). This is
recorded in the conformance report as a MAY-not-implemented row with exactly
this reasoning, not as a silent omission.

**Deliberately absent.** Refresh-token binding (§5) — foundry issues none.
PAR interaction (§10.1) — no `/par` endpoint (`HAIP-0007`, separately
`ambiguous`). Introspection (§6.2) — no remote resource server. Each becomes
a one-line conformance row rather than an unexplained gap.

## 7. Testing strategy

### 7.1 Unit — `dpop.rs`

One shared helper, modelled on `token.rs`'s existing `pop_jwt_for`:

```rust
fn dpop_proof(kp: &EcKeyPair, htm: &str, htu: &str,
              iat: i64, jti: &str, ath: Option<&str>) -> String
```

so every negative case is one mutated argument from the happy path rather
than a hand-rolled JWT per test.

A test per §4.3 check, each asserting rejection:

| Test | Covers |
|---|---|
| `valid_proof_yields_the_rfc7638_thumbprint` | happy path; **known-answer** against RFC 9449 Figure 9's published `jkt` for the Figure 2 key — asserts against the RFC's own vector, not our output |
| `rejects_a_non_jwt_string`, `rejects_a_two_part_jws` | check 2 |
| `rejects_missing_jti` / `_htm` / `_htu` / `_iat` | check 3 |
| `rejects_wrong_typ` | check 4 |
| `rejects_alg_none`, `rejects_symmetric_alg` | check 5 |
| `rejects_a_bad_signature`, `rejects_a_signature_by_another_key` | check 6 |
| `rejects_a_jwk_carrying_a_private_key` | check 7 |
| `rejects_htm_mismatch` | check 8 |
| `rejects_htu_mismatch`, `accepts_htu_differing_only_by_query`, `accepts_htu_differing_only_by_default_port_or_case` | check 9 + normalisation |
| `rejects_iat_too_old`, `rejects_iat_too_far_in_future`, `accepts_iat_within_skew_window` | check 11 |
| `rejects_ath_mismatch`, `rejects_missing_ath_when_expected` | check 12 |
| `a_replayed_jti_is_rejected`, `the_same_jti_at_a_different_htu_is_accepted`, `two_wallets_may_use_the_same_jti` | §11.1 keying |

That last trio is the highest-value review target: it is the difference
between a correct replay store and one that either admits replays or lets
one wallet deny service to another.

### 7.2 Unit — `token.rs`

A 3×2 mode matrix, mirroring the 9-row attestation matrix in
`attestation.rs`:

| mode | no header | valid proof |
|---|---|---|
| `Disabled` | `Bearer`, `tx.dpop_jkt == None` | `Bearer`, ignored, **not** rejected |
| `Optional` | `Bearer` | `DPoP`, `tx.dpop_jkt == Some(jkt)` |
| `Required` | `InvalidDpopProof` | `DPoP` |

Plus, on both grant branches:

- `dpop_jkt_pinned_at_authorize_must_match_the_proof_at_token` (§10 happy
  path)
- `mismatched_dpop_jkt_is_rejected` (§10 MUST)
- `mismatched_dpop_jkt_does_not_burn_the_authorization_code` — the ordering
  invariant from §5.2 *of this document*; a direct analogue of the existing
  `wrong_tx_code_does_not_burn_the_pre_authorized_code` and
  `pop_replay_rejection_does_not_burn_the_pre_authorized_code`
- `an_invalid_dpop_proof_does_not_burn_the_pre_authorized_code`
- `pre_authorized_code_regression_still_passes_without_dpop` — the existing
  no-DPoP tests must stay green untouched, which is the real guarantee that
  the defaults are backward-compatible

### 7.3 Unit — `credential.rs`

One test per row of the §5.3 table:
`bound_token_presented_as_bearer_is_rejected` (§7.2),
`bound_token_with_matching_proof_is_accepted`,
`bound_token_with_another_keys_proof_is_rejected`,
`bound_token_without_a_proof_is_rejected`,
`unbound_token_with_dpop_scheme_is_rejected` (the §5.3 deviation),
`unbound_token_with_bearer_is_accepted` (regression).

### 7.4 Integration — `crates/foundry/tests/`

- **`wallet_issuance.rs`** — one full `mode: Optional` DPoP flow: `/token`
  with a proof ⇒ `DPoP` token type ⇒ `/credential` with
  `Authorization: DPoP` plus a fresh proof carrying `ath` ⇒ credential
  issued. This is the only test exercising real Axum header handling, and
  therefore the only place §4.3 check 1 (duplicate `DPoP` headers) can be
  tested at all.
- **`wallet_metadata.rs`** — `dpop_signing_alg_values_supported == ["ES256"]`
  when enabled, absent under `Disabled` (§5.1).
- **`conformance_vci.rs`** — `haip_0009_token_response_uses_dpop_token_type`
  un-ignored and **rewritten**: it currently asserts `token_type == "DPoP"`
  for a request carrying no DPoP header, which §5 says must be `Bearer`. The
  name is kept (the conformance report cites it); the body is corrected. New
  rows added for the RFC 9449 clauses.
- **`instrumentation_hygiene.rs`**, **`logging_redaction.rs`** — structural
  and behavioural scanners, so they cover `dpop.rs` automatically once it
  exists: `skip_all` on any new instrument, and a positive control proving
  the proof JWT never reaches a log line.
- **`e2e_full_flow.rs`** — left alone. It runs the default config, which is
  `Optional` with no proof ⇒ Bearer ⇒ unchanged. Adding a DPoP variant would
  double the slowest suite in the repository to re-test what §7.4's
  `wallet_issuance.rs` case already covers.

### 7.5 Gates

`foundry-core` (config model) and `foundry-issuer` are touched, and
`foundry` consumes both, so the scoped gate per root `AGENTS.md` §5.1–5.2 is:

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```

The full gate of §5.3 (including the `--ignored` E2E suite) runs **once**, at
the end of the branch, before the final review — not per task.

## 8. Documentation to update

Closing a gap means updating the record, not only the code (root
`AGENTS.md` §8):

- **`docs/conformance/openid4vc-conformance.md`**
  - `HAIP-0009`: `gap` → `conforming`, evidence rewritten, test named.
  - Gap register: the `GAP-HAIP-03` row is **removed**.
  - Summary table: HAIP `gap` 2 → 1, `conforming` 53 → 54.
  - `VCI-0163` (long-lived tokens MUST be sender-constrained): currently
    `conforming` by vacuous precondition with a note pointing at
    `GAP-HAIP-03`. That note now dangles — the evidence must be rewritten to
    say the requirement is satisfied *substantively*.
  - New rows for the RFC 9449 clauses foundry now implements or knowingly
    declines. RFC 9449 is not one of the three inventoried specs, so per the
    report's own stated convention these are appended rather than renumbered
    into an existing sequence.
- **Root `AGENTS.md` §4.4** — add the `rfc9449-dpop.txt` row to the
  pinned-spec table (the file is checked in but unlisted), worded like the
  ABCA draft row: it governs `foundry-issuer`'s `dpop.rs`, the `/token`
  route, and the `/credential` route.
- **`crates/foundry-issuer/AGENTS.md`** — `dpop.rs` in the module map; the
  updated `handle_token_request` signature row; gotchas for the
  `Disabled`-ignores-rather-than-rejects choice, the dual-purpose
  `dpop_jkt` field, and the §5.3 deviation.
- **`openapi.json`** — regenerated (§4.5).
- **`README.md`** — the new `issuer.dpop` config block.
- **`docs/superpowers/changes/2026-08-03-dpop-sender-constrained-tokens.md`**
  — change record, written at the end of the cycle.