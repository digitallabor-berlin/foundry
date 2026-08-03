# GAP-VCI-14 — Client Attestation PoP JWT Verification

> Migrated from `docs/superpowers/specs/2026-08-01-gap-vci-14-client-attestation-pop-spec.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Date:** 2026-08-01
**Status:** approved

## Problem

`handle_token_request` (crates/foundry-issuer/src/token.rs) and
`validate_wallet_attestation_jwt` (crates/foundry-issuer/src/attestation.rs)
fully validate the `OAuth-Client-Attestation` JWT itself — signature, `x5c`
chain against configured trust anchors, `exp`/`nbf`, and the presence and
parseability of `cnf.jwk` and `sub`. That work landed on 2026-08-01 while
closing GAP-HAIP-04.

Nothing in this workspace reads the paired `OAuth-Client-Attestation-PoP`
header. `handle_token_request` has no parameter for one. Consequently a Wallet
Attestation JWT captured off the wire — or lifted from a compromised log, or
replayed from an earlier request — is accepted **identically to a legitimate
one**, with no proof whatsoever that the presenter holds the private key the
attestation's `cnf.jwk` attests to.

This is the entire security purpose of the Client Attestation PoP JWT. Without
it, the wallet-attestation mechanism authenticates the *Wallet Provider* (whose
CA signed the attestation) but not the *Wallet Instance* presenting it.

The gap is tracked as **GAP-VCI-14** (Important) in
`docs/conformance/openid4vc-conformance.md`, with clause **VCI-0232**
(`gap`) and **HAIP-0088** (`gap`) citing it, and a genuinely-red `#[ignore]`d
test `vci_0232_wallet_attestation_pop_jwt_is_never_verified` in
`crates/foundry-issuer/tests/conformance_vci.rs`.

## Goal / Non-Goals

### Goal

Verify the Client Attestation PoP JWT at `POST /token`, per
Attestation-Based Client Authentication draft -07 §5.2, §6.2, §6.3 and §9,
including replay detection via a `jti` store bounded by an `iat` sliding
window (§10.6, §12.1).

Closing this gap means:

- VCI-0232 `gap` → `conforming`
- HAIP-0088 `gap` → `conforming`
- The GAP-VCI-14 register row is deleted (register: **21 rows → 20**, counted
  from the current file, not from an older document)
- The `#[ignore]` is removed from the test that cites the gap ID

### Non-Goals

Deliberately out of scope, each its own future item:

- **ABCA §10.1 — Authorization Server metadata advertisement.**
  `attest_jwt_client_auth` in `token_endpoint_auth_methods_supported` plus the
  two `client_attestation*_signing_alg_values_supported` arrays. It is
  all-or-nothing (§10.1 makes the alg arrays a MUST once the method is
  advertised) and is a metadata concern, not a verification one.
- **Wallet-side PoP generation** in `foundry-wallet`. Requires a CA-chained
  attestation fixture and config to hold it — a second subsystem.
- **ABCA §8 — the challenge endpoint** and the `challenge` claim. OPTIONAL in
  the draft; the `jti` mechanism is the mandatory fallback (§12.1: "The `jti`
  value is mandatory and hence acts as a default fallback").
- **PAR.** foundry exposes no Pushed Authorization Request endpoint, so ABCA
  §6.4 has no surface to bind to.

### Not applicable

- **ABCA §10.3 — refresh token binding.** Verified, not assumed: `TokenResponse`
  carries only `access_token`, `token_type`, `expires_in`, and the string
  `refresh_token` appears nowhere in the workspace. foundry issues no refresh
  tokens, so there is nothing to bind.

## Approach

### Chosen

A pure, synchronous verification function plus a separate storage-backed replay
claim, wired into the attestation step that `handle_token_request` already
performs.

Verification (all cryptographic and claim checks) stays sync and takes no
`Storage`; the `jti` claim is a distinct `.await`ed step in `token.rs`. This
keeps `foundry-core`'s storage out of the verifier, avoids making
`WalletAttestationVerifier` an async trait, and lets every crypto check be
unit-tested without a database.

### Rejected alternatives

| Alternative | Why rejected |
|---|---|
| **Do not vendor ABCA draft -07**; implement from the OpenID4VCI reference plus recall | AGENTS.md §4.4 forbids inferring wire format "from existing code, other implementations, or memory". The PoP JWT's entire normative definition lives in the draft; without the text a reviewer cannot check any claim. |
| **`aud` escape hatch** (`additional_pop_audiences` config) for wallets that send the token endpoint URL | Speculative — no wallet has broken on it here, and foundry's own debug wallet sends neither header. Cheap to add the day one does. |
| **Lenient `aud`** (accept issuer identifier *or* `<issuer>/token`) | Silently non-conformant and undetectable by foundry itself. |
| **Get-then-put `jti` dedup** via the existing `put_kv` (the `status_index.rs` pattern) | `put_kv` is an upsert (`ON CONFLICT … DO UPDATE`), so get-then-put has a TOCTOU window: two concurrent replays of the same PoP both observe "absent" and are both accepted. Tolerable for a dedup counter; fatal for the anti-replay control this gap is about. |
| **In-memory `Mutex<HashMap>` jti store** | Atomic for free, but replay protection evaporates on restart and never existed across two instances. Wrong layer for a security control. |
| **No `jti` store; rely solely on the `iat` window** | §12.1 is a SHOULD, so arguably conformant — but a captured PoP would replay freely for the whole window, which is precisely the attack GAP-VCI-14 was filed about. |
| **Separate `pop_mode` config knob** (required/optional/disabled) for staged rollout | Makes "attestation required, PoP disabled" an expressible configuration — exactly the unauthenticated-attestation state this work eliminates. |
| **PoP enforced only in `Mode::Required`** | A malformed header pair would be silently downgraded to "unattested" rather than rejected, contradicting §6.2's "exactly one of each". |
| **Keep `invalid_request` as the error code** | RFC 6749 §5.2 makes a client-authentication failure `invalid_client`. Reporting it as a malformed-request error is wrong and would be a fair audit finding. |
| **Emit `invalid_client_attestation`** (ABCA §6.2) | A MAY with no consumer in this workspace, and the JSON `error` field holds one value — so "in addition to `invalid_client`" collapses to "instead of". |
| **Async `WalletAttestationVerifier` trait** taking `&dyn Storage` | Drags storage into the verifier and forces a DB for every crypto unit test, for no gain over a separate claim step. |

## Design

### Data flow

```
POST /token
  ├─ server.rs reads  OAuth-Client-Attestation
  │                   OAuth-Client-Attestation-PoP
  │             expected_aud = build_authorization_server_metadata(cfg).issuer
  ↓
handle_token_request(storage, req, wallet_attestation, attestation_header,
                     pop_header, issuer_identifier, now_unix)
  ├─ verify_wallet_attestation(...)          ── sync, pure ──→ Option<PopClaims>
  │    ├─ validate_wallet_attestation_jwt    → ValidatedAttestation { sub, cnf_jwk }
  │    └─ validate_client_attestation_pop_jwt(pop, &attestation,
  │                                           expected_aud, now, max_age)
  ├─ claim_pop_jti(storage, &pop_claims, max_age).await  ← atomic; replay rejected
  ├─ §6.3 client_id cross-check
  └─ existing grant handling — unchanged
```

The expected audience is taken from `build_authorization_server_metadata(cfg).issuer`
rather than re-derived from config, so the value foundry **publishes** at
`/.well-known/oauth-authorization-server` and the value it **checks** cannot
drift apart.

### Vendored specification

`docs/specs/draft-ietf-oauth-attestation-based-client-auth-07.txt` — the IETF
text, verbatim, becomes a fourth pinned spec with its own row in the AGENTS.md
§4.4 table. It stays `.txt` where the other three are `.md`: verbatim fidelity
is the point of a pinned spec, and reformatting would undermine it.

Version pin rationale: OpenID4VCI 1.0 L1600 names "Attestation-Based Client
Authentication draft **-07**" explicitly. That is the version foundry
implements.

### `foundry-core` changes

**`Storage::insert_kv_if_absent`**

```rust
async fn insert_kv_if_absent(
    &self,
    namespace: &str,
    key: &str,
    value: &str,
    expires_at: Option<i64>,
) -> Result<bool, StorageError>;
```

SQLite implementation: `INSERT INTO kv (namespace, key, value, expires_at)
VALUES (?1, ?2, ?3, ?4) ON CONFLICT(namespace, key) DO NOTHING`, returning
`rows_affected() == 1`. `true` = the caller claimed the key; `false` = it was
already held.

`put_kv`'s upsert semantics are unchanged — existing callers are unaffected.
`SqliteStorage` is the only implementor of `Storage` in the workspace.

**`AttestationMode.pop_max_age_secs: u64`**, `#[serde(default)]` = **300**.

`AttestationMode` is shared by `issuer.wallet_attestation` and
`issuer.key_attestation`; this field is consulted only for the former, and
carries a doc comment saying so.

### `foundry-issuer/src/attestation.rs`

**`ValidatedAttestation { sub: String, cnf_jwk: Jwk }`** — returned by
`validate_wallet_attestation_jwt`, whose signature changes from
`Result<(), IssuanceError>` to `Result<ValidatedAttestation, IssuanceError>`.
Both values are already parsed and discarded today; the existing code comment
says they are kept "available for a future PoP implementation (GAP-VCI-14)".

**`PopClaims { iss: String, jti: String, iat: i64 }`** — returned by the new
validator, consumed by the replay claim.

**`validate_client_attestation_pop_jwt(pop_jwt, &ValidatedAttestation,
expected_aud, now_unix, max_age_secs) -> Result<PopClaims, IssuanceError>`**

Every check cites its clause in a code comment:

| # | Check | Clause |
|---|---|---|
| 1 | Exactly three dot-separated parts; base64url-decodable header and payload | ABCA §5.2 / RFC 7519 |
| 2 | Header `typ == "oauth-client-attestation-pop+jwt"` | ABCA §5.2 |
| 3 | Header `alg == "ES256"` — a registered asymmetric algorithm, not `none` | ABCA §9 rule 4; HAIP-0088 |
| 4 | Signature verifies against the attestation's `cnf.jwk` | ABCA §5.2 r3, §6.2 rule 3, §9 rule 7 |
| 5 | `iss` present, non-empty, equals the attestation's `sub` | ABCA §5.2 r4, §9 rule 13 |
| 6 | `aud` present; string **or** array; equals / contains `expected_aud` exactly | ABCA §5.2, §9 rule 10 |
| 7 | `jti` present, a non-empty string | ABCA §5.2 |
| 8 | `iat` present, an integer; `now - iat <= max_age_secs`; `iat <= now + SKEW` | ABCA §9 rule 9, §10.6, §12.1 |
| 9 | `nbf`, if present, `<= now + SKEW` | ABCA §5.2 |

`POP_CLOCK_SKEW_SECS: i64 = 60`, a named constant citing §12.1's "clock skews
between servers and clients may be large".

Note there is **no `exp` check** — ABCA removed `exp` from the PoP JWT in
draft -06. Freshness is entirely the `iat` sliding window. A PoP carrying an
`exp` is not rejected for it (§5.2 r1: "The JWT MAY contain other claims. All
claims that are not understood by implementations MUST be ignored").

**`claim_pop_jti(storage, &PopClaims, max_age_secs) -> Result<(), IssuanceError>`**

(No `now_unix` parameter: the TTL is derived from the PoP's own `iat`, which
`validate_client_attestation_pop_jwt` has already bounded against `now`.)

- Namespace: `client_attestation_pop_jti`
- Key: base64url-no-pad of `SHA-256(iss ‖ 0x00 ‖ jti)`
- Value: `"1"`
- `expires_at`: `iat + max_age_secs + POP_CLOCK_SKEW_SECS`
- `insert_kv_if_absent` returning `false` ⇒ replay ⇒ `InvalidClient`

Keying on `(iss, jti)` rather than `jti` alone is deliberate: a bare-`jti`
namespace would let one wallet pre-claim `jti` values and deny service to
another. Hashing keeps an attacker-controlled string out of the SQL key and out
of any log line.

Ordering matters: the `iat` window (check 8) is evaluated **before** the store
is consulted. `get_kv`/`insert_kv_if_absent` do not filter on `expires_at` —
expiry is enforced only by the background sweeper (`server.rs`) — so a
lingering row can only ever over-reject. Checking the window first means a
lingering row can never reject a *fresh* PoP, since a fresh PoP carries a fresh
`jti` (§5.2: `jti` MUST be a unique identifier).

**`verify_wallet_attestation`** gains `pop_header: Option<&str>`,
`expected_aud: &str`, `max_age_secs: u64`, and returns
`Result<Option<PopClaims>, IssuanceError>`:

| `Mode` | Attestation | PoP | Outcome |
|---|---|---|---|
| `Disabled` | any | any | `Ok(None)` — no checks, unchanged |
| `Required` | absent | any | reject — attestation required |
| `Required` | present | absent | reject — ABCA §6.2 rule 2 |
| `Required` | present | present | both validated → `Ok(Some(claims))` |
| `Optional` | absent | absent | `Ok(None)` |
| `Optional` | absent | present | reject — no `cnf` key to verify against |
| `Optional` | present | absent | reject — ABCA §6.2 rule 2 |
| `Optional` | present | present | both validated → `Ok(Some(claims))` |

### `foundry-issuer/src/token.rs`

`handle_token_request` gains two parameters — `pop_header: Option<&str>` and
`issuer_identifier: &str` — bringing it to seven. There are 28 call sites,
nearly all in `crates/foundry-issuer/tests/conformance_vci.rs`; adapting them is
mechanical.

After a successful verification returning `Some(claims)`:

1. `claim_pop_jti(...)` — replay rejected here.
2. **ABCA §6.3 `client_id` cross-check:** if `req.client_id` is `Some(id)`, then
   `id` MUST equal the attestation's `sub` **and** the PoP's `iss`. (Those two
   are already known equal from check 5, but both comparisons are asserted
   because the spec names both.)

### `foundry-issuer/src/error.rs`

New variant `InvalidClient(String)`, `#[error("invalid client: {0}")]`, with
`kind()` returning `"invalid_client"`. The `kind()` match is deliberately
exhaustive with no catch-all, so the new variant is a compile error until its
arm is added; the `kind_is_a_stable_name_for_every_variant` test gains a case.

All wallet-attestation and PoP failures move from `InvalidRequest` to
`InvalidClient` — approximately 30 sites in `attestation.rs`.

### `foundry/src/server.rs`

- Read `OAuth-Client-Attestation-PoP` alongside the existing header. Axum's
  `HeaderMap` lookup is already case-insensitive, satisfying ABCA §6.1's
  RFC 9110 note.
- Pass `build_authorization_server_metadata(&state.config).issuer` as
  `issuer_identifier`.
- `wallet_error_response`: `InvalidClient(_) => (StatusCode::BAD_REQUEST, "invalid_client")`.

### Error handling

Every attestation and PoP failure returns `IssuanceError::InvalidClient` →
HTTP **400** with `{"error": "invalid_client", "error_description": …}`.

This is a policy/authentication rejection, not a structural fault, and it is
logged exactly once — inside `wallet_error_response`, never at the call site
(AGENTS.md §4.5). `warn` level, consistent with the existing "wallet attestation
rejected" record.

### Observability (AGENTS.md §4.5)

- Every new `#[tracing::instrument]` carries `skip_all`. The arguments are the
  attestation JWT, the PoP JWT, and the `cnf` JWK.
- **Never logged:** the PoP JWT, the attestation JWT, the raw `jti`, the raw
  `iss`, the `cnf` JWK. A key is logged only as an RFC 7638 thumbprint via
  `foundry_core::obs::thumbprint`.
- One new span field on `handle_token_request`: `pop_present: bool`, alongside
  the existing `wallet_attestation_present`.
- The storage key is a hash, so it is safe to appear in a storage-layer error;
  the inputs to that hash are not logged.

## Global Constraints

- **Spec pin:** Attestation-Based Client Authentication **draft -07**, as named
  by OpenID4VCI 1.0 L1600. The checked-in `docs/specs/` copy is the source of
  truth, not any newer draft found online.
- **Signature algorithm:** `ES256` only, for both the attestation JWT and the
  PoP JWT. HAIP-0088 mandates ES256 support; ES256 is the only JWS algorithm
  this workspace signs or verifies.
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
- **No panics in request paths** (AGENTS.md §4.1): no `.unwrap()`,
  `.expect()`, `panic!()` or `unreachable!()` outside `#[cfg(test)]`.
- **`skip_all` on every `#[tracing::instrument]`** (AGENTS.md §4.5).
- **Dependency layering** (AGENTS.md §3): `foundry-core` gains no dependency on
  any `foundry-*` crate. No new third-party dependencies at all — `sha2` and
  `base64` are already dependencies of `foundry-issuer`.

## Testing Strategy

TDD throughout: one failing test per behaviour, verified failing *for the right
reason*, then minimal implementation.

### The gap test

`vci_0232_wallet_attestation_pop_jwt_is_never_verified` is un-`#[ignore]`d and
**renamed** — its current name asserts the bug rather than the requirement. New
name: `vci_0232_rejects_a_wallet_attestation_presented_without_a_pop_jwt`. The
two conformance-register rows that cite the old name (VCI-0232, HAIP-0088) are
updated in the same task.

### `foundry-core`

- `insert_kv_if_absent` returns `true` on first call, `false` on second for the
  same `(namespace, key)`.
- A `false` return leaves the stored value and `expires_at` untouched (it is
  `DO NOTHING`, not an upsert).
- `insert_kv_if_absent` and `put_kv` do not interfere across namespaces.

### `foundry-issuer` — PoP validation

Happy path, then one test per rejection:

- valid PoP accepted (happy path)
- `typ` absent / wrong
- `alg: none`
- `alg: HS256` with a genuinely HS256-signed JWT (proves the check is enforced
  by attempted verification, not assumed)
- signature made by a key other than the attestation's `cnf.jwk`
- `iss` absent; `iss` present but ≠ attestation `sub`
- `aud` absent; `aud` wrong; `aud` array **containing** the issuer identifier
  (accept); `aud` array **not** containing it (reject)
- `jti` absent; `jti` empty string
- `iat` absent; `iat` non-integer
- `iat` older than `pop_max_age_secs` (reject)
- `iat` more than `POP_CLOCK_SKEW_SECS` in the future (reject)
- `iat` slightly in the future, within skew (accept)
- `nbf` in the future beyond skew (reject)
- unknown extra claim present (accept — §5.2 r1)

### `foundry-issuer` — replay

- the same PoP presented twice: first accepted, second rejected
- a second PoP with a **different** `jti`, same `iss`: accepted
- the same `jti` under a **different** `iss`: accepted (proves `(iss, jti)`
  keying, not bare `jti`)

### `foundry-issuer` — mode matrix and `client_id`

- all eight rows of the `Mode` × attestation × PoP table above
- `req.client_id` present and matching: accepted
- `req.client_id` present and mismatched: rejected (ABCA §6.3)
- `req.client_id` absent: accepted

### HTTP level

- a token request failing PoP verification returns HTTP 400 with
  `{"error": "invalid_client"}`

### Verification gates

`cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
and `cargo fmt --check` must all pass before the work is complete
(AGENTS.md §5).

## Open Questions

None.
