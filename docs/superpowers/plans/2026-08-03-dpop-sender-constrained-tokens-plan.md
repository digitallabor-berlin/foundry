# DPoP Sender-Constrained Access Tokens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close `GAP-HAIP-03` by implementing RFC 9449 DPoP so foundry's OpenID4VCI access tokens can be sender-constrained to a wallet-held key.

**Architecture:** A new `crates/foundry-issuer/src/dpop.rs` owns all of RFC 9449 §4.2/§4.3 proof validation and §11.1 replay defence. Two thin call sites consume it — `handle_token_request` (binds the key, sets `token_type: "DPoP"`, enforces §10 `dpop_jkt`) and `handle_credential_request` (verifies the presented proof against the token's bound key). The binding itself is an RFC 7638 thumbprint stored on `IssuanceTransaction`, which is RFC 9449 §6's explicitly-permitted third mechanism — valid here because the authorization server and the resource server are one process sharing one `Storage`.

**Tech Stack:** Rust, `josekit` (ES256 JWS), `sha2`, `base64`, `serde_json`, `axum`, `utoipa`, `tokio`.

**Design spec:** [`docs/superpowers/specs/2026-08-03-dpop-sender-constrained-tokens-design.md`](../specs/2026-08-03-dpop-sender-constrained-tokens-design.md)
**Pinned protocol text:** [`docs/specs/rfc9449-dpop.txt`](../../specs/rfc9449-dpop.txt)

## Global Constraints

Every task's requirements implicitly include this section.

- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside `#[cfg(test)]` in `foundry-issuer` or `foundry::server`. Return typed `IssuanceError`. (root `AGENTS.md` §4.1)
- **Every `#[tracing::instrument]` MUST carry `skip_all`.** Enforced by `crates/foundry/tests/instrumentation_hygiene.rs`. (root `AGENTS.md` §4.5)
- **Never log**, at any level: the DPoP proof JWT, the access token, `ath`, `jti`, or any private key parameter. `jkt` IS loggable — it is already an RFC 7638 thumbprint. (root `AGENTS.md` §4.5)
- **Exactly one log record per typed error**, emitted in `crates/foundry/src/server.rs`'s error mapper — never at the call site, never nowhere. (root `AGENTS.md` §4.5)
- **Cite the spec in every new protocol code path**, e.g. `// RFC 9449 §4.3 check 8 — htm claim`. (root `AGENTS.md` §4.4)
- **`alg` allowlist is `ES256` and nothing else.** HAIP's crypto-suites section mandates it and it is what `josekit` is wired for throughout `foundry-issuer`.
- **Saturating arithmetic on every wire-sourced timestamp.** `iat` arrives off the wire and `max_age_secs` is a `u64` from config: use `i64::try_from(max_age_secs).unwrap_or(i64::MAX)` and `saturating_sub`/`saturating_add`. A bare `+`/`-` panics under the dev profile's `overflow-checks = true` (violating §4.1) or silently wraps in release, which disables the freshness window entirely. Copy the reasoning already documented in `attestation.rs`'s `iat` bounds check.
- **Scoped gate only** (root `AGENTS.md` §5.1–5.2). After each task:
  ```bash
  cargo test -p foundry-core -p foundry-issuer -p foundry
  cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
  cargo fmt --check
  ```
  **Never** run `cargo test --workspace` between tasks. Narrow with `-p <crate>` / `--test <file>` while iterating. Tasks 1–5 touch only `foundry-core`/`foundry-issuer` and may drop `-p foundry` until Task 6.
- **Do not run the E2E suite** (`e2e_full_flow`, `#[ignore]`d) in any per-task gate. It belongs to the one-time Full Gate at the end (Task 10).

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `crates/foundry-core/src/config/model.rs` | Modify | `DpopConfig` struct; `IssuerConfig.dpop` field |
| `crates/foundry-core/src/config/validate.rs` | Modify | reject `max_age_secs == 0` |
| `crates/foundry-issuer/src/dpop.rs` | **Create** | RFC 9449 §4.2/§4.3 validation, `htu` normalisation, §11.1 replay claim |
| `crates/foundry-issuer/src/lib.rs` | Modify | declare + re-export the `dpop` module |
| `crates/foundry-issuer/src/error.rs` | Modify | `InvalidDpopProof` variant + `kind()` arm |
| `crates/foundry-issuer/src/transaction.rs` | Modify | `dpop_jkt` field |
| `crates/foundry-issuer/src/authorize.rs` | Modify | accept `dpop_jkt`, persist on tx (§10 producer) |
| `crates/foundry-issuer/src/token.rs` | Modify | mode matrix, §10 enforcement, `token_type` |
| `crates/foundry-issuer/src/credential.rs` | Modify | §6/§7 presentation checks |
| `crates/foundry-issuer/src/metadata.rs` | Modify | `dpop_signing_alg_values_supported` (§5.1) |
| `crates/foundry/src/server.rs` | Modify | header extraction, `ath`, scheme parsing, 401 mapping |
| `crates/foundry/src/openapi.rs` | Modify | annotate the new header/param |
| `crates/foundry/tests/wallet_issuance.rs` | Modify | full DPoP flow, duplicate-header case |
| `crates/foundry/tests/wallet_metadata.rs` | Modify | §5.1 metadata assertions |
| `crates/foundry-issuer/tests/conformance_vci.rs` | Modify | un-ignore + rewrite `haip_0009_*` |
| `docs/conformance/openid4vc-conformance.md` | Modify | close `HAIP-0009`, drop `GAP-HAIP-03` |
| `AGENTS.md`, `crates/foundry-issuer/AGENTS.md`, `README.md` | Modify | §4.4 spec row, module map, config docs |
| `openapi.json`, `openapi-wallet.json` | Regenerate | root `AGENTS.md` §6 |

---

## Task 1: `DpopConfig` in `foundry-core`

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs`
- Modify: `crates/foundry-core/src/config/validate.rs`
- Test: inline `#[cfg(test)]` in both

**Interfaces:**
- Consumes: the existing `foundry_core::config::Mode` enum (`Required` | `Optional` | `Disabled`, `#[default] Optional`).
- Produces: `foundry_core::config::DpopConfig { mode: Mode, max_age_secs: u64 }`, reachable as `cfg.issuer.dpop`. Tasks 7, 8 and 9 read it.

This task is config plumbing only — no behaviour changes anywhere. It is separated so a reviewer can confirm the **defaults preserve current behaviour** before any request path moves.

- [ ] **Step 1: Write the failing test**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-core/src/config/model.rs`:

```rust
#[test]
fn dpop_defaults_to_optional_mode_and_a_300_second_window() {
    // RFC 9449 §5 permits Bearer when no proof is presented, so the default
    // must be the mode that preserves foundry's pre-DPoP behaviour.
    let cfg: DpopConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(cfg.mode, Mode::Optional);
    assert_eq!(cfg.max_age_secs, 300);
}

#[test]
fn issuer_config_without_a_dpop_block_still_deserializes() {
    // Every config file in the wild predates this field.
    let json = serde_json::json!({
        "credential_issuer": "https://issuer.example.com",
        "status_list": { "enabled": false }
    });
    let issuer: IssuerConfig = serde_json::from_value(json).unwrap();
    assert_eq!(issuer.dpop.mode, Mode::Optional);
    assert_eq!(issuer.dpop.max_age_secs, 300);
}

#[test]
fn dpop_mode_deserializes_from_lowercase() {
    let cfg: DpopConfig =
        serde_json::from_str(r#"{"mode":"required","max_age_secs":60}"#).unwrap();
    assert_eq!(cfg.mode, Mode::Required);
    assert_eq!(cfg.max_age_secs, 60);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p foundry-core --lib config::model 2>&1 | tail -20`
Expected: FAIL — `cannot find type DpopConfig in this scope`.

- [ ] **Step 3: Add `DpopConfig` and the `IssuerConfig` field**

In `crates/foundry-core/src/config/model.rs`, add the field to `IssuerConfig`:

```rust
pub struct IssuerConfig {
    pub credential_issuer: String,
    #[serde(default)]
    pub wallet_attestation: AttestationMode,
    #[serde(default)]
    pub key_attestation: AttestationMode,
    pub status_list: StatusListConfig,
    /// RFC 9449 (DPoP) — sender-constrained access tokens. Absent means
    /// `Optional`, which reproduces foundry's pre-DPoP behaviour exactly.
    #[serde(default)]
    pub dpop: DpopConfig,
}
```

and the new struct immediately after `AttestationMode`'s `default_pop_max_age_secs`:

```rust
/// RFC 9449 DPoP policy for the Token and Credential Endpoints.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct DpopConfig {
    /// RFC 9449 §5 / §5.2.
    ///
    /// - `Optional` (default) — a valid `DPoP` proof yields a key-bound token
    ///   and `token_type: "DPoP"`; its absence yields `Bearer`, exactly as
    ///   before DPoP existed.
    /// - `Required` — equivalent to §5.2's `dpop_bound_access_tokens: true`:
    ///   a token request with no `DPoP` header is rejected.
    /// - `Disabled` — the header is **ignored** and `Bearer` is always issued.
    ///   Deliberately *not* "reject": §10.1 encourages clients that blindly
    ///   attach `DPoP` to every AS call, and §5 states an AS "MAY elect to
    ///   issue access tokens that are not DPoP bound, which is signaled to the
    ///   client with a value of `Bearer`". Rejecting would hard-fail a wallet
    ///   doing exactly what the RFC recommends.
    #[serde(default)]
    pub mode: Mode,
    /// RFC 9449 §4.3 check 11 / §11.1: how far from `now` a proof's `iat` may
    /// sit, in **either** direction — §11.1 explicitly permits accepting an
    /// `iat` "in the reasonably near future" to absorb clock skew.
    #[serde(default = "default_dpop_max_age_secs")]
    pub max_age_secs: u64,
}

fn default_dpop_max_age_secs() -> u64 {
    300
}
```

`Default` derive gives `mode: Mode::Optional` (that enum's own `#[default]`) but `max_age_secs: 0`, which is wrong. Implement it explicitly instead of deriving:

```rust
impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            max_age_secs: default_dpop_max_age_secs(),
        }
    }
}
```

and drop `Default` from the `derive` list on `DpopConfig`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p foundry-core --lib config::model 2>&1 | tail -20`
Expected: PASS (3 new tests).

> If `issuer_config_without_a_dpop_block_still_deserializes` fails on a *different* missing field, the `IssuerConfig` literal in the test needs whatever `StatusListConfig` requires — add `"list_size": null` etc. Do not add `#[serde(default)]` to unrelated fields to make it pass.

- [ ] **Step 5: Write the failing validation test**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-core/src/config/validate.rs`, following the existing tests' `Config` construction pattern in that file:

```rust
#[test]
fn a_zero_dpop_max_age_is_rejected() {
    let mut cfg = test_config();
    cfg.issuer.dpop.max_age_secs = 0;
    let err = cfg.validate().expect_err("max_age_secs 0 must be rejected");
    assert!(
        err.to_string().contains("issuer.dpop.max_age_secs"),
        "error must name the offending field, got: {err}"
    );
}

#[test]
fn a_nonzero_dpop_max_age_validates() {
    let mut cfg = test_config();
    cfg.issuer.dpop.max_age_secs = 1;
    assert!(cfg.validate().is_ok());
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `cargo test -p foundry-core --lib config::validate 2>&1 | tail -20`
Expected: FAIL — `a_zero_dpop_max_age_is_rejected` panics on `expect_err` because `validate()` returns `Ok`.

- [ ] **Step 7: Add the validation**

In `crates/foundry-core/src/config/validate.rs`, inside `pub fn validate(&self)`, before the final `Ok(())`:

```rust
// RFC 9449 §4.3 check 11: a zero acceptance window makes every proof stale
// the instant it is minted, so every DPoP request would fail with a blanket
// invalid_dpop_proof. Caught at startup rather than at request time.
if self.issuer.dpop.max_age_secs == 0 {
    return Err(ConfigError::Validation(
        "issuer.dpop.max_age_secs must be greater than 0".to_string(),
    ));
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p foundry-core --lib config 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 9: Run the scoped gate**

```bash
cargo test -p foundry-core
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green. `-p foundry-issuer -p foundry` are not needed yet — nothing consumes the new field.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry-core/src/config/model.rs crates/foundry-core/src/config/validate.rs
git commit -m "feat(core): issuer.dpop config block (RFC 9449)

DpopConfig { mode, max_age_secs } on IssuerConfig, defaulting to
Mode::Optional / 300s so every existing config keeps its current
behaviour. Default is hand-written rather than derived: the derive would
give max_age_secs = 0, which validate() now rejects outright.

Disabled deliberately means 'ignore the header', not 'reject it' --
RFC 9449 section 10.1 encourages clients that attach DPoP to every AS
call, and section 5 lets an AS signal non-binding via token_type Bearer."
```

---

## Task 2: `dpop_jkt` on `IssuanceTransaction`

**Files:**
- Modify: `crates/foundry-issuer/src/transaction.rs`
- Modify (mechanical, add `dpop_jkt: None` to each literal): `crates/foundry-issuer/src/create_offer.rs`, `crates/foundry-issuer/src/authorize.rs`, `crates/foundry-issuer/src/token.rs`, `crates/foundry-issuer/src/credential.rs`
- Test: inline `#[cfg(test)]` in `transaction.rs`

**Interfaces:**
- Produces: `IssuanceTransaction.dpop_jkt: Option<String>`. Tasks 6, 7 and 9 read and write it.

There are **13 `IssuanceTransaction { .. }` construction sites across 5 files** (including test fixtures such as `token.rs`'s `sample_tx` and `authorize.rs`'s). Adding a field breaks every one, so this is its own mechanical task with no behavioural content — keeping it separate stops the compiler churn from obscuring the logic changes in later tasks.

- [ ] **Step 1: Write the failing test**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/transaction.rs`:

```rust
#[tokio::test]
async fn dpop_jkt_round_trips_through_storage() {
    let storage = test_storage().await;
    let mut tx = sample_tx("tx-dpop-rt");
    tx.dpop_jkt = Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string());
    save_transaction(&storage, &tx, 600, 1_700_000_000).await.unwrap();

    let loaded = load_transaction(&storage, "tx-dpop-rt").await.unwrap().unwrap();
    assert_eq!(
        loaded.dpop_jkt,
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string())
    );
}

#[test]
fn a_transaction_persisted_before_dpop_existed_still_deserializes() {
    // Transactions live as JSON in the KV store, so a row written by a
    // pre-DPoP binary must survive a rolling restart onto this one. This is
    // what #[serde(default)] on dpop_jkt buys, and it is the only test that
    // would catch its removal.
    let legacy = r#"{
        "transaction_id": "tx-legacy",
        "credential_type_id": "pid",
        "claims": {},
        "pre_authorized_code": null,
        "tx_code": null,
        "status_list_index": null,
        "access_token": null,
        "state": "offered",
        "created_at": 1700000000,
        "redirect_uri": null,
        "issuer_state": null,
        "authorization_code": null,
        "code_challenge": null,
        "code_challenge_method": null
    }"#;
    let tx: IssuanceTransaction = serde_json::from_str(legacy).unwrap();
    assert_eq!(tx.dpop_jkt, None);
}
```

> `transaction.rs`'s test module may not already have `test_storage`/`sample_tx` helpers. If it doesn't, copy them from `token.rs`'s test module (shown in Task 7 Step 1) rather than inventing new ones.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p foundry-issuer --lib transaction 2>&1 | tail -20`
Expected: FAIL — `no field dpop_jkt on type IssuanceTransaction`.

- [ ] **Step 3: Add the field**

In `crates/foundry-issuer/src/transaction.rs`, at the end of the `IssuanceTransaction` struct:

```rust
    /// RFC 9449 §6: the RFC 7638 JWK thumbprint of the DPoP key this flow is
    /// pinned to.
    ///
    /// Written at two different points for two different clauses, but it is
    /// one concept — "the key this flow is pinned to" — at both:
    /// - `/authorize` writes it from the §10 `dpop_jkt` request parameter, and
    ///   `/token` then requires the presented proof to match it.
    /// - `/token` writes it from the verified proof, and `/credential` then
    ///   requires the presented proof to match it.
    ///
    /// `Some` ⇒ the access token is DPoP-bound and MUST be presented with the
    /// `DPoP` scheme plus a matching proof (§7.1); `None` ⇒ plain Bearer.
    ///
    /// `#[serde(default)]` is load-bearing: transactions are persisted as JSON
    /// in the KV store, so a row written before this field existed must still
    /// deserialize after a rolling restart.
    #[serde(default)]
    pub dpop_jkt: Option<String>,
```

- [ ] **Step 4: Fix every construction site**

Run this to find them all:

```bash
grep -rn "IssuanceTransaction {" --include=*.rs crates/
```

Add `dpop_jkt: None,` to each of the 13 literals. They are in `transaction.rs`, `create_offer.rs`, `authorize.rs`, `token.rs` (including the `sample_tx` and `sample_auth_code_tx` test helpers), and `credential.rs`. Add nothing else — this step is purely mechanical.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib transaction 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green — every pre-existing test must still pass, since `dpop_jkt: None` changes no behaviour. `-p foundry` is included here because the integration suite constructs transactions indirectly through the HTTP API.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-issuer/src/
git commit -m "feat(issuer): dpop_jkt on IssuanceTransaction (RFC 9449 section 6)

Carries the RFC 7638 thumbprint of the key a flow is pinned to. One
field serves both section 10 (written by /authorize, checked at /token)
and section 6 (written by /token, checked at /credential) -- it means
'the key this flow is pinned to' at every stage.

serde(default) so a transaction row persisted by a pre-DPoP binary
still deserializes after a rolling restart; covered by a regression
test against a literal legacy JSON payload.

Mechanical: all 13 construction sites get dpop_jkt: None. No behaviour
change."
```

---

## Task 3: `IssuanceError::InvalidDpopProof`

**Files:**
- Modify: `crates/foundry-issuer/src/error.rs`
- Modify: `crates/foundry/src/server.rs` (the `wallet_error_response` mapper)
- Test: inline `#[cfg(test)]` in `error.rs`

**Interfaces:**
- Produces: `IssuanceError::InvalidDpopProof(String)` with `kind() == "invalid_dpop_proof"`. Tasks 4, 5, 7 and 9 return it.

One variant covers every DPoP failure, because RFC 9449 defines exactly one error code for them (`invalid_dpop_proof`, registered §12.2). The distinguishing detail belongs in the `Display` string, not in the type.

- [ ] **Step 1: Write the failing test**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/error.rs`, matching the style of the existing `kind()` tests there:

```rust
#[test]
fn invalid_dpop_proof_has_a_stable_kind_and_message() {
    let e = IssuanceError::InvalidDpopProof("htu claim does not match".into());
    // RFC 9449 §5 / §12.2 register `invalid_dpop_proof` as the error code.
    assert_eq!(e.kind(), "invalid_dpop_proof");
    assert_eq!(e.to_string(), "invalid dpop proof: htu claim does not match");
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p foundry-issuer --lib error 2>&1 | tail -20`
Expected: FAIL — `no variant named InvalidDpopProof`.

- [ ] **Step 3: Add the variant**

In `crates/foundry-issuer/src/error.rs`, in the `IssuanceError` enum (place it directly after `InvalidClient` — both are client-facing authentication/possession failures):

```rust
    /// RFC 9449 §5: any DPoP proof failure — malformed JWT, wrong `typ`/`alg`,
    /// bad signature, `htm`/`htu`/`iat`/`ath` mismatch, replayed `jti`, a
    /// §10 `dpop_jkt` mismatch, or a §7.2 scheme/binding mismatch.
    ///
    /// Deliberately one variant, not one per check: §5 defines a single error
    /// code (`invalid_dpop_proof`, registered in §12.2), so the discriminating
    /// detail belongs in this string. That string reaches the wire as
    /// `error_description`, so it MUST name only the structural defect and
    /// MUST NOT echo the proof, the access token, or key material.
    #[error("invalid dpop proof: {0}")]
    InvalidDpopProof(String),
```

and the matching `kind()` arm (the `match` is deliberately exhaustive with no catch-all, so omitting this is a compile error):

```rust
            IssuanceError::InvalidDpopProof(_) => "invalid_dpop_proof",
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p foundry-issuer --lib error 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Map it at the Token Endpoint**

In `crates/foundry/src/server.rs`'s `wallet_error_response`, add an arm next to the `InvalidClient` one:

```rust
        // RFC 9449 §5: "If the DPoP proof is invalid, the authorization server
        // issues an error response per Section 5.2 of [RFC6749] with
        // invalid_dpop_proof as the value of the error parameter."
        //
        // This is the Token Endpoint mapping. The Credential Endpoint is a
        // *protected resource*, where §7.1 requires 401 + WWW-Authenticate
        // instead — see `credential_error_response` (Task 9).
        InvalidDpopProof(_) => (StatusCode::BAD_REQUEST, "invalid_dpop_proof"),
```

- [ ] **Step 6: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-issuer/src/error.rs crates/foundry/src/server.rs
git commit -m "feat(issuer): InvalidDpopProof error variant (RFC 9449 section 5)

One variant for every DPoP failure, because RFC 9449 registers exactly
one error code for them (invalid_dpop_proof, section 12.2). The
discriminating detail lives in the Display string, which reaches the
wire as error_description and therefore names only the structural
defect -- never the proof, the token, or key material.

Mapped to 400 at /token per section 5. The Credential Endpoint's 401 +
WWW-Authenticate mapping (section 7.1) lands with the endpoint itself."
```

---

## Task 4: `dpop.rs` — proof validation (RFC 9449 §4.2/§4.3)

**Files:**
- Create: `crates/foundry-issuer/src/dpop.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`
- Test: inline `#[cfg(test)]` in `dpop.rs`

**Interfaces:**
- Consumes: `IssuanceError::InvalidDpopProof` (Task 3); `foundry_core::obs::thumbprint_bytes(&serde_json::Value) -> Result<[u8; 32], String>`.
- Produces:
  ```rust
  pub struct VerifiedDpopProof { pub jkt: String, pub jti: String, pub htu: String }
  pub fn verify_dpop_proof(
      proof_jwt: &str, htm: &str, htu: &str, expected_ath: Option<&str>,
      now_unix: i64, max_age_secs: u64,
  ) -> Result<VerifiedDpopProof, IssuanceError>
  ```
  Tasks 7 and 9 call it; Task 5 consumes `VerifiedDpopProof`'s fields.

`VerifiedDpopProof.htu` carries the **normalised** value so Task 5's replay key and this function's comparison can never disagree.

This is the largest task. It is one task rather than several because the twelve checks share one parse of one JWT — splitting them would mean either re-parsing or handing a reviewer half a validator.

**Do NOT implement §4.3 check 1** (at most one `DPoP` header) here: this function receives a single `&str` and cannot see the header map. It lands in `server.rs` in Tasks 7 and 9, via the existing `exactly_one_header` helper.

**Do NOT implement §4.3 check 10** (`nonce`): the design deliberately omits server-provided nonces, so there is never a nonce to match. §11.3 is satisfied vacuously.

- [ ] **Step 1: Write the failing known-answer test**

Create `crates/foundry-issuer/src/dpop.rs` with only the test module for now:

```rust
//! RFC 9449 (DPoP) proof JWT validation.

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jws::{JwsHeader, ES256};
    use josekit::jwt::{self, JwtPayload};

    const HTU: &str = "https://issuer.example.com/token";
    const NOW: i64 = 1_700_000_000;
    const MAX_AGE: u64 = 300;

    fn keypair() -> EcKeyPair {
        EcKeyPair::generate(EcCurve::P256).unwrap()
    }

    /// The RFC 9449 §4.2 Figure 2 key, whose §6.1 Figure 9 `jkt` is published
    /// in the RFC itself — the known-answer vector this module asserts against.
    fn rfc9449_figure2_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
        })
    }

    /// Mint a DPoP proof. Every negative test below is this call with exactly
    /// one argument mutated.
    fn dpop_proof(
        kp: &EcKeyPair,
        typ: &str,
        htm: Option<&str>,
        htu: Option<&str>,
        iat: Option<i64>,
        jti: Option<&str>,
        ath: Option<&str>,
    ) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type(typ);
        let mut jwk = kp.to_jwk_public_key();
        jwk.set_key_id_deleted();
        header.set_jwk(jwk);

        let mut payload = JwtPayload::new();
        if let Some(v) = htm {
            payload.set_claim("htm", Some(v.into())).unwrap();
        }
        if let Some(v) = htu {
            payload.set_claim("htu", Some(v.into())).unwrap();
        }
        if let Some(v) = iat {
            payload.set_claim("iat", Some(v.into())).unwrap();
        }
        if let Some(v) = jti {
            payload.set_claim("jti", Some(v.into())).unwrap();
        }
        if let Some(v) = ath {
            payload.set_claim("ath", Some(v.into())).unwrap();
        }

        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    /// A fully valid proof for the happy path.
    fn valid(kp: &EcKeyPair) -> String {
        dpop_proof(kp, "dpop+jwt", Some("POST"), Some(HTU), Some(NOW), Some("jti-1"), None)
    }

    #[test]
    fn thumbprint_matches_the_rfc9449_figure_9_known_answer() {
        // RFC 9449 §6.1 Figure 9 publishes this jkt for the Figure 2 key.
        // Asserting against the RFC's own vector, not against our output.
        let jkt = jwk_thumbprint(&rfc9449_figure2_jwk()).unwrap();
        assert_eq!(jkt, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    }

    #[test]
    fn a_valid_proof_is_accepted_and_yields_a_thumbprint() {
        let kp = keypair();
        let v = verify_dpop_proof(&valid(&kp), "POST", HTU, None, NOW, MAX_AGE).unwrap();
        assert_eq!(v.jti, "jti-1");
        assert_eq!(v.htu, HTU);
        assert!(!v.jkt.is_empty());
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

First declare the module — in `crates/foundry-issuer/src/lib.rs` add `pub mod dpop;` alongside the other `pub mod` lines, and re-export next to the existing ones:

```rust
pub use dpop::{verify_dpop_proof, VerifiedDpopProof};
```

Run: `cargo test -p foundry-issuer --lib dpop 2>&1 | tail -20`
Expected: FAIL — `cannot find function jwk_thumbprint` / `verify_dpop_proof`.

- [ ] **Step 3: Implement the module**

Replace the top of `crates/foundry-issuer/src/dpop.rs` (above the test module) with:

```rust
//! RFC 9449 (DPoP) proof JWT validation — Demonstrating Proof of Possession.
//!
//! Implements §4.2 (proof JWT syntax) and §4.3 (checking proofs) for both the
//! Token Endpoint and the Credential Endpoint, plus §11.1 replay defence.
//!
//! **Two of §4.3's twelve checks are deliberately not here:**
//!
//! - **Check 1** ("not more than one DPoP HTTP request header field") needs the
//!   header map, which this module never sees — it takes a single `&str`. It is
//!   enforced in `crates/foundry/src/server.rs` via `exactly_one_header`.
//! - **Check 10** (`nonce` matches a server-supplied nonce) is vacuous: foundry
//!   does not implement §8/§9 server-provided nonces, so it never supplies one.
//!   §11.3 ("MUST NOT accept any DPoP proofs without the nonce claim when a
//!   DPoP nonce has been provided") is therefore satisfied by construction.
//!   See the design doc §2.2 for why, and §6.2 for the residual §11.2 exposure.

use crate::error::IssuanceError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::obs::thumbprint_bytes;
use foundry_core::storage::Storage;
use josekit::jwk::Jwk;
use josekit::jws::ES256;
use sha2::{Digest, Sha256};

/// RFC 9449 §11.1: "To accommodate for clock offsets, the server MAY accept
/// DPoP proofs that carry an iat time in the reasonably near future."
///
/// Distinct from `max_age_secs`, which bounds how far into the *past* an `iat`
/// may sit. Mirrors `attestation.rs`'s `POP_CLOCK_SKEW_SECS`.
const DPOP_CLOCK_SKEW_SECS: i64 = 60;

/// A DPoP proof that has passed every §4.3 check this module is responsible
/// for. Carries only what a caller still needs; every other claim was checked
/// here and has no consumer above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    /// RFC 7638 JWK SHA-256 thumbprint of the proof's `jwk` header, base64url
    /// — the §6.1 `jkt` value the access token is bound to.
    pub jkt: String,
    /// The proof's `jti`, for the caller to hand to [`claim_dpop_jti`].
    /// Never logged (root `AGENTS.md` §4.5).
    pub jti: String,
    /// The **normalised** `htu`. Returned rather than recomputed by the caller
    /// so the §11.1 replay key and this function's comparison can never
    /// disagree about what URI a proof was scoped to.
    pub htu: String,
}

/// RFC 7638 JWK thumbprint, base64url — the §6.1 `jkt` / §10 `dpop_jkt` value.
///
/// Uses `thumbprint_bytes` (the fail-closed form) rather than `obs::thumbprint`
/// deliberately: the infallible form degrades a malformed JWK to a placeholder
/// string, which would then compare unequal to every real `jkt` and turn a
/// parse error into a confusing binding mismatch.
fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, IssuanceError> {
    let digest = thumbprint_bytes(jwk).map_err(|e| {
        // `e` names only the structural defect (which member, which kty) and
        // never echoes key material — see obs::thumbprint_bytes's contract.
        IssuanceError::InvalidDpopProof(format!("jwk header is not a valid JWK: {e}"))
    })?;
    Ok(B64URL.encode(digest))
}

/// RFC 9449 §4.3 check 9: compare `htu` "ignoring any query and fragment
/// parts", after the RFC 3986 §6.2.2/§6.2.3 normalisation §4.3 recommends
/// ("servers SHOULD employ syntax-based normalization and scheme-based
/// normalization before comparing the htu claim").
///
/// Applies exactly three transformations: strip query and fragment, lowercase
/// scheme and authority, and drop an explicitly-written default port.
///
/// Deliberately does **no** path normalisation: collapsing `..` segments is a
/// security-relevant rewrite of a value used for an equality check, and neither
/// side of that comparison should contain them in the first place.
fn normalize_htu(raw: &str) -> String {
    let no_fragment = raw.split('#').next().unwrap_or("");
    let no_query = no_fragment.split('?').next().unwrap_or("");

    let Some((scheme, rest)) = no_query.split_once("://") else {
        // Not an absolute URI. Returned as-is so the comparison simply fails
        // rather than this function inventing a shape for it.
        return no_query.to_string();
    };
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let authority = authority.to_ascii_lowercase();

    // RFC 3986 §6.2.3: an explicitly-written default port is equivalent to
    // omitting it.
    let default_port = match scheme.as_str() {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    let authority = match default_port {
        Some(p) => authority.strip_suffix(p).unwrap_or(&authority).to_string(),
        None => authority,
    };

    format!("{scheme}://{authority}{path}")
}

/// Validate a DPoP proof JWT per RFC 9449 §4.3.
///
/// `htm` and `htu` MUST be the real method and target URI of the request being
/// authenticated. They are parameters rather than being derived here because
/// only the HTTP layer knows them — and `htu` must come from configuration,
/// never from a client-controlled `Host` header, or an attacker could replay a
/// proof minted for a different origin.
///
/// `expected_ath` is `Some` only at a protected resource (§7): `None` at the
/// Token Endpoint, where no access token is being presented and check 12 does
/// not apply.
///
/// `skip_all` is mandatory: `proof_jwt` is the wallet's proof and
/// `expected_ath` is derived from an access token (root `AGENTS.md` §4.5).
#[tracing::instrument(skip_all, fields(htm = %htm))]
pub fn verify_dpop_proof(
    proof_jwt: &str,
    htm: &str,
    htu: &str,
    expected_ath: Option<&str>,
    now_unix: i64,
    max_age_secs: u64,
) -> Result<VerifiedDpopProof, IssuanceError> {
    // Check 2: "a single and well-formed JWT".
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidDpopProof(
            "invalid JWS format, expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL
        .decode(parts[0])
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid base64url header: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid header JSON: {e}")))?;

    // Check 4: "The typ JOSE Header Parameter has the value dpop+jwt."
    let typ = header
        .get("typ")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing typ header".into()))?;
    if typ != "dpop+jwt" {
        return Err(IssuanceError::InvalidDpopProof(format!(
            "invalid typ header '{typ}', expected dpop+jwt"
        )));
    }

    // Check 5: alg is a registered asymmetric algorithm, "is not none, is
    // supported by the application, and is acceptable per local policy". Local
    // policy here is ES256 only (HAIP crypto suites), which also discharges
    // "not none" and "not symmetric" by construction.
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing alg header".into()))?;
    if alg != "ES256" {
        return Err(IssuanceError::InvalidDpopProof(format!(
            "alg '{alg}' is not permitted, expected ES256"
        )));
    }

    // §4.2: the jwk header is REQUIRED and "represents the public key chosen
    // by the client".
    let jwk_value = header
        .get("jwk")
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing jwk header".into()))?;

    // Check 7: "The jwk JOSE Header Parameter does not contain a private key."
    //
    // Checked across every key type's private parameters (RFC 7518 §6.2.2 EC,
    // §6.3.2 RSA, §6.4.1 oct; RFC 8037 §2 OKP) rather than only EC's `d`, so a
    // non-EC jwk cannot smuggle one past on a technicality even though the
    // ES256 verifier below would reject its kty. Same list and reasoning as
    // `attestation.rs`'s cnf.jwk guard.
    const PRIVATE_JWK_PARAMS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if let Some(param) = PRIVATE_JWK_PARAMS
        .iter()
        .find(|p| jwk_value.get(**p).is_some())
    {
        // Names the offending parameter but never its value — that value is,
        // by construction, private key material (root `AGENTS.md` §4.5).
        return Err(IssuanceError::InvalidDpopProof(format!(
            "jwk header MUST be a public key, but carries the private parameter `{param}`"
        )));
    }

    // Check 6: "The JWT signature verifies with the public key contained in
    // the jwk JOSE Header Parameter."
    let jwk: Jwk = serde_json::from_value(jwk_value.clone())
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid jwk header: {e}")))?;
    let verifier = ES256.verifier_from_jwk(&jwk).map_err(|e| {
        IssuanceError::InvalidDpopProof(format!("unable to build a verifier from the jwk header: {e}"))
    })?;
    josekit::jwt::decode_with_verifier(proof_jwt, &verifier).map_err(|e| {
        IssuanceError::InvalidDpopProof(format!("signature verification failed: {e}"))
    })?;

    let payload_bytes = B64URL
        .decode(parts[1])
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid base64url payload: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid payload JSON: {e}")))?;

    // Check 3 (for jti) + §4.2: jti is REQUIRED, "unique identifier for the
    // DPoP proof JWT".
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing or empty jti claim".into()))?;

    // Check 8: "The htm claim matches the HTTP method of the current request."
    // Case-sensitive: RFC 9110 method names are uppercase tokens.
    let claim_htm = payload
        .get("htm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing htm claim".into()))?;
    if claim_htm != htm {
        return Err(IssuanceError::InvalidDpopProof(
            "htm claim does not match the request method".into(),
        ));
    }

    // Check 9: "The htu claim matches the HTTP URI value for the HTTP request
    // in which the JWT was received, ignoring any query and fragment parts."
    let claim_htu = payload
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing htu claim".into()))?;
    let normalized_claim_htu = normalize_htu(claim_htu);
    if normalized_claim_htu != normalize_htu(htu) {
        // Never echoes either URI: the expected one is configuration and the
        // claimed one is attacker-controlled.
        return Err(IssuanceError::InvalidDpopProof(
            "htu claim does not match the request URI".into(),
        ));
    }

    // Check 11: "The creation time of the JWT, as determined by either the iat
    // claim or a server managed timestamp via the nonce claim, is within an
    // acceptable window."
    //
    // Saturating throughout, and via try_from rather than `as`: `iat` arrives
    // off the wire, and `max_age_secs as i64` would be a lossy cast of a u64
    // config value (`u64::MAX as i64 == -1`, which would reject every proof).
    // A bare +/- would panic under the dev profile's overflow-checks (breaking
    // root AGENTS.md §4.1 in a request path) or silently wrap in release, in
    // which case *both* freshness bounds stop firing and the §11.1 window is
    // bypassed rather than merely mis-tuned.
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing or non-integer iat claim".into()))?;
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    if now_unix.saturating_sub(iat) > max_age {
        return Err(IssuanceError::InvalidDpopProof(
            "iat is older than the allowed max age".into(),
        ));
    }
    if iat > now_unix.saturating_add(DPOP_CLOCK_SKEW_SECS) {
        return Err(IssuanceError::InvalidDpopProof(
            "iat is too far in the future".into(),
        ));
    }

    // Check 12, first half: "ensure that the value of the ath claim equals the
    // hash of that access token". The second half — "confirm that the public
    // key to which the access token is bound matches the public key from the
    // DPoP proof" — is the caller's, since this module knows nothing about
    // transactions.
    if let Some(expected) = expected_ath {
        let claim_ath = payload
            .get("ath")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IssuanceError::InvalidDpopProof("missing ath claim".into()))?;
        // Never echoes either value: both are derived from the access token.
        if claim_ath != expected {
            return Err(IssuanceError::InvalidDpopProof(
                "ath claim does not match the presented access token".into(),
            ));
        }
    }

    Ok(VerifiedDpopProof {
        jkt: jwk_thumbprint(jwk_value)?,
        jti: jti.to_string(),
        htu: normalized_claim_htu,
    })
}

/// RFC 9449 §7: `base64url(SHA-256(ASCII(access_token)))` — the `ath` claim
/// value a proof presented alongside `access_token` must carry.
pub fn access_token_hash(access_token: &str) -> String {
    B64URL.encode(Sha256::digest(access_token.as_bytes()))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib dpop 2>&1 | tail -20`
Expected: PASS (2 tests).

> If `thumbprint_matches_the_rfc9449_figure_9_known_answer` fails, the bug is in `jwk_thumbprint`, not in the vector — the value was verified against `thumbprint_bytes`'s canonicalisation during design. Do not change the expected string.

- [ ] **Step 5: Write the negative tests for every remaining check**

Append to `dpop.rs`'s test module:

```rust
    #[test]
    fn rejects_a_non_jwt_string() {
        // Check 2.
        let e = verify_dpop_proof("not-a-jwt", "POST", HTU, None, NOW, MAX_AGE).unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[test]
    fn rejects_a_two_part_jws() {
        // Check 2.
        assert!(verify_dpop_proof("aaa.bbb", "POST", HTU, None, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn rejects_wrong_typ() {
        // Check 4. `jwt` instead of `dpop+jwt` is the realistic mistake, and
        // §11.5 (signed JWT swapping) is why typ is checked at all.
        let kp = keypair();
        let p = dpop_proof(&kp, "jwt", Some("POST"), Some(HTU), Some(NOW), Some("j"), None);
        let e = verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).unwrap_err();
        assert!(e.to_string().contains("dpop+jwt"), "got: {e}");
    }

    #[test]
    fn rejects_missing_jti() {
        // Check 3.
        let kp = keypair();
        let p = dpop_proof(&kp, "dpop+jwt", Some("POST"), Some(HTU), Some(NOW), None, None);
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("jti"));
    }

    #[test]
    fn rejects_missing_htm() {
        // Check 3.
        let kp = keypair();
        let p = dpop_proof(&kp, "dpop+jwt", None, Some(HTU), Some(NOW), Some("j"), None);
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("htm"));
    }

    #[test]
    fn rejects_missing_htu() {
        // Check 3.
        let kp = keypair();
        let p = dpop_proof(&kp, "dpop+jwt", Some("POST"), None, Some(NOW), Some("j"), None);
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("htu"));
    }

    #[test]
    fn rejects_missing_iat() {
        // Check 3.
        let kp = keypair();
        let p = dpop_proof(&kp, "dpop+jwt", Some("POST"), Some(HTU), None, Some("j"), None);
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("iat"));
    }

    #[test]
    fn rejects_a_signature_by_another_key() {
        // Check 6: the jwk header advertises one key, the signature is by
        // another. This is the check that makes the proof a proof.
        let signer_kp = keypair();
        let other_kp = keypair();
        let p = valid(&signer_kp);
        // Swap the jwk header for a different key, keeping the signature.
        let parts: Vec<&str> = p.split('.').collect();
        let mut header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        let mut other_jwk = other_kp.to_jwk_public_key();
        other_jwk.set_key_id_deleted();
        header["jwk"] = serde_json::to_value(&other_jwk).unwrap();
        let forged = format!(
            "{}.{}.{}",
            B64URL.encode(serde_json::to_vec(&header).unwrap()),
            parts[1],
            parts[2]
        );
        assert!(verify_dpop_proof(&forged, "POST", HTU, None, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn rejects_a_tampered_payload() {
        // Check 6.
        let kp = keypair();
        let p = valid(&kp);
        let parts: Vec<&str> = p.split('.').collect();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        payload["htm"] = serde_json::json!("GET");
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            B64URL.encode(serde_json::to_vec(&payload).unwrap()),
            parts[2]
        );
        assert!(verify_dpop_proof(&forged, "GET", HTU, None, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn rejects_a_jwk_carrying_a_private_key() {
        // Check 7. A private key in the header means the wallet leaked its
        // signing key into a plaintext HTTP header, at which point the proof
        // proves nothing.
        let kp = keypair();
        let p = valid(&kp);
        let parts: Vec<&str> = p.split('.').collect();
        let mut header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        header["jwk"]["d"] = serde_json::json!("c3VwZXItc2VjcmV0LXNjYWxhcg");
        let leaked = format!(
            "{}.{}.{}",
            B64URL.encode(serde_json::to_vec(&header).unwrap()),
            parts[1],
            parts[2]
        );
        let e = verify_dpop_proof(&leaked, "POST", HTU, None, NOW, MAX_AGE).unwrap_err();
        assert!(e.to_string().contains('d'), "must name the parameter: {e}");
        assert!(
            !e.to_string().contains("c3VwZXItc2VjcmV0"),
            "the private scalar must never appear in an error message: {e}"
        );
    }

    #[test]
    fn rejects_htm_mismatch() {
        // Check 8.
        let kp = keypair();
        let e = verify_dpop_proof(&valid(&kp), "GET", HTU, None, NOW, MAX_AGE).unwrap_err();
        assert!(e.to_string().contains("htm"), "got: {e}");
    }

    #[test]
    fn rejects_htu_mismatch() {
        // Check 9. A proof minted for /token replayed at /credential is
        // exactly what this prevents.
        let kp = keypair();
        let e = verify_dpop_proof(
            &valid(&kp),
            "POST",
            "https://issuer.example.com/credential",
            None,
            NOW,
            MAX_AGE,
        )
        .unwrap_err();
        assert!(e.to_string().contains("htu"), "got: {e}");
    }

    #[test]
    fn accepts_htu_differing_only_by_query_or_fragment() {
        // Check 9: "ignoring any query and fragment parts".
        let kp = keypair();
        let p = dpop_proof(
            &kp, "dpop+jwt", Some("POST"),
            Some("https://issuer.example.com/token?x=1#frag"),
            Some(NOW), Some("j"), None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).is_ok());
    }

    #[test]
    fn accepts_htu_differing_only_by_case_or_default_port() {
        // Check 9 + RFC 3986 §6.2.2/§6.2.3 normalisation.
        let kp = keypair();
        let p = dpop_proof(
            &kp, "dpop+jwt", Some("POST"),
            Some("HTTPS://Issuer.Example.COM:443/token"),
            Some(NOW), Some("j"), None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).is_ok());
    }

    #[test]
    fn htu_normalisation_does_not_collapse_dot_segments() {
        // Deliberate: path normalisation is a security-relevant rewrite of a
        // value used for an equality check. A traversal-shaped htu must fail,
        // not be silently rewritten into a match.
        let kp = keypair();
        let p = dpop_proof(
            &kp, "dpop+jwt", Some("POST"),
            Some("https://issuer.example.com/admin/../token"),
            Some(NOW), Some("j"), None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn rejects_iat_older_than_the_window() {
        // Check 11 / §11.1.
        let kp = keypair();
        let p = dpop_proof(
            &kp, "dpop+jwt", Some("POST"), Some(HTU),
            Some(NOW - 301), Some("j"), None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("older"));
    }

    #[test]
    fn rejects_iat_too_far_in_the_future() {
        // Check 11 / §11.2: an attacker pre-generating proofs.
        let kp = keypair();
        let p = dpop_proof(
            &kp, "dpop+jwt", Some("POST"), Some(HTU),
            Some(NOW + 61), Some("j"), None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("future"));
    }

    #[test]
    fn accepts_iat_slightly_in_the_future_within_clock_skew() {
        // §11.1: "servers MAY accept DPoP proofs that carry an iat time in the
        // reasonably near future."
        let kp = keypair();
        let p = dpop_proof(
            &kp, "dpop+jwt", Some("POST"), Some(HTU),
            Some(NOW + 30), Some("j"), None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).is_ok());
    }

    #[test]
    fn does_not_overflow_on_a_boundary_iat() {
        // Root AGENTS.md §4.1: overflow-checks = true in the dev profile turns
        // a bare +/- on a wire-sourced i64 into a panic in a request path.
        let kp = keypair();
        for iat in [i64::MIN, i64::MAX] {
            let p = dpop_proof(
                &kp, "dpop+jwt", Some("POST"), Some(HTU),
                Some(iat), Some("j"), None,
            );
            // Must return an error, never panic.
            assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, u64::MAX).is_err());
        }
    }

    #[test]
    fn rejects_missing_ath_when_an_access_token_is_presented() {
        // Check 12 / §7: "The DPoP proof MUST include the ath claim."
        let kp = keypair();
        let e = verify_dpop_proof(&valid(&kp), "POST", HTU, Some("expected-hash"), NOW, MAX_AGE)
            .unwrap_err();
        assert!(e.to_string().contains("ath"), "got: {e}");
    }

    #[test]
    fn rejects_ath_mismatch() {
        // Check 12 / §11.5: prevents a proof for token AT1 being replayed
        // with token AT2.
        let kp = keypair();
        let p = dpop_proof(
            &kp, "dpop+jwt", Some("POST"), Some(HTU), Some(NOW), Some("j"),
            Some(&access_token_hash("at_one")),
        );
        assert!(verify_dpop_proof(
            &p, "POST", HTU, Some(&access_token_hash("at_two")), NOW, MAX_AGE
        )
        .is_err());
    }

    #[test]
    fn accepts_a_matching_ath() {
        let kp = keypair();
        let token = "at_deadbeef";
        let p = dpop_proof(
            &kp, "dpop+jwt", Some("POST"), Some(HTU), Some(NOW), Some("j"),
            Some(&access_token_hash(token)),
        );
        assert!(
            verify_dpop_proof(&p, "POST", HTU, Some(&access_token_hash(token)), NOW, MAX_AGE)
                .is_ok()
        );
    }

    #[test]
    fn ath_is_the_base64url_sha256_of_the_token() {
        // §7 / §4.2: "the result of a base64url encoding the SHA-256 hash of
        // the ASCII encoding of the associated access token's value."
        // Known answer for the RFC 9449 §7.1 Figure 13 token.
        assert_eq!(
            access_token_hash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
            "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
        );
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib dpop 2>&1 | tail -30`
Expected: PASS, all tests.

> Two tests are load-bearing beyond their own check and must not be weakened to make them pass:
> - `ath_is_the_base64url_sha256_of_the_token` is a second known-answer vector, taken from RFC 9449 §7.1 Figure 13/14 (that figure's token and its `ath`). If it fails, `access_token_hash` is wrong.
> - `does_not_overflow_on_a_boundary_iat` will *panic* rather than fail if the saturating arithmetic is missing. A panic here is the §4.1 violation, not a test bug.

- [ ] **Step 7: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer
cargo clippy -p foundry-core -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green. `-p foundry` is not needed — nothing in the binary calls `dpop.rs` yet.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-issuer/src/dpop.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): RFC 9449 DPoP proof validation

New dpop.rs implementing section 4.3 checks 2-9 and 11-12: JWS shape,
typ dpop+jwt, ES256-only alg, signature against the embedded jwk,
public-key-only jwk, htm/htu match, iat window, and ath.

Checks 1 and 10 are deliberately absent and the module documents why:
check 1 (at most one DPoP header) needs the header map and lands in
server.rs; check 10 (nonce) is vacuous because foundry implements no
section 8/9 server-provided nonce, which also satisfies section 11.3 by
construction.

htu comparison applies RFC 3986 section 6.2.2/6.2.3 normalisation but
deliberately no path normalisation -- collapsing dot segments would
rewrite a value used for an equality check.

Two known-answer vectors taken from the RFC itself: the Figure 9 jkt
and the Figure 13/14 ath. jkt uses obs::thumbprint_bytes, the
fail-closed form, so a malformed jwk is a parse error rather than a
placeholder that mismatches every real binding."
```

---

## Task 5: `claim_dpop_jti` — §11.1 replay defence

**Files:**
- Modify: `crates/foundry-issuer/src/dpop.rs`
- Test: inline `#[cfg(test)]` in `dpop.rs`

**Interfaces:**
- Consumes: `VerifiedDpopProof` (Task 4); `foundry_core::storage::Storage::insert_kv_if_absent`.
- Produces: `pub(crate) async fn claim_dpop_jti(storage: &dyn Storage, proof: &VerifiedDpopProof, max_age_secs: u64, now_unix: i64) -> Result<(), IssuanceError>`. Tasks 7 and 9 call it.

Taking `&VerifiedDpopProof` rather than loose `jkt`/`htu`/`jti` strings makes it impossible for a caller to key the store on a *different* `htu` than the one `verify_dpop_proof` compared — which would silently scope replay detection to attacker-influenced input.

- [ ] **Step 1: Write the failing tests**

Append to `dpop.rs`'s test module:

```rust
    async fn test_storage() -> foundry_core::storage::SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        std::mem::forget(dir);
        foundry_core::storage::SqliteStorage::connect(db.to_str().unwrap())
            .await
            .unwrap()
    }

    fn proof_for(jkt: &str, htu: &str, jti: &str) -> VerifiedDpopProof {
        VerifiedDpopProof {
            jkt: jkt.to_string(),
            htu: htu.to_string(),
            jti: jti.to_string(),
        }
    }

    #[tokio::test]
    async fn a_first_sighting_is_claimed_and_a_replay_is_rejected() {
        // §11.1: "servers can store the jti value of each DPoP proof for the
        // time window in which the respective DPoP proof JWT would be
        // accepted to prevent multiple uses of the same DPoP proof."
        let storage = test_storage().await;
        let p = proof_for("jkt-a", HTU, "jti-1");

        claim_dpop_jti(&storage, &p, MAX_AGE, NOW).await.unwrap();
        let e = claim_dpop_jti(&storage, &p, MAX_AGE, NOW)
            .await
            .expect_err("a replayed jti must be rejected");
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn the_same_jti_at_a_different_htu_is_accepted() {
        // §11.1 scopes single-use "in the context of the target URI", so the
        // same jti at /token and at /credential are distinct claims.
        let storage = test_storage().await;
        claim_dpop_jti(&storage, &proof_for("jkt-a", HTU, "jti-1"), MAX_AGE, NOW)
            .await
            .unwrap();
        claim_dpop_jti(
            &storage,
            &proof_for("jkt-a", "https://issuer.example.com/credential", "jti-1"),
            MAX_AGE,
            NOW,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn two_wallets_may_use_the_same_jti() {
        // Keyed per jkt so one wallet cannot pre-claim jti values and deny
        // service to another -- the same reasoning as claim_pop_jti.
        let storage = test_storage().await;
        claim_dpop_jti(&storage, &proof_for("jkt-a", HTU, "shared"), MAX_AGE, NOW)
            .await
            .unwrap();
        claim_dpop_jti(&storage, &proof_for("jkt-b", HTU, "shared"), MAX_AGE, NOW)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_raw_jti_never_appears_in_the_storage_key() {
        // §11.1: "a server that is tracking jti values should reject DPoP
        // proof JWTs with unnecessarily large jti values or store only a hash
        // thereof." Also keeps attacker-controlled bytes out of the SQL key.
        let storage = test_storage().await;
        let p = proof_for("jkt-a", HTU, "recognisable-raw-jti");
        claim_dpop_jti(&storage, &p, MAX_AGE, NOW).await.unwrap();
        assert!(
            storage
                .get_kv(DPOP_JTI_NAMESPACE, "recognisable-raw-jti")
                .await
                .unwrap()
                .is_none(),
            "the raw jti must not be the storage key"
        );
    }

    #[tokio::test]
    async fn claiming_does_not_overflow_on_an_absurd_max_age() {
        // u64::MAX as i64 would be -1; try_from + saturating keeps the TTL sane.
        let storage = test_storage().await;
        claim_dpop_jti(&storage, &proof_for("jkt-a", HTU, "j"), u64::MAX, NOW)
            .await
            .unwrap();
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p foundry-issuer --lib dpop 2>&1 | tail -20`
Expected: FAIL — `cannot find function claim_dpop_jti` / `DPOP_JTI_NAMESPACE`.

- [ ] **Step 3: Implement it**

Append to the non-test part of `crates/foundry-issuer/src/dpop.rs`:

```rust
/// KV namespace for RFC 9449 §11.1 DPoP proof `jti` replay claims.
pub(crate) const DPOP_JTI_NAMESPACE: &str = "dpop_jti";

/// RFC 9449 §11.1: claim a proof's `jti` for its acceptance window, rejecting
/// a replay.
///
/// The key is `base64url(SHA-256(jkt ‖ 0x00 ‖ htu ‖ 0x00 ‖ jti))`. Three
/// deliberate properties:
///
/// - **Scoped per target URI**, because §11.1 scopes single-use "in the context
///   of the target URI" — a proof for `/token` and one for `/credential` are
///   distinct claims. The `htu` used is the *normalised* one from
///   `VerifiedDpopProof`, which is why this function takes the whole struct
///   rather than loose strings: a caller cannot key the store on a URI other
///   than the one `verify_dpop_proof` actually compared.
/// - **Scoped per `jkt`**, so one wallet cannot pre-claim `jti` values and deny
///   service to another. Same reasoning as `attestation.rs`'s `claim_pop_jti`.
/// - **Hashed**, because §11.1 says to "store only a hash thereof" to bound
///   memory against exhaustion attacks, and because it keeps the raw,
///   attacker-controlled `jti` out of the SQL key and out of anything derived
///   from it.
///
/// Uses `insert_kv_if_absent`, not get-then-put: the atomicity is the entire
/// mechanism. A get-then-put has a TOCTOU window in which two concurrent
/// replays both observe "absent" and both succeed.
///
/// `skip_all` is mandatory: `proof` carries the raw `jti` (root `AGENTS.md`
/// §4.5).
#[tracing::instrument(skip_all)]
pub(crate) async fn claim_dpop_jti(
    storage: &dyn Storage,
    proof: &VerifiedDpopProof,
    max_age_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    let mut hasher = Sha256::new();
    hasher.update(proof.jkt.as_bytes());
    hasher.update([0u8]);
    hasher.update(proof.htu.as_bytes());
    hasher.update([0u8]);
    hasher.update(proof.jti.as_bytes());
    let key = B64URL.encode(hasher.finalize());

    // Saturating and via try_from for the same reasons as the `iat` bounds
    // check above: `max_age_secs as i64` would be lossy for a u64 config value.
    // The row need only outlive the window in which the proof itself would
    // still be accepted, so the TTL mirrors that window plus the skew
    // tolerance.
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    let expires_at = now_unix
        .saturating_add(max_age)
        .saturating_add(DPOP_CLOCK_SKEW_SECS);

    let claimed = storage
        .insert_kv_if_absent(DPOP_JTI_NAMESPACE, &key, "1", Some(expires_at))
        .await?;
    if !claimed {
        return Err(IssuanceError::InvalidDpopProof(
            "jti has already been used".into(),
        ));
    }
    Ok(())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib dpop 2>&1 | tail -30`
Expected: PASS, all tests.

> `tempfile` must be a `dev-dependency` of `foundry-issuer` — it already is (`token.rs`'s tests use it). If the import fails, check `crates/foundry-issuer/Cargo.toml`'s `[dev-dependencies]` rather than adding it to `[dependencies]`.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer
cargo clippy -p foundry-core -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/dpop.rs
git commit -m "feat(issuer): DPoP jti replay defence (RFC 9449 section 11.1)

claim_dpop_jti keys an atomic insert_kv_if_absent on
base64url(SHA-256(jkt || 0 || htu || 0 || jti)):

- per target URI, because section 11.1 scopes single-use 'in the
  context of the target URI'
- per jkt, so one wallet cannot pre-claim jti values and deny service
  to another (same reasoning as claim_pop_jti)
- hashed, because section 11.1 says to store only a hash, and to keep
  the attacker-controlled jti out of the SQL key

Takes &VerifiedDpopProof rather than loose strings so a caller cannot
key the store on a different htu than verify_dpop_proof compared.
insert_kv_if_absent rather than get-then-put: the atomicity is the
mechanism, since get-then-put lets two concurrent replays both win."
```

---

## Task 6: `/authorize` accepts `dpop_jkt` (RFC 9449 §10)

**Files:**
- Modify: `crates/foundry-issuer/src/authorize.rs`
- Modify: `crates/foundry/src/server.rs` (`AuthorizeQuery`, `authorize_handler`)
- Modify: `crates/foundry/src/openapi.rs` if the `/authorize` params are enumerated there
- Test: inline `#[cfg(test)]` in `authorize.rs`

**Interfaces:**
- Consumes: `IssuanceTransaction.dpop_jkt` (Task 2).
- Produces: `AuthorizeParams.dpop_jkt: Option<String>`, persisted onto the transaction. Task 7 enforces it.

This task only *records* `dpop_jkt`; Task 7 enforces it. Split that way because a reviewer can verify "the parameter is captured and stored" independently of "the token endpoint honours it", and because §10's producer must exist before its consumer can be tested end to end.

- [ ] **Step 1: Write the failing test**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/authorize.rs`:

```rust
#[tokio::test]
async fn dpop_jkt_is_persisted_on_the_transaction() {
    // RFC 9449 §10: the dpop_jkt authorization request parameter binds the
    // issued authorization code to the client's proof-of-possession key.
    let storage = test_storage().await;
    let tx = sample_offered_tx();
    save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
        .await
        .unwrap();

    let mut params = valid_params();
    params.dpop_jkt = Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string());

    let outcome = handle_authorize_request(
        &storage, &params, ISSUER_IDENTIFIER, 600, 1_700_000_000,
    )
    .await;
    assert!(matches!(outcome, AuthorizeOutcome::Success { .. }));

    let loaded = load_transaction(&storage, &tx.transaction_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.dpop_jkt,
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string())
    );
}

#[tokio::test]
async fn an_absent_dpop_jkt_leaves_the_transaction_unpinned() {
    // §10: "Use of the dpop_jkt authorization request parameter is OPTIONAL."
    let storage = test_storage().await;
    let tx = sample_offered_tx();
    save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
        .await
        .unwrap();

    let outcome = handle_authorize_request(
        &storage, &valid_params(), ISSUER_IDENTIFIER, 600, 1_700_000_000,
    )
    .await;
    assert!(matches!(outcome, AuthorizeOutcome::Success { .. }));

    let loaded = load_transaction(&storage, &tx.transaction_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.dpop_jkt, None);
}
```

> Reuse whatever the existing tests in this module call their fixtures — the names above (`sample_offered_tx`, `valid_params`, `ISSUER_IDENTIFIER`, `test_storage`) follow that module's existing conventions. Read the module's test helpers first and match them exactly rather than adding parallel ones.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p foundry-issuer --lib authorize 2>&1 | tail -20`
Expected: FAIL — `no field dpop_jkt on type AuthorizeParams`.

- [ ] **Step 3: Add the parameter and persist it**

In `crates/foundry-issuer/src/authorize.rs`, add to `AuthorizeParams`:

```rust
    /// RFC 9449 §10: the JWK Thumbprint (SHA-256, base64url) of the client's
    /// proof-of-possession key, binding the issued authorization code to that
    /// key. OPTIONAL for the client to send — but once sent, honouring it is a
    /// MUST for the authorization server ("If they do not match, it MUST
    /// reject the request"), which `handle_token_request` does.
    ///
    /// Not validated for shape here: any value that is not the thumbprint of
    /// the key in the eventual DPoP proof simply fails that comparison at
    /// `/token`. Rejecting malformed shapes here would add a second,
    /// redundant failure mode for the same mistake.
    pub dpop_jkt: Option<String>,
```

and in `handle_authorize_request`, alongside the existing `code_challenge` assignments (around the `tx.code_challenge = ...` lines):

```rust
    // RFC 9449 §10: pin the transaction to the client's DPoP key, so /token
    // can reject a captured authorization code redeemed under a different key
    // (§11.9).
    tx.dpop_jkt = params.dpop_jkt.clone();
```

- [ ] **Step 4: Fix the existing `AuthorizeParams` literals**

Every construction of `AuthorizeParams` (including this module's `valid_params()` helper and `crates/foundry/src/server.rs`'s `authorize_handler`) needs `dpop_jkt: None` — or, in the handler, the real query value. Find them:

```bash
grep -rn "AuthorizeParams {" --include=*.rs crates/
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib authorize 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Wire the HTTP query parameter**

In `crates/foundry/src/server.rs`, add to `AuthorizeQuery`:

```rust
    /// RFC 9449 §10: JWK Thumbprint of the wallet's DPoP key.
    #[serde(default)]
    dpop_jkt: Option<String>,
```

and pass it through in `authorize_handler`'s `AuthorizeParams` construction:

```rust
        dpop_jkt: q.dpop_jkt,
```

Update the `#[utoipa::path]` annotation on `authorize_handler` to document the new parameter, matching the style of the existing `params(...)` entries:

```rust
        ("dpop_jkt" = Option<String>, Query,
         description = "RFC 9449 §10: JWK Thumbprint (SHA-256, base64url) of the \
                        wallet's DPoP proof-of-possession key. OPTIONAL, but when \
                        present the token request MUST present a DPoP proof for \
                        that same key."),
```

- [ ] **Step 7: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green. If `crates/foundry/tests/openapi_endpoints.rs` fails, that is expected — it compares the committed specs against the generated ones and they are regenerated in Task 10. Note it and continue; do **not** regenerate here, or the spec churn will be spread across commits.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-issuer/src/authorize.rs crates/foundry/src/server.rs
git commit -m "feat(issuer): accept the dpop_jkt authorization parameter (RFC 9449 section 10)

/authorize now records dpop_jkt on the transaction, pinning the issued
authorization code to the wallet's DPoP key. Sending it is OPTIONAL for
the client, but once sent, honouring it is a MUST for the AS -- the
enforcement half lands at /token in the next commit.

Shape is deliberately not validated here: a value that is not the
thumbprint of the key in the eventual proof simply fails that
comparison, so validating here would add a redundant second failure
mode for one mistake."
```

---
## Task 7: `/token` binds the key (RFC 9449 §5, §5.2, §10)

**Files:**
- Modify: `crates/foundry-issuer/src/dpop.rs` (add `DpopPresentation`)
- Modify: `crates/foundry-issuer/src/lib.rs` (re-export it)
- Modify: `crates/foundry-issuer/src/token.rs`
- Modify: `crates/foundry/src/server.rs` (`token_handler`)
- Test: inline `#[cfg(test)]` in `token.rs`

**Interfaces:**
- Consumes: `DpopConfig` (Task 1), `IssuanceTransaction.dpop_jkt` (Task 2), `InvalidDpopProof` (Task 3), `verify_dpop_proof` (Task 4), `claim_dpop_jti` (Task 5), the `/authorize` producer (Task 6).
- Produces:
  ```rust
  pub struct DpopPresentation<'a> {
      pub scheme_is_dpop: bool,
      pub proof_jwt: Option<&'a str>,
      pub htm: &'a str,
      pub htu: &'a str,
      pub ath: Option<&'a str>,
  }
  ```
  in `dpop.rs`, re-exported from `lib.rs`. `handle_token_request` gains two parameters after `pop_header`: `dpop_cfg: &DpopConfig` and `dpop: &DpopPresentation<'_>`. Task 9 reuses `DpopPresentation` unchanged.

- [ ] **Step 1: Add `DpopPresentation`**

Append to the non-test part of `crates/foundry-issuer/src/dpop.rs`:

```rust
/// What the HTTP layer observed about one request's DPoP presentation.
///
/// A struct rather than five more positional parameters on two already-long
/// functions. Every field is supplied by `crates/foundry`, never inferred here:
/// `htu` in particular MUST come from configuration rather than a
/// client-controlled `Host` header, or an attacker could replay a proof minted
/// for a different origin.
#[derive(Debug, Clone, Copy)]
pub struct DpopPresentation<'a> {
    /// `true` when the `Authorization` scheme was `DPoP` rather than `Bearer`.
    /// Only meaningful at a protected resource; the Token Endpoint carries no
    /// access token, so `/token` ignores it.
    pub scheme_is_dpop: bool,
    /// The raw `DPoP` header value, `None` when the header was absent.
    pub proof_jwt: Option<&'a str>,
    /// The real HTTP method — §4.3 check 8.
    pub htm: &'a str,
    /// The real target URI, from configuration — §4.3 check 9.
    pub htu: &'a str,
    /// `base64url(SHA-256(access_token))` — `None` at `/token`, where no access
    /// token is presented and §4.3 check 12 does not apply.
    pub ath: Option<&'a str>,
}
```

and in `crates/foundry-issuer/src/lib.rs` extend the re-export:

```rust
pub use dpop::{access_token_hash, verify_dpop_proof, DpopPresentation, VerifiedDpopProof};
```

- [ ] **Step 2: Write the failing mode-matrix tests**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/token.rs`. Add `DpopConfig` to the `foundry_core::config` import and `crate::dpop::DpopPresentation` to the `use` list first.

```rust
    fn dpop_cfg(mode: Mode) -> DpopConfig {
        DpopConfig {
            mode,
            max_age_secs: 300,
        }
    }

    const TOKEN_HTU: &str = "https://issuer.example.com/token";

    fn no_dpop<'a>() -> DpopPresentation<'a> {
        DpopPresentation {
            scheme_is_dpop: false,
            proof_jwt: None,
            htm: "POST",
            htu: TOKEN_HTU,
            ath: None,
        }
    }

    fn with_dpop<'a>(proof: &'a str) -> DpopPresentation<'a> {
        DpopPresentation {
            scheme_is_dpop: false,
            proof_jwt: Some(proof),
            htm: "POST",
            htu: TOKEN_HTU,
            ath: None,
        }
    }

    /// A wallet's DPoP keypair plus a valid proof for `POST /token`.
    /// Returns `(proof_jwt, jkt)`.
    fn dpop_keypair_and_proof(jti: &str, now: i64) -> (String, String) {
        use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
        use josekit::jws::{JwsHeader, ES256};
        use josekit::jwt::{self, JwtPayload};

        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public = kp.to_jwk_public_key();
        public.set_key_id_deleted();

        let mut header = JwsHeader::new();
        header.set_token_type("dpop+jwt");
        header.set_jwk(public.clone());

        let mut payload = JwtPayload::new();
        payload.set_claim("htm", Some("POST".into())).unwrap();
        payload.set_claim("htu", Some(TOKEN_HTU.into())).unwrap();
        payload.set_claim("iat", Some(now.into())).unwrap();
        payload.set_claim("jti", Some(jti.into())).unwrap();

        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        let proof = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let jkt = crate::dpop::verify_dpop_proof(&proof, "POST", TOKEN_HTU, None, now, 300)
            .unwrap()
            .jkt;
        (proof, jkt)
    }

    // --- RFC 9449 §5 / §5.2 mode matrix: 3 modes x {no header, valid proof} ---

    #[tokio::test]
    async fn disabled_mode_ignores_an_absent_proof_and_issues_bearer() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-dis-none");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Disabled),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "Bearer");
        let loaded = load_transaction(&storage, "tx-dpop-dis-none").await.unwrap().unwrap();
        assert_eq!(loaded.dpop_jkt, None);
    }

    #[tokio::test]
    async fn disabled_mode_ignores_a_present_proof_rather_than_rejecting_it() {
        // RFC 9449 §10.1 encourages clients that "blindly attach the DPoP
        // header to all requests to the authorization server", and §5 lets an
        // AS signal non-binding with token_type Bearer. Rejecting here would
        // hard-fail a wallet doing exactly what the RFC recommends.
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-dis-some");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let (proof, _) = dpop_keypair_and_proof("j-dis", 1_700_000_010);
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Disabled),
            &with_dpop(&proof),
            "https://issuer.example.com",
            1_700_000_010,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "Bearer", "Disabled ignores, it does not reject");
        let loaded = load_transaction(&storage, "tx-dpop-dis-some").await.unwrap().unwrap();
        assert_eq!(loaded.dpop_jkt, None);
    }

    #[tokio::test]
    async fn optional_mode_without_a_proof_issues_bearer() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-opt-none");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "Bearer");
    }

    #[tokio::test]
    async fn optional_mode_with_a_valid_proof_issues_a_bound_dpop_token() {
        // RFC 9449 §5: "A token_type of DPoP MUST be included in the access
        // token response to signal to the client that the access token was
        // bound to its DPoP key."
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-opt-some");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let (proof, jkt) = dpop_keypair_and_proof("j-opt", 1_700_000_010);
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &with_dpop(&proof),
            "https://issuer.example.com",
            1_700_000_010,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "DPoP");
        let loaded = load_transaction(&storage, "tx-dpop-opt-some").await.unwrap().unwrap();
        assert_eq!(loaded.dpop_jkt, Some(jkt), "§6: the token must record its bound key");
    }

    #[tokio::test]
    async fn required_mode_without_a_proof_is_rejected() {
        // RFC 9449 §5.2: "the authorization server MUST reject token requests
        // from the client that do not contain the DPoP header."
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-req-none");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let e = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn required_mode_with_a_valid_proof_issues_a_dpop_token() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-req-some");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let (proof, _) = dpop_keypair_and_proof("j-req", 1_700_000_010);
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &with_dpop(&proof),
            "https://issuer.example.com",
            1_700_000_010,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "DPoP");
    }

    // --- Ordering invariants: a bad proof must not burn a code ---

    #[tokio::test]
    async fn an_invalid_dpop_proof_does_not_burn_the_pre_authorized_code() {
        // Same invariant as wrong_tx_code_does_not_burn_the_pre_authorized_code
        // and pop_replay_rejection_does_not_burn_the_pre_authorized_code: an
        // attacker probing with a forged proof must not deny the legitimate
        // holder their credential.
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-noburn");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &with_dpop("not-a-jwt"),
            "https://issuer.example.com",
            1_700_000_010,
        )
        .await
        .expect_err("a malformed proof must be rejected");

        // The code must still work for the legitimate holder.
        let (proof, _) = dpop_keypair_and_proof("j-after", 1_700_000_020);
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &with_dpop(&proof),
            "https://issuer.example.com",
            1_700_000_020,
        )
        .await
        .expect("the pre-authorized code must survive a rejected proof");
        assert_eq!(res.token_type, "DPoP");
    }

    #[tokio::test]
    async fn a_replayed_dpop_proof_is_rejected_at_the_token_endpoint() {
        // §11.1, via claim_dpop_jti.
        let storage = test_storage().await;
        for id in ["tx-dpop-replay-1", "tx-dpop-replay-2"] {
            let mut tx = sample_tx(id);
            tx.pre_authorized_code = Some(format!("code-{id}"));
            save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
                .await
                .unwrap();
        }
        let (proof, _) = dpop_keypair_and_proof("j-replayed", 1_700_000_010);

        let mut req1 = pre_auth_req();
        req1.pre_authorized_code = Some("code-tx-dpop-replay-1".to_string());
        handle_token_request(
            &storage, &req1, &disabled(), None, None,
            &dpop_cfg(Mode::Required), &with_dpop(&proof),
            "https://issuer.example.com", 1_700_000_010,
        )
        .await
        .unwrap();

        let mut req2 = pre_auth_req();
        req2.pre_authorized_code = Some("code-tx-dpop-replay-2".to_string());
        let e = handle_token_request(
            &storage, &req2, &disabled(), None, None,
            &dpop_cfg(Mode::Required), &with_dpop(&proof),
            "https://issuer.example.com", 1_700_000_010,
        )
        .await
        .expect_err("the same proof must not be usable twice");
        assert!(e.to_string().contains("jti"), "got: {e}");
    }

    // --- RFC 9449 §10: dpop_jkt pinned at /authorize ---

    #[tokio::test]
    async fn a_proof_matching_the_pinned_dpop_jkt_is_accepted() {
        let storage = test_storage().await;
        let (proof, jkt) = dpop_keypair_and_proof("j-pin-ok", 1_700_000_010);
        let mut tx = sample_auth_code_tx("tx-dpop-pin-ok");
        tx.dpop_jkt = Some(jkt.clone());
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let res = handle_token_request(
            &storage, &auth_code_req(), &disabled(), None, None,
            &dpop_cfg(Mode::Optional), &with_dpop(&proof),
            "https://issuer.example.com", 1_700_000_010,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "DPoP");
    }

    #[tokio::test]
    async fn a_proof_for_another_key_than_the_pinned_dpop_jkt_is_rejected() {
        // RFC 9449 §10: "If they do not match, it MUST reject the request."
        // §11.9: this is what stops a harvested authorization code being
        // redeemed under an attacker-controlled key.
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-dpop-pin-bad");
        tx.dpop_jkt = Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string());
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let (proof, _) = dpop_keypair_and_proof("j-pin-bad", 1_700_000_010);
        let e = handle_token_request(
            &storage, &auth_code_req(), &disabled(), None, None,
            &dpop_cfg(Mode::Optional), &with_dpop(&proof),
            "https://issuer.example.com", 1_700_000_010,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_pinned_dpop_jkt_with_no_proof_at_all_is_rejected() {
        // §10 pins the code to a key; redeeming it with no proof would silently
        // drop that binding.
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-dpop-pin-noproof");
        tx.dpop_jkt = Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string());
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let e = handle_token_request(
            &storage, &auth_code_req(), &disabled(), None, None,
            &dpop_cfg(Mode::Optional), &no_dpop(),
            "https://issuer.example.com", 1_700_000_010,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_mismatched_dpop_jkt_does_not_burn_the_authorization_code() {
        // The §10 comparison happens after the transaction loads but before
        // the code is invalidated, for the same reason as every other
        // "does_not_burn" test in this module.
        let storage = test_storage().await;
        let (good_proof, good_jkt) = dpop_keypair_and_proof("j-noburn-ok", 1_700_000_020);
        let mut tx = sample_auth_code_tx("tx-dpop-authnoburn");
        tx.dpop_jkt = Some(good_jkt);
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let (wrong_proof, _) = dpop_keypair_and_proof("j-noburn-bad", 1_700_000_010);
        handle_token_request(
            &storage, &auth_code_req(), &disabled(), None, None,
            &dpop_cfg(Mode::Optional), &with_dpop(&wrong_proof),
            "https://issuer.example.com", 1_700_000_010,
        )
        .await
        .expect_err("wrong key must be rejected");

        handle_token_request(
            &storage, &auth_code_req(), &disabled(), None, None,
            &dpop_cfg(Mode::Optional), &with_dpop(&good_proof),
            "https://issuer.example.com", 1_700_000_020,
        )
        .await
        .expect("the authorization code must survive a rejected proof");
    }
```

> This module's existing tests build their `TokenRequest` inline. If there is no `pre_auth_req()` helper, add one that returns the same `TokenRequest` the existing `handles_valid_token_request_and_issues_access_token_and_nonce` builds, and reuse the existing `auth_code_req()` / `sample_auth_code_tx()` as-is. Do not duplicate fixtures under new names.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p foundry-issuer --lib token 2>&1 | tail -20`
Expected: FAIL — `handle_token_request` takes 7 arguments but 9 were supplied.

- [ ] **Step 4: Extend `handle_token_request`**

In `crates/foundry-issuer/src/token.rs`, add the imports:

```rust
use crate::dpop::{claim_dpop_jti, verify_dpop_proof, DpopPresentation};
use foundry_core::config::{AttestationMode, DpopConfig, Mode};
```

Change the signature (the existing `#[allow(clippy::too_many_arguments)]` already covers the additions):

```rust
pub async fn handle_token_request(
    storage: &dyn Storage,
    req: &TokenRequest,
    wallet_attestation: &AttestationMode,
    attestation_header: Option<&str>,
    pop_header: Option<&str>,
    dpop_cfg: &DpopConfig,
    dpop: &DpopPresentation<'_>,
    issuer_identifier: &str,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
```

Immediately **after** the existing Wallet Attestation / `claim_pop_jti` / `client_id` block and **before** the `match req.grant_type.as_str()`, insert:

```rust
    // RFC 9449 §5: resolve the DPoP key this token will be bound to, if any.
    //
    // Deliberately before any grant work — like `claim_pop_jti` above — so a
    // replayed or forged proof can never burn a legitimate holder's
    // pre-authorized or authorization code.
    let dpop_jkt = match (&dpop_cfg.mode, dpop.proof_jwt) {
        // §5: "An authorization server MAY elect to issue access tokens that
        // are not DPoP bound." Disabled ignores the header rather than
        // rejecting it — §10.1 encourages clients that attach it to every AS
        // call, and §5 already gives us `token_type: Bearer` to signal
        // non-binding.
        (Mode::Disabled, _) => None,
        (Mode::Optional, None) => None,
        // §5.2 (`dpop_bound_access_tokens: true`): "the authorization server
        // MUST reject token requests from the client that do not contain the
        // DPoP header."
        (Mode::Required, None) => {
            return Err(IssuanceError::InvalidDpopProof(
                "a DPoP proof is required at this Token Endpoint".into(),
            ));
        }
        (Mode::Optional | Mode::Required, Some(proof_jwt)) => {
            let verified = verify_dpop_proof(
                proof_jwt,
                dpop.htm,
                dpop.htu,
                // §4.3 check 12 does not apply at the Token Endpoint: no
                // access token is being presented.
                None,
                now_unix,
                dpop_cfg.max_age_secs,
            )
            .inspect_err(|e| {
                tracing::warn!(error.kind = e.kind(), "dpop proof rejected");
            })?;
            // §11.1 single-use.
            claim_dpop_jti(storage, &verified, dpop_cfg.max_age_secs, now_unix).await?;
            // A thumbprint, so loggable per root AGENTS.md §4.5.
            tracing::info!(jkt = %verified.jkt, "dpop proof accepted");
            Some(verified.jkt)
        }
    };

    match req.grant_type.as_str() {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
            handle_pre_authorized_code_grant(storage, req, dpop_jkt, now_unix).await
        }
        "authorization_code" => {
            handle_authorization_code_grant(storage, req, dpop_jkt, now_unix).await
        }
        _ => Err(IssuanceError::InvalidGrant(
            "unsupported_grant_type".to_string(),
        )),
    }
```

(replacing the existing `match req.grant_type.as_str()` block).

- [ ] **Step 5: Thread `dpop_jkt` through both grant handlers**

Give `handle_pre_authorized_code_grant` and `handle_authorization_code_grant` a `dpop_jkt: Option<String>` parameter after `req`. In **each**, immediately after the transaction is loaded and before any code is invalidated, insert:

```rust
    // RFC 9449 §10: "the authorization server computes the JWK Thumbprint of
    // the proof-of-possession public key in the DPoP proof and verifies that
    // it matches the dpop_jkt parameter value in the authorization request. If
    // they do not match, it MUST reject the request."
    //
    // Checked before the code is invalidated so a wrong-key attempt cannot
    // burn the legitimate holder's code (§11.9 is the attack this closes).
    if let Some(pinned) = &tx.dpop_jkt {
        if dpop_jkt.as_deref() != Some(pinned.as_str()) {
            return Err(IssuanceError::InvalidDpopProof(
                "the DPoP proof key does not match the dpop_jkt pinned at the \
                 Authorization Endpoint"
                    .into(),
            ));
        }
    }
```

and change each handler's tail call to `mint_and_save_tokens(storage, tx, dpop_jkt, now_unix).await`.

- [ ] **Step 6: Bind the key in `mint_and_save_tokens`**

```rust
/// Shared by both grant branches: mint a fresh access_token, persist it on
/// `tx`, and return the wire `TokenResponse`.
///
/// `dpop_jkt` is `Some` when a valid RFC 9449 DPoP proof accompanied the
/// request. It is recorded on the transaction (§6's "other methods of
/// associating a public key with an access token ... per an agreement by the
/// authorization server and the protected resource" — here that agreement is
/// internal, since both are this process sharing one `Storage`) and it selects
/// the `token_type` (§5).
async fn mint_and_save_tokens(
    storage: &dyn Storage,
    mut tx: IssuanceTransaction,
    dpop_jkt: Option<String>,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let access_token = format!("at_{}", Uuid::new_v4().simple());
    let expires_in = 600u64;

    tx.access_token = Some(access_token.clone());
    // §6: the binding the Credential Endpoint will check. Overwrites any §10
    // pin with the same value — Step 5 has already proved them equal.
    tx.dpop_jkt = dpop_jkt.clone();

    save_transaction_with_indices(storage, &tx, expires_in, now_unix).await?;

    Ok(TokenResponse {
        access_token,
        // RFC 9449 §5: "A token_type of DPoP MUST be included in the access
        // token response to signal to the client that the access token was
        // bound to its DPoP key."
        token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_string(),
        expires_in,
    })
}
```

Also update `TokenResponse.token_type`'s doc comment so it no longer implies `Bearer` is the only value.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib token 2>&1 | tail -30`
Expected: PASS — the 12 new tests plus every pre-existing `token.rs` test. The pre-existing ones need `&dpop_cfg(Mode::Optional), &no_dpop()` added to their `handle_token_request` calls; that is the only change they need, and their assertions (`token_type == "Bearer"`) must remain untouched. If any pre-existing assertion has to change, the defaults are wrong — fix the implementation, not the test.

- [ ] **Step 8: Wire the HTTP layer**

In `crates/foundry/src/server.rs`'s `token_handler`, after the existing `attestation_hdr` / `pop_hdr` extraction:

```rust
    // RFC 9449 §4.3 check 1: "There is not more than one DPoP HTTP request
    // header field." `exactly_one_header` is the same guard ABCA §6.2 needs,
    // and for the same reason: `HeaderMap::get` silently returns only the
    // first of several.
    let dpop_hdr = exactly_one_header(&headers, "DPoP").map_err(|e| wallet_error_response(&e))?;
```

and replace the `handle_token_request` call:

```rust
    let dpop_presentation = foundry_issuer::DpopPresentation {
        scheme_is_dpop: false,
        proof_jwt: dpop_hdr,
        htm: "POST",
        // From configuration, never from the Host header: a client-controlled
        // Host would let an attacker replay a proof minted for another origin.
        htu: &format!("{}/token", issuer_identifier.trim_end_matches('/')),
        ath: None,
    };

    foundry_issuer::handle_token_request(
        state.storage.as_ref(),
        &req,
        &state.config.issuer.wallet_attestation,
        attestation_hdr,
        pop_hdr,
        &state.config.issuer.dpop,
        &dpop_presentation,
        &issuer_identifier,
        now,
    )
    .await
    .map(Json)
    .map_err(|e| wallet_error_response(&e))
```

> The `htu` `format!` needs to outlive the borrow — bind it to a `let htu = format!(...);` above the struct and reference that, rather than inlining a temporary.

Add the header to the `#[utoipa::path]` `params(...)` block:

```rust
        ("DPoP" = Option<String>, Header,
         description = "RFC 9449 §4.1 DPoP proof JWT. Required when \
                        issuer.dpop.mode is `required`. When present and valid, \
                        the issued access token is bound to the proof's key and \
                        the response carries `token_type: DPoP`. MUST appear at \
                        most once (§4.3 check 1)."),
```

and a `400` response note for `invalid_dpop_proof`.

- [ ] **Step 9: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green except a known `openapi_endpoints.rs` failure (specs regenerate in Task 10).

- [ ] **Step 10: Commit**

```bash
git add crates/foundry-issuer/src/ crates/foundry/src/server.rs
git commit -m "feat(issuer): bind access tokens to a DPoP key at /token (RFC 9449)

handle_token_request gains a DpopConfig and a DpopPresentation and
implements the section 5 / 5.2 mode matrix: Disabled ignores the header,
Optional binds when a proof is present, Required rejects its absence.
A bound token gets token_type DPoP per section 5 and records its jkt on
the transaction per section 6.

Also enforces section 10: when /authorize pinned a dpop_jkt, the proof's
thumbprint MUST match it. Both that comparison and proof verification
happen before any code is invalidated, so a forged or wrong-key proof
cannot burn a legitimate holder's code -- the same ordering invariant
the tx_code and PoP-replay paths already hold, and section 11.9 is the
attack it closes.

section 4.3 check 1 (at most one DPoP header) lands in server.rs via the
existing exactly_one_header helper. htu comes from configuration, never
from the Host header, so a proof minted for another origin cannot be
replayed here."
```

---
## Task 8: Advertise DPoP support in AS metadata (RFC 9449 §5.1)

**Files:**
- Modify: `crates/foundry-issuer/src/metadata.rs`
- Modify: `crates/foundry/tests/wallet_metadata.rs`
- Test: inline `#[cfg(test)]` in `metadata.rs` + the integration test

**Interfaces:**
- Consumes: `DpopConfig` (Task 1).
- Produces: `AuthorizationServerMetadata.dpop_signing_alg_values_supported: Vec<String>`.

`build_authorization_server_metadata` already takes `&Config`, so no signature change.

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/metadata.rs`:

```rust
#[test]
fn advertises_dpop_signing_algs_when_dpop_is_enabled() {
    // RFC 9449 §5.1: dpop_signing_alg_values_supported is "A JSON array
    // containing a list of the JWS alg values supported by the authorization
    // server for DPoP proof JWTs". Its presence is the support signal.
    let mut cfg = test_config();
    cfg.issuer.dpop.mode = Mode::Optional;
    let md = build_authorization_server_metadata(&cfg);
    assert_eq!(md.dpop_signing_alg_values_supported, vec!["ES256".to_string()]);
}

#[test]
fn advertises_dpop_signing_algs_under_required_mode_too() {
    let mut cfg = test_config();
    cfg.issuer.dpop.mode = Mode::Required;
    let md = build_authorization_server_metadata(&cfg);
    assert_eq!(md.dpop_signing_alg_values_supported, vec!["ES256".to_string()]);
}

#[test]
fn omits_dpop_signing_algs_when_dpop_is_disabled() {
    // Advertising support while ignoring every proof would be a lie: a wallet
    // reading this field would conclude it can sender-constrain when it cannot.
    let mut cfg = test_config();
    cfg.issuer.dpop.mode = Mode::Disabled;
    let md = build_authorization_server_metadata(&cfg);
    assert!(md.dpop_signing_alg_values_supported.is_empty());

    // skip_serializing_if means an empty vec is absent from the wire, not `[]`.
    let json = serde_json::to_value(&md).unwrap();
    assert!(
        json.get("dpop_signing_alg_values_supported").is_none(),
        "an empty list MUST be omitted, not serialized as []"
    );
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p foundry-issuer --lib metadata 2>&1 | tail -20`
Expected: FAIL — `no field dpop_signing_alg_values_supported`.

- [ ] **Step 3: Add the field and populate it**

In `crates/foundry-issuer/src/metadata.rs`, add to `AuthorizationServerMetadata`:

```rust
    /// RFC 9449 §5.1: "A JSON array containing a list of the JWS alg values
    /// (from the [IANA.JOSE.ALGS] registry) supported by the authorization
    /// server for DPoP proof JWTs."
    ///
    /// Omitted entirely when `issuer.dpop.mode` is `Disabled` — the field's
    /// presence *is* the support signal, so advertising it while ignoring every
    /// proof would tell a wallet it can sender-constrain when it cannot.
    /// Contrast `authorization_response_iss_parameter_supported` above, which
    /// RFC 9207 §2.3 wants present-and-true unconditionally.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dpop_signing_alg_values_supported: Vec<String>,
```

and in `build_authorization_server_metadata`:

```rust
        dpop_signing_alg_values_supported: if cfg.issuer.dpop.mode == Mode::Disabled {
            Vec::new()
        } else {
            // ES256 only: it is what josekit verification is wired for
            // throughout this crate, and HAIP's crypto-suites section mandates
            // it for every JWS in this profile.
            vec!["ES256".to_string()]
        },
```

Add `Mode` to the file's `foundry_core::config` import if it is not already there.

- [ ] **Step 4: Run them to verify they pass**

Run: `cargo test -p foundry-issuer --lib metadata 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Add the integration assertion**

In `crates/foundry/tests/wallet_metadata.rs`, extend the existing AS-metadata
test — the one whose request URI is `/.well-known/oauth-authorization-server`
and which already asserts on `json["issuer"]` and `json["token_endpoint"]`.
Note the variable is `json`; `body` in that test holds the raw byte buffer, so
asserting on `body[...]` would not compile.

```rust
    // RFC 9449 §5.1 — HAIP OpenID4VCI L163 requires DPoP support, and this
    // field is how a wallet discovers it. The harness builds the default
    // config, so mode is Optional here (Task 1) and the field must be present.
    assert_eq!(
        json["dpop_signing_alg_values_supported"],
        serde_json::json!(["ES256"])
    );
```

- [ ] **Step 6: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green except the known `openapi_endpoints.rs` failure.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-issuer/src/metadata.rs crates/foundry/tests/wallet_metadata.rs
git commit -m "feat(issuer): advertise dpop_signing_alg_values_supported (RFC 9449 section 5.1)

ES256 when issuer.dpop.mode is optional or required; omitted entirely
under disabled, since the field's presence is itself the support signal
and advertising it while ignoring every proof would tell a wallet it can
sender-constrain when it cannot.

Deliberately unlike authorization_response_iss_parameter_supported,
which RFC 9207 section 2.3 wants present-and-true unconditionally."
```

---
## Task 9: `/credential` enforces the binding (RFC 9449 §6, §7, §7.1, §7.2)

**Files:**
- Modify: `crates/foundry-issuer/src/credential.rs`
- Modify: `crates/foundry/src/server.rs` (`credential_handler`, new `credential_error_response`)
- Modify: `crates/foundry/tests/wallet_issuance.rs`
- Test: inline `#[cfg(test)]` in `credential.rs` + the integration test

**Interfaces:**
- Consumes: `DpopPresentation` (Task 7), `verify_dpop_proof` + `access_token_hash` (Task 4), `claim_dpop_jti` (Task 5), `IssuanceTransaction.dpop_jkt` (Task 2), `DpopConfig` (Task 1).
- Produces: `handle_credential_request` gains a `dpop: &DpopPresentation<'_>` parameter after `access_token`. `config` is already a parameter, so `DpopConfig` needs no separate one.

The five-row decision table from the design's §5.3 is the whole of this task.

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/credential.rs`. Reuse this module's existing fixtures (`test_config`, `test_storage`, and whatever it uses to build an `Offered` transaction with an access token); add only the DPoP-specific helpers:

```rust
    const CRED_HTU: &str = "https://issuer.example.com/credential";

    fn bearer_presentation<'a>() -> DpopPresentation<'a> {
        DpopPresentation {
            scheme_is_dpop: false,
            proof_jwt: None,
            htm: "POST",
            htu: CRED_HTU,
            ath: None,
        }
    }

    /// A `DPoP`-scheme presentation carrying `proof` and the `ath` for `token`.
    fn dpop_presentation<'a>(proof: Option<&'a str>, ath: &'a str) -> DpopPresentation<'a> {
        DpopPresentation {
            scheme_is_dpop: true,
            proof_jwt: proof,
            htm: "POST",
            htu: CRED_HTU,
            ath: Some(ath),
        }
    }

    /// A DPoP proof for `POST /credential` bound to `access_token`.
    /// Returns `(proof_jwt, jkt)`.
    fn credential_proof(access_token: &str, jti: &str, now: i64) -> (String, String) {
        use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
        use josekit::jws::{JwsHeader, ES256};
        use josekit::jwt::{self, JwtPayload};

        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public = kp.to_jwk_public_key();
        public.set_key_id_deleted();

        let mut header = JwsHeader::new();
        header.set_token_type("dpop+jwt");
        header.set_jwk(public);

        let ath = crate::dpop::access_token_hash(access_token);
        let mut payload = JwtPayload::new();
        payload.set_claim("htm", Some("POST".into())).unwrap();
        payload.set_claim("htu", Some(CRED_HTU.into())).unwrap();
        payload.set_claim("iat", Some(now.into())).unwrap();
        payload.set_claim("jti", Some(jti.into())).unwrap();
        payload.set_claim("ath", Some(ath.clone().into())).unwrap();

        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        let proof = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let jkt = crate::dpop::verify_dpop_proof(
            &proof, "POST", CRED_HTU, Some(&ath), now, 300,
        )
        .unwrap()
        .jkt;
        (proof, jkt)
    }

    // --- The design's §5.3 decision table, one test per row ---

    #[tokio::test]
    async fn an_unbound_token_with_the_bearer_scheme_is_accepted() {
        // Row 1: today's path. This is the regression that proves DPoP is
        // additive and does not break existing wallets.
        let cfg = test_config();
        let storage = test_storage().await;
        let token = seed_offered_tx_with_token(&storage, "tx-cred-bearer", None).await;

        let res = handle_credential_request(
            &cfg, &storage, &token, &sample_request(), &nonce_secret(),
            &bearer_presentation(), 1_700_000_000,
        )
        .await;
        assert!(res.is_ok(), "an unbound token must still work with Bearer");
    }

    #[tokio::test]
    async fn a_bound_token_presented_as_bearer_is_rejected() {
        // Row 2 / §7.2: "such a protected resource MUST reject a DPoP-bound
        // access token received as a bearer token." Without this, an attacker
        // holding a stolen bound token downgrades to Bearer and the binding
        // buys nothing.
        let cfg = test_config();
        let storage = test_storage().await;
        let token = seed_offered_tx_with_token(
            &storage, "tx-cred-downgrade", Some("some-jkt".to_string()),
        )
        .await;

        let e = handle_credential_request(
            &cfg, &storage, &token, &sample_request(), &nonce_secret(),
            &bearer_presentation(), 1_700_000_000,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_bound_token_with_a_matching_proof_is_accepted() {
        // Row 3 / §7.1 + §4.3 check 12.
        let cfg = test_config();
        let storage = test_storage().await;
        // Seed with a placeholder, then re-seed with the real jkt once known.
        let token = "at_cred_dpop_ok";
        let (proof, jkt) = credential_proof(token, "j-cred-ok", 1_700_000_000);
        seed_offered_tx_with_exact_token(&storage, "tx-cred-ok", token, Some(jkt)).await;

        let ath = crate::dpop::access_token_hash(token);
        let res = handle_credential_request(
            &cfg, &storage, token, &sample_request(), &nonce_secret(),
            &dpop_presentation(Some(&proof), &ath), 1_700_000_000,
        )
        .await;
        assert!(res.is_ok(), "a matching proof must be accepted: {res:?}");
    }

    #[tokio::test]
    async fn a_bound_token_with_another_keys_proof_is_rejected() {
        // Row 3 negative / §7.1: "check that the public key of the DPoP proof
        // matches the public key to which the access token is bound". This is
        // the check that makes a stolen token useless.
        let cfg = test_config();
        let storage = test_storage().await;
        let token = "at_cred_dpop_wrongkey";
        let (proof, _wrong_jkt) = credential_proof(token, "j-cred-wrong", 1_700_000_000);
        seed_offered_tx_with_exact_token(
            &storage, "tx-cred-wrongkey", token,
            Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string()),
        )
        .await;

        let ath = crate::dpop::access_token_hash(token);
        let e = handle_credential_request(
            &cfg, &storage, token, &sample_request(), &nonce_secret(),
            &dpop_presentation(Some(&proof), &ath), 1_700_000_000,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_bound_token_with_no_proof_at_all_is_rejected() {
        // Row 4 / §7: "Requests to DPoP-protected resources MUST include both
        // a DPoP proof as per Section 4 and the access token."
        let cfg = test_config();
        let storage = test_storage().await;
        let token = seed_offered_tx_with_token(
            &storage, "tx-cred-noproof", Some("some-jkt".to_string()),
        )
        .await;

        let ath = crate::dpop::access_token_hash(&token);
        let e = handle_credential_request(
            &cfg, &storage, &token, &sample_request(), &nonce_secret(),
            &dpop_presentation(None, &ath), 1_700_000_000,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn an_unbound_token_with_the_dpop_scheme_is_rejected() {
        // Row 5 — a DELIBERATE DEVIATION, stricter than RFC 9449, which leaves
        // this case undefined. Accepting it would let a wallet conclude it has
        // sender-constraining when the token has no bound key at all: the same
        // false assurance §5's "the client MUST discard the response" language
        // exists to prevent. Fail-closed.
        let cfg = test_config();
        let storage = test_storage().await;
        let token = "at_cred_unbound_dpop";
        let (proof, _) = credential_proof(token, "j-cred-unbound", 1_700_000_000);
        seed_offered_tx_with_exact_token(&storage, "tx-cred-unbound", token, None).await;

        let ath = crate::dpop::access_token_hash(token);
        let e = handle_credential_request(
            &cfg, &storage, token, &sample_request(), &nonce_secret(),
            &dpop_presentation(Some(&proof), &ath), 1_700_000_000,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_credential_proof_replayed_at_the_credential_endpoint_is_rejected() {
        // §11.1 again, this time at the protected resource. Note the offer is
        // single-use anyway, so this asserts the *proof* is rejected on its own
        // terms rather than incidentally by the state check -- hence a fresh
        // transaction bound to the same key for the second attempt.
        let cfg = test_config();
        let storage = test_storage().await;
        let token = "at_cred_replay";
        let (proof, jkt) = credential_proof(token, "j-cred-replay", 1_700_000_000);
        let ath = crate::dpop::access_token_hash(token);

        seed_offered_tx_with_exact_token(&storage, "tx-cred-replay-1", token, Some(jkt.clone()))
            .await;
        handle_credential_request(
            &cfg, &storage, token, &sample_request(), &nonce_secret(),
            &dpop_presentation(Some(&proof), &ath), 1_700_000_000,
        )
        .await
        .unwrap();

        // A different transaction, same token value and same bound key, so the
        // only thing that can reject the second call is the jti claim.
        seed_offered_tx_with_exact_token(&storage, "tx-cred-replay-2", token, Some(jkt)).await;
        let e = handle_credential_request(
            &cfg, &storage, token, &sample_request(), &nonce_secret(),
            &dpop_presentation(Some(&proof), &ath), 1_700_000_000,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("jti"), "got: {e}");
    }
```

> This module's existing tests already seed transactions with access tokens. Add the two seeding helpers (`seed_offered_tx_with_token` returning the generated token, and `seed_offered_tx_with_exact_token` taking a caller-chosen one) as **thin wrappers over the module's existing fixture**, not as reimplementations — the credential path depends on `credential_configuration_id`, `status_list_index` and claim shape, and duplicating that setup is how these tests drift from the real one.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p foundry-issuer --lib credential 2>&1 | tail -20`
Expected: FAIL — `handle_credential_request` takes 6 arguments but 7 were supplied.

- [ ] **Step 3: Implement the table**

In `crates/foundry-issuer/src/credential.rs`, add the imports and the parameter:

```rust
use crate::dpop::{claim_dpop_jti, verify_dpop_proof, DpopPresentation};
```

```rust
pub async fn handle_credential_request(
    config: &Config,
    storage: &dyn Storage,
    access_token: &str,
    req: &CredentialRequest,
    nonce_secret: &NonceSecret,
    dpop: &DpopPresentation<'_>,
    now_unix: i64,
) -> Result<CredentialResponse, IssuanceError> {
```

Immediately **after** the transaction loads and the `IssuanceState::Offered` check, and **before** the `credential_configuration_id` validation:

```rust
    // RFC 9449 §6/§7: enforce the access token's key binding before doing any
    // issuance work. `tx.dpop_jkt` is how this resource server "reliably
    // identif[ies] whether an access token is DPoP-bound" (§6) — the AS and the
    // resource server are this same process sharing one `Storage`, which is the
    // "agreement by the authorization server and the protected resource" §6
    // permits as an alternative to a JWT `cnf.jkt` or introspection.
    match (&tx.dpop_jkt, dpop.scheme_is_dpop) {
        // Unbound token, Bearer scheme: the pre-DPoP path, unchanged.
        (None, false) => {}

        // §7.2: "such a protected resource MUST reject a DPoP-bound access
        // token received as a bearer token." Without this, an attacker holding
        // a stolen bound token simply downgrades to Bearer.
        (Some(_), false) => {
            return Err(IssuanceError::InvalidDpopProof(
                "this access token is DPoP-bound and MUST be presented with the DPoP scheme"
                    .into(),
            ));
        }

        // Deliberate deviation, stricter than RFC 9449, which leaves this case
        // undefined: accepting it would let a wallet conclude it has
        // sender-constraining when the token has no bound key at all — the
        // false assurance §5's "the client MUST discard the response" language
        // exists to prevent. Fail-closed.
        (None, true) => {
            return Err(IssuanceError::InvalidDpopProof(
                "this access token is not DPoP-bound and MUST be presented with the Bearer scheme"
                    .into(),
            ));
        }

        (Some(bound_jkt), true) => {
            // §7: "Requests to DPoP-protected resources MUST include both a
            // DPoP proof as per Section 4 and the access token."
            let proof_jwt = dpop.proof_jwt.ok_or_else(|| {
                IssuanceError::InvalidDpopProof(
                    "a DPoP proof is required when presenting a DPoP-bound access token".into(),
                )
            })?;
            // §7: "The DPoP proof MUST include the ath claim with a valid hash
            // of the associated access token." Absent `ath` here would be a
            // caller bug, not a client one — the HTTP layer always computes it.
            let expected_ath = dpop.ath.ok_or_else(|| {
                IssuanceError::Internal("dpop presentation is missing the computed ath".into())
            })?;

            let verified = verify_dpop_proof(
                proof_jwt,
                dpop.htm,
                dpop.htu,
                Some(expected_ath),
                now_unix,
                config.issuer.dpop.max_age_secs,
            )
            .inspect_err(|e| {
                tracing::warn!(error.kind = e.kind(), "dpop proof rejected at /credential");
            })?;

            // §4.3 check 12, second half / §7.1: "confirm that the public key
            // to which the access token is bound matches the public key from
            // the DPoP proof." This is the check that makes a stolen access
            // token useless without the private key.
            if &verified.jkt != bound_jkt {
                return Err(IssuanceError::InvalidDpopProof(
                    "the DPoP proof key does not match the key this access token is bound to"
                        .into(),
                ));
            }

            // §11.1 single-use, scoped to this endpoint's htu.
            claim_dpop_jti(storage, &verified, config.issuer.dpop.max_age_secs, now_unix).await?;
            // A thumbprint, so loggable per root AGENTS.md §4.5.
            tracing::info!(jkt = %verified.jkt, "dpop-bound access token accepted");
        }
    }
```

> `issuer.dpop.mode` is deliberately **not** consulted here. The binding is a property of the token that was already issued, not of current policy: flipping the config to `Disabled` must not retroactively let already-bound tokens be presented as Bearer. `tx.dpop_jkt` is the only authority.

- [ ] **Step 4: Run them to verify they pass**

Run: `cargo test -p foundry-issuer --lib credential 2>&1 | tail -30`
Expected: PASS. Pre-existing `credential.rs` tests need `&bearer_presentation()` inserted into their calls and nothing else.

- [ ] **Step 5: Write the failing integration tests**

These go in `crates/foundry/tests/wallet_issuance.rs`, which uses
`tower::ServiceExt::oneshot` against `wallet_router(state)` — **not** a reqwest
test server. Match that idiom exactly.

No new spawn helper is needed: `setup_test_app()` builds a default `Config`, and
Task 1 made `issuer.dpop.mode` default to `Optional`, which is the mode these
tests want.

First the two helpers, modelled on the existing `issue_offer_and_get_access_token`
and `create_proof`:

```rust
/// Mint a DPoP proof JWT for `method $htu`, optionally binding it to an access
/// token via `ath` (RFC 9449 §4.2, §7). Reuses `kp` so a caller can prove
/// possession of the same key at `/token` and then at `/credential`.
fn create_dpop_proof(
    kp: &EcKeyPair,
    method: &str,
    htu: &str,
    jti: &str,
    access_token: Option<&str>,
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("dpop+jwt");
    let mut public = kp.to_jwk_public_key();
    public.set_key_id_deleted();
    header.set_jwk(public);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut payload = JwtPayload::new();
    payload.set_claim("htm", Some(method.into())).unwrap();
    payload.set_claim("htu", Some(htu.into())).unwrap();
    payload.set_claim("iat", Some(now.into())).unwrap();
    payload.set_claim("jti", Some(jti.into())).unwrap();
    if let Some(at) = access_token {
        // §7: "The DPoP proof MUST include the ath claim with a valid hash of
        // the associated access token."
        let ath = foundry_issuer::access_token_hash(at);
        payload.set_claim("ath", Some(ath.into())).unwrap();
    }

    let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

/// Like `issue_offer_and_get_access_token`, but presents a DPoP proof at
/// `/token` so the returned token is key-bound. Returns the token and the
/// keypair it is bound to, and asserts §5's `token_type: DPoP`.
async fn issue_offer_and_get_dpop_bound_access_token(
    state: &AppState,
) -> (String, EcKeyPair) {
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": { "given_name": "Alice" },
        "tx_code_required": false
    });
    let offer_req = Request::builder()
        .method("POST")
        .uri("/admin/issuance/offers")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(offer_req_body.to_string()))
        .unwrap();
    let offer_res = admin_app.oneshot(offer_req).await.unwrap();
    assert_eq!(offer_res.status(), StatusCode::OK);
    let offer_bytes = axum::body::to_bytes(offer_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let offer_json: serde_json::Value = serde_json::from_slice(&offer_bytes).unwrap();
    let pre_auth_code = offer_json["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .unwrap();

    let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/token",
        "dpop-token-1",
        None,
    );

    let token_form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
    );
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("DPoP", proof)
        .body(Body::from(token_form_body))
        .unwrap();

    let token_res = wallet_router(state.clone()).oneshot(token_req).await.unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    assert_eq!(
        token_json["token_type"], "DPoP",
        "RFC 9449 §5: a key-bound token MUST be signalled with token_type DPoP"
    );

    (
        token_json["access_token"].as_str().unwrap().to_string(),
        kp,
    )
}
```

then the §7.1 / §7.2 test:

```rust
/// RFC 9449 §7.2: "such a protected resource MUST reject a DPoP-bound access
/// token received as a bearer token." §7.1 makes that rejection a 401 with a
/// `WWW-Authenticate: DPoP` challenge whose `algs` tells the wallet what to
/// sign with — not the 400 the Bearer paths use.
#[tokio::test]
async fn credential_endpoint_rejects_a_downgraded_dpop_token_with_a_401_challenge() {
    let (state, _dir) = setup_test_app().await;
    let (access_token, _kp) = issue_offer_and_get_dpop_bound_access_token(&state).await;
    let c_nonce = mint_c_nonce(&state).await;
    let (proof_jwt, _) = create_proof(&c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });

    // Deliberately downgraded: a bound token presented with the Bearer scheme.
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(cred_req_body.to_string()))
        .unwrap();

    let cred_res = wallet_router(state.clone()).oneshot(cred_req).await.unwrap();
    assert_eq!(
        cred_res.status(),
        StatusCode::UNAUTHORIZED,
        "§7.1: a DPoP binding failure is a 401, not a 400"
    );
    let challenge = cred_res
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("§7.1 requires a WWW-Authenticate challenge")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        challenge.starts_with("DPoP"),
        "§7.1: the scheme name is DPoP, got: {challenge}"
    );
    assert!(challenge.contains(r#"error="invalid_token""#), "got: {challenge}");
    assert!(challenge.contains(r#"algs="ES256""#), "got: {challenge}");
}
```

- [ ] **Step 6: Wire the HTTP layer**

In `crates/foundry/src/server.rs`, replace `credential_handler`'s hardcoded `strip_prefix("Bearer ")` with scheme-aware parsing, and change its error type so a header can be attached:

```rust
/// Split an `Authorization` header into its scheme and credentials.
///
/// RFC 9449 §7.1 uses the same `token68` credentials syntax as Bearer
/// (RFC 6750 §2.1), so one splitter serves both. Any scheme other than `DPoP`
/// or `Bearer` — and a header with no scheme at all — is rejected before the
/// transaction is even looked up, preserving today's behaviour for malformed
/// `Authorization` headers.
fn parse_authorization(header: &str) -> Result<(bool, &str), foundry_issuer::IssuanceError> {
    let (scheme, credentials) = header.split_once(' ').ok_or_else(|| {
        foundry_issuer::IssuanceError::InvalidGrant("malformed authorization header".into())
    })?;
    let credentials = credentials.trim();
    if credentials.is_empty() {
        return Err(foundry_issuer::IssuanceError::InvalidGrant(
            "empty authorization credentials".into(),
        ));
    }
    // RFC 9110 §11.1: the scheme is case-insensitive.
    if scheme.eq_ignore_ascii_case("DPoP") {
        Ok((true, credentials))
    } else if scheme.eq_ignore_ascii_case("Bearer") {
        Ok((false, credentials))
    } else {
        Err(foundry_issuer::IssuanceError::InvalidGrant(
            "unsupported authorization scheme".into(),
        ))
    }
}

/// Error mapper for the Credential Endpoint, which is a **protected resource**
/// and therefore answers DPoP failures per RFC 9449 §7.1 rather than §5.
///
/// Every non-DPoP error keeps its existing `wallet_error_response` mapping —
/// `/credential` returning 400 for a missing `Authorization` header is a
/// pre-existing question RFC 9449 does not reach, and widening it here would
/// break unrelated tests for no conformance gain.
///
/// Emits exactly one log record per error either way (root `AGENTS.md` §4.5).
fn credential_error_response(
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    if matches!(e, foundry_issuer::IssuanceError::InvalidDpopProof(_)) {
        log_typed_error("wallet", e.kind(), e, StatusCode::UNAUTHORIZED);
        let mut headers = HeaderMap::new();
        // §7.1: scheme name DPoP, an `error` parameter, and an `algs` parameter
        // "to signal to the client the JWS algorithms that are acceptable for
        // the DPoP proof JWT".
        if let Ok(v) = axum::http::HeaderValue::from_str(
            r#"DPoP error="invalid_token", error_description="DPoP binding check failed", algs="ES256""#,
        ) {
            headers.insert(axum::http::header::WWW_AUTHENTICATE, v);
        }
        return (
            StatusCode::UNAUTHORIZED,
            headers,
            Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": e.to_string(),
            })),
        );
    }
    let (status, body) = wallet_error_response(e);
    (status, HeaderMap::new(), body)
}
```

then the handler itself:

```rust
async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Result<Json<CredentialResponse>, (StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            credential_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
                "missing authorization header".into(),
            ))
        })?;

    let (scheme_is_dpop, access_token) =
        parse_authorization(auth_header).map_err(|e| credential_error_response(&e))?;

    // RFC 9449 §4.3 check 1.
    let dpop_hdr =
        exactly_one_header(&headers, "DPoP").map_err(|e| credential_error_response(&e))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // §7: ath is always computed here, so the engine never has to.
    let ath = foundry_issuer::access_token_hash(access_token);
    let credential_issuer = state.config.issuer.credential_issuer.trim_end_matches('/');
    let htu = format!("{credential_issuer}/credential");
    let dpop = foundry_issuer::DpopPresentation {
        scheme_is_dpop,
        proof_jwt: dpop_hdr,
        htm: "POST",
        htu: &htu,
        ath: Some(&ath),
    };

    foundry_issuer::handle_credential_request(
        &state.config,
        state.storage.as_ref(),
        access_token,
        &req,
        state.nonce_secret.as_ref(),
        &dpop,
        now,
    )
    .await
    .map(Json)
    .map_err(|e| credential_error_response(&e))
}
```

Update the `#[utoipa::path]` annotation with the `DPoP` header, an `Authorization` description covering both schemes, and a `401` response.

- [ ] **Step 7: Add the happy-path and duplicate-header integration tests**

Also in `crates/foundry/tests/wallet_issuance.rs`. The duplicate-header case is
the **only** place §4.3 check 1 is reachable at all, since it needs a real
`HeaderMap`:

```rust
/// The full RFC 9449 flow over HTTP: a DPoP proof at `/token` yields a bound
/// token with `token_type: DPoP` (§5), and `/credential` then accepts it when
/// presented with the `DPoP` scheme plus a second proof carrying `ath` (§7).
#[tokio::test]
async fn full_dpop_issuance_flow_over_http() {
    let (state, _dir) = setup_test_app().await;

    // 1. Offer -> /token with a DPoP proof -> a key-bound access token.
    //    (the token_type == "DPoP" assertion lives in the helper)
    let (access_token, kp) = issue_offer_and_get_dpop_bound_access_token(&state).await;

    // 2. c_nonce for the holder proof (unrelated to DPoP -- OpenID4VCI §7).
    let c_nonce = mint_c_nonce(&state).await;
    let (holder_proof, _holder_kp) = create_proof(&c_nonce, "https://issuer.example.com");

    // 3. A *fresh* DPoP proof for this endpoint, bound to the access token via
    //    ath. A distinct jti from the /token one, since §11.1 makes each
    //    single-use, and a distinct htu, which §4.3 check 9 requires.
    let cred_dpop = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/credential",
        "dpop-credential-1",
        Some(&access_token),
    );

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [holder_proof] },
    });
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        // §7.1: a bound token is presented with the DPoP scheme, not Bearer.
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
        .header("DPoP", cred_dpop)
        .body(Body::from(cred_req_body.to_string()))
        .unwrap();

    let cred_res = wallet_router(state.clone()).oneshot(cred_req).await.unwrap();
    assert_eq!(cred_res.status(), StatusCode::OK);

    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();
    let credential_str = cred_json["credentials"][0]["credential"].as_str().unwrap();
    assert!(!credential_str.is_empty());
    // SD-JWT VC concatenates disclosures with `~`.
    assert!(credential_str.contains('~'));
}

/// RFC 9449 §4.3 check 1: "There is not more than one DPoP HTTP request header
/// field." Unreachable from the engine's unit tests, which take a single &str —
/// this is the only test that covers it.
#[tokio::test]
async fn two_dpop_headers_at_the_token_endpoint_are_rejected() {
    let (state, _dir) = setup_test_app().await;

    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("DPoP", "first")
        .header("DPoP", "second")
        .body(Body::from(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code",
        ))
        .unwrap();

    let res = wallet_router(state.clone()).oneshot(token_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Rejected on the duplicate header alone, before the grant is even looked
    // at -- so it must not surface as invalid_grant.
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_ne!(json["error"], "invalid_grant", "got: {json}");
}

/// RFC 9449 §4.3 check 1 again, at the protected resource.
#[tokio::test]
async fn two_dpop_headers_at_the_credential_endpoint_are_rejected() {
    let (state, _dir) = setup_test_app().await;
    let (access_token, _kp) = issue_offer_and_get_dpop_bound_access_token(&state).await;

    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
        .header("DPoP", "first")
        .header("DPoP", "second")
        .body(Body::from(
            serde_json::json!({
                "credential_configuration_id": "pid",
                "format": "dc+sd-jwt",
            })
            .to_string(),
        ))
        .unwrap();

    let res = wallet_router(state.clone()).oneshot(cred_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
```

> Both helpers are built on this file's **existing** primitives
> (`setup_test_app`, `admin_router`/`wallet_router` + `oneshot`, `mint_c_nonce`,
> `create_proof`). Do not introduce a second harness or a reqwest client — this
> file has neither.

- [ ] **Step 8: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green except the known `openapi_endpoints.rs` failure. If `logging_redaction.rs` fails, a DPoP proof or an access token is reaching a log line — fix the logging, not the test.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry-issuer/src/credential.rs crates/foundry/src/server.rs crates/foundry/tests/wallet_issuance.rs
git commit -m "feat(issuer): enforce DPoP binding at /credential (RFC 9449 sections 6, 7)

/credential now parses the Authorization scheme instead of hardcoding
Bearer, computes ath, and enforces the five-case table:

- unbound + Bearer   -> accept (unchanged)
- bound   + Bearer   -> reject, section 7.2 anti-downgrade
- bound   + DPoP     -> verify proof, match ath, match jkt, claim jti
- bound   + no proof -> reject, section 7
- unbound + DPoP     -> reject (deliberate deviation, fail-closed)

The last case is stricter than RFC 9449, which leaves it undefined:
accepting it would let a wallet believe it has sender-constraining when
the token has no bound key at all.

issuer.dpop.mode is deliberately not consulted here -- the binding is a
property of the already-issued token, so flipping config to disabled
must not retroactively allow bound tokens to be presented as Bearer.

DPoP failures answer with 401 + WWW-Authenticate: DPoP error=invalid_token
algs=ES256 per section 7.1. Scoped strictly to DPoP failures: the
existing Bearer paths keep their 400 mapping, which RFC 9449 does not
reach."
```

---
## Task 10: Close the gap in the record + Full Gate

**Files:**
- Modify: `crates/foundry-issuer/tests/conformance_vci.rs`
- Modify: `docs/conformance/openid4vc-conformance.md`
- Modify: `AGENTS.md` (§4.4 spec table)
- Modify: `crates/foundry-issuer/AGENTS.md`
- Modify: `README.md`
- Regenerate: `openapi.json`, `openapi-wallet.json`
- Create: `docs/superpowers/changes/2026-08-03-dpop-sender-constrained-tokens.md`

**Interfaces:** none — documentation and the conformance record. Closing a gap means updating the record, not only the code (root `AGENTS.md` §8).

- [ ] **Step 1: Rewrite the conformance test that cites the gap**

In `crates/foundry-issuer/tests/conformance_vci.rs`, `haip_0009_token_response_uses_dpop_token_type` currently asserts `token_type == "DPoP"` for a token request that carries **no** DPoP header. That assertion is itself non-conformant — RFC 9449 §5 says `Bearer` is correct when no proof is presented. Keep the name (the conformance report cites it) and correct the body:

```rust
// ---------------------------------------------------------------------------
// HAIP-0009 — HAIP OpenID4VCI (L163): MUST support DPoP per RFC9449 for
// sender-constrained access tokens.
//
// The assertion is "a DPoP proof yields a DPoP-bound token", not "every token
// is DPoP" -- RFC 9449 §5 explicitly permits `Bearer` when no proof is
// presented, and an AS "MAY elect to issue access tokens that are not DPoP
// bound". This test therefore exercises both halves.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn haip_0009_token_response_uses_dpop_token_type() {
    let cfg = test_config();
    let storage = test_storage().await;

    // Half 1: a request with a valid DPoP proof gets a bound token.
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code = resp
        .credential_offer
        .grants
        .pre_authorized_code
        .unwrap()
        .pre_authorized_code;

    let (proof, jkt) = dpop_proof_for_token_endpoint("haip-0009", 1_700_000_010);
    let token = handle_token_request(
        &storage,
        &pre_auth_token_request(code),
        &disabled_attestation(),
        None,
        None,
        &dpop_optional(),
        &dpop_presentation(Some(&proof)),
        "https://issuer.example.com",
        1_700_000_010,
    )
    .await
    .unwrap();

    assert_eq!(
        token.token_type, "DPoP",
        "RFC 9449 §5: a token bound to a DPoP key MUST carry token_type DPoP"
    );

    // Half 2: without a proof, Bearer remains correct (§5).
    let resp2 = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code2 = resp2
        .credential_offer
        .grants
        .pre_authorized_code
        .unwrap()
        .pre_authorized_code;
    let bearer = handle_token_request(
        &storage,
        &pre_auth_token_request(code2),
        &disabled_attestation(),
        None,
        None,
        &dpop_optional(),
        &dpop_presentation(None),
        "https://issuer.example.com",
        1_700_000_010,
    )
    .await
    .unwrap();
    assert_eq!(
        bearer.token_type, "Bearer",
        "RFC 9449 §5: an AS MAY issue non-bound tokens, signalled as Bearer"
    );

    // The bound token records its key (§6) -- the property /credential checks.
    let tx = load_transaction_by_access_token(&storage, &token.access_token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tx.dpop_jkt, Some(jkt));
}
```

**Delete the `#[ignore]` attribute.** Add the local helpers (`dpop_proof_for_token_endpoint`, `dpop_optional`, `dpop_presentation`, `pre_auth_token_request`) mirroring Task 7 Step 2's, and add a `mismatched_dpop_jkt` case if this file already groups §10 coverage; otherwise leave §10 to `token.rs`'s unit tests.

- [ ] **Step 2: Run it to verify it passes**

Run: `cargo test -p foundry-issuer --test conformance_vci haip_0009 2>&1 | tail -20`
Expected: PASS, and **not** reported as ignored.

- [ ] **Step 3: Update the conformance report**

In `docs/conformance/openid4vc-conformance.md`:

**(a)** Flip the `HAIP-0009` inventory row from `gap` to `conforming` and replace its evidence:

```
| HAIP-0009 | OpenID4VCI (L163) | MUST support DPoP per RFC9449 for sender-constrained access tokens | issuer | `conforming` | Closed 2026-08-03 (GAP-HAIP-03). `dpop.rs` implements RFC 9449 §4.3 checks 2-9 and 11-12 plus §11.1 `jti` replay defence; `handle_token_request` implements the §5/§5.2 mode matrix via `issuer.dpop.mode`, records the §6 `jkt` binding on the transaction and sets `token_type: "DPoP"`; `handle_credential_request` enforces §7/§7.1/§7.2 including the anti-downgrade rule; `/authorize` accepts and `/token` enforces the §10 `dpop_jkt` pin; AS metadata advertises `dpop_signing_alg_values_supported` per §5.1. §8/§9 server-provided nonces are deliberately not implemented (a MAY -- see RFC-9449-0008) | haip_0009_token_response_uses_dpop_token_type, optional_mode_with_a_valid_proof_issues_a_bound_dpop_token, a_bound_token_presented_as_bearer_is_rejected, a_proof_for_another_key_than_the_pinned_dpop_jkt_is_rejected |
```

**(b)** **Delete** the `GAP-HAIP-03` row from the Gap Register table.

**(c)** In the Summary table, adjust the HAIP row: `gap` 2 → 1, `conforming` 53 → 54. Re-count from the inventory rather than trusting these numbers — if they no longer match, the discrepancy predates this change and should be reported, not silently papered over.

**(d)** Rewrite `VCI-0163`'s evidence. It is currently `conforming` by a *vacuous* precondition and its note points at `GAP-HAIP-03`, which no longer exists:

```
| VCI-0163 | Security / Protecting the Access Token (L1527) | Long-lived Access Tokens MUST NOT be issued unless sender-constrained | issuer | `conforming` | Satisfied on both independent grounds. (1) `mint_and_save_tokens` (token.rs) sets `expires_in: 600` unconditionally, so no access token is ever "long-lived" and this clause's precondition never triggers. (2) Since GAP-HAIP-03's closure the requirement is also met substantively: an access token can be sender-constrained via RFC 9449 DPoP (`issuer.dpop.mode`), which HAIP-0009 mandates unconditionally and which this row's narrower conditional mandate is a subset of | handles_valid_token_request_and_issues_access_token_and_nonce, optional_mode_with_a_valid_proof_issues_a_bound_dpop_token |
```

**(e)** Append new RFC 9449 rows. RFC 9449 is not one of the three inventoried specs, so per the report's own stated convention (see its note on late-discovered clauses) these are appended in their own short section rather than renumbered into an existing sequence. Cover at minimum:

| ID | Clause | Verdict |
|---|---|---|
| RFC-9449-0001 | §4.3 checks 1–9, 11–12 (validating a proof) | `conforming` |
| RFC-9449-0002 | §5 (`token_type: DPoP` on a bound token) | `conforming` |
| RFC-9449-0003 | §5.1 (`dpop_signing_alg_values_supported`) | `conforming` |
| RFC-9449-0004 | §5.2 (`dpop_bound_access_tokens` ⇒ reject requests without the header) | `conforming` |
| RFC-9449-0005 | §6 (resource server can identify the binding) | `conforming` |
| RFC-9449-0006 | §7 / §7.1 (proof + `ath` required at a protected resource) | `conforming` |
| RFC-9449-0007 | §7.2 (reject a bound token presented as Bearer) | `conforming` |
| RFC-9449-0008 | §8 / §9 (server-provided `DPoP-Nonce`) | `not-implemented` — a MAY; §11.2's named compensating control (short-lived tokens) holds, since foundry's are fixed at 600 s and non-renewable. §11.3 satisfied vacuously |
| RFC-9449-0009 | §10 (`dpop_jkt` authorization parameter) | `conforming` |
| RFC-9449-0010 | §10.1 (PAR interaction) | `out-of-scope` — no `/par` endpoint (HAIP-0007) |
| RFC-9449-0011 | §5 (refresh-token binding) | `out-of-scope` — foundry issues no refresh tokens |
| RFC-9449-0012 | §6.2 (introspection) | `out-of-scope` — no remote resource server |
| RFC-9449-0013 | §11.1 (`jti` replay tracking) | `conforming` |

Give each a real evidence string naming the function and test, in the same voice as the surrounding rows. Also record the §5.3 `(None, true)` **deliberate deviation** — a stricter-than-spec rejection — as an explicit note on RFC-9449-0007, since root `AGENTS.md` §4.4 requires deviations to be documented rather than silent.

- [ ] **Step 4: Add RFC 9449 to the pinned-spec table**

In root `AGENTS.md` §4.4, add a row (the file is checked in but unlisted), worded like the ABCA draft row:

```
| [`rfc9449-dpop.txt`](docs/specs/rfc9449-dpop.txt) | DPoP — the sender-constrained access token mechanism HAIP OpenID4VCI L163 mandates by reference (`MUST support DPoP as defined in [@!RFC9449]`); `foundry-issuer`'s `dpop.rs`, the `/token` route and the `/credential` route. Where HAIP defers to RFC 9449, RFC 9449 governs. Kept as `.txt`, not `.md` — verbatim fidelity to the RFC text is the point of a pinned spec. |
```

- [ ] **Step 5: Update the crate AGENTS.md**

In `crates/foundry-issuer/AGENTS.md`:

**(a)** Module map — add:

```
| `dpop.rs` | RFC 9449 DPoP: proof JWT validation (§4.3 checks 2-9, 11-12), `htu` normalisation, RFC 7638 `jkt` computation, and `jti` replay claiming (§11.1) under KV namespace `dpop_jti` |
```

**(b)** Entry-point table — update `handle_token_request`'s signature to the 9-parameter form and `handle_credential_request`'s to include `dpop`.

**(c)** Public surface — add `verify_dpop_proof`, `VerifiedDpopProof`, `DpopPresentation`, `access_token_hash`, and `IssuanceError::InvalidDpopProof`.

**(d)** Gotchas — add these four, since each is a decision a future reader would otherwise "fix" wrongly:

- **`issuer.dpop.mode: Disabled` ignores the `DPoP` header; it does not reject it.** RFC 9449 §10.1 encourages clients that attach `DPoP` to every AS call, and §5 provides `token_type: Bearer` precisely to signal non-binding. Rejecting would hard-fail a conformant wallet.
- **`IssuanceTransaction.dpop_jkt` is written at two stages and means the same thing at both** — "the key this flow is pinned to". `/authorize` writes the §10 request parameter; `/token` overwrites it with the verified proof's thumbprint (having first proved them equal). Not two overloaded uses of one field.
- **`/credential` never consults `issuer.dpop.mode`.** The binding is a property of the already-issued token, so flipping config to `Disabled` must not retroactively let bound tokens be presented as Bearer. `tx.dpop_jkt` is the only authority.
- **An unbound token presented with the `DPoP` scheme is rejected — a deliberate deviation.** RFC 9449 leaves the case undefined; accepting it would let a wallet believe it has sender-constraining when the token has no bound key. Fail-closed, approved in the design doc's §5.3.
- **Two of §4.3's checks are not in `dpop.rs` and that is correct.** Check 1 (single `DPoP` header) needs the header map and lives in `server.rs`'s `exactly_one_header`; check 10 (`nonce`) is vacuous because no §8/§9 nonce is ever supplied, which also satisfies §11.3 by construction.

- [ ] **Step 6: Document the config in README.md**

Add `issuer.dpop` to the configuration reference, next to `wallet_attestation`:

```toml
[issuer.dpop]
# RFC 9449 sender-constrained access tokens.
#   optional (default) — bind when the wallet sends a DPoP proof, else Bearer
#   required           — reject token requests with no DPoP proof
#   disabled           — ignore the DPoP header, always Bearer
mode = "optional"
# How far from now a proof's `iat` may sit, in either direction (clock skew).
max_age_secs = 300
```

If the "Logging & Observability" section enumerates log fields, note that `jkt` may appear (an RFC 7638 thumbprint) and that the proof JWT, `ath` and `jti` never do.

- [ ] **Step 7: Regenerate the OpenAPI specs**

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
```

Then confirm the comparison test that has been failing since Task 6 now passes:

```bash
cargo test -p foundry --test openapi_endpoints
```
Expected: PASS. Review the diff: it should show only the `DPoP` header on `/token` and `/credential`, the `dpop_jkt` query parameter on `/authorize`, the new `401` response, and `dpop_signing_alg_values_supported` on the AS metadata schema. Anything else means an unintended annotation change.

- [ ] **Step 8: Write the change record**

Create `docs/superpowers/changes/2026-08-03-dpop-sender-constrained-tokens.md` covering: what closed (`GAP-HAIP-03`, `HAIP-0009`), the four scope decisions and their rejected alternatives, the deliberate deviation, what is knowingly **not** implemented (§8/§9 nonces, refresh-token binding, PAR, introspection) with the reasoning, and the config surface. Follow the structure of `docs/superpowers/changes/2026-08-03-conformance-tier4-fixes.md`.

- [ ] **Step 9: Run the FULL GATE — once**

This is the one and only place the full gate runs (root `AGENTS.md` §5.3). `cargo fmt` **applies** first, so the suite runs against an already-formatted tree:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: all green, including the E2E suite (which runs the default `Optional` config with no proof, i.e. the unchanged Bearer path).

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "docs: close GAP-HAIP-03 in the conformance record

HAIP-0009 flips gap -> conforming; the GAP-HAIP-03 register row is
removed and the HAIP summary counts adjusted. VCI-0163's evidence is
rewritten: it was conforming only by a vacuous precondition and its note
pointed at a gap that no longer exists, so it now records both grounds.

New RFC-9449-* rows inventory the clauses foundry implements and the
four it knowingly declines (section 8/9 nonces as a MAY, refresh-token
binding, PAR, introspection), each with its reasoning, plus the
section 5.3 stricter-than-spec deviation.

RFC 9449 added to the root AGENTS.md section 4.4 pinned-spec table; it
was checked in but unlisted. Crate AGENTS.md gains dpop.rs, the updated
signatures and five gotchas. OpenAPI specs regenerated.

Full gate run once at the end of the branch per AGENTS.md section 5.3:
workspace tests, the ignored E2E suite, and clippy all green."
```

---

## Self-Review

Run after all ten tasks, before requesting the final review.

**Spec coverage** — every design section maps to a task:

| Design § | Task |
|---|---|
| §2.1 enforcement tri-state | 1, 7 |
| §2.2 no server nonce | 4 (documented), 10 (RFC-9449-0008 row) |
| §2.3 `dpop_jkt` | 6 (record), 7 (enforce) |
| §2.4 binding on the transaction | 2, 7, 9 |
| §3.1 `dpop.rs` | 4, 5 |
| §3.2 call sites | 7, 9 |
| §4.1 config | 1 |
| §4.2 `dpop_jkt` field | 2 |
| §4.3 authorize/token plumbing | 6, 7 |
| §4.4 AS metadata | 8 |
| §4.5 OpenAPI | 10 |
| §5.1 the twelve checks | 4 (2-9, 11-12), 7+9 (check 1), 4 (check 10 vacuous) |
| §5.1 replay | 5 |
| §5.2 `/token` flow | 7 |
| §5.3 `/credential` table | 9 |
| §6.1 error taxonomy | 3, 7, 9 |
| §6.2 achieved / not achieved | 10 |
| §7 testing | every task's own steps |
| §8 documentation | 10 |

**Placeholder scan** — two defects were found and fixed inline during this review:

1. Task 9's integration tests were originally written against a reqwest-style
   `srv.client.post(...)` harness that **does not exist** in this repository.
   `crates/foundry/tests/wallet_issuance.rs` drives the app with
   `tower::ServiceExt::oneshot` against `wallet_router(state)` and builds
   requests with `Request::builder()`. Rewritten to that idiom, on top of the
   file's real helpers (`setup_test_app`, `mint_c_nonce`, `create_proof`).
2. `full_dpop_issuance_flow_over_http`'s body was elided behind a comment.
   Now written out in full, and the duplicate-`DPoP`-header case (§4.3 check 1)
   is covered at **both** endpoints rather than only `/token`.

A third simplification fell out of the first fix: no `spawn_wallet_server_with_dpop`
helper is needed at all. `setup_test_app()` builds a default `Config`, and Task 1
makes `issuer.dpop.mode` default to `Optional` — exactly the mode these tests
require. Only a `Required`-mode integration test would need a config override,
and none is specified.

**Type consistency** — checked across tasks:

- `VerifiedDpopProof { jkt, jti, htu }` — defined Task 4, consumed Tasks 5, 7, 9. `htu` is the normalised value at every use.
- `DpopPresentation { scheme_is_dpop, proof_jwt, htm, htu, ath }` — defined Task 7 Step 1, used Tasks 7 and 9 identically.
- `claim_dpop_jti(storage, &VerifiedDpopProof, max_age_secs, now_unix)` — one signature, both call sites.
- `access_token_hash(&str) -> String` — defined Task 4, used Tasks 9 (engine + handler).
- `handle_token_request` — 9 parameters, `dpop_cfg` then `dpop` after `pop_header`; consistent in Tasks 7 and 10.
- `handle_credential_request` — `dpop` after `nonce_secret`, before `now_unix`; consistent in Tasks 9 and 10.
- `DpopConfig { mode, max_age_secs }` — Task 1; read in 7, 8, 9.
- `IssuanceError::InvalidDpopProof` / `kind() == "invalid_dpop_proof"` — Task 3; asserted in 4, 5, 7, 9.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-08-03-dpop-sender-constrained-tokens-plan.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — a fresh subagent per task, reviewed between tasks, fast iteration. Per root `AGENTS.md` §7: Tasks 1, 2, 3, 6, 8 are `mechanical-implementer` (1–2 files, complete spec); Tasks 4, 5, 7, 9, 10 are `integration-implementer` (multi-file, crypto, HTTP wiring). Every task is gated by `task-reviewer`, and `final-reviewer` runs once at the end.

**2. Inline Execution** — execute tasks in this session using `superpowers:executing-plans`, batching with checkpoints for review.

**Which approach?**
