# EMVCo DPC Credential Type Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make foundry able to issue a schema-valid EMVCo Digital Payment Credential (`vct = com.emvco.dpc.card`) as an SD-JWT VC, by closing three generic gaps in its SD-JWT VC issuance path and shipping the credential type as configuration.

**Architecture:** Three additive, vendor-neutral changes — an optional `sub`, a `required` flag on claim definitions decoupled from `selectively_disclosable`, and a configurable credential lifetime. The DPC type itself is then pure configuration in the quickstart template; no code in the tree mentions EMVCo, DPC, or Google.

**Tech Stack:** Rust (Cargo workspace), `serde` / `serde_yaml` for config, `serde_json` for claim values, `tokio` + `#[tokio::test]` for async tests, `tempfile` for fixtures.

**Design doc:** [`docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md`](../specs/2026-08-05-emvco-dpc-credential-type-design.md)

## Global Constraints

- **Scoped gate only, per root `AGENTS.md` §5.1.** Never run `cargo test --workspace`. Each task names the exact `-p` set to run. The §5.3 full gate runs once, at the end, by whoever closes the branch.
- **No `.unwrap()`, `.expect()`, `panic!()` or `unreachable!()` in request paths** (root `AGENTS.md` §4.1). Permitted only under `#[cfg(test)]` and in `tests/`.
- **`#[tracing::instrument]` must carry `skip_all`** (§4.5). No new instrumented functions are added by this plan, but do not remove `skip_all` from any you touch.
- **Cite the spec in code comments** for protocol-facing behaviour (§4.4). For this plan the EMVCo reference is `docs/specs/emvco-dpc-schema-framework.md` (created in Task 6); until then, comments may reference it by that path.
- **`cargo fmt` before every commit.** `cargo fmt --check` must be clean.
- **Clippy with `-D warnings`** on the crates you touched: `cargo clippy -p <crate> --all-targets -- -D warnings`.
- **Exact default values, copied verbatim from the design doc:** `required` absent resolves to `!selectively_disclosable`; `validity_seconds` absent resolves to `31_536_000`; the DPC type's `validity_seconds` is `43200`.
- **Commit messages:** conventional prefixes as used in this repo (`feat(core):`, `feat(issuer):`, `test(issuer):`, `docs:`).

---

## File Structure

| File | Change | Responsibility after the change |
|---|---|---|
| `crates/foundry-sd-jwt-vc/src/builder.rs` | Modify | `IssuerClaims.sub` is `Option<String>`; `build_sd_jwt_vc` omits the `sub` payload key when `None` |
| `crates/foundry-core/src/config/model.rs` | Modify | `ClaimDef.required: Option<bool>` + `is_required()`; `CredentialType.validity_seconds: Option<u64>` + `resolved_validity_seconds()` |
| `crates/foundry-core/src/config/validate.rs` | Modify | Rejects `validity_seconds: Some(0)` and `path: []` at startup |
| `crates/foundry-issuer/src/create_offer.rs` | Modify | Presence validation gates on `is_required()`, not on `!selectively_disclosable` |
| `crates/foundry-issuer/src/credential.rs` | Modify | Passes `sub: None`; computes `exp` from `resolved_validity_seconds()` |
| `crates/foundry/src/commands.rs` | Modify | `QUICKSTART_CONFIG` gains the `com.emvco.dpc.card` credential type with three locales |
| `crates/foundry/tests/quickstart_config.rs` | **Create** | Asserts the generated quickstart config loads, validates, and carries both credential types with the DPC shape intact |
| `docs/specs/emvco-dpc-schema-framework.md` | **Create** | Non-redistributable external reference stub + restated interface facts |

**Mechanical blast radius** (adding a field to a `Deserialize` struct still breaks every Rust struct literal):

| Struct | Literal sites | Affected files |
|---|---|---|
| `IssuerClaims` | 32 | `foundry-sd-jwt-vc` (4), `foundry-issuer` (1), `foundry-verifier` (21), `foundry/tests` (9) |
| `ClaimDef` | 18 | `foundry-core` (1), `foundry-issuer` (7), `foundry/tests` (10) |
| `CredentialType` | 28 | `foundry-core` (9), `foundry-issuer` (8), `foundry/tests` (11) |

These are compiler-driven edits. In each task, `cargo build --workspace --all-targets` enumerates every site; do not attempt a blind regex, because `sub:` and `selectively_disclosable:` also appear in *other* structs (`StatusListTokenClaims`, wallet-attestation JWT payloads) and in YAML string literals.

**Note on affected crates:** `foundry-verifier` holds 21 `IssuerClaims` literals in its test module, so Task 1's gate includes `-p foundry-verifier`. The design doc's §6 test list omits it; this plan is the correct set.

---

## Task 1: Make `sub` optional and omit it by default

**Files:**
- Modify: `crates/foundry-sd-jwt-vc/src/builder.rs:11` (field), `:41` (payload insert), test module (new tests)
- Modify: `crates/foundry-sd-jwt-vc/src/verifier.rs:409,449` (test literals)
- Modify: `crates/foundry-sd-jwt-vc/tests/sdjwt_tests.rs:56` (`make_claims` helper)
- Modify: `crates/foundry-issuer/src/credential.rs:398` (production call site)
- Modify: `crates/foundry-verifier/src/verify.rs` (21 test literals)
- Modify: `crates/foundry/tests/wallet_verification.rs` (8 test literals), `crates/foundry/tests/conformance_http.rs:1102` (1 test literal)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `pub struct IssuerClaims { pub sub: Option<String>, .. }`. `build_sd_jwt_vc(claims: IssuerClaims, signer: &dyn Signer, x5c: Option<Vec<String>>) -> Result<String, FormatError>` — signature unchanged; behaviour changes so that the payload contains a `sub` key **iff** `claims.sub.is_some()`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block at the bottom of `crates/foundry-sd-jwt-vc/src/builder.rs`:

```rust
    /// Decode the issuer JWT payload out of an issuer presentation
    /// (`<header>.<payload>.<sig>~<disclosure>~...`).
    fn payload_of(presentation: &str) -> serde_json::Map<String, serde_json::Value> {
        use base64::Engine as _;
        let jwt = presentation.split('~').next().expect("issuer jwt segment");
        let b64 = jwt.split('.').nth(1).expect("jwt payload segment");
        let bytes = B64URL.decode(b64).expect("payload is base64url");
        serde_json::from_slice(&bytes).expect("payload is a JSON object")
    }

    fn claims_with_sub(sub: Option<String>) -> IssuerClaims {
        IssuerClaims {
            iss: "https://issuer.dev.local".to_string(),
            sub,
            iat: 1700000000,
            exp: 1800000000,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: serde_json::json!({"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}),
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: serde_json::Map::new(),
        }
    }

    /// `sub` is a unique, static, always-disclosed identifier that no consumer
    /// in this workspace reads, so it is omitted unless explicitly set. See
    /// docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md §1.2(a).
    #[test]
    fn omits_sub_when_none() {
        let signer = test_signer();
        let payload = payload_of(&build_sd_jwt_vc(claims_with_sub(None), &signer, None).unwrap());
        assert!(
            !payload.contains_key("sub"),
            "sub must be absent from the payload when IssuerClaims.sub is None, got keys {:?}",
            payload.keys().collect::<Vec<_>>()
        );
        // The rest of the payload is unaffected.
        assert_eq!(payload["iss"], "https://issuer.dev.local");
        assert_eq!(payload["vct"], "https://localhost:8443/vct/pid");
    }

    #[test]
    fn includes_sub_when_some() {
        let signer = test_signer();
        let claims = claims_with_sub(Some("did:example:123".to_string()));
        let payload = payload_of(&build_sd_jwt_vc(claims, &signer, None).unwrap());
        assert_eq!(payload["sub"], "did:example:123");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p foundry-sd-jwt-vc omits_sub_when_none 2>&1 | tail -20`
Expected: **compile error**, `mismatched types: expected `String`, found `Option<String>`` at `claims_with_sub`.

- [ ] **Step 3: Change the field type**

In `crates/foundry-sd-jwt-vc/src/builder.rs`, change line 11:

```rust
pub struct IssuerClaims {
    pub iss: String,
    /// Optional and omitted by default. A synthesised `sub` is a unique,
    /// static, always-disclosed identifier — a correlation handle no consumer
    /// in this workspace reads. Set it only when a deployment has a specific
    /// need. See docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md §1.2(a).
    pub sub: Option<String>,
    pub iat: i64,
```

- [ ] **Step 4: Make the payload insertion conditional**

In `build_sd_jwt_vc`, replace the unconditional insert:

```rust
    let mut payload = Map::new();
    payload.insert("iss".into(), Value::String(claims.iss));
    if let Some(sub) = claims.sub {
        payload.insert("sub".into(), Value::String(sub));
    }
    payload.insert("iat".into(), Value::Number(claims.iat.into()));
```

- [ ] **Step 5: Fix the production call site**

In `crates/foundry-issuer/src/credential.rs`, inside the `IssuerClaims` literal at line 396:

```rust
                let sd_claims = IssuerClaims {
                    iss: config.issuer.credential_issuer.clone(),
                    // Omitted deliberately: a per-transaction `sub` is a static
                    // correlation identifier no verifier needs. See
                    // docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md §1.2(a).
                    sub: None,
                    iat: now_unix,
```

- [ ] **Step 6: Let the compiler enumerate the remaining literals, and fix each**

Run: `cargo build --workspace --all-targets 2>&1 | grep -A3 'expected `Option<String>`' | head -80`

Every reported site is a **test** literal of the form `sub: "<something>".to_string(),`. Replace each with `sub: None,` — no test in this workspace asserts on a credential's `sub`, so none needs a value.

**Do not** use a global find-and-replace. `sub:` also appears in `StatusListTokenClaims` literals (`crates/foundry-core/src/status_list/mod.rs`, `crates/foundry/tests/wallet_verification.rs:54`) and in wallet-attestation JWT JSON payloads, where it is **required and must not change**.

Sites to expect (32 total, one of which was Step 5):
- `crates/foundry-sd-jwt-vc/src/builder.rs` — 1 (the pre-existing `builds_sd_jwt_vc_with_disclosures` test)
- `crates/foundry-sd-jwt-vc/src/verifier.rs` — 2
- `crates/foundry-sd-jwt-vc/tests/sdjwt_tests.rs` — 1 (`make_claims`)
- `crates/foundry-verifier/src/verify.rs` — 21
- `crates/foundry/tests/wallet_verification.rs` — 8
- `crates/foundry/tests/conformance_http.rs` — 1

- [ ] **Step 7: Verify the build is clean**

Run: `cargo build --workspace --all-targets 2>&1 | tail -5`
Expected: `Finished` with no errors.

- [ ] **Step 8: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-sd-jwt-vc -p foundry-verifier -p foundry-issuer -p foundry 2>&1 | tee /tmp/task1.log
grep -c FAILED /tmp/task1.log
grep '^test result:' /tmp/task1.log
```
Expected: `grep -c FAILED` prints `0`; every `test result:` line reports `ok`. `omits_sub_when_none` and `includes_sub_when_some` both pass.

- [ ] **Step 9: Clippy**

Run: `cargo clippy -p foundry-sd-jwt-vc -p foundry-verifier -p foundry-issuer -p foundry --all-targets -- -D warnings 2>&1 | tail -5`
Expected: no warnings.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "feat(sd-jwt-vc): make the credential sub claim optional and omit it by default

A synthesised sub_<transaction_id> was a unique, static, always-disclosed
identifier in every credential foundry issues -- never selectively
disclosable, so present in every presentation to every verifier. Nothing in
the workspace reads it: verify_sd_jwt_vc ignores it and no conformance clause
depends on it (every sub row in the report concerns a different JWT).

IssuerClaims.sub becomes Option<String> and build_sd_jwt_vc emits the payload
key only when Some, so the capability remains for a deployment that needs it."
```

---

## Task 2: Decouple `required` from `selectively_disclosable`

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs` (`ClaimDef` struct + new `impl ClaimDef`, test module)
- Modify: `crates/foundry-issuer/src/create_offer.rs:82-100` (the presence loop), test module
- Modify: 18 `ClaimDef` literal sites across `foundry-core`, `foundry-issuer`, `foundry/tests`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `ClaimDef { pub required: Option<bool>, .. }` and `ClaimDef::is_required(&self) -> bool`. `create_offer` rejects an offer omitting any claim for which `is_required()` is true, with `IssuanceError::ClaimValidation`.

- [ ] **Step 1: Write the failing unit tests for the resolver**

Add to the `#[cfg(test)] mod tests` block in `crates/foundry-core/src/config/model.rs`:

```rust
    /// `required` absent must reproduce the historical rule exactly:
    /// non-disclosable claims were implicitly mandatory, disclosable ones
    /// implicitly optional.
    #[test]
    fn claim_required_absent_resolves_to_the_historical_rule() {
        let disclosable = ClaimDef {
            path: vec!["given_name".to_string()],
            required: None,
            selectively_disclosable: true,
            display: vec![],
        };
        assert!(!disclosable.is_required());

        let always = ClaimDef {
            path: vec!["country".to_string()],
            required: None,
            selectively_disclosable: false,
            display: vec![],
        };
        assert!(always.is_required());
    }

    /// The combination the EMVCo DPC shape needs: mandatory AND selectively
    /// disclosable, which the historical rule could not express.
    #[test]
    fn claim_required_can_be_set_independently_of_disclosability() {
        let required_and_disclosable = ClaimDef {
            path: vec!["credential_id".to_string()],
            required: Some(true),
            selectively_disclosable: true,
            display: vec![],
        };
        assert!(required_and_disclosable.is_required());

        let optional_and_always_disclosed = ClaimDef {
            path: vec!["nickname".to_string()],
            required: Some(false),
            selectively_disclosable: false,
            display: vec![],
        };
        assert!(!optional_and_always_disclosed.is_required());
    }

    /// An omitted `required` key must deserialize, so existing config files
    /// need no edit.
    #[test]
    fn claim_def_without_required_deserializes() {
        let cd: ClaimDef =
            serde_yaml::from_str("path: [given_name]\nselectively_disclosable: true\n")
                .expect("claim def parses");
        assert_eq!(cd.required, None);
        assert!(!cd.is_required());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p foundry-core claim_required 2>&1 | tail -20`
Expected: compile error — `struct `ClaimDef` has no field named `required``.

- [ ] **Step 3: Add the field and resolver**

In `crates/foundry-core/src/config/model.rs`, replace the `ClaimDef` struct:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimDef {
    pub path: Vec<String>,
    /// Whether a value for this claim must be supplied when an offer is created.
    ///
    /// Absent resolves to `!selectively_disclosable` — exactly the rule
    /// `create_offer` applied before this field existed. Setting it explicitly
    /// decouples "mandatory" from "disclosable", which some credential types
    /// require: a claim can be mandatory in the credential's schema *and*
    /// selectively disclosable in the SD-JWT.
    #[serde(default)]
    pub required: Option<bool>,
    #[serde(default)]
    pub selectively_disclosable: bool,
    #[serde(default)]
    pub display: Vec<serde_json::Value>,
}

impl ClaimDef {
    /// Whether an offer must carry a value for this claim.
    /// See the `required` field for the default-resolution rule.
    pub fn is_required(&self) -> bool {
        self.required.unwrap_or(!self.selectively_disclosable)
    }
}
```

- [ ] **Step 4: Fix the 18 `ClaimDef` literal sites**

Run: `cargo build --workspace --all-targets 2>&1 | grep -B2 -A6 'missing field `required`' | head -60`

Add `required: None,` immediately after the `path:` line at each site. `None` preserves each site's existing behaviour by construction.

- [ ] **Step 5: Run the resolver tests — they must now pass**

Run: `cargo test -p foundry-core claim_required 2>&1 | tail -10` and `cargo test -p foundry-core claim_def_without_required 2>&1 | tail -10`
Expected: 3 tests pass.

- [ ] **Step 6: Write the failing `create_offer` tests**

Add to the `#[cfg(test)] mod tests` block in `crates/foundry-issuer/src/create_offer.rs`:

```rust
    /// A claim that is BOTH required and selectively disclosable. Before
    /// `ClaimDef::is_required` existed, `create_offer` skipped presence
    /// validation for every selectively-disclosable claim, so this offer was
    /// accepted and issued a credential missing a schema-mandatory claim.
    #[tokio::test]
    async fn a_required_selectively_disclosable_claim_must_be_supplied() {
        let mut cfg = test_config();
        cfg.credential_types[0].claims = vec![ClaimDef {
            path: vec!["credential_id".to_string()],
            required: Some(true),
            selectively_disclosable: true,
            display: vec![],
        }];
        let storage = test_storage().await;

        let err = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims: serde_json::Map::new(),
                tx_code_required: false,
                redirect_uri: None,
            },
        )
        .await
        .expect_err("an offer omitting a required claim must be rejected");

        assert!(
            matches!(err, IssuanceError::ClaimValidation(_)),
            "expected ClaimValidation, got {err:?}"
        );
    }

    /// The counterpart: a claim that is only selectively disclosable stays
    /// optional, so `pid`-style configurations keep working unchanged.
    #[tokio::test]
    async fn an_optional_selectively_disclosable_claim_may_be_omitted() {
        let mut cfg = test_config();
        cfg.credential_types[0].claims = vec![ClaimDef {
            path: vec!["card_id".to_string()],
            required: None,
            selectively_disclosable: true,
            display: vec![],
        }];
        let storage = test_storage().await;

        create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims: serde_json::Map::new(),
                tx_code_required: false,
                redirect_uri: None,
            },
        )
        .await
        .expect("an offer omitting an optional claim must be accepted");
    }
```

If `ClaimDef` is not already imported in that test module, add it to the module's `use` list.

- [ ] **Step 7: Run to verify the first test fails**

Run: `cargo test -p foundry-issuer a_required_selectively_disclosable 2>&1 | tail -20`
Expected: **FAIL** — `an offer omitting a required claim must be rejected`, because the loop still skips disclosable claims.

- [ ] **Step 8: Gate on `is_required()`**

In `crates/foundry-issuer/src/create_offer.rs`, replace the presence loop:

```rust
    // Every required claim's top-level path segment must be present.
    // "Required" is `ClaimDef::is_required()`, not `!selectively_disclosable`:
    // a claim can be mandatory in a credential's schema and still be
    // selectively disclosable in the SD-JWT.
    // (Nested-path validation remains a follow-up — see GAP-VCI-13.)
    for claim_def in &ct.claims {
        if !claim_def.is_required() {
            continue;
        }
        let top = claim_def.path.first().ok_or_else(|| {
            IssuanceError::ClaimValidation(format!(
                "credential_type '{}' has a claim with an empty path",
                ct.id
            ))
        })?;
        if !req.claims.contains_key(top) {
            return Err(IssuanceError::ClaimValidation(format!(
                "missing required claim '{top}' for credential_type '{}'",
                ct.id
            )));
        }
    }
```

- [ ] **Step 9: Run both tests to verify they pass**

Run: `cargo test -p foundry-issuer selectively_disclosable_claim 2>&1 | tail -10`
Expected: both PASS.

- [ ] **Step 10: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-core -p foundry-issuer -p foundry 2>&1 | tee /tmp/task2.log
grep -c FAILED /tmp/task2.log
grep '^test result:' /tmp/task2.log
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings 2>&1 | tail -5
```
Expected: `0` FAILED, every `test result:` line `ok`, no clippy warnings.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "feat(core): decouple claim required from selectively_disclosable

create_offer treated \"not selectively disclosable\" as \"required\", so a claim
could not be both mandatory and selectively disclosable -- a combination real
credential schemas need. An offer omitting such a claim was silently accepted
and issued an incomplete credential.

ClaimDef.required is Option<bool> resolving to !selectively_disclosable when
absent, so every existing config keeps its current semantics unchanged."
```

---

## Task 3: Make the credential lifetime configurable

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs` (`CredentialType` + `impl CredentialType`, test module)
- Modify: `crates/foundry-issuer/src/credential.rs:400` (`exp`), test module
- Modify: 28 `CredentialType` literal sites across `foundry-core`, `foundry-issuer`, `foundry/tests`

**Interfaces:**
- Consumes: `ClaimDef::is_required` exists (Task 2) — not used here, but the same file is edited, so rebase cleanly.
- Produces: `CredentialType { pub validity_seconds: Option<u64>, .. }` and `CredentialType::resolved_validity_seconds(&self) -> u64`, returning `31_536_000` when absent. `handle_credential_request` sets `exp = iat + resolved_validity_seconds()`.

- [ ] **Step 1: Write the failing resolver test**

Add to the `#[cfg(test)] mod tests` block in `crates/foundry-core/src/config/model.rs`:

```rust
    /// Absent must reproduce the value `handle_credential_request` hardcoded
    /// before this field existed: 365 days.
    #[test]
    fn credential_validity_defaults_to_one_year() {
        let yaml = format!(
            "{MINIMAL}credential_types:\n  - id: pid\n    format: dc+sd-jwt\n    vct: https://example.test/vct/pid\n"
        );
        let cfg = parse(&yaml);
        assert_eq!(cfg.credential_types[0].validity_seconds, None);
        assert_eq!(cfg.credential_types[0].resolved_validity_seconds(), 31_536_000);
    }

    #[test]
    fn credential_validity_is_settable() {
        let yaml = format!(
            "{MINIMAL}credential_types:\n  - id: dpc\n    format: dc+sd-jwt\n    vct: com.emvco.dpc.card\n    validity_seconds: 43200\n"
        );
        let cfg = parse(&yaml);
        assert_eq!(cfg.credential_types[0].resolved_validity_seconds(), 43_200);
    }
```

`MINIMAL` and `parse` already exist in that test module.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p foundry-core credential_validity 2>&1 | tail -20`
Expected: compile error — no method `resolved_validity_seconds`.

- [ ] **Step 3: Add the field and resolver**

In `crates/foundry-core/src/config/model.rs`, inside `CredentialType`, after the `claims` field:

```rust
    #[serde(default)]
    pub claims: Vec<ClaimDef>,
    /// Credential lifetime in seconds: the issued credential's `exp` is its
    /// `iat` plus this value. Absent resolves to 365 days, the value the
    /// Credential Endpoint hardcoded before this field existed. A credential's
    /// lifecycle is independent of the lifecycle of whatever it attests, so
    /// ecosystems with short-lived credentials set this explicitly.
    #[serde(default)]
    pub validity_seconds: Option<u64>,
}
```

and extend the existing `impl CredentialType`:

```rust
    /// The configured credential lifetime, or the 365-day default.
    /// See the `validity_seconds` field.
    pub fn resolved_validity_seconds(&self) -> u64 {
        self.validity_seconds.unwrap_or(31_536_000)
    }
```

- [ ] **Step 4: Fix the 28 `CredentialType` literal sites**

Run: `cargo build --workspace --all-targets 2>&1 | grep -B2 -A6 'missing field `validity_seconds`' | head -80`

Add `validity_seconds: None,` after the `claims:` field at each site.

- [ ] **Step 5: Run the resolver tests — must pass**

Run: `cargo test -p foundry-core credential_validity 2>&1 | tail -10`
Expected: 2 tests pass.

- [ ] **Step 6: Add three test helpers to `credential.rs`'s test module**

These are purely additive — `issues_sd_jwt_vc_credential_successfully` is left
**untouched**, because it also asserts the transaction state transition, which a
credential-returning helper cannot express. `base64` is already a dependency of
`foundry-issuer`, so no `Cargo.toml` change is needed.

```rust
    /// Run one full `handle_credential_request` and return the issued SD-JWT VC
    /// compact presentation, so lifetime and claim-shape tests share one setup.
    async fn issue_for_test_with_claims(
        config: &Config,
        credential_type_id: &str,
        claims: serde_json::Map<String, serde_json::Value>,
    ) -> String {
        let storage = test_storage().await;

        let tx = IssuanceTransaction {
            transaction_id: "tx-cred-1".to_string(),
            credential_type_id: credential_type_id.to_string(),
            claims,
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: None,
            status_list_index: None,
            access_token: Some("at_secret_123".to_string()),
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
        };
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let secret = test_secret();
        let nonce = minted_nonce(&secret, 1_700_000_000);
        let (proof_jwt, _) = generate_proof(&nonce, "https://issuer.example.com");

        let req = CredentialRequest {
            credential_configuration_id: Some(credential_type_id.to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proofs: Some(ProofsRequest::from_jwts(vec![proof_jwt])),
            credential_response_encryption: None,
        };

        let res = handle_credential_request(
            config,
            &storage,
            "at_secret_123",
            &req,
            &secret,
            &bearer_presentation(),
            1_700_000_010,
            false,
        )
        .await
        .unwrap();

        assert_eq!(res.credentials.len(), 1);
        res.credentials[0].credential.clone()
    }

    /// The issuer JWT payload of an SD-JWT VC issuer presentation.
    fn payload_of(presentation: &str) -> serde_json::Map<String, serde_json::Value> {
        use base64::Engine as _;
        let jwt = presentation.split('~').next().unwrap();
        let b64 = jwt.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Disclosed claim name -> value, decoded from the `~`-separated disclosures.
    fn disclosures_of(presentation: &str) -> std::collections::BTreeMap<String, serde_json::Value> {
        use base64::Engine as _;
        presentation
            .split('~')
            .skip(1)
            .filter(|s| !s.is_empty())
            .map(|d| {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(d)
                    .unwrap();
                let arr: Vec<serde_json::Value> = serde_json::from_slice(&raw).unwrap();
                (arr[1].as_str().unwrap().to_string(), arr[2].clone())
            })
            .collect()
    }
```

- [ ] **Step 6b: Write the failing `exp` test**

```rust
    /// `exp` must follow the credential type's configured lifetime rather than
    /// a hardcoded year.
    #[tokio::test]
    async fn credential_exp_follows_the_configured_validity() {
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let mut config = test_config(key_path.to_str().unwrap());
        config.credential_types[0].validity_seconds = Some(43_200);

        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));
        let credential = issue_for_test_with_claims(&config, "pid", claims).await;
        let payload = payload_of(&credential);

        let iat = payload["iat"].as_i64().expect("iat");
        let exp = payload["exp"].as_i64().expect("exp");
        assert_eq!(
            exp - iat,
            43_200,
            "exp must be iat + validity_seconds, got iat={iat} exp={exp}"
        );
        assert!(
            !payload.contains_key("sub"),
            "sub must not be present (Task 1)"
        );
    }
```

- [ ] **Step 7: Run to verify failure**

Run: `cargo test -p foundry-issuer credential_exp_follows 2>&1 | tail -20`
Expected: **FAIL** — `exp - iat` is `31536000`, not `43200`.

- [ ] **Step 8: Compute `exp` from the configured lifetime**

In `crates/foundry-issuer/src/credential.rs`, in the `IssuerClaims` literal:

```rust
                    iat: now_unix,
                    // Credential lifetime is per credential type; see
                    // CredentialType::resolved_validity_seconds.
                    exp: now_unix + cred_type.resolved_validity_seconds() as i64,
```

- [ ] **Step 9: Run to verify it passes**

Run: `cargo test -p foundry-issuer credential_exp_follows 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 10: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-core -p foundry-issuer -p foundry 2>&1 | tee /tmp/task3.log
grep -c FAILED /tmp/task3.log
grep '^test result:' /tmp/task3.log
cargo clippy -p foundry-core -p foundry-issuer -p foundry --all-targets -- -D warnings 2>&1 | tail -5
```
Expected: `0` FAILED, all `ok`, no warnings.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "feat(core): make the credential lifetime configurable per type

The Credential Endpoint hardcoded exp = iat + 365 days for every credential
type. A credential's lifecycle is independent of whatever it attests, and
ecosystems exist with far shorter windows.

CredentialType.validity_seconds is Option<u64> resolving to 31_536_000 when
absent, so existing configs are unchanged."
```

---

## Task 4: Reject unusable claim paths and zero lifetimes at startup

**Files:**
- Modify: `crates/foundry-core/src/config/validate.rs:25-51` (the credential-type loop), test module
- Modify: `crates/foundry-issuer/tests/conformance_vci.rs:1019-1039` (narrow the GAP-VCI-13 test)
- Modify: `docs/conformance/openid4vc-conformance.md:129` (narrow the GAP-VCI-13 register row)

**Interfaces:**
- Consumes: `CredentialType.validity_seconds` (Task 3), `ClaimDef.required` (Task 2).
- Produces: `Config::validate()` returns `Err(ConfigError::Validation(_))` for a credential type with `validity_seconds: Some(0)` or any `ClaimDef` with an empty `path`.

- [ ] **Step 1: Write the failing validation tests**

Add to the `#[cfg(test)] mod tests` block in `crates/foundry-core/src/config/validate.rs`, following the style of the existing `request_encryption_*` tests:

Use `cfg_with_signing_key()`, the `(Config, TempDir)` helper the existing
`request_encryption_*` tests use. **Note:** `minimal_config()` ships
`credential_types: Vec::new()`, so these tests must supply their own credential
type rather than index `[0]`.

```rust
    /// A credential whose `exp` equals its `iat` is never usable — that is a
    /// configuration error, not a policy choice.
    #[test]
    fn validity_seconds_may_not_be_zero() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.credential_types = vec![CredentialType {
            id: "dpc".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("com.emvco.dpc.card".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
            validity_seconds: Some(0),
        }];
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("validity_seconds"),
            "error must name the offending field, got: {msg}"
        );
    }

    /// An empty claims path pointer addresses nothing, so no supplied value can
    /// ever satisfy it. Catching it at startup beats failing per offer.
    /// Closes the emptiness half of GAP-VCI-13.
    #[test]
    fn claim_path_may_not_be_empty() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.credential_types = vec![CredentialType {
            id: "dpc".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("com.emvco.dpc.card".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec![],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
            validity_seconds: None,
        }];
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("path"),
            "error must name the offending field, got: {msg}"
        );
    }
```

If `CredentialType` / `ClaimDef` are not already imported in that test module, add them to its `use` list.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p foundry-core validity_seconds_may_not_be_zero claim_path_may_not_be_empty 2>&1 | tail -20`
Expected: both **FAIL** — `validate()` returned `Ok`.

- [ ] **Step 3: Add both rejections**

In `crates/foundry-core/src/config/validate.rs`, extend the existing credential-type loop. Insert immediately after the `match ct.format.as_str() { .. }` block, still inside `for ct in &self.credential_types`:

```rust
            // A zero lifetime yields exp == iat: never usable.
            if ct.validity_seconds == Some(0) {
                return Err(ConfigError::Validation(format!(
                    "credential_type '{}' has validity_seconds: 0; a credential \
                     whose exp equals its iat is never valid",
                    ct.id
                )));
            }
            // OpenID4VCI Claims Path Pointer (L2366): a claims path pointer is a
            // non-empty array. An empty path addresses no claim, so no supplied
            // value can satisfy it — reject at startup rather than per offer.
            // Closes the emptiness half of GAP-VCI-13.
            for cd in &ct.claims {
                if cd.path.is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}' has a claim with an empty 'path'; a \
                         claims path pointer must be a non-empty array",
                        ct.id
                    )));
                }
            }
```

- [ ] **Step 4: Run to verify both pass**

Run: `cargo test -p foundry-core validity_seconds_may_not_be_zero claim_path_may_not_be_empty 2>&1 | tail -10`
Expected: both PASS.

- [ ] **Step 5: Narrow the GAP-VCI-13 test**

`crates/foundry-issuer/tests/conformance_vci.rs:1019` currently asserts that `validate()` rejects an empty path — which now **passes**, so it must no longer be `#[ignore]`d for that reason. Replace the whole test with one that covers only the surviving half of the gap:

```rust
#[tokio::test]
#[ignore = "GAP-VCI-13: OpenID4VCI Claims Path Pointer (L2366) — ClaimDef.path is typed Vec<String>, so it can never represent the null (address every element of an array) or non-negative-integer (address a specific array index) path segments the claims path pointer grammar defines. The emptiness half of this gap was closed 2026-08-05 by Config::validate(); this test covers only the typing half, which remains open."]
async fn gap_vci_13_claims_path_pointer_cannot_express_null_or_index_segments() {
    // ClaimDef.path is Vec<String>. A conformant claims path pointer such as
    // ["addresses", null, "street"] or ["addresses", 0, "street"] cannot be
    // constructed at all, so there is no value to feed validate(). This test
    // documents the type-level gap and fails until `path` becomes a sequence of
    // string | null | u64 segments.
    panic!(
        "ClaimDef.path is Vec<String>; null and integer claims-path-pointer \
         segments are unrepresentable. Closing this gap requires retyping the \
         field, not a validation change."
    );
}
```

- [ ] **Step 6: Verify the ignored test is still ignored and the suite is green**

Run: `cargo test -p foundry-issuer --test conformance_vci 2>&1 | grep '^test result:'`
Expected: one `ok` line whose `ignored` count is unchanged from before this task.

- [ ] **Step 7: Narrow the gap-register row**

In `docs/conformance/openid4vc-conformance.md`, edit the `GAP-VCI-13` row (line ~129):
- Keep the `Vec<String>` typing evidence.
- Replace the "Separately, `Config::validate()` never checks that a configured `path` is non-empty…" sentence with: `The emptiness half was closed 2026-08-05: Config::validate() now rejects a credential type carrying a claim with an empty 'path'. The typing half remains open, which is why this entry survives.`
- Update the Test column to the renamed test `gap_vci_13_claims_path_pointer_cannot_express_null_or_index_segments`.

- [ ] **Step 8: Verify the conformance report's own cross-reference test still passes**

Run: `cargo test -p foundry --test conformance_report 2>&1 | grep '^test result:'`
Expected: `ok`. This test asserts every gap-register entry names a test that exists and is `#[ignore]`d citing the same gap ID — so a rename in Step 5 not mirrored in Step 7 fails here.

- [ ] **Step 9: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-core -p foundry-issuer -p foundry 2>&1 | tee /tmp/task4.log
grep -c FAILED /tmp/task4.log
grep '^test result:' /tmp/task4.log
cargo clippy -p foundry-core -p foundry-issuer --all-targets -- -D warnings 2>&1 | tail -5
```
Expected: `0` FAILED, all `ok`, no warnings.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "feat(core): reject empty claim paths and zero credential lifetimes

Both are configurations that can never work: exp == iat, and a claims path
pointer addressing nothing. The empty-path check closes the emptiness half of
GAP-VCI-13 -- previously it only surfaced per offer, at runtime. The typing
half (Vec<String> cannot express null or integer segments) remains open, so
the gap row is narrowed rather than removed."
```

---

## Task 5: Ship the DPC credential type in the quickstart

**Files:**
- Modify: `crates/foundry/src/commands.rs:312-327` (`QUICKSTART_CONFIG` `credential_types`)
- Create: `crates/foundry/tests/quickstart_config.rs`
- Modify: `crates/foundry-issuer/src/credential.rs` test module (two DPC claim-shape tests)
- Modify: `crates/foundry-issuer/src/metadata.rs` test module (multi-locale display passthrough)

**Interfaces:**
- Consumes: `ClaimDef.required` (Task 2), `CredentialType.validity_seconds` (Task 3), optional `sub` (Task 1).
- Produces: a `com.emvco.dpc.card` credential type in the generated quickstart config. No new Rust API.

- [ ] **Step 1: Write the failing quickstart-config test**

Create `crates/foundry/tests/quickstart_config.rs`:

```rust
//! The config `foundry quickstart` generates must load, validate, and carry the
//! credential types the documentation promises. Guards the template in
//! `commands.rs` against edits that make it unparseable or drop a type.

use foundry_core::config::Config;

/// Generate a real quickstart tree in a temp dir and load the config it wrote.
fn quickstart_config() -> Config {
    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("config.yaml");
    foundry::commands::quickstart(dir.path(), &config_path).expect("quickstart succeeds");
    let cfg = Config::load(&config_path).expect("generated config parses and validates");
    // Keep the temp dir alive until after load.
    std::mem::forget(dir);
    cfg
}

#[test]
fn quickstart_config_carries_both_credential_types() {
    let cfg = quickstart_config();
    let ids: Vec<&str> = cfg
        .credential_types
        .iter()
        .map(|ct| ct.id.as_str())
        .collect();
    assert!(ids.contains(&"pid"), "expected pid, got {ids:?}");
    assert!(
        ids.contains(&"com.emvco.dpc.card"),
        "expected com.emvco.dpc.card, got {ids:?}"
    );
}

/// The DPC type's shape is the whole point of shipping it: three claims, two of
/// which are mandatory *and* selectively disclosable, and a 12-hour lifetime.
#[test]
fn quickstart_dpc_type_has_the_expected_shape() {
    let cfg = quickstart_config();
    let dpc = cfg
        .credential_types
        .iter()
        .find(|ct| ct.id == "com.emvco.dpc.card")
        .expect("dpc type present");

    assert_eq!(dpc.format, "dc+sd-jwt");
    assert_eq!(dpc.vct.as_deref(), Some("com.emvco.dpc.card"));
    assert!(dpc.cryptographic_holder_binding);
    assert_eq!(dpc.resolved_validity_seconds(), 43_200);

    let claim = |name: &str| {
        dpc.claims
            .iter()
            .find(|c| c.path == vec![name.to_string()])
            .unwrap_or_else(|| panic!("claim {name} present"))
    };

    for name in ["credential_id", "network"] {
        let c = claim(name);
        assert!(c.is_required(), "{name} must be required");
        assert!(
            c.selectively_disclosable,
            "{name} must be selectively disclosable"
        );
    }

    let card_id = claim("card_id");
    assert!(!card_id.is_required(), "card_id is optional");
    assert!(card_id.selectively_disclosable);
}

/// Multiple locales, per the design doc's §4 configuration.
#[test]
fn quickstart_dpc_type_has_multiple_display_locales() {
    let cfg = quickstart_config();
    let dpc = cfg
        .credential_types
        .iter()
        .find(|ct| ct.id == "com.emvco.dpc.card")
        .expect("dpc type present");

    let locales: Vec<&str> = dpc
        .display
        .iter()
        .filter_map(|d| d.get("locale").and_then(|l| l.as_str()))
        .collect();
    for expected in ["en-US", "de-DE", "fr-FR"] {
        assert!(
            locales.contains(&expected),
            "expected locale {expected}, got {locales:?}"
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p foundry --test quickstart_config 2>&1 | tail -25`
Expected: `quickstart_config_carries_both_credential_types` FAILS — only `pid` is present.

If instead this fails to compile because `commands` is private, change `mod commands;` to `pub mod commands;` in `crates/foundry/src/lib.rs`.

- [ ] **Step 3: Add the DPC type to the quickstart template**

In `crates/foundry/src/commands.rs`, inside `QUICKSTART_CONFIG`, immediately after the `pid` type's last claim line (`        selectively_disclosable: true`) and before `verifier:`:

```yaml
  # EMVCo Digital Payment Credential. Reference:
  # docs/specs/emvco-dpc-schema-framework.md -- the claim set below is the
  # SD-JWT binding of that specification's disclosable attributes.
  - id: com.emvco.dpc.card
    format: dc+sd-jwt
    # Unlike `pid` above, this vct is a reverse-DNS identifier rather than a URL.
    # The specification fixes this exact string as the canonical credential type.
    vct: com.emvco.dpc.card
    cryptographic_holder_binding: true
    # 12 hours. A credential's lifecycle is independent of the card's.
    validity_seconds: 43200
    display:
      - { locale: en-US, name: "Payment Card", background_color: "#1A1A2E", text_color: "#FFFFFF" }
      - { locale: de-DE, name: "Zahlungskarte", background_color: "#1A1A2E", text_color: "#FFFFFF" }
      - { locale: fr-FR, name: "Carte de paiement", background_color: "#1A1A2E", text_color: "#FFFFFF" }
    claims:
      # credential_id and network are mandatory in the DPC payload schema AND
      # selectively disclosable, which is why `required` is a field separate
      # from `selectively_disclosable`.
      - path: [credential_id]
        required: true
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Credential ID" }
          - { locale: de-DE, name: "Credential-ID" }
          - { locale: fr-FR, name: "Identifiant du justificatif" }
      # A single string for one network, or an array for co-badged cards.
      - path: [network]
        required: true
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Payment Network" }
          - { locale: de-DE, name: "Zahlungsnetzwerk" }
          - { locale: fr-FR, name: "Réseau de paiement" }
      - path: [card_id]
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Card Identifier" }
          - { locale: de-DE, name: "Karten-ID" }
          - { locale: fr-FR, name: "Identifiant de carte" }
```

**Note:** the quickstart config enables status lists, so a DPC credential issued
from it carries a `status` claim that the DPC payload schema does not list. That
is a contradiction inside the specification itself (its §6 mandates status
checks). Leave status lists enabled — see the design doc §4.1.

- [ ] **Step 4: Run to verify all three tests pass**

Run: `cargo test -p foundry --test quickstart_config 2>&1 | tail -15`
Expected: 3 tests PASS (`carries_both`, `expected_shape`, `multiple_display_locales`).

- [ ] **Step 5: Write the DPC issuance claim-shape test**

Add to `crates/foundry-issuer/src/credential.rs`'s test module, reusing the `issue_for_test` helper from Task 3:

```rust
    /// A DPC-shaped credential type: `network` may be a single string or an
    /// array (co-badged cards), required claims live in the disclosures rather
    /// than the payload, and an unsupplied optional claim is absent entirely.
    #[tokio::test]
    async fn dpc_shaped_type_issues_with_claims_in_disclosures() {
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let mut config = test_config(key_path.to_str().unwrap());
        config.credential_types[0].id = "com.emvco.dpc.card".to_string();
        config.credential_types[0].vct = Some("com.emvco.dpc.card".to_string());
        config.credential_types[0].validity_seconds = Some(43_200);
        config.credential_types[0].claims = vec![
            ClaimDef {
                path: vec!["credential_id".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
            ClaimDef {
                path: vec!["network".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
            ClaimDef {
                path: vec!["card_id".to_string()],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            },
        ];

        // Co-badged: an array-valued `network`. `card_id` is deliberately not
        // supplied, so it must not appear anywhere in the credential.
        let mut claims = serde_json::Map::new();
        claims.insert(
            "credential_id".to_string(),
            serde_json::json!("urn:uuid:9f2b7a2e-3b74-4a0d-9b1a-0e6a91f5d2c8"),
        );
        claims.insert(
            "network".to_string(),
            serde_json::json!(["example_network", "example_network_2"]),
        );

        let credential = issue_for_test_with_claims(&config, "com.emvco.dpc.card", claims).await;
        let payload = payload_of(&credential);

        // Payload: vct present, no sub, the disclosable claims NOT inline.
        assert_eq!(payload["vct"], "com.emvco.dpc.card");
        assert!(!payload.contains_key("sub"), "sub must be omitted");
        assert!(
            !payload.contains_key("credential_id"),
            "a selectively-disclosable claim must not be inline in the payload"
        );
        assert!(!payload.contains_key("network"));
        assert!(payload.contains_key("_sd"), "expected _sd digests");

        let named = disclosures_of(&credential);
        assert_eq!(
            named["credential_id"],
            serde_json::json!("urn:uuid:9f2b7a2e-3b74-4a0d-9b1a-0e6a91f5d2c8")
        );
        assert_eq!(
            named["network"],
            serde_json::json!(["example_network", "example_network_2"]),
            "an array-valued network must survive as an array"
        );
        assert!(
            !named.contains_key("card_id"),
            "an unsupplied optional claim must not be disclosed"
        );
    }
```

This reuses `issue_for_test_with_claims`, `payload_of` and `disclosures_of` from
Task 3 Step 6 — no further helper work is needed.

- [ ] **Step 5b: Cover the single-network case**

The DPC schema allows `network` to be a plain string *or* an array. The test
above covers the co-badged array; this covers the single-network string, which is
the common case and a different serde path.

```rust
    /// The single-network case: `network` as a plain string, not an array.
    #[tokio::test]
    async fn dpc_shaped_type_accepts_a_single_string_network() {
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let mut config = test_config(key_path.to_str().unwrap());
        config.credential_types[0].id = "com.emvco.dpc.card".to_string();
        config.credential_types[0].vct = Some("com.emvco.dpc.card".to_string());
        config.credential_types[0].claims = vec![
            ClaimDef {
                path: vec!["credential_id".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
            ClaimDef {
                path: vec!["network".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
        ];

        let mut claims = serde_json::Map::new();
        claims.insert("credential_id".to_string(), serde_json::json!("urn:uuid:abc"));
        claims.insert("network".to_string(), serde_json::json!("example_network"));

        let credential = issue_for_test_with_claims(&config, "com.emvco.dpc.card", claims).await;
        let named = disclosures_of(&credential);

        assert_eq!(
            named["network"],
            serde_json::json!("example_network"),
            "a string-valued network must survive as a string, not be wrapped"
        );
    }
```

- [ ] **Step 5c: Assert the issuer metadata carries every configured locale**

The DPC type's whole visible payoff is its display metadata, and
`build_issuer_metadata` is what a wallet actually reads. Add to
`crates/foundry-issuer/src/metadata.rs`'s test module:

```rust
    /// `display` is an opaque passthrough into
    /// `credential_configurations_supported[].display`, so every configured
    /// locale entry must arrive intact and in order.
    #[test]
    fn credential_configuration_display_carries_every_configured_locale() {
        let mut cfg = test_config();
        cfg.credential_types[0].display = vec![
            serde_json::json!({"name": "Payment Card", "locale": "en-US"}),
            serde_json::json!({"name": "Zahlungskarte", "locale": "de-DE"}),
            serde_json::json!({"name": "Carte de paiement", "locale": "fr-FR"}),
        ];
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();

        let locales: Vec<&str> = pid
            .display
            .iter()
            .filter_map(|d| d.get("locale").and_then(|l| l.as_str()))
            .collect();
        assert_eq!(locales, vec!["en-US", "de-DE", "fr-FR"]);
        assert_eq!(pid.display[1]["name"], "Zahlungskarte");
    }
```

- [ ] **Step 6: Run the three new issuer tests**

```bash
cargo test -p foundry-issuer dpc_shaped_type 2>&1 | tail -20
cargo test -p foundry-issuer credential_configuration_display_carries 2>&1 | tail -10
```
Expected: all three PASS (`..._issues_with_claims_in_disclosures`, `..._accepts_a_single_string_network`, `credential_configuration_display_carries_every_configured_locale`).

If either `network` assertion fails, **stop and report** — a string or array value not surviving verbatim is a real finding about disclosure construction, not a test bug.

- [ ] **Step 7: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-issuer -p foundry 2>&1 | tee /tmp/task5.log
grep -c FAILED /tmp/task5.log
grep '^test result:' /tmp/task5.log
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings 2>&1 | tail -5
```
Expected: `0` FAILED, all `ok`, no warnings. `e2e_full_flow` is `#[ignore]`d and does not run here.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(cli): ship the EMVCo DPC credential type in the quickstart config

com.emvco.dpc.card as pure configuration alongside pid: three claims, two of
them mandatory and selectively disclosable, a 12-hour lifetime, and display
metadata in three locales. No code in the tree names EMVCo.

Adds tests/quickstart_config.rs, which generates a real quickstart tree and
asserts the config loads, validates, and keeps the DPC shape intact -- and an
issuer test covering the co-badged array-valued network case."
```

---

## Task 6: Documentation, spec stub, and OpenAPI verification

**Files:**
- Create: `docs/specs/emvco-dpc-schema-framework.md`
- Create: `docs/superpowers/changes/2026-08-05-emvco-dpc-credential-type.md`
- Modify: `AGENTS.md` (§4.4 — new reference category row)
- Modify: `README.md` (config reference + quickstart section)
- Modify: `crates/foundry-sd-jwt-vc/AGENTS.md`, `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md` (module notes + gotchas)
- Modify: `crates/foundry/tests/AGENTS.md` (row for the new test file)

**Interfaces:**
- Consumes: everything from Tasks 1–5.
- Produces: no code.

- [ ] **Step 1: Write the specification reference stub**

Create `docs/specs/emvco-dpc-schema-framework.md`:

```markdown
# EMV® Digital Payment Credential Specification — Schema Framework

**This file is a reference stub, not a copy of the specification.**

| | |
|---|---|
| Document | EMV® Digital Payment Credential Specification — Schema Framework |
| Version | v1.0 |
| Status when implemented against | **DRAFT — Associate Review 2** (dated 8 May 2026) |
| Publisher | EMVCo, LLC |
| Obtain from | <https://www.emvco.com> — EMVCo publishes its specifications there; draft review copies are distributed to Associates under the applicable EMVCo agreement |

## Why no verbatim copy is in this directory

Every other file in `docs/specs/` is an IETF or OpenID Foundation text carrying
redistribution permission. This one does not. Its legal notice states:

> © 2026 EMVCo, LLC. All rights reserved. Reproduction, distribution and other
> use of this document is permitted only pursuant to the applicable agreement
> between the user and EMVCo.

It is additionally an unpublished draft. This repository is Apache-2.0 licensed,
so committing the document would purport to convey redistribution rights the
project does not hold. A reader verifying foundry's behaviour against this
specification must obtain their own copy.

## What foundry implements from it

Only the SD-JWT VC binding of the DPC **card** credential. The facts below are
interface information — claim names, JSON types, and inclusion requirements —
restated rather than quoted.

**Canonical credential type identifier:** `com.emvco.dpc.card`. The
specification uses this one string as the logical credential type, the SD-JWT
`vct`, the mdoc `docType`, the mdoc namespace, and the payload schema `$id`.

**Credential meta-attributes → SD-JWT claims**

| Meta-attribute | Claim | Type |
|---|---|---|
| Credential Type | `vct` | string, constant `com.emvco.dpc.card` |
| Credential Issuer | `iss` | string (URI) |
| User Binding Key | `cnf` | object carrying a `jwk` |
| Issuance Time | `iat` | number (Unix time) |
| Expiration Time | `exp` | number (Unix time) |

**Disclosable attributes**

| Claim | Type | Required |
|---|---|---|
| `credential_id` | string | yes |
| `network` | string, or array of string (co-badged cards) | yes |
| `card_id` | string | no |

The payload schema declares `additionalProperties: false` and requires
`vct`, `iss`, `cnf`, `credential_id`, `network`.

## Known contradictions in the reviewed draft

Recorded so a later review round can be checked against them:

1. The payload schema forbids additional properties, yet the specification's own
   sample credentials carry `_sd` and `_sd_alg`. The schema therefore describes
   a known claim vocabulary rather than a literal closed world.
2. §6 requires implementers to "implement status check mechanisms", but the
   payload schema has no room for a `status` claim.

## What foundry does not implement

The display-metadata schema (`com.emvco.dpc.card.meta`), the mdoc binding, and
the DCQL query patterns. See
[`docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md`](../superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md)
§8 for why, and what would be needed.
```

- [ ] **Step 2: Add the §4.4 reference-category row to root `AGENTS.md`**

After the existing "Vendor profile" table and its vendor-profile rule, add:

```markdown
A third pinned source is neither standards-track nor a vendor profile, and is
**not present in this repository at all**:

| External reference | Governs |
|---|---|
| [`emvco-dpc-schema-framework.md`](docs/specs/emvco-dpc-schema-framework.md) | EMV® Digital Payment Credential Specification — Schema Framework (v1.0, DRAFT Associate Review 2). Governs the shape of the `com.emvco.dpc.card` credential type only: its `vct`, its three disclosable claims and their types and inclusion requirements. The linked file is a **reference stub**, not the specification — the document is all-rights-reserved and unpublished, so no verbatim copy is committed. |

**External-reference rule.** Where a governing document cannot be committed, the
stub in `docs/specs/` records its exact title, version and review round, why no
copy is in-tree, where a reader obtains one, and the interface facts foundry
relies on, restated rather than quoted. Treat the stub as the record of *which*
revision the code was built against — not as a substitute for the text. Do not
infer unrecorded behaviour from it; obtain the document. A stub does **not**
acquire the precedence of a standards-track specification, and where it
conflicts with one, the specification wins.
```

- [ ] **Step 3: Update the §4.4 maintenance note in root `AGENTS.md` §8**

In §8, extend the protocol-behaviour bullet so future readers know stubs count:

```markdown
- **Protocol behaviour change** → verify it against the pinned specs in
  `docs/specs/` (§4.4) and cite the section in a code comment. **New or replaced
  spec file in `docs/specs/`** → add or update its row in the §4.4 table. A
  governing document that cannot be committed gets a **reference stub** instead,
  under §4.4's external-reference rule.
```

- [ ] **Step 4: Update `README.md`**

Add `required` and `validity_seconds` to the credential-type configuration
reference, and mention the DPC type in the quickstart section:

```markdown
| `credential_types[].validity_seconds` | no | `31536000` (365 days) | Credential lifetime in seconds; the issued credential's `exp` is its `iat` plus this value. |
| `credential_types[].claims[].required` | no | `!selectively_disclosable` | Whether an offer must supply a value for this claim. Omit it to keep the historical rule (non-disclosable claims mandatory, disclosable ones optional). Set it explicitly for a claim that is **both** mandatory and selectively disclosable. |
```

In the quickstart section, note that the generated config ships two credential
types — `pid` and `com.emvco.dpc.card` — and that the latter is an EMVCo Digital
Payment Credential whose reference is `docs/specs/emvco-dpc-schema-framework.md`.

- [ ] **Step 5: Update the three crate `AGENTS.md` files**

`crates/foundry-sd-jwt-vc/AGENTS.md` — in Key Public Types, change the
`IssuerClaims` line to note `sub` is `Option<String>`, and add a gotcha:

```markdown
- **`IssuerClaims.sub` is optional and omitted by default.** A synthesised
  per-transaction `sub` is a unique, static, always-disclosed correlation
  identifier that no consumer in this workspace reads. `build_sd_jwt_vc` emits
  the payload key only when the field is `Some`. Do not reintroduce an
  unconditional `sub`.
```

`crates/foundry-core/AGENTS.md` — add to the config module notes:

```markdown
- `CredentialType::resolved_validity_seconds()` and `ClaimDef::is_required()`
  follow the same `Option` + resolver pattern as `resolved_scope()`: an omitted
  key reproduces the behaviour that predated the field. `is_required()` resolves
  to `!selectively_disclosable`; `resolved_validity_seconds()` to `31_536_000`.
```

`crates/foundry-issuer/AGENTS.md` — add a gotcha:

```markdown
- **"Required" is not "not selectively disclosable".** `create_offer` gates
  claim-presence validation on `ClaimDef::is_required()`. A claim can be
  mandatory in a credential's schema *and* selectively disclosable in the
  SD-JWT; before this distinction existed, such a claim was never validated and
  an offer omitting it issued an incomplete credential.
```

- [ ] **Step 6: Add the test-file row to `crates/foundry/tests/AGENTS.md`**

```markdown
| `quickstart_config.rs` | The config `foundry quickstart` generates loads and validates, and carries both shipped credential types (`pid`, `com.emvco.dpc.card`) with the DPC claim shape and display locales intact. |
```

- [ ] **Step 7: Verify the OpenAPI specs have not drifted**

`CredentialType` and `ClaimDef` are configuration types, not HTTP schemas, so no
diff is expected — but verify rather than assume:

```bash
cargo test -p foundry --test openapi_endpoints 2>&1 | grep '^test result:'
```
Expected: `ok`. If it fails, the failure message names the regeneration command;
run it and commit the regenerated `openapi.json` / `openapi-wallet.json`:

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
```

- [ ] **Step 8: Write the change record**

Create `docs/superpowers/changes/2026-08-05-emvco-dpc-credential-type.md`
covering: what shipped (the three generic changes plus the config), the one
behaviour change external consumers would notice (`sub` gone from every issued
credential), the `IssuerClaims.sub` signature change, the half-closure of
GAP-VCI-13, the deliberate non-vendoring of the EMVCo document, and the roadmap
position — item **E**, completing the A–E Google Wallet decomposition, with §8's
open issues carried forward.

- [ ] **Step 9: Final scoped gate for this task**

```bash
cargo fmt
cargo fmt --check
cargo test -p foundry 2>&1 | tee /tmp/task6.log
grep -c FAILED /tmp/task6.log
grep '^test result:' /tmp/task6.log
```
Expected: `0` FAILED, all `ok`.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "docs: EMVCo DPC reference stub, AGENTS updates, and operator docs

Adds docs/specs/emvco-dpc-schema-framework.md as a reference stub rather than a
vendored copy: the document is all-rights-reserved and unpublished, and this
repository is Apache-2.0. Introduces an external-reference category in
AGENTS.md §4.4 with a rule stating a stub never acquires standards-track
precedence.

Records the sub, required and validity_seconds changes in the three affected
crate AGENTS.md files, the README config reference, and a change record."
```

---

## Branch Closure (not a task — for whoever finishes the branch)

Run the §5.3 **full gate exactly once**, after Task 6:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace 2>&1 | tee /tmp/test-output.log
grep -c "FAILED" /tmp/test-output.log
grep "^test result:" /tmp/test-output.log
cargo test -p foundry --test e2e_full_flow -- --ignored 2>&1 | tail -20
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee /tmp/clippy.log | tail -5
```

`e2e_full_flow` is the load-bearing check for Task 1: it spawns the real binary,
runs `quickstart`, and issues a `pid` credential. It must still pass with `sub`
gone.