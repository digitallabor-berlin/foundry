# Foundry Plan 9 — Verifier Hardening: DCQL Matching, Status-List Revocation & mdoc Presentations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three Critical verifier gaps in `crates/foundry-verifier/src/verify.rs::do_verify_vp_response` — it currently returns `verified: true` unconditionally without (1) checking the transaction's DCQL query, (2) checking Token Status List revocation, or (3) supporting mdoc presentations at all.

**Architecture:** Keep Plan 7's working pipeline (JWE decryption, SD-JWT VC signature + KB-JWT verification, request-object building) untouched. Add two pure, independently-testable policy helpers in `foundry-verifier` — `dcql::check_dcql_match` and `status::check_status` — plus an injectable `StatusListResolver` trait (default `HttpStatusListResolver` over `reqwest`) so the status fetch is real in production but mockable in unit tests. Route the `vp_token` by shape (JSON string ⇒ SD-JWT VC; JSON object with `mdoc`+`device_signature` ⇒ mso_mdoc) into the already-complete-but-unused `foundry_mdoc::verifier::verify_mdoc`, and feed both credential formats through the same DCQL-match and status-check helpers. Make the overall `verified` flag the logical AND of every `CheckResult`, so a DCQL mismatch or a revoked credential yields `verified: false` with a named failed check rather than a silent pass.

**Tech Stack:** Rust (edition 2021), tokio, axum, `foundry-core`, `foundry-sd-jwt-vc`, `foundry-mdoc`, `openid4vp` (vendored, for the typed `DcqlQuery` model), `josekit`, `reqwest` (new), `async-trait` (new), `serde_json`.

## Global Constraints

- **No panics or unwraps** in verification request-handling paths. Every fallible step returns a typed `VerificationError` or records a failed `CheckResult`; a status-list network failure is a clean recoverable `VerificationError::StatusUnavailable`, never a panic.
- **`verified` must be honest:** `VerificationResult.verified` is computed as `checks.iter().all(|c| c.passed)`. A DCQL mismatch or a revoked/suspended status MUST make `verified == false`. Do not reintroduce a hardcoded `verified: true`.
- **Per-check transparency preserved:** every verification concern pushes its own named `CheckResult` into `VerificationResult.checks`. Check names used by this plan: `jwe_decryption`, `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check`.
- **Policy failure vs. structural failure:** structural/crypto/decryption failures (bad JWE, bad issuer signature, bad KB-JWT/DeviceAuth, missing/garbled `vp_token`) remain hard `Err(VerificationError)` → HTTP 400. Policy failures (DCQL mismatch, revoked/suspended status, unverifiable status token) are captured as failed `CheckResult`s with `verified: false` and returned as `Ok` → HTTP 200 with `verified:false`, so the negative outcome and per-check detail are stored and queryable via `GET /admin/verification/requests/{id}`. Status-list *network* unavailability is `Err(VerificationError::StatusUnavailable)` → HTTP 502.
- **Reuse existing primitives:** `foundry_core::trust::TrustStore` / `validate_chain`, `foundry_core::status_list::{verify_status_list_token, StatusValue, VerifiedStatusList}`, `foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc`, `foundry_mdoc::verifier::verify_mdoc`, and the vendored `openid4vp::core::dcql_query::DcqlQuery`. Do not reimplement DCQL parsing or status-list crypto.
- **Error taxonomy via `thiserror`** in `crates/foundry-verifier/src/error.rs`; unit tests colocated per module with `#[test]` / `#[tokio::test]`; TDD (write/adjust tests, verify red, implement, verify green, commit).
- **Spec compliance:** OpenID4VP 1.0 / draft-20, DCQL draft-03, IETF draft-ietf-oauth-status-list-14.

---

### Task 1: DCQL Query Matching (SD-JWT VC path) + honest `verified` flag

Adds a pure `check_dcql_match` helper that parses the transaction's stored `dcql_query` into the vendored typed `DcqlQuery` model and confirms the disclosed credential satisfies a credential query of its format (correct `vct`, all mandatory claim paths present, any `values` constraints met). Wires it into the SD-JWT VC branch of `do_verify_vp_response`, and changes the engine so `verified` is the AND of all checks and `tx.state` is derived from `result.verified` (not from `Ok`/`Err`).

**Design decisions (locked for this task):**
- **Parse into the typed `DcqlQuery`** (`serde_json::from_value(tx.dcql_query.clone())`) rather than a bespoke matcher — the fully-typed, unit-tested model already exists in `crates/openid4vp/src/core/dcql_query.rs`. A parse failure is a **failed** `dcql_match` check (fail-closed), because a query we cannot interpret cannot be asserted satisfied.
- **DCQL mismatch ⇒ failed `CheckResult` + `verified:false` on the `Ok` path, not a hard `Err`** — preserves per-check transparency (the failed check is stored/queryable) and keeps `verified` honest.
- **Single-credential satisfaction semantics:** this codebase carries one credential per `vp_token` (a bare value, not a DCQL-id-keyed map). The presentation satisfies the query if it satisfies **at least one** credential query whose `format` matches the presented format. Full multi-credential / `credential_sets` matching is out of scope (documented in code).

**Files:**
- Create: `crates/foundry-verifier/src/dcql.rs`
- Modify: `crates/foundry-verifier/src/lib.rs` (add `pub mod dcql;` + re-exports)
- Modify: `crates/foundry-verifier/src/verify.rs` (`verify_vp_response` state logic + SD-JWT branch tail; add one unit test)

**Interfaces:**
- Consumes: `openid4vp::core::dcql_query::{DcqlQuery, DcqlCredentialQuery, DcqlCredentialClaimsQueryPath, DcqlCredentialClaimsQueryValue}`, `openid4vp::core::credential_format::ClaimFormatDesignation`, `crate::transaction::CheckResult`.
- Produces: `pub enum PresentedFormat { SdJwtVc, MsoMdoc }`; `pub fn check_dcql_match(dcql_query: &serde_json::Value, format: PresentedFormat, disclosed_claims: &serde_json::Value, doc_type: Option<&str>) -> CheckResult` (check name `"dcql_match"`; never errors). Later tasks (2, 3) call `check_dcql_match` with `PresentedFormat::MsoMdoc` and a `doc_type`.

- [ ] **Step 1: Create `crates/foundry-verifier/src/dcql.rs` with the matcher and its unit tests**

```rust
//! DCQL (Digital Credentials Query Language) satisfaction checking.
//!
//! After a presentation's signatures are verified and its claims disclosed,
//! this module confirms the disclosed credential actually satisfies the
//! verification transaction's DCQL query: correct credential format, correct
//! `vct` (SD-JWT VC) or `doctype` (mso_mdoc), all mandatory claim paths
//! present, and any `values` constraints met.
//!
//! Scope: this codebase presents a single credential per `vp_token`, so we
//! require the presented credential to satisfy at least one credential query
//! of its format. Multi-credential and `credential_sets` combination logic is
//! out of scope for this phase.

use crate::transaction::CheckResult;
use openid4vp::core::credential_format::ClaimFormatDesignation;
use openid4vp::core::dcql_query::{
    DcqlCredentialClaimsQueryPath, DcqlCredentialQuery, DcqlQuery,
};
use serde_json::Value;

/// The concrete credential format actually present in the `vp_token`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedFormat {
    SdJwtVc,
    MsoMdoc,
}

impl PresentedFormat {
    fn matches(self, designation: &ClaimFormatDesignation) -> bool {
        matches!(
            (self, designation),
            (PresentedFormat::SdJwtVc, ClaimFormatDesignation::DcSdJwt)
                | (PresentedFormat::MsoMdoc, ClaimFormatDesignation::MsoMDoc)
        )
    }
}

fn failed(reason: String) -> CheckResult {
    CheckResult {
        check: "dcql_match".to_string(),
        passed: false,
        detail: Some(reason),
    }
}

/// Check that `disclosed_claims` satisfy `dcql_query` for a credential of
/// `format`. `doc_type` is the mdoc docType (`None` for SD-JWT VC). Returns a
/// `CheckResult { check: "dcql_match", .. }`; never errors (fail-closed).
pub fn check_dcql_match(
    dcql_query: &Value,
    format: PresentedFormat,
    disclosed_claims: &Value,
    doc_type: Option<&str>,
) -> CheckResult {
    let query: DcqlQuery = match serde_json::from_value(dcql_query.clone()) {
        Ok(q) => q,
        Err(e) => return failed(format!("dcql_query is not a valid DCQL query: {e}")),
    };

    let mut first_reason: Option<String> = None;
    for cq in query.credentials() {
        if !format.matches(cq.format()) {
            continue;
        }
        match credential_query_satisfied(cq, format, disclosed_claims, doc_type) {
            Ok(()) => {
                return CheckResult {
                    check: "dcql_match".to_string(),
                    passed: true,
                    detail: Some(format!("matched credential query '{}'", cq.id())),
                };
            }
            Err(reason) => {
                if first_reason.is_none() {
                    first_reason = Some(format!("credential query '{}': {reason}", cq.id()));
                }
            }
        }
    }

    failed(first_reason.unwrap_or_else(|| {
        "no credential query in the DCQL query matches the presented credential format".to_string()
    }))
}

fn credential_query_satisfied(
    cq: &DcqlCredentialQuery,
    format: PresentedFormat,
    claims: &Value,
    doc_type: Option<&str>,
) -> Result<(), String> {
    // --- format-specific metadata constraints ---
    match format {
        PresentedFormat::SdJwtVc => {
            if let Some(vct_values) = cq.meta().get("vct_values").and_then(|v| v.as_array()) {
                let vct = claims.get("vct").and_then(|v| v.as_str()).unwrap_or("");
                if !vct_values.iter().any(|v| v.as_str() == Some(vct)) {
                    return Err(format!("vct '{vct}' not in requested vct_values"));
                }
            }
        }
        PresentedFormat::MsoMdoc => {
            if let Some(want) = cq.meta().get("doctype_value").and_then(|v| v.as_str()) {
                let got = doc_type.unwrap_or("");
                if got != want {
                    return Err(format!("doctype '{got}' does not equal requested '{want}'"));
                }
            }
        }
    }

    // --- claim path + value constraints ---
    if let Some(claim_queries) = cq.claims() {
        for claim in claim_queries.iter() {
            let found = resolve_path(claims, claim.path()).ok_or_else(|| {
                format!("required claim path {:?} not disclosed", path_debug(claim.path()))
            })?;
            if let Some(expected) = claim.values() {
                let ok = expected.iter().any(|e| {
                    use openid4vp::core::dcql_query::DcqlCredentialClaimsQueryValue as V;
                    match e {
                        V::String(s) => found.as_str() == Some(s.as_str()),
                        V::Integer(i) => found.as_i64() == Some(*i as i64),
                        V::Boolean(b) => found.as_bool() == Some(*b),
                    }
                });
                if !ok {
                    return Err(format!(
                        "claim path {:?} value {found} not in requested values",
                        path_debug(claim.path())
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Walk a claims `Value` by a DCQL claims path. Supports `String` (object key)
/// and `Integer` (array index) segments. `Null` (array wildcard) segments are
/// not supported in this phase and cause the lookup to fail (fail-closed).
fn resolve_path<'a>(claims: &'a Value, path: &[DcqlCredentialClaimsQueryPath]) -> Option<&'a Value> {
    let mut cur = claims;
    for seg in path {
        match seg {
            DcqlCredentialClaimsQueryPath::String(k) => cur = cur.get(k)?,
            DcqlCredentialClaimsQueryPath::Integer(i) => cur = cur.get(*i)?,
            DcqlCredentialClaimsQueryPath::Null => return None,
        }
    }
    Some(cur)
}

fn path_debug(path: &[DcqlCredentialClaimsQueryPath]) -> Vec<String> {
    path.iter()
        .map(|p| match p {
            DcqlCredentialClaimsQueryPath::String(s) => s.clone(),
            DcqlCredentialClaimsQueryPath::Integer(i) => i.to_string(),
            DcqlCredentialClaimsQueryPath::Null => "null".to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sd_jwt_query(vct: &str) -> Value {
        json!({"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":[vct]},
            "claims":[{"path":["given_name"]}]}]})
    }

    #[test]
    fn sd_jwt_vct_and_claim_present_passes() {
        let q = sd_jwt_query("https://issuer.example/pid");
        let claims = json!({"vct":"https://issuer.example/pid","given_name":"Alice"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(r.passed, "detail={:?}", r.detail);
        assert_eq!(r.check, "dcql_match");
    }

    #[test]
    fn sd_jwt_vct_mismatch_fails() {
        let q = sd_jwt_query("https://issuer.example/OTHER");
        let claims = json!({"vct":"https://issuer.example/pid","given_name":"Alice"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(!r.passed);
        assert!(r.detail.unwrap().contains("vct"));
    }

    #[test]
    fn sd_jwt_missing_mandatory_claim_fails() {
        let q = sd_jwt_query("https://issuer.example/pid");
        let claims = json!({"vct":"https://issuer.example/pid"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(!r.passed);
        assert!(r.detail.unwrap().contains("given_name"));
    }

    #[test]
    fn sd_jwt_values_constraint_enforced() {
        let q = json!({"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},
            "claims":[{"path":["age_over_18"],"values":[true]}]}]});
        let ok = json!({"vct":"x","age_over_18":true});
        assert!(check_dcql_match(&q, PresentedFormat::SdJwtVc, &ok, None).passed);
        let bad = json!({"vct":"x","age_over_18":false});
        assert!(!check_dcql_match(&q, PresentedFormat::SdJwtVc, &bad, None).passed);
    }

    #[test]
    fn mdoc_doctype_and_namespaced_claim() {
        let q = json!({"credentials":[{"id":"mdl","format":"mso_mdoc",
            "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
            "claims":[{"path":["org.iso.18013.5.1","given_name"]}]}]});
        let claims = json!({"org.iso.18013.5.1":{"given_name":"John"}});
        let r = check_dcql_match(&q, PresentedFormat::MsoMdoc, &claims, Some("org.iso.18013.5.1.mDL"));
        assert!(r.passed, "detail={:?}", r.detail);
        let bad = check_dcql_match(&q, PresentedFormat::MsoMdoc, &claims, Some("org.iso.WRONG"));
        assert!(!bad.passed);
    }

    #[test]
    fn format_mismatch_fails() {
        let q = json!({"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{}}]});
        let claims = json!({"vct":"x","given_name":"Alice"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(!r.passed);
    }

    #[test]
    fn unparseable_query_fails_closed() {
        let q = json!({"credentials":[]}); // NonEmptyVec rejects empty -> parse error
        let claims = json!({"vct":"x"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(!r.passed);
    }
}
```

- [ ] **Step 2: Register the module in `crates/foundry-verifier/src/lib.rs`**

The file currently declares `error`, `request`, `transaction`, `verify`. Apply two edits.

Edit 1 — add the module declaration. Change:
```rust
pub mod error;
pub mod request;
pub mod transaction;
pub mod verify;
```
to:
```rust
pub mod dcql;
pub mod error;
pub mod request;
pub mod transaction;
pub mod verify;
```

Edit 2 — add the re-export. Change:
```rust
pub use error::VerificationError;
```
to:
```rust
pub use error::VerificationError;
pub use dcql::{check_dcql_match, PresentedFormat};
```

- [ ] **Step 3: Run the DCQL unit tests to verify they pass**

Run: `cargo test -p foundry-verifier dcql::`
Expected: 7 tests pass (`sd_jwt_vct_and_claim_present_passes`, `sd_jwt_vct_mismatch_fails`, `sd_jwt_missing_mandatory_claim_fails`, `sd_jwt_values_constraint_enforced`, `mdoc_doctype_and_namespaced_claim`, `format_mismatch_fails`, `unparseable_query_fails_closed`).

- [ ] **Step 4: Wire DCQL matching into `verify.rs` and make `verified` honest**

In `crates/foundry-verifier/src/verify.rs`, add the import near the top (after the existing `use` lines):

```rust
use crate::dcql::{check_dcql_match, PresentedFormat};
```

Replace the entire `verify_vp_response` function with this version (state now derives from `result.verified`):

```rust
pub fn verify_vp_response(
    config: &Config,
    tx: &mut VerificationTransaction,
    encrypted_jwe_str: &str,
) -> Result<VerificationResult, VerificationError> {
    match do_verify_vp_response(config, tx, encrypted_jwe_str) {
        Ok(result) => {
            tx.state = if result.verified {
                VerificationState::Verified
            } else {
                VerificationState::Failed
            };
            tx.result = Some(result.clone());
            Ok(result)
        }
        Err(err) => {
            tx.state = VerificationState::Failed;
            Err(err)
        }
    }
}
```

Then, in `do_verify_vp_response`, replace the final result construction block (currently `// 3. Result Construction` returning `verified: true`) with:

```rust
    let claims_value = Value::Object(disclosed_claims);

    // 3. DCQL query satisfaction (SD-JWT VC path)
    checks.push(check_dcql_match(
        &tx.dcql_query,
        PresentedFormat::SdJwtVc,
        &claims_value,
        None,
    ));

    // 4. Overall verdict is the AND of every check performed.
    let verified = checks.iter().all(|c| c.passed);
    Ok(VerificationResult {
        verified,
        checks,
        claims: claims_value,
    })
```

- [ ] **Step 5: Add a `verify.rs` unit test proving a DCQL mismatch yields `verified:false`**

Append this test inside the existing `#[cfg(test)] mod tests` block in `crates/foundry-verifier/src/verify.rs` (it reuses the module's existing `test_pki`, `holder`, `der_b64`, `test_config`, `sample_tx` helpers and imports):

```rust
    #[test]
    fn test_verify_vp_response_dcql_vct_mismatch_is_not_verified() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let config = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        // Require a vct the credential will NOT have.
        tx.dcql_query = serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://localhost:8443/vct/OTHER"] }
            }]
        });

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation =
            attach_kb_jwt(issuer_pres, &holder_signer, "x509_san_dns:localhost", &tx.nonce).unwrap();

        let jwe_str = JweBuilder::new()
            .payload(serde_json::json!({ "vp_token": presentation }))
            .recipient_key_json(&tx.ephem_public_jwk)
            .unwrap()
            .alg("ECDH-ES")
            .enc("A128GCM")
            .build()
            .unwrap();

        let res = verify_vp_response(&config, &mut tx, &jwe_str).unwrap();
        assert!(!res.verified, "DCQL vct mismatch must not verify");
        assert_eq!(tx.state, VerificationState::Failed);
        let dcql = res.checks.iter().find(|c| c.check == "dcql_match").unwrap();
        assert!(!dcql.passed);
        // The signature check still passed and is still reported for transparency.
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "sd_jwt_vc_signature_and_kb_jwt" && c.passed));
    }
```

- [ ] **Step 6: Run the verifier crate tests and confirm the existing happy-path test still verifies**

Run: `cargo test -p foundry-verifier`
Expected: all tests pass, including the pre-existing `test_verify_vp_response_sd_jwt_vc` (its `sample_tx` query has no `vct_values`/`claims` constraints, so `dcql_match` passes and `verified` stays `true`) and the new `test_verify_vp_response_dcql_vct_mismatch_is_not_verified`.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-verifier/src/dcql.rs crates/foundry-verifier/src/lib.rs crates/foundry-verifier/src/verify.rs
git commit -m "feat(verifier): enforce DCQL query matching and derive verified from all checks"
```

---
### Task 2: Token Status List Revocation Checking (injectable resolver + HTTP fetch)

Adds an injectable `StatusListResolver` trait with a production `HttpStatusListResolver` (over `reqwest`), plus a `check_status` helper that resolves a credential's `status.status_list` reference, verifies the Status List Token against the configured trust anchors, and reads the index bit. Wires it into `do_verify_vp_response` and makes the whole verify path `async`.

**Design decisions (locked for this task):**
- **Fetch over HTTP via an injectable resolver, no same-instance shortcut.** A verifier generally checks credentials from *other* issuers, so HTTP resolution of `status.status_list.uri` is the correct general design (matches the design spec §Status List: "Verify: resolve `status.status_list.uri`, fetch + verify the token"). Same-instance local resolution is deliberately **not** implemented: the issuer embeds `uri = "{public_base_url}/1"` (hardcoded list id `1`, `crates/foundry-issuer/src/credential.rs`) while the CLI issues tokens with `sub = "{public_base_url}/{credential_type}"` (`crates/foundry/src/commands.rs::status_list_token`), so there is no unambiguous `uri`→`PersistentStatusList` mapping to shortcut through today. Noted as a future optimization; out of scope here.
- **`expected_sub == uri`.** Per draft-ietf-oauth-status-list-14 §5.1 a Status List Token's `sub` MUST equal the referenced token's `uri`, so `check_status` verifies the fetched token against the credential's `status_list.uri`.
- **Network failure is a hard `Err(VerificationError::StatusUnavailable)` → HTTP 502.** A *revoked/suspended* status, a *malformed* status claim, or a Status List Token that fails trust-anchor/`sub`/`exp` verification is a **failed `status_check`** (policy ⇒ `verified:false`, HTTP 200). A credential with **no** `status.status_list` claim passes with an explanatory detail (it is simply not revocable).
- **The verify path becomes `async`.** `verify_vp_response` / `do_verify_vp_response` gain `async` + a `resolver: &dyn StatusListResolver` parameter; the four existing verify tests plus Task 1's new test convert to `#[tokio::test]` and pass a no-op mock resolver (they carry no status claim, so the resolver is never invoked).

**Files:**
- Create: `crates/foundry-verifier/src/status.rs`
- Modify: `crates/foundry-verifier/Cargo.toml` (add `reqwest`, `async-trait`, dev-dep `coset`)
- Modify: `crates/foundry-verifier/src/error.rs` (add `StatusUnavailable` variant + display assertion)
- Modify: `crates/foundry-verifier/src/lib.rs` (add `pub mod status;` + re-exports)
- Modify: `crates/foundry-verifier/src/verify.rs` (async signatures + resolver param + status wiring; convert 5 unit tests)
- Modify: `crates/foundry/src/server.rs` (`post_response_handler` builds an `HttpStatusListResolver`, awaits; map `StatusUnavailable` → 502)

**Interfaces:**
- Consumes: `foundry_core::status_list::{verify_status_list_token, StatusValue}`, `foundry_core::trust::TrustStore`, `crate::transaction::CheckResult`, `crate::error::VerificationError`.
- Produces:
  - `pub trait StatusListResolver: Send + Sync { async fn fetch(&self, uri: &str) -> Result<String, VerificationError>; }` (via `async_trait`).
  - `pub struct HttpStatusListResolver` with `pub fn new() -> Result<Self, VerificationError>`.
  - `pub async fn check_status(disclosed_claims: &serde_json::Value, trust_store: &TrustStore, resolver: &dyn StatusListResolver, now_unix: u64) -> Result<CheckResult, VerificationError>` (check name `"status_check"`).
  - `crate::status::test_support::MockResolver { pub token: Option<String> }` (cfg(test), `pub(crate)`).
  - Changed: `pub async fn verify_vp_response(config: &Config, tx: &mut VerificationTransaction, encrypted_jwe_str: &str, resolver: &dyn StatusListResolver) -> Result<VerificationResult, VerificationError>`.

- [ ] **Step 1: Add dependencies to `crates/foundry-verifier/Cargo.toml`**

Under `[dependencies]`, add these two lines (after `tracing = { workspace = true }`):

```toml
async-trait = { workspace = true }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```

Under `[dev-dependencies]`, add (after `tempfile = "3"`):

```toml
coset = { workspace = true }
```

(`async-trait` and `coset` are already pinned in the workspace root `[workspace.dependencies]`; `reqwest` is new and pinned locally. `rustls-tls` avoids an OpenSSL system dependency and still performs the plain-HTTP `127.0.0.1` fetch used by the Task 4 integration test.)

- [ ] **Step 2: Add the `StatusUnavailable` error variant in `crates/foundry-verifier/src/error.rs`**

Edit 1 — add the variant. Change:
```rust
    #[error("verification failed: {0}")]
    Failed(String),
```
to:
```rust
    #[error("verification failed: {0}")]
    Failed(String),

    #[error("status list unavailable: {0}")]
    StatusUnavailable(String),
```

Edit 2 — extend the display test. Change:
```rust
        let err = VerificationError::Serialization("json fail".to_string());
        assert_eq!(err.to_string(), "serialization error: json fail");
    }
```
to:
```rust
        let err = VerificationError::Serialization("json fail".to_string());
        assert_eq!(err.to_string(), "serialization error: json fail");

        let err = VerificationError::StatusUnavailable("network".to_string());
        assert_eq!(err.to_string(), "status list unavailable: network");
    }
```

- [ ] **Step 3: Create `crates/foundry-verifier/src/status.rs`**

```rust
//! Token Status List revocation checking (draft-ietf-oauth-status-list-14).
//!
//! After a credential's claims are disclosed, if it carries a
//! `status.status_list` claim we resolve the referenced Status List Token,
//! verify it against the configured trust anchors, and read the credential's
//! index bit. A revoked/suspended (non-`Valid`) status yields a failed
//! `status_check` (making the overall result `verified: false`); an IO/network
//! failure fetching the token is a clean, recoverable `VerificationError`.

use crate::error::VerificationError;
use crate::transaction::CheckResult;
use foundry_core::status_list::{verify_status_list_token, StatusValue};
use foundry_core::trust::TrustStore;
use serde_json::Value;
use std::time::Duration;

/// Resolves a Status List Token (compact JWS string) from its `uri`.
#[async_trait::async_trait]
pub trait StatusListResolver: Send + Sync {
    async fn fetch(&self, uri: &str) -> Result<String, VerificationError>;
}

/// Production resolver: HTTP GET the `uri`, expecting a `statuslist+jwt` body.
pub struct HttpStatusListResolver {
    client: reqwest::Client,
}

impl HttpStatusListResolver {
    /// Build a resolver with a 10s request timeout. Returns an error (never
    /// panics) if the HTTP/TLS backend cannot be initialized.
    pub fn new() -> Result<Self, VerificationError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| VerificationError::StatusUnavailable(format!("http client init: {e}")))?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl StatusListResolver for HttpStatusListResolver {
    async fn fetch(&self, uri: &str) -> Result<String, VerificationError> {
        let resp = self
            .client
            .get(uri)
            .send()
            .await
            .map_err(|e| VerificationError::StatusUnavailable(format!("fetch {uri}: {e}")))?;
        if !resp.status().is_success() {
            return Err(VerificationError::StatusUnavailable(format!(
                "fetch {uri}: HTTP {}",
                resp.status()
            )));
        }
        resp.text()
            .await
            .map_err(|e| VerificationError::StatusUnavailable(format!("read {uri}: {e}")))
    }
}

fn passed(detail: &str) -> CheckResult {
    CheckResult {
        check: "status_check".to_string(),
        passed: true,
        detail: Some(detail.to_string()),
    }
}

fn failed(detail: String) -> CheckResult {
    CheckResult {
        check: "status_check".to_string(),
        passed: false,
        detail: Some(detail),
    }
}

/// Check the disclosed credential's Token Status List status.
///
/// A missing `status.status_list` claim passes (the credential is not
/// revocable). A revoked/suspended index, a malformed status claim, or a
/// Status List Token failing trust-anchor/`sub`/`exp` verification is a
/// **failed** check. Only an IO/network failure fetching the token is a hard
/// `Err(VerificationError::StatusUnavailable)`.
pub async fn check_status(
    disclosed_claims: &Value,
    trust_store: &TrustStore,
    resolver: &dyn StatusListResolver,
    now_unix: u64,
) -> Result<CheckResult, VerificationError> {
    let status_list = match disclosed_claims
        .get("status")
        .and_then(|s| s.get("status_list"))
    {
        Some(sl) => sl,
        None => return Ok(passed("no status list claim present")),
    };

    let uri = match status_list.get("uri").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return Ok(failed("status_list.uri missing or not a string".to_string())),
    };
    let idx = match status_list.get("idx").and_then(|v| v.as_u64()) {
        Some(i) => i,
        None => return Ok(failed("status_list.idx missing or not an integer".to_string())),
    };

    // IO: fetch the token. A network failure is a hard, recoverable error.
    let token = resolver.fetch(uri).await?;

    // Per draft-ietf-oauth-status-list-14 §5.1 the token's `sub` MUST equal the
    // referenced token's `uri`, so we verify against `uri` as the expected sub.
    let verified = match verify_status_list_token(&token, trust_store, uri, now_unix) {
        Ok(v) => v,
        Err(e) => return Ok(failed(format!("status list token verification failed: {e}"))),
    };

    match verified.status_at(idx) {
        Ok(StatusValue::Valid) => Ok(passed(&format!("index {idx} is valid"))),
        Ok(other) => Ok(failed(format!(
            "credential status at index {idx} is {other:?}"
        ))),
        Err(e) => Ok(failed(format!("status lookup failed at index {idx}: {e}"))),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A resolver returning a fixed token, or an error if `token` is `None`.
    pub struct MockResolver {
        pub token: Option<String>,
    }

    #[async_trait::async_trait]
    impl StatusListResolver for MockResolver {
        async fn fetch(&self, _uri: &str) -> Result<String, VerificationError> {
            match &self.token {
                Some(t) => Ok(t.clone()),
                None => Err(VerificationError::StatusUnavailable(
                    "mock resolver has no token".to_string(),
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockResolver;
    use super::*;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::status_list::{build_status_list_token, StatusList, StatusListTokenClaims};
    use foundry_core::trust::{build_x5c, TrustStore};
    use serde_json::json;

    const URI: &str = "https://issuer.example/statuslists/1";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // A (trust_store, token) pair whose status list marks `revoked_idx` Invalid.
    fn token_with_revoked(revoked_idx: usize, sub: &str) -> (TrustStore, String) {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        let signer =
            FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let x5c = build_x5c(&[leaf.cert_pem.into_bytes()]).unwrap();
        let trust_store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();

        let mut values = vec![0u8; revoked_idx + 1];
        values[revoked_idx] = 1; // Invalid
        let list = StatusList::build(&values, 2, None).unwrap();
        let n = now() as i64;
        let claims = StatusListTokenClaims {
            sub: sub.to_string(),
            iat: n - 100,
            exp: Some(n + 3600),
            ttl: None,
        };
        let token = build_status_list_token(claims, &list, &signer, Some(x5c)).unwrap();
        (trust_store, token)
    }

    #[tokio::test]
    async fn no_status_claim_passes() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let trust_store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        let resolver = MockResolver { token: None };
        let claims = json!({ "vct": "x", "given_name": "Alice" });
        let r = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap();
        assert!(r.passed);
        assert_eq!(r.check, "status_check");
    }

    #[tokio::test]
    async fn valid_index_passes() {
        let (trust_store, token) = token_with_revoked(7, URI);
        let resolver = MockResolver { token: Some(token) };
        let claims = json!({ "status": { "status_list": { "idx": 3, "uri": URI } } });
        let r = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap();
        assert!(r.passed, "detail={:?}", r.detail);
    }

    #[tokio::test]
    async fn revoked_index_fails() {
        let (trust_store, token) = token_with_revoked(7, URI);
        let resolver = MockResolver { token: Some(token) };
        let claims = json!({ "status": { "status_list": { "idx": 7, "uri": URI } } });
        let r = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap();
        assert!(!r.passed);
        assert!(r.detail.unwrap().contains("Invalid"));
    }

    #[tokio::test]
    async fn network_failure_is_hard_error() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let trust_store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        let resolver = MockResolver { token: None }; // errors on fetch
        let claims = json!({ "status": { "status_list": { "idx": 1, "uri": URI } } });
        let err = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::StatusUnavailable(_)));
    }

    #[tokio::test]
    async fn subject_mismatch_fails_check() {
        // Token sub differs from the credential's uri -> verification fails -> failed check.
        let (trust_store, token) = token_with_revoked(2, "https://issuer.example/statuslists/OTHER");
        let resolver = MockResolver { token: Some(token) };
        let claims = json!({ "status": { "status_list": { "idx": 0, "uri": URI } } });
        let r = check_status(&claims, &trust_store, &resolver, now())
            .await
            .unwrap();
        assert!(!r.passed);
    }
}
```

- [ ] **Step 4: Register the module in `crates/foundry-verifier/src/lib.rs`**

Edit 1 — add the module declaration (after Task 1 this block starts with `pub mod dcql;`). Change:
```rust
pub mod dcql;
pub mod error;
pub mod request;
pub mod transaction;
pub mod verify;
```
to:
```rust
pub mod dcql;
pub mod error;
pub mod request;
pub mod status;
pub mod transaction;
pub mod verify;
```

Edit 2 — add the re-exports. Change:
```rust
pub use error::VerificationError;
pub use dcql::{check_dcql_match, PresentedFormat};
```
to:
```rust
pub use error::VerificationError;
pub use dcql::{check_dcql_match, PresentedFormat};
pub use status::{check_status, HttpStatusListResolver, StatusListResolver};
```

- [ ] **Step 5: Run the status unit tests**

Run: `cargo test -p foundry-verifier status::`
Expected: 5 tests pass (`no_status_claim_passes`, `valid_index_passes`, `revoked_index_fails`, `network_failure_is_hard_error`, `subject_mismatch_fails_check`).

- [ ] **Step 6: Make the verify engine `async` and wire in the status check (`crates/foundry-verifier/src/verify.rs`)**

Edit 1 — add imports. Change:
```rust
use crate::dcql::{check_dcql_match, PresentedFormat};
```
to:
```rust
use crate::dcql::{check_dcql_match, PresentedFormat};
use crate::status::{check_status, StatusListResolver};
```

Edit 2 — make `verify_vp_response` async + resolver param. Replace the Task 1 version — change:
```rust
pub fn verify_vp_response(
    config: &Config,
    tx: &mut VerificationTransaction,
    encrypted_jwe_str: &str,
) -> Result<VerificationResult, VerificationError> {
    match do_verify_vp_response(config, tx, encrypted_jwe_str) {
        Ok(result) => {
            tx.state = if result.verified {
                VerificationState::Verified
            } else {
                VerificationState::Failed
            };
            tx.result = Some(result.clone());
            Ok(result)
        }
        Err(err) => {
            tx.state = VerificationState::Failed;
            Err(err)
        }
    }
}
```
to:
```rust
pub async fn verify_vp_response(
    config: &Config,
    tx: &mut VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
) -> Result<VerificationResult, VerificationError> {
    match do_verify_vp_response(config, tx, encrypted_jwe_str, resolver).await {
        Ok(result) => {
            tx.state = if result.verified {
                VerificationState::Verified
            } else {
                VerificationState::Failed
            };
            tx.result = Some(result.clone());
            Ok(result)
        }
        Err(err) => {
            tx.state = VerificationState::Failed;
            Err(err)
        }
    }
}
```

Edit 3 — make `do_verify_vp_response` async + resolver param. Change:
```rust
fn do_verify_vp_response(
    config: &Config,
    tx: &VerificationTransaction,
    encrypted_jwe_str: &str,
) -> Result<VerificationResult, VerificationError> {
```
to:
```rust
async fn do_verify_vp_response(
    config: &Config,
    tx: &VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
) -> Result<VerificationResult, VerificationError> {
```

Edit 4 — restructure the disclosure-branch tail (the Task 1 version) into shared per-format variables and add the status check. Change:
```rust
    let mut disclosed_claims = serde_json::Map::new();

    if let Some(jwt_str) = vp_token.as_str() {
        let verified = foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc(
            jwt_str,
            &trust_store,
            &client_id,
            &tx.nonce,
            now_unix,
        )
        .map_err(|e| VerificationError::Failed(e.to_string()))?;

        checks.push(CheckResult {
            check: "sd_jwt_vc_signature_and_kb_jwt".to_string(),
            passed: true,
            detail: None,
        });

        if let Value::Object(map) = verified.claims {
            for (k, v) in map {
                disclosed_claims.insert(k, v);
            }
        }
    } else {
        return Err(VerificationError::Failed(
            "unsupported vp_token format".to_string(),
        ));
    }

    let claims_value = Value::Object(disclosed_claims);

    // 3. DCQL query satisfaction (SD-JWT VC path)
    checks.push(check_dcql_match(
        &tx.dcql_query,
        PresentedFormat::SdJwtVc,
        &claims_value,
        None,
    ));

    // 4. Overall verdict is the AND of every check performed.
    let verified = checks.iter().all(|c| c.passed);
    Ok(VerificationResult {
        verified,
        checks,
        claims: claims_value,
    })
}
```
to:
```rust
    // 3. Credential-format-specific signature/binding verification + disclosure.
    let mut disclosed_claims = serde_json::Map::new();
    let presented_format;
    let doc_type: Option<String>;

    if let Some(jwt_str) = vp_token.as_str() {
        let verified = foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc(
            jwt_str,
            &trust_store,
            &client_id,
            &tx.nonce,
            now_unix,
        )
        .map_err(|e| VerificationError::Failed(e.to_string()))?;

        checks.push(CheckResult {
            check: "sd_jwt_vc_signature_and_kb_jwt".to_string(),
            passed: true,
            detail: None,
        });

        if let Value::Object(map) = verified.claims {
            for (k, v) in map {
                disclosed_claims.insert(k, v);
            }
        }
        presented_format = PresentedFormat::SdJwtVc;
        doc_type = None;
    } else {
        return Err(VerificationError::Failed(
            "unsupported vp_token format".to_string(),
        ));
    }

    let claims_value = Value::Object(disclosed_claims);

    // 4. DCQL query satisfaction (shared across credential formats).
    checks.push(check_dcql_match(
        &tx.dcql_query,
        presented_format,
        &claims_value,
        doc_type.as_deref(),
    ));

    // 5. Token Status List revocation check (shared across credential formats).
    //    A network failure fetching the token propagates as a hard error.
    checks.push(check_status(&claims_value, &trust_store, resolver, now_unix).await?);

    // 6. Overall verdict is the AND of every check performed.
    let verified = checks.iter().all(|c| c.passed);
    Ok(VerificationResult {
        verified,
        checks,
        claims: claims_value,
    })
}
```

Edit 5 — convert the five verify unit tests to async and inject a no-op resolver. At the top of the `#[cfg(test)] mod tests` block, add this import alongside the others:
```rust
    use crate::status::test_support::MockResolver;
```
Then, for **each** of the five test functions — `test_verify_vp_response_sd_jwt_vc`, `test_verify_vp_response_missing_vp_token`, `test_verify_vp_response_invalid_jwe`, `test_verify_vp_response_kb_nonce_mismatch`, and `test_verify_vp_response_dcql_vct_mismatch_is_not_verified` — change the attribute+signature from `#[test]\n    fn <name>() {` to `#[tokio::test]\n    async fn <name>() {`, and update the single `verify_vp_response(...)` call in each body:
  - In the three that bind the result to `res` or `err` via `verify_vp_response(&config, &mut tx, &jwe_str)`, change that expression to:
    ```rust
    let resolver = MockResolver { token: None };
    verify_vp_response(&config, &mut tx, &jwe_str, &resolver).await
    ```
    (i.e. declare `let resolver = MockResolver { token: None };` on the line above the existing `let res = ...`/`let err = ...` statement, and append `, &resolver).await` inside the call, replacing the trailing `)`).
  - In `test_verify_vp_response_invalid_jwe`, the call is `verify_vp_response(&config, &mut tx, "not.a.valid.jwe.token")`; declare `let resolver = MockResolver { token: None };` above it and change the call to `verify_vp_response(&config, &mut tx, "not.a.valid.jwe.token", &resolver).await`.

The resolver is never invoked in these tests (none of their credentials carry a `status.status_list` claim), so `token: None` is safe.

- [ ] **Step 7: Wire the resolver into the HTTP handler and map the 502 (`crates/foundry/src/server.rs`)**

Edit 1 — in `verifier_wallet_error_response`, add the `StatusUnavailable` arm. Change:
```rust
    let (status, code) = match e {
        Decryption(_) | Failed(_) | Serialization(_) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
```
to:
```rust
    let (status, code) = match e {
        Decryption(_) | Failed(_) | Serialization(_) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        StatusUnavailable(_) => (StatusCode::BAD_GATEWAY, "status_unavailable"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
```

Edit 2 — in `post_response_handler`, construct the resolver and await the call. Change:
```rust
    let verify_res =
        foundry_verifier::verify_vp_response(&state.config, &mut tx, &encrypted_jwe_str);
```
to:
```rust
    let resolver = match foundry_verifier::HttpStatusListResolver::new() {
        Ok(r) => r,
        Err(e) => return Err(verifier_wallet_error_response(&e)),
    };
    let verify_res =
        foundry_verifier::verify_vp_response(&state.config, &mut tx, &encrypted_jwe_str, &resolver)
            .await;
```

- [ ] **Step 8: Run the verifier crate tests and the whole workspace build**

Run: `cargo test -p foundry-verifier`
Expected: all `dcql::`, `status::`, `verify::`, `transaction::`, `request::`, `error::` tests pass.

Run: `cargo build`
Expected: workspace builds (confirms the `server.rs` handler change compiles against the new async signature).

- [ ] **Step 9: Commit**

```bash
git add crates/foundry-verifier/Cargo.toml crates/foundry-verifier/src/status.rs crates/foundry-verifier/src/error.rs crates/foundry-verifier/src/lib.rs crates/foundry-verifier/src/verify.rs crates/foundry/src/server.rs
git commit -m "feat(verifier): check Token Status List revocation via injectable resolver"
```

---

### Task 3: mdoc Presentation Verification Wiring

Routes an mdoc-shaped `vp_token` (a JSON object `{ "mdoc": <b64url CBOR>, "device_signature": <b64url COSE_Sign1> }`) into the existing-but-unused `foundry_mdoc::verifier::verify_mdoc`, merges its namespaced claims into the same `VerificationResult.claims` shape, and feeds the mdoc path through the same `check_dcql_match` (with docType) and `check_status` helpers. First extends `MdocVerificationResult` with the MSO `doc_type` (needed for the DCQL `doctype_value` check).

**Design decisions (locked for this task):**
- **`vp_token` envelope for mdoc: a JSON object `{ "mdoc", "device_signature" }` (both base64url).** `verify_mdoc` requires two separate byte blobs — the issued mdoc CBOR (`build_mdoc` output) and a detached `DeviceAuth` COSE_Sign1 over the OpenID4VP-handover SessionTranscript — and no ISO 18013-7 `DeviceResponse` parser exists in the codebase. A minimal JSON envelope is the smallest testable adapter (YAGNI over implementing full `DeviceResponse` parsing). Routing is by `vp_token` **shape** (string ⇒ SD-JWT VC; object ⇒ mdoc); `check_dcql_match` independently enforces that the shape agrees with the DCQL-requested `format`.
- **SessionTranscript inputs are reconstructed verifier-side** from values it already owns: `client_id = "x509_san_dns:{host}"`, `response_uri = "{public_base_url}/vp/response/{tx.id}"`, and `tx.nonce` — matching `foundry_mdoc::types::serialize_session_transcript(Some(client_id), Some(response_uri), nonce)`.
- **mdoc claims are represented namespaced** in `VerificationResult.claims` as `{ namespace: { element: value } }`, so DCQL mdoc claim paths `[namespace, element]` resolve directly via `check_dcql_match`.

**Files:**
- Modify: `crates/foundry-mdoc/src/verifier.rs` (add `doc_type` to `MdocVerificationResult`; update its one unit test)
- Modify: `crates/foundry-verifier/src/verify.rs` (base64 imports; mdoc branch; add one unit test)

**Interfaces:**
- Consumes: `foundry_mdoc::verifier::{verify_mdoc, MdocVerificationResult}` (now with `pub doc_type: String`), `foundry_mdoc::builder::{build_mdoc, MdocClaims}` and `foundry_mdoc::types::serialize_session_transcript` (tests only), `crate::dcql::PresentedFormat::MsoMdoc`.
- Produces: no new public items; extends `do_verify_vp_response`'s `vp_token` routing to accept the mdoc envelope.

- [ ] **Step 1: Add `doc_type` to `MdocVerificationResult` (`crates/foundry-mdoc/src/verifier.rs`)**

Edit 1 — add the field. Change:
```rust
#[derive(Debug)]
pub struct MdocVerificationResult {
    pub claims: BTreeMap<String, BTreeMap<String, JsonValue>>,
    pub device_key_jwk: JsonValue,
    pub issuer_x5c: Option<Vec<String>>,
}
```
to:
```rust
#[derive(Debug)]
pub struct MdocVerificationResult {
    pub claims: BTreeMap<String, BTreeMap<String, JsonValue>>,
    pub device_key_jwk: JsonValue,
    pub issuer_x5c: Option<Vec<String>>,
    pub doc_type: String,
}
```

Edit 2 — populate it from the verified MSO. Change:
```rust
    Ok(MdocVerificationResult {
        claims: verified_claims,
        device_key_jwk,
        issuer_x5c: Some(x5c_b64s),
    })
```
to:
```rust
    Ok(MdocVerificationResult {
        claims: verified_claims,
        device_key_jwk,
        issuer_x5c: Some(x5c_b64s),
        doc_type: mso.doc_type.clone(),
    })
```

- [ ] **Step 2: Assert `doc_type` in the existing mdoc verifier test**

In `crates/foundry-mdoc/src/verifier.rs`, in `parses_and_verifies_valid_mdoc_presentation`, change:
```rust
        assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");
```
to:
```rust
        assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");
        assert_eq!(res.doc_type, "org.iso.18013.5.1.mDL");
```

- [ ] **Step 3: Run the mdoc crate tests**

Run: `cargo test -p foundry-mdoc`
Expected: all tests pass, including the updated `parses_and_verifies_valid_mdoc_presentation`.

- [ ] **Step 4: Commit the foundry-mdoc change**

```bash
git add crates/foundry-mdoc/src/verifier.rs
git commit -m "feat(mdoc): surface MSO docType in MdocVerificationResult"
```

- [ ] **Step 5: Add base64 imports to `crates/foundry-verifier/src/verify.rs`**

Change:
```rust
use foundry_core::config::Config;
```
to:
```rust
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::config::Config;
```

- [ ] **Step 6: Add the mdoc branch to `do_verify_vp_response`**

Replace the `else` branch introduced in Task 2 Edit 4. Change:
```rust
        presented_format = PresentedFormat::SdJwtVc;
        doc_type = None;
    } else {
        return Err(VerificationError::Failed(
            "unsupported vp_token format".to_string(),
        ));
    }
```
to:
```rust
        presented_format = PresentedFormat::SdJwtVc;
        doc_type = None;
    } else if let Some(obj) = vp_token.as_object() {
        // mdoc presentation envelope:
        //   { "mdoc": <b64url(issued mdoc CBOR)>,
        //     "device_signature": <b64url(COSE_Sign1 over SessionTranscript)> }
        let mdoc_b64 = obj
            .get("mdoc")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VerificationError::Failed("mdoc vp_token missing 'mdoc'".to_string()))?;
        let dev_sig_b64 = obj
            .get("device_signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VerificationError::Failed("mdoc vp_token missing 'device_signature'".to_string())
            })?;
        let mdoc_bytes = B64URL
            .decode(mdoc_b64)
            .map_err(|e| VerificationError::Failed(format!("mdoc base64 decode: {e}")))?;
        let dev_sig_bytes = B64URL
            .decode(dev_sig_b64)
            .map_err(|e| VerificationError::Failed(format!("device_signature base64 decode: {e}")))?;

        let response_uri = format!("{base_url}/vp/response/{}", tx.id);
        let mdoc_res = foundry_mdoc::verifier::verify_mdoc(
            &mdoc_bytes,
            &trust_store,
            Some(client_id.clone()),
            Some(response_uri),
            tx.nonce.clone(),
            &dev_sig_bytes,
            now_unix,
        )
        .map_err(|e| VerificationError::Failed(format!("mdoc verification failed: {e}")))?;

        checks.push(CheckResult {
            check: "mdoc_issuer_auth_and_device_signature".to_string(),
            passed: true,
            detail: None,
        });

        for (ns, elements) in mdoc_res.claims {
            let mut ns_obj = serde_json::Map::new();
            for (k, v) in elements {
                ns_obj.insert(k, v);
            }
            disclosed_claims.insert(ns, Value::Object(ns_obj));
        }
        presented_format = PresentedFormat::MsoMdoc;
        doc_type = Some(mdoc_res.doc_type);
    } else {
        return Err(VerificationError::Failed(
            "unsupported vp_token format".to_string(),
        ));
    }
```

- [ ] **Step 7: Add an mdoc unit test to `crates/foundry-verifier/src/verify.rs`**

At the top of the `#[cfg(test)] mod tests` block, add these imports alongside the existing ones:
```rust
    use foundry_mdoc::builder::{build_mdoc, MdocClaims};
    use foundry_mdoc::types::serialize_session_transcript;
    use std::collections::BTreeMap;
```
Then append this test inside the `mod tests` block:
```rust
    #[tokio::test]
    async fn test_verify_vp_response_mdoc_presentation() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let config = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        // Device (holder) key.
        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(&d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // Request an mdoc of the doctype/namespace/element we will issue.
        tx.dcql_query = serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
            }]
        });

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Build the issued mdoc.
        let mut elements = std::collections::BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        let mut namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        let mdoc_claims = MdocClaims {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces,
            device_key_jwk: d_jwk_pub,
            signed_at: (now - 100) as i64,
            valid_until: (now + 3600) as i64,
        };
        let mdoc_bytes =
            build_mdoc(mdoc_claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // Build the detached DeviceAuth COSE_Sign1 over the OpenID4VP SessionTranscript.
        let client_id = "x509_san_dns:localhost".to_string();
        let response_uri = format!("https://localhost:8443/vp/response/{}", tx.id);
        let transcript =
            serialize_session_transcript(Some(client_id), Some(response_uri), tx.nonce.clone())
                .unwrap();
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
        let partial = coset::CoseSign1Builder::new()
            .protected(protected.clone())
            .build();
        let d_tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            partial.protected.clone(),
            None,
            &[],
            &transcript,
        );
        let sig = {
            use foundry_core::crypto::Signer as _;
            d_signer.sign(&d_tbs).unwrap()
        };
        let d_sign = coset::CoseSign1Builder::new()
            .protected(protected)
            .signature(sig)
            .build();
        let d_sig_bytes = coset::CborSerializable::to_vec(d_sign).unwrap();

        // Envelope + JWE.
        let vp_token = serde_json::json!({
            "mdoc": B64URL.encode(&mdoc_bytes),
            "device_signature": B64URL.encode(&d_sig_bytes),
        });
        let jwe_str = JweBuilder::new()
            .payload(serde_json::json!({ "vp_token": vp_token }))
            .recipient_key_json(&tx.ephem_public_jwk)
            .unwrap()
            .alg("ECDH-ES")
            .enc("A128GCM")
            .build()
            .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(res.verified, "checks={:?}", res.checks);
        assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "mdoc_issuer_auth_and_device_signature" && c.passed));
        assert!(res.checks.iter().any(|c| c.check == "dcql_match" && c.passed));
        assert!(res.checks.iter().any(|c| c.check == "status_check" && c.passed));
    }
```

This test uses `B64URL` (imported into the module in Step 5), `MockResolver` (imported in Task 2 Edit 5), and `coset` (dev-dep added in Task 2 Step 1). It reuses the module's existing `test_pki`, `test_config`, `sample_tx`, `der_b64` helpers and the existing `EcCurve`/`EcKeyPair`/`JweBuilder` imports.

- [ ] **Step 8: Run the verifier tests**

Run: `cargo test -p foundry-verifier`
Expected: all tests pass, including the new `test_verify_vp_response_mdoc_presentation`.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs
git commit -m "feat(verifier): verify mdoc presentations and apply DCQL + status checks"
```

---

### Task 4: HTTP-Level Integration Tests (DCQL mismatch, revocation, regression, mdoc)

Adds end-to-end tests in `crates/foundry/tests/wallet_verification.rs` exercising the full wallet flow through the real axum handlers: a DCQL mismatch is rejected, a revoked credential is rejected (via a real in-process TCP server serving a signed Status List Token that the handler's `HttpStatusListResolver` really fetches), a valid non-revoked credential matching the DCQL query still verifies, and an mdoc presentation is accepted.

**Design decisions (locked for this task):**
- **Policy rejections return HTTP 200 with `verified: false`** (the verification *completed* with a negative verdict); the per-check detail is asserted from the response body. Only structural/crypto failures are 4xx and status-fetch network failures are 502 (not exercised here; unit-tested in Task 2).
- **Revocation is proven honestly over real HTTP.** The `post_response_handler` always builds an `HttpStatusListResolver`; rather than mock it, the test binds a real `127.0.0.1:0` listener serving `GET /statuslists/1` → a signed Status List Token, and issues the credential with `status_list_uri` pointing at that address. The token is signed by the same issuer leaf (chaining to the test root trust anchor) with `sub == uri`.

**Files:**
- Modify: `crates/foundry/Cargo.toml` (dev-deps: add `foundry-mdoc`, `coset`)
- Modify: `crates/foundry/tests/wallet_verification.rs` (add imports, two helpers, four `#[tokio::test]`s)

**Interfaces:**
- Consumes: `foundry::server::{admin_router, wallet_router, AppState}`, `foundry_verifier::{CreateVerificationResponse, VerificationResult}`, `foundry_core::status_list::{StatusList, StatusListTokenClaims, build_status_list_token}`, `foundry_core::trust::build_x5c`, `foundry_core::crypto::{FileSigner, SignatureAlgorithm}`, `foundry_mdoc::builder::{build_mdoc, MdocClaims}`, `foundry_mdoc::types::serialize_session_transcript`.
- Produces: test-only helper `build_status_token(...)` (the status server is bound + served inline in `run_status_flow`).

- [ ] **Step 1: Add dev-dependencies to `crates/foundry/Cargo.toml`**

Under `[dev-dependencies]`, add (after `openid4vp = { path = "../openid4vp" }`):
```toml
foundry-mdoc = { path = "../foundry-mdoc" }
coset = { workspace = true }
```

- [ ] **Step 2: Add imports and helpers at the top of `crates/foundry/tests/wallet_verification.rs`**

After the existing `use tower::ServiceExt;` line, add (a single helper; the in-process status server is bound and served inline in `run_status_flow` in Step 4):
```rust
use axum::routing::get;
use foundry_core::status_list::{build_status_list_token, StatusList, StatusListTokenClaims};
use foundry_core::trust::build_x5c;
use foundry_mdoc::builder::{build_mdoc, MdocClaims};
use foundry_mdoc::types::serialize_session_transcript;

/// Build a signed Status List Token (compact JWS, `statuslist+jwt`) whose list
/// marks `revoked_idx` (if any) Invalid and everything else Valid, signed by
/// the issuer leaf so it chains to the test root trust anchor. `sub == uri`.
fn build_status_token(
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
    sub: &str,
    len: usize,
    revoked_idx: Option<u64>,
) -> String {
    let signer = FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
    let x5c = build_x5c(&[issuer_cert_pem.as_bytes().to_vec()]).unwrap();
    let mut values = vec![0u8; len];
    if let Some(i) = revoked_idx {
        values[i as usize] = 1; // Invalid
    }
    let list = StatusList::build(&values, 2, None).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = StatusListTokenClaims {
        sub: sub.to_string(),
        iat: now - 100,
        exp: Some(now + 3600),
        ttl: None,
    };
    build_status_list_token(claims, &list, &signer, Some(x5c)).unwrap()
}
```

- [ ] **Step 3: Add the DCQL-mismatch rejection test**

Append to `crates/foundry/tests/wallet_verification.rs`:
```rust
#[tokio::test]
async fn dcql_vct_mismatch_is_rejected() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    // Request vct "pid" ...
    let create_req_body = serde_json::json!({
        "dcql_query": { "credentials": [{
            "id": "c1", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
        }]},
        "transport": "request_uri"
    });
    let create_req = Request::builder()
        .method("POST")
        .uri("/admin/verification/requests")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(create_req_body.to_string()))
        .unwrap();
    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX).await.unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX).await.unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    // ... but issue a credential with a DIFFERENT vct.
    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(&holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer =
        FileSigner::from_pem(&holder_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut select = serde_json::Map::new();
    select.insert("given_name".to_string(), serde_json::json!("Alice"));
    let claims = IssuerClaims {
        iss: "localhost".to_string(),
        sub: "did:example:holder".to_string(),
        iat: (now - 100) as i64,
        exp: (now + 3600) as i64,
        vct: "https://localhost:8443/vct/OTHER".to_string(),
        cnf_jwk: holder_pub_jwk,
        status_list_index: None,
        status_list_uri: None,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };
    let issuer_pres =
        build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(issuer_cert_pem.as_bytes())]))
            .unwrap();
    let presentation = attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &nonce).unwrap();
    let jwe_str = JweBuilder::new()
        .payload(serde_json::json!({ "vp_token": presentation }))
        .recipient_key_json(&ephem_public_jwk)
        .unwrap()
        .alg("ECDH-ES")
        .enc("A128GCM")
        .build()
        .unwrap();

    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(jwe_str))
        .unwrap();
    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);
    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX).await.unwrap();
    let verify_result: VerificationResult = serde_json::from_slice(&verify_bytes).unwrap();

    assert!(!verify_result.verified, "DCQL vct mismatch must not verify");
    assert!(verify_result
        .checks
        .iter()
        .any(|c| c.check == "dcql_match" && !c.passed));
}
```

- [ ] **Step 4: Add the revoked-credential and valid-regression tests**

Both follow the same flow; a shared inner helper keeps them DRY. Append:
```rust
/// Run the full SD-JWT VC verification flow issuing a credential whose
/// `status.status_list` points at an in-process status server. Returns the
/// decoded `VerificationResult`.
async fn run_status_flow(revoked_idx: Option<u64>, credential_idx: u64) -> VerificationResult {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    let create_req_body = serde_json::json!({
        "dcql_query": { "credentials": [{
            "id": "c1", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
        }]},
        "transport": "request_uri"
    });
    let create_req = Request::builder()
        .method("POST")
        .uri("/admin/verification/requests")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(create_req_body.to_string()))
        .unwrap();
    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX).await.unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX).await.unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    // Status server: bind first to learn the port, so the token's `sub` can
    // equal the credential's `uri` (draft-ietf-oauth-status-list-14 §5.1).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let uri = format!("http://{addr}/statuslists/1");
    let token = build_status_token(&issuer_cert_pem, &issuer_key_pem, &uri, 128, revoked_idx);
    let app = axum::Router::new().route(
        "/statuslists/1",
        get(move || {
            let token = token.clone();
            async move { token }
        }),
    );
    let _server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });

    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(&holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer =
        FileSigner::from_pem(&holder_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut select = serde_json::Map::new();
    select.insert("given_name".to_string(), serde_json::json!("Alice"));
    let claims = IssuerClaims {
        iss: "localhost".to_string(),
        sub: "did:example:holder".to_string(),
        iat: (now - 100) as i64,
        exp: (now + 3600) as i64,
        vct: "https://localhost:8443/vct/pid".to_string(),
        cnf_jwk: holder_pub_jwk,
        status_list_index: Some(credential_idx),
        status_list_uri: Some(uri),
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };
    let issuer_pres =
        build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(issuer_cert_pem.as_bytes())]))
            .unwrap();
    let presentation = attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &nonce).unwrap();
    let jwe_str = JweBuilder::new()
        .payload(serde_json::json!({ "vp_token": presentation }))
        .recipient_key_json(&ephem_public_jwk)
        .unwrap()
        .alg("ECDH-ES")
        .enc("A128GCM")
        .build()
        .unwrap();

    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(jwe_str))
        .unwrap();
    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);
    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&verify_bytes).unwrap()
}

#[tokio::test]
async fn revoked_credential_is_rejected() {
    // Credential at index 5; the status list marks index 5 revoked.
    let result = run_status_flow(Some(5), 5).await;
    assert!(!result.verified, "revoked credential must not verify");
    assert!(result
        .checks
        .iter()
        .any(|c| c.check == "status_check" && !c.passed));
}

#[tokio::test]
async fn valid_non_revoked_credential_succeeds() {
    // Credential at index 5; nothing is revoked.
    let result = run_status_flow(None, 5).await;
    assert!(result.verified, "checks={:?}", result.checks);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check == "status_check" && c.passed));
    assert!(result
        .checks
        .iter()
        .any(|c| c.check == "dcql_match" && c.passed));
    assert_eq!(result.claims["given_name"], "Alice");
}
```

- [ ] **Step 5: Add the mdoc acceptance test**

Append:
```rust
#[tokio::test]
async fn mdoc_presentation_is_accepted() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    let create_req_body = serde_json::json!({
        "dcql_query": { "credentials": [{
            "id": "c1", "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
            "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
        }]},
        "transport": "request_uri"
    });
    let create_req = Request::builder()
        .method("POST")
        .uri("/admin/verification/requests")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(create_req_body.to_string()))
        .unwrap();
    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX).await.unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX).await.unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();
    let response_uri = format!("https://localhost:8443/vp/response/{verification_id}");

    // Device key + issued mdoc.
    let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let d_jwk_pub = serde_json::to_value(&d_kp.to_jwk_public_key()).unwrap();
    let d_signer =
        FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let mut elements = std::collections::BTreeMap::new();
    elements.insert("given_name".to_string(), serde_json::json!("John"));
    let mut namespaces = std::collections::BTreeMap::new();
    namespaces.insert("org.iso.18013.5.1".to_string(), elements);
    let mdoc_claims = MdocClaims {
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
        namespaces,
        device_key_jwk: d_jwk_pub,
        signed_at: (now - 100) as i64,
        valid_until: (now + 3600) as i64,
    };
    let mdoc_bytes =
        build_mdoc(mdoc_claims, &issuer_signer, Some(vec![der_b64(issuer_cert_pem.as_bytes())]))
            .unwrap();

    // Detached DeviceAuth over the reconstructed SessionTranscript.
    let transcript =
        serialize_session_transcript(Some(client_id), Some(response_uri), nonce).unwrap();
    let protected = coset::HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::ES256)
        .build();
    let partial = coset::CoseSign1Builder::new()
        .protected(protected.clone())
        .build();
    let d_tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        partial.protected.clone(),
        None,
        &[],
        &transcript,
    );
    let sig = {
        use foundry_core::crypto::Signer as _;
        d_signer.sign(&d_tbs).unwrap()
    };
    let d_sign = coset::CoseSign1Builder::new()
        .protected(protected)
        .signature(sig)
        .build();
    let d_sig_bytes = coset::CborSerializable::to_vec(d_sign).unwrap();

    let vp_token = serde_json::json!({
        "mdoc": B64URL.encode(&mdoc_bytes),
        "device_signature": B64URL.encode(&d_sig_bytes),
    });
    let jwe_str = JweBuilder::new()
        .payload(serde_json::json!({ "vp_token": vp_token }))
        .recipient_key_json(&ephem_public_jwk)
        .unwrap()
        .alg("ECDH-ES")
        .enc("A128GCM")
        .build()
        .unwrap();

    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(jwe_str))
        .unwrap();
    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);
    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX).await.unwrap();
    let verify_result: VerificationResult = serde_json::from_slice(&verify_bytes).unwrap();

    assert!(verify_result.verified, "checks={:?}", verify_result.checks);
    assert_eq!(verify_result.claims["org.iso.18013.5.1"]["given_name"], "John");
    assert!(verify_result
        .checks
        .iter()
        .any(|c| c.check == "mdoc_issuer_auth_and_device_signature" && c.passed));
}
```

- [ ] **Step 6: Run the integration tests, then the full workspace suite**

Run: `cargo test -p foundry --test wallet_verification`
Expected: all six tests pass — the two pre-existing (`full_verification_flow_end_to_end`, `resubmitting_a_verification_response_is_rejected`) plus the four new ones (`dcql_vct_mismatch_is_rejected`, `revoked_credential_is_rejected`, `valid_non_revoked_credential_succeeds`, `mdoc_presentation_is_accepted`).

Run: `cargo test`
Expected: the entire workspace test suite passes.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/Cargo.toml crates/foundry/tests/wallet_verification.rs
git commit -m "test(verifier): HTTP-level DCQL, revocation, and mdoc verification coverage"
```

---

## Plan Self-Review

**1. Spec coverage**

| Required scope item | Task |
|---|---|
| DCQL query matching (format/vct/doctype, mandatory claim paths, `values` constraints) with a `dcql_match` `CheckResult` | Task 1 (SD-JWT), Task 3 (mdoc reuses the same helper) |
| DCQL mismatch ⇒ `verified: false` (decision: failed check + `Ok`, not hard `Err`) | Task 1 (Edit 4 makes `verified` the AND of all checks; `verify_vp_response` sets `state` from `result.verified`) |
| Token Status List revocation check with a `status_check` `CheckResult`; revoked ⇒ overall failure | Task 2 |
| Fetch status token over HTTP; clean recoverable error on network failure (no panic) | Task 2 (`HttpStatusListResolver`, `VerificationError::StatusUnavailable`, mapped to HTTP 502) |
| Decide same-instance vs HTTP fetch and document it | Task 2 design-decisions block (HTTP only; same-instance shortcut rejected with rationale) |
| Confirm `status` claim surfaces from `verify_sd_jwt_vc` (whether `foundry-sd-jwt-vc` needs a change) | Confirmed in exploration: `verify_sd_jwt_vc` retains all non-`_sd`/`_sd_alg` top-level claims, so `status` already surfaces — **no `foundry-sd-jwt-vc` change needed** (user's optional Task 5 is unnecessary; noted below) |
| mdoc presentation verification wired to `verify_mdoc`; claims merged into same shape; DCQL + status applied to mdoc too | Task 3 (branch + shared helpers), Task 4 (mdoc E2E) |
| Factor DCQL matching + status checking as shared helpers between formats | Tasks 1–3: `check_dcql_match` and `check_status` are format-agnostic; the mdoc branch calls the identical tail |
| Integration tests: DCQL mismatch rejected, revoked rejected, valid regression, mdoc accepted | Task 4 |
| Preserve per-check `checks` transparency; every concern adds a named `CheckResult` | All: `jwe_decryption`, `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check` |
| No panics/unwraps in request-handling paths | All non-test code returns `Result`; `unwrap()` appears only in `#[cfg(test)]` code |

**Optional user Task 5 (surface `status` from `foundry-sd-jwt-vc`):** Not required. Verified `crates/foundry-sd-jwt-vc/src/verifier.rs` copies every remaining top-level payload key into `claims` after removing only `_sd` and `_sd_alg`, so the issuer's top-level `status` object is already present in `VerificationResult.claims`. No task added; if a future reviewer disputes this, the `valid_non_revoked_credential_succeeds` E2E (Task 4) fails loudly if `status` is absent, so the assumption is test-guarded.

**2. Placeholder scan**

No `TBD`/`TODO`/"implement later"/"add error handling"/"similar to Task N" placeholders. Every code step contains complete, compilable code. Every "run" step states the exact command and expected outcome. The only prose-only step is Task 2 Edit 5 (converting five near-identical existing tests), which is unavoidably descriptive because two of the five call sites are textually identical (`let err = verify_vp_response(&config, &mut tx, &jwe_str).unwrap_err();`) and a verbatim find/replace would be ambiguous — the instruction gives the exact transformation and the resolver literal to insert.

**3. Type consistency**

- `PresentedFormat { SdJwtVc, MsoMdoc }` — defined Task 1, used Tasks 1/3. `ClaimFormatDesignation::DcSdJwt` / `MsoMDoc` are the real vendored variant names (verified in `crates/openid4vp/src/core/credential_format/mod.rs`), matched exactly in `PresentedFormat::matches`.
- `check_dcql_match(&Value, PresentedFormat, &Value, Option<&str>) -> CheckResult` — signature identical across Tasks 1, 3.
- `check_status(&Value, &TrustStore, &dyn StatusListResolver, u64) -> Result<CheckResult, VerificationError>` — Task 2 definition matches the Task 2 Edit 4 call `check_status(&claims_value, &trust_store, resolver, now_unix).await?`.
- `verify_vp_response(&Config, &mut VerificationTransaction, &str, &dyn StatusListResolver) -> Result<VerificationResult, VerificationError>` (async) — Task 2 definition matches all call sites: `server.rs` handler (Task 2 Step 7), verify unit tests (Task 2 Edit 5, Task 3 Step 7).
- `MdocVerificationResult.doc_type: String` — added Task 3 Step 1, consumed Task 3 Step 6 (`mdoc_res.doc_type`).
- `StatusValue::{Valid, Invalid, Suspended, ApplicationSpecific}` — the real variants (verified in `foundry-core`); `check_status` matches `Valid` as pass and everything else as fail (revoked credentials are `Invalid`).
- `IssuerClaims { status_list_index: Option<u64>, status_list_uri: Option<String>, .. }` — the real builder fields (verified in `crates/foundry-sd-jwt-vc/src/builder.rs`); used in Task 4 to embed the `status.status_list` claim.
- `serialize_session_transcript(Option<String>, Option<String>, String) -> Result<Vec<u8>, String>` and `verify_mdoc(&[u8], &TrustStore, Option<String>, Option<String>, String, &[u8], u64)` — the real signatures (verified in `foundry-mdoc`), matched in Task 3 branch and Task 4 mdoc test.
- Check names are string-identical between producers (`dcql.rs`, `status.rs`, `verify.rs`) and test assertions (`"dcql_match"`, `"status_check"`, `"mdoc_issuer_auth_and_device_signature"`, `"sd_jwt_vc_signature_and_kb_jwt"`).