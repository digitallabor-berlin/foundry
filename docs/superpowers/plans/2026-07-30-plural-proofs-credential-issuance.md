# Plural `proofs`/`credentials` Credential Endpoint — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `POST /credential` accept the OpenID4VCI plural `proofs` request shape and return the plural `credentials` response shape, so wallets built against `eudi-lib-jvm-openid4vci-kt` (and any other wallet using the current draft's batch-shaped wire format) can complete issuance end-to-end.

**Architecture:** `foundry-issuer::proof` gains a `ProofsRequest { jwt: Vec<String> }` wire type and a `verify_holder_proof(jwt_str: &str, ...)` that verifies one JWT at a time. `foundry-issuer::credential`'s `CredentialRequest`/`CredentialResponse` switch to `proofs: Option<ProofsRequest>` / `credentials: Vec<IssuedCredential>`, and `handle_credential_request` verifies every JWT in the array and builds one credential per verified proof (same claims/transaction, different holder key — this is the batch-issuance use case the plural shape exists for). The singular `proof`/`credential` shape is removed entirely (Option A — no dual-path support), so every producer/consumer of `/credential` in this repo (the vendored debug wallet and both HTTP test suites) is updated in lockstep.

**Tech Stack:** Rust, Axum, `josekit` (JWS/JWK), `serde`/`serde_json`, `utoipa` (OpenAPI schema derivation).

## Global Constraints

(No separate spec was written for this fix — root cause was confirmed via `systematic-debugging` and the design was approved inline. These constraints are copied from the project's root `AGENTS.md`, which binds every task below.)

- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** in `foundry-issuer`'s request-handling code outside `#[cfg(test)]` (root AGENTS.md §4.1). The new per-proof loop must return `IssuanceError` on every failure path, never panic.
- **Endpoint shape changes must be mirrored in the OpenAPI specs** (`openapi.json`, `openapi-wallet.json`) — root AGENTS.md §6. This is a wallet-facing (`/credential`) request/response shape change, so `openapi-wallet.json` must be regenerated, not just `openapi.rs`'s schema list edited.
- **No upward/sideways dependencies** — this plan touches only `foundry-issuer`, `crates/foundry` (openapi.rs, tests), and `crates/foundry-wallet`; none of these edits introduce a new dependency edge.
- **Gates before completion** (root AGENTS.md §5): `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` — all three must pass cleanly before this plan is considered done.

## File Structure

- `crates/foundry-issuer/src/proof.rs` — drops `ProofObject`; adds `ProofsRequest { jwt: Vec<String> }`; `verify_holder_proof` now takes a single JWT string instead of a `ProofObject`.
- `crates/foundry-issuer/src/credential.rs` — `CredentialRequest.proofs: Option<ProofsRequest>` (was `proof: Option<ProofObject>`); new `IssuedCredential { credential: String }`; `CredentialResponse { credentials: Vec<IssuedCredential>, notification_id: Option<String> }` (was `{ credential, c_nonce, c_nonce_expires_in }`); `handle_credential_request` verifies every JWT in `proofs.jwt` and builds one credential per proof.
- `crates/foundry-issuer/src/lib.rs` — re-export list updates (`ProofObject` → `ProofsRequest`; add `IssuedCredential`).
- `crates/foundry/src/openapi.rs` — `WalletApiDoc`'s `components(schemas(...))` list swaps `ProofObject` for `ProofsRequest` and adds `IssuedCredential`.
- `crates/foundry-wallet/src/actions/proof.rs` — `HolderProof.jwt: String` (was `proof_json: serde_json::Value` shaped `{"proof_type":"jwt","jwt":...}`).
- `crates/foundry-wallet/src/actions/issuance.rs` — builds `"proofs": {"jwt": [proof.jwt]}` instead of `"proof": proof.proof_json`; parses `cred_json["credentials"][0]["credential"]` instead of `cred_json["credential"]`.
- `crates/foundry/tests/wallet_issuance.rs` — `create_proof` helper returns a raw JWT string; all 6 call sites build `"proofs"` requests; the one response assertion reads `credentials[0].credential`.
- `crates/foundry/tests/e2e_full_flow.rs` — same `create_proof` / request / response updates, single call site.
- `openapi.json`, `openapi-wallet.json` — regenerated tracked artifacts (admin spec is untouched by this change but gets rewritten as a byproduct of the regen mechanism; only `openapi-wallet.json`'s `/credential` schemas actually change).

---

### Task 1: `foundry-issuer::proof` — plural-shaped proof verification

**Files:**
- Modify: `crates/foundry-issuer/src/proof.rs` (whole file, ~185 lines)
- Modify: `crates/foundry-issuer/src/lib.rs:27`

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub struct ProofsRequest { pub jwt: Vec<String> }` (Deserialize + Serialize + `utoipa::ToSchema`) and `pub fn verify_holder_proof(jwt_str: &str, expected_issuer: &str, expected_c_nonce: &str, c_nonce_expires_at: i64, now_unix: i64) -> Result<VerifiedProof, IssuanceError>` — both consumed by Task 2. `VerifiedProof { holder_jwk: Jwk }` is unchanged.

- [ ] **Step 1: Replace `crates/foundry-issuer/src/proof.rs` in full**

```rust
//! Holder proof of possession JWT verification for OpenID4VCI.

use crate::error::IssuanceError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256};
use serde::{Deserialize, Serialize};

/// Wire shape of the OpenID4VCI `proofs` request member. Only the `jwt`
/// proof type is supported — that is the only proof path
/// `eudi-lib-jvm-openid4vci-kt`'s `ProofsSpecification.JwtProofs` (the
/// wallet this issuer serves) ever emits; `di_vp` and `attestation` proof
/// types are intentionally not accepted.
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ProofsRequest {
    pub jwt: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedProof {
    pub holder_jwk: Jwk,
}

/// Verifies a single holder proof-of-possession JWT: JWS signature (against
/// the `jwk` embedded in its header), `typ`, `aud`, and `nonce`/expiry
/// binding to the transaction's `c_nonce`.
pub fn verify_holder_proof(
    jwt_str: &str,
    expected_issuer: &str,
    expected_c_nonce: &str,
    c_nonce_expires_at: i64,
    now_unix: i64,
) -> Result<VerifiedProof, IssuanceError> {
    if now_unix > c_nonce_expires_at {
        return Err(IssuanceError::InvalidProof("c_nonce has expired".into()));
    }

    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidProof(
            "invalid JWS format: expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL
        .decode(parts[0])
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid base64url header: {e}")))?;

    let header = JwsHeader::from_bytes(&header_bytes)
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid proof header: {e}")))?;

    let typ = header
        .token_type()
        .ok_or_else(|| IssuanceError::InvalidProof("missing typ header in proof JWT".into()))?;
    if typ != "openid4vci-proof+jwt" {
        return Err(IssuanceError::InvalidProof(format!(
            "invalid proof typ header: {typ}, expected openid4vci-proof+jwt"
        )));
    }

    let jwk_val = header
        .claim("jwk")
        .ok_or_else(|| IssuanceError::InvalidProof("missing jwk in proof header".into()))?;
    let jwk: Jwk = serde_json::from_value(jwk_val.clone())
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid jwk in proof header: {e}")))?;

    let verifier = ES256.verifier_from_jwk(&jwk).map_err(|e| {
        IssuanceError::InvalidProof(format!("unable to create verifier from jwk: {e}"))
    })?;

    let (payload, _) = josekit::jwt::decode_with_verifier(jwt_str, &verifier).map_err(|e| {
        IssuanceError::InvalidProof(format!("proof JWS signature verification failed: {e}"))
    })?;

    let aud = payload
        .claim("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("missing or non-string aud claim in proof payload".into())
        })?;
    if aud != expected_issuer {
        return Err(IssuanceError::InvalidProof(format!(
            "proof aud mismatch: got {aud}, expected {expected_issuer}"
        )));
    }

    let nonce = payload
        .claim("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("missing or non-string nonce claim in proof payload".into())
        })?;
    if nonce != expected_c_nonce {
        return Err(IssuanceError::InvalidProof(format!(
            "proof nonce mismatch: got {nonce}, expected {expected_c_nonce}"
        )));
    }

    Ok(VerifiedProof { holder_jwk: jwk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwt::{self, JwtPayload};

    fn signed_proof_jwt(aud: &str, nonce: &str) -> String {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public_jwk = keypair.to_jwk_public_key();
        public_jwk.set_algorithm("ES256");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
            .unwrap();

        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!(aud)))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!(nonce)))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    #[test]
    fn verifies_valid_proof_jwt() {
        let jwt_str = signed_proof_jwt("https://issuer.example.com", "nonce-123");

        let res = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(res.holder_jwk.key_type(), "EC");
    }

    #[test]
    fn rejects_mismatched_nonce() {
        let jwt_str = signed_proof_jwt("https://issuer.example.com", "wrong-nonce");

        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
        )
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }
}
```

- [ ] **Step 2: Update the re-export in `crates/foundry-issuer/src/lib.rs:27`**

Replace:
```rust
pub use proof::{verify_holder_proof, ProofObject, VerifiedProof};
```
with:
```rust
pub use proof::{verify_holder_proof, ProofsRequest, VerifiedProof};
```

- [ ] **Step 3: Verify**

Run: `cargo test -p foundry-issuer proof::`
Expected: compiles and both `proof::tests::verifies_valid_proof_jwt` and `proof::tests::rejects_mismatched_nonce` pass. (The crate as a whole will not yet compile — `credential.rs` still refers to the old `ProofObject`/`proof` field. That is expected until Task 2 lands; if you want an isolated green run of just this module, use `cargo check -p foundry-issuer --lib 2>&1 | grep proof.rs` to confirm no errors originate in `proof.rs` itself.)

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-issuer/src/proof.rs crates/foundry-issuer/src/lib.rs
git commit -m "foundry-issuer: verify_holder_proof takes a raw JWT string; add ProofsRequest"
```

---

### Task 2: `foundry-issuer::credential` — plural request/response + per-proof issuance loop

**Files:**
- Modify: `crates/foundry-issuer/src/credential.rs` (struct defs ~lines 1-33, proof extraction ~lines 60-75, credential-building block ~lines 99-198, tests ~lines 202-385)
- Modify: `crates/foundry-issuer/src/lib.rs` (the line changed in Task 1's Step 2, immediately below it)

**Interfaces:**
- Consumes: `foundry-issuer::proof::{verify_holder_proof, ProofsRequest}` (Task 1).
- Produces: `pub struct IssuedCredential { pub credential: String }` and `pub struct CredentialResponse { pub credentials: Vec<IssuedCredential>, pub notification_id: Option<String> }`, both consumed by Task 3 (openapi.rs schema list), Task 5 (foundry-wallet parses the raw JSON shape, no direct type dependency), and Tasks 6-7 (HTTP tests parse the raw JSON shape).

**Behaviors to test:**
- A request with `proofs.jwt` containing exactly one JWT still issues exactly one credential (happy path, matches today's single-proof usage).
- A request with `proofs` absent, or `proofs.jwt` empty, is rejected the same way as before: `IssuanceError::InvalidProof("missing proof in credential request")`.

- [ ] **Step 1: Update the request/response struct definitions**

Replace (originally lines 19-33):
```rust
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CredentialRequest {
    pub credential_configuration_id: Option<String>,
    pub format: Option<String>,
    pub proof: Option<ProofObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialResponse {
    pub credential: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<u64>,
}
```
with:
```rust
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CredentialRequest {
    pub credential_configuration_id: Option<String>,
    pub format: Option<String>,
    pub proofs: Option<ProofsRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IssuedCredential {
    pub credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialResponse {
    pub credentials: Vec<IssuedCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
}
```

Also update the top-of-file import (originally near the other `use crate::...` lines):
```rust
use crate::proof::{verify_holder_proof, ProofObject};
```
to:
```rust
use crate::proof::{verify_holder_proof, ProofsRequest};
```

- [ ] **Step 2: Replace the proof-extraction-and-verification block**

Replace (originally around lines 60-75):
```rust
    let proof = req
        .proof
        .as_ref()
        .ok_or_else(|| IssuanceError::InvalidProof("missing proof in credential request".into()))?;

    let verified_proof = verify_holder_proof(
        proof,
        &config.issuer.credential_issuer,
        c_nonce,
        c_nonce_expires_at,
        now_unix,
    )?;
```
with:
```rust
    let proof_jwts = req
        .proofs
        .as_ref()
        .map(|p| p.jwt.as_slice())
        .filter(|jwts| !jwts.is_empty())
        .ok_or_else(|| IssuanceError::InvalidProof("missing proof in credential request".into()))?;

    let verified_proofs = proof_jwts
        .iter()
        .map(|jwt_str| {
            verify_holder_proof(
                jwt_str,
                &config.issuer.credential_issuer,
                c_nonce,
                c_nonce_expires_at,
                now_unix,
            )
        })
        .collect::<Result<Vec<_>, IssuanceError>>()?;
```

- [ ] **Step 3: Wrap the credential-building block in a per-proof loop**

Replace the existing block that starts at `let holder_jwk_json = ...` and ends at `Ok(CredentialResponse { credential: credential_str, c_nonce: None, c_nonce_expires_in: None })` with:

```rust
    let mut credentials = Vec::with_capacity(verified_proofs.len());
    for verified_proof in &verified_proofs {
        let holder_jwk_json = serde_json::to_value(&verified_proof.holder_jwk)
            .map_err(|e| IssuanceError::Serialization(e.to_string()))?;

        let credential_str = match cred_type.format.as_str() {
            "dc+sd-jwt" => {
                let vct = cred_type
                    .vct
                    .clone()
                    .unwrap_or_else(|| tx.credential_type_id.clone());

                let mut always_disclosed = Map::new();
                let mut selectively_disclosable = Map::new();

                for claim_def in &cred_type.claims {
                    if let Some(top_key) = claim_def.path.first() {
                        if let Some(val) = tx.claims.get(top_key) {
                            if claim_def.selectively_disclosable {
                                selectively_disclosable.insert(top_key.clone(), val.clone());
                            } else {
                                always_disclosed.insert(top_key.clone(), val.clone());
                            }
                        }
                    }
                }

                let (status_list_index, status_list_uri) = if config.issuer.status_list.enabled {
                    (
                        tx.status_list_index,
                        config
                            .issuer
                            .status_list
                            .public_base_url
                            .as_ref()
                            .map(|url| format!("{}/1", url.trim_end_matches('/'))),
                    )
                } else {
                    (None, None)
                };

                let sd_claims = IssuerClaims {
                    iss: config.issuer.credential_issuer.clone(),
                    sub: format!("sub_{}", tx.transaction_id),
                    iat: now_unix,
                    exp: now_unix + 86400 * 365,
                    vct,
                    cnf_jwk: holder_jwk_json,
                    status_list_index,
                    status_list_uri,
                    always_disclosed,
                    selectively_disclosable,
                };

                build_sd_jwt_vc(sd_claims, &signer, x5c.clone()).map_err(|e| {
                    IssuanceError::InvalidRequest(format!("sd-jwt vc build failed: {e}"))
                })?
            }
            "mso_mdoc" => {
                let doc_type = cred_type
                    .vct
                    .clone()
                    .or_else(|| cred_type.doctype.clone())
                    .unwrap_or_else(|| tx.credential_type_id.clone());

                let mut ns_map = BTreeMap::new();
                let mut elem_map = BTreeMap::new();
                for (k, v) in &tx.claims {
                    elem_map.insert(k.clone(), v.clone());
                }
                ns_map.insert(doc_type.clone(), elem_map);

                let mdoc_claims = MdocClaims {
                    doc_type,
                    namespaces: ns_map,
                    device_key_jwk: holder_jwk_json,
                    signed_at: now_unix,
                    valid_until: now_unix + 86400 * 365,
                };

                let cbor_bytes = build_mdoc(mdoc_claims, &signer, x5c.clone()).map_err(|e| {
                    IssuanceError::InvalidRequest(format!("mdoc build failed: {e}"))
                })?;

                B64STD.encode(cbor_bytes)
            }
            other => {
                return Err(IssuanceError::InvalidRequest(format!(
                    "unsupported credential format: {other}"
                )))
            }
        };

        credentials.push(IssuedCredential {
            credential: credential_str,
        });
    }

    tx.state = IssuanceState::Issued;
    save_transaction_with_indices(storage, &tx, 600, now_unix).await?;

    Ok(CredentialResponse {
        credentials,
        notification_id: None,
    })
```

(`x5c` is `Option<Vec<String>>`, which is `Clone` — `x5c.clone()` per iteration is required because `build_sd_jwt_vc`/`build_mdoc` consume it by value and the loop may call one of them more than once.)

- [ ] **Step 4: Update the inline test**

Replace the `generate_proof` helper (originally lines 297-313):
```rust
    fn generate_proof(c_nonce: &str, issuer: &str) -> (ProofObject, EcKeyPair) {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public_jwk = keypair.to_jwk_public_key();
        public_jwk.set_algorithm("ES256");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
            .unwrap();

        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!(issuer)))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!(c_nonce)))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        (
            ProofObject {
                proof_type: "jwt".to_string(),
                jwt: Some(jwt_str),
            },
            keypair,
        )
    }
```
with:
```rust
    fn generate_proof(c_nonce: &str, issuer: &str) -> (String, EcKeyPair) {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public_jwk = keypair.to_jwk_public_key();
        public_jwk.set_algorithm("ES256");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
            .unwrap();

        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!(issuer)))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!(c_nonce)))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        (jwt_str, keypair)
    }
```

Then in `issues_sd_jwt_vc_credential_successfully`, replace:
```rust
        let (proof, _) = generate_proof("cn_nonce_123", "https://issuer.example.com");

        let req = CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proof: Some(proof),
        };

        let res =
            handle_credential_request(&config, &storage, "at_secret_123", &req, 1_700_000_010)
                .await
                .unwrap();

        assert!(!res.credential.is_empty());
```
with:
```rust
        let (proof_jwt, _) = generate_proof("cn_nonce_123", "https://issuer.example.com");

        let req = CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proofs: Some(ProofsRequest {
                jwt: vec![proof_jwt],
            }),
        };

        let res =
            handle_credential_request(&config, &storage, "at_secret_123", &req, 1_700_000_010)
                .await
                .unwrap();

        assert_eq!(res.credentials.len(), 1);
        assert!(!res.credentials[0].credential.is_empty());
```

- [ ] **Step 5: Update the re-export in `crates/foundry-issuer/src/lib.rs`**

Replace:
```rust
pub use credential::{handle_credential_request, CredentialRequest, CredentialResponse};
```
with:
```rust
pub use credential::{
    handle_credential_request, CredentialRequest, CredentialResponse, IssuedCredential,
};
```

- [ ] **Step 6: Verify**

Run: `cargo test -p foundry-issuer`
Expected: PASS — the whole crate now compiles and all inline tests (including `credential::tests::issues_sd_jwt_vc_credential_successfully`) pass.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-issuer/src/credential.rs crates/foundry-issuer/src/lib.rs
git commit -m "foundry-issuer: /credential request/response use plural proofs/credentials"
```

---

### Task 3: `crates/foundry/src/openapi.rs` — swap the wallet-facing schema list

**Files:**
- Modify: `crates/foundry/src/openapi.rs:58-60`

**Interfaces:**
- Consumes: `foundry_issuer::{CredentialRequest, CredentialResponse, IssuedCredential, ProofsRequest}` (Tasks 1-2). This is the change that lets `cargo build -p foundry` compile again — `foundry_issuer::ProofObject` no longer exists after Task 1.
- Produces: nothing new; this is the last change required for the `foundry` binary crate itself (not its tests) to compile.

- [ ] **Step 1: Replace the schema list entries**

Replace (in the `WalletApiDoc`'s `components(schemas(...))` block):
```rust
        foundry_issuer::CredentialRequest,
        foundry_issuer::CredentialResponse,
        foundry_issuer::ProofObject,
```
with:
```rust
        foundry_issuer::CredentialRequest,
        foundry_issuer::CredentialResponse,
        foundry_issuer::IssuedCredential,
        foundry_issuer::ProofsRequest,
```

- [ ] **Step 2: Verify**

Run: `cargo test -p foundry openapi::`
Expected: PASS — `wallet_openapi_spec_generates_valid_json` and `wallet_openapi_spec_includes_authorize_path` both pass, confirming the schema list still produces valid OpenAPI v3 JSON. (`cargo build -p foundry` should also now succeed; `crates/foundry/tests/*` will still fail to compile until Tasks 6-7 land — that is expected.)

- [ ] **Step 3: Commit**

```bash
git add crates/foundry/src/openapi.rs
git commit -m "foundry: register ProofsRequest/IssuedCredential in the wallet OpenAPI schema"
```

---

### Task 4: `foundry-wallet::actions::proof` — emit a raw JWT instead of a proof-type wrapper

**Files:**
- Modify: `crates/foundry-wallet/src/actions/proof.rs` (whole file, ~65 lines)

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub struct HolderProof { pub jwt: String, pub private_key_pem: Vec<u8> }` (was `pub proof_json: serde_json::Value`) — consumed by Task 5.

- [ ] **Step 1: Replace `crates/foundry-wallet/src/actions/proof.rs` in full**

```rust
//! Builds an `openid4vci-proof+jwt` bound to a `c_nonce`/`aud`, generating a
//! fresh holder EC key pair per credential. Construction mirrors the one
//! already proven out against the real server in
//! `crates/foundry/tests/e2e_full_flow.rs::create_proof`.

use crate::error::WalletResult;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};

pub struct HolderProof {
    pub jwt: String,
    pub private_key_pem: Vec<u8>,
}

pub fn build_proof_jwt(c_nonce: &str, aud: &str) -> WalletResult<HolderProof> {
    let keypair = EcKeyPair::generate(EcCurve::P256).map_err(|e| {
        crate::error::WalletError::MalformedOffer(format!("key generation failed: {e}"))
    })?;
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk)?))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(aud)))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256
        .signer_from_jwk(&private_jwk)
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer)
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    Ok(HolderProof {
        jwt: jwt_str,
        private_key_pem: keypair.to_pem_private_key(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine;

    #[test]
    fn builds_a_proof_jwt_bound_to_nonce_and_aud() {
        let proof = build_proof_jwt("nonce-123", "https://issuer.example.com").unwrap();
        let parts: Vec<&str> = proof.jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "must be a compact JWS");

        let header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        assert!(header["jwk"].is_object());

        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["aud"], "https://issuer.example.com");
        assert_eq!(payload["nonce"], "nonce-123");
    }
}
```

- [ ] **Step 2: Verify**

Run: `cargo test -p foundry-wallet proof::`
Expected: PASS. (`foundry-wallet` as a whole will not yet compile — `actions/issuance.rs` still references the removed `proof.proof_json` field. That is expected until Task 5 lands.)

- [ ] **Step 3: Commit**

```bash
git add crates/foundry-wallet/src/actions/proof.rs
git commit -m "foundry-wallet: build_proof_jwt returns a raw JWT string, not a proof-type wrapper"
```

---

### Task 5: `foundry-wallet::actions::issuance` — send `proofs`, parse `credentials`

**Files:**
- Modify: `crates/foundry-wallet/src/actions/issuance.rs:108-127` (approximate original range covering the two spots below)

**Interfaces:**
- Consumes: `HolderProof.jwt: String` (Task 4).
- Produces: nothing new; this is the debug wallet's own `/credential` client, consumed only by whoever runs the `foundry-wallet` CLI.

- [ ] **Step 1: Update the credential request body**

Replace:
```rust
    let cred_url = format!("{}/credential", config.endpoints.wallet_base_url);
    let cred_req = serde_json::json!({
        "credential_configuration_id": credential_configuration_id,
        "format": "dc+sd-jwt",
        "proof": proof.proof_json,
    });
```
with:
```rust
    let cred_url = format!("{}/credential", config.endpoints.wallet_base_url);
    let cred_req = serde_json::json!({
        "credential_configuration_id": credential_configuration_id,
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof.jwt] },
    });
```

- [ ] **Step 2: Update the credential response parsing**

Replace:
```rust
    let cred_json: serde_json::Value = serde_json::from_str(&cred_body)?;
    let compact = cred_json["credential"]
        .as_str()
        .ok_or_else(|| {
            WalletError::MalformedOffer("credential response missing 'credential'".to_string())
        })?
        .to_string();
```
with:
```rust
    let cred_json: serde_json::Value = serde_json::from_str(&cred_body)?;
    let compact = cred_json["credentials"][0]["credential"]
        .as_str()
        .ok_or_else(|| {
            WalletError::MalformedOffer(
                "credential response missing 'credentials[0].credential'".to_string(),
            )
        })?
        .to_string();
```

- [ ] **Step 3: Verify**

Run: `cargo test -p foundry-wallet`
Expected: PASS — the whole `foundry-wallet` crate compiles and its test suite passes (this crate's own tests don't exercise `run_issuance` against a live server; that end-to-end path is covered by Tasks 6-7's HTTP tests and, optionally, a manual run described in Task 8).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-wallet/src/actions/issuance.rs
git commit -m "foundry-wallet: issuance flow sends plural proofs, parses plural credentials"
```

---

### Task 6: `crates/foundry/tests/wallet_issuance.rs` — update the HTTP-level issuance suite

**Files:**
- Modify: `crates/foundry/tests/wallet_issuance.rs` (the `create_proof` helper, plus 6 call sites across 5 test functions, plus the one response assertion)

**Interfaces:**
- Consumes: nothing new — this test drives the real `wallet_router`/`admin_router` over HTTP-shaped `axum::body::Body` requests, so it only needs the wire-format changes (Tasks 1-3), not any Rust-level type import changes.
- Produces: nothing consumed elsewhere; this is the crate's compile-blocking test file (part of `cargo test --workspace`).

**Behaviors to test (all pre-existing, now exercised against the new wire shape):**
- Full pre-authorized_code → token → nonce → credential flow succeeds and returns a non-empty SD-JWT VC compact serialization.
- A proof with mismatched `aud` is rejected with `invalid_proof`.
- A proof with mismatched `nonce` is rejected with `invalid_proof`.
- A proof presented against an expired `c_nonce` is rejected with `invalid_proof`.
- A second `/credential` request against an already-issued transaction is rejected with `invalid_grant`.

- [ ] **Step 1: Replace the `create_proof` helper**

Replace:
```rust
fn create_proof(c_nonce: &str, issuer: &str) -> (serde_json::Value, EcKeyPair) {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(issuer)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    (
        serde_json::json!({
            "proof_type": "jwt",
            "jwt": jwt_str,
        }),
        keypair,
    )
}
```
with:
```rust
fn create_proof(c_nonce: &str, issuer: &str) -> (String, EcKeyPair) {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(issuer)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    (jwt_str, keypair)
}
```

- [ ] **Step 2: Update every call site that builds a `/credential` request body**

The helper's return value changes name at every call site (`proof_json` → the JWT string) and every `cred_req_body` literal changes its `"proof"` key to a `"proofs"` key. Apply this exact substitution at all 6 call sites below (identified by enclosing test function and, where a function has two, by ordinal):

1. `full_issuance_flow_end_to_end`:
   Replace:
   ```rust
    let (proof_json, _keypair) = create_proof(c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proof": proof_json,
    });
   ```
   with:
   ```rust
    let (proof_jwt, _keypair) = create_proof(c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });
   ```

2. `credential_request_with_proof_aud_mismatch_is_rejected`:
   Replace:
   ```rust
    let (proof_json, _keypair) = create_proof(&c_nonce, "https://wrong-issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proof": proof_json,
    });
   ```
   with:
   ```rust
    let (proof_jwt, _keypair) = create_proof(&c_nonce, "https://wrong-issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });
   ```

3. `credential_request_with_proof_nonce_mismatch_is_rejected`:
   Replace:
   ```rust
    let (proof_json, _keypair) = create_proof("not-the-real-nonce", "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proof": proof_json,
    });
   ```
   with:
   ```rust
    let (proof_jwt, _keypair) = create_proof("not-the-real-nonce", "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });
   ```

4. `credential_request_with_expired_c_nonce_is_rejected`:
   Replace:
   ```rust
    let (proof_json, _keypair) = create_proof(&c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proof": proof_json,
    });
   ```
   with:
   ```rust
    let (proof_jwt, _keypair) = create_proof(&c_nonce, "https://issuer.example.com");

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });
   ```

5. `second_credential_request_with_same_access_token_is_rejected` (first request):
   Replace:
   ```rust
    let (proof_json, _keypair) = create_proof(&c_nonce, "https://issuer.example.com");
    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proof": proof_json,
    });
   ```
   with:
   ```rust
    let (proof_jwt, _keypair) = create_proof(&c_nonce, "https://issuer.example.com");
    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });
   ```

6. `second_credential_request_with_same_access_token_is_rejected` (second request):
   Replace:
   ```rust
    let (proof_json_2, _keypair_2) = create_proof(&c_nonce, "https://issuer.example.com");
    let cred_req_body_2 = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proof": proof_json_2,
    });
   ```
   with:
   ```rust
    let (proof_jwt_2, _keypair_2) = create_proof(&c_nonce, "https://issuer.example.com");
    let cred_req_body_2 = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt_2] },
    });
   ```

- [ ] **Step 3: Update the one response assertion that reads the issued credential**

In `full_issuance_flow_end_to_end`, replace:
```rust
    let credential_str = cred_json["credential"].as_str().unwrap();
```
with:
```rust
    let credential_str = cred_json["credentials"][0]["credential"].as_str().unwrap();
```

- [ ] **Step 4: Verify**

Run: `cargo test -p foundry --test wallet_issuance`
Expected: PASS — all tests in this file pass, including `full_issuance_flow_end_to_end`, both proof-mismatch tests, the expired-nonce test, and the replay-rejection test.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry/tests/wallet_issuance.rs
git commit -m "foundry tests: wallet_issuance.rs uses plural proofs/credentials wire shape"
```

---

### Task 7: `crates/foundry/tests/e2e_full_flow.rs` — update the ignored end-to-end suite

**Files:**
- Modify: `crates/foundry/tests/e2e_full_flow.rs` (the `create_proof` helper and its single call site inside `create_offer_and_issue_credential`)

**Interfaces:**
- Consumes: nothing new — same reasoning as Task 6; this is a `reqwest`-based HTTP client test, wire-format only.
- Produces: nothing consumed elsewhere. This file's tests are `#[ignore]`d (per its header doc: "Run with: `cargo test -p foundry --test e2e_full_flow -- --ignored`") and spin up the real `foundry` binary as a subprocess against real sockets, so they are not part of the default `cargo test --workspace` *execution*, but they must still *compile* for that gate to pass.

- [ ] **Step 1: Replace the `create_proof` helper**

Replace:
```rust
fn create_proof(c_nonce: &str, issuer: &str) -> (serde_json::Value, EcKeyPair) {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(issuer)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    (
        serde_json::json!({ "proof_type": "jwt", "jwt": jwt_str }),
        keypair,
    )
}
```
with:
```rust
fn create_proof(c_nonce: &str, issuer: &str) -> (String, EcKeyPair) {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(issuer)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    (jwt_str, keypair)
}
```

- [ ] **Step 2: Update the single call site in `create_offer_and_issue_credential`**

Replace:
```rust
    let (proof_json, holder_keypair) = create_proof(&c_nonce, "https://localhost:8443");
    let cred_res = client
        .post(format!("{wallet_base}/credential"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "credential_configuration_id": "pid",
            "format": "dc+sd-jwt",
            "proof": proof_json,
        }))
        .send()
        .await
        .expect("POST /credential");
    assert_eq!(cred_res.status(), reqwest::StatusCode::OK);
    let cred_json: serde_json::Value = cred_res.json().await.unwrap();
    let compact = cred_json["credential"].as_str().unwrap().to_string();
```
with:
```rust
    let (proof_jwt, holder_keypair) = create_proof(&c_nonce, "https://localhost:8443");
    let cred_res = client
        .post(format!("{wallet_base}/credential"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "credential_configuration_id": "pid",
            "format": "dc+sd-jwt",
            "proofs": { "jwt": [proof_jwt] },
        }))
        .send()
        .await
        .expect("POST /credential");
    assert_eq!(cred_res.status(), reqwest::StatusCode::OK);
    let cred_json: serde_json::Value = cred_res.json().await.unwrap();
    let compact = cred_json["credentials"][0]["credential"]
        .as_str()
        .unwrap()
        .to_string();
```

- [ ] **Step 3: Verify (compile-only — do not run the ignored E2E suite as part of this task)**

Run: `cargo test -p foundry --test e2e_full_flow --no-run`
Expected: compiles cleanly with no errors (the tests themselves stay `#[ignore]`d and are out of scope for this plan's execution — they spin up real subprocesses and sockets).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry/tests/e2e_full_flow.rs
git commit -m "foundry tests: e2e_full_flow.rs uses plural proofs/credentials wire shape"
```

---

### Task 8: Regenerate tracked OpenAPI specs and run the full workspace gate

**Files:**
- Modify: `openapi.json` (rewritten as a byproduct; its content should be unchanged since the admin API surface is untouched by this plan)
- Modify: `openapi-wallet.json` (rewritten — `/credential`'s request/response schemas change: `CredentialRequest.proofs` replaces `.proof`, `CredentialResponse.credentials`/`.notification_id` replace `.credential`/`.c_nonce`/`.c_nonce_expires_in`, `ProofsRequest` replaces `ProofObject`, `IssuedCredential` is added)

**Interfaces:**
- Consumes: everything from Tasks 1-7 (this is the final integration step; both binary crates and all test crates must already compile).
- Produces: the two tracked OpenAPI spec files kept current per root AGENTS.md §6.

- [ ] **Step 1: Regenerate the dev PKI and config, then run the server briefly to regenerate both specs**

Per `crates/foundry/AGENTS.md`'s documented mechanism ("`serve()` overwrites `openapi.json` and `openapi-wallet.json` in the process working directory on every startup... this — not the CLI — is what actually keeps the specs current"), run from the repo root:

```bash
rm -rf /tmp/foundry-openapi-regen && mkdir -p /tmp/foundry-openapi-regen
cargo run -p foundry -- config quickstart --dir /tmp/foundry-openapi-regen --out /tmp/foundry-openapi-regen/foundry.toml
timeout 3 cargo run -p foundry -- serve --config /tmp/foundry-openapi-regen/foundry.toml || true
```

(The `quickstart` subcommand name and its exact flags should be confirmed against `crates/foundry/src/cli.rs`'s `ConfigAction` enum before running — see `crates/foundry/AGENTS.md` for the authoritative CLI surface. The `serve` command binds real sockets and runs until killed; `timeout 3` lets it write both spec files on startup and then exits. Run this from the repository root so the two `openapi*.json` files at the repo root are the ones overwritten.)

- [ ] **Step 2: Confirm the diff is scoped to what this plan changed**

```bash
git diff openapi.json
git diff openapi-wallet.json
```
Expected: `openapi.json` (admin spec) has no schema-shape diff (only possibly non-semantic key-ordering/whitespace if the serializer output changed — verify with `git diff --stat` showing 0 or a trivial diff). `openapi-wallet.json` shows `CredentialRequest`, `CredentialResponse`, `ProofsRequest` (new), and `IssuedCredential` (new) changed/added, and `ProofObject` removed.

- [ ] **Step 3: Full workspace verification gate**

Run, in order, and confirm each is clean before proceeding to the next:
```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
Expected: all three pass with no errors and no warnings.

- [ ] **Step 4: Manual smoke test against the real `eudipal-android` wallet (optional but recommended, given this plan exists because of a real failed run)**

Start the server with the quickstart config from Step 1 (or the project's normal dev config), point the `eudipal-android` app at it, and repeat the issuance flow that originally produced `invalid proof: missing proof in credential request`. Confirm the credential is now issued successfully end-to-end.

- [ ] **Step 5: Commit**

```bash
git add openapi.json openapi-wallet.json
git commit -m "foundry: regenerate OpenAPI specs for plural proofs/credentials"
```

## Progress Log

_(Append one line per completed task: date, task, commit SHA.)_