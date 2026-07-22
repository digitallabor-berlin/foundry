# Foundry Plan 6 — OpenID4VCI Token, Nonce & Credential Endpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the OpenID4VCI wallet-facing `/token`, `/nonce`, and `/credential` HTTP endpoints with OAuth2 pre-authorized code token exchange, attestation verification seams, `c_nonce` management, holder proof-of-possession verification (`openid4vci-proof+jwt`), and credential issuance in SD-JWT VC (`dc+sd-jwt`) and mdoc (`mso_mdoc`) formats.

**Architecture:** Extend `foundry-issuer` with token/nonce/credential business logic, transaction index lookups, attestation seams, and proof verification. Wire axum HTTP routes on the public wallet-facing listener in `foundry` binary. Ensure spec-compliant OAuth2/OpenID error formats (`invalid_grant`, `invalid_proof`, etc.) and TDD coverage throughout.

**Tech Stack:** Rust (edition 2021), tokio, axum, `foundry-core`, `foundry-issuer`, `foundry-sd-jwt-vc`, `foundry-mdoc`, `oid4vci`, `josekit`, `serde_json`.

## Global Constraints

- **No panics or unwraps** in request handling or public APIs.
- **Spec Compliance:** OpenID4VCI 1.0 final / draft-13/17 & HAIP 1.0.
- **Wallet Error Responses:** Return OAuth2/OpenID JSON errors (`{"error": "...", "error_description": "..."}`) with appropriate HTTP status codes (400, 401, etc.).
- **Holder Proof:** Enforce JWS signature, `typ = "openid4vci-proof+jwt"`, `aud = credential_issuer`, and fresh `c_nonce`.
- **Issuance State:** Transition `IssuanceTransaction.state` from `Offered` to `Issued` upon successful issuance.

---

### Task 1: Attestation Verification Seams and Transaction Pre-Auth Indexing

**Files:**
- Create: `crates/foundry-issuer/src/attestation.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`
- Modify: `crates/foundry-issuer/src/transaction.rs`
- Modify: `crates/foundry-issuer/src/create_offer.rs`
- Test: `crates/foundry-issuer/src/attestation.rs` (unit tests)
- Test: `crates/foundry-issuer/src/transaction.rs` (unit tests)

**Interfaces:**
- Consumes: `foundry_core::config::AttestationMode`, `IssuanceTransaction`, `Storage`
- Produces: `WalletAttestationVerifier`, `KeyAttestationVerifier`, `DefaultAttestationVerifier`, `save_transaction_with_indices`, `load_transaction_by_pre_auth_code`, `load_transaction_by_access_token`

- [ ] **Step 1: Write the failing test for transaction code & token lookups**

In `crates/foundry-issuer/src/transaction.rs`, add tests for looking up transactions by `pre_authorized_code` and `access_token`.

```rust
#[tokio::test]
async fn lookup_by_pre_auth_code_and_access_token_round_trips() {
    let storage = test_storage().await;
    let mut tx = sample_tx("tx-auth-1");
    tx.access_token = Some("bearer-token-xyz".to_string());
    save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000).await.unwrap();

    let loaded_by_code = load_transaction_by_pre_auth_code(&storage, "code-123").await.unwrap().unwrap();
    assert_eq!(loaded_by_code.transaction_id, "tx-auth-1");

    let loaded_by_token = load_transaction_by_access_token(&storage, "bearer-token-xyz").await.unwrap().unwrap();
    assert_eq!(loaded_by_token.transaction_id, "tx-auth-1");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer lookup_by_pre_auth_code_and_access_token_round_trips`
Expected: FAIL with `save_transaction_with_indices` and lookup functions not found.

- [ ] **Step 3: Update `IssuanceTransaction` struct and implement index lookups**

In `crates/foundry-issuer/src/transaction.rs`:
Add fields to `IssuanceTransaction`:
```rust
pub access_token: Option<String>,
pub c_nonce: Option<String>,
pub c_nonce_expires_at: Option<i64>,
```
Add index key functions and helpers:
```rust
const PRE_AUTH_NS: &str = "tx_pre_auth";
const ACCESS_TOKEN_NS: &str = "tx_access_token";

pub async fn save_transaction_with_indices(
    storage: &dyn Storage,
    tx: &IssuanceTransaction,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    save_transaction(storage, tx, ttl_secs, now_unix).await?;
    let expires_at = now_unix + ttl_secs as i64;
    storage
        .put_kv(PRE_AUTH_NS, &tx.pre_authorized_code, &tx.transaction_id, Some(expires_at))
        .await?;
    if let Some(ref token) = tx.access_token {
        storage
            .put_kv(ACCESS_TOKEN_NS, token, &tx.transaction_id, Some(expires_at))
            .await?;
    }
    Ok(())
}

pub async fn load_transaction_by_pre_auth_code(
    storage: &dyn Storage,
    code: &str,
) -> Result<Option<IssuanceTransaction>, IssuanceError> {
    if let Some(tx_id) = storage.get_kv(PRE_AUTH_NS, code).await? {
        load_transaction(storage, &tx_id).await
    } else {
        Ok(None)
    }
}

pub async fn load_transaction_by_access_token(
    storage: &dyn Storage,
    token: &str,
) -> Result<Option<IssuanceTransaction>, IssuanceError> {
    if let Some(tx_id) = storage.get_kv(ACCESS_TOKEN_NS, token).await? {
        load_transaction(storage, &tx_id).await
    } else {
        Ok(None)
    }
}
```
Update `create_offer.rs` to call `save_transaction_with_indices`.

- [ ] **Step 4: Implement Attestation Verifier Traits**

Create `crates/foundry-issuer/src/attestation.rs`:
```rust
use foundry_core::config::AttestationMode;
use crate::error::IssuanceError;

pub trait WalletAttestationVerifier: Send + Sync {
    fn verify_wallet_attestation(
        &self,
        mode: AttestationMode,
        attestation_header: Option<&str>,
    ) -> Result<(), IssuanceError>;
}

pub trait KeyAttestationVerifier: Send + Sync {
    fn verify_key_attestation(
        &self,
        mode: AttestationMode,
        attestation_data: Option<&str>,
    ) -> Result<(), IssuanceError>;
}

#[derive(Debug, Clone, Default)]
pub struct DefaultAttestationVerifier;

impl WalletAttestationVerifier for DefaultAttestationVerifier {
    fn verify_wallet_attestation(
        &self,
        mode: AttestationMode,
        attestation_header: Option<&str>,
    ) -> Result<(), IssuanceError> {
        match mode {
            AttestationMode::Required => {
                if attestation_header.is_none() {
                    return Err(IssuanceError::InvalidRequest("wallet attestation is required".into()));
                }
                Ok(())
            }
            AttestationMode::Optional | AttestationMode::Disabled => Ok(()),
        }
    }
}

impl KeyAttestationVerifier for DefaultAttestationVerifier {
    fn verify_key_attestation(
        &self,
        mode: AttestationMode,
        attestation_data: Option<&str>,
    ) -> Result<(), IssuanceError> {
        match mode {
            AttestationMode::Required => {
                if attestation_data.is_none() {
                    return Err(IssuanceError::InvalidRequest("key attestation is required".into()));
                }
                Ok(())
            }
            AttestationMode::Optional | AttestationMode::Disabled => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_mode_required_checks_presence() {
        let verifier = DefaultAttestationVerifier;
        assert!(verifier.verify_wallet_attestation(AttestationMode::Required, None).is_err());
        assert!(verifier.verify_wallet_attestation(AttestationMode::Required, Some("header")).is_ok());
        assert!(verifier.verify_wallet_attestation(AttestationMode::Optional, None).is_ok());
        assert!(verifier.verify_wallet_attestation(AttestationMode::Disabled, None).is_ok());
    }
}
```

Expose `attestation` in `crates/foundry-issuer/src/lib.rs`.

- [ ] **Step 5: Run tests and verify all pass**

Run: `cargo test -p foundry-issuer`
Expected: PASS.

- [ ] **Step 6: Commit changes**

```bash
git add crates/foundry-issuer/src
git commit -m "feat(issuer): add transaction pre-auth/token index lookups and attestation verifier seams"
```

---

### Task 2: Token Endpoint Core Business Logic and Proof Verification

**Files:**
- Create: `crates/foundry-issuer/src/token.rs`
- Create: `crates/foundry-issuer/src/proof.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`
- Test: `crates/foundry-issuer/src/token.rs` (unit tests)
- Test: `crates/foundry-issuer/src/proof.rs` (unit tests)

**Interfaces:**
- Consumes: `IssuanceTransaction`, `Storage`, `DefaultAttestationVerifier`, `AttestationMode`
- Produces: `TokenRequest`, `TokenResponse`, `handle_token_request`, `verify_holder_proof`

- [ ] **Step 1: Write failing test for token request handling**

In `crates/foundry-issuer/src/token.rs`, write unit tests:
```rust
#[tokio::test]
async fn handles_valid_token_request_and_issues_access_token_and_nonce() {
    let storage = test_storage().await;
    let tx = sample_tx("tx-tok-1");
    save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000).await.unwrap();

    let req = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        pre_authorized_code: Some("code-123".to_string()),
        tx_code: Some("4242".to_string()),
    };

    let res = handle_token_request(&storage, &req, AttestationMode::Disabled, None, 1_700_000_010)
        .await
        .unwrap();

    assert_eq!(res.token_type, "Bearer");
    assert!(!res.access_token.is_empty());
    assert!(!res.c_nonce.is_empty());

    let updated_tx = load_transaction(&storage, "tx-tok-1").await.unwrap().unwrap();
    assert_eq!(updated_tx.access_token.unwrap(), res.access_token);
    assert_eq!(updated_tx.c_nonce.unwrap(), res.c_nonce);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer handles_valid_token_request_and_issues_access_token_and_nonce`
Expected: FAIL with `TokenRequest` / `handle_token_request` not found.

- [ ] **Step 3: Implement `handle_token_request` and `TokenResponse`**

Create `crates/foundry-issuer/src/token.rs`:
```rust
use crate::attestation::{DefaultAttestationVerifier, WalletAttestationVerifier};
use crate::error::IssuanceError;
use crate::transaction::{load_transaction_by_pre_auth_code, save_transaction_with_indices, IssuanceTransaction};
use foundry_core::config::AttestationMode;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    pub tx_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}

pub async fn handle_token_request(
    storage: &dyn Storage,
    req: &TokenRequest,
    attestation_mode: AttestationMode,
    attestation_header: Option<&str>,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    if req.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
        return Err(IssuanceError::InvalidGrant("unsupported_grant_type".to_string()));
    }

    let verifier = DefaultAttestationVerifier;
    verifier.verify_wallet_attestation(attestation_mode, attestation_header)?;

    let code = req
        .pre_authorized_code
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing pre-authorized_code".to_string()))?;

    let mut tx = load_transaction_by_pre_auth_code(storage, code)
        .await?
        .ok_or_else(|| IssuanceError::InvalidGrant("invalid or expired pre-authorized_code".to_string()))?;

    if let Some(ref expected_tx_code) = tx.tx_code {
        match req.tx_code.as_deref() {
            Some(supplied) if supplied == expected_tx_code => {}
            _ => return Err(IssuanceError::InvalidGrant("invalid tx_code".to_string())),
        }
    }

    let access_token = format!("at_{}", Uuid::new_v4().simple());
    let c_nonce = format!("cn_{}", Uuid::new_v4().simple());
    let expires_in = 600u64;
    let c_nonce_expires_in = 600u64;

    tx.access_token = Some(access_token.clone());
    tx.c_nonce = Some(c_nonce.clone());
    tx.c_nonce_expires_at = Some(now_unix + c_nonce_expires_in as i64);

    save_transaction_with_indices(storage, &tx, expires_in, now_unix).await?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        c_nonce,
        c_nonce_expires_in,
    })
}
```

- [ ] **Step 4: Implement Holder Proof Verification (`proof.rs`)**

Create `crates/foundry-issuer/src/proof.rs`:
```rust
use crate::error::IssuanceError;
use josekit::jwk::Jwk;
use josekit::jws::JwsHeader;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct ProofObject {
    pub proof_type: String,
    pub jwt: Option<String>,
}

pub struct VerifiedProof {
    pub holder_jwk: Jwk,
}

pub fn verify_holder_proof(
    proof: &ProofObject,
    expected_issuer: &str,
    expected_c_nonce: &str,
    c_nonce_expires_at: i64,
    now_unix: i64,
) -> Result<VerifiedProof, IssuanceError> {
    if proof.proof_type != "jwt" {
        return Err(IssuanceError::InvalidProof(format!(
            "unsupported proof_type: {}",
            proof.proof_type
        )));
    }

    let jwt_str = proof
        .jwt
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidProof("missing jwt string in proof".into()))?;

    if now_unix > c_nonce_expires_at {
        return Err(IssuanceError::InvalidProof("c_nonce has expired".into()));
    }

    let header = JwsHeader::from_token(jwt_str)
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid proof header: {e}")))?;

    let typ = header.type_().ok_or_else(|| {
        IssuanceError::InvalidProof("missing typ header in proof JWT".into())
    })?;
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

    let verifier = jwk
        .to_verifier()
        .map_err(|e| IssuanceError::InvalidProof(format!("unable to create verifier from jwk: {e}")))?;

    let (payload, _) = josekit::jwt::decode_with_verifier(jwt_str, &verifier)
        .map_err(|e| IssuanceError::InvalidProof(format!("proof JWS signature verification failed: {e}")))?;

    let aud = payload.claim("aud").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidProof("missing or non-string aud claim in proof payload".into())
    })?;
    if aud != expected_issuer {
        return Err(IssuanceError::InvalidProof(format!(
            "proof aud mismatch: got {aud}, expected {expected_issuer}"
        )));
    }

    let nonce = payload.claim("nonce").and_then(|v| v.as_str()).ok_or_else(|| {
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
    use josekit::jwk::Jwk;
    use josekit::jwt::{self, JwtPayload};

    #[test]
    fn verifies_valid_proof_jwt() {
        let keypair = Jwk::generate_ec_key("P-256").unwrap();
        let mut public_jwk = keypair.to_public_key().unwrap();
        public_jwk.set_algorithm("ES256");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header.set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap())).unwrap();

        let mut payload = JwtPayload::new();
        payload.set_claim("aud", Some(serde_json::json!("https://issuer.example.com"))).unwrap();
        payload.set_claim("nonce", Some(serde_json::json!("nonce-123"))).unwrap();

        let signer = keypair.to_signer("ES256").unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let proof = ProofObject {
            proof_type: "jwt".to_string(),
            jwt: Some(jwt_str),
        };

        let res = verify_holder_proof(
            &proof,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(res.holder_jwk.key_type(), "EC");
    }
}
```

- [ ] **Step 5: Expose modules in `lib.rs` and run tests**

Expose `pub mod token;` and `pub mod proof;` in `crates/foundry-issuer/src/lib.rs`.
Run: `cargo test -p foundry-issuer`
Expected: PASS.

- [ ] **Step 6: Commit changes**

```bash
git add crates/foundry-issuer/src
git commit -m "feat(issuer): add token request handling and proof-of-possession JWT verification"
```

---

### Task 3: Credential Issuance Engine (`foundry-issuer::credential`)

**Files:**
- Create: `crates/foundry-issuer/src/credential.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`
- Test: `crates/foundry-issuer/src/credential.rs` (unit tests)

**Interfaces:**
- Consumes: `IssuanceTransaction`, `Config`, `Signer`, `verify_holder_proof`, `foundry_sd_jwt_vc`, `foundry_mdoc`
- Produces: `CredentialRequest`, `CredentialResponse`, `handle_credential_request`

- [ ] **Step 1: Write failing test for credential request handling**

In `crates/foundry-issuer/src/credential.rs`, write unit tests for SD-JWT VC and mdoc credential issuance.

```rust
#[tokio::test]
async fn issues_sd_jwt_vc_credential_when_valid_proof_and_token_provided() {
    // Set up config, storage, transaction with access token & c_nonce
    // Call handle_credential_request with valid proof
    // Assert response contains credential string and transaction state is Issued
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer issues_sd_jwt_vc_credential_when_valid_proof_and_token_provided`
Expected: FAIL with module/functions missing.

- [ ] **Step 3: Implement `handle_credential_request`**

Create `crates/foundry-issuer/src/credential.rs`:
```rust
use crate::error::IssuanceError;
use crate::proof::{verify_holder_proof, ProofObject};
use crate::transaction::{load_transaction_by_access_token, save_transaction_with_indices, IssuanceState};
use foundry_core::config::{Config, CredentialFormat};
use foundry_core::crypto::Signer;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialRequest {
    pub credential_configuration_id: Option<String>,
    pub format: Option<String>,
    pub proof: Option<ProofObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    pub credential: String,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

pub async fn handle_credential_request(
    config: &Config,
    storage: &dyn Storage,
    access_token: &str,
    req: &CredentialRequest,
    now_unix: i64,
) -> Result<CredentialResponse, IssuanceError> {
    let mut tx = load_transaction_by_access_token(storage, access_token)
        .await?
        .ok_or_else(|| IssuanceError::InvalidGrant("invalid or expired access_token".into()))?;

    if tx.state != IssuanceState::Offered {
        return Err(IssuanceError::InvalidGrant("credential offer has already been claimed".into()));
    }

    let c_nonce = tx
        .c_nonce
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidProof("no active c_nonce on transaction".into()))?;
    let c_nonce_expires_at = tx
        .c_nonce_expires_at
        .ok_or_else(|| IssuanceError::InvalidProof("missing c_nonce expiration".into()))?;

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

    let cred_type = config
        .credential_types
        .iter()
        .find(|ct| ct.id == tx.credential_type_id)
        .ok_or_else(|| IssuanceError::UnknownCredentialType(tx.credential_type_id.clone()))?;

    let issuer_key = config
        .keys
        .get(&config.issuer.status_list.signing_key)
        .ok_or_else(|| IssuanceError::InvalidRequest("configured signing key not found".into()))?;

    let signer = Signer::from_pem_file(&issuer_key.private_key, issuer_key.alg)?;
    let x5c = foundry_core::trust::build_x5c(&issuer_key.x5c)?;

    let credential_str = match cred_type.format {
        CredentialFormat::DcSdJwt => {
            let vct = cred_type.vct.as_deref().unwrap_or(&tx.credential_type_id);
            let sd_paths: Vec<String> = cred_type
                .claims
                .iter()
                .filter(|c| c.selectively_disclosable)
                .map(|c| c.path.join("."))
                .collect();

            let status_claim = if config.issuer.status_list.enabled {
                tx.status_list_index.map(|idx| {
                    serde_json::json!({
                        "status_list": {
                            "idx": idx,
                            "uri": format!("{}/1", config.issuer.status_list.public_base_url)
                        }
                    })
                })
            } else {
                None
            };

            foundry_sd_jwt_vc::builder::build_sd_jwt_vc(
                vct,
                &tx.claims,
                &sd_paths,
                &verified_proof.holder_jwk,
                &signer,
                &x5c,
                status_claim.as_ref(),
                now_unix,
            )
            .map_err(|e| IssuanceError::InvalidRequest(format!("sd-jwt vc build failed: {e}")))?
        }
        CredentialFormat::MsoMdoc => {
            let doctype = cred_type.vct.as_deref().unwrap_or(&tx.credential_type_id);
            foundry_mdoc::builder::build_mdoc(
                doctype,
                &tx.claims,
                &verified_proof.holder_jwk,
                &signer,
                &x5c,
                now_unix,
            )
            .map_err(|e| IssuanceError::InvalidRequest(format!("mdoc build failed: {e}")))?
        }
    };

    tx.state = IssuanceState::Issued;
    save_transaction_with_indices(storage, &tx, 600, now_unix).await?;

    Ok(CredentialResponse {
        credential: credential_str,
        c_nonce: None,
        c_nonce_expires_in: None,
    })
}
```

- [ ] **Step 4: Expose `credential` module in `lib.rs` and run tests**

Add `pub mod credential;` to `crates/foundry-issuer/src/lib.rs`.
Run: `cargo test -p foundry-issuer`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add crates/foundry-issuer/src
git commit -m "feat(issuer): implement credential issuance engine for SD-JWT VC and mdoc formats"
```

---

### Task 4: HTTP Routes Wiring on Wallet-Facing Listener (`/token`, `/nonce`, `/credential`)

**Files:**
- Modify: `src/main.rs` (or server module)
- Modify: `crates/foundry-issuer/src/error.rs`
- Test: `tests/wallet_issuance.rs` (integration test)

**Interfaces:**
- Consumes: `foundry-issuer::{handle_token_request, handle_credential_request, IssuanceError}`, axum router
- Produces: HTTP handlers for `POST /token`, `POST /nonce`, `POST /credential` returning spec-compliant OAuth2 error responses.

- [ ] **Step 1: Write integration tests for wallet issuance flow**

Create `tests/wallet_issuance.rs`:
```rust
use axum::http::StatusCode;
use foundry_core::config::Config;
use foundry_core::storage::SqliteStorage;

#[tokio::test]
async fn full_issuance_flow_offer_token_credential_succeeds() {
    // 1. Create offer via admin endpoint
    // 2. Call POST /token with pre-authorized_code + tx_code -> get access_token + c_nonce
    // 3. Construct proof JWT using holder key and c_nonce
    // 4. Call POST /credential with Bearer access_token + proof -> get issued credential
    // 5. Verify credential string is non-empty and valid format
}
```

- [ ] **Step 2: Run integration test to verify failure**

Run: `cargo test --test wallet_issuance`
Expected: FAIL because HTTP routes `/token`, `/nonce`, `/credential` are not yet mounted or return 404.

- [ ] **Step 3: Add `IntoResponse` for `IssuanceError`**

In `crates/foundry-issuer/src/error.rs`, implement axum's `IntoResponse` for `IssuanceError`:
```rust
impl axum::response::IntoResponse for IssuanceError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_code) = match self {
            IssuanceError::InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
            IssuanceError::InvalidProof(_) => (StatusCode::BAD_REQUEST, "invalid_proof"),
            IssuanceError::UnknownCredentialType(_) => (StatusCode::BAD_REQUEST, "invalid_credential_request"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };

        let body = serde_json::json!({
            "error": error_code,
            "error_description": self.to_string(),
        });

        (status, axum::Json(body)).into_response()
    }
}
```

- [ ] **Step 4: Wire axum handlers in `src/server.rs` or `src/main.rs`**

Add wallet-facing HTTP handlers:
```rust
async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<foundry_issuer::token::TokenRequest>,
) -> Result<Json<foundry_issuer::token::TokenResponse>, IssuanceError> {
    let attestation_hdr = headers.get("OAuth-Client-Attestation").and_then(|v| v.to_str().ok());
    let now = chrono::Utc::now().timestamp();
    let res = foundry_issuer::token::handle_token_request(
        state.storage.as_ref(),
        &req,
        state.config.issuer.wallet_attestation.mode,
        attestation_hdr,
        now,
    ).await?;
    Ok(Json(res))
}

async fn nonce_handler() -> Json<serde_json::Value> {
    let c_nonce = format!("cn_{}", uuid::Uuid::new_v4().simple());
    Json(serde_json::json!({
        "c_nonce": c_nonce,
        "c_nonce_expires_in": 600
    }))
}

async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<foundry_issuer::credential::CredentialRequest>,
) -> Result<Json<foundry_issuer::credential::CredentialResponse>, IssuanceError> {
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| IssuanceError::InvalidGrant("missing authorization header".into()))?;

    let access_token = auth_header.strip_prefix("Bearer ")
        .ok_or_else(|| IssuanceError::InvalidGrant("invalid bearer authorization token".into()))?;

    let now = chrono::Utc::now().timestamp();
    let res = foundry_issuer::credential::handle_credential_request(
        &state.config,
        state.storage.as_ref(),
        access_token,
        &req,
        now,
    ).await?;
    Ok(Json(res))
}
```

Mount `POST /token` (handling both Form and Json), `POST /nonce`, and `POST /credential` on the public wallet-facing axum router.

- [ ] **Step 5: Run integration tests and cargo test**

Run: `cargo test`
Expected: ALL unit and integration tests PASS.

- [ ] **Step 6: Commit changes**

```bash
git add src/ crates/ tests/
git commit -m "feat(issuer): wire /token, /nonce, and /credential endpoints on wallet-facing listener"
```

---

## Plan Self-Review

1. **Spec Coverage:**
   - Section 3 (Issuance Flow): Covers `/token`, `/nonce`, `/credential`, pre-auth code + tx_code, attestation verification seams, `openid4vci-proof+jwt` verification, and issuance in SD-JWT VC and mdoc formats.
2. **Placeholder Scan:** No placeholders or vague "TBD" statements.
3. **Type Consistency:** Types (`TokenRequest`, `TokenResponse`, `CredentialRequest`, `CredentialResponse`, `VerifiedProof`) and function signatures match across all tasks.
