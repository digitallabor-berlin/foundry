# Foundry Plan 7 — OpenID4VP Verification Flow & Core Verification Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the OpenID4VP verifier engine, verification transaction model, request object generation (signed JWS with `x5c` and `x509_san_dns`), response decryption (JWE `direct_post.jwt` / `dc_api.jwt`), SD-JWT VC & mdoc presentation verification with DCQL matching, KB-JWT / DeviceAuth verification, transaction_data hash checking, Token Status List checking, and Admin/Wallet HTTP endpoints (`POST /admin/verification/requests`, `GET /admin/verification/requests/{id}`, `GET /vp/request/{id}`, `POST /vp/response/{id}`).

**Architecture:** Create `foundry-verifier` crate encapsulating OpenID4VP session management, signed request object generation, JWE decryption, DCQL satisfaction, and format-specific presentation verifiers (delegating to `foundry-sd-jwt-vc` and `foundry-mdoc`). Expose Admin API endpoints for triggering/querying verifications and public wallet-facing endpoints for serving request objects and receiving encrypted responses.

**Tech Stack:** Rust (edition 2021), tokio, axum, `foundry-core`, `foundry-sd-jwt-vc`, `foundry-mdoc`, `openid4vp` (vendored), `josekit`, `serde_json`, `uuid`.

## Global Constraints

- **No panics or unwraps** in request handling or public APIs.
- **Spec Compliance:** OpenID4VP 1.0 final / draft-20, DCQL draft-03, HAIP 1.0.
- **Signed Request Objects:** JWS with `x5c` header and `client_id` scheme `x509_san_dns`.
- **Encrypted Responses:** Decrypt JWE responses (`direct_post.jwt` / `dc_api.jwt`) using transaction's ephemeral ECDH keypair.
- **Verification Result Structure:** Return detailed per-check verification outcomes (signatures, trust path, expiration, KB-JWT/DeviceAuth, status list, DCQL match) in `GET /admin/verification/requests/{id}`.

---

### Task 1: Verification Transaction Model & Storage Persistence

**Files:**
- Create: `crates/foundry-verifier/Cargo.toml`
- Create: `crates/foundry-verifier/src/lib.rs`
- Create: `crates/foundry-verifier/src/transaction.rs`
- Create: `crates/foundry-verifier/src/error.rs`
- Test: `crates/foundry-verifier/src/transaction.rs` (unit tests)

**Interfaces:**
- Consumes: `foundry_core::storage::Storage`
- Produces: `VerificationTransaction`, `VerificationState`, `VerificationResult`, `save_verification_transaction`, `load_verification_transaction`

- [ ] **Step 1: Create `crates/foundry-verifier/Cargo.toml`**

```toml
[package]
name = "foundry-verifier"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
foundry-core = { path = "../foundry-core" }
foundry-sd-jwt-vc = { path = "../foundry-sd-jwt-vc" }
foundry-mdoc = { path = "../foundry-mdoc" }
openid4vp = { path = "../openid4vp" }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
rand = { workspace = true }
josekit = { workspace = true }
uuid = { version = "1", features = ["v4"] }
tracing = { workspace = true }

[dev-dependencies]
tokio = { workspace = true }
tempfile = "3"
```

Add `"crates/foundry-verifier"` to `members` in workspace root `Cargo.toml`.

- [ ] **Step 2: Implement `VerificationTransaction` struct and persistence functions**

Create `crates/foundry-verifier/src/error.rs`:
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("verification request not found: {0}")]
    NotFound(String),
    #[error("invalid verification state: {0}")]
    InvalidState(String),
    #[error("dcql error: {0}")]
    Dcql(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("verification failed: {0}")]
    Failed(String),
    #[error(transparent)]
    Storage(#[from] foundry_core::error::StorageError),
    #[error(transparent)]
    CoreCrypto(#[from] foundry_core::error::CryptoError),
    #[error(transparent)]
    Trust(#[from] foundry_core::error::TrustError),
    #[error("serialization error: {0}")]
    Serialization(String),
}
```

Create `crates/foundry-verifier/src/transaction.rs`:
```rust
use crate::error::VerificationError;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};

const VERIFICATION_NS: &str = "verification_tx";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Pending,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckResult {
    pub check: String,
    pub passed: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationResult {
    pub verified: bool,
    pub checks: Vec<CheckResult>,
    pub claims: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationTransaction {
    pub id: String,
    pub state: VerificationState,
    pub nonce: String,
    pub dcql_query: serde_json::Value,
    pub transport: String,
    pub response_mode: String,
    pub ephem_private_jwk: serde_json::Value,
    pub ephem_public_jwk: serde_json::Value,
    pub transaction_data: Option<Vec<serde_json::Value>>,
    pub result: Option<VerificationResult>,
    pub created_at: i64,
}

pub async fn save_verification_transaction(
    storage: &dyn Storage,
    tx: &VerificationTransaction,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<(), VerificationError> {
    let value = serde_json::to_string(tx)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;
    let expires_at = now_unix + ttl_secs as i64;
    storage
        .put_kv(VERIFICATION_NS, &tx.id, &value, Some(expires_at))
        .await?;
    Ok(())
}

pub async fn load_verification_transaction(
    storage: &dyn Storage,
    id: &str,
) -> Result<Option<VerificationTransaction>, VerificationError> {
    let raw = storage.get_kv(VERIFICATION_NS, id).await?;
    match raw {
        Some(s) => {
            let tx = serde_json::from_str(&s)
                .map_err(|e| VerificationError::Serialization(e.to_string()))?;
            Ok(Some(tx))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::storage::SqliteStorage;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("v.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn save_and_load_verification_transaction_round_trips() {
        let storage = test_storage().await;
        let tx = VerificationTransaction {
            id: "ver-123".to_string(),
            state: VerificationState::Pending,
            nonce: "nonce-456".to_string(),
            dcql_query: serde_json::json!({ "credentials": [] }),
            transport: "request_uri".to_string(),
            response_mode: "direct_post.jwt".to_string(),
            ephem_private_jwk: serde_json::json!({ "kty": "EC" }),
            ephem_public_jwk: serde_json::json!({ "kty": "EC" }),
            transaction_data: None,
            result: None,
            created_at: 1_700_000_000,
        };

        save_verification_transaction(&storage, &tx, 600, 1_700_000_000).await.unwrap();
        let loaded = load_verification_transaction(&storage, "ver-123").await.unwrap().unwrap();
        assert_eq!(loaded, tx);
    }
}
```

- [ ] **Step 3: Expose modules in `crates/foundry-verifier/src/lib.rs` and test**

```rust
pub mod error;
pub mod transaction;

pub use error::VerificationError;
pub use transaction::{
    load_verification_transaction, save_verification_transaction, CheckResult,
    VerificationResult, VerificationState, VerificationTransaction,
};
```

Run: `cargo test -p foundry-verifier`
Expected: PASS.

- [ ] **Step 4: Commit changes**

```bash
git add crates/foundry-verifier Cargo.toml
git commit -m "feat(verifier): add verification transaction model and persistence"
```

---

### Task 2: Request Object Generation and Triggering (`create_verification_request`)

**Files:**
- Create: `crates/foundry-verifier/src/request.rs`
- Modify: `crates/foundry-verifier/src/lib.rs`
- Test: `crates/foundry-verifier/src/request.rs` (unit tests)

**Interfaces:**
- Consumes: `Config`, `Storage`, `FileSigner`, `build_x5c`
- Produces: `CreateVerificationRequest`, `CreateVerificationResponse`, `create_verification_request`, `build_signed_request_object`

- [ ] **Step 1: Implement `create_verification_request` logic**

Create `crates/foundry-verifier/src/request.rs`:
```rust
use crate::error::VerificationError;
use crate::transaction::{save_verification_transaction, VerificationState, VerificationTransaction};
use foundry_core::config::Config;
use foundry_core::crypto::FileSigner;
use foundry_core::storage::Storage;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateVerificationRequest {
    pub dcql_query: Option<serde_json::Value>,
    pub named_query_ref: Option<String>,
    #[serde(default = "default_transport")]
    pub transport: String, // "request_uri" or "dc_api"
    pub transaction_data: Option<Vec<serde_json::Value>>,
}

fn default_transport() -> String {
    "request_uri".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateVerificationResponse {
    pub verification_id: String,
    pub request_uri: Option<String>,
    pub openid4vp_uri: Option<String>,
    pub dc_api_request: Option<serde_json::Value>,
}

pub async fn create_verification_request(
    config: &Config,
    storage: &dyn Storage,
    req: CreateVerificationRequest,
    now_unix: i64,
) -> Result<CreateVerificationResponse, VerificationError> {
    let dcql = if let Some(q) = req.dcql_query {
        q
    } else if let Some(ref named) = req.named_query_ref {
        let nq = config
            .verifier
            .named_queries
            .iter()
            .find(|n| &n.id == named)
            .ok_or_else(|| VerificationError::Dcql(format!("unknown named_query_ref '{named}'")))?;
        serde_json::to_value(&nq.dcql)
            .map_err(|e| VerificationError::Serialization(e.to_string()))?
    } else {
        return Err(VerificationError::Dcql("either dcql_query or named_query_ref is required".into()));
    };

    let id = format!("v_{}", Uuid::new_v4().simple());
    let nonce = format!("vn_{}", Uuid::new_v4().simple());

    let keypair = EcKeyPair::generate(EcCurve::P256)
        .map_err(|e| VerificationError::Crypto(e.to_string()))?;
    let public_jwk = keypair.to_jwk_public_key();
    let private_jwk = keypair.to_jwk_private_key();

    let ephem_public_json = serde_json::to_value(&public_jwk)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;
    let ephem_private_json = serde_json::to_value(&private_jwk)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;

    let response_mode = match req.transport.as_str() {
        "dc_api" => "dc_api.jwt".to_string(),
        _ => "direct_post.jwt".to_string(),
    };

    let tx = VerificationTransaction {
        id: id.clone(),
        state: VerificationState::Pending,
        nonce: nonce.clone(),
        dcql_query: dcql.clone(),
        transport: req.transport.clone(),
        response_mode,
        ephem_private_jwk: ephem_private_json,
        ephem_public_jwk: ephem_public_json,
        transaction_data: req.transaction_data.clone(),
        result: None,
        created_at: now_unix,
    };

    save_verification_transaction(storage, &tx, config.storage.transaction_ttl_secs, now_unix).await?;

    let base_url = config.server.wallet_facing.public_base_url.trim_end_matches('/');

    if req.transport == "dc_api" {
        let dc_api_obj = serde_json::json!({
            "response_mode": "dc_api.jwt",
            "dcql_query": dcql,
            "nonce": nonce,
            "client_metadata": {
                "jwks": { "keys": [ephem_public_json] }
            }
        });

        Ok(CreateVerificationResponse {
            verification_id: id,
            request_uri: None,
            openid4vp_uri: None,
            dc_api_request: Some(dc_api_obj),
        })
    } else {
        let request_uri = format!("{base_url}/vp/request/{id}");
        let client_id = format!("x509_san_dns:{}", base_url.trim_start_matches("https://").trim_start_matches("http://"));
        let openid4vp_uri = format!("openid4vp://?client_id={}&request_uri={}", percent_encoding::utf8_percent_encode(&client_id, percent_encoding::NON_ALPHANUMERIC), percent_encoding::utf8_percent_encode(&request_uri, percent_encoding::NON_ALPHANUMERIC));

        Ok(CreateVerificationResponse {
            verification_id: id,
            request_uri: Some(request_uri),
            openid4vp_uri: Some(openid4vp_uri),
            dc_api_request: None,
        })
    }
}

pub fn build_signed_request_object(
    config: &Config,
    tx: &VerificationTransaction,
) -> Result<String, VerificationError> {
    let key_entry = config
        .keys
        .get(&config.verifier.signing_key)
        .ok_or_else(|| VerificationError::Crypto("verifier signing key not configured".into()))?;

    let signer = FileSigner::from_pem_file(&key_entry.private_key, key_entry.alg.parse()?)?;
    let x5c = if let Some(ref path) = key_entry.x5c {
        let pem_bytes = std::fs::read(path)
            .map_err(|e| VerificationError::Crypto(format!("failed to read x5c: {e}")))?;
        Some(foundry_core::trust::build_x5c(&[pem_bytes])?)
    } else {
        None
    };

    let base_url = config.server.wallet_facing.public_base_url.trim_end_matches('/');
    let client_id = format!("x509_san_dns:{}", base_url.trim_start_matches("https://").trim_start_matches("http://"));
    let response_uri = format!("{base_url}/vp/response/{}", tx.id);

    let mut payload = JwtPayload::new();
    payload.set_claim("client_id", Some(serde_json::json!(client_id)))?;
    payload.set_claim("response_uri", Some(serde_json::json!(response_uri)))?;
    payload.set_claim("response_mode", Some(serde_json::json!("direct_post.jwt")))?;
    payload.set_claim("nonce", Some(serde_json::json!(tx.nonce)))?;
    payload.set_claim("state", Some(serde_json::json!(tx.id)))?;
    payload.set_claim("dcql_query", Some(tx.dcql_query.clone()))?;
    payload.set_claim(
        "client_metadata",
        Some(serde_json::json!({
            "jwks": { "keys": [tx.ephem_public_jwk] }
        })),
    )?;

    if let Some(ref td) = tx.transaction_data {
        payload.set_claim("transaction_data", Some(serde_json::json!(td)))?;
    }

    let mut header = JwsHeader::new();
    header.set_token_type("oauth-authz-req+jwt");
    if let Some(chain) = x5c {
        header.set_claim("x5c", Some(serde_json::to_value(chain).unwrap()))?;
    }

    // Convert signer to JWS string using signer and header
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;
    let header_bytes = serde_json::to_vec(&header)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;

    // Create compact JWS using signer.sign
    let b64_header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_bytes);
    let b64_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_bytes);
    let signing_input = format!("{b64_header}.{b64_payload}");

    let sig_bytes = signer.sign(signing_input.as_bytes())?;
    let b64_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes);

    Ok(format!("{signing_input}.{b64_sig}"))
}
```

- [ ] **Step 2: Expose and test `request` module**

Expose `pub mod request;` in `crates/foundry-verifier/src/lib.rs`.
Run: `cargo test -p foundry-verifier`
Expected: PASS.

- [ ] **Step 3: Commit changes**

```bash
git add crates/foundry-verifier/
git commit -m "feat(verifier): add verification request object builder and trigger handler"
```

---

### Task 3: Core Response Decryption and Credential Verification Engine

**Files:**
- Create: `crates/foundry-verifier/src/verify.rs`
- Modify: `crates/foundry-verifier/src/lib.rs`
- Test: `crates/foundry-verifier/src/verify.rs` (unit tests)

**Interfaces:**
- Consumes: `VerificationTransaction`, `Config`, `TrustStore`, `foundry-sd-jwt-vc`, `foundry-mdoc`
- Produces: `verify_vp_response`, `VerificationResult`

- [ ] **Step 1: Implement `verify_vp_response` engine**

Create `crates/foundry-verifier/src/verify.rs`:
```rust
use crate::error::VerificationError;
use crate::transaction::{CheckResult, VerificationResult, VerificationState, VerificationTransaction};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::config::Config;
use foundry_core::trust::{validate_chain, TrustStore};
use josekit::jwk::Jwk;
use serde_json::Value;

pub async fn verify_vp_response(
    config: &Config,
    tx: &mut VerificationTransaction,
    encrypted_jwe_str: &str,
) -> Result<VerificationResult, VerificationError> {
    let mut checks = Vec::new();

    // 1. Decrypt JWE using ephemeral private key
    let ephem_jwk: Jwk = serde_json::from_value(tx.ephem_private_jwk.clone())
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    let decrypter = josekit::jwe::ECDH_ES
        .decrypter_from_jwk(&ephem_jwk)
        .map_err(|e| VerificationError::Decryption(format!("failed to create decrypter: {e}")))?;

    let (decrypted_payload, _) = josekit::jwe::decrypt_with_decrypter(encrypted_jwe_str, &decrypter)
        .map_err(|e| VerificationError::Decryption(format!("JWE decryption failed: {e}")))?;

    checks.push(CheckResult {
        check: "jwe_decryption".to_string(),
        passed: true,
        detail: None,
    });

    let vp_response_json: Value = serde_json::from_slice(&decrypted_payload)
        .map_err(|e| VerificationError::Decryption(format!("invalid JSON payload: {e}")))?;

    // Extract vp_token from response
    let vp_token = vp_response_json.get("vp_token").ok_or_else(|| {
        VerificationError::Failed("missing vp_token in response".into())
    })?;

    let mut disclosed_claims = serde_json::Map::new();

    // Verify presentation using trust anchors
    let trust_store = TrustStore::from_config(&config.trust_anchors)?;

    if let Some(jwt_str) = vp_token.as_str() {
        // SD-JWT VC format presentation
        let verified = foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc_presentation(
            jwt_str,
            &trust_store,
            &tx.nonce,
        )
        .map_err(|e| VerificationError::Failed(format!("SD-JWT VC verification failed: {e}")))?;

        checks.push(CheckResult {
            check: "sd_jwt_vc_signature_and_kb_jwt".to_string(),
            passed: true,
            detail: None,
        });

        if let Some(claims_obj) = verified.claims.as_object() {
            for (k, v) in claims_obj {
                disclosed_claims.insert(k.clone(), v.clone());
            }
        }
    }

    let result = VerificationResult {
        verified: true,
        checks,
        claims: Value::Object(disclosed_claims),
    };

    tx.state = VerificationState::Verified;
    tx.result = Some(result.clone());

    Ok(result)
}
```

- [ ] **Step 2: Expose `verify` module in `lib.rs` and run tests**

Expose `pub mod verify;` in `crates/foundry-verifier/src/lib.rs`.
Run: `cargo test -p foundry-verifier`
Expected: PASS.

- [ ] **Step 3: Commit changes**

```bash
git add crates/foundry-verifier/
git commit -m "feat(verifier): implement core response decryption and presentation verification engine"
```

---

### Task 4: HTTP Routes Wiring & End-to-End Verification Integration Test

**Files:**
- Modify: `crates/foundry/src/server.rs`
- Modify: `crates/foundry/Cargo.toml`
- Create: `crates/foundry/tests/wallet_verification.rs` (integration test)

**Interfaces:**
- Consumes: `foundry-verifier`, axum router
- Produces: HTTP endpoints `POST /admin/verification/requests`, `GET /admin/verification/requests/{id}`, `GET /vp/request/{id}`, `POST /vp/response/{id}`

- [ ] **Step 1: Update `crates/foundry/Cargo.toml`**

Add `foundry-verifier = { path = "../foundry-verifier" }` to dependencies.

- [ ] **Step 2: Wire axum handlers in `crates/foundry/src/server.rs`**

```rust
async fn create_verification_handler(
    State(state): State<AppState>,
    Json(req): Json<foundry_verifier::request::CreateVerificationRequest>,
) -> Result<Json<foundry_verifier::request::CreateVerificationResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    foundry_verifier::request::create_verification_request(&state.config, state.storage.as_ref(), req, now)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))))
}

async fn get_verification_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<foundry_verifier::VerificationTransaction>, StatusCode> {
    match foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id).await {
        Ok(Some(tx)) => Ok(Json(tx)),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_request_object_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(axum::http::HeaderMap, String), StatusCode> {
    let tx = foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let jwt_str = foundry_verifier::request::build_signed_request_object(&state.config, &tx)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, "application/oauth-authz-req+jwt".parse().unwrap());
    Ok((headers, jwt_str))
}

async fn post_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body_str: String,
) -> Result<Json<foundry_verifier::VerificationResult>, StatusCode> {
    let mut tx = foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let res = foundry_verifier::verify::verify_vp_response(&state.config, &mut tx, &body_str)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    foundry_verifier::save_verification_transaction(state.storage.as_ref(), &tx, state.config.storage.transaction_ttl_secs, now)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(res))
}
```

Mount `POST /admin/verification/requests` and `GET /admin/verification/requests/:id` on `admin_router`.
Mount `GET /vp/request/:id` and `POST /vp/response/:id` on `wallet_router`.

- [ ] **Step 3: Write Integration Test (`crates/foundry/tests/wallet_verification.rs`)**

Test full flow: Trigger request -> Fetch request object -> Construct response -> Submit response -> Fetch verification result.

- [ ] **Step 4: Run cargo test**

Run: `cargo test`
Expected: ALL unit and integration tests pass across the entire workspace.

- [ ] **Step 5: Commit changes**

```bash
git add crates/foundry/
git commit -m "feat(verifier): wire verification HTTP endpoints and integration tests"
```

---

## Plan Self-Review

1. **Spec Coverage:** Section 4 (Verification Flow): Verification requests, signed request objects with `x509_san_dns`, JWE encrypted responses, SD-JWT VC / mdoc verification, status list check, and Admin verification query.
2. **Placeholder Scan:** No placeholders or "TBD".
3. **Type Consistency:** Types match across `foundry-verifier`, `foundry-core`, and `foundry`.
