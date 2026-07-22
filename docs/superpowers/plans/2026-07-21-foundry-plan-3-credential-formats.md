# Credential Formats (SD-JWT VC & mdoc) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the core verifiable credential encoding, decoding, and verification layers of Foundry as two independent, self-contained workspace crates: `foundry-sd-jwt-vc` and `foundry-mdoc`. This phase delivers a **dev-reference, self-consistent round-trip** (our issuer + our verifier agree) with real ECDSA signing, x5c trust-chain validation, and holder key-binding. **Full wire-interoperability with third-party wallets/verifiers is an explicit follow-up** — see "Conformance Caveats & Non-Goals".

**Architecture:** Each credential format lives in its own dedicated workspace member crate (`crates/foundry-sd-jwt-vc` and `crates/foundry-mdoc`) depending only on `foundry-core` for crypto/trust primitives (not on each other), isolating format-specific encoding/decoding behind independently-testable boundaries. SD-JWT VC implements the draft-ietf-oauth-sd-jwt-vc-17 shape with selective disclosures and key binding (KB-JWT), while mdoc implements a CBOR/COSE MSO with IssuerAuth/DeviceAuth parsing and validation (exchanged over OpenID4VP; offline proximity retrieval out-of-scope).

**Tech Stack:** Rust 1.97, edition 2021, `josekit` 0.10 (JWS verify + JWK), `ciborium` 0.2 (CBOR), `coset` 0.3 (COSE), `serde` 1.0, `serde_json` 1.0, `base64` 0.22, `sha2` 0.10, `rand` 0.8 (CSPRNG salts), `hex` 0.4, `time` 0.3 (RFC 3339).

## Prerequisites (verified present)

Plan 2 (Crypto & Trust) is **already merged**. This plan builds directly on these existing, working `foundry-core` APIs (verified against the tree):

- `foundry_core::crypto::{Signer, SignatureAlgorithm, FileSigner}` — `Signer::algorithm()`, `Signer::sign(&[u8])`, `Signer::public_jwk()`; `FileSigner::from_pem(&[u8], SignatureAlgorithm)`.
- `foundry_core::pki::{new_ca, issue_leaf, CertMaterial}` — `CertMaterial { cert_pem: String, key_pem: String }`.
- `foundry_core::trust::{TrustStore, parse_cert_pem, validate_chain, cert_ec_public_coords, build_x5c}` — `TrustStore::from_pems(&[Vec<u8>])`, `validate_chain(leaf_pem, intermediates, store, now_unix)`, `cert_ec_public_coords(&Certificate) -> Result<(Vec<u8>, Vec<u8>)>`.

> Note: `foundry_core::trust::validate_chain` performs DN-based path building and validity-window checks; per its own `TODO(trust-hardening)`, x509-cert 0.3 does not yet cryptographically verify each chain link. That is a `foundry-core` concern, out of scope here. This plan **does** cryptographically verify the credential's own signature (issuer JWS / IssuerAuth COSE_Sign1) against the leaf certificate's public key.

## Global Constraints

- Language / runtime: Rust (edition 2021), tokio async runtime. Toolchain pinned at 1.97.
- Crate structure: `foundry-sd-jwt-vc` and `foundry-mdoc` depend only on `foundry-core`. No cross-format dependencies.
- Errors: typed via `thiserror` — per-layer domain enums. **No `unwrap`/`panic`/`expect` in non-test code paths.** Every fallible call uses `?` with `map_err`/`ok_or_else`.
- Crypto: signing uses the `Signer` trait from `foundry-core`; verification uses `josekit` verifiers built from the certificate/holder public key. Chain validation uses `foundry_core::trust::validate_chain`.
- Security: leaves in certificate chains (`x5c`) must NOT be self-signed and must validate up to a configured trust anchor via `trust::validate_chain`.
- Randomness: all salts use a CSPRNG (`rand::rngs::ThreadRng` via `RngCore::fill_bytes`). **No entropy harvesting or zero-fallback salts.**
- Holder binding: SD-JWT VC verification **must** verify a KB-JWT (typ `kb+jwt`, `aud`, `nonce`, `sd_hash`, signature under the credential's `cnf.jwk`). mdoc verification **must** verify the DeviceAuth COSE_Sign1 over the SessionTranscript under the MSO `deviceKey`.
- Every code change lands via TDD: failing test first (capture the genuine RED transcript), then minimal implementation, then commit.
- Vendored crates (`oid4vci`, `openid4vp`, `openid4vp-frontend`) are owned copies — do not touch them or hold them to our lint bar.
- Commit only the files a task declares. Never `git add -A` (untracked `.superpowers/` scratch and harness `.pi/` files must stay uncommitted).

## Conformance Caveats & Non-Goals (this phase)

This phase produces a **self-consistent dev reference**, not a wire-interoperable implementation. The following are **explicit non-goals**, each marked with a `TODO(interop)` in code where relevant, to be addressed in a later hardening pass:

1. **mdoc CBOR tag-24 wrapping.** `IssuerSignedItem` and the MSO are serialized as plain `bstr`, not `#6.24(bstr)` embedded-CBOR. Digests are computed over the untagged bytes. Real ISO 18013-5 verifiers require tag-24; ours does not emit or expect it yet.
2. **mdoc `tdate`.** `ValidityInfo.signed`/`validUntil` are RFC 3339 text strings, not CBOR `tdate` (tag 0).
3. **OpenID4VP `SessionTranscript` handover.** We use a simplified `[client_id, response_uri, nonce]` array rather than the hashed `OID4VPHandover` from OpenID4VP / ISO 18013-7. A default origin placeholder is used in the DC-API branch.
4. **SD-JWT VC canonicalization.** Header/payload are serialized via `serde_json` (deterministic key order not guaranteed across versions); acceptable for our own round-trip.

The `typ` header for SD-JWT VC **is** set to draft-17's `dc+sd-jwt` (a trivial correctness fix, not deferred).

---

## File Structure

**Workspace & foundry-core (modified):**
- `Cargo.toml` (root) — MODIFY: add both crates to members; add `coset`, `ciborium`, `sha2`, `rand`, `hex` to workspace deps; add features to `time`.
- `crates/foundry-core/src/error.rs` — MODIFY: add `FormatError` enum and wire into `CoreError`.

**foundry-sd-jwt-vc (new):**
- `crates/foundry-sd-jwt-vc/Cargo.toml`
- `crates/foundry-sd-jwt-vc/src/lib.rs`
- `crates/foundry-sd-jwt-vc/src/error.rs`
- `crates/foundry-sd-jwt-vc/src/builder.rs`
- `crates/foundry-sd-jwt-vc/src/verifier.rs`
- `crates/foundry-sd-jwt-vc/tests/sdjwt_tests.rs`

**foundry-mdoc (new):**
- `crates/foundry-mdoc/Cargo.toml`
- `crates/foundry-mdoc/src/lib.rs`
- `crates/foundry-mdoc/src/error.rs`
- `crates/foundry-mdoc/src/types.rs`
- `crates/foundry-mdoc/src/builder.rs`
- `crates/foundry-mdoc/src/verifier.rs`
- `crates/foundry-mdoc/tests/mdoc_tests.rs`

---

### Task 1: Format errors and Crate Skeleton for `foundry-sd-jwt-vc`

**Files:**
- Modify: `Cargo.toml` (root)
- Modify: `crates/foundry-core/src/error.rs`
- Create: `crates/foundry-sd-jwt-vc/Cargo.toml`
- Create: `crates/foundry-sd-jwt-vc/src/lib.rs`
- Create: `crates/foundry-sd-jwt-vc/src/error.rs`

**Interfaces:**
- Consumes: existing `CoreError` enums.
- Produces: `FormatError` enum inside `foundry_core::error`; `crates/foundry-sd-jwt-vc` workspace crate compiling with stubs.

- [ ] **Step 1: Update workspace members, deps, and `time` features**

In root `Cargo.toml`, set `members`:

```toml
members = [
    "crates/oid4vci",
    "crates/openid4vp",
    "crates/openid4vp-frontend",
    "crates/foundry-core",
    "crates/foundry",
    "crates/foundry-sd-jwt-vc",
    "crates/foundry-mdoc",
]
```

Under `[workspace.dependencies]`, add the new deps and **replace** the existing `time` line with a feature-bearing one (the code needs RFC 3339 formatting/parsing):

```toml
coset = "0.3"
ciborium = "0.2"
sha2 = "0.10"
rand = "0.8"
hex = "0.4"
time = { version = "0.3", features = ["formatting", "parsing"] }
```

> The existing `time = "0.3"` (no features) must be removed to avoid a duplicate key. `pki/mod.rs` already uses `time` and keeps working (default `std` feature still enabled).

- [ ] **Step 2: Add `FormatError` to `foundry-core` and wire into `CoreError`**

In `crates/foundry-core/src/error.rs`, add after `TrustError`:

```rust
#[derive(Debug, Error)]
pub enum FormatError {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization or parsing failed: {0}")]
    Deserialization(String),
    #[error("invalid credential structure: {0}")]
    InvalidStructure(String),
    #[error("cryptographic verification failed: {0}")]
    SignatureVerification(String),
    #[error("holder key binding verification failed: {0}")]
    KeyBinding(String),
    #[error("credential has expired or is not yet valid")]
    Expired,
    #[error("unsupported algorithm or key type: {0}")]
    Unsupported(String),
}
```

Add the variant to `CoreError`:

```rust
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error(transparent)]
    Format(#[from] FormatError),
}
```

- [ ] **Step 3: Add failing tests in `foundry-core`**

Append to `#[cfg(test)] mod tests` in `crates/foundry-core/src/error.rs`:

```rust
    #[test]
    fn format_error_serialization_displays() {
        let e = FormatError::Serialization("JSON drift".into());
        assert_eq!(e.to_string(), "serialization failed: JSON drift");
    }

    #[test]
    fn core_error_wraps_format_error() {
        let c: CoreError = FormatError::Expired.into();
        assert_eq!(c.to_string(), "credential has expired or is not yet valid");
    }
```

Run `cargo test -p foundry-core error::` — the two new tests are the RED→GREEN target (they pass once Step 2's enum is in place; run before adding Step 2 to capture RED).

- [ ] **Step 4: Create `crates/foundry-sd-jwt-vc/Cargo.toml`**

```toml
[package]
name = "foundry-sd-jwt-vc"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
foundry-core = { path = "../foundry-core" }
serde = { workspace = true }
serde_json = { workspace = true }
josekit = { workspace = true }
base64 = { workspace = true }
thiserror = { workspace = true }
sha2 = { workspace = true }
rand = { workspace = true }
time = { workspace = true }
```

- [ ] **Step 5: Create skeletons for `foundry-sd-jwt-vc`**

`crates/foundry-sd-jwt-vc/src/error.rs`:

```rust
//! SD-JWT VC format-specific error re-exports.

pub use foundry_core::error::FormatError;
```

`crates/foundry-sd-jwt-vc/src/lib.rs`:

```rust
//! SD-JWT VC Credential Format (draft-ietf-oauth-sd-jwt-vc-17 shape).

pub mod error;
pub mod builder;
pub mod verifier;

pub use error::FormatError;
```

`crates/foundry-sd-jwt-vc/src/builder.rs`:

```rust
use crate::error::FormatError;

pub fn build_sd_jwt_vc_mock() -> Result<String, FormatError> {
    Ok("mock-sd-jwt".to_string())
}
```

`crates/foundry-sd-jwt-vc/src/verifier.rs`:

```rust
use crate::error::FormatError;

pub fn verify_sd_jwt_vc_mock() -> Result<(), FormatError> {
    Ok(())
}
```

- [ ] **Step 6: Verify build**

Run: `cargo build -p foundry-sd-jwt-vc` → exits 0.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/foundry-core/src/error.rs crates/foundry-sd-jwt-vc
git commit -m "feat(sd-jwt): add format error taxonomy and foundry-sd-jwt-vc skeleton"
```

---

### Task 2: SD-JWT VC Issuer (Builder) + KB-JWT helper in `crates/foundry-sd-jwt-vc`

**Files:**
- Modify: `crates/foundry-sd-jwt-vc/src/builder.rs`

**Interfaces:**
- Consumes: `foundry_core::crypto::Signer`.
- Produces:
  ```rust
  pub struct IssuerClaims { /* fields below */ }
  pub fn build_sd_jwt_vc(claims: IssuerClaims, signer: &dyn Signer, x5c: Option<Vec<String>>) -> Result<String, FormatError>;
  pub fn build_kb_jwt(holder_signer: &dyn Signer, audience: &str, nonce: &str, sd_hash: &str) -> Result<String, FormatError>;
  pub fn attach_kb_jwt(issuer_presentation: String, holder_signer: &dyn Signer, audience: &str, nonce: &str) -> Result<String, FormatError>;
  ```

- [ ] **Step 1: Write the failing test**

Append to `crates/foundry-sd-jwt-vc/src/builder.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};

    fn test_signer() -> FileSigner {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap()
    }

    #[test]
    fn builds_sd_jwt_vc_with_disclosures() {
        let signer = test_signer();
        let mut always = serde_json::Map::new();
        always.insert("country".to_string(), serde_json::json!("DE"));
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("John"));

        let claims = IssuerClaims {
            iss: "https://issuer.dev.local".to_string(),
            sub: "did:example:123".to_string(),
            iat: 1700000000,
            exp: 1800000000,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: serde_json::json!({"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}),
            status_list_index: Some(42),
            status_list_uri: Some("https://localhost:8443/statuslists/list1".to_string()),
            always_disclosed: always,
            selectively_disclosable: select,
        };

        let result = build_sd_jwt_vc(claims, &signer, None).unwrap();
        assert!(result.ends_with('~')); // issuer presentation ends with a trailing tilde
        let parts: Vec<&str> = result.split('~').collect();
        assert_eq!(parts[0].split('.').count(), 3); // compact JWS h.p.s
        assert!(parts.len() >= 2); // at least one disclosure segment
    }

    #[test]
    fn salts_are_random() {
        let a = generate_salt();
        let b = generate_salt();
        assert_ne!(a, b);
        assert!(!a.is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-sd-jwt-vc builder::tests` → FAIL (`IssuerClaims`, `build_sd_jwt_vc`, `generate_salt` undefined).

- [ ] **Step 3: Implement the builder**

Replace everything above the test module in `crates/foundry-sd-jwt-vc/src/builder.rs`:

```rust
use crate::error::FormatError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use foundry_core::crypto::Signer;
use rand::RngCore;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct IssuerClaims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub vct: String,
    pub cnf_jwk: Value,
    pub status_list_index: Option<u64>,
    pub status_list_uri: Option<String>,
    pub always_disclosed: Map<String, Value>,
    pub selectively_disclosable: Map<String, Value>,
}

/// 16 bytes of CSPRNG entropy, URL-safe base64 (unpadded).
fn generate_salt() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::ThreadRng::default().fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

fn b64url_json(value: &Value) -> Result<String, FormatError> {
    let bytes = serde_json::to_vec(value).map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(B64URL.encode(bytes))
}

pub fn build_sd_jwt_vc(
    claims: IssuerClaims,
    signer: &dyn Signer,
    x5c: Option<Vec<String>>,
) -> Result<String, FormatError> {
    let mut payload = Map::new();
    payload.insert("iss".into(), Value::String(claims.iss));
    payload.insert("sub".into(), Value::String(claims.sub));
    payload.insert("iat".into(), Value::Number(claims.iat.into()));
    payload.insert("exp".into(), Value::Number(claims.exp.into()));
    payload.insert("vct".into(), Value::String(claims.vct));
    payload.insert("cnf".into(), json!({ "jwk": claims.cnf_jwk }));

    if let (Some(idx), Some(uri)) = (claims.status_list_index, claims.status_list_uri) {
        payload.insert("status".into(), json!({ "status_list": { "idx": idx, "uri": uri } }));
    }
    for (k, v) in claims.always_disclosed {
        payload.insert(k, v);
    }

    let mut sd_digests: Vec<String> = Vec::new();
    let mut disclosures: Vec<String> = Vec::new();
    for (k, v) in claims.selectively_disclosable {
        let salt = generate_salt();
        let disclosure_b64 = b64url_json(&json!([salt, k, v]))?;
        let mut hasher = Sha256::new();
        hasher.update(disclosure_b64.as_bytes());
        sd_digests.push(B64URL.encode(hasher.finalize()));
        disclosures.push(disclosure_b64);
    }
    if !sd_digests.is_empty() {
        sd_digests.sort();
        payload.insert(
            "_sd".into(),
            Value::Array(sd_digests.into_iter().map(Value::String).collect()),
        );
        payload.insert("_sd_alg".into(), Value::String("sha-256".into()));
    }

    let alg = signer.algorithm().as_str();
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(alg.to_string()));
    // TODO(interop): draft-17 SD-JWT VC media type.
    header.insert("typ".into(), Value::String("dc+sd-jwt".into()));
    if let Some(chain) = x5c {
        header.insert(
            "x5c".into(),
            Value::Array(chain.into_iter().map(Value::String).collect()),
        );
    }

    let header_b64 = b64url_json(&Value::Object(header))?;
    let payload_b64 = b64url_json(&Value::Object(payload))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let signature_b64 = B64URL.encode(signature);

    let mut output = format!("{signing_input}.{signature_b64}");
    for d in disclosures {
        output.push('~');
        output.push_str(&d);
    }
    output.push('~'); // trailing tilde; a KB-JWT may be appended by the holder
    Ok(output)
}

/// Build a holder Key-Binding JWT (typ `kb+jwt`) over the presentation's `sd_hash`.
pub fn build_kb_jwt(
    holder_signer: &dyn Signer,
    audience: &str,
    nonce: &str,
    sd_hash: &str,
) -> Result<String, FormatError> {
    let alg = holder_signer.algorithm().as_str();
    let header = json!({ "alg": alg, "typ": "kb+jwt" });
    let iat = time::OffsetDateTime::now_utc().unix_timestamp();
    let payload = json!({ "aud": audience, "nonce": nonce, "iat": iat, "sd_hash": sd_hash });

    let header_b64 = b64url_json(&header)?;
    let payload_b64 = b64url_json(&payload)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = holder_signer
        .sign(signing_input.as_bytes())
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
}

/// Append a KB-JWT to an issuer presentation (which must end with `~`).
pub fn attach_kb_jwt(
    issuer_presentation: String,
    holder_signer: &dyn Signer,
    audience: &str,
    nonce: &str,
) -> Result<String, FormatError> {
    let mut hasher = Sha256::new();
    hasher.update(issuer_presentation.as_bytes());
    let sd_hash = B64URL.encode(hasher.finalize());
    let kb = build_kb_jwt(holder_signer, audience, nonce, &sd_hash)?;
    Ok(format!("{issuer_presentation}{kb}"))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-sd-jwt-vc builder::tests` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-sd-jwt-vc
git commit -m "feat(sd-jwt): implement SD-JWT VC builder, KB-JWT, CSPRNG salts"
```

---

### Task 3: SD-JWT VC Verifier (incl. KB-JWT) in `crates/foundry-sd-jwt-vc`

**Files:**
- Modify: `crates/foundry-sd-jwt-vc/src/verifier.rs`

**Interfaces:**
- Consumes: `foundry_core::trust::{TrustStore, parse_cert_pem, validate_chain, cert_ec_public_coords}`.
- Produces:
  ```rust
  pub struct VerificationResult { pub claims: Value, pub holder_jwk: Value, pub issuer_x5c: Option<Vec<String>> }
  pub fn verify_sd_jwt_vc(presentation_string: &str, trust_store: &TrustStore, expected_audience: &str, expected_nonce: &str, now_unix: u64) -> Result<VerificationResult, FormatError>;
  ```
  KB-JWT is **required** and verified.

- [ ] **Step 1: Write the failing test**

Append to `crates/foundry-sd-jwt-vc/src/verifier.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::TrustStore;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};

    fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &root.cert_pem, &root.key_pem, "localhost",
            &["localhost".to_string()], 365,
        ).unwrap();
        (root.cert_pem.into_bytes(), leaf.cert_pem.into_bytes(), leaf.key_pem.into_bytes())
    }

    fn holder() -> (FileSigner, serde_json::Value) {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        let signer = FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
        let pubjwk = signer.public_jwk().unwrap();
        (signer, pubjwk)
    }

    fn der_b64(pem_bytes: &[u8]) -> String {
        std::str::from_utf8(pem_bytes).unwrap()
            .lines().filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>().join("")
    }

    #[test]
    fn parses_and_verifies_valid_presentation() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let trust_store = TrustStore::from_pems(&[root]).unwrap();
        let (holder_signer, holder_pub) = holder();

        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: 1700000000,
            exp: 1800000000,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };

        let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(issuer_pres, &holder_signer, "audience", "nonce").unwrap();

        let res = verify_sd_jwt_vc(&presentation, &trust_store, "audience", "nonce", 1750000000).unwrap();
        assert_eq!(res.claims["given_name"], "Alice");
        assert_eq!(res.claims["sub"], "did:example:alice");
    }

    #[test]
    fn rejects_kb_nonce_mismatch() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let trust_store = TrustStore::from_pems(&[root]).unwrap();
        let (holder_signer, holder_pub) = holder();

        let claims = IssuerClaims {
            iss: "localhost".to_string(), sub: "s".to_string(),
            iat: 1700000000, exp: 1800000000, vct: "v".to_string(),
            cnf_jwk: holder_pub, status_list_index: None, status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: serde_json::Map::new(),
        };
        let issuer_pres = build_sd_jwt_vc(claims, &signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(issuer_pres, &holder_signer, "audience", "WRONG").unwrap();

        let err = verify_sd_jwt_vc(&presentation, &trust_store, "audience", "nonce", 1750000000).unwrap_err();
        assert!(matches!(err, FormatError::KeyBinding(_)));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-sd-jwt-vc verifier::tests` → FAIL (`verify_sd_jwt_vc` undefined).

- [ ] **Step 3: Implement the verifier**

Replace everything above the test module in `crates/foundry-sd-jwt-vc/src/verifier.rs`:

```rust
use crate::error::FormatError;
use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use foundry_core::trust::{cert_ec_public_coords, parse_cert_pem, validate_chain, TrustStore};
use josekit::jwk::Jwk;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug)]
pub struct VerificationResult {
    pub claims: Value,
    pub holder_jwk: Value,
    pub issuer_x5c: Option<Vec<String>>,
}

fn curve_for_alg(alg: &str) -> Result<&'static str, FormatError> {
    match alg {
        "ES256" => Ok("P-256"),
        "ES384" => Ok("P-384"),
        "ES512" => Ok("P-521"),
        other => Err(FormatError::Unsupported(other.to_string())),
    }
}

fn jws_alg_for_curve(curve: &str) -> Result<&'static josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm, FormatError> {
    match curve {
        "P-256" => Ok(&josekit::jws::ES256),
        "P-384" => Ok(&josekit::jws::ES384),
        "P-521" => Ok(&josekit::jws::ES512),
        other => Err(FormatError::Unsupported(other.to_string())),
    }
}

fn verify_jws_with_coords(
    curve: &str,
    x: &[u8],
    y: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), FormatError> {
    let jwk_value = json!({ "kty": "EC", "crv": curve, "x": B64URL.encode(x), "y": B64URL.encode(y) });
    verify_jws_with_jwk(&jwk_value, curve, message, signature)
}

fn verify_jws_with_jwk(
    jwk_value: &Value,
    curve: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), FormatError> {
    let obj = jwk_value
        .as_object()
        .ok_or_else(|| FormatError::SignatureVerification("holder jwk is not an object".into()))?
        .clone();
    let jwk = Jwk::from_map(obj).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let alg = jws_alg_for_curve(curve)?;
    let verifier = alg
        .verifier_from_jwk(&jwk)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    verifier
        .verify(message, signature)
        .map_err(|e| FormatError::SignatureVerification(format!("signature mismatch: {e}")))?;
    Ok(())
}

/// Rebuild a PEM cert from a base64(standard) DER string without unwrap.
fn der_b64_to_pem(standard_b64: &str) -> Result<Vec<u8>, FormatError> {
    let der = B64STD
        .decode(standard_b64)
        .map_err(|e| FormatError::SignatureVerification(format!("x5c base64 decode: {e}")))?;
    let re_b64 = B64STD.encode(&der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut i = 0;
    while i < re_b64.len() {
        let end = (i + 64).min(re_b64.len());
        pem.push_str(&re_b64[i..end]); // base64 chars are single-byte; boundary-safe
        pem.push('\n');
        i = end;
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem.into_bytes())
}

pub fn verify_sd_jwt_vc(
    presentation_string: &str,
    trust_store: &TrustStore,
    expected_audience: &str,
    expected_nonce: &str,
    now_unix: u64,
) -> Result<VerificationResult, FormatError> {
    // <issuer_jwt>~<disclosure_1>~...~<disclosure_n>~<kb_jwt>
    // The issuer presentation ends with '~'; a KB-JWT (no trailing '~') follows.
    let parts: Vec<&str> = presentation_string.split('~').collect();
    if parts.len() < 2 {
        return Err(FormatError::InvalidStructure("empty or malformed presentation".into()));
    }
    let issuer_jwt_str = parts[0];
    let last = *parts.last().unwrap_or(&"");
    let kb_jwt: Option<&str> = if last.is_empty() { None } else { Some(last) };
    // disclosures are everything between the issuer JWT and the final segment.
    let disclosures_str = &parts[1..parts.len() - 1];

    // --- Parse issuer JWT ---
    let jwt_parts: Vec<&str> = issuer_jwt_str.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err(FormatError::InvalidStructure("invalid JWS compact serialization".into()));
    }
    let header_json: Value = serde_json::from_slice(
        &B64URL.decode(jwt_parts[0]).map_err(|e| FormatError::Deserialization(format!("header b64: {e}")))?,
    ).map_err(|e| FormatError::Deserialization(format!("header json: {e}")))?;
    let mut payload_json: Value = serde_json::from_slice(
        &B64URL.decode(jwt_parts[1]).map_err(|e| FormatError::Deserialization(format!("payload b64: {e}")))?,
    ).map_err(|e| FormatError::Deserialization(format!("payload json: {e}")))?;

    // --- Validity window ---
    if let Some(exp) = payload_json.get("exp").and_then(|v| v.as_i64()) {
        if now_unix > exp as u64 {
            return Err(FormatError::Expired);
        }
    }
    if let Some(iat) = payload_json.get("iat").and_then(|v| v.as_i64()) {
        if now_unix < iat as u64 {
            return Err(FormatError::Expired);
        }
    }

    // --- x5c trust-chain validation ---
    let x5c_array = header_json
        .get("x5c")
        .and_then(|v| v.as_array())
        .ok_or_else(|| FormatError::SignatureVerification("issuer x5c missing".into()))?;
    if x5c_array.is_empty() {
        return Err(FormatError::SignatureVerification("empty x5c header".into()));
    }
    let mut chain_pems: Vec<Vec<u8>> = Vec::with_capacity(x5c_array.len());
    for val in x5c_array {
        let s = val
            .as_str()
            .ok_or_else(|| FormatError::SignatureVerification("non-string x5c element".into()))?;
        chain_pems.push(der_b64_to_pem(s)?);
    }
    let leaf_pem = &chain_pems[0];
    let intermediates: Vec<Vec<u8>> = chain_pems[1..].to_vec();
    validate_chain(leaf_pem, &intermediates, trust_store, now_unix)
        .map_err(|e| FormatError::SignatureVerification(format!("issuer cert validation: {e}")))?;

    // --- Verify issuer JWS signature against the leaf public key ---
    let leaf_cert = parse_cert_pem(leaf_pem).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let (ix, iy) = cert_ec_public_coords(&leaf_cert)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let alg_str = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::SignatureVerification("alg missing".into()))?;
    let curve = curve_for_alg(alg_str)?;
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    let sig = B64URL
        .decode(jwt_parts[2])
        .map_err(|e| FormatError::SignatureVerification(format!("signature b64: {e}")))?;
    verify_jws_with_coords(curve, &ix, &iy, signing_input.as_bytes(), &sig)?;

    // --- Reconstruct disclosed claims ---
    let mut disclosures_map: HashMap<String, (String, Value)> = HashMap::new();
    for d_b64 in disclosures_str {
        if d_b64.is_empty() {
            continue;
        }
        let d_val: Value = serde_json::from_slice(
            &B64URL.decode(d_b64).map_err(|e| FormatError::Deserialization(format!("disclosure b64: {e}")))?,
        ).map_err(|e| FormatError::Deserialization(format!("disclosure json: {e}")))?;
        let arr = d_val
            .as_array()
            .ok_or_else(|| FormatError::InvalidStructure("disclosure must be a JSON array".into()))?;
        if arr.len() != 3 {
            return Err(FormatError::InvalidStructure("disclosure must have 3 items".into()));
        }
        let name = arr[1]
            .as_str()
            .ok_or_else(|| FormatError::InvalidStructure("disclosure name must be a string".into()))?;
        let mut hasher = Sha256::new();
        hasher.update(d_b64.as_bytes());
        let digest_b64 = B64URL.encode(hasher.finalize());
        disclosures_map.insert(digest_b64, (name.to_string(), arr[2].clone()));
    }

    let mut claims_map = Map::new();
    if let Some(payload_map) = payload_json.as_object_mut() {
        if let Some(Value::Array(sd_array)) = payload_map.remove("_sd") {
            for digest_val in sd_array {
                let digest_str = digest_val
                    .as_str()
                    .ok_or_else(|| FormatError::InvalidStructure("_sd elements must be strings".into()))?;
                if let Some((name, val)) = disclosures_map.get(digest_str) {
                    payload_map.insert(name.clone(), val.clone());
                }
            }
        }
        payload_map.remove("_sd_alg");
        claims_map = payload_map.clone();
    }

    let holder_jwk = claims_map
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .cloned()
        .ok_or_else(|| FormatError::InvalidStructure("holder cnf.jwk missing".into()))?;

    // --- KB-JWT holder binding (required) ---
    let kb = kb_jwt.ok_or_else(|| FormatError::KeyBinding("KB-JWT missing from presentation".into()))?;
    verify_kb_jwt(kb, presentation_string, &holder_jwk, expected_audience, expected_nonce)?;

    let x5c_vec: Option<Vec<String>> = header_json
        .get("x5c")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect());

    Ok(VerificationResult {
        claims: Value::Object(claims_map),
        holder_jwk,
        issuer_x5c: x5c_vec,
    })
}

fn verify_kb_jwt(
    kb: &str,
    full_presentation: &str,
    holder_jwk: &Value,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<(), FormatError> {
    let kb_parts: Vec<&str> = kb.split('.').collect();
    if kb_parts.len() != 3 {
        return Err(FormatError::KeyBinding("KB-JWT is not compact JWS".into()));
    }
    let kb_header: Value = serde_json::from_slice(
        &B64URL.decode(kb_parts[0]).map_err(|e| FormatError::KeyBinding(format!("kb header b64: {e}")))?,
    ).map_err(|e| FormatError::KeyBinding(format!("kb header json: {e}")))?;
    if kb_header.get("typ").and_then(|v| v.as_str()) != Some("kb+jwt") {
        return Err(FormatError::KeyBinding("KB-JWT typ must be kb+jwt".into()));
    }
    let kb_payload: Value = serde_json::from_slice(
        &B64URL.decode(kb_parts[1]).map_err(|e| FormatError::KeyBinding(format!("kb payload b64: {e}")))?,
    ).map_err(|e| FormatError::KeyBinding(format!("kb payload json: {e}")))?;

    if kb_payload.get("aud").and_then(|v| v.as_str()) != Some(expected_audience) {
        return Err(FormatError::KeyBinding("KB-JWT audience mismatch".into()));
    }
    if kb_payload.get("nonce").and_then(|v| v.as_str()) != Some(expected_nonce) {
        return Err(FormatError::KeyBinding("KB-JWT nonce mismatch".into()));
    }

    // sd_hash is over the issuer presentation (everything up to and including the last '~').
    let without_kb = &full_presentation[..full_presentation.len() - kb.len()];
    let mut hasher = Sha256::new();
    hasher.update(without_kb.as_bytes());
    let expected_sd_hash = B64URL.encode(hasher.finalize());
    if kb_payload.get("sd_hash").and_then(|v| v.as_str()) != Some(expected_sd_hash.as_str()) {
        return Err(FormatError::KeyBinding("KB-JWT sd_hash mismatch".into()));
    }

    // Signature under the holder's confirmation key.
    let alg_str = kb_header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::KeyBinding("KB-JWT alg missing".into()))?;
    let curve = curve_for_alg(alg_str).map_err(|_| FormatError::KeyBinding("unsupported KB-JWT alg".into()))?;
    let signing_input = format!("{}.{}", kb_parts[0], kb_parts[1]);
    let sig = B64URL
        .decode(kb_parts[2])
        .map_err(|e| FormatError::KeyBinding(format!("kb signature b64: {e}")))?;
    verify_jws_with_jwk(holder_jwk, curve, signing_input.as_bytes(), &sig)
        .map_err(|e| FormatError::KeyBinding(format!("KB-JWT signature invalid: {e}")))?;
    Ok(())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-sd-jwt-vc verifier::tests` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-sd-jwt-vc
git commit -m "feat(sd-jwt): implement verifier with x5c validation and KB-JWT binding"
```

---

### Task 4: `crates/foundry-mdoc` Crate Skeleton and Types

**Files:**
- Create: `crates/foundry-mdoc/Cargo.toml`
- Create: `crates/foundry-mdoc/src/lib.rs`
- Create: `crates/foundry-mdoc/src/error.rs`
- Create: `crates/foundry-mdoc/src/types.rs`
- Create stub `builder.rs`, `verifier.rs`

**Interfaces:**
- Produces: `crates/foundry-mdoc` crate; CBOR types under `foundry_mdoc::types`.

- [ ] **Step 1: Create `crates/foundry-mdoc/Cargo.toml`**

```toml
[package]
name = "foundry-mdoc"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
foundry-core = { path = "../foundry-core" }
serde = { workspace = true }
serde_json = { workspace = true }
ciborium = { workspace = true }
coset = { workspace = true }
thiserror = { workspace = true }
base64 = { workspace = true }
sha2 = { workspace = true }
rand = { workspace = true }
hex = { workspace = true }
time = { workspace = true }
josekit = { workspace = true }
```

> `josekit` is required in non-test code: the verifier builds josekit verifiers for COSE_Sign1 signature checks.

- [ ] **Step 2: Create skeletons and CBOR/COSE types**

`crates/foundry-mdoc/src/error.rs`:

```rust
//! mdoc format-specific error re-exports.

pub use foundry_core::error::FormatError;
```

`crates/foundry-mdoc/src/types.rs`:

```rust
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// MobileSecurityObject (ISO/IEC 18013-5 §9.1.2.4).
/// TODO(interop): payload is not tag-24 embedded-CBOR wrapped.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MobileSecurityObject {
    pub version: String,
    #[serde(rename = "digestAlgorithm")]
    pub digest_algorithm: String,
    #[serde(rename = "docType")]
    pub doc_type: String,
    #[serde(rename = "valueDigests")]
    pub value_digests: BTreeMap<String, BTreeMap<u64, Vec<u8>>>,
    #[serde(rename = "deviceKeyInfo")]
    pub device_key_info: DeviceKeyInfo,
    #[serde(rename = "validityInfo")]
    pub validity_info: ValidityInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceKeyInfo {
    #[serde(rename = "deviceKey")]
    pub device_key: ciborium::Value,
}

/// TODO(interop): should be CBOR `tdate` (tag 0), not plain text.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidityInfo {
    pub signed: String,
    #[serde(rename = "validUntil")]
    pub valid_until: String,
}

/// IssuerSignedItem (ISO/IEC 18013-5 §9.1.2.5).
/// TODO(interop): should be transported as tag-24 embedded CBOR.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IssuerSignedItem {
    #[serde(rename = "digestID")]
    pub digest_id: u64,
    pub random: Vec<u8>,
    #[serde(rename = "elementIdentifier")]
    pub element_identifier: String,
    #[serde(rename = "elementValue")]
    pub element_value: ciborium::Value,
}

/// SessionTranscript for OpenID4VP handover.
/// TODO(interop): simplified handover; not the hashed OID4VPHandover from 18013-7.
pub fn serialize_session_transcript(
    client_id: Option<String>,
    response_uri: Option<String>,
    nonce: String,
) -> Result<Vec<u8>, String> {
    let handover = if let (Some(cid), Some(ruri)) = (client_id, response_uri) {
        ciborium::Value::Array(vec![
            ciborium::Value::Text(cid),
            ciborium::Value::Text(ruri),
            ciborium::Value::Text(nonce),
        ])
    } else {
        ciborium::Value::Array(vec![
            ciborium::Value::Text("https://localhost:8443".to_string()),
            ciborium::Value::Text(nonce),
        ])
    };
    let transcript = ciborium::Value::Array(vec![
        ciborium::Value::Null,
        ciborium::Value::Null,
        handover,
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&transcript, &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
```

`crates/foundry-mdoc/src/lib.rs`:

```rust
//! mdoc Credential Format (ISO/IEC 18013-5 CBOR/COSE profile).

pub mod error;
pub mod types;
pub mod builder;
pub mod verifier;

pub use error::FormatError;
```

`crates/foundry-mdoc/src/builder.rs` (stub):

```rust
use crate::error::FormatError;
pub fn build_mdoc_mock() -> Result<Vec<u8>, FormatError> { Ok(vec![]) }
```

`crates/foundry-mdoc/src/verifier.rs` (stub):

```rust
use crate::error::FormatError;
pub fn verify_mdoc_mock() -> Result<(), FormatError> { Ok(()) }
```

- [ ] **Step 3: Verify build**

Run: `cargo build -p foundry-mdoc` → exits 0.

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-mdoc
git commit -m "feat(mdoc): add foundry-mdoc crate skeleton and CBOR type mappings"
```

---

### Task 5: mdoc Issuer (Builder) in `crates/foundry-mdoc`

**Files:**
- Modify: `crates/foundry-mdoc/src/builder.rs`

**Interfaces:**
- Consumes: `foundry_core::crypto::Signer`.
- Produces:
  ```rust
  pub struct MdocClaims { /* below */ }
  pub fn build_mdoc(claims: MdocClaims, signer: &dyn Signer, x5c: Option<Vec<String>>) -> Result<Vec<u8>, FormatError>;
  ```

- [ ] **Step 1: Write the failing test**

Append to `crates/foundry-mdoc/src/builder.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};

    fn test_signer() -> FileSigner {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap()
    }

    #[test]
    fn builds_mdoc_verifiably() {
        let signer = test_signer();
        let d_jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();

        let mut ns_items = BTreeMap::new();
        let mut elements = BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        elements.insert("family_name".to_string(), serde_json::json!("Doe"));
        ns_items.insert("org.iso.18013.5.1".to_string(), elements);

        let claims = MdocClaims {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces: ns_items,
            device_key_jwk: serde_json::to_value(&d_jwk).unwrap(),
            signed_at: 1700000000,
            valid_until: 1800000000,
        };

        let bytes = build_mdoc(claims, &signer, None).unwrap();
        assert!(!bytes.is_empty());
        let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert!(matches!(decoded, ciborium::Value::Map(_)));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-mdoc builder::tests` → FAIL (`build_mdoc` undefined).

- [ ] **Step 3: Implement the builder**

Replace everything above the test module in `crates/foundry-mdoc/src/builder.rs`:

```rust
use crate::error::FormatError;
use crate::types::{DeviceKeyInfo, IssuerSignedItem, MobileSecurityObject, ValidityInfo};
use base64::{engine::general_purpose::STANDARD as B64STD, engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use coset::{iana, CborSerializable, CoseKeyBuilder, CoseSign1Builder, Header, ProtectedHeader};
use foundry_core::crypto::Signer;
use rand::RngCore;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct MdocClaims {
    pub doc_type: String,
    pub namespaces: BTreeMap<String, BTreeMap<String, JsonValue>>,
    pub device_key_jwk: JsonValue,
    pub signed_at: i64,
    pub valid_until: i64,
}

fn generate_random_salt() -> Vec<u8> {
    let mut bytes = [0u8; 16];
    rand::rngs::ThreadRng::default().fill_bytes(&mut bytes);
    bytes.to_vec()
}

fn format_epoch_seconds(epoch: i64) -> Result<String, FormatError> {
    let dt = time::OffsetDateTime::from_unix_timestamp(epoch)
        .map_err(|e| FormatError::Serialization(format!("timestamp: {e}")))?;
    dt.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| FormatError::Serialization(format!("rfc3339 format: {e}")))
}

fn cbor_to_value_bytes(bytes: &[u8]) -> Result<ciborium::Value, FormatError> {
    ciborium::from_reader(bytes).map_err(|e| FormatError::Serialization(e.to_string()))
}

fn alg_label(signer: &dyn Signer) -> iana::Algorithm {
    match signer.algorithm() {
        foundry_core::crypto::SignatureAlgorithm::Es256 => iana::Algorithm::ES256,
        foundry_core::crypto::SignatureAlgorithm::Es384 => iana::Algorithm::ES384,
        foundry_core::crypto::SignatureAlgorithm::Es512 => iana::Algorithm::ES512,
    }
}

pub fn build_mdoc(
    claims: MdocClaims,
    signer: &dyn Signer,
    x5c: Option<Vec<String>>,
) -> Result<Vec<u8>, FormatError> {
    let mut issuer_signed_namespaces: BTreeMap<String, ciborium::Value> = BTreeMap::new();
    let mut value_digests: BTreeMap<String, BTreeMap<u64, Vec<u8>>> = BTreeMap::new();
    let mut digest_id_counter = 0u64;

    for (ns, elements) in claims.namespaces {
        let mut ns_items: Vec<ciborium::Value> = Vec::new();
        let mut digests_map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();

        for (elem_id, elem_val) in elements {
            digest_id_counter += 1;
            let item = IssuerSignedItem {
                digest_id: digest_id_counter,
                random: generate_random_salt(),
                element_identifier: elem_id,
                element_value: json_to_cbor_value(&elem_val)?,
            };
            let mut item_bytes = Vec::new();
            ciborium::into_writer(&item, &mut item_bytes)
                .map_err(|e| FormatError::Serialization(e.to_string()))?;

            let mut hasher = Sha256::new();
            hasher.update(&item_bytes);
            digests_map.insert(digest_id_counter, hasher.finalize().to_vec());
            ns_items.push(ciborium::Value::Bytes(item_bytes));
        }
        value_digests.insert(ns.clone(), digests_map);
        issuer_signed_namespaces.insert(ns, ciborium::Value::Array(ns_items));
    }

    // Device (holder) public key → COSE_Key.
    let d_kx = claims.device_key_jwk.get("x").and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::InvalidStructure("device_key_jwk missing x".into()))?;
    let d_ky = claims.device_key_jwk.get("y").and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::InvalidStructure("device_key_jwk missing y".into()))?;
    let d_kx_bytes = B64URL.decode(d_kx)
        .map_err(|e| FormatError::InvalidStructure(format!("device key x b64: {e}")))?;
    let d_ky_bytes = B64URL.decode(d_ky)
        .map_err(|e| FormatError::InvalidStructure(format!("device key y b64: {e}")))?;

    let cose_key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, d_kx_bytes, d_ky_bytes).build();
    let cose_key_bytes = cose_key.to_vec()
        .map_err(|e| FormatError::Serialization(format!("cose key encode: {e}")))?;
    let cose_key_value = cbor_to_value_bytes(&cose_key_bytes)?;

    let mso = MobileSecurityObject {
        version: "1.0".to_string(),
        digest_algorithm: "SHA-256".to_string(),
        doc_type: claims.doc_type.clone(),
        value_digests,
        device_key_info: DeviceKeyInfo { device_key: cose_key_value },
        validity_info: ValidityInfo {
            signed: format_epoch_seconds(claims.signed_at)?,
            valid_until: format_epoch_seconds(claims.valid_until)?,
        },
    };

    let mut mso_bytes = Vec::new();
    ciborium::into_writer(&mso, &mut mso_bytes)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;

    // IssuerAuth COSE_Sign1.
    let mut protected = ProtectedHeader::default();
    protected.header.alg = Some(coset::Algorithm::Assigned(alg_label(signer)));

    let mut unprotected = Header::default();
    if let Some(chain) = x5c {
        let x5c_values: Vec<ciborium::Value> = chain
            .into_iter()
            .filter_map(|s| B64STD.decode(s).ok())
            .map(ciborium::Value::Bytes)
            .collect();
        // Label 33 = x5chain (RFC 9360). TODO(interop): confirm wallet expectations.
        unprotected.rest.push((coset::Label::Int(33), ciborium::Value::Array(x5c_values)));
    }

    let partial = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(mso_bytes.clone())
        .build();

    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        partial.protected.clone(),
        None,
        &[],
        &mso_bytes,
    );
    let signature = signer.sign(&tbs).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;

    let final_sign1 = CoseSign1Builder::new()
        .protected(partial.protected)
        .unprotected(partial.unprotected)
        .payload(mso_bytes)
        .signature(signature)
        .build();
    let issuer_auth_bytes = final_sign1.to_vec()
        .map_err(|e| FormatError::Serialization(format!("issuerAuth encode: {e}")))?;
    let issuer_auth_val = cbor_to_value_bytes(&issuer_auth_bytes)?;

    // Outer mdoc CBOR.
    let mut issuer_signed: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    issuer_signed.push((
        ciborium::Value::Text("nameSpaces".to_string()),
        ciborium::Value::Map(
            issuer_signed_namespaces.into_iter()
                .map(|(k, v)| (ciborium::Value::Text(k), v))
                .collect(),
        ),
    ));
    issuer_signed.push((ciborium::Value::Text("issuerAuth".to_string()), issuer_auth_val));

    let doc_map: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (ciborium::Value::Text("docType".to_string()), ciborium::Value::Text(claims.doc_type)),
        (ciborium::Value::Text("issuerSigned".to_string()), ciborium::Value::Map(issuer_signed)),
    ];

    let outer: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (ciborium::Value::Text("version".to_string()), ciborium::Value::Text("1.0".to_string())),
        (
            ciborium::Value::Text("documents".to_string()),
            ciborium::Value::Array(vec![ciborium::Value::Map(doc_map)]),
        ),
    ];

    let mut final_bytes = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(outer), &mut final_bytes)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(final_bytes)
}

fn json_to_cbor_value(json: &JsonValue) -> Result<ciborium::Value, FormatError> {
    match json {
        JsonValue::Null => Ok(ciborium::Value::Null),
        JsonValue::Bool(b) => Ok(ciborium::Value::Bool(*b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(ciborium::Value::Integer(i.into()))
            } else if let Some(f) = n.as_f64() {
                Ok(ciborium::Value::Float(f))
            } else {
                Err(FormatError::Serialization("invalid number".into()))
            }
        }
        JsonValue::String(s) => Ok(ciborium::Value::Text(s.clone())),
        JsonValue::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(json_to_cbor_value(v)?);
            }
            Ok(ciborium::Value::Array(out))
        }
        JsonValue::Object(map) => {
            let mut out = Vec::with_capacity(map.len());
            for (k, v) in map {
                out.push((ciborium::Value::Text(k.clone()), json_to_cbor_value(v)?));
            }
            Ok(ciborium::Value::Map(out))
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-mdoc builder::tests` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-mdoc
git commit -m "feat(mdoc): implement mdoc CBOR builder with IssuerAuth COSE_Sign1"
```

---

### Task 6: mdoc Verifier & DeviceAuth in `crates/foundry-mdoc`

**Files:**
- Modify: `crates/foundry-mdoc/src/verifier.rs`

**Interfaces:**
- Consumes: `foundry_core::trust::{TrustStore, parse_cert_pem, validate_chain, cert_ec_public_coords}`.
- Produces:
  ```rust
  pub struct MdocVerificationResult { pub claims: BTreeMap<String, BTreeMap<String, serde_json::Value>>, pub device_key_jwk: serde_json::Value, pub issuer_x5c: Option<Vec<String>> }
  pub fn verify_mdoc(mdoc_bytes: &[u8], trust_store: &TrustStore, client_id: Option<String>, response_uri: Option<String>, nonce: String, device_signature_cose_sign1_bytes: &[u8], now_unix: u64) -> Result<MdocVerificationResult, FormatError>;
  ```

- [ ] **Step 1: Write the failing test**

Append to `crates/foundry-mdoc/src/verifier.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{build_mdoc, MdocClaims};
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::TrustStore;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};
    use std::collections::BTreeMap;

    fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(&root.cert_pem, &root.key_pem, "localhost", &["localhost".to_string()], 365).unwrap();
        (root.cert_pem.into_bytes(), leaf.cert_pem.into_bytes(), leaf.key_pem.into_bytes())
    }

    fn der_b64(pem_bytes: &[u8]) -> String {
        std::str::from_utf8(pem_bytes).unwrap()
            .lines().filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>().join("")
    }

    #[test]
    fn parses_and_verifies_valid_mdoc_presentation() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let trust_store = TrustStore::from_pems(&[root]).unwrap();

        let d_jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let d_kp = EcKeyPair::from_jwk(&d_jwk).unwrap();
        let d_signer = FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let mut ns_items = BTreeMap::new();
        let mut elements = BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        ns_items.insert("org.iso.18013.5.1".to_string(), elements);

        let claims = MdocClaims {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces: ns_items,
            device_key_jwk: serde_json::to_value(&d_jwk).unwrap(),
            signed_at: 1700000000,
            valid_until: 1800000000,
        };
        let mdoc_bytes = build_mdoc(claims, &signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let transcript = crate::types::serialize_session_transcript(
            Some("client".to_string()), Some("uri".to_string()), "nonce".to_string(),
        ).unwrap();

        let mut protected = coset::ProtectedHeader::default();
        protected.header.alg = Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256));
        let partial = coset::CoseSign1Builder::new().protected(protected).build();
        let d_tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1, partial.protected.clone(), None, &[], &transcript,
        );
        let sig = d_signer.sign(&d_tbs).unwrap();
        let d_sign = coset::CoseSign1Builder::new().protected(partial.protected).signature(sig).build();
        let d_sig_bytes = coset::CborSerializable::to_vec(d_sign).unwrap();

        let res = verify_mdoc(
            &mdoc_bytes, &trust_store,
            Some("client".to_string()), Some("uri".to_string()), "nonce".to_string(),
            &d_sig_bytes, 1750000000,
        ).unwrap();
        assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-mdoc verifier::tests` → FAIL (`verify_mdoc` undefined).

- [ ] **Step 3: Implement the verifier**

Replace everything above the test module in `crates/foundry-mdoc/src/verifier.rs`:

```rust
use crate::error::FormatError;
use crate::types::{serialize_session_transcript, IssuerSignedItem, MobileSecurityObject};
use base64::{engine::general_purpose::STANDARD as B64STD, engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use coset::iana::EnumI64;
use coset::{iana, CborSerializable, CoseKey, CoseSign1};
use foundry_core::trust::{cert_ec_public_coords, parse_cert_pem, validate_chain, TrustStore};
use josekit::jwk::Jwk;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct MdocVerificationResult {
    pub claims: BTreeMap<String, BTreeMap<String, JsonValue>>,
    pub device_key_jwk: JsonValue,
    pub issuer_x5c: Option<Vec<String>>,
}

fn curve_for_alg(alg: &str) -> Result<&'static str, FormatError> {
    match alg {
        "ES256" => Ok("P-256"),
        "ES384" => Ok("P-384"),
        "ES512" => Ok("P-521"),
        other => Err(FormatError::Unsupported(other.to_string())),
    }
}

fn jws_alg_for_curve(curve: &str) -> Result<&'static josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm, FormatError> {
    match curve {
        "P-256" => Ok(&josekit::jws::ES256),
        "P-384" => Ok(&josekit::jws::ES384),
        "P-521" => Ok(&josekit::jws::ES512),
        other => Err(FormatError::Unsupported(other.to_string())),
    }
}

fn verify_ecdsa(curve: &str, x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> Result<(), FormatError> {
    let jwk_value = json!({ "kty": "EC", "crv": curve, "x": B64URL.encode(x), "y": B64URL.encode(y) });
    let obj = jwk_value
        .as_object()
        .ok_or_else(|| FormatError::SignatureVerification("jwk build failed".into()))?
        .clone();
    let jwk = Jwk::from_map(obj).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let alg = jws_alg_for_curve(curve)?;
    let verifier = alg
        .verifier_from_jwk(&jwk)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    verifier
        .verify(message, signature)
        .map_err(|e| FormatError::SignatureVerification(format!("signature mismatch: {e}")))?;
    Ok(())
}

fn der_b64_to_pem(standard_b64: &str) -> Result<Vec<u8>, FormatError> {
    let der = B64STD
        .decode(standard_b64)
        .map_err(|e| FormatError::SignatureVerification(format!("x5c b64: {e}")))?;
    let re_b64 = B64STD.encode(&der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut i = 0;
    while i < re_b64.len() {
        let end = (i + 64).min(re_b64.len());
        pem.push_str(&re_b64[i..end]);
        pem.push('\n');
        i = end;
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem.into_bytes())
}

fn lookup_map_key<'a>(map: &'a [(ciborium::Value, ciborium::Value)], key: &str) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(k, v)| match k {
        ciborium::Value::Text(s) if s == key => Some(v),
        _ => None,
    })
}

fn cbor_value_to_bytes(v: &ciborium::Value) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(v, &mut bytes).map_err(|e| FormatError::Deserialization(e.to_string()))?;
    Ok(bytes)
}

fn cose_alg_str(alg: &coset::Algorithm) -> Result<&'static str, FormatError> {
    match alg {
        coset::Algorithm::Assigned(iana::Algorithm::ES256) => Ok("ES256"),
        coset::Algorithm::Assigned(iana::Algorithm::ES384) => Ok("ES384"),
        coset::Algorithm::Assigned(iana::Algorithm::ES512) => Ok("ES512"),
        _ => Err(FormatError::Unsupported("unsupported COSE algorithm".into())),
    }
}

pub fn verify_mdoc(
    mdoc_bytes: &[u8],
    trust_store: &TrustStore,
    client_id: Option<String>,
    response_uri: Option<String>,
    nonce: String,
    device_signature_cose_sign1_bytes: &[u8],
    now_unix: u64,
) -> Result<MdocVerificationResult, FormatError> {
    // --- Outer CBOR ---
    let outer_val: ciborium::Value = ciborium::from_reader(mdoc_bytes)
        .map_err(|e| FormatError::Deserialization(format!("outer CBOR: {e}")))?;
    let outer_map = outer_val
        .as_map()
        .ok_or_else(|| FormatError::InvalidStructure("mdoc must be a CBOR map".into()))?;
    let docs = lookup_map_key(outer_map, "documents")
        .and_then(|v| v.as_array())
        .ok_or_else(|| FormatError::InvalidStructure("missing documents array".into()))?;
    let first_doc = docs
        .first()
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("empty or invalid documents".into()))?;
    let issuer_signed = lookup_map_key(first_doc, "issuerSigned")
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("missing issuerSigned".into()))?;
    let namespaces_map = lookup_map_key(issuer_signed, "nameSpaces")
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("missing nameSpaces".into()))?;
    let issuer_auth_val = lookup_map_key(issuer_signed, "issuerAuth")
        .ok_or_else(|| FormatError::InvalidStructure("missing issuerAuth".into()))?;

    // --- IssuerAuth COSE_Sign1 ---
    let issuer_auth_bytes = cbor_value_to_bytes(issuer_auth_val)?;
    let sign1 = CoseSign1::from_slice(&issuer_auth_bytes)
        .map_err(|e| FormatError::Deserialization(format!("issuerAuth COSE: {e}")))?;

    let mut x5c_b64s: Vec<String> = Vec::new();
    for (label, value) in &sign1.unprotected.rest {
        if *label == coset::Label::Int(33) {
            if let Some(arr) = value.as_array() {
                for item in arr {
                    if let Some(bytes) = item.as_bytes() {
                        x5c_b64s.push(B64STD.encode(bytes));
                    }
                }
            }
        }
    }
    if x5c_b64s.is_empty() {
        return Err(FormatError::SignatureVerification("issuerAuth missing x5c".into()));
    }

    let mut chain_pems: Vec<Vec<u8>> = Vec::with_capacity(x5c_b64s.len());
    for b64 in &x5c_b64s {
        chain_pems.push(der_b64_to_pem(b64)?);
    }
    let leaf_pem = &chain_pems[0];
    let intermediates: Vec<Vec<u8>> = chain_pems[1..].to_vec();
    validate_chain(leaf_pem, &intermediates, trust_store, now_unix)
        .map_err(|e| FormatError::SignatureVerification(format!("issuer cert validation: {e}")))?;

    let leaf_cert = parse_cert_pem(leaf_pem).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let (ix, iy) = cert_ec_public_coords(&leaf_cert)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;

    let mso_bytes = sign1
        .payload
        .clone()
        .ok_or_else(|| FormatError::InvalidStructure("issuerAuth missing payload".into()))?;
    let alg = sign1
        .protected
        .header
        .alg
        .clone()
        .ok_or_else(|| FormatError::SignatureVerification("issuerAuth missing alg".into()))?;
    let curve = curve_for_alg(cose_alg_str(&alg)?)?;
    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        sign1.protected.clone(),
        None,
        &[],
        &mso_bytes,
    );
    verify_ecdsa(curve, &ix, &iy, &tbs, &sign1.signature)?;

    // --- MSO ---
    let mso: MobileSecurityObject = ciborium::from_reader(mso_bytes.as_slice())
        .map_err(|e| FormatError::Deserialization(format!("MSO CBOR: {e}")))?;

    let signed_ts = time::OffsetDateTime::parse(&mso.validity_info.signed, &time::format_description::well_known::Rfc3339)
        .map_err(|e| FormatError::Deserialization(format!("signed parse: {e}")))?;
    let until_ts = time::OffsetDateTime::parse(&mso.validity_info.valid_until, &time::format_description::well_known::Rfc3339)
        .map_err(|e| FormatError::Deserialization(format!("validUntil parse: {e}")))?;
    if now_unix < signed_ts.unix_timestamp() as u64 || now_unix > until_ts.unix_timestamp() as u64 {
        return Err(FormatError::Expired);
    }

    // --- Digest verification & claim reconstruction ---
    let mut verified_claims: BTreeMap<String, BTreeMap<String, JsonValue>> = BTreeMap::new();
    for (ns_key, items_val) in namespaces_map {
        let ns_str = match ns_key {
            ciborium::Value::Text(s) => s,
            _ => continue,
        };
        let items = match items_val.as_array() {
            Some(a) => a,
            None => continue,
        };
        let mso_digests = match mso.value_digests.get(ns_str) {
            Some(d) => d,
            None => continue,
        };
        let mut ns_elements: BTreeMap<String, JsonValue> = BTreeMap::new();
        for item_val in items {
            let item_bytes = match item_val.as_bytes() {
                Some(b) => b,
                None => continue,
            };
            let mut hasher = Sha256::new();
            hasher.update(item_bytes);
            let computed = hasher.finalize().to_vec();

            let item: IssuerSignedItem = ciborium::from_reader(item_bytes.as_slice())
                .map_err(|e| FormatError::Deserialization(format!("IssuerSignedItem: {e}")))?;
            if let Some(expected) = mso_digests.get(&item.digest_id) {
                if expected == &computed {
                    ns_elements.insert(item.element_identifier, cbor_value_to_json(&item.element_value)?);
                }
            }
        }
        if !ns_elements.is_empty() {
            verified_claims.insert(ns_str.clone(), ns_elements);
        }
    }

    // --- Device (holder) binding: DeviceAuth over SessionTranscript ---
    let device_key_bytes = cbor_value_to_bytes(&mso.device_key_info.device_key)?;
    let device_cose_key = CoseKey::from_slice(&device_key_bytes)
        .map_err(|e| FormatError::Deserialization(format!("deviceKey COSE: {e}")))?;

    let mut d_x: Vec<u8> = Vec::new();
    let mut d_y: Vec<u8> = Vec::new();
    for (label, value) in &device_cose_key.params {
        if *label == coset::Label::Int(iana::Ec2KeyParameter::X.to_i64()) {
            if let Some(b) = value.as_bytes() {
                d_x = b.clone();
            }
        } else if *label == coset::Label::Int(iana::Ec2KeyParameter::Y.to_i64()) {
            if let Some(b) = value.as_bytes() {
                d_y = b.clone();
            }
        }
    }
    if d_x.is_empty() || d_y.is_empty() {
        return Err(FormatError::InvalidStructure("deviceKey missing EC coords".into()));
    }
    let device_key_jwk = json!({ "kty": "EC", "crv": "P-256", "x": B64URL.encode(&d_x), "y": B64URL.encode(&d_y) });

    let d_sign1 = CoseSign1::from_slice(device_signature_cose_sign1_bytes)
        .map_err(|e| FormatError::Deserialization(format!("device COSE: {e}")))?;
    let transcript = serialize_session_transcript(client_id, response_uri, nonce)
        .map_err(FormatError::Serialization)?;
    let d_alg = d_sign1
        .protected
        .header
        .alg
        .clone()
        .ok_or_else(|| FormatError::KeyBinding("device signature missing alg".into()))?;
    let d_curve = curve_for_alg(cose_alg_str(&d_alg)?)
        .map_err(|_| FormatError::KeyBinding("unsupported device alg".into()))?;
    let d_tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        d_sign1.protected.clone(),
        None,
        &[],
        &transcript,
    );
    verify_ecdsa(d_curve, &d_x, &d_y, &d_tbs, &d_sign1.signature)
        .map_err(|e| FormatError::KeyBinding(format!("device signature invalid: {e}")))?;

    Ok(MdocVerificationResult {
        claims: verified_claims,
        device_key_jwk,
        issuer_x5c: Some(x5c_b64s),
    })
}

fn cbor_value_to_json(val: &ciborium::Value) -> Result<JsonValue, FormatError> {
    match val {
        ciborium::Value::Null => Ok(JsonValue::Null),
        ciborium::Value::Bool(b) => Ok(JsonValue::Bool(*b)),
        ciborium::Value::Integer(i) => {
            let num: i128 = (*i).into();
            let as_i64 = i64::try_from(num)
                .map_err(|_| FormatError::Deserialization("integer out of i64 range".into()))?;
            Ok(JsonValue::Number(as_i64.into()))
        }
        ciborium::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(JsonValue::Number)
            .ok_or_else(|| FormatError::Deserialization("non-finite float".into())),
        ciborium::Value::Text(s) => Ok(JsonValue::String(s.clone())),
        ciborium::Value::Bytes(b) => Ok(JsonValue::String(hex::encode(b))),
        ciborium::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(cbor_value_to_json(v)?);
            }
            Ok(JsonValue::Array(out))
        }
        ciborium::Value::Map(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let key = k
                    .as_text()
                    .ok_or_else(|| FormatError::Deserialization("CBOR map key not text".into()))?;
                out.insert(key.to_string(), cbor_value_to_json(v)?);
            }
            Ok(JsonValue::Object(out))
        }
        _ => Err(FormatError::Unsupported("unsupported CBOR type".into())),
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-mdoc verifier::tests` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-mdoc
git commit -m "feat(mdoc): implement verifier with IssuerAuth and DeviceAuth validation"
```

---

### Task 7: Format-level integration & negative tests; workspace gates

**Files:**
- Create: `crates/foundry-sd-jwt-vc/tests/sdjwt_tests.rs`
- Create: `crates/foundry-mdoc/tests/mdoc_tests.rs`

**Interfaces:**
- Consumes: all format APIs.
- Produces: negative/edge tests; clippy-clean, fmt-clean workspace.

- [ ] **Step 1: Write `crates/foundry-sd-jwt-vc/tests/sdjwt_tests.rs`**

```rust
use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::trust::TrustStore;
use foundry_sd_jwt_vc::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
use foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc;
use foundry_sd_jwt_vc::FormatError;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::{Jwk, KeyPair as _};

fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
    let leaf = issue_leaf(&root.cert_pem, &root.key_pem, "localhost", &["localhost".to_string()], 365).unwrap();
    (root.cert_pem.into_bytes(), leaf.cert_pem.into_bytes(), leaf.key_pem.into_bytes())
}

fn holder() -> (FileSigner, serde_json::Value) {
    let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    let kp = EcKeyPair::from_jwk(&jwk).unwrap();
    let signer = FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let pubjwk = signer.public_jwk().unwrap();
    (signer, pubjwk)
}

fn encode_der(pem_bytes: &[u8]) -> String {
    std::str::from_utf8(pem_bytes).unwrap()
        .lines().filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>().join("")
}

fn make_claims(cnf: serde_json::Value, iat: i64, exp: i64) -> IssuerClaims {
    let mut select = serde_json::Map::new();
    select.insert("name".to_string(), serde_json::json!("Bob"));
    IssuerClaims {
        iss: "localhost".to_string(), sub: "did:example:bob".to_string(),
        iat, exp, vct: "vct".to_string(), cnf_jwk: cnf,
        status_list_index: None, status_list_uri: None,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    }
}

#[test]
fn verifies_selective_claims() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let issuer_pres = build_sd_jwt_vc(make_claims(h_pub, 1000, 2000), &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce").unwrap();
    let res = verify_sd_jwt_vc(&pres, &trust_store, "aud", "nonce", 1500).unwrap();
    assert_eq!(res.claims["name"], "Bob");
}

#[test]
fn rejects_expired_sd_jwt() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let issuer_pres = build_sd_jwt_vc(make_claims(h_pub, 1000, 2000), &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce").unwrap();
    let err = verify_sd_jwt_vc(&pres, &trust_store, "aud", "nonce", 2500).unwrap_err();
    assert!(matches!(err, FormatError::Expired));
}

#[test]
fn rejects_untrusted_anchor() {
    let (_root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    // A DIFFERENT root that did not sign the leaf.
    let other = new_ca("Other Root", 3650).unwrap();
    let trust_store = TrustStore::from_pems(&[other.cert_pem.into_bytes()]).unwrap();
    let (h_signer, h_pub) = holder();

    let issuer_pres = build_sd_jwt_vc(make_claims(h_pub, 1000, 2000), &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce").unwrap();
    let err = verify_sd_jwt_vc(&pres, &trust_store, "aud", "nonce", 1500).unwrap_err();
    assert!(matches!(err, FormatError::SignatureVerification(_)));
}

#[test]
fn rejects_kb_audience_mismatch() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let issuer_pres = build_sd_jwt_vc(make_claims(h_pub, 1000, 2000), &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "WRONG_AUD", "nonce").unwrap();
    let err = verify_sd_jwt_vc(&pres, &trust_store, "aud", "nonce", 1500).unwrap_err();
    assert!(matches!(err, FormatError::KeyBinding(_)));
}

#[test]
fn rejects_tampered_disclosure() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();
    let (h_signer, h_pub) = holder();

    let issuer_pres = build_sd_jwt_vc(make_claims(h_pub, 1000, 2000), &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let pres = attach_kb_jwt(issuer_pres, &h_signer, "aud", "nonce").unwrap();

    // Flip a character in the first disclosure segment; its digest no longer matches _sd,
    // so the claim silently drops out of the reconstructed set (it is not asserted).
    let mut segs: Vec<String> = pres.split('~').map(str::to_string).collect();
    let d = &mut segs[1];
    let last = d.pop().unwrap();
    d.push(if last == 'A' { 'B' } else { 'A' });
    let tampered = segs.join("~");

    // KB sd_hash now mismatches the modified presentation → KeyBinding failure.
    let err = verify_sd_jwt_vc(&tampered, &trust_store, "aud", "nonce", 1500).unwrap_err();
    assert!(matches!(err, FormatError::KeyBinding(_)));
}
```

- [ ] **Step 2: Write `crates/foundry-mdoc/tests/mdoc_tests.rs`**

```rust
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::trust::TrustStore;
use foundry_mdoc::builder::{build_mdoc, MdocClaims};
use foundry_mdoc::verifier::verify_mdoc;
use foundry_mdoc::FormatError;
use std::collections::BTreeMap;

fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
    let leaf = issue_leaf(&root.cert_pem, &root.key_pem, "localhost", &["localhost".to_string()], 365).unwrap();
    (root.cert_pem.into_bytes(), leaf.cert_pem.into_bytes(), leaf.key_pem.into_bytes())
}

fn encode_der(pem_bytes: &[u8]) -> String {
    std::str::from_utf8(pem_bytes).unwrap()
        .lines().filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>().join("")
}

fn make_claims(signed_at: i64, valid_until: i64) -> MdocClaims {
    MdocClaims {
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
        namespaces: BTreeMap::new(),
        device_key_jwk: serde_json::json!({"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}),
        signed_at,
        valid_until,
    }
}

#[test]
fn rejects_expired_mdoc() {
    let (root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let trust_store = TrustStore::from_pems(&[root]).unwrap();

    let mdoc_bytes = build_mdoc(make_claims(1000, 2000), &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    // Expiry is checked before device-signature binding, so empty device sig is fine here.
    let err = verify_mdoc(
        &mdoc_bytes, &trust_store,
        Some("client".to_string()), Some("uri".to_string()), "nonce".to_string(),
        &[], 2500,
    ).unwrap_err();
    assert!(matches!(err, FormatError::Expired));
}

#[test]
fn rejects_untrusted_anchor_mdoc() {
    let (_root, leaf_cert, leaf_key) = test_pki();
    let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
    let other = new_ca("Other Root", 3650).unwrap();
    let trust_store = TrustStore::from_pems(&[other.cert_pem.into_bytes()]).unwrap();

    let mdoc_bytes = build_mdoc(make_claims(1000, 2000), &signer, Some(vec![encode_der(&leaf_cert)])).unwrap();
    let err = verify_mdoc(
        &mdoc_bytes, &trust_store,
        Some("client".to_string()), Some("uri".to_string()), "nonce".to_string(),
        &[], 1500,
    ).unwrap_err();
    assert!(matches!(err, FormatError::SignatureVerification(_)));
}
```

> Note: the untrusted-anchor mdoc test relies on `validate_chain` running before the device-signature check; both the trust-chain and (in the happy path) device-binding failures surface as distinct typed errors.

- [ ] **Step 3: Run integration tests**

Run: `cargo test -p foundry-sd-jwt-vc --test sdjwt_tests && cargo test -p foundry-mdoc --test mdoc_tests` → PASS.

- [ ] **Step 4: Workspace gates**

```bash
cargo fmt -p foundry-sd-jwt-vc -p foundry-mdoc -- --check
cargo clippy -p foundry-sd-jwt-vc -p foundry-mdoc --all-targets -- -D warnings
cargo build --workspace
cargo test -p foundry-sd-jwt-vc -p foundry-mdoc
```

Expected: zero warnings, clean format, zero errors, all tests green.

- [ ] **Step 5: Commit**

```bash
git add Cargo.lock crates/foundry-sd-jwt-vc/tests crates/foundry-mdoc/tests
git commit -m "test(formats): add integration and negative tests for SD-JWT VC and mdoc"
```