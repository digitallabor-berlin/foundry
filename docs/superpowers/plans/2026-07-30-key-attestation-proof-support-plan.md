# Key Attestation & Full Proof-Type Support for the Credential Endpoint — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `docs/superpowers/specs/2026-07-30-key-attestation-proof-support-spec.md`
**Branch:** create `fix/key-attestation-proof-support` before Task 1 (or a worktree, per `superpowers:using-git-worktrees`, if isolation is needed).

**Goal:** Make `POST /credential` accept the HAIP-mandated `kid` + `key_attestation` proof shape (in addition to the existing `jwk`-only shape), with real x5c-chain-verified attestation trust.

**Architecture:** Add a Wallet-Provider trust-anchor list to `issuer.key_attestation` config; add `attestation::verify_key_attestation_jwt` to cryptographically verify the nested attestation JWT; extend `proof::verify_holder_proof` to branch on `jwk`/`kid`/`x5c` and gate on `key_attestation.mode`; advertise `key_attestations_required` in metadata; wire it all through `credential::handle_credential_request`.

**Tech Stack:** Rust (edition 2021), `josekit` (JOSE/JWK), `foundry_core::trust` (x5c chain validation), `foundry_core::pki` (test CA/leaf generation), `serde_json`, `utoipa`.

## Global Constraints

- Spec compliance target: OpenID4VCI 1.0 final Appendix D + Appendix F.1; HAIP 1.0 final §4.5.1.
- No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` outside `#[cfg(test)]` (root `AGENTS.md` §4.1).
- `foundry-issuer` must not gain a dependency on `foundry-verifier` or `crates/foundry` (root `AGENTS.md` §3).
- Any endpoint/metadata shape change must be reflected in `openapi.json`/`openapi-wallet.json` (root `AGENTS.md` §6).
- `crates/oid4vci` (vendored) is not touched by this plan.
- Backward compatibility: existing `jwk`-only proofs must keep passing unmodified when `key_attestation.mode` is `Optional` or `Disabled`.
- Gates before completion: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.
- Every code change lands via TDD: failing test first, then minimal implementation, then commit.
- Commit only the files a task declares. Never `git add -A`.

## File Structure

- `crates/foundry-core/src/config/model.rs` — `AttestationMode` gains `trusted_anchors: Vec<TrustAnchor>`.
- `crates/foundry-core/src/config/validate.rs` — validate the new field's cert files at startup.
- `crates/foundry-issuer/src/attestation.rs` — new `KeyAttestationClaims` + `verify_key_attestation_jwt`.
- `crates/foundry-issuer/src/proof.rs` — `verify_holder_proof` gains `kid`/`key_attestation` branching, gated by `key_attestation.mode`.
- `crates/foundry-issuer/src/credential.rs` — builds the key-attestation `TrustStore` and passes the new parameters through.
- `crates/foundry-issuer/src/metadata.rs` — `ProofTypeSupported.key_attestations_required`.
- `crates/foundry/tests/wallet_issuance.rs` — new end-to-end test for the `kid`+`key_attestation` path.
- 13 existing test files across `crates/foundry-*` construct `AttestationMode { mode: ... }` literals and need a one-line mechanical fixup (Task 1, Step 5).

---

### Task 1: Config — Wallet-Provider trust-anchor list for key attestation

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs`
- Modify: `crates/foundry-core/src/config/validate.rs`
- Modify (mechanical, one line each): every file listed in Task 1 Step 5

**Interfaces:**
- Consumes: existing `TrustAnchor { name: String, certs: String }` (unchanged).
- Produces: `AttestationMode { mode: Mode, trusted_anchors: Vec<TrustAnchor> }`; `Config::validate_key_material` now also validates `issuer.wallet_attestation.trusted_anchors` and `issuer.key_attestation.trusted_anchors`.

- [ ] **Step 1: Write the failing test**

In `crates/foundry-core/src/config/validate.rs`, add a `#[cfg(test)]` module (none exists yet in this file):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{
        AdminConfig, AttestationMode, Config, IssuerConfig, Mode, ServerConfig, StatusListConfig,
        StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
    };
    use std::collections::BTreeMap;

    fn minimal_config() -> Config {
        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://issuer.example.com".to_string(),
                    bind: "0.0.0.0:8443".to_string(),
                    swagger_ui_enabled: true,
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:9000".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                    console_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "./foundry.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys: BTreeMap::new(),
            trust_anchors: Vec::new(),
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                wallet_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: None,
                    list_size: None,
                    public_base_url: None,
                },
            },
            credential_types: Vec::new(),
            verifier: VerifierConfig {
                client_id_scheme: "x509_san_dns".to_string(),
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: Vec::new(),
                named_queries: Vec::new(),
                webhook: None,
            },
        }
    }

    #[test]
    fn key_attestation_trusted_anchor_must_resolve_and_parse() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "missing.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer.key_attestation.trusted_anchors.push(TrustAnchor {
            name: "wallet-provider-ca".to_string(),
            certs: "does-not-exist.pem".to_string(),
        });

        let err = cfg.validate_key_material(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("wallet-provider-ca"),
            "expected error to name the anchor, got: {msg}"
        );
    }

    #[test]
    fn key_attestation_trusted_anchor_parses_when_valid() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let ca = crate::pki::new_ca("Wallet Provider Root CA", 3650).unwrap();
        let ca_path = dir.path().join("wallet-provider-ca.pem");
        std::fs::write(&ca_path, &ca.cert_pem).unwrap();

        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "key.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer.key_attestation.trusted_anchors.push(TrustAnchor {
            name: "wallet-provider-ca".to_string(),
            certs: "wallet-provider-ca.pem".to_string(),
        });

        cfg.validate_key_material(dir.path()).unwrap();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core key_attestation_trusted_anchor -- --nocapture`
Expected: compile error — `AttestationMode` has no field `trusted_anchors` yet.

- [ ] **Step 3: Add the field and validation**

In `crates/foundry-core/src/config/model.rs`, modify `AttestationMode`:

```rust
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AttestationMode {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub trusted_anchors: Vec<TrustAnchor>,
}
```

In `crates/foundry-core/src/config/validate.rs`, factor the existing trust-anchor loop into a helper and call it three times:

```rust
fn validate_trust_anchor_list(
    anchors: &[super::model::TrustAnchor],
    base_dir: &Path,
    label: &str,
) -> Result<(), ConfigError> {
    for anchor in anchors {
        let path = base_dir.join(&anchor.certs);
        let pem = std::fs::read(&path).map_err(|e| {
            ConfigError::Validation(format!(
                "{label} trust anchor '{}' {}: {e}",
                anchor.name,
                path.display()
            ))
        })?;
        crate::trust::parse_cert_pem(&pem).map_err(|e| {
            ConfigError::Validation(format!("{label} trust anchor '{}': {e}", anchor.name))
        })?;
    }
    Ok(())
}
```

Replace the existing inline loop at the end of `validate_key_material` with:

```rust
        validate_trust_anchor_list(&self.trust_anchors, base_dir, "top-level")?;
        validate_trust_anchor_list(
            &self.issuer.wallet_attestation.trusted_anchors,
            base_dir,
            "issuer.wallet_attestation",
        )?;
        validate_trust_anchor_list(
            &self.issuer.key_attestation.trusted_anchors,
            base_dir,
            "issuer.key_attestation",
        )?;

        Ok(())
    }
}
```

(Remove the old `for anchor in &self.trust_anchors { ... }` block it replaces.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core key_attestation_trusted_anchor -- --nocapture`
Expected: both tests still fail to compile — the whole workspace now has ~14 `AttestationMode { mode: ... }` literals missing the new field. Proceed to Step 5 before re-running.

- [ ] **Step 5: Mechanical fixup of every existing `AttestationMode { ... }` literal**

Run to enumerate every remaining compile error:

```bash
cargo build --workspace 2>&1 | grep -B1 "missing field \`trusted_anchors\`"
```

For **every** file below, find each `AttestationMode { mode: <expr> }` (or
`AttestationMode { mode: <expr>, }`) literal and change it to
`AttestationMode { mode: <expr>, trusted_anchors: Vec::new() }` (add the
field as the second line, comma-separated). Do not change anything else in
these files. Known affected files (confirmed via
`grep -rln "AttestationMode {" crates --include=*.rs`, excluding
`model.rs` itself which defines the struct):

```
crates/foundry/tests/openapi_endpoints.rs
crates/foundry/tests/authorization_code_flow.rs
crates/foundry/tests/health.rs
crates/foundry/tests/wallet_issuance.rs
crates/foundry/tests/wallet_verification.rs
crates/foundry/tests/wallet_metadata.rs
crates/foundry/tests/console.rs
crates/foundry/tests/issuer_offers.rs
crates/foundry/tests/wallet_status_list_route.rs
crates/foundry-wallet/tests/support/mod.rs
crates/foundry-issuer/src/create_offer.rs
crates/foundry-issuer/src/metadata.rs
crates/foundry-issuer/src/credential.rs
crates/foundry-verifier/src/verify.rs
```

After editing, re-run:

```bash
cargo build --workspace 2>&1 | tail -20
```

Expected: exit clean (no `missing field` errors remain). If any remain, the
grep above missed an occurrence — repeat until clean.

- [ ] **Step 6: Run the Task 1 tests to verify they pass**

Run: `cargo test -p foundry-core key_attestation_trusted_anchor -- --nocapture`
Expected: both tests PASS.

Run: `cargo test --workspace 2>&1 | tail -30`
Expected: no regressions (every pre-existing test still passes — this step
touched only struct literals, not behavior).

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-core/src/config/model.rs crates/foundry-core/src/config/validate.rs \
  crates/foundry/tests/openapi_endpoints.rs crates/foundry/tests/authorization_code_flow.rs \
  crates/foundry/tests/health.rs crates/foundry/tests/wallet_issuance.rs \
  crates/foundry/tests/wallet_verification.rs crates/foundry/tests/wallet_metadata.rs \
  crates/foundry/tests/console.rs crates/foundry/tests/issuer_offers.rs \
  crates/foundry/tests/wallet_status_list_route.rs crates/foundry-wallet/tests/support/mod.rs \
  crates/foundry-issuer/src/create_offer.rs crates/foundry-issuer/src/metadata.rs \
  crates/foundry-issuer/src/credential.rs crates/foundry-verifier/src/verify.rs
git commit -m "feat(config): add issuer.key_attestation.trusted_anchors"
```

---

### Task 2: Key-attestation JWT verification (`attestation.rs`)

**Files:**
- Modify: `crates/foundry-issuer/src/attestation.rs`
- Test: `crates/foundry-issuer/src/attestation.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: `foundry_core::trust::{TrustStore, validate_chain, x5c_entry_to_pem, parse_cert_pem}`, `foundry_core::pki::{new_ca, issue_leaf}` (tests only), `foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer}` (tests only), `josekit::jwk::Jwk`.
- Produces: `pub struct KeyAttestationClaims { pub attested_keys: Vec<josekit::jwk::Jwk> }`; `pub fn verify_key_attestation_jwt(key_attestation_jwt: &str, trust_store: &foundry_core::trust::TrustStore, expected_c_nonce: &str, now_unix: i64) -> Result<KeyAttestationClaims, IssuanceError>`.

- [ ] **Step 1: Write the failing tests**

Add to `crates/foundry-issuer/src/attestation.rs` (append to the existing
`#[cfg(test)] mod tests` block — do not create a second one):

```rust
    use super::{verify_key_attestation_jwt, KeyAttestationClaims};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::TrustStore;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::KeyPair as _;

    /// Builds a signed key-attestation JWT whose leaf cert chains to `ca`.
    /// Returns (jwt, ca_cert_pem) so the caller can build a matching TrustStore.
    fn signed_key_attestation(
        nonce: &str,
        exp: i64,
        attested_keys: Vec<serde_json::Value>,
    ) -> (String, String) {
        let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "wallet-provider.example.com",
            &["wallet-provider.example.com".to_string()],
            365,
        )
        .unwrap();
        let leaf_der = {
            let cert = foundry_core::trust::parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
            use x509_cert::der::Encode;
            cert.to_der().unwrap()
        };
        let x5c = vec![base64::engine::general_purpose::STANDARD.encode(&leaf_der)];

        let header = serde_json::json!({
            "typ": "key-attestation+jwt",
            "alg": "ES256",
            "x5c": x5c,
        });
        let payload = serde_json::json!({
            "iss": "https://wallet-provider.example.com",
            "iat": 1_700_000_000,
            "exp": exp,
            "nonce": nonce,
            "attested_keys": attested_keys,
        });
        let header_b64 = B64URL.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = B64URL.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signer = FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let sig = signer.sign(signing_input.as_bytes()).unwrap();
        let sig_b64 = B64URL.encode(sig);

        (format!("{signing_input}.{sig_b64}"), ca.cert_pem)
    }

    fn sample_jwk() -> serde_json::Value {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut jwk = kp.to_jwk_public_key();
        jwk.set_algorithm("ES256");
        serde_json::to_value(&jwk).unwrap()
    }

    #[test]
    fn verifies_valid_key_attestation_and_returns_attested_keys() {
        let (jwt, ca_pem) = signed_key_attestation(
            "nonce-abc",
            1_800_000_000,
            vec![sample_jwk(), sample_jwk()],
        );
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let claims = verify_key_attestation_jwt(&jwt, &store, "nonce-abc", 1_700_000_100).unwrap();
        assert_eq!(claims.attested_keys.len(), 2);
    }

    #[test]
    fn rejects_nonce_mismatch() {
        let (jwt, ca_pem) = signed_key_attestation("nonce-abc", 1_800_000_000, vec![sample_jwk()]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, "wrong-nonce", 1_700_000_100).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_expired_attestation() {
        let (jwt, ca_pem) = signed_key_attestation("nonce-abc", 1_600_000_000, vec![sample_jwk()]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, "nonce-abc", 1_700_000_100).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_untrusted_chain() {
        let (jwt, _ca_pem) =
            signed_key_attestation("nonce-abc", 1_800_000_000, vec![sample_jwk()]);
        let other_ca = new_ca("Some Other Root CA", 3650).unwrap();
        let store = TrustStore::from_pems(&[other_ca.cert_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, "nonce-abc", 1_700_000_100).unwrap_err();
        assert!(matches!(err, IssuanceError::Trust(_)) || matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_empty_attested_keys() {
        let (jwt, ca_pem) = signed_key_attestation("nonce-abc", 1_800_000_000, vec![]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, "nonce-abc", 1_700_000_100).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p foundry-issuer attestation:: -- --nocapture`
Expected: FAIL to compile — `verify_key_attestation_jwt`/`KeyAttestationClaims` don't exist yet.

- [ ] **Step 3: Implement `verify_key_attestation_jwt`**

Add to `crates/foundry-issuer/src/attestation.rs` (above the existing
`#[cfg(test)]` module), alongside the existing imports (extend the `use`
list at the top of the file):

```rust
use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use foundry_core::trust::{validate_chain, x5c_entry_to_pem, TrustStore};
use josekit::jwk::Jwk;
use josekit::jws::ES256;

/// The `attested_keys` a verified key attestation vouches for.
#[derive(Debug, Clone)]
pub struct KeyAttestationClaims {
    pub attested_keys: Vec<Jwk>,
}

/// Verify a key-attestation JWT (OpenID4VCI Appendix D.1) against `trust_store`
/// (the issuer's configured Wallet-Provider CAs), binding it to the current
/// `c_nonce` per Appendix F.1's `key_attestation` header rule.
pub fn verify_key_attestation_jwt(
    key_attestation_jwt: &str,
    trust_store: &TrustStore,
    expected_c_nonce: &str,
    now_unix: i64,
) -> Result<KeyAttestationClaims, IssuanceError> {
    let parts: Vec<&str> = key_attestation_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidProof(
            "key_attestation: invalid JWS format, expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL.decode(parts[0]).map_err(|e| {
        IssuanceError::InvalidProof(format!("key_attestation: invalid base64url header: {e}"))
    })?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| {
        IssuanceError::InvalidProof(format!("key_attestation: invalid header JSON: {e}"))
    })?;

    let typ = header.get("typ").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidProof("key_attestation: missing typ header".into())
    })?;
    if typ != "key-attestation+jwt" {
        return Err(IssuanceError::InvalidProof(format!(
            "key_attestation: invalid typ header: {typ}, expected key-attestation+jwt"
        )));
    }

    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidProof("key_attestation: missing alg header".into())
    })?;
    if alg == "none" || alg.starts_with("HS") {
        return Err(IssuanceError::InvalidProof(format!(
            "key_attestation: alg '{alg}' is not permitted (must not be none or symmetric)"
        )));
    }

    let x5c = header
        .get("x5c")
        .and_then(|v| v.as_array())
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("key_attestation: header has no x5c chain".into())
        })?;
    let leaf_b64 = x5c[0].as_str().ok_or_else(|| {
        IssuanceError::InvalidProof("key_attestation: x5c[0] is not a string".into())
    })?;
    let leaf_pem = x5c_entry_to_pem(leaf_b64)?;
    let intermediates: Vec<Vec<u8>> = x5c[1..]
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|s| x5c_entry_to_pem(s).ok())
        .collect();

    let leaf_cert = foundry_core::trust::parse_cert_pem(&leaf_pem)?;
    use x509_cert::der::Encode;
    let spki_der = leaf_cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| {
            IssuanceError::InvalidProof(format!(
                "key_attestation: failed to re-encode leaf public key: {e}"
            ))
        })?;
    let mut spki_pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    let spki_b64 = B64STD.encode(&spki_der);
    for chunk in spki_b64.as_bytes().chunks(64) {
        spki_pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        spki_pem.push('\n');
    }
    spki_pem.push_str("-----END PUBLIC KEY-----\n");

    let verifier = ES256.verifier_from_pem(spki_pem.as_bytes()).map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "key_attestation: unable to build verifier from leaf cert: {e}"
        ))
    })?;
    josekit::jwt::decode_with_verifier(key_attestation_jwt, &verifier).map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "key_attestation: signature verification failed: {e}"
        ))
    })?;

    validate_chain(&leaf_pem, &intermediates, trust_store, now_unix as u64)?;

    let payload_bytes = B64URL.decode(parts[1]).map_err(|e| {
        IssuanceError::InvalidProof(format!("key_attestation: invalid base64url payload: {e}"))
    })?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        IssuanceError::InvalidProof(format!("key_attestation: invalid payload JSON: {e}"))
    })?;

    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidProof("key_attestation: missing exp claim".into())
    })?;
    if now_unix > exp {
        return Err(IssuanceError::InvalidProof(
            "key_attestation: has expired".into(),
        ));
    }

    let nonce = payload.get("nonce").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidProof("key_attestation: missing nonce claim".into())
    })?;
    if nonce != expected_c_nonce {
        return Err(IssuanceError::InvalidProof(format!(
            "key_attestation: nonce mismatch: got {nonce}, expected {expected_c_nonce}"
        )));
    }

    let attested_keys_json = payload
        .get("attested_keys")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            IssuanceError::InvalidProof(
                "key_attestation: missing or empty attested_keys claim".into(),
            )
        })?;

    let mut attested_keys = Vec::with_capacity(attested_keys_json.len());
    for jwk_val in attested_keys_json {
        let jwk: Jwk = serde_json::from_value(jwk_val.clone()).map_err(|e| {
            IssuanceError::InvalidProof(format!("key_attestation: invalid attested key JWK: {e}"))
        })?;
        attested_keys.push(jwk);
    }

    Ok(KeyAttestationClaims { attested_keys })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p foundry-issuer attestation:: -- --nocapture`
Expected: all 5 new tests PASS, plus the pre-existing
`attestation_mode_required_checks_presence` test still passes.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-issuer/src/attestation.rs
git commit -m "feat(issuer): verify key-attestation JWTs (OpenID4VCI Appendix D.1)"
```

---

### Task 3: `jwk`/`kid`/`x5c` header branching in `proof.rs`

**Files:**
- Modify: `crates/foundry-issuer/src/proof.rs`
- Test: `crates/foundry-issuer/src/proof.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: `crate::attestation::{verify_key_attestation_jwt, KeyAttestationClaims}` (Task 2); `foundry_core::config::Mode`; `foundry_core::trust::TrustStore`.
- Produces: `verify_holder_proof(jwt_str: &str, expected_issuer: &str, expected_c_nonce: &str, c_nonce_expires_at: i64, now_unix: i64, key_attestation_mode: foundry_core::config::Mode, key_attestation_trust_store: &foundry_core::trust::TrustStore) -> Result<VerifiedProof, IssuanceError>` (two new trailing parameters).

- [ ] **Step 1: Write the failing tests**

Replace the existing `#[cfg(test)] mod tests` block in
`crates/foundry-issuer/src/proof.rs` — keep the existing two tests
(`verifies_valid_proof_jwt`, `rejects_mismatched_nonce`) but update their
calls to pass the two new trailing arguments, and add new tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::config::Mode;
    use foundry_core::trust::TrustStore;
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

    /// Builds a valid key attestation whose sole attested key is `holder_pub_jwk`
    /// (so the caller can sign the outer proof with the matching private key).
    fn valid_key_attestation(
        nonce: &str,
        holder_pub_jwk: &serde_json::Value,
    ) -> (String, foundry_core::trust::TrustStore) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use base64::Engine as _;
        use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
        use foundry_core::pki::{issue_leaf, new_ca};

        let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "wallet-provider.example.com",
            &["wallet-provider.example.com".to_string()],
            365,
        )
        .unwrap();
        let leaf_der = {
            let cert = foundry_core::trust::parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
            use x509_cert::der::Encode;
            cert.to_der().unwrap()
        };
        let x5c = vec![base64::engine::general_purpose::STANDARD.encode(&leaf_der)];

        let header = serde_json::json!({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c});
        let payload = serde_json::json!({
            "iss": "https://wallet-provider.example.com",
            "iat": 1_700_000_000,
            "exp": 1_800_000_000,
            "nonce": nonce,
            "attested_keys": [holder_pub_jwk],
        });
        let header_b64 = B64URL.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = B64URL.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signer =
            FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let sig_b64 = B64URL.encode(signer.sign(signing_input.as_bytes()).unwrap());
        let jwt = format!("{signing_input}.{sig_b64}");

        let store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        (jwt, store)
    }

    #[test]
    fn verifies_valid_proof_jwt() {
        let jwt_str = signed_proof_jwt("https://issuer.example.com", "nonce-123");
        let empty_store = TrustStore::from_pems(&[]).unwrap();

        let res = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
            Mode::Optional,
            &empty_store,
        )
        .unwrap();

        assert_eq!(res.holder_jwk.key_type(), "EC");
    }

    #[test]
    fn rejects_mismatched_nonce() {
        let jwt_str = signed_proof_jwt("https://issuer.example.com", "wrong-nonce");
        let empty_store = TrustStore::from_pems(&[]).unwrap();

        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
            Mode::Optional,
            &empty_store,
        )
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn accepts_kid_plus_key_attestation_proof() {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut holder_pub = keypair.to_jwk_public_key();
        holder_pub.set_algorithm("ES256");
        let holder_pub_json = serde_json::to_value(&holder_pub).unwrap();

        let (attestation_jwt, store) = valid_key_attestation("nonce-123", &holder_pub_json);

        // Sign the outer proof with the SAME key that's listed in attested_keys[0].
        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header.set_claim("kid", Some(serde_json::json!("0"))).unwrap();
        header
            .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
            .unwrap();
        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!("nonce-123")))
            .unwrap();
        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let res = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
            Mode::Required,
            &store,
        )
        .unwrap();

        assert_eq!(res.holder_jwk.key_type(), "EC");
    }

    #[test]
    fn rejects_kid_without_key_attestation() {
        // A `kid` header with no accompanying `key_attestation` claim at all.
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header.set_claim("kid", Some(serde_json::json!("0"))).unwrap();
        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!("nonce-123")))
            .unwrap();
        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let no_attestation_jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let empty_store = TrustStore::from_pems(&[]).unwrap();
        let err = verify_holder_proof(
            &no_attestation_jwt,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
            Mode::Optional,
            &empty_store,
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_jwk_proof_when_key_attestation_required() {
        let jwt_str = signed_proof_jwt("https://issuer.example.com", "nonce-123");
        let empty_store = TrustStore::from_pems(&[]).unwrap();

        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
            Mode::Required,
            &empty_store,
        )
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_kid_attestation_proof_when_key_attestation_disabled() {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut holder_pub = keypair.to_jwk_public_key();
        holder_pub.set_algorithm("ES256");
        let holder_pub_json = serde_json::to_value(&holder_pub).unwrap();
        let (attestation_jwt, store) = valid_key_attestation("nonce-123", &holder_pub_json);

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header.set_claim("kid", Some(serde_json::json!("0"))).unwrap();
        header
            .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
            .unwrap();
        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!("nonce-123")))
            .unwrap();
        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
            Mode::Disabled,
            &store,
        )
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p foundry-issuer proof:: -- --nocapture`
Expected: FAIL to compile — `verify_holder_proof` doesn't yet accept the two
new parameters.

- [ ] **Step 3: Implement the branching**

Replace the current `jwk`-only block in `verify_holder_proof` (the section
starting at `let jwk_val = header.claim("jwk")...` through
`let verifier = ES256.verifier_from_jwk(&jwk)...`) with:

```rust
    let jwk_claim = header.claim("jwk");
    let kid_claim = header.claim("kid");
    let x5c_claim = header.claim("x5c");
    let key_attestation_claim = header.claim("key_attestation");

    let present_count = [jwk_claim.is_some(), kid_claim.is_some(), x5c_claim.is_some()]
        .iter()
        .filter(|p| **p)
        .count();
    if present_count != 1 {
        return Err(IssuanceError::InvalidProof(
            "exactly one of jwk, kid, x5c header claims is required".into(),
        ));
    }

    let jwk: Jwk = if let Some(jwk_val) = jwk_claim {
        if key_attestation_mode == Mode::Required {
            return Err(IssuanceError::InvalidProof(
                "key attestation is required for this credential type".into(),
            ));
        }
        serde_json::from_value(jwk_val.clone())
            .map_err(|e| IssuanceError::InvalidProof(format!("invalid jwk in proof header: {e}")))?
    } else if let Some(kid_val) = kid_claim {
        let key_attestation_jwt = key_attestation_claim
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                IssuanceError::InvalidProof(
                    "kid header without key_attestation is not supported".into(),
                )
            })?;

        if key_attestation_mode == Mode::Disabled {
            return Err(IssuanceError::InvalidProof(
                "key attestation is disabled by issuer configuration".into(),
            ));
        }

        let kid_str = kid_val
            .as_str()
            .ok_or_else(|| IssuanceError::InvalidProof("kid header must be a string".into()))?;
        let kid_index: usize = kid_str.parse().map_err(|_| {
            IssuanceError::InvalidProof("kid header must be a valid attested-key index".into())
        })?;

        let claims = crate::attestation::verify_key_attestation_jwt(
            key_attestation_jwt,
            key_attestation_trust_store,
            expected_c_nonce,
            now_unix,
        )?;

        claims
            .attested_keys
            .get(kid_index)
            .cloned()
            .ok_or_else(|| {
                IssuanceError::InvalidProof("kid index out of bounds for attested_keys".into())
            })?
    } else {
        return Err(IssuanceError::InvalidProof(
            "x5c header for the jwt proof type is not yet supported".into(),
        ));
    };

    let verifier = ES256.verifier_from_jwk(&jwk).map_err(|e| {
        IssuanceError::InvalidProof(format!("unable to create verifier from jwk: {e}"))
    })?;
```

(This assumes `key_attestation_mode: Mode` and
`key_attestation_trust_store: &TrustStore` are new parameters — see next
edit — and that the function's final `Ok(VerifiedProof { holder_jwk: jwk })`
line is unchanged, since `jwk` is still the resolved key's name.)

Update the function signature and imports at the top of the file:

```rust
use foundry_core::config::Mode;
use foundry_core::trust::TrustStore;
```

```rust
pub fn verify_holder_proof(
    jwt_str: &str,
    expected_issuer: &str,
    expected_c_nonce: &str,
    c_nonce_expires_at: i64,
    now_unix: i64,
    key_attestation_mode: Mode,
    key_attestation_trust_store: &TrustStore,
) -> Result<VerifiedProof, IssuanceError> {
```

(`Mode` needs `PartialEq`/`Eq` — confirm it already derives them in
`foundry-core::config::model` before proceeding; it does per the existing
`#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]` on `Mode`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p foundry-issuer proof:: -- --nocapture`
Expected: all tests PASS (7 total: the 2 original plus 5 new).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-issuer/src/proof.rs
git commit -m "feat(issuer): support kid+key_attestation proofs alongside jwk"
```

---

### Task 4: Wire `credential.rs` — build the trust store, pass mode through

**Files:**
- Modify: `crates/foundry-issuer/src/credential.rs`

**Interfaces:**
- Consumes: `verify_holder_proof`'s new signature (Task 3);
  `foundry_core::trust::TrustStore::from_config`.
- Produces: `handle_credential_request` unchanged externally (same
  `CredentialRequest`/`CredentialResponse` shapes).

- [ ] **Step 1: Update the existing test's config and add a new one**

The existing `test_config()` helper in `credential.rs` already needs its
`AttestationMode` literals fixed per Task 1 Step 5 — confirm that landed.
Add one new test to the existing `#[cfg(test)] mod tests` block:

```rust
    #[tokio::test]
    async fn issues_credential_with_kid_key_attestation_proof() {
        use foundry_core::pki::{issue_leaf, new_ca};
        use foundry_core::trust::parse_cert_pem;
        use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
        use josekit::jwk::KeyPair as _;
        use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
        use base64::Engine as _;

        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        // Wallet Provider CA that will be configured as a trusted anchor.
        let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "wallet-provider.example.com",
            &["wallet-provider.example.com".to_string()],
            365,
        )
        .unwrap();
        let ca_path = key_dir.path().join("wallet-provider-ca.pem");
        std::fs::write(&ca_path, &ca.cert_pem).unwrap();

        let mut config = test_config(key_path.to_str().unwrap());
        config.issuer.key_attestation.mode = Mode::Required;
        config.issuer.key_attestation.trusted_anchors = vec![foundry_core::config::TrustAnchor {
            name: "wallet-provider-ca".to_string(),
            certs: "wallet-provider-ca.pem".to_string(),
        }];

        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));

        let tx = IssuanceTransaction {
            transaction_id: "tx-cred-2".to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: Some("code-456".to_string()),
            tx_code: None,
            status_list_index: None,
            access_token: Some("at_secret_456".to_string()),
            c_nonce: Some("cn_nonce_456".to_string()),
            c_nonce_expires_at: Some(1_700_000_600),
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        // Build a key attestation whose sole attested key matches the outer proof's signer.
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut holder_pub = keypair.to_jwk_public_key();
        holder_pub.set_algorithm("ES256");

        let leaf_der = {
            let cert = parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
            use x509_cert::der::Encode;
            cert.to_der().unwrap()
        };
        let x5c = vec![B64STD.encode(&leaf_der)];
        let attestation_header =
            serde_json::json!({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c});
        let attestation_payload = serde_json::json!({
            "iss": "https://wallet-provider.example.com",
            "iat": 1_700_000_000,
            "exp": 1_800_000_000,
            "nonce": "cn_nonce_456",
            "attested_keys": [serde_json::to_value(&holder_pub).unwrap()],
        });
        let h_b64 = B64URL.encode(serde_json::to_vec(&attestation_header).unwrap());
        let p_b64 = B64URL.encode(serde_json::to_vec(&attestation_payload).unwrap());
        let signing_input = format!("{h_b64}.{p_b64}");
        let leaf_signer =
            foundry_core::crypto::FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256)
                .unwrap();
        let sig_b64 =
            B64URL.encode(foundry_core::crypto::Signer::sign(&leaf_signer, signing_input.as_bytes()).unwrap());
        let attestation_jwt = format!("{signing_input}.{sig_b64}");

        let mut proof_header = JwsHeader::new();
        proof_header.set_token_type("openid4vci-proof+jwt");
        proof_header
            .set_claim("kid", Some(serde_json::json!("0")))
            .unwrap();
        proof_header
            .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
            .unwrap();
        let mut proof_payload = JwtPayload::new();
        proof_payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        proof_payload
            .set_claim("nonce", Some(serde_json::json!("cn_nonce_456")))
            .unwrap();
        let private_jwk = keypair.to_jwk_private_key();
        let proof_signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let proof_jwt = jwt::encode_with_signer(&proof_payload, &proof_header, &proof_signer).unwrap();

        let req = CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proofs: Some(ProofsRequest { jwt: vec![proof_jwt] }),
        };

        let res =
            handle_credential_request(&config, &storage, "at_secret_456", &req, 1_700_000_010)
                .await
                .unwrap();

        assert_eq!(res.credentials.len(), 1);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p foundry-issuer credential:: issues_credential_with_kid_key_attestation_proof -- --nocapture`
Expected: FAIL to compile — `verify_holder_proof` call site inside
`handle_credential_request` doesn't pass the two new arguments yet.

- [ ] **Step 3: Wire the trust store through**

In `handle_credential_request`, before the `let verified_proofs = ...` block,
add:

```rust
    let key_attestation_trust_store =
        foundry_core::trust::TrustStore::from_config(&config.issuer.key_attestation.trusted_anchors)?;
```

Update the `verify_holder_proof` call inside the `.map(...)` closure to pass
the two new arguments:

```rust
    let verified_proofs = proof_jwts
        .iter()
        .map(|jwt_str| {
            verify_holder_proof(
                jwt_str,
                &config.issuer.credential_issuer,
                c_nonce,
                c_nonce_expires_at,
                now_unix,
                config.issuer.key_attestation.mode.clone(),
                &key_attestation_trust_store,
            )
        })
        .collect::<Result<Vec<_>, IssuanceError>>()?;
```

(`IssuanceError` must convert from `foundry_core::error::TrustError` — it
already does via the existing `#[from]` variant, so `?` on
`TrustStore::from_config` works unmodified.)

- [ ] **Step 4: Run all `credential.rs` tests to verify they pass**

Run: `cargo test -p foundry-issuer credential:: -- --nocapture`
Expected: all tests PASS, including the pre-existing
`issues_sd_jwt_vc_credential_successfully` (which uses `Mode::Optional` and a
`jwk` proof — must still work unchanged) and the new
`issues_credential_with_kid_key_attestation_proof`.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-issuer/src/credential.rs
git commit -m "feat(issuer): wire key-attestation trust store into credential handling"
```

---

### Task 5: `key_attestations_required` in issuer metadata

**Files:**
- Modify: `crates/foundry-issuer/src/metadata.rs`

**Interfaces:**
- Consumes: `cfg.issuer.key_attestation.mode` (existing field).
- Produces: `ProofTypeSupported.key_attestations_required: Option<serde_json::Value>`.

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` block in `metadata.rs`:

```rust
    #[test]
    fn key_attestations_required_present_when_mode_required() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.mode = Mode::Required;
        let meta = build_issuer_metadata(&cfg);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let jwt_proof = pid.proof_types_supported.get("jwt").unwrap();
        assert_eq!(
            jwt_proof.key_attestations_required,
            Some(serde_json::json!({}))
        );
    }

    #[test]
    fn key_attestations_required_absent_when_mode_optional_or_disabled() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.mode = Mode::Optional;
        let meta = build_issuer_metadata(&cfg);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(
            pid.proof_types_supported.get("jwt").unwrap().key_attestations_required,
            None
        );

        cfg.issuer.key_attestation.mode = Mode::Disabled;
        let meta = build_issuer_metadata(&cfg);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(
            pid.proof_types_supported.get("jwt").unwrap().key_attestations_required,
            None
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p foundry-issuer metadata::tests::key_attestations_required -- --nocapture`
Expected: FAIL to compile — `ProofTypeSupported` has no field
`key_attestations_required` yet.

- [ ] **Step 3: Implement**

Modify `ProofTypeSupported`:

```rust
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub key_attestations_required: Option<serde_json::Value>,
}
```

In `build_issuer_metadata`, where `proof_types_supported` is constructed,
change:

```rust
                proof_types_supported: BTreeMap::from([(
                    "jwt".to_string(),
                    ProofTypeSupported {
                        proof_signing_alg_values_supported: vec!["ES256".to_string()],
                    },
                )]),
```

to:

```rust
                proof_types_supported: BTreeMap::from([(
                    "jwt".to_string(),
                    ProofTypeSupported {
                        proof_signing_alg_values_supported: vec!["ES256".to_string()],
                        key_attestations_required: if cfg.issuer.key_attestation.mode
                            != foundry_core::config::Mode::Disabled
                        {
                            Some(serde_json::json!({}))
                        } else {
                            None
                        },
                    },
                )]),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p foundry-issuer metadata:: -- --nocapture`
Expected: all tests PASS, including pre-existing
`builds_issuer_metadata_from_credential_types` (which uses `Mode::Optional`
by default per Task 1's fixup — must assert `key_attestations_required` is
`None` there too; if that pre-existing test doesn't already assert on this
field, no change needed since it only checks other fields).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-issuer/src/metadata.rs
git commit -m "feat(issuer): advertise key_attestations_required in issuer metadata"
```

---

### Task 6: End-to-end test + OpenAPI regeneration

**Files:**
- Modify: `crates/foundry/tests/wallet_issuance.rs`
- Modify (generated): `openapi.json`, `openapi-wallet.json`

**Interfaces:**
- Consumes: `setup_test_app`, `wallet_router`, `create_proof` (existing
  helpers in `wallet_issuance.rs`); `foundry_core::pki::{new_ca, issue_leaf}`.
- Produces: no new public interface — this task only adds test coverage and
  regenerates the OpenAPI specs to reflect Task 5's `key_attestations_required`
  field.

- [ ] **Step 1: Write the failing test**

Add to `crates/foundry/tests/wallet_issuance.rs`:

```rust
#[tokio::test]
async fn full_issuance_flow_with_kid_key_attestation_proof() {
    use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
    use base64::Engine as _;
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::parse_cert_pem;

    let (mut state, dir) = setup_test_app().await;

    // Configure a Wallet Provider trust anchor and require key attestation.
    let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "wallet-provider.example.com",
        &["wallet-provider.example.com".to_string()],
        365,
    )
    .unwrap();
    let ca_path = dir.path().join("wallet-provider-ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).unwrap();

    let mut config = (*state.config).clone();
    config.issuer.key_attestation.mode = foundry_core::config::Mode::Required;
    config.issuer.key_attestation.trusted_anchors = vec![foundry_core::config::TrustAnchor {
        name: "wallet-provider-ca".to_string(),
        certs: ca_path.to_str().unwrap().to_string(),
    }];
    state.config = Arc::new(config);

    let access_token = issue_offer_and_get_access_token(&state).await;
    let c_nonce = mint_c_nonce(&state, &access_token).await;

    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut holder_pub = keypair.to_jwk_public_key();
    holder_pub.set_algorithm("ES256");

    let leaf_der = {
        let cert = parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
        use x509_cert::der::Encode;
        cert.to_der().unwrap()
    };
    let x5c = vec![B64STD.encode(&leaf_der)];
    let attestation_header =
        serde_json::json!({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c});
    let attestation_payload = serde_json::json!({
        "iss": "https://wallet-provider.example.com",
        "iat": 1_700_000_000,
        "exp": 1_800_000_000,
        "nonce": c_nonce,
        "attested_keys": [serde_json::to_value(&holder_pub).unwrap()],
    });
    let h_b64 = B64URL.encode(serde_json::to_vec(&attestation_header).unwrap());
    let p_b64 = B64URL.encode(serde_json::to_vec(&attestation_payload).unwrap());
    let signing_input = format!("{h_b64}.{p_b64}");
    let leaf_signer = foundry_core::crypto::FileSigner::from_pem(
        leaf.key_pem.as_bytes(),
        foundry_core::crypto::SignatureAlgorithm::Es256,
    )
    .unwrap();
    let sig_b64 = B64URL.encode(
        foundry_core::crypto::Signer::sign(&leaf_signer, signing_input.as_bytes()).unwrap(),
    );
    let attestation_jwt = format!("{signing_input}.{sig_b64}");

    let mut proof_header = JwsHeader::new();
    proof_header.set_token_type("openid4vci-proof+jwt");
    proof_header.set_claim("kid", Some(serde_json::json!("0"))).unwrap();
    proof_header
        .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
        .unwrap();
    let mut proof_payload = JwtPayload::new();
    proof_payload
        .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
        .unwrap();
    proof_payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();
    let private_jwk = keypair.to_jwk_private_key();
    let proof_signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let proof_jwt = jwt::encode_with_signer(&proof_payload, &proof_header, &proof_signer).unwrap();

    let cred_req_body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });

    let wallet_app = wallet_router(state.clone());
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(cred_req_body.to_string()))
        .unwrap();

    let cred_res = wallet_app.oneshot(cred_req).await.unwrap();
    assert_eq!(cred_res.status(), StatusCode::OK);

    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();
    let credential_str = cred_json["credentials"][0]["credential"].as_str().unwrap();
    assert!(!credential_str.is_empty());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p foundry --test wallet_issuance full_issuance_flow_with_kid_key_attestation_proof -- --nocapture`
Expected: FAILS (or fails to compile) before Tasks 1–5 land in this branch —
if run after Tasks 1–5, this should already PASS since the underlying
capability was built incrementally. If Tasks 1–5 are already committed on
this branch (the expected order), this test should compile and pass
immediately; treat "run once to confirm PASS" as this step's success
criterion in that case, and only chase a genuine failure if one occurs.

- [ ] **Step 3: (If needed) fix any integration-level gap**

If the test fails despite Tasks 1–5 being complete, the failure is almost
certainly a wiring gap (e.g. `AppState.config` not being `Arc`-swappable as
assumed) — inspect the actual `AppState` definition in
`crates/foundry/src/server.rs` and adjust the test's config-mutation
approach (e.g. constructing the whole `Config` via `setup_test_app`'s
existing builder with the two new fields set from the start, instead of
mutating `state.config` after the fact) rather than changing production
code. Do not add new production code in this step — Tasks 1–5 already cover
the feature; this step is verification-only.

- [ ] **Step 4: Regenerate OpenAPI specs and verify**

Per `crates/foundry/AGENTS.md`, `serve()` overwrites both `openapi.json` and
`openapi-wallet.json` in the process working directory on every startup —
that is the documented mechanism for refreshing both files (the `openapi`
CLI subcommand only writes the admin spec, so it is not sufficient alone).
Run, from the repo root:

```bash
cargo test -p foundry --test e2e_full_flow -- --nocapture
```

This test boots the real compiled binary via `quickstart` then `serve` from
the repo root, which overwrites both spec files as a side effect. After it
passes, confirm both files actually changed and inspect the diff:

```bash
git status --porcelain openapi.json openapi-wallet.json
git diff openapi.json openapi-wallet.json
```

Expected: both files show a diff, and the *only* schema-level change is the
new `key_attestations_required` property on the `ProofTypeSupported` schema
object (present as `Option<Object>` — i.e. an optional, untyped JSON object
field) in both specs. If anything else changed, investigate before
committing — an unrelated diff here means something else in the workspace
drifted from its spec, which is out of scope for this plan to silently
carry along.

- [ ] **Step 5: Run the full gate**

```bash
cargo test --workspace 2>&1 | tail -40
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -40
cargo fmt --check
```

Expected: all three clean (zero failures, zero warnings, zero formatting
diffs).

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/tests/wallet_issuance.rs openapi.json openapi-wallet.json
git commit -m "test(foundry): kid+key_attestation end-to-end issuance flow; regen OpenAPI"
```

---

## Progress Log

Append one line per completed task: date, task, commit SHA.