# Credential Request and Response Encryption — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OpenID4VCI JWE encryption to the Credential Endpoint in both directions — decrypt `application/jwt` Credential Requests, encrypt Credential Responses to a wallet-supplied JWK — config-gated and default-off.

**Architecture:** Crypto primitives (`DecryptionKey`, `decrypt_compact`, a `kid`-aware `encrypt_compact`) land in `foundry-core::crypto::jwe`. Protocol policy (allowed `enc` values, `encryption_required`, §L960's request/response coupling) lands in `foundry-issuer` inside `handle_credential_request`. HTTP shape (the `Content-Type` switch, 415, the `application/jwt` response body) lands in a new `crates/foundry/src/extract.rs`. Keys load once at startup from the existing `keys:` map; `kid`s are RFC 7638 thumbprints.

**Tech Stack:** Rust 2021 · axum 0.7.9 · josekit 0.10.3 (`ECDH_ES`, `EcKeyPair`) · serde / serde_yaml · utoipa 4 · async-trait 0.1

**Design:** [`docs/superpowers/specs/2026-08-04-credential-request-response-encryption-design.md`](../specs/2026-08-04-credential-request-response-encryption-design.md)

## Global Constraints

- **Specs are normative.** OpenID4VCI 1.0 in `docs/specs/openid-4-verifiable-credential-issuance-1_0.md`. Relevant lines: L848, L853–856, L871–875 (Credential Request), L960, L969 (Credential Response), L1183–L1192 (Encrypted Messages), L1373–L1381 (Credential Issuer Metadata). Every new protocol branch carries a comment naming the spec and line — root `AGENTS.md` §4.4.
- **No panics in request paths.** No `.unwrap()`, `.expect()`, `panic!()`, `unreachable!()` in `foundry-core/src`, `foundry-issuer/src`, `foundry/src`. Permitted only under `#[cfg(test)]` and in `tests/`. Root `AGENTS.md` §4.1.
- **`#[tracing::instrument]` MUST carry `skip_all`.** Enforced by `crates/foundry/tests/instrumentation_hygiene.rs`. Root `AGENTS.md` §4.5.
- **Never logged, at any level, under any flag:** the raw compact JWE request body, the decrypted Credential Request JSON, the plaintext `CredentialResponse` when encryption was requested, the wallet's `credential_response_encryption.jwk`, the loaded private decryption JWKs. Public keys appear only as RFC 7638 thumbprints.
- **Exactly one log record per typed error**, emitted in its error mapper.
- **Algorithm surface is fixed:** `alg` = `ECDH-ES` only; `enc` ∈ `{A128GCM, A256GCM}`; `zip` unsupported and `zip_values_supported` omitted from metadata.
- **Default-off.** With `issuer.request_encryption` and `issuer.response_encryption` both absent, the metadata document must be byte-identical to today's and `/credential` behaviour unchanged.
- **Scoped gate per task** (root `AGENTS.md` §5.1): `cargo test -p <touched>` plus dependents per §5.2, `cargo clippy -p <touched> --all-targets -- -D warnings`, `cargo fmt --check`. **Do NOT run `cargo test --workspace` per task.** The full gate runs once, in Task 9.
- **Three signature changes cause mechanical churn** (`build_issuer_metadata`, `handle_credential_request`, `CredentialRequest` literals). They are scheduled in Tasks 3 and 4 with exact verification commands. Do not defer them.

---

### Task 1: `DecryptionKey`, `decrypt_compact`, and a `kid`-aware `encrypt_compact`

**Files:**
- Modify: `crates/foundry-core/src/crypto/jwe.rs`

**Interfaces:**
- Consumes: `foundry_core::obs::thumbprint_bytes`, `crate::error::CryptoError`, `josekit::jwk::alg::ec::EcKeyPair`, `josekit::jwk::KeyPair`.
- Produces:
  - `pub struct DecryptionKey` with `from_pem(&[u8]) -> Result<Self, CryptoError>`, `from_pem_file(&str) -> Result<Self, CryptoError>`, `kid(&self) -> &str`, `published_jwk(&self) -> serde_json::Value`
  - `pub fn decrypt_compact(jwe: &str, keys: &[DecryptionKey], allowed_enc: &[String]) -> Result<serde_json::Value, CryptoError>`
  - `pub fn encrypt_compact_with_kid(payload: &Value, recipient_public_jwk: &Value, alg: &str, enc: &str, kid: Option<&str>) -> Result<String, CryptoError>`
  - `encrypt_compact` keeps its existing 4-argument signature and delegates with `kid = None`

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` in `crates/foundry-core/src/crypto/jwe.rs` (it already imports `EcCurve`, `EcKeyPair`, `KeyPair as _`, `Jwk`, `json` and defines `annotated_public_and_bare_private()`):

```rust
    fn test_decryption_key() -> DecryptionKey {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        DecryptionKey::from_pem(&kp.to_pem_private_key()).unwrap()
    }

    fn both_gcm() -> Vec<String> {
        vec!["A128GCM".to_string(), "A256GCM".to_string()]
    }

    #[test]
    fn kid_is_the_rfc7638_thumbprint_of_the_public_jwk() {
        let key = test_decryption_key();
        let published = key.published_jwk();
        assert_eq!(key.kid(), crate::obs::thumbprint(&published));
        assert_eq!(published["kid"], json!(key.kid()));
        assert_eq!(published["use"], json!("enc"));
        assert_eq!(published["alg"], json!("ECDH-ES"));
    }

    #[test]
    fn round_trips_an_encrypted_credential_request() {
        let key = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "credential_configuration_id": "pid" }),
            &key.published_jwk(),
            "ECDH-ES",
            "A128GCM",
            Some(key.kid()),
        )
        .unwrap();
        let out = decrypt_compact(&jwe, std::slice::from_ref(&key), &both_gcm()).unwrap();
        assert_eq!(out["credential_configuration_id"], json!("pid"));
    }

    #[test]
    fn selects_the_right_key_from_several() {
        let k1 = test_decryption_key();
        let k2 = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "a": 1 }),
            &k2.published_jwk(),
            "ECDH-ES",
            "A256GCM",
            Some(k2.kid()),
        )
        .unwrap();
        let keys = vec![k1, k2];
        assert_eq!(decrypt_compact(&jwe, &keys, &both_gcm()).unwrap()["a"], json!(1));
    }

    #[test]
    fn rejects_a_missing_kid() {
        let key = test_decryption_key();
        let jwe =
            encrypt_compact(&json!({ "a": 1 }), &key.published_jwk(), "ECDH-ES", "A128GCM").unwrap();
        let err = decrypt_compact(&jwe, std::slice::from_ref(&key), &both_gcm()).unwrap_err();
        assert!(err.to_string().contains("kid"), "got: {err}");
    }

    #[test]
    fn rejects_an_unknown_kid() {
        let k1 = test_decryption_key();
        let k2 = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "a": 1 }),
            &k2.published_jwk(),
            "ECDH-ES",
            "A128GCM",
            Some(k2.kid()),
        )
        .unwrap();
        let err = decrypt_compact(&jwe, std::slice::from_ref(&k1), &both_gcm()).unwrap_err();
        assert!(err.to_string().contains("kid"), "got: {err}");
    }

    #[test]
    fn rejects_an_unsupported_enc() {
        let key = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "a": 1 }),
            &key.published_jwk(),
            "ECDH-ES",
            "A256GCM",
            Some(key.kid()),
        )
        .unwrap();
        let only_128 = vec!["A128GCM".to_string()];
        let err = decrypt_compact(&jwe, std::slice::from_ref(&key), &only_128).unwrap_err();
        assert!(err.to_string().contains("A256GCM"), "got: {err}");
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "a": 1 }),
            &key.published_jwk(),
            "ECDH-ES",
            "A128GCM",
            Some(key.kid()),
        )
        .unwrap();
        let mut parts: Vec<String> = jwe.split('.').map(|s| s.to_string()).collect();
        parts[3].push('A');
        let broken = parts.join(".");
        assert!(decrypt_compact(&broken, std::slice::from_ref(&key), &both_gcm()).is_err());
    }

    #[test]
    fn rejects_a_non_compact_input() {
        let key = test_decryption_key();
        let err = decrypt_compact("not.a.jwe", std::slice::from_ref(&key), &both_gcm()).unwrap_err();
        assert!(err.to_string().contains("five segments"), "got: {err}");
    }

    #[test]
    fn rejects_when_no_keys_are_configured() {
        let err = decrypt_compact("a.b.c.d.e", &[], &both_gcm()).unwrap_err();
        assert!(
            err.to_string().contains("no request-decryption keys"),
            "got: {err}"
        );
    }

    /// Regression guard: the OpenID4VP path must keep its exact wire shape, so
    /// the four-argument form still emits no `kid`.
    #[test]
    fn encrypt_compact_still_writes_no_kid() {
        let (public, _private) = annotated_public_and_bare_private();
        let jwe =
            encrypt_compact(&json!({ "vp_token": "x" }), &public, "ECDH-ES", "A128GCM").unwrap();
        let header = protected_header(&jwe).unwrap();
        assert!(header.get("kid").is_none(), "header was {header}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-core --lib crypto::jwe
```

Expected: FAIL to compile — `DecryptionKey`, `decrypt_compact`, `encrypt_compact_with_kid`, `protected_header` are undefined.

- [ ] **Step 3: Add imports and `DecryptionKey`**

Extend the `use` block at the top of the file:

```rust
use base64::Engine as _;
use josekit::jwk::alg::ec::EcKeyPair;
use josekit::jwk::KeyPair as _;
```

Add after the `SUPPORTED_ALG` constant:

```rust
/// A long-lived issuer key used to **decrypt** Credential Requests.
///
/// OpenID4VCI L1373 requires every JWK published in
/// `credential_request_encryption.jwks` to carry a unique `kid`, and L1188
/// requires the encrypting client to echo it. The `kid` here is *derived* — the
/// RFC 7638 thumbprint of the public JWK — so it is unique by construction,
/// stable across restarts and replicas, and cannot drift from its key.
///
/// The private JWK stays **bare** (no `kid`/`use`/`alg`), mirroring the
/// asymmetry `foundry-verifier` already relies on: an annotated public JWK goes
/// to the client, a bare private JWK feeds `ECDH_ES.decrypter_from_jwk`.
pub struct DecryptionKey {
    kid: String,
    public_jwk: Value,
    private_jwk: Value,
}

impl std::fmt::Debug for DecryptionKey {
    /// Hand-written: a derive would print `private_jwk`, and private key
    /// material must never reach a log (root `AGENTS.md` §4.5).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl DecryptionKey {
    /// Load from an in-memory PKCS#8 PEM. Curve auto-detected, as in
    /// `FileSigner::from_pem`.
    pub fn from_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let key_pair =
            EcKeyPair::from_pem(pem, None).map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
        let public_jwk = serde_json::to_value(key_pair.to_jwk_public_key())
            .map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
        let private_jwk = serde_json::to_value(key_pair.to_jwk_private_key())
            .map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
        // `obs::thumbprint` degrades to a placeholder on malformed input, which
        // is the wrong contract for a value that goes on the wire as an
        // identifier. Use the fail-closed form and propagate.
        let digest = crate::obs::thumbprint_bytes(&public_jwk).map_err(CryptoError::KeyLoad)?;
        let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        Ok(Self {
            kid,
            public_jwk,
            private_jwk,
        })
    }

    pub fn from_pem_file(path: &str) -> Result<Self, CryptoError> {
        let pem = std::fs::read(path).map_err(|source| CryptoError::KeyRead {
            path: path.to_string(),
            source,
        })?;
        Self::from_pem(&pem)
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public JWK as published in `credential_request_encryption.jwks`.
    ///
    /// L1188 makes `alg` mandatory on the encryption key, L1373 makes `kid`
    /// mandatory, and `use: "enc"` lets a wallet select by purpose. Same
    /// annotation pattern as `foundry-verifier`'s `annotate_encryption_jwk`.
    pub fn published_jwk(&self) -> Value {
        let mut jwk = self.public_jwk.clone();
        if let Some(obj) = jwk.as_object_mut() {
            obj.insert("kid".to_string(), Value::String(self.kid.clone()));
            obj.insert("use".to_string(), Value::String("enc".to_string()));
            obj.insert("alg".to_string(), Value::String(SUPPORTED_ALG.to_string()));
        }
        jwk
    }
}
```

- [ ] **Step 4: Add `protected_header` and `decrypt_compact`**

```rust
/// The clear-text protected header of a compact-serialization JWE.
///
/// Parsed directly from segment 0 rather than via a josekit selector callback so
/// the `alg`/`enc`/`kid` checks below can return typed `CryptoError`s naming the
/// offending value instead of an opaque JOSE error.
fn protected_header(jwe: &str) -> Result<Value, CryptoError> {
    let segments: Vec<&str> = jwe.split('.').collect();
    if segments.len() != 5 {
        return Err(CryptoError::Jwe(format!(
            "a compact JWE must have five segments, got {}",
            segments.len()
        )));
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[0])
        .map_err(|e| CryptoError::Jwe(format!("protected header is not base64url: {e}")))?;
    serde_json::from_slice(&raw)
        .map_err(|e| CryptoError::Jwe(format!("protected header is not JSON: {e}")))
}

/// Decrypt a compact-serialization JWE Credential Request to its JWT claims set.
///
/// OpenID4VCI L1186 requires the message contents to be a JWT, so the returned
/// value is the claims set — which *is* the Credential Request object.
///
/// Three header checks run **before** any key agreement, each a conformance
/// clause:
///
/// * L1188 / VCI-0100 — the JWE `alg` MUST equal the `alg` of the chosen JWK,
///   and every published JWK carries `ECDH-ES`.
/// * L1188 / VCI-0101 — the JWE MUST echo the selected key's `kid`. Every
///   published key has one, so an absent `kid` is a rejection rather than a fall
///   back to trial decryption; trial decryption would reduce `kid` to decoration
///   and mask a client bug.
/// * VCI-0135 — `enc` must be one of the advertised values.
pub fn decrypt_compact(
    jwe: &str,
    keys: &[DecryptionKey],
    allowed_enc: &[String],
) -> Result<Value, CryptoError> {
    if keys.is_empty() {
        return Err(CryptoError::Jwe(
            "no request-decryption keys are configured".to_string(),
        ));
    }

    let header = protected_header(jwe)?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CryptoError::Jwe("JWE header has no string `alg`".to_string()))?;
    if alg != SUPPORTED_ALG {
        return Err(CryptoError::Jwe(format!(
            "unsupported key-management algorithm '{alg}' (only {SUPPORTED_ALG} is supported)"
        )));
    }

    let enc = header
        .get("enc")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CryptoError::Jwe("JWE header has no string `enc`".to_string()))?;
    if !allowed_enc.iter().any(|a| a == enc) {
        return Err(CryptoError::Jwe(format!(
            "unsupported content-encryption algorithm '{enc}'"
        )));
    }

    let kid = header.get("kid").and_then(|v| v.as_str()).ok_or_else(|| {
        CryptoError::Jwe(
            "JWE header has no `kid`; every published encryption key carries one \
             (OpenID4VCI L1188)"
                .to_string(),
        )
    })?;
    let key = keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| CryptoError::Jwe(format!("no decryption key matches `kid` '{kid}'")))?;

    let jwk_bytes = serde_json::to_vec(&key.private_jwk)
        .map_err(|e| CryptoError::Jwe(format!("decryption jwk is not serialisable: {e}")))?;
    let jwk =
        Jwk::from_bytes(&jwk_bytes).map_err(|e| CryptoError::Jwe(format!("invalid jwk: {e}")))?;
    let decrypter = josekit::jwe::ECDH_ES
        .decrypter_from_jwk(&jwk)
        .map_err(|e| CryptoError::Jwe(format!("cannot build decrypter: {e}")))?;

    let (payload, _header) = josekit::jwt::decode_with_decrypter(jwe, &decrypter)
        .map_err(|e| CryptoError::Jwe(e.to_string()))?;

    serde_json::to_value(payload.claims_set())
        .map_err(|e| CryptoError::Jwe(format!("decrypted claims are not JSON: {e}")))
}
```

- [ ] **Step 5: Split `encrypt_compact` into a `kid`-aware form**

Replace the existing `pub fn encrypt_compact(...)` with these two functions. The body of `encrypt_compact_with_kid` is the current body plus the `kid` insertion.

```rust
/// Encrypt `payload` to `recipient_public_jwk` as a compact-serialization JWE.
///
/// Emits **no** `kid` header. This is the OpenID4VP path (a wallet encrypting an
/// authorization response to the verifier's ephemeral key) and its wire shape
/// must not change; see [`encrypt_compact_with_kid`] for the Credential Response
/// path, where OpenID4VCI L1188 requires the recipient's `kid` to be echoed.
pub fn encrypt_compact(
    payload: &Value,
    recipient_public_jwk: &Value,
    alg: &str,
    enc: &str,
) -> Result<String, CryptoError> {
    encrypt_compact_with_kid(payload, recipient_public_jwk, alg, enc, None)
}

/// As [`encrypt_compact`], but writes `kid` into the protected header when one
/// is supplied.
///
/// OpenID4VCI L1188: *"If the selected public key contains a `kid` parameter,
/// the JWE MUST include the same value in the `kid` JWE Header Parameter."* On
/// the Credential Response path the selected key is the wallet's
/// `credential_response_encryption.jwk` (VCI-0101).
pub fn encrypt_compact_with_kid(
    payload: &Value,
    recipient_public_jwk: &Value,
    alg: &str,
    enc: &str,
    kid: Option<&str>,
) -> Result<String, CryptoError> {
    if alg != SUPPORTED_ALG {
        return Err(CryptoError::Jwe(format!(
            "unsupported key-management algorithm '{alg}' (only {SUPPORTED_ALG} is supported)"
        )));
    }

    let claims = payload
        .as_object()
        .ok_or_else(|| CryptoError::Jwe("payload must be a JSON object".to_string()))?
        .clone();
    let jwt_payload = JwtPayload::from_map(claims)
        .map_err(|e| CryptoError::Jwe(format!("invalid payload claims: {e}")))?;

    let jwk_bytes = serde_json::to_vec(recipient_public_jwk)
        .map_err(|e| CryptoError::Jwe(format!("recipient jwk is not serialisable: {e}")))?;
    let jwk = Jwk::from_bytes(&jwk_bytes)
        .map_err(|e| CryptoError::Jwe(format!("invalid recipient jwk: {e}")))?;
    let encrypter = josekit::jwe::ECDH_ES
        .encrypter_from_jwk(&jwk)
        .map_err(|e| CryptoError::Jwe(format!("cannot encrypt to recipient jwk: {e}")))?;

    let mut header = JweHeader::new();
    header.set_algorithm(alg);
    header.set_content_encryption(enc);
    if let Some(kid) = kid {
        header.set_key_id(kid);
    }

    josekit::jwt::encode_with_encrypter(&jwt_payload, &header, &encrypter)
        .map_err(|e| CryptoError::Jwe(e.to_string()))
}
```

If `JweHeader::set_key_id` is absent under that name, confirm the correct setter and use it:

```bash
grep -n 'pub fn set_key_id\|pub fn set_claim' ~/.cargo/registry/src/*/josekit-0.10.3/src/jwe/jwe_header.rs
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test -p foundry-core --lib crypto::jwe
```

Expected: PASS, including the pre-existing `round_trips_annotated_public_to_bare_private`, `round_trips_with_a_bare_public_jwk_too`, and `rejects_malformed_recipient_jwk` — unchanged OpenID4VP behaviour is the point of Step 5's split.

- [ ] **Step 7: Scoped gate and commit**

`crypto/` feeds both engines (§5.2); this task is additive apart from the internal split, so verify they are unaffected:

```bash
cargo test -p foundry-core
cargo test -p foundry-issuer -p foundry-verifier
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
git add crates/foundry-core/src/crypto/jwe.rs
git commit -m "feat(core): JWE decryption, DecryptionKey, and a kid-aware encrypt"
```
---

### Task 2: Config blocks, key loading, and startup validation

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs`
- Modify: `crates/foundry-core/src/config/validate.rs`
- Modify: `crates/foundry-core/src/config/mod.rs`
- Modify: every file containing an `IssuerConfig { ... }` literal (mechanical, Step 6)

**Interfaces:**
- Consumes: `DecryptionKey` (Task 1).
- Produces:
  - `pub struct RequestEncryptionConfig { pub keys: Vec<String>, pub enc_values_supported: Vec<String>, pub encryption_required: bool }`
  - `pub struct ResponseEncryptionConfig { pub enc_values_supported: Vec<String>, pub encryption_required: bool }`
  - `IssuerConfig::request_encryption: Option<RequestEncryptionConfig>`, `IssuerConfig::response_encryption: Option<ResponseEncryptionConfig>`
  - `pub const SUPPORTED_ENC_VALUES: [&str; 2]`
  - `Config::load_request_decryption_keys(&self, base_dir: &Path) -> Result<Vec<DecryptionKey>, ConfigError>`

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-core/src/config/validate.rs`. It already defines `minimal_config()`.

```rust
    fn cfg_with_signing_key() -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
        std::fs::write(dir.path().join("key.pem"), km.private_pem).unwrap();
        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "key.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        (cfg, dir)
    }

    fn req_enc(keys: Vec<String>) -> crate::config::RequestEncryptionConfig {
        crate::config::RequestEncryptionConfig {
            keys,
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: false,
        }
    }

    #[test]
    fn request_encryption_key_must_resolve() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(vec!["nope".to_string()]));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("nope"), "message must name the key, got: {msg}");
    }

    #[test]
    fn request_encryption_keys_must_be_non_empty() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(Vec::new()));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("non-empty"), "got: {msg}");
    }

    #[test]
    fn an_encryption_key_may_not_also_be_a_signing_key() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(vec!["verifier_signing".to_string()]));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("verifier_signing") && msg.contains("signing"),
            "got: {msg}"
        );
    }

    #[test]
    fn required_response_encryption_needs_request_encryption() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.response_encryption = Some(crate::config::ResponseEncryptionConfig {
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: true,
        });
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("request_encryption"), "got: {msg}");
    }

    #[test]
    fn advertised_enc_values_must_be_supported() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.response_encryption = Some(crate::config::ResponseEncryptionConfig {
            enc_values_supported: vec!["A192GCM".to_string()],
            encryption_required: false,
        });
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("A192GCM"), "got: {msg}");
    }

    #[test]
    fn loads_request_decryption_keys_and_derives_distinct_kids() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = minimal_config();
        for name in ["enc_a", "enc_b"] {
            let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
            std::fs::write(dir.path().join(format!("{name}.pem")), km.private_pem).unwrap();
            cfg.keys.insert(
                name.to_string(),
                crate::config::model::KeyEntry {
                    private_key: format!("{name}.pem"),
                    x5c: None,
                    alg: "ES256".to_string(),
                },
            );
        }
        cfg.issuer.request_encryption =
            Some(req_enc(vec!["enc_a".to_string(), "enc_b".to_string()]));
        let keys = cfg.load_request_decryption_keys(dir.path()).unwrap();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0].kid(), keys[1].kid());
    }

    #[test]
    fn loads_no_keys_when_the_feature_is_off() {
        let cfg = minimal_config();
        assert!(cfg
            .load_request_decryption_keys(std::path::Path::new("."))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn encryption_blocks_default_to_both_gcm_sizes_and_optional() {
        let yaml = "server:\n  wallet_facing:\n    public_base_url: https://example.test\n    bind: 127.0.0.1:8080\n  admin:\n    bind: 127.0.0.1:8081\nstorage:\n  path: ./t.db\nissuer:\n  credential_issuer: https://example.test\n  status_list:\n    enabled: false\n  request_encryption:\n    keys: [k]\n  response_encryption: {}\nverifier:\n  signing_key: verifier-key\n";
        let cfg: Config = serde_yaml::from_str(yaml).expect("config should parse");
        let re = cfg.issuer.request_encryption.as_ref().unwrap();
        assert_eq!(re.enc_values_supported, vec!["A128GCM", "A256GCM"]);
        assert!(!re.encryption_required);
        let rs = cfg.issuer.response_encryption.as_ref().unwrap();
        assert_eq!(rs.enc_values_supported, vec!["A128GCM", "A256GCM"]);
        assert!(!rs.encryption_required);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-core --lib config::
```

Expected: FAIL to compile — the two config structs, the two `IssuerConfig` fields, and `load_request_decryption_keys` do not exist.

- [ ] **Step 3: Add the config model**

In `crates/foundry-core/src/config/model.rs`, append these two fields to `IssuerConfig` (after `dpop`):

```rust
    /// OpenID4VCI §Credential Request (L848, L871) and §Credential Issuer
    /// Metadata (L1373): encryption of the Credential Request on top of TLS.
    /// Absent means the mechanism is off and `credential_request_encryption` is
    /// omitted from metadata entirely.
    #[serde(default)]
    pub request_encryption: Option<RequestEncryptionConfig>,
    /// OpenID4VCI §Credential Response (L960, L969) and §Credential Issuer
    /// Metadata (L1378): encryption of the Credential Response on top of TLS.
    ///
    /// Distinct from `verifier.response_encryption`, which configures the
    /// unrelated OpenID4VP authorization-response JWE.
    #[serde(default)]
    pub response_encryption: Option<ResponseEncryptionConfig>,
```

And add, after `DpopConfig`'s `Default` impl:

```rust
/// The only content-encryption algorithms foundry advertises or accepts.
///
/// HAIP OpenID4VP L260 requires both on the presentation side; mirroring them on
/// the issuance side keeps one algorithm story across the codebase.
pub const SUPPORTED_ENC_VALUES: [&str; 2] = ["A128GCM", "A256GCM"];

fn default_enc_values_supported() -> Vec<String> {
    SUPPORTED_ENC_VALUES.iter().map(|s| s.to_string()).collect()
}

/// OpenID4VCI `credential_request_encryption` (L1373–L1377).
#[derive(Debug, Clone, Deserialize)]
pub struct RequestEncryptionConfig {
    /// Names of `keys:` entries whose private keys decrypt Credential Requests.
    ///
    /// Ordered and non-empty. Listing several at once is how rotation happens
    /// without downtime: all are published and all decrypt.
    ///
    /// The referenced `keys:` entry carries `alg: ES256`, naming the **key
    /// material** (a P-256 EC key) — `validate_key_material` parses every entry's
    /// `alg` as a `SignatureAlgorithm`, so `ECDH-ES` there would fail startup.
    /// The published JWK carries `alg: "ECDH-ES"` instead; see
    /// `DecryptionKey::published_jwk`.
    pub keys: Vec<String>,
    #[serde(default = "default_enc_values_supported")]
    pub enc_values_supported: Vec<String>,
    /// L1377. `false` (the default) lets a wallet choose; `true` rejects an
    /// unencrypted Credential Request (L1192).
    #[serde(default)]
    pub encryption_required: bool,
}

/// OpenID4VCI `credential_response_encryption` (L1378–L1381).
///
/// No `alg_values_supported`: it is always `["ECDH-ES"]`, because
/// `foundry_core::crypto::jwe::encrypt_compact_with_kid` rejects every other
/// key-management algorithm. Making it configurable could only advertise
/// something the code cannot do.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseEncryptionConfig {
    #[serde(default = "default_enc_values_supported")]
    pub enc_values_supported: Vec<String>,
    /// L1381. `true` requires every Credential Response to be encrypted, which
    /// in turn requires the wallet to supply keys in the request.
    #[serde(default)]
    pub encryption_required: bool,
}
```

- [ ] **Step 4: Add the four validation rules**

In `crates/foundry-core/src/config/validate.rs`, inside `Config::validate`, immediately before the final `Ok(())`:

```rust
        // OpenID4VCI Credential Issuer Metadata (L1373): `jwks` is REQUIRED, so
        // an enabled block with no resolvable keys is unservable metadata.
        if let Some(re) = &self.issuer.request_encryption {
            if re.keys.is_empty() {
                return Err(ConfigError::Validation(
                    "issuer.request_encryption.keys must be non-empty".to_string(),
                ));
            }
            for name in &re.keys {
                if !self.keys.contains_key(name) {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references unknown key '{name}'"
                    )));
                }
                // One EC key must not serve both ECDSA signing and ECDH key
                // agreement. The `keys:` map is shared, so this is the only place
                // cross-purpose reuse can be prevented.
                if name == &self.verifier.signing_key {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references '{name}', which is also \
                         verifier.signing_key; an encryption key must not be reused for signing"
                    )));
                }
                if self.issuer.status_list.signing_key.as_deref() == Some(name.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references '{name}', which is also \
                         issuer.status_list.signing_key; an encryption key must not be reused \
                         for signing"
                    )));
                }
            }
            check_enc_values("issuer.request_encryption", &re.enc_values_supported)?;
        }

        if let Some(rs) = &self.issuer.response_encryption {
            check_enc_values("issuer.response_encryption", &rs.enc_values_supported)?;
            // OpenID4VCI L960: a request carrying `credential_response_encryption`
            // MUST itself be encrypted. Requiring response encryption while
            // supporting no request decryption is unsatisfiable.
            let no_request_keys = match &self.issuer.request_encryption {
                None => true,
                Some(re) => re.keys.is_empty(),
            };
            if rs.encryption_required && no_request_keys {
                return Err(ConfigError::Validation(
                    "issuer.response_encryption.encryption_required is true but \
                     issuer.request_encryption has no keys; OpenID4VCI L960 requires a request \
                     carrying credential_response_encryption to be encrypted, so no conformant \
                     wallet could use this deployment"
                        .to_string(),
                ));
            }
        }
```

And next to `is_loopback_host`, add:

```rust
/// An `enc` value may be advertised only if it can actually be honoured.
fn check_enc_values(block: &str, values: &[String]) -> Result<(), ConfigError> {
    if values.is_empty() {
        return Err(ConfigError::Validation(format!(
            "{block}.enc_values_supported must be non-empty"
        )));
    }
    for v in values {
        if !crate::config::SUPPORTED_ENC_VALUES.contains(&v.as_str()) {
            return Err(ConfigError::Validation(format!(
                "{block}.enc_values_supported contains unsupported value '{v}' (supported: {})",
                crate::config::SUPPORTED_ENC_VALUES.join(", ")
            )));
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Add `load_request_decryption_keys`**

In `crates/foundry-core/src/config/mod.rs`, add `use crate::crypto::jwe::DecryptionKey;` to the imports and this method to the existing `impl Config` block:

```rust
    /// Load the private keys that decrypt Credential Requests.
    ///
    /// Called once at startup — never per request. Returns an empty vector when
    /// `issuer.request_encryption` is absent, which is what makes the feature
    /// default-off.
    pub fn load_request_decryption_keys(
        &self,
        base_dir: &Path,
    ) -> Result<Vec<DecryptionKey>, ConfigError> {
        let Some(re) = &self.issuer.request_encryption else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(re.keys.len());
        for name in &re.keys {
            let entry = self.keys.get(name).ok_or_else(|| {
                ConfigError::Validation(format!(
                    "issuer.request_encryption.keys references unknown key '{name}'"
                ))
            })?;
            let path = base_dir.join(&entry.private_key);
            let key = DecryptionKey::from_pem_file(&path.to_string_lossy()).map_err(|e| {
                ConfigError::Validation(format!("issuer.request_encryption key '{name}': {e}"))
            })?;
            out.push(key);
        }
        Ok(out)
    }
```

- [ ] **Step 6: Fix every `IssuerConfig` struct literal**

Two new fields break every literal. Locate them:

```bash
grep -rn 'IssuerConfig {' --include='*.rs' crates/
```

Add to each literal:

```rust
            request_encryption: None,
            response_encryption: None,
```

Then confirm none were missed:

```bash
cargo build --workspace --all-targets 2>&1 | grep -c 'missing field'
```

Expected: `0`.

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cargo test -p foundry-core --lib config::
```

Expected: PASS, including all eight new tests.

- [ ] **Step 8: Scoped gate and commit**

`config/` is consumed by every crate, so widen to the direct consumers (§5.2):

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
git add -A
git commit -m "feat(core): config, key loading, and validation for credential encryption"
```

---

### Task 3: Metadata objects

**Files:**
- Modify: `crates/foundry-issuer/src/metadata.rs`
- Modify: `crates/foundry-issuer/src/lib.rs` (re-exports)
- Modify: `crates/foundry-issuer/src/offer.rs:120`
- Modify: `crates/foundry/src/server.rs:143`
- Modify: `crates/foundry/src/openapi.rs` (`WalletApiDoc` schemas, ~line 56)
- Modify: `crates/foundry-issuer/tests/conformance_vci.rs` (mechanical)

**Interfaces:**
- Consumes: `DecryptionKey` (Task 1); `RequestEncryptionConfig`, `ResponseEncryptionConfig`, the two `IssuerConfig` fields (Task 2).
- Produces:
  - `pub struct CredentialRequestEncryption { pub jwks: serde_json::Value, pub enc_values_supported: Vec<String>, pub encryption_required: bool }`
  - `pub struct CredentialResponseEncryption { pub alg_values_supported: Vec<String>, pub enc_values_supported: Vec<String>, pub encryption_required: bool }`
  - `CredentialIssuerMetadata::{credential_request_encryption, credential_response_encryption}`, both `Option`
  - **Signature change:** `build_issuer_metadata(cfg: &Config, request_decryption_keys: &[DecryptionKey]) -> CredentialIssuerMetadata`

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/metadata.rs`. Reuse whatever config helper the existing `build_issuer_metadata(&cfg)` tests in that module already use; the snippets below call it `test_config()` — rename to match.

```rust
    #[test]
    fn omits_both_encryption_objects_when_unconfigured() {
        let cfg = test_config();
        let json = serde_json::to_value(build_issuer_metadata(&cfg, &[])).unwrap();
        assert!(
            json.get("credential_request_encryption").is_none(),
            "unconfigured metadata must stay byte-identical to pre-encryption output"
        );
        assert!(json.get("credential_response_encryption").is_none());
    }

    #[test]
    fn publishes_the_request_jwks_with_annotated_kids() {
        let mut cfg = test_config();
        cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
            keys: vec!["issuer_request_enc".to_string()],
            enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
            encryption_required: false,
        });
        let km =
            foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
                .unwrap();
        let key =
            foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes()).unwrap();
        let expected_kid = key.kid().to_string();

        let json =
            serde_json::to_value(build_issuer_metadata(&cfg, std::slice::from_ref(&key))).unwrap();
        let obj = &json["credential_request_encryption"];
        assert_eq!(obj["jwks"]["keys"][0]["kid"], serde_json::json!(expected_kid));
        assert_eq!(obj["jwks"]["keys"][0]["alg"], serde_json::json!("ECDH-ES"));
        assert_eq!(obj["jwks"]["keys"][0]["use"], serde_json::json!("enc"));
        assert_eq!(obj["encryption_required"], serde_json::json!(false));
        assert_eq!(
            obj["enc_values_supported"],
            serde_json::json!(["A128GCM", "A256GCM"])
        );
        // OpenID4VCI L1375: absence means compression MUST NOT be used.
        assert!(obj.get("zip_values_supported").is_none());
    }

    #[test]
    fn publishes_response_encryption_with_ecdh_es_only() {
        let mut cfg = test_config();
        cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
            enc_values_supported: vec!["A256GCM".to_string()],
            encryption_required: true,
        });
        let json = serde_json::to_value(build_issuer_metadata(&cfg, &[])).unwrap();
        let obj = &json["credential_response_encryption"];
        assert_eq!(obj["alg_values_supported"], serde_json::json!(["ECDH-ES"]));
        assert_eq!(obj["enc_values_supported"], serde_json::json!(["A256GCM"]));
        assert_eq!(obj["encryption_required"], serde_json::json!(true));
        assert!(obj.get("zip_values_supported").is_none());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib metadata
```

Expected: FAIL to compile — `build_issuer_metadata` takes one argument and the fields do not exist.

- [ ] **Step 3: Add the metadata types and fields**

In `crates/foundry-issuer/src/metadata.rs`, after `ProofTypeSupported`:

```rust
/// OpenID4VCI Credential Issuer Metadata `credential_request_encryption`
/// (L1373–L1377). `zip_values_supported` is deliberately absent: L1375 makes it
/// optional and its absence means no compression algorithm is supported.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialRequestEncryption {
    /// L1373: a JWK Set whose every member carries a unique `kid`.
    #[schema(value_type = Object)]
    pub jwks: serde_json::Value,
    pub enc_values_supported: Vec<String>,
    pub encryption_required: bool,
}

/// OpenID4VCI Credential Issuer Metadata `credential_response_encryption`
/// (L1378–L1381). `zip_values_supported` is deliberately absent (L1380).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialResponseEncryption {
    pub alg_values_supported: Vec<String>,
    pub enc_values_supported: Vec<String>,
    pub encryption_required: bool,
}
```

Add to `CredentialIssuerMetadata`, after `credential_configurations_supported`:

```rust
    /// `skip_serializing_if` is load-bearing: with the feature off the
    /// serialised document must stay byte-identical to the pre-encryption one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_request_encryption: Option<CredentialRequestEncryption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
```

- [ ] **Step 4: Change `build_issuer_metadata`**

Replace the signature:

```rust
/// Build the Credential Issuer Metadata document, fully derived from
/// `cfg.credential_types` and `cfg.issuer` — nothing hard-coded per credential type.
///
/// `request_decryption_keys` are the already-loaded keys from
/// `Config::load_request_decryption_keys`. They are passed in rather than read
/// from disk here because metadata is served on every wallet request and must not
/// do filesystem I/O.
pub fn build_issuer_metadata(
    cfg: &Config,
    request_decryption_keys: &[foundry_core::crypto::jwe::DecryptionKey],
) -> CredentialIssuerMetadata {
```

and extend the returned literal:

```rust
        credential_configurations_supported: configs,
        credential_request_encryption: cfg.issuer.request_encryption.as_ref().map(|re| {
            CredentialRequestEncryption {
                jwks: serde_json::json!({
                    "keys": request_decryption_keys
                        .iter()
                        .map(|k| k.published_jwk())
                        .collect::<Vec<_>>(),
                }),
                enc_values_supported: re.enc_values_supported.clone(),
                encryption_required: re.encryption_required,
            }
        }),
        credential_response_encryption: cfg.issuer.response_encryption.as_ref().map(|rs| {
            CredentialResponseEncryption {
                // Fixed, not configurable: `encrypt_compact_with_kid` supports no
                // other key-management algorithm.
                alg_values_supported: vec!["ECDH-ES".to_string()],
                enc_values_supported: rs.enc_values_supported.clone(),
                encryption_required: rs.encryption_required,
            }
        }),
```

- [ ] **Step 5: Re-export, register schemas, and fix all call sites**

`crates/foundry-issuer/src/lib.rs` — add `CredentialRequestEncryption, CredentialResponseEncryption` to the `metadata` re-export list beside `CredentialIssuerMetadata`.

`crates/foundry/src/openapi.rs`, `WalletApiDoc`'s `components(schemas(...))` block:

```rust
        foundry_issuer::CredentialRequestEncryption,
        foundry_issuer::CredentialResponseEncryption,
```

`crates/foundry/src/server.rs:143` — `AppState::request_decryption_keys` does not exist until Task 5, so pass an empty slice now and change it there:

```rust
async fn issuer_metadata(State(state): State<AppState>) -> Json<CredentialIssuerMetadata> {
    // Encryption keys are wired in alongside AppState in the extractor task.
    Json(foundry_issuer::build_issuer_metadata(&state.config, &[]))
}
```

`crates/foundry-issuer/src/offer.rs:120`:

```rust
    // Credential offers carry no encryption metadata; wallets read it from the
    // well-known document.
    let mut issuer_metadata = build_issuer_metadata(cfg, &[]);
```

Every remaining call is a test. Locate and fix mechanically by adding `, &[]`:

```bash
grep -rn 'build_issuer_metadata(&cfg)\|build_issuer_metadata(&config)' --include='*.rs' crates/
```

Verify:

```bash
cargo build --workspace --all-targets 2>&1 | grep -c 'this function takes 2 arguments'
```

Expected: `0`.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib metadata
cargo test -p foundry-issuer --test conformance_vci
```

Expected: PASS. The pre-existing metadata tests must be unaffected, since both new fields serialise as absent.

- [ ] **Step 7: Scoped gate and commit**

```bash
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
git add -A
git commit -m "feat(issuer): publish credential_request/response_encryption metadata"
```

---

### Task 4: Request parameters and encryption policy

**Files:**
- Modify: `crates/foundry-issuer/src/credential.rs`
- Modify: `crates/foundry-issuer/src/lib.rs` (re-exports)
- Modify: `crates/foundry/src/server.rs` (call site ~line 1048)
- Modify: `crates/foundry-issuer/tests/conformance_vci.rs` (mechanical)

**Interfaces:**
- Consumes: `IssuerConfig::{request_encryption, response_encryption}` (Task 2).
- Produces:
  - `pub struct CredentialResponseEncryptionParams { pub jwk: serde_json::Value, pub enc: String, pub zip: Option<String> }`
  - `CredentialRequest::credential_response_encryption: Option<CredentialResponseEncryptionParams>`
  - `pub fn check_encryption_policy(cfg: &Config, req: &CredentialRequest, request_was_encrypted: bool) -> Result<(), IssuanceError>`
  - **Signature change:** `handle_credential_request(config, storage, access_token, req, nonce_secret, dpop, now_unix, request_was_encrypted: bool)` — the `bool` is the **last** parameter.

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/credential.rs`. It already has a `test_config(key_path)` helper and imports `SignatureAlgorithm`.

```rust
    fn wallet_enc_jwk() -> serde_json::Value {
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        let signer =
            foundry_core::crypto::FileSigner::from_pem(km.private_pem.as_bytes(), SignatureAlgorithm::Es256)
                .unwrap();
        let mut jwk = foundry_core::crypto::Signer::public_jwk(&signer).unwrap();
        if let Some(o) = jwk.as_object_mut() {
            o.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
        }
        jwk
    }

    fn req_with_response_encryption(
        jwk: serde_json::Value,
        enc: &str,
        zip: Option<&str>,
    ) -> CredentialRequest {
        CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: None,
            proofs: None,
            credential_response_encryption: Some(CredentialResponseEncryptionParams {
                jwk,
                enc: enc.to_string(),
                zip: zip.map(|z| z.to_string()),
            }),
        }
    }

    fn plain_req() -> CredentialRequest {
        CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: None,
            proofs: None,
            credential_response_encryption: None,
        }
    }

    /// A config with an issuer signing key on disk, optionally with both
    /// encryption blocks enabled. The `TempDir` is returned so the caller keeps
    /// the key file alive for the duration of the test.
    fn cfg_with_encryption(enabled: bool, required: bool) -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();
        let mut cfg = test_config(key_path.to_str().unwrap());
        if enabled {
            cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
                keys: vec!["enc".to_string()],
                enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
                encryption_required: required,
            });
            cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
                enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
                encryption_required: required,
            });
        }
        (cfg, dir)
    }

    #[test]
    fn plaintext_request_is_accepted_when_encryption_is_off() {
        let (cfg, _dir) = cfg_with_encryption(false, false);
        assert!(check_encryption_policy(&cfg, &plain_req(), false).is_ok());
    }

    #[test]
    fn plaintext_request_is_rejected_when_request_encryption_is_required() {
        let (cfg, _dir) = cfg_with_encryption(true, true);
        let err = check_encryption_policy(&cfg, &plain_req(), false).unwrap_err();
        assert!(
            matches!(err, IssuanceError::InvalidCredentialRequest(_)),
            "got: {err}"
        );
        assert!(err.to_string().contains("encrypted"), "got: {err}");
    }

    #[test]
    fn response_encryption_over_a_plaintext_request_is_rejected() {
        let (cfg, _dir) = cfg_with_encryption(true, false);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A128GCM", None);
        let err = check_encryption_policy(&cfg, &req, false).unwrap_err();
        assert!(err.to_string().contains("L960"), "got: {err}");
    }

    #[test]
    fn response_encryption_is_rejected_when_the_feature_is_off() {
        let (cfg, _dir) = cfg_with_encryption(false, false);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A128GCM", None);
        let err = check_encryption_policy(&cfg, &req, true).unwrap_err();
        assert!(err.to_string().contains("not supported"), "got: {err}");
    }

    #[test]
    fn response_encryption_requires_an_alg_on_the_wallet_jwk() {
        let (cfg, _dir) = cfg_with_encryption(true, false);
        let mut jwk = wallet_enc_jwk();
        if let Some(o) = jwk.as_object_mut() {
            o.remove("alg");
        }
        let req = req_with_response_encryption(jwk, "A128GCM", None);
        let err = check_encryption_policy(&cfg, &req, true).unwrap_err();
        assert!(err.to_string().contains("alg"), "got: {err}");
    }

    #[test]
    fn response_encryption_rejects_an_unadvertised_enc() {
        let (cfg, _dir) = cfg_with_encryption(true, false);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A192GCM", None);
        let err = check_encryption_policy(&cfg, &req, true).unwrap_err();
        assert!(err.to_string().contains("A192GCM"), "got: {err}");
    }

    #[test]
    fn response_encryption_rejects_zip() {
        let (cfg, _dir) = cfg_with_encryption(true, false);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A128GCM", Some("DEF"));
        let err = check_encryption_policy(&cfg, &req, true).unwrap_err();
        assert!(err.to_string().contains("zip"), "got: {err}");
    }

    #[test]
    fn a_well_formed_encrypted_pair_is_accepted() {
        let (cfg, _dir) = cfg_with_encryption(true, true);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A256GCM", None);
        assert!(check_encryption_policy(&cfg, &req, true).is_ok());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib credential
```

Expected: FAIL to compile — `CredentialResponseEncryptionParams`, the `CredentialRequest` field, and `check_encryption_policy` do not exist.

- [ ] **Step 3: Add the request parameter type and field**

In `crates/foundry-issuer/src/credential.rs`, immediately before `pub struct CredentialRequest`:

```rust
/// OpenID4VCI §Credential Request (L853–856): the wallet's parameters for
/// encrypting the Credential Response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialResponseEncryptionParams {
    /// L854: a single public key as a JWK. L1188 additionally requires an `alg`
    /// member on it.
    #[schema(value_type = Object)]
    pub jwk: serde_json::Value,
    /// L855: the JWE `enc` algorithm.
    pub enc: String,
    /// L856: compression before encryption. foundry advertises no
    /// `zip_values_supported`, so a present value is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
}
```

And add the field to `CredentialRequest`:

```rust
    /// L853. Absent means the Credential Response is not encrypted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryptionParams>,
```

- [ ] **Step 4: Add `check_encryption_policy`**

```rust
/// OpenID4VCI encryption policy for the Credential Endpoint.
///
/// Lives in the engine rather than in the HTTP extractor so no call site can
/// reach issuance while skipping it.
///
/// * L1192 — an unencrypted request is rejected when encryption was required.
/// * L960 — a request carrying `credential_response_encryption` MUST itself be
///   encrypted, "to prevent it being substituted by an attacker".
/// * L969 — the issuer MUST encrypt when asked. If the mechanism is not
///   configured the request is refused rather than answered in plaintext.
///   Deliberate deviation (root `AGENTS.md` §4.4): the specification does not
///   contemplate this case, and silently downgrading would deliver the
///   credential unencrypted to a wallet that asked for encryption.
/// * L1188 / L855 / L856 — the wallet's JWK must carry `alg`, `enc` must be
///   advertised, and `zip` must be absent.
pub fn check_encryption_policy(
    cfg: &Config,
    req: &CredentialRequest,
    request_was_encrypted: bool,
) -> Result<(), IssuanceError> {
    if let Some(re) = &cfg.issuer.request_encryption {
        if re.encryption_required && !request_was_encrypted {
            return Err(IssuanceError::InvalidCredentialRequest(
                "this Credential Endpoint requires the Credential Request to be encrypted \
                 (OpenID4VCI L1192)"
                    .to_string(),
            ));
        }
    }

    let Some(params) = &req.credential_response_encryption else {
        return Ok(());
    };

    if !request_was_encrypted {
        return Err(IssuanceError::InvalidCredentialRequest(
            "credential_response_encryption requires the Credential Request itself to be \
             encrypted (OpenID4VCI L960)"
                .to_string(),
        ));
    }

    let Some(rs) = &cfg.issuer.response_encryption else {
        return Err(IssuanceError::InvalidCredentialRequest(
            "Credential Response encryption is not supported by this deployment".to_string(),
        ));
    };

    if params.jwk.get("alg").and_then(|v| v.as_str()).is_none() {
        return Err(IssuanceError::InvalidCredentialRequest(
            "credential_response_encryption.jwk must carry an `alg` member (OpenID4VCI L1188)"
                .to_string(),
        ));
    }

    if !rs.enc_values_supported.contains(&params.enc) {
        return Err(IssuanceError::InvalidCredentialRequest(format!(
            "credential_response_encryption.enc '{}' is not supported",
            params.enc
        )));
    }

    if let Some(zip) = &params.zip {
        return Err(IssuanceError::InvalidCredentialRequest(format!(
            "credential_response_encryption.zip '{zip}' is not supported; this Credential \
             Endpoint advertises no zip_values_supported (OpenID4VCI L856)"
        )));
    }

    Ok(())
}
```

- [ ] **Step 5: Wire it into `handle_credential_request`**

Add `request_was_encrypted: bool` as the **final** parameter, add `request_encrypted = request_was_encrypted` to the `#[tracing::instrument]` `fields(...)` list (keep `skip_all`), and make the policy check the first statement in the body — before the storage lookup, so a malformed request costs no I/O:

```rust
    check_encryption_policy(config, req, request_was_encrypted)?;
    tracing::info!("credential request received");
```

Re-export `CredentialResponseEncryptionParams` and `check_encryption_policy` from `crates/foundry-issuer/src/lib.rs`, alongside `CredentialRequest`.

- [ ] **Step 6: Fix all call sites**

`crates/foundry/src/server.rs` (~line 1048) — the extractor's flag arrives in Task 5, so pass `false` now with this comment:

```rust
        // Wired to the extractor's `was_encrypted` flag in the extractor task.
        false,
```

Every remaining call site is a test. Locate them and add `, false` as the last argument:

```bash
grep -rn 'handle_credential_request(' --include='*.rs' crates/ | grep -v 'pub async fn'
```

Add `credential_response_encryption: None,` to every `CredentialRequest { ... }` literal:

```bash
grep -rn 'CredentialRequest {' --include='*.rs' crates/
```

Verify both:

```bash
cargo build --workspace --all-targets 2>&1 | grep -cE 'missing field|arguments were supplied'
```

Expected: `0`.

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib credential
cargo test -p foundry-issuer --test conformance_vci
```

Expected: PASS.

- [ ] **Step 8: Scoped gate and commit**

```bash
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
git add -A
git commit -m "feat(issuer): credential_response_encryption parameter and encryption policy"
```

---

### Task 5: The `MaybeEncrypted` extractor and the encrypted response body

**Files:**
- Create: `crates/foundry/src/extract.rs`
- Create: `crates/foundry/tests/credential_encryption.rs`
- Create: `crates/foundry/tests/support/mod.rs`
- Modify: `crates/foundry/Cargo.toml` (add `async-trait`)
- Modify: `crates/foundry/src/lib.rs` (declare `pub mod extract;`)
- Modify: `crates/foundry/src/server.rs` (`AppState`, `serve`, `issuer_metadata`, `credential_handler`, make `wallet_error_response` `pub(crate)`)
- Modify: `crates/foundry/src/main.rs` (load keys, pass them to `serve`)

**Interfaces:**
- Consumes: `decrypt_compact`, `encrypt_compact_with_kid`, `DecryptionKey` (Task 1); `Config::load_request_decryption_keys`, `SUPPORTED_ENC_VALUES` (Task 2); `CredentialRequest::credential_response_encryption` and `handle_credential_request`'s final `bool` (Task 4).
- Produces:
  - `pub struct MaybeEncrypted<T> { pub value: T, pub was_encrypted: bool }` implementing `FromRequest<AppState>`
  - `pub enum MaybeEncryptedRejection` implementing `IntoResponse`
  - `pub enum CredentialResponseBody { Json(CredentialResponse), Jwt(String) }` implementing `IntoResponse`
  - `AppState::request_decryption_keys: Arc<Vec<DecryptionKey>>` and `AppState::with_request_decryption_keys(self, Vec<DecryptionKey>) -> Self`
  - **Signature change:** `serve(cfg: Config, request_decryption_keys: Vec<DecryptionKey>)`

- [ ] **Step 1: Add the dependency**

In `crates/foundry/Cargo.toml`, next to `axum`:

```toml
async-trait = { workspace = true }
```

`async-trait 0.1` is already declared at the workspace root. axum 0.7's `FromRequest` is an `#[async_trait]` trait, so an impl needs the attribute.

- [ ] **Step 2: Create the test support module**

Create `crates/foundry/tests/support/mod.rs`. Copy `setup_test_app`, `issue_pre_auth_offer_and_get_access_token`, and `body_json` **verbatim** from `crates/foundry/tests/conformance_http.rs` (they already build an `AppState` with an on-disk issuer key and drive a pre-authorized-code flow to an access token), renaming `setup_test_app` to `setup_without_encryption` and making all four `pub`. Then append:

```rust
/// As `setup_without_encryption`, plus a generated request-decryption key and
/// both encryption blocks enabled with `encryption_required: false`.
pub async fn setup_with_encryption() -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_without_encryption().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
        keys: vec!["issuer_request_enc".to_string()],
        enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
        encryption_required: false,
    });
    cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
        enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
        encryption_required: false,
    });
    let km =
        foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256).unwrap();
    let key =
        foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes()).unwrap();
    let state = AppState::new(state.storage.clone(), std::sync::Arc::new(cfg))
        .with_request_decryption_keys(vec![key]);
    (state, dir)
}
```

> The access token minted by `issue_pre_auth_offer_and_get_access_token` is bound to the transaction in `state.storage`, and `setup_with_encryption` reuses that same `Arc<dyn Storage>`, so a token obtained from either state works against the other. Call the token helper **after** `setup_with_encryption` and pass it that state.

- [ ] **Step 3: Write the failing tests**

Create `crates/foundry/tests/credential_encryption.rs`:

```rust
//! The Credential Endpoint's encrypted request/response path.
//!
//! Drives the real wallet router over HTTP the way a wallet would: reads the
//! issuer's published JWKS from metadata, builds the request JWE itself with
//! `foundry_core::crypto::jwe`, and decrypts the response with its own key.
//! There is no wallet crate — the test *is* the client.

mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use foundry::server::wallet_router;
use tower::ServiceExt;

/// The wallet's ephemeral response-encryption keypair, as `(annotated public,
/// bare private)`.
fn wallet_response_key() -> (serde_json::Value, serde_json::Value) {
    let kp =
        josekit::jwk::alg::ec::EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let mut public =
        serde_json::to_value(josekit::jwk::KeyPair::to_jwk_public_key(&kp)).unwrap();
    if let Some(o) = public.as_object_mut() {
        o.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    }
    let private = serde_json::to_value(josekit::jwk::KeyPair::to_jwk_private_key(&kp)).unwrap();
    (public, private)
}

#[tokio::test]
async fn an_encrypted_request_yields_an_encrypted_response() {
    let (state, _dir) = support::setup_with_encryption().await;
    let access_token = support::issue_pre_auth_offer_and_get_access_token(&state).await;
    let app = wallet_router(state);

    // The issuer's published request-encryption key, read from metadata exactly
    // as a wallet would.
    let meta_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta: serde_json::Value = support::body_json(meta_res).await;
    let issuer_jwk = meta["credential_request_encryption"]["jwks"]["keys"][0].clone();
    let issuer_kid = issuer_jwk["kid"].as_str().unwrap().to_string();

    let (wallet_public, wallet_private) = wallet_response_key();
    let body = serde_json::json!({
        "credential_configuration_id": "pid",
        "credential_response_encryption": { "jwk": wallet_public, "enc": "A128GCM" },
    });
    let jwe = foundry_core::crypto::jwe::encrypt_compact_with_kid(
        &body,
        &issuer_jwk,
        "ECDH-ES",
        "A256GCM",
        Some(&issuer_kid),
    )
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/jwt")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(jwe))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/jwt"),
        "OpenID4VCI L1186: an encrypted Credential Response uses application/jwt"
    );

    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let compact = String::from_utf8(bytes.to_vec()).unwrap();
    let jwk = josekit::jwk::Jwk::from_bytes(
        serde_json::to_string(&wallet_private).unwrap().as_bytes(),
    )
    .unwrap();
    let decrypter = josekit::jwe::ECDH_ES.decrypter_from_jwk(&jwk).unwrap();
    let (payload, jwe_header) = josekit::jwt::decode_with_decrypter(&compact, &decrypter).unwrap();
    assert_eq!(
        jwe_header.content_encryption(),
        Some("A128GCM"),
        "OpenID4VCI L969: the issuer encrypts with the wallet's chosen `enc`"
    );
    let decrypted = serde_json::to_value(payload.claims_set()).unwrap();
    assert!(
        decrypted["credentials"][0]["credential"].is_string(),
        "decrypted response was {decrypted}"
    );
}

#[tokio::test]
async fn a_plaintext_request_still_gets_a_plaintext_response() {
    let (state, _dir) = support::setup_with_encryption().await;
    let access_token = support::issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = wallet_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(r#"{"credential_configuration_id":"pid"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "encryption is opt-in per request; an unencrypted request stays unencrypted"
    );
}

#[tokio::test]
async fn application_jwt_is_415_when_the_feature_is_off() {
    let (state, _dir) = support::setup_without_encryption().await;
    let access_token = support::issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = wallet_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/jwt")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from("a.b.c.d.e"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "an issuer that cannot decrypt must not appear to accept application/jwt"
    );
}
```

- [ ] **Step 4: Run the tests to verify they fail**

```bash
cargo test -p foundry --test credential_encryption
```

Expected: FAIL to compile — `with_request_decryption_keys` and the extractor do not exist.

- [ ] **Step 5: Write `crates/foundry/src/extract.rs`**

```rust
//! Content-type-aware body extraction for the Credential Endpoint.
//!
//! OpenID4VCI §Credential Request (L848) permits the Credential Request to be
//! encrypted on top of TLS, in which case §Encrypted Messages (L1186) requires
//! the body to be a JWT with media type `application/jwt`; L875 requires an
//! unencrypted request to use `application/json`.
//!
//! Rejections are mapped **here** because an extractor rejection short-circuits
//! before any handler runs, so `credential_error_response` never sees it. Root
//! `AGENTS.md` §4.5 requires exactly one log record per typed error emitted in
//! its mapper, so this module owns that mapper for this path — and delegates the
//! protocol arm to `wallet_error_response` so the body and log shape are
//! identical to the engine's.

use crate::server::{wallet_error_response, AppState};
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use foundry_issuer::{CredentialResponse, IssuanceError};
use serde::de::DeserializeOwned;

/// A request body that arrived either as `application/json` or as an
/// `application/jwt` JWE.
pub struct MaybeEncrypted<T> {
    pub value: T,
    /// Whether the body arrived encrypted. Feeds `handle_credential_request`,
    /// which needs it for OpenID4VCI L960 and L1192.
    pub was_encrypted: bool,
}

pub enum MaybeEncryptedRejection {
    /// L875 / VCI-0062: anything that is neither `application/json` nor a
    /// supported `application/jwt`.
    UnsupportedMediaType,
    /// A structurally bad encrypted body: wrong `alg`, unadvertised `enc`,
    /// absent or unknown `kid`, undecryptable ciphertext, or claims that are not
    /// a Credential Request.
    Issuance(IssuanceError),
    /// The plaintext path's own rejection, passed through unchanged.
    Json(JsonRejection),
}

impl IntoResponse for MaybeEncryptedRejection {
    fn into_response(self) -> Response {
        match self {
            // 415 is a transport-level refusal with no OAuth error body, which is
            // exactly what axum's `Json` extractor produced before this extractor
            // existed. `vci_0062_credential_request_requires_json_content_type`
            // pins the status.
            MaybeEncryptedRejection::UnsupportedMediaType => {
                tracing::warn!(
                    listener = "wallet",
                    "error.kind" = "unsupported_media_type",
                    "credential request rejected: unsupported Content-Type"
                );
                StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
            }
            // `wallet_error_response` emits the single log record; this arm adds
            // none of its own.
            MaybeEncryptedRejection::Issuance(e) => {
                let (status, body) = wallet_error_response(&e);
                (status, body).into_response()
            }
            MaybeEncryptedRejection::Json(r) => r.into_response(),
        }
    }
}

/// Is `value` the given media type, ignoring parameters such as `; charset=utf-8`?
fn is_media_type(value: Option<&str>, expected: &str) -> bool {
    value
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(expected)
        })
        .unwrap_or(false)
}

#[async_trait::async_trait]
impl<T> FromRequest<AppState> for MaybeEncrypted<T>
where
    T: DeserializeOwned + Send + 'static,
{
    type Rejection = MaybeEncryptedRejection;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        if is_media_type(content_type.as_deref(), "application/json") {
            let Json(value) = Json::<T>::from_request(req, state)
                .await
                .map_err(MaybeEncryptedRejection::Json)?;
            return Ok(Self {
                value,
                was_encrypted: false,
            });
        }

        if !is_media_type(content_type.as_deref(), "application/jwt") {
            return Err(MaybeEncryptedRejection::UnsupportedMediaType);
        }

        // L1183–L1192 is only reachable when the mechanism is configured. An
        // issuer with no decryption keys must not appear to accept the media
        // type, so this is 415 rather than a 400 the wallet cannot act on.
        let Some(re) = &state.config.issuer.request_encryption else {
            return Err(MaybeEncryptedRejection::UnsupportedMediaType);
        };
        if state.request_decryption_keys.is_empty() {
            return Err(MaybeEncryptedRejection::UnsupportedMediaType);
        }

        let body = String::from_request(req, state).await.map_err(|_| {
            MaybeEncryptedRejection::Issuance(IssuanceError::InvalidCredentialRequest(
                "an application/jwt body must be a UTF-8 compact JWE".to_string(),
            ))
        })?;

        let claims = foundry_core::crypto::jwe::decrypt_compact(
            &body,
            &state.request_decryption_keys,
            &re.enc_values_supported,
        )
        .map_err(|e| {
            // The message names only the structural defect; `CryptoError`'s
            // Display never echoes key material or ciphertext.
            MaybeEncryptedRejection::Issuance(IssuanceError::InvalidCredentialRequest(format!(
                "Credential Request decryption failed: {e}"
            )))
        })?;

        let value = serde_json::from_value(claims).map_err(|e| {
            MaybeEncryptedRejection::Issuance(IssuanceError::InvalidCredentialRequest(format!(
                "decrypted Credential Request is not well formed: {e}"
            )))
        })?;

        Ok(Self {
            value,
            was_encrypted: true,
        })
    }
}

/// A Credential Response body, plaintext or encrypted.
///
/// `IntoResponse` cannot fail but encryption can, so the encryption happens in
/// the handler (where it becomes a typed error) and this type only carries the
/// already-computed body plus its media type.
pub enum CredentialResponseBody {
    /// L971: `application/json`.
    Json(CredentialResponse),
    /// L1186: `application/jwt`, carrying the compact JWE as the raw body — not
    /// a JSON-quoted string.
    Jwt(String),
}

impl IntoResponse for CredentialResponseBody {
    fn into_response(self) -> Response {
        match self {
            CredentialResponseBody::Json(res) => Json(res).into_response(),
            CredentialResponseBody::Jwt(compact) => (
                [(header::CONTENT_TYPE, "application/jwt")],
                compact,
            )
                .into_response(),
        }
    }
}
```

Declare it in `crates/foundry/src/lib.rs`: `pub mod extract;`

- [ ] **Step 6: Wire `AppState`, `serve`, and `main.rs`**

In `crates/foundry/src/server.rs`, add the field and builder, and change `wallet_error_response`'s visibility from private to `pub(crate)`:

```rust
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub config: Arc<Config>,
    pub nonce_secret: Arc<foundry_issuer::NonceSecret>,
    /// OpenID4VCI request-decryption keys, loaded once at startup. Empty when
    /// `issuer.request_encryption` is absent, which is what makes the feature
    /// default-off.
    pub request_decryption_keys: Arc<Vec<foundry_core::crypto::jwe::DecryptionKey>>,
}

impl AppState {
    pub fn new(storage: Arc<dyn Storage>, config: Arc<Config>) -> Self {
        Self {
            storage,
            config,
            nonce_secret: Arc::new(foundry_issuer::NonceSecret::random()),
            request_decryption_keys: Arc::new(Vec::new()),
        }
    }

    /// Attach the loaded request-decryption keys.
    ///
    /// A builder rather than a fourth `new` parameter so the ~26 existing
    /// `AppState::new` call sites stay unchanged.
    pub fn with_request_decryption_keys(
        mut self,
        keys: Vec<foundry_core::crypto::jwe::DecryptionKey>,
    ) -> Self {
        self.request_decryption_keys = Arc::new(keys);
        self
    }
}
```

Change `issuer_metadata` (from Task 3's placeholder) to pass the real keys:

```rust
    Json(foundry_issuer::build_issuer_metadata(
        &state.config,
        &state.request_decryption_keys,
    ))
```

Change `serve` to accept the keys, build the state with them, and log what loaded:

```rust
pub async fn serve(
    cfg: Config,
    request_decryption_keys: Vec<foundry_core::crypto::jwe::DecryptionKey>,
) -> anyhow::Result<()> {
```

and, replacing the `AppState::new` line:

```rust
    // `kid`s are RFC 7638 thumbprints of *public* keys and are published in
    // metadata, so logging them is safe and is what makes a `kid` mismatch
    // diagnosable in the field.
    if !request_decryption_keys.is_empty() {
        tracing::info!(
            count = request_decryption_keys.len(),
            kids = ?request_decryption_keys.iter().map(|k| k.kid()).collect::<Vec<_>>(),
            "loaded credential request-decryption keys"
        );
    }
    let state = AppState::new(storage.clone(), config.clone())
        .with_request_decryption_keys(request_decryption_keys);
```

In `crates/foundry/src/main.rs`, in the `Command::Serve` arm, load the keys next to the existing `validate_key_material` call:

```rust
            cfg.validate_key_material(base_dir)?;
            let enc_keys = cfg.load_request_decryption_keys(base_dir)?;
            server::serve(cfg, enc_keys).await
```

- [ ] **Step 7: Rewire `credential_handler`**

Change the signature so `MaybeEncrypted` is the final argument (it consumes the body), and branch on the response side:

```rust
async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: crate::extract::MaybeEncrypted<CredentialRequest>,
) -> Result<
    (HeaderMap, crate::extract::CredentialResponseBody),
    (StatusCode, HeaderMap, Json<serde_json::Value>),
> {
    let crate::extract::MaybeEncrypted {
        value: req,
        was_encrypted,
    } = body;
```

Replace every later use of `req` unchanged, pass `was_encrypted` as `handle_credential_request`'s final argument (replacing Task 4's placeholder `false`), and replace the success return:

```rust
    let mut out = HeaderMap::new();
    if let Some((name, value)) = dpop_nonce_header(&state, now) {
        out.insert(name, value);
    }

    // OpenID4VCI L969: when the wallet supplied encryption parameters the
    // response MUST be encrypted with them, "regardless of the content".
    let body = match &req.credential_response_encryption {
        None => crate::extract::CredentialResponseBody::Json(res),
        Some(params) => {
            let payload = serde_json::to_value(&res).map_err(|e| {
                credential_error_response(
                    &state,
                    now,
                    &foundry_issuer::IssuanceError::Serialization(e.to_string()),
                )
            })?;
            // L1188 / VCI-0101: echo the recipient key's `kid` when it has one.
            let kid = params.jwk.get("kid").and_then(|v| v.as_str());
            let compact = foundry_core::crypto::jwe::encrypt_compact_with_kid(
                &payload,
                &params.jwk,
                "ECDH-ES",
                &params.enc,
                kid,
            )
            .map_err(|e| {
                credential_error_response(&state, now, &foundry_issuer::IssuanceError::Crypto(e))
            })?;
            crate::extract::CredentialResponseBody::Jwt(compact)
        }
    };
    Ok((out, body))
}
```

Update the `#[utoipa::path]` annotation on `credential_handler` to document both media types — add to `responses(...)`:

```rust
        (status = 200, content_type = "application/jwt",
         description = "OpenID4VCI L1186: an encrypted Credential Response when the request \
                        carried `credential_response_encryption`."),
        (status = 415,
         description = "OpenID4VCI L875: the Content-Type is neither application/json nor a \
                        supported application/jwt."),
```

- [ ] **Step 8: Run the tests to verify they pass**

```bash
cargo test -p foundry --test credential_encryption
cargo test -p foundry --test conformance_http
```

Expected: PASS. `vci_0062_credential_request_requires_json_content_type` must pass **unchanged** — the extractor's 415 arm exists to preserve it.

- [ ] **Step 9: Scoped gate and commit**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
git add -A
git commit -m "feat(server): decrypt Credential Requests and encrypt Credential Responses"
```

---

### Task 6: The HTTP rejection matrix

**Files:**
- Modify: `crates/foundry/tests/conformance_http.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–5, plus `support::setup_with_encryption` / `support::issue_pre_auth_offer_and_get_access_token`.
- Produces: no production code. This task exists so every policy branch has an HTTP-level test naming its conformance row.

- [ ] **Step 1: Write the tests**

Append to `crates/foundry/tests/conformance_http.rs`. It has its own `setup_test_app` and `issue_pre_auth_offer_and_get_access_token`; add a local `setup_with_encryption` mirroring the one in `tests/support/mod.rs` (that module is private to its own test binary, so it cannot be shared) plus this helper:

```rust
/// POST a body to `/credential` with the given Content-Type.
async fn post_credential(
    state: &AppState,
    access_token: &str,
    content_type: &str,
    body: impl Into<axum::body::Bytes>,
) -> axum::http::Response<Body> {
    wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, content_type)
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(body.into()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Encrypt `body` to the issuer's published request-encryption key.
async fn encrypt_to_issuer(state: &AppState, body: &serde_json::Value, enc: &str) -> String {
    let meta = foundry_issuer::build_issuer_metadata(
        &state.config,
        &state.request_decryption_keys,
    );
    let json = serde_json::to_value(meta).unwrap();
    let jwk = json["credential_request_encryption"]["jwks"]["keys"][0].clone();
    let kid = jwk["kid"].as_str().unwrap().to_string();
    foundry_core::crypto::jwe::encrypt_compact_with_kid(body, &jwk, "ECDH-ES", enc, Some(&kid))
        .unwrap()
}

fn wallet_enc_jwk_json() -> serde_json::Value {
    let kp =
        josekit::jwk::alg::ec::EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let mut jwk = serde_json::to_value(josekit::jwk::KeyPair::to_jwk_public_key(&kp)).unwrap();
    if let Some(o) = jwk.as_object_mut() {
        o.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    }
    jwk
}

// ---------------------------------------------------------------------------
// VCI-0098 — OpenID4VCI Encrypted Messages (L1186): the media type of an
// encrypted message MUST be `application/jwt`. Anything else is refused before
// parsing, which is also what keeps VCI-0062 true.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0098_text_plain_is_still_415_with_encryption_enabled() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(&state, &token, "text/plain", "not json at all").await;
    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ---------------------------------------------------------------------------
// VCI-0100 — Encrypted Messages (L1188): the JWE `alg` MUST equal the `alg` of
// the chosen JWK, which is always ECDH-ES.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0100_a_non_ecdh_es_alg_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    // Hand-build a header claiming RSA-OAEP over an otherwise well-formed shape.
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        br#"{"alg":"RSA-OAEP","enc":"A128GCM","kid":"x"}"#,
    );
    let bogus = format!("{header}.e.i.c.t");
    let res = post_credential(&state, &token, "application/jwt", bogus).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = body_json(res).await;
    assert_eq!(body["error"], serde_json::json!("invalid_credential_request"));
}

// ---------------------------------------------------------------------------
// VCI-0101 — Encrypted Messages (L1188): the JWE MUST carry the selected key's
// `kid`. Every published key has one, so an absent or unknown `kid` is refused
// rather than triggering trial decryption.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0101_a_missing_kid_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let meta = serde_json::to_value(foundry_issuer::build_issuer_metadata(
        &state.config,
        &state.request_decryption_keys,
    ))
    .unwrap();
    let jwk = meta["credential_request_encryption"]["jwks"]["keys"][0].clone();
    // The four-argument form deliberately writes no `kid`.
    let jwe = foundry_core::crypto::jwe::encrypt_compact(
        &serde_json::json!({ "credential_configuration_id": "pid" }),
        &jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// VCI-0135 — Credential Issuer Metadata (L1374): only advertised `enc` values
// are accepted on the Credential Request.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0135_an_unadvertised_request_enc_is_rejected() {
    let (mut state, _dir) = setup_with_encryption().await;
    // Narrow the advertised set to A128GCM, then send A256GCM.
    let mut cfg = (*state.config).clone();
    if let Some(re) = cfg.issuer.request_encryption.as_mut() {
        re.enc_values_supported = vec!["A128GCM".to_string()];
    }
    let keys = state.request_decryption_keys.clone();
    state = AppState::new(state.storage.clone(), std::sync::Arc::new(cfg));
    // Rebuilding AppState drops the keys, so reattach the same ones.
    let state = state.with_request_decryption_keys(
        keys.iter()
            .map(|_| unreachable!("see note below"))
            .collect::<Vec<_>>(),
    );
    let _ = state;
}
```

> **`DecryptionKey` is not `Clone`, so the snippet above cannot reattach the same keys.** Do **not** implement `Clone` for it (a clonable private key is a footgun). Instead, extend `setup_with_encryption` in this file to take the advertised `enc` list as a parameter and build the state once:
>
> ```rust
> async fn setup_with_encryption_enc(
>     request_enc: Vec<String>,
>     response_enc: Vec<String>,
>     required: bool,
> ) -> (AppState, tempfile::TempDir) { /* as setup_with_encryption, but with these lists */ }
> ```
>
> then write `vci_0135_an_unadvertised_request_enc_is_rejected` as:
>
> ```rust
> #[tokio::test]
> async fn vci_0135_an_unadvertised_request_enc_is_rejected() {
>     let (state, _dir) =
>         setup_with_encryption_enc(vec!["A128GCM".into()], vec!["A128GCM".into()], false).await;
>     let token = issue_pre_auth_offer_and_get_access_token(&state).await;
>     let jwe = encrypt_to_issuer(
>         &state,
>         &serde_json::json!({ "credential_configuration_id": "pid" }),
>         "A256GCM",
>     )
>     .await;
>     let res = post_credential(&state, &token, "application/jwt", jwe).await;
>     assert_eq!(res.status(), StatusCode::BAD_REQUEST);
> }
> ```
>
> Define `setup_with_encryption()` as `setup_with_encryption_enc(both, both, false)` so the other tests read cleanly.

Then the four policy rejections:

```rust
// ---------------------------------------------------------------------------
// VCI-0063 — Credential Request (L960): Credential Request encryption MUST be
// used whenever `credential_response_encryption` is included, to prevent
// substitution.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0063_response_encryption_over_plaintext_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let body = serde_json::json!({
        "credential_configuration_id": "pid",
        "credential_response_encryption": { "jwk": wallet_enc_jwk_json(), "enc": "A128GCM" },
    });
    let res = post_credential(
        &state,
        &token,
        "application/json",
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = body_json(res).await;
    assert_eq!(body["error"], serde_json::json!("invalid_credential_request"));
}

// ---------------------------------------------------------------------------
// VCI-0054 — Credential Request (L854): `credential_response_encryption.jwk` is
// REQUIRED, and Encrypted Messages (L1188) requires an `alg` on it.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0054_a_response_jwk_without_alg_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let mut jwk = wallet_enc_jwk_json();
    if let Some(o) = jwk.as_object_mut() {
        o.remove("alg");
    }
    let jwe = encrypt_to_issuer(
        &state,
        &serde_json::json!({
            "credential_configuration_id": "pid",
            "credential_response_encryption": { "jwk": jwk, "enc": "A128GCM" },
        }),
        "A128GCM",
    )
    .await;
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// VCI-0055 — Credential Request (L855): `credential_response_encryption.enc` is
// REQUIRED, and only advertised values are honoured (L1379).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0055_an_unadvertised_response_enc_is_rejected() {
    let (state, _dir) =
        setup_with_encryption_enc(vec!["A128GCM".into()], vec!["A128GCM".into()], false).await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let jwe = encrypt_to_issuer(
        &state,
        &serde_json::json!({
            "credential_configuration_id": "pid",
            "credential_response_encryption": { "jwk": wallet_enc_jwk_json(), "enc": "A256GCM" },
        }),
        "A128GCM",
    )
    .await;
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// VCI-0056 — Credential Request (L856): if `zip` is absent, compression MUST
// NOT be used. foundry advertises no `zip_values_supported`, so a present `zip`
// is refused rather than silently ignored.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0056_a_present_zip_is_rejected() {
    let (state, _dir) = setup_with_encryption().await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let jwe = encrypt_to_issuer(
        &state,
        &serde_json::json!({
            "credential_configuration_id": "pid",
            "credential_response_encryption": {
                "jwk": wallet_enc_jwk_json(), "enc": "A128GCM", "zip": "DEF",
            },
        }),
        "A128GCM",
    )
    .await;
    let res = post_credential(&state, &token, "application/jwt", jwe).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// OpenID4VCI Encrypted Messages (L1192): when encryption was required but the
// received message is unencrypted, it is rejected.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn required_request_encryption_rejects_a_plaintext_request() {
    let (state, _dir) = setup_with_encryption_enc(
        vec!["A128GCM".into(), "A256GCM".into()],
        vec!["A128GCM".into(), "A256GCM".into()],
        true,
    )
    .await;
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        "application/json",
        r#"{"credential_configuration_id":"pid"}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = body_json(res).await;
    assert_eq!(body["error"], serde_json::json!("invalid_credential_request"));
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo test -p foundry --test conformance_http
```

Expected: PASS, including every pre-existing test in the file.

- [ ] **Step 3: Scoped gate and commit**

```bash
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
git add crates/foundry/tests/conformance_http.rs
git commit -m "test(conformance): HTTP rejection matrix for credential encryption"
```

---

### Task 7: `quickstart`, metadata absence, and the redaction gate

**Files:**
- Modify: `crates/foundry/src/commands.rs` (`quickstart`, `QUICKSTART_CONFIG`)
- Modify: `crates/foundry/tests/quickstart.rs`
- Modify: `crates/foundry/tests/wallet_metadata.rs`
- Modify: `crates/foundry/tests/logging_redaction.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–5.
- Produces: no new public API. `quickstart` gains a generated `keys/issuer_request_enc.pem` and commented-out config blocks.

- [ ] **Step 1: Write the failing tests**

In `crates/foundry/tests/quickstart.rs`:

```rust
#[test]
fn quickstart_generates_a_request_encryption_key_but_leaves_it_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("config.yaml");
    foundry::commands::quickstart(dir.path(), &cfg_path).unwrap();

    assert!(
        dir.path().join("keys/issuer_request_enc.pem").exists(),
        "an operator enabling request encryption must not have to generate a key by hand"
    );
    let text = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(
        text.contains("# request_encryption:"),
        "the block must ship commented out so quickstart stays default-off"
    );

    // The emitted config must still parse and validate with encryption absent.
    let cfg = foundry_core::config::Config::load(&cfg_path).unwrap();
    cfg.validate().unwrap();
    assert!(cfg.issuer.request_encryption.is_none());
    assert!(cfg.issuer.response_encryption.is_none());
}
```

In `crates/foundry/tests/wallet_metadata.rs`:

```rust
#[tokio::test]
async fn metadata_omits_encryption_objects_when_unconfigured() {
    let app = test_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // The zero-blast-radius guarantee: an unconfigured deployment's document is
    // exactly what it was before encryption existed.
    assert!(json.get("credential_request_encryption").is_none());
    assert!(json.get("credential_response_encryption").is_none());
}
```

In `crates/foundry/tests/logging_redaction.rs` — the file already has `lock_flag()`, `capture_at_trace()`, `setup()`, `create_proof()`, and a positive control. Add a setup that enables encryption plus two tests:

```rust
/// `setup()` plus both encryption blocks and one generated decryption key.
async fn setup_with_encryption() -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
        keys: vec!["issuer_request_enc".to_string()],
        enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
        encryption_required: false,
    });
    cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
        enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
        encryption_required: false,
    });
    let km =
        foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256).unwrap();
    let key =
        foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes()).unwrap();
    let state = AppState::new(state.storage.clone(), Arc::new(cfg))
        .with_request_decryption_keys(vec![key]);
    (state, dir)
}

/// Drive an encrypted issuance and return the uniquely identifiable secrets that
/// must not appear in the log: the wallet's ephemeral encryption JWK `x`
/// coordinate, and the issued credential string.
async fn drive_encrypted_issuance(state: &AppState) -> (String, String) {
    // Build the request JWE against the published JWKS, POST it, decrypt the
    // response, and return (wallet_jwk_x, issued_credential). Mirror
    // `crates/foundry/tests/credential_encryption.rs`'s
    // `an_encrypted_request_yields_an_encrypted_response` exactly — same key
    // generation, same metadata read, same decrypt — and return the two values
    // instead of asserting on them.
    unimplemented!("transcribe from tests/credential_encryption.rs")
}

#[tokio::test]
async fn encrypted_issuance_never_logs_the_decrypted_request_or_the_wallet_jwk() {
    let _guard = lock_flag().await;
    let (_sub, capture) = capture_at_trace();
    let (state, _dir) = setup_with_encryption().await;
    let (wallet_jwk_x, credential) = drive_encrypted_issuance(&state).await;
    let log = capture.dump();
    assert!(
        !log.contains(&wallet_jwk_x),
        "the wallet's ephemeral encryption JWK must never be logged (root AGENTS.md §4.5)"
    );
    assert!(
        !log.contains(&credential),
        "the plaintext Credential Response must never be logged"
    );
}

#[tokio::test]
async fn encrypted_issuance_leaks_nothing_even_with_sensitive_payloads_enabled() {
    let _guard = lock_flag().await;
    foundry_core::obs::set_sensitive(true);
    let (_sub, capture) = capture_at_trace();
    let (state, _dir) = setup_with_encryption().await;
    let (wallet_jwk_x, _credential) = drive_encrypted_issuance(&state).await;
    foundry_core::obs::set_sensitive(false);
    let log = capture.dump();
    assert!(
        !log.contains(&wallet_jwk_x),
        "key material is never unlocked by the sensitive-payloads flag"
    );
}
```

> `drive_encrypted_issuance` is marked `unimplemented!()` above **only** to show its signature. Transcribe the real body from `tests/credential_encryption.rs` before running — an `unimplemented!()` left in place is a task failure. Match `capture.dump()` to whatever the existing tests in this file call on `CaptureHandle`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry --test quickstart --test wallet_metadata --test logging_redaction
```

Expected: FAIL — the key file is not generated, the config has no commented block, and the redaction tests do not compile until `drive_encrypted_issuance` is transcribed.

- [ ] **Step 3: Generate the key in `quickstart`**

In `crates/foundry/src/commands.rs`, after the existing leaf-per-key loop:

```rust
    // The Credential Request decryption key is an ECDH-ES key agreement key, not
    // a signing key, so it gets no x5c leaf: OpenID4VCI L1373 publishes it as a
    // bare JWK in `credential_request_encryption.jwks`. Generated unconditionally
    // so enabling the (commented-out) config block needs no extra step; the
    // `keys:` entry's `alg: ES256` names the key material, since
    // `validate_key_material` parses every entry's `alg` as a signature
    // algorithm.
    let enc = foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)?;
    std::fs::write(
        keys_dir.join("issuer_request_enc.pem"),
        enc.private_pem.as_bytes(),
    )?;
```

- [ ] **Step 4: Extend `QUICKSTART_CONFIG`**

Add the key entry to the `keys:` block:

```yaml
  issuer_request_enc:
    private_key: ./keys/issuer_request_enc.pem
    alg: ES256
```

and the two commented blocks under `issuer:`, after `status_list:`:

```yaml
  # OpenID4VCI Credential Request / Response encryption on top of TLS
  # (§Credential Request L848, §Credential Response L960, §Encrypted Messages
  # L1183). Both default to OFF; uncomment to enable. `request_encryption` must
  # be enabled for `response_encryption` to be usable, because L960 requires a
  # request carrying `credential_response_encryption` to itself be encrypted.
  # request_encryption:
  #   keys: [issuer_request_enc]
  #   enc_values_supported: [A128GCM, A256GCM]
  #   encryption_required: false
  # response_encryption:
  #   enc_values_supported: [A128GCM, A256GCM]
  #   encryption_required: false
```

- [ ] **Step 5: Transcribe `drive_encrypted_issuance`**

Replace the `unimplemented!()` with the real body, copied from
`tests/credential_encryption.rs::an_encrypted_request_yields_an_encrypted_response`, returning `(wallet_jwk_x, credential)` instead of asserting.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test -p foundry --test quickstart --test wallet_metadata --test logging_redaction
```

Expected: PASS, including the file's existing positive control
(`payload_logging_really_unlocks_the_payload_when_enabled`), which proves the harness is not inert.

- [ ] **Step 7: Scoped gate and commit**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
git add -A
git commit -m "feat(cli): quickstart encryption key; test metadata absence and redaction"
```

---

### Task 8: Real-subprocess end-to-end coverage

**Files:**
- Modify: `crates/foundry/tests/e2e_full_flow.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–7. This is the only layer that exercises `quickstart`-generated key material, `Config::load_request_decryption_keys`, and startup validation through the real binary.

- [ ] **Step 1: Write the test**

Append to `crates/foundry/tests/e2e_full_flow.rs`, reusing its existing `free_port`, `ServerGuard`, and quickstart/boot helpers. Read the top of that file first to match the existing boot helper's name and signature.

```rust
/// The encrypted `/credential` round trip through the real binary.
///
/// Distinct from the in-process tests: this is the only place where the config
/// file, the `quickstart`-generated PEM, `Config::load_request_decryption_keys`,
/// and the served metadata document all participate. A `kid` derived from a key
/// the server actually loaded from disk is the thing that cannot be faked
/// in-process.
#[tokio::test]
#[ignore = "real subprocess E2E; run with --ignored"]
async fn e2e_encrypted_credential_request_and_response() {
    // 1. quickstart into a temp dir, then edit the generated config to
    //    uncomment both encryption blocks. Editing the emitted file rather than
    //    writing a fresh one is deliberate: it proves the shipped commented
    //    block is syntactically correct once uncommented.
    // 2. Boot `foundry serve` on a probe-and-released port, as the existing
    //    tests do.
    // 3. GET /.well-known/openid-credential-issuer; assert
    //    `credential_request_encryption.jwks.keys[0].kid` is present and
    //    `credential_response_encryption.alg_values_supported == ["ECDH-ES"]`.
    // 4. Create an offer over the admin API and redeem it for an access token,
    //    exactly as `full_flow_end_to_end` does.
    // 5. Build the Credential Request JWE with
    //    `encrypt_compact_with_kid(.., "ECDH-ES", "A256GCM", Some(kid))`,
    //    including `credential_response_encryption` with a freshly generated
    //    wallet JWK and `enc: "A128GCM"`.
    // 6. POST it with `Content-Type: application/jwt`; assert 200 and
    //    `Content-Type: application/jwt` on the response.
    // 7. Decrypt with the wallet's private JWK; assert the claims carry
    //    `credentials[0].credential` and that it parses as an SD-JWT VC
    //    (three dot-separated segments plus disclosures), matching what the
    //    existing plaintext flow asserts.
}
```

Write the body out fully — the comment block above is the specification for it, not a placeholder to leave in the file. Uncommenting the config blocks is a string substitution on the file `quickstart` wrote:

```rust
    let text = std::fs::read_to_string(&cfg_path).expect("read quickstart config");
    let enabled = text
        .replace("  # request_encryption:", "  request_encryption:")
        .replace("  #   keys: [issuer_request_enc]", "    keys: [issuer_request_enc]")
        .replace(
            "  #   enc_values_supported: [A128GCM, A256GCM]",
            "    enc_values_supported: [A128GCM, A256GCM]",
        )
        .replace("  #   encryption_required: false", "    encryption_required: false")
        .replace("  # response_encryption:", "  response_encryption:");
    std::fs::write(&cfg_path, enabled).expect("write enabled config");
```

> The two `enc_values_supported` / `encryption_required` comment lines appear **twice** in the template (once per block), and `str::replace` replaces every occurrence — which is exactly what is wanted here. Assert afterwards that the edited file parses:
>
> ```rust
> let cfg = foundry_core::config::Config::load(&cfg_path).expect("edited config parses");
> assert!(cfg.issuer.request_encryption.is_some());
> assert!(cfg.issuer.response_encryption.is_some());
> ```

- [ ] **Step 2: Run it**

```bash
cargo test -p foundry --test e2e_full_flow -- --ignored
```

Expected: PASS, both the pre-existing `full_flow_end_to_end` and the new case.

- [ ] **Step 3: Scoped gate and commit**

```bash
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
git add crates/foundry/tests/e2e_full_flow.rs
git commit -m "test(e2e): encrypted credential request and response through the real binary"
```

---

### Task 9: OpenAPI, conformance report, documentation, and the full gate

**Files:**
- Modify: `openapi-wallet.json` (regenerated, not hand-edited)
- Modify: `docs/conformance/openid4vc-conformance.md`
- Modify: `README.md`
- Modify: `AGENTS.md` (§4.5 never-logged list)
- Modify: `crates/foundry-core/AGENTS.md`
- Modify: `crates/foundry-issuer/AGENTS.md`
- Modify: `crates/foundry/AGENTS.md`
- Create: `docs/superpowers/changes/2026-08-04-credential-request-response-encryption.md`

**Interfaces:**
- Consumes: everything from Tasks 1–8. Produces no code.

- [ ] **Step 1: Regenerate the OpenAPI specs**

Read the regeneration command in `crates/foundry/AGENTS.md` (Gotchas section, "The `openapi` CLI subcommand defaults to the ADMIN spec") — **do not guess it**. Both specs are regenerated because `tests/openapi_endpoints.rs` compares the committed files against freshly generated ones and fails on drift.

Verify the new surface landed:

```bash
grep -c 'CredentialRequestEncryption' openapi-wallet.json
grep -c 'application/jwt' openapi-wallet.json
```

Expected: both `>= 1`.

```bash
cargo test -p foundry --test openapi_endpoints
```

Expected: PASS.

- [ ] **Step 2: Update the conformance report**

In `docs/conformance/openid4vc-conformance.md`, flip these sixteen rows from `not-implemented` to `conforming`, filling the Evidence and Test columns. The table's column order is `ID | Clause | Requirement | Actor | Verdict | Evidence | Test`.

| Row | Evidence (new text) | Test |
|---|---|---|
| VCI-0054 (L854) | `check_encryption_policy` (credential.rs) rejects a `credential_response_encryption` whose `jwk` carries no `alg` (L1188 makes it mandatory) | `vci_0054_a_response_jwk_without_alg_is_rejected` |
| VCI-0055 (L855) | `check_encryption_policy` rejects an `enc` outside `issuer.response_encryption.enc_values_supported` | `vci_0055_an_unadvertised_response_enc_is_rejected` |
| VCI-0056 (L856) | No `zip_values_supported` is advertised, and `check_encryption_policy` rejects a present `zip` rather than ignoring it | `vci_0056_a_present_zip_is_rejected` |
| VCI-0063 (L960) | `check_encryption_policy` rejects `credential_response_encryption` on a request that did not itself arrive encrypted; `request_was_encrypted` is threaded from the `MaybeEncrypted` extractor | `vci_0063_response_encryption_over_plaintext_is_rejected` |
| VCI-0066 (L969) | `credential_handler` (server.rs) encrypts the Credential Response with `encrypt_compact_with_kid` using the wallet's `jwk`/`enc` and returns `CredentialResponseBody::Jwt` | `an_encrypted_request_yields_an_encrypted_response` |
| VCI-0097 (L1186) | `decrypt_compact` (foundry-core `crypto/jwe.rs`) decodes the message as a JWT via `josekit::jwt::decode_with_decrypter`; the encrypt side uses `encode_with_encrypter` | `round_trips_an_encrypted_credential_request` |
| VCI-0098 (L1186) | `MaybeEncrypted` accepts an encrypted body only under `application/jwt`, and `CredentialResponseBody::Jwt` sets that Content-Type on the response | `vci_0098_text_plain_is_still_415_with_encryption_enabled`, `an_encrypted_request_yields_an_encrypted_response` |
| VCI-0099 (L1188) | `DecryptionKey::published_jwk` stamps `alg: "ECDH-ES"` on every published JWK; `check_encryption_policy` requires `alg` on the wallet's response JWK | `publishes_the_request_jwks_with_annotated_kids`, `vci_0054_a_response_jwk_without_alg_is_rejected` |
| VCI-0100 (L1188) | `decrypt_compact` rejects any JWE `alg` other than `ECDH-ES` before key agreement | `vci_0100_a_non_ecdh_es_alg_is_rejected` |
| VCI-0101 (L1188) | `decrypt_compact` requires the JWE `kid` and matches it against the loaded keys; `credential_handler` echoes the wallet JWK's `kid` on the response | `vci_0101_a_missing_kid_is_rejected` |
| VCI-0134 (L1373) | `build_issuer_metadata` publishes `credential_request_encryption.jwks` from the loaded `DecryptionKey`s, each `kid` an RFC 7638 thumbprint and therefore unique by construction | `publishes_the_request_jwks_with_annotated_kids` |
| VCI-0135 (L1374) | `enc_values_supported` is published from config, validated non-empty and a subset of `{A128GCM, A256GCM}` at startup, and enforced in `decrypt_compact` | `vci_0135_an_unadvertised_request_enc_is_rejected`, `advertised_enc_values_must_be_supported` |
| VCI-0136 (L1376) | `encryption_required` is a non-`Option` bool on `CredentialRequestEncryption` and is always serialised | `publishes_the_request_jwks_with_annotated_kids` |
| VCI-0137 (L1378) | `alg_values_supported` is always `["ECDH-ES"]`, fixed rather than configurable because `encrypt_compact_with_kid` supports no other key-management algorithm | `publishes_response_encryption_with_ecdh_es_only` |
| VCI-0138 (L1379) | `enc_values_supported` is published from config and validated non-empty at startup | `publishes_response_encryption_with_ecdh_es_only` |
| VCI-0139 (L1381) | `encryption_required` is a non-`Option` bool on `CredentialResponseEncryption` and is always serialised | `publishes_response_encryption_with_ecdh_es_only` |

Then **make the deferred-endpoint exclusion explicit** rather than leaving a reader to infer it. Amend the Evidence text of VCI-0084 and each of VCI-0088–0096 so it names the actual blocker, e.g.:

> foundry exposes no Deferred Credential Endpoint at all, so this clause is unreachable. Encryption is **not** the blocker — Credential and Credential Response encryption are implemented (see VCI-0054…0066); building the endpoint is separate work.

Leave VCI-0060, VCI-0061, VCI-0088, and VCI-0089 as `out-of-scope` wallet obligations, unchanged.

**Add no new GAP entries.** Omitting `zip_values_supported` is conformance by L856/L1379, not a gap. Record the one deliberate deviation — §5.3 check 3, refusing a response-encryption request when `issuer.response_encryption` is unconfigured — as a note in the VCI-0066 Evidence cell, since it is stricter than the specification rather than weaker.

```bash
cargo test -p foundry --test conformance_report
```

Expected: PASS (that test validates the table's structure).

- [ ] **Step 3: Update `README.md`**

Add to the configuration reference, next to the DPoP and wallet-attestation blocks, a subsection documenting `issuer.request_encryption` and `issuer.response_encryption`: every field, its default, the requirement that the referenced `keys:` entry uses `alg: ES256` (naming the key material) and no `x5c`, that the `kid` is derived and therefore not configurable, that multiple keys enable zero-downtime rotation, and that `response_encryption.encryption_required: true` requires `request_encryption` to be present.

Add to the "Logging & Observability" field list: `request_encrypted`, `response_encrypted`, `enc`, `request_kid`. Add to that section's never-logged list the five items from the design §8.

- [ ] **Step 4: Update the AGENTS.md files**

Root `AGENTS.md` §4.5 — extend the "Never logged" sentence with: the raw compact JWE request body, the decrypted Credential Request, the plaintext Credential Response when encryption was requested, and the wallet's `credential_response_encryption.jwk`.

`crates/foundry-core/AGENTS.md` — module map: `crypto/jwe.rs` now also decrypts and owns `DecryptionKey`. Gotchas: add the §3.2 constraint — `validate_key_material` parses **every** `keys:` entry's `alg` as a `SignatureAlgorithm`, so an encryption key's entry says `ES256` (the key material) while its *published* JWK says `ECDH-ES`.

`crates/foundry-issuer/AGENTS.md` — `handle_credential_request` gained a trailing `request_was_encrypted: bool`; `check_encryption_policy` is the single gate for the L960/L969/L1192 rules; `build_issuer_metadata` gained a `&[DecryptionKey]` parameter.

`crates/foundry/AGENTS.md` — module map: new `extract.rs` (`MaybeEncrypted`, `MaybeEncryptedRejection`, `CredentialResponseBody`). Gotchas: `MaybeEncrypted` consumes the body and must be `credential_handler`'s final argument; the extractor owns a **second** error mapper because a rejection short-circuits before `credential_error_response` — and it delegates to `wallet_error_response` so §4.5's one-record rule holds. Also note `serve` now takes the loaded decryption keys.

- [ ] **Step 5: Write the change record**

Create `docs/superpowers/changes/2026-08-04-credential-request-response-encryption.md`: what shipped, the default-off posture, the sixteen closed conformance rows, the one deliberate deviation (§5.3 check 3), the two signature changes external callers would notice (`build_issuer_metadata`, `handle_credential_request`), and the roadmap position (Google Wallet compatibility item **C**; items **D** and **E** remain).

- [ ] **Step 6: Run the full gate**

This is the branch's single full gate (root `AGENTS.md` §5.3). Capture to disk and grep, per §5.6 — a bare `tail` of a workspace run can silently drop an earlier binary's `FAILED`:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace 2>&1 | tee /tmp/enc-test.log
grep -c 'FAILED' /tmp/enc-test.log        # expect 0 / no output
grep '^test result:' /tmp/enc-test.log    # one line per binary; all must say ok
cargo test -p foundry --test e2e_full_flow -- --ignored 2>&1 | tee /tmp/enc-e2e.log
grep '^test result:' /tmp/enc-e2e.log
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee /tmp/enc-clippy.log
grep -c 'warning\|error' /tmp/enc-clippy.log
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "docs: conformance, OpenAPI, and operator docs for credential encryption"
```

Then request the whole-branch review (`final-reviewer`). Do **not** re-run the full gate after merging (root `AGENTS.md` §5.4).

---

## Plan Self-Review Notes

**Spec coverage.** Every design section maps to a task: §3.1–3.2 → Task 2 Step 3; §3.3 → Task 1 Step 3 + Task 2 Step 5; §3.4 → Task 2 Step 4; §3.5 → Task 7 Steps 3–4; §4 → Task 3; §5.1 → Task 5 Step 5; §5.2 → Task 1 Step 4; §5.3 → Task 4 Step 4; §6 → Task 5 Step 7; §7.1 → Task 4 Step 4 (reuses `InvalidCredentialRequest`); §7.2 → Task 5 Step 5; §8 → Task 5 Step 6 (startup log, span fields) + Task 7 Step 1 (redaction tests); §9 → Tasks 1, 2, 4, 5, 6, 7, 8; §10 → Task 9 Step 6; §11 → Task 9 Steps 1–5; §12 risks are all mitigated in-task.

**Type consistency.** `DecryptionKey` is constructed in Task 1, loaded in Task 2, consumed by `build_issuer_metadata` in Task 3 and by `decrypt_compact` in Task 5. `request_was_encrypted` is named identically in Task 4's engine signature and Task 5's `MaybeEncrypted::was_encrypted` destructuring. `encrypt_compact_with_kid`'s five-argument form is used only in Tasks 5, 6, 7, 8 — never the four-argument `encrypt_compact`, except deliberately in Task 6's `vci_0101_a_missing_kid_is_rejected` and Task 1's regression guard.

**Two things a reviewer should check hardest.**

1. **`DecryptionKey` is not `Clone` by design** (a clonable private key is a footgun), which is why Task 6 parameterises its setup helper instead of rebuilding `AppState`. If an implementer adds `#[derive(Clone)]` to make a test easier, reject it.
2. **The extractor's rejection mapper is a second error mapper** (design §7.2). It must emit exactly one log record per rejection and must delegate the `Issuance` arm to `wallet_error_response` rather than reimplementing the status/body mapping.

**Two placeholders deliberately left as prose-with-a-transcription-instruction**, both because the body is a verbatim copy of code written earlier in the plan and duplicating it would guarantee drift: Task 7's `drive_encrypted_issuance` and Task 8's E2E body. Both carry an explicit instruction that leaving them unimplemented is a task failure.
