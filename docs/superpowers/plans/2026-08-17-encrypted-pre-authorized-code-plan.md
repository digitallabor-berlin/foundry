# Encrypted Pre-Authorized Code Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accept the Google Wallet profile's `encrypted_pre-authorized_code` Token Request parameter — a pre-authorized code wrapped as a JWS inside a JWE — behind a configuration switch that is off by default, and make the access-token lifetime configurable.

**Architecture:** A new `foundry-issuer` module owns the whole envelope-opening pipeline and exposes one entry point returning a plain `String`. The existing pre-authorized code grant handler consumes that string and never learns encryption happened. The outer JWE reuses the issuer's existing `credential_request_encryption` keys; the inner JWS is verified against the `cnf.jwk` of the Client Attestation JWT that already authenticated the request.

**Tech Stack:** Rust 2024, `josekit` 0.10.3 (JOSE), `serde`/`serde_json`, `sha2`, `axum`, `utoipa` (OpenAPI), `tokio` + `tempfile` (tests).

**Spec:** [`docs/superpowers/specs/2026-08-17-encrypted-pre-authorized-code-design.md`](../specs/2026-08-17-encrypted-pre-authorized-code-design.md)

## Global Constraints

These bind every task. They are the repository's own rules (root `AGENTS.md`), restated with the exact values this work must honour.

- **No panics in request paths.** No `.unwrap()`, `.expect()`, `panic!()`, `unreachable!()` in any non-test code under `crates/foundry-issuer/`, `crates/foundry-core/src/crypto/`, or `crates/foundry/src/`. Return typed `Result`s. Unwraps are permitted **only** inside `#[cfg(test)]` and under `tests/`.
- **Every `#[tracing::instrument]` MUST carry `skip_all`.** Fields are opt-in.
- **Never logged, at any level, under any flag:** the raw `encrypted_pre-authorized_code` value, the decrypted inner JWS (compact or parsed), the extracted pre-authorized code, the envelope's `jti`, and any private JWK. Loggable: the resolved mode, a boolean "member was present", and a `kid` (an RFC 7638 thumbprint of a *public* key).
- **Cite the spec in code comments.** Protocol logic names its source, e.g. `// OpenID4VCI L1188 — JWE alg/kid`. Behaviour justified **only** by the vendor profile MUST say so explicitly (root `AGENTS.md` §4.4).
- **Canonical parameter name is `encrypted_pre-authorized_code`** — hyphen before `authorized`, matching OpenID4VCI's `pre-authorized_code`. The profile's worked example spells it `encrypted_pre-authorization_code`; that spelling is **not** accepted.
- **Default is OFF.** `EncryptedPreAuthCodeConfig::default()` MUST yield `Mode::Disabled`. `Mode`'s own `Default` is `Optional`, so a bare `#[serde(default)]` on a `Mode` field would silently enable the feature. Task 2 has a test dedicated to this.
- **Inner JWS `alg` MUST be `ES256`** (HAIP-0088). Outer JWE `alg` MUST be `ECDH-ES` (already enforced by `foundry-core`).
- **Scoped verification gate** (root `AGENTS.md` §5.1) at every task boundary — never `cargo test --workspace`. Each task names its own crate set. The full gate of §5.3 runs **once**, at the end of the branch.

---

### Task 1: Raw-plaintext JWE decryption in `foundry-core`

`decrypt_compact` parses its plaintext as a JWT claims set, so it cannot carry a nested JWS. Extract the header checks into a sibling that returns raw bytes, and make `decrypt_compact` a thin wrapper. No existing caller changes behaviour.

**Files:**

- Modify: `crates/foundry-core/src/crypto/jwe.rs:136-196` (`decrypt_compact`)
- Test: `crates/foundry-core/src/crypto/jwe.rs` (inline `#[cfg(test)] mod tests`, which already exists around line 390)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:

  ```rust
  pub fn decrypt_compact_to_bytes(
      jwe: &str,
      keys: &[DecryptionKey],
      allowed_enc: &[String],
  ) -> Result<Vec<u8>, CryptoError>
  ```

  Task 4 calls this. `decrypt_compact` keeps its exact current signature
  `fn(&str, &[DecryptionKey], &[String]) -> Result<Value, CryptoError>`.

- [ ] **Step 1: Write the failing test**

Add to the existing `mod tests` in `crates/foundry-core/src/crypto/jwe.rs`. Read the helpers around line 398 first (`both_gcm()` and the key-generation pattern) so the new tests match their style.

```rust
    /// Test-only: encrypt arbitrary bytes to `recipient`, echoing its `kid`.
    /// Production code only ever *decrypts* these, so this stays in tests.
    fn encrypt_bytes_for_test(payload: &[u8], recipient: &DecryptionKey, enc: &str) -> String {
        let pub_jwk =
            Jwk::from_bytes(&serde_json::to_vec(&recipient.published_jwk()).unwrap()).unwrap();
        let encrypter = josekit::jwe::ECDH_ES.encrypter_from_jwk(&pub_jwk).unwrap();

        let mut header = JweHeader::new();
        header.set_algorithm("ECDH-ES");
        header.set_content_encryption(enc);
        header.set_key_id(recipient.kid());

        josekit::jwe::serialize_compact(payload, &header, &encrypter).unwrap()
    }

    fn test_decryption_key() -> DecryptionKey {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        DecryptionKey::from_pem(&kp.to_pem_private_key()).unwrap()
    }

    /// The nested-JWS case: the JWE plaintext is a compact JWS string, which is
    /// NOT JSON and therefore cannot go through `decrypt_compact`.
    #[test]
    fn decrypt_compact_to_bytes_returns_a_non_json_plaintext_verbatim() {
        let key = test_decryption_key();
        let plaintext = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln";
        let jwe = encrypt_bytes_for_test(plaintext.as_bytes(), &key, "A128GCM");

        let out = decrypt_compact_to_bytes(&jwe, std::slice::from_ref(&key), &both_gcm()).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), plaintext);

        // And the JSON wrapper must reject the same input -- which is exactly
        // why the byte-returning sibling has to exist.
        assert!(decrypt_compact(&jwe, std::slice::from_ref(&key), &both_gcm()).is_err());
    }

    /// The three header checks are conformance clauses (L1188 / VCI-0101 /
    /// VCI-0135), not an artifact of JSON parsing, so they must apply here too.
    #[test]
    fn decrypt_compact_to_bytes_enforces_the_same_header_checks() {
        let key = test_decryption_key();
        let jwe = encrypt_bytes_for_test(b"anything", &key, "A128GCM");

        let only_256 = vec!["A256GCM".to_string()];
        assert!(decrypt_compact_to_bytes(&jwe, std::slice::from_ref(&key), &only_256).is_err());
        assert!(decrypt_compact_to_bytes(&jwe, &[], &both_gcm()).is_err());
        assert!(
            decrypt_compact_to_bytes("not.a.jwe", std::slice::from_ref(&key), &both_gcm()).is_err()
        );
    }
```

Add `use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};` and `use josekit::jwk::KeyPair as _;` inside `mod tests` if not already present.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-core --lib crypto::jwe
```

Expected: FAIL — `cannot find function decrypt_compact_to_bytes in this scope`.

- [ ] **Step 3: Implement `decrypt_compact_to_bytes` and rewrite `decrypt_compact` as its wrapper**

The entire existing header-check block in `decrypt_compact` (lines 145-188) — `alg`, `enc`, `kid`, key selection, decrypter construction, each with its existing conformance comment — **moves verbatim** into the new function. Do not reword those comments; they carry citations other documents reference.

```rust
/// Decrypt a compact-serialization JWE to its **raw plaintext bytes**.
///
/// This is the primitive; [`decrypt_compact`] is the JSON-parsing wrapper over
/// it. Two callers need two different plaintext shapes:
///
/// * the Credential Request (OpenID4VCI L1186) is a JWT claims set — JSON;
/// * the Google Wallet profile's `encrypted_pre-authorized_code` is a nested
///   compact JWS, which is not JSON and must not be parsed as such.
///
/// The three header checks below are conformance clauses and apply to both.
pub fn decrypt_compact_to_bytes(
    jwe: &str,
    keys: &[DecryptionKey],
    allowed_enc: &[String],
) -> Result<Vec<u8>, CryptoError> {
    // ... the existing lines 137-188 of decrypt_compact, verbatim and in
    // order: the is_empty guard, protected_header, the alg check, the enc
    // check, the kid check, the key lookup, the jwk/decrypter construction ...

    let (payload, _header) = josekit::jwe::deserialize_compact(jwe, &decrypter)
        .map_err(|e| CryptoError::Jwe(e.to_string()))?;

    Ok(payload)
}
```

And `decrypt_compact` becomes — keeping its existing doc comment block (lines 121-135) untouched above it:

```rust
pub fn decrypt_compact(
    jwe: &str,
    keys: &[DecryptionKey],
    allowed_enc: &[String],
) -> Result<Value, CryptoError> {
    let plaintext = decrypt_compact_to_bytes(jwe, keys, allowed_enc)?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| CryptoError::Jwe(format!("decrypted claims are not JSON: {e}")))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-core --lib crypto::jwe
```

Expected: PASS, **including every pre-existing `decrypt_compact` test** (lines ~398-496). Those are the regression guard for this refactor — if one fails, the extraction changed behaviour and the code must be corrected, never the test.

- [ ] **Step 5: Scoped gate**

`foundry-core`'s `crypto/` module is consumed by both engines (root `AGENTS.md` §5.2):

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry-verifier
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-core/src/crypto/jwe.rs
git commit -m "feat(core): add decrypt_compact_to_bytes for nested-JWS payloads

decrypt_compact parses its plaintext as a JWT claims set, so it cannot
carry the compact JWS the Google Wallet profile nests inside a JWE.
Extract the alg/enc/kid conformance checks into a byte-returning sibling
and make decrypt_compact a thin JSON-parsing wrapper over it."
```

---

### Task 2: Configuration surface and fail-closed validation

Two new `IssuerConfig` fields plus the load-time rules that stop the feature being switched on into a configuration where it could never succeed.

**Files:**

- Modify: `crates/foundry-core/src/config/model.rs` (add `EncryptedPreAuthCodeConfig` after `AndroidKeystoreConfig`, which ends around line 262; add two fields to `IssuerConfig` at lines 128-152)
- Modify: `crates/foundry-core/src/config/mod.rs` (re-export the new type alongside `AttestationMode`/`DpopConfig`)
- Modify: `crates/foundry-core/src/config/validate.rs` (add rules after the `key_attestation.android.mode` rule at lines 207-217)
- Modify: 25 `IssuerConfig { .. }` struct-literal sites across 21 files — the compiler enumerates them (Step 4)
- Test: `crates/foundry-core/src/config/validate.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:

  ```rust
  pub struct EncryptedPreAuthCodeConfig {
      pub mode: Mode,
      pub max_age_secs: u64,
  }
  impl Default for EncryptedPreAuthCodeConfig  // -> { mode: Mode::Disabled, max_age_secs: 300 }

  // on IssuerConfig:
  pub encrypted_pre_authorized_code: EncryptedPreAuthCodeConfig,
  pub access_token_ttl_secs: u64,
  ```

  Tasks 4, 5, 6 and 7 all read these.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `crates/foundry-core/src/config/validate.rs`. `base_config()` is the existing fixture helper (the struct-literal block visible around lines 360-395); call it by whatever name it has there.

```rust
    /// The trap this guards: `Mode`'s own `Default` is `Optional`, so a bare
    /// `#[serde(default)]` on a `Mode` field would silently switch this
    /// feature ON for every deployment that never mentions it.
    #[test]
    fn encrypted_pre_authorized_code_defaults_to_disabled() {
        assert_eq!(EncryptedPreAuthCodeConfig::default().mode, Mode::Disabled);
        assert_eq!(EncryptedPreAuthCodeConfig::default().max_age_secs, 300);
    }

    /// `Default::default()` being right is not enough if serde reaches a
    /// different value for an omitted block.
    #[test]
    fn an_omitted_encrypted_pre_auth_block_deserializes_to_disabled() {
        let cfg: EncryptedPreAuthCodeConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(cfg.mode, Mode::Disabled);
    }

    #[test]
    fn encrypted_pre_auth_code_requires_wallet_attestation_to_be_enabled() {
        let mut cfg = base_config();
        cfg.issuer.encrypted_pre_authorized_code.mode = Mode::Required;
        cfg.issuer.wallet_attestation.mode = Mode::Disabled;
        cfg.issuer.request_encryption = Some(RequestEncryptionConfig {
            keys: vec!["req-dec".to_string()],
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: false,
        });

        let err = cfg
            .validate()
            .expect_err("no wallet attestation means no cnf.jwk, so every request would fail");
        assert!(
            format!("{err}").contains("wallet_attestation"),
            "the message must name the field an operator has to change, got: {err}"
        );
    }

    #[test]
    fn encrypted_pre_auth_code_requires_request_encryption_keys() {
        let mut cfg = base_config();
        cfg.issuer.encrypted_pre_authorized_code.mode = Mode::Optional;
        cfg.issuer.wallet_attestation.mode = Mode::Required;
        cfg.issuer.request_encryption = None;

        let err = cfg
            .validate()
            .expect_err("with no decryption keys the JWE could never be opened");
        assert!(
            format!("{err}").contains("request_encryption"),
            "the message must name the field an operator has to change, got: {err}"
        );
    }

    /// Deliberately legal: `required` here with `optional` wallet attestation
    /// means a wallet presenting no attestation is rejected at the
    /// encrypted-code step rather than at the attestation step. One knob
    /// strengthens another; it does not replace it.
    #[test]
    fn encrypted_pre_auth_code_required_with_optional_wallet_attestation_is_legal() {
        let mut cfg = base_config();
        cfg.issuer.encrypted_pre_authorized_code.mode = Mode::Required;
        cfg.issuer.wallet_attestation.mode = Mode::Optional;
        cfg.issuer.request_encryption = Some(RequestEncryptionConfig {
            keys: vec!["req-dec".to_string()],
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: false,
        });

        cfg.validate()
            .expect("required + optional is a coherent, supported combination");
    }

    /// Disabled must not drag the two preconditions in with it.
    #[test]
    fn disabled_encrypted_pre_auth_code_imposes_no_preconditions() {
        let mut cfg = base_config();
        cfg.issuer.encrypted_pre_authorized_code.mode = Mode::Disabled;
        cfg.issuer.wallet_attestation.mode = Mode::Disabled;
        cfg.issuer.request_encryption = None;

        cfg.validate()
            .expect("a disabled feature must not constrain unrelated configuration");
    }
```

If the `req-dec` key name trips an unrelated "unknown key reference" rule, add a matching entry to `cfg.keys` the way the other `request_encryption` tests in this file already do.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-core --lib config::validate
```

Expected: FAIL — `cannot find type EncryptedPreAuthCodeConfig`.

- [ ] **Step 3: Add the config types**

In `crates/foundry-core/src/config/model.rs`, after the `AndroidKeystoreConfig` block:

```rust
/// Google Wallet's `encrypted_pre-authorized_code` Token Request extension:
/// the pre-authorized code delivered as a JWS nested inside a JWE instead of
/// as a plaintext parameter.
///
/// **Vendor profile, not a specification.** Its only source is the Google
/// Wallet VCI 1.0 Profile, §"token request field signing & encryption"; no
/// standards-track document defines this parameter. Root `AGENTS.md` §4.4
/// therefore makes it accommodation, never conformance. Design:
/// `docs/superpowers/specs/2026-08-17-encrypted-pre-authorized-code-design.md`.
///
/// - `disabled` (default) — the member is **rejected** if present. Not
///   ignored: silently falling back to the plaintext parameter would be a
///   downgrade against the exact property the extension exists to provide.
/// - `optional` — either form is accepted, and exactly one of the two must be
///   present. The migration rung.
/// - `required` — the member is mandatory and a plaintext `pre-authorized_code`
///   is rejected. The anti-downgrade rule, mirroring RFC 9449 §7.2's
///   DPoP-bound-token-presented-as-Bearer rejection.
///
/// Enabling this (any mode but `disabled`) requires **both**
/// `issuer.wallet_attestation.mode != disabled` (the inner JWS is verified
/// against the Client Attestation's `cnf.jwk`) and a configured
/// `issuer.request_encryption` (its keys decrypt the outer JWE).
/// `Config::validate()` enforces both at load time.
#[derive(Debug, Clone, Deserialize)]
pub struct EncryptedPreAuthCodeConfig {
    /// **Not `#[serde(default)]`.** `Mode`'s own `Default` is `Optional`, so
    /// the bare attribute would switch this extension on for every deployment
    /// that never mentions it. The explicit function is load-bearing.
    #[serde(default = "default_encrypted_pre_auth_code_mode")]
    pub mode: Mode,
    /// Sliding window bounding how old the inner JWS's `iat` may be, and the
    /// basis for the `jti` replay row's `expires_at`. The same role
    /// `AttestationMode.pop_max_age_secs` plays for the Client Attestation PoP.
    #[serde(default = "default_encrypted_pre_auth_code_max_age_secs")]
    pub max_age_secs: u64,
}

fn default_encrypted_pre_auth_code_mode() -> Mode {
    Mode::Disabled
}

fn default_encrypted_pre_auth_code_max_age_secs() -> u64 {
    300
}

impl Default for EncryptedPreAuthCodeConfig {
    fn default() -> Self {
        Self {
            mode: default_encrypted_pre_auth_code_mode(),
            max_age_secs: default_encrypted_pre_auth_code_max_age_secs(),
        }
    }
}

fn default_access_token_ttl_secs() -> u64 {
    600
}
```

Then add both fields to `IssuerConfig`, after `response_encryption`:

```rust
    /// Google Wallet's `encrypted_pre-authorized_code` extension. Absent means
    /// `disabled`, which reproduces foundry's behaviour before the extension
    /// existed, byte for byte.
    #[serde(default)]
    pub encrypted_pre_authorized_code: EncryptedPreAuthCodeConfig,
    /// Lifetime of a minted access token, in seconds. Drives **both** the
    /// `expires_in` on the wire and the TTL of the issuance-transaction row the
    /// token addresses — the row must outlive the token, and equal lifetimes is
    /// the tightest correct choice.
    ///
    /// Distinct from `storage.transaction_ttl_secs`, which bounds how long an
    /// **offer** stays redeemable before `/token` is ever called. The two
    /// measure different phases of the flow; the similar names invite
    /// conflation.
    #[serde(default = "default_access_token_ttl_secs")]
    pub access_token_ttl_secs: u64,
```

- [ ] **Step 4: Add the two fields to every struct literal**

```bash
cargo build -p foundry-core --all-targets 2>&1 | grep -A3 'missing field'
```

The compiler lists every `IssuerConfig { .. }` site — 25 across 21 files spanning all four crates. Add to each:

```rust
                encrypted_pre_authorized_code: Default::default(),
                access_token_ttl_secs: 600,
```

`600` preserves each fixture's current behaviour exactly (it is the value `mint_and_save_tokens` hardcodes today), so no existing expectation shifts. Iterate until this is clean:

```bash
cargo build -p foundry-core -p foundry-issuer -p foundry-verifier -p foundry --all-targets
```

- [ ] **Step 5: Add the validation rules**

In `crates/foundry-core/src/config/validate.rs`, after the `key_attestation.android.mode` rule and before `Ok(())`:

```rust
        // Fail closed at load time, same reasoning as the android rule above.
        // Google Wallet profile, §"token request field signing & encryption":
        // the inner JWS is verified against the Client Attestation's `cnf.jwk`
        // and the outer JWE is opened with the credential_request_encryption
        // keys. Without either, every request carrying the member fails at
        // request time -- a silent total outage of the Token Endpoint rather
        // than a legible misconfiguration.
        if self.issuer.encrypted_pre_authorized_code.mode != super::model::Mode::Disabled {
            if self.issuer.wallet_attestation.mode == super::model::Mode::Disabled {
                return Err(ConfigError::Validation(
                    "issuer.encrypted_pre_authorized_code.mode is enabled but \
                     issuer.wallet_attestation.mode is disabled: the inner JWS is verified \
                     against the Client Attestation's cnf.jwk, so no request could ever \
                     succeed"
                        .into(),
                ));
            }
            let has_keys = self
                .issuer
                .request_encryption
                .as_ref()
                .is_some_and(|re| !re.keys.is_empty());
            if !has_keys {
                return Err(ConfigError::Validation(
                    "issuer.encrypted_pre_authorized_code.mode is enabled but \
                     issuer.request_encryption has no keys: there would be nothing to \
                     decrypt the outer JWE with"
                        .into(),
                ));
            }
        }
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test -p foundry-core --lib config
```

Expected: PASS, including every pre-existing config test.

- [ ] **Step 7: Scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

All four crates are in scope because Step 4 edited fixtures in all four.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-core crates/foundry-issuer crates/foundry-verifier crates/foundry
git commit -m "feat(core): add encrypted_pre_authorized_code and access_token_ttl_secs config

EncryptedPreAuthCodeConfig defaults to Disabled via an explicit function --
Mode's own Default is Optional, which would have switched the extension on
for every existing deployment.

Two fail-closed validate() rules: enabling the extension requires wallet
attestation enabled (for the cnf.jwk) and request_encryption keys (for the
outer JWE)."
```

---

### Task 3: Expose `cnf.jwk` on `PopClaims`

The Client Attestation's `cnf.jwk` is parsed and used to verify the PoP signature, then discarded. Task 4 needs it. Exposing it asserts nothing new: the PoP signature was already verified against exactly this key.

**Files:**

- Modify: `crates/foundry-issuer/src/attestation.rs:249-255` (the `PopClaims` struct), `:515-519` (its construction), `:1312` (the `matched_attestation_and_pop` test helper), `:2791-2795` (the `pop_claims` test helper)
- Modify: `crates/foundry-issuer/src/token.rs:1624` (a `PopClaims` literal in a test)
- Test: `crates/foundry-issuer/src/attestation.rs` (inline `mod tests`)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:

  ```rust
  pub struct PopClaims {
      pub iss: String,
      pub jti: String,
      pub iat: i64,
      pub cnf_jwk: josekit::jwk::Jwk,   // NEW
  }
  ```

  Task 6 reads `pop_claims.cnf_jwk` and passes it to Task 5's entry point.

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/foundry-issuer/src/attestation.rs`. `matched_attestation_and_pop(now, aud)` already exists at line 1312 returning `(String, String, String)`; read it and the neighbouring `verify_wallet_attestation` tests before writing this, and copy their `TrustStore` construction exactly.

```rust
    /// The key that verified the PoP must reach the caller: the Google Wallet
    /// profile's `encrypted_pre-authorized_code` inner JWS is signed by this
    /// same key, and there is no other route to it.
    #[test]
    fn verified_pop_claims_carry_the_attestation_cnf_jwk() {
        let now = now_secs();
        let (attestation, pop, expected_cnf_jwk) =
            matched_attestation_and_pop_with_jwk(now, POP_TEST_AUD);

        let claims = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Required,
                Some(&attestation),
                Some(&pop),
                &pop_trust_store(),
                POP_TEST_AUD,
                now,
                300,
                Mode::Disabled,
                &challenge_secret(),
            )
            .expect("a matched attestation and pop must verify")
            .expect("Required mode with both headers present must yield claims");

        assert_eq!(claims.cnf_jwk.key_type(), "EC");
        assert_eq!(
            claims.cnf_jwk.parameter("x"),
            expected_cnf_jwk.parameter("x"),
            "cnf_jwk must be the attestation's key, not a re-derived or empty one"
        );
    }
```

Add a `matched_attestation_and_pop_with_jwk` helper alongside the existing one, returning `(String, String, Jwk)` — reuse the existing helper's body and additionally return the client instance key's public JWK. `pop_trust_store()` stands for whatever the surrounding tests use to build a `TrustStore` for `POP_TEST_AUD`; if they build it inline, do the same here rather than inventing a helper.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p foundry-issuer --lib attestation::tests::verified_pop_claims_carry_the_attestation_cnf_jwk
```

Expected: FAIL — `no field cnf_jwk on type PopClaims`.

- [ ] **Step 3: Add the field**

Replace the struct at `crates/foundry-issuer/src/attestation.rs:249-255`:

```rust
/// The claims recovered from a verified Client Attestation PoP JWT (ABCA
/// draft -07 §5.2), consumed by `claim_pop_jti`'s anti-replay check.
#[derive(Debug, Clone)]
pub struct PopClaims {
    pub iss: String,
    pub jti: String,
    pub iat: i64,
    /// The Client Attestation JWT's `cnf.jwk` — the key this PoP's signature
    /// was verified against (check 4, ABCA §5.2 r3 / §9 rule 7).
    ///
    /// Carried out to the caller because the Google Wallet profile's
    /// `encrypted_pre-authorized_code` inner JWS is signed by this same key
    /// ("The JWS must be signed by the cnf.jwk found in the
    /// OAuth-Client-Attestation JWT used for wallet attestation"), and there is
    /// no other route to it. Exposing it asserts nothing new — the signature
    /// check above already proved this key authenticates this client.
    pub cnf_jwk: Jwk,
}
```

`Jwk` is already imported at the top of the file. At the construction site (line 515), `attestation` is the `&ValidatedAttestation` parameter already in scope:

```rust
    Ok(PopClaims {
        iss: iss.to_string(),
        jti: jti.to_string(),
        iat,
        cnf_jwk: attestation.cnf_jwk.clone(),
    })
```

Then fix the two test literals the compiler flags. Neither `claim_pop_jti` nor the token test reads `cnf_jwk`, so any well-formed P-256 public JWK serves:

```rust
    // attestation.rs:2791 and token.rs:1624
    cnf_jwk: EcKeyPair::generate(EcCurve::P256).unwrap().to_jwk_public_key(),
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib attestation
cargo test -p foundry-issuer --lib token
```

Expected: PASS, including all pre-existing attestation and token tests.

- [ ] **Step 5: Scoped gate**

```bash
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/attestation.rs crates/foundry-issuer/src/token.rs
git commit -m "feat(issuer): carry the attestation cnf.jwk out on PopClaims

The Google Wallet profile's encrypted_pre-authorized_code inner JWS is
signed by the Client Attestation's cnf.jwk, and PopClaims was the only
thing escaping verify_wallet_attestation. Exposing the key asserts nothing
new -- the PoP signature was already verified against it."
```

---

### Task 4: Envelope module — decrypt and verify (checks 1-7)

The new module's crypto half: open the JWE, confirm the plaintext is a compact JWS, verify its ES256 signature against `cnf.jwk`, return the payload as JSON. Claim validation is Task 5.

**Files:**

- Create: `crates/foundry-issuer/src/encrypted_pre_auth.rs`
- Modify: `crates/foundry-issuer/src/lib.rs` (add `pub mod encrypted_pre_auth;` after `pub mod dpop;`)
- Test: `crates/foundry-issuer/src/encrypted_pre_auth.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: `foundry_core::crypto::jwe::decrypt_compact_to_bytes` (Task 1).
- Produces:

  ```rust
  pub fn open_envelope(
      envelope: &str,
      decryption_keys: &[DecryptionKey],
      allowed_enc: &[String],
      cnf_jwk: &Jwk,
  ) -> Result<serde_json::Value, IssuanceError>
  ```

  Task 5 calls this and validates the returned payload.

- [ ] **Step 1: Write the failing tests**

Create `crates/foundry-issuer/src/encrypted_pre_auth.rs` containing only this test module for now.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwe::JweHeader;
    use josekit::jwk::KeyPair as _;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jws::{ES256, JwsHeader};
    use josekit::jwt::{self, JwtPayload};

    fn recipient_key() -> DecryptionKey {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        DecryptionKey::from_pem(&kp.to_pem_private_key()).unwrap()
    }

    fn both_gcm() -> Vec<String> {
        vec!["A128GCM".to_string(), "A256GCM".to_string()]
    }

    pub(super) fn sample_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "GoogleWallet",
            "sub": "GoogleWallet",
            "aud": "https://issuer.example.com/token",
            "jti": "envelope-jti-1",
            "iat": 1_700_000_000,
            "exp": 1_700_000_300,
            "pre-authorized_code": "code-123",
        })
    }

    /// Build a real envelope: ES256-sign `claims` with `signer_kp`, then
    /// ECDH-ES-encrypt the resulting compact JWS to `recipient`.
    fn build_envelope(
        claims: &serde_json::Value,
        signer_kp: &EcKeyPair,
        recipient: &DecryptionKey,
        enc: &str,
        alg_override: Option<&str>,
    ) -> String {
        let mut jws_header = JwsHeader::new();
        jws_header.set_algorithm(alg_override.unwrap_or("ES256"));
        jws_header.set_token_type("JWT");

        let payload = JwtPayload::from_map(claims.as_object().unwrap().clone()).unwrap();
        let signer = ES256.signer_from_jwk(&signer_kp.to_jwk_private_key()).unwrap();
        let jws = jwt::encode_with_signer(&payload, &jws_header, &signer).unwrap();

        wrap_in_jwe(jws.as_bytes(), recipient, enc)
    }

    fn wrap_in_jwe(plaintext: &[u8], recipient: &DecryptionKey, enc: &str) -> String {
        let pub_jwk =
            Jwk::from_bytes(&serde_json::to_vec(&recipient.published_jwk()).unwrap()).unwrap();
        let encrypter = josekit::jwe::ECDH_ES.encrypter_from_jwk(&pub_jwk).unwrap();

        let mut header = JweHeader::new();
        header.set_algorithm("ECDH-ES");
        header.set_content_encryption(enc);
        header.set_key_id(recipient.kid());

        josekit::jwe::serialize_compact(plaintext, &header, &encrypter).unwrap()
    }

    /// THE POSITIVE CONTROL. Without it every negative test below could pass
    /// against a function that rejects everything.
    #[test]
    fn a_valid_envelope_opens_to_its_claims() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(&sample_claims(), &signer_kp, &recipient, "A128GCM", None);

        let payload = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect("a correctly signed and encrypted envelope must open");

        assert_eq!(payload["pre-authorized_code"], "code-123");
        assert_eq!(payload["iss"], "GoogleWallet");
    }

    /// Check 2 (VCI-0135): `enc` must be advertised.
    #[test]
    fn rejects_an_enc_the_issuer_does_not_advertise() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(&sample_claims(), &signer_kp, &recipient, "A256GCM", None);

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &["A128GCM".to_string()],
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("an unadvertised enc must be rejected");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// Check 3 (L1188 / VCI-0101): the `kid` must match a configured key.
    #[test]
    fn rejects_an_envelope_encrypted_to_an_unknown_key() {
        let ours = recipient_key();
        let theirs = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(&sample_claims(), &signer_kp, &theirs, "A128GCM", None);

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&ours),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("an envelope for another issuer's key must be rejected");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// Check 4: undecryptable ciphertext.
    #[test]
    fn rejects_a_structurally_broken_envelope() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();

        let err = open_envelope(
            "not.a.valid.jwe.at-all",
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("a malformed envelope must be rejected");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// Check 5: the plaintext must be a compact JWS. A bare JSON object would
    /// mean an UNSIGNED code, which defeats the extension's whole purpose.
    #[test]
    fn rejects_a_plaintext_that_is_not_a_compact_jws() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = wrap_in_jwe(br#"{"pre-authorized_code":"naked"}"#, &recipient, "A128GCM");

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("a bare JSON plaintext must be rejected: the code must be SIGNED");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// Check 6 (HAIP-0088): ES256 only. Signed with a genuine ES256 key but
    /// declaring another alg, so the rejection is the alg policy and not a
    /// signature failure.
    #[test]
    fn rejects_an_inner_jws_that_does_not_declare_es256() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(
            &sample_claims(),
            &signer_kp,
            &recipient,
            "A128GCM",
            Some("ES384"),
        );

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("only ES256 is permitted (HAIP-0088)");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 7 -- THE FORGERY TEST. A well-formed envelope signed by a key the
    /// attestation never vouched for.
    #[test]
    fn rejects_an_inner_jws_signed_by_a_key_the_attestation_did_not_vouch_for() {
        let recipient = recipient_key();
        let attested_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let attacker_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(&sample_claims(), &attacker_kp, &recipient, "A128GCM", None);

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &attested_kp.to_jwk_public_key(),
        )
        .expect_err("a signature from an unattested key must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }
}
```

- [ ] **Step 2: Register the module and run the tests to verify they fail**

In `crates/foundry-issuer/src/lib.rs`, add after `pub mod dpop;`:

```rust
pub mod encrypted_pre_auth;
```

Then:

```bash
cargo test -p foundry-issuer --lib encrypted_pre_auth
```

Expected: FAIL — `cannot find function open_envelope in this scope`.

- [ ] **Step 3: Implement `open_envelope`**

Prepend to `crates/foundry-issuer/src/encrypted_pre_auth.rs`, above the test module:

```rust
//! Google Wallet's `encrypted_pre-authorized_code` Token Request extension:
//! the pre-authorized code delivered as a JWS nested inside a JWE.
//!
//! **Vendor profile, not a specification** (root `AGENTS.md` §4.4). Its only
//! source is the Google Wallet VCI 1.0 Profile, §"token request field signing
//! & encryption", whose stated motivation is that the wallet *server* relaying
//! the Token Request must be unable to read or forge the code. No
//! standards-track document defines this parameter. Design:
//! `docs/superpowers/specs/2026-08-17-encrypted-pre-authorized-code-design.md`.
//!
//! Two independent keys meet here, and conflating them is the mistake this
//! module exists to prevent:
//!
//! * the **outer JWE** is opened with the issuer's own
//!   `credential_request_encryption` private keys — the same keys that already
//!   decrypt a Credential Request, per the profile's explicit instruction;
//! * the **inner JWS** is verified against the *client's* `cnf.jwk`, carried
//!   out of the verified Client Attestation JWT on `PopClaims`.
//!
//! Nothing here may be logged: root `AGENTS.md` §4.5 covers the envelope, the
//! decrypted JWS, the extracted code and the `jti`.

use crate::error::IssuanceError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use foundry_core::crypto::jwe::{DecryptionKey, decrypt_compact_to_bytes};
use josekit::jwk::Jwk;
use josekit::jws::ES256;

/// Decrypt the outer JWE and verify the inner JWS, returning its payload.
///
/// Implements steps 3-6 of the profile's validation algorithm. Claim
/// validation is [`validate_claims`]; this function proves only that the bytes
/// came from the attested client and were addressed to this issuer.
///
/// `skip_all` is mandatory and total: `envelope` is the JWE, `decryption_keys`
/// are private keys, and the return value carries the pre-authorized code.
#[tracing::instrument(skip_all)]
pub fn open_envelope(
    envelope: &str,
    decryption_keys: &[DecryptionKey],
    allowed_enc: &[String],
    cnf_jwk: &Jwk,
) -> Result<serde_json::Value, IssuanceError> {
    // Checks 1-4. The three header checks (alg == ECDH-ES, enc advertised, kid
    // present and known) live in `decrypt_compact_to_bytes` and carry their
    // OpenID4VCI citations there: L1188, VCI-0100/0101, VCI-0135.
    //
    // `InvalidRequest`, not `InvalidClient`: nothing has been authenticated
    // yet, so a failure here is a malformed parameter value (RFC 6749 §5.2).
    // The message names only the structural defect -- `CryptoError`'s Display
    // never echoes ciphertext or key material.
    let plaintext =
        decrypt_compact_to_bytes(envelope, decryption_keys, allowed_enc).map_err(|e| {
            IssuanceError::InvalidRequest(format!(
                "encrypted_pre-authorized_code decryption failed: {e}"
            ))
        })?;

    let jws = std::str::from_utf8(&plaintext).map_err(|_| {
        IssuanceError::InvalidRequest(
            "encrypted_pre-authorized_code: the decrypted payload is not UTF-8".into(),
        )
    })?;

    // Check 5: the payload must be a compact JWS. A bare JSON object here
    // would mean an unsigned code, which defeats the extension's purpose --
    // so this is a rejection, never a fallback.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidRequest(
            "encrypted_pre-authorized_code: the decrypted payload is not a compact JWS \
             (expected 3 dot-separated parts)"
                .into(),
        ));
    }

    // Check 6 (HAIP-0088, narrowing the profile): ES256 only -- the same policy
    // `dpop.rs` and `attestation.rs` already apply to every other client-signed
    // artifact in this crate.
    //
    // From here on failures are `InvalidClient`: past decryption the artifact
    // is signed by the client instance key and asserts client identity, so a
    // failure is a failed client-authentication mechanism.
    let header_bytes = B64URL.decode(parts[0]).map_err(|_| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: inner JWS header is not valid base64url".into(),
        )
    })?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|_| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: inner JWS header is not JSON".into(),
        )
    })?;
    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: inner JWS header has no string alg".into(),
        )
    })?;
    if alg != "ES256" {
        return Err(IssuanceError::InvalidClient(format!(
            "encrypted_pre-authorized_code: inner JWS alg '{alg}' is not permitted, \
             expected ES256"
        )));
    }

    // Check 7: the signature MUST verify against the Client Attestation's
    // cnf.jwk -- "The JWS must be signed by the cnf.jwk found in the
    // OAuth-Client-Attestation JWT used for wallet attestation."
    let verifier = ES256.verifier_from_jwk(cnf_jwk).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "encrypted_pre-authorized_code: cannot build a verifier from the attestation's \
             cnf.jwk: {e}"
        ))
    })?;
    let (payload, _header) = josekit::jwt::decode_with_verifier(jws, &verifier).map_err(|_| {
        // Deliberately does not distinguish "bad signature" from "malformed
        // payload": telling a client which applied would be an oracle.
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: inner JWS signature did not verify against the \
             wallet attestation's cnf.jwk"
                .into(),
        )
    })?;

    serde_json::to_value(payload.claims_set()).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "encrypted_pre-authorized_code: inner JWS claims are not JSON: {e}"
        ))
    })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib encrypted_pre_auth
```

Expected: PASS — all seven tests, positive control first.

- [ ] **Step 5: Scoped gate**

```bash
cargo test -p foundry-issuer
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/encrypted_pre_auth.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): open the encrypted_pre-authorized_code envelope

Decrypt the outer JWE with the issuer's credential_request_encryption
keys, confirm the plaintext is a compact JWS, and verify its ES256
signature against the Client Attestation's cnf.jwk. Claim validation
follows separately."
```

---

### Task 5: Envelope module — claim validation and replay defence (checks 8-15)

The payload is authentic; now prove it was minted for *this* request by *this* client, recently, and only once.

**Files:**

- Modify: `crates/foundry-issuer/src/encrypted_pre_auth.rs` (add to the module created in Task 4)
- Test: `crates/foundry-issuer/src/encrypted_pre_auth.rs` (inline `mod tests`)

**Interfaces:**

- Consumes: `open_envelope` (Task 4); `PopClaims.cnf_jwk` (Task 3).
- Produces:

  ```rust
  pub struct EncryptedCodeClaims {
      pub iss: String,
      pub jti: String,
      pub iat: i64,
      pub pre_authorized_code: String,
  }

  pub fn validate_claims(
      payload: &serde_json::Value,
      attestation_iss: &str,
      expected_aud: &str,
      now_unix: i64,
      max_age_secs: u64,
  ) -> Result<EncryptedCodeClaims, IssuanceError>

  pub(crate) async fn claim_envelope_jti(
      storage: &dyn Storage,
      claims: &EncryptedCodeClaims,
      max_age_secs: u64,
  ) -> Result<(), IssuanceError>

  #[allow(clippy::too_many_arguments)]
  pub async fn resolve_encrypted_pre_authorized_code(
      storage: &dyn Storage,
      envelope: &str,
      decryption_keys: &[DecryptionKey],
      allowed_enc: &[String],
      cnf_jwk: &Jwk,
      attestation_iss: &str,
      token_endpoint: &str,
      now_unix: i64,
      max_age_secs: u64,
  ) -> Result<String, IssuanceError>
  ```

  Task 6 calls `resolve_encrypted_pre_authorized_code` only.

- [ ] **Step 1: Write the failing tests**

Append to the existing `mod tests` in `crates/foundry-issuer/src/encrypted_pre_auth.rs`. Reuse `sample_claims()` from Task 4. Add `use foundry_core::storage::{SqliteStorage, Storage};` to the test module's imports.

```rust
    const NOW: i64 = 1_700_000_000;
    const AUD: &str = "https://issuer.example.com/token";

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    /// Positive control for the claims half.
    #[test]
    fn valid_claims_yield_the_pre_authorized_code() {
        let claims = validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW, 300)
            .expect("a well-formed claim set must validate");

        assert_eq!(claims.pre_authorized_code, "code-123");
        assert_eq!(claims.iss, "GoogleWallet");
        assert_eq!(claims.jti, "envelope-jti-1");
        assert_eq!(claims.iat, NOW);
    }

    /// Check 8: iss must equal sub.
    #[test]
    fn rejects_claims_whose_iss_and_sub_disagree() {
        let mut c = sample_claims();
        c["sub"] = serde_json::json!("SomeoneElse");
        let err = validate_claims(&c, "GoogleWallet", AUD, NOW, 300).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 9 -- THE IMPERSONATION TEST. A perfectly signed envelope whose
    /// `iss` names a different client than the attestation that authenticated
    /// this request must be rejected. Without this check, any wallet holding
    /// any valid client attestation could redeem another client's code.
    #[test]
    fn rejects_claims_naming_a_different_client_than_the_attestation() {
        let err = validate_claims(&sample_claims(), "SomeOtherWallet", AUD, NOW, 300)
            .expect_err("the envelope's iss must match the attestation's sub");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 10: aud is the TOKEN ENDPOINT URL, deliberately not the issuer
    /// identifier the Client Attestation PoP uses (ABCA §9 rule 10). Two
    /// artifacts, two audiences; conflating them breaks the profile as written.
    #[test]
    fn rejects_claims_addressed_to_another_audience() {
        let err = validate_claims(
            &sample_claims(),
            "GoogleWallet",
            "https://issuer.example.com",
            NOW,
            300,
        )
        .expect_err("the issuer identifier is not the token endpoint URL");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 11.
    #[test]
    fn rejects_claims_without_a_jti() {
        let mut c = sample_claims();
        c.as_object_mut().unwrap().remove("jti");
        let err = validate_claims(&c, "GoogleWallet", AUD, NOW, 300).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 12: iat outside the issuer's own sliding window. `exp` alone is
    /// not enough -- a client can set an arbitrarily distant one -- so the
    /// issuer keeps its own bound, exactly as `pop_max_age_secs` does.
    #[test]
    fn rejects_claims_whose_iat_is_older_than_max_age() {
        let err = validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW + 301, 300)
            .expect_err("an iat beyond max_age_secs must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn accepts_claims_whose_iat_is_slightly_in_the_future_within_skew() {
        validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW - 30, 300)
            .expect("clock skew of 30s must be tolerated");
    }

    #[test]
    fn rejects_claims_whose_iat_is_far_in_the_future() {
        let err = validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW - 600, 300)
            .expect_err("an iat far beyond the skew allowance must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 13. `exp` is 1_700_000_300, so a large max_age isolates the
    /// rejection to `exp` rather than to check 12.
    #[test]
    fn rejects_expired_claims() {
        validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW + 299, 3600)
            .expect("one second before exp must still be accepted");

        let err = validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW + 301, 3600)
            .expect_err("a claim set past its exp must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 15.
    #[test]
    fn rejects_claims_without_a_pre_authorized_code() {
        let mut c = sample_claims();
        c.as_object_mut().unwrap().remove("pre-authorized_code");
        let err = validate_claims(&c, "GoogleWallet", AUD, NOW, 300).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_claims_whose_pre_authorized_code_is_empty() {
        let mut c = sample_claims();
        c["pre-authorized_code"] = serde_json::json!("");
        let err = validate_claims(&c, "GoogleWallet", AUD, NOW, 300).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    // -- check 14: replay --

    fn envelope_claims(iss: &str, jti: &str) -> EncryptedCodeClaims {
        EncryptedCodeClaims {
            iss: iss.to_string(),
            jti: jti.to_string(),
            iat: NOW,
            pre_authorized_code: "code-123".to_string(),
        }
    }

    #[tokio::test]
    async fn the_first_claim_of_an_envelope_jti_succeeds() {
        let storage = test_storage().await;
        claim_envelope_jti(&storage, &envelope_claims("GoogleWallet", "jti-1"), 300)
            .await
            .expect("the first use of a jti must succeed");
    }

    #[tokio::test]
    async fn a_replayed_envelope_jti_is_rejected() {
        let storage = test_storage().await;
        let claims = envelope_claims("GoogleWallet", "jti-1");
        claim_envelope_jti(&storage, &claims, 300).await.unwrap();

        let err = claim_envelope_jti(&storage, &claims, 300)
            .await
            .expect_err("a replayed envelope must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Namespace separation: a Client Attestation PoP `jti` and an envelope
    /// `jti` sharing a value must not collide. A shared namespace would let one
    /// artifact deny service to the other.
    #[tokio::test]
    async fn an_envelope_jti_does_not_collide_with_a_pop_jti_of_the_same_value() {
        let storage = test_storage().await;
        let shared = "jti-shared";

        crate::attestation::claim_pop_jti(
            &storage,
            &crate::attestation::PopClaims {
                iss: "GoogleWallet".to_string(),
                jti: shared.to_string(),
                iat: NOW,
                cnf_jwk: EcKeyPair::generate(EcCurve::P256)
                    .unwrap()
                    .to_jwk_public_key(),
            },
            300,
        )
        .await
        .unwrap();

        claim_envelope_jti(&storage, &envelope_claims("GoogleWallet", shared), 300)
            .await
            .expect("the two artifacts must use separate jti namespaces");
    }

    /// The raw jti must never be usable verbatim as a storage key -- the same
    /// anti-leak property `claim_pop_jti` is tested for.
    #[tokio::test]
    async fn the_raw_envelope_jti_is_not_the_storage_key() {
        let storage = test_storage().await;
        let claims = envelope_claims("GoogleWallet", "a-very-identifiable-jti");
        claim_envelope_jti(&storage, &claims, 300).await.unwrap();

        assert_eq!(
            storage
                .get_kv(ENVELOPE_JTI_NAMESPACE, &claims.jti)
                .await
                .unwrap(),
            None
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib encrypted_pre_auth
```

Expected: FAIL — `cannot find function validate_claims in this scope`.

- [ ] **Step 3: Implement claim validation, replay defence, and the orchestrator**

Append to `crates/foundry-issuer/src/encrypted_pre_auth.rs`, above the test module. Add `use foundry_core::storage::Storage;` and `use sha2::{Digest, Sha256};` to the module imports (`sha2` is already a `foundry-issuer` dependency).

`claim_pop_jti` stays `pub(crate)` and untouched. This module gets its own namespace and its own claims type, because sharing either would couple two artifacts that must not be able to deny service to each other.

```rust
/// The clock-skew tolerance for the inner JWS's `iat`. The same value and the
/// same reasoning as `attestation.rs`'s `POP_CLOCK_SKEW_SECS` (ABCA §12.1:
/// "clock skews between servers and clients may be large"). Never used to
/// widen how far into the *past* an `iat` may be — that is `max_age_secs`.
const ENVELOPE_CLOCK_SKEW_SECS: i64 = 60;

/// KV storage namespace for `encrypted_pre-authorized_code` `jti` replay
/// claims.
///
/// Deliberately **not** shared with `attestation.rs`'s
/// `client_attestation_pop_jti`: a shared namespace would let a PoP `jti` and
/// an envelope `jti` of the same value collide, so one artifact could deny
/// service to the other.
pub(crate) const ENVELOPE_JTI_NAMESPACE: &str = "encrypted_pre_auth_code_jti";

/// The claims recovered from a verified `encrypted_pre-authorized_code`
/// envelope.
#[derive(Debug, Clone)]
pub struct EncryptedCodeClaims {
    pub iss: String,
    pub jti: String,
    pub iat: i64,
    pub pre_authorized_code: String,
}

/// Validate the inner JWS payload (checks 8-13 and 15).
///
/// `attestation_iss` is `PopClaims.iss` — the `sub` of the Client Attestation
/// that authenticated this request, which `validate_client_attestation_pop_jwt`
/// already proved equal to the PoP's `iss`.
///
/// `expected_aud` is the **Token Endpoint URL**, not the Authorization Server's
/// issuer identifier. The profile's worked example is explicit
/// (`"aud": "https://authorization-server.example.com/token" // Token endpoint`)
/// and this deliberately differs from the Client Attestation PoP's `aud`, which
/// ABCA §9 rule 10 binds to the issuer identifier.
///
/// `skip_all` is mandatory: `payload` carries the pre-authorized code.
#[tracing::instrument(skip_all)]
pub fn validate_claims(
    payload: &serde_json::Value,
    attestation_iss: &str,
    expected_aud: &str,
    now_unix: i64,
    max_age_secs: u64,
) -> Result<EncryptedCodeClaims, IssuanceError> {
    let str_claim = |name: &str| -> Result<String, IssuanceError> {
        payload
            .get(name)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                IssuanceError::InvalidClient(format!(
                    "encrypted_pre-authorized_code: missing or empty {name} claim"
                ))
            })
    };

    // Check 8: iss == sub. Both are the client_id.
    let iss = str_claim("iss")?;
    let sub = str_claim("sub")?;
    if iss != sub {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: iss and sub disagree; both must be the client_id"
                .into(),
        ));
    }

    // Check 9: the envelope must name the client the attestation authenticated.
    // Without this, any wallet holding any valid client attestation could
    // submit an envelope claiming to be a different client -- the check that
    // makes the signature mean something. Profile, inline in its example:
    // "The client ID, must match the 'sub' in the attestation".
    if iss != attestation_iss {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: iss does not match the wallet attestation's sub"
                .into(),
        ));
    }

    // Check 10: aud is the Token Endpoint URL. Exact match, no normalization --
    // a prefix or case-insensitive match would weaken the binding, the same
    // posture `attestation.rs` takes for the PoP's aud.
    let aud = payload.get("aud").ok_or_else(|| {
        IssuanceError::InvalidClient("encrypted_pre-authorized_code: missing aud claim".into())
    })?;
    let aud_matches = match aud {
        serde_json::Value::String(s) => s == expected_aud,
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected_aud)),
        _ => false,
    };
    if !aud_matches {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: aud does not match this Token Endpoint".into(),
        ));
    }

    // Check 11.
    let jti = str_claim("jti")?;

    // Check 12: iat within the issuer's own window. Saturating arithmetic and
    // `try_from` for the same two reasons documented in `attestation.rs`:
    // `iat` originates off the wire, and `max_age_secs as i64` would be a lossy
    // cast of a u64 config value (`u64::MAX as i64 == -1`).
    let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: missing or non-integer iat claim".into(),
        )
    })?;
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    if iat.saturating_add(max_age) < now_unix {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: iat is too far in the past".into(),
        ));
    }
    if iat.saturating_sub(ENVELOPE_CLOCK_SKEW_SECS) > now_unix {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: iat is in the future beyond the tolerable skew".into(),
        ));
    }

    // Check 13. `exp` bounds the client's own intent; check 12 bounds the
    // issuer's. Both apply -- a client may set an arbitrarily distant `exp`.
    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: missing or non-integer exp claim".into(),
        )
    })?;
    if now_unix > exp {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: has expired".into(),
        ));
    }

    // Check 15.
    let pre_authorized_code = str_claim("pre-authorized_code")?;

    Ok(EncryptedCodeClaims {
        iss,
        jti,
        iat,
        pre_authorized_code,
    })
}

/// Check 14: claim this envelope's `jti` exactly once (atomic).
///
/// Mirrors `attestation.rs`'s `claim_pop_jti` deliberately — same `(iss, jti)`
/// keying so one client cannot pre-claim another's values, same hashed key so
/// the raw `jti` never appears in storage, same `iat`-relative `expires_at` so
/// the row expires with the artifact rather than with the request — but over
/// its own namespace and its own claims type.
///
/// `skip_all` is mandatory: `claims` carries the pre-authorized code.
#[tracing::instrument(skip_all)]
pub(crate) async fn claim_envelope_jti(
    storage: &dyn Storage,
    claims: &EncryptedCodeClaims,
    max_age_secs: u64,
) -> Result<(), IssuanceError> {
    let mut hasher = Sha256::new();
    hasher.update(claims.iss.as_bytes());
    hasher.update([0u8]);
    hasher.update(claims.jti.as_bytes());
    let key = B64URL.encode(hasher.finalize());

    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    let expires_at = claims
        .iat
        .saturating_add(max_age)
        .saturating_add(ENVELOPE_CLOCK_SKEW_SECS);

    let claimed = storage
        .insert_kv_if_absent(ENVELOPE_JTI_NAMESPACE, &key, "1", Some(expires_at))
        .await?;
    if !claimed {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: jti has already been used".into(),
        ));
    }
    Ok(())
}

/// The module's single entry point: envelope in, pre-authorized code out.
///
/// Runs the profile's steps 3-7 plus the claim validation its numbered
/// algorithm omits, then claims the `jti`. The caller receives a plain
/// `String` and never learns encryption was involved.
///
/// `skip_all` is mandatory and total.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
pub async fn resolve_encrypted_pre_authorized_code(
    storage: &dyn Storage,
    envelope: &str,
    decryption_keys: &[DecryptionKey],
    allowed_enc: &[String],
    cnf_jwk: &Jwk,
    attestation_iss: &str,
    token_endpoint: &str,
    now_unix: i64,
    max_age_secs: u64,
) -> Result<String, IssuanceError> {
    let payload = open_envelope(envelope, decryption_keys, allowed_enc, cnf_jwk)?;
    let claims = validate_claims(
        &payload,
        attestation_iss,
        token_endpoint,
        now_unix,
        max_age_secs,
    )?;
    claim_envelope_jti(storage, &claims, max_age_secs).await?;

    // No field carries a secret: this records only that the step succeeded.
    tracing::info!("encrypted_pre-authorized_code accepted");
    Ok(claims.pre_authorized_code)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib encrypted_pre_auth
```

Expected: PASS — all Task 4 and Task 5 tests.

- [ ] **Step 5: Scoped gate**

```bash
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/encrypted_pre_auth.rs
git commit -m "feat(issuer): validate encrypted_pre-authorized_code claims and defend replay

Checks 8-15: iss==sub, iss bound to the attestation's sub (the
impersonation defence the profile states only inline in its example),
aud == the token endpoint URL (deliberately not the ABCA PoP's issuer
identifier), jti/iat/exp, and a single-use jti in its own KV namespace so
it cannot collide with a Client Attestation PoP jti."
```

---

### Task 6: Wire the extension into the Token Endpoint

The mode matrix, the resolver call, and the configurable access-token lifetime — all inside `foundry-issuer`.

**Files:**

- Modify: `crates/foundry-issuer/src/token.rs` — `TokenRequest` (lines 21-32), `handle_token_request` (lines 56-180), `handle_pre_authorized_code_grant` (lines 180-243), `mint_and_save_tokens` (lines 318-343)
- Modify: `crates/foundry-issuer/src/lib.rs` (re-export the new public items)
- Test: `crates/foundry-issuer/src/token.rs` (inline `mod tests`)

**Interfaces:**

- Consumes: `resolve_encrypted_pre_authorized_code` (Task 5), `EncryptedPreAuthCodeConfig` and `IssuerConfig.access_token_ttl_secs` (Task 2), `PopClaims.cnf_jwk` (Task 3).
- Produces:

  ```rust
  pub struct EncryptedCodePolicy<'a> {
      pub cfg: &'a EncryptedPreAuthCodeConfig,
      pub decryption_keys: &'a [DecryptionKey],
      pub allowed_enc: &'a [String],
      pub token_endpoint: &'a str,
  }

  // TokenRequest gains:
  #[serde(rename = "encrypted_pre-authorized_code", default)]
  pub encrypted_pre_authorized_code: Option<String>,

  // handle_token_request gains two trailing parameters, in this order:
  //   encrypted_code: &EncryptedCodePolicy<'_>,
  //   access_token_ttl_secs: u64,
  ```

  Task 7 constructs `EncryptedCodePolicy` in `server.rs`.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `crates/foundry-issuer/src/token.rs`. First add these helpers — `pre_auth_token_request()` replaces the ad-hoc `TokenRequest` literals the existing tests build, so the new field lands in one place:

```rust
    fn pre_auth_token_request() -> TokenRequest {
        TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        }
    }

    fn encrypted_policy_cfg(mode: Mode) -> foundry_core::config::EncryptedPreAuthCodeConfig {
        foundry_core::config::EncryptedPreAuthCodeConfig {
            mode,
            max_age_secs: 300,
        }
    }

    /// Drives `handle_token_request` with wallet attestation and DPoP both
    /// disabled, so these tests isolate the encrypted-code mode matrix.
    async fn call_token_with_ttl(
        storage: &dyn Storage,
        req: &TokenRequest,
        encrypted_cfg: &foundry_core::config::EncryptedPreAuthCodeConfig,
        keys: &[foundry_core::crypto::jwe::DecryptionKey],
        now: i64,
        ttl: u64,
    ) -> Result<TokenResponse, IssuanceError> {
        let enc_values = vec!["A128GCM".to_string()];
        let policy = EncryptedCodePolicy {
            cfg: encrypted_cfg,
            decryption_keys: keys,
            allowed_enc: &enc_values,
            token_endpoint: TOKEN_HTU,
        };
        handle_token_request(
            storage,
            req,
            &AttestationMode {
                mode: Mode::Disabled,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            None,
            None,
            &DpopConfig::default(),
            &DpopPresentation {
                scheme_is_dpop: false,
                proof_jwt: None,
                htm: "POST",
                htu: TOKEN_HTU,
                ath: None,
            },
            &test_nonce_secret(),
            TOKEN_HTU,
            now,
            &policy,
            ttl,
        )
        .await
    }

    async fn call_token(
        storage: &dyn Storage,
        req: &TokenRequest,
        encrypted_cfg: &foundry_core::config::EncryptedPreAuthCodeConfig,
        keys: &[foundry_core::crypto::jwe::DecryptionKey],
        now: i64,
    ) -> Result<TokenResponse, IssuanceError> {
        call_token_with_ttl(storage, req, encrypted_cfg, keys, now, 600).await
    }
```

`test_nonce_secret()` already exists in this test module (`token.rs:376`, returning `NonceSecret::from_bytes([99u8; 32])` — note it takes the array **by value**, not by reference). `DpopConfig::default()` and the `DpopPresentation` literal must likewise match how the existing tests build them: read one existing `handle_token_request` test first and copy its construction rather than the shapes sketched above.

Then the tests:

```rust
    /// `disabled` REJECTS the member rather than ignoring it. Silently falling
    /// back to the plaintext parameter would be the downgrade the extension
    /// exists to prevent.
    #[tokio::test]
    async fn disabled_mode_rejects_a_present_encrypted_member() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-disabled");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut req = pre_auth_token_request();
        req.encrypted_pre_authorized_code = Some("eyJ.irrelevant.value".to_string());

        let err = call_token(
            &storage,
            &req,
            &encrypted_policy_cfg(Mode::Disabled),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("a disabled feature must reject the member, not ignore it");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// An attacker probing with a bogus envelope must not be able to burn a
    /// legitimate holder's code. The same property already tested for tx_code
    /// and code_verifier -- this is its third instance.
    #[tokio::test]
    async fn a_rejected_envelope_does_not_burn_the_pre_authorized_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-noburn");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut req = pre_auth_token_request();
        req.pre_authorized_code = None;
        req.encrypted_pre_authorized_code = Some("not.a.real.envelope".to_string());

        let _ = call_token(
            &storage,
            &req,
            &encrypted_policy_cfg(Mode::Required),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("a malformed envelope must be rejected");

        assert!(
            load_transaction_by_pre_auth_code(&storage, "code-123")
                .await
                .unwrap()
                .is_some(),
            "a rejected envelope must leave the pre-authorized code redeemable"
        );
    }

    /// `required` rejects the plaintext parameter -- the anti-downgrade rule.
    #[tokio::test]
    async fn required_mode_rejects_a_plaintext_pre_authorized_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-required");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let err = call_token(
            &storage,
            &pre_auth_token_request(),
            &encrypted_policy_cfg(Mode::Required),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("required mode must not accept a plaintext code");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn required_mode_rejects_a_request_with_neither_form() {
        let storage = test_storage().await;
        let mut req = pre_auth_token_request();
        req.pre_authorized_code = None;

        let err = call_token(
            &storage,
            &req,
            &encrypted_policy_cfg(Mode::Required),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("required mode with nothing present must be rejected");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// `optional` keeps the plaintext path working -- the migration rung.
    #[tokio::test]
    async fn optional_mode_still_accepts_a_plaintext_pre_authorized_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-optional");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let res = call_token(
            &storage,
            &pre_auth_token_request(),
            &encrypted_policy_cfg(Mode::Optional),
            &[],
            1_700_000_000,
        )
        .await
        .expect("optional mode must keep the plaintext path working");
        assert!(!res.access_token.is_empty());
    }

    /// BOTH present is a rejection, not a precedence decision. Two codes in one
    /// request is a client bug; picking a winner hides it.
    #[tokio::test]
    async fn optional_mode_rejects_a_request_carrying_both_forms() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-both");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut req = pre_auth_token_request();
        req.encrypted_pre_authorized_code = Some("eyJ.some.envelope".to_string());

        let err = call_token(
            &storage,
            &req,
            &encrypted_policy_cfg(Mode::Optional),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("exactly one of the two forms must be present");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// The remaining cheap cells of the mode matrix. Each is a configuration a
    /// real deployment can be in, so each gets its own case even where several
    /// share an expected outcome.
    #[tokio::test]
    async fn the_remaining_mode_matrix_cells_reject() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-matrix");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        // disabled + envelope only (no plaintext to fall back to)
        let mut req = pre_auth_token_request();
        req.pre_authorized_code = None;
        req.encrypted_pre_authorized_code = Some("eyJ.env.value".to_string());
        assert!(matches!(
            call_token(&storage, &req, &encrypted_policy_cfg(Mode::Disabled), &[], 1_700_000_000)
                .await
                .expect_err("disabled must reject the member even with no plaintext present"),
            IssuanceError::InvalidRequest(_)
        ));

        // disabled + neither -- the pre-existing "missing code" behaviour,
        // which the extension must not have changed.
        let mut req = pre_auth_token_request();
        req.pre_authorized_code = None;
        assert!(matches!(
            call_token(&storage, &req, &encrypted_policy_cfg(Mode::Disabled), &[], 1_700_000_000)
                .await
                .expect_err("a request with no code at all is still invalid_grant"),
            IssuanceError::InvalidGrant(_)
        ));

        // optional + neither -- same, under the migration rung.
        let mut req = pre_auth_token_request();
        req.pre_authorized_code = None;
        assert!(matches!(
            call_token(&storage, &req, &encrypted_policy_cfg(Mode::Optional), &[], 1_700_000_000)
                .await
                .expect_err("optional with neither form is still invalid_grant"),
            IssuanceError::InvalidGrant(_)
        ));

        // required + both -- the envelope is attempted (the plaintext is simply
        // ignored under required), so this fails on the envelope, not on
        // arity. Asserted only as "rejected": the precise variant is the
        // envelope resolver's business, covered in Tasks 4 and 5.
        let mut req = pre_auth_token_request();
        req.encrypted_pre_authorized_code = Some("not.an.envelope".to_string());
        assert!(
            call_token(&storage, &req, &encrypted_policy_cfg(Mode::Required), &[], 1_700_000_000)
                .await
                .is_err(),
            "required with both forms must not succeed on the plaintext"
        );

        // The transaction survived every one of those rejections.
        assert!(
            load_transaction_by_pre_auth_code(&storage, "code-123")
                .await
                .unwrap()
                .is_some(),
            "no rejected request may burn the pre-authorized code"
        );
    }

    #[tokio::test]
    async fn expires_in_reflects_the_configured_access_token_ttl() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-ttl");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let res = call_token_with_ttl(
            &storage,
            &pre_auth_token_request(),
            &encrypted_policy_cfg(Mode::Disabled),
            &[],
            1_700_000_000,
            86_400,
        )
        .await
        .expect("a configured ttl must be honoured");

        assert_eq!(res.expires_in, 86_400);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib token
```

Expected: FAIL — `struct TokenRequest has no field named encrypted_pre_authorized_code`.

**On mode-matrix coverage.** The spec (§7) asks for all twelve cells of
`3 modes × {member, plaintext, both, neither}`. Ten are covered above at this
level. The two remaining cells — `optional`/`required` with a **valid** envelope
that is *accepted* — are deliberately **not** duplicated here: exercising them
through `handle_token_request` needs a full trust-anchored wallet-attestation
plus PoP fixture, and the envelope path is already proven end to end by Task 4's
positive control and Task 5's, against the very function this one delegates to.
Testing it a third time through a heavier harness would buy no additional
coverage of the extension, only of the attestation plumbing that
`attestation.rs`'s own suite already covers.

- [ ] **Step 3: Add the request field and the policy struct**

In `crates/foundry-issuer/src/token.rs`, extend `TokenRequest`:

```rust
    /// Google Wallet's `encrypted_pre-authorized_code` extension: the
    /// pre-authorized code as a JWS nested inside a JWE, replacing the
    /// plaintext `pre-authorized_code` above.
    ///
    /// **Vendor profile only** (root `AGENTS.md` §4.4); see
    /// `crate::encrypted_pre_auth`. The serde rename is the canonical spelling
    /// from the profile's prose — its worked example says
    /// `encrypted_pre-authorization_code`, which is not accepted.
    #[serde(rename = "encrypted_pre-authorized_code", default)]
    pub encrypted_pre_authorized_code: Option<String>,
```

Add the policy grouping struct near `DpopPresentation`'s definition style — one struct rather than four loose parameters, matching how `DpopPresentation` and `DpopNoncePolicy` already group their inputs:

```rust
/// Everything `handle_token_request` needs to resolve an
/// `encrypted_pre-authorized_code`. Grouped rather than passed as four loose
/// parameters, following `DpopPresentation`/`DpopNoncePolicy`.
pub struct EncryptedCodePolicy<'a> {
    pub cfg: &'a EncryptedPreAuthCodeConfig,
    /// The issuer's `credential_request_encryption` private keys — the profile
    /// reuses them verbatim ("the same key used to encrypt the request to the
    /// Credential Endpoint"). Empty when the mechanism is unconfigured, which
    /// `Config::validate()` already forbids alongside a non-disabled mode.
    pub decryption_keys: &'a [DecryptionKey],
    pub allowed_enc: &'a [String],
    /// The absolute Token Endpoint URL the inner JWS's `aud` must equal.
    /// Deliberately not the AS issuer identifier — see
    /// `encrypted_pre_auth::validate_claims`.
    pub token_endpoint: &'a str,
}
```

Add the imports `use crate::encrypted_pre_auth::resolve_encrypted_pre_authorized_code;`, `use foundry_core::config::EncryptedPreAuthCodeConfig;` and `use foundry_core::crypto::jwe::DecryptionKey;`.

- [ ] **Step 4: Thread the parameters and implement the mode matrix**

`handle_token_request` gains two trailing parameters and forwards them plus `pop_claims` into the pre-auth branch:

```rust
    encrypted_code: &EncryptedCodePolicy<'_>,
    access_token_ttl_secs: u64,
```

Its dispatch becomes:

```rust
    match req.grant_type.as_str() {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
            handle_pre_authorized_code_grant(
                storage,
                req,
                dpop_jkt,
                encrypted_code,
                pop_claims.as_ref(),
                access_token_ttl_secs,
                now_unix,
            )
            .await
        }
        "authorization_code" => {
            handle_authorization_code_grant(
                storage,
                req,
                dpop_jkt,
                access_token_ttl_secs,
                now_unix,
            )
            .await
        }
        _ => Err(IssuanceError::InvalidGrant(
            "unsupported_grant_type".to_string(),
        )),
    }
```

`pop_claims` is currently consumed by `if let Some(claims) = pop_claims` around line 113; change that to `if let Some(claims) = pop_claims.as_ref()` so the binding survives to the dispatch.

Then replace the opening of `handle_pre_authorized_code_grant` — everything from its signature down to and including the current `let code = req.pre_authorized_code...` block — with:

```rust
#[allow(clippy::too_many_arguments)]
async fn handle_pre_authorized_code_grant(
    storage: &dyn Storage,
    req: &TokenRequest,
    dpop_jkt: Option<String>,
    encrypted_code: &EncryptedCodePolicy<'_>,
    pop_claims: Option<&crate::attestation::PopClaims>,
    access_token_ttl_secs: u64,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let code = resolve_code(storage, req, encrypted_code, pop_claims, now_unix).await?;
    // ... the rest of the existing body, using `&code` where it used `code` ...
```

and add the resolver alongside it. This is the mode matrix, and it runs **before**
`load_transaction_by_pre_auth_code`, so a rejected envelope can never reach the
transaction lookup — the same anti-code-burning ordering `claim_pop_jti` and the
DPoP check already establish in `handle_token_request`:

```rust
/// Resolve the pre-authorized code from whichever form the configured mode
/// permits.
///
/// **Vendor profile only** (root `AGENTS.md` §4.4): the encrypted form is
/// defined solely by the Google Wallet VCI 1.0 Profile, §"token request field
/// signing & encryption". Scoped to this grant deliberately — the profile
/// defines the extension only for the pre-authorized code flow, so the
/// authorization_code grant must not silently inherit half of it.
///
/// `skip_all` is mandatory: `req` carries both code forms.
#[tracing::instrument(skip_all, fields(mode = ?encrypted_code.cfg.mode))]
async fn resolve_code(
    storage: &dyn Storage,
    req: &TokenRequest,
    encrypted_code: &EncryptedCodePolicy<'_>,
    pop_claims: Option<&crate::attestation::PopClaims>,
    now_unix: i64,
) -> Result<String, IssuanceError> {
    let plaintext = req.pre_authorized_code.as_deref();
    let envelope = req.encrypted_pre_authorized_code.as_deref();

    match (&encrypted_code.cfg.mode, plaintext, envelope) {
        // Disabled: the member is REJECTED, never ignored. Silently falling
        // back to the plaintext form would be exactly the downgrade the
        // extension exists to prevent.
        (Mode::Disabled, _, Some(_)) => Err(IssuanceError::InvalidRequest(
            "encrypted_pre-authorized_code is not enabled at this Token Endpoint".into(),
        )),
        (Mode::Disabled, Some(code), None) => Ok(code.to_string()),
        (Mode::Disabled, None, None) => Err(IssuanceError::InvalidGrant(
            "missing pre-authorized_code".to_string(),
        )),

        // Optional: exactly one. Both present is a client bug, and picking a
        // winner would hide it.
        (Mode::Optional, Some(_), Some(_)) => Err(IssuanceError::InvalidRequest(
            "exactly one of pre-authorized_code and encrypted_pre-authorized_code may be \
             present"
                .into(),
        )),
        (Mode::Optional, Some(code), None) => Ok(code.to_string()),
        (Mode::Optional, None, None) => Err(IssuanceError::InvalidGrant(
            "missing pre-authorized_code".to_string(),
        )),

        // Required: the anti-downgrade rule, structurally identical to RFC 9449
        // §7.2's rejection of a DPoP-bound token presented as Bearer. Without
        // it `required` would be advisory.
        (Mode::Required, Some(_), None) => Err(IssuanceError::InvalidRequest(
            "this Token Endpoint requires encrypted_pre-authorized_code; a plaintext \
             pre-authorized_code is not accepted"
                .into(),
        )),
        (Mode::Required, _, None) => Err(IssuanceError::InvalidRequest(
            "encrypted_pre-authorized_code is required at this Token Endpoint".into(),
        )),

        (Mode::Optional | Mode::Required, _, Some(env)) => {
            // The profile's step 5 needs the Client Attestation's cnf.jwk. With
            // no verified attestation there is none, so the request cannot be
            // authenticated -- `Config::validate()` forbids the *configuration*
            // that makes this universal, leaving only the per-request case of a
            // wallet that sent no attestation under `wallet_attestation.mode:
            // optional`.
            let claims = pop_claims.ok_or_else(|| {
                IssuanceError::InvalidClient(
                    "encrypted_pre-authorized_code requires a verified wallet attestation: \
                     its inner JWS is signed by the attestation's cnf.jwk"
                        .into(),
                )
            })?;

            resolve_encrypted_pre_authorized_code(
                storage,
                env,
                encrypted_code.decryption_keys,
                encrypted_code.allowed_enc,
                &claims.cnf_jwk,
                &claims.iss,
                encrypted_code.token_endpoint,
                now_unix,
                encrypted_code.cfg.max_age_secs,
            )
            .await
        }
    }
}
```

`handle_pre_authorized_code_grant` and `handle_authorization_code_grant` both currently end by calling `mint_and_save_tokens`; give that function an `access_token_ttl_secs: u64` parameter and replace its hardcode:

```rust
async fn mint_and_save_tokens(
    storage: &dyn Storage,
    mut tx: IssuanceTransaction,
    dpop_jkt: Option<String>,
    access_token_ttl_secs: u64,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let access_token = format!("at_{}", Uuid::new_v4().simple());
    // One value drives both the wire `expires_in` and the transaction row's
    // TTL: the row must outlive the token that addresses it, and equal
    // lifetimes is the tightest correct choice.
    let expires_in = access_token_ttl_secs;
    // ... rest unchanged ...
```

Thread `access_token_ttl_secs` through `handle_authorization_code_grant` too, so both grants honour it.

Finally, re-export from `crates/foundry-issuer/src/lib.rs`:

```rust
pub use encrypted_pre_auth::{
    EncryptedCodeClaims, open_envelope, resolve_encrypted_pre_authorized_code, validate_claims,
};
pub use token::{EncryptedCodePolicy, TokenRequest, TokenResponse, handle_token_request};
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib token
```

Expected: PASS. Pre-existing token tests that build `TokenRequest` literals or call `handle_token_request` directly need the new field and the two new arguments; the compiler lists each one.

- [ ] **Step 6: Scoped gate**

```bash
cargo test -p foundry-issuer
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```

`foundry` is expected to fail to *compile* at this point — `server.rs` has not been updated yet. That is Task 7; do not patch it here.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-issuer/src/token.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): accept encrypted_pre-authorized_code at the Token Endpoint

Three-mode matrix: disabled rejects the member outright (never silently
falls back to plaintext), optional accepts exactly one form, required
rejects plaintext as an anti-downgrade rule. Resolution runs before the
transaction lookup, so a rejected envelope cannot burn a holder's code.

access_token_ttl_secs replaces the hardcoded 600 and drives both the wire
expires_in and the transaction row TTL."
```

---

### Task 7: HTTP wiring and OpenAPI

`server.rs` builds the policy from `AppState` and passes it through. The wire contract changes, so the OpenAPI specs must be regenerated.

**Files:**

- Modify: `crates/foundry/src/server.rs` — `token_handler` (around lines 735-835), where `handle_token_request` is called at line 811
- Modify: `openapi.json`, `openapi-wallet.json` (regenerated, not hand-edited)
- Test: `crates/foundry/tests/wallet_issuance.rs` (an end-to-end case)

**Interfaces:**

- Consumes: `EncryptedCodePolicy` and the two new `handle_token_request` parameters (Task 6); `AppState.request_decryption_keys` and `AppState.config` (existing).
- Produces: no new public API.

- [ ] **Step 1: Write the failing test**

Add to `crates/foundry/tests/wallet_issuance.rs`. `support::` already provides the router/config fixtures this file uses — read an existing `/token` test there and mirror its setup.

```rust
/// The extension is off unless configured. A wallet that sends the member to a
/// default deployment must get a clean rejection, not a 500 and not a silent
/// fallback to the plaintext code it also sent.
#[tokio::test]
async fn token_endpoint_rejects_the_encrypted_member_when_the_feature_is_disabled() {
    let (router, _state) = support::wallet_router_with_default_config().await;

    let body = "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code\
                &pre-authorized_code=code-123\
                &encrypted_pre-authorized_code=eyJ.some.envelope";

    let res = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
```

`support::wallet_router_with_default_config()` stands for whatever helper this file already uses to build a router plus a redeemable offer; use that helper's real name and, if it does not pre-create an offer, create one the way the neighbouring tests do.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p foundry --test wallet_issuance
```

Expected: FAIL to compile — `handle_token_request` takes 2 more arguments than supplied.

- [ ] **Step 3: Build the policy in `token_handler`**

In `crates/foundry/src/server.rs`, immediately before the `handle_token_request` call at line 811, and reusing the `htu` already computed just above it (which is exactly the Token Endpoint URL the inner JWS's `aud` must equal):

```rust
    // The profile reuses the Credential Request decryption keys verbatim: "The
    // JWE must be encrypted using the Issuer's credential_request_encryption.jwks.
    // This is the same key used to encrypt the request to the Credential
    // Endpoint." An empty enc list when the mechanism is unconfigured is safe:
    // `Config::validate()` forbids that alongside a non-disabled mode, and the
    // resolver rejects rather than accepting anything.
    let allowed_enc: &[String] = state
        .config
        .issuer
        .request_encryption
        .as_ref()
        .map(|re| re.enc_values_supported.as_slice())
        .unwrap_or(&[]);
    let encrypted_code_policy = foundry_issuer::EncryptedCodePolicy {
        cfg: &state.config.issuer.encrypted_pre_authorized_code,
        decryption_keys: &state.request_decryption_keys,
        allowed_enc,
        // The same `htu` the DPoP proof is bound to -- one value, so the two
        // audiences cannot drift apart.
        token_endpoint: &htu,
    };
```

and extend the call:

```rust
    let res = foundry_issuer::handle_token_request(
        state.storage.as_ref(),
        &req,
        &state.config.issuer.wallet_attestation,
        attestation_hdr,
        pop_hdr,
        &state.config.issuer.dpop,
        &dpop_presentation,
        state.nonce_secret.as_ref(),
        &issuer_identifier,
        now,
        &encrypted_code_policy,
        state.config.issuer.access_token_ttl_secs,
    )
```

No new error mapping is needed: `InvalidRequest` and `InvalidClient` already have arms in `token_error_response`, and root `AGENTS.md` §4.5's one-record rule is satisfied by that existing mapper.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p foundry --test wallet_issuance
```

Expected: PASS.

- [ ] **Step 5: Regenerate the OpenAPI specs**

`TokenRequest` gained a member, so both specs change (root `AGENTS.md` §6):

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
git diff --stat openapi.json openapi-wallet.json
```

Expected: the diff shows `encrypted_pre-authorized_code` added to the `TokenRequest` schema and nothing else. `crates/foundry/tests/openapi_endpoints.rs` compares the committed files against freshly generated ones, so a stale spec fails that test.

- [ ] **Step 6: Scoped gate**

```bash
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: all green — including `foundry`, which Task 6 deliberately left uncompilable.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/tests/wallet_issuance.rs openapi.json openapi-wallet.json
git commit -m "feat(server): wire encrypted_pre-authorized_code through the Token Endpoint

token_handler builds EncryptedCodePolicy from AppState, reusing the
credential_request_encryption keys the profile specifies and binding the
inner JWS aud to the same htu the DPoP proof already uses. OpenAPI specs
regenerated for the new TokenRequest member."
```

---

### Task 8: Redaction gate and documentation

The behavioural proof that no new secret leaks, plus the operator- and agent-facing documentation the repository's own maintenance rules require.

**Files:**

- Modify: `crates/foundry/tests/logging_redaction.rs`
- Modify: `crates/foundry-issuer/AGENTS.md` (module map + Gotchas)
- Modify: `crates/foundry/AGENTS.md` (the `token_handler` argument list note)
- Modify: `README.md` (the two config blocks)
- Modify: `docs/conformance/openid4vc-conformance.md` (the key-reuse note)

**Interfaces:**

- Consumes: everything from Tasks 1-7.
- Produces: no code API.

- [ ] **Step 1: Write the failing redaction test**

Add to `crates/foundry/tests/logging_redaction.rs`, following that file's existing pattern exactly — capture at `TRACE`, drive the real router, then search the whole buffer. Read its header comment (lines 1-18) first; it explains why both properties matter.

```rust
/// Root `AGENTS.md` §4.5: the envelope and the code inside it must never reach
/// a log, at any level, under any flag. The uniquely identifiable values below
/// exist so a substring search over the whole captured buffer is conclusive.
#[tokio::test]
async fn the_encrypted_pre_authorized_code_envelope_is_never_logged() {
    let _guard = sensitive_lock().await;
    let capture = log_capture::install_trace_capture();

    let (router, _state) = support::wallet_router_with_default_config().await;

    const ENVELOPE: &str = "UNIQUE-ENVELOPE-VALUE-ffffffff";
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code\
         &encrypted_pre-authorized_code={ENVELOPE}"
    );

    let _ = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let logs = capture.contents();
    assert!(
        !logs.contains(ENVELOPE),
        "the encrypted_pre-authorized_code envelope leaked into the log"
    );
}
```

`sensitive_lock()`, `log_capture::install_trace_capture()` and `capture.contents()` stand for whatever this file's existing helpers are actually called — copy them from the test immediately above rather than inventing names.

- [ ] **Step 2: Run the test to verify it passes (or exposes a real leak)**

```bash
cargo test -p foundry --test logging_redaction
```

Expected: PASS. **Unlike every other task, a pass here is the expected first result** — the implementation was written with `skip_all` throughout. If it FAILS, that is a genuine leak: fix the emitting site, never the assertion (that instruction is already in the file's header comment).

- [ ] **Step 3: Update the crate AGENTS.md files**

In `crates/foundry-issuer/AGENTS.md`, add to the module map table:

```markdown
| `encrypted_pre_auth.rs` | Google Wallet's `encrypted_pre-authorized_code` extension: JWE-then-JWS envelope opening, claim validation, `jti` replay defence |
```

and to Gotchas:

```markdown
- **The canonical parameter name is `encrypted_pre-authorized_code`.** The Google
  Wallet profile's prose says that; its worked Token Request example says
  `encrypted_pre-authorization_code`. Prose wins (it is the normative statement,
  and it matches OpenID4VCI's own `pre-authorized_code`), and only the canonical
  spelling is accepted. Raised with Google — see §9.2 of
  `docs/superpowers/specs/2026-08-17-encrypted-pre-authorized-code-design.md`.
- **`EncryptedPreAuthCodeConfig`'s `mode` needs an explicit `default =` function.**
  `Mode`'s own `Default` is `Optional`; a bare `#[serde(default)]` would switch
  the extension on for every deployment that never mentions it. Guarded by
  `encrypted_pre_authorized_code_defaults_to_disabled`.
- **The envelope's `aud` is the Token Endpoint URL, not the AS issuer
  identifier.** The Client Attestation PoP uses the issuer identifier (ABCA §9
  rule 10); the envelope uses the endpoint URL (Google Wallet profile example).
  Two artifacts, two audiences — conflating them breaks interop.
- **`encrypted_pre_auth.rs` has its own `jti` namespace.** Sharing
  `attestation.rs`'s would let a PoP `jti` and an envelope `jti` of the same
  value collide, so one artifact could deny service to the other.
```

In `crates/foundry/AGENTS.md`, note that `token_handler` now builds an
`EncryptedCodePolicy` from `AppState` and passes it plus
`issuer.access_token_ttl_secs` into `handle_token_request`. No route changed.

- [ ] **Step 4: Update README.md and the conformance report**

In `README.md`'s configuration section, document both blocks:

```yaml
issuer:
  # Google Wallet's encrypted_pre-authorized_code extension (vendor profile,
  # not a specification). Off by default.
  #   disabled  - the member is rejected if present
  #   optional  - either form accepted; exactly one must be present
  #   required  - the member is mandatory; a plaintext code is rejected
  # Enabling it requires wallet_attestation enabled AND request_encryption keys.
  encrypted_pre_authorized_code:
    mode: disabled
    max_age_secs: 300

  # Access-token lifetime. Drives both the `expires_in` on the wire and the
  # TTL of the transaction row the token addresses. NOT the same as
  # storage.transaction_ttl_secs, which bounds how long an OFFER stays
  # redeemable before /token is ever called.
  access_token_ttl_secs: 600
```

In `docs/conformance/openid4vc-conformance.md`, append to the evidence of the
rows covering `credential_request_encryption` keys (search for `VCI-0100`,
`VCI-0101` and `VCI-0135`) a sentence noting that since 2026-08-17 those keys
have a second consumer — the Google Wallet `encrypted_pre-authorized_code`
extension — which is off by default and introduces no new gap, being an
extension rather than a conformance claim.

- [ ] **Step 5: Full gate — the branch is complete**

This is the one place root `AGENTS.md` §5.3's full gate runs. Capture to disk and grep, per §5.6 — a bare `tail` of a workspace run silently drops earlier failures:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace 2>&1 | tee /tmp/test-output.log
grep -c "FAILED" /tmp/test-output.log       # 0 or no output
grep "^test result:" /tmp/test-output.log   # one line per binary -- read them all
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets 2>&1 | tee /tmp/clippy-output.log
grep -c "^error" /tmp/clippy-output.log     # 0
```

Expected: every `test result:` line reads `ok`, no `FAILED`, no clippy errors.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/tests/logging_redaction.rs crates/foundry-issuer/AGENTS.md \
        crates/foundry/AGENTS.md README.md docs/conformance/openid4vc-conformance.md
git commit -m "docs+test: redaction gate and documentation for encrypted_pre-authorized_code

Behavioural proof that the envelope never reaches a log, plus the module
map, gotchas, operator config docs and the conformance note recording that
the credential_request_encryption keys now have a second consumer."
```

---

## Notes for the Executor

**Task order matters.** 1 → 2 → 3 are independent of each other but all three precede 4. 4 → 5 → 6 → 7 are strictly sequential. 8 is last.

**Task 6 deliberately leaves `foundry` uncompilable.** `handle_token_request`'s signature changes there and `server.rs` catches up in Task 7. Do not fix `server.rs` early — it splits one reviewable change across two tasks.

**Read before you write.** Several steps say "copy what the neighbouring test does" rather than inventing a fixture. That is deliberate: this repository's test modules have established helpers (`sample_tx`, `test_storage`, `matched_attestation_and_pop`, `base_config`, the `logging_redaction.rs` capture helpers) whose exact names and signatures were not all transcribed into this plan. Match them rather than adding parallel ones.

**Five questions are open with Google** (spec §9.2). None block this plan. The one that could change code here is Q2 (the parameter-name discrepancy); if Google confirms the example's spelling instead, the fix is one `serde(rename = ...)` string and its test.
