# Signed OpenID4VP Requests over the DC API (`openid4vp-v1-signed`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a relying party request an OpenID4VP presentation over the W3C Digital Credentials API using a **signed** Request Object (`openid4vp-v1-signed`), alongside the unsigned form foundry already supports.

**Architecture:** A new `transport` value `dc_api_signed` on `POST /admin/verification/requests`. The signing half of the existing Request Object builder is extracted into a shared crate-private `sign_request_object`, and two thin payload builders sit on top of it — the existing redirect payload and a new DC API payload carrying `client_id` and `expected_origins`. A `VerificationTransaction::is_dc_api()` predicate replaces two `transport == "dc_api"` equality tests on the verify side so both DC API forms keep the Origin-based response binding. foundry additionally emits the DC API exchange protocol identifier on the response so the calling page cannot pair the wrong one with the payload.

**Tech Stack:** Rust (workspace crates `foundry-verifier`, `foundry`), `josekit`, `serde_json` (with `preserve_order` enabled transitively — `Map` is insertion-ordered), `axum`, `utoipa`, `cargo nextest`.

**Spec:** [`docs/superpowers/specs/2026-08-26-openid4vp-v1-signed-dc-api-design.md`](../specs/2026-08-26-openid4vp-v1-signed-dc-api-design.md)

## Global Constraints

- **Test runner is `cargo nextest run`, never `cargo test`.** Root `AGENTS.md` §5.1.
- **The gate is the whole workspace, every time — there is no cheaper tier:**

  ```bash
  cargo fmt
  cargo nextest run --workspace --no-fail-fast --status-level fail
  cargo clippy --workspace --all-targets -- -D warnings
  ```

- **No `.unwrap()`, `.expect()`, `panic!()` or `unreachable!()` in request-handling code.** Permitted only inside `#[cfg(test)]` and files under `tests/`. Root `AGENTS.md` §4.1.
- **Every `#[tracing::instrument]` MUST carry `skip_all`.** Root `AGENTS.md` §4.5. Enforced by `crates/foundry/tests/instrumentation_hygiene.rs`.
- **Never log** private/ephemeral JWKs, nonces, or raw request payloads except behind BOTH `foundry_core::obs::sensitive_enabled()` AND a `debug`/`trace` level. Root `AGENTS.md` §4.5.
- **Cite the spec in code comments** for any protocol-facing behaviour, naming section or line, e.g. `// OpenID4VP 1.0 L2442 -- expected_origins`. Root `AGENTS.md` §4.4.
- **Layering:** `foundry-verifier` may depend on `foundry-core`, `foundry-sd-jwt-vc`, `foundry-mdoc` — never on `foundry-issuer` or `crates/foundry`.
- **Spec line references** are line numbers in `docs/specs/openid-4-verifiable-presentations-1_0.md` unless prefixed HAIP, which means `docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md`.
- **Commit after each task.** Conventional-commit prefixes (`feat:`, `refactor:`, `test:`, `docs:`).

---

### Task 1: Transport predicate — `is_dc_api()`

Fixes a latent correctness hazard *before* the new transport exists. `verify.rs` decides the response-binding rules by testing `tx.transport == "dc_api"`. Once `dc_api_signed` exists, those tests would miss it and silently apply the **redirect** binding (an `x509_hash:` KB-JWT audience and an `OpenID4VPHandover` instead of `OpenID4VPDCAPIHandover`), so every signed DC API presentation would fail for a reason unrelated to its real defect. Doing this first means the new transport lands on already-correct verification.

**Files:**

- Modify: `crates/foundry-verifier/src/transaction.rs` (add method after the `VerificationTransaction` struct, which ends at line 110)
- Modify: `crates/foundry-verifier/src/verify.rs:836` (mdoc candidate transcripts) and `crates/foundry-verifier/src/verify.rs:1348` (SD-JWT VC expected audiences)
- Test: `crates/foundry-verifier/src/verify.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `VerificationTransaction::is_dc_api(&self) -> bool` — true for `"dc_api"` and `"dc_api_signed"`. Tasks 3 and 5 rely on this being true for `"dc_api_signed"`.

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `crates/foundry-verifier/src/verify.rs`. Both mirror existing tests: the first is `gap_vp_07_dc_api_transport_never_accepts_origin_prefixed_kb_jwt_audience` (line 4575) with the transport changed; the second is `dc_api_mdoc_accepts_a_later_configured_origin` (line 5261) with the transport changed.

```rust
    /// OpenID4VP L2543: the DC API response audience is the Origin prefixed
    /// with `origin:` **even for signed requests**. A signed DC API transport
    /// must therefore get the same KB-JWT audience treatment as the unsigned
    /// one -- if `verify.rs` compared `transport == "dc_api"` by equality, this
    /// presentation would be checked against the `x509_hash:` Client Identifier
    /// instead and fail as a policy verdict.
    #[tokio::test]
    async fn dc_api_signed_transport_expects_the_origin_prefixed_audience() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        tx.transport = "dc_api_signed".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: None,
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

        // `test_config` sets dc_api_expected_origins to this single entry.
        let origin_audience = "origin:https://verifier-website.example";
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            origin_audience,
            &tx.nonce,
            None,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(
            res.verified,
            "a signed DC API presentation bound to `origin:<origin>` must verify; checks={:?}, credentials={:?}",
            res.checks, res.credentials
        );
    }

    /// The mdoc half of the same rule (L2963): a signed DC API presentation
    /// must be bound by `OpenID4VPDCAPIHandover`, not the redirect
    /// `OpenID4VPHandover`.
    #[tokio::test]
    async fn dc_api_signed_transport_selects_the_dc_api_handover() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let (mut config, _dir) = test_config(&String::from_utf8(root_pem).unwrap());
        config.verifier.dc_api_expected_origins = vec!["https://first.example.com".to_string()];

        let (mut tx, _) = sample_tx();
        tx.dcql_query = mdoc_dcql_query();
        tx.transport = "dc_api_signed".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        let transcript = session_transcript_value(&SessionTranscriptParams::DcApi {
            origin: "https://first.example.com".to_string(),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
        })
        .unwrap();
        let jwe = mdoc_presentation_jwe(
            &leaf_cert,
            &leaf_key,
            &transcript,
            &tx.ephem_public_jwk,
            now_secs(),
        );

        let res = verify_vp_response(&config, &mut tx, &jwe, &MockResolver { token: None })
            .await
            .unwrap();
        assert!(
            res.verified,
            "a signed DC API mdoc presentation must be bound by OpenID4VPDCAPIHandover; checks={:?}",
            res.checks
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier dc_api_signed_transport
```

Expected: both FAIL. The SD-JWT VC one fails with a `sd_jwt_vc_signature_and_kb_jwt` check reporting an audience mismatch (it was compared against `x509_hash:…`); the mdoc one fails its `mdoc_issuer_auth_and_device_signature` check because the Device Signature was made over a DC API transcript but verified against a redirect one.

- [ ] **Step 3: Add the predicate**

In `crates/foundry-verifier/src/transaction.rs`, immediately after the closing brace of `pub struct VerificationTransaction` (line 110):

```rust
impl VerificationTransaction {
    /// Whether this transaction was invoked over the W3C Digital Credentials
    /// API, in either its unsigned (`dc_api`) or signed (`dc_api_signed`) form.
    ///
    /// The distinction matters for how the *response* is bound: OpenID4VP 1.0
    /// L2543 makes the audience the Origin prefixed with `origin:` and L2963
    /// makes the mdoc binding `OpenID4VPDCAPIHandover` — for **both** forms,
    /// "even for signed requests". Every site that decides binding rules must
    /// ask this question rather than compare `transport` to a single literal,
    /// because a missed form silently applies the redirect binding and turns a
    /// conformant presentation into a policy failure.
    pub fn is_dc_api(&self) -> bool {
        self.transport == "dc_api" || self.transport == "dc_api_signed"
    }
}
```

- [ ] **Step 4: Use it at both verify.rs call sites**

In `crates/foundry-verifier/src/verify.rs` line 836, change:

```rust
            let candidates: Vec<SessionTranscriptParams> = if ctx.tx.transport == "dc_api" {
```

to:

```rust
            let candidates: Vec<SessionTranscriptParams> = if ctx.tx.is_dc_api() {
```

In `crates/foundry-verifier/src/verify.rs` line 1348, change:

```rust
    let expected_audiences: Vec<String> = if tx.transport == "dc_api" {
```

to:

```rust
    let expected_audiences: Vec<String> = if tx.is_dc_api() {
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier dc_api_signed_transport
```

Expected: both PASS.

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Quote the `Summary` line when reporting.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-verifier/src/transaction.rs crates/foundry-verifier/src/verify.rs
git commit -m "fix: bind both DC API transports to the Origin-based response rules

Adds VerificationTransaction::is_dc_api() and uses it in place of two
transport == \"dc_api\" equality tests, so a signed DC API presentation
keeps the origin: audience (OpenID4VP L2543) and the
OpenID4VPDCAPIHandover binding (L2963) rather than silently falling
through to the redirect binding."
```

---

### Task 2: Extract the shared `sign_request_object`

A pure refactor with **no behaviour change other than one documented byte-order shift**. It exists so that Task 3's second builder cannot fork the security-relevant logic — the `x509_hash` Client Identifier derivation (HAIP-0043) and the trust-anchor exclusion from `x5c` (HAIP-0045) are recorded `conforming` on the strength of there being exactly one code path that emits a signed Request Object.

**Byte-order note, read before implementing:** `serde_json`'s `preserve_order` feature is enabled transitively (via `indexmap`), so `serde_json::Map` preserves insertion order and JSON member order is real in the signed bytes. Moving the `client_id` insertion into `sign_request_object` therefore shifts it from second position to **last** in the redirect Request Object payload. This is intentional and harmless: JWT payload member order carries no protocol meaning, the signature covers whatever bytes are produced, and no test pins payload member order. Do not try to preserve the old position — doing so would require the payload builders to derive `client_id` themselves, which is exactly the duplication this task removes. The **header** order (`typ, alg, x5c`) is unchanged and must stay unchanged.

**Files:**

- Modify: `crates/foundry-verifier/src/request.rs` (the `build_signed_request_object` function, which starts at line 511)

**Interfaces:**

- Consumes: `verifier_x5c_leaf_pem(config) -> Result<Vec<u8>, VerificationError>` and `x509_hash_client_id(&[u8]) -> Result<String, VerificationError>`, both already `pub(crate)` in `request.rs`.
- Produces: `fn sign_request_object(config: &Config, payload_map: serde_json::Map<String, serde_json::Value>) -> Result<String, VerificationError>` — crate-private. Inserts `client_id` into the payload itself; callers MUST NOT insert it. Task 3 calls this.

- [ ] **Step 1: Confirm the existing tests pass before touching anything**

```bash
cargo nextest run -p foundry-verifier request::tests
```

Expected: PASS. These are the tests that pin this refactor — in particular `haip_0045_signed_request_x5c_excludes_the_trust_anchor`, `client_id_is_the_x509_hash_of_the_configured_leaf_certificate`, and `test_build_signed_request_object_and_verify_jws`.

- [ ] **Step 2: Add `sign_request_object`**

Insert into `crates/foundry-verifier/src/request.rs` immediately **before** `pub fn build_signed_request_object`. This is the existing function's signing half, moved verbatim except that `response_uri`/`host` derivation stays behind in the caller and `client_id` is inserted into the passed-in map.

```rust
/// Sign a Request Object payload as a JWS Compact Serialization.
///
/// Shared by every signed Request Object this verifier emits, whichever
/// transport carries it. Owning the certificate handling in one place is the
/// point: HAIP OpenID4VP L256 makes the Client Identifier the hash of the leaf
/// certificate, and HAIP L190/L256 forbid the trust anchor in `x5c`. A second
/// copy of this logic could drift from the audience the verify side expects,
/// which would surface as every presentation failing as a policy verdict rather
/// than as a visible error.
///
/// `client_id` is inserted **here**, not by the caller, so no payload builder
/// can omit it or derive it differently. Callers must not insert it themselves.
fn sign_request_object(
    config: &Config,
    mut payload_map: serde_json::Map<String, serde_json::Value>,
) -> Result<String, VerificationError> {
    let key_entry = config
        .keys
        .get(&config.verifier.signing_key)
        .ok_or_else(|| {
            VerificationError::Crypto(format!(
                "verifier signing key '{}' not found in config.keys",
                config.verifier.signing_key
            ))
        })?;

    let alg: SignatureAlgorithm = key_entry.alg.parse()?;
    let signer = FileSigner::from_pem_file(&key_entry.private_key, alg)?;

    let base_url = config
        .server
        .wallet_facing
        .public_base_url
        .trim_end_matches('/');
    let host = dns_host_only(base_url);

    // HAIP OpenID4VP L256: for signed requests the Verifier MUST use the Client
    // Identifier Prefix `x509_hash`, narrowing OpenID4VP Section 5.9.3. The value
    // is base64url(SHA-256(DER of the leaf)) per OpenID4VP L616. Because the
    // identifier *is* the certificate hash, `x5c` is required -- with no
    // certificate there is no Client Identifier to emit.
    let pem_bytes = verifier_x5c_leaf_pem(config)?;

    // OpenID4VP 1.0 Defined Client Identifier Prefixes / x509_san_dns (L614) via
    // GAP-VP-02: the leaf's dNSName SAN is still cross-checked, but against
    // public_base_url's host directly now -- the host is no longer carried in
    // client_id under x509_hash, and public_base_url was always the real source of
    // truth. Keeps a misconfigured public_base_url/certificate pairing failing
    // loudly instead of signing a Request Object the wallet will reject.
    if !foundry_core::trust::match_san_dns(&pem_bytes, &host)? {
        return Err(VerificationError::Crypto(format!(
            "host '{host}' (derived from server.wallet_facing.public_base_url) does not \
             match any dNSName SAN entry in the configured x5c leaf certificate"
        )));
    }

    let client_id = x509_hash_client_id(&pem_bytes)?;
    payload_map.insert("client_id".to_string(), serde_json::json!(client_id));
    let x5c = Some(foundry_core::trust::build_x5c(&[pem_bytes])?);

    let payload_val = serde_json::Value::Object(payload_map);

    let mut header_map = serde_json::Map::new();
    header_map.insert("typ".to_string(), serde_json::json!("oauth-authz-req+jwt"));
    header_map.insert("alg".to_string(), serde_json::json!(alg.as_str()));
    if let Some(chain) = x5c {
        header_map.insert("x5c".to_string(), serde_json::json!(chain));
    }
    // Header order is `typ, alg, x5c` -- deliberately NOT the `alg, typ, x5c`
    // of the SD-JWT VC and status-list builders. `serde_json` preserves
    // insertion order, so the difference is real in the signed bytes; keep it.
    let jws = foundry_core::crypto::jws::sign_compact(&header_map, &payload_val, &signer)?;

    // Always-on and payload-free: records that a Request Object really was
    // served, and under which algorithm. `tx_id` is already on the caller's
    // span, so this threads into the rest of the flow.
    tracing::debug!(
        alg = %alg.as_str(),
        jws_len = jws.len(),
        "signed request object built"
    );

    // The Request Object the wallet actually receives, verbatim. Doubly gated
    // per root AGENTS.md sect-4.5: it commits to the transaction nonce and
    // carries the ephemeral PUBLIC JWK in `client_metadata`, so a
    // `debug`/`trace` level alone is not authorisation -- RUST_LOG=trace is not
    // consent. A wallet-side rejection cannot be reproduced offline without the
    // exact bytes that were sent.
    if foundry_core::obs::sensitive_enabled() {
        // Built here rather than before signing: `sign_compact` borrows the
        // header map, and this diagnostic is the map's only other reader.
        let header_val = serde_json::Value::Object(header_map);
        tracing::trace!(
            request_object_jws = %jws,
            request_object_header = %header_val,
            request_object_payload = %payload_val,
            "SENSITIVE: signed request object served to wallet"
        );
    }

    Ok(jws)
}
```

- [ ] **Step 3: Reduce `build_signed_request_object` to payload assembly**

Replace the entire body of `pub fn build_signed_request_object` (keeping its `#[tracing::instrument(skip_all, fields(tx_id = %tx.id))]` attribute and signature) with:

```rust
pub fn build_signed_request_object(
    config: &Config,
    tx: &VerificationTransaction,
) -> Result<String, VerificationError> {
    let base_url = config
        .server
        .wallet_facing
        .public_base_url
        .trim_end_matches('/');
    let response_uri = format!("{base_url}/vp/response/{}", tx.id);

    let mut payload_map = serde_json::Map::new();
    payload_map.insert(
        "response_type".to_string(),
        serde_json::json!(RESPONSE_TYPE_VP_TOKEN),
    );
    payload_map.insert("response_uri".to_string(), serde_json::json!(response_uri));
    payload_map.insert(
        "response_mode".to_string(),
        serde_json::json!("direct_post.jwt"),
    );
    // OpenID4VP 1.0 `aud` of a Request Object (L536): MUST be
    // "https://self-issued.me/v2" under Static Discovery -- the only branch this
    // verifier ever takes, since it performs no Dynamic Discovery (no
    // openid_federation Client Identifier Prefix; see VP-0041/VP-0048).
    payload_map.insert(
        "aud".to_string(),
        serde_json::json!("https://self-issued.me/v2"),
    );
    payload_map.insert("nonce".to_string(), serde_json::json!(tx.nonce));
    payload_map.insert("state".to_string(), serde_json::json!(tx.id));
    payload_map.insert("dcql_query".to_string(), tx.dcql_query.clone());
    let (_, response_enc_method) = response_encryption_params(config);
    payload_map.insert(
        "client_metadata".to_string(),
        serde_json::json!({
            "jwks": { "keys": [tx.ephem_public_jwk.clone()] },
            "encrypted_response_enc_values_supported": [response_enc_method],
            "vp_formats_supported": vp_formats_supported()
        }),
    );
    if let Some(ref td) = tx.transaction_data {
        payload_map.insert("transaction_data".to_string(), serde_json::json!(td));
    }

    // `client_id` is inserted by `sign_request_object`, which derives it from
    // the same leaf certificate it puts in `x5c`.
    sign_request_object(config, payload_map)
}
```

- [ ] **Step 4: Run the pinning tests**

```bash
cargo nextest run -p foundry-verifier request::tests
```

Expected: PASS, unchanged. If `haip_0045_signed_request_x5c_excludes_the_trust_anchor` or `client_id_is_the_x509_hash_of_the_configured_leaf_certificate` fails, the extraction dropped or reordered something — do not "fix" the test, fix the extraction.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-verifier/src/request.rs
git commit -m "refactor: extract sign_request_object from build_signed_request_object

Splits Request Object signing from payload assembly so a second
transport cannot fork the certificate handling. client_id derivation,
the dNSName SAN cross-check, x5c construction (leaf only, HAIP L190/L256)
and both diagnostics now live in one place. Payload member order shifts
client_id to last; JWT member order carries no protocol meaning and no
test pins it."
```

---

### Task 3: The `dc_api_signed` transport

**Files:**

- Modify: `crates/foundry-verifier/src/request.rs` — `CreateVerificationResponse` (line 103), `create_verification_request`'s transport/response-mode handling (lines 354-357) and its return arms (lines 425-443), plus a new builder
- Test: `crates/foundry-verifier/src/request.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: `sign_request_object(config, payload_map) -> Result<String, VerificationError>` from Task 2; `VerificationTransaction::is_dc_api()` from Task 1.
- Produces:
  - `CreateVerificationResponse.protocol: Option<String>` — `Some("openid4vp-v1-signed")`, `Some("openid4vp-v1-unsigned")`, or `None`. Tasks 4 and 5 read this.
  - `fn build_signed_dc_api_request_object(config: &Config, tx: &VerificationTransaction, expected_origins: &[String]) -> Result<String, VerificationError>` — crate-private.
  - The `transport` string `"dc_api_signed"`.

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `crates/foundry-verifier/src/request.rs`. Note that `sample_config` sets `dc_api_expected_origins: Vec::new()` and the DC API tests pass `"/tmp/fake_key.pem"` — that works for the *unsigned* form because it never signs. Signed tests need a **real** key file, as `test_build_signed_request_object_and_verify_jws` does.

```rust
    /// A real signing key plus a configured Origin: the minimum a signed DC API
    /// request needs. Returns the config and the tempdir guard, which must stay
    /// alive for the key file to exist.
    fn signed_dc_api_config() -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let mut config = sample_config(key_file.to_str().unwrap());
        config.verifier.dc_api_expected_origins =
            vec!["https://verifier-website.example".to_string()];
        (config, dir)
    }

    fn signed_dc_api_request() -> CreateVerificationRequest {
        CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "dc_api_signed".to_string(),
            transaction_data: None,
        }
    }

    /// Decode a compact JWS payload without verifying it -- the tests below
    /// assert on payload members, and the signature is covered separately by
    /// `test_build_signed_request_object_and_verify_jws`.
    fn decode_jws_payload(jws: &str) -> serde_json::Value {
        let payload_b64 = jws.split('.').nth(1).expect("compact JWS has three parts");
        let bytes = B64URL.decode(payload_b64).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// OpenID4VP L2476: the signed request travels as the `request` member of
    /// the DC API `data` element, and nothing else.
    #[tokio::test]
    async fn dc_api_signed_returns_a_compact_jws_under_the_request_key() {
        let storage = test_storage().await;
        let (config, _dir) = signed_dc_api_config();

        let res = create_verification_request(&config, &storage, signed_dc_api_request(), 1_700_000_000)
            .await
            .unwrap();

        assert!(res.request_uri.is_none(), "DC API has no request_uri");
        assert!(res.openid4vp_uri.is_none(), "DC API has no deep link");

        let dc_req = res.dc_api_request.expect("dc_api_request must be present");
        let obj = dc_req.as_object().unwrap();
        assert_eq!(
            obj.len(),
            1,
            "the signed DC API data element carries only `request`: {dc_req}"
        );
        let jws = obj["request"].as_str().expect("`request` must be a string");
        assert_eq!(
            jws.split('.').count(),
            3,
            "`request` must be a JWS Compact Serialization: {jws}"
        );
    }

    /// OpenID4VP L2437: `client_id` MUST be present in signed DC API requests.
    /// L2442: `expected_origins` is REQUIRED and non-empty.
    #[tokio::test]
    async fn dc_api_signed_request_object_carries_client_id_and_expected_origins() {
        let storage = test_storage().await;
        let (config, _dir) = signed_dc_api_config();

        let res = create_verification_request(&config, &storage, signed_dc_api_request(), 1_700_000_000)
            .await
            .unwrap();
        let jws = res.dc_api_request.unwrap()["request"]
            .as_str()
            .unwrap()
            .to_string();
        let payload = decode_jws_payload(&jws);

        let leaf_pem = verifier_x5c_leaf_pem(&config).unwrap();
        let expected_client_id = x509_hash_client_id(&leaf_pem).unwrap();
        assert_eq!(
            payload["client_id"], serde_json::json!(expected_client_id),
            "L2437 / HAIP L256: client_id must be the x509_hash of the leaf: {payload}"
        );
        assert_eq!(
            payload["expected_origins"],
            serde_json::json!(["https://verifier-website.example"]),
            "L2442: expected_origins must carry the configured Origins: {payload}"
        );
    }

    /// L2421 lists the DC API request parameters; `response_uri` is not among
    /// them, and L2448 notes `state` is not defined for the DC API. Both are
    /// present in the redirect payload, so both are easy to copy in by mistake.
    #[tokio::test]
    async fn dc_api_signed_request_object_omits_response_uri_and_state() {
        let storage = test_storage().await;
        let (config, _dir) = signed_dc_api_config();

        let res = create_verification_request(&config, &storage, signed_dc_api_request(), 1_700_000_000)
            .await
            .unwrap();
        let jws = res.dc_api_request.unwrap()["request"]
            .as_str()
            .unwrap()
            .to_string();
        let payload = decode_jws_payload(&jws);
        let obj = payload.as_object().unwrap();

        assert!(
            obj.get("response_uri").is_none(),
            "L2421: response_uri is not a DC API parameter: {payload}"
        );
        assert!(
            obj.get("state").is_none(),
            "L2448: state is not defined for the DC API: {payload}"
        );
    }

    /// L2438 + HAIP L286 (`dc_api.jwt`), and L536 (`aud` under Static Discovery).
    #[tokio::test]
    async fn dc_api_signed_request_object_uses_dc_api_jwt_response_mode_and_static_discovery_aud() {
        let storage = test_storage().await;
        let (config, _dir) = signed_dc_api_config();

        let res = create_verification_request(&config, &storage, signed_dc_api_request(), 1_700_000_000)
            .await
            .unwrap();
        let jws = res.dc_api_request.unwrap()["request"]
            .as_str()
            .unwrap()
            .to_string();
        let payload = decode_jws_payload(&jws);

        assert_eq!(payload["response_mode"], "dc_api.jwt");
        assert_eq!(payload["response_type"], "vp_token");
        assert_eq!(payload["aud"], "https://self-issued.me/v2");
        assert!(payload["nonce"].is_string());
        assert!(payload["client_metadata"]["jwks"]["keys"].is_array());
    }

    /// L2442 makes `expected_origins` REQUIRED for this transport, and there is
    /// no safe default -- guessing which Origins are legitimate is worse than
    /// refusing. The failure must also precede the write, so a rejected request
    /// leaves no transaction behind.
    #[tokio::test]
    async fn dc_api_signed_without_expected_origins_is_rejected_before_persisting() {
        let storage = test_storage().await;
        let (mut config, _dir) = signed_dc_api_config();
        config.verifier.dc_api_expected_origins = Vec::new();

        let err = create_verification_request(&config, &storage, signed_dc_api_request(), 1_700_000_000)
            .await
            .expect_err("an unconfigured dc_api_expected_origins must be rejected");

        match err {
            VerificationError::InvalidRequest(msg) => {
                assert!(
                    msg.contains("dc_api_expected_origins"),
                    "the error must name the config key an operator has to set: {msg}"
                );
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    /// VP-0196 / VP-0197: foundry emits the DC API exchange protocol identifier
    /// so the calling page cannot pair the wrong one with the payload shape.
    #[tokio::test]
    async fn protocol_identifier_matches_the_transport() {
        let cases = [
            ("request_uri", None),
            ("dc_api", Some("openid4vp-v1-unsigned")),
            ("dc_api_signed", Some("openid4vp-v1-signed")),
        ];

        for (transport, expected) in cases {
            let storage = test_storage().await;
            let (config, _dir) = signed_dc_api_config();
            let req = CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: transport.to_string(),
                transaction_data: None,
            };

            let res = create_verification_request(&config, &storage, req, 1_700_000_000)
                .await
                .unwrap();

            assert_eq!(
                res.protocol.as_deref(),
                expected,
                "transport {transport} must report protocol {expected:?}"
            );
        }
    }

    /// HAIP L190/L256 for the second builder. The existing
    /// `haip_0045_...` test reaches only the redirect transport.
    #[tokio::test]
    async fn dc_api_signed_x5c_excludes_the_trust_anchor() {
        let storage = test_storage().await;
        let (config, _dir) = signed_dc_api_config();

        let res = create_verification_request(&config, &storage, signed_dc_api_request(), 1_700_000_000)
            .await
            .unwrap();
        let jws = res.dc_api_request.unwrap()["request"]
            .as_str()
            .unwrap()
            .to_string();

        let header_b64 = jws.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(header_b64).unwrap()).unwrap();
        let chain = header["x5c"].as_array().expect("x5c must be present");
        assert_eq!(
            chain.len(),
            1,
            "x5c must carry the leaf only, never the trust anchor: {header}"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier request::tests
```

Expected: the seven new tests FAIL to compile (`res.protocol` does not exist) or fail at runtime (`dc_api_signed` currently falls into the `_` arm and is treated as `request_uri`, so `dc_api_request` is `None`). A compile failure here is a legitimate red — fix it by implementing, not by weakening the test.

- [ ] **Step 3: Add `protocol` to the response struct**

In `crates/foundry-verifier/src/request.rs`, replace the `CreateVerificationResponse` definition (line 103):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateVerificationResponse {
    pub verification_id: String,
    pub request_uri: Option<String>,
    pub openid4vp_uri: Option<String>,
    pub dc_api_request: Option<serde_json::Value>,
    /// The W3C Digital Credentials API exchange protocol identifier the calling
    /// page must pair with `dc_api_request` (OpenID4VP 1.0 L2395-L2402):
    /// `openid4vp-v1-unsigned` or `openid4vp-v1-signed`.
    ///
    /// `None` for the `request_uri` transport, which performs no DC API
    /// invocation and therefore has no protocol identifier to report. foundry
    /// emits this rather than leaving the page to derive it because the
    /// identifier and the `data` shape are two halves of one wire contract and
    /// foundry decides the shape -- pairing a signed payload with the unsigned
    /// identifier is a wallet-side failure with no server-side trace.
    pub protocol: Option<String>,
}
```

- [ ] **Step 4: Add the DC API protocol identifier constants**

In `crates/foundry-verifier/src/request.rs`, immediately after the `RESPONSE_TYPE_VP_TOKEN` constant (line 39):

```rust
/// W3C Digital Credentials API exchange protocol identifiers (OpenID4VP 1.0
/// L2395-L2402). The grammar is `openid4vp-v<version>-<request-type>`, where
/// `<version>` MUST be `1` for this version of the specification and
/// `<request-type>` is `unsigned`, `signed` or `multisigned`.
///
/// `multisigned` (JWS JSON Serialization) is deliberately not implemented; HAIP
/// L288 requires a Verifier to support at least one of the three.
const DC_API_PROTOCOL_UNSIGNED: &str = "openid4vp-v1-unsigned";
const DC_API_PROTOCOL_SIGNED: &str = "openid4vp-v1-signed";

/// The `transport` value selecting a signed DC API request.
const TRANSPORT_DC_API_SIGNED: &str = "dc_api_signed";
/// The `transport` value selecting an unsigned DC API request.
const TRANSPORT_DC_API: &str = "dc_api";
```

- [ ] **Step 5: Add the signed DC API payload builder**

Insert into `crates/foundry-verifier/src/request.rs` immediately after `build_signed_request_object`:

```rust
/// Build the signed Request Object for the `dc_api_signed` transport
/// (OpenID4VP 1.0 §A.2.1, L2464-L2476).
///
/// The payload is the redirect form's minus the two parameters the DC API does
/// not define — `response_uri` (not listed among the DC API request parameters
/// at L2421; the response returns through the API, not to a URI) and `state`
/// (L2448) — plus `expected_origins` (L2442). `client_id` is inserted by
/// `sign_request_object`, which HAIP L256 requires here just as for the
/// redirect transport.
///
/// `expected_origins` is taken as an argument rather than read from `config` so
/// that the non-empty check (L2442) happens once, at the caller, before the
/// transaction is persisted.
///
/// `skip_all` is mandatory: `tx` holds `ephem_private_jwk`.
#[tracing::instrument(skip_all, fields(tx_id = %tx.id))]
fn build_signed_dc_api_request_object(
    config: &Config,
    tx: &VerificationTransaction,
    expected_origins: &[String],
) -> Result<String, VerificationError> {
    let mut payload_map = serde_json::Map::new();
    payload_map.insert(
        "response_type".to_string(),
        serde_json::json!(RESPONSE_TYPE_VP_TOKEN),
    );
    // L2438: `dc_api.jwt` when the response is encrypted, which HAIP L286
    // makes mandatory for this profile.
    payload_map.insert("response_mode".to_string(), serde_json::json!("dc_api.jwt"));
    // L536: Static Discovery -- the only branch this verifier takes.
    payload_map.insert(
        "aud".to_string(),
        serde_json::json!("https://self-issued.me/v2"),
    );
    payload_map.insert("nonce".to_string(), serde_json::json!(tx.nonce));
    payload_map.insert("dcql_query".to_string(), tx.dcql_query.clone());
    // L2442: REQUIRED for signed DC API requests, non-empty. The Wallet
    // compares these against the Origin to detect request replay.
    payload_map.insert(
        "expected_origins".to_string(),
        serde_json::json!(expected_origins),
    );
    let (_, response_enc_method) = response_encryption_params(config);
    payload_map.insert(
        "client_metadata".to_string(),
        serde_json::json!({
            "jwks": { "keys": [tx.ephem_public_jwk.clone()] },
            "encrypted_response_enc_values_supported": [response_enc_method],
            "vp_formats_supported": vp_formats_supported()
        }),
    );
    // L2421 lists `transaction_data` among the supported DC API parameters.
    // The already-encoded entries are emitted so a wallet hashes the same
    // bytes into `transaction_data_hashes` on every transport.
    if let Some(ref td) = tx.transaction_data {
        payload_map.insert("transaction_data".to_string(), serde_json::json!(td));
    }

    sign_request_object(config, payload_map)
}
```

- [ ] **Step 6: Wire the transport into `create_verification_request`**

In `crates/foundry-verifier/src/request.rs`, replace the `response_mode` match (lines 354-357):

```rust
    let response_mode = match transport_str.as_str() {
        TRANSPORT_DC_API | TRANSPORT_DC_API_SIGNED => "dc_api.jwt".to_string(),
        _ => "direct_post.jwt".to_string(),
    };
```

Immediately **after** that match and **before** `let encoded_transaction_data = ...`, add the validation — it must precede the write so a rejected request leaves no transaction behind:

```rust
    // OpenID4VP 1.0 L2442: `expected_origins` is REQUIRED and non-empty when
    // signed requests are used with the DC API. There is no safe default --
    // the verifier would be signing an assertion about which Origins are
    // legitimate, and guessing that is worse than refusing. Checked before
    // anything is persisted so a rejected request leaves no transaction behind.
    // Note the verify side deliberately keeps its `public_base_url` fallback:
    // that one keeps *inbound* verification working against pre-existing
    // config, which is a different question from what to sign.
    if transport_str == TRANSPORT_DC_API_SIGNED
        && config.verifier.dc_api_expected_origins.is_empty()
    {
        return Err(VerificationError::InvalidRequest(
            "transport 'dc_api_signed' requires verifier.dc_api_expected_origins to be a \
             non-empty list of Origins (OpenID4VP 1.0 L2442); configure it or use \
             transport 'dc_api' for an unsigned request"
                .to_string(),
        ));
    }
```

- [ ] **Step 7: Add the return arm and set `protocol` on the existing arms**

In `crates/foundry-verifier/src/request.rs`, change the transport dispatch that currently reads `if transport_str == "dc_api" { ... } else { ... }` into a three-way dispatch. Insert this arm **before** the existing `if transport_str == "dc_api"`:

```rust
    if transport_str == TRANSPORT_DC_API_SIGNED {
        let jws = build_signed_dc_api_request_object(
            config,
            &tx,
            &config.verifier.dc_api_expected_origins,
        )?;

        // L2476: the JWS is the value of the `request` claim in the `data`
        // element of the API call, and nothing else travels alongside it --
        // every parameter is inside the signed object.
        return Ok(CreateVerificationResponse {
            verification_id: id,
            request_uri: None,
            openid4vp_uri: None,
            dc_api_request: Some(serde_json::json!({ "request": jws })),
            protocol: Some(DC_API_PROTOCOL_SIGNED.to_string()),
        });
    }
```

Then change the literal `"dc_api"` in the existing condition to `TRANSPORT_DC_API`, and add `protocol` to both remaining returns — `protocol: Some(DC_API_PROTOCOL_UNSIGNED.to_string())` in the `dc_api` arm, and `protocol: None` in the final `request_uri` arm.

- [ ] **Step 8: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier
```

Expected: PASS, including the seven new tests and every pre-existing one.

- [ ] **Step 9: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. `crates/foundry/src/server.rs` never constructs a `CreateVerificationResponse` literal — it names the type only in the `utoipa` annotation (line 1328) and the handler return type (line 1333), both of which are agnostic to the new field — so adding it cannot break the binary.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry-verifier/src/request.rs
git commit -m "feat: signed OpenID4VP requests over the DC API

Adds transport dc_api_signed, emitting the Request Object as a JWS
Compact Serialization under the DC API data element's \`request\` member
(OpenID4VP 1.0 L2476), carrying client_id (L2437) and expected_origins
(L2442) and omitting response_uri and state (L2421/L2448). An empty
verifier.dc_api_expected_origins is a 400 raised before the transaction
is persisted. CreateVerificationResponse now reports the DC API exchange
protocol identifier (L2395-L2402)."
```

---

### Task 4: OpenAPI regeneration and admin console

**Files:**

- Modify: `crates/foundry/src/server.rs:1367` (doc comment only)
- Modify: `crates/foundry/assets/console.html` — transport `<select>` (line 245), `supportsDcApi` guard (line 3062), `prepareDcApiRequest` call (line 3177)
- Modify: `openapi.json` (regenerated, not hand-edited)
- Test: `crates/foundry/tests/console.rs` (extend the existing test at line 221)

**Interfaces:**

- Consumes: `CreateVerificationResponse.protocol` from Task 3.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing console assertions**

In `crates/foundry/tests/console.rs`, add to `console_has_digital_credentials_api_trigger_for_dc_api_transport`, after the existing `dc_api` option assertion:

```rust
    assert!(
        html.contains(r#"<option value="dc_api_signed">"#),
        "console `transport` select should offer dc_api_signed"
    );
    assert!(
        !html.contains("'openid4vp-v1-unsigned'"),
        "the console must read the protocol identifier from the response \
         (body.protocol), not hardcode one -- a signed payload sent under the \
         unsigned identifier fails in the wallet with no server-side trace"
    );
    assert!(
        html.contains("body.protocol"),
        "console should pass the server-supplied protocol to the DC API call"
    );
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo nextest run -p foundry --test console console_has_digital_credentials_api_trigger_for_dc_api_transport
```

Expected: FAIL on the missing `dc_api_signed` option.

- [ ] **Step 3: Add the transport option**

In `crates/foundry/assets/console.html`, replace the transport select (line 245):

```html
      <select id="transport">
        <option value="request_uri" selected>request_uri (deep link / QR)</option>
        <option value="dc_api">dc_api (Digital Credentials API, unsigned)</option>
        <option value="dc_api_signed">dc_api_signed (Digital Credentials API, signed)</option>
      </select>
```

- [ ] **Step 4: Read the protocol from the response**

In `crates/foundry/assets/console.html`, the DC API request is prepared at line 3177. Replace:

```javascript
            lastDcApiRequest = prepareDcApiRequest(body.dc_api_request, 'openid4vp-v1-unsigned');
```

with:

```javascript
            // The server pairs the protocol identifier with the payload shape
            // it built (OpenID4VP 1.0 L2395-L2402); hardcoding one here would
            // let a signed request be announced as unsigned.
            lastDcApiProtocol = body.protocol || 'openid4vp-v1-unsigned';
            lastDcApiRequest = prepareDcApiRequest(body.dc_api_request, lastDcApiProtocol);
```

Declare `lastDcApiProtocol` immediately after the existing `let lastDcApiRequest = null;` at **line 2994**, initialised to `'openid4vp-v1-unsigned'`:

```javascript
  let lastDcApiProtocol = 'openid4vp-v1-unsigned';
```

Also reset it alongside the existing `lastDcApiRequest = null;` reset at line 3166, so a failed create does not leave a stale protocol behind:

```javascript
            lastDcApiProtocol = 'openid4vp-v1-unsigned';
```

- [ ] **Step 5: Use the same value in the support guard**

In `crates/foundry/assets/console.html` line 3062, replace:

```javascript
      if (!supportsDcApi('get', 'openid4vp-v1-unsigned')) {
```

with:

```javascript
      if (!supportsDcApi('get', lastDcApiProtocol)) {
```

- [ ] **Step 6: Update the stale server.rs doc comment**

In `crates/foundry/src/server.rs`, the comment near line 1367 reads that `create_verification_request` "always sets `response_mode: \"dc_api.jwt\"` for `transport: \"dc_api\"`". Change `for \`transport: "dc_api"\`` to `for both DC API transports (\`dc_api\` and \`dc_api_signed\`)`, leaving the rest of the sentence intact.

- [ ] **Step 7: Regenerate the OpenAPI spec**

```bash
cargo run -p foundry -- openapi --out openapi.json
```

Expected: `openapi.json` gains an optional nullable `protocol` string on `CreateVerificationResponse`. Do not hand-edit the file. `openapi-wallet.json` is not regenerated — this is an admin route.

- [ ] **Step 8: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry --test console --test openapi_endpoints --test cli_openapi
```

Expected: PASS. `openapi_endpoints.rs` compares the committed `openapi.json` against the generated one, so a stale file fails here.

- [ ] **Step 9: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry/assets/console.html crates/foundry/src/server.rs crates/foundry/tests/console.rs openapi.json
git commit -m "feat: offer the signed DC API transport in the admin console

Adds the dc_api_signed option and stops hardcoding the exchange protocol
identifier -- the console now sends the one the server paired with the
payload it built. Regenerates openapi.json for the new protocol field."
```

---

### Task 5: End-to-end integration test

The only test that proves the request side and the verify side agree: a Request Object signed by Task 3 and a presentation bound the way Task 1 expects.

**Files:**

- Test: `crates/foundry/tests/wallet_verification.rs`

**Interfaces:**

- Consumes: `transport: "dc_api_signed"` and `CreateVerificationResponse.protocol` from Task 3; the Origin-based binding from Task 1.
- Produces: nothing.

**Fixture facts already verified — do not re-derive:**

- `setup_test_app() -> (AppState, tempfile::TempDir, String, String)` where the two `String`s are the **issuer** leaf cert PEM and its key PEM (line 71).
- Its `verifier_key` already carries an `x5c` whose SAN is `localhost`, matching `public_base_url` (`https://localhost:8443`), so `sign_request_object`'s dNSName SAN cross-check passes unchanged.
- Its `verifier.dc_api_expected_origins` is `Vec::new()`, which Task 3 now rejects for this transport — the test must override it.
- `Config` is `Clone`; `AppState.storage` / `.config` are `pub` and `AppState::new` is `pub`, so a modified config can be rebuilt into a new state.
- `B64URL` (`base64::engine::general_purpose::URL_SAFE_NO_PAD`) and `base64::Engine` are already imported at the top of the file.

- [ ] **Step 1: Write the failing test**

Add to `crates/foundry/tests/wallet_verification.rs`. This is the complete test — it mirrors `dc_api_response_via_admin_endpoint_succeeds` (line 357), changing the transport, the config override, and the audience.

```rust
/// The signed DC API transport end to end: the Request Object foundry signs
/// and the presentation it accepts must agree. Request side per OpenID4VP 1.0
/// §A.2.1 (L2464-L2476); response side per L2543, where the audience is the
/// Origin prefixed with `origin:` **even for signed requests**.
#[tokio::test]
async fn signed_dc_api_presentation_verifies_end_to_end() {
    let (base_state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;

    // L2442: a signed DC API request asserts which Origins may invoke it, and
    // `create_verification_request` refuses the transport when the list is
    // empty. `setup_test_app` leaves it empty, so override it here.
    let origin = "https://verifier-website.example";
    let mut cfg = (*base_state.config).clone();
    cfg.verifier.dc_api_expected_origins = vec![origin.to_string()];
    let state = AppState::new(base_state.storage.clone(), Arc::new(cfg));

    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));

    // 1. Create the signed DC API request.
    let create_req_body = serde_json::json!({
        "dcql_query": {
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
            }]
        },
        "transport": "dc_api_signed"
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

    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id.clone();

    assert_eq!(
        create_resp.protocol.as_deref(),
        Some("openid4vp-v1-signed"),
        "VP-0196/VP-0197: the response must name the exchange protocol"
    );
    assert!(
        create_resp.request_uri.is_none() && create_resp.openid4vp_uri.is_none(),
        "the DC API transports carry no request_uri and no deep link"
    );

    let dc_api_request = create_resp
        .dc_api_request
        .expect("dc_api_signed must return dc_api_request");
    let jws = dc_api_request["request"]
        .as_str()
        .expect("L2476: the signed request travels under `request`")
        .to_string();

    // 2. Inspect the Request Object the way a wallet does before trusting any
    //    parameter inside it.
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "`request` must be a JWS Compact Serialization");

    let ro_header: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(ro_header["typ"], "oauth-authz-req+jwt");
    assert_eq!(
        ro_header["x5c"].as_array().map(|c| c.len()),
        Some(1),
        "HAIP L190/L256: x5c carries the leaf only, never the trust anchor"
    );

    let ro_payload: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(
        ro_payload["expected_origins"],
        serde_json::json!([origin]),
        "L2442: expected_origins must carry the configured Origins"
    );
    assert_eq!(ro_payload["response_mode"], "dc_api.jwt", "L2438");
    assert!(
        ro_payload["client_id"]
            .as_str()
            .is_some_and(|c| c.starts_with("x509_hash:")),
        "L2437 / HAIP L256: client_id must be present and x509_hash-prefixed"
    );
    assert!(
        ro_payload.get("response_uri").is_none() && ro_payload.get("state").is_none(),
        "L2421/L2448: neither response_uri nor state is a DC API parameter"
    );

    let nonce = ro_payload["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = ro_payload["client_metadata"]["jwks"]["keys"][0].clone();

    // 3. Issue an SD-JWT VC and bind it with a KB-JWT. L2543: over the DC API
    //    the audience is the Origin prefixed with `origin:` EVEN FOR SIGNED
    //    REQUESTS -- never the x509_hash Client Identifier in the object above.
    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer =
        FileSigner::from_pem(&holder_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut select = serde_json::Map::new();
    select.insert("given_name".to_string(), serde_json::json!("Alice"));

    let claims = IssuerClaims {
        iss: "localhost".to_string(),
        sub: None,
        iat: (now - 100) as i64,
        exp: (now + 3600) as i64,
        vct: "https://localhost:8443/vct/pid".to_string(),
        cnf_jwk: holder_pub_jwk,
        status_list_index: None,
        status_list_uri: None,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };

    let issuer_pres = build_sd_jwt_vc(
        claims,
        &issuer_signer,
        Some(vec![der_b64(issuer_cert_pem.as_bytes())]),
    )
    .unwrap();

    let sd_jwt_vc_presentation = attach_kb_jwt(
        issuer_pres,
        &holder_signer,
        &format!("origin:{origin}"),
        &nonce,
        None,
    )
    .unwrap();

    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [sd_jwt_vc_presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    // 4. Relay the response the way the console does after the DC API call.
    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/admin/verification/requests/{verification_id}/dc-api-response"
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(
            serde_json::json!({ "response": jwe_str }).to_string(),
        ))
        .unwrap();

    let post_resp_res = admin_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);

    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_result: VerificationResult = serde_json::from_slice(&verify_bytes).unwrap();

    assert!(
        verify_result.verified,
        "a conformant signed DC API presentation must verify; checks={:?}, credentials={:?}",
        verify_result.checks, verify_result.credentials
    );
    assert_eq!(verify_result.credentials[0].claims["given_name"], "Alice");

    // 5. The transaction reflects the verdict.
    let get_tx_req = Request::builder()
        .method("GET")
        .uri(format!("/admin/verification/requests/{verification_id}"))
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::empty())
        .unwrap();

    let get_tx_res = admin_app.clone().oneshot(get_tx_req).await.unwrap();
    assert_eq!(get_tx_res.status(), StatusCode::OK);

    let tx_bytes = axum::body::to_bytes(get_tx_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx: VerificationTransaction = serde_json::from_slice(&tx_bytes).unwrap();

    assert_eq!(tx.state, VerificationState::Verified);
    assert_eq!(tx.transport, "dc_api_signed");
}
```

- [ ] **Step 2: Run it**

```bash
cargo nextest run -p foundry --test wallet_verification signed_dc_api_presentation_verifies_end_to_end
```

This is the one test in the plan with no red phase of its own: it is an integration check over behaviour Tasks 1 and 3 already built and already red-greened, so writing it red would mean deliberately breaking a shipped task.

Expected: PASS once Tasks 1 and 3 are complete, since this test exercises only their behaviour. If it FAILS, that is a real defect in Task 1 or 3 — **investigate rather than adjusting the test.** The two likely causes, in order: a `verified: false` verdict with a failed `sd_jwt_vc_signature_and_kb_jwt` check means Task 1's `is_dc_api()` is not reaching the audience branch; a 400 naming `dc_api_expected_origins` means the config override above did not take effect.

- [ ] **Step 3: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crates/foundry/tests/wallet_verification.rs
git commit -m "test: end-to-end signed DC API presentation

Proves the signed Request Object foundry emits and the presentation it
accepts agree: the JWS verifies against the configured leaf, carries
expected_origins, and a KB-JWT bound to origin:<origin> (OpenID4VP
L2543) verifies."
```

---

### Task 6: Documentation and conformance report

Closing a conformance gap means updating the report, not only the code — root `AGENTS.md` §4.4 and §8.

**Files:**

- Modify: `docs/conformance/openid4vc-conformance.md` (rows VP-0196, VP-0197, VP-0198, VP-0200, VP-0201, VP-0202)
- Modify: `README.md` (transport table near line 1243; DC API Expected Origins section near line 409)
- Modify: `crates/foundry-verifier/AGENTS.md` (Module Map and Gotchas)

**Interfaces:**

- Consumes: the test names produced by Tasks 3 and 5.
- Produces: nothing.

- [ ] **Step 1: Update the four `not-implemented` conformance rows**

In `docs/conformance/openid4vc-conformance.md`, change the verdict of VP-0196, VP-0197, VP-0200 and VP-0202 from `not-implemented` to `conforming`, replace each Evidence cell, and fill the Tests column:

- **VP-0196** — Evidence: `create_verification_request` (request.rs) returns `protocol` on `CreateVerificationResponse`, built from the `DC_API_PROTOCOL_SIGNED`/`DC_API_PROTOCOL_UNSIGNED` constants, both of which carry `<version>` = `1`. Tests: `protocol_identifier_matches_the_transport`.
- **VP-0197** — Evidence: the same field selects `signed` for `transport: "dc_api_signed"` and `unsigned` for `transport: "dc_api"`; the admin console sends the server-supplied value rather than a hardcoded one. Tests: `protocol_identifier_matches_the_transport`, `console_has_digital_credentials_api_trigger_for_dc_api_transport`.
- **VP-0200** — Evidence: `sign_request_object` (request.rs) inserts `client_id` into every signed Request Object payload, including the DC API one built by `build_signed_dc_api_request_object`; the value is `x509_hash:<base64url(SHA-256(DER leaf))>` per HAIP L256. Tests: `dc_api_signed_request_object_carries_client_id_and_expected_origins`.
- **VP-0202** — Evidence: `build_signed_dc_api_request_object` emits `expected_origins` from `verifier.dc_api_expected_origins`, and `create_verification_request` rejects the transport with `VerificationError::InvalidRequest` when that list is empty, before the transaction is persisted. Tests: `dc_api_signed_request_object_carries_client_id_and_expected_origins`, `dc_api_signed_without_expected_origins_is_rejected_before_persisting`.

- [ ] **Step 2: Update the two `conforming` rows whose evidence is now ambiguous**

- **VP-0198** (`client_id` MUST be omitted in *unsigned* DC API requests) — append to the Evidence cell: "The signed DC API transport is a separate arm of `create_verification_request` producing a JWS under `request`, so the unsigned object literal asserted here remains the unsigned form's shape."
- **VP-0201** (`response_mode` MUST be `dc_api`/`dc_api.jwt`) — append: "Both DC API transports resolve to `dc_api.jwt` through the same match arm, and responses are never unencrypted in any deployment."

- [ ] **Step 3: Verify the report's mechanical guard still passes**

```bash
cargo nextest run -p foundry --test conformance_report
```

Expected: PASS. This test checks verdict legality, id ordering, gap cross-references and summary counts. If the summary counts fail, update the counts in the report's summary section to match.

- [ ] **Step 4: Update the README**

In `README.md`, add a row to the transport table near line 1243:

```markdown
| `dc_api_request.request` | `dc_api_signed` | The signed Request Object (JWS Compact) handed to the invoking page, paired with `protocol: "openid4vp-v1-signed"` |
```

In the "DC API Expected Origins" section near line 409, add after the existing description:

```markdown
> **`dc_api_expected_origins` is mandatory for `transport: "dc_api_signed"`.**
> A signed request carries `expected_origins` (OpenID4VP 1.0 L2442), which the
> wallet compares against the invoking Origin to detect replay. foundry rejects
> a signed DC API request with HTTP 400 when the list is empty rather than
> guessing an Origin from `public_base_url` — signing an assertion about which
> Origins are legitimate is not something a default can do safely. The unsigned
> `dc_api` transport is unaffected and still falls back.
```

- [ ] **Step 5: Update the verifier crate's AGENTS.md**

In `crates/foundry-verifier/AGENTS.md`, amend the `request.rs` Module Map row to mention that `sign_request_object` is shared by `build_signed_request_object` (redirect) and `build_signed_dc_api_request_object` (DC API), and add a Gotchas entry:

```markdown
- **Transport comparisons go through `tx.is_dc_api()`, never `== "dc_api"`.**
  There are two DC API transports — `dc_api` (unsigned) and `dc_api_signed`
  (signed) — and OpenID4VP L2543/L2963 give them the *same* response binding:
  an `origin:`-prefixed audience and the `OpenID4VPDCAPIHandover`, "even for
  signed requests". An equality test against a single literal silently applies
  the redirect binding to the other form, which surfaces as a failed
  `sd_jwt_vc_signature_and_kb_jwt` or `mdoc_issuer_auth_and_device_signature`
  check — a policy verdict, not an error, so nothing points at the real cause.
  Pinned by `dc_api_signed_transport_expects_the_origin_prefixed_audience` and
  `dc_api_signed_transport_selects_the_dc_api_handover`.
- **`verifier.dc_api_expected_origins` is required for `dc_api_signed` but
  optional everywhere else.** The verify side still falls back to a
  `public_base_url`-derived origin when it is unset; the request side refuses.
  The asymmetry is deliberate: the fallback keeps inbound verification working
  against pre-existing config, whereas signing `expected_origins` is an
  assertion foundry would be inventing.
```

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass.

- [ ] **Step 7: Run the E2E suite before the PR**

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

Expected: PASS. This is the pre-PR gate from root `AGENTS.md` §5.2, not a per-task one.

- [ ] **Step 8: Commit**

```bash
git add docs/conformance/openid4vc-conformance.md README.md crates/foundry-verifier/AGENTS.md
git commit -m "docs: record signed DC API support

Moves VP-0196, VP-0197, VP-0200 and VP-0202 from not-implemented to
conforming with test evidence, disambiguates VP-0198 and VP-0201 now
that two DC API transports exist, and documents the mandatory
dc_api_expected_origins requirement plus the is_dc_api() invariant."
```

---

## Self-Review

**Spec coverage.** Every section of the design maps to a task: §2.1 response shape → Task 3 Steps 3/7; §2.2 payload → Task 3 Step 5; §3 predicate → Task 1; §4 builder split → Task 2; §5 validation and error mapping → Task 3 Step 6; §6 HTTP/OpenAPI/console → Task 4; §7 testing → Tasks 1, 3, 5; §8 conformance rows → Task 6. The spec's §6 README and AGENTS.md items are Task 6 Steps 4-5. No spec section is unimplemented.

**Type consistency.** `sign_request_object(config, payload_map)` is defined in Task 2 and called in Task 3 with the same signature. `build_signed_dc_api_request_object(config, tx, expected_origins)` is defined and called in Task 3. `is_dc_api()` is defined in Task 1 and relied on (indirectly, through verification behaviour) in Tasks 3 and 5. `CreateVerificationResponse.protocol` is added in Task 3 and read in Tasks 4 and 5. The constants `DC_API_PROTOCOL_SIGNED`, `DC_API_PROTOCOL_UNSIGNED`, `TRANSPORT_DC_API` and `TRANSPORT_DC_API_SIGNED` are introduced in Task 3 Step 4 before their uses in Steps 6-7.

**Placeholder scan.** No `TBD`, no "similar to Task N", no "add error handling". Every code step carries the literal code. Task 5 was rewritten from an earlier draft that carried three `/* fill this in */` blocks: the fixtures were read (`setup_test_app` at line 71, `dc_api_response_via_admin_endpoint_succeeds` at line 357) and the test is now complete.

**Assumptions verified against the tree rather than assumed.**

- `setup_test_app` returns the **issuer** cert and key PEMs, not a CA PEM — the earlier draft had this wrong and would have produced a test that did not compile.
- Its `verifier_key` already carries an `x5c` with SAN `localhost` matching `public_base_url`, so `sign_request_object`'s SAN cross-check passes in Task 5 without new fixtures. Had it not, Task 5 would have needed to build a certificate.
- `serde_json`'s `preserve_order` is enabled transitively via `indexmap` (`cargo tree -e features -i serde_json`), which is why Task 2's byte-order note is a real caveat rather than a theoretical one.
- `crates/foundry/src/server.rs` names `CreateVerificationResponse` only in a `utoipa` annotation and a return type — no struct literal — so Task 3's new field cannot break the binary.
- `lastDcApiRequest` is declared at `console.html:2994` and reset at 3166; Task 4 now names both sites.
- `VerificationError::InvalidRequest` maps to HTTP 400 in `verifier_admin_error_response` (`server.rs:1284`), which is what makes Task 3's validation an operator-visible 400 rather than a 500.

**Ordering rationale.** Task 1 precedes everything because it fixes a latent hazard, and its tests pass before the new transport exists (they set `tx.transport` directly). Task 2 is a pure refactor pinned by existing tests, so any breakage is unambiguous. Task 3 depends on both. Tasks 4 and 5 depend on Task 3's `protocol` field. Task 6 depends on the test names from Tasks 3 and 5.
