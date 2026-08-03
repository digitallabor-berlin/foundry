# Conformance Tier 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three remaining `Important` conformance gaps — GAP-HAIP-05 (`x509_hash` Client Identifier Prefix), GAP-HAIP-01 (`scope` in issuer metadata and `/authorize`), GAP-VP-04 (`transaction_data_hashes` binding validation).

**Architecture:** Three independent fixes across four crates. Fix 1 is a two-sided wire change (request emission *and* response audience expectation) driven by one new `foundry-core` helper. Fix 2 threads a `scope` value from config through issuer metadata and `/authorize`. Fix 3 adds a sixth named verification check plus the builder support needed to construct a correctly-bound presentation.

**Tech Stack:** Rust (Cargo workspace), `x509-cert`, `sha2`, `base64`, `josekit`, `serde`/`serde_json`, `axum`, `tokio`, `utoipa`.

**Spec:** [`docs/superpowers/specs/2026-08-03-conformance-tier4-fixes-spec.md`](../specs/2026-08-03-conformance-tier4-fixes-spec.md)

## Global Constraints

- **Scoped gate only, per task.** Run exactly the `cargo test -p <crate>` set each task names, plus `cargo clippy -p <crate> --all-targets -- -D warnings` and `cargo fmt --check`. **Never run `cargo test --workspace` in Tasks 1–9** (AGENTS.md §5.1). The full gate runs once, in Task 10.
- **No `.unwrap()`, `.expect()`, `panic!()`, `unreachable!()` in production request paths** — `foundry-issuer`, `foundry-verifier`, `foundry::server`. Permitted only in `#[cfg(test)]` and `tests/` (§4.1).
- **`VerificationResult.verified` MUST equal `checks.iter().all(|c| c.passed)`.** Never hardcode `verified: true` (§4.2).
- **Policy failures → HTTP 200 + `verified: false`; structural/crypto → 400; network → 502** (§4.3).
- **Every `#[tracing::instrument]` carries `skip_all`.** Never log private/ephemeral JWKs, access tokens, `c_nonce`, pre-authorized or authorization codes, transaction codes, the admin API key (§4.5).
- **Cite the spec in code comments** for every protocol-facing change, naming file and line (§4.4).
- **Register bookkeeping is atomic with the code.** `crates/foundry/tests/conformance_report.rs` enforces that every gap-register entry names an existing `#[ignore]`d test citing that gap id, that every `#[ignore = "GAP-..."]` cites a registered gap, that no `gap` clause row references a missing register entry, and that Summary counts equal actual row counts. **Un-ignoring a test, removing its register row, flipping its clause rows, and recomputing the Summary must land in the SAME commit** — otherwise `cargo test -p foundry` fails. Only Tasks 2, 6, 9 touch the register.
- Exact spec lines: OpenID4VP `x509_hash` = **L616**; HAIP `x509_hash` = **L256**; HAIP metadata scope = **L186**; HAIP offer scope = **L199**; HAIP authorization-endpoint scope = **L209**; VP token validation = **L1523**; `transaction_data_hashes_alg` = **L3142**; `transaction_data_hashes` = **L3144**; response-side alg REQUIRED = **L3145**.

## File Structure

**Created:** none — every change lands in an existing file.

| File | Responsibility after this work |
|---|---|
| `crates/foundry-core/src/trust/mod.rs` | + `x509_hash_client_id_value` — the single source of the `x509_hash` value |
| `crates/foundry-core/src/config/model.rs` | − `VerifierConfig.client_id_scheme`; + `CredentialType.scope` + `resolved_scope()` |
| `crates/foundry-core/src/config/validate.rs` | + resolved-scope uniqueness and non-emptiness |
| `crates/foundry-verifier/Cargo.toml` | + `sha2` (workspace dep) |
| `crates/foundry-verifier/src/request.rs` | emits `x509_hash:` client_id; requires `x5c`; injects `transaction_data_hashes_alg` |
| `crates/foundry-verifier/src/verify.rs` | expects `x509_hash:` audience; + `transaction_data_binding` check |
| `crates/foundry-sd-jwt-vc/src/builder.rs` | `attach_kb_jwt` can emit `transaction_data_hashes` |
| `crates/foundry-issuer/src/metadata.rs` | + `CredentialConfigurationSupported.scope` |
| `crates/foundry-issuer/src/authorize.rs` | + `AuthorizeParams.scope` + scope↔`issuer_state` agreement |
| `crates/foundry/src/server.rs` | `/authorize` accepts and forwards `scope` |
| `crates/foundry/src/commands.rs`, `config.yaml` | − `client_id_scheme`, + documented `scope` |
| `AGENTS.md`, `crates/foundry-verifier/AGENTS.md` | §4.2 six check names; verifier module map |
| `docs/conformance/openid4vc-conformance.md` | register + clause rows + Summary |
| `openapi.json` | `/authorize` `scope`, `CredentialConfigurationSupported.scope` |

---

## Task 1: `x509_hash` value helper in `foundry-core`

**Files:**
- Modify: `crates/foundry-core/src/trust/mod.rs`

**Interfaces:**
- Consumes: existing `parse_cert_pem`, `build_x5c`, `TrustError`, and the test-module fixtures `LEAF_CERT_PEM` / `crate::pki::{issue_leaf, new_ca}`.
- Produces: `pub fn x509_hash_client_id_value(leaf_pem: &[u8]) -> Result<String, TrustError>` — base64url-unpadded SHA-256 of the DER-encoded certificate, **without** the `x509_hash:` prefix. Tasks 2 and 9 depend on this exact name and signature.

- [ ] **Step 1: Write the failing test**

Append inside the existing `#[cfg(test)] mod tests` block of `crates/foundry-core/src/trust/mod.rs`:

```rust
    #[test]
    fn x509_hash_client_id_value_is_base64url_sha256_of_the_der() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL_NOPAD;
        use sha2::{Digest, Sha256};

        let value = x509_hash_client_id_value(LEAF_CERT_PEM).unwrap();

        // build_x5c already yields base64-STANDARD DER for the same cert, so it is
        // an independent route to the bytes that must be hashed.
        let der = B64
            .decode(&build_x5c(&[LEAF_CERT_PEM.to_vec()]).unwrap()[0])
            .unwrap();
        assert_eq!(value, B64URL_NOPAD.encode(Sha256::digest(&der)));

        // OpenID4VP L616: base64url; SHA-256 is 32 bytes -> 43 unpadded chars.
        assert_eq!(value.len(), 43);
        assert!(!value.contains('='), "must be unpadded: {value}");
        assert!(
            !value.contains('+') && !value.contains('/'),
            "must be base64URL: {value}"
        );
    }

    #[test]
    fn x509_hash_client_id_value_differs_per_certificate() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let a = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "a.dev.local",
            &["a.dev.local".to_string()],
            365,
        )
        .unwrap();
        let b = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "b.dev.local",
            &["b.dev.local".to_string()],
            365,
        )
        .unwrap();
        assert_ne!(
            x509_hash_client_id_value(a.cert_pem.as_bytes()).unwrap(),
            x509_hash_client_id_value(b.cert_pem.as_bytes()).unwrap()
        );
    }

    #[test]
    fn x509_hash_client_id_value_rejects_garbage_pem() {
        assert!(x509_hash_client_id_value(b"not a certificate").is_err());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-core x509_hash_client_id_value
```

Expected: FAIL — `cannot find function 'x509_hash_client_id_value' in this scope`.

- [ ] **Step 3: Write the minimal implementation**

Add to the imports at the top of the file. The module aliases `B64` to base64 **STANDARD** for `x5c` per RFC 7515; this value is base64url **unpadded** per VP L616, so it needs its own alias:

```rust
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL_NOPAD;
use sha2::{Digest, Sha256};
```

Add the function next to `build_x5c`:

```rust
/// The `x509_hash` Client Identifier value for a leaf certificate.
///
/// OpenID4VP 1.0, Defined Client Identifier Prefixes / `x509_hash` (L616): "The
/// value of `x509_hash` is the base64url-encoded value of the SHA-256 hash of the
/// DER-encoded X.509 certificate."
///
/// Returns the value **without** the `x509_hash:` prefix, so callers compose the
/// Client Identifier themselves. This is the only place the value is computed:
/// the Request Object's `client_id` (request.rs) and the expected KB-JWT audience
/// (verify.rs) must both call it, or the two sides drift apart silently.
pub fn x509_hash_client_id_value(leaf_pem: &[u8]) -> Result<String, TrustError> {
    let cert = parse_cert_pem(leaf_pem)?;
    let der = cert
        .to_der()
        .map_err(|e| TrustError::Parse(e.to_string()))?;
    Ok(B64URL_NOPAD.encode(Sha256::digest(&der)))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-core x509_hash_client_id_value
```

Expected: PASS, 3 tests.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry-core
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

Expected: green. `B64` is still used by `build_x5c` and `x5c_entry_to_pem`, so no unused-import warning.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-core/src/trust/mod.rs
git commit -m "feat(core): x509_hash_client_id_value per OpenID4VP L616

The base64url-unpadded SHA-256 of the DER-encoded leaf certificate, computed in
one place so the Request Object's client_id and the expected KB-JWT audience
cannot drift apart."
```

---

## Task 2: Swap the Client Identifier Prefix to `x509_hash` (both sides)

**Highest-risk task in the plan.** The identifier is emitted in `request.rs` and *independently recomputed* in `verify.rs` as the expected KB-JWT audience. Changing one side only yields a build that issues requests no wallet can satisfy, and the failure surfaces as `verified: false` with HTTP 200 — not a compile error.

**Files:**
- Modify: `crates/foundry-verifier/src/request.rs` (both `client_id` sites, the `x5c` block, the inline test module)
- Modify: `crates/foundry-verifier/src/verify.rs` (the `client_id` recomputation in `do_verify_vp_response`; ~9 audience literals in the test module)
- Modify: `crates/foundry-verifier/tests/conformance_vp.rs`
- Modify: `docs/conformance/openid4vc-conformance.md`

**Interfaces:**
- Consumes: `foundry_core::trust::x509_hash_client_id_value` (Task 1).
- Produces: `client_id` of the form `x509_hash:<43-char base64url>` on every non-`dc_api` transport, plus a test-module helper `expected_client_id(&Config) -> String`. Task 9's tests use both.

- [ ] **Step 1: Un-ignore the gap test and add the two-sided assertions**

In `crates/foundry-verifier/src/request.rs`, delete the `#[ignore = "GAP-HAIP-05: ..."]` attribute from `gap_haip_05_signed_request_object_never_uses_x509_hash_prefix`, keeping the body. Then add to the same module:

```rust
    /// HAIP OpenID4VP L256 + OpenID4VP L616: the Client Identifier the Request
    /// Object advertises MUST be exactly the value a wallet will use as its KB-JWT
    /// audience, and `do_verify_vp_response` recomputes that expectation
    /// independently. This test fails if the two sides are ever derived
    /// differently -- the failure that would otherwise appear only as a
    /// `verified: false` policy verdict at runtime.
    #[tokio::test]
    async fn client_id_is_the_x509_hash_of_the_configured_leaf_certificate() {
        let (config, _dir, tx) = signed_request_fixture();
        let jws = build_signed_request_object(&config, &tx).unwrap();

        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(jws.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        let client_id = payload["client_id"].as_str().unwrap();

        let key_entry = config.keys.get(&config.verifier.signing_key).unwrap();
        let pem = std::fs::read(key_entry.x5c.as_ref().unwrap()).unwrap();
        let expected = format!(
            "x509_hash:{}",
            foundry_core::trust::x509_hash_client_id_value(&pem).unwrap()
        );

        assert_eq!(client_id, expected);
        assert!(client_id.starts_with("x509_hash:"));
    }

    /// Decision 3: under `x509_hash` the Client Identifier *is* the certificate
    /// hash, so a signed request with no configured `x5c` has no identifier to
    /// emit. A configuration fault, and it must be a typed error.
    #[tokio::test]
    async fn signed_request_without_x5c_is_a_typed_error() {
        let (mut config, _dir, tx) = signed_request_fixture();
        if let Some(entry) = config.keys.get_mut(&config.verifier.signing_key) {
            entry.x5c = None;
        }
        let err = build_signed_request_object(&config, &tx).unwrap_err();
        assert!(
            matches!(err, VerificationError::Crypto(ref m) if m.contains("x5c")),
            "expected a Crypto error naming x5c, got {err:?}"
        );
    }
```

`signed_request_fixture()` returns `(Config, TempDir, VerificationTransaction)` with `keys.<verifier.signing_key>` carrying **both** `private_key` and `x5c` as files in the `TempDir`. Build the CA and leaf with `foundry_core::pki::{new_ca, issue_leaf}`, issuing the leaf for the same DNS name as `dns_host_only(public_base_url)` so the SAN cross-check passes. **Reuse the equivalent fixture already in this file if one exists — do not duplicate it.**

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-verifier --lib request:: 2>&1 | tail -30
```

Expected: FAIL — `gap_haip_05_...` on `starts_with("x509_hash:")`; `client_id_is_the_x509_hash_...` on the `assert_eq!`; `signed_request_without_x5c_...` because absent `x5c` currently yields `Ok`.

- [ ] **Step 3: Implement the emission side**

In `build_signed_request_object`, replace the `let client_id = format!("x509_san_dns:{host}");` line **and** the `x5c` block that follows with:

```rust
    // HAIP OpenID4VP L256: for signed requests the Verifier MUST use the Client
    // Identifier Prefix `x509_hash`, narrowing OpenID4VP Section 5.9.3. The value
    // is base64url(SHA-256(DER of the leaf)) per OpenID4VP L616. Because the
    // identifier *is* the certificate hash, `x5c` is required -- with no
    // certificate there is no Client Identifier to emit.
    let x5c_path = key_entry.x5c.as_ref().ok_or_else(|| {
        VerificationError::Crypto(format!(
            "verifier signing key '{}' has no x5c certificate; the x509_hash Client \
             Identifier Prefix (HAIP OpenID4VP L256) requires one",
            config.verifier.signing_key
        ))
    })?;
    let pem_bytes = std::fs::read(x5c_path).map_err(|e| {
        VerificationError::Crypto(format!("failed to read x5c file '{x5c_path}': {e}"))
    })?;

    // GAP-VP-02, re-anchored: the leaf's dNSName SAN is still cross-checked, but
    // against `public_base_url`'s host directly -- the host is no longer carried in
    // `client_id`, and `public_base_url` was always the real source of truth. Keeps
    // a misconfigured public_base_url/certificate pairing failing loudly instead of
    // signing a Request Object the wallet will reject.
    if !foundry_core::trust::match_san_dns(&pem_bytes, &host)? {
        return Err(VerificationError::Crypto(format!(
            "host '{host}' (derived from server.wallet_facing.public_base_url) does not \
             match any dNSName SAN entry in the configured x5c leaf certificate"
        )));
    }

    let client_id = format!(
        "x509_hash:{}",
        foundry_core::trust::x509_hash_client_id_value(&pem_bytes)?
    );
    let x5c = Some(foundry_core::trust::build_x5c(&[pem_bytes])?);
```

If no `From<TrustError> for VerificationError` impl exists, map explicitly with `.map_err(|e| VerificationError::Crypto(e.to_string()))?` rather than adding a conversion.

Apply the same prefix change to the unsigned `openid4vp://` URI path earlier in the file. That path has no `key_entry` in scope — read the verifier signing key's `x5c` there the same way and return the same typed error when absent, so both transports agree.

- [ ] **Step 4: Implement the expectation side**

In `do_verify_vp_response`, replace `let client_id = format!("x509_san_dns:{host}");` with:

```rust
    // HAIP OpenID4VP L256 / OpenID4VP L616: the Client Identifier is
    // `x509_hash:<base64url(SHA-256(DER leaf))>`. A wallet binds its KB-JWT `aud`
    // to the Client Identifier it received, so this MUST be computed by the same
    // helper `build_signed_request_object` (request.rs) uses -- if the two ever
    // diverge, every redirect-transport presentation fails as a policy verdict
    // rather than a visible error.
    let key_entry = config
        .keys
        .get(&config.verifier.signing_key)
        .ok_or_else(|| {
            VerificationError::Crypto(format!(
                "verifier signing key '{}' not found in config.keys",
                config.verifier.signing_key
            ))
        })?;
    let x5c_path = key_entry.x5c.as_ref().ok_or_else(|| {
        VerificationError::Crypto(format!(
            "verifier signing key '{}' has no x5c certificate; the expected KB-JWT \
             audience is the x509_hash Client Identifier (HAIP OpenID4VP L256)",
            config.verifier.signing_key
        ))
    })?;
    let leaf_pem = std::fs::read(x5c_path).map_err(|e| {
        VerificationError::Crypto(format!("failed to read x5c file '{x5c_path}': {e}"))
    })?;
    let client_id = format!(
        "x509_hash:{}",
        foundry_core::trust::x509_hash_client_id_value(&leaf_pem)?
    );
```

Leave the `dc_api` branch untouched — it uses `origin:`-prefixed audiences and does not consult `client_id`. Keep `let host = dns_host_only(base_url);` only if something else still uses it; if it becomes unused, remove it rather than silencing the warning.

Then find any other inline reconstruction and route it through the helper:

```bash
grep -rn 'x509_san_dns' crates/foundry-verifier/src/
```

Check the mdoc `SessionTranscript` path specifically — if it consumes the Client Identifier it must use the same value.

- [ ] **Step 5: Replace the hardcoded audiences in the test fixtures**

Add one helper to `verify.rs`'s test module and use it at every site that currently passes `"x509_san_dns:localhost"`:

```rust
    /// The Client Identifier a wallet would have received for this fixture.
    /// Computed, never hardcoded: a literal would silently diverge if the fixture
    /// certificate is regenerated.
    fn expected_client_id(config: &Config) -> String {
        let key_entry = config.keys.get(&config.verifier.signing_key).unwrap();
        let pem = std::fs::read(key_entry.x5c.as_ref().unwrap()).unwrap();
        format!(
            "x509_hash:{}",
            foundry_core::trust::x509_hash_client_id_value(&pem).unwrap()
        )
    }
```

**`test_config` must now configure `x5c`.** `do_verify_vp_response` reads the verifier signing key's certificate to compute the audience, so the fixture needs a `keys` entry whose `x5c` points at the test leaf PEM written into the existing tempdir. Write `leaf_cert` (already produced by `test_pki()`) to a file there and reference it.

Do **not** change the `dc_api` tests (`gap_vp_07_...`, `dc_api_audience_trailing_slash_variations_both_match`, the fallback test) — their `origin:` audiences are unaffected. **Do** update the test whose doc comment says a non-`dc_api` transport "must still require the `x509_san_dns:<host>` Client Identifier": its assertion stays (an `origin:` audience must be rejected), only the expected identifier and the comment change.

Apply the same treatment to `crates/foundry-verifier/tests/conformance_vp.rs`.

- [ ] **Step 6: Run the verifier tests**

```bash
cargo test -p foundry-verifier 2>&1 | tail -40
```

Expected: PASS, including `gap_haip_05_...`, `test_build_signed_request_object_and_verify_jws`, and `vp_0128_0130_0132_response_uri_present_no_redirect_uri_same_origin_as_client_id` — the latter must now derive its expected host from `public_base_url`, since `client_id` no longer carries it.

- [ ] **Step 7: Update the conformance register — same commit, non-negotiable**

In `docs/conformance/openid4vc-conformance.md`:

1. **Delete** the `GAP-HAIP-05` row from the Gap Register.
2. `HAIP-0043`: `gap` → `conforming`. Evidence: `build_signed_request_object` emits `x509_hash:<base64url(SHA-256(DER leaf))>` via `foundry_core::trust::x509_hash_client_id_value`, and `do_verify_vp_response` derives the expected KB-JWT audience from the same helper. Test: `client_id_is_the_x509_hash_of_the_configured_leaf_certificate`.
3. `VP-0068`, `VP-0069`: `not-implemented` → `conforming`, same evidence. VP-0069's signing-key requirement holds because the signing key and the `x5c` leaf come from the same `keys.<signing_key>` entry.
4. `HAIP-0045` (trust anchor MUST NOT be in `x5c`): **re-adjudicate against the code as it lands.** `build_x5c` is called with the leaf PEM only, so no anchor is included — verify that before writing a verdict, and if it becomes `conforming` it needs a citing test.
5. `HAIP-0055`: its evidence mentions the prefix; update the wording.
6. **Recompute the Summary** for OpenID4VP and HAIP.

- [ ] **Step 8: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-verifier -p foundry
cargo clippy -p foundry-verifier --all-targets -- -D warnings
cargo fmt --check
```

Expected: green, including all 11 `conformance_report.rs` tests. If `every_gap_test_is_ignored_citing_its_own_gap_id` or `summary_counts_match_the_inventories` fails, Step 7 is incomplete — fix the document, not the test.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry-verifier/src/request.rs crates/foundry-verifier/src/verify.rs \
        crates/foundry-verifier/tests/conformance_vp.rs \
        docs/conformance/openid4vc-conformance.md
git commit -m "fix(verifier): GAP-HAIP-05 — use the x509_hash Client Identifier Prefix

HAIP OpenID4VP L256 mandates x509_hash for signed requests, narrowing OpenID4VP
Section 5.9.3; the value is base64url(SHA-256(DER leaf)) per L616.

Two-sided by necessity: build_signed_request_object emits the identifier and
do_verify_vp_response recomputes it as the expected KB-JWT audience. Both now call
foundry_core::trust::x509_hash_client_id_value, so they cannot drift.

x5c becomes required for signed requests -- the identifier *is* the certificate
hash. GAP-VP-02's SAN cross-check is preserved, re-anchored on public_base_url's
host now that client_id no longer carries it.

Closes GAP-HAIP-05; HAIP-0043, VP-0068, VP-0069 now conforming."
```

---

## Task 3: Delete the dead `verifier.client_id_scheme` config field

Mechanical but wide: `x509_san_dns` appears in 24 files and every `VerifierConfig { .. }` literal must be updated or the workspace will not compile.

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs`, `crates/foundry-core/src/config/validate.rs`
- Modify: `config.yaml`, `crates/foundry/src/commands.rs`
- Modify: every test file constructing `VerifierConfig` — `crates/foundry-core/tests/validate_key_material.rs`, `crates/foundry-issuer/src/{create_offer,metadata,credential}.rs`, `crates/foundry-issuer/tests/conformance_vci.rs`, `crates/foundry-verifier/src/{request,verify}.rs`, and `crates/foundry/tests/{logging_redaction,openapi_endpoints,authorization_code_flow,health,wallet_issuance,wallet_verification,wallet_metadata,console,issuer_offers,conformance_http,wallet_status_list_route}.rs`

**Interfaces:**
- Consumes: nothing. Produces: `VerifierConfig` without `client_id_scheme`. No later task references it.

- [ ] **Step 1: Confirm the field is genuinely unread before deleting**

```bash
grep -rn 'client_id_scheme' crates/ --include='*.rs' | grep -v 'tests/' | grep -v '"x509_san_dns"'
```

Expected: only the field declaration in `model.rs` and its doc-comment example. **If any production code reads it, stop** — Decision 2's premise is wrong and the spec needs revisiting.

- [ ] **Step 2: Delete the field**

Remove `pub client_id_scheme: String,` from `VerifierConfig` in `crates/foundry-core/src/config/model.rs`, and remove the `client_id_scheme: x509_san_dns` line from that file's doc-comment YAML example and from the inline YAML fixture string in its test module.

- [ ] **Step 3: Fix every construction site**

```bash
cargo build --workspace --all-targets 2>&1 | grep -E '^error' | head -30
```

Remove the `client_id_scheme: ...` line from each reported `VerifierConfig` literal. Repeat until clean. Do not add `..Default::default()` — these fixtures are explicit by design.

- [ ] **Step 4: Update the shipped config and the init template**

Delete the `client_id_scheme: x509_san_dns` line from `config.yaml` and from the embedded template in `crates/foundry/src/commands.rs`. Add in its place, in `config.yaml`:

```yaml
  # The Client Identifier Prefix is not configurable: HAIP OpenID4VP L256 mandates
  # `x509_hash` for signed requests, so it is always derived from the `x5c` leaf of
  # `verifier.signing_key`.
```

- [ ] **Step 5: Prove old configs still load**

Existing deployments have `client_id_scheme` in their YAML. No config struct sets `#[serde(deny_unknown_fields)]`, so it must be ignored rather than rejected — that is what makes the removal non-breaking. Add to `crates/foundry-core/src/config/model.rs`'s test module a test that takes the module's existing minimal YAML fixture string, re-inserts `  client_id_scheme: x509_san_dns` under `verifier:`, deserializes it with the same loader the neighbouring tests use, and asserts the parse succeeds and `cfg.verifier.signing_key` is intact. Name it `a_config_still_listing_the_removed_client_id_scheme_key_loads`, and comment it with the reason above.

- [ ] **Step 6: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Clippy is workspace-wide **only** because this task edits fixtures in every crate; the test set above is still the scoped set, not `--workspace`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(core): remove the dead verifier.client_id_scheme config field

Declared, documented in config.yaml, and set in every fixture -- but never read by
any production code path. Since GAP-HAIP-05 fixes the prefix to x509_hash (HAIP
OpenID4VP L256), the field would have exactly one legal value, which is not
configuration.

Removal is non-breaking: no config struct sets deny_unknown_fields, so an existing
config.yaml that still lists the key keeps loading. Covered by a regression test."
```
---

## Task 4: `CredentialType.scope` in config, with uniqueness validation

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs`, `crates/foundry-core/src/config/validate.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `CredentialType.scope: Option<String>` and `CredentialType::resolved_scope(&self) -> &str`, implementing **resolved scope = `scope` if set, else `id`**. Tasks 5 and 6 both call `resolved_scope()`; neither re-derives the rule.

- [ ] **Step 1: Write the failing tests**

Add to the test module of `crates/foundry-core/src/config/validate.rs`. Build `cfg` with whatever `Config` fixture that module already uses (there is an existing full `Config` literal around its `VerifierConfig` construction) — the only additions are the `credential_types` entries. `dc+sd-jwt` types require a `vct`, so every entry below sets one:

```rust
    #[test]
    fn duplicate_resolved_scopes_are_rejected() {
        // HAIP OpenID4VCI L209: "The scope value MUST map to a specific Credential
        // Type." Two types resolving to one scope makes that unsatisfiable.
        let mut cfg = test_config();
        cfg.credential_types = vec![
            CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/pid".to_string()),
                doctype: None,
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
            },
            CredentialType {
                id: "other".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/other".to_string()),
                doctype: None,
                // Collides with the first type's defaulted scope ("pid").
                scope: Some("pid".to_string()),
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
            },
        ];
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("scope"),
            "the error must name the scope collision: {err}"
        );
    }

    #[test]
    fn distinct_resolved_scopes_are_accepted() {
        let mut cfg = test_config();
        cfg.credential_types = vec![
            CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/pid".to_string()),
                doctype: None,
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
            },
            CredentialType {
                id: "mdl".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/mdl".to_string()),
                doctype: None,
                scope: Some("eu.europa.ec.eudi.pid.1".to_string()),
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
            },
        ];
        cfg.validate().unwrap();
    }

    #[test]
    fn an_explicitly_blank_scope_is_rejected() {
        let mut cfg = test_config();
        cfg.credential_types = vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/pid".to_string()),
            doctype: None,
            scope: Some("   ".to_string()),
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
        }];
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("scope"), "{err}");
    }

    #[test]
    fn resolved_scope_defaults_to_the_id() {
        let ct = CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/pid".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
        };
        assert_eq!(ct.resolved_scope(), "pid");
        let with_scope = CredentialType { scope: Some("s".to_string()), ..ct };
        assert_eq!(with_scope.resolved_scope(), "s");
    }
```

If that module's `Config` fixture is not already a named helper, extract the existing literal into `fn test_config() -> Config` first so all four tests share it.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-core scope 2>&1 | tail -20
```

Expected: FAIL — `CredentialType` has no field `scope` and no method `resolved_scope`.

- [ ] **Step 3: Add the field and the resolution rule**

In `crates/foundry-core/src/config/model.rs`, add to `CredentialType` after `doctype`:

```rust
    /// The OAuth `scope` value that identifies this Credential Type.
    ///
    /// HAIP OpenID4VCI L186 requires the Credential Issuer metadata to carry a
    /// scope for every Credential Configuration, and L199/L209 require the value to
    /// map to a specific Credential Type. When unset, the credential type's `id` is
    /// used, so an unconfigured deployment is conformant without change; set it
    /// explicitly when an Ecosystem mandates a particular scope string.
    #[serde(default)]
    pub scope: Option<String>,
```

Add the resolver as an inherent method so both consumers share one definition:

```rust
impl CredentialType {
    /// The scope this Credential Type is published and requested under.
    /// HAIP OpenID4VCI L186/L199/L209 — see the `scope` field.
    pub fn resolved_scope(&self) -> &str {
        self.scope.as_deref().unwrap_or(&self.id)
    }
}
```

- [ ] **Step 4: Add the validation**

In `Config::validate()`, after the existing `for ct in &self.credential_types` format-checking loop (not inside it — this check is over the whole list):

```rust
        // HAIP OpenID4VCI L209: the scope value MUST map to a *specific* Credential
        // Type, so two types may not resolve to the same scope.
        let mut seen_scopes: std::collections::BTreeMap<&str, &str> =
            std::collections::BTreeMap::new();
        for ct in &self.credential_types {
            if let Some(explicit) = &ct.scope {
                if explicit.trim().is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}' has an empty 'scope'",
                        ct.id
                    )));
                }
            }
            if let Some(previous) = seen_scopes.insert(ct.resolved_scope(), &ct.id) {
                return Err(ConfigError::Validation(format!(
                    "credential_types '{}' and '{}' both resolve to scope '{}'; each \
                     scope must map to exactly one Credential Type",
                    previous,
                    ct.id,
                    ct.resolved_scope()
                )));
            }
        }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p foundry-core scope 2>&1 | tail -20
```

Expected: PASS, 4 tests.

- [ ] **Step 6: Add `scope: None` to every other `CredentialType` literal**

```bash
cargo build --workspace --all-targets 2>&1 | grep -E '^error' | head -30
```

`#[serde(default)]` covers YAML, but struct literals must be exhaustive. Add `scope: None,` to each reported site.

- [ ] **Step 7: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(core): credential_types[].scope with resolved-scope uniqueness

HAIP OpenID4VCI L186/L199/L209. Defaults to the credential type's id via
CredentialType::resolved_scope(), so nothing needs configuring; Config::validate()
rejects two types resolving to the same scope, which would make L209's 'maps to a
specific Credential Type' unsatisfiable."
```

---

## Task 5: Publish `scope` in Credential Issuer metadata

**Files:**
- Modify: `crates/foundry-issuer/src/metadata.rs`

**Interfaces:**
- Consumes: `CredentialType::resolved_scope() -> &str` (Task 4).
- Produces: `CredentialConfigurationSupported.scope: String`, always serialized. Task 6's register update cites the tests added here.

- [ ] **Step 1: Write the failing tests**

Add to the test module of `crates/foundry-issuer/src/metadata.rs`:

```rust
    #[test]
    fn every_credential_configuration_carries_a_scope() {
        // HAIP OpenID4VCI L186: the Credential Issuer metadata MUST include a scope
        // for every Credential Configuration it supports.
        let cfg = test_config();
        let metadata = build_issuer_metadata(&cfg);
        assert!(!metadata.credential_configurations_supported.is_empty());
        for (id, config) in &metadata.credential_configurations_supported {
            let json = serde_json::to_value(config).unwrap();
            let scope = json
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("configuration '{id}' has no scope"));
            assert!(!scope.is_empty(), "configuration '{id}' has an empty scope");
        }
    }

    #[test]
    fn scope_defaults_to_the_credential_type_id_and_can_be_overridden() {
        let mut cfg = test_config();
        cfg.credential_types[0].scope = None;
        let default_id = cfg.credential_types[0].id.clone();
        cfg.credential_types.push(CredentialType {
            id: "override_me".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/other".to_string()),
            doctype: None,
            scope: Some("eu.europa.ec.eudi.pid.1".to_string()),
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
        });

        let metadata = build_issuer_metadata(&cfg);
        assert_eq!(
            metadata.credential_configurations_supported[&default_id].scope,
            default_id
        );
        assert_eq!(
            metadata.credential_configurations_supported["override_me"].scope,
            "eu.europa.ec.eudi.pid.1"
        );
    }
```

Match the field order of the `CredentialType` literal to the struct as it stands after Task 4.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --lib metadata:: 2>&1 | tail -20
```

Expected: FAIL — no field `scope` on `CredentialConfigurationSupported`.

- [ ] **Step 3: Add the field**

In `crates/foundry-issuer/src/metadata.rs`, add to `CredentialConfigurationSupported` immediately after `format`:

```rust
    /// HAIP OpenID4VCI L186: the metadata MUST include a scope for every Credential
    /// Configuration. Neither `Option` nor `skip_serializing_if`: "every" admits no
    /// omission.
    pub scope: String,
```

And in the construction inside `build_issuer_metadata`, alongside `format: ct.format.clone(),`:

```rust
                scope: ct.resolved_scope().to_string(),
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --lib metadata:: 2>&1 | tail -20
```

Expected: PASS.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```

`crates/foundry/tests/wallet_metadata.rs` asserts on the metadata document — if it fails, the new field is expected output and the assertion should be extended, not the field removed.

**`haip_0023_credential_configuration_metadata_carries_a_scope_value` stays `#[ignore]`d until Task 6.** The register row cannot be removed while HAIP-0027/0028 are still `gap`, and `conformance_report.rs` enforces that pairing.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(issuer): publish scope for every Credential Configuration

HAIP OpenID4VCI L186. Value comes from CredentialType::resolved_scope(), so it
defaults to the credential type id and can be overridden per Ecosystem. Serialized
unconditionally -- 'every Credential Configuration' admits no omission. The
GAP-HAIP-01 register row stays open until /authorize accepts the parameter."
```

---

## Task 6: Accept `scope` at `/authorize` and close GAP-HAIP-01

**Files:**
- Modify: `crates/foundry-issuer/src/authorize.rs`, `crates/foundry/src/server.rs`
- Modify: `crates/foundry-issuer/tests/conformance_vci.rs` (un-ignore), `crates/foundry/tests/authorization_code_flow.rs`
- Modify: `docs/conformance/openid4vc-conformance.md`, `openapi.json`, `config.yaml`, `crates/foundry/src/commands.rs`

**Interfaces:**
- Consumes: `CredentialType::resolved_scope()` (Task 4); `CredentialConfigurationSupported.scope` (Task 5).
- Produces: `AuthorizeParams.scope: Option<String>` and `handle_authorize_request(storage, params, issuer_identifier, tx_ttl_secs, now_unix, scopes: &BTreeMap<String, String>)` where the map is **resolved scope → credential type id**. No later task calls it.

- [ ] **Step 1: Write the failing tests**

In `crates/foundry-issuer/tests/conformance_vci.rs`, delete the `#[ignore = "GAP-HAIP-01: ..."]` attribute from `haip_0023_credential_configuration_metadata_carries_a_scope_value`.

`crates/foundry/tests/authorization_code_flow.rs` already drives offer → `/authorize` → `/token`. Copy its existing round-trip test three times and change only the query string and the assertion:

```rust
/// HAIP OpenID4VCI L209: the `scope` parameter MUST be used to communicate the
/// Credential Type(s) to be issued, and the value MUST map to a specific Credential
/// Type. A scope naming the type the offer is bound to succeeds.
#[tokio::test]
async fn authorize_accepts_a_scope_matching_the_offers_credential_type() {
    // Existing offer + /authorize setup, with `&scope=pid` appended to the query.
    // Assert: 302 whose Location carries a `code` parameter, exactly as the
    // no-scope flow does, and the subsequent /token call still succeeds.
}

/// HAIP OpenID4VCI L209: the scope value MUST map to a *specific* Credential Type.
/// A scope naming a different type than `issuer_state` is bound to is a conflicting
/// request and must be refused -- by redirect, since redirect_uri is already
/// validated at that point (RFC 6749 4.1.2.1).
#[tokio::test]
async fn authorize_rejects_a_scope_naming_a_different_credential_type() {
    // Same setup, but `&scope=` a second configured type's resolved scope.
    // Assert: 302 whose Location carries error=invalid_scope and no `code`.
}

/// Absent `scope`, behaviour is unchanged: issuer_state remains the authoritative
/// binding. The mandate is on the Issuer to publish and honour a scope, not to
/// require one.
#[tokio::test]
async fn authorize_without_a_scope_still_succeeds() {
    // The existing no-scope flow, asserted explicitly so the regression is pinned.
}
```

The second test needs a second credential type in the server's config fixture; add one (`dc+sd-jwt` with its own `vct` and a distinct `id`) if the fixture ships only `pid`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-issuer --test conformance_vci haip_0023 2>&1 | tail -20
cargo test -p foundry --test authorization_code_flow scope 2>&1 | tail -20
```

Expected: `haip_0023` **passes** — Task 5 added the field; it was ignored only because the register row could not be removed yet. The three `authorize_*` tests FAIL: `scope` is not a recognized parameter.

- [ ] **Step 3: Add the parameter and the agreement check**

In `crates/foundry-issuer/src/authorize.rs`, add to `AuthorizeParams`:

```rust
    /// HAIP OpenID4VCI L209: the `scope` parameter communicates the Credential Type
    /// to be issued. Optional here -- the mandate is that the Issuer publish a scope
    /// (L186) and honour it when sent, not that a Wallet must send one;
    /// `issuer_state` remains the authoritative binding.
    pub scope: Option<String>,
```

Add a `scopes` parameter to `handle_authorize_request`:

```rust
pub async fn handle_authorize_request(
    storage: &dyn Storage,
    params: &AuthorizeParams,
    issuer_identifier: &str,
    tx_ttl_secs: u64,
    now_unix: i64,
    // Resolved scope -> credential type id, per HAIP OpenID4VCI L209. Passed in
    // rather than taking `&Config`: this function needs the mapping, nothing else.
    scopes: &std::collections::BTreeMap<String, String>,
) -> AuthorizeOutcome {
```

Insert the check **after** the `redirect_uri` match and the `let redirect_uri = ...;` / `let state = params.state.clone();` bindings, so errors from here on return by redirect:

```rust
    // HAIP OpenID4VCI L209: the `scope` parameter MUST be used to communicate the
    // Credential Type(s) to be issued and the value MUST map to a specific
    // Credential Type. When a Wallet sends one it must name the same type the
    // transaction was bound to at create_offer time; a mismatch is a conflicting
    // request, not a silently-ignored hint.
    if let Some(scope) = params.scope.as_deref() {
        let names_this_transaction = scopes
            .get(scope)
            .is_some_and(|credential_type_id| *credential_type_id == tx.credential_type_id);
        if !names_this_transaction {
            return AuthorizeOutcome::ErrorRedirect {
                redirect_uri,
                error: "invalid_scope".to_string(),
                description: "scope is unknown or does not match the Credential Type of \
                              this offer"
                    .to_string(),
                state,
                iss,
            };
        }
    }
```

**Read the real `AuthorizeOutcome::ErrorRedirect` variant shape and the real transaction field name for the credential type from the file and adjust** — the names above follow the existing conventions but must be confirmed. Keep `iss` populated: Tier 3 added it for RFC 9207 §2, which covers error responses too.

- [ ] **Step 4: Wire it through the HTTP layer**

In `crates/foundry/src/server.rs`: add `scope: Option<String>` to the `/authorize` query struct (all its fields are already optional so a malformed request yields a protocol error, not an axum 422); pass `scope: q.scope.clone()` when constructing `foundry_issuer::AuthorizeParams`; and build the map at the call site:

```rust
    // HAIP OpenID4VCI L209 — resolved scope -> credential type id.
    let scopes: std::collections::BTreeMap<String, String> = config
        .credential_types
        .iter()
        .map(|ct| (ct.resolved_scope().to_string(), ct.id.clone()))
        .collect();
```

Use the handler's actual accessor for `config`. Add `scope` to the route's `utoipa` parameter annotations.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p foundry-issuer --test conformance_vci haip_0023
cargo test -p foundry --test authorization_code_flow
```

Expected: PASS.

- [ ] **Step 6: Regenerate OpenAPI and document the config key**

Regenerate `openapi.json` (and `openapi-wallet.json` if `/authorize` appears there) using the command in `crates/foundry/AGENTS.md` — do not hand-edit. Then add to `config.yaml` and the `commands.rs` template, under the `pid` credential type:

```yaml
    # HAIP OpenID4VCI L186/L209: the scope a Wallet uses to request this type.
    # Defaults to the credential type's `id` when omitted; set it explicitly when an
    # Ecosystem mandates a specific value.
    # scope: eu.europa.ec.eudi.pid.1
```

- [ ] **Step 7: Update the conformance register — same commit**

1. **Delete** the `GAP-HAIP-01` row from the Gap Register.
2. `HAIP-0014`, `HAIP-0023`: `gap` → `conforming`. Evidence: `CredentialConfigurationSupported.scope` (metadata.rs) is serialized for every configuration from `CredentialType::resolved_scope()`. Tests: `haip_0023_credential_configuration_metadata_carries_a_scope_value`, `every_credential_configuration_carries_a_scope`.
3. `HAIP-0027`, `HAIP-0028`: `gap` → `conforming`. Evidence: `handle_authorize_request` (authorize.rs) resolves `params.scope` against the configured scope map and rejects a scope that does not match the transaction's Credential Type; `Config::validate()` enforces one-to-one scope↔type. Tests: `authorize_accepts_a_scope_matching_the_offers_credential_type`, `authorize_rejects_a_scope_naming_a_different_credential_type`, `duplicate_resolved_scopes_are_rejected`.
4. `VCI-0145`: **re-adjudicate.** It was `not-implemented` because no `scope` existed; decide its verdict against what now exists and record the rationale.
5. **Recompute the Summary** for OpenID4VCI and HAIP.

- [ ] **Step 8: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: green, including all 11 `conformance_report.rs` tests and `openapi_endpoints.rs`.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "fix(issuer): GAP-HAIP-01 — accept and honour the scope parameter

HAIP OpenID4VCI L209: /authorize now accepts `scope`, resolves it against the
configured scope -> credential type map, and rejects a scope naming a different
type than the offer's issuer_state is bound to (invalid_scope, by redirect, per
RFC 6749 4.1.2.1). Absent scope, behaviour is unchanged.

Closes GAP-HAIP-01; HAIP-0014, HAIP-0023, HAIP-0027, HAIP-0028 now conforming."
```

---

## Task 7: `attach_kb_jwt` can emit `transaction_data_hashes`

**Files:**
- Modify: `crates/foundry-sd-jwt-vc/src/builder.rs`, and the crate root re-export
- Modify: every caller — `crates/foundry-sd-jwt-vc/src/verifier.rs` (tests), `crates/foundry-verifier/src/verify.rs` (tests), `crates/foundry-verifier/tests/conformance_vp.rs`, plus anything else `grep` finds

**Interfaces:**
- Consumes: nothing.
- Produces:

```rust
pub struct TransactionDataBinding<'a> {
    pub hashes: &'a [String],
    pub alg: Option<&'a str>,
}

pub fn attach_kb_jwt(
    issuer_presentation: String,
    holder_signer: &dyn Signer,
    audience: &str,
    nonce: &str,
    transaction_data_hashes: Option<TransactionDataBinding<'_>>,
) -> Result<String, FormatError>
```

Task 9's positive test constructs `TransactionDataBinding`.

- [ ] **Step 1: Write the failing tests**

Add to the test module of `crates/foundry-sd-jwt-vc/src/builder.rs`. Add `use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;` inside `mod tests` if it is not already in scope there:

```rust
    #[test]
    fn attach_kb_jwt_emits_transaction_data_hashes_when_asked() {
        // OpenID4VP L3144: a non-empty array of base64url-encoded hashes.
        // L3145: transaction_data_hashes_alg is REQUIRED in the response when the
        // request carried it.
        let signer = test_signer();
        let issuer_pres = "eyJhbGciOiJFUzI1NiJ9.e30.sig~".to_string();
        let hashes = vec!["aGFzaDE".to_string(), "aGFzaDI".to_string()];

        let out = attach_kb_jwt(
            issuer_pres.clone(),
            &signer,
            "x509_hash:abc",
            "nonce-1",
            Some(TransactionDataBinding {
                hashes: &hashes,
                alg: Some("sha-256"),
            }),
        )
        .unwrap();

        let kb = out.strip_prefix(&issuer_pres).expect("KB-JWT is appended");
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(kb.split('.').nth(1).unwrap()).unwrap())
                .unwrap();

        assert_eq!(payload["transaction_data_hashes"], serde_json::json!(hashes));
        assert_eq!(payload["transaction_data_hashes_alg"], "sha-256");
    }

    #[test]
    fn attach_kb_jwt_omits_the_claims_when_not_asked() {
        let signer = test_signer();
        let issuer_pres = "eyJhbGciOiJFUzI1NiJ9.e30.sig~".to_string();

        let out = attach_kb_jwt(issuer_pres.clone(), &signer, "aud", "nonce", None).unwrap();

        let kb = out.strip_prefix(&issuer_pres).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(kb.split('.').nth(1).unwrap()).unwrap())
                .unwrap();

        assert!(payload.get("transaction_data_hashes").is_none());
        assert!(payload.get("transaction_data_hashes_alg").is_none());
    }

    #[test]
    fn attach_kb_jwt_omits_the_alg_when_the_request_did_not_carry_one() {
        // L3145 makes the response field REQUIRED only when the request had it.
        let signer = test_signer();
        let issuer_pres = "eyJhbGciOiJFUzI1NiJ9.e30.sig~".to_string();
        let hashes = vec!["aGFzaDE".to_string()];

        let out = attach_kb_jwt(
            issuer_pres.clone(),
            &signer,
            "aud",
            "nonce",
            Some(TransactionDataBinding {
                hashes: &hashes,
                alg: None,
            }),
        )
        .unwrap();

        let kb = out.strip_prefix(&issuer_pres).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(kb.split('.').nth(1).unwrap()).unwrap())
                .unwrap();

        assert_eq!(payload["transaction_data_hashes"], serde_json::json!(hashes));
        assert!(payload.get("transaction_data_hashes_alg").is_none());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-sd-jwt-vc --lib builder:: 2>&1 | tail -20
```

Expected: FAIL — `attach_kb_jwt` takes 4 arguments and `TransactionDataBinding` does not exist.

- [ ] **Step 3: Implement**

In `crates/foundry-sd-jwt-vc/src/builder.rs`:

```rust
/// The `transaction_data_hashes` binding a Wallet places in its KB-JWT.
///
/// OpenID4VP 1.0, Format / IETF SD-JWT VC / Transaction Data (L3144): each element
/// is a base64url-encoded hash computed over the string received in the
/// `transaction_data` request parameter. L3145: `transaction_data_hashes_alg` is
/// REQUIRED in the response when the request carried it.
pub struct TransactionDataBinding<'a> {
    pub hashes: &'a [String],
    pub alg: Option<&'a str>,
}

pub fn attach_kb_jwt(
    issuer_presentation: String,
    holder_signer: &dyn Signer,
    audience: &str,
    nonce: &str,
    transaction_data_hashes: Option<TransactionDataBinding<'_>>,
) -> Result<String, FormatError> {
    let mut hasher = Sha256::new();
    hasher.update(issuer_presentation.as_bytes());
    let sd_hash = B64URL.encode(hasher.finalize());
    let kb = build_kb_jwt(
        holder_signer,
        audience,
        nonce,
        &sd_hash,
        transaction_data_hashes,
    )?;
    Ok(format!("{issuer_presentation}{kb}"))
}
```

Thread the new parameter into `build_kb_jwt` and, after its existing claims are set, add:

```rust
    // OpenID4VP L3144/L3145.
    if let Some(binding) = transaction_data_hashes {
        payload.set_claim(
            "transaction_data_hashes",
            Some(serde_json::json!(binding.hashes)),
        )?;
        if let Some(alg) = binding.alg {
            payload.set_claim("transaction_data_hashes_alg", Some(serde_json::json!(alg)))?;
        }
    }
```

Adapt to the actual payload API `build_kb_jwt` uses — josekit's `JwtPayload::set_claim` returns a `Result`, a `serde_json::Map` does not. Re-export `TransactionDataBinding` from the crate root alongside `attach_kb_jwt`.

- [ ] **Step 4: Update every existing caller to pass `None`**

```bash
grep -rn 'attach_kb_jwt(' crates/ --include='*.rs'
```

Add `, None` to each call. All current callers are in test modules.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p foundry-sd-jwt-vc
```

Expected: PASS.

- [ ] **Step 6: Run the scoped gate**

```bash
cargo test -p foundry-sd-jwt-vc -p foundry-verifier -p foundry
cargo clippy -p foundry-sd-jwt-vc --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(sd-jwt-vc): attach_kb_jwt can emit transaction_data_hashes

OpenID4VP L3144/L3145. Optional TransactionDataBinding parameter; every existing
caller passes None. Without this the workspace has no way to construct a correctly
bound presentation, so GAP-VP-04's check could only ever be tested negatively --
and a blanket refusal would pass that test."
```

---

## Task 8: `encode_transaction_data` advertises `transaction_data_hashes_alg`

**Files:**
- Modify: `crates/foundry-verifier/src/request.rs`

**Interfaces:**
- Consumes: `config.verifier.transaction_data_hashes_alg: Vec<String>` — already declared, previously never read.
- Produces: stored `tx.transaction_data` entries carrying `transaction_data_hashes_alg` when configured. Task 9's check compares against these.

- [ ] **Step 1: Write the failing tests**

The test module of `crates/foundry-verifier/src/request.rs` already has a `transaction_data` test (the one asserting `tx.transaction_data.unwrap().len() == 1`). Copy its config, storage, and request construction verbatim into two new tests, changing only the config field and the assertions:

```rust
    #[tokio::test]
    async fn transaction_data_entries_advertise_the_configured_hash_algorithm() {
        // OpenID4VP L3142: transaction_data_hashes_alg is a member of each
        // transaction data object, and one of its values MUST be used to compute
        // transaction_data_hashes. It must therefore be inside the entry *before*
        // base64url encoding, so what a wallet hashes is what was advertised.
        // ... same setup as the existing transaction_data test, plus:
        //     config.verifier.transaction_data_hashes_alg = vec!["sha-256".to_string()];
        let encoded = &tx.transaction_data.unwrap()[0];
        let entry: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(encoded).unwrap()).unwrap();
        assert_eq!(
            entry["transaction_data_hashes_alg"],
            serde_json::json!(["sha-256"])
        );
        // The operator-supplied members survive untouched.
        assert_eq!(entry["type"], "payment");
    }

    #[tokio::test]
    async fn transaction_data_entries_omit_the_algorithm_when_unconfigured() {
        // L3142: absent the field, sha-256 is the default -- so an empty config must
        // advertise nothing rather than advertising a guess.
        // ... same setup, plus:
        //     config.verifier.transaction_data_hashes_alg = vec![];
        let encoded = &tx.transaction_data.unwrap()[0];
        let entry: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(encoded).unwrap()).unwrap();
        assert!(entry.get("transaction_data_hashes_alg").is_none());
    }
```

Use the `type: "payment"` / `credential_ids` entry shape the existing test already builds, so the DCQL id it names is valid for that fixture.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-verifier --lib request::tests::transaction_data_entries 2>&1 | tail -20
```

Expected: FAIL — the encoded entry has no `transaction_data_hashes_alg`.

- [ ] **Step 3: Implement**

Change the signature:

```rust
fn encode_transaction_data(
    entries: &[serde_json::Value],
    dcql: &serde_json::Value,
    hashes_alg: &[String],
) -> Result<Vec<String>, VerificationError> {
```

Replace the final encode step (`let bytes = serde_json::to_vec(entry)...`) with:

```rust
            // OpenID4VP L3142: `transaction_data_hashes_alg` is a member of the
            // transaction data object. Injected before encoding so the advertised
            // bytes and the bytes a wallet hashes are identical -- the guarantee this
            // function's contract rests on. An operator-supplied value is never
            // silently replaced.
            let entry = if hashes_alg.is_empty() {
                entry.clone()
            } else {
                let mut with_alg = obj.clone();
                with_alg
                    .entry("transaction_data_hashes_alg".to_string())
                    .or_insert_with(|| serde_json::json!(hashes_alg));
                serde_json::Value::Object(with_alg)
            };
            let bytes = serde_json::to_vec(&entry)
                .map_err(|e| VerificationError::Serialization(e.to_string()))?;
            Ok(B64URL.encode(bytes))
```

Update the single call site in `create_verification_request` to pass `&config.verifier.transaction_data_hashes_alg`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry-verifier --lib request:: 2>&1 | tail -30
```

Expected: PASS. The existing test that decodes `payload["transaction_data"][0]` may need its expectation extended — the entry legitimately carries one more member now.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry-verifier -p foundry
cargo clippy -p foundry-verifier --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-verifier/src/request.rs
git commit -m "feat(verifier): advertise transaction_data_hashes_alg in each entry

OpenID4VP L3142 places the field inside each transaction data object. The
verifier.transaction_data_hashes_alg config key existed but was never read, so a
wallet had nothing to select from and the verifier nothing to validate against.
Injected before base64url encoding, preserving the byte-identical guarantee
encode_transaction_data documents."
```

---

## Task 9: The `transaction_data_binding` check — close GAP-VP-04

**Files:**
- Modify: `crates/foundry-verifier/Cargo.toml` (+ `sha2`)
- Modify: `crates/foundry-verifier/src/verify.rs`
- Modify: `AGENTS.md` (§4.2), `crates/foundry-verifier/AGENTS.md`
- Modify: `docs/conformance/openid4vc-conformance.md`

**Interfaces:**
- Consumes: `TransactionDataBinding` and the 5-arg `attach_kb_jwt` (Task 7); entries carrying `transaction_data_hashes_alg` (Task 8); `expected_client_id(&Config)` (Task 2).
- Produces: a `CheckResult` named `transaction_data_binding`. Nothing consumes it downstream.

- [ ] **Step 1: Write the failing tests**

In `crates/foundry-verifier/src/verify.rs`, remove the `#[ignore = "GAP-VP-04: ..."]` from `gap_vp_04_transaction_data_hashes_never_validated`. Its body stays as written (its `attach_kb_jwt` call already gained `, None` in Task 7).

Add `use sha2::{Digest, Sha256};` to the test module and four tests. Copy the omitted setup verbatim from `gap_vp_04_transaction_data_hashes_never_validated`, which already builds every fixture these need:

```rust
    /// The positive counterpart to `gap_vp_04_...`: a presentation that *does* bind
    /// to the requested transaction_data must still verify. Without this, a blanket
    /// "reject whenever transaction_data was requested" implementation would pass the
    /// negative test and look correct.
    #[tokio::test]
    async fn a_correctly_bound_transaction_data_presentation_verifies() {
        // ... test_pki(), test_config(), issuer_signer, holder(), sample_tx() exactly
        //     as in gap_vp_04_transaction_data_hashes_never_validated ...
        let td_entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["c1"],
            "amount": 5000
        });
        let td_encoded = B64URL.encode(serde_json::to_vec(&td_entry).unwrap());
        tx.transaction_data = Some(vec![td_encoded.clone()]);

        // OpenID4VP L3144: hash the *string* as advertised -- no base64url decode.
        let hash = B64URL.encode(Sha256::digest(td_encoded.as_bytes()));

        // ... build_sd_jwt_vc(...) as in that test ...
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            Some(TransactionDataBinding {
                hashes: &[hash],
                alg: None,
            }),
        )
        .unwrap();

        // ... encrypt_compact(...) as in that test ...
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(
            res.verified,
            "a correctly bound presentation must verify: checks={:?}",
            res.checks
        );
        assert!(
            res.checks
                .iter()
                .any(|c| c.name == "transaction_data_binding" && c.passed),
            "the binding check must be recorded as passed: {:?}",
            res.checks
        );
    }

    /// A hash that corresponds to no requested entry is not a binding.
    #[tokio::test]
    async fn a_transaction_data_hash_that_matches_nothing_does_not_verify() {
        // ... identical setup, but hashes: &["bm90LWEtcmVhbC1oYXNo".to_string()] ...
        assert!(!res.verified);
        assert!(res
            .checks
            .iter()
            .any(|c| c.name == "transaction_data_binding" && !c.passed));
    }

    /// L3142: the algorithm MUST be one of the request's values. A wallet that used
    /// something else has not produced a hash this Verifier can rely on.
    #[tokio::test]
    async fn an_unadvertised_transaction_data_hashes_alg_does_not_verify() {
        // ... entry carrying "transaction_data_hashes_alg": ["sha-256"], KB-JWT
        //     declaring alg: Some("sha-512") ...
        assert!(!res.verified);
        assert!(res
            .checks
            .iter()
            .any(|c| c.name == "transaction_data_binding" && !c.passed));
    }

    /// No transaction_data requested -> no such check exists. The common path's
    /// result shape is unchanged.
    #[tokio::test]
    async fn no_transaction_data_means_no_binding_check() {
        // ... sample_tx() with transaction_data left None, a plain presentation ...
        assert!(res.verified);
        assert!(!res
            .checks
            .iter()
            .any(|c| c.name == "transaction_data_binding"));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-verifier --lib verify:: 2>&1 | tail -40
```

Expected: FAIL — `gap_vp_04_...` fails (`res.verified` is still `true`) and the four new tests fail on the missing check.

- [ ] **Step 3: Add the `sha2` dependency**

In `crates/foundry-verifier/Cargo.toml`, under `[dependencies]`:

```toml
sha2 = { workspace = true }
```

- [ ] **Step 4: Implement the check**

Add to `crates/foundry-verifier/src/verify.rs` a function that returns a `CheckResult` and **never errors** — fail-closed, matching `check_dcql_match`'s contract:

```rust
/// OpenID4VP 1.0 Response / VP Token Validation (L1523): Verifiers MUST check that
/// the set of Presentations satisfies all requirements of the request. When the
/// request carried `transaction_data`, the IETF SD-JWT VC profile binds it to the
/// presentation through the KB-JWT's `transaction_data_hashes` claim (L3144).
///
/// Each hash is computed over the entry **as advertised** -- the base64url string
/// itself, with no decoding first (L3144). The algorithm must be one the request
/// advertised, defaulting to `sha-256` when it advertised none (L3142).
///
/// A missing or non-matching binding is a **policy** outcome, not a structural
/// error: it records `passed: false`, which makes `verified` false by AGENTS.md
/// §4.2, and the response stays HTTP 200 per §4.3. Never returns `Err`.
fn check_transaction_data_binding(
    requested_entries: &[String],
    answered_query_id: &str,
    kb_payload: &serde_json::Value,
) -> CheckResult {
```

Implement it in this order:

1. Decode each `requested_entries` string as JSON to read its `credential_ids`, and keep only the entries whose `credential_ids` contains `answered_query_id`. Entries scoped to other credential queries impose nothing here. A non-decodable entry is a `passed: false` with a detail naming the index — it was produced by `encode_transaction_data`, so it should never happen, and silently ignoring it would weaken the check.
2. Read `transaction_data_hashes` from `kb_payload` as a non-empty array of strings; absent or empty ⇒ `passed: false` ("presentation carries no transaction_data_hashes").
3. Resolve the algorithm: `kb_payload["transaction_data_hashes_alg"]` if present, else `"sha-256"`. If the applicable entries advertised a `transaction_data_hashes_alg` array, the resolved value MUST appear in it. Reject anything other than `sha-256` regardless — L3142 requires `sha-256` support and permits others, and only `sha-256` is implemented here; say so in the detail.
4. For every applicable entry, compute `B64URL.encode(Sha256::digest(entry_string.as_bytes()))` and require it to be present in the claim array.
5. `passed` = every applicable entry matched. Put the number of applicable entries and the index of the first mismatch in `detail` — **never the entry contents** (AGENTS.md §4.5: payload fields need `foundry_core::obs::sensitive_enabled()` *and* debug/trace).

Call it from `do_verify_vp_response` **after** the SD-JWT VC format check — the KB-JWT payload must be signature-verified before its claims are trusted — and **before** `check_dcql_match`:

```rust
    // Only present when the Verifier actually requested transaction_data.
    if let Some(ref entries) = tx.transaction_data {
        checks.push(check_transaction_data_binding(
            entries,
            &answered_query_id,
            &kb_payload,
        ));
    }
```

Getting the verified KB-JWT payload may require `verify_sd_jwt_vc` (or the verifier-side helper that calls it) to return it. If it does not already, thread it out — do **not** re-parse the presentation string independently, which would validate a different KB-JWT than the one whose signature was checked.

For an **mdoc** presentation there is no KB-JWT: record `passed: false` with a detail saying mdoc transaction-data binding is not implemented. The Verifier asked for a binding it cannot confirm, so it must not report success. Do not silently skip the check.

If a new error mapping is needed, log at `warn` inside the mapper in `crates/foundry/src/server.rs` — never at the call site (AGENTS.md §4.5).

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p foundry-verifier --lib verify:: 2>&1 | tail -40
```

Expected: PASS, including `gap_vp_04_transaction_data_hashes_never_validated`.

- [ ] **Step 6: Update the governing documents**

In `AGENTS.md` §4.2, extend the check-name list to six:

```markdown
- Every verification step pushes a named `CheckResult`: `jwe_decryption`,
  `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`,
  `dcql_match`, `status_check`, `transaction_data_binding` (the last only when the
  request carried `transaction_data`).
```

In `crates/foundry-verifier/AGENTS.md`: add `transaction_data_binding` to the `verify.rs` row's pipeline description, and — following Task 2 — change the `request.rs` row so it no longer says `client_id` is derived as `x509_san_dns:<host>`; it is now `x509_hash:<base64url(SHA-256(DER leaf))>` via `foundry_core::trust::x509_hash_client_id_value`.

- [ ] **Step 7: Update the conformance register — same commit**

1. **Delete** the `GAP-VP-04` row from the Gap Register.
2. `VP-0153`: `gap` → `conforming`. Evidence: `check_transaction_data_binding` (verify.rs) requires every `transaction_data` entry scoped to the answered credential query to be hashed into the KB-JWT's `transaction_data_hashes`. Tests: `gap_vp_04_transaction_data_hashes_never_validated`, `a_correctly_bound_transaction_data_presentation_verifies`.
3. `VP-0254`, `VP-0256`: `not-implemented` → `conforming`. Test for VP-0256: `an_unadvertised_transaction_data_hashes_alg_does_not_verify` plus the positive test.
4. `VP-0253`, `VP-0255`, `VP-0257`, `VP-0258`, `VP-0259`: **re-check each** — some may move now that the claim is actually read.
5. `VP-0005`, `VP-0006`, `VP-0145`, `VP-0146`, `VP-0223`: review for stale `transaction_data` evidence.
6. **Recompute the Summary** for OpenID4VP.

- [ ] **Step 8: Run the scoped gate**

```bash
cargo test -p foundry-sd-jwt-vc -p foundry-verifier -p foundry
cargo clippy -p foundry-verifier --all-targets -- -D warnings
cargo fmt --check
```

Expected: green, including `instrumentation_hygiene.rs`, `logging_redaction.rs`, and all 11 `conformance_report.rs` tests.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "fix(verifier): GAP-VP-04 — validate the transaction_data_hashes binding

OpenID4VP L1523 + L3144. A new transaction_data_binding CheckResult, pushed only
when the request carried transaction_data, requires every entry scoped to the
answered credential query to be hashed into the KB-JWT. Hashes are computed over
the advertised base64url string with no decoding (L3144); the algorithm must be one
the request advertised, defaulting to sha-256 (L3142).

A missing binding is a policy outcome: verified: false, HTTP 200, warn (§4.3).
Previously a presentation with no binding at all verified exactly as if one had
been checked and passed.

AGENTS.md §4.2's check-name list grows to six.
Closes GAP-VP-04; VP-0153, VP-0254, VP-0256 now conforming."
```

---

## Task 10: Change record and the single full gate

**Files:**
- Create: `docs/superpowers/changes/2026-08-03-conformance-tier4-fixes.md`

**Interfaces:**
- Consumes: everything above. Produces: nothing.

- [ ] **Step 1: Verify the register is consistent and three gaps are gone**

```bash
grep -c '^| GAP-' docs/conformance/openid4vc-conformance.md
grep -n 'GAP-HAIP-05\|GAP-HAIP-01\|GAP-VP-04' docs/conformance/openid4vc-conformance.md
grep -rn '#\[ignore = "GAP-' crates/ --include='*.rs'
```

Expected: the Gap Register has **10** rows (13 − 3); the three closed ids appear nowhere; the remaining `#[ignore = "GAP-..."]` attributes are exactly the Tier-5 Minor ones.

- [ ] **Step 2: Write the change record**

Create `docs/superpowers/changes/2026-08-03-conformance-tier4-fixes.md` following the structure of `docs/superpowers/changes/2026-08-02-conformance-tier3-fixes.md`: a Date / Type / Branch / Spec+Plan header, then **Why**, **Changes** (per gap, with files touched), **Tests**, and **Left unfixed**. Record explicitly:

- `verifier.client_id_scheme` was **deleted** — a documented config key. Non-breaking (no `deny_unknown_fields`) and covered by a regression test, but operators will see it vanish from `config.yaml`.
- `verifier.transaction_data_hashes_alg` was **wired for the first time**; request-object `transaction_data` entries now carry one more member.
- The `x509_hash` swap is **wire-visible and two-sided** — emission and audience expectation both moved.
- `x5c` is now **required** for signed verification requests.
- **Left unfixed:** DPoP (GAP-HAIP-03, its own cycle, RFC 9449 pinned there); the Tier-5 Minor gaps; the `validate_chain` trust-anchor ambiguity (HAIP-0039/0079/0084); PAR (HAIP-0007).

- [ ] **Step 3: Run the full gate — once, here only**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Expected: green. This is the only full-gate run in the plan (AGENTS.md §5.3). A failure in a crate absent from every scoped set is exactly what this gate exists to catch.

- [ ] **Step 4: Run the ignored end-to-end test explicitly**

```bash
cargo test -p foundry --test e2e_full_flow -- --ignored
```

Expected: PASS. It drives a real issue → verify → revoke → re-verify flow against a spawned server and is the only end-to-end proof that the two-sided `x509_hash` swap works in a live process. It does not run in the default suite, so it must be invoked here.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/changes/2026-08-03-conformance-tier4-fixes.md
git commit -m "docs: change record for conformance Tier 4

Three Important gaps closed: GAP-HAIP-05 (x509_hash), GAP-HAIP-01 (scope),
GAP-VP-04 (transaction_data_hashes). Gap register: 13 -> 10 entries; no Critical or
Important gaps remain outside DPoP.

Full gate (cargo test --workspace, clippy --workspace -D warnings, fmt --check) run
once, green; e2e_full_flow run explicitly with --ignored."
```

---

## Self-Review

**1. Spec coverage.** Every spec section maps to a task:

| Spec element | Task |
|---|---|
| Decision 1 (unconditional prefix swap) | 2 |
| Decision 2 (delete `client_id_scheme`) | 3 |
| Decision 3 (`x5c` mandatory) | 2 Steps 1, 3, 4 |
| Decision 4 (config-authored scope) | 4, 5, 6 |
| Decision 5 (own check + builder + positive test) | 7, 8, 9 |
| Fix 1 — emission, SAN re-anchor, unsigned URI, `x5c` | 2 Step 3 |
| Fix 1 — response-side coupling, fixture literals | 2 Steps 4, 5 |
| Fix 2 — changes 1–2 (model, validate) | 4 |
| Fix 2 — change 3 (metadata) | 5 |
| Fix 2 — changes 4–6 (`authorize`, `server.rs`, config docs) | 6 |
| Fix 3 — change 1 (`encode_transaction_data`) | 8 |
| Fix 3 — change 2 (`sha2` dep) | 9 Step 3 |
| Fix 3 — change 3 (`attach_kb_jwt`) | 7 |
| Fix 3 — change 4 (the check) | 9 Step 4 |
| Governing-document updates (§4.2, verifier AGENTS.md) | 9 Step 6 |
| Conformance rows + Summary | 2/6/9 Step 7 |
| `openapi.json` | 6 Step 6 |
| `config.yaml` + `commands.rs` template | 3 Step 4, 6 Step 6 |
| Change record | 10 Step 2 |
| Risks | 2 Step 3 note, 3 Step 5, 10 Step 2 |

No uncovered spec requirement.

**2. Placeholder scan.** No "TBD", "TODO", "implement later", or "add appropriate error handling". Where a step says "copy the setup from `<named test>`" it names the exact existing test to copy and states which lines change — the alternative would be reproducing 60 lines of fixture construction four times, which the "repeat the code" rule exists to prevent only when the reader has no other source. Two deliberate instructions to *verify before writing* (`AuthorizeOutcome::ErrorRedirect`'s shape in Task 6 Step 3; `HAIP-0045`'s verdict in Task 2 Step 7) are not placeholders — they are guards against the plan asserting something it could not confirm.

**3. Type consistency.**

- `x509_hash_client_id_value(leaf_pem: &[u8]) -> Result<String, TrustError>` returns the value **without** the prefix in Task 1; every consumer (Task 2 Steps 3–5, Task 9's fixtures) composes `format!("x509_hash:{}", ...)`. Consistent.
- `CredentialType::resolved_scope(&self) -> &str` — defined Task 4, called in Task 5 (`.to_string()`) and Task 6 Step 4 (`.to_string()`). Consistent.
- `CredentialConfigurationSupported.scope: String` (not `Option`) — Task 5 defines it, Task 6 Step 7 cites it. Consistent.
- `TransactionDataBinding { hashes: &'a [String], alg: Option<&'a str> }` — defined Task 7, constructed in Task 9's tests with `hashes: &[hash]` and `alg: None` / `Some("sha-512")`. Consistent.
- `attach_kb_jwt` is 5-arg from Task 7 onward; Task 2's fixture edits happen **before** Task 7, so those call sites are 4-arg at the time Task 2 runs and gain `, None` in Task 7 Step 4. Ordering is correct.
- `expected_client_id(&Config) -> String` — introduced Task 2 Step 5, used Task 9 Step 1. Consistent.
- `check_transaction_data_binding(&[String], &str, &serde_json::Value) -> CheckResult` — defined and called only in Task 9.
- Check name string is `"transaction_data_binding"` in the implementation (Task 9 Step 4), the tests (Step 1), `AGENTS.md` (Step 6), and the register (Step 7). Consistent.
