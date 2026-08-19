# Per-Credential Verification Verdicts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every credential in a multi-credential `vp_token` produce a named,
logged verdict — so "the mdoc failed its trust anchor, the SD-JWT VC passed" is
readable in the log and the admin console instead of one anonymous error line.

**Architecture:** `foundry-verifier`'s per-credential loop currently aborts on the
first error because `verify_one_credential` returns `Result` and the caller uses
`?` — contradicting the comment directly above it, which claims verify-all. The
fix removes `Result` from that function's return type so the defect is
unrepresentable, converts each credential's failure into a failed `CheckResult`
on that credential, and widens the existing `deferred` mechanism (already used
for status-list unavailability) to carry any per-credential error with explicit
400-over-502 precedence. A new `credential_type` field surfaces the asserted
`vct`/`docType`, and a per-credential roll-up log line makes the mixed verdict
legible without renaming any existing log field.

**Tech Stack:** Rust 2024 (Cargo workspace), `tokio`, `tracing`, `serde_json`,
`utoipa` (OpenAPI), `cargo-nextest` (test runner), vanilla JS admin console.

**Spec:** `docs/superpowers/specs/2026-08-19-per-credential-verification-verdicts-design.md`

## Global Constraints

Read these before starting. They are the repository's normative rules and every
task's requirements implicitly include them.

- **Read `crates/foundry-verifier/AGENTS.md` first.** It is NOT auto-loaded. Also
  read the root `AGENTS.md` §4.2, §4.3, §4.5, §5, §6.
- **Test runner is `cargo nextest run`, never `cargo test`.** The whole workspace
  runs in ~2 seconds. There is no cheaper tier and no affected-crate subset to
  derive — always run the whole workspace.
- **The gate (root AGENTS.md §5.1), run before marking any task complete:**

  ```bash
  cargo fmt
  cargo nextest run --workspace --no-fail-fast --status-level fail
  cargo clippy --workspace --all-targets -- -D warnings
  ```

  A green run's summary line looks like
  `Summary [   1.9s] 995 tests run: 995 passed, 13 skipped`. **Quote that line
  when reporting.** Never claim a gate you did not run.
- **nextest filters are positional, with no `--` separator.** e.g.
  `cargo nextest run -p foundry-verifier verifies_two_credentials`.
  `--nocapture` is spelled `--no-capture`.
- **No `.unwrap()`, `.expect()`, `panic!()`, `unreachable!()` in request-path
  code** (root AGENTS.md §4.1). Permitted only inside `#[cfg(test)]` and
  `tests/`.
- **`verified` is always derived, never assigned** (§4.2): via
  `result.derive_verified()`, which folds `all_checks()` across the top level
  AND every `credentials[i].checks`.
- **The per-credential check-name vocabulary is closed** (§4.2):
  `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`,
  `dcql_match`, `status_check`, `transaction_data_binding`. This plan adds no
  new per-credential check name.
- **HTTP status mapping is unchanged** (§4.3): crypto/structural → 400, network
  status-fetch unavailability → 502, policy → 200 with `verified: false`.
- **Log field names are operator-facing API** (§4.5). This plan **adds**
  `credential_type`, `format`, `checks`, `checks_passed`, `credentials_failed`
  and **renames nothing**.
- **Every `#[tracing::instrument]` carries `skip_all`** (§4.5). This plan adds no
  new instrumented function; if you add one, `skip_all` is mandatory.
- **Exactly one log record per typed error** (§4.5), emitted in
  `crates/foundry/src/server.rs`'s error mapper. Do not add an error log record
  in `foundry-verifier`.
- **Cite the spec in code comments** for protocol-facing logic (§4.4), e.g.
  `// OpenID4VP 1.0 L1166 — credential query id`.
- **Commit after each task.** Conventional-commit prefixes (`feat:`, `fix:`,
  `test:`, `docs:`, `refactor:`).

---

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `crates/foundry-verifier/src/transaction.rs` | `PresentedCredential`, `CheckResult`, `VerificationResult`, `all_checks`/`derive_verified` | Add `credential_type` field (Task 1) |
| `crates/foundry-verifier/src/verify.rs` | VP response verification engine, per-credential loop, all verification logging | Asserted-type helpers (Task 1); non-`Result` per-credential return, precedence fold, step-5 gating (Task 2); roll-up log lines (Task 3) |
| `crates/foundry/assets/console.html` | Admin test console rendering | Render `credential_type` (Task 1) |
| `openapi.json` | Generated admin OpenAPI spec | Regenerate (Task 1) |
| `crates/foundry/tests/logging_redaction.rs` | Behavioural redaction harness with positive controls | Positive control for `credential_type` (Task 3) |
| `README.md` | Operator-facing logging documentation | Document roll-up line + new fields (Task 3) |
| `AGENTS.md` (root) | §4.5 operator-facing field list | Add the four new field names (Task 3) |
| `crates/foundry-verifier/AGENTS.md` | Crate gotchas | Record verify-all, precedence, short-circuit (Task 4) |
| `docs/superpowers/changes/2026-08-19-per-credential-verification-verdicts.md` | Change record | Create (Task 4) |

---

## Task 1: Surface the asserted credential type

**Files:**

- Modify: `crates/foundry-verifier/src/transaction.rs` — add field at the
  `PresentedCredential` definition (line 33); fix test constructors at lines
  182, 229, 235
- Modify: `crates/foundry-verifier/src/verify.rs` — add
  `asserted_vct_unverified` helper; populate `credential_type` inside
  `verify_one_credential`; add the field to the `PresentedCredential` literal at
  line 853; fix test constructors at lines 2892, 2898
- Modify: `crates/foundry/assets/console.html` — line ~2862
- Modify: `openapi.json` — regenerate
- Test: `crates/foundry-verifier/src/verify.rs` (`mod tests`)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:
  - `PresentedCredential.credential_type: Option<String>` — the asserted
    credential type.
  - `fn asserted_vct_unverified(presentation: &str) -> Option<String>` — private
    to `verify.rs`.
  - **A guarantee Task 2 depends on:** inside `verify_one_credential`, the local
    `credential_type` is populated **before** the format-specific signature
    stage can fail, so Task 2's error path can report it. Task 1 wires this even
    though nothing observes it yet, because the failure path is unreachable
    until Task 2.

### Steps

- [ ] **Step 1: Write the failing test for the SD-JWT `vct`**

Add to `crates/foundry-verifier/src/verify.rs`, inside `mod tests`, next to the
other multi-credential tests (after
`verifies_two_credentials_in_one_vp_token`):

```rust
    /// The asserted credential type is surfaced as its own field, so a log line
    /// and the admin console can name a credential without the reader parsing
    /// the claims blob. For SD-JWT VC that is `vct`.
    #[tokio::test]
    async fn credential_type_is_the_vct_for_an_sd_jwt_vc() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let pid = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );
        let diploma = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("degree", serde_json::json!("MSc"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid], "diploma": [diploma]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .unwrap();

        // `sd_jwt_presentation_for` mints both credentials with this vct.
        assert_eq!(
            res.credentials[0].credential_type.as_deref(),
            Some("https://localhost:8443/vct/pid")
        );
        assert_eq!(
            res.credentials[1].credential_type.as_deref(),
            Some("https://localhost:8443/vct/pid")
        );
    }
```

- [ ] **Step 2: Write the failing test for the mdoc `docType`**

Add immediately after the test from Step 1:

```rust
    /// For `mso_mdoc` the asserted credential type is the `docType`, and on the
    /// success path it is the **authenticated** one from the MSO rather than the
    /// unverified copy read from the DeviceResponse envelope.
    #[tokio::test]
    async fn credential_type_is_the_doctype_for_an_mdoc() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        tx.dcql_query = serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
            }]
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut elements = std::collections::BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        let mut namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        let mdoc_bytes = build_mdoc(
            MdocClaims {
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                namespaces,
                device_key_jwk: d_jwk_pub,
                signed_at: (now - 100) as i64,
                valid_until: (now + 3600) as i64,
            },
            &issuer_signer,
            Some(vec![der_b64(&leaf_cert)]),
        )
        .unwrap();

        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({
                "vp_token": { "c1": [B64URL.encode(&device_response)] }
            }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert_eq!(
            res.credentials[0].credential_type.as_deref(),
            Some("org.iso.18013.5.1.mDL")
        );
    }
```

- [ ] **Step 3: Write the failing unit test for the unverified-`vct` helper**

Add to the same `mod tests`:

```rust
    /// The helper reads the ISSUER-SIGNED JWT's payload, which is everything
    /// before the first `~` in the compact SD-JWT serialization. Disclosures and
    /// the KB-JWT follow and must not be mistaken for it.
    #[test]
    fn asserted_vct_reads_the_issuer_jwt_payload_and_never_errors() {
        use base64::Engine as _;
        let payload = B64URL.encode(br#"{"vct":"com.emvco.dpc.card","iss":"x"}"#);
        let presentation =
            format!("aGVhZGVy.{payload}.c2ln~WyJzYWx0IiwiYSIsMV0~a2I.a2I.a2I");
        assert_eq!(
            asserted_vct_unverified(&presentation).as_deref(),
            Some("com.emvco.dpc.card")
        );

        // Every malformed shape yields None rather than an error: this is a
        // diagnostic and must never be able to change a verdict.
        assert_eq!(asserted_vct_unverified(""), None);
        assert_eq!(asserted_vct_unverified("not-a-jwt"), None);
        assert_eq!(asserted_vct_unverified("a.!!!not-base64!!!.c"), None);
        let no_vct = B64URL.encode(br#"{"iss":"x"}"#);
        assert_eq!(asserted_vct_unverified(&format!("a.{no_vct}.c")), None);
    }
```

- [ ] **Step 4: Run the three tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier credential_type asserted_vct
```

Expected: FAIL — compile errors, because `PresentedCredential` has no
`credential_type` field and `asserted_vct_unverified` does not exist.

- [ ] **Step 5: Add the `credential_type` field**

In `crates/foundry-verifier/src/transaction.rs`, inside `pub struct
PresentedCredential`, insert after the `format` field:

```rust
    /// The credential type the presentation **asserts**: `vct` for
    /// `dc+sd-jwt` (IETF SD-JWT VC), `docType` for `mso_mdoc`
    /// (ISO/IEC 18013-5).
    ///
    /// Extracted BEFORE the format-specific signature check, so it survives a
    /// failure -- a failed credential an operator cannot name is the defect
    /// this field exists to fix. It is therefore only *authenticated* when that
    /// check passed, exactly the caveat that already governs `claims`; on the
    /// mdoc success path it is replaced with the MSO's authenticated `docType`.
    ///
    /// `None` when the presentation could not be decoded far enough to read a
    /// type at all.
    pub credential_type: Option<String>,
```

- [ ] **Step 6: Add the asserted-`vct` helper**

In `crates/foundry-verifier/src/verify.rs`, immediately **above** `struct
CredentialVerifyCtx` (line ~560):

```rust
/// The `vct` a compact SD-JWT VC presentation **asserts**, read without
/// verifying any signature.
///
/// Deliberately unauthenticated, and named to say so. It exists so a
/// presentation that fails its signature check can still be named in a log
/// record and in the admin console: a failed credential an operator cannot
/// identify is the defect this serves. On the success path the value is
/// identical to the verified payload's `vct`, because `verify_sd_jwt_vc` reads
/// the same segment.
///
/// Every malformed shape yields `None` rather than an error. This is a
/// diagnostic, and a diagnostic must not be able to change the verdict it
/// describes.
fn asserted_vct_unverified(presentation: &str) -> Option<String> {
    // IETF SD-JWT compact serialization: the issuer-signed JWT is everything
    // before the first `~`; the disclosures and the KB-JWT follow it.
    let jwt = presentation.split('~').next()?;
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = B64URL.decode(payload_b64).ok()?;
    let payload: Value = serde_json::from_slice(&bytes).ok()?;
    payload.get("vct")?.as_str().map(str::to_string)
}
```

- [ ] **Step 7: Populate `credential_type` in `verify_one_credential`**

In `verify_one_credential`, find the existing declaration block just before the
`let doc_type: Option<String> = match selected {` line and add a new local
**above** it:

```rust
    // The asserted type, filled as early as each format allows so it survives
    // the error return Task 2 adds. Kept separate from `doc_type` below, which
    // exists only for DCQL doctype matching and MUST stay `None` for SD-JWT.
    let mut credential_type: Option<String> = None;
```

In the `SelectedPresentation::SdJwtVc(jwt_str)` arm, make the **first** statement:

```rust
            credential_type = asserted_vct_unverified(jwt_str);
```

In the `SelectedPresentation::MsoMdoc { .. }` arm, immediately after the
existing `let resp = foundry_mdoc::verifier::parse_device_response(&decoded)`
statement:

```rust
            // Unverified at this point -- read from the DeviceResponse envelope
            // so it is available if `verify_issuer_signed` below rejects the
            // chain. Replaced with the authenticated MSO `docType` on success.
            credential_type = Some(resp.doc_type().to_string());
```

and immediately after the existing `let issuer =
foundry_mdoc::verifier::verify_issuer_signed(..)?;` statement:

```rust
            // Now authenticated: this docType comes from the signed MSO.
            credential_type = Some(issuer.doc_type.clone());
```

- [ ] **Step 8: Add the field to the constructed `PresentedCredential`**

In `verify_one_credential`'s `let credential = PresentedCredential {` literal
(line ~853), add after `format: ...`:

```rust
        credential_type,
```

- [ ] **Step 9: Fix the five test constructors the new field breaks**

The compiler names all of them. In `transaction.rs` lines ~182, ~229, ~235 and
`verify.rs` lines ~2892, ~2898, add an explicit value to each
`PresentedCredential { .. }` literal. Give each a deliberate value rather than a
reflexive `None`:

- `transaction.rs:182` (round-trip persistence test, `query_id: "c1"`,
  `dc+sd-jwt`) → `credential_type: Some("https://example.test/vct/pid".to_string()),`
  — proves the field survives storage.
- `transaction.rs:229` (`all_checks` test, `query_id: "pid"`, `dc+sd-jwt`) →
  `credential_type: Some("https://example.test/vct/pid".to_string()),`
- `transaction.rs:235` (`all_checks` test, `query_id: "mdl"`, `mso_mdoc`) →
  `credential_type: Some("org.iso.18013.5.1.mDL".to_string()),`
- `verify.rs:2892` (`requested_credentials_answered` test, `pid`) →
  `credential_type: None,` — this check ignores the type, and `None` documents
  that.
- `verify.rs:2898` (same test, `mdl`) → `credential_type: None,`

- [ ] **Step 10: Run the three tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier credential_type asserted_vct
```

Expected: PASS (3 tests).

- [ ] **Step 11: Render the credential type in the admin console**

In `crates/foundry/assets/console.html`, in the per-credential rendering block
(~line 2862), after the existing `h.appendChild(fmt);`:

```javascript
        // The credential type the presentation asserted (vct / docType). Only
        // authenticated when this credential's format check passed, same as its
        // claims -- so it is shown as a label, never as a trust signal.
        if (cred.credential_type) {
          const ct = document.createElement('span');
          ct.className = 'fmt';
          ct.textContent = cred.credential_type;
          h.appendChild(ct);
        }
```

- [ ] **Step 12: Regenerate the OpenAPI specs**

`crates/foundry/tests/openapi_endpoints.rs` compares the committed JSON against
freshly generated output, so this is required, not optional (root AGENTS.md §6).

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
```

Confirm the diff adds `credential_type` to the `PresentedCredential` schema:

```bash
git diff --stat openapi.json openapi-wallet.json
```

- [ ] **Step 13: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Quote the summary line.

- [ ] **Step 14: Commit**

```bash
git add crates/foundry-verifier/src/transaction.rs \
        crates/foundry-verifier/src/verify.rs \
        crates/foundry/assets/console.html \
        openapi.json openapi-wallet.json
git commit -m "feat(verifier): surface the asserted credential type per credential

A PresentedCredential named only a DCQL query id and a format, so neither
the log nor the admin console could say which credential type a verdict
belonged to. Both values were already computed and dropped: the mdoc
docType by verify_issuer_signed, the SD-JWT vct inside the cloned payload.

Extracted before the format-specific signature check so it will survive
the failure path, and replaced with the authenticated MSO docType on the
mdoc success path."
```

---

## Task 2: Verify every credential, then decide

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs` — `verify_one_credential`
  signature and body (lines ~571-880); the loop in `do_verify_vp_response`
  (lines ~1084-1101); step 5's deferred-fault block (lines ~1109-1121); the
  `Err`-arm comment in `verify_vp_response` (line ~353); new
  `with_credential_context` helper
- Test: `crates/foundry-verifier/src/verify.rs` (`mod tests`)

**Interfaces:**

- Consumes from Task 1: `PresentedCredential.credential_type`, and the guarantee
  that the local `credential_type` in `verify_one_credential` is populated before
  the signature stage can fail.
- Produces:
  - `async fn verify_one_credential(ctx: &CredentialVerifyCtx<'_>, query_id: &str, selected: SelectedPresentation<'_>, resolver: &dyn StatusListResolver) -> (PresentedCredential, Option<VerificationError>)`
    — **no longer returns `Result`**.
  - `async fn verify_credential_payload(ctx: &CredentialVerifyCtx<'_>, selected: SelectedPresentation<'_>, credential_type: &mut Option<String>) -> Result<FormatStage, VerificationError>`
  - `struct FormatStage { claims: serde_json::Map<String, Value>, kb_jwt_payload: Option<Value>, doc_type: Option<String> }`
  - `fn with_credential_context(query_id: &str, err: VerificationError) -> VerificationError`
  - `VerifyOutcome.deferred` keeps its existing type, `Option<VerificationError>`.
  - Behaviour Task 3 depends on: `result.credentials` now contains an entry for
    **every** answered credential, including failed ones, on the error path too.

### Steps

- [ ] **Step 1: Write the failing test for the reported defect**

This is the regression test for the bug that started this work. Add to
`crates/foundry-verifier/src/verify.rs`, inside `mod tests`, after the
multi-credential section:

```rust
    /// The reported defect, pinned. A two-credential `vp_token` where the mdoc's
    /// issuer chain has no configured trust anchor must still report the SD-JWT
    /// VC credential's passing verdict.
    ///
    /// Before this, `verify_one_credential`'s error propagated through `?` and
    /// abandoned the loop, so the credential verified FIRST -- which had already
    /// passed -- was discarded along with it, and the only log line named
    /// neither credential. The comment above the loop claimed verify-all; the
    /// return type said fail-fast, and the type won.
    #[tokio::test]
    async fn one_credentials_bad_chain_does_not_hide_anothers_passing_verdict() {
        // The trust store carries CA #1; the mdoc is signed under CA #2's leaf,
        // while the SD-JWT VC is signed under CA #1's -- so exactly one
        // credential is untrusted and nothing else differs.
        let (trusted_root_pem, trusted_leaf_cert, trusted_leaf_key) = test_pki();
        let (_, foreign_leaf_cert, foreign_leaf_key) = test_pki();
        let ca_str = String::from_utf8(trusted_root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let trusted_signer =
            FileSigner::from_pem(&trusted_leaf_key, SignatureAlgorithm::Es256).unwrap();
        let foreign_signer =
            FileSigner::from_pem(&foreign_leaf_key, SignatureAlgorithm::Es256).unwrap();

        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // `sd` is declared first, so DCQL declaration order verifies it before
        // the failing mdoc -- reproducing the original ordering exactly.
        tx.dcql_query = serde_json::json!({
            "credentials": [
                { "id": "sd", "format": "dc+sd-jwt" },
                {
                    "id": "md",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
                }
            ]
        });

        let sd = sd_jwt_presentation_for(
            &config,
            &tx,
            &trusted_leaf_cert,
            &trusted_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut elements = std::collections::BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        let mut namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        let mdoc_bytes = build_mdoc(
            MdocClaims {
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                namespaces,
                device_key_jwk: d_jwk_pub,
                signed_at: (now - 100) as i64,
                valid_until: (now + 3600) as i64,
            },
            &foreign_signer,
            Some(vec![der_b64(&foreign_leaf_cert)]),
        )
        .unwrap();

        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {
                "sd": [sd],
                "md": [B64URL.encode(&device_response)],
            }}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .expect_err("an unanchored issuer chain is a structural failure (§4.3 -> 400)");

        // §4.3: still a crypto failure, so still the 400 class -- not a policy
        // 200. The verdict on the wire does not change; what changes is what an
        // operator can see.
        assert_eq!(err.kind(), "failed", "got: {err}");
        // §4.4: the message names the credential it belongs to.
        assert!(
            err.to_string().contains("credential query 'md'"),
            "the error must name the credential: {err}"
        );

        // The whole point: BOTH credentials are reported.
        let result = tx.result.as_ref().expect("the result must be persisted");
        assert!(!result.verified, "a failed credential fails the response");
        assert_eq!(result.credentials.len(), 2, "every credential is reported");

        let sd_cred = &result.credentials[0];
        assert_eq!(sd_cred.query_id, "sd");
        assert!(
            sd_cred.checks.iter().all(|c| c.passed),
            "the trusted credential's verdict must survive its neighbour's failure: {:?}",
            sd_cred.checks
        );
        assert_eq!(
            sd_cred.credential_type.as_deref(),
            Some("https://localhost:8443/vct/pid")
        );

        let md_cred = &result.credentials[1];
        assert_eq!(md_cred.query_id, "md");
        assert_eq!(
            md_cred.credential_type.as_deref(),
            Some("org.iso.18013.5.1.mDL"),
            "a failed credential must still be nameable"
        );
        assert_eq!(
            md_cred.checks.len(),
            1,
            "a failed format check short-circuits the rest: {:?}",
            md_cred.checks
        );
        assert_eq!(md_cred.checks[0].check, "mdoc_issuer_auth_and_device_signature");
        assert!(!md_cred.checks[0].passed);
        assert!(
            md_cred.checks[0]
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("trust anchor"),
            "the real reason belongs in detail: {:?}",
            md_cred.checks[0].detail
        );
        assert_eq!(tx.state, VerificationState::Failed);
    }
```

- [ ] **Step 2: Write the failing test for the short-circuit and no double-count**

Add immediately after:

```rust
    /// A credential whose format check failed records exactly that one check.
    ///
    /// Running `dcql_match` and `status_check` against the empty claims map
    /// would report three failures where one occurred, two of them
    /// misattributed: "DCQL mismatch" when the truth is "we never obtained
    /// claims". And the top-level `checks` list gains no fault record, because
    /// the per-credential one already represents this fault -- recording both
    /// would double-count it.
    #[tokio::test]
    async fn a_failed_format_check_short_circuits_without_double_counting() {
        let res = run_unanchored_mdoc_presentation_reporting_result().await;
        let result = res.expect("the helper returns the persisted result");

        assert!(!result.verified);
        assert_eq!(result.credentials.len(), 1);
        let checks = &result.credentials[0].checks;
        assert_eq!(checks.len(), 1, "only the format check: {checks:?}");
        assert!(
            !checks.iter().any(|c| c.check == "dcql_match"),
            "dcql_match must not run on claims that were never obtained"
        );
        assert!(
            !checks.iter().any(|c| c.check == "status_check"),
            "status_check must not run on claims that were never obtained"
        );

        // Cross-cutting checks: jwe_decryption and requested_credentials_answered
        // only. No `verification_error` fault record, which would double-count.
        let top: Vec<&str> = result.checks.iter().map(|c| c.check.as_str()).collect();
        assert_eq!(
            top,
            vec!["jwe_decryption", "requested_credentials_answered"],
            "the deferred-fault record is StatusUnavailable-only"
        );
        assert_eq!(
            result.all_checks().filter(|c| !c.passed).count(),
            1,
            "exactly one failure is counted"
        );
    }
```

Add this helper next to `run_unanchored_mdoc_presentation` (line ~2527), so the
existing helper keeps its exact current contract and nothing else changes:

```rust
    /// `run_unanchored_mdoc_presentation`, but returning the persisted
    /// `VerificationResult` instead of the error.
    ///
    /// The result is what an operator sees in the admin console, and it is only
    /// reachable through `tx.result` -- the function itself returns `Err` per
    /// root AGENTS.md §4.3.
    async fn run_unanchored_mdoc_presentation_reporting_result()
    -> Result<VerificationResult, VerificationError> {
        let (trusted_root_pem, _, _) = test_pki();
        let (_, foreign_leaf_cert, foreign_leaf_key) = test_pki();
        let ca_str = String::from_utf8(trusted_root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer =
            FileSigner::from_pem(&foreign_leaf_key, SignatureAlgorithm::Es256).unwrap();

        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        tx.dcql_query = serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
            }]
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut elements = std::collections::BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        let mut namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        let mdoc_bytes = build_mdoc(
            MdocClaims {
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                namespaces,
                device_key_jwk: d_jwk_pub,
                signed_at: (now - 100) as i64,
                valid_until: (now + 3600) as i64,
            },
            &issuer_signer,
            Some(vec![der_b64(&foreign_leaf_cert)]),
        )
        .unwrap();

        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({
                "vp_token": { "c1": [B64URL.encode(&device_response)] }
            }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let _ = verify_vp_response(&config, &mut tx, &jwe_str, &resolver).await;
        Ok(tx.result.expect("the result is persisted even on the error path"))
    }
```

- [ ] **Step 3: Write the failing test for status-code precedence**

Add immediately after:

```rust
    /// Root AGENTS.md §4.3, made explicit. With one credential's chain untrusted
    /// (a crypto failure -> 400) and another's status list unreachable (a
    /// network fault -> 502), the response can carry only one status. The crypto
    /// failure wins: it is deterministic, so answering 502 would invite the
    /// wallet to retry a presentation that can never succeed.
    ///
    /// Before verify-all this was decided by accident -- `?` returned the crypto
    /// error immediately while StatusUnavailable was parked in `deferred`.
    #[tokio::test]
    async fn a_crypto_failure_outranks_an_unreachable_status_list() {
        let (trusted_root_pem, trusted_leaf_cert, trusted_leaf_key) = test_pki();
        let (_, foreign_leaf_cert, foreign_leaf_key) = test_pki();
        let ca_str = String::from_utf8(trusted_root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let trusted_signer =
            FileSigner::from_pem(&trusted_leaf_key, SignatureAlgorithm::Es256).unwrap();
        let foreign_signer =
            FileSigner::from_pem(&foreign_leaf_key, SignatureAlgorithm::Es256).unwrap();

        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // The SD-JWT is declared FIRST and is the one whose status list is
        // unreachable, so its StatusUnavailable is parked before the mdoc's
        // crypto failure is seen. That ordering is what makes this a real
        // precedence test rather than a first-wins test.
        tx.dcql_query = serde_json::json!({
            "credentials": [
                { "id": "sd", "format": "dc+sd-jwt" },
                {
                    "id": "md",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
                }
            ]
        });

        // A `status.status_list` claim makes `check_status` call the resolver,
        // and `MockResolver { token: None }` answers StatusUnavailable.
        let (holder_signer, holder_pub) = holder();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let sd_claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: None,
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: Some(7),
            status_list_uri: Some("https://localhost:8443/statuslists/1".to_string()),
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let sd_issued =
            build_sd_jwt_vc(sd_claims, &trusted_signer, Some(vec![der_b64(&trusted_leaf_cert)]))
                .unwrap();
        let sd = attach_kb_jwt(
            sd_issued,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            None,
        )
        .unwrap();

        let mut elements = std::collections::BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        let mut namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        let mdoc_bytes = build_mdoc(
            MdocClaims {
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                namespaces,
                device_key_jwk: d_jwk_pub,
                signed_at: (now - 100) as i64,
                valid_until: (now + 3600) as i64,
            },
            &foreign_signer,
            Some(vec![der_b64(&foreign_leaf_cert)]),
        )
        .unwrap();
        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {
                "sd": [sd],
                "md": [B64URL.encode(&device_response)],
            }}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .expect_err("both credentials failed, in different ways");

        assert_eq!(
            err.kind(),
            "failed",
            "the crypto failure decides the status, not the unreachable status list: {err}"
        );
        assert!(
            !matches!(err, VerificationError::StatusUnavailable(_)),
            "a 502 would tell the wallet to retry a permanently invalid presentation"
        );

        // Both credentials are still reported, each with its own reason.
        let result = tx.result.as_ref().expect("the result must be persisted");
        assert_eq!(result.credentials.len(), 2);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.check == "status_check" && !c.passed),
            "the parked unavailability is still recorded as a fault: {:?}",
            result.checks
        );
    }
```

- [ ] **Step 4: Run the new tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier one_credentials_bad_chain short_circuits outranks
```

Expected: FAIL — the first two on assertions (`credentials.len()` is 0 today),
the third likely on `err.kind()`.

- [ ] **Step 5: Extract the format-specific stage**

In `crates/foundry-verifier/src/verify.rs`, add this struct immediately above
`verify_one_credential`:

```rust
/// What the format-specific signature stage produces on success.
///
/// Extracted so `verify_one_credential` can convert this stage's `Err` into a
/// failed `CheckResult` in exactly one place, instead of every fallible call
/// inside it having the option of `?`-ing out of the per-credential loop.
struct FormatStage {
    /// This credential's disclosed claims, never merged with another's.
    claims: serde_json::Map<String, Value>,
    /// The verified KB-JWT payload. `None` for `mso_mdoc`, which has no KB-JWT
    /// (OpenID4VP L3144).
    kb_jwt_payload: Option<Value>,
    /// The mdoc `docType`, for DCQL doctype matching only. `None` for SD-JWT VC,
    /// whose queries carry no `doctype_value`.
    doc_type: Option<String>,
}
```

Now move the existing `let doc_type: Option<String> = match selected { .. };`
block out of `verify_one_credential` into a new function directly above it. The
body is the existing `match` arms, unchanged except that each arm returns a
`FormatStage` instead of assigning locals, and `credential_type` is written
through the out-parameter:

```rust
/// Verify one credential's format-specific signature stage.
///
/// `credential_type` is an out-parameter rather than part of the return value on
/// purpose: it is filled as early as each format allows, so it is still
/// populated when this function returns `Err`. A failed credential an operator
/// cannot name is the defect that field exists to fix.
async fn verify_credential_payload(
    ctx: &CredentialVerifyCtx<'_>,
    selected: SelectedPresentation<'_>,
    credential_type: &mut Option<String>,
) -> Result<FormatStage, VerificationError> {
    // ... the existing `match selected { .. }` body, with each arm ending in
    // `Ok(FormatStage { claims, kb_jwt_payload, doc_type })` instead of
    // assigning `disclosed_claims` / `kb_jwt_payload` / returning `Some(..)`.
    // The `checks.push(CheckResult { .. passed: true .. })` calls move OUT of
    // here and into `verify_one_credential`, which is now the only place that
    // records the format check either way.
}
```

Mechanical notes for this move — get them right and the rest follows:

- The SD-JWT arm's `credential_type = asserted_vct_unverified(jwt_str);` from
  Task 1 becomes `*credential_type = asserted_vct_unverified(jwt_str);`.
- The mdoc arm's two `credential_type = Some(..)` from Task 1 likewise become
  `*credential_type = Some(..)`.
- The two `checks.push(CheckResult { check: "sd_jwt_vc_signature_and_kb_jwt" /
  "mdoc_issuer_auth_and_device_signature", passed: true, detail: None })` calls
  are **deleted** here; `verify_one_credential` pushes the check in Step 6.
- The SD-JWT arm's `disclosed_claims.insert(..)` loop writes into a local
  `claims` map that the arm returns.
- The legacy `web-origin:` audience `tracing::warn!` stays exactly where it is,
  inside the SD-JWT arm.
- The `SENSITIVE: candidate mdoc SessionTranscript` `tracing::trace!` block
  stays exactly where it is, **before** `verify_issuer_signed` — a diagnostic
  must not be conditional on the outcome it diagnoses
  (`the_session_transcript_diagnostic_survives_an_issuer_trust_failure` pins
  this).

- [ ] **Step 6: Make `verify_one_credential` unable to `?` out**

Replace `verify_one_credential`'s signature and its opening section:

```rust
/// Verify one credential from a `vp_token` and collect its checks.
///
/// **Returns no `Result`, deliberately.** Root AGENTS.md §4.2 defines `verified`
/// as the conjunction of the checks performed, which is only meaningful when
/// they were all performed, and "PID signature bad, mDL fine" is a far more
/// useful operator verdict than "PID signature bad, mDL unknown". That was
/// already the documented intent; it was not the behaviour, because this
/// function returned `Result` and its caller reached for `?`. The type won the
/// argument with the comment. A non-`Result` return makes the defect
/// unrepresentable rather than merely commented against.
///
/// The accompanying `Option<VerificationError>` is how a failure still reaches
/// the HTTP layer: a bad signature is a structural failure and must stay a 400
/// (root AGENTS.md §4.3), never a policy `200 verified:false`. The caller parks
/// it, finishes the loop, and returns it after every credential has a verdict.
async fn verify_one_credential(
    ctx: &CredentialVerifyCtx<'_>,
    query_id: &str,
    selected: SelectedPresentation<'_>,
    resolver: &dyn StatusListResolver,
) -> (PresentedCredential, Option<VerificationError>) {
    let presented_format = selected.format();
    let format = match presented_format {
        PresentedFormat::SdJwtVc => "dc+sd-jwt",
        PresentedFormat::MsoMdoc => "mso_mdoc",
    };
    // The format's own check name, per root AGENTS.md §4.2's closed
    // per-credential vocabulary. Every failure in the signature stage is
    // recorded under it, with the real reason in `detail`.
    let format_check = match presented_format {
        PresentedFormat::SdJwtVc => "sd_jwt_vc_signature_and_kb_jwt",
        PresentedFormat::MsoMdoc => "mdoc_issuer_auth_and_device_signature",
    };

    let mut checks: Vec<CheckResult> = Vec::new();
    let mut credential_type: Option<String> = None;

    let stage = match verify_credential_payload(ctx, selected, &mut credential_type).await {
        Ok(stage) => {
            checks.push(CheckResult {
                check: format_check.to_string(),
                passed: true,
                detail: None,
            });
            stage
        }
        Err(err) => {
            checks.push(CheckResult {
                check: format_check.to_string(),
                passed: false,
                detail: Some(foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX)),
            });
            // The remaining checks are SKIPPED, not run against empty claims.
            // `dcql_match: false` and `status_check: false` would report three
            // failures where one occurred, two of them misattributed: "DCQL
            // mismatch" when the truth is "we never obtained claims".
            return (
                PresentedCredential {
                    query_id: query_id.to_string(),
                    format: format.to_string(),
                    credential_type,
                    claims: Value::Object(serde_json::Map::new()),
                    checks,
                },
                Some(with_credential_context(query_id, err)),
            );
        }
    };

    let claims_value = Value::Object(stage.claims);
    let kb_jwt_payload = stage.kb_jwt_payload;
    let doc_type = stage.doc_type;
```

Then keep the existing `transaction_data_binding` / `check_dcql_match` /
`check_status` sections **unchanged**, except:

- `check_status`'s `Err(other) => return Err(other)` arm becomes
  `Err(other) => return (credential_of(..), Some(with_credential_context(query_id, other)))`.
  Simplest correct shape: collapse both non-`Ok` arms into one local variable
  and build the credential once at the end:

```rust
    let mut deferred: Option<VerificationError> = None;
    match check_status(&claims_value, ctx.trust_store, resolver, ctx.now_unix).await {
        Ok(check) => checks.push(check),
        // Unavailability is NOT a policy failure -- "I could not determine
        // whether this is revoked" is not "this is revoked" -- so no
        // status_check record is pushed and the fault travels as an error.
        Err(err) => deferred = Some(with_credential_context(query_id, err)),
    }

    let credential = PresentedCredential {
        query_id: query_id.to_string(),
        format: format.to_string(),
        credential_type,
        claims: claims_value,
        checks,
    };

    (credential, deferred)
```

Note this widens the old behaviour slightly and correctly: previously only
`StatusUnavailable` was parked and any other `check_status` error propagated with
`?`. Now every `check_status` error is parked, and the loop's precedence rule
decides. The status code is unaffected — a non-`StatusUnavailable` error from
`check_status` outranks nothing and is returned as itself.

- [ ] **Step 7: Add the credential-context helper**

Add above `check_name_for` in `verify.rs`:

```rust
/// Name the credential query a per-credential error belongs to, without
/// changing the error's kind.
///
/// With N credentials a bare "mdoc verification failed" does not say whose. A
/// DCQL credential query id is operator-authored request structure, not a holder
/// value, so naming it is safe (root AGENTS.md §4.5) -- the status-unavailability
/// path already did exactly this.
///
/// `error.kind` is operator-facing API that operators alert on (§4.5), so a
/// variant is never swapped for a more convenient one. The three
/// `#[error(transparent)]` variants wrap a foreign error whose `Display` is the
/// whole message and have no field to prefix, so they are returned unchanged;
/// the per-credential log record names the credential in those cases.
///
/// Exhaustive with no catch-all, for the same reason `check_name_for` is: a new
/// variant should be a deliberate decision, not a silent fallthrough.
fn with_credential_context(query_id: &str, err: VerificationError) -> VerificationError {
    let prefixed = |detail: String| format!("credential query '{query_id}': {detail}");
    match err {
        VerificationError::Failed(d) => VerificationError::Failed(prefixed(d)),
        VerificationError::StatusUnavailable(d) => {
            VerificationError::StatusUnavailable(prefixed(d))
        }
        VerificationError::Crypto(d) => VerificationError::Crypto(prefixed(d)),
        VerificationError::Dcql(d) => VerificationError::Dcql(prefixed(d)),
        VerificationError::Decryption(d) => VerificationError::Decryption(prefixed(d)),
        VerificationError::Serialization(d) => VerificationError::Serialization(prefixed(d)),
        VerificationError::NotFound(d) => VerificationError::NotFound(prefixed(d)),
        VerificationError::InvalidState(d) => VerificationError::InvalidState(prefixed(d)),
        VerificationError::InvalidRequest(d) => VerificationError::InvalidRequest(prefixed(d)),
        e @ (VerificationError::Storage(_)
        | VerificationError::CoreCrypto(_)
        | VerificationError::Trust(_)) => e,
    }
}
```

- [ ] **Step 8: Fold the loop's errors by precedence**

Replace the loop body in `do_verify_vp_response` (lines ~1084-1101):

```rust
    let mut credentials = Vec::with_capacity(selected.len());
    // The failure that decides the response. Precedence (root AGENTS.md §4.3):
    // a structural/crypto failure (400) outranks a status-list unavailability
    // (502), because a bad signature is deterministic and answering 502 would
    // invite the wallet to retry a presentation that can never succeed. Within
    // one class the incumbent wins, so the first credential in DCQL declaration
    // order is the one reported.
    //
    // Before verify-all this precedence was an accident of `?` short-circuiting
    // rather than a decision.
    let mut deferred: Option<VerificationError> = None;

    for (query_id, payload) in selected {
        let (credential, err) = verify_one_credential(&ctx, &query_id, payload, resolver).await;
        credentials.push(credential);

        if let Some(err) = err {
            let challenger_is_status = matches!(err, VerificationError::StatusUnavailable(_));
            match &deferred {
                None => deferred = Some(err),
                Some(VerificationError::StatusUnavailable(_)) if !challenger_is_status => {
                    deferred = Some(err)
                }
                Some(_) => {}
            }
        }
    }
```

- [ ] **Step 9: Gate the top-level fault record to unavailability**

Replace step 5's block (lines ~1109-1121):

```rust
    // 5. A credential whose status fetch was unavailable pushed NO status_check
    //    record, because unavailability is not a policy failure. On its own that
    //    leaves the conjunction computing `true` and persists `verified: true` on
    //    a transaction that returned 502 -- a lie the admin console would render
    //    faithfully. Record the fault as a check so the verdict stays derived and
    //    honest.
    //
    //    StatusUnavailable ONLY. Every other per-credential failure already has
    //    a per-credential record from `verify_one_credential`, so adding a
    //    top-level one would double-count one fault and inflate `failed_checks`.
    if let Some(ref err) = deferred
        && matches!(err, VerificationError::StatusUnavailable(_))
    {
        checks.push(CheckResult {
            check: check_name_for(err).to_string(),
            passed: false,
            detail: Some(foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX)),
        });
    }
```

- [ ] **Step 10: Correct the two stale comments**

At `verify.rs:1065`, the "Verify-all, never fail-fast" comment is now true — add
one sentence recording that it was not:

```rust
    // 3. Per-credential verification. Verify-all, never fail-fast: root
    //    AGENTS.md §4.2 defines `verified` as the conjunction of the checks
    //    performed, which is only meaningful when they were all performed, and
    //    "PID signature bad, mDL fine" is a far more useful operator verdict
    //    than "PID signature bad, mDL unknown".
    //
    //    This is enforced by `verify_one_credential`'s return type, not by this
    //    comment. It previously returned `Result` and this loop used `?`, so the
    //    comment described an intent the type defeated.
```

At `verify.rs:353`, in `verify_vp_response`'s `Err` arm, replace the
`credentials: Vec::new()` comment:

```rust
                // Genuinely empty, not a convenience. This arm is now reachable
                // only by transaction-level failures -- JWE decryption, a
                // missing `vp_token`, trust-store construction,
                // `select_presentations` -- all of which happen before any
                // credential is examined. A per-credential failure no longer
                // arrives here: it is recorded on its own credential and
                // returned through `deferred`, so its neighbours' verdicts
                // survive.
                credentials: Vec::new(),
```

- [ ] **Step 11: Run the new tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier one_credentials_bad_chain short_circuits outranks
```

Expected: PASS (3 tests).

- [ ] **Step 12: Run the whole verifier suite and fix the regressions this exposes**

```bash
cargo nextest run -p foundry-verifier --no-fail-fast
```

Expect failures in existing tests that assumed fail-fast. For each, decide
deliberately whether the new behaviour is correct and update the assertion —
**never** weaken a test to accommodate a change you have not justified. Known
candidates:

- `the_session_transcript_diagnostic_survives_an_issuer_trust_failure` and its
  payload-off sibling both still expect `Err`, which is unchanged. They should
  pass untouched; if they do not, the precedence fold is wrong.
- Any test asserting `res.credentials.is_empty()` or reading `tx.result` after a
  crypto failure now sees a populated list. That is the intended change.

- [ ] **Step 13: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Quote the summary line.

- [ ] **Step 14: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs
git commit -m "fix(verifier): verify every credential before deciding the verdict

verify_one_credential returned Result and the loop used \`?\`, so the first
credential's failure abandoned the rest -- and the error arm then discarded
the verdicts already computed. A two-credential presentation whose mdoc
failed its trust anchor reported nothing about the SD-JWT VC that had
already passed. The comment above the loop claimed verify-all; the type
said fail-fast, and the type won.

The return type is no longer a Result, so the defect is unrepresentable.
Each credential's failure is recorded as its format check with the real
reason in detail, remaining checks are skipped rather than run against
claims that were never obtained, and the existing deferred mechanism now
carries any per-credential error with explicit crypto-over-unavailable
precedence (root AGENTS.md §4.3). Status codes are unchanged: a bad
signature is still 400, never a policy 200."
```

---

## Task 3: Make the mixed verdict legible in the log

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs` — the logging block in
  `verify_vp_response`'s `Ok` arm (lines ~264-315)
- Modify: `crates/foundry/tests/logging_redaction.rs` — positive control
- Modify: `README.md` — Logging & Observability section (~line 1015)
- Modify: `AGENTS.md` (root) — §4.5 field-name list
- Test: `crates/foundry-verifier/src/verify.rs` (`mod tests`), using the existing
  `FieldCapture` layer (line ~2487)

**Interfaces:**

- Consumes from Task 1: `PresentedCredential.credential_type`.
- Consumes from Task 2: `result.credentials` populated for failed credentials on
  the error path.
- Produces: log field names `credential_type`, `format`, `checks`,
  `checks_passed` on per-credential records, and `credentials_failed` on the
  `vp response not verified` record. No field is renamed.

### Steps

- [ ] **Step 1: Write the failing test for the roll-up records**

Add to `crates/foundry-verifier/src/verify.rs`, inside `mod tests`, after the
Task 2 tests:

```rust
    /// A mixed verdict must be readable without reconstructing it from
    /// per-check lines. One roll-up record per credential, naming the credential,
    /// its format and its asserted type.
    #[tokio::test]
    async fn a_mixed_verdict_emits_one_roll_up_record_per_credential() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = FieldCapture::default();
        let subscriber = tracing_subscriber::Registry::default()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(capture.clone());

        foundry_core::obs::set_sensitive(false);
        let guard = tracing::subscriber::set_default(subscriber);
        let _ = run_unanchored_mdoc_presentation_reporting_result().await;
        drop(guard);

        // The failing credential is named, typed, and counted.
        assert!(
            capture.contains("credential failed"),
            "a failed credential needs its own record"
        );
        assert!(
            capture.contains("credential_type=\"org.iso.18013.5.1.mDL\""),
            "the roll-up must name the credential type"
        );
        assert!(
            capture.contains("checks_passed=0"),
            "the roll-up must carry the passed count"
        );
        assert!(
            capture.contains("format=\"mso_mdoc\""),
            "the roll-up must carry the format"
        );
        // The per-check record still exists and is now typed too -- §4.5 makes
        // these field names operator-facing API, so they are enriched, never
        // replaced.
        assert!(
            capture.contains("check=\"mdoc_issuer_auth_and_device_signature\""),
            "the per-check trail must survive"
        );
        assert!(
            capture.contains("credentials_failed=1"),
            "the verdict record must count failed credentials"
        );
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo nextest run -p foundry-verifier a_mixed_verdict_emits
```

Expected: FAIL — `credential failed`, `credential_type`, `checks_passed`,
`format` and `credentials_failed` are not emitted.

- [ ] **Step 3: Emit the roll-up records**

In `verify_vp_response`'s `Ok` arm, replace the existing
`for credential in &result.credentials { for check in &credential.checks { .. } }`
block with:

```rust
            // One roll-up record per credential, then that credential's
            // per-check trail. The roll-up is the line an operator reads; the
            // per-check records are the drill-down, and §4.5 makes their field
            // names operator-facing API, so they are enriched here and never
            // replaced.
            //
            // A DCQL credential query id is operator-authored request structure
            // and a `vct`/`docType` is a credential type identifier -- neither
            // is a holder value, so both are logged unconditionally, at no
            // sensitivity gate (root AGENTS.md §4.5).
            for credential in &result.credentials {
                let checks_total = credential.checks.len();
                let checks_passed = credential.checks.iter().filter(|c| c.passed).count();
                let credential_type = credential.credential_type.as_deref().unwrap_or("");

                if checks_passed == checks_total {
                    tracing::info!(
                        credential = %credential.query_id,
                        format = %credential.format,
                        credential_type,
                        checks = checks_total,
                        checks_passed,
                        "credential verified"
                    );
                } else {
                    // A per-credential failure is still a correct service
                    // outcome, so `warn` rather than `error` (root AGENTS.md
                    // §4.5). The reason lives on the per-check record below.
                    tracing::warn!(
                        credential = %credential.query_id,
                        format = %credential.format,
                        credential_type,
                        checks = checks_total,
                        checks_passed,
                        "credential failed"
                    );
                }

                for check in &credential.checks {
                    if check.passed {
                        tracing::info!(
                            credential = %credential.query_id,
                            credential_type,
                            check = %check.check,
                            passed = true,
                            "verification check"
                        );
                    } else {
                        tracing::warn!(
                            credential = %credential.query_id,
                            credential_type,
                            check = %check.check,
                            passed = false,
                            detail = %check.detail.as_deref().unwrap_or(""),
                            "verification check failed"
                        );
                    }
                }
            }
```

- [ ] **Step 4: Add `credentials_failed` to the not-verified verdict record**

In the same arm, in the `else` branch of `if result.verified`, add the field.
Only that branch: on a verified response the count is always zero, and a field
that is always zero is noise.

```rust
            } else {
                tracing::warn!(
                    verified = false,
                    // BOTH levels: after multi-credential support most checks are
                    // per-credential, so a top-level-only count under-reports and
                    // would read as zero failures on a failed verification.
                    failed_checks = result.all_checks().filter(|c| !c.passed).count(),
                    credentials_requested,
                    credentials_answered,
                    // A COUNT, never an identifier -- the roll-up records above
                    // name the credentials. This makes "1 of 2 failed" visible
                    // on the verdict line itself.
                    credentials_failed = result
                        .credentials
                        .iter()
                        .filter(|c| c.checks.iter().any(|k| !k.passed))
                        .count(),
                    "vp response not verified"
                );
            }
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cargo nextest run -p foundry-verifier a_mixed_verdict_emits
```

Expected: PASS.

- [ ] **Step 6: Add the redaction positive control**

Read `crates/foundry/tests/logging_redaction.rs` first and follow its existing
harness shape — do not invent a new one. Add a test asserting that
`credential_type` **is** present in captured output for a verification (the
positive control root AGENTS.md §4.5 requires, proving the negative assertions
are not vacuous), and that no disclosed claim value appears alongside it with
`sensitive_payloads` off.

- [ ] **Step 7: Document the new fields in `README.md`**

In the Logging & Observability section, after the existing paragraph beginning
"Because one `vp_token` may answer several DCQL credential queries", add:

```markdown
Each credential also gets one **roll-up record** — `credential verified` at
`INFO`, or `credential failed` at `WARN` — carrying `credential` (the DCQL query
id), `format`, `credential_type` (the `vct` for SD-JWT VC, the `docType` for
mdoc), and the `checks` / `checks_passed` counts. That record is the one to read;
the per-check records above are the drill-down. `credential_type` is the type the
presentation *asserted*, and is authenticated only when that credential's format
check passed — the same caveat that governs its claims.

Because a failure in one credential no longer abandons the others, a mixed
verdict is fully reported: the `vp response not verified` record carries
`credentials_failed` alongside `credentials_requested` and
`credentials_answered`, and every credential appears in the admin API and test
console with its own checks — including the ones that failed.
```

- [ ] **Step 8: Add the field names to root `AGENTS.md` §4.5**

In the "Log field names are operator-facing API" bullet, extend the list:

```markdown
- **Log field names are operator-facing API.** `request_id`, `tx_id`, `route`,
  `method`, `listener`, `http.status`, `latency_ms`, `error.kind`,
  `error.detail`, and on per-credential verification records `credential`,
  `credential_type`, `format`, `check`, `passed`, `checks`, `checks_passed`,
  plus `credentials_requested` / `credentials_answered` / `credentials_failed`
  on the verdict record. Renaming one is a breaking change for whoever is
  watching the logs; update `README.md` too.
```

- [ ] **Step 9: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Quote the summary line.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs \
        crates/foundry/tests/logging_redaction.rs \
        README.md AGENTS.md
git commit -m "feat(verifier): log a per-credential verdict roll-up

Reading a multi-credential verdict meant reconstructing it from per-check
records that named a DCQL query id and nothing else. Each credential now
emits one roll-up record -- credential verified / credential failed --
carrying its format, asserted credential type and check counts, and the
per-check records carry the type too.

Additive only: no existing field is renamed, per root AGENTS.md §4.5.
The verdict record gains credentials_failed, a count and never an
identifier."
```

---

## Task 4: Prove it over HTTP and record the change

**Files:**

- Modify or create: a test in `crates/foundry/tests/` — read
  `crates/foundry/tests/AGENTS.md` first to place it in the file that already
  covers verifier HTTP routes rather than creating a new one
- Modify: `crates/foundry-verifier/AGENTS.md` — Gotchas
- Create: `docs/superpowers/changes/2026-08-19-per-credential-verification-verdicts.md`

**Interfaces:**

- Consumes: everything from Tasks 1-3.
- Produces: no new code interfaces.

### Steps

- [ ] **Step 1: Read the integration-test routing guide**

```bash
cat crates/foundry/tests/AGENTS.md
```

Identify the existing file covering verifier response submission
(`/admin/verification/requests/:id/dc-api-response` or the wallet-facing
`/vp/response/:id`). Add to it; do not create a parallel file.

- [ ] **Step 2: Write the failing integration test**

Assert, over the real HTTP route with a two-credential `vp_token` whose mdoc
chain is untrusted:

1. the response status is **400** (root AGENTS.md §4.3 — unchanged by this work);
2. a follow-up `GET /admin/verification/requests/{id}` returns a transaction
   whose `result.credentials` has **two** entries;
3. the passing credential's checks are all `passed: true`;
4. the failing credential has exactly one check,
   `mdoc_issuer_auth_and_device_signature`, `passed: false`;
5. both entries carry a non-null `credential_type`.

Follow the fixture and harness patterns already in that file. If it has no
two-credential mdoc fixture, port the construction from Task 2 Step 1's test.

- [ ] **Step 3: Run it to verify it fails, then passes**

```bash
cargo nextest run -p foundry <your_test_name>
```

Expected: FAIL before the assertions are satisfiable is not possible here —
Tasks 1-3 are already merged, so this test should **pass immediately**. That is
the point: it pins the HTTP-level contract against regression. If it fails,
something in Tasks 1-3 is wrong at the route boundary — fix that, not the test.

- [ ] **Step 4: Record the gotchas in the crate's `AGENTS.md`**

In `crates/foundry-verifier/AGENTS.md`, under Gotchas:

```markdown
- **`verify_one_credential` returns no `Result`, on purpose.** It returns
  `(PresentedCredential, Option<VerificationError>)` so the per-credential loop
  cannot `?` out of itself. It previously returned `Result` and the loop used
  `?`, which meant the first credential's failure abandoned every credential
  after it — while the comment above the loop claimed verify-all. If you find
  yourself wanting a `Result` here, you are re-introducing that bug.
- **A failed format check short-circuits that credential's remaining checks.**
  No `dcql_match` and no `status_check` are recorded for it. Running them against
  claims that were never obtained would report three failures where one occurred,
  two of them misattributed.
- **Error precedence in the loop is explicit: crypto/structural (400) outranks
  `StatusUnavailable` (502).** A bad signature is deterministic, so a 502 would
  invite the wallet to retry something that can never succeed. Within one class
  the first credential in DCQL declaration order wins. Before verify-all this was
  an accident of `?` short-circuiting.
- **The top-level deferred-fault `CheckResult` is `StatusUnavailable`-only.**
  Every other per-credential failure already has a per-credential record;
  recording both would double-count one fault and inflate `failed_checks`.
- **`verify_vp_response`'s `Err` arm reports no credentials because there are
  none.** It is reachable only by transaction-level failures — JWE decryption, a
  missing `vp_token`, trust-store construction, `select_presentations` — all of
  which precede any credential examination.
```

- [ ] **Step 5: Write the change record**

Create
`docs/superpowers/changes/2026-08-19-per-credential-verification-verdicts.md`
covering: the reported symptom (the operator's log), the two defects found
(fail-fast contradicting its own comment; the error arm discarding computed
verdicts), the three decisions taken and why (log shape, 400-over-502
precedence, uniform attribution to the closed check vocabulary), what changed
per file, and what deliberately did **not** change (HTTP status codes, the §4.2
check-name enumeration, `foundry-mdoc` and `foundry-sd-jwt-vc`). Link the spec.

- [ ] **Step 6: Audit the conformance report**

```bash
grep -n "fail-fast\|per-credential\|verify-all" docs/conformance/openid4vc-conformance.md
```

At the time of writing this returns nothing, so no verdict rows change. If a row
has appeared that cites the old fail-fast behaviour, update it — the report is a
living document (root AGENTS.md §4.4).

- [ ] **Step 7: Run the full gate plus the E2E suite**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

The E2E suite runs once, here at the end of the branch (root AGENTS.md §5.2).
Expected: all pass. Quote both summary lines.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry/tests crates/foundry-verifier/AGENTS.md \
        docs/superpowers/changes/2026-08-19-per-credential-verification-verdicts.md
git commit -m "test(verifier): pin the mixed multi-credential verdict over HTTP

Proves at the route boundary that an untrusted mdoc alongside a valid
SD-JWT VC still answers 400 (root AGENTS.md §4.3) while persisting both
credentials' verdicts, each with its own checks and credential type.

Records the crate gotchas that keep the fix from being undone: the
non-Result per-credential return, the short-circuit, the 400-over-502
precedence, and why the error arm's empty credentials list is honest."
```

---

## Self-Review

**Spec coverage.** Walked each spec section against the tasks:

| Spec section | Task |
| --- | --- |
| §4.1 data model (`credential_type`, both formats, `Option`, wire-additive) | Task 1 Steps 5-8, 12 |
| §4.2 non-`Result` return, short-circuit, precedence fold, step-5 gating, stale comments | Task 2 Steps 5-10 |
| §4.3 log surface (roll-up, enriched per-check, `credentials_failed`) | Task 3 Steps 3-4 |
| §4.4 error message + transparent-variant amendment | Task 2 Step 7 |
| §4.5 admin console | Task 1 Step 11 |
| §5 testing 1-6 | Task 2 Steps 1-3, 12; Task 1 Steps 1-3 |
| §5 testing 7-8 (observability) | Task 3 Steps 1, 6 |
| §5 testing 9 (integration) | Task 4 Step 2 |
| §6 documentation | Task 1 Step 12; Task 3 Steps 7-8; Task 4 Steps 4-6 |

No gaps. §5 item 7 (`instrumentation_hygiene.rs`) needs no change because no
`#[tracing::instrument]` is added; the Global Constraints record the rule in case
an implementer adds one.

**Placeholder scan.** One deliberate prose-shaped step remains: Task 2 Step 5's
extraction of the existing `match selected` body into
`verify_credential_payload`. It is a mechanical move of ~200 existing lines, so
transcribing them here would be a worse instruction than the explicit list of
what changes during the move — which the step provides, item by item. Task 3
Step 6 and Task 4 Steps 2 and 5 point at files whose existing harness shape must
be followed rather than at code to copy, and each names exactly what to assert
or cover. Everything else carries real code.

**Type consistency.** Checked across tasks: `credential_type: Option<String>` is
the field name in Task 1 and the log field name in Task 3; `FormatStage`'s three
members (`claims`, `kb_jwt_payload`, `doc_type`) match their consumption in Task
2 Step 6; `with_credential_context(query_id, err)` has one signature used in two
places (Step 6 and Step 8's fold reads its output only);
`run_unanchored_mdoc_presentation_reporting_result` is defined in Task 2 Step 2
and reused in Task 3 Step 1; `asserted_vct_unverified` is defined in Task 1 Step
6 and tested in Task 1 Step 3. `resp.doc_type()` is an accessor method and
`issuer.doc_type` a public field — both verified against
`crates/foundry-mdoc/src/verifier.rs:127` and `:230`.
