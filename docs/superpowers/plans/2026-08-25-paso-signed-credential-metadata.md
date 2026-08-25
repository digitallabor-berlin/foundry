# PaSO Signed Credential Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let foundry act as a PaSO Attestation Provider: publish signed
credential metadata carrying `transaction_data_types` at a per-configuration
`credential_metadata_uri`, and mint ad-hoc transaction data metadata JWTs on
demand.

**Architecture:** Config-driven. A credential type declaring
`transaction_data_types` becomes a "PaSO credential type"; that alone turns on
a `credential_metadata_uri` in issuer metadata and a new wallet-facing
`GET /credential-metadata/:id` that content-negotiates between plain JSON and
a signed `credential-metadata+jwt`. Both JWTs are minted statelessly per
request from the credential signing key. A shared
`foundry_core::crypto::jws::sign_compact` replaces three existing hand-rolled
compact-JWS builders and hosts the fourth and fifth callers too.

**Tech Stack:** Rust (edition 2024), axum 0.7, serde/serde_json (built **with
`preserve_order`** — see Global Constraints), utoipa, tokio, cargo-nextest.

**Spec:** `docs/superpowers/specs/2026-08-25-paso-signed-credential-metadata-design.md`

## Global Constraints

- **Test runner is `cargo nextest run`. Never `cargo test`.** The gate, run
  before every commit and before marking any task complete (root AGENTS.md
  §5.1), is exactly:

  ```bash
  cargo fmt
  cargo nextest run --workspace --no-fail-fast --status-level fail
  cargo clippy --workspace --all-targets -- -D warnings
  ```

  There is no scoped tier — always the whole workspace. Quote the summary line
  as evidence.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside
  `#[cfg(test)]` (root AGENTS.md §4.1). Return typed errors.
- **Every `#[tracing::instrument]` MUST carry `skip_all`** (root AGENTS.md
  §4.5). Enforced by `crates/foundry/tests/instrumentation_hygiene.rs`.
- **Every typed error produces exactly one log record, emitted inside the
  error mapper in `crates/foundry/src/server.rs`** — never at the call site
  (root AGENTS.md §4.5).
- **Dependency layering is one-directional** (root AGENTS.md §3):
  `foundry-core` → {`foundry-sd-jwt-vc`, `foundry-mdoc`} →
  {`foundry-issuer`, `foundry-verifier`} → `foundry`. `foundry-core` must not
  depend on any other `foundry-*` crate.
- **`serde_json` is built with `preserve_order`.** `Cargo.lock` lists
  `indexmap` as a `serde_json` dependency and `serde_json`'s manifest declares
  `preserve_order = ["indexmap", "std"]`. Therefore `serde_json::Map` is an
  `IndexMap` and **JSON object member order is insertion order** — load-bearing
  for the JOSE headers in Tasks 2 and 3.
- **Endpoint changes must be mirrored in `openapi.json` (admin) and
  `openapi-wallet.json` (wallet)** (root AGENTS.md §6). Regenerate with:

  ```bash
  cargo run -p foundry -- openapi --out openapi.json
  cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
  ```

- **Cite the spec in code comments.** New protocol logic names the governing
  document and section, e.g. `// PaSO Proof Metadata §4 — signed credential
  metadata JWT`.
- **Spec sections this plan relies on** (against the vendored copies from Task
  1): PaSO Core §5.2 (type identifier grammar); PaSO Proof Metadata §2
  (`credential_metadata_uri`, content negotiation), §3 / §3.1 / §3.2
  (`transaction_data_types`, claims metadata, `ui_labels`), §4 (signed
  credential metadata JWT), §5.1 / §5.2 / §5.4 (ad-hoc metadata JWT), §7
  (wallet-side verification), §8 (URI binding).
- **Exact values, verbatim:** default `issuer.paso_metadata.ttl_secs` is
  `86400`; default `issuer.paso_metadata.adhoc_ttl_secs` is `300`. The type
  identifier prefix is `urn:paso:sca:`. The JOSE `typ` values are
  `credential-metadata+jwt` and `adhoc-transaction-metadata+jwt`. The wallet
  route is `GET /credential-metadata/:credential_configuration_id`; the admin
  route is `POST /admin/paso/ad-hoc-metadata`.
- **Existing symbols this plan builds on** (verified present; do not re-derive):
  `foundry_core::crypto::Signer` (`algorithm()`, `sign()`, `public_jwk()`),
  `foundry_core::crypto::FileSigner::{from_pem, from_pem_file}`,
  `foundry_core::crypto::SignatureAlgorithm::as_str`,
  `foundry_core::error::CryptoError::{UnsupportedAlgorithm, Sign}`,
  `foundry_core::error::ConfigError::Validation`,
  `foundry_core::trust::build_x5c(&[Vec<u8>]) -> Result<Vec<String>, TrustError>`,
  `foundry_core::pki::{new_ca, issue_leaf, generate_ec_key}`,
  `Config::credential_signing_key() -> Option<(&str, &KeyEntry)>`,
  `KeyEntry { private_key, x5c: Option<String>, alg }`,
  `foundry_issuer::IssuanceError` (`InvalidRequest`, `Serialization`, `kind()`),
  `crates/foundry/src/server.rs`'s `AppState`, `wallet_router`, `admin_router`,
  `internal_error(op, kind, detail) -> StatusCode`,
  `log_typed_error(surface, kind, detail, status)`,
  `admin_error_response(&IssuanceError) -> (StatusCode, Json<Value>)`,
  and `crates/foundry/src/openapi.rs`'s `AdminApiDoc` / `WalletApiDoc`.

---

### Task 1: Vendor the PaSO specifications

**Files:**

- Create: `docs/specs/paso-core.md`
- Create: `docs/specs/paso-proof-metadata.md`
- Modify: `AGENTS.md` (§4.4 table)

**Interfaces:**

- Consumes: nothing.
- Produces: two vendored spec files every later task cites by section number.
  No code symbols.

**Context:** Root AGENTS.md §4.4 requires that every protocol foundry
implements has its governing text pinned in `docs/specs/`. The PaSO source
repository is `~/dev/eudiw/payments-and-sca-for-openid`; the files are
`docs/specifications/paso-core.md` and
`docs/specifications/proof/paso-proof-metadata.md`. These are the user's own
documents and freely committable, so they are vendored verbatim rather than
stubbed.

- [ ] **Step 1: Capture the pin commit and refuse a dirty source**

```bash
cd ~/dev/eudiw/payments-and-sca-for-openid
git status --short docs/specifications/
git rev-parse --short HEAD
```

Expected: **no output** from `git status --short` and a short commit hash from
`rev-parse`. If `proof/paso-proof-metadata.md` shows as modified, **STOP and
report** — the §5 `x5c`/`kid` amendment must be committed upstream first, or
the vendored copy would record a commit whose content differs from what was
copied.

- [ ] **Step 2: Copy both files with a provenance header**

```bash
cd /Users/senexi/dev/eudiw/foundry
PASO_DIR=~/dev/eudiw/payments-and-sca-for-openid
PIN=$(cd "$PASO_DIR" && git rev-parse --short HEAD)

for pair in "docs/specifications/paso-core.md:docs/specs/paso-core.md" \
            "docs/specifications/proof/paso-proof-metadata.md:docs/specs/paso-proof-metadata.md"; do
  src="${pair%%:*}"; dst="${pair##*:}"
  {
    echo "<!--"
    echo "  VENDORED SPECIFICATION - do not edit in this repository."
    echo "  Source:  payments-and-sca-for-openid, ${src}"
    echo "  Pinned:  ${PIN}"
    echo "  Bumping this pin is a deliberate change (root AGENTS.md 4.4):"
    echo "  update this file, then reconcile the code that cites it."
    echo "-->"
    echo
    cat "$PASO_DIR/$src"
  } > "$dst"
done

head -8 docs/specs/paso-core.md
```

Expected: each file begins with the comment block naming the pin commit,
followed by the spec text.

- [ ] **Step 3: Add the §4.4 table rows**

In `AGENTS.md`, inside the §4.4 table of standards-track specifications, add
these two rows immediately after the
`eu-age-verification-annex-a-av-profile.md` row:

```markdown
| [`paso-core.md`](docs/specs/paso-core.md) | PaSO (Payments and SCA for OpenID) Core — the transaction data model foundry publishes metadata for: the `payload` parameter on an OpenID4VP `transaction_data` entry (§7.1) and the `urn:paso:sca:<domain>:<suffix>:<version>` transaction data type identifier grammar (§5.2) that `Config::validate()` enforces. Vendored verbatim rather than stubbed because it is the repository owner's own document and freely committable. **Scope note:** foundry implements the Attestation Provider role only; PaSO Core's Wallet-side processing (§6, §7.3, §7.4) and the Relying Party and Authorizing Party roles are not implemented |
| [`paso-proof-metadata.md`](docs/specs/paso-proof-metadata.md) | PaSO Proof: Metadata Module — the `credential_metadata_uri` extension to OpenID4VCI Credential Issuer Metadata (§2), the `transaction_data_types` structure with its claims metadata and `ui_labels` (§3), the signed credential metadata JWT `credential-metadata+jwt` (§4), and the ad-hoc `adhoc-transaction-metadata+jwt` (§5). Governs `foundry-issuer`'s `paso_metadata.rs`, the `GET /credential-metadata/:id` route, and `POST /admin/paso/ad-hoc-metadata`. **Unimplemented optional path:** §4/§5.2/§7's `kid`/key-set signing branch — foundry's issuer keys are `x5c`-published and it takes the `x5c` branch only |
```

- [ ] **Step 4: Verify the vendored text is byte-identical below the header**

```bash
cd /Users/senexi/dev/eudiw/foundry
diff <(tail -n +7 docs/specs/paso-core.md) \
     ~/dev/eudiw/payments-and-sca-for-openid/docs/specifications/paso-core.md
diff <(tail -n +7 docs/specs/paso-proof-metadata.md) \
     ~/dev/eudiw/payments-and-sca-for-openid/docs/specifications/proof/paso-proof-metadata.md
```

Expected: no output from either `diff`.

- [ ] **Step 5: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass (this task changes no code).

- [ ] **Step 6: Commit**

```bash
git add docs/specs/paso-core.md docs/specs/paso-proof-metadata.md AGENTS.md
git commit -m "docs(specs): vendor PaSO Core and PaSO Proof Metadata"
```

---

### Task 2: Add `foundry_core::crypto::jws::sign_compact`

**Files:**

- Create: `crates/foundry-core/src/crypto/jws.rs`
- Modify: `crates/foundry-core/src/crypto/mod.rs` (add `pub mod jws;`)

**Interfaces:**

- Consumes: `crate::crypto::Signer`, `crate::error::CryptoError`.
- Produces:

  ```rust
  pub fn sign_compact(
      header: &serde_json::Map<String, serde_json::Value>,
      payload: &serde_json::Value,
      signer: &dyn Signer,
  ) -> Result<String, CryptoError>
  ```

  Tasks 3 and 5 call this.

**Context:** Three call sites hand-roll compact JWS today
(`foundry-sd-jwt-vc/src/builder.rs`, `foundry-core/src/status_list/mod.rs`,
`foundry-verifier/src/request.rs`), each with a private `b64url_json`. This
task adds the shared implementation; Task 3 migrates the callers.

The **caller supplies the complete header**, including `alg` at whatever
position it wants, because `serde_json` preserves insertion order and the three
sites disagree (`alg,typ,x5c` vs `typ,alg,x5c`). `sign_compact` *validates* a
supplied `alg` rather than inserting one — which keeps every migration
byte-identical and also catches a caller that hardcodes an algorithm its signer
does not use.

- [ ] **Step 1: Declare the module**

In `crates/foundry-core/src/crypto/mod.rs`, immediately after the existing
`pub mod jwe;`:

```rust
pub mod jwe;
pub mod jws;
```

- [ ] **Step 2: Write the failing tests**

Create `crates/foundry-core/src/crypto/jws.rs` containing only this test
module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FileSigner, SignatureAlgorithm};
    use crate::pki::generate_ec_key;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    use serde_json::{Map, Value, json};

    fn test_signer() -> FileSigner {
        let key = generate_ec_key().expect("generate key");
        FileSigner::from_pem(key.key_pem.as_bytes(), SignatureAlgorithm::Es256)
            .expect("build signer")
    }

    fn raw_header(jws: &str) -> String {
        let part = jws.split('.').next().expect("header segment");
        String::from_utf8(B64URL.decode(part).expect("b64url header")).expect("utf8")
    }

    /// `preserve_order` is enabled workspace-wide, so JSON object member order
    /// is insertion order. Every byte-identical claim in this module and in the
    /// Task 3 migrations rests on that. If a dependency change ever turns the
    /// feature off, this fails loudly instead of silently reordering signed
    /// JOSE headers.
    #[test]
    fn serde_json_map_preserves_insertion_order() {
        let mut m = Map::new();
        m.insert("zebra".to_string(), json!(1));
        m.insert("alpha".to_string(), json!(2));
        let s = serde_json::to_string(&Value::Object(m)).expect("serialize");
        assert_eq!(
            s, r#"{"zebra":1,"alpha":2}"#,
            "serde_json must be built with preserve_order"
        );
    }

    #[test]
    fn caller_header_order_is_preserved_verbatim() {
        let signer = test_signer();
        let mut header = Map::new();
        header.insert("typ".to_string(), json!("oauth-authz-req+jwt"));
        header.insert("alg".to_string(), json!("ES256"));
        header.insert("x5c".to_string(), json!(["AAAA"]));

        let jws = sign_compact(&header, &json!({"a": 1}), &signer).expect("sign");
        assert_eq!(
            raw_header(&jws),
            r#"{"typ":"oauth-authz-req+jwt","alg":"ES256","x5c":["AAAA"]}"#
        );
    }

    #[test]
    fn alg_is_inserted_first_when_the_caller_omits_it() {
        let signer = test_signer();
        let mut header = Map::new();
        header.insert("typ".to_string(), json!("credential-metadata+jwt"));

        let jws = sign_compact(&header, &json!({}), &signer).expect("sign");
        assert_eq!(
            raw_header(&jws),
            r#"{"alg":"ES256","typ":"credential-metadata+jwt"}"#
        );
    }

    #[test]
    fn a_header_alg_that_disagrees_with_the_signer_is_rejected() {
        let signer = test_signer(); // ES256
        let mut header = Map::new();
        header.insert("alg".to_string(), json!("ES384"));

        let err = sign_compact(&header, &json!({}), &signer).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("ES384"), "should name the header alg: {msg}");
        assert!(msg.contains("ES256"), "should name the signer alg: {msg}");
    }

    #[test]
    fn a_non_string_header_alg_is_rejected() {
        let signer = test_signer();
        let mut header = Map::new();
        header.insert("alg".to_string(), json!(7));

        assert!(sign_compact(&header, &json!({}), &signer).is_err());
    }

    #[test]
    fn output_is_three_b64url_segments_over_the_signing_input() {
        let signer = test_signer();
        let mut header = Map::new();
        header.insert("typ".to_string(), json!("test+jwt"));
        let payload = json!({"iss": "https://issuer.example", "iat": 1});

        let jws = sign_compact(&header, &payload, &signer).expect("sign");
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload_bytes = B64URL.decode(parts[1]).expect("b64url payload");
        let decoded: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
        assert_eq!(decoded, payload);

        let sig = B64URL.decode(parts[2]).expect("b64url signature");
        assert!(!sig.is_empty());
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-core crypto::jws
```

Expected: compilation failure — `cannot find function 'sign_compact' in this scope`.

- [ ] **Step 4: Write the implementation**

Insert above the test module in `crates/foundry-core/src/crypto/jws.rs`:

```rust
//! Compact JWS construction — the single owner of JOSE header assembly and
//! signing-input encoding for every JWT foundry mints.
//!
//! Before this module existed, three call sites hand-rolled the same twenty
//! lines with three private copies of `b64url_json`. Consolidating them puts
//! the `alg`-versus-signing-key agreement in one place: a header claiming
//! `ES256` over a key that is ES384 produces a JWS no verifier can check, and
//! that is the divergence class
//! [`crate::crypto::SignatureAlgorithm::cose_value`] documents as a
//! conformance defect no single crate's tests would catch.
//!
//! ## The caller owns header member order
//!
//! `serde_json` is built with `preserve_order` in this workspace (`Cargo.lock`
//! lists `indexmap` as a `serde_json` dependency; the feature is
//! `preserve_order = ["indexmap", "std"]`), so a JSON object serialises in
//! insertion order and JOSE header member order is observable in the signed
//! bytes. The existing call sites do not agree on it — `foundry-sd-jwt-vc` and
//! the status list emit `alg, typ, x5c`; the verifier's Request Object emits
//! `typ, alg, x5c`. This function therefore imposes no order: the caller
//! passes a complete header, and `alg` is *validated* where the caller placed
//! it. `alg` is inserted (first) only when the caller omitted it entirely, so
//! a new caller cannot forget it.

use crate::crypto::Signer;
use crate::error::CryptoError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::{Map, Value};

/// Build a compact JWS: `b64url(header) "." b64url(payload) "." b64url(sig)`.
///
/// `header` is the **complete** JOSE header. When it carries an `alg` member,
/// that member must be a string equal to the signer's algorithm name, and its
/// position is preserved. When it carries none, `alg` is inserted first.
pub fn sign_compact(
    header: &Map<String, Value>,
    payload: &Value,
    signer: &dyn Signer,
) -> Result<String, CryptoError> {
    let expected = signer.algorithm().as_str();

    let header = match header.get("alg") {
        Some(Value::String(a)) if a == expected => header.clone(),
        Some(other) => {
            return Err(CryptoError::UnsupportedAlgorithm(format!(
                "JOSE header 'alg' is {other}, but the signing key's algorithm is {expected}"
            )));
        }
        None => {
            let mut with_alg = Map::new();
            with_alg.insert("alg".to_string(), Value::String(expected.to_string()));
            for (k, v) in header.clone() {
                with_alg.insert(k, v);
            }
            with_alg
        }
    };

    let header_b64 = b64url_json(&Value::Object(header))?;
    let payload_b64 = b64url_json(payload)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
}

fn b64url_json(value: &Value) -> Result<String, CryptoError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| CryptoError::Sign(format!("JOSE JSON serialization failed: {e}")))?;
    Ok(B64URL.encode(bytes))
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-core crypto::jws
```

Expected: 6 tests pass.

- [ ] **Step 6: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-core/src/crypto/jws.rs crates/foundry-core/src/crypto/mod.rs
git commit -m "feat(core): add crypto::jws::sign_compact, one owner for compact JWS"
```

---

### Task 3: Migrate the three existing JWS call sites onto `sign_compact`

**Files:**

- Modify: `crates/foundry-sd-jwt-vc/src/builder.rs`
- Modify: `crates/foundry-core/src/status_list/mod.rs`
- Modify: `crates/foundry-verifier/src/request.rs`

**Interfaces:**

- Consumes: `foundry_core::crypto::jws::sign_compact` from Task 2.
- Produces: no new public symbols. `build_sd_jwt_vc`, `build_status_list_token`
  and `build_signed_request_object` keep their exact current signatures.

**Context:** A **pure extraction**. Each migrated site must produce
byte-identical output for a fixed key and payload, which is why each header is
rebuilt in its current insertion order. The existing suites are the primary
regression net; Step 1 adds explicit characterization guards.

- [ ] **Step 1: Write the characterization tests**

Add to the existing `#[cfg(test)] mod tests` in
`crates/foundry-core/src/status_list/mod.rs`:

```rust
    /// Pins the exact JOSE header `build_status_list_token` emits. The
    /// migration onto `crypto::jws::sign_compact` must not change these bytes:
    /// `serde_json` preserves insertion order, so a reordered header is a
    /// different signed message.
    #[test]
    fn status_list_token_header_is_alg_then_typ() {
        use crate::crypto::{FileSigner, SignatureAlgorithm};
        use crate::pki::generate_ec_key;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};

        let key = generate_ec_key().expect("generate key");
        let signer = FileSigner::from_pem(key.key_pem.as_bytes(), SignatureAlgorithm::Es256)
            .expect("build signer");
        let list = StatusList::new("TestType", 128, 1);
        let claims = StatusListTokenClaims {
            sub: "https://issuer.example/statuslists/TestType".to_string(),
            iat: 1_700_000_000,
            exp: None,
            ttl: None,
        };

        let jws = build_status_list_token(claims, &list, &signer, None).expect("build");
        let part = jws.split('.').next().expect("header segment");
        let raw = String::from_utf8(B64URL.decode(part).expect("b64url")).expect("utf8");
        assert_eq!(raw, r#"{"alg":"ES256","typ":"statuslist+jwt"}"#);
    }
```

Add to the existing `#[cfg(test)] mod tests` in
`crates/foundry-verifier/src/request.rs`:

```rust
    /// Pins the exact JOSE header `build_signed_request_object` emits. Note the
    /// order is `typ, alg, x5c` — NOT the `alg, typ, x5c` of the status-list
    /// and SD-JWT VC builders. `serde_json` preserves insertion order, so the
    /// difference is real in the signed bytes and the migration onto
    /// `crypto::jws::sign_compact` must preserve it.
    #[tokio::test]
    async fn signed_request_object_header_is_typ_then_alg_then_x5c() {
        let mut config = test_config();
        if let Some(entry) = config.keys.get_mut(&config.verifier.signing_key) {
            entry.x5c = Some(sample_verifier_x5c_path());
        }
        let tx = sample_transaction();

        let jws = build_signed_request_object(&config, &tx).expect("build");
        let part = jws.split('.').next().expect("header segment");
        let raw = String::from_utf8(B64URL.decode(part).expect("b64url")).expect("utf8");
        assert!(
            raw.starts_with(r#"{"typ":"oauth-authz-req+jwt","alg":"ES256","x5c":["#),
            "header order changed: {raw}"
        );
    }
```

> **Implementer note:** `test_config()` and `sample_verifier_x5c_path()` already
> exist in that module (see around lines 651–700). `sample_transaction()` is a
> placeholder for whatever helper the neighbouring `#[tokio::test]` functions
> use to build a `VerificationTransaction` — read
> `test_build_signed_request_object_and_verify_jws` (around line 1016) and reuse
> exactly what it uses. Do not invent a new fixture.

- [ ] **Step 2: Run the characterization tests — they must PASS before any change**

```bash
cargo nextest run -p foundry-core status_list_token_header_is_alg_then_typ
cargo nextest run -p foundry-verifier signed_request_object_header_is_typ_then_alg_then_x5c
```

Expected: **PASS**. These describe the code as it is today, so a failure *after*
the migration proves the migration changed the signed bytes. If either fails
now, the asserted string is wrong — correct the assertion to match reality
before touching any production code.

- [ ] **Step 3: Migrate `foundry-sd-jwt-vc`**

In `crates/foundry-sd-jwt-vc/src/builder.rs`, delete the private helper:

```rust
fn b64url_json(value: &Value) -> Result<String, FormatError> {
    let bytes = serde_json::to_vec(value).map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(B64URL.encode(bytes))
}
```

Replace the signing tail of `build_sd_jwt_vc` — everything from
`let alg = signer.algorithm().as_str();` through
`let signature_b64 = B64URL.encode(signature);` — with:

```rust
    // Header order is `alg, typ, x5c` and must stay that way: `serde_json` is
    // built with `preserve_order`, so a reordered header is a different signed
    // message. `crypto::jws::sign_compact` validates that `alg` matches the
    // signing key rather than imposing a position.
    let mut header = Map::new();
    header.insert(
        "alg".into(),
        Value::String(signer.algorithm().as_str().to_string()),
    );
    // TODO(interop): draft-17 SD-JWT VC media type.
    header.insert("typ".into(), Value::String("dc+sd-jwt".into()));
    if let Some(chain) = x5c {
        header.insert(
            "x5c".into(),
            Value::Array(chain.into_iter().map(Value::String).collect()),
        );
    }

    let jws = foundry_core::crypto::jws::sign_compact(&header, &Value::Object(payload), signer)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
```

Then change the line that assembled the output from

```rust
    let mut output = format!("{signing_input}.{signature_b64}");
```

to

```rust
    let mut output = jws;
```

leaving the disclosure-appending loop and the trailing `~` untouched.

> The old code mapped a serialization failure to `FormatError::Serialization`
> and a signing failure to `FormatError::SignatureVerification`; `sign_compact`
> returns `CryptoError` for both, so both now map to `SignatureVerification`.
> Serializing a `Map<String, Value>` just built from owned values cannot fail
> in practice, so no reachable behaviour changes.

- [ ] **Step 4: Migrate `foundry-core::status_list`**

In `crates/foundry-core/src/status_list/mod.rs`, delete the private
`b64url_json` helper, and replace the tail of `build_status_list_token` — from
`let header_b64 = b64url_json(&Value::Object(header))?;` through the final
`Ok(format!("{signing_input}.{}", B64URL.encode(signature)))` — with:

```rust
    // Header order is `alg, typ, x5c`; see `crate::crypto::jws` for why the
    // position of each member is load-bearing.
    crate::crypto::jws::sign_compact(&header, &Value::Object(payload), signer)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))
```

The `header` and `payload` maps built above it are unchanged. If `B64URL` or
`Engine` imports become unused after this and Step 3, remove them — `-D warnings`
will flag them otherwise.

- [ ] **Step 5: Migrate `foundry-verifier`**

In `crates/foundry-verifier/src/request.rs`, replace the block from
`let header_bytes = serde_json::to_vec(&header_val)` through
`let jws = format!("{signing_input}.{sig_b64}");` with:

```rust
    // Header order is `typ, alg, x5c` — deliberately NOT the `alg, typ, x5c`
    // of the SD-JWT VC and status-list builders. `serde_json` preserves
    // insertion order, so the difference is real in the signed bytes; keep it.
    let header_map = match header_val {
        serde_json::Value::Object(m) => m,
        // Unreachable: `header_val` was constructed as an object immediately
        // above. Typed rather than `unreachable!()` per root AGENTS.md §4.1.
        other => {
            return Err(VerificationError::Serialization(format!(
                "request object header was not an object: {other}"
            )));
        }
    };

    let jws = foundry_core::crypto::jws::sign_compact(&header_map, &payload_val, signer)?;
```

> **On the `?`:** it works only if `VerificationError: From<CryptoError>`. The
> function already does `let sig_bytes = signer.sign(signing_input.as_bytes())?;`
> on a `Result<_, CryptoError>`, so that impl exists. Keep `?`.

The `tracing::debug!` that follows is untouched — it reads `alg` and
`jws.len()`, both still in scope. Note the `debug!` previously came after
`header_val` was consumed; `header_val` is now moved into the `match`, so if
the log statement references it, switch that field to `%header_map_json` only
if such a field already exists — otherwise leave the statement exactly as-is.

- [ ] **Step 6: Re-run the characterization tests — bytes must be unchanged**

```bash
cargo nextest run -p foundry-core status_list_token_header_is_alg_then_typ
cargo nextest run -p foundry-verifier signed_request_object_header_is_typ_then_alg_then_x5c
```

Expected: both still PASS. A failure means the migration changed the signed
bytes — fix the header construction; do **not** adjust the assertion.

- [ ] **Step 7: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. The SD-JWT VC, status-list and verifier suites exercise
these builders end to end (including signature verification against the
produced JWS), so a byte change surfaces here even where no characterization
test was added.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-sd-jwt-vc/src/builder.rs \
        crates/foundry-core/src/status_list/mod.rs \
        crates/foundry-verifier/src/request.rs
git commit -m "refactor: route the three compact-JWS builders through crypto::jws"
```

---

### Task 4: Config surface — `transaction_data_types` and `paso_metadata`

**Files:**

- Modify: `crates/foundry-core/src/config/model.rs`
- Modify: `crates/foundry-core/src/config/mod.rs` (re-exports)
- Modify: `crates/foundry-core/src/config/validate.rs`

**Interfaces:**

- Consumes: `ConfigError::Validation`, `Config::credential_signing_key()`.
- Produces:

  ```rust
  pub struct TransactionDataTypeMetadata {
      pub claims: Vec<serde_json::Value>,
      pub ui_labels: Option<serde_json::Value>,
      pub extra: serde_json::Map<String, serde_json::Value>,
  }
  pub struct PasoMetadataConfig { pub ttl_secs: u64, pub adhoc_ttl_secs: u64 }
  // CredentialType.transaction_data_types:
  //     Option<std::collections::BTreeMap<String, TransactionDataTypeMetadata>>
  // IssuerConfig.paso_metadata: PasoMetadataConfig
  pub fn validate_paso_transaction_data_type_metadata(
      type_id: &str,
      meta: &TransactionDataTypeMetadata,
  ) -> Result<(), String>;
  ```

  Tasks 5–9 consume these. Task 5 and Task 8 both call
  `validate_paso_transaction_data_type_metadata` — it is `pub` precisely so the
  ad-hoc override path is held to exactly the config-time rules.

**Context:** A credential type declaring `transaction_data_types` **is** a PaSO
credential type; absence changes nothing. Validation is startup-fatal so an
operator's typo can never become a wallet-facing failure.

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` in
`crates/foundry-core/src/config/validate.rs`:

```rust
    fn tdt(value: serde_json::Value) -> crate::config::TransactionDataTypeMetadata {
        serde_json::from_value(value).expect("transaction data type fixture must deserialize")
    }

    fn valid_tdt() -> crate::config::TransactionDataTypeMetadata {
        tdt(serde_json::json!({
            "claims": [
                { "path": ["transaction_id"], "mandatory": true },
                {
                    "path": ["amount"],
                    "mandatory": true,
                    "value_type": "iso_currency_amount",
                    "display": [
                        { "locale": "en", "name": "Amount" },
                        { "locale": "de", "name": "Betrag" }
                    ]
                }
            ],
            "ui_labels": {
                "affirmative_action_label": [
                    { "locale": "en", "value": "Confirm Payment" }
                ]
            }
        }))
    }

    #[test]
    fn a_well_formed_transaction_data_type_validates() {
        assert!(
            validate_paso_transaction_data_type_metadata(
                "urn:paso:sca:global:payment:1",
                &valid_tdt()
            )
            .is_ok()
        );
    }

    /// PaSO Core §5.2: the identifier must start with `urn:paso:sca:`.
    #[test]
    fn a_type_identifier_without_the_paso_prefix_is_rejected() {
        let err = validate_paso_transaction_data_type_metadata(
            "urn:example:payment:1",
            &valid_tdt(),
        )
        .expect_err("must reject");
        assert!(err.contains("urn:paso:sca:"), "{err}");
    }

    /// PaSO Core §5.2 as amended: the version segment is a positive integer
    /// without leading zeros, and is the final segment.
    #[test]
    fn the_version_segment_must_be_a_positive_integer_without_leading_zeros() {
        let meta = valid_tdt();

        for bad in [
            "urn:paso:sca:global:payment:v1",
            "urn:paso:sca:global:payment:01",
            "urn:paso:sca:global:payment:0",
            "urn:paso:sca:global:payment",
            "urn:paso:sca:global::1",
        ] {
            assert!(
                validate_paso_transaction_data_type_metadata(bad, &meta).is_err(),
                "expected '{bad}' to be rejected"
            );
        }

        for good in [
            "urn:paso:sca:global:payment:1",
            "urn:paso:sca:com.example:pay:transaction:2",
            "urn:paso:sca:global:payment:10",
        ] {
            assert!(
                validate_paso_transaction_data_type_metadata(good, &meta).is_ok(),
                "expected '{good}' to be accepted"
            );
        }
    }

    /// PaSO Proof Metadata §3.1: "The `value_type` parameter MUST NOT be used
    /// on claims without a `display` array."
    #[test]
    fn value_type_without_display_is_rejected() {
        let meta = tdt(serde_json::json!({
            "claims": [{ "path": ["amount"], "value_type": "iso_currency_amount" }]
        }));
        let err =
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .expect_err("must reject");
        assert!(err.contains("value_type"), "{err}");
    }

    /// PaSO Proof Metadata §3: `claims` is REQUIRED and describes every claim
    /// of the payload — an empty array describes nothing.
    #[test]
    fn an_empty_claims_array_is_rejected() {
        let meta = tdt(serde_json::json!({ "claims": [] }));
        assert!(
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .is_err()
        );
    }

    #[test]
    fn a_claim_without_a_non_empty_string_path_is_rejected() {
        for bad in [
            serde_json::json!({ "claims": [{ "mandatory": true }] }),
            serde_json::json!({ "claims": [{ "path": [] }] }),
            serde_json::json!({ "claims": [{ "path": ["ok", 7] }] }),
        ] {
            let meta = tdt(bad);
            assert!(
                validate_paso_transaction_data_type_metadata(
                    "urn:paso:sca:global:payment:1",
                    &meta
                )
                .is_err()
            );
        }
    }

    /// Two display entries with no `locale` cannot be told apart by the
    /// Wallet's RFC 4647 Lookup (PaSO Core §7.2).
    #[test]
    fn multiple_display_entries_without_locale_are_rejected() {
        let meta = tdt(serde_json::json!({
            "claims": [{
                "path": ["amount"],
                "display": [{ "name": "Amount" }, { "name": "Betrag" }]
            }]
        }));
        assert!(
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .is_err()
        );
    }

    /// A single display entry needs no locale — §3.2 lets an entry without one
    /// serve as the default.
    #[test]
    fn a_single_display_entry_without_locale_is_accepted() {
        let meta = tdt(serde_json::json!({
            "claims": [{ "path": ["amount"], "display": [{ "name": "Amount" }] }]
        }));
        assert!(
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .is_ok()
        );
    }

    /// PaSO Proof Metadata §3.2: each `ui_labels` entry carries a string `value`.
    #[test]
    fn ui_labels_entries_require_a_string_value() {
        let meta = tdt(serde_json::json!({
            "claims": [{ "path": ["a"] }],
            "ui_labels": { "affirmative_action_label": [{ "locale": "en" }] }
        }));
        let err =
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .expect_err("must reject");
        assert!(err.contains("value"), "{err}");
    }

    /// §3 permits additional parameters and obliges the Wallet to ignore
    /// unrecognised ones, so foundry must accept and preserve them.
    #[test]
    fn unrecognised_members_are_preserved_not_rejected() {
        let meta = tdt(serde_json::json!({
            "claims": [{ "path": ["a"] }],
            "risk_signal_profile": "urn:paso:risk:global:default:1"
        }));
        assert!(
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .is_ok()
        );
        assert!(meta.extra.contains_key("risk_signal_profile"));
    }
```

And two `Config`-level tests. These need a `Config` that already passes
`validate()`; read the top of this test module and reuse the helper it already
uses for that (the existing tests in this file construct one). Referred to
below as `valid_config()` — **substitute the real name**:

```rust
    /// PaSO Proof Metadata §4: the metadata JWT carries the issuer's chain in
    /// its `x5c` header, so a PaSO deployment without one cannot mint a
    /// conformant artifact. Fail at boot, not at request time.
    #[test]
    fn a_paso_credential_type_requires_an_x5c_on_the_credential_signing_key() {
        let mut cfg = valid_config();
        if let Some(ct) = cfg.credential_types.first_mut() {
            let mut map = std::collections::BTreeMap::new();
            map.insert("urn:paso:sca:global:payment:1".to_string(), valid_tdt());
            ct.transaction_data_types = Some(map);
        }
        for entry in cfg.keys.values_mut() {
            entry.x5c = None;
        }

        let err = cfg.validate().expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("x5c"), "{msg}");
        assert!(msg.contains("PaSO"), "{msg}");
    }

    /// A credential type with no `transaction_data_types` is not a PaSO type
    /// and imposes no new requirement — existing deployments are unaffected.
    #[test]
    fn a_non_paso_config_does_not_require_an_x5c() {
        let mut cfg = valid_config();
        for entry in cfg.keys.values_mut() {
            entry.x5c = None;
        }
        assert!(cfg.validate().is_ok());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-core config::validate
```

Expected: compilation failure — no `TransactionDataTypeMetadata`, no
`transaction_data_types` field, no
`validate_paso_transaction_data_type_metadata`.

- [ ] **Step 3: Add the config model**

In `crates/foundry-core/src/config/model.rs`, ensure `Serialize` is imported
(`use serde::{Deserialize, Serialize};` — `TransactionDataTypeMetadata` is
serialized into the published metadata document), then add immediately above
`pub struct CredentialType`:

```rust
/// PaSO Proof Metadata §3 — one entry of the `transaction_data_types` object:
/// the machine-readable description of a transaction data payload a PaSO
/// Credential supports, and how a Wallet renders it for consent.
///
/// Typed exactly as deep as foundry validates (`claims`, `ui_labels`) and
/// passthrough below that, the same posture as `CredentialType::display`.
/// `extra` preserves unrecognised members because §3 permits additional
/// parameters and obliges the Wallet to ignore the ones it does not know —
/// dropping them here would silently narrow what an issuer can publish.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransactionDataTypeMetadata {
    /// §3: REQUIRED. Claim metadata objects, validated by
    /// [`crate::config::validate_paso_transaction_data_type_metadata`].
    pub claims: Vec<serde_json::Value>,
    /// §3.2: localised strings for consent UI elements.
    ///
    /// §3 marks this "REQUIRED when the credential is issued to a Wallet that
    /// does not have a dedicated UI for the transaction data type" — a
    /// condition the publisher cannot evaluate, since it serves static
    /// metadata at a URI and never learns the fetching Wallet's capabilities.
    /// foundry therefore treats it as always OPTIONAL and never enforces the
    /// conditional. Recorded as ambiguity #1 in
    /// `docs/superpowers/specs/2026-08-25-paso-signed-credential-metadata-design.md` §10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_labels: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
```

Add the field to `CredentialType`, after `validity_seconds`:

```rust
    /// PaSO Proof Metadata §3 — the transaction data types this credential
    /// supports, keyed by the `urn:paso:sca:<domain>:<suffix>:<version>`
    /// identifier of PaSO Core §5.2.
    ///
    /// **Presence is what makes a credential type a PaSO Credential type.** It
    /// turns on the `credential_metadata_uri` in Issuer Metadata and the
    /// `GET /credential-metadata/:id` route for this configuration. Absent
    /// leaves every byte of existing wire output unchanged.
    #[serde(default)]
    pub transaction_data_types:
        Option<std::collections::BTreeMap<String, TransactionDataTypeMetadata>>,
```

Add the TTL config immediately above `pub struct IssuerConfig`:

```rust
/// PaSO Proof Metadata §4 / §5.2 — the `exp` foundry sets on the two metadata
/// JWT kinds.
///
/// Both JWTs are minted per request, so §4's "rotate signed credential
/// metadata JWTs before their `exp` time" holds by construction; these values
/// only bound how long a Wallet or Relying Party may cache what it received.
#[derive(Debug, Clone, Deserialize)]
pub struct PasoMetadataConfig {
    /// Lifetime of a signed credential metadata JWT (§4).
    #[serde(default = "default_paso_ttl_secs")]
    pub ttl_secs: u64,
    /// Lifetime of an ad-hoc transaction data metadata JWT (§5.2). Shorter by
    /// default: §5.2 asks for "a validity period that bounds how long Relying
    /// Parties can cache and reuse the JWT".
    #[serde(default = "default_paso_adhoc_ttl_secs")]
    pub adhoc_ttl_secs: u64,
}

fn default_paso_ttl_secs() -> u64 {
    86_400
}

fn default_paso_adhoc_ttl_secs() -> u64 {
    300
}

impl Default for PasoMetadataConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_paso_ttl_secs(),
            adhoc_ttl_secs: default_paso_adhoc_ttl_secs(),
        }
    }
}
```

Add the field to `IssuerConfig`, after `offer_by_reference`:

```rust
    /// PaSO Proof Metadata §4 / §5.2 — lifetimes of the metadata JWTs. Absent
    /// uses the defaults; the block is inert for a deployment with no PaSO
    /// credential types.
    #[serde(default)]
    pub paso_metadata: PasoMetadataConfig,
```

In `crates/foundry-core/src/config/mod.rs`, add `TransactionDataTypeMetadata`
and `PasoMetadataConfig` to the `pub use model::{...}` list that already
re-exports `CredentialType`, and add
`pub use validate::validate_paso_transaction_data_type_metadata;` (or extend
the existing `validate` re-export list if one exists).

- [ ] **Step 4: Add the validation**

Append to `crates/foundry-core/src/config/validate.rs`, at module level
(outside `impl Config`):

```rust
/// PaSO Core §5.2 — `urn:paso:sca:<domain>:<suffix>:<version>`.
///
/// `<version>` "SHALL be a positive integer without leading zeros and SHALL be
/// the final segment of the identifier".
fn validate_paso_type_identifier(id: &str) -> Result<(), String> {
    let Some(rest) = id.strip_prefix("urn:paso:sca:") else {
        return Err(format!(
            "transaction data type '{id}' must start with 'urn:paso:sca:' (PaSO Core §5.2)"
        ));
    };
    let segments: Vec<&str> = rest.split(':').collect();
    // <domain>, at least one <suffix> segment, <version>.
    if segments.len() < 3 {
        return Err(format!(
            "transaction data type '{id}' must have the form \
             urn:paso:sca:<domain>:<suffix>:<version> (PaSO Core §5.2)"
        ));
    }
    if segments.iter().any(|s| s.is_empty()) {
        return Err(format!(
            "transaction data type '{id}' contains an empty segment (PaSO Core §5.2)"
        ));
    }
    let version = segments[segments.len() - 1];
    if !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "transaction data type '{id}': version segment '{version}' must be an integer \
             (PaSO Core §5.2)"
        ));
    }
    if version.starts_with('0') {
        return Err(format!(
            "transaction data type '{id}': version segment '{version}' must be a positive \
             integer without leading zeros (PaSO Core §5.2)"
        ));
    }
    Ok(())
}

/// PaSO Proof Metadata §3, §3.1, §3.2 — structural validation of one
/// `transaction_data_types` entry.
///
/// Public because two channels publish this shape and both must be held to the
/// same rules: `Config::validate()` at startup, and the admin ad-hoc mint
/// endpoint, which accepts an inline metadata override. A channel that
/// accepted shapes the other rejects would make validation advisory.
pub fn validate_paso_transaction_data_type_metadata(
    type_id: &str,
    meta: &crate::config::TransactionDataTypeMetadata,
) -> Result<(), String> {
    validate_paso_type_identifier(type_id)?;

    // §3: `claims` is REQUIRED, and §3.1 requires metadata "for each claim of
    // the transaction data payload" — an empty array describes nothing.
    if meta.claims.is_empty() {
        return Err(format!(
            "transaction data type '{type_id}': 'claims' must not be empty \
             (PaSO Proof Metadata §3)"
        ));
    }

    for (i, claim) in meta.claims.iter().enumerate() {
        let Some(obj) = claim.as_object() else {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] must be an object"
            ));
        };

        // §3.1: `path` resolves against the transaction_data `payload` object;
        // OpenID4VCI's claims description object makes it REQUIRED.
        let Some(path) = obj.get("path").and_then(|v| v.as_array()) else {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] requires a 'path' array \
                 (PaSO Proof Metadata §3.1)"
            ));
        };
        if path.is_empty() {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] 'path' must not be empty"
            ));
        }
        if !path.iter().all(|p| p.is_string()) {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] 'path' must contain only strings"
            ));
        }

        let display = obj.get("display").and_then(|v| v.as_array());

        // §3.1: "The `value_type` parameter MUST NOT be used on claims without
        // a `display` array."
        if obj.contains_key("value_type") && display.is_none() {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] sets 'value_type' but has no \
                 'display' array (PaSO Proof Metadata §3.1)"
            ));
        }

        if let Some(entries) = display {
            if entries.is_empty() {
                return Err(format!(
                    "transaction data type '{type_id}': claims[{i}] 'display' must not be empty"
                ));
            }
            let needs_locale = entries.len() > 1;
            for (j, entry) in entries.iter().enumerate() {
                let Some(eo) = entry.as_object() else {
                    return Err(format!(
                        "transaction data type '{type_id}': claims[{i}].display[{j}] must be an \
                         object"
                    ));
                };
                if !eo.get("name").map(|n| n.is_string()).unwrap_or(false) {
                    return Err(format!(
                        "transaction data type '{type_id}': claims[{i}].display[{j}] requires a \
                         string 'name'"
                    ));
                }
                // Two entries with no locale cannot be told apart by the
                // Wallet's RFC 4647 Lookup (PaSO Core §7.2).
                if needs_locale && !eo.contains_key("locale") {
                    return Err(format!(
                        "transaction data type '{type_id}': claims[{i}].display[{j}] requires a \
                         'locale' when the claim has more than one display entry"
                    ));
                }
            }
        }
    }

    // §3.2: each value is an array of {locale?, value, value_type?}.
    if let Some(ui) = &meta.ui_labels {
        let Some(obj) = ui.as_object() else {
            return Err(format!(
                "transaction data type '{type_id}': 'ui_labels' must be an object \
                 (PaSO Proof Metadata §3.2)"
            ));
        };
        for (key, val) in obj {
            let Some(arr) = val.as_array() else {
                return Err(format!(
                    "transaction data type '{type_id}': ui_labels['{key}'] must be an array \
                     (PaSO Proof Metadata §3.2)"
                ));
            };
            if arr.is_empty() {
                return Err(format!(
                    "transaction data type '{type_id}': ui_labels['{key}'] must not be empty"
                ));
            }
            for (j, entry) in arr.iter().enumerate() {
                let Some(eo) = entry.as_object() else {
                    return Err(format!(
                        "transaction data type '{type_id}': ui_labels['{key}'][{j}] must be an \
                         object"
                    ));
                };
                if !eo.get("value").map(|v| v.is_string()).unwrap_or(false) {
                    return Err(format!(
                        "transaction data type '{type_id}': ui_labels['{key}'][{j}] requires a \
                         string 'value' (PaSO Proof Metadata §3.2)"
                    ));
                }
                if let Some(l) = eo.get("locale")
                    && !l.is_string()
                {
                    return Err(format!(
                        "transaction data type '{type_id}': ui_labels['{key}'][{j}] 'locale' must \
                         be a string"
                    ));
                }
                if let Some(v) = eo.get("value_type")
                    && !v.is_string()
                {
                    return Err(format!(
                        "transaction data type '{type_id}': ui_labels['{key}'][{j}] 'value_type' \
                         must be a string"
                    ));
                }
            }
        }
    }

    Ok(())
}
```

Wire it into `Config::validate()`. Inside the existing
`for ct in &self.credential_types { ... }` loop, after the format `match`
block:

```rust
            // PaSO Proof Metadata §3 — validate every declared transaction data
            // type at startup, so an operator's typo is a boot failure rather
            // than a wallet-facing one.
            if let Some(types) = &ct.transaction_data_types {
                if types.is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}': 'transaction_data_types' must not be empty; omit \
                         the key entirely for a non-PaSO credential type",
                        ct.id
                    )));
                }
                for (type_id, meta) in types {
                    validate_paso_transaction_data_type_metadata(type_id, meta).map_err(|e| {
                        ConfigError::Validation(format!("credential_type '{}': {e}", ct.id))
                    })?;
                }
            }
```

And after that loop closes, add the signing-key requirement:

```rust
        // PaSO Proof Metadata §4 — the signed credential metadata JWT carries
        // the Attestation Provider's certificate chain in its `x5c` JOSE
        // header, and §7 step 6 binds that chain to the credential's own. A
        // deployment with PaSO credential types but no chain on the credential
        // signing key cannot mint a conformant JWT at all, so this is fatal at
        // startup rather than a 500 at request time.
        //
        // foundry implements the `x5c` branch only; §4's `kid`/key-set
        // alternative is a documented unimplemented optional path.
        if self
            .credential_types
            .iter()
            .any(|ct| ct.transaction_data_types.is_some())
        {
            match self.credential_signing_key() {
                None => {
                    return Err(ConfigError::Validation(
                        "a PaSO credential type is configured (transaction_data_types) but no \
                         credential signing key resolves; PaSO Proof Metadata §4 requires one"
                            .to_string(),
                    ));
                }
                Some((name, entry)) if entry.x5c.is_none() => {
                    return Err(ConfigError::Validation(format!(
                        "a PaSO credential type is configured (transaction_data_types) but the \
                         credential signing key '{name}' has no 'x5c' certificate chain; PaSO \
                         Proof Metadata §4 requires one in the metadata JWT header"
                    )));
                }
                Some(_) => {}
            }
        }
```

- [ ] **Step 5: Fix every literal `CredentialType` construction**

The new field is `#[serde(default)]`, so YAML is unaffected, but struct
literals in tests are not. Find and fix them:

```bash
cargo nextest run --workspace --no-fail-fast 2>&1 | grep -c "missing field" || true
rg -n "CredentialType \{" --glob '!target' crates/
```

Add `transaction_data_types: None,` to each literal that does not set it.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-core config
```

Expected: all new tests pass; all existing config tests still pass.

- [ ] **Step 7: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-core/src/config/ crates/
git commit -m "feat(core): PaSO transaction_data_types config surface and validation"
```

---

### Task 5: `foundry-issuer::paso_metadata` — the two JWT builders

**Files:**

- Create: `crates/foundry-issuer/src/paso_metadata.rs`
- Modify: `crates/foundry-issuer/src/lib.rs` (declare + re-export)
- Modify: `crates/foundry-issuer/src/metadata.rs` (extract `claims_description_objects`; expose the test config helper)
- Modify: `crates/foundry-issuer/Cargo.toml` (add `tempfile` as a dev-dependency if absent)

**Interfaces:**

- Consumes: Task 2's `foundry_core::crypto::jws::sign_compact`; Task 4's
  `CredentialType::transaction_data_types`, `PasoMetadataConfig`,
  `validate_paso_transaction_data_type_metadata`.
- Produces:

  ```rust
  pub const CREDENTIAL_METADATA_TYP: &str = "credential-metadata+jwt";
  pub const ADHOC_METADATA_TYP: &str = "adhoc-transaction-metadata+jwt";
  pub fn is_paso_credential_type(ct: &CredentialType) -> bool;
  pub fn credential_metadata_uri(cfg: &Config, credential_type_id: &str) -> String;
  pub fn build_credential_metadata_document(ct: &CredentialType) -> Result<serde_json::Value, IssuanceError>;
  pub fn build_credential_metadata_jwt(cfg: &Config, ct: &CredentialType, now_unix: i64) -> Result<String, IssuanceError>;
  pub fn build_adhoc_metadata_jwt(cfg: &Config, ct: &CredentialType, transaction_data_type: &str, override_metadata: Option<serde_json::Value>, now_unix: i64, ttl_secs: Option<u64>) -> Result<String, IssuanceError>;
  pub(crate) fn claims_description_objects(ct: &CredentialType) -> Vec<serde_json::Value>; // in metadata.rs
  ```

  Tasks 6–9 consume these.

**Design refinement:** the design doc sketched these builders taking
`signer: &dyn Signer, x5c_chain: &[String]`. They instead take `&Config` and
resolve the signer internally, exactly as
`credential.rs::handle_credential_request` does — so the HTTP layer never
touches key material and the resolution idiom stays in one crate.

- [ ] **Step 1: Extract the claims builder in `metadata.rs`**

The `credential_metadata` document served at `credential_metadata_uri` must
carry the *same* `claims` array that `build_issuer_metadata` nests, or the two
published descriptions of one credential type disagree.

In `crates/foundry-issuer/src/metadata.rs`, lift the
`let claims: Vec<serde_json::Value> = ct.claims.iter().map(...).collect();`
block out of `build_issuer_metadata` into a crate-visible function placed
immediately above it, **moving its existing comment blocks verbatim** (the
"OpenID4VCI L2321-L2338 ... Built as a map rather than with `json!` ..." and
"`selectively_disclosable` was never an OpenID4VCI parameter ..." paragraphs,
and the inline `L2323` / `L2326` / `L2332` comments):

```rust
/// OpenID4VCI L2321-L2338 — the claims description objects for one Credential
/// Configuration.
///
/// Extracted so the PaSO `credential_metadata` document (PaSO Proof Metadata
/// §3), served from a different endpoint, cannot describe the same credential
/// type differently from Issuer Metadata.
///
/// [move the two existing explanatory comment paragraphs here verbatim]
pub(crate) fn claims_description_objects(ct: &CredentialType) -> Vec<serde_json::Value> {
    ct.claims
        .iter()
        .map(|c| {
            let mut claim = serde_json::Map::new();
            // L2323: REQUIRED.
            claim.insert("path".to_string(), serde_json::json!(c.path));
            // [move the existing `mandatory` comment here verbatim]
            claim.insert("mandatory".to_string(), serde_json::json!(c.is_required()));
            // L2332: "A non-empty array of objects" -- omitted when empty.
            if !c.display.is_empty() {
                claim.insert("display".to_string(), serde_json::json!(c.display));
            }
            serde_json::Value::Object(claim)
        })
        .collect()
}
```

and replace the inline block inside `build_issuer_metadata` with:

```rust
        let claims = claims_description_objects(ct);
```

Also make `metadata.rs`'s test `Config` builder reusable from the new module's
tests: change its `#[cfg(test)] mod tests`'s `fn test_config() -> Config` to
`pub(crate) fn test_config() -> Config` and, if the enclosing module is
private, change `mod tests` to `pub(crate) mod tests`. One fixture, no drift.

- [ ] **Step 2: Write the failing tests**

Create `crates/foundry-issuer/src/paso_metadata.rs` with only this test module
for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    use serde_json::{Value, json};

    /// A `Config` with a real ES256 signing key and an `x5c` chain on disk.
    fn paso_config() -> Config {
        let mut cfg = crate::metadata::tests::test_config();

        let ca = foundry_core::pki::new_ca("Foundry Test Issuer Root", 3650).expect("ca");
        let leaf = foundry_core::pki::issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "issuer.example.com",
            &["issuer.example.com".to_string()],
            365,
        )
        .expect("leaf");

        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("issuer.pem");
        let chain_path = dir.path().join("issuer-chain.pem");
        std::fs::write(&key_path, leaf.key_pem.as_bytes()).expect("write key");
        std::fs::write(&chain_path, leaf.cert_pem.as_bytes()).expect("write chain");
        std::mem::forget(dir);

        cfg.keys.insert(
            "issuer_key".to_string(),
            foundry_core::config::KeyEntry {
                private_key: key_path.to_string_lossy().to_string(),
                x5c: Some(chain_path.to_string_lossy().to_string()),
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer.status_list.signing_key = Some("issuer_key".to_string());
        cfg
    }

    fn paso_credential_type() -> CredentialType {
        let types = serde_json::from_value(json!({
            "urn:paso:sca:global:payment:1": {
                "claims": [
                    { "path": ["transaction_id"], "mandatory": true },
                    {
                        "path": ["amount"],
                        "mandatory": true,
                        "value_type": "iso_currency_amount",
                        "display": [
                            { "locale": "en", "name": "Amount" },
                            { "locale": "de", "name": "Betrag" }
                        ]
                    }
                ],
                "ui_labels": {
                    "affirmative_action_label": [
                        { "locale": "en", "value": "Confirm Payment" }
                    ]
                }
            }
        }))
        .expect("transaction_data_types fixture");

        CredentialType {
            id: "BankPaymentCard".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://bank.example/sca/card".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: Vec::new(),
            claims: Vec::new(),
            validity_seconds: None,
            transaction_data_types: Some(types),
        }
    }

    fn decode_part(jwt: &str, index: usize) -> Value {
        let part = jwt.split('.').nth(index).expect("segment");
        serde_json::from_slice(&B64URL.decode(part).expect("b64url")).expect("json")
    }

    #[test]
    fn a_type_declaring_transaction_data_types_is_a_paso_type() {
        assert!(is_paso_credential_type(&paso_credential_type()));

        let mut plain = paso_credential_type();
        plain.transaction_data_types = None;
        assert!(!is_paso_credential_type(&plain));
    }

    /// PaSO Proof Metadata §8 makes the `credential_metadata_uri` claim
    /// load-bearing: the Wallet checks it against the URI it fetched from. It
    /// must therefore use the same base as every sibling issuer endpoint.
    #[test]
    fn the_metadata_uri_uses_the_credential_issuer_base() {
        let cfg = paso_config();
        assert_eq!(
            credential_metadata_uri(&cfg, "BankPaymentCard"),
            "https://issuer.example.com/credential-metadata/BankPaymentCard"
        );
    }

    /// PaSO Proof Metadata §4 — header and every REQUIRED payload claim.
    #[test]
    fn the_credential_metadata_jwt_carries_the_required_claims() {
        let cfg = paso_config();
        let ct = paso_credential_type();
        let now = 1_710_000_000;

        let jwt = build_credential_metadata_jwt(&cfg, &ct, now).expect("build");

        let header = decode_part(&jwt, 0);
        assert_eq!(header["typ"], json!(CREDENTIAL_METADATA_TYP));
        assert_eq!(header["alg"], json!("ES256"));
        assert!(
            header["x5c"].as_array().is_some_and(|c| !c.is_empty()),
            "§4: x5c is REQUIRED when the issuer keys are x5c-published"
        );
        assert!(
            header.get("kid").is_none(),
            "§4: when x5c is used, kid SHALL NOT be"
        );

        let payload = decode_part(&jwt, 1);
        assert_eq!(payload["iss"], json!("https://issuer.example.com"));
        assert_eq!(payload["sub"], json!("https://bank.example/sca/card"));
        assert_eq!(payload["format"], json!("dc+sd-jwt"));
        assert_eq!(payload["iat"], json!(now));
        assert_eq!(payload["exp"], json!(now + 86_400));
        assert_eq!(
            payload["credential_metadata_uri"],
            json!("https://issuer.example.com/credential-metadata/BankPaymentCard")
        );
        assert!(
            payload["credential_metadata"]["transaction_data_types"]
                ["urn:paso:sca:global:payment:1"]["claims"]
                .is_array()
        );
    }

    /// §2 serves the bare object; §4 nests the same object under
    /// `credential_metadata`. They can never disagree.
    #[test]
    fn the_json_document_and_the_jwt_claim_are_identical() {
        let cfg = paso_config();
        let ct = paso_credential_type();

        let doc = build_credential_metadata_document(&ct).expect("document");
        let jwt = build_credential_metadata_jwt(&cfg, &ct, 1_710_000_000).expect("build");

        assert_eq!(decode_part(&jwt, 1)["credential_metadata"], doc);
    }

    /// §4 / §7 step 6: `sub` is `vct` for SD-JWT VC, `docType` for mdoc.
    #[test]
    fn an_mdoc_paso_type_uses_doctype_as_sub() {
        let cfg = paso_config();
        let mut ct = paso_credential_type();
        ct.format = "mso_mdoc".to_string();
        ct.vct = None;
        ct.doctype = Some("com.example.bank.paymentcard.1".to_string());

        let payload = decode_part(
            &build_credential_metadata_jwt(&cfg, &ct, 1_710_000_000).expect("build"),
            1,
        );
        assert_eq!(payload["sub"], json!("com.example.bank.paymentcard.1"));
        assert_eq!(payload["format"], json!("mso_mdoc"));
    }

    /// The configured TTL drives `exp`.
    #[test]
    fn the_configured_ttl_drives_the_credential_metadata_exp() {
        let mut cfg = paso_config();
        cfg.issuer.paso_metadata.ttl_secs = 3_600;
        let ct = paso_credential_type();
        let now = 1_710_000_000;

        let payload = decode_part(&build_credential_metadata_jwt(&cfg, &ct, now).expect("build"), 1);
        assert_eq!(payload["exp"], json!(now + 3_600));
    }

    /// PaSO Proof Metadata §5.2 — the ad-hoc JWT's own shape.
    #[test]
    fn the_adhoc_jwt_carries_the_configured_metadata_by_default() {
        let cfg = paso_config();
        let ct = paso_credential_type();
        let now = 1_710_000_000;

        let jwt =
            build_adhoc_metadata_jwt(&cfg, &ct, "urn:paso:sca:global:payment:1", None, now, None)
                .expect("build");

        assert_eq!(decode_part(&jwt, 0)["typ"], json!(ADHOC_METADATA_TYP));

        let payload = decode_part(&jwt, 1);
        assert_eq!(
            payload["transaction_data_type"],
            json!("urn:paso:sca:global:payment:1")
        );
        assert_eq!(payload["exp"], json!(now + 300));
        assert_eq!(payload["sub"], json!("https://bank.example/sca/card"));
        // `metadata` is a single `transaction_data_types` entry value, not the
        // whole map.
        assert!(payload["metadata"]["claims"].is_array());
        assert!(payload["metadata"]["ui_labels"].is_object());
        assert!(payload["metadata"]["urn:paso:sca:global:payment:1"].is_null());
    }

    /// §5.4: a valid ad-hoc JWT makes the type "considered supported ... even
    /// if it is absent from the signed credential metadata". An override for an
    /// unconfigured type is therefore legitimate, not an error.
    #[test]
    fn an_override_may_introduce_a_type_absent_from_config() {
        let cfg = paso_config();
        let ct = paso_credential_type();
        let override_meta = json!({
            "claims": [{ "path": ["reward_points"], "display": [{ "name": "Points" }] }]
        });

        let jwt = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:paso:sca:com.example.pay:transaction:2",
            Some(override_meta.clone()),
            1_710_000_000,
            None,
        )
        .expect("build");

        let payload = decode_part(&jwt, 1);
        assert_eq!(
            payload["transaction_data_type"],
            json!("urn:paso:sca:com.example.pay:transaction:2")
        );
        assert_eq!(payload["metadata"], override_meta);
    }

    #[test]
    fn an_unconfigured_type_without_an_override_is_rejected() {
        let cfg = paso_config();
        let ct = paso_credential_type();

        let err = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:paso:sca:global:unknown:1",
            None,
            1_710_000_000,
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// An override is held to exactly the config-time rules — here §3.1's
    /// "`value_type` MUST NOT be used on claims without a `display` array".
    #[test]
    fn a_structurally_invalid_override_is_rejected() {
        let cfg = paso_config();
        let ct = paso_credential_type();

        let err = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:paso:sca:global:payment:1",
            Some(json!({
                "claims": [{ "path": ["amount"], "value_type": "iso_currency_amount" }]
            })),
            1_710_000_000,
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// An override naming a type identifier that violates PaSO Core §5.2 is
    /// rejected too — the identifier is validated, not just the body.
    #[test]
    fn an_override_with_a_malformed_type_identifier_is_rejected() {
        let cfg = paso_config();
        let ct = paso_credential_type();

        let err = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:example:not-paso:1",
            Some(json!({ "claims": [{ "path": ["a"] }] })),
            1_710_000_000,
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    #[test]
    fn an_explicit_ttl_overrides_the_configured_default() {
        let cfg = paso_config();
        let ct = paso_credential_type();
        let now = 1_710_000_000;

        let jwt = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:paso:sca:global:payment:1",
            None,
            now,
            Some(60),
        )
        .expect("build");
        assert_eq!(decode_part(&jwt, 1)["exp"], json!(now + 60));
    }

    /// A credential type with no PaSO types still produces a well-formed
    /// document — it simply carries no `transaction_data_types`. (The route in
    /// Task 7 never serves this case, but the builder must not panic on it.)
    #[test]
    fn a_non_paso_type_yields_a_document_without_transaction_data_types() {
        let mut ct = paso_credential_type();
        ct.transaction_data_types = None;

        let doc = build_credential_metadata_document(&ct).expect("document");
        assert!(doc.get("transaction_data_types").is_none());
    }
}
```

In `crates/foundry-issuer/src/lib.rs` add the module and its re-exports
alongside the existing ones:

```rust
pub mod paso_metadata;
pub use paso_metadata::{
    ADHOC_METADATA_TYP, CREDENTIAL_METADATA_TYP, build_adhoc_metadata_jwt,
    build_credential_metadata_document, build_credential_metadata_jwt, credential_metadata_uri,
    is_paso_credential_type,
};
```

(Match the file's existing style — if it declares modules as `mod x;` with
`pub use x::...`, follow that instead.)

Ensure `tempfile` is in `[dev-dependencies]` of
`crates/foundry-issuer/Cargo.toml`; it is already a dev-dependency of
`foundry-verifier`, so copy that line verbatim.

- [ ] **Step 3: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-issuer paso_metadata
```

Expected: compilation failure — the functions do not exist.

- [ ] **Step 4: Write the implementation**

Insert above the test module in `crates/foundry-issuer/src/paso_metadata.rs`:

```rust
//! PaSO Proof Metadata — the Attestation Provider's published metadata.
//!
//! Two artifacts, both minted per request and never stored:
//!
//! * the **signed credential metadata JWT** (§4, `credential-metadata+jwt`),
//!   served from `credential_metadata_uri`, carrying the credential's
//!   `transaction_data_types`;
//! * the **ad-hoc transaction data metadata JWT** (§5.2,
//!   `adhoc-transaction-metadata+jwt`), minted on an operator's request for a
//!   Relying Party to embed in a `transaction_data` entry's `metadata`
//!   parameter (§5.1).
//!
//! Statelessness is deliberate. §4 requires the Attestation Provider to
//! "rotate signed credential metadata JWTs before their `exp` time"; minting
//! per request satisfies that by construction, with no cache to expire and no
//! rotation task to fail. It matches how every other issuer-minted artifact in
//! this crate works (`challenge.rs`).
//!
//! **Unimplemented optional path:** §4 and §5.2 allow the signing key to be
//! identified by `kid` against a published issuer key set instead of `x5c`.
//! foundry's issuer keys are x5c-published, so it takes the `x5c` branch only,
//! and `Config::validate()` refuses to boot a PaSO deployment whose credential
//! signing key has no chain.

use crate::error::IssuanceError;
use foundry_core::config::{Config, CredentialType, TransactionDataTypeMetadata};
use foundry_core::crypto::FileSigner;
use serde_json::{Map, Value};

/// PaSO Proof Metadata §4 — `typ` of the signed credential metadata JWT.
pub const CREDENTIAL_METADATA_TYP: &str = "credential-metadata+jwt";
/// PaSO Proof Metadata §5.2 — `typ` of the ad-hoc metadata JWT.
pub const ADHOC_METADATA_TYP: &str = "adhoc-transaction-metadata+jwt";

/// A credential type is a PaSO Credential type exactly when it declares
/// `transaction_data_types` (PaSO Proof Metadata §3).
pub fn is_paso_credential_type(ct: &CredentialType) -> bool {
    ct.transaction_data_types.is_some()
}

/// PaSO Proof Metadata §2 — the URL serving this configuration's credential
/// metadata.
///
/// Built from `issuer.credential_issuer`, the same base `build_issuer_metadata`
/// uses for `credential_endpoint` and `nonce_endpoint`. §8 makes the value
/// load-bearing: the Wallet compares the `credential_metadata_uri` claim
/// against the URI it fetched from and rejects a mismatch. This function is the
/// single owner of the string, so the advertised value and the JWT claim cannot
/// drift apart.
pub fn credential_metadata_uri(cfg: &Config, credential_type_id: &str) -> String {
    let base = cfg.issuer.credential_issuer.trim_end_matches('/');
    format!("{base}/credential-metadata/{credential_type_id}")
}

/// The credential type identifier a Wallet binds `sub` against (PaSO Proof
/// Metadata §4, §7 step 6): `vct` for SD-JWT VC, `docType` for mdoc.
///
/// `Config::validate()` already guarantees the relevant field is present for
/// each supported format, so these error arms are unreachable in a booted
/// process — typed rather than `unwrap` per root AGENTS.md §4.1.
fn credential_type_identifier(ct: &CredentialType) -> Result<&str, IssuanceError> {
    match ct.format.as_str() {
        "dc+sd-jwt" => ct.vct.as_deref().ok_or_else(|| {
            IssuanceError::InvalidRequest(format!(
                "credential type '{}' (dc+sd-jwt) has no vct",
                ct.id
            ))
        }),
        "mso_mdoc" => ct.doctype.as_deref().ok_or_else(|| {
            IssuanceError::InvalidRequest(format!(
                "credential type '{}' (mso_mdoc) has no doctype",
                ct.id
            ))
        }),
        other => Err(IssuanceError::InvalidRequest(format!(
            "credential type '{}' has unsupported format '{other}'",
            ct.id
        ))),
    }
}

/// The credential signing key and its certificate chain as `x5c`.
///
/// Same resolution as `credential.rs::handle_credential_request`, so the JWT's
/// chain **is** the credential's chain and §7 step 6's credential binding (same
/// root CA, same leaf Subject) holds by construction rather than by
/// convention.
fn signer_and_chain(cfg: &Config) -> Result<(FileSigner, Vec<String>), IssuanceError> {
    let (name, key) = cfg.credential_signing_key().ok_or_else(|| {
        IssuanceError::InvalidRequest("no credential signing key configured".to_string())
    })?;
    let signer = FileSigner::from_pem_file(&key.private_key, key.alg.parse()?)?;
    let path = key.x5c.as_ref().ok_or_else(|| {
        IssuanceError::InvalidRequest(format!(
            "credential signing key '{name}' has no x5c chain; PaSO Proof Metadata §4 requires one"
        ))
    })?;
    let pem = std::fs::read(path).map_err(|e| {
        IssuanceError::InvalidRequest(format!("failed to read x5c file '{path}': {e}"))
    })?;
    let chain = foundry_core::trust::build_x5c(&[pem])?;
    Ok((signer, chain))
}

/// PaSO Proof Metadata §2 / §3 — the `credential_metadata` object: OpenID4VCI's
/// display and claims, extended with `transaction_data_types`.
///
/// Served verbatim for `Accept: application/json` (§2) and nested under the
/// `credential_metadata` claim for `Accept: application/jwt` (§4), so the
/// signed and unsigned representations can never disagree.
pub fn build_credential_metadata_document(ct: &CredentialType) -> Result<Value, IssuanceError> {
    let mut doc = Map::new();
    if !ct.display.is_empty() {
        doc.insert("display".to_string(), serde_json::json!(ct.display));
    }
    let claims = crate::metadata::claims_description_objects(ct);
    if !claims.is_empty() {
        doc.insert("claims".to_string(), serde_json::json!(claims));
    }
    if let Some(types) = &ct.transaction_data_types {
        let value =
            serde_json::to_value(types).map_err(|e| IssuanceError::Serialization(e.to_string()))?;
        doc.insert("transaction_data_types".to_string(), value);
    }
    Ok(Value::Object(doc))
}

/// PaSO Proof Metadata §4 — the signed credential metadata JWT.
#[tracing::instrument(skip_all, fields(credential_type_id = %ct.id))]
pub fn build_credential_metadata_jwt(
    cfg: &Config,
    ct: &CredentialType,
    now_unix: i64,
) -> Result<String, IssuanceError> {
    let (signer, chain) = signer_and_chain(cfg)?;
    let uri = credential_metadata_uri(cfg, &ct.id);

    // §4: `typ` and `x5c`. `alg` is supplied by `sign_compact` from the signing
    // key, so the header cannot claim an algorithm the key does not use.
    let mut header = Map::new();
    header.insert(
        "typ".to_string(),
        Value::String(CREDENTIAL_METADATA_TYP.to_string()),
    );
    header.insert("x5c".to_string(), serde_json::json!(chain));

    let ttl = cfg.issuer.paso_metadata.ttl_secs as i64;
    let mut payload = Map::new();
    payload.insert(
        "iss".to_string(),
        Value::String(
            cfg.issuer
                .credential_issuer
                .trim_end_matches('/')
                .to_string(),
        ),
    );
    payload.insert(
        "sub".to_string(),
        Value::String(credential_type_identifier(ct)?.to_string()),
    );
    payload.insert("format".to_string(), Value::String(ct.format.clone()));
    payload.insert("iat".to_string(), serde_json::json!(now_unix));
    payload.insert("exp".to_string(), serde_json::json!(now_unix + ttl));
    // §8: the Wallet verifies this equals the URI it fetched from.
    payload.insert("credential_metadata_uri".to_string(), Value::String(uri));
    payload.insert(
        "credential_metadata".to_string(),
        build_credential_metadata_document(ct)?,
    );

    Ok(foundry_core::crypto::jws::sign_compact(
        &header,
        &Value::Object(payload),
        &signer,
    )?)
}

/// PaSO Proof Metadata §5.2 — the ad-hoc transaction data metadata JWT.
///
/// `override_metadata`, when present, replaces the configured
/// `transaction_data_types` entry for this one artifact. That is the whole
/// point of the ad-hoc channel (§1.1: "transaction-specific or updated metadata
/// without rotating the signed credential metadata JWT"), and §5.4 makes a type
/// covered by a valid ad-hoc JWT "considered supported ... even if it is absent
/// from the signed credential metadata" — so an override may legitimately name
/// a type this issuer has not configured.
///
/// An override is held to exactly the config-time structural rules; a channel
/// that accepted shapes the config channel rejects would make validation
/// advisory.
#[tracing::instrument(
    skip_all,
    fields(
        credential_type_id = %ct.id,
        transaction_data_type = %transaction_data_type,
        override_supplied = override_metadata.is_some(),
    )
)]
pub fn build_adhoc_metadata_jwt(
    cfg: &Config,
    ct: &CredentialType,
    transaction_data_type: &str,
    override_metadata: Option<Value>,
    now_unix: i64,
    ttl_secs: Option<u64>,
) -> Result<String, IssuanceError> {
    let metadata: Value = match override_metadata {
        Some(v) => {
            let parsed: TransactionDataTypeMetadata =
                serde_json::from_value(v.clone()).map_err(|e| {
                    IssuanceError::InvalidRequest(format!("metadata override is malformed: {e}"))
                })?;
            foundry_core::config::validate_paso_transaction_data_type_metadata(
                transaction_data_type,
                &parsed,
            )
            .map_err(IssuanceError::InvalidRequest)?;
            v
        }
        None => {
            let configured = ct
                .transaction_data_types
                .as_ref()
                .and_then(|m| m.get(transaction_data_type))
                .ok_or_else(|| {
                    IssuanceError::InvalidRequest(format!(
                        "credential type '{}' does not declare transaction data type '{}', and no \
                         metadata override was supplied",
                        ct.id, transaction_data_type
                    ))
                })?;
            serde_json::to_value(configured)
                .map_err(|e| IssuanceError::Serialization(e.to_string()))?
        }
    };

    let (signer, chain) = signer_and_chain(cfg)?;

    let mut header = Map::new();
    header.insert(
        "typ".to_string(),
        Value::String(ADHOC_METADATA_TYP.to_string()),
    );
    header.insert("x5c".to_string(), serde_json::json!(chain));

    let ttl = ttl_secs.unwrap_or(cfg.issuer.paso_metadata.adhoc_ttl_secs) as i64;
    let mut payload = Map::new();
    payload.insert(
        "iss".to_string(),
        Value::String(
            cfg.issuer
                .credential_issuer
                .trim_end_matches('/')
                .to_string(),
        ),
    );
    payload.insert(
        "sub".to_string(),
        Value::String(credential_type_identifier(ct)?.to_string()),
    );
    payload.insert("format".to_string(), Value::String(ct.format.clone()));
    payload.insert("iat".to_string(), serde_json::json!(now_unix));
    payload.insert("exp".to_string(), serde_json::json!(now_unix + ttl));
    // §5.2: SHALL equal the `type` of the enclosing transaction_data entry.
    payload.insert(
        "transaction_data_type".to_string(),
        Value::String(transaction_data_type.to_string()),
    );
    payload.insert("metadata".to_string(), metadata);

    Ok(foundry_core::crypto::jws::sign_compact(
        &header,
        &Value::Object(payload),
        &signer,
    )?)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-issuer paso_metadata
```

Expected: 12 tests pass.

- [ ] **Step 6: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. `metadata.rs`'s existing tests cover the extracted
`claims_description_objects` — in particular
`claims_description_omits_display_when_none_configured` and
`credential_metadata_is_absent_when_neither_display_nor_claims_configured` —
so the extraction is proven behaviour-preserving there.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-issuer/
git commit -m "feat(issuer): mint PaSO credential metadata and ad-hoc metadata JWTs"
```

---

### Task 6: Advertise `credential_metadata_uri` in Issuer Metadata

**Files:**

- Modify: `crates/foundry-issuer/src/metadata.rs` (`CredentialConfigurationSupported`, `build_issuer_metadata`)
- Modify: `crates/foundry-issuer/src/offer.rs` (`build_dc_api_offer`) — only if it rebuilds configurations rather than reusing `build_issuer_metadata`'s output

**Interfaces:**

- Consumes: Task 5's `is_paso_credential_type`, `credential_metadata_uri`.
- Produces: `CredentialConfigurationSupported.credential_metadata_uri: Option<String>`,
  serialised as `credential_metadata_uri` and omitted when `None`. Task 9's
  integration tests assert on it.

**Context:** PaSO Proof Metadata §2 — "The Attestation Provider SHALL include a
`credential_metadata_uri` in each PaSO Credential configuration". Only PaSO
configurations get it: advertising it for a type with no
`transaction_data_types` would publish a link to a 404, and §3 makes
`transaction_data_types` REQUIRED in whatever that URI serves.

**Critical:** the DC API offer embeds its own copy of issuer metadata and is the
*only* metadata a DC API wallet ever sees — there is no well-known fetch to fall
back on. This shipped broken once for the request-encryption JWKs (see
`crates/foundry-issuer/AGENTS.md` and its regression test
`dc_api_offer_embeds_the_request_encryption_jwks`). Step 4 checks it.

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` in
`crates/foundry-issuer/src/metadata.rs`:

```rust
    /// PaSO Proof Metadata §2: a PaSO Credential configuration SHALL carry a
    /// `credential_metadata_uri`, built from the same base as every sibling
    /// endpoint so §8's URI-binding check can succeed.
    #[test]
    fn a_paso_credential_configuration_advertises_its_metadata_uri() {
        let mut cfg = test_config();
        let types = serde_json::from_value(serde_json::json!({
            "urn:paso:sca:global:payment:1": {
                "claims": [{ "path": ["amount"], "display": [{ "name": "Amount" }] }]
            }
        }))
        .expect("fixture");
        if let Some(ct) = cfg.credential_types.first_mut() {
            ct.transaction_data_types = Some(types);
        }
        let first_id = cfg
            .credential_types
            .first()
            .map(|c| c.id.clone())
            .expect("at least one credential type");

        let md = build_issuer_metadata(&cfg, &[]);
        let entry = md
            .credential_configurations_supported
            .get(&first_id)
            .expect("configuration present");

        assert_eq!(
            entry.credential_metadata_uri,
            Some(format!(
                "https://issuer.example.com/credential-metadata/{first_id}"
            ))
        );
    }

    /// A non-PaSO configuration must not advertise the URI: the route 404s for
    /// it, and §3 makes `transaction_data_types` REQUIRED in what it serves.
    /// Asserted on the serialised keys, because a `null` would pass a weaker
    /// `Option` check while still changing the wire output.
    #[test]
    fn a_non_paso_credential_configuration_omits_the_metadata_uri_key() {
        let cfg = test_config();
        let md = build_issuer_metadata(&cfg, &[]);
        let json = serde_json::to_value(&md).expect("serialize");

        let configs = json["credential_configurations_supported"]
            .as_object()
            .expect("configurations object");
        assert!(!configs.is_empty(), "fixture must have configurations");
        for (id, entry) in configs {
            assert!(
                entry.get("credential_metadata_uri").is_none(),
                "non-PaSO configuration '{id}' must not emit credential_metadata_uri"
            );
        }
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-issuer metadata
```

Expected: compilation failure — no `credential_metadata_uri` field on
`CredentialConfigurationSupported`.

- [ ] **Step 3: Add and populate the field**

In `crates/foundry-issuer/src/metadata.rs`, add to
`CredentialConfigurationSupported` immediately after `credential_metadata`:

```rust
    /// PaSO Proof Metadata §2 — the URL serving this configuration's credential
    /// metadata, as plain JSON or as a signed `credential-metadata+jwt`.
    ///
    /// Emitted **only** for PaSO Credential configurations (those declaring
    /// `transaction_data_types`). §2 scopes the requirement to them, and the
    /// route 404s for anything else — advertising it more widely would publish
    /// a link to a 404. `skip_serializing_if` rather than an emitted `null`, so
    /// every non-PaSO deployment's wire output stays byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata_uri: Option<String>,
```

And set it in `build_issuer_metadata`, inside the
`CredentialConfigurationSupported { ... }` literal, after `credential_metadata`:

```rust
                // PaSO Proof Metadata §2. `paso_metadata::credential_metadata_uri`
                // is the single owner of this string, so the value advertised
                // here and the `credential_metadata_uri` claim inside the signed
                // JWT are equal by construction — which is exactly what §8's
                // URI-binding check requires of us.
                credential_metadata_uri: if crate::paso_metadata::is_paso_credential_type(ct) {
                    Some(crate::paso_metadata::credential_metadata_uri(cfg, &ct.id))
                } else {
                    None
                },
```

- [ ] **Step 4: Check the DC API offer path**

```bash
rg -n "CredentialConfigurationSupported" crates/foundry-issuer/src/offer.rs crates/foundry-issuer/src/create_offer.rs
rg -n "fn build_dc_api_offer" -A 40 crates/foundry-issuer/src/offer.rs
```

- If `build_dc_api_offer` calls `build_issuer_metadata` and narrows the
  resulting map, **no code change is needed** — the field rides along. Say so in
  the commit message.
- If it constructs `CredentialConfigurationSupported` values itself, add the
  same `credential_metadata_uri` expression there, and add a regression test
  beside `dc_api_offer_embeds_the_request_encryption_jwks` that mirrors that
  test's setup verbatim, gives the credential type a
  `transaction_data_types` map (copy the fixture from Step 1), and asserts the
  embedded configuration's `credential_metadata_uri` equals
  `https://issuer.example.com/credential-metadata/<id>`. Reason to state in the
  test's doc comment: the embedded metadata is the only issuer metadata a DC
  API wallet sees, so a PaSO configuration missing this URI there can never be
  accepted by such a wallet (§3 requires signed metadata before acceptance).

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-issuer metadata
cargo nextest run -p foundry-issuer offer
```

Expected: pass.

- [ ] **Step 6: Regenerate the OpenAPI specs**

`CredentialConfigurationSupported` derives `utoipa::ToSchema`, so its schema
changed.

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
git diff --stat openapi.json openapi-wallet.json
```

Expected: `openapi-wallet.json` gains `credential_metadata_uri` on the
`CredentialConfigurationSupported` schema.

- [ ] **Step 7: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass, including `tests/openapi_endpoints.rs`, which compares the
committed specs against the live routes and asserts every `$ref` resolves.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-issuer/ openapi.json openapi-wallet.json
git commit -m "feat(issuer): advertise credential_metadata_uri for PaSO configurations"
```

---

### Task 7: Wallet route `GET /credential-metadata/:credential_configuration_id`

**Files:**

- Modify: `crates/foundry/src/server.rs` (negotiation helper, handler, route registration)
- Modify: `crates/foundry/src/openapi.rs` (register the path on `WalletApiDoc`)
- Modify: `openapi-wallet.json` (regenerated)

**Interfaces:**

- Consumes: Task 5's `build_credential_metadata_document`,
  `build_credential_metadata_jwt`, `is_paso_credential_type`.
- Produces: `pub(crate) enum MetadataRepresentation { Json, Jwt }`,
  `pub(crate) fn negotiate_metadata_representation(accept: Option<&str>) -> Option<MetadataRepresentation>`,
  `pub(crate) async fn credential_metadata_handler(...)`. Task 9 drives the
  route over HTTP.

**Context:** PaSO Proof Metadata §2 content negotiation. **Nothing in foundry
reads an `Accept` header today** — this is the first such route, so the
negotiation logic is a separately unit-tested pure function rather than inline
handler code.

- [ ] **Step 1: Write the failing unit tests for negotiation**

Add to the existing `#[cfg(test)] mod tests` in `crates/foundry/src/server.rs`:

```rust
    /// PaSO Proof Metadata §2: "If the Accept header is absent or does not
    /// express a preference, the Attestation Provider SHALL default to
    /// application/json."
    #[test]
    fn absent_or_unopinionated_accept_defaults_to_json() {
        for header in [None, Some(""), Some("*/*"), Some("application/*")] {
            assert!(
                matches!(
                    negotiate_metadata_representation(header),
                    Some(MetadataRepresentation::Json)
                ),
                "expected JSON for Accept: {header:?}"
            );
        }
    }

    #[test]
    fn application_jwt_selects_the_signed_representation() {
        for header in [
            "application/jwt",
            "application/jwt; q=1.0",
            "application/json, application/jwt",
            " application/jwt ",
        ] {
            assert!(
                matches!(
                    negotiate_metadata_representation(Some(header)),
                    Some(MetadataRepresentation::Jwt)
                ),
                "expected JWT for Accept: {header}"
            );
        }
    }

    #[test]
    fn application_json_selects_the_plain_representation() {
        assert!(matches!(
            negotiate_metadata_representation(Some("application/json")),
            Some(MetadataRepresentation::Json)
        ));
    }

    /// An Accept naming only media types this route cannot produce is a 406,
    /// not a silent fallback — a fallback would hand a wallet bytes it just
    /// told us it cannot parse.
    #[test]
    fn an_unsatisfiable_accept_is_none() {
        for header in ["text/html", "application/cbor, image/png"] {
            assert!(
                negotiate_metadata_representation(Some(header)).is_none(),
                "expected unsatisfiable for Accept: {header}"
            );
        }
    }
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo nextest run -p foundry negotiate
```

Expected: compilation failure — no `negotiate_metadata_representation`, no
`MetadataRepresentation`.

- [ ] **Step 3: Write the negotiation helper**

Add to `crates/foundry/src/server.rs` near the other free helpers (just above
`fn internal_error`):

```rust
/// Which representation of the credential metadata a request asked for
/// (PaSO Proof Metadata §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataRepresentation {
    /// The bare `credential_metadata` object (§2, `Accept: application/json`).
    Json,
    /// The signed `credential-metadata+jwt` (§2 and §4, `Accept: application/jwt`).
    Jwt,
}

/// PaSO Proof Metadata §2 content negotiation.
///
/// Returns `None` when `Accept` names only media types this route cannot
/// produce; the caller turns that into 406. Returns `Json` when the header is
/// absent or "does not express a preference" (§2's phrase, read here as absent,
/// empty, or a wildcard).
///
/// **Deliberately not full RFC 9110 q-value negotiation.** `application/jwt`
/// anywhere in the list wins. The two representations carry identical
/// information, and only the signed one is usable for the PaSO flow — §3: a
/// Wallet "SHALL NOT use unsigned credential metadata from the Credential
/// Issuer Metadata endpoint for PaSO Credentials". A client listing both is
/// therefore better served the signed form whatever weights it attached.
/// Scanning for one token also makes the result order-independent and
/// deterministic.
pub(crate) fn negotiate_metadata_representation(
    accept: Option<&str>,
) -> Option<MetadataRepresentation> {
    let Some(raw) = accept else {
        return Some(MetadataRepresentation::Json);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Some(MetadataRepresentation::Json);
    }

    let mut json_acceptable = false;
    for part in raw.split(',') {
        // Strip parameters (`;q=0.8`, `;charset=...`). `next()` on a split
        // always yields at least one element; `unwrap_or` keeps this free of
        // `unwrap` per root AGENTS.md §4.1.
        let media = part.split(';').next().unwrap_or("").trim();
        match media {
            "application/jwt" => return Some(MetadataRepresentation::Jwt),
            "application/json" | "application/*" | "*/*" => json_acceptable = true,
            _ => {}
        }
    }

    if json_acceptable {
        Some(MetadataRepresentation::Json)
    } else {
        None
    }
}
```

- [ ] **Step 4: Write the handler**

Add to `crates/foundry/src/server.rs` beside the other wallet-facing GET
handlers, immediately after `get_credential_offer_handler`:

```rust
#[utoipa::path(
    get,
    path = "/credential-metadata/{credential_configuration_id}",
    params(
        ("credential_configuration_id" = String, Path,
         description = "Credential Configuration id declaring transaction_data_types")
    ),
    responses(
        (status = 200, description = "Signed credential metadata JWT (Accept: application/jwt)",
         content_type = "application/jwt", body = String),
        (status = 404, description = "Unknown configuration, or not a PaSO Credential type"),
        (status = 406, description = "Accept names no representation this route produces")
    )
)]
pub(crate) async fn credential_metadata_handler(
    State(state): State<AppState>,
    Path(credential_configuration_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    use axum::response::IntoResponse;

    // PaSO Proof Metadata §2 scopes this endpoint to PaSO Credential
    // configurations, and §3 makes `transaction_data_types` REQUIRED in what it
    // serves. A configuration without them has nothing conformant to return, so
    // it is treated exactly like an unknown id -- and 404 leaks nothing beyond
    // what Issuer Metadata already publishes.
    let Some(ct) = state
        .config
        .credential_types
        .iter()
        .find(|c| c.id == credential_configuration_id)
        .filter(|c| foundry_issuer::is_paso_credential_type(c))
    else {
        log_typed_error(
            "wallet",
            "unknown_credential_configuration",
            "no PaSO credential configuration with that id",
            StatusCode::NOT_FOUND,
        );
        return Err(StatusCode::NOT_FOUND);
    };

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok());
    let Some(representation) = negotiate_metadata_representation(accept) else {
        log_typed_error(
            "wallet",
            "not_acceptable",
            "Accept names neither application/jwt nor application/json",
            StatusCode::NOT_ACCEPTABLE,
        );
        return Err(StatusCode::NOT_ACCEPTABLE);
    };

    match representation {
        // §2: the plain JSON form is the bare `credential_metadata` object --
        // explicitly NOT the JWT payload structure of §4.
        MetadataRepresentation::Json => {
            let doc = foundry_issuer::build_credential_metadata_document(ct)
                .map_err(|e| internal_error("build_credential_metadata_document", e.kind(), e))?;
            Ok(Json(doc).into_response())
        }
        // §4: minted fresh on every request, so "rotate before exp" holds by
        // construction -- there is no cache to go stale.
        MetadataRepresentation::Jwt => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let jwt = foundry_issuer::build_credential_metadata_jwt(&state.config, ct, now)
                .map_err(|e| internal_error("build_credential_metadata_jwt", e.kind(), e))?;
            Ok((
                [(axum::http::header::CONTENT_TYPE, "application/jwt")],
                jwt,
            )
                .into_response())
        }
    }
}
```

> The `now` computation mirrors `create_offer_handler`'s existing
> `SystemTime::now().duration_since(UNIX_EPOCH).map(...).unwrap_or(0)` idiom —
> use it verbatim rather than inventing a new one.

- [ ] **Step 5: Register the route**

In `wallet_router`, in the initial `Router::new()` chain, immediately after the
`/credential-offer/:id` route:

```rust
        // PaSO Proof Metadata §2. Registered unconditionally: the handler 404s
        // for any configuration that is not a PaSO Credential type, so the
        // route's presence can never contradict what Issuer Metadata
        // advertises.
        .route(
            "/credential-metadata/:credential_configuration_id",
            get(credential_metadata_handler),
        )
```

> **axum 0.7 path syntax is `:name`.** Every existing route in this file uses it
> (`/credential-offer/:id`, `/vp/request/:id`, `/statuslists/:id`). Do not write
> `{name}` — that is axum 0.8 syntax and will not match.

- [ ] **Step 6: Register the OpenAPI path**

In `crates/foundry/src/openapi.rs`, add to `WalletApiDoc`'s `paths(...)` list,
immediately after `crate::server::get_credential_offer_handler,`:

```rust
        crate::server::credential_metadata_handler,
```

- [ ] **Step 7: Run the unit tests**

```bash
cargo nextest run -p foundry negotiate
```

Expected: 4 tests pass.

- [ ] **Step 8: Regenerate the OpenAPI specs**

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
```

Expected: `openapi-wallet.json` gains the
`/credential-metadata/{credential_configuration_id}` path.

- [ ] **Step 9: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass, including `tests/openapi_endpoints.rs` (route-vs-spec
parity) and `tests/instrumentation_hygiene.rs`.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/src/openapi.rs \
        openapi.json openapi-wallet.json
git commit -m "feat(server): serve PaSO credential metadata as JSON or signed JWT"
```

---

### Task 8: Admin route `POST /admin/paso/ad-hoc-metadata`

**Files:**

- Modify: `crates/foundry/src/server.rs` (request/response types, handler, route registration)
- Modify: `crates/foundry/src/openapi.rs` (register path + schemas on `AdminApiDoc`)
- Modify: `openapi.json` (regenerated)

**Interfaces:**

- Consumes: Task 5's `build_adhoc_metadata_jwt`.
- Produces:

  ```rust
  pub(crate) struct AdHocMetadataRequest {
      pub credential_type_id: String,
      pub transaction_data_type: String,
      pub metadata: Option<serde_json::Value>,
      pub ttl_secs: Option<u64>,
  }
  pub(crate) struct AdHocMetadataResponse { pub jwt: String, pub exp: i64 }
  pub(crate) async fn create_adhoc_metadata_handler(...)
  ```

  Task 9 drives the route over HTTP.

**Context:** PaSO Proof Metadata §5.1 — a Relying Party embeds this JWT in a
`transaction_data` entry's `metadata` parameter, and "the mechanism by which it
obtains it from the Attestation Provider is out of scope of this
specification". This route is foundry's answer to that out-of-scope gap; it is
therefore an operator API on the admin listener, not a wallet-facing one.

**Observability:** log `credential_type_id`, `transaction_data_type`, and
**whether** an override was supplied — never its contents. An override can carry
transaction-specific label text (payee names, amount formats), which mirrors why
`create_offer` records only the *presence* of EMVCo display metadata
(root AGENTS.md §4.5).

- [ ] **Step 1: Write the failing tests**

Create `crates/foundry/tests/paso_adhoc_metadata.rs`:

```rust
//! PaSO Proof Metadata §5 — the admin ad-hoc metadata mint endpoint.

mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::{Value, json};

fn decode_part(jwt: &str, index: usize) -> Value {
    let part = jwt.split('.').nth(index).expect("segment");
    serde_json::from_slice(&B64URL.decode(part).expect("b64url")).expect("json")
}

#[tokio::test]
async fn minting_an_adhoc_metadata_jwt_returns_a_signed_artifact() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:global:payment:1"
            }),
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json body");
    let jwt = body["jwt"].as_str().expect("jwt string");

    assert_eq!(
        decode_part(jwt, 0)["typ"],
        json!("adhoc-transaction-metadata+jwt")
    );
    let payload = decode_part(jwt, 1);
    assert_eq!(
        payload["transaction_data_type"],
        json!("urn:paso:sca:global:payment:1")
    );
    assert_eq!(body["exp"], payload["exp"]);
}

/// §5.4: a valid ad-hoc JWT makes a type supported "even if it is absent from
/// the signed credential metadata", so an override may introduce a new type.
#[tokio::test]
async fn an_override_may_introduce_an_unconfigured_type() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:com.example.pay:transaction:2",
                "metadata": {
                    "claims": [
                        { "path": ["reward_points"], "display": [{ "name": "Points" }] }
                    ]
                }
            }),
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json body");
    let payload = decode_part(body["jwt"].as_str().expect("jwt"), 1);
    assert_eq!(payload["metadata"]["claims"][0]["path"][0], json!("reward_points"));
}

#[tokio::test]
async fn an_unknown_credential_type_is_a_400() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "NoSuchType",
                "transaction_data_type": "urn:paso:sca:global:payment:1"
            }),
        )
        .await;

    assert_eq!(resp.status(), 400);
}

/// An override is held to exactly the config-time rules of §3.1.
#[tokio::test]
async fn a_structurally_invalid_override_is_a_400() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:global:payment:1",
                "metadata": {
                    "claims": [{ "path": ["amount"], "value_type": "iso_currency_amount" }]
                }
            }),
        )
        .await;

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn the_route_requires_the_admin_api_key() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post_without_key(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:global:payment:1"
            }),
        )
        .await;

    assert!(
        resp.status() == 401 || resp.status() == 403,
        "expected an auth rejection, got {}",
        resp.status()
    );
}
```

> **Implementer note on `support::paso_test_env()`:** this helper does not exist
> yet — **build it in Task 9 Step 1 and land Task 8 and Task 9 together, or
> build it here.** Read `crates/foundry/tests/support/mod.rs` first: it already
> provides the pattern for booting a server with a `Config` and calling admin
> routes with the API key (see how `issuer_offers.rs` and `console.rs` use it).
> `paso_test_env()` must produce a config with one PaSO credential type
> (`BankPaymentCard`, `dc+sd-jwt`, `vct: https://bank.example/sca/card`, one
> `urn:paso:sca:global:payment:1` entry) **and** a credential signing key with a
> real `x5c` chain — `Config::validate()` refuses to boot without one (Task 4).
> Name the accessors to match whatever `support` already exposes; the
> `admin_post` / `admin_post_without_key` names above are indicative, not
> prescriptive.

- [ ] **Step 2: Run to verify they fail**

```bash
cargo nextest run -p foundry --test paso_adhoc_metadata
```

Expected: compilation failure — no such route, and no `paso_test_env` helper.

- [ ] **Step 3: Add the request and response types**

In `crates/foundry/src/server.rs`, beside the other admin request/response
types:

```rust
/// PaSO Proof Metadata §5 — request to mint an ad-hoc transaction data metadata
/// JWT for a Relying Party to embed in a `transaction_data` entry (§5.1).
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct AdHocMetadataRequest {
    /// The Credential Configuration id the metadata applies to. Supplies the
    /// JWT's `sub` and `format` (§5.2).
    pub credential_type_id: String,
    /// §5.2: SHALL equal the `type` of the enclosing `transaction_data` entry.
    pub transaction_data_type: String,
    /// OPTIONAL transaction-specific metadata replacing the configured entry
    /// for this one artifact (§5.4). Absent uses the configured entry; present,
    /// it is validated against exactly the config-time rules of §3.1/§3.2.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
    /// OPTIONAL override of `issuer.paso_metadata.adhoc_ttl_secs`.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// The minted ad-hoc metadata JWT and its expiry.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub(crate) struct AdHocMetadataResponse {
    /// Compact `adhoc-transaction-metadata+jwt` (§5.2).
    pub jwt: String,
    /// The JWT's `exp`, echoed so an operator need not decode the artifact to
    /// know how long a Relying Party may cache it (§5.2).
    pub exp: i64,
}
```

- [ ] **Step 4: Write the handler**

Add beside the other admin handlers in `crates/foundry/src/server.rs`:

```rust
#[utoipa::path(
    post,
    path = "/admin/paso/ad-hoc-metadata",
    request_body = AdHocMetadataRequest,
    responses(
        (status = 200, body = AdHocMetadataResponse),
        (status = 400, description = "Unknown credential type, unconfigured transaction data type with no override, or a structurally invalid override")
    )
)]
pub(crate) async fn create_adhoc_metadata_handler(
    State(state): State<AppState>,
    Json(req): Json<AdHocMetadataRequest>,
) -> Result<Json<AdHocMetadataResponse>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ct) = state
        .config
        .credential_types
        .iter()
        .find(|c| c.id == req.credential_type_id)
    else {
        // Typed error so the single log record is emitted by the mapper, per
        // root AGENTS.md §4.5 -- not logged here.
        return Err(admin_error_response(&foundry_issuer::IssuanceError::
            UnknownCredentialType(req.credential_type_id.clone())));
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // PaSO Proof Metadata §5. `override_supplied` records PRESENCE only: an
    // override can carry transaction-specific label text (payee names, amount
    // formats), so its contents are not log material -- the same rule
    // `create_offer` applies to EMVCo display metadata (root AGENTS.md §4.5).
    tracing::info!(
        credential_type_id = %req.credential_type_id,
        transaction_data_type = %req.transaction_data_type,
        override_supplied = req.metadata.is_some(),
        "minting PaSO ad-hoc transaction data metadata"
    );

    let jwt = foundry_issuer::build_adhoc_metadata_jwt(
        &state.config,
        ct,
        &req.transaction_data_type,
        req.metadata,
        now,
        req.ttl_secs,
    )
    .map_err(|e| admin_error_response(&e))?;

    let ttl = req
        .ttl_secs
        .unwrap_or(state.config.issuer.paso_metadata.adhoc_ttl_secs) as i64;

    Ok(Json(AdHocMetadataResponse {
        jwt,
        exp: now + ttl,
    }))
}
```

> **`admin_error_response` maps `UnknownCredentialType` to 400** — verified in
> its existing `match` (`UnknownCredentialType(_) | ClaimValidation(_) =>
> StatusCode::BAD_REQUEST`). `InvalidRequest`, which
> `build_adhoc_metadata_jwt` returns for an unconfigured type or an invalid
> override, currently falls into that mapper's `_ => INTERNAL_SERVER_ERROR`
> arm. **That is wrong for this route** — both are operator input errors. Add
> `InvalidRequest(_)` to the `BAD_REQUEST` arm of `admin_error_response`:
>
> ```rust
>         UnknownCredentialType(_) | ClaimValidation(_) | InvalidRequest(_) => {
>             StatusCode::BAD_REQUEST
>         }
> ```
>
> Check no existing admin route depended on `InvalidRequest` producing a 500 —
> `rg -n "InvalidRequest" crates/foundry-issuer/src/create_offer.rs` — and if
> one does, note it in the commit message. A 500 for malformed operator input
> would be a defect either way (root AGENTS.md §4.3).

- [ ] **Step 5: Register the route**

In `admin_router`, in the `authenticated` chain, after the
`/admin/verification/requests/:id/dc-api-response` route and **before**
`.route_layer(...)` so the API-key middleware covers it:

```rust
        .route(
            "/admin/paso/ad-hoc-metadata",
            post(create_adhoc_metadata_handler),
        )
```

- [ ] **Step 6: Register in OpenAPI**

In `crates/foundry/src/openapi.rs`, add to `AdminApiDoc`'s `paths(...)`:

```rust
        crate::server::create_adhoc_metadata_handler,
```

and to its `components(schemas(...))`:

```rust
        crate::server::AdHocMetadataRequest,
        crate::server::AdHocMetadataResponse,
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry --test paso_adhoc_metadata
```

Expected: 5 tests pass.

- [ ] **Step 8: Regenerate the OpenAPI specs**

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
```

Expected: `openapi.json` gains the `/admin/paso/ad-hoc-metadata` path and both
schemas.

- [ ] **Step 9: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass, including `tests/logging_redaction.rs` — which is why the
override contents must never reach a log field.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/src/openapi.rs \
        crates/foundry/tests/paso_adhoc_metadata.rs \
        crates/foundry/tests/support/ openapi.json openapi-wallet.json
git commit -m "feat(server): mint PaSO ad-hoc transaction data metadata JWTs"
```

---

### Task 9: Integration tests, quickstart config, and documentation

**Files:**

- Create: `crates/foundry/tests/paso_metadata.rs`
- Modify: `crates/foundry/tests/support/mod.rs` (add `paso_test_env`)
- Modify: `crates/foundry/tests/AGENTS.md` (describe the two new test files)
- Modify: `crates/foundry/src/commands.rs` (quickstart config gains a PaSO type)
- Modify: `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md`, `crates/foundry/AGENTS.md`
- Modify: `README.md` (endpoint list + config reference)

**Interfaces:**

- Consumes: everything from Tasks 4–8.
- Produces: `support::paso_test_env()` (also used by Task 8's tests).

**Context:** This task proves the artifact is *verifiable*, not merely
well-formed. foundry ships no wallet client, so the verification test acts as
its own test-wallet in-process, running the checks of PaSO Proof Metadata §7
and the URI binding of §8 against a JWT fetched over real HTTP.

- [ ] **Step 1: Add the `paso_test_env` support helper**

Read `crates/foundry/tests/support/mod.rs` and follow its existing pattern for
booting a server. Add a helper that produces an environment whose config has:

- one credential type `BankPaymentCard`, `format: dc+sd-jwt`,
  `vct: https://bank.example/sca/card`, `cryptographic_holder_binding: true`;
- its `transaction_data_types` containing one `urn:paso:sca:global:payment:1`
  entry with the `claims` and `ui_labels` from Task 5's fixture;
- one non-PaSO credential type (any existing fixture type) so the 404 case is
  testable;
- a credential signing key with a **real `x5c` chain on disk** — generate it
  with `foundry_core::pki::{new_ca, issue_leaf}` into a `tempfile::tempdir()`
  and `std::mem::forget` the dir, exactly as
  `crates/foundry-verifier/src/request.rs`'s `sample_verifier_x5c_path()` does.
  `Config::validate()` refuses to boot a PaSO deployment without one (Task 4).

Expose whatever accessors the existing support module's style implies — at
minimum: the wallet-facing base URL, an unauthenticated GET that lets the
caller set an `Accept` header, an admin POST that sends the API key, and an
admin POST that omits it.

- [ ] **Step 2: Write the failing integration tests**

Create `crates/foundry/tests/paso_metadata.rs`:

```rust
//! PaSO Proof Metadata §2, §4, §7, §8 — the wallet-facing credential metadata
//! endpoint, end to end over HTTP.

mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::{Value, json};

fn decode_part(jwt: &str, index: usize) -> Value {
    let part = jwt.split('.').nth(index).expect("segment");
    serde_json::from_slice(&B64URL.decode(part).expect("b64url")).expect("json")
}

/// §2: `Accept: application/jwt` returns the signed form with the media type
/// the spec names.
#[tokio::test]
async fn accept_application_jwt_returns_a_signed_credential_metadata_jwt() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept(
            "/credential-metadata/BankPaymentCard",
            Some("application/jwt"),
        )
        .await;

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/jwt")
    );

    let jwt = resp.text().await.expect("body");
    assert_eq!(jwt.split('.').count(), 3, "compact JWS has three segments");
    assert_eq!(
        decode_part(&jwt, 0)["typ"],
        json!("credential-metadata+jwt")
    );
}

/// §2: the plain JSON form is the bare `credential_metadata` object — NOT the
/// JWT payload structure of §4. A client must not find `iss`/`exp` here.
#[tokio::test]
async fn accept_application_json_returns_the_bare_metadata_object() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept(
            "/credential-metadata/BankPaymentCard",
            Some("application/json"),
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json body");

    assert!(body["transaction_data_types"]["urn:paso:sca:global:payment:1"]["claims"].is_array());
    assert!(body.get("credential_metadata").is_none(), "not the JWT envelope");
    assert!(body.get("iss").is_none(), "not the JWT envelope");
    assert!(body.get("exp").is_none(), "not the JWT envelope");
}

/// §2: absent `Accept` defaults to `application/json`.
#[tokio::test]
async fn an_absent_accept_header_defaults_to_json() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept("/credential-metadata/BankPaymentCard", None)
        .await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json body");
    assert!(body["transaction_data_types"].is_object());
}

#[tokio::test]
async fn an_unsatisfiable_accept_is_406() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept("/credential-metadata/BankPaymentCard", Some("text/html"))
        .await;

    assert_eq!(resp.status(), 406);
}

#[tokio::test]
async fn an_unknown_configuration_id_is_404() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept("/credential-metadata/NoSuchType", Some("application/jwt"))
        .await;

    assert_eq!(resp.status(), 404);
}

/// A configured but non-PaSO credential type has no conformant document to
/// return (§3 makes `transaction_data_types` REQUIRED here), so it 404s exactly
/// like an unknown id.
#[tokio::test]
async fn a_non_paso_configuration_id_is_404() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept(
            &format!("/credential-metadata/{}", support::NON_PASO_TYPE_ID),
            Some("application/jwt"),
        )
        .await;

    assert_eq!(resp.status(), 404);
}

/// §2: Issuer Metadata advertises the URI for PaSO configurations only, and the
/// advertised value must be exactly what §8's binding check compares against.
#[tokio::test]
async fn issuer_metadata_advertises_the_uri_for_paso_types_only() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept("/.well-known/openid-credential-issuer", None)
        .await;
    let md: Value = resp.json().await.expect("json body");
    let configs = md["credential_configurations_supported"]
        .as_object()
        .expect("configurations");

    let paso = &configs["BankPaymentCard"];
    assert_eq!(
        paso["credential_metadata_uri"].as_str(),
        Some(
            format!(
                "{}/credential-metadata/BankPaymentCard",
                env.credential_issuer()
            )
            .as_str()
        )
    );

    let non_paso = &configs[support::NON_PASO_TYPE_ID];
    assert!(
        non_paso.get("credential_metadata_uri").is_none(),
        "a non-PaSO configuration must not advertise the URI"
    );
}

/// **The §7 verification test.** foundry publishes; a Wallet verifies. With no
/// wallet client in this repo, this test performs the Wallet's checks in
/// process against a JWT fetched over real HTTP — proving the artifact is
/// verifiable, not merely well-formed.
///
/// Steps mirror §7: (1) `typ`; (2) signature; (3) `x5c` chain; (4) `iss`;
/// (5) `exp`; (6) credential binding via `sub`. Plus §8's URI binding.
#[tokio::test]
async fn a_fetched_metadata_jwt_passes_the_wallet_side_verification() {
    let env = support::paso_test_env().await;
    let url = format!(
        "{}/credential-metadata/BankPaymentCard",
        env.credential_issuer()
    );

    let resp = env
        .wallet_get_with_accept(
            "/credential-metadata/BankPaymentCard",
            Some("application/jwt"),
        )
        .await;
    let jwt = resp.text().await.expect("body");

    let header = decode_part(&jwt, 0);
    let payload = decode_part(&jwt, 1);

    // §7 step 1 -- typ.
    assert_eq!(header["typ"], json!("credential-metadata+jwt"));

    // §7 step 3 -- the chain is present and usable. foundry takes the x5c
    // branch; §4's kid/key-set alternative is unimplemented by design.
    let chain = header["x5c"].as_array().expect("x5c chain");
    assert!(!chain.is_empty());
    assert!(header.get("kid").is_none(), "§4: with x5c, kid SHALL NOT be used");

    // §7 step 2 -- verify the signature against the leaf certificate's public
    // key. Decode the leaf from the x5c chain (base64 DER), extract its public
    // key, and verify over `header_b64 . payload_b64`.
    //
    // Use whichever verification helper this workspace already exposes for an
    // x5c-signed compact JWS -- `crates/foundry-core/src/status_list/mod.rs`
    // verifies a status list token this way, and
    // `crates/foundry-verifier/src/request.rs`'s
    // `test_build_signed_request_object_and_verify_jws` does it for a Request
    // Object. Copy the idiom from whichever is closer; do NOT hand-roll ECDSA.

    // §7 step 4 -- iss.
    assert_eq!(payload["iss"].as_str(), Some(env.credential_issuer()));

    // §7 step 5 -- exp is in the future.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    assert!(payload["exp"].as_i64().expect("exp") > now);

    // §7 step 6 -- credential binding: `sub` is the credential's type
    // identifier (`vct` for SD-JWT VC), and explicitly not the device-signed
    // namespace `urn:paso:sca:1`.
    assert_eq!(payload["sub"], json!("https://bank.example/sca/card"));
    assert_ne!(payload["sub"], json!("urn:paso:sca:1"));
    assert_eq!(payload["format"], json!("dc+sd-jwt"));

    // §8 -- URI binding: the claim equals the URI the JWT was retrieved from.
    assert_eq!(payload["credential_metadata_uri"].as_str(), Some(url.as_str()));
}

/// §4: minted per request, so two fetches are independently valid artifacts.
/// (They need not be byte-identical — nothing in PaSO requires that, and §8
/// wants retrieval decorrelated from use.)
#[tokio::test]
async fn each_fetch_yields_an_independently_valid_jwt() {
    let env = support::paso_test_env().await;

    for _ in 0..2 {
        let resp = env
            .wallet_get_with_accept(
                "/credential-metadata/BankPaymentCard",
                Some("application/jwt"),
            )
            .await;
        assert_eq!(resp.status(), 200);
        let jwt = resp.text().await.expect("body");
        assert_eq!(
            decode_part(&jwt, 0)["typ"],
            json!("credential-metadata+jwt")
        );
    }
}
```

> **Implementer note:** the signature-verification block in
> `a_fetched_metadata_jwt_passes_the_wallet_side_verification` is described
> rather than written because the exact helper differs by what
> `foundry-core`/`foundry-verifier` expose. **Replace the comment with real
> code** — find the existing x5c-leaf-to-verifier idiom (start with
> `rg -n "verify_jws_with_coords\|verifier_from" crates/foundry-core/src crates/foundry-verifier/src`)
> and use it. Shipping the comment as-is is a defect; a §7 test that does not
> check the signature proves nothing.

- [ ] **Step 3: Run to verify they fail**

```bash
cargo nextest run -p foundry --test paso_metadata
```

Expected: compilation failure (no `paso_test_env`) or assertion failures.

- [ ] **Step 4: Make them pass**

Implement `support::paso_test_env()` and `support::NON_PASO_TYPE_ID` per
Step 1, and fill in the signature verification per the note. No production code
should need changing — Tasks 4–8 built all of it. If something does, that is a
gap in an earlier task: fix it there and say so.

```bash
cargo nextest run -p foundry --test paso_metadata
cargo nextest run -p foundry --test paso_adhoc_metadata
```

Expected: all pass.

- [ ] **Step 5: Add a PaSO credential type to the quickstart config**

In `crates/foundry/src/commands.rs`, find where the quickstart config's
`credential_types` are generated (the same place the EMVCo DPC type was added —
`rg -n "credential_types" crates/foundry/src/commands.rs`) and add a
`transaction_data_types` block to **one** type, so a quickstart deployment
exercises the endpoint:

```yaml
    transaction_data_types:
      "urn:paso:sca:global:payment:1":
        claims:
          - path: [transaction_id]
            mandatory: true
          - path: [amount]
            mandatory: true
            value_type: iso_currency_amount
            display:
              - { locale: en, name: Amount }
              - { locale: de, name: Betrag }
          - path: [payee, name]
            mandatory: true
            display:
              - { locale: en, name: Payee }
              - { locale: de, name: Empfänger }
        ui_labels:
          affirmative_action_label:
            - { locale: en, value: Confirm Payment }
            - { locale: de, value: Zahlung bestätigen }
```

> The quickstart already generates a signing key **with** an `x5c` chain
> (`keys/issuer_sdjwt-chain.pem`), so Task 4's startup check is satisfied. Verify
> with `cargo nextest run -p foundry --test quickstart_config` — if that test
> asserts on the generated YAML, update its expectations.

- [ ] **Step 6: Update the crate AGENTS.md files**

- `crates/foundry-core/AGENTS.md`: add `crypto/jws.rs` to the module map
  ("compact JWS construction; the single owner of JOSE header assembly and of
  `alg`-versus-signing-key agreement"), note `transaction_data_types` and
  `paso_metadata` on the config model, and add a Gotcha: **`serde_json` is
  built with `preserve_order`, so JOSE header member order is insertion order —
  `sign_compact` validates `alg` where the caller placed it rather than
  inserting it, precisely so the three pre-existing call sites stay
  byte-identical.**
- `crates/foundry-issuer/AGENTS.md`: add `paso_metadata.rs` to the module map;
  add the two builders and `credential_metadata_uri` to the public surface; add
  Gotchas: **the ad-hoc override may name a type absent from config (§5.4) and
  that is deliberate, not a hole**; **`credential_metadata_uri` is derived from
  `issuer.credential_issuer`, not `server.wallet_facing.public_base_url`,
  because §8 binds the claim to the fetched URI and every sibling endpoint uses
  that base**; **the `kid`/key-set signing branch of §4/§5.2/§7 is deliberately
  unimplemented**.
- `crates/foundry/AGENTS.md`: add both routes to the route tables (wallet:
  `GET /credential-metadata/:credential_configuration_id`, unauthenticated;
  admin: `POST /admin/paso/ad-hoc-metadata`), and note that the wallet route is
  **the only route in this crate that reads an `Accept` header**.
- `crates/foundry/tests/AGENTS.md`: add rows for `paso_metadata.rs` ("content
  negotiation, 404/406, issuer-metadata advertisement, and the §7 wallet-side
  verification of a JWT fetched over HTTP") and `paso_adhoc_metadata.rs`
  ("admin ad-hoc mint: default and override paths, validation rejections, API
  key required").

> Root AGENTS.md §8: no line counts or test counts in any AGENTS.md.

- [ ] **Step 7: Update README.md**

Add both endpoints to the endpoint tables, and document the config surface:
`credential_types[].transaction_data_types` (presence makes a type a PaSO
credential type) and `issuer.paso_metadata.{ttl_secs, adhoc_ttl_secs}` with
their defaults (`86400`, `300`). Mention that the wallet route content-negotiates
on `Accept` between `application/json` and `application/jwt`.

- [ ] **Step 8: Run the full gate, including the E2E suite**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

Expected: all pass. The E2E run matters here because Step 5 changed the
quickstart config that E2E environments boot from (root AGENTS.md §5.2).

- [ ] **Step 9: Commit**

```bash
git add crates/ README.md openapi.json openapi-wallet.json
git commit -m "test(paso): end-to-end credential metadata coverage; document PaSO support"
```

---

## Plan Self-Review

**Spec coverage** — each design section maps to a task:

| Design section | Task |
| --- | --- |
| §1 Spec governance | 1 |
| §2 Config surface | 4 |
| §3 Shared JWS helper | 2, 3 |
| §4.1 Credential metadata JWT | 5 |
| §4.2 Ad-hoc JWT | 5, 8 |
| §4.3 Statelessness | 5 (per-request minting), 9 (`each_fetch_yields_an_independently_valid_jwt`) |
| §4.4 Locale handling | 5 (all locales always served — no filtering code exists, which *is* the implementation) |
| §5.1 Wallet route | 7 |
| §5.2 Admin route | 8 |
| §5.3 OpenAPI | 6, 7, 8 |
| §6 Observability | 7 (`log_typed_error` at 404/406), 8 (presence-only override logging) |
| §7 Testing | 2, 4, 5, 6, 7, 8, 9 |
| §8 Files touched | all |
| §9 Non-goals | 1 (spec rows record the unimplemented `kid` branch), 5 (module docs), 9 (AGENTS.md) |
| §10 Ambiguity register | already in the design doc; Task 4 and Task 5 cite entry #1 inline |

**Type consistency check.** `TransactionDataTypeMetadata`,
`PasoMetadataConfig`, `validate_paso_transaction_data_type_metadata`,
`is_paso_credential_type`, `credential_metadata_uri`,
`build_credential_metadata_document`, `build_credential_metadata_jwt`,
`build_adhoc_metadata_jwt`, `claims_description_objects`,
`MetadataRepresentation`, `negotiate_metadata_representation`,
`credential_metadata_handler`, `AdHocMetadataRequest`, `AdHocMetadataResponse`,
`create_adhoc_metadata_handler` are each defined in exactly one task and spelled
identically everywhere they appear.

**Known soft spots**, flagged rather than hidden — each is a place the
implementer must read the existing code rather than trust this plan:

1. Task 3 Step 1's `sample_transaction()` — the real helper name in
   `foundry-verifier`'s test module.
2. Task 4 Step 1's `valid_config()` — the real helper name in `foundry-core`'s
   config test module.
3. Task 5 Step 1's `crate::metadata::tests::test_config()` — requires making
   that helper and its module `pub(crate)`.
4. Task 6 Step 4 — whether `build_dc_api_offer` rebuilds configurations.
5. Task 9 Step 2 — the signature-verification idiom, which must be written out
   rather than left as a comment.

**Ordering note.** Task 8's tests depend on `support::paso_test_env()`, built in
Task 9 Step 1. Either build the helper in Task 8 and let Task 9 extend it, or
execute 8 and 9 as one unit. Do not leave Task 8 "complete" with a test file
that does not compile.
