# Cryptographic X.509 Trust-Chain Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `foundry_core::trust::validate_chain` cryptographically verify every link of an X.509 chain up to a configured trust anchor, replacing the current Distinguished-Name string walk.

**Architecture:** Path validation is delegated to OpenSSL's `X509_STORE_CTX`, which is already linked into every foundry build transitively via `josekit`. `TrustStore` gains an internal `openssl::x509::store::X509Store` built from the configured anchor PEMs; `validate_chain` keeps its exact signature and maps OpenSSL verify codes onto `TrustError`. The `x509-cert` crate is retained for all certificate *inspection* helpers — the division is "`x509-cert` inspects, OpenSSL validates".

**Tech Stack:** Rust 2021, `openssl` 0.10 (new direct dependency), `x509-cert` 0.3 (retained), `rcgen` 0.14 (test chain generation, already a dependency), `thiserror`.

**Design doc:** `docs/superpowers/specs/2026-08-04-trust-chain-signature-verification-design.md`

## Global Constraints

- **No opt-out.** There is no configuration flag to weaken, warn instead of fail, or bypass verification. Hard cutover, fail closed. (Design: "Rollout posture: hard cutover".)
- **`validate_chain`'s signature does not change:** `pub fn validate_chain(leaf_pem: &[u8], intermediates: &[Vec<u8>], store: &TrustStore, now_unix: u64) -> Result<(), TrustError>`. Six production call sites depend on it and must not be edited.
- **`TrustStore::from_pems`, `TrustStore::from_config`, `TrustStore::is_empty` keep their existing signatures.**
- **AGENTS.md §4.1 — no panics in library code.** No `.unwrap()`, `.expect()`, `panic!()`, or `unreachable!()` anywhere in `src/`. Permitted only inside `#[cfg(test)]` and files under `tests/`.
- **AGENTS.md §4.5 — nothing sensitive logged.** `trust/` emits no log records at all; it returns typed errors. Never log certificate bytes, Distinguished Names, or public keys.
- **Verification time is always the caller's `now_unix`,** never the system clock.
- **Verification purpose is left unset** (no `set_purpose` call). Setting one enables Extended Key Usage checks, and Android attestation certificates carry no EKU.
- **RSA is added for certificate-signature verification only.** `foundry_core::crypto::SignatureAlgorithm` stays EC-only and keeps rejecting `RS256`. Do not add RSA JOSE signing.
- **Scoped gate for every task** (AGENTS.md §5.1/§5.2). `foundry-core/trust` is consumed by every crate, so the affected set is: `cargo test -p foundry-core -p foundry-sd-jwt-vc -p foundry-mdoc -p foundry-issuer -p foundry-verifier -p foundry`. **Never run `cargo test --workspace`** and never run the `#[ignore]`d `e2e_full_flow` suite; those belong to the §5.3 full gate at the end of the branch.
- **Pinned fixture time:** `1767225600` (2026-01-01T00:00:00Z). Used for all Android-fixture assertions. Chosen because both TEE intermediates are valid 2022-03-20 → 2032-03-17.

---

## File Structure

| File | Responsibility |
|---|---|
| `Cargo.toml` (workspace root) | Declare `openssl = "0.10"` in `[workspace.dependencies]` |
| `crates/foundry-core/Cargo.toml` | Consume `openssl = { workspace = true }` |
| `crates/foundry-core/src/error.rs` | Add `TrustError::InvalidSignature` |
| `crates/foundry-core/src/trust/mod.rs` | `TrustStore` holds an `X509Store`; `validate_chain` delegates to OpenSSL; verify-code → `TrustError` mapping. All existing `x509-cert` inspection helpers unchanged. |
| `crates/foundry-core/tests/trust_chain_verification.rs` | **New.** All new behavioural tests for chain verification. |
| `crates/foundry-core/tests/fixtures/android-attestation/*.pem` | **Already committed.** Real 4-certificate Google chain. |
| `crates/foundry-core/AGENTS.md` | Gotchas: the `x509-cert`/OpenSSL split, and why purpose is unset |
| `docs/conformance/openid4vc-conformance.md` | Correct the four overstated rows; resolve three `ambiguous` rows |

New tests go in a **new integration test file** rather than into `src/trust/mod.rs`'s existing `#[cfg(test)] mod tests`, for two reasons: the fixture-based tests need `tests/fixtures/` relative paths, and `trust/mod.rs` is already ~450 lines with a large inline test module. The existing unit tests stay exactly where they are and must not be edited.

---

### Task 1: Replace the DN walk with OpenSSL path validation

This is the core change. Setup (dependency, error variant) is folded in because the deliverable cannot be tested without it.

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]`)
- Modify: `crates/foundry-core/Cargo.toml`
- Modify: `crates/foundry-core/src/error.rs:46-65` (the `TrustError` enum)
- Modify: `crates/foundry-core/src/trust/mod.rs` (imports, `TrustStore`, `validate_chain`)
- Test: `crates/foundry-core/tests/trust_chain_verification.rs` (create)

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `TrustError::InvalidSignature` — unit variant, `Display` = `"certificate signature verification failed"`.
  - `TrustStore` — unchanged public API: `from_pems(&[Vec<u8>]) -> Result<Self, TrustError>`, `from_config(&[TrustAnchor]) -> Result<Self, TrustError>`, `is_empty(&self) -> bool`. Internally now holds `openssl::x509::store::X509Store`.
  - `validate_chain(leaf_pem: &[u8], intermediates: &[Vec<u8>], store: &TrustStore, now_unix: u64) -> Result<(), TrustError>` — signature unchanged, behaviour now cryptographic.

- [ ] **Step 1: Write the failing test file**

Create `crates/foundry-core/tests/trust_chain_verification.rs`:

```rust
//! Behavioural tests for cryptographic X.509 chain verification.
//!
//! Design: docs/superpowers/specs/2026-08-04-trust-chain-signature-verification-design.md
//!
//! These are integration tests (not unit tests in `src/trust/mod.rs`) because
//! several of them load PEM fixtures from `tests/fixtures/`.

use foundry_core::error::TrustError;
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::trust::{validate_chain, TrustStore};

/// Wall-clock now, for chains generated during the test run.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

/// Re-encode `pem` with one byte of the subject Common Name flipped.
///
/// The mutation is inside `tbsCertificate` and is length-preserving, so the DER
/// still parses; only the issuer's signature over the body no longer matches.
/// This is what makes the expected error specifically `InvalidSignature` rather
/// than a path-building failure.
fn corrupt_subject_cn(pem: &[u8], cn: &str) -> Vec<u8> {
    let cert = openssl::x509::X509::from_pem(pem).expect("fixture parses");
    let mut der = cert.to_der().expect("cert re-encodes to DER");
    let needle = cn.as_bytes();
    let pos = der
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the Common Name must appear verbatim in the DER");
    // Flip one character of the CN, preserving length.
    der[pos] = if der[pos] == b'z' { b'y' } else { b'z' };
    openssl::x509::X509::from_der(&der)
        .expect("mutated DER still parses")
        .to_pem()
        .expect("mutated cert re-encodes to PEM")
}

#[test]
fn tampered_certificate_body_is_rejected_as_invalid_signature() {
    let ca = new_ca("Foundry Test Root CA", 3650).expect("generate CA");
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "zzz.test.local",
        &["zzz.test.local".to_string()],
        365,
    )
    .expect("issue leaf");
    let store = TrustStore::from_pems(&[ca.cert_pem.clone().into_bytes()]).expect("build store");

    // Positive control: the untouched chain must validate. Without this, a
    // rejection below would prove only that *something* is broken.
    validate_chain(leaf.cert_pem.as_bytes(), &[], &store, now_secs())
        .expect("the genuine chain must validate");

    let tampered = corrupt_subject_cn(leaf.cert_pem.as_bytes(), "zzz.test.local");
    let err = validate_chain(&tampered, &[], &store, now_secs())
        .expect_err("a tampered certificate body must be rejected");
    assert!(
        matches!(err, TrustError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn leaf_signed_by_an_impostor_ca_with_an_identical_dn_is_rejected() {
    // This is the vulnerability this work closes. Two CAs share a Distinguished
    // Name but hold different keys. The pre-change `validate_chain` walked DN
    // strings only, so impersonating an anchor required nothing but spelling
    // its DN correctly.
    let genuine = new_ca("Foundry Dev Root CA", 3650).expect("generate genuine CA");
    let impostor = new_ca("Foundry Dev Root CA", 3650).expect("generate impostor CA");

    let forged = issue_leaf(
        &impostor.cert_pem,
        &impostor.key_pem,
        "forged.test.local",
        &["forged.test.local".to_string()],
        365,
    )
    .expect("issue forged leaf");

    let store = TrustStore::from_pems(&[genuine.cert_pem.clone().into_bytes()]).expect("store");

    let err = validate_chain(forged.cert_pem.as_bytes(), &[], &store, now_secs())
        .expect_err("a leaf signed by an impostor CA must be rejected");
    // `issue_leaf` sets an Authority Key Identifier, so OpenSSL cannot even
    // select the genuine CA as a candidate issuer; the failure surfaces as a
    // path-building error rather than a signature error. Either is a correct
    // rejection.
    assert!(
        matches!(
            err,
            TrustError::UntrustedChain | TrustError::InvalidSignature
        ),
        "expected UntrustedChain or InvalidSignature, got {err:?}"
    );

    // Positive control: a leaf genuinely signed by the trusted CA validates.
    let good = issue_leaf(
        &genuine.cert_pem,
        &genuine.key_pem,
        "good.test.local",
        &["good.test.local".to_string()],
        365,
    )
    .expect("issue genuine leaf");
    validate_chain(good.cert_pem.as_bytes(), &[], &store, now_secs())
        .expect("a genuinely signed leaf must validate");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry-core --test trust_chain_verification
```

Expected: **compile error** — `TrustError::InvalidSignature` does not exist yet, and `openssl` is not a dependency of `foundry-core`. That compile failure is the correct starting state; do not work around it by weakening the test.

- [ ] **Step 3: Add the `openssl` dependency**

In the workspace root `Cargo.toml`, add to `[workspace.dependencies]` (keep the existing alphabetical-ish grouping; place it after `josekit`):

```toml
openssl = "0.10"
```

In `crates/foundry-core/Cargo.toml`, add to `[dependencies]` after `josekit`:

```toml
openssl = { workspace = true }
```

No feature flags. This introduces **no new native linkage**: `openssl-sys` is already built for every foundry target because `josekit` depends on it.

- [ ] **Step 4: Add the `InvalidSignature` error variant**

In `crates/foundry-core/src/error.rs`, inside `pub enum TrustError`, add the variant after `Expired` and before `UntrustedChain`:

```rust
    #[error("certificate signature verification failed")]
    InvalidSignature,
```

Distinct from `UntrustedChain` deliberately: `UntrustedChain`'s message is *"no configured trust anchor matches the certificate chain"*, which would misdirect an operator to audit their anchor bundle when the real finding is a tampered chain. Per AGENTS.md §4.5, operator-facing diagnostics are API.

- [ ] **Step 5: Rewrite `TrustStore` and `validate_chain`**

In `crates/foundry-core/src/trust/mod.rs`:

Add these imports below the existing ones:

```rust
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509StoreContext, X509 as OsslX509};
```

Add the OpenSSL verify-code constants near the top of the file, after the `pub use x509_cert::Certificate;` line:

```rust
// OpenSSL verification result codes, from `include/openssl/x509_vfy.h`. These
// are a stable part of OpenSSL's ABI. Declared locally rather than pulling in
// `openssl-sys` as a second direct dependency; `X509VerifyResult::from_raw` is
// `unsafe`, so classification reads `as_raw()` and compares integers instead.
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: i32 = 2;
const X509_V_ERR_CERT_SIGNATURE_FAILURE: i32 = 7;
const X509_V_ERR_CERT_NOT_YET_VALID: i32 = 9;
const X509_V_ERR_CERT_HAS_EXPIRED: i32 = 10;
const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: i32 = 18;
const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: i32 = 19;
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: i32 = 20;
const X509_V_ERR_INVALID_CA: i32 = 24;
const X509_V_ERR_PATH_LENGTH_EXCEEDED: i32 = 25;
const X509_V_ERR_KEYUSAGE_NO_CERTSIGN: i32 = 32;
```

Replace the `TrustStore` struct and its `impl` block. Keep `from_config` reading files exactly as it does today; only the terminal `Self::from_pems` construction changes:

```rust
/// A set of trust-anchor certificates, held as an OpenSSL certificate store.
///
/// `X509Store` is `Send + Sync` (declared via `foreign_type_and_impl_send_sync!`
/// in `openssl::x509::store`), which this type relies on: `TrustStore` is built
/// and held across `.await` points in `foundry-issuer`'s `token.rs` and
/// `credential.rs`.
pub struct TrustStore {
    store: X509Store,
    anchor_count: usize,
}

impl TrustStore {
    pub fn from_pems(pems: &[Vec<u8>]) -> Result<Self, TrustError> {
        let mut builder =
            X509StoreBuilder::new().map_err(|e| TrustError::Parse(e.to_string()))?;

        // A configured anchor may be an intermediate rather than a self-signed
        // root -- foundry has always allowed this. PARTIAL_CHAIN is what lets
        // OpenSSL stop at such an anchor instead of insisting on reaching a
        // self-signed certificate.
        builder
            .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
            .map_err(|e| TrustError::Parse(e.to_string()))?;

        let mut anchor_count = 0;
        for pem in pems {
            // Parse with x509-cert first so malformed input yields the same
            // TrustError::Parse it always has.
            parse_cert_pem(pem)?;
            let cert = OsslX509::from_pem(pem).map_err(|e| TrustError::Parse(e.to_string()))?;
            builder
                .add_cert(cert)
                .map_err(|e| TrustError::Parse(e.to_string()))?;
            anchor_count += 1;
        }

        Ok(Self {
            store: builder.build(),
            anchor_count,
        })
    }

    pub fn from_config(anchors: &[crate::config::TrustAnchor]) -> Result<Self, TrustError> {
        let mut pems = Vec::new();
        for anchor in anchors {
            let content =
                std::fs::read_to_string(&anchor.certs).map_err(|e| TrustError::CertRead {
                    path: anchor.certs.clone(),
                    source: e,
                })?;
            for block in content.split("-----BEGIN CERTIFICATE-----") {
                let trimmed = block.trim();
                if !trimmed.is_empty() {
                    let pem = format!("-----BEGIN CERTIFICATE-----\n{}", trimmed);
                    pems.push(pem.into_bytes());
                }
            }
        }
        Self::from_pems(&pems)
    }

    pub fn is_empty(&self) -> bool {
        self.anchor_count == 0
    }
}
```

Replace `validate_chain` entirely (delete the DN walk and the `TODO(trust-hardening)` comment):

```rust
/// Validate a leaf (+ optional intermediates) against the trust store.
///
/// Every link's signature is verified and RFC 5280 CA constraints are enforced
/// by OpenSSL: `basicConstraints: CA:TRUE` and `keyUsage: keyCertSign` on every
/// non-leaf, `pathLenConstraint`, validity windows, and Authority/Subject Key
/// Identifier path building.
///
/// Verification purpose is deliberately **not** set. Setting one enables
/// Extended Key Usage checks, and Android key-attestation certificates carry no
/// EKU at all -- setting a purpose here would reject every Google Wallet chain.
pub fn validate_chain(
    leaf_pem: &[u8],
    intermediates: &[Vec<u8>],
    store: &TrustStore,
    now_unix: u64,
) -> Result<(), TrustError> {
    // Retained ahead of OpenSSL: HAIP-0040/0080/0085 assert this specific
    // variant, and OpenSSL reports the case with a less specific code.
    let leaf = parse_cert_pem(leaf_pem)?;
    if is_self_signed(&leaf) {
        return Err(TrustError::SelfSignedLeaf);
    }

    let leaf_ossl = OsslX509::from_pem(leaf_pem).map_err(|e| TrustError::Parse(e.to_string()))?;

    let mut chain: Stack<OsslX509> =
        Stack::new().map_err(|e| TrustError::Parse(e.to_string()))?;
    for pem in intermediates {
        let parsed = parse_cert_pem(pem)?;
        // A presented root is never trusted: the anchor must come from
        // configuration. This is defence-in-depth -- OpenSSL already refuses to
        // bootstrap trust from a self-signed certificate in the untrusted set
        // (X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) -- but dropping it here makes
        // the intent explicit and yields a more accurate error when no anchor is
        // configured. Google Wallet transmits the Android root inside the chain.
        if is_self_signed(&parsed) {
            continue;
        }
        let cert = OsslX509::from_pem(pem).map_err(|e| TrustError::Parse(e.to_string()))?;
        chain
            .push(cert)
            .map_err(|e| TrustError::Parse(e.to_string()))?;
    }

    // Validity is evaluated at the caller's instant, never the system clock:
    // callers pass synthetic times (see `expired_leaf_is_rejected`).
    let mut param = X509VerifyParam::new().map_err(|e| TrustError::Parse(e.to_string()))?;
    param.set_time(now_unix as i64);
    param
        .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|e| TrustError::Parse(e.to_string()))?;

    let mut builder = X509StoreBuilder::new().map_err(|e| TrustError::Parse(e.to_string()))?;
    builder
        .set_param(&param)
        .map_err(|e| TrustError::Parse(e.to_string()))?;

    let mut ctx = X509StoreContext::new().map_err(|e| TrustError::Parse(e.to_string()))?;
    let verified = ctx
        .init(&store.store, &leaf_ossl, &chain, |ctx| {
            let ok = ctx.verify_cert()?;
            Ok((ok, ctx.error().as_raw()))
        })
        .map_err(|e| TrustError::Parse(e.to_string()))?;

    match verified {
        (true, _) => Ok(()),
        (false, code) => Err(map_verify_error(code)),
    }
}

/// Translate an OpenSSL verification result code into a `TrustError`.
fn map_verify_error(code: i32) -> TrustError {
    match code {
        X509_V_ERR_CERT_HAS_EXPIRED | X509_V_ERR_CERT_NOT_YET_VALID => TrustError::Expired,
        X509_V_ERR_CERT_SIGNATURE_FAILURE => TrustError::InvalidSignature,
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
        | X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        | X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        | X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        | X509_V_ERR_INVALID_CA
        | X509_V_ERR_PATH_LENGTH_EXCEEDED
        | X509_V_ERR_KEYUSAGE_NO_CERTSIGN => TrustError::UntrustedChain,
        _ => TrustError::UntrustedChain,
    }
}
```

> **Note on `set_param`:** the verify parameters must be applied to the store the
> context is initialised with. `TrustStore` builds its own store with
> `PARTIAL_CHAIN` at construction time, but the per-call time cannot be baked in
> there. If `builder` above (which has the param but no anchors) turns out not to
> influence the verification because `ctx.init` is given `&store.store`, apply
> the param to the *context* instead — `X509StoreContextRef` exposes
> `verify_param_mut()`. Step 6 is what tells you which is the case: if
> `expired_leaf_is_rejected` fails, the time is not being applied, and the param
> must move onto the context inside the `init` closure:
> ```rust
> .init(&store.store, &leaf_ossl, &chain, |ctx| {
>     ctx.verify_param_mut().set_time(now_unix as i64);
>     ctx.verify_param_mut().set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
>     let ok = ctx.verify_cert()?;
>     Ok((ok, ctx.error().as_raw()))
> })
> ```
> Prefer this second form if both work — it keeps per-call state out of the
> shared store. Delete the unused `builder`/`param` block if you take it.

- [ ] **Step 6: Run the new tests and the existing trust unit tests**

```bash
cargo test -p foundry-core --test trust_chain_verification
cargo test -p foundry-core trust::
```

Expected: both new tests PASS, and all pre-existing `trust::tests::*` unit tests still PASS unchanged — in particular `expired_leaf_is_rejected` (proves `now_unix` is honoured, not the system clock), `self_signed_leaf_is_rejected`, `untrusted_anchor_is_rejected`, `valid_leaf_against_anchor_passes`.

If `expired_leaf_is_rejected` fails, apply the `verify_param_mut()` variant from Step 5's note.

- [ ] **Step 7: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-sd-jwt-vc -p foundry-mdoc \
           -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

Expected: all green. Every downstream suite generates its chains with `rcgen`, which signs properly, so they should pass unchanged. **A failure here is a real finding about that call site's fixtures — investigate it, do not relax the test.**

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock crates/foundry-core/Cargo.toml \
        crates/foundry-core/src/error.rs crates/foundry-core/src/trust/mod.rs \
        crates/foundry-core/tests/trust_chain_verification.rs
git commit -m "feat(core): cryptographically verify X.509 trust chains

validate_chain walked issuer/subject DN strings, so impersonating a trust
anchor required only spelling its DN correctly. Path validation now goes
through OpenSSL X509_STORE_CTX, which verifies every link's signature and
enforces CA:TRUE, keyCertSign and pathLen. Verification time is the caller's
now_unix; purpose is deliberately unset so EKU-less Android attestation certs
still validate.

Adds TrustError::InvalidSignature so a tampered chain is not reported as an
anchor-configuration problem."
```

---

### Task 2: Golden Android chain, and a presented root grants nothing

**Files:**
- Modify: `crates/foundry-core/tests/trust_chain_verification.rs` (append)
- Read-only: `crates/foundry-core/tests/fixtures/android-attestation/{leaf,intermediate-tee-p256,intermediate-tee-p384,root-rsa4096}.pem` (already committed)

**Interfaces:**
- Consumes: `validate_chain`, `TrustStore::from_pems`, `TrustError` from Task 1.
- Produces: no new API.

This is the interop proof. One test exercises RSA-4096 verification, a P-384 issuer key signing with SHA-256, in-chain root filtering, and a 1970→2106 leaf validity window simultaneously.

- [ ] **Step 1: Write the failing tests**

Append to `crates/foundry-core/tests/trust_chain_verification.rs`:

```rust
/// A real Android Keystore attestation chain, captured from Google Wallet.
///
/// Structure (verified with `openssl verify`):
///   leaf            CN=Android Keystore Key   EC P-256, sig ecdsa-with-SHA256
///   intermediate-1  title=TEE, serial=58eb..  EC P-256, sig ecdsa-with-SHA256
///   intermediate-2  title=TEE, serial=3fb6..  EC P-384, sig sha256WithRSAEncryption
///   root            serial=f92009e853b6b045   RSA 4096, self-signed
///
/// Note intermediate-1 carries a P-256 key but is signed by intermediate-2's
/// P-384 key using SHA-256 -- the digest is not derivable from the key curve.
const ANDROID_LEAF: &[u8] = include_bytes!("fixtures/android-attestation/leaf.pem");
const ANDROID_INT_P256: &[u8] =
    include_bytes!("fixtures/android-attestation/intermediate-tee-p256.pem");
const ANDROID_INT_P384: &[u8] =
    include_bytes!("fixtures/android-attestation/intermediate-tee-p384.pem");
const ANDROID_ROOT: &[u8] = include_bytes!("fixtures/android-attestation/root-rsa4096.pem");

/// 2026-01-01T00:00:00Z. Pinned so the fixture assertions cannot rot: both TEE
/// intermediates are valid 2022-03-20 -> 2032-03-17.
const ANDROID_PINNED_NOW: u64 = 1_767_225_600;

/// The chain exactly as Google transmits it: leaf first, root included last.
fn android_presented_intermediates() -> Vec<Vec<u8>> {
    vec![
        ANDROID_INT_P256.to_vec(),
        ANDROID_INT_P384.to_vec(),
        ANDROID_ROOT.to_vec(),
    ]
}

#[test]
fn real_android_attestation_chain_validates_against_the_configured_google_root() {
    let store = TrustStore::from_pems(&[ANDROID_ROOT.to_vec()]).expect("build store");
    validate_chain(
        ANDROID_LEAF,
        &android_presented_intermediates(),
        &store,
        ANDROID_PINNED_NOW,
    )
    .expect("the real Android attestation chain must validate");
}

#[test]
fn presented_android_root_grants_nothing_without_a_configured_anchor() {
    // The full chain is presented, root included -- but the only configured
    // anchor is unrelated. Trust must not be bootstrappable from a certificate
    // the caller supplied.
    let unrelated = new_ca("Unrelated Root CA", 3650).expect("generate unrelated CA");
    let store = TrustStore::from_pems(&[unrelated.cert_pem.into_bytes()]).expect("store");

    let err = validate_chain(
        ANDROID_LEAF,
        &android_presented_intermediates(),
        &store,
        ANDROID_PINNED_NOW,
    )
    .expect_err("a presented root must not establish trust");
    assert!(
        matches!(err, TrustError::UntrustedChain),
        "expected UntrustedChain, got {err:?}"
    );
}

#[test]
fn android_chain_is_rejected_outside_the_intermediate_validity_window() {
    // 2035-01-01T00:00:00Z -- past both TEE intermediates' 2032 notAfter,
    // though still inside the leaf's absurd 2106 window. Proves the whole path
    // is time-checked, not just the leaf.
    const AFTER_INTERMEDIATES_EXPIRE: u64 = 2_051_222_400;
    let store = TrustStore::from_pems(&[ANDROID_ROOT.to_vec()]).expect("build store");
    let err = validate_chain(
        ANDROID_LEAF,
        &android_presented_intermediates(),
        &store,
        AFTER_INTERMEDIATES_EXPIRE,
    )
    .expect_err("an expired intermediate must be rejected");
    assert!(
        matches!(err, TrustError::Expired),
        "expected Expired, got {err:?}"
    );
}
```

- [ ] **Step 2: Run the tests to verify current behaviour**

```bash
cargo test -p foundry-core --test trust_chain_verification
```

Expected: all three PASS if Task 1 is correct. If `real_android_attestation_chain_validates_against_the_configured_google_root` fails, the likely causes in order are: a purpose was set somewhere (must not be), `PARTIAL_CHAIN` is missing, or the self-signed filtering dropped a certificate it should have kept. Diagnose by printing `err` — the `TrustError` variant distinguishes these.

- [ ] **Step 3: Verify the fixtures independently of the Rust code**

```bash
cd crates/foundry-core/tests/fixtures/android-attestation
openssl verify -attime 1767225600 -CAfile root-rsa4096.pem \
  -untrusted intermediate-tee-p384.pem -untrusted intermediate-tee-p256.pem leaf.pem
```

Expected: `leaf.pem: OK`. This is the independent oracle — if OpenSSL's CLI accepts the chain but `validate_chain` does not, the defect is in foundry's wiring, not the fixtures.

- [ ] **Step 4: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-sd-jwt-vc -p foundry-mdoc \
           -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/tests/trust_chain_verification.rs
git commit -m "test(core): golden Android attestation chain validation

Pins the real four-certificate Google Wallet chain as the interop oracle:
RSA-4096 root, a P-384 issuer key signing with SHA-256, the root presented
in-chain, and a 1970-2106 leaf window. Adds the companion negative -- a
presented root establishes no trust when the configured anchor is unrelated --
and a whole-path expiry check using the intermediates' 2032 notAfter."
```

---

### Task 3: CA constraint enforcement (privilege escalation)

**Files:**
- Modify: `crates/foundry-core/tests/trust_chain_verification.rs` (append)

**Interfaces:**
- Consumes: `validate_chain`, `TrustStore`, `TrustError`, `new_ca`, `issue_leaf`.
- Produces: no new API.

Characterization tests. No production change is expected — OpenSSL enforces this already (observed: `error 79 invalid CA certificate` and `error 32 key usage does not include certificate signing`). The tests exist to pin the behaviour so a future flag change cannot silently remove it.

`issue_leaf` produces certificates with `IsCa::NoCa` and `keyUsage: DigitalSignature` only, so using its output as an issuer is exactly the escalation being tested.

- [ ] **Step 1: Write the failing tests**

Append to `crates/foundry-core/tests/trust_chain_verification.rs`:

```rust
#[test]
fn a_non_ca_certificate_cannot_act_as_an_intermediate() {
    // `issue_leaf` emits IsCa::NoCa with keyUsage: DigitalSignature only. Using
    // it to sign another certificate is the privilege escalation that DN-only
    // path building permitted: any holder of a chained leaf could mint leaves.
    let root = new_ca("Escalation Test Root CA", 3650).expect("generate root");
    let non_ca = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "notaca.test.local",
        &["notaca.test.local".to_string()],
        3650,
    )
    .expect("issue non-CA certificate");

    let forged = issue_leaf(
        &non_ca.cert_pem,
        &non_ca.key_pem,
        "escalated.test.local",
        &["escalated.test.local".to_string()],
        365,
    )
    .expect("issue leaf under the non-CA certificate");

    let store = TrustStore::from_pems(&[root.cert_pem.clone().into_bytes()]).expect("store");

    let err = validate_chain(
        forged.cert_pem.as_bytes(),
        &[non_ca.cert_pem.clone().into_bytes()],
        &store,
        now_secs(),
    )
    .expect_err("a chain through a non-CA certificate must be rejected");
    assert!(
        matches!(err, TrustError::UntrustedChain),
        "expected UntrustedChain, got {err:?}"
    );

    // Positive control: a leaf signed directly by the real CA validates against
    // the same store. Without this, the rejection above could be caused by
    // anything.
    let legitimate = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "legit.test.local",
        &["legit.test.local".to_string()],
        365,
    )
    .expect("issue legitimate leaf");
    validate_chain(legitimate.cert_pem.as_bytes(), &[], &store, now_secs())
        .expect("a leaf signed by the real CA must validate");
}
```

> If `issue_leaf` refuses to use a non-CA certificate as an issuer (rcgen's
> `Issuer::from_ca_cert_pem` may reject it), generate the fixture chain with
> OpenSSL instead, commit it under
> `crates/foundry-core/tests/fixtures/non-ca-intermediate/`, and load it with
> `include_bytes!`. The generation commands, verified to produce the intended
> rejection:
> ```bash
> openssl ecparam -name prime256v1 -genkey -noout -out root.key
> openssl req -new -x509 -key root.key -out root.pem -days 3650 \
>   -subj "/CN=Escalation Test Root" \
>   -addext "basicConstraints=critical,CA:TRUE" \
>   -addext "keyUsage=critical,keyCertSign,cRLSign"
> openssl ecparam -name prime256v1 -genkey -noout -out nonca.key
> openssl req -new -key nonca.key -out nonca.csr -subj "/CN=Not A CA"
> printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n" > nonca.ext
> openssl x509 -req -in nonca.csr -CA root.pem -CAkey root.key -out nonca.pem \
>   -days 3650 -extfile nonca.ext -set_serial 2
> openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
> openssl req -new -key leaf.key -out leaf.csr -subj "/CN=Escalated Leaf"
> openssl x509 -req -in leaf.csr -CA nonca.pem -CAkey nonca.key -out leaf.pem \
>   -days 3650 -set_serial 3
> ```
> Pin `now_unix` for those fixtures rather than using `now_secs()`.

- [ ] **Step 2: Run the test**

```bash
cargo test -p foundry-core --test trust_chain_verification::a_non_ca_certificate_cannot_act_as_an_intermediate
```

Expected: PASS. If it fails with the forged chain being *accepted*, OpenSSL's CA checks are not running — verify that no `X509VerifyFlags` value was set that disables them and that `PARTIAL_CHAIN` was not confused with `NO_CHECK_TIME`.

- [ ] **Step 3: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-sd-jwt-vc -p foundry-mdoc \
           -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-core/tests/trust_chain_verification.rs
git commit -m "test(core): pin CA:TRUE and keyCertSign enforcement

A certificate with basicConstraints CA:FALSE and keyUsage DigitalSignature
must not be usable as an intermediate. Includes the positive control so the
rejection is attributable."
```

---

### Task 4: Anchor-as-intermediate and curve coverage

**Files:**
- Modify: `crates/foundry-core/tests/trust_chain_verification.rs` (append)

**Interfaces:**
- Consumes: `validate_chain`, `TrustStore`, and `rcgen`'s `CertificateParams` / `KeyPair` / `Issuer` API directly (`rcgen` is a normal dependency of `foundry-core`, so integration tests may use it).
- Produces: no new API.

Two regression guards. The first pins `PARTIAL_CHAIN` — without it, an anchor bundle that names an intermediate stops working, and nothing else in the suite would catch that. The second covers more than one curve.

**Curve coverage is P-256 and P-384 only, deliberately.** `foundry_core::pki::new_ca` and `issue_leaf` both call `rcgen::KeyPair::generate()`, which hardcodes `PKCS_ECDSA_P256_SHA256` — a loop over those helpers would test P-256 three times while appearing to test three curves. This test therefore drives `rcgen` directly with explicit algorithms. P-521 is **not** covered: `rcgen::PKCS_ECDSA_P521_SHA512` is gated behind `#[cfg(feature = "aws_lc_rs")]` and foundry builds rcgen with default features (`ring`), so the symbol does not exist in this build. That is a fixture limitation, not a foundry gap — OpenSSL verifies P-521 natively and `cert_ec_public_coords` already handles P-521 SPKIs. Do not enable `aws_lc_rs` to get this test; it would switch the crypto backend of the whole workspace.

- [ ] **Step 1: Write the tests**

Append to `crates/foundry-core/tests/trust_chain_verification.rs`:

```rust
#[test]
fn an_intermediate_pinned_as_the_anchor_validates_the_leaf() {
    // foundry has always allowed a configured anchor to be a non-self-signed
    // certificate. This is what X509VerifyFlags::PARTIAL_CHAIN buys; without it
    // OpenSSL insists on reaching a self-signed root and this test fails.
    //
    // The real Android chain provides a ready-made three-level path: pin the
    // P-384 TEE intermediate as the sole anchor and present only the P-256 one.
    let store = TrustStore::from_pems(&[ANDROID_INT_P384.to_vec()]).expect("store");
    validate_chain(
        ANDROID_LEAF,
        &[ANDROID_INT_P256.to_vec()],
        &store,
        ANDROID_PINNED_NOW,
    )
    .expect("an intermediate pinned as the anchor must validate the leaf");
}

/// Build a self-signed CA and a leaf it signs, both keyed on `alg`.
///
/// Driven through `rcgen` directly rather than `foundry_core::pki`, because
/// `pki::new_ca`/`issue_leaf` call `KeyPair::generate()`, which is hardcoded to
/// `PKCS_ECDSA_P256_SHA256`. Returns `(ca_pem, leaf_pem)`.
fn ca_and_leaf_on(alg: &'static rcgen::SignatureAlgorithm, cn: &str) -> (String, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use time::{Duration, OffsetDateTime};

    let now = OffsetDateTime::now_utc();

    let ca_key = KeyPair::generate_for(alg).expect("generate CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, format!("{cn} Root CA"));
    ca_params.distinguished_name = ca_dn;
    ca_params.not_before = now - Duration::days(1);
    ca_params.not_after = now + Duration::days(3650);
    let ca_pem = ca_params.self_signed(&ca_key).expect("self-sign CA").pem();

    // `Issuer::from_ca_cert_pem` takes the signing key by value.
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).expect("build issuer");
    let leaf_key = KeyPair::generate_for(alg).expect("generate leaf key");
    let mut leaf_params = CertificateParams::new(vec![cn.to_string()]).expect("leaf params");
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, cn);
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - Duration::days(1);
    leaf_params.not_after = now + Duration::days(365);
    let leaf_pem = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign leaf")
        .pem();

    (ca_pem, leaf_pem)
}

#[test]
fn chains_on_p256_and_p384_validate() {
    // P-521 is intentionally absent: rcgen's PKCS_ECDSA_P521_SHA512 requires the
    // aws_lc_rs backend and foundry builds rcgen with default features (ring).
    // OpenSSL verifies P-521 natively, so this is a fixture limitation only.
    for (label, alg) in [
        ("p256", &rcgen::PKCS_ECDSA_P256_SHA256),
        ("p384", &rcgen::PKCS_ECDSA_P384_SHA384),
    ] {
        let cn = format!("{label}.curve.test.local");
        let (ca_pem, leaf_pem) = ca_and_leaf_on(alg, &cn);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()])
            .unwrap_or_else(|e| panic!("build store for {label}: {e}"));
        validate_chain(leaf_pem.as_bytes(), &[], &store, now_secs())
            .unwrap_or_else(|e| panic!("{label} chain must validate: {e}"));
    }
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo test -p foundry-core --test trust_chain_verification
```

Expected: all PASS. If `an_intermediate_pinned_as_the_anchor_validates_the_leaf` fails with `UntrustedChain`, `PARTIAL_CHAIN` is not reaching the verification — re-check Step 5 of Task 1.

- [ ] **Step 3: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-sd-jwt-vc -p foundry-mdoc \
           -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-core/tests/trust_chain_verification.rs
git commit -m "test(core): pin PARTIAL_CHAIN and multi-curve chain validation

An anchor bundle naming an intermediate must keep working, and both P-256 and
P-384 chains must validate. P-521 is not covered: rcgen's P-521 algorithms need
the aws_lc_rs backend and foundry builds rcgen with ring."
```

---

### Task 5: Documentation corrections

**Files:**
- Modify: `docs/conformance/openid4vc-conformance.md` (rows VCI-0231, HAIP-0031, HAIP-0082, HAIP-0083, HAIP-0039, HAIP-0079, HAIP-0084)
- Modify: `crates/foundry-core/AGENTS.md` (Gotchas section)

**Interfaces:**
- Consumes: the completed implementation from Tasks 1–4.
- Produces: no code.

The conformance report currently claims cryptographic trust from a function that compared strings. This task makes the record accurate. Read `docs/conformance/openid4vc-conformance.md`'s header first — it is a **living document** whose internal consistency is enforced by `crates/foundry/tests/conformance_report.rs`.

- [ ] **Step 1: Correct the four overstated rows**

For each of **VCI-0231**, **HAIP-0031**, **HAIP-0082**, **HAIP-0083**, the verdict stays `conforming` but the evidence text must state what is now actually verified. Replace vague phrasing like "the chain is checked against `trusted_anchors`" with, adapted per row:

> `validate_chain` (foundry-core `trust/mod.rs`) verifies every link's signature via OpenSSL `X509_STORE_CTX` and enforces `basicConstraints: CA:TRUE`, `keyUsage: keyCertSign` and `pathLenConstraint`, building the path to a configured anchor by Authority/Subject Key Identifier. Closed 2026-08-04: prior to that date the function compared Distinguished-Name strings only, so these rows overstated the property.

Cite the covering test `real_android_attestation_chain_validates_against_the_configured_google_root` or `tampered_certificate_body_is_rejected_as_invalid_signature` in the test column, matching the format used by neighbouring rows.

- [ ] **Step 2: Resolve the three `ambiguous` rows**

**HAIP-0039**, **HAIP-0079**, **HAIP-0084** ("The X.509 certificate of the trust anchor MUST NOT be included in the `x5c` JOSE header"). These were `ambiguous` because `validate_chain` ignored a redundantly-presented anchor. Give them a definite verdict with this evidence:

> `validate_chain` discards self-signed certificates from the presented intermediates, so a transmitted root is never used to establish trust; OpenSSL independently rejects such a chain with `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN` when no matching anchor is configured. A redundantly-presented *non*-self-signed anchor is accepted but ignored — receiver-side enforcement of a sender-side MUST, which HAIP does not require. Covering test: `presented_android_root_grants_nothing_without_a_configured_anchor`.

Choose the verdict consistent with the report's existing conventions for "sender-side MUST, receiver does not enforce" — check how comparable rows are labelled before picking, and keep the `Unresolved Ambiguities` section in sync if these rows are referenced there.

- [ ] **Step 3: Add the AGENTS.md Gotchas entry**

Append to the Gotchas section of `crates/foundry-core/AGENTS.md`:

```markdown
- **`trust/` uses two X.509 libraries on purpose.** `x509-cert` *inspects*
  (parsing, DNs, validity windows, SANs, SPKI coordinates, `x5c` encoding);
  OpenSSL *validates* (`validate_chain` path validation). Do not migrate one to
  the other — `x509-cert` is needed for Android key-attestation extension
  parsing, and OpenSSL is needed for multi-algorithm path validation.
- **`validate_chain` deliberately sets no verification purpose.** Setting one
  enables Extended Key Usage checks, and Android key-attestation certificates
  carry no EKU — setting a purpose would reject every Google Wallet chain.
  Covered by `real_android_attestation_chain_validates_against_the_configured_google_root`.
- **`X509VerifyFlags::PARTIAL_CHAIN` is required,** not optional: a configured
  trust anchor may be an intermediate rather than a self-signed root. Covered by
  `an_intermediate_pinned_as_the_anchor_validates_the_leaf`.
```

- [ ] **Step 4: Verify the conformance report's self-consistency**

```bash
cargo test -p foundry --test conformance_report
```

Expected: PASS. This test enforces the report's internal cross-references; a failure means a row ID, gap ID, or test name reference is wrong.

- [ ] **Step 5: Confirm the `TODO(trust-hardening)` comment is gone**

```bash
rg -n "TODO\(trust-hardening\)" crates/
```

Expected: no matches. It should have been deleted in Task 1 Step 5; if it survives, remove it now.

- [ ] **Step 6: Run the scoped gate**

```bash
cargo test -p foundry-core -p foundry-sd-jwt-vc -p foundry-mdoc \
           -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 7: Commit**

```bash
git add docs/conformance/openid4vc-conformance.md crates/foundry-core/AGENTS.md
git commit -m "docs: correct trust-chain conformance rows and record the OpenSSL split

VCI-0231, HAIP-0031, HAIP-0082 and HAIP-0083 claimed cryptographic trust from
a function that compared Distinguished-Name strings. Their evidence now
describes what is actually verified. HAIP-0039/0079/0084 move off 'ambiguous'
now that a presented root is explicitly discarded."
```

---

## Post-plan: full gate

Only after all five tasks are complete and this is ready for review or merge, run the §5.3 full gate **once**:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets -- -D warnings
```

Do not run this between tasks. Do not re-run it after merging (§5.4).

## Follow-on work, explicitly out of scope

- **Sub-project D** — `android_keystore_attestation` proof type: `KeyDescription` extension parsing (`1.3.6.1.4.1.11129.2.1.17`), `attestationChallenge` ↔ `c_nonce` binding, security-level policy, revocation against `https://android.googleapis.com/attestation/status`.
- Installing Google's two attestation roots (RSA-4096 `f92009e853b6b045` and ECDSA P-384 `Key Attestation CA1`) as configured trust anchors — operational setup that D requires.
- RSA JOSE signing. Explicitly not wanted.