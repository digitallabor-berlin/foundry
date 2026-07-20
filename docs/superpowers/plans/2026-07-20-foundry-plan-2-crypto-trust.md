# Foundry — Plan 2: Crypto & Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `foundry-core` a cryptographic signing seam (`Signer` trait + file-based ES256/384/512 signer), an X.509 parsing + trust-path-building module, dev-PKI generation helpers, and wire them into `foundry` CLI subcommands (`keys generate`, `cert new-ca`, `cert issue`, `quickstart`/`init`) plus filesystem-aware config validation.

**Architecture:** `foundry-core` gains three new modules — `crypto` (algorithm enum, `Signer` trait, `FileSigner` over `josekit`), `trust` (cert parse, SAN extraction, self-signed detection, x5c building, DN-based chain validation via `x509-cert`), and `pki` (EC key + CA + leaf generation via `josekit`/`rcgen`). The `foundry` binary adds thin CLI command handlers (in a new `commands` module) that call these core functions and do file IO, culminating in a `quickstart` command that emits a complete dev PKI + ready-to-run `config.yaml`.

**Tech Stack:** Rust 1.97, edition 2021. `josekit` 0.10 (JOSE signing, EC key gen, JWK export), `rcgen` 0.14 with `x509-parser` feature (X.509 cert generation + CA-from-PEM issuance), `x509-cert` 0.3 with `pem` feature (cert parsing), `base64` 0.22 (x5c DER→base64), `time` 0.3 (rcgen validity windows). All three crate APIs were verified end-to-end against these exact versions before this plan was written.

## Global Constraints

- Language / runtime: Rust (edition 2021), tokio async runtime. Toolchain pinned at 1.97.
- CLI framework: `clap` v4 with derive macros. No other arg parser.
- Logging: `tracing` + `tracing-subscriber`, structured, **console-only** — no file/remote sinks. Format via `--log-format`, level via `--log-level`.
- Storage: embedded **SQLite** only, via `sqlx`.
- Config: single YAML **or** JSON file, typed serde structs, **validated at startup**; invalid config fails fast with a non-zero exit and an actionable message.
- Errors: typed via `thiserror` — per-layer domain enums. **No `unwrap`/`panic` in non-test code paths.**
- Crypto: ECDSA **ES256 (P-256) default** per HAIP; `Signer` trait is the seam so a KMS/HSM backend can slot in later without touching issuer/verifier logic. The v1 file-based signer loads PEM from `keys` config. Also support ES384/ES512.
- X.509: build `x5c` as **leaf..intermediate, trust anchor excluded** (HAIP §6.1.1). Incoming chains: reject self-signed leaves, check validity windows, build a path from leaf up to a configured trust anchor.
- Dev PKI (`quickstart`): produce a proper **2-level chain (self-signed root → non-self-signed leaf)**, NOT a single self-signed leaf. Root is the trust anchor (excluded from x5c); each leaf's x5c file contains just the leaf. Output is **dev/test only** and MUST be marked as such.
- Every code change lands via TDD: failing test first (capture the genuine RED transcript), then minimal implementation, then commit.
- Vendored crates (`oid4vci`, `openid4vp`, `openid4vp-frontend`) are owned copies — do not touch them or hold them to our lint bar.
- Commit only the files a task declares. Never `git add -A` (untracked `.superpowers/` scratch and harness `.pi/` files must stay uncommitted).

### Verified crate-API facts (baked into this plan's code — do not "correct" them)

- **josekit signatures are raw JOSE r‖s**, not DER: 64 bytes (ES256), 96 (ES384), 132 (ES512).
- `to_jwk_public_key()` / `to_pem_private_key()` / `to_pem_public_key()` are methods on the **`josekit::jwk::KeyPair` trait** — you MUST `use josekit::jwk::KeyPair as _;` for them to resolve on `EcKeyPair`.
- `EcKeyPair::from_pem(pem, None)` — second arg is `Option<EcCurve>`; `None` auto-detects the curve from PKCS#8.
- `josekit::jws::{ES256, ES384, ES512}` are exported constants; the underlying `EcdsaJwsAlgorithm` enum is private — use the constants.
- A `josekit` `to_pem_private_key()` PKCS#8 PEM is loadable **directly** by `rcgen::KeyPair::from_pem` — keys and certs share one on-disk format.
- `rcgen::KeyPair::generate()` defaults to `PKCS_ECDSA_P256_SHA256`. `serialize_pem()` yields PKCS#8 "PRIVATE KEY" PEM. `cert.pem()` yields the cert PEM. `cert.der()` yields `&CertificateDer` (derefs to `&[u8]`).
- `rcgen::CertificateParams::default()` sets an absurd validity window (1975–4096); ALWAYS override `not_before`/`not_after` (they are `time::OffsetDateTime`).
- CA signing in-memory: `Issuer::from_params(&ca_params, &ca_key)` then `leaf_params.signed_by(&leaf_key, &issuer)`.
- CA signing from disk: `Issuer::from_ca_cert_pem(&ca_cert_pem_str, ca_keypair_by_value)` — **requires `rcgen` feature `x509-parser`** (not default). `signing_key` is taken **by value**.
- `x509-cert` 0.3 does **NOT** verify signatures — it is pure ASN.1. Field access is via **accessor methods**: `cert.tbs_certificate().subject()/.issuer()/.validity()/.extensions()` (double-parens, not fields).
- `x509_cert::Certificate::from_pem` needs `use x509_cert::der::DecodePem;`. `Time::to_unix_duration().as_secs()` gives unix seconds. `Name` implements `PartialEq` and `Display`.
- SAN extraction: iterate `extensions()`, match `ext.extn_id == SubjectAltName::OID` (`SubjectAltName::OID` needs `use x509_cert::der::oid::AssociatedOid;`), decode `SubjectAltName::from_der(ext.extn_value.as_bytes())` (needs `use x509_cert::der::Decode;`), iterate `.0` for `GeneralName::DnsName`.
- Cert PEM→DER: `Certificate::from_pem(pem)?.to_der()?` (needs `use x509_cert::der::Encode;`); byte-identical to rcgen's own `der()`.

### Known v1 limitation (tracked, intentional)

`trust::validate_chain` in this plan performs **DN-based path building + validity-window checks + self-signed-leaf rejection**, but does **NOT** cryptographically verify that each certificate's signature was produced by its issuer's private key (x509-cert 0.3 has no signature-verification capability). This is an accepted foundation-slice boundary. A later hardening pass MUST add real signature-path validation (via `rustls-webpki`, or manual `p256`/`ecdsa` verification of `tbs_certificate` against the issuer SPKI). This does not change any public interface introduced here — only `validate_chain`'s internals get stronger. Leave a `// TODO(trust-hardening): ...` comment at the validation site so it is discoverable.

---

## File Structure

**foundry-core (new/modified):**
- `crates/foundry-core/src/error.rs` — MODIFY: add `CryptoError`, `TrustError`; wire into `CoreError`.
- `crates/foundry-core/src/crypto/mod.rs` — CREATE: `SignatureAlgorithm`, `Signer` trait, re-exports.
- `crates/foundry-core/src/crypto/signer.rs` — CREATE: `FileSigner` (josekit).
- `crates/foundry-core/src/trust/mod.rs` — CREATE: parse/inspect + x5c + chain validation (x509-cert).
- `crates/foundry-core/src/pki/mod.rs` — CREATE: `generate_ec_key`, `new_ca`, `issue_leaf` (josekit + rcgen).
- `crates/foundry-core/src/config/validate.rs` — MODIFY: add `validate_key_material`.
- `crates/foundry-core/src/lib.rs` — MODIFY: register `crypto`, `trust`, `pki`.
- `crates/foundry-core/Cargo.toml` — MODIFY: add deps.
- `Cargo.toml` (root) — MODIFY: add workspace deps.

**foundry binary (new/modified):**
- `crates/foundry/src/commands.rs` — CREATE: CLI handler functions.
- `crates/foundry/src/cli.rs` — MODIFY: add `Keys`, `Cert`, `Quickstart` subcommands.
- `crates/foundry/src/main.rs` — MODIFY: dispatch new subcommands; call `validate_key_material`.
- `crates/foundry/src/lib.rs` — MODIFY: register `commands`.
- `crates/foundry/tests/cli_pki.rs` — CREATE: keys/cert command integration test.
- `crates/foundry/tests/quickstart.rs` — CREATE: quickstart integration test.

---

### Task 1: Crypto & trust error taxonomy

**Files:**
- Modify: `crates/foundry-core/src/error.rs`

**Interfaces:**
- Consumes: existing `CoreError`, `ConfigError`, `StorageError`.
- Produces: `CryptoError`, `TrustError` enums; `CoreError::Crypto`, `CoreError::Trust` variants. Used by every later task in this plan.

- [ ] **Step 1: Write the failing test**

Append to the `#[cfg(test)] mod tests` block in `crates/foundry-core/src/error.rs`:

```rust
    #[test]
    fn crypto_unsupported_alg_displays() {
        let e = CryptoError::UnsupportedAlgorithm("RS256".into());
        assert_eq!(e.to_string(), "unsupported signature algorithm 'RS256'");
    }

    #[test]
    fn trust_self_signed_leaf_displays() {
        let e = TrustError::SelfSignedLeaf;
        assert_eq!(
            e.to_string(),
            "leaf certificate must not be self-signed (HAIP §6.1.1)"
        );
    }

    #[test]
    fn core_error_wraps_crypto_and_trust() {
        let c: CoreError = CryptoError::Sign("boom".into()).into();
        assert_eq!(c.to_string(), "signing failed: boom");
        let t: CoreError = TrustError::UntrustedChain.into();
        assert_eq!(
            t.to_string(),
            "no configured trust anchor matches the certificate chain"
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core error:: 2>&1 | tail -20`
Expected: FAIL — `cannot find type CryptoError` / `TrustError` in this scope.

- [ ] **Step 3: Add the error enums and wire them into `CoreError`**

In `crates/foundry-core/src/error.rs`, add these two enums (after `StorageError`, before `CoreError`):

```rust
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("failed to read key file {path}: {source}")]
    KeyRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unsupported signature algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    #[error("failed to load signing key: {0}")]
    KeyLoad(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("key or certificate generation failed: {0}")]
    Generation(String),
}

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("failed to read certificate file {path}: {source}")]
    CertRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse certificate: {0}")]
    Parse(String),
    #[error("certificate chain is empty")]
    EmptyChain,
    #[error("leaf certificate must not be self-signed (HAIP §6.1.1)")]
    SelfSignedLeaf,
    #[error("certificate is outside its validity window")]
    Expired,
    #[error("no configured trust anchor matches the certificate chain")]
    UntrustedChain,
    #[error("DNS SAN mismatch: certificate does not assert '{0}'")]
    SanMismatch(String),
}
```

Then extend `CoreError`:

```rust
#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Trust(#[from] TrustError),
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core error:: 2>&1 | tail -20`
Expected: PASS — all error tests green.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/error.rs
git commit -m "feat(core): add crypto and trust error taxonomy"
```

---

### Task 2: SignatureAlgorithm enum + Signer trait

**Files:**
- Create: `crates/foundry-core/src/crypto/mod.rs`
- Modify: `crates/foundry-core/src/lib.rs`
- Modify: `crates/foundry-core/Cargo.toml`
- Modify: `Cargo.toml` (root workspace deps)

**Interfaces:**
- Consumes: `CryptoError` (Task 1).
- Produces:
  - `pub enum SignatureAlgorithm { Es256, Es384, Es512 }` with `impl std::str::FromStr<Err = CryptoError>`, `fn as_str(&self) -> &'static str`, `impl std::fmt::Display`, `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`.
  - `pub trait Signer: Send + Sync { fn algorithm(&self) -> SignatureAlgorithm; fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>; fn public_jwk(&self) -> Result<serde_json::Value, CryptoError>; }`
  - `pub use signer::FileSigner;` (module declared here, implemented in Task 3 — see note).

> **Note on module wiring:** This task declares `pub mod signer;` and `pub use signer::FileSigner;`. To compile before Task 3, create a MINIMAL placeholder `crates/foundry-core/src/crypto/signer.rs` containing only the struct shell needed to satisfy the re-export; Task 3 fills in the real implementation and its tests. The placeholder is specified in Step 3 below.

- [ ] **Step 1: Add workspace + crate dependencies**

In root `Cargo.toml`, under `[workspace.dependencies]`, add:

```toml
josekit = "0.10"
```

In `crates/foundry-core/Cargo.toml`, under `[dependencies]`, add:

```toml
josekit = { workspace = true }
```

(`serde_json` is already a dependency of `foundry-core`.)

- [ ] **Step 2: Write the failing test**

Create `crates/foundry-core/src/crypto/mod.rs` with ONLY the test module first (so it fails to compile against missing items):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_known_algorithms_case_insensitively() {
        assert_eq!(SignatureAlgorithm::from_str("ES256").unwrap(), SignatureAlgorithm::Es256);
        assert_eq!(SignatureAlgorithm::from_str("es384").unwrap(), SignatureAlgorithm::Es384);
        assert_eq!(SignatureAlgorithm::from_str("Es512").unwrap(), SignatureAlgorithm::Es512);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let err = SignatureAlgorithm::from_str("RS256").unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn as_str_and_display_round_trip() {
        assert_eq!(SignatureAlgorithm::Es256.as_str(), "ES256");
        assert_eq!(format!("{}", SignatureAlgorithm::Es512), "ES512");
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

First register the module: in `crates/foundry-core/src/lib.rs` add `pub mod crypto;` (keep existing lines):

```rust
pub mod config;
pub mod crypto;
pub mod error;
pub mod storage;
```

Run: `cargo test -p foundry-core crypto:: 2>&1 | tail -20`
Expected: FAIL — `cannot find type SignatureAlgorithm` (module has only tests + missing `signer`).

- [ ] **Step 4: Write the enum, trait, and placeholder signer module**

Prepend to `crates/foundry-core/src/crypto/mod.rs` (above the test module):

```rust
use crate::error::CryptoError;

pub mod signer;
pub use signer::FileSigner;

/// Supported JOSE ECDSA signature algorithms (HAIP: ES256 default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Es256,
    Es384,
    Es512,
}

impl SignatureAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Es256 => "ES256",
            SignatureAlgorithm::Es384 => "ES384",
            SignatureAlgorithm::Es512 => "ES512",
        }
    }
}

impl std::str::FromStr for SignatureAlgorithm {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "ES256" => Ok(SignatureAlgorithm::Es256),
            "ES384" => Ok(SignatureAlgorithm::Es384),
            "ES512" => Ok(SignatureAlgorithm::Es512),
            other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Abstraction over a signing key. The file-based implementation lives in
/// `signer.rs`; a KMS/HSM backend can implement this trait later without
/// touching issuer/verifier logic.
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn public_jwk(&self) -> Result<serde_json::Value, CryptoError>;
}
```

Create the placeholder `crates/foundry-core/src/crypto/signer.rs` (Task 3 replaces the body):

```rust
//! File-based `Signer` implementation. Real body added in Plan 2 Task 3.

/// Placeholder — implemented in Task 3.
pub struct FileSigner;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p foundry-core crypto:: 2>&1 | tail -20`
Expected: PASS — 3 crypto tests green.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/foundry-core/Cargo.toml crates/foundry-core/src/lib.rs crates/foundry-core/src/crypto
git commit -m "feat(core): add SignatureAlgorithm enum and Signer trait"
```

---

### Task 3: FileSigner (josekit ES256/384/512)

**Files:**
- Modify: `crates/foundry-core/src/crypto/signer.rs` (replace placeholder)

**Interfaces:**
- Consumes: `SignatureAlgorithm`, `Signer` (Task 2), `CryptoError` (Task 1), `josekit`.
- Produces:
  - `pub struct FileSigner { .. }`
  - `impl FileSigner { pub fn from_pem(pem: &[u8], algorithm: SignatureAlgorithm) -> Result<Self, CryptoError>; pub fn from_pem_file(path: &str, algorithm: SignatureAlgorithm) -> Result<Self, CryptoError>; }`
  - `impl Signer for FileSigner` (algorithm/sign/public_jwk).

- [ ] **Step 1: Write the failing test**

Replace the entire contents of `crates/foundry-core/src/crypto/signer.rs` with the test-only shell first (so it fails against the missing real API). Put this at the BOTTOM; the top will be filled in Step 3:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SignatureAlgorithm, Signer};
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};

    fn generate_p256_pkcs8_pem() -> Vec<u8> {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        kp.to_pem_private_key()
    }

    #[test]
    fn es256_signs_and_exports_public_jwk() {
        let pem = generate_p256_pkcs8_pem();
        let signer = FileSigner::from_pem(&pem, SignatureAlgorithm::Es256).unwrap();

        assert_eq!(signer.algorithm(), SignatureAlgorithm::Es256);

        // josekit ES256 produces a raw r||s JOSE signature = 64 bytes for P-256.
        let sig = signer.sign(b"payload-to-sign").unwrap();
        assert_eq!(sig.len(), 64);

        let jwk = signer.public_jwk().unwrap();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
    }

    #[test]
    fn from_pem_file_round_trips() {
        let pem = generate_p256_pkcs8_pem();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.pem");
        std::fs::write(&path, &pem).unwrap();

        let signer = FileSigner::from_pem_file(path.to_str().unwrap(), SignatureAlgorithm::Es256).unwrap();
        let sig = signer.sign(b"hi").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn wrong_pem_is_a_key_load_error() {
        let err = FileSigner::from_pem(b"not a pem", SignatureAlgorithm::Es256).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::KeyLoad(_)));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core crypto::signer 2>&1 | tail -20`
Expected: FAIL — `FileSigner` is a unit struct with no `from_pem`/`sign`; missing `Signer` impl.

- [ ] **Step 3: Write the real implementation**

Put this ABOVE the test module in `crates/foundry-core/src/crypto/signer.rs`:

```rust
//! File-based `Signer` implementation over josekit.

use crate::crypto::{SignatureAlgorithm, Signer};
use crate::error::CryptoError;
use josekit::jwk::alg::ec::EcKeyPair;
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsSigner, ES256, ES384, ES512};

/// A `Signer` backed by an EC private key loaded from a PKCS#8 PEM.
pub struct FileSigner {
    algorithm: SignatureAlgorithm,
    signer: Box<dyn JwsSigner>,
    public_jwk: serde_json::Value,
}

impl FileSigner {
    /// Load a signer from an in-memory PKCS#8 PEM.
    pub fn from_pem(pem: &[u8], algorithm: SignatureAlgorithm) -> Result<Self, CryptoError> {
        let signer: Box<dyn JwsSigner> = match algorithm {
            SignatureAlgorithm::Es256 => Box::new(
                ES256
                    .signer_from_pem(pem)
                    .map_err(|e| CryptoError::KeyLoad(e.to_string()))?,
            ),
            SignatureAlgorithm::Es384 => Box::new(
                ES384
                    .signer_from_pem(pem)
                    .map_err(|e| CryptoError::KeyLoad(e.to_string()))?,
            ),
            SignatureAlgorithm::Es512 => Box::new(
                ES512
                    .signer_from_pem(pem)
                    .map_err(|e| CryptoError::KeyLoad(e.to_string()))?,
            ),
        };

        // Curve is auto-detected from the PKCS#8 structure (None).
        let key_pair =
            EcKeyPair::from_pem(pem, None).map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
        let public_jwk = serde_json::to_value(key_pair.to_jwk_public_key())
            .map_err(|e| CryptoError::KeyLoad(e.to_string()))?;

        Ok(Self {
            algorithm,
            signer,
            public_jwk,
        })
    }

    /// Load a signer from a PEM file on disk.
    pub fn from_pem_file(path: &str, algorithm: SignatureAlgorithm) -> Result<Self, CryptoError> {
        let pem = std::fs::read(path).map_err(|source| CryptoError::KeyRead {
            path: path.to_string(),
            source,
        })?;
        Self::from_pem(&pem, algorithm)
    }
}

impl Signer for FileSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer
            .sign(message)
            .map_err(|e| CryptoError::Sign(e.to_string()))
    }

    fn public_jwk(&self) -> Result<serde_json::Value, CryptoError> {
        Ok(self.public_jwk.clone())
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core crypto::signer 2>&1 | tail -20`
Expected: PASS — `es256_signs_and_exports_public_jwk`, `from_pem_file_round_trips`, `wrong_pem_is_a_key_load_error`.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/crypto/signer.rs
git commit -m "feat(core): implement file-based Signer over josekit"
```

---

### Task 4: Trust module — cert parsing, SAN, self-signed detection

**Files:**
- Create: `crates/foundry-core/src/trust/mod.rs`
- Modify: `crates/foundry-core/src/lib.rs`
- Modify: `crates/foundry-core/Cargo.toml`
- Modify: `Cargo.toml` (root workspace deps)

**Interfaces:**
- Consumes: `TrustError` (Task 1), `x509-cert`.
- Produces (all `pub`, in `foundry_core::trust`):
  - `pub use x509_cert::Certificate;` (re-export so callers need not depend on x509-cert directly)
  - `fn parse_cert_pem(pem: &[u8]) -> Result<Certificate, TrustError>`
  - `fn is_self_signed(cert: &Certificate) -> bool`
  - `fn validity_window(cert: &Certificate) -> (u64, u64)` (unix seconds: not_before, not_after)
  - `fn san_dns_names(cert: &Certificate) -> Result<Vec<String>, TrustError>`

- [ ] **Step 1: Add dependencies**

In root `Cargo.toml` `[workspace.dependencies]`, add:

```toml
x509-cert = { version = "0.3", features = ["pem"] }
base64 = "0.22"
```

In `crates/foundry-core/Cargo.toml` `[dependencies]`, add:

```toml
x509-cert = { workspace = true }
base64 = { workspace = true }
```

- [ ] **Step 2: Write the failing test**

Create `crates/foundry-core/src/trust/mod.rs` with ONLY the test module first. The two PEM constants below are real certificates generated with rcgen 0.14.8 (a self-signed CA and a CA-signed leaf with SAN `issuer.dev.local`, both valid until 2036):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const CA_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBgTCCASagAwIBAgIUMuXzxAQ2jbmV3Vl23cKzyjjrQXswCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTRm91bmRyeSBEZXYgUm9vdCBDQTAeFw0yNjA3MjAwOTMyMzBa
Fw0zNjA3MTcwOTMyMzBaMB4xHDAaBgNVBAMME0ZvdW5kcnkgRGV2IFJvb3QgQ0Ew
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQX5bSK9rymRHCiOHPFqYxAFMWMibvT
83zroR2k3euLLkzBlUHndEKBVlesake2CdC0+eD+Sn5jIVtAEcd1QJUBo0IwQDAO
BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFOh1OqjnYe/4I4EdxK3uwbJ5xE4WMA8G
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAJRps/NQx/LiLodmMHnx
/hEpxeuUJbNw9hL5cRskcp7cAiEAm4XCO5qfzHVm+DT1uFcKPcSRZx3VstuUjW70
Hx2Z6f4=
-----END CERTIFICATE-----
";

    const LEAF_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBajCCARCgAwIBAgIURWe+XknN8BJ1cxSddzvuo58nky8wCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTRm91bmRyeSBEZXYgUm9vdCBDQTAeFw0yNjA3MjAwOTMyMzBa
Fw0zNjA3MTcwOTMyMzBaMBsxGTAXBgNVBAMMEGlzc3Vlci5kZXYubG9jYWwwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAATl55Pkho1O7vCodjCN5Pg0bLD0Enq2NHB+
CQtZzhVZZ2J9pnrpNhec+4pvhEiSoDnHbDO1hCVo9j7Y6MLy2pbJoy8wLTAbBgNV
HREEFDASghBpc3N1ZXIuZGV2LmxvY2FsMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjO
PQQDAgNIADBFAiAiUDy4sT+j71gmXiB4w+UOhfaA02IuOiuwqdRflDGd2wIhAILW
vP5vWUL28PymIi7FZin3ExljHeW+S4QiHVbOkeJ0
-----END CERTIFICATE-----
";

    #[test]
    fn parses_and_detects_self_signed_ca() {
        let ca = parse_cert_pem(CA_CERT_PEM).unwrap();
        assert!(is_self_signed(&ca));
    }

    #[test]
    fn leaf_is_not_self_signed_and_links_to_ca() {
        let ca = parse_cert_pem(CA_CERT_PEM).unwrap();
        let leaf = parse_cert_pem(LEAF_CERT_PEM).unwrap();
        assert!(!is_self_signed(&leaf));
        // leaf.issuer == ca.subject → genuine CA-signed chain link
        assert_eq!(
            leaf.tbs_certificate().issuer(),
            ca.tbs_certificate().subject()
        );
    }

    #[test]
    fn extracts_san_dns_names() {
        let leaf = parse_cert_pem(LEAF_CERT_PEM).unwrap();
        let names = san_dns_names(&leaf).unwrap();
        assert_eq!(names, vec!["issuer.dev.local".to_string()]);
    }

    #[test]
    fn validity_window_is_ordered() {
        let leaf = parse_cert_pem(LEAF_CERT_PEM).unwrap();
        let (nb, na) = validity_window(&leaf);
        assert!(nb < na);
    }

    #[test]
    fn rejects_garbage_pem() {
        let err = parse_cert_pem(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
            .unwrap_err();
        assert!(matches!(err, crate::error::TrustError::Parse(_)));
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Register the module: in `crates/foundry-core/src/lib.rs` add `pub mod trust;`:

```rust
pub mod config;
pub mod crypto;
pub mod error;
pub mod storage;
pub mod trust;
```

Run: `cargo test -p foundry-core trust:: 2>&1 | tail -20`
Expected: FAIL — `cannot find function parse_cert_pem` etc.

- [ ] **Step 4: Write the implementation**

Prepend to `crates/foundry-core/src/trust/mod.rs` (above the test module):

```rust
//! X.509 parsing, inspection, and (DN-based) trust-path validation.

use crate::error::TrustError;
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, DecodePem};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;

pub use x509_cert::Certificate;

/// Parse a single PEM-encoded certificate.
pub fn parse_cert_pem(pem: &[u8]) -> Result<Certificate, TrustError> {
    Certificate::from_pem(pem).map_err(|e| TrustError::Parse(e.to_string()))
}

/// A certificate is self-signed when its subject DN equals its issuer DN.
pub fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate().subject() == cert.tbs_certificate().issuer()
}

/// (not_before, not_after) as unix seconds.
pub fn validity_window(cert: &Certificate) -> (u64, u64) {
    let validity = cert.tbs_certificate().validity();
    (
        validity.not_before.to_unix_duration().as_secs(),
        validity.not_after.to_unix_duration().as_secs(),
    )
}

/// All dNSName entries from the SubjectAltName extension (empty if none).
pub fn san_dns_names(cert: &Certificate) -> Result<Vec<String>, TrustError> {
    let mut names = Vec::new();
    if let Some(extensions) = cert.tbs_certificate().extensions() {
        for ext in extensions.iter() {
            if ext.extn_id == SubjectAltName::OID {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| TrustError::Parse(e.to_string()))?;
                for name in san.0.iter() {
                    if let GeneralName::DnsName(dns) = name {
                        names.push(dns.to_string());
                    }
                }
            }
        }
    }
    Ok(names)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p foundry-core trust:: 2>&1 | tail -20`
Expected: PASS — 5 trust tests green.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/foundry-core/Cargo.toml crates/foundry-core/src/lib.rs crates/foundry-core/src/trust
git commit -m "feat(core): add X.509 parsing, SAN extraction, self-signed detection"
```

---

### Task 5: PKI module — EC key generation

**Files:**
- Create: `crates/foundry-core/src/pki/mod.rs`
- Modify: `crates/foundry-core/src/lib.rs`

**Interfaces:**
- Consumes: `SignatureAlgorithm` (Task 2), `CryptoError` (Task 1), `FileSigner` (Task 3, in tests), `josekit`.
- Produces (in `foundry_core::pki`):
  - `pub struct KeyMaterial { pub private_pem: String, pub public_pem: String }`
  - `fn generate_ec_key(alg: SignatureAlgorithm) -> Result<KeyMaterial, CryptoError>`

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-core/src/pki/mod.rs` with ONLY the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FileSigner, SignatureAlgorithm, Signer};

    #[test]
    fn generates_loadable_es256_key() {
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        assert!(km.private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(km.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));

        // The generated key must be usable by the file signer.
        let signer = FileSigner::from_pem(km.private_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let sig = signer.sign(b"data").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn generates_es384_and_es512_keys() {
        let k384 = generate_ec_key(SignatureAlgorithm::Es384).unwrap();
        let s384 = FileSigner::from_pem(k384.private_pem.as_bytes(), SignatureAlgorithm::Es384).unwrap();
        assert_eq!(s384.sign(b"x").unwrap().len(), 96);

        let k512 = generate_ec_key(SignatureAlgorithm::Es512).unwrap();
        let s512 = FileSigner::from_pem(k512.private_pem.as_bytes(), SignatureAlgorithm::Es512).unwrap();
        assert_eq!(s512.sign(b"x").unwrap().len(), 132);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Register the module: in `crates/foundry-core/src/lib.rs` add `pub mod pki;`:

```rust
pub mod config;
pub mod crypto;
pub mod error;
pub mod pki;
pub mod storage;
pub mod trust;
```

Run: `cargo test -p foundry-core pki:: 2>&1 | tail -20`
Expected: FAIL — `cannot find function generate_ec_key`.

- [ ] **Step 3: Write the implementation**

Prepend to `crates/foundry-core/src/pki/mod.rs` (above the test module):

```rust
//! Dev-PKI generation helpers (keys, CAs, leaf certificates).

use crate::crypto::SignatureAlgorithm;
use crate::error::CryptoError;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::{Jwk, KeyPair as _};

/// A freshly generated EC key pair as PEM strings (PKCS#8 private + SPKI public).
pub struct KeyMaterial {
    pub private_pem: String,
    pub public_pem: String,
}

/// Generate an EC key pair for the given algorithm's curve.
pub fn generate_ec_key(alg: SignatureAlgorithm) -> Result<KeyMaterial, CryptoError> {
    let curve = match alg {
        SignatureAlgorithm::Es256 => EcCurve::P256,
        SignatureAlgorithm::Es384 => EcCurve::P384,
        SignatureAlgorithm::Es512 => EcCurve::P521,
    };
    let jwk = Jwk::generate_ec_key(curve).map_err(|e| CryptoError::Generation(e.to_string()))?;
    let kp = EcKeyPair::from_jwk(&jwk).map_err(|e| CryptoError::Generation(e.to_string()))?;
    let private_pem = String::from_utf8(kp.to_pem_private_key())
        .map_err(|e| CryptoError::Generation(e.to_string()))?;
    let public_pem = String::from_utf8(kp.to_pem_public_key())
        .map_err(|e| CryptoError::Generation(e.to_string()))?;
    Ok(KeyMaterial {
        private_pem,
        public_pem,
    })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core pki:: 2>&1 | tail -20`
Expected: PASS — `generates_loadable_es256_key`, `generates_es384_and_es512_keys`.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/lib.rs crates/foundry-core/src/pki
git commit -m "feat(core): add EC key generation to pki module"
```

---

### Task 6: PKI module — CA + leaf certificate issuance (rcgen)

**Files:**
- Modify: `crates/foundry-core/src/pki/mod.rs`
- Modify: `crates/foundry-core/Cargo.toml`
- Modify: `Cargo.toml` (root workspace deps)

**Interfaces:**
- Consumes: `CryptoError` (Task 1), `trust::parse_cert_pem`/`is_self_signed`/`san_dns_names` (Task 4, in tests), `rcgen`, `time`.
- Produces (in `foundry_core::pki`):
  - `pub struct CertMaterial { pub cert_pem: String, pub key_pem: String }`
  - `fn new_ca(common_name: &str, days: i64) -> Result<CertMaterial, CryptoError>` — self-signed CA (keyCertSign + cRLSign, BasicConstraints CA).
  - `fn issue_leaf(ca_cert_pem: &str, ca_key_pem: &str, common_name: &str, dns_sans: &[String], days: i64) -> Result<CertMaterial, CryptoError>` — end-entity cert signed by the given CA; the returned `key_pem` is the leaf's OWN key (the cert certifies it).

- [ ] **Step 1: Add dependencies**

In root `Cargo.toml` `[workspace.dependencies]`, add:

```toml
rcgen = { version = "0.14", features = ["x509-parser"] }
time = "0.3"
```

> **Feature note:** `x509-parser` is REQUIRED for `Issuer::from_ca_cert_pem` (used by `issue_leaf`). It is not in rcgen's default features.

In `crates/foundry-core/Cargo.toml` `[dependencies]`, add:

```toml
rcgen = { workspace = true }
time = { workspace = true }
```

- [ ] **Step 2: Write the failing test**

Append to the `#[cfg(test)] mod tests` block in `crates/foundry-core/src/pki/mod.rs`:

```rust
    use crate::trust::{is_self_signed, parse_cert_pem, san_dns_names};

    #[test]
    fn new_ca_is_self_signed_pem() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        assert!(ca.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(ca.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let cert = parse_cert_pem(ca.cert_pem.as_bytes()).unwrap();
        assert!(is_self_signed(&cert));
    }

    #[test]
    fn issue_leaf_is_ca_signed_with_san() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "issuer.dev.local",
            &["issuer.dev.local".to_string()],
            365,
        )
        .unwrap();

        let leaf_cert = parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
        let ca_cert = parse_cert_pem(ca.cert_pem.as_bytes()).unwrap();

        // Not self-signed, and genuinely chained to the CA.
        assert!(!is_self_signed(&leaf_cert));
        assert_eq!(
            leaf_cert.tbs_certificate().issuer(),
            ca_cert.tbs_certificate().subject()
        );
        // SAN carries the requested DNS name.
        assert_eq!(
            san_dns_names(&leaf_cert).unwrap(),
            vec!["issuer.dev.local".to_string()]
        );
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p foundry-core pki:: 2>&1 | tail -20`
Expected: FAIL — `cannot find function new_ca` / `issue_leaf`.

- [ ] **Step 4: Write the implementation**

Append to `crates/foundry-core/src/pki/mod.rs` (below `generate_ec_key`, above the test module). Add these imports to the existing `use` block at the top of the file:

```rust
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};
```

Then add:

```rust
/// A generated certificate plus its own private key, as PEM strings.
pub struct CertMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a self-signed CA certificate (BasicConstraints CA; keyCertSign + cRLSign).
pub fn new_ca(common_name: &str, days: i64) -> Result<CertMaterial, CryptoError> {
    let key = KeyPair::generate().map_err(|e| CryptoError::Generation(e.to_string()))?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(days);

    let cert = params
        .self_signed(&key)
        .map_err(|e| CryptoError::Generation(e.to_string()))?;

    Ok(CertMaterial {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Issue an end-entity certificate signed by an existing CA (loaded from PEM).
/// The returned `key_pem` is the leaf's own freshly generated key.
pub fn issue_leaf(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    common_name: &str,
    dns_sans: &[String],
    days: i64,
) -> Result<CertMaterial, CryptoError> {
    let ca_key = KeyPair::from_pem(ca_key_pem).map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
    // Requires rcgen feature "x509-parser"; signing key is moved in by value.
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key)
        .map_err(|e| CryptoError::Generation(e.to_string()))?;

    let leaf_key = KeyPair::generate().map_err(|e| CryptoError::Generation(e.to_string()))?;

    // CertificateParams::new adds the SANs; we set CN + usages explicitly.
    let mut params = CertificateParams::new(dns_sans.to_vec())
        .map_err(|e| CryptoError::Generation(e.to_string()))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(days);

    let leaf = params
        .signed_by(&leaf_key, &issuer)
        .map_err(|e| CryptoError::Generation(e.to_string()))?;

    Ok(CertMaterial {
        cert_pem: leaf.pem(),
        key_pem: leaf_key.serialize_pem(),
    })
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p foundry-core pki:: 2>&1 | tail -20`
Expected: PASS — key-gen tests plus `new_ca_is_self_signed_pem`, `issue_leaf_is_ca_signed_with_san`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/foundry-core/Cargo.toml crates/foundry-core/src/pki
git commit -m "feat(core): add CA and leaf certificate issuance via rcgen"
```

---

### Task 7: Trust module — x5c building + chain validation + SAN matching

**Files:**
- Modify: `crates/foundry-core/src/trust/mod.rs`

**Interfaces:**
- Consumes: `TrustError` (Task 1), parsing helpers (Task 4), `pki::new_ca`/`issue_leaf` (Task 6, in tests), `base64`, `x509-cert`.
- Produces (in `foundry_core::trust`):
  - `fn build_x5c(chain_pems: &[Vec<u8>]) -> Result<Vec<String>, TrustError>` — base64(DER) per cert, order preserved (leaf..intermediate).
  - `pub struct TrustStore { .. }` with `fn from_pems(pems: &[Vec<u8>]) -> Result<Self, TrustError>` and `fn is_empty(&self) -> bool`.
  - `fn validate_chain(leaf_pem: &[u8], intermediates: &[Vec<u8>], store: &TrustStore, now_unix: u64) -> Result<(), TrustError>` — rejects self-signed leaf, checks validity windows, builds a DN path to an anchor. (See "Known v1 limitation": no crypto signature verification yet.)
  - `fn match_san_dns(leaf_pem: &[u8], expected_dns: &str) -> Result<bool, TrustError>`

- [ ] **Step 1: Write the failing test**

Append to the `#[cfg(test)] mod tests` block in `crates/foundry-core/src/trust/mod.rs`:

```rust
    use crate::pki::{issue_leaf, new_ca};

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn build_x5c_encodes_each_cert() {
        let x5c = build_x5c(&[LEAF_CERT_PEM.to_vec()]).unwrap();
        assert_eq!(x5c.len(), 1);
        // Valid base64 that decodes to non-empty DER.
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let der = B64.decode(&x5c[0]).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn build_x5c_rejects_empty() {
        let err = build_x5c(&[]).unwrap_err();
        assert!(matches!(err, crate::error::TrustError::EmptyChain));
    }

    #[test]
    fn valid_leaf_against_anchor_passes() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(&ca.cert_pem, &ca.key_pem, "issuer.dev.local",
            &["issuer.dev.local".to_string()], 365).unwrap();
        let store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        assert!(!store.is_empty());
        validate_chain(leaf.cert_pem.as_bytes(), &[], &store, now_secs()).unwrap();
    }

    #[test]
    fn self_signed_leaf_is_rejected() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let store = TrustStore::from_pems(&[ca.cert_pem.clone().into_bytes()]).unwrap();
        // Feed the self-signed CA as if it were the leaf.
        let err = validate_chain(ca.cert_pem.as_bytes(), &[], &store, now_secs()).unwrap_err();
        assert!(matches!(err, crate::error::TrustError::SelfSignedLeaf));
    }

    #[test]
    fn expired_leaf_is_rejected() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(&ca.cert_pem, &ca.key_pem, "issuer.dev.local",
            &["issuer.dev.local".to_string()], 365).unwrap();
        let store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        // now far in the future → outside the 365-day window.
        let future = now_secs() + 400 * 24 * 3600;
        let err = validate_chain(leaf.cert_pem.as_bytes(), &[], &store, future).unwrap_err();
        assert!(matches!(err, crate::error::TrustError::Expired));
    }

    #[test]
    fn untrusted_anchor_is_rejected() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(&ca.cert_pem, &ca.key_pem, "issuer.dev.local",
            &["issuer.dev.local".to_string()], 365).unwrap();
        let other = new_ca("Some Other CA", 3650).unwrap();
        let store = TrustStore::from_pems(&[other.cert_pem.into_bytes()]).unwrap();
        let err = validate_chain(leaf.cert_pem.as_bytes(), &[], &store, now_secs()).unwrap_err();
        assert!(matches!(err, crate::error::TrustError::UntrustedChain));
    }

    #[test]
    fn san_matching_works() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(&ca.cert_pem, &ca.key_pem, "issuer.dev.local",
            &["issuer.dev.local".to_string()], 365).unwrap();
        assert!(match_san_dns(leaf.cert_pem.as_bytes(), "issuer.dev.local").unwrap());
        assert!(!match_san_dns(leaf.cert_pem.as_bytes(), "attacker.example.com").unwrap());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core trust:: 2>&1 | tail -20`
Expected: FAIL — `cannot find function build_x5c` / `validate_chain` / type `TrustStore`.

- [ ] **Step 3: Write the implementation**

Add to the top `use` block of `crates/foundry-core/src/trust/mod.rs`:

```rust
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use x509_cert::der::Encode;
```

Then append (below `san_dns_names`, above the test module):

```rust
/// Build an `x5c` array (base64 DER per cert). Order is preserved:
/// callers pass leaf..intermediate (trust anchor excluded) per HAIP §6.1.1.
pub fn build_x5c(chain_pems: &[Vec<u8>]) -> Result<Vec<String>, TrustError> {
    if chain_pems.is_empty() {
        return Err(TrustError::EmptyChain);
    }
    let mut out = Vec::with_capacity(chain_pems.len());
    for pem in chain_pems {
        let cert = parse_cert_pem(pem)?;
        let der = cert.to_der().map_err(|e| TrustError::Parse(e.to_string()))?;
        out.push(B64.encode(&der));
    }
    Ok(out)
}

/// A set of trust-anchor certificates.
pub struct TrustStore {
    anchors: Vec<Certificate>,
}

impl TrustStore {
    pub fn from_pems(pems: &[Vec<u8>]) -> Result<Self, TrustError> {
        let mut anchors = Vec::with_capacity(pems.len());
        for pem in pems {
            anchors.push(parse_cert_pem(pem)?);
        }
        Ok(Self { anchors })
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

fn assert_in_window(cert: &Certificate, now_unix: u64) -> Result<(), TrustError> {
    let (nb, na) = validity_window(cert);
    if now_unix < nb || now_unix > na {
        return Err(TrustError::Expired);
    }
    Ok(())
}

/// Validate a leaf (+ optional intermediates) against the trust store.
///
/// v1 scope: reject self-signed leaf, check validity windows, and build a
/// DN-based path from the leaf up to a configured anchor.
/// TODO(trust-hardening): x509-cert 0.3 cannot verify signatures. A later pass
/// MUST cryptographically verify each link (issuer SPKI over tbs_certificate)
/// via rustls-webpki or p256/ecdsa. This function's signature will not change.
pub fn validate_chain(
    leaf_pem: &[u8],
    intermediates: &[Vec<u8>],
    store: &TrustStore,
    now_unix: u64,
) -> Result<(), TrustError> {
    let leaf = parse_cert_pem(leaf_pem)?;
    if is_self_signed(&leaf) {
        return Err(TrustError::SelfSignedLeaf);
    }
    assert_in_window(&leaf, now_unix)?;

    let mut inter_parsed = Vec::with_capacity(intermediates.len());
    for pem in intermediates {
        inter_parsed.push(parse_cert_pem(pem)?);
    }

    // Walk from the leaf's issuer DN upward through intermediates.
    let mut current_issuer = leaf.tbs_certificate().issuer().clone();
    for inter in &inter_parsed {
        if inter.tbs_certificate().subject() == &current_issuer {
            assert_in_window(inter, now_unix)?;
            current_issuer = inter.tbs_certificate().issuer().clone();
        }
    }

    // The remaining issuer DN must match a trust anchor's subject.
    for anchor in &store.anchors {
        if anchor.tbs_certificate().subject() == &current_issuer {
            assert_in_window(anchor, now_unix)?;
            return Ok(());
        }
    }

    Err(TrustError::UntrustedChain)
}

/// Whether the leaf certificate asserts `expected_dns` as a dNSName SAN.
pub fn match_san_dns(leaf_pem: &[u8], expected_dns: &str) -> Result<bool, TrustError> {
    let leaf = parse_cert_pem(leaf_pem)?;
    Ok(san_dns_names(&leaf)?.iter().any(|n| n == expected_dns))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core trust:: 2>&1 | tail -20`
Expected: PASS — parsing tests plus `build_x5c_encodes_each_cert`, `build_x5c_rejects_empty`, `valid_leaf_against_anchor_passes`, `self_signed_leaf_is_rejected`, `expired_leaf_is_rejected`, `untrusted_anchor_is_rejected`, `san_matching_works`.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/trust
git commit -m "feat(core): add x5c building and DN-based chain validation"
```

---

### Task 8: CLI — `keys generate`, `cert new-ca`, `cert issue`

**Files:**
- Create: `crates/foundry/src/commands.rs`
- Modify: `crates/foundry/src/cli.rs`
- Modify: `crates/foundry/src/main.rs`
- Modify: `crates/foundry/src/lib.rs`
- Create: `crates/foundry/tests/cli_pki.rs`

**Interfaces:**
- Consumes: `foundry_core::pki::{generate_ec_key, new_ca, issue_leaf}`, `foundry_core::crypto::SignatureAlgorithm`.
- Produces (in `foundry::commands`):
  - `fn keys_generate(alg: &str, out: &std::path::Path) -> anyhow::Result<()>`
  - `fn cert_new_ca(common_name: &str, out_cert: &std::path::Path, out_key: &std::path::Path, days: i64) -> anyhow::Result<()>`
  - `fn cert_issue(ca: &std::path::Path, key: &std::path::Path, common_name: &str, san_dns: &[String], out_cert: &std::path::Path, out_key: &std::path::Path, days: i64) -> anyhow::Result<()>`
  - New clap subcommands `Command::Keys { action: KeysAction }` and `Command::Cert { action: CertAction }`.

- [ ] **Step 1: Write the failing test**

Create `crates/foundry/tests/cli_pki.rs`:

```rust
use foundry::commands;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
use foundry_core::trust::{is_self_signed, match_san_dns, parse_cert_pem};

#[test]
fn keys_generate_writes_loadable_key() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("issuer.pem");
    commands::keys_generate("ES256", &out).unwrap();

    let signer =
        FileSigner::from_pem_file(out.to_str().unwrap(), SignatureAlgorithm::Es256).unwrap();
    assert_eq!(signer.sign(b"x").unwrap().len(), 64);
}

#[test]
fn cert_new_ca_then_issue_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let ca_cert = dir.path().join("root.pem");
    let ca_key = dir.path().join("root-key.pem");
    commands::cert_new_ca("Foundry Dev Root CA", &ca_cert, &ca_key, 3650).unwrap();

    let ca = parse_cert_pem(&std::fs::read(&ca_cert).unwrap()).unwrap();
    assert!(is_self_signed(&ca));

    let leaf_cert = dir.path().join("issuer-chain.pem");
    let leaf_key = dir.path().join("issuer.pem");
    commands::cert_issue(
        &ca_cert,
        &ca_key,
        "issuer.dev.local",
        &["issuer.dev.local".to_string()],
        &leaf_cert,
        &leaf_key,
        365,
    )
    .unwrap();

    let leaf_pem = std::fs::read(&leaf_cert).unwrap();
    assert!(!is_self_signed(&parse_cert_pem(&leaf_pem).unwrap()));
    assert!(match_san_dns(&leaf_pem, "issuer.dev.local").unwrap());
    // Leaf key is usable as a signer.
    let signer =
        FileSigner::from_pem_file(leaf_key.to_str().unwrap(), SignatureAlgorithm::Es256).unwrap();
    assert_eq!(signer.sign(b"x").unwrap().len(), 64);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry --test cli_pki 2>&1 | tail -20`
Expected: FAIL — `unresolved import foundry::commands`.

- [ ] **Step 3: Write the command handlers**

Create `crates/foundry/src/commands.rs`:

```rust
//! Thin CLI command handlers: parse-free logic that calls foundry-core and does file IO.

use anyhow::Context;
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::pki::{generate_ec_key, issue_leaf, new_ca};
use std::path::Path;
use std::str::FromStr;

/// `foundry keys generate` — write a fresh EC private key (PKCS#8 PEM).
pub fn keys_generate(alg: &str, out: &Path) -> anyhow::Result<()> {
    let alg = SignatureAlgorithm::from_str(alg)?;
    let km = generate_ec_key(alg)?;
    std::fs::write(out, km.private_pem.as_bytes())
        .with_context(|| format!("writing key to {}", out.display()))?;
    tracing::info!(path = %out.display(), alg = %alg, "generated EC private key");
    println!("OK: wrote key {}", out.display());
    Ok(())
}

/// `foundry cert new-ca` — write a self-signed CA cert + key.
pub fn cert_new_ca(
    common_name: &str,
    out_cert: &Path,
    out_key: &Path,
    days: i64,
) -> anyhow::Result<()> {
    let ca = new_ca(common_name, days)?;
    std::fs::write(out_cert, ca.cert_pem.as_bytes())
        .with_context(|| format!("writing CA cert to {}", out_cert.display()))?;
    std::fs::write(out_key, ca.key_pem.as_bytes())
        .with_context(|| format!("writing CA key to {}", out_key.display()))?;
    tracing::info!(cert = %out_cert.display(), key = %out_key.display(), "generated CA");
    println!("OK: wrote CA cert {} and key {}", out_cert.display(), out_key.display());
    Ok(())
}

/// `foundry cert issue` — issue a leaf cert (+ its key) signed by the given CA.
pub fn cert_issue(
    ca: &Path,
    key: &Path,
    common_name: &str,
    san_dns: &[String],
    out_cert: &Path,
    out_key: &Path,
    days: i64,
) -> anyhow::Result<()> {
    let ca_cert_pem = std::fs::read_to_string(ca)
        .with_context(|| format!("reading CA cert {}", ca.display()))?;
    let ca_key_pem = std::fs::read_to_string(key)
        .with_context(|| format!("reading CA key {}", key.display()))?;
    let leaf = issue_leaf(&ca_cert_pem, &ca_key_pem, common_name, san_dns, days)?;
    std::fs::write(out_cert, leaf.cert_pem.as_bytes())
        .with_context(|| format!("writing leaf cert to {}", out_cert.display()))?;
    std::fs::write(out_key, leaf.key_pem.as_bytes())
        .with_context(|| format!("writing leaf key to {}", out_key.display()))?;
    tracing::info!(cert = %out_cert.display(), key = %out_key.display(), "issued leaf certificate");
    println!("OK: wrote leaf cert {} and key {}", out_cert.display(), out_key.display());
    Ok(())
}
```

Register the module in `crates/foundry/src/lib.rs`:

```rust
pub mod cli;
pub mod commands;
pub mod logging;
pub mod server;
```

- [ ] **Step 4: Add the clap subcommands**

In `crates/foundry/src/cli.rs`, add two variants to `enum Command` (keep `Serve` and `Config`):

```rust
    /// Key material operations.
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Certificate operations.
    Cert {
        #[command(subcommand)]
        action: CertAction,
    },
```

Then add these subcommand enums (after `ConfigAction`):

```rust
#[derive(Debug, Subcommand)]
pub enum KeysAction {
    /// Generate a fresh EC private key (PKCS#8 PEM).
    Generate {
        #[arg(long, default_value = "ES256")]
        alg: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum CertAction {
    /// Create a self-signed CA certificate + key.
    NewCa {
        #[arg(long, default_value = "Foundry Dev Root CA")]
        common_name: String,
        #[arg(long)]
        out_cert: PathBuf,
        #[arg(long)]
        out_key: PathBuf,
        #[arg(long, default_value_t = 3650)]
        days: i64,
    },
    /// Issue a leaf certificate signed by a CA.
    Issue {
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        common_name: String,
        #[arg(long = "san-dns")]
        san_dns: Vec<String>,
        #[arg(long)]
        out_cert: PathBuf,
        #[arg(long)]
        out_key: PathBuf,
        #[arg(long, default_value_t = 365)]
        days: i64,
    },
}
```

- [ ] **Step 5: Dispatch in `main.rs`**

In `crates/foundry/src/main.rs`, update the imports and add match arms. Change the import line to include the new types:

```rust
use foundry::cli::{Cli, CertAction, Command, ConfigAction, KeysAction};
use foundry::{commands, logging, server};
```

(Remove the separate `use foundry::logging;` / `use foundry::server;` lines — they are now covered by the grouped `use foundry::{commands, logging, server};`. Keep `use foundry_core::config::Config;` and `use clap::Parser;`.)

Add these arms to the `match cli.command { .. }` block (alongside `Config` and `Serve`):

```rust
        Command::Keys {
            action: KeysAction::Generate { alg, out },
        } => commands::keys_generate(&alg, &out),
        Command::Cert {
            action: CertAction::NewCa {
                common_name,
                out_cert,
                out_key,
                days,
            },
        } => commands::cert_new_ca(&common_name, &out_cert, &out_key, days),
        Command::Cert {
            action: CertAction::Issue {
                ca,
                key,
                common_name,
                san_dns,
                out_cert,
                out_key,
                days,
            },
        } => commands::cert_issue(&ca, &key, &common_name, &san_dns, &out_cert, &out_key, days),
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p foundry --test cli_pki 2>&1 | tail -20`
Expected: PASS — `keys_generate_writes_loadable_key`, `cert_new_ca_then_issue_leaf`.

Also confirm existing tests still pass and the CLI parses:
Run: `cargo test -p foundry 2>&1 | tail -20`
Expected: PASS — `cli::` and `health` tests unaffected.
Run: `cargo run -p foundry -- cert --help 2>&1 | tail -15`
Expected: help text listing `new-ca` and `issue`.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/src/commands.rs crates/foundry/src/cli.rs crates/foundry/src/main.rs crates/foundry/src/lib.rs crates/foundry/tests/cli_pki.rs
git commit -m "feat(cli): add keys generate and cert new-ca/issue commands"
```

---

### Task 9: CLI — `quickstart` / `init` (dev PKI + ready-to-run config)

**Files:**
- Modify: `crates/foundry/src/commands.rs`
- Modify: `crates/foundry/src/cli.rs`
- Modify: `crates/foundry/src/main.rs`
- Create: `crates/foundry/tests/quickstart.rs`

**Interfaces:**
- Consumes: `foundry_core::pki::{new_ca, issue_leaf}`, `foundry_core::config::Config`.
- Produces (in `foundry::commands`):
  - `fn quickstart(dir: &std::path::Path, out_config: &std::path::Path) -> anyhow::Result<()>` — writes `dir/trust/root.pem` (+ `root-key.pem`), `dir/keys/{issuer_sdjwt,verifier_signing,statuslist_signer}.pem` (leaf keys) and `*-chain.pem` (leaf certs = x5c), and `out_config` (a valid `config.yaml`).
  - New clap subcommand `Command::Quickstart { .. }` (aliased `init`).

> **PKI shape:** 2-level chain — one self-signed root CA (the trust anchor, excluded from x5c) directly signs each leaf. Each leaf's `*-chain.pem` (its x5c file) therefore contains only the leaf cert (leaf..intermediate with zero intermediates). Output is dev/test only.

- [ ] **Step 1: Write the failing test**

Create `crates/foundry/tests/quickstart.rs`:

```rust
use foundry::commands;
use foundry_core::config::Config;

#[test]
fn quickstart_emits_valid_pki_and_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("config.yaml");
    commands::quickstart(dir.path(), &cfg_path).unwrap();

    // Files exist.
    for rel in [
        "trust/root.pem",
        "keys/issuer_sdjwt.pem",
        "keys/issuer_sdjwt-chain.pem",
        "keys/verifier_signing.pem",
        "keys/verifier_signing-chain.pem",
        "keys/statuslist_signer.pem",
        "keys/statuslist_signer-chain.pem",
    ] {
        assert!(dir.path().join(rel).exists(), "missing {rel}");
    }

    // Config parses and passes structural validation.
    let cfg = Config::load(&cfg_path).unwrap();
    cfg.validate().unwrap();

    // Key material resolves relative to the config directory (Task 10 API).
    cfg.validate_key_material(dir.path()).unwrap();
}
```

> This test also exercises `validate_key_material` (Task 10). If executing strictly task-by-task, expect this specific assertion to compile only after Task 10; that is acceptable because Task 9 and Task 10 are committed in sequence and the full suite is run green at the end of Task 10. If you want Task 9 to go green independently, temporarily comment the last line, then re-enable it in Task 10 Step 1. Note this choice in your report.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry --test quickstart 2>&1 | tail -20`
Expected: FAIL — `no function quickstart in foundry::commands` (and/or `no method validate_key_material`).

- [ ] **Step 3: Write the `quickstart` handler**

Append to `crates/foundry/src/commands.rs`:

```rust
/// `foundry quickstart` — generate a 2-level dev PKI and a ready-to-run config.
/// DEV/TEST ONLY. Not for production.
pub fn quickstart(dir: &Path, out_config: &Path) -> anyhow::Result<()> {
    let keys_dir = dir.join("keys");
    let trust_dir = dir.join("trust");
    std::fs::create_dir_all(&keys_dir)?;
    std::fs::create_dir_all(&trust_dir)?;

    // Root CA (trust anchor).
    let root = new_ca("Foundry Dev Root CA", 3650)?;
    std::fs::write(trust_dir.join("root.pem"), root.cert_pem.as_bytes())?;
    std::fs::write(trust_dir.join("root-key.pem"), root.key_pem.as_bytes())?;

    // One leaf per named key. Each chain file (x5c) holds just the leaf.
    for (name, cn, san) in [
        ("issuer_sdjwt", "Foundry Dev Issuer", "localhost"),
        ("verifier_signing", "Foundry Dev Verifier", "localhost"),
        ("statuslist_signer", "Foundry Dev Status List", "localhost"),
    ] {
        let leaf = issue_leaf(&root.cert_pem, &root.key_pem, cn, &[san.to_string()], 365)?;
        std::fs::write(keys_dir.join(format!("{name}.pem")), leaf.key_pem.as_bytes())?;
        std::fs::write(
            keys_dir.join(format!("{name}-chain.pem")),
            leaf.cert_pem.as_bytes(),
        )?;
    }

    std::fs::write(out_config, QUICKSTART_CONFIG.as_bytes())?;

    tracing::warn!("quickstart PKI is DEV/TEST ONLY — do not use in production");
    println!("OK: wrote dev PKI under {} and config {}", dir.display(), out_config.display());
    println!("   ⚠  DEV/TEST ONLY — self-signed dev PKI, not for production.");
    println!("   Next: foundry serve --config {}", out_config.display());
    Ok(())
}

/// Ready-to-run dev config wired to quickstart's key/cert paths (relative to the config dir).
const QUICKSTART_CONFIG: &str = r#"# Foundry dev config generated by `foundry quickstart`.
# ⚠ DEV/TEST ONLY — uses a self-signed dev PKI. Do NOT use in production.
server:
  wallet_facing:
    public_base_url: https://localhost:8443
    bind: 0.0.0.0:8443
  admin:
    bind: 127.0.0.1:9000
    api_key: dev-admin-key
storage:
  path: ./foundry.db
  transaction_ttl_secs: 600
keys:
  issuer_sdjwt:
    private_key: ./keys/issuer_sdjwt.pem
    x5c: ./keys/issuer_sdjwt-chain.pem
    alg: ES256
  verifier_signing:
    private_key: ./keys/verifier_signing.pem
    x5c: ./keys/verifier_signing-chain.pem
    alg: ES256
  statuslist_signer:
    private_key: ./keys/statuslist_signer.pem
    x5c: ./keys/statuslist_signer-chain.pem
    alg: ES256
trust_anchors:
  - name: foundry-dev-root
    certs: ./trust/root.pem
issuer:
  credential_issuer: https://localhost:8443
  wallet_attestation: { mode: optional }
  key_attestation: { mode: optional }
  status_list:
    enabled: true
    signing_key: statuslist_signer
    list_size: 1048576
    public_base_url: https://localhost:8443/statuslists
credential_types:
  - id: pid
    format: dc+sd-jwt
    vct: https://localhost:8443/vct/pid
    cryptographic_holder_binding: true
    display: [{ name: "Person ID", locale: en-US }]
    claims:
      - path: [given_name]
        selectively_disclosable: true
      - path: [birthdate]
        selectively_disclosable: true
verifier:
  client_id_scheme: x509_san_dns
  signing_key: verifier_signing
  response_encryption: { alg: ECDH-ES, enc: A128GCM }
  transaction_data_hashes_alg: [sha-256]
  named_queries:
    - id: over18
      dcql: { credentials: [] }
"#;
```

- [ ] **Step 4: Add the clap subcommand + dispatch**

In `crates/foundry/src/cli.rs`, add to `enum Command`:

```rust
    /// Generate a dev PKI and a ready-to-run config (alias: init). DEV/TEST ONLY.
    #[command(alias = "init")]
    Quickstart {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[arg(long = "out-config", default_value = "config.yaml")]
        out_config: PathBuf,
    },
```

In `crates/foundry/src/main.rs`, add a match arm (the `Command` import already covers `Quickstart`):

```rust
        Command::Quickstart { dir, out_config } => commands::quickstart(&dir, &out_config),
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p foundry --test quickstart 2>&1 | tail -20`
Expected: PASS (if you temporarily commented the `validate_key_material` line per the Step 1 note, it passes now; otherwise it goes green at the end of Task 10).

Manual check:
Run: `cd "$(mktemp -d)" && (cd /Users/senexi/dev/eudiw/foundry && cargo build -q -p foundry) && /Users/senexi/dev/eudiw/foundry/target/debug/foundry quickstart --dir . --out-config config.yaml 2>&1 | tail -8 && ls keys trust`
Expected: prints the DEV/TEST warning + next-step line; `keys/` has 6 files, `trust/` has 2.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/src/commands.rs crates/foundry/src/cli.rs crates/foundry/src/main.rs crates/foundry/tests/quickstart.rs
git commit -m "feat(cli): add quickstart command generating dev PKI and config"
```

---

### Task 10: Config key-material validation + wiring + full workspace check

**Files:**
- Modify: `crates/foundry-core/src/config/validate.rs`
- Modify: `crates/foundry/src/main.rs`
- Create: `crates/foundry-core/tests/validate_key_material.rs`

**Interfaces:**
- Consumes: `crypto::{FileSigner, SignatureAlgorithm}`, `trust::{parse_cert_pem, is_self_signed}`, config model.
- Produces:
  - `impl Config { pub fn validate_key_material(&self, base_dir: &std::path::Path) -> Result<(), ConfigError> }` — resolves every `keys.*.private_key` (loadable as a signer), every `keys.*.x5c` (parses; leaf must NOT be self-signed), and every `trust_anchors.*.certs` (parses), all relative to `base_dir`.
  - `main.rs` calls it for both `serve` and `config validate`, using the config file's parent directory as `base_dir`.

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-core/tests/validate_key_material.rs`:

```rust
use foundry_core::config::Config;
use foundry_core::pki::{issue_leaf, new_ca};
use std::fs;

/// Build a temp dir with a real dev PKI + a config that references it, then
/// assert validate_key_material accepts it and rejects a self-signed x5c leaf.
fn write_pki(dir: &std::path::Path) {
    fs::create_dir_all(dir.join("keys")).unwrap();
    fs::create_dir_all(dir.join("trust")).unwrap();
    let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
    fs::write(dir.join("trust/root.pem"), &root.cert_pem).unwrap();
    let leaf = issue_leaf(&root.cert_pem, &root.key_pem, "localhost",
        &["localhost".to_string()], 365).unwrap();
    fs::write(dir.join("keys/issuer_sdjwt.pem"), &leaf.key_pem).unwrap();
    fs::write(dir.join("keys/issuer_sdjwt-chain.pem"), &leaf.cert_pem).unwrap();
    // Also stash the self-signed root as a key so we can test the negative path.
    fs::write(dir.join("keys/selfsigned-chain.pem"), &root.cert_pem).unwrap();
    fs::write(dir.join("keys/selfsigned.pem"), &leaf.key_pem).unwrap();
}

const CONFIG_TMPL: &str = r#"server:
  wallet_facing: { public_base_url: https://localhost:8443, bind: 0.0.0.0:8443 }
  admin: { bind: 127.0.0.1:9000, api_key: dev }
storage: { path: ./foundry.db, transaction_ttl_secs: 600 }
keys:
  issuer_sdjwt:
    private_key: ./keys/issuer_sdjwt.pem
    x5c: ./keys/issuer_sdjwt-chain.pem
    alg: ES256
trust_anchors:
  - name: root
    certs: ./trust/root.pem
issuer:
  credential_issuer: https://localhost:8443
  wallet_attestation: { mode: optional }
  key_attestation: { mode: optional }
  status_list: { enabled: false }
credential_types: []
verifier:
  client_id_scheme: x509_san_dns
  signing_key: issuer_sdjwt
  transaction_data_hashes_alg: [sha-256]
  named_queries: []
"#;

#[test]
fn accepts_valid_key_material() {
    let dir = tempfile::tempdir().unwrap();
    write_pki(dir.path());
    let cfg_path = dir.path().join("config.yaml");
    fs::write(&cfg_path, CONFIG_TMPL).unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    cfg.validate().unwrap();
    cfg.validate_key_material(dir.path()).unwrap();
}

#[test]
fn rejects_self_signed_x5c_leaf() {
    let dir = tempfile::tempdir().unwrap();
    write_pki(dir.path());
    // Point the x5c at the self-signed root.
    let bad = CONFIG_TMPL.replace(
        "x5c: ./keys/issuer_sdjwt-chain.pem",
        "x5c: ./keys/selfsigned-chain.pem",
    );
    let cfg_path = dir.path().join("config.yaml");
    fs::write(&cfg_path, bad).unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    let err = cfg.validate_key_material(dir.path()).unwrap_err();
    assert!(err.to_string().contains("self-signed"));
}

#[test]
fn reports_missing_key_file() {
    let dir = tempfile::tempdir().unwrap();
    // No PKI written → files absent.
    let cfg_path = dir.path().join("config.yaml");
    fs::write(&cfg_path, CONFIG_TMPL).unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    assert!(cfg.validate_key_material(dir.path()).is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core --test validate_key_material 2>&1 | tail -20`
Expected: FAIL — `no method named validate_key_material`.

- [ ] **Step 3: Implement `validate_key_material`**

In `crates/foundry-core/src/config/validate.rs`, add these imports at the top (below the existing `use` lines):

```rust
use crate::crypto::{FileSigner, SignatureAlgorithm};
use std::path::Path;
use std::str::FromStr;
```

Then add a second `impl Config` block (below the existing one):

```rust
impl Config {
    /// Filesystem-aware validation: every key/cert reference must resolve
    /// (relative to `base_dir`), keys must load as signers, x5c leaves must
    /// parse and MUST NOT be self-signed (HAIP §6.1.1), and trust-anchor
    /// certs must parse.
    pub fn validate_key_material(&self, base_dir: &Path) -> Result<(), ConfigError> {
        for (name, entry) in &self.keys {
            let alg = SignatureAlgorithm::from_str(&entry.alg)
                .map_err(|e| ConfigError::Validation(format!("key '{name}': {e}")))?;
            let key_path = base_dir.join(&entry.private_key);
            let key_path = key_path.to_string_lossy();
            FileSigner::from_pem_file(&key_path, alg)
                .map_err(|e| ConfigError::Validation(format!("key '{name}': {e}")))?;

            if let Some(x5c) = &entry.x5c {
                let cert_path = base_dir.join(x5c);
                let pem = std::fs::read(&cert_path).map_err(|e| {
                    ConfigError::Validation(format!("key '{name}' x5c {}: {e}", cert_path.display()))
                })?;
                let cert = crate::trust::parse_cert_pem(&pem)
                    .map_err(|e| ConfigError::Validation(format!("key '{name}' x5c: {e}")))?;
                if crate::trust::is_self_signed(&cert) {
                    return Err(ConfigError::Validation(format!(
                        "key '{name}' x5c leaf must not be self-signed (HAIP §6.1.1)"
                    )));
                }
            }
        }

        for anchor in &self.trust_anchors {
            let path = base_dir.join(&anchor.certs);
            let pem = std::fs::read(&path).map_err(|e| {
                ConfigError::Validation(format!(
                    "trust anchor '{}' {}: {e}",
                    anchor.name,
                    path.display()
                ))
            })?;
            crate::trust::parse_cert_pem(&pem).map_err(|e| {
                ConfigError::Validation(format!("trust anchor '{}': {e}", anchor.name))
            })?;
        }

        Ok(())
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core --test validate_key_material 2>&1 | tail -20`
Expected: PASS — `accepts_valid_key_material`, `rejects_self_signed_x5c_leaf`, `reports_missing_key_file`.

- [ ] **Step 5: Wire it into the CLI**

In `crates/foundry/src/main.rs`, in BOTH the `Config { action: ConfigAction::Validate { config } }` arm and the `Serve { config }` arm, call `validate_key_material` after `cfg.validate()?`, resolving `base_dir` from the config file's parent. Update the two arms:

```rust
        Command::Config {
            action: ConfigAction::Validate { config },
        } => {
            let cfg = Config::load(&config)?;
            cfg.validate()?;
            let base_dir = config.parent().unwrap_or_else(|| std::path::Path::new("."));
            cfg.validate_key_material(base_dir)?;
            tracing::info!(path = %config.display(), "config is valid");
            println!("OK: {} is valid", config.display());
            Ok(())
        }
        Command::Serve { config } => {
            let cfg = Config::load(&config)?;
            cfg.validate()?;
            let base_dir = config.parent().unwrap_or_else(|| std::path::Path::new("."));
            cfg.validate_key_material(base_dir)?;
            server::serve(cfg).await
        }
```

If Task 9's `quickstart.rs` test had the `validate_key_material` line commented, re-enable it now.

- [ ] **Step 6: End-to-end manual check (quickstart → validate)**

Run:
```bash
cd "$(mktemp -d)" && \
/Users/senexi/dev/eudiw/foundry/target/debug/foundry quickstart --dir . --out-config config.yaml >/dev/null 2>&1 || \
  (cd /Users/senexi/dev/eudiw/foundry && cargo build -q -p foundry) ; \
cd "$(mktemp -d)" && /Users/senexi/dev/eudiw/foundry/target/debug/foundry quickstart --dir . --out-config config.yaml >/dev/null && \
/Users/senexi/dev/eudiw/foundry/target/debug/foundry config validate --config config.yaml 2>&1 | tail -3
```
Expected: `OK: config.yaml is valid` (quickstart output validates cleanly, proving the whole loop: generate PKI → emit config → load → structural validate → key-material validate).

- [ ] **Step 7: Full verification (scoped to OUR crates) + workspace build**

The vendored crates are exempt from our fmt/clippy bar. First normalize formatting (also fixes any missing trailing newlines in files added by this plan):

```bash
cargo fmt -p foundry-core -p foundry
```

Then verify:
```bash
cargo fmt -p foundry-core -p foundry -- --check && \
cargo clippy -p foundry-core -p foundry --all-targets -- -D warnings 2>&1 | tail -20 && \
cargo test -p foundry-core -p foundry 2>&1 | tail -30 && \
cargo build --workspace 2>&1 | tail -5
```
Expected: fmt clean, clippy no warnings, all `foundry-core` + `foundry` tests pass (crypto, trust, pki, cli_pki, quickstart, validate_key_material, plus the Plan 1 suite), and the full workspace builds (exit 0). If `cargo fmt` changed files, stage them in the commit.

- [ ] **Step 8: Commit (including the updated lockfile)**

```bash
git add crates/foundry-core/src/config/validate.rs crates/foundry-core/tests/validate_key_material.rs crates/foundry/src/main.rs Cargo.lock
git commit -m "feat(core): add filesystem-aware key-material validation and wire into CLI"
```

---

## Self-Review

**1. Spec coverage (Plan 2 slice — spec §5 Quickstart, §6 Crypto/Trust internals):**
- `Signer` trait seam for future KMS/HSM → Task 2 (`Signer`), Task 3 (`FileSigner`). ✓
- ES256 default + ES384/ES512 → Tasks 2, 3, 5 (all three algs generated + signed). ✓
- File-based signer loads PEM from `keys` config → Task 3 + Task 10 (validate loads them). ✓
- X.509 parse/validate via maintained lib → Task 4 (x509-cert). ✓
- Build `x5c` leaf..intermediate, anchor excluded → Task 7 (`build_x5c`, order preserved). ✓
- Validate incoming chains (path to anchor, reject self-signed leaf, validity windows) → Task 7 (`validate_chain`). ✓ (crypto signature verification explicitly deferred — see Known limitation.)
- `x509_san_dns` SAN matching → Task 7 (`match_san_dns`). ✓
- `foundry keys generate` → Task 8. ✓
- `foundry cert new-ca` / `cert issue` → Task 8. ✓
- `foundry quickstart` / `init`: self-signed dev PKI (2-level root→leaf), writes keys/ + trust/, emits ready-to-run config with pid type + over18 named query, DEV-ONLY warning, prints next steps → Task 9. ✓
- Config validation rules: every keys/trust_anchors/signing_key reference resolves; certs parse; non-self-signed leaf where HAIP requires → Task 10 (`validate_key_material`) + existing structural `validate` (Plan 1). ✓
- Out of Plan 2 scope (later plans): SD-JWT VC / mdoc format crates (Plan 3), status list token issue/serve/verify (later), issuer/verifier HTTP endpoints, DCQL, OpenAPI. Also deferred: cryptographic cert-chain signature verification (trust-hardening pass).

**2. Placeholder scan:** No "TBD/implement later" placeholders. The Task 2 `FileSigner` placeholder struct is an explicit, specified, single-task scaffold that Task 3 replaces (not an open-ended TODO). The one `TODO(trust-hardening)` comment is a deliberate, documented deferral of signature-path validation with a concrete follow-up, not a missing implementation.

**3. Type consistency (checked across tasks):**
- `SignatureAlgorithm { Es256, Es384, Es512 }` — defined Task 2, used identically in Tasks 3, 5, 6, 8, 10 (via `FromStr`/variants). ✓
- `Signer` methods `algorithm()`/`sign()->Result<Vec<u8>,CryptoError>`/`public_jwk()->Result<serde_json::Value,CryptoError>` — Task 2 def, Task 3 impl, used in tests Tasks 3/5/8. ✓
- `FileSigner::from_pem(&[u8], SignatureAlgorithm)` and `from_pem_file(&str, SignatureAlgorithm)` — Task 3 def; called in Tasks 5, 8 tests and Task 10 impl. ✓
- `pki::KeyMaterial { private_pem, public_pem }` (Task 5) and `pki::CertMaterial { cert_pem, key_pem }` (Task 6) — field names used consistently in Tasks 8, 9 handlers and Task 10 test. ✓
- `trust::parse_cert_pem`/`is_self_signed`/`validity_window`/`san_dns_names` (Task 4) + `build_x5c`/`TrustStore`/`validate_chain`/`match_san_dns` (Task 7) — signatures reused verbatim in Tasks 8, 10 and their tests. ✓
- `CryptoError`/`TrustError` variants (Task 1) — matched in tests across Tasks 2–7; `ConfigError::Validation(String)` wrapping used in Task 10. ✓
- `commands::{keys_generate, cert_new_ca, cert_issue, quickstart}` (Tasks 8, 9) — signatures match the `main.rs` dispatch arms and the integration tests. ✓
- clap `Command` variants `Keys`/`Cert`/`Quickstart` + `KeysAction`/`CertAction` — defined Tasks 8/9, dispatched in `main.rs` the same task. ✓

**4. Incremental dependency additions (each added in the first task that needs it):**
- josekit → Task 2. x509-cert + base64 → Task 4. rcgen (feature `x509-parser`) + time → Task 6. All referenced via `workspace = true`. `Cargo.lock` committed in Task 10. ✓

**5. Test genuineness:** Every task captures a real RED (missing item / no method) before implementing, and tests exercise real behavior (actual signing byte-lengths, real rcgen-issued certs parsed by x509-cert, real files written+reloaded, self-signed rejection on a genuinely self-signed cert) — not mocks. ✓