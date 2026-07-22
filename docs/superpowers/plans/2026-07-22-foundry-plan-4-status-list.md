# Token Status List (draft-ietf-oauth-status-list-14) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Token Status List mechanism (bit-packed status arrays, zlib compression, signed Status List Tokens) as a new `status_list` module inside the existing `foundry-core` crate, per the spec's own workspace layout (`foundry-core` owns "crypto, key/cert store, X.509 trust, Token Status List, storage trait + SQLite impl, config model"). This delivers pure build/verify functions — issuing and checking a signed Status List Token — that `foundry-issuer` and `foundry-verifier` will both depend on in later phases.

**Architecture:** A single new module, `crates/foundry-core/src/status_list/mod.rs`, layered bottom-up: (1) bit-packing of per-token status values into the spec's compressed-byte-array shape, (2) zlib (RFC 1950/1951) compression at max level, (3) a `StatusList` struct combining both into the JSON `{bits, lst, aggregation_uri?}` shape, (4) a signed JWT "Status List Token" (`typ: statuslist+jwt`) built the same way `foundry-sd-jwt-vc`'s builder/verifier build and verify JWS-based credentials — reusing `foundry_core::crypto::Signer` for signing and `foundry_core::trust::{TrustStore, validate_chain, cert_ec_public_coords}` for x5c-based verification. A new small `trust::x5c_entry_to_pem` helper is added (additive, does not touch already-merged code) so both this module and any format crate can rebuild a PEM from a JOSE `x5c` entry.

**Tech Stack:** Rust 1.97, edition 2021, `flate2` (new dependency, zlib DEFLATE per RFC 1950/1951), `josekit` 0.10 (JWS verify + JWK), `serde_json`, `base64` 0.22.

## Prerequisites (verified present)

Plans 1–3 are merged. This plan builds directly on these existing, working `foundry-core` APIs (verified against the tree):

- `foundry_core::crypto::{Signer, SignatureAlgorithm, FileSigner}` — `Signer::algorithm() -> SignatureAlgorithm`, `Signer::sign(&[u8]) -> Result<Vec<u8>, CryptoError>`, `Signer::public_jwk()`; `SignatureAlgorithm::as_str() -> &'static str` (`"ES256"`/`"ES384"`/`"ES512"`).
- `foundry_core::pki::{new_ca, issue_leaf}` — `new_ca(common_name: &str, days: i64) -> Result<CertMaterial, CryptoError>`; `issue_leaf(ca_cert_pem: &str, ca_key_pem: &str, common_name: &str, san_dns: &[String], days: i64) -> Result<CertMaterial, CryptoError>`; `CertMaterial { cert_pem: String, key_pem: String }`.
- `foundry_core::trust::{TrustStore, parse_cert_pem, validate_chain, cert_ec_public_coords}` — `TrustStore::from_pems(&[Vec<u8>]) -> Result<TrustStore, TrustError>`; `validate_chain(leaf_pem: &[u8], intermediates: &[Vec<u8>], store: &TrustStore, now_unix: u64) -> Result<(), TrustError>`; `cert_ec_public_coords(&Certificate) -> Result<(Vec<u8>, Vec<u8>), TrustError>`.
- `foundry_core::error::FormatError` — existing variants `Serialization(String)`, `Deserialization(String)`, `InvalidStructure(String)`, `SignatureVerification(String)`, `Expired`, `Unsupported(String)` are reused as-is; this plan adds two new variants (Task 1).
- Reference pattern: `crates/foundry-sd-jwt-vc/src/verifier.rs` already implements this exact "parse compact JWS → validate x5c chain via `validate_chain` → verify signature via `cert_ec_public_coords` + `josekit`" flow for SD-JWT VC. This plan's Status List Token verifier follows the identical pattern, self-contained inside `foundry-core` (which cannot depend on `foundry-sd-jwt-vc` — the dependency direction is the other way around).

## Global Constraints

- Language / runtime: Rust (edition 2021), toolchain pinned at 1.97.
- Crate structure: this plan modifies **only** `foundry-core` (root `Cargo.toml` to register the new dependency, `crates/foundry-core/Cargo.toml`, `crates/foundry-core/src/lib.rs`, `crates/foundry-core/src/error.rs`, `crates/foundry-core/src/trust/mod.rs`, and the new `crates/foundry-core/src/status_list/mod.rs`). No other crate is touched.
- Errors: typed via `thiserror`, reusing/extending the existing `FormatError` enum (spec §7 names four typed error enums: `IssuanceError`, `VerificationError`, `TrustError`, `FormatError` — a signed status list token is a token *format*, so its errors belong in `FormatError`). **No `unwrap`/`panic`/`expect` in non-test code paths.**
- Crypto: signing uses the `Signer` trait; verification uses `josekit` JWS verifiers built from the leaf certificate's EC public key coordinates, exactly as `foundry-sd-jwt-vc`'s verifier does.
- Compression: byte arrays are compressed using **DEFLATE (RFC 1951) wrapped in the ZLIB format (RFC 1950), at the highest compression level available** (draft-ietf-oauth-status-list-14 §4.1 step 5) — this is `flate2`'s `flate2::write::ZlibEncoder` / `flate2::read::ZlibDecoder` with `Compression::best()`. Do not use raw DEFLATE or gzip framing.
- Bit-packing: per §4.1, status blocks are packed from **least-significant bit to most-significant bit** within each byte, index 0 first; `bits` MUST be one of 1, 2, 4, 8; unused trailing bits MUST be zero.
- Status values: per §7.1, `0x00` = VALID, `0x01` = INVALID, `0x02` = SUSPENDED; `0x03` and `0x0C`–`0x0F` are permanently reserved as application-specific; all other values are also treated as application-specific by this implementation (forward-compatible, no panic on unknown values).
- Every code change lands via TDD: failing test first, then minimal implementation, then commit.
- Commit only the files a task declares. Never `git add -A`.

## Non-Goals (this phase)

- **Unpredictable index allocation.** HAIP requires a "unique unpredictable status-list index per credential" — that is a storage-backed allocation policy that belongs to `foundry-issuer` (a later phase), which will call into this module's `StatusList::build`/`status_at` but own the index-allocation strategy itself.
- **HTTP hosting of `/statuslists/{id}`.** Serving the Status List Token over HTTP, and the admin API to set a credential's status, belong to the `foundry-issuer`/`foundry` (bin) phases.
- **CWT/COSE status list encoding** (draft §4.3/§5.2). Only the JWT/JSON encoding (§4.2/§5.1) is implemented — consistent with this project's JOSE-first approach for SD-JWT VC; mdoc's own status checking will reuse the same verify function since IETF status lists are format-agnostic at the token level.
- **Status List Aggregation** (draft §9). `aggregation_uri` is stored/round-tripped but not fetched or processed.

---

## File Structure

**Workspace & foundry-core (modified):**
- `Cargo.toml` (root) — MODIFY: add `flate2` to `[workspace.dependencies]`.
- `crates/foundry-core/Cargo.toml` — MODIFY: add `flate2 = { workspace = true }`.
- `crates/foundry-core/src/lib.rs` — MODIFY: register `pub mod status_list;`.
- `crates/foundry-core/src/error.rs` — MODIFY: add two `FormatError` variants.
- `crates/foundry-core/src/trust/mod.rs` — MODIFY: add `x5c_entry_to_pem` helper.

**foundry-core/src/status_list (new):**
- `crates/foundry-core/src/status_list/mod.rs` — bit-packing, compression, `StatusList`, `StatusListToken` build/verify, `StatusValue`.

---

### Task 1: Crate wiring — dependency, module skeleton, `StatusValue`, error variants

**Files:**
- Modify: `Cargo.toml` (root)
- Modify: `crates/foundry-core/Cargo.toml`
- Modify: `crates/foundry-core/src/lib.rs`
- Modify: `crates/foundry-core/src/error.rs`
- Create: `crates/foundry-core/src/status_list/mod.rs`

**Interfaces:**
- Produces: `foundry_core::status_list::StatusValue` with `from_u8(u8) -> Self` and `to_u8(self) -> u8`; `foundry_core::error::FormatError::StatusIndexOutOfBounds { idx: u64, len: u64 }` and `FormatError::StatusSubjectMismatch { expected: String }`.

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-core/src/status_list/mod.rs`:

```rust
//! Token Status List (IETF draft-ietf-oauth-status-list-14): bit-packed
//! status arrays, zlib compression, and signed Status List Tokens.

use crate::error::FormatError;

/// A Referenced Token's status (draft-ietf-oauth-status-list-14 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusValue {
    Valid,
    Invalid,
    Suspended,
    ApplicationSpecific(u8),
}

impl StatusValue {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => StatusValue::Valid,
            0x01 => StatusValue::Invalid,
            0x02 => StatusValue::Suspended,
            other => StatusValue::ApplicationSpecific(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            StatusValue::Valid => 0x00,
            StatusValue::Invalid => 0x01,
            StatusValue::Suspended => 0x02,
            StatusValue::ApplicationSpecific(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_value_round_trips_known_values() {
        assert_eq!(StatusValue::from_u8(0x00), StatusValue::Valid);
        assert_eq!(StatusValue::from_u8(0x01), StatusValue::Invalid);
        assert_eq!(StatusValue::from_u8(0x02), StatusValue::Suspended);
        assert_eq!(StatusValue::Valid.to_u8(), 0x00);
        assert_eq!(StatusValue::Invalid.to_u8(), 0x01);
        assert_eq!(StatusValue::Suspended.to_u8(), 0x02);
    }

    #[test]
    fn status_value_unknown_is_application_specific() {
        assert_eq!(StatusValue::from_u8(0x03), StatusValue::ApplicationSpecific(3));
        assert_eq!(StatusValue::from_u8(0x0C), StatusValue::ApplicationSpecific(12));
        assert_eq!(StatusValue::ApplicationSpecific(7).to_u8(), 7);
    }
}
```

Add to `crates/foundry-core/src/lib.rs` (after the existing `pub mod pki;` line, keeping the list alphabetical):

```rust
pub mod status_list;
```

Add two variants to `FormatError` in `crates/foundry-core/src/error.rs` (insert after the existing `Unsupported(String)` variant, before the closing `}`):

```rust
    #[error("status list index {idx} out of bounds (list has {len} entries)")]
    StatusIndexOutOfBounds { idx: u64, len: u64 },
    #[error("status list subject mismatch: expected '{expected}'")]
    StatusSubjectMismatch { expected: String },
```

Add `flate2` to root `Cargo.toml`'s `[workspace.dependencies]` (after the `time` line):

```toml
flate2 = "1"
```

Add to `crates/foundry-core/Cargo.toml`'s `[dependencies]` (after `time = { workspace = true }`):

```toml
flate2 = { workspace = true }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core status_list::tests -- --nocapture`
Expected: FAIL to compile — `status_list` module not yet registered, or `FormatError` variants not defined (depending on edit order; if all edits above are applied together it will compile and PASS immediately since this step only adds new code). Since all four files are edited together in Step 1, run the test now to confirm it **passes** instead (this task has no separate red step because module registration and the enum are inseparable):

Run: `cargo test -p foundry-core status_list::tests -- --nocapture`
Expected: PASS (2 tests: `status_value_round_trips_known_values`, `status_value_unknown_is_application_specific`).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml crates/foundry-core/Cargo.toml crates/foundry-core/src/lib.rs crates/foundry-core/src/error.rs crates/foundry-core/src/status_list/mod.rs
git commit -m "feat(status-list): add flate2 dep, StatusValue enum, and FormatError variants"
```

---

### Task 2: Bit-packing — `pack_status_array` / `unpack_status`

**Files:**
- Modify: `crates/foundry-core/src/status_list/mod.rs`

**Interfaces:**
- Consumes: `foundry_core::error::FormatError::{Unsupported, InvalidStructure, StatusIndexOutOfBounds}` (Task 1).
- Produces:
  ```rust
  pub fn pack_status_array(values: &[u8], bits: u8) -> Result<Vec<u8>, FormatError>;
  pub fn unpack_status(byte_array: &[u8], bits: u8, idx: u64) -> Result<u8, FormatError>;
  ```

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `crates/foundry-core/src/status_list/mod.rs`:

```rust
    #[test]
    fn packs_bits1_least_significant_bit_first() {
        // index: 0 1 2 3 4 5 6 7 -> values 1 0 1 1 0 0 1 0
        // byte = sum(v_i << i) = 1 + 0 + 4 + 8 + 0 + 0 + 64 + 0 = 77 = 0x4D
        let packed = pack_status_array(&[1, 0, 1, 1, 0, 0, 1, 0], 1).unwrap();
        assert_eq!(packed, vec![0x4D]);
        for (idx, expected) in [1u8, 0, 1, 1, 0, 0, 1, 0].into_iter().enumerate() {
            assert_eq!(unpack_status(&packed, 1, idx as u64).unwrap(), expected);
        }
    }

    #[test]
    fn packs_bits2_four_statuses_per_byte() {
        // index 0..3 -> values 1,2,0,3 packed LSB-first: byte = 1 | (2<<2) | (0<<4) | (3<<6) = 0xC9
        let packed = pack_status_array(&[1, 2, 0, 3], 2).unwrap();
        assert_eq!(packed, vec![0xC9]);
        assert_eq!(unpack_status(&packed, 2, 0).unwrap(), 1);
        assert_eq!(unpack_status(&packed, 2, 1).unwrap(), 2);
        assert_eq!(unpack_status(&packed, 2, 2).unwrap(), 0);
        assert_eq!(unpack_status(&packed, 2, 3).unwrap(), 3);
    }

    #[test]
    fn packs_bits4_two_statuses_per_byte() {
        // byte = 5 | (10 << 4) = 0xA5
        let packed = pack_status_array(&[5, 10], 4).unwrap();
        assert_eq!(packed, vec![0xA5]);
        assert_eq!(unpack_status(&packed, 4, 0).unwrap(), 5);
        assert_eq!(unpack_status(&packed, 4, 1).unwrap(), 10);
    }

    #[test]
    fn packs_bits8_one_status_per_byte() {
        let packed = pack_status_array(&[200, 3], 8).unwrap();
        assert_eq!(packed, vec![200, 3]);
        assert_eq!(unpack_status(&packed, 8, 0).unwrap(), 200);
        assert_eq!(unpack_status(&packed, 8, 1).unwrap(), 3);
    }

    #[test]
    fn packing_spans_multiple_bytes() {
        // 5 values at bits=2 -> byte0 covers idx 0..3 (0xC9), byte1 covers idx 4 (value 2)
        let packed = pack_status_array(&[1, 2, 0, 3, 2], 2).unwrap();
        assert_eq!(packed, vec![0xC9, 0x02]);
        assert_eq!(unpack_status(&packed, 2, 4).unwrap(), 2);
    }

    #[test]
    fn rejects_unsupported_bit_widths() {
        let err = pack_status_array(&[1], 3).unwrap_err();
        assert!(matches!(err, FormatError::Unsupported(_)));
        let err = unpack_status(&[0], 3, 0).unwrap_err();
        assert!(matches!(err, FormatError::Unsupported(_)));
    }

    #[test]
    fn rejects_value_not_fitting_in_bits() {
        // bits=2 allows 0..=3; 4 does not fit.
        let err = pack_status_array(&[4], 2).unwrap_err();
        assert!(matches!(err, FormatError::InvalidStructure(_)));
    }

    #[test]
    fn unpack_out_of_bounds_index_errors() {
        // packed has 1 byte -> at bits=2 that covers indices 0..=3; index 4 is out of bounds.
        let err = unpack_status(&[0xC9], 2, 4).unwrap_err();
        match err {
            FormatError::StatusIndexOutOfBounds { idx, len } => {
                assert_eq!(idx, 4);
                assert_eq!(len, 4);
            }
            other => panic!("expected StatusIndexOutOfBounds, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core status_list::tests -- --nocapture`
Expected: FAIL — `pack_status_array`/`unpack_status` not defined.

- [ ] **Step 3: Implement bit-packing**

Insert into `crates/foundry-core/src/status_list/mod.rs`, after the `StatusValue` impl block and before `#[cfg(test)]`:

```rust
fn checked_bits(bits: u8) -> Result<(), FormatError> {
    if matches!(bits, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(FormatError::Unsupported(format!(
            "status list bits must be 1, 2, 4, or 8 (got {bits})"
        )))
    }
}

/// Pack per-token status values into the uncompressed byte array described
/// in draft-ietf-oauth-status-list-14 §4.1: statuses are packed `bits`-wide,
/// index 0 first, least-significant bit first within each byte.
pub fn pack_status_array(values: &[u8], bits: u8) -> Result<Vec<u8>, FormatError> {
    checked_bits(bits)?;
    let max_value = ((1u16 << bits) - 1) as u8;
    for &v in values {
        if v > max_value {
            return Err(FormatError::InvalidStructure(format!(
                "status value {v} does not fit in {bits} bits"
            )));
        }
    }
    let per_byte = 8 / bits as usize;
    let len = values.len().div_ceil(per_byte);
    let mut out = vec![0u8; len];
    for (idx, &v) in values.iter().enumerate() {
        let byte_idx = idx / per_byte;
        let bit_offset = (idx % per_byte) * bits as usize;
        out[byte_idx] |= v << bit_offset;
    }
    Ok(out)
}

/// Extract the `bits`-wide status value for `idx` from an uncompressed
/// status byte array (the inverse of `pack_status_array`).
pub fn unpack_status(byte_array: &[u8], bits: u8, idx: u64) -> Result<u8, FormatError> {
    checked_bits(bits)?;
    let per_byte = (8 / bits as usize) as u64;
    let byte_idx = (idx / per_byte) as usize;
    let byte = byte_array
        .get(byte_idx)
        .ok_or(FormatError::StatusIndexOutOfBounds {
            idx,
            len: byte_array.len() as u64 * per_byte,
        })?;
    let bit_offset = ((idx % per_byte) * bits as u64) as u32;
    let mask = ((1u16 << bits) - 1) as u8;
    Ok((byte >> bit_offset) & mask)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core status_list::tests -- --nocapture`
Expected: PASS (all tests in the module, including Task 1's).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/status_list/mod.rs
git commit -m "feat(status-list): implement bit-packed status array pack/unpack"
```

---

### Task 3: zlib compression — `compress_zlib` / `decompress_zlib`

**Files:**
- Modify: `crates/foundry-core/src/status_list/mod.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn compress_zlib(raw: &[u8]) -> Result<Vec<u8>, FormatError>;
  pub fn decompress_zlib(compressed: &[u8]) -> Result<Vec<u8>, FormatError>;
  ```

- [ ] **Step 1: Write the failing test**

Append to the `tests` module:

```rust
    #[test]
    fn zlib_round_trips_arbitrary_bytes() {
        let raw = vec![0xC9, 0x02, 0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x01, 0x01, 0x01, 0x01];
        let compressed = compress_zlib(&raw).unwrap();
        // A valid zlib stream starts with a CMF/FLG header (RFC 1950); the
        // low nibble of the first byte is the compression method (8 = deflate).
        assert_eq!(compressed[0] & 0x0F, 8);
        let decompressed = decompress_zlib(&compressed).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn zlib_round_trips_empty_input() {
        let compressed = compress_zlib(&[]).unwrap();
        let decompressed = decompress_zlib(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn decompress_rejects_garbage() {
        let err = decompress_zlib(&[0x00, 0x01, 0x02]).unwrap_err();
        assert!(matches!(err, FormatError::Deserialization(_)));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core status_list::tests::zlib -- --nocapture`
Expected: FAIL — `compress_zlib`/`decompress_zlib` not defined.

- [ ] **Step 3: Implement zlib compression**

Add near the top of `crates/foundry-core/src/status_list/mod.rs`, updating the module's `use` block to:

```rust
use crate::error::FormatError;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};
```

Insert after the bit-packing functions and before `#[cfg(test)]`:

```rust
/// zlib-compress (RFC 1950 wrapping RFC 1951 DEFLATE) at the highest
/// compression level, per draft-ietf-oauth-status-list-14 §4.1 step 5.
pub fn compress_zlib(raw: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(raw)
        .map_err(|e| FormatError::Serialization(format!("zlib compress: {e}")))?;
    encoder
        .finish()
        .map_err(|e| FormatError::Serialization(format!("zlib compress: {e}")))
}

/// zlib-decompress the inverse of `compress_zlib`.
pub fn decompress_zlib(compressed: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| FormatError::Deserialization(format!("zlib decompress: {e}")))?;
    Ok(out)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core status_list::tests -- --nocapture`
Expected: PASS (all tests so far).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/status_list/mod.rs
git commit -m "feat(status-list): implement zlib (RFC 1950/1951) compression"
```

---

### Task 4: `StatusList` struct — build, decode, JSON round trip

**Files:**
- Modify: `crates/foundry-core/src/status_list/mod.rs`

**Interfaces:**
- Consumes: `pack_status_array`, `unpack_status`, `compress_zlib`, `decompress_zlib` (Tasks 2–3); `StatusValue` (Task 1).
- Produces:
  ```rust
  pub struct StatusList { pub bits: u8, pub lst_b64url: String, pub aggregation_uri: Option<String> }
  impl StatusList {
      pub fn build(values: &[u8], bits: u8, aggregation_uri: Option<String>) -> Result<Self, FormatError>;
      pub fn decode_bytes(&self) -> Result<Vec<u8>, FormatError>;
      pub fn status_at(&self, idx: u64) -> Result<StatusValue, FormatError>;
      pub fn to_json(&self) -> serde_json::Value;
      pub fn from_json(value: &serde_json::Value) -> Result<Self, FormatError>;
  }
  ```

- [ ] **Step 1: Write the failing test**

Append to the `tests` module:

```rust
    #[test]
    fn status_list_build_and_status_at_round_trips() {
        // idx: 0=Invalid(1), 1=Suspended(2), 2=Valid(0), 3=ApplicationSpecific(3), 4=Suspended(2)
        let list = StatusList::build(&[1, 2, 0, 3, 2], 2, None).unwrap();
        assert_eq!(list.bits, 2);
        assert_eq!(list.status_at(0).unwrap(), StatusValue::Invalid);
        assert_eq!(list.status_at(1).unwrap(), StatusValue::Suspended);
        assert_eq!(list.status_at(2).unwrap(), StatusValue::Valid);
        assert_eq!(list.status_at(3).unwrap(), StatusValue::ApplicationSpecific(3));
        assert_eq!(list.status_at(4).unwrap(), StatusValue::Suspended);
    }

    #[test]
    fn status_list_decode_bytes_matches_packed_array() {
        let list = StatusList::build(&[1, 2, 0, 3, 2], 2, None).unwrap();
        assert_eq!(list.decode_bytes().unwrap(), vec![0xC9, 0x02]);
    }

    #[test]
    fn status_list_json_round_trips() {
        let list = StatusList::build(&[0, 1, 2, 3], 2, Some("https://example.com/agg".to_string())).unwrap();
        let json = list.to_json();
        assert_eq!(json["bits"], 2);
        assert_eq!(json["aggregation_uri"], "https://example.com/agg");
        let parsed = StatusList::from_json(&json).unwrap();
        assert_eq!(parsed.bits, list.bits);
        assert_eq!(parsed.lst_b64url, list.lst_b64url);
        assert_eq!(parsed.aggregation_uri, list.aggregation_uri);
    }

    #[test]
    fn status_list_from_json_rejects_missing_fields() {
        let err = StatusList::from_json(&serde_json::json!({"lst": "abc"})).unwrap_err();
        assert!(matches!(err, FormatError::InvalidStructure(_)));
        let err = StatusList::from_json(&serde_json::json!({"bits": 2})).unwrap_err();
        assert!(matches!(err, FormatError::InvalidStructure(_)));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core status_list::tests::status_list -- --nocapture`
Expected: FAIL — `StatusList` not defined.

- [ ] **Step 3: Implement `StatusList`**

Update the `use` block at the top of `crates/foundry-core/src/status_list/mod.rs` to add base64 and JSON:

```rust
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use serde_json::{json, Value};
```

Insert after the zlib functions and before `#[cfg(test)]`:

```rust
/// A Status List per draft-ietf-oauth-status-list-14 §4.2 (JSON encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList {
    pub bits: u8,
    pub lst_b64url: String,
    pub aggregation_uri: Option<String>,
}

impl StatusList {
    /// Build a Status List from per-token status values.
    pub fn build(
        values: &[u8],
        bits: u8,
        aggregation_uri: Option<String>,
    ) -> Result<Self, FormatError> {
        let raw = pack_status_array(values, bits)?;
        let compressed = compress_zlib(&raw)?;
        Ok(Self {
            bits,
            lst_b64url: B64URL.encode(compressed),
            aggregation_uri,
        })
    }

    /// Decompress `lst` back into the raw, unpacked-ready byte array.
    pub fn decode_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let compressed = B64URL
            .decode(&self.lst_b64url)
            .map_err(|e| FormatError::Deserialization(format!("lst base64: {e}")))?;
        decompress_zlib(&compressed)
    }

    /// Look up a single Referenced Token's status by index.
    pub fn status_at(&self, idx: u64) -> Result<StatusValue, FormatError> {
        let raw = self.decode_bytes()?;
        let v = unpack_status(&raw, self.bits, idx)?;
        Ok(StatusValue::from_u8(v))
    }

    pub fn to_json(&self) -> Value {
        let mut obj = json!({ "bits": self.bits, "lst": self.lst_b64url });
        if let Some(uri) = &self.aggregation_uri {
            obj["aggregation_uri"] = json!(uri);
        }
        obj
    }

    pub fn from_json(value: &Value) -> Result<Self, FormatError> {
        let bits = value
            .get("bits")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| FormatError::InvalidStructure("status_list.bits missing".into()))?
            as u8;
        let lst_b64url = value
            .get("lst")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormatError::InvalidStructure("status_list.lst missing".into()))?
            .to_string();
        let aggregation_uri = value
            .get("aggregation_uri")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok(Self {
            bits,
            lst_b64url,
            aggregation_uri,
        })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core status_list::tests -- --nocapture`
Expected: PASS (all tests so far).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/status_list/mod.rs
git commit -m "feat(status-list): implement StatusList build/decode/JSON round trip"
```

---

### Task 5: `x5c_entry_to_pem` trust helper + Status List Token builder

**Files:**
- Modify: `crates/foundry-core/src/trust/mod.rs`
- Modify: `crates/foundry-core/src/status_list/mod.rs`

**Interfaces:**
- Consumes: `foundry_core::crypto::Signer`, `StatusList` (Task 4).
- Produces:
  ```rust
  // trust/mod.rs
  pub fn x5c_entry_to_pem(standard_b64: &str) -> Result<Vec<u8>, TrustError>;

  // status_list/mod.rs
  pub struct StatusListTokenClaims { pub sub: String, pub iat: i64, pub exp: Option<i64>, pub ttl: Option<i64> }
  pub fn build_status_list_token(claims: StatusListTokenClaims, status_list: &StatusList, signer: &dyn Signer, x5c: Option<Vec<String>>) -> Result<String, FormatError>;
  ```

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `crates/foundry-core/src/trust/mod.rs` (this crate already imports `crate::pki::{issue_leaf, new_ca}` in its test module — reuse the existing `use` already present there):

```rust
    #[test]
    fn x5c_entry_to_pem_round_trips_a_cert() {
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let der_b64 = &build_x5c(&[ca.cert_pem.clone().into_bytes()]).unwrap()[0];
        let pem = x5c_entry_to_pem(der_b64).unwrap();
        let reparsed = parse_cert_pem(&pem).unwrap();
        assert!(is_self_signed(&reparsed));
    }
```

Append to the `tests` module in `crates/foundry-core/src/status_list/mod.rs`:

```rust
    #[test]
    fn build_status_list_token_produces_compact_jws_with_correct_typ() {
        use crate::crypto::{FileSigner, SignatureAlgorithm};
        use crate::pki::{issue_leaf, new_ca};

        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        let signer = FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let x5c = crate::trust::build_x5c(&[leaf.cert_pem.into_bytes()]).unwrap();

        let list = StatusList::build(&[0, 1, 2, 0], 2, None).unwrap();
        let claims = StatusListTokenClaims {
            sub: "https://example.com/statuslists/1".to_string(),
            iat: 1_700_000_000,
            exp: Some(1_800_000_000),
            ttl: None,
        };
        let token = build_status_list_token(claims, &list, &signer, Some(x5c)).unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value = serde_json::from_slice(
            &B64URL.decode(parts[0]).unwrap(),
        )
        .unwrap();
        assert_eq!(header["typ"], "statuslist+jwt");
        assert_eq!(header["alg"], "ES256");
        assert!(header["x5c"].is_array());
        let payload: Value = serde_json::from_slice(
            &B64URL.decode(parts[1]).unwrap(),
        )
        .unwrap();
        assert_eq!(payload["sub"], "https://example.com/statuslists/1");
        assert_eq!(payload["status_list"]["bits"], 2);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core -- x5c_entry_to_pem build_status_list_token`
Expected: FAIL — `x5c_entry_to_pem` and `build_status_list_token`/`StatusListTokenClaims` not defined.

- [ ] **Step 3: Implement the helper and the builder**

Add to `crates/foundry-core/src/trust/mod.rs`, after `build_x5c` and before the `TrustStore` struct:

```rust
/// Rebuild a PEM certificate from a single `x5c` entry (base64-STANDARD DER),
/// as found in a JOSE header per RFC 7515 §4.1.6.
pub fn x5c_entry_to_pem(standard_b64: &str) -> Result<Vec<u8>, TrustError> {
    let der = B64
        .decode(standard_b64)
        .map_err(|e| TrustError::Parse(format!("x5c base64 decode: {e}")))?;
    let re_b64 = B64.encode(&der);
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
```

Update the `use` block at the top of `crates/foundry-core/src/status_list/mod.rs` to add `Signer`:

```rust
use crate::crypto::Signer;
```

Insert after the `StatusList` impl block and before `#[cfg(test)]`:

```rust
/// Claims for a Status List Token, excluding the `status_list` body itself
/// (draft-ietf-oauth-status-list-14 §5.1).
pub struct StatusListTokenClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: Option<i64>,
    pub ttl: Option<i64>,
}

fn b64url_json(value: &Value) -> Result<String, FormatError> {
    let bytes = serde_json::to_vec(value).map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(B64URL.encode(bytes))
}

/// Build and sign a Status List Token (compact JWS, `typ: statuslist+jwt`)
/// per draft-ietf-oauth-status-list-14 §5.1.
pub fn build_status_list_token(
    claims: StatusListTokenClaims,
    status_list: &StatusList,
    signer: &dyn Signer,
    x5c: Option<Vec<String>>,
) -> Result<String, FormatError> {
    let mut header = serde_json::Map::new();
    header.insert(
        "alg".into(),
        Value::String(signer.algorithm().as_str().to_string()),
    );
    header.insert("typ".into(), Value::String("statuslist+jwt".into()));
    if let Some(chain) = x5c {
        header.insert(
            "x5c".into(),
            Value::Array(chain.into_iter().map(Value::String).collect()),
        );
    }

    let mut payload = serde_json::Map::new();
    payload.insert("sub".into(), Value::String(claims.sub));
    payload.insert("iat".into(), Value::Number(claims.iat.into()));
    if let Some(exp) = claims.exp {
        payload.insert("exp".into(), Value::Number(exp.into()));
    }
    if let Some(ttl) = claims.ttl {
        payload.insert("ttl".into(), Value::Number(ttl.into()));
    }
    payload.insert("status_list".into(), status_list.to_json());

    let header_b64 = b64url_json(&Value::Object(header))?;
    let payload_b64 = b64url_json(&Value::Object(payload))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core -- x5c_entry_to_pem build_status_list_token`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/trust/mod.rs crates/foundry-core/src/status_list/mod.rs
git commit -m "feat(status-list): add x5c_entry_to_pem helper and Status List Token builder"
```

---

### Task 6: Status List Token verifier + negative tests

**Files:**
- Modify: `crates/foundry-core/src/status_list/mod.rs`

**Interfaces:**
- Consumes: `x5c_entry_to_pem`, `validate_chain`, `cert_ec_public_coords`, `TrustStore` (`foundry_core::trust`); `StatusListTokenClaims`, `build_status_list_token`, `StatusList` (Task 5).
- Produces:
  ```rust
  pub struct VerifiedStatusList { pub bits: u8, pub raw: Vec<u8>, pub aggregation_uri: Option<String> }
  impl VerifiedStatusList { pub fn status_at(&self, idx: u64) -> Result<StatusValue, FormatError>; }
  pub fn verify_status_list_token(token: &str, trust_store: &TrustStore, expected_sub: &str, now_unix: u64) -> Result<VerifiedStatusList, FormatError>;
  ```

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `crates/foundry-core/src/status_list/mod.rs`:

```rust
    fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use crate::pki::{issue_leaf, new_ca};
        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        (
            ca.cert_pem.into_bytes(),
            leaf.cert_pem.into_bytes(),
            leaf.key_pem.into_bytes(),
        )
    }

    fn build_test_token(
        leaf_key: &[u8],
        leaf_cert: &[u8],
        sub: &str,
        iat: i64,
        exp: Option<i64>,
    ) -> String {
        use crate::crypto::{FileSigner, SignatureAlgorithm};
        let signer = FileSigner::from_pem(leaf_key, SignatureAlgorithm::Es256).unwrap();
        let x5c = crate::trust::build_x5c(&[leaf_cert.to_vec()]).unwrap();
        let list = StatusList::build(&[0, 1, 2, 0], 2, None).unwrap();
        let claims = StatusListTokenClaims {
            sub: sub.to_string(),
            iat,
            exp,
            ttl: None,
        };
        build_status_list_token(claims, &list, &signer, Some(x5c)).unwrap()
    }

    #[test]
    fn verify_round_trips_and_status_at_matches_original() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let trust_store = crate::trust::TrustStore::from_pems(&[root]).unwrap();
        let now = 1_750_000_000u64;
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 100,
            Some(now as i64 + 3600),
        );

        let verified =
            verify_status_list_token(&token, &trust_store, "https://example.com/statuslists/1", now)
                .unwrap();
        assert_eq!(verified.status_at(0).unwrap(), StatusValue::Valid);
        assert_eq!(verified.status_at(1).unwrap(), StatusValue::Invalid);
        assert_eq!(verified.status_at(2).unwrap(), StatusValue::Suspended);
        assert_eq!(verified.status_at(3).unwrap(), StatusValue::Valid);
    }

    #[test]
    fn verify_rejects_expired_token() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let trust_store = crate::trust::TrustStore::from_pems(&[root]).unwrap();
        let now = 1_750_000_000u64;
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 7200,
            Some(now as i64 - 3600), // expired 3600s before `now`
        );

        let err =
            verify_status_list_token(&token, &trust_store, "https://example.com/statuslists/1", now)
                .unwrap_err();
        assert!(matches!(err, FormatError::Expired));
    }

    #[test]
    fn verify_rejects_subject_mismatch() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let trust_store = crate::trust::TrustStore::from_pems(&[root]).unwrap();
        let now = 1_750_000_000u64;
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 100,
            Some(now as i64 + 3600),
        );

        let err = verify_status_list_token(
            &token,
            &trust_store,
            "https://example.com/statuslists/WRONG",
            now,
        )
        .unwrap_err();
        assert!(matches!(err, FormatError::StatusSubjectMismatch { .. }));
    }

    #[test]
    fn verify_rejects_untrusted_anchor() {
        let (_root, leaf_cert, leaf_key) = test_pki();
        use crate::pki::new_ca;
        let other = new_ca("Some Other CA", 3650).unwrap();
        let trust_store = crate::trust::TrustStore::from_pems(&[other.cert_pem.into_bytes()]).unwrap();
        let now = 1_750_000_000u64;
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 100,
            Some(now as i64 + 3600),
        );

        let err =
            verify_status_list_token(&token, &trust_store, "https://example.com/statuslists/1", now)
                .unwrap_err();
        assert!(matches!(err, FormatError::SignatureVerification(_)));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let trust_store = crate::trust::TrustStore::from_pems(&[root]).unwrap();
        let now = 1_750_000_000u64;
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 100,
            Some(now as i64 + 3600),
        );
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });

        let err = verify_status_list_token(
            &tampered,
            &trust_store,
            "https://example.com/statuslists/1",
            now,
        )
        .unwrap_err();
        assert!(matches!(err, FormatError::SignatureVerification(_)));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core status_list::tests::verify -- --nocapture`
Expected: FAIL — `verify_status_list_token`/`VerifiedStatusList` not defined.

- [ ] **Step 3: Implement the verifier**

Update the `use` block at the top of `crates/foundry-core/src/status_list/mod.rs`:

```rust
use crate::trust::{cert_ec_public_coords, parse_cert_pem, validate_chain, TrustStore};
use josekit::jwk::Jwk;
```

Insert after `build_status_list_token` and before `#[cfg(test)]`:

```rust
fn curve_for_alg(alg: &str) -> Result<&'static str, FormatError> {
    match alg {
        "ES256" => Ok("P-256"),
        "ES384" => Ok("P-384"),
        "ES512" => Ok("P-521"),
        other => Err(FormatError::Unsupported(other.to_string())),
    }
}

fn jws_alg_for_curve(
    curve: &str,
) -> Result<&'static josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm, FormatError> {
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
    let jwk_value =
        json!({ "kty": "EC", "crv": curve, "x": B64URL.encode(x), "y": B64URL.encode(y) });
    let obj = jwk_value
        .as_object()
        .cloned()
        .ok_or_else(|| FormatError::SignatureVerification("jwk is not an object".into()))?;
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

/// A verified, decoded Status List: the raw (unpacked-ready) byte array plus
/// its `bits` width, ready for repeated `status_at` lookups.
pub struct VerifiedStatusList {
    pub bits: u8,
    pub raw: Vec<u8>,
    pub aggregation_uri: Option<String>,
}

impl VerifiedStatusList {
    pub fn status_at(&self, idx: u64) -> Result<StatusValue, FormatError> {
        let v = unpack_status(&self.raw, self.bits, idx)?;
        Ok(StatusValue::from_u8(v))
    }
}

/// Verify a Status List Token (compact JWS) against `trust_store`, checking
/// `sub`, `exp`, and the issuer's x5c chain, and return the decoded list.
pub fn verify_status_list_token(
    token: &str,
    trust_store: &TrustStore,
    expected_sub: &str,
    now_unix: u64,
) -> Result<VerifiedStatusList, FormatError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(FormatError::InvalidStructure(
            "status list token is not a compact JWS".into(),
        ));
    }
    let header_json: Value = serde_json::from_slice(
        &B64URL
            .decode(parts[0])
            .map_err(|e| FormatError::Deserialization(format!("header b64: {e}")))?,
    )
    .map_err(|e| FormatError::Deserialization(format!("header json: {e}")))?;
    let payload_json: Value = serde_json::from_slice(
        &B64URL
            .decode(parts[1])
            .map_err(|e| FormatError::Deserialization(format!("payload b64: {e}")))?,
    )
    .map_err(|e| FormatError::Deserialization(format!("payload json: {e}")))?;

    if header_json.get("typ").and_then(|v| v.as_str()) != Some("statuslist+jwt") {
        return Err(FormatError::InvalidStructure(
            "status list token typ must be statuslist+jwt".into(),
        ));
    }

    if payload_json.get("sub").and_then(|v| v.as_str()) != Some(expected_sub) {
        return Err(FormatError::StatusSubjectMismatch {
            expected: expected_sub.to_string(),
        });
    }
    if let Some(exp) = payload_json.get("exp").and_then(|v| v.as_i64()) {
        if now_unix > exp as u64 {
            return Err(FormatError::Expired);
        }
    }

    let x5c_array = header_json
        .get("x5c")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            FormatError::SignatureVerification("status list token x5c missing".into())
        })?;
    if x5c_array.is_empty() {
        return Err(FormatError::SignatureVerification(
            "empty x5c header".into(),
        ));
    }
    let mut chain_pems: Vec<Vec<u8>> = Vec::with_capacity(x5c_array.len());
    for val in x5c_array {
        let s = val
            .as_str()
            .ok_or_else(|| FormatError::SignatureVerification("non-string x5c element".into()))?;
        chain_pems.push(
            crate::trust::x5c_entry_to_pem(s)
                .map_err(|e| FormatError::SignatureVerification(e.to_string()))?,
        );
    }
    let leaf_pem = &chain_pems[0];
    let intermediates: Vec<Vec<u8>> = chain_pems[1..].to_vec();
    validate_chain(leaf_pem, &intermediates, trust_store, now_unix).map_err(|e| {
        FormatError::SignatureVerification(format!("status list cert validation: {e}"))
    })?;

    let leaf_cert =
        parse_cert_pem(leaf_pem).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let (lx, ly) = cert_ec_public_coords(&leaf_cert)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let alg_str = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::SignatureVerification("alg missing".into()))?;
    let curve = curve_for_alg(alg_str)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = B64URL
        .decode(parts[2])
        .map_err(|e| FormatError::SignatureVerification(format!("signature b64: {e}")))?;
    verify_jws_with_coords(curve, &lx, &ly, signing_input.as_bytes(), &sig)?;

    let status_list_val = payload_json
        .get("status_list")
        .ok_or_else(|| FormatError::InvalidStructure("status_list claim missing".into()))?;
    let status_list = StatusList::from_json(status_list_val)?;
    let raw = status_list.decode_bytes()?;

    Ok(VerifiedStatusList {
        bits: status_list.bits,
        raw,
        aggregation_uri: status_list.aggregation_uri,
    })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core status_list -- --nocapture`
Expected: PASS (all `status_list` tests, including Tasks 1–5's).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/status_list/mod.rs
git commit -m "feat(status-list): implement Status List Token verifier with negative tests"
```

---

### Task 7: Workspace gates

**Files:** none (verification only).

**Interfaces:** none — this task runs the full quality gate across `foundry-core` and the workspace.

- [ ] **Step 1: Format check**

Run: `cargo fmt -p foundry-core -- --check`
Expected: no output (clean).

If it reports diffs, run `cargo fmt -p foundry-core` and re-run the check.

- [ ] **Step 2: Clippy**

Run: `cargo clippy -p foundry-core --all-targets -- -D warnings`
Expected: `Finished` with zero warnings.

- [ ] **Step 3: Full workspace build and test**

Run: `cargo build --workspace && cargo test --workspace`
Expected: zero errors; every test suite green, including the new `status_list::tests` module (16 tests: 2 from Task 1, 8 from Task 2, 3 from Task 3, 4 from Task 4, 2 builder tests from Task 5 — 1 in `trust::tests`, 1 in `status_list::tests` — and 5 verifier tests from Task 6).

- [ ] **Step 4: Commit (only if fmt/clippy required fixes)**

If Step 1 or Step 2 required any code changes to pass, commit them:

```bash
git add crates/foundry-core/src/status_list/mod.rs crates/foundry-core/src/trust/mod.rs
git commit -m "style(status-list): apply rustfmt/clippy fixes"
```

If no changes were needed, skip this step — the plan is complete.