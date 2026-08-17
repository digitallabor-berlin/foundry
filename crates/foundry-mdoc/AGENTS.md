# AGENTS.md — `crates/foundry-mdoc`

## Purpose

Builds and verifies **mdoc** (mobile document, ISO/IEC 18013-5 CBOR/COSE profile) credentials. The crate handles CBOR serialization of IssuerSignedItems with salts and digest computation, MobileSecurityObject construction, COSE_Sign1 signature wrapping for issuer and device authentication, and reconstruction of verified claims via digest matching and device binding.

**NOT owned by this crate**: OpenID4VCI/VP protocol flow (that's `foundry-issuer`/`foundry-verifier`), trust-anchor policy evaluation, or Token Status List fetching (that's `foundry-core`/`foundry-verifier`).

---

## Position in the Dependency Graph

Depends exclusively on `foundry-core` (crypto signers, PKI, trust stores, error types). Consumed by `foundry-issuer` (issuance) and `foundry-verifier` (verification).

**Critical invariant**: this crate MUST NOT depend on `foundry-sd-jwt-vc` or the protocol engines. If both format crates need shared behaviour, it belongs in `foundry-core`. — See root [AGENTS.md](../../AGENTS.md) §3.

---

## Module Map

| File | Purpose |
| --- | --- |
| `lib.rs` | Public re-exports: `builder`, `verifier`, `types`, `error` modules and `FormatError`. |
| `builder.rs` | Issuer-side: `MdocClaims` struct (doc_type, namespaces map, device_key_jwk, timestamps), `build_mdoc()` (creates IssuerSignedItems with CBOR encoding, salts, SHA-256 digests; wraps in MSO; signs as COSE_Sign1; embeds in outer CBOR). |
| `verifier.rs` | Holder verification (verification engine receives this crate's output). Parse outer CBOR; extract IssuerAuth COSE_Sign1 and x5c; validate issuer cert chain; verify IssuerAuth signature; parse MSO and check validity window; **digest verification** (SHA-256 of each IssuerSignedItem must match MSO value_digests by namespace); extract device key; **device binding** (verify DeviceAuth COSE_Sign1 over SessionTranscript). Returns `MdocVerificationResult`. |
| `types.rs` | CBOR-serializable types: `MobileSecurityObject`, `DeviceKeyInfo`, `ValidityInfo`, `IssuerSignedItem`, and `serialize_session_transcript()` helper. |
| `error.rs` | Re-exports `FormatError` from `foundry-core`. |
| `tests/mdoc_tests.rs` | Integration tests: valid presentation, expiry rejection, untrusted anchor. |

---

## Key Public Types & Entry Points

- **`FormatError`** (re-exported from `foundry-core::error`) — all verification errors.
- **Builder API**:
  - `MdocClaims` — doc_type, namespaces (BTreeMap<namespace_str, BTreeMap<element_id, json_value>>), device_key_jwk, signed_at, valid_until (epoch secs).
  - `build_mdoc(claims, signer, x5c?) → Vec<u8>` — returns CBOR-encoded mdoc bytes.
- **Verifier API**:
  - `verify_mdoc(mdoc_bytes, trust_store, client_id?, response_uri?, nonce, device_sig_bytes, now_unix) → Result<MdocVerificationResult>`.
  - `MdocVerificationResult` — `claims` (nested map by namespace), `device_key_jwk`, `issuer_x5c`, `doc_type`.
  - `serialize_session_transcript(client_id?, response_uri?, nonce) → Vec<u8>` — SessionTranscript CBOR for device binding.
- **Types**:
  - `MobileSecurityObject`, `DeviceKeyInfo`, `ValidityInfo`, `IssuerSignedItem` (all CBOR-serializable).

---

## Binding Invariants

- No panics in verification: return typed `FormatError` rather than `.unwrap()` — root [AGENTS.md](../../AGENTS.md) §4.1.
- Verification must never report success for a step it did not perform. The `mdoc_issuer_auth_and_device_signature` check result in `foundry-verifier` consumes this crate's output; every successful `verify_mdoc()` call must have validated issuer IssuerAuth signature + device DeviceAuth signature — root [AGENTS.md](../../AGENTS.md) §4.2.
- No upward/sideways dependency on engines or sd-jwt-vc — root [AGENTS.md](../../AGENTS.md) §3.

---

## Tests

**Inline** (`src/builder.rs`, `src/verifier.rs` `#[cfg(test)]` modules):

- Builder: CBOR structure, MSO/IssuerAuth encoding.
- Verifier: valid mdoc parse, signature validation, digest matching, device binding mock.

**Integration** (`tests/mdoc_tests.rs`):

- Valid presentation.
- Expiry rejection (MSO validity window).
- Untrusted issuer root rejection.

**Run**: `cargo nextest run -p foundry-mdoc` while iterating. The gate is always
the whole workspace — `cargo nextest run --workspace --no-fail-fast
--status-level fail` — per root [AGENTS.md](../../AGENTS.md) §5. Do not use
`cargo test`.

---

## Gotchas

- **Namespace/digest matching**: each IssuerSignedItem is CBOR-serialized, SHA-256 hashed, and stored in MSO value_digests keyed by (namespace, digest_id). Verification recomputes hashes of the received items and matches them to MSO; if an item's digest_id is missing from the MSO or the computed hash does not match, the item is silently dropped (not included in claims). — Mismatched namespace strings cause the item to be ignored entirely.
- **CBOR canonical encoding**: IssuerSignedItem serialization uses `ciborium::into_writer()` with no special tag wrapping. MSO and outer mdoc use BTreeMap for deterministic key ordering. **Not yet tag-24 embedded** per TODOs in types.rs.
- **Device key extraction**: COSE_Key labels `iana::Ec2KeyParameter::X` (int label) and `Y` are read from the MSO device_key_info; if either is missing, device binding fails with `InvalidStructure`.
- **SessionTranscript for device binding**: simplified format (not ISO 18013-7 hashed OID4VPHandover). Verifier passes client_id, response_uri, nonce; transcript is CBOR [null, null, [client_id?, response_uri?, nonce]] or [null, null, [nonce]].
- **mdoc presentation is NOT interoperable with real wallets, and a green mdoc
  test proves only self-consistency.** Two independent divergences, both
  deliberately unfixed and both mdoc-only (SD-JWT VC is unaffected):
  1. **Payload shape.** `verify_mdoc` takes the device signature as a *separate*
     argument and never reads `deviceSigned` from the document — it looks up only
     `issuerSigned` → `nameSpaces`/`issuerAuth`. OpenID4VP Annex B requires a
     base64url ISO 18013-5 `DeviceResponse` with
     `deviceSigned.deviceAuth.deviceSignature` nested inside each document.
     Nothing in this workspace parses a `DeviceResponse`.
  2. **Handover.** The transcript above is not the spec `OpenID4VPHandover`,
     which is `["OpenID4VPHandover", bstr(SHA-256(cbor([clientId, nonce,
     jwkThumbprint, responseUri])))]`. Different member order, no label, no hash,
     and no JWK thumbprint — which is mandatory under `direct_post.jwt`. No
     RFC 7638 thumbprint implementation exists in this workspace.
  The `vp_token` *envelope* is OpenID4VP-conformant (see
  `crates/foundry-verifier/AGENTS.md`); the mdoc *payload* inside it is not.
  Fixing this needs a captured real mdoc presentation or an official test vector
  as a fixture — writing both sides from one reading of the spec is what let
  these diverge unnoticed in the first place.
