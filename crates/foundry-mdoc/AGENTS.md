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
| `builder.rs` | Issuer-side `build_mdoc()` (tag-24 `IssuerSignedItem`s, SHA-256 digests over the full tagged encoding, tag-24 MSO payload, COSE_Sign1 IssuerAuth) plus `build_device_response()` — the **wallet** side, used only by tests so they can produce the shape a real wallet sends. |
| `verifier.rs` | `DeviceResponse` parsing and verification, split into four entry points so the two halves are independently callable: `decode_device_response` → `parse_device_response` → `verify_issuer_signed` (chain, IssuerAuth signature, MSO validity, element digests, holder key) → `verify_device_auth` (DeviceSignature over `DeviceAuthenticationBytes`). `verify_mdoc` orchestrates all four. |
| `types.rs` | CBOR-serializable types (`MobileSecurityObject`, `DeviceKeyInfo`, `ValidityInfo`, `IssuerSignedItem`), the `SessionTranscript` builders (`session_transcript_value` / `build_session_transcript`), the shared tag-24 helpers (`tag24_encode` / `tag24_unwrap`), and `device_authentication_bytes` — kept here, `pub(crate)`, so builder and verifier cannot disagree about what was signed. |
| `error.rs` | Re-exports `FormatError` from `foundry-core`. |
| `tests/mdoc_tests.rs` | Integration tests: expiry rejection, untrusted anchor. |
| `tests/real_presentation.rs` | **The only test that checks foundry against bytes it did not produce** — a captured real `DeviceResponse`. See `tests/fixtures/README.md` for what it deliberately does not cover. |

---

## Key Public Types & Entry Points

- **`FormatError`** (re-exported from `foundry-core::error`) — all verification errors.
- **Builder API**:
  - `MdocClaims` — doc_type, namespaces (BTreeMap<namespace_str, BTreeMap<element_id, json_value>>), device_key_jwk, signed_at, valid_until (epoch secs).
  - `build_mdoc(claims, signer, x5c?) → Vec<u8>` — the issuer-signed mdoc.
  - `build_device_response(issuer_signed_mdoc, doc_type, device_signer, session_transcript) → Vec<u8>` —
    the **holder** side. Production never calls this; it exists so tests build what
    a wallet sends rather than asserting foundry agrees with itself.
- **Verifier API** — four entry points, because the halves are separable:
  - `decode_device_response(bytes) → ciborium::Value` — the caller owns the decoded
    value, since `DeviceResponse<'_>` borrows from it.
  - `parse_device_response(&Value) → DeviceResponse<'_>` — structural validation.
  - `verify_issuer_signed(&DeviceResponse, trust_store, now_unix) → IssuerVerified`
    — chain, IssuerAuth signature, MSO validity, digests, holder key.
  - `verify_device_auth(&DeviceResponse, session_transcript, device_key_x, device_key_y) → ()`
    — takes **no trust store**, so a captured presentation whose chain cannot
    anchor here is still testable.
  - `verify_mdoc(device_response_bytes, trust_store, &ciborium::Value, now_unix) → MdocVerificationResult`
    — orchestrates the above. The transcript is a `Value`, not bytes: it is
    spliced into `DeviceAuthentication` by value.
  - `MdocVerificationResult` — `claims` (nested map by namespace), `device_key_jwk`, `issuer_x5c`, `doc_type`.
- **Types**:
  - `MobileSecurityObject`, `DeviceKeyInfo`, `ValidityInfo`, `IssuerSignedItem` (all CBOR-serializable).
  - `session_transcript_value(params) → ciborium::Value` and
    `build_session_transcript(params) → Vec<u8>` — the same structure in both
    forms. The byte form is pinned against OpenID4VP's published vectors; the
    `Value` form is what `DeviceAuthentication` element [1] is spliced from.
  - `tag24_encode(inner) → Vec<u8>` / `tag24_unwrap(&Value) → &[u8]` — shared by
    builder and verifier so the digest basis cannot drift.

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

- **Digests commit to the FULL tag-24 encoding.** Elements travel as
  `IssuerSignedItemBytes` = `#6.24(bstr .cbor IssuerSignedItem)`, and
  `valueDigests` is SHA-256 over those *tagged* bytes — not over the inner CBOR.
  This is **proven** against a captured real presentation, not inferred; see
  `tests/real_presentation.rs`. Always go through `tag24_encode` / `tag24_unwrap`
  so the two sides cannot drift.
- **A non-tag-24 element is a structural ERROR, never a silent skip.** The
  previous code called `as_bytes()` on each item, which returns `None` for a
  tagged value, and `continue`d. Every disclosed element was therefore dropped,
  the credential "verified" with zero claims, and the transaction failed as a
  DCQL policy mismatch at HTTP 200 — a wrong answer that looked like a policy
  verdict. A digest that is *absent or mismatched* still drops the element: that
  one is selective disclosure, not a fault.
- **The IssuerAuth payload is `MobileSecurityObjectBytes`**, `#6.24(bstr .cbor
  MSO)`, and the signature is computed over the **wrapped** bytes. Unwrap only to
  parse; never feed the unwrapped form to the signature check.
- **Structural checks run AFTER signature verification, deliberately.** Parsing
  unauthenticated CBOR is the thing to avoid, so `verify_issuer_signed`
  authenticates the payload bytes first. A test that tampers with the MSO must
  therefore **re-sign**, or it will fail on the signature and never reach the
  structural check it means to exercise.
- **`ValidityInfo` members are `tdate` (CBOR tag 0)** and are typed
  `ciborium::tag::Required<String, 0>`, which requires the tag when reading and
  always emits it when writing. A plain `String` field is a trap here: `ciborium`
  *skips* unexpected tags in its typed deserializers, so it would accept a
  conformant `tdate` while emitting untagged text — a silent one-way divergence.
- **The validity window is `validFrom`..`validUntil`, not `signed`..`validUntil`.**
  `signed` records when the MSO was signed and does not bound validity. The
  builder currently emits `validFrom == signed`, so no builder-produced document
  distinguishes the two rules — a test that means to pin this must rewrite
  `validFrom` and re-sign.
- **`DeviceAuthenticationBytes` is DERIVED, not proven.** The structure
  `#6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, docType,
  DeviceNameSpacesBytes])` was reconstructed from two independent implementations
  at pinned commits (multipaz, isomdl) which agree byte-for-byte; ISO/IEC 18013-5
  is a paid standard and is **not** vendored (root [AGENTS.md](../../AGENTS.md)
  §4.4). Do not restate it as proven, and do not add behaviour by inferring
  further structure from it — obtain the document. Two traps, both pinned by
  tests: the `SessionTranscript` goes in **bare** (its tag-24 form is a
  MAC-key-derivation salt, not this), and `DeviceNameSpacesBytes` is the received
  item **verbatim**.
- **`DeviceMac` is refused with a typed `Unsupported`,** not a structural error:
  foundry accepts only ES256 `deviceSignature`. A MAC would additionally need an
  ECDH agreement this crate never performs.
- **More than one document, or a non-zero `status`, is rejected.** foundry's DCQL
  layer answers exactly one credential query per presentation, so several
  documents are ambiguous about which was meant; a non-zero status is the wallet
  saying it did not answer, and verifying it anyway would invent a result it
  never sent.
- **Re-encoding decoded CBOR is assumed byte-identical to the wire.** Both the
  digest check and `DeviceAuthentication` assembly re-encode `ciborium::Value`s
  taken from the wire rather than slicing the original buffer. That holds only
  while the wallet's encoding is canonical.
  `real_presentation::re_encoding_the_capture_is_byte_identical` asserts it
  explicitly, so a non-canonical wallet fails loudly there instead of as
  inexplicably mismatching digests.
- **Device key extraction**: COSE_Key labels `iana::Ec2KeyParameter::X` and `Y`
  are read from the MSO `deviceKeyInfo`; if either is missing, verification fails
  with `InvalidStructure`. Note `cbor_value_to_bytes` (verifier) *re-encodes* a
  `Value` while `cbor_to_value_bytes` (builder) *decodes* — the near-identical
  names have caused a misreading before.
- **The `SessionTranscript` is supplied by the caller, as a `Value`.** Which
  transcript applies is an OpenID4VP question (invocation method, Response Mode,
  Origin) and this crate sees none of it. The `Value` form also avoids a
  decode/re-encode round trip when it is spliced into `DeviceAuthentication`.
- **The remaining known non-conformance is the OpenID4VCI credential envelope,
  on the issuance side.** `build_mdoc` returns a `DeviceResponse`-shaped wrapper
  where OpenID4VCI L2249 wants a bare `IssuerSigned`. The CBOR *inside* the
  envelope is conformant; the wrapper is not. Tracked as a conformance gap in
  `docs/conformance/openid4vc-conformance.md`.
- **A green mdoc test no longer proves only self-consistency — but only one test
  earns that.** Everything except `tests/real_presentation.rs` round-trips
  foundry's builder through its own verifier, which is precisely how four format
  defects survived. When changing wire format, add or extend a
  `real_presentation.rs` assertion; a passing round-trip is not evidence.
