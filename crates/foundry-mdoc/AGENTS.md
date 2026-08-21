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
  - `Bstr` — a `Vec<u8>` newtype that serializes as a CBOR byte string. Required
    wherever ISO/IEC 18013-5 says `bstr`; see Gotchas for why `Vec<u8>` is wrong.
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

**Interop** (`tests/real_presentation.rs`) — the only tests checking foundry
against bytes it did not produce. Structure, MSO parsing, element digests and
`x5chain` extraction, plus the device-signature proof: a real wallet's
`DeviceSignature` verified against the captured `SessionTranscript`, with the
other configured Origin's candidate asserted to fail. That pair is what moved
`DeviceAuthenticationBytes` from derived to proven; it is PKI-free, so the
capture's unanchored expired issuer chain does not bear on it. See
`tests/fixtures/README.md`.

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
- **`random` and every `Digest` are `bstr`, and a plain `Vec<u8>` field cannot
  say so.** serde's blanket `Vec<T>` impl serializes through `serialize_seq`, so
  `ciborium` emits major type **4** — an array of integers — where ISO/IEC
  18013-5 requires major type **2**. Both `IssuerSignedItem.random` and
  `MobileSecurityObject::value_digests`' values are therefore the `Bstr` newtype
  (`types.rs`), which calls `serialize_bytes`. Every mdoc foundry issued before
  2026-08-21 carries the array form on the wire.
  **This is the same trap as `ValidityInfo` below, and it hid for the same
  reason:** `ciborium`'s deserializer accepts *either* shape into a byte
  container, so foundry read the conformant form from real wallets while writing
  the non-conformant one and agreed with itself throughout — a round-trip test
  passes against both and proves nothing. Assert the **major type of an untyped
  `ciborium::Value`**, never a round trip. `Bstr` is deliberately strict on write
  and tolerant on read: it never emits the array form, but still accepts it, so
  already-signed legacy documents remain verifiable.
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
- **`DeviceAuthenticationBytes` is PROVEN as of 2026-08-19** — it was DERIVED
  until then, and the distinction is recorded because it bounds what may be
  inferred. The structure
  `#6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, docType,
  DeviceNameSpacesBytes])` was reconstructed from two independent implementations
  at pinned commits (multipaz, isomdl) which agree byte-for-byte, and is now
  additionally confirmed by a real wallet's Device Signature verifying against it
  (`real_presentation::the_real_device_signature_verifies_over_the_captured_session_transcript`).
  A signature check proves the whole structure at once — including both traps
  below and the empty `external_aad` — because it admits no partial credit.
  ISO/IEC 18013-5 remains a paid standard and is **not** vendored (root
  [AGENTS.md](../../AGENTS.md) §4.4), so a *proven* interface fact still licenses
  no inference beyond itself: do not extend this structure to a case the capture
  does not exercise — obtain the document. The two traps: the
  `SessionTranscript` goes in **bare** (its tag-24 form is a MAC-key-derivation
  salt, not this), and `DeviceNameSpacesBytes` is the received item **verbatim**.
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
- **`build_mdoc` returns the bare `IssuerSigned`, and `build_device_response`
  adds the `DeviceResponse` layer.** As of 2026-08-20 the builder emits exactly
  `{nameSpaces, issuerAuth}` — the structure OpenID4VCI L2249 requires the
  `credential` claim to carry once base64url-encoded — so the Credential
  Endpoint only encodes it. Wrapping a `DeviceResponse` is the holder's job and
  now happens *only* in `build_device_response`, which production never calls.
  The verifier's `version` / `documents` traversal is unchanged and remains
  correct: it parses **presentations**, which are still `DeviceResponse`s. This
  is a statement about the current code, not a standing guarantee — the previous
  version of this entry overstated conformance once already, so verify before
  repeating it. The guard is
  `build_mdoc_emits_a_bare_issuer_signed_not_a_device_response`, which reads the
  CBOR directly: a round trip cannot see this class of defect, because
  `verify_mdoc` parses a `DeviceResponse` and `build_device_response` still
  produces one, so both sides moved together and would agree either way.
- **The mdoc namespace is not always the docType.**
  `foundry_core::config::mdoc::namespace_for_doctype` resolves it: ISO mDL's
  doctype `org.iso.18013.5.1.mDL` maps to namespace `org.iso.18013.5.1`, while
  every EUDI attestation uses its doctype verbatim (EU Age Verification Annex A
  §4.1.2, "All attributes belong to namespace `eu.europa.ec.av.1`").
  `build_mdoc` itself has no opinion — it takes the namespace as a key of
  `MdocClaims::namespaces`; the caller resolves it.
- **A green mdoc test no longer proves only self-consistency — but only one test
  earns that.** Everything except `tests/real_presentation.rs` round-trips
  foundry's builder through its own verifier, which is precisely how five format
  defects survived. When changing wire format, add or extend a
  `real_presentation.rs` assertion; a passing round-trip is not evidence.
- **`x5chain` (label 33) encodes by cardinality; the verifier accepts both
  forms.** RFC 9360 §2 says a single conveyed certificate "is placed in a CBOR
  byte string" while multiple certificates use an array of byte strings, and its
  CDDL — `COSE_X509 = bstr / [ 2*certs: bstr ]` — sets the array's lower bound at
  two. The bare byte string is therefore the encoding prescribed for one
  certificate, not a lenient alternative to the array. The builder **used to**
  emit the array unconditionally, so every round-trip test passed while a real
  wallet sending the bare form was rejected with `issuerAuth missing x5c` — a
  chain that was present, reported as missing. A present-but-wrongly-typed label
  33 is now a typed error, not a silent skip.
- **Both sides now obey the cardinality rule, and the builder is the side that
  can regress silently.** `build_mdoc` emits `Bytes` for a one-certificate chain,
  an array for two or more, and no label-33 header at all for an empty chain
  (`[ 2*certs: bstr ]` admits neither a one-element nor an empty array). This
  matters in production: the issuer resolves `x5c` via
  `foundry_core::trust::build_x5c(&[pem_bytes])` with exactly one PEM blob, so
  **every** issued mdoc takes the single-certificate path. Guard it by asserting
  on emitted bytes — `builder.rs`'s
  `single_certificate_x5chain_is_a_bare_byte_string` reads label 33 out of the
  CBOR directly and deliberately does *not* call the verifier, because the
  verifier accepts both forms and would pass either way. A round trip cannot see
  this class of defect at all.
