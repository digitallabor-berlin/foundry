# mdoc `DeviceResponse` Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `foundry-mdoc` verify a conformant ISO 18013-5 `DeviceResponse` from a real wallet, and make `foundry-verifier` accept one as the `vp_token` payload.

**Architecture:** Four blocking format defects are fixed one per task, each flipping builder and verifier together inside `foundry-mdoc` so the crate round-trips green at every step. Two shared tag-24 helpers land first so builder and verifier can never disagree. The captured real presentation is then used to prove the `IssuerSigned` half before the `DeviceAuth` half is rewritten on top. `foundry-verifier`'s envelope changes last, followed by cross-crate test migration and documentation.

**Tech Stack:** Rust, `ciborium` (CBOR), `coset` (COSE), `sha2`, `time`, `openssl` (via `foundry-core`'s `TrustStore`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-19-mdoc-deviceresponse-verification-design.md`

## Global Constraints

- **Test runner is `cargo nextest run`. Never `cargo test`.** (root `AGENTS.md` §5)
- **The gate, run before marking any task complete** (root `AGENTS.md` §5.1):

  ```bash
  cargo fmt
  cargo nextest run --workspace --no-fail-fast --status-level fail
  cargo clippy --workspace --all-targets -- -D warnings
  ```

  Report the `Summary [...] N tests run: N passed` line as evidence.
- **No new dependencies**, not even `[dev-dependencies]` (spec §3 decision 3, root `AGENTS.md` §3).
- **No `.unwrap()`, `.expect()`, `panic!()`, `unreachable!()` in non-test code.** Return typed `FormatError` / `VerificationError`. (root `AGENTS.md` §4.1)
- **Be strict, not liberal.** Never accept both the old and new CBOR shapes. (spec §3 decision 2)
- **Every `#[tracing::instrument]` carries `skip_all`.** (root `AGENTS.md` §4.5)
- **Cite the governing source in code comments** — `OpenID4VP 1.0 L<line>` for spec-derived behaviour, `spec §2.1` / `spec §2.3` for ISO facts derived or proven in the design doc. ISO 18013-5 is not vendored; do not cite it as if it were in-tree.
- Digest facts are **proven** (spec §2.3); `DeviceAuthentication` is **derived** from two implementations (spec §2.1). Do not upgrade derived to proven in comments.

---

### Task 1: Shared tag-24 helpers and the transcript as a `Value`

Purely additive. Nothing changes behaviour; later tasks depend on these.

**Files:**

- Modify: `crates/foundry-mdoc/src/types.rs`
- Test: `crates/foundry-mdoc/src/types.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: nothing.
- Produces: `pub fn tag24_encode(inner_cbor: &[u8]) -> Result<Vec<u8>, String>`, `pub fn tag24_unwrap(value: &ciborium::Value) -> Result<&[u8], String>`, `pub fn session_transcript_value(params: &SessionTranscriptParams) -> Result<ciborium::Value, String>`.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `crates/foundry-mdoc/src/types.rs`:

```rust
    #[test]
    fn tag24_round_trips_and_matches_the_captured_wire_bytes() {
        // An empty CBOR map (`a0`) wrapped as #6.24(bstr) is `d81841a0` — the
        // exact bytes a real wallet sends for an empty `deviceSigned.nameSpaces`
        // (spec §2.3).
        let inner = hex::decode("a0").expect("valid hex");
        let tagged = tag24_encode(&inner).expect("encodes");
        assert_eq!(hex::encode(&tagged), "d81841a0");

        let value: ciborium::Value =
            ciborium::from_reader(tagged.as_slice()).expect("decodes");
        assert_eq!(tag24_unwrap(&value).expect("unwraps"), inner.as_slice());
    }

    #[test]
    fn tag24_unwrap_rejects_untagged_and_wrongly_tagged_values() {
        // Silence here is what made spec defect 4 invisible: an untagged item
        // must be an error, never a skip.
        let bare = ciborium::Value::Bytes(vec![0xa0]);
        assert!(tag24_unwrap(&bare).is_err(), "a bare bstr is not tag-24");

        let wrong_tag =
            ciborium::Value::Tag(0, Box::new(ciborium::Value::Bytes(vec![0xa0])));
        assert!(tag24_unwrap(&wrong_tag).is_err(), "tag 0 is not tag 24");

        let tag24_over_text =
            ciborium::Value::Tag(24, Box::new(ciborium::Value::Text("x".into())));
        assert!(
            tag24_unwrap(&tag24_over_text).is_err(),
            "tag 24 must wrap a byte string"
        );
    }

    #[test]
    fn session_transcript_value_encodes_to_the_byte_form() {
        // The `Value` form and the byte form must never diverge: the byte form is
        // pinned against OpenID4VP's published vectors, and the `Value` form is
        // what DeviceAuthentication element [1] is spliced from.
        let params = SessionTranscriptParams::DcApi {
            origin: "https://verifier.example.com".to_string(),
            nonce: SPEC_NONCE.to_string(),
            jwk_thumbprint: Some(thumbprint_fixture()),
        };
        let as_value = session_transcript_value(&params).expect("value");
        let mut encoded = Vec::new();
        ciborium::into_writer(&as_value, &mut encoded).expect("encodes");
        assert_eq!(
            encoded,
            build_session_transcript(&params).expect("bytes"),
            "session_transcript_value and build_session_transcript must agree"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-mdoc tag24`
Expected: compile error — `cannot find function tag24_encode in this scope`.

- [ ] **Step 3: Implement the helpers**

Add to `crates/foundry-mdoc/src/types.rs`, above the `tests` module:

```rust
/// A human-readable CBOR type name, for error messages only.
fn cbor_type_name(value: &ciborium::Value) -> &'static str {
    match value {
        ciborium::Value::Integer(_) => "integer",
        ciborium::Value::Bytes(_) => "byte string",
        ciborium::Value::Float(_) => "float",
        ciborium::Value::Text(_) => "text string",
        ciborium::Value::Bool(_) => "boolean",
        ciborium::Value::Null => "null",
        ciborium::Value::Tag(..) => "tag",
        ciborium::Value::Array(_) => "array",
        ciborium::Value::Map(_) => "map",
        _ => "unknown",
    }
}

/// Wrap pre-encoded CBOR as `#6.24(bstr .cbor …)` and return the **full tagged
/// encoding**.
///
/// That full encoding — not the inner CBOR — is what ISO/IEC 18013-5 digests in
/// `valueDigests` and signs in `DeviceAuthenticationBytes`. Proven against a real
/// wallet's presentation; see the design doc §2.3.
pub fn tag24_encode(inner_cbor: &[u8]) -> Result<Vec<u8>, String> {
    encode_cbor(&ciborium::Value::Tag(
        24,
        Box::new(ciborium::Value::Bytes(inner_cbor.to_vec())),
    ))
}

/// Unwrap `#6.24(bstr …)` to its inner CBOR bytes.
///
/// Every non-tag-24 shape is an error rather than a skip. Returning `None` for an
/// untagged value is precisely how foundry silently dropped every disclosed
/// element and then reported a DCQL mismatch instead (design doc §1.6).
pub fn tag24_unwrap(value: &ciborium::Value) -> Result<&[u8], String> {
    match value {
        ciborium::Value::Tag(24, inner) => match inner.as_ref() {
            ciborium::Value::Bytes(b) => Ok(b.as_slice()),
            other => Err(format!(
                "CBOR tag 24 must wrap a byte string, got {}",
                cbor_type_name(other)
            )),
        },
        ciborium::Value::Tag(other, _) => {
            Err(format!("expected CBOR tag 24, got tag {other}"))
        }
        other => Err(format!(
            "expected CBOR tag 24 embedded CBOR, got {}",
            cbor_type_name(other)
        )),
    }
}
```

Then split the existing `build_session_transcript` into a `Value` producer and a
byte wrapper. Replace the whole existing function body with:

```rust
pub fn session_transcript_value(
    params: &SessionTranscriptParams,
) -> Result<ciborium::Value, String> {
    let (identifier, info) = handover_info(params);
    let info_bytes = encode_cbor(&info)?;

    let handover = ciborium::Value::Array(vec![
        ciborium::Value::Text(identifier.to_string()),
        ciborium::Value::Bytes(Sha256::digest(&info_bytes).to_vec()),
    ]);

    // SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ],
    // the first two pinned to null by OpenID4VP (L2831-L2832, L2961-L2962).
    Ok(ciborium::Value::Array(vec![
        ciborium::Value::Null,
        ciborium::Value::Null,
        handover,
    ]))
}

/// The encoded form of [`session_transcript_value`].
///
/// Both forms exist because they serve different consumers: this one is pinned
/// against OpenID4VP's published hex vectors, while `DeviceAuthentication`
/// element [1] needs the `Value` so the transcript can be spliced **by value**
/// with no decode/re-encode round trip (design doc §2.1).
pub fn build_session_transcript(params: &SessionTranscriptParams) -> Result<Vec<u8>, String> {
    encode_cbor(&session_transcript_value(params)?)
}
```

Keep the existing doc comment on `build_session_transcript` by moving it onto
`session_transcript_value`, since that is now where the structure is built.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-mdoc`
Expected: PASS, including the pre-existing `redirect_session_transcript_matches_openid4vp_vector` and `dc_api_session_transcript_matches_openid4vp_vector`.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-mdoc/src/types.rs
git commit -m "feat(mdoc): tag-24 helpers and SessionTranscript as a CBOR Value

tag24_encode/tag24_unwrap are shared by builder and verifier so the two cannot
disagree about the digest basis. tag24_unwrap errors on every non-tag-24 shape
rather than returning None -- silence there is what let foundry drop every
disclosed element and report a DCQL mismatch instead.

session_transcript_value exposes the transcript pre-encoding so
DeviceAuthentication element [1] can splice it by value; the byte-emitting
form stays for the published-vector tests."
```

---

### Task 2: Defect 4 — tag-24 `IssuerSignedItem`s, digested over the full encoding

Builder and verifier flip together so `foundry-mdoc` stays green.

**Files:**

- Modify: `crates/foundry-mdoc/src/builder.rs`
- Modify: `crates/foundry-mdoc/src/types.rs` (`IssuerSignedItem` doc comment)
- Modify: `crates/foundry-mdoc/src/verifier.rs`
- Test: `crates/foundry-mdoc/src/verifier.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: `tag24_encode`, `tag24_unwrap` from Task 1.
- Produces: no signature changes. `build_mdoc` now emits `nameSpaces` entries as `Value::Tag(24, Bytes)`; `verify_mdoc` requires them.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/foundry-mdoc/src/verifier.rs`:

```rust
    /// The digest basis, proven against a real wallet's presentation
    /// (design doc §2.3). The negative assertion matters as much as the
    /// positive: hashing the inner CBOR is exactly what foundry used to do.
    #[test]
    fn value_digests_are_computed_over_the_full_tag24_encoding() {
        let item = IssuerSignedItem {
            digest_id: 4,
            random: vec![0xAB; 16],
            element_identifier: "age_over_18".to_string(),
            element_value: ciborium::Value::Bool(true),
        };
        let mut inner = Vec::new();
        ciborium::into_writer(&item, &mut inner).expect("item encodes");
        let tagged = crate::types::tag24_encode(&inner).expect("tag24");

        let over_tagged = Sha256::digest(&tagged).to_vec();
        let over_inner = Sha256::digest(&inner).to_vec();
        assert_ne!(
            over_tagged, over_inner,
            "the two digest bases must differ, else this test proves nothing"
        );

        let (_, digest_from_builder) = build_single_item_digest(&item);
        assert_eq!(
            digest_from_builder, over_tagged,
            "the builder must digest the full tag-24 encoding"
        );
    }

    #[test]
    fn an_untagged_namespace_item_is_a_structural_error() {
        let (signer, leaf_cert, trust_store) = test_pki();
        let mut mdoc = build_valid_mdoc(&signer, &leaf_cert);
        replace_first_namespace_item_with_untagged_bytes(&mut mdoc);

        let err = verify_mdoc(
            &mdoc,
            &trust_store,
            &dc_api_transcript_value(),
            fixed_now(),
        )
        .expect_err("an untagged item must be rejected, not silently skipped");
        assert!(
            format!("{err}").contains("tag 24"),
            "error must name the tag-24 requirement, got: {err}"
        );
    }
```

Add these test helpers to the same module:

```rust
    fn build_single_item_digest(item: &IssuerSignedItem) -> (Vec<u8>, Vec<u8>) {
        let mut inner = Vec::new();
        ciborium::into_writer(item, &mut inner).expect("encodes");
        let tagged = crate::types::tag24_encode(&inner).expect("tag24");
        (tagged.clone(), Sha256::digest(&tagged).to_vec())
    }

    /// Rewrite `documents[0].issuerSigned.nameSpaces`'s first item as a bare
    /// byte string, reproducing foundry's pre-fix wire shape.
    fn replace_first_namespace_item_with_untagged_bytes(mdoc: &mut Vec<u8>) {
        let mut value: ciborium::Value =
            ciborium::from_reader(mdoc.as_slice()).expect("mdoc decodes");
        let inner_bytes = {
            let items = first_namespace_items_mut(&mut value);
            crate::types::tag24_unwrap(&items[0])
                .expect("fixture item is tag-24")
                .to_vec()
        };
        let items = first_namespace_items_mut(&mut value);
        items[0] = ciborium::Value::Bytes(inner_bytes);
        mdoc.clear();
        ciborium::into_writer(&value, mdoc).expect("re-encodes");
    }

    fn first_namespace_items_mut(value: &mut ciborium::Value) -> &mut Vec<ciborium::Value> {
        fn entry<'a>(
            map: &'a mut Vec<(ciborium::Value, ciborium::Value)>,
            key: &str,
        ) -> &'a mut ciborium::Value {
            map.iter_mut()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == key))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("fixture must contain {key}"))
        }
        let outer = value.as_map_mut().expect("outer map");
        let docs = entry(outer, "documents").as_array_mut().expect("documents");
        let doc = docs[0].as_map_mut().expect("document map");
        let issuer_signed = entry(doc, "issuerSigned").as_map_mut().expect("issuerSigned");
        let namespaces = entry(issuer_signed, "nameSpaces")
            .as_map_mut()
            .expect("nameSpaces");
        namespaces[0].1.as_array_mut().expect("items")
    }
```

The existing test module already builds an mdoc and a trust store; extract that
setup into `build_valid_mdoc(&signer, &leaf_cert) -> Vec<u8>`,
`dc_api_transcript_value() -> ciborium::Value` and `fixed_now() -> u64` helpers so
both the existing test and the new ones use them.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-mdoc`
Expected: FAIL — `the builder must digest the full tag-24 encoding`, and the untagged-item test fails because the item is currently accepted-then-skipped rather than rejected.

- [ ] **Step 3: Change the builder**

In `crates/foundry-mdoc/src/builder.rs`, inside `build_mdoc`'s per-element loop,
replace the digest-and-push block:

```rust
            let mut item_bytes = Vec::new();
            ciborium::into_writer(&item, &mut item_bytes)
                .map_err(|e| FormatError::Serialization(e.to_string()))?;

            // ISO/IEC 18013-5: elements travel as IssuerSignedItemBytes,
            // `#6.24(bstr .cbor IssuerSignedItem)`, and `valueDigests` commits to
            // that FULL tagged encoding — not the inner CBOR. Proven against a
            // real wallet's presentation; see the design doc §2.3.
            let tagged_bytes = crate::types::tag24_encode(&item_bytes)
                .map_err(FormatError::Serialization)?;

            let mut hasher = Sha256::new();
            hasher.update(&tagged_bytes);
            digests_map.insert(digest_id_counter, hasher.finalize().to_vec());

            ns_items.push(ciborium::Value::Tag(
                24,
                Box::new(ciborium::Value::Bytes(item_bytes)),
            ));
```

- [ ] **Step 4: Change the verifier**

In `crates/foundry-mdoc/src/verifier.rs`, inside `verify_mdoc`'s digest loop,
replace the `item_val.as_bytes()` block:

```rust
        for item_val in items {
            // The digest commits to the FULL tag-24 encoding (design doc §2.3),
            // so re-encode the received item rather than hashing its contents.
            let tagged_bytes = cbor_value_to_bytes(item_val)?;
            let inner = crate::types::tag24_unwrap(item_val)
                .map_err(FormatError::InvalidStructure)?;

            let mut hasher = Sha256::new();
            hasher.update(&tagged_bytes);
            let computed = hasher.finalize().to_vec();

            let item: IssuerSignedItem = ciborium::from_reader(inner)
                .map_err(|e| FormatError::Deserialization(format!("IssuerSignedItem: {e}")))?;
            if let Some(expected) = mso_digests.get(&item.digest_id)
                && expected == &computed
            {
                ns_elements.insert(
                    item.element_identifier,
                    cbor_value_to_json(&item.element_value)?,
                );
            }
        }
```

A digest that is absent or mismatched still drops the element — that is a
selective-disclosure outcome, not a structural fault. A non-tag-24 item is now an
error.

- [ ] **Step 5: Update the `IssuerSignedItem` doc comment**

In `crates/foundry-mdoc/src/types.rs`, replace the `TODO(interop)` line:

```rust
/// IssuerSignedItem (ISO/IEC 18013-5 §9.1.2.5).
///
/// Always transported as `IssuerSignedItemBytes` = `#6.24(bstr .cbor
/// IssuerSignedItem)`, and `valueDigests` commits to that **full tagged
/// encoding**. Use [`tag24_encode`] / [`tag24_unwrap`] on both sides so the two
/// cannot drift. Proven against a real presentation; see the design doc §2.3.
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-mdoc`
Expected: PASS.

- [ ] **Step 7: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Note: `foundry-verifier` and `crates/foundry` mdoc tests build their own mdocs
via `build_mdoc`, so they migrate automatically with this change.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-mdoc/src
git commit -m "fix(mdoc): tag-24 IssuerSignedItems digested over the full encoding

Elements travel as #6.24(bstr .cbor IssuerSignedItem) and valueDigests commits
to that full tagged encoding, proven against a real wallet's presentation:
sha256 over the tagged bytes reproduces the MSO's valueDigests entry, sha256
over the inner CBOR does not.

Before this, the verifier called as_bytes() on each item -- None for a tagged
value -- so every disclosed element was silently skipped, the credential
verified with zero claims, and the transaction failed as a DCQL policy
mismatch at HTTP 200. An untagged item is now a structural error."
```

---

### Task 3: Defect 3 — tag-24 `MobileSecurityObject` payload

**Files:**

- Modify: `crates/foundry-mdoc/src/builder.rs`
- Modify: `crates/foundry-mdoc/src/types.rs` (`MobileSecurityObject` doc comment)
- Modify: `crates/foundry-mdoc/src/verifier.rs`
- Test: `crates/foundry-mdoc/src/verifier.rs`

**Interfaces:**

- Consumes: `tag24_encode`, `tag24_unwrap` from Task 1.
- Produces: no signature changes. The IssuerAuth COSE_Sign1 payload is now `#6.24(bstr .cbor MSO)`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn issuer_auth_payload_is_tag24_wrapped_mso() {
        let (signer, leaf_cert, _) = test_pki();
        let mdoc = build_valid_mdoc(&signer, &leaf_cert);
        let payload = issuer_auth_payload(&mdoc);
        assert_eq!(
            &payload[..2],
            &[0xd8, 0x18],
            "IssuerAuth payload must begin with CBOR tag 24"
        );

        let wrapper: ciborium::Value =
            ciborium::from_reader(payload.as_slice()).expect("payload decodes");
        let inner = crate::types::tag24_unwrap(&wrapper).expect("tag-24");
        let mso: MobileSecurityObject =
            ciborium::from_reader(inner).expect("MSO parses from the unwrapped bytes");
        assert_eq!(mso.version, "1.0");
    }

    #[test]
    fn an_untagged_mso_payload_is_rejected() {
        let (signer, leaf_cert, trust_store) = test_pki();
        let mut mdoc = build_valid_mdoc(&signer, &leaf_cert);
        unwrap_issuer_auth_payload_in_place(&mut mdoc);

        let err = verify_mdoc(&mdoc, &trust_store, &dc_api_transcript_value(), fixed_now())
            .expect_err("a bare MSO payload must be rejected");
        assert!(
            format!("{err}").contains("tag 24"),
            "error must name the tag-24 requirement, got: {err}"
        );
    }
```

Helpers, same module:

```rust
    fn issuer_auth_payload(mdoc: &[u8]) -> Vec<u8> {
        let value: ciborium::Value = ciborium::from_reader(mdoc).expect("mdoc decodes");
        let mut ia_bytes = Vec::new();
        ciborium::into_writer(issuer_auth_value(&value), &mut ia_bytes).expect("re-encodes");
        CoseSign1::from_slice(&ia_bytes)
            .expect("COSE_Sign1")
            .payload
            .expect("payload present")
    }

    /// Replace the tag-24 IssuerAuth payload with its inner bytes, WITHOUT
    /// re-signing — this test only needs the structure to be rejected before any
    /// signature check, and rebuilding the signature would test the builder
    /// rather than the verifier.
    fn unwrap_issuer_auth_payload_in_place(mdoc: &mut Vec<u8>) {
        /* decode, locate issuerSigned.issuerAuth, rebuild the COSE_Sign1 with
           tag24_unwrap(payload) as the payload, re-encode into `mdoc` */
        unimplemented!("see Step 2 note")
    }
```

> **Implementer note for `unwrap_issuer_auth_payload_in_place`:** mirror
> `replace_first_namespace_item_with_untagged_bytes` from Task 2 — walk to
> `documents[0].issuerSigned`, take the `issuerAuth` value, re-encode it to
> bytes, `CoseSign1::from_slice`, replace `payload` with the tag-24-unwrapped
> inner bytes, `to_vec()` it back, decode that to a `ciborium::Value` and store
> it back under `issuerAuth`, then re-encode the whole document. Do not
> re-sign: the structural check must fire before signature verification, and
> asserting that ordering is part of the point.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-mdoc issuer_auth`
Expected: FAIL — payload begins with `a6` (a 6-entry map), not `d818`.

- [ ] **Step 3: Change the builder**

In `crates/foundry-mdoc/src/builder.rs`, after the MSO is encoded, wrap it before
signing. Replace:

```rust
    let mut mso_bytes = Vec::new();
    ciborium::into_writer(&mso, &mut mso_bytes)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;
```

with:

```rust
    let mut mso_inner = Vec::new();
    ciborium::into_writer(&mso, &mut mso_inner)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;

    // ISO/IEC 18013-5: the IssuerAuth COSE_Sign1 payload is
    // MobileSecurityObjectBytes = `#6.24(bstr .cbor MobileSecurityObject)`.
    // The signature is computed over these wrapped bytes, so the wrapping must
    // happen before `sig_structure_data`.
    let mso_bytes = crate::types::tag24_encode(&mso_inner)
        .map_err(FormatError::Serialization)?;
```

Everything downstream (`sig_structure_data(..., &mso_bytes)` and
`.payload(mso_bytes)`) is unchanged and now signs and carries the wrapped form.

- [ ] **Step 4: Change the verifier**

In `crates/foundry-mdoc/src/verifier.rs`, the signature check over
`sign1.payload` stays **exactly as it is** — it must verify the wrapped bytes
verbatim. Only the parse changes. Replace:

```rust
    let mso: MobileSecurityObject = ciborium::from_reader(mso_bytes.as_slice())
        .map_err(|e| FormatError::Deserialization(format!("MSO CBOR: {e}")))?;
```

with:

```rust
    // The signature above was verified over `mso_bytes` verbatim, which is
    // MobileSecurityObjectBytes = `#6.24(bstr .cbor MobileSecurityObject)`.
    // Unwrap only to parse; never feed the unwrapped form to the signature check.
    let mso_wrapper: ciborium::Value = ciborium::from_reader(mso_bytes.as_slice())
        .map_err(|e| FormatError::Deserialization(format!("issuerAuth payload CBOR: {e}")))?;
    let mso_inner =
        crate::types::tag24_unwrap(&mso_wrapper).map_err(FormatError::InvalidStructure)?;
    let mso: MobileSecurityObject = ciborium::from_reader(mso_inner)
        .map_err(|e| FormatError::Deserialization(format!("MSO CBOR: {e}")))?;
```

- [ ] **Step 5: Update the `MobileSecurityObject` doc comment**

Replace the `TODO(interop)` line in `crates/foundry-mdoc/src/types.rs`:

```rust
/// MobileSecurityObject (ISO/IEC 18013-5 §9.1.2.4).
///
/// Transported as `MobileSecurityObjectBytes` = `#6.24(bstr .cbor
/// MobileSecurityObject)` in the IssuerAuth COSE_Sign1 payload. The tag-24
/// wrapper is applied and stripped at the call sites rather than by this type,
/// because the IssuerAuth signature is computed over the **wrapped** bytes.
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-mdoc`
Expected: PASS.

- [ ] **Step 7: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-mdoc/src
git commit -m "fix(mdoc): tag-24 wrap the MobileSecurityObject payload

The IssuerAuth COSE_Sign1 payload is MobileSecurityObjectBytes,
#6.24(bstr .cbor MSO). foundry emitted a bare MSO map and parsed one, so a real
payload failed with 'invalid type: bytes, expected map'.

The signature is computed over the wrapped bytes, so the wrapper is applied
before sig_structure_data and the verifier still checks the payload verbatim --
unwrapping is only for parsing. An untagged payload is now rejected."
```

---

### Task 4: Decisions 9-10 — tag-0 `tdate` validity and `validFrom`

Not a blocker (spec §1.7); an issuance-conformance fix plus a validity-semantics
correction, in scope by decision.

**Files:**

- Modify: `crates/foundry-mdoc/src/types.rs`
- Modify: `crates/foundry-mdoc/src/builder.rs`
- Modify: `crates/foundry-mdoc/src/verifier.rs`
- Test: `crates/foundry-mdoc/src/verifier.rs`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `ValidityInfo { signed, valid_from, valid_until }`, each `ciborium::tag::Required<String, 0>`. `MdocClaims` is unchanged; `valid_from` is emitted equal to `signed_at`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn validity_values_are_cbor_tag0_tdate() {
        let (signer, leaf_cert, _) = test_pki();
        let mdoc = build_valid_mdoc(&signer, &leaf_cert);
        let payload = issuer_auth_payload(&mdoc);
        let wrapper: ciborium::Value =
            ciborium::from_reader(payload.as_slice()).expect("decodes");
        let inner = crate::types::tag24_unwrap(&wrapper).expect("tag-24");
        let raw: ciborium::Value = ciborium::from_reader(inner).expect("MSO Value");

        for member in ["signed", "validFrom", "validUntil"] {
            let v = validity_member(&raw, member);
            assert!(
                matches!(v, ciborium::Value::Tag(0, _)),
                "{member} must be CBOR tag 0 (tdate), got {v:?}"
            );
        }
    }

    #[test]
    fn validity_window_is_bounded_by_valid_from_not_signed() {
        let (signer, leaf_cert, trust_store) = test_pki();
        // valid_until is 2000; `signed_at` is 1000. A `now` of 999 is before
        // validFrom and must be rejected; the old check used `signed` for the
        // same bound, so this test would also have passed pre-change -- the
        // discriminating case is that validFrom is now *present and read*.
        let mdoc = build_valid_mdoc(&signer, &leaf_cert);
        let err = verify_mdoc(&mdoc, &trust_store, &dc_api_transcript_value(), 999)
            .expect_err("before validFrom must be rejected");
        assert!(matches!(err, FormatError::Expired), "got {err}");

        assert!(
            verify_mdoc(&mdoc, &trust_store, &dc_api_transcript_value(), 1500).is_ok(),
            "inside the window must verify"
        );
    }

    #[test]
    fn an_untagged_validity_value_is_rejected() {
        // Per spec §3 decision 2 the verifier is strict: `Required<String, 0>`
        // must refuse a plain text string, not silently accept it.
        #[derive(serde::Serialize)]
        struct LooseValidity {
            signed: String,
            #[serde(rename = "validFrom")]
            valid_from: String,
            #[serde(rename = "validUntil")]
            valid_until: String,
        }
        let loose = LooseValidity {
            signed: "1970-01-01T00:16:40Z".to_string(),
            valid_from: "1970-01-01T00:16:40Z".to_string(),
            valid_until: "1970-01-01T00:33:20Z".to_string(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&loose, &mut bytes).expect("encodes");
        let parsed: Result<crate::types::ValidityInfo, _> =
            ciborium::from_reader(bytes.as_slice());
        assert!(parsed.is_err(), "untagged validity values must be rejected");
    }
```

Helper:

```rust
    fn validity_member<'a>(mso: &'a ciborium::Value, name: &str) -> &'a ciborium::Value {
        let map = mso.as_map().expect("MSO map");
        let validity = map
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "validityInfo"))
            .map(|(_, v)| v)
            .expect("validityInfo")
            .as_map()
            .expect("validityInfo map");
        validity
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == name))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("validityInfo.{name}"))
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-mdoc validity`
Expected: FAIL — members are `Text`, not `Tag(0, _)`; `validFrom` is absent.

- [ ] **Step 3: Change the type**

In `crates/foundry-mdoc/src/types.rs`, replace `ValidityInfo`:

```rust
/// ValidityInfo (ISO/IEC 18013-5 §9.1.2.4).
///
/// All three members are `tdate` — CBOR tag 0 over an RFC 3339 text string.
/// `ciborium::tag::Required<String, 0>` requires the tag on deserialization and
/// always emits it on serialization, so builder and verifier cannot drift and an
/// untagged value is refused rather than silently accepted (design doc §3
/// decision 2).
///
/// Note `ciborium` skips unexpected tags in its typed deserializers, so a plain
/// `String` field would have *accepted* a `tdate` while emitting an untagged
/// value — a silent one-way divergence. The wrapper is what closes it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidityInfo {
    pub signed: ciborium::tag::Required<String, 0>,
    /// The start of the document's validity window. Distinct from `signed`,
    /// which records when the MSO was signed.
    #[serde(rename = "validFrom")]
    pub valid_from: ciborium::tag::Required<String, 0>,
    #[serde(rename = "validUntil")]
    pub valid_until: ciborium::tag::Required<String, 0>,
}
```

- [ ] **Step 4: Change the builder**

In `crates/foundry-mdoc/src/builder.rs`, replace the `validity_info` initialiser:

```rust
        validity_info: ValidityInfo {
            signed: ciborium::tag::Required(format_epoch_seconds(claims.signed_at)?),
            // `MdocClaims` carries no separate validity start, so the document is
            // valid from the moment it was signed. Widen `MdocClaims` if an
            // issuer ever needs to post-date a credential.
            valid_from: ciborium::tag::Required(format_epoch_seconds(claims.signed_at)?),
            valid_until: ciborium::tag::Required(format_epoch_seconds(claims.valid_until)?),
        },
```

- [ ] **Step 5: Change the verifier**

In `crates/foundry-mdoc/src/verifier.rs`, replace the validity block:

```rust
    // ISO/IEC 18013-5: the document's validity window is validFrom..validUntil.
    // `signed` records when the MSO was signed and does not bound validity.
    let from_ts = time::OffsetDateTime::parse(
        &mso.validity_info.valid_from.0,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| FormatError::Deserialization(format!("validFrom parse: {e}")))?;
    let until_ts = time::OffsetDateTime::parse(
        &mso.validity_info.valid_until.0,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| FormatError::Deserialization(format!("validUntil parse: {e}")))?;
    if now_unix < from_ts.unix_timestamp() as u64 || now_unix > until_ts.unix_timestamp() as u64 {
        return Err(FormatError::Expired);
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-mdoc`
Expected: PASS. Fix any other `ValidityInfo` construction sites the compiler
reports (expected in `crates/foundry-mdoc/src/builder.rs` tests).

- [ ] **Step 7: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-mdoc/src
git commit -m "fix(mdoc): emit and require tag-0 tdate validity, model validFrom

ISO ValidityInfo members are tdate -- CBOR tag 0 over RFC 3339 text. foundry
emitted untagged text, so issued MSOs were non-conformant on the wire. It also
parsed fine, because ciborium skips unexpected tags in typed deserializers --
a silent one-way divergence that ciborium::tag::Required<String, 0> closes in
both directions.

Also models validFrom, absent until now, and bounds the validity window with
validFrom..validUntil instead of signed..validUntil. signed records when the
MSO was signed; it does not bound validity.

Closes the last of the three TODO(interop) notes in types.rs."
```

---

### Task 5: Prove Tasks 2-4 against the real capture

The first test in this workspace that checks foundry against bytes foundry did
not produce.

**Files:**

- Create: `crates/foundry-mdoc/tests/fixtures/av_device_response.b64`
- Create: `crates/foundry-mdoc/tests/fixtures/README.md`
- Create: `crates/foundry-mdoc/tests/real_presentation.rs`

**Interfaces:**

- Consumes: `tag24_unwrap` (Task 1), the tag-24 shapes (Tasks 2-3), `ValidityInfo` (Task 4).
- Produces: nothing consumed later; a regression barrier.

- [ ] **Step 1: Add the fixture and its provenance**

Write the captured base64url `DeviceResponse` (single line, no trailing newline
issues — the test trims) to `crates/foundry-mdoc/tests/fixtures/av_device_response.b64`.
The bytes are in the design doc's source trace; ask the maintainer for
`/tmp/dr_b64.txt` if it is no longer to hand.

`crates/foundry-mdoc/tests/fixtures/README.md`:

```markdown
# mdoc test fixtures

## `av_device_response.b64`

A real ISO 18013-5 `DeviceResponse`, captured 2026-08-19 from a wallet presenting
an EU Age Verification attestation (`docType eu.europa.ec.av.1`) over the OpenID4VP
Digital Credentials API, in response to foundry's `av` named query.

Base64url, no padding — exactly as it appeared in `vp_token["av"][0]`.

**Its issuer chain does not validate here, by design.** The chain is
`[Test] mDL Reference Implementation DS` under
`[Test] mDL Reference Implementation IACA` — the OpenWallet Foundation Labs
`identity-credential` test PKI, which is not a foundry trust anchor — and the DS
certificate expired 2025-09-17. Tests using this fixture therefore assert
**structure and digests only**, never a full trust-validated verification. Do not
"fix" that by adding the anchor or relaxing expiry; see the design doc §8.

Design doc: `docs/superpowers/specs/2026-08-19-mdoc-deviceresponse-verification-design.md`
```

- [ ] **Step 2: Write the test**

`crates/foundry-mdoc/tests/real_presentation.rs`:

```rust
//! Verifies foundry's mdoc parsing against a real wallet's presentation.
//!
//! Every other mdoc test in this workspace round-trips foundry's own builder
//! through its own verifier, which proves only that the two agree with each
//! other. This file is the only one that checks foundry against bytes it did not
//! produce, and it is what four format defects survived the absence of.
//!
//! Trust validation is deliberately out of scope here — see
//! `tests/fixtures/README.md`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use foundry_mdoc::types::{MobileSecurityObject, tag24_unwrap};
use sha2::{Digest, Sha256};

const CAPTURE_B64: &str = include_str!("fixtures/av_device_response.b64");

fn capture() -> Vec<u8> {
    B64URL
        .decode(CAPTURE_B64.trim())
        .expect("fixture is base64url")
}

fn lookup<'a>(value: &'a ciborium::Value, key: &str) -> &'a ciborium::Value {
    value
        .as_map()
        .expect("map")
        .iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == key))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("missing {key}"))
}

fn document() -> ciborium::Value {
    let dr: ciborium::Value =
        ciborium::from_reader(capture().as_slice()).expect("DeviceResponse CBOR");
    lookup(&dr, "documents").as_array().expect("documents")[0].clone()
}

#[test]
fn the_capture_has_the_shape_openid4vp_requires() {
    let dr: ciborium::Value =
        ciborium::from_reader(capture().as_slice()).expect("DeviceResponse CBOR");
    assert_eq!(
        lookup(&dr, "version").as_text(),
        Some("1.0"),
        "DeviceResponse.version"
    );
    assert_eq!(
        lookup(&dr, "status").as_integer(),
        Some(0.into()),
        "DeviceResponse.status must be 0"
    );
    assert_eq!(
        lookup(&dr, "documents").as_array().expect("documents").len(),
        1,
        "one document per DeviceResponse"
    );
    assert_eq!(
        lookup(&document(), "docType").as_text(),
        Some("eu.europa.ec.av.1")
    );
}

#[test]
fn the_real_mso_parses_after_tag24_unwrapping() {
    let issuer_signed = lookup(&document(), "issuerSigned").clone();
    let issuer_auth = lookup(&issuer_signed, "issuerAuth");

    let mut ia_bytes = Vec::new();
    ciborium::into_writer(issuer_auth, &mut ia_bytes).expect("re-encode issuerAuth");
    let sign1 = <coset::CoseSign1 as coset::CborSerializable>::from_slice(&ia_bytes)
        .expect("issuerAuth is a COSE_Sign1");
    let payload = sign1.payload.expect("IssuerAuth payload");

    // Task 3's defect: this is tag-24, so a direct struct parse cannot work.
    assert_eq!(&payload[..2], &[0xd8, 0x18], "payload is tag-24");

    let wrapper: ciborium::Value =
        ciborium::from_reader(payload.as_slice()).expect("payload CBOR");
    let inner = tag24_unwrap(&wrapper).expect("tag-24 unwraps");
    let mso: MobileSecurityObject =
        ciborium::from_reader(inner).expect("real MSO parses");

    assert_eq!(mso.version, "1.0");
    assert_eq!(mso.digest_algorithm, "SHA-256");
    assert_eq!(mso.doc_type, "eu.europa.ec.av.1");
    // Task 4: tag-0 tdate values, and validFrom is present.
    assert_eq!(mso.validity_info.signed.0, "2026-08-13T00:00:00Z");
    assert_eq!(mso.validity_info.valid_from.0, "2026-08-13T00:00:00Z");
    assert_eq!(mso.validity_info.valid_until.0, "2027-08-13T00:00:00Z");
    // Six digests committed, one element disclosed — ordinary selective disclosure.
    assert_eq!(
        mso.value_digests["eu.europa.ec.av.1"].len(),
        6,
        "valueDigests commits to every element, disclosed or not"
    );
}

#[test]
fn the_real_element_digest_matches_the_full_tag24_encoding() {
    let issuer_signed = lookup(&document(), "issuerSigned").clone();
    let namespaces = lookup(&issuer_signed, "nameSpaces");
    let items = lookup(namespaces, "eu.europa.ec.av.1")
        .as_array()
        .expect("items");
    let item = &items[0];

    let mut tagged = Vec::new();
    ciborium::into_writer(item, &mut tagged).expect("re-encode item");
    let inner = tag24_unwrap(item).expect("item is tag-24");

    let issuer_auth = lookup(&issuer_signed, "issuerAuth");
    let mut ia_bytes = Vec::new();
    ciborium::into_writer(issuer_auth, &mut ia_bytes).expect("re-encode issuerAuth");
    let payload = <coset::CoseSign1 as coset::CborSerializable>::from_slice(&ia_bytes)
        .expect("COSE_Sign1")
        .payload
        .expect("payload");
    let wrapper: ciborium::Value =
        ciborium::from_reader(payload.as_slice()).expect("payload CBOR");
    let mso: MobileSecurityObject =
        ciborium::from_reader(tag24_unwrap(&wrapper).expect("tag-24")).expect("MSO");

    let item_parsed: foundry_mdoc::types::IssuerSignedItem =
        ciborium::from_reader(inner).expect("IssuerSignedItem");
    assert_eq!(item_parsed.element_identifier, "age_over_18");
    assert_eq!(item_parsed.element_value, ciborium::Value::Bool(true));

    let expected = &mso.value_digests["eu.europa.ec.av.1"][&item_parsed.digest_id];
    assert_eq!(
        Sha256::digest(&tagged).to_vec(),
        *expected,
        "valueDigests commits to the FULL tag-24 encoding"
    );
    assert_ne!(
        Sha256::digest(inner).to_vec(),
        *expected,
        "hashing the inner CBOR is what foundry used to do; it must not match"
    );
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo nextest run -p foundry-mdoc --test real_presentation`
Expected: PASS — all three. If `the_real_mso_parses_after_tag24_unwrapping` fails,
Tasks 3 or 4 are wrong; if `the_real_element_digest_matches...` fails, Task 2 is.

- [ ] **Step 4: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-mdoc/tests
git commit -m "test(mdoc): prove the format fixes against a real presentation

Adds the captured EU Age Verification DeviceResponse as a fixture and asserts
foundry parses it: tag-24 MSO unwraps, tag-0 tdate values including validFrom
parse, and the disclosed age_over_18 element's digest matches valueDigests when
computed over the full tag-24 encoding -- and does NOT match when computed over
the inner CBOR.

Every other mdoc test round-trips foundry's builder through its own verifier,
which is why four format defects went unnoticed. This is the only test that
checks foundry against bytes it did not produce.

Trust validation is deliberately excluded: the fixture's chain is the OWF
identity-credential test PKI and its DS cert expired 2025-09-17. See
tests/fixtures/README.md."
```

---

### Task 6: Defect 2 — `DeviceAuthenticationBytes`, and the verifier split

**Files:**

- Modify: `crates/foundry-mdoc/src/verifier.rs`
- Modify: `crates/foundry-mdoc/src/builder.rs`
- Modify: `crates/foundry-mdoc/AGENTS.md` (public entry points; Gotchas)
- Test: `crates/foundry-mdoc/src/verifier.rs`, `crates/foundry-mdoc/tests/mdoc_tests.rs`

**Interfaces:**

- Consumes: `tag24_encode` (Task 1), `session_transcript_value` (Task 1).
- Produces:
  - `pub struct DeviceResponse<'a>` with `pub fn doc_type(&self) -> &str`.
  - `pub fn parse_device_response(bytes: &[u8]) -> Result<DeviceResponse<'_>, FormatError>`
  - `pub fn verify_issuer_signed(resp: &DeviceResponse<'_>, trust_store: &TrustStore, now_unix: u64) -> Result<IssuerVerified, FormatError>` where `pub struct IssuerVerified { pub claims: BTreeMap<String, BTreeMap<String, JsonValue>>, pub device_key_jwk: JsonValue, pub device_key_x: Vec<u8>, pub device_key_y: Vec<u8>, pub issuer_x5c: Vec<String>, pub doc_type: String }`
  - `pub fn verify_device_auth(resp: &DeviceResponse<'_>, session_transcript: &ciborium::Value, device_key_x: &[u8], device_key_y: &[u8]) -> Result<(), FormatError>`
  - `pub fn verify_mdoc(device_response_bytes: &[u8], trust_store: &TrustStore, session_transcript: &ciborium::Value, now_unix: u64) -> Result<MdocVerificationResult, FormatError>`
  - `pub fn build_device_response(issuer_signed_mdoc: &[u8], doc_type: &str, device_signer: &dyn Signer, session_transcript: &ciborium::Value) -> Result<Vec<u8>, FormatError>`

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn device_authentication_bytes_have_the_derived_structure() {
        // Derived from two independent implementations (design doc §2.1):
        // #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, docType,
        //                   DeviceNameSpacesBytes])
        let transcript = dc_api_transcript_value();
        let ns = ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(vec![0xa0])));
        let bytes = device_authentication_bytes(&transcript, "eu.europa.ec.av.1", &ns)
            .expect("builds");

        assert_eq!(&bytes[..2], &[0xd8, 0x18], "outer tag-24");
        let wrapper: ciborium::Value =
            ciborium::from_reader(bytes.as_slice()).expect("decodes");
        let inner: ciborium::Value =
            ciborium::from_reader(crate::types::tag24_unwrap(&wrapper).expect("tag24"))
                .expect("inner array");
        let arr = inner.as_array().expect("array");
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0].as_text(), Some("DeviceAuthentication"));
        assert_eq!(&arr[1], &transcript, "element [1] is the BARE transcript");
        assert!(
            !matches!(arr[1], ciborium::Value::Tag(..)),
            "the transcript must NOT be tag-24 wrapped here (design doc §2.2 hazard 2)"
        );
        assert_eq!(arr[2].as_text(), Some("eu.europa.ec.av.1"));
        assert_eq!(&arr[3], &ns, "element [3] is the wire bytes verbatim");
    }

    #[test]
    fn a_device_signature_over_the_bare_transcript_is_rejected() {
        // The pre-fix behaviour. Without this, a regression is invisible.
        let (issuer_signer, leaf_cert, trust_store) = test_pki();
        let device_signer = test_device_signer();
        let transcript = dc_api_transcript_value();
        let mdoc = build_valid_mdoc_for_device(&issuer_signer, &leaf_cert, &device_signer);

        let dr = build_device_response_signing_bare_transcript(
            &mdoc,
            "org.iso.18013.5.1.mDL",
            &device_signer,
            &transcript,
        );
        let err = verify_mdoc(&dr, &trust_store, &transcript, fixed_now())
            .expect_err("a signature over the bare transcript must fail");
        assert!(matches!(err, FormatError::KeyBinding(_)), "got {err}");
    }

    #[test]
    fn round_trips_a_conformant_device_response() {
        let (issuer_signer, leaf_cert, trust_store) = test_pki();
        let device_signer = test_device_signer();
        let transcript = dc_api_transcript_value();
        let mdoc = build_valid_mdoc_for_device(&issuer_signer, &leaf_cert, &device_signer);

        let dr = build_device_response(
            &mdoc,
            "org.iso.18013.5.1.mDL",
            &device_signer,
            &transcript,
        )
        .expect("builds a DeviceResponse");

        let res = verify_mdoc(&dr, &trust_store, &transcript, fixed_now())
            .expect("verifies end to end");
        assert_eq!(res.doc_type, "org.iso.18013.5.1.mDL");
        assert!(!res.claims.is_empty(), "claims must be reconstructed");
    }

    #[test]
    fn device_namespaces_bytes_are_used_verbatim_not_re_encoded() {
        // Both reference implementations reuse the received tag-24 item rather
        // than rebuilding it (design doc §2.2 hazard 1).
        let (issuer_signer, leaf_cert, trust_store) = test_pki();
        let device_signer = test_device_signer();
        let transcript = dc_api_transcript_value();
        let mdoc = build_valid_mdoc_for_device(&issuer_signer, &leaf_cert, &device_signer);
        let dr = build_device_response(
            &mdoc,
            "org.iso.18013.5.1.mDL",
            &device_signer,
            &transcript,
        )
        .expect("builds");

        let parsed: ciborium::Value =
            ciborium::from_reader(dr.as_slice()).expect("decodes");
        assert_eq!(
            hex::encode(device_signed_namespaces_bytes(&parsed)),
            "d81841a0",
            "empty DeviceNameSpaces is #6.24(bstr .cbor {{}}) = d81841a0"
        );
        assert!(verify_mdoc(&dr, &trust_store, &transcript, fixed_now()).is_ok());
    }

    #[test]
    fn a_multi_document_device_response_is_rejected() {
        let (issuer_signer, leaf_cert, _) = test_pki();
        let device_signer = test_device_signer();
        let mdoc = build_valid_mdoc_for_device(&issuer_signer, &leaf_cert, &device_signer);
        let dr = build_device_response(
            &mdoc,
            "org.iso.18013.5.1.mDL",
            &device_signer,
            &dc_api_transcript_value(),
        )
        .expect("builds");

        let err = parse_device_response(&duplicate_first_document(&dr))
            .expect_err("more than one document must be rejected");
        assert!(format!("{err}").contains("one document"), "got {err}");
    }

    #[test]
    fn a_nonzero_status_is_rejected() {
        let (issuer_signer, leaf_cert, _) = test_pki();
        let device_signer = test_device_signer();
        let mdoc = build_valid_mdoc_for_device(&issuer_signer, &leaf_cert, &device_signer);
        let dr = build_device_response(
            &mdoc,
            "org.iso.18013.5.1.mDL",
            &device_signer,
            &dc_api_transcript_value(),
        )
        .expect("builds");

        let err = parse_device_response(&set_status(&dr, 10))
            .expect_err("a non-zero status must be rejected");
        assert!(format!("{err}").contains("status"), "got {err}");
    }
```

> **Implementer note on the helpers.** `test_device_signer`,
> `build_valid_mdoc_for_device`, `build_device_response_signing_bare_transcript`,
> `device_signed_namespaces_bytes`, `duplicate_first_document` and `set_status`
> are all CBOR-surgery or fixture helpers of the same kind as Task 2's
> `first_namespace_items_mut`. Write them in the test module.
> `build_device_response_signing_bare_transcript` must be a near-copy of
> `build_device_response` that passes the *encoded bare transcript* as the
> COSE_Sign1 payload instead of `DeviceAuthenticationBytes` — that is exactly the
> pre-fix behaviour, and copying rather than parameterising keeps the production
> path free of a "sign it the wrong way" switch.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-mdoc`
Expected: compile errors — `parse_device_response`, `build_device_response`, `device_authentication_bytes` not found; `verify_mdoc` arity mismatch.

- [ ] **Step 3: Add `DeviceResponse` and `parse_device_response`**

In `crates/foundry-mdoc/src/verifier.rs`:

```rust
/// A parsed, structurally validated `DeviceResponse`.
///
/// Holds borrowed views into the caller's decoded CBOR. That is deliberate: the
/// `deviceSigned.nameSpaces` item must be re-emitted **byte-for-byte** inside
/// `DeviceAuthentication` (design doc §2.2 hazard 1), so it is never decoded and
/// rebuilt.
pub struct DeviceResponse<'a> {
    doc_type: &'a str,
    issuer_signed: &'a [(ciborium::Value, ciborium::Value)],
    device_namespaces: &'a ciborium::Value,
    device_signature: &'a ciborium::Value,
}

impl<'a> DeviceResponse<'a> {
    pub fn doc_type(&self) -> &str {
        self.doc_type
    }
}

/// Parse and structurally validate a `DeviceResponse`.
///
/// OpenID4VP 1.0 L2825-L2828 carries the base64url of this CBOR structure as the
/// `vp_token` entry for `mso_mdoc`.
pub fn parse_device_response(bytes: &[u8]) -> Result<DeviceResponse<'_>, FormatError> {
    // `Box::leak` is not used and no allocation escapes: the returned views
    // borrow from `owned`, so callers hold the decoded value. See
    // `parse_device_response_owned` below for the owning entry point.
    unimplemented!("see Step 3 note")
}
```

> **Implementer note — lifetimes.** A borrowed `DeviceResponse<'a>` cannot borrow
> from a `ciborium::Value` created inside `parse_device_response`. Resolve it by
> having the caller own the decode:
>
> ```rust
> /// Decode the outer CBOR. Kept separate from `parse_device_response` so the
> /// caller owns the decoded value that `DeviceResponse<'_>` borrows from.
> pub fn decode_device_response(bytes: &[u8]) -> Result<ciborium::Value, FormatError>;
>
> pub fn parse_device_response(decoded: &ciborium::Value)
>     -> Result<DeviceResponse<'_>, FormatError>;
> ```
>
> Update the `Interfaces` contract above accordingly and use this two-call shape
> everywhere, including Task 7's call site. `verify_mdoc` does both internally, so
> its own signature is unaffected.
>
> `parse_device_response` must check, in order: the value is a map; `version` is
> present and text; `documents` is an array of **exactly one** entry (error text
> must contain `one document`); `status` is present and integer `0` (error text
> must contain `status`); the document carries `docType` (text), `issuerSigned`
> (map), and `deviceSigned.deviceAuth.deviceSignature`. If `deviceAuth` carries
> `deviceMac` instead, return `FormatError::Unsupported` naming `DeviceMac`
> (spec §3 decision 8).

- [ ] **Step 4: Split the issuer half out of `verify_mdoc`**

Move the existing body of `verify_mdoc` — x5c extraction, `validate_chain`,
IssuerAuth signature, MSO parse and validity, digest loop, device-key extraction
— into `verify_issuer_signed`, reading `issuer_signed` from the
`DeviceResponse<'_>` instead of re-walking the outer CBOR. Return
`IssuerVerified` as declared in this task's `Interfaces`.

- [ ] **Step 5: Add `device_authentication_bytes` and `verify_device_auth`**

```rust
/// `DeviceAuthenticationBytes`, the detached payload a `DeviceSignature` is
/// computed over.
///
/// ```text
/// #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, docType,
///                   DeviceNameSpacesBytes])
/// ```
///
/// Derived from two independent implementations at pinned commits, which agree
/// byte-for-byte; see the design doc §2.1. Two traps, both real:
/// `SessionTranscript` goes in **bare** — the tag-24 wrapping of the transcript
/// is a MAC-key-derivation construct and must not appear here — and
/// `DeviceNameSpacesBytes` is the received item **verbatim**, never re-encoded
/// from a decoded map.
fn device_authentication_bytes(
    session_transcript: &ciborium::Value,
    doc_type: &str,
    device_namespaces_tagged: &ciborium::Value,
) -> Result<Vec<u8>, FormatError> {
    let device_auth = ciborium::Value::Array(vec![
        ciborium::Value::Text("DeviceAuthentication".to_string()),
        session_transcript.clone(),
        ciborium::Value::Text(doc_type.to_string()),
        device_namespaces_tagged.clone(),
    ]);
    let mut inner = Vec::new();
    ciborium::into_writer(&device_auth, &mut inner)
        .map_err(|e| FormatError::Serialization(format!("DeviceAuthentication: {e}")))?;
    crate::types::tag24_encode(&inner).map_err(FormatError::Serialization)
}

/// Verify the `DeviceSignature` over `DeviceAuthenticationBytes`.
///
/// Callable without a trust store on purpose: it is the only half of mdoc
/// verification that a captured real presentation can exercise, since such a
/// capture's issuer chain will not anchor here (design doc §8).
pub fn verify_device_auth(
    resp: &DeviceResponse<'_>,
    session_transcript: &ciborium::Value,
    device_key_x: &[u8],
    device_key_y: &[u8],
) -> Result<(), FormatError> {
    let d_sig_bytes = cbor_value_to_bytes(resp.device_signature)?;
    let d_sign1 = CoseSign1::from_slice(&d_sig_bytes)
        .map_err(|e| FormatError::Deserialization(format!("deviceSignature COSE: {e}")))?;
    let d_alg = d_sign1
        .protected
        .header
        .alg
        .clone()
        .ok_or_else(|| FormatError::KeyBinding("device signature missing alg".into()))?;
    let d_curve = curve_for_alg(cose_alg_str(&d_alg)?)
        .map_err(|_| FormatError::KeyBinding("unsupported device alg".into()))?;

    let payload = device_authentication_bytes(
        session_transcript,
        resp.doc_type,
        resp.device_namespaces,
    )?;

    // COSE_Sign1 with a DETACHED payload: the wire structure carries
    // `payload: null`, but the Sig_structure still receives the payload in the
    // payload slot. `external_aad` is the empty byte string.
    let d_tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        d_sign1.protected.clone(),
        None,
        &[],
        &payload,
    );
    verify_ecdsa(d_curve, device_key_x, device_key_y, &d_tbs, &d_sign1.signature)
        .map_err(|e| FormatError::KeyBinding(format!("device signature invalid: {e}")))
}
```

- [ ] **Step 6: Rewrite `verify_mdoc` as an orchestrator**

```rust
/// Verify an mdoc presentation: structure, IssuerAuth chain and signature, MSO
/// validity, element digests, and the DeviceAuth signature.
///
/// `session_transcript` is supplied by the caller as a `ciborium::Value` rather
/// than derived here or taken as bytes. Which transcript applies is an OpenID4VP
/// question — invocation method, Response Mode, request Origin — and this crate
/// has access to none of them; the `Value` form avoids a decode/re-encode round
/// trip when it is spliced into `DeviceAuthentication`. Build it with
/// [`crate::types::session_transcript_value`].
pub fn verify_mdoc(
    device_response_bytes: &[u8],
    trust_store: &TrustStore,
    session_transcript: &ciborium::Value,
    now_unix: u64,
) -> Result<MdocVerificationResult, FormatError> {
    let decoded = decode_device_response(device_response_bytes)?;
    let resp = parse_device_response(&decoded)?;
    let issuer = verify_issuer_signed(&resp, trust_store, now_unix)?;
    verify_device_auth(
        &resp,
        session_transcript,
        &issuer.device_key_x,
        &issuer.device_key_y,
    )?;
    Ok(MdocVerificationResult {
        claims: issuer.claims,
        device_key_jwk: issuer.device_key_jwk,
        issuer_x5c: Some(issuer.issuer_x5c),
        doc_type: issuer.doc_type,
    })
}
```

- [ ] **Step 7: Add `build_device_response`**

In `crates/foundry-mdoc/src/builder.rs`:

```rust
/// Build a conformant ISO/IEC 18013-5 `DeviceResponse` around an already-issued
/// mdoc, signing `DeviceAuthenticationBytes` with the holder's key.
///
/// This is the device/holder side of the protocol. foundry is not a wallet, so
/// production never calls this — it exists so that tests can produce the shape a
/// real wallet sends, instead of asserting that foundry's verifier agrees with
/// foundry's own bespoke envelope. That circularity is what hid four format
/// defects; see the design doc §1.4.
pub fn build_device_response(
    issuer_signed_mdoc: &[u8],
    doc_type: &str,
    device_signer: &dyn Signer,
    session_transcript: &ciborium::Value,
) -> Result<Vec<u8>, FormatError> {
    // DeviceNameSpaces is an empty map when nothing device-signed is disclosed:
    // #6.24(bstr .cbor {}) = d81841a0 (design doc §2.3).
    let device_namespaces = ciborium::Value::Tag(
        24,
        Box::new(ciborium::Value::Bytes(vec![0xa0])),
    );
    /* 1. decode `issuer_signed_mdoc`, lift out documents[0].issuerSigned
       2. payload = device_authentication_bytes(session_transcript, doc_type,
                                                &device_namespaces)
       3. protected = HeaderBuilder::new().algorithm(alg_label(device_signer)).build()
       4. signature = device_signer.sign(&sig_structure_data(CoseSign1,
              protected_wrapped, None, &[], &payload))
       5. deviceSignature = CoseSign1Builder::new().protected(protected)
              .signature(signature).build()   // NO .payload() -> detached
       6. assemble {version: "1.0",
                    documents: [{docType, issuerSigned,
                                 deviceSigned: {nameSpaces, deviceAuth:
                                     {deviceSignature}}}],
                    status: 0}                                                  */
    unimplemented!("assemble per the outline above")
}
```

> **Implementer note.** `device_authentication_bytes` currently lives in
> `verifier.rs`; move it to `types.rs` and make it `pub(crate)` so both sides use
> one implementation — the whole point of the shared-helper rule (spec §10, last
> risk row). Omitting `.payload()` on the builder is what produces the detached
> `payload: null` a real wallet sends.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-mdoc`
Expected: PASS. `crates/foundry-mdoc/tests/mdoc_tests.rs` will need its
`verify_mdoc` calls migrated to the new signature.

- [ ] **Step 9: Update `crates/foundry-mdoc/AGENTS.md`**

- Module map: note `builder.rs` now also carries `build_device_response`, and
  `verifier.rs` the parse/split entry points.
- Public entry points: replace the `verify_mdoc` signature; add
  `decode_device_response`, `parse_device_response`, `verify_issuer_signed`,
  `verify_device_auth`, `build_device_response`, `tag24_encode`, `tag24_unwrap`,
  `session_transcript_value`.
- Gotchas: **delete divergence #2** — it is stale (VP-0229…VP-0246 are all
  `conforming`). Rewrite divergence #1 to record that the payload is now a
  conformant `DeviceResponse`, and that the remaining non-conformance is the
  OpenID4VCI credential envelope (design doc §7).
- Gotchas: rewrite "Namespace/digest matching" (digests are over the full tag-24
  encoding; an untagged item is now an error, not a silent drop) and "CBOR
  canonical encoding" (the `Not yet tag-24 embedded` claim is now false).

- [ ] **Step 10: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 11: Commit**

```bash
git add crates/foundry-mdoc
git commit -m "feat(mdoc): verify DeviceAuth over DeviceAuthenticationBytes

The DeviceSignature is a detached-payload COSE_Sign1 whose Sig_structure
payload is #6.24(bstr .cbor ['DeviceAuthentication', SessionTranscript,
docType, DeviceNameSpacesBytes]). foundry signed over the bare SessionTranscript
instead, so no real wallet's signature could ever verify. external_aad was
already correct and stays the empty bstr -- detachment changes the wire
structure, not the Sig_structure.

Structure derived from two independent implementations at pinned commits which
agree byte-for-byte; ISO 18013-5 is not vendored. Two traps are pinned by
tests: the transcript goes in bare (its tag-24 form is a MAC construct), and
DeviceNameSpacesBytes is reused verbatim rather than re-encoded.

verify_mdoc is now an orchestrator over decode/parse/verify_issuer_signed/
verify_device_auth. The split is not cosmetic: a captured real presentation
cannot pass issuer validation here, so the device half has to be verifiable on
its own -- and a verifier whose only entry point was 'verify everything' is why
no interop test existed.

build_device_response lets tests produce what a wallet sends instead of
asserting foundry agrees with itself."
```

---

### Task 7: Defect 1 — the `vp_token` envelope

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs`
- Modify: `crates/foundry-verifier/AGENTS.md`
- Test: `crates/foundry-verifier/src/verify.rs`

**Interfaces:**

- Consumes: everything from Task 6.
- Produces: `SelectedPresentation::MsoMdoc { device_response_b64: &'a str }`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn mso_mdoc_presentation_must_be_a_base64url_device_response_string() {
        // The bespoke {mdoc, device_signature} object is gone (spec §3 decision 4).
        let vp = serde_json::json!({
            "c1": [{ "mdoc": "AAAA", "device_signature": "BBBB" }]
        });
        let err = select_presentation(&vp, &mdoc_dcql_query())
            .expect_err("an object must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("DeviceResponse"), "must name DeviceResponse: {msg}");
        assert!(msg.contains("L2825"), "must cite the spec line: {msg}");
    }

    #[tokio::test]
    async fn a_conformant_device_response_string_is_selected() {
        let vp = serde_json::json!({ "c1": ["ZmFrZQ"] });
        let selected = select_presentation(&vp, &mdoc_dcql_query()).expect("selects");
        assert!(matches!(
            selected.as_slice(),
            [(id, SelectedPresentation::MsoMdoc { device_response_b64: "ZmFrZQ" })] if id == "c1"
        ));
    }
```

Keep the existing `test_verify_vp_response_mdoc_presentation`,
`dc_api_accepts_a_later_configured_origin` and
`dc_api_rejects_an_unconfigured_origin`, migrating them to build their
`vp_token` with `build_device_response` and `B64URL.encode`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-verifier`
Expected: FAIL — the object shape is still accepted.

- [ ] **Step 3: Collapse the enum variant and accept a string**

In `crates/foundry-verifier/src/verify.rs`, replace the `MsoMdoc` variant and its
now-obsolete warning comment:

```rust
enum SelectedPresentation<'a> {
    SdJwtVc(&'a str),
    /// OpenID4VP 1.0 L2825-L2828: the base64url-encoded ISO/IEC 18013-5
    /// `DeviceResponse` CBOR structure. One string, not a split envelope — the
    /// `{mdoc, device_signature}` pair this once carried was foundry-invented and
    /// no wallet ever sent it.
    MsoMdoc { device_response_b64: &'a str },
}
```

Then replace the `CredentialFormat::MsoMdoc` arm of `select_presentation`:

```rust
            CredentialFormat::MsoMdoc => SelectedPresentation::MsoMdoc {
                device_response_b64: presentation.as_str().ok_or_else(|| {
                    VerificationError::Failed(format!(
                        "credential query '{}' declares format mso_mdoc, so its \
                         presentation must be a base64url-encoded ISO 18013-5 \
                         DeviceResponse string (OpenID4VP 1.0 L2825-L2828), got {}",
                        cq.id(),
                        json_type_name(presentation)
                    ))
                })?,
            },
```

- [ ] **Step 4: Restructure the consumption site**

Replace the `SelectedPresentation::MsoMdoc { mdoc_b64, device_signature_b64 }`
match arm's decode block:

```rust
        SelectedPresentation::MsoMdoc {
            device_response_b64,
        } => {
            let dr_bytes = B64URL.decode(device_response_b64).map_err(|e| {
                VerificationError::Failed(format!("DeviceResponse base64url decode: {e}"))
            })?;
            let decoded = foundry_mdoc::verifier::decode_device_response(&dr_bytes)
                .map_err(|e| VerificationError::Failed(format!("DeviceResponse: {e}")))?;
            let resp = foundry_mdoc::verifier::parse_device_response(&decoded)
                .map_err(|e| VerificationError::Failed(format!("DeviceResponse: {e}")))?;
```

Keep the `jwk_thumbprint` and `candidates` blocks exactly as they are. Then
replace the candidate loop so the issuer half runs once:

```rust
            // The issuer half does not depend on the Origin, so it runs once.
            // Only the Device Signature commits to a SessionTranscript, so only
            // that check is retried per candidate Origin. Before this it re-ran
            // full chain validation, MSO validity and digest matching for every
            // configured Origin to retry one signature.
            let issuer =
                foundry_mdoc::verifier::verify_issuer_signed(&resp, ctx.trust_store, ctx.now_unix)
                    .map_err(|e| {
                        VerificationError::Failed(format!("mdoc verification failed: {e}"))
                    })?;

            let mut accepted = false;
            let mut last_err = None;
            for params in &candidates {
                let transcript = foundry_mdoc::types::session_transcript_value(params)
                    .map_err(|e| VerificationError::Failed(format!("SessionTranscript: {e}")))?;

                // §4.5: the transcript is a per-Origin candidate and its hex is
                // interop-diagnostic gold, but it commits to `tx.nonce`. Gate on
                // BOTH sensitive_enabled() AND trace — a level is not authorisation.
                if foundry_core::obs::sensitive_enabled() {
                    let mut encoded = Vec::new();
                    if ciborium::into_writer(&transcript, &mut encoded).is_ok() {
                        tracing::trace!(
                            session_transcript = %hex::encode(&encoded),
                            "SENSITIVE: candidate mdoc SessionTranscript"
                        );
                    }
                }

                match foundry_mdoc::verifier::verify_device_auth(
                    &resp,
                    &transcript,
                    &issuer.device_key_x,
                    &issuer.device_key_y,
                ) {
                    Ok(()) => {
                        accepted = true;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(VerificationError::Failed(format!(
                            "mdoc verification failed: {e}"
                        )))
                    }
                }
            }

            if !accepted {
                // `candidates` is never empty, so `last_err` is always populated
                // here. The fallback exists only so this cannot become a panic if
                // that ever stops holding.
                return Err(last_err.unwrap_or_else(|| {
                    VerificationError::Failed(
                        "mdoc verification failed: no candidate SessionTranscript".to_string(),
                    )
                }));
            }

            let mdoc_res = MdocVerificationResult {
                claims: issuer.claims,
                device_key_jwk: issuer.device_key_jwk,
                issuer_x5c: Some(issuer.issuer_x5c),
                doc_type: issuer.doc_type,
            };
```

> **Implementer note.** This folds design doc §9 step 1 — the permanent
> `SessionTranscript` trace — into the loop where the value already exists, rather
> than adding a separate diagnostic pass. `hex` is already a workspace dependency
> of `foundry-verifier`; add it to that crate's `Cargo.toml` only if the compiler
> says it is missing. Keep the rest of the arm (`cbor_value_to_json`, the
> `CheckResult` push, DCQL and status checks) unchanged.

- [ ] **Step 5: Update `crates/foundry-verifier/AGENTS.md`**

Replace the per-format payload description. The current text says
`mso_mdoc` → `{ "mdoc": <b64url CBOR>, "device_signature": <b64url COSE_Sign1> }`
and calls it "**bespoke and NOT interoperable**". It becomes:

`mso_mdoc` → a base64url-encoded ISO/IEC 18013-5 `DeviceResponse` string
(OpenID4VP L2825-L2828). Delete the non-interoperability warning and the pointer
to it in `crates/foundry-mdoc/AGENTS.md`; note instead that the remaining mdoc
non-conformance is the OpenID4VCI credential envelope on the issuance side
(design doc §7).

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-verifier
git commit -m "fix(verifier): accept a base64url DeviceResponse as the mdoc vp_token

OpenID4VP L2825-L2828 requires the mso_mdoc vp_token entry to be the base64url
of an ISO 18013-5 DeviceResponse. foundry required a foundry-invented
{mdoc, device_signature} object, so every real wallet was rejected at HTTP 400
with 'presentation must be an object, got a string'. That shape had no
production producer -- only foundry's own tests built it.

The DC API Origin loop now runs the issuer half once and retries only the
Device Signature per candidate Origin; only that check commits to a
SessionTranscript. Previously each Origin re-ran chain validation, MSO validity
and digest matching to retry one signature.

Also adds the candidate SessionTranscript hex as a trace diagnostic, gated on
BOTH obs::sensitive_enabled() and trace level per AGENTS.md 4.5 -- it commits
to tx.nonce. This is what makes a real-wallet device-signature fixture
capturable at all."
```

---

### Task 8: Migrate the cross-crate mdoc tests

**Files:**

- Modify: `crates/foundry/tests/wallet_verification.rs`
- Modify: `crates/foundry-verifier/tests/conformance_vp.rs`
- Modify: `crates/foundry/tests/AGENTS.md` if the mdoc coverage description changes

**Interfaces:**

- Consumes: `build_device_response`, `session_transcript_value` (Task 6); the string envelope (Task 7).
- Produces: nothing.

- [ ] **Step 1: Run the suite to see what breaks**

Run: `cargo nextest run --workspace --no-fail-fast --status-level fail`
Expected: FAIL in `wallet_verification::mdoc_presentation_is_accepted` and any
`conformance_vp` mdoc test, because they still build the bespoke object.

- [ ] **Step 2: Migrate `mdoc_presentation_is_accepted`**

In `crates/foundry/tests/wallet_verification.rs`, replace the `vp_token`
construction. The old form was:

```rust
        "mdoc": B64URL.encode(&mdoc_bytes),
        "device_signature": B64URL.encode(&d_sig_bytes),
```

The new form builds a real `DeviceResponse` and encodes it as one string:

```rust
    // Build what a conformant wallet sends: one base64url DeviceResponse
    // (OpenID4VP L2825-L2828), not foundry's former split envelope.
    let transcript = foundry_mdoc::types::session_transcript_value(
        &SessionTranscriptParams::DcApi {
            origin: origin.to_string(),
            nonce: nonce.clone(),
            jwk_thumbprint: Some(thumbprint),
        },
    )
    .expect("transcript");
    let device_response = foundry_mdoc::builder::build_device_response(
        &mdoc_bytes,
        doc_type,
        &device_signer,
        &transcript,
    )
    .expect("DeviceResponse");

    let vp_token = serde_json::json!({ "c1": [B64URL.encode(&device_response)] });
```

Delete the now-unused `d_sig_bytes` computation and its imports. The assertion on
`mdoc_issuer_auth_and_device_signature` stays as-is.

- [ ] **Step 3: Migrate the `conformance_vp` mdoc tests**

`crates/foundry-verifier/tests/conformance_vp.rs` covers VP-0110 (mdoc value
matching) and the GAP-VP-06 transcript literal check. Apply the same
`build_device_response` substitution wherever a `vp_token` is constructed. Where a
test asserts on `foundry_mdoc::verifier::verify_mdoc`'s output directly, update the
call to the new four-argument signature with a `session_transcript_value`.

- [ ] **Step 4: Check `crates/foundry/tests/AGENTS.md`**

If it describes the mdoc `vp_token` shape or names the split envelope, update it.
If it only lists which file covers what, no change is needed.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 6: Run the E2E suite**

Per root `AGENTS.md` §5.2, before opening a PR:

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/tests crates/foundry-verifier/tests
git commit -m "test: migrate cross-crate mdoc tests to the DeviceResponse envelope

wallet_verification and conformance_vp built the bespoke {mdoc,
device_signature} object by hand. They now build a real DeviceResponse via
build_device_response and pass one base64url string, which is what a wallet
sends -- so these tests now exercise the shape they claim to."
```

---

### Task 9: Documentation, conformance and the ISO reference stub

**Files:**

- Create: `docs/specs/iso-18013-5-device-auth.md`
- Modify: `AGENTS.md` (§4.4 governing-documents table)
- Modify: `docs/conformance/openid4vc-conformance.md`

**Interfaces:**

- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Write the reference stub**

`docs/specs/iso-18013-5-device-auth.md`, following the external-reference rule in
root `AGENTS.md` §4.4 and the precedent set by
`docs/specs/emvco-dpc-schema-framework.md`:

- **Document identified:** ISO/IEC 18013-5:2021, *Personal identification — ISO-compliant driving licence — Part 5: Mobile driving licence (mDL) application*.
- **Why no copy is in-tree:** a paid ISO standard; redistribution is forbidden. Obtain from ISO.
- **What foundry relies on**, restated rather than quoted:
  - `IssuerSignedItemBytes` = `#6.24(bstr .cbor IssuerSignedItem)`; `valueDigests` commits to the full tagged encoding. **Proven** against a captured presentation — record the digest comparison from the design doc §2.3.
  - `MobileSecurityObjectBytes` = `#6.24(bstr .cbor MobileSecurityObject)` as the IssuerAuth COSE_Sign1 payload; the signature covers the wrapped bytes.
  - `ValidityInfo` members `signed`, `validFrom`, `validUntil` are `tdate` (CBOR tag 0); the validity window is `validFrom`..`validUntil`.
  - `deviceKeyInfo.deviceKey` is a COSE_Key map.
  - `DeviceAuthenticationBytes` = `#6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes])`, used as the **payload** of a detached COSE_Sign1 with an empty `external_aad`. **Derived**, not proven — from `openwallet-foundation-labs/identity-credential` at `35bed72e20848a4bd8ec5c4bccece42021c9ee49` and `spruceid/isomdl` at `fcb49d15ad9d54afa028a12183ee7fab1e46a5dc`, which agree byte-for-byte.
- **State plainly** which facts are proven and which are derived, that neither status equals having read the standard, and that this stub does not acquire the precedence of a standards-track specification.
- **Not covered:** `DeviceMac`, multi-document responses, NFC/BLE device engagement.

- [ ] **Step 2: Add the §4.4 table row**

In root `AGENTS.md`, add `iso-18013-5-device-auth.md` to the external-reference
table alongside `emvco-dpc-schema-framework.md`, governing "the mdoc CBOR
internals `foundry-mdoc` builds and verifies".

- [ ] **Step 3: Update the conformance register**

In `docs/conformance/openid4vc-conformance.md`:

- `HAIP-0070` → `conforming`. Its current evidence says foundry's payload "is the
  bespoke `{mdoc, device_signature}` pair rather than a `DeviceResponse` at all";
  replace with the `DeviceResponse` envelope plus the fixture and vector tests.
- Add a new `GAP-VCI-<next free id>` row for the OpenID4VCI credential envelope
  (design doc §7): `build_mdoc` returns a `DeviceResponse`-shaped wrapper where
  L2249 requires a bare `IssuerSigned`. Severity Minor; note that the CBOR
  *inside* the envelope is now conformant.
- `VCI-0176`: correct the evidence to say it justifies the base64url **encoding**
  only, and cross-reference the new gap for the structure.
- `VCI-0071`: re-check against the new credential bytes; the base64url claim still
  holds, so this is an evidence refresh, not a verdict change.
- Remove the "excluded — not vendorable" note for mdoc format internals **only if**
  it now overstates the exclusion; the standard is still not vendored, so prefer
  amending it to point at the new stub.

- [ ] **Step 4: Verify the docs are internally consistent**

```bash
rg -n "device_signature|bespoke" crates/*/AGENTS.md docs/conformance/openid4vc-conformance.md
```

Expected: no remaining claim that foundry's mdoc payload is the split envelope.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
git add AGENTS.md docs/specs/iso-18013-5-device-auth.md docs/conformance/openid4vc-conformance.md
git commit -m "docs: ISO 18013-5 reference stub, close HAIP-0070, open the envelope gap

Adds a docs/specs reference stub under the AGENTS.md 4.4 external-reference
rule: ISO 18013-5 is a paid standard and cannot be committed, so the stub
records the exact document, why no copy is in-tree, and the interface facts
foundry relies on -- restated, not quoted.

It marks each fact as proven or derived and does not conflate them. The digest
basis and the CBOR shapes are proven against a captured presentation; the
DeviceAuthentication structure is derived from two independent implementations
at pinned commits. Neither is the same as having read the standard.

HAIP-0070 becomes conforming. A new GAP-VCI row records the still-deferred
OpenID4VCI credential envelope, and VCI-0176's evidence is corrected to claim
only the base64url encoding it actually justifies."
```

---

### Task 10: Change record

**Files:**

- Create: `docs/superpowers/changes/2026-08-19-mdoc-deviceresponse-verification.md`

- [ ] **Step 1: Write the change record**

Cover: the reported symptom and its root cause; the four blocking defects and
which were proven versus derived; the two **retracted** suspicions from design doc
§1.7 and why (inferred from reading, refuted by executing); the deliberate
deferrals (§7 credential envelope, §8 trust and expiry policy); and the honest
status of the interop proof.

**State plainly whether the real-wallet device-signature fixture (design doc §9,
§5 test 4) was captured.** If it was not, say so: the change ships with proven
`IssuerSigned` internals and derived `DeviceAuthentication` vectors, but no
real-wallet proof that the Device Signature verifies. That is a materially weaker
position than the rest of the work and must not be glossed.

Also record the expected operational outcome: the `av` query stops failing on the
envelope and starts failing on issuer trust, which is a truthful verdict about an
expired, unanchored credential — not a remaining bug.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/changes/2026-08-19-mdoc-deviceresponse-verification.md
git commit -m "docs: change record for mdoc DeviceResponse verification"
```

---

## Self-Review

Run against the design doc before starting Task 1.

**Spec coverage.** §1.6 defects 3 and 4 → Tasks 3 and 2. §1.5 defect (DeviceAuth)
→ Task 6. §1.3 defect (envelope) → Task 7. §1.7 retractions → no task, by design.
§3 decisions: 1 → Tasks 2-4 scope; 2 → the strictness assertions in Tasks 2-4 and
7; 3 → Global Constraints; 4 → Task 7; 5 → Task 6; 6-8 → Task 6 parse checks;
9-10 → Task 4; 11 → not implemented, by design (§8). §4.1-§4.6 → Tasks 1-7.
§5 tests 1-8 → Tasks 2 (test 1 synthetic), 5 (test 1 proven, test 3), 6 (tests 2,
5, 7, 8), 7-8 (test 5 cross-crate), and the per-defect anti-regressions of test 6
are spread across Tasks 2, 3, 4, 6 and 7. §6 → Task 9. §9 → folded into Task 7
Step 4 (the trace) plus Task 5 (the fixture); the fresh capture itself is a
maintainer action, flagged in Task 10.

**Known gaps in this plan, stated rather than hidden.**

1. **Design doc §5 test 2 — the pinned `DeviceAuthenticationBytes` hex — has no
   literal.** Task 6's `device_authentication_bytes_have_the_derived_structure`
   asserts the *structure* element by element, which catches every shape error,
   but it does not pin a byte string produced independently of foundry. Producing
   that literal requires running one of the two reference implementations to
   generate a vector offline. **Do this during Task 6** and add the literal; if it
   is skipped, say so in Task 10's change record.
2. **Design doc §5 test 4 — the interop golden fixture — is blocked** on the fresh
   capture (§9). Task 5 delivers everything provable from the existing capture;
   the device-signature half needs a transcript that only a live run produces.
3. **Two `unimplemented!()` markers** are deliberate, in Task 3
   (`unwrap_issuer_auth_payload_in_place`) and Task 6 (`parse_device_response`,
   `build_device_response`). Each carries an implementer note with the full
   algorithm. They are CBOR surgery whose exact expression depends on decisions
   the implementer makes about helper reuse; spelling them out line by line would
   be guessing at code the implementer can write correctly from the outline.

**Type consistency.** `verify_mdoc` takes `&ciborium::Value` for the transcript in
Tasks 2-6 and at the Task 7 call site. `IssuerVerified` carries both
`device_key_jwk` (for `MdocVerificationResult`) and `device_key_x`/`device_key_y`
(for `verify_device_auth`) — both are needed and both are declared in Task 6.
`tag24_unwrap` returns `Result<&[u8], String>` and every caller maps the `String`
into a `FormatError` variant. Task 6's implementer note supersedes the
`parse_device_response(bytes)` signature shown in its own first code block with
the two-call `decode_device_response` + `parse_device_response(&decoded)` shape;
**the two-call shape is normative** and Task 7 Step 4 uses it.
