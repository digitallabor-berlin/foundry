# mdoc `DeviceResponse` Verification and ISO 18013-5 Format Internals — Design

**Date:** 2026-08-19
**Revised:** 2026-08-19 — scope widened after decoding the real MSO (§1.6), then two
suspected defects retracted after executing a probe against the capture (§1.7)
**Status:** approved (design); implementation plan pending
**Crates touched:** `foundry-mdoc`, `foundry-verifier`
**Closes:** `HAIP-0070`; divergences #1 and #2 in `crates/foundry-mdoc/AGENTS.md`; three
`TODO(interop)` notes in `crates/foundry-mdoc/src/types.rs`
**Opens:** one new issuance-leg gap (`GAP-VCI-<next free id>`, assigned when the row is written)

---

## 1. Problem

A real wallet presented an EU Age Verification attestation over the DC API against
the `av` named query. foundry rejected it at HTTP 400:

```text
credential query 'av' declares format mso_mdoc, so its presentation
must be an object, got a string
```

The wallet was right and foundry was wrong. That error is the **first** of four
blocking defects; the rest were found while planning the fix (§1.6).

### 1.1 What the wallet sent

Decoding the `vp_token["av"][0]` string from the captured trace yields a
structurally conformant ISO 18013-5 `DeviceResponse`:

```text
DeviceResponse{}
  version: '1.0'
  documents[1]
    [0] docType: 'eu.europa.ec.av.1'
        issuerSigned{ nameSpaces{'eu.europa.ec.av.1'[1]}, issuerAuth[COSE_Sign1] }
        deviceSigned{ nameSpaces: Tag24(bstr(1)), deviceAuth{ deviceSignature[COSE_Sign1] } }
  status: 0
```

Note `deviceSignature`'s third element (payload) is CBOR `null` — a **detached
payload**.

### 1.2 What the specification requires

`docs/specs/openid-4-verifiable-presentations-1_0.md` L2825-L2828, *Mobile
Documents or mdocs → Presentation Response*:

> ```json
> { "my_credential": ["<base64url-encoded DeviceResponse>"] }
> ```
>
> The VP Token contains the base64url-encoded `DeviceResponse` CBOR structure as
> defined in ISO/IEC 18013-5 or ISO/IEC 23220-4.

### 1.3 What foundry does instead

`crates/foundry-verifier/src/verify.rs` (`select_presentation`, mso_mdoc arm)
requires a JSON **object** carrying two independently base64url-encoded members:

```json
{ "mdoc": "<b64url CBOR>", "device_signature": "<b64url COSE_Sign1>" }
```

This shape is foundry-invented. It appears in no specification. It has **no
production producer** anywhere in the workspace — only test code in
`crates/foundry-verifier/src/verify.rs` and `crates/foundry/tests/wallet_verification.rs`
constructs it.

### 1.4 Why it survived

`crates/foundry-mdoc/src/verifier.rs`'s `verify_mdoc` takes the device signature
as a **separate argument** and never reads `deviceSigned` from the document.
`crates/foundry-mdoc/src/builder.rs`'s `build_mdoc` emits the matching envelope.
Builder and verifier therefore agree with each other and with nothing else, and
every mdoc test in the workspace is a round trip between the two. A green mdoc
suite proved only self-consistency — stated explicitly in
`crates/foundry-mdoc/AGENTS.md`'s Gotchas.

### 1.5 The device-authentication defect

Fixing the envelope alone would not make a real presentation verify. Today:

```rust
// crates/foundry-mdoc/src/verifier.rs — device signature verification
let d_tbs = coset::sig_structure_data(
    coset::SignatureContext::CoseSign1,
    d_sign1.protected.clone(),
    None,
    &[],                // external_aad — correct
    session_transcript, // payload — WRONG
);
```

foundry signs over the `SessionTranscript` **alone**. A conformant wallet signs
over the `DeviceAuthentication` array that *contains* the transcript. The
`external_aad` slot was already correct.

### 1.6 Two further blocking defects, found by decoding the captured MSO

`verify_mdoc` cannot parse a real mdoc **at all**. Both rows below are
independently fatal.

| # | Element | Real wallet | foundry today |
| --- | --- | --- | --- |
| 3 | `issuerAuth` payload | `#6.24(bstr .cbor MSO)` — begins `d818 5902 02` | passes `sign1.payload` straight to `ciborium::from_reader::<MobileSecurityObject>`, which fails with `invalid type: bytes, expected map` |
| 4 | `IssuerSignedItem`s in `nameSpaces` | `#6.24(bstr …)`, with `valueDigests` computed over the **full tagged encoding** | `item_val.as_bytes()`, and hashes those inner bytes |

Defect 4 is the most damaging because it fails *quietly*. `as_bytes()` returns
`None` for a tagged value, so every item hits the loop's `continue`, the
credential verifies with **zero reconstructed claims**, and the transaction then
fails `dcql_match` — a **policy** outcome at HTTP 200 per root `AGENTS.md` §4.3.
A reader would see `verified: false` with a DCQL mismatch and reasonably conclude
the wallet sent the wrong claims.

Both are already recorded in the tree as `TODO(interop)` comments in
`crates/foundry-mdoc/src/types.rs` — *"payload is not tag-24 embedded-CBOR
wrapped"* and *"should be transported as tag-24 embedded CBOR"*. They read as
cosmetic and are in fact two of the four reasons no real mdoc can be verified.

### 1.7 Two suspected defects, retracted

A first pass at §1.6 listed two further defects. Both were **inferred from
reading code** and both are wrong; a probe executed against the captured bytes
retracted them. Recorded here because the reasoning is a trap worth naming.

- **`deviceKeyInfo.deviceKey` is fine.** It *is* a COSE_Key map rather than a
  byte string, but `cbor_value_to_bytes` is `ciborium::into_writer` — it
  **re-encodes** any `Value`, so the map becomes COSE_Key bytes and
  `CoseKey::from_slice` accepts it. (The builder's inverse helper is named
  `cbor_to_value_bytes` and *decodes*; the two names invite exactly this
  misreading.) No change required.
- **`validityInfo` tag-0 `tdate` values parse today.** ciborium's deserializer
  carries `Header::Tag(..) => continue` in every typed `deserialize_*`, so it
  silently skips tags and a tag-0 value deserializes into `String` unharmed.

What survives of the second point is narrower and belongs to issuance, not
verification: foundry's **builder** emits untagged text where ISO wants tag-0,
and foundry does not model `validFrom` at all. Both are in scope by decision
(§3 decisions 9-10) as conformance fixes, not as blockers.

---

## 2. Ground truth

ISO/IEC 18013-5 is a paid standard, is not vendored here, and is listed as out of
scope in `docs/conformance/openid4vc-conformance.md` ("mdoc format internals …
not vendorable — paid standard"). OpenID4VP restates the `SessionTranscript`
changes but nothing else of the format.

Ground truth therefore comes from two places, with **different and separately
recorded strengths of evidence**:

- **Derived** (§2.1-§2.2) — from two independent open-source implementations read
  at pinned commits, which agree byte-for-byte.
- **Proven** (§2.3) — computed from the captured real presentation. Stronger: a
  digest either matches or it does not.

| Derivation source | Language | Commit |
| --- | --- | --- |
| `openwallet-foundation-labs/identity-credential` (multipaz) | Kotlin | `35bed72e20848a4bd8ec5c4bccece42021c9ee49` |
| `spruceid/isomdl` | Rust | `fcb49d15ad9d54afa028a12183ee7fab1e46a5dc` |

multipaz is authoritative for the captured fixture specifically: the credential's
issuer certificate is `CN=[Test] mDL Reference Implementation DS`, that project's
own test PKI.

### 2.1 `DeviceAuthentication` (derived)

```cddl
Sig_structure = ["Signature1", protected, h'', DeviceAuthenticationBytes]

DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)

DeviceAuthentication = [
    "DeviceAuthentication",   ; tstr
    SessionTranscript,        ; bare 3-element array, BY VALUE, untagged
    docType,                  ; tstr
    DeviceNameSpacesBytes     ; #6.24(bstr), copied VERBATIM from the wire
]
```

`external_aad` is the empty byte string. Detachment changes only the wire
COSE_Sign1 (`payload: null`), never the `Sig_structure` — multipaz states this in
a source comment: *"Next field is the payload, independently of how it's
transported"*.

### 2.2 Two hazards, flagged independently by both sources

1. **`DeviceNameSpacesBytes` must be byte-preserved, never re-encoded.** Both
   verifiers reuse the received tag-24 item verbatim rather than rebuilding it
   from the decoded map.
2. **tag-24 on `SessionTranscript` is a decoy.** multipaz *does* wrap the
   transcript in tag-24 — but only as a MAC key-derivation salt, never for
   signatures. Element [1] of `DeviceAuthentication` is the bare, untagged array.

### 2.3 `IssuerSigned` internals (proven from the capture)

**`valueDigests` are SHA-256 over the FULL tag-24 encoding** of each
`IssuerSignedItemBytes`, not over the inner CBOR:

```text
digestID 4, MSO valueDigests : 7c85201a1c0ba374fb569d36beab6b52251483618b70dcb0782599a2e3e8f2f6
sha256(full #6.24(bstr …))   : 7c85201a1c0ba374fb569d36beab6b52251483618b70dcb0782599a2e3e8f2f6   MATCH
sha256(inner .cbor item)     : b27f1be959cd027d5308f86f331fb962bfb8eefdba39672330f9fac7845db11d   what foundry hashes
```

Other values read directly from the capture, to be used as test literals:

```text
issuerAuth payload prefix       d818 5902 02          ; #6.24(bstr(514))
MSO version / digestAlgorithm   "1.0" / "SHA-256"
MSO docType                     "eu.europa.ec.av.1"
valueDigests digestIDs          0,1,2,3,4,5           ; 6 committed, 1 disclosed
deviceKey (COSE_Key map)        {1: 2, -1: 1, -2: bstr32, -3: bstr32}   ; already handled, §1.7
validityInfo members            signed, validFrom, validUntil  ; all CBOR tag-0 tdate
deviceSigned.nameSpaces         d81841a0              ; #6.24(bstr(1) = A0), empty map
```

The 6-committed / 1-disclosed split confirms ordinary selective disclosure and
that the reconstruction loop must iterate the **received items**, not the MSO's
digest list — which today's loop already does correctly.

---

## 3. Scope decisions

| # | Decision | Rationale |
| --- | --- | --- |
| 1 | **Verifier leg *and* format internals.** The OpenID4VCI credential envelope is the only deferred piece (§7). | Revised from "verifier leg only" after §1.6. Format internals are not separable: every synthetic mdoc test round-trips through `build_mdoc`, so a verifier that requires conformant shapes needs a builder that emits them. Since `build_mdoc`'s output *is* what foundry issues, this necessarily changes the issued wire format. |
| 2 | **Be strict, not liberal: do not also accept foundry's current non-conformant shapes.** | The tempting alternative — accept tag-24-or-bare and tdate-or-tstr — would let the builder stay untouched and avoid all test churn. Rejected: permanently accepting shapes no wallet emits is the same reflex that produced the bespoke envelope in §1.3, and it would leave the codebase with two live formats and no statement of which is real. |
| 3 | **No `isomdl` dependency — not even `[dev-dependencies]`.** | Root `AGENTS.md` §3: no vendored third-party crates; prefer extending foundry-owned models over introducing a protocol dependency. Assessed and rejected: `isomdl` 0.2.0 collides on `x509-cert` (0.2 vs 0.3) and `base64` (0.13), imposes `generic-array = "=0.14.7"`, adds a second complete X.509 stack that foundry would never call (trust policy lives in `foundry-core`'s openssl-based `TrustStore`), and has 0 crates.io dependents. Used as a **read-only reference** instead. |
| 4 | **Drop the bespoke `{mdoc, device_signature}` object; do not accept both shapes.** | No production producer exists, so "accept both" would preserve a shape whose only purpose was passing our own tests, while leaving the real contract ambiguous to the next reader. |
| 5 | **Add a public `build_device_response()` to `foundry-mdoc::builder`.** | Synthetic tests in three crates need to produce a conformant presentation. The workspace has no `test-util` feature pattern, and `build_mdoc` is already plain-public and consumed cross-crate. |
| 6 | **Reject a `DeviceResponse` carrying more than one document.** | Today `docs.first()` silently ignores extras — the same defect class `select_presentation` already refuses for presentation arrays. HAIP-0070 independently requires each mdoc in its own `DeviceResponse`. |
| 7 | **Read and require `status == 0`.** | Currently never read. Verifying a document inside a response the wallet itself flagged as failed would report success for something the sender did not claim succeeded. |
| 8 | **`DeviceMac` stays unimplemented, as a typed error.** | foundry accepts only ES256/COSE `-7` (VP-0225/VP-0226). Root `AGENTS.md` §4.4: unimplemented optional features are acceptable; incorrect implementations are not. |
| 9 | **Emit and require tag-0 `tdate` validity values.** Not a blocker (§1.7) — included as a conformance fix. | The builder emits untagged text where ISO wants `tdate`, so foundry-issued MSOs are non-conformant on the wire. `ciborium::tag::Required<String, 0>` closes it declaratively and, per decision 2, also makes the verifier reject the untagged form rather than tolerating two encodings. Closes the third `TODO(interop)`. |
| 10 | **Model `validFrom` and check validity against `validFrom`…`validUntil`, not `signed`…`validUntil`.** Not a blocker (§1.7) — included as a semantic fix. | `validFrom` is present in real MSOs and is the member that bounds document validity; `signed` records when the MSO was signed. Today's check uses `signed` only because the struct has no `validFrom` to use. |
| 11 | **No change to trust or expiry policy.** | See §8. |

---

## 4. Design

### 4.1 `foundry-mdoc/src/types.rs` — model the real CBOR

```rust
/// MobileSecurityObject (ISO/IEC 18013-5 §9.1.2.4).
///
/// Transported as `#6.24(bstr .cbor MobileSecurityObject)` in the IssuerAuth
/// COSE_Sign1 payload; the tag-24 wrapper is handled at the parse site, not
/// here, because the IssuerAuth signature is computed over the wrapped bytes.
pub struct MobileSecurityObject {
    pub version: String,
    #[serde(rename = "digestAlgorithm")]
    pub digest_algorithm: String,
    #[serde(rename = "docType")]
    pub doc_type: String,
    #[serde(rename = "valueDigests")]
    pub value_digests: BTreeMap<String, BTreeMap<u64, Vec<u8>>>,
    #[serde(rename = "deviceKeyInfo")]
    pub device_key_info: DeviceKeyInfo,
    #[serde(rename = "validityInfo")]
    pub validity_info: ValidityInfo,
}

/// `deviceKey` is a COSE_Key **map**. Unchanged by this design: the existing
/// re-encode-then-`CoseKey::from_slice` path already handles it (§1.7).
pub struct DeviceKeyInfo {
    #[serde(rename = "deviceKey")]
    pub device_key: ciborium::Value,
}

/// All three members are CBOR `tdate` — tag 0 over an RFC 3339 text string.
/// `ciborium::tag::Required<String, 0>` both requires the tag on the way in and
/// always emits it on the way out, so builder and verifier cannot drift.
pub struct ValidityInfo {
    pub signed: ciborium::tag::Required<String, 0>,
    #[serde(rename = "validFrom")]
    pub valid_from: ciborium::tag::Required<String, 0>,
    #[serde(rename = "validUntil")]
    pub valid_until: ciborium::tag::Required<String, 0>,
}
```

`IssuerSignedItem` keeps its fields; what changes is that it is always
transported inside `#6.24(bstr …)` and digested over that full encoding
(§2.3). Its `TODO(interop)` comment is replaced by a statement of that contract.

New helpers, used by both builder and verifier so the two cannot disagree:

```rust
/// Wrap pre-encoded CBOR as `#6.24(bstr .cbor …)`, returning the full tagged
/// encoding — the form ISO digests and signs over.
pub fn tag24_encode(inner_cbor: &[u8]) -> Result<Vec<u8>, String>;

/// Unwrap `#6.24(bstr …)`, returning the inner CBOR bytes. Errors if the value
/// is not tag 24 over a byte string.
pub fn tag24_unwrap(value: &ciborium::Value) -> Result<&[u8], String>;

/// The `SessionTranscript` as a `ciborium::Value`, for splicing by value into
/// `DeviceAuthentication` element [1] without a decode/re-encode round trip.
pub fn session_transcript_value(
    params: &SessionTranscriptParams,
) -> Result<ciborium::Value, String>;

/// Unchanged signature; now `encode_cbor(&session_transcript_value(params)?)`.
pub fn build_session_transcript(params: &SessionTranscriptParams) -> Result<Vec<u8>, String>;
```

### 4.2 `foundry-mdoc/src/verifier.rs` — split, and parse the real shapes

```rust
/// Borrowed structural view of a parsed DeviceResponse. Holds references into
/// the caller's decoded CBOR rather than owning re-decoded types, so that
/// `deviceSigned.nameSpaces` can be re-emitted byte-for-byte (§2.2 hazard 1).
pub struct DeviceResponse<'a> { /* doc_type, issuer_signed, device_signed views */ }

pub fn parse_device_response(bytes: &[u8]) -> Result<DeviceResponse<'_>, FormatError>;

pub fn verify_issuer_signed(
    resp: &DeviceResponse<'_>,
    trust_store: &TrustStore,
    now_unix: u64,
) -> Result<IssuerVerified, FormatError>;   // claims + device key coords + x5c + doc_type

pub fn verify_device_auth(
    resp: &DeviceResponse<'_>,
    session_transcript: &ciborium::Value,
    device_key_x: &[u8],
    device_key_y: &[u8],
) -> Result<(), FormatError>;

pub fn verify_mdoc(                        // thin orchestrator, existing call site
    device_response_bytes: &[u8],
    trust_store: &TrustStore,
    session_transcript: &ciborium::Value,
    now_unix: u64,
) -> Result<MdocVerificationResult, FormatError>;
```

Behaviour changes inside the issuer half, one per defect:

- **#3** — the IssuerAuth signature is still verified over `sign1.payload`
  **verbatim** (unchanged, and important not to "fix"); the MSO is then parsed
  from `tag24_unwrap` of that payload.
- **#4** — each namespace item is `tag24_unwrap`ped to parse the
  `IssuerSignedItem`, while the digest is computed over the item's **full tagged
  encoding**. An item whose digest is absent from the MSO or does not match is
  still dropped (existing behaviour), but an item that is not tag-24 at all is now
  a structural error rather than a silent skip — silence there is what made
  defect 4 invisible.
- **Decisions 9-10** — validity is checked as `valid_from <= now <= valid_until`,
  both parsed RFC 3339 out of the `Required<String, 0>` wrappers.
- **`deviceKey` is untouched** (§1.7).

`MdocVerificationResult` is unchanged (`claims`, `device_key_jwk`, `issuer_x5c`,
`doc_type`).

**Why three functions rather than one.** The captured fixture can never pass
issuer validation here (§8), so the device-signature half must be verifiable
*without* the issuer half. A design whose only entry point is "verify everything"
makes the interop fixture impossible to write — which is how these divergences
survived. `verify_mdoc` remains a thin orchestrator so the existing call site
changes minimally.

### 4.3 `foundry-mdoc/src/builder.rs` — emit the real shapes

`build_mdoc` changes to emit: tag-24-wrapped `IssuerSignedItemBytes` with digests
over the full tagged encoding; a tag-24-wrapped MSO as the IssuerAuth payload;
and tag-0 `tdate` validity values including `validFrom`. `deviceKey` already
emits a COSE_Key map and is unchanged (§1.7). The outer
`{version, documents:[…]}` envelope is unchanged here — that is §7.

New:

```rust
pub fn build_device_response(
    issuer_signed_mdoc: &[u8],
    doc_type: &str,
    device_signer: &dyn Signer,
    session_transcript: &ciborium::Value,
) -> Result<Vec<u8>, FormatError>;
```

It emits `deviceSigned.nameSpaces` as `d81841a0` (empty map) and a detached
`deviceSignature` over `DeviceAuthenticationBytes`, and sets `status: 0`.

### 4.4 `foundry-verifier` — envelope and candidate loop

- `SelectedPresentation::MsoMdoc` collapses from
  `{ mdoc_b64, device_signature_b64 }` to a single `device_response_b64: &str`.
- The mso_mdoc arm of `select_presentation` accepts a **string**; a non-string
  presentation produces a structural error citing OpenID4VP L2825-L2828 and
  naming `DeviceResponse`.
- The DC API Origin candidate loop restructures: `parse_device_response` and
  `verify_issuer_signed` run **once**; only `verify_device_auth` repeats per
  candidate Origin. Today the loop re-runs full chain validation, MSO validity
  and digest matching for every configured Origin to retry one signature check.

### 4.5 Data flow

```text
vp_token["av"][0] : base64url string
  → B64URL decode                        → DeviceResponse CBOR bytes
  → parse_device_response                → version, exactly one document, status == 0
  → verify_issuer_signed (once)          → IssuerAuth chain + signature over the
                                           tag-24 payload; MSO from tag24_unwrap;
                                           validFrom..validUntil; digests over full
                                           tag-24 item encodings
  → for each candidate Origin:
        session_transcript_value(DcApi{origin, nonce, thumbprint})
        verify_device_auth(resp, transcript, device_key)   // DeviceAuthenticationBytes
  → first success wins; all failures → last error
  → MdocVerificationResult → cbor_value_to_json → DCQL match → status check
```

### 4.6 Error handling

Structural, surfacing as HTTP 400 per root `AGENTS.md` §4.3, as typed
`FormatError` values — no panics, no `.unwrap()` (root `AGENTS.md` §4.1):

- malformed outer CBOR; missing `version` / `documents` / `status`
- more than one document (§3 decision 6); `status != 0` (§3 decision 7)
- missing `deviceSigned`, `deviceAuth`, or `deviceSignature`
- `deviceMac` instead of `deviceSignature` → explicit "unsupported" (§3 decision 8)
- IssuerAuth payload not tag-24 (defect 3); a namespace item not tag-24 (defect 4)
- a `validityInfo` member missing tag 0 (§3 decision 9)
- unsupported COSE `alg` on either signature

Device-signature mismatch remains `FormatError::KeyBinding`, folded into the
`mdoc_issuer_auth_and_device_signature` per-credential `CheckResult` (root
`AGENTS.md` §4.2 honesty: the check passes only if `verify_mdoc` returned `Ok`).

---

## 5. Testing

The gate is root `AGENTS.md` §5.1 — whole workspace, `cargo nextest run`, never
`cargo test`.

1. **Pinned digest vector (proven).** `sha256` of the captured item's full tag-24
   encoding equals the MSO's `valueDigests[4]`, with the literals of §2.3. This
   pins defect 4's resolution against real bytes, and asserts the *negative* too:
   the inner-CBOR digest must **not** match.
2. **Pinned `DeviceAuthenticationBytes` vector (derived).** Expected hex derived
   offline from the two reference implementations of §2 and pinned as a literal,
   following the existing `spec_hex(…)` precedent in
   `crates/foundry-mdoc/src/types.rs`. Assert the intermediate
   `DeviceAuthentication` encoding alongside the tag-24 wrapping, so a regression
   says which layer drifted.
3. **Real-shape parse tests.** The captured `DeviceResponse` parses: tag-24 MSO
   unwraps, `deviceKey` map yields the expected coords, `validityInfo` tag-0
   values parse, and the disclosed `age_over_18 = true` claim is reconstructed —
   all without a trust store.
4. **Interop golden fixture.** The captured `DeviceResponse` plus its
   transaction's `SessionTranscript`, asserting `verify_device_auth` succeeds.
   PKI-free, so the expired and unanchored issuer chain is irrelevant. First test
   in the workspace proving mdoc interoperability rather than self-consistency.
   **Blocked on §9.**
5. **Synthetic round trip.** `build_mdoc` → `build_device_response` →
   `verify_mdoc`, migrating the existing mdoc tests in
   `crates/foundry-mdoc/src/verifier.rs`, `crates/foundry-verifier/src/verify.rs`,
   `crates/foundry-verifier/tests/conformance_vp.rs` and
   `crates/foundry/tests/wallet_verification.rs`.
6. **Anti-regression, per defect.** Each old behaviour must now fail: the bespoke
   envelope; a device signature over the bare `SessionTranscript`; a bare
   (untagged) MSO payload; an untagged namespace item; and untagged (tstr)
   validity values. Without these, the migration in test 5 could silently
   preserve any of them.
7. **Byte-preservation.** A `deviceSigned.nameSpaces` whose re-encoding would
   differ from its received bytes MUST still verify — pinning hazard 1 of §2.2.
8. **Envelope rejection.** Multi-document response and `status != 0` each produce
   the expected typed structural error.

---

## 6. Documentation and conformance updates

- **New:** `docs/specs/iso-18013-5-device-auth.md` — a reference stub under root
  `AGENTS.md` §4.4's external-reference rule. Records the document's exact title
  and revision, why no copy is in-tree (paid standard, redistribution
  forbidden), where a reader obtains one, and the interface facts foundry relies
  on **restated rather than quoted** — the §2.1 structure, the §2.3 internals —
  plus the two derivation sources at their pinned commits, and which facts are
  derived versus proven. A stub does not acquire the precedence of a
  standards-track specification.
- **Row added** to §4.4's governing-documents table in the root `AGENTS.md`.
- `crates/foundry-mdoc/AGENTS.md`: rewrite Gotchas divergence #1; **delete
  divergence #2**, which is stale — the `SessionTranscript` / `OpenID4VPHandover`
  work landed and VP-0229…VP-0246 are all `conforming`, pinned byte-for-byte
  against published vectors. Update the module map, the public-entry-point list,
  and the "Namespace/digest matching" and "CBOR canonical encoding" gotchas,
  which describe the pre-change behaviour.
- `crates/foundry-verifier/AGENTS.md`: replace the per-format payload description
  of the bespoke mdoc shape.
- `docs/conformance/openid4vc-conformance.md`:
  - `HAIP-0070` → `conforming`, citing the new fixture and vector tests.
  - **New `GAP-VCI-<next free id>`** for the deferred credential envelope (§7).
  - `VCI-0176` evidence corrected: it justifies the base64url *encoding* only,
    not the CBOR *structure*. Re-check `VCI-0071` and `VCI-0176` against the new
    credential bytes, since §4.3 changes what foundry issues.

---

## 7. Deferred: the OpenID4VCI credential envelope

`build_mdoc` returns `{version, documents: [{docType, issuerSigned}]}` — a
`DeviceResponse`-shaped wrapper minus `status` and `deviceSigned` — and
`handle_credential_request` base64url-encodes that whole envelope as the
OpenID4VCI `credential`. OpenID4VCI L2249 requires the `credential` claim to be
the base64url-encoded CBOR **`IssuerSigned`** structure: the inner object only.

Deliberately out of scope (§3 decision 1) and recorded as a new gap. Note what
this change *does* alter: after §4.3, the bytes inside that envelope become
ISO-conformant even though the envelope around them does not. A wallet still
cannot load a foundry-issued mdoc, so mdoc issuance and mdoc presentation remain
un-exercisable as one end-to-end flow against third-party software.

---

## 8. Deferred: trust and expiry policy

The captured credential fails issuer validation here for two independent reasons
this design does not address:

1. Its chain roots at `[Test] mDL Reference Implementation IACA`, which is not in
   `trust_anchors`. There is exactly one trust store, built from
   `config.trust_anchors` and shared with SD-JWT VC issuer chains and Token
   Status List chains — so anchoring it would widen trust for every other path.
2. Its DS certificate expired 2025-09-17. `foundry-core`'s trust layer maps
   `X509_V_ERR_CERT_HAS_EXPIRED` to a typed `TrustError` with no override.

**Expected outcome of this change, stated plainly:** the `av` query stops failing
on the envelope and starts failing on issuer trust — a truthful rejection of a
credential that is genuinely expired and genuinely unanchored in this deployment.
Making it verify requires a security-policy decision (a trust-relaxation switch,
with its own justification and its own conformance rows) or re-issuance under
foundry's own PKI, which depends on §7. Neither belongs in a format change.

---

## 9. Open item: capturing the golden fixture

Test 4 in §5 needs the exact `SessionTranscript` of a live transaction. The
transcript is derived from `tx.nonce`, the Origin and the response-encryption key
thumbprint; the original transaction has aged out of storage
(`transaction_ttl_secs: 600`), and neither the nonce nor the thumbprint was
logged.

Required, in order:

1. Add a permanent diagnostic to the mdoc branch of `verify.rs`: the candidate
   `SessionTranscript` hex, gated on **both**
   `foundry_core::obs::sensitive_enabled()` **and** `trace` level, per root
   `AGENTS.md` §4.5. This matches the existing treatment of the decrypted
   response payload and is independently useful for interop debugging.
2. One fresh `av` run against the wallet, capturing the transcript hex alongside
   the `DeviceResponse`.
3. Commit both as a fixture with provenance recorded: wallet, date, docType, and
   the fact that its issuer chain is expired and unanchored by design.

Implementation is **not** blocked on this. Tests 1, 3 and 6 already run against
the captured bytes without a transcript, §2.1 is pinned by two independent
sources, and tests 2, 5, 7 and 8 are writable immediately. Only the end-to-end
device-signature proof is blocked. If the capture never happens, this change
ships with proven `IssuerSigned` internals, derived `DeviceAuthentication`
vectors and synthetic round trips, but **no real-wallet proof of the device
signature** — which must be stated as such in the change record.

---

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| `DeviceAuthentication` is derived, not proven; no live oracle. | Two independent implementations agreeing at pinned commits (§2.1), pinned vectors (§5 test 2), and the interop fixture (§5 test 4) once §9 lands. |
| Changing `build_mdoc` changes issued credential bytes. | Intended (§3 decision 1) and called out in §6 as a `VCI-0071`/`VCI-0176` re-check. No stored-credential migration exists to break — issuance is demo-stage. |
| Several simultaneous format changes make a failure hard to localise. | Per-defect anti-regression tests (§5 test 6) and per-layer vector assertions (§5 tests 1-2), so each defect has an independent witness. The plan sequences one format flip per task. |
| Defects inferred from reading rather than executing. | §1.7 records two such retractions and why. Every remaining structural claim is either proven against the capture (§2.3) or agreed by two independent implementations (§2.1). |
| `ciborium` re-encoding perturbs `deviceSigned.nameSpaces`. | Borrowed views in `DeviceResponse<'a>`; explicit byte-preservation test (§5 test 7). |
| Transcript decode/re-encode drift. | `session_transcript_value` returns the `Value` directly; no round trip. Existing published-vector tests continue to pin the byte form. |
| `tag24_encode`/`tag24_unwrap` used inconsistently between builder and verifier. | One shared pair of helpers in `types.rs` (§4.1), exercised from both sides by the round-trip test (§5 test 5). |
| ISO internals derived from implementations and one capture, not the standard. | §2 separates proven from derived facts and records both; the §6 reference stub carries that distinction forward rather than flattening it. |
