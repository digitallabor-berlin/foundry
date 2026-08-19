# mdoc `DeviceResponse` Verification — Design

**Date:** 2026-08-19
**Status:** approved (design); implementation plan pending
**Crates touched:** `foundry-mdoc`, `foundry-verifier`
**Closes:** `HAIP-0070`; divergence #1 in `crates/foundry-mdoc/AGENTS.md`
**Opens:** one new issuance-leg gap (`GAP-VCI-<next free id>`, assigned when the row is written)

---

## 1. Problem

A real wallet presented an EU Age Verification attestation over the DC API against
the `av` named query. foundry rejected it at HTTP 400:

```text
credential query 'av' declares format mso_mdoc, so its presentation
must be an object, got a string
```

The wallet was right and foundry was wrong.

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

### 1.5 The second, deeper defect

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

---

## 2. Ground truth for `DeviceAuthentication`

ISO/IEC 18013-5 is a paid standard, is not vendored in this repository, and is
listed as out of scope in `docs/conformance/openid4vc-conformance.md`
("mdoc format internals … not vendorable — paid standard"). OpenID4VP restates
the `SessionTranscript` changes but never the `DeviceAuthentication` structure.

The structure was therefore derived from **two independent open-source
implementations, read at pinned commits**, which agree byte-for-byte:

| Source | Language | Commit |
| --- | --- | --- |
| `openwallet-foundation-labs/identity-credential` (multipaz) | Kotlin | `35bed72e20848a4bd8ec5c4bccece42021c9ee49` |
| `spruceid/isomdl` | Rust | `fcb49d15ad9d54afa028a12183ee7fab1e46a5dc` |

multipaz is authoritative for the captured fixture specifically: the credential's
issuer certificate is `CN=[Test] mDL Reference Implementation DS`, that project's
own test PKI.

### 2.1 The structure

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

### 2.2 Two hazards, both flagged independently by both sources

1. **`DeviceNameSpacesBytes` must be byte-preserved, never re-encoded.** Both
   verifiers reuse the received tag-24 item verbatim rather than rebuilding it
   from the decoded map. For the captured empty-map case the bytes are
   `d818 41 a0`.
2. **tag-24 on `SessionTranscript` is a decoy.** multipaz *does* wrap the
   transcript in tag-24 — but only as a MAC key-derivation salt, never for
   signatures. Element [1] of `DeviceAuthentication` is the bare, untagged array.

---

## 3. Scope decisions

| # | Decision | Rationale |
| --- | --- | --- |
| 1 | **Verifier leg only.** Issuance stays as-is, recorded as a new gap. | The two legs are independently testable. Rewriting both sides of the only equality the mdoc tests assert, in one change, means a failure cannot be localised. |
| 2 | **No `isomdl` dependency — not even `[dev-dependencies]`.** | Root `AGENTS.md` §3: no vendored third-party crates; prefer extending foundry-owned models over introducing a protocol dependency. Assessed and rejected: `isomdl` 0.2.0 collides on `x509-cert` (0.2 vs 0.3) and `base64` (0.13), imposes `generic-array = "=0.14.7"`, adds a second complete X.509 stack that foundry would never call (trust policy lives in `foundry-core`'s openssl-based `TrustStore`), and has 0 crates.io dependents. Used as a **read-only reference** instead. |
| 3 | **Drop the bespoke `{mdoc, device_signature}` object; do not accept both shapes.** | No production producer exists, so "accept both" would preserve a shape whose only purpose was passing our own tests, while leaving the real contract ambiguous to the next reader. |
| 4 | **Add a public `build_device_response()` to `foundry-mdoc::builder`.** | Synthetic tests in three crates need to produce a conformant presentation. The workspace has no `test-util` feature pattern, and `build_mdoc` is already plain-public and consumed cross-crate. |
| 5 | **Reject a `DeviceResponse` carrying more than one document.** | Today `docs.first()` silently ignores extras — the same defect class `select_presentation` already refuses for presentation arrays. HAIP-0070 independently requires each mdoc in its own `DeviceResponse`. |
| 6 | **Read and require `status == 0`.** | Currently never read. Verifying a document inside a response the wallet itself flagged as failed would report success for something the sender did not claim succeeded. |
| 7 | **`DeviceMac` stays unimplemented, as a typed error.** | foundry accepts only ES256/COSE `-7` (VP-0225/VP-0226). Root `AGENTS.md` §4.4: unimplemented optional features are acceptable; incorrect implementations are not. |
| 8 | **No change to trust or expiry policy.** | See §8. |

---

## 4. Design

### 4.1 `foundry-mdoc` — public API

```rust
// types.rs — split the existing builder so the transcript is available by value
pub fn session_transcript_value(
    params: &SessionTranscriptParams,
) -> Result<ciborium::Value, String>;

pub fn build_session_transcript(       // unchanged signature; now a thin wrapper
    params: &SessionTranscriptParams,
) -> Result<Vec<u8>, String>;
```

```rust
// verifier.rs
/// Borrowed structural view of a parsed DeviceResponse. Holds references into
/// the caller's decoded CBOR rather than owning re-decoded types, so that
/// `deviceSigned.nameSpaces` can be re-emitted byte-for-byte (§2.2 hazard 1).
pub struct DeviceResponse<'a> { /* docType, issuerSigned, deviceSigned views */ }

pub fn parse_device_response(bytes: &[u8]) -> Result<DeviceResponse<'_>, FormatError>;

pub fn verify_device_auth(
    resp: &DeviceResponse<'_>,
    session_transcript: &ciborium::Value,
    device_key_x: &[u8],
    device_key_y: &[u8],
) -> Result<(), FormatError>;

pub fn verify_mdoc(
    device_response_bytes: &[u8],
    trust_store: &TrustStore,
    session_transcript: &ciborium::Value,
    now_unix: u64,
) -> Result<MdocVerificationResult, FormatError>;
```

```rust
// builder.rs
pub fn build_device_response(
    issuer_signed_mdoc: &[u8],
    doc_type: &str,
    device_signer: &dyn Signer,
    session_transcript: &ciborium::Value,
) -> Result<Vec<u8>, FormatError>;
```

Changes from today:

- `verify_mdoc` loses `device_signature_cose_sign1_bytes` — the signature now
  comes from inside the document.
- `verify_mdoc` takes the transcript as `&ciborium::Value`, not `&[u8]`. Element
  [1] of `DeviceAuthentication` must be spliced **by value**; accepting bytes
  would force a decode-then-re-encode round trip on the one structure least able
  to tolerate perturbation.
- `MdocVerificationResult` is unchanged (`claims`, `device_key_jwk`,
  `issuer_x5c`, `doc_type`).

**Why three functions rather than one.** The captured fixture can never pass
issuer validation here (§8), so the device-signature half must be verifiable
*without* the issuer half. A design whose only entry point is "verify everything"
makes the interop fixture impossible to write — which is how divergence #1
survived. `verify_mdoc` remains a thin orchestrator over the three so the
existing call site changes minimally.

### 4.2 `foundry-verifier` — envelope and candidate loop

- `SelectedPresentation::MsoMdoc` collapses from
  `{ mdoc_b64, device_signature_b64 }` to a single `device_response_b64: &str`.
- The mso_mdoc arm of `select_presentation` accepts a **string**; a non-string
  presentation produces a structural error citing OpenID4VP L2825-L2828 and
  naming `DeviceResponse`.
- The DC API Origin candidate loop restructures: `parse_device_response` and the
  issuer half run **once**; only `verify_device_auth` repeats per candidate
  Origin. Today the loop re-runs full chain validation, MSO validity and digest
  matching for every configured Origin in order to retry one signature check.

### 4.3 Data flow

```text
vp_token["av"][0] : base64url string
  → B64URL decode                                   → DeviceResponse CBOR bytes
  → parse_device_response                            → structural checks (§3 decisions 5-6)
  → verify_issuer_signed (once)                      → IssuerAuth chain, MSO validity,
                                                       digest matching, device key
  → for each candidate Origin:
        session_transcript_value(DcApi{origin, nonce, thumbprint})
        verify_device_auth(resp, transcript, device_key)
  → first success wins; all failures → last error
  → MdocVerificationResult → cbor_value_to_json → DCQL match → status check
```

### 4.4 Error handling

All of the following are **structural** and surface as HTTP 400 per root
`AGENTS.md` §4.3, as typed `FormatError` values — no panics, no `.unwrap()`
(root `AGENTS.md` §4.1):

- malformed outer CBOR; missing `version` / `documents` / `status`
- more than one document (§3 decision 5)
- `status != 0` (§3 decision 6)
- missing `deviceSigned`, `deviceAuth`, or `deviceSignature`
- `deviceMac` present instead of `deviceSignature` → explicit "unsupported"
  (§3 decision 7)
- unsupported COSE `alg` on either signature

Device-signature mismatch remains `FormatError::KeyBinding`, folded into the
`mdoc_issuer_auth_and_device_signature` per-credential `CheckResult` (root
`AGENTS.md` §4.2 honesty: the check passes only if `verify_mdoc` returned `Ok`).

---

## 5. Testing

The gate is root `AGENTS.md` §5.1 — whole workspace, `cargo nextest run`, never
`cargo test`.

1. **Pinned cross-implementation vectors.** `DeviceAuthenticationBytes` hex,
   derived offline from the two reference implementations of §2 and pinned as a
   literal. This follows the existing precedent in
   `crates/foundry-mdoc/src/types.rs`, where the OpenID4VP `SessionTranscript`
   vectors are pinned via a `spec_hex(…)` helper. Assert the intermediate
   `DeviceAuthentication` encoding alongside the final tag-24 wrapping, for the
   same reason the transcript test asserts `OpenID4VPHandoverInfo` separately: a
   regression should say *which* layer drifted.
2. **Interop golden fixture.** The captured real `DeviceResponse` plus its
   transaction's `SessionTranscript`, asserting `verify_device_auth` succeeds.
   PKI-free by construction, so the fixture's expired and unanchored issuer chain
   is irrelevant. This is the first test in the workspace that proves mdoc
   interoperability rather than self-consistency. **Blocked on §9.**
3. **Synthetic round trip.** `build_device_response` → `verify_mdoc`, migrating
   the existing mdoc tests in `crates/foundry-mdoc/src/verifier.rs`,
   `crates/foundry-verifier/src/verify.rs`,
   `crates/foundry-verifier/tests/conformance_vp.rs` and
   `crates/foundry/tests/wallet_verification.rs`.
4. **Anti-regression on the old construction.** A device signature computed over
   the bare `SessionTranscript` (today's behaviour) MUST now fail. Without this,
   nothing stops a future edit reintroducing §1.5.
5. **Byte-preservation.** A `deviceSigned.nameSpaces` whose re-encoding would
   differ from its received bytes MUST still verify — pinning hazard 1 of §2.2.
6. **Envelope rejection.** The bespoke object shape, a bare non-string, a
   multi-document response and `status != 0` each produce the expected typed
   structural error.

---

## 6. Documentation and conformance updates

- **New:** `docs/specs/iso-18013-5-device-auth.md` — a reference stub under root
  `AGENTS.md` §4.4's external-reference rule. Records the document's exact title
  and revision, why no copy is in-tree (paid standard, redistribution
  forbidden), where a reader obtains one, and the interface facts foundry relies
  on **restated rather than quoted**, plus the two derivation sources at their
  pinned commits. A stub does not acquire the precedence of a standards-track
  specification.
- **Row added** to §4.4's governing-documents table in the root `AGENTS.md`.
- `crates/foundry-mdoc/AGENTS.md`: rewrite Gotchas divergence #1; **delete
  divergence #2**, which is stale — the `SessionTranscript` / `OpenID4VPHandover`
  work landed and VP-0229…VP-0246 are all `conforming`, pinned byte-for-byte
  against published vectors. Update the module map and public-entry-point list.
- `crates/foundry-verifier/AGENTS.md`: replace the per-format payload description
  of the bespoke mdoc shape.
- `docs/conformance/openid4vc-conformance.md`:
  - `HAIP-0070` → `conforming`, citing the new fixture and vector tests.
  - **New `GAP-VCI-xx`** for the deferred issuance leg (§7).
  - `VCI-0176` evidence corrected: it justifies the base64url *encoding* only,
    not the CBOR *structure*.

---

## 7. Deferred: the issuance leg

`build_mdoc` emits `{version, documents: [{docType, issuerSigned}]}` — a
`DeviceResponse`-shaped wrapper minus `status` and `deviceSigned` — and
`handle_credential_request` base64url-encodes that whole envelope as the
OpenID4VCI `credential`. OpenID4VCI L2249 requires the `credential` claim to be
the base64url-encoded CBOR **`IssuerSigned`** structure: the inner object only.

Deliberately out of scope here (§3 decision 1). Recorded as a new gap so it is carried
honestly rather than silently. Consequence to be aware of: a foundry-issued mdoc
is not loadable as an mdoc credential by a conformant wallet, so mdoc issuance
and mdoc presentation cannot yet be exercised as one end-to-end flow against
third-party software.

---

## 8. Deferred: trust and expiry policy

The captured credential fails issuer validation here for two independent reasons
that this design does not address:

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
foundry's own PKI, which depends on §7. Neither belongs in a CBOR-parsing change.

---

## 9. Open item: capturing the golden fixture

Test 2 in §5 needs the exact `SessionTranscript` of a live transaction. The
transcript is derived from `tx.nonce`, the Origin and the response-encryption key
thumbprint; the original transaction has aged out of storage
(`transaction_ttl_secs: 600`), and neither the nonce nor the thumbprint was
logged.

Required, in order:

1. Add a permanent diagnostic to the mdoc branch of `verify.rs`: the candidate
   `SessionTranscript` hex, gated on **both** `foundry_core::obs::sensitive_enabled()`
   **and** `trace` level, per root `AGENTS.md` §4.5. This matches the existing
   treatment of the decrypted response payload and is independently useful for
   interop debugging.
2. One fresh `av` run against the wallet, capturing the transcript hex alongside
   the `DeviceResponse`.
3. Commit both as a fixture with provenance recorded: wallet, date, docType,
   and the fact that its issuer chain is expired and unanchored by design.

Implementation is **not** blocked on this — §2 pins the construction from two
independent sources, and tests 1 and 3-6 are writable immediately. Only the
interop *proof* is blocked. If the capture never happens, this change ships with
cross-implementation vectors and synthetic round trips but **no real-wallet
evidence**, which is a materially weaker position and must be stated as such in
the change record.

---

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| Hand-rolled construction is subtly wrong; no live oracle. | Pinned vectors from two independent implementations (§5 test 1) plus the interop fixture (§5 test 2). |
| `ciborium` re-encoding perturbs `deviceSigned.nameSpaces`. | Borrowed views in `DeviceResponse<'a>`; explicit byte-preservation test (§5 test 5). |
| Transcript decode/re-encode drift. | `session_transcript_value` returns the `Value` directly; no round trip. Existing published-vector tests continue to pin the byte form. |
| Migrating ~8-10 mdoc tests hides a real regression behind churn. | Anti-regression test (§5 test 4) asserts the *old* construction now fails, so the migration cannot silently preserve it. |
| ISO structure derived from implementations, not the standard. | Two independent sources agreeing, both pinned; recorded as a §4.4 reference stub, explicitly not granted specification precedence. |
