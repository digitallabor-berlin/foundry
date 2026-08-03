# GAP-VP-06 — Build the Spec-Defined mdoc `SessionTranscript` Handover

> Migrated from `docs/superpowers/specs/2026-08-02-gap-vp-06-session-transcript-spec.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Date:** 2026-08-02
**Status:** approved

## Problem

`foundry_mdoc::types::serialize_session_transcript`
(`crates/foundry-mdoc/src/types.rs:50`) is the **only** `SessionTranscript`
builder in this workspace. It emits:

```
[null, null, [client_id, response_uri, nonce]]        # 3-element ad-hoc array
[null, null, ["https://localhost:8443", nonce]]       # 2-element fallback
```

Its own doc comment already concedes the defect: *"TODO(interop): simplified
handover; not the hashed OID4VPHandover from 18013-7."*

OpenID4VP 1.0 requires the third element to be one of two specific CBOR
structures, selected by invocation method:

```cddl
OpenID4VPHandover = [ "OpenID4VPHandover", bstr ]           ; redirects   (L2833-L2873)
OpenID4VPDCAPIHandover = [ "OpenID4VPDCAPIHandover", bstr ] ; DC API      (L2963-L2999)
```

where the second element is the SHA-256 hash of the CBOR-encoded
`…HandoverInfo` array, **not** the raw parameter values.

`SessionTranscript` is precisely the byte string a Device Signature — mdoc's
holder-binding proof — is computed over. A conformant wallet signs the
spec-correct transcript; foundry recomputes a *different*, non-conformant one
to check against; the signature can never validate. **mdoc presentation is
therefore broken against every wallet except foundry's own** — which happens
to compute the identical wrong transcript. This is one of only two credential
formats the workspace supports, hence Critical.

19 clauses cite this gap: VP-0209, VP-0229, VP-0232–VP-0240 (redirects),
VP-0243–VP-0250 (DC API).

### Why this is more tractable than "Critical" suggests

Three facts, each verified before this spec was written:

1. **`foundry-wallet` contains no mdoc presentation code at all** (`grep` for
   `device_signature|DeviceAuth|mso_mdoc` in `crates/foundry-wallet/src/`
   returns nothing). There is no debug-wallet signing path to keep in sync.
   Blast radius is 3 in-repo `serialize_session_transcript` call sites —
   `foundry-mdoc/src/verifier.rs:287` (production),
   `foundry-mdoc/src/verifier.rs:411` (inline test), and
   `crates/foundry/tests/wallet_verification.rs:1031` (a test acting as the
   wallet) — plus 4 `verify_mdoc` call sites whose signature must adapt:
   `foundry-mdoc/tests/mdoc_tests.rs:67` and `:98`,
   `foundry-mdoc/src/verifier.rs:441` (inline test), and
   `foundry-verifier/src/verify.rs:464` (the sole production caller).
2. **Every input the spec demands is already on `VerificationTransaction`** —
   `transport`, `response_mode`, and `ephem_public_jwk` — and the 2026-08-01
   Tier 1 run added `verifier.dc_api_expected_origins`, which supplies the
   Origin.
3. **The spec ships complete byte-level known-answer vectors** for both
   variants (L2885-L2950, L3010-L3080), plus the input JWK behind the
   thumbprint. This is implement-against-KAT, not implement-and-hope.

### KAT interpretation, confirmed empirically before any code

The phrase *"the sha-256 hash of the bytes of `OpenID4VPHandoverInfo` when
encoded as CBOR"* is ambiguous between hashing the plain CBOR array and
hashing a tag-24 / `bstr`-wrapped embedding. Resolved against the spec's own
vectors rather than by reading:

| Check | Result |
|---|---|
| `sha256(plain CBOR of redirects info array)` == hash embedded in `OpenID4VPHandover` | ✅ `048bc053…38ac` |
| `sha256(plain CBOR of DC API info array)` == hash embedded in `OpenID4VPDCAPIHandover` | ✅ `fbece366…761a` |
| `83 f6 f6 ‖ <handover>` == published `SessionTranscript` hex (both variants) | ✅ |
| RFC 7638 thumbprint of the spec's example JWK == the `bstr` in both info arrays | ✅ `4283ec92…9047` |

**Conclusion: no tag 24, no `bstr` wrapper — hash the plain CBOR encoding of
the info array.** The fourth row additionally proves the canonicalization
already implemented in `foundry_core::obs::thumbprint` is byte-identical to
what the handover needs.

## Goal / Non-Goals

### Goal

Replace the ad-hoc handover with the two spec-defined structures, selected by
transport; close GAP-VP-06 and flip all 19 citing clauses; keep
`conformance_report.rs`'s 11 consistency checks green at every commit.

### Non-Goals

- **Proximity / ISO 18013-5 native flows.** `DeviceEngagementBytes` and
  `EReaderKeyBytes` stay `null` — OpenID4VP mandates exactly that for both
  invocation methods. Non-null variants are not implemented and are not
  becoming implemented here.
- **MAC-based `deviceMac` DeviceAuth.** foundry verifies `deviceSignature`
  only; that is unchanged and independently out of scope.
- **`redirect_uri` response modes.** VP-0238 requires the fourth element to be
  "either the `redirect_uri` or the `response_uri` … depending on which is
  present". foundry only ever issues `response_uri`, so the `response_uri`
  branch fully satisfies the clause for every mode foundry supports. A
  `redirect_uri` mode would need its own work, and foundry has none.
- **GAP-VCI-14** (Client Attestation PoP) and the remaining 20 open gaps.
- **`status_index.rs`'s `TODO(concurrency)`** — still pre-existing, still out
  of scope.
- **The MSO tag-24 embedding TODO.** `types.rs:5` carries a second, unrelated
  interop concession: *"TODO(interop): payload is not tag-24 embedded-CBOR
  wrapped"* on `MobileSecurityObject`. Noticed while reading the file; it is a
  distinct defect in a distinct structure (the MSO, not the
  `SessionTranscript`), is not cited by any of GAP-VP-06's 19 clauses, and is
  not fixed here. Recorded so it is not mistaken for something this change
  addressed.

## Approach

Four decisions, all approved at interview.

### 1. Both handover variants in one change

They share one shape (`["<literal>", sha256(cbor(info))]`), differ only in
literal and info-array contents, and the spec ships KATs for both. Splitting
would double the report bookkeeping while reducing risk not at all.

### 2. Move transcript construction out of `verify_mdoc`

`foundry-mdoc` gets a pure builder; `foundry-verifier` — the only layer that
knows `transport`, `response_mode`, and the Origin — decides which handover
applies and calls it.

### 3. Fail-closed thumbprint bytes in `foundry-core`

`obs::thumbprint()` returns a base64url **String** and **never errors**
(yielding `INVALID_JWK_THUMBPRINT` on malformed input). That is right for
logging and wrong here: the handover needs a raw 32-byte `bstr`, and a
malformed key must abort verification, not silently hash the string
`"<invalid-jwk>"` into a transcript.

### 4. Try each configured Origin

The Origin sits *inside* the hash, so unlike the KB-JWT `aud` (which Task 5 of
the Tier 1 run matches against a list) the verifier cannot compare — it must
**pick** before it can verify.

### Rejected alternatives

| Rejected | Why |
|---|---|
| Reimplement RFC 7638 inside `foundry-mdoc` | Duplicates canonicalization already in `foundry-core`, and would need its own KAT to stay trustworthy. |
| Decode `obs::thumbprint()`'s base64url output back to bytes | `INVALID_JWK_THUMBPRINT` (`"<invalid-jwk>"`) is not valid base64url of a 32-byte digest, but a decoder would fail *late* and opaquely rather than at the malformed key. Fail-soft plumbed into a crypto path. |
| Keep construction inside `verify_mdoc`, pass a params enum | Hides the multi-Origin retry loop inside the mdoc crate, which has no business knowing about OpenID4VP transports. |
| Require exactly one `dc_api_expected_origins` entry for mdoc | Gratuitously inconsistent with Task 5, which already accepts a list for the SD-JWT VC audience. |
| Keep the `https://localhost:8443` fallback branch | The spec defines no such variant; it exists only to paper over absent parameters. Removing it makes the parameters non-optional and the illegal state unrepresentable. |

## Design

### 1. `foundry-core` — `obs::thumbprint_bytes`

```rust
/// RFC 7638 JWK thumbprint as raw SHA-256 bytes, fail-closed.
///
/// Unlike [`thumbprint`], which is a logging helper that degrades to
/// [`INVALID_JWK_THUMBPRINT`], this returns `Err` for any JWK it cannot
/// canonicalise — callers embed the result in signed/hashed structures where
/// a placeholder would be a correctness defect.
pub fn thumbprint_bytes(jwk: &serde_json::Value) -> Result<[u8; 32], String>;
```

`thumbprint()` is refactored to call it and map `Err` → `INVALID_JWK_THUMBPRINT`,
so there is exactly **one** canonicalization implementation. Its existing
RFC 7638 §3.1 known-answer test keeps covering both.

### 2. `foundry-mdoc` — spec-shaped builder

```rust
pub enum SessionTranscriptParams {
    /// OpenID4VP 1.0 "Invocation via Redirects" (L2829-L2873)
    Redirect { client_id: String, nonce: String,
               jwk_thumbprint: Option<[u8; 32]>, response_uri: String },
    /// OpenID4VP 1.0 "Invocation via the Digital Credentials API" (L2959-L2999)
    DcApi   { origin: String, nonce: String,
              jwk_thumbprint: Option<[u8; 32]> },
}

pub fn build_session_transcript(
    params: &SessionTranscriptParams,
) -> Result<Vec<u8>, String>;
```

Emits `[null, null, Handover]`. `jwk_thumbprint: None` encodes CBOR `null` as
the third info element, per L2870 (redirects) / L2999 (DC API).
`serialize_session_transcript` and its `https://localhost:8443` fallback are
deleted.

### 3. `foundry-mdoc` — `verify_mdoc` takes the transcript

```rust
pub fn verify_mdoc(
    mdoc_bytes: &[u8],
    trust_store: &TrustStore,
    session_transcript: &[u8],          // was: client_id, response_uri, nonce
    device_signature_cose_sign1_bytes: &[u8],
    now_unix: u64,
) -> Result<MdocVerificationResult, FormatError>;
```

Three transcript parameters collapse to one. The function no longer builds
anything; it verifies against bytes it is handed.

### 4. `foundry-verifier` — select the handover, try each Origin

In `do_verify_vp_response`'s `MsoMdoc` branch:

- **Thumbprint** — `Some(thumbprint_bytes(&tx.ephem_public_jwk)?)` when the
  response mode is encrypted, else `None`:

  | `tx.response_mode` | third element |
  |---|---|
  | `dc_api.jwt` | thumbprint (L2999) |
  | `dc_api` | `null` (L2999) |
  | `direct_post.jwt` | thumbprint (L2870) |
  | `direct_post` | `null` (L2870) |

  These four are the complete set present in the codebase (verified by grep);
  an unrecognised mode is a typed error, not a silent `None`.

- **Candidates** — for `tx.transport == "dc_api"`, one `DcApi` params per
  configured `dc_api_expected_origins` entry (**bare, not `origin:`-prefixed**
  — L2997 forbids the prefix), falling back to the `public_base_url`-derived
  origin when unconfigured. Every other transport yields exactly one
  `Redirect` candidate using the existing `x509_san_dns:<host>` client_id and
  `{base_url}/vp/response/{tx.id}` response_uri.

- **Selection** — call `verify_mdoc` per candidate; accept the first that
  verifies; if all fail, surface the last error. With the usual single Origin
  this is one call.

### 5. Report bookkeeping

Delete the GAP-VP-06 register row; flip VP-0229, VP-0232–VP-0240,
VP-0243–VP-0250 to `conforming`; recount the OpenID4VP Summary row.

**VP-0209 requires judgement, not a mechanical flip.** Its recorded evidence
splits the clause: the SD-JWT VC half became conforming in the Tier 1 run
(VP-0265), while the mdoc half was left `gap` *because* the DC API
`SessionTranscript` binding was non-conformant. Closing that binding should
make the clause conforming as a whole — but that is a claim to **re-verify
against the code at bookkeeping time**, not to assume here. Note also that
VP-0209's binding for mdoc is the handover's bare `origin` element, which the
spec explicitly forbids prefixing — the `origin:` prefix in VP-0209's text
governs the KB-JWT `aud`, a different mechanism. The two must not be conflated.

## Global Constraints

- No `.unwrap()`/`.expect()`/`panic!`/`unreachable!()` outside `#[cfg(test)]`
  in `foundry-mdoc`, `foundry-verifier`, or `foundry/src` (root AGENTS.md §4.1).
- `verified` stays `checks.iter().all(|c| c.passed)`; no new hardcoded verdict
  (§4.2). The `mdoc_issuer_auth_and_device_signature` check must not report
  `passed: true` for a transcript that never verified (§4.2, and
  foundry-mdoc's own binding invariant).
- Structural/crypto failure → 400; policy failure → 200 with `verified: false`
  (§4.3). A transcript mismatch is a **crypto** failure.
- Every new `#[tracing::instrument]` carries `skip_all`; no JWK, transcript
  bytes, or nonce logged above `debug`-plus-`sensitive_enabled()` (§4.5).
- Cite the spec section in every new protocol-facing comment (§4.4).
- Dependency layering unchanged: `foundry-core` ← `foundry-mdoc` ←
  `foundry-verifier`. No new sideways or upward edge (§3).
- OpenAPI specs must remain byte-identical — no endpoint shape changes here.

## Testing Strategy

**Known-answer tests are the backbone.** The spec's published vectors are
transcribed verbatim and asserted byte-for-byte:

| Test | Asserts |
|---|---|
| `foundry-core` | `thumbprint_bytes` of the spec's example JWK == `4283ec92…9047` |
| `foundry-core` | `thumbprint_bytes` returns `Err` where `thumbprint` returns the placeholder |
| `foundry-mdoc` | `build_session_transcript(Redirect{…})` == published redirects `SessionTranscript` hex |
| `foundry-mdoc` | `build_session_transcript(DcApi{…})` == published DC API `SessionTranscript` hex |
| `foundry-mdoc` | `jwk_thumbprint: None` encodes CBOR `null` as the third info element |
| `foundry-verifier` | un-`#[ignore]`d `gap_vp_06_…` now passes |
| `foundry-verifier` | a device signature over the spec-correct transcript verifies; over the old ad-hoc transcript it does **not** |
| `foundry-verifier` | second configured Origin verifies (multi-Origin retry) |
| `foundry-verifier` | `dc_api` vs `dc_api.jwt` select `null` vs thumbprint |
| `crates/foundry` | E2E `wallet_verification.rs` mdoc round-trip still green |

Rule carried over from the Tier 1 run: **existing gap tests are un-`#[ignore]`d,
never rewritten.** Any exception must be declared in the plan before it is
taken, with its reason.

Gates, all four required per task:

```
cargo test --workspace
cargo test --workspace --no-fail-fast -- --ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

## Open Questions

None blocking. One item deferred to bookkeeping-time verification rather than
decided in advance: **whether VP-0209 flips to `conforming`** (see Design §5).
It is recorded as a judgement call so that the implementer re-reads the code
instead of trusting this document.
