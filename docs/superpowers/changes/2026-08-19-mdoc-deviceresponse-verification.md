# Conformant mdoc `DeviceResponse` verification

**Date:** 2026-08-19
**Design:** [`../specs/2026-08-19-mdoc-deviceresponse-verification-design.md`](../specs/2026-08-19-mdoc-deviceresponse-verification-design.md)
**Plan:** [`../plans/2026-08-19-mdoc-deviceresponse-verification-plan.md`](../plans/2026-08-19-mdoc-deviceresponse-verification-plan.md)

## The symptom

A real wallet presenting an EU Age Verification attestation (`eu.europa.ec.av.1`,
`mso_mdoc`) over the OpenID4VP Digital Credentials API was rejected with
HTTP 400:

```text
verification failed: credential query 'av' declares format mso_mdoc,
so its presentation must be an object, got a string
```

The wallet was right and foundry was wrong. OpenID4VP 1.0 L2825–L2828 requires
that entry to be the base64url of an ISO/IEC 18013-5 `DeviceResponse` — a string.

## Root cause: four independently fatal defects

Fixing the error message's immediate cause would have moved the failure one step
along, four times. Each of these alone prevents a real presentation from
verifying:

1. **The `vp_token` envelope.** foundry required
   `{mdoc, device_signature}` — a shape it invented. Grep found **no production
   producer**: only foundry's own tests ever built it.
2. **The DeviceAuth signed payload.** foundry verified the Device Signature over
   the bare `SessionTranscript`. The payload is `DeviceAuthenticationBytes`.
   (`external_aad` was already correct — the empty byte string — and an earlier
   claim that it was wrong was retracted.)
3. **The `issuerAuth` payload** is `#6.24(bstr .cbor MSO)`. foundry parsed it
   bare and failed with `invalid type: bytes, expected map`.
4. **`IssuerSignedItem`s are tag-24 wrapped**, and `valueDigests` commits to the
   **full tagged encoding**. foundry called `as_bytes()` — `None` for a tagged
   value — and `continue`d.

Defect 4 was the worst, because it **failed quietly**. Every disclosed element
was skipped, the credential "verified" with zero claims, and the transaction then
failed `dcql_match` — presenting as an HTTP 200 policy verdict about the wallet
rather than a bug in foundry.

## Two retracted suspicions

The design doc initially claimed six defects. A probe run against the real
capture — rather than more reading — refuted two, and §1.7 records them:

- **`deviceKeyInfo.deviceKey` needed no change.** `cbor_value_to_bytes` is
  `ciborium::into_writer`, which *re-encodes* any `Value`, so the COSE_Key map
  became COSE_Key bytes and `CoseKey::from_slice` accepted it. The builder's
  inverse helper is named `cbor_to_value_bytes` and *decodes* — the two
  near-identical names invited exactly this misreading.
- **tag-0 `tdate` values already parsed.** `ciborium`'s typed deserializers carry
  `Header::Tag(..) => continue`, silently skipping tags.

Both had been inferred from reading the source. The lesson is recorded as its own
risk row in the design doc: *defects inferred rather than executed are themselves
a hazard.* The second finding did survive in weaker form — foundry **emitted**
untagged text, an issuance-conformance defect, and did not model `validFrom` at
all.

## What changed

**`foundry-mdoc`**

- Shared `tag24_encode` / `tag24_unwrap`, used by builder and verifier so the
  digest basis cannot drift. `tag24_unwrap` **errors** on every non-tag-24 shape;
  returning `None` is what made defect 4 invisible.
- `IssuerSignedItem`s are emitted and required tag-24 wrapped, digested over the
  full tagged encoding.
- The MSO travels as `MobileSecurityObjectBytes`; the IssuerAuth signature is
  computed over the wrapped bytes, and unwrapping happens only to parse.
- `ValidityInfo` members are `ciborium::tag::Required<String, 0>` — strict in
  both directions — and `validFrom` is now modelled. The validity window is
  `validFrom`..`validUntil`; `signed` does not bound validity.
- The Device Signature is verified over `DeviceAuthenticationBytes`.
- `verify_mdoc` split into `decode_device_response` → `parse_device_response` →
  `verify_issuer_signed` → `verify_device_auth`.
- `build_device_response` added, so tests build what a wallet sends.
- All three `TODO(interop)` notes in `types.rs` are closed.

**`foundry-verifier`**

- `SelectedPresentation::MsoMdoc` collapses to one `device_response_b64`.
- The DC API Origin loop runs the issuer half **once** and retries only the
  Device Signature. Previously each candidate Origin re-ran chain validation, MSO
  validity and digest matching to retry a single signature.
- The candidate `SessionTranscript` is logged at `trace`, gated on
  `obs::sensitive_enabled()` — it commits to `tx.nonce`.

**Docs:** `docs/specs/iso-18013-5-device-auth.md` (reference stub, §4.4
external-reference rule), root `AGENTS.md` §4.4 row, `HAIP-0070` → conforming,
`VCI-0176` → gap, new `GAP-VCI-16`, plus corrections to three stale sections of
`crates/foundry-mdoc/AGENTS.md` and one of `crates/foundry-verifier/AGENTS.md`.

## Evidence, and its limits

`cargo nextest run --workspace`: **988 passed, 13 skipped**. Clippy clean.
E2E (`--run-ignored ignored-only`): passed.

**The interop proof is partial, and this is the most important thing in this
record.**

- **The `IssuerSigned` half is proven.** `crates/foundry-mdoc/tests/real_presentation.rs`
  checks foundry against the captured `DeviceResponse` — bytes foundry did not
  produce. The tag-24 MSO unwraps, the `tdate` values including `validFrom` parse
  to their exact instants, and `age_over_18`'s digest matches `valueDigests` over
  the full tag-24 encoding while **not** matching over the inner CBOR.
- **The `DeviceAuth` half is NOT proven against a real wallet.** Its structure
  rests on two independent implementations (multipaz, isomdl at pinned commits)
  agreeing byte-for-byte. That is strong evidence, not proof: both could share a
  misreading. Tests assert the structure element by element, and **the pinned
  independent byte vector the plan called for was not produced** — generating it
  needs an offline run of one of those implementations. No test in this workspace
  verifies a real wallet's Device Signature.
- **The golden interop fixture remains blocked** on one fresh `av` run. The
  original transaction aged out (`transaction_ttl_secs: 600`) and its nonce was
  never logged, so the transcript the wallet signed cannot be reconstructed. The
  gated trace added here is what makes the next attempt capturable.

Each fix was additionally checked for **discrimination**, not just agreement: the
change was reverted and the new tests confirmed to fail, then restored. All did.
Without this, a test can pass merely because it was written against the same
wrong assumption as the code.

## Deliberately not done

- **The OpenID4VCI credential envelope** (`GAP-VCI-16`). `build_mdoc` returns a
  `DeviceResponse`-shaped wrapper where L2249 wants a bare `IssuerSigned`. The
  CBOR *inside* is now conformant, so the remaining fault is the envelope alone.
- **Trust and expiry policy** (design doc §8). Unchanged, deliberately.
- **`DeviceMac`**, multi-document responses, non-ES256 device algorithms — all
  refused with typed errors rather than implemented incorrectly.

## Expected operational outcome

The `av` query **stops failing on the envelope and starts failing on issuer
trust.** That is not a remaining bug: the capture's chain is the OpenWallet
Foundation Labs `identity-credential` test PKI, which is not a configured
`trust_anchor`, and its DS certificate expired 2025-09-17. Rejecting it is the
truthful verdict. Anyone reading a trust failure here as "the fix didn't work"
should check the anchor set first.

## Plan deviations worth knowing

Three, all corrections to the plan rather than to the code:

1. **Task 3 asserted the tag-24 structural check fires *before* signature
   verification.** It does not, and should not: `verify_issuer_signed`
   authenticates payload bytes before parsing them, because parsing
   unauthenticated CBOR is the thing to avoid. The tamper helper re-signs, which
   also makes it the realistic case — an old-format credential, not a corrupt
   one.
2. **Task 4's validity-window test could not work as written.** It verified at
   `now=999`, but chain validation runs first and the test PKI's certificate is
   not valid then, so it would have failed on the chain and never reached the
   bound. It also had no discriminating case, since the builder emits
   `validFrom == signed`. Replaced with a tamper-and-re-sign that pushes
   `validFrom` past `now` and asserts both directions.
3. **One assertion the plan did not ask for.** Both the digest check and
   `DeviceAuthentication` assembly re-encode `Value`s decoded from the wire
   rather than slicing the original buffer — sound only while the wallet's CBOR
   is canonical. That assumption was load-bearing and unstated;
   `re_encoding_the_capture_is_byte_identical` now fails loudly instead of as
   inexplicably mismatching digests.
