# Unblocking the mdoc `DeviceAuth` golden fixture — 2026-08-19

**Branch:** `feat/2026-08-19-mdoc-deviceauth-golden-fixture`
**Design:** [`../specs/2026-08-19-mdoc-deviceresponse-verification-design.md`](../specs/2026-08-19-mdoc-deviceresponse-verification-design.md) §9

## What was blocked

§5 test 4 of the design — the first test in this workspace that would prove mdoc
*interoperability* rather than self-consistency — needs a real wallet's
`DeviceResponse` together with the exact `SessionTranscript` its Device Signature
covers. §9 listed three steps to get one: add a permanent transcript diagnostic,
do one fresh capture, commit the pair.

Step 1 had landed. The capture still could not be taken, for a reason §9 did not
anticipate: the emission sat **inside** the candidate retry loop, which
`do_verify_vp_response` reaches only after

```rust
let issuer = verify_issuer_signed(&resp, ctx.trust_store, ctx.now_unix)?;
```

The wallet worth capturing (`eu.europa.ec.av.1`, `[Test] mDL Reference
Implementation DS`) fails exactly there — unanchored test PKI, DS certificate
expired 2025-09-17, both deferred by design §8. A live run on 2026-08-19T09:35Z
confirmed it: the `decrypted response payload` trace fired, then
`no configured trust anchor matches the certificate chain`, and **no transcript
record was ever emitted**. The diagnostic was suppressed by precisely the verdict
it exists to explain.

## What changed

- **`crates/foundry-verifier/src/verify.rs`** — the sensitive-gated transcript
  emission moves out of the candidate loop to immediately after `candidates` is
  built and **before** `verify_issuer_signed`. One record per candidate; the
  double gate (`obs::sensitive_enabled()` **and** `trace`, root `AGENTS.md` §4.5)
  is unchanged, as is every verification behaviour. Verification logic in the
  loop is untouched.
- **Two inline tests, same file.**
  `the_session_transcript_diagnostic_survives_an_issuer_trust_failure` drives an
  mdoc presentation signed under a CA the config does not trust, asserts the
  anchor rejection, and asserts the transcript was logged anyway. Verified
  genuinely red before the fix, with the failure message stating the diagnosis.
  `..._stays_locked_by_default` is the negative control: flag off ⇒ no
  transcript, plus a non-vacuity assertion that events were captured at all.
  A ~35-line `FieldCapture` layer and a `tracing-subscriber` **dev**-dependency
  support them; `crates/foundry`'s `logging_redaction.rs` keeps ownership of the
  redaction harness proper.
- **`crates/foundry-verifier/AGENTS.md`** — the existing transcript gotcha now
  records the ordering requirement and names both tests.
- **`crates/foundry-mdoc/tests/fixtures/README.md`** — an operator-facing capture
  recipe: the exact invocation, the two log records and fields to lift, the
  same-`tx_id` requirement, and the one-record-per-Origin caveat.

## The capture, and the interop proof it unblocked

Design §9 steps 2 and 3 followed immediately, in the same session: one fresh `av`
run (transaction `v_eca7bc0cbc514ee9aa61b2760e11182b`, `dc_api`) produced the
`DeviceResponse` **and** — now that the diagnostic fires before the trust check —
both candidate `SessionTranscript`s, one per configured Origin.

The new `DeviceResponse` proved byte-identical to the committed fixture **except**
its 64-byte device signature: same credential, same MSO, same device key, a
second presentation of the same attestation. It therefore *replaced*
`av_device_response.b64` rather than sitting beside it, and two hex fixtures joined
it: `av_session_transcript.hex` (the one the wallet signed) and
`av_session_transcript_other_origin.hex` (the same run's other candidate).

- **`crates/foundry-mdoc/tests/real_presentation.rs`** — design §5 test 4:
  `the_real_device_signature_verifies_over_the_captured_session_transcript`. A
  real third-party wallet's `DeviceSignature` verifies against foundry's
  `DeviceAuthentication` assembly. PKI-free, via a `device_key_coords()` helper
  reading the holder coordinates out of the MSO's `deviceKey` COSE_Key, so the
  unanchored expired chain of §8 is irrelevant.
  `the_other_origins_candidate_transcript_does_not_verify` is its indispensable
  companion: without it the positive test is satisfiable by an assembly that
  ignores the transcript entirely — precisely the defect §1.5 recorded.

**`DeviceAuthentication` is now proven, not derived.** A signature check admits no
partial credit, so one passing assertion confirms the tag-24 wrapping, the bare
(not tag-24) transcript splice, the `docType`, the byte-preserved
`DeviceNameSpacesBytes`, the detached payload in the `Sig_structure` and the empty
`external_aad` — all at once, against an implementation foundry did not write.
Updated accordingly:
[`docs/specs/iso-18013-5-device-auth.md`](../../specs/iso-18013-5-device-auth.md)
(provenance section and the mdoc-authentication heading),
`crates/foundry-mdoc/AGENTS.md` (the DERIVED gotcha, and a new Interop entry in
Tests), the fixtures README, and design §5 test 4 / §9 / the §10 risk row, which
is retired rather than deleted.

Three conformance rows gain real-wallet evidence — **VP-0177** (device signature
bound to audience and nonce), **VP-0246** (the Origin element, now proven by the
two-candidate selection) and **VP-0250** (CBOR `null` third element for
`dc_api`). All three were already `conforming`; this widens evidence from
foundry's own round trip to a third-party wallet. No verdict flips, no gap closes.

## What is still open

Trust and expiry policy stay deferred per design §8: the capture's chain roots at
`[Test] mDL Reference Implementation IACA` and its DS certificate expired
2025-09-17, so a live `av` run still — correctly — returns HTTP 400. Making it
verify end to end is a security-policy decision, not a format fix. The OpenID4VCI
credential envelope stays open as `GAP-VCI-16` (design §7), so mdoc issuance and
mdoc presentation remain un-exercisable as one flow against third-party software.

## Gate

Run twice — once for the diagnostic hoist, once after the fixture work.
`cargo fmt`; `cargo nextest run --workspace --no-fail-fast --status-level fail` —
993 passed then **995 tests run: 995 passed, 13 skipped**; `cargo clippy
--workspace --all-targets -- -D warnings` — clean both times. §5.2, as this is
merged rather than left on a branch: `cargo nextest run -p foundry --test
e2e_full_flow --run-ignored ignored-only` — 2 tests run: 2 passed, 0 skipped.
