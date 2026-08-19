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

## What is still open

Design §9 steps 2 and 3. This change makes the capture *possible*; it does not
take it. §5 test 4 remains unwritten, the `DeviceAuthentication` facts in
[`docs/specs/iso-18013-5-device-auth.md`](../../specs/iso-18013-5-device-auth.md)
remain **derived** rather than **proven**, and `HAIP-0070`'s evidence is
unchanged. Trust and expiry policy stay deferred per design §8 — the fixture test
will be PKI-free, so it does not depend on them.

## Gate

`cargo fmt`; `cargo nextest run --workspace --no-fail-fast --status-level fail` —
993 tests run: 993 passed, 13 skipped; `cargo clippy --workspace --all-targets --
-D warnings` — clean. §5.2, as this is merged rather than left on a branch:
`cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only` —
2 tests run: 2 passed, 0 skipped.
