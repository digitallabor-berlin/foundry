# GAP-VP-06 mdoc `SessionTranscript` Handover — Implementation Plan

**Spec:** [`../specs/2026-08-02-gap-vp-06-session-transcript-spec.md`](../specs/2026-08-02-gap-vp-06-session-transcript-spec.md)
**Branch:** `superlight/2026-08-02-gap-vp-06-session-transcript`
**Date:** 2026-08-02

## Ordering Rationale

Smallest-first, dependency-ordered — the ordering that landed all five Tier 1
tasks cleanly. Each task is independently green on all four gates:

1. **Task 1** touches one leaf crate with no callers to break.
2. **Task 2** is purely additive; the old builder still serves its callers.
3. **Task 3** is the breaking change, forced atomic by the signature.
4. **Task 4** completes behaviour **and carries every report edit**, because
   `conformance_report.rs` enforces bidirectional consistency: an `#[ignore]`
   removal and its clause verdict flip must be in the *same commit*.
5. **Task 5** verifies the whole.

## File Structure

| File | Task | Change |
|---|---|---|
| `crates/foundry-core/src/obs.rs` | 1 | add `thumbprint_bytes`; `thumbprint` delegates |
| `crates/foundry-mdoc/src/types.rs` | 2, 3 | add `SessionTranscriptParams` + `build_session_transcript`; delete `serialize_session_transcript` |
| `crates/foundry-mdoc/src/verifier.rs` | 3 | `verify_mdoc` takes `session_transcript: &[u8]`; inline test adapts |
| `crates/foundry-mdoc/tests/mdoc_tests.rs` | 3 | 2 call sites adapt |
| `crates/foundry-verifier/src/verify.rs` | 3, 4 | handover selection; multi-Origin retry; new tests |
| `crates/foundry-verifier/tests/conformance_vp.rs` | 3, 4 | gap test constructor adapts (T3); `#[ignore]` removed (T4) |
| `crates/foundry/tests/wallet_verification.rs` | 3 | test-wallet builds the spec-correct transcript |
| `docs/conformance/openid4vc-conformance.md` | 4 | 19 clause flips + register row deletion + Summary recount |

## Declared Exception to "Never Rewrite Gap Tests"

`gap_vp_06_…` (`conformance_vp.rs:572`) calls
`foundry_mdoc::types::serialize_session_transcript`, which Task 3 deletes. Its
**constructor call must change** or the crate stops compiling.

- **Permitted:** swapping the call to `build_session_transcript(&Redirect{…})`
  with the same four input values.
- **Forbidden:** touching the assertion, the needle (`b"OpenID4VPHandover"`),
  the doc comment's description of the defect, or the test name.

This is the same category as the Tier 1 run's `handle_token_request`
adaptation: a mechanical consequence of a signature change, not a weakening of
the test. Verify by diffing the test body and confirming only the constructor
lines moved.

---

### Task 1: `foundry-core` — fail-closed thumbprint bytes

**Files:** `crates/foundry-core/src/obs.rs`

- [x] Add `pub fn thumbprint_bytes(jwk: &serde_json::Value) -> Result<[u8; 32], String>`
      carrying the existing RFC 7638 §3.2 canonicalization (required members
      only, lexicographic via `BTreeMap`, no whitespace).
- [x] Refactor `thumbprint()` to delegate, mapping `Err` → `INVALID_JWK_THUMBPRINT`.
      **One** canonicalization implementation must remain.
- [x] Test: `thumbprint_bytes` of the OpenID4VP example JWK (spec L2878-L2886)
      == `4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047`.
- [x] Test: `thumbprint_bytes` returns `Err` for each input where `thumbprint`
      returns the placeholder (non-object, missing `kty`, unknown `kty`,
      missing required member) — asserted as a *paired* contract in one test.
- [x] Confirm the pre-existing `thumbprint_matches_rfc7638_vector` and
      `thumbprint_never_contains_key_material` tests still pass **unmodified**
      — 15/15 `obs` tests green, no pre-existing test edited.
- [x] Gates ×4. One `cargo fmt` fixup applied and re-verified.

**Landed:** `b6835c8`. `--ignored` baseline re-confirmed unchanged at 23
failing gap tests + 1 passing E2E (`full_flow_issue_verify_revoke_reverify`),
as expected for a purely additive change.

**Done when:** two independent KATs (RFC 7638 §3.1 and OpenID4VP's example JWK)
pass against a single canonicalization.

---

### Task 2: `foundry-mdoc` — spec-shaped transcript builder (additive)

**Files:** `crates/foundry-mdoc/src/types.rs`

- [x] Add `SessionTranscriptParams` enum (`Redirect`, `DcApi`) with spec
      citations on each variant.
- [x] Add `build_session_transcript(&SessionTranscriptParams) -> Result<Vec<u8>, String>`
      emitting `[null, null, Handover]`, where `Handover` is
      `["OpenID4VPHandover" | "OpenID4VPDCAPIHandover", bstr sha256(cbor(info))]`.
- [x] `jwk_thumbprint: None` MUST encode CBOR `null` as the third info element.
- [x] **KAT — redirects:** exact equality against the published
      `SessionTranscript` hex
      `83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac`
      using inputs `client_id="x509_san_dns:example.com"`,
      `nonce="exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"`,
      `jwk_thumbprint=Some(4283ec92…9047)`,
      `response_uri="https://example.com/response"`.
- [x] **KAT — DC API:** exact equality against
      `83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a`
      using `origin="https://example.com"`, same nonce, same thumbprint.
- [x] Assert the intermediate `…HandoverInfo` encodings too, so a failure
      localises to info-vs-hash rather than "bytes differ".
- [x] `serialize_session_transcript` stays for now — Task 3 deletes it.
- [x] Gates ×4.

**Done when:** both published `SessionTranscript` vectors reproduce
byte-for-byte.

**Landed:** `f327937`.

**Deviation — test transcription method changed mid-task.** The plan implied
inlining the vectors as ordinary literals. The first draft re-joined the
spec's line-wrapped hex by hand and transposed four characters
(`6578633767` → `6563376742`), producing a *test* failure against *correct*
code. Replaced with a `spec_hex()` helper that strips whitespace at runtime,
so the spec's blocks are pasted in their published layout and can be diffed
against the spec line-for-line. Recorded because it changes how a reviewer
should check these literals.

**Why these KATs cannot pass vacuously:** the expected `SessionTranscript`
literals embed SHA-256 digests authored by the spec (`048bc053…`,
`fbece366…`); the implementation reproduced them from the input parameters
alone. The transposition failure additionally proved the assertions are live
to a 4-character difference. Two extra tests pin the axes the vectors cannot:
redirect-vs-DC-API transcripts never collide, and the thumbprint genuinely
affects the hash.

---

### Task 3: migrate to the new builder; delete the old one

**Files:** `foundry-mdoc/src/{types,verifier}.rs`,
`foundry-mdoc/tests/mdoc_tests.rs`, `foundry-verifier/src/verify.rs`,
`foundry-verifier/tests/conformance_vp.rs`,
`foundry/tests/wallet_verification.rs`

- [x] `verify_mdoc`: replace `client_id`/`response_uri`/`nonce` with
      `session_transcript: &[u8]`. It must no longer build anything.
- [x] Migrate all 4 `verify_mdoc` call sites (`mdoc_tests.rs:67`, `:98`,
      `verifier.rs:441`, `verify.rs:464`).
- [x] In `verify.rs`, implement **full handover selection**, single Origin:
      - `response_mode` → thumbprint: `dc_api.jwt`/`direct_post.jwt` →
        `Some(thumbprint_bytes(&tx.ephem_public_jwk)?)`; `dc_api`/`direct_post`
        → `None`; anything else → typed error, never a silent `None`.
      - `tx.transport == "dc_api"` → `DcApi{ origin }` with the **bare**
        origin (L2997 forbids the `origin:` prefix) taken from the first
        `dc_api_expected_origins` entry, else the `public_base_url` fallback.
      - otherwise → `Redirect{ client_id, nonce, thumbprint, response_uri }`.
- [x] Migrate the `serialize_session_transcript` call sites, then **delete**
      the function and its `https://localhost:8443` fallback.
- [x] Adapt the gap test's constructor call **only** (see Declared Exception).
      Keep `#[ignore]`.
- [x] `wallet_verification.rs`'s test-wallet builds the spec-correct
      transcript so the E2E mdoc round-trip stays green — this is the
      end-to-end proof the verifier and a "wallet" agree.
- [x] Gates ×4. One `cargo fmt` fixup applied and re-verified.

**Done when:** the workspace compiles with one transcript builder, the E2E
mdoc round-trip passes, and no report edits have been made yet.

**Landed:** `183ed12`.

**Correction — the spec's call-site count was wrong.** The spec claimed 3
`serialize_session_transcript` call sites; there were **5**. The two missed
sites were both inside `foundry-verifier/src/verify.rs`'s own test module
(the `use` at :584 and the call at :1501). Cause: the research grep's output
was truncated mid-list and the count was taken from the visible portion
rather than re-run. Caught immediately by the compiler, not by review. The
omitted call site turned out to matter substantively — `sample_tx` uses
`direct_post` + `direct_post.jwt`, so it needed the thumbprint-bearing
Redirect handover rather than a null one.

**Verification:** all five mdoc tests pass by name
(`mdoc_presentation_is_accepted`,
`verifier::tests::parses_and_verifies_valid_mdoc_presentation`,
`verify::tests::test_verify_vp_response_mdoc_presentation`,
`rejects_expired_mdoc`, `rejects_untrusted_anchor_mdoc`) — confirmed by name,
not inferred from a green summary. `--ignored` sweep moved from 23 FAILED + 1
ok to **22 FAILED + 2 ok**, the single flip being `gap_vp_06_…`, matching the
prediction exactly.

---

### Task 4: multi-Origin retry, remaining tests, and **all** bookkeeping

**Files:** `foundry-verifier/src/verify.rs`,
`foundry-verifier/tests/conformance_vp.rs`,
`docs/conformance/openid4vc-conformance.md`

- [x] Replace single-Origin selection with candidate iteration: one `DcApi`
      params per configured origin (plus fallback when unset); call
      `verify_mdoc` per candidate; accept the first that verifies; on total
      failure surface the last error.
- [x] Test: device signature over the spec-correct transcript verifies; the
      same signature over the **old ad-hoc** transcript does **not** (guards
      against the fix being vacuous).
- [x] Test: the **second** configured Origin verifies (proves retry, not
      first-only).
- [x] Test: an Origin matching neither a configured entry nor the fallback is
      rejected.
- [x] Test: `dc_api` vs `dc_api.jwt` select `null` vs thumbprint — asserted in
      **both** directions (correct choice accepted, opposite rejected).
- [x] Remove `#[ignore]` from `gap_vp_06_…`.
- [x] **Bookkeeping, same commit:** delete the GAP-VP-06 register row; flip
      VP-0229, VP-0232–VP-0240, VP-0243–VP-0250 to `conforming` with evidence
      naming `build_session_transcript`; recount the OpenID4VP Summary row.
- [x] **VP-0209 — judgement call, re-verify against the code, do not assume.**
- [x] `cargo test -p foundry --test conformance_report` (11/11) **before**
      committing.
- [x] Gates ×4. One `cargo fmt` fixup applied and re-verified.

**Done when:** GAP-VP-06 is absent from the register, every citing clause is
reconciled, and the 11 consistency checks are green.

**Landed:** `facbcfa`.

**VP-0209 verdict and reasoning (as required, recorded not assumed).** Re-read
`verify.rs` as it now stands. The clause covers *all* DC API response formats.
Its SD-JWT VC half became conforming in the Tier 1 run (VP-0265); its mdoc half
is closed here, because a DC API presentation is now bound by
`OpenID4VPDCAPIHandover` carrying the Origin. Flipped to `conforming`.

The substantive point worth recording: the two mechanisms **differ in
prefixing**. The KB-JWT `aud` carries `origin:`; the Handover's Origin element
MUST NOT (L2997). VP-0209's requirement text names the prefixed form, which is
the SD-JWT VC mechanism only. They are reconciled separately and must not be
conflated — a future reader could otherwise "fix" one to match the other and
break interop. That is now written into the clause's evidence.

**Second declared exception to "never rewrite gap tests".** The gap test's
block comment *and* its assertion message both named
`serialize_session_transcript`, deleted in Task 3. The needle
(`b"OpenID4VPHandover"`), the assertion logic and the test name are untouched;
only the symbol references were retargeted. Rationale: a failure message
pointing at a nonexistent function would misdirect whoever hits a future
regression, and the block comment asserting "foundry never constructs this"
next to a passing test would be actively false. Recorded rather than taken
silently, since the plan authorised only the constructor swap.

**Scope creep, deliberate and small:** four clauses that were *already*
`conforming` (VP-0230/0231/0241/0242) cited `serialize_session_transcript` as
evidence. Verdicts unchanged, evidence retargeted — a stale symbol reference in
a conformance record is still a defect, and leaving four of them behind while
closing this gap would have been dishonest bookkeeping.

**Counts verified, not asserted:** the OpenID4VP Summary was recomputed by
counting inventory rows programmatically (conforming 85, gap 11) and only then
compared against the 66+19 / 30−19 arithmetic. Both agreed. `--ignored` sweep
landed at **22 FAILED + 1 ok** against **21** remaining register rows, the
extra failing test being GAP-VCI-05's second citation — matching the plan's
prediction exactly.

---

### Task 5: Reconciliation

- [ ] `cargo test --workspace --no-fail-fast -- --ignored`: enumerate the
      failing set and **diff it line-by-line against the prediction** — 21 gap
      register rows remain (22 − GAP-VP-06), and GAP-VCI-05 is cited by two
      tests, so expect **22 failing gap tests** plus the passing E2E
      `full_flow_issue_verify_revoke_reverify`. Do not merely count.
- [ ] Confirm `openapi.json` / `openapi-wallet.json` byte-identical to `main`.
- [ ] Confirm no stale narrative gap counts elsewhere in the report.
- [ ] Gates ×4 on the final tree.

---

## Progress Log

_(appended as tasks land)_