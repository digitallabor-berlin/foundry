# GAP-VP-06 — Spec-Defined mdoc `SessionTranscript` Handover — Change Record

**Date:** 2026-08-02
**Branch:** `superlight/2026-08-02-gap-vp-06-session-transcript`
**Spec:** [`../specs/2026-08-02-gap-vp-06-session-transcript-spec.md`](../specs/2026-08-02-gap-vp-06-session-transcript-spec.md)
**Plan:** [`../plans/2026-08-02-gap-vp-06-session-transcript-plan.md`](../plans/2026-08-02-gap-vp-06-session-transcript-plan.md)

## Why

GAP-VP-06 was the last remaining **Critical** entry in the conformance gap
register, and the one with the widest interop consequence.

`foundry_mdoc::types::serialize_session_transcript` was the only
`SessionTranscript` builder in the workspace. It emitted:

```
[null, null, [client_id, response_uri, nonce]]        # ad-hoc 3-element array
[null, null, ["https://localhost:8443", nonce]]       # hardcoded fallback
```

OpenID4VP 1.0 requires the third element to be one of two specific structures —
`OpenID4VPHandover` for redirects (L2833-L2873), `OpenID4VPDCAPIHandover` for
the Digital Credentials API (L2963-L2999) — each a two-element array whose
first element is a fixed literal string and whose second is the SHA-256 hash of
a CBOR-encoded `…HandoverInfo`. foundry emitted neither literal, computed no
hash, and did not distinguish the two invocation methods at all. Its own doc
comment conceded as much: *"TODO(interop): simplified handover; not the hashed
OID4VPHandover from 18013-7."*

`SessionTranscript` is precisely the byte string an mdoc Device Signature is
computed over. A conformant wallet signs the spec-correct transcript; foundry
recomputed a different one to check against; the signature could never
validate. **mdoc presentation was broken against every wallet except foundry's
own**, which happened to compute the identical wrong bytes. That is one of only
two credential formats this workspace supports.

19 clauses cited the gap: VP-0209, VP-0229, VP-0232–VP-0240 (redirects),
VP-0243–VP-0250 (DC API).

### Three findings that reshaped the work before any code was written

1. **`foundry-wallet` contains no mdoc presentation code at all.** Grepping
   `device_signature|DeviceAuth|mso_mdoc` across `crates/foundry-wallet/src/`
   returns nothing. There was no debug-wallet signing path to keep in lockstep,
   which collapsed the expected blast radius to a handful of in-repo call
   sites.
2. **Every input the spec demands was already on `VerificationTransaction`** —
   `transport`, `response_mode`, `ephem_public_jwk` — and the 2026-08-01 Tier 1
   run had just added `verifier.dc_api_expected_origins`, which supplies the
   Origin. No new configuration was needed.
3. **The spec ships complete byte-level test vectors for both variants**
   (L2885-L2950, L3010-L3080), plus the input JWK behind the thumbprint. This
   turned the task from "implement and hope" into "implement against
   known-answer tests".

### An ambiguity settled by measurement rather than reading

The prose — *"the sha-256 hash of the bytes of `OpenID4VPHandoverInfo` when
encoded as CBOR"* — is equally compatible with hashing the plain CBOR array or
hashing a tag-24 / `bstr`-wrapped embedding. Rather than pick a reading, the
spec's own published vectors were used to decide, **before** production code
existed:

| Check | Result |
|---|---|
| `sha256(plain CBOR of redirects info array)` == hash embedded in `OpenID4VPHandover` | ✅ `048bc053…38ac` |
| `sha256(plain CBOR of DC API info array)` == hash embedded in `OpenID4VPDCAPIHandover` | ✅ `fbece366…761a` |
| `83 f6 f6 ‖ <handover>` == published `SessionTranscript` (both variants) | ✅ |
| RFC 7638 thumbprint of the spec's example JWK == the `bstr` in both info arrays | ✅ `4283ec92…9047` |

Verdict: plain CBOR, no tag 24, no `bstr` wrapper. The fourth row additionally
proved the canonicalization already in `foundry_core::obs::thumbprint` is
byte-identical to what the handover needs, which is why no new RFC 7638
implementation was written.

## What Changed

### `foundry-core` — a fail-closed thumbprint (`b6835c8`)

`obs::thumbprint` is infallible **by contract**: it is called from log
statements, so malformed input degrades to `INVALID_JWK_THUMBPRINT`. That is
right for logging and wrong for a handover, where the digest is hashed into
bytes a signature commits to — the literal string `"<invalid-jwk>"` would be
baked into a transcript that verifies against nothing.

Added `thumbprint_bytes(jwk) -> Result<[u8; 32], String>` and refactored
`thumbprint` to delegate to it, so exactly one canonicalization remains and
both forms stay covered by the same vectors. Two tests: OpenID4VP's example JWK
must yield the bytes embedded in both published `…HandoverInfo` vectors, and a
paired assertion that `thumbprint` degrades exactly where `thumbprint_bytes`
fails — keeping that divergence deliberate rather than accidental.

The pre-existing RFC 7638 §3.1 vector and the never-contains-key-material test
pass **unmodified**, which is the evidence the refactor preserved behaviour.

### `foundry-mdoc` — the spec-shaped builder (`f327937`)

New `SessionTranscriptParams` (`Redirect` | `DcApi`) and
`build_session_transcript`, each variant carrying its spec citations. An absent
thumbprint encodes CBOR `null`, never an omitted element.

Tests transcribe both published vectors and assert them byte-for-byte,
including the intermediate `…HandoverInfo` encodings so a regression localises
to the info array rather than reporting only "bytes differ".

### `foundry-mdoc` / `foundry-verifier` — moving the decision up a layer (`183ed12`)

`verify_mdoc` previously built its own transcript from
`client_id`/`response_uri`/`nonce`, which forced every caller into the one
ad-hoc shape and left the mdoc crate deciding an OpenID4VP question it has no
inputs for. It now takes `session_transcript: &[u8]` — three parameters
collapse to one — and builds nothing.

`foundry-verifier` selects the Handover, because it is the only layer that
knows the transaction:

| `tx.response_mode` | third `…HandoverInfo` element |
|---|---|
| `dc_api.jwt`, `direct_post.jwt` | RFC 7638 thumbprint of `tx.ephem_public_jwk` |
| `dc_api`, `direct_post` | CBOR `null` |

An unrecognised Response Mode is a typed error, never a silent `None`: guessing
would produce a transcript that fails to verify for a reason no operator could
diagnose. `tx.transport == "dc_api"` selects `OpenID4VPDCAPIHandover` bound to
the bare Origin — L2997 forbids the `origin:` prefix — and every other
transport selects `OpenID4VPHandover`.

`serialize_session_transcript` and its hardcoded `https://localhost:8443`
fallback were deleted; the spec defines no such variant.

### `foundry-verifier` — multi-Origin selection and the fix proper (`facbcfa`)

The Origin sits *inside* the hash, so unlike the KB-JWT audience — which is
compared against a list — the verifier cannot compare. It must **pick** before
it can verify, and a deployment may legitimately serve several origins. Each
configured `dc_api_expected_origins` entry therefore yields a candidate
transcript, and the Device Signature decides which one the wallet used.

## Verification

| Claim | How it was verified |
|---|---|
| The transcript bytes are the spec's | Both published `SessionTranscript` vectors reproduced byte-for-byte. These embed SHA-256 digests authored by the spec (`048bc053…`, `fbece366…`) which the code reproduced from input parameters alone — this cannot pass vacuously |
| The KAT assertions are live | A 4-character transposition in a hand-joined hex literal was caught immediately by the intermediate `HandoverInfo` assertion |
| **The fix is not cosmetic** | A DeviceAuth over the *pre-fix* ad-hoc transcript is now rejected. Without this, every other assertion would still pass if the verifier had simply stopped checking the Device Signature |
| Multi-Origin retry is real | The **second** configured origin verifies — a first-only implementation fails this |
| Retry did not become permissive | An origin matching no configured candidate is still rejected |
| Thumbprint selection is correct both ways | `dc_api` vs `dc_api.jwt` assert the correct choice accepted **and** the opposite rejected |
| A wallet and this verifier agree | The E2E `wallet_verification` round-trip derives the thumbprint from the key the *request object* advertised, while the verifier derives it from the transaction — genuinely cross-checked, not assumed |
| §4.2 honesty preserved | `checks.push(passed: true)` is structurally unreachable unless `verify_mdoc` returned `Ok`; total failure returns `Err` first |
| §4.1 no panics in request paths | Added-lines-only scan of every production file, splitting at `#[cfg(test)]`: zero matches outside test modules |
| §4.5 no new logging surface | The branch adds **zero** `tracing` calls and zero `#[tracing::instrument]` sites |
| No layering violation | **Zero** `Cargo.toml` changes across the branch — no new dependency edges |
| OpenAPI unchanged | `git diff main..HEAD` on both spec files is empty |
| Register reconciles by name | The `--ignored` set was **set-diffed** against the gap register's `Test` column, not counted (see below) |

All four gates green at every commit: `cargo test --workspace`,
`cargo test --workspace --no-fail-fast -- --ignored`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.
`conformance_report.rs` 11/11 throughout.

Final reconciliation:

```
register rows          : 21
distinct cited tests   : 21
cited-but-not-failing  : none
failing-but-not-cited  : vci_0186_key_attestation_without_iat_is_rejected
actual ok (ignored)    : full_flow_issue_verify_revoke_reverify
```

The lone "failing-but-not-cited" entry is GAP-VCI-05's **second** citing test,
the known double-citation carried over from the Tier 1 run — so 22 FAILED = 21
gaps + 1 second citation, every remaining gap accounted for by name.

## Conformance Impact

**21 gaps remain** (was 22): 11 Important, 10 Minor, and — with GAP-VP-06
deleted — **no Critical gaps open for the first time since the audit**.

OpenID4VP summary moved **66 conforming / 30 gap → 85 / 11**, verified by
recounting the inventory programmatically before comparing against the
19-flip arithmetic. Both agreed.

**VP-0209 was re-read against the code rather than flipped mechanically.** It
covers all DC API response formats; its SD-JWT VC half became conforming in the
Tier 1 run and its mdoc half closed here. Its evidence now records that the two
mechanisms **differ in prefixing** — the KB-JWT `aud` carries `origin:`, the
Handover's Origin element MUST NOT (L2997) — so they are reconciled separately
and must not be conflated. A future reader could otherwise "fix" one to match
the other and break interop.

## Deviations From the Plan

All recorded in the plan ledger when taken:

- **The spec's call-site count was wrong** — 3 claimed, 5 actual. The two
  missed sites were in `foundry-verifier/src/verify.rs`'s own test module.
  Cause: a research grep's output was truncated mid-list and the count was
  taken from the visible portion instead of re-run. Caught by the compiler, not
  by review. It mattered substantively: the missed site uses `direct_post.jwt`,
  so it needed the thumbprint-bearing handover rather than a null one.
- **Test vectors are transcribed verbatim via a `spec_hex()` helper** that
  strips whitespace at runtime, after hand-joining the spec's wrapped hex
  transposed four characters. Reviewers can now diff the literals against the
  spec line-for-line.
- **A second exception to "never rewrite gap tests"** was taken: the gap test's
  block comment *and* assertion message both named the deleted
  `serialize_session_transcript`. The needle, assertion logic and test name are
  untouched — only symbol references were retargeted, since a failure message
  pointing at a nonexistent function would misdirect whoever hits a future
  regression.
- **Small deliberate scope creep:** four already-`conforming` clauses
  (VP-0230/0231/0241/0242) cited the deleted function as evidence. Verdicts
  unchanged, evidence retargeted — a stale symbol reference in a conformance
  record is still a defect.

## Follow-Ups

1. **The MSO tag-24 embedding TODO.** `foundry-mdoc/src/types.rs` carries a
   second, unrelated interop concession on `MobileSecurityObject`:
   *"TODO(interop): payload is not tag-24 embedded-CBOR wrapped"* (and similar
   on `IssuerSignedItem` and `ValidityInfo`'s `tdate`). Noticed while working
   in the file; distinct structures, not cited by any GAP-VP-06 clause, not
   fixed here. Recorded so it is not mistaken for something this change
   addressed.
2. **`dc_api` Response Mode still arrives as a JWE.** `do_verify_vp_response`
   decrypts unconditionally without branching on `response_mode`, so the
   unencrypted `dc_api` mode cannot currently be exercised end-to-end. The
   transcript selection for it *is* tested, but the transport quirk is
   pre-existing and out of scope here — plausibly its own gap on a future pass.
3. **21 gaps remain** across Tiers 2–5 — **11 Important, 10 Minor, zero
   Critical** (counted from the register, not inferred). GAP-VCI-14, the
   Client Attestation PoP gap filed by the Tier 1 run, is one of the 11.