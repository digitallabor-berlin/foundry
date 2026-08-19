# Per-Credential Verification Verdicts

**Date:** 2026-08-19
**Spec:** [`../specs/2026-08-19-per-credential-verification-verdicts-design.md`](../specs/2026-08-19-per-credential-verification-verdicts-design.md)
**Plan:** [`../plans/2026-08-19-per-credential-verification-verdicts.md`](../plans/2026-08-19-per-credential-verification-verdicts.md)

## The Reported Symptom

A real two-credential presentation arrived: an SD-JWT VC (`com.emvco.dpc.card`,
under `vp_token` key `dpc`) and an mdoc (`eu.europa.ec.av.1`, under key `av`).
The mdoc's issuer chain had no configured trust anchor. The log said:

```text
verification failed: mdoc verification failed: cryptographic verification failed:
issuer cert validation: no configured trust anchor matches the certificate chain
```

That line names neither credential. With two credentials in the response, an
operator could not tell *which* one failed, nor whether the other had passed —
and the admin console showed nothing about either.

The request that started this work was "make the logs more readable". The logs
were a symptom.

## The Two Defects Found

**1. The per-credential loop was fail-fast, and said the opposite.**
`verify_one_credential` returned `Result`, and the loop in
`do_verify_vp_response` called it with `?`. So the first credential's failure
abandoned every credential after it. Directly above that loop sat a comment
explaining that verification is verify-all *because* root `AGENTS.md` §4.2
defines `verified` as the conjunction of the checks performed, which is only
meaningful when they were all performed. The function's own doc comment said the
same. The type said fail-fast, and the type won.

**2. The error path discarded the verdicts already computed.**
`verify_vp_response`'s `Err` arm rebuilt `tx.result` from scratch with
`credentials: Vec::new()` and the comment "Nothing was verified, so there is no
credential to report." That was true when the arm was written and had since
become false: by the time a per-credential error arrived there, one credential
*had* been fully verified. Its verdict was dropped on the floor.

A third, smaller gap made the symptom unfixable even in principle: a
`PresentedCredential` recorded a DCQL query id and a format, but not the
credential *type*. Both values were already computed and thrown away — the mdoc
`docType` by `verify_issuer_signed`, the SD-JWT `vct` inside the cloned payload.

## What Changed

### `crates/foundry-verifier/src/transaction.rs`

- `PresentedCredential` gains `credential_type: Option<String>` — the `vct` for
  `dc+sd-jwt`, the `docType` for `mso_mdoc`. Extracted **before** the
  format-specific signature check, so it survives a failure; authenticated only
  when that check passed, exactly the caveat that already governs `claims`.

### `crates/foundry-verifier/src/verify.rs`

- **`verify_one_credential` no longer returns `Result`.** It returns
  `(PresentedCredential, Option<VerificationError>)`, so `?`-propagation out of
  the loop is unrepresentable rather than merely commented against.
- The format-specific signature stage moved into `verify_credential_payload`,
  which does return `Result` — so exactly one place converts that `Err` into a
  failed `CheckResult`, instead of every fallible call inside it having the
  option of escaping the loop.
- A failed format check **short-circuits** that credential's remaining checks.
- `with_credential_context` names the credential query in the error message.
- The loop collects **every** fault; step 5 records one top-level `status_check`
  per unavailability; step 5b reduces the faults to the one error the wallet is
  told about.
- `asserted_vct_unverified` reads the `vct` a presentation asserts without
  verifying a signature. Every malformed shape yields `None` rather than an
  error — a diagnostic must not be able to change the verdict it describes.
- One roll-up log record per credential: `credential verified` (INFO) or
  `credential failed` (WARN), carrying `credential`, `format`,
  `credential_type`, `checks`, `checks_passed`. Per-check records gain
  `credential_type`. The `vp response not verified` record gains
  `credentials_failed`.

### Elsewhere

- `crates/foundry/assets/console.html` renders `credential_type` as a label
  beside the format.
- `openapi.json` / `openapi-wallet.json` regenerated.
- `crates/foundry/tests/wallet_verification.rs` pins the mixed verdict over HTTP.
- `README.md`, root `AGENTS.md` §4.5, `crates/foundry-verifier/AGENTS.md` updated.

## The Three Decisions, and Why

**Log shape: both a roll-up and enriched per-check records.** Replacing the
per-check records with a summary would have been a breaking change for anyone
alerting on `check=`/`passed=` — root `AGENTS.md` §4.5 makes log field names
operator-facing API. So the roll-up is the line to read and the per-check trail
is the drill-down. Purely additive; nothing renamed.

**Precedence: crypto/structural (400) outranks `StatusUnavailable` (502).** A bad
signature is deterministic, so answering 502 would invite the wallet to retry a
presentation that can never succeed. Within one class the incumbent wins, so DCQL
declaration order decides. This keeps wire behaviour identical to before: the
change is visible only in the log and the console.

**Attribution: uniformly to the format-specific check name.** A failure in the
signature stage is recorded as `sd_jwt_vc_signature_and_kb_jwt` or
`mdoc_issuer_auth_and_device_signature`, with the real reason in `detail`. This
leaves §4.2's closed per-credential check vocabulary untouched — no new check
name was invented for this work.

## Where This Departed From the Plan

**Recording a fault and choosing the response status became separate steps.**
The approved plan kept a single `deferred` slot chosen by precedence. Its own
test then failed, and the failure was correct: it asserted both that a crypto
failure wins the returned error *and* that a concurrent status-list
unavailability is still recorded as a `status_check` fault. Those cannot both
hold with one slot. An unavailability pushes **no** per-credential
`status_check` by design — "I could not determine whether this is revoked" is not
"this is revoked" — so when the crypto failure took the slot, the unavailability
was recorded nowhere at all.

Fixing the design rather than weakening the test: the loop collects every fault,
step 5 records each unavailability at the top level (§4.2 — a failure path never
skips a push), and step 5b then picks the single error the wallet sees (§4.3).
Status codes are unchanged.

**The credential-name prefix cannot be applied to three error variants.**
`Storage`, `CoreCrypto` and `Trust` are `#[error(transparent)]` and wrap a
foreign error with no string field to prefix. Rewrapping one as `Failed` to gain
a field would change `error.kind`, which §4.5 makes operator-facing API. Those
three are returned unchanged; the per-credential roll-up record names the
credential regardless, which is what the original request actually needed.

**The redaction control lives in `verify.rs`, not `logging_redaction.rs`.** That
file's `drive_verification` posts a deliberately undecryptable JWE, so it returns
before any credential is examined and emits no per-credential record to assert
against. Reaching one there would mean duplicating ~100 lines of presentation
fixture that already exist in `verify.rs`. The control asserts, against one
capture, that `credential_type` **is** logged and that disclosed claim values are
**not** — so neither property can drift without the other noticing.

## What Deliberately Did Not Change

- **HTTP status codes.** Crypto/structural → 400, status-fetch → 502, policy →
  200 with `verified: false` (§4.3). Verified by an HTTP-level test asserting the
  400 while the transaction carries both credentials' verdicts.
- **§4.2's per-credential check-name enumeration.** No new check name.
- **Any existing log field name.** Additive only (§4.5).
- **`foundry-mdoc` and `foundry-sd-jwt-vc`.** Both already exposed everything
  needed (`DeviceResponse::doc_type()`, `IssuerVerified.doc_type`, and the `vct`
  inside the verified payload). No format-crate change was required.

## Verification

Gate (root `AGENTS.md` §5.1), with exit codes checked rather than output read:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

## A Note on Method

Substantial time in this work was lost to a misdiagnosis worth recording. Tool
output arrived out of order and interleaved across concurrent invocations, which
produced duplicated `git status` lines, `/tmp` files that appeared then vanished,
a `shasum` that returned a UUID, and file reads containing identifiers that exist
nowhere in the repository. This was twice escalated as suspected data corruption.

The actual cause was ordinary concurrency: several shell invocations running at
once, colliding on `.git/index.lock` and interleaving their output.

Two lessons, both applied in the later tasks:

1. **Trust exit codes over rendered text.** `cargo check` returning `EXIT=0` is
   ground truth about the file on disk; a rendering of that file is not. A gate
   was once reported green from output that actually contained a failure.
2. **One command per turn, and narrow, self-labelling output.** Single-value
   greps and filtered prints rendered reliably; long `&&` chains and wide reads
   did not.
