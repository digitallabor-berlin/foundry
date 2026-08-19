# Per-Credential Verification Verdicts

**Date:** 2026-08-19
**Status:** Approved design, pending implementation plan
**Crates touched:** `foundry-verifier`, `foundry` (console, OpenAPI)

---

## 1. Problem

A two-credential presentation — an SD-JWT VC `com.emvco.dpc.card` under
`vp_token` key `dpc`, and an mdoc `eu.europa.ec.av.1` under key `av` — failed
because the mdoc's issuer chain had no configured trust anchor. That failure is
expected. What is not acceptable is that the log said only this:

```text
WARN vp response verification failed tx_id=v_c60d… error.kind="failed"
     error.detail=verification failed: mdoc verification failed: cryptographic
     verification failed: issuer cert validation: no configured trust anchor
     matches the certificate chain check="verification_error"
```

Nothing names *which* credential failed, and nothing reports that the other
credential passed — even though it demonstrably had: the `idx=819937` status-list
fetch two lines earlier is the DPC credential's, and it returned
`status="valid"`.

### 1.1 Root cause — the type won an argument with the comment

The per-credential loop is fail-fast, despite documenting the opposite.

`crates/foundry-verifier/src/verify.rs:1086`:

```rust
for (query_id, payload) in selected {
    let (credential, status_unavailable) =
        verify_one_credential(&ctx, &query_id, payload, resolver).await?;   // ← aborts
```

Iteration is in DCQL declaration order, so `dpc` was verified first and passed,
then `av`'s failure propagated through `?` and abandoned the loop.

Two comments in the same file assert this does not happen:

- `verify.rs:1065` — *"Per-credential verification. Verify-all, never fail-fast:
  root AGENTS.md §4.2 defines `verified` as the conjunction of the checks
  performed, which is only meaningful when they were all performed, and 'PID
  signature bad, mDL fine' is a far more useful operator verdict than 'PID
  signature bad, mDL unknown'."*
- the doc comment on `verify_one_credential` (`verify.rs:~572`) — *"the caller
  verifies every credential before deciding anything (a bad signature on one
  credential must not hide another's verdict)"*.

Only `VerificationError::StatusUnavailable` actually honours this, via the
`deferred` mechanism at `verify.rs:1090`. Every other error bypasses it. The
function's return type is `Result`, the caller reached for `?`, and the type won.

### 1.2 Second defect — the error path discards completed verdicts

`verify.rs:353`, in `verify_vp_response`'s `Err` arm:

```rust
// Nothing was verified, so there is no credential to report.
credentials: Vec::new(),
```

`dpc`'s passing checks existed in memory and were thrown away. This is also why
the log carried no per-credential lines at all: the `for credential in
&result.credentials` logging loop (`verify.rs:266`) runs only on the `Ok` arm.

### 1.3 Third defect — the credential type is never surfaced

`PresentedCredential` (`transaction.rs:33`) carries `query_id` and `format` but
no `vct`/`docType`. Both are already computed and dropped:

- mdoc `docType` — returned by `verify_issuer_signed` and kept only in a local
  for DCQL matching (`verify.rs:790`).
- SD-JWT `vct` — already *persisted* inside `credentials[i].claims`, because
  `foundry-sd-jwt-vc/src/verifier.rs:255` clones the whole JWT payload into the
  claims map. It is simply never surfaced as a field or logged.

---

## 2. Governing constraints

| Source | Constraint |
| --- | --- |
| Root AGENTS.md §4.2 | `verified` MUST equal the conjunction over **every** `CheckResult` at both levels, via `VerificationResult::all_checks()`. Never assigned. |
| Root AGENTS.md §4.2 | The per-credential check-name vocabulary is closed: `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check`, `transaction_data_binding`. |
| Root AGENTS.md §4.3 | Crypto/structural failure → **400**. Network status-fetch unavailability → **502**. Policy failure → **200** with `verified: false`. |
| Root AGENTS.md §4.5 | `skip_all` mandatory; log field names are operator-facing API and renaming one is a breaking change; every typed error produces exactly one log record. |
| Root AGENTS.md §6 | Endpoint/schema changes MUST be reflected in `openapi.json`. |

The §4.3 row is the load-bearing one: **verify-all must not turn a bad signature
into `200 verified:false`.** It means *finish the loop, record the failure as
that credential's check, then still return `Err`* — which is exactly the
`deferred` mechanism already present for `StatusUnavailable`.

---

## 3. Decisions taken

Recorded because each was a live choice, not a derivation:

1. **Log shape: roll-up *and* per-check lines** (not either/or). §4.5 makes the
   existing `check=`/`passed=` lines operator-facing API, so they are enriched,
   never replaced. A new per-credential roll-up line is added on top.
2. **Status-code precedence: crypto/structural (400) beats
   `StatusUnavailable` (502).** Preserves today's observable behaviour, so this
   change is visible in logs and the admin console but not on the wire. Also the
   honest verdict: a deterministic signature failure must not hand a wallet a
   retryable code.
3. **Uniform attribution to the format-specific check name.** Every error raised
   while verifying one credential becomes that credential's format check with
   `passed: false` and the original message as `detail`. §4.2's enumeration is
   left untouched and the console needs no new check name. The accepted stretch:
   a `DeviceResponse` CBOR parse failure or an unsupported `response_mode` also
   reads as `mdoc_issuer_auth_and_device_signature: false`, with the real reason
   in `detail`.
4. **Conversion happens inside `verify_one_credential`, whose return type stops
   being a `Result`.** Rejected: converting at the call site, which loses what
   the function already knew (the mdoc `docType` was in hand before the chain
   check failed), re-derives `format` outside the function that owns that
   mapping, and leaves the invariant in the caller where a future `?` silently
   restores this bug.
5. **A failed format check short-circuits that credential's remaining checks.**
   Running `dcql_match` and `status_check` against empty claims would report
   three failures where one occurred, two of them misattributed — "DCQL
   mismatch" when the truth is "we never obtained claims".

---

## 4. Design

### 4.1 Data model

One field added to `PresentedCredential` (`crates/foundry-verifier/src/transaction.rs:33`):

```rust
/// The credential type the presentation **asserts**: `vct` for
/// `dc+sd-jwt`, `docType` for `mso_mdoc`.
///
/// Extracted BEFORE the format-specific signature check so it survives a
/// failure -- a failed credential an operator cannot name is the defect
/// this field exists to fix. It is therefore only *authenticated* when
/// that check passed, exactly the caveat that already governs `claims`.
/// `None` when the presentation could not be decoded far enough to read a
/// type.
pub credential_type: Option<String>,
```

Population:

- **SD-JWT VC** — read `vct` from the JWT payload segment *before* calling
  `verify_sd_jwt_vc`, through a local helper in `verify.rs` whose name states its
  trust status (`asserted_vct_unverified`). It base64url-decodes the second
  compact segment and reads `vct`; any failure yields `None` rather than an
  error, because this is a diagnostic value and the format check is what decides
  the verdict.
- **mdoc** — `docType` from `parse_device_response`, which already runs before
  verification (`verify.rs:645`). On success it is overwritten with the
  authenticated `issuer.doc_type` (`verify.rs:790`), so the persisted value is
  authenticated whenever it can be.

§4.5 disposition: a `vct`/`docType` is a credential *type* identifier, not a
holder value — the same class as `query_id`, whose logging the code already
justifies. Logged unconditionally, at no sensitivity gate.

Wire compatibility: additive. `Option<String>` serialises as `null` when absent.

### 4.2 Control flow

`verify_one_credential` returns a type that **cannot be `?`-propagated**:

```rust
async fn verify_one_credential(
    ctx: &CredentialVerifyCtx<'_>,
    query_id: &str,
    selected: SelectedPresentation<'_>,
    resolver: &dyn StatusListResolver,
) -> (PresentedCredential, Option<VerificationError>)
```

This is the mechanism, not a stylistic preference: the defect exists because the
signature was `Result` and `?` was available. Removing `Result` makes the defect
unrepresentable.

Internal behaviour:

1. Extract `credential_type` (§4.1) — never fails.
2. Run the format-specific signature stage. On failure: push
   `CheckResult { check: <format check name>, passed: false, detail: <message> }`,
   **skip stages 3–5**, return the credential and the error. The returned
   credential's `claims` is an empty JSON object — no claims were obtained, and
   an empty map is the honest representation of that (the console renders it as
   `{}`).
3. `transaction_data_binding`, when `tx.transaction_data` is present — unchanged.
4. `dcql_match` — unchanged.
5. `status_check` — unchanged, including that `StatusUnavailable` pushes **no**
   record (unavailability is not a policy failure) and is returned as the
   accompanying error.

The loop at `verify.rs:1084` folds the returned errors by precedence:

```text
crypto / structural  (→ 400)   >   StatusUnavailable  (→ 502)
```

Tie-breaking is by iteration order: the first error of the winning class is the
one returned, so two crypto failures report the first credential's. Decision 2,
now explicit rather than an accident of `?` short-circuiting.

Consequential edits in `do_verify_vp_response`:

- **Step 5** (`verify.rs:1109`), which records the deferred fault as a
  *top-level* check, becomes conditional on `StatusUnavailable`. It exists only
  because unavailability pushes no per-credential record; a crypto failure
  already has one, so recording both would double-count one fault in the check
  list and inflate `failed_checks`.
- **Step 3's comment** (`verify.rs:1065`) becomes accurate for the first time.
- `check_requested_credentials_answered` needs no change and becomes *more*
  correct: it matches on `query_id` presence, and a credential that was answered
  but failed was still answered. Today that check never runs at all on a crypto
  failure.

Consequential edit in `verify_vp_response`:

- The `Err` arm (`verify.rs:340`) is now reached **only** by genuinely
  transaction-level errors — JWE decryption, missing `vp_token`, trust-store
  construction, `select_presentations`. Its `credentials: Vec::new()` becomes
  true rather than a convenient fiction, and the comment is rewritten to say
  why it is true *there* specifically.
- The `Ok` arm's existing `deferred` handling (`verify.rs:320`) needs no
  structural change: it already logs the whole result, persists `tx.result`,
  sets `tx.state = Failed`, and returns `Err(err)`. Widening `deferred` gives
  the crypto-failure case all of that for free.

### 4.3 Log surface

All logging stays in the single place that already owns it —
`verify_vp_response`'s `Ok` arm, `verify.rs:266` — so the deferred/error path
inherits it and §4.5's "exactly one log record per typed error" is preserved.

Per credential: a roll-up header line, then that credential's per-check lines.

```text
INFO  credential verified  credential=dpc format=dc+sd-jwt credential_type=com.emvco.dpc.card checks=3 checks_passed=3
INFO  verification check   credential=dpc credential_type=com.emvco.dpc.card check=sd_jwt_vc_signature_and_kb_jwt passed=true
INFO  verification check   credential=dpc credential_type=com.emvco.dpc.card check=dcql_match passed=true
INFO  verification check   credential=dpc credential_type=com.emvco.dpc.card check=status_check passed=true
WARN  credential failed    credential=av format=mso_mdoc credential_type=eu.europa.ec.av.1 checks=1 checks_passed=0
WARN  verification check failed  credential=av credential_type=eu.europa.ec.av.1 check=mdoc_issuer_auth_and_device_signature passed=false detail=…no configured trust anchor matches the certificate chain
WARN  vp response not verified  verified=false failed_checks=1 credentials_requested=2 credentials_answered=2 credentials_failed=1
WARN  vp response verification failed  error.detail=credential query 'av': mdoc verification failed: … check=verification_error
```

New field names, all additive — none renamed, per §4.5:

| Field | Where | Meaning |
| --- | --- | --- |
| `credential_type` | roll-up + per-check lines | asserted `vct`/`docType`; empty string when `None` |
| `checks` | roll-up | count of checks recorded for this credential |
| `checks_passed` | roll-up | count that passed |
| `credentials_failed` | the `vp response not verified` line | count of credentials with ≥1 failed check |

Deliberately **absent** from the roll-up: the failed check's name and detail. The
adjacent per-check `WARN` carries both, and the existing verdict line already
uses `failed_checks` as a *count* — reusing that name for a list of names would
give one operator-facing field two types.

Level follows meaning (§4.5): a passing credential is `INFO`, a failing one
`WARN`. `detail` stays truncated to `DETAIL_MAX` (512).

### 4.4 Error message

Per-credential errors gain the credential prefix the `StatusUnavailable` path
already uses (`verify.rs:1094`):

```text
credential query 'av': mdoc verification failed: cryptographic verification
failed: issuer cert validation: no configured trust anchor matches the
certificate chain
```

Additive change to the 400 body's `error_description`. Status codes unchanged.

**The prefix cannot be applied uniformly, and must not be forced.** Three
`VerificationError` variants are `#[error(transparent)]` and wrap a foreign
error — `Storage`, `CoreCrypto`, `Trust` (`error.rs:31-38`). They carry no
string field to prefix. Rewrapping them as `Failed` to gain one would change
`error.kind`, which §4.5 makes operator-facing API that operators alert on, so
that is refused: those three are returned unchanged. The prefix therefore
applies to the nine string-carrying variants, and the per-credential roll-up
line of §4.3 is what names the credential in *every* case, including the three.

The helper is exhaustive with no catch-all, for the same reason `check_name_for`
is: a new variant should be a deliberate decision about whether it can carry
credential context, not a silent fallthrough.

No new error log record is emitted. §4.5 requires exactly one record per typed
error, emitted in `crates/foundry/src/server.rs`'s mapper; the deferred arm
(`verify.rs:320`) deliberately does not log today and must continue not to.

### 4.5 Admin console

`crates/foundry/assets/console.html:2862` renders `cred.query_id` as the section
header with `cred.format` as a badge. It gains `credential_type` beside the
format badge, and — because failed credentials now appear at all — this is the
change that makes a mixed verdict visible in the UI rather than only in the log.

---

## 5. Testing

TDD: each behaviour gets a failing test before the change that satisfies it.

### 5.1 Unit (`crates/foundry-verifier/src/verify.rs`, `mod tests`)

1. **Two credentials, untrusted mdoc chain + valid SD-JWT.** Asserts the call
   returns `Err` of the 400 class **and** `tx.result.credentials.len() == 2`,
   with the SD-JWT credential all-passed and the mdoc credential holding exactly
   one check, `mdoc_issuer_auth_and_device_signature: false`. This is the
   regression test for the reported defect.
2. **Precedence.** One credential crypto-fails, another's status list is
   unreachable → the returned error is the crypto one, so the route answers 400
   and not 502.
3. **Short-circuit.** The credential whose format check failed carries **no**
   `dcql_match` and no `status_check` record.
4. **No double-counting.** With a crypto failure, the top-level `checks` list
   gains no fault record (step 5 is `StatusUnavailable`-only), and
   `failed_checks` counts one.
5. **`credential_type`.** `vct` for SD-JWT, `docType` for mdoc, `None` for a
   presentation that cannot be decoded; and `verified == false` still derives
   correctly via `all_checks()`.
6. **Regression sweep.** Existing tests asserting an empty `credentials` list on
   a crypto failure are updated. This is the behaviour change and it must be
   visible in the diff rather than silently accommodated.

Adding a non-`default` field also breaks every struct-literal construction of
`PresentedCredential` — `transaction.rs:182`, `transaction.rs:229`,
`transaction.rs:235`, `verify.rs:2892`, `verify.rs:2898`. The compiler finds all
of them; each gets a deliberate value rather than a reflexive `None`.

### 5.2 Observability (`crates/foundry/tests/`)

1. `instrumentation_hygiene.rs` — new instrumented functions, if any, keep
   `skip_all`.
2. `logging_redaction.rs` — positive control that `credential_type` *is* emitted,
   plus confirmation that no claim value or payload rides along with the new
   roll-up fields.

### 5.3 Integration (`crates/foundry/tests/`)

1. The mixed two-credential case over the HTTP route still answers **400**, with
   the transaction's persisted result carrying both credentials.

### 5.4 Gate

Root AGENTS.md §5.1, run before any completion claim:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

`cargo nextest run`, never `cargo test`. The E2E suite (§5.2) runs once at the
end of the branch.

---

## 6. Documentation to update

| File | Change |
| --- | --- |
| `openapi.json` | Regenerate — `PresentedCredential` gains `credential_type` (§6) |
| `crates/foundry/assets/console.html` | Render `credential_type` (§4.5) |
| `crates/foundry-verifier/AGENTS.md` | Gotchas: verify-all is now real, error precedence, per-credential short-circuit |
| Root `AGENTS.md` §4.5 | Add `credential_type`, `checks`, `checks_passed`, `credentials_failed` to the operator-facing field list |
| `README.md` (Logging & Observability, ~line 1015) | Document the roll-up line and the new fields alongside the existing per-credential `credential` field description |
| `docs/conformance/openid4vc-conformance.md` | Audited: no row currently cites fail-fast per-credential behaviour, so no verdict changes. Re-audit during implementation in case a row is added meanwhile. |
| `docs/superpowers/changes/2026-08-19-per-credential-verification-verdicts.md` | Change record |

---

## 7. Out of scope

- Changing which HTTP status a bad signature produces. §4.3 governs; this design
  preserves it exactly.
- Making `transaction_data_binding` work for mdoc. It remains a recorded
  `passed: false` with its existing "not implemented" detail.
- Any change to `foundry-mdoc` or `foundry-sd-jwt-vc` verification logic. Both
  are consumed unchanged; only what `foundry-verifier` does with their results
  changes.
- Reordering credential verification. DCQL declaration order is retained, and
  with verify-all the order no longer determines what an operator learns.
