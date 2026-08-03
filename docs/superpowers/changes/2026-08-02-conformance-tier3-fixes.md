# Conformance Tier 3 — Seven Gap Closures

> Migrated from `docs/superpowers/changes/2026-08-02-conformance-tier3-fixes.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Date:** 2026-08-02
**Type:** feature
**Track:** B
**Branch:** superlight/2026-08-02-conformance-tier3-fixes
**Spec:** docs/superpowers/specs/2026-08-02-conformance-tier3-fixes-spec.md
**Plan:** docs/superpowers/plans/2026-08-02-conformance-tier3-fixes-plan.md

## Problem

Seven entries in [`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md)'s
Gap Register were open, each with a confirmed root cause and a committed
`#[ignore]`d test naming it. None was architectural — they were open because
the code was never written, not because the design was unclear.

| Gap | Severity | Site |
|---|---|---|
| GAP-VP-01 | Important | `build_signed_request_object` emitted no `aud` claim |
| GAP-VP-02 | Important | `client_id` host never cross-checked against the `x5c` leaf's dNSName SAN |
| GAP-VCI-09 | Important | `Config::validate()` never compared `credential_issuer` to `public_base_url` |
| GAP-VCI-08 | Minor | `Config::validate()` never checked `credential_issuer`'s scheme |
| GAP-HAIP-02 | Important | Authorization Response carried no `iss` (RFC 9207) |
| GAP-VCI-04 | Important | Every nonce failure reported `invalid_proof`; no `InvalidNonce` variant existed |
| GAP-VCI-02 | Important | `handle_credential_request` never read `credential_configuration_id` |

## Approach

Each gap was fixed at the site the register named, using the mechanism the
register identified. Four decisions were genuinely open — the pinned specs and
existing tests did not settle them — and were put to the user:

1. **GAP-VCI-08 exempts loopback hosts** from the `https` MUST (OpenID4VCI
   L1368/L1369). *Rejected:* strict `https` with a `config.yaml` migration;
   an `issuer.allow_insecure_http` opt-out knob. This is a deliberate
   documented deviation per AGENTS.md §4.4 — the repository's own dev config
   runs `http://localhost:8443` and would otherwise fail to boot.
2. **GAP-HAIP-02 closes RFC 9207 fully** — `iss` on success *and* error
   redirects, plus the `authorization_response_iss_parameter_supported`
   metadata flag. *Rejected:* both redirects without the flag; success-only
   (which the test alone would have accepted, leaving §2's "including error
   responses" and §2.3 unmet).
3. **GAP-VCI-04 propagates `InvalidNonce` from the key-attestation path**,
   keeping the `key_attestation:` message prefix. *Rejected:* leaving the
   wrap, which would give a wallet two different codes for one recoverable
   condition depending on which nested JWT carried the nonce.
4. **GAP-VCI-02 uses the full three-way error split.** *Rejected:* two-way
   (reusing `UnknownCredentialType`); one-way (a single generic variant) —
   self-defeating for a gap whose defect *is* "the specific code is not used".

Two places where the pinned specs proved **wider than the register's own
description**, caught by reading the source text rather than trusting the row:

- **RFC 9207 §2** requires `iss` "including error responses", and **§2.3**
  requires the metadata flag. The register described only the success path,
  and `haip_0008`'s assertion would have passed a partial fix.
- **OpenID4VCI L1049 clause 3 vs L1050** partition the two error codes by
  *cause*: a **missing** `c_nonce` stays `invalid_proof`; only a **present but
  invalid** one becomes `invalid_nonce`. Naively converting every
  "nonce-related" failure would have been wrong.

## Changes

- `crates/foundry-core/src/url.rs` — **new.** `dns_host_only`, hoisted verbatim
  from `foundry-verifier`'s `pub(crate)` copy so both crates share one host
  extractor. No new dependency; the workspace deliberately carries no URL crate.
- `crates/foundry-core/src/lib.rs` — declares `pub mod url`.
- `crates/foundry-core/src/config/validate.rs` — two checks appended after the
  existing keyref checks (so `bad-missing-keyref.yaml` still trips that one
  first): `https` scheme with a loopback exemption (GAP-VCI-08), then
  byte-exact `credential_issuer` == `public_base_url` (GAP-VCI-09). Private
  `is_loopback_host` covers exactly `localhost`, `127.0.0.1`, `::1`, `[::1]`.
- `crates/foundry-verifier/src/request.rs` — host derivation moved above the
  `x5c` block; `match_san_dns` cross-check inside it, reusing the already-read
  PEM (GAP-VP-02); `"aud": "https://self-issued.me/v2"` inserted into the
  payload (GAP-VP-01); local `dns_host_only` deleted.
- `crates/foundry-verifier/src/verify.rs` — imports `dns_host_only` from
  `foundry-core`. The compiler caught this second in-crate call site that a
  plain grep-and-replace would have missed.
- `crates/foundry-issuer/src/error.rs` — three new variants (`InvalidNonce`,
  `InvalidCredentialRequest`, `UnknownCredentialConfiguration`) with their
  `kind()` arms. `kind()`'s exhaustive-no-catch-all design forced every site.
- `crates/foundry-issuer/src/nonce.rs` — all four `verify_nonce` failures now
  `InvalidNonce`.
- `crates/foundry-issuer/src/proof.rs` — **unchanged behaviour**, deliberately:
  the missing-nonce-claim branch stays `InvalidProof` (L1049 clause 3).
- `crates/foundry-issuer/src/attestation.rs` — matches on the variant to keep
  `InvalidNonce` while preserving the `key_attestation:` prefix; `other => other`
  leaves any non-nonce error untouched.
- `crates/foundry-issuer/src/credential.rs` — `credential_configuration_id`
  validated after the `Offered` state check and **before** proof verification,
  so a misaddressed request fails on the cheap check. `req.format` remains
  deliberately unread — it is not a Credential Request parameter in
  OpenID4VCI 1.0, and every caller including `foundry-wallet` sends it.
- `crates/foundry-issuer/src/authorize.rs` — `handle_authorize_request` gains
  `issuer_identifier: &str`; `AuthorizeOutcome::Success` and `::ErrorRedirect`
  gain `iss`. `DirectError` deliberately does not — it renders as a JSON body,
  not a redirect, so RFC 9207 §2 never reaches it.
- `crates/foundry-issuer/src/metadata.rs` — `AuthorizationServerMetadata` gains
  `authorization_response_iss_parameter_supported: bool`, hardcoded `true`.
- `crates/foundry/src/server.rs` — three new `wallet_error_response` arms
  (placed before the catch-all); `authorize_handler` passes the issuer
  identifier; both `append_query` call sites add `iss`.
- `crates/foundry-wallet/tests/support/mod.rs` — verifier leaf reissued with
  SAN `issuer.example.com` (see Review below).
- `openapi-wallet.json` — regenerated; diff verified to be exactly the one new
  required field. `openapi.json` unchanged (the schema is wallet-only).
- `docs/conformance/openid4vc-conformance.md` — 7 Gap Register rows removed,
  **8** clause rows flipped to `conforming` with fresh evidence (eight, not
  seven: GAP-VCI-08 spans VCI-0130 *and* VCI-0131). Summary: VCI 71/23 → 76/18,
  VP 85/11 → 87/9, HAIP 46/8 → 47/7; totals unchanged.
- `crates/foundry-{core,issuer,verifier}/AGENTS.md` — Gotchas for the loopback
  deviation and its RFC 9207 consequence, the byte-exact identity rule, the
  `InvalidNonce`/`InvalidProof` split-by-cause, the three-way
  `credential_configuration_id` split, and `handle_authorize_request`'s new
  parameter.

## Tests

All seven formerly-`#[ignore]`d tests now pass unmodified as the acceptance
criteria. `crates/foundry/tests/conformance_report.rs` enforces register↔test
consistency **in both directions** and machine-checks the Summary arithmetic,
so it failed once per task until that task's register rows were updated — the
mechanism working as designed, not friction.

**New tests beyond the seven:**

- `foundry-core/src/url.rs` — 5 tests pinning `dns_host_only`'s exact behaviour
  across the hoist.
- `config/validate.rs` — loopback accepted (`localhost` and `127.0.0.1`),
  non-loopback `http` rejected, trailing-slash-only divergence rejected, and a
  regression guard that a well-formed config still passes.
- `conformance_vp.rs` — **positive control** proving the SAN check is a genuine
  comparison (a matching SAN signs successfully), plus a no-`x5c` guard.
  Without these, `vp_0063` would also pass if the function merely always errored.
- `proof.rs` — a **missing** `nonce` claim still yields `InvalidProof`, the
  boundary that makes the GAP-VCI-04 split meaningful.
- `attestation.rs` — key-attestation nonce failure surfaces `InvalidNonce` with
  the prefix retained.
- `conformance_vci.rs` — absent id, configured-but-unbound id, and proof that
  the config-id check runs **before** proof verification (a broken proof paired
  with a bad id still reports the config-id failure).
- `authorize.rs` — `iss` present on both `Success` and `ErrorRedirect` at the
  engine level, not only through HTTP.
- `conformance_http.rs` — `iss` on the error redirect, and the success-path
  assertion tightened from "contains `iss=`" to the exact percent-encoded value.

**Two existing tests were flipped, as corrections not regressions:**
`wallet_issuance.rs`'s `proof_nonce_mismatch` and `expired_c_nonce` now expect
`invalid_nonce`. `proof_aud_mismatch` still expects `invalid_proof` and serves
as the positive control that the two codes stay distinguished.

**Verified:**

```
cargo test --workspace --no-fail-fast   → 46/46 test result blocks ok, 0 failed
cargo clippy --workspace --all-targets -- -D warnings   → clean
cargo fmt --check                        → clean
```

## Review

**One Critical finding, found and fixed.** The workspace-wide gate — not any
per-crate run — surfaced 6 failing tests in `foundry-wallet`. Root-caused
before editing: the shared harness `foundry-wallet/tests/support/mod.rs` paired
`public_base_url: "https://issuer.example.com"` with a verifier leaf whose only
SAN was `"localhost"`. GAP-VP-02's new check correctly rejected it. This was a
genuine pre-existing misconfiguration that the codebase had silently tolerated
— precisely the defect class the gap exists to catch — so the fixture was
fixed, not the check weakened. `crates/foundry/tests/wallet_verification.rs`
was confirmed already correct (`public_base_url` and SAN both `localhost`),
which is why it passed unchanged throughout.

**Deliberately left:** `server::tests::detail_is_length_capped` is a
pre-existing flake in the shared `tracing` test-subscriber harness (parallel
tests racing on process-global subscriber state). Confirmed by A/B comparison
against `main` before any commit on this branch — it reproduces identically on
both and passes reliably single-threaded or in isolation. Unrelated to this
work and out of scope.

No other Critical or Important findings. Fresh-eyes review read every
production diff line-by-line against `main`, confirming match-arm ordering
(new variants before catch-alls), correct scoping of the SAN check, no
information loss in the `attestation.rs` fallthrough, and no drift in
`authorize.rs`'s untouched logic despite the full-file rewrite. No leftover
`TODO`/`FIXME`/`dbg!`/`println!` in any touched production file.

## Follow-ups (not done here)

- **`config.yaml` is stale.** It still uses `http://localhost:8443` while the
  `foundry quickstart` template (`commands.rs`) emits `https://localhost:8443`.
  Boots fine today thanks to the loopback exemption, but the two disagreeing is
  pre-existing drift worth reconciling deliberately.
- **A loopback deployment emits a non-conformant `http://` `iss`** (RFC 9207 §2
  requires `https`). An accepted, documented consequence of Decision 1 — not a
  new defect, recorded in `foundry-core/AGENTS.md` Gotchas.
- **`detail_is_length_capped`'s flakiness** deserves its own fix (likely a
  serialized test or a per-test subscriber), as its own piece of work.
