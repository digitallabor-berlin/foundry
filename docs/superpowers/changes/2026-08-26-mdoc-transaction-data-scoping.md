# Verifier — `transaction_data` Scoping Is Decided Before the Format

**Date:** 2026-08-26
**Spec / Plan:** none — a bugfix found by systematic debugging of a live
CMWallet interop failure, not a planned feature.

## The Reported Symptom

A multi-credential DC API presentation from CMWallet — an EMVCo DPC card
(`com.emvco.dpc.card`, `dc+sd-jwt`) plus an EU Proof of Age attestation
(`eu.europa.ec.av.1`, `mso_mdoc`) — returned `verified: false`:

```text
credential failed credential=av_mdoc format=mso_mdoc credential_type=eu.europa.ec.av.1 checks=4 checks_passed=3
verification check failed credential=av_mdoc check=transaction_data_binding passed=false
    detail=mdoc transaction_data binding is not implemented
```

The DPC credential passed all four of its checks, including
`transaction_data_binding`.

## Root Cause

Not the unimplemented mdoc binding the `detail` names. The defect was that
`verify_one_credential` decided **scoping after format** instead of before it.

`crates/foundry-verifier/src/verify.rs` read:

```rust
if let Some(ref entries) = ctx.tx.transaction_data {
    match &kb_jwt_payload {
        Some(kb_payload) => checks.push(check_transaction_data_binding(entries, query_id, kb_payload)),
        None => checks.push(/* mdoc transaction_data binding is not implemented */),
    }
}
```

The mdoc arm fired on whether the **transaction** carried any
`transaction_data` at all, never on whether an entry was scoped to *this*
credential — note `entries` is unused in it. The `credential_ids` filter lived
inside `check_transaction_data_binding`, which only the SD-JWT VC arm calls, so
only that format ever benefited from it.

Consequence: **any** mdoc credential in **any** multi-credential request failed
as soon as some *other* credential carried transaction data. The comment above
the block asserted the check was "already multi-credential aware… it filters
entries by `credential_ids`" — true of the function, false of the arm that
never called it.

CMWallet was correct throughout. `OpenId4VP.kt:116-153`
(`generateDeviceSignedTransactionData`) filters by
`dcqlId in transactionDataItem.credentialIds` and found no entry for the mdoc,
so it signed `{"net.openid.open4vc": {"transaction_data_hashes": []}}` into
`DeviceSigned.nameSpaces` — decoded from the captured response as evidence. The
request had scoped its PaSO payment entry to the DPC card only, which is right:
a payment binds to the card, not to a proof of age.

## What Changed

One source file, `crates/foundry-verifier/src/verify.rs`:

- **New `applicable_transaction_data(entries, answered_query_id)`** — the
  `credential_ids` filter, extracted from `check_transaction_data_binding`'s
  former step 1 verbatim. Returns `Ok(Vec<ApplicableEntry>)`, or `Err` carrying
  the ready-made failing `CheckResult` for an entry foundry cannot re-read.
  OpenID4VP L320 makes `credential_ids` REQUIRED on every entry: which
  credentials an entry addresses is a property of the **request**, not of the
  format answering it, so this cannot sit behind a format branch.
- **New `ApplicableEntry` struct** replacing the `(usize, String, Vec<String>)`
  tuple, so `index` / `encoded` / `advertised_algs` are named at use sites.
- **New `no_applicable_transaction_data()`** — the format-independent passing
  verdict, and now the single home of the
  `"no transaction_data entries scoped to the answered credential query"`
  detail string.
- **New `TD_BINDING_CHECK` const** — the check name, shared by the scoping and
  binding stages so they cannot drift.
- **`check_transaction_data_binding` narrowed** to
  `(&[ApplicableEntry], &Value)`: it now receives pre-filtered, non-empty
  entries and performs only the hash/algorithm verification (former steps 2-4,
  unchanged in behaviour). Its only call site changed with it.
- **The call site** now matches on scoping first, and only then on format.

No behaviour changed for SD-JWT VC: the same filter runs, in the same order,
producing the same records. For mdoc, a credential no entry addresses now gets
the same passing "nothing scoped here" record the SD-JWT path always got.

## What Deliberately Did Not Change

An entry **genuinely** scoped to an `mso_mdoc` credential query still records
`passed: false` with the same `mdoc transaction_data binding is not
implemented` detail. That is fail-closed and is a permitted unimplemented
option under root AGENTS.md §4.4, not a conformance gap:

- OpenID4VP L2751 places its only MUST on the **Wallet**, defers the mdoc
  mechanism to the document type's own specification, and defines no generic
  namespace. Implementing it means adopting a vendor convention (CMWallet uses
  `net.openid.open4vc`), which §4.4's vendor-profile rule requires be
  documented as accommodation rather than conformance.
- `build_device_response` (foundry-mdoc) hardcodes `empty_device_namespaces()`,
  so foundry cannot even construct the wallet side to test against.

It is therefore **not** in the gap register. That was tried first and the
report's own structural tests correctly rejected it —
`gap_clauses_and_gap_register_reference_each_other` requires every register row
be cited by a clause whose verdict is `gap`, and
`gap_register_rows_are_complete_and_well_formed` requires every row name a real
executable test. Neither could be satisfied honestly: no clause is a gap
(foundry checks, and fails closed), and no test could assert a wire format no
pinned spec defines.

## Tests

One new test in `crates/foundry-verifier/src/verify.rs`:

- `transaction_data_scoped_to_another_credential_does_not_fail_an_mdoc` —
  reproduces the reported scenario: a two-credential DCQL (`dpc` SD-JWT VC +
  `av` mdoc) with `transaction_data` scoped to `["dpc"]`, both credentials in
  one `vp_token`. Asserts the mdoc records no failing
  `transaction_data_binding`, that the DPC's own binding is still verified as
  passing (so the fix narrows the arm rather than disabling the check), and
  that the whole response verifies.

Confirmed genuinely red before the fix, with the production `detail` string
reproduced exactly.

## Documentation

- `docs/conformance/openid4vc-conformance.md` — VP-0153's evidence now records
  that scoping is decided by `applicable_transaction_data` before the format is
  consulted, and states the mdoc capability limit and why it is not a gap.
  Cites the new test. Verdict unchanged (`conforming`); no Summary counts move.
- `crates/foundry-verifier/AGENTS.md` — two Gotchas: do not move the filter
  back inside `check_transaction_data_binding`, and the mdoc branch is
  deliberately unimplemented and must never be made to pass without verifying
  something.

## Verification

- `cargo fmt`
- `cargo nextest run --workspace --no-fail-fast --status-level fail` —
  `1159 tests run: 1159 passed, 11 skipped`
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
