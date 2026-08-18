# 2026-08-18 — Generated certificates backdate `not_before`

## Motivation

Two ABCA tests in `crates/foundry-issuer/src/token.rs` failed once during
unrelated work and then passed on an immediate re-run of the identical tree:

- `token::tests::client_id_matching_sub_and_iss_is_accepted` — its `expect` on
  `handle_token_request` panicked.
- `token::tests::client_id_mismatched_is_rejected` — got some error other than
  the `IssuanceError::InvalidClient` it asserts.

Both symptoms point *away* from the real cause, which is why this was initially
filed as "flaky ABCA client_id tests". Neither failure was about `client_id` at
all: something failed earlier in the request, before the `client_id` check ran.

## Root cause

`pki::new_ca` and `pki::issue_leaf` stamped `not_before = OffsetDateTime::now_utc()`
with **no backdating**. Certificate validity is therefore taken from the wall
clock at the instant of generation.

`validate_chain` (`trust/mod.rs`) does *not* use the wall clock — it compares
validity against a `now_unix` the **caller** supplies, via OpenSSL
`X509_VERIFY_PARAM::set_time`. `TrustStore` itself checks no validity windows;
that is by design and documented.

The two clocks meet in this sequence, which every attestation fixture in the
workspace uses:

```rust
let now = now_secs();                                    // t0
let (attestation_jwt, pop_jwt, ca_pem) =
    signed_attestation_and_pop(now, ISSUER_ID, "jti");   // generates CA + leaf at t1 > t0
// ...
handle_token_request(/* … */, now, /* … */)               // validates the chain AT t0
```

`not_before` is stored at one-second resolution. So whenever CA and leaf key
generation happened to cross a second boundary — `floor(t1) > floor(t0)` — the
certificate's `not_before` was **one second after** the timestamp it was then
validated against, and OpenSSL rejected the chain as "not yet valid".

That is a genuine race, not a theoretical one: two EC keypairs plus two
signatures take a few milliseconds, giving a small but real chance of straddling
a boundary on every run. It explains every observed detail — the rarity, both
tests failing in the same run (they hit the same boundary), and the misleading
error in each.

The codebase already knew certs use the wall clock: `attestation.rs`'s test
helper `now_secs()` carries a comment saying so, added to stop fixtures using a
*fixed* timestamp. That mitigation was incomplete — using real wall-clock time
still leaves the sub-second gap between capturing `now` and generating the certs.

## Change

`pki::CLOCK_SKEW_BACKDATE_SECS` (300s), applied to `not_before` in both
`new_ca` and `issue_leaf`. Backdating is the standard X.509 answer to clock
skew, and five minutes comfortably exceeds the millisecond-scale gap here while
staying far shorter than any validity period this module issues. `not_after` is
still measured from `now`, so no validity period is lengthened.

This fixes the whole class at the source rather than per-test. `new_ca` /
`issue_leaf` are used by 20+ test files plus the `pki` / `quickstart` CLI
commands, so every caller that captures `now` before generating a chain is
covered by one change.

**Scope check.** `pki/mod.rs` is documented as **dev-only** PKI
(`crates/foundry-core/AGENTS.md`) — its production use is the CLI generating a
"Foundry Dev Root CA" for local development. Backdating dev certificates by five
minutes carries no protocol or security consequence, and is in any case what
real CAs do.

## Tests

Written before the fix and each confirmed to fail without it:

| Test | Level |
| --- | --- |
| `pki::tests::generated_certs_backdate_not_before_for_clock_skew` | the property directly: `not_before` is backdated on both CA and leaf |
| `trust::tests::freshly_issued_chain_validates_against_a_slightly_lagging_clock` | the mechanism: a fresh chain validates against `now_secs() - 1` |
| `token::tests::attestation_verifies_against_a_clock_lagging_cert_generation` | the reported symptom, at the exact call site, made deterministic |

Reverting the backdate fails **exactly** those three and nothing else
(`964 passed, 3 failed`), which is what ties the fix to the originally reported
flake rather than to a plausible-sounding story.

## Honesty note

The original intermittent failure was **never reproduced directly** — it is a
millisecond-wide race and re-running is not a reliable trigger. The causal claim
rests instead on: a mechanism traced end-to-end through the source
(`pki` wall clock → caller-supplied `now_unix` → OpenSSL `set_time`), a
deterministic reproduction of that mechanism, and the fact that removing the fix
reproduces the reported symptom at the reported call site. That is strong
evidence, but it is inference from mechanism, not observation of the original
flake ceasing.

## Files

| File | Change |
| --- | --- |
| `crates/foundry-core/src/pki/mod.rs` | `CLOCK_SKEW_BACKDATE_SECS`; `not_before` backdated in `new_ca` and `issue_leaf`; unit test |
| `crates/foundry-core/src/trust/mod.rs` | Lagging-clock chain-validation regression test |
| `crates/foundry-issuer/src/token.rs` | Regression test at the reported call site |
| `crates/foundry-core/AGENTS.md` | Gotcha recording why the backdate exists and not to remove it |
