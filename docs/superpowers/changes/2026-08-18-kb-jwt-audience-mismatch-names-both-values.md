# 2026-08-18 — `KB-JWT audience mismatch` now names both compared values

## Motivation

Diagnosing the draft-24 `web-origin:` mismatch recorded in
[`2026-08-18-dc-api-legacy-web-origin-audience.md`](2026-08-18-dc-api-legacy-web-origin-audience.md)
cost a round trip that the error message should have made unnecessary. All the
operator got was:

```text
verification failed: holder key binding verification failed: KB-JWT audience mismatch
```

Two values had just been compared and neither was reported. Recovering the
presented `aud` meant enabling `--log-sensitive` **and** `RUST_LOG=trace` on a
live deployment so `do_verify_vp_response` would dump the whole decrypted
response payload — a log record carrying the raw `vp_token` and every disclosed
claim value, i.e. exactly what root `AGENTS.md` §4.5 exists to keep out of
production logs. A wrong prefix on an otherwise-correct Origin does not justify
that.

## Change

`verify_kb_jwt` (`crates/foundry-sd-jwt-vc/src/verifier.rs`) now returns:

```text
KB-JWT audience mismatch: presented "web-origin:https://site.example", expected one of ["origin:https://site.example"]
```

Three properties, each with a test:

1. **Both sides are named.** Presented first, then the accepted list — so a
   downstream `obs::truncate` at `DETAIL_MAX` can only ever cut the list, never
   the value the operator most needs.
2. **The presented `aud` is `{:?}`-formatted, not `{}`.** It is
   wallet-controlled and this string reaches both a log record and an HTTP 400
   body; a raw newline in it would let a caller forge log lines. Debug
   formatting escapes it and keeps it readable.
3. **The expected list is bounded** by `MAX_NAMED_EXPECTED_AUDIENCES` (8) and
   appends `(+N more)` when it truncates, rather than silently omitting. The
   list is doubled when `verifier.dc_api_accept_legacy_web_origin_audience` is
   on, so an unbounded render was a real possibility.

## Why this is not a §4.5 leak

Both values are public identifiers: an Origin (RFC 6454) or a Client Identifier
(`x509_hash:<hash>`). Neither appears on §4.5's never-log list, which enumerates
keys, tokens, nonces, codes and payloads. The wallet already knows the value it
sent, and the accepted Origins are operator-published. No new information
crosses a boundary.

## Files

| File | Change |
| --- | --- |
| `crates/foundry-sd-jwt-vc/src/verifier.rs` | `MAX_NAMED_EXPECTED_AUDIENCES`, `describe_expected_audiences`, richer `KeyBinding` message |
| `crates/foundry-sd-jwt-vc/tests/sdjwt_tests.rs` | 3 new tests |
| `crates/foundry-sd-jwt-vc/AGENTS.md` | Gotcha: both values named, presented one stays `{:?}` |
| `README.md` | DC API troubleshooting sample updated to the new message |

## Tests

- `kb_audience_mismatch_names_both_the_presented_and_the_expected_audiences`
- `kb_audience_mismatch_escapes_a_wallet_controlled_audience` — a newline in the
  presented `aud` must survive as `\n`, never raw
- `kb_audience_mismatch_bounds_a_long_expected_audience_list` — 20 configured
  audiences render bounded, with the presented value intact and a `more` marker

The pre-existing `rejects_kb_audience_mismatch` still passes: it asserts the
variant, not the message, which is the right level for it.

## Note

Only the SD-JWT VC path is affected. mdoc has no KB-JWT — its holder binding is
the Device Signature over a `SessionTranscript`, where the Origin is *inside*
the hash and so cannot be reported as a compared value at all.
