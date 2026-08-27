# Conformance Test Suite

Foundry carries a spec-conformance audit of the three protocol texts pinned in
[`docs/specs/`](https://github.com/digitallabor-berlin/foundry/tree/main/docs/specs/). Every mandatory clause is adjudicated in
[`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md),
and the verdicts are backed by four test suites:

| Command | Covers |
| --- | --- |
| `cargo nextest run -p foundry-issuer --test conformance_vci` | OpenID4VCI issuance engine (offers, `/token`, `/nonce`, `/credential`, holder proofs, attestations, issuer metadata) |
| `cargo nextest run -p foundry-verifier --test conformance_vp` | OpenID4VP verification engine (request objects, client identifier prefixes, DCQL, response encryption) |
| `cargo nextest run -p foundry --test conformance_http` | HTTP boundary in `crates/foundry/src/server.rs` (status codes, `Content-Type`, redirects, error bodies) |
| `cargo nextest run -p foundry --test conformance_report` | The report itself — parses the Markdown and enforces its internal consistency |

All four are ordinary integration tests, so `cargo nextest run --workspace`
already includes them. To run just the conformance suites, select all four
binaries with one nextest filterset:

```bash
cargo nextest run -E 'binary(/^conformance_/)'
```

## Known gaps are `#[ignore]`d and expected to fail

Each open finding in the report's Gap Register has a test that reproduces it,
marked `#[ignore]` with a reason string citing its gap ID:

```rust
#[ignore = "GAP-VCI-03: OpenID4VCI Credential Response (L976) — binary Credential Formats MUST be base64url-encoded"]
```

These are **deliberately failing tests describing behaviour foundry does not yet
have** — not broken tests. A default `cargo nextest run` skips them, which is why
the suite is green. Running them surfaces the open gaps, and they *should* fail:

```bash
# Expect failures — at least one per unclosed gap
cargo nextest run --workspace --run-ignored ignored-only
```

To enumerate the gap tests *without* running them:

```bash
cargo nextest list --workspace --run-ignored ignored-only
```

Unlike `cargo test`, nextest does **not** echo each `#[ignore = "..."]` reason
string, so that listing gives you test names only. Most names carry their gap ID
(`gap_vci_13_…`); to read the reasons themselves, go to the source:

```bash
rg -n '#\[ignore = ' crates/*/tests/ crates/foundry/tests/
```

Two things to know when reading those results:

- **A gap can have more than one failing test.** Where a single gap spans two
  code paths — e.g. `GAP-VCI-05`, a missing `iat` check in both `attestation.rs`
  and `proof.rs` — it is reproduced by one test per site.
- **Not every `#[ignore]`d test is a conformance gap.**
  `full_flow_issue_verify_revoke_reverify` in
  `crates/foundry/tests/e2e_full_flow.rs` carries a bare `#[ignore]` because it
  is slow, not because anything is non-conformant — it *passes* when run. Gap
  tests always carry a reason string naming their gap ID, which is exactly what
  the `grep` above filters on.

The `conformance_report` suite keeps this honest in CI: it asserts that every
gap-register entry names a test that exists, that each such test is actually
`#[ignore]`d citing its own gap ID (so an open gap can never masquerade as
passing), and that the summary counts match the clause inventory.

## Closing a gap

1. Fix the behaviour in the relevant crate.
2. Remove the `#[ignore]` attribute — the test should now pass.
3. Update that clause's row and the summary counts in
   `docs/conformance/openid4vc-conformance.md`, and drop its Gap Register entry.
4. Run `cargo nextest run -p foundry --test conformance_report` to confirm the report is
   still self-consistent.

The report is a living document, not a historical record — see
[`AGENTS.md`](https://github.com/digitallabor-berlin/foundry/blob/main/AGENTS.md) §8.

---
