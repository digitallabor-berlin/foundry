# Testing

Foundry's test runner is [cargo-nextest](https://nexte.st). Install it with:

```bash
cargo install cargo-nextest --locked
```

Run all unit and integration tests across the workspace — this is the gate, and
it takes seconds, so there is no reason to run anything narrower before
committing:

```bash
cargo nextest run --workspace --no-fail-fast --status-level fail
```

`--no-fail-fast` reports every failure rather than stopping at the first;
`--status-level fail` prints only failures plus a one-line summary. Drop both to
watch every test go by.

While iterating you can narrow to a single crate, a single test binary, or a
single test — note that nextest takes filters positionally, with no `--`
separator:

```bash
cargo nextest run -p foundry-issuer
cargo nextest run -p foundry-sd-jwt-vc
cargo nextest run -p foundry-mdoc
cargo nextest run -p foundry-core
cargo nextest run -p foundry
cargo nextest run -p foundry --test wallet_issuance full_issuance_flow_end_to_end
```

> **nextest does not run doctests.** This workspace has none — the only fenced
> blocks in its doc comments are ` ```text ` and ` ```cddl `, which rustdoc never
> compiles — so nothing is currently lost. If you add a real Rust doctest, run
> `cargo test --doc` as well; nextest will not.

Run code formatting and linter checks:

```bash
# Check formatting
cargo fmt --all -- --check

# Run Clippy
cargo clippy --workspace --all-targets -- -D warnings
```
