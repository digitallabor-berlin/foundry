# DPoP Sender-Constrained Access Tokens (RFC 9449)

**Date:** 2026-08-03
**Type:** feat
**Branch:** dpop-sender-constrained-tokens
**Spec:** docs/superpowers/specs/2026-08-03-dpop-sender-constrained-tokens-design.md
**Plan:** docs/superpowers/plans/2026-08-03-dpop-sender-constrained-tokens-plan.md

## Why

Closes **GAP-HAIP-03**: HAIP OpenID4VCI L163 mandates DPoP (RFC 9449) for
sender-constrained access tokens unconditionally, and foundry always issued
plain `Bearer` tokens with no DPoP support anywhere in the workspace. This was
deliberately deferred out of the 2026-08-03 conformance Tier 4 cycle ("Tier 4
minus DPoP") as its own cycle, since it is a genuinely new protocol surface
(new config, a new module, three modified endpoints) rather than a fix to
existing logic.

`HAIP-0009` flips from `gap` to `conforming`; `VCI-0163` (Security / Protecting
the Access Token) now also holds on substantive grounds, not only the
pre-existing vacuous one (every access token is short-lived by construction).

## Approach

Four scope decisions were put to the user during brainstorming, each answered
with the recommended option:

1. **Enforcement is a tri-state (`issuer.dpop.mode`: `optional` (default) /
   `required` / `disabled`)**, reusing the existing `foundry_core::config::Mode`
   enum rather than a new type. `optional` binds an access token only when the
   wallet actually presents a proof — the interop-safe default, since RFC 9449
   §5 explicitly permits `Bearer` when no proof is presented. `disabled`
   **ignores** the `DPoP` header rather than rejecting it: §10.1 encourages
   clients that attach it to every AS call, and rejecting would hard-fail a
   wallet doing exactly what the RFC recommends.
2. **Server-provided `DPoP-Nonce` challenges (§8/§9) are deliberately not
   implemented.** They are a MAY. §11.2's named compensating control — access
   tokens fixed at a short, non-renewable 600s lifetime — already holds, and
   §11.3 ("MUST NOT accept proofs without the nonce claim when a nonce has been
   provided") is satisfied vacuously since no nonce is ever supplied.
3. **The `dpop_jkt` authorization request parameter (§10) is accepted and
   enforced.** A wallet MAY pin the eventual authorization code to a specific
   key at `/authorize`; `/token` then MUST reject a mismatch before the code is
   invalidated, closing the harvested-code-redeemed-under-a-different-key
   attack (§11.9).
4. **Key binding is a field on the transaction (`IssuanceTransaction.dpop_jkt:
   Option<String>`)**, using §6's explicitly-permitted third mechanism ("an
   agreement by the authorization server and the protected resource") rather
   than a `cnf.jkt` JWT claim or an introspection endpoint — valid here because
   the authorization server and the resource server are this one process
   sharing one `Storage`.

**Deliberate deviation, approved by the user and documented in the conformance
report (RFC-9449-0007) and the crate `AGENTS.md` Gotchas:** an *unbound* token
presented with the `DPoP` scheme is rejected, stricter than RFC 9449, which
leaves that case undefined. Accepting it would let a wallet conclude it has
sender-constraining when the token has no bound key at all — the same false
assurance §5's "the client MUST discard the response" language exists to
prevent.

## What Changed

New module `crates/foundry-issuer/src/dpop.rs`:

- `verify_dpop_proof` — RFC 9449 §4.3 checks 2–9 and 11–12 within a single
  parse of the proof JWT (§4.3 check 1, "at most one `DPoP` header", needs the
  header map and lives in `server.rs`'s pre-existing `exactly_one_header`;
  check 10, `nonce`, is vacuous per decision 2 above).
- `claim_dpop_jti` — §11.1 replay defence: an atomic
  `insert_kv_if_absent(dpop_jti, base64url(SHA-256(jkt‖0‖htu‖0‖jti)), ...)`,
  scoped per target URI (§11.1's "in the context of the target URI") and per
  `jkt` (so one wallet cannot pre-claim `jti` values and deny service to
  another).
- `access_token_hash` — §7's `ath` computation.
- `DpopPresentation<'a>` — what the HTTP layer observed about one request's
  presentation (scheme, proof, `htm`/`htu`/`ath`), threaded into both engine
  entry points below instead of five more positional parameters.

Config: `foundry_core::config::DpopConfig { mode: Mode, max_age_secs: u64 }` on
`IssuerConfig.dpop`, defaulting to `Optional` / `300` so every existing
`config.yaml` keeps its current all-`Bearer` behaviour unchanged.
`Config::validate()` rejects `max_age_secs == 0` (a zero acceptance window
would make every proof stale the instant it is minted).

Error: one new `IssuanceError::InvalidDpopProof(String)` variant
(`kind() == "invalid_dpop_proof"`) covers every DPoP failure, since RFC 9449
§5/§12.2 registers exactly one error code for them; the discriminating detail
lives in the `Display` string.

Three endpoints:

- **`/authorize`** (`AuthorizeParams.dpop_jkt`) records the §10 pin on the
  transaction. Shape is not validated — a value that is not the thumbprint of
  the eventual proof's key simply fails the comparison at `/token`.
- **`/token`** (`handle_token_request`, now 9 parameters) implements the
  §5/§5.2 mode matrix, enforces the §10 pin (before the code is invalidated —
  same anti-burn ordering the `tx_code` and PoP-replay paths already use), and
  sets `token_type: "DPoP"` plus `IssuanceTransaction.dpop_jkt` on a bound
  token.
- **`/credential`** (`handle_credential_request`, gains a `dpop` parameter)
  enforces the five-row §5.3/§6/§7/§7.1/§7.2 decision table: unbound+Bearer
  (accept, unchanged), bound+Bearer (reject, §7.2 anti-downgrade), bound+DPoP
  (verify proof, match `ath`, match `jkt`, claim `jti`), bound+no-proof
  (reject, §7), unbound+DPoP (reject, the deliberate deviation above).
  `issuer.dpop.mode` is **not** consulted here: the binding is a property of
  the already-issued token, so flipping config to `Disabled` must not
  retroactively let bound tokens be presented as Bearer. DPoP failures answer
  401 + `WWW-Authenticate: DPoP error="invalid_token", algs="ES256"` (§7.1) via
  a new `credential_error_response`, distinct from `/token`'s 400 mapping —
  RFC 9449 §5 governs the Token Endpoint, §7.1 the Credential Endpoint.

AS metadata: `dpop_signing_alg_values_supported` (§5.1) advertises `["ES256"]`
under `optional`/`required`, omitted entirely under `disabled` — its presence
is itself the support signal.

Documentation: `docs/conformance/openid4vc-conformance.md` — `HAIP-0009`
flipped to `conforming`, `GAP-HAIP-03` removed from the Gap Register, `VCI-0163`
rewritten to cite both grounds, and a new "Clause Inventory — RFC 9449 (DPoP)"
section (13 rows, `RFC-9449-0001`–`0013`) added per the report's own
late-discovered-clause convention, since RFC 9449 was not one of the three
originally inventoried specs. Root `AGENTS.md` §4.4 gains a row for
`docs/specs/rfc9449-dpop.txt`. `crates/foundry-issuer/AGENTS.md` gains the
`dpop.rs` module-map row, updated entry-point signatures, the new public
surface, and five Gotchas. `README.md` gains a "DPoP (RFC 9449)" configuration
section. `openapi.json`/`openapi-wallet.json` regenerated (only `/token`,
`/credential`, and the AS metadata schema changed — `/authorize` gained no
documented parameter, since none of its existing query parameters are
individually documented in its `#[utoipa::path]` annotation either, and adding
one solely for `dpop_jkt` would have been inconsistent).

## What Is Knowingly Not Implemented

- **§8/§9 server-provided `DPoP-Nonce` challenges** — a MAY; see decision 2
  above (`RFC-9449-0008`, `not-implemented`).
- **§10.1 PAR interaction** — no `/par` endpoint exists at all (`HAIP-0007`,
  `ambiguous`); the interaction cannot arise (`RFC-9449-0010`,
  `out-of-scope`).
- **§5 refresh-token binding** — foundry issues no refresh tokens anywhere
  (`RFC-9449-0011`, `out-of-scope`).
- **§6.2 introspection response `cnf.jkt`** — no `/introspect` endpoint or
  remote resource server; the AS and RS are the same process, which is exactly
  the §6 alternative this implementation uses instead (`RFC-9449-0012`,
  `out-of-scope`).

## Testing

Scoped gate run after every task (`cargo test -p foundry-core -p foundry-issuer
[-p foundry]`, `cargo clippy ... -D warnings`, `cargo fmt --check`), per root
`AGENTS.md` §5.1 — never `--workspace` between tasks. New coverage:

- `dpop.rs`: 33 unit tests, including two RFC 9449 known-answer vectors (the
  §6.1 Figure 9 `jkt` and the §7.1 Figure 13/14 `ath`) verified against the
  RFC's own published values, not against this implementation's own output.
- `token.rs`: the full §5/§5.2 mode matrix (3 modes × {no header, valid proof}),
  the §10 pin (match / mismatch / missing-proof-with-a-pin), and two
  ordering-invariant tests proving a forged or wrong-key proof cannot burn a
  legitimate holder's code.
- `credential.rs`: all five rows of the §5.3 decision table, plus a
  same-token-different-transaction replay test isolating the `jti` check from
  the transaction single-use check.
- `crates/foundry/tests/wallet_issuance.rs`: a full DPoP issuance flow over the
  real HTTP router (offer → `/token` with a proof → `/credential` with the
  `DPoP` scheme and a second proof carrying `ath`), the §7.2 downgrade
  returning 401 with the `WWW-Authenticate` challenge, and §4.3 check 1
  (duplicate `DPoP` header, only reachable through a real `HeaderMap`) at both
  endpoints.
- `crates/foundry-issuer/tests/conformance_vci.rs`: `haip_0009_token_response_uses_dpop_token_type`
  un-ignored and rewritten — its previous assertion (`token_type == "DPoP"`
  with *no* DPoP header sent) was itself non-conformant with §5; it now
  exercises both the bound and unbound halves and asserts the transaction
  records the bound key.

Full gate (root `AGENTS.md` §5.3) run once, at the end of the branch: `cargo
fmt` (apply) → `cargo fmt --check` → `cargo test --workspace` → `cargo test -p
foundry --test e2e_full_flow -- --ignored` → `cargo clippy --workspace
--all-targets -- -D warnings`.

## Follow-ups / Known Limitations

- Two `attestation.rs` tests were observed to fail once under a full-crate
  parallel test run and passed clean on three immediate reruns and in
  isolation — a pre-existing flake unrelated to this branch (`dpop.rs` shares
  no code path with `attestation.rs`), noted rather than chased down, since
  reproducing it reliably would require its own investigation.
- If a future cycle adds Pushed Authorization Requests (resolving
  `HAIP-0007`'s "ambiguous" verdict), `RFC-9449-0010`'s `out-of-scope` verdict
  for §10.1 will need revisiting — a `/par` endpoint accepting `dpop_jkt` would
  bring that interaction back into scope.