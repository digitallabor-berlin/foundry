# GAP-VCI-14 — Client Attestation Proof-of-Possession Verification — Change Record

**Date:** 2026-08-01
**Branch:** `superlight/2026-08-01-gap-vci-14-client-attestation-pop`
**Spec:** [`../specs/2026-08-01-gap-vci-14-client-attestation-pop-spec.md`](../specs/2026-08-01-gap-vci-14-client-attestation-pop-spec.md)
**Plan:** [`../plans/2026-08-01-gap-vci-14-client-attestation-pop-plan.md`](../plans/2026-08-01-gap-vci-14-client-attestation-pop-plan.md)

## Why

GAP-VCI-14 was filed by the 2026-08-01 Tier 1 run *against itself*. That run
closed GAP-HAIP-04 by making `validate_wallet_attestation_jwt` genuinely
verify the `OAuth-Client-Attestation` header — signature, `x5c` chain to a
configured anchor, `exp`/`nbf`, `cnf.jwk` and `sub` presence — and then
recorded, honestly, that it had implemented only half of a two-half mechanism.

The other half is the **Client Attestation PoP JWT**. Nothing in the workspace
read the paired `OAuth-Client-Attestation-PoP` header; `handle_token_request`
had no parameter for it. The consequence is the one that makes the whole
mechanism worth having:

> A Wallet Attestation JWT is a **bearer** credential until something proves the
> presenter holds the key it attests to.

The attestation travels in a plaintext HTTP header, is long-lived by design,
and is deliberately reusable across requests (ABCA §10.2). Anyone who observed
one — a proxy log, a captured request, a compromised intermediary — could
replay it verbatim and be authenticated as that wallet. foundry accepted a
stolen attestation identically to a legitimate one, so `mode: required` bought
an audit trail, not authentication.

Two clauses cited the gap: **VCI-0232** (OpenID4VCI Wallet Attestation, L2600)
and **HAIP-0088** (Requirements for Digital Signatures, L353 — "including proof
of possession", the clause whose second half was untrue).

### The authority question came first

OpenID4VCI Appendix E does not define the PoP wire format; it incorporates
`draft-ietf-oauth-attestation-based-client-auth` by reference (L1600, L2564,
L2600). Neither that draft nor the ABCA text was in `docs/specs/`, so per
AGENTS.md §4.4 there was no legitimate basis to write any of this code — the
rule explicitly forbids inferring a wire format from memory or from other
implementations.

So Task 1 vendored **draft -07** verbatim (1624 lines, kept as `.txt` rather
than converted to `.md`: verbatim fidelity is the entire point of a pinned
draft) and added it as a fourth row to the §4.4 spec table. Everything
downstream cites it.

That mattered immediately, because memory would have been wrong. **ABCA removed
`exp` from the PoP JWT in draft -06.** A PoP carrying an `exp` — even an expired
one — must be *accepted*, since §5.2 rule 1 requires unrecognised claims to be
ignored. An implementation written from recollection of JWT convention would
have added an `exp` check and rejected conformant wallets. The behaviour is now
pinned by `accepts_pop_with_an_already_expired_exp_claim` specifically so a
future reader does not "fix" it.

### Two design calls the gap register had deferred

The Tier 1 run named these as its reason for deferring:

**Replay store.** ABCA §10.6/§12.1 require `jti` replay detection. A
get-then-put check would have been TOCTOU-racy, so this added
`Storage::insert_kv_if_absent` — `INSERT ... ON CONFLICT DO NOTHING` with
`rows_affected() == 1` as the claim signal — as a genuine atomic primitive
distinct from `put_kv`'s upsert. The key is `B64URL(SHA-256(iss ‖ 0x00 ‖ jti))`,
**not** the bare `jti`: a bare-`jti` namespace would let one wallet pre-claim
`jti` values and deny service to every other wallet. It also keeps the raw,
attacker-controlled `iss`/`jti` out of the SQL key and out of anything derived
from it.

**`aud` policy.** Exact match only, no prefix matching, no case-insensitivity,
no config escape hatch. `expected_aud` is sourced from
`build_authorization_server_metadata(&config).issuer` rather than re-derived
from `config.issuer.credential_issuer`, so the value published at
`/.well-known/oauth-authorization-server` and the value a PoP is checked
against cannot drift apart.

## What Changed

### `foundry-core` — the atomic primitive and the knob (`5183bee`, `7242464`)

`Storage::insert_kv_if_absent(namespace, key, value, expires_at) -> Result<bool, _>`
plus its SQLite implementation. `false` means "already claimed" and leaves the
existing row entirely untouched — value *and* `expires_at` — which is what makes
it a claim rather than an upsert.

`AttestationMode.pop_max_age_secs: u64` (serde default 300). This rippled to 44
struct literals across 19 files; isolating that churn into its own task was
deliberate. The mechanical pass initially mangled a `-> AttestationMode {`
return type, which was caught by a full revert and a corrected brace-aware
re-run rather than by patching over it.

### `foundry-issuer` — the verifier (`47e1c53`, `45ea004`, `d7714e4`)

`validate_wallet_attestation_jwt` now returns `ValidatedAttestation { sub,
cnf_jwk }` instead of `()` — those are exactly the two values the PoP is checked
against, and returning them beats re-parsing.

`validate_client_attestation_pop_jwt` implements nine checks, each citing its
ABCA clause: JWS structure, `typ`, `alg == ES256` (ABCA §9 rule 4 permits any
registered asymmetric algorithm; HAIP-0088 narrows it), signature against the
attestation's `cnf.jwk`, `iss == sub`, `aud` exact match, `jti` presence, `iat`
sliding window, `nbf` skew. `POP_CLOCK_SKEW_SECS = 60`, applied only to
future-dated values.

`claim_pop_jti` performs the anti-replay claim. It takes no `now_unix`: the TTL
derives from the PoP's own `iat`, which the validator has already bounded
against `now`, and passing `now` again would create a second source of truth for
one fact.

Verification stays **synchronous and storage-free**; the replay claim is a
separate `async` step. That keeps `Storage` out of the crypto unit tests
entirely.

### `foundry-issuer` — the mode matrix and the token endpoint (`39ce70a`, `c00e951`)

`verify_wallet_attestation` returns `Result<Option<PopClaims>, IssuanceError>`
over a fully enumerated 9-row matrix (`Disabled`/`Optional`/`Required` ×
attestation present/absent × PoP present/absent), one test per row. The row that
matters: **a present attestation with no PoP is rejected under `Optional` too**,
not just `Required` (ABCA §6.2 rule 2). `Optional` means "you may present
nothing", never "you may present half".

`handle_token_request` calls `claim_pop_jti` **strictly before any grant work**,
so a replayed PoP can never burn a legitimate holder's `pre-authorized_code`.
There is a test for exactly that ordering
(`pop_replay_rejection_does_not_burn_the_pre_authorized_code`), because getting
it backwards would turn a replay attempt into a denial of service against the
real wallet.

ABCA §6.3 is then one comparison: `client_id == claims.iss`. Check 5 already
proved `claims.iss == attestation.sub`, so the two spec-named requirements are
the same value by construction.

### `foundry-issuer` — error taxonomy (`08147e0`)

New `IssuanceError::InvalidClient(String)` → HTTP 400 `{"error":
"invalid_client"}` per RFC 6749 §5.2, which ABCA §6.2 confirms is the correct
general code. 21 of `attestation.rs`'s 22 `InvalidRequest` sites migrated; the
holdout is documented below.

### `crates/foundry` — HTTP wiring (`5eabfb3`)

`token_handler` reads both headers and sources `issuer_identifier` from the
published AS metadata. axum's `HeaderMap` is already case-insensitive per
RFC 9110, which satisfies ABCA §6.1 with no extra normalisation — verified by a
test that sends the header lower-cased rather than assumed.

### Review fixes (`922db32`)

Phase 5 ran two independent fresh-eyes reviews. Both found the core PoP path
sound with no bypass; both also hit their turn budget with items unverified,
which were then closed by hand. Three real spec gaps surfaced:

**ABCA §9 rule 6 was not implemented at all** — "The key contained in the `cnf`
claim of the Client Attestation JWT is not a private key." This one is worth
dwelling on, because it fails silently in the worst direction:
`ES256.verifier_from_jwk` builds a perfectly good verifier from a *private* JWK
(it reads `x`/`y` and ignores `d`), so the PoP signature check would **succeed**.
A private key in `cnf` means the Attester leaked the wallet's signing key into a
JWT that travels in a plaintext header — anyone who sees one attestation can
mint PoPs for that wallet indefinitely. Now rejected across every key type's
private parameters (RFC 7518 §6.2.2/§6.3.2/§6.4.1, RFC 8037 §2), naming the
offending parameter but never its value.

Why it was missed is itself worth recording: the first review verified the nine
checks against **§5.2's claim list** and correctly reported them complete. Rule 6
lives in **§9's separate 13-rule list**. §5.2 and §9 impose different,
non-overlapping requirements, and checking one is not checking the other.

**ABCA §6.2 rules 1–2 ("precisely one" of each header) were not enforced.**
`HeaderMap::get` returns only the first of several values, so a duplicated
header was processed against whichever copy arrived first with the rest
discarded unexamined — the shape where two intermediaries can disagree about
which value is authoritative. New `exactly_one_header` uses `get_all`. The same
helper closes an adjacent hole: `.and_then(|v| v.to_str().ok())` mapped a
non-UTF-8 value to `None`, i.e. to *absent*, and under `Mode::Optional` absence
is permitted — so an unreadable attestation header was accepted as "none
presented".

**Citation notation.** Code and spec cited "§9.4", "§9.7", "§9.13", "§6.2.3".
ABCA §9 and §6.2 are each a single flat numbered rule list with no subsections
(unlike §10, which genuinely has §10.1–§10.6), so those read as section numbers
a reviewer cannot find. Every referenced *content* was correct; only the
notation was wrong. Reformatted to "§9 rule 4" per AGENTS.md §4.4's "a wrong
citation is worse than none".

**Saturating arithmetic.** A reviewer flagged `now_unix - iat` as an `i64::MIN`
panic reachable from `POST /token`. That specific claim does not hold — josekit
rejects a negative `iat` during check 4, before check 8's arithmetic, which was
established by instrumenting the test rather than by reasoning about it. But two
real problems remained: `claim_pop_jti`'s `iat + max_age + skew` genuinely does
overflow (the new test panicked on that exact line), and `max_age_secs as i64`
is a lossy cast of a `u64` config value — `u64::MAX as i64` is `-1`, which would
make *every* PoP "older than the allowed max age". All four sites are now
saturating regardless of present reachability: the `i64::MIN` guard is an
incidental property of a third-party library's claim validation, not a contract
a security bound should rest on.

## Verification

Every gate clean at `922db32`: `cargo fmt --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, and `cargo test --workspace` at **591 passing / 0
failing / 22 ignored** (the ignored set is exactly the unclosed-gap tests).

Beyond the gates, three habits did the actual work:

**Every new negative test was confirmed genuinely red** by reverting the
corresponding fix and watching it fail, not by trusting that it would.

**That habit caught a vacuous test of my own, twice.** The non-UTF-8 header test
first ran under `Mode::Required`, where a header degraded to `None` is rejected
anyway because absence is itself an error — it passed with *and* without the fix.
Moved to `Mode::Optional`, it still passed either way, because a PoP present
with no attestation is rejected by the mode matrix for an unrelated reason. Only
`Mode::Optional` **and** no PoP makes absent+absent a genuine 200, so a 400 can
only mean the malformed header was noticed. Both dead ends are recorded in the
test's doc comment so the setup does not look arbitrary and get "simplified"
later.

**Claims in prose were re-derived, not trusted.** The conformance register's
counts were recounted from the file: OpenID4VCI 232 = 71+23+78+6+54, OpenID4VP
266 = 85+11+55+8+107, HAIP 96 = 46+8+11+7+20+4, gap register 20 rows. (A first
pass counted 100 HAIP rows — the extra 4 are the Unresolved Ambiguities section
re-listing the same 4 `ambiguous` clauses.) Similarly confirmed by reading the
code rather than the plan: `rejects_pop_with_hs256_alg_even_when_genuinely_hs256_signed`
uses a real `HS256.signer_from_bytes` rather than relabelling an ES256 header;
the `exp` test plants `now - 1_000_000`; both redaction tests capture at TRACE
with `sensitive_enabled()` off *and* on, use the sentinel
`Zzyzx-Planted-Pop-Jti-4471`, and assert the log is non-empty so the negative
assertions cannot pass vacuously; the pre-existing positive control still
passes; and README's YAML matches `config/model.rs` field-for-field.

## Conformance Impact

| Clause | Before | After |
|---|---|---|
| VCI-0232 | `gap` (GAP-VCI-14) | `conforming` |
| HAIP-0088 | `gap` (GAP-VCI-14) | `conforming` |

Gap register: **21 rows → 20**. Summary counts: OpenID4VCI conforming 70 → 71,
gap 24 → 23; HAIP conforming 45 → 46, gap 9 → 8. Totals unchanged.

The gap test was renamed from
`vci_0232_wallet_attestation_pop_jwt_is_never_verified` to
`vci_0232_rejects_a_wallet_attestation_presented_without_a_pop_jwt` and
un-`#[ignore]`d — the old name asserted the bug rather than the requirement,
which is fine for a gap tripwire and wrong for a permanent regression test.

## Behaviour Change (Operator-Facing)

**A Wallet Attestation presented without a matching
`OAuth-Client-Attestation-PoP` header is now rejected with HTTP 400
`invalid_client`, under both `required` and `optional` mode.** It was previously
accepted outright.

Deployments running `wallet_attestation.mode: required` — or `optional` with
wallets that send an attestation — **must upgrade the wallet client to send the
PoP header before upgrading the issuer**, or existing wallets will start failing
`/token`. Documented in README's new "Wallet Attestation & Client Attestation
Proof-of-Possession" section along with `pop_max_age_secs`, the exactly-once
header rule, and the `cnf`-must-be-public rule.

## Deviations From the Plan

- **`KeyAttestationVerifier::verify_key_attestation` was left on
  `InvalidRequest`**, excluded from Task 5's migration of the other 21 sites.
  It is an unused trait method (no caller anywhere) for a *different* mechanism —
  OpenID4VCI Appendix D credential-key attestation, not OAuth client auth.
  Migrating it would have been scope creep with a real chance of the wrong error
  semantics if it ever gets a non-`/token` caller. During Phase 5 this produced a
  documentation hazard worth noting: the near-identically-named free function
  `verify_key_attestation_jwt` *is* live (called from `proof.rs`), so the initial
  AGENTS.md wording invited concluding "key attestation is dead code" wholesale.
  The gotcha now breaks all three entry points out explicitly.

- **Placeholder-then-wire across Tasks 8→9→10.** Each signature change made a
  minimal compile-preserving update to its downstream caller with a `TODO`,
  wired properly in the following task. This keeps every commit building and
  every task's test run meaningful, at the cost of two commits that briefly
  contain a knowingly-inert call site.

- **`token.rs` needed no changes in Task 5**, contrary to the plan's file list —
  it calls the trait method, whose signature did not change until Task 8.

- **OpenAPI was regenerated after all.** Task 11 concluded no regeneration was
  needed, which was correct as stated: `/token` documented only `status = 200`,
  so the `invalid_request` → `invalid_client` change had no visible surface. But
  that also revealed the *pre-existing* `OAuth-Client-Attestation` header was
  undocumented, and this branch materially expands `/token`'s request contract.
  Both headers and the 400 response are now declared;
  `openapi-wallet.json` changed, `openapi.json` did not (`/token` is
  wallet-facing only).

- **Test fixtures must use real wall-clock time.** `pki::new_ca`/`issue_leaf`
  stamp validity windows via `now_utc()` with no injectable clock, so fixed-epoch
  fixtures produce spurious `Trust(Expired)` failures. Cost six failures in
  Task 9 before the cause was found.

## Follow-Ups

Not blockers; none has a filed gap unless noted.

- **ABCA §10.1 metadata advertisement** — the AS does not publish that it
  supports attestation-based client authentication. Deliberately out of scope
  this run (verification only).
- **Wallet-side PoP generation** — `foundry-wallet` cannot produce a PoP, so it
  cannot exercise `mode: required` end-to-end against itself. Also deliberately
  deferred.
- **ABCA §8.1 server-provided challenge** (`use_attestation_challenge`,
  `OAuth-Client-Attestation-Challenge`) — not implemented. Check 8's `iat`
  window is the freshness mechanism instead, which §9 rule 9 explicitly permits
  as the alternative.
- **Pre-existing parallel-test flake**, confirmed present on a base commit
  before this work and *not* introduced here: `log_capture`'s
  `each_mapper_logs_exactly_one_record`, `level_follows_status_class`, and
  `detail_is_length_capped` in `crates/foundry/src/server.rs` fail
  intermittently under parallel `cargo test` (2 of 5 base-commit runs failed, on
  *different* tests each time) and pass consistently under `--test-threads=1`.
  The harness appears to share process-global state across tests. Worth its own
  investigation.