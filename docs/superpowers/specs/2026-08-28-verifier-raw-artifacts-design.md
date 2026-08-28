# Design — Persisted Verifier Raw Artifacts

**Date:** 2026-08-28
**Status:** Draft (design). Awaiting review; implementation plan pending.
**Scope:** Optionally retain the verbatim protocol artifacts of a verification —
the signed Request Object served to the wallet and the decrypted `vp_token` it
returned — in a separately-expiring storage row, and expose them on
`GET /admin/verification/requests/{id}`.

---

## 1. Problem

When a wallet rejects a presentation request, or returns a presentation foundry
rejects, the bytes involved cannot be reconstructed after the fact: the nonce
and the ephemeral key are per transaction, and the `vp_token` exists only as a
local variable inside `do_verify_vp_response`.

Foundry already records these bytes — but **only to the log stream**, and only
under `--log-sensitive` at `trace` level
(`docs/manual/verification/request-diagnostics.md`). That has three limits:

1. **It is not addressable.** Diagnosing transaction `v_1a2b3c` means grepping a
   log stream that may be shipped elsewhere, rotated, or not captured at all.
2. **It must be enabled before the failure.** `--log-sensitive` is a process-start
   flag. A failure observed in a deployment running without it is unreproducible;
   the operator restarts with the flag and waits for the wallet to fail again.
3. **Its retention is the log system's, not foundry's.** Holder PII in a log
   stream inherits whatever retention the aggregator applies — typically far
   longer than a debugging window, and outside foundry's control.

The request is therefore to retain the same artifacts **as data**, addressable by
transaction id through the existing admin API, under a retention window foundry
enforces itself.

## 2. Decisions

Decisions taken during brainstorming, with the alternatives rejected.

| # | Decision | Rejected alternative |
| --- | --- | --- |
| D1 | Retention is **config-gated, default off** (`verifier.persist_raw_artifacts`) | Unconditional persistence; persist-always but gate only the exposure |
| D2 | One nullable `request_object_jws` field covering **both signed transports** (`request_uri`, `dc_api_signed`); unsigned `dc_api` leaves it `null` | A union-typed field also holding the unsigned `dc_api` JSON object; covering `dc_api_signed` only |
| D3 | The `vp_token` is captured **at extraction**, before any check runs, so it survives a failed verification | Capturing on the success path only, via `VerifyOutcome` |
| D4 | Artifacts live in **their own storage row** under **their own TTL**, default **900 s** (`verifier.raw_artifacts_ttl_secs`) | Extra fields inside the existing transaction row, sharing `storage.transaction_ttl_secs` |
| D5 | A TTL inversion (`raw_artifacts_ttl_secs > storage.transaction_ttl_secs`) is a **startup warning**, not a rejection and not a silent clamp | Reject at `validate()`; clamp to `min(raw, transaction)` |
| D6 | `GET /vp/request/:id` **serves the stored JWS when present**, falling back to rebuilding when absent | Store an eagerly-built copy and document that its signature differs from the served one |
| D7 | The raw compact **JWE is not retained** — a decryption failure yields no artifact | A third artifact field under the same flag and TTL |
| D8 | The transaction row **never** carries raw artifacts, under any configuration — `save_verification_transaction` strips them unconditionally | Rely on callers to clear them before saving |
| D9 | Nothing new is written to the **log** stream except a contents-free presence record | Log the artifacts at persist time; log nothing at all |

## 3. Verified Technical Facts

Verified against this repository at commit `21e0df6` on 2026-08-28. Each fact
below constrains a decision above; none is recalled or assumed.

- **`get_kv` does not filter on `expires_at`.** `crates/foundry-core/src/storage/sqlite.rs:53`
  selects on `(namespace, key)` only. Expiry is enforced *solely* by
  `purge_expired` (`sqlite.rs:94`), which the sweeper runs on a **60-second**
  period (`spawn_sweeper(storage, 60)`, `crates/foundry/src/server.rs:1913`).
  A TTL therefore means *deleted within ~60 s of nominal expiry*, and an expired
  row stays readable until the next sweep. D4's claim that PII is "evicted" is
  true; a claim that it becomes unreadable at the instant of expiry would not be.
- **`storage.transaction_ttl_secs` defaults to 600 s**
  (`crates/foundry-core/src/config/model.rs:109`), which is **shorter** than
  D4's 900 s default. At stock configuration, turning the flag on produces the
  inversion D5 warns about. This is why D5 rejects "reject at startup": a
  default-config operator flipping one boolean would get a hard boot failure.
- **ECDSA signing is randomized.** HAIP mandates ES256, so signing the same
  Request Object twice yields two different signatures. An eagerly-built JWS is
  therefore **not** byte-identical to one re-signed at fetch time — which is what
  forces D6. A field labelled "the request object the wallet received" whose
  third segment differs from the served copy cannot answer the question it
  exists for.
- **The Request Object payload is otherwise deterministic.**
  `build_signed_request_object` (`crates/foundry-verifier/src/request.rs:686`)
  inserts no `iat`, `exp`, or `jti`; header and payload are a pure function of
  `config` and `tx`. Only the signature varies between builds.
- **Verification transactions are never deleted.** No `delete_kv` call targets
  the `verification_tx` namespace (`delete_kv` users are
  `foundry-issuer/src/transaction.rs:210,223` only). Both rows are reclaimed by
  the sweeper and nothing else, so the raw row needs no deletion hook on state
  transitions. This answers an open question raised during brainstorming.
- **`logging::init` runs before `cfg.validate()`** (`crates/foundry/src/main.rs:18`
  and `:38`), so a `tracing::warn!` emitted inside `validate()` is captured by the
  configured subscriber. D5's warning is therefore visible.
- **`do_verify_vp_response` is crate-private**
  (`crates/foundry-verifier/src/verify.rs:1281`); changing its signature is an
  internal refactor. `save_verification_transaction` **is** public and re-exported
  (`crates/foundry-verifier/src/lib.rs:19`), so changing *its* signature is an
  API change — see §7 O1.
- **`get_verification_handler` returns the transaction verbatim**
  (`crates/foundry/src/server.rs:1349`), including `ephem_private_jwk`. The route
  is admin-key-gated; `docs/conformance/openid4vc-conformance.md` VP-0185 records
  this as the OpenID4VP L1880 "internal interface" protection. New optional
  fields surface automatically once `openapi.json` is regenerated.

## 4. Design

### 4.1 Configuration

Two fields on `VerifierConfig` (`crates/foundry-core/src/config/model.rs`),
already added to the tree:

```yaml
verifier:
  persist_raw_artifacts: false      # default
  raw_artifacts_ttl_secs: 900       # default (15 minutes)
```

`Config::validate()` gains one non-fatal check: when `persist_raw_artifacts` is
on and `raw_artifacts_ttl_secs > storage.transaction_ttl_secs`, emit a
`tracing::warn!` naming both values and the consequence — the artifacts outlive
the transaction that addresses them, so the admin route 404s while the PII
lingers unreachable until swept.

### 4.2 Storage

A new namespace, `verification_raw`, keyed by transaction id, holding:

```rust
pub struct RawArtifacts {
    pub request_object_jws: Option<String>,
    pub vp_token: Option<serde_json::Value>,
}
```

written with `expires_at = now_unix + raw_artifacts_ttl_secs`, independent of
the transaction row's own expiry. A separate row — rather than fields inside the
transaction row — is what makes the TTL mean *deleted* rather than *hidden*: the
storage layer expires whole rows, and there is no mechanism to expire a subset
of one row's fields.

### 4.3 In-memory carriage

The same two fields are added to `VerificationTransaction`, serialized with
`#[serde(default, skip_serializing_if = "Option::is_none")]`. They exist there
for two reasons only: as the sink `do_verify_vp_response` writes into (D3), and
as the shape the admin response hydrates into (§4.6). `skip_serializing_if` is
load-bearing twice — a flag-off deployment's admin response is byte-identical to
today's, and transactions already in storage still deserialize.

### 4.4 The single choke point

`save_verification_transaction` gains a `raw_ttl_secs: Option<u64>` parameter
(`None` = flag off) and becomes the one place artifacts move between memory and
storage. It:

1. **Unconditionally** clears `request_object_jws` and `vp_token` from the value
   it serializes into `verification_tx` — the invariant of D8, which holds even
   if a caller left them populated with the flag off. The signature stays
   `&VerificationTransaction`, so this operates on a local copy and never
   mutates the caller's transaction: a caller that reads `tx.vp_token` after
   saving still sees it;
2. when `raw_ttl_secs` is `Some` **and** at least one artifact is populated,
   writes the `verification_raw` row under that TTL;
3. emits one always-on `debug` record naming `tx_id` and `ttl_secs` and **which**
   artifacts were retained — presence only, never contents, in the manner
   `create_offer` already records EMVCo display metadata (root AGENTS.md §4.5).

`load_verification_transaction` is deliberately **not** changed. Hydrating there
would add a wasted `get_kv` to the wallet-facing `POST /vp/response/:id` path,
which never needs the artifacts.

### 4.5 Write points

**`create_verification_request`** (`request.rs`) — reordered so the transaction
is constructed, the Request Object built, the field assigned, and only then the
transaction saved:

- `request_uri`: with the flag on, the JWS is now built **eagerly** at creation
  rather than lazily per fetch.
- `dc_api_signed`: the JWS is already built at creation (`request.rs:450`) but
  *after* the save; the fork is reordered to build before saving and to reuse
  that same JWS in the response, so the stored and returned bytes are one object.
- `dc_api`: no signed form exists; the field stays `None`.

The existing non-empty `expected_origins` check (OpenID4VP L2442) must remain
*before* the save, as it is today.

One consequence to accept deliberately: with the flag on and the `request_uri`
transport, a **signing failure now surfaces at `POST /admin/verification/requests`
instead of at `GET /vp/request/:id`**. This is a strict improvement — the
operator who caused it sees it — but it is a change in when errors appear.

**`do_verify_vp_response`** (`verify.rs:1281`) — takes `&mut VerificationTransaction`
and assigns `tx.vp_token` immediately after extraction (`verify.rs:1318`), before
any check runs, so both the `Ok` and `Err` paths retain it. The assignment is
gated on `persist_raw_artifacts`, so a flag-off deployment does not even clone
the value. The call site in `verify_vp_response` reborrows.

### 4.6 Read points

**`GET /admin/verification/requests/{id}`** — loads the transaction as today,
then, **only when the flag is on**, loads the `verification_raw` row and hydrates
the two fields onto the response. Response type and schema are unchanged; the
fields are optional. Gating the extra `get_kv` on the flag keeps a flag-off
deployment's cost identical to today's.

**`GET /vp/request/:id`** (wallet-facing) — per D6, serves the stored JWS when
present and rebuilds when absent. The lookup is gated on the flag, so a flag-off
deployment takes exactly today's path. The fallback is not decorative: the raw
row has its own TTL, so an operator who configures `transaction_ttl_secs` longer
than `raw_artifacts_ttl_secs` will have live transactions whose artifact row has
already been swept.

### 4.7 Relationship to the existing log diagnostics

This feature does not replace `docs/manual/verification/request-diagnostics.md`
and does not change it. The two are the same bytes through different channels:

| | Log diagnostics | Persisted artifacts |
| --- | --- | --- |
| Enabled by | `--log-sensitive` + `RUST_LOG=trace`, at process start | `verifier.persist_raw_artifacts`, at process start |
| Addressed by | grepping `tx_id` in a log stream | `GET /admin/verification/requests/{id}` |
| Covers | Request Object (all transports) + `decrypted_response` | Request Object (signed transports) + `vp_token` |
| Retention | the log aggregator's | `raw_artifacts_ttl_secs`, enforced by the sweeper |

## 5. Security & Privacy

- A retained `vp_token` is **holder PII in the clear** — SD-JWT disclosures or
  mdoc `IssuerSignedItem`s exactly as presented. This is the entire reason for
  D1 (default off) and D4 (its own, shorter TTL).
- Exposure is bounded by the existing admin-key gate on `admin_router`'s
  `authenticated` group (`crates/foundry/src/admin_auth.rs`), the same control
  VP-0185 already records for this route. No new exposure surface is created —
  the route already returns `ephem_private_jwk`.
- Root AGENTS.md **§4.5 is untouched**. Exactly two new log records exist, and
  neither carries an artifact: the contents-free presence line of §4.4, and the
  startup TTL-inversion warning of D5 (which names two configured integers).
  `instrumentation_hygiene.rs` and `logging_redaction.rs` should need no
  changes; that they do not is itself a test assertion (§6).
- The TTL is a *deletion* guarantee with a ~60 s sweep granularity, per §3. The
  documentation must say that, not imply instant expiry.

## 6. Testing Strategy

TDD throughout — each behaviour gets a failing test first. The gate is root
AGENTS.md §5.1 (`cargo fmt`; `cargo nextest run --workspace --no-fail-fast
--status-level fail`; `cargo clippy --workspace --all-targets -- -D warnings`),
plus `mkdocs build --strict` for the doc changes.

| Area | Test | Location |
| --- | --- | --- |
| Config default | `raw_artifacts_ttl_secs` defaults to 900 when the key is absent | `foundry-core` config tests |
| Config warning | flag on + TTL inversion emits the warn; no inversion emits nothing | `crates/foundry/tests/` (log capture available there) |
| D8 invariant | a tx with both artifacts populated, saved with `raw_ttl: None`, round-trips with both `None` and the stored row absent | `foundry-verifier/src/transaction.rs` |
| Separate TTL | `purge_expired(now + 901)` removes the raw row while a 3600 s transaction row survives | `foundry-verifier/src/transaction.rs` |
| D2 coverage | flag on ⇒ `request_object_jws` present for `request_uri` and `dc_api_signed`, absent for `dc_api`; flag off ⇒ absent for all three | `foundry-verifier/src/request.rs` |
| D2 identity | for `dc_api_signed`, the stored JWS is the same string returned in `dc_api_request.request` | `foundry-verifier/src/request.rs` |
| D3 (the point) | `vp_token` is retained after a **failed** verification | `foundry-verifier/src/verify.rs` |
| D6 | `GET /vp/request/:id` returns the stored JWS byte-for-byte when present, and rebuilds successfully after the raw row is swept | `crates/foundry/tests/wallet_verification.rs` |
| Exposure | admin GET exposes both fields with the flag on, and neither with it off | `crates/foundry/tests/wallet_verification.rs` |
| §4.5 | no artifact contents appear in any log record, flag on, at trace level | `crates/foundry/tests/logging_redaction.rs` |

## 7. Open Questions

**O1 — `save_verification_transaction`'s public signature.** Adding
`raw_ttl_secs: Option<u64>` is a breaking change to a `pub` re-exported function.
The alternative is a second entry point (`save_verification_transaction_with_artifacts`)
leaving the original intact. **Recommendation: change the signature.** With the
fields present on `VerificationTransaction`, an untouched `save_*` that does not
strip them would serialize holder PII into the *transaction* row under the
*transaction* TTL — precisely the outcome D4 and D8 exist to prevent. Forcing
every call site to state its intent removes that footgun; leaving a
silently-wrong overload in place preserves it. The blast radius is small: two
production call sites (`request.rs:429`, `server.rs:1694`) and two test sites.

**O2 — Raw-row lifecycle on state transitions.** Answered by §3: no code path
deletes a verification transaction, so both rows are reclaimed by the sweeper
alone and no deletion hook is required. Recorded here because it was raised as
an open question and its answer is a fact about the tree, not a decision.

**O3 — Strip-at-save versus a response projection type.** §4.4 keeps
`VerificationTransaction` as both the storage type and the admin response type,
stripping fields on the way out. The alternative is an `AdminVerificationStatus`
projection, mirroring the existing `AdminIssuanceStatus` — whose own doc comment
notes it is "deliberately not the whole transaction, unlike
`get_verification_handler`". That would separate the two concerns properly and
would also let `ephem_private_jwk` drop out of the admin response.
**Recommendation: keep strip-at-save for this change, and treat the projection
as separate work.** Introducing it here would change the admin response's schema
name and its contents in the same commit that adds a feature, mixing a security
improvement into a diagnostics change. It should be its own spec.

**O4 — Should the flag also gate an artifact for the unsigned `dc_api`
transport?** D2 says no, so a `dc_api` transaction retains only its `vp_token`.
The unsigned request object is currently recoverable only from the
`dc_api_request` trace log. Flagged rather than decided: closing it means either
a union-typed field or a second nullable field, both of which were rejected once
already.

## 8. Files Touched

| File | Change |
| --- | --- |
| `crates/foundry-core/src/config/model.rs` | Two `VerifierConfig` fields + `default_raw_artifacts_ttl()` — **already applied** |
| `crates/foundry-core/src/config/validate.rs` | D5 warning |
| `crates/foundry-verifier/src/transaction.rs` | `RawArtifacts`, `verification_raw` namespace, save/load, `save_verification_transaction` signature |
| `crates/foundry-verifier/src/request.rs` | Eager Request Object build + reordering |
| `crates/foundry-verifier/src/verify.rs` | `&mut` signature, `vp_token` capture at extraction |
| `crates/foundry/src/server.rs` | Admin hydration; `GET /vp/request/:id` serve-then-fallback |
| `crates/foundry/src/commands.rs` | Sample-config comment block — **already applied** |
| 24 `VerifierConfig` literals across the workspace | Two new fields — **already applied** |
| `openapi.json` | Regenerated (`foundry openapi --out openapi.json`) |
| `docs/manual/reference/configuration.md` | The two new config keys |
| `docs/manual/verification/request-diagnostics.md` | §4.7's comparison, so the two channels are documented together |
| `crates/foundry-verifier/AGENTS.md` | Gotchas: the D8 invariant and the two-row lifecycle |

## 9. Out of Scope

- Retaining the raw compact JWE (D7), and with it any artifact for a
  decryption-stage failure.
- The `AdminVerificationStatus` projection and removing `ephem_private_jwk` from
  the admin response (O3).
- Any change to the existing log-diagnostics behaviour or to root AGENTS.md §4.5.
- Encryption at rest for the retained artifacts. The storage layer offers none
  today, and adding it for one namespace would be a storage-layer design, not a
  verifier one.
