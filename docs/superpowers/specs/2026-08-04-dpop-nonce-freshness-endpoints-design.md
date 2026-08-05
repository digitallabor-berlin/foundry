# DPoP Nonces at the Unauthenticated Freshness Endpoints

**Date:** 2026-08-04
**Status:** approved
**Roadmap item:** Google Wallet compatibility — a gap discovered while re-reading
the vendor profile after items **A**, **B** and **C** had merged. It is not one
of the original five sub-projects; see §10.
**Sources:** `docs/specs/google-wallet-openid4vci-profile.md` (added by this
change) · RFC 9449 §8, §8.2, §9 · OpenID4VCI 1.1 WG draft §8.2-4 (cited by the
vendor profile; **not** pinned in this repository) ·
`draft-ietf-oauth-attestation-based-client-auth-07` §8

## 1. Problem

Google Wallet's OpenID4VCI implementation expects a `DPoP-Nonce` response header
at two endpoints where foundry does not emit one:

> **Token Endpoint** — DPoP is supported and required. DPoP Nonce is expected to
> be returned from the Challenge endpoint header. Note: this is not
> standardized. Meanwhile, there's an active effort to standardize this way of
> retrieving the DPoP nonce, similar to how it's already been standardized to
> retrieve the Credential endpoint DPoP nonce from the c_nonce endpoint.

> **Credential Endpoint** — DPoP, credential_request_encryption, and
> credential_response_encryption is supported and required. DPoP Nonce is
> expected to be returned from the c_nonce endpoint.

Both of the vendor's own examples show it:

```
HTTP/1.1 200 OK                     HTTP/1.1 200 OK
Content-Type: application/json      Content-Type: application/json
Cache-Control: no-store             Cache-Control: no-store
DPoP-nonce: eyJ7S_zG.eyJH0-Z...     DPoP-Nonce: eyJ7S_zG.eyJH0-Z...

{                                   {
  "attestation_challenge": "…"        "c_nonce": "wKI4LT17ac15ES9bw8ac4"
}                                   }
```

Foundry implements RFC 9449 §8/§9 server-provided nonces (roadmap item **B**,
merged 2026-08-04) and emits `DPoP-Nonce` on `/token` success responses, on
`/token`'s 400 `use_dpop_nonce` error, and on `/credential`'s 401 challenge.
It does **not** emit one from `POST /nonce` or `POST /challenge`: both handlers
return a fixed single-element header array carrying only `Cache-Control:
no-store` (`crates/foundry/src/server.rs`, `nonce_handler` and
`challenge_handler`).

A wallet that expects to obtain its first nonce from one of those two endpoints
therefore has no nonce to put in its first `/token` DPoP proof. Under
`nonce_mode: required` that request is rejected with `use_dpop_nonce`, and the
wallet only then learns the nonce from the error response — an extra round trip
the vendor's flow does not perform. This is an interop blocker, not a
conformance defect: no pinned specification requires either header.

### Conformance standing of the two endpoints differs

- **`/nonce`** — the vendor profile cites OpenID4VCI **1.1 WG draft §8.2-4**,
  and states this retrieval path "has already been standardized". This
  repository pins OpenID4VCI **1.0**, which has no such rule. Emitting the
  header here anticipates a standards-track direction; it does not implement a
  pinned requirement.
- **`/challenge`** — standardized nowhere. The vendor profile says so in as many
  words ("Note: this is not standardized"). ABCA draft -07 §8, which foundry
  pins and which defines this endpoint, mentions no DPoP interaction at all.

Neither header is forbidden by any pinned specification, so emitting both is
additive rather than divergent. §3.3 records how the vendor profile is allowed
to justify behaviour without becoming a licence to violate a spec.

## 2. Scope

**In scope.** A `DPoP-Nonce` header on the success responses of `POST /nonce`
and `POST /challenge`, gated on the existing `issuer.dpop.nonce_mode`; pinning
the vendor profile into `docs/specs/` with a root `AGENTS.md` §4.4 row and a
precedence clause for vendor profiles; the documentation and OpenAPI updates
those two changes oblige.

**Out of scope.** Each of the following was identified while reading the vendor
profile and is deliberately excluded, so that a two-handler change does not
become a compound one:

- **Roadmap item D** — the `android_keystore_attestation` proof type. The vendor
  profile shows `proofs: { android_keystore_attestation: [[cert, …], …] }`:
  arrays of X.509 chains, not JWTs. `ProofsRequest` carries only
  `jwt: Vec<String>` and `handle_credential_request` reads `p.jwt` directly, so
  this is a new proof type rather than an extension of
  `verify_key_attestation_jwt`. Its own spec, plan and review cycle.
- **Roadmap item E** — the credential-type shape: SD-JWT with
  `vct = com.emvco.dpc.card` (an EMVCo Digital Payment Credential).
- **Bumping the ABCA pin from -07 to -10.** The vendor profile cites draft-10
  §6.1 for the challenge endpoint where foundry pins -07 §8. The wire shape
  foundry already emits matches the vendor's example byte for byte
  (`{"attestation_challenge": "…"}`), so the skew has no behavioural
  consequence today. Bumping a pinned draft is its own deliberate change per
  root `AGENTS.md` §4.4 and must not be smuggled into this branch.
- **RFC 9421 HTTP Message Signatures.** The vendor's Credential Request example
  carries `Content-Digest`, `Signature` and `Signature-Input` headers. Nothing
  in the requirements table mentions them and nothing in the workspace
  implements them. Whether they are required, or an artifact of a copied
  example, is unresolved and must be confirmed with Google before any work
  starts.
- **`credential_identifier` support.** The vendor's example request carries it;
  foundry deliberately does not support it (`credential.rs`: this issuer never
  returns `credential_identifiers`, so `credential_configuration_id` is
  REQUIRED). Same open question as above — the example's value,
  `"CivilEngineeringDegree-2023"`, is the OpenID4VCI specification's own
  illustrative value, which suggests the body was copied rather than captured.
- **`wallet_name == "Google Wallet"`.** The profile records it under Wallet
  (Client) Attestation. Whether foundry should *verify* that claim or merely
  tolerate it is undecided; `wallet_name` appears nowhere in the workspace.

**Rollout posture: no new configuration.** The change is gated entirely on the
existing `issuer.dpop.nonce_mode`, whose default is `disabled`. An unconfigured
deployment's `/nonce` and `/challenge` responses stay byte-identical to today's.

## 3. Design

### 3.1 The gate: reuse `issuer.dpop.nonce_mode`

`dpop_nonce_header(&state, now_unix) -> Option<(HeaderName, HeaderValue)>`
already exists in `crates/foundry/src/server.rs`, already returns `None` when
`issuer.dpop.nonce_mode == Mode::Disabled`, and already mints with
`dpop.max_age_secs` as the TTL. It is reused verbatim; no new helper and no new
configuration key.

Three alternatives were considered and rejected:

1. **A dedicated toggle for `/challenge` only** (`nonce_on_challenge_endpoint`),
   on the grounds that this endpoint's behaviour is standardized nowhere.
   Rejected: it adds a knob guarding a response header the operator already
   opted into by enabling `nonce_mode`, so the knob encodes no decision the
   operator has not already made.
2. **A single vendor-named toggle** (`google_wallet_compat`). Rejected: it would
   be the first vendor-named configuration key in the tree, and a key named
   after a company invites a second one. The vendor-specific justification
   belongs in a code comment and in §4.4, where it is auditable, not in an
   operator's configuration file.
3. **Unconditional emission**, ignoring `nonce_mode`. Rejected: under
   `disabled`, `verify_dpop_proof` ignores a presented `nonce` claim entirely,
   so handing out a nonce the server will not check would advertise a freshness
   guarantee that does not exist.

The resulting semantics are stated once, in the README: *if server-provided DPoP
nonces are enabled, foundry supplies one from every unauthenticated freshness
endpoint it exposes.*

### 3.2 Handler changes

Both handlers currently return
`([(HeaderName, &'static str); 1], Json<T>)`. A fixed-size array cannot express
a conditionally absent header, so both become
`(HeaderMap, Json<T>)` — the shape `token_handler` already uses for exactly this
reason.

- **`nonce_handler`** — build a `HeaderMap`, insert `Cache-Control: no-store`
  (OpenID4VCI §7.2), then insert the nonce header when `dpop_nonce_header`
  returns `Some`.
- **`challenge_handler`** — identical, with the `Cache-Control` comment citing
  ABCA §8 as it does today.

Each insertion carries a comment naming the **vendor profile** as its source
rather than a specification section, because no pinned specification requires
it. The `/nonce` comment additionally names OpenID4VCI 1.1 WG draft §8.2-4 as
the standards-track direction it anticipates and states that this repository
still pins 1.0 — so a later reader does not mistake the citation for a pinned
requirement.

`HeaderMap::insert` (not `append`) on both, preserving RFC 9449 §8's "there MUST
NOT be more than one DPoP-Nonce header" by construction.

### 3.3 Pinning the vendor profile, and what it may justify

The document is checked in verbatim as
`docs/specs/google-wallet-openid4vci-profile.md`, alongside the five pinned
protocol specifications, and gains a row in root `AGENTS.md` §4.4.

It is a different *kind* of artifact from its neighbours: a record of one
wallet's implementation choices, not a standards-track text. §4.4's existing
precedence rule ("Where HAIP is stricter, HAIP wins") must therefore not extend
to it by analogy, or vendor accommodation would start reading as conformance.
The row is accompanied by an explicit clause:

> A **vendor profile** records one implementation's observable behaviour and
> requirements. It is normative only for what foundry does when accommodating
> that implementation. It is never grounds for violating a MUST in a
> standards-track specification above, and where the two conflict the
> specification wins and the conflict is recorded as a known limitation.
> Behaviour whose only justification is a vendor profile MUST carry a code
> comment naming the profile, so a reader can tell vendor accommodation from
> conformance.

Checking in the prose verbatim also brings the profile's embedded **real Android
Keystore attestation chains** (five four-certificate chains, captured from
Google Wallet) into the repository. Item D needs precisely that as its interop
oracle, and item A already pins one such chain in
`crates/foundry-core/tests/trust_chain_verification.rs`.

## 4. Why this is safe

- **Additive on a success path.** No status code, body, or existing header
  changes. A wallet that does not understand `DPoP-Nonce` ignores it; RFC 9449
  §8 already contemplates an authorization server supplying nonces
  proactively.
- **Inert by default.** Under `nonce_mode: disabled` — the default —
  `dpop_nonce_header` returns `None` and both responses are byte-identical to
  today's.
- **No new secret exposure.** The value is minted by the same
  `mint_dpop_nonce` already reachable from `/token`, under the same MAC secret
  and TTL. The endpoints are unauthenticated, but minting is stateless, so an
  anonymous caller cannot grow storage — the property that already justifies
  both endpoints being unauthenticated.
- **Domain-separated.** The value is minted under `challenge::Domain::DpopNonce`,
  so it cannot be replayed as an OpenID4VCI `c_nonce` or an ABCA
  `attestation_challenge`. §6 pins this with a test rather than trusting the
  construction.

## 5. Error handling and observability

No new error paths and no status-code changes, so root `AGENTS.md` §4.3 is
untouched by this branch.

`dpop_nonce_header` already discards a mint failure with `.ok()?`, which is the
behaviour `/token` has today. That is correct here for the same reason: the
nonce is an optimisation, not the response's purpose, and failing an otherwise
successful `/nonce` because a nonce could not be minted would deny the wallet
the `c_nonce` it actually asked for. The consequence — a silently absent header
— is identical to the `disabled` case the wallet must already tolerate.

No new log records and no new span fields. DPoP `nonce` values are on the
never-log list (root `AGENTS.md` §4.5; README "Logging & Observability"), and
stay there: §6 includes a behavioural test proving the minted value never
reaches a log record.

## 6. Testing strategy

All HTTP-level, extending the existing DPoP-Nonce block in
`crates/foundry/tests/conformance_http.rs` — which already holds
`successful_responses_carry_a_dpop_nonce_when_enabled`,
`exactly_one_dpop_nonce_header_is_emitted` and
`no_dpop_nonce_header_is_emitted_when_nonce_mode_is_disabled` — rather than a
new file, so the whole mechanism stays readable in one place.

| # | Test | What it pins |
|---|---|---|
| 1 | `/nonce` carries `DPoP-Nonce` under `nonce_mode: optional` and under `required` | the primary behaviour, both enabled modes |
| 2 | `/challenge` carries it under both modes | ditto for the second endpoint |
| 3 | Extend the existing disabled-mode test to assert **neither** endpoint emits it | the negative control; the default posture is unchanged |
| 4 | A nonce read from `/nonce` is **accepted** by a subsequent `/token` DPoP proof under `nonce_mode: required` | that the header carries a *usable* value, not merely a well-formed one — the test that would catch a wrong-`Domain` or wrong-TTL mint |
| 5 | `Cache-Control: no-store` still present on both | regression guard on the return-type change from array to `HeaderMap` |
| 6 | A `logging_redaction.rs` case: an enabled-mode `/nonce` and `/challenge` never log the minted value, including with `sensitive_payloads` enabled | §4.5 — key/freshness material is not unlocked by that flag |

Test 4 is the one that matters most. Tests 1–3 would pass against a handler
that emitted a syntactically valid but semantically useless header.

**Domain separation is deliberately not retested here.** `challenge.rs`'s own
unit tests already prove it exhaustively and in all three directions
(`a_c_nonce_is_rejected_as_a_dpop_nonce`,
`a_dpop_nonce_is_rejected_as_an_attestation_challenge`,
`an_attestation_challenge_is_rejected_as_a_c_nonce`). The property belongs to
the MAC construction, not to the transport; asserting it again over HTTP would
add a slower duplicate of a test that already exists, and would not fail for any
reason the unit tests would miss.

`openapi_endpoints.rs` already drift-tests both committed specs against
generator output as parsed JSON, so the OpenAPI regeneration in §7 is covered by
an existing test rather than a new one — and forgetting to regenerate fails the
suite rather than drifting silently.

## 7. Documentation changes

| File | Change |
|---|---|
| `docs/specs/google-wallet-openid4vci-profile.md` | **New.** The vendor document, verbatim, attestation chains included. |
| `AGENTS.md` §4.4 | New table row for the profile, plus the vendor-precedence clause quoted in §3.3. |
| `docs/conformance/openid4vc-conformance.md` | Extend RFC-9449-0008's evidence with the two new emission points and the new test names. Stays `conforming` — this widens evidence for an already-implemented MAY; it closes no gap and adds no row. |
| `README.md` §"Server-Provided DPoP Nonces (RFC 9449 §8/§9)" | Add the two endpoints to the list of places the header appears. The `disabled` bullet's "no `DPoP-Nonce` header is ever emitted" stays true and must be verified, not rewritten. |
| `openapi-wallet.json` | Both `#[utoipa::path]` response blocks document the header, then regenerate with `cargo run -p foundry -- openapi --wallet --out openapi-wallet.json` (root `AGENTS.md` §6). Note that `serve()` also overwrites both committed specs from the process working directory on startup, so an E2E run from the repo root can produce the same diff. |
| `crates/foundry/AGENTS.md` | Only if the handler-shape change invalidates something stated there; check, do not assume. |

## 8. Verification gate

Scoped, per root `AGENTS.md` §5.1. Only `crates/foundry` is touched —
`foundry-issuer` supplies `mint_dpop_nonce` but is not modified — so the
affected set is `foundry` alone and, per §5.2, nothing depends on it:

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

While iterating, narrow with
`cargo test -p foundry --test conformance_http`.

The §5.3 full gate runs **once**, at the end of the branch, before the
whole-branch review.

## 9. Follow-ups this branch deliberately leaves open

In the order they block a Google Wallet integration:

1. **Item D** — `android_keystore_attestation` proof type: a new `proofs` key
   whose value is an array of X.509 chains; `KeyDescription` extension parsing
   (`1.3.6.1.4.1.11129.2.1.17`), `attestationChallenge` ↔ `c_nonce` binding,
   security-level policy, and revocation against
   `https://android.googleapis.com/attestation/status`. Item A is its
   prerequisite and is merged. Operationally it also needs Google's two
   attestation roots (RSA-4096 `f92009e853b6b045`, ECDSA P-384 `Key Attestation
   CA1`) installed as configured trust anchors.
2. **Item E** — credential-type shape: SD-JWT with `vct = com.emvco.dpc.card`.
3. **Confirm with Google** whether RFC 9421 message signatures
   (`Content-Digest` / `Signature` / `Signature-Input`) and
   `credential_identifier` are genuinely required, or artifacts of a copied
   example. Both appear only in an example, neither in the requirements table.
4. **Decide whether `wallet_name` should be verified** rather than tolerated.
5. **Bump the ABCA pin from -07 to -10** and reconcile section references.
6. **Issuer onboarding.** The profile states Google hard-codes issuer metadata
   on their backend and must be sent the metadata document before onboarding
   can start. That is an operational step, not a code change, but it gates the
   integration and belongs on someone's list.
7. **Unrelated, carried from item C:** `check_encryption_policy` accepts a
   structurally-valid-but-unusable `credential_response_encryption.jwk`, which
   burns the wallet's single-use offer and returns 500 instead of 400. See
   `docs/superpowers/changes/2026-08-04-credential-request-response-encryption.md`.

## 10. Appendix: the recovered Google Wallet compatibility roadmap

The A–E decomposition was agreed in a brainstorming session whose transcript is
gone, and only items A–D were ever named in a checked-in document. Recording all
five here so the roadmap survives in the repository rather than in memory:

| Item | Scope | State |
|---|---|---|
| **A** | Cryptographic X.509 trust-chain verification (`validate_chain`) | merged 2026-08-04 (`2d50c7b`) |
| **B** | ABCA §8 challenge retrieval + RFC 9449 §8/§9 server-provided DPoP nonces | merged 2026-08-04 (`59b36be`) |
| **C** | Credential Request / Response JWE encryption | landed 2026-08-04 (`ece76ff`…`0a84ad1`, committed directly on `main`) |
| **D** | `android_keystore_attestation` proof type | landed 2026-08-05 (`8b91256`…`8707af1`, committed directly on `main`) |
| **E** | Credential-type shape (SD-JWT, `vct = com.emvco.dpc.card`) | merged 2026-08-05 (`90e80d7`) |

**This table is maintained past the branch that created it.** It is the only
place the A–E decomposition is recorded, so its `State` column is updated as
items land rather than frozen at this branch's snapshot — the surrounding prose
is point-in-time, the table is not. Last updated 2026-08-05, on completion of E.

Note that A, B and E arrived via merge commits while C and D were committed
straight onto `main`, so "find the merge commit" is not a reliable way to date an
item — hence the explicit ranges above. `1c1f8aa`
(`Merge feature/dpop-nonce-freshness-endpoints`) is *this* document's change and
belongs to no item; do not read it as B's.

**All five items are now done — which is not the same as "Google Wallet
integration is complete."** The decomposition covered the mechanisms the vendor
profile requires; several accommodations, unresolved questions with Google, and
one operational prerequisite remain outstanding. They are listed under "Open
issues carried forward" in
[`docs/superpowers/changes/2026-08-05-emvco-dpc-credential-type.md`](../changes/2026-08-05-emvco-dpc-credential-type.md),
which is where the residual work now lives. Do not read a fully-merged A–E as a
green light for interop.

The change *this* document designs belongs to none of the five items: it closes a
gap found by re-reading the vendor profile after A, B and C had merged, in the
seam between B (which built the RFC 9449 nonce mechanism) and where the vendor
actually expects the nonce to be handed out.