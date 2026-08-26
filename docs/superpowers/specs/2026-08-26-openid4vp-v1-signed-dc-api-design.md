# Signed OpenID4VP Requests over the DC API (`openid4vp-v1-signed`) — Design

**Date:** 2026-08-26
**Status:** Approved (design review in chat, 2026-08-26)
**Scope:** `foundry-verifier` request side, plus the admin API, OpenAPI and
admin console surfaces that carry it
**Governing specs:** OpenID4VP 1.0 Appendix A (`docs/specs/openid-4-verifiable-presentations-1_0.md`),
HAIP 1.0 (`docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md`)

---

## 0 Context and Scope

foundry's verifier can already be invoked over the W3C Digital Credentials API,
but only in the **unsigned** form: `create_verification_request` with
`transport: "dc_api"` returns a bare parameter object with no `client_id` and no
signature. OpenID4VP 1.0 §A.2 also defines a **signed** form, in which the same
Authorization Request parameters are encoded as a Request Object, signed as a
JWS Compact Serialization, and passed as the `request` member of the DC API
`data` element (L2464–L2476). The wallet authenticates the Verifier from that
signature and its `x5c` chain rather than relying solely on the browser's web
PKI and the platform-supplied Origin (L2456–L2460).

HAIP L288 requires a Verifier to support **at least one** of unsigned, signed
and multi-signed. foundry supports unsigned today; this design adds signed.

**In scope:**

- A new `transport` value, `dc_api_signed`, on `POST /admin/verification/requests`.
- A signed DC API Request Object builder in `foundry-verifier`, sharing the
  signing half with the existing redirect-transport builder.
- The `expected_origins` request parameter (L2442), sourced from the existing
  `verifier.dc_api_expected_origins` config key.
- A new `protocol` field on `CreateVerificationResponse` carrying the DC API
  exchange protocol identifier (L2395–L2402).
- Console, OpenAPI, README and conformance-report updates.

**Out of scope:**

- `openid4vp-v1-multisigned` (JWS JSON Serialization, §A.2.2). It is a distinct
  wire form with its own parameter-placement rules; HAIP L288 does not require
  it once signed is supported. VP-0207 and VP-0208 stay `not-implemented`.
- Any change to the verify side's protocol behaviour. §A.4 L2543 keeps the
  response audience at `origin:<origin>` **even for signed requests**, so
  `expected_audiences` and the `OpenID4VPDCAPIHandover` are correct as they
  stand. The only verify-side edit is mechanical (see §3).
- Wallet-side behaviour. foundry ships no wallet client.

---

## 1 Design Decisions (settled in review)

| # | Decision | Alternatives rejected |
| --- | --- | --- |
| 1 | Selection is a **new `transport` value**, `dc_api_signed` | A `signed: bool` flag alongside `transport: "dc_api"`; a deployment-wide config toggle. `transport` is already the discriminator persisted on the transaction and consulted during verification, and the two DC API forms produce genuinely different wire artifacts, so they are different transports |
| 2 | Empty `verifier.dc_api_expected_origins` + `dc_api_signed` is a **hard failure** | Falling back to a `public_base_url`-derived origin, as the verify side does. The verify-side fallback keeps *inbound* verification working against pre-existing config; here foundry would be manufacturing a signed assertion about which Origins are legitimate, and guessing that is worse than refusing |
| 3 | foundry **emits the protocol identifier** on the response | Leaving the calling page to derive it. The identifier and the `data` shape are two halves of one wire contract and foundry decides the shape; emitting them together is the only way they cannot drift. Also converts VP-0196/VP-0197 from `not-implemented` to evidence-backed `conforming` |
| 4 | The console offers **both DC API forms**, via a third `<option>` in the existing transport select | A config-driven single button; replacing the unsigned form outright. The console is an interop-debugging surface first, and comparing wallet behaviour across the two forms is its purpose |
| 5 | The builder is split as **shared signing + per-transport payload assembly** | Parameterising the existing builder with a mode argument; a fully independent second builder. See §4 |

---

## 2 Wire Contract

### 2.1 Response from `POST /admin/verification/requests`

```json
{
  "verification_id": "…",
  "protocol": "openid4vp-v1-signed",
  "dc_api_request": { "request": "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXEran…" },
  "request_uri": null,
  "openid4vp_uri": null
}
```

`protocol` is `Option<String>` on `CreateVerificationResponse`:

| `transport` | `protocol` | `dc_api_request` |
| --- | --- | --- |
| `request_uri` | `null` | `null` |
| `dc_api` | `"openid4vp-v1-unsigned"` | parameter object (unchanged) |
| `dc_api_signed` | `"openid4vp-v1-signed"` | `{ "request": "<compact JWS>" }` |

`null` on `request_uri` is the honest value: that transport performs no DC API
invocation, so there is no exchange protocol identifier to report. It is not the
empty string.

The `{ "request": … }` wrapper is L2476's `data` element verbatim.

### 2.2 Signed DC API Request Object payload

| Claim | Value | Authority |
| --- | --- | --- |
| `response_type` | `vp_token` | OpenID4VP §5 (REQUIRED); HAIP L255 |
| `client_id` | `x509_hash:<base64url(SHA-256(DER leaf))>` | L2437 (MUST be present in signed DC API requests); HAIP L256 fixes the prefix |
| `response_mode` | `dc_api.jwt` | L2438; HAIP L286 mandates the encrypted mode |
| `nonce` | `tx.nonce` | OpenID4VP §5 (REQUIRED) |
| `dcql_query` | `tx.dcql_query` | OpenID4VP §6 |
| `client_metadata` | `jwks` / `encrypted_response_enc_values_supported` / `vp_formats_supported` | §5.1; identical to the other two forms |
| `expected_origins` | `verifier.dc_api_expected_origins` | L2442 (REQUIRED for signed DC API requests, non-empty array) |
| `aud` | `https://self-issued.me/v2` | L536 — Static Discovery; foundry performs no Dynamic Discovery |
| `transaction_data` | encoded entries, only when the request carried them | L2421 lists it among supported DC API parameters |
| `response_uri` | **absent** | Not a DC API Authorization Request parameter (L2421). The response returns through the API, not to a URI |
| `state` | **absent** | Explicitly not defined for the DC API (L2448) |

JOSE header, unchanged from the redirect form and shared with it:
`typ: oauth-authz-req+jwt`, `alg`, `x5c` — in that insertion order, which is
load-bearing because `serde_json` preserves it and the bytes are signed. `x5c`
carries the **leaf only**; the trust anchor is excluded (HAIP L190, L256).

### 2.3 What does not change

- `response_mode` for both DC API transports is `dc_api.jwt`, so VP-0249's
  thumbprint selection in the mdoc `SessionTranscript` — which keys off
  `tx.response_mode`, not `tx.transport` — is already correct.
- The KB-JWT audience remains `origin:<origin>` and the mdoc binding remains
  `OpenID4VPDCAPIHandover` (L2543, L2963).
- `POST /admin/verification/requests/:id/dc-api-response` is unchanged; both DC
  API forms return their response through it.

---

## 3 The Transport Predicate (a required correctness fix)

`verify.rs` currently tests `tx.transport == "dc_api"` in two load-bearing
places:

- the Origin-prefixed `expected_audiences` computation (SD-JWT VC KB-JWT `aud`);
- the `OpenID4VPDCAPIHandover` candidate-transcript construction (mdoc).

A new transport string that those equality tests do not match would silently
downgrade every signed DC API presentation to the **redirect** binding — an
`x509_hash:` audience and an `OpenID4VPHandover` — so each such presentation
would fail for a reason unrelated to its actual defect.

`VerificationTransaction::is_dc_api(&self) -> bool` is added in
`transaction.rs` (which owns the type and is visible to both call sites),
returning true for `"dc_api"` and `"dc_api_signed"`. Both equality tests become
`tx.is_dc_api()`. No other site in the crate compares `transport` for meaning.

This is not an optional tidy-up: without it the feature is broken on the verify
side, and the failure mode is a misleading verdict rather than an error.

---

## 4 Builder Structure (`foundry-verifier/src/request.rs`)

The redirect flow signs **lazily**, at `GET /vp/request/:id`, from the persisted
transaction. A signed DC API request has no fetch step — the JWS *is* the
`dc_api_request` payload — so it must be signed inside
`create_verification_request` and returned immediately. Two call sites, one set
of security-relevant logic.

**`sign_request_object(config, payload_map) -> Result<String, VerificationError>`**
(crate-private) owns everything transport-agnostic and security-relevant:

- key lookup in `config.keys[config.verifier.signing_key]` and `alg` parse;
- `FileSigner::from_pem_file`;
- `verifier_x5c_leaf_pem` and the dNSName-SAN cross-check against
  `public_base_url`'s host;
- `x509_hash_client_id` derivation and insertion of `client_id` into the
  payload — so neither payload builder can omit it or derive it differently;
- `build_x5c(&[leaf])` (trust anchor excluded);
- header assembly in `typ, alg, x5c` order and `sign_compact`;
- the always-on payload-free `debug` record and the doubly-gated `trace` dump
  (`foundry_core::obs::sensitive_enabled()` AND `trace`, per root AGENTS.md
  §4.5).

**`build_signed_request_object(config, tx)`** keeps its public signature and its
`GET /vp/request/:id` caller. Its body reduces to the redirect payload
(`response_uri`, `state`, `response_mode: direct_post.jwt`, …) plus a call to
`sign_request_object`.

**`build_signed_dc_api_request_object(config, tx)`** (crate-private) assembles
the §2.2 payload plus the same call. It receives `expected_origins` already
validated as non-empty.

Rationale for this split over the alternatives: HAIP-0043 (`x509_hash` client
id) and HAIP-0045 (no trust anchor in `x5c`) are recorded `conforming` on the
strength of there being exactly one code path that emits a signed request
object. A second independent builder forks that path; a mode argument keeps it
singular but interleaves two wire formats inside one function — the same shape
as the `transaction_data` scoping defect this crate already recorded. The split
keeps the security-relevant half singular while making each payload readable
against the spec section it cites.

The existing tests `haip_0045_signed_request_x5c_excludes_the_trust_anchor` and
`client_id_is_the_x509_hash_of_the_configured_leaf_certificate` continue to
target `build_signed_request_object` and therefore pin the refactor for free.

---

## 5 Request Creation and Error Handling

`create_verification_request` gains a `"dc_api_signed"` arm:

1. Resolve `response_mode` to `dc_api.jwt` (same as `dc_api`).
2. **Validate** `config.verifier.dc_api_expected_origins` is non-empty. If it is
   empty, return `VerificationError::InvalidRequest` naming the config key —
   **before** the transaction is persisted.
3. Persist the transaction with `transport: "dc_api_signed"`.
4. Call `build_signed_dc_api_request_object`.
5. Return `dc_api_request: { "request": jws }` and
   `protocol: "openid4vp-v1-signed"`.

The `dc_api` arm additionally sets `protocol: "openid4vp-v1-unsigned"`; the
`request_uri` arm sets `None`.

**Error mapping.** `InvalidRequest` maps to HTTP 400 for the *operator* who
called the admin API — this is a misconfiguration, not a wallet-visible policy
outcome, so root AGENTS.md §4.3's policy/structural distinction is not engaged.
A missing or unreadable `x5c` remains `VerificationError::Crypto`, raised inside
`sign_request_object`, exactly as it is for the redirect transport today. Note
the asymmetry this produces on the create-request route:
`verifier_admin_error_response` maps `InvalidRequest` to 400 but lets `Crypto`
fall through to the 500 arm, so an empty `dc_api_expected_origins` is a 400
while a missing certificate is a 500 — both operator misconfigurations,
reported at different statuses. This is pre-existing behaviour inherited from
the redirect transport, not introduced here, and re-classifying `Crypto` is
deliberately out of scope: it would also change the status of existing
`GET /vp/request/:id` failures.

`dc_api_expected_origins` remains **optional** in `Config::validate()`. It
becomes required only for this transport, so deployments that never request it
are unaffected.

**Observability.** Per root AGENTS.md §4.5: the existing `create_verification_request`
`info` record already carries `transport`, which now distinguishes the two DC API
forms. `sign_request_object`, if instrumented at all, carries `skip_all`. The
verbatim `request_object_jws` / `request_object_payload` dump stays doubly gated;
it may reproduce the ephemeral **public** JWK in `client_metadata` (an explicitly
recorded exception in §4.5) but never the private one. No new field names are
introduced, so the operator-facing log API is unchanged.

---

## 6 HTTP, OpenAPI and Console

**`crates/foundry/src/server.rs`** — no route or handler-logic change. The doc
comment stating that `response_mode` is `dc_api.jwt` "for `transport: dc_api`"
is updated to cover both DC API transports.

**OpenAPI** — `openapi.json` is regenerated for the additive optional `protocol`
field on `CreateVerificationResponse`. `openapi-wallet.json` is unaffected; this
is an admin route.

**`crates/foundry/assets/console.html`** —

- a third `<option value="dc_api_signed">` in the transport `<select>`;
- `prepareDcApiRequest(body.dc_api_request, body.protocol)` replacing the
  hardcoded `'openid4vp-v1-unsigned'`;
- the `supportsDcApi('get', …)` guard uses the same value, so the browser's
  `userAgentAllowsProtocol` check is asked about the protocol actually being
  sent.

The single trigger button is unchanged — it already appears whenever the
response carries `dc_api_request`, which both DC API transports produce.

**README** — the transport rows and the "DC API Expected Origins" section gain
the signed form and state that `dc_api_expected_origins` is *mandatory* for it.

**`crates/foundry-verifier/AGENTS.md`** — module-map entry for the builder split,
plus a Gotchas line recording that transport comparisons go through
`is_dc_api()` and why (§3).

---

## 7 Testing

**Unit (`foundry-verifier/src/request.rs`)** — the module's existing
`sample_config` / `sample_verifier_x5c_path` fixtures apply.

| Test | Asserts |
| --- | --- |
| `dc_api_signed_returns_a_compact_jws_under_the_request_key` | `dc_api_request` is `{"request": "<three dot-separated segments>"}`; `request_uri`/`openid4vp_uri` are `None` |
| `dc_api_signed_request_object_carries_client_id_and_expected_origins` | Decoded payload has `client_id == x509_hash:<fixture leaf hash>` (L2437) and `expected_origins` equal to config (L2442) |
| `dc_api_signed_request_object_omits_response_uri_and_state` | The negative half of L2421/L2448 — the members most likely to be copied in from the redirect builder |
| `dc_api_signed_request_object_uses_dc_api_jwt_response_mode_and_static_discovery_aud` | L2438 and L536 |
| `dc_api_signed_without_expected_origins_is_rejected_before_persisting` | `InvalidRequest`, **and** `load_verification_transaction` returns `NotFound` — proving the failure precedes the write |
| `protocol_identifier_matches_the_transport` | All three transports, table-driven (VP-0196/VP-0197) |
| `dc_api_signed_x5c_excludes_the_trust_anchor` | HAIP-0045 for the second builder; the existing test reaches only the redirect one |

**Regression pins for §3 (`foundry-verifier/src/verify.rs` tests)** — these are
the tests that would catch the silent downgrade:

- `dc_api_signed_transport_expects_the_origin_prefixed_audience` (SD-JWT VC).
- `dc_api_signed_transport_selects_the_dc_api_handover` (mdoc).

**Integration (`crates/foundry/tests/wallet_verification.rs`)** —
`signed_dc_api_presentation_verifies_end_to_end`: create with
`transport: "dc_api_signed"`, verify the returned JWS against the configured
leaf, build a presentation whose KB-JWT audience is `origin:<configured origin>`,
POST it to `/admin/verification/requests/:id/dc-api-response`, assert
`verified: true` and the full check set. This is the only test proving the
request side and verify side agree.

**Console (`crates/foundry/tests/console.rs`)** — extend
`console_has_digital_credentials_api_trigger_for_dc_api_transport`: the select
offers `dc_api_signed`, and the trigger path reads `body.protocol` rather than a
literal protocol string.

**Existing mechanical guards, no new code:** `conformance_report.rs` validates
the edited rows; `instrumentation_hygiene.rs` rejects a `#[tracing::instrument]`
without `skip_all`; `openapi_endpoints.rs` / `cli_openapi.rs` cover the
regenerated `protocol` field.

**Gate** (root AGENTS.md §5.1), before any completion claim:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

plus `cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only`
before opening the PR.

**Deliberately untested:** whether a real wallet accepts the signed form. That
is interop evidence, not a unit test; the `SENSITIVE`-gated `request_object_jws`
dump exists for that loop.

---

## 8 Conformance Report Updates

`docs/conformance/openid4vc-conformance.md` is a living document (root AGENTS.md
§4.4, §8). Closing this feature means editing these rows:

| Clause | From | To | Evidence | Test |
| --- | --- | --- | --- | --- |
| VP-0196 | `not-implemented` | `conforming` | foundry emits `protocol` with `<version>` = `1` | `protocol_identifier_matches_the_transport` |
| VP-0197 | `not-implemented` | `conforming` | `<request-type>` is `signed` or `unsigned` per transport | `protocol_identifier_matches_the_transport` |
| VP-0200 | `not-implemented` | `conforming` | `client_id` present in the signed DC API request object | `dc_api_signed_request_object_carries_client_id_and_expected_origins` |
| VP-0202 | `not-implemented` | `conforming` | `expected_origins` emitted, and required non-empty | `dc_api_signed_request_object_carries_client_id_and_expected_origins`, `dc_api_signed_without_expected_origins_is_rejected_before_persisting` |
| VP-0198 | `conforming` | `conforming` | Evidence text updated: the *unsigned* transport omits `client_id`, and the signed transport is a separate arm | `vp_0198_0201_dc_api_unsigned_request_shape` |
| VP-0201 | `conforming` | `conforming` | Evidence text updated: both DC API transports resolve to `dc_api.jwt` | `vp_0198_0201_dc_api_unsigned_request_shape` |
| VP-0207, VP-0208 | `not-implemented` | unchanged | Multisigned (JWS JSON Serialization) remains out of scope | — |

---

## 9 Files Touched (expected)

| File | Change |
| --- | --- |
| `crates/foundry-verifier/src/transaction.rs` | `is_dc_api()` |
| `crates/foundry-verifier/src/request.rs` | Builder split; `dc_api_signed` arm; `expected_origins` validation; `protocol` on `CreateVerificationResponse`; new unit tests |
| `crates/foundry-verifier/src/verify.rs` | Two equality tests → `is_dc_api()`; two regression tests |
| `crates/foundry-verifier/AGENTS.md` | Module map + Gotchas |
| `crates/foundry/src/server.rs` | Doc comment only |
| `crates/foundry/src/openapi.rs`, `openapi.json` | Regenerated `protocol` field |
| `crates/foundry/assets/console.html` | Transport option; `body.protocol` |
| `crates/foundry/tests/wallet_verification.rs` | End-to-end signed DC API test |
| `crates/foundry/tests/console.rs` | Extended console assertions |
| `README.md` | Transport rows; DC API Expected Origins section |
| `docs/conformance/openid4vc-conformance.md` | Rows in §8 |

---

## 10 Open Questions

None. All five decisions in §1 were settled in review; no `TBD` remains.
