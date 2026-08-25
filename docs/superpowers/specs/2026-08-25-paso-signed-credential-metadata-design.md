# PaSO Signed Credential Metadata — Design

**Date:** 2026-08-25
**Status:** Approved (design review in chat, 2026-08-25)
**Scope:** PaSO Attestation Provider role, publish-only
**Governing specs:** PaSO Core, PaSO Proof Metadata (to be vendored into
`docs/specs/`, pinned at the source repo's HEAD when implementation starts —
see §1; the §5 `x5c`/`kid` amendment must be committed in the source repo
before pinning)

---

## 0 Context and Scope

PaSO (Payments and SCA for OpenID) extends OpenID4VP/OpenID4VCI for
verifiable, user-consented transactions. Its Proof Metadata module solves a
gap in OpenID4VCI: credential metadata is served unsigned, so a wallet cannot
prove after the fact which display metadata it used to render a transaction
for consent. PaSO's answer is a **signed credential metadata JWT** served from
a per-configuration `credential_metadata_uri`, extended with
`transaction_data_types` — the machine-readable description of the
transaction data payloads a PaSO Credential supports and how they are
displayed.

foundry implements the **Attestation Provider** role only, **publish-only**:

- Serve credential metadata (JSON and signed-JWT forms) at a new wallet-facing
  endpoint (Proof Metadata §2, §3, §4).
- Advertise `credential_metadata_uri` in issuer metadata for PaSO credential
  configurations (Proof Metadata §2).
- Mint **ad-hoc transaction data metadata JWTs** on request via a new admin
  endpoint (Proof Metadata §5), for Relying Parties to embed in
  `transaction_data` entries.

**Out of scope** (each a future increment with its own design): the Relying
Party role (PaSO-conformant `transaction_data` emission from
foundry-verifier), the Authorizing Party role (holder-binding-proof
verification, Verify module endpoint), all wallet-side behaviour (foundry
ships no wallet client), risk signals, PaSO View rendering, and the
`kid`/key-set signing branch (see §4 below).

foundry is partly a **reference implementation** here: the PaSO spec is
authored by this user and moving. Spec ambiguities found during
implementation are a deliverable — see §10.

## 1 Spec Governance

- Vendor `paso-core.md` and `proof/paso-proof-metadata.md` from
  `~/dev/eudiw/payments-and-sca-for-openid/docs/specifications/` into
  `docs/specs/` verbatim, each prefixed with a header block recording the
  source repository and the pinned commit.
- Add two rows to root `AGENTS.md` §4.4:
  - **PaSO Core** — governs the transaction data model (`payload`
    parameter), the `urn:paso:sca:<domain>:<suffix>:<version>` type-identifier
    grammar (§5.2), and the terminology foundry's config validation cites.
  - **PaSO Proof Metadata** — governs the `credential_metadata_uri`
    extension, the `transaction_data_types` structure, claims metadata and
    `ui_labels` (§3), the signed credential metadata JWT (§4), and the ad-hoc
    metadata JWT (§5).
- Bumping the pin is a deliberate change, exactly like an OpenID4VCI draft
  bump: update the vendored file, then reconcile the code.
- The other PaSO modules (View, Verify, Log, Risk Signals, Risk Signal
  Registry, SD-JWT-VC/SVG) are **not** vendored — nothing in this increment
  implements them, and vendoring unimplemented spec text invites false
  conformance claims.
- The conformance report (`docs/conformance/openid4vc-conformance.md`) gets
  **no PaSO section yet** — deferred until foundry claims PaSO *conformance*
  rather than PaSO *support*.

## 2 Config Surface (`foundry-core`)

### 2.1 `CredentialType.transaction_data_types`

`CredentialType` (`crates/foundry-core/src/config/model.rs`) gains:

```yaml
credential_types:
  - id: BankPaymentCard
    format: dc+sd-jwt
    vct: https://bank.example/sca/card
    # ...existing fields...
    transaction_data_types:
      "urn:paso:sca:global:payment:1":
        claims:
          - path: [transaction_id]
            mandatory: true
          - path: [amount]
            mandatory: true
            value_type: iso_currency_amount
            display:
              - { locale: en, name: Amount }
              - { locale: de, name: Betrag }
        ui_labels:
          affirmative_action_label:
            - { locale: en, value: Confirm Payment }
            - { locale: de, value: Zahlung bestätigen }
```

Rust model: `Option<BTreeMap<String, TransactionDataTypeMetadata>>` where

```rust
pub struct TransactionDataTypeMetadata {
    pub claims: Vec<serde_json::Value>,      // validated structurally
    pub ui_labels: Option<serde_json::Value>, // validated structurally
    // unknown members preserved via #[serde(flatten)] extra: Map<String, Value>
}
```

Typed at the level foundry validates, passthrough below that — the same
posture as `CredentialType.display`. Unknown members are preserved and
re-serialized (Proof Metadata §3 allows additional parameters; the Wallet
ignores unrecognised ones).

**A credential type declaring this map is a PaSO credential type.** Absence
changes nothing anywhere: default-off, wire-identical output for existing
deployments.

### 2.2 Validation (`Config::validate()`, startup-fatal)

Per PaSO Core §5.2 and Proof Metadata §3.1/§3.2, each cited in the error
message and a code comment:

- Type keys match `urn:paso:sca:<domain>:<suffix>:<version>`; `<version>` is
  a positive integer without leading zeros (Core §5.2 as amended).
- Each entry has non-empty `claims`; each claim object has a non-empty `path`
  array of strings.
- `value_type` appears only on claims that have a `display` array
  (Proof Metadata §3.1: "MUST NOT be used on claims without a `display`
  array").
- Each `display` entry has a `name`; `locale` is required when an entry's
  claim has more than one `display` entry.
- `ui_labels` values are arrays of objects each with a string `value`,
  optional `locale`, optional `value_type`.
- **If any credential type is PaSO, `credential_signing_key()` must resolve
  to a `KeyEntry` with `x5c`.** The metadata JWTs are unmintable without a
  chain; that must be a startup failure, not a wallet-facing 500.

An operator's typo is a startup failure, never a wallet-facing one (same
philosophy as the av.1 closed-attribute-set check).

`ui_labels` is treated as **optional always** — Proof Metadata §3's
conditional requirement ("REQUIRED when the credential is issued to a Wallet
that does not have a dedicated UI") is undecidable by the publisher; see
ambiguity register §10.

### 2.3 TTL knob

```yaml
issuer:
  paso_metadata:        # optional block; both fields defaulted
    ttl_secs: 86400     # exp of the signed credential metadata JWT
    adhoc_ttl_secs: 300 # exp of ad-hoc metadata JWTs
```

### 2.4 Signing key

The **credential signing key** (`Config::credential_signing_key()`), not a
dedicated metadata key. An identical leaf certificate satisfies Proof
Metadata §7 step 6's credential binding by construction (same root CA, same
Subject). §5.5 permits a dedicated metadata-signing key under the same
Subject; deferred until someone needs it (YAGNI).

foundry's issuer keys are x5c-published, so foundry takes the **x5c branch**
of §4/§5.2/§7. The `kid`/key-set branch is a **recorded unimplemented
optional path**: no code, a note here and in the issuer AGENTS.md, per root
AGENTS.md §4.4 ("unimplemented optional features are acceptable; incorrect
implementations are not").

## 3 Shared JWS Helper (`foundry-core`)

New module `foundry_core::crypto::jws`:

```rust
pub fn sign_compact(
    header_extras: &serde_json::Map<String, serde_json::Value>, // typ, x5c, kid, ...
    payload: &serde_json::Value,
    signer: &dyn Signer,
) -> Result<String, CryptoError>
```

Owns: `alg` derived from `signer.algorithm()` (callers cannot set a
mismatched `alg`), b64url encoding of header and payload, signing-input
assembly, signature encoding. Callers own everything else via
`header_extras`.

The three existing hand-rolled compact-JWS sites migrate onto it:

| Site | Header it passes |
| --- | --- |
| `foundry-sd-jwt-vc/src/builder.rs` (`build_sd_jwt_vc`) | `typ: dc+sd-jwt`, optional `x5c`; its private `b64url_json` is deleted |
| `foundry-core/src/status_list/mod.rs` | its existing `typ`; its private `b64url_json` is deleted |
| `foundry-verifier/src/request.rs` (`build_signed_request_object`) | `typ: oauth-authz-req+jwt`, `x5c`; payload and x5c resolution untouched |

**Pure extraction**: each migration must produce byte-identical output for a
fixed key and payload. Pinned by the existing tests plus one new equivalence
unit test per site. No JWT *verification* moves — construction only.
Layering is clean: `foundry-core` is the bottom of the graph.

## 4 PaSO Minting (`foundry-issuer`, new module `paso_metadata.rs`)

Two stateless builders, both `#[tracing::instrument(skip_all)]`, both citing
spec sections in comments:

```rust
pub fn build_credential_metadata_jwt(
    cfg: &Config, cred_type: &CredentialType,
    signer: &dyn Signer, x5c_chain: &[String], now_unix: i64,
) -> Result<String, IssuanceError>

pub fn build_adhoc_metadata_jwt(
    cfg: &Config, cred_type: &CredentialType, tx_data_type: &str,
    override_metadata: Option<serde_json::Value>,
    signer: &dyn Signer, x5c_chain: &[String], now_unix: i64,
) -> Result<String, IssuanceError>
```

### 4.1 Credential metadata JWT (Proof Metadata §4)

- Header: `{ typ: "credential-metadata+jwt", alg, x5c }`.
- Payload: `{ iss, sub, format, iat, exp: iat + ttl_secs,
  credential_metadata_uri, credential_metadata }`.
- `iss` = `issuer.credential_issuer`; `sub` = `vct` (SD-JWT VC) or `doctype`
  (mdoc) per `format`; `credential_metadata_uri` = the exact URL the route
  serves (load-bearing per §8's URI-binding check).
- `credential_metadata` = the same object `build_issuer_metadata` nests today
  (`display`, `claims`) **plus** `transaction_data_types` from config. One
  construction function is shared with the JSON-response path so the signed
  and unsigned bodies can never diverge.

### 4.2 Ad-hoc metadata JWT (Proof Metadata §5)

- Header: `{ typ: "adhoc-transaction-metadata+jwt", alg, x5c }`.
- Payload: `{ iss, sub, format, iat, exp: iat + adhoc_ttl_secs,
  transaction_data_type, metadata }`.
- `metadata` = the configured `transaction_data_types` entry for
  `tx_data_type`, or the caller's `override_metadata` when provided — §5.4's
  transaction-specific channel; this is the entire reason ad-hoc exists
  beyond §4.
- Requesting a type that is neither configured nor overridden →
  `InvalidRequest`. An override for an **unconfigured** type is **allowed**
  (§5.4: a valid ad-hoc JWT makes the type "considered supported … even if
  absent from the signed credential metadata").
- Overrides get the same structural validation as config-time entries
  (§2.2's rules), at the admin boundary.

### 4.3 Statelessness and rotation

Every JWT is signed at request time (`iat = now`). No storage, no cache, no
rotation task. §4's "SHALL rotate before `exp`" is satisfied by construction
— a served JWT was minted moments ago. This is foundry's established posture
for minted artifacts (`challenge.rs`'s stateless MACs). Nothing in PaSO
requires byte-stability across fetches; §8 actively wants re-fetching
decorrelated from use. One ES256 signature (~50µs) per fetch on an
unauthenticated endpoint is not a meaningful amplification vector next to
TLS handshake cost; noted, not mitigated.

### 4.4 Locale handling (§2)

foundry serves **all configured locales** in every response. This trivially
satisfies "SHALL include at least the first supported locale from
`Accept-Language`" and avoids per-locale signing variants. `Accept-Language`
is read but never filters. foundry does **not** exercise §2's MAY-refuse
(400) for a missing `Accept-Language` header — refusal is optional, and a
reference implementation should be permissive on optional strictness.

## 5 HTTP Surface (`crates/foundry`)

### 5.1 Wallet listener (unauthenticated)

`GET /credential-metadata/:credential_configuration_id`

| Condition | Response |
| --- | --- |
| id unknown, or known but not PaSO (no `transaction_data_types`) | **404** |
| `Accept: application/jwt` | 200, body = compact JWT, `Content-Type: application/jwt` |
| `Accept: application/json`, absent, or no preference | 200, bare `credential_metadata` object (§2's default; explicitly *not* the JWT payload envelope) |
| `Accept` acceptable to neither | **406** |

404 for non-PaSO ids: the URI is only advertised for PaSO types, so a
non-PaSO id here is a client error, and 404 leaks nothing beyond what issuer
metadata already publishes.

`credential_metadata_uri` is advertised in `credential_configurations_supported`
entries **for PaSO types only**, built from
`server.wallet_facing.public_base_url` — and threaded into
`build_dc_api_offer`'s embedded metadata too (DC API wallets never fetch the
well-known document; see the issuer AGENTS.md gotcha that shipped broken
once for encryption JWKs).

### 5.2 Admin listener (API-key)

`POST /admin/paso/ad-hoc-metadata`

Request: `{ credential_type_id, transaction_data_type, metadata?, ttl_secs? }`
Response: `200 { jwt, exp }`
Validation failure → 400 with the standard admin error envelope.

### 5.3 OpenAPI

Wallet route → `openapi-wallet.json`; admin route → `openapi.json`; both via
`utoipa` annotations in `crates/foundry/src/openapi.rs` (root AGENTS.md §6).

## 6 Observability & Error Mapping

Nothing minted here is secret: credential metadata is a published document;
the ad-hoc JWT is designed to be handed to a Relying Party. No new entries in
root AGENTS.md §4.5's never-log list. Rules that apply:

- `skip_all` on every `#[tracing::instrument]` (builders take `Config`).
- Wallet route logs: `route`, `credential_configuration_id`, negotiated
  content type, outcome.
- Admin route logs: `credential_type_id`, `transaction_data_type`, and
  whether an override was present — **presence only, never contents**
  (mirrors `create_offer`'s display-metadata treatment; an override could
  carry transaction-specific payee/amount label text).
- Error mapping in `server.rs`'s existing mappers, exactly one log record per
  typed error (§4.5): unknown/non-PaSO id → 404 (`warn`); unacceptable
  `Accept` → 406 (`warn`); admin validation failure → 400 (`warn`); signing
  failure → 500 (`error`).

## 7 Testing

- **Unit, `foundry-core` (`crypto::jws`):** header assembly, `alg`
  derivation, b64url correctness; byte-equivalence of each migrated call
  site against its pre-extraction output for a fixed key.
- **Unit, `foundry-core` (config):** validation matrix — bad URN grammar
  (wrong prefix, non-integer version, leading zeros), `value_type` without
  `display`, empty `claims`, missing `x5c` on the signing key with a PaSO
  type present, absent block ⇒ non-PaSO and wire output unchanged.
- **Unit, `foundry-issuer` (`paso_metadata`):** decode both JWT kinds; assert
  `typ`, `x5c`, every payload claim, `exp` arithmetic; ad-hoc override
  precedence; override-for-unconfigured-type allowed; unconfigured +
  no-override rejected; `sub` follows `vct` vs `doctype` by format; JSON body
  and JWT `credential_metadata` claim are the same value.
- **Integration, `crates/foundry/tests/paso_metadata.rs`:** full HTTP —
  content-negotiation matrix (jwt/json/absent/406); 404 for unknown and
  non-PaSO ids; `credential_metadata_uri` present in well-known metadata for
  PaSO types, absent otherwise, and present in the DC API offer's embedded
  metadata; admin mint round-trip; and a **§7-shaped verification test**:
  fetch the JWT over HTTP and run the wallet-side checks in-process —
  signature via the served `x5c`, `typ`, `iss`, `exp`,
  `credential_metadata_uri` equals the fetched URL (§8), `sub` matches the
  credential type identifier, chain root and leaf Subject match the
  credential's chain (§7 step 6). Publish-only scope, but it proves the
  artifact is *verifiable*, not merely well-formed.
- **Quickstart:** one credential type in the quickstart config gains a
  `transaction_data_types` block so E2E environments exercise the endpoint;
  `openapi_endpoints.rs` keeps the specs honest.
- **Gate:** root AGENTS.md §5.1, every time — `cargo fmt`;
  `cargo nextest run --workspace --no-fail-fast --status-level fail`;
  `cargo clippy --workspace --all-targets -- -D warnings`.

## 8 Files Touched (expected)

| Area | Files |
| --- | --- |
| Spec vendoring | `docs/specs/paso-core.md`, `docs/specs/paso-proof-metadata.md`, root `AGENTS.md` §4.4 |
| Config | `crates/foundry-core/src/config/model.rs`, `validate.rs`, config tests |
| JWS helper | `crates/foundry-core/src/crypto/jws.rs` (new), `crypto/mod.rs`; migrations in `foundry-sd-jwt-vc/src/builder.rs`, `foundry-core/src/status_list/mod.rs`, `foundry-verifier/src/request.rs` |
| Minting | `crates/foundry-issuer/src/paso_metadata.rs` (new), `lib.rs`, `error.rs` (if a new variant is needed), `metadata.rs` (`credential_metadata_uri` emission), `offer.rs`/`create_offer.rs` (DC API threading, if applicable) |
| HTTP | `crates/foundry/src/server.rs`, `openapi.rs`; `openapi.json`, `openapi-wallet.json` |
| Tests | `crates/foundry/tests/paso_metadata.rs` (new), `crates/foundry/tests/AGENTS.md`, quickstart config template |
| Docs | `crates/foundry-issuer/AGENTS.md`, `crates/foundry-core/AGENTS.md`, `README.md` (endpoint list), this file |

## 9 Explicit Non-Goals / Deferred

- `kid`/key-set signing branch (§4/§5.2/§7): foundry is x5c-published;
  the branch is documented as unimplemented-optional.
- Dedicated metadata-signing key (§5.5): deferred.
- Per-locale filtering of served metadata: all locales always served.
- §2's optional 400-on-missing-`Accept-Language`: not exercised.
- RP role (PaSO `transaction_data` emission), AP role (proof verification,
  Verify module), risk signals, PaSO View: future increments.
- Conformance-report section for PaSO: deferred until conformance is claimed.

## 10 Spec Ambiguity Register (deliverable)

Found while designing against PaSO Core + Proof Metadata; maintained through
implementation. Resolved rounds are kept for the record.

### Open

| # | Spec point | Issue | foundry's posture |
| --- | --- | --- | --- |
| 1 | Proof Metadata §3 | `ui_labels` "REQUIRED when the credential is issued to a Wallet that does not have a dedicated UI for the transaction data type" — the publisher serves static metadata at a URI and cannot know the fetching Wallet's UI capabilities; the conditional is undecidable at publication time | `ui_labels` treated as always-optional; never enforced |
| 2 | Proof Metadata §2/§3.1 | Citations "[OID4VCI] §12.2.2 / §12.2.4 / Appendix B.2" do not exist under those numbers in the OpenID4VCI 1.0 text foundry pins (claims description objects are main-body, ~L2321; no Appendix B.2) — citation targets a differently-numbered draft | Mapped to the pinned text's structures; noted so wallet implementers on other drafts resolve identically |
| 3 | Proof Metadata §8 | Unlinkability SHALL binds only the Wallet; no AP-side counterpart (e.g. cache-control guidance against fetch-time correlation) | Editorial; no code impact |

### Resolved by spec amendment during design (2026-08-25)

| Spec point | Was | Resolution |
| --- | --- | --- |
| §7 step 6 | Credential binding unsatisfiable for credentials without `x5c` | §4 `kid`/key-set alternative; §7 step 3 branches; step 6 no-`x5c` binding (commit `4868517`) |
| §2 JSON variant | Return shape (bare object vs JWT-payload envelope) unstated | Explicit: bare `credential_metadata` object (commit `4868517`) |
| §8 URI binding | No rule when `credential_metadata_uri` claim disagrees with fetched URI | Match check after redirects; mismatch invalidates (commit `4868517`) |
| §5.2/§7 mdoc `sub` | `doctype` vs `urn:paso:sca:1` namespace confusable | Explicit paragraph + §7 rejection + Annex A.5 (commit `de42067`) |
| §2 Accept-Language refusal | No status code | 400 mandated (commit `cace6df`) |
| Core §5.2 `<version>` | Numeric-or-any-segment unstated | Positive integer, no leading zeros, final segment, monotonic (commit `cace6df`) |
| §5.2/§5.3/§5.5 ad-hoc | `x5c` unconditional while §4/§7 gained the key-set branch — key-set issuers couldn't mint conformant ad-hoc JWTs at all | §5 mirrors §4's `x5c`/`kid` fork; §5.5 extended with key-set forgery analysis (uncommitted at design time — **commit before pinning**) |

## 11 Design Decisions Log

| Decision | Alternatives rejected | Why |
| --- | --- | --- |
| Config-driven metadata, admin override for ad-hoc only | All-admin/storage-driven; config-only | Config stays the single reviewable source of truth for the durable artifact; the ad-hoc channel's entire purpose (§5.4) is transaction-specific metadata, which config cannot express |
| Stateless per-request signing | Pre-signed cache + rotation task | Foundry's established posture (`challenge.rs`); rotation-before-`exp` holds by construction; caching adds a real failure mode (serving a stale expired artifact) for a property nothing needs |
| Shared `sign_compact` extraction | Fourth local hand-roll | This work adds JWS sites 4 and 5; three copies already exist with unprincipled divergence; `alg`-from-signer in one place kills a real bug class |
| Credential signing key for metadata JWTs | Dedicated metadata key (§5.5 allows) | Identical leaf ⇒ §7 step 6 binding by construction; a second key is config surface with no current consumer |
| All locales served always | `Accept-Language`-filtered variants | Satisfies §2's SHALL trivially; avoids per-locale signing variants and a negotiation matrix |
| 404 for non-PaSO configuration ids | 200 with metadata sans `transaction_data_types` | The URI is only advertised for PaSO types; §3 makes `transaction_data_types` REQUIRED in metadata served from this URI, so a 200 without it would be non-conformant |
