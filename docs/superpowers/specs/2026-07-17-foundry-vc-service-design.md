# Foundry — Digital Credential Issuing & Verification Service

**Status:** Design (approved)
**Date:** 2026-07-17
**Author:** flo@digitallabor.berlin

## 1. Overview

Foundry is a server-side service for **issuing** and **verifying** digital
credentials, implemented as a single Rust CLI binary. It speaks
**OpenID4VCI** (issuance) and **OpenID4VP** (verification) to wallets and
follows the **OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0
final**. Supported credential formats: **SD-JWT VC** (`dc+sd-jwt`) and
**mdoc** (`mso_mdoc`).

The primary command `foundry serve --config config.yaml` boots an async
(tokio) runtime and starts an axum HTTP server exposing two surfaces. Other
subcommands are one-shot tools for key/cert generation, config scaffolding,
and status-list management.

### Goals

- Complete service: issuance **and** verification from v1.
- Full control over the protocol implementation — vendor the Spruce crates
  (`oid4vci-rs`, `openid4vp`) as owned internal workspace crates, not external
  dependencies.
- Config-driven, generic credential types — nothing hard-coded.
- HAIP-conformant crypto, trust, and protocol behavior.
- Single self-contained binary with an embedded store (no external DB).

### Non-goals (v1)

- Authorization Code flow for issuance (pre-authorized code only in v1).
- Presentation Exchange / `presentation_definition` (DCQL only).
- External KMS/HSM integration (file-based keys, with a `Signer` seam for later).
- Horizontal scale / external database (SQLite embedded store in v1).
- ISO 18013-5 / mDL **transport and retrieval** mechanisms: device engagement
  (QR/NFC/BLE), proximity/offline retrieval, and reader (mdoc-reader) protocols
  are out of scope. Foundry supports the mdoc **credential format** (data model)
  only, exchanged exclusively over OpenID4VP. ISO 18013-7 is not implemented as
  a standalone stack; only the OpenID4VP handover SessionTranscript needed to
  verify an mdoc presented over OpenID4VP is used.

## 2. Architecture & Runtime Model

### Binary

Single Rust binary `foundry` (clap-based CLI). Commands:

- `foundry serve --config <file>` — boot the long-running HTTP service.
- `foundry quickstart` / `foundry init` — generate dev PKI + ready-to-run config.
- `foundry keys generate ...`, `foundry cert new-ca ...`, `foundry cert issue ...`
  — granular key/cert helpers.
- `foundry status-list ...` — administrative status-list operations (offline/scripting).
- `foundry config validate --config <file>` — validate without serving.

### Two HTTP surfaces, one process, separate routers/listeners

- **Wallet-facing** (public, spec-defined paths): OpenID4VCI and OpenID4VP
  endpoints. No auth beyond the protocols themselves.
- **Admin/integration** (private): REST endpoints the calling backend uses to
  create credential offers, start verifications, fetch results, and manage
  credential status. Bound to a separate listener/port, protected by a
  config-set API key (bearer token). Optional webhook callbacks for
  verification results.

### Crate dependency direction (acyclic)

```
foundry (bin) ── depends on ──▶ foundry-issuer, foundry-verifier, foundry-core
foundry-issuer ─▶ foundry-core, oid4vci
foundry-verifier ─▶ foundry-core, openid4vp
foundry-core ─▶ (vendored crates only where shared types are needed)
oid4vci, openid4vp = vendored, self-contained
```

### Workspace layout

```
foundry/
├─ crates/
│  ├─ oid4vci/         # vendored Spruce crate (owned, modifiable)
│  ├─ openid4vp/       # vendored Spruce crate (owned, modifiable)
│  ├─ foundry-core/    # crypto, key/cert store, X.509 trust, SD-JWT & mdoc
│  │                   #   builders/parsers, Token Status List, storage trait
│  │                   #   + SQLite impl, config model
│  ├─ foundry-issuer/  # OpenID4VCI server logic (offers, pre-auth, token,
│  │                   #   nonce, credential endpoint) on oid4vci types
│  ├─ foundry-verifier/# OpenID4VP server logic (request objects, DCQL,
│  │                   #   direct_post.jwt + DC API, response decrypt/verify)
│  └─ foundry/         # binary: CLI (clap) + HTTP servers (axum), config load
└─ config/             # example YAML/JSON configs
```

Vendored crates provide the protocol **data types**. `oid4vci-rs`'s documented
flows are client-centric, so the issuer **server** orchestration is built by
Foundry on top of its types (`CredentialOffer`, `CredentialIssuerMetadata`,
`AuthorizationServerMetadata`, offer/issuer-metadata modules). `openid4vp`
ships a server-side `Verifier` with DCQL support that the verifier engine uses.

### Request → state model

Every wallet interaction resolves against a **transaction** row in the embedded
SQLite store.

- **Issuance transaction:** offer, pre-auth code, `tx_code`, access token,
  `c_nonce`, claim set, status-list index, state.
- **Verification transaction:** request object, `state`, `nonce`, expected
  DCQL, ephemeral response-encryption key, result, state.

TTLs on all transient rows; a background sweeper purges expired ones.

### Config-first

All behavior (issuer identity, credential type definitions, keys/certs, trust
anchors, listeners, storage path, status-list config) comes from one YAML/JSON
file, deserialized into typed structs and **validated at startup** before
serving. Startup fails fast with an actionable error if invalid.

## 3. Issuance Flow (OpenID4VCI, Pre-Authorized Code)

1. **Backend → Admin API:** `POST /admin/issuance/offers` with
   `{ credential_type, claims, tx_code?, holder_binding? }`. Foundry validates
   claims against the configured credential type, creates an issuance
   transaction, allocates a status-list index, returns
   `{ transaction_id, credential_offer, credential_offer_uri, qr_code_svg? }`.
2. **Wallet ← offer:** grant
   `urn:ietf:params:oauth:grant-type:pre-authorized_code`,
   `pre-authorized_code`, and `tx_code` metadata if a PIN was set.
3. **Wallet-facing metadata:**
   - `/.well-known/openid-credential-issuer` (`CredentialIssuerMetadata`, incl.
     per-type `credential_configurations_supported`)
   - `/.well-known/oauth-authorization-server` (`AuthorizationServerMetadata`)
4. **Token endpoint** `POST /token`: validate `pre-authorized_code` (+
   `tx_code`), enforce HAIP client auth (wallet-attestation seam), issue an
   access token bound to the transaction and a `c_nonce`.
5. **Nonce endpoint** `POST /nonce`: fresh `c_nonce` per HAIP/OID4VCI 1.0.
6. **Credential endpoint** `POST /credential`: verify the wallet key-binding
   proof (`jwt` proof type; validate `c_nonce`, extract holder public key for
   `cnf`), then build and sign the credential in the requested format:
   - **SD-JWT VC** (`dc+sd-jwt`): selectively-disclosable claims per config,
     `cnf` with holder JWK, issuer `x5c` chain, `status` claim → status list,
     compact serialization.
   - **mdoc** (`mso_mdoc`): MSO with device key, namespaces/elements per config,
     IssuerAuth COSE_Sign1 with `x5c`, status-list entry.

   Marks the transaction issued.

**HAIP conformance baked in:** issuer key resolution via X.509 `x5c` (trust
chain excl. anchor, non-self-signed leaf); mandatory KB-JWT for holder-bound
credentials; `c_nonce` freshness; unique unpredictable status-list index per
credential.

### Wallet Attestation & Key Attestation

HAIP requires client auth at the token endpoint and supports key attestation at
the credential endpoint. v1 provides a **verification seam**: traits
`WalletAttestationVerifier` and `KeyAttestationVerifier` with a config toggle
(`required` / `optional` / `disabled`) and an Appendix D/E-format implementation
that validates structure + `x5c`. Enforceable but non-blocking for early interop.

## 4. Verification Flow (OpenID4VP, DCQL)

**Admin trigger:** `POST /admin/verification/requests` with
`{ dcql_query | named_query_ref, transport: "request_uri" | "dc_api",
response_mode? }`. Foundry creates a verification transaction (generates
`state`, `nonce`, ephemeral response-encryption key pair) and returns
transport-specific material.

### Transport A — `request_uri` (cross/same-device)

1. Returns `request_uri` + `client_id` (scheme `x509_san_dns`) and a QR/deep
   link (`openid4vp://?...`).
2. **`GET /vp/request/{id}`** serves a **signed request object** (JWS, issuer
   `x5c`) containing the DCQL query, `response_mode=direct_post.jwt`,
   `response_uri`, `client_metadata` (incl. JWKS for response encryption),
   `nonce`, `state`.
3. Wallet posts an **encrypted** response (JWE, `direct_post.jwt`) to
   **`POST /vp/response/{id}`**.

### Transport B — DC API

1. Returns a DC API request object for the browser's `navigator.credentials`
   call, `response_mode=dc_api.jwt`, with `expected_origins`.
2. Wallet/browser returns the response; the frontend relays it to
   **`POST /vp/dc-api/response/{id}`**.

### Core verification engine (shared)

Decrypt JWE → parse `vp_token` → for each DCQL credential query, verify the
presented credential:

- **SD-JWT VC:** verify issuer signature via `x5c` against configured **trust
  anchors**, check `exp`/`nbf`, verify **KB-JWT** (audience = client_id, nonce
  match, `sd_hash`), enforce selective-disclosure ↔ DCQL claim set, **check
  Token Status List**.
- **mdoc:** verify IssuerAuth COSE_Sign1 via `x5c`/trust anchors, verify
  DeviceAuth against the session transcript, validate elements vs DCQL, check
  status. The engine builds the correct session transcript per transport
  (`request_uri` handover vs DC API).
- DCQL matching enforced (required claims present, credential set satisfied).

**Result:** transaction transitions to `verified` / `failed` with a structured
result (disclosed claims, per-check outcomes, trust path, status). Available via
**`GET /admin/verification/requests/{id}`** and/or **webhook POST** to a
configured callback URL.

**HAIP conformance baked in:** signed request objects with `x509_san_dns`;
encrypted responses (`direct_post.jwt` / `dc_api.jwt`); mandatory KB-JWT; X.509
trust-anchor validation (non-self-signed leaf); status-list checking.

## 5. Config Model & Credential Type Definitions

One validated config file (YAML shown; JSON accepted):

```yaml
server:
  wallet_facing:
    public_base_url: https://issuer.example.com
    bind: 0.0.0.0:8443
  admin:
    bind: 127.0.0.1:9000
    api_key_env: FOUNDRY_ADMIN_API_KEY   # or api_key: <literal>
storage:
  path: ./foundry.db                     # SQLite
  transaction_ttl_secs: 600

keys:                                    # named key/cert material
  issuer_sdjwt:
    private_key: ./keys/issuer_ec.pem
    x5c: ./keys/issuer_chain.pem         # leaf..intermediate (no anchor)
    alg: ES256
  verifier_signing:
    private_key: ./keys/verifier_ec.pem
    x5c: ./keys/verifier_chain.pem
    alg: ES256

trust_anchors:                           # for verification
  - name: eudi-root
    certs: ./trust/eudi_root.pem

issuer:
  credential_issuer: https://issuer.example.com
  wallet_attestation: { mode: optional }   # required|optional|disabled
  key_attestation:    { mode: optional }
  status_list:
    enabled: true
    signing_key: issuer_sdjwt
    list_size: 1048576
    public_base_url: https://issuer.example.com/statuslists

credential_types:                        # fully generic, no hard-coded types
  - id: pid
    format: dc+sd-jwt                     # or mso_mdoc
    vct: https://example.com/vct/pid      # (doctype for mdoc)
    cryptographic_holder_binding: true
    display: [{ name: "Person ID", locale: en-US }]
    claims:
      - path: [given_name]
        selectively_disclosable: true
        display: [{ name: "Given name", locale: en-US }]
      - path: [birthdate]
        selectively_disclosable: true

verifier:
  client_id_scheme: x509_san_dns
  signing_key: verifier_signing
  response_encryption: { alg: ECDH-ES, enc: A128GCM }
  named_queries:                         # optional reusable DCQL
    - id: over18
      dcql: { credentials: [ ... ] }
  webhook: { url: https://app.example.com/vp-callback, secret_env: FOUNDRY_WEBHOOK_SECRET }
```

**Validation rules:** every `keys` / `trust_anchors` / `signing_key` reference
must resolve; certs must parse and be non-self-signed where HAIP requires; claim
`path`s must be well-formed; formats must be supported. `credential_types`
drives both the issuer metadata (`credential_configurations_supported`) and
issuance-claim validation; nothing about a credential type is hard-coded.

### Quickstart

`foundry quickstart` (alias `foundry init`) is a convenience wrapper over the
granular key/cert commands:

- Generates a self-signed dev PKI: a root CA plus leaf key+cert chains for
  `issuer_sdjwt`, `verifier_signing`, and the status-list signer, all referencing
  the generated intermediate so `x5c` chains are HAIP-shaped
  (leaf..intermediate, anchor excluded).
- Writes them under `./keys/` and `./trust/` (root cert as a trust anchor).
- Emits a ready-to-run `config.yaml` wired to those paths, with one example
  `pid` credential type and one `over18` named query.
- Prints next steps (`foundry serve --config config.yaml`).

**HAIP caveat:** HAIP mandates that the leaf cert signing requests/credentials
MUST NOT be self-signed, so quickstart produces a proper 2-level chain
(self-signed *root* → non-self-signed *leaf*), not a single self-signed leaf. A
prominent warning marks the output as **dev/test only, not for production**.

Supporting granular commands:

- `foundry keys generate --alg ES256 --out ./keys/issuer_ec.pem`
- `foundry cert new-ca --out ./trust/root.pem`
- `foundry cert issue --ca ... --san-dns issuer.example.com --out ...`

## 6. Crypto, Formats & Trust Internals

### Crypto primitives

ECDSA P-256 (ES256) default per HAIP; the signer abstraction allows
ES384/ES512 and (later) EdDSA. All signing goes through a `Signer` trait so a
KMS/HSM backend can slot in later without touching issuer/verifier logic. The
v1 file-based signer loads PEM/JWK from `keys` config.

### X.509 & trust

- Cert parsing/validation via a maintained Rust lib (`x509-cert` /
  `rustls-pki-types` + `webpki`-style path building).
- **Building `x5c`:** leaf..intermediate, trust anchor excluded (HAIP §6.1.1).
- **Validating incoming chains** (issuer sig on SD-JWT/mdoc, status-list token,
  request-object signer): build path from leaf up to a configured trust anchor,
  reject self-signed leaves, check validity windows and (v1) basic key-usage.
  `x509_san_dns` client-id: match the DNS SAN in the leaf against the request's
  `client_id`.

### SD-JWT VC (`dc+sd-jwt`)

- **Build:** split claims into always-disclosed vs selectively-disclosable (per
  config `path`), generate salted disclosure digests (`_sd`), assemble
  issuer-signed JWT with `x5c`, `cnf` (holder JWK), `vct`, `status`. Compact
  serialization.
- **Verify:** parse SD-JWT + disclosures, recompute digests, verify issuer sig
  via trust anchors, verify KB-JWT (aud, nonce, `sd_hash`), reconstruct
  disclosed claim set.
- **Library:** lean toward a thin in-house implementation over `josekit` for
  full control (consistent with the "own the protocol" goal); final choice
  confirmed during planning.

### mdoc (`mso_mdoc`)

**Scope: credential format only.** Foundry issues and verifies the mdoc data
model (namespaces/elements, MSO, `IssuerAuth`) and exchanges it exclusively over
OpenID4VP. It does NOT implement ISO 18013-5 device engagement, proximity/offline
retrieval, or reader protocols.

- CBOR/COSE via `ciborium` + `coset`. Build MSO (value digests per namespace,
  device key, validity), sign IssuerAuth `COSE_Sign1` with `x5c`.
  Namespaces/elements from config.
- **Verify:** decode CBOR, verify IssuerAuth via trust anchors, verify DeviceAuth
  (device signature or MAC) over the session transcript, match elements to DCQL,
  check status.
- `DeviceAuth` is required for holder binding when an mdoc is presented over
  OpenID4VP. The verifier engine builds the correct **OpenID4VP-handover
  SessionTranscript** per transport: for `request_uri`, from client_id +
  response_uri + nonce; for DC API, from the origin + request nonce. This is the
  OpenID4VP handover only — the ISO 18013-5 proximity/device-retrieval
  transcripts are explicitly out of scope.

### Token Status List (IETF draft-14)

- **Issue:** maintain per-config status lists (bitstring), allocate unique
  unpredictable indices, publish a signed Status List Token (JWT, `x5c`) at
  `/statuslists/{id}`. Admin API to set a credential's status
  (valid/revoked/suspended).
- **Verify:** resolve `status.status_list.uri`, fetch + verify the token
  (`x5c` → trust anchor, non-self-signed), read the index bit, apply to the
  result.

### Testing seams

Each format builder/parser is a pure function over inputs (claims + keys →
credential; credential + trust → verification result), independently
unit-testable with fixture keys from `quickstart`.

## 7. Error Handling, Testing & Observability

### Error handling

- Library crates use typed errors via `thiserror` — per-layer domain enums
  (`IssuanceError`, `VerificationError`, `TrustError`, `FormatError`). No
  `unwrap`/`panic` in request paths.
- HTTP boundary mapping:
  - **Wallet-facing:** spec-compliant OAuth2/OpenID error responses
    (`invalid_request`, `invalid_grant`, `invalid_proof`,
    `invalid_credential_request`, …) with correct status — never leak internal
    detail to wallets.
  - **Admin API:** structured JSON `{ error, message, detail? }` with
    diagnostics (trusted caller).
- Startup/config errors fail fast with an actionable message and non-zero exit.
- Verification produces a **structured per-check result** even on failure
  (which check failed: signature / trust path / KB-JWT / status / DCQL match)
  rather than a single opaque error.

### Testing strategy (TDD throughout)

- **Unit:** format builders/parsers, DCQL matching, disclosure logic,
  status-list bit ops, X.509 path building — fixtures from `quickstart` dev PKI.
- **Integration:** in-process axum app driven by an in-process **wallet stub**
  (issuance: offer → token → nonce → credential; verification: fetch request →
  build VP → encrypted response). Covers both transports, both formats, and
  revocation (issue → revoke → verify-fails).
- **Conformance-oriented:** targeted tests asserting HAIP MUSTs (KB-JWT
  required, `x5c` chain shape, non-self-signed leaf rejected, encrypted response
  required, DCQL enforced).
- **Negative:** expired credential, wrong audience/nonce, tampered signature,
  untrusted anchor, revoked status, missing required DCQL claim.

### Observability

- `tracing` with structured spans keyed by `transaction_id`; per-request logs on
  both surfaces. Log level via config/CLI flag (`--log-level`).
- No secrets/PII at info level; sensitive fields redacted. Debug level may
  include protocol detail.
- **Health/readiness:** `GET /health` (liveness) and `GET /ready` (readiness —
  DB reachable, keys loaded) on the admin listener.
- Optional startup banner summarizing loaded config (issuer id, credential
  types, listeners, storage).

## 8. Technology Summary

| Concern | Choice |
|---|---|
| Language / runtime | Rust, tokio async |
| CLI | clap |
| HTTP server | axum |
| Storage | SQLite (embedded), via `sqlx`/`rusqlite` |
| JOSE / JWT / JWE | `josekit` |
| CBOR / COSE | `ciborium` + `coset` |
| X.509 | `x509-cert` / `rustls-pki-types` + path building |
| Errors | `thiserror` |
| Logging | `tracing` |
| Protocol types | vendored `oid4vci`, `openid4vp` |
| Formats | SD-JWT VC (`dc+sd-jwt`), mdoc (`mso_mdoc`) |
| Query language | DCQL only |
| Profile | HAIP 1.0 final |