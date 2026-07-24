# Foundry Debug Wallet CLI — Design

Status: Approved
Date: 2026-07-24

## 1. Overview

A new binary crate, `foundry-wallet`, provides a terminal-UI (and fully
scriptable headless CLI) debug wallet for exercising and inspecting Foundry's
OpenID4VCI issuance and OpenID4VP verification flows against a running (or
configured) issuer/verifier. It stores every credential-related artifact
(keys, credentials, decoded payloads) as plain files under a wallet data
directory, and logs every outbound HTTP interaction in full for step-by-step
review.

v1 scope is **SD-JWT VC only**; mdoc is future work.

**Goals**
- Trigger issuance end-to-end: create-or-consume a credential offer → `/token`
  → `/nonce` → `/credential` → store the result.
- Trigger verification end-to-end: create-or-consume a verification request →
  fetch the signed request object → match against stored credentials →
  coarse consent → build/encrypt/submit the response → show the result.
- Real X.509 trust validation on both the issuer's credential signature and
  the verifier's request-object signature, toggleable via config.
- Full artifact and event transparency on disk — no hidden state.
- Operable identically by a human (TUI) or a script/AI agent (headless
  subcommands with JSON stdout).

**Non-goals (v1)**
- mdoc format (issuance or verification).
- Fine-grained per-claim consent (coarse accept/decline of the whole request
  only).
- Free-form DCQL/claims editing in the TUI (config-file presets only).
- Proximity/offline (BLE/NFC) flows.
- Multi-wallet-profile support.
- Cryptographic (not just DN-path) certificate chain verification — inherits
  the existing `TODO(trust-hardening)` scope limit already documented in
  `foundry_core::trust::validate_chain`.

## 2. Architecture

New crate `crates/foundry-wallet` (binary `foundry-wallet`), added to the
workspace `members`. New workspace dependencies: `ratatui`, `crossterm`.

```
crates/foundry-wallet/
  src/
    main.rs              # entry point: parse CLI, dispatch to tui:: or headless subcommand handlers
    cli.rs                # clap Parser/Subcommand definitions (tui, issue, verify, credentials, events)
    config.rs             # WalletConfig: admin_url, wallet_url, data_dir, trust_validation flag,
                           #   trust anchors, issuance_presets, verification_presets
    actions/               # shared logic used by both TUI and headless subcommands
      mod.rs
      issuance.rs          # create-or-consume offer -> token -> nonce -> credential -> store
      verification.rs      # create-or-consume request -> fetch request object -> validate trust ->
                            #   match credentials -> consent -> build/encrypt/submit response
      trust.rs              # wraps foundry_core::trust::{TrustStore, validate_chain} for both directions
    storage/
      mod.rs
      credential_store.rs   # read/write wallet-data/credentials/<id>/*
      key_store.rs          # read/write wallet-data/keys/*
      event_log.rs          # append-only JSONL writer/reader for wallet-data/log/events.jsonl
    http/
      mod.rs                # thin reqwest client wrapper that logs every request/response via event_log
    tui/
      mod.rs                # ratatui app loop, screen enum, event dispatch
      screens/
        main_menu.rs
        issuance.rs
        verification.rs
        credentials.rs
        event_log.rs
  Cargo.toml
```

Dependency reuse from existing crates — no protocol logic re-implemented from
scratch:
- `foundry_core::pki::generate_ec_key` — holder key generation.
- `foundry_core::trust::{TrustStore, validate_chain, build_x5c, x5c_entry_to_pem}`
  — chain validation in both directions.
- `foundry_sd_jwt_vc::builder::attach_kb_jwt` — KB-JWT construction for
  presentation.
- `openid4vp::core::jwe::JweBuilder` — encrypting the VP token response.
- `josekit` — JWS proof construction/verification, JWT parsing.
- `foundry_verifier::CreateVerificationResponse` / `foundry_issuer::CreateOfferResponse`
  — typed admin API response deserialization.

## 3. Config file schema (`wallet.yaml`)

```yaml
data_dir: ./wallet-data

endpoints:
  admin_base_url: http://127.0.0.1:9000
  wallet_base_url: http://127.0.0.1:8443
  admin_api_key: dev-admin-key        # or admin_api_key_env, mirroring foundry server's convention

trust:
  validation: enabled                  # enabled | disabled
  anchors:
    - certs: ./trust/root-ca.pem       # same TrustAnchor shape as foundry-core::config::TrustAnchor

issuance_presets:
  pid:
    credential_type_id: pid
    claims:
      given_name: Alice
      birthdate: "1990-01-01"
    tx_code_required: false

verification_presets:
  dcql1:
    dcql_query:
      credentials:
        - id: c1
          format: dc+sd-jwt
          meta: { vct_values: ["https://issuer.example.com/vct/pid"] }
          claims:
            - path: ["given_name"]
            - path: ["birthdate"]
    transport: request_uri
```

- `--config` is required for every subcommand (including `tui`) — no implicit
  default path, to avoid silently operating against the wrong data dir.
- `admin_api_key` follows the same `_env` fallback convention as the server's
  `AdminConfig` for consistency.
- Presets are looked up by name (`--preset <name>`); consuming an external
  URI (`--offer-uri` / `--request-uri`) bypasses the preset entirely and
  skips the "create" admin call.

## 4. CLI surface

```
foundry-wallet tui --config wallet.yaml                 # interactive TUI (default when no subcommand given)
foundry-wallet issue --config wallet.yaml --preset pid [--offer-uri <uri>] [--tx-code <code>]
foundry-wallet verify --config wallet.yaml --preset dcql1 [--request-uri <uri>] --consent accept|decline
foundry-wallet credentials list --config wallet.yaml
foundry-wallet credentials show --config wallet.yaml --id <credential-id>
foundry-wallet events tail --config wallet.yaml [--follow]
```

Headless subcommands print a machine-readable JSON result to stdout on
success and exit 0; on failure they print `{"error": "...", "kind": "..."}`
to stderr and exit 1 — enabling scripted or AI-driven operation without
parsing TUI output.

## 5. Storage layout

```
wallet-data/
  keys/                          # wallet-global keys (not tied to one credential)
  credentials/<credential-id>/
    credential.sdjwt             # raw compact SD-JWT VC (issuer-signed JWT + disclosures)
    payload.json                 # decoded, human-readable: issuer JWT header+payload
                                  #   + merged disclosed claims
    holder_key.pem                # holder private key bound to this credential (PKCS#8 PEM)
    metadata.json                # vct, issuer, received_at, status list uri/idx,
                                  #   disclosed claim names, trust_valid, holder key path
  trust/                         # trusted issuer/verifier root certs (PEM)
  log/
    events.jsonl                 # append-only event log (see section 8)
```

## 6. Issuance flow (`foundry-wallet issue`)

1. **Obtain offer**: if `--offer-uri` is given, parse it
   (`openid-credential-offer://?credential_offer=<url-encoded-json>` or
   `...credential_offer_uri=<url>`, fetching the latter if present) into a
   `CredentialOffer`. Otherwise (preset path), `POST
   {admin_base_url}/admin/issuance/offers` with the preset's
   `credential_type_id`/`claims`/`tx_code_required`, deserializing via
   `foundry_issuer::CreateOfferResponse`.
2. **Token**: extract `pre-authorized_code` from the offer's grants, `POST
   {wallet_base_url}/token` (form-encoded pre-auth grant). If the offer
   requires a `tx_code`, headless mode takes it via `--tx-code`; the TUI
   prompts for it.
3. **Nonce**: `POST {wallet_base_url}/nonce` with the access token → `c_nonce`.
4. **Holder key + proof**: generate a fresh EC key
   (`foundry_core::pki::generate_ec_key`), build an
   `openid4vci-proof+jwt` bound to `c_nonce`/`aud` (issuer identifier from
   the offer/metadata) — construction mirrors the one already proven out in
   `crates/foundry/tests/e2e_full_flow.rs::create_proof`.
5. **Credential**: `POST {wallet_base_url}/credential` with the proof →
   compact SD-JWT VC.
6. **Trust validation** (when `trust.validation: enabled`): parse the issuer
   JWT header's `x5c`, run `foundry_core::trust::validate_chain` against the
   configured anchors. On failure: record `trust_valid: false` plus the
   error detail in `metadata.json` and the event log — storage is **never
   blocked**, since inspecting a broken issuer response is the point of the
   tool. When `disabled`, skip validation and record `trust_valid: null`.
7. **Decode & store**: assign a `credential-id`, write `credential.sdjwt`
   (raw compact), `payload.json` (decoded header + JWT claims + all
   disclosures resolved into a merged claims map), `holder_key.pem`, and
   `metadata.json` (vct, issuer, received_at, status list uri/idx, disclosed
   claim names, trust_valid, holder key path).
8. **Result**: headless prints
   `{"credential_id": "...", "trust_valid": true, "vct": "...", ...}` to
   stdout, exit 0; the TUI shows a result panel with the same information.

Every HTTP request/response in steps 1–5 is logged **in full — no
redaction, including bearer tokens and API keys** — to `events.jsonl`. This
is a deliberate, explicit choice: the wallet is a debugging tool, and
withholding secrets from its own local, human-reviewable log would work
against its purpose.

## 7. Verification flow (`foundry-wallet verify`)

1. **Obtain request**: if `--request-uri` is given, parse it
   (`openid4vp://?request_uri=<url>` or a direct
   `https://.../vp/request/:id` URL) and `GET` it. Otherwise (preset path),
   `POST {admin_base_url}/admin/verification/requests` with the preset's
   `dcql_query`/`transport` (via `foundry_verifier::CreateVerificationResponse`),
   then `GET {wallet_base_url}/vp/request/{verification_id}`.
2. **Parse & validate the signed request object**: split the compact JWS,
   decode the header for `x5c`, decode the payload for `client_id`, `nonce`,
   `dcql_query`, `client_metadata.jwks`. When `trust.validation: enabled`:
   verify the JWS signature using the leaf certificate's public key, then
   `validate_chain` against the configured anchors; **on failure, abort the
   flow** — unlike issuance, there is no artifact worth keeping if the
   request itself cannot be trusted enough to safely respond to. When
   `disabled`: skip both checks, log a warning, and proceed.
3. **Match stored credentials**: for each `credentials[]` entry in the DCQL
   query, scan `wallet-data/credentials/*/metadata.json` for a stored SD-JWT
   VC whose `vct` is among `meta.vct_values` (if present) and whose
   disclosed claims cover every requested `claims[].path`. Pick the
   most-recently-received match per entry. If any entry has no match, the
   request cannot be satisfied: headless exits non-zero with a clear
   "no matching credential" result; the TUI shows this instead of a consent
   screen.
4. **Consent (coarse)**: present the requester's `client_id`, the matched
   credential id(s), and the exact claims that will be disclosed. Headless:
   `--consent accept|decline` is a required flag (no default, forcing an
   explicit choice even in scripted/AI use). TUI: Accept/Decline keypress.
5. **On accept**: build the presentation via `attach_kb_jwt` (using the
   matched credential's `holder_key.pem`) bound to `client_id`/`nonce`;
   encrypt with `JweBuilder` using the ephemeral key from
   `client_metadata.jwks`; `POST {wallet_base_url}/vp/response/{verification_id}`
   with the JWE body.
6. **On decline**: the response endpoint is never called (mirrors how a real
   wallet aborts); a decline event is logged; headless exits 0 with
   `{"consent": "declined"}`.
7. **Result**: parse and print/display the returned `VerificationResult`
   (`verified`, `checks[]`).

Same full-logging behavior as issuance applies here — every HTTP call
logged in full, no redaction.

## 8. Event log format

`wallet-data/log/events.jsonl` — one JSON object per line, append-only:

```json
{"ts":"2026-07-24T10:00:00Z","kind":"http_request","direction":"out","method":"POST","url":"http://127.0.0.1:8443/credential","headers":{"...":"..."},"body":"..."}
{"ts":"2026-07-24T10:00:00Z","kind":"http_response","status":200,"headers":{"...":"..."},"body":"..."}
{"ts":"2026-07-24T10:00:00Z","kind":"credential_stored","credential_id":"...","trust_valid":true}
{"ts":"2026-07-24T10:00:01Z","kind":"consent_decision","verification_id":"...","decision":"accept"}
{"ts":"2026-07-24T10:00:01Z","kind":"trust_validation_failed","context":"verification_request","error":"..."}
```

`foundry-wallet events tail [--follow]` reads/tails this file; the TUI's
Event Log screen renders the same records live.

## 9. TUI screens

Built with ratatui, driven by a crossterm `EventStream` under tokio.

- **Main menu**: Trigger Issuance / Trigger Verification / Browse
  Credentials / Event Log / Quit.
- **Trigger Issuance**: preset picker (from config) or "paste offer URI"
  text input → live progress log of each step → result panel.
- **Trigger Verification**: same input pattern → consent screen
  (`client_id` + claims + Accept/Decline) → result panel.
- **Browse Credentials**: list of credential ids (vct, issuer, received_at)
  → detail view rendering `payload.json` and `metadata.json`.
- **Event Log**: scrollable tail of `events.jsonl`, most recent last,
  following new entries live.

## 10. Error handling

- Every `actions/` module returns a typed `WalletError` (`thiserror`) with
  variants for HTTP failures, trust validation failures, storage I/O,
  malformed offers/request objects, and no-matching-credential.
- Headless subcommands: on `Err`, print `{"error": "<message>", "kind": "<variant>"}`
  to stderr as JSON and exit 1. This mirrors the server's
  "structural vs. policy" distinction — a failed trust chain is a hard
  error; "no matching credential" is a normal, expected outcome, still
  reported via JSON but distinguishable by `kind`.
- TUI: errors render as a dismissable panel over the current screen; the
  event loop never crashes. No `.unwrap()`/`.expect()`/`panic!()`/
  `unreachable!()` in `actions/`, `storage/`, or `http/` (production request
  paths), matching the workspace-wide rule in `AGENTS.md` — permitted only
  inside `#[cfg(test)]` code.

## 11. Testing strategy

- **Unit tests**: offer/request-URI parsing, DCQL-to-stored-credential
  matching logic, event log read/write, storage layout read/write
  round-trips — all pure functions, no network.
- **Integration tests**: spin up the real `foundry` binary (reusing the
  `spawn_server` pattern from `crates/foundry/tests/e2e_full_flow.rs`) and
  drive `foundry-wallet issue` / `foundry-wallet verify` as subprocesses,
  asserting on stdout JSON and on the resulting files under a tempdir
  `data_dir`. This is the primary regression net, exercising the real
  HTTP/crypto path end-to-end without mocking.
- **No TUI-rendering tests** in v1 — out of scope. All business logic lives
  in `actions/`, independently testable from rendering; ratatui's
  `Terminal`/`TestBackend` could add screen snapshot tests later as a
  fast-follow.

## 12. Non-goals / future work (recap)

mdoc format support; fine-grained per-claim consent selection; free-form
DCQL/claims editing in the TUI; cryptographic (not just DN-path)
certificate chain verification (tracked as the pre-existing
`TODO(trust-hardening)` in `foundry_core::trust`, inherited as-is);
multi-wallet-profile support; TUI snapshot tests.