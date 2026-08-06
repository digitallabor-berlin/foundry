# Foundry

**Foundry** is a modular, high-performance Digital Credential Issuing & Verification Service written in Rust. It implements standards including OpenID for Verifiable Credential Issuance (OpenID4VCI), OpenID for Verifiable Presentations (OpenID4VP), W3C SD-JWT VC (`dc+sd-jwt`), ISO/IEC 18013-5 mdoc, and IETF Token Status Lists.

---

## Workspace Architecture

Foundry is structured as a Rust cargo workspace comprising several modular crates:

| Crate | Path | Description |
|---|---|---|
| `foundry` | `crates/foundry` | Main binary & HTTP service providing server startup, admin API, wallet endpoints, and PKI CLI commands. |
| `foundry-core` | `crates/foundry-core` | Core data models, YAML configuration parser/validator, SQLite storage driver, PKI/cert handling, trust anchor validation, and Token Status List generation/verification. |
| `foundry-issuer` | `crates/foundry-issuer` | Framework-agnostic OpenID4VCI business logic: metadata builders, transaction lifecycle, CSPRNG status-list index allocation, and offer creation. |
| `foundry-sd-jwt-vc` | `crates/foundry-sd-jwt-vc` | SD-JWT VC issuing, disclosure calculation, holder binding (KB-JWT), and verification. |
| `foundry-mdoc` | `crates/foundry-mdoc` | ISO/IEC 18013-5 mdoc / CBOR / COSE IssuerAuth builder and DeviceAuth verifier. |

---

## Prerequisites

- **Rust:** Version 1.97 or later (edition 2021). See `rust-toolchain.toml`.
- **Cargo:** Included with Rust installation (`rustup`).

---

## Building the Project

To build the entire workspace:

```bash
cargo build --workspace
```

To build in release mode:

```bash
cargo build --workspace --release
```

To build only the `foundry` binary CLI tool:

```bash
cargo build -p foundry
```

---

## Docker

A multi-stage `Dockerfile` at the repo root builds and packages the `foundry` server binary. The builder stage uses `rust:1.97-slim-bookworm` (matching `rust-toolchain.toml`) with `pkg-config`/`libssl-dev` installed, since `josekit` depends on a dynamically linked `openssl-sys`. The runtime stage is `debian:bookworm-slim` with `ca-certificates`/`libssl3` and runs as a non-root `foundry` user.

### Building the image

```bash
docker build -t foundry:latest .
```

(Podman works as a drop-in replacement: `podman build -t foundry:latest .`)

**Building for a different target architecture (e.g. deploying to an amd64
cluster from an Apple Silicon / arm64 machine):** a plain `docker build` always
targets the *host's* architecture and gives no warning when that doesn't match
where the image will run — the mismatch only surfaces at container start as an
`exec format error` (or an equivalent silent failure, depending on the runtime).
The naive fix is to force the target platform with `buildx`:

```bash
docker buildx build --platform linux/amd64 -t foundry:latest --load .
```

**This reliably segfaults `rustc` on Apple Silicon.** `--platform linux/amd64`
does not cross-compile — it runs the *entire* amd64 toolchain, including
`rustc`/LLVM, under QEMU's user-mode CPU emulation, and rustc crashes under
that emulation on M-series Macs (`rustc -vV` or even a bare `rustc` invocation
segfaults, signal 11, before any of your code is even touched). This is a
currently open upstream issue — see
[rust-lang/rust#147026](https://github.com/rust-lang/rust/issues/147026) and
[rust-lang/rustup#3902](https://github.com/rust-lang/rustup/issues/3902) — not
something wrong with this Dockerfile or your Docker setup, and there is no
reliable QEMU flag that fixes it.

Two real ways around it:

1. **Build on a native amd64 host** (a cloud VM, a GitHub Actions `ubuntu-latest`
   runner, etc.) instead of emulating locally. No Dockerfile or command changes
   needed — just run the same `docker build`/`docker buildx build --platform
   linux/amd64 --push .` on an amd64 machine, where it's a native build rather
   than an emulated one. `.github/workflows/docker-publish.yml` already does
   exactly this on every push/tag — see [CI](#ci-automated-build--push) below
   — so in practice you shouldn't need to build+push manually at all.
2. **True cross-compilation**, if you need to keep building on Apple Silicon.
   This means rustc runs *natively* (arm64) and targets amd64 without ever
   executing amd64 machine code, so QEMU emulation of the compiler itself is
   avoided entirely. The standard tool for this in a Dockerfile is
   [`tonistiigi/xx`](https://github.com/tonistiigi/xx) (its `xx-cargo` wrapper
   handles the target triple, C toolchain and `pkg-config` setup, which matters
   here since `josekit` needs `openssl-sys` to link dynamically against the
   *target* architecture's `libssl-dev`, not the host's). This is a real
   rewrite of the builder stage of this Dockerfile — it hasn't been done here
   yet; happy to do it on request, but it needs validating against an actual
   `docker buildx` environment before trusting it in CI.

Once you have a genuinely `amd64` image (built either way), verify it before
pushing:

```bash
docker inspect foundry:latest --format '{{.Architecture}}'   # must print: amd64
```

### CI: automated build & push

`.github/workflows/docker-publish.yml` builds and pushes
`containers.digitallabor.dev/foundry/foundry` on a GitHub-hosted
`ubuntu-latest` runner — genuinely amd64, not emulated, which is exactly why
this exists (see the segfault discussion above). It runs `cargo fmt --check` +
`cargo clippy --workspace --all-targets -- -D warnings` + `cargo test
--workspace` first and only builds/pushes if those pass — mirroring the
workspace-wide gates this repo requires before any change is considered done
(see the root `AGENTS.md`).

| Trigger | Tags produced |
|---|---|
| push to `main` | `:latest`, `:sha-<short-sha>` |
| push tag `vX.Y.Z` | `:vX.Y.Z`, `:X.Y`, `:X`, `:sha-<short-sha>` |
| manual (`workflow_dispatch`) | whatever the current ref would produce |

It intentionally does **not** use `docker/setup-qemu-action` — adding it back
would reintroduce the segfault this workflow exists to avoid; if you ever need
multi-arch (`linux/amd64,linux/arm64`) images, that requires the
`tonistiigi/xx`-based cross-compilation rewrite discussed above, not QEMU.

**One-time repo setup** — two secrets under *Settings → Secrets and
variables → Actions*, matching the credentials already in
`~/dev/dl-infra-k8s/foundry/regcred.yaml` for `containers.digitallabor.dev`:

| Secret | Value |
|---|---|
| `REGISTRY_USERNAME` | the registry username (`capmin`) |
| `REGISTRY_PASSWORD` | the registry password |

### Running the image

The image expects `config.yaml`, the key material, and trust anchors it references to be bind-mounted rather than baked in (they're config-driven via paths relative to the config file, and already gitignored). The default entrypoint runs `foundry`, with `CMD` set to `serve --config /app/config.yaml`:

```bash
docker run --rm \
  -v $PWD/config.yaml:/app/config.yaml \
  -v $PWD/keys:/app/keys \
  -v $PWD/trust:/app/trust \
  -v $PWD/foundry.db:/app/foundry.db \
  -p 8443:8443 -p 9000:9000 \
  foundry:latest
```

The wallet-facing (`8443`) and admin (`9000`) listeners are both plain HTTP inside the container — TLS is expected to be terminated externally (e.g. a reverse proxy), same as when running the binary directly.

Other CLI subcommands work the same way by overriding the default command, e.g. to run `quickstart` against a mounted output directory:

```bash
docker run --rm -v $PWD/dev:/app/dev foundry:latest quickstart --dir /app/dev --out-config /app/dev/config.yaml
```

*Note: the image runs as a fixed non-root user (uid 999). If a bind-mounted host directory isn't writable by that uid, pass `--user "$(id -u):$(id -g)"` to run as your own user instead.*

---

## Running the Project

Foundry includes CLI commands for setting up a development environment, managing keys and certificates, validating configuration files, and running the HTTP service.

### 1. Quickstart (Development Setup)

Generate a self-signed dev PKI (Root CA + leaf certificates for issuer, verifier, and status list) along with a ready-to-run `config.yaml`:

```bash
cargo run -p foundry -- quickstart
```

The generated config ships **two** credential types: `pid` (a Person ID) and
`com.emvco.dpc.card` (an EMVCo Digital Payment Credential). See
[Credential Types & Claim Configuration](#credential-types--claim-configuration).

*Note: The quickstart command is for development/testing only.*

### 2. Validating Configuration

Validate your YAML configuration file against key files and trust anchors:

```bash
cargo run -p foundry -- config validate --config config.yaml
```

### 3. Running the HTTP Server

Boot the dual-listener HTTP service (Admin API on `127.0.0.1:9000` and Wallet-facing API on `0.0.0.0:8443` by default):

```bash
cargo run -p foundry -- serve --config config.yaml
```

#### Exposed Endpoints

**Wallet-facing Server (`0.0.0.0:8443`):**
- `GET /.well-known/openid-credential-issuer` — OpenID4VCI Credential Issuer Metadata
- `GET /.well-known/oauth-authorization-server` — OAuth 2.0 Authorization Server Metadata
- `POST /challenge` — ABCA §8 attestation challenge retrieval; registered only when `issuer.wallet_attestation.challenge_mode` is not `disabled` (see [ABCA Challenge Retrieval](#abca-challenge-retrieval-post-challenge))
- `GET /api-docs` — Interactive OpenAPI/Swagger UI for the wallet-facing (OpenID4VCI/OpenID4VP) endpoints
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON) for the wallet-facing endpoints

**Admin Server (`127.0.0.1:9000`):**
- `GET /health` — Health check endpoint
- `GET /ready` — Readiness check endpoint (verifies storage connectivity)
- `GET /api-docs` — Interactive OpenAPI/Swagger UI (enabled by default; see [API Documentation](#api-documentation-openapi--swagger-ui) below)
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON)
- `GET /console` — Embedded HTML/JS test console for triggering issuance/verification flows (enabled by default; see [Admin Test Console](#admin-test-console) below)
- `POST /admin/issuance/offers` — Create credential offers (requires Bearer token if `admin.api_key` is set)

#### API Documentation (OpenAPI / Swagger UI)

Foundry auto-generates **two independent** OpenAPI 3.x specifications — one for the admin API, one for the wallet-facing OpenID4VCI/OpenID4VP protocol endpoints — each served from its own listener.

**Admin API** (`127.0.0.1:9000` by default):
- Swagger UI: `http://127.0.0.1:9000/api-docs`
- Raw spec: `http://127.0.0.1:9000/api-docs/openapi.json`
- Toggle: `server.admin.swagger_ui_enabled` (default `true`)
- Startup file: `openapi.json`

**Wallet-facing API** (`0.0.0.0:8443` by default):
- Swagger UI: `http://localhost:8443/api-docs`
- Raw spec: `http://localhost:8443/api-docs/openapi.json`
- Toggle: `server.wallet_facing.swagger_ui_enabled` (default `true`)
- Startup file: `openapi-wallet.json`

All four docs endpoints are unauthenticated, served alongside `/health`/`/ready` on the admin listener and alongside the protocol endpoints on the wallet-facing listener. Since the wallet-facing listener binds `0.0.0.0` by default (publicly reachable), set `server.wallet_facing.swagger_ui_enabled: false` in production if you don't want the docs UI exposed on the public interface — the raw JSON spec at `/api-docs/openapi.json` remains available either way (it does not carry secrets, only route/schema shapes).

Both `openapi.json` and `openapi-wallet.json` are written to the working directory on every `serve` startup — convenient for generating client SDKs or importing into tools like Postman/Insomnia.

#### Example: Creating an Offer via Admin API

```bash
curl -X POST http://127.0.0.1:9000/admin/issuance/offers \
  -H "Authorization: Bearer dev-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type_id": "pid",
    "claims": {
      "given_name": "Alice",
      "birthdate": "1990-01-01"
    },
    "tx_code_required": false
  }'
```

#### Admin Test Console

`foundry` serves a self-contained HTML/JS test console at `GET /console` on
the Admin listener (`http://127.0.0.1:9000/console` by default) — no build
step, no external dependencies (a small QR-code library is vendored inline).
It lets you trigger the two admin flows from a browser instead of hand-rolling
`curl` calls, and produces a QR code a real wallet app can scan:

- **Issuance**: enter a `credential_type_id` and `claims` JSON, click
  "Create Offer" — get back the `credential_offer_uri` as copyable text and
  as a QR code. Scan it with a real wallet, tap **Open in Wallet** on the same
  device, or use **Add to Wallet (Digital Credentials API)** to hand the offer
  to the platform's wallet picker (see below). The page polls the transaction
  and shows `offered` → `issued`, plus the transaction code when
  `tx_code_required` is set.
- **Verification**: pick a named query (`named_query_ref`) or paste raw
  `dcql_query` JSON, optionally paste a `transaction_data` JSON array under
  "Transaction data (optional)", click "Create Verification Request" — get back
  the `openid4vp_uri`/`request_uri` as copyable text and as a QR code. The page
  auto-polls the request's status and shows `verified`, each check's
  pass/fail, and the disclosed claims once the wallet responds. When
  `transaction_data` was requested, the checks list gains a
  `transaction_data_binding` entry reporting whether the wallet hashed the
  advertised entries into its Key Binding JWT.

The console only calls the existing Admin API (same endpoints as the `curl`
example above) — paste your Admin API key into the field at the top of the
page; it is remembered in the browser's `localStorage` for convenience,
since the Admin listener is loopback-only by default. Disable it entirely
with `server.admin.console_enabled: false` if you don't want it exposed;
like Swagger UI, this only affects the Admin listener.

##### Digital Credentials API prerequisites

Both "Add to Wallet (Digital Credentials API)" (issuance,
`navigator.credentials.create()`) and "Trigger via Digital Credentials API"
(presentation, `navigator.credentials.get()`) invoke a browser API with
platform requirements the console cannot satisfy on your behalf:

- Chrome 143 or later, and Google Play services 24.0 or later on the Android
  device.
- `chrome://flags/#web-identity-digital-credentials-creation` enabled (issuance
  is an origin trial; `foundry` embeds no origin-trial token, since the console
  is a local testing tool rather than a deployed origin).
- A supported wallet app installed on the Android device.
- **`issuer.credential_issuer` must be reachable from the Android device.** A
  `localhost` or `127.0.0.1` issuer URL fails the cross-device flow even though
  the QR scans correctly and the handoff appears to succeed — the wallet
  resolves `credential_issuer` itself when it calls `/token`. Use a
  LAN-reachable host or a tunnel. This is the failure mode most likely to be
  misread as a `foundry` bug.
- **`verifier.dc_api_expected_origins` must list the origin the console is
  served from** — see [DC API Expected Origins](#dc-api-expected-origins) below.
  This is the presentation-side equivalent of the previous bullet, and the
  second most likely thing to be misread as a `foundry` bug.

The console never gates the buttons on browser sniffing: it always offers them
and reports an unsupported browser at the point of use.

The console is responsive and usable from a phone, which is the expected setup
for driving a Digital Credentials API flow: below 640px the DC API button becomes
the first, full-width action in the result block, and the QR code collapses
behind a `QR code` disclosure — it is unscannable on the device displaying it,
and one tap reopens it. Desktop layout is unchanged.

Note that the Digital Credentials API is a **platform handoff channel, not a
protocol**. The payload handed to the wallet is the same OpenID4VCI Credential
Offer the deep link carries, so `/token` and `/credential` behave identically
regardless of which affordance you used.

##### DC API Expected Origins

Over the Digital Credentials API transport, OpenID4VP requires a wallet to bind
an SD-JWT VC's KB-JWT `aud` to the **browsing-context Origin** of the page that
called `navigator.credentials.get()`, prefixed with `origin:` — *not* to the
verifier's `x509_hash` Client Identifier, which is what every other transport
uses. The browser attests that Origin to the wallet; the server cannot derive it
(RFC 6454), so it has to be told:

```yaml
verifier:
  dc_api_expected_origins: ["https://verifier-site.example"]
```

List one entry per site expected to invoke this verifier over the DC API. A
single trailing slash is normalised away, so `https://x.example` and
`https://x.example/` both match.

> **Set this whenever you drive a DC API presentation from the admin console.**
> `/console` is served **only by the admin listener**, so the Origin the wallet
> is handed is the *admin* origin — `http://127.0.0.1:9000` by default, or
> whatever hostname a reverse proxy exposes that listener on. Left unset,
> foundry falls back to a single origin derived from
> `server.wallet_facing.public_base_url`, which is a **different** Origin
> whenever the two listeners differ in host *or* port — which is the default
> (`:9000` vs `:8443`) and stays true behind a proxy that gives them separate
> hostnames. The fallback exists only for the single-origin case where the DC
> API caller and the wallet-facing listener genuinely share an Origin.

The symptom when this is wrong is an otherwise well-formed presentation failing
at HTTP 400 with:

```
verification failed: holder key binding verification failed: KB-JWT audience mismatch
```

The log record does not carry the two values being compared, so confirm them
from each side: the wallet's attested Origin (CMWallet logs it as
`GetCredentialActivity: origin <value>`, readable via `adb logcat`) against this
config key — or, when it is unset, against `public_base_url`.

The console plus a real wallet app is the supported way to drive an issuance
or presentation by hand — foundry ships no wallet client of its own. For a
scripted equivalent that needs no wallet at all, the end-to-end test boots the
real binary and drives both flows over HTTP:

```bash
cargo test -p foundry --test e2e_full_flow -- --ignored
```

See [End-to-End Test](#end-to-end-test-real-subprocess-issue--verify--revoke--re-verify)
below for what it covers.

### 4. Key & Certificate Management CLI

Foundry provides built-in tools for generating EC private keys (PKCS#8 PEM) and issuing X.509 certificates.

#### Generate an EC Private Key (ES256 / P-256)
```bash
cargo run -p foundry -- keys generate --alg ES256 --out private_key.pem
```

#### Create a Root CA
```bash
cargo run -p foundry -- cert new-ca --cn "My Root CA" --out-cert ca.pem --out-key ca-key.pem --days 3650
```

#### Issue a Leaf Certificate
```bash
cargo run -p foundry -- cert issue \
  --ca ca.pem \
  --key ca-key.pem \
  --cn "Issuer Service" \
  --san localhost \
  --out-cert leaf.pem \
  --out-key leaf-key.pem \
  --days 365
```

---

## Wallet Attestation & Client Attestation Proof-of-Possession

Foundry gates `POST /token` on `issuer.wallet_attestation.mode`
(`disabled` / `optional` / `required`), configured per-issuer:

```yaml
issuer:
  wallet_attestation:
    mode: required
    trusted_anchors:
      - name: wallet-provider-ca
        certs: /path/to/wallet-provider-ca.pem
    pop_max_age_secs: 300   # optional; default shown
```

- `mode: disabled` — no attestation is required or checked, even if a wallet
  sends one.
- `mode: optional` — a wallet may omit the `OAuth-Client-Attestation` header
  entirely; but if it sends one, the attestation (and, since the field below,
  its accompanying proof-of-possession) MUST be valid.
- `mode: required` — a wallet MUST send `OAuth-Client-Attestation`.
- `pop_max_age_secs` (`u64`, default `300`) — the ABCA (Attestation-Based
  Client Authentication) draft's sliding-window staleness bound for the
  Client Attestation PoP JWT's `iat` claim, per `draft-ietf-oauth-
  attestation-based-client-auth` §10.6/§12.1.

**Behaviour change:** as of this release, whenever a Wallet Attestation JWT
(`OAuth-Client-Attestation`) is presented — under **both** `optional` and
`required` mode — the request MUST also carry a matching
`OAuth-Client-Attestation-PoP` header: a JWT proving possession of the
private key the attestation's `cnf.jwk` claim attests to, per
`draft-ietf-oauth-attestation-based-client-auth` §5.2/§6.2. A Wallet
Attestation presented with no PoP is now rejected with HTTP 400
`{"error": "invalid_client"}`, where previously it was accepted outright
(GAP-VCI-14). **Deployments running `wallet_attestation.mode: required` (or
`optional` with wallets that send an attestation) must upgrade their wallet
client to send the PoP header before upgrading the issuer**, or existing
wallets will start failing `/token` requests.

The PoP's `jti` is claimed exactly once via an atomic anti-replay check
(`Storage::insert_kv_if_absent`), so a captured-and-resent PoP is rejected on
its second use even if it is otherwise perfectly valid and unexpired.

Two further rules are enforced and worth knowing when debugging a client:

- **Each header must appear at most once** (ABCA §6.2 rules 1–2). Sending
  `OAuth-Client-Attestation` or `OAuth-Client-Attestation-PoP` twice is
  rejected even if both copies are identical and valid — a proxy that
  duplicates the header will break the request rather than being silently
  tolerated. A present-but-non-UTF-8 header value is likewise rejected rather
  than treated as absent.
- **The attestation's `cnf.jwk` must be a public key** (ABCA §9 rule 6). An
  Attester that mistakenly embeds private key material is rejected, since such
  an attestation would let any observer mint PoPs for that wallet.

### ABCA Challenge Retrieval (`POST /challenge`)

Independently of the fields above, `issuer.wallet_attestation.challenge_mode`
(`disabled` / `optional` / `required`, **`disabled` by default** — nothing
changes for an existing deployment until an operator opts in) gates ABCA §8's
server-provided challenge mechanism:

```yaml
issuer:
  wallet_attestation:
    challenge_mode: required   # disabled (default) | optional | required
```

- **`disabled`** (default) — `POST /challenge` is not served (404) and
  `challenge_endpoint` is not advertised in `/.well-known/oauth-authorization-
  server`. A Client Attestation PoP's `challenge` claim, if a wallet sends
  one anyway, is ignored.
- **`optional`** — `POST /challenge` is served; a PoP's `challenge` claim is
  validated if present, but its absence is accepted.
- **`required`** — a PoP MUST carry a valid `challenge` claim, minted by this
  issuer via `POST /challenge` within `pop_max_age_secs` of the request. A
  missing, expired, mismatched, or foreign `challenge` is rejected with HTTP
  400 `{"error": "use_attestation_challenge"}`, and — per ABCA §6.2 — the
  response carries a fresh `OAuth-Client-Attestation-Challenge` header the
  wallet can retry with immediately, no extra round trip to `/challenge`
  required. The same header rides a **successful** `/token` response too
  (ABCA §8.1), so a wallet always holds a usable challenge for its next
  request.

> **`required` only binds a PoP that is actually presented.** `challenge_mode`
> strengthens a Client Attestation PoP; it is not an independent authentication
> requirement. Under `wallet_attestation.mode: optional`, a wallet that sends no
> `OAuth-Client-Attestation` header at all is never asked for a PoP, so no
> `challenge` is ever checked — `challenge_mode: required` is then effectively
> optional. To make challenges genuinely mandatory, set **both**
> `mode: required` and `challenge_mode: required`.

`POST /challenge` is unauthenticated (like `POST /nonce`), returns
`{"attestation_challenge": "..."}`, and sets `Cache-Control: no-store` on
every response.

---

## Android Keystore Attestation (Google Wallet `android_keystore_attestation` proof type)

Foundry accepts Google Wallet's `android_keystore_attestation` proof type at
`POST /credential` — an array of X.509 certificate chains carrying an Android
Keystore hardware attestation, rather than a signed JWT (it is not the
OpenID4VCI Appendix D key attestation JWT format). It is configured alongside
the existing `issuer.key_attestation` block (which continues to govern the
`jwt` proof type's own key-attestation-JWT support), sharing its
`trusted_anchors`:

```yaml
issuer:
  key_attestation:
    trusted_anchors:
      - name: google-android-root
        certs: /etc/foundry/android-attestation-roots.pem
    android:
      mode: optional                              # disabled (default) | optional | required
      key_mint_security_level: TrustedEnvironment  # Software | TrustedEnvironment | StrongBox
```

- `mode: disabled` (default) — the proof type is never advertised in issuer
  metadata, and any `android_keystore_attestation` member in a `/credential`
  request's `proofs` object is rejected with HTTP 400 `invalid_proof`.
- `mode: optional` — the proof type is accepted alongside `jwt`; a Credential
  Request must still use exactly one proof type, per OpenID4VCI's own rule.
- `mode: required` — only `android_keystore_attestation` is accepted; a
  Credential Request presenting the `jwt` proof type is rejected.
- `key_mint_security_level` (default `TrustedEnvironment`) — the minimum
  KeyMint security level enforced independently against **both** the
  certificate's `attestationSecurityLevel` and `keyMintSecurityLevel` fields.
  `StrongBox` is strictly stronger than `TrustedEnvironment`, which is
  strictly stronger than `Software`.
- **Enabling this proof type with an empty `trusted_anchors` is a startup
  configuration error** — the same fail-closed rule the `wallet_attestation`
  and `key_attestation` (`jwt`) blocks already enforce.
- `trusted_anchors` should point at Google's published Android Key Attestation
  root certificates:
  <https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate>.
- **Revocation is not checked.** Google's guidance asks issuers to check a
  presented attestation certificate against
  `https://android.googleapis.com/attestation/status`; foundry does not make
  this call. A revoked attestation key is currently accepted if its
  certificate chain otherwise validates and its security level and
  `attestationChallenge` are correct. This is a named follow-on, not an
  oversight — see the design doc's "Deviations and known limitations"
  (`docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md`).

No new log field names are introduced, so the Logging & Observability section
below needs no change; the `attestationChallenge` (a `c_nonce`) and the
attestation's `uniqueId` (a privacy-sensitive hardware device identifier) are
never logged, per root `AGENTS.md` §4.5.

---

## DPoP (RFC 9449) — Sender-Constrained Access Tokens

Foundry supports RFC 9449 DPoP so an access token can be bound to a wallet-held
key instead of being a bare bearer credential, gated by `issuer.dpop.mode`:

```yaml
issuer:
  dpop:
    mode: optional          # optional (default) | required | disabled
    max_age_secs: 300       # how far from now a proof's iat may sit, in either direction (clock skew)
```

- **`optional`** (default) — a valid `DPoP` proof at `POST /token` binds the
  issued access token to that key and the response carries
  `token_type: "DPoP"`; its absence yields a plain `token_type: "Bearer"`
  token exactly as before DPoP existed.
- **`required`** — `POST /token` rejects any request that does not carry a
  `DPoP` header.
- **`disabled`** — the `DPoP` header is **ignored**, not rejected: RFC 9449
  §10.1 encourages clients that attach `DPoP` to every request to the
  authorization server, and §5 lets an AS signal non-binding via
  `token_type: Bearer`. Rejecting the header here would hard-fail a wallet
  doing exactly what the RFC recommends.

Once an access token is DPoP-bound, `POST /credential` enforces the binding
unconditionally, regardless of `issuer.dpop.mode` at request time (the binding
is a property of the already-issued token, not of current policy): the token
MUST be presented with the `DPoP` scheme and a matching proof, or the request
is rejected with HTTP 401 and a `WWW-Authenticate: DPoP` challenge. A
DPoP-bound token presented as `Bearer` is rejected (RFC 9449 §7.2's
anti-downgrade rule) — this is what stops a stolen bound token being replayed
under the weaker scheme.

A proof is single-use, tracked via its `jti` for `max_age_secs` (plus a fixed
clock-skew allowance) at both `/token` and `/credential`, scoped independently
per target URI and per key, so no wallet can exhaust another's replay budget.

Optionally, a wallet MAY send a `dpop_jkt` parameter to `GET /authorize`,
pinning the eventual authorization code to that key; `POST /token` then
rejects a mismatched key before the code is invalidated, so a captured code
cannot be redeemed under an attacker-controlled key.

### Server-Provided DPoP Nonces (RFC 9449 §8/§9)

Independently of `mode` above, `issuer.dpop.nonce_mode` (`disabled` /
`optional` / `required`, **`disabled` by default** — nothing changes for an
existing deployment until an operator opts in) gates RFC 9449's optional
server-provided nonce mechanism:

```yaml
issuer:
  dpop:
    nonce_mode: required   # disabled (default) | optional | required
```

- **`disabled`** (default) — no `DPoP-Nonce` header is ever emitted; a
  proof's `nonce` claim, if a wallet sends one anyway, is ignored.
- **`optional`** — a proof's `nonce` claim is verified if present, but its
  absence is accepted.
- **`required`** — a proof MUST carry a valid, unexpired `nonce` minted by
  this issuer. A missing or stale one is rejected: at `POST /token` (RFC 9449
  §8) with HTTP 400 `{"error": "use_dpop_nonce"}`; at `POST /credential` (§9)
  with HTTP 401 and a `WWW-Authenticate: DPoP error="use_dpop_nonce",
  algs="ES256"` challenge. Either way the response carries a fresh
  `DPoP-Nonce` header the wallet retries with immediately. The same header
  rides a **successful** response too (§8.2), so a wallet always holds a
  usable nonce for its next request, and never more than one `DPoP-Nonce`
  header is ever emitted on a single response.

Under `optional` and `required` alike, a fresh `DPoP-Nonce` also rides the
responses of the two unauthenticated freshness endpoints — `POST /nonce` and
`POST /challenge` — so a wallet can obtain its first nonce before its first
authenticated request instead of learning it from a rejection. No pinned
specification requires this: it accommodates wallets that expect it, Google
Wallet among them (`docs/specs/google-wallet-openid4vci-profile.md`).
OpenID4VCI 1.1 WG draft §8.2-4 standardises the `/nonce` case; the
`/challenge` case is standardised nowhere.

> **`required` only binds a proof that is actually presented.** `nonce_mode`
> strengthens a DPoP proof; it is not an independent authentication requirement.
> Under `dpop.mode: optional`, a wallet that sends no `DPoP` header receives a
> plain `Bearer` token and never encounters the nonce requirement —
> `nonce_mode: required` is then effectively optional. To make nonces genuinely
> mandatory, set **both** `mode: required` and `nonce_mode: required`.

A DPoP nonce, an ABCA `attestation_challenge`, and an OpenID4VCI `c_nonce` are
minted from the same MAC secret but are domain-separated: one can never verify
as another, even if presented in the wrong place.

---

## Credential Request / Response Encryption

On top of TLS, `POST /credential` can decrypt an encrypted Credential Request
and/or encrypt its Credential Response, per OpenID4VCI's Credential Request,
Credential Response, and Encrypted Messages sections. Both directions are
gated independently and **default to off** — an unconfigured deployment's
wire behaviour and metadata document are byte-identical to a build without
this feature.

```yaml
issuer:
  request_encryption:
    keys: [issuer_request_enc]               # required; names entries in the top-level `keys:` map
    enc_values_supported: [A128GCM, A256GCM] # required, non-empty, subset of {A128GCM, A256GCM}
    encryption_required: false               # default false — reject an unencrypted request when true
  response_encryption:
    enc_values_supported: [A128GCM, A256GCM] # required, non-empty, subset of {A128GCM, A256GCM}
    encryption_required: false               # default false — requires request_encryption to also be set when true
```

- **`request_encryption.keys`** — one or more names from the top-level
  `keys:` map. Each entry must set `alg: ES256` — naming the *key material*,
  not the JOSE algorithm: `Config::validate_key_material` parses every
  `keys:` entry's `alg` as a signature algorithm, so `ECDH-ES` there would fail
  startup. The entry does not need an `x5c`: it is never read for a
  request-encryption key, since an ECDH-ES key-agreement key is not a signing
  key and has no certificate chain. The *published* JWK's own `alg` is always
  `"ECDH-ES"`, stamped by `DecryptionKey::published_jwk`, independent of the
  `keys:` entry's `alg`. Listing more than one key enables zero-downtime
  rotation: publish the new key alongside the old one, let in-flight wallets
  keep using the old `kid`, then remove the old key once traffic has drained.
- **`kid`** is not configurable. It is derived as the RFC 7638 JWK thumbprint
  of each key's public component, so it is stable across restarts and
  collision-free by construction.
- **`enc_values_supported`** (both blocks) — the AEAD content-encryption
  algorithms this issuer will accept/produce. Must be non-empty and a subset
  of `{A128GCM, A256GCM}`. `alg` itself is always `ECDH-ES` (fixed, not
  configurable), and `zip` (compression) is never advertised or accepted.
- **`encryption_required`** (both blocks, default `false`) — when `true` on
  `request_encryption`, an unencrypted Credential Request is rejected
  outright (Encrypted Messages: reject unencrypted when required). When
  `true` on `response_encryption`, `request_encryption` must also be
  configured — `Config::validate()` rejects a config that sets one without
  the other, since a request carrying `credential_response_encryption` must
  itself arrive encrypted (Credential Request, substitution prevention).

`foundry quickstart` always generates a `keys/issuer_request_enc.pem` ECDH-ES
key, so enabling encryption later needs no separate key-generation step —
uncomment the two blocks above (shipped commented out) in the generated
`config.yaml`.

A wallet discovers the issuer's public encryption key(s) and both blocks'
capabilities from `.well-known/openid-credential-issuer`'s
`credential_request_encryption`/`credential_response_encryption` objects,
each present only when the corresponding config block is set.

---

## Credential Types & Claim Configuration

Each entry under `credential_types` defines one Credential Configuration. Beyond
`id`, `format`, `vct`/`doctype`, `scope` and `display`, two keys control claim
handling and credential lifetime.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `validity_seconds` | no | `31536000` (365 days) | Credential lifetime in seconds. The issued credential's `exp` is its `iat` plus this value — for SD-JWT VC, and for the mdoc MSO's `validUntil`. Must be non-zero: a credential whose `exp` equals its `iat` is rejected at startup. |
| `claims[].required` | no | `!selectively_disclosable` | Whether an offer must supply a value for this claim. Omit it to keep the historical rule — non-disclosable claims mandatory, disclosable ones optional. Set it explicitly for a claim that is **both** mandatory and selectively disclosable. |

`required` exists because "mandatory" and "selectively disclosable" are different
properties. A credential schema can require a claim to be present while the
SD-JWT still discloses it selectively; before this key existed such a claim was
never validated, and an offer omitting it issued an incomplete credential.

A claim's `path` must be a non-empty array — an empty path addresses nothing, so
no supplied value could satisfy it, and it is rejected at startup.

Note that issued credentials do **not** carry a `sub` claim. A per-transaction
`sub` is a static, always-disclosed identifier that rides along in every
presentation, and nothing consumes it; it is omitted deliberately.

### The two shipped credential types

`foundry quickstart` generates both:

- **`pid`** — a Person ID with `given_name` and `birthdate`, both selectively
  disclosable, on the default 365-day lifetime.
- **`com.emvco.dpc.card`** — an EMVCo Digital Payment Credential: `credential_id`
  and `network` (mandatory *and* selectively disclosable), plus an optional
  `card_id`, on a 12-hour lifetime, with display metadata in three locales.
  `network` may be a single string or an array of strings for co-badged cards.
  Its `vct` is a reverse-DNS identifier rather than a URL.

The DPC credential's shape is governed by the EMV® Digital Payment Credential
Specification — Schema Framework, which is **not** vendored into this repository
because it is all-rights-reserved and unpublished. See
[`docs/specs/emvco-dpc-schema-framework.md`](docs/specs/emvco-dpc-schema-framework.md)
for the reference, the claim set foundry relies on, and what parts of that
specification are deliberately not implemented.

---

## Logging & Observability

Every HTTP request on both listeners produces one structured log record, and
every typed error produces exactly one — so an operator can follow both what
happened and why it failed.

### Choosing a level

Three sources can set the log level. They are resolved in this order, highest
priority first:

| Priority | Source | Example |
|---|---|---|
| 1 | `RUST_LOG` environment variable | `RUST_LOG=info,foundry_verifier=debug` |
| 2 | `--log-level` CLI flag | `foundry --log-level debug serve --config config.yaml` |
| 3 | `logging.level` in the config file | see below |
| 4 | built-in default | `info` |

The same ladder applies to the output format (`--log-format` /
`logging.format`, no environment tier) and to payload logging
(`--log-sensitive` / `logging.sensitive_payloads`).

```bash
# Everything at info, but verbose verification internals
RUST_LOG=info,foundry_verifier=debug foundry serve --config config.yaml

# JSON output for a log shipper
foundry --log-format json serve --config config.yaml
```

> **A silent log usually means a typo, not a bug.** `RUST_LOG` accepts any
> target name, so a misspelled level such as `RUST_LOG=infoo` builds a valid
> filter that matches nothing — and the process then logs nothing at all, with
> no warning. Only a *syntactically* invalid directive is reported and downgraded
> to `info`.

### Configuration file

All three settings can live in `config.yaml`. The whole section is optional; a
config without it behaves exactly as before.

```yaml
logging:
  level: info                  # any EnvFilter directive
  format: human                # human | json
  sensitive_payloads: false    # DEV/TEST ONLY — see the warning below
```

### Following a request

Every access record carries these fields. They are stable names — alerting and
log queries can rely on them:

| Field | Meaning |
|---|---|
| `request_id` | Random per request; also returned in the `x-request-id` response header |
| `method` | HTTP method |
| `route` | The route **template** (`/vp/response/:id`), never the concrete path |
| `listener` | `admin` or `wallet` — the two listeners bind different ports |
| `http.status` | Response status |
| `latency_ms` | Time to produce the response |
| `error.kind` | Stable error-variant name, on failure records |
| `error.detail` | Human-readable reason, length-capped |
| `request_encrypted` | Whether the Credential Request arrived as a decrypted `application/jwt` JWE, on `handle_credential_request`'s span |

The level follows the status class: 2xx/3xx at `info`, 4xx at `warn`, 5xx at
`error`.

**To reconstruct one wallet interaction**, grep the domain transaction id
(`tx_id`) rather than `request_id`. A presentation spans three requests across
both listeners — `POST /admin/verification/requests`, then the wallet's
`GET /vp/request/:id` and `POST /vp/response/:id` — and `tx_id` is what ties them
together:

```bash
# Whole flow for one transaction
foundry serve --config config.yaml 2>&1 | grep 'v_1a2b3c'

# Or, if a wallet reported a failure, start from the header it saw
foundry serve --config config.yaml 2>&1 | grep '<the x-request-id value>'
```

A failed verification records which stage rejected the presentation, using the
same check names the successful path reports — `jwe_decryption`,
`sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`,
`dcql_match`, `status_check`, `transaction_data_binding` (only present when the
request carried `transaction_data`) — and the reason is also persisted on the
transaction, so it appears in the admin API and the test console rather than only
in the log.

### `sensitive_payloads` — development only

> **Do not enable this in production.** With `sensitive_payloads: true` (or
> `--log-sensitive`), `debug` and `trace` records may include raw JWEs,
> `vp_token` values, decrypted response payloads and disclosed claim values —
> that is, holder personal data. The process prints a `WARN` on startup whenever
> the flag is on.

Without the flag, no payload is logged at any level. Regardless of the flag,
these are **never** logged: private and ephemeral JWKs, the admin API key,
access tokens, `c_nonce` values, ABCA `attestation_challenge` values, DPoP
`nonce` values, the nonce secret, pre-authorized codes, authorization codes,
transaction codes, the raw compact JWE of an encrypted Credential Request, the
decrypted Credential Request, the plaintext Credential Response when
encryption was requested, and the wallet's `credential_response_encryption.jwk`.
Public keys appear only as RFC 7638 thumbprints. This is enforced by tests
(`crates/foundry/tests/logging_redaction.rs`), not by convention.

---

## End-to-End Test (real subprocess, issue → verify → revoke → re-verify)

A full end-to-end test spawns the real `foundry` binary (`quickstart` then
`serve`, on dynamically-selected free ports) and drives it purely over HTTP:
creates a credential offer, issues an SD-JWT VC `pid` credential, verifies it
via OpenID4VP (happy path), revokes it via `foundry status-list set`, and
re-verifies to confirm `verified: false` with `status_check` failing. It is
excluded from the default `cargo test --workspace` run (slower, binds real OS
ports) — run it explicitly:

```bash
cargo test -p foundry --test e2e_full_flow -- --ignored
```

See `docs/superpowers/specs/2026-07-23-foundry-e2e-full-flow-design.md` for
the design rationale.

## Testing

Run all unit and integration tests across the workspace:

```bash
cargo test --workspace
```

Run tests for a specific crate:

```bash
cargo test -p foundry-issuer
cargo test -p foundry-sd-jwt-vc
cargo test -p foundry-mdoc
cargo test -p foundry-core
cargo test -p foundry
```

Run code formatting and linter checks:

```bash
# Check formatting
cargo fmt --all -- --check

# Run Clippy
cargo clippy --workspace --all-targets -- -D warnings
```

### Conformance Test Suite

Foundry carries a spec-conformance audit of the three protocol texts pinned in
[`docs/specs/`](docs/specs/). Every mandatory clause is adjudicated in
[`docs/conformance/openid4vc-conformance.md`](docs/conformance/openid4vc-conformance.md),
and the verdicts are backed by four test suites:

| Command | Covers |
|---|---|
| `cargo test -p foundry-issuer --test conformance_vci` | OpenID4VCI issuance engine (offers, `/token`, `/nonce`, `/credential`, holder proofs, attestations, issuer metadata) |
| `cargo test -p foundry-verifier --test conformance_vp` | OpenID4VP verification engine (request objects, client identifier prefixes, DCQL, response encryption) |
| `cargo test -p foundry --test conformance_http` | HTTP boundary in `crates/foundry/src/server.rs` (status codes, `Content-Type`, redirects, error bodies) |
| `cargo test -p foundry --test conformance_report` | The report itself — parses the Markdown and enforces its internal consistency |

All four are ordinary integration tests, so `cargo test --workspace` already
includes them. To run just the conformance suites:

```bash
cargo test -p foundry-issuer   --test conformance_vci \
  && cargo test -p foundry-verifier --test conformance_vp \
  && cargo test -p foundry          --test conformance_http \
  && cargo test -p foundry          --test conformance_report
```

#### Known gaps are `#[ignore]`d and expected to fail

Each open finding in the report's Gap Register has a test that reproduces it,
marked `#[ignore]` with a reason string citing its gap ID:

```rust
#[ignore = "GAP-VCI-03: OpenID4VCI Credential Response (L976) — binary Credential Formats MUST be base64url-encoded"]
```

These are **deliberately failing tests describing behaviour foundry does not yet
have** — not broken tests. A default `cargo test` run skips them, which is why
the suite is green. Running them surfaces the open gaps, and they *should* fail:

```bash
# Expect failures — at least one per unclosed gap
cargo test --workspace -- --ignored
```

To review the open gaps *without* running them, note that a normal (green) run
already prints each reason string next to the skipped test:

```bash
cargo test --workspace 2>&1 | grep 'ignored,'
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

#### Closing a gap

1. Fix the behaviour in the relevant crate.
2. Remove the `#[ignore]` attribute — the test should now pass.
3. Update that clause's row and the summary counts in
   `docs/conformance/openid4vc-conformance.md`, and drop its Gap Register entry.
4. Run `cargo test -p foundry --test conformance_report` to confirm the report is
   still self-consistent.

The report is a living document, not a historical record — see
[`AGENTS.md`](AGENTS.md) §8.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) or `Cargo.toml` for details.
