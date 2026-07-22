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
| `oid4vci` | `crates/oid4vci` | Vendored OpenID4VCI protocol models and proof verifier. |
| `openid4vp` | `crates/openid4vp` | Vendored OpenID4VP protocol types and verifier engine. |
| `openid4vp-frontend` | `crates/openid4vp-frontend` | Frontend helpers for presentation flows. |

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

## Running the Project

Foundry includes CLI commands for setting up a development environment, managing keys and certificates, validating configuration files, and running the HTTP service.

### 1. Quickstart (Development Setup)

Generate a self-signed dev PKI (Root CA + leaf certificates for issuer, verifier, and status list) along with a ready-to-run `config.yaml`:

```bash
cargo run -p foundry -- quickstart
```

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

**Admin Server (`127.0.0.1:9000`):**
- `GET /health` — Health check endpoint
- `GET /ready` — Readiness check endpoint (verifies storage connectivity)
- `POST /admin/issuance/offers` — Create credential offers (requires Bearer token if `admin.api_key` is set)

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

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) or `Cargo.toml` for details.
