<p align="center">
  <img src="docs/assets/foundry_logo.png" />
</p>

# Foundry

**Foundry** is a modular, high-performance Digital Credential Issuing & Verification Service written in Rust. It implements standards including OpenID for Verifiable Credential Issuance (OpenID4VCI), OpenID for Verifiable Presentations (OpenID4VP), W3C SD-JWT VC (`dc+sd-jwt`), ISO/IEC 18013-5 mdoc, and IETF Token Status Lists.

---

## Workspace Architecture

Foundry is structured as a Rust cargo workspace comprising several modular crates:

| Crate | Path | Description |
| --- | --- | --- |
| `foundry` | `crates/foundry` | Main binary & HTTP service providing server startup, admin API, wallet endpoints, and PKI CLI commands. |
| `foundry-core` | `crates/foundry-core` | Core data models, YAML configuration parser/validator, SQLite storage driver, PKI/cert handling, trust anchor validation, and Token Status List generation/verification. |
| `foundry-issuer` | `crates/foundry-issuer` | Framework-agnostic OpenID4VCI business logic: metadata builders, transaction lifecycle, CSPRNG status-list index allocation, and offer creation. |
| `foundry-sd-jwt-vc` | `crates/foundry-sd-jwt-vc` | SD-JWT VC issuing, disclosure calculation, holder binding (KB-JWT), and verification. |
| `foundry-mdoc` | `crates/foundry-mdoc` | ISO/IEC 18013-5 mdoc / CBOR / COSE IssuerAuth builder and DeviceAuth verifier. |

---

## Prerequisites

- **Rust:** Version 1.97 or later (edition 2024). See `rust-toolchain.toml`.
- **Cargo:** Included with Rust installation (`rustup`).

---

## Quickstart

Generate a self-signed dev PKI (Root CA + leaf certificates for issuer, verifier, and status list) along with a ready-to-run `config.yaml`:

```bash
cargo run -p foundry -- quickstart
```

The generated config ships **two** credential types: `pid` (a Person ID) and
`com.emvco.dpc.card` (an EMVCo Digital Payment Credential). See
[Credential Types & Claim Configuration](docs/manual/issuance/credential-types.md).

*Note: The quickstart command is for development/testing only.*

---

## Documentation

Full documentation: **<https://digitallabor-berlin.github.io/foundry/>**

| Topic | |
| --- | --- |
| Installation and building | [Getting Started](docs/manual/getting-started/installation.md) |
| Docker images and CI | [Deployment](docs/manual/deployment/docker.md) |
| Endpoints, admin API, test console, keys, logging | [Operating](docs/manual/operating/http-server.md) |
| Credential types, attestation, DPoP, encryption, PaSO | [Issuance](docs/manual/issuance/credential-types.md) |
| DC API origins, request diagnostics | [Verification](docs/manual/verification/dc-api-origins.md) |
| Test gate, conformance suite | [Development](docs/manual/development/testing.md) |
| Configuration keys, log fields, specifications | [Reference](docs/manual/reference/configuration.md) |
| Clause-by-clause conformance verdicts | [Conformance report](docs/conformance/openid4vc-conformance.md) |

Contributor guidelines and the normative invariants live in
[`AGENTS.md`](AGENTS.md).

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) or `Cargo.toml` for details.
