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

## Where to go next

- **[Getting Started](manual/getting-started/installation.md)** — prerequisites, building, and a running server.
- **[Deployment](manual/deployment/docker.md)** — Docker images and CI.
- **[Operating](manual/operating/http-server.md)** — endpoints, admin API, test console, keys, logging.
- **[Issuance (OpenID4VCI)](manual/issuance/credential-types.md)** — credential types and protocol extensions.
- **[Verification (OpenID4VP)](manual/verification/dc-api-origins.md)** — DC API origins and request diagnostics.
- **[Development](manual/development/testing.md)** — the test gate and conformance suite.
- **[Reference](manual/reference/configuration.md)** — configuration keys, log fields, specifications.
