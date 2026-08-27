# Running the Project

Foundry includes CLI commands for setting up a development environment, managing keys and certificates, validating configuration files, and running the HTTP service.

## 1. Quickstart (Development Setup)

Generate a self-signed dev PKI (Root CA + leaf certificates for issuer, verifier, and status list) along with a ready-to-run `config.yaml`:

```bash
cargo run -p foundry -- quickstart
```

The generated config ships **two** credential types: `pid` (a Person ID) and
`com.emvco.dpc.card` (an EMVCo Digital Payment Credential). See
Credential Types & Claim Configuration.

*Note: The quickstart command is for development/testing only.*

## 2. Validating Configuration

Validate your YAML configuration file against key files and trust anchors:

```bash
cargo run -p foundry -- config validate --config config.yaml
```
