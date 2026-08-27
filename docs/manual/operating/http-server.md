# HTTP Server & Endpoints

## 3. Running the HTTP Server

Boot the dual-listener HTTP service (Admin API on `127.0.0.1:9000` and Wallet-facing API on `0.0.0.0:8443` by default):

```bash
cargo run -p foundry -- serve --config config.yaml
```

### Exposed Endpoints

**Wallet-facing Server (`0.0.0.0:8443`):**

- `GET /.well-known/openid-credential-issuer` — OpenID4VCI Credential Issuer Metadata
- `GET /.well-known/oauth-authorization-server` — OAuth 2.0 Authorization Server Metadata
- `GET /credential-offer/:id` — Credential Offer Object served **by reference** (OpenID4VCI §4.2); the target of the `credential_offer_uri` link produced when `issuer.offer_by_reference` is enabled (see [By-Reference Credential Offers](../issuance/by-reference-offers.md))
- `POST /challenge` — ABCA §8 attestation challenge retrieval; registered only when `issuer.wallet_attestation.challenge_mode` is not `disabled` (see [ABCA Challenge Retrieval](../issuance/wallet-attestation.md#abca-challenge-retrieval-post-challenge))
- `GET /credential-metadata/:credential_configuration_id` — PaSO signed credential metadata (PaSO Proof Metadata §2). **Content-negotiates on `Accept`**: `application/jwt` returns the signed `credential-metadata+jwt` of §4, `application/json` returns the bare `credential_metadata` object, and an absent or wildcard `Accept` defaults to JSON. An `Accept` naming neither is `406`. Served only for **PaSO Credential types** — those declaring `transaction_data_types` — so any other configuration id is `404` (see [PaSO Transaction Data Metadata](../issuance/paso-transaction-data.md))
- `GET /api-docs` — Interactive OpenAPI/Swagger UI for the wallet-facing (OpenID4VCI/OpenID4VP) endpoints
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON) for the wallet-facing endpoints

**Admin Server (`127.0.0.1:9000`):**

- `GET /health` — Health check endpoint
- `GET /ready` — Readiness check endpoint (verifies storage connectivity)
- `GET /api-docs` — Interactive OpenAPI/Swagger UI (enabled by default; see [API Documentation](openapi.md) below)
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON)
- `GET /console` — Embedded HTML/JS test console for triggering issuance/verification flows (enabled by default; see [Admin Test Console](test-console.md) below)
- `POST /admin/issuance/offers` — Create credential offers (requires Bearer token if `admin.api_key` is set)
- `POST /admin/paso/ad-hoc-metadata` — Mint an ad-hoc transaction data metadata JWT (PaSO Proof Metadata §5.2) for a Relying Party to embed in a `transaction_data` entry (requires Bearer token if `admin.api_key` is set; see [PaSO Transaction Data Metadata](../issuance/paso-transaction-data.md))
