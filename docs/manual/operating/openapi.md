# API Documentation (OpenAPI / Swagger UI)

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
