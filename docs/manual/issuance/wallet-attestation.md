# Wallet Attestation & Client Attestation Proof-of-Possession

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

## ABCA Challenge Retrieval (`POST /challenge`)

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
