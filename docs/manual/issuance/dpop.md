# DPoP (RFC 9449) — Sender-Constrained Access Tokens

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

## Server-Provided DPoP Nonces (RFC 9449 §8/§9)

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
