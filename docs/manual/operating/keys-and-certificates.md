# Key & Certificate Management CLI

## Which key signs what

Every signing key foundry uses is an entry in the top-level `keys:` map,
selected by name from elsewhere in the config. Three roles select a key:

| Role | Selected by | Signs |
| --- | --- | --- |
| Credential issuer | `issuer.credential_signing_key` | issued credentials (SD-JWT VC JWS, mdoc `IssuerAuth`) and the PaSO metadata JWTs |
| Status-list authority | `issuer.status_list.signing_key` | Status List Tokens served from `issuer.status_list.public_base_url` |
| Verifier | `verifier.signing_key` | OpenID4VP Request Objects |

```yaml
keys:
  issuer_sdjwt:
    private_key: ./keys/issuer_sdjwt.pem
    x5c: ./keys/issuer_sdjwt-chain.pem
    alg: ES256
  verifier_signing:
    private_key: ./keys/verifier_signing.pem
    x5c: ./keys/verifier_signing-chain.pem
    alg: ES256
issuer:
  credential_signing_key: issuer_sdjwt
  status_list:
    # Deliberately the same key as credential_signing_key — see
    # "The status-list signer must currently match the credential signer" below.
    signing_key: issuer_sdjwt
verifier:
  signing_key: verifier_signing
```

The verifier key must be its own. The credential and status-list roles are
different trust roles and *ought* to be different keys, but in practice they
cannot be yet — see below.

### Always set `issuer.credential_signing_key`

It is optional only for backward compatibility. Omitted, foundry falls back —
first to `issuer.status_list.signing_key`, and then to the **alphabetically
first** entry in `keys:`. Both fallbacks predate the field and are hazards, not
conveniences:

- Falling back to the status-list key makes one key serve two distinct trust
  roles *by accident, under a misleading name*. Rotating or revoking the
  status-list signer then silently invalidates the issuance identity as well,
  and every credential you issue carries an `x5c` whose subject names the
  status-list signer — which is misleading in exactly the situation where you
  are reading a credential to diagnose something. (One key serving both roles
  is currently required for wallet interoperability; the defect here is
  arriving there implicitly, so that no field says which key signs
  credentials.)
- Falling back to the first `keys:` entry is *alphabetical* order, not the
  order you wrote. A key named early in the alphabet wins regardless of intent.

foundry refuses to boot when that last fallback would select a
Credential-Request decryption key (an ECDH-ES key-agreement key, which carries
no certificate) as the credential signer. The fix in that case is the same as
the advice above: name the key explicitly.

A name that does not resolve to a `keys:` entry is rejected at startup, for all
three roles.

### The status-list signer must currently match the credential signer

If you enable status lists, point `issuer.status_list.signing_key` at the **same
key** as `issuer.credential_signing_key`. foundry logs a `WARN` at startup — and
from `foundry config validate` — when they differ:

```text
issuer.status_list.signing_key 'statuslist_signer' is not the credential signing
key 'issuer_sdjwt', so Status List Tokens are signed by a different key than the
credentials that reference them.
```

Nothing in the specifications requires this. Token Status List §11.3 mandates no
key-resolution method at all, and §13.5 explicitly permits a wholly separate
Status Issuer. foundry serves a fully conformant Status List Token either way:
the verification key is in the token's own `x5c` JOSE header, as
[HAIP](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md)
requires.

The constraint is a wallet one. The Credo / `@sd-jwt` stack — which the Paradym
wallet and others are built on — verifies a Status List Token with the
**credential issuer's** key and never decodes the token's own `x5c`. Against a
deployment whose two keys differ, every credential carrying a `status` claim
fails status validation in those wallets, with a signature error that points at
the status list rather than at the key configuration:

```text
CredoError: Failed to validate sd-jwt-vc credentials.
SLException: Status List JWT verification failed: Verify Error: Invalid JWT Signature
```

The token is not malformed and its signature is not invalid — it was simply
checked against the wrong key.

Diverge only if every wallet consuming your credentials resolves the status-list
key from the token itself, or you are deliberately operating a separate Status
Issuer for a known client. The warning is advisory and never blocks startup.

## 4. Key & Certificate Management CLI

Foundry provides built-in tools for generating EC private keys (PKCS#8 PEM) and issuing X.509 certificates.

### Generate an EC Private Key (ES256 / P-256)

```bash
cargo run -p foundry -- keys generate --alg ES256 --out private_key.pem
```

### Create a Root CA

```bash
cargo run -p foundry -- cert new-ca --cn "My Root CA" --out-cert ca.pem --out-key ca-key.pem --days 3650
```

### Issue a Leaf Certificate

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
