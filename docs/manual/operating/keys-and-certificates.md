# Key & Certificate Management CLI

## Which key signs what

Every signing key foundry uses is an entry in the top-level `keys:` map,
selected by name from elsewhere in the config. Three roles select a key, and
each should name a **different** one:

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
  statuslist_signer:
    private_key: ./keys/statuslist_signer.pem
    x5c: ./keys/statuslist_signer-chain.pem
    alg: ES256
issuer:
  credential_signing_key: issuer_sdjwt
  status_list:
    signing_key: statuslist_signer
```

### Always set `issuer.credential_signing_key`

It is optional only for backward compatibility. Omitted, foundry falls back —
first to `issuer.status_list.signing_key`, and then to the **alphabetically
first** entry in `keys:`. Both fallbacks predate the field and are hazards, not
conveniences:

- Falling back to the status-list key makes one key serve two distinct trust
  roles. Rotating or revoking the status-list signer then silently invalidates
  the issuance identity as well, and every credential you issue carries an
  `x5c` whose subject names the status-list signer — which is misleading in
  exactly the situation where you are reading a credential to diagnose
  something.
- Falling back to the first `keys:` entry is *alphabetical* order, not the
  order you wrote. A key named early in the alphabet wins regardless of intent.

foundry refuses to boot when that last fallback would select a
Credential-Request decryption key (an ECDH-ES key-agreement key, which carries
no certificate) as the credential signer. The fix in that case is the same as
the advice above: name the key explicitly.

A name that does not resolve to a `keys:` entry is rejected at startup, for all
three roles.

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
