# Key & Certificate Management CLI

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
