# Explicit `issuer.credential_signing_key` — design

**Date:** 2026-08-28
**Status:** accepted, implementing
**Crates touched:** `foundry-core` (config), plus the compiler-enumerated
`IssuerConfig` struct-literal sites across the workspace.

## Problem

`Config::credential_signing_key()` — the single resolver naming the key that
signs issued credentials — has no field of its own. It reads
`issuer.status_list.signing_key`:

```rust
// crates/foundry-core/src/config/mod.rs
pub fn credential_signing_key(&self) -> Option<(&str, &KeyEntry)> {
    let name = self
        .issuer
        .status_list
        .signing_key
        .as_deref()
        .or_else(|| self.keys.keys().next().map(|s| s.as_str()))?;
    self.keys.get_key_value(name).map(|(k, v)| (k.as_str(), v))
}
```

The resolver's own doc comment already records this as a historical artefact:
one configured key signs both Status List Tokens and credentials, and only the
status-list spelling was ever given a config field.

### Observed consequence

Diagnosed on 2026-08-28 while debugging a Paradym wallet issuance failure
against the `foundry.digitallabor.dev` deployment. That failure turned out to be
unrelated (malformed VCT type metadata JSON), but the investigation surfaced
this: every credential the deployment issues carries

```text
x5c leaf subject = CN=Foundry statuslist_signer
```

byte-identical to the leaf on its Status List Tokens (same SHA-256). The
deployment configures `issuer.status_list.signing_key: statuslist_signer`, so
that key signs credentials too. `issuer_sdjwt` — defined in the same config with
its own `x5c`, and named as if it were the issuance key — is referenced nowhere
else and is therefore **dead config**.

Nothing is *rejected* by this. The certificate is valid, chains to the
configured root, carries `keyUsage: Digital Signature` with no EKU, and its SAN
`DNS:foundry.digitallabor.dev` matches the credential's `iss` host. This is a
key-hygiene and operability defect, not a conformance break:

1. **No key separation** between two distinct trust roles — credential issuer
   and status-list authority. Rotating or revoking the status-list key silently
   invalidates the issuance identity with it.
2. **The operator-visible name lies.** Rotating `issuer_sdjwt` has no effect;
   changing `statuslist_signer` re-keys every credential. Neither is
   discoverable from the config.
3. **Misleading diagnostics** in every issued credential — the direct cost paid
   in the session that found this.

### Latent second defect

`Config.keys` is a `BTreeMap<String, KeyEntry>`, so the fallback
`self.keys.keys().next()` is the **alphabetically first** key, not the first
written. For the deployment above that ordering is:

```text
issuer_request_enc   <- alphabetically first
issuer_sdjwt
statuslist_signer
verifier_signing
```

`issuer_request_enc` is the ECDH-ES Credential-Request decryption key, and
carries no `x5c` (correctly — OpenID4VCI L1373 publishes a key-agreement key as
a bare JWK). So removing `status_list.signing_key`, or setting
`status_list.enabled: false` and dropping it, would make foundry sign
credentials with the request-decryption key and emit no `x5c` at all.

The cross-purpose reuse guard in `config/validate.rs` does **not** catch this.
It checks only two *named* fields:

```rust
if name == &self.verifier.signing_key { ... }
if self.issuer.status_list.signing_key.as_deref() == Some(name.as_str()) { ... }
```

The implicit fallback is not a named field, so it is unguarded. In the
deployment above the PaSO `x5c` check would incidentally reject boot (a
`transaction_data_types` block is configured, and PaSO Proof Metadata §4
requires a chain on the credential signing key) — but that is luck, and it
disappears the moment PaSO types are removed.

## Decision

Add an explicit, optional `issuer.credential_signing_key`, and **prepend** it to
the existing resolution order rather than replacing it:

```rust
let name = self
    .issuer
    .credential_signing_key
    .as_deref()                                             // new, explicit
    .or(self.issuer.status_list.signing_key.as_deref())      // historical
    .or_else(|| self.keys.keys().next().map(|s| s.as_str()))?; // historical
```

The deployment then sets `issuer.credential_signing_key: issuer_sdjwt`.

### Why prepend rather than replace

Replacing the order would change which key signs credentials in every existing
deployment that never mentions the new field — exactly the silent re-keying the
original doc comment refused. Prepending is inert until an operator opts in.

The historical two-step tail is retained deliberately and stays documented as
historical, not as design.

### Rejected alternative: point `status_list.signing_key` at `issuer_sdjwt`

A zero-code workaround exists — set `issuer.status_list.signing_key:
issuer_sdjwt` — but it merely inverts the coupling: the issuance key would then
sign Status List Tokens. One field cannot express two roles. Rejected.

## Constraints on the implementation

1. **One resolver, no second answer.** `credential.rs`, `metadata.rs`,
   `paso_metadata.rs` and `validate.rs` all call
   `Config::credential_signing_key()`. Conformance row **VCI-0234** turns on the
   advertised `credential_signing_alg_values_supported` and the actual
   `IssuerAuth`/JWS `alg` being derived from the *same* answer; a second
   resolution path reintroduces the drift that row records as closed. Do not add
   a parallel lookup.
2. **Extend the encryption-key reuse guard to the resolved name**, not to
   another named field. Checking the *resolution result* is what closes the
   `issuer_request_enc` hole, because the hole is in the fallback.
3. **Reject an unresolvable name at startup**, matching the
   `issuer.status_list.signing_key` check already in `Config::validate()`.
4. **Already-issued credentials are unaffected.** Their `x5c` is embedded in
   the signed header and chains to the same root; only newly issued credentials
   change leaf. No wallet-side migration.

## Out of scope

- Splitting the status-list signer from the credential signer in the deployed
  `dl-infra-k8s` config. That is an infrastructure change, gated on this field
  existing, and is the operator's call — the code change alone re-keys nothing.
- Deprecating or removing the `status_list.signing_key` fallback. It stays.
- Any change to how Status List Tokens themselves are signed.
