# Explicit `issuer.credential_signing_key`

**Date:** 2026-08-28
**Design:** [`../specs/2026-08-28-explicit-credential-signing-key-design.md`](../specs/2026-08-28-explicit-credential-signing-key-design.md)

## What changed

`Config::credential_signing_key()` — the single resolver for the key that signs
issued credentials — gained an explicit config field at the head of its
resolution order:

```text
issuer.credential_signing_key        (new, explicit)
  else issuer.status_list.signing_key (historical)
  else the first `keys` entry         (historical, BTreeMap = alphabetical)
```

Prepended rather than substituted, so a deployment that never sets the new
field signs with exactly the key it signed with before.

Two new startup rejections in `Config::validate`:

- `issuer.credential_signing_key` naming a key absent from `keys` — same rule
  the other two signing-key fields already had.
- A `issuer.request_encryption.keys` entry that **resolves** as the credential
  signing key. The two pre-existing cross-purpose reuse checks compare against
  *named* fields (`verifier.signing_key`, `issuer.status_list.signing_key`) and
  so were structurally blind to the fallback; this one compares against the
  resolution result. It closes the case where the alphabetically-first `keys`
  entry is an ECDH-ES Credential-Request decryption key, which would have
  signed credentials with a key-agreement key and emitted no `x5c`.

## Why

Found while debugging a Paradym wallet issuance failure against
`foundry.digitallabor.dev`. The failure itself was unrelated — malformed VCT
type metadata JSON, fixed in the `dl-infra-k8s` manifest — but every credential
that issuer mints carries an `x5c` leaf whose subject is
`CN=Foundry statuslist_signer`, byte-identical to the leaf on its Status List
Tokens. Nothing rejects it, so this was a key-hygiene and operability defect,
not a conformance break: one key served two distinct trust roles, and
`issuer_sdjwt` — defined with its own `x5c` and named as if it were the issuance
key — was dead config that no rotation would affect.

## Files

| File | Change |
| --- | --- |
| `crates/foundry-core/src/config/model.rs` | `IssuerConfig::credential_signing_key: Option<String>` |
| `crates/foundry-core/src/config/mod.rs` | resolution order + rewritten doc comment recording both fallbacks as hazards |
| `crates/foundry-core/src/config/validate.rs` | two new checks; 6 new tests; `cfg_with_enc_key` fixture disambiguated |
| 25 `IssuerConfig` struct literals across the workspace | new field (compiler-enumerated) |
| `crates/foundry/src/commands.rs` | the `quickstart` config template sets the field (and the local, gitignored `config.yaml` was updated to match) |
| `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md` | module map, Gotchas, cross-reference |
| `docs/manual/operating/keys-and-certificates.md` | new "Which key signs what" section |
| `docs/manual/reference/configuration.md` | index rows for both issuer signing keys |
| `docs/conformance/openid4vc-conformance.md` | VCI-0234 evidence notes the new first step |

## Note on the fixture change

`cfg_with_enc_key()` began failing `Config::validate` once the new guard
existed: its keys are `req_dec` and `verifier_signing`, and `req_dec` sorts
first, so the encryption key resolved as the credential signer. That rejection
is the guard working. The fixture now names a credential signing key
explicitly — the same thing a real deployment must do — rather than the guard
being weakened to accommodate it.

## Verification

```text
cargo nextest run --workspace --no-fail-fast --status-level fail
     Summary [   2.338s] 1202 tests run: 1202 passed, 11 skipped
cargo clippy --workspace --all-targets -- -D warnings   # clean
mkdocs build --strict                                    # built in 0.44s
```

## Follow-up, not done here

The deployed `dl-infra-k8s/foundry/foundry_config.yml` still has no
`issuer.credential_signing_key`, so it continues to sign credentials with
`statuslist_signer` — unchanged behaviour, by design. Setting it to
`issuer_sdjwt` is an operator decision and re-keys newly issued credentials
(already-issued ones embed their own `x5c` and keep verifying).
