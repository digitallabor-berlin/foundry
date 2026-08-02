# AGENTS.md — `crates/foundry-core`

## Purpose

The **bottom infrastructure layer** of the workspace: configuration loading and
validation, signing-key abstraction, dev PKI helpers, X.509 trust store and
chain validation, Token Status List bit-packing / compression / signed tokens,
and the async key-value storage trait with its SQLite implementation.

**Not** in scope here: any OpenID4VCI or OpenID4VP protocol logic, credential
format encoding (`foundry-sd-jwt-vc`, `foundry-mdoc`), and HTTP/Axum code
(`crates/foundry`). This crate is pure infrastructure.

## Position in the Dependency Graph

`foundry-core` is the **bottom layer** and **MUST NOT depend on any other
`foundry-*` crate**. It is consumed by every other workspace crate:
`foundry-sd-jwt-vc`, `foundry-mdoc`, `foundry-issuer`, `foundry-verifier`,
`crates/foundry`, `foundry-wallet`.

If two same-layer crates need shared behaviour, it belongs here. Full layering
rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
|---|---|
| `lib.rs` | Declares `config`, `crypto`, `error`, `obs`, `pki`, `status_list`, `storage`, `trust`, `url` |
| `config/mod.rs` | `Config::load(&Path)` — reads the file and parses **JSON if the extension is `.json`, otherwise YAML**; re-exports all of `model` |
| `config/model.rs` | The whole config tree: `Config`, `ServerConfig`, `WalletFacingConfig`, `AdminConfig`, `StorageConfig`, `KeyEntry`, `TrustAnchor`, `IssuerConfig`, `AttestationMode`, `Mode`, `StatusListConfig`, `CredentialType`, `ClaimDef`, `VerifierConfig`, `LoggingConfig`, `LogFormat` |
| `config/validate.rs` | Post-load semantic validation (notably that key references resolve to configured/readable key material) |
| `crypto/mod.rs` | `SignatureAlgorithm` (`Es256`/`Es384`/`Es512`) and the `Signer` trait (`algorithm`, `sign`, `public_jwk`) |
| `crypto/signer.rs` | `FileSigner` — PEM-file-backed `Signer` implementation |
| `crypto/jwe.rs` | `encrypt_compact(payload, recipient_public_jwk, alg, enc)` — ECDH-ES JWE compact serialization over `josekit`, the encrypt counterpart to `foundry-verifier`'s decrypt path. Rejects any `alg` other than `ECDH-ES` rather than emitting a header that misdescribes the ciphertext |
| `error.rs` | All error enums plus the `CoreError` umbrella and `CoreResult<T>` alias |
| `obs.rs` | Observability support shared by both engines and the binary: the process-global sensitive-payload flag (`set_sensitive` / `sensitive_enabled`) and the redaction helpers `truncate` and `thumbprint` (RFC 7638). **Contains no log statements** |
| `pki/mod.rs` | **Dev-only** PKI: `KeyMaterial`, `CertMaterial`, `generate_ec_key`, `new_ca`, `issue_leaf` |
| `status_list/mod.rs` | Token Status List (IETF `draft-ietf-oauth-status-list-14`): status packing, zlib compression, `StatusList`, signed Status List Token build/sign/verify, and `Storage`-backed persistence |
| `storage/mod.rs` | The async `Storage` trait; re-exports `SqliteStorage` |
| `storage/sqlite.rs` | `SqliteStorage` — single `kv` table, connects with `create_if_missing`, runs `migrations/` on connect |
| `migrations/` | SQL schema migrations (`0001_init.sql`), embedded via `sqlx::migrate!` |
| `url.rs` | `dns_host_only(base_url) -> String` — strips a `https://`/`http://` scheme and truncates at the first `/` or `:`, leaving a bare DNS host. Shared by `Config::validate()` and `foundry-verifier`'s Request Object signing; the workspace deliberately carries no URL-parsing crate |

## Key Public Types & Entry Points

- **Config:** `Config` (fields: `server`, `storage`, `keys`, `trust_anchors`,
  `issuer`, `credential_types`, `verifier`), loaded via `Config::load(&Path)`.
  `Mode` (`Required`/`Optional`/`Disabled`) drives attestation gating in
  `foundry-issuer`. `AttestationMode.pop_max_age_secs: u64` (default 300) is the
  ABCA draft -07 sliding-window staleness bound for Client Attestation PoP JWTs
  (GAP-VCI-14); applicable only to `issuer.wallet_attestation`, present but
  unused by `issuer.key_attestation` since that mechanism has no PoP JWT.
- **Crypto:** `Signer` trait, `FileSigner`, `SignatureAlgorithm` (with `as_str`,
  `FromStr` — case-insensitive, `Display`).
- **Storage:** `Storage` trait — `put_kv(namespace, key, value, expires_at)`
  (upsert), `get_kv`, `delete_kv`, `purge_expired(now_unix) -> u64`, and
  `insert_kv_if_absent(namespace, key, value, expires_at) -> Result<bool, _>` —
  atomic claim semantics (`INSERT ... ON CONFLICT DO NOTHING`) distinct from
  `put_kv`'s upsert; a rejected (`false`) claim leaves the existing row
  untouched. This is the primitive `foundry-issuer`'s `claim_pop_jti` builds
  Client Attestation PoP `jti` replay detection on (GAP-VCI-14). Impl:
  `SqliteStorage::connect(path)`.
- **Trust:** `TrustStore` (`from_pems`, `from_config`, `is_empty`),
  `validate_chain(leaf_pem, intermediates, store, now_unix)`, plus helpers
  `parse_cert_pem`, `is_self_signed`, `validity_window`, `san_dns_names`,
  `match_san_dns`, `build_x5c`, `x5c_entry_to_pem`, `cert_ec_public_coords`.
- **Status list:** `StatusValue` (`Valid`/`Invalid`/`Suspended`/
  `ApplicationSpecific(u8)`), `pack_status_array(values, bits)`,
  `unpack_status(byte_array, bits, idx)`, `compress_zlib` / `decompress_zlib`,
  `StatusList`, `StatusListTokenClaims`, `build_status_list_token`,
  `sign_status_list_token`, `verify_status_list_token` → `VerifiedStatusList`,
  `PersistentStatusList`, `load_status_list` / `save_status_list`,
  `STATUS_LIST_NAMESPACE`.
- **PKI (dev):** `generate_ec_key(alg) -> KeyMaterial`,
  `new_ca(common_name, days) -> CertMaterial`, `issue_leaf(..)`.
- **Errors:** `ConfigError`, `StorageError`, `CryptoError`, `TrustError`,
  `FormatError`, `CoreError`, `CoreResult<T>`.

## Binding Invariants

- **No upward dependencies** — never depend on `foundry-sd-jwt-vc`,
  `foundry-mdoc`, `foundry-issuer`, `foundry-verifier`, `crates/foundry`, or
  `foundry-wallet` — full rule: root [AGENTS.md](../../AGENTS.md) §3.
- **Every fallible helper returns a typed `Result`.** Code here runs inside the
  engines' request paths, so a `panic!`/`unwrap` here becomes a 500 there;
  returning `Result` is what lets those crates honour their no-panic rule —
  full rule: root [AGENTS.md](../../AGENTS.md) §4.1.
- **Never widen a status/trust helper into reporting success it did not verify.**
  `foundry-verifier` derives its `verified` verdict from these results — full
  rule: root [AGENTS.md](../../AGENTS.md) §4.2.
- **Gates before completion:** `cargo test --workspace`, `cargo clippy
  --workspace --all-targets -- -D warnings`, `cargo fmt --check` — root
  [AGENTS.md](../../AGENTS.md) §5.

## Tests

- **Inline `#[cfg(test)]` modules** in `crypto/mod.rs`, `crypto/signer.rs`,
  `error.rs`, `status_list/mod.rs`, `trust/mod.rs`, `pki/mod.rs`.
- **Integration tests** in `tests/`:
  - `config_load.rs` — `Config::load()` against the YAML fixtures.
  - `storage_sqlite.rs` — `SqliteStorage` KV round-trip and expiry purge.
  - `validate_key_material.rs` — config validation of key references.
  - `fixtures/` — exactly two YAML config fixtures: `minimal.yaml` and
    `bad-missing-keyref.yaml`.

```bash
cargo test -p foundry-core
```

## Gotchas

- **`validate_chain` performs NO cryptographic signature verification.** There
  is an explicit `TODO(trust-hardening)` in `trust/mod.rs`: `x509-cert` 0.3
  cannot verify signatures, so the function only (a) rejects a self-signed leaf,
  (b) checks validity windows, and (c) builds a **DN-based** path from the leaf's
  issuer up to an anchor's subject. A forged certificate with matching DNs passes.
  Do not describe this as full X.509 validation, and do not weaken it further.
- **`get_kv` does not filter expired rows.** Expiry is enforced only by an
  explicit `purge_expired(now_unix)` sweep; between sweeps an expired row is
  still readable. Callers that care about freshness MUST check the expiry
  themselves — see how `foundry-issuer`'s `load_transaction_by_access_token`
  guards transaction reads.
- **`put_kv`'s last argument is an absolute Unix timestamp (`expires_at`), not a
  TTL duration.** Passing a duration silently creates a row that expired in 1970.
- **Status packing is index-0-first, least-significant-bit-first within each
  byte**, with `bits` restricted to 1/2/4/8 (`checked_bits`). Any decoder that
  assumes MSB-first will read plausible-but-wrong statuses rather than failing.
- **`unpack_status`'s out-of-bounds error reports `len` in status slots, not
  bytes** (`byte_array.len() * per_byte`). Don't compare it against a byte length.
- **`StatusValue::from_u8` never fails** — unrecognised values fall into
  `ApplicationSpecific(u8)`. A malformed status will not surface as an error, so
  callers must explicitly match on `Valid` rather than "not an error".
- **`TrustStore::from_config` splits each anchor file on
  `-----BEGIN CERTIFICATE-----`**, so concatenated PEM bundles are supported;
  a single anchor file may contribute multiple anchors.
- **`cert_ec_public_coords` assumes an uncompressed EC point (`0x04` prefix)**
  and errors otherwise — compressed points are not supported.
- **`SqliteStorage::connect` runs migrations on every connect** and uses
  `create_if_missing`, so a typo'd path silently creates a fresh empty database
  rather than failing.
- **`Config::validate()` exempts loopback hosts from the `https` MUST on
  `issuer.credential_issuer`** (OpenID4VCI L1368/L1369; GAP-VCI-08). This is a
  deliberate, documented deviation, not an oversight: the repository's own dev
  config (`config.yaml`) runs `issuer.credential_issuer` over plain
  `http://localhost:8443`, and enforcing the MUST unconditionally would make
  that shipped config fail to boot. The exemption set is exactly `localhost`,
  `127.0.0.1`, `::1`, `[::1]` — do not widen it to private IP ranges or
  `*.local`, and do not remove it without first migrating `config.yaml` and
  every fixture that relies on it. **Accepted consequence:** a loopback
  deployment's RFC 9207 `iss` value (also required to be `https`, RFC 9207 §2)
  will not be conformant either — this is the same deviation surfacing a second
  time, not a separate defect.
- **`Config::validate()` requires `issuer.credential_issuer` to be
  byte-identical to `server.wallet_facing.public_base_url`** (OpenID4VCI L1366;
  GAP-VCI-09) — "a simple string comparison with no normalization", so a
  trailing slash or case difference is a mismatch, not a benign variant. Do not
  add trimming or case-folding to make this check more lenient.