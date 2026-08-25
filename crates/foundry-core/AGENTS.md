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
`crates/foundry`.

If two same-layer crates need shared behaviour, it belongs here. Full layering
rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
| --- | --- |
| `lib.rs` | Declares `config`, `crypto`, `error`, `obs`, `pki`, `status_list`, `storage`, `trust`, `url` |
| `config/mod.rs` | `Config::load(&Path)` — reads the file and parses **JSON if the extension is `.json`, otherwise YAML**; re-exports all of `model`. `Config::load_request_decryption_keys(base_dir) -> Result<Vec<DecryptionKey>, ConfigError>` reads and returns the `issuer.request_encryption.keys` PEMs (empty vec when unconfigured) |
| `config/mdoc.rs` | What foundry knows about specific mdoc doctypes, keyed on the doctype string: `namespace_for_doctype` (ISO mDL is the exception — doctype `org.iso.18013.5.1.mDL`, namespace `org.iso.18013.5.1`; every EUDI attestation uses its doctype verbatim) and `validate_av_claims`, which enforces EU Age Verification Annex A §4.1.2's closed attribute set for `AV_DOCTYPE`. Also exports `AV_DOCTYPE` / `MDL_DOCTYPE`. Lives here because both `config/validate.rs` and `foundry-issuer` need it and core is the only crate below both |
| `config/model.rs` | The whole config tree: `Config`, `ServerConfig`, `WalletFacingConfig`, `AdminConfig`, `StorageConfig`, `KeyEntry`, `TrustAnchor`, `IssuerConfig`, `AttestationMode`, `Mode`, `StatusListConfig`, `CredentialType`, `ClaimDef`, `VerifierConfig`, `LoggingConfig`, `LogFormat`, `RequestEncryptionConfig`, `ResponseEncryptionConfig`, `SUPPORTED_ENC_VALUES` (`{A128GCM, A256GCM}`), and PaSO's `TransactionDataTypeMetadata` / `PasoMetadataConfig` plus `CredentialType::transaction_data_types` — whose **presence alone** makes a credential type a PaSO Credential type |
| `config/validate.rs` | Post-load semantic validation (notably that key references resolve to configured/readable key material). Also the `pub` `validate_paso_transaction_data_type_metadata` (PaSO Core §5.2's identifier grammar plus PaSO Proof Metadata §3/§3.1/§3.2's structure), exported because two channels publish that shape — startup validation and `foundry-issuer`'s ad-hoc mint override — and a channel accepting what the other rejects would make validation advisory. A PaSO deployment whose credential signing key has no `x5c` is rejected at startup (§4 puts the chain in the JWT header) |
| `crypto/mod.rs` | `SignatureAlgorithm` (`Es256`/`Es384`/`Es512`) and the `Signer` trait (`algorithm`, `sign`, `public_jwk`) |
| `crypto/signer.rs` | `FileSigner` — PEM-file-backed `Signer` implementation |
| `crypto/jws.rs` | `sign_compact(header, payload, signer)` — compact JWS construction; the single owner of JOSE header assembly, signing-input encoding, and of `alg`-versus-signing-key agreement. Replaced three hand-rolled copies (`foundry-sd-jwt-vc/builder.rs`, `status_list/mod.rs`, `foundry-verifier/request.rs`) and hosts the two PaSO metadata JWT builders. The caller supplies the **complete** header including `alg`'s position; `sign_compact` *validates* a supplied `alg` against the signer rather than inserting one, and inserts it first only when the caller omitted it — see Gotchas |
| `crypto/jwe.rs` | `encrypt_compact(payload, recipient_public_jwk, alg, enc)` — ECDH-ES JWE compact serialization over `josekit`, the encrypt counterpart to `foundry-verifier`'s decrypt path. `encrypt_compact_with_kid(payload, recipient_public_jwk, alg, enc, kid)` is the `kid`-echoing sibling `foundry-issuer` uses for the Credential Response, kept separate so `encrypt_compact`'s OpenID4VP wire shape never gains an accidental `kid`. `DecryptionKey` (`from_pem`/`from_pem_file`, `kid()`, `published_jwk()`) and `decrypt_compact(jwe, keys, allowed_enc)` are the Credential Request decrypt path: pre-decryption checks require `alg == ECDH-ES`, `enc` in the caller's allow-list, and a `kid` matching a loaded key. Rejects any `alg` other than `ECDH-ES` rather than emitting a header that misdescribes the ciphertext |
| `error.rs` | All error enums plus the `CoreError` umbrella and `CoreResult<T>` alias |
| `obs.rs` | Observability support shared by both engines and the binary: the process-global sensitive-payload flag (`set_sensitive` / `sensitive_enabled`) and the redaction helpers `truncate` and `thumbprint` (RFC 7638). **Contains no log statements** |
| `pki/mod.rs` | **Dev-only** PKI: `KeyMaterial`, `CertMaterial`, `generate_ec_key`, `new_ca`, `issue_leaf` |
| `status_list/mod.rs` | Token Status List (IETF `draft-ietf-oauth-status-list-14`): status packing, zlib compression, `StatusList`, signed Status List Token build/sign/verify, and `Storage`-backed persistence |
| `storage/mod.rs` | The async `Storage` trait; re-exports `SqliteStorage` |
| `trust/android_attestation.rs` | Android Key Attestation extension (`1.3.6.1.4.1.11129.2.1.17`) `KeyDescription` parsing: `parse_key_description`, `find_attestation_cert`, `SecurityLevel`, `AuthorizationList`, `RootOfTrust`. Parsing only, no policy — enforcement lives in `foundry-issuer`'s `keystore_proof.rs` |
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
  `foundry-mdoc`, `foundry-issuer`, `foundry-verifier`, or `crates/foundry`
  — full rule: root [AGENTS.md](../../AGENTS.md) §3.
- **Every fallible helper returns a typed `Result`.** Code here runs inside the
  engines' request paths, so a `panic!`/`unwrap` here becomes a 500 there;
  returning `Result` is what lets those crates honour their no-panic rule —
  full rule: root [AGENTS.md](../../AGENTS.md) §4.1.
- **Never widen a status/trust helper into reporting success it did not verify.**
  `foundry-verifier` derives its `verified` verdict from these results — full
  rule: root [AGENTS.md](../../AGENTS.md) §4.2.
- **One gate, always the whole workspace:** `cargo fmt`, then
  `cargo nextest run --workspace --no-fail-fast --status-level fail`, then
  `cargo clippy --workspace --all-targets -- -D warnings`. There is no scoped
  tier and no affected-crate set to derive — the suite runs in seconds, so
  running less than all of it only reduces coverage. This matters most here:
  `foundry-core` sits under every other crate. **Do not use `cargo test`.**
  Full rule: root [AGENTS.md](../../AGENTS.md) §5.

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
cargo nextest run --workspace --no-fail-fast --status-level fail  # the gate (§5.1)
cargo nextest run -p foundry-core                                 # narrow, while iterating
```

## Gotchas

- **`serde_json` is built with `preserve_order`, so JOSE header member order is
  insertion order** — and therefore observable in signed bytes. This is why
  `crypto/jws.rs`'s `sign_compact` validates `alg` *where the caller placed it*
  rather than inserting it: the three pre-existing call sites disagree on order
  (`alg, typ, x5c` for `foundry-sd-jwt-vc` and the status list; `typ, alg, x5c`
  for the verifier's Request Object), and imposing one would change bytes that
  wallets already verify. A unit test in that module asserts the feature is on,
  so a dependency change that silently disabled it fails loudly instead of
  reordering signed headers.

- **`CredentialType` and `ClaimDef` use the `Option` + resolver pattern.**
  `resolved_scope()`, `resolved_validity_seconds()` (default `31_536_000`) and
  `ClaimDef::is_required()` (default `!selectively_disclosable`) all exist so an
  omitted config key reproduces the behaviour that predated the field. Keep new
  optional config keys to this shape rather than a bare `bool`: a two-state field
  cannot express "unspecified, so keep the historical rule", and picking either
  default silently changes existing deployments.
- **Adding a field to a config struct is not a config-only change.** `ClaimDef`
  and `CredentialType` are `Deserialize`, so YAML tolerates a missing key — but
  every Rust struct literal in the workspace still breaks. Expect to update
  ~20 test fixture sites per field, compiler-enumerated.
- **`validate_chain` cryptographically verifies every link's signature, via
  OpenSSL `X509_STORE_CTX`.** As of 2026-08-04 this replaced an earlier
  implementation that only walked Distinguished-Name strings, under which a
  forged certificate with matching DNs would pass; see
  `docs/superpowers/specs/2026-08-04-trust-chain-signature-verification-design.md`.
  `basicConstraints: CA:TRUE`, `keyUsage: keyCertSign` and `pathLenConstraint`
  are enforced by OpenSSL on every non-leaf certificate. Do not weaken this back
  to a DN comparison.
- **`trust/` uses two X.509 libraries on purpose.** `x509-cert` *inspects*
  (parsing, DNs, validity windows, SANs, SPKI coordinates, `x5c` encoding);
  OpenSSL *validates* (`validate_chain` path validation). Do not migrate one to
  the other — `x509-cert` is needed for Android key-attestation extension
  parsing, and OpenSSL is needed for multi-algorithm path validation.
- **`validate_chain` deliberately sets no verification purpose.** Setting one
  enables Extended Key Usage checks, and Android key-attestation certificates
  carry no EKU — setting a purpose would reject every Google Wallet chain.
  Covered by
  `real_android_attestation_chain_validates_against_the_configured_google_root`.
- **`new_ca` / `issue_leaf` backdate `not_before` by
  `pki::CLOCK_SKEW_BACKDATE_SECS` (300s).** Not cosmetic: cert validity comes
  from the wall clock, while `validate_chain` compares it against a `now_unix`
  the *caller* supplies. Callers routinely capture `now` and only then generate
  the chain (every attestation fixture here does), so with `not_before = now`
  the two differ by one whole second whenever generation crosses a second
  boundary -- X.509 stores `not_before` at one-second resolution -- and OpenSSL
  rejects a perfectly good chain as "not yet valid". That was a real
  intermittent failure of `foundry-issuer`'s ABCA `client_id` tests, diagnosed
  as an ABCA fault for a while because the surfaced error was a trust error
  rather than the expected `InvalidClient`. Do not remove the backdate to
  "tighten" validity; `not_after` is still measured from `now`, so nothing is
  lengthened. Covered by
  `generated_certs_backdate_not_before_for_clock_skew`,
  `freshly_issued_chain_validates_against_a_slightly_lagging_clock`, and
  `attestation_verifies_against_a_clock_lagging_cert_generation`.
- **`X509VerifyFlags::PARTIAL_CHAIN` is required,** not optional: a configured
  trust anchor may be an intermediate rather than a self-signed root. Covered by
  `an_intermediate_pinned_as_the_anchor_validates_the_leaf`.
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
- **`validate_key_material` parses *every* `keys:` entry's `alg` as a
  `SignatureAlgorithm`, with no exception for an `issuer.request_encryption`
  key.** Such a key's config entry therefore names the *key material* as
  `alg: ES256` — the only thing `SignatureAlgorithm::from_str` accepts — even
  though its *published* JWK (`DecryptionKey::published_jwk`) always carries
  `alg: "ECDH-ES"`. Writing `alg: ECDH-ES` in the `keys:` entry itself fails
  startup validation; it belongs only on the wire, never in this config field.
- **`find_attestation_cert` (`trust/android_attestation.rs`) selects the
  attesting certificate nearest the root, not `chain[0]`** — it walks the
  chain reversed and returns the first certificate (from the root end) bearing
  the extension. This is deliberate: Google's own guidance warns an attacker
  can append extra certificates *below* a genuine hardware-attested leaf, so
  trusting `chain[0]` unconditionally would let a forged leaf ride on a real
  device's attestation. Do not simplify this to `chain[0]`.
- **The `KeyDescription` outer `SEQUENCE` is version-stable; `AuthorizationList`
  is not.** The parser is therefore strict on the outer sequence (`read_one`/
  `expect_tag` fail loudly on shape mismatch) but tag-driven and permissive on
  `AuthorizationList` — an unrecognised tag is skipped, not rejected, because
  Google adds tags across KeyMint versions. An unrecognised `SecurityLevel`
  enumeration value, by contrast, **is** a hard parse error: unlike an unread
  authorization tag, a security level foundry cannot rank is not safe to treat
  as `Software` (weakest) or ignore.

- **`vct` on an `mso_mdoc` credential type is rejected at load.** `Config::validate()`
  requires `doctype` and forbids `vct` for that format, because `vct` is an
  SD-JWT-VC identifier with no meaning for an mdoc and a type carrying both made
  docType resolution ambiguous. Downstream code therefore needs **no** fallback
  chain: `foundry-issuer`'s Credential Endpoint reads `cred_type.doctype` alone.
  Removing the ambiguous state, rather than picking a winner inside it, is what
  makes that safe — reintroducing a `vct` fallback would re-document a precedence
  rule that no longer exists.
- **An `eu.europa.ec.av.1` type is additionally checked against a closed
  attribute set.** EU Age Verification Annex A §4.1.2 admits only `age_over_18`
  (Mandatory in issuance, so it must also be `required`) and `age_over_NN`, and
  states a Proof of Age Attestation SHALL NOT include any other attribute. That
  is a startup failure, not a silent divergence; see `config/mdoc.rs`.
