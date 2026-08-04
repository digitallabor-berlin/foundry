# The `android_keystore_attestation` proof type

Date: 2026-08-04
Status: Approved

## Problem

Google Wallet does not perform credential-key attestation with an OpenID4VCI
Appendix D Key Attestation JWT. It uses its own proof type,
`android_keystore_attestation`, whose value is an **array of X.509 certificate
chains** — one chain per attested key, each chain a hardware-signed Android
Keystore attestation:

```json
{
  "credential_configuration_id": "org.iso.18013.5.1.mDL",
  "proofs": {
    "android_keystore_attestation": [
      ["MII…leaf", "MII…intermediate", "MII…root"],
      ["MII…", "MII…", "MII…"]
    ]
  }
}
```

foundry cannot accept this today, and cannot be extended into accepting it
through the existing key-attestation code:

- `ProofsRequest` (`crates/foundry-issuer/src/proof.rs`) is a struct with a
  single **required** `jwt: Vec<String>` field. A request carrying only
  `android_keystore_attestation` fails deserialization.
- `handle_credential_request` (`credential.rs`) reads `p.jwt` directly.
- `verify_key_attestation_jwt` (`attestation.rs`) is the wrong entry point in
  kind, not merely in detail: it verifies a JWS over a JSON payload containing
  `attested_keys`, `nonce`, `iat`, `exp`. There is no JWT anywhere in this proof
  type, no `attested_keys` array, and no claim set. Routing certificate chains
  into it would require gutting it.

This is sub-project **D** of the Google Wallet compatibility effort, unblocked
by sub-project **A** (cryptographic trust-chain verification, merged
2026-08-04). Without A, every chain would have been "validated" by comparing
Distinguished-Name strings, which would have made this proof type a hardware
guarantee in appearance only.

## Goals

1. Accept `proofs: { android_keystore_attestation: [[…], …] }` as a second proof
   type alongside `jwt`, opt-in and disabled by default.
2. Parse the Android Key Attestation extension (`1.3.6.1.4.1.11129.2.1.17`,
   `KeyDescription`) from the attesting certificate.
3. Bind each chain to this issuer's freshness challenge by requiring
   `attestationChallenge` to be a valid, unexpired, issuer-minted `c_nonce`.
4. Enforce a configurable minimum hardware security level.
5. Derive each credential's holder key from the attested certificate, so the
   issued credential is bound to the hardware-protected key.
6. Never claim more than is verified: every unenforced Android assertion is a
   named row in `docs/conformance/openid4vc-conformance.md`.

## Non-goals

- **Revocation.** No query against
  `https://android.googleapis.com/attestation/status`. Deferred to its own
  sub-project: it is the only networked, cache-bearing, operationally-configured
  part of the mechanism, and its fail-open/fail-closed policy deserves a
  decision of its own rather than being smuggled in behind four offline checks.
  Recorded as a gap row.
- **`user_auth_types` enforcement or advertisement.** Google's own schema is
  self-contradictory about whether `[]` means "no constraint" or "the key MUST
  carry `noAuthRequired`". Advertising a requirement in metadata that we then
  interpret by guesswork reproduces exactly the failure mode sub-project A
  existed to fix. Gap row.
- **Device-integrity assertions** (`rootOfTrust.verifiedBootState`,
  `deviceLocked`). The strongest checks in the structure and the natural next
  addition, but they reject unlocked-bootloader and custom-ROM devices, which is
  an operator policy call needing its own config knob. Gap row.
- **The OpenID4VCI top-level `attestation` proof type** (VCI-0198). Still not
  implemented; unrelated to this work despite the similar name.
- **Accepting non-EC attested keys.** The attested key becomes the credential's
  holder key, and foundry's credential formats bind ES256/P-256 keys.
- **Changing `validate_chain`'s signature or behaviour.** It stays
  `(leaf_pem, intermediates, store, now_unix)`. This design is a consumer.

## Evidence gathered before choosing an approach

All four findings came from the real Android chain already in-tree at
`crates/foundry-core/tests/fixtures/android-attestation/` (imported by
sub-project A from the vendor profile's "Real Android Keystore Attestation
example") and from the two authoritative Google pages: the issuer-facing
[keystore attestation guide](https://developer.android.com/identity/digital-credentials/credential-issuer/keystore-attestation)
and the AOSP
[Key and ID attestation](https://source.android.com/docs/security/features/keystore/attestation)
schema.

### 1. The `KeyDescription` outer shape is stable across every published version

Versions 1, 2, 3, 4, 100, 200, 300, 400 and 500 all define the identical
eight-element outer `SEQUENCE`:

```
KeyDescription ::= SEQUENCE {
    attestationVersion         INTEGER,
    attestationSecurityLevel   SecurityLevel,
    keyMintVersion             INTEGER,
    keyMintSecurityLevel       SecurityLevel,
    attestationChallenge       OCTET_STRING,
    uniqueId                   OCTET_STRING,
    softwareEnforced           AuthorizationList,
    hardwareEnforced           AuthorizationList,
}
SecurityLevel ::= ENUMERATED { Software(0), TrustedEnvironment(1), StrongBox(2) }
```

Only `AuthorizationList` grows new tags between versions. That asymmetry is what
makes "parse the outer structure strictly, parse `AuthorizationList`
permissively" safe: a future KeyMint release adds tags, not fields.

### 2. `attestationChallenge` holds the UTF-8 bytes of the `c_nonce` string

Decoding the fixture leaf's extension yields `attestationVersion = 3`,
`attestationSecurityLevel = TrustedEnvironment(1)`, `keyMintVersion = 41`,
`keyMintSecurityLevel = TrustedEnvironment(1)`, an empty `uniqueId`, and a
60-byte `attestationChallenge` whose content is ASCII:

```
MHMvK0dES1B1N3JwdlFoUjZCRG5QVFZjRTM1bXNYOHR2Ky9HTEpLbEdVST0=
```

That is the `c_nonce` string as it would have travelled on the wire, not raw
nonce bytes. The comparison is therefore: decode the OCTET STRING as UTF-8, then
hand the string to the existing `verify_nonce`. No encoding guesswork, and the
existing MAC-plus-expiry mechanism does all the work.

### 3. Leaf validity contributes zero freshness

The fixture leaf's validity window is `1970-01-01` → `2106-02-07`. Certificate
expiry cannot bound replay for this proof type at all, which makes the challenge
binding the **only** replay defence — load-bearing rather than a nicety.

### 4. The extension-bearing certificate must be chosen from the root end

Google's verification procedure (step 6 of "Retrieve and verify a
hardware-backed key pair") says to find the certificate *nearest the root* that
carries the attestation extension, because "any other instances of the extension
have not been issued by the secure hardware and might have been issued by an
attacker extending the chain while attempting to create fake attestations for
untrusted keys". Taking `chain[0]` blindly is the natural implementation and the
wrong one.

## Approach

### Chosen: a `foundry-core` parser plus a `foundry-issuer` policy layer

Certificate-extension parsing goes in `foundry-core`, beside every other X.509
concern (`parse_cert_pem`, `cert_ec_public_coords`, `validate_chain`) and beside
the real Android fixtures its tests consume. Protocol binding and policy go in
`foundry-issuer`, which is where `c_nonce` verification, config, and
`IssuanceError` live.

`x509-cert` 0.3 (and its re-exported `der`) is already a `foundry-core`
dependency, so the parser adds no new third-party code to the workspace.

### Rejected: everything in `foundry-issuer`

`x509-cert` is already a direct `foundry-issuer` dependency and keeping one proof
type in one crate would let a reader follow one file. Rejected because it
duplicates the Android fixture set across crates (or reaches across crate
boundaries with a `dev-dependencies` path hack) and puts format-agnostic
certificate parsing in a protocol-engine crate, against the §3 layering
intent.

### Rejected: extending `verify_key_attestation_jwt`

Discussed in Problem. The two mechanisms share a purpose and no wire format.

## Design

### Module layout

**New — `crates/foundry-core/src/trust/android_attestation.rs`.** Parsing only:
no policy, no protocol, no network.

```rust
pub enum SecurityLevel { Software = 0, TrustedEnvironment = 1, StrongBox = 2 }

pub struct AuthorizationList {
    pub purpose: Vec<i64>,                 // [1]
    pub algorithm: Option<i64>,            // [2]
    pub key_size: Option<i64>,             // [3]
    pub ec_curve: Option<i64>,             // [10]
    pub no_auth_required: bool,            // [503], NULL — presence means true
    pub user_auth_type: Option<i64>,       // [504]
    pub creation_date_time: Option<i64>,   // [701]
    pub origin: Option<i64>,               // [702]
    pub root_of_trust: Option<RootOfTrust>,// [704]
    pub os_version: Option<i64>,           // [705]
    pub os_patch_level: Option<i64>,       // [706]
}

pub enum VerifiedBootState { Verified = 0, SelfSigned = 1, Unverified = 2, Failed = 3 }

pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_hash: Vec<u8>,       // absent before version 3
}

pub struct KeyDescription {
    pub attestation_version: i64,
    pub attestation_security_level: SecurityLevel,
    pub key_mint_version: i64,
    pub key_mint_security_level: SecurityLevel,
    pub attestation_challenge: Vec<u8>,
    pub unique_id: Vec<u8>,
    pub software_enforced: AuthorizationList,
    pub hardware_enforced: AuthorizationList,
}

/// `Ok(None)` when the certificate carries no attestation extension.
pub fn parse_key_description(cert: &Certificate) -> Result<Option<KeyDescription>, TrustError>;

/// The extension-bearing certificate nearest the root, and its parsed
/// KeyDescription. Errors when no certificate in the chain carries one.
pub fn find_attestation_cert(chain: &[Certificate]) -> Result<(usize, KeyDescription), TrustError>;
```

That set is deliberately larger than the enforced policy: every field above is
exactly what one of the named follow-ons (`user_auth_types`,
`verifiedBootState`/`deviceLocked`) will need, so adding a policy check later
never re-touches the parser. Tags outside the set are skipped, not retained —
the struct is a decoded view, not a generic tag map, because a generic map
invites callers to reach for tags nobody has decided the semantics of.

`SecurityLevel` is `Ord` so policy comparison is a comparison, not a match arm
per pair. An `ENUMERATED` value outside `0..=2` is a **parse error**, not an
unknown-but-tolerated variant: a security level foundry cannot rank is a
security level it cannot apply a `>=` policy to, and defaulting it either way
would be a guess in the one place a guess is least acceptable. The same holds
for `VerifiedBootState`.

**New — `crates/foundry-issuer/src/keystore_proof.rs`.** Policy and protocol
binding, returning the existing `VerifiedProof { holder_jwk }` so nothing
downstream of proof verification changes.

**Changed — `crates/foundry-issuer/src/proof.rs`.** `ProofsRequest` becomes a
two-member, `deny_unknown_fields` structure resolved into an enum, enforcing
OpenID4VCI L852 ("The `proofs` parameter contains exactly one parameter named as
the proof type"): both members present → reject; neither → reject; an unknown
proof-type name → reject. That last case is a strictness gain: today serde
ignores the unknown key and the request then fails as "missing `jwt`".

**Changed — `crates/foundry-issuer/src/credential.rs`.** Dispatch on the
resolved proof type; both arms produce `Vec<VerifiedProof>` and the rest of
`handle_credential_request` is untouched.

**Changed — `crates/foundry-issuer/src/metadata.rs`.** A second
`proof_types_supported` entry when the mechanism is enabled.

**Changed — `crates/foundry-core/src/config/{model,validate}.rs`.** The nested
`android` block and its fail-closed startup validation.

### Verification pipeline, per chain

1. **Shape.** The outer array is non-empty; each chain is non-empty; each entry
   decodes through the existing `foundry_core::trust::x5c_entry_to_pem`
   (base64-STANDARD DER → PEM), which already matches Google's
   "Base64-NoWrap padded DER" exactly.
2. **Chain validation.** `validate_chain(chain[0], &chain[1..], &store, now)`,
   with `store` built from `issuer.key_attestation.trusted_anchors`. Google's
   format includes its own root as the last element; `validate_chain` discards
   self-signed presented certificates, so a transmitted root grants nothing and
   trust must reach a configured anchor. No new trust code — the behaviour is
   already asserted by
   `presented_android_root_grants_nothing_without_a_configured_anchor`.
3. **Select the attesting certificate.** Walk from the root end toward the leaf;
   take the first certificate carrying the extension (finding #4). None → reject.
4. **Parse** its `KeyDescription`.
5. **Challenge binding.** `attestation_challenge` must be valid UTF-8, then goes
   to `verify_nonce(secret, s, now)`.
6. **Policy.** `attestation_security_level` **and** `key_mint_security_level`
   must both be `>=` the configured minimum. Both, not just the one Google's
   metadata names: `attestationSecurityLevel` is the level of the location where
   the attested key lives, `keyMintSecurityLevel` the level of the implementation
   making the statement, and a policy satisfied by only one of them is not the
   policy an operator thinks they configured.
7. **Attested key.** The selected certificate's SPKI must be EC P-256 via
   `cert_ec_public_coords`; the coordinates become the `holder_jwk`
   (`kty: EC`, `crv: P-256`).

Chain count maps to credential count exactly as the `jwt` proof array does.

### Configuration

```yaml
issuer:
  key_attestation:
    mode: optional                 # unchanged: governs the jwt proof's kid + key_attestation path
    trusted_anchors: [...]         # shared; Google's two attestation roots go here
    android:
      mode: disabled                              # NEW, default disabled
      key_mint_security_level: TrustedEnvironment  # NEW, default
```

`trusted_anchors` is deliberately **shared** with the parent block. "Who may
attest a credential key" is the same question for the Appendix D JWT path and
for this one; two anchor lists would drift, and one of them would silently be
the wrong one.

`android.mode` reuses `Mode` with a meaning specific to this proof type:

| value | behaviour |
|---|---|
| `disabled` (default) | an `android_keystore_attestation` member is rejected; the metadata entry is omitted |
| `optional` | accepted alongside `jwt` |
| `required` | accepted, and a `jwt` proofs member is rejected — a Google-only deployment |

The default comes from the existing `default_disabled()` helper, not
`Mode::default()` (which is `Optional`). No deployment starts accepting a
proof type carrying no proof of possession as a result of an upgrade.

**Startup validation, fail-closed.** `android.mode != disabled` together with an
empty `trusted_anchors` is a config error at load time. Every chain would be
rejected anyway; failing at boot turns a silent total outage into a legible
misconfiguration.

### Metadata

Emitted only when `android.mode != disabled`:

```json
"android_keystore_attestation": {
  "proof_signing_alg_values_supported": ["ES256"],
  "key_attestations_required": { "key_mint_security_level": "TrustedEnvironment" }
}
```

Two vendor-profile readings, each carrying a code comment naming the profile per
root `AGENTS.md` §4.4:

- `proof_signing_alg_values_supported` is REQUIRED by Google's schema even
  though nothing in this proof type is signed by the attested key. We read it as
  constraining the *attested key's* algorithm — which is why pipeline step 7
  requires EC P-256.
- `key_attestations_required` here carries Google's field names, not
  OpenID4VCI's own `key_storage` / `user_authentication` shape. The name
  collision with the spec's parameter is the vendor's, not ours.

### Error mapping

No new `IssuanceError` variants, so `server.rs`'s mappers are untouched and
§4.5's one-record-per-typed-error rule holds without new code.

| failure | variant | HTTP |
|---|---|---|
| shape, base64, DER, chain, no extension, policy, non-P-256 key | `InvalidProof` | 400 `invalid_proof` |
| `attestationChallenge` absent from the minted-nonce space, expired, or forged | `InvalidNonce` (prefixed `android_keystore_attestation:`) | 400 `invalid_nonce` |
| member present while `android.mode: disabled` | `InvalidProof("unsupported proof type")` | 400 `invalid_proof` |

**One trap, called out because the natural implementation gets it wrong.**
`IssuanceError::Trust(_)` falls through `wallet_error_response`'s `_ =>` arm to
**HTTP 500 `server_error`**. A holder chain that does not reach a configured
anchor is a client fault, so `validate_chain` failures MUST be wrapped into
`InvalidProof` at the call site rather than propagated with `?`. Propagating it
turns "your attestation doesn't chain to a root I trust" into an apparent server
outage. A test asserts the variant, not just the status.

The `InvalidNonce` prefix mirrors the existing `key_attestation:` prefix in
`attestation.rs`, so an operator can tell which of the three nonce-consuming
paths rejected a request.

### Observability

Span fields on the new verifier, and nothing else: `chain_count`,
`attestation_version`, `attestation_security_level`, `key_mint_security_level`,
and the attested key's RFC 7638 thumbprint via `foundry_core::obs::thumbprint`.
`#[tracing::instrument(skip_all)]` as always.

Never logged, at any level, under any flag:

- **`attestation_challenge`** — it is a `c_nonce`, already forbidden by §4.5.
- **`unique_id`** — new to the forbidden list and the strongest reason this
  design touches root `AGENTS.md`. It is a privacy-sensitive hardware device
  identifier that survives factory reset. Never logged, never persisted, never
  returned.
- **Raw certificates.** Public, but bulky and fingerprintable. The attested key's
  thumbprint is the only identifier that appears.

### Invariants

1. `verified`-style honesty applies here too: a credential is issued only when
   every step above passed. There is no partial-acceptance path.
2. No `.unwrap()`, `.expect()`, `panic!()` or `unreachable!()` in the new
   request-path code (§4.1). ASN.1 parsing of attacker-controlled bytes is the
   single most panic-prone thing in this repository; every length and tag read
   returns a `TrustError`.
3. `foundry-core` gains no dependency on any `foundry-*` crate (§3), and nothing
   Android-specific reaches its protocol surface beyond a parsed struct.
4. `unique_id` never leaves the parser's return value.

## Testing

The load-bearing constraint: **the real Google fixture can never pass a
happy-path test.** Its `attestationChallenge` is Google's nonce and cannot
verify against foundry's per-process MAC secret; a static synthetic fixture is no
better, because a `c_nonce` embeds an expiry. Acceptance tests build chains at
runtime with `rcgen` (already a `foundry-core` dependency, already used this way
in `tests/trust_chain_verification.rs`; `foundry-issuer` gains it as a
dev-dependency). The real fixture covers parsing and chain validation.

One deliberate duplication: a compact `KeyDescription` DER builder in
`foundry-core`'s tests (single certificates) and a synthetic-chain builder in
`foundry-issuer`'s `#[cfg(test)]` and `crates/foundry/tests/support/`. The
alternative — a public `encode_key_description` in `foundry-core` — puts
production-shaped code in the tree that no production path calls. Two small test
builders beat one unused public encoder. Each carries a comment pointing at the
other.

**`crates/foundry-core/tests/android_attestation.rs`**

| test | asserts |
|---|---|
| real fixture parses | version 3, both levels `TrustedEnvironment`, the exact 60-byte challenge, empty `unique_id` |
| certificate without the extension | `Ok(None)` |
| truncated / garbage extension content | `Err(TrustError::Parse)`, no panic |
| `find_attestation_cert` on the real 4-cert chain | index 0 |
| attacker certificate bearing its own extension prepended | the genuine (higher-index) certificate is selected |
| chain with no extension anywhere | `Err` |
| `StrongBox` and `Software` levels | decode to the right variant, `Ord` holds |
| `SecurityLevel` enumerated value outside `0..=2` | `Err`, not a tolerated unknown |
| `hardwareEnforced.rootOfTrust` on the real fixture | decodes; `device_locked` and `verified_boot_state` are readable but unenforced |
| version-100 outer shape with unknown `AuthorizationList` tags | parses, unknown tags skipped |

**`crates/foundry-issuer/src/keystore_proof.rs` unit tests**

| test | asserts |
|---|---|
| happy path | `holder_jwk` equals the attested leaf key |
| challenge mismatch; expired nonce | `InvalidNonce` |
| non-UTF-8 challenge | `InvalidProof` |
| level below configured minimum | `InvalidProof` |
| `StrongBox` configured, TEE presented | `InvalidProof` |
| unanchored chain | `InvalidProof` — **and explicitly not `Trust`**; this is the regression test for the 500-instead-of-400 trap |
| RSA or P-384 attested key | `InvalidProof` |
| `mode: disabled` with the member present | `InvalidProof`, "unsupported proof type" |
| `mode: required` with a `jwt` member | rejected |
| both members / neither member / unknown member | rejected (L852) |
| N chains | N `VerifiedProof`s, in request order |

**`crates/foundry/tests/`**

- Issuance flow: token → nonce → credential with an `android_keystore_attestation`
  proof; the issued credential's `cnf` thumbprint equals the attested key.
- `wallet_metadata.rs`: the entry appears only when enabled, with the configured
  `key_mint_security_level`.
- `conformance_http.rs`: the rejection-status matrix — every failure above is 400
  with the right code, never 500.
- `logging_redaction.rs`: `unique_id` and the challenge never appear, with a
  positive control.
- `instrumentation_hygiene.rs`: the new spans carry `skip_all`.
- `cli_openapi.rs`: `openapi.json` and `openapi-wallet.json` regenerated for the
  changed Credential Request schema.

## Verification gate

Scoped gate per root `AGENTS.md` §5.1 at each task boundary:

```bash
cargo test -p foundry-core        # parser
cargo test -p foundry-issuer      # policy, proof dispatch, metadata
cargo test -p foundry             # config, HTTP, flows, OpenAPI
cargo clippy -p <touched> --all-targets -- -D warnings
cargo fmt --check
```

Affected set per §5.2: `foundry-core` (`trust/`, `config/`) → both engines and
`foundry`; in practice `foundry-verifier` is untouched by this design, so the
scoped set is `foundry-core`, `foundry-issuer`, `foundry`. The full gate of §5.3
runs once, at the end of the branch.

## Deviations and known limitations

Each becomes a row in `docs/conformance/openid4vc-conformance.md` and a Gotchas
entry in the owning crate's `AGENTS.md`.

1. **No audience binding — OpenID4VCI L862's mechanism is unmet.** L862 requires
   the proof to incorporate the Credential Issuer Identifier; this format
   carries no issuer identifier anywhere, so the mechanism cannot be satisfied.
   The *property* it exists for is nonetheless met: a `c_nonce` is MAC'd with
   this issuer's per-process secret, so another issuer's nonce does not verify
   here. The row records the distinction rather than collapsing it in either
   direction.
2. **No proof of possession of the attested key.** Nothing in the proof is signed
   by the key being attested; the hardware statement substitutes. This is the
   same posture as OpenID4VCI's own `attestation` proof type, defined as a key
   attestation "without using a proof of possession of the cryptographic key
   material that is being attested".
3. **Revocation is not checked.** Google's guidance asks issuers to check
   `https://android.googleapis.com/attestation/status`. Deferred sub-project.
4. **`user_auth_types` is neither enforced nor advertised.**
5. **`rootOfTrust.verifiedBootState` and `deviceLocked` are not enforced.** A
   chain from an unlocked-bootloader device with a genuine TEE key is accepted.
6. **Expired factory attestation keys are rejected.** Google states that
   pre-2021 devices' attestation certificates remain trustworthy after expiry
   unless revoked; `validate_chain` enforces validity windows through OpenSSL and
   rejects those chains. Not fixed here: suppressing time checks for this path is
   a genuine security tradeoff, and it interacts with Remote Key Provisioning
   certificates whose short validity is deliberately part of the threat model.
7. **`attestationChallenge` is read as UTF-8 of the `c_nonce` string**, on the
   evidence of the real fixture. A wallet embedding raw nonce bytes is rejected.

Per the vendor-profile rule in root `AGENTS.md` §4.4, every behaviour above whose
only justification is Google's documentation carries a code comment naming the
profile, so a reader can tell vendor accommodation from conformance.

## Documentation

- `docs/conformance/openid4vc-conformance.md` — the seven rows above.
- `README.md` — the `issuer.key_attestation.android` config block. No new log
  field names, so the logging section is unchanged.
- Root `AGENTS.md` §4.5 — add `uniqueId` to the never-logged list.
- `crates/foundry-core/AGENTS.md` — module map entry for
  `trust/android_attestation.rs`; a gotcha that the extension-bearing
  certificate is selected from the root end and why.
- `crates/foundry-issuer/AGENTS.md` — module map entry for `keystore_proof.rs`;
  gotchas for the three-way `Trust` → `InvalidProof` wrapping requirement, the
  `android.mode` semantics, and the now-four similarly-named attestation things
  in the crate.
- `openapi.json`, `openapi-wallet.json` — regenerated.
- `docs/superpowers/changes/2026-08-04-android-keystore-attestation-proof.md`.

## Follow-on work

In the order they matter:

1. **Revocation** against Google's status endpoint — resolver trait mirroring
   `foundry-verifier`'s `StatusResolver`, caching, and a fail-open/fail-closed
   decision.
2. **Device-integrity policy** — `verifiedBootState` / `deviceLocked` behind
   their own config knob.
3. **`user_auth_types`**, once Google clarifies the meaning of `[]`.
4. **Expired factory attestation keys** — whether to relax time checks for
   chains under the `f92009e853b6b045` root while keeping them for RKP.
5. Sub-project **E** — the credential-type shape (`vct = com.emvco.dpc.card`).