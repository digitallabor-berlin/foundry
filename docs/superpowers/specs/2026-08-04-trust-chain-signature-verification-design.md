# Cryptographic X.509 trust-chain verification

Date: 2026-08-04
Status: Approved

## Problem

`foundry_core::trust::validate_chain` does not verify signatures. It parses the
leaf, rejects a self-signed leaf, checks validity windows, and then walks
*issuer/subject Distinguished Name strings* from the leaf up to a configured
anchor. The function's own doc comment says so:

```rust
/// v1 scope: reject self-signed leaf, check validity windows, and build a
/// DN-based path from the leaf up to a configured anchor.
/// TODO(trust-hardening): x509-cert 0.3 cannot verify signatures. A later pass
/// MUST cryptographically verify each link (issuer SPKI over tbs_certificate)
/// via rustls-webpki or p256/ecdsa. This function's signature will not change.
```

An attacker who can present a certificate chain therefore only needs to get the
DN *strings* right. Self-signing a leaf whose `issuer` field spells the same
Distinguished Name as a configured anchor's `subject` field produces a chain
that `validate_chain` accepts. No key held by the anchor is ever involved.

This is not a hypothetical corner of the codebase. `validate_chain` has six
production call sites, spanning every crate:

| Call site | What it gates |
|---|---|
| `foundry-issuer/src/attestation.rs:165` | Wallet (Client) Attestation JWT signer |
| `foundry-issuer/src/attestation.rs:609` | Key Attestation JWT signer |
| `foundry-sd-jwt-vc/src/verifier.rs:172` | SD-JWT VC issuer certificate |
| `foundry-mdoc/src/verifier.rs:179` | mdoc `IssuerAuth` certificate |
| `foundry-core/src/status_list/mod.rs:406` | Status List Token signer |
| `foundry-verifier/src/verify.rs:529` | Verifier trust anchors (`TrustStore::from_config`) |

### Why this is being done now

Work is underway to make foundry interoperable with Google Wallet's OpenID4VCI
implementation. Google's requirements place the Android security key
attestation root certificates at the base of the **Wallet (Client) Attestation**
trust path:

> **Wallet (Client) Attestation** — […] Root keys are the ones found here:
> <https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate>

So `validate_chain` sits directly on the live Google integration path. Shipping
that integration on top of DN-name matching would produce an issuer that appears
to enforce hardware-backed wallet attestation while accepting any chain whose DN
strings are spelled correctly. That is worse than not integrating at all,
because the appearance of a hardware guarantee invites reliance on it.

This design is sub-project **A** of the Google Wallet compatibility effort and a
hard prerequisite for sub-project **D** (`android_keystore_attestation` proof
support). It is independently valuable and is not Google-specific.

### The conformance report currently overstates this

`docs/conformance/openid4vc-conformance.md` has **no gap row for this
weakness**, and several rows are marked `conforming` on the strength of
`validate_chain`:

- **VCI-0231** — "The Authorization Server MUST verify that the Wallet
  Attestation is signed by an issuer that the Credential Issuer trusts for this
  purpose" → `conforming`, evidence: `validate_chain` is called against
  `issuer.wallet_attestation.trusted_anchors`.
- **HAIP-0031** — "…the chain is checked against
  `issuer.wallet_attestation.trusted_anchors`" → `conforming`.
- **HAIP-0082 / HAIP-0083** — X.509 certificate-based issuer key resolution for
  SD-JWT VC → `conforming`.

These verdicts claim cryptographic trust from a function that compares strings.
Correcting them is part of this work, and is arguably more urgent than the code
change: a conformance report that overstates a security property is unreliable
exactly where a reader depends on it.

## Goals

Make `validate_chain` cryptographically real:

- every link in the path verified with the issuer's public key;
- RFC 5280 CA constraints enforced (`basicConstraints: CA:TRUE`,
  `keyUsage: keyCertSign`, `pathLenConstraint`);
- path built from the leaf to a **configured** anchor, using
  Authority/Subject Key Identifier rather than DN-string matching;
- validity windows evaluated at a caller-supplied instant;
- applied uniformly at all six call sites, fail-closed, with no opt-out.

### Rollout posture: hard cutover

There is deliberately **no configuration flag** to weaken or bypass
verification. A `warn`-and-allow mode exists precisely so that someone can ship
with it enabled, and a trust store that logs instead of rejecting is the defect
this design removes, wearing a different hat. It would also contradict
`AGENTS.md` §4.2: a check that can be configured to always pass is not a check.

The practical consequence is accepted: any deployment whose anchor bundle is
mis-assembled — anchors that do not actually sign the chains presented to them —
starts failing immediately and loudly. That is the correct outcome, and it is
cheaper to discover in a scoped test run than in production.

## Non-goals

Each of these is excluded deliberately; recording them prevents scope creep
during implementation.

- **Revocation.** No CRL, no OCSP, no querying Google's attestation status
  endpoint (`https://android.googleapis.com/attestation/status`). Android's own
  guidance asks issuers to perform a revocation check, but it is
  Android-specific and network-dependent, and belongs in sub-project **D**.
- **Android key attestation extension parsing.** The
  `1.3.6.1.4.1.11129.2.1.17` `KeyDescription` structure, `attestationChallenge`
  ↔ `c_nonce` binding, and security-level policy are sub-project **D**.
- **RSA for JOSE signing.** This design adds RSA *certificate-signature
  verification* only. `foundry_core::crypto::SignatureAlgorithm` remains
  EC-only and continues to reject `RS256` (asserted by an existing test in
  `crypto/mod.rs`). These are separate concerns, and the implementation must
  carry a comment saying so, because "finish the job by adding RS256 signing" is
  the natural next edit and would be wrong.
- **Changing `validate_chain`'s signature.** It stays
  `(leaf_pem, intermediates, store, now_unix)`. No call-site churn.
- **Name constraints, policy mapping, and other RFC 5280 features** beyond what
  the chosen backend applies by default.
- **Detecting a redundantly-presented non-self-signed anchor.** See the
  HAIP-0039 discussion under "Documentation".

## Evidence gathered before choosing an approach

Four facts were established empirically rather than assumed, because each one
would have invalidated an otherwise reasonable design.

### 1. Two live Android roots, with different key algorithms

Fetched from `https://android.googleapis.com/attestation/root`:

| Root | Key | Signature | Validity |
|---|---|---|---|
| `serialNumber=f92009e853b6b045` | RSA 4096 | `sha256WithRSAEncryption` | 2022-03-20 → 2042-03-15 |
| `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US` | ECDSA P-384 | `ecdsa-with-SHA384` | 2025-07-17 → 2035-07-15 |

Both are live. The P-384 root became mandatory for Remote Key Provisioning
devices in April 2026, but the RSA root remains valid until 2042 and is what
present-day chains use. A P-256-only verifier — the obvious thing to build in a
codebase that is ES256 everywhere — would have failed on both.

### 2. Digest is not derivable from the key curve

A real Google chain, structure decoded:

| # | Subject | Key | Signed with | CA | KeyUsage |
|---|---|---|---|---|---|
| 0 | `CN=Android Keystore Key` | EC P-256 | `ecdsa-with-SHA256` | — | Digital Signature |
| 1 | `title=TEE, serialNumber=58eb…` | EC P-256 | `ecdsa-with-SHA256` | CA:TRUE | Certificate Sign |
| 2 | `title=TEE, serialNumber=3fb6…` | EC **P-384** | `sha256WithRSAEncryption` | CA:TRUE | Certificate Sign |
| 3 | `serialNumber=f92009e853b6b045` | RSA 4096 | `sha256WithRSAEncryption` | CA:TRUE | Certificate Sign |

Certificate 1 carries a P-256 key but is signed **by certificate 2's P-384 key
using SHA-256**. A "P-384 implies SHA-384" mapping — the natural shortcut — is
wrong on real traffic. The digest must come from the signature
`AlgorithmIdentifier`, independent of the signing key's curve.

The chain verifies: `openssl verify -CAfile <root> -untrusted <int2>
-untrusted <int1> <leaf>` returns `OK`, and each link verifies individually.

### 3. The presented chain includes its own root

Element 3 above is the self-signed RSA root. Google transmits the anchor inside
the chain, whereas HAIP §6.1.1 (and foundry's `build_x5c`) excludes it. The
design must state explicitly what happens to it.

### 4. Leaf certificates effectively never expire

The Android leaf's validity window is `1970-01-01` → `2106-02-07`. Validity
checking contributes **no** freshness protection for these chains. All replay
resistance rests on the `attestationChallenge` ↔ `c_nonce` binding, which makes
that check load-bearing in sub-project D rather than a nicety.

## Approach

### Chosen: OpenSSL `X509_STORE_CTX`

`openssl` and `openssl-sys` are **already compiled into every foundry build**,
transitively via `josekit` (`Cargo.lock`: `josekit 0.10.3` → `openssl`). Using
OpenSSL for path validation therefore adds a direct crate dependency but **no
new native linkage** and no change to build or container requirements.

OpenSSL supplies every rule this design requires — link signatures,
`basicConstraints`, `keyUsage`, `pathLenConstraint`, validity, AKI/SKI path
building — across ECDSA P-256/P-384/P-521 and RSA, with the digest taken from
the signature algorithm. There is no algorithm matrix for foundry to maintain,
and `validate_chain`'s body gets *smaller*: the hand-rolled DN walk is deleted.

That OpenSSL enforces the CA constraints, and not merely signatures, was
verified rather than assumed. A leaf signed by a `CA:FALSE` intermediate is
rejected with:

```
error 79 at 1 depth lookup: invalid CA certificate
error 32 at 1 depth lookup: key usage does not include certificate signing
```

while the same chain shape with a proper `CA:TRUE` intermediate returns `OK`.
Both the rejection and its positive control were run.

### Rejected: hand-rolled on `x509-cert` + RustCrypto

Adding `p256`, `p384`, `p521`, `rsa`, `ecdsa`, `sha2` and implementing the rules
in `foundry-core` keeps everything in pure Rust with total control. It was
rejected because it means hand-writing security-critical path validation and
owning the algorithm matrix — including the P-384-key/SHA-256-signature case
above, which caught out the first attempt at reasoning about it. Path-validation
bugs are the class of defect that passes tests and fails in production. This
would only be preferable if avoiding OpenSSL were a hard constraint, and it is
not, because OpenSSL is already linked.

### Considered and not chosen: `rustls-webpki`

Audited, pure-Rust, and already present in `Cargo.lock` (`rustls-webpki
0.103.13`, transitively). **This is a viable alternative, not a disqualified
one**, and the record should say so plainly.

Three objections were raised against it during design and all three turned out
to be wrong on inspection; they are recorded here so that nobody re-derives
them:

- *"It requires EKU, and Android certificates have none."* False. webpki's own
  documentation states that the Extended Key Usage extension is optional and
  "certificates not carrying a particular value in the EKU extension are
  acceptable"; the constraint only binds when the extension is present.
- *"It requires a Subject Alternative Name."* Overstated. Subject-name
  verification is a separate, opt-in call
  (`EndEntityCert::verify_is_valid_for_subject_name`) and can simply not be
  made.
- *"It does not support P-521."* False. `ECDSA_P521_SHA256`,
  `ECDSA_P521_SHA384` and `ECDSA_P521_SHA512` are all provided.

The actual reasons for preferring OpenSSL are narrower, and weaker:

1. **No new dependency decision.** OpenSSL is already linked unavoidably through
   `josekit`, which underpins every JOSE operation in the workspace, so the
   "avoid C crypto" benefit is not available to us regardless. Promoting webpki
   to a direct dependency would instead require choosing and pinning a crypto
   provider feature (`ring` vs `aws-lc-rs`), which is a new build-surface
   decision.
2. **Strictly stronger constraint checking.** webpki deliberately ignores
   `keyUsage` on CA certificates, reasoning that `basicConstraints.cA` makes it
   redundant. OpenSSL enforces both, and was observed rejecting a chain on
   `keyUsage` grounds (`error 32`) independently of `CA:FALSE` (`error 79`).
   `CA:TRUE` is the substantive check, so this is a modest edge.
3. **PEM-native.** `TrustStore` and every call site already carry PEM; webpki
   works in DER and would add conversions.
4. **Empirically validated on the real artefact.** The exact validation OpenSSL
   performs was run against the real four-certificate Google chain and returned
   `OK`. No equivalent check was run through webpki.

If a future change makes the OpenSSL dependency undesirable — for example if
`josekit` were replaced — webpki is the obvious migration target and this
decision should be revisited rather than defended.

## Design

### Module layout

`crates/foundry-core/src/trust/mod.rs` keeps all of its existing
`x509-cert`-based inspection helpers unchanged: `parse_cert_pem`,
`is_self_signed`, `validity_window`, `san_dns_names`, `build_x5c`,
`x5c_entry_to_pem`, `cert_ec_public_coords`, `x509_hash_client_id_value`,
`match_san_dns`. Only path validation moves to OpenSSL.

The result is a clean division: **`x509-cert` inspects, OpenSSL validates.**
`x509-cert` is retained rather than replaced because sub-project D needs it to
decode the Android `KeyDescription` extension, and because these helpers are
consumed directly by callers that want coordinates or DNS names, not a verdict.

`TrustStore` changes internally — it builds an `openssl::x509::store::X509Store`
from the anchor PEMs — while `from_pems`, `from_config`, and `is_empty` keep
their signatures.

### Verification pipeline

`validate_chain(leaf_pem, intermediates, store, now_unix)` becomes:

1. **Parse the leaf** and apply the existing `is_self_signed` pre-check,
   returning `TrustError::SelfSignedLeaf`. This stays *ahead* of OpenSSL because
   HAIP-0040, HAIP-0080 and HAIP-0085 assert this specific error variant, and
   OpenSSL would report the case with a less specific code.
2. **Drop self-signed certificates from the presented intermediates.** This is
   where Google's in-chain RSA root is discarded.
3. **Convert** the leaf and surviving intermediates to `openssl::x509::X509` and
   collect the intermediates into an untrusted `Stack<X509>`.
4. **Verify** with `X509StoreContext::init(store, &leaf, &chain, |ctx|
   ctx.verify_cert())`.
5. **Map** the `X509VerifyResult` onto `TrustError`.

### The four load-bearing OpenSSL decisions

Each of these is a correctness requirement, not a tuning preference, and each
must carry an explanatory comment so that a later "cleanup" does not silently
undo it.

**1. Verification time is injected, never read from the clock.**
`X509VerifyParam::set_time(now_unix)`. `validate_chain` already receives
`now_unix`, and callers rely on it: the existing test
`expired_leaf_is_rejected` passes `now + 400 days` to prove a 365-day leaf is
rejected. Using system time would silently break that contract.

**2. `X509VerifyFlags::PARTIAL_CHAIN` is set.** foundry's existing semantics
allow a configured anchor to be *any* certificate, not necessarily a self-signed
root. Without `PARTIAL_CHAIN`, OpenSSL insists on building a path to a
self-signed root and would reject anchor bundles that pin an intermediate. This
was confirmed against the real chain: pinning the P-384 TEE intermediate as the
sole anchor validates the leaf only with `-partial_chain`.

**3. Purpose is left unset.** Setting a purpose enables Extended Key Usage
checks. Android attestation certificates carry no EKU, so setting a purpose
would reject every Google chain. It is the single most likely thing for a future
change to get wrong in the name of hardening.

**4. A presented root is never trusted.** Step 2 discards self-signed
certificates from the untrusted set; the anchor must come from configuration.

This is **defence-in-depth, not load-bearing**, and the distinction was
established by experiment rather than assumed. OpenSSL already refuses to
bootstrap trust from a presented root: with the real Google chain supplied in
full — root included as an untrusted intermediate — and only an *unrelated*
anchor configured, verification fails with `error 19 self-signed certificate in
certificate chain`. Conversely, with the genuine root configured as an anchor
*and* also presented in the chain (exactly what Google sends), verification
succeeds. So the filtering step changes neither outcome.

It is kept for two smaller reasons: it makes the intent explicit at the point
where a reader would otherwise have to know OpenSSL's behaviour to be
reassured, and it yields a more accurate error (`UntrustedChain` rather than a
self-signed-in-chain code) when an anchor genuinely is not configured. The
implementation comment must state that it is redundant with OpenSSL's own
behaviour, so that a future reader does not mistake it for the sole barrier.

Consequence, recorded here because it is operational setup rather than code:
**sub-project D requires Google's two attestation roots to be installed as
configured trust anchors.** Until they are, every Google request fails closed.

### Error mapping

| OpenSSL verify result | `TrustError` |
|---|---|
| `CERT_HAS_EXPIRED`, `CERT_NOT_YET_VALID` | `Expired` (existing) |
| `UNABLE_TO_GET_ISSUER_CERT`, `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | `UntrustedChain` (existing) |
| `SELF_SIGNED_CERT_IN_CHAIN`, `DEPTH_ZERO_SELF_SIGNED_CERT` | `UntrustedChain` (existing) |
| `INVALID_CA`, `KEYUSAGE_NO_CERTSIGN`, `PATH_LENGTH_EXCEEDED` | `UntrustedChain` (existing) |
| `CERT_SIGNATURE_FAILURE` | **`InvalidSignature` (new)** |
| PEM/DER conversion failure | `Parse` (existing) |
| any other verify result | `UntrustedChain` (existing) |

One variant is added: `TrustError::InvalidSignature`. Folding a forged signature
into `UntrustedChain` would emit *"no configured trust anchor matches the
certificate chain"*, which is actively misleading — it sends an operator to
audit their anchor bundle when the real finding is that a chain was tampered
with. `AGENTS.md` §4.5 treats operator-facing diagnostics as API, so conflating
the two would be a defect.

The addition is safe: no exhaustive `match` on `TrustError` exists anywhere in
the workspace. Of the 17 `TrustError::` usages outside `error.rs`, every one is
either a construction site or a `matches!` assertion in a test; `error.rs`
itself only derives a `#[from]` conversion into `CoreError`. Adding a variant
therefore cannot break a match arm.

### Invariants

- **§4.1** — no `unwrap`, `expect`, or `panic!` in the new code; every OpenSSL
  call returns a `Result` mapped to `TrustError`.
- **§4.5** — certificate bytes, DNs, and public keys are never logged from
  `trust/`. `validate_chain` returns typed errors; the single log record is
  emitted by the existing error mapper in `crates/foundry/src/server.rs`.
- **`X509Store` is `Send + Sync`** — confirmed: `openssl::x509::store` declares
  it through `foreign_type_and_impl_send_sync!`. This matters because
  `TrustStore` is constructed and held across `.await` points in `token.rs` and
  `credential.rs`.
- **`X509VerifyResult::from_raw` is `unsafe`**, so error classification reads
  `ctx.error().as_raw()` and compares against integer constants declared locally
  with a citation to OpenSSL's `x509_vfy.h`. No `unsafe` block is required.

## Testing

The point of this change is a check that currently does nothing, so the tests
*are* the deliverable. Written test-first.

**Golden positive — the real Google chain.** The four-certificate chain decoded
above, committed as a fixture and validated against the RSA-4096 root as a
configured anchor, pinned at a fixed `now_unix` so it cannot rot. This one test
exercises RSA-4096 verification, a P-384 issuer key signing with SHA-256,
in-chain root filtering, and a 1970→2106 leaf validity window simultaneously.

**The test that fails today.** Take a valid `rcgen` chain, flip a byte in the
leaf's signature, assert `TrustError::InvalidSignature`. This currently passes
validation — that is the bug, expressed as a test.

**Privilege escalation, with its control.** A leaf signed by a `CA:FALSE`
intermediate must be rejected; the same chain shape with a `CA:TRUE`
intermediate must pass. Both directions are required — a rejection test without
a positive control proves only that *something* failed, the pattern
`crates/foundry/tests/logging_redaction.rs` already establishes.

**Preserved behaviour.** The existing `trust/mod.rs` tests stay green,
unmodified: `self_signed_leaf_is_rejected`, `expired_leaf_is_rejected`,
`untrusted_anchor_is_rejected`, `valid_leaf_against_anchor_passes`,
`san_matching_works`, `x5c_entry_to_pem_round_trips_a_cert`,
`from_config_reads_certs_as_a_file_path_not_literal_pem`.
`expired_leaf_is_rejected` is what proves `set_time` is wired rather than the
system clock.

**Curve coverage.** P-256 and P-384 chains both validate, built through `rcgen`
with explicit algorithms. Note that `pki::new_ca` and `pki::issue_leaf` call
`rcgen::KeyPair::generate()`, which is hardcoded to `PKCS_ECDSA_P256_SHA256`, so
a loop over those helpers would test one curve repeatedly while appearing to
test several.

P-521 is **not** covered by a test: `rcgen::PKCS_ECDSA_P521_SHA512` is gated
behind `#[cfg(feature = "aws_lc_rs")]` and foundry builds `rcgen` with default
features (`ring`), so the symbol does not exist in this build. This is a fixture
limitation rather than a foundry gap — OpenSSL verifies P-521 natively, and
`cert_ec_public_coords` already handles P-521 SPKIs — but it is recorded here
rather than papered over. Enabling `aws_lc_rs` purely to obtain the fixture
would switch the crypto backend of the whole workspace and is not worth it.

**Anchor-as-intermediate.** A non-self-signed certificate configured as the
anchor still validates. This pins `PARTIAL_CHAIN` and prevents a future cleanup
from removing it.

**Downstream call sites.** The existing suites for the other five call sites —
`foundry-sd-jwt-vc`, `foundry-mdoc`, `status_list`, `foundry-issuer`
attestation, `foundry-verifier` — must pass unchanged. `rcgen` signs properly,
so they should; any failure there is a real finding about that call site's
fixtures, not test friction to work around.

## Verification gate

`foundry-core/trust` is consumed by every crate, so per `AGENTS.md` §5.2 the
affected set is the whole dependency graph:

```bash
cargo test -p foundry-core -p foundry-sd-jwt-vc -p foundry-mdoc \
           -p foundry-issuer -p foundry-verifier -p foundry
cargo clippy -p foundry-core --all-targets -- -D warnings
cargo fmt --check
```

This is the one sub-project where the scoped gate legitimately approaches the
full gate. That is a property of where the change sits in the layering, not a
licence to reach for `--workspace`; the E2E suite still runs only in the §5.3
full gate at the end of the branch.

## Documentation

**`docs/conformance/openid4vc-conformance.md`** — corrective, not a status flip:

- Rewrite the evidence for **VCI-0231**, **HAIP-0031**, **HAIP-0082** and
  **HAIP-0083** to describe what is actually verified. Their `conforming`
  verdicts become true for the first time; today the evidence text claims a
  cryptographic property the code does not provide.
- Resolve **HAIP-0039**, **HAIP-0079** and **HAIP-0084** ("the X.509 certificate
  of the trust anchor MUST NOT be included in the `x5c` header"), currently
  `ambiguous` because `validate_chain` ignores a redundant anchor. Step 2 gives
  a definite answer for the self-signed case: a presented root is explicitly
  discarded and never trusted. The non-self-signed-anchor case remains
  accepted-but-ignored, and that is documented as deliberate — it is
  receiver-side enforcement of a sender-side MUST, which HAIP does not require.
- Internal consistency is enforced by
  `crates/foundry/tests/conformance_report.rs`; edits must keep its
  cross-references valid.

**`crates/foundry-core/src/trust/mod.rs`** — delete the `TODO(trust-hardening)`
comment.

**`crates/foundry-core/AGENTS.md`** — add a Gotchas entry recording the
`x509-cert` inspects / OpenSSL validates split, and *why* verification purpose
is left unset, so that nobody "hardens" it by setting one and silently breaks
every Android chain.

## Follow-on work

This design unblocks, but does not include:

- **D** — `android_keystore_attestation` proof type: `KeyDescription` extension
  parsing, `attestationChallenge` ↔ `c_nonce` binding, security-level policy,
  and revocation against Google's status endpoint.
- Installing Google's two attestation roots as configured trust anchors, which
  D requires as operational setup.