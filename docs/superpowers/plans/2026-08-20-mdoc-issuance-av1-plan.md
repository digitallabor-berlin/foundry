# mdoc issuance — `eu.europa.ec.av.1` Proof of Age — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make foundry's existing-but-unused mdoc issuance path conformant,
configured, and covered, by issuing the EUDI Proof of Age attestation
(`eu.europa.ec.av.1`).

**Architecture:** `build_mdoc` starts returning a bare `IssuerSigned` instead of
a `DeviceResponse` wrapper; a new `foundry-core` `config::mdoc` module holds the
two facts foundry knows about specific mdoc doctypes (namespace, and av.1's
closed attribute set); `credential.rs`'s mdoc arm reads its docType from
`doctype` alone, resolves the namespace through that module, and builds elements
from the configured claim list rather than from the offer. One credential type is
shipped in both configs and covered from the wallet routes down to a verified
presentation.

**Tech Stack:** Rust 2024 workspace, `ciborium` (CBOR), `coset` (COSE),
`serde_yaml`, `axum` + `tower` for route tests, `cargo nextest`.

**Spec:** `docs/superpowers/specs/2026-08-20-mdoc-issuance-av1-design.md`

## Global Constraints

- **Test runner is `cargo nextest run`, never `cargo test`.** nextest does not
  run doctests; none are added here.
- **The gate is the whole workspace, every time, no tiers** (root `AGENTS.md`
  §5.1):

  ```bash
  cargo fmt
  cargo nextest run --workspace --no-fail-fast --status-level fail
  cargo clippy --workspace --all-targets -- -D warnings
  ```

  Baseline before this plan: `1038 tests run: 1038 passed, 13 skipped`.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` in request
  paths** — `foundry-issuer`, `foundry-verifier`, `foundry::server`. Permitted
  only under `#[cfg(test)]` and in `tests/`. (§4.1)
- **Every protocol-facing change carries a spec citation in a comment**, naming
  document and clause. (§4.4)
- **Dependencies flow one way:** `foundry-core` → format crates → engines →
  binary. `foundry-core` must not depend on any `foundry-*` crate. (§3)
- **`isomdl` is a reference only — never add it as a dependency.**
- **No new `#[tracing::instrument]` without `skip_all`.** No new log fields.
  (§4.5)
- Governing clause strings, verbatim, for use in comments:
  - EU AV Annex A §4.1.1 — "The document type for Proof of Age attestation SHALL
    be `eu.europa.ec.av.1`."
  - EU AV Annex A §4.1.2 — "All attributes belong to namespace
    `eu.europa.ec.av.1`" and "A Proof of Age Attestation SHALL NOT include any
    other attribute."
  - OpenID4VCI L2235 — `doctype` is REQUIRED and identifies the Credential type
    per ISO 18013-5.
  - OpenID4VCI L2249 — the `credential` claim MUST be the base64url-encoded CBOR
    `IssuerSigned` structure.
  - OpenID4VCI L976 — Credential Formats expressed as binary data MUST be
    base64url-encoded.

---

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `docs/specs/eu-age-verification-annex-a-av-profile.md` | **Create.** Vendored Annex A, pinned | 1 |
| `AGENTS.md` | Modify. §4.4 spec table row | 1 |
| `crates/foundry-mdoc/src/builder.rs` | Modify. Bare `IssuerSigned`; simplify `build_device_response`; byte-level test | 2 |
| `crates/foundry-core/src/config/mdoc.rs` | **Create.** Doctype constants, `namespace_for_doctype`, `validate_av_claims` | 3 |
| `crates/foundry-core/src/config/mod.rs` | Modify. Register the module | 3 |
| `crates/foundry-core/src/config/validate.rs` | Modify. Reject `vct` on `mso_mdoc`; call `validate_av_claims` | 4 |
| `crates/foundry-issuer/src/credential.rs` | Modify. mdoc arm: doctype-only, resolved namespace, config-filtered claims | 5 |
| `crates/foundry-issuer/tests/conformance_vci.rs` | Modify. Un-ignore + rename the two gap tests; fix a base64 engine | 6 |
| `config.yaml` | Modify. The av.1 credential type + `over18_mdoc` named query | 7 |
| `crates/foundry/src/commands.rs` | Modify. Same two additions to `QUICKSTART_CONFIG` | 7 |
| `crates/foundry/tests/quickstart_config.rs` | Modify. Three-type assertion + av.1 shape test | 7 |
| `crates/foundry/tests/wallet_issuance.rs` | Modify. Structural HTTP issuance test (8); closed-loop verify test (9) | 8, 9 |
| `docs/conformance/openid4vc-conformance.md` | Modify. VCI-0175/0176 → conforming; drop two gap rows | 10 |
| `crates/foundry-mdoc/AGENTS.md`, `crates/foundry-core/AGENTS.md`, `crates/foundry-issuer/AGENTS.md`, `README.md` | Modify. Gotchas, module maps, config docs | 10 |

**Dependencies:** 1, 2, 3 are independent. 4 needs 3. 5 needs 3. 6 needs 2+4+5.
7 needs 4. 8 needs 5. 9 needs 8. 10 needs all.

---

## Task 1: Vendor Annex A and register it as a governing spec

**Files:**

- Create: `docs/specs/eu-age-verification-annex-a-av-profile.md`
- Modify: `AGENTS.md` (§4.4 table)

**Interfaces:**

- Consumes: nothing.
- Produces: the path `docs/specs/eu-age-verification-annex-a-av-profile.md`,
  cited by comments in Tasks 3, 4, 5, 7.

Docs-only. No test cycle; its gate is that the workspace still builds and the
licence attribution is present verbatim.

- [ ] **Step 1: Fetch the pinned Annex A**

Pinned to release **1.0.9**, commit `5eb8a033bf41179a83c27a5df47ff8fdde388bf8`.
Fetch by SHA, never `main`, so content matches the pin:

```bash
curl -sSL -o /tmp/annex-a.md \
  "https://raw.githubusercontent.com/eu-digital-identity-wallet/av-doc-technical-specification/5eb8a033bf41179a83c27a5df47ff8fdde388bf8/docs/annexes/annex-A/annex-A-av-profile.md"
wc -l /tmp/annex-a.md
```

Expected: a non-empty markdown file. If it 404s the path moved in that release —
locate it via
`curl -sSL "https://api.github.com/repos/eu-digital-identity-wallet/av-doc-technical-specification/git/trees/5eb8a033bf41179a83c27a5df47ff8fdde388bf8?recursive=1" | grep annex-A`
and use what you find. **Do not substitute `main`.**

- [ ] **Step 2: Write the vendored file with a provenance header**

Create the file with exactly this header, a blank line, then the **verbatim**
contents of `/tmp/annex-a.md`:

```markdown
<!--
  VENDORED SPECIFICATION — DO NOT EDIT THE BODY.

  Document:   EU Age Verification Solution Technical Specification
              Annex A (normative) — "Age Verification Profile"
  Upstream:   https://github.com/eu-digital-identity-wallet/av-doc-technical-specification
  Path:       docs/annexes/annex-A/annex-A-av-profile.md
  Release:    1.0.9
  Commit:     5eb8a033bf41179a83c27a5df47ff8fdde388bf8
  Retrieved:  2026-08-20

  Only Annex A is vendored. The wider specification covers wallet architecture,
  app UX and transport concerns foundry does not implement; vendoring it whole
  would misrepresent how much of it governs this repository.

  This is a PINNED copy. Treat it as the source of truth for this repository,
  not a newer revision found online. Bumping the pin is a deliberate change:
  update this file, then reconcile the code (root AGENTS.md §4.4).

  LICENCE / ATTRIBUTION (reproduced verbatim as CC BY 4.0 requires):

    The European Age Verification Solution technical specification © 2025
    by European Commission is licensed under Attribution 4.0 International.
    To view a copy of this licence, visit http://creativecommons.org/licenses/by/4.0/
-->
```

- [ ] **Step 3: Verify the licence text and load-bearing clauses survived**

```bash
cd /Users/senexi/dev/eudiw/foundry
F=docs/specs/eu-age-verification-annex-a-av-profile.md
grep -c "Attribution 4.0 International" $F
grep -c "eu.europa.ec.av.1" $F
grep -c "SHALL NOT include any other attribute" $F
grep -c "age_over_18" $F
```

Expected: every count `>= 1`. A zero on the third means the wrong file or
revision — stop and re-check the pin.

- [ ] **Step 4: Add the §4.4 table row**

In `AGENTS.md` §4.4's **first** table (the pinned standards-track specs —
OpenID4VCI / OpenID4VP / HAIP / ABCA / DPoP), **not** the vendor-profile table
and **not** the external-reference table, append:

```markdown
| [`eu-age-verification-annex-a-av-profile.md`](docs/specs/eu-age-verification-annex-a-av-profile.md) | EU Age Verification Solution Technical Specification, **Annex A (normative), "Age Verification Profile"** — the `eu.europa.ec.av.1` Proof of Age attestation: its doctype (§4.1.1), its namespace (§4.1.2), and its closed two-attribute set (§4.1.2, "A Proof of Age Attestation SHALL NOT include any other attribute"). Profiles ISO/IEC 18013-5 and ISO/IEC 23220-2. Authority is **scoped to that one doctype**; where it is stricter than ISO 18013-5 for it, this profile wins. Vendored rather than stubbed because it is CC BY 4.0 — freely redistributable with attribution, which the file's header carries verbatim. Pinned to release 1.0.9 (`5eb8a033`); Annex A only. Note its "Out of Scope" section: OpenID4VCI profiling for ISO mDoc is deferred to ISO/IEC 23220-3, which is **not** vendored — foundry's OpenID4VCI behaviour remains governed by OpenID4VCI 1.0 and HAIP |
```

- [ ] **Step 5: Confirm the workspace is unaffected and commit**

```bash
cd /Users/senexi/dev/eudiw/foundry
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
```

Expected: `1038 tests run: 1038 passed, 13 skipped` — a docs-only change must
move nothing.

```bash
git add docs/specs/eu-age-verification-annex-a-av-profile.md AGENTS.md
git commit -m "docs(specs): vendor EU Age Verification Annex A, pinned to 1.0.9

CC BY 4.0 permits redistribution with attribution, so this is a verbatim pinned
copy rather than an external-reference stub. Annex A only -- the wider
specification governs wallet architecture and transport concerns foundry does
not implement. Authority is scoped to the eu.europa.ec.av.1 doctype."
```

---

## Task 2: `build_mdoc` returns a bare `IssuerSigned` (closes GAP-VCI-16)

**Files:**

- Modify: `crates/foundry-mdoc/src/builder.rs`
- Test: `crates/foundry-mdoc/src/builder.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:
  `build_mdoc(claims: MdocClaims, signer: &dyn Signer, x5c: Option<Vec<String>>) -> Result<Vec<u8>, FormatError>`
  — signature **unchanged**; return *content* changes from a `DeviceResponse`
  wrapper to a bare `IssuerSigned` map with exactly the keys `nameSpaces` and
  `issuerAuth`.
  `build_device_response(issuer_signed_mdoc: &[u8], doc_type: &str, device_signer: &dyn Signer, session_transcript: &ciborium::Value) -> Result<Vec<u8>, FormatError>`
  — signature unchanged; its first argument is now a bare `IssuerSigned`.
  Task 5 calls `build_mdoc`; Tasks 6, 8, 9 assert on the new content.

This is a wire-format change. The crate's `AGENTS.md` records that five format
defects survived a green suite because every test round-tripped foundry's builder
through foundry's own verifier — so **the new test reads CBOR directly and must
not call the verifier.** A round trip is structurally blind here: `verify_mdoc`
parses a `DeviceResponse` and `build_device_response` still produces one, so it
would pass either way.

- [ ] **Step 1: Write the failing byte-level test**

Append to the `#[cfg(test)] mod tests` block in
`crates/foundry-mdoc/src/builder.rs`, after
`multi_certificate_x5chain_is_an_array_of_byte_strings`:

```rust
    /// OpenID4VCI Format Profile / mdoc (L2249): "The `credential` claim MUST be
    /// the base64url-encoded CBOR `IssuerSigned` structure." `build_mdoc`'s
    /// output IS that structure — the Credential Endpoint only base64url-encodes
    /// it — so the top level must be `IssuerSigned` itself, `{nameSpaces,
    /// issuerAuth}`, and not a `DeviceResponse` that merely contains one.
    ///
    /// Reads the CBOR directly and deliberately does NOT call
    /// `foundry_mdoc::verifier`. The verifier parses a `DeviceResponse`, which
    /// `build_device_response` still produces, so a round trip is blind to this
    /// distinction and would pass for either envelope (crate AGENTS.md: a
    /// passing round-trip is not evidence).
    #[test]
    fn build_mdoc_emits_a_bare_issuer_signed_not_a_device_response() {
        let signer = test_signer();
        let bytes = build_mdoc(sample_claims(), &signer, None).unwrap();

        let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let map = decoded.as_map().expect("IssuerSigned is a CBOR map");

        let keys: Vec<&str> = map
            .iter()
            .filter_map(|(k, _)| match k {
                ciborium::Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();

        assert_eq!(
            keys,
            vec!["nameSpaces", "issuerAuth"],
            "IssuerSigned carries exactly nameSpaces and issuerAuth at the top level"
        );
        assert!(
            !keys.contains(&"documents")
                && !keys.contains(&"version")
                && !keys.contains(&"docType"),
            "a DeviceResponse wrapper is one layer too many for L2249, got {keys:?}"
        );
    }
```

- [ ] **Step 2: Run it to confirm it fails**

```bash
cd /Users/senexi/dev/eudiw/foundry
cargo nextest run -p foundry-mdoc build_mdoc_emits_a_bare_issuer_signed_not_a_device_response
```

Expected: FAIL, reporting `keys == ["version", "documents"]`.

- [ ] **Step 3: Drop the wrapper in `build_mdoc`**

Replace this block (from the `doc_map` binding through the function's
`Ok(final_bytes)`):

```rust
    let doc_map: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            ciborium::Value::Text("docType".to_string()),
            ciborium::Value::Text(claims.doc_type),
        ),
        (
            ciborium::Value::Text("issuerSigned".to_string()),
            ciborium::Value::Map(issuer_signed),
        ),
    ];

    let outer: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            ciborium::Value::Text("version".to_string()),
            ciborium::Value::Text("1.0".to_string()),
        ),
        (
            ciborium::Value::Text("documents".to_string()),
            ciborium::Value::Array(vec![ciborium::Value::Map(doc_map)]),
        ),
    ];

    let mut final_bytes = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(outer), &mut final_bytes)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(final_bytes)
```

with:

```rust
    // OpenID4VCI Format Profile / mdoc (L2249): the `credential` claim MUST be
    // the base64url-encoded CBOR `IssuerSigned` structure. This function's
    // output IS that structure — the Credential Endpoint only base64url-encodes
    // it — so the bare `IssuerSigned` is returned, not a `DeviceResponse`
    // wrapper containing one. A wallet following L2249 literally parses these
    // bytes as `IssuerSigned` directly.
    //
    // The `docType` the wrapper used to carry is not lost: it is inside the
    // signed `MobileSecurityObject` above, which is where a verifier must read
    // it from anyway, since the wrapper's copy was unauthenticated.
    let mut final_bytes = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(issuer_signed), &mut final_bytes)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(final_bytes)
```

Also change the `// Outer mdoc CBOR.` comment above the `issuer_signed` binding
to `// IssuerSigned = { nameSpaces, issuerAuth }.`

`claims.doc_type` is now read only by the `claims.doc_type.clone()` that builds
the MSO. Leave that clone as-is.

- [ ] **Step 4: Update `build_mdoc`'s doc comment**

Replace the final paragraph — from `/// The remaining known divergence is the
**outer envelope**` through `/// conformance gap rather than fixed here.` — with:

```rust
/// Returns the bare `IssuerSigned` structure — `{nameSpaces, issuerAuth}` —
/// which is what OpenID4VCI's mdoc Format Profile (L2249) requires the
/// `credential` claim to carry once base64url-encoded. It is deliberately NOT a
/// `DeviceResponse`: wrapping one is the holder's job, and
/// [`build_device_response`] does it for tests.
```

- [ ] **Step 5: Simplify `build_device_response`**

Replace:

```rust
    let outer: ciborium::Value = ciborium::from_reader(issuer_signed_mdoc)
        .map_err(|e| FormatError::Deserialization(format!("issuer-signed mdoc CBOR: {e}")))?;
    let issuer_signed = outer
        .as_map()
        .and_then(|m| lookup(m, "documents"))
        .and_then(|v| v.as_array())
        .and_then(|docs| docs.first())
        .and_then(|d| d.as_map())
        .and_then(|d| lookup(d, "issuerSigned"))
        .ok_or_else(|| {
            FormatError::InvalidStructure(
                "issuer-signed mdoc missing documents[0].issuerSigned".into(),
            )
        })?
        .clone();
```

with:

```rust
    // `build_mdoc` returns the bare `IssuerSigned` (OpenID4VCI L2249), so there
    // is no wrapper to unpick — this function's whole job is to ADD the
    // DeviceResponse layer a holder sends.
    let issuer_signed: ciborium::Value = ciborium::from_reader(issuer_signed_mdoc)
        .map_err(|e| FormatError::Deserialization(format!("issuer-signed mdoc CBOR: {e}")))?;
    if issuer_signed
        .as_map()
        .and_then(|m| lookup(m, "issuerAuth"))
        .is_none()
    {
        return Err(FormatError::InvalidStructure(
            "issuer-signed mdoc is not an IssuerSigned map carrying issuerAuth".into(),
        ));
    }
```

Then update that function's doc comment — replace:

```rust
/// `issuer_signed_mdoc` is [`build_mdoc`]'s output; its `documents[0].issuerSigned`
/// is lifted out and rewrapped with a `deviceSigned` half disclosing nothing.
```

with:

```rust
/// `issuer_signed_mdoc` is [`build_mdoc`]'s output — a bare `IssuerSigned` — and
/// is wrapped here with a `deviceSigned` half disclosing nothing.
```

- [ ] **Step 6: Fix the test helper that navigated the old wrapper**

In the same test module, `x5chain_header` walks
`documents[0].issuerSigned.issuerAuth`. Replace:

```rust
        let issuer_auth = outer
            .as_map()
            .and_then(|m| lookup(m, "documents"))
            .and_then(|v| v.as_array())
            .and_then(|docs| docs.first())
            .and_then(|d| d.as_map())
            .and_then(|d| lookup(d, "issuerSigned"))
            .and_then(|v| v.as_map())
            .and_then(|m| lookup(m, "issuerAuth"))
            .expect("documents[0].issuerSigned.issuerAuth is present")
            .clone();
```

with:

```rust
        let issuer_auth = outer
            .as_map()
            .and_then(|m| lookup(m, "issuerAuth"))
            .expect("issuerAuth is present at the IssuerSigned top level")
            .clone();
```

- [ ] **Step 7: Run the crate's suite and fix remaining wrapper assumptions**

```bash
cd /Users/senexi/dev/eudiw/foundry
cargo nextest run -p foundry-mdoc --no-fail-fast --status-level fail
```

Expected: all pass, including the new test.

Any other failure is another site that assumed the wrapper. **Do not** change
`src/verifier.rs`'s `version` / `documents` traversal (~lines 151, 167) or
`tests/real_presentation.rs` — both correctly parse a *`DeviceResponse`*, which is
still what `build_device_response` and a real wallet produce. Only sites that
consumed `build_mdoc`'s output *directly* legitimately change.

- [ ] **Step 8: Run the whole gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: `1039 passed, 13 skipped` — the prior 1038 plus one new test. The two
`#[ignore]`d gap tests stay skipped; Task 6 un-ignores them.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry-mdoc/src/builder.rs
git commit -m "fix(mdoc)!: build_mdoc returns a bare IssuerSigned (closes GAP-VCI-16)

OpenID4VCI L2249 requires the credential claim to be the base64url-encoded CBOR
IssuerSigned structure. build_mdoc returned a DeviceResponse-shaped wrapper, so
an issued credential carried one layer more than the clause allows and a wallet
parsing it as IssuerSigned failed.

build_device_response gets simpler: it no longer unpicks
documents[0].issuerSigned, it just adds the DeviceResponse layer a holder sends.

Guarded by a byte-level test that reads the CBOR directly and does not call the
verifier -- the verifier parses a DeviceResponse either way, so a round trip is
structurally blind to this change."
```

---

## Task 3: `foundry-core` `config::mdoc` — doctype-keyed facts

**Files:**

- Create: `crates/foundry-core/src/config/mdoc.rs`
- Modify: `crates/foundry-core/src/config/mod.rs`
- Test: `crates/foundry-core/src/config/mdoc.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: `ClaimDef` (existing, `crates/foundry-core/src/config/model.rs`) —
  fields `path: Vec<String>`, `required: Option<bool>`,
  `selectively_disclosable: bool`, `display: Vec<serde_json::Value>`, and method
  `is_required() -> bool`.
- Produces, all `pub` from `foundry_core::config::mdoc`:
  - `const AV_DOCTYPE: &str`
  - `const MDL_DOCTYPE: &str`
  - `fn namespace_for_doctype(doctype: &str) -> &str`
  - `fn validate_av_claims(credential_type_id: &str, claims: &[ClaimDef]) -> Result<(), ConfigError>`

  Task 4 calls `AV_DOCTYPE` and `validate_av_claims`; Task 5 calls
  `namespace_for_doctype`.

This module is pure functions over owned data, so tests and implementation are
written together — there is no observable behaviour before the function exists.
What matters is that each negative test was written from a **clause**, not from
the implementation.

- [ ] **Step 1: Write the module with its tests**

Create `crates/foundry-core/src/config/mdoc.rs`:

```rust
//! What foundry knows about specific mdoc doctypes.
//!
//! Two facts are keyed on a doctype string: which namespace its data elements
//! live in, and — for the EUDI Proof of Age attestation — which elements it may
//! carry at all. They live in one module so they cannot drift apart, and in
//! `foundry-core` because both `super::validate` and `foundry-issuer` need them
//! and `foundry-core` is the only crate below both (root AGENTS.md §3).

use super::model::ClaimDef;
use crate::error::ConfigError;

/// The EUDI Proof of Age attestation.
///
/// EU Age Verification Solution Technical Specification, Annex A §4.1.1: "The
/// document type for Proof of Age attestation SHALL be `eu.europa.ec.av.1`."
/// See `docs/specs/eu-age-verification-annex-a-av-profile.md`.
pub const AV_DOCTYPE: &str = "eu.europa.ec.av.1";

/// The ISO/IEC 18013-5 mobile driving licence.
pub const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";

/// The namespace ISO mDL data elements live in.
///
/// Deliberately NOT equal to [`MDL_DOCTYPE`] — that difference is the entire
/// reason this module exists.
const MDL_NAMESPACE: &str = "org.iso.18013.5.1";

/// The mdoc namespace a doctype's data elements belong to.
///
/// Doctype-as-namespace is the **correct default**, not a fallback: every EUDI
/// attestation uses its doctype verbatim as the namespace — Annex A §4.1.2,
/// "All attributes belong to namespace `eu.europa.ec.av.1`" — and the EMVCo DPC
/// specification does the same. ISO mDL is the exception, carrying elements in
/// `org.iso.18013.5.1` under doctype `org.iso.18013.5.1.mDL`.
///
/// Fails safe: an unrecognised doctype returns itself, which is right for every
/// EUDI attestation foundry might add without touching this function.
pub fn namespace_for_doctype(doctype: &str) -> &str {
    match doctype {
        MDL_DOCTYPE => MDL_NAMESPACE,
        other => other,
    }
}

/// Enforce Annex A §4.1.2's closed attribute set for [`AV_DOCTYPE`].
///
/// §4.1.2 defines exactly two attributes, both encoded `bool` — `age_over_18`
/// (Mandatory in issuance) and a repeatable optional `age_over_NN` — and then
/// closes the set: "A Proof of Age Attestation SHALL NOT include any other
/// attribute."
///
/// Checked at config load so a non-conformant credential type is a startup
/// failure rather than a silently non-conformant credential. `age_over_18` must
/// additionally be `required`: §4.1.2 records it as *Mandatory* in issuance, so
/// a config declaring it optional describes a credential the profile does not
/// admit — presence alone is not enough.
pub fn validate_av_claims(
    credential_type_id: &str,
    claims: &[ClaimDef],
) -> Result<(), ConfigError> {
    for claim in claims {
        let [element] = claim.path.as_slice() else {
            return Err(ConfigError::Validation(format!(
                "credential_type '{credential_type_id}' ({AV_DOCTYPE}) claim path {:?} is not a \
                 single mdoc data element; Annex A §4.1.2 defines a flat attribute set",
                claim.path
            )));
        };
        if !is_age_over_element(element) {
            return Err(ConfigError::Validation(format!(
                "credential_type '{credential_type_id}' ({AV_DOCTYPE}) declares attribute \
                 '{element}'; Annex A §4.1.2 admits only 'age_over_18' and 'age_over_NN', and \
                 states a Proof of Age Attestation SHALL NOT include any other attribute"
            )));
        }
    }

    match claims.iter().find(|c| c.path.as_slice() == ["age_over_18"]) {
        None => Err(ConfigError::Validation(format!(
            "credential_type '{credential_type_id}' ({AV_DOCTYPE}) must declare 'age_over_18'; \
             Annex A §4.1.2 records it as Mandatory in issuance"
        ))),
        Some(c) if !c.is_required() => Err(ConfigError::Validation(format!(
            "credential_type '{credential_type_id}' ({AV_DOCTYPE}) declares 'age_over_18' as \
             optional; Annex A §4.1.2 records it as Mandatory in issuance"
        ))),
        Some(_) => Ok(()),
    }
}

/// `age_over_18`, or `age_over_NN` for a decimal NN.
///
/// A real integer parse, not a prefix match: `age_over_banana` and a bare
/// `age_over_` must both be rejected. Leading zeros are rejected too, since
/// `age_over_08` is not an ISO/IEC 18013-5 §7.2.5 element name even though it
/// parses as a number.
fn is_age_over_element(element: &str) -> bool {
    match element.strip_prefix("age_over_") {
        Some(nn) => nn.parse::<u8>().is_ok() && (nn.len() == 1 || !nn.starts_with('0')),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(path: &str, required: Option<bool>) -> ClaimDef {
        ClaimDef {
            path: vec![path.to_string()],
            required,
            selectively_disclosable: false,
            display: vec![],
        }
    }

    #[test]
    fn mdl_namespace_is_not_the_mdl_doctype() {
        assert_eq!(namespace_for_doctype(MDL_DOCTYPE), "org.iso.18013.5.1");
        assert_ne!(namespace_for_doctype(MDL_DOCTYPE), MDL_DOCTYPE);
    }

    /// Annex A §4.1.2: "All attributes belong to namespace `eu.europa.ec.av.1`"
    /// — identical to the doctype, which is the EUDI convention.
    #[test]
    fn eudi_doctypes_use_the_doctype_as_the_namespace() {
        assert_eq!(namespace_for_doctype(AV_DOCTYPE), AV_DOCTYPE);
    }

    /// Fails safe rather than erroring or guessing.
    #[test]
    fn an_unknown_doctype_resolves_to_itself() {
        assert_eq!(
            namespace_for_doctype("com.example.something.1"),
            "com.example.something.1"
        );
    }

    #[test]
    fn the_two_shipped_av_attributes_are_accepted() {
        let claims = vec![
            claim("age_over_18", Some(true)),
            claim("age_over_16", Some(false)),
        ];
        assert!(validate_av_claims("av", &claims).is_ok());
    }

    #[test]
    fn a_foreign_attribute_is_rejected() {
        let claims = vec![claim("age_over_18", Some(true)), claim("issue_date", None)];
        let err = validate_av_claims("av", &claims).unwrap_err().to_string();
        assert!(
            err.contains("issue_date") && err.contains("SHALL NOT include any other attribute"),
            "the error must name the offending attribute and cite the clause: {err}"
        );
    }

    #[test]
    fn omitting_age_over_18_is_rejected() {
        let claims = vec![claim("age_over_16", Some(true))];
        let err = validate_av_claims("av", &claims).unwrap_err().to_string();
        assert!(err.contains("must declare 'age_over_18'"), "{err}");
    }

    /// Mandatory in issuance is stronger than merely present.
    #[test]
    fn declaring_age_over_18_optional_is_rejected() {
        let claims = vec![claim("age_over_18", Some(false))];
        let err = validate_av_claims("av", &claims).unwrap_err().to_string();
        assert!(err.contains("as optional"), "{err}");
    }

    /// A prefix match would accept all of these; a real parse must not.
    #[test]
    fn age_over_suffix_must_be_a_number() {
        for bad in ["age_over_banana", "age_over_", "age_over_1a", "age_over_08"] {
            let claims = vec![claim("age_over_18", Some(true)), claim(bad, None)];
            assert!(
                validate_av_claims("av", &claims).is_err(),
                "'{bad}' is not an age_over_NN element and must be rejected"
            );
        }
    }

    #[test]
    fn a_nested_claim_path_is_rejected() {
        let claims = vec![
            claim("age_over_18", Some(true)),
            ClaimDef {
                path: vec!["a".to_string(), "b".to_string()],
                required: None,
                selectively_disclosable: false,
                display: vec![],
            },
        ];
        let err = validate_av_claims("av", &claims).unwrap_err().to_string();
        assert!(err.contains("flat attribute set"), "{err}");
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/foundry-core/src/config/mod.rs`, change:

```rust
mod model;
mod validate;

pub use model::*;
```

to:

```rust
pub mod mdoc;
mod model;
mod validate;

pub use model::*;
```

`mdoc` is `pub mod` rather than `mod` + glob re-export, so callers write
`foundry_core::config::mdoc::namespace_for_doctype` — the module name is part of
the meaning, and a bare `namespace_for_doctype` would be ambiguous at a call
site.

- [ ] **Step 3: Run the new tests**

```bash
cd /Users/senexi/dev/eudiw/foundry
cargo nextest run -p foundry-core config::mdoc --no-fail-fast --status-level fail
```

Expected: 9 tests, all pass.

- [ ] **Step 4: Run the gate and commit**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: previous total plus 9.

```bash
git add crates/foundry-core/src/config/mdoc.rs crates/foundry-core/src/config/mod.rs
git commit -m "feat(core): config::mdoc -- doctype-keyed namespace and av.1 attribute set

Two facts foundry keys on an mdoc doctype, in one module so they cannot drift:
the namespace its elements live in (ISO mDL is the exception -- doctype
org.iso.18013.5.1.mDL, namespace org.iso.18013.5.1; every EUDI attestation uses
its doctype verbatim), and eu.europa.ec.av.1's closed attribute set per EU Age
Verification Annex A 4.1.2.

Lives in foundry-core because both config::validate and foundry-issuer need it
and core is the only crate below both (AGENTS.md 3). Not yet wired in."
```

---

## Task 4: Wire the mdoc validation into `Config::validate()` (closes GAP-VCI-12, half 1)

**Files:**

- Modify: `crates/foundry-core/src/config/validate.rs` (the `"mso_mdoc"` match arm, ~line 36)
- Test: `crates/foundry-core/src/config/validate.rs` (its `#[cfg(test)]` module)

**Interfaces:**

- Consumes: `super::mdoc::{AV_DOCTYPE, validate_av_claims}` from Task 3.
- Produces: `Config::validate()` now rejects (a) `vct` set on an `mso_mdoc`
  credential type, (b) an `AV_DOCTYPE` type violating the closed attribute set.
  Task 7's two configs must satisfy both.

- [ ] **Step 1: Locate the existing test module and its config helper**

```bash
cd /Users/senexi/dev/eudiw/foundry
rg -n '#\[cfg\(test\)\]' crates/foundry-core/src/config/validate.rs
rg -n 'fn .*-> Config|const MINIMAL|fn cfg' crates/foundry-core/src/config/validate.rs | head
rg -n 'CredentialType \{' crates/foundry-core/src/config/validate.rs | head -3
```

There are already 9 `CredentialType { .. }` literals in this file's tests. Copy
the shape of the nearest one rather than inventing a fixture — in particular
match how it obtains a base `Config`.

- [ ] **Step 2: Write the two failing tests**

Add to that test module, adapting the `Config`-construction line to the helper
the file actually uses:

```rust
    /// OpenID4VCI L2235 identifies an mdoc by `doctype`. `vct` is an SD-JWT-VC
    /// identifier with no meaning here, and a type carrying both left docType
    /// resolution ambiguous — GAP-VCI-12. The ambiguous state is removed rather
    /// than resolved, which is what lets the Credential Endpoint read `doctype`
    /// with no fallback at all.
    #[test]
    fn vct_on_an_mso_mdoc_credential_type_is_rejected() {
        let mut cfg = /* base valid Config, per this file's existing helper */;
        cfg.credential_types = vec![CredentialType {
            id: "av".to_string(),
            format: "mso_mdoc".to_string(),
            vct: Some("https://issuer.example.com/vct/av".to_string()),
            doctype: Some(super::mdoc::AV_DOCTYPE.to_string()),
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["age_over_18".to_string()],
                required: Some(true),
                selectively_disclosable: false,
                display: vec![],
            }],
            validity_seconds: None,
        }];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("must not set 'vct'"),
            "an mso_mdoc type carrying vct must be rejected: {err}"
        );
    }

    /// The closed attribute set is enforced at load, not merely documented.
    /// Annex A §4.1.2: "A Proof of Age Attestation SHALL NOT include any other
    /// attribute." Without this, an operator's `issuing_country` would be
    /// issued as an mdoc data element the profile forbids.
    #[test]
    fn a_foreign_attribute_on_the_av_doctype_is_rejected_at_load() {
        let mut cfg = /* base valid Config, per this file's existing helper */;
        cfg.credential_types = vec![CredentialType {
            id: "av".to_string(),
            format: "mso_mdoc".to_string(),
            vct: None,
            doctype: Some(super::mdoc::AV_DOCTYPE.to_string()),
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![
                ClaimDef {
                    path: vec!["age_over_18".to_string()],
                    required: Some(true),
                    selectively_disclosable: false,
                    display: vec![],
                },
                ClaimDef {
                    path: vec!["issuing_country".to_string()],
                    required: None,
                    selectively_disclosable: false,
                    display: vec![],
                },
            ],
            validity_seconds: None,
        }];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("issuing_country"), "{err}");
    }
```

- [ ] **Step 3: Run them to confirm they fail**

```bash
cargo nextest run -p foundry-core vct_on_an_mso_mdoc_credential_type_is_rejected a_foreign_attribute_on_the_av_doctype_is_rejected_at_load
```

Expected: both FAIL with `called Result::unwrap_err() on an Ok value` —
`validate()` currently accepts both configs.

- [ ] **Step 4: Implement the two checks**

Add `use super::mdoc;` to `validate.rs`'s imports, then replace the `"mso_mdoc"`
arm:

```rust
                "mso_mdoc" => {
                    if ct.doctype.is_none() {
                        return Err(ConfigError::Validation(format!(
                            "credential_type '{}' (mso_mdoc) requires 'doctype'",
                            ct.id
                        )));
                    }
                }
```

with:

```rust
                "mso_mdoc" => {
                    // OpenID4VCI Format Profile / mdoc (L2235): `doctype` is
                    // REQUIRED and identifies the Credential type per ISO
                    // 18013-5.
                    let Some(doctype) = ct.doctype.as_deref() else {
                        return Err(ConfigError::Validation(format!(
                            "credential_type '{}' (mso_mdoc) requires 'doctype'",
                            ct.id
                        )));
                    };
                    // `vct` is an SD-JWT-VC identifier (typically an HTTPS URL)
                    // with no relationship to ISO 18013-5's reverse-DNS docType
                    // convention. A type carrying both was config-legal and made
                    // docType resolution ambiguous — GAP-VCI-12. Rejecting it
                    // removes the ambiguous state rather than picking a winner
                    // inside it, which is what lets `credential.rs` read
                    // `doctype` with no fallback at all.
                    if ct.vct.is_some() {
                        return Err(ConfigError::Validation(format!(
                            "credential_type '{}' (mso_mdoc) must not set 'vct'; an mdoc is \
                             identified by 'doctype' (OpenID4VCI L2235)",
                            ct.id
                        )));
                    }
                    // EU Age Verification Annex A §4.1.2's closed attribute set.
                    // Keyed on a known doctype, in the manner of
                    // `create_offer.rs`'s DPC_VCT; see
                    // docs/specs/eu-age-verification-annex-a-av-profile.md.
                    if doctype == mdoc::AV_DOCTYPE {
                        mdoc::validate_av_claims(&ct.id, &ct.claims)?;
                    }
                }
```

- [ ] **Step 5: Run the tests to confirm they pass**

```bash
cargo nextest run -p foundry-core vct_on_an_mso_mdoc_credential_type_is_rejected a_foreign_attribute_on_the_av_doctype_is_rejected_at_load
```

Expected: both PASS.

- [ ] **Step 6: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: green. If a pre-existing test fails because it built an `mso_mdoc` type
with `vct: Some(..)` **and** called `validate()`, that fixture was
non-conformant — fix the fixture to `vct: None`, do **not** weaken the check.
`conformance_vci.rs`'s VCI-0175 test deliberately sets `vct` but never calls
`validate()`, so it is unaffected.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-core/src/config/validate.rs
git commit -m "feat(core)!: reject vct on mso_mdoc types and enforce av.1's attribute set

Two config-load checks. vct on an mso_mdoc credential type is now an error: it
is an SD-JWT-VC identifier with no meaning for an mdoc, and a type carrying both
it and doctype made docType resolution ambiguous (GAP-VCI-12). Removing the
ambiguous state is what lets the Credential Endpoint read doctype with no
fallback.

An eu.europa.ec.av.1 type is additionally checked against EU Age Verification
Annex A 4.1.2's closed attribute set, so a SHALL NOT violation is a startup
failure rather than a silently non-conformant credential."
```

---

## Task 5: `credential.rs` — doctype-only, resolved namespace, config-filtered claims

**Files:**

- Modify: `crates/foundry-issuer/src/credential.rs` (the `"mso_mdoc"` arm, ~line 428)
- Test: `crates/foundry-issuer/src/credential.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**

- Consumes: `foundry_core::config::mdoc::namespace_for_doctype` (Task 3);
  `build_mdoc` returning a bare `IssuerSigned` (Task 2);
  `MdocClaims { doc_type, namespaces, device_key_jwk, signed_at, valid_until }`
  (unchanged); `IssuanceError::InvalidRequest(String)`.
- Produces: an issued `mso_mdoc` credential whose docType is exactly
  `cred_type.doctype`, whose single namespace is
  `namespace_for_doctype(doctype)`, and whose elements are the intersection of
  `cred_type.claims` and `tx.claims`. Tasks 6, 8, 9 assert on this.

- [ ] **Step 1: Add a decode helper and the failing test**

The claim-filtering half is the security-relevant one: the arm currently iterates
`tx.claims` (the **offer's** claims), so an offer can introduce an attribute the
configured type — and therefore Task 4's validation — never approved.

Find the module's existing mdoc-issuing test to copy its setup:

```bash
cd /Users/senexi/dev/eudiw/foundry
rg -n 'mso_mdoc' crates/foundry-issuer/src/credential.rs
rg -n 'async fn ' crates/foundry-issuer/src/credential.rs | sed -n '1,40p'
```

Add this helper to `credential.rs`'s `#[cfg(test)] mod tests`:

```rust
    /// Element identifiers present in an issued mdoc credential, sorted.
    ///
    /// Decodes rather than trusting: base64url → CBOR `IssuerSigned` →
    /// `nameSpaces[ns]` → each `#6.24(bstr .cbor IssuerSignedItem)` →
    /// `elementIdentifier`.
    fn issued_elements(credential_b64: &str, namespace: &str) -> Vec<String> {
        let bytes = B64URL.decode(credential_b64).expect("base64url");
        let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice()).expect("CBOR");
        let map = decoded.as_map().expect("IssuerSigned map");
        let namespaces = map
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(s) if s == "nameSpaces" => Some(v),
                _ => None,
            })
            .expect("nameSpaces")
            .as_map()
            .expect("nameSpaces is a map");
        let items = namespaces
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(s) if s == namespace => Some(v),
                _ => None,
            })
            .unwrap_or_else(|| panic!("namespace {namespace} is present"))
            .as_array()
            .expect("a namespace holds an array of IssuerSignedItemBytes");

        let mut out = Vec::new();
        for item in items {
            let inner = match item {
                ciborium::Value::Tag(24, b) => match b.as_ref() {
                    ciborium::Value::Bytes(bytes) => bytes.clone(),
                    other => panic!("tag 24 must wrap a byte string, got {other:?}"),
                },
                other => panic!("elements travel tag-24 embedded, got {other:?}"),
            };
            let item: ciborium::Value =
                ciborium::from_reader(inner.as_slice()).expect("IssuerSignedItem CBOR");
            out.push(
                item.as_map()
                    .expect("IssuerSignedItem map")
                    .iter()
                    .find_map(|(k, v)| match k {
                        ciborium::Value::Text(s) if s == "elementIdentifier" => v.as_text(),
                        _ => None,
                    })
                    .expect("elementIdentifier")
                    .to_string(),
            );
        }
        out.sort();
        out
    }
```

Then the test. Build a credential type declaring **only** `age_over_18`, and a
transaction whose `tx.claims` carries `age_over_18` **and** a rogue
`issuing_country`; issue, and assert only the declared element appears. Model the
config/transaction construction on the module's existing mdoc test:

```rust
    /// An offer may not introduce an mdoc data element the credential type did
    /// not declare.
    ///
    /// `Config::validate()` checks a credential type's claim list against the
    /// governing profile — for `eu.europa.ec.av.1`, Annex A §4.1.2's closed
    /// attribute set. That check is worthless if the Credential Endpoint then
    /// emits whatever the offer happened to carry, so the element **set** comes
    /// from configuration and the offer supplies only **values**. The SD-JWT VC
    /// arm has always worked this way; the two arms disagreeing was the defect.
    #[tokio::test]
    async fn an_offer_supplied_element_absent_from_config_is_not_issued() {
        // ... construct cfg with one mso_mdoc credential type whose claims are
        // [age_over_18] alone and whose doctype is "eu.europa.ec.av.1";
        // construct the transaction with tx.claims = {age_over_18: true,
        // issuing_country: "Deutschland"}; drive handle_credential_request.
        assert_eq!(
            issued_elements(&res.credentials[0].credential, "eu.europa.ec.av.1"),
            vec!["age_over_18".to_string()],
            "an element the credential type never declared must not be issued"
        );
    }
```

Write that body out concretely — a step may not ship as a comment. The two
assertions above are the requirement; the setup is whatever this module's
existing mdoc test already does.

- [ ] **Step 2: Run it to confirm it fails**

```bash
cargo nextest run -p foundry-issuer an_offer_supplied_element_absent_from_config_is_not_issued
```

Expected: FAIL — `["age_over_18", "issuing_country"]` was issued, because the arm
iterates `tx.claims`.

- [ ] **Step 3: Rewrite the `"mso_mdoc"` arm**

Replace:

```rust
            "mso_mdoc" => {
                let doc_type = cred_type
                    .vct
                    .clone()
                    .or_else(|| cred_type.doctype.clone())
                    .unwrap_or_else(|| tx.credential_type_id.clone());

                let mut ns_map = BTreeMap::new();
                let mut elem_map = BTreeMap::new();
                for (k, v) in &tx.claims {
                    elem_map.insert(k.clone(), v.clone());
                }
                ns_map.insert(doc_type.clone(), elem_map);
```

with:

```rust
            "mso_mdoc" => {
                // OpenID4VCI Format Profile / mdoc (L2235): `doctype` is
                // REQUIRED and identifies the Credential type per ISO 18013-5.
                // `doctype` is the SOLE source — there is deliberately no
                // fallback to `vct` or to the credential type id. Preferring
                // `vct` produced an SD-JWT-VC-style URL where an ISO 18013-5
                // reverse-DNS identifier belongs, which was GAP-VCI-12;
                // `Config::validate()` now rejects `vct` on an `mso_mdoc` type
                // outright, so a fallback chain here could only ever return
                // `doctype` while documenting a precedence rule that no longer
                // exists.
                //
                // Validation makes the `None` branch unreachable for a loaded
                // config. It stays a typed error rather than an unwrap because
                // this is a request path (root AGENTS.md §4.1).
                let doc_type = cred_type.doctype.clone().ok_or_else(|| {
                    IssuanceError::InvalidRequest(format!(
                        "credential type '{}' has format mso_mdoc but no doctype",
                        tx.credential_type_id
                    ))
                })?;

                // The namespace is NOT always the docType. ISO mDL carries its
                // elements in `org.iso.18013.5.1` under docType
                // `org.iso.18013.5.1.mDL`; EUDI attestations do use the docType
                // verbatim — EU Age Verification Annex A §4.1.2, "All attributes
                // belong to namespace `eu.europa.ec.av.1`". See
                // `foundry_core::config::mdoc`.
                let namespace = foundry_core::config::mdoc::namespace_for_doctype(&doc_type);

                // Elements come from the credential type's CONFIGURED claim
                // list, with the offer supplying only values — the same rule the
                // SD-JWT VC arm above follows. Iterating `tx.claims` instead
                // would let an offer introduce an element the configured type
                // never declared, defeating the profile checks
                // `Config::validate()` performs against the closed attribute set
                // of a doctype like `eu.europa.ec.av.1`.
                let mut elem_map = BTreeMap::new();
                for claim_def in &cred_type.claims {
                    if let Some(top_key) = claim_def.path.first()
                        && let Some(val) = tx.claims.get(top_key)
                    {
                        elem_map.insert(top_key.clone(), val.clone());
                    }
                }

                let mut ns_map = BTreeMap::new();
                ns_map.insert(namespace.to_string(), elem_map);
```

The rest of the arm — `MdocClaims { .. }`, `build_mdoc(..)`, `B64URL.encode(..)`
— is unchanged.

- [ ] **Step 4: Run the test to confirm it passes**

```bash
cargo nextest run -p foundry-issuer an_offer_supplied_element_absent_from_config_is_not_issued
```

Expected: PASS — the element set is exactly `["age_over_18"]`.

- [ ] **Step 5: Run the gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: green. An existing mdoc test that relied on offer-supplied elements
reaching the credential must declare those claims on its credential type — that
is the new intended contract, not a regression. A test whose mdoc doctype is
`org.iso.18013.5.1.mDL` will now find its elements under namespace
`org.iso.18013.5.1`; update the assertion, since that is the correction.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/credential.rs
git commit -m "fix(issuer)!: mdoc docType from doctype only; elements from config

Three changes to the mso_mdoc arm of the Credential Endpoint.

docType now comes from cred_type.doctype alone. The vct -> doctype ->
credential_type_id fallback is deleted rather than reordered: Config::validate()
rejects vct on an mso_mdoc type, so the chain could only ever return doctype
while documenting a precedence rule that no longer exists (GAP-VCI-12).

The namespace is resolved through foundry_core::config::mdoc rather than assumed
equal to the docType -- correct for EUDI attestations, wrong for ISO mDL.

Elements are built from the configured claim list, with the offer supplying only
values. Iterating tx.claims let an offer introduce an element the credential type
never declared, which defeated the closed-attribute-set validation entirely. The
SD-JWT VC arm always worked this way; the arms disagreeing was the defect."
```

---

## Task 6: Close the two conformance gaps in `conformance_vci.rs`

**Files:**

- Modify: `crates/foundry-issuer/tests/conformance_vci.rs` (~lines 965-1125)

**Interfaces:**

- Consumes: Tasks 2, 4, 5.
- Produces: two now-running tests named
  `vci_0176_mdoc_credential_is_a_bare_issuer_signed` and
  `vci_0175_mdoc_doc_type_comes_from_doctype`. Task 10 cites these exact names as
  evidence in the conformance report.

Both tests were written failing-first and **already assert the conformant
behaviour**, so no assertion is inverted — only the `#[ignore]`, the names, and
the prose change. One latent bug must be fixed at the same time.

- [ ] **Step 1: Un-ignore and rename the VCI-0176 test**

Delete the `#[ignore = "GAP-VCI-16: ..."]` attribute line above
`gap_vci_16_mdoc_credential_is_not_a_bare_issuer_signed`, rename the function to
`vci_0176_mdoc_credential_is_a_bare_issuer_signed`, and replace the banner
comment above it:

```rust
// ---------------------------------------------------------------------------
// VCI-0176 — OpenID4VCI Format Profile / mdoc (L2249): the `credential` claim
// MUST be the base64url-encoded CBOR `IssuerSigned` structure.
//
// Closed 2026-08-20: `build_mdoc` returns the bare `IssuerSigned`. The
// assertions below are unchanged from when this test recorded GAP-VCI-16 — it
// was written failing-first, so closing the gap is the code catching up to the
// test, not the test changing its mind.
// ---------------------------------------------------------------------------
```

- [ ] **Step 2: Run it**

```bash
cd /Users/senexi/dev/eudiw/foundry
cargo nextest run -p foundry-issuer vci_0176_mdoc_credential_is_a_bare_issuer_signed
```

Expected: PASS.

- [ ] **Step 3: Fix the base64 engine in the VCI-0175 test**

This test has never run, so a bug in its body has never surfaced: it decodes with
`base64::engine::general_purpose::STANDARD`, but the credential has been
base64url since VCI-0071 was closed. Un-ignoring it without this fix panics on
`.expect()`.

First confirm the import exists:

```bash
rg -n 'URL_SAFE_NO_PAD' crates/foundry-issuer/tests/conformance_vci.rs | head -3
```

Then replace:

```rust
    let cbor_bytes = base64::engine::general_purpose::STANDARD
        .decode(credential)
        .expect("mdoc credential must be valid base64 (GAP-VCI-03's own encoding)");
```

with:

```rust
    // OpenID4VCI L976 / VCI-0071: binary Credential Formats are base64url, not
    // standard base64. This line read `STANDARD` for exactly as long as the test
    // was `#[ignore]`d — which is how long nothing could notice.
    let cbor_bytes = URL_SAFE_NO_PAD
        .decode(credential)
        .expect("mdoc credential must be base64url (OpenID4VCI L976)");
```

- [ ] **Step 4: Un-ignore, rename, and re-word the VCI-0175 test**

Delete its `#[ignore = "GAP-VCI-12: ..."]` attribute and rename the function to
`vci_0175_mdoc_doc_type_comes_from_doctype`. Replace the banner:

```rust
// ---------------------------------------------------------------------------
// VCI-0175 — OpenID4VCI Format Profile / mdoc (L2235): `doctype` is REQUIRED
// and identifies the Credential type per ISO 18013-5.
//
// Closed 2026-08-20 in two places: `Config::validate()` rejects `vct` on an
// `mso_mdoc` credential type, and the Credential Endpoint reads `doctype` with
// no fallback at all.
// ---------------------------------------------------------------------------
```

Replace the in-body comment on the `vct` mutation, which no longer describes a
config-legal state:

```rust
    // Set BOTH fields. `Config::validate()` now REJECTS this, so it is not a
    // state a loaded config can reach -- which is the point: the Config is
    // built programmatically here, bypassing validation, to prove the credential
    // path ITSELF never reads `vct`. Defence in depth behind the config-load
    // check, not a redundant duplicate of it.
```

And replace the assertion message, which still argues the gap exists:

```rust
    assert!(
        cbor_bytes
            .windows(doctype_needle.len())
            .any(|w| w == doctype_needle),
        "OpenID4VCI Format Profile / mdoc (L2235): the docType must be the configured \
         `doctype` ('org.iso.18013.5.1.mDL'), never the `vct`, even when a \
         programmatically-built Config carries both"
    );
```

- [ ] **Step 5: Run it**

```bash
cargo nextest run -p foundry-issuer vci_0175_mdoc_doc_type_comes_from_doctype
```

Expected: PASS. The needle is the docType inside the MSO, which is present
regardless of Task 3's namespace resolution (this fixture's doctype is
`org.iso.18013.5.1.mDL`, so its *namespace* becomes `org.iso.18013.5.1` — the
docType string itself is unchanged). If it fails, read the actual bytes before
touching the assertion.

- [ ] **Step 6: Confirm two tests moved from skipped to passing, then commit**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: the **skipped** count drops by exactly 2 (13 → 11) and the passed count
rises by 2. If skipped did not drop by 2, an `#[ignore]` was missed.

```bash
git add crates/foundry-issuer/tests/conformance_vci.rs
git commit -m "test(issuer): un-ignore VCI-0175 and VCI-0176; GAP-VCI-12/16 closed

Both tests were written failing-first and already asserted the conformant
behaviour, so only the #[ignore], the names and the prose change.

Also fixes a bug that had never surfaced: the VCI-0175 body decoded the
credential with base64 STANDARD, while credentials have been base64url since
VCI-0071 was closed. An #[ignore]d test cannot report its own rot."
```

---

## Task 7: Ship the `eu.europa.ec.av.1` credential type in both configs

**Files:**

- Modify: `config.yaml`
- Modify: `crates/foundry/src/commands.rs` (`QUICKSTART_CONFIG`, ~line 260)
- Test: `crates/foundry/tests/quickstart_config.rs`

**Interfaces:**

- Consumes: Task 4's validation — both configs must pass it.
- Produces: credential type id `eu.europa.ec.av.1` and named query id
  `over18_mdoc` in both configs. `quickstart.rs` and `e2e_full_flow.rs` load
  these.

`config.yaml` and `QUICKSTART_CONFIG` are near-identical twins.
`QUICKSTART_CONFIG` is a `const &str`, which is why `quickstart_config.rs` exists
at all — nothing else in the suite notices it drifting.

- [ ] **Step 1: Write the failing tests**

In `crates/foundry/tests/quickstart_config.rs`, rename
`quickstart_config_carries_both_credential_types` to
`quickstart_config_carries_all_credential_types` ("both" becomes false with a
third type, and a test whose name contradicts its body is how the next reader is
misled), add the third id, and add a shape test:

```rust
#[test]
fn quickstart_config_carries_all_credential_types() {
    let cfg = quickstart_config();
    let ids: Vec<&str> = cfg
        .credential_types
        .iter()
        .map(|ct| ct.id.as_str())
        .collect();
    assert!(ids.contains(&"pid"), "expected pid, got {ids:?}");
    assert!(
        ids.contains(&"com.emvco.dpc.card"),
        "expected com.emvco.dpc.card, got {ids:?}"
    );
    assert!(
        ids.contains(&"eu.europa.ec.av.1"),
        "expected eu.europa.ec.av.1, got {ids:?}"
    );
}

/// The Proof of Age type's shape is the whole point of shipping it: an mdoc
/// identified by `doctype` with no `vct`, and exactly the two attributes EU Age
/// Verification Annex A §4.1.2 admits — `age_over_18` mandatory, one optional
/// `age_over_NN`.
#[test]
fn quickstart_av_type_has_the_expected_shape() {
    let cfg = quickstart_config();
    let av = cfg
        .credential_types
        .iter()
        .find(|ct| ct.id == "eu.europa.ec.av.1")
        .expect("av type present");

    assert_eq!(av.format, "mso_mdoc");
    assert_eq!(av.doctype.as_deref(), Some("eu.europa.ec.av.1"));
    assert_eq!(
        av.vct, None,
        "an mdoc is identified by doctype; vct is rejected at load (OpenID4VCI L2235)"
    );
    assert!(av.cryptographic_holder_binding);
    assert_eq!(av.resolved_validity_seconds(), 7_776_000);

    let names: Vec<&str> = av.claims.iter().map(|c| c.path[0].as_str()).collect();
    assert_eq!(names, vec!["age_over_18", "age_over_16"]);

    let age_over_18 = av
        .claims
        .iter()
        .find(|c| c.path == vec!["age_over_18".to_string()])
        .expect("age_over_18 declared");
    assert!(
        age_over_18.is_required(),
        "Annex A §4.1.2 records age_over_18 as Mandatory in issuance"
    );
}

/// The repository's own `config.yaml` must load and validate. Nothing else in
/// the suite reads it, so a change there can otherwise only fail at runtime.
/// Parses and validates only — it does not resolve key files, so it needs none
/// of the PKI the quickstart generator produces.
#[test]
fn repository_config_yaml_loads_and_validates() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("config.yaml");
    let cfg = foundry_core::config::Config::load(&path).expect("config.yaml parses");
    cfg.validate().expect("config.yaml validates");
}
```

- [ ] **Step 2: Run them to confirm they fail**

```bash
cd /Users/senexi/dev/eudiw/foundry
cargo nextest run -p foundry --test quickstart_config --no-fail-fast --status-level fail
```

Expected: `quickstart_config_carries_all_credential_types` FAILS with
`expected eu.europa.ec.av.1, got ["pid", "com.emvco.dpc.card"]`, and
`quickstart_av_type_has_the_expected_shape` FAILS on `av type present`.
`repository_config_yaml_loads_and_validates` should PASS already — it is a
regression guard for the next two steps.

- [ ] **Step 3: Add the credential type to `config.yaml`**

Append to the `credential_types:` list, after the `com.emvco.dpc.card` entry:

```yaml
  # EUDI Proof of Age attestation, and the only mso_mdoc type this issuer mints.
  # Governed by docs/specs/eu-age-verification-annex-a-av-profile.md -- EU Age
  # Verification Solution Technical Specification, Annex A (normative).
  - id: eu.europa.ec.av.1
    format: mso_mdoc
    # Annex A 4.1.1: "The document type for Proof of Age attestation SHALL be
    # `eu.europa.ec.av.1`." Deliberately no `vct` -- that is an SD-JWT-VC
    # identifier and Config::validate() rejects it on an mso_mdoc type
    # (OpenID4VCI L2235). 4.1.2 puts the attributes in a namespace equal to the
    # doctype, which foundry resolves in code rather than from config.
    doctype: eu.europa.ec.av.1
    cryptographic_holder_binding: true
    # 90 days, matching Annex A A.11's example validity window. The MSO's
    # validFrom equals its signed time, so this is a relative lifetime -- the
    # profile specifies no absolute window.
    validity_seconds: 7776000
    display:
      - { locale: en-US, name: "Proof of Age" }
      - { locale: de-DE, name: "Altersnachweis" }
    # Annex A 4.1.2 defines exactly two attributes, both `bool`, then closes the
    # set: "A Proof of Age Attestation SHALL NOT include any other attribute."
    # Config::validate() enforces that, so adding a claim here -- an issue_date,
    # an issuing_country -- is a startup failure, not a silent divergence.
    #
    # `selectively_disclosable` is deliberately unset: every IssuerSignedItem is
    # inherently selectively disclosable, so the flag has no meaning for mdoc.
    # That is why `required` is stated explicitly rather than left to its
    # `!selectively_disclosable` default, which would make the
    # mandatory/optional distinction depend on a flag that does not apply here.
    claims:
      - path: [age_over_18]
        required: true
      - path: [age_over_16]
        required: false
```

- [ ] **Step 4: Add the named query to `config.yaml`**

Append to `verifier.named_queries:`:

```yaml
    # The mdoc counterpart to `over18` above. An mdoc claims path is
    # [namespace, element], and for this doctype the namespace equals the
    # doctype (Annex A 4.1.2). `doctype_value` is REQUIRED in an mso_mdoc
    # Credential Query's `meta` (OpenID4VP L2802).
    - id: over18_mdoc
      dcql:
        credentials:
          - id: av
            format: mso_mdoc
            meta: { doctype_value: eu.europa.ec.av.1 }
            claims:
              - path: [eu.europa.ec.av.1, age_over_18]
```

- [ ] **Step 5: Mirror both blocks into `QUICKSTART_CONFIG`**

Apply the identical two blocks to the `QUICKSTART_CONFIG` raw string literal in
`crates/foundry/src/commands.rs`.

**Trap:** that template is a Rust raw string `r#"..."#`. A `"` immediately
followed by `#` **terminates the literal** — which is why the DPC entry's hex
colours are single-quoted. The blocks above deliberately contain no `"#`
sequence; verify after pasting:

```bash
cd /Users/senexi/dev/eudiw/foundry
cargo build -p foundry 2>&1 | head -20
```

Expected: builds. A parse error pointing into `commands.rs` means a `"#` crept
in.

- [ ] **Step 6: Run the config tests**

```bash
cargo nextest run -p foundry --test quickstart_config --test quickstart --no-fail-fast --status-level fail
```

Expected: all pass, including all three tests from Step 1.

If `repository_config_yaml_loads_and_validates` fails here, the `config.yaml`
block violates Task 4's validation — read the error, which names the offending
attribute and cites the clause.

- [ ] **Step 7: Run the gate and commit**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

```bash
git add config.yaml crates/foundry/src/commands.rs crates/foundry/tests/quickstart_config.rs
git commit -m "feat(config): ship the eu.europa.ec.av.1 Proof of Age mdoc type

The first mso_mdoc credential type foundry configures. Exactly the two
attributes EU Age Verification Annex A 4.1.2 admits -- age_over_18 mandatory,
age_over_16 as an optional age_over_NN -- with no vct, and a 90-day relative
validity matching the profile's own example.

Added to config.yaml and to QUICKSTART_CONFIG, which are twins; the latter is a
const &str that only quickstart_config.rs would notice drifting. Also adds an
over18_mdoc named query, whose claims path is [namespace, element], and a test
that the repository's own config.yaml loads and validates -- nothing else in the
suite read it."
```

---

## Task 8: Prove the HTTP-issued credential's shape

**Files:**

- Modify: `crates/foundry/tests/wallet_issuance.rs`

**Interfaces:**

- Consumes: Tasks 2, 3, 5. Existing items in that file: `setup_test_app()`,
  `create_proof(c_nonce, issuer) -> (String, EcKeyPair)`, and the
  `admin_router` / `wallet_router` + `oneshot` request pattern in
  `full_issuance_flow_end_to_end`.
- Produces: `async fn issue_av_credential(state: &AppState) -> (String, EcKeyPair)`
  — the base64url credential string and the holder keypair. Task 9 reuses it.

This asserts the OpenID4VCI-facing contract over the real routes, not by calling
the issuer library directly.

- [ ] **Step 1: Add the av.1 credential type to the fixture**

In `setup_test_app()`, the `credential_types` field is
`vec![CredentialType { /* pid */ }]`. Make it two elements by appending:

```rust
            CredentialType {
                id: "eu.europa.ec.av.1".to_string(),
                format: "mso_mdoc".to_string(),
                // No vct: an mdoc is identified by doctype (OpenID4VCI L2235),
                // and Config::validate() rejects vct on an mso_mdoc type.
                vct: None,
                doctype: Some("eu.europa.ec.av.1".to_string()),
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![],
                // EU Age Verification Annex A §4.1.2's complete attribute set.
                claims: vec![
                    ClaimDef {
                        path: vec!["age_over_18".to_string()],
                        required: Some(true),
                        selectively_disclosable: false,
                        display: vec![],
                    },
                    ClaimDef {
                        path: vec!["age_over_16".to_string()],
                        required: Some(false),
                        selectively_disclosable: false,
                        display: vec![],
                    },
                ],
                validity_seconds: Some(7_776_000),
            },
```

- [ ] **Step 2: Add the issuance helper**

Add to `crates/foundry/tests/wallet_issuance.rs`:

```rust
/// Drive a full `eu.europa.ec.av.1` issuance over the wallet routes and return
/// the base64url `credential` string plus the holder keypair.
///
/// Goes through the HTTP surface rather than calling `foundry_issuer` directly,
/// so what it returns is what a wallet actually receives.
async fn issue_av_credential(state: &AppState) -> (String, EcKeyPair) {
    // 1. Offer, carrying a value for each declared attribute.
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_body = serde_json::json!({
        "credential_type_id": "eu.europa.ec.av.1",
        "claims": { "age_over_18": true, "age_over_16": true },
        "tx_code_required": false
    });
    let offer_req = Request::builder()
        .method("POST")
        .uri("/admin/issuance/offers")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(offer_body.to_string()))
        .unwrap();
    let offer_res = admin_app.oneshot(offer_req).await.unwrap();
    assert_eq!(offer_res.status(), StatusCode::OK);
    let offer_bytes = axum::body::to_bytes(offer_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let offer_json: serde_json::Value = serde_json::from_slice(&offer_bytes).unwrap();
    let pre_auth_code = offer_json["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Token.
    let wallet_app = wallet_router(state.clone());
    let token_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
    );
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(token_body))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    // 3. Nonce.
    let wallet_app = wallet_router(state.clone());
    let nonce_req = Request::builder()
        .method("POST")
        .uri("/nonce")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let nonce_res = wallet_app.oneshot(nonce_req).await.unwrap();
    assert_eq!(nonce_res.status(), StatusCode::OK);
    let nonce_bytes = axum::body::to_bytes(nonce_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let nonce_json: serde_json::Value = serde_json::from_slice(&nonce_bytes).unwrap();
    let c_nonce = nonce_json["c_nonce"].as_str().unwrap().to_string();

    // 4. Credential.
    let (proof_jwt, keypair) = create_proof(&c_nonce, "https://issuer.example.com");
    let cred_body = serde_json::json!({
        "credential_configuration_id": "eu.europa.ec.av.1",
        "format": "mso_mdoc",
        "proofs": { "jwt": [proof_jwt] },
    });
    let wallet_app = wallet_router(state.clone());
    let cred_req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(cred_body.to_string()))
        .unwrap();
    let cred_res = wallet_app.oneshot(cred_req).await.unwrap();
    assert_eq!(cred_res.status(), StatusCode::OK);
    let cred_bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let cred_json: serde_json::Value = serde_json::from_slice(&cred_bytes).unwrap();
    let credential = cred_json["credentials"][0]["credential"]
        .as_str()
        .unwrap()
        .to_string();

    (credential, keypair)
}
```

- [ ] **Step 3: Write the failing shape test**

```rust
/// Issue an `eu.europa.ec.av.1` Proof of Age over the real wallet routes and
/// assert the credential's wire shape.
///
/// Every assertion is a clause foundry is accountable to, not a foundry
/// convention:
///   * OpenID4VCI L976  — a binary Credential Format is base64url;
///   * OpenID4VCI L2249 — the payload IS an `IssuerSigned`, not a wrapper;
///   * EU AV Annex A §4.1.2 — the namespace equals the doctype, and the
///     attributes are the two declared booleans and nothing else;
///   * ISO/IEC 18013-5 — elements travel as `#6.24(bstr .cbor
///     IssuerSignedItem)`.
#[tokio::test]
async fn av_mdoc_issuance_emits_a_conformant_issuer_signed() {
    let (state, _dir) = setup_test_app().await;
    let (credential, _holder) = issue_av_credential(&state).await;

    // OpenID4VCI L976.
    let cbor = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&credential)
        .expect("the credential is base64url (OpenID4VCI L976)");

    // OpenID4VCI L2249.
    let decoded: ciborium::Value = ciborium::from_reader(cbor.as_slice()).expect("CBOR");
    let map = decoded.as_map().expect("IssuerSigned is a CBOR map");
    let top_keys: Vec<&str> = map
        .iter()
        .filter_map(|(k, _)| match k {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        top_keys,
        vec!["nameSpaces", "issuerAuth"],
        "L2249 wants IssuerSigned itself, not a DeviceResponse containing one"
    );

    // EU AV Annex A §4.1.2: attributes live in a namespace equal to the doctype.
    let namespaces = map
        .iter()
        .find_map(|(k, v)| match k {
            ciborium::Value::Text(s) if s == "nameSpaces" => v.as_map(),
            _ => None,
        })
        .expect("nameSpaces is a map");
    let ns_names: Vec<&str> = namespaces
        .iter()
        .filter_map(|(k, _)| match k {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        ns_names,
        vec!["eu.europa.ec.av.1"],
        "Annex A §4.1.2: all attributes belong to namespace eu.europa.ec.av.1"
    );

    // The two declared attributes, as CBOR booleans, and nothing else.
    let items = namespaces[0].1.as_array().expect("an array of items");
    let mut got: Vec<(String, bool)> = items
        .iter()
        .map(|item| {
            // ISO/IEC 18013-5: #6.24(bstr .cbor IssuerSignedItem).
            let inner = match item {
                ciborium::Value::Tag(24, b) => match b.as_ref() {
                    ciborium::Value::Bytes(bytes) => bytes.clone(),
                    other => panic!("tag 24 must wrap a byte string, got {other:?}"),
                },
                other => panic!("elements travel tag-24 embedded, got {other:?}"),
            };
            let item: ciborium::Value =
                ciborium::from_reader(inner.as_slice()).expect("item CBOR");
            let m = item.as_map().expect("IssuerSignedItem is a map");
            let field = |name: &str| {
                m.iter().find_map(|(k, v)| match k {
                    ciborium::Value::Text(s) if s == name => Some(v),
                    _ => None,
                })
            };
            let id = field("elementIdentifier")
                .and_then(|v| v.as_text())
                .expect("elementIdentifier")
                .to_string();
            let value = match field("elementValue").expect("elementValue") {
                ciborium::Value::Bool(b) => *b,
                other => panic!(
                    "Annex A §4.1.2 encodes {id} as bool, got {other:?} -- a date-shaped \
                     string here would mean the closed attribute set leaked"
                ),
            };
            (id, value)
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("age_over_16".to_string(), true),
            ("age_over_18".to_string(), true)
        ],
        "exactly the two declared attributes, both true"
    );
}
```

Add whatever imports this needs at the top of the file — at minimum
`use base64::Engine as _;`. Confirm `ciborium` and `base64` are dev-dependencies
of the `foundry` crate:

```bash
rg -n 'ciborium|base64' crates/foundry/Cargo.toml
```

If either is missing from `[dev-dependencies]`, add it using the workspace
version already pinned in the root `Cargo.toml` — do not introduce a new version.

- [ ] **Step 4: Run it**

```bash
cargo nextest run -p foundry --test wallet_issuance av_mdoc_issuance_emits_a_conformant_issuer_signed
```

Expected: PASS (Tasks 2, 3 and 5 are already in place, so this is a
characterisation test proving the composed behaviour rather than a red-first
one). If it fails on `ns_names`, Task 5's namespace wiring is wrong; if on
`top_keys`, Task 2's is.

- [ ] **Step 5: Run the gate and commit**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

```bash
git add crates/foundry/tests/wallet_issuance.rs
git commit -m "test: mdoc issuance over the wallet routes emits a conformant IssuerSigned

The first workspace-level coverage of mdoc issuance -- wallet_issuance.rs did
not mention mdoc at all. Asserts the clauses foundry is accountable to:
base64url (L976), a bare IssuerSigned (L2249), the namespace equal to the
doctype and exactly the two declared boolean attributes (EU AV Annex A 4.1.2),
and tag-24 element embedding (ISO 18013-5)."
```

---

## Task 9: Close the loop — verify what the issuer emitted

**Files:**

- Modify: `crates/foundry/tests/wallet_issuance.rs`

**Interfaces:**

- Consumes: `issue_av_credential` (Task 8);
  `foundry_core::pki::{new_ca, issue_leaf}`, `foundry_core::trust::build_x5c`,
  `foundry_core::config::TrustAnchor` (all already used by
  `crates/foundry/tests/wallet_verification.rs` — copy its setup);
  `foundry_mdoc::builder::build_device_response`,
  `foundry_mdoc::verifier::{decode_device_response, parse_device_response, verify_issuer_signed}`,
  `foundry_mdoc::types::{SessionTranscriptParams, session_transcript_value}`.
- Produces: nothing later tasks consume.

No test today closes the issue→verify loop: `wallet_verification.rs`'s
`mdoc_presentation_is_accepted` calls `build_mdoc` **directly**, so it never sees
what the HTTP endpoint actually emitted. That gap is why the envelope defect
survived — the two halves were only ever tested against their own inputs.

- [ ] **Step 1: Add a PKI-enabled fixture**

`setup_test_app()` sets `x5c: None` and `trust_anchors: Vec::new()`, so an issued
mdoc carries no certificate chain and cannot be chain-verified. Add a second
fixture that does. Read the existing pattern first — do not invent it:

```bash
cd /Users/senexi/dev/eudiw/foundry
sed -n '71,200p' crates/foundry/tests/wallet_verification.rs
```

Write `async fn setup_test_app_with_pki() -> (AppState, tempfile::TempDir)` that
is `setup_test_app()` plus:

- `let root = new_ca("Foundry Test Root CA", 365)` and an
  `issue_leaf(..)`-produced issuer leaf, both written to files under the temp dir;
- the `issuer_key` `KeyEntry` given `x5c: Some(<leaf cert path>)`;
- `trust_anchors: vec![TrustAnchor { .. }]` naming the root, matching
  `wallet_verification.rs`'s construction field-for-field;
- the same two credential types as Task 8.

Factor the shared config out if that is cleaner than duplicating it — but
duplicating a test fixture is acceptable here and is what `wallet_verification.rs`
already does.

- [ ] **Step 2: Write the failing closed-loop test**

```rust
/// What the Credential Endpoint emitted must verify as an mdoc.
///
/// The only test that spans both halves. `wallet_verification.rs`'s mdoc test
/// calls `build_mdoc` directly, so it never sees the endpoint's actual output;
/// this takes the base64url credential a wallet received over HTTP, wraps it in
/// the `DeviceResponse` a holder would send, and runs foundry's own verifier
/// over it — chain, IssuerAuth signature, MSO validity, element digests and
/// holder-key binding.
#[tokio::test]
async fn an_issued_av_mdoc_verifies_as_an_mdoc() {
    let (state, _dir) = setup_test_app_with_pki().await;
    let (credential, _holder) = issue_av_credential(&state).await;

    let issuer_signed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&credential)
        .expect("base64url (OpenID4VCI L976)");

    // The holder half. Any transcript will do: `verify_issuer_signed` does not
    // consult it, and binding the device signature is `wallet_verification.rs`'s
    // subject, not this test's.
    let transcript = session_transcript_value(SessionTranscriptParams::Redirect {
        client_id: "x509_san_dns:issuer.example.com".to_string(),
        nonce: "test-nonce".to_string(),
        jwk_thumbprint: None,
        response_uri: "https://issuer.example.com/vp/response/x".to_string(),
    })
    .expect("transcript");

    let device_signer = /* an ES256 Signer over the holder key from
                           issue_av_credential's returned keypair -- construct it
                           the way wallet_verification.rs constructs its device
                           signer */;
    let device_response = build_device_response(
        &issuer_signed,
        "eu.europa.ec.av.1",
        &device_signer,
        &transcript,
    )
    .expect("a holder can wrap the issued credential");

    // Verify the issuer half against the trust anchor the fixture configured.
    let decoded = decode_device_response(&device_response).expect("decodes");
    let parsed = parse_device_response(&decoded).expect("parses");
    let now = /* a unix timestamp inside the MSO validity window */;
    let verified = verify_issuer_signed(&parsed, /* trust store */, now)
        .expect("the issued mdoc verifies: chain, IssuerAuth, MSO validity, digests");

    assert_eq!(verified.doc_type, "eu.europa.ec.av.1");
    let ns = verified
        .claims
        .get("eu.europa.ec.av.1")
        .expect("the doctype namespace carries the claims");
    assert_eq!(ns.get("age_over_18"), Some(&serde_json::json!(true)));
    assert_eq!(ns.get("age_over_16"), Some(&serde_json::json!(true)));
}
```

Resolve the three `/* ... */` placeholders against
`wallet_verification.rs`'s `mdoc_presentation_is_accepted` (its device signer and
trust-store construction) and against `MdocVerificationResult`'s actual field
types. **A step may not ship with a placeholder** — check the real signatures:

```bash
rg -n 'pub fn verify_issuer_signed|pub struct MdocVerificationResult|pub struct IssuerVerified' -A 12 crates/foundry-mdoc/src/verifier.rs
rg -n 'device_signer|TrustStore|trust_store' crates/foundry/tests/wallet_verification.rs | sed -n '1,20p'
```

If `verified.claims` is not a nested `serde_json` map, adapt the two claim
assertions to whatever it actually is — but keep them asserting **both**
attributes and their **boolean `true`** values.

- [ ] **Step 3: Run it**

```bash
cargo nextest run -p foundry --test wallet_issuance an_issued_av_mdoc_verifies_as_an_mdoc
```

Expected: PASS. A chain failure means the fixture's `x5c` / `trust_anchors`
wiring is wrong, not the credential — check that before doubting Task 2.

- [ ] **Step 4: Run the gate and commit**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

```bash
git add crates/foundry/tests/wallet_issuance.rs
git commit -m "test: an issued av.1 mdoc verifies through foundry's own verifier

The first test spanning both halves. wallet_verification.rs's mdoc test calls
build_mdoc directly, so it never saw what the Credential Endpoint emitted --
which is precisely how the DeviceResponse-envelope defect survived a green
suite. This takes the base64url credential a wallet received over HTTP, wraps it
as a holder would, and verifies chain, IssuerAuth, MSO validity, digests and
holder-key binding."
```

---

## Task 10: Documentation fallout

**Files:**

- Modify: `docs/conformance/openid4vc-conformance.md`
- Modify: `crates/foundry-mdoc/AGENTS.md`
- Modify: `crates/foundry-core/AGENTS.md`
- Modify: `crates/foundry-issuer/AGENTS.md`
- Modify: `README.md`

**Interfaces:**

- Consumes: the test names from Tasks 3, 4, 5, 6, 8, 9.
- Produces: nothing code-facing.

The conformance report is a **living document**: closing a gap means updating its
rows, not only changing the code (root `AGENTS.md` §8).

- [ ] **Step 1: Update the two clause rows**

In `docs/conformance/openid4vc-conformance.md`:

- **VCI-0175** — status `gap` → `conforming`. Replace the evidence cell with a
  statement of what now holds: `Config::validate()` rejects `vct` on an
  `mso_mdoc` credential type, and `handle_credential_request` reads
  `cred_type.doctype` with no fallback. Test column:
  `vci_0175_mdoc_doc_type_comes_from_doctype, vct_on_an_mso_mdoc_credential_type_is_rejected`.
- **VCI-0176** — status `gap` → `conforming`. Evidence: `build_mdoc` returns the
  bare `IssuerSigned`; note the base64url half was already covered by VCI-0071.
  Test column:
  `vci_0176_mdoc_credential_is_a_bare_issuer_signed, build_mdoc_emits_a_bare_issuer_signed_not_a_device_response, av_mdoc_issuance_emits_a_conformant_issuer_signed`.

- [ ] **Step 2: Remove the two gap-register rows**

Delete the `GAP-VCI-12` and `GAP-VCI-16` rows from the gap register table. Both
are closed; the register is current state, not history.

- [ ] **Step 3: Rewrite `foundry-mdoc/AGENTS.md`'s envelope gotcha**

Replace the bullet beginning **"The remaining known non-conformance is the
OpenID4VCI credential envelope, on the issuance side."** with one stating the
closed position — and state it as a property of the **current code**, since that
file already records having overstated this once:

- `build_mdoc` returns the bare `IssuerSigned` per OpenID4VCI L2249.
- `build_device_response` adds the `DeviceResponse` layer; the verifier's
  `version` / `documents` traversal is for **presentations** and is unchanged.
- The guard is `build_mdoc_emits_a_bare_issuer_signed_not_a_device_response`,
  which reads CBOR directly — a round trip cannot see this class of defect,
  because both sides moved together.

Add a new gotcha:

- **The mdoc namespace is not always the docType.** `foundry_core::config::mdoc`
  resolves it: ISO mDL's doctype `org.iso.18013.5.1.mDL` maps to namespace
  `org.iso.18013.5.1`, while every EUDI attestation uses its doctype verbatim
  (EU AV Annex A §4.1.2). `build_mdoc` itself takes the namespace as a key of
  `MdocClaims::namespaces` and has no opinion; the caller resolves it.

- [ ] **Step 4: Update the other three files**

- `crates/foundry-core/AGENTS.md` — add `config/mdoc.rs` to the module map
  (doctype-keyed namespace + av.1 closed attribute set), and a gotcha that
  `vct` on an `mso_mdoc` type is rejected at load so downstream code needs no
  fallback.
- `crates/foundry-issuer/AGENTS.md` — a gotcha that the mdoc arm takes its
  element **set** from `cred_type.claims` and only its **values** from
  `tx.claims`, matching the SD-JWT VC arm, because config-time profile
  validation is void otherwise.
- `README.md` — document the new credential type in the `credential_types`
  section (~line 888), including that `mso_mdoc` types use `doctype` and must
  not set `vct`, and that `eu.europa.ec.av.1`'s attribute set is fixed by the
  profile. **Do not** document a `namespace` config field — none exists.

- [ ] **Step 5: Verify no stale references remain**

```bash
cd /Users/senexi/dev/eudiw/foundry
rg -n 'GAP-VCI-12|GAP-VCI-16|gap_vci_12|gap_vci_16' . --glob '!target' || echo "clean"
```

Expected: `clean`, or only historical mentions inside
`docs/superpowers/changes/` and `docs/superpowers/specs/`, which are dated
records and must **not** be rewritten.

- [ ] **Step 6: Run the gate, including the E2E suite**

`config.yaml` changed in Task 7 and `e2e_full_flow` loads it, so §5.2's ignored
suite runs before this branch is proposed for merge:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

- [ ] **Step 7: Commit**

```bash
git add docs/conformance/openid4vc-conformance.md crates/foundry-mdoc/AGENTS.md \
        crates/foundry-core/AGENTS.md crates/foundry-issuer/AGENTS.md README.md
git commit -m "docs: record mdoc issuance conformance; GAP-VCI-12 and -16 closed

VCI-0175 and VCI-0176 move from gap to conforming with the new tests as
evidence, and both gap-register rows are removed -- the register is current
state, not history.

foundry-mdoc's AGENTS.md loses the credential-envelope non-conformance and gains
the namespace-is-not-the-docType gotcha. foundry-core documents config/mdoc.rs;
foundry-issuer documents that the mdoc element set comes from config and only
values from the offer. README documents the new credential type."
```

---

## Self-Review

Run against the spec, `docs/superpowers/specs/2026-08-20-mdoc-issuance-av1-design.md`.

**Spec coverage.** §1 vendoring → Task 1. §2.1 → Task 1. §2.2 → Tasks 3, 4.
§2.3 → Task 2. §2.4 → Tasks 4, 5. §2.5 → Task 5. §2.6 → Tasks 3, 5.
§3.1 → Task 1. §3.2 → Task 2. §3.3 → Tasks 3, 4. §3.4 → Task 5. §3.5 → Task 7.
§4 test table → Tasks 2, 3, 4, 6, 7, 8, 9. §4.1 gate → every task's final step,
plus the E2E suite in Task 10. §5 docs → Task 10. §6 out-of-scope items appear in
no task, which is correct.

**Two places this plan goes beyond the spec, deliberately:**

1. **Task 9** (closed-loop verification) is a *new* task. The spec's test table
   asked for `verify_issuer_signed` inside the `wallet_issuance.rs` row; splitting
   it out is right because it needs a PKI-enabled fixture the structural test does
   not, and a reviewer could reasonably approve Task 8 while rejecting Task 9.
2. **Task 7** adds `repository_config_yaml_loads_and_validates`. The spec did not
   ask for it; it exists because nothing in the suite validated the repository's
   own `config.yaml`, and Task 7 is the first change to make that dangerous.

**Known incompleteness, flagged rather than hidden.** Three steps carry
`/* ... */` markers that the implementer must resolve against code this plan
could not fully read: Task 4 Steps 2 (the file's `Config` helper), Task 5 Step 1
(the module's existing mdoc-test setup), and Task 9 Step 2 (device signer, trust
store, `MdocVerificationResult` field types). Each names the exact `rg` command
that reveals the answer and states what the resolved code must assert. These are
the plan's weakest points; an implementer who cannot resolve one should stop and
ask rather than invent a fixture.

**Type consistency.** `namespace_for_doctype(&str) -> &str` is defined in Task 3
and called in Task 5 as
`foundry_core::config::mdoc::namespace_for_doctype(&doc_type)`, with
`.to_string()` at the insertion point — consistent. `validate_av_claims(&str,
&[ClaimDef])` is defined in Task 3 and called in Task 4 as
`mdoc::validate_av_claims(&ct.id, &ct.claims)` — consistent. `AV_DOCTYPE` is used
in Tasks 3, 4. `issue_av_credential(&AppState) -> (String, EcKeyPair)` is defined
in Task 8 and called in Task 9 — consistent. `build_mdoc` and
`build_device_response` keep their signatures throughout.

**The one number to watch.** Task 6 is the only task that should change the
*skipped* count: 13 → 11. Every other task adds to *passed* only. A task that
moves skipped is a task that touched an `#[ignore]` it should not have.

---

## Execution Handoff

**Plan complete and saved to
`docs/superpowers/plans/2026-08-20-mdoc-issuance-av1-plan.md`. Two execution
options:**

**1. Subagent-Driven (recommended)** — a fresh subagent per task, reviewed
between tasks, fast iteration. Suggested tiers per root `AGENTS.md` §7: Tasks 1
and 6 are `mechanical-implementer` (docs and attribute deletions); Tasks 2, 3, 4,
7 are `mechanical-implementer` (1-2 files, complete specs above); Tasks 5, 8, 9
are `integration-implementer` (they resolve placeholders against surrounding
code); Task 10 is `mechanical-implementer`. `task-reviewer` gates each; one
`final-reviewer` pass at the end, which also runs §5.2's E2E suite.

**2. Inline Execution** — execute in this session via
`superpowers:executing-plans`, batching with checkpoints for review.

**Which approach?**
