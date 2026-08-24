# Credential Metadata Nesting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move a Credential Configuration's `display` and `claims` inside the
nested `credential_metadata` object OpenID4VCI 1.0 requires, and correct the
claims description objects' contents, so a conformant wallet stops silently
discarding foundry's credential display metadata.

**Architecture:** One new serialisation struct (`CredentialMetadata`) in
`crates/foundry-issuer/src/metadata.rs` replaces two flat fields on
`CredentialConfigurationSupported`. `build_issuer_metadata` populates it only
when non-empty, and rebuilds each claims description object to carry the
specification's three members instead of foundry's config field names. No
configuration, storage, or request-path behaviour changes — this is purely a
metadata emission change on `GET /.well-known/openid-credential-issuer`.

**Tech Stack:** Rust, `serde`, `serde_json`, `utoipa` (OpenAPI generation),
`cargo nextest` (test runner).

**Spec:** [`docs/superpowers/specs/2026-08-24-credential-metadata-nesting-design.md`](../specs/2026-08-24-credential-metadata-nesting-design.md)

## Global Constraints

- **Test runner is `cargo nextest run`, never `cargo test`.** Root `AGENTS.md`
  §5.1. The whole workspace runs in seconds; there is no scoped or cheaper tier.
- **The gate, run in this order, before marking any task complete:**

  ```bash
  cargo fmt
  cargo nextest run --workspace --no-fail-fast --status-level fail
  cargo clippy --workspace --all-targets -- -D warnings
  ```

- **Never claim a gate you did not run.** Quote the summary line
  (`Summary [ <elapsed>] <N> tests run: <N> passed, <M> skipped`) as evidence.
  Root `AGENTS.md` §5.3.
- **No `.unwrap()` / `.expect()` / `panic!()` in production request paths** —
  permitted only inside `#[cfg(test)]` and under `tests/`. Root `AGENTS.md` §4.1.
  Both tasks here touch only `build_issuer_metadata` (which returns no `Result`
  and performs no fallible operation) and test code, so nothing new is needed.
- **Cite the spec in code comments.** Every new or changed protocol line carries
  a comment naming the line number in
  `docs/specs/openid-4-verifiable-credential-issuance-1_0.md`. Root `AGENTS.md`
  §4.4. The relevant lines, all verified against the pinned copy:

  | Line | Content |
  | --- | --- |
  | L1400 | `credential_metadata`: OPTIONAL, object |
  | L1401 | `credential_metadata.display`: OPTIONAL, non-empty array |
  | L1412 | `credential_metadata.claims`: OPTIONAL, non-empty array |
  | L1423 | "The Wallet MUST ignore any unrecognized parameters" (Credential Issuer metadata) |
  | L2323 | claims description `path`: REQUIRED |
  | L2326 | claims description `mandatory`: OPTIONAL |
  | L2327 | `mandatory: true` — issuer will always include the claim |
  | L2331 | omitted `mandatory` defaults to `false` |
  | L2332 | claims description `display`: OPTIONAL, non-empty array |

- **`config.yaml` is NOT modified by this plan.** If you find yourself editing
  it, stop — you have misread the change.
- **Do not touch the EMVCo DPC `display` members** on `CredentialOffer` or
  `CredentialResponse`. They are a different structure with a different
  governing document. `crates/foundry/tests/wallet_issuance.rs:1156` and `:1225`
  assert them and must keep passing **unchanged**. A search-and-replace on the
  word `display` will break them; edit by hand.

---

## File Structure

| File | Responsibility after this plan |
| --- | --- |
| `crates/foundry-issuer/src/metadata.rs` | Owns the issuer-metadata wire model. Gains `CredentialMetadata`; `CredentialConfigurationSupported` carries `credential_metadata` instead of flat `display`/`claims`; `build_issuer_metadata` builds both |
| `crates/foundry-issuer/src/lib.rs` | Public re-export surface. Gains `CredentialMetadata` |
| `crates/foundry/src/openapi.rs` | utoipa document definitions. Registers `CredentialMetadata` as a component |
| `crates/foundry-issuer/tests/conformance_vci.rs` | Clause-by-clause conformance tests. `vci_0155_…` rewritten for the new shape |
| `openapi.json`, `openapi-wallet.json` | Generated artifacts, regenerated |
| `docs/conformance/openid4vc-conformance.md` | Living conformance record. Four new rows, two corrected evidence cells, updated summary counts |
| `crates/foundry-issuer/AGENTS.md` | Crate guide. Gains a Gotcha about the nesting |
| `docs/superpowers/changes/2026-08-24-credential-metadata-nesting.md` | Change record (new) |

**Why two tasks and not more.** Task 1 is compile-coupled and gate-coupled:
deleting the flat fields breaks `conformance_vci.rs`, and omitting the utoipa
registration makes `openapi_endpoints.rs`'s `assert_all_refs_resolve` fail on a
dangling `$ref`. Splitting any of it leaves the workspace red, so it cannot be
split without breaking the gate. Task 2 is documentation and generated
artifacts — a reviewer could reasonably reject it while approving Task 1.

---

### Task 1: Nest `credential_metadata` and correct the claims description objects

**Files:**

- Modify: `crates/foundry-issuer/src/metadata.rs` — struct at `:91-116`, claims
  build at `:208-218`, field assignment at `:304-305`, tests from `:952`
- Modify: `crates/foundry-issuer/src/lib.rs:40-44` — re-export list
- Modify: `crates/foundry/src/openapi.rs:58-60` — `components(schemas(..))`
- Modify: `crates/foundry-issuer/tests/conformance_vci.rs:2449-2461` — `vci_0155_…`
- Test: same files (`metadata.rs` has an inline `#[cfg(test)] mod`)

**Interfaces:**

- Consumes: `foundry_core::config::ClaimDef::is_required(&self) -> bool`
  (`crates/foundry-core/src/config/model.rs:563-565`, already `pub` and already
  used cross-crate by `create_offer.rs:151`). Returns
  `self.required.unwrap_or(!self.selectively_disclosable)`.
- Produces:
  - `pub struct CredentialMetadata { pub display: Vec<serde_json::Value>, pub claims: Vec<serde_json::Value> }`
  - `CredentialConfigurationSupported::credential_metadata: Option<CredentialMetadata>`
  - Both re-exported from the `foundry_issuer` crate root.
  - **Removed:** `CredentialConfigurationSupported::display` and
    `::claims`. Any code constructing that struct by literal must be updated.

---

- [ ] **Step 1: Read the two spec regions before writing anything**

Run:

```bash
sed -n '1400,1412p' docs/specs/openid-4-verifiable-credential-issuance-1_0.md
sed -n '2315,2340p' docs/specs/openid-4-verifiable-credential-issuance-1_0.md
```

You are implementing exactly what these two passages say. Do not infer the wire
format from the existing code — the existing code is the defect.

- [ ] **Step 2: Write the four failing tests**

Append these to the existing `#[cfg(test)] mod tests` in
`crates/foundry-issuer/src/metadata.rs`, after
`credential_configuration_display_carries_every_configured_locale`.

`ClaimDef` is already imported in that module (it is used by `test_config` at
`:441`), so no new `use` is needed.

```rust
    /// OpenID4VCI L1400-L1412: `display` and `claims` are members of a nested
    /// `credential_metadata` object, not flat siblings of `format`/`scope`.
    /// Until 2026-08-24 foundry emitted the flat, pre-1.0 draft shape, and
    /// L1423 ("The Wallet MUST ignore any unrecognized parameters") then
    /// obliged every conformant wallet to discard it.
    #[test]
    fn credential_metadata_nests_display_and_claims() {
        let cfg = test_config();
        let meta = build_issuer_metadata(&cfg, &[]);
        let value = serde_json::to_value(&meta).expect("metadata serialises");
        let pid = &value["credential_configurations_supported"]["pid"];

        assert_eq!(
            pid["credential_metadata"]["display"][0]["name"],
            "Person ID"
        );
        assert_eq!(
            pid["credential_metadata"]["claims"][0]["path"],
            serde_json::json!(["given_name"])
        );

        // The load-bearing half. A wallet is obliged to ignore the flat
        // members, so their presence is invisible to any positive assertion --
        // which is exactly how the original defect survived.
        assert!(
            pid.get("display").is_none(),
            "flat `display` is the pre-1.0 draft shape and must not be emitted"
        );
        assert!(
            pid.get("claims").is_none(),
            "flat `claims` is the pre-1.0 draft shape and must not be emitted"
        );
    }

    /// L1400 is OPTIONAL. A credential type with neither display nor claims
    /// must emit no `credential_metadata` key at all -- an empty object is not
    /// "information relevant to the usage and display of issued Credentials",
    /// and emitting one would trade this defect for a smaller one.
    #[test]
    fn credential_metadata_is_absent_when_neither_display_nor_claims_configured() {
        let mut cfg = test_config();
        cfg.credential_types[0].display = vec![];
        cfg.credential_types[0].claims = vec![];
        let meta = build_issuer_metadata(&cfg, &[]);
        let value = serde_json::to_value(&meta).expect("metadata serialises");
        let pid = &value["credential_configurations_supported"]["pid"];

        assert!(
            pid.get("credential_metadata").is_none(),
            "expected no credential_metadata key, got {:?}",
            pid.get("credential_metadata")
        );
    }

    /// L2321-L2338 defines a claims description object for Issuer Metadata as
    /// exactly `path`, `mandatory` and `display`. `selectively_disclosable` is
    /// a foundry config field name, never an OpenID4VCI parameter, and conveys
    /// nothing a wallet can use at either format.
    #[test]
    fn claims_description_emits_mandatory_and_not_selectively_disclosable() {
        let mut cfg = test_config();
        cfg.credential_types[0].claims = vec![
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
        ];
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let claims = &pid
            .credential_metadata
            .as_ref()
            .expect("claims are configured, so credential_metadata is present")
            .claims;

        // L2326/L2327: `mandatory` mirrors ClaimDef::is_required().
        assert_eq!(claims[0]["mandatory"], serde_json::json!(true));
        assert_eq!(claims[1]["mandatory"], serde_json::json!(false));

        for claim in claims {
            assert!(
                claim.get("selectively_disclosable").is_none(),
                "selectively_disclosable is not an OpenID4VCI claims-description \
                 parameter"
            );
        }
    }

    /// L2332: claims description `display` is "a non-empty array of objects"
    /// when present. The old `json!` macro had no `skip_serializing_if`, so a
    /// claim with no configured display emitted `"display": []`.
    #[test]
    fn claims_description_omits_display_when_none_configured() {
        let cfg = test_config();
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let claims = &pid
            .credential_metadata
            .as_ref()
            .expect("claims are configured, so credential_metadata is present")
            .claims;

        assert!(
            claims[0].get("display").is_none(),
            "expected no display member, got {:?}",
            claims[0].get("display")
        );
    }
```

- [ ] **Step 3: Update the one existing test that reads the flat path**

In the same module, `credential_configuration_display_carries_every_configured_locale`
currently reads `pid.display`. Replace the whole test **including its doc
comment** — the comment names the flat path and would otherwise document the
defect as the design:

```rust
    /// `display` is an opaque passthrough into
    /// `credential_configurations_supported[].credential_metadata.display`
    /// (OpenID4VCI L1401), so every configured locale entry must arrive intact,
    /// in order, with its members preserved. A wallet reads this array to
    /// render the credential, so silently dropping or reordering entries would
    /// be invisible here but visible on a device.
    #[test]
    fn credential_configuration_display_carries_every_configured_locale() {
        let mut cfg = test_config();
        cfg.credential_types[0].display = vec![
            serde_json::json!({"name": "Payment Card", "locale": "en-US"}),
            serde_json::json!({"name": "Zahlungskarte", "locale": "de-DE"}),
            serde_json::json!({"name": "Carte de paiement", "locale": "fr-FR"}),
        ];
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let display = &pid
            .credential_metadata
            .as_ref()
            .expect("display is configured, so credential_metadata is present")
            .display;

        let locales: Vec<&str> = display
            .iter()
            .filter_map(|d| d.get("locale").and_then(|l| l.as_str()))
            .collect();
        assert_eq!(locales, vec!["en-US", "de-DE", "fr-FR"]);
        assert_eq!(display[1]["name"], "Zahlungskarte");
    }
```

- [ ] **Step 4: Run the tests to verify they fail for the right reason**

Run:

```bash
cargo nextest run --workspace --no-fail-fast --status-level fail
```

Use the canonical workspace shape, not a scoped `-p foundry-issuer --lib` run:
root `AGENTS.md` §5.5 notes that every novel command shape mints a cargo cache
fingerprint that is never evicted, and that a scoped run is not faster under
nextest. At this step nothing compiles anyway, so any shape fails identically.

Expected: **compile error**, not a test failure. rustc will report a missing
field named `credential_metadata` on the `CredentialConfigurationSupported`
type (`E0609`), once per test that reads it.
That is the correct failure at this point: the tests describe a struct that does
not exist yet. If instead you see the tests compile and pass, you have edited
the implementation early — revert and redo Step 2.

- [ ] **Step 5: Add the `CredentialMetadata` struct**

In `crates/foundry-issuer/src/metadata.rs`, insert immediately **after** the
closing brace of `CredentialConfigurationSupported` (i.e. directly before
`#[derive(...)] pub struct ProofTypeSupported`):

```rust
/// OpenID4VCI L1400 — `credential_metadata`, the nested object carrying a
/// Credential Configuration's display and claims metadata.
///
/// Until 2026-08-24 foundry emitted `display` and `claims` as flat siblings of
/// `format`/`scope` — the pre-1.0 draft shape. A 1.0 wallet finds no
/// `credential_metadata`, and L1423 ("The Wallet MUST ignore any unrecognized
/// parameters") then obliges it to discard the flat copies, so the credential
/// arrives renderable but unrendered. For an `mso_mdoc` credential this is
/// total rather than partial: L1400 calls itself the fallback behind
/// format-specific mechanisms, but mdoc has none, so this object is the only
/// display channel that exists.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialMetadata {
    /// L1401: OPTIONAL, and "a non-empty array" when present — hence
    /// `skip_serializing_if` rather than an emitted `[]`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    /// L1412: OPTIONAL, and "a non-empty array" when present.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub claims: Vec<serde_json::Value>,
}
```

- [ ] **Step 6: Replace the two flat fields on `CredentialConfigurationSupported`**

Delete these six lines (`metadata.rs:110-115`):

```rust
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub claims: Vec<serde_json::Value>,
```

and put this in their place:

```rust
    /// L1400: OPTIONAL, so a credential type with neither display nor claims
    /// emits no key at all rather than `"credential_metadata": {}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<CredentialMetadata>,
```

- [ ] **Step 7: Rebuild the claims description objects**

In `build_issuer_metadata`, replace the whole `let claims: Vec<serde_json::Value> = ...`
statement (`metadata.rs:208-218`) with:

```rust
        // OpenID4VCI L2321-L2338 — a claims description object for Issuer
        // Metadata defines exactly `path`, `mandatory` and `display`. Built as
        // a map rather than with `json!` because `skip_serializing_if` does not
        // apply inside the macro: the old code emitted `"display": []` for
        // every claim without configured display, contradicting L2332's "a
        // non-empty array of objects".
        //
        // `selectively_disclosable` was never an OpenID4VCI parameter. It is a
        // foundry config field name, and conveys nothing a wallet can use: for
        // SD-JWT VC the wallet learns disclosability from the credential's own
        // disclosures, and for mdoc every IssuerSignedItem is inherently
        // selectively disclosable.
        let claims: Vec<serde_json::Value> = ct
            .claims
            .iter()
            .map(|c| {
                let mut claim = serde_json::Map::new();
                // L2323: REQUIRED.
                claim.insert("path".to_string(), serde_json::json!(c.path));
                // L2326/L2327: `mandatory` means "the Credential Issuer will
                // always include this claim in the issued Credential" -- which
                // is exactly `ClaimDef::is_required()`, the same predicate
                // `create_offer` uses to decide whether a value must be
                // supplied when an offer is created. Emitted unconditionally:
                // L2331 makes absence default to `false`, but the value is
                // always determinate here, so publishing it states the
                // issuer's intent instead of leaving it to a default.
                claim.insert(
                    "mandatory".to_string(),
                    serde_json::json!(c.is_required()),
                );
                // L2332: "A non-empty array of objects" -- omitted when empty.
                if !c.display.is_empty() {
                    claim.insert("display".to_string(), serde_json::json!(c.display));
                }
                serde_json::Value::Object(claim)
            })
            .collect();
```

- [ ] **Step 8: Populate the new field**

In the same function, replace these two lines (`metadata.rs:304-305`):

```rust
                display: ct.display.clone(),
                claims,
```

with:

```rust
                // L1400 is OPTIONAL: emit nothing when there is nothing to
                // say, rather than an empty object.
                credential_metadata: if ct.display.is_empty() && claims.is_empty() {
                    None
                } else {
                    Some(CredentialMetadata {
                        display: ct.display.clone(),
                        claims,
                    })
                },
```

Note the surrounding `CredentialIssuerMetadata { ... display: Vec::new(), ... }`
a few lines below is the **issuer-level** `display` (L1384) and is deliberately
left alone.

- [ ] **Step 9: Re-export the new type**

In `crates/foundry-issuer/src/lib.rs`, add `CredentialMetadata` to the
`pub use metadata::{...}` list at `:40`, keeping alphabetical order — between
`CredentialIssuerMetadata` and `CredentialRequestEncryption`:

```rust
pub use metadata::{
    AuthorizationServerMetadata, CredentialConfigurationSupported, CredentialIssuerMetadata,
    CredentialMetadata, CredentialRequestEncryption, CredentialResponseEncryption,
    CredentialSigningAlg, ProofTypeSupported, build_authorization_server_metadata,
    build_issuer_metadata,
};
```

`cargo fmt` will re-wrap; do not hand-tune the line breaks.

- [ ] **Step 10: Register the schema with utoipa**

In `crates/foundry/src/openapi.rs`, in the **second** `components(schemas(` block
(the wallet-facing document, at `:58`), add the new component immediately after
`foundry_issuer::CredentialConfigurationSupported,`:

```rust
        foundry_issuer::CredentialConfigurationSupported,
        // Registered explicitly for the same reason as `CredentialSigningAlg`
        // below: it is reachable only as the type of
        // `CredentialConfigurationSupported.credential_metadata`, and utoipa
        // emits a `$ref` to it there without pulling the component in. Omit it
        // and the spec ships a dangling reference, which
        // `openapi_endpoints.rs::assert_all_refs_resolve` fails on.
        foundry_issuer::CredentialMetadata,
```

Do **not** add it to the first `components(schemas(` block at `:15` — that is the
admin document, which does not reference `CredentialConfigurationSupported`.

- [ ] **Step 11: Rewrite the conformance test that pinned the non-spec key**

In `crates/foundry-issuer/tests/conformance_vci.rs`, replace the body of
`vci_0155_credential_configuration_claims_reveal_disclosed_paths` (`:2449-2461`).
Leave the `// VCI-0155 — …` banner comment above it as it is.

```rust
#[test]
fn vci_0155_credential_configuration_claims_reveal_disclosed_paths() {
    let cfg = test_config();
    let meta = build_issuer_metadata(&cfg, &[]);
    let pid = meta.credential_configurations_supported.get("pid").unwrap();
    // L1412: the claims description array is a member of `credential_metadata`,
    // not a flat sibling of `format`/`scope`.
    let claims = &pid
        .credential_metadata
        .as_ref()
        .expect("pid configures claims, so credential_metadata is present")
        .claims;

    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["path"], serde_json::json!(["given_name"]));
    // L2326 is the specification's own vehicle for telling the Authorization
    // Server whether a claim is always disclosed -- which is what this clause
    // asks for. `test_config`'s claim is selectively disclosable with no
    // explicit `required`, so `ClaimDef::is_required()` resolves to `false`.
    assert_eq!(claims[0]["mandatory"], serde_json::json!(false));
}
```

- [ ] **Step 12: Run the full gate**

Run:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Quote the `Summary [...]` line in your report.

If `openapi_endpoints.rs` fails with a dangling `$ref` for `CredentialMetadata`,
Step 10 was skipped or applied to the wrong `components` block.

If any test in `crates/foundry/tests/wallet_issuance.rs` fails, you have edited
the EMVCo DPC offer/response `display` members — revert that edit. They are a
different structure and are out of scope (see Global Constraints).

- [ ] **Step 13: Commit**

```bash
git add crates/foundry-issuer/src/metadata.rs crates/foundry-issuer/src/lib.rs \
        crates/foundry/src/openapi.rs crates/foundry-issuer/tests/conformance_vci.rs
git commit -m "fix(issuer): nest credential display/claims under credential_metadata

OpenID4VCI 1.0 L1400-L1412 places a Credential Configuration's display and
claims inside a nested credential_metadata object. foundry emitted them flat --
the pre-1.0 draft shape -- so L1423 obliged every conformant wallet to discard
them and credentials rendered unnamed and uncoloured. For mso_mdoc this was
total, not a fallback loss: mdoc has no format-specific display mechanism.

Also corrects the claims description objects, which are moving anyway:
- drop selectively_disclosable, never an OpenID4VCI parameter (L2321-L2338)
- emit mandatory from ClaimDef::is_required() (L2326)
- omit display instead of emitting [] (L2332)"
```

---

### Task 2: Regenerate the OpenAPI documents and update the conformance record

**Files:**

- Modify: `openapi.json` (generated)
- Modify: `openapi-wallet.json` (generated)
- Modify: `docs/conformance/openid4vc-conformance.md` — summary at `:138`,
  GAP-VCI-10 at `:150`, VCI-0155 at `:314`, new rows after `:395`
- Modify: `crates/foundry-issuer/AGENTS.md` — Gotchas section
- Create: `docs/superpowers/changes/2026-08-24-credential-metadata-nesting.md`

**Interfaces:**

- Consumes: `CredentialMetadata` and
  `CredentialConfigurationSupported.credential_metadata` from Task 1.
- Produces: no code interface. Documentation and generated artifacts only.

---

- [ ] **Step 1: Regenerate both OpenAPI documents**

Run:

```bash
cargo run -q -p foundry -- openapi --out openapi.json
cargo run -q -p foundry -- openapi --wallet --out openapi-wallet.json
```

- [ ] **Step 2: Verify the regenerated specs carry the new shape**

Run:

```bash
python3 -c "
import json
for f in ('openapi.json', 'openapi-wallet.json'):
    s = json.load(open(f))
    c = s.get('components', {}).get('schemas', {})
    cc = c.get('CredentialConfigurationSupported')
    if cc is None:
        print(f, '- CredentialConfigurationSupported absent (expected in openapi.json)')
        continue
    props = cc['properties']
    print(f, '- credential_metadata:', 'credential_metadata' in props)
    print(f, '- flat display gone:', 'display' not in props)
    print(f, '- flat claims gone:', 'claims' not in props)
    print(f, '- CredentialMetadata component:', 'CredentialMetadata' in c)
"
```

Expected: for whichever file defines `CredentialConfigurationSupported`, all four
lines report `True`. `openapi.json` is the admin document and may legitimately
not define it at all.

- [ ] **Step 3: Update the conformance summary counts**

In `docs/conformance/openid4vc-conformance.md:138`, four new `conforming`
clauses are being added, so replace:

```text
| OpenID4VCI | 235 | 100 | 17 | 58 | 6 | 54 | 0 | 0 |
```

with:

```text
| OpenID4VCI | 239 | 104 | 17 | 58 | 6 | 54 | 0 | 0 |
```

- [ ] **Step 4: Correct GAP-VCI-10's evidence**

The gap is *validation*, not *location*, so the verdict stays `gap` — only the
path it names stops being true. In the `GAP-VCI-10` row (`:150`), replace the
substring:

```text
into `CredentialConfigurationSupported.display` with no structural validation anywhere
```

with:

```text
into `CredentialConfigurationSupported.credential_metadata.display` (nested there since 2026-08-24) with no structural validation anywhere
```

Leave VCI-0181 and VCI-0182 alone: their evidence describes
`build_issuer_metadata` passing values through without naming the flat path, so
it remains accurate.

- [ ] **Step 5: Correct VCI-0155's evidence**

In the `VCI-0155` row (`:314`), replace the substring:

```text
`CredentialConfigurationSupported.claims` (metadata.rs) is always populated from `ct.claims`, carrying each claim's `path` and `selectively_disclosable` flag
```

with:

```text
`CredentialConfigurationSupported.credential_metadata.claims` (metadata.rs) is always populated from `ct.claims`, carrying each claim's `path` (L2323) and its `mandatory` flag (L2326), the latter derived from `ClaimDef::is_required()`. The non-spec `selectively_disclosable` member it previously carried was removed 2026-08-24
```

- [ ] **Step 6: Append the four new clause rows**

`:120-133` of the report states that identifiers are never renumbered and that
clauses discovered after initial extraction **append at the end of their spec's
inventory** rather than being inserted in spec-line order. VCI-0235 is currently
the highest, so these take VCI-0236 through VCI-0239 and go immediately after
the `VCI-0235` row at `:395`:

```text
| VCI-0236 | Credential Issuer Metadata (L1401) | Credential `display` is a member of the `credential_metadata` object | issuer | `conforming` | `CredentialConfigurationSupported.credential_metadata` (metadata.rs) is an `Option<CredentialMetadata>` whose `display` member carries `ct.display`. Before 2026-08-24 `display` was emitted flat, as a sibling of `format`/`scope` -- the pre-1.0 draft shape -- which L1423 obliged every conformant wallet to discard | credential_metadata_nests_display_and_claims, credential_configuration_display_carries_every_configured_locale |
| VCI-0237 | Credential Issuer Metadata (L1412) | `claims` is a member of the `credential_metadata` object | issuer | `conforming` | Same field as VCI-0236: the claims description array is `credential_metadata.claims`, not a flat sibling. `credential_metadata` itself is OPTIONAL (L1400), so it is omitted entirely -- never emitted as `{}` -- when a credential type configures neither display nor claims | credential_metadata_nests_display_and_claims, credential_metadata_is_absent_when_neither_display_nor_claims_configured, vci_0155_credential_configuration_claims_reveal_disclosed_paths |
| VCI-0238 | Claims Description / Issuer Metadata (L2326) | `mandatory`, when `true`, indicates the Credential Issuer will always include this claim | issuer | `conforming` | `build_issuer_metadata` (metadata.rs) emits `mandatory` from `ClaimDef::is_required()` (foundry-core/src/config/model.rs), the same predicate `create_offer` uses to require a value at offer creation -- so `true` means the claim is always supplied and therefore always present (L2327), and `false` means it appears only when the offer supplied one (L2328-L2331). Emitted unconditionally rather than omitted when `false`: the value is always determinate, so publishing it states the issuer's intent instead of relying on L2331's default | claims_description_emits_mandatory_and_not_selectively_disclosable |
| VCI-0239 | Claims Description / Issuer Metadata (L2332) | Claims description `display` is a non-empty array of objects when present | issuer | `conforming` | Each claims description object is built as a `serde_json::Map` rather than with the `json!` macro, so `display` is inserted only when `ClaimDef.display` is non-empty. The macro form previously used had no `skip_serializing_if` and emitted `"display": []` for every claim without configured display | claims_description_omits_display_when_none_configured |
```

- [ ] **Step 7: Add the crate Gotcha**

Append to the Gotchas section of `crates/foundry-issuer/AGENTS.md`:

```markdown
- **A Credential Configuration's `display` and `claims` live under
  `credential_metadata`, not flat.** OpenID4VCI L1400-L1412 nests both inside an
  OPTIONAL `credential_metadata` object. foundry emitted them flat until
  2026-08-24 — the pre-1.0 draft shape — and because L1423 obliges a wallet to
  ignore unrecognized parameters, conformant wallets silently discarded them and
  credentials rendered unnamed. There is no compatibility echo: the flat members
  were removed, not duplicated. Note `CredentialIssuerMetadata.display` (L1384)
  is a *different*, issuer-level field and is still flat and still hardcoded
  empty; so are the EMVCo DPC `display` members on `CredentialOffer` and
  `CredentialResponse`. Design:
  `docs/superpowers/specs/2026-08-24-credential-metadata-nesting-design.md`.
- **A claims description object has exactly `path`, `mandatory` and `display`**
  (L2321-L2338). `selectively_disclosable` is a config field name and must never
  reach the wire. `mandatory` comes from `ClaimDef::is_required()`.
```

- [ ] **Step 8: Write the change record**

Create `docs/superpowers/changes/2026-08-24-credential-metadata-nesting.md`:

```markdown
# Credential display and claims nested under `credential_metadata`

**Date:** 2026-08-24
**Design:** [`../specs/2026-08-24-credential-metadata-nesting-design.md`](../specs/2026-08-24-credential-metadata-nesting-design.md)

## What changed

`GET /.well-known/openid-credential-issuer` now emits each Credential
Configuration's `display` and `claims` inside a nested `credential_metadata`
object (OpenID4VCI 1.0 L1400-L1412) instead of as flat siblings of `format` and
`scope`. The flat members were removed, not duplicated.

Each claims description object now carries the specification's three members
(L2321-L2338): `path`, `mandatory` (from `ClaimDef::is_required()`, L2326) and
`display` (omitted rather than `[]` when unconfigured, L2332). The non-spec
`selectively_disclosable` member was removed.

## Why

An `eu.europa.ec.av.1` credential issued to a wallet built on
`eudi-lib-jvm-openid4vci-kt` v0.11.0 rendered with no name and a hash-derived
placeholder colour, despite `config.yaml` configuring two locales of display
metadata. The wallet was conformant: `CredentialMetadataTO` is the only reader of
those members, it is reached only via `@SerialName("credential_metadata")`, and
L1423 ("The Wallet MUST ignore any unrecognized parameters") obliged it to
discard foundry's flat copies. Nothing was logged on either side.

For `mso_mdoc` the loss was total rather than partial. L1400 describes itself as
the fallback behind format-specific display mechanisms, but mdoc has none — the
SD-JWT VC VCT document that sentence refers to has no mdoc equivalent — so
`credential_metadata.display` was the only channel that existed.

## Breaking change

Wallets implementing an OpenID4VCI draft (13/14) read the flat members and no
longer receive credential display metadata. This was accepted deliberately: the
flat shape never worked for any 1.0 wallet, so nothing that worked before
depended on it. A compatibility echo was rejected because a flat `display` has
no governing document to cite — "an old draft" is not a pinned spec in
`docs/specs/`, so the deviation comment §4.4 requires would have nothing to name.

## Conformance

Four new `conforming` rows: VCI-0236 (L1401), VCI-0237 (L1412), VCI-0238
(L2326), VCI-0239 (L2332). Corrected evidence on GAP-VCI-10 and VCI-0155, both
of which named the flat path.

GAP-VCI-10 remains **open**: `ct.display` is still untyped
`Vec<serde_json::Value>` and `Config::validate()` still performs no structural
validation of display objects. That untyped field is why the mis-nesting
survived — nobody had to think about the shape of a field with no shape — which
makes typing it the natural sequel to this change.
```

- [ ] **Step 9: Run the full gate**

Run:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Quote the `Summary [...]` line.

- [ ] **Step 10: Run the E2E suite**

Both OpenAPI documents changed, so per root `AGENTS.md` §5.2:

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

Expected: pass.

- [ ] **Step 11: Commit**

```bash
git add openapi.json openapi-wallet.json \
        docs/conformance/openid4vc-conformance.md \
        crates/foundry-issuer/AGENTS.md \
        docs/superpowers/changes/2026-08-24-credential-metadata-nesting.md
git commit -m "docs: record credential_metadata nesting in OpenAPI and conformance

Regenerates both OpenAPI documents for the new credential_metadata component.
Adds VCI-0236 (L1401), VCI-0237 (L1412), VCI-0238 (L2326) and VCI-0239 (L2332)
as conforming, and corrects GAP-VCI-10 and VCI-0155, which both named the
now-removed flat path. GAP-VCI-10 itself stays open -- the gap is structural
validation, not location."
```

---

## Verification Checklist

Before declaring the plan complete:

- [ ] `grep -rn "selectively_disclosable" crates/foundry-issuer/src/metadata.rs`
      returns nothing — the identifier is gone from the emission path.
- [ ] `grep -rn "credential_metadata" crates/ | wc -l` is non-zero — the
      parameter now exists in this repository.
- [ ] `crates/foundry/tests/wallet_issuance.rs` is **unmodified**
      (`git diff --stat` must not list it).
- [ ] `config.yaml` is **unmodified**.
- [ ] The `#[ignore]` on
      `vci_0150_0151_0152_0153_0154_credential_display_objects_are_not_structurally_validated`
      is still present — GAP-VCI-10 is deliberately not closed here.
