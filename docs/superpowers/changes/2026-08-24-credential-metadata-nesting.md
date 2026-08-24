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

## Note on the commit split

The plan assigned the OpenAPI regeneration to its second task, but
`openapi_endpoints.rs::committed_wallet_openapi_matches_generated` asserts the
committed `openapi-wallet.json` matches the generated spec. The new
`CredentialMetadata` component therefore had to land in the same commit as the
code, or that commit would have left the tree red — the same coupling the plan
cited as its reason for not splitting the code change further.
