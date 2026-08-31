# Admin Console — PaSO Ad-Hoc Transaction Data Metadata

**Date:** 2026-08-31
**Spec:** none — bounded change, design agreed in chat (both the endpoint and the
console already existed; no new subsystem, no interface others depend on).

## What Changed

One source file, `crates/foundry/assets/console.html`, plus its test and two
manual pages. No server, verifier, or config change; no OpenAPI change, because
no endpoint changed.

`POST /admin/paso/ad-hoc-metadata` (PaSO Proof Metadata §5.2) had existed since
the signed-credential-metadata work but was reachable only by `curl` — the
console had zero occurrences of `ad-hoc`. The Verification card's existing
"Transaction data (optional)" disclosure now also mints the artifact:

- **Markup:** four controls in that disclosure — `credential_type_id`,
  `transaction_data_type`, an optional `metadata` override textarea, an optional
  `ttl_secs` — a "Mint ad-hoc metadata JWT" button, its own `error-banner`, and a
  `result` block showing the compact JWT (`uri-text` + the existing
  `data-copy-target` copy wiring) and its `exp`. No new CSS: every class is one
  the console already had.
- **Script:** `initPasoAdHocMetadata()`, `spliceAdHocMetadata()`, and
  `describeAdHocExpiry()`, wired into the existing `DOMContentLoaded` block.

## Why It Lives in the Transaction-Data Disclosure

§5.1 makes the ad-hoc metadata JWT a `metadata` member of a `transaction_data`
entry. The artifact has no other use, so a card of its own would have separated
the mint from the only field it feeds. This is also why the mint is not on the
Issuance card despite being an issuer-signed artifact on the issuer's endpoint.

## Why the Splice Is Keyed on `type`

On success the handler parses the `transaction_data` textarea and writes the JWT
to `metadata` on every entry whose `type` equals the minted
`transaction_data_type`, then rewrites the textarea pretty-printed.

That rule is the spec's, not a convenience. §5.2 requires the JWT's
`transaction_data_type` to equal the `type` of the enclosing entry, and §5.3
step 7 makes a Wallet reject the entry outright when they differ. Selecting by
that equality means the console structurally cannot hand a wallet a mismatched
pair — the failure mode a "splice into the first entry" shortcut would have
introduced.

Nothing is spliced silently. An empty, unparsable, non-array, or non-matching
textarea still shows the JWT for manual use and reports what was **not** spliced
and why — a silent no-op would read as success while sending an entry carrying
no metadata at all.

## Why Both Text Inputs Ship Empty

A mint is accepted only for a credential type declaring `transaction_data_types`
— the declaration that *makes* a type a PaSO Credential type (§3) — and the
shipped `config.yaml` declares none on any of `pid`,
`com.emvco.dpc.card`, `eu.europa.ec.av.1`. A prefilled default would therefore
be a value that always fails on the very instance serving the page, the same
reasoning that keeps the DPC display-metadata textareas empty. The `metadata`
override is what makes the control usable on such an instance: §5.4 lets an
override name a transaction data type the issuer has not configured, and a valid
ad-hoc JWT makes that type supported for the transaction it accompanies.

## Validation Split

The console checks shape only: both identifiers present, override parses as
JSON, `ttl_secs` is a positive integer. Everything semantic — the credential type
resolving, the type being configured absent an override, the override matching
§3.1/§3.2's structural rules — stays in `build_adhoc_metadata_jwt`, whose typed
errors surface through the existing `showError` banner with the server's detail.
`encode_transaction_data` clones each entry verbatim before base64url-encoding
it, so the spliced `metadata` member reaches the wallet untouched without any
verifier change.

## Tests

`crates/foundry/tests/console.rs::console_has_paso_adhoc_metadata_minting_for_verification`,
in the served-HTML-marker style of the sibling console tests: the four field ids,
the endpoint path, the copy target, the §5.2 type-equality selector, the
`metadata`-member write, the splice-report element, and the negative assertion
that `credential_type_id` ships without a `value`.
