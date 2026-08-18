# 2026-08-18 — Accept OpenID4VP draft 24's `web-origin:` DC API audience (opt-in)

## Symptom

A real Google Wallet DPC (`com.emvco.dpc.card`, `dc+sd-jwt`) presented over the
Digital Credentials API failed at HTTP 400:

```text
verification failed: holder key binding verification failed: KB-JWT audience mismatch
```

`verifier.dc_api_expected_origins` was configured **correctly** and was live —
the ConfigMap and pod both predated the failing request — so this was not the
misconfiguration the README's "DC API Expected Origins" section describes.

## Root cause

The wallet signed:

```text
"aud": "web-origin:https://foundry-admin.digitallabor.dev"
```

The **Origin was right** — it was the first configured entry. Only the prefix
differed.

`web-origin:` is the **OpenID4VP draft 24** spelling. Draft 24, Appendix A.2:

> The `client_id` parameter MUST be omitted in unsigned requests […] The Wallet
> determines the effective Client Identifier from the Origin. The effective
> Client Identifier is composed of a synthetic Client Identifier Scheme of
> `web-origin` and the Origin itself. For example, an Origin of
> `https://verifier.example.com` would result in an effective Client Identifier
> of `web-origin:https://verifier.example.com`.

In draft 24 the KB-JWT `aud` was the Client Identifier, hence
`web-origin:<origin>`. OpenID4VP **1.0** renamed the prefix to `origin:`
(pinned spec L618, L2543). foundry implements 1.0 and had never known the string
`web-origin`.

Google Wallet advertises support for the `openid4vp-v1-unsigned` protocol the
console requests (`crates/foundry/assets/console.html`), then answers with a
draft-24 audience. That inconsistency is Google's; accommodating it is ours.

## Change

New `VerifierConfig.dc_api_accept_legacy_web_origin_audience: bool`
(`#[serde(default)]`, **default `false`**). When enabled,
`do_verify_vp_response` pushes `web-origin:<origin>` alongside `origin:<origin>`
for every entry of the DC API audience list (configured origins, or the
`public_base_url`-derived fallback).

### Why opt-in rather than unconditional

This repository keeps a clause-by-clause conformance record, and VP-0265 covers
exactly this clause. Accepting a superseded draft's audience **by default**
would convert a `conforming` verdict into a silent deviation for every
deployment. As a flag it is a recorded operator choice, which is what root
`AGENTS.md` §4.4 requires of a deliberate deviation.

### Why it is safe

The accommodation relaxes the **prefix**, never the Origin allow-list. The
origin half is still matched against `dc_api_expected_origins`, so no additional
Origin becomes acceptable and the audience-binding property L2543 exists to
provide is preserved. A dedicated test pins this
(`dc_api_legacy_web_origin_flag_still_enforces_the_origin_allow_list`).

### Observability

`do_verify_vp_response` emits a `warn` naming the audience each time a
presentation is accepted on the legacy prefix, so an operator can see when the
flag can be turned off again. The value is an Origin — a public identifier, not
a payload — so it is logged unconditionally under §4.5.

## Files

| File | Change |
| --- | --- |
| `crates/foundry-core/src/config/model.rs` | New `VerifierConfig` field + rationale doc comment |
| `crates/foundry-verifier/src/verify.rs` | `LEGACY_WEB_ORIGIN_PREFIX`; audience list built from a bare-origin list then prefixed; `warn` on legacy acceptance; 4 new tests |
| `crates/foundry/src/commands.rs` | Quickstart config template comment |
| `README.md` | New "Wallets Still on OpenID4VP draft 24 (`web-origin:`)" subsection |
| `crates/foundry-verifier/AGENTS.md` | Gotcha: two accepted spellings, only one on by default |
| `docs/conformance/openid4vc-conformance.md` | VP-0265 evidence + test list |
| 24 call sites | `dc_api_accept_legacy_web_origin_audience: false` added to `VerifierConfig` struct literals |

## Tests

- `dc_api_legacy_web_origin_audience_is_rejected_by_default` — strict 1.0 is the
  default posture even when the Origin is configured.
- `dc_api_legacy_web_origin_audience_accepted_when_flag_enabled` — the switch
  that unblocks a draft-24 wallet. **This is the test that reproduced the
  reported failure**, failing with the exact production message before the fix.
- `dc_api_legacy_web_origin_flag_still_enforces_the_origin_allow_list` — an
  unlisted Origin stays rejected under the flag.
- `dc_api_conformant_origin_audience_still_accepted_when_legacy_flag_enabled` —
  enabling the flag *adds* a spelling, it does not replace the conformant one.

## Known limitation

The mdoc DC API path binds the Origin **unprefixed** inside
`OpenID4VPDCAPIHandoverInfo` (L2997), so it is untouched by this change. Draft
24 used a different Handover structure, so an mdoc presented from a draft-24
wallet over the DC API is a separate, uninvestigated question.

## Follow-up

**Done, same day** — see
[`2026-08-18-kb-jwt-audience-mismatch-names-both-values.md`](2026-08-18-kb-jwt-audience-mismatch-names-both-values.md).
`FormatError::KeyBinding("KB-JWT audience mismatch")` discarded both compared
values, which is why diagnosing this one required enabling `--log-sensitive`
plus `trace` on a live pod to dump the whole decrypted `vp_token`. The message
now names the presented `aud` and the accepted list, so the next such mismatch
is a one-line read.
