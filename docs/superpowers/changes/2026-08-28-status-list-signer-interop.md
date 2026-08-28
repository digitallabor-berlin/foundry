# Status List Token signer must match the credential signer

**Date:** 2026-08-28
**Amends:** [`../specs/2026-08-28-explicit-credential-signing-key-design.md`](../specs/2026-08-28-explicit-credential-signing-key-design.md)

## Symptom

Issuance to the Paradym wallet against `foundry.digitallabor.dev` failed after
the credential was received and its own signature checked:

```text
CredoError: Failed to validate sd-jwt-vc credentials.
SLException: Status List JWT verification failed: Verify Error: Invalid JWT Signature
```

## Root cause

Not a defect in the Status List Token. Fetching
`https://foundry.digitallabor.dev/statuslists/1` and verifying it independently:

| Property | Value |
| --- | --- |
| header | `{"alg":"ES256","typ":"statuslist+jwt","x5c":[1 cert]}` |
| `x5c` leaf | `CN=Foundry statuslist_signer`, CA-signed, no trust anchor in the chain |
| signature | **valid** against that leaf; 64-byte raw R‖S |
| payload | `sub` equal to the referencing `uri`, `iat`, `exp` |

That satisfies `draft-ietf-oauth-status-list-14` §5.1 and HAIP L327. The absent
`iss` claim is not a defect — §5.1 defines no `iss`.

The wallet was verifying it against the wrong key. In `@sd-jwt/sd-jwt-vc`,
`SDJwtVcInstance.verifyStatus()` resolves
`this.userConfig.statusVerifier ?? this.userConfig.verifier`, and Credo 0.5.x —
what Paradym ships — sets only `verifier`, built from the **credential issuer's**
key. The Status List Token's own header is never decoded. The throw site is
`@sd-jwt/core` `jwt.ts:282`, `if (!verified) throw new SDJWTException('Verify
Error: Invalid JWT Signature')` — the verifier *returned false*, so a key was
resolved and the ECDSA check failed. Key mismatch, not key-resolution failure.

The keys diverged earlier the same day. Commit `d9cf716` added
`issuer.credential_signing_key`; the deployment then set it to `issuer_sdjwt`
while `issuer.status_list.signing_key` stayed `statuslist_signer`. Before that,
one key signed both and status checks worked — accidentally. The design record
for `d9cf716` explicitly rejected pointing `status_list.signing_key` at
`issuer_sdjwt` on hygiene grounds, and scoped the operator's re-key out; neither
document knew that key separation is fatal to the Credo wallet stack.

**There is no configuration in which the two trust roles are separate and
Paradym works.** One key must sign both until Credo ships its `statusVerifier`
path (present on `main`, unreleased) *and* wallets configure a dedicated trusted
status certificate.

## What changed

| File | Change |
| --- | --- |
| `docs/specs/draft-ietf-oauth-status-list-14.txt` | **new** — the governing draft, vendored verbatim (revision 14, 10 Dec 2025). It was previously cited by pinned revision throughout `foundry-core` but absent from the tree, so nothing pinned the text the code was built against |
| `AGENTS.md` | §4.4 row for the vendored draft: what it governs, where HAIP L327 is stricter, and the interop constraint |
| `crates/foundry-core/src/config/validate.rs` | `Config::status_list_signer_divergence()` + a `tracing::warn!` from `Config::validate()`; 6 tests |
| `crates/foundry-core/AGENTS.md` | Gotcha recording the constraint and why it stays a warning |
| `crates/foundry/src/commands.rs` | `quickstart` template now points `status_list.signing_key` at `issuer_sdjwt` — it previously generated the exact broken pairing, so every new deployment inherited this bug |
| `docs/manual/operating/keys-and-certificates.md` | "Which key signs what" no longer advises three distinct keys; new subsection with the symptom text and the reasoning |
| `docs/superpowers/specs/2026-08-28-explicit-credential-signing-key-design.md` | amendment retracting the "Rejected alternative" reasoning |

The guard **warns and does not reject**: §11.3 mandates no key-resolution method
and §13.5 permits a wholly separate Status Issuer, so the configuration is legal
and a hard failure would be foundry overriding the spec on a wallet's behalf. It
compares resolved key *material* rather than config labels, so two `keys:` names
for one PEM stay silent.

## Deployment

`dl-infra-k8s/foundry/foundry_config.yml` sets
`issuer.status_list.signing_key: issuer_sdjwt`, matching
`issuer.credential_signing_key`. `statuslist_signer` stays defined and unused.
Already-issued credentials are unaffected — their `status` claims point at a list
whose token is now signed by the key those credentials name in their own `x5c`,
which is precisely what makes them verifiable again.

## Follow-up, not done here

- `GET /statuslists/:id?time=…` returns 200 with the *current* list. §8.4 says a
  server not supporting historical resolution SHOULD return 501, or 406 for an
  unsupported instant, and that a client MUST reject a token whose validity
  window excludes the requested time. Answering a historical query with
  present-day data is a silent wrong answer.
- `ttl` is never emitted; §5.1 and §13.7 RECOMMEND it alongside `exp`, and it is
  the claim that lets a wallet cache correctly.
- Neither is a regression from this change, and both belong in
  `docs/conformance/openid4vc-conformance.md` as gap rows.

## Verification

See the session's gate run.
