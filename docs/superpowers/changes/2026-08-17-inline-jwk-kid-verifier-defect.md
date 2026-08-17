# Inline-Key JWS Verification: a JWK's `kid` Must Not Demand a Header `kid`

**Date:** 2026-08-17
**Trigger:** production failure — Google Wallet issuance rejected at `POST /token`
**Method:** `superpowers:systematic-debugging` (no design/plan doc; a defect, not a feature)

## Symptom

A live Google Wallet issuance attempt failed at the Token Endpoint:

```text
WARN ...:handle_token_request{grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code}:
     foundry_issuer::token: dpop proof rejected error.kind="invalid_dpop_proof"
WARN ...: foundry::server: request rejected surface="wallet"
     error.kind="invalid_dpop_proof"
     error.detail=invalid dpop proof: signature verification failed:
                  Invalid JWS format: The JWS kid header claim is required.
     http.status=400
```

## Root cause

Ours, not the wallet's. `josekit`'s `EcdsaJwsAlgorithm::verifier_from_jwk`
copies the JWK's own `kid` member into the *verifier*
(`josekit-0.10.3/src/jws/alg/ecdsa.rs:246`), and `decode_with_verifier` then
requires a matching `kid` on the **outer JWS header**
(`.../jws/jws_context.rs:439-445`), bailing with
`"The JWS kid header claim is required."` when there is none.

Google Wallet's DPoP proof embeds a `jwk` header carrying its own `kid` and —
correctly — puts no `kid` on the outer header. `dpop.rs` passed that JWK
straight to `verifier_from_jwk`, so foundry demanded a `kid` no specification
asks for.

RFC 9449 §4.2 (L407-409) defines the `jwk` header parameter as an RFC 7517 JWK,
where `kid` is an optional member (RFC 7517 §4.5); §4.3 check 6 (L500) requires
only that the signature "verifies with the public key contained in the `jwk`
JOSE Header Parameter". No check requires a header `kid`. **The wallet was
conformant and foundry was not.**

## Why it recurred

The identical defect had already been found and fixed **once**, in `proof.rs`,
which stripped the `kid` from a cloned JWK before building its verifier and
carried a regression test naming this exact error string. The fix was never
propagated to the three sibling call sites — so the same bug shipped three more
times and surfaced in production months later.

## What shipped

| Area | Change |
| --- | --- |
| `foundry-issuer/src/jose.rs` | **New**, crate-internal. `es256_verifier_from_inline_jwk` — builds the verifier, then `remove_key_id()`. Module docs carry the mechanism, the safety argument, and this history |
| `foundry-issuer/src/dpop.rs` | Routed through the helper — **the reported failure** |
| `foundry-issuer/src/attestation.rs` | Routed through the helper (Client Attestation PoP vs `cnf.jwk`) — latent |
| `foundry-issuer/src/encrypted_pre_auth.rs` | Routed through the helper (inner JWS vs the same `cnf.jwk`) — latent |
| `foundry-issuer/src/proof.rs` | Local clone-and-strip workaround replaced by the helper — behaviour unchanged |
| `foundry-issuer/tests/inline_jwk_verifier_hygiene.rs` | **New.** Structural guard: no production code in the crate may call `verifier_from_jwk` directly |
| `foundry-issuer/AGENTS.md` | Module-map row, a Gotchas entry stating the rule, corrected Tests section (it wrongly claimed the crate had no `tests/`) |

## Decisions

1. **A shared helper, not a fourth copy of the workaround.** Copy-paste is
   precisely how this reached production. One helper means the next inline-key
   call site inherits the fix instead of the bug.

2. **`verifier.remove_key_id()` rather than stripping `kid` from a cloned JWK.**
   Same outcome, no clone, no fallible `set_parameter`, and it leaves the
   caller's JWK intact — `proof.rs` hands the holder JWK onward with its `kid`.

3. **Dropping the `kid` weakens nothing.** The verifier is built from the exact
   key the message supplied and the signature is checked against it. A `kid`
   selects among candidate keys; with exactly one inline candidate it decides
   nothing. The removed comparison could only ever have agreed with the key
   already committed to, or spuriously rejected. A dedicated test asserts a
   signature from another key is still rejected even when the `kid`s match.

4. **Scoped to inline keys only.** A key looked up *by* `kid` from a set (a
   JWKS, the issuer's configured recipients) has a load-bearing label. The
   helper is named for the inline case and the guard's failure message spells
   out the distinction. Ruled out as unaffected: `attestation.rs:161/680`
   (`verifier_from_pem`), and `foundry-mdoc`, `foundry-sd-jwt-vc`,
   `foundry-core/status_list` — all call `verifier.verify(msg, sig)` directly,
   and the `kid` check exists only in `decode_with_verifier`.

5. **Enforced structurally rather than documented.** A Gotchas entry is what the
   previous fix effectively relied on, and it did not hold. The guard exempts
   `#[cfg(test)]` code, where several tests call `verifier_from_jwk` directly on
   purpose, and ships with a positive control so it cannot pass vacuously by
   scanning nothing. It was verified to fail against a deliberate violation.

## Verification

Each of the four sites has its own regression test; three were confirmed **red**
first, two reproducing the production error string verbatim.

Scoped gate (root `AGENTS.md` §5.1/§5.2 — `foundry-issuer` plus its dependent
`foundry`):

```bash
cargo test -p foundry-issuer -p foundry          # 29 binaries, 0 failed
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings   # clean
cargo fmt --check                                                        # clean
```

## Follow-up

Not verified against live Google Wallet — the fix is confirmed against tests
that reproduce the wallet's message shape. Re-run a real issuance to close it
out. If the flow now advances past `/token`, note that the wallet attestation is
currently `Disabled`; enabling it exercises the `attestation.rs` and
`encrypted_pre_auth.rs` sites fixed here, which had never run against Google's
`cnf.jwk` in production.
