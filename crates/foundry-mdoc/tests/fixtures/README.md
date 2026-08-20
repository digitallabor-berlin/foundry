# mdoc test fixtures

The three files here are **one capture**, taken together and only meaningful
together: a real wallet's presentation and the `SessionTranscript` candidates
foundry derived for that same transaction. Replacing one without the others
invalidates the device-signature tests.

## `av_device_response.b64`

A real ISO/IEC 18013-5 `DeviceResponse`, captured 2026-08-19 from a wallet
presenting an EU Age Verification attestation (`docType eu.europa.ec.av.1`) over
the OpenID4VP Digital Credentials API, in response to foundry's `av` named query.
Transaction `v_eca7bc0cbc514ee9aa61b2760e11182b`, response mode `dc_api`
(unencrypted, so the transcript's third `…HandoverInfo` element is CBOR `null`).

Base64url, no padding — exactly as it appeared in `vp_token["av"][0]`.

**Its `issuerAuth` carries `x5chain` as a bare byte string**, not an array. The
COSE unprotected header is a single-entry map, label 33, encoding to
`a1 1821 5902b2 …` — a 690-byte string. That is the encoding RFC 9360 §2
prescribes for a single certificate (`COSE_X509 = bstr / [ 2*certs: bstr ]`), and
it is precisely what foundry's extraction once rejected as `issuerAuth missing
x5c`. So this fixture held that counterexample from the day it landed; the tests
using it simply never reached x5c extraction. Keep new assertions here reaching at
least that deep.

**Its issuer chain does not validate here, by design.** The chain is
`[Test] mDL Reference Implementation DS` under
`[Test] mDL Reference Implementation IACA` — the OpenWallet Foundation Labs
`identity-credential` test PKI, which is not a foundry trust anchor — and the DS
certificate expired 2025-09-17. No test here asserts a full trust-validated
verification. Do not "fix" that by adding the anchor or relaxing expiry; see the
design doc §8.

## `av_session_transcript.hex` and `av_session_transcript_other_origin.hex`

Hex of the two candidate `SessionTranscript`s foundry derived for that
transaction — one per configured entry in `verifier.dc_api_expected_origins`, in
configuration order, lifted from the `SENSITIVE: candidate mdoc SessionTranscript`
records of the same request.

The **first** is the one the wallet actually signed over;
`the_real_device_signature_verifies_over_the_captured_session_transcript` proves
it. The second is kept deliberately: it is a transcript the wallet never signed,
and `the_other_origins_candidate_transcript_does_not_verify` uses it to rule out a
`DeviceAuthentication` assembly that passes while ignoring the transcript — the
exact defect design doc §1.5 recorded. Without that negative, the positive test
would be satisfiable by code that is still wrong.

## What this capture does and does not prove

**Proven, since 2026-08-19:** the whole `DeviceAuthentication` structure. A
signature check admits no partial credit — the tag-24 wrapping, the transcript
spliced in bare rather than tag-24 wrapped, the `docType`, the byte-preserved
`DeviceNameSpacesBytes`, the detached payload in the `Sig_structure` and the empty
`external_aad` are all confirmed against a third-party implementation at once.
This replaced two independent implementations *agreeing* as the basis for those
facts; see [`docs/specs/iso-18013-5-device-auth.md`](../../../../docs/specs/iso-18013-5-device-auth.md).

The device-signature test is **PKI-free**: `verify_device_auth` takes no trust
store, and the holder coordinates come from the MSO's `deviceKey`, so the
unanchored expired chain above is irrelevant to it. That is why this half is
provable from a capture and the issuer half is not.

**Still not proven here:** issuer-chain trust and MSO expiry policy (design doc
§8). The OpenID4VCI credential envelope on the issuance side (design doc §7) is
no longer among them: it was closed on 2026-08-20, and `build_mdoc` now returns
the bare `IssuerSigned` L2249 requires. That is guarded by
`build_mdoc_emits_a_bare_issuer_signed_not_a_device_response`, which — like this
fixture — asserts on bytes rather than on a round trip.

## Capturing a fresh pair

Both halves come from one run, and both are gated on payload logging
(`--log-sensitive` / `logging.sensitive_payloads: true`) **and** `trace`, per root
`AGENTS.md` §4.5. Run the server with:

```bash
RUST_LOG=info,foundry_verifier=trace foundry --log-sensitive serve --config config.yaml
```

Present a credential, then take two fields from the log — from the **same**
`tx_id`, because the transcript commits to that transaction's `nonce`:

| Log record | Field | What it is |
| --- | --- | --- |
| `SENSITIVE: decrypted response payload` | `decrypted_response` | JSON; the `DeviceResponse` is `vp_token.<query id>[0]`, base64url |
| `SENSITIVE: candidate mdoc SessionTranscript` | `session_transcript` | hex of the CBOR `SessionTranscript`, one record per configured Origin |

With several `dc_api_expected_origins` configured, only one candidate will verify
— keep them all and let the tests identify which.

The transcript record is emitted **before** issuer verification, so it appears
even when the presentation is rejected for an untrusted or expired issuer chain
(design doc §8) — which is the normal case for the wallets worth capturing. Do
not move that emission back into the candidate loop; see the Gotchas in
[`crates/foundry-verifier/AGENTS.md`](../../../foundry-verifier/AGENTS.md).

Design doc:
`docs/superpowers/specs/2026-08-19-mdoc-deviceresponse-verification-design.md`
