# mdoc test fixtures

## `av_device_response.b64`

A real ISO/IEC 18013-5 `DeviceResponse`, captured 2026-08-19 from a wallet
presenting an EU Age Verification attestation (`docType eu.europa.ec.av.1`) over
the OpenID4VP Digital Credentials API, in response to foundry's `av` named query.

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
certificate expired 2025-09-17. Tests using this fixture therefore assert
**structure and digests only**, never a full trust-validated verification. Do not
"fix" that by adding the anchor or relaxing expiry; see the design doc §8.

**The device-signature half is not covered either.** The `SessionTranscript` the
wallet signed over commits to the transaction's `nonce`, which was never logged,
and the transaction has since aged out of storage
(`transaction_ttl_secs: 600`). Verifying this capture's `DeviceAuth` therefore
needs a *fresh* run captured together with its transcript. Until then
`DeviceAuthentication`'s structure rests on two independent implementations
agreeing, not on a real wallet's signature verifying here — see the design doc
§2.1 and §9.

## Capturing a fresh `DeviceResponse` + `SessionTranscript` pair

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
| `SENSITIVE: candidate mdoc SessionTranscript` | `session_transcript` | hex of the CBOR `SessionTranscript` |

With several `dc_api_expected_origins` configured there is one transcript record
per Origin, in configuration order, and only one of them will verify — try each.

The transcript record is emitted **before** issuer verification, so it appears
even when the presentation is rejected for an untrusted or expired issuer chain
(design doc §8) — which is the normal case for the wallets worth capturing. Do
not move that emission back into the candidate loop; see the Gotchas in
`crates/foundry-verifier/AGENTS.md`.

Design doc:
`docs/superpowers/specs/2026-08-19-mdoc-deviceresponse-verification-design.md`
