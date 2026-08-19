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

Design doc:
`docs/superpowers/specs/2026-08-19-mdoc-deviceresponse-verification-design.md`
