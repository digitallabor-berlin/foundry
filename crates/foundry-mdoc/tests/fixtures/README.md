# mdoc test fixtures

## `av_device_response.b64`

A real ISO/IEC 18013-5 `DeviceResponse`, captured 2026-08-19 from a wallet
presenting an EU Age Verification attestation (`docType eu.europa.ec.av.1`) over
the OpenID4VP Digital Credentials API, in response to foundry's `av` named query.

Base64url, no padding — exactly as it appeared in `vp_token["av"][0]`.

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
