# ISO/IEC 18013-5 — reference stub (mdoc CBOR internals)

> **This file is a reference stub, not the specification.** It exists under root
> [`AGENTS.md`](../../AGENTS.md) §4.4's external-reference rule, which applies when
> a governing document cannot be committed.

## Document identified

**ISO/IEC 18013-5:2021** — *Personal identification — ISO-compliant driving
licence — Part 5: Mobile driving licence (mDL) application.* First edition,
2021-09.

The clauses foundry depends on are §9.1.2 (issuer data authentication:
`IssuerSigned`, `IssuerSignedItem`, `MobileSecurityObject`, `ValidityInfo`) and
§9.1.3–§9.1.5 (mdoc authentication: `DeviceAuth`, `DeviceAuthentication`,
`SessionTranscript`).

## Why no copy is in-tree

ISO/IEC 18013-5 is a **paid standard**. ISO's licence forbids redistribution, so
no verbatim copy — partial or complete — may be committed to this repository.
Obtain it from ISO (<https://www.iso.org/standard/69084.html>) or a national
member body.

This is a stronger constraint than the one on
[`emvco-dpc-schema-framework.md`](emvco-dpc-schema-framework.md), which is
unpublished rather than paid, but the rule is the same: the interface facts below
are **restated, not quoted**, and the prose is not reproduced.

## Provenance of each fact below — read this before relying on any of them

Facts here fall into two classes, and the distinction is load-bearing:

- **Proven** — reproduced from a real wallet's presentation captured 2026-08-19,
  now committed as `crates/foundry-mdoc/tests/fixtures/av_device_response.b64`.
  A test asserts each one. If foundry's reading were wrong, that test fails.
- **Derived** — reconstructed from two independent open-source implementations at
  pinned commits, which agree byte-for-byte with each other:
  - `openwallet-foundation-labs/identity-credential` (multipaz, Kotlin) at
    `35bed72e20848a4bd8ec5c4bccece42021c9ee49`
  - `spruceid/isomdl` (Rust) at `fcb49d15ad9d54afa028a12183ee7fab1e46a5dc`

  Agreement between two implementations is strong evidence and is *not* proof.
  Both could share a misreading, and neither is normative.

**Neither status is the same as having read the standard.** Do not infer
unrecorded behaviour from this file — obtain the document. In particular, do not
extend a derived fact by analogy to a case the two implementations do not cover.

## Interface facts foundry relies on

### Issuer-signed data — **proven**

- `IssuerSignedItemBytes` = `#6.24(bstr .cbor IssuerSignedItem)`. Elements always
  travel tag-24 wrapped.
- `MobileSecurityObject.valueDigests` commits to the **full tag-24 encoding** of
  each `IssuerSignedItemBytes`, not to the inner `IssuerSignedItem` CBOR.
  Verified against the capture: SHA-256 over the tagged bytes reproduces the
  `valueDigests` entry; SHA-256 over the inner CBOR does not.
- `MobileSecurityObjectBytes` = `#6.24(bstr .cbor MobileSecurityObject)`, and this
  wrapped form is the `IssuerAuth` COSE_Sign1 **payload**. The signature is
  computed over the wrapped bytes.
- `ValidityInfo` members `signed`, `validFrom` and `validUntil` are each `tdate` —
  CBOR **tag 0** over an RFC 3339 text string. All three appear in the capture.
- `deviceKeyInfo.deviceKey` is a **COSE_Key map** (RFC 9052), not a byte string.
- `valueDigests` commits to every element the credential contains, disclosed or
  not; the capture commits to six and discloses one.

### mdoc authentication — **derived**

```cddl
DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)

DeviceAuthentication = [
    "DeviceAuthentication",   ; tstr
    SessionTranscript,        ; spliced in BY VALUE, untagged
    docType,                  ; tstr
    DeviceNameSpacesBytes     ; #6.24(bstr), copied verbatim from the wire
]
```

`DeviceAuthenticationBytes` is the **payload** slot of a detached-payload
COSE_Sign1 (`DeviceSignature`), whose `external_aad` is the empty byte string.
Detachment changes the wire structure — `payload` is absent — not the
`Sig_structure`.

Two hazards both reference implementations avoid, recorded because each is a
plausible-looking error:

- The `SessionTranscript` goes in **bare**. A tag-24 wrapping of the transcript
  does exist in multipaz, but only as a salt for MAC key derivation; it must not
  appear here.
- `DeviceNameSpacesBytes` is the **received bytes verbatim**. Decoding it to a map
  and re-encoding risks a different byte string under the signature. For a
  presentation disclosing nothing at device level it is `#6.24(bstr .cbor {})` =
  `d81841a0`.

### `DeviceResponse` envelope — **proven** (structure), from the capture

`version` (tstr, `"1.0"`), `documents` (array), `status` (uint, `0` = OK). Each
document carries `docType`, `issuerSigned`, `deviceSigned`; `deviceSigned` carries
`nameSpaces` and `deviceAuth`.

## Deliberately not covered here

- **`DeviceMac`** — the MAC alternative to `DeviceSignature` in `DeviceAuth`.
  foundry rejects it with a typed "unsupported"; HAIP mandates ES256 for this
  profile and a MAC additionally requires an ECDH agreement foundry never
  performs.
- **Multi-document `DeviceResponse`** — foundry rejects more than one document.
- **NFC/BLE device engagement, `DeviceEngagement`, `EReaderKey`** — foundry is
  reached over OpenID4VP only, where OpenID4VP pins both transcript elements to
  `null`.
- **MSO revocation mechanisms** (§9.1.2.7) — see `HAIP-0071` in the conformance
  register, recorded as out-of-scope.

## Precedence

Per §4.4's external-reference rule, this stub does **not** acquire the precedence
of a standards-track specification. Where it conflicts with
[`openid-4-verifiable-presentations-1_0.md`](openid-4-verifiable-presentations-1_0.md)
or [`openid4vc-high-assurance-interoperability-profile-1_0.md`](openid4vc-high-assurance-interoperability-profile-1_0.md),
the specification wins.

Treat this file as the record of *which* facts foundry was built against and how
strongly each is evidenced — never as a substitute for the standard.

## Related

- Design: [`../superpowers/specs/2026-08-19-mdoc-deviceresponse-verification-design.md`](../superpowers/specs/2026-08-19-mdoc-deviceresponse-verification-design.md)
- Fixture provenance and its deliberate coverage gaps:
  `crates/foundry-mdoc/tests/fixtures/README.md`
- Crate-level gotchas, including which facts are proven vs derived:
  [`../../crates/foundry-mdoc/AGENTS.md`](../../crates/foundry-mdoc/AGENTS.md)
