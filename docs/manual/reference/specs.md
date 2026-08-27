# Specifications

The documents foundry implements. All behaviour — wire formats, parameter names,
error codes, metadata fields, signing and encryption algorithms, and state
transitions — is meant to align with them.

These files live in `docs/specs/`, which is excluded from this site, so every
link below points at the copy in the repository.

## Standards-track specifications

| Document | Governs |
| --- | --- |
| [`openid-4-verifiable-credential-issuance-1_0.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/openid-4-verifiable-credential-issuance-1_0.md) | OpenID4VCI — `foundry-issuer` and the issuer HTTP routes (offers, pre-auth codes, `/token`, `/nonce`, `/credential`, holder proofs, issuer metadata) |
| [`openid-4-verifiable-presentations-1_0.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/openid-4-verifiable-presentations-1_0.md) | OpenID4VP — `foundry-verifier` and the verifier HTTP routes (authorization/request objects, `vp_token`, response modes, JARM/JWE, DCQL, client ID schemes) |
| [`openid4vc-high-assurance-interoperability-profile-1_0.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md) | HAIP — the profile that narrows both of the above (mandated SD-JWT VC / mdoc formats, required algorithms, key binding, trust mechanisms). Where HAIP is stricter, **HAIP wins.** |
| [`draft-ietf-oauth-attestation-based-client-auth-07.txt`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/draft-ietf-oauth-attestation-based-client-auth-07.txt) | ABCA — the Client Attestation JWT and Client Attestation PoP JWT formats OpenID4VCI's Wallet Attestation section incorporates by reference; `foundry-issuer`'s `attestation.rs` and the `/token` route. Where OpenID4VCI defers to ABCA, ABCA governs. |
| [`rfc9449-dpop.txt`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/rfc9449-dpop.txt) | DPoP — the sender-constrained access token mechanism HAIP OpenID4VCI mandates by reference; `foundry-issuer`'s `dpop.rs`, the `/token` route and the `/credential` route. Where HAIP defers to RFC 9449, RFC 9449 governs. |
| [`eu-age-verification-annex-a-av-profile.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/eu-age-verification-annex-a-av-profile.md) | EU Age Verification Solution Technical Specification, **Annex A (normative), "Age Verification Profile"** — the `eu.europa.ec.av.1` Proof of Age attestation: its doctype, its namespace, and its closed two-attribute set. Authority is **scoped to that one doctype**; where it is stricter than ISO 18013-5 for it, this profile wins. Pinned to release 1.0.9; Annex A only. |
| [`paso-core.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/paso-core.md) | PaSO (Payments and SCA for OpenID) Core — the transaction data model foundry publishes metadata for: the `payload` parameter on an OpenID4VP `transaction_data` entry, and the `urn:paso:sca:<domain>:<suffix>:<version>` transaction data type identifier grammar that `Config::validate()` enforces. **Scope note:** foundry implements the Attestation Provider role only. |
| [`paso-proof-metadata.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/paso-proof-metadata.md) | PaSO Proof: Metadata Module — the `credential_metadata_uri` extension to OpenID4VCI Credential Issuer Metadata, the `transaction_data_types` structure, the signed credential metadata JWT `credential-metadata+jwt`, and the ad-hoc `adhoc-transaction-metadata+jwt`. **Unimplemented optional path:** the `kid`/key-set signing branch — foundry takes the `x5c` branch only. |

These are **pinned drafts**. The checked-in copy is the source of truth for this
repository, not a newer draft found online.

## Vendor profile

A vendor profile records one implementation's observable behaviour and
requirements. It is normative **only** for what foundry does when accommodating
that implementation. It is **never** grounds for violating a MUST in a
standards-track specification above; where the two conflict, the specification
wins and the conflict is recorded as a known limitation.

| Document | Governs |
| --- | --- |
| [`google-wallet-openid4vci-profile.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/google-wallet-openid4vci-profile.md) | Google Wallet's OpenID4VCI implementation — the choices it makes where the specifications permit several, and the two places it expects behaviour no specification defines (a `DPoP-Nonce` header on the ABCA challenge response and on the OpenID4VCI Nonce Endpoint response). Also the source of the real Android Keystore attestation chains used as interop fixtures. |

## External references

Where a governing document cannot be committed — because its licence forbids
redistribution, or because it is unpublished — the file in `docs/specs/` is a
**reference stub**, not the specification. A stub records which revision the
code was built against; it is never a substitute for the text, and unrecorded
behaviour must not be inferred from it. A stub does **not** acquire the
precedence of a standards-track specification.

| Document | Governs |
| --- | --- |
| [`emvco-dpc-schema-framework.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/emvco-dpc-schema-framework.md) | EMV® Digital Payment Credential Specification — Schema Framework (v1.0, DRAFT Associate Review 2). Governs the shape of the `com.emvco.dpc.card` credential type only: its `vct`, and its three disclosable claims with their types and inclusion requirements. The document is all-rights-reserved and unpublished, so no verbatim copy is committed. |
| [`iso-18013-5-device-auth.md`](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/iso-18013-5-device-auth.md) | ISO/IEC 18013-5:2021 — the mdoc CBOR internals `foundry-mdoc` builds and verifies. ISO 18013-5 is a paid standard whose licence forbids redistribution. The stub marks each recorded fact **proven** (reproduced from a captured real presentation) or **derived** (reconstructed from two independent implementations at pinned commits, which agree). Neither status equals having read the standard. |

## Conformance

The clause-by-clause record of where foundry stands against OpenID4VCI,
OpenID4VP and HAIP — verdicts, evidence, and the register of known gaps — is the
[Conformance Report](../../conformance/openid4vc-conformance.md). How the suites
that back it are run is on
[Conformance Suite](../development/conformance-suite.md).
