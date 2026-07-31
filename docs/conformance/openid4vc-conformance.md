# OpenID4VC Conformance Report

**Status:** in progress
**Scope:** `foundry-issuer`, `foundry-verifier`, and the protocol HTTP routes in `crates/foundry/src/server.rs`

This is a **living document**. It is not a snapshot of one audit run: later work
that closes a gap edits the affected rows in place. Do not duplicate its
contents into a changelog or a run artifact — link to it instead.

Its internal consistency is enforced mechanically by
`crates/foundry/tests/conformance_report.rs`, which runs as part of
`cargo test --workspace`. Edits that break the cross-references below will fail
that test.

## Specifications Under Audit

The authoritative texts are the pinned copies in [`docs/specs/`](../specs/), per
[`AGENTS.md`](../../AGENTS.md) §4.4 — not any newer draft published elsewhere.

| Short name | File | Pinned version |
|---|---|---|
| OpenID4VCI | [`openid-4-verifiable-credential-issuance-1_0.md`](../specs/openid-4-verifiable-credential-issuance-1_0.md) | `openid-4-verifiable-credential-issuance-1_0-17` |
| OpenID4VP | [`openid-4-verifiable-presentations-1_0.md`](../specs/openid-4-verifiable-presentations-1_0.md) | `openid-4-verifiable-presentations-1_0-30` |
| HAIP | [`openid4vc-high-assurance-interoperability-profile-1_0.md`](../specs/openid4vc-high-assurance-interoperability-profile-1_0.md) | `openid4vc-high-assurance-interoperability-profile-1_0-06` |

Where HAIP is stricter than OpenID4VCI or OpenID4VP, **HAIP wins**.

## Audit Boundary

**In scope**

- `foundry-issuer`, all modules.
- `foundry-verifier`, all modules.
- The protocol routes in `crates/foundry/src/server.rs`: `/token`, `/authorize`,
  `/nonce`, `/credential`, `/vp/request/:id`, `/vp/response/:id`,
  `/statuslists/:id`, and the `.well-known` metadata routes.

**Clause selection.** Mandatory clauses only — MUST, MUST NOT, REQUIRED, SHALL,
SHALL NOT — over features foundry implements. Per `AGENTS.md` §4.4,
unimplemented *optional* features are acceptable and are recorded as
`not-implemented`. SHOULD and RECOMMENDED clauses may carry a verdict but are
not systematically inventoried.

**Out of scope**, recorded explicitly so that silence is never mistaken for a
pass:

| Area | Reason |
|---|---|
| `foundry-wallet` | Debug client, not part of the issuer/verifier surface |
| SD-JWT VC format internals (disclosure encoding, KB-JWT structure) | Defining spec (IETF SD-JWT VC) not vendored under §4.4 |
| mdoc format internals (CBOR structure, MSO layout) | Defining spec (ISO/IEC 18013-5) not vendored and not vendorable — paid standard |
| Token Status List bitstring encoding | Defining spec not vendored |
| Wallet-side and third-party obligations | Recorded with `Applies to = wallet` / `other` and verdict `out-of-scope` |

What *is* in scope for the credential formats is what the three vendored specs
say about their **usage**: which formats must be supported, required algorithms,
key binding requirements, and the profile's constraints on `vct` and doctype
handling. That a status check happens and is honoured is in scope; whether the
bitset is decoded correctly is not.

## Legend — Verdicts

| Verdict | Meaning |
|---|---|
| `conforming` | Implemented and correct; `Evidence` cites code, `Test` cites the proving test |
| `gap` | Implemented incorrectly, or mandatory and absent; has a row in the gap register |
| `not-implemented` | Optional feature foundry does not offer; permitted by `AGENTS.md` §4.4. Rationale required |
| `not-unit-testable` | Transport, deployment, or operational requirement. Rationale required |
| `out-of-scope` | Outside the audit boundary above. Rationale required |
| `ambiguous` | Examined, but genuinely readable two ways. Terminal — makes no conformance claim, does not block completion. Listed under Unresolved Ambiguities |
| `unverified` | Not yet adjudicated. The remaining-work marker; must be zero when the audit is complete |

## Legend — Severity

| Severity | Meaning |
|---|---|
| `Critical` | Accepts something it must reject — a forged, replayed, or unauthorized credential or presentation |
| `Important` | A conformant counterparty fails to interoperate |
| `Minor` | No functional consequence — wording, ordering, or a redundant field |

## Identifiers

Clause identifiers are `VCI-NNNN`, `VP-NNNN`, `HAIP-NNNN`, zero-padded to four
digits, sequential in document order within each spec. Gap identifiers are
`GAP-VCI-NN`, `GAP-VP-NN`, `GAP-HAIP-NN`, `GAP-HTTP-NN`.

**Identifiers are never renumbered.** They are cited by `#[ignore]` reason
strings, commit messages, and follow-up work.

## Summary

| Spec | Total | conforming | gap | not-implemented | not-unit-testable | out-of-scope | ambiguous | unverified |
|---|---|---|---|---|---|---|---|---|
| OpenID4VCI | 230 | 0 | 0 | 0 | 0 | 29 | 0 | 201 |
| OpenID4VP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| HAIP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Gap Register

| ID | Severity | Spec § | Requirement | Impact | Test |
|---|---|---|---|---|---|

## Clause Inventory — OpenID4VCI

| ID | § | Requirement | Applies to | Verdict | Evidence | Test |
|---|---|---|---|---|---|---|
| VCI-0001 | Overview / Core Concepts (L181) | Credentials batched in one response MUST share the same Credential Format and Credential Dataset | issuer | `unverified` |  |  |
| VCI-0002 | Overview / Core Concepts (L183) | To issue Credentials of differing Formats or Datasets, multiple requests MUST be sent to the Credential Endpoint | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0003 | Pre-Authorized Code Flow (L354) | Implementers MUST implement mitigations suitable to the use case against pre-authorized code theft | issuer | `unverified` |  |  |
| VCI-0004 | Credential Offer (L374) | `credential_offer` MUST NOT be present when `credential_offer_uri` is present | issuer | `unverified` |  |  |
| VCI-0005 | Credential Offer (L375) | `credential_offer_uri` MUST NOT be present when `credential_offer` is present | issuer | `unverified` |  |  |
| VCI-0006 | Credential Offer (L383) | `credential_issuer` is REQUIRED in the Credential Offer | issuer | `unverified` |  |  |
| VCI-0007 | Credential Offer (L384) | `credential_configuration_ids` is REQUIRED and MUST be a non-empty array of unique strings keyed into `credential_configurations_supported` | issuer | `unverified` |  |  |
| VCI-0008 | Credential Offer (L385) | Wallet MUST use the grant per its parameters; if `grants` is absent or empty the Wallet MUST determine grant types from metadata | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0009 | Credential Offer (L388) | Wallet MUST ignore unrecognized Credential Offer parameters | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0010 | Credential Offer (L393) | If `issuer_state` was received the Wallet MUST include it in the subsequent Authorization Request | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0011 | Credential Offer (L394) | `authorization_server` (authorization_code grant) MUST NOT be used unless metadata `authorization_servers` has multiple entries, and MUST match one of its values | issuer | `unverified` |  |  |
| VCI-0012 | Credential Offer (L396) | `pre-authorized_code` is REQUIRED and MUST be short lived and single use | issuer | `unverified` |  |  |
| VCI-0013 | Credential Offer (L396) | Wallet MUST include the `pre-authorized_code` value in the subsequent Token Request | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0014 | Credential Offer (L397) | If a `tx_code` object was present the Wallet MUST send the Transaction Code in the `tx_code` Token Request parameter | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0015 | Credential Offer (L400) | `tx_code.description` length MUST NOT exceed 300 characters | issuer | `unverified` |  |  |
| VCI-0016 | Credential Offer (L401) | `authorization_server` (pre-authorized_code grant) MUST NOT be used unless metadata has multiple entries, and MUST match one of its values | issuer | `unverified` |  |  |
| VCI-0017 | Credential Offer (L434) | Wallet MUST send an HTTP GET to `credential_offer_uri` to retrieve the Credential Offer Object | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0018 | Credential Offer (L445) | The response carrying a Credential Offer Object MUST use media type `application/json` | http | `unverified` |  |  |
| VCI-0019 | Credential Offer (L465) | Credential Offer retrieval MUST use `application/json` and MUST NOT use `application/jwt` with `alg: none` | http | `unverified` |  |  |
| VCI-0020 | Authorization Request (L489) | `authorization_details` MUST be used to convey the details of the Credentials requested | issuer | `unverified` |  |  |
| VCI-0021 | Authorization Request (L491) | `type` is REQUIRED and MUST be set to `openid_credential` | issuer | `unverified` |  |  |
| VCI-0022 | Authorization Request (L492) | `credential_configuration_id` is REQUIRED and MUST identify an entry in `credential_configurations_supported` | issuer | `unverified` |  |  |
| VCI-0023 | Authorization Request (L502) | If metadata contains `authorization_servers`, the authorization detail `locations` MUST be set to the Credential Issuer Identifier | issuer | `unverified` |  |  |
| VCI-0024 | Authorization Request (L541) | Credential Issuers MUST interpret each scope value as a request to access the Credential Endpoint for that Credential type | issuer | `unverified` |  |  |
| VCI-0025 | Authorization Request (L542) | Each scope occurrence MUST be interpreted individually | issuer | `unverified` |  |  |
| VCI-0026 | Authorization Request (L544) | Credential Issuers MUST ignore unknown scope values | issuer | `unverified` |  |  |
| VCI-0027 | Authorization Request (L562) | When both scope and `authorization_details` are present the Credential Issuer MUST interpret them individually | issuer | `unverified` |  |  |
| VCI-0028 | Authorization Request (L562) | When scope and `authorization_details` request the same Credential type the Issuer MUST follow the authorization details object | issuer | `unverified` |  |  |
| VCI-0029 | Authorization Request (L570) | The Credential Issuer MUST account for `issuer_state` not being guaranteed to originate from it | issuer | `unverified` |  |  |
| VCI-0030 | Authorization Request (L574) | The Authorization Server MUST ignore unrecognized Authorization Request parameters | issuer | `unverified` |  |  |
| VCI-0031 | Successful Authorization Response (L620) | Authorization Responses MUST be made as defined in RFC6749 | http | `unverified` |  |  |
| VCI-0032 | Authorization Error Response (L632) | The Authorization Error Response MUST be made as defined in RFC6749 | http | `unverified` |  |  |
| VCI-0033 | Token Request (L653) | `pre-authorized_code` MUST be present when `grant_type` is the pre-authorized code grant | issuer | `unverified` |  |  |
| VCI-0034 | Token Request (L654) | `tx_code` MUST be present if a `tx_code` object was present in the Credential Offer, including when empty | issuer | `unverified` |  |  |
| VCI-0035 | Token Request (L654) | `tx_code` MUST only be used when `grant_type` is the pre-authorized code grant | issuer | `unverified` |  |  |
| VCI-0036 | Token Request (L656) | Client identification/authentication MUST follow RFC6749 Sections 4.1.3 and 3.2.1 | issuer | `unverified` |  |  |
| VCI-0037 | Token Request (L660) | If the Token Request carries `authorization_details` of type `openid_credential` and metadata has `authorization_servers`, `locations` MUST contain the Credential Issuer identifier | issuer | `unverified` |  |  |
| VCI-0038 | Token Request (L668) | The Authorization Server MUST ignore unrecognized Token Request parameters | issuer | `unverified` |  |  |
| VCI-0039 | Successful Token Response (L715) | `authorization_details` is REQUIRED in the Token Response when it was used in the Authorization or Token Request | issuer | `unverified` |  |  |
| VCI-0040 | Successful Token Response (L716) | `credential_identifiers` is REQUIRED and MUST be a non-empty array of strings each identifying an issuable Credential Dataset | issuer | `unverified` |  |  |
| VCI-0041 | Successful Token Response (L716) | Wallet MUST use `credential_identifiers` together with the Access Token in subsequent Credential Requests | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0042 | Successful Token Response (L721) | Wallet MUST ignore unrecognized Token Response parameters | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0043 | Successful Token Response (L724) | Wallet MUST ignore unrecognized data fields in Token Response `authorization_details` | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0044 | Nonce Endpoint (L784) | A Credential Issuer that requires `c_nonce` values in proofs MUST offer a Nonce Endpoint | issuer | `unverified` |  |  |
| VCI-0045 | Nonce Response (L805) | `c_nonce` is REQUIRED in the Nonce Response | issuer | `unverified` |  |  |
| VCI-0046 | Nonce Response (L805) | New `c_nonce` challenge values MUST be unpredictable | issuer | `unverified` |  |  |
| VCI-0047 | Nonce Response (L807) | The Nonce Response MUST be uncacheable via a `Cache-Control: no-store` header | http | `unverified` |  |  |
| VCI-0048 | Credential Endpoint (L827) | Support for the Credential Endpoint is REQUIRED | issuer | `unverified` |  |  |
| VCI-0049 | Credential Endpoint (L829) | Communication with the Credential Endpoint MUST utilize TLS | http | `unverified` |  |  |
| VCI-0050 | Credential Request (L850) | `credential_identifier` is REQUIRED when authorization details of type `openid_credential` were returned, and MUST NOT be used otherwise | issuer | `unverified` |  |  |
| VCI-0051 | Credential Request (L850) | When `credential_identifier` is used, `credential_configuration_id` MUST NOT be present | issuer | `unverified` |  |  |
| VCI-0052 | Credential Request (L851) | `credential_configuration_id` is REQUIRED when `credential_identifiers` was not returned, and MUST NOT be used otherwise | issuer | `unverified` |  |  |
| VCI-0053 | Credential Request (L851) | The `credential_configurations_supported` entry MUST contain one of the scope values used in the Authorization Request | issuer | `unverified` |  |  |
| VCI-0054 | Credential Request (L854) | `credential_response_encryption.jwk` is REQUIRED when response encryption is requested | issuer | `unverified` |  |  |
| VCI-0055 | Credential Request (L855) | `credential_response_encryption.enc` is REQUIRED when response encryption is requested | issuer | `unverified` |  |  |
| VCI-0056 | Credential Request (L856) | If `zip` is absent, compression MUST NOT be used | issuer | `unverified` |  |  |
| VCI-0057 | Credential Request (L862) | Proofs MUST incorporate the Credential Issuer Identifier as audience and, if a Nonce Endpoint exists, a `c_nonce` | issuer | `unverified` |  |  |
| VCI-0058 | Credential Request (L864) | `proofs` MUST be present when `proof_types_supported` is present for the requested Credential | issuer | `unverified` |  |  |
| VCI-0059 | Credential Request (L869) | The Credential Issuer MUST ignore unrecognized Credential Request parameters | issuer | `unverified` |  |  |
| VCI-0060 | Credential Request (L871) | The Client MUST encrypt the request when `encryption_required` is true | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0061 | Credential Request (L873) | The Client MUST encode an encrypted Credential Request as a JWT per the encrypted-messages rules | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0062 | Credential Request (L875) | An unencrypted Credential Request MUST use media type `application/json` | http | `unverified` |  |  |
| VCI-0063 | Credential Request (L960) | Credential Request encryption MUST be used whenever `credential_response_encryption` is included, to prevent substitution | issuer | `unverified` |  |  |
| VCI-0064 | Credential Response (L966) | On immediate issuance the Credential Issuer MUST respond with HTTP 200 | http | `unverified` |  |  |
| VCI-0065 | Credential Response (L967) | On deferred issuance the Credential Issuer MUST return `transaction_id` and MUST use HTTP 202 | http | `unverified` |  |  |
| VCI-0066 | Credential Response (L969) | If encryption was requested the Credential Response MUST be encoded per the encrypted-messages rules | issuer | `unverified` |  |  |
| VCI-0067 | Credential Response (L971) | An unencrypted Credential Response MUST use media type `application/json` | http | `unverified` |  |  |
| VCI-0068 | Credential Response (L975) | `credentials` MUST NOT be used when `transaction_id` is present | issuer | `unverified` |  |  |
| VCI-0069 | Credential Response (L975) | The elements of the `credentials` array MUST be objects | issuer | `unverified` |  |  |
| VCI-0070 | Credential Response (L976) | `credential` is REQUIRED within each `credentials` element | issuer | `unverified` |  |  |
| VCI-0071 | Credential Response (L976) | Credential Formats expressed as binary data MUST be base64url-encoded and returned as a string | issuer | `unverified` |  |  |
| VCI-0072 | Credential Response (L977) | `transaction_id` MUST NOT be used when `credentials` is present | issuer | `unverified` |  |  |
| VCI-0073 | Credential Response (L977) | `transaction_id` MUST be invalidated once the Credential has been obtained | issuer | `unverified` |  |  |
| VCI-0074 | Credential Response (L978) | `interval` is REQUIRED when `transaction_id` is present and MUST NOT be used when `credentials` is present | issuer | `unverified` |  |  |
| VCI-0075 | Credential Response (L979) | `notification_id` MUST NOT be used when `credentials` is absent | issuer | `unverified` |  |  |
| VCI-0076 | Credential Response (L979) | Wallet MUST include `notification_id` in the Notification Request | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0077 | Credential Response (L981) | Wallet MUST ignore unrecognized Credential Response parameters | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0078 | Credential Error Response (L1041) | Payload-related errors MUST use the specific error codes of this section rather than generic `invalid_request` | issuer | `unverified` |  |  |
| VCI-0079 | Credential Error Response (L1043) | An unsupported Credential request MUST return HTTP 400 with content type `application/json` | http | `unverified` |  |  |
| VCI-0080 | Credential Error Response (L1045) | `error` is REQUIRED in the Credential Error Response | http | `unverified` |  |  |
| VCI-0081 | Credential Error Response (L1053) | `error_description` MUST be human-readable ASCII text | http | `unverified` |  |  |
| VCI-0082 | Credential Error Response (L1053) | `error_description` MUST NOT include characters outside %x20-21 / %x23-5B / %x5D-7E | http | `unverified` |  |  |
| VCI-0083 | Deferred Credential Endpoint (L1075) | Wallet MUST present an Access Token valid for the previously requested Credentials | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0084 | Deferred Credential Endpoint (L1077) | Communication with the Deferred Credential Endpoint MUST utilize TLS | http | `unverified` |  |  |
| VCI-0085 | Deferred Credential Request (L1085) | `transaction_id` is REQUIRED in the Deferred Credential Request | issuer | `unverified` |  |  |
| VCI-0086 | Deferred Credential Request (L1088) | The Credential Issuer MUST invalidate `transaction_id` once the Credential has been obtained | issuer | `unverified` |  |  |
| VCI-0087 | Deferred Credential Request (L1091) | The Credential Issuer MUST ignore unrecognized Deferred Credential Request parameters | issuer | `unverified` |  |  |
| VCI-0088 | Deferred Credential Request (L1093) | The Client MUST encrypt the deferred request when `encryption_required` is true | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0089 | Deferred Credential Request (L1095) | An encrypted Deferred Credential Request MUST be encoded as a JWT per the encrypted-messages rules | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0090 | Deferred Credential Request (L1097) | An unencrypted Deferred Credential Request MUST use media type `application/json` | http | `unverified` |  |  |
| VCI-0091 | Deferred Credential Request (L1112) | Deferred Credential Request encryption MUST be used whenever `credential_response_encryption` is included | issuer | `unverified` |  |  |
| VCI-0092 | Deferred Credential Response (L1118) | On success the Deferred Credential Response MUST use `credentials` and MUST respond with HTTP 200 | http | `unverified` |  |  |
| VCI-0093 | Deferred Credential Response (L1119) | When more time is needed the response MUST use `interval` and `transaction_id`, MUST use HTTP 202, and `transaction_id` MUST equal the request value | http | `unverified` |  |  |
| VCI-0094 | Deferred Credential Response (L1124) | Wallet MUST ignore unrecognized Deferred Credential Response parameters | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0095 | Deferred Credential Response (L1126) | If encryption was requested the Issuer MUST encode the deferred response accordingly and MUST use the newly provided encryption object | issuer | `unverified` |  |  |
| VCI-0096 | Deferred Credential Response (L1128) | An unencrypted Deferred Credential Response MUST use media type `application/json` | http | `unverified` |  |  |
| VCI-0097 | Encrypted Messages (L1186) | The contents of an encrypted message MUST be encoded as a JWT | issuer | `unverified` |  |  |
| VCI-0098 | Encrypted Messages (L1186) | The media type of an encrypted message MUST be set to `application/jwt` | http | `unverified` |  |  |
| VCI-0099 | Encrypted Messages (L1188) | The `alg` parameter MUST be present on the encryption key | issuer | `unverified` |  |  |
| VCI-0100 | Encrypted Messages (L1188) | The JWE `alg` algorithm used MUST equal the `alg` value of the chosen JWK | issuer | `unverified` |  |  |
| VCI-0101 | Encrypted Messages (L1188) | If the selected public key has a `kid`, the JWE MUST include the same `kid` header parameter | issuer | `unverified` |  |  |
| VCI-0102 | Notification Endpoint (L1200) | Wallet MUST present a valid Access Token to the Notification Endpoint | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0103 | Notification Endpoint (L1202) | A Credential Issuer requiring notification MUST ensure the Access Token is valid at the Notification Endpoint | issuer | `unverified` |  |  |
| VCI-0104 | Notification Endpoint (L1206) | Communication with the Notification Endpoint MUST utilize TLS | http | `unverified` |  |  |
| VCI-0105 | Notification Request (L1212) | `notification_id` is REQUIRED in the Notification Request | issuer | `unverified` |  |  |
| VCI-0106 | Notification Request (L1213) | `event` is REQUIRED and MUST be a case-sensitive string from the defined set | issuer | `unverified` |  |  |
| VCI-0107 | Notification Request (L1213) | Partial errors when issuing a batch MUST be treated as the overall issuance flow failing | issuer | `unverified` |  |  |
| VCI-0108 | Notification Request (L1214) | `event_description` MUST NOT include characters outside %x20-21 / %x23-5B / %x5D-7E | issuer | `unverified` |  |  |
| VCI-0109 | Notification Request (L1217) | The Credential Issuer MUST ignore unrecognized Notification Request parameters | issuer | `unverified` |  |  |
| VCI-0110 | Notification Response (L1250) | On success the Credential Issuer MUST respond with a 2xx HTTP status code | http | `unverified` |  |  |
| VCI-0111 | Notification Error Response (L1262) | An invalid `notification_id` MUST return HTTP 400 with content type `application/json` | http | `unverified` |  |  |
| VCI-0112 | Notification Error Response (L1264) | `error` is REQUIRED in the Notification Error Response | http | `unverified` |  |  |
| VCI-0113 | Client Metadata (L1292) | Wallet MUST ignore unrecognized Client Metadata parameters | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0114 | Credential Issuer Metadata (L1312) | Issuers publishing metadata MUST serve it at `/.well-known/openid-credential-issuer` inserted between host and path | http | `unverified` |  |  |
| VCI-0115 | Credential Issuer Metadata (L1316) | Communication with the Credential Issuer Metadata Endpoint MUST utilize TLS | http | `unverified` |  |  |
| VCI-0116 | Credential Issuer Metadata (L1318) | Wallet MUST fetch Credential Issuer Metadata using HTTP GET | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0117 | Credential Issuer Metadata (L1320) | The Credential Issuer MUST respond with HTTP 200 and the metadata parameters | http | `unverified` |  |  |
| VCI-0118 | Credential Issuer Metadata (L1325) | The Credential Issuer MUST support returning metadata unsigned as `application/json` | issuer | `unverified` |  |  |
| VCI-0119 | Credential Issuer Metadata (L1325) | The Credential Issuer MUST indicate the media type of returned metadata via the `Content-Type` header | http | `unverified` |  |  |
| VCI-0120 | Credential Issuer Metadata (L1332) | `Accept-Language` and `Content-Language` values MUST follow RFC3066 | http | `unverified` |  |  |
| VCI-0121 | Credential Issuer Metadata (L1344) | Signed metadata MUST be secured using a JWS | issuer | `unverified` |  |  |
| VCI-0122 | Credential Issuer Metadata (L1347) | Signed metadata `alg` is REQUIRED and MUST NOT be `none` or a symmetric algorithm | issuer | `unverified` |  |  |
| VCI-0123 | Credential Issuer Metadata (L1348) | Signed metadata `typ` is REQUIRED and MUST be `openidvci-issuer-metadata+jwt` | issuer | `unverified` |  |  |
| VCI-0124 | Credential Issuer Metadata (L1352) | Signed metadata `sub` is REQUIRED and MUST match the Credential Issuer Identifier | issuer | `unverified` |  |  |
| VCI-0125 | Credential Issuer Metadata (L1353) | Signed metadata `iat` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0126 | Credential Issuer Metadata (L1356) | All metadata parameters MUST appear as top-level claims in the JWS payload | issuer | `unverified` |  |  |
| VCI-0127 | Credential Issuer Metadata (L1358) | Wallet MUST establish trust in the signer of signed metadata, and MUST otherwise reject it | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0128 | Credential Issuer Metadata (L1366) | `credential_issuer` is REQUIRED and MUST be identical to the identifier used to build the well-known URL | issuer | `unverified` |  |  |
| VCI-0129 | Credential Issuer Metadata (L1367) | `authorization_servers`, when present, MUST be a non-empty array of Authorization Server identifiers | issuer | `unverified` |  |  |
| VCI-0130 | Credential Issuer Metadata (L1368) | `credential_endpoint` is REQUIRED and MUST use the `https` scheme | issuer | `unverified` |  |  |
| VCI-0131 | Credential Issuer Metadata (L1369) | `nonce_endpoint`, when present, MUST use the `https` scheme | issuer | `unverified` |  |  |
| VCI-0132 | Credential Issuer Metadata (L1370) | `deferred_credential_endpoint`, when present, MUST use the `https` scheme | issuer | `unverified` |  |  |
| VCI-0133 | Credential Issuer Metadata (L1371) | `notification_endpoint`, when present, MUST use the `https` scheme | issuer | `unverified` |  |  |
| VCI-0134 | Credential Issuer Metadata (L1373) | `credential_request_encryption.jwks` is REQUIRED and every JWK MUST carry a unique `kid` | issuer | `unverified` |  |  |
| VCI-0135 | Credential Issuer Metadata (L1374) | `credential_request_encryption.enc_values_supported` is REQUIRED and non-empty | issuer | `unverified` |  |  |
| VCI-0136 | Credential Issuer Metadata (L1376) | `credential_request_encryption.encryption_required` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0137 | Credential Issuer Metadata (L1378) | `credential_response_encryption.alg_values_supported` is REQUIRED and non-empty | issuer | `unverified` |  |  |
| VCI-0138 | Credential Issuer Metadata (L1379) | `credential_response_encryption.enc_values_supported` is REQUIRED and non-empty | issuer | `unverified` |  |  |
| VCI-0139 | Credential Issuer Metadata (L1381) | `credential_response_encryption.encryption_required` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0140 | Credential Issuer Metadata (L1383) | `batch_size` is REQUIRED and MUST be 2 or greater | issuer | `unverified` |  |  |
| VCI-0141 | Credential Issuer Metadata (L1386) | There MUST be only one issuer `display` object per language identifier | issuer | `unverified` |  |  |
| VCI-0142 | Credential Issuer Metadata (L1388) | Issuer logo `uri` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0143 | Credential Issuer Metadata (L1390) | `credential_configurations_supported` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0144 | Credential Issuer Metadata (L1391) | `format` is REQUIRED in each supported credential configuration | issuer | `unverified` |  |  |
| VCI-0145 | Credential Issuer Metadata (L1392) | The Authorization Server MUST be able to uniquely identify the Credential Issuer from the `scope` value | issuer | `unverified` |  |  |
| VCI-0146 | Credential Issuer Metadata (L1394) | `cryptographic_binding_methods_supported` MUST be present when Cryptographic Key Binding is required and omitted otherwise | issuer | `unverified` |  |  |
| VCI-0147 | Credential Issuer Metadata (L1395) | `proof_types_supported` MUST be present if `cryptographic_binding_methods_supported` is present and omitted otherwise | issuer | `unverified` |  |  |
| VCI-0148 | Credential Issuer Metadata (L1396) | `proof_signing_alg_values_supported` is REQUIRED and non-empty for each proof type | issuer | `unverified` |  |  |
| VCI-0149 | Credential Issuer Metadata (L1397) | `key_attestations_required` MUST NOT be present when key attestation is not required | issuer | `unverified` |  |  |
| VCI-0150 | Credential Issuer Metadata (L1402) | Credential display `name` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0151 | Credential Issuer Metadata (L1403) | There MUST be only one credential `display` object per language identifier | issuer | `unverified` |  |  |
| VCI-0152 | Credential Issuer Metadata (L1405) | Credential logo `uri` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0153 | Credential Issuer Metadata (L1409) | `background_image` MUST include a `uri` parameter | issuer | `unverified` |  |  |
| VCI-0154 | Credential Issuer Metadata (L1410) | `background_image.uri` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0155 | Credential Issuer Metadata (L1420) | The Authorization Server MUST be able to determine from Issuer metadata which claims the requested Credentials disclose | issuer | `unverified` |  |  |
| VCI-0156 | Credential Issuer Metadata (L1423) | Wallet MUST ignore unrecognized Credential Issuer Metadata parameters | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0157 | AS Metadata (L1441) | Wallet MUST ignore unrecognized Authorization Server Metadata parameters | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0158 | Security / Credential Offer (L1486) | Wallet MUST treat Credential Offer parameter values as untrustworthy | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0159 | Security / Credential Offer (L1488) | Wallet MUST NOT accept Credentials merely because a Credential Offer was used; all protocol steps MUST still be performed | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0160 | Security / Credential Offer (L1490) | The Credential Issuer MUST ensure release of privacy-sensitive data in a Credential Offer is legal | issuer | `unverified` |  |  |
| VCI-0161 | Security / TLS Requirements (L1522) | Implementations MUST follow BCP195 | http | `unverified` |  |  |
| VCI-0162 | Security / TLS Requirements (L1523) | A TLS server certificate check MUST be performed per RFC6125 whenever TLS is used | http | `unverified` |  |  |
| VCI-0163 | Security / Protecting the Access Token (L1527) | Long-lived Access Tokens MUST NOT be issued unless sender-constrained | issuer | `unverified` |  |  |
| VCI-0164 | Security / Protecting the Access Token (L1529) | Bearer Access Tokens stored by the Wallet MUST be stored securely | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0165 | Format Profile / jwt_vc_json (L2116) | With format `jwt_vc_json` the Offer, Authorization Details, Credential Request and Issuer metadata MUST NOT be processed using JSON-LD rules | issuer | `unverified` |  |  |
| VCI-0166 | Format Profile / jwt_vc_json (L2124) | `credential_definition` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0167 | Format Profile / jwt_vc_json (L2125) | `credential_definition.type` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0168 | Format Profile / jwt_vc_json (L2139) | The `credential` claim MUST be a JWT and MUST NOT be re-encoded | issuer | `unverified` |  |  |
| VCI-0169 | Format Profile / ldp_vc (L2155) | With format `ldp_vc` the Offer, Authorization Details, Credential Request and Issuer metadata MUST NOT be processed using JSON-LD rules | issuer | `unverified` |  |  |
| VCI-0170 | Format Profile / ldp_vc (L2167) | `credential_definition` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0171 | Format Profile / ldp_vc (L2168) | `credential_definition.@context` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0172 | Format Profile / ldp_vc (L2169) | `credential_definition.type` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0173 | Format Profile / ldp_vc (L2183) | The `credential` claim MUST be a JSON object and MUST NOT be re-encoded | issuer | `unverified` |  |  |
| VCI-0174 | Format Profile / jwt_vc_json-ld (L2195) | With format `jwt_vc_json-ld` the Offer, Authorization Details, Credential Request and Issuer metadata MUST NOT be processed using JSON-LD rules | issuer | `unverified` |  |  |
| VCI-0175 | Format Profile / mdoc (L2235) | `doctype` is REQUIRED and identifies the Credential type per ISO 18013-5 | issuer | `unverified` |  |  |
| VCI-0176 | Format Profile / mdoc (L2249) | The `credential` claim MUST be the base64url-encoded CBOR `IssuerSigned` structure | issuer | `unverified` |  |  |
| VCI-0177 | Format Profile / SD-JWT VC (L2270) | `vct` is REQUIRED and designates the Credential type | issuer | `unverified` |  |  |
| VCI-0178 | Format Profile / SD-JWT VC (L2284) | The `credential` claim MUST be an SD-JWT VC string and MUST NOT be re-encoded | issuer | `unverified` |  |  |
| VCI-0179 | Claims Description / Authorization Details (L2306) | `path` is REQUIRED and MUST be a non-empty array | issuer | `unverified` |  |  |
| VCI-0180 | Claims Description / Issuer Metadata (L2323) | `path` MUST be a non-empty array representing a claims path pointer | issuer | `unverified` |  |  |
| VCI-0181 | Claims Description / Issuer Metadata (L2338) | There MUST be only one claims display object per language identifier | issuer | `unverified` |  |  |
| VCI-0182 | Claims Description / Processing Rules (L2349) | Processing MUST be aborted when a claims description object cannot be resolved | issuer | `unverified` |  |  |
| VCI-0183 | Claims Path Pointer (L2366) | A claims path pointer MUST be a non-empty array of strings, nulls and integers | issuer | `unverified` |  |  |
| VCI-0184 | Key Attestation JWT (L2497) | `alg` is REQUIRED and MUST NOT be `none` or a symmetric algorithm | issuer | `unverified` |  |  |
| VCI-0185 | Key Attestation JWT (L2498) | `typ` is REQUIRED and MUST be `key-attestation+jwt` | issuer | `unverified` |  |  |
| VCI-0186 | Key Attestation JWT (L2503) | `iat` is REQUIRED | issuer | `unverified` |  |  |
| VCI-0187 | Key Attestation JWT (L2504) | `exp` MUST be present when the attestation is used with the `jwt` proof type | issuer | `unverified` |  |  |
| VCI-0188 | Key Attestation JWT (L2505) | `attested_keys` is REQUIRED and MUST be a non-empty array of JWKs from the same key storage component | issuer | `unverified` |  |  |
| VCI-0189 | Key Attestation JWT (L2512) | With the `jwt` proof type the Credential Issuer MUST validate that the proof JWT is signed by a key contained in the attestation | issuer | `unverified` |  |  |
| VCI-0190 | Attack Potential Resistance (L2544) | `iso_18045_high` MUST be used when resistant to attack potential High (VAN.5) | issuer | `unverified` |  |  |
| VCI-0191 | Attack Potential Resistance (L2545) | `iso_18045_moderate` MUST be used when resistant to attack potential Moderate (VAN.4) | issuer | `unverified` |  |  |
| VCI-0192 | Attack Potential Resistance (L2546) | `iso_18045_enhanced-basic` MUST be used when resistant to attack potential Enhanced-Basic (VAN.3) | issuer | `unverified` |  |  |
| VCI-0193 | Attack Potential Resistance (L2547) | `iso_18045_basic` MUST be used when resistant to attack potential Basic (VAN.2) | issuer | `unverified` |  |  |
| VCI-0194 | Attack Potential Resistance (L2549) | Specifications extending the resistance list MUST choose collision-resistant values | other | `out-of-scope` | Obligation falls on specification authors, not on an implementation |  |
| VCI-0195 | Wallet Attestation (L2600) | Wallet MUST generate a proof of possession per Client Attestation PoP JWT | wallet | `out-of-scope` | Obligation falls on the Wallet or a third party, not on foundry's issuer/verifier surface |  |
| VCI-0196 | Proof Types (L2610) | A `jwt` proof object MUST include a `jwt` parameter whose value is a non-empty array of JWTs | issuer | `unverified` |  |  |
| VCI-0197 | Proof Types (L2611) | A `di_vp` proof object MUST include a `di_vp` parameter whose value is a non-empty array of W3C Verifiable Presentations | issuer | `unverified` |  |  |
| VCI-0198 | Proof Types (L2612) | An `attestation` proof object MUST include an `attestation` parameter containing exactly one key attestation JWT | issuer | `unverified` |  |  |
| VCI-0199 | jwt Proof Type (L2625) | The proof JWT MUST contain the header and payload elements defined for the `jwt` proof type | issuer | `unverified` |  |  |
| VCI-0200 | jwt Proof Type (L2628) | Proof `alg` is REQUIRED and MUST NOT be `none` or a symmetric algorithm | issuer | `unverified` |  |  |
| VCI-0201 | jwt Proof Type (L2629) | Proof `typ` is REQUIRED and MUST be `openid4vci-proof+jwt` | issuer | `unverified` |  |  |
| VCI-0202 | jwt Proof Type (L2630) | `kid` MUST NOT be present if `jwk` or `x5c` is present | issuer | `unverified` |  |  |
| VCI-0203 | jwt Proof Type (L2631) | `jwk` MUST NOT be present if `kid` or `x5c` is present | issuer | `unverified` |  |  |
| VCI-0204 | jwt Proof Type (L2632) | `x5c` MUST NOT be present if `kid` or `jwk` is present | issuer | `unverified` |  |  |
| VCI-0205 | jwt Proof Type (L2633) | When a `c_nonce` was provided, the `nonce` claim in a header key attestation MUST be set to that `c_nonce` | issuer | `unverified` |  |  |
| VCI-0206 | jwt Proof Type (L2634) | When `trust_chain` is used for signature verification the `kid` header parameter MUST be present | issuer | `unverified` |  |  |
| VCI-0207 | jwt Proof Type (L2637) | `iss` MUST be the `client_id` of the Client, and MUST be omitted when the access token came from anonymous pre-authorized code access | issuer | `unverified` |  |  |
| VCI-0208 | jwt Proof Type (L2638) | `aud` is REQUIRED and MUST be the Credential Issuer Identifier | issuer | `unverified` |  |  |
| VCI-0209 | jwt Proof Type (L2639) | `iat` is REQUIRED and MUST be the time the key proof was issued | issuer | `unverified` |  |  |
| VCI-0210 | jwt Proof Type (L2640) | `nonce` MUST be present when the Issuer has a Nonce Endpoint and MUST carry the server-provided `c_nonce` | issuer | `unverified` |  |  |
| VCI-0211 | jwt Proof Type (L2642) | The Credential Issuer MUST validate that the proof JWT is signed by the key identified in the JOSE header via `kid`, `jwk` or `x5c` | issuer | `unverified` |  |  |
| VCI-0212 | jwt Proof Type (L2647) | The proof `alg`, and the `alg` of `key_attestation` and `trust_chain` when present, MUST match `proof_signing_alg_values_supported` | issuer | `unverified` |  |  |
| VCI-0213 | di_vp Proof Type (L2704) | A Data Integrity secured W3C VP used as key proof MUST contain the defined properties | issuer | `unverified` |  |  |
| VCI-0214 | di_vp Proof Type (L2706) | `holder`, when present, MUST equal the controller identifier of the `proof.verificationMethod` | issuer | `unverified` |  |  |
| VCI-0215 | di_vp Proof Type (L2707) | `proof` is REQUIRED and MUST be a Data Integrity Proof | issuer | `unverified` |  |  |
| VCI-0216 | di_vp Proof Type (L2708) | `cryptosuite` is REQUIRED and MUST match `proof_signing_alg_values_supported` | issuer | `unverified` |  |  |
| VCI-0217 | di_vp Proof Type (L2709) | `proofPurpose` is REQUIRED and MUST be `authentication` | issuer | `unverified` |  |  |
| VCI-0218 | di_vp Proof Type (L2710) | `domain` is REQUIRED and MUST be the Credential Issuer Identifier | issuer | `unverified` |  |  |
| VCI-0219 | di_vp Proof Type (L2711) | `challenge` is REQUIRED when a `c_nonce` was provided and MUST NOT be used otherwise | issuer | `unverified` |  |  |
| VCI-0220 | di_vp Proof Type (L2713) | The Credential Issuer MUST validate the W3C VP proof is signed with a key held by the Holder | issuer | `unverified` |  |  |
| VCI-0221 | di_vp Proof Type (L2715) | Additional properties not understood MUST be ignored | issuer | `unverified` |  |  |
| VCI-0222 | attestation Proof Type (L2756) | When the Issuer has a Nonce Endpoint the `c_nonce` MUST be provided in the key attestation `nonce` | issuer | `unverified` |  |  |
| VCI-0223 | attestation Proof Type (L2772) | The key attestation `alg` MUST match one of `proof_signing_alg_values_supported` | issuer | `unverified` |  |  |
| VCI-0224 | Verifying Proof (L2777) | All required claims for the proof type MUST be present | issuer | `unverified` |  |  |
| VCI-0225 | Verifying Proof (L2778) | The key proof MUST be explicitly typed using the header parameters defined for its proof type | issuer | `unverified` |  |  |
| VCI-0226 | Verifying Proof (L2779) | The `alg` header MUST indicate a registered asymmetric signature algorithm, MUST NOT be `none`, and MUST be supported and acceptable per local policy | issuer | `unverified` |  |  |
| VCI-0227 | Verifying Proof (L2780) | The signature on the key proof MUST verify with the public key in the header parameter | issuer | `unverified` |  |  |
| VCI-0228 | Verifying Proof (L2781) | The header parameter MUST NOT contain a private key | issuer | `unverified` |  |  |
| VCI-0229 | Verifying Proof (L2782) | When the server has a Nonce Endpoint the nonce in the key proof MUST match the server-provided `c_nonce` | issuer | `unverified` |  |  |
| VCI-0230 | Verifying Proof (L2783) | The key proof creation time MUST be within an acceptable window | issuer | `unverified` |  |  |

## Clause Inventory — OpenID4VP

| ID | § | Requirement | Applies to | Verdict | Evidence | Test |
|---|---|---|---|---|---|---|

## Clause Inventory — HAIP

| ID | § | Requirement | Applies to | Verdict | Evidence | Test |
|---|---|---|---|---|---|---|

## Unresolved Ambiguities

| ID | Spec § | Reading A | Reading B | Why it matters |
|---|---|---|---|---|