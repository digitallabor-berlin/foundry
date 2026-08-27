# Configuration Reference

`config.yaml` keys, and where each is explained in full. This page is an index —
the behavioural documentation lives on the linked pages.

Every key below appears in a configuration example on the page it links to. Keys
are grouped by their top-level section.

## Credential types

Entries under `credential_types:`. Each defines one Credential Configuration.

| Key | Documented in |
| --- | --- |
| `credential_types[].id` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].format` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].vct` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].doctype` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].scope` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].display` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].validity_seconds` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].claims[].path` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].claims[].required` | [Credential Types & Claims](../issuance/credential-types.md) |
| `credential_types[].transaction_data_types` | [PaSO Transaction Data](../issuance/paso-transaction-data.md) |

## Issuer

| Key | Documented in |
| --- | --- |
| `issuer.offer_by_reference` | [By-Reference Offers](../issuance/by-reference-offers.md) |
| `issuer.access_token_ttl_secs` | [Encrypted Pre-Authorized Code](../issuance/encrypted-pre-auth-code.md) |
| `issuer.wallet_attestation.mode` | [Wallet Attestation & ABCA](../issuance/wallet-attestation.md) |
| `issuer.wallet_attestation.trusted_anchors` | [Wallet Attestation & ABCA](../issuance/wallet-attestation.md) |
| `issuer.wallet_attestation.pop_max_age_secs` | [Wallet Attestation & ABCA](../issuance/wallet-attestation.md) |
| `issuer.wallet_attestation.challenge_mode` | [Wallet Attestation & ABCA](../issuance/wallet-attestation.md) |
| `issuer.key_attestation.trusted_anchors` | [Android Keystore Attestation](../issuance/android-keystore-attestation.md) |
| `issuer.key_attestation.android.mode` | [Android Keystore Attestation](../issuance/android-keystore-attestation.md) |
| `issuer.key_attestation.android.key_mint_security_level` | [Android Keystore Attestation](../issuance/android-keystore-attestation.md) |
| `issuer.dpop.mode` | [DPoP](../issuance/dpop.md) |
| `issuer.dpop.max_age_secs` | [DPoP](../issuance/dpop.md) |
| `issuer.dpop.nonce_mode` | [DPoP](../issuance/dpop.md) |
| `issuer.request_encryption.keys` | [Request & Response Encryption](../issuance/credential-encryption.md) |
| `issuer.request_encryption.enc_values_supported` | [Request & Response Encryption](../issuance/credential-encryption.md) |
| `issuer.request_encryption.encryption_required` | [Request & Response Encryption](../issuance/credential-encryption.md) |
| `issuer.response_encryption.enc_values_supported` | [Request & Response Encryption](../issuance/credential-encryption.md) |
| `issuer.response_encryption.encryption_required` | [Request & Response Encryption](../issuance/credential-encryption.md) |
| `issuer.encrypted_pre_authorized_code.mode` | [Encrypted Pre-Authorized Code](../issuance/encrypted-pre-auth-code.md) |
| `issuer.encrypted_pre_authorized_code.max_age_secs` | [Encrypted Pre-Authorized Code](../issuance/encrypted-pre-auth-code.md) |
| `issuer.paso_metadata.ttl_secs` | [PaSO Transaction Data](../issuance/paso-transaction-data.md) |
| `issuer.paso_metadata.adhoc_ttl_secs` | [PaSO Transaction Data](../issuance/paso-transaction-data.md) |

## Verifier

| Key | Documented in |
| --- | --- |
| `verifier.dc_api_expected_origins` | [DC API Expected Origins](../verification/dc-api-origins.md) |
| `verifier.dc_api_accept_legacy_web_origin_audience` | [Admin Test Console](../operating/test-console.md) |

## Logging

| Key | Documented in |
| --- | --- |
| `logging.level` | [Logging](../operating/logging.md) |
| `logging.format` | [Logging](../operating/logging.md) |
| `logging.sensitive_payloads` | [Logging](../operating/logging.md) |

The field names those records carry are listed in
[Log Fields](log-fields.md).
