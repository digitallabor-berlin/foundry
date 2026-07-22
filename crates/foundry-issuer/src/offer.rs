//! Pre-authorized code / tx_code generation and `CredentialOffer` construction.

use crate::error::IssuanceError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::RngCore;
use serde::Serialize;

/// 32 bytes of CSPRNG entropy, URL-safe base64 (unpadded). Same idiom as
/// `foundry-sd-jwt-vc`'s `generate_salt`.
pub fn generate_pre_authorized_code() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::ThreadRng::default().fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

/// A numeric `tx_code` of `length` digits (HAIP default input_mode: numeric).
pub fn generate_tx_code(length: usize) -> String {
    let mut rng = rand::rngs::ThreadRng::default();
    (0..length)
        .map(|_| char::from(b'0' + (rng.next_u32() % 10) as u8))
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: CredentialOfferGrants,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialOfferGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: PreAuthorizedCodeGrant,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCodeDefinition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TxCodeDefinition {
    pub input_mode: String,
    pub length: usize,
}

/// Build a `credential_offer_uri` deep link (`openid-credential-offer://?credential_offer=...`)
/// with the offer JSON percent-encoded per RFC 3986.
pub fn build_offer_uri(offer: &CredentialOffer) -> Result<String, IssuanceError> {
    let json =
        serde_json::to_string(offer).map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    let encoded = utf8_percent_encode(&json, NON_ALPHANUMERIC).to_string();
    Ok(format!(
        "openid-credential-offer://?credential_offer={encoded}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_authorized_codes_are_random_and_nonempty() {
        let a = generate_pre_authorized_code();
        let b = generate_pre_authorized_code();
        assert_ne!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn tx_codes_have_the_requested_length_and_are_numeric() {
        let code = generate_tx_code(6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn build_offer_uri_percent_encodes_and_uses_the_correct_scheme() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["pid".to_string()],
            grants: CredentialOfferGrants {
                pre_authorized_code: PreAuthorizedCodeGrant {
                    pre_authorized_code: "abc123".to_string(),
                    tx_code: Some(TxCodeDefinition {
                        input_mode: "numeric".to_string(),
                        length: 4,
                    }),
                },
            },
        };
        let uri = build_offer_uri(&offer).unwrap();
        assert!(uri.starts_with("openid-credential-offer://?credential_offer="));
        // The raw JSON must not appear verbatim (braces/quotes are percent-encoded).
        assert!(!uri.contains('{'));
        assert!(!uri.contains('"'));
    }
}
