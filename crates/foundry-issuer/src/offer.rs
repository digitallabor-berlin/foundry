//! Pre-authorized code / tx_code generation and `CredentialOffer` construction.

use crate::error::IssuanceError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::RngCore;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: CredentialOfferGrants,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialOfferGrants {
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    #[serde(
        rename = "authorization_code",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub authorization_code: Option<AuthorizationCodeGrant>,
}

/// The `authorization_code` grant member of a `CredentialOffer`'s `grants`
/// object. `issuer_state` lets the wallet round-trip an opaque value back to
/// `/authorize`, which resolves it to the pre-created `IssuanceTransaction`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuthorizationCodeGrant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCodeDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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

    fn pre_auth_offer() -> CredentialOffer {
        CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["pid".to_string()],
            grants: CredentialOfferGrants {
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "abc123".to_string(),
                    tx_code: Some(TxCodeDefinition {
                        input_mode: "numeric".to_string(),
                        length: 4,
                    }),
                }),
                authorization_code: None,
            },
        }
    }

    fn authorization_code_offer() -> CredentialOffer {
        CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["pid".to_string()],
            grants: CredentialOfferGrants {
                pre_authorized_code: None,
                authorization_code: Some(AuthorizationCodeGrant {
                    issuer_state: Some("issuer-state-abc".to_string()),
                }),
            },
        }
    }

    #[test]
    fn build_offer_uri_percent_encodes_and_uses_the_correct_scheme() {
        let offer = pre_auth_offer();
        let uri = build_offer_uri(&offer).unwrap();
        assert!(uri.starts_with("openid-credential-offer://?credential_offer="));
        // The raw JSON must not appear verbatim (braces/quotes are percent-encoded).
        assert!(!uri.contains('{'));
        assert!(!uri.contains('"'));
    }

    #[test]
    fn build_offer_uri_percent_encodes_authorization_code_offers_too() {
        let offer = authorization_code_offer();
        let uri = build_offer_uri(&offer).unwrap();
        assert!(uri.starts_with("openid-credential-offer://?credential_offer="));
    }

    #[test]
    fn credential_offer_round_trips_through_json() {
        let offer = pre_auth_offer();
        let json = serde_json::to_string(&offer).unwrap();
        let round_tripped: CredentialOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.credential_issuer, offer.credential_issuer);
        assert_eq!(
            round_tripped
                .grants
                .pre_authorized_code
                .unwrap()
                .pre_authorized_code,
            "abc123"
        );
    }

    #[test]
    fn pre_auth_offer_serializes_with_only_the_pre_authorized_code_grant_member() {
        let offer = pre_auth_offer();
        let json = serde_json::to_value(&offer).unwrap();
        let grants = json.get("grants").unwrap().as_object().unwrap();
        assert!(grants.contains_key("urn:ietf:params:oauth:grant-type:pre-authorized_code"));
        assert!(!grants.contains_key("authorization_code"));
    }

    #[test]
    fn authorization_code_offer_serializes_with_only_the_authorization_code_grant_member() {
        let offer = authorization_code_offer();
        let json = serde_json::to_value(&offer).unwrap();
        let grants = json.get("grants").unwrap().as_object().unwrap();
        assert!(!grants.contains_key("urn:ietf:params:oauth:grant-type:pre-authorized_code"));
        assert!(grants.contains_key("authorization_code"));
        assert_eq!(
            grants["authorization_code"]["issuer_state"],
            serde_json::json!("issuer-state-abc")
        );
    }

    #[test]
    fn authorization_code_grant_round_trips_through_json() {
        let grant = AuthorizationCodeGrant {
            issuer_state: Some("abc".to_string()),
        };
        let json = serde_json::to_string(&grant).unwrap();
        assert_eq!(json, r#"{"issuer_state":"abc"}"#);
        let round_tripped: AuthorizationCodeGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.issuer_state, Some("abc".to_string()));
    }
}
