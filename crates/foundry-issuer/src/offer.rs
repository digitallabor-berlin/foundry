//! Pre-authorized code / tx_code generation and `CredentialOffer` construction.

use crate::error::IssuanceError;
use crate::metadata::{build_authorization_server_metadata, build_issuer_metadata};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use foundry_core::config::Config;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
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
    /// EMVCo DPC display metadata (`com.emvco.dpc.card.meta`), carried per the
    /// Schema Framework A.5 "Protocol Alignment" proposal.
    ///
    /// **OpenID4VCI 1.0 defines no `display` member on a Credential Offer.**
    /// This is a deliberate, documented divergence justified only by an
    /// external-reference document (root AGENTS.md §4.4) and confined by
    /// `create_offer` to the `com.emvco.dpc.card` credential type. See
    /// `docs/specs/emvco-dpc-schema-framework.md` and
    /// `docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md`.
    ///
    /// `skip_serializing_if` is load-bearing: an offer without display metadata
    /// must serialise to exactly the bytes it did before this field existed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub display: Option<Vec<serde_json::Value>>,
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

/// Render `offer` as the `data` member of a W3C Digital Credentials API
/// issuance request — `navigator.credentials.create()` with protocol
/// `openid4vci-v1`.
///
/// Sibling of [`build_offer_uri`]: the same offer, rendered for a different
/// wallet-facing transport. Nothing about the OpenID4VCI wire protocol changes
/// — same pre-authorized-code grant, same `/token`, same `/credential`; only
/// the channel by which the offer reaches the wallet differs.
///
/// `openid4vci-v1` is a Chrome origin-trial protocol identifier with **no
/// pinned specification** in `docs/specs/`. The shape below follows Chrome's
/// documentation
/// (<https://developer.chrome.com/blog/digital-credentials-api-143-issuance-ot>),
/// the only normative source that currently exists for it. This is a
/// deliberate, documented departure from root AGENTS.md §4.4's
/// implement-only-against-`docs/specs/` rule; see
/// `docs/superpowers/specs/2026-08-04-admin-console-dc-api-issuance-design.md`.
///
/// `credential_configurations_supported` is narrowed to exactly the
/// configuration ids named in the offer. The wallet renders its consent screen
/// from that map, so shipping every configured credential type would leave it
/// to guess which one the offer is about.
///
/// The returned value embeds the `pre-authorized_code`, exactly as
/// [`CredentialOffer`] and `credential_offer_uri` do. It is a secret: never log
/// it, at any level, under any flag (root AGENTS.md §4.5).
pub fn build_dc_api_offer(
    cfg: &Config,
    offer: &CredentialOffer,
    request_decryption_keys: &[foundry_core::crypto::jwe::DecryptionKey],
) -> Result<serde_json::Value, IssuanceError> {
    // Serialize the offer rather than hand-building the object: `CredentialOffer`
    // already owns the serde renames for the grant URN key and the hyphenated
    // `pre-authorized_code`, and duplicating them here is how they drift.
    let mut root =
        serde_json::to_value(offer).map_err(|e| IssuanceError::Serialization(e.to_string()))?;

    // The decryption keys MUST be threaded through, not defaulted to `&[]`.
    //
    // This object is the ONLY issuer metadata a DC API wallet sees: the offer is
    // handed to it in-process by the platform, so there is no fetch of the
    // well-known document to fall back on. Building it with an empty key slice
    // publishes `credential_request_encryption.jwks.keys: []` while
    // `encryption_required` stays `true` -- a self-contradictory document that
    // asks the wallet to encrypt and gives it nothing to encrypt to.
    //
    // OpenID4VCI L871/L873: the Client MUST encrypt the Credential Request when
    // `encryption_required` is `true`, "using the parameters from the
    // `credential_request_encryption` object in the Credential Issuer Metadata"
    // (L1372 defines that object, including `jwks`). With no key there, the
    // mandated behaviour is unperformable and a conformant wallet can only abort.
    let mut issuer_metadata = build_issuer_metadata(cfg, request_decryption_keys);
    issuer_metadata
        .credential_configurations_supported
        .retain(|id, _| offer.credential_configuration_ids.contains(id));

    let issuer_metadata = serde_json::to_value(issuer_metadata)
        .map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    let as_metadata = serde_json::to_value(build_authorization_server_metadata(cfg))
        .map_err(|e| IssuanceError::Serialization(e.to_string()))?;

    let obj = root.as_object_mut().ok_or_else(|| {
        IssuanceError::Serialization(
            "CredentialOffer did not serialize to a JSON object".to_string(),
        )
    })?;
    obj.insert("authorization_server_metadata".to_string(), as_metadata);
    obj.insert("credential_issuer_metadata".to_string(), issuer_metadata);

    Ok(root)
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
            display: None,
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
            display: None,
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

    /// The no-regression assertion for every credential type that is not DPC.
    ///
    /// Asserted on the serialised object's KEYS, not on a round-tripped
    /// `Option`: a `display: null` member would satisfy the weaker check while
    /// still changing the bytes every existing wallet receives.
    #[test]
    fn an_offer_without_display_serialises_without_a_display_key() {
        let offer = pre_auth_offer();
        let value = serde_json::to_value(&offer).unwrap();
        let object = value.as_object().unwrap();
        assert!(
            !object.contains_key("display"),
            "an offer with no display metadata must not carry the key at all, got: {value}"
        );
    }

    #[test]
    fn an_offer_with_display_serialises_the_array_verbatim() {
        let mut offer = pre_auth_offer();
        offer.display = Some(vec![serde_json::json!({
            "locale": "en-US",
            "card": { "type": { "code": "CREDIT" } }
        })]);
        let value = serde_json::to_value(&offer).unwrap();
        assert_eq!(value["display"][0]["card"]["type"]["code"], "CREDIT");
    }
}
