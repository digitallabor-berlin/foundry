//! Parses `openid-credential-offer://` deep links (RFC-style query params
//! `credential_offer=<url-encoded-json>` or `credential_offer_uri=<url>`).

use crate::error::{WalletError, WalletResult};
use foundry_issuer::CredentialOffer;

#[derive(Debug)]
pub enum OfferSource {
    /// The offer JSON was inline in the deep link.
    Inline(CredentialOffer),
    /// The deep link referenced a URL that must be fetched to obtain the offer JSON.
    RemoteUri(String),
}

/// Parse an `openid-credential-offer://?credential_offer=...` or
/// `...?credential_offer_uri=...` deep link. Also accepts a bare
/// `credential_offer_uri` URL (no scheme wrapper) for convenience.
pub fn parse_offer_deep_link(uri: &str) -> WalletResult<OfferSource> {
    let query = extract_query(uri)?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        let decoded = percent_decode(value);
        match key {
            "credential_offer" => {
                let offer: CredentialOffer = serde_json::from_str(&decoded)?;
                return Ok(OfferSource::Inline(offer));
            }
            "credential_offer_uri" => return Ok(OfferSource::RemoteUri(decoded)),
            _ => continue,
        }
    }
    Err(WalletError::MalformedOffer(format!(
        "no credential_offer or credential_offer_uri parameter found in '{uri}'"
    )))
}

fn extract_query(uri: &str) -> WalletResult<String> {
    if let Some(idx) = uri.find('?') {
        Ok(uri[idx + 1..].to_string())
    } else {
        Err(WalletError::MalformedOffer(format!(
            "offer deep link has no query string: '{uri}'"
        )))
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_issuer::{CredentialOfferGrants, PreAuthorizedCodeGrant};

    fn sample_offer() -> CredentialOffer {
        CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["pid".to_string()],
            grants: CredentialOfferGrants {
                pre_authorized_code: PreAuthorizedCodeGrant {
                    pre_authorized_code: "abc123".to_string(),
                    tx_code: None,
                },
            },
        }
    }

    #[test]
    fn parses_inline_credential_offer() {
        let uri = foundry_issuer::build_offer_uri(&sample_offer()).unwrap();
        match parse_offer_deep_link(&uri).unwrap() {
            OfferSource::Inline(offer) => {
                assert_eq!(offer.credential_issuer, "https://issuer.example.com");
                assert_eq!(
                    offer.grants.pre_authorized_code.pre_authorized_code,
                    "abc123"
                );
            }
            OfferSource::RemoteUri(_) => panic!("expected Inline"),
        }
    }

    #[test]
    fn parses_remote_credential_offer_uri() {
        let uri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Foffer%2F123";
        match parse_offer_deep_link(uri).unwrap() {
            OfferSource::RemoteUri(url) => {
                assert_eq!(url, "https://issuer.example.com/offer/123")
            }
            OfferSource::Inline(_) => panic!("expected RemoteUri"),
        }
    }

    #[test]
    fn errors_on_missing_query_string() {
        let err = parse_offer_deep_link("openid-credential-offer://").unwrap_err();
        assert_eq!(err.kind(), "malformed_offer");
    }

    #[test]
    fn errors_when_no_recognized_parameter_present() {
        let err = parse_offer_deep_link("openid-credential-offer://?foo=bar").unwrap_err();
        assert_eq!(err.kind(), "malformed_offer");
    }

    #[test]
    fn malformed_percent_encoding_does_not_panic() {
        // A lone trailing '%' near the end of the string must not panic.
        let result = parse_offer_deep_link("openid-credential-offer://?credential_offer_uri=abc%");
        assert!(result.is_ok() || result.is_err()); // must not panic; either outcome is acceptable
    }
}
