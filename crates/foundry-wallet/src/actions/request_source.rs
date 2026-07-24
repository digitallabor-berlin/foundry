//! Parses `openid4vp://` deep links referencing a `request_uri` to `GET`.

use crate::error::{WalletError, WalletResult};

/// Parse an `openid4vp://?request_uri=<url>` deep link, or accept a bare
/// `https://.../vp/request/:id` URL directly (both forms are documented
/// entry points per the design doc section 7, step 1).
pub fn parse_request_deep_link(uri: &str) -> WalletResult<String> {
    if uri.starts_with("http://") || uri.starts_with("https://") {
        return Ok(uri.to_string());
    }
    let query = uri.find('?').map(|idx| &uri[idx + 1..]).ok_or_else(|| {
        WalletError::MalformedRequestObject(format!(
            "request deep link has no query string and is not a bare http(s) URL: '{uri}'"
        ))
    })?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if key == "request_uri" {
            return Ok(percent_decode(value));
        }
    }
    Err(WalletError::MalformedRequestObject(format!(
        "no request_uri parameter found in '{uri}'"
    )))
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

    #[test]
    fn parses_openid4vp_request_uri_deep_link() {
        let uri =
            "openid4vp://?request_uri=https%3A%2F%2Fverifier.example.com%2Fvp%2Frequest%2Fabc";
        assert_eq!(
            parse_request_deep_link(uri).unwrap(),
            "https://verifier.example.com/vp/request/abc"
        );
    }

    #[test]
    fn accepts_a_bare_https_url() {
        let uri = "https://verifier.example.com/vp/request/abc";
        assert_eq!(parse_request_deep_link(uri).unwrap(), uri);
    }

    #[test]
    fn errors_on_malformed_deep_link() {
        let err = parse_request_deep_link("openid4vp://?foo=bar").unwrap_err();
        assert_eq!(err.kind(), "malformed_request_object");
    }

    #[test]
    fn malformed_percent_encoding_does_not_panic() {
        let result = parse_request_deep_link("openid4vp://?request_uri=abc%");
        assert!(result.is_ok() || result.is_err()); // must not panic; either outcome is acceptable
    }
}
