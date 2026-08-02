//! Small, dependency-free host-extraction helper shared by every crate that
//! derives a DNS host from a configured base URL (`server.wallet_facing.public_base_url`,
//! `issuer.credential_issuer`). The workspace deliberately carries no URL-parsing
//! crate (see `foundry-core/AGENTS.md`); this is the one shared implementation
//! rather than divergent copies in each caller.

/// Strip a leading `https://` or `http://` scheme, then truncate at the first
/// `/` (path) and `:` (port), leaving a bare DNS host.
///
/// Behaviour is intentionally simple string manipulation, not RFC 3986
/// parsing: it is adequate for the shapes `public_base_url` and
/// `credential_issuer` are configured with in this workspace, and matches the
/// pattern used throughout `foundry-core`/`foundry-verifier` for other URL
/// handling (e.g. `trim_end_matches('/')`).
pub fn dns_host_only(base_url: &str) -> String {
    let host = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    host.split(':').next().unwrap_or(host).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_https_scheme() {
        assert_eq!(
            dns_host_only("https://issuer.example.com"),
            "issuer.example.com"
        );
    }

    #[test]
    fn strips_http_scheme() {
        assert_eq!(dns_host_only("http://localhost:8443"), "localhost");
    }

    #[test]
    fn truncates_at_first_slash() {
        assert_eq!(
            dns_host_only("https://issuer.example.com/tenant1"),
            "issuer.example.com"
        );
    }

    #[test]
    fn truncates_at_first_colon() {
        assert_eq!(
            dns_host_only("https://issuer.example.com:8443"),
            "issuer.example.com"
        );
    }

    #[test]
    fn no_scheme_no_change() {
        assert_eq!(dns_host_only("issuer.example.com"), "issuer.example.com");
    }
}
