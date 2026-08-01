//! Observability support shared by the issuer engine, the verifier engine and
//! the binary.
//!
//! This module deliberately contains **no log statements** and no `tracing`
//! usage. It exists because the sensitive-payload switch and the redaction
//! helpers must be readable by `foundry-issuer`, `foundry-verifier` and
//! `foundry` alike, and per the workspace layering rule shared behaviour
//! between same-layer crates belongs in `foundry-core`.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// Marker appended to a value that `truncate` had to shorten, so a reader can
/// tell a capped value from a genuinely short one.
const TRUNCATION_MARKER: &str = "…[truncated]";

/// Returned by [`thumbprint`] when the input is not a JWK it can canonicalise.
///
/// `thumbprint` is infallible by contract — it is called from log statements,
/// which must never introduce a failure path — so a malformed input yields this
/// placeholder rather than an error or a panic.
pub const INVALID_JWK_THUMBPRINT: &str = "<invalid-jwk>";

/// Whether payload-bearing log fields are unlocked.
///
/// Written once during subscriber initialisation and read from many request
/// threads thereafter. `Relaxed` is sufficient: the value is not used to
/// establish any happens-before relationship, and a stale read during the
/// startup window can only cause a payload field to be omitted.
static SENSITIVE: AtomicBool = AtomicBool::new(false);

/// Unlock (or re-lock) payload-bearing log fields process-wide.
///
/// Called exactly once, from the binary's logging initialisation. Payload
/// fields must additionally be emitted at `debug` or `trace` — this flag alone
/// is never sufficient authorisation to log a payload.
pub fn set_sensitive(enabled: bool) {
    SENSITIVE.store(enabled, Ordering::Relaxed);
}

/// Whether payload-bearing log fields are currently unlocked.
pub fn sensitive_enabled() -> bool {
    SENSITIVE.load(Ordering::Relaxed)
}

/// Cap `s` at `max` bytes, appending a visible marker when anything was cut.
///
/// The cap is applied on a UTF-8 character boundary, so a multi-byte character
/// straddling `max` is dropped rather than split. Used to bound `error.detail`
/// and any other free-form string reaching the log or the admin API.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &s[..end], TRUNCATION_MARKER)
}

/// RFC 7638 JWK thumbprint: base64url(SHA-256(canonical JWK)), unpadded.
///
/// Logged in place of a public key so that two records can be correlated to the
/// same key without the key itself ever reaching the log. Never returns an
/// error: an input this cannot canonicalise yields [`INVALID_JWK_THUMBPRINT`].
pub fn thumbprint(jwk: &serde_json::Value) -> String {
    match thumbprint_bytes(jwk) {
        Ok(digest) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
        Err(_) => INVALID_JWK_THUMBPRINT.to_string(),
    }
}

/// RFC 7638 JWK thumbprint as raw SHA-256 bytes — **fail-closed**.
///
/// [`thumbprint`] is a logging helper and is infallible by contract: a JWK it
/// cannot canonicalise degrades to [`INVALID_JWK_THUMBPRINT`]. That is the
/// wrong contract for a caller that embeds the digest in a signed or hashed
/// structure, where a placeholder would silently produce bytes that verify
/// against nothing. Such callers use this function and propagate the error.
///
/// The sole canonicalisation lives here; `thumbprint` delegates to it, so both
/// forms are covered by the same known-answer tests.
///
/// The returned error names only the structural defect (which member, which
/// `kty`) and never echoes key material.
pub fn thumbprint_bytes(jwk: &serde_json::Value) -> Result<[u8; 32], String> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| "JWK is not a JSON object".to_string())?;
    let kty = obj
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "JWK has no string `kty` member".to_string())?;

    // RFC 7638 §3.2 — only the required members of each key type participate,
    // and they are serialised in lexicographic order with no whitespace.
    let required: &[&str] = match kty {
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        "OKP" => &["crv", "kty", "x"],
        "oct" => &["k", "kty"],
        other => return Err(format!("unsupported JWK `kty` `{other}`")),
    };

    // BTreeMap serialises in key order, which is the lexicographic ordering the
    // RFC requires.
    let mut canonical: BTreeMap<&str, &str> = BTreeMap::new();
    for member in required {
        let value = obj
            .get(*member)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("JWK of `kty` `{kty}` is missing required member `{member}`"))?;
        canonical.insert(member, value);
    }

    let json = serde_json::to_string(&canonical)
        .map_err(|e| format!("JWK canonicalisation failed: {e}"))?;
    Ok(Sha256::digest(json.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The sensitive-payload flag is process-global, so all of its behaviour is
    /// asserted by a single test. Splitting it into several `#[test]` functions
    /// would let them race: the test harness runs them concurrently in one
    /// process, and a "defaults to off" assertion would then depend on
    /// scheduling order.
    #[test]
    fn sensitive_flag_defaults_off_and_toggles() {
        assert!(
            !sensitive_enabled(),
            "sensitive payload logging must be off until explicitly enabled"
        );

        set_sensitive(true);
        assert!(sensitive_enabled());

        set_sensitive(false);
        assert!(!sensitive_enabled());
    }

    #[test]
    fn truncate_leaves_short_string_unchanged() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_at_exact_max_is_unchanged() {
        assert_eq!(truncate("abcde", 5), "abcde");
    }

    #[test]
    fn truncate_caps_long_string_and_marks_it() {
        let out = truncate("abcdefghij", 5);
        assert!(out.starts_with("abcde"), "prefix preserved: {out}");
        assert!(
            out.contains("truncated"),
            "truncation must be visible in the log line: {out}"
        );
        assert!(
            !out.contains("fghij"),
            "the tail must not survive truncation: {out}"
        );
    }

    #[test]
    fn truncate_does_not_split_multibyte_char() {
        // Each 'ä' is two bytes, so a byte cap of 3 falls inside the second one.
        let out = truncate("äää", 3);
        assert!(out.starts_with('ä'));
        assert!(
            out.contains("truncated"),
            "expected a truncation marker: {out}"
        );
        // The real assertion is that the line above did not panic on a
        // non-boundary slice, and that what remains is valid UTF-8.
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn truncate_with_zero_max_yields_only_the_marker() {
        let out = truncate("abc", 0);
        assert!(!out.contains("abc"), "nothing may leak at max = 0: {out}");
    }

    fn ec_jwk() -> serde_json::Value {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        })
    }

    /// RFC 7638 §3.1 known-answer vector. Without this, every other thumbprint
    /// assertion is merely self-consistent — this one proves the canonical form
    /// and digest actually match the RFC.
    #[test]
    fn thumbprint_matches_rfc7638_vector() {
        let jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4\
                  cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn\
                  64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz\
                  qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08\
                  qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
                  jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        });
        assert_eq!(
            thumbprint(&jwk),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// OpenID4VP 1.0's own worked example for the mdoc `SessionTranscript`
    /// handover: this JWK's RFC 7638 thumbprint is the `jwkThumbprint` byte
    /// string embedded in both published `…HandoverInfo` vectors (spec
    /// L2878-L2886, L2888-L2910, L3013-L3035).
    ///
    /// A second, independent KAT alongside the RFC 7638 §3.1 vector, and the
    /// only one that pins the **raw bytes** — the base64url form cannot, and
    /// raw bytes are what the handover CBOR embeds.
    #[test]
    fn thumbprint_bytes_matches_openid4vp_handover_vector() {
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "1",
        });
        let got = thumbprint_bytes(&jwk).expect("the spec's own example JWK must canonicalise");
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047",
            "OpenID4VP mdoc handover vector: jwkThumbprint bytes must match the spec"
        );
    }

    /// The two functions deliberately have *opposite* contracts on bad input:
    /// the logging helper must degrade so a log statement cannot fail, the
    /// crypto helper must fail so a placeholder never reaches a hashed
    /// structure. Asserting both in one test keeps that divergence intentional
    /// rather than accidental.
    #[test]
    fn thumbprint_bytes_fails_closed_where_thumbprint_degrades() {
        let cases = [
            ("non-object", json!("not-a-jwk")),
            ("missing kty", json!({"crv": "P-256", "x": "a", "y": "b"})),
            ("unknown kty", json!({"kty": "XYZ"})),
            (
                "missing required member",
                json!({"kty": "EC", "crv": "P-256", "x": "a"}),
            ),
        ];
        for (label, jwk) in cases {
            assert_eq!(
                thumbprint(&jwk),
                INVALID_JWK_THUMBPRINT,
                "{label}: the logging helper must degrade, never fail"
            );
            assert!(
                thumbprint_bytes(&jwk).is_err(),
                "{label}: the crypto helper must fail closed, never degrade"
            );
        }
    }

    #[test]
    fn thumbprint_is_stable_for_same_jwk() {
        assert_eq!(thumbprint(&ec_jwk()), thumbprint(&ec_jwk()));
    }

    #[test]
    fn thumbprint_ignores_member_order_and_extra_members() {
        // RFC 7638 hashes only the required members, in lexicographic order, so
        // key order in the JSON and any additional members must not matter.
        let reordered = json!({
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "crv": "P-256",
            "kty": "EC",
            "use": "sig",
            "kid": "ignored",
        });
        assert_eq!(thumbprint(&ec_jwk()), thumbprint(&reordered));
    }

    #[test]
    fn thumbprint_differs_for_different_jwks() {
        let other = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        });
        assert_ne!(thumbprint(&ec_jwk()), thumbprint(&other));
    }

    #[test]
    fn thumbprint_supports_rsa_and_okp() {
        let rsa = json!({ "kty": "RSA", "n": "0vx7ag", "e": "AQAB" });
        let okp = json!({ "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg" });
        assert_ne!(thumbprint(&rsa), INVALID_JWK_THUMBPRINT);
        assert_ne!(thumbprint(&okp), INVALID_JWK_THUMBPRINT);
        assert_ne!(thumbprint(&rsa), thumbprint(&okp));
    }

    #[test]
    fn thumbprint_returns_placeholder_for_malformed_jwk() {
        // Not an object.
        assert_eq!(thumbprint(&json!("nope")), INVALID_JWK_THUMBPRINT);
        // Object with no `kty`.
        assert_eq!(thumbprint(&json!({ "x": "abc" })), INVALID_JWK_THUMBPRINT);
        // Unknown key type.
        assert_eq!(
            thumbprint(&json!({ "kty": "Martian" })),
            INVALID_JWK_THUMBPRINT
        );
        // Known key type missing a required member.
        assert_eq!(
            thumbprint(&json!({ "kty": "EC", "crv": "P-256", "x": "abc" })),
            INVALID_JWK_THUMBPRINT
        );
    }

    #[test]
    fn thumbprint_never_contains_key_material() {
        let jwk = ec_jwk();
        let tp = thumbprint(&jwk);
        assert!(!tp.contains("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"));
        assert!(!tp.contains("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"));
    }
}
