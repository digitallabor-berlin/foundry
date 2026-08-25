//! Compact JWS construction — the single owner of JOSE header assembly and
//! signing-input encoding for every JWT foundry mints.
//!
//! Before this module existed, three call sites hand-rolled the same twenty
//! lines with three private copies of `b64url_json`. Consolidating them puts
//! the `alg`-versus-signing-key agreement in one place: a header claiming
//! `ES256` over a key that is ES384 produces a JWS no verifier can check, and
//! that is the divergence class
//! [`crate::crypto::SignatureAlgorithm::cose_value`] documents as a
//! conformance defect no single crate's tests would catch.
//!
//! ## The caller owns header member order
//!
//! `serde_json` is built with `preserve_order` in this workspace (`Cargo.lock`
//! lists `indexmap` as a `serde_json` dependency; the feature is
//! `preserve_order = ["indexmap", "std"]`), so a JSON object serialises in
//! insertion order and JOSE header member order is observable in the signed
//! bytes. The existing call sites do not agree on it — `foundry-sd-jwt-vc` and
//! the status list emit `alg, typ, x5c`; the verifier's Request Object emits
//! `typ, alg, x5c`. This function therefore imposes no order: the caller
//! passes a complete header, and `alg` is *validated* where the caller placed
//! it. `alg` is inserted (first) only when the caller omitted it entirely, so
//! a new caller cannot forget it.

use crate::crypto::Signer;
use crate::error::CryptoError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::{Map, Value};

/// Build a compact JWS: `b64url(header) "." b64url(payload) "." b64url(sig)`.
///
/// `header` is the **complete** JOSE header. When it carries an `alg` member,
/// that member must be a string equal to the signer's algorithm name, and its
/// position is preserved. When it carries none, `alg` is inserted first.
pub fn sign_compact(
    header: &Map<String, Value>,
    payload: &Value,
    signer: &dyn Signer,
) -> Result<String, CryptoError> {
    let expected = signer.algorithm().as_str();

    let header = match header.get("alg") {
        Some(Value::String(a)) if a == expected => header.clone(),
        Some(other) => {
            return Err(CryptoError::UnsupportedAlgorithm(format!(
                "JOSE header 'alg' is {other}, but the signing key's algorithm is {expected}"
            )));
        }
        None => {
            let mut with_alg = Map::new();
            with_alg.insert("alg".to_string(), Value::String(expected.to_string()));
            for (k, v) in header.clone() {
                with_alg.insert(k, v);
            }
            with_alg
        }
    };

    let header_b64 = b64url_json(&Value::Object(header))?;
    let payload_b64 = b64url_json(payload)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
}

fn b64url_json(value: &Value) -> Result<String, CryptoError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| CryptoError::Sign(format!("JOSE JSON serialization failed: {e}")))?;
    Ok(B64URL.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FileSigner, SignatureAlgorithm};
    use crate::pki::generate_ec_key;
    use serde_json::json;

    fn test_signer() -> FileSigner {
        let km = generate_ec_key(SignatureAlgorithm::Es256).expect("generate key");
        FileSigner::from_pem(km.private_pem.as_bytes(), SignatureAlgorithm::Es256)
            .expect("build signer")
    }

    fn raw_header(jws: &str) -> String {
        let part = jws.split('.').next().expect("header segment");
        String::from_utf8(B64URL.decode(part).expect("b64url header")).expect("utf8")
    }

    /// `preserve_order` is enabled workspace-wide, so JSON object member order
    /// is insertion order. Every byte-identical claim in this module and in the
    /// Task 3 migrations rests on that. If a dependency change ever turns the
    /// feature off, this fails loudly instead of silently reordering signed
    /// JOSE headers.
    #[test]
    fn serde_json_map_preserves_insertion_order() {
        let mut m = Map::new();
        m.insert("zebra".to_string(), json!(1));
        m.insert("alpha".to_string(), json!(2));
        let s = serde_json::to_string(&Value::Object(m)).expect("serialize");
        assert_eq!(
            s, r#"{"zebra":1,"alpha":2}"#,
            "serde_json must be built with preserve_order"
        );
    }

    #[test]
    fn caller_header_order_is_preserved_verbatim() {
        let signer = test_signer();
        let mut header = Map::new();
        header.insert("typ".to_string(), json!("oauth-authz-req+jwt"));
        header.insert("alg".to_string(), json!("ES256"));
        header.insert("x5c".to_string(), json!(["AAAA"]));

        let jws = sign_compact(&header, &json!({"a": 1}), &signer).expect("sign");
        assert_eq!(
            raw_header(&jws),
            r#"{"typ":"oauth-authz-req+jwt","alg":"ES256","x5c":["AAAA"]}"#
        );
    }

    #[test]
    fn alg_is_inserted_first_when_the_caller_omits_it() {
        let signer = test_signer();
        let mut header = Map::new();
        header.insert("typ".to_string(), json!("credential-metadata+jwt"));

        let jws = sign_compact(&header, &json!({}), &signer).expect("sign");
        assert_eq!(
            raw_header(&jws),
            r#"{"alg":"ES256","typ":"credential-metadata+jwt"}"#
        );
    }

    #[test]
    fn a_header_alg_that_disagrees_with_the_signer_is_rejected() {
        let signer = test_signer(); // ES256
        let mut header = Map::new();
        header.insert("alg".to_string(), json!("ES384"));

        let err = sign_compact(&header, &json!({}), &signer).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("ES384"), "should name the header alg: {msg}");
        assert!(msg.contains("ES256"), "should name the signer alg: {msg}");
    }

    #[test]
    fn a_non_string_header_alg_is_rejected() {
        let signer = test_signer();
        let mut header = Map::new();
        header.insert("alg".to_string(), json!(7));

        assert!(sign_compact(&header, &json!({}), &signer).is_err());
    }

    #[test]
    fn output_is_three_b64url_segments_over_the_signing_input() {
        let signer = test_signer();
        let mut header = Map::new();
        header.insert("typ".to_string(), json!("test+jwt"));
        let payload = json!({"iss": "https://issuer.example", "iat": 1});

        let jws = sign_compact(&header, &payload, &signer).expect("sign");
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload_bytes = B64URL.decode(parts[1]).expect("b64url payload");
        let decoded: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
        assert_eq!(decoded, payload);

        let sig = B64URL.decode(parts[2]).expect("b64url signature");
        assert!(!sig.is_empty());
    }
}
