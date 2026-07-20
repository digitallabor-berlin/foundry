use crate::error::FormatError;
use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use foundry_core::trust::{cert_ec_public_coords, parse_cert_pem, validate_chain, TrustStore};
use josekit::jwk::Jwk;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug)]
pub struct VerificationResult {
    pub claims: Value,
    pub holder_jwk: Value,
    pub issuer_x5c: Option<Vec<String>>,
}

fn curve_for_alg(alg: &str) -> Result<&'static str, FormatError> {
    match alg {
        "ES256" => Ok("P-256"),
        "ES384" => Ok("P-384"),
        "ES512" => Ok("P-521"),
        other => Err(FormatError::Unsupported(other.to_string())),
    }
}

fn jws_alg_for_curve(
    curve: &str,
) -> Result<&'static josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm, FormatError> {
    match curve {
        "P-256" => Ok(&josekit::jws::ES256),
        "P-384" => Ok(&josekit::jws::ES384),
        "P-521" => Ok(&josekit::jws::ES512),
        other => Err(FormatError::Unsupported(other.to_string())),
    }
}

fn verify_jws_with_coords(
    curve: &str,
    x: &[u8],
    y: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), FormatError> {
    let jwk_value =
        json!({ "kty": "EC", "crv": curve, "x": B64URL.encode(x), "y": B64URL.encode(y) });
    verify_jws_with_jwk(&jwk_value, curve, message, signature)
}

fn verify_jws_with_jwk(
    jwk_value: &Value,
    curve: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), FormatError> {
    let obj = jwk_value
        .as_object()
        .ok_or_else(|| FormatError::SignatureVerification("holder jwk is not an object".into()))?
        .clone();
    let jwk = Jwk::from_map(obj).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let alg = jws_alg_for_curve(curve)?;
    let verifier = alg
        .verifier_from_jwk(&jwk)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    verifier
        .verify(message, signature)
        .map_err(|e| FormatError::SignatureVerification(format!("signature mismatch: {e}")))?;
    Ok(())
}

/// Rebuild a PEM cert from a base64(standard) DER string without unwrap.
fn der_b64_to_pem(standard_b64: &str) -> Result<Vec<u8>, FormatError> {
    let der = B64STD
        .decode(standard_b64)
        .map_err(|e| FormatError::SignatureVerification(format!("x5c base64 decode: {e}")))?;
    let re_b64 = B64STD.encode(&der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut i = 0;
    while i < re_b64.len() {
        let end = (i + 64).min(re_b64.len());
        pem.push_str(&re_b64[i..end]); // base64 chars are single-byte; boundary-safe
        pem.push('\n');
        i = end;
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem.into_bytes())
}

pub fn verify_sd_jwt_vc(
    presentation_string: &str,
    trust_store: &TrustStore,
    expected_audience: &str,
    expected_nonce: &str,
    now_unix: u64,
) -> Result<VerificationResult, FormatError> {
    // <issuer_jwt>~<disclosure_1>~...~<disclosure_n>~<kb_jwt>
    // The issuer presentation ends with '~'; a KB-JWT (no trailing '~') follows.
    let parts: Vec<&str> = presentation_string.split('~').collect();
    if parts.len() < 2 {
        return Err(FormatError::InvalidStructure(
            "empty or malformed presentation".into(),
        ));
    }
    let issuer_jwt_str = parts[0];
    let last = *parts.last().unwrap_or(&"");
    let kb_jwt: Option<&str> = if last.is_empty() { None } else { Some(last) };
    // disclosures are everything between the issuer JWT and the final segment.
    let disclosures_str = &parts[1..parts.len() - 1];

    // --- Parse issuer JWT ---
    let jwt_parts: Vec<&str> = issuer_jwt_str.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err(FormatError::InvalidStructure(
            "invalid JWS compact serialization".into(),
        ));
    }
    let header_json: Value = serde_json::from_slice(
        &B64URL
            .decode(jwt_parts[0])
            .map_err(|e| FormatError::Deserialization(format!("header b64: {e}")))?,
    )
    .map_err(|e| FormatError::Deserialization(format!("header json: {e}")))?;
    let mut payload_json: Value = serde_json::from_slice(
        &B64URL
            .decode(jwt_parts[1])
            .map_err(|e| FormatError::Deserialization(format!("payload b64: {e}")))?,
    )
    .map_err(|e| FormatError::Deserialization(format!("payload json: {e}")))?;

    // --- Validity window ---
    if let Some(exp) = payload_json.get("exp").and_then(|v| v.as_i64()) {
        if now_unix > exp as u64 {
            return Err(FormatError::Expired);
        }
    }
    if let Some(iat) = payload_json.get("iat").and_then(|v| v.as_i64()) {
        if now_unix < iat as u64 {
            return Err(FormatError::Expired);
        }
    }

    // --- x5c trust-chain validation ---
    let x5c_array = header_json
        .get("x5c")
        .and_then(|v| v.as_array())
        .ok_or_else(|| FormatError::SignatureVerification("issuer x5c missing".into()))?;
    if x5c_array.is_empty() {
        return Err(FormatError::SignatureVerification(
            "empty x5c header".into(),
        ));
    }
    let mut chain_pems: Vec<Vec<u8>> = Vec::with_capacity(x5c_array.len());
    for val in x5c_array {
        let s = val
            .as_str()
            .ok_or_else(|| FormatError::SignatureVerification("non-string x5c element".into()))?;
        chain_pems.push(der_b64_to_pem(s)?);
    }
    let leaf_pem = &chain_pems[0];
    let intermediates: Vec<Vec<u8>> = chain_pems[1..].to_vec();
    validate_chain(leaf_pem, &intermediates, trust_store, now_unix)
        .map_err(|e| FormatError::SignatureVerification(format!("issuer cert validation: {e}")))?;

    // --- Verify issuer JWS signature against the leaf public key ---
    let leaf_cert =
        parse_cert_pem(leaf_pem).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let (ix, iy) = cert_ec_public_coords(&leaf_cert)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let alg_str = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::SignatureVerification("alg missing".into()))?;
    let curve = curve_for_alg(alg_str)?;
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    let sig = B64URL
        .decode(jwt_parts[2])
        .map_err(|e| FormatError::SignatureVerification(format!("signature b64: {e}")))?;
    verify_jws_with_coords(curve, &ix, &iy, signing_input.as_bytes(), &sig)?;

    // --- Reconstruct disclosed claims ---
    let mut disclosures_map: HashMap<String, (String, Value)> = HashMap::new();
    for d_b64 in disclosures_str {
        if d_b64.is_empty() {
            continue;
        }
        let d_val: Value = serde_json::from_slice(
            &B64URL
                .decode(d_b64)
                .map_err(|e| FormatError::Deserialization(format!("disclosure b64: {e}")))?,
        )
        .map_err(|e| FormatError::Deserialization(format!("disclosure json: {e}")))?;
        let arr = d_val.as_array().ok_or_else(|| {
            FormatError::InvalidStructure("disclosure must be a JSON array".into())
        })?;
        if arr.len() != 3 {
            return Err(FormatError::InvalidStructure(
                "disclosure must have 3 items".into(),
            ));
        }
        let name = arr[1].as_str().ok_or_else(|| {
            FormatError::InvalidStructure("disclosure name must be a string".into())
        })?;
        let mut hasher = Sha256::new();
        hasher.update(d_b64.as_bytes());
        let digest_b64 = B64URL.encode(hasher.finalize());
        disclosures_map.insert(digest_b64, (name.to_string(), arr[2].clone()));
    }

    let mut claims_map = Map::new();
    if let Some(payload_map) = payload_json.as_object_mut() {
        if let Some(Value::Array(sd_array)) = payload_map.remove("_sd") {
            for digest_val in sd_array {
                let digest_str = digest_val.as_str().ok_or_else(|| {
                    FormatError::InvalidStructure("_sd elements must be strings".into())
                })?;
                if let Some((name, val)) = disclosures_map.get(digest_str) {
                    payload_map.insert(name.clone(), val.clone());
                }
            }
        }
        payload_map.remove("_sd_alg");
        claims_map = payload_map.clone();
    }

    let holder_jwk = claims_map
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .cloned()
        .ok_or_else(|| FormatError::InvalidStructure("holder cnf.jwk missing".into()))?;

    // --- KB-JWT holder binding (required) ---
    let kb =
        kb_jwt.ok_or_else(|| FormatError::KeyBinding("KB-JWT missing from presentation".into()))?;
    verify_kb_jwt(
        kb,
        presentation_string,
        &holder_jwk,
        expected_audience,
        expected_nonce,
    )?;

    let x5c_vec: Option<Vec<String>> =
        header_json
            .get("x5c")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            });

    Ok(VerificationResult {
        claims: Value::Object(claims_map),
        holder_jwk,
        issuer_x5c: x5c_vec,
    })
}

fn verify_kb_jwt(
    kb: &str,
    full_presentation: &str,
    holder_jwk: &Value,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<(), FormatError> {
    let kb_parts: Vec<&str> = kb.split('.').collect();
    if kb_parts.len() != 3 {
        return Err(FormatError::KeyBinding("KB-JWT is not compact JWS".into()));
    }
    let kb_header: Value = serde_json::from_slice(
        &B64URL
            .decode(kb_parts[0])
            .map_err(|e| FormatError::KeyBinding(format!("kb header b64: {e}")))?,
    )
    .map_err(|e| FormatError::KeyBinding(format!("kb header json: {e}")))?;
    if kb_header.get("typ").and_then(|v| v.as_str()) != Some("kb+jwt") {
        return Err(FormatError::KeyBinding("KB-JWT typ must be kb+jwt".into()));
    }
    let kb_payload: Value = serde_json::from_slice(
        &B64URL
            .decode(kb_parts[1])
            .map_err(|e| FormatError::KeyBinding(format!("kb payload b64: {e}")))?,
    )
    .map_err(|e| FormatError::KeyBinding(format!("kb payload json: {e}")))?;

    if kb_payload.get("aud").and_then(|v| v.as_str()) != Some(expected_audience) {
        return Err(FormatError::KeyBinding("KB-JWT audience mismatch".into()));
    }
    if kb_payload.get("nonce").and_then(|v| v.as_str()) != Some(expected_nonce) {
        return Err(FormatError::KeyBinding("KB-JWT nonce mismatch".into()));
    }

    // sd_hash is over the issuer presentation (everything up to and including the last '~').
    let without_kb = &full_presentation[..full_presentation.len() - kb.len()];
    let mut hasher = Sha256::new();
    hasher.update(without_kb.as_bytes());
    let expected_sd_hash = B64URL.encode(hasher.finalize());
    if kb_payload.get("sd_hash").and_then(|v| v.as_str()) != Some(expected_sd_hash.as_str()) {
        return Err(FormatError::KeyBinding("KB-JWT sd_hash mismatch".into()));
    }

    // Signature under the holder's confirmation key.
    let alg_str = kb_header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::KeyBinding("KB-JWT alg missing".into()))?;
    let curve = curve_for_alg(alg_str)
        .map_err(|_| FormatError::KeyBinding("unsupported KB-JWT alg".into()))?;
    let signing_input = format!("{}.{}", kb_parts[0], kb_parts[1]);
    let sig = B64URL
        .decode(kb_parts[2])
        .map_err(|e| FormatError::KeyBinding(format!("kb signature b64: {e}")))?;
    verify_jws_with_jwk(holder_jwk, curve, signing_input.as_bytes(), &sig)
        .map_err(|e| FormatError::KeyBinding(format!("KB-JWT signature invalid: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::TrustStore;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};

    fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &root.cert_pem,
            &root.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        (
            root.cert_pem.into_bytes(),
            leaf.cert_pem.into_bytes(),
            leaf.key_pem.into_bytes(),
        )
    }

    fn holder() -> (FileSigner, serde_json::Value) {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        let signer =
            FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
        let pubjwk = signer.public_jwk().unwrap();
        (signer, pubjwk)
    }

    fn der_b64(pem_bytes: &[u8]) -> String {
        std::str::from_utf8(pem_bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn parses_and_verifies_valid_presentation() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let trust_store = TrustStore::from_pems(&[root]).unwrap();
        let (holder_signer, holder_pub) = holder();

        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: 1700000000,
            exp: 1800000000,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };

        let issuer_pres =
            build_sd_jwt_vc(claims, &signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(issuer_pres, &holder_signer, "audience", "nonce").unwrap();

        // Cert validity is stamped from the system clock by pki::issue_leaf, so
        // verify against the current time (the issuer iat/exp window spans it).
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let res = verify_sd_jwt_vc(&presentation, &trust_store, "audience", "nonce", now).unwrap();
        assert_eq!(res.claims["given_name"], "Alice");
        assert_eq!(res.claims["sub"], "did:example:alice");
    }

    #[test]
    fn rejects_kb_nonce_mismatch() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let trust_store = TrustStore::from_pems(&[root]).unwrap();
        let (holder_signer, holder_pub) = holder();

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "s".to_string(),
            iat: 1700000000,
            exp: 1800000000,
            vct: "v".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: serde_json::Map::new(),
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(issuer_pres, &holder_signer, "audience", "WRONG").unwrap();

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let err =
            verify_sd_jwt_vc(&presentation, &trust_store, "audience", "nonce", now).unwrap_err();
        assert!(matches!(err, FormatError::KeyBinding(_)));
    }
}
