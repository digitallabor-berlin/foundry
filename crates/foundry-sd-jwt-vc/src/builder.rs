use crate::error::FormatError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use foundry_core::crypto::Signer;
use rand::RngCore;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct IssuerClaims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub vct: String,
    pub cnf_jwk: Value,
    pub status_list_index: Option<u64>,
    pub status_list_uri: Option<String>,
    pub always_disclosed: Map<String, Value>,
    pub selectively_disclosable: Map<String, Value>,
}

/// 16 bytes of CSPRNG entropy, URL-safe base64 (unpadded).
fn generate_salt() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::ThreadRng::default().fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

fn b64url_json(value: &Value) -> Result<String, FormatError> {
    let bytes = serde_json::to_vec(value).map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(B64URL.encode(bytes))
}

pub fn build_sd_jwt_vc(
    claims: IssuerClaims,
    signer: &dyn Signer,
    x5c: Option<Vec<String>>,
) -> Result<String, FormatError> {
    let mut payload = Map::new();
    payload.insert("iss".into(), Value::String(claims.iss));
    payload.insert("sub".into(), Value::String(claims.sub));
    payload.insert("iat".into(), Value::Number(claims.iat.into()));
    payload.insert("exp".into(), Value::Number(claims.exp.into()));
    payload.insert("vct".into(), Value::String(claims.vct));
    payload.insert("cnf".into(), json!({ "jwk": claims.cnf_jwk }));

    if let (Some(idx), Some(uri)) = (claims.status_list_index, claims.status_list_uri) {
        payload.insert(
            "status".into(),
            json!({ "status_list": { "idx": idx, "uri": uri } }),
        );
    }
    for (k, v) in claims.always_disclosed {
        payload.insert(k, v);
    }

    let mut sd_digests: Vec<String> = Vec::new();
    let mut disclosures: Vec<String> = Vec::new();
    for (k, v) in claims.selectively_disclosable {
        let salt = generate_salt();
        let disclosure_b64 = b64url_json(&json!([salt, k, v]))?;
        let mut hasher = Sha256::new();
        hasher.update(disclosure_b64.as_bytes());
        sd_digests.push(B64URL.encode(hasher.finalize()));
        disclosures.push(disclosure_b64);
    }
    if !sd_digests.is_empty() {
        sd_digests.sort();
        payload.insert(
            "_sd".into(),
            Value::Array(sd_digests.into_iter().map(Value::String).collect()),
        );
        payload.insert("_sd_alg".into(), Value::String("sha-256".into()));
    }

    let alg = signer.algorithm().as_str();
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(alg.to_string()));
    // TODO(interop): draft-17 SD-JWT VC media type.
    header.insert("typ".into(), Value::String("dc+sd-jwt".into()));
    if let Some(chain) = x5c {
        header.insert(
            "x5c".into(),
            Value::Array(chain.into_iter().map(Value::String).collect()),
        );
    }

    let header_b64 = b64url_json(&Value::Object(header))?;
    let payload_b64 = b64url_json(&Value::Object(payload))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let signature_b64 = B64URL.encode(signature);

    let mut output = format!("{signing_input}.{signature_b64}");
    for d in disclosures {
        output.push('~');
        output.push_str(&d);
    }
    output.push('~'); // trailing tilde; a KB-JWT may be appended by the holder
    Ok(output)
}

/// The `transaction_data_hashes` binding a Wallet places in its KB-JWT.
///
/// OpenID4VP 1.0, Format / IETF SD-JWT VC / Transaction Data (L3144): each element
/// is a base64url-encoded hash computed over the string received in the
/// `transaction_data` request parameter. L3145: `transaction_data_hashes_alg` is
/// REQUIRED in the response when the request carried it.
pub struct TransactionDataBinding<'a> {
    pub hashes: &'a [String],
    pub alg: Option<&'a str>,
}

/// Build a holder Key-Binding JWT (typ `kb+jwt`) over the presentation's `sd_hash`.
pub fn build_kb_jwt(
    holder_signer: &dyn Signer,
    audience: &str,
    nonce: &str,
    sd_hash: &str,
    transaction_data_hashes: Option<TransactionDataBinding<'_>>,
) -> Result<String, FormatError> {
    let alg = holder_signer.algorithm().as_str();
    let header = json!({ "alg": alg, "typ": "kb+jwt" });
    let iat = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut payload = json!({ "aud": audience, "nonce": nonce, "iat": iat, "sd_hash": sd_hash });

    // OpenID4VP L3144/L3145.
    if let Some(binding) = transaction_data_hashes {
        payload["transaction_data_hashes"] = json!(binding.hashes);
        if let Some(alg) = binding.alg {
            payload["transaction_data_hashes_alg"] = json!(alg);
        }
    }

    let header_b64 = b64url_json(&header)?;
    let payload_b64 = b64url_json(&payload)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = holder_signer
        .sign(signing_input.as_bytes())
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
}

/// Append a KB-JWT to an issuer presentation (which must end with `~`).
pub fn attach_kb_jwt(
    issuer_presentation: String,
    holder_signer: &dyn Signer,
    audience: &str,
    nonce: &str,
    transaction_data_hashes: Option<TransactionDataBinding<'_>>,
) -> Result<String, FormatError> {
    let mut hasher = Sha256::new();
    hasher.update(issuer_presentation.as_bytes());
    let sd_hash = B64URL.encode(hasher.finalize());
    let kb = build_kb_jwt(
        holder_signer,
        audience,
        nonce,
        &sd_hash,
        transaction_data_hashes,
    )?;
    Ok(format!("{issuer_presentation}{kb}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};

    fn test_signer() -> FileSigner {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap()
    }

    #[test]
    fn builds_sd_jwt_vc_with_disclosures() {
        let signer = test_signer();
        let mut always = serde_json::Map::new();
        always.insert("country".to_string(), serde_json::json!("DE"));
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("John"));

        let claims = IssuerClaims {
            iss: "https://issuer.dev.local".to_string(),
            sub: "did:example:123".to_string(),
            iat: 1700000000,
            exp: 1800000000,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: serde_json::json!({"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}),
            status_list_index: Some(42),
            status_list_uri: Some("https://localhost:8443/statuslists/list1".to_string()),
            always_disclosed: always,
            selectively_disclosable: select,
        };

        let result = build_sd_jwt_vc(claims, &signer, None).unwrap();
        assert!(result.ends_with('~')); // issuer presentation ends with a trailing tilde
        let parts: Vec<&str> = result.split('~').collect();
        assert_eq!(parts[0].split('.').count(), 3); // compact JWS h.p.s
        assert!(parts.len() >= 2); // at least one disclosure segment
    }

    #[test]
    fn salts_are_random() {
        let a = generate_salt();
        let b = generate_salt();
        assert_ne!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn attach_kb_jwt_emits_transaction_data_hashes_when_asked() {
        // OpenID4VP L3144: a non-empty array of base64url-encoded hashes.
        // L3145: transaction_data_hashes_alg is REQUIRED in the response when the
        // request carried it.
        let signer = test_signer();
        let issuer_pres = "eyJhbGciOiJFUzI1NiJ9.e30.sig~".to_string();
        let hashes = vec!["aGFzaDE".to_string(), "aGFzaDI".to_string()];

        let out = attach_kb_jwt(
            issuer_pres.clone(),
            &signer,
            "x509_hash:abc",
            "nonce-1",
            Some(TransactionDataBinding {
                hashes: &hashes,
                alg: Some("sha-256"),
            }),
        )
        .unwrap();

        let kb = out.strip_prefix(&issuer_pres).expect("KB-JWT is appended");
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(kb.split('.').nth(1).unwrap()).unwrap()).unwrap();

        assert_eq!(
            payload["transaction_data_hashes"],
            serde_json::json!(hashes)
        );
        assert_eq!(payload["transaction_data_hashes_alg"], "sha-256");
    }

    #[test]
    fn attach_kb_jwt_omits_the_claims_when_not_asked() {
        let signer = test_signer();
        let issuer_pres = "eyJhbGciOiJFUzI1NiJ9.e30.sig~".to_string();

        let out = attach_kb_jwt(issuer_pres.clone(), &signer, "aud", "nonce", None).unwrap();

        let kb = out.strip_prefix(&issuer_pres).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(kb.split('.').nth(1).unwrap()).unwrap()).unwrap();

        assert!(payload.get("transaction_data_hashes").is_none());
        assert!(payload.get("transaction_data_hashes_alg").is_none());
    }

    #[test]
    fn attach_kb_jwt_omits_the_alg_when_the_request_did_not_carry_one() {
        // L3145 makes the response field REQUIRED only when the request had it.
        let signer = test_signer();
        let issuer_pres = "eyJhbGciOiJFUzI1NiJ9.e30.sig~".to_string();
        let hashes = vec!["aGFzaDE".to_string()];

        let out = attach_kb_jwt(
            issuer_pres.clone(),
            &signer,
            "aud",
            "nonce",
            Some(TransactionDataBinding {
                hashes: &hashes,
                alg: None,
            }),
        )
        .unwrap();

        let kb = out.strip_prefix(&issuer_pres).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(kb.split('.').nth(1).unwrap()).unwrap()).unwrap();

        assert_eq!(
            payload["transaction_data_hashes"],
            serde_json::json!(hashes)
        );
        assert!(payload.get("transaction_data_hashes_alg").is_none());
    }
}
