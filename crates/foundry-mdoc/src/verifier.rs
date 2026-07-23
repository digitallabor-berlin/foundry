use crate::error::FormatError;
use crate::types::{serialize_session_transcript, IssuerSignedItem, MobileSecurityObject};
use base64::{
    engine::general_purpose::STANDARD as B64STD,
    engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _,
};
use coset::iana::EnumI64;
use coset::{iana, CborSerializable, CoseKey, CoseSign1};
use foundry_core::trust::{cert_ec_public_coords, parse_cert_pem, validate_chain, TrustStore};
use josekit::jwk::Jwk;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct MdocVerificationResult {
    pub claims: BTreeMap<String, BTreeMap<String, JsonValue>>,
    pub device_key_jwk: JsonValue,
    pub issuer_x5c: Option<Vec<String>>,
    pub doc_type: String,
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

fn verify_ecdsa(
    curve: &str,
    x: &[u8],
    y: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), FormatError> {
    let jwk_value =
        json!({ "kty": "EC", "crv": curve, "x": B64URL.encode(x), "y": B64URL.encode(y) });
    let obj = jwk_value
        .as_object()
        .ok_or_else(|| FormatError::SignatureVerification("jwk build failed".into()))?
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

fn der_b64_to_pem(standard_b64: &str) -> Result<Vec<u8>, FormatError> {
    let der = B64STD
        .decode(standard_b64)
        .map_err(|e| FormatError::SignatureVerification(format!("x5c b64: {e}")))?;
    let re_b64 = B64STD.encode(&der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut i = 0;
    while i < re_b64.len() {
        let end = (i + 64).min(re_b64.len());
        pem.push_str(&re_b64[i..end]);
        pem.push('\n');
        i = end;
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem.into_bytes())
}

fn lookup_map_key<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(k, v)| match k {
        ciborium::Value::Text(s) if s == key => Some(v),
        _ => None,
    })
}

fn cbor_value_to_bytes(v: &ciborium::Value) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(v, &mut bytes)
        .map_err(|e| FormatError::Deserialization(e.to_string()))?;
    Ok(bytes)
}

fn cose_alg_str(alg: &coset::Algorithm) -> Result<&'static str, FormatError> {
    match alg {
        coset::Algorithm::Assigned(iana::Algorithm::ES256) => Ok("ES256"),
        coset::Algorithm::Assigned(iana::Algorithm::ES384) => Ok("ES384"),
        coset::Algorithm::Assigned(iana::Algorithm::ES512) => Ok("ES512"),
        _ => Err(FormatError::Unsupported(
            "unsupported COSE algorithm".into(),
        )),
    }
}

pub fn verify_mdoc(
    mdoc_bytes: &[u8],
    trust_store: &TrustStore,
    client_id: Option<String>,
    response_uri: Option<String>,
    nonce: String,
    device_signature_cose_sign1_bytes: &[u8],
    now_unix: u64,
) -> Result<MdocVerificationResult, FormatError> {
    // --- Outer CBOR ---
    let outer_val: ciborium::Value = ciborium::from_reader(mdoc_bytes)
        .map_err(|e| FormatError::Deserialization(format!("outer CBOR: {e}")))?;
    let outer_map = outer_val
        .as_map()
        .ok_or_else(|| FormatError::InvalidStructure("mdoc must be a CBOR map".into()))?;
    let docs = lookup_map_key(outer_map, "documents")
        .and_then(|v| v.as_array())
        .ok_or_else(|| FormatError::InvalidStructure("missing documents array".into()))?;
    let first_doc = docs
        .first()
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("empty or invalid documents".into()))?;
    let issuer_signed = lookup_map_key(first_doc, "issuerSigned")
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("missing issuerSigned".into()))?;
    let namespaces_map = lookup_map_key(issuer_signed, "nameSpaces")
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("missing nameSpaces".into()))?;
    let issuer_auth_val = lookup_map_key(issuer_signed, "issuerAuth")
        .ok_or_else(|| FormatError::InvalidStructure("missing issuerAuth".into()))?;

    // --- IssuerAuth COSE_Sign1 ---
    let issuer_auth_bytes = cbor_value_to_bytes(issuer_auth_val)?;
    let sign1 = CoseSign1::from_slice(&issuer_auth_bytes)
        .map_err(|e| FormatError::Deserialization(format!("issuerAuth COSE: {e}")))?;

    let mut x5c_b64s: Vec<String> = Vec::new();
    for (label, value) in &sign1.unprotected.rest {
        if *label == coset::Label::Int(33) {
            if let Some(arr) = value.as_array() {
                for item in arr {
                    if let Some(bytes) = item.as_bytes() {
                        x5c_b64s.push(B64STD.encode(bytes));
                    }
                }
            }
        }
    }
    if x5c_b64s.is_empty() {
        return Err(FormatError::SignatureVerification(
            "issuerAuth missing x5c".into(),
        ));
    }

    let mut chain_pems: Vec<Vec<u8>> = Vec::with_capacity(x5c_b64s.len());
    for b64 in &x5c_b64s {
        chain_pems.push(der_b64_to_pem(b64)?);
    }
    let leaf_pem = &chain_pems[0];
    let intermediates: Vec<Vec<u8>> = chain_pems[1..].to_vec();
    validate_chain(leaf_pem, &intermediates, trust_store, now_unix)
        .map_err(|e| FormatError::SignatureVerification(format!("issuer cert validation: {e}")))?;

    let leaf_cert =
        parse_cert_pem(leaf_pem).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let (ix, iy) = cert_ec_public_coords(&leaf_cert)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;

    let mso_bytes = sign1
        .payload
        .clone()
        .ok_or_else(|| FormatError::InvalidStructure("issuerAuth missing payload".into()))?;
    let alg = sign1
        .protected
        .header
        .alg
        .clone()
        .ok_or_else(|| FormatError::SignatureVerification("issuerAuth missing alg".into()))?;
    let curve = curve_for_alg(cose_alg_str(&alg)?)?;
    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        sign1.protected.clone(),
        None,
        &[],
        &mso_bytes,
    );
    verify_ecdsa(curve, &ix, &iy, &tbs, &sign1.signature)?;

    // --- MSO ---
    let mso: MobileSecurityObject = ciborium::from_reader(mso_bytes.as_slice())
        .map_err(|e| FormatError::Deserialization(format!("MSO CBOR: {e}")))?;

    let signed_ts = time::OffsetDateTime::parse(
        &mso.validity_info.signed,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| FormatError::Deserialization(format!("signed parse: {e}")))?;
    let until_ts = time::OffsetDateTime::parse(
        &mso.validity_info.valid_until,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| FormatError::Deserialization(format!("validUntil parse: {e}")))?;
    if now_unix < signed_ts.unix_timestamp() as u64 || now_unix > until_ts.unix_timestamp() as u64 {
        return Err(FormatError::Expired);
    }

    // --- Digest verification & claim reconstruction ---
    let mut verified_claims: BTreeMap<String, BTreeMap<String, JsonValue>> = BTreeMap::new();
    for (ns_key, items_val) in namespaces_map {
        let ns_str = match ns_key {
            ciborium::Value::Text(s) => s,
            _ => continue,
        };
        let items = match items_val.as_array() {
            Some(a) => a,
            None => continue,
        };
        let mso_digests = match mso.value_digests.get(ns_str) {
            Some(d) => d,
            None => continue,
        };
        let mut ns_elements: BTreeMap<String, JsonValue> = BTreeMap::new();
        for item_val in items {
            let item_bytes = match item_val.as_bytes() {
                Some(b) => b,
                None => continue,
            };
            let mut hasher = Sha256::new();
            hasher.update(item_bytes);
            let computed = hasher.finalize().to_vec();

            let item: IssuerSignedItem = ciborium::from_reader(item_bytes.as_slice())
                .map_err(|e| FormatError::Deserialization(format!("IssuerSignedItem: {e}")))?;
            if let Some(expected) = mso_digests.get(&item.digest_id) {
                if expected == &computed {
                    ns_elements.insert(
                        item.element_identifier,
                        cbor_value_to_json(&item.element_value)?,
                    );
                }
            }
        }
        if !ns_elements.is_empty() {
            verified_claims.insert(ns_str.clone(), ns_elements);
        }
    }

    // --- Device (holder) binding: DeviceAuth over SessionTranscript ---
    let device_key_bytes = cbor_value_to_bytes(&mso.device_key_info.device_key)?;
    let device_cose_key = CoseKey::from_slice(&device_key_bytes)
        .map_err(|e| FormatError::Deserialization(format!("deviceKey COSE: {e}")))?;

    let mut d_x: Vec<u8> = Vec::new();
    let mut d_y: Vec<u8> = Vec::new();
    for (label, value) in &device_cose_key.params {
        if *label == coset::Label::Int(iana::Ec2KeyParameter::X.to_i64()) {
            if let Some(b) = value.as_bytes() {
                d_x = b.clone();
            }
        } else if *label == coset::Label::Int(iana::Ec2KeyParameter::Y.to_i64()) {
            if let Some(b) = value.as_bytes() {
                d_y = b.clone();
            }
        }
    }
    if d_x.is_empty() || d_y.is_empty() {
        return Err(FormatError::InvalidStructure(
            "deviceKey missing EC coords".into(),
        ));
    }
    let device_key_jwk =
        json!({ "kty": "EC", "crv": "P-256", "x": B64URL.encode(&d_x), "y": B64URL.encode(&d_y) });

    let d_sign1 = CoseSign1::from_slice(device_signature_cose_sign1_bytes)
        .map_err(|e| FormatError::Deserialization(format!("device COSE: {e}")))?;
    let transcript = serialize_session_transcript(client_id, response_uri, nonce)
        .map_err(FormatError::Serialization)?;
    let d_alg = d_sign1
        .protected
        .header
        .alg
        .clone()
        .ok_or_else(|| FormatError::KeyBinding("device signature missing alg".into()))?;
    let d_curve = curve_for_alg(cose_alg_str(&d_alg)?)
        .map_err(|_| FormatError::KeyBinding("unsupported device alg".into()))?;
    let d_tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        d_sign1.protected.clone(),
        None,
        &[],
        &transcript,
    );
    verify_ecdsa(d_curve, &d_x, &d_y, &d_tbs, &d_sign1.signature)
        .map_err(|e| FormatError::KeyBinding(format!("device signature invalid: {e}")))?;

    Ok(MdocVerificationResult {
        claims: verified_claims,
        device_key_jwk,
        issuer_x5c: Some(x5c_b64s),
        doc_type: mso.doc_type.clone(),
    })
}

fn cbor_value_to_json(val: &ciborium::Value) -> Result<JsonValue, FormatError> {
    match val {
        ciborium::Value::Null => Ok(JsonValue::Null),
        ciborium::Value::Bool(b) => Ok(JsonValue::Bool(*b)),
        ciborium::Value::Integer(i) => {
            let num: i128 = (*i).into();
            let as_i64 = i64::try_from(num)
                .map_err(|_| FormatError::Deserialization("integer out of i64 range".into()))?;
            Ok(JsonValue::Number(as_i64.into()))
        }
        ciborium::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(JsonValue::Number)
            .ok_or_else(|| FormatError::Deserialization("non-finite float".into())),
        ciborium::Value::Text(s) => Ok(JsonValue::String(s.clone())),
        ciborium::Value::Bytes(b) => Ok(JsonValue::String(hex::encode(b))),
        ciborium::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(cbor_value_to_json(v)?);
            }
            Ok(JsonValue::Array(out))
        }
        ciborium::Value::Map(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let key = k
                    .as_text()
                    .ok_or_else(|| FormatError::Deserialization("CBOR map key not text".into()))?;
                out.insert(key.to_string(), cbor_value_to_json(v)?);
            }
            Ok(JsonValue::Object(out))
        }
        _ => Err(FormatError::Unsupported("unsupported CBOR type".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{build_mdoc, MdocClaims};
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
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

    fn der_b64(pem_bytes: &[u8]) -> String {
        std::str::from_utf8(pem_bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn parses_and_verifies_valid_mdoc_presentation() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let trust_store = TrustStore::from_pems(&[root]).unwrap();

        let d_jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let d_kp = EcKeyPair::from_jwk(&d_jwk).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let mut ns_items = BTreeMap::new();
        let mut elements = BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        ns_items.insert("org.iso.18013.5.1".to_string(), elements);

        let claims = MdocClaims {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces: ns_items,
            device_key_jwk: serde_json::to_value(&d_jwk).unwrap(),
            signed_at: 1700000000,
            valid_until: 1800000000,
        };
        let mdoc_bytes = build_mdoc(claims, &signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let transcript = crate::types::serialize_session_transcript(
            Some("client".to_string()),
            Some("uri".to_string()),
            "nonce".to_string(),
        )
        .unwrap();

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
        let partial = coset::CoseSign1Builder::new()
            .protected(protected.clone())
            .build();
        let d_tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            partial.protected.clone(),
            None,
            &[],
            &transcript,
        );
        let sig = d_signer.sign(&d_tbs).unwrap();
        let d_sign = coset::CoseSign1Builder::new()
            .protected(protected)
            .signature(sig)
            .build();
        let d_sig_bytes = coset::CborSerializable::to_vec(d_sign).unwrap();

        // Cert validity is stamped from the system clock by pki::issue_leaf, so verify
        // against the current time (the MSO signed/validUntil window spans it).
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let res = verify_mdoc(
            &mdoc_bytes,
            &trust_store,
            Some("client".to_string()),
            Some("uri".to_string()),
            "nonce".to_string(),
            &d_sig_bytes,
            now,
        )
        .unwrap();
        assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");
        assert_eq!(res.doc_type, "org.iso.18013.5.1.mDL");
    }
}
