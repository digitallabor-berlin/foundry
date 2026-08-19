use crate::error::FormatError;
use crate::types::{IssuerSignedItem, MobileSecurityObject};
use base64::{
    Engine as _, engine::general_purpose::STANDARD as B64STD,
    engine::general_purpose::URL_SAFE_NO_PAD as B64URL,
};
use coset::iana::EnumI64;
use coset::{CborSerializable, CoseKey, CoseSign1, iana};
use foundry_core::trust::{TrustStore, cert_ec_public_coords, parse_cert_pem, validate_chain};
use josekit::jwk::Jwk;
use serde_json::{Value as JsonValue, json};
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

/// A parsed, structurally validated `DeviceResponse`.
///
/// Holds borrowed views into the caller's decoded CBOR rather than owning
/// anything. That is deliberate: `deviceSigned.nameSpaces` must be re-emitted
/// **byte-for-byte** inside `DeviceAuthentication`, so it is never decoded into a
/// map and rebuilt.
#[derive(Debug)]
pub struct DeviceResponse<'a> {
    doc_type: &'a str,
    issuer_signed: &'a [(ciborium::Value, ciborium::Value)],
    device_namespaces: &'a ciborium::Value,
    device_signature: &'a ciborium::Value,
}

impl DeviceResponse<'_> {
    pub fn doc_type(&self) -> &str {
        self.doc_type
    }
}

/// Decode the outer `DeviceResponse` CBOR.
///
/// Separate from [`parse_device_response`] so the caller owns the decoded value
/// that `DeviceResponse<'_>` borrows from — a borrowed view cannot outlive a
/// `ciborium::Value` created inside the parser.
pub fn decode_device_response(bytes: &[u8]) -> Result<ciborium::Value, FormatError> {
    ciborium::from_reader(bytes)
        .map_err(|e| FormatError::Deserialization(format!("DeviceResponse CBOR: {e}")))
}

/// Structurally validate a decoded `DeviceResponse`.
///
/// OpenID4VP 1.0 L2825-L2828 carries the base64url of this structure as the
/// `vp_token` entry for `mso_mdoc`.
pub fn parse_device_response(decoded: &ciborium::Value) -> Result<DeviceResponse<'_>, FormatError> {
    let outer = decoded
        .as_map()
        .ok_or_else(|| FormatError::InvalidStructure("DeviceResponse must be a CBOR map".into()))?;

    lookup_map_key(outer, "version")
        .and_then(|v| v.as_text())
        .ok_or_else(|| FormatError::InvalidStructure("DeviceResponse missing version".into()))?;

    // ISO/IEC 18013-5: `status` is a DeviceResponseStatus, and 0 means OK. A
    // non-zero status is the wallet telling us it did not or could not answer, so
    // treating it as a presentation to verify would invent a result it never sent.
    let status = lookup_map_key(outer, "status")
        .and_then(|v| v.as_integer())
        .ok_or_else(|| FormatError::InvalidStructure("DeviceResponse missing status".into()))?;
    if status != 0.into() {
        return Err(FormatError::InvalidStructure(format!(
            "DeviceResponse status must be 0, got {status:?}"
        )));
    }

    let docs = lookup_map_key(outer, "documents")
        .and_then(|v| v.as_array())
        .ok_or_else(|| FormatError::InvalidStructure("missing documents array".into()))?;
    // foundry's DCQL layer answers exactly one credential query per presentation,
    // so a response carrying several documents is ambiguous about which one was
    // meant. Rejecting beats silently verifying the first.
    if docs.len() != 1 {
        return Err(FormatError::InvalidStructure(format!(
            "expected exactly one document in the DeviceResponse, got {}",
            docs.len()
        )));
    }
    let doc = docs[0]
        .as_map()
        .ok_or_else(|| FormatError::InvalidStructure("document must be a CBOR map".into()))?;

    let doc_type = lookup_map_key(doc, "docType")
        .and_then(|v| v.as_text())
        .ok_or_else(|| FormatError::InvalidStructure("document missing docType".into()))?;
    let issuer_signed = lookup_map_key(doc, "issuerSigned")
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("missing issuerSigned".into()))?;

    let device_signed = lookup_map_key(doc, "deviceSigned")
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("missing deviceSigned".into()))?;
    let device_namespaces = lookup_map_key(device_signed, "nameSpaces")
        .ok_or_else(|| FormatError::InvalidStructure("missing deviceSigned.nameSpaces".into()))?;
    let device_auth = lookup_map_key(device_signed, "deviceAuth")
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("missing deviceSigned.deviceAuth".into()))?;

    // DeviceAuth is a choice of deviceSignature or deviceMac. foundry accepts only
    // ES256 signatures, so a MAC gets a typed "unsupported" rather than a
    // misleading structural error — HAIP requires ES256 for this profile and a MAC
    // additionally needs an ECDH agreement foundry never performs.
    if device_auth
        .iter()
        .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "deviceMac"))
    {
        return Err(FormatError::Unsupported(
            "DeviceMac device authentication (only deviceSignature/ES256 is supported)".into(),
        ));
    }
    let device_signature = lookup_map_key(device_auth, "deviceSignature").ok_or_else(|| {
        FormatError::InvalidStructure("missing deviceSigned.deviceAuth.deviceSignature".into())
    })?;

    Ok(DeviceResponse {
        doc_type,
        issuer_signed,
        device_namespaces,
        device_signature,
    })
}

/// The issuer-authenticated half of a `DeviceResponse`.
pub struct IssuerVerified {
    pub claims: BTreeMap<String, BTreeMap<String, JsonValue>>,
    pub device_key_jwk: JsonValue,
    pub device_key_x: Vec<u8>,
    pub device_key_y: Vec<u8>,
    pub issuer_x5c: Vec<String>,
    pub doc_type: String,
}

/// Verify the issuer half: certificate chain, IssuerAuth signature, MSO validity
/// window, and element digests.
///
/// Split from the device half for two reasons that are not cosmetic. It lets
/// `foundry-verifier` run this **once** and retry only the Device Signature per
/// candidate Origin, instead of re-validating a certificate chain to retry one
/// signature. And it makes the device half reachable without a trust store, which
/// is what a captured real presentation needs — such a capture's issuer chain
/// will not anchor here (design doc §8).
pub fn verify_issuer_signed(
    resp: &DeviceResponse<'_>,
    trust_store: &TrustStore,
    now_unix: u64,
) -> Result<IssuerVerified, FormatError> {
    let namespaces_map = lookup_map_key(resp.issuer_signed, "nameSpaces")
        .and_then(|v| v.as_map())
        .ok_or_else(|| FormatError::InvalidStructure("missing nameSpaces".into()))?;
    let issuer_auth_val = lookup_map_key(resp.issuer_signed, "issuerAuth")
        .ok_or_else(|| FormatError::InvalidStructure("missing issuerAuth".into()))?;

    // --- IssuerAuth COSE_Sign1 ---
    let issuer_auth_bytes = cbor_value_to_bytes(issuer_auth_val)?;
    let sign1 = CoseSign1::from_slice(&issuer_auth_bytes)
        .map_err(|e| FormatError::Deserialization(format!("issuerAuth COSE: {e}")))?;

    let mut x5c_b64s: Vec<String> = Vec::new();
    for (label, value) in &sign1.unprotected.rest {
        if *label == coset::Label::Int(33)
            && let Some(arr) = value.as_array()
        {
            for item in arr {
                if let Some(bytes) = item.as_bytes() {
                    x5c_b64s.push(B64STD.encode(bytes));
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
    // The signature above was verified over `mso_bytes` verbatim, which is
    // MobileSecurityObjectBytes = `#6.24(bstr .cbor MobileSecurityObject)`.
    // Unwrap only to parse; never feed the unwrapped form to the signature check.
    let mso_wrapper: ciborium::Value = ciborium::from_reader(mso_bytes.as_slice())
        .map_err(|e| FormatError::Deserialization(format!("issuerAuth payload CBOR: {e}")))?;
    let mso_inner =
        crate::types::tag24_unwrap(&mso_wrapper).map_err(FormatError::InvalidStructure)?;
    let mso: MobileSecurityObject = ciborium::from_reader(mso_inner)
        .map_err(|e| FormatError::Deserialization(format!("MSO CBOR: {e}")))?;

    // ISO/IEC 18013-5: the document's validity window is validFrom..validUntil.
    // `signed` records when the MSO was signed and does not bound validity.
    let from_ts = time::OffsetDateTime::parse(
        &mso.validity_info.valid_from.0,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| FormatError::Deserialization(format!("validFrom parse: {e}")))?;
    let until_ts = time::OffsetDateTime::parse(
        &mso.validity_info.valid_until.0,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| FormatError::Deserialization(format!("validUntil parse: {e}")))?;
    if now_unix < from_ts.unix_timestamp() as u64 || now_unix > until_ts.unix_timestamp() as u64 {
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
            // Elements travel as `#6.24(bstr .cbor IssuerSignedItem)`. A non-tag-24
            // item is a structural fault, never a skip: skipping is exactly how
            // foundry dropped every disclosed element and then reported the result
            // as a DCQL policy mismatch (design doc §1.6).
            let inner =
                crate::types::tag24_unwrap(item_val).map_err(FormatError::InvalidStructure)?;

            // The digest commits to the FULL tag-24 encoding (design doc §2.3), so
            // re-wrap through the same helper the builder uses rather than hashing
            // the item's contents.
            let tagged_bytes =
                crate::types::tag24_encode(inner).map_err(FormatError::Serialization)?;

            let mut hasher = Sha256::new();
            hasher.update(&tagged_bytes);
            let computed = hasher.finalize().to_vec();

            let item: IssuerSignedItem = ciborium::from_reader(inner)
                .map_err(|e| FormatError::Deserialization(format!("IssuerSignedItem: {e}")))?;
            if let Some(expected) = mso_digests.get(&item.digest_id)
                && expected == &computed
            {
                ns_elements.insert(
                    item.element_identifier,
                    cbor_value_to_json(&item.element_value)?,
                );
            }
        }
        if !ns_elements.is_empty() {
            verified_claims.insert(ns_str.clone(), ns_elements);
        }
    }

    // --- Holder key, as committed to by the MSO ---
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
        } else if *label == coset::Label::Int(iana::Ec2KeyParameter::Y.to_i64())
            && let Some(b) = value.as_bytes()
        {
            d_y = b.clone();
        }
    }
    if d_x.is_empty() || d_y.is_empty() {
        return Err(FormatError::InvalidStructure(
            "deviceKey missing EC coords".into(),
        ));
    }
    let device_key_jwk =
        json!({ "kty": "EC", "crv": "P-256", "x": B64URL.encode(&d_x), "y": B64URL.encode(&d_y) });

    Ok(IssuerVerified {
        claims: verified_claims,
        device_key_jwk,
        device_key_x: d_x,
        device_key_y: d_y,
        issuer_x5c: x5c_b64s,
        doc_type: mso.doc_type.clone(),
    })
}

/// Verify the `DeviceSignature` over `DeviceAuthenticationBytes`.
///
/// Takes no trust store on purpose: this is the only half of mdoc verification a
/// captured real presentation can exercise, since such a capture's issuer chain
/// will not anchor here.
pub fn verify_device_auth(
    resp: &DeviceResponse<'_>,
    session_transcript: &ciborium::Value,
    device_key_x: &[u8],
    device_key_y: &[u8],
) -> Result<(), FormatError> {
    let d_sig_bytes = cbor_value_to_bytes(resp.device_signature)?;
    let d_sign1 = CoseSign1::from_slice(&d_sig_bytes)
        .map_err(|e| FormatError::Deserialization(format!("deviceSignature COSE: {e}")))?;
    let d_alg = d_sign1
        .protected
        .header
        .alg
        .clone()
        .ok_or_else(|| FormatError::KeyBinding("device signature missing alg".into()))?;
    let d_curve = curve_for_alg(cose_alg_str(&d_alg)?)
        .map_err(|_| FormatError::KeyBinding("unsupported device alg".into()))?;

    let payload = crate::types::device_authentication_bytes(
        session_transcript,
        resp.doc_type,
        resp.device_namespaces,
    )
    .map_err(FormatError::Serialization)?;

    // COSE_Sign1 with a DETACHED payload: the wire structure carries
    // `payload: null`, but the Sig_structure still receives the payload in the
    // payload slot. `external_aad` is the empty byte string and always was —
    // detachment changes the wire form, not the Sig_structure. foundry previously
    // passed the bare SessionTranscript in this slot (design doc §1.5).
    let d_tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        d_sign1.protected.clone(),
        None,
        &[],
        &payload,
    );
    verify_ecdsa(
        d_curve,
        device_key_x,
        device_key_y,
        &d_tbs,
        &d_sign1.signature,
    )
    .map_err(|e| FormatError::KeyBinding(format!("device signature invalid: {e}")))
}

/// Verify an mdoc presentation: structure, IssuerAuth chain and signature, MSO
/// validity window, element digests, and the DeviceAuth signature.
///
/// `session_transcript` is supplied by the caller as a `ciborium::Value` rather
/// than derived here or taken as bytes. Which transcript applies is an OpenID4VP
/// question — invocation method, Response Mode, request Origin — and this crate
/// has access to none of them; the `Value` form additionally avoids a
/// decode/re-encode round trip when it is spliced into `DeviceAuthentication`.
/// Build it with [`crate::types::session_transcript_value`].
pub fn verify_mdoc(
    device_response_bytes: &[u8],
    trust_store: &TrustStore,
    session_transcript: &ciborium::Value,
    now_unix: u64,
) -> Result<MdocVerificationResult, FormatError> {
    let decoded = decode_device_response(device_response_bytes)?;
    let resp = parse_device_response(&decoded)?;
    let issuer = verify_issuer_signed(&resp, trust_store, now_unix)?;
    verify_device_auth(
        &resp,
        session_transcript,
        &issuer.device_key_x,
        &issuer.device_key_y,
    )?;
    Ok(MdocVerificationResult {
        claims: issuer.claims,
        device_key_jwk: issuer.device_key_jwk,
        issuer_x5c: Some(issuer.issuer_x5c),
        doc_type: issuer.doc_type,
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
    use crate::builder::{MdocClaims, build_device_response, build_mdoc};
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

    const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";

    /// A conformant `DeviceResponse` and everything needed to verify or tamper
    /// with it, built once so every test exercises the same fixture.
    struct Fixture {
        /// What a wallet sends: the full `DeviceResponse`.
        response: Vec<u8>,
        /// The issuer-signed mdoc `build_mdoc` emitted, before the device half
        /// was wrapped around it.
        mdoc: Vec<u8>,
        /// The issuer's private key PEM, so a tamper helper can re-sign after
        /// rewriting the MSO — isolating a structural check from the signature
        /// check that legitimately runs before it.
        leaf_key: Vec<u8>,
        /// The holder's private key PEM, for building a deliberately wrong
        /// device signature.
        device_key: Vec<u8>,
        trust_store: TrustStore,
        transcript: ciborium::Value,
        now: u64,
    }

    fn dc_api_transcript() -> ciborium::Value {
        crate::types::session_transcript_value(&crate::types::SessionTranscriptParams::DcApi {
            origin: "https://client.example.com".to_string(),
            nonce: "nonce".to_string(),
            jwk_thumbprint: None,
        })
        .unwrap()
    }

    fn valid_fixture() -> Fixture {
        let (root, leaf_cert, leaf_key) = test_pki();
        let signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let trust_store = TrustStore::from_pems(&[root]).unwrap();

        let d_jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let d_kp = EcKeyPair::from_jwk(&d_jwk).unwrap();
        let device_key = d_kp.to_pem_private_key();
        let d_signer = FileSigner::from_pem(&device_key, SignatureAlgorithm::Es256).unwrap();

        let mut ns_items = BTreeMap::new();
        let mut elements = BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        ns_items.insert("org.iso.18013.5.1".to_string(), elements);

        let claims = MdocClaims {
            doc_type: DOC_TYPE.to_string(),
            namespaces: ns_items,
            device_key_jwk: serde_json::to_value(&d_jwk).unwrap(),
            signed_at: 1700000000,
            valid_until: 1800000000,
        };
        let mdoc = build_mdoc(claims, &signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let transcript = dc_api_transcript();
        let response =
            build_device_response(&mdoc, DOC_TYPE, &d_signer, &transcript).expect("DeviceResponse");

        Fixture {
            response,
            mdoc,
            leaf_key,
            device_key,
            trust_store,
            transcript,
            // Cert validity is stamped from the system clock by pki::issue_leaf, so
            // verify against the current time (the MSO window spans it).
            now: time::OffsetDateTime::now_utc().unix_timestamp() as u64,
        }
    }

    fn verify(f: &Fixture) -> Result<MdocVerificationResult, FormatError> {
        verify_mdoc(&f.response, &f.trust_store, &f.transcript, f.now)
    }

    #[test]
    fn round_trips_a_conformant_device_response() {
        let f = valid_fixture();
        let res = verify(&f).expect("verifies end to end");
        assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");
        assert_eq!(res.doc_type, DOC_TYPE);
        assert!(!res.claims.is_empty(), "claims must be reconstructed");
    }

    // ---- Defect 2: DeviceAuthenticationBytes ----

    /// The structure is **derived** from two independent implementations, not read
    /// from ISO 18013-5 (design doc §2.1). This asserts it element by element; a
    /// byte vector generated independently of foundry would be stronger and does
    /// not yet exist — see the plan's Self-Review.
    #[test]
    fn device_authentication_bytes_have_the_derived_structure() {
        let transcript = dc_api_transcript();
        let ns = crate::types::empty_device_namespaces();
        let bytes =
            crate::types::device_authentication_bytes(&transcript, "eu.europa.ec.av.1", &ns)
                .expect("builds");

        assert_eq!(&bytes[..2], &[0xd8, 0x18], "outer tag-24");
        let wrapper: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let inner: ciborium::Value =
            ciborium::from_reader(crate::types::tag24_unwrap(&wrapper).unwrap()).unwrap();
        let arr = inner.as_array().expect("array");

        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0].as_text(), Some("DeviceAuthentication"));
        assert_eq!(&arr[1], &transcript, "element [1] is the BARE transcript");
        assert!(
            !matches!(arr[1], ciborium::Value::Tag(..)),
            "the transcript must NOT be tag-24 wrapped here — that form is a MAC \
             key-derivation salt (design doc §2.2 hazard 2)"
        );
        assert_eq!(arr[2].as_text(), Some("eu.europa.ec.av.1"));
        assert_eq!(&arr[3], &ns, "element [3] is the wire bytes verbatim");
    }

    /// The pre-fix behaviour. Without this, a regression to it is invisible.
    #[test]
    fn a_device_signature_over_the_bare_transcript_is_rejected() {
        let mut f = valid_fixture();
        f.response = build_device_response_signing_bare_transcript(
            &f.mdoc,
            DOC_TYPE,
            &f.device_key,
            &f.transcript,
        );

        let err = verify(&f).expect_err("a signature over the bare transcript must fail");
        assert!(matches!(err, FormatError::KeyBinding(_)), "got {err}");
    }

    /// Both reference implementations reuse the received tag-24 item rather than
    /// rebuilding it (design doc §2.2 hazard 1).
    #[test]
    fn device_namespaces_bytes_are_used_verbatim() {
        let f = valid_fixture();
        let decoded = decode_device_response(&f.response).unwrap();
        let resp = parse_device_response(&decoded).unwrap();

        let mut encoded = Vec::new();
        ciborium::into_writer(resp.device_namespaces, &mut encoded).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "d81841a0",
            "empty DeviceNameSpaces is #6.24(bstr .cbor {{}}) = d81841a0"
        );
        assert!(verify(&f).is_ok());
    }

    // ---- Structural validation of the DeviceResponse ----

    #[test]
    fn a_multi_document_device_response_is_rejected() {
        let f = valid_fixture();
        let tampered = duplicate_first_document(&f.response);
        let decoded = decode_device_response(&tampered).unwrap();
        let err =
            parse_device_response(&decoded).expect_err("more than one document must be rejected");
        assert!(format!("{err}").contains("one document"), "got {err}");
    }

    #[test]
    fn a_nonzero_status_is_rejected() {
        let f = valid_fixture();
        let tampered = set_status(&f.response, 10);
        let decoded = decode_device_response(&tampered).unwrap();
        let err = parse_device_response(&decoded).expect_err("a non-zero status must be rejected");
        assert!(format!("{err}").contains("status"), "got {err}");
    }

    /// A MAC is refused with a typed "unsupported", not a misleading structural
    /// error: foundry accepts only ES256 signatures here.
    #[test]
    fn a_device_mac_is_unsupported() {
        let f = valid_fixture();
        let tampered = replace_device_signature_with_mac(&f.response);
        let decoded = decode_device_response(&tampered).unwrap();
        let err = parse_device_response(&decoded).expect_err("DeviceMac must be unsupported");
        assert!(
            matches!(err, FormatError::Unsupported(ref m) if m.contains("DeviceMac")),
            "got {err}"
        );
    }

    // ---- Defects 3 and 4: the issuer-signed format internals ----

    /// The digest basis, proven against a real wallet's presentation (design doc
    /// §2.3). The negative assertion matters as much as the positive: hashing the
    /// inner CBOR is exactly what foundry used to do.
    #[test]
    fn value_digests_are_computed_over_the_full_tag24_encoding() {
        // First: the two candidate bases are genuinely different, so the
        // assertions below can distinguish them.
        let probe = IssuerSignedItem {
            digest_id: 4,
            random: vec![0xAB; 16],
            element_identifier: "age_over_18".to_string(),
            element_value: ciborium::Value::Bool(true),
        };
        let mut probe_inner = Vec::new();
        ciborium::into_writer(&probe, &mut probe_inner).unwrap();
        let probe_tagged = crate::types::tag24_encode(&probe_inner).unwrap();
        assert_ne!(
            Sha256::digest(&probe_tagged).to_vec(),
            Sha256::digest(&probe_inner).to_vec(),
            "the two digest bases must differ, else this test proves nothing"
        );

        // Then: which one the builder actually committed to, read back out of the
        // MSO it signed.
        let f = valid_fixture();
        let (mso, namespaces) = decode_mso_and_namespaces(&f.response);
        let items = namespaces[0].1.as_array().unwrap();
        let wire_inner = crate::types::tag24_unwrap(&items[0]).unwrap();
        let wire_tagged = crate::types::tag24_encode(wire_inner).unwrap();
        let wire_item: IssuerSignedItem = ciborium::from_reader(wire_inner).unwrap();

        let committed = &mso.value_digests["org.iso.18013.5.1"][&wire_item.digest_id];
        assert_eq!(
            committed,
            &Sha256::digest(&wire_tagged).to_vec(),
            "the builder must digest the full tag-24 encoding"
        );
        assert_ne!(
            committed,
            &Sha256::digest(wire_inner).to_vec(),
            "the builder must not digest the inner CBOR"
        );
    }

    #[test]
    fn an_untagged_namespace_item_is_a_structural_error() {
        let mut f = valid_fixture();
        replace_first_namespace_item_with_untagged_bytes(&mut f.response);

        let err = verify(&f).expect_err("an untagged item must be rejected, not silently skipped");
        assert!(
            format!("{err}").contains("tag 24"),
            "error must name the tag-24 requirement, got: {err}"
        );
    }

    /// The IssuerAuth payload is `MobileSecurityObjectBytes`. Asserting the
    /// two-byte tag-24 head (`d818`) pins the wire form, not just that a
    /// round-trip happens to work.
    #[test]
    fn issuer_auth_payload_is_tag24_wrapped_mso() {
        let f = valid_fixture();
        let payload = issuer_auth_payload(&f.response);
        assert_eq!(
            &payload[..2],
            &[0xd8, 0x18],
            "IssuerAuth payload must begin with CBOR tag 24"
        );
        assert_eq!(parse_wrapped_mso(&payload).version, "1.0");
    }

    #[test]
    fn an_untagged_mso_payload_is_rejected() {
        let mut f = valid_fixture();
        unwrap_issuer_auth_payload_in_place(&mut f.response, &f.leaf_key.clone());

        let err = verify(&f).expect_err("a bare MSO payload must be rejected");
        assert!(
            format!("{err}").contains("tag 24"),
            "error must name the tag-24 requirement, got: {err}"
        );
    }

    // ---- Decisions 9-10: tdate validity and validFrom ----

    #[test]
    fn validity_values_are_cbor_tag0_tdate() {
        let f = valid_fixture();
        let payload = issuer_auth_payload(&f.response);
        let wrapper: ciborium::Value = ciborium::from_reader(payload.as_slice()).unwrap();
        let raw: ciborium::Value =
            ciborium::from_reader(crate::types::tag24_unwrap(&wrapper).unwrap()).unwrap();

        for member in ["signed", "validFrom", "validUntil"] {
            let v = validity_member(&raw, member);
            assert!(
                matches!(v, ciborium::Value::Tag(0, _)),
                "{member} must be CBOR tag 0 (tdate), got {v:?}"
            );
        }
    }

    /// Per design doc §3 decision 2 the verifier is strict: an untagged value must
    /// be refused, not silently accepted. This is the direction a plain `String`
    /// field got wrong — `ciborium` skips unexpected tags, so it accepted a
    /// `tdate` while emitting untagged text.
    #[test]
    fn an_untagged_validity_value_is_rejected() {
        #[derive(serde::Serialize)]
        struct LooseValidity {
            signed: String,
            #[serde(rename = "validFrom")]
            valid_from: String,
            #[serde(rename = "validUntil")]
            valid_until: String,
        }
        let loose = LooseValidity {
            signed: "1970-01-01T00:16:40Z".to_string(),
            valid_from: "1970-01-01T00:16:40Z".to_string(),
            valid_until: "1970-01-01T00:33:20Z".to_string(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&loose, &mut bytes).unwrap();
        let parsed: Result<crate::types::ValidityInfo, _> = ciborium::from_reader(bytes.as_slice());
        assert!(parsed.is_err(), "untagged validity values must be rejected");
    }

    /// `validFrom`, not `signed`, is the lower bound.
    ///
    /// The builder emits `validFrom == signed`, so no builder-produced document
    /// can distinguish the two rules. This rewrites `validFrom` forward — past
    /// `now`, still inside `validUntil` — and re-signs. Under the old
    /// `signed..validUntil` rule that document verifies; under the correct
    /// `validFrom..validUntil` rule it is not yet valid.
    #[test]
    fn validity_window_is_bounded_by_valid_from_not_signed() {
        let mut f = valid_fixture();
        let not_yet = f.now + 60 * 60 * 24 * 30;
        let leaf_key = f.leaf_key.clone();
        rewrite_mso_and_resign(&mut f.response, &leaf_key, |mso| {
            mso.validity_info.valid_from =
                ciborium::tag::Required(format_rfc3339_for_test(not_yet));
        });

        let err =
            verify(&f).expect_err("a document whose validFrom is in the future is not yet valid");
        assert!(matches!(err, FormatError::Expired), "got {err}");

        // Same document, evaluated inside the window: the rejection above is the
        // bound being read, not a document that cannot verify at all.
        assert!(
            verify_mdoc(&f.response, &f.trust_store, &f.transcript, not_yet + 1).is_ok(),
            "inside validFrom..validUntil the same document must verify"
        );
    }

    // ---- Test-only CBOR surgery ----

    fn format_rfc3339_for_test(epoch: u64) -> String {
        time::OffsetDateTime::from_unix_timestamp(epoch as i64)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    /// A near-copy of `build_device_response` that signs the **bare encoded
    /// transcript** instead of `DeviceAuthenticationBytes` — exactly foundry's
    /// pre-fix behaviour.
    ///
    /// Copied rather than parameterised on purpose: the production path must not
    /// carry a "sign it the wrong way" switch.
    fn build_device_response_signing_bare_transcript(
        mdoc: &[u8],
        doc_type: &str,
        device_key: &[u8],
        session_transcript: &ciborium::Value,
    ) -> Vec<u8> {
        let signer = FileSigner::from_pem(device_key, SignatureAlgorithm::Es256).unwrap();
        let mut transcript_bytes = Vec::new();
        ciborium::into_writer(session_transcript, &mut transcript_bytes).unwrap();

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
        let tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            coset::ProtectedHeader {
                original_data: None,
                header: protected.clone(),
            },
            None,
            &[],
            &transcript_bytes,
        );
        let d_sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .signature(signer.sign(&tbs).unwrap())
            .build();
        let d_sig_bytes = coset::CborSerializable::to_vec(d_sign1).unwrap();

        // Assemble the same DeviceResponse shape, differing only in what the
        // signature covers.
        let correct = build_device_response(
            mdoc,
            doc_type,
            &FileSigner::from_pem(device_key, SignatureAlgorithm::Es256).unwrap(),
            session_transcript,
        )
        .unwrap();
        let mut value: ciborium::Value = ciborium::from_reader(correct.as_slice()).unwrap();
        {
            let device_auth = device_auth_mut(&mut value);
            *map_entry_mut(device_auth, "deviceSignature") =
                ciborium::from_reader(d_sig_bytes.as_slice()).unwrap();
        }
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    fn duplicate_first_document(response: &[u8]) -> Vec<u8> {
        let mut value: ciborium::Value = ciborium::from_reader(response).unwrap();
        {
            let outer = value.as_map_mut().unwrap();
            let docs = map_entry_mut(outer, "documents").as_array_mut().unwrap();
            let first = docs[0].clone();
            docs.push(first);
        }
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    fn set_status(response: &[u8], status: i64) -> Vec<u8> {
        let mut value: ciborium::Value = ciborium::from_reader(response).unwrap();
        {
            let outer = value.as_map_mut().unwrap();
            *map_entry_mut(outer, "status") = ciborium::Value::Integer(status.into());
        }
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    fn replace_device_signature_with_mac(response: &[u8]) -> Vec<u8> {
        let mut value: ciborium::Value = ciborium::from_reader(response).unwrap();
        {
            let device_auth = device_auth_mut(&mut value);
            device_auth.clear();
            device_auth.push((
                ciborium::Value::Text("deviceMac".to_string()),
                ciborium::Value::Bytes(vec![0u8; 32]),
            ));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    fn parse_wrapped_mso(payload: &[u8]) -> MobileSecurityObject {
        let wrapper: ciborium::Value = ciborium::from_reader(payload).unwrap();
        let inner = crate::types::tag24_unwrap(&wrapper).unwrap();
        ciborium::from_reader(inner).unwrap()
    }

    fn issuer_auth_payload(response: &[u8]) -> Vec<u8> {
        let mut value: ciborium::Value = ciborium::from_reader(response).unwrap();
        let issuer_signed = issuer_signed_mut(&mut value);
        let issuer_auth = map_entry_mut(issuer_signed, "issuerAuth").clone();
        CoseSign1::from_slice(&cbor_value_to_bytes(&issuer_auth).unwrap())
            .unwrap()
            .payload
            .unwrap()
    }

    fn decode_mso_and_namespaces(
        response: &[u8],
    ) -> (
        MobileSecurityObject,
        Vec<(ciborium::Value, ciborium::Value)>,
    ) {
        let mut value: ciborium::Value = ciborium::from_reader(response).unwrap();
        let issuer_signed = issuer_signed_mut(&mut value);
        let namespaces = map_entry_mut(issuer_signed, "nameSpaces")
            .as_map()
            .unwrap()
            .clone();
        let issuer_auth = map_entry_mut(issuer_signed, "issuerAuth").clone();
        let sign1 = CoseSign1::from_slice(&cbor_value_to_bytes(&issuer_auth).unwrap()).unwrap();
        let mso = parse_wrapped_mso(sign1.payload.as_deref().unwrap());
        (mso, namespaces)
    }

    /// Rewrite the first `nameSpaces` item as a bare byte string, reproducing
    /// foundry's pre-fix wire shape.
    fn replace_first_namespace_item_with_untagged_bytes(response: &mut Vec<u8>) {
        let mut value: ciborium::Value = ciborium::from_reader(response.as_slice()).unwrap();
        {
            let issuer_signed = issuer_signed_mut(&mut value);
            let namespaces = map_entry_mut(issuer_signed, "nameSpaces")
                .as_map_mut()
                .unwrap();
            let items = namespaces[0].1.as_array_mut().unwrap();
            let inner = crate::types::tag24_unwrap(&items[0]).unwrap().to_vec();
            items[0] = ciborium::Value::Bytes(inner);
        }
        response.clear();
        ciborium::into_writer(&value, response).unwrap();
    }

    /// Replace the tag-24 IssuerAuth payload with its inner bytes and **re-sign**,
    /// reproducing exactly what foundry's pre-fix builder emitted: a bare MSO map
    /// under a signature that genuinely covers it.
    ///
    /// Re-signing is required, not incidental. `verify_mdoc` authenticates the
    /// payload bytes before parsing them — which is the correct order, since
    /// parsing unauthenticated CBOR is the thing to avoid — so without a valid
    /// signature this test would fail on the signature and never reach the
    /// structural check it exists to pin.
    fn unwrap_issuer_auth_payload_in_place(response: &mut Vec<u8>, leaf_key: &[u8]) {
        let signer = FileSigner::from_pem(leaf_key, SignatureAlgorithm::Es256).unwrap();
        let mut value: ciborium::Value = ciborium::from_reader(response.as_slice()).unwrap();
        {
            let issuer_signed = issuer_signed_mut(&mut value);
            let slot = map_entry_mut(issuer_signed, "issuerAuth");
            let sign1 = CoseSign1::from_slice(&cbor_value_to_bytes(slot).unwrap()).unwrap();

            let wrapper: ciborium::Value =
                ciborium::from_reader(sign1.payload.as_deref().unwrap()).unwrap();
            let unwrapped = crate::types::tag24_unwrap(&wrapper).unwrap().to_vec();

            let tbs = coset::sig_structure_data(
                coset::SignatureContext::CoseSign1,
                sign1.protected.clone(),
                None,
                &[],
                &unwrapped,
            );
            let rebuilt = coset::CoseSign1Builder::new()
                .protected(sign1.protected.header.clone())
                .unprotected(sign1.unprotected.clone())
                .payload(unwrapped)
                .signature(signer.sign(&tbs).unwrap())
                .build();

            let bytes = coset::CborSerializable::to_vec(rebuilt).unwrap();
            *slot = ciborium::from_reader(bytes.as_slice()).unwrap();
        }
        response.clear();
        ciborium::into_writer(&value, response).unwrap();
    }

    /// Apply `edit` to the MSO, re-wrap it as tag-24 and re-sign, so the document
    /// stays cryptographically valid and only the edited semantics are under test.
    fn rewrite_mso_and_resign(
        response: &mut Vec<u8>,
        leaf_key: &[u8],
        edit: impl FnOnce(&mut MobileSecurityObject),
    ) {
        let signer = FileSigner::from_pem(leaf_key, SignatureAlgorithm::Es256).unwrap();
        let mut value: ciborium::Value = ciborium::from_reader(response.as_slice()).unwrap();
        {
            let issuer_signed = issuer_signed_mut(&mut value);
            let slot = map_entry_mut(issuer_signed, "issuerAuth");
            let sign1 = CoseSign1::from_slice(&cbor_value_to_bytes(slot).unwrap()).unwrap();

            let mut mso = parse_wrapped_mso(sign1.payload.as_deref().unwrap());
            edit(&mut mso);

            let mut inner = Vec::new();
            ciborium::into_writer(&mso, &mut inner).unwrap();
            let payload = crate::types::tag24_encode(&inner).unwrap();

            let tbs = coset::sig_structure_data(
                coset::SignatureContext::CoseSign1,
                sign1.protected.clone(),
                None,
                &[],
                &payload,
            );
            let rebuilt = coset::CoseSign1Builder::new()
                .protected(sign1.protected.header.clone())
                .unprotected(sign1.unprotected.clone())
                .payload(payload)
                .signature(signer.sign(&tbs).unwrap())
                .build();

            let bytes = coset::CborSerializable::to_vec(rebuilt).unwrap();
            *slot = ciborium::from_reader(bytes.as_slice()).unwrap();
        }
        response.clear();
        ciborium::into_writer(&value, response).unwrap();
    }

    fn first_document_mut(
        value: &mut ciborium::Value,
    ) -> &mut Vec<(ciborium::Value, ciborium::Value)> {
        let outer = value.as_map_mut().unwrap();
        let docs = map_entry_mut(outer, "documents").as_array_mut().unwrap();
        docs[0].as_map_mut().unwrap()
    }

    fn issuer_signed_mut(
        value: &mut ciborium::Value,
    ) -> &mut Vec<(ciborium::Value, ciborium::Value)> {
        let doc = first_document_mut(value);
        map_entry_mut(doc, "issuerSigned").as_map_mut().unwrap()
    }

    fn device_auth_mut(
        value: &mut ciborium::Value,
    ) -> &mut Vec<(ciborium::Value, ciborium::Value)> {
        let doc = first_document_mut(value);
        let device_signed = map_entry_mut(doc, "deviceSigned").as_map_mut().unwrap();
        map_entry_mut(device_signed, "deviceAuth")
            .as_map_mut()
            .unwrap()
    }

    fn validity_member<'a>(mso: &'a ciborium::Value, name: &str) -> &'a ciborium::Value {
        let map = mso.as_map().unwrap();
        let validity = map
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "validityInfo"))
            .map(|(_, v)| v)
            .expect("validityInfo")
            .as_map()
            .unwrap();
        validity
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == name))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("validityInfo.{name}"))
    }

    fn map_entry_mut<'a>(
        map: &'a mut [(ciborium::Value, ciborium::Value)],
        key: &str,
    ) -> &'a mut ciborium::Value {
        map.iter_mut()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == key))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("fixture must contain {key}"))
    }
}
