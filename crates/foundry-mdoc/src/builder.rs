use crate::error::FormatError;
use crate::types::{DeviceKeyInfo, IssuerSignedItem, MobileSecurityObject, ValidityInfo};
use base64::{
    Engine as _, engine::general_purpose::STANDARD as B64STD,
    engine::general_purpose::URL_SAFE_NO_PAD as B64URL,
};
use coset::{CborSerializable, CoseKeyBuilder, CoseSign1Builder, Header, HeaderBuilder, iana};
use foundry_core::crypto::Signer;
use rand::RngCore;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct MdocClaims {
    pub doc_type: String,
    pub namespaces: BTreeMap<String, BTreeMap<String, JsonValue>>,
    pub device_key_jwk: JsonValue,
    pub signed_at: i64,
    pub valid_until: i64,
}

fn generate_random_salt() -> Vec<u8> {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.to_vec()
}

fn format_epoch_seconds(epoch: i64) -> Result<String, FormatError> {
    let dt = time::OffsetDateTime::from_unix_timestamp(epoch)
        .map_err(|e| FormatError::Serialization(format!("timestamp: {e}")))?;
    dt.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| FormatError::Serialization(format!("rfc3339 format: {e}")))
}

fn cbor_to_value_bytes(bytes: &[u8]) -> Result<ciborium::Value, FormatError> {
    ciborium::from_reader(bytes).map_err(|e| FormatError::Serialization(e.to_string()))
}

fn alg_label(signer: &dyn Signer) -> iana::Algorithm {
    match signer.algorithm() {
        foundry_core::crypto::SignatureAlgorithm::Es256 => iana::Algorithm::ES256,
        foundry_core::crypto::SignatureAlgorithm::Es384 => iana::Algorithm::ES384,
        foundry_core::crypto::SignatureAlgorithm::Es512 => iana::Algorithm::ES512,
    }
}

fn json_to_cbor_value(json: &JsonValue) -> Result<ciborium::Value, FormatError> {
    match json {
        JsonValue::Null => Ok(ciborium::Value::Null),
        JsonValue::Bool(b) => Ok(ciborium::Value::Bool(*b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(ciborium::Value::Integer(i.into()))
            } else if let Some(f) = n.as_f64() {
                Ok(ciborium::Value::Float(f))
            } else {
                Err(FormatError::Serialization("invalid number".into()))
            }
        }
        JsonValue::String(s) => Ok(ciborium::Value::Text(s.clone())),
        JsonValue::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(json_to_cbor_value(v)?);
            }
            Ok(ciborium::Value::Array(out))
        }
        JsonValue::Object(map) => {
            let mut out = Vec::with_capacity(map.len());
            for (k, v) in map {
                out.push((ciborium::Value::Text(k.clone()), json_to_cbor_value(v)?));
            }
            Ok(ciborium::Value::Map(out))
        }
    }
}

/// Builds a signed ISO/IEC 18013-5 mdoc CBOR document.
///
/// `IssuerSignedItem`s and the `MobileSecurityObject` are both carried as tag-24
/// embedded CBOR, and validity timestamps as `tdate` (tag 0); see
/// [`crate::types`] for which of those facts are proven against a real
/// presentation and which are derived.
///
/// The remaining known divergence is the **outer envelope**, not the CBOR inside
/// it: this returns a `DeviceResponse`-shaped wrapper, where OpenID4VCI L2249
/// wants a bare `IssuerSigned` for the credential. That is tracked as a
/// conformance gap rather than fixed here.
pub fn build_mdoc(
    claims: MdocClaims,
    signer: &dyn Signer,
    x5c: Option<Vec<String>>,
) -> Result<Vec<u8>, FormatError> {
    let mut issuer_signed_namespaces: BTreeMap<String, ciborium::Value> = BTreeMap::new();
    let mut value_digests: BTreeMap<String, BTreeMap<u64, Vec<u8>>> = BTreeMap::new();
    let mut digest_id_counter = 0u64;

    for (ns, elements) in claims.namespaces {
        let mut ns_items: Vec<ciborium::Value> = Vec::new();
        let mut digests_map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();

        for (elem_id, elem_val) in elements {
            digest_id_counter += 1;
            let item = IssuerSignedItem {
                digest_id: digest_id_counter,
                random: generate_random_salt(),
                element_identifier: elem_id,
                element_value: json_to_cbor_value(&elem_val)?,
            };
            let mut item_bytes = Vec::new();
            ciborium::into_writer(&item, &mut item_bytes)
                .map_err(|e| FormatError::Serialization(e.to_string()))?;

            // ISO/IEC 18013-5: elements travel as IssuerSignedItemBytes,
            // `#6.24(bstr .cbor IssuerSignedItem)`, and `valueDigests` commits to
            // that FULL tagged encoding — not the inner CBOR. Proven against a
            // real wallet's presentation; see the design doc §2.3.
            let tagged_bytes =
                crate::types::tag24_encode(&item_bytes).map_err(FormatError::Serialization)?;

            let mut hasher = Sha256::new();
            hasher.update(&tagged_bytes);
            digests_map.insert(digest_id_counter, hasher.finalize().to_vec());

            ns_items.push(ciborium::Value::Tag(
                24,
                Box::new(ciborium::Value::Bytes(item_bytes)),
            ));
        }
        value_digests.insert(ns.clone(), digests_map);
        issuer_signed_namespaces.insert(ns, ciborium::Value::Array(ns_items));
    }

    // Device (holder) public key -> COSE_Key.
    let d_kx = claims
        .device_key_jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::InvalidStructure("device_key_jwk missing x".into()))?;
    let d_ky = claims
        .device_key_jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::InvalidStructure("device_key_jwk missing y".into()))?;
    let d_kx_bytes = B64URL
        .decode(d_kx)
        .map_err(|e| FormatError::InvalidStructure(format!("device key x b64: {e}")))?;
    let d_ky_bytes = B64URL
        .decode(d_ky)
        .map_err(|e| FormatError::InvalidStructure(format!("device key y b64: {e}")))?;

    let cose_key =
        CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, d_kx_bytes, d_ky_bytes).build();
    let cose_key_bytes = cose_key
        .to_vec()
        .map_err(|e| FormatError::Serialization(format!("cose key encode: {e}")))?;
    let cose_key_value = cbor_to_value_bytes(&cose_key_bytes)?;

    let mso = MobileSecurityObject {
        version: "1.0".to_string(),
        digest_algorithm: "SHA-256".to_string(),
        doc_type: claims.doc_type.clone(),
        value_digests,
        device_key_info: DeviceKeyInfo {
            device_key: cose_key_value,
        },
        validity_info: ValidityInfo {
            signed: ciborium::tag::Required(format_epoch_seconds(claims.signed_at)?),
            // `MdocClaims` carries no separate validity start, so the document is
            // valid from the moment it was signed. Widen `MdocClaims` if an issuer
            // ever needs to post-date a credential.
            valid_from: ciborium::tag::Required(format_epoch_seconds(claims.signed_at)?),
            valid_until: ciborium::tag::Required(format_epoch_seconds(claims.valid_until)?),
        },
    };

    let mut mso_inner = Vec::new();
    ciborium::into_writer(&mso, &mut mso_inner)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;

    // ISO/IEC 18013-5: the IssuerAuth COSE_Sign1 payload is
    // MobileSecurityObjectBytes = `#6.24(bstr .cbor MobileSecurityObject)`. The
    // signature is computed over these wrapped bytes, so the wrapping must happen
    // before `sig_structure_data`.
    let mso_bytes = crate::types::tag24_encode(&mso_inner).map_err(FormatError::Serialization)?;

    // IssuerAuth COSE_Sign1.
    let protected = HeaderBuilder::new().algorithm(alg_label(signer)).build();

    let mut unprotected = Header::default();
    if let Some(chain) = x5c {
        let mut x5c_values: Vec<ciborium::Value> = Vec::with_capacity(chain.len());
        for cert in chain {
            let der = B64STD
                .decode(cert)
                .map_err(|e| FormatError::InvalidStructure(format!("x5c cert b64: {e}")))?;
            x5c_values.push(ciborium::Value::Bytes(der));
        }
        // Label 33 = x5chain (RFC 9360). TODO(interop): confirm wallet expectations.
        unprotected
            .rest
            .push((coset::Label::Int(33), ciborium::Value::Array(x5c_values)));
    }

    let protected_wrapped = coset::ProtectedHeader {
        original_data: None,
        header: protected.clone(),
    };
    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        protected_wrapped,
        None,
        &[],
        &mso_bytes,
    );
    let signature = signer
        .sign(&tbs)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;

    let final_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(mso_bytes)
        .signature(signature)
        .build();
    let issuer_auth_bytes = final_sign1
        .to_vec()
        .map_err(|e| FormatError::Serialization(format!("issuerAuth encode: {e}")))?;
    let issuer_auth_val = cbor_to_value_bytes(&issuer_auth_bytes)?;

    // Outer mdoc CBOR.
    let issuer_signed: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            ciborium::Value::Text("nameSpaces".to_string()),
            ciborium::Value::Map(
                issuer_signed_namespaces
                    .into_iter()
                    .map(|(k, v)| (ciborium::Value::Text(k), v))
                    .collect(),
            ),
        ),
        (
            ciborium::Value::Text("issuerAuth".to_string()),
            issuer_auth_val,
        ),
    ];

    let doc_map: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            ciborium::Value::Text("docType".to_string()),
            ciborium::Value::Text(claims.doc_type),
        ),
        (
            ciborium::Value::Text("issuerSigned".to_string()),
            ciborium::Value::Map(issuer_signed),
        ),
    ];

    let outer: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            ciborium::Value::Text("version".to_string()),
            ciborium::Value::Text("1.0".to_string()),
        ),
        (
            ciborium::Value::Text("documents".to_string()),
            ciborium::Value::Array(vec![ciborium::Value::Map(doc_map)]),
        ),
    ];

    let mut final_bytes = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(outer), &mut final_bytes)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(final_bytes)
}

/// Build a conformant ISO/IEC 18013-5 `DeviceResponse` around an already-issued
/// mdoc, signing `DeviceAuthenticationBytes` with the holder's key.
///
/// This is the device/holder side of the protocol. foundry is not a wallet, so
/// **production never calls this** — it exists so tests can produce the shape a
/// real wallet sends, instead of asserting that foundry's verifier agrees with
/// foundry's own envelope. That circularity is what hid four format defects; see
/// the design doc §1.4.
///
/// `issuer_signed_mdoc` is [`build_mdoc`]'s output; its `documents[0].issuerSigned`
/// is lifted out and rewrapped with a `deviceSigned` half disclosing nothing.
pub fn build_device_response(
    issuer_signed_mdoc: &[u8],
    doc_type: &str,
    device_signer: &dyn Signer,
    session_transcript: &ciborium::Value,
) -> Result<Vec<u8>, FormatError> {
    let outer: ciborium::Value = ciborium::from_reader(issuer_signed_mdoc)
        .map_err(|e| FormatError::Deserialization(format!("issuer-signed mdoc CBOR: {e}")))?;
    let issuer_signed = outer
        .as_map()
        .and_then(|m| lookup(m, "documents"))
        .and_then(|v| v.as_array())
        .and_then(|docs| docs.first())
        .and_then(|d| d.as_map())
        .and_then(|d| lookup(d, "issuerSigned"))
        .ok_or_else(|| {
            FormatError::InvalidStructure(
                "issuer-signed mdoc missing documents[0].issuerSigned".into(),
            )
        })?
        .clone();

    let device_namespaces = crate::types::empty_device_namespaces();
    let payload =
        crate::types::device_authentication_bytes(session_transcript, doc_type, &device_namespaces)
            .map_err(FormatError::Serialization)?;

    let protected = HeaderBuilder::new()
        .algorithm(alg_label(device_signer))
        .build();
    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        coset::ProtectedHeader {
            original_data: None,
            header: protected.clone(),
        },
        None,
        &[],
        &payload,
    );
    let signature = device_signer
        .sign(&tbs)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;

    // No `.payload()`: the DeviceSignature is a DETACHED-payload COSE_Sign1. The
    // payload is derived from the SessionTranscript, which the verifier already
    // holds, so sending it would be redundant and would let a wallet assert a
    // transcript rather than prove one.
    let device_signature = CoseSign1Builder::new()
        .protected(protected)
        .signature(signature)
        .build();
    let device_signature_bytes = device_signature
        .to_vec()
        .map_err(|e| FormatError::Serialization(format!("deviceSignature encode: {e}")))?;

    let device_auth = ciborium::Value::Map(vec![(
        ciborium::Value::Text("deviceSignature".to_string()),
        cbor_to_value_bytes(&device_signature_bytes)?,
    )]);
    let device_signed = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("nameSpaces".to_string()),
            device_namespaces,
        ),
        (ciborium::Value::Text("deviceAuth".to_string()), device_auth),
    ]);

    let doc = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("docType".to_string()),
            ciborium::Value::Text(doc_type.to_string()),
        ),
        (
            ciborium::Value::Text("issuerSigned".to_string()),
            issuer_signed,
        ),
        (
            ciborium::Value::Text("deviceSigned".to_string()),
            device_signed,
        ),
    ]);

    let response = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("version".to_string()),
            ciborium::Value::Text("1.0".to_string()),
        ),
        (
            ciborium::Value::Text("documents".to_string()),
            ciborium::Value::Array(vec![doc]),
        ),
        (
            ciborium::Value::Text("status".to_string()),
            ciborium::Value::Integer(0.into()),
        ),
    ]);

    let mut bytes = Vec::new();
    ciborium::into_writer(&response, &mut bytes)
        .map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(bytes)
}

fn lookup<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(k, v)| match k {
        ciborium::Value::Text(s) if s == key => Some(v),
        _ => None,
    })
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
    fn builds_mdoc_verifiably() {
        let signer = test_signer();
        let d_jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();

        let mut ns_items = BTreeMap::new();
        let mut elements = BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        elements.insert("family_name".to_string(), serde_json::json!("Doe"));
        ns_items.insert("org.iso.18013.5.1".to_string(), elements);

        let claims = MdocClaims {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces: ns_items,
            device_key_jwk: serde_json::to_value(&d_jwk).unwrap(),
            signed_at: 1700000000,
            valid_until: 1800000000,
        };

        let bytes = build_mdoc(claims, &signer, None).unwrap();
        assert!(!bytes.is_empty());
        let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert!(matches!(decoded, ciborium::Value::Map(_)));
    }
}
