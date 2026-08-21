use crate::error::FormatError;
use crate::types::{Bstr, DeviceKeyInfo, IssuerSignedItem, MobileSecurityObject, ValidityInfo};
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

/// 16 bytes of entropy for an `IssuerSignedItem`'s `random` salt.
///
/// ISO/IEC 18013-5 requires at least 16 bytes and types the member as a `bstr`,
/// hence [`Bstr`] rather than `Vec<u8>` — see that type for why the distinction
/// is load-bearing.
fn generate_random_salt() -> Bstr {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    Bstr(bytes.to_vec())
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

/// The COSE `alg` header label for a JOSE signature algorithm.
///
/// Takes the algorithm rather than the `Signer` that carries it so the mapping
/// is exercisable for every variant without materialising a P-384 or P-521 key;
/// see `alg_label_agrees_with_cose_value` below, which pins it against
/// `SignatureAlgorithm::cose_value` — the single owner of the JOSE/COSE
/// correspondence. The two must agree: OpenID4VCI 1.0 L2223 requires the
/// `credential_signing_alg_values_supported` value an issuer advertises for
/// `mso_mdoc` to match the `alg` in the `IssuerAuth` COSE header this function
/// produces, and nothing else checks that across crate boundaries.
fn alg_label(alg: foundry_core::crypto::SignatureAlgorithm) -> iana::Algorithm {
    match alg {
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
/// Returns the bare `IssuerSigned` structure — `{nameSpaces, issuerAuth}` —
/// which is what OpenID4VCI's mdoc Format Profile (L2249) requires the
/// `credential` claim to carry once base64url-encoded. It is deliberately NOT a
/// `DeviceResponse`: wrapping one is the holder's job, and
/// [`build_device_response`] does it for tests.
pub fn build_mdoc(
    claims: MdocClaims,
    signer: &dyn Signer,
    x5c: Option<Vec<String>>,
) -> Result<Vec<u8>, FormatError> {
    let mut issuer_signed_namespaces: BTreeMap<String, ciborium::Value> = BTreeMap::new();
    let mut value_digests: BTreeMap<String, BTreeMap<u64, Bstr>> = BTreeMap::new();
    let mut digest_id_counter = 0u64;

    for (ns, elements) in claims.namespaces {
        let mut ns_items: Vec<ciborium::Value> = Vec::new();
        let mut digests_map: BTreeMap<u64, Bstr> = BTreeMap::new();

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
            digests_map.insert(digest_id_counter, Bstr(hasher.finalize().to_vec()));

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
    let protected = HeaderBuilder::new()
        .algorithm(alg_label(signer.algorithm()))
        .build();

    let mut unprotected = Header::default();
    if let Some(chain) = x5c {
        let mut ders: Vec<Vec<u8>> = Vec::with_capacity(chain.len());
        for cert in chain {
            ders.push(
                B64STD
                    .decode(cert)
                    .map_err(|e| FormatError::InvalidStructure(format!("x5c cert b64: {e}")))?,
            );
        }

        // Label 33 = x5chain (RFC 9360 §2). The encoding is chosen by cardinality,
        // not by preference: "If a single certificate is conveyed, it is placed in
        // a CBOR byte string", while "if multiple certificates are conveyed, a
        // CBOR array of byte strings is used, with each certificate being in its
        // own byte string." The section's CDDL bounds the array at two:
        //
        //     COSE_X509 = bstr / [ 2*certs: bstr ]
        //
        // so a one-element array is not merely unidiomatic, it is not admitted by
        // the grammar. foundry emitted one unconditionally until now; the fault
        // hid because foundry's verifier accepts both forms, so every round trip
        // through it agreed (crate AGENTS.md: a passing round-trip is not
        // evidence). An empty chain adds no header at all rather than an empty
        // array, which the grammar likewise does not admit.
        let header_value = match ders.len() {
            0 => None,
            1 => ders.pop().map(ciborium::Value::Bytes),
            _ => Some(ciborium::Value::Array(
                ders.into_iter().map(ciborium::Value::Bytes).collect(),
            )),
        };
        if let Some(value) = header_value {
            unprotected.rest.push((coset::Label::Int(33), value));
        }
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

    // IssuerSigned = { nameSpaces, issuerAuth }.
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

    // OpenID4VCI Format Profile / mdoc (L2249): the `credential` claim MUST be
    // the base64url-encoded CBOR `IssuerSigned` structure. This function's
    // output IS that structure — the Credential Endpoint only base64url-encodes
    // it — so the bare `IssuerSigned` is returned, not a `DeviceResponse`
    // wrapper containing one. A wallet following L2249 literally parses these
    // bytes as `IssuerSigned` directly.
    //
    // The `docType` the wrapper used to carry is not lost: it is inside the
    // signed `MobileSecurityObject` above, which is where a verifier must read
    // it from anyway, since the wrapper's copy was unauthenticated.
    let mut final_bytes = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(issuer_signed), &mut final_bytes)
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
/// `issuer_signed_mdoc` is [`build_mdoc`]'s output — a bare `IssuerSigned` — and
/// is wrapped here with a `deviceSigned` half disclosing nothing.
pub fn build_device_response(
    issuer_signed_mdoc: &[u8],
    doc_type: &str,
    device_signer: &dyn Signer,
    session_transcript: &ciborium::Value,
) -> Result<Vec<u8>, FormatError> {
    // `build_mdoc` returns the bare `IssuerSigned` (OpenID4VCI L2249), so there
    // is no wrapper to unpick — this function's whole job is to ADD the
    // DeviceResponse layer a holder sends.
    let issuer_signed: ciborium::Value = ciborium::from_reader(issuer_signed_mdoc)
        .map_err(|e| FormatError::Deserialization(format!("issuer-signed mdoc CBOR: {e}")))?;
    if issuer_signed
        .as_map()
        .and_then(|m| lookup(m, "issuerAuth"))
        .is_none()
    {
        return Err(FormatError::InvalidStructure(
            "issuer-signed mdoc is not an IssuerSigned map carrying issuerAuth".into(),
        ));
    }

    let device_namespaces = crate::types::empty_device_namespaces();
    let payload =
        crate::types::device_authentication_bytes(session_transcript, doc_type, &device_namespaces)
            .map_err(FormatError::Serialization)?;

    let protected = HeaderBuilder::new()
        .algorithm(alg_label(device_signer.algorithm()))
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
    use coset::iana::EnumI64 as _;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};

    fn test_signer() -> FileSigner {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap()
    }

    /// The `alg` this crate writes into the `IssuerAuth` COSE header and the
    /// COSE value `foundry-issuer` advertises in
    /// `credential_signing_alg_values_supported` must be the same number
    /// (OpenID4VCI 1.0 L2223: the advertised value SHOULD exactly match the
    /// `alg` in the `IssuerAuth` COSE header).
    ///
    /// The two are computed in different crates from different types — an
    /// `iana::Algorithm` here, an `i64` in `foundry-core` — so nothing but this
    /// assertion stops them from drifting. Without it, adding a fourth
    /// algorithm to `SignatureAlgorithm` and forgetting one of the two mappings
    /// would ship an issuer that advertises an algorithm it does not sign with.
    #[test]
    fn alg_label_agrees_with_cose_value() {
        for alg in [
            SignatureAlgorithm::Es256,
            SignatureAlgorithm::Es384,
            SignatureAlgorithm::Es512,
        ] {
            assert_eq!(
                alg_label(alg).to_i64(),
                alg.cose_value(),
                "COSE label for {alg} disagrees with SignatureAlgorithm::cose_value"
            );
        }
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

    fn sample_claims() -> MdocClaims {
        let d_jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let mut ns_items = BTreeMap::new();
        let mut elements = BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        ns_items.insert("org.iso.18013.5.1".to_string(), elements);
        MdocClaims {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces: ns_items,
            device_key_jwk: serde_json::to_value(&d_jwk).unwrap(),
            signed_at: 1700000000,
            valid_until: 1800000000,
        }
    }

    /// Read the `issuerAuth` COSE unprotected-header entry at label 33 straight
    /// out of the built CBOR.
    ///
    /// Deliberately does NOT go through `foundry_mdoc::verifier`: the verifier
    /// accepts both encodings, so routing the assertion through it would pass for
    /// either one and prove nothing about what the builder emits. Reading the
    /// bytes is the whole point (crate AGENTS.md: a passing round-trip is not
    /// evidence).
    fn x5chain_header(mdoc: &[u8]) -> ciborium::Value {
        let outer: ciborium::Value = ciborium::from_reader(mdoc).unwrap();
        let issuer_auth = outer
            .as_map()
            .and_then(|m| lookup(m, "issuerAuth"))
            .expect("issuerAuth is present at the IssuerSigned top level")
            .clone();

        // COSE_Sign1 = [protected, unprotected, payload, signature].
        let sign1 = issuer_auth
            .as_array()
            .expect("issuerAuth is a COSE_Sign1 array");
        sign1[1]
            .as_map()
            .expect("the COSE unprotected header is a map")
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Integer(i) if i128::from(*i) == 33 => Some(v.clone()),
                _ => None,
            })
            .expect("x5chain label 33 is present when a chain was supplied")
    }

    /// RFC 9360 §2 keys the `x5chain` encoding to cardinality, and its CDDL is
    /// `COSE_X509 = bstr / [ 2*certs: bstr ]` — the array's lower bound is TWO.
    /// A single certificate therefore has exactly one conformant encoding: the
    /// bare byte string. A one-element array is not a stylistic choice, it is
    /// output the grammar does not admit.
    ///
    /// This asserts on emitted bytes rather than on a round trip through
    /// foundry's verifier, which accepts both forms; the verifier's leniency is
    /// exactly what let non-conformant output go unnoticed.
    #[test]
    fn single_certificate_x5chain_is_a_bare_byte_string() {
        let signer = test_signer();
        let der = vec![0xAAu8; 40];
        let chain = vec![B64STD.encode(&der)];

        let bytes = build_mdoc(sample_claims(), &signer, Some(chain)).unwrap();

        match x5chain_header(&bytes) {
            ciborium::Value::Bytes(b) => assert_eq!(
                b, der,
                "the bare byte string must be the certificate's DER verbatim"
            ),
            ciborium::Value::Array(items) => panic!(
                "a single-certificate x5chain must be a bare byte string, not a \
                 {}-element array: `COSE_X509 = bstr / [ 2*certs: bstr ]` admits no \
                 array shorter than two",
                items.len()
            ),
            other => panic!("unexpected x5chain encoding: {other:?}"),
        }
    }

    /// The other half of the same dichotomy: two or more certificates take the
    /// array form, each in its own byte string, ordered leaf-first.
    #[test]
    fn multi_certificate_x5chain_is_an_array_of_byte_strings() {
        let signer = test_signer();
        let leaf = vec![0x11u8; 30];
        let issuer = vec![0x22u8; 31];
        let chain = vec![B64STD.encode(&leaf), B64STD.encode(&issuer)];

        let bytes = build_mdoc(sample_claims(), &signer, Some(chain)).unwrap();

        let items = match x5chain_header(&bytes) {
            ciborium::Value::Array(items) => items,
            other => panic!("a two-certificate x5chain must be an array, got {other:?}"),
        };
        let ders: Vec<Vec<u8>> = items
            .iter()
            .map(|i| {
                i.as_bytes()
                    .expect("each array member is a byte string")
                    .clone()
            })
            .collect();
        assert_eq!(
            ders,
            vec![leaf, issuer],
            "the chain must stay ordered leaf-first"
        );
    }

    /// OpenID4VCI Format Profile / mdoc (L2249): "The `credential` claim MUST be
    /// the base64url-encoded CBOR `IssuerSigned` structure." `build_mdoc`'s
    /// output IS that structure — the Credential Endpoint only base64url-encodes
    /// it — so the top level must be `IssuerSigned` itself, `{nameSpaces,
    /// issuerAuth}`, and not a `DeviceResponse` that merely contains one.
    ///
    /// Reads the CBOR directly and deliberately does NOT call
    /// `foundry_mdoc::verifier`. The verifier parses a `DeviceResponse`, which
    /// `build_device_response` still produces, so a round trip is blind to this
    /// distinction and would pass for either envelope (crate AGENTS.md: a
    /// passing round-trip is not evidence).
    #[test]
    fn build_mdoc_emits_a_bare_issuer_signed_not_a_device_response() {
        let signer = test_signer();
        let bytes = build_mdoc(sample_claims(), &signer, None).unwrap();

        let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let map = decoded.as_map().expect("IssuerSigned is a CBOR map");

        let keys: Vec<&str> = map
            .iter()
            .filter_map(|(k, _)| match k {
                ciborium::Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();

        assert_eq!(
            keys,
            vec!["nameSpaces", "issuerAuth"],
            "IssuerSigned carries exactly nameSpaces and issuerAuth at the top level"
        );
        assert!(
            !keys.contains(&"documents")
                && !keys.contains(&"version")
                && !keys.contains(&"docType"),
            "a DeviceResponse wrapper is one layer too many for L2249, got {keys:?}"
        );
    }
}
