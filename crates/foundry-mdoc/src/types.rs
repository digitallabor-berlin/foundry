use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// MobileSecurityObject (ISO/IEC 18013-5 §9.1.2.4).
///
/// Transported as `MobileSecurityObjectBytes` = `#6.24(bstr .cbor
/// MobileSecurityObject)` in the IssuerAuth COSE_Sign1 payload. The tag-24
/// wrapper is applied and stripped at the call sites rather than by this type,
/// because the IssuerAuth signature is computed over the **wrapped** bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MobileSecurityObject {
    pub version: String,
    #[serde(rename = "digestAlgorithm")]
    pub digest_algorithm: String,
    #[serde(rename = "docType")]
    pub doc_type: String,
    #[serde(rename = "valueDigests")]
    pub value_digests: BTreeMap<String, BTreeMap<u64, Vec<u8>>>,
    #[serde(rename = "deviceKeyInfo")]
    pub device_key_info: DeviceKeyInfo,
    #[serde(rename = "validityInfo")]
    pub validity_info: ValidityInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceKeyInfo {
    #[serde(rename = "deviceKey")]
    pub device_key: ciborium::Value,
}

/// ValidityInfo (ISO/IEC 18013-5 §9.1.2.4).
///
/// All three members are `tdate` — CBOR tag 0 over an RFC 3339 text string.
/// [`ciborium::tag::Required`] requires the tag on deserialization and always
/// emits it on serialization, so builder and verifier cannot drift and an
/// untagged value is refused rather than silently accepted (design doc §3
/// decision 2).
///
/// Note `ciborium` skips unexpected tags in its typed deserializers, so a plain
/// `String` field would have *accepted* a `tdate` while emitting an untagged
/// value — a silent one-way divergence. The wrapper is what closes it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidityInfo {
    pub signed: ciborium::tag::Required<String, 0>,
    /// The start of the document's validity window. Distinct from `signed`,
    /// which records when the MSO was signed and does not bound validity.
    #[serde(rename = "validFrom")]
    pub valid_from: ciborium::tag::Required<String, 0>,
    #[serde(rename = "validUntil")]
    pub valid_until: ciborium::tag::Required<String, 0>,
}

/// IssuerSignedItem (ISO/IEC 18013-5 §9.1.2.5).
///
/// Always transported as `IssuerSignedItemBytes` = `#6.24(bstr .cbor
/// IssuerSignedItem)`, and `valueDigests` commits to that **full tagged
/// encoding**. Use [`tag24_encode`] / [`tag24_unwrap`] on both sides so the two
/// cannot drift. Proven against a real presentation; see the design doc §2.3.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IssuerSignedItem {
    #[serde(rename = "digestID")]
    pub digest_id: u64,
    pub random: Vec<u8>,
    #[serde(rename = "elementIdentifier")]
    pub element_identifier: String,
    #[serde(rename = "elementValue")]
    pub element_value: ciborium::Value,
}

/// Which OpenID4VP invocation method a `SessionTranscript` is being built for.
///
/// The two variants are **not** interchangeable: they differ in the fixed
/// identifier string, in the number and meaning of the `…HandoverInfo`
/// elements, and therefore in the hash the Device Signature commits to. Using
/// the wrong one yields a transcript no conformant wallet's signature can
/// verify against, which is exactly the defect GAP-VP-06 recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionTranscriptParams {
    /// OpenID4VP 1.0 — Format / mdoc / Invocation via Redirects (L2829-L2873).
    Redirect {
        /// The `client_id` request parameter, including its Client Identifier
        /// Prefix where applicable (L2868).
        client_id: String,
        /// The `nonce` request parameter (L2869).
        nonce: String,
        /// RFC 7638 SHA-256 thumbprint of the Verifier's response-encryption
        /// public key when the response is encrypted (e.g. `direct_post.jwt`);
        /// `None` encodes CBOR `null` (L2870).
        jwk_thumbprint: Option<[u8; 32]>,
        /// The `response_uri` or `redirect_uri` request parameter, whichever
        /// the Response Mode makes present (L2871). foundry only ever issues
        /// `response_uri`.
        response_uri: String,
    },
    /// OpenID4VP 1.0 — Format / mdoc / Invocation via the Digital Credentials
    /// API (L2959-L2999).
    DcApi {
        /// The request's Origin. MUST NOT carry the `origin:` prefix (L2997);
        /// that prefix belongs to the KB-JWT audience, a different mechanism.
        origin: String,
        /// The `nonce` request parameter (L2998).
        nonce: String,
        /// RFC 7638 SHA-256 thumbprint of the Verifier's response-encryption
        /// public key for Response Mode `dc_api.jwt`; `None` encodes CBOR
        /// `null` for `dc_api` (L2999).
        jwk_thumbprint: Option<[u8; 32]>,
    },
}

/// Build the OpenID4VP `SessionTranscript` that a Device Signature is computed
/// over.
///
/// This is the ISO/IEC 18013-5 §9.1.5.1 `SessionTranscript` with the OpenID4VP
/// changes (L2825-L2833 for redirects, L2955-L2963 for the DC API):
/// `DeviceEngagementBytes` and `EReaderKeyBytes` are both `null`, and
/// `Handover` is the invocation-specific structure
///
/// ```cddl
/// OpenID4VPHandover      = [ "OpenID4VPHandover",      bstr ]  ; L2836-L2839
/// OpenID4VPDCAPIHandover = [ "OpenID4VPDCAPIHandover", bstr ]  ; L2966-L2969
/// ```
///
/// where the second element is the SHA-256 hash of the CBOR-encoded
/// `…HandoverInfo` array — the **plain** encoding, with no tag-24 wrapper and
/// no enclosing byte string.
///
/// That reading is not self-evident from the prose ("the sha-256 hash of the
/// bytes of `OpenID4VPHandoverInfo` when encoded as CBOR" is equally
/// compatible with a tag-24 embedding). It was settled against the spec's own
/// published vectors rather than by interpretation, and this module's tests
/// assert those vectors byte-for-byte so the decision cannot silently drift.
pub fn session_transcript_value(
    params: &SessionTranscriptParams,
) -> Result<ciborium::Value, String> {
    let (identifier, info) = handover_info(params);
    let info_bytes = encode_cbor(&info)?;

    let handover = ciborium::Value::Array(vec![
        ciborium::Value::Text(identifier.to_string()),
        ciborium::Value::Bytes(Sha256::digest(&info_bytes).to_vec()),
    ]);

    // SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ],
    // the first two pinned to null by OpenID4VP (L2831-L2832, L2961-L2962).
    Ok(ciborium::Value::Array(vec![
        ciborium::Value::Null,
        ciborium::Value::Null,
        handover,
    ]))
}

/// The encoded form of [`session_transcript_value`].
///
/// Both forms exist because they serve different consumers: this one is pinned
/// against OpenID4VP's published hex vectors, while `DeviceAuthentication`
/// element [1] needs the `Value` so the transcript can be spliced **by value**
/// with no decode/re-encode round trip (design doc §2.1).
pub fn build_session_transcript(params: &SessionTranscriptParams) -> Result<Vec<u8>, String> {
    encode_cbor(&session_transcript_value(params)?)
}

/// The fixed identifier and the `…HandoverInfo` array for `params`.
///
/// Split out from [`build_session_transcript`] so tests can pin the
/// intermediate encoding: when a vector fails, this localises the regression to
/// the info array or to the hash/wrapper instead of reporting "bytes differ".
fn handover_info(params: &SessionTranscriptParams) -> (&'static str, ciborium::Value) {
    match params {
        SessionTranscriptParams::Redirect {
            client_id,
            nonce,
            jwk_thumbprint,
            response_uri,
        } => (
            "OpenID4VPHandover",
            // OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint,
            // responseUri] (L2846-L2851, ordering per L2868-L2871).
            ciborium::Value::Array(vec![
                ciborium::Value::Text(client_id.clone()),
                ciborium::Value::Text(nonce.clone()),
                thumbprint_value(jwk_thumbprint),
                ciborium::Value::Text(response_uri.clone()),
            ]),
        ),
        SessionTranscriptParams::DcApi {
            origin,
            nonce,
            jwk_thumbprint,
        } => (
            "OpenID4VPDCAPIHandover",
            // OpenID4VPDCAPIHandoverInfo = [origin, nonce, jwkThumbprint]
            // (L2976-L2980, ordering per L2997-L2999).
            ciborium::Value::Array(vec![
                ciborium::Value::Text(origin.clone()),
                ciborium::Value::Text(nonce.clone()),
                thumbprint_value(jwk_thumbprint),
            ]),
        ),
    }
}

/// An absent thumbprint is CBOR `null`, never an omitted element and never an
/// empty byte string (L2870, L2999).
fn thumbprint_value(jwk_thumbprint: &Option<[u8; 32]>) -> ciborium::Value {
    match jwk_thumbprint {
        Some(bytes) => ciborium::Value::Bytes(bytes.to_vec()),
        None => ciborium::Value::Null,
    }
}

fn encode_cbor(value: &ciborium::Value) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// A human-readable CBOR type name, for error messages only.
fn cbor_type_name(value: &ciborium::Value) -> &'static str {
    match value {
        ciborium::Value::Integer(_) => "integer",
        ciborium::Value::Bytes(_) => "byte string",
        ciborium::Value::Float(_) => "float",
        ciborium::Value::Text(_) => "text string",
        ciborium::Value::Bool(_) => "boolean",
        ciborium::Value::Null => "null",
        ciborium::Value::Tag(..) => "tag",
        ciborium::Value::Array(_) => "array",
        ciborium::Value::Map(_) => "map",
        _ => "unknown",
    }
}

/// Wrap pre-encoded CBOR as `#6.24(bstr .cbor …)` and return the **full tagged
/// encoding**.
///
/// That full encoding — not the inner CBOR — is what ISO/IEC 18013-5 digests in
/// `valueDigests` and signs in `DeviceAuthenticationBytes`. Proven against a
/// real wallet's presentation; see the design doc §2.3.
pub fn tag24_encode(inner_cbor: &[u8]) -> Result<Vec<u8>, String> {
    encode_cbor(&ciborium::Value::Tag(
        24,
        Box::new(ciborium::Value::Bytes(inner_cbor.to_vec())),
    ))
}

/// Unwrap `#6.24(bstr …)` to its inner CBOR bytes.
///
/// Every non-tag-24 shape is an error rather than a skip. Returning `None` for
/// an untagged value is precisely how foundry silently dropped every disclosed
/// element and then reported a DCQL mismatch instead (design doc §1.6).
pub fn tag24_unwrap(value: &ciborium::Value) -> Result<&[u8], String> {
    match value {
        ciborium::Value::Tag(24, inner) => match inner.as_ref() {
            ciborium::Value::Bytes(b) => Ok(b.as_slice()),
            other => Err(format!(
                "CBOR tag 24 must wrap a byte string, got {}",
                cbor_type_name(other)
            )),
        },
        ciborium::Value::Tag(other, _) => Err(format!("expected CBOR tag 24, got tag {other}")),
        other => Err(format!(
            "expected CBOR tag 24 embedded CBOR, got {}",
            cbor_type_name(other)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `jwkThumbprint` byte string shared by both published
    /// `…HandoverInfo` vectors — the RFC 7638 thumbprint of the example JWK at
    /// spec L2878-L2886. `foundry_core::obs` asserts independently that this
    /// is what that JWK actually hashes to.
    fn thumbprint_fixture() -> [u8; 32] {
        let bytes = hex::decode("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047")
            .expect("fixture is valid hex");
        bytes.try_into().expect("thumbprint is 32 bytes")
    }

    const SPEC_NONCE: &str = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";

    /// Strip whitespace from a hex vector so the spec's published blocks can be
    /// transcribed **verbatim**, line breaks and all.
    ///
    /// The first draft of these tests re-joined the spec's wrapped hex by hand
    /// and silently transposed four characters, producing a test that failed
    /// against correct code. Pasting the spec's own layout removes that class
    /// of error and lets a reviewer diff these literals against the spec
    /// line-for-line.
    fn spec_hex(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// OpenID4VP 1.0's published worked example for invocation via redirects
    /// (spec L2888-L2950).
    ///
    /// The intermediate `OpenID4VPHandoverInfo` is asserted alongside the final
    /// `SessionTranscript` deliberately: if only the transcript were checked, a
    /// regression would report "bytes differ" without saying whether the info
    /// array or the hash/wrapper drifted.
    #[test]
    fn redirect_session_transcript_matches_openid4vp_vector() {
        let params = SessionTranscriptParams::Redirect {
            client_id: "x509_san_dns:example.com".to_string(),
            nonce: SPEC_NONCE.to_string(),
            jwk_thumbprint: Some(thumbprint_fixture()),
            response_uri: "https://example.com/response".to_string(),
        };

        let (identifier, info) = handover_info(&params);
        assert_eq!(identifier, "OpenID4VPHandover", "L2865: fixed identifier");
        assert_eq!(
            hex::encode(encode_cbor(&info).expect("info encodes")),
            spec_hex(
                "847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767
                 426b786a7831726463397564527276654b7653734a4971383061766c58654c486847
                 7771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6
                 bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365"
            ),
            "OpenID4VPHandoverInfo must match the spec vector at L2890-L2910"
        );

        assert_eq!(
            hex::encode(build_session_transcript(&params).expect("transcript encodes")),
            spec_hex(
                "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e
                 ed494cefdd9d95240d254b046b11b68013722aad38ac"
            ),
            "SessionTranscript must match the spec vector at L2937-L2950"
        );
    }

    /// OpenID4VP 1.0's published worked example for invocation via the Digital
    /// Credentials API (spec L3013-L3075).
    #[test]
    fn dc_api_session_transcript_matches_openid4vp_vector() {
        let params = SessionTranscriptParams::DcApi {
            origin: "https://example.com".to_string(),
            nonce: SPEC_NONCE.to_string(),
            jwk_thumbprint: Some(thumbprint_fixture()),
        };

        let (identifier, info) = handover_info(&params);
        assert_eq!(
            identifier, "OpenID4VPDCAPIHandover",
            "L2994: fixed identifier"
        );
        assert_eq!(
            hex::encode(encode_cbor(&info).expect("info encodes")),
            spec_hex(
                "837368747470733a2f2f6578616d706c652e636f6d782b6578633767426b786a7831
                 726463397564527276654b7653734a4971383061766c58654c486847777174415820
                 4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
            ),
            "OpenID4VPDCAPIHandoverInfo must match the spec vector at L3015-L3035"
        );

        assert_eq!(
            hex::encode(build_session_transcript(&params).expect("transcript encodes")),
            spec_hex(
                "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4
                 212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
            ),
            "SessionTranscript must match the spec vector at L3062-L3075"
        );
    }

    /// L2870 (redirects) / L2999 (DC API): when the response is not encrypted
    /// the third `…HandoverInfo` element MUST be `null` — not an omitted
    /// element, and not an empty byte string.
    #[test]
    fn absent_thumbprint_encodes_as_cbor_null_not_omission() {
        for params in [
            SessionTranscriptParams::DcApi {
                origin: "https://example.com".to_string(),
                nonce: SPEC_NONCE.to_string(),
                jwk_thumbprint: None,
            },
            SessionTranscriptParams::Redirect {
                client_id: "x509_san_dns:example.com".to_string(),
                nonce: SPEC_NONCE.to_string(),
                jwk_thumbprint: None,
                response_uri: "https://example.com/response".to_string(),
            },
        ] {
            let expected_len = match params {
                SessionTranscriptParams::DcApi { .. } => 3,
                SessionTranscriptParams::Redirect { .. } => 4,
            };
            let (_, info) = handover_info(&params);
            let arr = match &info {
                ciborium::Value::Array(a) => a,
                other => panic!("HandoverInfo must be an array, got {other:?}"),
            };
            assert_eq!(
                arr.len(),
                expected_len,
                "the thumbprint element must be present, never omitted"
            );
            assert!(
                matches!(arr[2], ciborium::Value::Null),
                "an absent thumbprint MUST encode as CBOR null, got {:?}",
                arr[2]
            );
        }
    }

    /// The two invocation methods must never produce the same transcript for
    /// otherwise-equivalent inputs, or a Device Signature bound to one would
    /// verify against the other.
    #[test]
    fn redirect_and_dc_api_transcripts_are_distinct() {
        let redirect = build_session_transcript(&SessionTranscriptParams::Redirect {
            client_id: "https://example.com".to_string(),
            nonce: SPEC_NONCE.to_string(),
            jwk_thumbprint: None,
            response_uri: "https://example.com".to_string(),
        })
        .expect("encodes");
        let dc_api = build_session_transcript(&SessionTranscriptParams::DcApi {
            origin: "https://example.com".to_string(),
            nonce: SPEC_NONCE.to_string(),
            jwk_thumbprint: None,
        })
        .expect("encodes");
        assert_ne!(
            redirect, dc_api,
            "the invocation method must be committed to by the transcript"
        );
    }

    /// The thumbprint must actually be committed to, not accepted and dropped.
    #[test]
    fn thumbprint_changes_the_transcript() {
        let with = build_session_transcript(&SessionTranscriptParams::DcApi {
            origin: "https://example.com".to_string(),
            nonce: SPEC_NONCE.to_string(),
            jwk_thumbprint: Some(thumbprint_fixture()),
        })
        .expect("encodes");
        let without = build_session_transcript(&SessionTranscriptParams::DcApi {
            origin: "https://example.com".to_string(),
            nonce: SPEC_NONCE.to_string(),
            jwk_thumbprint: None,
        })
        .expect("encodes");
        assert_ne!(with, without, "jwkThumbprint must affect the hash");
    }

    #[test]
    fn tag24_round_trips_and_matches_the_captured_wire_bytes() {
        // An empty CBOR map (`a0`) wrapped as #6.24(bstr) is `d81841a0` — the
        // exact bytes a real wallet sends for an empty `deviceSigned.nameSpaces`
        // (design doc §2.3).
        let inner = hex::decode("a0").expect("valid hex");
        let tagged = tag24_encode(&inner).expect("encodes");
        assert_eq!(hex::encode(&tagged), "d81841a0");

        let value: ciborium::Value = ciborium::from_reader(tagged.as_slice()).expect("decodes");
        assert_eq!(tag24_unwrap(&value).expect("unwraps"), inner.as_slice());
    }

    #[test]
    fn tag24_unwrap_rejects_untagged_and_wrongly_tagged_values() {
        // Silence here is what made design doc defect 4 invisible: an untagged
        // item must be an error, never a skip.
        let bare = ciborium::Value::Bytes(vec![0xa0]);
        assert!(tag24_unwrap(&bare).is_err(), "a bare bstr is not tag-24");

        let wrong_tag = ciborium::Value::Tag(0, Box::new(ciborium::Value::Bytes(vec![0xa0])));
        assert!(tag24_unwrap(&wrong_tag).is_err(), "tag 0 is not tag 24");

        let tag24_over_text = ciborium::Value::Tag(24, Box::new(ciborium::Value::Text("x".into())));
        assert!(
            tag24_unwrap(&tag24_over_text).is_err(),
            "tag 24 must wrap a byte string"
        );
    }

    #[test]
    fn session_transcript_value_encodes_to_the_byte_form() {
        // The `Value` form and the byte form must never diverge: the byte form
        // is pinned against OpenID4VP's published vectors, and the `Value` form
        // is what DeviceAuthentication element [1] is spliced from.
        let params = SessionTranscriptParams::DcApi {
            origin: "https://verifier.example.com".to_string(),
            nonce: SPEC_NONCE.to_string(),
            jwk_thumbprint: Some(thumbprint_fixture()),
        };
        let as_value = session_transcript_value(&params).expect("value");
        let mut encoded = Vec::new();
        ciborium::into_writer(&as_value, &mut encoded).expect("encodes");
        assert_eq!(
            encoded,
            build_session_transcript(&params).expect("bytes"),
            "session_transcript_value and build_session_transcript must agree"
        );
    }
}
