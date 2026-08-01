use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// MobileSecurityObject (ISO/IEC 18013-5 §9.1.2.4).
/// TODO(interop): payload is not tag-24 embedded-CBOR wrapped.
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

/// TODO(interop): should be CBOR `tdate` (tag 0), not plain text.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidityInfo {
    pub signed: String,
    #[serde(rename = "validUntil")]
    pub valid_until: String,
}

/// IssuerSignedItem (ISO/IEC 18013-5 §9.1.2.5).
/// TODO(interop): should be transported as tag-24 embedded CBOR.
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
pub fn build_session_transcript(params: &SessionTranscriptParams) -> Result<Vec<u8>, String> {
    let (identifier, info) = handover_info(params);
    let info_bytes = encode_cbor(&info)?;

    let handover = ciborium::Value::Array(vec![
        ciborium::Value::Text(identifier.to_string()),
        ciborium::Value::Bytes(Sha256::digest(&info_bytes).to_vec()),
    ]);

    // SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ],
    // the first two pinned to null by OpenID4VP (L2831-L2832, L2961-L2962).
    encode_cbor(&ciborium::Value::Array(vec![
        ciborium::Value::Null,
        ciborium::Value::Null,
        handover,
    ]))
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

/// SessionTranscript for OpenID4VP handover.
/// TODO(interop): simplified handover; not the hashed OID4VPHandover from 18013-7.
pub fn serialize_session_transcript(
    client_id: Option<String>,
    response_uri: Option<String>,
    nonce: String,
) -> Result<Vec<u8>, String> {
    let handover = if let (Some(cid), Some(ruri)) = (client_id, response_uri) {
        ciborium::Value::Array(vec![
            ciborium::Value::Text(cid),
            ciborium::Value::Text(ruri),
            ciborium::Value::Text(nonce),
        ])
    } else {
        ciborium::Value::Array(vec![
            ciborium::Value::Text("https://localhost:8443".to_string()),
            ciborium::Value::Text(nonce),
        ])
    };
    let transcript =
        ciborium::Value::Array(vec![ciborium::Value::Null, ciborium::Value::Null, handover]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&transcript, &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
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
}
