use serde::{Deserialize, Serialize};
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
