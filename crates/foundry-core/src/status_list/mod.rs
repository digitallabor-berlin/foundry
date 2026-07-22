//! Token Status List (IETF draft-ietf-oauth-status-list-14): bit-packed
//! status arrays, zlib compression, and signed Status List Tokens.

use crate::crypto::Signer;
use crate::error::FormatError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use serde_json::{json, Value};

/// A Referenced Token's status (draft-ietf-oauth-status-list-14 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusValue {
    Valid,
    Invalid,
    Suspended,
    ApplicationSpecific(u8),
}

impl StatusValue {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => StatusValue::Valid,
            0x01 => StatusValue::Invalid,
            0x02 => StatusValue::Suspended,
            other => StatusValue::ApplicationSpecific(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            StatusValue::Valid => 0x00,
            StatusValue::Invalid => 0x01,
            StatusValue::Suspended => 0x02,
            StatusValue::ApplicationSpecific(v) => v,
        }
    }
}

fn checked_bits(bits: u8) -> Result<(), FormatError> {
    if matches!(bits, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(FormatError::Unsupported(format!(
            "status list bits must be 1, 2, 4, or 8 (got {bits})"
        )))
    }
}

/// Pack per-token status values into the uncompressed byte array described
/// in draft-ietf-oauth-status-list-14 §4.1: statuses are packed `bits`-wide,
/// index 0 first, least-significant bit first within each byte.
pub fn pack_status_array(values: &[u8], bits: u8) -> Result<Vec<u8>, FormatError> {
    checked_bits(bits)?;
    let max_value = ((1u16 << bits) - 1) as u8;
    for &v in values {
        if v > max_value {
            return Err(FormatError::InvalidStructure(format!(
                "status value {v} does not fit in {bits} bits"
            )));
        }
    }
    let per_byte = 8 / bits as usize;
    let len = values.len().div_ceil(per_byte);
    let mut out = vec![0u8; len];
    for (idx, &v) in values.iter().enumerate() {
        let byte_idx = idx / per_byte;
        let bit_offset = (idx % per_byte) * bits as usize;
        out[byte_idx] |= v << bit_offset;
    }
    Ok(out)
}

/// Extract the `bits`-wide status value for `idx` from an uncompressed
/// status byte array (the inverse of `pack_status_array`).
pub fn unpack_status(byte_array: &[u8], bits: u8, idx: u64) -> Result<u8, FormatError> {
    checked_bits(bits)?;
    let per_byte = (8 / bits as usize) as u64;
    let byte_idx = (idx / per_byte) as usize;
    let byte = byte_array
        .get(byte_idx)
        .ok_or(FormatError::StatusIndexOutOfBounds {
            idx,
            len: byte_array.len() as u64 * per_byte,
        })?;
    let bit_offset = ((idx % per_byte) * bits as u64) as u32;
    let mask = ((1u16 << bits) - 1) as u8;
    Ok((byte >> bit_offset) & mask)
}

/// zlib-compress (RFC 1950 wrapping RFC 1951 DEFLATE) at the highest
/// compression level, per draft-ietf-oauth-status-list-14 §4.1 step 5.
pub fn compress_zlib(raw: &[u8]) -> Result<Vec<u8>, FormatError> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(raw)
        .map_err(|e| FormatError::Serialization(format!("zlib compress: {e}")))?;
    encoder
        .finish()
        .map_err(|e| FormatError::Serialization(format!("zlib compress: {e}")))
}

/// zlib-decompress the inverse of `compress_zlib`.
pub fn decompress_zlib(compressed: &[u8]) -> Result<Vec<u8>, FormatError> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    
    let mut decoder = ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| FormatError::Deserialization(format!("zlib decompress: {e}")))?;
    Ok(out)
}

/// A Status List per draft-ietf-oauth-status-list-14 §4.2 (JSON encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList {
    pub bits: u8,
    pub lst_b64url: String,
    pub aggregation_uri: Option<String>,
}

impl StatusList {
    /// Build a Status List from per-token status values.
    pub fn build(
        values: &[u8],
        bits: u8,
        aggregation_uri: Option<String>,
    ) -> Result<Self, FormatError> {
        let raw = pack_status_array(values, bits)?;
        let compressed = compress_zlib(&raw)?;
        Ok(Self {
            bits,
            lst_b64url: B64URL.encode(compressed),
            aggregation_uri,
        })
    }

    /// Decompress `lst` back into the raw, unpacked-ready byte array.
    pub fn decode_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let compressed = B64URL
            .decode(&self.lst_b64url)
            .map_err(|e| FormatError::Deserialization(format!("lst base64: {e}")))?;
        decompress_zlib(&compressed)
    }

    /// Look up a single Referenced Token's status by index.
    pub fn status_at(&self, idx: u64) -> Result<StatusValue, FormatError> {
        let raw = self.decode_bytes()?;
        let v = unpack_status(&raw, self.bits, idx)?;
        Ok(StatusValue::from_u8(v))
    }

    pub fn to_json(&self) -> Value {
        let mut obj = json!({ "bits": self.bits, "lst": self.lst_b64url });
        if let Some(uri) = &self.aggregation_uri {
            obj["aggregation_uri"] = json!(uri);
        }
        obj
    }

    pub fn from_json(value: &Value) -> Result<Self, FormatError> {
        let bits = value
            .get("bits")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| FormatError::InvalidStructure("status_list.bits missing".into()))?
            as u8;
        let lst_b64url = value
            .get("lst")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormatError::InvalidStructure("status_list.lst missing".into()))?
            .to_string();
        let aggregation_uri = value
            .get("aggregation_uri")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok(Self {
            bits,
            lst_b64url,
            aggregation_uri,
        })
    }
}

/// Claims for a Status List Token, excluding the `status_list` body itself
/// (draft-ietf-oauth-status-list-14 §5.1).
pub struct StatusListTokenClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: Option<i64>,
    pub ttl: Option<i64>,
}

fn b64url_json(value: &Value) -> Result<String, FormatError> {
    let bytes = serde_json::to_vec(value).map_err(|e| FormatError::Serialization(e.to_string()))?;
    Ok(B64URL.encode(bytes))
}

/// Build and sign a Status List Token (compact JWS, `typ: statuslist+jwt`)
/// per draft-ietf-oauth-status-list-14 §5.1.
pub fn build_status_list_token(
    claims: StatusListTokenClaims,
    status_list: &StatusList,
    signer: &dyn Signer,
    x5c: Option<Vec<String>>,
) -> Result<String, FormatError> {
    let mut header = serde_json::Map::new();
    header.insert(
        "alg".into(),
        Value::String(signer.algorithm().as_str().to_string()),
    );
    header.insert("typ".into(), Value::String("statuslist+jwt".into()));
    if let Some(chain) = x5c {
        header.insert(
            "x5c".into(),
            Value::Array(chain.into_iter().map(Value::String).collect()),
        );
    }

    let mut payload = serde_json::Map::new();
    payload.insert("sub".into(), Value::String(claims.sub));
    payload.insert("iat".into(), Value::Number(claims.iat.into()));
    if let Some(exp) = claims.exp {
        payload.insert("exp".into(), Value::Number(exp.into()));
    }
    if let Some(ttl) = claims.ttl {
        payload.insert("ttl".into(), Value::Number(ttl.into()));
    }
    payload.insert("status_list".into(), status_list.to_json());

    let header_b64 = b64url_json(&Value::Object(header))?;
    let payload_b64 = b64url_json(&Value::Object(payload))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FormatError;

    #[test]
    fn status_value_round_trips_known_values() {
        assert_eq!(StatusValue::from_u8(0x00), StatusValue::Valid);
        assert_eq!(StatusValue::from_u8(0x01), StatusValue::Invalid);
        assert_eq!(StatusValue::from_u8(0x02), StatusValue::Suspended);
        assert_eq!(StatusValue::Valid.to_u8(), 0x00);
        assert_eq!(StatusValue::Invalid.to_u8(), 0x01);
        assert_eq!(StatusValue::Suspended.to_u8(), 0x02);
    }

    #[test]
    fn status_value_unknown_is_application_specific() {
        assert_eq!(
            StatusValue::from_u8(0x03),
            StatusValue::ApplicationSpecific(3)
        );
        assert_eq!(
            StatusValue::from_u8(0x0C),
            StatusValue::ApplicationSpecific(12)
        );
        assert_eq!(StatusValue::ApplicationSpecific(7).to_u8(), 7);
    }

    #[test]
    fn packs_bits1_least_significant_bit_first() {
        // index: 0 1 2 3 4 5 6 7 -> values 1 0 1 1 0 0 1 0
        // byte = sum(v_i << i) = 1 + 0 + 4 + 8 + 0 + 0 + 64 + 0 = 77 = 0x4D
        let packed = pack_status_array(&[1, 0, 1, 1, 0, 0, 1, 0], 1).unwrap();
        assert_eq!(packed, vec![0x4D]);
        for (idx, expected) in [1u8, 0, 1, 1, 0, 0, 1, 0].into_iter().enumerate() {
            assert_eq!(unpack_status(&packed, 1, idx as u64).unwrap(), expected);
        }
    }

    #[test]
    fn packs_bits2_four_statuses_per_byte() {
        // index 0..3 -> values 1,2,0,3 packed LSB-first: byte = 1 | (2<<2) | (0<<4) | (3<<6) = 0xC9
        let packed = pack_status_array(&[1, 2, 0, 3], 2).unwrap();
        assert_eq!(packed, vec![0xC9]);
        assert_eq!(unpack_status(&packed, 2, 0).unwrap(), 1);
        assert_eq!(unpack_status(&packed, 2, 1).unwrap(), 2);
        assert_eq!(unpack_status(&packed, 2, 2).unwrap(), 0);
        assert_eq!(unpack_status(&packed, 2, 3).unwrap(), 3);
    }

    #[test]
    fn packs_bits4_two_statuses_per_byte() {
        // byte = 5 | (10 << 4) = 0xA5
        let packed = pack_status_array(&[5, 10], 4).unwrap();
        assert_eq!(packed, vec![0xA5]);
        assert_eq!(unpack_status(&packed, 4, 0).unwrap(), 5);
        assert_eq!(unpack_status(&packed, 4, 1).unwrap(), 10);
    }

    #[test]
    fn packs_bits8_one_status_per_byte() {
        let packed = pack_status_array(&[200, 3], 8).unwrap();
        assert_eq!(packed, vec![200, 3]);
        assert_eq!(unpack_status(&packed, 8, 0).unwrap(), 200);
        assert_eq!(unpack_status(&packed, 8, 1).unwrap(), 3);
    }

    #[test]
    fn packing_spans_multiple_bytes() {
        // 5 values at bits=2 -> byte0 covers idx 0..3 (0xC9), byte1 covers idx 4 (value 2)
        let packed = pack_status_array(&[1, 2, 0, 3, 2], 2).unwrap();
        assert_eq!(packed, vec![0xC9, 0x02]);
        assert_eq!(unpack_status(&packed, 2, 4).unwrap(), 2);
    }

    #[test]
    fn rejects_unsupported_bit_widths() {
        let err = pack_status_array(&[1], 3).unwrap_err();
        assert!(matches!(err, FormatError::Unsupported(_)));
        let err = unpack_status(&[0], 3, 0).unwrap_err();
        assert!(matches!(err, FormatError::Unsupported(_)));
    }

    #[test]
    fn rejects_value_not_fitting_in_bits() {
        // bits=2 allows 0..=3; 4 does not fit.
        let err = pack_status_array(&[4], 2).unwrap_err();
        assert!(matches!(err, FormatError::InvalidStructure(_)));
    }

    #[test]
    fn unpack_out_of_bounds_index_errors() {
        // packed has 1 byte -> at bits=2 that covers indices 0..=3; index 4 is out of bounds.
        let err = unpack_status(&[0xC9], 2, 4).unwrap_err();
        match err {
            FormatError::StatusIndexOutOfBounds { idx, len } => {
                assert_eq!(idx, 4);
                assert_eq!(len, 4);
            }
            other => panic!("expected StatusIndexOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn zlib_round_trips_arbitrary_bytes() {
        let raw = vec![0xC9, 0x02, 0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x01, 0x01, 0x01, 0x01];
        let compressed = compress_zlib(&raw).unwrap();
        assert_eq!(compressed[0] & 0x0F, 8);
        let decompressed = decompress_zlib(&compressed).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn zlib_round_trips_empty_input() {
        let compressed = compress_zlib(&[]).unwrap();
        let decompressed = decompress_zlib(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn decompress_rejects_garbage() {
        let err = decompress_zlib(&[0x00, 0x01, 0x02]).unwrap_err();
        assert!(matches!(err, FormatError::Deserialization(_)));
    }

    #[test]
    fn status_list_build_and_status_at_round_trips() {
        // idx: 0=Invalid(1), 1=Suspended(2), 2=Valid(0), 3=ApplicationSpecific(3), 4=Suspended(2)
        let list = StatusList::build(&[1, 2, 0, 3, 2], 2, None).unwrap();
        assert_eq!(list.bits, 2);
        assert_eq!(list.status_at(0).unwrap(), StatusValue::Invalid);
        assert_eq!(list.status_at(1).unwrap(), StatusValue::Suspended);
        assert_eq!(list.status_at(2).unwrap(), StatusValue::Valid);
        assert_eq!(list.status_at(3).unwrap(), StatusValue::ApplicationSpecific(3));
        assert_eq!(list.status_at(4).unwrap(), StatusValue::Suspended);
    }

    #[test]
    fn status_list_decode_bytes_matches_packed_array() {
        let list = StatusList::build(&[1, 2, 0, 3, 2], 2, None).unwrap();
        assert_eq!(list.decode_bytes().unwrap(), vec![0xC9, 0x02]);
    }

    #[test]
    fn status_list_json_round_trips() {
        let list = StatusList::build(&[0, 1, 2, 3], 2, Some("https://example.com/agg".to_string())).unwrap();
        let json = list.to_json();
        assert_eq!(json["bits"], 2);
        assert_eq!(json["aggregation_uri"], "https://example.com/agg");
        let parsed = StatusList::from_json(&json).unwrap();
        assert_eq!(parsed.bits, list.bits);
        assert_eq!(parsed.lst_b64url, list.lst_b64url);
        assert_eq!(parsed.aggregation_uri, list.aggregation_uri);
    }

    #[test]
    fn status_list_from_json_rejects_missing_fields() {
        let err = StatusList::from_json(&serde_json::json!({"lst": "abc"})).unwrap_err();
        assert!(matches!(err, FormatError::InvalidStructure(_)));
        let err = StatusList::from_json(&serde_json::json!({"bits": 2})).unwrap_err();
        assert!(matches!(err, FormatError::InvalidStructure(_)));
    }

    #[test]
    fn build_status_list_token_produces_compact_jws_with_correct_typ() {
        use crate::crypto::{FileSigner, SignatureAlgorithm};
        use crate::pki::{issue_leaf, new_ca};

        let ca = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        let signer = FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let x5c = crate::trust::build_x5c(&[leaf.cert_pem.into_bytes()]).unwrap();

        let list = StatusList::build(&[0, 1, 2, 0], 2, None).unwrap();
        let claims = StatusListTokenClaims {
            sub: "https://example.com/statuslists/1".to_string(),
            iat: 1_700_000_000,
            exp: Some(1_800_000_000),
            ttl: None,
        };
        let token = build_status_list_token(claims, &list, &signer, Some(x5c)).unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value = serde_json::from_slice(
            &B64URL.decode(parts[0]).unwrap(),
        )
        .unwrap();
        assert_eq!(header["typ"], "statuslist+jwt");
        assert_eq!(header["alg"], "ES256");
        assert!(header["x5c"].is_array());
        let payload: Value = serde_json::from_slice(
            &B64URL.decode(parts[1]).unwrap(),
        )
        .unwrap();
        assert_eq!(payload["sub"], "https://example.com/statuslists/1");
        assert_eq!(payload["status_list"]["bits"], 2);
    }
}
