//! Token Status List (IETF draft-ietf-oauth-status-list-14): bit-packed
//! status arrays, zlib compression, and signed Status List Tokens.

use crate::crypto::{FileSigner, SignatureAlgorithm, Signer};
use crate::error::{CoreError, CryptoError, FormatError};
use crate::trust::{build_x5c, cert_ec_public_coords, parse_cert_pem, validate_chain, TrustStore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use josekit::jwk::Jwk;
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

/// Sign a Status List Token (`statuslist+jwt`) for an already-loaded `status_list`,
/// resolving the signer from `key_path`/`alg` and, if given, an x5c chain from
/// `x5c_path`. `key_path`/`x5c_path` must already be resolved to real filesystem
/// paths by the caller — this function has no config-relative-path knowledge, so
/// both the CLI (`foundry status-list token`) and the `/statuslists/:id` HTTP
/// route can share it while resolving paths their own way.
pub fn sign_status_list_token(
    status_list: &StatusList,
    sub: String,
    now_unix: i64,
    key_path: &str,
    alg: SignatureAlgorithm,
    x5c_path: Option<&std::path::Path>,
) -> Result<String, CoreError> {
    let signer = FileSigner::from_pem_file(key_path, alg)?;
    let x5c = match x5c_path {
        Some(path) => {
            let pem_bytes = std::fs::read(path).map_err(|source| CryptoError::KeyRead {
                path: path.display().to_string(),
                source,
            })?;
            Some(build_x5c(&[pem_bytes])?)
        }
        None => None,
    };
    let claims = StatusListTokenClaims {
        sub,
        iat: now_unix,
        exp: Some(now_unix + 86400),
        ttl: None,
    };
    Ok(build_status_list_token(claims, status_list, &signer, x5c)?)
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
    let obj = jwk_value
        .as_object()
        .cloned()
        .ok_or_else(|| FormatError::SignatureVerification("jwk is not an object".into()))?;
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

/// A verified, decoded Status List: the raw (unpacked-ready) byte array plus
/// its `bits` width, ready for repeated `status_at` lookups.
#[derive(Debug)]
pub struct VerifiedStatusList {
    pub bits: u8,
    pub raw: Vec<u8>,
    pub aggregation_uri: Option<String>,
}

impl VerifiedStatusList {
    pub fn status_at(&self, idx: u64) -> Result<StatusValue, FormatError> {
        let v = unpack_status(&self.raw, self.bits, idx)?;
        Ok(StatusValue::from_u8(v))
    }
}

/// Verify a Status List Token (compact JWS) against `trust_store`, checking
/// `sub`, `exp`, and the issuer's x5c chain, and return the decoded list.
pub fn verify_status_list_token(
    token: &str,
    trust_store: &TrustStore,
    expected_sub: &str,
    now_unix: u64,
) -> Result<VerifiedStatusList, FormatError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(FormatError::InvalidStructure(
            "status list token is not a compact JWS".into(),
        ));
    }
    let header_json: Value = serde_json::from_slice(
        &B64URL
            .decode(parts[0])
            .map_err(|e| FormatError::Deserialization(format!("header b64: {e}")))?,
    )
    .map_err(|e| FormatError::Deserialization(format!("header json: {e}")))?;
    let payload_json: Value = serde_json::from_slice(
        &B64URL
            .decode(parts[1])
            .map_err(|e| FormatError::Deserialization(format!("payload b64: {e}")))?,
    )
    .map_err(|e| FormatError::Deserialization(format!("payload json: {e}")))?;

    if header_json.get("typ").and_then(|v| v.as_str()) != Some("statuslist+jwt") {
        return Err(FormatError::InvalidStructure(
            "status list token typ must be statuslist+jwt".into(),
        ));
    }

    if payload_json.get("sub").and_then(|v| v.as_str()) != Some(expected_sub) {
        return Err(FormatError::StatusSubjectMismatch {
            expected: expected_sub.to_string(),
        });
    }
    if let Some(exp) = payload_json.get("exp").and_then(|v| v.as_i64()) {
        if now_unix > exp as u64 {
            return Err(FormatError::Expired);
        }
    }

    let x5c_array = header_json
        .get("x5c")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            FormatError::SignatureVerification("status list token x5c missing".into())
        })?;
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
        chain_pems.push(
            crate::trust::x5c_entry_to_pem(s)
                .map_err(|e| FormatError::SignatureVerification(e.to_string()))?,
        );
    }
    let leaf_pem = &chain_pems[0];
    let intermediates: Vec<Vec<u8>> = chain_pems[1..].to_vec();
    validate_chain(leaf_pem, &intermediates, trust_store, now_unix).map_err(|e| {
        FormatError::SignatureVerification(format!("status list cert validation: {e}"))
    })?;

    let leaf_cert =
        parse_cert_pem(leaf_pem).map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let (lx, ly) = cert_ec_public_coords(&leaf_cert)
        .map_err(|e| FormatError::SignatureVerification(e.to_string()))?;
    let alg_str = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FormatError::SignatureVerification("alg missing".into()))?;
    let curve = curve_for_alg(alg_str)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = B64URL
        .decode(parts[2])
        .map_err(|e| FormatError::SignatureVerification(format!("signature b64: {e}")))?;
    verify_jws_with_coords(curve, &lx, &ly, signing_input.as_bytes(), &sig)?;

    let status_list_val = payload_json
        .get("status_list")
        .ok_or_else(|| FormatError::InvalidStructure("status_list claim missing".into()))?;
    let status_list = StatusList::from_json(status_list_val)?;
    let raw = status_list.decode_bytes()?;

    Ok(VerifiedStatusList {
        bits: status_list.bits,
        raw,
        aggregation_uri: status_list.aggregation_uri,
    })
}

pub const STATUS_LIST_NAMESPACE: &str = "status_lists";

/// A persistent status list stored in Storage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistentStatusList {
    pub credential_type: String,
    pub bits: u8,
    pub raw: Vec<u8>,
}

impl PersistentStatusList {
    pub fn new(credential_type: impl Into<String>, list_size: u64, bits: u8) -> Self {
        let per_byte = (8 / bits as usize) as u64;
        let len = (list_size.div_ceil(per_byte)) as usize;
        Self {
            credential_type: credential_type.into(),
            bits,
            raw: vec![0u8; len],
        }
    }

    pub fn get_status(&self, idx: u64) -> Result<StatusValue, FormatError> {
        if self.raw.is_empty() {
            return Ok(StatusValue::Valid);
        }
        let per_byte = (8 / self.bits as usize) as u64;
        let byte_idx = (idx / per_byte) as usize;
        if byte_idx >= self.raw.len() {
            return Ok(StatusValue::Valid);
        }
        let v = unpack_status(&self.raw, self.bits, idx)?;
        Ok(StatusValue::from_u8(v))
    }

    pub fn set_status(&mut self, idx: u64, status: StatusValue) -> Result<(), FormatError> {
        let bits = self.bits;
        checked_bits(bits)?;
        let per_byte = (8 / bits as usize) as u64;
        let byte_idx = (idx / per_byte) as usize;
        let bit_offset = ((idx % per_byte) * bits as u64) as u32;
        let mask = ((1u16 << bits) - 1) as u8;
        let val = status.to_u8();
        if val > mask {
            return Err(FormatError::InvalidStructure(format!(
                "status value {val} does not fit in {bits} bits"
            )));
        }
        if byte_idx >= self.raw.len() {
            self.raw.resize(byte_idx + 1, 0);
        }
        self.raw[byte_idx] &= !(mask << bit_offset);
        self.raw[byte_idx] |= (val & mask) << bit_offset;
        Ok(())
    }

    pub fn to_status_list(
        &self,
        aggregation_uri: Option<String>,
    ) -> Result<StatusList, FormatError> {
        let compressed = compress_zlib(&self.raw)?;
        Ok(StatusList {
            bits: self.bits,
            lst_b64url: B64URL.encode(compressed),
            aggregation_uri,
        })
    }
}

pub async fn load_status_list(
    storage: &dyn crate::storage::Storage,
    credential_type: &str,
) -> Result<Option<PersistentStatusList>, crate::error::StorageError> {
    if let Some(json_str) = storage
        .get_kv(STATUS_LIST_NAMESPACE, credential_type)
        .await?
    {
        let list: PersistentStatusList = serde_json::from_str(&json_str)
            .map_err(|e| crate::error::StorageError::Backend(e.to_string()))?;
        Ok(Some(list))
    } else {
        Ok(None)
    }
}

pub async fn save_status_list(
    storage: &dyn crate::storage::Storage,
    list: &PersistentStatusList,
) -> Result<(), crate::error::StorageError> {
    let json_str = serde_json::to_string(list)
        .map_err(|e| crate::error::StorageError::Backend(e.to_string()))?;
    storage
        .put_kv(
            STATUS_LIST_NAMESPACE,
            &list.credential_type,
            &json_str,
            None,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FormatError;

    #[test]
    fn sign_status_list_token_produces_parseable_jwt_with_expected_sub() {
        use crate::crypto::SignatureAlgorithm;
        use crate::pki::generate_ec_key;

        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        std::fs::write(&key_path, &km.private_pem).unwrap();

        let list = StatusList::build(&[0, 1, 0], 2, None).unwrap();
        let token = sign_status_list_token(
            &list,
            "https://issuer.example.com/statuslists/1".to_string(),
            1_700_000_000,
            key_path.to_str().unwrap(),
            SignatureAlgorithm::Es256,
            None,
        )
        .unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "must be a compact JWS");
        let payload: Value = serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["sub"], "https://issuer.example.com/statuslists/1");
        assert_eq!(payload["iat"], 1_700_000_000);
        assert_eq!(payload["status_list"]["bits"], 2);
        assert!(payload["status_list"]["lst"].is_string());
    }

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
        let raw = vec![
            0xC9, 0x02, 0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x01, 0x01, 0x01, 0x01,
        ];
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
        assert_eq!(
            list.status_at(3).unwrap(),
            StatusValue::ApplicationSpecific(3)
        );
        assert_eq!(list.status_at(4).unwrap(), StatusValue::Suspended);
    }

    #[test]
    fn status_list_decode_bytes_matches_packed_array() {
        let list = StatusList::build(&[1, 2, 0, 3, 2], 2, None).unwrap();
        assert_eq!(list.decode_bytes().unwrap(), vec![0xC9, 0x02]);
    }

    #[test]
    fn status_list_json_round_trips() {
        let list = StatusList::build(
            &[0, 1, 2, 3],
            2,
            Some("https://example.com/agg".to_string()),
        )
        .unwrap();
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
        let signer =
            FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
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
        let header: Value = serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "statuslist+jwt");
        assert_eq!(header["alg"], "ES256");
        assert!(header["x5c"].is_array());
        let payload: Value = serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["sub"], "https://example.com/statuslists/1");
        assert_eq!(payload["status_list"]["bits"], 2);
    }

    fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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
        (
            ca.cert_pem.into_bytes(),
            leaf.cert_pem.into_bytes(),
            leaf.key_pem.into_bytes(),
        )
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn build_test_token(
        leaf_key: &[u8],
        leaf_cert: &[u8],
        sub: &str,
        iat: i64,
        exp: Option<i64>,
    ) -> String {
        use crate::crypto::{FileSigner, SignatureAlgorithm};
        let signer = FileSigner::from_pem(leaf_key, SignatureAlgorithm::Es256).unwrap();
        let x5c = crate::trust::build_x5c(&[leaf_cert.to_vec()]).unwrap();
        let list = StatusList::build(&[0, 1, 2, 0], 2, None).unwrap();
        let claims = StatusListTokenClaims {
            sub: sub.to_string(),
            iat,
            exp,
            ttl: None,
        };
        build_status_list_token(claims, &list, &signer, Some(x5c)).unwrap()
    }

    #[test]
    fn verify_round_trips_and_status_at_matches_original() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let trust_store = crate::trust::TrustStore::from_pems(&[root]).unwrap();
        let now = now_secs();
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 100,
            Some(now as i64 + 3600),
        );

        let verified = verify_status_list_token(
            &token,
            &trust_store,
            "https://example.com/statuslists/1",
            now,
        )
        .unwrap();
        assert_eq!(verified.status_at(0).unwrap(), StatusValue::Valid);
        assert_eq!(verified.status_at(1).unwrap(), StatusValue::Invalid);
        assert_eq!(verified.status_at(2).unwrap(), StatusValue::Suspended);
        assert_eq!(verified.status_at(3).unwrap(), StatusValue::Valid);
    }

    #[test]
    fn verify_rejects_expired_token() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let trust_store = crate::trust::TrustStore::from_pems(&[root]).unwrap();
        let now = now_secs();
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 7200,
            Some(now as i64 - 3600), // expired 3600s before `now`
        );

        let err = verify_status_list_token(
            &token,
            &trust_store,
            "https://example.com/statuslists/1",
            now,
        )
        .unwrap_err();
        assert!(matches!(err, FormatError::Expired));
    }

    #[test]
    fn verify_rejects_subject_mismatch() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let trust_store = crate::trust::TrustStore::from_pems(&[root]).unwrap();
        let now = now_secs();
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 100,
            Some(now as i64 + 3600),
        );

        let err = verify_status_list_token(
            &token,
            &trust_store,
            "https://example.com/statuslists/WRONG",
            now,
        )
        .unwrap_err();
        assert!(matches!(err, FormatError::StatusSubjectMismatch { .. }));
    }

    #[test]
    fn verify_rejects_untrusted_anchor() {
        let (_root, leaf_cert, leaf_key) = test_pki();
        use crate::pki::new_ca;
        let other = new_ca("Some Other CA", 3650).unwrap();
        let trust_store =
            crate::trust::TrustStore::from_pems(&[other.cert_pem.into_bytes()]).unwrap();
        let now = now_secs();
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 100,
            Some(now as i64 + 3600),
        );

        let err = verify_status_list_token(
            &token,
            &trust_store,
            "https://example.com/statuslists/1",
            now,
        )
        .unwrap_err();
        assert!(matches!(err, FormatError::SignatureVerification(_)));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let (root, leaf_cert, leaf_key) = test_pki();
        let trust_store = crate::trust::TrustStore::from_pems(&[root]).unwrap();
        let now = now_secs();
        let token = build_test_token(
            &leaf_key,
            &leaf_cert,
            "https://example.com/statuslists/1",
            now as i64 - 100,
            Some(now as i64 + 3600),
        );
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });

        let err = verify_status_list_token(
            &tampered,
            &trust_store,
            "https://example.com/statuslists/1",
            now,
        )
        .unwrap_err();
        assert!(matches!(err, FormatError::SignatureVerification(_)));
    }

    #[tokio::test]
    async fn persistent_status_list_storage_roundtrip() {
        use crate::storage::SqliteStorage;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let storage = SqliteStorage::connect(db_path.to_str().unwrap())
            .await
            .unwrap();

        let loaded = load_status_list(&storage, "pid").await.unwrap();
        assert!(loaded.is_none());

        let mut list = PersistentStatusList::new("pid", 1024, 2);
        assert_eq!(list.get_status(42).unwrap(), StatusValue::Valid);

        list.set_status(42, StatusValue::Invalid).unwrap();
        list.set_status(100, StatusValue::Suspended).unwrap();
        assert_eq!(list.get_status(42).unwrap(), StatusValue::Invalid);
        assert_eq!(list.get_status(100).unwrap(), StatusValue::Suspended);

        save_status_list(&storage, &list).await.unwrap();

        let loaded = load_status_list(&storage, "pid").await.unwrap().unwrap();
        assert_eq!(loaded.get_status(42).unwrap(), StatusValue::Invalid);
        assert_eq!(loaded.get_status(100).unwrap(), StatusValue::Suspended);
        assert_eq!(loaded.get_status(0).unwrap(), StatusValue::Valid);

        let status_list = loaded.to_status_list(None).unwrap();
        assert_eq!(status_list.status_at(42).unwrap(), StatusValue::Invalid);
        assert_eq!(status_list.status_at(100).unwrap(), StatusValue::Suspended);
    }
}
