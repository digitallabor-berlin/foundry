//! Holder proof of possession JWT verification for OpenID4VCI.

use crate::error::IssuanceError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofObject {
    pub proof_type: String,
    pub jwt: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedProof {
    pub holder_jwk: Jwk,
}

pub fn verify_holder_proof(
    proof: &ProofObject,
    expected_issuer: &str,
    expected_c_nonce: &str,
    c_nonce_expires_at: i64,
    now_unix: i64,
) -> Result<VerifiedProof, IssuanceError> {
    if proof.proof_type != "jwt" {
        return Err(IssuanceError::InvalidProof(format!(
            "unsupported proof_type: {}",
            proof.proof_type
        )));
    }

    let jwt_str = proof
        .jwt
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidProof("missing jwt string in proof".into()))?;

    if now_unix > c_nonce_expires_at {
        return Err(IssuanceError::InvalidProof("c_nonce has expired".into()));
    }

    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidProof(
            "invalid JWS format: expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL
        .decode(parts[0])
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid base64url header: {e}")))?;

    let header = JwsHeader::from_bytes(&header_bytes)
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid proof header: {e}")))?;

    let typ = header
        .token_type()
        .ok_or_else(|| IssuanceError::InvalidProof("missing typ header in proof JWT".into()))?;
    if typ != "openid4vci-proof+jwt" {
        return Err(IssuanceError::InvalidProof(format!(
            "invalid proof typ header: {typ}, expected openid4vci-proof+jwt"
        )));
    }

    let jwk_val = header
        .claim("jwk")
        .ok_or_else(|| IssuanceError::InvalidProof("missing jwk in proof header".into()))?;
    let jwk: Jwk = serde_json::from_value(jwk_val.clone())
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid jwk in proof header: {e}")))?;

    let verifier = ES256.verifier_from_jwk(&jwk).map_err(|e| {
        IssuanceError::InvalidProof(format!("unable to create verifier from jwk: {e}"))
    })?;

    let (payload, _) = josekit::jwt::decode_with_verifier(jwt_str, &verifier).map_err(|e| {
        IssuanceError::InvalidProof(format!("proof JWS signature verification failed: {e}"))
    })?;

    let aud = payload
        .claim("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("missing or non-string aud claim in proof payload".into())
        })?;
    if aud != expected_issuer {
        return Err(IssuanceError::InvalidProof(format!(
            "proof aud mismatch: got {aud}, expected {expected_issuer}"
        )));
    }

    let nonce = payload
        .claim("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("missing or non-string nonce claim in proof payload".into())
        })?;
    if nonce != expected_c_nonce {
        return Err(IssuanceError::InvalidProof(format!(
            "proof nonce mismatch: got {nonce}, expected {expected_c_nonce}"
        )));
    }

    Ok(VerifiedProof { holder_jwk: jwk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwt::{self, JwtPayload};

    #[test]
    fn verifies_valid_proof_jwt() {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public_jwk = keypair.to_jwk_public_key();
        public_jwk.set_algorithm("ES256");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
            .unwrap();

        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!("nonce-123")))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let proof = ProofObject {
            proof_type: "jwt".to_string(),
            jwt: Some(jwt_str),
        };

        let res = verify_holder_proof(
            &proof,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(res.holder_jwk.key_type(), "EC");
    }

    #[test]
    fn rejects_mismatched_nonce() {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public_jwk = keypair.to_jwk_public_key();
        public_jwk.set_algorithm("ES256");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
            .unwrap();

        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!("wrong-nonce")))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let proof = ProofObject {
            proof_type: "jwt".to_string(),
            jwt: Some(jwt_str),
        };

        let err = verify_holder_proof(
            &proof,
            "https://issuer.example.com",
            "nonce-123",
            1_700_000_100,
            1_700_000_000,
        )
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }
}
