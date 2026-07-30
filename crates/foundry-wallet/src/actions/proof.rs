//! Builds an `openid4vci-proof+jwt` bound to a `c_nonce`/`aud`, generating a
//! fresh holder EC key pair per credential. Construction mirrors the one
//! already proven out against the real server in
//! `crates/foundry/tests/e2e_full_flow.rs::create_proof`.

use crate::error::WalletResult;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};

pub struct HolderProof {
    pub jwt: String,
    pub private_key_pem: Vec<u8>,
}

pub fn build_proof_jwt(c_nonce: &str, aud: &str) -> WalletResult<HolderProof> {
    let keypair = EcKeyPair::generate(EcCurve::P256).map_err(|e| {
        crate::error::WalletError::MalformedOffer(format!("key generation failed: {e}"))
    })?;
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk)?))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(aud)))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256
        .signer_from_jwk(&private_jwk)
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer)
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    Ok(HolderProof {
        jwt: jwt_str,
        private_key_pem: keypair.to_pem_private_key(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine;

    #[test]
    fn builds_a_proof_jwt_bound_to_nonce_and_aud() {
        let proof = build_proof_jwt("nonce-123", "https://issuer.example.com").unwrap();
        let parts: Vec<&str> = proof.jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "must be a compact JWS");

        let header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        assert!(header["jwk"].is_object());

        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["aud"], "https://issuer.example.com");
        assert_eq!(payload["nonce"], "nonce-123");
    }
}