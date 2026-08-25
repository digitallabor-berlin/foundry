use crate::error::CryptoError;

pub mod jwe;
pub mod jws;
pub mod signer;
pub use signer::FileSigner;

/// Supported JOSE ECDSA signature algorithms (HAIP: ES256 default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Es256,
    Es384,
    Es512,
}

impl SignatureAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Es256 => "ES256",
            SignatureAlgorithm::Es384 => "ES384",
            SignatureAlgorithm::Es512 => "ES512",
        }
    }

    /// The numeric COSE algorithm identifier (IANA COSE Algorithms registry)
    /// corresponding to this JOSE algorithm.
    ///
    /// COSE-secured formats identify algorithms by integer, not by JWS name:
    /// an mdoc's `IssuerAuth` COSE header carries `-7`, never `"ES256"`. Both
    /// spellings of the same algorithm are therefore needed, and they must not
    /// be maintained independently — OpenID4VCI 1.0 L2223 requires the value an
    /// issuer *advertises* for `mso_mdoc` to match the `alg` it actually *signs*
    /// with, so a divergence between the two mappings is a conformance defect
    /// that no single crate's tests would catch. This method is the one owner of
    /// the correspondence; `foundry-mdoc`'s `alg_label` is pinned against it.
    ///
    /// Deliberately total and infallible: every variant of this enum is an
    /// ECDSA algorithm with a registered COSE identifier, so there is no
    /// "unsupported" case to report.
    pub fn cose_value(&self) -> i64 {
        match self {
            SignatureAlgorithm::Es256 => -7,
            SignatureAlgorithm::Es384 => -35,
            SignatureAlgorithm::Es512 => -36,
        }
    }
}

impl std::str::FromStr for SignatureAlgorithm {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "ES256" => Ok(SignatureAlgorithm::Es256),
            "ES384" => Ok(SignatureAlgorithm::Es384),
            "ES512" => Ok(SignatureAlgorithm::Es512),
            other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Abstraction over a signing key. The file-based implementation lives in
/// `signer.rs`; a KMS/HSM backend can implement this trait later without
/// touching issuer/verifier logic.
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn public_jwk(&self) -> Result<serde_json::Value, CryptoError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_known_algorithms_case_insensitively() {
        assert_eq!(
            SignatureAlgorithm::from_str("ES256").unwrap(),
            SignatureAlgorithm::Es256
        );
        assert_eq!(
            SignatureAlgorithm::from_str("es384").unwrap(),
            SignatureAlgorithm::Es384
        );
        assert_eq!(
            SignatureAlgorithm::from_str("Es512").unwrap(),
            SignatureAlgorithm::Es512
        );
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let err = SignatureAlgorithm::from_str("RS256").unwrap_err();
        assert!(matches!(
            err,
            crate::error::CryptoError::UnsupportedAlgorithm(_)
        ));
    }

    #[test]
    fn as_str_and_display_round_trip() {
        assert_eq!(SignatureAlgorithm::Es256.as_str(), "ES256");
        assert_eq!(format!("{}", SignatureAlgorithm::Es512), "ES512");
    }

    /// The IANA COSE Algorithms registry values for the three ECDSA algorithms
    /// this enum admits. Pinned literally rather than derived, because these are
    /// external registry assignments: the point of the test is that a future
    /// edit cannot quietly renumber them.
    #[test]
    fn cose_values_match_the_iana_cose_registry() {
        assert_eq!(SignatureAlgorithm::Es256.cose_value(), -7);
        assert_eq!(SignatureAlgorithm::Es384.cose_value(), -35);
        assert_eq!(SignatureAlgorithm::Es512.cose_value(), -36);
    }

    /// The JOSE and COSE spellings must stay in bijection: two algorithms
    /// sharing a COSE value would let an issuer advertise one and sign with the
    /// other, which is precisely the class of defect `cose_value` exists to
    /// prevent.
    #[test]
    fn cose_values_are_distinct_per_algorithm() {
        let all = [
            SignatureAlgorithm::Es256,
            SignatureAlgorithm::Es384,
            SignatureAlgorithm::Es512,
        ];
        let mut seen = std::collections::HashSet::new();
        for alg in all {
            assert!(
                seen.insert(alg.cose_value()),
                "{alg} reuses COSE value {}",
                alg.cose_value()
            );
        }
    }
}
