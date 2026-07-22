//! Wallet and key attestation verifier traits and default implementations.

use crate::error::IssuanceError;
use foundry_core::config::Mode;

pub trait WalletAttestationVerifier: Send + Sync {
    fn verify_wallet_attestation(
        &self,
        mode: Mode,
        attestation_header: Option<&str>,
    ) -> Result<(), IssuanceError>;
}

pub trait KeyAttestationVerifier: Send + Sync {
    fn verify_key_attestation(
        &self,
        mode: Mode,
        attestation_data: Option<&str>,
    ) -> Result<(), IssuanceError>;
}

#[derive(Debug, Clone, Default)]
pub struct DefaultAttestationVerifier;

impl WalletAttestationVerifier for DefaultAttestationVerifier {
    fn verify_wallet_attestation(
        &self,
        mode: Mode,
        attestation_header: Option<&str>,
    ) -> Result<(), IssuanceError> {
        match mode {
            Mode::Required => {
                if attestation_header.is_none() {
                    return Err(IssuanceError::InvalidRequest(
                        "wallet attestation is required".into(),
                    ));
                }
                Ok(())
            }
            Mode::Optional | Mode::Disabled => Ok(()),
        }
    }
}

impl KeyAttestationVerifier for DefaultAttestationVerifier {
    fn verify_key_attestation(
        &self,
        mode: Mode,
        attestation_data: Option<&str>,
    ) -> Result<(), IssuanceError> {
        match mode {
            Mode::Required => {
                if attestation_data.is_none() {
                    return Err(IssuanceError::InvalidRequest(
                        "key attestation is required".into(),
                    ));
                }
                Ok(())
            }
            Mode::Optional | Mode::Disabled => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_mode_required_checks_presence() {
        let verifier = DefaultAttestationVerifier;
        assert!(verifier
            .verify_wallet_attestation(Mode::Required, None)
            .is_err());
        assert!(verifier
            .verify_wallet_attestation(Mode::Required, Some("header"))
            .is_ok());
        assert!(verifier
            .verify_wallet_attestation(Mode::Optional, None)
            .is_ok());
        assert!(verifier
            .verify_wallet_attestation(Mode::Disabled, None)
            .is_ok());
    }
}
