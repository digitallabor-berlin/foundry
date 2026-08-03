use thiserror::Error;

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid grant: {0}")]
    InvalidGrant(String),
    #[error("invalid proof: {0}")]
    InvalidProof(String),
    /// OpenID4VCI 1.0 Credential Error Response (L1041, L1050): the `proofs`
    /// parameter uses an invalid nonce -- at least one key proof carries a
    /// `c_nonce` that is malformed, forged, or expired. Deliberately distinct
    /// from `InvalidProof`, which per L1049 clause 3 stays reserved for a
    /// *missing* `c_nonce` value -- GAP-VCI-04.
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),
    #[error("unknown credential_type_id '{0}'")]
    UnknownCredentialType(String),
    /// OpenID4VCI 1.0 Credential Request (L851): `credential_configuration_id`
    /// is REQUIRED (this implementation never returns `credential_identifiers`,
    /// so the exemption never applies) and MUST identify the Credential Type
    /// the Access Token was issued for -- absent, or present but naming a
    /// *different* (still-configured) Credential Type, is
    /// `invalid_credential_request` per L1041/L1046, not a generic code --
    /// GAP-VCI-02.
    #[error("invalid credential request: {0}")]
    InvalidCredentialRequest(String),
    /// A `credential_configuration_id` naming a configuration this Credential
    /// Issuer does not have at all, distinct from `InvalidCredentialRequest`
    /// (present-but-wrong) so a Wallet can tell "re-read metadata" apart from
    /// "fix your request" -- GAP-VCI-02.
    #[error("unknown credential_configuration: {0}")]
    UnknownCredentialConfiguration(String),
    #[error("claim validation failed: {0}")]
    ClaimValidation(String),
    /// Client-authentication failures per RFC 6749 sect-5.2: an absent, malformed,
    /// unsigned, expired, replayed, or otherwise unverifiable Wallet Attestation
    /// or Client Attestation PoP JWT (ABCA draft -07). Deliberately distinct from
    /// `InvalidRequest`, which is for malformed *request parameters*, not a
    /// failed client-auth mechanism -- GAP-VCI-14.
    #[error("invalid client: {0}")]
    InvalidClient(String),
    /// RFC 9449 §5: any DPoP proof failure — malformed JWT, wrong `typ`/`alg`,
    /// bad signature, `htm`/`htu`/`iat`/`ath` mismatch, replayed `jti`, a
    /// §10 `dpop_jkt` mismatch, or a §7.2 scheme/binding mismatch.
    ///
    /// Deliberately one variant, not one per check: §5 defines a single error
    /// code (`invalid_dpop_proof`, registered in §12.2), so the discriminating
    /// detail belongs in this string. That string reaches the wire as
    /// `error_description`, so it MUST name only the structural defect and
    /// MUST NOT echo the proof, the access token, or key material.
    #[error("invalid dpop proof: {0}")]
    InvalidDpopProof(String),
    #[error("status list exhausted while allocating an index for credential_type '{0}'")]
    StatusListExhausted(String),
    #[error(transparent)]
    Storage(#[from] foundry_core::error::StorageError),
    #[error(transparent)]
    Crypto(#[from] foundry_core::error::CryptoError),
    #[error(transparent)]
    Trust(#[from] foundry_core::error::TrustError),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
}

impl IssuanceError {
    /// A stable, low-cardinality name for this variant, for the `error.kind` log
    /// field.
    ///
    /// Operators group and alert on this, so it must stay decoupled from the
    /// `Display` text — which is prose and may be reworded — and must never
    /// include the error's detail.
    ///
    /// Deliberately exhaustive with no catch-all arm: a new variant should be a
    /// compile error here, not a log line labelled `"unknown"`.
    pub fn kind(&self) -> &'static str {
        match self {
            IssuanceError::InvalidRequest(_) => "invalid_request",
            IssuanceError::InvalidGrant(_) => "invalid_grant",
            IssuanceError::InvalidProof(_) => "invalid_proof",
            IssuanceError::InvalidNonce(_) => "invalid_nonce",
            IssuanceError::UnknownCredentialType(_) => "unknown_credential_type",
            IssuanceError::InvalidCredentialRequest(_) => "invalid_credential_request",
            IssuanceError::UnknownCredentialConfiguration(_) => "unknown_credential_configuration",
            IssuanceError::ClaimValidation(_) => "claim_validation",
            IssuanceError::InvalidClient(_) => "invalid_client",
            IssuanceError::InvalidDpopProof(_) => "invalid_dpop_proof",
            IssuanceError::StatusListExhausted(_) => "status_list_exhausted",
            IssuanceError::Storage(_) => "storage",
            IssuanceError::Crypto(_) => "crypto",
            IssuanceError::Trust(_) => "trust",
            IssuanceError::Internal(_) => "internal",
            IssuanceError::Serialization(_) => "serialization",
            IssuanceError::Deserialization(_) => "deserialization",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_credential_type_displays_the_id() {
        let e = IssuanceError::UnknownCredentialType("pid".to_string());
        assert_eq!(e.to_string(), "unknown credential_type_id 'pid'");
    }

    #[test]
    fn storage_error_wraps_transparently() {
        let e: IssuanceError = foundry_core::error::StorageError::NotFound("tx-1".into()).into();
        assert_eq!(e.to_string(), "record not found: tx-1");
    }

    /// One assertion per variant. `kind()` is exhaustive with no catch-all arm,
    /// so a newly added variant is a compile error here rather than a log line
    /// silently labelled "unknown".
    #[test]
    fn kind_is_a_stable_name_for_every_variant() {
        let s = || "x".to_string();
        let cases: Vec<(IssuanceError, &str)> = vec![
            (IssuanceError::InvalidRequest(s()), "invalid_request"),
            (IssuanceError::InvalidGrant(s()), "invalid_grant"),
            (IssuanceError::InvalidProof(s()), "invalid_proof"),
            (IssuanceError::InvalidNonce(s()), "invalid_nonce"),
            (
                IssuanceError::UnknownCredentialType(s()),
                "unknown_credential_type",
            ),
            (
                IssuanceError::InvalidCredentialRequest(s()),
                "invalid_credential_request",
            ),
            (
                IssuanceError::UnknownCredentialConfiguration(s()),
                "unknown_credential_configuration",
            ),
            (IssuanceError::ClaimValidation(s()), "claim_validation"),
            (IssuanceError::InvalidClient(s()), "invalid_client"),
            (IssuanceError::InvalidDpopProof(s()), "invalid_dpop_proof"),
            (
                IssuanceError::StatusListExhausted(s()),
                "status_list_exhausted",
            ),
            (
                IssuanceError::Storage(foundry_core::error::StorageError::NotFound(s())),
                "storage",
            ),
            (
                IssuanceError::Crypto(foundry_core::error::CryptoError::UnsupportedAlgorithm(s())),
                "crypto",
            ),
            (IssuanceError::Internal(s()), "internal"),
            (IssuanceError::Serialization(s()), "serialization"),
            (IssuanceError::Deserialization(s()), "deserialization"),
        ];

        for (err, expected) in cases {
            assert_eq!(err.kind(), expected, "for {err:?}");
        }
    }

    /// `kind()` must never carry the error's *detail* — it is the low-cardinality
    /// field operators group and alert on.
    #[test]
    fn kind_does_not_include_the_detail() {
        let err = IssuanceError::InvalidProof("a-very-specific-secret".to_string());
        assert_eq!(err.kind(), "invalid_proof");
        assert!(!err.kind().contains("secret"));
    }

    /// GAP-VCI-14: a failed Client Attestation PoP JWT never leaks into the
    /// `Display` text either -- the detail string is operator-facing, not the
    /// raw JWT.
    #[test]
    fn invalid_client_does_not_leak_a_raw_jwt_in_display() {
        let err = IssuanceError::InvalidClient("pop jti already claimed".to_string());
        assert_eq!(err.kind(), "invalid_client");
        assert_eq!(err.to_string(), "invalid client: pop jti already claimed");
    }

    /// GAP-VCI-04: `InvalidNonce` is a distinct variant from `InvalidProof`,
    /// with its own kind and its own Display prefix -- a wallet must be able
    /// to tell "fetch a fresh c_nonce and retry" apart from "the whole proof
    /// is broken".
    #[test]
    fn invalid_nonce_is_a_distinct_variant_from_invalid_proof() {
        let err = IssuanceError::InvalidNonce("c_nonce has expired".to_string());
        assert_eq!(err.kind(), "invalid_nonce");
        assert_eq!(err.to_string(), "invalid nonce: c_nonce has expired");
    }

    #[test]
    fn invalid_dpop_proof_has_a_stable_kind_and_message() {
        let e = IssuanceError::InvalidDpopProof("htu claim does not match".into());
        // RFC 9449 §5 / §12.2 register `invalid_dpop_proof` as the error code.
        assert_eq!(e.kind(), "invalid_dpop_proof");
        assert_eq!(
            e.to_string(),
            "invalid dpop proof: htu claim does not match"
        );
    }

    /// GAP-VCI-02: a wallet must be able to distinguish "your
    /// credential_configuration_id is missing/wrong" from "that configuration
    /// doesn't exist at all" -- two different recoveries.
    #[test]
    fn invalid_credential_request_and_unknown_credential_configuration_are_distinct() {
        let a = IssuanceError::InvalidCredentialRequest("missing".to_string());
        assert_eq!(a.kind(), "invalid_credential_request");

        let b = IssuanceError::UnknownCredentialConfiguration("nope".to_string());
        assert_eq!(b.kind(), "unknown_credential_configuration");

        assert_ne!(a.kind(), b.kind());
    }
}
