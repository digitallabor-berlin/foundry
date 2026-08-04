use utoipa::OpenApi;

/// Admin OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::server::health,
        crate::server::ready,
        crate::server::create_offer_handler,
        crate::server::get_issuance_offer_handler,
        crate::server::create_verification_handler,
        crate::server::get_verification_handler,
        crate::server::post_admin_dc_api_response_handler,
    ),
    components(schemas(
        foundry_issuer::CreateOfferRequest,
        foundry_issuer::CreateOfferResponse,
        foundry_issuer::IssuanceState,
        crate::server::AdminIssuanceStatus,
        foundry_issuer::CredentialOffer,
        foundry_issuer::CredentialOfferGrants,
        foundry_issuer::PreAuthorizedCodeGrant,
        foundry_issuer::AuthorizationCodeGrant,
        foundry_issuer::TxCodeDefinition,
        foundry_verifier::request::CreateVerificationRequest,
        foundry_verifier::request::CreateVerificationResponse,
        foundry_verifier::VerificationTransaction,
        foundry_verifier::VerificationState,
        foundry_verifier::VerificationResult,
        foundry_verifier::CheckResult,
        crate::server::AdminDcApiResponseBody,
    ))
)]
pub struct AdminApiDoc;

/// Generate admin OpenAPI specification
pub fn generate_admin_openapi_spec() -> String {
    AdminApiDoc::openapi().to_json().unwrap_or_default()
}

/// Wallet OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::server::issuer_metadata,
        crate::server::auth_server_metadata,
        crate::server::authorize_handler,
        crate::server::token_handler,
        crate::server::nonce_handler,
        crate::server::challenge_handler,
        crate::server::credential_handler,
        crate::server::get_request_object_handler,
        crate::server::post_response_handler,
        crate::server::status_list_handler,
    ),
    components(schemas(
        foundry_issuer::CredentialIssuerMetadata,
        foundry_issuer::CredentialConfigurationSupported,
        foundry_issuer::ProofTypeSupported,
        foundry_issuer::CredentialRequestEncryption,
        foundry_issuer::CredentialResponseEncryption,
        foundry_issuer::AuthorizationServerMetadata,
        foundry_issuer::TokenRequest,
        foundry_issuer::TokenResponse,
        foundry_issuer::NonceResponse,
        foundry_issuer::ChallengeResponse,
        foundry_issuer::CredentialRequest,
        foundry_issuer::CredentialResponse,
        foundry_issuer::IssuedCredential,
        foundry_issuer::ProofsRequest,
        foundry_verifier::VerificationResult,
        foundry_verifier::CheckResult,
        crate::server::VpResponseForm,
    ))
)]
pub struct WalletApiDoc;

/// Generate wallet OpenAPI specification
pub fn generate_wallet_openapi_spec() -> String {
    WalletApiDoc::openapi().to_json().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_valid_v3_spec(spec_json: &str) {
        assert!(!spec_json.is_empty(), "OpenAPI spec should not be empty");

        let val: serde_json::Value =
            serde_json::from_str(spec_json).expect("OpenAPI spec should be valid JSON");

        let openapi_ver = val
            .get("openapi")
            .and_then(|v| v.as_str())
            .expect("spec should contain 'openapi' version field");

        assert!(
            openapi_ver.starts_with("3."),
            "Expected OpenAPI version 3.x, got '{openapi_ver}'"
        );
    }

    #[test]
    fn admin_openapi_spec_generates_valid_json() {
        assert_valid_v3_spec(&generate_admin_openapi_spec());
    }

    #[test]
    fn wallet_openapi_spec_generates_valid_json() {
        assert_valid_v3_spec(&generate_wallet_openapi_spec());
    }

    #[test]
    fn admin_openapi_spec_includes_authorization_code_grant_schema() {
        let spec = generate_admin_openapi_spec();
        assert!(
            spec.contains("AuthorizationCodeGrant"),
            "admin OpenAPI spec should document the AuthorizationCodeGrant schema"
        );
    }

    #[test]
    fn wallet_openapi_spec_includes_authorize_path() {
        let spec = generate_wallet_openapi_spec();
        assert!(
            spec.contains("/authorize"),
            "wallet OpenAPI spec should document the /authorize path"
        );
    }
}
