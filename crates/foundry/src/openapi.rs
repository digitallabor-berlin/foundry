use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::server::health,
        crate::server::ready,
        crate::server::create_offer_handler,
        crate::server::create_verification_handler,
        crate::server::get_verification_handler,
    ),
    components(schemas(
        foundry_issuer::CreateOfferRequest,
        foundry_issuer::CreateOfferResponse,
        foundry_issuer::CredentialOffer,
        foundry_issuer::CredentialOfferGrants,
        foundry_issuer::PreAuthorizedCodeGrant,
        foundry_issuer::TxCodeDefinition,
        foundry_verifier::request::CreateVerificationRequest,
        foundry_verifier::request::CreateVerificationResponse,
        foundry_verifier::VerificationTransaction,
        foundry_verifier::VerificationState,
        foundry_verifier::VerificationResult,
        foundry_verifier::CheckResult,
    ))
)]
pub struct ApiDoc;

pub fn generate_openapi_spec() -> String {
    ApiDoc::openapi().to_json().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_spec_generates_valid_json() {
        let spec_json = generate_openapi_spec();
        assert!(!spec_json.is_empty(), "OpenAPI spec should not be empty");

        let val: serde_json::Value =
            serde_json::from_str(&spec_json).expect("OpenAPI spec should be valid JSON");

        let openapi_ver = val
            .get("openapi")
            .and_then(|v| v.as_str())
            .expect("spec should contain 'openapi' version field");

        assert!(
            openapi_ver.starts_with("3."),
            "Expected OpenAPI version 3.x, got '{openapi_ver}'"
        );
    }
}
