pub mod attestation;
pub mod authorize;
pub mod challenge;
pub mod create_offer;
pub mod credential;
pub mod display_metadata;
pub mod dpop;
pub mod encrypted_pre_auth;
pub mod error;
/// Crate-internal: see the module docs for why every inline-key JWS
/// verification in this crate must go through it.
pub(crate) mod jose;
pub mod keystore_proof;
pub mod metadata;
pub mod nonce;
pub mod offer;
pub mod offer_ref;
pub mod proof;
pub mod status_index;
pub mod token;
pub mod transaction;

pub use authorize::{
    AUTH_CODE_TTL_SECS, AuthorizeOutcome, AuthorizeParams, handle_authorize_request,
};
pub use challenge::{ChallengeResponse, NonceSecret, issue_attestation_challenge, mint_dpop_nonce};
pub use create_offer::{CreateOfferRequest, CreateOfferResponse, create_offer};
pub use credential::{
    CredentialRequest, CredentialResponse, CredentialResponseEncryptionParams, IssuedCredential,
    check_encryption_policy, handle_credential_request,
};
pub use display_metadata::{DisplayStage, validate_display};
pub use dpop::{
    DpopNoncePolicy, DpopPresentation, VerifiedDpopProof, access_token_hash, verify_dpop_proof,
};
pub use encrypted_pre_auth::{
    EncryptedCodeClaims, open_envelope, resolve_encrypted_pre_authorized_code, validate_claims,
};
pub use error::IssuanceError;
pub use metadata::{
    AuthorizationServerMetadata, CredentialConfigurationSupported, CredentialIssuerMetadata,
    CredentialMetadata, CredentialRequestEncryption, CredentialResponseEncryption,
    CredentialSigningAlg, ProofTypeSupported, build_authorization_server_metadata,
    build_issuer_metadata,
};
pub use nonce::{C_NONCE_TTL_SECS, NonceResponse, issue_nonce, verify_nonce};
pub use offer::{
    AuthorizationCodeGrant, CredentialOffer, CredentialOfferGrants, PreAuthorizedCodeGrant,
    TxCodeDefinition, build_dc_api_offer, build_offer_uri, build_offer_uri_by_reference,
    generate_offer_id, generate_pre_authorized_code, generate_tx_code,
};
pub use offer_ref::{load_offer_by_reference, save_offer_by_reference};
pub use proof::{ProofsRequest, VerifiedProof, verify_holder_proof};
pub use status_index::allocate_status_index;
pub use token::{EncryptedCodePolicy, TokenRequest, TokenResponse, handle_token_request};
pub use transaction::{
    IssuanceState, IssuanceTransaction, load_transaction, load_transaction_by_access_token,
    load_transaction_by_pre_auth_code, save_transaction, save_transaction_with_indices,
};
