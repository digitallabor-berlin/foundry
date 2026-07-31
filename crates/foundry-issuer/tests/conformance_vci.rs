//! OpenID4VCI + HAIP conformance evidence for the Credential Offer (VCI §4)
//! and the issuer-initiated / `authorization_code`-grant HAIP requirements
//! filed under "Credential Offer" in the clause inventory (Task 6 of the
//! OpenID4VC conformance audit).
//!
//! See `docs/conformance/openid4vc-conformance.md` for the full clause
//! inventory and the verdicts these tests are cited as evidence for.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, KeyEntry, Mode,
    ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use foundry_core::trust::TrustStore;
use foundry_issuer::attestation::verify_key_attestation_jwt;
use foundry_issuer::{
    build_authorization_server_metadata, build_issuer_metadata, create_offer,
    handle_authorize_request, handle_credential_request, handle_token_request, issue_nonce,
    verify_holder_proof, AuthorizeOutcome, AuthorizeParams, CreateOfferRequest, CredentialRequest,
    NonceSecret, ProofsRequest, TokenRequest,
};
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn test_config() -> Config {
    Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://issuer.example.com".to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: true,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: None,
                api_key_env: None,
                swagger_ui_enabled: true,
                console_enabled: true,
            },
        },
        storage: StorageConfig {
            path: "./foundry.db".to_string(),
            transaction_ttl_secs: 600,
        },
        keys: BTreeMap::new(),
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://issuer.example.com".to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: None,
                list_size: Some(1024),
                public_base_url: None,
            },
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://issuer.example.com/vct/pid".to_string()),
            doctype: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                selectively_disclosable: true,
                display: vec![],
            }],
        }],
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
        },
    }
}

async fn test_storage() -> SqliteStorage {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("conformance_vci.db");
    // Leak the tempdir so the file survives for the life of the test process;
    // the OS reclaims it, matching the pattern already used by this crate's
    // unit tests (see create_offer.rs, metadata.rs).
    std::mem::forget(dir);
    SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
}

fn claims_with(field: &str, value: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert(field.to_string(), serde_json::json!(value));
    m
}

fn offer_request(redirect_uri: Option<&str>) -> CreateOfferRequest {
    CreateOfferRequest {
        credential_type_id: "pid".to_string(),
        claims: claims_with("given_name", "Alice"),
        tx_code_required: false,
        redirect_uri: redirect_uri.map(|s| s.to_string()),
    }
}

// ---------------------------------------------------------------------------
// VCI-0004 / VCI-0005 — OpenID4VCI §4 (Credential Offer Parameters, L374-375):
// `credential_offer` and `credential_offer_uri` MUST be mutually exclusive.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0004_0005_offer_uri_carries_exactly_one_delivery_parameter() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();

    let occurrences = resp
        .credential_offer_uri
        .matches("credential_offer=")
        .count();
    assert_eq!(
        occurrences, 1,
        "the offer URI must carry the offer via exactly one `credential_offer` parameter"
    );
    assert!(
        !resp.credential_offer_uri.contains("credential_offer_uri="),
        "foundry never offers by reference, so `credential_offer_uri` must never appear"
    );
}

// ---------------------------------------------------------------------------
// VCI-0006 — OpenID4VCI §4 (Credential Offer Parameters, L383): `credential_issuer`
// is REQUIRED.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0006_credential_issuer_is_always_present_and_matches_config() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();

    assert_eq!(
        resp.credential_offer.credential_issuer,
        "https://issuer.example.com"
    );
}

// ---------------------------------------------------------------------------
// VCI-0007 — OpenID4VCI §4 (Credential Offer Parameters, L384):
// `credential_configuration_ids` is REQUIRED, non-empty, and its entries MUST
// resolve against `credential_configurations_supported`.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0007_credential_configuration_ids_are_nonempty_and_resolve_against_metadata() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let metadata = build_issuer_metadata(&cfg);

    assert!(!resp
        .credential_offer
        .credential_configuration_ids
        .is_empty());
    for id in &resp.credential_offer.credential_configuration_ids {
        assert!(
            metadata
                .credential_configurations_supported
                .contains_key(id),
            "offered configuration id `{id}` must be keyed into issuer metadata"
        );
    }
}

// ---------------------------------------------------------------------------
// VCI-0012 — OpenID4VCI §4 (Credential Offer Parameters, L396): `pre-authorized_code`
// is REQUIRED and MUST be short lived and single use.
//
// Presence and per-offer distinctness are conforming (below). Single use is
// not — see the ignored test below, registered as GAP-VCI-01.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0012_pre_authorized_code_is_present_and_distinct_per_offer() {
    let cfg = test_config();
    let storage = test_storage().await;

    let resp_a = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code_a = resp_a
        .credential_offer
        .grants
        .pre_authorized_code
        .as_ref()
        .expect("pre-authorized_code grant must be present")
        .pre_authorized_code
        .clone();
    assert!(!code_a.is_empty());

    let resp_b = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code_b = resp_b
        .credential_offer
        .grants
        .pre_authorized_code
        .as_ref()
        .expect("pre-authorized_code grant must be present")
        .pre_authorized_code
        .clone();

    assert_ne!(
        code_a, code_b,
        "each offer must mint its own pre-authorized_code"
    );
}

#[tokio::test]
#[ignore = "GAP-VCI-01: OpenID4VCI Credential Offer (L396) — pre-authorized_code MUST be single use"]
async fn vci_0012_pre_authorized_code_grant_rejects_replay_after_token_issuance() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code = resp
        .credential_offer
        .grants
        .pre_authorized_code
        .unwrap()
        .pre_authorized_code;

    let token_req = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        pre_authorized_code: Some(code),
        tx_code: None,
        code: None,
        redirect_uri: None,
        client_id: None,
        code_verifier: None,
    };

    handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_010)
        .await
        .expect("first redemption must succeed");

    let replay =
        handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_020).await;
    assert!(
        replay.is_err(),
        "a second /token call with the same pre-authorized_code must be rejected"
    );
}

// ---------------------------------------------------------------------------
// HAIP-0010 — HAIP OpenID4VCI (L173): if Issuer-initiated flows are supported
// they MUST use the Credential Offer (OpenID4VCI §4.1).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn haip_0010_issuer_initiated_flow_always_produces_a_credential_offer() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();

    // foundry's only issuer-initiated issuance entry point is `create_offer`,
    // and it always produces a well-formed CredentialOffer plus its deep-link.
    assert!(!resp
        .credential_offer
        .credential_configuration_ids
        .is_empty());
    assert!(resp
        .credential_offer_uri
        .starts_with("openid-credential-offer://"));
}

// ---------------------------------------------------------------------------
// HAIP-0022 — HAIP OpenID4VCI (L198): Grant Type `authorization_code` MUST be
// supported.
// ---------------------------------------------------------------------------
fn s256_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[tokio::test]
async fn haip_0022_authorization_code_grant_type_is_supported_end_to_end() {
    let cfg = test_config();
    let storage = test_storage().await;

    // The Authorization Server metadata must advertise the grant.
    let as_metadata = build_authorization_server_metadata(&cfg);
    assert!(as_metadata
        .grant_types_supported
        .contains(&"authorization_code".to_string()));

    // And the flow must actually work end to end: offer -> authorize -> token.
    let redirect_uri = "eudi-openid4ci://authorize";
    let resp = create_offer(
        &cfg,
        &storage,
        offer_request(Some(redirect_uri)),
        1_700_000_000,
    )
    .await
    .unwrap();
    let issuer_state = resp
        .credential_offer
        .grants
        .authorization_code
        .as_ref()
        .expect("authorization_code grant must be present")
        .issuer_state
        .clone()
        .expect("issuer_state must be present");

    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let params = AuthorizeParams {
        response_type: "code".to_string(),
        client_id: "wallet-dev".to_string(),
        redirect_uri: redirect_uri.to_string(),
        state: None,
        code_challenge: s256_code_challenge(code_verifier),
        code_challenge_method: "S256".to_string(),
        issuer_state,
    };
    let outcome = handle_authorize_request(
        &storage,
        &params,
        cfg.storage.transaction_ttl_secs,
        1_700_000_005,
    )
    .await;
    let code = match outcome {
        AuthorizeOutcome::Success { code, .. } => code,
        other => panic!("expected AuthorizeOutcome::Success, got {other:?}"),
    };

    let token_req = TokenRequest {
        grant_type: "authorization_code".to_string(),
        pre_authorized_code: None,
        tx_code: None,
        code: Some(code),
        redirect_uri: Some(redirect_uri.to_string()),
        client_id: Some("wallet-dev".to_string()),
        code_verifier: Some(code_verifier.to_string()),
    };
    handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_010)
        .await
        .expect("authorization_code grant must issue an access token");
}

// ---------------------------------------------------------------------------
// HAIP-0023 — HAIP OpenID4VCI (L199): for Grant Type `authorization_code` the
// Issuer MUST include a scope value so the Wallet can identify the desired
// Credential Type.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-HAIP-01: HAIP OpenID4VCI (L199) — the Issuer MUST include a scope value for the authorization_code grant"]
async fn haip_0023_credential_configuration_metadata_carries_a_scope_value() {
    let cfg = test_config();
    let metadata = build_issuer_metadata(&cfg);
    let pid = metadata
        .credential_configurations_supported
        .get("pid")
        .unwrap();
    let json = serde_json::to_value(pid).unwrap();

    assert!(
        json.as_object().unwrap().contains_key("scope"),
        "HAIP requires a scope value the Wallet can use to identify the Credential Type"
    );
}

// ---------------------------------------------------------------------------
// Task 9 fixtures: a signing-key-backed Config and a proof-JWT generator,
// needed to reach handle_credential_request's happy path (Tasks 6-8's
// fixtures never configure key material).
// ---------------------------------------------------------------------------
fn credential_test_config(key_path: &str) -> Config {
    let mut cfg = test_config();
    let mut keys = BTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            private_key: key_path.to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );
    cfg.keys = keys;
    cfg.issuer.status_list.signing_key = Some("issuer_key".to_string());
    cfg.credential_types.push(CredentialType {
        id: "mdl".to_string(),
        format: "mso_mdoc".to_string(),
        vct: None,
        doctype: Some("org.iso.18013.5.1.mDL".to_string()),
        cryptographic_holder_binding: true,
        display: vec![],
        claims: vec![ClaimDef {
            path: vec!["given_name".to_string()],
            selectively_disclosable: true,
            display: vec![],
        }],
    });
    cfg
}

fn generate_proof_jwt(c_nonce: &str, issuer: &str) -> String {
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
        .set_claim("aud", Some(serde_json::json!(issuer)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

/// Runs a full offer -> token exchange for `credential_type_id` against a
/// signing-key-backed config, returning everything a Credential Request needs.
async fn setup_credential_flow(
    key_path: &str,
    credential_type_id: &str,
) -> (Config, SqliteStorage, String, NonceSecret) {
    let cfg = credential_test_config(key_path);
    let storage = test_storage().await;
    let req = CreateOfferRequest {
        credential_type_id: credential_type_id.to_string(),
        claims: claims_with("given_name", "Alice"),
        tx_code_required: false,
        redirect_uri: None,
    };
    let resp = create_offer(&cfg, &storage, req, 1_700_000_000)
        .await
        .unwrap();
    let code = resp
        .credential_offer
        .grants
        .pre_authorized_code
        .unwrap()
        .pre_authorized_code;

    let token_req = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        pre_authorized_code: Some(code),
        tx_code: None,
        code: None,
        redirect_uri: None,
        client_id: None,
        code_verifier: None,
    };
    let token = handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_010)
        .await
        .unwrap();

    let secret = NonceSecret::from_bytes([7u8; 32]);
    (cfg, storage, token.access_token, secret)
}

fn write_test_issuer_key() -> (tempfile::TempDir, String) {
    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("issuer.pem");
    let km = foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
        .unwrap();
    std::fs::write(&key_path, km.private_pem).unwrap();
    let path_str = key_path.to_str().unwrap().to_string();
    (key_dir, path_str)
}

// ---------------------------------------------------------------------------
// VCI-0058 — OpenID4VCI Credential Request (L864): `proofs` MUST be present
// when `proof_types_supported` is present for the requested Credential.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0058_proofs_are_required_when_proof_types_supported() {
    let (_key_dir, key_path) = write_test_issuer_key();
    let (cfg, storage, access_token, secret) = setup_credential_flow(&key_path, "pid").await;

    let req = CredentialRequest {
        credential_configuration_id: Some("pid".to_string()),
        format: Some("dc+sd-jwt".to_string()),
        proofs: None,
    };

    let result =
        handle_credential_request(&cfg, &storage, &access_token, &req, &secret, 1_700_000_020)
            .await;

    assert!(
        result.is_err(),
        "a Credential Request with no proofs must be rejected when proof_types_supported is present"
    );
}

// ---------------------------------------------------------------------------
// VCI-0059 — OpenID4VCI Credential Request (L869): the Credential Issuer
// MUST ignore unrecognized Credential Request parameters.
// ---------------------------------------------------------------------------
#[test]
fn vci_0059_credential_request_ignores_unrecognized_parameters() {
    let json = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": ["abc.def.ghi"] },
        "some_unrecognized_field": "whatever",
    });

    let req: CredentialRequest = serde_json::from_value(json)
        .expect("unrecognized fields must not cause deserialization to fail");

    assert_eq!(req.credential_configuration_id.as_deref(), Some("pid"));
}

// ---------------------------------------------------------------------------
// VCI-0052 — OpenID4VCI Credential Request (L851): `credential_configuration_id`
// is REQUIRED when `credential_identifiers` was not returned (i.e. always, per
// Task 8's finding that `authorization_details`/`credential_identifiers` are
// not implemented) and MUST identify the Credential this Access Token binds to.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-VCI-02: OpenID4VCI Credential Request (L851) — credential_configuration_id MUST identify the Credential the Access Token was issued for"]
async fn vci_0052_credential_configuration_id_mismatch_is_rejected() {
    let (_key_dir, key_path) = write_test_issuer_key();
    let (cfg, storage, access_token, secret) = setup_credential_flow(&key_path, "pid").await;

    let nonce = issue_nonce(&secret, 1_700_000_015).unwrap().c_nonce;
    let proof_jwt = generate_proof_jwt(&nonce, "https://issuer.example.com");

    // The access token was issued for "pid"; requesting an unrelated
    // configuration id must be rejected, not silently served as "pid".
    let req = CredentialRequest {
        credential_configuration_id: Some("some-other-configuration-entirely".to_string()),
        format: Some("dc+sd-jwt".to_string()),
        proofs: Some(ProofsRequest {
            jwt: vec![proof_jwt],
        }),
    };

    let result =
        handle_credential_request(&cfg, &storage, &access_token, &req, &secret, 1_700_000_020)
            .await;

    assert!(
        result.is_err(),
        "a credential_configuration_id mismatched with the Access Token's bound Credential Type must be rejected"
    );
}

// ---------------------------------------------------------------------------
// VCI-0071 — OpenID4VCI Credential Response (L976): Credential Formats
// expressed as binary data MUST be base64url-encoded and returned as a string.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-VCI-03: OpenID4VCI Credential Response (L976) — binary Credential Formats MUST be base64url-encoded"]
async fn vci_0071_mdoc_credential_string_is_base64url_encoded() {
    let (_key_dir, key_path) = write_test_issuer_key();
    let (cfg, storage, access_token, secret) = setup_credential_flow(&key_path, "mdl").await;

    let nonce = issue_nonce(&secret, 1_700_000_015).unwrap().c_nonce;
    let proof_jwt = generate_proof_jwt(&nonce, "https://issuer.example.com");

    let req = CredentialRequest {
        credential_configuration_id: Some("mdl".to_string()),
        format: Some("mso_mdoc".to_string()),
        proofs: Some(ProofsRequest {
            jwt: vec![proof_jwt],
        }),
    };

    let res =
        handle_credential_request(&cfg, &storage, &access_token, &req, &secret, 1_700_000_020)
            .await
            .expect("mdoc issuance must succeed");
    let credential = &res.credentials[0].credential;

    assert!(
        !credential.contains('+') && !credential.contains('/') && !credential.contains('='),
        "the mdoc credential string must be base64url-encoded (no +, /, or = padding), got: {credential}"
    );
}

// ---------------------------------------------------------------------------
// HAIP-0025 — HAIP OpenID4VCI (L204): both Issuer and Wallet MUST support the
// Credential Offer in same-device and cross-device flows.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn haip_0025_credential_offer_uri_format_is_transport_agnostic() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();

    // The offer is a self-contained deep link with no device-mode signal, so
    // the identical value serves a QR-scanned cross-device flow and a
    // directly-opened same-device flow alike.
    assert!(resp
        .credential_offer_uri
        .starts_with("openid-credential-offer://?credential_offer="));
}

// ---------------------------------------------------------------------------
// HAIP-0009 — HAIP OpenID4VCI (L163): MUST support DPoP per RFC9449 for
// sender-constrained access tokens.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-HAIP-03: HAIP OpenID4VCI (L163) — MUST support DPoP per RFC9449 for sender-constrained access tokens"]
async fn haip_0009_token_response_uses_dpop_token_type() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code = resp
        .credential_offer
        .grants
        .pre_authorized_code
        .unwrap()
        .pre_authorized_code;

    let token_req = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        pre_authorized_code: Some(code),
        tx_code: None,
        code: None,
        redirect_uri: None,
        client_id: None,
        code_verifier: None,
    };
    let token = handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_010)
        .await
        .unwrap();

    assert_eq!(
        token.token_type, "DPoP",
        "sender-constrained access tokens use token_type=DPoP, not Bearer"
    );
}

// ---------------------------------------------------------------------------
// HAIP-0031 — HAIP OpenID4VCI / Wallet Attestation (L225): the public key
// certificate validating the Wallet Attestation signature MUST be included
// in the `x5c` JOSE header of the Client Attestation JWT, i.e. the presented
// attestation MUST be a validly signed JWT, not an arbitrary opaque string.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-HAIP-04: HAIP OpenID4VCI / Wallet Attestation (L225) — the Wallet Attestation MUST be a validly signed JWT with an x5c-verified chain, not merely present"]
async fn haip_0031_wallet_attestation_header_must_be_a_validly_signed_jwt() {
    let cfg = test_config();
    let storage = test_storage().await;
    let resp = create_offer(&cfg, &storage, offer_request(None), 1_700_000_000)
        .await
        .unwrap();
    let code = resp
        .credential_offer
        .grants
        .pre_authorized_code
        .unwrap()
        .pre_authorized_code;

    let token_req = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        pre_authorized_code: Some(code),
        tx_code: None,
        code: None,
        redirect_uri: None,
        client_id: None,
        code_verifier: None,
    };

    // Not a JWT at all — no dots, no header, no signature. A conformant
    // issuer requiring Wallet Attestation must reject this.
    let result = handle_token_request(
        &storage,
        &token_req,
        Mode::Required,
        Some("not-a-jwt-at-all"),
        1_700_000_010,
    )
    .await;

    assert!(
        result.is_err(),
        "an unsigned, non-JWT-shaped value must not be accepted as a valid Wallet Attestation"
    );
}

// ---------------------------------------------------------------------------
// VCI-0033 — OpenID4VCI Token Request (L653): `pre-authorized_code` MUST be
// present when `grant_type` is the pre-authorized code grant.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0033_pre_authorized_code_is_required_for_that_grant() {
    let storage = test_storage().await;
    let token_req = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        pre_authorized_code: None,
        tx_code: None,
        code: None,
        redirect_uri: None,
        client_id: None,
        code_verifier: None,
    };

    let result =
        handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_000).await;

    assert!(
        result.is_err(),
        "a pre-authorized_code grant without a pre-authorized_code must be rejected"
    );
}

// ---------------------------------------------------------------------------
// VCI-0034 — OpenID4VCI Token Request (L654): `tx_code` MUST be present if a
// `tx_code` object was present in the Credential Offer.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0034_tx_code_is_required_when_the_offer_carried_one() {
    let cfg = test_config();
    let storage = test_storage().await;
    let req = CreateOfferRequest {
        credential_type_id: "pid".to_string(),
        claims: claims_with("given_name", "Alice"),
        tx_code_required: true,
        redirect_uri: None,
    };
    let resp = create_offer(&cfg, &storage, req, 1_700_000_000)
        .await
        .unwrap();
    let code = resp
        .credential_offer
        .grants
        .pre_authorized_code
        .unwrap()
        .pre_authorized_code;

    let token_req = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        pre_authorized_code: Some(code),
        tx_code: None, // omitted, though the offer required one
        code: None,
        redirect_uri: None,
        client_id: None,
        code_verifier: None,
    };

    let result =
        handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_010).await;

    assert!(
        result.is_err(),
        "omitting tx_code when the offer required one must be rejected"
    );
}

// ---------------------------------------------------------------------------
// VCI-0035 — OpenID4VCI Token Request (L654): `tx_code` MUST only be used
// when `grant_type` is the pre-authorized code grant — an authorization_code
// grant request must not be affected by an incidental `tx_code` value.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0035_tx_code_is_ignored_by_the_authorization_code_grant() {
    let cfg = test_config();
    let storage = test_storage().await;
    let redirect_uri = "eudi-openid4ci://authorize";
    let resp = create_offer(
        &cfg,
        &storage,
        offer_request(Some(redirect_uri)),
        1_700_000_000,
    )
    .await
    .unwrap();
    let issuer_state = resp
        .credential_offer
        .grants
        .authorization_code
        .as_ref()
        .unwrap()
        .issuer_state
        .clone()
        .unwrap();

    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let params = AuthorizeParams {
        response_type: "code".to_string(),
        client_id: "wallet-dev".to_string(),
        redirect_uri: redirect_uri.to_string(),
        state: None,
        code_challenge: s256_code_challenge(code_verifier),
        code_challenge_method: "S256".to_string(),
        issuer_state,
    };
    let outcome = handle_authorize_request(
        &storage,
        &params,
        cfg.storage.transaction_ttl_secs,
        1_700_000_005,
    )
    .await;
    let code = match outcome {
        AuthorizeOutcome::Success { code, .. } => code,
        other => panic!("expected AuthorizeOutcome::Success, got {other:?}"),
    };

    // tx_code has no meaning for this grant; a stray value must not change
    // the outcome.
    let token_req = TokenRequest {
        grant_type: "authorization_code".to_string(),
        pre_authorized_code: None,
        tx_code: Some("999999".to_string()),
        code: Some(code),
        redirect_uri: Some(redirect_uri.to_string()),
        client_id: Some("wallet-dev".to_string()),
        code_verifier: Some(code_verifier.to_string()),
    };
    handle_token_request(&storage, &token_req, Mode::Disabled, None, 1_700_000_010)
        .await
        .expect("a stray tx_code must not affect the authorization_code grant");
}

// ---------------------------------------------------------------------------
// VCI-0038 — OpenID4VCI Token Request (L668): the Authorization Server MUST
// ignore unrecognized Token Request parameters.
// ---------------------------------------------------------------------------
#[test]
fn vci_0038_token_request_ignores_unrecognized_parameters() {
    let json = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "abc123",
        "some_unrecognized_field": "whatever",
        "another_bogus_one": 42,
    });

    let req: TokenRequest = serde_json::from_value(json)
        .expect("unrecognized fields must not cause deserialization to fail");

    assert_eq!(req.pre_authorized_code.as_deref(), Some("abc123"));
}

// ---------------------------------------------------------------------------
// Task 10 fixtures: builders that vary specific header/payload fields the
// happy-path helpers above (`generate_proof_jwt`, `signed_key_attestation` in
// attestation.rs's own unit tests) hold fixed, to exercise the jwt-proof-type
// and Key-Attestation-JWT structural requirements (VCI Proof Types, Key
// Attestation JWT, Verifying Proof; HAIP Requirements for Digital Signatures).
// ---------------------------------------------------------------------------

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sample_attested_jwk() -> serde_json::Value {
    let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut jwk = kp.to_jwk_public_key();
    jwk.set_algorithm("ES256");
    serde_json::to_value(&jwk).unwrap()
}

/// Builds a Key Attestation JWT ((#keyattestation-jwt)) with full control
/// over header `alg`/`typ` and payload claim presence, chained to a fresh
/// CA, to exercise the structural requirements in VCI-0184 through VCI-0189
/// that the happy-path `signed_key_attestation` builder in attestation.rs's
/// own unit tests does not vary. Returns (jwt, ca_cert_pem).
fn key_attestation_jwt_custom(
    alg: &str,
    typ: &str,
    iat: Option<i64>,
    exp: Option<i64>,
    nonce: Option<&str>,
    attested_keys: Vec<serde_json::Value>,
) -> (String, String) {
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};

    let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "wallet-provider.example.com",
        &["wallet-provider.example.com".to_string()],
        365,
    )
    .unwrap();
    let leaf_der = {
        let cert = foundry_core::trust::parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
        use x509_cert::der::Encode;
        cert.to_der().unwrap()
    };
    let x5c = vec![base64::engine::general_purpose::STANDARD.encode(&leaf_der)];

    let header = serde_json::json!({"typ": typ, "alg": alg, "x5c": x5c});
    let mut payload = serde_json::Map::new();
    payload.insert(
        "iss".to_string(),
        serde_json::json!("https://wallet-provider.example.com"),
    );
    if let Some(v) = iat {
        payload.insert("iat".to_string(), serde_json::json!(v));
    }
    if let Some(v) = exp {
        payload.insert("exp".to_string(), serde_json::json!(v));
    }
    if let Some(v) = nonce {
        payload.insert("nonce".to_string(), serde_json::json!(v));
    }
    payload.insert(
        "attested_keys".to_string(),
        serde_json::Value::Array(attested_keys),
    );

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::Value::Object(payload)).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signer = FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signer.sign(signing_input.as_bytes()).unwrap());
    (format!("{signing_input}.{sig_b64}"), ca.cert_pem)
}

/// Builds a `jwt`-proof-type JWT with an overridable `typ` header and `aud`
/// claim, otherwise identical to `generate_proof_jwt`'s happy path.
fn generate_proof_jwt_with_typ(typ: &str, aud: &str, nonce: &str) -> String {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type(typ);
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(aud)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

/// Builds a `jwt`-proof-type JWT actually signed with HS256 rather than
/// ES256, to prove the alg requirement is enforced by attempted signature
/// verification, not merely assumed because every other fixture in this
/// suite happens to use ES256.
fn generate_proof_jwt_signed_with_hs256(aud: &str, nonce: &str) -> String {
    use josekit::jws::HS256;

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
        .set_claim("aud", Some(serde_json::json!(aud)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(nonce)))
        .unwrap();

    let signer = HS256
        .signer_from_bytes(b"a-shared-symmetric-secret-irrelevant-to-ec-keys")
        .unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

/// Builds a `jwt`-proof-type JWT whose payload includes an `iss` claim,
/// exercising VCI-0207's "MUST be the client_id ... MUST be omitted [when
/// obtained through] anonymous access" rule.
fn generate_proof_jwt_with_iss(aud: &str, nonce: &str, iss: &str) -> String {
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
        .set_claim("iss", Some(serde_json::json!(iss)))
        .unwrap();
    payload
        .set_claim("aud", Some(serde_json::json!(aud)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

/// Builds a `jwt`-proof-type JWT whose `jwk` header carries the full private
/// key (including `d`), exercising Verifying Proof's "the header parameter
/// does not contain a private key" rule.
fn generate_proof_jwt_with_private_key_in_header(aud: &str, nonce: &str) -> String {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut private_jwk = keypair.to_jwk_private_key();
    private_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&private_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(aud)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(nonce)))
        .unwrap();

    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

/// Builds a `jwt`-proof-type JWT whose header carries both `jwk` and `kid`,
/// violating the header key-material mutual-exclusivity rule.
fn generate_proof_jwt_with_jwk_and_kid(aud: &str, nonce: &str) -> String {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();
    header
        .set_claim("kid", Some(serde_json::json!("0")))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(aud)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

// ---------------------------------------------------------------------------
// VCI-0184 — Key Attestation JWT (L2497): `alg` is REQUIRED and MUST NOT be
// `none` or a symmetric algorithm.
// ---------------------------------------------------------------------------
#[test]
fn vci_0184_key_attestation_rejects_symmetric_alg() {
    let secret = NonceSecret::from_bytes([11u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let (jwt_str, ca_pem) = key_attestation_jwt_custom(
        "HS256",
        "key-attestation+jwt",
        Some(now),
        Some(now + 100_000),
        Some(&nonce),
        vec![sample_attested_jwk()],
    );
    let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

    let err = verify_key_attestation_jwt(&jwt_str, &store, &secret, now).unwrap_err();
    assert!(
        err.to_string().contains("alg"),
        "a symmetric (HS256) key attestation alg must be rejected, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// VCI-0185 — Key Attestation JWT (L2498): `typ` is REQUIRED and MUST be
// `key-attestation+jwt`.
// ---------------------------------------------------------------------------
#[test]
fn vci_0185_key_attestation_requires_correct_typ() {
    let secret = NonceSecret::from_bytes([12u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let (jwt_str, ca_pem) = key_attestation_jwt_custom(
        "ES256",
        "some-other-type+jwt",
        Some(now),
        Some(now + 100_000),
        Some(&nonce),
        vec![sample_attested_jwk()],
    );
    let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

    let err = verify_key_attestation_jwt(&jwt_str, &store, &secret, now).unwrap_err();
    assert!(err.to_string().contains("typ"), "got: {err}");
}

// ---------------------------------------------------------------------------
// VCI-0186 — Key Attestation JWT (L2503): `iat` is REQUIRED.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "GAP-VCI-05: OpenID4VCI Key Attestation JWT (L2503) — iat is REQUIRED in the Key Attestation JWT payload"]
fn vci_0186_key_attestation_without_iat_is_rejected() {
    let secret = NonceSecret::from_bytes([13u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let (jwt_str, ca_pem) = key_attestation_jwt_custom(
        "ES256",
        "key-attestation+jwt",
        None, // no iat at all
        Some(now + 100_000),
        Some(&nonce),
        vec![sample_attested_jwk()],
    );
    let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

    let result = verify_key_attestation_jwt(&jwt_str, &store, &secret, now);
    assert!(
        result.is_err(),
        "a Key Attestation JWT with no `iat` claim at all must be rejected — iat is REQUIRED"
    );
}

// ---------------------------------------------------------------------------
// VCI-0187 — Key Attestation JWT (L2504): `exp` MUST be present when the
// attestation is used with the `jwt` proof type (foundry requires it
// unconditionally, a superset of this rule).
// ---------------------------------------------------------------------------
#[test]
fn vci_0187_key_attestation_without_exp_is_rejected() {
    let secret = NonceSecret::from_bytes([14u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let (jwt_str, ca_pem) = key_attestation_jwt_custom(
        "ES256",
        "key-attestation+jwt",
        Some(now),
        None, // no exp
        Some(&nonce),
        vec![sample_attested_jwk()],
    );
    let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

    let err = verify_key_attestation_jwt(&jwt_str, &store, &secret, now).unwrap_err();
    assert!(err.to_string().contains("exp"), "got: {err}");
}

// ---------------------------------------------------------------------------
// VCI-0196 — Proof Types (L2610): a `jwt` proof object MUST include a `jwt`
// parameter whose value is a *non-empty* array of JWTs.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0196_proofs_jwt_array_must_be_non_empty() {
    let (_key_dir, key_path) = write_test_issuer_key();
    let (cfg, storage, access_token, secret) = setup_credential_flow(&key_path, "pid").await;

    let req = CredentialRequest {
        credential_configuration_id: Some("pid".to_string()),
        format: Some("dc+sd-jwt".to_string()),
        proofs: Some(ProofsRequest { jwt: vec![] }),
    };

    let result =
        handle_credential_request(&cfg, &storage, &access_token, &req, &secret, 1_700_000_020)
            .await;

    assert!(
        result.is_err(),
        "an empty `jwt` array in the proofs object must be rejected, not treated as no proof"
    );
}

// ---------------------------------------------------------------------------
// VCI-0200 / VCI-0212 / VCI-0226 / HAIP-0090 — jwt Proof Type (L2628, L2647);
// Verifying Proof (L2779); HAIP Requirements for Digital Signatures (L355):
// the proof `alg` MUST NOT be `none` or symmetric, and MUST match
// `proof_signing_alg_values_supported` (`["ES256"]`).
// ---------------------------------------------------------------------------
#[test]
fn vci_0200_0212_0226_haip_0090_proof_alg_must_be_es256() {
    let secret = NonceSecret::from_bytes([15u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let jwt_str = generate_proof_jwt_signed_with_hs256("https://issuer.example.com", &nonce);
    let empty_store = TrustStore::from_pems(&[]).unwrap();

    let result = verify_holder_proof(
        &jwt_str,
        "https://issuer.example.com",
        &secret,
        now,
        Mode::Optional,
        &empty_store,
    );

    assert!(
        result.is_err(),
        "a proof JWT actually signed with HS256 must be rejected — only ES256 is in \
         proof_signing_alg_values_supported"
    );
}

// ---------------------------------------------------------------------------
// VCI-0201 / VCI-0225 — jwt Proof Type (L2629); Verifying Proof (L2778): the
// proof MUST be explicitly typed via `typ: openid4vci-proof+jwt`.
// ---------------------------------------------------------------------------
#[test]
fn vci_0201_0225_proof_requires_correct_typ_header() {
    let secret = NonceSecret::from_bytes([16u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let jwt_str =
        generate_proof_jwt_with_typ("some-other-type+jwt", "https://issuer.example.com", &nonce);
    let empty_store = TrustStore::from_pems(&[]).unwrap();

    let err = verify_holder_proof(
        &jwt_str,
        "https://issuer.example.com",
        &secret,
        now,
        Mode::Optional,
        &empty_store,
    )
    .unwrap_err();

    assert!(err.to_string().contains("typ"), "got: {err}");
}

// ---------------------------------------------------------------------------
// VCI-0202 / VCI-0203 / VCI-0204 — jwt Proof Type (L2630-2632): `kid`, `jwk`
// and `x5c` header claims are mutually exclusive.
// ---------------------------------------------------------------------------
#[test]
fn vci_0202_0203_0204_proof_header_key_fields_are_mutually_exclusive() {
    let secret = NonceSecret::from_bytes([17u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let jwt_str = generate_proof_jwt_with_jwk_and_kid("https://issuer.example.com", &nonce);
    let empty_store = TrustStore::from_pems(&[]).unwrap();

    let result = verify_holder_proof(
        &jwt_str,
        "https://issuer.example.com",
        &secret,
        now,
        Mode::Optional,
        &empty_store,
    );

    assert!(
        result.is_err(),
        "a proof JWT header carrying both `jwk` and `kid` must be rejected"
    );
}

// ---------------------------------------------------------------------------
// VCI-0205 — jwt Proof Type (L2633): when a `c_nonce` was provided, the
// `nonce` claim in a header key attestation MUST be set to that `c_nonce` —
// i.e. it must match the outer proof's own (independently valid) nonce.
// ---------------------------------------------------------------------------
#[test]
fn vci_0205_proof_nonce_must_match_key_attestation_nonce() {
    let secret = NonceSecret::from_bytes([18u8; 32]);
    let now = now_secs();
    let attestation_nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let proof_nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    assert_ne!(
        attestation_nonce, proof_nonce,
        "the two minted nonces must differ to exercise a genuine mismatch"
    );

    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut holder_pub = keypair.to_jwk_public_key();
    holder_pub.set_algorithm("ES256");
    let holder_pub_json = serde_json::to_value(&holder_pub).unwrap();

    let (attestation_jwt, ca_pem) = key_attestation_jwt_custom(
        "ES256",
        "key-attestation+jwt",
        Some(now),
        Some(now + 100_000),
        Some(&attestation_nonce),
        vec![holder_pub_json],
    );
    let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("kid", Some(serde_json::json!("0")))
        .unwrap();
    header
        .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
        .unwrap();
    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(proof_nonce)))
        .unwrap();
    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    let result = verify_holder_proof(
        &jwt_str,
        "https://issuer.example.com",
        &secret,
        now,
        Mode::Required,
        &store,
    );

    assert!(
        result.is_err(),
        "a proof whose own nonce differs from the key attestation's nonce must be rejected, \
         even though both are independently valid minted nonces"
    );
}

// ---------------------------------------------------------------------------
// VCI-0207 — jwt Proof Type (L2637): `iss` MUST be omitted if the access
// token authorizing the issuance call was obtained from a Pre-Authorized
// Code Flow through anonymous access to the token endpoint.
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "GAP-VCI-06: OpenID4VCI jwt Proof Type (L2637) — iss MUST be omitted when the access token came from anonymous pre-authorized_code access"]
async fn vci_0207_proof_iss_must_be_omitted_after_anonymous_pre_auth_access() {
    let (_key_dir, key_path) = write_test_issuer_key();
    let (cfg, storage, access_token, secret) = setup_credential_flow(&key_path, "pid").await;

    // setup_credential_flow's TokenRequest carries client_id: None, i.e. this
    // access token was minted via anonymous pre-authorized_code access.
    let nonce = issue_nonce(&secret, 1_700_000_015).unwrap().c_nonce;
    let proof_jwt = generate_proof_jwt_with_iss(
        "https://issuer.example.com",
        &nonce,
        "attacker-supplied-client-id",
    );

    let req = CredentialRequest {
        credential_configuration_id: Some("pid".to_string()),
        format: Some("dc+sd-jwt".to_string()),
        proofs: Some(ProofsRequest {
            jwt: vec![proof_jwt],
        }),
    };

    let result =
        handle_credential_request(&cfg, &storage, &access_token, &req, &secret, 1_700_000_020)
            .await;

    assert!(
        result.is_err(),
        "a proof JWT carrying `iss` after anonymous pre-authorized_code access must be rejected"
    );
}

// ---------------------------------------------------------------------------
// VCI-0208 — jwt Proof Type (L2638): `aud` is REQUIRED and MUST be the
// Credential Issuer Identifier.
// ---------------------------------------------------------------------------
#[test]
fn vci_0208_proof_aud_mismatch_is_rejected() {
    let secret = NonceSecret::from_bytes([19u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let jwt_str = generate_proof_jwt_with_typ(
        "openid4vci-proof+jwt",
        "https://wrong-issuer.example.com",
        &nonce,
    );
    let empty_store = TrustStore::from_pems(&[]).unwrap();

    let err = verify_holder_proof(
        &jwt_str,
        "https://issuer.example.com",
        &secret,
        now,
        Mode::Optional,
        &empty_store,
    )
    .unwrap_err();

    assert!(err.to_string().contains("aud"), "got: {err}");
}

// ---------------------------------------------------------------------------
// VCI-0199 / VCI-0209 / VCI-0224 — jwt Proof Type (L2625, L2639); Verifying
// Proof (L2777): `iat` is REQUIRED in the jwt proof type payload.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "GAP-VCI-05: OpenID4VCI jwt Proof Type (L2639) — iat is REQUIRED in the jwt proof type payload"]
fn vci_0199_0209_0224_proof_jwt_without_iat_is_rejected() {
    let secret = NonceSecret::from_bytes([20u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    // generate_proof_jwt never sets `iat` at all — this is the happy-path
    // builder every other (non-ignored) test in this suite relies on, which
    // is itself evidence of how unenforced this requirement is.
    let jwt_str = generate_proof_jwt(&nonce, "https://issuer.example.com");
    let empty_store = TrustStore::from_pems(&[]).unwrap();

    let result = verify_holder_proof(
        &jwt_str,
        "https://issuer.example.com",
        &secret,
        now,
        Mode::Optional,
        &empty_store,
    );

    assert!(
        result.is_err(),
        "a proof JWT with no `iat` claim at all must be rejected — iat is REQUIRED"
    );
}

// ---------------------------------------------------------------------------
// VCI-0228 — Verifying Proof (L2781): the header parameter MUST NOT contain
// a private key. A JWK header carrying `d` (the private scalar) fails
// verification here — josekit's `verifier_from_jwk` rejects building an
// ES256 verifier from a JWK that includes private-key material, so this
// turned out to already be conforming (the initial hypothesis of a gap was
// disproved by running this test before writing the `#[ignore]`).
// ---------------------------------------------------------------------------
#[test]
fn vci_0228_proof_jwk_header_must_not_contain_private_key() {
    let secret = NonceSecret::from_bytes([21u8; 32]);
    let now = now_secs();
    let nonce = issue_nonce(&secret, now).unwrap().c_nonce;
    let jwt_str =
        generate_proof_jwt_with_private_key_in_header("https://issuer.example.com", &nonce);
    let empty_store = TrustStore::from_pems(&[]).unwrap();

    let result = verify_holder_proof(
        &jwt_str,
        "https://issuer.example.com",
        &secret,
        now,
        Mode::Optional,
        &empty_store,
    );

    assert!(
        result.is_err(),
        "a proof JWT whose `jwk` header contains the private key (a `d` component) must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Plural `proofs`: every proof in the array MUST be validated, not just the
// first — a later invalid proof must still cause rejection.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vci_0058_plural_proofs_validates_every_proof_not_just_the_first() {
    let (_key_dir, key_path) = write_test_issuer_key();
    let (cfg, storage, access_token, secret) = setup_credential_flow(&key_path, "pid").await;

    let nonce = issue_nonce(&secret, 1_700_000_015).unwrap().c_nonce;
    let good = generate_proof_jwt(&nonce, "https://issuer.example.com");
    // aud mismatch — invalid, and placed *after* a valid proof.
    let bad = generate_proof_jwt(&nonce, "https://wrong-issuer.example.com");

    let req = CredentialRequest {
        credential_configuration_id: Some("pid".to_string()),
        format: Some("dc+sd-jwt".to_string()),
        proofs: Some(ProofsRequest {
            jwt: vec![good, bad],
        }),
    };

    let result =
        handle_credential_request(&cfg, &storage, &access_token, &req, &secret, 1_700_000_020)
            .await;

    assert!(
        result.is_err(),
        "a later invalid proof must still cause rejection, even though an earlier proof in the \
         same request was valid"
    );
}

// ---------------------------------------------------------------------------
// Task 11 fixtures and tests: Issuer and Authorization Server Metadata
// (VCI §12, HAIP §3.1 Issuer Metadata). Code under audit:
// `crates/foundry-issuer/src/metadata.rs`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// VCI-0118 — Credential Issuer Metadata (L1325): the Credential Issuer MUST
// support returning metadata in an unsigned form as `application/json`.
// ---------------------------------------------------------------------------
#[test]
fn vci_0118_metadata_round_trips_as_plain_json() {
    let cfg = test_config();
    let meta = build_issuer_metadata(&cfg);

    // metadata.rs never signs or wraps the document; it is a plain `Serialize`
    // struct that always round-trips as ordinary JSON, which is exactly what
    // `issuer_metadata` (crates/foundry/src/server.rs) returns via `Json<..>`.
    let value = serde_json::to_value(&meta).expect("metadata must serialize as plain JSON");
    assert!(value.is_object());
    assert_eq!(
        value["credential_issuer"],
        serde_json::json!("https://issuer.example.com")
    );

    // VCI-0141: issuer-level `display` is hardcoded to `Vec::new()` in
    // `build_issuer_metadata` (metadata.rs) and thus always omitted — zero
    // objects trivially satisfies "at most one object per language
    // identifier".
    assert!(value.get("display").is_none());
}

// ---------------------------------------------------------------------------
// VCI-0129 — Credential Issuer Metadata (L1367): `authorization_servers`,
// when present, MUST be a non-empty array of Authorization Server
// identifiers. foundry never populates this field (it always acts as its
// own implicit Authorization Server — the same single-AS topology already
// established for VCI-0011/0016), so the field is always omitted rather than
// present-and-empty, and the conditional MUST is vacuously satisfied.
// ---------------------------------------------------------------------------
#[test]
fn vci_0129_authorization_servers_omitted_when_empty() {
    let cfg = test_config();
    let meta = build_issuer_metadata(&cfg);
    let value = serde_json::to_value(&meta).unwrap();

    assert!(
        value.get("authorization_servers").is_none(),
        "authorization_servers must be omitted entirely, not serialized as an empty array, \
         since it is never populated with a non-empty set of identifiers"
    );
}

// ---------------------------------------------------------------------------
// VCI-0155 — Credential Issuer Metadata (L1420): the Authorization Server
// MUST be able to determine from Issuer metadata which claims the requested
// Credentials disclose.
// ---------------------------------------------------------------------------
#[test]
fn vci_0155_credential_configuration_claims_reveal_disclosed_paths() {
    let cfg = test_config();
    let meta = build_issuer_metadata(&cfg);
    let pid = meta.credential_configurations_supported.get("pid").unwrap();

    assert_eq!(pid.claims.len(), 1);
    assert_eq!(pid.claims[0]["path"], serde_json::json!(["given_name"]));
    assert_eq!(
        pid.claims[0]["selectively_disclosable"],
        serde_json::json!(true)
    );
}

// ---------------------------------------------------------------------------
// VCI-0130 / VCI-0131 — Credential Issuer Metadata (L1368, L1369):
// `credential_endpoint` is REQUIRED and MUST use the `https` scheme;
// `nonce_endpoint`, when present, MUST use the `https` scheme. Both are
// derived unconditionally from `issuer.credential_issuer` (`build_issuer_metadata`,
// metadata.rs), but `Config::validate()` (foundry-core/src/config/validate.rs)
// never inspects its scheme — an operator-supplied `http://` (or any
// non-`https`) `credential_issuer` passes validation and is silently baked
// into both derived endpoint URLs.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "GAP-VCI-08: OpenID4VCI Credential Issuer Metadata (L1368, L1369) — credential_endpoint and nonce_endpoint MUST use the https scheme, but Config::validate() never checks the scheme of issuer.credential_issuer"]
fn vci_0130_0131_config_validation_does_not_enforce_https_scheme_for_issuer_urls() {
    let mut cfg = test_config();
    // Satisfy the *only* other check `Config::validate()` performs (that
    // `verifier.signing_key` resolves in `keys`) so that a failure here can
    // only be attributed to the https-scheme hypothesis under test.
    cfg.keys.insert(
        "verifier_signing".to_string(),
        KeyEntry {
            private_key: "unused.pem".to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );
    cfg.issuer.credential_issuer = "http://issuer.example.com".to_string();
    cfg.server.wallet_facing.public_base_url = "http://issuer.example.com".to_string();

    let result = cfg.validate();

    assert!(
        result.is_err(),
        "a non-https credential_issuer must be rejected by config validation, since both \
         credential_endpoint and nonce_endpoint are derived from it and MUST use https"
    );
}

// ---------------------------------------------------------------------------
// VCI-0128 — Credential Issuer Metadata (L1366): `credential_issuer` is
// REQUIRED and MUST be identical to the identifier used to build the
// well-known URL. foundry has two independently configurable values —
// `server.wallet_facing.public_base_url` (what the wallet-facing router is
// actually served under) and `issuer.credential_issuer` (what
// `build_issuer_metadata` puts in the `credential_issuer` field) — and
// `Config::validate()` never checks that they match.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "GAP-VCI-09: OpenID4VCI Credential Issuer Metadata (L1366) — credential_issuer MUST be identical to the identifier used to build the well-known URL, but Config::validate() never checks server.wallet_facing.public_base_url against issuer.credential_issuer"]
fn vci_0128_config_validation_does_not_enforce_credential_issuer_identity_match() {
    let mut cfg = test_config();
    // Satisfy the *only* other check `Config::validate()` performs (that
    // `verifier.signing_key` resolves in `keys`) so that a failure here can
    // only be attributed to the identity-mismatch hypothesis under test.
    cfg.keys.insert(
        "verifier_signing".to_string(),
        KeyEntry {
            private_key: "unused.pem".to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );
    cfg.server.wallet_facing.public_base_url = "https://different-host.example.com".to_string();
    // cfg.issuer.credential_issuer is left at "https://issuer.example.com" —
    // the two values now diverge.

    let result = cfg.validate();

    assert!(
        result.is_err(),
        "a credential_issuer that diverges from the wallet-facing router's own public_base_url \
         must be rejected by config validation, since the served metadata's credential_issuer \
         field would not match the identifier used to reach it"
    );
}

// ---------------------------------------------------------------------------
// VCI-0146 / VCI-0147 — Credential Issuer Metadata (L1394, L1395):
// `cryptographic_binding_methods_supported` MUST be present when
// Cryptographic Key Binding is required and omitted otherwise;
// `proof_types_supported` MUST be present if
// `cryptographic_binding_methods_supported` is present, and omitted
// otherwise. `build_issuer_metadata` (metadata.rs) always serializes both
// fields regardless of `ct.cryptographic_holder_binding` — neither field
// carries a `skip_serializing_if` annotation, and `proof_types_supported`
// is unconditionally populated with a `jwt` entry.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "GAP-VCI-07: OpenID4VCI Credential Issuer Metadata (L1394, L1395) — cryptographic_binding_methods_supported and proof_types_supported MUST be omitted when Cryptographic Key Binding is not required, but build_issuer_metadata always serializes both"]
fn vci_0146_0147_metadata_omits_binding_and_proof_fields_when_key_binding_not_required() {
    let mut cfg = test_config();
    cfg.credential_types[0].cryptographic_holder_binding = false;

    let meta = build_issuer_metadata(&cfg);
    let value = serde_json::to_value(&meta).unwrap();
    let pid = &value["credential_configurations_supported"]["pid"];

    assert!(
        pid.get("cryptographic_binding_methods_supported").is_none(),
        "cryptographic_binding_methods_supported must be omitted when key binding is not \
         required, not serialized as an empty array"
    );
    assert!(
        pid.get("proof_types_supported").is_none(),
        "proof_types_supported must be omitted when cryptographic_binding_methods_supported is \
         absent, since key binding is not required for this credential configuration"
    );
}

// ---------------------------------------------------------------------------
// VCI-0150 / VCI-0151 / VCI-0152 / VCI-0153 / VCI-0154 — Credential Issuer
// Metadata (L1402-1410): credential `display` objects are subject to several
// structural MUSTs — `name` is REQUIRED, at most one `display` object per
// language identifier, logo `uri` is REQUIRED, `background_image` MUST carry
// a `uri`. `ct.display` (config.rs) is untyped `Vec<serde_json::Value>`
// passed straight through by `build_issuer_metadata` into
// `CredentialConfigurationSupported.display`, and `Config::validate()`
// performs no structural check on it at all.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "GAP-VCI-10: OpenID4VCI Credential Issuer Metadata (L1402-1410) — credential display objects MUST carry a required name, at most one object per locale, and required logo/background_image uri fields, but Config::validate() never structurally validates the display array"]
fn vci_0150_0151_0152_0153_0154_credential_display_objects_are_not_structurally_validated() {
    let mut cfg = test_config();
    // Satisfy the *only* other check `Config::validate()` performs (that
    // `verifier.signing_key` resolves in `keys`) so that a failure here can
    // only be attributed to the display-shape hypothesis under test.
    cfg.keys.insert(
        "verifier_signing".to_string(),
        KeyEntry {
            private_key: "unused.pem".to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );
    // Two objects that violate every one of the clauses above: duplicate
    // locale, no `name`, a logo with no `uri`, and a background_image with
    // no `uri`.
    cfg.credential_types[0].display = vec![
        serde_json::json!({"locale": "en-US", "logo": {}, "background_image": {}}),
        serde_json::json!({"locale": "en-US"}),
    ];

    let result = cfg.validate();

    assert!(
        result.is_err(),
        "malformed credential display objects (duplicate locale, missing name, logo without \
         uri, background_image without uri) must be rejected by config validation"
    );
}

// ---------------------------------------------------------------------------
// HAIP-0011 — OpenID4VCI (L177): the Issuer MUST indicate whether batch
// issuance is supported by including or omitting `batch_credential_issuance`.
// foundry always omits the field (the struct has no such member at all —
// see VCI-0140, `not-implemented`), which is itself a fully valid indication
// under the letter of this clause. As positive evidence that this omission
// is at least a coherent design choice and not an oversight that silently
// breaks multi-proof requests, this test confirms `handle_credential_request`
// (credential.rs) actually accepts more than one proof and issues one
// Credential per proof for the same Credential Dataset in a single
// request/response — i.e. batch issuance functionally works even though it
// is never advertised via `batch_credential_issuance`.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn haip_0011_multiple_proofs_yield_one_credential_per_proof() {
    let (_key_dir, key_path) = write_test_issuer_key();
    let (cfg, storage, access_token, secret) = setup_credential_flow(&key_path, "pid").await;

    let nonce = issue_nonce(&secret, 1_700_000_015).unwrap().c_nonce;
    let first = generate_proof_jwt(&nonce, "https://issuer.example.com");
    let second = generate_proof_jwt(&nonce, "https://issuer.example.com");

    let req = CredentialRequest {
        credential_configuration_id: Some("pid".to_string()),
        format: Some("dc+sd-jwt".to_string()),
        proofs: Some(ProofsRequest {
            jwt: vec![first, second],
        }),
    };

    let res =
        handle_credential_request(&cfg, &storage, &access_token, &req, &secret, 1_700_000_020)
            .await
            .expect(
                "two independently valid proofs for the same Credential Dataset must be accepted",
            );

    assert_eq!(
        res.credentials.len(),
        2,
        "one Credential must be issued per proof in the plural `proofs` array"
    );

    // And yet the metadata for this very configuration never advertises
    // batch support at all (VCI-0140, not-implemented) — the field does not
    // exist as a struct member, so it can never be serialized.
    let meta = build_issuer_metadata(&cfg);
    let value = serde_json::to_value(&meta).unwrap();
    assert!(
        value.get("batch_credential_issuance").is_none(),
        "batch_credential_issuance has no corresponding struct field and can never be present"
    );
}
