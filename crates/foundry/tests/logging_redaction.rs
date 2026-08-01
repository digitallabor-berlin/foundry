//! The redaction gate: proves that no secret reaches the log.
//!
//! Every other test in this change asserts that something *is* logged. These
//! assert the harder property — that specific values are **not** logged — by
//! driving real flows through the real routers with uniquely identifiable
//! secrets and then searching the entire captured buffer for them.
//!
//! Two design points make these tests worth their weight:
//!
//! 1. **They capture at `TRACE`**, so the assertions cover every level, not just
//!    the ones enabled by default. A leak that only appears at `debug` is still
//!    a leak: `RUST_LOG=debug` is an ordinary thing to set.
//! 2. **There is a positive control.** Without proving that
//!    `sensitive_payloads = true` really does unlock a payload field, every
//!    negative assertion here could pass because the feature is inert.
//!
//! If an assertion in this file fails, that is a real leak. Fix the emitting
//! site; never weaken the assertion.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::log_capture::{self, CaptureHandle};
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, KeyEntry,
    LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
    WalletFacingConfig,
};
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::storage::SqliteStorage;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use tower::ServiceExt;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;

/// `obs::set_sensitive` is process-global, so tests that depend on its value
/// must not run concurrently. Every test here takes this lock, including the
/// negative ones — they depend on the flag being *off*.
///
/// Deliberately `tokio::sync::Mutex`, not `std::sync::Mutex`: the guard is held
/// across `.await` points while a flow is driven, and a `std` guard held across
/// an await can deadlock on a multi-threaded runtime (clippy's
/// `await_holding_lock` flags exactly this).
static FLAG_LOCK: Mutex<()> = Mutex::const_new(());

async fn lock_flag() -> MutexGuard<'static, ()> {
    FLAG_LOCK.lock().await
}

/// Install a capture layer at `TRACE` for the duration of the returned guard.
fn capture_at_trace() -> (tracing::subscriber::DefaultGuard, CaptureHandle) {
    let (layer, handle) = log_capture::capture_layer();
    let subscriber = tracing_subscriber::Registry::default()
        .with(LevelFilter::TRACE)
        .with(layer);
    (tracing::subscriber::set_default(subscriber), handle)
}

const ADMIN_KEY: &str = "test-admin-key";
const ISSUER: &str = "https://issuer.example.com";

/// A claim value planted so it can be searched for. Deliberately unlike any
/// word that could appear in a log message by coincidence.
const PLANTED_CLAIM: &str = "Zzyzx-Planted-Claim-Value-9182";

async fn setup() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("foundry.db");
    let key_path = dir.path().join("issuer.pem");

    let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).expect("key");
    std::fs::write(&key_path, km.private_pem).expect("write key");

    let storage = SqliteStorage::connect(db_path.to_str().expect("db path"))
        .await
        .expect("storage");

    let mut keys = BTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            private_key: key_path.to_str().expect("key path").to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: ISSUER.to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: false,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: Some(ADMIN_KEY.to_string()),
                api_key_env: None,
                swagger_ui_enabled: false,
                console_enabled: false,
            },
        },
        storage: StorageConfig {
            path: db_path.to_str().expect("db path").to_string(),
            transaction_ttl_secs: 600,
        },
        keys,
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: ISSUER.to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some(format!("{ISSUER}/vct/pid")),
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
            signing_key: "issuer_key".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
            dc_api_expected_origins: Vec::new(),
        },
        logging: LoggingConfig::default(),
    };

    (AppState::new(Arc::new(storage), Arc::new(config)), dir)
}

fn create_proof(c_nonce: &str) -> String {
    let keypair = EcKeyPair::generate(EcCurve::P256).expect("keypair");
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).expect("jwk")))
        .expect("set jwk");

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(ISSUER)))
        .expect("aud");
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .expect("nonce");

    let signer = ES256
        .signer_from_jwk(&keypair.to_jwk_private_key())
        .expect("signer");
    jwt::encode_with_signer(&payload, &header, &signer).expect("jwt")
}

async fn body_json(res: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Everything an issuance produces that must never appear in a log.
struct IssuanceSecrets {
    pre_auth_code: String,
    access_token: String,
    c_nonce: String,
    credential: String,
}

/// Drive a complete issuance through the real routers.
async fn drive_issuance(state: &AppState) -> IssuanceSecrets {
    let admin = admin_router(state.clone(), AdminApiKey(Some(ADMIN_KEY.into())));
    let offer_res = admin
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
                .body(Body::from(
                    serde_json::json!({
                        "credential_type_id": "pid",
                        "claims": { "given_name": PLANTED_CLAIM },
                        "tx_code_required": false
                    })
                    .to_string(),
                ))
                .expect("offer request"),
        )
        .await
        .expect("offer response");
    assert_eq!(offer_res.status(), StatusCode::OK);
    let offer = body_json(offer_res).await;
    let pre_auth_code = offer["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .expect("pre-authorized code")
        .to_string();

    let token_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
                )))
                .expect("token request"),
        )
        .await
        .expect("token response");
    assert_eq!(token_res.status(), StatusCode::OK);
    let token = body_json(token_res).await;
    let access_token = token["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let nonce_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/nonce")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("nonce request"),
        )
        .await
        .expect("nonce response");
    assert_eq!(nonce_res.status(), StatusCode::OK);
    let c_nonce = body_json(nonce_res).await["c_nonce"]
        .as_str()
        .expect("c_nonce")
        .to_string();

    let cred_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(
                    serde_json::json!({
                        "credential_configuration_id": "pid",
                        "format": "dc+sd-jwt",
                        "proofs": { "jwt": [create_proof(&c_nonce)] },
                    })
                    .to_string(),
                ))
                .expect("credential request"),
        )
        .await
        .expect("credential response");
    assert_eq!(cred_res.status(), StatusCode::OK);
    let credential = body_json(cred_res).await["credentials"][0]["credential"]
        .as_str()
        .expect("credential")
        .to_string();

    IssuanceSecrets {
        pre_auth_code,
        access_token,
        c_nonce,
        credential,
    }
}

/// Create a verification request and post `jwe` to it, returning the status.
async fn drive_verification(state: &AppState, jwe: &str) -> StatusCode {
    let admin = admin_router(state.clone(), AdminApiKey(Some(ADMIN_KEY.into())));
    let create_res = admin
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/verification/requests")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
                .body(Body::from(
                    serde_json::json!({
                        "dcql_query": {
                            "credentials": [{
                                "id": "q1",
                                "format": "dc+sd-jwt",
                                "meta": { "vct_values": [format!("{ISSUER}/vct/pid")] }
                            }]
                        }
                    })
                    .to_string(),
                ))
                .expect("create verification request"),
        )
        .await
        .expect("create verification response");
    assert_eq!(create_res.status(), StatusCode::OK);
    let created = body_json(create_res).await;
    let id = created["verification_id"]
        .as_str()
        .expect("verification_id")
        .to_string();

    let res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/vp/response/{id}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("response={jwe}")))
                .expect("vp response request"),
        )
        .await
        .expect("vp response");
    res.status()
}

/// The central negative assertion: a complete issuance, captured at `TRACE`,
/// must not have written the pre-authorized code, the access token, the
/// `c_nonce`, the issued credential, or the holder's claim value anywhere.
#[tokio::test]
async fn issuance_never_logs_codes_tokens_nonces_or_claims() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir) = setup().await;
    let (guard, log) = capture_at_trace();
    let secrets = drive_issuance(&state).await;
    drop(guard);

    // Sanity: the capture actually saw the flow. Without this, the assertions
    // below would pass on an empty buffer.
    assert!(
        !log.events().is_empty(),
        "captured nothing; the negative assertions below would be vacuous"
    );

    for (label, secret) in [
        ("pre-authorized code", &secrets.pre_auth_code),
        ("access token", &secrets.access_token),
        ("c_nonce", &secrets.c_nonce),
        ("issued credential", &secrets.credential),
    ] {
        assert!(
            !secret.is_empty(),
            "{label} was empty, so its assertion would be vacuous"
        );
        assert!(!log.contains_value(secret), "{label} leaked into the log");
    }

    assert!(
        !log.contains_value(PLANTED_CLAIM),
        "the holder's claim value leaked into the log"
    );
}

/// The response JWE and the ephemeral private key must not be logged when
/// payload logging is off.
#[tokio::test]
async fn verification_never_logs_the_response_payload_when_locked() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir) = setup().await;
    let jwe = "Zzyzx.Planted.Jwe.Value.7731";

    let (guard, log) = capture_at_trace();
    let status = drive_verification(&state, jwe).await;
    drop(guard);

    // A junk JWE is a structural failure: HTTP 400 per root AGENTS.md §4.3.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!log.events().is_empty(), "captured nothing");

    assert!(
        !log.contains_value(jwe),
        "the raw response JWE leaked with payload logging disabled"
    );
    // The ephemeral private key must never be logged, in any mode.
    assert!(
        !log.contains_value("\"d\":"),
        "a private JWK component appears in the log"
    );
    assert!(
        !log.contains_value("ephem_private_jwk"),
        "the ephemeral private key field name appears in the log"
    );
}

/// The positive control. Without this, every negative assertion above could pass
/// simply because the payload feature is inert — which would be a false sense of
/// safety rather than safety.
#[tokio::test]
async fn payload_logging_really_unlocks_the_payload_when_enabled() {
    let _flag = lock_flag().await;

    let (state, _dir) = setup().await;
    let jwe = "Zzyzx.Positive.Control.Jwe.5540";

    foundry_core::obs::set_sensitive(true);
    let (guard, log) = capture_at_trace();
    let _ = drive_verification(&state, jwe).await;
    drop(guard);
    // Restore immediately: this flag is process-global.
    foundry_core::obs::set_sensitive(false);

    assert!(
        log.contains_value(jwe),
        "with sensitive_payloads enabled the JWE should be logged at debug; if it \
         is not, the switch is inert and every negative assertion in this file is \
         meaningless"
    );
}

/// Even with payloads unlocked, private key material stays out of the log. The
/// dev-only flag widens what may be logged; it does not remove the floor.
#[tokio::test]
async fn payload_logging_does_not_unlock_private_key_material() {
    let _flag = lock_flag().await;

    let (state, _dir) = setup().await;
    foundry_core::obs::set_sensitive(true);
    let (guard, log) = capture_at_trace();
    let _ = drive_verification(&state, "Zzyzx.Another.Jwe.3312").await;
    drop(guard);
    foundry_core::obs::set_sensitive(false);

    assert!(
        !log.contains_value("ephem_private_jwk"),
        "the ephemeral private key must stay out of the log even in dev mode"
    );
}

/// Field names are operator-facing API. This asserts they are actually present
/// on a real request, complementing the static check in
/// `instrumentation_hygiene.rs`.
#[tokio::test]
async fn a_real_request_carries_the_documented_correlation_fields() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir) = setup().await;
    let (guard, log) = capture_at_trace();
    let _ = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    drop(guard);

    let access = log
        .events()
        .into_iter()
        .find(|e| e.fields.contains_key("http.status"))
        .expect("an access-log record");

    for field in [
        "request_id",
        "method",
        "route",
        "listener",
        "http.status",
        "latency_ms",
    ] {
        assert!(
            access.fields.contains_key(field),
            "access record is missing `{field}`: {access:?}"
        );
    }
    assert_eq!(
        access.fields.get("route").map(String::as_str),
        Some("/.well-known/openid-credential-issuer"),
        "route must be the template, not a rewritten path"
    );
}

// ---------------------------------------------------------------------------
// Task 10 (GAP-VCI-14): the Client Attestation PoP JWT and its raw `jti` are
// new secret-bearing values introduced by this change; AGENTS.md sect-4.5 makes
// redaction a *behavioural* requirement, so these must be asserted, not just
// reviewed.
// ---------------------------------------------------------------------------

const POP_JTI_PLANTED: &str = "Zzyzx-Planted-Pop-Jti-4471";

/// Same shape as `setup()`, but with `wallet_attestation: Mode::Required`
/// pointed at a fresh CA -- needed to drive a real attestation+pop /token
/// request. Returns `(state, _tempdir, _ca_tempdir)`.
async fn setup_with_required_attestation() -> (
    AppState,
    tempfile::TempDir,
    tempfile::TempDir,
    String,
    String,
) {
    use foundry_core::config::TrustAnchor;
    use foundry_core::pki::new_ca;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("foundry.db");
    let key_path = dir.path().join("issuer.pem");

    let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).expect("key");
    std::fs::write(&key_path, km.private_pem).expect("write key");

    let storage = SqliteStorage::connect(db_path.to_str().expect("db path"))
        .await
        .expect("storage");

    let mut keys = BTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            private_key: key_path.to_str().expect("key path").to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );

    let ca = new_ca("Test Wallet Provider Root CA", 3650).expect("ca");
    let ca_dir = tempfile::tempdir().expect("ca tempdir");
    let ca_path = ca_dir.path().join("wallet-provider-ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: ISSUER.to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: false,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: Some(ADMIN_KEY.to_string()),
                api_key_env: None,
                swagger_ui_enabled: false,
                console_enabled: false,
            },
        },
        storage: StorageConfig {
            path: db_path.to_str().expect("db path").to_string(),
            transaction_ttl_secs: 600,
        },
        keys,
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: ISSUER.to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Required,
                trusted_anchors: vec![TrustAnchor {
                    name: "wallet-provider-ca".to_string(),
                    certs: ca_path.to_str().expect("ca path").to_string(),
                }],
                pop_max_age_secs: 300,
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some(format!("{ISSUER}/vct/pid")),
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
            signing_key: "issuer_key".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
            dc_api_expected_origins: Vec::new(),
        },
        logging: LoggingConfig::default(),
    };

    (
        AppState::new(Arc::new(storage), Arc::new(config)),
        dir,
        ca_dir,
        ca.cert_pem,
        ca.key_pem,
    )
}

/// A validly signed Wallet Attestation JWT (chained to the CA identified by
/// `ca_cert_pem`/`ca_key_pem`) plus a Client Attestation PoP JWT carrying
/// `POP_JTI_PLANTED` as its `jti`, that verifies against the attestation's
/// `cnf.jwk`.
fn signed_attestation_and_pop_with_planted_jti(
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> (String, String) {
    use base64::Engine as _;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm as SigAlg, Signer};
    use foundry_core::pki::issue_leaf;
    use foundry_core::trust::build_x5c;
    use josekit::jws::JwsSigner;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64;

    let kp = EcKeyPair::generate(EcCurve::P256).expect("pop keypair");
    let mut cnf_jwk = kp.to_jwk_public_key();
    cnf_jwk.set_algorithm("ES256");
    let pop_signer = ES256
        .signer_from_jwk(&kp.to_jwk_private_key())
        .expect("pop signer");

    let leaf = issue_leaf(
        ca_cert_pem,
        ca_key_pem,
        "wallet-provider.example.com",
        &["wallet-provider.example.com".to_string()],
        365,
    )
    .expect("issue_leaf");
    let x5c = build_x5c(&[leaf.cert_pem.clone().into_bytes()]).expect("x5c");

    let wallet_sub = "https://wallet.example.org";
    let header = serde_json::json!({
        "typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": x5c,
    });
    let payload = serde_json::json!({
        "iss": "https://wallet-provider.example.com",
        "sub": wallet_sub,
        "exp": now + 100_000,
        "cnf": { "jwk": cnf_jwk },
    });
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let leaf_signer =
        FileSigner::from_pem(leaf.key_pem.as_bytes(), SigAlg::Es256).expect("leaf signer");
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(leaf_signer.sign(signing_input.as_bytes()).unwrap());
    let attestation_jwt = format!("{signing_input}.{sig_b64}");

    let pop_header = serde_json::json!({
        "typ": "oauth-client-attestation-pop+jwt", "alg": "ES256",
    });
    let pop_payload = serde_json::json!({
        "iss": wallet_sub, "aud": ISSUER, "jti": POP_JTI_PLANTED, "iat": now,
    });
    let pop_header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&pop_header).unwrap());
    let pop_payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&pop_payload).unwrap());
    let pop_signing_input = format!("{pop_header_b64}.{pop_payload_b64}");
    let pop_sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(pop_signer.sign(pop_signing_input.as_bytes()).unwrap());
    let pop_jwt = format!("{pop_signing_input}.{pop_sig_b64}");

    (attestation_jwt, pop_jwt)
}

/// Creates a `pre-authorized_code` offer and drives `/token` with the given
/// attestation/pop headers attached. Returns the response status.
async fn drive_token_with_attestation_and_pop(
    state: &AppState,
    attestation_jwt: &str,
    pop_jwt: &str,
) -> StatusCode {
    let admin_app = admin_router(state.clone(), AdminApiKey(Some(ADMIN_KEY.into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": { "given_name": "Alice" },
        "tx_code_required": false,
    });
    let offer_res = admin_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
                .body(Body::from(offer_req_body.to_string()))
                .expect("offer request"),
        )
        .await
        .expect("offer response");
    assert_eq!(offer_res.status(), StatusCode::OK);
    let offer_json = body_json(offer_res).await;
    let pre_auth_code = offer_json["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .expect("pre-authorized_code");

    let wallet_app = wallet_router(state.clone());
    let token_res = wallet_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("OAuth-Client-Attestation", attestation_jwt)
                .header("OAuth-Client-Attestation-PoP", pop_jwt)
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
                )))
                .expect("token request"),
        )
        .await
        .expect("token response");
    token_res.status()
}

/// The raw PoP JWT and its raw `jti` must never appear in the log with
/// payload logging *disabled* -- the ordinary production posture.
#[tokio::test]
async fn token_request_never_logs_the_raw_pop_jwt_or_jti_when_locked() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir, _ca_dir, ca_cert_pem, ca_key_pem) = setup_with_required_attestation().await;
    let (attestation_jwt, pop_jwt) =
        signed_attestation_and_pop_with_planted_jti(&ca_cert_pem, &ca_key_pem);

    let (guard, log) = capture_at_trace();
    let _ = drive_token_with_attestation_and_pop(&state, &attestation_jwt, &pop_jwt).await;
    drop(guard);

    assert!(!log.events().is_empty(), "captured nothing");
    assert!(
        !log.contains_value(&pop_jwt),
        "the raw Client Attestation PoP JWT leaked into the log (sensitive disabled)"
    );
    assert!(
        !log.contains_value(POP_JTI_PLANTED),
        "the raw pop jti leaked into the log (sensitive disabled)"
    );
}

/// The same two values must stay out of the log even with payload logging
/// *enabled* -- sect-4.5's floor applies regardless of the dev-only flag; only a
/// `debug`/`trace` level payload field is conditionally unlocked, and the raw
/// PoP JWT / jti are never that kind of field.
#[tokio::test]
async fn token_request_never_logs_the_raw_pop_jwt_or_jti_even_with_sensitive_enabled() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(true);

    let (state, _dir, _ca_dir, ca_cert_pem, ca_key_pem) = setup_with_required_attestation().await;
    let (attestation_jwt, pop_jwt) =
        signed_attestation_and_pop_with_planted_jti(&ca_cert_pem, &ca_key_pem);

    let (guard, log) = capture_at_trace();
    let _ = drive_token_with_attestation_and_pop(&state, &attestation_jwt, &pop_jwt).await;
    drop(guard);
    foundry_core::obs::set_sensitive(false);

    assert!(!log.events().is_empty(), "captured nothing");
    assert!(
        !log.contains_value(&pop_jwt),
        "the raw Client Attestation PoP JWT leaked into the log (sensitive enabled)"
    );
    assert!(
        !log.contains_value(POP_JTI_PLANTED),
        "the raw pop jti leaked into the log (sensitive enabled)"
    );
}

/// A whole presentation flow must be reconstructible from one `tx_id`, across
/// three requests on two different listeners. That is the property that turns a
/// pile of log lines into a diagnosis.
#[tokio::test]
async fn one_tx_id_threads_the_whole_verification_flow() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir) = setup().await;
    let (guard, log) = capture_at_trace();
    let _ = drive_verification(&state, "Zzyzx.Thread.Test.1199").await;
    drop(guard);

    let events = log.events();
    let tx_ids: std::collections::BTreeSet<&str> = events
        .iter()
        .filter_map(|e| e.fields.get("tx_id").map(String::as_str))
        .collect();

    assert_eq!(
        tx_ids.len(),
        1,
        "expected exactly one transaction id across the flow, saw {tx_ids:?}"
    );
    let tx_id = tx_ids.iter().next().expect("one tx_id");

    let tagged = events
        .iter()
        .filter(|e| e.fields.get("tx_id").map(String::as_str) == Some(*tx_id))
        .count();
    assert!(
        tagged >= 2,
        "only {tagged} event(s) carry tx_id; a single id should thread the \
         creation and the response"
    );
}
