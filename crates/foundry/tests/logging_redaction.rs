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

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use foundry::admin_auth::AdminApiKey;
use foundry::log_capture::{self, CaptureHandle};
use foundry::server::{AppState, admin_router, wallet_router};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
    KeyEntry, LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
    WalletFacingConfig,
};
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::storage::SqliteStorage;
use josekit::jwk::KeyPair as _;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jws::{ES256, JwsHeader};
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

    // HAIP OpenID4VP L256: x509_hash requires a certificate to hash. This
    // KeyEntry ("issuer_key") also signs the verifier's Request Objects
    // (verifier.signing_key below), so it needs a leaf certificate whose SAN
    // matches ISSUER's host, not a bare EC key pair.
    let ca = foundry_core::pki::new_ca("Test Redaction Root CA", 3650).expect("ca");
    let leaf = foundry_core::pki::issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "issuer.example.com",
        &["issuer.example.com".to_string()],
        365,
    )
    .expect("issue_leaf");
    std::fs::write(&key_path, &leaf.key_pem).expect("write key");
    let cert_path = dir.path().join("issuer_leaf_cert.pem");
    std::fs::write(&cert_path, &leaf.cert_pem).expect("write cert");

    let storage = SqliteStorage::connect(db_path.to_str().expect("db path"))
        .await
        .expect("storage");

    let mut keys = BTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            private_key: key_path.to_str().expect("key path").to_string(),
            x5c: Some(cert_path.to_str().expect("cert path").to_string()),
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
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
            encrypted_pre_authorized_code: Default::default(),
            access_token_ttl_secs: 600,
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some(format!("{ISSUER}/vct/pid")),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
            validity_seconds: None,
        }],
        verifier: VerifierConfig {
            signing_key: "issuer_key".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
            dc_api_expected_origins: Vec::new(),
            dc_api_accept_legacy_web_origin_audience: false,
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
    /// ABCA §8 attestation_challenge -- empty unless produced by
    /// `drive_issuance_with_challenge_and_nonce`.
    attestation_challenge: String,
    /// RFC 9449 §8/§9 DPoP nonce -- empty unless produced by
    /// `drive_issuance_with_challenge_and_nonce`.
    dpop_nonce: String,
    /// The `DPoP-Nonce` now riding the ABCA §8 challenge response -- empty
    /// unless produced by `drive_issuance_with_challenge_and_nonce`.
    challenge_endpoint_dpop_nonce: String,
    /// The `DPoP-Nonce` now riding the OpenID4VCI §7 Nonce Endpoint response --
    /// empty unless produced by `drive_issuance_with_challenge_and_nonce`.
    nonce_endpoint_dpop_nonce: String,
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
    let pre_auth_code =
        offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
            ["pre-authorized_code"]
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
        attestation_challenge: String::new(),
        dpop_nonce: String::new(),
        challenge_endpoint_dpop_nonce: String::new(),
        nonce_endpoint_dpop_nonce: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Task 9 of the ABCA challenge-retrieval / DPoP-nonce plan
// (docs/superpowers/plans/2026-08-04-abca-challenge-and-dpop-nonce-plan.md):
// the ABCA attestation_challenge and the RFC 9449 DPoP nonce are exactly the
// values an attacker needs to complete an otherwise-unforgeable PoP or DPoP
// proof -- root AGENTS.md sect-4.5 makes this a *behavioural* requirement, so
// it is asserted here, not only reviewed.
// ---------------------------------------------------------------------------

/// The `sub`/`iss` shared between the Wallet Attestation and its Client
/// Attestation PoP JWTs in this section's tests.
const CHALLENGE_WALLET_SUB: &str = "https://wallet-challenge.example.org";

/// As `setup_with_required_attestation`, but with
/// `wallet_attestation.challenge_mode`, `dpop.mode`, and `dpop.nonce_mode` all
/// `Mode::Required` too -- Task 9 needs a state where both new freshness
/// values actually flow through a request, or the redaction assertions below
/// would be vacuous.
async fn setup_with_challenge_and_dpop_nonce() -> (
    AppState,
    tempfile::TempDir,
    tempfile::TempDir,
    String,
    String,
) {
    let (state, dir, ca_dir, ca_cert_pem, ca_key_pem) = setup_with_required_attestation().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.wallet_attestation.challenge_mode = Mode::Required;
    cfg.issuer.dpop.mode = Mode::Required;
    cfg.issuer.dpop.nonce_mode = Mode::Required;
    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    (state, dir, ca_dir, ca_cert_pem, ca_key_pem)
}

/// Builds a Wallet Attestation JWT (chained to `ca_cert_pem`/`ca_key_pem`) and
/// returns it alongside the EC key pair whose public JWK is embedded in its
/// `cnf.jwk` -- sign a matching Client Attestation PoP JWT against that same
/// key with `sign_pop_with_challenge`. Split from a single combined builder
/// (as `signed_attestation_and_pop_with_planted_jti` above is) because this
/// section's driver needs two *different* PoP JWTs -- one per /token attempt
/// -- bound to the same attestation key: `claim_dpop_jti`'s sibling,
/// `claim_pop_jti`, burns the first attempt's PoP jti even though that attempt
/// only fails on the DPoP nonce check, so a retry needs a fresh PoP jti
/// without a fresh attestation.
fn build_wallet_attestation(ca_cert_pem: &str, ca_key_pem: &str, now: i64) -> (String, EcKeyPair) {
    use base64::Engine as _;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm as SigAlg, Signer};
    use foundry_core::pki::issue_leaf;
    use foundry_core::trust::build_x5c;

    let kp = EcKeyPair::generate(EcCurve::P256).expect("pop keypair");
    let mut cnf_jwk = kp.to_jwk_public_key();
    cnf_jwk.set_algorithm("ES256");

    let leaf = issue_leaf(
        ca_cert_pem,
        ca_key_pem,
        "wallet-provider.example.com",
        &["wallet-provider.example.com".to_string()],
        365,
    )
    .expect("issue_leaf");
    let x5c = build_x5c(&[leaf.cert_pem.clone().into_bytes()]).expect("x5c");

    let header = serde_json::json!({
        "typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": x5c,
    });
    let payload = serde_json::json!({
        "iss": "https://wallet-provider.example.com",
        "sub": CHALLENGE_WALLET_SUB,
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

    (attestation_jwt, kp)
}

/// Signs a Client Attestation PoP JWT (ABCA §5.2) against `kp` (from
/// `build_wallet_attestation`), optionally carrying a `challenge` claim (ABCA
/// §5.2/§8, Task 4 of the ABCA/DPoP-nonce plan).
fn sign_pop_with_challenge(kp: &EcKeyPair, jti: &str, now: i64, challenge: Option<&str>) -> String {
    use base64::Engine as _;
    use josekit::jws::JwsSigner;

    let pop_signer = ES256
        .signer_from_jwk(&kp.to_jwk_private_key())
        .expect("pop signer");
    let pop_header = serde_json::json!({
        "typ": "oauth-client-attestation-pop+jwt", "alg": "ES256",
    });
    let mut pop_payload = serde_json::json!({
        "iss": CHALLENGE_WALLET_SUB, "aud": ISSUER, "jti": jti, "iat": now,
    });
    if let Some(c) = challenge {
        pop_payload["challenge"] = serde_json::json!(c);
    }
    let pop_header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&pop_header).unwrap());
    let pop_payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&pop_payload).unwrap());
    let pop_signing_input = format!("{pop_header_b64}.{pop_payload_b64}");
    let pop_sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(pop_signer.sign(pop_signing_input.as_bytes()).unwrap());
    format!("{pop_signing_input}.{pop_sig_b64}")
}

/// A DPoP proof JWT (RFC 9449 §4.2), with an optional `nonce` claim (§8/§9)
/// and an optional `ath` claim (§7, for /credential presentations --
/// `access_token` is what gets hashed into it).
fn create_dpop_proof_with_nonce(
    kp: &EcKeyPair,
    method: &str,
    htu: &str,
    jti: &str,
    iat: i64,
    access_token: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("dpop+jwt");
    header.set_jwk(kp.to_jwk_public_key());

    let mut payload = JwtPayload::new();
    payload.set_claim("htm", Some(method.into())).unwrap();
    payload.set_claim("htu", Some(htu.into())).unwrap();
    payload.set_claim("iat", Some(iat.into())).unwrap();
    payload.set_claim("jti", Some(jti.into())).unwrap();
    if let Some(at) = access_token {
        let ath = foundry_issuer::access_token_hash(at);
        payload.set_claim("ath", Some(ath.into())).unwrap();
    }
    if let Some(n) = nonce {
        payload.set_claim("nonce", Some(n.into())).unwrap();
    }

    let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

/// Drives issuance with ABCA challenge retrieval and DPoP nonces **enabled**,
/// so the new secrets actually flow through the request path this test then
/// scans. Running the default (disabled) config here would make the
/// assertions vacuously true.
///
/// Mirrors `drive_issuance`, but: fetches an attestation_challenge from
/// `POST /challenge`; drives `/token` with a Wallet Attestation + PoP (the PoP
/// carrying that challenge) and a DPoP proof, retrying once (fresh PoP jti,
/// fresh DPoP jti, the server-supplied nonce) exactly as RFC 9449 §8
/// prescribes; then completes `/nonce` and `/credential` as `drive_issuance`
/// does, reusing the same DPoP nonce value at `/credential` too --
/// `Domain::DpopNonce` is not endpoint-scoped, so no second failed round trip
/// is needed to prove that.
async fn drive_issuance_with_challenge_and_nonce(
    state: &AppState,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> IssuanceSecrets {
    let admin = admin_router(state.clone(), AdminApiKey(Some(ADMIN_KEY.into())));

    let challenge_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/challenge")
                .body(Body::empty())
                .expect("challenge request"),
        )
        .await
        .expect("challenge response");
    assert_eq!(challenge_res.status(), StatusCode::OK);
    // Read the header before `body_json`, which consumes the response.
    let challenge_endpoint_dpop_nonce = challenge_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("nonce_mode: required must supply a DPoP-Nonce from /challenge")
        .to_string();
    let attestation_challenge = body_json(challenge_res).await["attestation_challenge"]
        .as_str()
        .expect("attestation_challenge")
        .to_string();

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
    let pre_auth_code =
        offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
            ["pre-authorized_code"]
            .as_str()
            .expect("pre-authorized code")
            .to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64;
    let (attestation_jwt, attestation_kp) = build_wallet_attestation(ca_cert_pem, ca_key_pem, now);
    let dpop_kp = EcKeyPair::generate(EcCurve::P256).expect("dpop keypair");
    let token_htu = format!("{ISSUER}/token");

    // First attempt: attestation + challenge verify fully, but the DPoP proof
    // carries no `nonce` claim yet -- expected to fail with use_dpop_nonce.
    let pop_jwt_1 = sign_pop_with_challenge(
        &attestation_kp,
        "jti-pop-nonce-1",
        now,
        Some(&attestation_challenge),
    );
    let dpop_proof_1 =
        create_dpop_proof_with_nonce(&dpop_kp, "POST", &token_htu, "jti-dpop-1", now, None, None);
    let token_res_1 = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("OAuth-Client-Attestation", &attestation_jwt)
                .header("OAuth-Client-Attestation-PoP", &pop_jwt_1)
                .header("DPoP", &dpop_proof_1)
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
                )))
                .expect("token request 1"),
        )
        .await
        .expect("token response 1");
    assert_eq!(token_res_1.status(), StatusCode::BAD_REQUEST);
    let dpop_nonce = token_res_1
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("first /token attempt must supply a DPoP-Nonce")
        .to_string();

    // Retry: a fresh Client Attestation PoP jti (claim_pop_jti already burned
    // the first) and a DPoP proof carrying the supplied nonce.
    let pop_jwt_2 = sign_pop_with_challenge(
        &attestation_kp,
        "jti-pop-nonce-2",
        now,
        Some(&attestation_challenge),
    );
    let dpop_proof_2 = create_dpop_proof_with_nonce(
        &dpop_kp,
        "POST",
        &token_htu,
        "jti-dpop-2",
        now,
        None,
        Some(&dpop_nonce),
    );
    let token_res_2 = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("OAuth-Client-Attestation", &attestation_jwt)
                .header("OAuth-Client-Attestation-PoP", &pop_jwt_2)
                .header("DPoP", &dpop_proof_2)
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
                )))
                .expect("token request 2"),
        )
        .await
        .expect("token response 2");
    assert_eq!(token_res_2.status(), StatusCode::OK);
    let token = body_json(token_res_2).await;
    assert_eq!(token["token_type"], "DPoP");
    let access_token = token["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let nonce_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/nonce")
                .body(Body::empty())
                .expect("nonce request"),
        )
        .await
        .expect("nonce response");
    assert_eq!(nonce_res.status(), StatusCode::OK);
    // Read the header before `body_json`, which consumes the response.
    let nonce_endpoint_dpop_nonce = nonce_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("nonce_mode: required must supply a DPoP-Nonce from /nonce")
        .to_string();
    let c_nonce = body_json(nonce_res).await["c_nonce"]
        .as_str()
        .expect("c_nonce")
        .to_string();

    let cred_htu = format!("{ISSUER}/credential");
    let cred_proof = create_dpop_proof_with_nonce(
        &dpop_kp,
        "POST",
        &cred_htu,
        "jti-dpop-cred-1",
        now,
        Some(&access_token),
        Some(&dpop_nonce),
    );
    let cred_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
                .header("DPoP", &cred_proof)
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
        attestation_challenge,
        dpop_nonce,
        challenge_endpoint_dpop_nonce,
        nonce_endpoint_dpop_nonce,
    }
}

/// Every freshness value in this flow is a secret: leaking one hands an attacker
/// what it needs to complete a forged PoP or DPoP proof. Root `AGENTS.md` §4.5.
///
/// Four of them now, not two: since 2026-08-04 the two unauthenticated freshness
/// endpoints supply a `DPoP-Nonce` of their own (`/challenge` and `/nonce`, per
/// the Google Wallet profile), and those are secrets for exactly the same reason
/// as the one `/token` supplies.
#[tokio::test]
async fn issuance_never_logs_challenges_or_dpop_nonces() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir, _ca_dir, ca_cert_pem, ca_key_pem) =
        setup_with_challenge_and_dpop_nonce().await;
    let (guard, log) = capture_at_trace();
    let secrets = drive_issuance_with_challenge_and_nonce(&state, &ca_cert_pem, &ca_key_pem).await;
    drop(guard);

    assert!(
        !log.events().is_empty(),
        "captured nothing; the negative assertions below would be vacuous"
    );

    for (label, secret) in [
        ("attestation_challenge", &secrets.attestation_challenge),
        ("dpop_nonce", &secrets.dpop_nonce),
        (
            "challenge_endpoint_dpop_nonce",
            &secrets.challenge_endpoint_dpop_nonce,
        ),
        (
            "nonce_endpoint_dpop_nonce",
            &secrets.nonce_endpoint_dpop_nonce,
        ),
    ] {
        assert!(
            !secret.is_empty(),
            "{label} was empty, so its assertion would be vacuous"
        );
        assert!(!log.contains_value(secret), "{label} leaked into the log");
    }
}

/// Positive control: proves the capture harness would have caught a leak. If
/// this fails, the assertions above are meaningless.
#[tokio::test]
async fn the_capture_harness_would_catch_a_leaked_challenge() {
    let _flag = lock_flag().await;
    let (guard, log) = capture_at_trace();
    let planted = "planted-challenge-value-must-be-visible";
    tracing::trace!(planted = planted, "deliberate leak");
    drop(guard);
    assert!(log.contains_value(planted));
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

/// As `setup()`, but with `key_attestation.android` enabled at `Mode::Optional`
/// against a freshly generated CA, whose material is returned so a test can
/// build a `support::synthetic_android_chain` around it.
async fn setup_with_android_keystore_attestation()
-> (AppState, tempfile::TempDir, foundry_core::pki::CertMaterial) {
    use foundry_core::config::{AndroidKeystoreConfig, TrustAnchor};
    use foundry_core::trust::android_attestation::SecurityLevel;

    let (state, dir) = setup().await;
    let ca = foundry_core::pki::new_ca("Redaction Test Android Root", 3650).expect("ca");
    let anchor_path = dir.path().join("android-root.pem");
    std::fs::write(&anchor_path, &ca.cert_pem).expect("write anchor");

    let mut cfg = (*state.config).clone();
    cfg.issuer.key_attestation.trusted_anchors = vec![TrustAnchor {
        name: "android-redaction-root".to_string(),
        certs: anchor_path.to_str().expect("utf-8 path").to_string(),
    }];
    cfg.issuer.key_attestation.android = AndroidKeystoreConfig {
        mode: Mode::Optional,
        key_mint_security_level: SecurityLevel::TrustedEnvironment,
    };
    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    (state, dir, ca)
}

/// An `android_keystore_attestation` issuance must never log the
/// `attestationChallenge` (it is a `c_nonce`) or the `uniqueId` (a
/// privacy-sensitive hardware device identifier) -- root AGENTS.md sect-4.5.
///
/// The positive control for this harness already exists in this binary
/// (`the_capture_harness_would_catch_a_leaked_challenge`), so the absence
/// assertions below are trustworthy.
#[tokio::test]
async fn android_keystore_issuance_never_logs_the_challenge_or_unique_id() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir, ca) = setup_with_android_keystore_attestation().await;

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
    let pre_auth_code =
        offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
            ["pre-authorized_code"]
            .as_str()
            .expect("pre-authorized code")
            .to_string();

    let token_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
                )))
                .expect("token request"),
        )
        .await
        .expect("token response");
    assert_eq!(token_res.status(), StatusCode::OK);
    let access_token = body_json(token_res).await["access_token"]
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

    let chain = support::synthetic_android_chain(&ca, c_nonce.as_bytes());

    let (guard, log) = capture_at_trace();
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
                        "proofs": { "android_keystore_attestation": [chain] },
                    })
                    .to_string(),
                ))
                .expect("credential request"),
        )
        .await
        .expect("credential response");
    drop(guard);

    // The issuance must succeed first -- a rejected request would make the
    // absence assertions below vacuous.
    assert_eq!(cred_res.status(), StatusCode::OK);
    assert!(!log.events().is_empty(), "captured nothing");

    assert!(
        !log.contains_value(&c_nonce),
        "the c_nonce used as attestationChallenge must never appear in logs"
    );
    assert!(
        !log.contains_value("unique_id") && !log.contains_value("uniqueId"),
        "uniqueId must never be logged, not even as a field name"
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

/// Create a verification request over `transport` and, on the `request_uri`
/// transport, fetch the signed Request Object the wallet would actually
/// receive from `GET /vp/request/:id`.
///
/// Returns the admin-API response body together with the served compact JWS.
/// The JWS is `None` for the DC API transport, which has no signed form -- its
/// request object is carried in the admin response body instead.
async fn drive_request_object(
    state: &AppState,
    transport: &str,
) -> (serde_json::Value, Option<String>) {
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
                        "transport": transport,
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

    if transport != "request_uri" {
        return (created, None);
    }

    let id = created["verification_id"]
        .as_str()
        .expect("verification_id")
        .to_string();
    let res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/vp/request/{id}"))
                .body(Body::empty())
                .expect("request object request"),
        )
        .await
        .expect("request object response");
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("request object body");
    let jws = String::from_utf8(bytes.to_vec()).expect("request object is UTF-8");

    (created, Some(jws))
}

/// The `nonce` inside a compact Request Object JWS.
///
/// Asserted on rather than the whole JWS alone: a leak that logged only the
/// *decoded* payload would not contain the compact string as a substring, so
/// checking the JWS by itself would miss exactly the shape this feature adds.
fn request_object_nonce(jws: &str) -> String {
    let payload_b64 = jws.split('.').nth(1).expect("jws has a payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload is base64url");
    let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("payload is JSON");
    payload["nonce"]
        .as_str()
        .expect("request object carries a nonce")
        .to_string()
}

/// The Request Object served to the wallet is a payload: it commits to the
/// transaction nonce and carries the ephemeral public JWK. Without the dev-only
/// flag it must not appear, at any level -- the capture here runs at `TRACE`.
#[tokio::test]
async fn the_request_object_served_to_the_wallet_stays_locked_by_default() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir) = setup().await;
    let (guard, log) = capture_at_trace();
    let (_created, jws) = drive_request_object(&state, "request_uri").await;
    drop(guard);

    let jws = jws.expect("request_uri transport serves a signed Request Object");
    assert!(!log.events().is_empty(), "captured nothing");

    assert!(
        !log.contains_value(&jws),
        "the signed Request Object leaked with payload logging disabled"
    );
    assert!(
        !log.contains_value(&request_object_nonce(&jws)),
        "the Request Object nonce leaked with payload logging disabled"
    );
}

/// The positive control for the signed Request Object. Without it the negative
/// test above could pass simply because nothing is ever emitted.
#[tokio::test]
async fn payload_logging_unlocks_the_request_object_served_to_the_wallet() {
    let _flag = lock_flag().await;

    let (state, _dir) = setup().await;
    foundry_core::obs::set_sensitive(true);
    let (guard, log) = capture_at_trace();
    let (_created, jws) = drive_request_object(&state, "request_uri").await;
    drop(guard);
    // Restore immediately: this flag is process-global.
    foundry_core::obs::set_sensitive(false);

    let jws = jws.expect("request_uri transport serves a signed Request Object");
    assert!(
        log.contains_value(&jws),
        "with sensitive_payloads enabled the served Request Object should be logged \
         at trace; if it is not, the diagnostic is inert and the negative test above \
         is meaningless"
    );
}

/// The DC API transport has no signed form, so its request object is the JSON
/// handed to the invoking page. It is the same tier of payload and gets the
/// same default.
#[tokio::test]
async fn the_dc_api_request_object_stays_locked_by_default() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir) = setup().await;
    let (guard, log) = capture_at_trace();
    let (created, _) = drive_request_object(&state, "dc_api").await;
    drop(guard);

    let nonce = created["dc_api_request"]["nonce"]
        .as_str()
        .expect("dc_api_request carries a nonce");
    assert!(!log.events().is_empty(), "captured nothing");
    assert!(
        !log.contains_value(nonce),
        "the DC API request object leaked with payload logging disabled"
    );
}

/// The positive control for the DC API transport.
#[tokio::test]
async fn payload_logging_unlocks_the_dc_api_request_object() {
    let _flag = lock_flag().await;

    let (state, _dir) = setup().await;
    foundry_core::obs::set_sensitive(true);
    let (guard, log) = capture_at_trace();
    let (created, _) = drive_request_object(&state, "dc_api").await;
    drop(guard);
    foundry_core::obs::set_sensitive(false);

    let nonce = created["dc_api_request"]["nonce"]
        .as_str()
        .expect("dc_api_request carries a nonce");
    assert!(
        log.contains_value(nonce),
        "with sensitive_payloads enabled the DC API request object should be logged \
         at trace; if it is not, the diagnostic is inert"
    );
}

/// Unlocking the Request Object widens what may be logged; it does not remove
/// the floor. The transaction's ephemeral **private** key stays out, and the
/// dump is deliberately of the public half only.
#[tokio::test]
async fn unlocking_the_request_object_does_not_unlock_the_ephemeral_private_key() {
    let _flag = lock_flag().await;

    let (state, _dir) = setup().await;
    foundry_core::obs::set_sensitive(true);
    let (guard, log) = capture_at_trace();
    let _ = drive_request_object(&state, "request_uri").await;
    drop(guard);
    foundry_core::obs::set_sensitive(false);

    assert!(
        !log.contains_value("ephem_private_jwk"),
        "the ephemeral private key field name appears in the log"
    );
    assert!(
        !log.contains_value("\"d\":"),
        "a private JWK component appears in the log while serving a Request Object"
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
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
            encrypted_pre_authorized_code: Default::default(),
            access_token_ttl_secs: 600,
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some(format!("{ISSUER}/vct/pid")),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
            validity_seconds: None,
        }],
        verifier: VerifierConfig {
            signing_key: "issuer_key".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
            dc_api_expected_origins: Vec::new(),
            dc_api_accept_legacy_web_origin_audience: false,
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

// ---------------------------------------------------------------------------
// OpenID4VCI Credential Request/Response encryption: the decrypted request
// body and the wallet's ephemeral response-encryption key are new secrets
// introduced by this change. Root AGENTS.md sect-4.5 makes their redaction a
// *behavioural* requirement, so it is asserted here, not only reviewed.
// ---------------------------------------------------------------------------

/// `setup()` plus both encryption blocks and one generated decryption key.
async fn setup_with_encryption() -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
        keys: vec!["issuer_request_enc".to_string()],
        enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
        encryption_required: false,
    });
    cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
        enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
        encryption_required: false,
    });
    let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).expect("enc key");
    let key = foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes())
        .expect("decryption key");
    let state =
        AppState::new(state.storage.clone(), Arc::new(cfg)).with_request_decryption_keys(vec![key]);
    (state, dir)
}

/// Drive an encrypted issuance and return the uniquely identifiable secrets that
/// must not appear in the log: the wallet's ephemeral encryption JWK `x`
/// coordinate, and the issued credential string.
///
/// Mirrors `crates/foundry/tests/credential_encryption.rs`'s
/// `an_encrypted_request_yields_an_encrypted_response` -- same key generation,
/// same metadata read, same decrypt -- but returns the two values instead of
/// asserting on them.
async fn drive_encrypted_issuance(state: &AppState) -> (String, String) {
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
    let pre_auth_code =
        offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
            ["pre-authorized_code"]
            .as_str()
            .expect("pre-authorized code")
            .to_string();

    let token_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
                )))
                .expect("token request"),
        )
        .await
        .expect("token response");
    assert_eq!(token_res.status(), StatusCode::OK);
    let access_token = body_json(token_res).await["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let nonce_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/nonce")
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
    let proof_jwt = create_proof(&c_nonce);

    let meta_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .expect("metadata request"),
        )
        .await
        .expect("metadata response");
    assert_eq!(meta_res.status(), StatusCode::OK);
    let meta = body_json(meta_res).await;
    let issuer_jwk = meta["credential_request_encryption"]["jwks"]["keys"][0].clone();
    let issuer_kid = issuer_jwk["kid"].as_str().expect("kid").to_string();

    let kp = EcKeyPair::generate(EcCurve::P256).expect("wallet enc keypair");
    let mut wallet_public = serde_json::to_value(kp.to_jwk_public_key()).expect("public jwk");
    if let Some(o) = wallet_public.as_object_mut() {
        o.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    }
    let wallet_jwk_x = wallet_public["x"]
        .as_str()
        .expect("x coordinate")
        .to_string();
    let wallet_private = serde_json::to_value(kp.to_jwk_private_key()).expect("private jwk");

    let body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
        "credential_response_encryption": { "jwk": wallet_public, "enc": "A128GCM" },
    });
    let jwe = foundry_core::crypto::jwe::encrypt_compact_with_kid(
        &body,
        &issuer_jwk,
        "ECDH-ES",
        "A256GCM",
        Some(&issuer_kid),
    )
    .expect("encrypt request");

    let cred_res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/jwt")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(jwe))
                .expect("credential request"),
        )
        .await
        .expect("credential response");
    assert_eq!(cred_res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(cred_res.into_body(), usize::MAX)
        .await
        .expect("body");
    let compact = String::from_utf8(bytes.to_vec()).expect("utf8");
    let jwk = josekit::jwk::Jwk::from_bytes(
        serde_json::to_string(&wallet_private)
            .expect("jwk json")
            .as_bytes(),
    )
    .expect("jwk");
    let decrypter = josekit::jwe::ECDH_ES
        .decrypter_from_jwk(&jwk)
        .expect("decrypter");
    let (payload, _jwe_header) =
        josekit::jwt::decode_with_decrypter(&compact, &decrypter).expect("decrypt");
    let decrypted = serde_json::to_value(payload.claims_set()).expect("claims");
    let credential = decrypted["credentials"][0]["credential"]
        .as_str()
        .expect("credential")
        .to_string();

    (wallet_jwk_x, credential)
}

#[tokio::test]
async fn encrypted_issuance_never_logs_the_decrypted_request_or_the_wallet_jwk() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir) = setup_with_encryption().await;
    let (guard, log) = capture_at_trace();
    let (wallet_jwk_x, credential) = drive_encrypted_issuance(&state).await;
    drop(guard);

    assert!(
        !log.events().is_empty(),
        "captured nothing; the negative assertions below would be vacuous"
    );

    for (label, secret) in [
        ("wallet jwk x coordinate", &wallet_jwk_x),
        ("issued credential", &credential),
    ] {
        assert!(
            !secret.is_empty(),
            "{label} was empty, so its assertion would be vacuous"
        );
        assert!(!log.contains_value(secret), "{label} leaked into the log");
    }
}

#[tokio::test]
async fn encrypted_issuance_leaks_nothing_even_with_sensitive_payloads_enabled() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(true);

    let (state, _dir) = setup_with_encryption().await;
    let (guard, log) = capture_at_trace();
    let (wallet_jwk_x, _credential) = drive_encrypted_issuance(&state).await;
    drop(guard);
    foundry_core::obs::set_sensitive(false);

    assert!(!log.events().is_empty(), "captured nothing");
    assert!(
        !wallet_jwk_x.is_empty(),
        "wallet jwk x coordinate was empty, so its assertion would be vacuous"
    );
    assert!(
        !log.contains_value(&wallet_jwk_x),
        "key material is never unlocked by the sensitive-payloads flag"
    );
}

/// EMVCo DPC display metadata carries `card.last_four`, a cardholder-recognisable
/// alias and possibly personalised art URLs. Root AGENTS.md §4.5 puts all of it
/// on the never-logged list; `create_offer` records presence only.
///
/// Captured at TRACE so the assertion covers every level -- a leak that only
/// appears at `debug` is still a leak.
#[tokio::test]
async fn display_metadata_never_reaches_the_log() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (base, _dir) = setup().await;

    // `setup()` configures only `pid`, and the DPC_VCT gate rejects display
    // metadata for anything else. Extend the config rather than duplicating the
    // whole harness.
    let mut cfg = (*base.config).clone();
    cfg.credential_types.push(CredentialType {
        id: "com.emvco.dpc.card".to_string(),
        format: "dc+sd-jwt".to_string(),
        vct: Some("com.emvco.dpc.card".to_string()),
        doctype: None,
        scope: None,
        cryptographic_holder_binding: true,
        display: vec![],
        claims: vec![
            ClaimDef {
                path: vec!["credential_id".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
            ClaimDef {
                path: vec!["network".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
        ],
        validity_seconds: None,
    });
    let state = AppState::new(base.storage.clone(), Arc::new(cfg));

    // Distinctive values, so a match cannot be coincidental.
    const LAST_FOUR: &str = "9137";
    const ALIAS: &str = "Unmistakable Alias 8f3a2c";
    const ART_URL_MARKER: &str = "personalised-7d41e9";

    let request = serde_json::json!({
        "credential_type_id": "com.emvco.dpc.card",
        "claims": { "credential_id": "cred-1", "network": "example_network" },
        "tx_code_required": false,
        "offer_display": [{
            "locale": "en-US",
            "card": { "type": { "code": "CREDIT" } }
        }],
        "credential_response_display": [{
            "locale": "en-US",
            "card": {
                "last_four": LAST_FOUR,
                "alias": ALIAS,
                "card_art": [
                    { "theme": "DEFAULT", "image_url": "https://bank.example/personalised-7d41e9.png" }
                ]
            }
        }]
    });

    let (guard, log) = capture_at_trace();
    let res = admin_router(state.clone(), AdminApiKey(Some(ADMIN_KEY.into())))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
                .body(Body::from(request.to_string()))
                .expect("create offer request"),
        )
        .await
        .expect("create offer response");
    let status = res.status();
    let created = body_json(res).await;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::OK,
        "the offer must be created, else the assertions below are vacuous: {created}"
    );
    assert!(
        !log.events().is_empty(),
        "captured nothing; the negative assertions below would be vacuous"
    );

    for (label, secret) in [
        ("last_four", LAST_FOUR),
        ("cardholder alias", ALIAS),
        ("personalised card-art URL", ART_URL_MARKER),
    ] {
        assert!(
            !log.contains_value(secret),
            "{label} leaked into the log: {secret:?} found"
        );
    }

    // The positive control: prove the capture window actually covered this
    // request, so the negative assertions above are not vacuously true of an
    // irrelevant buffer.
    //
    // This deliberately does NOT assert on `offer_display_present` /
    // `credential_response_display_present`. Those are span fields, and
    // `create_offer` emits no tracing event of its own -- so nothing is ever
    // recorded *inside* its span and its fields reach no log record. That is
    // pre-existing and equally true of `credential_type_id`,
    // `tx_code_required` and `authorization_code_grant`, which have been on
    // that span all along. The fields are still correct per AGENTS.md §4.5
    // (presence only, never contents); they are simply unobservable until some
    // event is emitted within the span. Asserting otherwise would encode a
    // property this code does not have.
    let saw_this_request = log.events().iter().any(|e| {
        e.fields
            .get("route")
            .is_some_and(|r| r.contains("/admin/issuance/offers"))
            && e.fields.get("http.status").map(String::as_str) == Some("200")
    });
    assert!(
        saw_this_request,
        "the capture window must cover the create-offer request, else the \
         negative assertions above prove nothing; captured fields: {:?}",
        log.events()
            .iter()
            .map(|e| e.fields.clone())
            .collect::<Vec<_>>()
    );
}

/// Root `AGENTS.md` §4.5: the `encrypted_pre-authorized_code` envelope — and
/// therefore the pre-authorized code sealed inside it — must never reach a
/// log, at any level, under any flag.
///
/// Driven against the default configuration, where the extension is
/// `disabled`, so the request takes the rejection path: `resolve_code` refuses
/// the member and `token_error_response` writes the one log record §4.5
/// requires. That record must name the failure without quoting the artifact.
///
/// The envelope value is deliberately unlike anything a log line could contain
/// by coincidence, so a substring search over the whole captured buffer is
/// conclusive.
#[tokio::test]
async fn the_encrypted_pre_authorized_code_envelope_is_never_logged() {
    let _flag = lock_flag().await;
    foundry_core::obs::set_sensitive(false);

    let (state, _dir) = setup().await;

    const ENVELOPE: &str = "Qqxlm-Planted-Envelope-Value-7731";

    let (guard, log) = capture_at_trace();
    let res = wallet_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code\
                     &encrypted_pre-authorized_code={ENVELOPE}"
                )))
                .expect("token request"),
        )
        .await
        .expect("token response");
    drop(guard);

    // The disabled mode rejects the member rather than ignoring it; a 200 here
    // would mean the anti-downgrade rule silently fell back to the plaintext
    // path and this test proved nothing about the rejection log record.
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    assert!(
        !log.events().is_empty(),
        "captured nothing; the negative assertion below would be vacuous"
    );
    assert!(
        !log.contains_value(ENVELOPE),
        "the encrypted_pre-authorized_code envelope leaked into the log"
    );

    // The positive control: the capture window really covered this request.
    let saw_this_request = log
        .events()
        .iter()
        .any(|e| e.fields.get("route").is_some_and(|r| r.contains("/token")));
    assert!(
        saw_this_request,
        "the capture window must cover the /token request, else the negative \
         assertion above proves nothing"
    );
}
