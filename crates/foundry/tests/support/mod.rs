//! Shared setup for the credential-encryption and Android keystore-attestation
//! test binaries.
//!
//! Copied (not imported) from `conformance_http.rs`'s `setup_test_app` and its
//! helpers, per this repository's convention that test-fixture helpers are
//! duplicated across test binaries rather than shared through the crate's own
//! public API. Renamed `setup_test_app` -> `setup_without_encryption` to make
//! the pairing with `setup_with_encryption` below explicit.
//!
//! `mod support;` compiles this file separately into each test binary that
//! declares it, so no single binary calls every helper here -- e.g.
//! `credential_encryption.rs` never calls `synthetic_android_chain`, and
//! `keystore_attestation_proof.rs` never calls `setup_with_encryption`. The
//! module-wide allow below reflects that shared-fixture shape, not a real dead
//! path in any one binary.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{AppState, admin_router, wallet_router};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
    LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
    WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use josekit::jwk::KeyPair as _;
use josekit::jwk::alg::ec::EcKeyPair;
use josekit::jws::{ES256, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

pub async fn setup_without_encryption() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let key_path = dir.path().join("issuer.pem");
    let km = foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
        .unwrap();
    std::fs::write(&key_path, km.private_pem).unwrap();
    let mut keys = BTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        foundry_core::config::KeyEntry {
            private_key: key_path.to_str().unwrap().to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://issuer.example.com".to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: true,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: Some("test-admin-key".to_string()),
                api_key_env: None,
                swagger_ui_enabled: true,
                console_enabled: true,
            },
        },
        storage: StorageConfig {
            path: db_path.to_str().unwrap().to_string(),
            transaction_ttl_secs: 600,
        },
        keys,
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_signing_key: None,
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
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
            encrypted_pre_authorized_code: Default::default(),
            access_token_ttl_secs: 600,
            offer_by_reference: false,
            paso_metadata: Default::default(),
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://issuer.example.com/vct/pid".to_string()),
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
            transaction_data_types: None,
        }],
        verifier: VerifierConfig {
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
            dc_api_expected_origins: Vec::new(),
            dc_api_accept_legacy_web_origin_audience: false,
        },
        logging: LoggingConfig::default(),
    };

    let state = AppState::new(Arc::new(storage), Arc::new(config));

    (state, dir)
}

/// A `POST /admin/issuance/offers` (pre-authorized_code grant) followed by a
/// `POST /token` exchange, exactly as `conformance_http.rs`'s copy does.
pub async fn issue_pre_auth_offer_and_get_access_token(state: &AppState) -> String {
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let offer_req_body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": { "given_name": "Alice" },
        "tx_code_required": false,
    });
    let offer_req = Request::builder()
        .method("POST")
        .uri("/admin/issuance/offers")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(offer_req_body.to_string()))
        .unwrap();
    let offer_res = admin_app.oneshot(offer_req).await.unwrap();
    assert_eq!(offer_res.status(), StatusCode::OK);
    let offer_bytes = axum::body::to_bytes(offer_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let offer_json: serde_json::Value = serde_json::from_slice(&offer_bytes).unwrap();
    let pre_auth_code = offer_json["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .unwrap();

    let wallet_app = wallet_router(state.clone());
    let token_form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
    );
    let token_req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(token_form_body))
        .unwrap();
    let token_res = wallet_app.oneshot(token_req).await.unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_bytes = axum::body::to_bytes(token_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_bytes).unwrap();
    token_json["access_token"].as_str().unwrap().to_string()
}

/// Mint a real MAC-authenticated `c_nonce` exactly as `POST /nonce` would.
pub async fn mint_c_nonce(state: &AppState) -> String {
    let wallet_app = wallet_router(state.clone());
    let nonce_req = Request::builder()
        .method("POST")
        .uri("/nonce")
        .body(Body::empty())
        .unwrap();
    let nonce_res = wallet_app.oneshot(nonce_req).await.unwrap();
    assert_eq!(nonce_res.status(), StatusCode::OK);
    let nonce_bytes = axum::body::to_bytes(nonce_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let nonce_json: serde_json::Value = serde_json::from_slice(&nonce_bytes).unwrap();
    nonce_json["c_nonce"].as_str().unwrap().to_string()
}

/// A proof-of-possession JWT with a bare `jwk` header, exactly as
/// `conformance_http.rs`'s `create_proof` builds one.
pub fn create_proof(c_nonce: &str, issuer: &str) -> String {
    let keypair = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
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

pub async fn body_json(res: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// A synthetic Android-shaped attestation chain: a leaf carrying the Android
/// key attestation extension with `challenge` as its `attestationChallenge`,
/// signed by `ca`, returned as `[leaf, root]` in base64-STANDARD DER.
///
/// Runtime-generated rather than a fixture: the real Google chain's challenge is
/// Google's `c_nonce`, which can never verify against foundry's MAC secret, and
/// a static chain cannot carry an unexpired one. The DER builder is deliberately
/// duplicated from `crates/foundry-issuer/src/keystore_proof.rs`'s tests -- see
/// the design doc's Testing section.
pub fn synthetic_android_chain(
    ca: &foundry_core::pki::CertMaterial,
    challenge: &[u8],
) -> Vec<String> {
    use rcgen::{
        CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(content);
        out
    }
    fn integer(v: i64) -> Vec<u8> {
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
            bytes.remove(0);
        }
        tlv(&[0x02], &bytes)
    }
    fn enumerated(v: u8) -> Vec<u8> {
        tlv(&[0x0a], &[v])
    }
    fn octet_string(bytes: &[u8]) -> Vec<u8> {
        tlv(&[0x04], bytes)
    }
    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &parts.concat())
    }

    // Attestation version 3, TrustedEnvironment for both security levels.
    let key_description = sequence(&[
        integer(3),
        enumerated(1),
        integer(41),
        enumerated(1),
        octet_string(challenge),
        octet_string(&[]),
        sequence(&[]),
        sequence(&[]),
    ]);

    let ca_key = KeyPair::from_pem(&ca.key_pem).expect("CA key parses");
    let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, ca_key).expect("issuer");

    // rcgen's default KeyPair is ECDSA P-256, which is what the attested key
    // must be.
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::default();
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, "Android Keystore Key");
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description,
        ));
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");

    // The root is included, exactly as Google transmits it: `validate_chain`
    // discards self-signed presented certificates, so it grants nothing.
    foundry_core::trust::build_x5c(&[leaf.pem().into_bytes(), ca.cert_pem.clone().into_bytes()])
        .expect("base64 DER chain")
}

/// As `setup_without_encryption`, plus `android_keystore_attestation` enabled at
/// `optional` with `anchor_cert_pem` as the only configured trust anchor.
pub async fn setup_with_android_keystore(anchor_cert_pem: &str) -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_without_encryption().await;
    let anchor_path = dir.path().join("android-root.pem");
    std::fs::write(&anchor_path, anchor_cert_pem).expect("write anchor");

    let mut cfg = (*state.config).clone();
    cfg.issuer.key_attestation.trusted_anchors = vec![foundry_core::config::TrustAnchor {
        name: "android-test-root".to_string(),
        certs: anchor_path.to_str().expect("utf-8 path").to_string(),
    }];
    cfg.issuer.key_attestation.android = foundry_core::config::AndroidKeystoreConfig {
        mode: Mode::Optional,
        key_mint_security_level:
            foundry_core::trust::android_attestation::SecurityLevel::TrustedEnvironment,
    };
    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    (state, dir)
}

/// The non-PaSO credential type `paso_test_env` leaves in place, so the
/// "configured but not a PaSO type" 404 path is testable.
pub const NON_PASO_TYPE_ID: &str = "pid";

/// A booted environment for the PaSO credential metadata tests.
///
/// Holds the `TempDir` so the generated signing key and certificate chain
/// outlive every request made through it.
pub struct PasoTestEnv {
    pub state: AppState,
    _dir: tempfile::TempDir,
}

impl PasoTestEnv {
    /// The `issuer.credential_issuer` value, which PaSO Proof Metadata §8 binds
    /// the `credential_metadata_uri` claim to.
    pub fn credential_issuer(&self) -> &str {
        &self.state.config.issuer.credential_issuer
    }

    /// An unauthenticated wallet-facing GET, optionally carrying an `Accept`
    /// header. `None` exercises §2's "absent Accept defaults to
    /// application/json".
    pub async fn wallet_get_with_accept(
        &self,
        path: &str,
        accept: Option<&str>,
    ) -> axum::http::Response<Body> {
        let app = wallet_router(self.state.clone());
        let mut builder = Request::builder().method("GET").uri(path);
        if let Some(a) = accept {
            builder = builder.header(header::ACCEPT, a);
        }
        let req = builder.body(Body::empty()).expect("build request");
        app.oneshot(req).await.expect("wallet response")
    }

    /// An admin POST carrying the API key.
    pub async fn admin_post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> axum::http::Response<Body> {
        self.admin_post_inner(path, body, true).await
    }

    /// An admin POST with no `Authorization` header, to prove the route is
    /// behind the API-key middleware.
    pub async fn admin_post_without_key(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> axum::http::Response<Body> {
        self.admin_post_inner(path, body, false).await
    }

    async fn admin_post_inner(
        &self,
        path: &str,
        body: serde_json::Value,
        with_key: bool,
    ) -> axum::http::Response<Body> {
        let app = admin_router(
            self.state.clone(),
            AdminApiKey(Some("test-admin-key".to_string())),
        );
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if with_key {
            builder = builder.header(header::AUTHORIZATION, "Bearer test-admin-key");
        }
        let req = builder
            .body(Body::from(body.to_string()))
            .expect("build request");
        app.oneshot(req).await.expect("admin response")
    }
}

/// As `setup_without_encryption`, plus a PaSO credential type
/// (`BankPaymentCard`) and a credential signing key with a **real `x5c` chain
/// on disk** — `Config::validate()` refuses to boot a PaSO deployment without
/// one (PaSO Proof Metadata §4 puts the chain in the JWT header).
///
/// The `pid` type from `setup_without_encryption` is left in place as
/// [`NON_PASO_TYPE_ID`], so a configured-but-not-PaSO id can be shown to 404
/// exactly like an unknown one.
pub async fn paso_test_env() -> PasoTestEnv {
    let (state, dir) = setup_without_encryption().await;
    let mut cfg = (*state.config).clone();

    // A real chain, not a fixture: the leaf's public key must actually verify
    // the JWTs this environment mints, which is what the §7 wallet-side
    // verification test checks.
    let ca = foundry_core::pki::new_ca("Foundry Test Issuer Root", 3650).expect("ca");
    let leaf = foundry_core::pki::issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "issuer.example.com",
        &["issuer.example.com".to_string()],
        365,
    )
    .expect("leaf");

    let key_path = dir.path().join("paso-issuer.pem");
    let chain_path = dir.path().join("paso-issuer-chain.pem");
    std::fs::write(&key_path, leaf.key_pem.as_bytes()).expect("write key");
    std::fs::write(&chain_path, leaf.cert_pem.as_bytes()).expect("write chain");

    cfg.keys.insert(
        "paso_issuer_key".to_string(),
        foundry_core::config::KeyEntry {
            private_key: key_path.to_str().expect("utf-8 path").to_string(),
            x5c: Some(chain_path.to_str().expect("utf-8 path").to_string()),
            alg: "ES256".to_string(),
        },
    );
    // `credential_signing_key()` resolves `issuer.status_list.signing_key`
    // first, so naming it here is what makes the x5c-bearing key sign the
    // metadata JWTs.
    cfg.issuer.status_list.signing_key = Some("paso_issuer_key".to_string());

    // `setup_without_encryption` names `verifier.signing_key` without defining
    // it -- harmless there because that fixture never calls `validate()`. This
    // one does (deliberately: booting is the point), so the key must exist.
    cfg.keys.insert(
        cfg.verifier.signing_key.clone(),
        foundry_core::config::KeyEntry {
            private_key: key_path.to_str().expect("utf-8 path").to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );

    let transaction_data_types = serde_json::from_value(serde_json::json!({
        "urn:paso:sca:global:payment:1": {
            "claims": [
                { "path": ["transaction_id"], "mandatory": true },
                {
                    "path": ["amount"],
                    "mandatory": true,
                    "value_type": "iso_currency_amount",
                    "display": [
                        { "locale": "en", "name": "Amount" },
                        { "locale": "de", "name": "Betrag" }
                    ]
                }
            ],
            "ui_labels": {
                "affirmative_action_label": [
                    { "locale": "en", "value": "Confirm Payment" }
                ]
            }
        }
    }))
    .expect("transaction_data_types fixture");

    cfg.credential_types.push(CredentialType {
        id: "BankPaymentCard".to_string(),
        format: "dc+sd-jwt".to_string(),
        vct: Some("https://bank.example/sca/card".to_string()),
        doctype: None,
        scope: None,
        cryptographic_holder_binding: true,
        display: vec![],
        claims: vec![],
        validity_seconds: None,
        transaction_data_types: Some(transaction_data_types),
    });

    cfg.validate()
        .expect("the PaSO test config must be one foundry would actually boot");

    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    PasoTestEnv { state, _dir: dir }
}

/// As `setup_without_encryption`, plus a generated request-decryption key and
/// both encryption blocks enabled with `encryption_required: false`.
pub async fn setup_with_encryption() -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_without_encryption().await;
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
    let km = foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
        .unwrap();
    let key =
        foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes()).unwrap();
    let state = AppState::new(state.storage.clone(), std::sync::Arc::new(cfg))
        .with_request_decryption_keys(vec![key]);
    (state, dir)
}

/// A `WebhookSink` that hands every delivered event to the test over a
/// channel.
///
/// A channel rather than a shared `Vec`: dispatch is `tokio::spawn`ed, so a
/// test that inspects a `Vec` right after the HTTP call races the spawned
/// task. Awaiting `recv()` blocks until delivery has actually happened.
pub struct RecordingSink {
    tx: tokio::sync::mpsc::UnboundedSender<foundry_verifier::WebhookEvent>,
}

#[async_trait::async_trait]
impl foundry_verifier::WebhookSink for RecordingSink {
    async fn deliver(
        &self,
        event: &foundry_verifier::WebhookEvent,
    ) -> Result<u16, foundry_verifier::WebhookError> {
        let _ = self.tx.send(event.clone());
        Ok(200)
    }
}

pub fn recording_sink() -> (
    std::sync::Arc<RecordingSink>,
    tokio::sync::mpsc::UnboundedReceiver<foundry_verifier::WebhookEvent>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (std::sync::Arc::new(RecordingSink { tx }), rx)
}

/// Await the next delivered event, failing the test rather than hanging.
pub async fn next_event(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<foundry_verifier::WebhookEvent>,
) -> foundry_verifier::WebhookEvent {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for a webhook event")
        .expect("sink channel closed without delivering an event")
}

/// A sink that always fails, for proving §4.3: delivery problems must be
/// invisible to the wallet.
pub struct FailingSink;

#[async_trait::async_trait]
impl foundry_verifier::WebhookSink for FailingSink {
    async fn deliver(
        &self,
        _event: &foundry_verifier::WebhookEvent,
    ) -> Result<u16, foundry_verifier::WebhookError> {
        Err(foundry_verifier::WebhookError::Status(500))
    }
}
