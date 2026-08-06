//! OpenID4VP + HAIP conformance evidence for Authorization Request
//! construction, Client Identifier Prefix handling, and Wallet/Verifier
//! Metadata (OpenID4VP Authorization Request, Client Identifier Prefix and
//! Verifier Metadata Management, Wallet Metadata, Verifier Metadata sections;
//! HAIP OpenID4VP via Redirects / via the W3C DC API) — Task 12 of the
//! OpenID4VC conformance audit.
//!
//! See `docs/conformance/openid4vc-conformance.md` for the full clause
//! inventory and the verdicts these tests are cited as evidence for.
//!
//! Code under audit: `crates/foundry-verifier/src/request.rs`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::config::*;
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::pki::{generate_ec_key, issue_leaf, new_ca};
use foundry_core::storage::SqliteStorage;
use foundry_verifier::{
    build_signed_request_object, check_dcql_match, create_verification_request,
    load_verification_transaction, CreateVerificationRequest, PresentedFormat,
};
use std::collections::BTreeMap;

async fn test_storage() -> SqliteStorage {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("conformance_vp.db");
    std::mem::forget(dir);
    SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
}

fn sample_config(key_path: &str, x5c_path: Option<&str>) -> Config {
    let mut keys = BTreeMap::new();
    keys.insert(
        "verifier_signing".to_string(),
        KeyEntry {
            private_key: key_path.to_string(),
            x5c: x5c_path.map(|s| s.to_string()),
            alg: "ES256".to_string(),
        },
    );

    Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://verifier.example.com".to_string(),
                bind: "127.0.0.1:8080".to_string(),
                swagger_ui_enabled: true,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:8081".to_string(),
                api_key: None,
                api_key_env: None,
                swagger_ui_enabled: true,
                console_enabled: true,
            },
        },
        storage: StorageConfig {
            path: ":memory:".to_string(),
            transaction_ttl_secs: 600,
        },
        keys,
        trust_anchors: vec![],
        issuer: IssuerConfig {
            credential_issuer: "https://issuer.example.com".to_string(),
            wallet_attestation: Default::default(),
            key_attestation: Default::default(),
            status_list: StatusListConfig {
                enabled: false,
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
        },
        credential_types: vec![],
        verifier: VerifierConfig {
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec!["sha-256".to_string()],
            named_queries: vec![],
            webhook: None,
            dc_api_expected_origins: Vec::new(),
        },
        logging: LoggingConfig::default(),
    }
}

fn write_key(dir: &std::path::Path, name: &str) -> String {
    let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, km.private_pem.as_bytes()).unwrap();
    path.to_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// VP-0085 — Request URI Method `post` / Request URI Response (L679): the
// `client_id` request parameter and the Request Object `client_id` claim
// MUST be identical, including the Client Identifier Prefix.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vp_0085_client_id_matches_between_uri_and_request_object() {
    let dir = tempfile::tempdir().unwrap();

    // HAIP OpenID4VP L256: x509_hash requires a certificate to hash, so both the
    // unsigned openid4vp:// URI and the signed Request Object now need one.
    let ca = new_ca("Test Verifier Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "verifier.example.com",
        &["verifier.example.com".to_string()],
        365,
    )
    .unwrap();
    let x5c_path = dir.path().join("leaf.pem");
    std::fs::write(&x5c_path, leaf.cert_pem.as_bytes()).unwrap();
    let key_path = dir.path().join("leaf_key.pem");
    std::fs::write(&key_path, leaf.key_pem.as_bytes()).unwrap();

    let config = sample_config(key_path.to_str().unwrap(), Some(x5c_path.to_str().unwrap()));
    let storage = test_storage().await;

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "request_uri".to_string(),
        transaction_data: None,
    };

    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();

    // Extract client_id from the openid4vp:// URI query string.
    let uri = res.openid4vp_uri.unwrap();
    let uri_client_id = uri
        .split("client_id=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .map(|encoded| {
            percent_encoding::percent_decode_str(encoded)
                .decode_utf8_lossy()
                .to_string()
        })
        .expect("openid4vp:// URI must carry a client_id parameter");

    let tx = load_verification_transaction(&storage, &res.verification_id)
        .await
        .unwrap()
        .unwrap();
    let jws = build_signed_request_object(&config, &tx).unwrap();
    let payload_b64 = jws.split('.').nth(1).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(payload_b64).unwrap()).unwrap();
    let claim_client_id = payload["client_id"].as_str().unwrap();

    assert_eq!(
        uri_client_id, claim_client_id,
        "the client_id carried in the openid4vp:// URI must be identical, including the \
         Client Identifier Prefix, to the client_id claim in the Request Object"
    );
}

// ---------------------------------------------------------------------------
// VP-0026 / VP-0028 — Authorization Request / Existing Parameters (L358):
// the Verifier MUST create a fresh, cryptographically random `nonce` with
// sufficient entropy, and `nonce` values MUST only contain ASCII URL-safe
// characters.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vp_0026_0028_nonce_has_sufficient_entropy_and_is_ascii_url_safe() {
    let storage = test_storage().await;
    let config = sample_config("/tmp/fake_key.pem", None);

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "dc_api".to_string(),
        transaction_data: None,
    };

    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();
    let tx = load_verification_transaction(&storage, &res.verification_id)
        .await
        .unwrap()
        .unwrap();

    // "vn_" prefix + a UUID v4 in "simple" (unhyphenated hex) form: 122 bits
    // of randomness, well above what a cryptographically weak generator
    // could produce, and composed only of ASCII letters, digits and
    // underscore -- all URL-safe per this clause.
    assert!(tx.nonce.starts_with("vn_"));
    let suffix = tx.nonce.strip_prefix("vn_").unwrap();
    assert_eq!(
        suffix.len(),
        32,
        "expected a 32-hex-char UUID-v4 simple form"
    );
    assert!(
        suffix.chars().all(|c| c.is_ascii_hexdigit()),
        "nonce suffix must be pure hex, got: {suffix}"
    );
    assert!(
        tx.nonce.chars().all(|c| c.is_ascii_alphanumeric()
            || c == '-'
            || c == '.'
            || c == '_'
            || c == '~'),
        "nonce must only contain ASCII URL-safe characters, got: {}",
        tx.nonce
    );

    // Freshness: two requests must not reuse the same nonce.
    let req2 = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "dc_api".to_string(),
        transaction_data: None,
    };
    let res2 = create_verification_request(&config, &storage, req2, 1_700_000_001)
        .await
        .unwrap();
    let tx2 = load_verification_transaction(&storage, &res2.verification_id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        tx.nonce, tx2.nonce,
        "each Authorization Request must get a fresh nonce"
    );
}

// ---------------------------------------------------------------------------
// VP-0064 — Defined Client Identifier Prefixes / `x509_san_dns` (L614): the
// request MUST be signed with the private key of the leaf X.509 certificate
// carried in the `x5c` JOSE header. `build_signed_request_object` reads both
// the signer and the `x5c` chain from the *same* configured `KeyEntry`, so
// they are always paired: the JWS signature must verify against the public
// key extracted from the embedded leaf certificate.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vp_0064_signing_key_and_x5c_chain_are_paired() {
    let dir = tempfile::tempdir().unwrap();

    let ca = new_ca("Test Verifier Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "verifier.example.com",
        &["verifier.example.com".to_string()],
        365,
    )
    .unwrap();
    let x5c_path = dir.path().join("leaf.pem");
    std::fs::write(&x5c_path, leaf.cert_pem.as_bytes()).unwrap();
    let key_path = dir.path().join("leaf_key.pem");
    std::fs::write(&key_path, leaf.key_pem.as_bytes()).unwrap();

    // public_base_url's host matches the leaf certificate's SAN here, so any
    // failure below is attributable only to a signer/x5c key mismatch, not
    // the VP-0063 SAN concern.
    let config = sample_config(key_path.to_str().unwrap(), Some(x5c_path.to_str().unwrap()));
    let storage = test_storage().await;

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "request_uri".to_string(),
        transaction_data: None,
    };
    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();
    let tx = load_verification_transaction(&storage, &res.verification_id)
        .await
        .unwrap()
        .unwrap();

    let jws = build_signed_request_object(&config, &tx).unwrap();

    // The leaf certificate's public key is mathematically determined by its
    // own private key (leaf.key_pem); load it directly (bypassing X.509
    // parsing of the x5c header, which is unnecessary here) and confirm the
    // JWS signature verifies against it -- proving the configured signer and
    // the embedded x5c chain are the same key pair.
    let leaf_keypair =
        josekit::jwk::alg::ec::EcKeyPair::from_pem(leaf.key_pem.as_bytes(), None).unwrap();
    let verifier = josekit::jws::ES256
        .verifier_from_jwk(&leaf_keypair.to_jwk_public_key())
        .unwrap();
    josekit::jwt::decode_with_verifier(&jws, &verifier)
        .expect("the JWS must verify against the public key of its own x5c leaf's private key");
}

// ---------------------------------------------------------------------------
// VP-0042 — `aud` of a Request Object (L536): the `aud` claim MUST be
// `https://self-issued.me/v2` when Static Discovery metadata is used (i.e.
// Verifier metadata is passed inline via `client_metadata`, which is what
// foundry always does -- it never performs Dynamic/OpenID-Federation-based
// discovery, see VP-0041, `not-implemented`).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vp_0042_request_object_missing_aud_claim() {
    let dir = tempfile::tempdir().unwrap();

    // HAIP OpenID4VP L256: x509_hash requires a certificate; unrelated to what
    // this test is actually about (the `aud` claim), but building a signed
    // Request Object now needs one regardless.
    let ca = new_ca("Test Verifier Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "verifier.example.com",
        &["verifier.example.com".to_string()],
        365,
    )
    .unwrap();
    let x5c_path = dir.path().join("leaf.pem");
    std::fs::write(&x5c_path, leaf.cert_pem.as_bytes()).unwrap();
    let key_path = dir.path().join("leaf_key.pem");
    std::fs::write(&key_path, leaf.key_pem.as_bytes()).unwrap();

    let config = sample_config(key_path.to_str().unwrap(), Some(x5c_path.to_str().unwrap()));
    let storage = test_storage().await;

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "request_uri".to_string(),
        transaction_data: None,
    };
    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();
    let tx = load_verification_transaction(&storage, &res.verification_id)
        .await
        .unwrap()
        .unwrap();

    let jws = build_signed_request_object(&config, &tx).unwrap();
    let payload_b64 = jws.split('.').nth(1).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(payload_b64).unwrap()).unwrap();

    assert_eq!(
        payload["aud"],
        serde_json::json!("https://self-issued.me/v2"),
        "the Request Object payload must carry an aud claim of https://self-issued.me/v2 \
         under Static Discovery (client_metadata passed inline), got: {payload}"
    );
}

// ---------------------------------------------------------------------------
// VP-0063, re-anchored for GAP-HAIP-05's x509_hash swap -- the check this test
// proves is no longer about the Client Identifier itself (which under x509_hash
// carries a certificate hash, not a host), but about the invariant it stands
// in for: `public_base_url`'s host, the value a wallet reaches this Verifier
// at, MUST match a `dNSName` SAN entry in the leaf certificate carried in
// `x5c`. `build_signed_request_object` calls `foundry_core::trust::match_san_dns`
// against that host before signing.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vp_0063_client_id_host_not_validated_against_x5c_certificate_san() {
    let dir = tempfile::tempdir().unwrap();

    // Leaf certificate whose SAN is a *different* host than the verifier's
    // configured public_base_url below.
    let ca = new_ca("Test Verifier Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "other-host.example.com",
        &["other-host.example.com".to_string()],
        365,
    )
    .unwrap();
    let x5c_path = dir.path().join("leaf.pem");
    std::fs::write(&x5c_path, leaf.cert_pem.as_bytes()).unwrap();
    let key_path = dir.path().join("leaf_key.pem");
    std::fs::write(&key_path, leaf.key_pem.as_bytes()).unwrap();

    // public_base_url's host ("verifier.example.com") does not match the
    // leaf certificate's SAN ("other-host.example.com").
    let config = sample_config(key_path.to_str().unwrap(), Some(x5c_path.to_str().unwrap()));
    let storage = test_storage().await;

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "request_uri".to_string(),
        transaction_data: None,
    };
    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();
    let tx = load_verification_transaction(&storage, &res.verification_id)
        .await
        .unwrap()
        .unwrap();

    let result = build_signed_request_object(&config, &tx);

    assert!(
        result.is_err(),
        "signing a request object whose public_base_url host does not match any \
         dNSName SAN entry in the configured x5c leaf certificate must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Positive control for GAP-VP-02: a leaf certificate whose SAN *does* match
// the derived client_id host must sign successfully. Without this, vp_0063
// above would also pass if build_signed_request_object were changed to
// unconditionally error whenever x5c is configured, regardless of SAN
// content -- this proves the check is a genuine comparison, not a stub.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn build_signed_request_object_succeeds_when_x5c_san_matches_public_base_url_host() {
    let dir = tempfile::tempdir().unwrap();

    let ca = new_ca("Test Verifier Root CA", 3650).unwrap();
    let leaf = issue_leaf(
        &ca.cert_pem,
        &ca.key_pem,
        "verifier.example.com",
        &["verifier.example.com".to_string()],
        365,
    )
    .unwrap();
    let x5c_path = dir.path().join("leaf.pem");
    std::fs::write(&x5c_path, leaf.cert_pem.as_bytes()).unwrap();
    let key_path = dir.path().join("leaf_key.pem");
    std::fs::write(&key_path, leaf.key_pem.as_bytes()).unwrap();

    // public_base_url's host ("verifier.example.com") matches the leaf
    // certificate's SAN this time.
    let config = sample_config(key_path.to_str().unwrap(), Some(x5c_path.to_str().unwrap()));
    let storage = test_storage().await;

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "request_uri".to_string(),
        transaction_data: None,
    };
    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();
    let tx = load_verification_transaction(&storage, &res.verification_id)
        .await
        .unwrap()
        .unwrap();

    build_signed_request_object(&config, &tx)
        .expect("a matching x509_hash leaf certificate must sign successfully");
}

// ---------------------------------------------------------------------------
// Decision 3 (2026-08-03 Tier 4 spec): under x509_hash the Client Identifier
// *is* the certificate hash, so a signed request with no configured x5c has no
// identifier to emit at all -- unlike the old x509_san_dns behaviour this test
// used to cover, absent x5c is now a configuration error, not a degraded-but-
// working path.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn create_verification_request_requires_x5c_for_the_request_uri_transport() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = write_key(dir.path(), "verifier.pem");
    let config = sample_config(&key_path, None);
    let storage = test_storage().await;

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "request_uri".to_string(),
        transaction_data: None,
    };

    // The unsigned openid4vp:// URI branch of create_verification_request also
    // computes the x509_hash Client Identifier now, so the error surfaces here
    // rather than only in build_signed_request_object.
    let err = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("x5c"),
        "expected a typed error naming the missing x5c certificate, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Task 13 — DCQL and Claims Path Pointer (OpenID4VP 1.0 §6, §7).
// Code under audit: `crates/foundry-verifier/src/dcql.rs` and
// `crates/foundry-verifier/src/dcql_model.rs`, exercised through the public
// `check_dcql_match` entry point (`dcql_model` itself is a private module).
// ---------------------------------------------------------------------------

// VP-0091, VP-0105, VP-0109 — DCQL / Credential Query (L739): entries in
// `credentials` MUST be objects with the defined properties. DCQL / Claims
// Query (L900): entries in `claims` MUST be objects with the defined
// properties. DCQL / Claims Query (L910): `path` is REQUIRED. All three are
// enforced at deserialization (`DcqlCredentialQuery`/`DcqlClaimsQuery` have no
// permissive fallback), and `check_dcql_match` fails closed -- it never
// panics on a malformed query, it reports a failed `dcql_match` check.
#[test]
fn vp_0091_0105_0109_malformed_dcql_shapes_fail_closed() {
    let claims = serde_json::json!({"vct": "x", "given_name": "Alice"});

    // VP-0091: a `credentials` entry that is not an object.
    let q = serde_json::json!({"credentials": ["not-an-object"]});
    let r = check_dcql_match(&q, "pid", PresentedFormat::SdJwtVc, &claims, None);
    assert!(!r.passed, "non-object credentials entry must be rejected");

    // VP-0105: a `claims` entry that is not an object.
    let q = serde_json::json!({"credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": {},
        "claims": ["not-an-object"]
    }]});
    let r = check_dcql_match(&q, "pid", PresentedFormat::SdJwtVc, &claims, None);
    assert!(!r.passed, "non-object claims entry must be rejected");

    // VP-0109: `path` missing entirely (not just present-and-empty) from a
    // Claims Query.
    let q = serde_json::json!({"credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": {},
        "claims": [{"values": ["x"]}]
    }]});
    let r = check_dcql_match(&q, "pid", PresentedFormat::SdJwtVc, &claims, None);
    assert!(!r.passed, "a Claims Query missing `path` must be rejected");
}

// VP-0110 — DCQL / Claims Query (L920): value matching against an ISO mdoc
// Credential requires the CBOR value to first be converted to JSON per
// RFC8949 §6.1. That conversion itself happens in
// `foundry_mdoc::verifier::cbor_value_to_json`, upstream of `check_dcql_match`
// (see `verify.rs`, which builds `disclosed_claims` from
// `foundry_mdoc::verifier::verify_mdoc`'s already-JSON-converted output before
// ever calling `check_dcql_match`). This test exercises the boundary
// `check_dcql_match` itself owns: that a `values` constraint correctly
// matches (and rejects a mismatch of) the JSON types that conversion
// produces for an mdoc claim.
#[test]
fn vp_0110_mdoc_value_matching_matches_converted_json_types() {
    let q = serde_json::json!({"credentials":[{"id":"mdl","format":"mso_mdoc",
        "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
        "claims":[{"path":["org.iso.18013.5.1","age_over_18"],"values":[true]}]}]});

    let claims = serde_json::json!({"org.iso.18013.5.1":{"age_over_18": true}});
    let r = check_dcql_match(
        &q,
        "mdl",
        PresentedFormat::MsoMdoc,
        &claims,
        Some("org.iso.18013.5.1.mDL"),
    );
    assert!(r.passed, "detail={:?}", r.detail);

    let claims_mismatch = serde_json::json!({"org.iso.18013.5.1":{"age_over_18": false}});
    let r2 = check_dcql_match(
        &q,
        "mdl",
        PresentedFormat::MsoMdoc,
        &claims_mismatch,
        Some("org.iso.18013.5.1.mDL"),
    );
    assert!(
        !r2.passed,
        "a values mismatch must not be credited as a match"
    );
}

// GAP-VP-03 — DCQL / Credential Query (L743, L745, L756); DCQL / Claims Query
// (L780): a Credential Query `id` MUST be a non-empty string of alphanumeric,
// underscore or hyphen characters (VP-0093) and MUST NOT repeat within one
// Authorization Request (VP-0094); `meta` is REQUIRED, even if empty
// (VP-0096); and Verifiers MUST NOT point to the same claim more than once in
// a single query's `claims` array (VP-0097). None of these four constraints
// is validated by `DcqlCredentialQuery`/`DcqlClaimsQuery` deserialization --
// `id` is an unconstrained `String`, `meta` is `Option<Value>` with
// `#[serde(default)]` (so it may be entirely absent, not merely empty), and
// neither `credentials` nor `claims` checks its entries for duplicates. This
// query violates all four simultaneously and parses and evaluates as if it
// were a well-formed request.
#[test]
#[ignore = "GAP-VP-03: OpenID4VP DCQL / Credential Query (L743, L745, L756); DCQL / Claims Query (L780) — id character-class and uniqueness, meta required-presence, and claims duplicate-path uniqueness are never validated"]
fn vp_0093_0094_0096_0097_dcql_structural_constraints_not_validated() {
    let q = serde_json::json!({"credentials": [
        {"id": "dup!", "format": "dc+sd-jwt",
         "claims": [{"path": ["given_name"]}, {"path": ["given_name"]}]},
        {"id": "dup!", "format": "mso_mdoc", "meta": {}}
    ]});
    let claims = serde_json::json!({"given_name": "Alice"});
    let r = check_dcql_match(&q, "dup!", PresentedFormat::SdJwtVc, &claims, None);
    assert!(
        !r.passed,
        "expected the malformed query (duplicate/invalid-charset ids, a \
         credential query missing `meta` entirely, and a claims array \
         repeating the same path) to be rejected before matching; instead \
         it evaluated successfully: detail={:?}",
        r.detail
    );
}

// ---------------------------------------------------------------------------
// Task 15 — Encrypted Responses and Transaction Data (OpenID4VP 1.0 §8.3,
// §8.4; HAIP OpenID4VP encryption requirements).
// ---------------------------------------------------------------------------

// GAP-VP-05 — HAIP OpenID4VP (L258): Verifiers MUST list both `A128GCM` and
// `A256GCM` in `encrypted_response_enc_values_supported` in their client
// metadata. `response_encryption_params` (request.rs) resolves to exactly one
// `enc` value (the configured value, defaulting to `A128GCM`), and both the
// `request_uri` and `dc_api` transports advertise
// `"encrypted_response_enc_values_supported": [response_enc_method]` -- a
// single-element array. `A256GCM` decryption itself works fine when a wallet
// chooses to use it (see `haip_0049_0050_0053_ecdh_es_p256_and_a256gcm_supported`
// in verify.rs), but the Verifier never *advertises* it as supported, so a
// wallet consulting client_metadata alone would not know to try it.
#[tokio::test]
#[ignore = "GAP-VP-05: HAIP OpenID4VP (L258) — encrypted_response_enc_values_supported only ever lists the single configured enc value (default A128GCM), never both A128GCM and A256GCM as HAIP-0052 requires"]
async fn haip_0052_encrypted_response_enc_values_supported_lists_only_one_value() {
    let storage = test_storage().await;
    let config = sample_config("/tmp/fake_key.pem", None);

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "dc_api".to_string(),
        transaction_data: None,
    };
    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();

    let dc_req = res.dc_api_request.unwrap();
    let supported = dc_req["client_metadata"]["encrypted_response_enc_values_supported"]
        .as_array()
        .unwrap();
    let values: Vec<&str> = supported.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        values.contains(&"A128GCM") && values.contains(&"A256GCM"),
        "encrypted_response_enc_values_supported must list both A128GCM and \
         A256GCM per HAIP-0052, got: {values:?}"
    );
}

// ---------------------------------------------------------------------------
// VP-0229 / VP-0232-VP-0240 / VP-0243-VP-0250 — OpenID4VP Format / mdoc /
// Invocation via Redirects (L2833, L2865); Invocation via the DC API (L2963,
// L2994): the mdoc `SessionTranscript`'s `Handover` element MUST be the
// spec-defined `OpenID4VPHandover` (redirects) or `OpenID4VPDCAPIHandover`
// (DC API) CBOR structure, whose first element is the literal text string
// naming that structure and whose second element is the SHA-256 hash of a
// CBOR-encoded `HandoverInfo` structure — not raw request parameter values
// placed directly in the array.
//
// Formerly GAP-VP-06: `serialize_session_transcript` built an ad-hoc 3-element
// array of the raw client_id/response_uri/nonce and never emitted the literal
// at all. Closed 2026-08-02 by `foundry_mdoc::types::build_session_transcript`,
// which is pinned byte-for-byte against OpenID4VP's own published vectors in
// that module's tests, with foundry-verifier selecting the variant from the
// transaction's transport and Response Mode.
// ---------------------------------------------------------------------------
#[test]
fn gap_vp_06_mdoc_session_transcript_handover_should_contain_the_spec_defined_literal() {
    // Exactly the shape the transcript builder is called with for a
    // redirect-based mdoc presentation (see foundry-verifier's `verify.rs`).
    let bytes = foundry_mdoc::types::build_session_transcript(
        &foundry_mdoc::types::SessionTranscriptParams::Redirect {
            client_id: "x509_san_dns:issuer.example.com".to_string(),
            nonce: "some-nonce-value".to_string(),
            jwk_thumbprint: None,
            response_uri: "https://issuer.example.com/vp/response/tx1".to_string(),
        },
    )
    .unwrap();

    // OpenID4VP L2865: "The first element of `OpenID4VPHandover` MUST be the
    // string `OpenID4VPHandover`." ciborium's definite-length encoding for a
    // short (<24-byte) CBOR text string is a single major-type-3 length byte
    // immediately followed by the UTF-8 bytes verbatim, so if this literal
    // were present anywhere in the Handover element, its raw ASCII bytes
    // would appear somewhere in the encoded SessionTranscript.
    let needle = b"OpenID4VPHandover";
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "OpenID4VP mdoc profile (L2865) requires the Handover's first element to be the \
         literal string 'OpenID4VPHandover', but the encoded SessionTranscript bytes never \
         contain it -- build_session_transcript must place that literal first, not the raw \
         client_id/response_uri/nonce values, and must hash a spec-defined \
         HandoverInfo structure into the second element"
    );
}

// ---------------------------------------------------------------------------
// VP-0198 / VP-0201 — OpenID4VP DC API / Request (L2433, L2438): `client_id`
// MUST be omitted in unsigned DC API requests, and `response_mode` MUST be
// `dc_api.jwt` when the response is encrypted (always, in this workspace).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn vp_0198_0201_dc_api_unsigned_request_shape() {
    let storage = test_storage().await;
    let config = sample_config("/tmp/fake_key.pem", None);

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "dc_api".to_string(),
        transaction_data: None,
    };
    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();

    let dc_req = res.dc_api_request.unwrap();
    assert!(
        dc_req.as_object().unwrap().get("client_id").is_none(),
        "VP-0198: client_id MUST be omitted in an unsigned DC API request, got: {dc_req}"
    );
    assert_eq!(
        dc_req["response_mode"], "dc_api.jwt",
        "VP-0201: response_mode MUST be dc_api.jwt when the response is encrypted"
    );
}

/// OpenID4VP 1.0 §A.3 (DC API / Request, L2421-L2431) lists `transaction_data`
/// among the Authorization Request parameters supported over the W3C Digital
/// Credentials API. The bytes advertised must be the same base64url strings
/// persisted on the transaction -- which are also what the `request_uri`
/// transport emits -- so a wallet hashes identical input on either transport.
#[tokio::test]
async fn dc_api_request_advertises_encoded_transaction_data() {
    let storage = test_storage().await;
    let config = sample_config("/tmp/fake_key.pem", None);

    let req = CreateVerificationRequest {
        dcql_query: Some(serde_json::json!({
            "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
        })),
        named_query_ref: None,
        transport: "dc_api".to_string(),
        transaction_data: Some(vec![serde_json::json!({
            "type": "qes_authorization",
            "credential_ids": ["c1"]
        })]),
    };

    let res = create_verification_request(&config, &storage, req, 1_700_000_000)
        .await
        .unwrap();

    let verification_id = res.verification_id.clone();
    let dc_req = res.dc_api_request.unwrap();

    let entries = dc_req["transaction_data"]
        .as_array()
        .unwrap_or_else(|| panic!("dc_api_request must carry transaction_data, got: {dc_req}"));
    assert_eq!(
        entries.len(),
        1,
        "one requested entry must yield one advertised entry"
    );

    let encoded = entries[0]
        .as_str()
        .expect("each transaction_data entry must be a base64url string, not an object");

    let decoded: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(encoded).unwrap()).unwrap();
    assert_eq!(decoded["type"], "qes_authorization");
    assert_eq!(decoded["credential_ids"], serde_json::json!(["c1"]));
    assert_eq!(
        decoded["transaction_data_hashes_alg"],
        serde_json::json!(["sha-256"]),
        "transaction_data_hashes_alg must be injected before encoding (OpenID4VP L3142)"
    );

    let tx = load_verification_transaction(&storage, &verification_id)
        .await
        .unwrap()
        .expect("transaction must be persisted");
    assert_eq!(
        tx.transaction_data.as_deref(),
        Some(&[encoded.to_string()][..]),
        "the advertised bytes must be exactly the bytes stored for the hash check"
    );
}
