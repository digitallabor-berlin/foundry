//! OpenID4VCI Credential Issuer Metadata and OAuth Authorization Server
//! Metadata, defined directly against the specification rather than derived
//! from a generic protocol library's types.

use foundry_core::config::{Config, CredentialType, Mode};
use foundry_core::crypto::SignatureAlgorithm;
use serde::Serialize;
use std::collections::BTreeMap;

/// One entry of `credential_signing_alg_values_supported`.
///
/// OpenID4VCI 1.0 L1393 makes the identifier *type* a property of the
/// Credential Format rather than of this parameter: "Algorithm identifier types
/// and values used are determined by the Credential Format." The two formats
/// foundry issues sit in different registries:
///
/// * `mso_mdoc` (L2223) — the **numeric** COSE algorithm identifiers securing
///   the `IssuerAuth` COSE structure, e.g. `-7`.
/// * `dc+sd-jwt` (L2265) — case-sensitive **strings** from the IANA JOSE
///   registry, e.g. `"ES256"`.
///
/// Modelled as an untagged enum rather than `Vec<String>` so the mdoc case is
/// expressible at all: a `Vec<String>` silently forces every format into the
/// JOSE spelling, which is the defect this type exists to make impossible.
/// Untagged serialisation emits the bare scalar — `"ES256"` or `-7` — with no
/// wrapper object.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum CredentialSigningAlg {
    /// A JOSE Algorithm Name, for JWS-secured formats (L2265).
    Jose(String),
    /// A numeric COSE algorithm identifier, for COSE-secured formats (L2223).
    Cose(i64),
}

/// The algorithm identifiers to advertise for one credential configuration,
/// in the registry its Credential Format uses.
///
/// Derived from the key that actually signs credentials
/// (`Config::credential_signing_key`) rather than hardcoded: L2223 asks the
/// advertised `mso_mdoc` value to match the `alg` in the `IssuerAuth` COSE
/// header, and an issuer configured with an ES384 key that advertises ES256
/// misdescribes every credential it issues in either format.
///
/// Empty when no signing key resolves or its `alg` does not parse — a state
/// `Config::validate_key_material` rejects at startup, so it is unreachable in
/// a running issuer. Empty means the parameter is omitted entirely, which L1393
/// permits (it is OPTIONAL); emitting `[]` would not, since L1393 requires "a
/// non-empty array".
fn credential_signing_algs(cfg: &Config, format: &str) -> Vec<CredentialSigningAlg> {
    let Some((_, key)) = cfg.credential_signing_key() else {
        return Vec::new();
    };
    let Ok(alg) = key.alg.parse::<SignatureAlgorithm>() else {
        return Vec::new();
    };

    match format {
        // L2223: the numeric COSE identifier securing `IssuerAuth`. Kept in
        // lockstep with the header `foundry-mdoc`'s `alg_label` writes by
        // `SignatureAlgorithm::cose_value`, which owns the correspondence.
        "mso_mdoc" => vec![CredentialSigningAlg::Cose(alg.cose_value())],
        // L2265 for `dc+sd-jwt`. Also the fallback: every non-COSE Credential
        // Format profile in OpenID4VCI 1.0 uses JOSE Algorithm Names, and
        // `Config::validate()` admits no format beyond these two, so an unknown
        // format here cannot arise from configuration.
        _ => vec![CredentialSigningAlg::Jose(alg.as_str().to_string())],
    }
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    pub credential_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfigurationSupported>,
    /// `skip_serializing_if` is load-bearing: with the feature off the
    /// serialised document must stay byte-identical to the pre-encryption one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_request_encryption: Option<CredentialRequestEncryption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialConfigurationSupported {
    pub format: String,
    /// HAIP OpenID4VCI L186: the metadata MUST include a scope for every Credential
    /// Configuration. Neither `Option` nor `skip_serializing_if`: "every" admits no
    /// omission.
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    pub cryptographic_binding_methods_supported: Vec<String>,
    /// L1393: OPTIONAL, and "a non-empty array" when present — hence
    /// `skip_serializing_if` rather than an emitted `[]`. See
    /// [`credential_signing_algs`] for how the values are derived and why the
    /// element type is not `String`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credential_signing_alg_values_supported: Vec<CredentialSigningAlg>,
    pub proof_types_supported: BTreeMap<String, ProofTypeSupported>,
    /// L1400: OPTIONAL, so a credential type with neither display nor claims
    /// emits no key at all rather than `"credential_metadata": {}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<CredentialMetadata>,
    /// PaSO Proof Metadata §2 — the URL serving this configuration's credential
    /// metadata, as plain JSON or as a signed `credential-metadata+jwt`.
    ///
    /// Emitted **only** for PaSO Credential configurations (those declaring
    /// `transaction_data_types`). §2 scopes the requirement to them, and the
    /// route 404s for anything else — advertising it more widely would publish
    /// a link to a 404. `skip_serializing_if` rather than an emitted `null`, so
    /// every non-PaSO deployment's wire output stays byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata_uri: Option<String>,
}

/// OpenID4VCI L1400 — `credential_metadata`, the nested object carrying a
/// Credential Configuration's display and claims metadata.
///
/// Until 2026-08-24 foundry emitted `display` and `claims` as flat siblings of
/// `format`/`scope` — the pre-1.0 draft shape. A 1.0 wallet finds no
/// `credential_metadata`, and L1423 ("The Wallet MUST ignore any unrecognized
/// parameters") then obliges it to discard the flat copies, so the credential
/// arrives renderable but unrendered. For an `mso_mdoc` credential this is
/// total rather than partial: L1400 calls itself the fallback behind
/// format-specific mechanisms, but mdoc has none, so this object is the only
/// display channel that exists.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialMetadata {
    /// L1401: OPTIONAL, and "a non-empty array" when present — hence
    /// `skip_serializing_if` rather than an emitted `[]`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    /// L1412: OPTIONAL, and "a non-empty array" when present.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub claims: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub key_attestations_required: Option<serde_json::Value>,
}

/// OpenID4VCI Credential Issuer Metadata `credential_request_encryption`
/// (L1373–L1377). `zip_values_supported` is deliberately absent: L1375 makes it
/// optional and its absence means no compression algorithm is supported.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialRequestEncryption {
    /// L1373: a JWK Set whose every member carries a unique `kid`.
    #[schema(value_type = Object)]
    pub jwks: serde_json::Value,
    pub enc_values_supported: Vec<String>,
    pub encryption_required: bool,
}

/// OpenID4VCI Credential Issuer Metadata `credential_response_encryption`
/// (L1378–L1381). `zip_values_supported` is deliberately absent (L1380).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialResponseEncryption {
    pub alg_values_supported: Vec<String>,
    pub enc_values_supported: Vec<String>,
    pub encryption_required: bool,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
    /// RFC 9207 §2.3: an authorization server publishing metadata per RFC 8414
    /// MUST indicate its support for the `iss` parameter by setting this to
    /// `true` -- GAP-HAIP-02. Deliberately a plain required field (no
    /// `skip_serializing_if`): §2.3 wants it present and `true`, not merely
    /// inferable from its absence.
    pub authorization_response_iss_parameter_supported: bool,
    /// RFC 9449 §5.1: "A JSON array containing a list of the JWS alg values
    /// (from the [IANA.JOSE.ALGS] registry) supported by the authorization
    /// server for DPoP proof JWTs."
    ///
    /// Omitted entirely when `issuer.dpop.mode` is `Disabled` — the field's
    /// presence *is* the support signal, so advertising it while ignoring every
    /// proof would tell a wallet it can sender-constrain when it cannot.
    /// Contrast `authorization_response_iss_parameter_supported` above, which
    /// RFC 9207 §2.3 wants present-and-true unconditionally.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// ABCA draft -07 §10.1: "URL of the authorization servers challenge
    /// endpoint which is used to obtain a fresh challenge for usage in the
    /// Client Attestation PoP JWT."
    ///
    /// Omitted entirely when `issuer.wallet_attestation.challenge_mode` is
    /// `Disabled`. Per §8, publishing this field is what obliges a client to
    /// fetch and use a challenge -- so advertising it while ignoring every
    /// challenge would be actively misleading. Same reasoning as
    /// `dpop_signing_alg_values_supported` above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_endpoint: Option<String>,
}

/// OpenID4VCI L2321-L2338 — the claims description objects for one Credential
/// Configuration.
///
/// Extracted so the PaSO `credential_metadata` document (PaSO Proof Metadata
/// §3), served from a different endpoint, cannot describe the same credential
/// type differently from Issuer Metadata.
///
/// A claims description object for Issuer Metadata defines exactly `path`,
/// `mandatory` and `display`. Built as a map rather than with `json!` because
/// `skip_serializing_if` does not apply inside the macro: the old code emitted
/// `"display": []` for every claim without configured display, contradicting
/// L2332's "a non-empty array of objects".
///
/// `selectively_disclosable` was never an OpenID4VCI parameter. It is a
/// foundry config field name, and conveys nothing a wallet can use: for
/// SD-JWT VC the wallet learns disclosability from the credential's own
/// disclosures, and for mdoc every IssuerSignedItem is inherently
/// selectively disclosable.
pub(crate) fn claims_description_objects(ct: &CredentialType) -> Vec<serde_json::Value> {
    ct.claims
        .iter()
        .map(|c| {
            let mut claim = serde_json::Map::new();
            // L2323: REQUIRED.
            claim.insert("path".to_string(), serde_json::json!(c.path));
            // L2326/L2327: `mandatory` means "the Credential Issuer will
            // always include this claim in the issued Credential" -- which
            // is exactly `ClaimDef::is_required()`, the same predicate
            // `create_offer` uses to decide whether a value must be
            // supplied when an offer is created. Emitted unconditionally:
            // L2331 makes absence default to `false`, but the value is
            // always determinate here, so publishing it states the
            // issuer's intent instead of leaving it to a default.
            claim.insert("mandatory".to_string(), serde_json::json!(c.is_required()));
            // L2332: "A non-empty array of objects" -- omitted when empty.
            if !c.display.is_empty() {
                claim.insert("display".to_string(), serde_json::json!(c.display));
            }
            serde_json::Value::Object(claim)
        })
        .collect()
}

/// Build the Credential Issuer Metadata document, fully derived from
/// `cfg.credential_types` and `cfg.issuer` — nothing hard-coded per credential type.
///
/// `request_decryption_keys` are the already-loaded keys from
/// `Config::load_request_decryption_keys`. They are passed in rather than read
/// from disk here because metadata is served on every wallet request and must not
/// do filesystem I/O.
pub fn build_issuer_metadata(
    cfg: &Config,
    request_decryption_keys: &[foundry_core::crypto::jwe::DecryptionKey],
) -> CredentialIssuerMetadata {
    let base = cfg.issuer.credential_issuer.trim_end_matches('/');
    let mut configs = BTreeMap::new();
    for ct in &cfg.credential_types {
        let cryptographic_binding_methods_supported = if ct.cryptographic_holder_binding {
            vec!["jwk".to_string()]
        } else {
            Vec::new()
        };
        let claims = claims_description_objects(ct);
        configs.insert(
            ct.id.clone(),
            CredentialConfigurationSupported {
                format: ct.format.clone(),
                scope: ct.resolved_scope().to_string(),
                vct: ct.vct.clone(),
                doctype: ct.doctype.clone(),
                cryptographic_binding_methods_supported,
                credential_signing_alg_values_supported: credential_signing_algs(cfg, &ct.format),
                proof_types_supported: {
                    // OpenID4VCI L1395: each name here identifies a proof type
                    // this issuer *supports*, and the Wallet picks from this set
                    // for its Credential Request. L864 then makes `proofs`
                    // mandatory whenever this object is present. So the
                    // advertised set MUST mirror what `handle_credential_request`
                    // (credential.rs) actually accepts: advertising a type the
                    // Credential Endpoint refuses strands any wallet that
                    // implements only that type -- it complies with the metadata
                    // exactly and still gets `invalid_proof`.
                    let android_mode = cfg.issuer.key_attestation.android.mode.clone();
                    let mut types = BTreeMap::new();

                    // Withheld under `android.mode: required`, where
                    // `handle_credential_request` rejects a `jwt` proofs member
                    // outright -- before verifying anything -- because
                    // android_keystore_attestation is then the only accepted
                    // proof type. Closes GAP-VCI-15.
                    //
                    // The two conditions cannot both exclude: `required` keeps
                    // the android entry, `disabled` keeps this one, `optional`
                    // keeps both. So `proof_types_supported` is never emitted
                    // empty, which would be its own misrepresentation.
                    if android_mode != Mode::Required {
                        types.insert(
                            "jwt".to_string(),
                            ProofTypeSupported {
                                proof_signing_alg_values_supported: vec!["ES256".to_string()],
                                key_attestations_required: if cfg.issuer.key_attestation.mode
                                    == Mode::Required
                                {
                                    Some(serde_json::json!({}))
                                } else {
                                    None
                                },
                            },
                        );
                    }
                    // Google Wallet's proof type, advertised only when enabled.
                    // Vendor profile: docs/specs/google-wallet-openid4vci-profile.md.
                    //
                    // Two vendor readings, both deliberate:
                    //
                    // * `proof_signing_alg_values_supported` is REQUIRED by
                    //   Google's schema even though nothing in this proof type
                    //   is signed by the attested key. It is read as
                    //   constraining the *attested key's* algorithm, which is
                    //   what `keystore_proof.rs` enforces (P-256 only).
                    // * `key_attestations_required` here carries Google's field
                    //   names (`key_mint_security_level`), not OpenID4VCI's own
                    //   `key_storage`/`user_authentication` shape. The name
                    //   collision with the spec parameter is the vendor's.
                    //
                    // Its `key_attestations_required` is unconditional when the
                    // proof type is enabled: a minimum security level is always
                    // enforced, so a key attestation requirement always exists.
                    // (The `jwt` entry above varies that field with
                    // `key_attestation.mode`.)
                    if android_mode != Mode::Disabled {
                        types.insert(
                            "android_keystore_attestation".to_string(),
                            ProofTypeSupported {
                                proof_signing_alg_values_supported: vec!["ES256".to_string()],
                                key_attestations_required: Some(serde_json::json!({
                                    "key_mint_security_level": cfg
                                        .issuer
                                        .key_attestation
                                        .android
                                        .key_mint_security_level
                                        .as_str(),
                                })),
                            },
                        );
                    }
                    types
                },
                // L1400 is OPTIONAL: emit nothing when there is nothing to
                // say, rather than an empty object.
                credential_metadata: if ct.display.is_empty() && claims.is_empty() {
                    None
                } else {
                    Some(CredentialMetadata {
                        display: ct.display.clone(),
                        claims,
                    })
                },
                // PaSO Proof Metadata §2. `paso_metadata::credential_metadata_uri`
                // is the single owner of this string, so the value advertised
                // here and the `credential_metadata_uri` claim inside the signed
                // JWT are equal by construction — which is exactly what §8's
                // URI-binding check requires of us.
                credential_metadata_uri: if crate::paso_metadata::is_paso_credential_type(ct) {
                    Some(crate::paso_metadata::credential_metadata_uri(cfg, &ct.id))
                } else {
                    None
                },
            },
        );
    }
    CredentialIssuerMetadata {
        credential_issuer: base.to_string(),
        authorization_servers: Vec::new(),
        credential_endpoint: format!("{base}/credential"),
        nonce_endpoint: Some(format!("{base}/nonce")),
        display: Vec::new(),
        credential_configurations_supported: configs,
        credential_request_encryption: cfg.issuer.request_encryption.as_ref().map(|re| {
            CredentialRequestEncryption {
                jwks: serde_json::json!({
                    "keys": request_decryption_keys
                        .iter()
                        .map(|k| k.published_jwk())
                        .collect::<Vec<_>>(),
                }),
                enc_values_supported: re.enc_values_supported.clone(),
                encryption_required: re.encryption_required,
            }
        }),
        credential_response_encryption: cfg.issuer.response_encryption.as_ref().map(|rs| {
            CredentialResponseEncryption {
                // Fixed, not configurable: `encrypt_compact_with_kid` supports no
                // other key-management algorithm.
                alg_values_supported: vec!["ECDH-ES".to_string()],
                enc_values_supported: rs.enc_values_supported.clone(),
                encryption_required: rs.encryption_required,
            }
        }),
    }
}

/// Build the OAuth Authorization Server Metadata document.
pub fn build_authorization_server_metadata(cfg: &Config) -> AuthorizationServerMetadata {
    let base = cfg.issuer.credential_issuer.trim_end_matches('/');
    AuthorizationServerMetadata {
        issuer: base.to_string(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        nonce_endpoint: Some(format!("{base}/nonce")),
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            "authorization_code".to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        pre_authorized_grant_anonymous_access_supported: true,
        authorization_response_iss_parameter_supported: true,
        dpop_signing_alg_values_supported: if cfg.issuer.dpop.mode == Mode::Disabled {
            Vec::new()
        } else {
            // ES256 only: it is what josekit verification is wired for
            // throughout this crate, and HAIP's crypto-suites section mandates
            // it for every JWS in this profile.
            vec!["ES256".to_string()]
        },
        challenge_endpoint: if cfg.issuer.wallet_attestation.challenge_mode == Mode::Disabled {
            None
        } else {
            Some(format!("{base}/challenge"))
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, DpopConfig, IssuerConfig, KeyEntry,
        LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
        WalletFacingConfig,
    };
    use std::collections::BTreeMap as StdBTreeMap;

    pub(crate) fn test_config() -> Config {
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
            keys: StdBTreeMap::new(),
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
                    enabled: true,
                    signing_key: None,
                    list_size: Some(1024),
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
                display: vec![serde_json::json!({"name": "Person ID", "locale": "en-US"})],
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
                transaction_data_hashes_alg: vec!["sha-256".to_string()],
                named_queries: vec![],
                webhook: None,
                dc_api_expected_origins: Vec::new(),
                dc_api_accept_legacy_web_origin_audience: false,
            },
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn builds_issuer_metadata_from_credential_types() {
        let cfg = test_config();
        let meta = build_issuer_metadata(&cfg, &[]);
        assert_eq!(meta.credential_issuer, "https://issuer.example.com");
        assert_eq!(
            meta.credential_endpoint,
            "https://issuer.example.com/credential"
        );
        assert_eq!(
            meta.nonce_endpoint.as_deref(),
            Some("https://issuer.example.com/nonce")
        );
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(pid.format, "dc+sd-jwt");
        assert_eq!(
            pid.vct.as_deref(),
            Some("https://issuer.example.com/vct/pid")
        );
        assert_eq!(
            pid.cryptographic_binding_methods_supported,
            vec!["jwk".to_string()]
        );
        assert!(pid.proof_types_supported.contains_key("jwt"));
    }

    #[test]
    fn key_attestations_required_present_when_mode_required() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.mode = Mode::Required;
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let jwt_proof = pid.proof_types_supported.get("jwt").unwrap();
        assert_eq!(
            jwt_proof.key_attestations_required,
            Some(serde_json::json!({}))
        );
    }

    #[test]
    fn key_attestations_required_absent_when_mode_optional_or_disabled() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.mode = Mode::Optional;
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(
            pid.proof_types_supported
                .get("jwt")
                .unwrap()
                .key_attestations_required,
            None
        );

        cfg.issuer.key_attestation.mode = Mode::Disabled;
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(
            pid.proof_types_supported
                .get("jwt")
                .unwrap()
                .key_attestations_required,
            None
        );
    }

    #[test]
    fn android_proof_type_is_absent_when_disabled() {
        let cfg = test_config();
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert!(pid.proof_types_supported.contains_key("jwt"));
        assert!(
            !pid.proof_types_supported
                .contains_key("android_keystore_attestation"),
            "a disabled proof type must not be advertised"
        );
    }

    #[test]
    fn android_proof_type_is_advertised_with_the_configured_level() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.android.mode = Mode::Optional;
        cfg.issuer.key_attestation.android.key_mint_security_level =
            foundry_core::trust::android_attestation::SecurityLevel::StrongBox;
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let entry = pid
            .proof_types_supported
            .get("android_keystore_attestation")
            .expect("advertised when enabled");
        assert_eq!(entry.proof_signing_alg_values_supported, vec!["ES256"]);
        let required = entry
            .key_attestations_required
            .as_ref()
            .expect("key_attestations_required is always present for this proof type");
        assert_eq!(required["key_mint_security_level"], "StrongBox");
        // user_auth_types is deliberately absent: advertising a requirement
        // foundry does not enforce is the failure mode the design rejects.
        assert!(required.get("user_auth_types").is_none());
    }

    /// A signing key entry for the tests below. The path never has to exist:
    /// `build_issuer_metadata` reads `alg` only and does no filesystem I/O.
    fn key(alg: &str) -> KeyEntry {
        KeyEntry {
            private_key: "unused-by-metadata.pem".to_string(),
            x5c: None,
            alg: alg.to_string(),
        }
    }

    /// Turn the shipped `pid` configuration into an mdoc one, in place, so these
    /// tests do not have to restate every `CredentialType` field.
    fn make_mdoc(cfg: &mut Config) {
        let ct = &mut cfg.credential_types[0];
        ct.format = "mso_mdoc".to_string();
        ct.vct = None;
        ct.doctype = Some("eu.europa.ec.av.1".to_string());
    }

    fn advertised_algs(cfg: &Config) -> serde_json::Value {
        let meta = build_issuer_metadata(cfg, &[]);
        let json = serde_json::to_value(&meta).expect("metadata serialises");
        json["credential_configurations_supported"]["pid"]
            ["credential_signing_alg_values_supported"]
            .clone()
    }

    /// OpenID4VCI 1.0 L2223: for `mso_mdoc` the values "correspond to the
    /// numeric COSE algorithm identifiers used to secure the `IssuerAuth` COSE
    /// structure". A JOSE name string there is what a conformant wallet rejects
    /// — mdocs are COSE-signed, so the value space is the COSE registry.
    ///
    /// Asserted on the SERIALISED document, not on the Rust value: the defect
    /// this pins was observable only on the wire (`"ES256"` where `-7` belongs),
    /// and an untagged enum is exactly the kind of type whose Debug
    /// representation can look right while its JSON does not.
    #[test]
    fn mso_mdoc_advertises_a_numeric_cose_algorithm() {
        let mut cfg = test_config();
        cfg.keys.insert("issuer_key".to_string(), key("ES256"));
        make_mdoc(&mut cfg);

        let algs = advertised_algs(&cfg);
        assert_eq!(
            algs,
            serde_json::json!([-7]),
            "mso_mdoc must advertise the numeric COSE identifier (L2223), not a JOSE name"
        );
        assert!(
            algs[0].is_number(),
            "the entry must be a JSON number, not a string: {algs}"
        );
    }

    /// OpenID4VCI 1.0 L2265: for the SD-JWT VC profile the values are "case
    /// sensitive strings" from the IANA JOSE registry. The counterpart to the
    /// test above — the same parameter, the other registry, chosen by format.
    #[test]
    fn sd_jwt_vc_advertises_a_jose_algorithm_name() {
        let mut cfg = test_config();
        cfg.keys.insert("issuer_key".to_string(), key("ES256"));

        let algs = advertised_algs(&cfg);
        assert_eq!(algs, serde_json::json!(["ES256"]));
        assert!(
            algs[0].is_string(),
            "the entry must be a JSON string, not a number: {algs}"
        );
    }

    /// L2223 asks the advertised value to match the `alg` the issuer actually
    /// signs with, so the value must follow the configured key rather than a
    /// hardcoded ES256. An ES384 deployment that advertises ES256 misdescribes
    /// every credential it issues, in either format.
    #[test]
    fn the_advertised_algorithm_follows_the_configured_key() {
        let mut sd_jwt = test_config();
        sd_jwt.keys.insert("issuer_key".to_string(), key("ES384"));
        assert_eq!(advertised_algs(&sd_jwt), serde_json::json!(["ES384"]));

        let mut mdoc = test_config();
        mdoc.keys.insert("issuer_key".to_string(), key("ES384"));
        make_mdoc(&mut mdoc);
        assert_eq!(
            advertised_algs(&mdoc),
            serde_json::json!([-35]),
            "the COSE identifier must be ES384's, not ES256's"
        );
    }

    /// The metadata must describe the key that *signs*, which
    /// `handle_credential_request` resolves through
    /// `Config::credential_signing_key`: `issuer.status_list.signing_key` first,
    /// the first entry in `keys` only as a fallback.
    ///
    /// The two keys here carry different algorithms and are named so that map
    /// order puts the WRONG one first — a metadata builder that reached for
    /// `keys.first()` unconditionally would advertise ES256 while the issuer
    /// signed with ES384, and no other test in this file would notice.
    #[test]
    fn the_advertised_algorithm_comes_from_the_key_that_signs() {
        let mut cfg = test_config();
        cfg.keys.insert("aaa_other_key".to_string(), key("ES256"));
        cfg.keys.insert("zzz_signing_key".to_string(), key("ES512"));
        cfg.issuer.status_list.signing_key = Some("zzz_signing_key".to_string());

        assert_eq!(advertised_algs(&cfg), serde_json::json!(["ES512"]));
    }

    /// L1393 makes the parameter OPTIONAL but requires "a non-empty array" when
    /// present, so an issuer that cannot resolve a signing key must omit the
    /// member rather than emit `[]`.
    ///
    /// Unreachable in a running issuer — `Config::validate_key_material` rejects
    /// this configuration at startup — which is precisely why it is pinned here:
    /// the branch has no other observable consumer.
    #[test]
    fn the_parameter_is_omitted_when_no_signing_key_resolves() {
        let cfg = test_config();
        assert!(cfg.keys.is_empty(), "precondition: no keys configured");

        let meta = build_issuer_metadata(&cfg, &[]);
        let json = serde_json::to_value(&meta).expect("metadata serialises");
        let pid = &json["credential_configurations_supported"]["pid"];

        assert!(
            pid.get("credential_signing_alg_values_supported").is_none(),
            "an unresolvable signing key must omit the OPTIONAL parameter, not emit an \
             empty array: {pid}"
        );
    }

    #[test]
    fn trims_trailing_slash_from_credential_issuer() {
        let mut cfg = test_config();
        cfg.issuer.credential_issuer = "https://issuer.example.com/".to_string();
        let meta = build_issuer_metadata(&cfg, &[]);
        assert_eq!(
            meta.credential_endpoint,
            "https://issuer.example.com/credential"
        );
    }

    #[test]
    fn builds_authorization_server_metadata() {
        let cfg = test_config();
        let meta = build_authorization_server_metadata(&cfg);
        assert_eq!(meta.issuer, "https://issuer.example.com");
        assert_eq!(meta.token_endpoint, "https://issuer.example.com/token");
        assert!(meta.pre_authorized_grant_anonymous_access_supported);
        assert_eq!(
            meta.authorization_endpoint,
            "https://issuer.example.com/authorize"
        );
        assert_eq!(meta.response_types_supported, vec!["code".to_string()]);
        assert_eq!(
            meta.code_challenge_methods_supported,
            vec!["S256".to_string()]
        );
        assert_eq!(
            meta.grant_types_supported,
            vec![
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                "authorization_code".to_string(),
            ]
        );
        // RFC 9207 §2.3, GAP-HAIP-02.
        assert!(meta.authorization_response_iss_parameter_supported);
    }

    #[test]
    fn every_credential_configuration_carries_a_scope() {
        // HAIP OpenID4VCI L186: the Credential Issuer metadata MUST include a scope
        // for every Credential Configuration it supports.
        let cfg = test_config();
        let metadata = build_issuer_metadata(&cfg, &[]);
        assert!(!metadata.credential_configurations_supported.is_empty());
        for (id, config) in &metadata.credential_configurations_supported {
            let json = serde_json::to_value(config).unwrap();
            let scope = json
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("configuration '{id}' has no scope"));
            assert!(!scope.is_empty(), "configuration '{id}' has an empty scope");
        }
    }

    #[test]
    fn scope_defaults_to_the_credential_type_id_and_can_be_overridden() {
        let mut cfg = test_config();
        cfg.credential_types[0].scope = None;
        let default_id = cfg.credential_types[0].id.clone();
        cfg.credential_types.push(CredentialType {
            id: "override_me".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/other".to_string()),
            doctype: None,
            scope: Some("eu.europa.ec.eudi.pid.1".to_string()),
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
            validity_seconds: None,
            transaction_data_types: None,
        });

        let metadata = build_issuer_metadata(&cfg, &[]);
        assert_eq!(
            metadata.credential_configurations_supported[&default_id].scope,
            default_id
        );
        assert_eq!(
            metadata.credential_configurations_supported["override_me"].scope,
            "eu.europa.ec.eudi.pid.1"
        );
    }

    /// VCI-0145 (OpenID4VCI Credential Issuer Metadata L1392): "The Authorization
    /// Server MUST be able to uniquely identify the Credential Issuer based on the
    /// scope value." foundry's Authorization Server always serves exactly one
    /// Credential Issuer (`config.issuer.credential_issuer`), so `issuer` in
    /// `AuthorizationServerMetadata` is the same single value no matter which
    /// Credential Type's scope a Wallet used to get there -- there is only ever one
    /// candidate to identify.
    #[test]
    fn authorization_server_metadata_issuer_is_independent_of_credential_type_scope() {
        let mut cfg = test_config();
        cfg.credential_types.push(CredentialType {
            id: "mdl".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/mdl".to_string()),
            doctype: None,
            scope: Some("eu.europa.ec.eudi.pid.1".to_string()),
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
            validity_seconds: None,
            transaction_data_types: None,
        });

        let meta = build_authorization_server_metadata(&cfg);
        assert_eq!(meta.issuer, cfg.issuer.credential_issuer);
    }

    #[test]
    fn advertises_dpop_signing_algs_when_dpop_is_enabled() {
        // RFC 9449 §5.1: dpop_signing_alg_values_supported is "A JSON array
        // containing a list of the JWS alg values supported by the authorization
        // server for DPoP proof JWTs". Its presence is the support signal.
        let mut cfg = test_config();
        cfg.issuer.dpop.mode = Mode::Optional;
        let md = build_authorization_server_metadata(&cfg);
        assert_eq!(
            md.dpop_signing_alg_values_supported,
            vec!["ES256".to_string()]
        );
    }

    #[test]
    fn advertises_dpop_signing_algs_under_required_mode_too() {
        let mut cfg = test_config();
        cfg.issuer.dpop.mode = Mode::Required;
        let md = build_authorization_server_metadata(&cfg);
        assert_eq!(
            md.dpop_signing_alg_values_supported,
            vec!["ES256".to_string()]
        );
    }

    #[test]
    fn omits_dpop_signing_algs_when_dpop_is_disabled() {
        // Advertising support while ignoring every proof would be a lie: a wallet
        // reading this field would conclude it can sender-constrain when it cannot.
        let mut cfg = test_config();
        cfg.issuer.dpop.mode = Mode::Disabled;
        let md = build_authorization_server_metadata(&cfg);
        assert!(md.dpop_signing_alg_values_supported.is_empty());

        // skip_serializing_if means an empty vec is absent from the wire, not `[]`.
        let json = serde_json::to_value(&md).unwrap();
        assert!(
            json.get("dpop_signing_alg_values_supported").is_none(),
            "an empty list MUST be omitted, not serialized as []"
        );
    }

    /// ABCA §8: the metadata entry's *presence* is the support signal, and its
    /// presence is what makes the `challenge` claim mandatory for clients.
    /// Advertising it while ignoring every challenge would tell a wallet something
    /// false -- the same reasoning already recorded for
    /// `dpop_signing_alg_values_supported`.
    #[test]
    fn advertises_challenge_endpoint_when_challenge_mode_is_enabled() {
        let mut cfg = test_config();
        cfg.issuer.wallet_attestation.challenge_mode = Mode::Optional;
        let base = cfg
            .issuer
            .credential_issuer
            .trim_end_matches('/')
            .to_string();
        let meta = build_authorization_server_metadata(&cfg);
        assert_eq!(
            meta.challenge_endpoint.as_deref(),
            Some(format!("{base}/challenge").as_str())
        );

        cfg.issuer.wallet_attestation.challenge_mode = Mode::Required;
        assert!(
            build_authorization_server_metadata(&cfg)
                .challenge_endpoint
                .is_some()
        );
    }

    #[test]
    fn omits_challenge_endpoint_when_challenge_mode_is_disabled() {
        let mut cfg = test_config();
        cfg.issuer.wallet_attestation.challenge_mode = Mode::Disabled;
        let meta = build_authorization_server_metadata(&cfg);
        assert!(meta.challenge_endpoint.is_none());

        let json = serde_json::to_value(&meta).expect("serialize");
        assert!(
            json.get("challenge_endpoint").is_none(),
            "the field must be absent from the wire form, not null"
        );
    }

    #[test]
    fn omits_both_encryption_objects_when_unconfigured() {
        let cfg = test_config();
        let json = serde_json::to_value(build_issuer_metadata(&cfg, &[])).unwrap();
        assert!(
            json.get("credential_request_encryption").is_none(),
            "unconfigured metadata must stay byte-identical to pre-encryption output"
        );
        assert!(json.get("credential_response_encryption").is_none());
    }

    #[test]
    fn publishes_the_request_jwks_with_annotated_kids() {
        let mut cfg = test_config();
        cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
            keys: vec!["issuer_request_enc".to_string()],
            enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
            encryption_required: false,
        });
        let km =
            foundry_core::pki::generate_ec_key(foundry_core::crypto::SignatureAlgorithm::Es256)
                .unwrap();
        let key =
            foundry_core::crypto::jwe::DecryptionKey::from_pem(km.private_pem.as_bytes()).unwrap();
        let expected_kid = key.kid().to_string();

        let json =
            serde_json::to_value(build_issuer_metadata(&cfg, std::slice::from_ref(&key))).unwrap();
        let obj = &json["credential_request_encryption"];
        assert_eq!(
            obj["jwks"]["keys"][0]["kid"],
            serde_json::json!(expected_kid)
        );
        assert_eq!(obj["jwks"]["keys"][0]["alg"], serde_json::json!("ECDH-ES"));
        assert_eq!(obj["jwks"]["keys"][0]["use"], serde_json::json!("enc"));
        assert_eq!(obj["encryption_required"], serde_json::json!(false));
        assert_eq!(
            obj["enc_values_supported"],
            serde_json::json!(["A128GCM", "A256GCM"])
        );
        // OpenID4VCI L1375: absence means compression MUST NOT be used.
        assert!(obj.get("zip_values_supported").is_none());
    }

    #[test]
    fn publishes_response_encryption_with_ecdh_es_only() {
        let mut cfg = test_config();
        cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
            enc_values_supported: vec!["A256GCM".to_string()],
            encryption_required: true,
        });
        let json = serde_json::to_value(build_issuer_metadata(&cfg, &[])).unwrap();
        let obj = &json["credential_response_encryption"];
        assert_eq!(obj["alg_values_supported"], serde_json::json!(["ECDH-ES"]));
        assert_eq!(obj["enc_values_supported"], serde_json::json!(["A256GCM"]));
        assert_eq!(obj["encryption_required"], serde_json::json!(true));
        assert!(obj.get("zip_values_supported").is_none());
    }

    /// `display` is an opaque passthrough into
    /// `credential_configurations_supported[].credential_metadata.display`
    /// (OpenID4VCI L1401), so every configured locale entry must arrive intact,
    /// in order, with its members preserved. A wallet reads this array to
    /// render the credential, so silently dropping or reordering entries would
    /// be invisible here but visible on a device.
    #[test]
    fn credential_configuration_display_carries_every_configured_locale() {
        let mut cfg = test_config();
        cfg.credential_types[0].display = vec![
            serde_json::json!({"name": "Payment Card", "locale": "en-US"}),
            serde_json::json!({"name": "Zahlungskarte", "locale": "de-DE"}),
            serde_json::json!({"name": "Carte de paiement", "locale": "fr-FR"}),
        ];
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let display = &pid
            .credential_metadata
            .as_ref()
            .expect("display is configured, so credential_metadata is present")
            .display;

        let locales: Vec<&str> = display
            .iter()
            .filter_map(|d| d.get("locale").and_then(|l| l.as_str()))
            .collect();
        assert_eq!(locales, vec!["en-US", "de-DE", "fr-FR"]);
        assert_eq!(display[1]["name"], "Zahlungskarte");
    }

    /// OpenID4VCI L1400-L1412: `display` and `claims` are members of a nested
    /// `credential_metadata` object, not flat siblings of `format`/`scope`.
    /// Until 2026-08-24 foundry emitted the flat, pre-1.0 draft shape, and
    /// L1423 ("The Wallet MUST ignore any unrecognized parameters") then
    /// obliged every conformant wallet to discard it.
    #[test]
    fn credential_metadata_nests_display_and_claims() {
        let cfg = test_config();
        let meta = build_issuer_metadata(&cfg, &[]);
        let value = serde_json::to_value(&meta).expect("metadata serialises");
        let pid = &value["credential_configurations_supported"]["pid"];

        assert_eq!(
            pid["credential_metadata"]["display"][0]["name"],
            "Person ID"
        );
        assert_eq!(
            pid["credential_metadata"]["claims"][0]["path"],
            serde_json::json!(["given_name"])
        );

        // The load-bearing half. A wallet is obliged to ignore the flat
        // members, so their presence is invisible to any positive assertion --
        // which is exactly how the original defect survived.
        assert!(
            pid.get("display").is_none(),
            "flat `display` is the pre-1.0 draft shape and must not be emitted"
        );
        assert!(
            pid.get("claims").is_none(),
            "flat `claims` is the pre-1.0 draft shape and must not be emitted"
        );
    }

    /// L1400 is OPTIONAL. A credential type with neither display nor claims
    /// must emit no `credential_metadata` key at all -- an empty object is not
    /// "information relevant to the usage and display of issued Credentials",
    /// and emitting one would trade this defect for a smaller one.
    #[test]
    fn credential_metadata_is_absent_when_neither_display_nor_claims_configured() {
        let mut cfg = test_config();
        cfg.credential_types[0].display = vec![];
        cfg.credential_types[0].claims = vec![];
        let meta = build_issuer_metadata(&cfg, &[]);
        let value = serde_json::to_value(&meta).expect("metadata serialises");
        let pid = &value["credential_configurations_supported"]["pid"];

        assert!(
            pid.get("credential_metadata").is_none(),
            "expected no credential_metadata key, got {:?}",
            pid.get("credential_metadata")
        );
    }

    /// L2321-L2338 defines a claims description object for Issuer Metadata as
    /// exactly `path`, `mandatory` and `display`. `selectively_disclosable` is
    /// a foundry config field name, never an OpenID4VCI parameter, and conveys
    /// nothing a wallet can use at either format.
    #[test]
    fn claims_description_emits_mandatory_and_not_selectively_disclosable() {
        let mut cfg = test_config();
        cfg.credential_types[0].claims = vec![
            ClaimDef {
                path: vec!["age_over_18".to_string()],
                required: Some(true),
                selectively_disclosable: false,
                display: vec![],
            },
            ClaimDef {
                path: vec!["age_over_16".to_string()],
                required: Some(false),
                selectively_disclosable: false,
                display: vec![],
            },
        ];
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let claims = &pid
            .credential_metadata
            .as_ref()
            .expect("claims are configured, so credential_metadata is present")
            .claims;

        // L2326/L2327: `mandatory` mirrors ClaimDef::is_required().
        assert_eq!(claims[0]["mandatory"], serde_json::json!(true));
        assert_eq!(claims[1]["mandatory"], serde_json::json!(false));

        for claim in claims {
            assert!(
                claim.get("selectively_disclosable").is_none(),
                "selectively_disclosable is not an OpenID4VCI claims-description \
                 parameter"
            );
        }
    }

    /// L2332: claims description `display` is "a non-empty array of objects"
    /// when present. The old `json!` macro had no `skip_serializing_if`, so a
    /// claim with no configured display emitted `"display": []`.
    #[test]
    fn claims_description_omits_display_when_none_configured() {
        let cfg = test_config();
        let meta = build_issuer_metadata(&cfg, &[]);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let claims = &pid
            .credential_metadata
            .as_ref()
            .expect("claims are configured, so credential_metadata is present")
            .claims;

        assert!(
            claims[0].get("display").is_none(),
            "expected no display member, got {:?}",
            claims[0].get("display")
        );
    }

    /// PaSO Proof Metadata §2: a PaSO Credential configuration SHALL carry a
    /// `credential_metadata_uri`, built from the same base as every sibling
    /// endpoint so §8's URI-binding check can succeed.
    #[test]
    fn a_paso_credential_configuration_advertises_its_metadata_uri() {
        let mut cfg = test_config();
        let types = serde_json::from_value(serde_json::json!({
            "urn:paso:sca:global:payment:1": {
                "claims": [{ "path": ["amount"], "display": [{ "name": "Amount" }] }]
            }
        }))
        .expect("fixture");
        if let Some(ct) = cfg.credential_types.first_mut() {
            ct.transaction_data_types = Some(types);
        }
        let first_id = cfg
            .credential_types
            .first()
            .map(|c| c.id.clone())
            .expect("at least one credential type");

        let md = build_issuer_metadata(&cfg, &[]);
        let entry = md
            .credential_configurations_supported
            .get(&first_id)
            .expect("configuration present");

        assert_eq!(
            entry.credential_metadata_uri,
            Some(format!(
                "https://issuer.example.com/credential-metadata/{first_id}"
            ))
        );
    }

    /// A non-PaSO configuration must not advertise the URI: the route 404s for
    /// it, and §3 makes `transaction_data_types` REQUIRED in what it serves.
    /// Asserted on the serialised keys, because a `null` would pass a weaker
    /// `Option` check while still changing the wire output.
    #[test]
    fn a_non_paso_credential_configuration_omits_the_metadata_uri_key() {
        let cfg = test_config();
        let md = build_issuer_metadata(&cfg, &[]);
        let json = serde_json::to_value(&md).expect("serialize");

        let configs = json["credential_configurations_supported"]
            .as_object()
            .expect("configurations object");
        assert!(!configs.is_empty(), "fixture must have configurations");
        for (id, entry) in configs {
            assert!(
                entry.get("credential_metadata_uri").is_none(),
                "non-PaSO configuration '{id}' must not emit credential_metadata_uri"
            );
        }
    }
}
