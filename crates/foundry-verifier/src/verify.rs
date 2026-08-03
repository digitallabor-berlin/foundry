use crate::dcql::{check_dcql_match, PresentedFormat};
use crate::dcql_model::{CredentialFormat, DcqlQuery};
use crate::error::VerificationError;
use crate::request::verifier_x5c_leaf_pem;
use crate::status::{check_status, StatusListResolver};
use crate::transaction::{
    CheckResult, VerificationResult, VerificationState, VerificationTransaction,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::config::Config;
use foundry_core::trust::TrustStore;
use foundry_mdoc::types::{build_session_transcript, SessionTranscriptParams};
use josekit::jwk::Jwk;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The single presentation selected from a `vp_token`, already destructured
/// according to the credential format the DCQL query declared.
///
/// Carrying the typed payload — rather than a `&Value` plus a format tag — keeps
/// every shape check inside `select_presentation`, so the verification arms
/// cannot re-derive the format or trip over an "impossible" type error.
#[derive(Debug)]
enum SelectedPresentation<'a> {
    SdJwtVc(&'a str),
    /// **Non-conformant payload, deliberately retained.** OpenID4VP Annex B
    /// requires a base64url ISO 18013-5 `DeviceResponse` carrying `deviceSigned`
    /// inside each document. This split envelope is what `verify_mdoc` consumes
    /// today, so mdoc is **not** interoperable with real wallets: the envelope
    /// is now conformant, the payload is not. See spec defects 2-3.
    MsoMdoc {
        mdoc_b64: &'a str,
        device_signature_b64: &'a str,
    },
}

impl SelectedPresentation<'_> {
    fn format(&self) -> PresentedFormat {
        match self {
            Self::SdJwtVc(_) => PresentedFormat::SdJwtVc,
            Self::MsoMdoc { .. } => PresentedFormat::MsoMdoc,
        }
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Select the one presentation to verify from an OpenID4VP 1.0 section 8.1
/// `vp_token`.
///
/// `vp_token` is a JSON object keyed by DCQL credential query id whose values are
/// **arrays** of presentations — the same shape for every credential format. The
/// format therefore *cannot* be read off the JSON type of the payload; it is
/// whatever the answered credential query declared. Inferring it from the shape
/// is exactly what made a conformant SD-JWT VC presentation report the
/// misleading `mdoc vp_token missing 'mdoc'`.
///
/// Returns the answered credential query id with the destructured payload. Every
/// failure here is structural (HTTP 400), never a policy verdict.
fn select_presentation<'a>(
    vp_token: &'a Value,
    dcql_query: &Value,
) -> Result<(String, SelectedPresentation<'a>), VerificationError> {
    let entries = vp_token.as_object().ok_or_else(|| {
        VerificationError::Failed(format!(
            "vp_token must be a JSON object keyed by DCQL credential query id \
             (OpenID4VP 1.0 section 8.1), got {}",
            json_type_name(vp_token)
        ))
    })?;

    // The declared format is the only trustworthy source of the credential
    // format, so an unusable dcql_query is fatal rather than a failed check.
    let query: DcqlQuery = serde_json::from_value(dcql_query.clone()).map_err(|e| {
        VerificationError::Failed(format!(
            "cannot determine the requested credential format: this transaction's \
             dcql_query is not a valid DCQL query: {e}"
        ))
    })?;

    let mut answering = query
        .credentials()
        .iter()
        .filter(|cq| entries.contains_key(cq.id()));
    let cq = match (answering.next(), answering.next()) {
        (Some(cq), None) => cq,
        (None, _) => {
            let received: Vec<&str> = entries.keys().map(String::as_str).collect();
            let expected: Vec<&str> = query.credentials().iter().map(|c| c.id()).collect();
            return Err(VerificationError::Failed(format!(
                "vp_token names no credential query from this request: got [{}], \
                 expected one of [{}]",
                received.join(", "),
                expected.join(", ")
            )));
        }
        (Some(_), Some(_)) => {
            let matched: Vec<&str> = query
                .credentials()
                .iter()
                .filter(|c| entries.contains_key(c.id()))
                .map(|c| c.id())
                .collect();
            return Err(VerificationError::Failed(format!(
                "vp_token answers several credential queries ([{}]); this verifier \
                 verifies a single credential per vp_token",
                matched.join(", ")
            )));
        }
    };

    let value = entries.get(cq.id()).unwrap_or(&Value::Null);
    let presentations = value.as_array().ok_or_else(|| {
        VerificationError::Failed(format!(
            "vp_token['{}'] must be an array of presentations \
             (OpenID4VP 1.0 section 8.1), got {}",
            cq.id(),
            json_type_name(value)
        ))
    })?;

    // Exactly one: silently taking [0] of a longer array would verify part of a
    // presentation set while reporting the whole set as satisfied.
    let presentation = match presentations.as_slice() {
        [single] => single,
        other => {
            return Err(VerificationError::Failed(format!(
                "vp_token['{}'] must contain exactly one presentation, got {}",
                cq.id(),
                other.len()
            )))
        }
    };

    let selected = match cq.format() {
        CredentialFormat::DcSdJwt => {
            SelectedPresentation::SdJwtVc(presentation.as_str().ok_or_else(|| {
                VerificationError::Failed(format!(
                    "credential query '{}' declares format dc+sd-jwt, so its \
                     presentation must be an SD-JWT VC string, got {}",
                    cq.id(),
                    json_type_name(presentation)
                ))
            })?)
        }
        CredentialFormat::MsoMdoc => {
            let obj = presentation.as_object().ok_or_else(|| {
                VerificationError::Failed(format!(
                    "credential query '{}' declares format mso_mdoc, so its \
                     presentation must be an object, got {}",
                    cq.id(),
                    json_type_name(presentation)
                ))
            })?;
            let mdoc_b64 = obj.get("mdoc").and_then(|v| v.as_str()).ok_or_else(|| {
                VerificationError::Failed(format!(
                    "mdoc presentation for credential query '{}' is missing 'mdoc'",
                    cq.id()
                ))
            })?;
            let device_signature_b64 = obj
                .get("device_signature")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VerificationError::Failed(format!(
                        "mdoc presentation for credential query '{}' is missing \
                         'device_signature'",
                        cq.id()
                    ))
                })?;
            SelectedPresentation::MsoMdoc {
                mdoc_b64,
                device_signature_b64,
            }
        }
        // `CredentialFormat::Other` exists so that an unimplemented format inside a
        // multi-credential query simply fails to match rather than invalidating the
        // whole query (see `dcql_model`). Once a wallet has *answered* such a query
        // there is nothing to fall back to: no verifier for the format exists, so
        // this is a request the verifier cannot service.
        CredentialFormat::Other(other) => {
            return Err(VerificationError::Failed(format!(
                "credential query '{}' requests credential format '{}', which this \
                 verifier does not implement",
                cq.id(),
                other
            )))
        }
    };

    Ok((cq.id().to_string(), selected))
}

/// `skip_all` is mandatory here, not stylistic: the default `instrument`
/// behaviour `Debug`-formats every argument, which would write `Config` and
/// `VerificationTransaction` — the latter holding `ephem_private_jwk` — plus the
/// raw JWE straight into the log. Fields are opt-in, always.
#[tracing::instrument(
    skip_all,
    fields(tx_id = %tx.id, transport = %tx.transport, jwe_len = encrypted_jwe_str.len())
)]
pub async fn verify_vp_response(
    config: &Config,
    tx: &mut VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
) -> Result<VerificationResult, VerificationError> {
    tracing::info!("verifying vp response");

    // Payload access is doubly gated: the explicit dev-only flag AND a
    // debug/trace level. Either alone is insufficient authorisation.
    if foundry_core::obs::sensitive_enabled() {
        tracing::debug!(
            vp_response_jwe = %encrypted_jwe_str,
            "SENSITIVE: raw encrypted response"
        );
    }

    match do_verify_vp_response(config, tx, encrypted_jwe_str, resolver).await {
        Ok(result) => {
            tx.state = if result.verified {
                VerificationState::Verified
            } else {
                VerificationState::Failed
            };

            // One record per check, so an operator can see which stage rejected a
            // presentation without reading the JSON verdict.
            for check in &result.checks {
                if check.passed {
                    tracing::info!(check = %check.check, passed = true, "verification check");
                } else {
                    tracing::warn!(
                        check = %check.check,
                        passed = false,
                        detail = %check.detail.as_deref().unwrap_or(""),
                        "verification check failed"
                    );
                }
            }

            // A policy failure (DCQL mismatch, revoked credential) is a 200 with
            // verified: false, so `warn` — not `error` — is the right level: the
            // service behaved correctly.
            if result.verified {
                tracing::info!(verified = true, "vp response verified");
            } else {
                tracing::warn!(
                    verified = false,
                    failed_checks = result.checks.iter().filter(|c| !c.passed).count(),
                    "vp response not verified"
                );
            }

            tx.result = Some(result.clone());
            Ok(result)
        }
        Err(err) => {
            tx.state = VerificationState::Failed;

            // Record *why*. Previously this arm set the state and dropped the
            // reason on the floor: the detail existed only inside `err`, which
            // the HTTP layer turned into a 400 body for the wallet. An operator
            // watching the admin console saw a bare red "failed" with no
            // explanation, because the console renders its checks list only when
            // `tx.result` is present.
            //
            // `verified` stays derived — one check, not passed — so the
            // invariant `verified == checks.iter().all(|c| c.passed)` holds
            // (root AGENTS.md §4.2).
            let checks = vec![CheckResult {
                check: check_name_for(&err).to_string(),
                passed: false,
                detail: Some(foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX)),
            }];
            tx.result = Some(VerificationResult {
                verified: checks.iter().all(|c| c.passed),
                checks,
                claims: serde_json::Value::Null,
            });

            tracing::warn!(
                tx_id = %tx.id,
                error.kind = err.kind(),
                error.detail = %foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX),
                check = check_name_for(&err),
                "vp response verification failed"
            );

            Err(err)
        }
    }
}

/// Cap on the `detail` string persisted into `tx.result` and logged.
///
/// This value is served over the admin API and rendered in a browser, so it is
/// bounded rather than trusted to be short.
const DETAIL_MAX: usize = 512;

/// The verification stage that aborted, named to match the `CheckResult` names
/// the success path already produces.
///
/// Using the same vocabulary matters: the console renders whatever check names it
/// is given, so a failure should appear in the same list position an operator
/// already knows how to read.
///
/// Exhaustive with no catch-all: a new error variant should be a deliberate
/// decision about which stage it belongs to, not a silent fallthrough.
fn check_name_for(err: &VerificationError) -> &'static str {
    match err {
        VerificationError::Decryption(_) => "jwe_decryption",
        VerificationError::StatusUnavailable(_) => "status_check",
        VerificationError::Dcql(_) => "dcql_match",
        VerificationError::NotFound(_)
        | VerificationError::InvalidState(_)
        | VerificationError::InvalidRequest(_)
        | VerificationError::Crypto(_)
        | VerificationError::Failed(_)
        | VerificationError::Storage(_)
        | VerificationError::CoreCrypto(_)
        | VerificationError::Trust(_)
        | VerificationError::Serialization(_) => "verification_error",
    }
}

/// OpenID4VP 1.0 Response / VP Token Validation (L1523): Verifiers MUST check that
/// the set of Presentations satisfies all requirements of the request. When the
/// request carried `transaction_data`, the IETF SD-JWT VC profile binds it to the
/// presentation through the KB-JWT's `transaction_data_hashes` claim (L3144).
///
/// Each hash is computed over the entry **as advertised** -- the base64url string
/// itself, with no decoding first (L3144). The algorithm must be one the request
/// advertised, defaulting to `sha-256` when it advertised none (L3142).
///
/// A missing or non-matching binding is a **policy** outcome, not a structural
/// error: it records `passed: false`, which makes `verified` false by AGENTS.md
/// §4.2, and the response stays HTTP 200 per §4.3. Never returns `Err`.
fn check_transaction_data_binding(
    requested_entries: &[String],
    answered_query_id: &str,
    kb_payload: &Value,
) -> CheckResult {
    const CHECK: &str = "transaction_data_binding";

    // Step 1: keep only the entries scoped to the credential query this
    // presentation answered. An entry produced by anything other than
    // `encode_transaction_data` (request.rs) -- i.e. malformed -- should never
    // reach this point, so failing loudly here rather than ignoring it is
    // deliberate.
    let mut applicable: Vec<(usize, String, Vec<String>)> = Vec::new();
    for (i, encoded) in requested_entries.iter().enumerate() {
        let decoded = match B64URL.decode(encoded) {
            Ok(bytes) => bytes,
            Err(e) => {
                return CheckResult {
                    check: CHECK.to_string(),
                    passed: false,
                    detail: Some(format!("transaction_data[{i}] is not valid base64url: {e}")),
                };
            }
        };
        let entry: Value = match serde_json::from_slice(&decoded) {
            Ok(v) => v,
            Err(e) => {
                return CheckResult {
                    check: CHECK.to_string(),
                    passed: false,
                    detail: Some(format!("transaction_data[{i}] is not valid JSON: {e}")),
                };
            }
        };
        let credential_ids: Vec<&str> = entry
            .get("credential_ids")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if !credential_ids.contains(&answered_query_id) {
            // Scoped to a different credential query; imposes nothing here.
            continue;
        }
        let advertised_algs: Vec<String> = entry
            .get("transaction_data_hashes_alg")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        applicable.push((i, encoded.clone(), advertised_algs));
    }

    if applicable.is_empty() {
        return CheckResult {
            check: CHECK.to_string(),
            passed: true,
            detail: Some(
                "no transaction_data entries scoped to the answered credential query".to_string(),
            ),
        };
    }

    // Step 2: the presentation must carry a non-empty transaction_data_hashes.
    let claimed_hashes: Vec<&str> = match kb_payload
        .get("transaction_data_hashes")
        .and_then(|v| v.as_array())
    {
        Some(arr) if !arr.is_empty() => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => {
            return CheckResult {
                check: CHECK.to_string(),
                passed: false,
                detail: Some("presentation carries no transaction_data_hashes".to_string()),
            };
        }
    };

    // Step 3: resolve the algorithm (L3142 default: sha-256). Only sha-256 is
    // implemented, regardless of what the request advertised or permitted.
    let claimed_alg = kb_payload
        .get("transaction_data_hashes_alg")
        .and_then(|v| v.as_str())
        .unwrap_or("sha-256");
    if claimed_alg != "sha-256" {
        return CheckResult {
            check: CHECK.to_string(),
            passed: false,
            detail: Some(format!(
                "transaction_data_hashes_alg '{claimed_alg}' is not supported; only sha-256 is \
                 implemented"
            )),
        };
    }
    for (i, _, advertised_algs) in &applicable {
        if !advertised_algs.is_empty() && !advertised_algs.iter().any(|a| a == claimed_alg) {
            return CheckResult {
                check: CHECK.to_string(),
                passed: false,
                detail: Some(format!(
                    "transaction_data[{i}] does not advertise the algorithm the presentation used"
                )),
            };
        }
    }

    // Step 4: every applicable entry must be hashed (as advertised, undecoded)
    // into the claimed set.
    let mut first_mismatch: Option<usize> = None;
    for (i, encoded, _) in &applicable {
        let hash = B64URL.encode(Sha256::digest(encoded.as_bytes()));
        if !claimed_hashes.contains(&hash.as_str()) {
            first_mismatch = Some(*i);
            break;
        }
    }

    match first_mismatch {
        None => CheckResult {
            check: CHECK.to_string(),
            passed: true,
            detail: Some(format!(
                "{} applicable transaction_data entry(ies) bound",
                applicable.len()
            )),
        },
        Some(i) => CheckResult {
            check: CHECK.to_string(),
            passed: false,
            detail: Some(format!(
                "transaction_data[{i}] hash is not present in transaction_data_hashes"
            )),
        },
    }
}

#[tracing::instrument(skip_all)]
async fn do_verify_vp_response(
    config: &Config,
    tx: &VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
) -> Result<VerificationResult, VerificationError> {
    // 1. JWE Decryption
    let jwk_str = serde_json::to_string(&tx.ephem_private_jwk)
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;
    let ephem_jwk = Jwk::from_bytes(jwk_str.as_bytes())
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    let decrypter = josekit::jwe::ECDH_ES
        .decrypter_from_jwk(&ephem_jwk)
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    let (jwt_payload, _header) = josekit::jwt::decode_with_decrypter(encrypted_jwe_str, &decrypter)
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    let response_json = serde_json::to_value(jwt_payload.claims_set())
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    tracing::debug!(step = "jwe_decryption", "response decrypted");
    if foundry_core::obs::sensitive_enabled() {
        tracing::trace!(
            decrypted_response = %response_json,
            "SENSITIVE: decrypted response payload"
        );
    }

    let mut checks = vec![CheckResult {
        check: "jwe_decryption".to_string(),
        passed: true,
        detail: None,
    }];

    // 2. vp_token Extraction & Verification
    let vp_token = response_json.get("vp_token").ok_or_else(|| {
        VerificationError::Failed("missing vp_token in response payload".to_string())
    })?;

    let trust_store = TrustStore::from_config(&config.trust_anchors)?;

    let base_url = config
        .server
        .wallet_facing
        .public_base_url
        .trim_end_matches('/');

    // HAIP OpenID4VP L256 / OpenID4VP L616: the Client Identifier is
    // `x509_hash:<base64url(SHA-256(DER leaf))>`. A wallet binds its KB-JWT `aud`
    // to the Client Identifier it received, so this MUST be computed by the same
    // helper `build_signed_request_object` (request.rs) uses -- if the two ever
    // diverge, every redirect-transport presentation fails as a policy verdict
    // rather than a visible error.
    let leaf_pem = verifier_x5c_leaf_pem(config)?;
    let client_id = crate::request::x509_hash_client_id(&leaf_pem)?;

    // OpenID4VP L2543 / IETF SD-JWT VC Presentation Response L3179: over the
    // DC API transport the KB-JWT `aud` MUST be the Origin prefixed with
    // `origin:`, not the `x509_hash:<hash>` Client Identifier used by
    // every other transport. The Origin is a browsing-context property
    // (RFC 6454) this server cannot derive on its own, so it is read from
    // `verifier.dc_api_expected_origins` when configured; an unconfigured
    // deployment falls back to a single origin derived from
    // `public_base_url`, which keeps existing single-origin dev/test setups
    // working without requiring the new config field.
    let expected_audiences: Vec<String> = if tx.transport == "dc_api" {
        if config.verifier.dc_api_expected_origins.is_empty() {
            let fallback = format!("origin:{base_url}");
            tracing::debug!(
                fallback_origin = %fallback,
                "verifier.dc_api_expected_origins is unset; falling back to an origin derived \
                 from public_base_url"
            );
            vec![fallback]
        } else {
            config
                .verifier
                .dc_api_expected_origins
                .iter()
                .map(|origin| format!("origin:{origin}"))
                .collect()
        }
    } else {
        vec![client_id.clone()]
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| VerificationError::Crypto(e.to_string()))?
        .as_secs();

    // 3. Credential-format-specific signature/binding verification + disclosure.
    //    The format is taken from the answered DCQL credential query, never
    //    inferred from the shape of the payload.
    let (answered_query_id, selected) = select_presentation(vp_token, &tx.dcql_query)?;
    let presented_format = selected.format();
    let mut disclosed_claims = serde_json::Map::new();
    // Populated only for SD-JWT VC presentations, whose Key Binding JWT carries
    // `transaction_data_hashes` (L3144). An mdoc presentation has no KB-JWT, so
    // this stays `None` for that format -- checked below.
    let mut kb_jwt_payload: Option<Value> = None;

    let doc_type: Option<String> = match selected {
        SelectedPresentation::SdJwtVc(jwt_str) => {
            let verified = foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc(
                jwt_str,
                &trust_store,
                &expected_audiences,
                &tx.nonce,
                now_unix,
            )
            .map_err(|e| VerificationError::Failed(e.to_string()))?;

            checks.push(CheckResult {
                check: "sd_jwt_vc_signature_and_kb_jwt".to_string(),
                passed: true,
                detail: None,
            });

            kb_jwt_payload = Some(verified.kb_jwt_payload);
            if let Value::Object(map) = verified.claims {
                for (k, v) in map {
                    disclosed_claims.insert(k, v);
                }
            }
            None
        }
        SelectedPresentation::MsoMdoc {
            mdoc_b64,
            device_signature_b64,
        } => {
            let mdoc_bytes = B64URL
                .decode(mdoc_b64)
                .map_err(|e| VerificationError::Failed(format!("mdoc base64 decode: {e}")))?;
            let dev_sig_bytes = B64URL.decode(device_signature_b64).map_err(|e| {
                VerificationError::Failed(format!("device_signature base64 decode: {e}"))
            })?;

            // OpenID4VP L2870 (redirects) / L2999 (DC API): the third
            // `…HandoverInfo` element is the RFC 7638 thumbprint of the
            // Verifier's response-encryption public key when the response is
            // encrypted, and CBOR `null` when it is not. An unrecognised
            // Response Mode is an error rather than a silent `None`: guessing
            // would build a transcript that fails to verify for a reason no
            // operator could diagnose.
            let jwk_thumbprint: Option<[u8; 32]> = match tx.response_mode.as_str() {
                "dc_api.jwt" | "direct_post.jwt" => Some(
                    foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).map_err(|e| {
                        VerificationError::Failed(format!(
                            "cannot compute the response-encryption key thumbprint: {e}"
                        ))
                    })?,
                ),
                "dc_api" | "direct_post" => None,
                other => {
                    return Err(VerificationError::Failed(format!(
                        "unsupported response_mode for the mdoc SessionTranscript: {other}"
                    )))
                }
            };

            // The invocation method selects the Handover structure: the DC API
            // binds to the request's Origin (L2959-L2999), every other
            // transport binds to the Client Identifier and response URI
            // (L2829-L2873). Building the wrong one yields a transcript no
            // conformant wallet's Device Signature can verify against.
            //
            // The Origin sits *inside* the hashed `OpenID4VPDCAPIHandoverInfo`,
            // so unlike the KB-JWT audience above — which is compared against a
            // list — the verifier cannot compare here. It must *pick* an Origin
            // before it can verify anything, and a deployment may legitimately
            // serve several. Each configured Origin therefore yields a
            // candidate transcript, and the Device Signature decides which one
            // the wallet actually used.
            let candidates: Vec<SessionTranscriptParams> = if tx.transport == "dc_api" {
                let origins: Vec<String> = if config.verifier.dc_api_expected_origins.is_empty() {
                    vec![base_url.to_string()]
                } else {
                    config.verifier.dc_api_expected_origins.clone()
                };
                origins
                    .into_iter()
                    // L2997: the Origin element MUST NOT carry the `origin:`
                    // prefix. That prefix belongs to the KB-JWT audience — a
                    // different mechanism that happens to name the same value.
                    .map(|origin| SessionTranscriptParams::DcApi {
                        origin,
                        nonce: tx.nonce.clone(),
                        jwk_thumbprint,
                    })
                    .collect()
            } else {
                vec![SessionTranscriptParams::Redirect {
                    client_id: client_id.clone(),
                    nonce: tx.nonce.clone(),
                    jwk_thumbprint,
                    response_uri: format!("{base_url}/vp/response/{}", tx.id),
                }]
            };

            let mut accepted = None;
            let mut last_err = None;
            for params in &candidates {
                let session_transcript = build_session_transcript(params)
                    .map_err(|e| VerificationError::Failed(format!("SessionTranscript: {e}")))?;
                match foundry_mdoc::verifier::verify_mdoc(
                    &mdoc_bytes,
                    &trust_store,
                    &session_transcript,
                    &dev_sig_bytes,
                    now_unix,
                ) {
                    Ok(res) => {
                        accepted = Some(res);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(VerificationError::Failed(format!(
                            "mdoc verification failed: {e}"
                        )))
                    }
                }
            }

            // `candidates` is never empty, so `last_err` is always populated on
            // the failure path. The fallback message exists only so that this
            // cannot become a panic if that ever stops holding.
            let mdoc_res = match accepted {
                Some(res) => res,
                None => {
                    return Err(last_err.unwrap_or_else(|| {
                        VerificationError::Failed(
                            "mdoc verification failed: no SessionTranscript candidate".to_string(),
                        )
                    }))
                }
            };

            checks.push(CheckResult {
                check: "mdoc_issuer_auth_and_device_signature".to_string(),
                passed: true,
                detail: None,
            });

            for (ns, elements) in mdoc_res.claims {
                let mut ns_obj = serde_json::Map::new();
                for (k, v) in elements {
                    ns_obj.insert(k, v);
                }
                disclosed_claims.insert(ns, Value::Object(ns_obj));
            }
            Some(mdoc_res.doc_type)
        }
    };

    let claims_value = Value::Object(disclosed_claims);

    // 3b. Transaction Data binding (OpenID4VP L1523/L3144), only when the
    // Verifier actually requested transaction_data for this transaction.
    if let Some(ref entries) = tx.transaction_data {
        match &kb_jwt_payload {
            Some(kb_payload) => {
                checks.push(check_transaction_data_binding(
                    entries,
                    &answered_query_id,
                    kb_payload,
                ));
            }
            // mdoc: no KB-JWT exists to carry the binding. The Verifier asked
            // for one it cannot confirm, so this must not report success.
            None => {
                checks.push(CheckResult {
                    check: "transaction_data_binding".to_string(),
                    passed: false,
                    detail: Some("mdoc transaction_data binding is not implemented".to_string()),
                });
            }
        }
    }

    // 4. DCQL query satisfaction (shared across credential formats).
    checks.push(check_dcql_match(
        &tx.dcql_query,
        &answered_query_id,
        presented_format,
        &claims_value,
        doc_type.as_deref(),
    ));

    // 5. Token Status List revocation check (shared across credential formats).
    //    A network failure fetching the token propagates as a hard error.
    checks.push(check_status(&claims_value, &trust_store, resolver, now_unix).await?);

    // 6. Overall verdict is the AND of every check performed.
    let verified = checks.iter().all(|c| c.passed);
    Ok(VerificationResult {
        verified,
        checks,
        claims: claims_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::test_support::MockResolver;
    use crate::transaction::VerificationState;
    use foundry_core::config::{
        AdminConfig, AttestationMode, Config, DpopConfig, IssuerConfig, KeyEntry, LoggingConfig,
        Mode, ServerConfig, StatusListConfig, StorageConfig, TrustAnchor, VerifierConfig,
        WalletFacingConfig,
    };
    use foundry_core::crypto::jwe::encrypt_compact;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_mdoc::builder::{build_mdoc, MdocClaims};
    use foundry_sd_jwt_vc::builder::{
        attach_kb_jwt, build_sd_jwt_vc, IssuerClaims, TransactionDataBinding,
    };
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &root.cert_pem,
            &root.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        (
            root.cert_pem.into_bytes(),
            leaf.cert_pem.into_bytes(),
            leaf.key_pem.into_bytes(),
        )
    }

    fn holder() -> (FileSigner, serde_json::Value) {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        let signer =
            FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
        let pubjwk = signer.public_jwk().unwrap();
        (signer, pubjwk)
    }

    fn der_b64(pem_bytes: &[u8]) -> String {
        std::str::from_utf8(pem_bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    }

    /// The Client Identifier a wallet would have received for this fixture.
    /// Computed, never hardcoded: a literal would silently diverge if the fixture
    /// certificate is regenerated.
    fn expected_client_id(config: &Config) -> String {
        let leaf_pem = crate::request::verifier_x5c_leaf_pem(config).unwrap();
        crate::request::x509_hash_client_id(&leaf_pem).unwrap()
    }

    fn test_config(ca_pem: &str) -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("root.pem");
        std::fs::write(&cert_path, ca_pem).unwrap();

        // The verifier's own x509_hash leaf certificate (HAIP OpenID4VP L256),
        // independent of the trust_anchors CA above: do_verify_vp_response never
        // cross-checks it against trust_anchors, only against the dNSName SAN vs.
        // public_base_url's host (build_signed_request_object does the equivalent
        // check when emitting a request). SAN "localhost" matches this fixture's
        // public_base_url below.
        let verifier_ca = new_ca("Foundry Test Verifier Root", 3650).unwrap();
        let verifier_leaf = issue_leaf(
            &verifier_ca.cert_pem,
            &verifier_ca.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        let verifier_leaf_path = dir.path().join("verifier_leaf.pem");
        std::fs::write(&verifier_leaf_path, verifier_leaf.cert_pem.as_bytes()).unwrap();

        let mut keys = BTreeMap::new();
        keys.insert(
            "verifier_key".to_string(),
            KeyEntry {
                // Never read by do_verify_vp_response (which only reads x5c); a
                // placeholder is sufficient here.
                private_key: "/dev/null".to_string(),
                x5c: Some(verifier_leaf_path.to_str().unwrap().to_string()),
                alg: "ES256".to_string(),
            },
        );

        let config = Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://localhost:8443".to_string(),
                    bind: "127.0.0.1:8443".to_string(),
                    swagger_ui_enabled: true,
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:8444".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                    console_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "test.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys,
            trust_anchors: vec![TrustAnchor {
                name: "test_ca".to_string(),
                certs: cert_path.to_str().unwrap().to_string(),
            }],
            issuer: IssuerConfig {
                credential_issuer: "https://localhost:8443".to_string(),
                wallet_attestation: AttestationMode {
                    mode: Mode::Disabled,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                },
                key_attestation: AttestationMode {
                    mode: Mode::Disabled,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: None,
                    list_size: Some(131072),
                    public_base_url: None,
                },
                dpop: DpopConfig::default(),
            },
            credential_types: vec![],
            verifier: VerifierConfig {
                signing_key: "verifier_key".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec![],
                named_queries: vec![],
                webhook: None,
                // Only `gap_vp_07_...` exercises the `dc_api` transport in
                // this file; every other test here uses `direct_post` (see
                // `sample_tx`), so this default is inert for them.
                dc_api_expected_origins: vec!["https://verifier-website.example".to_string()],
            },
            logging: LoggingConfig::default(),
        };
        (config, dir)
    }

    fn sample_tx() -> (VerificationTransaction, Jwk) {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let public_jwk = keypair.to_jwk_public_key();
        let private_jwk = keypair.to_jwk_private_key();

        let ephem_public_json = serde_json::to_value(&public_jwk).unwrap();
        let ephem_private_json = serde_json::to_value(&private_jwk).unwrap();

        let tx = VerificationTransaction {
            id: "vtx-test-123".to_string(),
            state: VerificationState::Pending,
            nonce: "nonce-99999".to_string(),
            dcql_query: serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            }),
            transport: "direct_post".to_string(),
            response_mode: "direct_post.jwt".to_string(),
            ephem_private_jwk: ephem_private_json,
            ephem_public_jwk: ephem_public_json,
            transaction_data: None,
            result: None,
            created_at: 1_700_000_000,
        };
        (tx, public_jwk)
    }

    #[tokio::test]
    async fn test_verify_vp_response_sd_jwt_vc() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();

        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };

        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let client_id = expected_client_id(&config);
        let presentation =
            attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &tx.nonce, None).unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(res.verified);
        assert_eq!(tx.state, VerificationState::Verified);
        assert_eq!(res.claims["given_name"], "Alice");
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "jwe_decryption" && c.passed));
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "sd_jwt_vc_signature_and_kb_jwt" && c.passed));
    }

    /// VP-0125 (OpenID4VP 1.0 Response / Response Parameters, L1172): the
    /// Client MUST ignore any unrecognized response parameters.
    /// `do_verify_vp_response` reads only `vp_token` out of the decrypted JWE
    /// payload; any other top-level member is never inspected, so a response
    /// carrying an unrecognized parameter alongside a valid `vp_token` must
    /// verify identically to one without it.
    #[tokio::test]
    async fn vp_0125_unrecognized_response_parameters_are_ignored() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            None,
        )
        .unwrap();

        // `code`, `iss`, and a made-up future parameter alongside `vp_token`.
        let jwe_str = encrypt_compact(
            &serde_json::json!({
                "vp_token": { "c1": [presentation] },
                "code": "unused-by-this-verifier",
                "iss": "https://verifier.example.com",
                "some_future_response_parameter": { "nested": true }
            }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            res.verified,
            "unrecognized response parameters must not affect verification: checks={:?}",
            res.checks
        );
    }

    /// GAP-VP-04 -- OpenID4VP 1.0 Response / VP Token Validation (L1523),
    /// Format / IETF SD-JWT VC / Transaction Data (L3144): Verifiers MUST
    /// check that the set of Presentations satisfies all requirements of the
    /// Verifier's request (VP-0153), which includes any `transaction_data`
    /// the Verifier itself requested (VP-0019/VP-0020, conforming --
    /// `encode_transaction_data` validates and advertises it). The SD-JWT VC
    /// profile of Transaction Data binds the request to the presentation via
    /// a `transaction_data_hashes` claim in the Key Binding JWT. Nothing in
    /// this workspace ever reads or checks that claim: `attach_kb_jwt`
    /// (foundry-sd-jwt-vc's builder) has no parameter for it at all, and
    /// `do_verify_vp_response`/`verify_sd_jwt_vc` never look for it either.
    /// A transaction is requested, but never verified to have been bound to
    /// the presentation at all.
    #[tokio::test]
    async fn gap_vp_04_transaction_data_hashes_never_validated() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        // The Verifier requested transaction_data for this transaction, per
        // the same base64url-encoded-entry shape `encode_transaction_data`
        // (request.rs) produces and persists on `VerificationTransaction`.
        let td_entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["c1"],
            "amount": 5000
        });
        let td_encoded = B64URL.encode(serde_json::to_vec(&td_entry).unwrap());
        tx.transaction_data = Some(vec![td_encoded]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // A KB-JWT built the only way this codebase can build one: with no
        // `transaction_data_hashes` claim at all, since `attach_kb_jwt` has no
        // parameter for it.
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            None,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            !res.verified,
            "a presentation with no transaction_data_hashes binding must not verify \
             when the Verifier requested transaction_data, but it did: checks={:?}",
            res.checks
        );
        assert!(
            res.checks
                .iter()
                .any(|c| c.check == "transaction_data_binding" && !c.passed),
            "the missing binding must be recorded as a failed check: {:?}",
            res.checks
        );
    }

    /// The positive counterpart to `gap_vp_04_...`: a presentation that *does* bind
    /// to the requested transaction_data must still verify. Without this, a blanket
    /// "reject whenever transaction_data was requested" implementation would pass the
    /// negative test and look correct.
    #[tokio::test]
    async fn a_correctly_bound_transaction_data_presentation_verifies() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let td_entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["c1"],
            "amount": 5000
        });
        let td_encoded = B64URL.encode(serde_json::to_vec(&td_entry).unwrap());
        tx.transaction_data = Some(vec![td_encoded.clone()]);

        // OpenID4VP L3144: hash the *string* as advertised -- no base64url decode.
        let hash = B64URL.encode(Sha256::digest(td_encoded.as_bytes()));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            Some(TransactionDataBinding {
                hashes: &[hash],
                alg: None,
            }),
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(
            res.verified,
            "a correctly bound presentation must verify: checks={:?}",
            res.checks
        );
        assert!(
            res.checks
                .iter()
                .any(|c| c.check == "transaction_data_binding" && c.passed),
            "the binding check must be recorded as passed: {:?}",
            res.checks
        );
    }

    /// A hash that corresponds to no requested entry is not a binding.
    #[tokio::test]
    async fn a_transaction_data_hash_that_matches_nothing_does_not_verify() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let td_entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["c1"],
            "amount": 5000
        });
        let td_encoded = B64URL.encode(serde_json::to_vec(&td_entry).unwrap());
        tx.transaction_data = Some(vec![td_encoded]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            Some(TransactionDataBinding {
                hashes: &["bm90LWEtcmVhbC1oYXNo".to_string()],
                alg: None,
            }),
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(!res.verified, "checks={:?}", res.checks);
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "transaction_data_binding" && !c.passed));
    }

    /// L3142: the algorithm MUST be one of the request's values. A wallet that used
    /// something else has not produced a hash this Verifier can rely on.
    #[tokio::test]
    async fn an_unadvertised_transaction_data_hashes_alg_does_not_verify() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let td_entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["c1"],
            "amount": 5000,
            "transaction_data_hashes_alg": ["sha-256"]
        });
        let td_encoded = B64URL.encode(serde_json::to_vec(&td_entry).unwrap());
        tx.transaction_data = Some(vec![td_encoded.clone()]);

        let hash = B64URL.encode(Sha256::digest(td_encoded.as_bytes()));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // The presentation declares an algorithm the request never advertised.
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            Some(TransactionDataBinding {
                hashes: &[hash],
                alg: Some("sha-512"),
            }),
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(!res.verified, "checks={:?}", res.checks);
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "transaction_data_binding" && !c.passed));
    }

    /// No transaction_data requested -> no such check exists. The common path's
    /// result shape is unchanged.
    #[tokio::test]
    async fn no_transaction_data_means_no_binding_check() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        assert!(tx.transaction_data.is_none());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            None,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(res.verified, "checks={:?}", res.checks);
        assert!(!res
            .checks
            .iter()
            .any(|c| c.check == "transaction_data_binding"));
    }

    /// HAIP-0049, HAIP-0050, HAIP-0053 (HAIP OpenID4VP, L258-259): the JWE
    /// `alg` value `ECDH-ES` with key agreement on the `P-256` curve MUST be
    /// supported; the JWE `enc` values `A128GCM` and `A256GCM` MUST be
    /// supported by Verifiers; and Verifiers MUST supply ephemeral encryption
    /// public keys specific to each Authorization Request. `sample_tx`
    /// generates a fresh P-256 `EcKeyPair` per call (HAIP-0053, HAIP-0049);
    /// `do_verify_vp_response`'s decrypter is generic over the JWE `enc`
    /// header, so a response encrypted with `A256GCM` decrypts successfully
    /// alongside the `A128GCM` default already exercised by every other test
    /// in this module (HAIP-0050).
    #[tokio::test]
    async fn haip_0049_0050_0053_ecdh_es_p256_and_a256gcm_supported() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        let (tx2, _) = sample_tx();

        // HAIP-0049: the ephemeral encryption key is always P-256.
        assert_eq!(tx.ephem_public_jwk["crv"], "P-256");
        // HAIP-0053: a fresh ephemeral key per Authorization Request.
        assert_ne!(tx.ephem_public_jwk["x"], tx2.ephem_public_jwk["x"]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            None,
        )
        .unwrap();

        // HAIP-0050: encrypt with A256GCM rather than the A128GCM default.
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A256GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            res.verified,
            "A256GCM-encrypted responses must decrypt and verify: checks={:?}",
            res.checks
        );
    }

    #[tokio::test]
    async fn test_verify_vp_response_missing_vp_token() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "other_field": "no_vp_token" }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::Failed(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }

    /// The defect this task exists to fix: the error path used to set the state
    /// and drop the reason, so the admin console showed a bare red "failed".
    #[tokio::test]
    async fn a_structural_failure_records_why_in_tx_result() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, "not.a.valid.jwe.token", &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::Decryption(_)));
        assert_eq!(tx.state, VerificationState::Failed);

        let result = tx
            .result
            .as_ref()
            .expect("the failure reason must be persisted, not discarded");
        assert!(!result.verified);
        assert_eq!(result.checks.len(), 1, "checks={:?}", result.checks);
        let check = &result.checks[0];
        assert_eq!(check.check, "jwe_decryption");
        assert!(!check.passed);
        let detail = check.detail.as_deref().expect("detail must be present");
        assert!(!detail.is_empty());

        // Root AGENTS.md §4.2: `verified` is derived, never hardcoded.
        assert_eq!(
            result.verified,
            result.checks.iter().all(|c| c.passed),
            "verified must equal the conjunction of the checks"
        );
    }

    /// A non-decryption failure lands under a generic stage name rather than
    /// being mislabelled as a decryption problem.
    #[tokio::test]
    async fn a_non_decryption_failure_uses_the_generic_check_name() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "other_field": "no_vp_token" }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let _ = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();

        let result = tx.result.as_ref().expect("failure reason persisted");
        assert_eq!(result.checks[0].check, "verification_error");
        assert!(!result.verified);
    }

    #[test]
    fn check_name_maps_each_stage_to_the_success_paths_vocabulary() {
        let s = || "x".to_string();
        assert_eq!(
            check_name_for(&VerificationError::Decryption(s())),
            "jwe_decryption"
        );
        assert_eq!(
            check_name_for(&VerificationError::StatusUnavailable(s())),
            "status_check"
        );
        assert_eq!(check_name_for(&VerificationError::Dcql(s())), "dcql_match");
        assert_eq!(
            check_name_for(&VerificationError::Crypto(s())),
            "verification_error"
        );
        assert_eq!(
            check_name_for(&VerificationError::Failed(s())),
            "verification_error"
        );
    }

    #[tokio::test]
    async fn persisted_detail_is_length_capped() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        // A pathologically long JWE yields a long error string; the persisted
        // detail is served over the admin API and rendered in a browser, so it
        // must be bounded.
        let junk = "j".repeat(DETAIL_MAX * 8);
        let resolver = MockResolver { token: None };
        let _ = verify_vp_response(&config, &mut tx, &junk, &resolver)
            .await
            .unwrap_err();

        let detail = tx.result.as_ref().unwrap().checks[0]
            .detail
            .as_deref()
            .unwrap();
        assert!(
            detail.len() <= DETAIL_MAX + 32,
            "detail was not capped: {} bytes",
            detail.len()
        );
    }

    #[tokio::test]
    async fn test_verify_vp_response_invalid_jwe() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, "not.a.valid.jwe.token", &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::Decryption(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[tokio::test]
    async fn test_verify_vp_response_kb_nonce_mismatch() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();

        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: serde_json::Map::new(),
        };

        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let client_id = expected_client_id(&config);
        // Attach KB-JWT with wrong nonce
        let presentation =
            attach_kb_jwt(issuer_pres, &holder_signer, &client_id, "wrong-nonce", None).unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::Failed(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[tokio::test]
    async fn test_verify_vp_response_dcql_vct_mismatch_is_not_verified() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        // Require a vct the credential will NOT have.
        tx.dcql_query = serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://localhost:8443/vct/OTHER"] }
            }]
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            None,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(!res.verified, "DCQL vct mismatch must not verify");
        assert_eq!(tx.state, VerificationState::Failed);
        let dcql = res.checks.iter().find(|c| c.check == "dcql_match").unwrap();
        assert!(!dcql.passed);
        // The signature check still passed and is still reported for transparency.
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "sd_jwt_vc_signature_and_kb_jwt" && c.passed));
    }

    /// VP-0175, VP-0177, VP-0179, VP-0180 -- OpenID4VP 1.0 Security /
    /// Preventing Replay (L1789-1795): the Verifier MUST verify the binding
    /// of the proof of possession (the KB-JWT) to audience and `nonce`, MUST
    /// validate that every individual Presentation is linked to the
    /// `client_id` and `nonce` of *its own* request, and MUST reject a
    /// response if any Presentation carries the wrong `nonce`. A captured
    /// presentation is bound (via the KB-JWT's `aud` and `nonce` claims) to
    /// the specific transaction it was produced for; replaying it verbatim
    /// against a second, independently-created transaction exercises
    /// exactly the attack this section defends against, distinct from
    /// `test_verify_vp_response_kb_nonce_mismatch`'s arbitrary bad-nonce
    /// case.
    #[tokio::test]
    async fn vp_0175_0177_0179_0180_presentation_replayed_against_second_transaction_is_rejected() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();

        // Transaction 1: the presentation is legitimately produced for this one.
        let (tx1, _) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx1.nonce,
            None,
        )
        .unwrap();

        // Sanity: the presentation verifies fine against the transaction it
        // was actually produced for.
        let mut tx1_for_check = tx1.clone();
        let jwe_for_tx1 = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation.clone()] } }),
            &tx1_for_check.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();
        let resolver = MockResolver { token: None };
        let ok = verify_vp_response(&config, &mut tx1_for_check, &jwe_for_tx1, &resolver)
            .await
            .unwrap();
        assert!(
            ok.verified,
            "sanity check: the presentation must verify against its own transaction"
        );

        // Transaction 2: a wholly separate request (independent nonce and
        // ephemeral encryption key), as if an attacker relayed the captured
        // presentation to a second Authorization Request.
        let keypair2 = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut tx2 = tx1.clone();
        tx2.id = "vtx-test-456".to_string();
        tx2.nonce = "nonce-replay-attempt".to_string();
        tx2.ephem_public_jwk = serde_json::to_value(keypair2.to_jwk_public_key()).unwrap();
        tx2.ephem_private_jwk = serde_json::to_value(keypair2.to_jwk_private_key()).unwrap();

        let jwe_for_tx2 = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx2.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();
        let err = verify_vp_response(&config, &mut tx2, &jwe_for_tx2, &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Failed(_)),
            "replaying a presentation bound to a different transaction's nonce \
             must be rejected: {err:?}"
        );
        assert_eq!(tx2.state, VerificationState::Failed);
    }

    /// AGENTS.md Sec4.2/Sec4.3, VP-0152 (Response / VP Token Validation,
    /// L1522): a Status List Token that cannot be fetched is a
    /// network/structural failure, not a policy verdict -- it MUST
    /// propagate as `Err`, never resolve to
    /// `Ok(VerificationResult { verified: false, .. })`. `status.rs`'s own
    /// `network_failure_is_hard_error` proves this for `check_status` in
    /// isolation; this test proves the same holds through the full
    /// `verify_vp_response` entry point, including the transaction state
    /// transition on failure.
    #[tokio::test]
    async fn vp_0152_status_endpoint_unreachable_is_a_hard_error_through_full_verification() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            // A status claim is present, so check_status must actually fetch
            // the Status List Token -- and the MockResolver below has none.
            status_list_index: Some(42),
            status_list_uri: Some("https://issuer.example/statuslists/1".to_string()),
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: serde_json::Map::new(),
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            None,
        )
        .unwrap();
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None }; // errors on fetch
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::StatusUnavailable(_)),
            "an unreachable status list endpoint must propagate as a hard error, \
             not a policy verdict: {err:?}"
        );
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[tokio::test]
    async fn test_verify_vp_response_mdoc_presentation() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        // Device (holder) key.
        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // Request an mdoc of the doctype/namespace/element we will issue.
        tx.dcql_query = serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
            }]
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build the issued mdoc.
        let mut elements = std::collections::BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        let mut namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        let mdoc_claims = MdocClaims {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces,
            device_key_jwk: d_jwk_pub,
            signed_at: (now - 100) as i64,
            valid_until: (now + 3600) as i64,
        };
        let mdoc_bytes =
            build_mdoc(mdoc_claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // Build the detached DeviceAuth COSE_Sign1 over the OpenID4VP
        // SessionTranscript. `sample_tx` uses transport `direct_post` with
        // response_mode `direct_post.jwt`, so the "Invocation via Redirects"
        // Handover applies (L2829-L2873) and the encrypted-response thumbprint
        // is present rather than null (L2870).
        let transcript = build_session_transcript(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
        let partial = coset::CoseSign1Builder::new()
            .protected(protected.clone())
            .build();
        let d_tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            partial.protected.clone(),
            None,
            &[],
            &transcript,
        );
        let sig = {
            use foundry_core::crypto::Signer as _;
            d_signer.sign(&d_tbs).unwrap()
        };
        let d_sign = coset::CoseSign1Builder::new()
            .protected(protected)
            .signature(sig)
            .build();
        let d_sig_bytes = coset::CborSerializable::to_vec(d_sign).unwrap();

        // Envelope + JWE.
        let vp_token = serde_json::json!({
            "mdoc": B64URL.encode(&mdoc_bytes),
            "device_signature": B64URL.encode(&d_sig_bytes),
        });
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [vp_token] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(res.verified, "checks={:?}", res.checks);
        assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "mdoc_issuer_auth_and_device_signature" && c.passed));
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "dcql_match" && c.passed));
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "status_check" && c.passed));
    }

    // --- select_presentation: the OpenID4VP 1.0 section 8.1 envelope ---
    //
    // These exercise envelope selection directly, with no JWE, no keys and no
    // trust store, so a failure points at the envelope rather than at crypto.

    fn sd_jwt_dcql() -> Value {
        serde_json::json!({"credentials": [{"id": "c1", "format": "dc+sd-jwt"}]})
    }

    fn mdoc_dcql() -> Value {
        serde_json::json!({"credentials": [{"id": "c1", "format": "mso_mdoc"}]})
    }

    /// Assert rejection and hand back the message, so each test can check that the
    /// message actually says something actionable.
    fn rejection_of(vp_token: Value, dcql_query: &Value) -> String {
        match select_presentation(&vp_token, dcql_query) {
            Ok((id, selected)) => {
                panic!("expected rejection, but selected id={id} payload={selected:?}")
            }
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn select_presentation_accepts_conformant_sd_jwt_envelope() {
        let vp = serde_json::json!({"c1": ["header.body.sig~disclosure~kb"]});
        let (id, selected) = select_presentation(&vp, &sd_jwt_dcql()).unwrap();
        assert_eq!(id, "c1");
        match selected {
            SelectedPresentation::SdJwtVc(s) => assert_eq!(s, "header.body.sig~disclosure~kb"),
            other => panic!("expected SdJwtVc, got {other:?}"),
        }
    }

    #[test]
    fn select_presentation_accepts_conformant_mdoc_envelope() {
        let vp = serde_json::json!({"c1": [{"mdoc": "AAAA", "device_signature": "BBBB"}]});
        let (id, selected) = select_presentation(&vp, &mdoc_dcql()).unwrap();
        assert_eq!(id, "c1");
        match selected {
            SelectedPresentation::MsoMdoc {
                mdoc_b64,
                device_signature_b64,
            } => {
                assert_eq!(mdoc_b64, "AAAA");
                assert_eq!(device_signature_b64, "BBBB");
            }
            other => panic!("expected MsoMdoc, got {other:?}"),
        }
    }

    /// The reported production defect: a bare string was foundry's old SD-JWT VC
    /// shape, and no conformant wallet sends it.
    #[test]
    fn select_presentation_rejects_bare_string_vp_token() {
        let msg = rejection_of(serde_json::json!("header.body.sig~"), &sd_jwt_dcql());
        assert!(msg.contains("must be a JSON object"), "{msg}");
        assert!(msg.contains("got a string"), "{msg}");
    }

    /// foundry's old mdoc shape put these keys at the top level of `vp_token`.
    #[test]
    fn select_presentation_rejects_legacy_top_level_mdoc_envelope() {
        let msg = rejection_of(
            serde_json::json!({"mdoc": "AAAA", "device_signature": "BBBB"}),
            &mdoc_dcql(),
        );
        assert!(msg.contains("names no credential query"), "{msg}");
    }

    #[test]
    fn select_presentation_rejects_unknown_query_id_naming_both_sides() {
        let msg = rejection_of(serde_json::json!({"unexpected": ["x"]}), &sd_jwt_dcql());
        assert!(msg.contains("unexpected"), "must name what arrived: {msg}");
        assert!(msg.contains("c1"), "must name what was expected: {msg}");
    }

    #[test]
    fn select_presentation_rejects_multiple_answered_queries() {
        let dcql = serde_json::json!({"credentials": [
            {"id": "a", "format": "dc+sd-jwt"},
            {"id": "b", "format": "dc+sd-jwt"}
        ]});
        let msg = rejection_of(serde_json::json!({"a": ["x"], "b": ["y"]}), &dcql);
        assert!(msg.contains("several credential queries"), "{msg}");
    }

    #[test]
    fn select_presentation_requires_exactly_one_presentation() {
        let dcql = sd_jwt_dcql();
        let empty = rejection_of(serde_json::json!({"c1": []}), &dcql);
        assert!(empty.contains("exactly one presentation"), "{empty}");
        let two = rejection_of(serde_json::json!({"c1": ["x", "y"]}), &dcql);
        assert!(two.contains("exactly one presentation"), "{two}");
    }

    #[test]
    fn select_presentation_requires_an_array_value() {
        let msg = rejection_of(serde_json::json!({"c1": "not-an-array"}), &sd_jwt_dcql());
        assert!(msg.contains("must be an array"), "{msg}");
    }

    /// The payload must match the format the query *declared*. This is where the
    /// old shape-sniffing protection now lives, with a message that names the
    /// declared format instead of guessing.
    #[test]
    fn select_presentation_rejects_payload_contradicting_declared_format() {
        let object_for_sd_jwt = rejection_of(
            serde_json::json!({"c1": [{"mdoc": "A", "device_signature": "B"}]}),
            &sd_jwt_dcql(),
        );
        assert!(
            object_for_sd_jwt.contains("dc+sd-jwt"),
            "{object_for_sd_jwt}"
        );

        let string_for_mdoc = rejection_of(serde_json::json!({"c1": ["a-string"]}), &mdoc_dcql());
        assert!(string_for_mdoc.contains("mso_mdoc"), "{string_for_mdoc}");
    }

    #[test]
    fn select_presentation_rejects_unusable_dcql_query() {
        let msg = rejection_of(
            serde_json::json!({"c1": ["x"]}),
            &serde_json::json!({"credentials": []}),
        );
        assert!(msg.contains("not a valid DCQL query"), "{msg}");
    }

    /// `CredentialFormat::Other` parses fine so that unimplemented formats simply
    /// fail to match inside a multi-credential query. Once one is *answered*,
    /// though, there is no verifier to dispatch to.
    #[test]
    fn select_presentation_rejects_unimplemented_credential_format() {
        let dcql = serde_json::json!({"credentials": [{"id": "c1", "format": "jwt_vc_json"}]});
        let msg = rejection_of(serde_json::json!({"c1": ["x"]}), &dcql);
        assert!(msg.contains("jwt_vc_json"), "{msg}");
        assert!(msg.contains("does not implement"), "{msg}");
    }

    /// GAP-VP-07 / VP-0265 (OpenID4VP mdoc-adjacent IETF SD-JWT VC Presentation
    /// Response, L3179): "Over the DC API the `aud` claim MUST instead be the
    /// Origin prefixed with `origin:`." `do_verify_vp_response` always computed
    /// `expected_audience` as the `x509_san_dns:<host>` Client Identifier (now
    /// `x509_hash:<hash>` per GAP-HAIP-05, but the bug this test guards against
    /// is the same regardless of prefix),
    /// regardless of `tx.transport` -- there is no branch anywhere that
    /// switches to an Origin-prefixed audience for `dc_api` transport. A
    /// spec-conformant wallet responding to an *unsigned* DC API request (the
    /// only kind foundry's `dc_api` transport ever issues, since `client_id` is
    /// never included -- see VP-0198/VP-0200) is required by this same clause
    /// to bind its KB-JWT to the Origin, not the Client Identifier -- so this
    /// verifier would reject every genuinely conformant wallet's dc_api
    /// presentation.
    #[tokio::test]
    async fn gap_vp_07_dc_api_transport_never_accepts_origin_prefixed_kb_jwt_audience() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // Same shape `create_verification_request` builds for `transport: "dc_api"`
        // (request.rs): `dc_api.jwt` response_mode, no `client_id` ever emitted.
        tx.transport = "dc_api".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // OpenID4VP L3179: over the DC API the KB-JWT `aud` MUST be the Origin
        // prefixed with `origin:`, not the Client Identifier -- exactly what a
        // conformant wallet would send back for this unsigned dc_api request.
        let origin_audience = "origin:https://verifier-website.example";
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            origin_audience,
            &tx.nonce,
            None,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(
            res.verified,
            "a conformant wallet's Origin-prefixed KB-JWT audience for a dc_api presentation \
             should verify, but do_verify_vp_response rejected it: {:?}",
            res.checks
        );
    }

    /// OpenID4VP L2543: with `verifier.dc_api_expected_origins` left unconfigured
    /// (the `#[serde(default)]` empty-Vec case), `do_verify_vp_response` falls
    /// back to a single origin derived from `public_base_url` rather than
    /// rejecting every dc_api presentation outright -- this keeps an
    /// unconfigured single-origin deployment working.
    #[tokio::test]
    async fn dc_api_presentation_with_no_configured_origins_accepts_public_base_url_fallback() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (mut config, _trust_dir) = test_config(&ca_str);
        config.verifier.dc_api_expected_origins = Vec::new();

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        tx.transport = "dc_api".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // test_config()'s public_base_url is "https://localhost:8443" -- the
        // fallback audience the unconfigured branch derives.
        let fallback_audience = "origin:https://localhost:8443";
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            fallback_audience,
            &tx.nonce,
            None,
        )
        .unwrap();
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            res.verified,
            "an unconfigured deployment must fall back to a public_base_url-derived origin: {:?}",
            res.checks
        );
    }

    /// OpenID4VP L2543 / RFC 6454: the spec text and RFC 6454's own Origin
    /// serialization do not agree on trailing-slash handling, so both a
    /// configured origin and a presented audience are normalized the same way
    /// before comparison -- neither a trailing slash on the config value nor
    /// on the presented `aud` should defeat the match.
    #[tokio::test]
    async fn dc_api_audience_trailing_slash_variations_both_match() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (mut config, _trust_dir) = test_config(&ca_str);
        // Configured origin carries a trailing slash; the presented `aud` does not.
        config.verifier.dc_api_expected_origins =
            vec!["https://verifier-website.example/".to_string()];

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        tx.transport = "dc_api".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let no_slash_audience = "origin:https://verifier-website.example";
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            no_slash_audience,
            &tx.nonce,
            None,
        )
        .unwrap();
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            res.verified,
            "a configured origin with a trailing slash must still match a presented audience \
             without one: {:?}",
            res.checks
        );
    }

    /// Guards against over-broadening the fix: only the `dc_api` transport
    /// gets the Origin-prefixed audience treatment. A `request_uri` (or any
    /// other) transport must still require the `x509_hash:<hash>` Client
    /// Identifier (HAIP OpenID4VP L256) and reject an Origin-prefixed audience.
    #[tokio::test]
    async fn request_uri_transport_rejects_origin_prefixed_audience() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        tx.transport = "request_uri".to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let origin_audience = "origin:https://verifier-website.example";
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            origin_audience,
            &tx.nonce,
            None,
        )
        .unwrap();
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Failed(_)),
            "a request_uri-transport presentation with an Origin-prefixed audience must still be \
             rejected, got: {err:?}"
        );
    }

    /// A `dc_api` presentation whose audience matches neither a configured
    /// origin nor the `public_base_url`-derived fallback must be rejected --
    /// the fix must not accept an arbitrary Origin.
    #[tokio::test]
    async fn dc_api_audience_matching_neither_configured_nor_fallback_is_rejected() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        tx.transport = "dc_api".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let unrelated_audience = "origin:https://some-other-site.example";
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            unrelated_audience,
            &tx.nonce,
            None,
        )
        .unwrap();
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Failed(_)),
            "an audience matching neither a configured origin nor the fallback must be rejected, \
             got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // mdoc SessionTranscript Handover binding (formerly GAP-VP-06, closed
    // 2026-08-02).
    //
    // `foundry-mdoc`'s own tests pin the transcript bytes against OpenID4VP's
    // published vectors. These tests cover the other half: that the verifier
    // actually *requires* those bytes, and selects the right variant from the
    // transaction's transport and Response Mode.
    // -----------------------------------------------------------------------

    fn cbor_text(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::new();
        if b.len() < 24 {
            out.push(0x60 | b.len() as u8);
        } else if b.len() < 256 {
            out.push(0x78);
            out.push(b.len() as u8);
        } else {
            out.push(0x79);
            out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(b);
        out
    }

    /// The exact `SessionTranscript` foundry produced *before* GAP-VP-06 was
    /// closed: `[null, null, [client_id, response_uri, nonce]]`, with the raw
    /// request values sitting where the spec requires a hashed
    /// `OpenID4VPHandover`.
    ///
    /// Hand-encoded because `ciborium` is not a dependency of this crate, and
    /// because pinning the pre-fix bytes literally is the point: it is what a
    /// wallet built against the old behaviour would sign.
    fn pre_fix_ad_hoc_transcript(client_id: &str, response_uri: &str, nonce: &str) -> Vec<u8> {
        let mut out = vec![0x83, 0xf6, 0xf6, 0x83];
        out.extend(cbor_text(client_id));
        out.extend(cbor_text(response_uri));
        out.extend(cbor_text(nonce));
        out
    }

    fn mdoc_dcql_query() -> serde_json::Value {
        serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
            }]
        })
    }

    /// Issue an mdoc and sign a detached DeviceAuth over `transcript`, then
    /// wrap it in the JWE a wallet would post. Taking the transcript as raw
    /// bytes lets a caller sign a deliberately wrong one.
    fn mdoc_presentation_jwe(
        leaf_cert: &[u8],
        leaf_key: &[u8],
        transcript: &[u8],
        ephem_public_jwk: &serde_json::Value,
        now: u64,
    ) -> String {
        let issuer_signer = FileSigner::from_pem(leaf_key, SignatureAlgorithm::Es256).unwrap();
        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let mut elements = std::collections::BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        let mut namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        let mdoc_bytes = build_mdoc(
            MdocClaims {
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                namespaces,
                device_key_jwk: d_jwk_pub,
                signed_at: (now - 100) as i64,
                valid_until: (now + 3600) as i64,
            },
            &issuer_signer,
            Some(vec![der_b64(leaf_cert)]),
        )
        .unwrap();

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
        let partial = coset::CoseSign1Builder::new()
            .protected(protected.clone())
            .build();
        let d_tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            partial.protected.clone(),
            None,
            &[],
            transcript,
        );
        let sig = {
            use foundry_core::crypto::Signer as _;
            d_signer.sign(&d_tbs).unwrap()
        };
        let d_sign = coset::CoseSign1Builder::new()
            .protected(protected)
            .signature(sig)
            .build();
        let d_sig_bytes = coset::CborSerializable::to_vec(d_sign).unwrap();

        encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [serde_json::json!({
                "mdoc": B64URL.encode(&mdoc_bytes),
                "device_signature": B64URL.encode(&d_sig_bytes),
            })] } }),
            ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap()
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// The fix must not be cosmetic: a wallet still signing the pre-GAP-VP-06
    /// ad-hoc transcript has to be rejected now. Without this, every other
    /// assertion here would still pass if the verifier had simply stopped
    /// checking the Device Signature.
    #[tokio::test]
    async fn mdoc_device_signature_over_the_pre_fix_ad_hoc_transcript_is_rejected() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let (config, _dir) = test_config(&String::from_utf8(root_pem).unwrap());
        let (mut tx, _) = sample_tx();
        tx.dcql_query = mdoc_dcql_query();

        let legacy = pre_fix_ad_hoc_transcript(
            &expected_client_id(&config),
            &format!("https://localhost:8443/vp/response/{}", tx.id),
            &tx.nonce,
        );
        let jwe = mdoc_presentation_jwe(
            &leaf_cert,
            &leaf_key,
            &legacy,
            &tx.ephem_public_jwk,
            now_secs(),
        );

        let err = verify_vp_response(&config, &mut tx, &jwe, &MockResolver { token: None })
            .await
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("mdoc verification failed"),
            "a DeviceAuth over the pre-fix ad-hoc transcript must no longer verify, got: {err:?}"
        );
    }

    /// OpenID4VP L2997: the DC API Handover binds to the request's Origin. The
    /// Origin is inside the hash, so the verifier must try each configured
    /// candidate — including ones that are not the first.
    #[tokio::test]
    async fn dc_api_mdoc_accepts_a_later_configured_origin() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let (mut config, _dir) = test_config(&String::from_utf8(root_pem).unwrap());
        config.verifier.dc_api_expected_origins = vec![
            "https://first.example.com".to_string(),
            "https://second.example.com".to_string(),
        ];

        let (mut tx, _) = sample_tx();
        tx.dcql_query = mdoc_dcql_query();
        tx.transport = "dc_api".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        // The wallet used the *second* origin; a first-only implementation
        // would reject this.
        let transcript = build_session_transcript(&SessionTranscriptParams::DcApi {
            origin: "https://second.example.com".to_string(),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
        })
        .unwrap();
        let jwe = mdoc_presentation_jwe(
            &leaf_cert,
            &leaf_key,
            &transcript,
            &tx.ephem_public_jwk,
            now_secs(),
        );

        let res = verify_vp_response(&config, &mut tx, &jwe, &MockResolver { token: None })
            .await
            .unwrap();
        assert!(res.verified, "checks={:?}", res.checks);
    }

    /// Trying every configured Origin must not degrade into accepting any
    /// Origin.
    #[tokio::test]
    async fn dc_api_mdoc_rejects_an_unconfigured_origin() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let (mut config, _dir) = test_config(&String::from_utf8(root_pem).unwrap());
        config.verifier.dc_api_expected_origins = vec!["https://first.example.com".to_string()];

        let (mut tx, _) = sample_tx();
        tx.dcql_query = mdoc_dcql_query();
        tx.transport = "dc_api".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        let transcript = build_session_transcript(&SessionTranscriptParams::DcApi {
            origin: "https://attacker.example.com".to_string(),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
        })
        .unwrap();
        let jwe = mdoc_presentation_jwe(
            &leaf_cert,
            &leaf_key,
            &transcript,
            &tx.ephem_public_jwk,
            now_secs(),
        );

        let err = verify_vp_response(&config, &mut tx, &jwe, &MockResolver { token: None })
            .await
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("mdoc verification failed"),
            "an Origin matching no configured candidate must be rejected, got: {err:?}"
        );
    }

    /// OpenID4VP L2999: for Response Mode `dc_api.jwt` the third
    /// `OpenID4VPDCAPIHandoverInfo` element is the encryption key's thumbprint;
    /// for `dc_api` it is `null`. The two are not interchangeable, and this
    /// asserts both directions so neither can be silently dropped.
    #[tokio::test]
    async fn dc_api_response_mode_selects_null_or_thumbprint() {
        for (response_mode, correct, wrong) in
            [("dc_api.jwt", true, false), ("dc_api", false, true)]
        {
            let (root_pem, leaf_cert, leaf_key) = test_pki();
            let (mut config, _dir) = test_config(&String::from_utf8(root_pem).unwrap());
            config.verifier.dc_api_expected_origins =
                vec!["https://origin.example.com".to_string()];

            let (mut tx, _) = sample_tx();
            tx.dcql_query = mdoc_dcql_query();
            tx.transport = "dc_api".to_string();
            tx.response_mode = response_mode.to_string();

            let thumb = foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap();
            let build = |with_thumbprint: bool| {
                build_session_transcript(&SessionTranscriptParams::DcApi {
                    origin: "https://origin.example.com".to_string(),
                    nonce: tx.nonce.clone(),
                    jwk_thumbprint: if with_thumbprint { Some(thumb) } else { None },
                })
                .unwrap()
            };

            let ok_jwe = mdoc_presentation_jwe(
                &leaf_cert,
                &leaf_key,
                &build(correct),
                &tx.ephem_public_jwk,
                now_secs(),
            );
            let mut tx_ok = tx.clone();
            let res =
                verify_vp_response(&config, &mut tx_ok, &ok_jwe, &MockResolver { token: None })
                    .await
                    .unwrap_or_else(|e| {
                        panic!("{response_mode}: correct transcript must verify: {e:?}")
                    });
            assert!(res.verified, "{response_mode}: checks={:?}", res.checks);

            let bad_jwe = mdoc_presentation_jwe(
                &leaf_cert,
                &leaf_key,
                &build(wrong),
                &tx.ephem_public_jwk,
                now_secs(),
            );
            let mut tx_bad = tx.clone();
            let err = verify_vp_response(
                &config,
                &mut tx_bad,
                &bad_jwe,
                &MockResolver { token: None },
            )
            .await
            .unwrap_err();
            assert!(
                format!("{err:?}").contains("mdoc verification failed"),
                "{response_mode}: the opposite thumbprint choice must be rejected, got: {err:?}"
            );
        }
    }
}
