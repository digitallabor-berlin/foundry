use crate::dcql::{PresentedFormat, check_dcql_match};
use crate::dcql_model::{CredentialFormat, DcqlQuery};
use crate::error::VerificationError;
use crate::request::verifier_x5c_leaf_pem;
use crate::status::{StatusListResolver, check_status};
use crate::transaction::{
    CheckResult, PresentedCredential, VerificationResult, VerificationState,
    VerificationTransaction,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use foundry_core::config::Config;
use foundry_core::trust::TrustStore;
use foundry_mdoc::types::{
    SessionTranscriptParams, build_session_transcript, session_transcript_value,
};
use josekit::jwk::Jwk;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Audience prefix OpenID4VP **draft 24** Appendix A.2 gave the effective
/// Client Identifier of an unsigned DC API request, superseded by `origin:`
/// in OpenID4VP 1.0 (L618, L2543).
///
/// Only ever consulted when `verifier.dc_api_accept_legacy_web_origin_audience`
/// is enabled; foundry implements 1.0 and rejects this spelling by default.
const LEGACY_WEB_ORIGIN_PREFIX: &str = "web-origin:";

/// The single presentation selected from a `vp_token`, already destructured
/// according to the credential format the DCQL query declared.
///
/// Carrying the typed payload — rather than a `&Value` plus a format tag — keeps
/// every shape check inside `select_presentation`, so the verification arms
/// cannot re-derive the format or trip over an "impossible" type error.
#[derive(Debug)]
enum SelectedPresentation<'a> {
    SdJwtVc(&'a str),
    /// OpenID4VP 1.0 L2825-L2828: the base64url-encoded ISO/IEC 18013-5
    /// `DeviceResponse` CBOR structure. One string, not a split envelope — the
    /// `{mdoc, device_signature}` pair this once carried was foundry-invented,
    /// and no wallet ever sent it.
    MsoMdoc {
        device_response_b64: &'a str,
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

/// Select every presentation to verify from an OpenID4VP 1.0 `vp_token`
/// (Response Parameters, L1161; the `vp_token` parameter itself at L1166).
///
/// `vp_token` is a JSON object keyed by DCQL credential query id whose values are
/// **arrays** of presentations — the same shape for every credential format. The
/// format therefore *cannot* be read off the JSON type of the payload; it is
/// whatever the answered credential query declared. Inferring it from the shape
/// is exactly what made a conformant SD-JWT VC presentation report the
/// misleading `mdoc vp_token missing 'mdoc'`.
///
/// Returns one entry per answered credential query, in **DCQL declaration
/// order** — never `vp_token` key order, which depends on the wallet's
/// serialization and on whether `serde_json` was built with `preserve_order`.
///
/// Every failure here is structural (HTTP 400), never a policy verdict. In
/// particular a `vp_token` answering only *some* of the requested credential
/// queries is **accepted** here: it violates L1007-1008 ("If the Wallet cannot
/// deliver all non-optional Credentials requested by the Verifier according to
/// these rules, it MUST NOT return any Credential(s)"), but it is well-formed,
/// so the verdict belongs to `check_requested_credentials_answered`
/// (root AGENTS.md §4.3).
fn select_presentations<'a>(
    vp_token: &'a Value,
    dcql_query: &Value,
) -> Result<Vec<(String, SelectedPresentation<'a>)>, VerificationError> {
    let entries = vp_token.as_object().ok_or_else(|| {
        VerificationError::Failed(format!(
            "vp_token must be a JSON object keyed by DCQL credential query id \
             (OpenID4VP 1.0 L1166), got {}",
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

    let requested: Vec<&str> = query.credentials().iter().map(|cq| cq.id()).collect();

    // An id the request never asked for is a contract violation with no possible
    // verdict attached: there is no credential query to verify it against, so it
    // cannot be reported as a policy outcome the way a *missing* one can.
    for key in entries.keys() {
        if !requested.contains(&key.as_str()) {
            return Err(VerificationError::Failed(format!(
                "vp_token names credential query '{}', which this request did not ask \
                 for; expected one of [{}]",
                key,
                requested.join(", ")
            )));
        }
    }

    let mut selected = Vec::with_capacity(requested.len());
    for cq in query.credentials() {
        let Some(value) = entries.get(cq.id()) else {
            // Not answered. Whether that is acceptable is a POLICY question
            // (L1007-1008 makes it a wallet violation), decided by
            // `check_requested_credentials_answered` -- not a structural one.
            continue;
        };

        let presentations = value.as_array().ok_or_else(|| {
            VerificationError::Failed(format!(
                "vp_token['{}'] must be an array of presentations \
                 (OpenID4VP 1.0 L1166), got {}",
                cq.id(),
                json_type_name(value)
            ))
        })?;

        // L1166: "When `multiple` is omitted, or set to `false`, the array MUST
        // contain only one Presentation." foundry ignores `multiple` (an unknown
        // property per VP-0090), so it never requests more than one and the
        // one-presentation rule always applies. Silently taking [0] of a longer
        // array would verify part of a presentation set while reporting the
        // whole set as satisfied.
        let presentation = match presentations.as_slice() {
            [single] => single,
            other => {
                return Err(VerificationError::Failed(format!(
                    "vp_token['{}'] must contain exactly one presentation, got {}",
                    cq.id(),
                    other.len()
                )));
            }
        };

        let payload = match cq.format() {
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
            CredentialFormat::MsoMdoc => SelectedPresentation::MsoMdoc {
                device_response_b64: presentation.as_str().ok_or_else(|| {
                    VerificationError::Failed(format!(
                        "credential query '{}' declares format mso_mdoc, so its \
                         presentation must be a base64url-encoded ISO 18013-5 \
                         DeviceResponse string (OpenID4VP 1.0 L2825-L2828), got {}",
                        cq.id(),
                        json_type_name(presentation)
                    ))
                })?,
            },
            // `CredentialFormat::Other` exists so that an unimplemented format inside
            // a multi-credential query simply fails to match rather than invalidating
            // the whole query (see `dcql_model`). Once a wallet has *answered* such a
            // query there is nothing to fall back to: no verifier for the format
            // exists, so this is a request the verifier cannot service.
            CredentialFormat::Other(other) => {
                return Err(VerificationError::Failed(format!(
                    "credential query '{}' requests credential format '{}', which this \
                     verifier does not implement",
                    cq.id(),
                    other
                )));
            }
        };

        selected.push((cq.id().to_string(), payload));
    }

    if selected.is_empty() {
        return Err(VerificationError::Failed(format!(
            "vp_token answers no credential query from this request: expected one of [{}]",
            requested.join(", ")
        )));
    }

    Ok(selected)
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
        Ok(outcome) => {
            let VerifyOutcome { result, deferred } = outcome;

            tx.state = if result.verified {
                VerificationState::Verified
            } else {
                VerificationState::Failed
            };

            // One record per check, so an operator can see which stage rejected a
            // presentation without reading the JSON verdict.
            //
            // Both levels, and per-credential records name their credential:
            // with N credentials `check=dcql_match passed=false` alone does not
            // say whose. A DCQL credential query id is operator-authored request
            // structure, not a holder value, so naming it is safe -- the same
            // reasoning `dcql.rs` records for naming claim paths in a mismatch
            // (root AGENTS.md §4.5).
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
            // One roll-up record per credential, then that credential's
            // per-check trail. The roll-up is the line an operator reads; the
            // per-check records are the drill-down, and §4.5 makes their field
            // names operator-facing API, so they are enriched here and never
            // replaced.
            //
            // A DCQL credential query id is operator-authored request structure
            // and a `vct`/`docType` is a credential type identifier -- neither
            // is a holder value, so both are logged unconditionally, at no
            // sensitivity gate (root AGENTS.md §4.5).
            for credential in &result.credentials {
                let checks_total = credential.checks.len();
                let checks_passed = credential.checks.iter().filter(|c| c.passed).count();
                let credential_type = credential.credential_type.as_deref().unwrap_or("");

                if checks_passed == checks_total {
                    tracing::info!(
                        credential = %credential.query_id,
                        format = %credential.format,
                        credential_type = %credential_type,
                        checks = checks_total,
                        checks_passed,
                        "credential verified"
                    );
                } else {
                    // A per-credential failure is still a correct service
                    // outcome, so `warn` rather than `error` (root AGENTS.md
                    // §4.5). The reason lives on the per-check record below.
                    tracing::warn!(
                        credential = %credential.query_id,
                        format = %credential.format,
                        credential_type = %credential_type,
                        checks = checks_total,
                        checks_passed,
                        "credential failed"
                    );
                }

                for check in &credential.checks {
                    if check.passed {
                        tracing::info!(
                            credential = %credential.query_id,
                            credential_type = %credential_type,
                            check = %check.check,
                            passed = true,
                            "verification check"
                        );
                    } else {
                        tracing::warn!(
                            credential = %credential.query_id,
                            credential_type = %credential_type,
                            check = %check.check,
                            passed = false,
                            detail = %check.detail.as_deref().unwrap_or(""),
                            "verification check failed"
                        );
                    }
                }
            }

            // A policy failure (DCQL mismatch, revoked credential) is a 200 with
            // verified: false, so `warn` — not `error` — is the right level: the
            // service behaved correctly.
            //
            // `credentials_requested` / `credentials_answered` are COUNTS, never
            // identifiers, so they carry no request structure at all. The count
            // pair is what makes a subset response visible at a glance.
            let credentials_requested = serde_json::from_value::<DcqlQuery>(tx.dcql_query.clone())
                .map(|q| q.credentials().len())
                .unwrap_or(0);
            let credentials_answered = result.credentials.len();

            if result.verified {
                tracing::info!(
                    verified = true,
                    credentials_requested,
                    credentials_answered,
                    "vp response verified"
                );
            } else {
                tracing::warn!(
                    verified = false,
                    // BOTH levels: after multi-credential support most checks are
                    // per-credential, so a top-level-only count under-reports and
                    // would read as zero failures on a failed verification.
                    failed_checks = result.all_checks().filter(|c| !c.passed).count(),
                    credentials_requested,
                    credentials_answered,
                    // A COUNT, never an identifier -- the roll-up records above
                    // name the credentials. This makes "1 of 2 failed" visible
                    // on the verdict line itself. Emitted only here: on a
                    // verified response it is always zero, and a field that is
                    // always zero is noise.
                    credentials_failed = result
                        .credentials
                        .iter()
                        .filter(|c| c.checks.iter().any(|k| !k.passed))
                        .count(),
                    "vp response not verified"
                );
            }

            tx.result = Some(result.clone());

            match deferred {
                None => Ok(result),
                // The result is already persisted, so the operator keeps every
                // other credential's verdict while the wallet still gets the
                // retryable status code.
                Some(err) => {
                    tx.state = VerificationState::Failed;
                    Err(err)
                }
            }
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
            let mut result = VerificationResult {
                verified: false,
                checks,
                // Genuinely empty, not a convenience. This arm is now reachable
                // only by transaction-level failures -- JWE decryption, a
                // missing `vp_token`, trust-store construction,
                // `select_presentations` -- all of which happen before any
                // credential is examined. A per-credential failure no longer
                // arrives here: it is recorded on its own credential and
                // returned through `deferred`, so its neighbours' verdicts
                // survive.
                credentials: Vec::new(),
            };
            // Still derived: one check, not passed (root AGENTS.md §4.2).
            result.verified = result.derive_verified();
            tx.result = Some(result);

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

/// The `vct` a compact SD-JWT VC presentation **asserts**, read without
/// verifying any signature.
///
/// Deliberately unauthenticated, and named to say so. It exists so a
/// presentation that fails its signature check can still be named in a log
/// record and in the admin console: a failed credential an operator cannot
/// identify is the defect this serves. On the success path the value is
/// identical to the verified payload's `vct`, because `verify_sd_jwt_vc` reads
/// the same segment.
///
/// Every malformed shape yields `None` rather than an error. This is a
/// diagnostic, and a diagnostic must not be able to change the verdict it
/// describes.
fn asserted_vct_unverified(presentation: &str) -> Option<String> {
    // IETF SD-JWT compact serialization: the issuer-signed JWT is everything
    // before the first `~`; the disclosures and the KB-JWT follow it.
    let jwt = presentation.split('~').next()?;
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = B64URL.decode(payload_b64).ok()?;
    let payload: Value = serde_json::from_slice(&bytes).ok()?;
    payload.get("vct")?.as_str().map(str::to_string)
}

/// Inputs shared by every credential in one `vp_token`, computed once.
///
/// `base_url` and `client_id` are carried here because the mdoc
/// SessionTranscript is built from them; they are derived once in
/// `do_verify_vp_response` and are identical for every credential.
struct CredentialVerifyCtx<'a> {
    config: &'a Config,
    tx: &'a VerificationTransaction,
    trust_store: &'a TrustStore,
    expected_audiences: &'a [String],
    now_unix: u64,
    base_url: &'a str,
    client_id: &'a str,
}

/// What the format-specific signature stage produces on success.
///
/// Extracted so `verify_one_credential` can convert this stage's `Err` into a
/// failed `CheckResult` in exactly one place, instead of every fallible call
/// inside it having the option of `?`-ing out of the per-credential loop.
struct FormatStage {
    /// This credential's disclosed claims, never merged with another's.
    claims: serde_json::Map<String, Value>,
    /// The verified KB-JWT payload. `None` for `mso_mdoc`, which has no KB-JWT
    /// (OpenID4VP L3144).
    kb_jwt_payload: Option<Value>,
    /// The mdoc `docType`, for DCQL doctype matching only. `None` for SD-JWT VC,
    /// whose queries carry no `doctype_value`.
    doc_type: Option<String>,
}

/// Verify one credential's format-specific signature stage.
///
/// `credential_type` is an out-parameter rather than part of the return value on
/// purpose: it is filled as early as each format allows, so it is still
/// populated when this function returns `Err`. A failed credential an operator
/// cannot name is the defect that field exists to fix.
async fn verify_credential_payload(
    ctx: &CredentialVerifyCtx<'_>,
    selected: SelectedPresentation<'_>,
    credential_type: &mut Option<String>,
) -> Result<FormatStage, VerificationError> {
    let mut disclosed_claims = serde_json::Map::new();
    // Populated only for SD-JWT VC presentations, whose Key Binding JWT carries
    // `transaction_data_hashes` (L3144). An mdoc presentation has no KB-JWT, so
    // this stays `None` for that format -- checked below.
    let mut kb_jwt_payload: Option<Value> = None;

    // `doc_type` feeds DCQL doctype matching and MUST stay `None` for SD-JWT VC,
    // whose queries carry no `doctype_value`. The asserted credential type is a
    // separate concern and travels through the out-parameter.
    let doc_type: Option<String> = match selected {
        SelectedPresentation::SdJwtVc(jwt_str) => {
            // Read from the presentation before it is verified, so this cannot
            // become conditional on the verdict it helps explain.
            *credential_type = asserted_vct_unverified(jwt_str);

            let verified = foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc(
                jwt_str,
                ctx.trust_store,
                ctx.expected_audiences,
                &ctx.tx.nonce,
                ctx.now_unix,
            )
            .map_err(|e| VerificationError::Failed(e.to_string()))?;

            // Say out loud when a presentation was only accepted because the
            // operator enabled the draft-24 accommodation, so the flag can be
            // turned off again once the wallets in play have caught up. This
            // is an Origin -- a public identifier, not a payload -- so it is
            // logged unconditionally (root AGENTS.md §4.5).
            if let Some(aud) = verified
                .kb_jwt_payload
                .get("aud")
                .and_then(|v| v.as_str())
                .filter(|aud| aud.starts_with(LEGACY_WEB_ORIGIN_PREFIX))
            {
                tracing::warn!(
                    audience = %aud,
                    "KB-JWT bound to the superseded OpenID4VP draft 24 `web-origin:` audience \
                     prefix; accepted only because \
                     verifier.dc_api_accept_legacy_web_origin_audience is enabled -- OpenID4VP \
                     1.0 L2543 mandates `origin:`"
                );
            }

            kb_jwt_payload = Some(verified.kb_jwt_payload);
            if let Value::Object(map) = verified.claims {
                for (k, v) in map {
                    disclosed_claims.insert(k, v);
                }
            }
            None
        }
        SelectedPresentation::MsoMdoc {
            device_response_b64,
        } => {
            let dr_bytes = B64URL.decode(device_response_b64).map_err(|e| {
                VerificationError::Failed(format!("DeviceResponse base64url decode: {e}"))
            })?;
            let decoded = foundry_mdoc::verifier::decode_device_response(&dr_bytes)
                .map_err(|e| VerificationError::Failed(format!("DeviceResponse: {e}")))?;
            let resp = foundry_mdoc::verifier::parse_device_response(&decoded)
                .map_err(|e| VerificationError::Failed(format!("DeviceResponse: {e}")))?;

            // Unverified at this point -- read from the DeviceResponse envelope
            // so it is available if `verify_issuer_signed` below rejects the
            // chain. Replaced with the authenticated MSO `docType` on success.
            *credential_type = Some(resp.doc_type().to_string());

            // OpenID4VP L2870 (redirects) / L2999 (DC API): the third
            // `…HandoverInfo` element is the RFC 7638 thumbprint of the
            // Verifier's response-encryption public key when the response is
            // encrypted, and CBOR `null` when it is not. An unrecognised
            // Response Mode is an error rather than a silent `None`: guessing
            // would build a transcript that fails to verify for a reason no
            // operator could diagnose.
            let jwk_thumbprint: Option<[u8; 32]> = match ctx.tx.response_mode.as_str() {
                "dc_api.jwt" | "direct_post.jwt" => Some(
                    foundry_core::obs::thumbprint_bytes(&ctx.tx.ephem_public_jwk).map_err(|e| {
                        VerificationError::Failed(format!(
                            "cannot compute the response-encryption key thumbprint: {e}"
                        ))
                    })?,
                ),
                "dc_api" | "direct_post" => None,
                other => {
                    return Err(VerificationError::Failed(format!(
                        "unsupported response_mode for the mdoc SessionTranscript: {other}"
                    )));
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
            let candidates: Vec<SessionTranscriptParams> = if ctx.tx.transport == "dc_api" {
                let origins: Vec<String> = if ctx.config.verifier.dc_api_expected_origins.is_empty()
                {
                    vec![ctx.base_url.to_string()]
                } else {
                    ctx.config.verifier.dc_api_expected_origins.clone()
                };
                origins
                    .into_iter()
                    // L2997: the Origin element MUST NOT carry the `origin:`
                    // prefix. That prefix belongs to the KB-JWT audience — a
                    // different mechanism that happens to name the same value.
                    .map(|origin| SessionTranscriptParams::DcApi {
                        origin,
                        nonce: ctx.tx.nonce.clone(),
                        jwk_thumbprint,
                    })
                    .collect()
            } else {
                vec![SessionTranscriptParams::Redirect {
                    client_id: ctx.client_id.to_string(),
                    nonce: ctx.tx.nonce.clone(),
                    jwk_thumbprint,
                    response_uri: format!("{}/vp/response/{}", ctx.base_url, ctx.tx.id),
                }]
            };

            // The transcript is interop-diagnostic gold — without it a real
            // wallet's Device Signature cannot be reproduced offline — but it
            // commits to `tx.nonce`. Gated on BOTH sensitive_enabled() AND
            // trace per root AGENTS.md §4.5: a level is not authorisation.
            //
            // Emitted HERE, before any verification, and never from inside the
            // candidate loop below. The presentations that most need
            // reproducing offline are the ones that fail — a test-PKI or expired
            // issuer chain (design doc §8) — and those return from
            // `verify_issuer_signed` below. A diagnostic conditioned on the
            // verdict it exists to explain is no diagnostic at all.
            if foundry_core::obs::sensitive_enabled() {
                for params in &candidates {
                    if let Ok(encoded) = build_session_transcript(params) {
                        tracing::trace!(
                            session_transcript = %hex::encode(&encoded),
                            "SENSITIVE: candidate mdoc SessionTranscript"
                        );
                    }
                }
            }

            // The issuer half does not depend on the Origin, so it runs ONCE.
            // Only the Device Signature commits to a SessionTranscript, so only
            // that check is retried per candidate. Before this, each candidate
            // Origin re-ran full chain validation, MSO validity and digest
            // matching just to retry one signature.
            let issuer =
                foundry_mdoc::verifier::verify_issuer_signed(&resp, ctx.trust_store, ctx.now_unix)
                    .map_err(|e| {
                        VerificationError::Failed(format!("mdoc verification failed: {e}"))
                    })?;

            // Now authenticated: this docType comes from the signed MSO, and may
            // differ from the envelope copy read above, which nothing commits to.
            *credential_type = Some(issuer.doc_type.clone());

            let mut accepted = false;
            let mut last_err = None;
            for params in &candidates {
                let session_transcript = session_transcript_value(params)
                    .map_err(|e| VerificationError::Failed(format!("SessionTranscript: {e}")))?;

                match foundry_mdoc::verifier::verify_device_auth(
                    &resp,
                    &session_transcript,
                    &issuer.device_key_x,
                    &issuer.device_key_y,
                ) {
                    Ok(()) => {
                        accepted = true;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(VerificationError::Failed(format!(
                            "mdoc verification failed: {e}"
                        )))
                    }
                }
            }

            if !accepted {
                // `candidates` is never empty, so `last_err` is always populated
                // here. The fallback exists only so this cannot become a panic if
                // that ever stops holding.
                return Err(last_err.unwrap_or_else(|| {
                    VerificationError::Failed(
                        "mdoc verification failed: no SessionTranscript candidate".to_string(),
                    )
                }));
            }

            let mdoc_res = foundry_mdoc::verifier::MdocVerificationResult {
                claims: issuer.claims,
                device_key_jwk: issuer.device_key_jwk,
                issuer_x5c: Some(issuer.issuer_x5c),
                doc_type: issuer.doc_type,
            };

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

    Ok(FormatStage {
        claims: disclosed_claims,
        kb_jwt_payload,
        doc_type,
    })
}

/// Name the credential query a per-credential error belongs to, without
/// changing the error's kind.
///
/// With N credentials a bare "mdoc verification failed" does not say whose. A
/// DCQL credential query id is operator-authored request structure, not a holder
/// value, so naming it is safe (root AGENTS.md §4.5) -- the status-unavailability
/// path already did exactly this.
///
/// `error.kind` is operator-facing API that operators alert on (§4.5), so a
/// variant is never swapped for a more convenient one. The three
/// `#[error(transparent)]` variants wrap a foreign error whose `Display` is the
/// whole message and have no field to prefix, so they are returned unchanged;
/// the per-credential log record names the credential in those cases.
///
/// Exhaustive with no catch-all, for the same reason `check_name_for` is: a new
/// variant should be a deliberate decision, not a silent fallthrough.
fn with_credential_context(query_id: &str, err: VerificationError) -> VerificationError {
    let prefixed = |detail: String| format!("credential query '{query_id}': {detail}");
    match err {
        VerificationError::Failed(d) => VerificationError::Failed(prefixed(d)),
        VerificationError::StatusUnavailable(d) => {
            VerificationError::StatusUnavailable(prefixed(d))
        }
        VerificationError::Crypto(d) => VerificationError::Crypto(prefixed(d)),
        VerificationError::Dcql(d) => VerificationError::Dcql(prefixed(d)),
        VerificationError::Decryption(d) => VerificationError::Decryption(prefixed(d)),
        VerificationError::Serialization(d) => VerificationError::Serialization(prefixed(d)),
        VerificationError::NotFound(d) => VerificationError::NotFound(prefixed(d)),
        VerificationError::InvalidState(d) => VerificationError::InvalidState(prefixed(d)),
        VerificationError::InvalidRequest(d) => VerificationError::InvalidRequest(prefixed(d)),
        e @ (VerificationError::Storage(_)
        | VerificationError::CoreCrypto(_)
        | VerificationError::Trust(_)) => e,
    }
}

/// Verify one credential from a `vp_token` and collect its checks.
///
/// **Returns no `Result`, deliberately.** Root AGENTS.md §4.2 defines `verified`
/// as the conjunction of the checks performed, which is only meaningful when
/// they were all performed, and "PID signature bad, mDL fine" is a far more
/// useful operator verdict than "PID signature bad, mDL unknown". That was
/// already the documented intent; it was not the behaviour, because this
/// function returned `Result` and its caller reached for `?`. The type won the
/// argument with the comment. A non-`Result` return makes the defect
/// unrepresentable rather than merely commented against.
///
/// The accompanying `Option<VerificationError>` is how a failure still reaches
/// the HTTP layer: a bad signature is a structural failure and must stay a 400
/// (root AGENTS.md §4.3), never a policy `200 verified:false`. The caller parks
/// it, finishes the loop, and returns it after every credential has a verdict.
async fn verify_one_credential(
    ctx: &CredentialVerifyCtx<'_>,
    query_id: &str,
    selected: SelectedPresentation<'_>,
    resolver: &dyn StatusListResolver,
) -> (PresentedCredential, Option<VerificationError>) {
    let presented_format = selected.format();
    let format = match presented_format {
        PresentedFormat::SdJwtVc => "dc+sd-jwt",
        PresentedFormat::MsoMdoc => "mso_mdoc",
    };
    // The format's own check name, per root AGENTS.md §4.2's closed
    // per-credential vocabulary. Every failure in the signature stage is
    // recorded under it, with the real reason in `detail`.
    let format_check = match presented_format {
        PresentedFormat::SdJwtVc => "sd_jwt_vc_signature_and_kb_jwt",
        PresentedFormat::MsoMdoc => "mdoc_issuer_auth_and_device_signature",
    };

    let mut checks: Vec<CheckResult> = Vec::new();
    let mut credential_type: Option<String> = None;

    let stage = match verify_credential_payload(ctx, selected, &mut credential_type).await {
        Ok(stage) => {
            checks.push(CheckResult {
                check: format_check.to_string(),
                passed: true,
                detail: None,
            });
            stage
        }
        Err(err) => {
            checks.push(CheckResult {
                check: format_check.to_string(),
                passed: false,
                detail: Some(foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX)),
            });
            // The remaining checks are SKIPPED, not run against empty claims.
            // `dcql_match: false` and `status_check: false` would report three
            // failures where one occurred, two of them misattributed: "DCQL
            // mismatch" when the truth is "we never obtained claims".
            return (
                PresentedCredential {
                    query_id: query_id.to_string(),
                    format: format.to_string(),
                    credential_type,
                    claims: Value::Object(serde_json::Map::new()),
                    checks,
                },
                Some(with_credential_context(query_id, err)),
            );
        }
    };

    let claims_value = Value::Object(stage.claims);
    let kb_jwt_payload = stage.kb_jwt_payload;
    let doc_type = stage.doc_type;

    // Transaction Data binding (OpenID4VP L1523/L3144), only when the Verifier
    // requested transaction_data for this transaction. Already multi-credential
    // aware: it filters entries by whether their `credential_ids` array contains
    // this credential's query id, so an entry scoped elsewhere imposes nothing
    // here.
    if let Some(ref entries) = ctx.tx.transaction_data {
        match &kb_jwt_payload {
            Some(kb_payload) => {
                checks.push(check_transaction_data_binding(
                    entries, query_id, kb_payload,
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

    // DCQL satisfaction, bound to the credential query this presentation
    // ANSWERED -- not to any query of the presented format, so a presentation
    // cannot be credited against a query it does not answer.
    checks.push(check_dcql_match(
        &ctx.tx.dcql_query,
        query_id,
        presented_format,
        &claims_value,
        doc_type.as_deref(),
    ));

    // Token Status List revocation, against THIS credential's claims. Handing it
    // a map merged across credentials would read one credential's
    // `status.status_list` while reporting another's verdict.
    //
    // Unavailability is NOT a policy failure -- "I could not determine whether
    // this is revoked" is not "this is revoked" -- so no `status_check` record is
    // pushed and the fault travels as an error for the caller's precedence rule
    // to weigh. Every other `check_status` error travels the same way: before
    // verify-all only `StatusUnavailable` was parked and the rest propagated with
    // `?`, which is exactly the fail-fast this function's return type now forbids.
    let mut deferred: Option<VerificationError> = None;
    match check_status(&claims_value, ctx.trust_store, resolver, ctx.now_unix).await {
        Ok(check) => checks.push(check),
        Err(err) => deferred = Some(with_credential_context(query_id, err)),
    }

    let credential = PresentedCredential {
        query_id: query_id.to_string(),
        format: format.to_string(),
        credential_type,
        claims: claims_value,
        checks,
    };

    (credential, deferred)
}

/// Did the wallet answer every credential query the request asked for?
///
/// OpenID4VP 1.0 L993: with `credential_sets` absent -- the only case foundry
/// implements -- "the Verifier requests presentations for all Credentials in
/// `credentials`", so every credential query is non-optional. L1007-1008: "If
/// the Wallet cannot deliver all non-optional Credentials requested by the
/// Verifier according to these rules, it MUST NOT return any Credential(s)."
///
/// A subset `vp_token` is therefore a **wallet MUST-violation**. It is
/// nonetheless reported as a policy verdict (HTTP 200, `verified: false`) rather
/// than a structural 400: the spec constrains the wallet here, not the
/// verifier's status code; the response is well-formed, so root AGENTS.md §4.3's
/// structural category does not fit; and naming the missing credential query is
/// far more actionable for whoever has to diagnose the wallet than an opaque
/// `invalid_request`.
///
/// Never returns `Err` -- fail-closed, matching `check_dcql_match`.
fn check_requested_credentials_answered(
    dcql_query: &Value,
    answered: &[PresentedCredential],
) -> CheckResult {
    const CHECK: &str = "requested_credentials_answered";

    let query: DcqlQuery = match serde_json::from_value(dcql_query.clone()) {
        Ok(q) => q,
        // Not reachable through the request path -- `select_presentations` has
        // already parsed this query successfully, and `create_verification_request`
        // validated it before persisting. Fail closed rather than pass on a query
        // this function cannot read.
        Err(e) => {
            let reason = format!("dcql_query is not a valid DCQL query: {e}");
            tracing::warn!(check = CHECK, reason = %reason, "cannot evaluate requested credentials");
            return CheckResult {
                check: CHECK.to_string(),
                passed: false,
                detail: Some(reason),
            };
        }
    };

    let missing: Vec<&str> = query
        .credentials()
        .iter()
        .map(|cq| cq.id())
        .filter(|id| !answered.iter().any(|c| c.query_id == *id))
        .collect();

    if missing.is_empty() {
        return CheckResult {
            check: CHECK.to_string(),
            passed: true,
            detail: None,
        };
    }

    // Attribute the fault to the wallet. Without this an operator reads the
    // failure as foundry having asked for something unusual, when in fact
    // L1007-1008 required the wallet to return nothing at all rather than a
    // partial set. Credential query ids are operator-authored request structure,
    // not holder values, so naming them is safe (root AGENTS.md §4.5).
    let reason = format!(
        "wallet returned no presentation for credential query [{}]; OpenID4VP 1.0 \
         requires a wallet that cannot deliver all non-optional Credentials to \
         return none at all, so this response is not conformant",
        missing.join(", ")
    );
    tracing::warn!(check = CHECK, reason = %reason, "not every requested credential was answered");
    CheckResult {
        check: CHECK.to_string(),
        passed: false,
        detail: Some(reason),
    }
}

/// What `do_verify_vp_response` produces: always a result, plus optionally an
/// error that still has to reach the wallet as a status code.
///
/// A per-credential failure still has to reach the wallet as a status code --
/// a bad signature is a structural 400 and a status-list fetch failure a network
/// 502, never a policy `passed: false` (root AGENTS.md §4.3). But propagating it
/// with `?` from inside the per-credential loop would throw away every check
/// already collected, and the wrapper's `Err` arm would rebuild `tx.result` from
/// scratch -- leaving the operator with none of the other credentials' verdicts,
/// which is the whole reason a precise status code is worth having. So the error
/// travels beside the result instead of replacing it.
struct VerifyOutcome {
    result: VerificationResult,
    /// Any per-credential error, not just `StatusUnavailable`.
    ///
    /// It carried only `StatusUnavailable` while every other per-credential
    /// error short-circuited the loop with `?` -- which is exactly the fail-fast
    /// defect `verify_one_credential`'s return type now forbids. When several
    /// credentials failed this is the ONE the wallet is told about, chosen by the
    /// precedence rule in step 5b; every fault is recorded in `result`
    /// regardless, so choosing a winner here cannot lose one.
    deferred: Option<VerificationError>,
}

#[tracing::instrument(skip_all)]
async fn do_verify_vp_response(
    config: &Config,
    tx: &VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
) -> Result<VerifyOutcome, VerificationError> {
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
        let origins: Vec<String> = if config.verifier.dc_api_expected_origins.is_empty() {
            tracing::debug!(
                fallback_origin = %base_url,
                "verifier.dc_api_expected_origins is unset; falling back to an origin derived \
                 from public_base_url"
            );
            vec![base_url.to_string()]
        } else {
            config.verifier.dc_api_expected_origins.clone()
        };

        // OpenID4VP **draft 24** Appendix A.2 derived the effective Client
        // Identifier of an unsigned DC API request from "a synthetic Client
        // Identifier Scheme of `web-origin` and the Origin itself", and its
        // KB-JWT `aud` was that Client Identifier -- so a draft-24 wallet
        // signs `web-origin:<origin>` where 1.0 (L618, L2543) says
        // `origin:<origin>`. Wallets still implementing draft 24 are in the
        // field, so an operator may opt into the older spelling. The
        // accommodation adds a prefix to the accepted set and never an
        // Origin: `origins` above is still the whole allow-list, so an
        // unlisted Origin stays rejected under either prefix and the
        // audience-binding property L2543 exists to provide is preserved.
        let mut audiences = Vec::with_capacity(origins.len() * 2);
        for origin in &origins {
            audiences.push(format!("origin:{origin}"));
            if config.verifier.dc_api_accept_legacy_web_origin_audience {
                audiences.push(format!("{LEGACY_WEB_ORIGIN_PREFIX}{origin}"));
            }
        }
        audiences
    } else {
        vec![client_id.clone()]
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| VerificationError::Crypto(e.to_string()))?
        .as_secs();

    // 3. Per-credential verification. Verify-all, never fail-fast: root
    //    AGENTS.md §4.2 defines `verified` as the conjunction of the checks
    //    performed, which is only meaningful when they were all performed, and
    //    "PID signature bad, mDL fine" is a far more useful operator verdict
    //    than "PID signature bad, mDL unknown".
    //
    //    This is enforced by `verify_one_credential`'s return type, not by this
    //    comment. It previously returned `Result` and this loop used `?`, so the
    //    comment described an intent the type defeated.
    let selected = select_presentations(vp_token, &tx.dcql_query)?;
    let ctx = CredentialVerifyCtx {
        config,
        tx,
        trust_store: &trust_store,
        expected_audiences: &expected_audiences,
        now_unix,
        base_url,
        client_id: &client_id,
    };

    let mut credentials = Vec::with_capacity(selected.len());
    // EVERY credential's failure, not just the one that decides the response.
    //
    // Keeping only the winner loses information: a status-list unavailability
    // pushes no per-credential `status_check` (unavailability is not a policy
    // verdict), so if a crypto failure outranks it for the returned error, the
    // unavailability would be recorded absolutely nowhere -- neither on its
    // credential nor at the top level. Precedence decides the HTTP status; it
    // must not decide what gets reported.
    let mut faults: Vec<VerificationError> = Vec::new();

    for (query_id, payload) in selected {
        let (credential, err) = verify_one_credential(&ctx, &query_id, payload, resolver).await;
        credentials.push(credential);
        if let Some(err) = err {
            faults.push(err);
        }
    }

    // 4. Set-level policy: did every requested credential query get answered?
    checks.push(check_requested_credentials_answered(
        &tx.dcql_query,
        &credentials,
    ));

    // 5. A credential whose status fetch was unavailable pushed NO status_check
    //    record, because unavailability is not a policy failure. On its own that
    //    leaves the conjunction computing `true` and persists `verified: true` on
    //    a transaction that returned 502 -- a lie the admin console would render
    //    faithfully. Record the fault as a check so the verdict stays derived and
    //    honest, exactly as the wrapper's error arm already does.
    //
    //    StatusUnavailable ONLY. Every other per-credential failure already has
    //    a per-credential record from `verify_one_credential`, so adding a
    //    top-level one would double-count one fault and inflate `failed_checks`.
    //    One record per unavailability, and ONLY for unavailability -- every
    //    other per-credential failure already has a per-credential record from
    //    `verify_one_credential`, so a top-level copy would double-count one
    //    fault and inflate `failed_checks`.
    for err in faults
        .iter()
        .filter(|e| matches!(e, VerificationError::StatusUnavailable(_)))
    {
        checks.push(CheckResult {
            check: check_name_for(err).to_string(),
            passed: false,
            detail: Some(foundry_core::obs::truncate(&err.to_string(), DETAIL_MAX)),
        });
    }

    // 5b. Pick the ONE error that decides the response. Precedence (root
    //     AGENTS.md §4.3): a structural/crypto failure (400) outranks a
    //     status-list unavailability (502), because a bad signature is
    //     deterministic and answering 502 would invite the wallet to retry a
    //     presentation that can never succeed. Within one class the incumbent
    //     wins, so the first credential in DCQL declaration order is reported.
    //
    //     This decides only what the WALLET is told. Step 5 has already recorded
    //     every unavailability for the operator, so choosing a winner here can no
    //     longer make a fault disappear -- which it did when a single slot held
    //     both roles.
    let deferred = faults.into_iter().reduce(|incumbent, challenger| {
        let incumbent_is_status = matches!(incumbent, VerificationError::StatusUnavailable(_));
        let challenger_is_status = matches!(challenger, VerificationError::StatusUnavailable(_));
        if incumbent_is_status && !challenger_is_status {
            challenger
        } else {
            incumbent
        }
    });

    // 6. Overall verdict: the conjunction over EVERY check, at both levels
    //    (root AGENTS.md §4.2). Derived, never assigned.
    let mut result = VerificationResult {
        verified: false,
        checks,
        credentials,
    };
    result.verified = result.derive_verified();

    Ok(VerifyOutcome { result, deferred })
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
    use foundry_mdoc::builder::{MdocClaims, build_mdoc};
    use foundry_sd_jwt_vc::builder::{
        IssuerClaims, TransactionDataBinding, attach_kb_jwt, build_sd_jwt_vc,
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
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                key_attestation: AttestationMode {
                    mode: Mode::Disabled,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: None,
                    list_size: Some(131072),
                    public_base_url: None,
                },
                dpop: DpopConfig::default(),
                request_encryption: None,
                response_encryption: None,
                encrypted_pre_authorized_code: Default::default(),
                access_token_ttl_secs: 600,
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
                dc_api_accept_legacy_web_origin_audience: false,
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
            sub: None,
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
        assert_eq!(res.credentials[0].claims["given_name"], "Alice");
        assert!(
            res.all_checks()
                .any(|c| c.check == "jwe_decryption" && c.passed)
        );
        assert!(
            res.all_checks()
                .any(|c| c.check == "sd_jwt_vc_signature_and_kb_jwt" && c.passed)
        );
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
            sub: None,
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
            sub: None,
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
            res.all_checks()
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
            sub: None,
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
            res.all_checks()
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
            sub: None,
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
        assert!(
            res.all_checks()
                .any(|c| c.check == "transaction_data_binding" && !c.passed)
        );
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
            sub: None,
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
        assert!(
            res.all_checks()
                .any(|c| c.check == "transaction_data_binding" && !c.passed)
        );
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
            sub: None,
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
        assert!(
            !res.all_checks()
                .any(|c| c.check == "transaction_data_binding")
        );
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
            sub: None,
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
        assert_eq!(result.all_checks().count(), 1, "checks={:?}", result.checks);
        let check = &result.checks[0];
        assert_eq!(check.check, "jwe_decryption");
        assert!(!check.passed);
        let detail = check.detail.as_deref().expect("detail must be present");
        assert!(!detail.is_empty());

        // Root AGENTS.md §4.2: `verified` is derived, never hardcoded.
        assert_eq!(
            result.verified,
            result.all_checks().all(|c| c.passed),
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
            sub: None,
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
            sub: None,
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
        let dcql = res.all_checks().find(|c| c.check == "dcql_match").unwrap();
        assert!(!dcql.passed);
        // The signature check still passed and is still reported for transparency.
        assert!(
            res.all_checks()
                .any(|c| c.check == "sd_jwt_vc_signature_and_kb_jwt" && c.passed)
        );
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
            sub: None,
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
            sub: None,
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
        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        // Build what a wallet sends: one base64url DeviceResponse whose
        // DeviceSignature covers DeviceAuthenticationBytes.
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        // Envelope + JWE.
        let jwe_str = encrypt_compact(
            &serde_json::json!({
                "vp_token": { "c1": [B64URL.encode(&device_response)] }
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

        assert!(res.verified, "checks={:?}", res.checks);
        assert_eq!(
            res.credentials[0].claims["org.iso.18013.5.1"]["given_name"],
            "John"
        );
        assert!(
            res.all_checks()
                .any(|c| c.check == "mdoc_issuer_auth_and_device_signature" && c.passed)
        );
        assert!(
            res.all_checks()
                .any(|c| c.check == "dcql_match" && c.passed)
        );
        assert!(
            res.all_checks()
                .any(|c| c.check == "status_check" && c.passed)
        );
    }

    /// Collects the fields of every event, so a test can assert that a
    /// diagnostic was emitted at all. Deliberately minimal: `crates/foundry`'s
    /// `logging_redaction.rs` owns the full redaction harness (root `AGENTS.md`
    /// §4.5); this proves one positive property about one record.
    #[derive(Clone, Default)]
    struct FieldCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl FieldCapture {
        fn contains(&self, needle: &str) -> bool {
            self.0
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.contains(needle))
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for FieldCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visitor<'a>(&'a mut String);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, " {}={:?}", field.name(), value);
                }
            }
            let mut line = String::new();
            event.record(&mut Visitor(&mut line));
            self.0.lock().unwrap().push(line);
        }
    }

    /// Build an mdoc presentation whose issuer chain roots at a CA the config
    /// does **not** trust, and run it through `verify_vp_response`. Identical to
    /// `test_verify_vp_response_mdoc_presentation` in every respect except the
    /// anchor mismatch, so the only reason it can fail is issuer trust.
    async fn run_unanchored_mdoc_presentation() -> Result<VerificationResult, VerificationError> {
        run_unanchored_mdoc_presentation_with_tx().await.0
    }

    /// The PERSISTED result of the same presentation.
    ///
    /// That is what an operator sees in the admin console, and it is reachable
    /// only through `tx.result`: the call itself returns `Err`, because an
    /// unanchored issuer chain is a structural failure (root AGENTS.md §4.3).
    async fn run_unanchored_mdoc_presentation_reporting_result() -> VerificationResult {
        let (_, tx) = run_unanchored_mdoc_presentation_with_tx().await;
        tx.result
            .expect("the result is persisted even on the error path")
    }

    /// The shared body of the two helpers above, handing back the mutated
    /// transaction as well as the call's own outcome. One fixture rather than two
    /// copies: a duplicated PKI/mdoc/transcript construction would be free to
    /// drift, and then "identical except the anchor mismatch" would stop being
    /// true without anything failing.
    async fn run_unanchored_mdoc_presentation_with_tx() -> (
        Result<VerificationResult, VerificationError>,
        VerificationTransaction,
    ) {
        // Two independent CAs: the trust store carries #1, the credential is
        // signed under #2's leaf.
        let (trusted_root_pem, _, _) = test_pki();
        let (_, foreign_leaf_cert, foreign_leaf_key) = test_pki();
        let ca_str = String::from_utf8(trusted_root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer =
            FileSigner::from_pem(&foreign_leaf_key, SignatureAlgorithm::Es256).unwrap();

        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
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
            Some(vec![der_b64(&foreign_leaf_cert)]),
        )
        .unwrap();

        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({
                "vp_token": { "c1": [B64URL.encode(&device_response)] }
            }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver).await;
        (res, tx)
    }

    /// The candidate `SessionTranscript` diagnostic MUST survive an issuer-trust
    /// failure.
    ///
    /// Without it there is no way to reproduce a real wallet's Device Signature
    /// offline, and the wallets whose presentations most need reproducing are
    /// exactly the ones foundry cannot yet trust — a test PKI, or an expired DS
    /// certificate (design doc §8). When the emission sat inside the candidate
    /// retry loop, which runs only after `verify_issuer_signed(..)?`, capturing
    /// the golden fixture of design doc §9 was impossible: the record an
    /// operator needed was suppressed by the very verdict it was meant to
    /// explain.
    ///
    /// A diagnostic must not be conditional on the outcome it diagnoses.
    #[tokio::test]
    async fn the_session_transcript_diagnostic_survives_an_issuer_trust_failure() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = FieldCapture::default();
        let subscriber = tracing_subscriber::Registry::default()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(capture.clone());

        foundry_core::obs::set_sensitive(true);
        let guard = tracing::subscriber::set_default(subscriber);
        let res = run_unanchored_mdoc_presentation().await;
        drop(guard);
        // Process-global: restore before asserting, so a failure cannot leave
        // the flag on for whatever runs next in this process.
        foundry_core::obs::set_sensitive(false);

        let err = res.expect_err("an unanchored issuer chain must be rejected");
        assert!(
            err.to_string().contains("trust anchor"),
            "expected an anchor failure, got: {err}"
        );
        assert!(
            capture.contains("session_transcript"),
            "the candidate SessionTranscript was not logged; it is emitted only \
             after the issuer check, so the golden fixture of design doc §9 \
             cannot be captured from any wallet foundry does not already trust"
        );
    }

    /// The negative control for the test above: the transcript commits to
    /// `tx.nonce`, so it stays locked unless payload logging is explicitly
    /// unlocked. A `trace` level alone is not authorisation (root `AGENTS.md`
    /// §4.5).
    #[tokio::test]
    async fn the_session_transcript_diagnostic_stays_locked_by_default() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = FieldCapture::default();
        let subscriber = tracing_subscriber::Registry::default()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(capture.clone());

        foundry_core::obs::set_sensitive(false);
        let guard = tracing::subscriber::set_default(subscriber);
        let res = run_unanchored_mdoc_presentation().await;
        drop(guard);

        res.expect_err("an unanchored issuer chain must be rejected");
        assert!(
            !capture.contains("session_transcript"),
            "the SessionTranscript was logged with payload logging disabled"
        );
        // Proves the assertion above is not vacuous: something was captured.
        assert!(
            capture.contains("step"),
            "captured no events at all, so the negative assertion proves nothing"
        );
    }

    // --- Multi-credential verification (Task 4) ---

    /// Build an SD-JWT VC presentation disclosing `disclose`, bound to `tx`'s
    /// nonce and the redirect-transport audience. Each call mints its own holder
    /// key, so the credentials are independently key-bound exactly as two
    /// separately-issued credentials would be.
    fn sd_jwt_presentation_for(
        config: &Config,
        tx: &VerificationTransaction,
        leaf_cert: &[u8],
        issuer_signer: &FileSigner,
        disclose: &[(&str, serde_json::Value)],
    ) -> String {
        let (holder_signer, holder_pub) = holder();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut select = serde_json::Map::new();
        for (k, v) in disclose {
            select.insert((*k).to_string(), v.clone());
        }

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: None,
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
            build_sd_jwt_vc(claims, issuer_signer, Some(vec![der_b64(leaf_cert)])).unwrap();
        let client_id = expected_client_id(config);
        attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &tx.nonce, None).unwrap()
    }

    fn two_sd_jwt_tx() -> (VerificationTransaction, Jwk) {
        let (mut tx, pub_jwk) = sample_tx();
        tx.dcql_query = serde_json::json!({"credentials": [
            {"id": "pid", "format": "dc+sd-jwt"},
            {"id": "diploma", "format": "dc+sd-jwt"}
        ]});
        (tx, pub_jwk)
    }

    /// Two credentials in one `vp_token` both verify, and each appears as its own
    /// record in DCQL declaration order.
    #[tokio::test]
    async fn verifies_two_credentials_in_one_vp_token() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let pid = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );
        let diploma = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("degree", serde_json::json!("MSc"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid], "diploma": [diploma]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .unwrap();

        assert!(res.verified, "both credentials are valid: {:?}", res.checks);
        assert_eq!(res.credentials.len(), 2);
        assert_eq!(res.credentials[0].query_id, "pid");
        assert_eq!(res.credentials[1].query_id, "diploma");
        assert_eq!(res.credentials[0].claims["given_name"], "Alice");
        assert_eq!(res.credentials[1].claims["degree"], "MSc");
        assert_eq!(tx.state, VerificationState::Verified);
    }

    /// The asserted credential type is surfaced as its own field, so a log line
    /// and the admin console can name a credential without the reader parsing
    /// the claims blob. For SD-JWT VC that is `vct`.
    #[tokio::test]
    async fn credential_type_is_the_vct_for_an_sd_jwt_vc() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let pid = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );
        let diploma = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("degree", serde_json::json!("MSc"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid], "diploma": [diploma]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .unwrap();

        // `sd_jwt_presentation_for` mints both credentials with this vct.
        assert_eq!(
            res.credentials[0].credential_type.as_deref(),
            Some("https://localhost:8443/vct/pid")
        );
        assert_eq!(
            res.credentials[1].credential_type.as_deref(),
            Some("https://localhost:8443/vct/pid")
        );
    }

    /// For `mso_mdoc` the asserted credential type is the `docType`, and on the
    /// success path it is the **authenticated** one from the MSO rather than the
    /// unverified copy read from the DeviceResponse envelope.
    #[tokio::test]
    async fn credential_type_is_the_doctype_for_an_mdoc() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
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
            Some(vec![der_b64(&leaf_cert)]),
        )
        .unwrap();

        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({
                "vp_token": { "c1": [B64URL.encode(&device_response)] }
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

        assert_eq!(
            res.credentials[0].credential_type.as_deref(),
            Some("org.iso.18013.5.1.mDL")
        );
    }

    /// The helper reads the ISSUER-SIGNED JWT's payload, which is everything
    /// before the first `~` in the compact SD-JWT serialization. Disclosures and
    /// the KB-JWT follow and must not be mistaken for it.
    #[test]
    fn asserted_vct_reads_the_issuer_jwt_payload_and_never_errors() {
        let payload = B64URL.encode(br#"{"vct":"com.emvco.dpc.card","iss":"x"}"#);
        let presentation = format!("aGVhZGVy.{payload}.c2ln~WyJzYWx0IiwiYSIsMV0~a2I.a2I.a2I");
        assert_eq!(
            asserted_vct_unverified(&presentation).as_deref(),
            Some("com.emvco.dpc.card")
        );

        // Every malformed shape yields None rather than an error: this is a
        // diagnostic and must never be able to change a verdict.
        assert_eq!(asserted_vct_unverified(""), None);
        assert_eq!(asserted_vct_unverified("not-a-jwt"), None);
        assert_eq!(asserted_vct_unverified("a.!!!not-base64!!!.c"), None);
        let no_vct = B64URL.encode(br#"{"iss":"x"}"#);
        assert_eq!(asserted_vct_unverified(&format!("a.{no_vct}.c")), None);
    }

    /// The reported defect, pinned. A two-credential `vp_token` where the mdoc's
    /// issuer chain has no configured trust anchor must still report the SD-JWT
    /// VC credential's passing verdict.
    ///
    /// Before this, `verify_one_credential`'s error propagated through `?` and
    /// abandoned the loop, so the credential verified FIRST -- which had already
    /// passed -- was discarded along with it, and the only log line named
    /// neither credential. The comment above the loop claimed verify-all; the
    /// return type said fail-fast, and the type won.
    #[tokio::test]
    async fn one_credentials_bad_chain_does_not_hide_anothers_passing_verdict() {
        // The trust store carries CA #1; the mdoc is signed under CA #2's leaf,
        // while the SD-JWT VC is signed under CA #1's -- so exactly one
        // credential is untrusted and nothing else differs.
        let (trusted_root_pem, trusted_leaf_cert, trusted_leaf_key) = test_pki();
        let (_, foreign_leaf_cert, foreign_leaf_key) = test_pki();
        let ca_str = String::from_utf8(trusted_root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let trusted_signer =
            FileSigner::from_pem(&trusted_leaf_key, SignatureAlgorithm::Es256).unwrap();
        let foreign_signer =
            FileSigner::from_pem(&foreign_leaf_key, SignatureAlgorithm::Es256).unwrap();

        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // `sd` is declared first, so DCQL declaration order verifies it before
        // the failing mdoc -- reproducing the original ordering exactly.
        tx.dcql_query = serde_json::json!({
            "credentials": [
                { "id": "sd", "format": "dc+sd-jwt" },
                {
                    "id": "md",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
                }
            ]
        });

        let sd = sd_jwt_presentation_for(
            &config,
            &tx,
            &trusted_leaf_cert,
            &trusted_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
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
            &foreign_signer,
            Some(vec![der_b64(&foreign_leaf_cert)]),
        )
        .unwrap();

        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {
                "sd": [sd],
                "md": [B64URL.encode(&device_response)],
            }}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .expect_err("an unanchored issuer chain is a structural failure (§4.3 -> 400)");

        // §4.3: still a crypto failure, so still the 400 class -- not a policy
        // 200. The verdict on the wire does not change; what changes is what an
        // operator can see.
        assert_eq!(err.kind(), "failed", "got: {err}");
        // The message names the credential it belongs to.
        assert!(
            err.to_string().contains("credential query 'md'"),
            "the error must name the credential: {err}"
        );

        // The whole point: BOTH credentials are reported.
        let result = tx.result.as_ref().expect("the result must be persisted");
        assert!(!result.verified, "a failed credential fails the response");
        assert_eq!(result.credentials.len(), 2, "every credential is reported");

        let sd_cred = &result.credentials[0];
        assert_eq!(sd_cred.query_id, "sd");
        assert!(
            sd_cred.checks.iter().all(|c| c.passed),
            "the trusted credential's verdict must survive its neighbour's failure: {:?}",
            sd_cred.checks
        );
        assert_eq!(
            sd_cred.credential_type.as_deref(),
            Some("https://localhost:8443/vct/pid")
        );

        let md_cred = &result.credentials[1];
        assert_eq!(md_cred.query_id, "md");
        assert_eq!(
            md_cred.credential_type.as_deref(),
            Some("org.iso.18013.5.1.mDL"),
            "a failed credential must still be nameable"
        );
        assert_eq!(
            md_cred.checks.len(),
            1,
            "a failed format check short-circuits the rest: {:?}",
            md_cred.checks
        );
        assert_eq!(
            md_cred.checks[0].check,
            "mdoc_issuer_auth_and_device_signature"
        );
        assert!(!md_cred.checks[0].passed);
        assert!(
            md_cred.checks[0]
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("trust anchor"),
            "the real reason belongs in detail: {:?}",
            md_cred.checks[0].detail
        );
        assert_eq!(tx.state, VerificationState::Failed);
    }

    /// A credential whose format check failed records exactly that one check.
    ///
    /// Running `dcql_match` and `status_check` against the empty claims map
    /// would report three failures where one occurred, two of them
    /// misattributed: "DCQL mismatch" when the truth is "we never obtained
    /// claims". And the top-level `checks` list gains no fault record, because
    /// the per-credential one already represents this fault -- recording both
    /// would double-count it.
    #[tokio::test]
    async fn a_failed_format_check_short_circuits_without_double_counting() {
        let result = run_unanchored_mdoc_presentation_reporting_result().await;

        assert!(!result.verified);
        assert_eq!(result.credentials.len(), 1);
        let checks = &result.credentials[0].checks;
        assert_eq!(checks.len(), 1, "only the format check: {checks:?}");
        assert!(
            !checks.iter().any(|c| c.check == "dcql_match"),
            "dcql_match must not run on claims that were never obtained"
        );
        assert!(
            !checks.iter().any(|c| c.check == "status_check"),
            "status_check must not run on claims that were never obtained"
        );

        // Cross-cutting checks: jwe_decryption and requested_credentials_answered
        // only. No top-level fault record, which would double-count.
        let top: Vec<&str> = result.checks.iter().map(|c| c.check.as_str()).collect();
        assert_eq!(
            top,
            vec!["jwe_decryption", "requested_credentials_answered"],
            "the top-level deferred-fault record is StatusUnavailable-only"
        );
        assert_eq!(
            result.all_checks().filter(|c| !c.passed).count(),
            1,
            "exactly one failure is counted"
        );
    }

    /// Root AGENTS.md §4.3, made explicit. With one credential's chain untrusted
    /// (a crypto failure -> 400) and another's status list unreachable (a
    /// network fault -> 502), the response can carry only one status. The crypto
    /// failure wins: it is deterministic, so answering 502 would invite the
    /// wallet to retry a presentation that can never succeed.
    ///
    /// Before verify-all this was decided by accident -- `?` returned the crypto
    /// error immediately while StatusUnavailable was parked in `deferred`.
    #[tokio::test]
    async fn a_crypto_failure_outranks_an_unreachable_status_list() {
        let (trusted_root_pem, trusted_leaf_cert, trusted_leaf_key) = test_pki();
        let (_, foreign_leaf_cert, foreign_leaf_key) = test_pki();
        let ca_str = String::from_utf8(trusted_root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let trusted_signer =
            FileSigner::from_pem(&trusted_leaf_key, SignatureAlgorithm::Es256).unwrap();
        let foreign_signer =
            FileSigner::from_pem(&foreign_leaf_key, SignatureAlgorithm::Es256).unwrap();

        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // The SD-JWT is declared FIRST and is the one whose status list is
        // unreachable, so its StatusUnavailable is parked before the mdoc's
        // crypto failure is seen. That ordering is what makes this a real
        // precedence test rather than a first-wins test.
        tx.dcql_query = serde_json::json!({
            "credentials": [
                { "id": "sd", "format": "dc+sd-jwt" },
                {
                    "id": "md",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
                }
            ]
        });

        // A `status.status_list` claim makes `check_status` call the resolver,
        // and `MockResolver { token: None }` answers StatusUnavailable.
        let (holder_signer, holder_pub) = holder();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let sd_claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: None,
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: Some(7),
            status_list_uri: Some("https://localhost:8443/statuslists/1".to_string()),
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let sd_issued = build_sd_jwt_vc(
            sd_claims,
            &trusted_signer,
            Some(vec![der_b64(&trusted_leaf_cert)]),
        )
        .unwrap();
        let sd = attach_kb_jwt(
            sd_issued,
            &holder_signer,
            &expected_client_id(&config),
            &tx.nonce,
            None,
        )
        .unwrap();

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
            &foreign_signer,
            Some(vec![der_b64(&foreign_leaf_cert)]),
        )
        .unwrap();
        let transcript = session_transcript_value(&SessionTranscriptParams::Redirect {
            client_id: expected_client_id(&config),
            nonce: tx.nonce.clone(),
            jwk_thumbprint: Some(
                foundry_core::obs::thumbprint_bytes(&tx.ephem_public_jwk).unwrap(),
            ),
            response_uri: format!("https://localhost:8443/vp/response/{}", tx.id),
        })
        .unwrap();
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            &transcript,
        )
        .unwrap();

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {
                "sd": [sd],
                "md": [B64URL.encode(&device_response)],
            }}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .expect_err("both credentials failed, in different ways");

        assert_eq!(
            err.kind(),
            "failed",
            "the crypto failure decides the status, not the unreachable status list: {err}"
        );
        assert!(
            !matches!(err, VerificationError::StatusUnavailable(_)),
            "a 502 would tell the wallet to retry a permanently invalid presentation"
        );

        // Both credentials are still reported, each with its own reason.
        let result = tx.result.as_ref().expect("the result must be persisted");
        assert_eq!(result.credentials.len(), 2);
        // The unavailability is not the returned error, but it is not lost
        // either: it has no per-credential record (unavailability is not a
        // policy verdict), so the top-level fault record is the only place it
        // can be reported at all.
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.check == "status_check" && !c.passed),
            "the parked unavailability is still recorded as a fault: {:?}",
            result.checks
        );
    }

    /// A mixed verdict must be readable without reconstructing it from
    /// per-check lines. One roll-up record per credential, naming the credential,
    /// its format and its asserted type.
    #[tokio::test]
    async fn a_mixed_verdict_emits_one_roll_up_record_per_credential() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = FieldCapture::default();
        let subscriber = tracing_subscriber::Registry::default()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(capture.clone());

        foundry_core::obs::set_sensitive(false);
        let guard = tracing::subscriber::set_default(subscriber);
        let _ = run_unanchored_mdoc_presentation_reporting_result().await;
        drop(guard);

        // The failing credential is named, typed, and counted.
        assert!(
            capture.contains("credential failed"),
            "a failed credential needs its own record"
        );
        // Unquoted: every string field in these records is `%`-formatted
        // (Display), matching the `check`/`credential`/`detail` fields that
        // predate this roll-up.
        assert!(
            capture.contains("credential_type=org.iso.18013.5.1.mDL"),
            "the roll-up must name the credential type"
        );
        assert!(
            capture.contains("checks_passed=0"),
            "the roll-up must carry the passed count"
        );
        assert!(
            capture.contains("format=mso_mdoc"),
            "the roll-up must carry the format"
        );
        // The per-check record still exists and is now typed too -- §4.5 makes
        // these field names operator-facing API, so they are enriched, never
        // replaced.
        assert!(
            capture.contains("check=mdoc_issuer_auth_and_device_signature"),
            "the per-check trail must survive"
        );
        assert!(
            capture.contains("credentials_failed=1"),
            "the verdict record must count failed credentials"
        );
    }

    /// The positive counterpart: a credential that passed emits the same roll-up
    /// shape at `info`, so an operator reading a green verification still sees
    /// which credential types were accepted -- not only which were rejected.
    #[tokio::test]
    async fn a_verified_credential_emits_its_own_roll_up_record() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let pid = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );
        let diploma = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("degree", serde_json::json!("MSc"))],
        );
        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid], "diploma": [diploma]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let capture = FieldCapture::default();
        let subscriber = tracing_subscriber::Registry::default()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(capture.clone());

        foundry_core::obs::set_sensitive(false);
        let resolver = MockResolver { token: None };
        let guard = tracing::subscriber::set_default(subscriber);
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver).await;
        drop(guard);

        assert!(res.expect("both credentials are valid").verified);
        assert!(
            capture.contains("credential verified"),
            "a passing credential needs its own record too"
        );
        assert!(
            capture.contains("credential_type=https://localhost:8443/vct/pid"),
            "the roll-up must name the asserted vct"
        );
        // Three, not two: a credential with no `status.status_list` claim is
        // non-revocable, so `check_status` PASSES and still pushes its record
        // (see the crate's Gotchas). So signature + dcql_match + status_check.
        assert!(
            capture.contains("checks_passed=3"),
            "signature + dcql_match + a passing status_check"
        );
        // `credentials_failed` is emitted ONLY on the not-verified record: on a
        // verified response the count is always zero, and a field that is always
        // zero is noise.
        assert!(
            !capture.contains("credentials_failed"),
            "a verified response must not carry a permanently-zero count"
        );

        // The paired negative, and the reason the assertions above are a
        // meaningful control rather than a tautology: `credential_type` is a
        // credential TYPE identifier and is logged unconditionally, while a
        // DISCLOSED CLAIM VALUE is holder data and must never appear with
        // `sensitive_payloads` off (root AGENTS.md §4.5). Both properties are
        // asserted against one capture, so neither can drift without the other
        // noticing.
        //
        // This control lives here rather than in
        // `crates/foundry/tests/logging_redaction.rs` because that file's
        // `drive_verification` deliberately posts an undecryptable JWE: it
        // returns before any credential is examined, so no per-credential
        // record is ever emitted there to assert against.
        assert!(
            !capture.contains("Alice"),
            "a disclosed claim value must not be logged with sensitive payloads off"
        );
        assert!(
            !capture.contains("MSc"),
            "a disclosed claim value must not be logged with sensitive payloads off"
        );
    }

    /// The claim-collision bug, pinned. Two credentials disclosing the SAME claim
    /// name must not overwrite each other -- a single flat claims map reported one
    /// value as if both credentials agreed on it.
    #[tokio::test]
    async fn per_credential_claims_do_not_collide_on_a_shared_claim_name() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let first = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );
        let second = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Bob"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [first], "diploma": [second]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .unwrap();

        assert_eq!(res.credentials[0].claims["given_name"], "Alice");
        assert_eq!(
            res.credentials[1].claims["given_name"], "Bob",
            "each credential keeps its own value; a merged map would report one twice"
        );
    }

    /// A subset `vp_token` violates OpenID4VP L1007-1008 but is well-formed, so
    /// it is a policy verdict (HTTP 200, verified: false), not a structural 400
    /// (root AGENTS.md §4.3). The credential that DID arrive is still verified.
    ///
    /// This is deliberately **non-conformant wallet input**: a wallet that cannot
    /// deliver all non-optional credentials is required to return none at all.
    #[tokio::test]
    async fn a_subset_vp_token_is_a_policy_verdict_naming_the_missing_credential() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();
        let pid = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("given_name", serde_json::json!("Alice"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe, &resolver)
            .await
            .expect("a subset is a policy verdict, not a structural error");

        assert!(!res.verified, "a missing requested credential is a failure");

        let answered = res
            .checks
            .iter()
            .find(|c| c.check == "requested_credentials_answered")
            .expect("the set-level check must be recorded");
        assert!(!answered.passed);
        let detail = answered.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("diploma"),
            "must name the credential query that went unanswered: {detail}"
        );

        // The credential that arrived is still fully verified and reported.
        assert_eq!(res.credentials.len(), 1);
        assert_eq!(res.credentials[0].query_id, "pid");
        assert!(
            res.credentials[0].checks.iter().all(|c| c.passed),
            "the answered credential's own checks all pass: {:?}",
            res.credentials[0].checks
        );
    }

    /// `check_requested_credentials_answered` is fail-closed and never errors,
    /// matching `check_dcql_match`'s contract.
    #[test]
    fn requested_credentials_answered_passes_when_every_query_is_answered() {
        let query = serde_json::json!({"credentials": [
            {"id": "pid", "format": "dc+sd-jwt"},
            {"id": "mdl", "format": "mso_mdoc"}
        ]});
        let answered = vec![
            PresentedCredential {
                query_id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                // This check ignores the credential type; `None` documents that.
                credential_type: None,
                claims: serde_json::json!({}),
                checks: Vec::new(),
            },
            PresentedCredential {
                query_id: "mdl".to_string(),
                format: "mso_mdoc".to_string(),
                credential_type: None,
                claims: serde_json::json!({}),
                checks: Vec::new(),
            },
        ];

        let check = check_requested_credentials_answered(&query, &answered);
        assert_eq!(check.check, "requested_credentials_answered");
        assert!(check.passed);
    }

    #[test]
    fn requested_credentials_answered_fails_closed_on_an_unreadable_query() {
        let check = check_requested_credentials_answered(&serde_json::json!({}), &[]);
        assert!(
            !check.passed,
            "an unreadable query must fail closed, never pass"
        );
    }

    /// An unreachable status list keeps its HTTP 502 -- "I could not determine
    /// whether this is revoked" is not "this is revoked", and collapsing the two
    /// would invite a relying party to treat an unreachable list as a clean bill
    /// of health (root AGENTS.md §4.3).
    ///
    /// But it must not be lossy: `tx.result` has to retain the OTHER credential's
    /// verdict, which is the entire reason for keeping the 502 precise. And the
    /// persisted `verified` must be `false` -- the trap here is that an
    /// unavailable status pushes NO `status_check` record, so a naive
    /// `all(passed)` computes `true` and persists `verified: true` on a
    /// transaction that just returned 502.
    ///
    /// `MockResolver { token: None }` already fails every fetch with
    /// `StatusUnavailable`, so it *is* the unreachable-endpoint resolver; a
    /// separate type would only duplicate it.
    #[tokio::test]
    async fn an_unavailable_status_list_returns_502_without_discarding_other_credentials() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _pub) = two_sd_jwt_tx();

        // `pid` carries a status claim, so its check hits the failing resolver.
        let (holder_signer, holder_pub) = holder();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let pid_claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: None,
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: Some(7),
            status_list_uri: Some("https://localhost:8443/statuslist/1".to_string()),
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let pid_issuer =
            build_sd_jwt_vc(pid_claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let client_id = expected_client_id(&config);
        let pid = attach_kb_jwt(pid_issuer, &holder_signer, &client_id, &tx.nonce, None).unwrap();

        // `diploma` carries no status claim, so its own checks all pass.
        let diploma = sd_jwt_presentation_for(
            &config,
            &tx,
            &leaf_cert,
            &issuer_signer,
            &[("degree", serde_json::json!("MSc"))],
        );

        let jwe = encrypt_compact(
            &serde_json::json!({"vp_token": {"pid": [pid], "diploma": [diploma]}}),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let err = verify_vp_response(&config, &mut tx, &jwe, &MockResolver { token: None })
            .await
            .expect_err("an unreachable status list is a network fault, so HTTP 502");

        assert!(
            matches!(err, VerificationError::StatusUnavailable(_)),
            "must stay StatusUnavailable so the HTTP layer maps it to 502, got: {err}"
        );
        assert!(
            err.to_string().contains("pid"),
            "must name WHICH credential's status list was unreachable: {err}"
        );

        // Non-lossy: the operator keeps the other credential's verdict.
        let persisted = tx.result.as_ref().expect(
            "the error path must populate tx.result, or the admin console shows a \
             bare red failure with no explanation",
        );
        assert_eq!(tx.state, VerificationState::Failed);
        assert!(
            !persisted.verified,
            "verified must be false on a transaction that returned 502 -- an \
             unavailable status pushes no status_check, so a naive all(passed) \
             would have computed true here"
        );
        assert_eq!(
            persisted.credentials.len(),
            2,
            "both credentials' records survive: {:?}",
            persisted.credentials
        );
        let diploma_record = persisted
            .credentials
            .iter()
            .find(|c| c.query_id == "diploma")
            .expect("the healthy credential must still be reported");
        assert!(
            diploma_record.checks.iter().all(|c| c.passed),
            "the healthy credential's own checks all passed: {:?}",
            diploma_record.checks
        );
        assert!(
            persisted
                .checks
                .iter()
                .any(|c| c.check == "status_check" && !c.passed),
            "the fault is recorded as a check so the verdict stays derived: {:?}",
            persisted.checks
        );
    }

    // --- select_presentations: the OpenID4VP 1.0 `vp_token` envelope (L1161) ---
    //
    // These exercise envelope selection directly, with no JWE, no keys and no
    // trust store, so a failure points at the envelope rather than at crypto.

    fn sd_jwt_dcql() -> Value {
        serde_json::json!({"credentials": [{"id": "c1", "format": "dc+sd-jwt"}]})
    }

    fn mdoc_dcql() -> Value {
        serde_json::json!({"credentials": [{"id": "c1", "format": "mso_mdoc"}]})
    }

    fn two_credential_dcql() -> Value {
        serde_json::json!({"credentials": [
            {"id": "pid", "format": "dc+sd-jwt"},
            {"id": "mdl", "format": "mso_mdoc"}
        ]})
    }

    /// Assert rejection and hand back the message, so each test can check that the
    /// message actually says something actionable.
    fn rejection_of(vp_token: Value, dcql_query: &Value) -> String {
        match select_presentations(&vp_token, dcql_query) {
            Ok(selected) => {
                let ids: Vec<&str> = selected.iter().map(|(id, _)| id.as_str()).collect();
                panic!("expected rejection, but selected {ids:?}")
            }
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn select_presentations_accepts_conformant_sd_jwt_envelope() {
        let vp = serde_json::json!({"c1": ["header.body.sig~disclosure~kb"]});
        let selected = select_presentations(&vp, &sd_jwt_dcql()).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, "c1");
        match &selected[0].1 {
            SelectedPresentation::SdJwtVc(s) => assert_eq!(*s, "header.body.sig~disclosure~kb"),
            other => panic!("expected SdJwtVc, got {other:?}"),
        }
    }

    /// OpenID4VP L2825-L2828: the mdoc presentation is ONE base64url
    /// `DeviceResponse` string.
    #[test]
    fn select_presentations_accepts_a_device_response_string() {
        let vp = serde_json::json!({"c1": ["QUFBQQ"]});
        let selected = select_presentations(&vp, &mdoc_dcql()).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, "c1");
        match &selected[0].1 {
            SelectedPresentation::MsoMdoc {
                device_response_b64,
            } => assert_eq!(*device_response_b64, "QUFBQQ"),
            other => panic!("expected MsoMdoc, got {other:?}"),
        }
    }

    /// Strict, not liberal (design doc §3 decision 2): the former
    /// `{mdoc, device_signature}` object was foundry-invented and is now refused
    /// outright rather than accepted alongside the conformant shape.
    #[test]
    fn select_presentations_rejects_the_former_split_mdoc_envelope() {
        let vp = serde_json::json!({"c1": [{"mdoc": "AAAA", "device_signature": "BBBB"}]});
        let err = select_presentations(&vp, &mdoc_dcql()).expect_err("must be rejected");
        assert!(
            format!("{err}").contains("DeviceResponse"),
            "the error should name the required shape, got: {err}"
        );
    }

    /// The inverse of the guard this feature removes. A `vp_token` answering
    /// several credential queries is the point, not an error.
    #[test]
    fn select_presentations_accepts_several_answered_queries() {
        let vp = serde_json::json!({
            "pid": ["header.body.sig~disclosure~kb"],
            "mdl": ["QUFBQQ"]
        });
        let selected = select_presentations(&vp, &two_credential_dcql()).unwrap();

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0, "pid");
        assert_eq!(selected[1].0, "mdl");
        assert!(matches!(selected[0].1, SelectedPresentation::SdJwtVc(_)));
        assert!(matches!(
            selected[1].1,
            SelectedPresentation::MsoMdoc { .. }
        ));
    }

    /// Declaration order, not `vp_token` key order. Depending on the wallet's
    /// serialization -- or on whether serde_json is built with `preserve_order`
    /// -- would make the operator-visible output non-deterministic.
    #[test]
    fn select_presentations_follows_dcql_declaration_order() {
        // `mdl` first in the vp_token, `pid` first in the query.
        let vp = serde_json::json!({
            "mdl": ["QUFBQQ"],
            "pid": ["header.body.sig~disclosure~kb"]
        });
        let selected = select_presentations(&vp, &two_credential_dcql()).unwrap();

        let ids: Vec<&str> = selected.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["pid", "mdl"],
            "order must follow the DCQL query, not the vp_token"
        );
    }

    /// A subset is a wallet MUST-violation (OpenID4VP 1.0 L1007-1008) but a
    /// well-formed one, so selection must NOT reject it: it is a policy verdict
    /// decided later by `requested_credentials_answered` (root AGENTS.md §4.3).
    #[test]
    fn select_presentations_accepts_a_subset_and_leaves_the_verdict_to_policy() {
        let vp = serde_json::json!({"pid": ["header.body.sig~disclosure~kb"]});
        let selected = select_presentations(&vp, &two_credential_dcql()).unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, "pid");
    }

    /// An id the request never asked for is structural: there is no credential
    /// query to verify it against, so no verdict can be attributed to it.
    #[test]
    fn select_presentations_rejects_an_id_that_was_never_requested() {
        let vp = serde_json::json!({
            "pid": ["header.body.sig~disclosure~kb"],
            "surprise": ["x"]
        });
        let msg = rejection_of(vp, &two_credential_dcql());
        assert!(
            msg.contains("surprise"),
            "must name the unexpected id: {msg}"
        );
        assert!(msg.contains("did not ask for"), "{msg}");
    }

    #[test]
    fn select_presentations_rejects_an_empty_vp_token() {
        let msg = rejection_of(serde_json::json!({}), &two_credential_dcql());
        assert!(msg.contains("no credential query"), "{msg}");
    }

    /// The reported production defect: a bare string was foundry's old SD-JWT VC
    /// shape, and no conformant wallet sends it.
    #[test]
    fn select_presentations_rejects_bare_string_vp_token() {
        let msg = rejection_of(serde_json::json!("header.body.sig~"), &sd_jwt_dcql());
        assert!(msg.contains("must be a JSON object"), "{msg}");
        assert!(msg.contains("got a string"), "{msg}");
    }

    /// foundry's old mdoc shape put these keys at the top level of `vp_token`.
    /// They now read as credential query ids that were never requested.
    #[test]
    fn select_presentations_reject_legacy_top_level_mdoc_envelope() {
        let msg = rejection_of(
            serde_json::json!({"mdoc": "AAAA", "device_signature": "BBBB"}),
            &mdoc_dcql(),
        );
        assert!(msg.contains("did not ask for"), "{msg}");
    }

    #[test]
    fn select_presentations_rejects_unknown_query_id_naming_both_sides() {
        let msg = rejection_of(serde_json::json!({"unexpected": ["x"]}), &sd_jwt_dcql());
        assert!(msg.contains("unexpected"), "must name what arrived: {msg}");
        assert!(msg.contains("c1"), "must name what was expected: {msg}");
    }

    #[test]
    fn select_presentations_requires_exactly_one_presentation() {
        let dcql = sd_jwt_dcql();
        let empty = rejection_of(serde_json::json!({"c1": []}), &dcql);
        assert!(empty.contains("exactly one presentation"), "{empty}");
        let two = rejection_of(serde_json::json!({"c1": ["x", "y"]}), &dcql);
        assert!(two.contains("exactly one presentation"), "{two}");
    }

    #[test]
    fn select_presentations_requires_an_array_value() {
        let msg = rejection_of(serde_json::json!({"c1": "not-an-array"}), &sd_jwt_dcql());
        assert!(msg.contains("must be an array"), "{msg}");
    }

    /// The payload must match the format the query *declared*. This is where the
    /// old shape-sniffing protection now lives, with a message that names the
    /// declared format instead of guessing.
    ///
    /// Both formats now expect a JSON string, so a bare string no longer
    /// contradicts either one — the contradicting payload for each is a
    /// non-string. Before the DeviceResponse envelope landed, mso_mdoc expected
    /// an object and this test read the other way round.
    #[test]
    fn select_presentations_rejects_payload_contradicting_declared_format() {
        let object_for_sd_jwt = rejection_of(
            serde_json::json!({"c1": [{"mdoc": "A", "device_signature": "B"}]}),
            &sd_jwt_dcql(),
        );
        assert!(
            object_for_sd_jwt.contains("dc+sd-jwt"),
            "{object_for_sd_jwt}"
        );

        let object_for_mdoc = rejection_of(
            serde_json::json!({"c1": [{"mdoc": "A", "device_signature": "B"}]}),
            &mdoc_dcql(),
        );
        assert!(object_for_mdoc.contains("mso_mdoc"), "{object_for_mdoc}");
    }

    #[test]
    fn select_presentations_rejects_unusable_dcql_query() {
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
    fn select_presentations_rejects_unimplemented_credential_format() {
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
            sub: None,
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
            sub: None,
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
            sub: None,
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
            sub: None,
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
            sub: None,
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
    // OpenID4VP draft 24 `web-origin:` audience accommodation
    // (`verifier.dc_api_accept_legacy_web_origin_audience`).
    //
    // Draft 24 Appendix A.2 composed the effective Client Identifier of an
    // unsigned DC API request from "a synthetic Client Identifier Scheme of
    // `web-origin` and the Origin itself", and its KB-JWT `aud` was that
    // Client Identifier. OpenID4VP 1.0 renamed the prefix to `origin:`
    // (L618, L2543). Real wallets still in the field sign the draft-24
    // spelling, so foundry can be told to accept it -- but only when asked,
    // and never at the cost of the Origin allow-list.
    // -----------------------------------------------------------------------

    /// Build a `dc_api` presentation bound to `audience`, ready to hand to
    /// `verify_vp_response`. Shared by the four `web-origin` tests below,
    /// which differ only in the audience string and the config flag.
    fn dc_api_presentation_with_audience(
        leaf_cert: &[u8],
        leaf_key: &[u8],
        tx: &mut VerificationTransaction,
        audience: &str,
    ) -> String {
        let issuer_signer = FileSigner::from_pem(leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
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
            sub: None,
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
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(leaf_cert)])).unwrap();
        let presentation =
            attach_kb_jwt(issuer_pres, &holder_signer, audience, &tx.nonce, None).unwrap();

        encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap()
    }

    /// Default posture is strict OpenID4VP 1.0: the draft-24 `web-origin:`
    /// spelling is rejected even when the Origin half names a configured
    /// origin, because L2543 mandates the `origin:` prefix. Accepting it by
    /// default would make every deployment silently deviate.
    #[tokio::test]
    async fn dc_api_legacy_web_origin_audience_is_rejected_by_default() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        assert!(
            !config.verifier.dc_api_accept_legacy_web_origin_audience,
            "the accommodation must be off unless an operator asks for it"
        );

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        let jwe_str = dc_api_presentation_with_audience(
            &leaf_cert,
            &leaf_key,
            &mut tx,
            // The very value real Google Wallet sends: right Origin, draft-24 prefix.
            "web-origin:https://verifier-website.example",
        );

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Failed(_)),
            "the draft-24 `web-origin:` audience must be rejected while the accommodation is off, \
             got: {err:?}"
        );
    }

    /// With the accommodation enabled, the draft-24 spelling of a *configured*
    /// Origin verifies -- this is the switch that unblocks a wallet still
    /// implementing OpenID4VP draft 24 Appendix A.2.
    #[tokio::test]
    async fn dc_api_legacy_web_origin_audience_accepted_when_flag_enabled() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (mut config, _trust_dir) = test_config(&ca_str);
        config.verifier.dc_api_accept_legacy_web_origin_audience = true;

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        let jwe_str = dc_api_presentation_with_audience(
            &leaf_cert,
            &leaf_key,
            &mut tx,
            "web-origin:https://verifier-website.example",
        );

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            res.verified,
            "a draft-24 `web-origin:` audience naming a configured origin must verify once the \
             accommodation is enabled: {:?}",
            res.checks
        );
    }

    /// The accommodation relaxes the *prefix*, never the Origin allow-list.
    /// An unlisted Origin must still be rejected under the flag -- otherwise
    /// the flag would widen the trust boundary rather than just its spelling.
    #[tokio::test]
    async fn dc_api_legacy_web_origin_flag_still_enforces_the_origin_allow_list() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (mut config, _trust_dir) = test_config(&ca_str);
        config.verifier.dc_api_accept_legacy_web_origin_audience = true;

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        let jwe_str = dc_api_presentation_with_audience(
            &leaf_cert,
            &leaf_key,
            &mut tx,
            "web-origin:https://some-other-site.example",
        );

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Failed(_)),
            "the accommodation must relax only the prefix; an unlisted Origin must still be \
             rejected, got: {err:?}"
        );
    }

    /// Enabling the accommodation ADDS the legacy spelling; it must not
    /// replace the conformant one, or turning it on would break every wallet
    /// that already implements OpenID4VP 1.0.
    #[tokio::test]
    async fn dc_api_conformant_origin_audience_still_accepted_when_legacy_flag_enabled() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (mut config, _trust_dir) = test_config(&ca_str);
        config.verifier.dc_api_accept_legacy_web_origin_audience = true;

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        let jwe_str = dc_api_presentation_with_audience(
            &leaf_cert,
            &leaf_key,
            &mut tx,
            "origin:https://verifier-website.example",
        );

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            res.verified,
            "the OpenID4VP 1.0 `origin:` audience must keep verifying with the accommodation \
             enabled: {:?}",
            res.checks
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
    /// The pre-GAP-VP-06 ad-hoc transcript, hand-assembled as raw CBOR then
    /// decoded — `mdoc_presentation_jwe` now takes a `Value` because
    /// `DeviceAuthentication` splices the transcript by value.
    ///
    /// Still assembled byte-by-byte rather than with `Value` constructors: the
    /// point is to reproduce a shape foundry's current code cannot produce.
    fn pre_fix_ad_hoc_transcript(
        client_id: &str,
        response_uri: &str,
        nonce: &str,
    ) -> ciborium::Value {
        let mut out = vec![0x83, 0xf6, 0xf6, 0x83];
        out.extend(cbor_text(client_id));
        out.extend(cbor_text(response_uri));
        out.extend(cbor_text(nonce));
        ciborium::from_reader(out.as_slice()).expect("hand-built CBOR decodes")
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

    /// Issue an mdoc, wrap it in the `DeviceResponse` a wallet would send, and
    /// encrypt it as the JWE a wallet would post.
    ///
    /// Taking the transcript as a caller-supplied `Value` lets a test sign a
    /// deliberately wrong one — which is how the Origin-candidate and
    /// thumbprint-selection tests below prove the transcript is actually
    /// committed to.
    fn mdoc_presentation_jwe(
        leaf_cert: &[u8],
        leaf_key: &[u8],
        transcript: &ciborium::Value,
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

        // Build what a wallet sends: one base64url DeviceResponse, with the
        // DeviceSignature over DeviceAuthenticationBytes. Previously this
        // hand-rolled a signature over the bare transcript and wrapped it in
        // foundry's own split envelope, so it could only ever confirm that
        // foundry agreed with itself.
        let device_response = foundry_mdoc::builder::build_device_response(
            &mdoc_bytes,
            "org.iso.18013.5.1.mDL",
            &d_signer,
            transcript,
        )
        .unwrap();

        encrypt_compact(
            &serde_json::json!({
                "vp_token": { "c1": [B64URL.encode(&device_response)] }
            }),
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
        let transcript = session_transcript_value(&SessionTranscriptParams::DcApi {
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

        let transcript = session_transcript_value(&SessionTranscriptParams::DcApi {
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
                session_transcript_value(&SessionTranscriptParams::DcApi {
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
