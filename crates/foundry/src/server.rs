use crate::admin_auth::{require_api_key, AdminApiKey};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use foundry_core::config::Config;
use foundry_core::storage::{SqliteStorage, Storage};
use foundry_issuer::{
    AuthorizationServerMetadata, ChallengeResponse, CreateOfferRequest, CreateOfferResponse,
    CredentialIssuerMetadata, CredentialRequest, CredentialResponse, IssuanceState, NonceResponse,
    TokenRequest, TokenResponse,
};
use foundry_verifier::{
    CreateVerificationRequest, CreateVerificationResponse, VerificationResult,
    VerificationTransaction,
};
use std::future::IntoFuture;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use utoipa::OpenApi;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub config: Arc<Config>,
    /// Keys the MAC on `c_nonce` values minted by `POST /nonce`. Generated
    /// once per process — see [`foundry_issuer::NonceSecret`].
    pub nonce_secret: Arc<foundry_issuer::NonceSecret>,
}

impl AppState {
    /// Build an `AppState`, generating this process's `c_nonce` MAC secret.
    pub fn new(storage: Arc<dyn Storage>, config: Arc<Config>) -> Self {
        Self {
            storage,
            config,
            nonce_secret: Arc::new(foundry_issuer::NonceSecret::random()),
        }
    }
}

pub fn admin_router(state: AppState, api_key: AdminApiKey) -> Router {
    let unauthenticated = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready));

    let unauthenticated = if state.config.server.admin.swagger_ui_enabled {
        unauthenticated.merge(utoipa_swagger_ui::SwaggerUi::new("/api-docs").url(
            "/api-docs/openapi.json",
            crate::openapi::AdminApiDoc::openapi(),
        ))
    } else {
        unauthenticated.route("/api-docs/openapi.json", get(openapi_json_handler))
    };

    let unauthenticated = if state.config.server.admin.console_enabled {
        unauthenticated.route("/console", get(console_handler))
    } else {
        unauthenticated
    };

    let unauthenticated = unauthenticated.with_state(state.clone());

    let authenticated = Router::new()
        .route("/admin/issuance/offers", post(create_offer_handler))
        .route(
            "/admin/issuance/offers/:id",
            get(get_issuance_offer_handler),
        )
        .route(
            "/admin/verification/requests",
            post(create_verification_handler),
        )
        .route(
            "/admin/verification/requests/:id",
            get(get_verification_handler),
        )
        .route(
            "/admin/verification/requests/:id/dc-api-response",
            post(post_admin_dc_api_response_handler),
        )
        .route_layer(middleware::from_fn_with_state(api_key, require_api_key))
        .with_state(state);

    crate::http_log::with_access_log(unauthenticated.merge(authenticated), "admin")
}

pub fn wallet_router(state: AppState) -> Router {
    let mut router = Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth_server_metadata),
        )
        .route("/token", post(token_handler))
        .route("/authorize", get(authorize_handler))
        .route("/nonce", post(nonce_handler))
        .route("/credential", post(credential_handler))
        .route("/vp/request/:id", get(get_request_object_handler))
        .route("/vp/response/:id", post(post_response_handler))
        .route("/statuslists/:id", get(status_list_handler));

    // ABCA §8: the route exists only when the mechanism is enabled, so its
    // absence and the absent `challenge_endpoint` metadata entry always agree.
    if state.config.issuer.wallet_attestation.challenge_mode != foundry_core::config::Mode::Disabled
    {
        router = router.route("/challenge", post(challenge_handler));
    }

    let router = if state.config.server.wallet_facing.swagger_ui_enabled {
        router.merge(utoipa_swagger_ui::SwaggerUi::new("/api-docs").url(
            "/api-docs/openapi.json",
            crate::openapi::WalletApiDoc::openapi(),
        ))
    } else {
        router.route("/api-docs/openapi.json", get(wallet_openapi_json_handler))
    };

    crate::http_log::with_access_log(router.with_state(state), "wallet")
}

pub(crate) async fn wallet_openapi_json_handler(
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::openapi::generate_wallet_openapi_spec(),
    )
}

#[utoipa::path(
    get,
    path = "/.well-known/openid-credential-issuer",
    responses((status = 200, body = CredentialIssuerMetadata))
)]
async fn issuer_metadata(State(state): State<AppState>) -> Json<CredentialIssuerMetadata> {
    // Encryption keys are wired in alongside AppState in the extractor task.
    Json(foundry_issuer::build_issuer_metadata(&state.config, &[]))
}

#[utoipa::path(
    get,
    path = "/.well-known/oauth-authorization-server",
    responses((status = 200, body = AuthorizationServerMetadata))
)]
async fn auth_server_metadata(State(state): State<AppState>) -> Json<AuthorizationServerMetadata> {
    Json(foundry_issuer::build_authorization_server_metadata(
        &state.config,
    ))
}

pub(crate) async fn openapi_json_handler(
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::openapi::generate_admin_openapi_spec(),
    )
}

#[utoipa::path(get, path = "/health", responses((status = 200, body = String)))]
pub(crate) async fn health() -> &'static str {
    "ok"
}

#[utoipa::path(get, path = "/ready", responses((status = 200, body = String)))]
pub(crate) async fn ready(State(state): State<AppState>) -> Result<&'static str, StatusCode> {
    // Readiness = storage reachable. A cheap purge with a far-past timestamp
    // touches the DB without deleting live rows.
    match state.storage.purge_expired(0).await {
        Ok(_) => Ok("ready"),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

// Embedded static Admin Test Console — trigger UI for the admin issuance
// and verification endpoints (see docs/superpowers/specs/2026-07-27-admin-test-console-design.md).
// Deliberately NOT a #[utoipa::path] handler: it returns static HTML, not a
// JSON API resource, exactly like the /api-docs Swagger UI route itself.
const CONSOLE_HTML: &str = include_str!("../assets/console.html");

pub(crate) async fn console_handler() -> Html<&'static str> {
    Html(CONSOLE_HTML)
}

#[utoipa::path(
    post,
    path = "/admin/issuance/offers",
    request_body = CreateOfferRequest,
    responses((status = 200, body = CreateOfferResponse))
)]
pub(crate) async fn create_offer_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateOfferRequest>,
) -> Result<Json<CreateOfferResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    foundry_issuer::create_offer(&state.config, state.storage.as_ref(), req, now)
        .await
        .map(Json)
        .map_err(|e| admin_error_response(&e))
}

/// Narrow, admin-facing projection of a [`foundry_issuer::IssuanceTransaction`].
///
/// Deliberately **not** the whole transaction, unlike `get_verification_handler`:
/// `IssuanceTransaction` holds `pre_authorized_code` and `access_token`, which
/// are live bearer credentials against the wallet-facing listener. Returning
/// them would let any admin-key holder redeem an offer intended for a wallet,
/// turning a read endpoint into a credential-exfiltration endpoint. Also
/// excluded: `authorization_code`, `code_challenge`, `code_challenge_method`,
/// `dpop_jkt`, `claims`, `redirect_uri`, `issuer_state`.
///
/// `tx_code` **is** included. Its entire purpose is to be relayed out-of-band to
/// the person completing the flow, and the already-authenticated operator who
/// created the offer is that channel; it is surfaced nowhere else today, which
/// makes `tx_code_required: true` untestable through the console. Root
/// AGENTS.md §4.5 forbids *logging* transaction codes and continues to apply
/// unchanged.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub(crate) struct AdminIssuanceStatus {
    transaction_id: String,
    credential_type_id: String,
    state: IssuanceState,
    created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_list_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_code: Option<String>,
}

/// Read the state of an issuance transaction, so the admin console can show
/// whether a credential was actually issued rather than only that an offer was
/// created.
#[utoipa::path(
    get,
    path = "/admin/issuance/offers/{id}",
    responses(
        (status = 200, body = AdminIssuanceStatus),
        (status = 404, description = "No such issuance transaction")
    )
)]
#[tracing::instrument(skip_all)]
pub(crate) async fn get_issuance_offer_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AdminIssuanceStatus>, StatusCode> {
    let tx = foundry_issuer::load_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|e| internal_error("load_transaction", e.kind(), e))?;
    match tx {
        Some(tx) => Ok(Json(AdminIssuanceStatus {
            transaction_id: tx.transaction_id,
            credential_type_id: tx.credential_type_id,
            state: tx.state,
            created_at: tx.created_at,
            status_list_index: tx.status_list_index,
            tx_code: tx.tx_code,
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Cap on `error.detail` in log records and persisted verdicts. Long enough for
/// a real diagnostic, short enough that a pathological error string cannot fill
/// the log.
pub(crate) const DETAIL_MAX: usize = 512;

/// Log an error that is about to be collapsed into a bare [`StatusCode`],
/// losing the error object.
///
/// Handlers returning `Result<_, StatusCode>` cannot carry a typed error into a
/// mapper, so without this the only trace of the failure would be the status
/// code — which is exactly the condition that made the original defect
/// undiagnosable.
///
/// `op` names what was being attempted; `kind` is the failure class, mirroring
/// the `error.kind` field the typed mappers emit.
/// Emit the single log record for a typed error on its way out as an HTTP
/// response.
///
/// Called from inside each of the four error mappers rather than at their call
/// sites. Every typed error passes through exactly one mapper exactly once, so
/// this placement gives complete coverage with no possibility of
/// double-logging — and inherits `request_id`, `route` and `listener` from the
/// access-log span for free.
///
/// Level follows the status class, the same rule the access log uses: `error!`
/// for 5xx (including 502 and 503 — an unreachable status list or an exhausted
/// list needs operator attention), `warn!` for 4xx.
fn log_typed_error(
    surface: &'static str,
    kind: &'static str,
    detail: impl std::fmt::Display,
    status: StatusCode,
) {
    let detail = foundry_core::obs::truncate(&detail.to_string(), DETAIL_MAX);
    let code = status.as_u16();
    if status.is_server_error() {
        tracing::error!(surface, error.kind = kind, error.detail = %detail, http.status = code, "request failed");
    } else {
        tracing::warn!(surface, error.kind = kind, error.detail = %detail, http.status = code, "request rejected");
    }
}

fn internal_error(
    op: &'static str,
    kind: &'static str,
    detail: impl std::fmt::Display,
) -> StatusCode {
    tracing::error!(
        op,
        error.kind = kind,
        error.detail = %foundry_core::obs::truncate(&detail.to_string(), DETAIL_MAX),
        http.status = 500,
        "request failed"
    );
    StatusCode::INTERNAL_SERVER_ERROR
}

fn admin_error_response(
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_issuer::IssuanceError::*;
    let status = match e {
        UnknownCredentialType(_) | ClaimValidation(_) => StatusCode::BAD_REQUEST,
        StatusListExhausted(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    log_typed_error("admin", e.kind(), e, status);
    (
        status,
        Json(serde_json::json!({ "error": e.to_string(), "message": e.to_string() })),
    )
}

fn wallet_error_response(
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_issuer::IssuanceError::*;
    let (status, code) = match e {
        InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
        InvalidProof(_) => (StatusCode::BAD_REQUEST, "invalid_proof"),
        // OpenID4VCI 1.0 Credential Error Response (L1050): a present but
        // invalid c_nonce is invalid_nonce, distinct from invalid_proof --
        // GAP-VCI-04.
        InvalidNonce(_) => (StatusCode::BAD_REQUEST, "invalid_nonce"),
        InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        UnknownCredentialType(_) | ClaimValidation(_) => {
            (StatusCode::BAD_REQUEST, "invalid_credential_request")
        }
        // OpenID4VCI 1.0 Credential Request (L851): credential_configuration_id
        // is REQUIRED and MUST identify the Credential Type the Access Token
        // was issued for -- GAP-VCI-02. Distinct codes so a Wallet can tell
        // "fix your request" (present-but-wrong or absent) from "re-read
        // metadata" (names a configuration this issuer doesn't have).
        InvalidCredentialRequest(_) => (StatusCode::BAD_REQUEST, "invalid_credential_request"),
        UnknownCredentialConfiguration(_) => {
            (StatusCode::BAD_REQUEST, "unknown_credential_configuration")
        }
        // RFC 6749 sect-5.2: a failed client-authentication mechanism (an absent,
        // malformed, or unverifiable Wallet Attestation / Client Attestation
        // PoP JWT, GAP-VCI-14) is `invalid_client`, not `invalid_request`.
        InvalidClient(_) => (StatusCode::BAD_REQUEST, "invalid_client"),
        // RFC 9449 §5: "If the DPoP proof is invalid, the authorization server
        // issues an error response per Section 5.2 of [RFC6749] with
        // invalid_dpop_proof as the value of the error parameter."
        //
        // This is the Token Endpoint mapping. The Credential Endpoint is a
        // *protected resource*, where §7.1 requires 401 + WWW-Authenticate
        // instead -- see `credential_error_response` (Task 9).
        InvalidDpopProof(_) => (StatusCode::BAD_REQUEST, "invalid_dpop_proof"),
        // ABCA §6.2's error codes are returned "in either Authorization Server
        // authenticated endpoint error responses (as defined in Section 5.2 of
        // [RFC6749])" -- the same 400 shape as `invalid_client`. The mandatory
        // OAuth-Client-Attestation-Challenge header is added by
        // `token_error_response`, the only mapper on a route that can produce
        // this error.
        UseAttestationChallenge(_) => (StatusCode::BAD_REQUEST, "use_attestation_challenge"),
        // RFC 9449 §8: "an HTTP 400 (Bad Request) error response ... using
        // use_dpop_nonce as the error code value". The accompanying DPoP-Nonce
        // header is added by `token_error_response`; the §9 (401) form for the
        // Credential Endpoint is in `credential_error_response`.
        UseDpopNonce(_) => (StatusCode::BAD_REQUEST, "use_dpop_nonce"),
        StatusListExhausted(_) => (StatusCode::SERVICE_UNAVAILABLE, "server_error"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    log_typed_error("wallet", e.kind(), e, status);
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": e.to_string(),
        })),
    )
}

/// A freshly-minted ABCA §8.1 `OAuth-Client-Attestation-Challenge` header, or
/// `None` when challenge retrieval is disabled.
///
/// §8.1 permits attaching a fresh challenge to *any* response; §6.2 *requires*
/// it alongside a `use_attestation_challenge` error. One helper serves both, so
/// the two paths can never disagree about the header's name or format.
///
/// A minting failure yields `None` rather than propagating: the challenge is an
/// optimisation on a success path and a mandatory extra on an already-failing
/// one, and in neither case should it become a *different* error. The failure is
/// already logged inside `challenge::mint`.
fn attestation_challenge_header(
    state: &AppState,
    now_unix: i64,
) -> Option<(axum::http::HeaderName, axum::http::HeaderValue)> {
    if state.config.issuer.wallet_attestation.challenge_mode == foundry_core::config::Mode::Disabled
    {
        return None;
    }
    let res = foundry_issuer::issue_attestation_challenge(
        state.nonce_secret.as_ref(),
        state.config.issuer.wallet_attestation.pop_max_age_secs,
        now_unix,
    )
    .ok()?;
    // Lowercase literal: axum normalises header names per RFC 9110, and
    // `from_static` requires lowercase input.
    let name = axum::http::HeaderName::from_static("oauth-client-attestation-challenge");
    // The value is base64url, so `from_str` cannot fail in practice; `ok()?`
    // rather than an unwrap because root `AGENTS.md` §4.1 forbids one here.
    let value = axum::http::HeaderValue::from_str(&res.attestation_challenge).ok()?;
    Some((name, value))
}

/// A freshly-minted RFC 9449 §8/§8.2 `DPoP-Nonce` header, or `None` when
/// server-provided nonces are disabled.
///
/// One helper for every emission point — §8's 400, §9's 401, and §8.2's
/// piggyback on a success — so §8's "there MUST NOT be more than one DPoP-Nonce
/// header" holds structurally: each response inserts from here exactly once.
///
/// A minting failure yields `None` for the same reason as
/// `attestation_challenge_header`: it must not convert one error into another.
fn dpop_nonce_header(
    state: &AppState,
    now_unix: i64,
) -> Option<(axum::http::HeaderName, axum::http::HeaderValue)> {
    if state.config.issuer.dpop.nonce_mode == foundry_core::config::Mode::Disabled {
        return None;
    }
    // TTL is `dpop.max_age_secs`: a nonce outliving the window in which the
    // proof carrying it would be accepted anyway is useless (design doc §3).
    let nonce = foundry_issuer::mint_dpop_nonce(
        state.nonce_secret.as_ref(),
        state.config.issuer.dpop.max_age_secs,
        now_unix,
    )
    .ok()?;
    let name = axum::http::HeaderName::from_static("dpop-nonce");
    let value = axum::http::HeaderValue::from_str(&nonce).ok()?;
    Some((name, value))
}

/// Error mapper for the Token Endpoint.
///
/// Wraps `wallet_error_response` and attaches the response headers ABCA §8.1
/// and RFC 9449 §8 put on `/token` responses. `wallet_error_response` still
/// emits the single log record (root `AGENTS.md` §4.5) -- this function adds no
/// second one.
fn token_error_response(
    state: &AppState,
    now_unix: i64,
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    let (status, body) = wallet_error_response(e);
    let mut headers = HeaderMap::new();
    // §6.2 makes this mandatory on a `use_attestation_challenge` error; §8.1
    // permits it on any other. Attaching it unconditionally (when enabled)
    // satisfies both without a branch that could get the mandatory case wrong.
    if let Some((name, value)) = attestation_challenge_header(state, now_unix) {
        headers.insert(name, value);
    }
    // RFC 9449 §8 requires DPoP-Nonce alongside `use_dpop_nonce`; §8.2 permits
    // it on any other response. Unconditional (when enabled) for the same
    // reason as the ABCA challenge above.
    if let Some((name, value)) = dpop_nonce_header(state, now_unix) {
        headers.insert(name, value);
    }
    (status, headers, body)
}

/// Query parameters for `GET /authorize`. All fields are optional at the
/// wire level (missing ones surface as a proper OAuth `invalid_request`
/// error via `handle_authorize_request`, not an axum 422 rejection).
#[derive(Debug, serde::Deserialize)]
pub(crate) struct AuthorizeQuery {
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    issuer_state: Option<String>,
    /// HAIP OpenID4VCI L209: the Credential Type(s) to be issued.
    #[serde(default)]
    scope: Option<String>,
    /// RFC 9449 §10: JWK Thumbprint of the wallet's DPoP key.
    #[serde(default)]
    dpop_jkt: Option<String>,
}

/// Percent-encode `params` (and `state`, if present) onto `base` as a query
/// string. `base` may be a bare custom-scheme URI (e.g.
/// `eudi-openid4ci://authorize`) with no existing query string.
fn append_query(base: &str, params: &[(&str, &str)], state: Option<&str>) -> String {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let mut pairs: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", utf8_percent_encode(v, NON_ALPHANUMERIC)))
        .collect();
    if let Some(s) = state {
        pairs.push(format!(
            "state={}",
            utf8_percent_encode(s, NON_ALPHANUMERIC)
        ));
    }
    format!("{base}?{}", pairs.join("&"))
}

#[utoipa::path(
    get,
    path = "/authorize",
    responses(
        (status = 303, description = "Redirect (axum::response::Redirect::to, See Other) to redirect_uri with `code` or `error`"),
        (status = 400, description = "invalid_request (untrusted redirect_uri/issuer_state)")
    )
)]
async fn authorize_handler(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AuthorizeQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Json<serde_json::Value>)> {
    let redirect_uri = q.redirect_uri.clone().ok_or_else(|| {
        wallet_error_response(&foundry_issuer::IssuanceError::InvalidRequest(
            "missing redirect_uri".to_string(),
        ))
    })?;
    let issuer_state = q.issuer_state.clone().ok_or_else(|| {
        wallet_error_response(&foundry_issuer::IssuanceError::InvalidRequest(
            "missing issuer_state".to_string(),
        ))
    })?;

    let params = foundry_issuer::AuthorizeParams {
        response_type: q.response_type.unwrap_or_default(),
        client_id: q.client_id.unwrap_or_default(),
        redirect_uri,
        state: q.state,
        code_challenge: q.code_challenge.unwrap_or_default(),
        code_challenge_method: q.code_challenge_method.unwrap_or_default(),
        issuer_state,
        scope: q.scope,
        dpop_jkt: q.dpop_jkt,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx_ttl_secs = state.config.storage.transaction_ttl_secs;

    // HAIP OpenID4VCI L209 -- resolved scope -> credential type id.
    let scopes: std::collections::BTreeMap<String, String> = state
        .config
        .credential_types
        .iter()
        .map(|ct| (ct.resolved_scope().to_string(), ct.id.clone()))
        .collect();

    let outcome = foundry_issuer::handle_authorize_request(
        state.storage.as_ref(),
        &params,
        &state.config.issuer.credential_issuer,
        tx_ttl_secs,
        now,
        &scopes,
    )
    .await;

    match outcome {
        foundry_issuer::AuthorizeOutcome::Success {
            redirect_uri,
            code,
            state: wallet_state,
            iss,
        } => Ok(axum::response::Redirect::to(&append_query(
            &redirect_uri,
            &[("code", code.as_str()), ("iss", iss.as_str())],
            wallet_state.as_deref(),
        ))),
        foundry_issuer::AuthorizeOutcome::ErrorRedirect {
            redirect_uri,
            error,
            state: wallet_state,
            iss,
        } => Ok(axum::response::Redirect::to(&append_query(
            &redirect_uri,
            &[("error", error.as_str()), ("iss", iss.as_str())],
            wallet_state.as_deref(),
        ))),
        foundry_issuer::AuthorizeOutcome::DirectError(e) => Err(wallet_error_response(&e)),
    }
}

/// Reads a header that ABCA draft -07 §6.2 requires to appear *precisely once*,
/// if at all.
///
/// Returns `Ok(None)` when the header is absent, `Ok(Some(value))` when it
/// appears exactly once with a UTF-8 value, and `InvalidClient` otherwise.
///
/// Two failure modes that a plain `HeaderMap::get(..).and_then(|v| v.to_str().ok())`
/// silently swallows are rejected here instead:
///
/// - **Duplicated header.** `get` yields only the first value, so a request
///   carrying the header twice would be processed against the first and the
///   rest discarded unexamined. §6.2 rules 1 and 2 both say "precisely one".
/// - **Non-UTF-8 value.** `to_str().ok()` maps it to `None`, i.e. to *absent*.
///   Under `Mode::Optional` absence is permitted, so an unreadable attestation
///   header would be accepted as "no attestation was presented" rather than
///   as the malformed one it is.
fn exactly_one_header<'h>(
    headers: &'h HeaderMap,
    name: &str,
) -> Result<Option<&'h str>, foundry_issuer::IssuanceError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        // The header name is a fixed literal from the call site, never
        // attacker-controlled, so echoing it carries no injection risk.
        return Err(foundry_issuer::IssuanceError::InvalidClient(format!(
            "{name}: header MUST appear exactly once"
        )));
    }
    // Deliberately does not include the value in the error: it is a client
    // attestation JWT or its PoP, both sensitive per AGENTS.md §4.5.
    let value = first.to_str().map_err(|_| {
        foundry_issuer::IssuanceError::InvalidClient(format!(
            "{name}: header value is not valid UTF-8"
        ))
    })?;
    Ok(Some(value))
}

/// Token Endpoint (OpenID4VCI 1.0 Section 6).
///
/// Optionally authenticates the client with Attestation-Based Client
/// Authentication (`draft-ietf-oauth-attestation-based-client-auth-07`, which
/// OpenID4VCI Appendix E incorporates by reference), gated by
/// `issuer.wallet_attestation.mode`. When a Wallet Attestation is presented,
/// a matching Client Attestation PoP MUST accompany it (ABCA §6.2).
#[utoipa::path(
    post,
    path = "/token",
    request_body = TokenRequest,
    params(
        ("OAuth-Client-Attestation" = Option<String>, Header,
         description = "Wallet Attestation JWT (ABCA §6.1). Required when \
                        issuer.wallet_attestation.mode is `required`. MUST appear \
                        at most once (ABCA §6.2 rule 1)."),
        ("OAuth-Client-Attestation-PoP" = Option<String>, Header,
         description = "Client Attestation PoP JWT (ABCA §5.2/§6.1), proving \
                        possession of the key in the Wallet Attestation's \
                        `cnf.jwk`. Required whenever OAuth-Client-Attestation is \
                        present, under both `required` and `optional` mode \
                        (ABCA §6.2 rule 2). MUST appear at most once."),
        ("DPoP" = Option<String>, Header,
         description = "RFC 9449 §4.1 DPoP proof JWT. Required when \
                        issuer.dpop.mode is `required`. When present and valid, \
                        the issued access token is bound to the proof's key and \
                        the response carries `token_type: DPoP`. MUST appear at \
                        most once (§4.3 check 1)."),
    ),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, description = "RFC 6749 §5.2 error object. `invalid_client` \
                                     for any Wallet Attestation / Client \
                                     Attestation PoP failure, `invalid_grant` for \
                                     an unusable code, `invalid_request` \
                                     otherwise, `invalid_dpop_proof` (RFC 9449 §5) \
                                     for any DPoP proof failure, `use_attestation_challenge` \
                                     (ABCA §6.2) when the PoP's `challenge` claim is missing, \
                                     stale, or wrong -- accompanied by a fresh \
                                     OAuth-Client-Attestation-Challenge response header (§6.2, \
                                     §8.1). The same header MAY also accompany a 200 response \
                                     when challenge retrieval is enabled."),
    )
)]
async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<(HeaderMap, Json<TokenResponse>), (StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let req: TokenRequest = if content_type.contains("application/json") {
        serde_json::from_slice(&body_bytes).map_err(|e| {
            token_error_response(
                &state,
                now,
                &foundry_issuer::IssuanceError::InvalidRequest(e.to_string()),
            )
        })?
    } else {
        serde_html_form::from_bytes(&body_bytes).map_err(|e| {
            token_error_response(
                &state,
                now,
                &foundry_issuer::IssuanceError::InvalidRequest(e.to_string()),
            )
        })?
    };

    // ABCA draft -07 §6.2 rules 1 and 2: there MUST be *precisely one* of each
    // header. `HeaderMap::get` silently returns only the first of several, so a
    // duplicated header would be accepted with the rest ignored; `get_all` is
    // what makes the "precisely one" requirement enforceable.
    //
    // A present-but-non-UTF-8 value is likewise rejected rather than degraded
    // to `None`: treating an unreadable attestation header as *absent* would
    // let it slip through `Mode::Optional` unexamined.
    //
    // axum's `HeaderMap` lookup is already case-insensitive (header names are
    // normalized to lowercase per RFC 9110), satisfying ABCA §6.1's header
    // matching requirement without any extra normalization here.
    let attestation_hdr = exactly_one_header(&headers, "OAuth-Client-Attestation")
        .map_err(|e| token_error_response(&state, now, &e))?;
    let pop_hdr = exactly_one_header(&headers, "OAuth-Client-Attestation-PoP")
        .map_err(|e| token_error_response(&state, now, &e))?;

    // RFC 9449 §4.3 check 1: "There is not more than one DPoP HTTP request
    // header field." `exactly_one_header` is the same guard ABCA §6.2 needs,
    // and for the same reason: `HeaderMap::get` silently returns only the
    // first of several.
    let dpop_hdr =
        exactly_one_header(&headers, "DPoP").map_err(|e| token_error_response(&state, now, &e))?;

    // Sourced from the published AS metadata's own `issuer` field -- not
    // re-derived from `config.issuer.credential_issuer` -- so the value
    // advertised at /.well-known/oauth-authorization-server and the value a
    // PoP's `aud` is checked against can never drift apart.
    let issuer_identifier =
        foundry_issuer::build_authorization_server_metadata(&state.config).issuer;

    // From configuration, never from the Host header: a client-controlled
    // Host would let an attacker replay a proof minted for another origin.
    let htu = format!("{}/token", issuer_identifier.trim_end_matches('/'));
    let dpop_presentation = foundry_issuer::DpopPresentation {
        scheme_is_dpop: false,
        proof_jwt: dpop_hdr,
        htm: "POST",
        htu: &htu,
        ath: None,
    };

    let res = foundry_issuer::handle_token_request(
        state.storage.as_ref(),
        &req,
        &state.config.issuer.wallet_attestation,
        attestation_hdr,
        pop_hdr,
        &state.config.issuer.dpop,
        &dpop_presentation,
        state.nonce_secret.as_ref(),
        &issuer_identifier,
        now,
    )
    .await
    .map_err(|e| token_error_response(&state, now, &e))?;

    // ABCA §8.1: a fresh challenge on the success response too, so a wallet
    // never needs a second `/challenge` call.
    let mut out = HeaderMap::new();
    if let Some((name, value)) = attestation_challenge_header(&state, now) {
        out.insert(name, value);
    }
    // RFC 9449 §8.2: a fresh nonce on the success response too.
    if let Some((name, value)) = dpop_nonce_header(&state, now) {
        out.insert(name, value);
    }
    Ok((out, Json(res)))
}

/// Nonce Endpoint (OpenID4VCI 1.0 Section 7).
///
/// Deliberately **unauthenticated**: Section 7.1 states the endpoint "is not a
/// protected resource, meaning the Wallet does not need to supply an access
/// token to access it". Requiring a bearer token here breaks conformant
/// wallets — they POST an empty body with no `Authorization` header, and on
/// failure end up with no challenge to put in the proof JWT at all.
///
/// Minting is stateless, so an anonymous caller cannot grow storage.
#[utoipa::path(
    post,
    path = "/nonce",
    responses((status = 200, body = NonceResponse))
)]
async fn nonce_handler(
    State(state): State<AppState>,
) -> Result<
    (
        [(axum::http::HeaderName, &'static str); 1],
        Json<NonceResponse>,
    ),
    (StatusCode, Json<serde_json::Value>),
> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::issue_nonce(state.nonce_secret.as_ref(), now)
        .map_err(|e| wallet_error_response(&e))?;

    // Section 7.2: the Credential Issuer MUST make the response uncacheable
    // by adding a Cache-Control header field including the value `no-store`.
    Ok(([(axum::http::header::CACHE_CONTROL, "no-store")], Json(res)))
}

/// Challenge Endpoint (ABCA draft -07 §8).
///
/// Registered only when `issuer.wallet_attestation.challenge_mode` is
/// `optional` or `required`; under `disabled` the route does not exist, so a
/// wallet cannot mistake foundry for a server that supports §8.
///
/// Deliberately **unauthenticated**, like `/nonce`: §8's request example carries
/// no credentials, and a client needs a challenge *before* it can authenticate.
/// Minting is stateless, so an anonymous caller cannot grow storage.
#[utoipa::path(
    post,
    path = "/challenge",
    responses(
        (status = 200, body = ChallengeResponse,
         description = "ABCA §8 challenge. Uncacheable per §8 (`Cache-Control: no-store`)."),
    )
)]
async fn challenge_handler(
    State(state): State<AppState>,
) -> Result<
    (
        [(axum::http::HeaderName, &'static str); 1],
        Json<ChallengeResponse>,
    ),
    (StatusCode, Json<serde_json::Value>),
> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::issue_attestation_challenge(
        state.nonce_secret.as_ref(),
        state.config.issuer.wallet_attestation.pop_max_age_secs,
        now,
    )
    .map_err(|e| wallet_error_response(&e))?;

    // §8: "The Authorization Server MUST make the response uncacheable by
    // adding a Cache-Control header field including the value no-store."
    Ok(([(axum::http::header::CACHE_CONTROL, "no-store")], Json(res)))
}

/// Split an `Authorization` header into its scheme and credentials.
///
/// RFC 9449 §7.1 uses the same `token68` credentials syntax as Bearer
/// (RFC 6750 §2.1), so one splitter serves both. Any scheme other than `DPoP`
/// or `Bearer` -- and a header with no scheme at all -- is rejected before the
/// transaction is even looked up, preserving today's behaviour for malformed
/// `Authorization` headers.
fn parse_authorization(header: &str) -> Result<(bool, &str), foundry_issuer::IssuanceError> {
    let (scheme, credentials) = header.split_once(' ').ok_or_else(|| {
        foundry_issuer::IssuanceError::InvalidGrant("malformed authorization header".into())
    })?;
    let credentials = credentials.trim();
    if credentials.is_empty() {
        return Err(foundry_issuer::IssuanceError::InvalidGrant(
            "empty authorization credentials".into(),
        ));
    }
    // RFC 9110 §11.1: the scheme is case-insensitive.
    if scheme.eq_ignore_ascii_case("DPoP") {
        Ok((true, credentials))
    } else if scheme.eq_ignore_ascii_case("Bearer") {
        Ok((false, credentials))
    } else {
        Err(foundry_issuer::IssuanceError::InvalidGrant(
            "unsupported authorization scheme".into(),
        ))
    }
}

/// Error mapper for the Credential Endpoint, which is a **protected resource**
/// and therefore answers DPoP failures per RFC 9449 §7.1 rather than §5.
///
/// Every non-DPoP error keeps its existing `wallet_error_response` mapping --
/// `/credential` returning 400 for a missing `Authorization` header is a
/// pre-existing question RFC 9449 does not reach, and widening it here would
/// break unrelated tests for no conformance gain.
///
/// Emits exactly one log record per error either way (root `AGENTS.md` §4.5).
fn credential_error_response(
    state: &AppState,
    now_unix: i64,
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    use foundry_issuer::IssuanceError::{InvalidDpopProof, UseDpopNonce};

    // RFC 9449 §9 + §7.1: at a protected resource both DPoP failure families
    // answer 401 with a WWW-Authenticate challenge, but with *different* error
    // codes -- §8's `use_dpop_nonce` is retriable, `invalid_token` is not.
    let dpop_error = match e {
        UseDpopNonce(_) => Some("use_dpop_nonce"),
        InvalidDpopProof(_) => Some("invalid_token"),
        _ => None,
    };

    if let Some(code) = dpop_error {
        log_typed_error("wallet", e.kind(), e, StatusCode::UNAUTHORIZED);
        let mut headers = HeaderMap::new();
        // §7.1: scheme name DPoP, an `error` parameter, and an `algs` parameter
        // "to signal to the client the JWS algorithms that are acceptable for
        // the DPoP proof JWT".
        let description = match code {
            "use_dpop_nonce" => "a server-provided DPoP nonce is required",
            _ => "DPoP binding check failed",
        };
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!(
            r#"DPoP error="{code}", error_description="{description}", algs="ES256""#
        )) {
            headers.insert(axum::http::header::WWW_AUTHENTICATE, v);
        }
        // §9: the nonce the client needs in order to retry.
        if let Some((name, value)) = dpop_nonce_header(state, now_unix) {
            headers.insert(name, value);
        }
        return (
            StatusCode::UNAUTHORIZED,
            headers,
            Json(serde_json::json!({
                "error": code,
                "error_description": e.to_string(),
            })),
        );
    }

    let (status, body) = wallet_error_response(e);
    (status, HeaderMap::new(), body)
}

#[utoipa::path(
    post,
    path = "/credential",
    request_body = CredentialRequest,
    params(
        ("Authorization" = String, Header,
         description = "`Bearer <access_token>` for an unbound token, or \
                        `DPoP <access_token>` (RFC 9449 §7.1) when the token is \
                        DPoP-bound. A bound token presented as Bearer is rejected \
                        (§7.2)."),
        ("DPoP" = Option<String>, Header,
         description = "RFC 9449 §4.1 DPoP proof JWT, carrying an `ath` claim \
                        (§7) bound to the presented access token. Required \
                        alongside `Authorization: DPoP ...`. MUST appear at most \
                        once (§4.3 check 1)."),
    ),
    responses(
        (status = 200, body = CredentialResponse),
        (status = 401, description = "RFC 9449 §7.1: WWW-Authenticate: DPoP \
                                     error=\"invalid_token\", algs=\"ES256\" -- the \
                                     access token's DPoP binding check failed \
                                     (missing/invalid proof, key mismatch, or a \
                                     bound token presented as Bearer); or \
                                     error=\"use_dpop_nonce\" (§8/§9) when a \
                                     server-provided nonce is required and \
                                     missing/stale, accompanied by a fresh \
                                     DPoP-Nonce response header."),
    )
)]
async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Result<(HeaderMap, Json<CredentialResponse>), (StatusCode, HeaderMap, Json<serde_json::Value>)>
{
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            credential_error_response(
                &state,
                now,
                &foundry_issuer::IssuanceError::InvalidGrant("missing authorization header".into()),
            )
        })?;

    let (scheme_is_dpop, access_token) =
        parse_authorization(auth_header).map_err(|e| credential_error_response(&state, now, &e))?;

    // RFC 9449 §4.3 check 1.
    let dpop_hdr = exactly_one_header(&headers, "DPoP")
        .map_err(|e| credential_error_response(&state, now, &e))?;

    // §7: ath is always computed here, so the engine never has to.
    let ath = foundry_issuer::access_token_hash(access_token);
    let credential_issuer = state.config.issuer.credential_issuer.trim_end_matches('/');
    let htu = format!("{credential_issuer}/credential");
    let dpop = foundry_issuer::DpopPresentation {
        scheme_is_dpop,
        proof_jwt: dpop_hdr,
        htm: "POST",
        htu: &htu,
        ath: Some(&ath),
    };

    let res = foundry_issuer::handle_credential_request(
        &state.config,
        state.storage.as_ref(),
        access_token,
        &req,
        state.nonce_secret.as_ref(),
        &dpop,
        now,
    )
    .await
    .map_err(|e| credential_error_response(&state, now, &e))?;

    // §8.2: supply a nonce on success too, so the wallet holds a usable one
    // before its next request.
    let mut out = HeaderMap::new();
    if let Some((name, value)) = dpop_nonce_header(&state, now) {
        out.insert(name, value);
    }
    Ok((out, Json(res)))
}

fn verifier_admin_error_response(
    e: &foundry_verifier::VerificationError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_verifier::VerificationError::*;
    let status = match e {
        Dcql(_) | InvalidRequest(_) | Serialization(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    log_typed_error("admin", e.kind(), e, status);
    (
        status,
        Json(serde_json::json!({ "error": e.to_string(), "message": e.to_string() })),
    )
}

/// Maps a `VerificationError` to the OpenID4VP-response HTTP status/error-code
/// classification (root AGENTS.md §4.3). This classification is a property of
/// the response itself, not of which route received it, so it is identical
/// whether the encrypted JWE arrived from a real wallet
/// (`POST /vp/response/:id`) or was relayed by the admin console after a
/// browser-side Digital Credentials API call
/// (`POST /admin/verification/requests/:id/dc-api-response`). Only the
/// `surface` log label differs between the two callers (root AGENTS.md §4.5).
fn verifier_wallet_error_response(
    e: &foundry_verifier::VerificationError,
    surface: &'static str,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_verifier::VerificationError::*;
    let (status, code) = match e {
        Decryption(_) | Failed(_) | Serialization(_) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        StatusUnavailable(_) => (StatusCode::BAD_GATEWAY, "status_unavailable"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    log_typed_error(surface, e.kind(), e, status);
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": e.to_string(),
        })),
    )
}

#[utoipa::path(
    post,
    path = "/admin/verification/requests",
    request_body = CreateVerificationRequest,
    responses((status = 200, body = CreateVerificationResponse))
)]
pub(crate) async fn create_verification_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateVerificationRequest>,
) -> Result<Json<CreateVerificationResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    foundry_verifier::create_verification_request(&state.config, state.storage.as_ref(), req, now)
        .await
        .map(Json)
        .map_err(|e| verifier_admin_error_response(&e))
}

#[utoipa::path(
    get,
    path = "/admin/verification/requests/{id}",
    responses((status = 200, body = VerificationTransaction), (status = 404))
)]
pub(crate) async fn get_verification_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<VerificationTransaction>, StatusCode> {
    let tx = foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|e| internal_error("load_verification_transaction", e.kind(), e))?;
    match tx {
        Some(tx) => Ok(Json(tx)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// The Digital Credentials API delivers the wallet's encrypted response as a
/// JS object property (`credentialResponse.data.response`), not a URL-encoded
/// form body, so the admin console submits it here as JSON instead of the
/// `application/x-www-form-urlencoded` shape `VpResponseForm` uses.
/// `foundry-verifier`'s `create_verification_request` always sets
/// `response_mode: "dc_api.jwt"` for `transport: "dc_api"` (never the
/// plaintext `dc_api` mode), so this is always the encrypted-JWE shape — there
/// is no unencrypted variant to additionally support here.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct AdminDcApiResponseBody {
    /// JWE compact serialization of the VP Token response, as delivered in
    /// `credentialResponse.data.response` by `navigator.credentials.get()`.
    response: String,
}

/// Admin-authenticated counterpart to `post_response_handler`, used by the
/// test console to relay the browser's Digital Credentials API response for
/// verification. See `submit_vp_response` for the shared core; the only
/// difference from the wallet-facing route is the request encoding (JSON, not
/// form-urlencoded) and the `surface` log label (`"admin"`, not `"wallet"`).
#[utoipa::path(
    post,
    path = "/admin/verification/requests/{id}/dc-api-response",
    request_body = AdminDcApiResponseBody,
    responses((status = 200, body = VerificationResult))
)]
pub(crate) async fn post_admin_dc_api_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AdminDcApiResponseBody>,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    submit_vp_response(&state, &id, &body.response, "admin").await
}

#[utoipa::path(
    get,
    path = "/vp/request/{id}",
    responses(
        (status = 200, description = "Signed Request Object JWT", content_type = "application/oauth-authz-req+jwt", body = String),
        (status = 404)
    )
)]
async fn get_request_object_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    let tx = foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|e| internal_error("load_verification_transaction", e.kind(), e))?;
    let tx = match tx {
        Some(tx) => tx,
        None => return Err(StatusCode::NOT_FOUND),
    };
    let jws_str = foundry_verifier::build_signed_request_object(&state.config, &tx)
        .map_err(|e| internal_error("build_signed_request_object", e.kind(), e))?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/oauth-authz-req+jwt",
        )],
        jws_str,
    ))
}

/// Shared core of "submit a wallet's encrypted VP Token response for
/// verification": load the transaction, reject if not `Pending`, call
/// `verify_vp_response`, persist the outcome, and map any error through the
/// same classification `post_response_handler` has always used. Used by both
/// the real wallet-facing route (`surface = "wallet"`) and the admin-facing
/// Digital Credentials API route (`surface = "admin"`) — see
/// `verifier_wallet_error_response` for why the status/code mapping itself
/// must not vary between the two callers.
async fn submit_vp_response(
    state: &AppState,
    id: &str,
    encrypted_jwe_str: &str,
    surface: &'static str,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx_opt = foundry_verifier::load_verification_transaction(state.storage.as_ref(), id)
        .await
        .map_err(|e| verifier_wallet_error_response(&e, surface))?;
    let mut tx = match tx_opt {
        Some(tx) => tx,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "error_description": format!("verification transaction '{id}' not found")
                })),
            ))
        }
    };

    if tx.state != foundry_verifier::VerificationState::Pending {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "verification response already submitted"
            })),
        ));
    }

    let resolver = match foundry_verifier::HttpStatusListResolver::new() {
        Ok(r) => r,
        Err(e) => return Err(verifier_wallet_error_response(&e, surface)),
    };
    let verify_res =
        foundry_verifier::verify_vp_response(&state.config, &mut tx, encrypted_jwe_str, &resolver)
            .await;

    // Losing this write is its own defect: it makes the admin API and the console
    // disagree with what actually happened. It must not change the response the
    // caller receives, so it is logged rather than propagated.
    if let Err(e) = foundry_verifier::save_verification_transaction(
        state.storage.as_ref(),
        &tx,
        state.config.storage.transaction_ttl_secs,
        now,
    )
    .await
    {
        tracing::error!(
            op = "save_verification_transaction",
            tx_id = %tx.id,
            error.kind = e.kind(),
            error.detail = %foundry_core::obs::truncate(&e.to_string(), DETAIL_MAX),
            "failed to persist the verification verdict; the admin API will not \
             reflect this transaction's outcome"
        );
    }

    match verify_res {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(verifier_wallet_error_response(&e, surface)),
    }
}

/// The OpenID4VP `direct_post.jwt` authorization response body.
///
/// The verifier advertises `response_mode: direct_post.jwt`, so per OpenID4VP
/// 1.0 §8.2/§8.3 the wallet POSTs `application/x-www-form-urlencoded` with the
/// JWE compact serialization in a `response` parameter.
///
/// Deliberately **not** `deny_unknown_fields`: §8 permits additional members
/// (wallets commonly echo `state`), and rejecting them would break conformant
/// wallets.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct VpResponseForm {
    /// JWE compact serialization of the VP Token response.
    response: String,
}

// NOTE: `content = VpResponseForm` must stay **unqualified**. utoipa generates the
// `$ref` from the literal spelling in this attribute, so a qualified path such as
// `crate::server::VpResponseForm` emits a dotted name that never matches the plain
// key `components(schemas(...))` registers — the resolver break fixed in 09b0bb0.
#[utoipa::path(
    post,
    path = "/vp/response/{id}",
    request_body(
        content = VpResponseForm,
        content_type = "application/x-www-form-urlencoded",
        description = "OpenID4VP `direct_post.jwt` authorization response: the `response` \
                       parameter carries the JWE compact serialization of the VP Token"
    ),
    responses((status = 200, body = VerificationResult))
)]
async fn post_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body_bytes: axum::body::Bytes,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    // Parse before touching storage: a malformed body is malformed regardless of
    // whether the transaction exists, so rejecting it first keeps the 400
    // deterministic instead of returning 400 or 404 depending on the id.
    let form: VpResponseForm = serde_html_form::from_bytes(&body_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": format!(
                    "expected an application/x-www-form-urlencoded body with a `response` parameter \
                     carrying the JWE (OpenID4VP direct_post.jwt): {e}"
                )
            })),
        )
    })?;

    submit_vp_response(&state, &id, &form.response, "wallet").await
}

#[utoipa::path(
    get,
    path = "/statuslists/{id}",
    responses(
        (status = 200, description = "Signed Status List Token JWT", content_type = "application/statuslist+jwt", body = String),
        (status = 404)
    )
)]
async fn status_list_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    if !state.config.issuer.status_list.enabled {
        return Err(StatusCode::NOT_FOUND);
    }

    let persistent = foundry_core::status_list::load_status_list(state.storage.as_ref(), &id)
        .await
        .map_err(|e| internal_error("load_status_list", "storage", e))?;
    let persistent = match persistent {
        Some(p) => p,
        None => return Err(StatusCode::NOT_FOUND),
    };
    let status_list = persistent
        .to_status_list(None)
        .map_err(|e| internal_error("to_status_list", "status_list", e))?;

    // These two are misconfigurations, not runtime faults: without a log line a
    // status-list request 500s with no explanation anywhere.
    let key_name = state
        .config
        .issuer
        .status_list
        .signing_key
        .as_deref()
        .ok_or_else(|| {
            internal_error(
                "status_list_signing_key",
                "config",
                "issuer.status_list.signing_key is not set but status lists are enabled",
            )
        })?;
    let key_entry = state.config.keys.get(key_name).ok_or_else(|| {
        internal_error(
            "status_list_signing_key",
            "config",
            format_args!("issuer.status_list.signing_key '{key_name}' is not present in keys"),
        )
    })?;
    let alg: foundry_core::crypto::SignatureAlgorithm = key_entry
        .alg
        .parse()
        .map_err(|e| internal_error("parse_signing_alg", "config", e))?;

    let base_url = state
        .config
        .issuer
        .status_list
        .public_base_url
        .as_deref()
        .unwrap_or(&state.config.issuer.credential_issuer);
    let sub = format!("{}/{}", base_url.trim_end_matches('/'), id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let token = foundry_core::status_list::sign_status_list_token(
        &status_list,
        sub,
        now,
        &key_entry.private_key,
        alg,
        key_entry.x5c.as_deref().map(std::path::Path::new),
    )
    .map_err(|e| internal_error("sign_status_list_token", "crypto", e))?;

    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/statuslist+jwt",
        )],
        token,
    ))
}

pub fn spawn_sweeper(storage: Arc<dyn Storage>, interval_secs: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        loop {
            ticker.tick().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            match storage.purge_expired(now).await {
                Ok(n) if n > 0 => tracing::debug!(purged = n, "swept expired rows"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "sweeper purge failed"),
            }
        }
    })
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    if let Err(e) = std::fs::write(
        "openapi.json",
        crate::openapi::generate_admin_openapi_spec(),
    ) {
        tracing::warn!(error = %e, "failed to write openapi.json on startup");
    } else {
        tracing::debug!("wrote openapi.json on startup");
    }

    if let Err(e) = std::fs::write(
        "openapi-wallet.json",
        crate::openapi::generate_wallet_openapi_spec(),
    ) {
        tracing::warn!(error = %e, "failed to write openapi-wallet.json on startup");
    } else {
        tracing::debug!("wrote openapi-wallet.json on startup");
    }

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::connect(&cfg.storage.path).await?);
    let config = Arc::new(cfg.clone());
    let state = AppState::new(storage.clone(), config.clone());
    let _sweeper = spawn_sweeper(storage, 60);

    let api_key = AdminApiKey::resolve(&cfg.server.admin);
    if api_key.0.is_none() {
        tracing::warn!(
            "admin API key not configured — admin endpoints are UNAUTHENTICATED (dev only)"
        );
    }
    let admin_app = admin_router(state.clone(), api_key);
    let wallet_app = wallet_router(state);

    let admin_listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    let wallet_listener = tokio::net::TcpListener::bind(&cfg.server.wallet_facing.bind).await?;
    let admin_bound_addr = admin_listener.local_addr()?;
    let wallet_bound_addr = wallet_listener.local_addr()?;
    tracing::info!(bind = %admin_bound_addr, "foundry admin server listening");
    tracing::info!(bind = %wallet_bound_addr, "foundry wallet-facing server listening");

    tokio::try_join!(
        axum::serve(admin_listener, admin_app).into_future(),
        axum::serve(wallet_listener, wallet_app).into_future(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_capture;
    use foundry_issuer::IssuanceError;
    use foundry_verifier::VerificationError;
    use tracing::Level;

    /// Run `body` under a capture layer and return what it logged.
    fn captured(body: impl FnOnce()) -> Vec<log_capture::CapturedEvent> {
        use tracing_subscriber::layer::SubscriberExt;
        let (layer, handle) = log_capture::capture_layer();
        let subscriber = tracing_subscriber::Registry::default()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(layer);
        tracing::subscriber::with_default(subscriber, body);
        handle.events()
    }

    /// Every mapper must emit exactly one record. More than one would
    /// double-count in an alert; none is the defect this work exists to fix.
    #[test]
    fn each_mapper_logs_exactly_one_record() {
        let events = captured(|| {
            let _ = admin_error_response(&IssuanceError::Internal("boom".into()));
        });
        assert_eq!(events.len(), 1, "admin issuance mapper: {events:?}");

        let events = captured(|| {
            let _ = wallet_error_response(&IssuanceError::InvalidGrant("bad code".into()));
        });
        assert_eq!(events.len(), 1, "wallet issuance mapper: {events:?}");

        let events = captured(|| {
            let _ = verifier_admin_error_response(&VerificationError::Dcql("no match".into()));
        });
        assert_eq!(events.len(), 1, "admin verification mapper: {events:?}");

        let events = captured(|| {
            let _ = verifier_wallet_error_response(
                &VerificationError::Decryption("nope".into()),
                "wallet",
            );
        });
        assert_eq!(events.len(), 1, "wallet verification mapper: {events:?}");
    }

    #[test]
    fn mapper_records_kind_detail_and_status() {
        let events = captured(|| {
            let _ = verifier_wallet_error_response(
                &VerificationError::Decryption("cek unwrap failed".into()),
                "wallet",
            );
        });
        let e = &events[0];
        assert_eq!(
            e.fields.get("error.kind").map(String::as_str),
            Some("decryption")
        );
        assert_eq!(e.fields.get("http.status").map(String::as_str), Some("400"));
        assert_eq!(e.fields.get("surface").map(String::as_str), Some("wallet"));
        assert!(
            e.fields
                .get("error.detail")
                .is_some_and(|d| d.contains("cek unwrap failed")),
            "detail should carry the diagnostic: {e:?}"
        );
    }

    /// Level follows the status class, matching the access log's rule.
    #[test]
    fn level_follows_status_class() {
        // 400 -> WARN
        let events = captured(|| {
            let _ = verifier_wallet_error_response(
                &VerificationError::Decryption("x".into()),
                "wallet",
            );
        });
        assert_eq!(events[0].level, Level::WARN);

        // 500 -> ERROR
        let events = captured(|| {
            let _ = admin_error_response(&IssuanceError::Internal("x".into()));
        });
        assert_eq!(events[0].level, Level::ERROR);

        // 502 -> ERROR: an unreachable status list needs operator attention.
        let events = captured(|| {
            let _ = verifier_wallet_error_response(
                &VerificationError::StatusUnavailable("dns".into()),
                "wallet",
            );
        });
        assert_eq!(events[0].level, Level::ERROR);
        assert_eq!(
            events[0].fields.get("http.status").map(String::as_str),
            Some("502")
        );

        // 503 -> ERROR
        let events = captured(|| {
            let _ = wallet_error_response(&IssuanceError::StatusListExhausted("pid".into()));
        });
        assert_eq!(events[0].level, Level::ERROR);
    }

    /// The status mapping is spec-governed (root AGENTS.md §4.3). Adding logging
    /// must not have perturbed it.
    #[test]
    fn status_mapping_is_unchanged_by_logging() {
        assert_eq!(
            admin_error_response(&IssuanceError::UnknownCredentialType("x".into())).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin_error_response(&IssuanceError::StatusListExhausted("x".into())).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            admin_error_response(&IssuanceError::Internal("x".into())).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            wallet_error_response(&IssuanceError::InvalidProof("x".into())).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            verifier_admin_error_response(&VerificationError::Dcql("x".into())).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            verifier_admin_error_response(&VerificationError::Crypto("x".into())).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            verifier_wallet_error_response(&VerificationError::Decryption("x".into()), "wallet").0,
            StatusCode::BAD_REQUEST
        );
        // GAP-VCI-14 / RFC 6749 sect-5.2: a failed client-authentication mechanism
        // is invalid_client, distinct from a malformed request.
        assert_eq!(
            wallet_error_response(&IssuanceError::InvalidClient("x".into())).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            verifier_wallet_error_response(
                &VerificationError::StatusUnavailable("x".into()),
                "wallet"
            )
            .0,
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn detail_is_length_capped() {
        let long = "z".repeat(DETAIL_MAX * 3);
        let events = captured(|| {
            let _ =
                verifier_wallet_error_response(&VerificationError::Failed(long.clone()), "wallet");
        });
        let detail = events[0]
            .fields
            .get("error.detail")
            .expect("detail present");
        assert!(
            detail.len() < DETAIL_MAX * 2,
            "detail was not capped: {} bytes",
            detail.len()
        );
        assert!(detail.contains("truncated"));
    }

    /// `internal_error` exists so that a handler collapsing to a bare StatusCode
    /// still leaves a diagnostic behind.
    #[test]
    fn internal_error_logs_and_returns_500() {
        let mut status = None;
        let events = captured(|| {
            status = Some(internal_error(
                "load_status_list",
                "storage",
                "disk on fire",
            ));
        });
        assert_eq!(status, Some(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].level, Level::ERROR);
        assert_eq!(
            events[0].fields.get("op").map(String::as_str),
            Some("load_status_list")
        );
        assert_eq!(
            events[0].fields.get("error.kind").map(String::as_str),
            Some("storage")
        );
        assert!(events[0]
            .fields
            .get("error.detail")
            .is_some_and(|d| d.contains("disk on fire")));
    }

    /// GAP-VCI-14: the wire body for a failed Client Attestation / PoP JWT is
    /// `{"error": "invalid_client"}`, matching RFC 6749 sect-5.2 -- not
    /// `invalid_request`, which the endpoint used to return for every
    /// attestation failure regardless of cause.
    #[test]
    fn invalid_client_wire_body_is_rfc6749_shaped() {
        let (status, Json(body)) =
            wallet_error_response(&IssuanceError::InvalidClient("pop jti replayed".into()));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_client");
        assert_eq!(
            body["error_description"],
            "invalid client: pop jti replayed"
        );
    }

    /// `InvalidClient` has no admin-surface meaning (client authentication is a
    /// wallet-facing concept) -- it must fall through the admin mapper's
    /// existing catch-all to 500, not silently gain a bespoke admin status.
    #[test]
    fn invalid_client_is_not_special_cased_on_the_admin_surface() {
        assert_eq!(
            admin_error_response(&IssuanceError::InvalidClient("x".into())).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// No production path in this file may throw an error object away on its way
    /// to a bare `StatusCode` — that is precisely the shape that made the
    /// original defect undiagnosable.
    ///
    /// Scans only the code above this test module, and assembles the needles at
    /// runtime, so the assertion cannot match its own source text.
    #[test]
    fn no_error_is_silently_discarded_in_production_code() {
        let src = include_str!("server.rs");
        let production = src
            .split_once("\n#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(src);

        let discarding_map_err = format!("map_err(|_| {}::", "StatusCode");
        assert!(
            !production.contains(&discarding_map_err),
            "found a map_err that discards the error object; use internal_error() so \
             the failure leaves a diagnostic behind"
        );

        let bare_ok_or = format!("ok_or({}::", "StatusCode");
        assert!(
            !production.contains(&bare_ok_or),
            "found an ok_or that yields a bare status with no diagnostic; use \
             ok_or_else(|| internal_error(..))"
        );

        let swallowed_save = format!(
            "let _ = {}::save_verification_transaction",
            "foundry_verifier"
        );
        assert!(
            !production.contains(&swallowed_save),
            "the verification verdict save must not be silently discarded"
        );
    }
}
