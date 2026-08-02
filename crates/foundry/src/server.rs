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
    AuthorizationServerMetadata, CreateOfferRequest, CreateOfferResponse, CredentialIssuerMetadata,
    CredentialRequest, CredentialResponse, NonceResponse, TokenRequest, TokenResponse,
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
            "/admin/verification/requests",
            post(create_verification_handler),
        )
        .route(
            "/admin/verification/requests/:id",
            get(get_verification_handler),
        )
        .route_layer(middleware::from_fn_with_state(api_key, require_api_key))
        .with_state(state);

    crate::http_log::with_access_log(unauthenticated.merge(authenticated), "admin")
}

pub fn wallet_router(state: AppState) -> Router {
    let router = Router::new()
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
    Json(foundry_issuer::build_issuer_metadata(&state.config))
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
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx_ttl_secs = state.config.storage.transaction_ttl_secs;

    let outcome =
        foundry_issuer::handle_authorize_request(state.storage.as_ref(), &params, tx_ttl_secs, now)
            .await;

    match outcome {
        foundry_issuer::AuthorizeOutcome::Success {
            redirect_uri,
            code,
            state: wallet_state,
        } => Ok(axum::response::Redirect::to(&append_query(
            &redirect_uri,
            &[("code", code.as_str())],
            wallet_state.as_deref(),
        ))),
        foundry_issuer::AuthorizeOutcome::ErrorRedirect {
            redirect_uri,
            error,
            state: wallet_state,
        } => Ok(axum::response::Redirect::to(&append_query(
            &redirect_uri,
            &[("error", error.as_str())],
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
    ),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, description = "RFC 6749 §5.2 error object. `invalid_client` \
                                     for any Wallet Attestation / Client \
                                     Attestation PoP failure, `invalid_grant` for \
                                     an unusable code, `invalid_request` \
                                     otherwise."),
    )
)]
async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let req: TokenRequest = if content_type.contains("application/json") {
        serde_json::from_slice(&body_bytes).map_err(|e| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidRequest(
                e.to_string(),
            ))
        })?
    } else {
        serde_html_form::from_bytes(&body_bytes).map_err(|e| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidRequest(
                e.to_string(),
            ))
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
        .map_err(|e| wallet_error_response(&e))?;
    let pop_hdr = exactly_one_header(&headers, "OAuth-Client-Attestation-PoP")
        .map_err(|e| wallet_error_response(&e))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Sourced from the published AS metadata's own `issuer` field -- not
    // re-derived from `config.issuer.credential_issuer` -- so the value
    // advertised at /.well-known/oauth-authorization-server and the value a
    // PoP's `aud` is checked against can never drift apart.
    let issuer_identifier =
        foundry_issuer::build_authorization_server_metadata(&state.config).issuer;

    foundry_issuer::handle_token_request(
        state.storage.as_ref(),
        &req,
        &state.config.issuer.wallet_attestation,
        attestation_hdr,
        pop_hdr,
        &issuer_identifier,
        now,
    )
    .await
    .map(Json)
    .map_err(|e| wallet_error_response(&e))
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

#[utoipa::path(
    post,
    path = "/credential",
    request_body = CredentialRequest,
    responses((status = 200, body = CredentialResponse))
)]
async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Result<Json<CredentialResponse>, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
                "missing authorization header".into(),
            ))
        })?;

    let access_token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
            "invalid bearer authorization header".into(),
        ))
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    foundry_issuer::handle_credential_request(
        &state.config,
        state.storage.as_ref(),
        access_token,
        &req,
        state.nonce_secret.as_ref(),
        now,
    )
    .await
    .map(Json)
    .map_err(|e| wallet_error_response(&e))
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

fn verifier_wallet_error_response(
    e: &foundry_verifier::VerificationError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_verifier::VerificationError::*;
    let (status, code) = match e {
        Decryption(_) | Failed(_) | Serialization(_) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        StatusUnavailable(_) => (StatusCode::BAD_GATEWAY, "status_unavailable"),
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
    let encrypted_jwe_str = form.response;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx_opt = foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|e| verifier_wallet_error_response(&e))?;
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
        Err(e) => return Err(verifier_wallet_error_response(&e)),
    };
    let verify_res =
        foundry_verifier::verify_vp_response(&state.config, &mut tx, &encrypted_jwe_str, &resolver)
            .await;

    // Losing this write is its own defect: it makes the admin API and the console
    // disagree with what actually happened. It must not change the response the
    // wallet receives, so it is logged rather than propagated.
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
        Err(e) => Err(verifier_wallet_error_response(&e)),
    }
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
            let _ = verifier_wallet_error_response(&VerificationError::Decryption("nope".into()));
        });
        assert_eq!(events.len(), 1, "wallet verification mapper: {events:?}");
    }

    #[test]
    fn mapper_records_kind_detail_and_status() {
        let events = captured(|| {
            let _ = verifier_wallet_error_response(&VerificationError::Decryption(
                "cek unwrap failed".into(),
            ));
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
            let _ = verifier_wallet_error_response(&VerificationError::Decryption("x".into()));
        });
        assert_eq!(events[0].level, Level::WARN);

        // 500 -> ERROR
        let events = captured(|| {
            let _ = admin_error_response(&IssuanceError::Internal("x".into()));
        });
        assert_eq!(events[0].level, Level::ERROR);

        // 502 -> ERROR: an unreachable status list needs operator attention.
        let events = captured(|| {
            let _ =
                verifier_wallet_error_response(&VerificationError::StatusUnavailable("dns".into()));
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
            verifier_wallet_error_response(&VerificationError::Decryption("x".into())).0,
            StatusCode::BAD_REQUEST
        );
        // GAP-VCI-14 / RFC 6749 sect-5.2: a failed client-authentication mechanism
        // is invalid_client, distinct from a malformed request.
        assert_eq!(
            wallet_error_response(&IssuanceError::InvalidClient("x".into())).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            verifier_wallet_error_response(&VerificationError::StatusUnavailable("x".into())).0,
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn detail_is_length_capped() {
        let long = "z".repeat(DETAIL_MAX * 3);
        let events = captured(|| {
            let _ = verifier_wallet_error_response(&VerificationError::Failed(long.clone()));
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
