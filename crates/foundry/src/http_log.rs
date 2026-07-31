//! HTTP access logging.
//!
//! One `axum` middleware, applied to both listeners, that does two things:
//!
//! 1. establishes a `tracing` span carrying the request's correlation fields, so
//!    that **every** event emitted downstream — handler, error mapper, issuer or
//!    verifier engine — inherits them without having to thread anything through
//!    call signatures;
//! 2. emits exactly one access record per request, with the status and latency.
//!
//! # Why hand-rolled rather than `tower-http`'s `TraceLayer`
//!
//! `TraceLayer`'s default `MakeSpan` records the full request URI **including the
//! query string**. `/authorize` and `/token` carry sensitive parameters, so both
//! `MakeSpan` and `OnResponse` would need overriding — which is most of the code
//! below, in exchange for a new dependency.
//!
//! # The route field
//!
//! `route` is always the route *template* (`/vp/response/:id`), read from
//! `MatchedPath`, never the concrete URI. That is a structural guarantee, not a
//! convention: a path parameter or query string cannot leak through this field
//! because the concrete path is never formatted into it.

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use std::time::Instant;
use tracing::Instrument;
use uuid::Uuid;

/// Response header carrying this request's correlation id.
///
/// A wallet developer, console user or operator can quote it to tie a failure
/// they saw to the server-side records.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Value of the `route` field when no route matched (a 404).
///
/// A literal placeholder rather than the requested URI: an unrouted path is
/// attacker-controlled input and must not be echoed into the log.
pub const UNMATCHED_ROUTE: &str = "<unmatched>";

/// Wrap `router` so every request through it is logged and correlated.
///
/// `listener` labels which of the two listeners served the request — the admin
/// and wallet-facing routers bind separate ports and mount disjoint route sets,
/// so the label is needed to tell otherwise-identical records apart.
///
/// Returns a `Router` rather than a layer because naming the concrete
/// `FromFnLayer` type here would expose an unnameable generic parameter.
pub fn with_access_log(router: Router, listener: &'static str) -> Router {
    router.layer(middleware::from_fn_with_state(listener, access_log))
}

async fn access_log(
    State(listener): State<&'static str>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let method = request.method().clone();

    // The route *template*, never the concrete URI. `MatchedPath` is absent for
    // unrouted requests, which degrades to a placeholder rather than panicking or
    // echoing attacker-controlled input.
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| UNMATCHED_ROUTE.to_string());

    // Everything emitted downstream inherits these fields. This is the only
    // reason an engine event can carry `request_id` without the engines knowing
    // anything about HTTP.
    let span = tracing::info_span!(
        "http",
        request_id = %request_id,
        method = %method,
        route = %route,
        listener = %listener,
    );

    async move {
        let started = Instant::now();
        let mut response = next.run(request).await;
        let latency_ms = started.elapsed().as_millis();
        let status = response.status();

        // Infallible in practice — a UUID is ASCII — but constructed without
        // unwrapping so a future change to the id format cannot panic a request.
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
        }

        let code = status.as_u16();
        if status.is_server_error() {
            tracing::error!(http.status = code, latency_ms, "request failed");
        } else if status.is_client_error() {
            tracing::warn!(http.status = code, latency_ms, "request rejected");
        } else {
            tracing::info!(http.status = code, latency_ms, "request completed");
        }

        response
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_capture;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;
    use tracing::Level;
    use tracing_subscriber::filter::LevelFilter;

    fn test_router(listener: &'static str) -> Router {
        let router = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .route("/thing/:id", get(|| async { "thing" }))
            .route("/bad", get(|| async { StatusCode::BAD_REQUEST }))
            .route("/boom", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }));
        with_access_log(router, listener)
    }

    /// Drive one request through the middleware and return the response plus
    /// everything that was logged.
    async fn call(
        listener: &'static str,
        uri: &str,
    ) -> (axum::http::Response<Body>, Vec<log_capture::CapturedEvent>) {
        let (layer, handle) = log_capture::capture_layer();
        let subscriber = {
            use tracing_subscriber::layer::SubscriberExt;
            tracing_subscriber::Registry::default()
                .with(LevelFilter::TRACE)
                .with(layer)
        };
        let guard = tracing::subscriber::set_default(subscriber);
        let response = test_router(listener)
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        drop(guard);
        let events = handle.events();
        (response, events)
    }

    fn access_events(events: &[log_capture::CapturedEvent]) -> Vec<&log_capture::CapturedEvent> {
        events
            .iter()
            .filter(|e| e.fields.contains_key("http.status"))
            .collect()
    }

    #[tokio::test]
    async fn logs_exactly_one_record_per_request_with_the_documented_fields() {
        let (response, events) = call("wallet", "/ok").await;
        assert_eq!(response.status(), StatusCode::OK);

        let access = access_events(&events);
        assert_eq!(
            access.len(),
            1,
            "expected one access record, got {access:?}"
        );
        let e = access[0];
        assert_eq!(e.level, Level::INFO);
        assert_eq!(e.fields.get("method").map(String::as_str), Some("GET"));
        assert_eq!(e.fields.get("route").map(String::as_str), Some("/ok"));
        assert_eq!(e.fields.get("listener").map(String::as_str), Some("wallet"));
        assert_eq!(e.fields.get("http.status").map(String::as_str), Some("200"));
        assert!(
            e.fields.contains_key("latency_ms"),
            "latency must be recorded: {e:?}"
        );
        let request_id = e.fields.get("request_id").expect("request_id field");
        assert!(!request_id.is_empty());
    }

    #[tokio::test]
    async fn level_follows_status_class() {
        let (_, events) = call("wallet", "/ok").await;
        assert_eq!(access_events(&events)[0].level, Level::INFO);

        let (_, events) = call("wallet", "/bad").await;
        assert_eq!(access_events(&events)[0].level, Level::WARN);

        let (_, events) = call("wallet", "/boom").await;
        assert_eq!(access_events(&events)[0].level, Level::ERROR);
    }

    /// The whole point of using `MatchedPath`: an identifier in the path must not
    /// end up in a log field, or every id becomes a distinct log dimension and
    /// any sensitive path segment leaks.
    #[tokio::test]
    async fn route_records_the_template_not_the_concrete_path() {
        let (_, events) = call("wallet", "/thing/abc-123-secret").await;
        let e = access_events(&events)[0];
        assert_eq!(
            e.fields.get("route").map(String::as_str),
            Some("/thing/:id")
        );
        assert!(
            !events
                .iter()
                .any(|e| e.fields.values().any(|v| v.contains("abc-123-secret"))),
            "the concrete path segment must not appear in any field"
        );
    }

    #[tokio::test]
    async fn an_unmatched_request_is_logged_without_panicking() {
        let (response, events) = call("wallet", "/no/such/route").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let access = access_events(&events);
        assert_eq!(access.len(), 1);
        assert_eq!(
            access[0].fields.get("route").map(String::as_str),
            Some(UNMATCHED_ROUTE)
        );
        assert_eq!(access[0].level, Level::WARN, "404 is a client error");
    }

    /// An operator, a wallet developer or a console user must be able to quote an
    /// identifier that ties their failure to the server-side records.
    #[tokio::test]
    async fn response_carries_x_request_id_matching_the_logged_id() {
        let (response, events) = call("admin", "/ok").await;
        let header = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("x-request-id header present")
            .to_str()
            .expect("header is valid ascii")
            .to_string();
        let logged = access_events(&events)[0]
            .fields
            .get("request_id")
            .expect("request_id field")
            .clone();
        assert_eq!(header, logged);
    }

    #[tokio::test]
    async fn request_ids_are_unique_per_request() {
        let (_, a) = call("admin", "/ok").await;
        let (_, b) = call("admin", "/ok").await;
        assert_ne!(
            access_events(&a)[0].fields.get("request_id"),
            access_events(&b)[0].fields.get("request_id")
        );
    }

    /// Query strings carry `code`, `state` and other sensitive parameters on
    /// `/authorize` and `/token`, so no query value may reach the log.
    #[tokio::test]
    async fn query_values_never_reach_the_log() {
        let (_, events) = call("wallet", "/ok?code=SEKRIT-QUERY-VALUE&state=xyz").await;
        assert!(
            !events
                .iter()
                .any(|e| e.message.contains("SEKRIT-QUERY-VALUE")
                    || e.fields.values().any(|v| v.contains("SEKRIT-QUERY-VALUE"))),
            "a query value leaked: {events:?}"
        );
    }

    #[tokio::test]
    async fn listener_label_distinguishes_the_two_ports() {
        let (_, events) = call("admin", "/ok").await;
        assert_eq!(
            access_events(&events)[0]
                .fields
                .get("listener")
                .map(String::as_str),
            Some("admin")
        );
    }

    /// Logging must be observationally neutral: same status, same body.
    #[tokio::test]
    async fn does_not_alter_the_response() {
        let (response, _) = call("wallet", "/ok").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("body reads");
        assert_eq!(&body[..], b"ok");
    }

    /// Downstream events must inherit the correlation fields, since that is what
    /// lets one `request_id` thread a whole request's log records together.
    #[tokio::test]
    async fn downstream_events_inherit_the_span_fields() {
        let (layer, handle) = log_capture::capture_layer();
        let subscriber = {
            use tracing_subscriber::layer::SubscriberExt;
            tracing_subscriber::Registry::default()
                .with(LevelFilter::TRACE)
                .with(layer)
        };
        let guard = tracing::subscriber::set_default(subscriber);

        let router = with_access_log(
            Router::new().route(
                "/emit",
                get(|| async {
                    tracing::info!(marker = "from-handler", "handler ran");
                    "done"
                }),
            ),
            "wallet",
        );
        let _ = router
            .oneshot(
                Request::builder()
                    .uri("/emit")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        drop(guard);

        let handler_event = handle
            .events()
            .into_iter()
            .find(|e| e.fields.get("marker").map(String::as_str) == Some("from-handler"))
            .expect("handler event captured");
        assert!(
            handler_event.fields.contains_key("request_id"),
            "handler event should inherit request_id: {handler_event:?}"
        );
        assert_eq!(
            handler_event.fields.get("route").map(String::as_str),
            Some("/emit")
        );
    }
}
