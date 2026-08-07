//! A `tracing` layer that records events into memory so tests can assert on
//! what was logged.
//!
//! # Why this is `pub` and not `#[cfg(test)]`
//!
//! Rust integration tests (`crates/foundry/tests/`) link the library compiled
//! **without** `cfg(test)`, so a `#[cfg(test)]` helper here would be invisible
//! to them. The alternatives were a `tracing-test` dev-dependency (ruled out:
//! this work adds no new crates) or duplicating the layer in every integration
//! test file. So it ships in the library. Do not "tidy" it behind `cfg(test)` —
//! that silently breaks the redaction suite, which is the one test proving no
//! secret reaches the log.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// One recorded `tracing` event.
#[derive(Debug, Clone)]
pub struct CapturedEvent {
    pub level: Level,
    pub target: String,
    /// The event's `message` field, rendered. Empty when the event has none.
    pub message: String,
    /// Every other field on the event, plus all fields of its enclosing spans.
    /// Span fields are merged first, so an event field of the same name wins.
    pub fields: BTreeMap<String, String>,
}

/// Read access to what a [`capture_layer`] has recorded.
///
/// Cheap to clone; clones share one buffer.
#[derive(Debug, Clone)]
pub struct CaptureHandle {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl CaptureHandle {
    /// Snapshot of everything recorded so far.
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.lock().clone()
    }

    /// Whether `needle` appears in **any** recorded message or field value.
    ///
    /// The redaction suite is built on this: it asserts that a planted secret
    /// appears nowhere in the whole buffer, rather than checking one event at a
    /// time and missing the one that leaked.
    pub fn contains_value(&self, needle: &str) -> bool {
        self.lock()
            .iter()
            .any(|e| e.message.contains(needle) || e.fields.values().any(|v| v.contains(needle)))
    }

    /// Every recorded event at `level` or more severe.
    pub fn at_least(&self, level: Level) -> Vec<CapturedEvent> {
        self.lock()
            .iter()
            .filter(|e| e.level <= level)
            .cloned()
            .collect()
    }

    /// Discard everything recorded so far.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Recover from a poisoned mutex rather than panicking: a panic here would
    /// replace a real test failure with a confusing one.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<CapturedEvent>> {
        self.events.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A subscriber that records nothing but always insists on being asked.
///
/// Its only job is to exist. See [`keep_interest_cache_resolvable`].
#[derive(Debug)]
struct AlwaysAsk;

impl Subscriber for AlwaysAsk {
    /// Never `never` and never `always`: `sometimes` forces `tracing` to call
    /// [`Subscriber::enabled`] on whichever dispatcher is current, which is the
    /// only answer that stays correct when subscribers are per-thread.
    fn register_callsite(&self, _: &Metadata<'_>) -> Interest {
        Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// Keep two dispatchers registered for the life of the process, so that a
/// callsite's cached `Interest` can never collapse to "never".
///
/// # The failure this prevents
///
/// `tracing-core` caches `Interest` **per callsite in a process-global slot**,
/// computed once, on the callsite's first use, by `rebuild_callsite_interest`.
/// While at most one dispatcher is registered, `Dispatchers::rebuilder` takes
/// its `JustOne` fast path and asks only `dispatcher::get_default` — *the
/// registering thread's own* subscriber. A test thread that has installed no
/// subscriber therefore answers with `NoSubscriber`, yielding
/// `Interest::never()`, and that verdict is cached **for every thread**. Any
/// other thread sitting inside `with_default` with a live capture subscriber
/// then loses its events: the `event!` macro short-circuits on the cached
/// interest before consulting any subscriber at all. The next dispatcher
/// registration rebuilds the cache and the symptom vanishes, which is what made
/// this present as a rare flake rather than a hard failure.
/// (tracing-core 0.1.36: `callsite.rs:505`, `callsite.rs` `dispatchers` module.)
///
/// Two are registered, not one, because `has_just_one` is set from
/// `dispatchers.len() <= 1` — a single keep-alive would leave the fast path
/// armed. Because both are held here forever, the `retain` in
/// `register_dispatch` can never drop the count back to one.
///
/// Registering them also rebuilds the interest cache for every callsite already
/// known, so a callsite poisoned before the first capture is repaired here.
///
/// This is a test-support concern only: nothing in the served binary calls
/// [`capture_layer`], and `AlwaysAsk` records nothing.
fn keep_interest_cache_resolvable() {
    static KEEPALIVE: OnceLock<[tracing::Dispatch; 2]> = OnceLock::new();
    KEEPALIVE.get_or_init(|| {
        [
            tracing::Dispatch::new(AlwaysAsk),
            tracing::Dispatch::new(AlwaysAsk),
        ]
    });
}

/// A [`Layer`] that records every event it is passed, plus a handle to read them.
///
/// Compose it into a registry and scope it with
/// `tracing::subscriber::with_default`, or use [`init_for_test`].
pub fn capture_layer() -> (CaptureLayer, CaptureHandle) {
    // Must happen before the caller emits anything: see the function's docs.
    keep_interest_cache_resolvable();
    let events = Arc::new(Mutex::new(Vec::new()));
    (
        CaptureLayer {
            events: Arc::clone(&events),
        },
        CaptureHandle { events },
    )
}

/// Install a capture layer as the scoped default subscriber.
///
/// The returned guard must stay alive for as long as events should be captured.
/// Scoped rather than global so tests do not fight over one subscriber.
pub fn init_for_test<F>(filter: F) -> (tracing::subscriber::DefaultGuard, CaptureHandle)
where
    F: Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt;
    let (layer, handle) = capture_layer();
    let subscriber = tracing_subscriber::Registry::default()
        .with(filter)
        .with(layer);
    (tracing::subscriber::set_default(subscriber), handle)
}

/// The recording layer. Construct via [`capture_layer`].
#[derive(Debug)]
pub struct CaptureLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

/// Fields recorded on a span, stashed in the span's extensions so that events
/// inside it can inherit them.
#[derive(Debug, Default)]
struct SpanFields(BTreeMap<String, String>);

/// Renders each field into a string. Values arrive already typed, so the typed
/// hooks are implemented to avoid `"..."` quoting that `Debug` would add to
/// strings — a quoted value would break substring assertions.
struct FieldVisitor<'a>(&'a mut BTreeMap<String, String>);

impl Visit for FieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = BTreeMap::new();
        attrs.record(&mut FieldVisitor(&mut fields));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(fields));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut ext = span.extensions_mut();
            if let Some(existing) = ext.get_mut::<SpanFields>() {
                values.record(&mut FieldVisitor(&mut existing.0));
            } else {
                let mut fields = BTreeMap::new();
                values.record(&mut FieldVisitor(&mut fields));
                ext.insert(SpanFields(fields));
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut fields = BTreeMap::new();

        // Outermost span first, so a nested span — and then the event itself —
        // can shadow an inherited field of the same name.
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(sf) = span.extensions().get::<SpanFields>() {
                    for (k, v) in &sf.0 {
                        fields.insert(k.clone(), v.clone());
                    }
                }
            }
        }

        event.record(&mut FieldVisitor(&mut fields));
        let message = fields.remove("message").unwrap_or_default();

        let captured = CapturedEvent {
            level: *event.metadata().level(),
            target: event.metadata().target().to_string(),
            message,
            fields,
        };

        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(captured);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{Level, debug, info, warn};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::{Layer, Registry, filter::LevelFilter};

    /// Run `body` with only the capture layer installed, and return what it saw.
    fn captured(body: impl FnOnce()) -> Vec<CapturedEvent> {
        let (layer, handle) = capture_layer();
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, body);
        handle.events()
    }

    /// A thread with **no** subscriber that happens to be the first to touch a
    /// callsite must not be able to silence that callsite for a thread that
    /// *does* have one.
    ///
    /// `tracing-core` caches `Interest` per callsite in a process-global slot.
    /// While only one dispatcher is registered, `Dispatchers::rebuilder` takes
    /// its `JustOne` fast path and asks *the registering thread's own* default
    /// subscriber — `NoSubscriber` on a bare thread — which answers
    /// `Interest::never()`. That verdict is then cached for every thread, and
    /// the `event!` macro drops the event before any subscriber is consulted.
    /// (tracing-core 0.1.36: `callsite.rs:505` and the `dispatchers` module.)
    ///
    /// This is a cold-start race, so it is staged deterministically here: the
    /// dispatch is registered *before* the callsite exists, and then entered
    /// with `dispatcher::with_default`, which does not re-register and so does
    /// not incidentally repair the cache.
    #[test]
    fn a_subscriberless_thread_cannot_silence_a_capture() {
        fn virgin_callsite() {
            warn!("interest-cache canary");
        }

        let (layer, handle) = capture_layer();
        let subscriber = Registry::default().with(LevelFilter::TRACE).with(layer);
        let dispatch = tracing::Dispatch::new(subscriber);

        // First touch of the callsite comes from a thread with no subscriber.
        std::thread::spawn(virgin_callsite).join().unwrap();

        tracing::dispatcher::with_default(&dispatch, virgin_callsite);

        assert_eq!(
            handle.events().len(),
            1,
            "event dropped at the process-global callsite-interest cache before \
             the capture subscriber was consulted"
        );
    }

    #[test]
    fn captures_level_message_and_target() {
        let events = captured(|| info!("hello"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].level, Level::INFO);
        assert_eq!(events[0].message, "hello");
        assert!(
            events[0].target.contains("log_capture"),
            "target was {:?}",
            events[0].target
        );
    }

    /// Structured fields must be available as key/value pairs. Asserting only on
    /// the rendered message would make every later assertion a substring search.
    #[test]
    fn captures_structured_fields_as_key_values() {
        let events = captured(|| info!(tx_id = "abc123", count = 7, ok = true, "done"));
        assert_eq!(events.len(), 1);
        let f = &events[0].fields;
        assert_eq!(f.get("tx_id").map(String::as_str), Some("abc123"));
        assert_eq!(f.get("count").map(String::as_str), Some("7"));
        assert_eq!(f.get("ok").map(String::as_str), Some("true"));
        assert!(
            !f.contains_key("message"),
            "the message belongs in .message, not in .fields"
        );
    }

    /// This is what makes request_id / tx_id correlation assertable: an event
    /// emitted deep inside a handler must carry the fields of the enclosing span.
    #[test]
    fn inherits_fields_from_enclosing_spans() {
        let events = captured(|| {
            let outer = tracing::info_span!("http", request_id = "req-1");
            let _o = outer.enter();
            let inner = tracing::info_span!("verify", tx_id = "tx-9");
            let _i = inner.enter();
            info!("step done");
        });
        assert_eq!(events.len(), 1);
        let f = &events[0].fields;
        assert_eq!(f.get("request_id").map(String::as_str), Some("req-1"));
        assert_eq!(f.get("tx_id").map(String::as_str), Some("tx-9"));
    }

    #[test]
    fn respects_the_active_filter() {
        let (layer, handle) = capture_layer();
        let subscriber = Registry::default().with(layer.with_filter(LevelFilter::WARN));
        tracing::subscriber::with_default(subscriber, || {
            debug!("invisible");
            info!("also invisible");
            warn!("visible");
        });
        let events = handle.events();
        assert_eq!(events.len(), 1, "got {events:?}");
        assert_eq!(events[0].message, "visible");
    }

    /// `contains_value` is the primitive the redaction suite is built on, so its
    /// behaviour is pinned here rather than assumed.
    #[test]
    fn contains_value_searches_messages_and_field_values() {
        let (layer, handle) = capture_layer();
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            info!(token = "SEKRIT-IN-FIELD", "nothing to see");
            info!("SEKRIT-IN-MESSAGE happened");
        });

        assert!(handle.contains_value("SEKRIT-IN-FIELD"), "field value");
        assert!(handle.contains_value("SEKRIT-IN-MESSAGE"), "message");
        assert!(!handle.contains_value("NEVER-LOGGED"), "absent needle");
    }

    /// A needle hidden inside a *span* field must also be found, or a secret
    /// recorded once on a span would slip past the redaction suite.
    #[test]
    fn contains_value_searches_span_fields_too() {
        let (layer, handle) = capture_layer();
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("op", secret = "SEKRIT-IN-SPAN");
            let _g = span.enter();
            info!("inside");
        });
        assert!(handle.contains_value("SEKRIT-IN-SPAN"));
    }

    #[test]
    fn captures_nothing_when_nothing_is_logged() {
        assert!(captured(|| {}).is_empty());
    }

    /// The handle is cloneable and shares one buffer, so a test can hand a clone
    /// to a spawned task and still assert from the main thread.
    #[test]
    fn handle_clones_share_one_buffer() {
        let (layer, handle) = capture_layer();
        let clone = handle.clone();
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || info!("once"));
        assert_eq!(handle.events().len(), 1);
        assert_eq!(clone.events().len(), 1);
    }

    #[test]
    fn init_for_test_is_usable_as_a_default_subscriber_guard() {
        // Sanity: the convenience wrapper installs a scoped subscriber and the
        // handle sees events emitted under it.
        let (guard, handle) = init_for_test(LevelFilter::TRACE);
        info!(marker = "scoped", "hi");
        drop(guard);
        assert!(handle.contains_value("scoped"));
    }
}
