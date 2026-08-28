//! Delivery of verification events to an operator-configured sink
//! (design `docs/superpowers/specs/2026-08-28-verifier-artifact-webhook-design.md`).

mod support;

#[tokio::test]
async fn an_unconfigured_app_state_holds_no_sink() {
    let (state, _dir) = support::setup_without_encryption().await;
    assert!(
        state.webhook_sink.is_none(),
        "no verifier.webhook config must mean no sink"
    );
}

#[tokio::test]
async fn a_sink_can_be_attached_for_tests() {
    let (state, _dir) = support::setup_without_encryption().await;
    let (sink, _rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);
    assert!(state.webhook_sink.is_some());
}
