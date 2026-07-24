//! Smoke test for the shared in-process test harness (`tests/support/mod.rs`).
//! Cargo only compiles files directly under `tests/` as integration test
//! binaries, so this thin file pulls in `support` as a module and hosts the
//! actual `#[tokio::test]`.

mod support;

use support::spawn_test_server;

#[tokio::test]
async fn server_boots_and_admin_base_is_reachable() {
    let server = spawn_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/ready", server.admin_base))
        .send()
        .await
        .expect("GET /ready");
    assert!(resp.status().is_success());
}
