//! Real subprocess end-to-end test: boots the actual `foundry` binary
//! (`quickstart` then `serve`) and drives it purely over HTTP as a wallet,
//! admin client, and verifier's relying party. See
//! docs/superpowers/specs/2026-07-23-foundry-e2e-full-flow-design.md for the
//! design rationale, including two corrections found during planning:
//! probe-and-release port discovery (not log-parsing) is required because the
//! server's own `issuer.status_list.public_base_url` must be genuinely
//! reachable at boot time; and the status-list storage key is always the
//! literal `"1"` today (see `foundry-issuer/src/credential.rs`), not the
//! credential type id.
//!
//! Run with: `cargo test -p foundry --test e2e_full_flow -- --ignored`

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bind to `127.0.0.1:0`, read the OS-assigned port, then drop the listener
/// to free it. Standard probe-and-release: accepts a small, unavoidable race
/// window in exchange for knowing the port before the config is written.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read bound port").port()
}

/// Keeps the spawned `foundry serve` child alive and kills it on drop, even
/// if the test panics mid-way.
struct ServerGuard {
    child: Child,
    log_lines: Arc<Mutex<Vec<String>>>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl ServerGuard {
    fn dump_logs(&self) -> String {
        self.log_lines.lock().unwrap().join("\n")
    }

    /// Poll the captured logs (up to `timeout`) for a substring, so a small
    /// delay in the background reader threads catching up to a fast-printing
    /// child doesn't make this check flaky.
    async fn wait_for_log_containing(&self, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if self.dump_logs().contains(needle) {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "expected server logs to contain '{needle}'; captured logs:\n{}",
                    self.dump_logs()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Rewrite the `quickstart`-generated config in place: bind both listeners to
/// pre-selected free ports, and point `issuer.status_list.public_base_url` at
/// the real wallet-facing port (required so the server's own status-list
/// HTTP fetch during verification can actually reach itself).
fn rewrite_config_for_e2e(config_path: &Path, admin_port: u16, wallet_port: u16) {
    let original = std::fs::read_to_string(config_path).expect("read generated config.yaml");
    let rewritten = original
        .replace(
            "bind: 0.0.0.0:8443\n",
            &format!("bind: 127.0.0.1:{wallet_port}\n"),
        )
        .replace(
            "bind: 127.0.0.1:9000\n",
            &format!("bind: 127.0.0.1:{admin_port}\n"),
        )
        .replace(
            "public_base_url: https://localhost:8443/statuslists\n",
            &format!("public_base_url: http://127.0.0.1:{wallet_port}/statuslists\n"),
        );
    assert_ne!(
        original, rewritten,
        "expected all three quickstart config lines to be present and rewritten \
         (bind: 0.0.0.0:8443 / bind: 127.0.0.1:9000 / status_list public_base_url) — \
         if this fails, the quickstart config template in commands.rs changed and \
         this rewrite needs updating"
    );
    std::fs::write(config_path, rewritten).expect("write rewritten config.yaml");
}

/// Spawn the real `foundry` binary to run `quickstart`, then `serve`, against
/// pre-selected free ports, with `current_dir` set so the generated
/// config's relative key/db paths resolve correctly (mirrors how `README.md`
/// documents running `foundry serve` from the directory containing its
/// `config.yaml`/`keys/`/`trust/`). Polls `/ready` before returning.
async fn spawn_server() -> (ServerGuard, tempfile::TempDir, u16, u16) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let binary = env!("CARGO_BIN_EXE_foundry");

    let quickstart_status = Command::new(binary)
        .args(["quickstart", "--dir", ".", "--out-config", "config.yaml"])
        .current_dir(dir.path())
        .status()
        .expect("spawn foundry quickstart");
    assert!(quickstart_status.success(), "foundry quickstart failed");

    let config_path = dir.path().join("config.yaml");
    let admin_port = free_port();
    let wallet_port = free_port();
    rewrite_config_for_e2e(&config_path, admin_port, wallet_port);

    let mut child = Command::new(binary)
        .args(["--log-format", "json", "serve", "--config", "config.yaml"])
        .current_dir(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn foundry serve");

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let log_lines = Arc::new(Mutex::new(Vec::new()));

    // Drain both streams continuously in background OS threads so the child
    // never blocks on a full pipe buffer once the test stops actively
    // reading (bounded to the last 500 lines to avoid unbounded growth).
    for (name, stream) in [
        ("stdout", Box::new(stdout) as Box<dyn Read + Send>),
        ("stderr", Box::new(stderr)),
    ] {
        let log_lines = log_lines.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stream);
            for line in reader.lines().map_while(Result::ok) {
                let mut lines = log_lines.lock().unwrap();
                lines.push(format!("[{name}] {line}"));
                if lines.len() > 500 {
                    lines.remove(0);
                }
            }
        });
    }

    let guard = ServerGuard {
        child,
        log_lines: log_lines.clone(),
    };

    let client = reqwest::Client::new();
    let ready_url = format!("http://127.0.0.1:{admin_port}/ready");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(resp) = client.get(&ready_url).send().await {
            if resp.status().is_success() {
                break;
            }
        }
        if Instant::now() > deadline {
            panic!(
                "server did not become ready in time; captured logs:\n{}",
                guard.dump_logs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Secondary sanity assertion (not the port-discovery mechanism itself):
    // the server's own "listening" log lines should report the same ports we
    // pre-selected, proving the Step 2 logging fix reports the real bound
    // address rather than echoing the configured string verbatim.
    guard
        .wait_for_log_containing(&format!("127.0.0.1:{admin_port}"), Duration::from_secs(2))
        .await;
    guard
        .wait_for_log_containing(&format!("127.0.0.1:{wallet_port}"), Duration::from_secs(2))
        .await;

    (guard, dir, admin_port, wallet_port)
}

#[tokio::test]
#[ignore]
async fn full_flow_issue_verify_revoke_reverify() {
    let (guard, _dir, admin_port, wallet_port) = spawn_server().await;
    let admin_base = format!("http://127.0.0.1:{admin_port}");
    let wallet_base = format!("http://127.0.0.1:{wallet_port}");

    // Smoke check for this task: the server is up and reachable on both
    // pre-selected ports. Tasks 4-6 extend this test with the actual flow.
    let client = reqwest::Client::new();
    let health = client
        .get(format!("{admin_base}/health"))
        .send()
        .await
        .expect("GET /health");
    assert!(health.status().is_success(), "logs:\n{}", guard.dump_logs());

    let metadata = client
        .get(format!(
            "{wallet_base}/.well-known/openid-credential-issuer"
        ))
        .send()
        .await
        .expect("GET /.well-known/openid-credential-issuer");
    assert!(
        metadata.status().is_success(),
        "logs:\n{}",
        guard.dump_logs()
    );
}
