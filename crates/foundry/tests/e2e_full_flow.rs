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

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_sd_jwt_vc::builder::attach_kb_jwt;
use foundry_verifier::{
    CreateVerificationResponse, VerificationResult, VerificationState, VerificationTransaction,
};
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use openid4vp::core::jwe::JweBuilder;
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

/// Build an OpenID4VCI key-proof JWT (`openid4vci-proof+jwt`) bound to
/// `c_nonce` and `issuer`. Ported from
/// `crates/foundry/tests/wallet_issuance.rs::create_proof`.
fn create_proof(c_nonce: &str, issuer: &str) -> (String, EcKeyPair) {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(issuer)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    (jwt_str, keypair)
}

/// An issued SD-JWT VC credential plus what later verification/revocation
/// steps need from it: its status-list index/uri, and the holder signing key
/// bound in its `cnf` claim (needed to build a matching KB-JWT later).
struct IssuedCredential {
    compact: String,
    status_idx: u64,
    status_uri: String,
    holder_signer: FileSigner,
}

/// Create a credential offer via the admin API, then perform the full
/// OpenID4VCI pre-authorized_code flow as the wallet: `/token` → `/nonce` →
/// `/credential`. Asserts the disclosed claims match what was requested and
/// returns everything later steps need. Ported (offer/token/nonce/credential
/// shapes) from `crates/foundry/tests/wallet_issuance.rs`.
async fn create_offer_and_issue_credential(
    client: &reqwest::Client,
    admin_base: &str,
    wallet_base: &str,
) -> IssuedCredential {
    let offer_res = client
        .post(format!("{admin_base}/admin/issuance/offers"))
        .bearer_auth("dev-admin-key")
        .json(&serde_json::json!({
            "credential_type_id": "pid",
            "claims": { "given_name": "Alice", "birthdate": "1990-01-01" },
            "tx_code_required": false
        }))
        .send()
        .await
        .expect("POST /admin/issuance/offers");
    assert_eq!(offer_res.status(), reqwest::StatusCode::OK);
    let offer_json: serde_json::Value = offer_res.json().await.unwrap();
    let pre_auth_code = offer_json["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .expect("pre-authorized_code present")
        .to_string();

    let token_form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
    );
    let token_res = client
        .post(format!("{wallet_base}/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(token_form)
        .send()
        .await
        .expect("POST /token");
    assert_eq!(token_res.status(), reqwest::StatusCode::OK);
    let token_json: serde_json::Value = token_res.json().await.unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    let nonce_res = client
        .post(format!("{wallet_base}/nonce"))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("POST /nonce");
    assert_eq!(nonce_res.status(), reqwest::StatusCode::OK);
    let nonce_json: serde_json::Value = nonce_res.json().await.unwrap();
    let c_nonce = nonce_json["c_nonce"].as_str().unwrap().to_string();

    // `aud` must equal the config's `issuer.credential_issuer` value
    // (`https://localhost:8443` from the quickstart template — a metadata
    // label only, never dereferenced over the network; see the design doc's
    // non-goals), not the real bound socket address.
    let (proof_jwt, holder_keypair) = create_proof(&c_nonce, "https://localhost:8443");
    let cred_res = client
        .post(format!("{wallet_base}/credential"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "credential_configuration_id": "pid",
            "format": "dc+sd-jwt",
            "proofs": { "jwt": [proof_jwt] },
        }))
        .send()
        .await
        .expect("POST /credential");
    assert_eq!(cred_res.status(), reqwest::StatusCode::OK);
    let cred_json: serde_json::Value = cred_res.json().await.unwrap();
    let compact = cred_json["credentials"][0]["credential"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        compact.contains('~'),
        "SD-JWT VC compact serialization must contain '~' separators"
    );

    // Parse the issuer-signed JWT (first segment before '~') for the status claim.
    let issuer_jwt = compact.split('~').next().unwrap();
    let jwt_parts: Vec<&str> = issuer_jwt.split('.').collect();
    assert_eq!(
        jwt_parts.len(),
        3,
        "issuer-signed JWT must be a compact JWS"
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(jwt_parts[1]).unwrap()).unwrap();
    let status_idx = payload["status"]["status_list"]["idx"]
        .as_u64()
        .expect("status.status_list.idx present");
    let status_uri = payload["status"]["status_list"]["uri"]
        .as_str()
        .expect("status.status_list.uri present")
        .to_string();

    // `given_name`/`birthdate` are selectively disclosable in the quickstart
    // `pid` credential type, so they live in disclosure segments
    // (`<jwt>~<d1>~<d2>~...~`), not directly in the issuer JWT payload.
    let mut disclosed: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for seg in compact.split('~').skip(1).filter(|s| !s.is_empty()) {
        let decoded = B64URL.decode(seg).expect("disclosure is valid base64url");
        let arr: serde_json::Value =
            serde_json::from_slice(&decoded).expect("disclosure is a JSON array");
        let arr = arr.as_array().expect("disclosure is [salt, name, value]");
        assert_eq!(
            arr.len(),
            3,
            "disclosure must be [salt, claim_name, claim_value]"
        );
        disclosed.insert(arr[1].as_str().unwrap().to_string(), arr[2].clone());
    }
    assert_eq!(
        disclosed.get("given_name"),
        Some(&serde_json::json!("Alice"))
    );
    assert_eq!(
        disclosed.get("birthdate"),
        Some(&serde_json::json!("1990-01-01"))
    );

    let holder_signer = FileSigner::from_pem(
        &holder_keypair.to_pem_private_key(),
        SignatureAlgorithm::Es256,
    )
    .unwrap();

    IssuedCredential {
        compact,
        status_idx,
        status_uri,
        holder_signer,
    }
}

/// Create a verification request via the admin API (DCQL matching the
/// issued `pid` credential's vct and claims), then respond as the wallet:
/// attach a KB-JWT (signed by the same holder key bound in the credential's
/// `cnf` claim) to the already-issued credential, encrypt it into a JWE, and
/// submit it. Returns the decoded `VerificationResult`. Cross-checks the
/// admin-facing transaction record too. Ported (request/response shapes,
/// KB-JWT/JWE construction) from
/// `crates/foundry/tests/wallet_verification.rs::full_verification_flow_end_to_end`.
async fn run_verification(
    client: &reqwest::Client,
    admin_base: &str,
    wallet_base: &str,
    issued: &IssuedCredential,
) -> VerificationResult {
    let create_res = client
        .post(format!("{admin_base}/admin/verification/requests"))
        .bearer_auth("dev-admin-key")
        .json(&serde_json::json!({
            "dcql_query": {
                "credentials": [{
                    "id": "c1",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://localhost:8443/vct/pid"] },
                    "claims": [
                        { "path": ["given_name"] },
                        { "path": ["birthdate"] }
                    ]
                }]
            },
            "transport": "request_uri"
        }))
        .send()
        .await
        .expect("POST /admin/verification/requests");
    assert_eq!(create_res.status(), reqwest::StatusCode::OK);
    let create_resp: CreateVerificationResponse = create_res.json().await.unwrap();
    let verification_id = create_resp.verification_id;

    let get_res = client
        .get(format!("{wallet_base}/vp/request/{verification_id}"))
        .send()
        .await
        .expect("GET /vp/request/:id");
    assert_eq!(get_res.status(), reqwest::StatusCode::OK);
    let jws_str = get_res.text().await.unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    assert_eq!(parts.len(), 3);
    let request_object: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    let presentation = attach_kb_jwt(
        issued.compact.clone(),
        &issued.holder_signer,
        &client_id,
        &nonce,
    )
    .expect("attach_kb_jwt");
    let jwe_str = JweBuilder::new()
        .payload(serde_json::json!({ "vp_token": presentation }))
        .recipient_key_json(&ephem_public_jwk)
        .unwrap()
        .alg("ECDH-ES")
        .enc("A128GCM")
        .build()
        .unwrap();

    let post_res = client
        .post(format!("{wallet_base}/vp/response/{verification_id}"))
        .header("content-type", "text/plain")
        .body(jwe_str)
        .send()
        .await
        .expect("POST /vp/response/:id");
    assert_eq!(post_res.status(), reqwest::StatusCode::OK);
    let result: VerificationResult = post_res.json().await.unwrap();

    let tx_res = client
        .get(format!(
            "{admin_base}/admin/verification/requests/{verification_id}"
        ))
        .bearer_auth("dev-admin-key")
        .send()
        .await
        .expect("GET /admin/verification/requests/:id");
    assert_eq!(tx_res.status(), reqwest::StatusCode::OK);
    let tx: VerificationTransaction = tx_res.json().await.unwrap();
    // `VerificationState::Verified` means "a verification attempt completed"
    // (state machine progress), not "passed" — the happy-path call lands in
    // `Verified` and the revoked-credential call lands in `Failed`; the
    // actual pass/fail signal is `VerificationResult.verified` and its
    // `checks`, asserted separately by the caller.
    assert!(
        matches!(
            tx.state,
            VerificationState::Verified | VerificationState::Failed
        ),
        "unexpected transaction state: {:?}",
        tx.state
    );

    result
}

#[tokio::test]
#[ignore]
async fn full_flow_issue_verify_revoke_reverify() {
    let (guard, dir, admin_port, wallet_port) = spawn_server().await;
    let admin_base = format!("http://127.0.0.1:{admin_port}");
    let wallet_base = format!("http://127.0.0.1:{wallet_port}");
    let client = reqwest::Client::new();

    let issued = create_offer_and_issue_credential(&client, &admin_base, &wallet_base).await;

    let happy = run_verification(&client, &admin_base, &wallet_base, &issued).await;
    assert!(
        happy.verified,
        "happy-path checks={:?} logs={}",
        happy.checks,
        guard.dump_logs()
    );
    for check in &happy.checks {
        assert!(
            check.passed,
            "check {} unexpectedly failed: {:?}",
            check.check, check.detail
        );
    }

    // Revoke: the status URI's final path segment is the storage-key `id`
    // to revoke (today always the literal "1" — see credential.rs and the
    // design doc's finding — derived here from the credential rather than
    // hardcoded, so this stays correct if that ever changes).
    let status_id = issued
        .status_uri
        .rsplit('/')
        .next()
        .expect("status uri has a path segment");
    let db_path = dir.path().join("foundry.db");
    let revoke_status = std::process::Command::new(env!("CARGO_BIN_EXE_foundry"))
        .args([
            "status-list",
            "set",
            "--db",
            db_path.to_str().unwrap(),
            "--credential-type",
            status_id,
            "--index",
            &issued.status_idx.to_string(),
            "--status",
            "revoked",
        ])
        .status()
        .expect("spawn foundry status-list set");
    assert!(revoke_status.success(), "foundry status-list set failed");

    // Fresh verification request/response (responses can't be resubmitted —
    // see wallet_verification.rs::resubmitting_a_verification_response_is_rejected).
    let revoked = run_verification(&client, &admin_base, &wallet_base, &issued).await;
    assert!(
        !revoked.verified,
        "revoked credential must not verify; checks={:?}",
        revoked.checks
    );
    let status_check = revoked
        .checks
        .iter()
        .find(|c| c.check == "status_check")
        .expect("status_check present");
    assert!(
        !status_check.passed,
        "status_check must fail after revocation"
    );
    for check in &revoked.checks {
        if check.check != "status_check" {
            assert!(
                check.passed,
                "unrelated check {} should still pass after revocation: {:?}",
                check.check, check.detail
            );
        }
    }
}
