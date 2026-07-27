# Admin Test Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve a self-contained HTML/JS "Admin Test Console" at `GET /console` on the Admin listener, letting a developer trigger OpenID4VCI issuance and OpenID4VP verification flows (with QR codes for scanning by a real wallet) without hand-rolling `curl` calls.

**Architecture:** One static HTML file (inline CSS + inline JS + a vendored MIT-licensed QR-encoder library) embedded into the `foundry` binary via `include_str!` and served same-origin with the Admin API it calls. Gated by a new `console_enabled` config flag (default `true`), following the exact existing `swagger_ui_enabled` pattern.

**Tech Stack:** Rust (axum, utoipa), vanilla HTML/CSS/JS (no build step, no CDN), vendored `qrcode-generator` (MIT, kazuhikoarase).

## Global Constraints

- No `.unwrap()`/`.expect()`/`panic!()`/`unreachable!()` in request-path code in `foundry-issuer`, `foundry-verifier`, or `foundry::server` (test code and `#[cfg(test)]` are exempt).
- Every task must leave the workspace passing: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.
- `GET /console` is a static-HTML route and is deliberately **excluded** from the `utoipa` OpenAPI spec (`AdminApiDoc`), the same treatment already given to the `/api-docs` Swagger UI route itself — this is intentional, not an oversight (see design spec §8).
- Commit after each task.

Full design rationale: `docs/superpowers/specs/2026-07-27-admin-test-console-design.md`.

---

### Task 1: Add `console_enabled` config flag to `AdminConfig`

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs`
- Modify: `crates/foundry-core/tests/config_load.rs`
- Modify: `crates/foundry/tests/health.rs`
- Modify: `crates/foundry/tests/wallet_issuance.rs`
- Modify: `crates/foundry/tests/wallet_verification.rs`
- Modify: `crates/foundry/tests/wallet_metadata.rs`
- Modify: `crates/foundry/tests/issuer_offers.rs`
- Modify: `crates/foundry/tests/wallet_status_list_route.rs`
- Modify: `crates/foundry/tests/openapi_endpoints.rs`
- Modify: `crates/foundry/src/admin_auth.rs`
- Modify: `crates/foundry-wallet/tests/support/mod.rs`
- Modify: `crates/foundry-issuer/src/create_offer.rs`
- Modify: `crates/foundry-issuer/src/metadata.rs`
- Modify: `crates/foundry-issuer/src/credential.rs`
- Modify: `crates/foundry-verifier/src/request.rs`
- Modify: `crates/foundry-verifier/src/verify.rs`

**Interfaces:**
- Produces: `foundry_core::config::AdminConfig.console_enabled: bool` (defaults to `true` via serde when omitted from YAML). Task 3 reads this field to gate the `/console` route.

- [ ] **Step 1: Add the field to `AdminConfig`**

In `crates/foundry-core/src/config/model.rs`:

```rust
// old
#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub bind: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "default_true")]
    pub swagger_ui_enabled: bool,
}
```

```rust
// new
#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub bind: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "default_true")]
    pub swagger_ui_enabled: bool,
    #[serde(default = "default_true")]
    pub console_enabled: bool,
}
```

- [ ] **Step 2: Attempt a workspace build and confirm it fails to compile**

Run: `cargo build --workspace`
Expected: FAIL — multiple "missing field `console_enabled` in initializer of `AdminConfig`" errors, one per file listed above (except `config_load.rs`, which doesn't construct the struct).

- [ ] **Step 3: Fix every `AdminConfig { .. }` literal**

Add `console_enabled: true,` immediately after each `swagger_ui_enabled: ...,` (or `swagger_ui_enabled,` shorthand) line. Exact edits:

`crates/foundry/tests/health.rs`, `wallet_metadata.rs`, `wallet_status_list_route.rs` — each has (adjust `api_key`/`bind` values are already whatever that file has; only touch the two lines shown):

```rust
// old (in each of health.rs, wallet_metadata.rs, wallet_status_list_route.rs)
                swagger_ui_enabled: true,
            },
        },
```

```rust
// new
                swagger_ui_enabled: true,
                console_enabled: true,
            },
        },
```

`crates/foundry/tests/wallet_issuance.rs`, `wallet_verification.rs`, `issuer_offers.rs` — same shape (these already have `api_key: Some("test-admin-key".to_string())`, don't touch that line):

```rust
// old
                swagger_ui_enabled: true,
            },
        },
```

```rust
// new
                swagger_ui_enabled: true,
                console_enabled: true,
            },
        },
```

`crates/foundry/tests/openapi_endpoints.rs` (uses field-init shorthand):

```rust
// old
                swagger_ui_enabled,
            },
        },
```

```rust
// new
                swagger_ui_enabled,
                console_enabled: true,
            },
        },
```

`crates/foundry/src/admin_auth.rs` (`cfg_with` test helper, 12-space field indent, no outer nesting):

```rust
// old
    fn cfg_with(api_key: Option<&str>, api_key_env: Option<&str>) -> AdminConfig {
        AdminConfig {
            bind: "127.0.0.1:9000".to_string(),
            api_key: api_key.map(str::to_string),
            api_key_env: api_key_env.map(str::to_string),
            swagger_ui_enabled: true,
        }
    }
```

```rust
// new
    fn cfg_with(api_key: Option<&str>, api_key_env: Option<&str>) -> AdminConfig {
        AdminConfig {
            bind: "127.0.0.1:9000".to_string(),
            api_key: api_key.map(str::to_string),
            api_key_env: api_key_env.map(str::to_string),
            swagger_ui_enabled: true,
            console_enabled: true,
        }
    }
```

`crates/foundry-wallet/tests/support/mod.rs`:

```rust
// old
                swagger_ui_enabled: false,
            },
        },
```

```rust
// new
                swagger_ui_enabled: false,
                console_enabled: true,
            },
        },
```

`crates/foundry-issuer/src/create_offer.rs`, `crates/foundry-issuer/src/metadata.rs`, `crates/foundry-issuer/src/credential.rs` (20-space field indent):

```rust
// old (in each of the three files)
                    swagger_ui_enabled: true,
                },
            },
```

```rust
// new
                    swagger_ui_enabled: true,
                    console_enabled: true,
                },
            },
```

`crates/foundry-verifier/src/request.rs`, `crates/foundry-verifier/src/verify.rs` (same 20-space indent):

```rust
// old (in each of the two files)
                    swagger_ui_enabled: true,
                },
            },
```

```rust
// new
                    swagger_ui_enabled: true,
                    console_enabled: true,
                },
            },
```

- [ ] **Step 4: Run a workspace build and confirm it now succeeds**

Run: `cargo build --workspace`
Expected: PASS (no errors).

- [ ] **Step 5: Add a default-value assertion to `config_load.rs`**

In `crates/foundry-core/tests/config_load.rs`:

```rust
// old
    assert!(
        cfg.server.wallet_facing.swagger_ui_enabled,
        "swagger_ui_enabled should default to true when omitted from YAML"
    );
    cfg.validate().expect("minimal config should be valid");
```

```rust
// new
    assert!(
        cfg.server.wallet_facing.swagger_ui_enabled,
        "swagger_ui_enabled should default to true when omitted from YAML"
    );
    assert!(
        cfg.server.admin.console_enabled,
        "console_enabled should default to true when omitted from YAML"
    );
    cfg.validate().expect("minimal config should be valid");
```

- [ ] **Step 6: Run the config test and confirm it passes**

Run: `cargo test -p foundry-core --test config_load loads_minimal_yaml_and_validates -- --nocapture`
Expected: PASS.

- [ ] **Step 7: Run full workspace tests**

Run: `cargo test --workspace`
Expected: PASS (all existing tests still green — this task only added a field with a default and one new assertion).

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(config): add console_enabled flag to AdminConfig

Defaults to true, mirroring the existing swagger_ui_enabled pattern.
Will gate the new GET /console route added in a follow-up task."
```

---

### Task 2: Vendor the QR code library and write the console HTML asset

**Files:**
- Create: `crates/foundry/assets/console.html`

**Interfaces:**
- Produces: a static file at `crates/foundry/assets/console.html`, to be embedded via `include_str!("../assets/console.html")` in Task 3. The page defines a global `qrcode(typeNumber, errorCorrectionLevel)` factory function (from the vendored library) used internally by the page's own script — no other task depends on any JS symbol from this file directly (Task 3 only serves the bytes verbatim).

This task has no Rust tests (it produces a static asset, not executable Rust). Verification is by exact byte-count/checksum/grep checks below, and by the Rust route test in Task 3.

- [ ] **Step 1: Fetch and verify the vendored QR library**

The library is `qrcode-generator` by Kazuhiko Arase (MIT licensed), pinned at commit `64f5976e5f9256348d0f5417ceff934bb43cf279` (2025-08-07), file `js/dist/qrcode.js`. Fetch it to a temp file and verify its checksum before using it — do not proceed if the checksum does not match:

```bash
curl -sL "https://raw.githubusercontent.com/kazuhikoarase/qrcode-generator/64f5976e5f9256348d0f5417ceff934bb43cf279/js/dist/qrcode.js" -o /tmp/qrcode-vendor.js
wc -c /tmp/qrcode-vendor.js   # expect: 56658 /tmp/qrcode-vendor.js
shasum -a 256 /tmp/qrcode-vendor.js   # expect: 79ec86f82856005b1c887905cfccfcfbec3821ca61c7fd5a952faa5f778f791c
```

If the network is unavailable in your environment, stop and flag this step as blocked rather than fabricating the library content — a subtly wrong hand-written QR encoder would silently produce invalid, unscannable QR codes, which is worse than a blocked task.

- [ ] **Step 2: Write the HTML skeleton with a splice marker**

Create `crates/foundry/assets/console.html` with exactly this content (the line `/* __VENDORED_QRCODE_JS__ */` is a marker that Step 3 replaces — leave it exactly as shown for now):

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Foundry Admin Test Console</title>
<style>
  :root {
    --bg: #0f1420;
    --panel: #161c2c;
    --panel-border: #262f45;
    --text: #e6e9f2;
    --muted: #8b93a7;
    --accent: #5b8cff;
    --accent-dark: #3f6fe0;
    --amber: #e0a83f;
    --green: #35c07a;
    --red: #e05656;
    --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    padding: 32px;
  }
  header { max-width: 1100px; margin: 0 auto 24px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  header p.sub { margin: 0 0 20px; color: var(--muted); font-size: 14px; }
  .key-bar {
    display: flex; gap: 8px; align-items: center;
    background: var(--panel); border: 1px solid var(--panel-border);
    border-radius: 10px; padding: 12px 16px;
  }
  .key-bar label { font-size: 13px; color: var(--muted); white-space: nowrap; }
  .key-bar input {
    flex: 1; background: #0c101a; border: 1px solid var(--panel-border);
    border-radius: 6px; padding: 8px 10px; color: var(--text); font-family: var(--mono); font-size: 13px;
  }
  .key-bar .remembered { font-size: 12px; color: var(--green); white-space: nowrap; }
  main {
    max-width: 1100px; margin: 0 auto;
    display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
  }
  @media (max-width: 860px) { main { grid-template-columns: 1fr; } }
  .card {
    background: var(--panel); border: 1px solid var(--panel-border);
    border-radius: 12px; padding: 20px;
  }
  .card h2 { margin: 0 0 4px; font-size: 16px; }
  .card p.hint { margin: 0 0 16px; color: var(--muted); font-size: 12.5px; }
  .field { margin-bottom: 14px; }
  .field label { display: block; font-size: 12.5px; color: var(--muted); margin-bottom: 6px; }
  .field input[type=text], .field textarea, .field select {
    width: 100%; background: #0c101a; border: 1px solid var(--panel-border);
    border-radius: 6px; padding: 8px 10px; color: var(--text); font-family: var(--mono); font-size: 13px;
  }
  .field textarea { min-height: 90px; resize: vertical; }
  .field.checkbox { display: flex; align-items: center; gap: 8px; }
  .field.checkbox label { margin: 0; }
  .radio-group { display: flex; gap: 16px; margin-bottom: 10px; font-size: 13px; }
  .radio-group label { display: flex; align-items: center; gap: 6px; color: var(--text); }
  button.primary {
    background: var(--accent); color: #fff; border: none; border-radius: 8px;
    padding: 10px 18px; font-size: 14px; font-weight: 600; cursor: pointer;
  }
  button.primary:hover { background: var(--accent-dark); }
  button.primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .copy-btn {
    background: transparent; border: 1px solid var(--panel-border); color: var(--muted);
    border-radius: 6px; padding: 4px 8px; font-size: 11px; cursor: pointer; margin-left: 8px;
  }
  .copy-btn:hover { color: var(--text); border-color: var(--accent); }
  .result { margin-top: 18px; border-top: 1px solid var(--panel-border); padding-top: 16px; }
  .result.hidden { display: none; }
  .uri-row { display: flex; align-items: center; gap: 6px; margin-bottom: 12px; }
  .uri-text {
    flex: 1; font-family: var(--mono); font-size: 12px; word-break: break-all;
    background: #0c101a; border: 1px solid var(--panel-border); border-radius: 6px; padding: 8px 10px;
  }
  .qr-wrap { display: flex; justify-content: center; margin: 12px 0; }
  .qr-wrap svg { background: #fff; padding: 10px; border-radius: 8px; }
  pre.json {
    background: #0c101a; border: 1px solid var(--panel-border); border-radius: 6px;
    padding: 10px; font-size: 12px; overflow-x: auto; max-height: 220px; margin: 0;
  }
  pre.json.hidden { display: none; }
  .badge {
    display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 600;
  }
  .badge.pending { background: rgba(224,168,63,0.18); color: var(--amber); }
  .badge.verified { background: rgba(53,192,122,0.18); color: var(--green); }
  .badge.failed { background: rgba(224,86,86,0.18); color: var(--red); }
  .checks { list-style: none; padding: 0; margin: 10px 0; }
  .checks.hidden { display: none; }
  .checks li { font-size: 13px; padding: 4px 0; display: flex; gap: 8px; align-items: baseline; }
  .checks li .mark { font-weight: 700; }
  .checks li.pass .mark { color: var(--green); }
  .checks li.fail .mark { color: var(--red); }
  .error-banner {
    background: rgba(224,86,86,0.12); border: 1px solid var(--red); color: #ffb3b3;
    border-radius: 8px; padding: 10px 14px; font-size: 13px; margin-top: 12px;
  }
  .error-banner.hidden { display: none; }
  .hidden { display: none; }
</style>
</head>
<body>
<header>
  <h1>Foundry Admin Test Console</h1>
  <p class="sub">Trigger OpenID4VCI issuance and OpenID4VP verification flows against this server. Scan the QR with a real wallet, or copy the link.</p>
  <div class="key-bar">
    <label for="api-key">Admin API key</label>
    <input type="text" id="api-key" placeholder="Bearer token for /admin/* endpoints" autocomplete="off">
    <span class="remembered hidden" id="remembered-indicator">remembered</span>
  </div>
</header>
<main>
  <section class="card" id="issuance-card">
    <h2>Issuance</h2>
    <p class="hint">POST /admin/issuance/offers</p>
    <div class="field">
      <label for="cred-type-id">credential_type_id</label>
      <input type="text" id="cred-type-id" value="pid">
    </div>
    <div class="field">
      <label for="claims-json">claims (JSON)</label>
      <textarea id="claims-json">{
  "given_name": "Alice",
  "birthdate": "1990-01-01"
}</textarea>
    </div>
    <div class="field checkbox">
      <input type="checkbox" id="tx-code-required">
      <label for="tx-code-required">tx_code_required</label>
    </div>
    <button class="primary" id="create-offer-btn">Create Offer</button>
    <div class="error-banner hidden" id="issuance-error"></div>
    <div class="result hidden" id="issuance-result">
      <div class="uri-row">
        <span class="uri-text" id="offer-uri"></span>
        <button class="copy-btn" data-copy-target="offer-uri">Copy</button>
      </div>
      <div class="qr-wrap" id="offer-qr"></div>
      <pre class="json" id="offer-json"></pre>
    </div>
  </section>

  <section class="card" id="verification-card">
    <h2>Verification</h2>
    <p class="hint">POST /admin/verification/requests</p>
    <div class="radio-group">
      <label><input type="radio" name="dcql-mode" value="named" checked> Named query</label>
      <label><input type="radio" name="dcql-mode" value="raw"> Raw DCQL</label>
    </div>
    <div class="field" id="named-query-field">
      <label for="named-query-ref">named_query_ref</label>
      <input type="text" id="named-query-ref" placeholder="e.g. dcql1">
    </div>
    <div class="field hidden" id="raw-dcql-field">
      <label for="dcql-json">dcql_query (JSON)</label>
      <textarea id="dcql-json">{}</textarea>
    </div>
    <div class="field">
      <label for="transport">transport</label>
      <input type="text" id="transport" value="request_uri">
    </div>
    <button class="primary" id="create-verification-btn">Create Verification Request</button>
    <div class="error-banner hidden" id="verification-error"></div>
    <div class="result hidden" id="verification-result">
      <div class="uri-row">
        <span class="uri-text" id="verification-uri"></span>
        <button class="copy-btn" data-copy-target="verification-uri">Copy</button>
      </div>
      <div class="qr-wrap" id="verification-qr"></div>
      <p>Status: <span class="badge pending" id="verification-status">pending</span></p>
      <ul class="checks hidden" id="verification-checks"></ul>
      <pre class="json hidden" id="verification-claims"></pre>
    </div>
  </section>
</main>

<script>
/* ---------------------------------------------------------------------
 * Vendored: QR Code Generator for JavaScript
 * Copyright (c) 2009 Kazuhiko Arase, MIT licensed.
 * Source: https://github.com/kazuhikoarase/qrcode-generator
 * Pinned commit: 64f5976e5f9256348d0f5417ceff934bb43cf279
 * (js/dist/qrcode.js, sha256: 79ec86f82856005b1c887905cfccfcfbec3821ca61c7fd5a952faa5f778f791c)
 * --------------------------------------------------------------------- */
/* __VENDORED_QRCODE_JS__ */
</script>
<script>
(function () {
  'use strict';

  const KEY_STORAGE_KEY = 'foundry_console_admin_api_key';

  function getApiKey() {
    return document.getElementById('api-key').value.trim();
  }

  function initApiKey() {
    const input = document.getElementById('api-key');
    const remembered = document.getElementById('remembered-indicator');
    const saved = window.localStorage.getItem(KEY_STORAGE_KEY);
    if (saved) {
      input.value = saved;
      remembered.classList.remove('hidden');
    }
    input.addEventListener('input', function () {
      const v = input.value.trim();
      if (v) {
        window.localStorage.setItem(KEY_STORAGE_KEY, v);
        remembered.classList.remove('hidden');
      } else {
        window.localStorage.removeItem(KEY_STORAGE_KEY);
        remembered.classList.add('hidden');
      }
    });
  }

  async function adminFetch(path, options) {
    const key = getApiKey();
    const headers = Object.assign({ 'Content-Type': 'application/json' }, (options && options.headers) || {});
    if (key) {
      headers['Authorization'] = 'Bearer ' + key;
    }
    const resp = await fetch(path, Object.assign({}, options, { headers: headers }));
    const text = await resp.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch (e) {
      body = text;
    }
    if (!resp.ok) {
      const err = new Error('Request to ' + path + ' failed with status ' + resp.status);
      err.status = resp.status;
      err.body = body;
      throw err;
    }
    return body;
  }

  function showError(el, err) {
    let message;
    if (err && err.status === 401) {
      message = 'Unauthorized (401). Check your Admin API key.';
    } else if (err && err.status) {
      const detail = (err.body && (err.body.error || JSON.stringify(err.body))) || '';
      message = 'Request failed (' + err.status + '). ' + detail;
    } else {
      message = (err && err.message) || String(err);
    }
    el.textContent = message;
    el.classList.remove('hidden');
  }

  function clearError(el) {
    el.textContent = '';
    el.classList.add('hidden');
  }

  function renderQr(container, text) {
    container.innerHTML = '';
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    container.innerHTML = qr.createSvgTag({ scalable: true });
  }

  function setupCopyButtons() {
    document.querySelectorAll('.copy-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        const targetId = btn.getAttribute('data-copy-target');
        const el = document.getElementById(targetId);
        const text = el.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text);
        }
        const original = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = original; }, 1200);
      });
    });
  }

  // --- Issuance ---
  function initIssuance() {
    const btn = document.getElementById('create-offer-btn');
    const errorEl = document.getElementById('issuance-error');
    const resultEl = document.getElementById('issuance-result');

    btn.addEventListener('click', async function () {
      clearError(errorEl);
      resultEl.classList.add('hidden');

      const credentialTypeId = document.getElementById('cred-type-id').value.trim();
      const claimsRaw = document.getElementById('claims-json').value;
      const txCodeRequired = document.getElementById('tx-code-required').checked;

      let claims;
      try {
        claims = claimsRaw.trim() ? JSON.parse(claimsRaw) : {};
      } catch (e) {
        showError(errorEl, new Error('claims is not valid JSON: ' + e.message));
        return;
      }

      btn.disabled = true;
      try {
        const body = await adminFetch('/admin/issuance/offers', {
          method: 'POST',
          body: JSON.stringify({
            credential_type_id: credentialTypeId,
            claims: claims,
            tx_code_required: txCodeRequired
          })
        });

        document.getElementById('offer-uri').textContent = body.credential_offer_uri;
        document.getElementById('offer-json').textContent = JSON.stringify(body.credential_offer, null, 2);
        renderQr(document.getElementById('offer-qr'), body.credential_offer_uri);
        resultEl.classList.remove('hidden');
      } catch (err) {
        showError(errorEl, err);
      } finally {
        btn.disabled = false;
      }
    });
  }

  // --- Verification ---
  let pollTimer = null;
  let pollFailures = 0;
  const MAX_POLL_FAILURES = 10;
  const POLL_INTERVAL_MS = 2000;

  function stopPolling() {
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function renderVerificationResult(tx) {
    const statusEl = document.getElementById('verification-status');
    const checksEl = document.getElementById('verification-checks');
    const claimsEl = document.getElementById('verification-claims');

    statusEl.textContent = tx.state;
    statusEl.className = 'badge ' + tx.state;

    if (tx.result) {
      checksEl.innerHTML = '';
      tx.result.checks.forEach(function (check) {
        const li = document.createElement('li');
        li.className = check.passed ? 'pass' : 'fail';
        li.innerHTML = '<span class="mark">' + (check.passed ? '\u2713' : '\u2717') + '</span> ' +
          check.check + (check.detail ? ' \u2014 ' + check.detail : '');
        checksEl.appendChild(li);
      });
      checksEl.classList.remove('hidden');

      claimsEl.textContent = JSON.stringify(tx.result.claims, null, 2);
      claimsEl.classList.remove('hidden');
    }
  }

  function pollVerification(id, errorEl) {
    stopPolling();
    pollFailures = 0;

    function tick() {
      adminFetch('/admin/verification/requests/' + encodeURIComponent(id), { method: 'GET' })
        .then(function (tx) {
          pollFailures = 0;
          renderVerificationResult(tx);
          if (tx.state === 'pending') {
            pollTimer = setTimeout(tick, POLL_INTERVAL_MS);
          }
        })
        .catch(function (err) {
          if (err && err.status) {
            // Hard error (404/500/...): stop polling, surface it.
            showError(errorEl, err);
            return;
          }
          pollFailures += 1;
          if (pollFailures >= MAX_POLL_FAILURES) {
            showError(errorEl, new Error('Gave up polling verification status after ' + MAX_POLL_FAILURES + ' failed attempts.'));
            return;
          }
          pollTimer = setTimeout(tick, POLL_INTERVAL_MS);
        });
    }

    tick();
  }

  function initVerificationModeToggle() {
    const radios = document.querySelectorAll('input[name="dcql-mode"]');
    const namedField = document.getElementById('named-query-field');
    const rawField = document.getElementById('raw-dcql-field');
    radios.forEach(function (radio) {
      radio.addEventListener('change', function () {
        if (radio.value === 'named' && radio.checked) {
          namedField.classList.remove('hidden');
          rawField.classList.add('hidden');
        } else if (radio.value === 'raw' && radio.checked) {
          namedField.classList.add('hidden');
          rawField.classList.remove('hidden');
        }
      });
    });
  }

  function initVerification() {
    initVerificationModeToggle();
    const btn = document.getElementById('create-verification-btn');
    const errorEl = document.getElementById('verification-error');
    const resultEl = document.getElementById('verification-result');

    btn.addEventListener('click', async function () {
      clearError(errorEl);
      resultEl.classList.add('hidden');
      stopPolling();

      const mode = document.querySelector('input[name="dcql-mode"]:checked').value;
      const transport = document.getElementById('transport').value.trim() || 'request_uri';

      const payload = { transport: transport };
      if (mode === 'named') {
        const ref = document.getElementById('named-query-ref').value.trim();
        if (!ref) {
          showError(errorEl, new Error('named_query_ref is required in "Named query" mode.'));
          return;
        }
        payload.named_query_ref = ref;
      } else {
        const raw = document.getElementById('dcql-json').value;
        try {
          payload.dcql_query = raw.trim() ? JSON.parse(raw) : {};
        } catch (e) {
          showError(errorEl, new Error('dcql_query is not valid JSON: ' + e.message));
          return;
        }
      }

      btn.disabled = true;
      try {
        const body = await adminFetch('/admin/verification/requests', {
          method: 'POST',
          body: JSON.stringify(payload)
        });

        const uri = body.openid4vp_uri || body.request_uri || '';
        const uriEl = document.getElementById('verification-uri');
        const qrEl = document.getElementById('verification-qr');
        qrEl.innerHTML = '';
        if (uri) {
          uriEl.textContent = uri;
          renderQr(qrEl, uri);
        } else if (body.dc_api_request) {
          uriEl.textContent = '(dc_api transport has no scannable URI; use the Digital Credentials API request object returned by the admin endpoint directly)';
        } else {
          uriEl.textContent = '';
        }

        document.getElementById('verification-status').textContent = 'pending';
        document.getElementById('verification-status').className = 'badge pending';
        document.getElementById('verification-checks').classList.add('hidden');
        document.getElementById('verification-claims').classList.add('hidden');
        resultEl.classList.remove('hidden');

        pollVerification(body.verification_id, errorEl);
      } catch (err) {
        showError(errorEl, err);
      } finally {
        btn.disabled = false;
      }
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    initApiKey();
    initIssuance();
    initVerification();
    setupCopyButtons();
  });
})();
</script>
</body>
</html>
```

- [ ] **Step 3: Splice the vendored library into the marker**

Run this from the repo root (it replaces the marker line with the fetched library's contents, in place):

```bash
python3 - <<'PYEOF'
import pathlib

console_path = pathlib.Path("crates/foundry/assets/console.html")
vendor_path = pathlib.Path("/tmp/qrcode-vendor.js")

marker = "/* __VENDORED_QRCODE_JS__ */"
html = console_path.read_text()
vendor = vendor_path.read_text()

assert html.count(marker) == 1, f"expected exactly one marker, found {html.count(marker)}"
html = html.replace(marker, vendor)
console_path.write_text(html)
print("spliced", len(vendor), "bytes of vendored JS into", console_path)
PYEOF
```

- [ ] **Step 4: Sanity-check the resulting file**

```bash
grep -c "__VENDORED_QRCODE_JS__" crates/foundry/assets/console.html   # expect: 0 (marker fully replaced)
grep -c "QR Code Generator for JavaScript" crates/foundry/assets/console.html   # expect: 1 (vendored header present)
grep -c "Foundry Admin Test Console" crates/foundry/assets/console.html   # expect: >= 1 (page title present)
wc -c crates/foundry/assets/console.html   # sanity: should be roughly (skeleton size) + 56658 bytes
```

Expected: all four commands succeed with the counts noted.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry/assets/console.html
git commit -m "feat: add Admin Test Console static asset

Self-contained HTML/CSS/JS page (no build step, no CDN) with the
kazuhikoarase/qrcode-generator library (MIT, pinned commit
64f5976e5f9256348d0f5417ceff934bb43cf279) vendored inline for
client-side QR rendering. Not yet wired to any route."
```

---

### Task 3: Serve `/console` on the Admin listener, gated by `console_enabled`

**Files:**
- Modify: `crates/foundry/src/server.rs`
- Create: `crates/foundry/tests/console.rs`

**Interfaces:**
- Consumes: `crates/foundry/assets/console.html` (Task 2, embedded via `include_str!`); `AppState.config.server.admin.console_enabled: bool` (Task 1).
- Produces: `pub(crate) async fn console_handler() -> Html<&'static str>` and the route `GET /console` registered inside `admin_router` (existing function, `crates/foundry/src/server.rs`), conditional on `console_enabled`.

- [ ] **Step 1: Write the failing tests**

Create `crates/foundry/tests/console.rs`:

```rust
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, IssuerConfig, Mode, ServerConfig, StatusListConfig,
    StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn test_config(console_enabled: bool) -> Config {
    Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://localhost:8443".to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: true,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: None,
                api_key_env: None,
                swagger_ui_enabled: true,
                console_enabled,
            },
        },
        storage: StorageConfig {
            path: "./foundry.db".to_string(),
            transaction_ttl_secs: 600,
        },
        keys: BTreeMap::new(),
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://localhost:8443".to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Optional,
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: Vec::new(),
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: Vec::new(),
            named_queries: Vec::new(),
            webhook: None,
        },
    }
}

#[tokio::test]
async fn console_endpoint_returns_html_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/html"),
        "Content-Type should be text/html, got '{content_type}'"
    );

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);
    assert!(
        html.contains("Foundry Admin Test Console"),
        "console page should contain its title marker"
    );
}

#[tokio::test]
async fn console_endpoint_returns_404_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(false));
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo test -p foundry --test console`
Expected: FAIL — `console_endpoint_returns_html_when_enabled` fails with a `404 NOT_FOUND` (route doesn't exist yet); `console_endpoint_returns_404_when_disabled` passes vacuously (also 404, but for the wrong reason) — the important signal is the first test failing.

- [ ] **Step 3: Add the handler and register the route**

In `crates/foundry/src/server.rs`, add `response::Html` to the existing `axum` import:

```rust
// old
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
```

```rust
// new
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::Html,
    routing::{get, post},
    Json, Router,
};
```

Add the handler right after `pub(crate) async fn ready(...)`:

```rust
// old
#[utoipa::path(get, path = "/ready", responses((status = 200, body = String)))]
pub(crate) async fn ready(State(state): State<AppState>) -> Result<&'static str, StatusCode> {
    // Readiness = storage reachable. A cheap purge with a far-past timestamp
    // touches the DB without deleting live rows.
    match state.storage.purge_expired(0).await {
        Ok(_) => Ok("ready"),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}
```

```rust
// new
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
```

Register the route in `admin_router`, right after the existing `swagger_ui_enabled` conditional and before `.with_state(state.clone())`:

```rust
// old
    let unauthenticated = if state.config.server.admin.swagger_ui_enabled {
        unauthenticated.merge(utoipa_swagger_ui::SwaggerUi::new("/api-docs").url(
            "/api-docs/openapi.json",
            crate::openapi::AdminApiDoc::openapi(),
        ))
    } else {
        unauthenticated.route("/api-docs/openapi.json", get(openapi_json_handler))
    };

    let unauthenticated = unauthenticated.with_state(state.clone());
```

```rust
// new
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
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo test -p foundry --test console`
Expected: PASS (both tests).

- [ ] **Step 5: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 6: Run clippy and fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS (no warnings).

Run: `cargo fmt --check`
Expected: PASS. If it reports diffs, run `cargo fmt` and re-check.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: serve Admin Test Console at GET /console

Registers the console route in admin_router, gated by
server.admin.console_enabled (default true). Route is same-origin
with the /admin/* API it calls; excluded from the OpenAPI spec like
the existing Swagger UI route."
```

---

### Task 4: Document the console in the README

**Files:**
- Modify: `README.md`

**Interfaces:** None (documentation only).

- [ ] **Step 1: Add the console to the Admin Server endpoint list**

```markdown
old:
**Admin Server (`127.0.0.1:9000`):**
- `GET /health` — Health check endpoint
- `GET /ready` — Readiness check endpoint (verifies storage connectivity)
- `GET /api-docs` — Interactive OpenAPI/Swagger UI (enabled by default; see [API Documentation](#api-documentation-openapi--swagger-ui) below)
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON)
- `POST /admin/issuance/offers` — Create credential offers (requires Bearer token if `admin.api_key` is set)
```

```markdown
new:
**Admin Server (`127.0.0.1:9000`):**
- `GET /health` — Health check endpoint
- `GET /ready` — Readiness check endpoint (verifies storage connectivity)
- `GET /api-docs` — Interactive OpenAPI/Swagger UI (enabled by default; see [API Documentation](#api-documentation-openapi--swagger-ui) below)
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON)
- `GET /console` — Embedded HTML/JS test console for triggering issuance/verification flows (enabled by default; see [Admin Test Console](#admin-test-console) below)
- `POST /admin/issuance/offers` — Create credential offers (requires Bearer token if `admin.api_key` is set)
```

- [ ] **Step 2: Insert a new "Admin Test Console" subsection**

Insert right after the "Example: Creating an Offer via Admin API" subsection and before "### 4. Key & Certificate Management CLI":

```markdown
old:
### 4. Key & Certificate Management CLI
```

```markdown
new:
#### Admin Test Console

`foundry` serves a self-contained HTML/JS test console at `GET /console` on
the Admin listener (`http://127.0.0.1:9000/console` by default) — no build
step, no external dependencies (a small QR-code library is vendored inline).
It lets you trigger the two admin flows from a browser instead of hand-rolling
`curl` calls, and produces a QR code a real wallet app can scan:

- **Issuance**: enter a `credential_type_id` and `claims` JSON, click
  "Create Offer" — get back the `credential_offer_uri` as copyable text and
  as a QR code. Scan it with a real wallet (or feed it to `foundry-wallet
  issue --offer-uri <uri>`) to complete the flow.
- **Verification**: pick a named query (`named_query_ref`) or paste raw
  `dcql_query` JSON, click "Create Verification Request" — get back the
  `openid4vp_uri`/`request_uri` as copyable text and as a QR code. The page
  auto-polls the request's status and shows `verified`, each check's
  pass/fail, and the disclosed claims once the wallet responds.

The console only calls the existing Admin API (same endpoints as the `curl`
example above) — paste your Admin API key into the field at the top of the
page; it is remembered in the browser's `localStorage` for convenience,
since the Admin listener is loopback-only by default. Disable it entirely
with `server.admin.console_enabled: false` if you don't want it exposed;
like Swagger UI, this only affects the Admin listener.

### 4. Key & Certificate Management CLI
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document the Admin Test Console (GET /console)"
```

---

### Task 5: Final verification gate

**Files:** none (verification only).

- [ ] **Step 1: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 2: Run clippy across the workspace**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS (no warnings).

- [ ] **Step 3: Run the fmt check**

Run: `cargo fmt --check`
Expected: PASS.

- [ ] **Step 4: Manual smoke test**

```bash
cargo run -p foundry -- quickstart --config /tmp/foundry-console-smoke/config.yaml --data-dir /tmp/foundry-console-smoke
cargo run -p foundry -- serve --config /tmp/foundry-console-smoke/config.yaml &
sleep 1
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9000/console   # expect: 200
kill %1
```

Expected: `200`. (Adjust the `quickstart`/`serve` invocation to match whatever flags your local checkout's `quickstart` subcommand currently takes — see `cargo run -p foundry -- quickstart --help` if the above differs.)

- [ ] **Step 5: If everything is green, no further commit is needed** — all changes were already committed at the end of Tasks 1–4. If any gate step required a fix, commit that fix now with a message describing what was fixed.