//! Structural guards on how the workspace is instrumented.
//!
//! These are not behavioural tests. They enforce two rules that are easy to
//! break silently and expensive to discover in production:
//!
//! 1. every `#[tracing::instrument]` carries `skip_all`;
//! 2. no payload-bearing field is emitted without the dev-only flag gating it.
//!
//! Both are stated in the spec, and both would otherwise rely on every future
//! author remembering them.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/foundry.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// Every `.rs` file under the given crate directories.
fn rust_sources(dirs: &[&str]) -> Vec<(PathBuf, String)> {
    let root = workspace_root();
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = dirs.iter().map(|d| root.join(d)).collect();
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => panic!("reading {}: {e}", dir.display()),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
                out.push((path, text));
            }
        }
    }
    assert!(!out.is_empty(), "found no Rust sources to check");
    out
}

/// `#[tracing::instrument]` without `skip_all` records **every argument** via
/// `Debug`. In these crates the arguments include `Config`,
/// `VerificationTransaction` (which holds `ephem_private_jwk`) and raw JWE
/// strings — so the default would write private key material into the log.
///
/// This is the single most consequential rule in the whole observability change,
/// which is why it is enforced rather than documented.
#[test]
fn every_instrument_attribute_skips_all_arguments() {
    let mut offenders = Vec::new();

    for (path, text) in rust_sources(&[
        "crates/foundry/src",
        "crates/foundry-issuer/src",
        "crates/foundry-verifier/src",
        "crates/foundry-core/src",
    ]) {
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("#[tracing::instrument") && !trimmed.starts_with("#[instrument")
            {
                continue;
            }
            // The attribute may span several lines; take everything up to the
            // matching close so `skip_all` on a later line still counts.
            let rest: String = text
                .lines()
                .skip(idx)
                .take_while(|l| {
                    !l.trim_start().starts_with("pub ")
                        && !l.trim_start().starts_with("fn ")
                        && !l.trim_start().starts_with("async ")
                })
                .collect::<Vec<_>>()
                .join(" ");
            if !rest.contains("skip_all") {
                offenders.push(format!("{}:{}", path.display(), idx + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "#[tracing::instrument] without skip_all would Debug-format every argument \
         into the span, including Config, VerificationTransaction (which holds \
         ephem_private_jwk) and raw JWEs. Add skip_all and opt into fields \
         explicitly. Offenders:\n  {}",
        offenders.join("\n  ")
    );
}

/// Field names are operator-facing API: people grep and alert on them. A rename
/// is a breaking change for whoever is watching the logs, so the documented set
/// is pinned here.
#[test]
fn the_documented_field_names_are_still_in_use() {
    let sources = rust_sources(&[
        "crates/foundry/src",
        "crates/foundry-issuer/src",
        "crates/foundry-verifier/src",
    ]);
    let all: String = sources.iter().map(|(_, t)| t.as_str()).collect();

    for field in [
        "request_id",
        "tx_id",
        "route",
        "method",
        "listener",
        "http.status",
        "latency_ms",
        "error.kind",
        "error.detail",
    ] {
        assert!(
            all.contains(field),
            "documented log field `{field}` is no longer emitted anywhere; if it was \
             renamed, update README.md and the spec too — operators grep these"
        );
    }
}

/// Payload-bearing fields must be gated on the dev-only flag. A `debug!` alone
/// is not sufficient: `RUST_LOG=debug` is a perfectly ordinary thing for an
/// operator to set in production.
#[test]
fn payload_fields_are_gated_on_the_sensitive_flag() {
    let payload_field_markers = [
        "vp_response_jwe",
        "decrypted_response",
        "vp_token",
        "disclosed_claims =",
        "credential_jwt",
    ];

    for (path, text) in rust_sources(&[
        "crates/foundry/src",
        "crates/foundry-issuer/src",
        "crates/foundry-verifier/src",
    ]) {
        for marker in payload_field_markers {
            for (idx, line) in text.lines().enumerate() {
                if !line.contains(marker) {
                    continue;
                }
                // Only log statements matter; the field name may legitimately
                // appear in ordinary code, comments or JSON keys.
                let is_log_line = text
                    .lines()
                    .skip(idx.saturating_sub(4))
                    .take(5)
                    .any(|l| l.contains("tracing::debug!") || l.contains("tracing::trace!"));
                if !is_log_line {
                    continue;
                }
                // Look back for the flag check guarding this statement.
                let preceding: String = text
                    .lines()
                    .skip(idx.saturating_sub(8))
                    .take(9)
                    .collect::<Vec<_>>()
                    .join(" ");
                assert!(
                    preceding.contains("sensitive_enabled()"),
                    "{}:{} logs the payload field `{marker}` without an \
                     obs::sensitive_enabled() gate. A debug level alone is not \
                     authorisation — RUST_LOG=debug is ordinary in production.",
                    path.display(),
                    idx + 1
                );
            }
        }
    }
}
