//! Structural guard: every inline-key JWS verification goes through
//! `jose::es256_verifier_from_inline_jwk`.
//!
//! Not a behavioural test. It exists because this defect has already been
//! fixed once and then rediscovered in production.
//!
//! josekit's `verifier_from_jwk` copies the JWK's own `kid` member into the
//! verifier, after which `decode_with_verifier` requires a matching `kid` on
//! the outer JWS header and otherwise fails with
//! `"The JWS kid header claim is required"`. When the key arrived *inline*
//! with the message (a `jwk` header, a `cnf.jwk`), no specification asks for
//! that header `kid` — so the call rejects conformant messages. It was fixed
//! in `proof.rs`, the fix was not carried to `dpop.rs`, `attestation.rs` or
//! `encrypted_pre_auth.rs`, and Google Wallet issuance broke at `/token`
//! months later.
//!
//! A comment saying "use the helper" would not have prevented that. This does.
//! Reasoning and the safety argument live in `src/jose.rs`'s module docs.

use std::path::{Path, PathBuf};

/// The one file allowed to call `verifier_from_jwk` — it *is* the wrapper.
const HELPER: &str = "jose.rs";

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The production half of a source file: everything before the first
/// `#[cfg(test)]`.
///
/// Test code is deliberately exempt. Several tests call
/// `ES256.verifier_from_jwk` directly *on purpose* — `attestation.rs` uses it
/// to assert that a malformed `cnf.jwk` is rejected at verifier-construction
/// time, which is exactly the raw behaviour under test.
fn production_half(text: &str) -> &str {
    match text.find("#[cfg(test)]") {
        Some(i) => &text[..i],
        None => text,
    }
}

#[test]
fn no_production_code_builds_a_verifier_from_a_jwk_directly() {
    let mut offenders = Vec::new();

    let entries = std::fs::read_dir(src_dir()).expect("crate src/ is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        if path.file_name().is_some_and(|n| n == HELPER) {
            continue;
        }

        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

        for (n, line) in production_half(&text).lines().enumerate() {
            if line.contains("verifier_from_jwk")
                && !line.contains("es256_verifier_from_inline_jwk")
            {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                offenders.push(format!("{name}:{}: {}", n + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these call `verifier_from_jwk` directly instead of \
         `jose::es256_verifier_from_inline_jwk`:\n  {}\n\n\
         If the key arrived inline with the message it verifies (a `jwk` header, \
         a `cnf.jwk`), use the helper — a `kid` on that JWK would otherwise be \
         turned into a demand for a `kid` on the JWS header, rejecting \
         conformant messages. If the key was instead selected *by* `kid` out of \
         a set, the label is load-bearing: keep the direct call and exempt it \
         here with a comment saying why.",
        offenders.join("\n  ")
    );
}

/// The positive control. Without it the guard above would still pass if
/// `production_half` silently truncated every file to nothing — for instance
/// if the marker string it splits on ever changed.
#[test]
fn the_guard_can_actually_see_production_code() {
    let dpop = std::fs::read_to_string(src_dir().join("dpop.rs")).expect("dpop.rs is readable");
    let prod = production_half(&dpop);

    assert!(
        prod.contains("es256_verifier_from_inline_jwk"),
        "the production half of dpop.rs must contain the helper call the guard \
         is scanning for; if this fails, the scan is looking at nothing"
    );
    assert!(
        prod.len() < dpop.len(),
        "dpop.rs has a #[cfg(test)] module, so its production half must be a \
         strict prefix — otherwise the test-code exemption is not being applied"
    );
}
