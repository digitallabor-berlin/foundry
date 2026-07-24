# Task #2: Strip port from x509_san_dns client_id host derivation

## Summary
Added a shared `pub(crate) fn dns_host_only(base_url: &str) -> String` helper in
`crates/foundry-verifier/src/request.rs` that strips the `https://`/`http://` scheme,
then strips everything from the first `/` (path) and first `:` (port), leaving only
the hostname. Replaced all three ad-hoc `trim_start_matches` call sites with this
helper so build-side and verify-side client_id derivation stay guaranteed-consistent.

## Call sites changed (localhost:8443 example)

1. `crates/foundry-verifier/src/request.rs` — `create_verification_request`
   (cross-device `openid4vp://` URI client_id), ~line 132
   - Before: `x509_san_dns:localhost:8443`
   - After:  `x509_san_dns:localhost`

2. `crates/foundry-verifier/src/request.rs` — `build_signed_request_object`
   (client_id embedded in signed request object JWT payload), ~line 174
   - Before: `x509_san_dns:localhost:8443`
   - After:  `x509_san_dns:localhost`

3. `crates/foundry-verifier/src/verify.rs` — `do_verify_vp_response`
   (client_id used to verify SD-JWT VC / KB-JWT `aud`), ~line 60
   - Before: `x509_san_dns:localhost:8443`
   - After:  `x509_san_dns:localhost`
   - Calls `crate::request::dns_host_only(base_url)` (request module was already
     `pub mod request` in lib.rs, so no visibility changes needed).

## Tests updated
- `crates/foundry-verifier/src/verify.rs` test `test_verify_vp_response_sd_jwt_vc`
  (~line 262, config uses `public_base_url: "https://localhost:8443"`):
  literal `client_id` fixture changed from `"x509_san_dns:localhost:8443"` to
  `"x509_san_dns:localhost"` to match what the fixed derivation now produces —
  this is a fixture used as input to `attach_kb_jwt`/verification, not incidental.
- `crates/foundry-verifier/src/verify.rs` test `test_verify_vp_response_kb_nonce_mismatch`
  (~line 349, same config): same literal fix, same reasoning (nonce-mismatch test,
  client_id itself must still match the verify-side derivation or the test would
  fail for the wrong reason).
- `crates/foundry-verifier/src/request.rs` test `test_build_signed_request_object_and_verify_jws`
  (~line 443, config `public_base_url: "https://verifier.example.com"`, no port):
  literal `"x509_san_dns:verifier.example.com"` is unaffected by the fix (no port
  to strip) — re-verified it still passes, left unchanged.

## Test run
`cargo test -p foundry-verifier` — 13/13 passed, 0 failed, pristine output
(unit tests + doc-tests, no warnings surfaced in test output).

## Commit
- `76f32b9` — fix(verifier): strip port from x509_san_dns client_id host derivation