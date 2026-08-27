# Android Keystore Attestation (Google Wallet `android_keystore_attestation` proof type)

Foundry accepts Google Wallet's `android_keystore_attestation` proof type at
`POST /credential` — an array of X.509 certificate chains carrying an Android
Keystore hardware attestation, rather than a signed JWT (it is not the
OpenID4VCI Appendix D key attestation JWT format). It is configured alongside
the existing `issuer.key_attestation` block (which continues to govern the
`jwt` proof type's own key-attestation-JWT support), sharing its
`trusted_anchors`:

```yaml
issuer:
  key_attestation:
    trusted_anchors:
      - name: google-android-root
        certs: /etc/foundry/android-attestation-roots.pem
    android:
      mode: optional                              # disabled (default) | optional | required
      key_mint_security_level: TrustedEnvironment  # Software | TrustedEnvironment | StrongBox
```

- `mode: disabled` (default) — the proof type is never advertised in issuer
  metadata, and any `android_keystore_attestation` member in a `/credential`
  request's `proofs` object is rejected with HTTP 400 `invalid_proof`.
- `mode: optional` — the proof type is accepted alongside `jwt`; a Credential
  Request must still use exactly one proof type, per OpenID4VCI's own rule.
- `mode: required` — only `android_keystore_attestation` is accepted; a
  Credential Request presenting the `jwt` proof type is rejected.
- `key_mint_security_level` (default `TrustedEnvironment`) — the minimum
  KeyMint security level enforced independently against **both** the
  certificate's `attestationSecurityLevel` and `keyMintSecurityLevel` fields.
  `StrongBox` is strictly stronger than `TrustedEnvironment`, which is
  strictly stronger than `Software`.
- **Enabling this proof type with an empty `trusted_anchors` is a startup
  configuration error** — the same fail-closed rule the `wallet_attestation`
  and `key_attestation` (`jwt`) blocks already enforce.
- `trusted_anchors` should point at Google's published Android Key Attestation
  root certificates:
  <https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate>.
- **Revocation is not checked.** Google's guidance asks issuers to check a
  presented attestation certificate against
  `https://android.googleapis.com/attestation/status`; foundry does not make
  this call. A revoked attestation key is currently accepted if its
  certificate chain otherwise validates and its security level and
  `attestationChallenge` are correct. This is a named follow-on, not an
  oversight — see the design doc's "Deviations and known limitations"
  (`docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md`).

No new log field names are introduced, so the Logging & Observability section
below needs no change; the `attestationChallenge` (a `c_nonce`) and the
attestation's `uniqueId` (a privacy-sensitive hardware device identifier) are
never logged, per root `AGENTS.md` §4.5.

---
