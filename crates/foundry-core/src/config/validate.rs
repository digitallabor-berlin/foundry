use super::mdoc;
use super::model::Config;
use crate::crypto::{FileSigner, SignatureAlgorithm, Signer};
use crate::error::ConfigError;
use base64::Engine as _;
use std::path::Path;
use std::str::FromStr;

impl Config {
    /// Warn-level diagnostic: the Status List Token signer is not the key that
    /// signs credentials. `None` means nothing to report.
    ///
    /// draft-ietf-oauth-status-list-14 §11.3 mandates no key-resolution method
    /// at all, and §13.5 explicitly permits a wholly separate Status Issuer, so
    /// this configuration is legal and must **never** be a rejection. It is
    /// nonetheless almost always a deployment mistake: the Credo / `@sd-jwt`
    /// wallet stack verifies a Status List Token with the *credential issuer's*
    /// key and never decodes the token's own `x5c`, so a divergent signer makes
    /// every credential carrying a `status` claim fail status validation there.
    /// Diagnosed 2026-08-28 against the `foundry.digitallabor.dev` deployment
    /// with the Paradym wallet.
    ///
    /// Compares resolved key *material*, not config labels — two `keys:` entries
    /// naming one PEM are confusing but interoperable. Path comparison is
    /// textual, so two spellings of one path (`./k.pem` vs `k.pem`) still warn:
    /// a false positive on an advisory line, preferred over missing the real
    /// case.
    fn status_list_signer_divergence(&self) -> Option<String> {
        if !self.issuer.status_list.enabled {
            return None;
        }
        // Unset while enabled is a *different* defect, surfaced by the
        // `/statuslists/:id` route at request time. Not this warning's business.
        let sl_name = self.issuer.status_list.signing_key.as_deref()?;
        // The single resolver — never a second lookup. See the design note on
        // `Config::credential_signing_key`.
        let (cred_name, cred_entry) = self.credential_signing_key()?;
        let sl_entry = self.keys.get(sl_name)?;
        if sl_name == cred_name || sl_entry.private_key == cred_entry.private_key {
            return None;
        }
        Some(format!(
            "issuer.status_list.signing_key '{sl_name}' is not the credential signing key \
             '{cred_name}', so Status List Tokens are signed by a different key than the \
             credentials that reference them. This is permitted \
             (draft-ietf-oauth-status-list-14 §11.3, §13.5), but the Credo/@sd-jwt wallet \
             stack verifies a Status List Token with the credential issuer's key and \
             ignores the token's own x5c, so wallets built on it will reject every \
             credential carrying a `status` claim. Point both fields at one key unless you \
             are deliberately operating a separate Status Issuer"
        ))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // Every verifier.signing_key must resolve into keys.
        if !self.keys.contains_key(&self.verifier.signing_key) {
            return Err(ConfigError::Validation(format!(
                "verifier.signing_key references unknown key '{}'",
                self.verifier.signing_key
            )));
        }
        // status_list.signing_key, when set, must resolve.
        if let Some(sk) = &self.issuer.status_list.signing_key
            && !self.keys.contains_key(sk)
        {
            return Err(ConfigError::Validation(format!(
                "issuer.status_list.signing_key references unknown key '{sk}'"
            )));
        }
        // credential_signing_key, when set, must resolve. Same rule as the two
        // above: a signing key named but absent is a startup failure, never a
        // silent fall-through to the next step of the resolution order --
        // falling through would sign credentials with a key the operator did
        // not choose, which is the failure mode this field exists to end.
        if let Some(sk) = &self.issuer.credential_signing_key
            && !self.keys.contains_key(sk)
        {
            return Err(ConfigError::Validation(format!(
                "issuer.credential_signing_key references unknown key '{sk}'"
            )));
        }
        // Permitted by the status-list draft, but a wallet-interop trap — so
        // permitted and never silent. See `status_list_signer_divergence`.
        if let Some(warning) = self.status_list_signer_divergence() {
            tracing::warn!("{warning}");
        }
        // Credential types: supported formats + required identifier per format.
        for ct in &self.credential_types {
            match ct.format.as_str() {
                "dc+sd-jwt" => {
                    if ct.vct.is_none() {
                        return Err(ConfigError::Validation(format!(
                            "credential_type '{}' (dc+sd-jwt) requires 'vct'",
                            ct.id
                        )));
                    }
                }
                "mso_mdoc" => {
                    // OpenID4VCI Format Profile / mdoc (L2235): `doctype` is
                    // REQUIRED and identifies the Credential type per ISO
                    // 18013-5.
                    let Some(doctype) = ct.doctype.as_deref() else {
                        return Err(ConfigError::Validation(format!(
                            "credential_type '{}' (mso_mdoc) requires 'doctype'",
                            ct.id
                        )));
                    };
                    // `vct` is an SD-JWT-VC identifier (typically an HTTPS URL)
                    // with no relationship to ISO 18013-5's reverse-DNS docType
                    // convention. A type carrying both was config-legal and made
                    // docType resolution ambiguous — GAP-VCI-12. Rejecting it
                    // removes the ambiguous state rather than picking a winner
                    // inside it, which is what lets `credential.rs` read
                    // `doctype` with no fallback at all.
                    if ct.vct.is_some() {
                        return Err(ConfigError::Validation(format!(
                            "credential_type '{}' (mso_mdoc) must not set 'vct'; an mdoc is \
                             identified by 'doctype' (OpenID4VCI L2235)",
                            ct.id
                        )));
                    }
                    // EU Age Verification Annex A §4.1.2's closed attribute set.
                    // Keyed on a known doctype, in the manner of
                    // `create_offer.rs`'s DPC_VCT; see
                    // docs/specs/eu-age-verification-annex-a-av-profile.md.
                    if doctype == mdoc::AV_DOCTYPE {
                        mdoc::validate_av_claims(&ct.id, &ct.claims)?;
                    }
                }
                other => {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}' has unsupported format '{other}'",
                        ct.id
                    )));
                }
            }

            // A zero lifetime yields exp == iat, so the credential is expired
            // the instant it is issued. That is a configuration error, not a
            // policy an operator could intend.
            if ct.validity_seconds == Some(0) {
                return Err(ConfigError::Validation(format!(
                    "credential_type '{}' has validity_seconds: 0; a credential whose \
                     exp equals its iat is never valid",
                    ct.id
                )));
            }

            // OpenID4VCI 1.0 Claims Path Pointer (L2366): a claims path pointer
            // is a *non-empty* array. An empty path addresses no claim, so no
            // supplied value can ever satisfy it -- reject at startup rather
            // than per offer. Closes the emptiness half of GAP-VCI-13; the
            // typing half (Vec<String> cannot express null or integer segments)
            // remains open.
            for cd in &ct.claims {
                if cd.path.is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}' has a claim with an empty 'path'; a claims \
                         path pointer must be a non-empty array",
                        ct.id
                    )));
                }
            }

            // PaSO Proof Metadata §3 — validate every declared transaction data
            // type at startup, so an operator's typo is a boot failure rather
            // than a wallet-facing one.
            if let Some(types) = &ct.transaction_data_types {
                if types.is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}': 'transaction_data_types' must not be empty; omit \
                         the key entirely for a non-PaSO credential type",
                        ct.id
                    )));
                }
                for (type_id, meta) in types {
                    validate_paso_transaction_data_type_metadata(type_id, meta).map_err(|e| {
                        ConfigError::Validation(format!("credential_type '{}': {e}", ct.id))
                    })?;
                }
            }
        }

        // PaSO Proof Metadata §4 — the signed credential metadata JWT carries
        // the Attestation Provider's certificate chain in its `x5c` JOSE
        // header, and §7 step 6 binds that chain to the credential's own. A
        // deployment with PaSO credential types but no chain on the credential
        // signing key cannot mint a conformant JWT at all, so this is fatal at
        // startup rather than a 500 at request time.
        //
        // foundry implements the `x5c` branch only; §4's `kid`/key-set
        // alternative is a documented unimplemented optional path.
        if self
            .credential_types
            .iter()
            .any(|ct| ct.transaction_data_types.is_some())
        {
            match self.credential_signing_key() {
                None => {
                    return Err(ConfigError::Validation(
                        "a PaSO credential type is configured (transaction_data_types) but no \
                         credential signing key resolves; PaSO Proof Metadata §4 requires one"
                            .to_string(),
                    ));
                }
                Some((name, entry)) if entry.x5c.is_none() => {
                    return Err(ConfigError::Validation(format!(
                        "a PaSO credential type is configured (transaction_data_types) but the \
                         credential signing key '{name}' has no 'x5c' certificate chain; PaSO \
                         Proof Metadata §4 requires one in the metadata JWT header"
                    )));
                }
                Some(_) => {}
            }
        }

        // HAIP OpenID4VCI L209: the scope value MUST map to a *specific* Credential
        // Type, so two types may not resolve to the same scope.
        let mut seen_scopes: std::collections::BTreeMap<&str, &str> =
            std::collections::BTreeMap::new();
        for ct in &self.credential_types {
            if let Some(explicit) = &ct.scope
                && explicit.trim().is_empty()
            {
                return Err(ConfigError::Validation(format!(
                    "credential_type '{}' has an empty 'scope'",
                    ct.id
                )));
            }
            if let Some(previous) = seen_scopes.insert(ct.resolved_scope(), &ct.id) {
                return Err(ConfigError::Validation(format!(
                    "credential_types '{}' and '{}' both resolve to scope '{}'; each \
                     scope must map to exactly one Credential Type",
                    previous,
                    ct.id,
                    ct.resolved_scope()
                )));
            }
        }

        // OpenID4VCI 1.0 Credential Issuer Metadata (L1368, L1369): `credential_endpoint`
        // and `nonce_endpoint`, both derived unconditionally from `issuer.credential_issuer`
        // (see `build_issuer_metadata`), MUST use the `https` scheme.
        //
        // Deliberate deviation (GAP-VCI-08, AGENTS.md §4.4): loopback hosts are exempt.
        // The repository's own dev config (`config.yaml`) runs `issuer.credential_issuer`
        // over plain `http://localhost:8443`, and enforcing the MUST unconditionally
        // would make that shipped config fail to boot. See `foundry-core/AGENTS.md`
        // Gotchas for the accepted consequence: a loopback deployment's RFC 9207 `iss`
        // value (also required to be `https`, RFC 9207 §2) will not be conformant either.
        if !self.issuer.credential_issuer.starts_with("https://") {
            let host = crate::url::dns_host_only(&self.issuer.credential_issuer);
            if !is_loopback_host(&host) {
                return Err(ConfigError::Validation(format!(
                    "issuer.credential_issuer '{}' must use the https scheme (OpenID4VCI \
                     credential_endpoint/nonce_endpoint MUST use https), unless its host is \
                     a loopback address",
                    self.issuer.credential_issuer
                )));
            }
        }

        // OpenID4VCI 1.0 Credential Issuer Metadata (L1366): `credential_issuer` MUST be
        // identical -- "compared using a simple string comparison with no normalization" --
        // to the identifier used to build the well-known URL, which in this deployment is
        // `server.wallet_facing.public_base_url` (the router `credential_issuer` is actually
        // served under). No trailing-slash or case tolerance.
        if self.issuer.credential_issuer != self.server.wallet_facing.public_base_url {
            return Err(ConfigError::Validation(format!(
                "issuer.credential_issuer '{}' must be byte-identical to \
                 server.wallet_facing.public_base_url '{}' (OpenID4VCI credential_issuer \
                 identity requires a simple string comparison with no normalization -- a \
                 trailing slash or scheme/case difference is a mismatch)",
                self.issuer.credential_issuer, self.server.wallet_facing.public_base_url
            )));
        }

        // RFC 9449 §4.3 check 11: a zero acceptance window makes every proof stale
        // the instant it is minted, so every DPoP request would fail with a blanket
        // invalid_dpop_proof. Caught at startup rather than at request time.
        if self.issuer.dpop.max_age_secs == 0 {
            return Err(ConfigError::Validation(
                "issuer.dpop.max_age_secs must be greater than 0".to_string(),
            ));
        }

        // OpenID4VCI Credential Issuer Metadata (L1373): `jwks` is REQUIRED, so
        // an enabled block with no resolvable keys is unservable metadata.
        if let Some(re) = &self.issuer.request_encryption {
            if re.keys.is_empty() {
                return Err(ConfigError::Validation(
                    "issuer.request_encryption.keys must be non-empty".to_string(),
                ));
            }
            for name in &re.keys {
                if !self.keys.contains_key(name) {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references unknown key '{name}'"
                    )));
                }
                // One EC key must not serve both ECDSA signing and ECDH key
                // agreement. The `keys:` map is shared, so this is the only place
                // cross-purpose reuse can be prevented.
                if name == &self.verifier.signing_key {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references '{name}', which is also \
                         verifier.signing_key; an encryption key must not be reused for signing"
                    )));
                }
                if self.issuer.status_list.signing_key.as_deref() == Some(name.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references '{name}', which is also \
                         issuer.status_list.signing_key; an encryption key must not be reused \
                         for signing"
                    )));
                }
                // The credential signing key is *resolved*, not always named:
                // with neither issuer.credential_signing_key nor
                // issuer.status_list.signing_key set it falls back to the
                // alphabetically first `keys` entry, which can be this very
                // encryption key. The two checks above compare against named
                // fields and so cannot see that path; this one compares against
                // the resolution result, which is the only thing that closes it.
                if self.credential_signing_key().map(|(n, _)| n) == Some(name.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references '{name}', which also resolves \
                         as the credential signing key; an encryption key must not be reused for \
                         signing. Set issuer.credential_signing_key explicitly to name a \
                         different key"
                    )));
                }
            }
            check_enc_values("issuer.request_encryption", &re.enc_values_supported)?;
        }

        if let Some(rs) = &self.issuer.response_encryption {
            check_enc_values("issuer.response_encryption", &rs.enc_values_supported)?;
            // OpenID4VCI L960: a request carrying `credential_response_encryption`
            // MUST itself be encrypted. Requiring response encryption while
            // supporting no request decryption is unsatisfiable.
            let no_request_keys = match &self.issuer.request_encryption {
                None => true,
                Some(re) => re.keys.is_empty(),
            };
            if rs.encryption_required && no_request_keys {
                return Err(ConfigError::Validation(
                    "issuer.response_encryption.encryption_required is true but \
                     issuer.request_encryption has no keys; OpenID4VCI L960 requires a request \
                     carrying credential_response_encryption to be encrypted, so no conformant \
                     wallet could use this deployment"
                        .to_string(),
                ));
            }
        }

        // Fail closed at load time. With the proof type enabled and no anchors
        // every attestation chain would be rejected at request time -- a silent
        // total outage. Failing here makes it a legible misconfiguration.
        if self.issuer.key_attestation.android.mode != super::model::Mode::Disabled
            && self.issuer.key_attestation.trusted_anchors.is_empty()
        {
            return Err(ConfigError::Validation(
                "issuer.key_attestation.android.mode is enabled but \
                 issuer.key_attestation.trusted_anchors is empty: every \
                 android_keystore_attestation chain would be rejected"
                    .into(),
            ));
        }

        // Fail closed at load time, same reasoning as the android rule above.
        // Google Wallet profile, §"token request field signing & encryption":
        // the inner JWS is verified against the Client Attestation's `cnf.jwk`
        // and the outer JWE is opened with the credential_request_encryption
        // keys. Without either, every request carrying the member fails at
        // request time -- a silent total outage of the Token Endpoint rather
        // than a legible misconfiguration.
        if self.issuer.encrypted_pre_authorized_code.mode != super::model::Mode::Disabled {
            if self.issuer.wallet_attestation.mode == super::model::Mode::Disabled {
                return Err(ConfigError::Validation(
                    "issuer.encrypted_pre_authorized_code.mode is enabled but \
                     issuer.wallet_attestation.mode is disabled: the inner JWS is verified \
                     against the Client Attestation's cnf.jwk, so no request could ever \
                     succeed"
                        .into(),
                ));
            }
            let has_keys = self
                .issuer
                .request_encryption
                .as_ref()
                .is_some_and(|re| !re.keys.is_empty());
            if !has_keys {
                return Err(ConfigError::Validation(
                    "issuer.encrypted_pre_authorized_code.mode is enabled but \
                     issuer.request_encryption has no keys: there would be nothing to \
                     decrypt the outer JWE with"
                        .into(),
                ));
            }
        }

        // Design §4.1 -- the webhook may carry holder PII, so plaintext to a
        // routable host is a configuration error rather than a warning.
        if let Some(wh) = &self.verifier.webhook {
            if !webhook_url_is_acceptable(&wh.url) {
                return Err(ConfigError::Validation(format!(
                    "verifier.webhook.url must use https, or http to a loopback host; got '{}'",
                    wh.url
                )));
            }
            // Permitted (the receiver may be on a trusted network) but never
            // silent: without a secret the receiver cannot establish that an
            // audit record came from this verifier.
            if wh.include_raw_artifacts && wh.secret.is_none() && wh.secret_env.is_none() {
                tracing::warn!(
                    "verifier.webhook.include_raw_artifacts is enabled with no secret or \
                     secret_env; holder PII will be delivered unsigned"
                );
            }
        }

        Ok(())
    }
}

/// Whether `url` may receive holder PII.
///
/// `https` always; `http` only to a loopback host. Hand-rolled rather than
/// using a URL parser because `url` is not a workspace dependency and adding
/// one for a scheme check is not warranted.
///
/// Loopback is decided by this module's existing [`is_loopback_host`] rather
/// than a second, wider predicate: two functions answering "is this host
/// loopback" with different answers is how one config key ends up more
/// permissive than another for no stated reason. Its exact-four-forms rule is
/// the stricter of the two, which is the right direction for a PII egress.
fn webhook_url_is_acceptable(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    match webhook_http_host(url) {
        Some(host) => is_loopback_host(host),
        None => false,
    }
}

/// The host of an `http://` URL, with userinfo, port, and path removed.
/// Returns `None` for any other scheme.
fn webhook_http_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("http://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    // `user:pass@host` -> `host`; a bare `host` is unchanged.
    let authority = authority.rsplit('@').next()?;
    // IPv6 literals are bracketed: `[::1]:9000` -> `::1`.
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split(']').next();
    }
    authority.split(':').next()
}

/// An `enc` value may be advertised only if it can actually be honoured.
/// PaSO Core §5.2 — `urn:paso:sca:<domain>:<suffix>:<version>`.
///
/// `<version>` "SHALL be a positive integer without leading zeros and SHALL be
/// the final segment of the identifier".
fn validate_paso_type_identifier(id: &str) -> Result<(), String> {
    let Some(rest) = id.strip_prefix("urn:paso:sca:") else {
        return Err(format!(
            "transaction data type '{id}' must start with 'urn:paso:sca:' (PaSO Core §5.2)"
        ));
    };
    let segments: Vec<&str> = rest.split(':').collect();
    // <domain>, at least one <suffix> segment, <version>.
    if segments.len() < 3 {
        return Err(format!(
            "transaction data type '{id}' must have the form \
             urn:paso:sca:<domain>:<suffix>:<version> (PaSO Core §5.2)"
        ));
    }
    if segments.iter().any(|s| s.is_empty()) {
        return Err(format!(
            "transaction data type '{id}' contains an empty segment (PaSO Core §5.2)"
        ));
    }
    let version = segments[segments.len() - 1];
    if !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "transaction data type '{id}': version segment '{version}' must be an integer \
             (PaSO Core §5.2)"
        ));
    }
    if version.starts_with('0') {
        return Err(format!(
            "transaction data type '{id}': version segment '{version}' must be a positive \
             integer without leading zeros (PaSO Core §5.2)"
        ));
    }
    Ok(())
}

/// PaSO Proof Metadata §3, §3.1, §3.2 — structural validation of one
/// `transaction_data_types` entry.
///
/// Public because two channels publish this shape and both must be held to the
/// same rules: `Config::validate()` at startup, and the admin ad-hoc mint
/// endpoint, which accepts an inline metadata override. A channel that
/// accepted shapes the other rejects would make validation advisory.
pub fn validate_paso_transaction_data_type_metadata(
    type_id: &str,
    meta: &crate::config::TransactionDataTypeMetadata,
) -> Result<(), String> {
    validate_paso_type_identifier(type_id)?;

    // §3: `claims` is REQUIRED, and §3.1 requires metadata "for each claim of
    // the transaction data payload" — an empty array describes nothing.
    if meta.claims.is_empty() {
        return Err(format!(
            "transaction data type '{type_id}': 'claims' must not be empty \
             (PaSO Proof Metadata §3)"
        ));
    }

    for (i, claim) in meta.claims.iter().enumerate() {
        let Some(obj) = claim.as_object() else {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] must be an object"
            ));
        };

        // §3.1: `path` resolves against the transaction_data `payload` object;
        // OpenID4VCI's claims description object makes it REQUIRED.
        let Some(path) = obj.get("path").and_then(|v| v.as_array()) else {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] requires a 'path' array \
                 (PaSO Proof Metadata §3.1)"
            ));
        };
        if path.is_empty() {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] 'path' must not be empty"
            ));
        }
        if !path.iter().all(|p| p.is_string()) {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] 'path' must contain only strings"
            ));
        }

        let display = obj.get("display").and_then(|v| v.as_array());

        // §3.1: "The `value_type` parameter MUST NOT be used on claims without
        // a `display` array."
        if obj.contains_key("value_type") && display.is_none() {
            return Err(format!(
                "transaction data type '{type_id}': claims[{i}] sets 'value_type' but has no \
                 'display' array (PaSO Proof Metadata §3.1)"
            ));
        }

        if let Some(entries) = display {
            if entries.is_empty() {
                return Err(format!(
                    "transaction data type '{type_id}': claims[{i}] 'display' must not be empty"
                ));
            }
            let needs_locale = entries.len() > 1;
            for (j, entry) in entries.iter().enumerate() {
                let Some(eo) = entry.as_object() else {
                    return Err(format!(
                        "transaction data type '{type_id}': claims[{i}].display[{j}] must be an \
                         object"
                    ));
                };
                if !eo.get("name").map(|n| n.is_string()).unwrap_or(false) {
                    return Err(format!(
                        "transaction data type '{type_id}': claims[{i}].display[{j}] requires a \
                         string 'name'"
                    ));
                }
                // Two entries with no locale cannot be told apart by the
                // Wallet's RFC 4647 Lookup (PaSO Core §7.2).
                if needs_locale && !eo.contains_key("locale") {
                    return Err(format!(
                        "transaction data type '{type_id}': claims[{i}].display[{j}] requires a \
                         'locale' when the claim has more than one display entry"
                    ));
                }
            }
        }
    }

    // §3.2: each value is an array of {locale?, value, value_type?}.
    if let Some(ui) = &meta.ui_labels {
        let Some(obj) = ui.as_object() else {
            return Err(format!(
                "transaction data type '{type_id}': 'ui_labels' must be an object \
                 (PaSO Proof Metadata §3.2)"
            ));
        };
        for (key, val) in obj {
            let Some(arr) = val.as_array() else {
                return Err(format!(
                    "transaction data type '{type_id}': ui_labels['{key}'] must be an array \
                     (PaSO Proof Metadata §3.2)"
                ));
            };
            if arr.is_empty() {
                return Err(format!(
                    "transaction data type '{type_id}': ui_labels['{key}'] must not be empty"
                ));
            }
            for (j, entry) in arr.iter().enumerate() {
                let Some(eo) = entry.as_object() else {
                    return Err(format!(
                        "transaction data type '{type_id}': ui_labels['{key}'][{j}] must be an \
                         object"
                    ));
                };
                if !eo.get("value").map(|v| v.is_string()).unwrap_or(false) {
                    return Err(format!(
                        "transaction data type '{type_id}': ui_labels['{key}'][{j}] requires a \
                         string 'value' (PaSO Proof Metadata §3.2)"
                    ));
                }
                if let Some(l) = eo.get("locale")
                    && !l.is_string()
                {
                    return Err(format!(
                        "transaction data type '{type_id}': ui_labels['{key}'][{j}] 'locale' must \
                         be a string"
                    ));
                }
                if let Some(v) = eo.get("value_type")
                    && !v.is_string()
                {
                    return Err(format!(
                        "transaction data type '{type_id}': ui_labels['{key}'][{j}] 'value_type' \
                         must be a string"
                    ));
                }
            }
        }
    }

    Ok(())
}

fn check_enc_values(block: &str, values: &[String]) -> Result<(), ConfigError> {
    if values.is_empty() {
        return Err(ConfigError::Validation(format!(
            "{block}.enc_values_supported must be non-empty"
        )));
    }
    for v in values {
        if !crate::config::SUPPORTED_ENC_VALUES.contains(&v.as_str()) {
            return Err(ConfigError::Validation(format!(
                "{block}.enc_values_supported contains unsupported value '{v}' (supported: {})",
                crate::config::SUPPORTED_ENC_VALUES.join(", ")
            )));
        }
    }
    Ok(())
}

/// GAP-VCI-08's documented exemption from the `https` MUST (OpenID4VCI L1368/L1369).
/// Exactly these four forms -- not private IP ranges, not `*.local`.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

impl Config {
    /// Filesystem-aware validation: every key/cert reference must resolve
    /// (relative to `base_dir`), keys must load as signers, x5c leaves must
    /// parse and MUST NOT be self-signed (HAIP §6.1.1), and trust-anchor
    /// certs must parse.
    pub fn validate_key_material(&self, base_dir: &Path) -> Result<(), ConfigError> {
        for (name, entry) in &self.keys {
            let alg = SignatureAlgorithm::from_str(&entry.alg)
                .map_err(|e| ConfigError::Validation(format!("key '{name}': {e}")))?;
            let key_path = base_dir.join(&entry.private_key);
            let key_path = key_path.to_string_lossy();
            let signer = FileSigner::from_pem_file(&key_path, alg)
                .map_err(|e| ConfigError::Validation(format!("key '{name}': {e}")))?;

            if let Some(x5c) = &entry.x5c {
                let cert_path = base_dir.join(x5c);
                let pem = std::fs::read(&cert_path).map_err(|e| {
                    ConfigError::Validation(format!(
                        "key '{name}' x5c {}: {e}",
                        cert_path.display()
                    ))
                })?;
                let cert = crate::trust::parse_cert_pem(&pem)
                    .map_err(|e| ConfigError::Validation(format!("key '{name}' x5c: {e}")))?;
                if crate::trust::is_self_signed(&cert) {
                    return Err(ConfigError::Validation(format!(
                        "key '{name}' x5c leaf must not be self-signed (HAIP §6.1.1)"
                    )));
                }

                // The private key must match its x5c leaf certificate.
                let jwk = signer
                    .public_jwk()
                    .map_err(|e| ConfigError::Validation(format!("key '{name}': {e}")))?;
                let kx = jwk.get("x").and_then(|v| v.as_str());
                let ky = jwk.get("y").and_then(|v| v.as_str());
                let (kx, ky) = match (kx, ky) {
                    (Some(x), Some(y)) => (
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(x)
                            .map_err(|e| {
                                ConfigError::Validation(format!("key '{name}': bad JWK x: {e}"))
                            })?,
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(y)
                            .map_err(|e| {
                                ConfigError::Validation(format!("key '{name}': bad JWK y: {e}"))
                            })?,
                    ),
                    _ => {
                        return Err(ConfigError::Validation(format!(
                            "key '{name}': public JWK missing EC coordinates"
                        )));
                    }
                };
                let (cx, cy) = crate::trust::cert_ec_public_coords(&cert)
                    .map_err(|e| ConfigError::Validation(format!("key '{name}' x5c: {e}")))?;
                if kx != cx || ky != cy {
                    return Err(ConfigError::Validation(format!(
                        "key '{name}' private key does not match its x5c leaf certificate"
                    )));
                }
            }
        }

        validate_trust_anchor_list(&self.trust_anchors, base_dir, "top-level")?;
        validate_trust_anchor_list(
            &self.issuer.wallet_attestation.trusted_anchors,
            base_dir,
            "issuer.wallet_attestation",
        )?;
        validate_trust_anchor_list(
            &self.issuer.key_attestation.trusted_anchors,
            base_dir,
            "issuer.key_attestation",
        )?;

        Ok(())
    }
}

fn validate_trust_anchor_list(
    anchors: &[super::model::TrustAnchor],
    base_dir: &Path,
    label: &str,
) -> Result<(), ConfigError> {
    for anchor in anchors {
        let path = base_dir.join(&anchor.certs);
        let pem = std::fs::read(&path).map_err(|e| {
            ConfigError::Validation(format!(
                "{label} trust anchor '{}' {}: {e}",
                anchor.name,
                path.display()
            ))
        })?;
        crate::trust::parse_cert_pem(&pem).map_err(|e| {
            ConfigError::Validation(format!("{label} trust anchor '{}': {e}", anchor.name))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_paso_transaction_data_type_metadata;
    use crate::config::model::{
        AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
        LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, TrustAnchor,
        VerifierConfig, WalletFacingConfig,
    };
    use std::collections::BTreeMap;

    fn minimal_config() -> Config {
        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://issuer.example.com".to_string(),
                    bind: "0.0.0.0:8443".to_string(),
                    swagger_ui_enabled: true,
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:9000".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                    console_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "./foundry.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys: BTreeMap::new(),
            trust_anchors: Vec::new(),
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                credential_signing_key: None,
                wallet_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: None,
                    list_size: None,
                    public_base_url: None,
                },
                dpop: DpopConfig::default(),
                request_encryption: None,
                response_encryption: None,
                encrypted_pre_authorized_code: Default::default(),
                access_token_ttl_secs: 600,
                offer_by_reference: false,
                paso_metadata: Default::default(),
            },
            credential_types: Vec::new(),
            verifier: VerifierConfig {
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: Vec::new(),
                named_queries: Vec::new(),
                webhook: None,
                dc_api_expected_origins: Vec::new(),
                dc_api_accept_legacy_web_origin_audience: false,
            },
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn key_attestation_trusted_anchor_must_resolve_and_parse() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "key.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer
            .key_attestation
            .trusted_anchors
            .push(TrustAnchor {
                name: "wallet-provider-ca".to_string(),
                certs: "does-not-exist.pem".to_string(),
            });

        let err = cfg.validate_key_material(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("wallet-provider-ca"),
            "expected error to name the anchor, got: {msg}"
        );
    }

    #[test]
    fn key_attestation_trusted_anchor_parses_when_valid() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let ca = crate::pki::new_ca("Wallet Provider Root CA", 3650).unwrap();
        let ca_path = dir.path().join("wallet-provider-ca.pem");
        std::fs::write(&ca_path, &ca.cert_pem).unwrap();

        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "key.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer
            .key_attestation
            .trusted_anchors
            .push(TrustAnchor {
                name: "wallet-provider-ca".to_string(),
                certs: "wallet-provider-ca.pem".to_string(),
            });

        cfg.validate_key_material(dir.path()).unwrap();
    }

    /// A config whose `verifier.signing_key` resolves, so that `Config::validate()`
    /// gets past the pre-existing keyref check and reaches the checks under test here.
    fn config_passing_keyref_check() -> Config {
        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "unused.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg
    }

    #[test]
    fn minimal_config_with_matching_https_urls_passes_validate() {
        // Regression guard: neither new check fires on a well-formed config.
        // minimal_config() already pairs identical https URLs.
        config_passing_keyref_check().validate().unwrap();
    }

    // ---- verifier.webhook (design §4.1) ---------------------------------

    fn config_with_webhook(url: &str, include_raw_artifacts: bool) -> Config {
        let mut cfg = config_passing_keyref_check();
        cfg.verifier.webhook = Some(crate::config::WebhookConfig {
            url: url.to_string(),
            secret: None,
            secret_env: None,
            timeout_secs: 5,
            include_raw_artifacts,
        });
        cfg
    }

    #[test]
    fn webhook_url_must_be_https_for_a_routable_host() {
        let err = config_with_webhook("http://audit.example.com/hook", false)
            .validate()
            .expect_err("plaintext to a routable host must be rejected");
        assert!(
            err.to_string().contains("verifier.webhook.url"),
            "error must name the offending key, got: {err}"
        );
    }

    #[test]
    fn webhook_url_accepts_https() {
        config_with_webhook("https://audit.example.com/hook", false)
            .validate()
            .expect("https must be accepted");
    }

    #[test]
    fn webhook_url_accepts_plaintext_on_loopback() {
        for url in [
            "http://localhost:9000/hook",
            "http://127.0.0.1:9000/hook",
            "http://[::1]:9000/hook",
        ] {
            config_with_webhook(url, false)
                .validate()
                .unwrap_or_else(|e| panic!("loopback {url} must be accepted, got: {e}"));
        }
    }

    #[test]
    fn webhook_rejects_a_url_with_no_recognised_scheme() {
        let err = config_with_webhook("audit.example.com/hook", false)
            .validate()
            .expect_err("a schemeless url must be rejected");
        assert!(err.to_string().contains("verifier.webhook.url"));
    }

    // ---- PaSO Proof Metadata §3 / PaSO Core §5.2 -------------------------

    fn tdt(value: serde_json::Value) -> crate::config::TransactionDataTypeMetadata {
        serde_json::from_value(value).expect("transaction data type fixture must deserialize")
    }

    fn valid_tdt() -> crate::config::TransactionDataTypeMetadata {
        tdt(serde_json::json!({
            "claims": [
                { "path": ["transaction_id"], "mandatory": true },
                {
                    "path": ["amount"],
                    "mandatory": true,
                    "value_type": "iso_currency_amount",
                    "display": [
                        { "locale": "en", "name": "Amount" },
                        { "locale": "de", "name": "Betrag" }
                    ]
                }
            ],
            "ui_labels": {
                "affirmative_action_label": [
                    { "locale": "en", "value": "Confirm Payment" }
                ]
            }
        }))
    }

    /// A config that passes `validate()` and carries exactly one credential
    /// type, so a test can make that type a PaSO type. `config_passing_keyref_check`
    /// has an empty `credential_types`, so mutating "the first" there is a no-op.
    fn config_with_one_credential_type() -> Config {
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types.push(CredentialType {
            id: "BankPaymentCard".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://bank.example/sca/card".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: Vec::new(),
            claims: Vec::new(),
            validity_seconds: None,
            transaction_data_types: None,
        });
        cfg
    }

    #[test]
    fn a_well_formed_transaction_data_type_validates() {
        assert!(
            validate_paso_transaction_data_type_metadata(
                "urn:paso:sca:global:payment:1",
                &valid_tdt()
            )
            .is_ok()
        );
    }

    /// PaSO Core §5.2: the identifier must start with `urn:paso:sca:`.
    #[test]
    fn a_type_identifier_without_the_paso_prefix_is_rejected() {
        let err =
            validate_paso_transaction_data_type_metadata("urn:example:payment:1", &valid_tdt())
                .expect_err("must reject");
        assert!(err.contains("urn:paso:sca:"), "{err}");
    }

    /// PaSO Core §5.2: the version segment is a positive integer without
    /// leading zeros, and is the final segment.
    #[test]
    fn the_version_segment_must_be_a_positive_integer_without_leading_zeros() {
        let meta = valid_tdt();

        for bad in [
            "urn:paso:sca:global:payment:v1",
            "urn:paso:sca:global:payment:01",
            "urn:paso:sca:global:payment:0",
            "urn:paso:sca:global:payment",
            "urn:paso:sca:global::1",
        ] {
            assert!(
                validate_paso_transaction_data_type_metadata(bad, &meta).is_err(),
                "expected '{bad}' to be rejected"
            );
        }

        for good in [
            "urn:paso:sca:global:payment:1",
            "urn:paso:sca:com.example:pay:transaction:2",
            "urn:paso:sca:global:payment:10",
        ] {
            assert!(
                validate_paso_transaction_data_type_metadata(good, &meta).is_ok(),
                "expected '{good}' to be accepted"
            );
        }
    }

    /// PaSO Proof Metadata §3.1: "The `value_type` parameter MUST NOT be used
    /// on claims without a `display` array."
    #[test]
    fn value_type_without_display_is_rejected() {
        let meta = tdt(serde_json::json!({
            "claims": [{ "path": ["amount"], "value_type": "iso_currency_amount" }]
        }));
        let err =
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .expect_err("must reject");
        assert!(err.contains("value_type"), "{err}");
    }

    /// PaSO Proof Metadata §3: `claims` is REQUIRED and describes every claim
    /// of the payload — an empty array describes nothing.
    #[test]
    fn an_empty_claims_array_is_rejected() {
        let meta = tdt(serde_json::json!({ "claims": [] }));
        assert!(
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .is_err()
        );
    }

    #[test]
    fn a_claim_without_a_non_empty_string_path_is_rejected() {
        for bad in [
            serde_json::json!({ "claims": [{ "mandatory": true }] }),
            serde_json::json!({ "claims": [{ "path": [] }] }),
            serde_json::json!({ "claims": [{ "path": ["ok", 7] }] }),
        ] {
            let meta = tdt(bad);
            assert!(
                validate_paso_transaction_data_type_metadata(
                    "urn:paso:sca:global:payment:1",
                    &meta
                )
                .is_err()
            );
        }
    }

    /// Two display entries with no `locale` cannot be told apart by the
    /// Wallet's RFC 4647 Lookup (PaSO Core §7.2).
    #[test]
    fn multiple_display_entries_without_locale_are_rejected() {
        let meta = tdt(serde_json::json!({
            "claims": [{
                "path": ["amount"],
                "display": [{ "name": "Amount" }, { "name": "Betrag" }]
            }]
        }));
        assert!(
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .is_err()
        );
    }

    /// A single display entry needs no locale — §3.2 lets an entry without one
    /// serve as the default.
    #[test]
    fn a_single_display_entry_without_locale_is_accepted() {
        let meta = tdt(serde_json::json!({
            "claims": [{ "path": ["amount"], "display": [{ "name": "Amount" }] }]
        }));
        assert!(
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .is_ok()
        );
    }

    /// PaSO Proof Metadata §3.2: each `ui_labels` entry carries a string `value`.
    #[test]
    fn ui_labels_entries_require_a_string_value() {
        let meta = tdt(serde_json::json!({
            "claims": [{ "path": ["a"] }],
            "ui_labels": { "affirmative_action_label": [{ "locale": "en" }] }
        }));
        let err =
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .expect_err("must reject");
        assert!(err.contains("value"), "{err}");
    }

    /// §3 permits additional parameters and obliges the Wallet to ignore
    /// unrecognised ones, so foundry must accept and preserve them.
    #[test]
    fn unrecognised_members_are_preserved_not_rejected() {
        let meta = tdt(serde_json::json!({
            "claims": [{ "path": ["a"] }],
            "risk_signal_profile": "urn:paso:risk:global:default:1"
        }));
        assert!(
            validate_paso_transaction_data_type_metadata("urn:paso:sca:global:payment:1", &meta)
                .is_ok()
        );
        assert!(meta.extra.contains_key("risk_signal_profile"));
    }

    /// PaSO Proof Metadata §4: the metadata JWT carries the issuer's chain in
    /// its `x5c` header, so a PaSO deployment without one cannot mint a
    /// conformant artifact. Fail at boot, not at request time.
    #[test]
    fn a_paso_credential_type_requires_an_x5c_on_the_credential_signing_key() {
        let mut cfg = config_with_one_credential_type();
        let mut map = BTreeMap::new();
        map.insert("urn:paso:sca:global:payment:1".to_string(), valid_tdt());
        cfg.credential_types[0].transaction_data_types = Some(map);
        for entry in cfg.keys.values_mut() {
            entry.x5c = None;
        }

        let err = cfg.validate().expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("x5c"), "{msg}");
        assert!(msg.contains("PaSO"), "{msg}");
    }

    /// A credential type with no `transaction_data_types` is not a PaSO type
    /// and imposes no new requirement — existing deployments are unaffected.
    #[test]
    fn a_non_paso_config_does_not_require_an_x5c() {
        let mut cfg = config_with_one_credential_type();
        for entry in cfg.keys.values_mut() {
            entry.x5c = None;
        }
        assert!(cfg.validate().is_ok());
    }

    /// An empty `transaction_data_types` map declares a PaSO type that
    /// describes nothing. Omitting the key is how a non-PaSO type is spelled.
    #[test]
    fn an_empty_transaction_data_types_map_is_rejected() {
        let mut cfg = config_with_one_credential_type();
        cfg.credential_types[0].transaction_data_types = Some(BTreeMap::new());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn non_loopback_http_credential_issuer_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_issuer = "http://issuer.example.com".to_string();
        cfg.server.wallet_facing.public_base_url = "http://issuer.example.com".to_string();

        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("https"),
            "expected an https-scheme error, got: {err}"
        );
    }

    #[test]
    fn loopback_http_credential_issuer_localhost_is_accepted() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_issuer = "http://localhost:8443".to_string();
        cfg.server.wallet_facing.public_base_url = "http://localhost:8443".to_string();

        cfg.validate().unwrap();
    }

    #[test]
    fn loopback_http_credential_issuer_127_0_0_1_is_accepted() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_issuer = "http://127.0.0.1:8443".to_string();
        cfg.server.wallet_facing.public_base_url = "http://127.0.0.1:8443".to_string();

        cfg.validate().unwrap();
    }

    #[test]
    fn credential_issuer_diverging_from_public_base_url_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.server.wallet_facing.public_base_url = "https://different-host.example.com".to_string();
        // cfg.issuer.credential_issuer stays at minimal_config()'s
        // "https://issuer.example.com" -- the two values now diverge.

        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("public_base_url"),
            "expected an identity-mismatch error, got: {err}"
        );
    }

    #[test]
    fn credential_issuer_differing_only_by_trailing_slash_is_rejected() {
        // OpenID4VCI L1366: "a simple string comparison with no normalization" --
        // a trailing slash is a mismatch, not a benign variant.
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_issuer = "https://issuer.example.com/".to_string();
        // public_base_url stays "https://issuer.example.com" (no trailing slash).

        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("public_base_url"),
            "expected an identity-mismatch error, got: {err}"
        );
    }

    #[test]
    fn duplicate_resolved_scopes_are_rejected() {
        // HAIP OpenID4VCI L209: "The scope value MUST map to a specific Credential
        // Type." Two types resolving to one scope makes that unsatisfiable.
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types = vec![
            CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/pid".to_string()),
                doctype: None,
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
                validity_seconds: None,
                transaction_data_types: None,
            },
            CredentialType {
                id: "other".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/other".to_string()),
                doctype: None,
                // Collides with the first type's defaulted scope ("pid").
                scope: Some("pid".to_string()),
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
                validity_seconds: None,
                transaction_data_types: None,
            },
        ];
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("scope"),
            "the error must name the scope collision: {err}"
        );
    }

    /// OpenID4VCI L2235 identifies an mdoc by `doctype`. `vct` is an SD-JWT-VC
    /// identifier with no meaning here, and a type carrying both left docType
    /// resolution ambiguous — GAP-VCI-12. The ambiguous state is removed rather
    /// than resolved, which is what lets the Credential Endpoint read `doctype`
    /// with no fallback at all.
    #[test]
    fn vct_on_an_mso_mdoc_credential_type_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types = vec![CredentialType {
            id: "av".to_string(),
            format: "mso_mdoc".to_string(),
            vct: Some("https://issuer.example.com/vct/av".to_string()),
            doctype: Some(crate::config::mdoc::AV_DOCTYPE.to_string()),
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["age_over_18".to_string()],
                required: Some(true),
                selectively_disclosable: false,
                display: vec![],
            }],
            validity_seconds: None,
            transaction_data_types: None,
        }];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("must not set 'vct'"),
            "an mso_mdoc type carrying vct must be rejected: {err}"
        );
    }

    /// The closed attribute set is enforced at load, not merely documented.
    /// Annex A §4.1.2: "A Proof of Age Attestation SHALL NOT include any other
    /// attribute." Without this, an operator's `issuing_country` would be
    /// issued as an mdoc data element the profile forbids.
    #[test]
    fn a_foreign_attribute_on_the_av_doctype_is_rejected_at_load() {
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types = vec![CredentialType {
            id: "av".to_string(),
            format: "mso_mdoc".to_string(),
            vct: None,
            doctype: Some(crate::config::mdoc::AV_DOCTYPE.to_string()),
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![
                ClaimDef {
                    path: vec!["age_over_18".to_string()],
                    required: Some(true),
                    selectively_disclosable: false,
                    display: vec![],
                },
                ClaimDef {
                    path: vec!["issuing_country".to_string()],
                    required: None,
                    selectively_disclosable: false,
                    display: vec![],
                },
            ],
            validity_seconds: None,
            transaction_data_types: None,
        }];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("issuing_country"), "{err}");
    }

    #[test]
    fn distinct_resolved_scopes_are_accepted() {
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types = vec![
            CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/pid".to_string()),
                doctype: None,
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
                validity_seconds: None,
                transaction_data_types: None,
            },
            CredentialType {
                id: "mdl".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/mdl".to_string()),
                doctype: None,
                scope: Some("eu.europa.ec.eudi.pid.1".to_string()),
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
                validity_seconds: None,
                transaction_data_types: None,
            },
        ];
        cfg.validate().unwrap();
    }

    #[test]
    fn an_explicitly_blank_scope_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types = vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/pid".to_string()),
            doctype: None,
            scope: Some("   ".to_string()),
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
            validity_seconds: None,
            transaction_data_types: None,
        }];
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("scope"), "{err}");
    }

    #[test]
    fn resolved_scope_defaults_to_the_id() {
        let ct = CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/pid".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
            validity_seconds: None,
            transaction_data_types: None,
        };
        assert_eq!(ct.resolved_scope(), "pid");
        let with_scope = CredentialType {
            scope: Some("s".to_string()),
            ..ct
        };
        assert_eq!(with_scope.resolved_scope(), "s");
    }

    #[test]
    fn a_zero_dpop_max_age_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.dpop.max_age_secs = 0;
        let err = cfg.validate().expect_err("max_age_secs 0 must be rejected");
        assert!(
            err.to_string().contains("issuer.dpop.max_age_secs"),
            "error must name the offending field, got: {err}"
        );
    }

    #[test]
    fn a_nonzero_dpop_max_age_validates() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.dpop.max_age_secs = 1;
        assert!(cfg.validate().is_ok());
    }

    fn cfg_with_signing_key() -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
        std::fs::write(dir.path().join("key.pem"), km.private_pem).unwrap();
        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "key.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        (cfg, dir)
    }

    /// `config_passing_keyref_check()` plus a second key entry that is not the
    /// verifier's signing key, so it may legally be named as an encryption key.
    ///
    /// It also names a credential signing key explicitly, and must: `req_dec`
    /// sorts before `verifier_signing`, so without one the `keys` fallback
    /// would resolve the *encryption* key as the credential signer and
    /// `Config::validate` would reject the whole fixture. That rejection is
    /// correct -- it is the guard doing its job -- so the fixture is
    /// disambiguated here rather than the guard weakened.
    fn cfg_with_enc_key() -> Config {
        let mut cfg = config_passing_keyref_check();
        cfg.keys.insert(
            "req_dec".to_string(),
            crate::config::model::KeyEntry {
                private_key: "unused-enc.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.keys.insert(
            "cred_signer".to_string(),
            crate::config::model::KeyEntry {
                private_key: "unused-cred.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer.credential_signing_key = Some("cred_signer".to_string());
        cfg
    }

    /// The trap this guards: `Mode`'s own `Default` is `Optional`, so a bare
    /// `#[serde(default)]` on a `Mode` field would silently switch this
    /// feature ON for every deployment that never mentions it.
    #[test]
    fn encrypted_pre_authorized_code_defaults_to_disabled() {
        assert_eq!(
            crate::config::EncryptedPreAuthCodeConfig::default().mode,
            Mode::Disabled
        );
        assert_eq!(
            crate::config::EncryptedPreAuthCodeConfig::default().max_age_secs,
            300
        );
    }

    /// `Default::default()` being right is not enough if serde reaches a
    /// different value for an omitted block.
    #[test]
    fn an_omitted_encrypted_pre_auth_block_deserializes_to_disabled() {
        let cfg: crate::config::EncryptedPreAuthCodeConfig =
            serde_yaml::from_str("{}").expect("an empty block must parse");
        assert_eq!(cfg.mode, Mode::Disabled);
        assert_eq!(cfg.max_age_secs, 300);
    }

    #[test]
    fn encrypted_pre_auth_code_requires_wallet_attestation_to_be_enabled() {
        let mut cfg = cfg_with_enc_key();
        cfg.issuer.encrypted_pre_authorized_code.mode = Mode::Required;
        cfg.issuer.wallet_attestation.mode = Mode::Disabled;
        cfg.issuer.request_encryption = Some(req_enc(vec!["req_dec".to_string()]));

        let err = cfg
            .validate()
            .expect_err("no wallet attestation means no cnf.jwk, so every request would fail");
        assert!(
            format!("{err}").contains("wallet_attestation"),
            "the message must name the field an operator has to change, got: {err}"
        );
    }

    #[test]
    fn encrypted_pre_auth_code_requires_request_encryption_keys() {
        let mut cfg = cfg_with_enc_key();
        cfg.issuer.encrypted_pre_authorized_code.mode = Mode::Optional;
        cfg.issuer.wallet_attestation.mode = Mode::Required;
        cfg.issuer.request_encryption = None;

        let err = cfg
            .validate()
            .expect_err("with no decryption keys the JWE could never be opened");
        assert!(
            format!("{err}").contains("request_encryption"),
            "the message must name the field an operator has to change, got: {err}"
        );
    }

    /// Deliberately legal: `required` here with `optional` wallet attestation
    /// means a wallet presenting no attestation is rejected at the
    /// encrypted-code step rather than at the attestation step. One knob
    /// strengthens another; it does not replace it.
    #[test]
    fn encrypted_pre_auth_code_required_with_optional_wallet_attestation_is_legal() {
        let mut cfg = cfg_with_enc_key();
        cfg.issuer.encrypted_pre_authorized_code.mode = Mode::Required;
        cfg.issuer.wallet_attestation.mode = Mode::Optional;
        cfg.issuer.request_encryption = Some(req_enc(vec!["req_dec".to_string()]));

        cfg.validate()
            .expect("required + optional is a coherent, supported combination");
    }

    /// Disabled must not drag the two preconditions in with it.
    #[test]
    fn disabled_encrypted_pre_auth_code_imposes_no_preconditions() {
        let mut cfg = cfg_with_enc_key();
        cfg.issuer.encrypted_pre_authorized_code.mode = Mode::Disabled;
        cfg.issuer.wallet_attestation.mode = Mode::Disabled;
        cfg.issuer.request_encryption = None;

        cfg.validate()
            .expect("a disabled feature must not constrain unrelated configuration");
    }

    fn req_enc(keys: Vec<String>) -> crate::config::RequestEncryptionConfig {
        crate::config::RequestEncryptionConfig {
            keys,
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: false,
        }
    }

    #[test]
    fn request_encryption_key_must_resolve() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(vec!["nope".to_string()]));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("nope"),
            "message must name the key, got: {msg}"
        );
    }

    #[test]
    fn request_encryption_keys_must_be_non_empty() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(Vec::new()));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("non-empty"), "got: {msg}");
    }

    #[test]
    fn an_encryption_key_may_not_also_be_a_signing_key() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(vec!["verifier_signing".to_string()]));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("verifier_signing") && msg.contains("signing"),
            "got: {msg}"
        );
    }

    /// A `keys` entry for tests that care only about the map's shape.
    fn dummy_key_entry() -> crate::config::model::KeyEntry {
        crate::config::model::KeyEntry {
            private_key: "unused.pem".to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        }
    }

    #[test]
    fn an_explicit_credential_signing_key_wins_over_the_status_list_key() {
        let mut cfg = config_passing_keyref_check();
        cfg.keys
            .insert("issuer_sdjwt".to_string(), dummy_key_entry());
        cfg.keys
            .insert("statuslist_signer".to_string(), dummy_key_entry());
        cfg.issuer.status_list.signing_key = Some("statuslist_signer".to_string());
        cfg.issuer.credential_signing_key = Some("issuer_sdjwt".to_string());
        assert_eq!(cfg.credential_signing_key().unwrap().0, "issuer_sdjwt");
    }

    /// The historical resolution order, retained so that a deployment which
    /// never mentions the new field is not silently re-keyed.
    #[test]
    fn the_credential_signing_key_falls_back_to_the_status_list_key() {
        let mut cfg = config_passing_keyref_check();
        cfg.keys
            .insert("issuer_sdjwt".to_string(), dummy_key_entry());
        cfg.keys
            .insert("statuslist_signer".to_string(), dummy_key_entry());
        cfg.issuer.status_list.signing_key = Some("statuslist_signer".to_string());
        cfg.issuer.credential_signing_key = None;
        assert_eq!(cfg.credential_signing_key().unwrap().0, "statuslist_signer");
    }

    /// `Config.keys` is a `BTreeMap`, so the last-resort fallback is the
    /// **alphabetically** first entry, not the first one written in YAML. Pinned
    /// because the ordering is load-bearing: it is what makes an encryption key
    /// reachable as a credential signer, which
    /// `an_encryption_key_may_not_be_the_resolved_credential_signing_key`
    /// then rejects.
    #[test]
    fn the_credential_signing_key_falls_back_to_the_alphabetically_first_key() {
        let mut cfg = config_passing_keyref_check();
        cfg.keys
            .insert("zzz_written_first".to_string(), dummy_key_entry());
        cfg.keys
            .insert("aaa_written_last".to_string(), dummy_key_entry());
        cfg.issuer.status_list.signing_key = None;
        cfg.issuer.credential_signing_key = None;
        assert_eq!(cfg.credential_signing_key().unwrap().0, "aaa_written_last");
    }

    #[test]
    fn an_unknown_credential_signing_key_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_signing_key = Some("no_such_key".to_string());
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("issuer.credential_signing_key") && msg.contains("no_such_key"),
            "got: {msg}"
        );
    }

    /// The fallback hole: with neither `issuer.credential_signing_key` nor
    /// `issuer.status_list.signing_key` set, the alphabetically first key wins
    /// -- and an ECDH-ES Credential-Request decryption key can be it. Signing
    /// credentials with a key-agreement key (and, since such a key needs no
    /// certificate, with no `x5c` at all) must be a startup failure, not a
    /// silent choice. The pre-existing guard compared against the two *named*
    /// signing-key fields and so could not see this path.
    #[test]
    fn an_encryption_key_may_not_be_the_resolved_credential_signing_key() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.keys
            .insert("aaa_request_enc".to_string(), dummy_key_entry());
        cfg.issuer.request_encryption = Some(req_enc(vec!["aaa_request_enc".to_string()]));
        cfg.issuer.status_list.signing_key = None;
        cfg.issuer.credential_signing_key = None;
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("aaa_request_enc") && msg.contains("credential signing key"),
            "got: {msg}"
        );
    }

    /// The same guard must not fire when an explicit credential signing key
    /// steers resolution away from the encryption key.
    #[test]
    fn an_explicit_credential_signing_key_clears_the_encryption_key_conflict() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.keys
            .insert("aaa_request_enc".to_string(), dummy_key_entry());
        cfg.keys
            .insert("issuer_sdjwt".to_string(), dummy_key_entry());
        cfg.issuer.request_encryption = Some(req_enc(vec!["aaa_request_enc".to_string()]));
        cfg.issuer.credential_signing_key = Some("issuer_sdjwt".to_string());
        cfg.validate()
            .expect("an explicit credential signing key resolves away from the encryption key");
    }

    #[test]
    fn required_response_encryption_needs_request_encryption() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.response_encryption = Some(crate::config::ResponseEncryptionConfig {
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: true,
        });
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("request_encryption"), "got: {msg}");
    }

    #[test]
    fn advertised_enc_values_must_be_supported() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.response_encryption = Some(crate::config::ResponseEncryptionConfig {
            enc_values_supported: vec!["A192GCM".to_string()],
            encryption_required: false,
        });
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("A192GCM"), "got: {msg}");
    }

    #[test]
    fn loads_request_decryption_keys_and_derives_distinct_kids() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = minimal_config();
        for name in ["enc_a", "enc_b"] {
            let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
            std::fs::write(dir.path().join(format!("{name}.pem")), km.private_pem).unwrap();
            cfg.keys.insert(
                name.to_string(),
                crate::config::model::KeyEntry {
                    private_key: format!("{name}.pem"),
                    x5c: None,
                    alg: "ES256".to_string(),
                },
            );
        }
        cfg.issuer.request_encryption =
            Some(req_enc(vec!["enc_a".to_string(), "enc_b".to_string()]));
        let keys = cfg.load_request_decryption_keys(dir.path()).unwrap();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0].kid(), keys[1].kid());
    }

    #[test]
    fn loads_no_keys_when_the_feature_is_off() {
        let cfg = minimal_config();
        assert!(
            cfg.load_request_decryption_keys(std::path::Path::new("."))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn encryption_blocks_default_to_both_gcm_sizes_and_optional() {
        let yaml = "server:\n  wallet_facing:\n    public_base_url: https://example.test\n    bind: 127.0.0.1:8080\n  admin:\n    bind: 127.0.0.1:8081\nstorage:\n  path: ./t.db\nissuer:\n  credential_issuer: https://example.test\n  status_list:\n    enabled: false\n  request_encryption:\n    keys: [k]\n  response_encryption: {}\nverifier:\n  signing_key: verifier-key\n";
        let cfg: Config = serde_yaml::from_str(yaml).expect("config should parse");
        let re = cfg.issuer.request_encryption.as_ref().unwrap();
        assert_eq!(re.enc_values_supported, vec!["A128GCM", "A256GCM"]);
        assert!(!re.encryption_required);
        let rs = cfg.issuer.response_encryption.as_ref().unwrap();
        assert_eq!(rs.enc_values_supported, vec!["A128GCM", "A256GCM"]);
        assert!(!rs.encryption_required);
    }

    #[test]
    fn android_keystore_attestation_requires_trust_anchors() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.key_attestation.android.mode = Mode::Optional;
        cfg.issuer.key_attestation.trusted_anchors = Vec::new();
        let err = cfg
            .validate()
            .expect_err("enabling the proof type with no anchors must fail at load time");
        let msg = err.to_string();
        assert!(
            msg.contains("android") && msg.contains("trusted_anchors"),
            "the message must name both fields, got: {msg}"
        );
    }

    #[test]
    fn android_keystore_attestation_disabled_needs_no_anchors() {
        let cfg = config_passing_keyref_check();
        assert_eq!(
            cfg.issuer.key_attestation.android.mode,
            Mode::Disabled,
            "the default must be Disabled so no deployment changes behaviour on upgrade"
        );
        cfg.validate()
            .expect("the default configuration stays valid");
    }

    #[test]
    fn android_key_mint_security_level_defaults_to_trusted_environment() {
        let cfg = minimal_config();
        assert_eq!(
            cfg.issuer.key_attestation.android.key_mint_security_level,
            crate::trust::android_attestation::SecurityLevel::TrustedEnvironment
        );
    }

    /// A `dc+sd-jwt` credential type with whatever claims the caller supplies.
    /// `minimal_config()` ships no credential types, so validation tests that
    /// need one construct it here rather than indexing an empty vec.
    fn sd_jwt_type(claims: Vec<ClaimDef>, validity_seconds: Option<u64>) -> CredentialType {
        CredentialType {
            id: "dpc".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("com.emvco.dpc.card".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims,
            validity_seconds,
            transaction_data_types: None,
        }
    }

    /// A credential whose `exp` equals its `iat` is never usable — that is a
    /// configuration error, not a policy choice.
    #[test]
    fn validity_seconds_may_not_be_zero() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.credential_types = vec![sd_jwt_type(vec![], Some(0))];
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("validity_seconds"),
            "error must name the offending field, got: {msg}"
        );
    }

    /// A non-zero lifetime must still pass, so the check is narrow.
    #[test]
    fn a_nonzero_validity_seconds_passes() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.credential_types = vec![sd_jwt_type(vec![], Some(43_200))];
        cfg.validate().expect("a 12-hour lifetime is valid");
    }

    // ---- status-list signer divergence (draft-ietf-oauth-status-list-14 §11.3)
    //
    // A Status List Token signed by a key other than the credential signing key
    // is spec-legal but unverifiable in the Credo / `@sd-jwt` wallet stack. The
    // warning is advisory, so these tests assert the *predicate*, not log output
    // -- a tracing subscriber in a unit test would be testing tracing, not this.

    /// Two named keys with distinct PEMs, both resolvable; status lists on.
    fn cfg_with_two_signers(
        credential_signing_key: Option<&str>,
        status_list_signing_key: Option<&str>,
        status_list_enabled: bool,
    ) -> Config {
        let mut cfg = config_passing_keyref_check();
        cfg.keys.insert(
            "issuer_sdjwt".to_string(),
            crate::config::model::KeyEntry {
                private_key: "issuer_sdjwt.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.keys.insert(
            "statuslist_signer".to_string(),
            crate::config::model::KeyEntry {
                private_key: "statuslist_signer.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer.credential_signing_key = credential_signing_key.map(str::to_string);
        cfg.issuer.status_list.enabled = status_list_enabled;
        cfg.issuer.status_list.signing_key = status_list_signing_key.map(str::to_string);
        cfg
    }

    #[test]
    fn status_list_signer_divergence_reported_when_signer_differs() {
        let cfg = cfg_with_two_signers(Some("issuer_sdjwt"), Some("statuslist_signer"), true);
        let warning = cfg
            .status_list_signer_divergence()
            .expect("a status-list signer that is not the credential signer must be reported");
        assert!(
            warning.contains("statuslist_signer") && warning.contains("issuer_sdjwt"),
            "warning must name both keys so it is actionable, got: {warning}"
        );
    }

    #[test]
    fn status_list_signer_divergence_is_a_warning_not_a_rejection() {
        // draft-ietf-oauth-status-list-14 §13.5 permits a separate Status Issuer,
        // so this configuration must still boot.
        cfg_with_two_signers(Some("issuer_sdjwt"), Some("statuslist_signer"), true)
            .validate()
            .expect("a divergent status-list signer must not fail startup");
    }

    #[test]
    fn status_list_signer_divergence_silent_when_one_key_signs_both() {
        let cfg = cfg_with_two_signers(Some("issuer_sdjwt"), Some("issuer_sdjwt"), true);
        assert!(
            cfg.status_list_signer_divergence().is_none(),
            "one key naming both roles is the interoperable case"
        );
    }

    #[test]
    fn status_list_signer_divergence_silent_when_two_names_share_one_pem() {
        // A wallet verifies with a *key*, not a config label. Two names for one
        // PEM is confusing config but not an interop failure, so it must not warn.
        let mut cfg = cfg_with_two_signers(Some("issuer_sdjwt"), Some("statuslist_signer"), true);
        cfg.keys
            .get_mut("statuslist_signer")
            .expect("fixture inserts it")
            .private_key = "issuer_sdjwt.pem".to_string();
        assert!(
            cfg.status_list_signer_divergence().is_none(),
            "two labels for the same private key must not warn"
        );
    }

    #[test]
    fn status_list_signer_divergence_silent_when_status_lists_disabled() {
        let cfg = cfg_with_two_signers(Some("issuer_sdjwt"), Some("statuslist_signer"), false);
        assert!(
            cfg.status_list_signer_divergence().is_none(),
            "no Status List Token is ever served, so there is nothing to warn about"
        );
    }

    #[test]
    fn status_list_signer_divergence_silent_when_status_list_names_no_key() {
        // Enabled with no signing_key is a different defect: the route fails at
        // request time. Not this warning's business.
        let cfg = cfg_with_two_signers(Some("issuer_sdjwt"), None, true);
        assert!(
            cfg.status_list_signer_divergence().is_none(),
            "an unset status_list.signing_key is a separate misconfiguration"
        );
    }

    /// An empty claims path pointer addresses nothing, so no supplied value can
    /// ever satisfy it. Catching it at startup beats failing per offer.
    /// Closes the emptiness half of GAP-VCI-13.
    #[test]
    fn claim_path_may_not_be_empty() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.credential_types = vec![sd_jwt_type(
            vec![ClaimDef {
                path: vec![],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
            None,
        )];
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("path"),
            "error must name the offending field, got: {msg}"
        );
    }
}
