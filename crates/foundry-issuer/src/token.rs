//! Token request handling for OpenID4VCI pre-authorized code and
//! authorization_code flows.

use crate::attestation::{DefaultAttestationVerifier, WalletAttestationVerifier, claim_pop_jti};
use crate::dpop::{DpopPresentation, claim_dpop_jti, verify_dpop_proof};
use crate::encrypted_pre_auth::resolve_encrypted_pre_authorized_code;
use crate::error::IssuanceError;
use crate::transaction::{
    IssuanceState, IssuanceTransaction, invalidate_authorization_code,
    invalidate_pre_authorized_code, load_transaction_by_authorization_code,
    load_transaction_by_pre_auth_code, save_transaction_with_indices,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use foundry_core::config::{AttestationMode, DpopConfig, EncryptedPreAuthCodeConfig, Mode};
use foundry_core::crypto::jwe::DecryptionKey;
use foundry_core::storage::Storage;
use foundry_core::trust::TrustStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    pub tx_code: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    /// Google Wallet's `encrypted_pre-authorized_code` extension: the
    /// pre-authorized code as a JWS nested inside a JWE, replacing the
    /// plaintext `pre-authorized_code` above.
    ///
    /// **Vendor profile only** (root `AGENTS.md` §4.4); see
    /// [`crate::encrypted_pre_auth`]. The serde rename is the canonical
    /// spelling from the profile's prose — its worked example says
    /// `encrypted_pre-authorization_code`, which is not accepted.
    #[serde(rename = "encrypted_pre-authorized_code", default)]
    pub encrypted_pre_authorized_code: Option<String>,
}

/// Everything [`handle_token_request`] needs to resolve an
/// `encrypted_pre-authorized_code`. Grouped rather than passed as four loose
/// parameters, following `DpopPresentation`/`DpopNoncePolicy`.
pub struct EncryptedCodePolicy<'a> {
    pub cfg: &'a EncryptedPreAuthCodeConfig,
    /// The issuer's `credential_request_encryption` private keys — the profile
    /// reuses them verbatim ("the same key used to encrypt the request to the
    /// Credential Endpoint"). Empty when the mechanism is unconfigured, which
    /// `Config::validate()` already forbids alongside a non-disabled mode.
    pub decryption_keys: &'a [DecryptionKey],
    pub allowed_enc: &'a [String],
    /// The absolute Token Endpoint URL the inner JWS's `aud` must equal.
    /// Deliberately not the AS issuer identifier — see
    /// `encrypted_pre_auth::validate_claims`.
    pub token_endpoint: &'a str,
}

/// Token Response (OpenID4VCI 1.0 Section 6.2).
///
/// Deliberately carries no `c_nonce`: the final specification moved challenge
/// issuance to the Nonce Endpoint (Section 7), so a wallet obtains its
/// challenge from `POST /nonce` and never from here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    /// `"Bearer"`, or `"DPoP"` when the access token is sender-constrained to
    /// an RFC 9449 DPoP key (issuer.dpop.mode `optional`/`required` and a
    /// valid proof was presented). §5: this is the client's signal to attach
    /// a DPoP proof, not a Bearer credential, on every subsequent request.
    pub token_type: String,
    pub expires_in: u64,
}

/// `skip_all` is mandatory: `req` carries the pre-authorized code, the
/// authorization code and the transaction code, none of which may ever be
/// logged; `wallet_attestation` carries the issuer's trusted Wallet-Provider
/// CAs, `attestation_header` carries the wallet's raw attestation JWT, and
/// `pop_header` carries the raw Client Attestation PoP JWT (GAP-VCI-14) --
/// none of these may ever be logged either.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(grant_type = %req.grant_type))]
pub async fn handle_token_request(
    storage: &dyn Storage,
    req: &TokenRequest,
    wallet_attestation: &AttestationMode,
    attestation_header: Option<&str>,
    pop_header: Option<&str>,
    dpop_cfg: &DpopConfig,
    dpop: &DpopPresentation<'_>,
    nonce_secret: &crate::challenge::NonceSecret,
    issuer_identifier: &str,
    now_unix: i64,
    encrypted_code: &EncryptedCodePolicy<'_>,
    access_token_ttl_secs: u64,
) -> Result<TokenResponse, IssuanceError> {
    tracing::info!(
        wallet_attestation_mode = ?wallet_attestation.mode,
        wallet_attestation_present = attestation_header.is_some(),
        pop_present = pop_header.is_some(),
        "token request received"
    );
    let verifier = DefaultAttestationVerifier;
    let trust_store = TrustStore::from_config(&wallet_attestation.trusted_anchors)?;
    let pop_claims = verifier
        .verify_wallet_attestation(
            wallet_attestation.mode.clone(),
            attestation_header,
            pop_header,
            &trust_store,
            issuer_identifier,
            now_unix,
            wallet_attestation.pop_max_age_secs,
            wallet_attestation.challenge_mode.clone(),
            nonce_secret,
        )
        .inspect_err(|e| {
            tracing::warn!(error.kind = e.kind(), "wallet attestation rejected");
        })?;

    if let Some(claims) = pop_claims.as_ref() {
        // Anti-replay claim happens before any grant work: a replayed PoP
        // must never get the chance to burn a legitimate holder's code.
        claim_pop_jti(storage, claims, wallet_attestation.pop_max_age_secs)
            .await
            .inspect_err(|e| {
                tracing::warn!(error.kind = e.kind(), "client attestation pop jti rejected");
            })?;

        // ABCA §6.3: if client_id is present, it MUST equal the attestation's
        // sub *and* the PoP's iss. validate_client_attestation_pop_jwt's
        // check 5 already proved those two equal, so claims.iss *is* that
        // shared value -- one comparison here mechanically covers both
        // named requirements.
        if let Some(client_id) = &req.client_id
            && client_id != &claims.iss
        {
            return Err(IssuanceError::InvalidClient(
                "client_id does not match the wallet attestation/client attestation pop".into(),
            ));
        }
    }

    // RFC 9449 §5: resolve the DPoP key this token will be bound to, if any.
    //
    // Deliberately before any grant work — like `claim_pop_jti` above — so a
    // replayed or forged proof can never burn a legitimate holder's
    // pre-authorized or authorization code.
    let dpop_jkt = match (&dpop_cfg.mode, dpop.proof_jwt) {
        // §5: "An authorization server MAY elect to issue access tokens that
        // are not DPoP bound." Disabled ignores the header rather than
        // rejecting it — §10.1 encourages clients that attach it to every AS
        // call, and §5 already gives us `token_type: Bearer` to signal
        // non-binding.
        (Mode::Disabled, _) => None,
        (Mode::Optional, None) => None,
        // §5.2 (`dpop_bound_access_tokens: true`): "the authorization server
        // MUST reject token requests from the client that do not contain the
        // DPoP header."
        (Mode::Required, None) => {
            return Err(IssuanceError::InvalidDpopProof(
                "a DPoP proof is required at this Token Endpoint".into(),
            ));
        }
        (Mode::Optional | Mode::Required, Some(proof_jwt)) => {
            let nonce_policy = crate::dpop::DpopNoncePolicy {
                mode: dpop_cfg.nonce_mode.clone(),
                secret: nonce_secret,
            };
            let verified = verify_dpop_proof(
                proof_jwt,
                dpop.htm,
                dpop.htu,
                // §4.3 check 12 does not apply at the Token Endpoint: no
                // access token is being presented.
                None,
                now_unix,
                dpop_cfg.max_age_secs,
                Some(&nonce_policy),
            )
            .inspect_err(|e| {
                tracing::warn!(error.kind = e.kind(), "dpop proof rejected");
            })?;
            // §11.1 single-use.
            claim_dpop_jti(storage, &verified, dpop_cfg.max_age_secs, now_unix).await?;
            // A thumbprint, so loggable per root AGENTS.md §4.5.
            tracing::info!(jkt = %verified.jkt, "dpop proof accepted");
            Some(verified.jkt)
        }
    };

    match req.grant_type.as_str() {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
            handle_pre_authorized_code_grant(
                storage,
                req,
                dpop_jkt,
                encrypted_code,
                pop_claims.as_ref(),
                access_token_ttl_secs,
                now_unix,
            )
            .await
        }
        "authorization_code" => {
            handle_authorization_code_grant(storage, req, dpop_jkt, access_token_ttl_secs, now_unix)
                .await
        }
        _ => Err(IssuanceError::InvalidGrant(
            "unsupported_grant_type".to_string(),
        )),
    }
}

/// Resolve the pre-authorized code from whichever form the configured mode
/// permits.
///
/// **Vendor profile only** (root `AGENTS.md` §4.4): the encrypted form is
/// defined solely by the Google Wallet VCI 1.0 Profile, §"token request field
/// signing & encryption". Scoped to this grant deliberately — the profile
/// defines the extension only for the pre-authorized code flow, so the
/// authorization_code grant must not silently inherit half of it.
///
/// `skip_all` is mandatory: `req` carries both code forms.
#[tracing::instrument(skip_all, fields(mode = ?encrypted_code.cfg.mode))]
async fn resolve_code(
    storage: &dyn Storage,
    req: &TokenRequest,
    encrypted_code: &EncryptedCodePolicy<'_>,
    pop_claims: Option<&crate::attestation::PopClaims>,
    now_unix: i64,
) -> Result<String, IssuanceError> {
    let plaintext = req.pre_authorized_code.as_deref();
    let envelope = req.encrypted_pre_authorized_code.as_deref();

    match (&encrypted_code.cfg.mode, plaintext, envelope) {
        // Disabled: the member is REJECTED, never ignored. Silently falling
        // back to the plaintext form would be exactly the downgrade the
        // extension exists to prevent.
        (Mode::Disabled, _, Some(_)) => Err(IssuanceError::InvalidRequest(
            "encrypted_pre-authorized_code is not enabled at this Token Endpoint".into(),
        )),
        (Mode::Disabled, Some(code), None) => Ok(code.to_string()),
        (Mode::Disabled, None, None) => Err(IssuanceError::InvalidGrant(
            "missing pre-authorized_code".to_string(),
        )),

        // Optional: exactly one. Both present is a client bug, and picking a
        // winner would hide it.
        (Mode::Optional, Some(_), Some(_)) => Err(IssuanceError::InvalidRequest(
            "exactly one of pre-authorized_code and encrypted_pre-authorized_code may be \
             present"
                .into(),
        )),
        (Mode::Optional, Some(code), None) => Ok(code.to_string()),
        (Mode::Optional, None, None) => Err(IssuanceError::InvalidGrant(
            "missing pre-authorized_code".to_string(),
        )),

        // Required: the anti-downgrade rule, structurally identical to RFC 9449
        // §7.2's rejection of a DPoP-bound token presented as Bearer. Without
        // it `required` would be advisory.
        (Mode::Required, Some(_), None) => Err(IssuanceError::InvalidRequest(
            "this Token Endpoint requires encrypted_pre-authorized_code; a plaintext \
             pre-authorized_code is not accepted"
                .into(),
        )),
        (Mode::Required, None, None) => Err(IssuanceError::InvalidRequest(
            "encrypted_pre-authorized_code is required at this Token Endpoint".into(),
        )),

        (Mode::Optional | Mode::Required, _, Some(env)) => {
            // The profile's step 5 needs the Client Attestation's cnf.jwk. With
            // no verified attestation there is none, so the request cannot be
            // authenticated -- `Config::validate()` forbids the *configuration*
            // that makes this universal, leaving only the per-request case of a
            // wallet that sent no attestation under `wallet_attestation.mode:
            // optional`.
            let claims = pop_claims.ok_or_else(|| {
                IssuanceError::InvalidClient(
                    "encrypted_pre-authorized_code requires a verified wallet attestation: \
                     its inner JWS is signed by the attestation's cnf.jwk"
                        .into(),
                )
            })?;

            resolve_encrypted_pre_authorized_code(
                storage,
                env,
                encrypted_code.decryption_keys,
                encrypted_code.allowed_enc,
                &claims.cnf_jwk,
                &claims.iss,
                encrypted_code.token_endpoint,
                now_unix,
                encrypted_code.cfg.max_age_secs,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_pre_authorized_code_grant(
    storage: &dyn Storage,
    req: &TokenRequest,
    dpop_jkt: Option<String>,
    encrypted_code: &EncryptedCodePolicy<'_>,
    pop_claims: Option<&crate::attestation::PopClaims>,
    access_token_ttl_secs: u64,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    // Runs before `load_transaction_by_pre_auth_code`, so a rejected envelope
    // can never reach the transaction lookup -- the same anti-code-burning
    // ordering `claim_pop_jti` and the DPoP check already establish above.
    let code = &resolve_code(storage, req, encrypted_code, pop_claims, now_unix).await?;

    let tx = load_transaction_by_pre_auth_code(storage, code)
        .await?
        .ok_or_else(|| {
            IssuanceError::InvalidGrant("invalid or expired pre-authorized_code".to_string())
        })?;

    if tx.state == IssuanceState::Issued {
        return Err(IssuanceError::InvalidGrant(
            "credential offer has already been claimed".to_string(),
        ));
    }

    if let Some(ref expected_tx_code) = tx.tx_code {
        match req.tx_code.as_deref() {
            Some(supplied) if supplied == expected_tx_code => {}
            _ => return Err(IssuanceError::InvalidGrant("invalid tx_code".to_string())),
        }
    }

    // RFC 9449 §10: "the authorization server computes the JWK Thumbprint of
    // the proof-of-possession public key in the DPoP proof and verifies that
    // it matches the dpop_jkt parameter value in the authorization request. If
    // they do not match, it MUST reject the request."
    //
    // Checked before the code is invalidated so a wrong-key attempt cannot
    // burn the legitimate holder's code (§11.9 is the attack this closes).
    if let Some(pinned) = &tx.dpop_jkt
        && dpop_jkt.as_deref() != Some(pinned.as_str())
    {
        return Err(IssuanceError::InvalidDpopProof(
            "the DPoP proof key does not match the dpop_jkt pinned at the \
                 Authorization Endpoint"
                .into(),
        ));
    }

    // OpenID4VCI 1.0 Credential Offer (L396): `pre-authorized_code` MUST be
    // short-lived and single use. Burn only after full validation passes: an
    // attacker probing with a wrong tx_code must not be able to destroy the
    // legitimate holder's code (mirrors the authorization_code branch below).
    invalidate_pre_authorized_code(storage, code).await?;

    let mut tx = tx;
    tx.pre_authorized_code = None;

    mint_and_save_tokens(storage, tx, dpop_jkt, access_token_ttl_secs, now_unix).await
}

/// RFC 7636 §4.6: `code_challenge == BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`.
/// The issuer only ever stores `code_challenge_method: "S256"` (enforced at
/// `/authorize` time), so this is the only comparison needed here.
fn code_verifier_matches(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == code_challenge
}

async fn handle_authorization_code_grant(
    storage: &dyn Storage,
    req: &TokenRequest,
    dpop_jkt: Option<String>,
    access_token_ttl_secs: u64,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let code = req
        .code
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing code".to_string()))?;

    let tx = load_transaction_by_authorization_code(storage, code)
        .await?
        .ok_or_else(|| IssuanceError::InvalidGrant("invalid or expired code".to_string()))?;

    if tx.state == IssuanceState::Issued {
        return Err(IssuanceError::InvalidGrant(
            "credential offer has already been claimed".to_string(),
        ));
    }

    if req.redirect_uri.as_deref() != tx.redirect_uri.as_deref() {
        return Err(IssuanceError::InvalidGrant(
            "redirect_uri does not match the authorization request".to_string(),
        ));
    }

    let code_challenge = tx
        .code_challenge
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing code_challenge".to_string()))?;
    let code_verifier = req
        .code_verifier
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing code_verifier".to_string()))?;
    if !code_verifier_matches(code_verifier, code_challenge) {
        return Err(IssuanceError::InvalidGrant(
            "code_verifier does not match code_challenge".to_string(),
        ));
    }

    // RFC 9449 §10 pin check -- see the identical comment in
    // handle_pre_authorized_code_grant. Checked before the code is
    // invalidated for the same anti-burn reason.
    if let Some(pinned) = &tx.dpop_jkt
        && dpop_jkt.as_deref() != Some(pinned.as_str())
    {
        return Err(IssuanceError::InvalidDpopProof(
            "the DPoP proof key does not match the dpop_jkt pinned at the \
                 Authorization Endpoint"
                .into(),
        ));
    }

    // Only invalidate the code once it has fully passed validation: an
    // attacker probing with a wrong code_verifier must not be able to burn
    // the legitimate holder's code.
    invalidate_authorization_code(storage, code).await?;

    let mut tx = tx;
    tx.authorization_code = None;

    mint_and_save_tokens(storage, tx, dpop_jkt, access_token_ttl_secs, now_unix).await
}

/// Shared by both grant branches: mint a fresh access_token, persist it on
/// `tx`, and return the wire `TokenResponse`.
///
/// `dpop_jkt` is `Some` when a valid RFC 9449 DPoP proof accompanied the
/// request. It is recorded on the transaction (§6's "other methods of
/// associating a public key with an access token ... per an agreement by the
/// authorization server and the protected resource" — here that agreement is
/// internal, since both are this process sharing one `Storage`) and it selects
/// the `token_type` (§5).
async fn mint_and_save_tokens(
    storage: &dyn Storage,
    mut tx: IssuanceTransaction,
    dpop_jkt: Option<String>,
    access_token_ttl_secs: u64,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let access_token = format!("at_{}", Uuid::new_v4().simple());
    // One value drives both the wire `expires_in` and the transaction row's
    // TTL: the row must outlive the token that addresses it, and equal
    // lifetimes is the tightest correct choice.
    let expires_in = access_token_ttl_secs;

    tx.access_token = Some(access_token.clone());
    // §6: the binding the Credential Endpoint will check. Overwrites any §10
    // pin with the same value — the caller has already proved them equal.
    tx.dpop_jkt = dpop_jkt.clone();

    save_transaction_with_indices(storage, &tx, expires_in, now_unix).await?;

    Ok(TokenResponse {
        access_token,
        // RFC 9449 §5: "A token_type of DPoP MUST be included in the access
        // token response to signal to the client that the access token was
        // bound to its DPoP key."
        token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_string(),
        expires_in,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{IssuanceState, IssuanceTransaction, load_transaction};
    use foundry_core::config::Mode;
    use foundry_core::storage::SqliteStorage;

    /// `Mode::Disabled`, wrapped in the `AttestationMode` `handle_token_request`
    /// now takes. Keeps the 15+ call sites below that don't exercise wallet
    /// attestation readable.
    fn disabled() -> AttestationMode {
        AttestationMode {
            mode: Mode::Disabled,
            trusted_anchors: Vec::new(),
            pop_max_age_secs: 300,
            challenge_mode: Mode::Disabled,
            android: Default::default(),
        }
    }

    fn dpop_cfg(mode: Mode) -> DpopConfig {
        DpopConfig {
            mode,
            max_age_secs: 300,
            nonce_mode: Mode::Disabled,
        }
    }

    /// A `NonceSecret` for the many call sites here that don't exercise the
    /// ABCA challenge or DPoP nonce mechanisms -- every fixture in this module
    /// sets `challenge_mode`/`nonce_mode` to `Disabled`, so the secret's value
    /// is never actually consulted.
    fn test_nonce_secret() -> crate::challenge::NonceSecret {
        crate::challenge::NonceSecret::from_bytes([99u8; 32])
    }

    const TOKEN_HTU: &str = "https://issuer.example.com/token";

    /// The extension switched off -- what every pre-existing test in this
    /// module exercises, and what a default deployment does.
    static DISABLED_EPAC: std::sync::LazyLock<EncryptedPreAuthCodeConfig> =
        std::sync::LazyLock::new(EncryptedPreAuthCodeConfig::default);

    fn no_encrypted_code() -> EncryptedCodePolicy<'static> {
        EncryptedCodePolicy {
            cfg: &DISABLED_EPAC,
            decryption_keys: &[],
            allowed_enc: &[],
            token_endpoint: TOKEN_HTU,
        }
    }

    fn encrypted_policy_cfg(mode: Mode) -> EncryptedPreAuthCodeConfig {
        EncryptedPreAuthCodeConfig {
            mode,
            max_age_secs: 300,
        }
    }

    /// Drives `handle_token_request` with wallet attestation and DPoP both
    /// disabled, so the tests below isolate the encrypted-code mode matrix.
    async fn call_token_with_ttl(
        storage: &dyn Storage,
        req: &TokenRequest,
        encrypted_cfg: &EncryptedPreAuthCodeConfig,
        keys: &[DecryptionKey],
        now: i64,
        ttl: u64,
    ) -> Result<TokenResponse, IssuanceError> {
        let enc_values = vec!["A128GCM".to_string()];
        let policy = EncryptedCodePolicy {
            cfg: encrypted_cfg,
            decryption_keys: keys,
            allowed_enc: &enc_values,
            token_endpoint: TOKEN_HTU,
        };
        handle_token_request(
            storage,
            req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Disabled),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &policy,
            ttl,
        )
        .await
    }

    async fn call_token(
        storage: &dyn Storage,
        req: &TokenRequest,
        encrypted_cfg: &EncryptedPreAuthCodeConfig,
        keys: &[DecryptionKey],
        now: i64,
    ) -> Result<TokenResponse, IssuanceError> {
        call_token_with_ttl(storage, req, encrypted_cfg, keys, now, 600).await
    }

    /// `disabled` REJECTS the member rather than ignoring it. Silently falling
    /// back to the plaintext parameter would be the downgrade the extension
    /// exists to prevent.
    #[tokio::test]
    async fn disabled_mode_rejects_a_present_encrypted_member() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-disabled");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut req = pre_auth_req();
        req.encrypted_pre_authorized_code = Some("eyJ.irrelevant.value".to_string());

        let err = call_token(
            &storage,
            &req,
            &encrypted_policy_cfg(Mode::Disabled),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("a disabled feature must reject the member, not ignore it");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// An attacker probing with a bogus envelope must not be able to burn a
    /// legitimate holder's code. The same property already tested for tx_code
    /// and code_verifier -- this is its third instance.
    #[tokio::test]
    async fn a_rejected_envelope_does_not_burn_the_pre_authorized_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-noburn");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut req = pre_auth_req();
        req.pre_authorized_code = None;
        req.encrypted_pre_authorized_code = Some("not.a.real.envelope".to_string());

        let _ = call_token(
            &storage,
            &req,
            &encrypted_policy_cfg(Mode::Required),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("a malformed envelope must be rejected");

        assert!(
            load_transaction_by_pre_auth_code(&storage, "code-123")
                .await
                .unwrap()
                .is_some(),
            "a rejected envelope must leave the pre-authorized code redeemable"
        );
    }

    /// `required` rejects the plaintext parameter -- the anti-downgrade rule.
    #[tokio::test]
    async fn required_mode_rejects_a_plaintext_pre_authorized_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-required");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let err = call_token(
            &storage,
            &pre_auth_req(),
            &encrypted_policy_cfg(Mode::Required),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("required mode must not accept a plaintext code");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn required_mode_rejects_a_request_with_neither_form() {
        let storage = test_storage().await;
        let mut req = pre_auth_req();
        req.pre_authorized_code = None;

        let err = call_token(
            &storage,
            &req,
            &encrypted_policy_cfg(Mode::Required),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("required mode with nothing present must be rejected");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// `optional` keeps the plaintext path working -- the migration rung.
    #[tokio::test]
    async fn optional_mode_still_accepts_a_plaintext_pre_authorized_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-optional");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let res = call_token(
            &storage,
            &pre_auth_req(),
            &encrypted_policy_cfg(Mode::Optional),
            &[],
            1_700_000_000,
        )
        .await
        .expect("optional mode must keep the plaintext path working");
        assert!(!res.access_token.is_empty());
    }

    /// BOTH present is a rejection, not a precedence decision. Two codes in one
    /// request is a client bug; picking a winner hides it.
    #[tokio::test]
    async fn optional_mode_rejects_a_request_carrying_both_forms() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-both");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let mut req = pre_auth_req();
        req.encrypted_pre_authorized_code = Some("eyJ.some.envelope".to_string());

        let err = call_token(
            &storage,
            &req,
            &encrypted_policy_cfg(Mode::Optional),
            &[],
            1_700_000_000,
        )
        .await
        .expect_err("exactly one of the two forms must be present");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// The remaining cheap cells of the mode matrix. Each is a configuration a
    /// real deployment can be in, so each gets its own assertion even where
    /// several share an expected outcome.
    #[tokio::test]
    async fn the_remaining_mode_matrix_cells_reject() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-epac-matrix");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        // disabled + envelope only (no plaintext to fall back to)
        let mut req = pre_auth_req();
        req.pre_authorized_code = None;
        req.encrypted_pre_authorized_code = Some("eyJ.env.value".to_string());
        assert!(matches!(
            call_token(
                &storage,
                &req,
                &encrypted_policy_cfg(Mode::Disabled),
                &[],
                1_700_000_000
            )
            .await
            .expect_err("disabled must reject the member even with no plaintext present"),
            IssuanceError::InvalidRequest(_)
        ));

        // disabled + neither -- the pre-existing "missing code" behaviour,
        // which the extension must not have changed.
        let mut req = pre_auth_req();
        req.pre_authorized_code = None;
        assert!(matches!(
            call_token(
                &storage,
                &req,
                &encrypted_policy_cfg(Mode::Disabled),
                &[],
                1_700_000_000
            )
            .await
            .expect_err("a request with no code at all is still invalid_grant"),
            IssuanceError::InvalidGrant(_)
        ));

        // optional + neither -- same, under the migration rung.
        let mut req = pre_auth_req();
        req.pre_authorized_code = None;
        assert!(matches!(
            call_token(
                &storage,
                &req,
                &encrypted_policy_cfg(Mode::Optional),
                &[],
                1_700_000_000
            )
            .await
            .expect_err("optional with neither form is still invalid_grant"),
            IssuanceError::InvalidGrant(_)
        ));

        // required + both -- the envelope is attempted (the plaintext is
        // ignored under required), so this fails on the envelope, not on
        // arity. Asserted only as "rejected": the precise variant is the
        // envelope resolver's business, covered by its own tests.
        let mut req = pre_auth_req();
        req.encrypted_pre_authorized_code = Some("not.an.envelope".to_string());
        assert!(
            call_token(
                &storage,
                &req,
                &encrypted_policy_cfg(Mode::Required),
                &[],
                1_700_000_000
            )
            .await
            .is_err(),
            "required with both forms must not succeed on the plaintext"
        );

        // The transaction survived every one of those rejections.
        assert!(
            load_transaction_by_pre_auth_code(&storage, "code-123")
                .await
                .unwrap()
                .is_some(),
            "no rejected request may burn the pre-authorized code"
        );
    }

    #[tokio::test]
    async fn expires_in_reflects_the_configured_access_token_ttl() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-ttl");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let res = call_token_with_ttl(
            &storage,
            &pre_auth_req(),
            &encrypted_policy_cfg(Mode::Disabled),
            &[],
            1_700_000_000,
            86_400,
        )
        .await
        .expect("a configured ttl must be honoured");

        assert_eq!(res.expires_in, 86_400);
    }

    fn no_dpop<'a>() -> DpopPresentation<'a> {
        DpopPresentation {
            scheme_is_dpop: false,
            proof_jwt: None,
            htm: "POST",
            htu: TOKEN_HTU,
            ath: None,
        }
    }

    fn with_dpop(proof: &str) -> DpopPresentation<'_> {
        DpopPresentation {
            scheme_is_dpop: false,
            proof_jwt: Some(proof),
            htm: "POST",
            htu: TOKEN_HTU,
            ath: None,
        }
    }

    /// A wallet's DPoP keypair plus a valid proof for `POST /token`.
    /// Returns `(proof_jwt, jkt)`.
    fn dpop_keypair_and_proof(jti: &str, now: i64) -> (String, String) {
        use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
        use josekit::jws::{ES256, JwsHeader};
        use josekit::jwt::{self, JwtPayload};

        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let public = kp.to_jwk_public_key();

        let mut header = JwsHeader::new();
        header.set_token_type("dpop+jwt");
        header.set_jwk(public);

        let mut payload = JwtPayload::new();
        payload.set_claim("htm", Some("POST".into())).unwrap();
        payload.set_claim("htu", Some(TOKEN_HTU.into())).unwrap();
        payload.set_claim("iat", Some(now.into())).unwrap();
        payload.set_claim("jti", Some(jti.into())).unwrap();

        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        let proof = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let jkt = crate::dpop::verify_dpop_proof(&proof, "POST", TOKEN_HTU, None, now, 300, None)
            .unwrap()
            .jkt;
        (proof, jkt)
    }

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    fn sample_tx(id: &str) -> IssuanceTransaction {
        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));
        IssuanceTransaction {
            transaction_id: id.to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            status_list_index: Some(7),
            access_token: None,
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            credential_response_display: None,
        }
    }

    #[tokio::test]
    async fn handles_valid_token_request_and_issues_access_token_and_nonce() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-tok-1");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };

        let res = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();

        assert_eq!(res.token_type, "Bearer");
        assert!(!res.access_token.is_empty());

        let updated_tx = load_transaction(&storage, "tx-tok-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_tx.access_token.unwrap(), res.access_token);
    }

    #[tokio::test]
    async fn rejects_invalid_tx_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-tok-2");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("wrong".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };

        let err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
    }

    /// A wrong `tx_code` must not burn the `pre-authorized_code`: an attacker
    /// probing with an incorrect code must not be able to destroy the
    /// legitimate holder's access. Mirrors the equivalent reasoning already
    /// tested for the `authorization_code` branch.
    #[tokio::test]
    async fn wrong_tx_code_does_not_burn_the_pre_authorized_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-tok-wrong-code");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let wrong_req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("wrong".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };
        handle_token_request(
            &storage,
            &wrong_req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();

        let good_req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };
        let res = handle_token_request(
            &storage,
            &good_req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_020,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("the legitimate holder must still be able to redeem the code afterwards");

        assert!(!res.access_token.is_empty());
    }

    /// Redeeming a `pre-authorized_code` a second time, with the correct
    /// `tx_code` both times, must be rejected: OpenID4VCI 1.0 Credential Offer
    /// (L396) requires the code be single use. GAP-VCI-01's regression is
    /// covered end-to-end by
    /// `vci_0012_pre_authorized_code_grant_rejects_replay_after_token_issuance`
    /// in `tests/conformance_vci.rs`; this is the crate-local unit twin.
    #[tokio::test]
    async fn rejects_pre_authorized_code_replay_after_successful_redemption() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-tok-replay");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };

        handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("first redemption must succeed");

        let replay_err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_020,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();

        assert!(matches!(replay_err, IssuanceError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn rejects_token_request_for_already_issued_transaction() {
        let storage = test_storage().await;
        let mut tx = sample_tx("tx-tok-issued");
        tx.state = IssuanceState::Issued;
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };

        let err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
        assert!(err.to_string().contains("already been claimed"));
    }

    const REDIRECT_URI: &str = "eudi-openid4ci://authorize";
    const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn s256_code_challenge(verifier: &str) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use sha2::{Digest, Sha256};
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    fn sample_auth_code_tx(id: &str) -> IssuanceTransaction {
        let mut tx = sample_tx(id);
        tx.pre_authorized_code = None;
        tx.tx_code = None;
        tx.redirect_uri = Some(REDIRECT_URI.to_string());
        tx.issuer_state = Some("issuer-state-tok".to_string());
        tx.authorization_code = Some("authz-code-xyz".to_string());
        tx.code_challenge = Some(s256_code_challenge(CODE_VERIFIER));
        tx.code_challenge_method = Some("S256".to_string());
        tx
    }

    fn auth_code_req() -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            pre_authorized_code: None,
            tx_code: None,
            code: Some("authz-code-xyz".to_string()),
            redirect_uri: Some(REDIRECT_URI.to_string()),
            client_id: Some("wallet-dev".to_string()),
            code_verifier: Some(CODE_VERIFIER.to_string()),
            encrypted_pre_authorized_code: None,
        }
    }

    #[tokio::test]
    async fn authorization_code_grant_happy_path_issues_tokens_and_burns_the_code() {
        let storage = test_storage().await;
        let tx = sample_auth_code_tx("tx-authz-tok-1");
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let req = auth_code_req();
        let res = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();

        assert_eq!(res.token_type, "Bearer");
        assert!(!res.access_token.is_empty());

        let updated_tx = load_transaction(&storage, "tx-authz-tok-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_tx.access_token.unwrap(), res.access_token);
        assert!(updated_tx.authorization_code.is_none());

        // Replay: the code must no longer resolve to any transaction.
        let replay_err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_020,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert!(matches!(replay_err, IssuanceError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_wrong_code_verifier() {
        let storage = test_storage().await;
        let tx = sample_auth_code_tx("tx-authz-tok-2");
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let mut req = auth_code_req();
        req.code_verifier = Some("totally-wrong-verifier-value-1234567890".to_string());

        let err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidGrant(_)));

        // The code must still be usable afterward: a failed PKCE check must
        // not burn a legitimate holder's code.
        let good_req = auth_code_req();
        handle_token_request(
            &storage,
            &good_req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_020,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_mismatched_redirect_uri() {
        let storage = test_storage().await;
        let tx = sample_auth_code_tx("tx-authz-tok-3");
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let mut req = auth_code_req();
        req.redirect_uri = Some("https://evil.example.com/callback".to_string());

        let err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_unknown_code() {
        let storage = test_storage().await;

        let mut req = auth_code_req();
        req.code = Some("no-such-code".to_string());

        let err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_already_issued_transaction() {
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-authz-tok-4");
        tx.state = IssuanceState::Issued;
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let req = auth_code_req();
        let err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
        assert!(err.to_string().contains("already been claimed"));
    }

    #[tokio::test]
    async fn pre_authorized_code_regression_still_passes_with_the_shared_helper() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-tok-regression");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };

        let res = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();
        assert!(!res.access_token.is_empty());
    }

    /// The shared `TokenRequest` fixture for the pre-authorized_code grant --
    /// same shape `handles_valid_token_request_and_issues_access_token_and_nonce`
    /// builds inline, promoted to a helper for the DPoP tests below.
    fn pre_auth_req() -> TokenRequest {
        TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        }
    }

    // --- RFC 9449 §5 / §5.2 mode matrix: 3 modes x {no header, valid proof} ---

    #[tokio::test]
    async fn disabled_mode_ignores_an_absent_proof_and_issues_bearer() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-dis-none");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Disabled),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "Bearer");
        let loaded = load_transaction(&storage, "tx-dpop-dis-none")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.dpop_jkt, None);
    }

    #[tokio::test]
    async fn disabled_mode_ignores_a_present_proof_rather_than_rejecting_it() {
        // RFC 9449 §10.1 encourages clients that "blindly attach the DPoP
        // header to all requests to the authorization server", and §5 lets an
        // AS signal non-binding with token_type Bearer. Rejecting here would
        // hard-fail a wallet doing exactly what the RFC recommends.
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-dis-some");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let (proof, _) = dpop_keypair_and_proof("j-dis", 1_700_000_010);
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Disabled),
            &with_dpop(&proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();
        assert_eq!(
            res.token_type, "Bearer",
            "Disabled ignores, it does not reject"
        );
        let loaded = load_transaction(&storage, "tx-dpop-dis-some")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.dpop_jkt, None);
    }

    #[tokio::test]
    async fn optional_mode_without_a_proof_issues_bearer() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-opt-none");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "Bearer");
    }

    #[tokio::test]
    async fn optional_mode_with_a_valid_proof_issues_a_bound_dpop_token() {
        // RFC 9449 §5: "A token_type of DPoP MUST be included in the access
        // token response to signal to the client that the access token was
        // bound to its DPoP key."
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-opt-some");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let (proof, jkt) = dpop_keypair_and_proof("j-opt", 1_700_000_010);
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &with_dpop(&proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "DPoP");
        let loaded = load_transaction(&storage, "tx-dpop-opt-some")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded.dpop_jkt,
            Some(jkt),
            "§6: the token must record its bound key"
        );
    }

    #[tokio::test]
    async fn required_mode_without_a_proof_is_rejected() {
        // RFC 9449 §5.2: "the authorization server MUST reject token requests
        // from the client that do not contain the DPoP header."
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-req-none");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let e = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn required_mode_with_a_valid_proof_issues_a_dpop_token() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-req-some");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
        let (proof, _) = dpop_keypair_and_proof("j-req", 1_700_000_010);
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &with_dpop(&proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "DPoP");
    }

    // --- Ordering invariants: a bad proof must not burn a code ---

    #[tokio::test]
    async fn an_invalid_dpop_proof_does_not_burn_the_pre_authorized_code() {
        // Same invariant as wrong_tx_code_does_not_burn_the_pre_authorized_code
        // and pop_replay_rejection_does_not_burn_the_pre_authorized_code: an
        // attacker probing with a forged proof must not deny the legitimate
        // holder their credential.
        let storage = test_storage().await;
        let tx = sample_tx("tx-dpop-noburn");
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &with_dpop("not-a-jwt"),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect_err("a malformed proof must be rejected");

        // The code must still work for the legitimate holder.
        let (proof, _) = dpop_keypair_and_proof("j-after", 1_700_000_020);
        let res = handle_token_request(
            &storage,
            &pre_auth_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &with_dpop(&proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_020,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("the pre-authorized code must survive a rejected proof");
        assert_eq!(res.token_type, "DPoP");
    }

    #[tokio::test]
    async fn a_replayed_dpop_proof_is_rejected_at_the_token_endpoint() {
        // §11.1, via claim_dpop_jti.
        let storage = test_storage().await;
        for id in ["tx-dpop-replay-1", "tx-dpop-replay-2"] {
            let mut tx = sample_tx(id);
            tx.pre_authorized_code = Some(format!("code-{id}"));
            save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
                .await
                .unwrap();
        }
        let (proof, _) = dpop_keypair_and_proof("j-replayed", 1_700_000_010);

        let mut req1 = pre_auth_req();
        req1.pre_authorized_code = Some("code-tx-dpop-replay-1".to_string());
        handle_token_request(
            &storage,
            &req1,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &with_dpop(&proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();

        let mut req2 = pre_auth_req();
        req2.pre_authorized_code = Some("code-tx-dpop-replay-2".to_string());
        let e = handle_token_request(
            &storage,
            &req2,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Required),
            &with_dpop(&proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect_err("the same proof must not be usable twice");
        assert!(e.to_string().contains("jti"), "got: {e}");
    }

    // --- RFC 9449 §10: dpop_jkt pinned at /authorize ---

    #[tokio::test]
    async fn a_proof_matching_the_pinned_dpop_jkt_is_accepted() {
        let storage = test_storage().await;
        let (proof, jkt) = dpop_keypair_and_proof("j-pin-ok", 1_700_000_010);
        let mut tx = sample_auth_code_tx("tx-dpop-pin-ok");
        tx.dpop_jkt = Some(jkt.clone());
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let res = handle_token_request(
            &storage,
            &auth_code_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &with_dpop(&proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap();
        assert_eq!(res.token_type, "DPoP");
    }

    #[tokio::test]
    async fn a_proof_for_another_key_than_the_pinned_dpop_jkt_is_rejected() {
        // RFC 9449 §10: "If they do not match, it MUST reject the request."
        // §11.9: this is what stops a harvested authorization code being
        // redeemed under an attacker-controlled key.
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-dpop-pin-bad");
        tx.dpop_jkt = Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string());
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let (proof, _) = dpop_keypair_and_proof("j-pin-bad", 1_700_000_010);
        let e = handle_token_request(
            &storage,
            &auth_code_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &with_dpop(&proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_pinned_dpop_jkt_with_no_proof_at_all_is_rejected() {
        // §10 pins the code to a key; redeeming it with no proof would silently
        // drop that binding.
        let storage = test_storage().await;
        let mut tx = sample_auth_code_tx("tx-dpop-pin-noproof");
        tx.dpop_jkt = Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string());
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let e = handle_token_request(
            &storage,
            &auth_code_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_mismatched_dpop_jkt_does_not_burn_the_authorization_code() {
        // The §10 comparison happens after the transaction loads but before
        // the code is invalidated, for the same reason as every other
        // "does_not_burn" test in this module.
        let storage = test_storage().await;
        let (good_proof, good_jkt) = dpop_keypair_and_proof("j-noburn-ok", 1_700_000_020);
        let mut tx = sample_auth_code_tx("tx-dpop-authnoburn");
        tx.dpop_jkt = Some(good_jkt);
        crate::transaction::save_transaction_with_auth_code(&storage, &tx, 600, 300, 1_700_000_000)
            .await
            .unwrap();

        let (wrong_proof, _) = dpop_keypair_and_proof("j-noburn-bad", 1_700_000_010);
        handle_token_request(
            &storage,
            &auth_code_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &with_dpop(&wrong_proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_010,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect_err("wrong key must be rejected");

        handle_token_request(
            &storage,
            &auth_code_req(),
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &with_dpop(&good_proof),
            &test_nonce_secret(),
            "https://issuer.example.com",
            1_700_000_020,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("the authorization code must survive a rejected proof");
    }

    // -- GAP-VCI-14: handle_token_request's Client Attestation PoP wiring --

    use crate::attestation::PopClaims;

    const ISSUER_ID: &str = "https://issuer.example.com";
    const WALLET_SUB: &str = "https://wallet.example.org";

    /// Real wall-clock time -- pki::new_ca/pki::issue_leaf stamp validity
    /// windows using now_utc(), not an injectable clock, so a fixed fixture
    /// timestamp would spuriously fail chain validation.
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// A validly signed Wallet Attestation (chained to a fresh CA) plus a
    /// Client Attestation PoP JWT that verifies against its `cnf.jwk` --
    /// mirrors attestation.rs's own `matched_attestation_and_pop` test
    /// fixture, duplicated here since `#[cfg(test)]` modules are not shared
    /// across files. Returns `(attestation_jwt, pop_jwt, ca_cert_pem)`.
    /// A fresh EC P-256 keypair usable both as a Wallet Attestation's
    /// `cnf.jwk` and to sign a matching Client Attestation PoP JWT.
    fn wallet_provider_keypair() -> josekit::jwk::alg::ec::EcKeyPair {
        use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
        EcKeyPair::generate(EcCurve::P256).unwrap()
    }

    /// A validly signed Wallet Attestation (chained to a fresh CA) whose
    /// `cnf.jwk` is `kp`'s public half. Returns `(attestation_jwt, ca_cert_pem)`.
    fn wallet_attestation_jwt_for(
        kp: &josekit::jwk::alg::ec::EcKeyPair,
        now: i64,
    ) -> (String, String) {
        use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
        use foundry_core::pki::{issue_leaf, new_ca};
        use josekit::jwk::KeyPair as _;

        let mut cnf_jwk = kp.to_jwk_public_key();
        cnf_jwk.set_algorithm("ES256");

        let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "wallet-provider.example.com",
            &["wallet-provider.example.com".to_string()],
            365,
        )
        .unwrap();
        let leaf_der = {
            let cert = foundry_core::trust::parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
            use x509_cert::der::Encode;
            cert.to_der().unwrap()
        };
        let x5c = vec![base64::engine::general_purpose::STANDARD.encode(&leaf_der)];

        let header = serde_json::json!({
            "typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": x5c,
        });
        let payload = serde_json::json!({
            "iss": "https://wallet-provider.example.com",
            "sub": WALLET_SUB,
            "exp": now + 100_000,
            "cnf": { "jwk": cnf_jwk },
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let leaf_signer =
            FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(leaf_signer.sign(signing_input.as_bytes()).unwrap());
        (format!("{signing_input}.{sig_b64}"), ca.cert_pem)
    }

    /// A Client Attestation PoP JWT signed by `kp`'s private half -- verifies
    /// against the `cnf.jwk` `wallet_attestation_jwt_for(kp, ..)` embeds.
    fn pop_jwt_for(
        kp: &josekit::jwk::alg::ec::EcKeyPair,
        aud: &str,
        jti: &str,
        iat: i64,
    ) -> String {
        use josekit::jwk::KeyPair as _;
        use josekit::jws::{ES256, JwsSigner};

        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        let header = serde_json::json!({
            "typ": "oauth-client-attestation-pop+jwt", "alg": "ES256",
        });
        let payload = serde_json::json!({
            "iss": WALLET_SUB, "aud": aud, "jti": jti, "iat": iat,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_b64 = URL_SAFE_NO_PAD.encode(signer.sign(signing_input.as_bytes()).unwrap());
        format!("{signing_input}.{sig_b64}")
    }

    /// Convenience wrapper for the common case: a fresh keypair, its
    /// attestation, and one matching pop. Returns
    /// `(attestation_jwt, pop_jwt, ca_cert_pem)`.
    fn signed_attestation_and_pop(now: i64, aud: &str, jti: &str) -> (String, String, String) {
        let kp = wallet_provider_keypair();
        let (attestation_jwt, ca_pem) = wallet_attestation_jwt_for(&kp, now);
        let pop = pop_jwt_for(&kp, aud, jti, now);
        (attestation_jwt, pop, ca_pem)
    }

    /// Writes `ca_pem` to a temp file and returns an `AttestationMode::Required`
    /// pointing at it, plus the guard keeping the file alive for the test's
    /// lifetime (`TrustStore::from_config` reads `certs` from disk).
    fn required_attestation_mode(ca_pem: &str) -> (tempfile::TempDir, AttestationMode) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, ca_pem).unwrap();
        let mode = AttestationMode {
            mode: Mode::Required,
            trusted_anchors: vec![foundry_core::config::TrustAnchor {
                name: "wallet-provider-ca".to_string(),
                certs: path.to_str().unwrap().to_string(),
            }],
            pop_max_age_secs: 300,
            challenge_mode: Mode::Disabled,
            android: Default::default(),
        };
        (dir, mode)
    }

    #[tokio::test]
    async fn attestation_with_valid_pop_issues_a_token() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-pop-1");
        save_transaction_with_indices(&storage, &tx, 600, now_secs())
            .await
            .unwrap();

        let now = now_secs();
        let (attestation_jwt, pop_jwt, ca_pem) =
            signed_attestation_and_pop(now, ISSUER_ID, "jti-happy-1");
        let (_dir, mode) = required_attestation_mode(&ca_pem);

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };

        let res = handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("attestation + a valid, matching pop must issue a token");
        assert!(!res.access_token.is_empty());
    }

    #[tokio::test]
    async fn a_replayed_pop_is_rejected_on_a_second_token_request() {
        let storage = test_storage().await;
        let tx_a = sample_tx("tx-pop-replay-a");
        save_transaction_with_indices(&storage, &tx_a, 600, now_secs())
            .await
            .unwrap();
        let mut tx_b = sample_tx("tx-pop-replay-b");
        tx_b.pre_authorized_code = Some("code-456".to_string());
        save_transaction_with_indices(&storage, &tx_b, 600, now_secs())
            .await
            .unwrap();

        let now = now_secs();
        let (attestation_jwt, pop_jwt, ca_pem) =
            signed_attestation_and_pop(now, ISSUER_ID, "jti-replay-1");
        let (_dir, mode) = required_attestation_mode(&ca_pem);

        let req_a = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };
        handle_token_request(
            &storage,
            &req_a,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("the first use of the pop must succeed");

        // A second, otherwise-perfectly-valid token request (its own,
        // never-yet-used pre-authorized_code) that reuses the SAME pop must
        // still be rejected: the failure must be attributable to pop replay,
        // not to pre-authorized_code single-use.
        let mut req_b = req_a.clone();
        req_b.pre_authorized_code = Some("code-456".to_string());
        let err = handle_token_request(
            &storage,
            &req_b,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// A replayed pop must be rejected *before* the grant is consumed: the
    /// legitimate holder must still be able to redeem their
    /// pre-authorized_code afterward with a fresh pop.
    #[tokio::test]
    async fn pop_replay_rejection_does_not_burn_the_pre_authorized_code() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-pop-preburn");
        save_transaction_with_indices(&storage, &tx, 600, now_secs())
            .await
            .unwrap();

        let now = now_secs();
        let kp = wallet_provider_keypair();
        let (attestation_jwt, ca_pem) = wallet_attestation_jwt_for(&kp, now);
        let pop_jwt = pop_jwt_for(&kp, ISSUER_ID, "jti-preburn-1", now);
        let (_dir, mode) = required_attestation_mode(&ca_pem);

        // Pre-claim the jti directly, simulating a prior use of this exact
        // pop, so the upcoming token request's own claim attempt fails.
        let claims = PopClaims {
            iss: WALLET_SUB.to_string(),
            jti: "jti-preburn-1".to_string(),
            iat: now,
            // `claim_pop_jti` keys on (iss, jti) only and never reads this.
            cnf_jwk: josekit::jwk::alg::ec::EcKeyPair::generate(
                josekit::jwk::alg::ec::EcCurve::P256,
            )
            .unwrap()
            .to_jwk_public_key(),
        };
        claim_pop_jti(&storage, &claims, 300).await.unwrap();

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };
        let err = handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));

        // The pre-authorized_code must still be redeemable afterward, with a
        // FRESH pop signed by the SAME wallet key -- proving the rejected
        // attempt above never burned it. A pop signed by a different key
        // would fail signature verification for an unrelated reason, so this
        // must reuse `attestation_jwt`'s exact keypair, not a new one.
        let pop_jwt_2 = pop_jwt_for(&kp, ISSUER_ID, "jti-preburn-2", now);
        let res = handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt_2),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("the pre-authorized_code must still be redeemable after a pop-replay rejection");
        assert!(!res.access_token.is_empty());
    }

    /// Regression for an intermittent failure of the ABCA `client_id` tests
    /// below. They capture `now` and only *then* generate the attestation
    /// chain, whose `notBefore` came from the wall clock with no backdating --
    /// so whenever CA + leaf generation happened to cross a second boundary,
    /// `notBefore` landed one second *after* `now` and `validate_chain`
    /// rejected a perfectly good attestation as "not yet valid". The symptom
    /// was never an ABCA fault: `client_id_matching_sub_and_iss_is_accepted`
    /// failed its `expect`, and `client_id_mismatched_is_rejected` got a trust
    /// error instead of `InvalidClient`.
    ///
    /// `foundry_core::pki::CLOCK_SKEW_BACKDATE_SECS` fixes it at the source.
    /// This pins the symptom deterministically by verifying against a clock
    /// that lags certificate generation, which is what that race produced by
    /// chance.
    #[tokio::test]
    async fn attestation_verifies_against_a_clock_lagging_cert_generation() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-pop-skew");
        save_transaction_with_indices(&storage, &tx, 600, now_secs())
            .await
            .unwrap();

        // One second behind the wall clock the certs below are stamped with --
        // the deterministic form of the boundary crossing.
        let now = now_secs() - 1;
        let (attestation_jwt, pop_jwt, ca_pem) =
            signed_attestation_and_pop(now, ISSUER_ID, "jti-skew-1");
        let (_dir, mode) = required_attestation_mode(&ca_pem);

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: Some(WALLET_SUB.to_string()),
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };

        handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect(
            "a chain generated a moment after `now` must still validate; \
             pki backdates notBefore for exactly this case",
        );
    }

    /// ABCA §6.3: a matching client_id must be accepted.
    #[tokio::test]
    async fn client_id_matching_sub_and_iss_is_accepted() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-pop-cid-1");
        save_transaction_with_indices(&storage, &tx, 600, now_secs())
            .await
            .unwrap();

        let now = now_secs();
        let (attestation_jwt, pop_jwt, ca_pem) =
            signed_attestation_and_pop(now, ISSUER_ID, "jti-cid-1");
        let (_dir, mode) = required_attestation_mode(&ca_pem);

        let mut req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };
        req.client_id = Some(WALLET_SUB.to_string());

        handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("a client_id matching the attestation's sub and the pop's iss must be accepted");
    }

    /// ABCA §6.3: a mismatched client_id must be rejected.
    #[tokio::test]
    async fn client_id_mismatched_is_rejected() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-pop-cid-2");
        save_transaction_with_indices(&storage, &tx, 600, now_secs())
            .await
            .unwrap();

        let now = now_secs();
        let (attestation_jwt, pop_jwt, ca_pem) =
            signed_attestation_and_pop(now, ISSUER_ID, "jti-cid-2");
        let (_dir, mode) = required_attestation_mode(&ca_pem);

        let mut req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };
        req.client_id = Some("https://someone-else.example.com".to_string());

        let err = handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// ABCA §6.3: the check is conditional -- an absent client_id is fine.
    #[tokio::test]
    async fn client_id_absent_is_accepted() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-pop-cid-3");
        save_transaction_with_indices(&storage, &tx, 600, now_secs())
            .await
            .unwrap();

        let now = now_secs();
        let (attestation_jwt, pop_jwt, ca_pem) =
            signed_attestation_and_pop(now, ISSUER_ID, "jti-cid-3");
        let (_dir, mode) = required_attestation_mode(&ca_pem);

        let req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: Some("4242".to_string()),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            encrypted_pre_authorized_code: None,
        };

        handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            &test_nonce_secret(),
            ISSUER_ID,
            now,
            &no_encrypted_code(),
            600,
        )
        .await
        .expect("an absent client_id must be accepted -- the sect-6.3 check is conditional");
    }
}
