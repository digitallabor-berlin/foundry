//! Token request handling for OpenID4VCI pre-authorized code and
//! authorization_code flows.

use crate::attestation::{claim_pop_jti, DefaultAttestationVerifier, WalletAttestationVerifier};
use crate::dpop::{claim_dpop_jti, verify_dpop_proof, DpopPresentation};
use crate::error::IssuanceError;
use crate::transaction::{
    invalidate_authorization_code, invalidate_pre_authorized_code,
    load_transaction_by_authorization_code, load_transaction_by_pre_auth_code,
    save_transaction_with_indices, IssuanceState, IssuanceTransaction,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use foundry_core::config::{AttestationMode, DpopConfig, Mode};
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
    issuer_identifier: &str,
    now_unix: i64,
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
        )
        .inspect_err(|e| {
            tracing::warn!(error.kind = e.kind(), "wallet attestation rejected");
        })?;

    if let Some(claims) = pop_claims {
        // Anti-replay claim happens before any grant work: a replayed PoP
        // must never get the chance to burn a legitimate holder's code.
        claim_pop_jti(storage, &claims, wallet_attestation.pop_max_age_secs)
            .await
            .inspect_err(|e| {
                tracing::warn!(error.kind = e.kind(), "client attestation pop jti rejected");
            })?;

        // ABCA §6.3: if client_id is present, it MUST equal the attestation's
        // sub *and* the PoP's iss. validate_client_attestation_pop_jwt's
        // check 5 already proved those two equal, so claims.iss *is* that
        // shared value -- one comparison here mechanically covers both
        // named requirements.
        if let Some(client_id) = &req.client_id {
            if client_id != &claims.iss {
                return Err(IssuanceError::InvalidClient(
                    "client_id does not match the wallet attestation/client attestation pop".into(),
                ));
            }
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
            let verified = verify_dpop_proof(
                proof_jwt,
                dpop.htm,
                dpop.htu,
                // §4.3 check 12 does not apply at the Token Endpoint: no
                // access token is being presented.
                None,
                now_unix,
                dpop_cfg.max_age_secs,
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
            handle_pre_authorized_code_grant(storage, req, dpop_jkt, now_unix).await
        }
        "authorization_code" => {
            handle_authorization_code_grant(storage, req, dpop_jkt, now_unix).await
        }
        _ => Err(IssuanceError::InvalidGrant(
            "unsupported_grant_type".to_string(),
        )),
    }
}

async fn handle_pre_authorized_code_grant(
    storage: &dyn Storage,
    req: &TokenRequest,
    dpop_jkt: Option<String>,
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let code = req
        .pre_authorized_code
        .as_deref()
        .ok_or_else(|| IssuanceError::InvalidGrant("missing pre-authorized_code".to_string()))?;

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
    if let Some(pinned) = &tx.dpop_jkt {
        if dpop_jkt.as_deref() != Some(pinned.as_str()) {
            return Err(IssuanceError::InvalidDpopProof(
                "the DPoP proof key does not match the dpop_jkt pinned at the \
                 Authorization Endpoint"
                    .into(),
            ));
        }
    }

    // OpenID4VCI 1.0 Credential Offer (L396): `pre-authorized_code` MUST be
    // short-lived and single use. Burn only after full validation passes: an
    // attacker probing with a wrong tx_code must not be able to destroy the
    // legitimate holder's code (mirrors the authorization_code branch below).
    invalidate_pre_authorized_code(storage, code).await?;

    let mut tx = tx;
    tx.pre_authorized_code = None;

    mint_and_save_tokens(storage, tx, dpop_jkt, now_unix).await
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
    if let Some(pinned) = &tx.dpop_jkt {
        if dpop_jkt.as_deref() != Some(pinned.as_str()) {
            return Err(IssuanceError::InvalidDpopProof(
                "the DPoP proof key does not match the dpop_jkt pinned at the \
                 Authorization Endpoint"
                    .into(),
            ));
        }
    }

    // Only invalidate the code once it has fully passed validation: an
    // attacker probing with a wrong code_verifier must not be able to burn
    // the legitimate holder's code.
    invalidate_authorization_code(storage, code).await?;

    let mut tx = tx;
    tx.authorization_code = None;

    mint_and_save_tokens(storage, tx, dpop_jkt, now_unix).await
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
    now_unix: i64,
) -> Result<TokenResponse, IssuanceError> {
    let access_token = format!("at_{}", Uuid::new_v4().simple());
    let expires_in = 600u64;

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
    use crate::transaction::{load_transaction, IssuanceState, IssuanceTransaction};
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
        }
    }

    fn dpop_cfg(mode: Mode) -> DpopConfig {
        DpopConfig {
            mode,
            max_age_secs: 300,
        }
    }

    const TOKEN_HTU: &str = "https://issuer.example.com/token";

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
        use josekit::jws::{JwsHeader, ES256};
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

        let jkt = crate::dpop::verify_dpop_proof(&proof, "POST", TOKEN_HTU, None, now, 300)
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
        };

        let res = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
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
        };

        let err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
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
        };
        handle_token_request(
            &storage,
            &wrong_req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
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
        };
        let res = handle_token_request(
            &storage,
            &good_req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_020,
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
        };

        handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_020,
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
        };

        let err = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidGrant(_)));
        assert!(err.to_string().contains("already been claimed"));
    }

    const REDIRECT_URI: &str = "eudi-openid4ci://authorize";
    const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn s256_code_challenge(verifier: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_020,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_020,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
        };

        let res = handle_token_request(
            &storage,
            &req,
            &disabled(),
            None,
            None,
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_020,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_010,
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
            "https://issuer.example.com",
            1_700_000_020,
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
        use josekit::jws::{JwsSigner, ES256};

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
        };

        let res = handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            ISSUER_ID,
            now,
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
        };
        handle_token_request(
            &storage,
            &req_a,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            ISSUER_ID,
            now,
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
            ISSUER_ID,
            now,
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
        };
        let err = handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            ISSUER_ID,
            now,
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
            ISSUER_ID,
            now,
        )
        .await
        .expect("the pre-authorized_code must still be redeemable after a pop-replay rejection");
        assert!(!res.access_token.is_empty());
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
            ISSUER_ID,
            now,
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
            ISSUER_ID,
            now,
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
        };

        handle_token_request(
            &storage,
            &req,
            &mode,
            Some(&attestation_jwt),
            Some(&pop_jwt),
            &dpop_cfg(Mode::Optional),
            &no_dpop(),
            ISSUER_ID,
            now,
        )
        .await
        .expect("an absent client_id must be accepted -- the sect-6.3 check is conditional");
    }
}
