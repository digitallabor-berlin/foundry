use crate::error::VerificationError;
use crate::transaction::{
    VerificationState, VerificationTransaction, save_verification_transaction,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use foundry_core::config::Config;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_core::storage::Storage;
use foundry_core::url::dns_host_only;
use josekit::jwk::KeyPair;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateVerificationRequest {
    pub dcql_query: Option<serde_json::Value>,
    pub named_query_ref: Option<String>,
    #[serde(default = "default_transport")]
    pub transport: String,
    pub transaction_data: Option<Vec<serde_json::Value>>,
}

fn default_transport() -> String {
    "request_uri".to_string()
}

/// The only `response_type` defined for an OpenID4VP presentation request
/// (OpenID4VP v1.0 §5, where the parameter is REQUIRED).
///
/// Wallets enforce this strictly and early: the EUDI reference iOS wallet aborts
/// request resolution unless `response_type` is both present and parseable into
/// its `ResponseType` enum, which happens *before* the DCQL query is inspected —
/// so omitting it surfaces as a misleading DCQL error rather than a missing
/// parameter. It must be emitted on every transport.
const RESPONSE_TYPE_VP_TOKEN: &str = "vp_token";

/// Response-encryption parameters advertised to wallets, sourced from
/// `verifier.response_encryption`. Defaults match OpenID4VP v1.0 §8.3.
fn response_encryption_params(config: &Config) -> (String, String) {
    let configured = config.verifier.response_encryption.as_ref();
    let alg = configured
        .and_then(|v| v.get("alg"))
        .and_then(|v| v.as_str())
        .unwrap_or("ECDH-ES")
        .to_string();
    let enc = configured
        .and_then(|v| v.get("enc"))
        .and_then(|v| v.as_str())
        .unwrap_or("A128GCM")
        .to_string();
    (alg, enc)
}

/// Presentation formats this verifier can actually verify, in the OpenID4VP
/// v1.0 `vp_formats_supported` shape. REQUIRED in client metadata unless the
/// wallet obtains it by another mechanism (§5.1).
///
/// The algorithm values are load-bearing, not decorative: wallets intersect this
/// set against their own supported formats by *exact equality*, so an
/// under-specified entry such as `"mso_mdoc": {}` causes that format to be
/// dropped entirely rather than read as "any algorithm".
///
/// Keep in sync with what `foundry-sd-jwt-vc` and `foundry-mdoc` actually
/// verify: ES256, which is COSE algorithm -7.
fn vp_formats_supported() -> serde_json::Value {
    serde_json::json!({
        "dc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256"],
            "kb-jwt_alg_values": ["ES256"]
        },
        "mso_mdoc": {
            "issuerauth_alg_values": [-7],
            "deviceauth_alg_values": [-7]
        }
    })
}

/// Annotate an ephemeral EC public JWK so a wallet can *select* it as the
/// response-encryption key.
///
/// OpenID4VP wallets filter candidate encryption keys on `kid` and `alg` being
/// present and non-empty, and locate the reader key via `use == "enc"`. josekit
/// emits none of these for a generated keypair, so a bare public JWK is silently
/// discarded and the wallet reports that the verifier advertised no encryption
/// keys at all.
///
/// Only the *public* JWK is annotated. The stored private JWK deliberately stays
/// bare so josekit's decrypter carries no key id, and therefore does not require
/// the wallet to echo `kid` back in the JWE header.
fn annotate_encryption_jwk(mut jwk: serde_json::Value, alg: &str) -> serde_json::Value {
    if let Some(obj) = jwk.as_object_mut() {
        obj.insert(
            "kid".to_string(),
            serde_json::json!(Uuid::new_v4().to_string()),
        );
        obj.insert("use".to_string(), serde_json::json!("enc"));
        obj.insert("alg".to_string(), serde_json::json!(alg));
    }
    jwk
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateVerificationResponse {
    pub verification_id: String,
    pub request_uri: Option<String>,
    pub openid4vp_uri: Option<String>,
    pub dc_api_request: Option<serde_json::Value>,
}

/// Encode `transaction_data` entries for the wire.
///
/// OpenID4VP v1.0 §8.4 defines each entry as a **base64url-encoded (unpadded)
/// JSON object**, not a bare JSON object. foundry's admin API accepts objects
/// because that is the ergonomic shape for a relying party; the encoding happens
/// here, once, and the encoded strings are what get stored and emitted so that
/// what a wallet hashes into `transaction_data_hashes` is byte-identical to what
/// was advertised.
///
/// The validation is load-bearing, not politeness. A wallet that cannot parse an
/// entry aborts the entire presentation rather than skipping it — the EUDI iOS
/// wallet unwraps every parsed entry with `.get()`
/// (`ResolvedRequestData.parseTransactionData`) and additionally requires each
/// `credential_ids` element to name a credential present in the DCQL query
/// (`TransactionData.hasCorrectIds`). Rejecting a malformed entry here converts
/// an opaque device-side failure into a precise 400 for whoever built the
/// request.
fn encode_transaction_data(
    entries: &[serde_json::Value],
    dcql: &serde_json::Value,
    hashes_alg: &[String],
) -> Result<Vec<String>, VerificationError> {
    let known_ids: Vec<&str> = dcql
        .get("credentials")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
                .collect()
        })
        .unwrap_or_default();

    entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let obj = entry.as_object().ok_or_else(|| {
                VerificationError::InvalidRequest(format!(
                    "transaction_data[{i}] must be a JSON object"
                ))
            })?;

            let has_type = obj
                .get("type")
                .and_then(|v| v.as_str())
                .is_some_and(|t| !t.is_empty());
            if !has_type {
                return Err(VerificationError::InvalidRequest(format!(
                    "transaction_data[{i}] requires a non-empty string 'type'"
                )));
            }

            let ids = obj
                .get("credential_ids")
                .and_then(|v| v.as_array())
                .filter(|a| !a.is_empty())
                .ok_or_else(|| {
                    VerificationError::InvalidRequest(format!(
                        "transaction_data[{i}] requires a non-empty 'credential_ids' array"
                    ))
                })?;

            for id in ids {
                let id = id.as_str().ok_or_else(|| {
                    VerificationError::InvalidRequest(format!(
                        "transaction_data[{i}] 'credential_ids' must contain only strings"
                    ))
                })?;
                if !known_ids.contains(&id) {
                    return Err(VerificationError::InvalidRequest(format!(
                        "transaction_data[{i}] references credential id '{id}' which is not \
                         present in the DCQL query"
                    )));
                }
            }

            // OpenID4VP L3142: `transaction_data_hashes_alg` is a member of the
            // transaction data object. Injected before encoding so the advertised
            // bytes and the bytes a wallet hashes are identical -- the guarantee this
            // function's contract rests on. An operator-supplied value is never
            // silently replaced.
            let entry = if hashes_alg.is_empty() {
                entry.clone()
            } else {
                let mut with_alg = obj.clone();
                with_alg
                    .entry("transaction_data_hashes_alg".to_string())
                    .or_insert_with(|| serde_json::json!(hashes_alg));
                serde_json::Value::Object(with_alg)
            };
            let bytes = serde_json::to_vec(&entry)
                .map_err(|e| VerificationError::Serialization(e.to_string()))?;
            Ok(B64URL.encode(bytes))
        })
        .collect()
}

/// `skip_all` is mandatory: the default would `Debug`-format `Config` and the
/// whole request into the span.
#[tracing::instrument(skip_all, fields(tx_id, named_query_ref = ?req.named_query_ref))]
pub async fn create_verification_request(
    config: &Config,
    storage: &dyn Storage,
    req: CreateVerificationRequest,
    now_unix: i64,
) -> Result<CreateVerificationResponse, VerificationError> {
    let dcql = if let Some(q) = req.dcql_query {
        q
    } else if let Some(ref named) = req.named_query_ref {
        let entry = config
            .verifier
            .named_queries
            .iter()
            .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(named.as_str()))
            .ok_or_else(|| VerificationError::Dcql(format!("unknown named_query_ref '{named}'")))?;

        entry
            .get("dcql")
            .or_else(|| entry.get("dcql_query"))
            .cloned()
            .unwrap_or_else(|| entry.clone())
    } else {
        return Err(VerificationError::Dcql(
            "either dcql_query or named_query_ref is required".to_string(),
        ));
    };

    // Validate before persisting. An unusable dcql_query would otherwise be
    // stored, advertised to a wallet, and only surface at verification time --
    // presenting the operator's configuration mistake as a presentation failure.
    // `Dcql` maps to HTTP 400 on the admin API (`verifier_admin_error_response`).
    let parsed: crate::dcql_model::DcqlQuery =
        serde_json::from_value(dcql.clone()).map_err(|e| {
            VerificationError::Dcql(format!("dcql_query is not a valid DCQL query: {e}"))
        })?;

    // OpenID4VP 1.0 L745-746: "Within the Authorization Request, the same `id`
    // MUST NOT be present more than once."
    //
    // This is checked here rather than at deserialization because it is the
    // operator's error, and this is where operator errors become HTTP 400
    // instead of a later presentation failure that reads as the wallet's fault.
    // It is load-bearing for multi-credential verification: `select_presentations`
    // matches each credential query against `vp_token`'s keys, so two queries
    // sharing an id both match the SAME entry -- one presentation would be
    // verified twice under contradictory queries, with no correct outcome to pick.
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for cq in parsed.credentials() {
        if !seen.insert(cq.id()) {
            return Err(VerificationError::Dcql(format!(
                "dcql_query repeats credential query id '{}'; OpenID4VP 1.0 requires \
                 each credential query id to appear at most once",
                cq.id()
            )));
        }
    }

    // OpenID4VP 1.0 L991-L997: once `credential_sets` is present, the Verifier
    // requests only the combinations those sets describe -- so a set the wallet
    // could never satisfy, or a credential query no set names, is an operator
    // error with no possible wallet response. Caught here, as a 400, for the
    // same reason the id-uniqueness check above is: this is where operator
    // mistakes stop looking like the wallet's fault.
    if let Some(sets) = parsed.credential_sets() {
        let declared: std::collections::HashSet<&str> =
            parsed.credentials().iter().map(|cq| cq.id()).collect();

        // L889-L890: option entries reference elements in `credentials`.
        for (set_index, set) in sets.iter().enumerate() {
            for (option_index, option) in set.options().iter().enumerate() {
                for id in option {
                    if !declared.contains(id.as_str()) {
                        return Err(VerificationError::Dcql(format!(
                            "credential set #{set_index} option #{option_index} references \
                             credential query '{id}', which is not declared in 'credentials'; \
                             OpenID4VP 1.0 requires option entries to reference elements in \
                             'credentials'"
                        )));
                    }
                }
            }
        }

        // The converse: a declared credential query that no set references can
        // never be requested (L991-L997), so it is unreachable dead weight and
        // almost certainly a missing reference.
        let referenced: std::collections::HashSet<&str> = sets
            .iter()
            .flat_map(|set| set.options().iter())
            .flat_map(|option| option.iter())
            .map(String::as_str)
            .collect();
        for cq in parsed.credentials() {
            if !referenced.contains(cq.id()) {
                return Err(VerificationError::Dcql(format!(
                    "credential query '{}' is declared in 'credentials' but referenced by no \
                     credential set; with 'credential_sets' present, OpenID4VP 1.0 requests \
                     only the combinations those sets describe, so it would never be requested",
                    cq.id()
                )));
            }
        }

        // A query whose every set is optional is satisfied by an empty
        // response, so it would report `verified: true` having verified
        // nothing. Not a spec violation -- an operator one.
        if !sets.iter().any(|set| set.required()) {
            return Err(VerificationError::Dcql(
                "dcql_query declares no required credential set; every set has \
                 required: false, so this request would verify successfully against an \
                 empty response"
                    .to_string(),
            ));
        }
    }

    let id = format!("v_{}", Uuid::new_v4().simple());
    let nonce = format!("vn_{}", Uuid::new_v4().simple());

    let keypair =
        EcKeyPair::generate(EcCurve::P256).map_err(|e| VerificationError::Crypto(e.to_string()))?;

    let public_jwk = keypair.to_jwk_public_key();
    let private_jwk = keypair.to_jwk_private_key();

    let (response_enc_alg, response_enc_method) = response_encryption_params(config);

    let ephem_public_json = annotate_encryption_jwk(
        serde_json::to_value(&public_jwk)
            .map_err(|e| VerificationError::Serialization(e.to_string()))?,
        &response_enc_alg,
    );
    let ephem_private_json = serde_json::to_value(&private_jwk)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;

    let transport_str = if req.transport.is_empty() {
        "request_uri".to_string()
    } else {
        req.transport.clone()
    };

    let response_mode = match transport_str.as_str() {
        "dc_api" => "dc_api.jwt".to_string(),
        _ => "direct_post.jwt".to_string(),
    };

    // Validate and encode before persisting: a bad entry must fail the request,
    // not reach a wallet that will abort the whole presentation over it.
    let encoded_transaction_data = match req.transaction_data.as_deref() {
        Some(entries) => Some(encode_transaction_data(
            entries,
            &dcql,
            &config.verifier.transaction_data_hashes_alg,
        )?),
        None => None,
    };

    let tx = VerificationTransaction {
        id: id.clone(),
        state: VerificationState::Pending,
        nonce: nonce.clone(),
        dcql_query: dcql.clone(),
        transport: transport_str.clone(),
        response_mode: response_mode.clone(),
        ephem_private_jwk: ephem_private_json,
        ephem_public_jwk: ephem_public_json.clone(),
        transaction_data: encoded_transaction_data,
        result: None,
        created_at: now_unix,
    };

    save_verification_transaction(storage, &tx, config.storage.transaction_ttl_secs, now_unix)
        .await?;

    // Recorded on the span so that every later event in this request — and the
    // wallet's subsequent GET /vp/request/:id and POST /vp/response/:id — can be
    // threaded together by one `tx_id` value.
    tracing::Span::current().record("tx_id", tracing::field::display(&tx.id));
    tracing::info!(
        tx_id = %tx.id,
        transport = %tx.transport,
        ttl_secs = config.storage.transaction_ttl_secs,
        "verification request created"
    );

    let base_url = config
        .server
        .wallet_facing
        .public_base_url
        .trim_end_matches('/');

    if transport_str == "dc_api" {
        let mut dc_api_obj = serde_json::json!({
            "response_type": RESPONSE_TYPE_VP_TOKEN,
            "response_mode": "dc_api.jwt",
            "dcql_query": dcql,
            "nonce": nonce,
            "client_metadata": {
                "jwks": { "keys": [ephem_public_json] },
                "encrypted_response_enc_values_supported": [response_enc_method],
                "vp_formats_supported": vp_formats_supported()
            }
        });

        // OpenID4VP 1.0 §A.3 (DC API / Request, L2421-L2431) lists
        // `transaction_data` among the Authorization Request parameters
        // supported over the W3C Digital Credentials API. The *encoded* entries
        // (already persisted on `tx`) are emitted -- the same bytes
        // `build_signed_request_object` advertises on the `request_uri`
        // transport -- so a wallet hashes identical input into
        // `transaction_data_hashes` whichever transport it was invoked over.
        // The key is conditional: a request that does not use the feature
        // keeps the unsigned-request shape VP-0198 documents.
        if let (Some(obj), Some(td)) = (dc_api_obj.as_object_mut(), tx.transaction_data.as_ref()) {
            obj.insert("transaction_data".to_string(), serde_json::json!(td));
        }

        // The DC API counterpart of the signed Request Object dump in
        // `build_signed_request_object`, emitted here because this transport
        // has no signed form and no later build step -- this object is what
        // the invoking page hands the wallet. Logged only once the conditional
        // `transaction_data` member is in place, so the record is the final
        // request rather than a prefix of it. Doubly gated for the same reason
        // as its signed counterpart: it carries `nonce` and the ephemeral
        // public JWK (root AGENTS.md sect-4.5).
        if foundry_core::obs::sensitive_enabled() {
            tracing::trace!(
                dc_api_request = %dc_api_obj,
                "SENSITIVE: DC API request object returned for wallet invocation"
            );
        }

        Ok(CreateVerificationResponse {
            verification_id: id,
            request_uri: None,
            openid4vp_uri: None,
            dc_api_request: Some(dc_api_obj),
        })
    } else {
        let request_uri = format!("{base_url}/vp/request/{id}");
        let leaf_pem = verifier_x5c_leaf_pem(config)?;
        let client_id = x509_hash_client_id(&leaf_pem)?;
        let client_id_enc = utf8_percent_encode(&client_id, NON_ALPHANUMERIC).to_string();
        let request_uri_enc = utf8_percent_encode(&request_uri, NON_ALPHANUMERIC).to_string();
        let openid4vp_uri =
            format!("openid4vp://?client_id={client_id_enc}&request_uri={request_uri_enc}");

        Ok(CreateVerificationResponse {
            verification_id: id,
            request_uri: Some(request_uri),
            openid4vp_uri: Some(openid4vp_uri),
            dc_api_request: None,
        })
    }
}

/// The configured leaf certificate PEM for `verifier.signing_key`.
///
/// Required for the `x509_hash` Client Identifier Prefix (HAIP OpenID4VP L256):
/// the identifier *is* the certificate hash, so without a certificate there is no
/// identifier to emit. Shared by both Request Object transports, so the
/// identifier on the `openid4vp://` invocation URI and the identifier inside the
/// signed Request Object it points to are derived from the same certificate.
pub(crate) fn verifier_x5c_leaf_pem(config: &Config) -> Result<Vec<u8>, VerificationError> {
    let key_entry = config
        .keys
        .get(&config.verifier.signing_key)
        .ok_or_else(|| {
            VerificationError::Crypto(format!(
                "verifier signing key '{}' not found in config.keys",
                config.verifier.signing_key
            ))
        })?;
    let x5c_path = key_entry.x5c.as_ref().ok_or_else(|| {
        VerificationError::Crypto(format!(
            "verifier signing key '{}' has no x5c certificate; the x509_hash Client \
             Identifier Prefix (HAIP OpenID4VP L256) requires one",
            config.verifier.signing_key
        ))
    })?;
    std::fs::read(x5c_path).map_err(|e| {
        VerificationError::Crypto(format!("failed to read x5c file '{x5c_path}': {e}"))
    })
}

/// The `x509_hash:` Client Identifier for a leaf certificate.
///
/// HAIP OpenID4VP L256 mandates the `x509_hash` Client Identifier Prefix for
/// signed requests, narrowing OpenID4VP Section 5.9.3; the value is
/// base64url(SHA-256(DER leaf)) per OpenID4VP L616.
pub(crate) fn x509_hash_client_id(leaf_pem: &[u8]) -> Result<String, VerificationError> {
    Ok(format!(
        "x509_hash:{}",
        foundry_core::trust::x509_hash_client_id_value(leaf_pem)?
    ))
}

/// `skip_all` is mandatory: `tx` holds `ephem_private_jwk`.
#[tracing::instrument(skip_all, fields(tx_id = %tx.id))]
pub fn build_signed_request_object(
    config: &Config,
    tx: &VerificationTransaction,
) -> Result<String, VerificationError> {
    let key_entry = config
        .keys
        .get(&config.verifier.signing_key)
        .ok_or_else(|| {
            VerificationError::Crypto(format!(
                "verifier signing key '{}' not found in config.keys",
                config.verifier.signing_key
            ))
        })?;

    let alg: SignatureAlgorithm = key_entry.alg.parse()?;
    let signer = FileSigner::from_pem_file(&key_entry.private_key, alg)?;

    let base_url = config
        .server
        .wallet_facing
        .public_base_url
        .trim_end_matches('/');
    let host = dns_host_only(base_url);
    let response_uri = format!("{base_url}/vp/response/{}", tx.id);

    // HAIP OpenID4VP L256: for signed requests the Verifier MUST use the Client
    // Identifier Prefix `x509_hash`, narrowing OpenID4VP Section 5.9.3. The value
    // is base64url(SHA-256(DER of the leaf)) per OpenID4VP L616. Because the
    // identifier *is* the certificate hash, `x5c` is required -- with no
    // certificate there is no Client Identifier to emit.
    let pem_bytes = verifier_x5c_leaf_pem(config)?;

    // OpenID4VP 1.0 Defined Client Identifier Prefixes / x509_san_dns (L614) via
    // GAP-VP-02: the leaf's dNSName SAN is still cross-checked, but against
    // public_base_url's host directly now -- the host is no longer carried in
    // client_id under x509_hash, and public_base_url was always the real source of
    // truth. Keeps a misconfigured public_base_url/certificate pairing failing
    // loudly instead of signing a Request Object the wallet will reject.
    if !foundry_core::trust::match_san_dns(&pem_bytes, &host)? {
        return Err(VerificationError::Crypto(format!(
            "host '{host}' (derived from server.wallet_facing.public_base_url) does not \
             match any dNSName SAN entry in the configured x5c leaf certificate"
        )));
    }

    let client_id = x509_hash_client_id(&pem_bytes)?;
    let x5c = Some(foundry_core::trust::build_x5c(&[pem_bytes])?);

    let mut payload_map = serde_json::Map::new();
    payload_map.insert(
        "response_type".to_string(),
        serde_json::json!(RESPONSE_TYPE_VP_TOKEN),
    );
    payload_map.insert("client_id".to_string(), serde_json::json!(client_id));
    payload_map.insert("response_uri".to_string(), serde_json::json!(response_uri));
    payload_map.insert(
        "response_mode".to_string(),
        serde_json::json!("direct_post.jwt"),
    );
    // OpenID4VP 1.0 `aud` of a Request Object (L536): MUST be
    // "https://self-issued.me/v2" under Static Discovery -- the only branch this
    // verifier ever takes, since it performs no Dynamic Discovery (no
    // openid_federation Client Identifier Prefix; see VP-0041/VP-0048).
    payload_map.insert(
        "aud".to_string(),
        serde_json::json!("https://self-issued.me/v2"),
    );
    payload_map.insert("nonce".to_string(), serde_json::json!(tx.nonce));
    payload_map.insert("state".to_string(), serde_json::json!(tx.id));
    payload_map.insert("dcql_query".to_string(), tx.dcql_query.clone());
    let (_, response_enc_method) = response_encryption_params(config);
    payload_map.insert(
        "client_metadata".to_string(),
        serde_json::json!({
            "jwks": { "keys": [tx.ephem_public_jwk.clone()] },
            "encrypted_response_enc_values_supported": [response_enc_method],
            "vp_formats_supported": vp_formats_supported()
        }),
    );
    if let Some(ref td) = tx.transaction_data {
        payload_map.insert("transaction_data".to_string(), serde_json::json!(td));
    }
    let payload_val = serde_json::Value::Object(payload_map);

    let mut header_map = serde_json::Map::new();
    header_map.insert("typ".to_string(), serde_json::json!("oauth-authz-req+jwt"));
    header_map.insert("alg".to_string(), serde_json::json!(alg.as_str()));
    if let Some(chain) = x5c {
        header_map.insert("x5c".to_string(), serde_json::json!(chain));
    }
    // Header order is `typ, alg, x5c` -- deliberately NOT the `alg, typ, x5c`
    // of the SD-JWT VC and status-list builders. `serde_json` preserves
    // insertion order, so the difference is real in the signed bytes; keep it.
    let jws = foundry_core::crypto::jws::sign_compact(&header_map, &payload_val, &signer)?;

    // Always-on and payload-free: records that a Request Object really was
    // served for this transaction, and under which algorithm. `tx_id` is
    // already on the span, so this threads into the rest of the flow.
    tracing::debug!(
        alg = %alg.as_str(),
        jws_len = jws.len(),
        "signed request object built"
    );

    // The Request Object the wallet actually receives, verbatim. Doubly gated
    // per root AGENTS.md sect-4.5: it commits to `tx.nonce` and carries the
    // ephemeral PUBLIC JWK in `client_metadata`, so a `debug`/`trace` level
    // alone is not authorisation -- RUST_LOG=trace is not consent. Same tier,
    // and the same justification, as the SessionTranscript diagnostic in
    // `verify.rs`: a wallet-side rejection cannot be reproduced offline
    // without the exact bytes that were sent.
    if foundry_core::obs::sensitive_enabled() {
        // Built here rather than before signing: `sign_compact` borrows the
        // header map, and this diagnostic is the map's only other reader.
        let header_val = serde_json::Value::Object(header_map);
        tracing::trace!(
            request_object_jws = %jws,
            request_object_header = %header_val,
            request_object_payload = %payload_val,
            "SENSITIVE: signed request object served to wallet"
        );
    }

    Ok(jws)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::load_verification_transaction;
    use foundry_core::config::*;
    use foundry_core::pki::{generate_ec_key, issue_leaf, new_ca};
    use foundry_core::storage::SqliteStorage;
    use josekit::jws::ES256;
    use std::collections::BTreeMap;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("verifier_test.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    /// A leaf certificate for `verifier.example.com` (this fixture's
    /// `public_base_url` host), leaked to a tempfile so its path outlives the
    /// call. HAIP OpenID4VP L256 makes `x5c` required for signed requests, so
    /// every test config needs one -- not only the tests that call
    /// `build_signed_request_object` directly, since `create_verification_request`
    /// also computes the `x509_hash` Client Identifier for its unsigned
    /// `openid4vp://` invocation URI.
    fn sample_verifier_x5c_path() -> String {
        let ca = new_ca("Foundry Test Verifier Root", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "verifier.example.com",
            &["verifier.example.com".to_string()],
            365,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verifier_leaf.pem");
        std::fs::write(&path, leaf.cert_pem.as_bytes()).unwrap();
        std::mem::forget(dir);
        path.to_str().unwrap().to_string()
    }

    fn sample_config(key_path: &str) -> Config {
        let mut keys = BTreeMap::new();
        keys.insert(
            "verifier_signing".to_string(),
            KeyEntry {
                private_key: key_path.to_string(),
                x5c: Some(sample_verifier_x5c_path()),
                alg: "ES256".to_string(),
            },
        );

        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://verifier.example.com".to_string(),
                    bind: "127.0.0.1:8080".to_string(),
                    swagger_ui_enabled: true,
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:8081".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                    console_enabled: true,
                },
            },
            storage: StorageConfig {
                path: ":memory:".to_string(),
                transaction_ttl_secs: 600,
            },
            keys,
            trust_anchors: vec![],
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                wallet_attestation: Default::default(),
                key_attestation: Default::default(),
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
            },
            credential_types: vec![],
            verifier: VerifierConfig {
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec!["sha-256".to_string()],
                named_queries: vec![serde_json::json!({
                    "id": "over18",
                    "dcql": {
                        "credentials": [{
                            "id": "c1",
                            "format": "mso_mdoc",
                            "meta": { "doctype": "org.iso.18013.5.1.mDL" }
                        }]
                    }
                })],
                webhook: None,
                dc_api_expected_origins: Vec::new(),
                dc_api_accept_legacy_web_origin_audience: false,
            },
            logging: LoggingConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_create_verification_request_dcql() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        assert!(res.verification_id.starts_with("v_"));
        let req_uri = res.request_uri.as_ref().unwrap();
        assert!(req_uri.contains("/vp/request/"));
        let vp_uri = res.openid4vp_uri.as_ref().unwrap();
        assert!(vp_uri.starts_with("openid4vp://?client_id="));
        assert!(res.dc_api_request.is_none());

        // Verify transaction saved in storage
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tx.id, res.verification_id);
        assert_eq!(tx.state, VerificationState::Pending);
        assert_eq!(tx.transport, "request_uri");
        assert_eq!(tx.response_mode, "direct_post.jwt");
    }

    /// An unusable `dcql_query` must fail the operator's create request rather
    /// than being persisted, advertised to a wallet, and surfacing later as a
    /// presentation failure that looks like the wallet's fault.
    #[tokio::test]
    async fn create_rejects_malformed_dcql_query() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({"credentials": "not-an-array"})),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let err = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Dcql(ref m) if m.contains("not a valid DCQL query")),
            "expected a Dcql error naming the parse failure, got: {err}"
        );
    }

    /// `credentials: []` requests nothing and can never be satisfied. It shipped
    /// in `config.yaml` and was accepted here until the query was validated.
    #[tokio::test]
    async fn create_rejects_empty_credentials_dcql_query() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({"credentials": []})),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let err = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Dcql(_)),
            "expected a Dcql error, got: {err}"
        );
    }

    /// OpenID4VP 1.0 L745-746: "Within the Authorization Request, the same `id`
    /// MUST NOT be present more than once."
    ///
    /// Unvalidated, this was a bounded operator misconfiguration -- every lookup
    /// resolved to the first match. Multi-credential verification makes it
    /// ambiguous: `select_presentations` matches each credential query against
    /// `vp_token`'s keys, so two queries sharing an id both match the SAME entry
    /// and one presentation would be verified twice under contradictory queries.
    /// There is no correct behaviour available, so the request is refused before
    /// it is persisted.
    #[tokio::test]
    async fn create_rejects_duplicate_credential_query_ids() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [
                    {"id": "pid", "format": "dc+sd-jwt"},
                    {"id": "pid", "format": "mso_mdoc"}
                ]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let err = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            matches!(err, VerificationError::Dcql(_)),
            "a repeated credential query id is the operator's error, so it must be \
             Dcql (HTTP 400 on the admin API), got: {err}"
        );
        assert!(
            msg.contains("pid"),
            "the message must name the repeated id so the operator can find it: {msg}"
        );
    }

    /// Distinct ids remain acceptable -- this is the case the feature exists for.
    #[tokio::test]
    async fn create_accepts_multiple_distinct_credential_queries() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [
                    {"id": "pid", "format": "dc+sd-jwt"},
                    {"id": "mdl", "format": "mso_mdoc"}
                ]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .expect("a multi-credential query with distinct ids must be accepted");
    }

    #[tokio::test]
    async fn test_create_verification_request_named_query() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: None,
            named_query_ref: Some("over18".to_string()),
            transport: "request_uri".to_string(),
            transaction_data: Some(vec![serde_json::json!({
                "type": "payment",
                "credential_ids": ["c1"]
            })]),
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tx.dcql_query["credentials"][0]["meta"]["doctype"],
            "org.iso.18013.5.1.mDL"
        );
        assert_eq!(tx.transaction_data.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_create_verification_request_unknown_named_query_fails() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: None,
            named_query_ref: Some("nonexistent".to_string()),
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let err = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();

        assert!(matches!(err, VerificationError::Dcql(_)));
    }

    #[tokio::test]
    async fn test_create_verification_request_dc_api() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "dc_api".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        assert!(res.request_uri.is_none());
        assert!(res.openid4vp_uri.is_none());
        let dc_req = res.dc_api_request.unwrap();
        assert_eq!(dc_req["response_mode"], "dc_api.jwt");
        assert!(dc_req["nonce"].is_string());
        assert!(dc_req["client_metadata"]["jwks"]["keys"].is_array());
    }

    /// A DC API request that does not use transaction data must keep its
    /// previous five-key shape exactly -- the key is conditional, not
    /// unconditionally present-and-null.
    #[tokio::test]
    async fn test_dc_api_request_omits_transaction_data_when_absent() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "dc_api".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let dc_req = res.dc_api_request.unwrap();
        assert!(
            dc_req
                .as_object()
                .unwrap()
                .get("transaction_data")
                .is_none(),
            "an unsigned DC API request without transaction data must not carry the key: {dc_req}"
        );
    }

    #[tokio::test]
    async fn test_build_signed_request_object_and_verify_jws() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");

        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: Some(vec![serde_json::json!({
                "type": "payment",
                "credential_ids": ["c1"],
                "amount": 50
            })]),
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();

        let jws_str = build_signed_request_object(&config, &tx).unwrap();

        // Check JWS structure: 3 dot-separated parts
        let parts: Vec<&str> = jws_str.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_bytes = B64URL.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "oauth-authz-req+jwt");
        assert_eq!(header["alg"], "ES256");

        let payload_bytes = B64URL.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        // HAIP OpenID4VP L256: x509_hash, computed from the same leaf certificate
        // build_signed_request_object reads -- never hardcode the hash, it would
        // silently diverge if the fixture certificate is regenerated.
        let leaf_pem = verifier_x5c_leaf_pem(&config).unwrap();
        let expected_client_id = x509_hash_client_id(&leaf_pem).unwrap();
        assert_eq!(payload["client_id"], expected_client_id);
        assert!(
            payload["client_id"]
                .as_str()
                .unwrap()
                .starts_with("x509_hash:")
        );
        assert_eq!(
            payload["response_uri"],
            format!("https://verifier.example.com/vp/response/{}", tx.id)
        );
        assert_eq!(payload["response_mode"], "direct_post.jwt");
        assert_eq!(payload["nonce"], tx.nonce);
        assert_eq!(payload["state"], tx.id);
        // Entries are advertised base64url-encoded per OpenID4VP v1.0 §8.4.
        let td_encoded = payload["transaction_data"][0].as_str().unwrap();
        let td: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(td_encoded).unwrap()).unwrap();
        assert_eq!(td["amount"], 50);
        assert_eq!(td["type"], "payment");

        // Verify JWS signature using verifier key
        let keypair = EcKeyPair::from_pem(km.private_pem.as_bytes(), None).unwrap();
        let verifier = ES256
            .verifier_from_jwk(&keypair.to_jwk_public_key())
            .unwrap();

        let (verified_payload, verified_header) =
            josekit::jwt::decode_with_verifier(&jws_str, &verifier).unwrap();
        assert_eq!(verified_header.token_type(), Some("oauth-authz-req+jwt"));
        assert_eq!(
            verified_payload.claim("state").and_then(|v| v.as_str()),
            Some(tx.id.as_str())
        );
    }

    /// Pins the exact JOSE header `build_signed_request_object` emits. Note the
    /// order is `typ, alg, x5c` -- NOT the `alg, typ, x5c` of the status-list
    /// and SD-JWT VC builders. `serde_json` preserves insertion order, so the
    /// difference is real in the signed bytes and the migration onto
    /// `crypto::jws::sign_compact` must preserve it.
    #[tokio::test]
    async fn signed_request_object_header_is_typ_then_alg_then_x5c() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };
        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();

        let jws = build_signed_request_object(&config, &tx).unwrap();
        let part = jws.split('.').next().unwrap();
        let raw = String::from_utf8(B64URL.decode(part).unwrap()).unwrap();
        assert!(
            raw.starts_with(r#"{"typ":"oauth-authz-req+jwt","alg":"ES256","x5c":["#),
            "header order changed: {raw}"
        );
    }

    /// GAP-HAIP-05 (closed) -- HAIP OpenID4VP (L256): for signed requests the
    /// Verifier MUST use the Client Identifier Prefix `x509_hash` (the leaf
    /// certificate's hash), not `x509_san_dns`. `build_signed_request_object`
    /// now emits `client_id: "x509_hash:<base64url(SHA-256(DER leaf))>"` for
    /// every signed request (the `request_uri` transport, HAIP-0055, always
    /// produces a signed JAR Request Object), via
    /// `foundry_core::trust::x509_hash_client_id_value`.
    #[tokio::test]
    async fn gap_haip_05_signed_request_object_never_uses_x509_hash_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;
        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };
        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let jws_str = build_signed_request_object(&config, &tx).unwrap();
        let payload_bytes = B64URL.decode(jws_str.split('.').nth(1).unwrap()).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        let client_id = payload["client_id"].as_str().unwrap();
        assert!(
            client_id.starts_with("x509_hash:"),
            "HAIP-0043 requires the x509_hash Client Identifier Prefix for signed \
             requests, got: {client_id}"
        );
    }

    /// HAIP OpenID4VP L256 + OpenID4VP L616: the Client Identifier the Request
    /// Object advertises MUST be exactly the value a wallet will use as its KB-JWT
    /// audience, and `do_verify_vp_response` recomputes that expectation
    /// independently. This test fails if the two sides are ever derived
    /// differently -- the failure that would otherwise appear only as a
    /// `verified: false` policy verdict at runtime.
    #[tokio::test]
    async fn client_id_is_the_x509_hash_of_the_configured_leaf_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;
        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };
        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();

        let jws = build_signed_request_object(&config, &tx).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(jws.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        let client_id = payload["client_id"].as_str().unwrap();

        let key_entry = config.keys.get(&config.verifier.signing_key).unwrap();
        let pem = std::fs::read(key_entry.x5c.as_ref().unwrap()).unwrap();
        let expected = format!(
            "x509_hash:{}",
            foundry_core::trust::x509_hash_client_id_value(&pem).unwrap()
        );

        assert_eq!(client_id, expected);
        assert!(client_id.starts_with("x509_hash:"));
    }

    /// Decision 3: under `x509_hash` the Client Identifier *is* the certificate
    /// hash, so a signed request with no configured `x5c` has no identifier to
    /// emit. A configuration fault, and it must be a typed error.
    #[tokio::test]
    async fn signed_request_without_x5c_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let mut config = sample_config(key_file.to_str().unwrap());
        if let Some(entry) = config.keys.get_mut(&config.verifier.signing_key) {
            entry.x5c = None;
        }
        let storage = test_storage().await;
        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        // The unsigned openid4vp:// URI branch of create_verification_request also
        // needs x5c now (it computes the same x509_hash Client Identifier for the
        // invocation URI), so the error surfaces here rather than only in
        // build_signed_request_object.
        let err = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Crypto(ref m) if m.contains("x5c")),
            "expected a Crypto error naming x5c, got {err:?}"
        );
    }

    /// HAIP-0045 -- HAIP OpenID4VP (L256): the X.509 certificate of the trust
    /// anchor MUST NOT be included in the `x5c` JOSE header of the signed
    /// request. `build_signed_request_object` calls
    /// `foundry_core::trust::build_x5c(&[pem_bytes])` with only the leaf
    /// certificate -- never the CA that issued it -- so the header's `x5c`
    /// array always has exactly one entry, and that entry's DER never matches
    /// the anchor's.
    #[tokio::test]
    async fn haip_0045_signed_request_x5c_excludes_the_trust_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let ca = new_ca("Foundry Test Verifier Root", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "verifier.example.com",
            &["verifier.example.com".to_string()],
            365,
        )
        .unwrap();
        let key_path = dir.path().join("leaf_key.pem");
        std::fs::write(&key_path, leaf.key_pem.as_bytes()).unwrap();
        let cert_path = dir.path().join("leaf_cert.pem");
        std::fs::write(&cert_path, leaf.cert_pem.as_bytes()).unwrap();

        let mut config = sample_config(key_path.to_str().unwrap());
        config
            .keys
            .get_mut(&config.verifier.signing_key)
            .unwrap()
            .x5c = Some(cert_path.to_str().unwrap().to_string());
        let storage = test_storage().await;

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };
        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let jws = build_signed_request_object(&config, &tx).unwrap();
        let header_bytes = B64URL.decode(jws.split('.').next().unwrap()).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

        let x5c = header["x5c"].as_array().unwrap();
        assert_eq!(
            x5c.len(),
            1,
            "x5c must carry only the leaf, never the trust anchor: {x5c:?}"
        );

        let anchor_der = foundry_core::trust::build_x5c(&[ca.cert_pem.into_bytes()]).unwrap();
        assert_ne!(
            x5c[0].as_str().unwrap(),
            anchor_der[0],
            "the sole x5c entry must be the leaf, not the trust anchor"
        );
    }

    /// VP-0128, VP-0130, VP-0132 (OpenID4VP 1.0 Response / Response Mode
    /// `direct_post`, L1222): `response_uri` is REQUIRED when Response Mode
    /// `direct_post` is used; `redirect_uri` MUST NOT be present alongside it;
    /// and `response_uri` MUST be a value the client would be permitted to use
    /// as `redirect_uri`. `build_signed_request_object` always emits
    /// `response_uri` (never `redirect_uri`, which this codebase has no field
    /// for at all), derived from the same `public_base_url` host as `client_id`
    /// -- so it is always same-origin with the client's own identity, the
    /// strictest form of "permitted to use as redirect_uri".
    #[tokio::test]
    async fn vp_0128_0130_0132_response_uri_present_no_redirect_uri_same_origin_as_client_id() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };
        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();

        let jws_str = build_signed_request_object(&config, &tx).unwrap();
        let payload_bytes = B64URL.decode(jws_str.split('.').nth(1).unwrap()).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        // VP-0128: response_uri is present.
        let response_uri = payload["response_uri"].as_str().unwrap();
        assert!(!response_uri.is_empty());

        // VP-0130: redirect_uri is never present alongside it.
        assert!(payload.get("redirect_uri").is_none());

        // VP-0132: response_uri is same-origin with the Verifier's own host.
        // Under x509_hash the host is no longer recoverable from client_id (it
        // carries the certificate hash instead), so the expected host comes from
        // public_base_url directly -- the actual source of truth this property
        // has always rested on.
        let client_host = dns_host_only(
            config
                .server
                .wallet_facing
                .public_base_url
                .trim_end_matches('/'),
        );
        assert!(
            response_uri.starts_with(&format!("https://{client_host}/")),
            "response_uri {response_uri} must be same-origin as the Verifier's public_base_url \
             host {client_host}"
        );
        assert!(
            payload["client_id"]
                .as_str()
                .unwrap()
                .starts_with("x509_hash:")
        );
    }

    /// The ephemeral response-encryption JWK must carry the metadata a wallet
    /// needs to *select* it: OpenID4VP wallets filter candidate encryption keys
    /// on `kid` and `alg` being present and non-empty, and locate the reader key
    /// via `use == "enc"`. A bare josekit public JWK has none of these and is
    /// silently discarded, leaving the wallet with zero encryption keys.
    #[tokio::test]
    async fn test_dc_api_client_metadata_encryption_jwk_is_wallet_selectable() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "dc_api".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let dc_req = res.dc_api_request.unwrap();
        let cm = &dc_req["client_metadata"];
        let key = &cm["jwks"]["keys"][0];

        assert!(
            key["kid"].as_str().is_some_and(|s| !s.is_empty()),
            "encryption JWK must carry a non-empty kid, got: {key}"
        );
        assert_eq!(key["alg"], "ECDH-ES", "encryption JWK must carry alg");
        assert_eq!(key["use"], "enc", "encryption JWK must be marked use=enc");

        assert_eq!(
            cm["encrypted_response_enc_values_supported"],
            serde_json::json!(["A128GCM"]),
            "client_metadata must advertise supported response encryption methods"
        );
    }

    /// Same contract for the `request_uri` transport, whose client metadata is
    /// carried inside the signed request object rather than returned inline.
    #[tokio::test]
    async fn test_signed_request_object_encryption_jwk_is_wallet_selectable() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();

        let jws_str = build_signed_request_object(&config, &tx).unwrap();
        let parts: Vec<&str> = jws_str.split('.').collect();
        let payload_bytes = B64URL.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let cm = &payload["client_metadata"];
        let key = &cm["jwks"]["keys"][0];

        assert!(
            key["kid"].as_str().is_some_and(|s| !s.is_empty()),
            "encryption JWK must carry a non-empty kid, got: {key}"
        );
        assert_eq!(key["alg"], "ECDH-ES", "encryption JWK must carry alg");
        assert_eq!(key["use"], "enc", "encryption JWK must be marked use=enc");

        assert_eq!(
            cm["encrypted_response_enc_values_supported"],
            serde_json::json!(["A128GCM"]),
            "client_metadata must advertise supported response encryption methods"
        );

        // The advertised public key must still be the transaction's ephemeral
        // key material, not a freshly generated one.
        assert_eq!(key["x"], tx.ephem_public_jwk["x"]);
        assert_eq!(key["y"], tx.ephem_public_jwk["y"]);
    }

    /// OpenID4VP v1.0 §5.1 makes `vp_formats_supported` REQUIRED unless the
    /// wallet learns it by another mechanism. It must describe what this verifier
    /// can actually verify: SD-JWT VC and mdoc, ES256 / COSE -7.
    ///
    /// The algorithm values are load-bearing, not decorative: wallets intersect
    /// this set against their own by *exact equality*, so advertising e.g.
    /// `"mso_mdoc": {}` would drop mdoc from the intersection entirely.
    #[tokio::test]
    async fn test_client_metadata_advertises_vp_formats_supported() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let expected = serde_json::json!({
            "dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256"],
                "kb-jwt_alg_values": ["ES256"]
            },
            "mso_mdoc": {
                "issuerauth_alg_values": [-7],
                "deviceauth_alg_values": [-7]
            }
        });

        // dc_api transport: client metadata is returned inline.
        let dc_res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "dc_api".to_string(),
                transaction_data: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
        assert_eq!(
            dc_res.dc_api_request.unwrap()["client_metadata"]["vp_formats_supported"],
            expected,
            "dc_api client_metadata must advertise vp_formats_supported"
        );

        // request_uri transport: client metadata lives in the signed request object.
        let res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let jws_str = build_signed_request_object(&config, &tx).unwrap();
        let parts: Vec<&str> = jws_str.split('.').collect();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            payload["client_metadata"]["vp_formats_supported"], expected,
            "signed request object client_metadata must advertise vp_formats_supported"
        );
    }

    /// OpenID4VP v1.0 §5 makes `response_type` a REQUIRED Authorization Request
    /// parameter, and `vp_token` is the only value defined for a presentation
    /// request. Wallets treat it as a hard gate: the EUDI reference iOS wallet
    /// resolves the request object into an `UnvalidatedRequestObject` and then
    /// requires both that `response_type` is present and that it parses into its
    /// `ResponseType` enum, otherwise resolution is abandoned before the DCQL
    /// query is ever looked at.
    #[tokio::test]
    async fn test_authorization_request_advertises_response_type_vp_token() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        // dc_api transport: the request object is returned inline.
        let dc_res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "dc_api".to_string(),
                transaction_data: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
        assert_eq!(
            dc_res.dc_api_request.unwrap()["response_type"],
            serde_json::json!("vp_token"),
            "dc_api request must advertise response_type=vp_token"
        );

        // request_uri transport: the request object is the signed JWS payload.
        let res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let jws_str = build_signed_request_object(&config, &tx).unwrap();
        let parts: Vec<&str> = jws_str.split('.').collect();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            payload["response_type"],
            serde_json::json!("vp_token"),
            "signed request object must advertise response_type=vp_token"
        );
    }

    /// `verifier.response_encryption` was previously parsed but never read.
    /// The advertised values must come from it rather than being hardcoded.
    #[tokio::test]
    async fn test_client_metadata_response_encryption_honours_config() {
        let storage = test_storage().await;
        let mut config = sample_config("/tmp/fake_key.pem");
        config.verifier.response_encryption = Some(serde_json::json!({
            "alg": "ECDH-ES",
            "enc": "A256GCM"
        }));

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "dc_api".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let cm = &res.dc_api_request.unwrap()["client_metadata"];
        assert_eq!(
            cm["encrypted_response_enc_values_supported"],
            serde_json::json!(["A256GCM"])
        );
        assert_eq!(cm["jwks"]["keys"][0]["alg"], "ECDH-ES");
    }

    /// OpenID4VP v1.0 §8.4 defines `transaction_data` as an array of
    /// **base64url-encoded JSON strings**, not raw JSON objects.
    ///
    /// Emitting objects is silently destructive rather than loudly wrong: the
    /// EUDI iOS wallet reads the parameter as `[String]`
    /// (`RequestAuthenticator.swift:48`), so an array of objects yields `nil`
    /// and the transaction data is dropped with no error at all.
    #[tokio::test]
    async fn test_transaction_data_is_emitted_as_base64url_strings() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();
        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let entry = serde_json::json!({
            "type": "qes_authorization",
            "credential_ids": ["pid"],
            "transaction_data_hashes_alg": ["sha-256"]
        });

        let res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "pid", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![entry.clone()]),
            },
            1_700_000_000,
        )
        .await
        .unwrap();

        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let jws = build_signed_request_object(&config, &tx).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();

        let arr = payload["transaction_data"]
            .as_array()
            .expect("transaction_data must be an array");
        assert_eq!(arr.len(), 1);
        let encoded = arr[0]
            .as_str()
            .unwrap_or_else(|| panic!("entry must be a base64url string, got: {}", arr[0]));

        // Must decode back to exactly the caller-supplied object.
        let decoded: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, entry);
    }

    /// OpenID4VP L3142: `transaction_data_hashes_alg` is a member of each
    /// transaction data object, and one of its values MUST be used to compute
    /// `transaction_data_hashes`. It must therefore be inside the entry *before*
    /// base64url encoding, so what a wallet hashes is what was advertised.
    #[tokio::test]
    async fn transaction_data_entries_advertise_the_configured_hash_algorithm() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();
        let mut config = sample_config(key_file.to_str().unwrap());
        config.verifier.transaction_data_hashes_alg = vec!["sha-256".to_string()];
        let storage = test_storage().await;

        let entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["pid"]
        });

        let res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "pid", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![entry]),
            },
            1_700_000_000,
        )
        .await
        .unwrap();

        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let encoded = &tx.transaction_data.unwrap()[0];
        let decoded_entry: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(encoded).unwrap()).unwrap();
        assert_eq!(
            decoded_entry["transaction_data_hashes_alg"],
            serde_json::json!(["sha-256"])
        );
        // The operator-supplied members survive untouched.
        assert_eq!(decoded_entry["type"], "payment");
    }

    /// L3142: absent the field, sha-256 is the default -- so an empty config must
    /// advertise nothing rather than advertising a guess.
    #[tokio::test]
    async fn transaction_data_entries_omit_the_algorithm_when_unconfigured() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();
        let mut config = sample_config(key_file.to_str().unwrap());
        config.verifier.transaction_data_hashes_alg = vec![];
        let storage = test_storage().await;

        let entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["pid"]
        });

        let res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "pid", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![entry]),
            },
            1_700_000_000,
        )
        .await
        .unwrap();

        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let encoded = &tx.transaction_data.unwrap()[0];
        let decoded_entry: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(encoded).unwrap()).unwrap();
        assert!(decoded_entry.get("transaction_data_hashes_alg").is_none());
    }

    /// A wallet hard-throws on an entry it cannot parse
    /// (`ResolvedRequestData.parseTransactionData` unwraps with `.get()`), so
    /// foundry must reject a structurally invalid entry at request-creation time
    /// with a clear error instead of shipping one that breaks resolution.
    #[tokio::test]
    async fn test_transaction_data_requires_type_and_credential_ids() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");
        let dcql = serde_json::json!({
            "credentials": [{"id": "pid", "format": "dc+sd-jwt"}]
        });

        // Missing `type`.
        let err = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(dcql.clone()),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![serde_json::json!({"credential_ids": ["pid"]})]),
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidRequest(ref m) if m.contains("type")),
            "expected InvalidRequest mentioning 'type', got: {err}"
        );

        // Missing `credential_ids`.
        let err = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(dcql.clone()),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![serde_json::json!({"type": "qes_authorization"})]),
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidRequest(ref m) if m.contains("credential_ids")),
            "expected InvalidRequest mentioning 'credential_ids', got: {err}"
        );

        // Not an object.
        let err = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(dcql),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![serde_json::json!("already-encoded?")]),
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VerificationError::InvalidRequest(_)));
    }

    /// The wallet also checks that every `credential_ids` entry refers to a
    /// credential actually present in the DCQL query
    /// (`TransactionData.hasCorrectIds`). foundry holds both at creation time,
    /// so it can and should catch the mismatch first.
    #[tokio::test]
    async fn test_transaction_data_credential_ids_must_exist_in_dcql() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let err = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "pid", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![serde_json::json!({
                    "type": "qes_authorization",
                    "credential_ids": ["not_in_the_query"]
                })]),
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, VerificationError::InvalidRequest(ref m)
                if m.contains("not_in_the_query")),
            "expected InvalidRequest naming the unknown id, got: {err}"
        );
    }

    /// A helper for the credential_sets validation tests: everything is
    /// identical except the query under test.
    async fn create_with_query(query: serde_json::Value) -> Result<(), VerificationError> {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");
        let req = CreateVerificationRequest {
            dcql_query: Some(query),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };
        create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .map(|_| ())
    }

    /// OpenID4VP 1.0 L889-L890: option entries "reference elements in
    /// `credentials`". A typo'd reference makes its set permanently
    /// unsatisfiable, so no wallet response could ever verify -- an operator
    /// error, caught at 400 rather than surfacing later as the wallet's fault.
    #[tokio::test]
    async fn create_rejects_a_credential_set_option_referencing_an_unknown_id() {
        let err = create_with_query(serde_json::json!({
            "credentials": [{ "id": "visa", "format": "dc+sd-jwt" }],
            "credential_sets": [{ "options": [["vsia"]] }]
        }))
        .await
        .expect_err("a dangling option reference must be rejected");

        let msg = err.to_string();
        assert!(matches!(err, VerificationError::Dcql(_)), "{msg}");
        assert!(msg.contains("vsia"), "name the dangling id: {msg}");
        assert!(msg.contains("credential set #0"), "locate it: {msg}");
    }

    /// L991-L997: with `credential_sets` present, only what satisfies a set is
    /// requested -- so a credential query no set references would never be
    /// asked for at all.
    #[tokio::test]
    async fn create_rejects_a_credential_query_no_set_references() {
        let err = create_with_query(serde_json::json!({
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt" },
                { "id": "orphan", "format": "dc+sd-jwt" }
            ],
            "credential_sets": [{ "options": [["pid"]] }]
        }))
        .await
        .expect_err("an unreferenced credential query must be rejected");

        let msg = err.to_string();
        assert!(matches!(err, VerificationError::Dcql(_)), "{msg}");
        assert!(msg.contains("orphan"), "name the orphan: {msg}");
    }

    /// A request whose every set is optional passes `credential_sets_satisfied`
    /// unconditionally -- including against an empty `vp_token`, yielding
    /// `verified: true` with zero credentials. Spec-permissible, operationally
    /// meaningless: a verification request that cannot fail is not a
    /// verification.
    #[tokio::test]
    async fn create_rejects_an_all_optional_credential_sets_query() {
        let err = create_with_query(serde_json::json!({
            "credentials": [{ "id": "loyalty", "format": "dc+sd-jwt" }],
            "credential_sets": [{ "options": [["loyalty"]], "required": false }]
        }))
        .await
        .expect_err("a query with no required set must be rejected");

        let msg = err.to_string();
        assert!(matches!(err, VerificationError::Dcql(_)), "{msg}");
        assert!(
            msg.contains("no required credential set"),
            "say what is missing: {msg}"
        );
    }

    /// The structural constraints are enforced at deserialization (Task 1), so
    /// they must arrive here as the SAME "not a valid DCQL query" 400 an empty
    /// `credentials` array already produces -- not as a panic or a 500.
    #[tokio::test]
    async fn create_rejects_structurally_invalid_credential_sets() {
        for query in [
            serde_json::json!({
                "credentials": [{ "id": "c1", "format": "dc+sd-jwt" }],
                "credential_sets": []
            }),
            serde_json::json!({
                "credentials": [{ "id": "c1", "format": "dc+sd-jwt" }],
                "credential_sets": [{ "options": [] }]
            }),
            serde_json::json!({
                "credentials": [{ "id": "c1", "format": "dc+sd-jwt" }],
                "credential_sets": [{ "options": [["c1"], []] }]
            }),
        ] {
            let Err(err) = create_with_query(query.clone()).await else {
                panic!("must be rejected: {query}");
            };
            let msg = err.to_string();
            assert!(
                msg.contains("not a valid DCQL query"),
                "structural failures keep the existing message: {msg}"
            );
        }
    }

    /// The same id in several sets is legitimate and useful -- a PID that
    /// satisfies both an identity set and an age set -- so orphan detection
    /// works off the UNION of referenced ids, never a partition.
    #[tokio::test]
    async fn create_accepts_one_credential_query_referenced_by_several_sets() {
        create_with_query(serde_json::json!({
            "credentials": [{ "id": "pid", "format": "dc+sd-jwt" }],
            "credential_sets": [
                { "options": [["pid"]] },
                { "options": [["pid"]], "required": false }
            ]
        }))
        .await
        .expect("an id may appear in several sets");
    }

    /// The driving use case must be creatable end to end.
    #[tokio::test]
    async fn create_accepts_the_payment_age_loyalty_query() {
        create_with_query(serde_json::json!({
            "credentials": [
                { "id": "dpc_card", "format": "dc+sd-jwt" },
                { "id": "visa_card", "format": "dc+sd-jwt" },
                { "id": "pid", "format": "dc+sd-jwt" },
                { "id": "av", "format": "dc+sd-jwt" },
                { "id": "loyalty", "format": "dc+sd-jwt" }
            ],
            "credential_sets": [
                { "options": [["dpc_card"], ["visa_card"]] },
                { "options": [["pid"], ["av"]] },
                { "options": [["loyalty"]], "required": false }
            ]
        }))
        .await
        .expect("the payment/age/loyalty query must be accepted");
    }
}
