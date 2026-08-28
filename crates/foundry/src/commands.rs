//! Thin CLI command handlers: parse-free logic that calls foundry-core and does file IO.

use anyhow::Context;
use foundry_core::config::Config;
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::pki::{generate_ec_key, issue_leaf, new_ca};
use foundry_core::status_list::{
    PersistentStatusList, StatusValue, load_status_list, save_status_list,
};
use foundry_core::storage::SqliteStorage;
use std::path::Path;
use std::str::FromStr;

/// `foundry keys generate` — write a fresh EC private key (PKCS#8 PEM).
pub fn keys_generate(alg: &str, out: &Path) -> anyhow::Result<()> {
    let alg = SignatureAlgorithm::from_str(alg)?;
    let km = generate_ec_key(alg)?;
    std::fs::write(out, km.private_pem.as_bytes())
        .with_context(|| format!("writing key to {}", out.display()))?;
    tracing::info!(path = %out.display(), alg = %alg, "generated EC private key");
    println!("OK: wrote key {}", out.display());
    Ok(())
}

/// `foundry cert new-ca` — write a self-signed CA cert + key.
pub fn cert_new_ca(
    common_name: &str,
    out_cert: &Path,
    out_key: &Path,
    days: i64,
) -> anyhow::Result<()> {
    let ca = new_ca(common_name, days)?;
    std::fs::write(out_cert, ca.cert_pem.as_bytes())
        .with_context(|| format!("writing CA cert to {}", out_cert.display()))?;
    std::fs::write(out_key, ca.key_pem.as_bytes())
        .with_context(|| format!("writing CA key to {}", out_key.display()))?;
    tracing::info!(cert = %out_cert.display(), key = %out_key.display(), "generated CA");
    println!(
        "OK: wrote CA cert {} and key {}",
        out_cert.display(),
        out_key.display()
    );
    Ok(())
}

/// `foundry cert issue` — issue a leaf cert (+ its key) signed by the given CA.
pub fn cert_issue(
    ca: &Path,
    key: &Path,
    common_name: &str,
    san_dns: &[String],
    out_cert: &Path,
    out_key: &Path,
    days: i64,
) -> anyhow::Result<()> {
    let ca_cert_pem =
        std::fs::read_to_string(ca).with_context(|| format!("reading CA cert {}", ca.display()))?;
    let ca_key_pem = std::fs::read_to_string(key)
        .with_context(|| format!("reading CA key {}", key.display()))?;
    let leaf = issue_leaf(&ca_cert_pem, &ca_key_pem, common_name, san_dns, days)?;
    std::fs::write(out_cert, leaf.cert_pem.as_bytes())
        .with_context(|| format!("writing leaf cert to {}", out_cert.display()))?;
    std::fs::write(out_key, leaf.key_pem.as_bytes())
        .with_context(|| format!("writing leaf key to {}", out_key.display()))?;
    tracing::info!(cert = %out_cert.display(), key = %out_key.display(), "issued leaf certificate");
    println!(
        "OK: wrote leaf cert {} and key {}",
        out_cert.display(),
        out_key.display()
    );
    Ok(())
}

/// `foundry quickstart` — generate a 2-level dev PKI and a ready-to-run config.
/// DEV/TEST ONLY. Not for production.
pub fn quickstart(dir: &Path, out_config: &Path) -> anyhow::Result<()> {
    let keys_dir = dir.join("keys");
    let trust_dir = dir.join("trust");
    std::fs::create_dir_all(&keys_dir)?;
    std::fs::create_dir_all(&trust_dir)?;

    // Root CA (trust anchor).
    let root = new_ca("Foundry Dev Root CA", 3650)?;
    std::fs::write(trust_dir.join("root.pem"), root.cert_pem.as_bytes())?;
    std::fs::write(trust_dir.join("root-key.pem"), root.key_pem.as_bytes())?;

    // One leaf per named key. Each chain file (x5c) holds just the leaf.
    for (name, cn, san) in [
        ("issuer_sdjwt", "Foundry Dev Issuer", "localhost"),
        ("verifier_signing", "Foundry Dev Verifier", "localhost"),
        ("statuslist_signer", "Foundry Dev Status List", "localhost"),
    ] {
        let leaf = issue_leaf(&root.cert_pem, &root.key_pem, cn, &[san.to_string()], 365)?;
        std::fs::write(
            keys_dir.join(format!("{name}.pem")),
            leaf.key_pem.as_bytes(),
        )?;
        std::fs::write(
            keys_dir.join(format!("{name}-chain.pem")),
            leaf.cert_pem.as_bytes(),
        )?;
    }

    // The Credential Request decryption key is an ECDH-ES key agreement key, not
    // a signing key, so it gets no x5c leaf: OpenID4VCI L1373 publishes it as a
    // bare JWK in `credential_request_encryption.jwks`. Generated unconditionally
    // so enabling the (commented-out) config block needs no extra step; the
    // `keys:` entry's `alg: ES256` names the key material, since
    // `validate_key_material` parses every entry's `alg` as a signature
    // algorithm.
    let enc = generate_ec_key(SignatureAlgorithm::Es256)?;
    std::fs::write(
        keys_dir.join("issuer_request_enc.pem"),
        enc.private_pem.as_bytes(),
    )?;

    std::fs::write(out_config, QUICKSTART_CONFIG.as_bytes())?;

    tracing::warn!("quickstart PKI is DEV/TEST ONLY — do not use in production");
    println!(
        "OK: wrote dev PKI under {} and config {}",
        dir.display(),
        out_config.display()
    );
    println!("   ⚠  DEV/TEST ONLY — self-signed dev PKI, not for production.");
    println!("   Next: foundry serve --config {}", out_config.display());
    Ok(())
}

/// `foundry status-list get` — get status value at index.
pub async fn status_list_get(db: &str, credential_type: &str, index: u64) -> anyhow::Result<()> {
    let storage = SqliteStorage::connect(db)
        .await
        .with_context(|| format!("connecting to database at {db}"))?;
    let list = load_status_list(&storage, credential_type)
        .await
        .with_context(|| format!("loading status list for {credential_type}"))?;
    let status = match list {
        Some(l) => l.get_status(index)?,
        None => StatusValue::Valid,
    };
    let status_name = match status {
        StatusValue::Valid => "valid".to_string(),
        StatusValue::Invalid => "revoked".to_string(),
        StatusValue::Suspended => "suspended".to_string(),
        StatusValue::ApplicationSpecific(v) => format!("{v}"),
    };
    println!("Status: {status_name}");
    Ok(())
}

/// `foundry status-list set` — set status value at index.
pub async fn status_list_set(
    db: &str,
    credential_type: &str,
    index: u64,
    status: &str,
) -> anyhow::Result<()> {
    let storage = SqliteStorage::connect(db)
        .await
        .with_context(|| format!("connecting to database at {db}"))?;
    let mut list = load_status_list(&storage, credential_type)
        .await
        .with_context(|| format!("loading status list for {credential_type}"))?
        .unwrap_or_else(|| PersistentStatusList::new(credential_type, 1_048_576, 2));

    let parsed_status = match status.to_lowercase().as_str() {
        "valid" | "0" => StatusValue::Valid,
        "revoked" | "invalid" | "1" => StatusValue::Invalid,
        "suspended" | "2" => StatusValue::Suspended,
        other => {
            if let Ok(v) = other.parse::<u8>() {
                StatusValue::ApplicationSpecific(v)
            } else {
                anyhow::bail!(
                    "invalid status value '{status}', expected 'valid', 'revoked', or 'suspended'"
                );
            }
        }
    };

    list.set_status(index, parsed_status)?;
    save_status_list(&storage, &list)
        .await
        .with_context(|| format!("saving status list for {credential_type}"))?;

    println!("Updated index {index} for {credential_type} to {status}");
    Ok(())
}

/// `foundry status-list token` — generate and print a signed Status List Token JWT.
pub async fn status_list_token(config_path: &str, credential_type: &str) -> anyhow::Result<()> {
    let cfg = Config::load(Path::new(config_path))
        .with_context(|| format!("loading config from {config_path}"))?;
    let base_dir = Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let storage_path = base_dir.join(&cfg.storage.path);
    let db_str = storage_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid storage path"))?;
    let storage = SqliteStorage::connect(db_str)
        .await
        .with_context(|| format!("connecting to database at {db_str}"))?;

    let persistent_list = load_status_list(&storage, credential_type)
        .await
        .with_context(|| format!("loading status list for {credential_type}"))?
        .unwrap_or_else(|| {
            PersistentStatusList::new(
                credential_type,
                cfg.issuer.status_list.list_size.unwrap_or(1_048_576),
                2,
            )
        });

    let status_list = persistent_list.to_status_list(None)?;

    let base_url = cfg
        .issuer
        .status_list
        .public_base_url
        .as_deref()
        .unwrap_or(&cfg.issuer.credential_issuer);
    let sub = format!("{}/{}", base_url.trim_end_matches('/'), credential_type);

    let key_name = cfg
        .issuer
        .status_list
        .signing_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("issuer.status_list.signing_key is not configured"))?;
    let key_entry = cfg.keys.get(key_name).ok_or_else(|| {
        anyhow::anyhow!("key '{key_name}' referenced by status_list signing_key not found")
    })?;

    let key_file = base_dir.join(&key_entry.private_key);
    let alg = key_entry.alg.parse()?;
    let x5c_file = key_entry.x5c.as_ref().map(|rel| base_dir.join(rel));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("getting system time")?
        .as_secs() as i64;

    let token = foundry_core::status_list::sign_status_list_token(
        &status_list,
        sub,
        now,
        &key_file.to_string_lossy(),
        alg,
        x5c_file.as_deref(),
    )?;
    println!("{token}");
    Ok(())
}

/// Ready-to-run dev config wired to quickstart's key/cert paths (relative to the config dir).
const QUICKSTART_CONFIG: &str = r#"# Foundry dev config generated by `foundry quickstart`.
# ⚠ DEV/TEST ONLY — uses a self-signed dev PKI. Do NOT use in production.
server:
  wallet_facing:
    public_base_url: https://localhost:8443
    bind: 0.0.0.0:8443
  admin:
    bind: 127.0.0.1:9000
    api_key: dev-admin-key
storage:
  path: ./foundry.db
  transaction_ttl_secs: 600
keys:
  issuer_sdjwt:
    private_key: ./keys/issuer_sdjwt.pem
    x5c: ./keys/issuer_sdjwt-chain.pem
    alg: ES256
  verifier_signing:
    private_key: ./keys/verifier_signing.pem
    x5c: ./keys/verifier_signing-chain.pem
    alg: ES256
  statuslist_signer:
    private_key: ./keys/statuslist_signer.pem
    x5c: ./keys/statuslist_signer-chain.pem
    alg: ES256
  issuer_request_enc:
    private_key: ./keys/issuer_request_enc.pem
    alg: ES256
trust_anchors:
  - name: foundry-dev-root
    certs: ./trust/root.pem
issuer:
  credential_issuer: https://localhost:8443
  # The key that signs issued credentials. Optional only for backward
  # compatibility: omitted, foundry falls back to status_list.signing_key and
  # then to the ALPHABETICALLY first `keys:` entry. Always name it -- the
  # fallbacks make one key serve two trust roles, or pick one by accident.
  credential_signing_key: issuer_sdjwt
  wallet_attestation: { mode: optional }
  key_attestation: { mode: optional }
  status_list:
    enabled: true
    # Deliberately the SAME key as credential_signing_key above, not the
    # generated `statuslist_signer`. draft-ietf-oauth-status-list-14 §11.3/§13.5
    # permit a separate Status Issuer key, and foundry's token carries it in the
    # token's own x5c per HAIP L327 -- but the Credo/@sd-jwt wallet stack
    # verifies a Status List Token with the CREDENTIAL ISSUER's key and ignores
    # that x5c, so a divergent signer makes every credential with a `status`
    # claim fail status validation in wallets built on it (e.g. Paradym).
    # `Config::validate` warns when these two differ. The statuslist_signer key
    # is still generated, for a deployment that can diverge; it is unused here.
    signing_key: issuer_sdjwt
    list_size: 1048576
    public_base_url: https://localhost:8443/statuslists
  # OpenID4VCI Credential Request / Response encryption on top of TLS
  # (§Credential Request L848, §Credential Response L960, §Encrypted Messages
  # L1183). Both default to OFF; uncomment to enable. `request_encryption` must
  # be enabled for `response_encryption` to be usable, because L960 requires a
  # request carrying `credential_response_encryption` to itself be encrypted.
  # request_encryption:
  #   keys: [issuer_request_enc]
  #   enc_values_supported: [A128GCM, A256GCM]
  #   encryption_required: false
  # response_encryption:
  #   enc_values_supported: [A128GCM, A256GCM]
  #   encryption_required: false
credential_types:
  - id: pid
    format: dc+sd-jwt
    vct: https://localhost:8443/vct/pid
    # HAIP OpenID4VCI L186/L209: the scope a Wallet uses to request this type.
    # Defaults to the credential type's `id` when omitted; set it explicitly when an
    # Ecosystem mandates a specific value.
    # scope: eu.europa.ec.eudi.pid.1
    cryptographic_holder_binding: true
    display: [{ name: "Person ID", locale: en-US }]
    claims:
      - path: [given_name]
        selectively_disclosable: true
      - path: [birthdate]
        selectively_disclosable: true
  # EMVCo Digital Payment Credential. Reference (not a vendored copy):
  # docs/specs/emvco-dpc-schema-framework.md -- the claim set below is the
  # SD-JWT binding of that specification's disclosable attributes.
  - id: com.emvco.dpc.card
    format: dc+sd-jwt
    # Unlike `pid` above, this vct is a reverse-DNS identifier rather than a URL.
    # The specification fixes this exact string as the canonical credential type,
    # and uses it as the SD-JWT vct, the mdoc docType and the mdoc namespace.
    vct: com.emvco.dpc.card
    cryptographic_holder_binding: true
    # 12 hours, matching the specification's own sample. A credential's lifecycle
    # is independent of the card's.
    validity_seconds: 43200
    # NOTE: status_list is enabled above, so credentials of this type carry a
    # `status` claim that the DPC payload schema does not list (it declares
    # additionalProperties: false). That contradiction is the specification's
    # own -- its security section separately requires status checking -- so
    # revocation is kept rather than dropped to satisfy the schema.
    display:
      # Colours are single-quoted deliberately: a double-quote immediately
      # followed by a hash would terminate the Rust raw-string literal that
      # holds this template, so double-quoted hex colours will not compile.
      - { locale: en-US, name: "Payment Card", background_color: '#1A1A2E', text_color: '#FFFFFF' }
      - { locale: de-DE, name: "Zahlungskarte", background_color: '#1A1A2E', text_color: '#FFFFFF' }
      - { locale: fr-FR, name: "Carte de paiement", background_color: '#1A1A2E', text_color: '#FFFFFF' }
    claims:
      # credential_id and network are mandatory in the DPC payload schema AND
      # selectively disclosable, which is why `required` is a field separate
      # from `selectively_disclosable`.
      - path: [credential_id]
        required: true
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Credential ID" }
          - { locale: de-DE, name: "Credential-ID" }
          - { locale: fr-FR, name: "Identifiant du justificatif" }
      # A single string for one network, or an array for co-badged cards.
      - path: [network]
        required: true
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Payment Network" }
          - { locale: de-DE, name: "Zahlungsnetzwerk" }
          - { locale: fr-FR, name: "Reseau de paiement" }
      - path: [card_id]
        selectively_disclosable: true
        display:
          - { locale: en-US, name: "Card Identifier" }
          - { locale: de-DE, name: "Karten-ID" }
          - { locale: fr-FR, name: "Identifiant de carte" }
    # PaSO Proof Metadata 3 -- declaring `transaction_data_types` is what makes
    # this a PaSO Credential type. Its presence alone turns on the
    # `credential_metadata_uri` in Issuer Metadata and the wallet-facing
    # `GET /credential-metadata/com.emvco.dpc.card`, which content-negotiates
    # between plain JSON and a signed `credential-metadata+jwt` (2, 4).
    # Remove this block and every byte of existing wire output is unchanged.
    #
    # The identifier grammar is PaSO Core 5.2:
    # `urn:paso:sca:<domain>:<suffix>:<version>`, the version a positive integer
    # without leading zeros and always the final segment. Config::validate()
    # enforces it, so a typo here is a startup failure rather than a
    # wallet-facing one.
    transaction_data_types:
      "urn:paso:sca:global:payment:1":
        claims:
          - path: [transaction_id]
            mandatory: true
          - path: [amount]
            mandatory: true
            value_type: iso_currency_amount
            display:
              - { locale: en, name: Amount }
              - { locale: de, name: Betrag }
          - path: [payee, name]
            mandatory: true
            display:
              - { locale: en, name: Payee }
              - { locale: de, name: Empfaenger }
        ui_labels:
          affirmative_action_label:
            - { locale: en, value: Confirm Payment }
            - { locale: de, value: Zahlung bestaetigen }
  # EUDI Proof of Age attestation, and the only mso_mdoc type this issuer mints.
  # Governed by docs/specs/eu-age-verification-annex-a-av-profile.md -- EU Age
  # Verification Solution Technical Specification, Annex A (normative).
  - id: eu.europa.ec.av.1
    format: mso_mdoc
    # Annex A 4.1.1: "The document type for Proof of Age attestation SHALL be
    # `eu.europa.ec.av.1`." Deliberately no `vct` -- that is an SD-JWT-VC
    # identifier and Config::validate() rejects it on an mso_mdoc type
    # (OpenID4VCI L2235). 4.1.2 puts the attributes in a namespace equal to the
    # doctype, which foundry resolves in code rather than from config.
    doctype: eu.europa.ec.av.1
    cryptographic_holder_binding: true
    # 90 days, matching Annex A A.11's example validity window. The MSO's
    # validFrom equals its signed time, so this is a relative lifetime -- the
    # profile specifies no absolute window.
    validity_seconds: 7776000
    display:
      - { name: "Proof of Age", locale: en-US }
      - { name: "Altersnachweis", locale: de-DE }
    # Annex A 4.1.2 defines exactly two attributes, both `bool`, then closes the
    # set: "A Proof of Age Attestation SHALL NOT include any other attribute."
    # Config::validate() enforces that, so adding a claim here -- an issue_date,
    # an issuing_country -- is a startup failure, not a silent divergence.
    #
    # `selectively_disclosable` is deliberately unset: every IssuerSignedItem is
    # inherently selectively disclosable, so the flag has no meaning for mdoc.
    # That is why `required` is stated explicitly rather than left to its
    # `!selectively_disclosable` default, which would make the
    # mandatory/optional distinction depend on a flag that does not apply here.
    claims:
      - path: [age_over_18]
        required: true
      - path: [age_over_16]
        required: false
verifier:
  # The Client Identifier Prefix is not configurable: HAIP OpenID4VP L256 mandates
  # `x509_hash` for signed requests, so it is always derived from the `x5c` leaf of
  # `verifier.signing_key`.
  signing_key: verifier_signing
  response_encryption: { alg: ECDH-ES, enc: A128GCM }
  transaction_data_hashes_alg: [sha-256]
  # OpenID4VP L2543 / IETF SD-JWT VC Presentation Response L3179: over the DC
  # API transport the KB-JWT audience MUST be the browsing-context Origin
  # prefixed with `origin:`, not this verifier's own Client Identifier -- an
  # Origin is unknowable from `server.wallet_facing.public_base_url` alone
  # (RFC 6454), so it must be listed explicitly for every site expected to
  # invoke this verifier over the DC API. Left empty (the default), a single
  # origin derived from `public_base_url` is accepted instead, which keeps an
  # unconfigured single-origin deployment working but is only appropriate
  # when the DC API caller and this server share an origin.
  # dc_api_expected_origins: ["https://wallet-relying-party.example"]
  # OpenID4VP draft 24 Appendix A.2 spelled that same audience
  # `web-origin:<origin>`; 1.0 renamed the prefix to `origin:`. Wallets still
  # implementing draft 24 (real Google Wallet, as of 2026-08) therefore fail
  # with "KB-JWT audience mismatch" even when the Origin above is correct.
  # Enable the line below to also accept the draft-24 spelling. It relaxes the
  # PREFIX only -- the Origin is still matched against the list above, so no
  # additional Origin becomes acceptable. Off by default, because accepting a
  # superseded draft's audience unconditionally would make every deployment
  # deviate from L2543 silently.
  # dc_api_accept_legacy_web_origin_audience: true
  #
  # Deliver verification events to an operator-owned endpoint. Absent (the
  # default) means no sink is constructed and nothing changes.
  # `include_raw_artifacts` is a SECOND gate, off by default: it authorises the
  # verbatim Request Object and the decrypted vp_token -- holder PII in the
  # clear -- to leave this process. Foundry stores none of it.
  # The url must be https, unless its host is a loopback address.
  # webhook:
  #   url: https://audit.example.com/vp-callback
  #   secret_env: FOUNDRY_WEBHOOK_SECRET
  #   timeout_secs: 5
  #   include_raw_artifacts: false
  named_queries:
    # `credentials` must be non-empty (OpenID4VP 1.0 §6, enforced when a
    # verification request is created). The shipped `pid` type has no
    # `age_equal_or_over` claim, so an age check requests `birthdate` and the
    # verifier derives the age itself.
    - id: over18
      dcql:
        credentials:
          - id: pid
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/pid"] }
            claims:
              - path: [birthdate]
    # Demonstrates DCQL `credential_sets` (OpenID4VP 1.0 L879-L894): a payment
    # credential (either of two), an age assertion (either of two), and an
    # optional loyalty card. `dpc_card` and `pid` are the two credential types
    # this issuer actually mints, so a wallet holding both satisfies each
    # required set via its FIRST option. `visa_card`, `av` and `loyalty` name
    # vcts this issuer does NOT mint; they exist to exercise the alternative and
    # optional branches, and a wallet will simply never answer them.
    - id: payment-age-loyalty
      dcql:
        credentials:
          - id: dpc_card
            format: dc+sd-jwt
            meta: { vct_values: ["com.emvco.dpc.card"] }
          - id: visa_card
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/visa"] }
          - id: pid
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/pid"] }
            claims:
              - path: [birthdate]
          - id: av
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/av"] }
          - id: loyalty
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/loyalty"] }
        credential_sets:
          - options: [[dpc_card], [visa_card]]
          - options: [[pid], [av]]
          - options: [[loyalty]]
            required: false

    # The mdoc counterpart to `over18` above. An mdoc claims path is
    # [namespace, element], and for this doctype the namespace equals the
    # doctype (Annex A 4.1.2). `doctype_value` is REQUIRED in an mso_mdoc
    # Credential Query's `meta` (OpenID4VP L2802).
    - id: over18_mdoc
      dcql:
        credentials:
          - id: av
            format: mso_mdoc
            meta: { doctype_value: eu.europa.ec.av.1 }
            claims:
              - path: [eu.europa.ec.av.1, age_over_18]"#;
