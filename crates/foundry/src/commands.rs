//! Thin CLI command handlers: parse-free logic that calls foundry-core and does file IO.

use anyhow::Context;
use foundry_core::config::Config;
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::pki::{generate_ec_key, issue_leaf, new_ca};
use foundry_core::status_list::{
    load_status_list, save_status_list, PersistentStatusList, StatusValue,
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
        x5c_file.as_deref().and_then(|p| p.to_str()),
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
trust_anchors:
  - name: foundry-dev-root
    certs: ./trust/root.pem
issuer:
  credential_issuer: https://localhost:8443
  wallet_attestation: { mode: optional }
  key_attestation: { mode: optional }
  status_list:
    enabled: true
    signing_key: statuslist_signer
    list_size: 1048576
    public_base_url: https://localhost:8443/statuslists
credential_types:
  - id: pid
    format: dc+sd-jwt
    vct: https://localhost:8443/vct/pid
    cryptographic_holder_binding: true
    display: [{ name: "Person ID", locale: en-US }]
    claims:
      - path: [given_name]
        selectively_disclosable: true
      - path: [birthdate]
        selectively_disclosable: true
verifier:
  client_id_scheme: x509_san_dns
  signing_key: verifier_signing
  response_encryption: { alg: ECDH-ES, enc: A128GCM }
  transaction_data_hashes_alg: [sha-256]
  named_queries:
    - id: over18
      dcql: { credentials: [] }
"#;
