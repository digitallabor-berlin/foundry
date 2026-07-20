//! Thin CLI command handlers: parse-free logic that calls foundry-core and does file IO.

use anyhow::Context;
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::pki::{generate_ec_key, issue_leaf, new_ca};
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
    println!("OK: wrote CA cert {} and key {}", out_cert.display(), out_key.display());
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
    let ca_cert_pem = std::fs::read_to_string(ca)
        .with_context(|| format!("reading CA cert {}", ca.display()))?;
    let ca_key_pem = std::fs::read_to_string(key)
        .with_context(|| format!("reading CA key {}", key.display()))?;
    let leaf = issue_leaf(&ca_cert_pem, &ca_key_pem, common_name, san_dns, days)?;
    std::fs::write(out_cert, leaf.cert_pem.as_bytes())
        .with_context(|| format!("writing leaf cert to {}", out_cert.display()))?;
    std::fs::write(out_key, leaf.key_pem.as_bytes())
        .with_context(|| format!("writing leaf key to {}", out_key.display()))?;
    tracing::info!(cert = %out_cert.display(), key = %out_key.display(), "issued leaf certificate");
    println!("OK: wrote leaf cert {} and key {}", out_cert.display(), out_key.display());
    Ok(())
}
