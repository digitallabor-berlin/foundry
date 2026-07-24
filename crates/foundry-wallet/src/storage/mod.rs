//! On-disk wallet data directory: `keys/`, `credentials/<id>/`, `trust/`,
//! `log/`. See docs/superpowers/specs/2026-07-24-foundry-wallet-cli-design.md
//! section 5.

pub mod credential_store;
pub mod event_log;

use crate::error::{WalletError, WalletResult};
use std::path::Path;

/// Create `keys/`, `credentials/`, `trust/`, `log/` under `data_dir` if they
/// don't already exist. Safe to call repeatedly.
pub fn ensure_data_dir_layout(data_dir: &Path) -> WalletResult<()> {
    for sub in ["keys", "credentials", "trust", "log"] {
        let dir = data_dir.join(sub);
        std::fs::create_dir_all(&dir).map_err(|e| WalletError::Storage {
            path: dir.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}

/// Current UTC time as RFC3339, used for event timestamps and
/// `metadata.json`'s `received_at`.
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_data_dir_layout_creates_all_four_subdirs() {
        let dir = tempfile::tempdir().unwrap();
        ensure_data_dir_layout(dir.path()).unwrap();
        for sub in ["keys", "credentials", "trust", "log"] {
            assert!(dir.path().join(sub).is_dir(), "missing {sub}");
        }
    }

    #[test]
    fn ensure_data_dir_layout_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        ensure_data_dir_layout(dir.path()).unwrap();
        ensure_data_dir_layout(dir.path()).unwrap(); // must not error the 2nd time
    }

    #[test]
    fn now_rfc3339_produces_a_parseable_timestamp() {
        let ts = now_rfc3339();
        assert!(ts.contains('T'));
        assert!(
            time::OffsetDateTime::parse(&ts, &time::format_description::well_known::Rfc3339)
                .is_ok()
        );
    }
}
