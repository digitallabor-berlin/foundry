//! Append-only JSONL event log at `<data_dir>/log/events.jsonl`. Every
//! outbound HTTP request/response and every wallet-level decision
//! (credential stored, consent decision, trust validation failure) is logged
//! here for human review — see the design doc section 8 for the event shapes.

use crate::error::{WalletError, WalletResult};
use serde_json::Value;
use std::io::{BufRead, Write};
use std::path::Path;

fn log_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("log").join("events.jsonl")
}

pub fn append_event(data_dir: &Path, event: &Value) -> WalletResult<()> {
    let path = log_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| WalletError::Storage {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| WalletError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;
    writeln!(file, "{}", serde_json::to_string(event)?).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

pub fn read_events(data_dir: &Path) -> WalletResult<Vec<Value>> {
    let path = log_path(data_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(&path).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })?;
    let reader = std::io::BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| WalletError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}

/// The last `n` events (fewer if the log is shorter), oldest-first.
pub fn tail_events(data_dir: &Path, n: usize) -> WalletResult<Vec<Value>> {
    let mut all = read_events(data_dir)?;
    if all.len() > n {
        all = all.split_off(all.len() - n);
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_then_read_round_trips_events_in_order() {
        let dir = tempfile::tempdir().unwrap();
        append_event(dir.path(), &serde_json::json!({"kind": "a"})).unwrap();
        append_event(dir.path(), &serde_json::json!({"kind": "b"})).unwrap();

        let events = read_events(dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["kind"], "a");
        assert_eq!(events[1]["kind"], "b");
    }

    #[test]
    fn read_events_on_missing_log_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_events(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn tail_events_returns_only_the_last_n() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            append_event(dir.path(), &serde_json::json!({"i": i})).unwrap();
        }
        let tail = tail_events(dir.path(), 2).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0]["i"], 3);
        assert_eq!(tail[1]["i"], 4);
    }
}
