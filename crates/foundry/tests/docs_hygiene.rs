//! Enforces the absolute-URL rule for documentation links that MkDocs cannot
//! check. `docs/specs/` and `docs/superpowers/` are excluded from the built
//! site via `exclude_docs`. MkDocs handles a link pointing INTO an excluded
//! tree by capping the log level — `warning_level = min(logging.INFO,
//! validation.links.not_found)` — so it emits INFO and `--strict` does not
//! abort. No config key promotes it. Confirmed empirically; see
//! `docs/superpowers/specs/2026-08-27-mkdocs-manual-design.md` §3.
//!
//! Consequence: such a link renders as a dead href in the published site with
//! CI green. Since root `AGENTS.md` §4.4 makes spec citation normative, this
//! test is the enforcement mechanism.

use std::fs;
use std::path::{Path, PathBuf};

/// Repository root, derived from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root must exist")
}

/// Every markdown file that MkDocs builds into a page.
fn built_pages(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("docs")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // The two trees excluded from the built site, plus dotdirs
                // (MkDocs excludes `.*` implicitly) and the local venv.
                if name == "specs" || name == "superpowers" || name.starts_with('.') {
                    continue;
                }
                stack.push(path);
            } else if name.ends_with(".md") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn built_pages_do_not_link_into_excluded_trees() {
    let root = repo_root();
    let pages = built_pages(&root);
    assert!(
        !pages.is_empty(),
        "found no built markdown pages under docs/ — the walk is broken"
    );

    let mut offences = Vec::new();
    for page in &pages {
        let text = fs::read_to_string(page).expect("page must be readable");
        let rel = page.strip_prefix(&root).unwrap_or(page).display();
        for (lineno, line) in text.lines().enumerate() {
            for target in link_targets(line) {
                if target.starts_with("http://") || target.starts_with("https://") {
                    continue;
                }
                let normalised = target.trim_start_matches("./");
                let hits_excluded = normalised
                    .split('/')
                    .any(|seg| seg == "specs" || seg == "superpowers");
                if hits_excluded {
                    offences.push(format!(
                        "{rel}:{}: relative link `{target}` points into a tree \
                         excluded from the built site. MkDocs logs this at INFO \
                         only, so --strict will not catch it. Use an absolute \
                         URL: https://github.com/digitallabor-berlin/foundry/\
                         blob/main/docs/{normalised}",
                        lineno + 1
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "{} documentation link(s) into excluded trees:\n{}",
        offences.len(),
        offences.join("\n")
    );
}

/// Extract each markdown inline-link target from one line.
fn link_targets(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b']'
            && bytes[i + 1] == b'('
            && let Some(end) = line[i + 2..].find(')')
        {
            let target = &line[i + 2..i + 2 + end];
            // Ignore pure fragments — those are validated by
            // `validation.links.anchors: warn` in mkdocs.yml.
            if !target.starts_with('#') && !target.is_empty() {
                out.push(target.to_string());
            }
            i = i + 2 + end;
            continue;
        }
        i += 1;
    }
    out
}
