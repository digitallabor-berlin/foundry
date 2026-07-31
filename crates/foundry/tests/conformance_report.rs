//! Mechanical consistency guard over `docs/conformance/openid4vc-conformance.md`.
//!
//! The conformance report is a living document (see `AGENTS.md` §4.4 and §8):
//! follow-up work closes gaps by editing rows in place. Nothing but a test can
//! keep its cross-references honest over that lifetime, so this file enforces
//! them:
//!
//! - clause identifiers are well-formed, unique, and ascending;
//! - every verdict is one of the seven legal values;
//! - `gap` clauses and gap-register entries reference each other in both
//!   directions — no orphans either way;
//! - every gap-register entry names a test that exists and is `#[ignore]`d
//!   citing that same gap identifier;
//! - every `#[ignore = "GAP-..."]` in the workspace cites a registered gap;
//! - the summary counts equal the actual row counts.
//!
//! This test is deliberately written to pass against an *empty* report, so the
//! scaffold is valid before any clause has been extracted.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const REPORT_REL: &str = "docs/conformance/openid4vc-conformance.md";

const VERDICTS: [&str; 7] = [
    "conforming",
    "gap",
    "not-implemented",
    "not-unit-testable",
    "out-of-scope",
    "ambiguous",
    "unverified",
];

/// Verdicts that must carry an explanation in the `Evidence` column, so that a
/// non-conforming or excluded clause never sits in the report unexplained.
const VERDICTS_REQUIRING_RATIONALE: [&str; 4] = [
    "not-implemented",
    "not-unit-testable",
    "out-of-scope",
    "ambiguous",
];

const APPLIES_TO: [&str; 5] = ["issuer", "verifier", "http", "wallet", "other"];

const SEVERITIES: [&str; 3] = ["Critical", "Important", "Minor"];

const INVENTORY_HEADINGS: [(&str, &str); 3] = [
    ("OpenID4VCI", "## Clause Inventory — OpenID4VCI"),
    ("OpenID4VP", "## Clause Inventory — OpenID4VP"),
    ("HAIP", "## Clause Inventory — HAIP"),
];

const ID_PREFIX_FOR_SPEC: [(&str, &str); 3] =
    [("OpenID4VCI", "VCI"), ("OpenID4VP", "VP"), ("HAIP", "HAIP")];

// ---------------------------------------------------------------------------
// Repository access
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<root>/crates/foundry`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("resolve repository root")
}

fn report_text() -> String {
    let path = repo_root().join(REPORT_REL);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("conformance report missing at {}: {e}", path.display()))
}

/// Every `.rs` file in the workspace, so test-name and `#[ignore]` scanning
/// covers both inline `#[cfg(test)]` modules and `tests/` directories.
fn rust_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rs(&repo_root().join("crates"), &mut out);
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Markdown table parsing
// ---------------------------------------------------------------------------

/// Rows of the first pipe table appearing after `heading`, as trimmed cells.
/// The header and separator rows are dropped.
fn table_after(text: &str, heading: &str) -> Vec<Vec<String>> {
    let mut lines = text.lines();
    let found = lines.any(|l| l.trim_end() == heading);
    assert!(found, "report is missing required heading: {heading}");

    let mut rows = Vec::new();
    let mut seen_table = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with('|') {
            seen_table = true;
            let cells = split_row(trimmed);
            if is_separator(&cells) {
                continue;
            }
            rows.push(cells);
        } else if seen_table && !trimmed.is_empty() {
            break; // table ended
        } else if trimmed.starts_with("## ") {
            break; // next section, table never started
        }
    }

    if rows.is_empty() {
        return rows;
    }
    rows.remove(0); // header row
    rows
}

fn split_row(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    inner.split('|').map(|c| c.trim().to_string()).collect()
}

fn is_separator(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

fn cell(row: &[String], idx: usize) -> String {
    row.get(idx).cloned().unwrap_or_default()
}

/// Strip markdown emphasis and backticks so `` `gap` `` compares equal to `gap`.
fn plain(value: &str) -> String {
    value.trim().trim_matches('`').trim().to_string()
}

// ---------------------------------------------------------------------------
// Domain rows
// ---------------------------------------------------------------------------

struct Clause {
    spec: &'static str,
    id: String,
    section: String,
    requirement: String,
    applies_to: String,
    verdict: String,
    evidence: String,
    test: String,
}

fn clauses(text: &str) -> Vec<Clause> {
    let mut out = Vec::new();
    for (spec, heading) in INVENTORY_HEADINGS {
        for row in table_after(text, heading) {
            out.push(Clause {
                spec,
                id: plain(&cell(&row, 0)),
                section: plain(&cell(&row, 1)),
                requirement: cell(&row, 2),
                applies_to: plain(&cell(&row, 3)),
                verdict: plain(&cell(&row, 4)),
                evidence: cell(&row, 5),
                test: plain(&cell(&row, 6)),
            });
        }
    }
    out
}

struct Gap {
    id: String,
    severity: String,
    section: String,
    requirement: String,
    impact: String,
    test: String,
}

fn gaps(text: &str) -> Vec<Gap> {
    table_after(text, "## Gap Register")
        .into_iter()
        .map(|row| Gap {
            id: plain(&cell(&row, 0)),
            severity: plain(&cell(&row, 1)),
            section: cell(&row, 2),
            requirement: cell(&row, 3),
            impact: cell(&row, 4),
            test: plain(&cell(&row, 5)),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Identifier helpers
// ---------------------------------------------------------------------------

/// `VCI-0042` -> `("VCI", 42)`.
fn parse_clause_id(id: &str) -> Option<(String, u32)> {
    let (prefix, digits) = id.rsplit_once('-')?;
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !matches!(prefix, "VCI" | "VP" | "HAIP") {
        return None;
    }
    Some((prefix.to_string(), digits.parse().ok()?))
}

fn is_gap_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("GAP-") else {
        return false;
    };
    let Some((area, num)) = rest.rsplit_once('-') else {
        return false;
    };
    !area.is_empty()
        && area
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && !num.is_empty()
        && num.chars().all(|c| c.is_ascii_digit())
}

/// Every `GAP-AREA-NN` token appearing in `text`.
fn gap_ids_in(text: &str) -> Vec<String> {
    let bytes: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(&['G', 'A', 'P', '-']) {
            let mut j = i + 4;
            while j < bytes.len()
                && (bytes[j].is_ascii_uppercase() || bytes[j].is_ascii_digit() || bytes[j] == '-')
            {
                j += 1;
            }
            let candidate: String = bytes[i..j].iter().collect();
            let candidate = candidate.trim_end_matches('-').to_string();
            if is_gap_id(&candidate) {
                out.push(candidate);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Source scanning
// ---------------------------------------------------------------------------

/// Test function names in the workspace, and for each, the gap IDs cited by an
/// `#[ignore = "..."]` attribute attached to it.
fn test_functions() -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in rust_sources() {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed != "#[test]" && trimmed != "#[tokio::test]" {
                continue;
            }
            let mut ignored_gaps = Vec::new();
            for probe in lines.iter().skip(idx + 1).take(8) {
                let probe = probe.trim();
                if probe.starts_with("#[ignore") {
                    ignored_gaps.extend(gap_ids_in(probe));
                }
                if let Some(name) = fn_name(probe) {
                    out.insert(name, ignored_gaps.clone());
                    break;
                }
                if !probe.starts_with('#') && !probe.is_empty() && !probe.starts_with("//") {
                    break;
                }
            }
        }
    }
    out
}

fn fn_name(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("async fn ")
        .or_else(|| line.strip_prefix("fn "))
        .or_else(|| line.strip_prefix("pub fn "))
        .or_else(|| line.strip_prefix("pub async fn "))?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Every gap ID cited by any `#[ignore = "..."]` anywhere in the workspace,
/// paired with the file it came from for a legible failure message.
fn ignored_gap_citations() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for path in rust_sources() {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("#[ignore") {
                for id in gap_ids_in(trimmed) {
                    out.push((id, path.clone()));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn report_exists_with_all_required_headings() {
    let text = report_text();
    for heading in [
        "## Specifications Under Audit",
        "## Audit Boundary",
        "## Legend — Verdicts",
        "## Legend — Severity",
        "## Summary",
        "## Gap Register",
        "## Clause Inventory — OpenID4VCI",
        "## Clause Inventory — OpenID4VP",
        "## Clause Inventory — HAIP",
        "## Unresolved Ambiguities",
    ] {
        assert!(
            text.lines().any(|l| l.trim_end() == heading),
            "conformance report is missing required heading: {heading}"
        );
    }
}

#[test]
fn clause_ids_are_wellformed_unique_and_ascending() {
    let text = report_text();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut last_per_spec: BTreeMap<&str, u32> = BTreeMap::new();

    for clause in clauses(&text) {
        let (prefix, number) = parse_clause_id(&clause.id).unwrap_or_else(|| {
            panic!(
                "clause id `{}` in the {} inventory is malformed; expected VCI-NNNN, VP-NNNN or HAIP-NNNN",
                clause.id, clause.spec
            )
        });

        let expected_prefix = ID_PREFIX_FOR_SPEC
            .iter()
            .find(|(spec, _)| *spec == clause.spec)
            .map(|(_, p)| *p)
            .expect("known spec");
        assert_eq!(
            prefix, expected_prefix,
            "clause `{}` sits in the {} inventory but carries the `{prefix}` prefix",
            clause.id, clause.spec
        );

        assert!(
            seen.insert(clause.id.clone()),
            "duplicate clause id: {}",
            clause.id
        );

        let last = last_per_spec.entry(clause.spec).or_insert(0);
        assert!(
            number > *last,
            "clause ids must ascend within the {} inventory: {} follows {:04}",
            clause.spec,
            clause.id,
            last
        );
        *last = number;
    }
}

#[test]
fn every_clause_has_a_legal_verdict_and_applies_to() {
    let text = report_text();
    for clause in clauses(&text) {
        assert!(
            VERDICTS.contains(&clause.verdict.as_str()),
            "clause {} has illegal verdict `{}`; legal verdicts are {:?}",
            clause.id,
            clause.verdict,
            VERDICTS
        );
        assert!(
            APPLIES_TO.contains(&clause.applies_to.as_str()),
            "clause {} has illegal `Applies to` value `{}`; legal values are {:?}",
            clause.id,
            clause.applies_to,
            APPLIES_TO
        );
        assert!(
            !clause.section.is_empty(),
            "clause {} does not cite a spec section",
            clause.id
        );
        assert!(
            !clause.requirement.trim().is_empty(),
            "clause {} has an empty requirement",
            clause.id
        );
    }
}

#[test]
fn verdicts_requiring_rationale_have_one() {
    let text = report_text();
    for clause in clauses(&text) {
        if VERDICTS_REQUIRING_RATIONALE.contains(&clause.verdict.as_str()) {
            assert!(
                !clause.evidence.trim().is_empty(),
                "clause {} is `{}` but records no rationale in its Evidence column",
                clause.id,
                clause.verdict
            );
        }
        if clause.verdict == "conforming" {
            assert!(
                !clause.evidence.trim().is_empty(),
                "clause {} is `conforming` but cites no code evidence",
                clause.id
            );
            assert!(
                !clause.test.is_empty(),
                "clause {} is `conforming` but cites no proving test",
                clause.id
            );
        }
    }
}

#[test]
fn gap_clauses_and_gap_register_reference_each_other() {
    let text = report_text();
    let register: BTreeSet<String> = gaps(&text).into_iter().map(|g| g.id).collect();
    let mut cited: BTreeSet<String> = BTreeSet::new();

    for clause in clauses(&text) {
        if clause.verdict != "gap" {
            continue;
        }
        let ids = gap_ids_in(&clause.evidence);
        assert!(
            !ids.is_empty(),
            "clause {} is a `gap` but its Evidence column cites no GAP-* identifier",
            clause.id
        );
        for id in ids {
            assert!(
                register.contains(&id),
                "clause {} cites {id}, which has no row in the gap register",
                clause.id
            );
            cited.insert(id);
        }
    }

    for id in &register {
        assert!(
            cited.contains(id),
            "gap register entry {id} is not referenced by any clause with verdict `gap`"
        );
    }
}

#[test]
fn gap_register_rows_are_complete_and_well_formed() {
    let text = report_text();
    let mut seen = BTreeSet::new();
    for gap in gaps(&text) {
        assert!(
            is_gap_id(&gap.id),
            "malformed gap identifier `{}`; expected GAP-AREA-NN",
            gap.id
        );
        assert!(seen.insert(gap.id.clone()), "duplicate gap id: {}", gap.id);
        assert!(
            SEVERITIES.contains(&gap.severity.as_str()),
            "gap {} has illegal severity `{}`; legal severities are {:?}",
            gap.id,
            gap.severity,
            SEVERITIES
        );
        assert!(
            !gap.section.trim().is_empty(),
            "gap {} does not cite a spec section",
            gap.id
        );
        assert!(
            !gap.requirement.trim().is_empty(),
            "gap {} has an empty requirement",
            gap.id
        );
        assert!(
            !gap.impact.trim().is_empty(),
            "gap {} records no impact",
            gap.id
        );
        assert!(
            !gap.test.is_empty(),
            "gap {} names no test; every gap must have an executable record",
            gap.id
        );
    }
}

#[test]
fn every_test_named_by_the_report_exists() {
    let text = report_text();
    let known = test_functions();

    for gap in gaps(&text) {
        assert!(
            known.contains_key(&gap.test),
            "gap {} names test `{}`, which does not exist in the workspace",
            gap.id,
            gap.test
        );
    }

    for clause in clauses(&text) {
        if clause.test.is_empty() {
            continue;
        }
        for name in clause
            .test
            .split(',')
            .map(|n| n.trim())
            .filter(|n| !n.is_empty())
        {
            assert!(
                known.contains_key(name),
                "clause {} names test `{name}`, which does not exist in the workspace",
                clause.id
            );
        }
    }
}

#[test]
fn every_gap_test_is_ignored_citing_its_own_gap_id() {
    let text = report_text();
    let known = test_functions();

    for gap in gaps(&text) {
        let Some(cited) = known.get(&gap.test) else {
            continue; // covered by `every_test_named_by_the_report_exists`
        };
        assert!(
            cited.contains(&gap.id),
            "test `{}` records gap {} but is not annotated \
             `#[ignore = \"{}: ...\"]`; an open gap must not appear to pass",
            gap.test,
            gap.id,
            gap.id
        );
    }
}

#[test]
fn every_ignored_gap_citation_is_registered() {
    let text = report_text();
    let register: BTreeSet<String> = gaps(&text).into_iter().map(|g| g.id).collect();

    for (id, path) in ignored_gap_citations() {
        assert!(
            register.contains(&id),
            "{} cites {id} in an #[ignore] attribute, but the gap register has no such entry",
            path.display()
        );
    }
}

#[test]
fn ambiguous_clauses_are_listed_under_unresolved_ambiguities() {
    let text = report_text();
    let listed: BTreeSet<String> = table_after(&text, "## Unresolved Ambiguities")
        .into_iter()
        .map(|row| plain(&cell(&row, 0)))
        .collect();

    let mut ambiguous = BTreeSet::new();
    for clause in clauses(&text) {
        if clause.verdict == "ambiguous" {
            assert!(
                listed.contains(&clause.id),
                "clause {} is `ambiguous` but is absent from the Unresolved Ambiguities table",
                clause.id
            );
            ambiguous.insert(clause.id);
        }
    }

    for id in listed {
        assert!(
            ambiguous.contains(&id),
            "{id} is listed under Unresolved Ambiguities but its clause verdict is not `ambiguous`"
        );
    }
}

#[test]
fn summary_counts_match_the_inventories() {
    let text = report_text();
    let all = clauses(&text);

    for row in table_after(&text, "## Summary") {
        let spec = plain(&cell(&row, 0));
        let rows: Vec<&Clause> = all.iter().filter(|c| c.spec == spec).collect();

        let declared_total: usize = plain(&cell(&row, 1))
            .parse()
            .unwrap_or_else(|_| panic!("summary total for {spec} is not a number"));
        assert_eq!(
            declared_total,
            rows.len(),
            "summary claims {declared_total} {spec} clauses, inventory has {}",
            rows.len()
        );

        for (offset, verdict) in VERDICTS.iter().enumerate() {
            let declared: usize = plain(&cell(&row, 2 + offset))
                .parse()
                .unwrap_or_else(|_| panic!("summary `{verdict}` count for {spec} is not a number"));
            let actual = rows.iter().filter(|c| c.verdict == *verdict).count();
            assert_eq!(
                declared, actual,
                "summary claims {declared} `{verdict}` {spec} clauses, inventory has {actual}"
            );
        }
    }
}
