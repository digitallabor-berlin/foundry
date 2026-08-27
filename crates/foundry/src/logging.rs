//! Subscriber setup and log-setting resolution.
//!
//! Three sources can specify how the process logs, and they are resolved in a
//! fixed order, highest priority first:
//!
//! 1. the `RUST_LOG` environment variable (level only)
//! 2. the `--log-level` / `--log-format` / `--log-sensitive` CLI flags
//! 3. the `logging:` section of the config file
//! 4. built-in defaults — `info`, `human`, payloads locked
//!
//! The `resolve_*` functions take every source as a parameter rather than
//! reading the environment themselves, so the table above is unit-testable
//! without mutating process state.

use crate::cli::LogFormat;
use foundry_core::config::{LogFormat as CfgFormat, LoggingConfig};
use tracing_subscriber::{EnvFilter, fmt};

/// Level applied when no source specifies one, and when a supplied directive
/// cannot be parsed.
const DEFAULT_LEVEL: &str = "info";

/// Resolve the log filter directive. `env` is `RUST_LOG`'s value, if set.
///
/// An `env` value that is empty or whitespace-only counts as unset: exporting
/// `RUST_LOG=` is a common way to clear the variable, and honouring it as a
/// directive would silence the process.
pub fn resolve_level(env: Option<&str>, cli: Option<&str>, cfg: Option<&LoggingConfig>) -> String {
    if let Some(env) = env.filter(|v| !v.trim().is_empty()) {
        return env.to_string();
    }
    if let Some(cli) = cli.filter(|v| !v.trim().is_empty()) {
        return cli.to_string();
    }
    cfg.map(|c| c.level.clone())
        .unwrap_or_else(|| DEFAULT_LEVEL.to_string())
}

/// Resolve the output format. There is no environment tier for this one.
pub fn resolve_format(cli: Option<LogFormat>, cfg: Option<&LoggingConfig>) -> CfgFormat {
    if let Some(cli) = cli {
        return cli.into();
    }
    cfg.map(|c| c.format).unwrap_or_default()
}

/// Resolve whether payload-bearing log fields are unlocked.
///
/// `--log-sensitive` is one-way: passing it turns payloads on, and omitting it
/// defers to the config rather than forcing them off. A bare boolean flag cannot
/// express "explicitly off", and inventing a `--no-log-sensitive` to close that
/// gap would only add a way to argue with a config file that already defaults to
/// locked.
pub fn resolve_sensitive(cli: bool, cfg: Option<&LoggingConfig>) -> bool {
    cli || cfg.map(|c| c.sensitive_payloads).unwrap_or(false)
}

/// Build the `EnvFilter` for a directive, reporting whether it had to fall back.
///
/// A malformed directive must not take the process down and must not yield an
/// empty filter that silently hides every log line, so it degrades to
/// [`DEFAULT_LEVEL`]. The `bool` lets the caller say so out loud.
///
/// **This catches syntax errors, not typos.** `EnvFilter` is lenient: anything
/// that parses as a target name is accepted, so `--log-level infoo` or
/// `--log-level garbage!!=` builds a perfectly valid filter that happens to
/// match no target in this workspace — the process then logs nothing at all and
/// no warning is possible, because nothing went wrong as far as the filter is
/// concerned. A silent log is therefore a directive to re-read before it is a
/// bug to report.
pub fn build_filter(level: &str) -> (EnvFilter, bool) {
    match EnvFilter::try_new(level) {
        Ok(filter) => (filter, false),
        Err(_) => (EnvFilter::new(DEFAULT_LEVEL), true),
    }
}

/// Install the global subscriber.
///
/// Call exactly once per process: `tracing_subscriber`'s `init` panics on a
/// second call.
pub fn init(level: &str, format: CfgFormat, sensitive: bool) {
    let (filter, fell_back) = build_filter(level);
    match format {
        CfgFormat::Human => {
            fmt().with_env_filter(filter).init();
        }
        CfgFormat::Json => {
            fmt().json().with_env_filter(filter).init();
        }
    }

    // Only now can these be reported — before `init` there is nowhere to report
    // them to.
    if fell_back {
        tracing::warn!(
            requested = %level,
            applied = %DEFAULT_LEVEL,
            "log level directive could not be parsed; falling back"
        );
    }

    foundry_core::obs::set_sensitive(sensitive);
    if sensitive {
        tracing::warn!(
            "sensitive payload logging ENABLED — dev/test only; the log may \
             contain raw JWEs, vp_tokens and disclosed claim values"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::config::{LogFormat as CfgFormat, LoggingConfig};

    fn cfg(level: &str, format: CfgFormat, sensitive: bool) -> LoggingConfig {
        LoggingConfig {
            level: level.to_string(),
            format,
            sensitive_payloads: sensitive,
        }
    }

    #[test]
    fn level_precedence_env_beats_cli_and_config() {
        let c = cfg("warn", CfgFormat::Human, false);
        assert_eq!(
            resolve_level(Some("trace"), Some("debug"), Some(&c)),
            "trace"
        );
    }

    #[test]
    fn level_precedence_cli_beats_config() {
        let c = cfg("warn", CfgFormat::Human, false);
        assert_eq!(resolve_level(None, Some("debug"), Some(&c)), "debug");
    }

    #[test]
    fn level_precedence_config_beats_default() {
        let c = cfg("warn", CfgFormat::Human, false);
        assert_eq!(resolve_level(None, None, Some(&c)), "warn");
    }

    #[test]
    fn level_falls_back_to_info_when_nothing_is_set() {
        assert_eq!(resolve_level(None, None, None), "info");
    }

    /// `RUST_LOG=` (exported but empty) is how a shell script commonly *clears*
    /// the variable. Treating it as a directive would silence everything.
    #[test]
    fn empty_env_var_is_treated_as_unset() {
        let c = cfg("warn", CfgFormat::Human, false);
        assert_eq!(resolve_level(Some(""), None, Some(&c)), "warn");
        assert_eq!(resolve_level(Some("   "), None, Some(&c)), "warn");
    }

    #[test]
    fn format_precedence_cli_beats_config_beats_default() {
        let json_cfg = cfg("info", CfgFormat::Json, false);
        assert_eq!(
            resolve_format(Some(LogFormat::Human), Some(&json_cfg)),
            CfgFormat::Human
        );
        assert_eq!(resolve_format(None, Some(&json_cfg)), CfgFormat::Json);
        assert_eq!(resolve_format(None, None), CfgFormat::Human);
    }

    #[test]
    fn sensitive_precedence_cli_flag_enables_config_can_also_enable() {
        let off = cfg("info", CfgFormat::Human, false);
        let on = cfg("info", CfgFormat::Human, true);

        // The CLI flag is one-way: `--log-sensitive` turns it on, and its
        // absence defers to the config rather than forcing it off.
        assert!(resolve_sensitive(true, Some(&off)));
        assert!(resolve_sensitive(false, Some(&on)));
        assert!(!resolve_sensitive(false, Some(&off)));
        assert!(!resolve_sensitive(false, None));
        assert!(resolve_sensitive(true, None));
    }

    #[test]
    fn a_valid_directive_is_used_verbatim() {
        let (_filter, fell_back) = build_filter("info,foundry_verifier=debug");
        assert!(!fell_back);
    }

    /// A syntactically broken directive must not take the process down, and must
    /// not silently produce an empty filter that hides every log line.
    #[test]
    fn an_unparseable_directive_falls_back_to_info() {
        let (_filter, fell_back) = build_filter("not a=valid=directive!!");
        assert!(fell_back);
    }

    /// Documents a real limitation rather than asserting desired behaviour: a
    /// misspelled level is valid `EnvFilter` syntax — it reads as a target name —
    /// so it cannot be detected here. The process will simply log nothing. This
    /// test exists so that reading the fallback above does not leave anyone
    /// believing typos are covered.
    #[test]
    fn a_misspelled_level_is_accepted_as_a_target_name_and_cannot_be_detected() {
        let (_filter, fell_back) = build_filter("infoo");
        assert!(
            !fell_back,
            "EnvFilter accepts this as a target directive; if this ever starts \
             failing, EnvFilter got stricter and the docs on build_filter and \
             in `docs/manual/operating/logging.md` should be relaxed accordingly"
        );
    }
}
