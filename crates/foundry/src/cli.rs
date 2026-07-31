use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "foundry",
    version,
    about = "Digital credential issuing & verification service"
)]
pub struct Cli {
    /// Log filter directive, e.g. `info` or `info,foundry_verifier=debug`.
    ///
    /// Deliberately an `Option` with no clap default: the resolver must be able
    /// to tell "not supplied" from "supplied as info", or a `logging:` block in
    /// the config file could never take effect. `RUST_LOG` overrides this.
    #[arg(long, global = true)]
    pub log_level: Option<String>,
    /// Log output shape. Same `Option` reasoning as `log_level`.
    #[arg(long, global = true, value_enum)]
    pub log_format: Option<LogFormat>,
    /// Unlock payload-bearing log fields at `debug`/`trace`. **DEV/TEST ONLY** —
    /// the log may then contain raw JWEs, `vp_token`s and disclosed claims.
    #[arg(long, global = true, default_value_t = false)]
    pub log_sensitive: bool,
    #[command(subcommand)]
    pub command: Command,
}

/// Log output shape as a CLI value.
///
/// Mirrors `foundry_core::config::LogFormat`, which cannot be used here because
/// it must not depend on `clap`. The `From` impl below is the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Human,
    Json,
}

impl From<LogFormat> for foundry_core::config::LogFormat {
    fn from(value: LogFormat) -> Self {
        match value {
            LogFormat::Human => foundry_core::config::LogFormat::Human,
            LogFormat::Json => foundry_core::config::LogFormat::Json,
        }
    }
}

impl Command {
    /// The config file this invocation reads, if it reads one.
    ///
    /// Used before the subcommand runs, to pick up the `logging:` block early
    /// enough to shape the subscriber. Exhaustive on purpose — a new subcommand
    /// that takes a config must be added here, or it silently loses
    /// config-driven logging.
    pub fn config_path(&self) -> Option<&Path> {
        match self {
            Command::Serve { config } => Some(config.as_path()),
            Command::Config {
                action: ConfigAction::Validate { config },
            } => Some(config.as_path()),
            Command::StatusList {
                command: StatusListCommands::Token { config, .. },
            } => Some(Path::new(config)),
            Command::Keys { .. }
            | Command::Cert { .. }
            | Command::Quickstart { .. }
            | Command::Openapi { .. }
            | Command::StatusList {
                command: StatusListCommands::Get { .. } | StatusListCommands::Set { .. },
            } => None,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Boot the long-running HTTP service.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Config operations.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Key material operations.
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Certificate operations.
    Cert {
        #[command(subcommand)]
        action: CertAction,
    },
    /// Generate a dev PKI and a ready-to-run config (alias: init). DEV/TEST ONLY.
    #[command(alias = "init")]
    Quickstart {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[arg(long = "out-config", default_value = "config.yaml")]
        out_config: PathBuf,
    },
    /// Export the Admin API OpenAPI 3.x specification to disk.
    Openapi {
        /// Output file path (e.g. openapi.json)
        #[arg(long)]
        out: String,
        /// Emit the wallet-facing spec (openapi-wallet.json) instead of the admin spec.
        #[arg(long, default_value_t = false)]
        wallet: bool,
    },
    /// Manage Token Status Lists offline (get, set status bit, generate status list token).
    StatusList {
        #[command(subcommand)]
        command: StatusListCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Validate a config file without serving.
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum KeysAction {
    /// Generate a fresh EC private key (PKCS#8 PEM).
    Generate {
        #[arg(long, default_value = "ES256")]
        alg: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum CertAction {
    /// Create a self-signed CA certificate + key.
    NewCa {
        #[arg(long, default_value = "Foundry Dev Root CA")]
        common_name: String,
        #[arg(long)]
        out_cert: PathBuf,
        #[arg(long)]
        out_key: PathBuf,
        #[arg(long, default_value_t = 3650)]
        days: i64,
    },
    /// Issue a leaf certificate signed by a CA.
    Issue {
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        common_name: String,
        #[arg(long = "san-dns")]
        san_dns: Vec<String>,
        #[arg(long)]
        out_cert: PathBuf,
        #[arg(long)]
        out_key: PathBuf,
        #[arg(long, default_value_t = 365)]
        days: i64,
    },
}

#[derive(Debug, Subcommand)]
pub enum StatusListCommands {
    /// Get status value at a specific index.
    Get {
        #[arg(long, default_value = "./foundry.db")]
        db: String,
        #[arg(long, rename_all = "kebab-case")]
        credential_type: String,
        #[arg(long)]
        index: u64,
    },
    /// Set status value at a specific index (valid, revoked, suspended).
    Set {
        #[arg(long, default_value = "./foundry.db")]
        db: String,
        #[arg(long, rename_all = "kebab-case")]
        credential_type: String,
        #[arg(long)]
        index: u64,
        #[arg(long)]
        status: String,
    },
    /// Generate and print a signed Status List Token JWT.
    Token {
        #[arg(long)]
        config: String,
        #[arg(long, rename_all = "kebab-case")]
        credential_type: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_serve_with_config() {
        let cli = Cli::parse_from(["foundry", "serve", "--config", "c.yaml"]);
        match cli.command {
            Command::Serve { config } => assert_eq!(config.to_str().unwrap(), "c.yaml"),
            _ => panic!("expected serve"),
        }
    }

    #[test]
    fn log_flags_are_none_when_not_supplied() {
        // "absent" must be distinguishable from "explicitly set to the default",
        // otherwise the config file could never win over a CLI flag.
        let cli = Cli::parse_from(["foundry", "serve", "--config", "c.yaml"]);
        assert_eq!(cli.log_level, None);
        assert_eq!(cli.log_format, None);
        assert!(!cli.log_sensitive);
    }

    #[test]
    fn parses_log_sensitive_flag() {
        let cli = Cli::parse_from(["foundry", "--log-sensitive", "serve", "--config", "c.yaml"]);
        assert!(cli.log_sensitive);
    }

    #[test]
    fn cli_log_format_converts_to_the_config_enum() {
        assert_eq!(
            foundry_core::config::LogFormat::from(LogFormat::Human),
            foundry_core::config::LogFormat::Human
        );
        assert_eq!(
            foundry_core::config::LogFormat::from(LogFormat::Json),
            foundry_core::config::LogFormat::Json
        );
    }

    /// One assertion per subcommand: a newly added subcommand that carries a
    /// config file should fail this test rather than silently losing
    /// config-driven logging.
    #[test]
    fn config_path_is_some_exactly_where_a_config_file_exists() {
        let cases: [(&[&str], Option<&str>); 9] = [
            (&["foundry", "serve", "--config", "c.yaml"], Some("c.yaml")),
            (
                &["foundry", "config", "validate", "--config", "c.json"],
                Some("c.json"),
            ),
            (
                &[
                    "foundry",
                    "status-list",
                    "token",
                    "--config",
                    "c.yaml",
                    "--credential-type",
                    "pid",
                ],
                Some("c.yaml"),
            ),
            (&["foundry", "keys", "generate", "--out", "k.pem"], None),
            (
                &[
                    "foundry",
                    "cert",
                    "new-ca",
                    "--common-name",
                    "ca",
                    "--out-cert",
                    "c.pem",
                    "--out-key",
                    "k.pem",
                ],
                None,
            ),
            (&["foundry", "quickstart"], None),
            (&["foundry", "openapi", "--out", "s.json"], None),
            (
                &[
                    "foundry",
                    "status-list",
                    "get",
                    "--db",
                    "d.sqlite",
                    "--credential-type",
                    "pid",
                    "--index",
                    "1",
                ],
                None,
            ),
            (
                &[
                    "foundry",
                    "status-list",
                    "set",
                    "--db",
                    "d.sqlite",
                    "--credential-type",
                    "pid",
                    "--index",
                    "1",
                    "--status",
                    "revoked",
                ],
                None,
            ),
        ];

        for (argv, expected) in cases {
            let cli = Cli::parse_from(argv);
            let actual = cli.command.config_path();
            match expected {
                Some(want) => assert_eq!(
                    actual.map(|p| p.to_string_lossy().into_owned()).as_deref(),
                    Some(want),
                    "argv {argv:?}"
                ),
                None => assert!(actual.is_none(), "argv {argv:?} yielded {actual:?}"),
            }
        }
    }

    #[test]
    fn parses_config_validate_and_log_flags() {
        let cli = Cli::parse_from([
            "foundry",
            "--log-level",
            "debug",
            "--log-format",
            "json",
            "config",
            "validate",
            "--config",
            "c.json",
        ]);
        assert_eq!(cli.log_level.as_deref(), Some("debug"));
        assert!(matches!(cli.log_format, Some(LogFormat::Json)));
        match cli.command {
            Command::Config {
                action: ConfigAction::Validate { config },
            } => {
                assert_eq!(config.to_str().unwrap(), "c.json");
            }
            _ => panic!("expected config validate"),
        }
    }

    #[test]
    fn parses_openapi_out() {
        let cli = Cli::parse_from(["foundry", "openapi", "--out", "spec.json"]);
        match cli.command {
            Command::Openapi { out, wallet } => {
                assert_eq!(out, "spec.json");
                assert!(!wallet, "the admin spec is the default");
            }
            _ => panic!("expected openapi"),
        }
    }

    #[test]
    fn parses_openapi_wallet_flag() {
        let cli = Cli::parse_from([
            "foundry",
            "openapi",
            "--wallet",
            "--out",
            "openapi-wallet.json",
        ]);
        match cli.command {
            Command::Openapi { out, wallet } => {
                assert_eq!(out, "openapi-wallet.json");
                assert!(wallet);
            }
            _ => panic!("expected openapi"),
        }
    }

    #[test]
    fn parses_status_list_commands() {
        let cli = Cli::parse_from([
            "foundry",
            "status-list",
            "set",
            "--db",
            "db.sqlite",
            "--credential-type",
            "pid",
            "--index",
            "42",
            "--status",
            "revoked",
        ]);
        match cli.command {
            Command::StatusList {
                command:
                    StatusListCommands::Set {
                        db,
                        credential_type,
                        index,
                        status,
                    },
            } => {
                assert_eq!(db, "db.sqlite");
                assert_eq!(credential_type, "pid");
                assert_eq!(index, 42);
                assert_eq!(status, "revoked");
            }
            _ => panic!("expected status-list set"),
        }
    }
}
