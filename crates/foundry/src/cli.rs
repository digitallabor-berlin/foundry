use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "foundry",
    version,
    about = "Digital credential issuing & verification service"
)]
pub struct Cli {
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Human)]
    pub log_format: LogFormat,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    Human,
    Json,
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
        assert_eq!(cli.log_level, "debug");
        assert!(matches!(cli.log_format, LogFormat::Json));
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
            Command::Openapi { out } => assert_eq!(out, "spec.json"),
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
