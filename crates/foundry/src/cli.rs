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
}
