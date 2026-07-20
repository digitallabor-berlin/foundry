use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "foundry", version, about = "Digital credential issuing & verification service")]
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
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Validate a config file without serving.
    Validate {
        #[arg(long)]
        config: PathBuf,
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
            "foundry", "--log-level", "debug", "--log-format", "json",
            "config", "validate", "--config", "c.json",
        ]);
        assert_eq!(cli.log_level, "debug");
        assert!(matches!(cli.log_format, LogFormat::Json));
        match cli.command {
            Command::Config { action: ConfigAction::Validate { config } } => {
                assert_eq!(config.to_str().unwrap(), "c.json");
            }
            _ => panic!("expected config validate"),
        }
    }
}