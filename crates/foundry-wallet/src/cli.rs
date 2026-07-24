use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "foundry-wallet",
    version,
    about = "Debug wallet for exercising Foundry's OpenID4VCI/OpenID4VP flows"
)]
pub struct Cli {
    #[arg(long)]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Launch the interactive TUI (default when no subcommand is given).
    Tui,
    /// Trigger or consume an issuance flow.
    Issue {
        #[arg(long)]
        preset: Option<String>,
        #[arg(long)]
        offer_uri: Option<String>,
        #[arg(long)]
        tx_code: Option<String>,
    },
    /// Trigger or consume a verification flow.
    Verify {
        #[arg(long)]
        preset: Option<String>,
        #[arg(long)]
        request_uri: Option<String>,
        #[arg(long, value_enum)]
        consent: ConsentArg,
    },
    /// Inspect stored credentials.
    Credentials {
        #[command(subcommand)]
        action: CredentialsAction,
    },
    /// Inspect the event log.
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ConsentArg {
    Accept,
    Decline,
}

#[derive(Debug, Subcommand)]
pub enum CredentialsAction {
    /// List all stored credentials.
    List,
    /// Show one stored credential's metadata and decoded payload.
    Show {
        #[arg(long)]
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EventsAction {
    /// Print the event log.
    Tail {
        #[arg(long, default_value_t = 20)]
        n: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_issue_with_preset() {
        let cli = Cli::parse_from([
            "foundry-wallet",
            "--config",
            "wallet.yaml",
            "issue",
            "--preset",
            "pid",
        ]);
        assert_eq!(cli.config.to_str().unwrap(), "wallet.yaml");
        match cli.command {
            Some(Command::Issue {
                preset,
                offer_uri,
                tx_code,
            }) => {
                assert_eq!(preset.as_deref(), Some("pid"));
                assert_eq!(offer_uri, None);
                assert_eq!(tx_code, None);
            }
            other => panic!("expected Issue, got {other:?}"),
        }
    }

    #[test]
    fn parses_verify_requires_consent() {
        let cli = Cli::parse_from([
            "foundry-wallet",
            "--config",
            "wallet.yaml",
            "verify",
            "--preset",
            "dcql1",
            "--consent",
            "accept",
        ]);
        match cli.command {
            Some(Command::Verify {
                preset, consent, ..
            }) => {
                assert_eq!(preset.as_deref(), Some("dcql1"));
                assert!(matches!(consent, ConsentArg::Accept));
            }
            other => panic!("expected Verify, got {other:?}"),
        }
    }

    #[test]
    fn defaults_to_no_subcommand_meaning_tui() {
        let cli = Cli::parse_from(["foundry-wallet", "--config", "wallet.yaml"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_credentials_show() {
        let cli = Cli::parse_from([
            "foundry-wallet",
            "--config",
            "wallet.yaml",
            "credentials",
            "show",
            "--id",
            "cred_1",
        ]);
        match cli.command {
            Some(Command::Credentials {
                action: CredentialsAction::Show { id },
            }) => assert_eq!(id, "cred_1"),
            other => panic!("expected Credentials Show, got {other:?}"),
        }
    }
}
