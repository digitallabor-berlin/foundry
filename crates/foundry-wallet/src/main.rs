use clap::Parser;
use foundry_wallet::actions::issuance::run_issuance;
use foundry_wallet::actions::verification::{run_verification, Consent, VerificationOutcome};
use foundry_wallet::cli::{Cli, Command, ConsentArg, CredentialsAction, EventsAction};
use foundry_wallet::config::WalletConfig;
use foundry_wallet::error::WalletError;
use foundry_wallet::storage::credential_store::{list_credentials, load_metadata, load_payload};
use foundry_wallet::storage::event_log::tail_events;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let exit_code = run(cli).await;
    std::process::exit(exit_code);
}

async fn run(cli: Cli) -> i32 {
    let config = match WalletConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => return print_error(&e),
    };

    match cli.command {
        None | Some(Command::Tui) => match foundry_wallet::tui::app::run(&config).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!(
                    "{}",
                    serde_json::json!({"error": e.to_string(), "kind": "tui"})
                );
                1
            }
        },
        Some(Command::Issue {
            preset,
            offer_uri,
            tx_code,
        }) => {
            match run_issuance(
                &config,
                preset.as_deref(),
                offer_uri.as_deref(),
                tx_code.as_deref(),
            )
            .await
            {
                Ok(outcome) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "credential_id": outcome.credential_id,
                            "vct": outcome.vct,
                            "trust_valid": outcome.trust_valid,
                        })
                    );
                    0
                }
                Err(e) => print_error(&e),
            }
        }
        Some(Command::Verify {
            preset,
            request_uri,
            consent,
        }) => {
            let consent = match consent {
                ConsentArg::Accept => Consent::Accept,
                ConsentArg::Decline => Consent::Decline,
            };
            match run_verification(&config, preset.as_deref(), request_uri.as_deref(), consent)
                .await
            {
                Ok(VerificationOutcome::Verified(result)) => print_json(&result),
                Ok(VerificationOutcome::Declined) => {
                    println!("{}", serde_json::json!({"consent": "declined"}));
                    0
                }
                Err(e) => print_error(&e),
            }
        }
        Some(Command::Credentials { action }) => match action {
            CredentialsAction::List => match list_credentials(&config.data_dir) {
                Ok(list) => print_json(&list),
                Err(e) => print_error(&e),
            },
            CredentialsAction::Show { id } => {
                let metadata = match load_metadata(&config.data_dir, &id) {
                    Ok(m) => m,
                    Err(e) => return print_error(&e),
                };
                let payload = match load_payload(&config.data_dir, &id) {
                    Ok(p) => p,
                    Err(e) => return print_error(&e),
                };
                println!(
                    "{}",
                    serde_json::json!({"metadata": metadata, "payload": payload})
                );
                0
            }
        },
        Some(Command::Events { action }) => match action {
            EventsAction::Tail { n } => match tail_events(&config.data_dir, n) {
                Ok(events) => print_json(&events),
                Err(e) => print_error(&e),
            },
        },
    }
}

/// Serialize `value` to JSON and print it to stdout, returning exit code 0.
/// If serialization itself fails (should not happen for the plain
/// serde-derived types this CLI prints, but must not be silently swallowed
/// per the "success always prints valid JSON" contract), routes through
/// `print_error` instead so the failure is visible and exit code 1 is used.
fn print_json<T: serde::Serialize>(value: &T) -> i32 {
    match serde_json::to_string(value) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => print_error(&WalletError::from(e)),
    }
}

fn print_error(e: &WalletError) -> i32 {
    eprintln!(
        "{}",
        serde_json::json!({"error": e.to_string(), "kind": e.kind()})
    );
    1
}
