use clap::Parser;
use foundry::cli::{CertAction, Cli, Command, ConfigAction, KeysAction, StatusListCommands};
use foundry::{commands, logging, server};
use foundry_core::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    logging::init(&cli.log_level, cli.log_format);

    match cli.command {
        Command::Config {
            action: ConfigAction::Validate { config },
        } => {
            let cfg = Config::load(&config)?;
            cfg.validate()?;
            let base_dir = config.parent().unwrap_or_else(|| std::path::Path::new("."));
            cfg.validate_key_material(base_dir)?;
            tracing::info!(path = %config.display(), "config is valid");
            println!("OK: {} is valid", config.display());
            Ok(())
        }
        Command::Serve { config } => {
            let cfg = Config::load(&config)?;
            cfg.validate()?;
            let base_dir = config.parent().unwrap_or_else(|| std::path::Path::new("."));
            cfg.validate_key_material(base_dir)?;
            server::serve(cfg).await
        }
        Command::Keys {
            action: KeysAction::Generate { alg, out },
        } => commands::keys_generate(&alg, &out),
        Command::Cert {
            action:
                CertAction::NewCa {
                    common_name,
                    out_cert,
                    out_key,
                    days,
                },
        } => commands::cert_new_ca(&common_name, &out_cert, &out_key, days),
        Command::Cert {
            action:
                CertAction::Issue {
                    ca,
                    key,
                    common_name,
                    san_dns,
                    out_cert,
                    out_key,
                    days,
                },
        } => commands::cert_issue(&ca, &key, &common_name, &san_dns, &out_cert, &out_key, days),
        Command::Quickstart { dir, out_config } => commands::quickstart(&dir, &out_config),
        Command::Openapi { out, wallet } => {
            let spec = if wallet {
                foundry::openapi::generate_wallet_openapi_spec()
            } else {
                foundry::openapi::generate_admin_openapi_spec()
            };
            std::fs::write(&out, spec)?;
            println!("Wrote OpenAPI spec to {out}");
            Ok(())
        }
        Command::StatusList { command } => match command {
            StatusListCommands::Get {
                db,
                credential_type,
                index,
            } => commands::status_list_get(&db, &credential_type, index).await,
            StatusListCommands::Set {
                db,
                credential_type,
                index,
                status,
            } => commands::status_list_set(&db, &credential_type, index, &status).await,
            StatusListCommands::Token {
                config,
                credential_type,
            } => commands::status_list_token(&config, &credential_type).await,
        },
    }
}
