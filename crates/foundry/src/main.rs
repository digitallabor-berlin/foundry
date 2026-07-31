use clap::Parser;
use foundry::cli::{CertAction, Cli, Command, ConfigAction, KeysAction, StatusListCommands};
use foundry::{commands, logging, server};
use foundry_core::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // The subscriber has to be installed before anything worth logging happens,
    // but the `logging:` block lives in the config file. So: load it here on a
    // best-effort basis purely to shape the subscriber, and discard any error.
    // The authoritative load still runs inside the matched arm below, so a
    // broken config still fails loudly with its typed `ConfigError` — it is just
    // reported by a subscriber built from defaults.
    let preloaded = cli.command.config_path().and_then(|p| Config::load(p).ok());
    let logging_cfg = preloaded.as_ref().map(|c| &c.logging);
    logging::init(
        &logging::resolve_level(
            std::env::var("RUST_LOG").ok().as_deref(),
            cli.log_level.as_deref(),
            logging_cfg,
        ),
        logging::resolve_format(cli.log_format, logging_cfg),
        logging::resolve_sensitive(cli.log_sensitive, logging_cfg),
    );

    match cli.command {
        Command::Config {
            action: ConfigAction::Validate { config },
        } => {
            // Reuse the preload where it succeeded; otherwise load again so the
            // real error surfaces.
            let cfg = match preloaded {
                Some(cfg) => cfg,
                None => Config::load(&config)?,
            };
            cfg.validate()?;
            let base_dir = config.parent().unwrap_or_else(|| std::path::Path::new("."));
            cfg.validate_key_material(base_dir)?;
            tracing::info!(path = %config.display(), "config is valid");
            println!("OK: {} is valid", config.display());
            Ok(())
        }
        Command::Serve { config } => {
            let cfg = match preloaded {
                Some(cfg) => cfg,
                None => Config::load(&config)?,
            };
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
