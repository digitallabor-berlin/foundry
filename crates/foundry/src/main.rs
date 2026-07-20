mod cli;
mod logging;
mod server;

use clap::Parser;
use cli::{Cli, Command, ConfigAction};
use foundry_core::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    logging::init(&cli.log_level, cli.log_format);

    match cli.command {
        Command::Config { action: ConfigAction::Validate { config } } => {
            let cfg = Config::load(&config)?;
            cfg.validate()?;
            tracing::info!(path = %config.display(), "config is valid");
            println!("OK: {} is valid", config.display());
            Ok(())
        }
        Command::Serve { config } => {
            let cfg = Config::load(&config)?;
            cfg.validate()?;
            server::serve(cfg).await
        }
    }
}