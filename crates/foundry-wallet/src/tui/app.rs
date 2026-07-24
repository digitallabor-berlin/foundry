//! Main TUI event loop: wires `tui::state::AppState` (navigation) to
//! `tui::screens::*` (rendering) and `actions::` (issuance/verification),
//! and to `storage::` for the Browse Credentials / Event Log screens.

use crate::actions::issuance::run_issuance;
use crate::actions::verification::{
    run_verification, Consent as ActionConsent, VerificationOutcome,
};
use crate::config::WalletConfig;
use crate::storage::credential_store::list_credentials;
use crate::storage::event_log::tail_events;
use crate::tui::screens;
use crate::tui::state::{AppState, Consent, Screen, TuiCommand};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::CrosstermBackend;
use ratatui::Terminal;
use std::io::stdout;
use std::time::Duration;

pub async fn run(config: &WalletConfig) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new(
        config.issuance_presets.keys().cloned().collect(),
        config.verification_presets.keys().cloned().collect(),
    );
    let mut last_result: Option<String> = None;

    let result = run_loop(&mut terminal, &mut app, config, &mut last_result).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut AppState,
    config: &WalletConfig,
    last_result: &mut Option<String>,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            match app.screen {
                Screen::MainMenu => screens::main_menu::render(frame, area, app.main_menu_selected),
                Screen::TriggerIssuance => screens::issuance::render(
                    frame,
                    area,
                    &app.issuance_preset_names,
                    app.preset_selected,
                    last_result.as_deref(),
                ),
                Screen::TriggerVerification => screens::verification::render(
                    frame,
                    area,
                    &app.verification_preset_names,
                    app.preset_selected,
                    last_result.as_deref(),
                ),
                Screen::BrowseCredentials => {
                    let credentials = list_credentials(&config.data_dir).unwrap_or_default();
                    screens::credentials::render(frame, area, &credentials);
                }
                Screen::EventLog => {
                    let events = tail_events(&config.data_dir, 50).unwrap_or_default();
                    screens::event_log::render(frame, area, &events);
                }
            }
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if let Some(command) = app.handle_key(key.code) {
                    match command {
                        TuiCommand::Quit => return Ok(()),
                        TuiCommand::RunIssuancePreset(preset) => {
                            let outcome = run_issuance(config, Some(&preset), None, None).await;
                            *last_result = Some(match outcome {
                                Ok(o) => format!(
                                    "stored {} (trust_valid={:?})",
                                    o.credential_id, o.trust_valid
                                ),
                                Err(e) => format!("error: {e}"),
                            });
                        }
                        TuiCommand::RunVerificationPreset(preset, consent) => {
                            let action_consent = match consent {
                                Consent::Accept => ActionConsent::Accept,
                                Consent::Decline => ActionConsent::Decline,
                            };
                            let outcome =
                                run_verification(config, Some(&preset), None, action_consent).await;
                            *last_result = Some(match outcome {
                                Ok(VerificationOutcome::Verified(r)) => {
                                    format!("verified={}", r.verified)
                                }
                                Ok(VerificationOutcome::Declined) => "declined".to_string(),
                                Err(e) => format!("error: {e}"),
                            });
                        }
                    }
                }
            }
        }
    }
}
