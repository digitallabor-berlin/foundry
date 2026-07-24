//! Pure TUI navigation state machine: given the current screen and a key
//! press, decides the next screen (if any) and/or an action for the caller
//! (`tui::app`, Task 16) to execute against `actions::`. No rendering, no
//! I/O — fully unit-testable without a real terminal.

use crossterm::event::KeyCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    MainMenu,
    TriggerIssuance,
    TriggerVerification,
    BrowseCredentials,
    EventLog,
}

const MAIN_MENU_ITEMS: [&str; 5] = [
    "Trigger Issuance",
    "Trigger Verification",
    "Browse Credentials",
    "Event Log",
    "Quit",
];

#[derive(Debug, Clone, PartialEq)]
pub enum TuiCommand {
    Quit,
    RunIssuancePreset(String),
    RunVerificationPreset(String, Consent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    Accept,
    Decline,
}

pub struct AppState {
    pub screen: Screen,
    pub main_menu_selected: usize,
    /// Presets available for issuance/verification screens, injected at
    /// construction from `WalletConfig` (Task 16 wires this).
    pub issuance_preset_names: Vec<String>,
    pub verification_preset_names: Vec<String>,
    pub preset_selected: usize,
}

impl AppState {
    pub fn new(issuance_preset_names: Vec<String>, verification_preset_names: Vec<String>) -> Self {
        Self {
            screen: Screen::MainMenu,
            main_menu_selected: 0,
            issuance_preset_names,
            verification_preset_names,
            preset_selected: 0,
        }
    }

    /// Handle one key press. Returns `Some(TuiCommand)` when the key press
    /// should trigger an action in the caller; navigation-only key presses
    /// (arrow keys, Enter into a submenu, Esc back to the main menu) mutate
    /// `self` and return `None`.
    pub fn handle_key(&mut self, key: KeyCode) -> Option<TuiCommand> {
        match self.screen {
            Screen::MainMenu => self.handle_main_menu_key(key),
            Screen::TriggerIssuance => {
                self.handle_preset_screen_key(key, &self.issuance_preset_names.clone(), true)
            }
            Screen::TriggerVerification => {
                self.handle_preset_screen_key(key, &self.verification_preset_names.clone(), false)
            }
            Screen::BrowseCredentials | Screen::EventLog => {
                if key == KeyCode::Esc {
                    self.screen = Screen::MainMenu;
                }
                None
            }
        }
    }

    fn handle_main_menu_key(&mut self, key: KeyCode) -> Option<TuiCommand> {
        match key {
            KeyCode::Down => {
                self.main_menu_selected = (self.main_menu_selected + 1) % MAIN_MENU_ITEMS.len();
                None
            }
            KeyCode::Up => {
                self.main_menu_selected =
                    (self.main_menu_selected + MAIN_MENU_ITEMS.len() - 1) % MAIN_MENU_ITEMS.len();
                None
            }
            KeyCode::Enter => match self.main_menu_selected {
                0 => {
                    self.screen = Screen::TriggerIssuance;
                    self.preset_selected = 0;
                    None
                }
                1 => {
                    self.screen = Screen::TriggerVerification;
                    self.preset_selected = 0;
                    None
                }
                2 => {
                    self.screen = Screen::BrowseCredentials;
                    None
                }
                3 => {
                    self.screen = Screen::EventLog;
                    None
                }
                4 => Some(TuiCommand::Quit),
                _ => None,
            },
            _ => None,
        }
    }

    fn handle_preset_screen_key(
        &mut self,
        key: KeyCode,
        presets: &[String],
        is_issuance: bool,
    ) -> Option<TuiCommand> {
        if presets.is_empty() {
            if key == KeyCode::Esc {
                self.screen = Screen::MainMenu;
            }
            return None;
        }
        match key {
            KeyCode::Down => {
                self.preset_selected = (self.preset_selected + 1) % presets.len();
                None
            }
            KeyCode::Up => {
                self.preset_selected = (self.preset_selected + presets.len() - 1) % presets.len();
                None
            }
            KeyCode::Esc => {
                self.screen = Screen::MainMenu;
                None
            }
            KeyCode::Enter if is_issuance => Some(TuiCommand::RunIssuancePreset(
                presets[self.preset_selected].clone(),
            )),
            KeyCode::Char('a') if !is_issuance => Some(TuiCommand::RunVerificationPreset(
                presets[self.preset_selected].clone(),
                Consent::Accept,
            )),
            KeyCode::Char('d') if !is_issuance => Some(TuiCommand::RunVerificationPreset(
                presets[self.preset_selected].clone(),
                Consent::Decline,
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_on_main_menu() {
        let state = AppState::new(vec![], vec![]);
        assert_eq!(state.screen, Screen::MainMenu);
        assert_eq!(state.main_menu_selected, 0);
    }

    #[test]
    fn down_and_up_wrap_around_the_main_menu() {
        let mut state = AppState::new(vec![], vec![]);
        for _ in 0..MAIN_MENU_ITEMS.len() {
            state.handle_key(KeyCode::Down);
        }
        assert_eq!(
            state.main_menu_selected, 0,
            "wraps back to 0 after a full cycle"
        );

        state.handle_key(KeyCode::Up);
        assert_eq!(state.main_menu_selected, MAIN_MENU_ITEMS.len() - 1);
    }

    #[test]
    fn enter_on_quit_item_returns_quit_command() {
        let mut state = AppState::new(vec![], vec![]);
        state.main_menu_selected = 4; // "Quit"
        let cmd = state.handle_key(KeyCode::Enter);
        assert_eq!(cmd, Some(TuiCommand::Quit));
    }

    #[test]
    fn enter_on_trigger_issuance_navigates_without_a_command() {
        let mut state = AppState::new(vec!["pid".to_string()], vec![]);
        state.main_menu_selected = 0; // "Trigger Issuance"
        let cmd = state.handle_key(KeyCode::Enter);
        assert_eq!(cmd, None);
        assert_eq!(state.screen, Screen::TriggerIssuance);
    }

    #[test]
    fn enter_on_a_preset_in_trigger_issuance_runs_it() {
        let mut state = AppState::new(vec!["pid".to_string()], vec![]);
        state.screen = Screen::TriggerIssuance;
        let cmd = state.handle_key(KeyCode::Enter);
        assert_eq!(cmd, Some(TuiCommand::RunIssuancePreset("pid".to_string())));
    }

    #[test]
    fn accept_and_decline_keys_run_verification_with_consent() {
        let mut state = AppState::new(vec![], vec!["dcql1".to_string()]);
        state.screen = Screen::TriggerVerification;
        assert_eq!(
            state.handle_key(KeyCode::Char('a')),
            Some(TuiCommand::RunVerificationPreset(
                "dcql1".to_string(),
                Consent::Accept
            ))
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('d')),
            Some(TuiCommand::RunVerificationPreset(
                "dcql1".to_string(),
                Consent::Decline
            ))
        );
    }

    #[test]
    fn esc_from_browse_credentials_returns_to_main_menu() {
        let mut state = AppState::new(vec![], vec![]);
        state.screen = Screen::BrowseCredentials;
        state.handle_key(KeyCode::Esc);
        assert_eq!(state.screen, Screen::MainMenu);
    }
}
