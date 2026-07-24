use crate::storage::credential_store::CredentialMetadata;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, credentials: &[CredentialMetadata]) {
    let items: Vec<ListItem> = credentials
        .iter()
        .map(|c| {
            ListItem::new(Line::from(format!(
                "{} | vct={} | trust_valid={:?}",
                c.credential_id, c.vct, c.trust_valid
            )))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .title("Browse Credentials (Esc to go back)")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}
