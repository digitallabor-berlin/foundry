use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, events: &[serde_json::Value]) {
    let items: Vec<ListItem> = events
        .iter()
        .map(|e| ListItem::new(Line::from(e.to_string())))
        .collect();
    let list = List::new(items).block(
        Block::default()
            .title("Event Log (Esc to go back)")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}
