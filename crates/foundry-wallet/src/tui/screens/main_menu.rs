use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

const ITEMS: [&str; 5] = [
    "Trigger Issuance",
    "Trigger Verification",
    "Browse Credentials",
    "Event Log",
    "Quit",
];

pub fn render(frame: &mut Frame, area: Rect, selected: usize) {
    let items: Vec<ListItem> = ITEMS
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(*label, style)))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .title("foundry-wallet")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}
