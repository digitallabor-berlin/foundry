use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

pub fn render(
    frame: &mut Frame,
    area: Rect,
    presets: &[String],
    selected: usize,
    last_result: Option<&str>,
) {
    if presets.is_empty() {
        let paragraph =
            Paragraph::new("No issuance_presets configured in wallet.yaml. Press Esc to go back.")
                .block(
                    Block::default()
                        .title("Trigger Issuance")
                        .borders(Borders::ALL),
                );
        frame.render_widget(paragraph, area);
        return;
    }
    let mut lines: Vec<ListItem> = presets
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(name.clone(), style)))
        })
        .collect();
    if let Some(result) = last_result {
        lines.push(ListItem::new(Line::from(format!("Last result: {result}"))));
    }
    let list = List::new(lines).block(
        Block::default()
            .title("Trigger Issuance (Enter to run, Esc to go back)")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}
