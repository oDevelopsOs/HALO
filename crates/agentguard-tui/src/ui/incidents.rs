//! Incidents — tabla de violaciones de seguridad.

use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::app::AppState;
use crate::theme;

pub fn render(f: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .title(format!(
            " Incidents — {} events (last 24h) ",
            state.daemon.incidents_count
        ))
        .borders(Borders::ALL)
        .border_style(theme::BORDER);

    let content = if state.incidents.is_empty() || state.incidents.iter().all(|s| s == "No incidents recorded yet.") {
        "No security incidents detected. Your data is safe.\n\nViolations appear here in real-time when an AI agent\nattempts to access or exfiltrate protected data.".to_string()
    } else {
        state.incidents.join("\n")
    };

    let para = Paragraph::new(content)
        .style(theme::muted_style())
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(para, area);
}
