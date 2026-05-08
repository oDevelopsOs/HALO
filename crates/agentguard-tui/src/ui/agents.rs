//! Agents tab — shows tracked AI agents with session statistics.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::theme;

pub fn render_agents(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Summary header
    let header = if state.agents.is_empty() {
        Paragraph::new("No agents tracked yet. Agents appear here when the daemon detects them.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title("AI Agents"),
            )
            .style(Style::default().fg(Color::Gray))
    } else {
        let total_sessions: i64 = state.agents.iter().map(|a| a.total_sessions).sum();
        let total_violations: i64 = state.agents.iter().map(|a| a.total_violations).sum();
        let summary = format!(
            " {} agents | {} sessions total | {} violations total ",
            state.agents.len(),
            total_sessions,
            total_violations
        );
        Paragraph::new(summary)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title("AI Agents"),
            )
            .style(Style::default().fg(Color::Cyan))
    };
    frame.render_widget(header, chunks[0]);

    // Agent list
    if !state.agents.is_empty() {
        let items: Vec<ListItem> = state
            .agents
            .iter()
            .map(|a| {
                let status_color = if a.total_violations > 0 {
                    theme::ORANGE
                } else {
                    theme::PURPLE_BRIGHT
                };
                let sandbox_time = if a.total_sandbox_seconds > 0 {
                    format!("{}s sandbox", a.total_sandbox_seconds)
                } else {
                    "monitor only".to_string()
                };
                let line = Line::from(vec![
                    Span::styled(
                        format!(" {:15}", a.agent_name),
                        Style::default()
                            .fg(status_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        " sessions:{:3}  violations:{:3}  {}",
                        a.total_sessions, a.total_violations, sandbox_time
                    )),
                ]);
                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::NONE))
            .highlight_style(Style::default().bg(Color::DarkGray));
        frame.render_widget(list, chunks[1]);
    }
}
