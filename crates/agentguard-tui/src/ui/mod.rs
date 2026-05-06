//! Módulo UI — renderizado por pestaña.

mod agents;
mod dashboard;
mod help;
mod incidents;
mod snapshots;
mod zones;

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::app::{AppState, Tab};
use crate::theme;

pub fn render_tab(f: &mut Frame, state: &AppState, area: Rect) {
    match state.current_tab {
        Tab::Dashboard => dashboard::render(f, state, area),
        Tab::Zones => zones::render(f, state, area),
        Tab::Agents => agents::render_agents(f, area, state),
        Tab::Incidents => incidents::render(f, state, area),
        Tab::Snapshots => snapshots::render(f, state, area),
        Tab::Help => help::render(f, area),
    }
}

pub fn render_tabs(f: &mut Frame, state: &AppState, area: Rect) {
    use ratatui::layout::{Constraint, Direction, Layout};

    let tab_titles: Vec<&str> = Tab::all().iter().map(|t| t.title()).collect();

    let tabs_widget = ratatui::widgets::Tabs::new(tab_titles)
        .select(state.current_tab.clone() as usize)
        .style(theme::muted_style())
        .highlight_style(theme::title_style())
        .divider("|");

    f.render_widget(tabs_widget, area);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    render_tab(f, state, inner[1]);
}

pub fn render_status_bar(f: &mut Frame, state: &AppState, area: Rect) {
    use ratatui::layout::{Alignment, Constraint, Direction, Layout};
    use ratatui::widgets::Paragraph;

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ])
        .split(area);

    // Left: daemon status
    let left = if state.daemon.connected {
        let paused = if state.daemon.paused { " [PAUSED]" } else { "" };
        format!(
            " AG v{} | {} ({}){paused}",
            state.daemon.version, state.daemon.guard_backend, state.daemon.protection_level,
        )
    } else {
        " ⚠ Daemon disconnected — retrying...".to_string()
    };
    f.render_widget(Paragraph::new(left).style(theme::muted_style()), chunks[0]);

    // Center: always-visible key hints
    let center = if state.filter_active {
        format!(" Filter: {} │ Enter=apply Esc=clear", state.filter_text)
    } else {
        " 1-6 tabs │ r refresh │ f filter │ p pause │ q quit ".to_string()
    };
    f.render_widget(
        Paragraph::new(center)
            .style(theme::title_style())
            .alignment(Alignment::Center),
        chunks[1],
    );

    // Right: status/error messages
    let right = if let Some(ref err) = state.error_message {
        format!(" {err} ")
    } else if let Some(ref msg) = state.status_message {
        format!(" {msg} ")
    } else {
        String::new()
    };
    let style = if state.error_message.is_some() {
        theme::danger_style()
    } else {
        theme::accent_style()
    };
    f.render_widget(
        Paragraph::new(right)
            .style(style)
            .alignment(Alignment::Right),
        chunks[2],
    );
}
