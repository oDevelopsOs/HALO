//! Módulo UI — renderizado por pestaña.

mod dashboard;
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
        Tab::Incidents => incidents::render(f, state, area),
        Tab::Snapshots => snapshots::render(f, state, area),
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
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left = if state.daemon.connected {
        let paused = if state.daemon.paused { " [PAUSED]" } else { "" };
        format!(
            " AG v{} | {} ({}){paused} | q quit",
            state.daemon.version, state.daemon.guard_backend, state.daemon.protection_level,
        )
    } else {
        " Daemon disconnected - retrying...".to_string()
    };
    f.render_widget(Paragraph::new(left).style(theme::muted_style()), chunks[0]);

    let right = if let Some(ref err) = state.error_message {
        format!(" ERROR: {err} ")
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
        chunks[1],
    );
}
