//! Dashboard — tarjeta de estado + indicadores.

#![allow(dead_code)]

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::app::AppState;
use crate::theme;

pub fn render(f: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(area);

    render_banner(f, state, chunks[0]);
    render_cards(f, state, chunks[1]);
    render_activity(f, state, chunks[2]);
}

fn render_banner(f: &mut Frame, state: &AppState, area: Rect) {
    let status = if state.daemon.paused {
        ("⏸  PROTECTION PAUSED", theme::WARNING)
    } else if state.daemon.connected {
        ("🛡  PROTECTED", theme::SUCCESS)
    } else {
        ("⚠  NOT PROTECTED", theme::DANGER)
    };

    let subtitle = format!(
        "v{} · {} · {} · DLP {} · Sandbox {}",
        state.daemon.version,
        state.daemon.guard_backend,
        state.daemon.protection_level,
        if state.daemon.dlp_enabled {
            "ON"
        } else {
            "OFF"
        },
        state.daemon.sandbox_mode.as_deref().unwrap_or("N/A"),
    );

    let style = if status.1 == theme::WARNING {
        theme::warning_style()
    } else if status.1 == theme::SUCCESS {
        theme::accent_style()
    } else {
        theme::danger_style()
    };

    let banner = Paragraph::new(format!("    {}\n    {}", status.0, subtitle,))
        .style(style)
        .block(Block::default().borders(Borders::NONE));

    f.render_widget(banner, area);
}

fn render_cards(f: &mut Frame, state: &AppState, area: Rect) {
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(area);

    let dirs_count = state.daemon.protected_dirs.len() + state.daemon.protected_files.len();
    let inc_count = state.daemon.incidents_count;
    let snap_count = state.snapshots.len();

    render_card(
        f,
        cards[0],
        "Protected Paths",
        &dirs_count.to_string(),
        &format!(
            "{} dirs · {} files",
            state.daemon.protected_dirs.len(),
            state.daemon.protected_files.len()
        ),
        theme::BG,
    );
    render_card(
        f,
        cards[1],
        "Incidents (24h)",
        &inc_count.to_string(),
        "",
        if inc_count > 0 {
            theme::SURFACE
        } else {
            theme::BG
        },
    );
    render_card(
        f,
        cards[2],
        "Snapshots",
        &snap_count.to_string(),
        "",
        theme::BG,
    );
}

fn render_card(
    f: &mut Frame,
    area: Rect,
    title: &str,
    value: &str,
    subtitle: &str,
    bg: ratatui::style::Color,
) {
    let text = format!("{}\n\n{}\n{}", title, value, subtitle);
    let para = Paragraph::new(text).style(theme::heading_style()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::muted_style())
            .style(ratatui::style::Style::default().bg(bg)),
    );
    f.render_widget(para, area);
}

fn render_activity(f: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .title(" Recent Activity ")
        .borders(Borders::ALL)
        .border_style(theme::BORDER);

    let content = if state.incidents.is_empty() {
        "No recent incidents. Your system is clean.".to_string()
    } else {
        state
            .incidents
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    };

    let para = Paragraph::new(content)
        .style(theme::muted_style())
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(para, area);
}
