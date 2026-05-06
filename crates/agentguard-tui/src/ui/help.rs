use ratatui::{
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::theme;

pub fn render(f: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" ? Help & Shortcuts ")
        .borders(Borders::ALL)
        .border_style(theme::BORDER);

    let lines = vec![
        Line::from(vec![Span::styled(
            "  ── Navigation (1-6 or Tab/Left/Right) ──",
            theme::heading_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  1", theme::title_style()),
            Span::styled("  Dashboard   ", theme::muted_style()),
            Span::styled(
                "overview: paths, incidents, snapshots",
                theme::muted_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("  2", theme::title_style()),
            Span::styled("  Zones       ", theme::muted_style()),
            Span::styled("protected folders and files", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  3", theme::title_style()),
            Span::styled("  Agents      ", theme::muted_style()),
            Span::styled("AI agents tracked with session stats", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  4", theme::title_style()),
            Span::styled("  Incidents   ", theme::muted_style()),
            Span::styled("security events timeline", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  5", theme::title_style()),
            Span::styled("  Snapshots   ", theme::muted_style()),
            Span::styled("vault recovery points", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  6/h", theme::title_style()),
            Span::styled("  Help        ", theme::muted_style()),
            Span::styled("this screen", theme::muted_style()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  ── Actions ──",
            theme::heading_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  r", theme::title_style()),
            Span::styled("   Refresh data from daemon", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  p", theme::title_style()),
            Span::styled("   Pause protection (30 minutes)", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  f", theme::title_style()),
            Span::styled(
                "   Filter/search incidents — type to filter, Enter to apply, Esc to clear",
                theme::muted_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Esc", theme::title_style()),
            Span::styled(
                "  Clear filter (first press) / Quit (second press)",
                theme::muted_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("  q", theme::title_style()),
            Span::styled("   Quit AgentGuard TUI", theme::muted_style()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  ── CLI Commands You Should Know ──",
            theme::heading_style(),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  agentguard rules add ~/Projects ~/Documents ~/.ssh",
            theme::muted_style(),
        )]),
        Line::from(vec![Span::styled(
            "  agentguard snapshot create --label \"my-save\"",
            theme::muted_style(),
        )]),
        Line::from(vec![Span::styled(
            "  agentguard snapshot restore latest --yes",
            theme::muted_style(),
        )]),
        Line::from(vec![Span::styled(
            "  agentguard incidents",
            theme::muted_style(),
        )]),
        Line::from(vec![Span::styled(
            "  agentguard agents",
            theme::muted_style(),
        )]),
        Line::from(vec![Span::styled(
            "  agentguard stats",
            theme::muted_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tip: ", theme::title_style()),
            Span::styled(
                "The status bar at the bottom always shows what keys you can press.",
                theme::muted_style(),
            ),
        ]),
    ];

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}
