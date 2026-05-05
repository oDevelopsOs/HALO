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
            "  ── Navigation ──",
            theme::heading_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  1", theme::title_style()),
            Span::styled("  Dashboard", theme::muted_style()),
            Span::styled("     · overview + live status", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  2", theme::title_style()),
            Span::styled("  Protected Zones", theme::muted_style()),
            Span::styled(" · monitored paths", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  3", theme::title_style()),
            Span::styled("  Incidents", theme::muted_style()),
            Span::styled("       · security violations (24h)", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  4", theme::title_style()),
            Span::styled("  Snapshots", theme::muted_style()),
            Span::styled("       · vault recovery points", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  5", theme::title_style()),
            Span::styled("  Help", theme::muted_style()),
            Span::styled("            · this screen", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  Tab / n", theme::title_style()),
            Span::styled("     next tab", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  Left", theme::title_style()),
            Span::styled("        previous tab", theme::muted_style()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  ── Actions ──",
            theme::heading_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  r", theme::title_style()),
            Span::styled("   Refresh data", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  p", theme::title_style()),
            Span::styled("   Pause protection (30 min)", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  q / Esc", theme::title_style()),
            Span::styled("   Quit", theme::muted_style()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  ── What is AgentGuard? ──",
            theme::heading_style(),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  AgentGuard monitors your filesystem in real-time and blocks AI agents",
            theme::muted_style(),
        )]),
        Line::from(vec![Span::styled(
            "  from accessing or exfiltrating sensitive data. It acts as a kernel-level",
            theme::muted_style(),
        )]),
        Line::from(vec![Span::styled(
            "  guard between your files and any AI tool running on your system.",
            theme::muted_style(),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  ── Getting started ──",
            theme::heading_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  $ agentguard protect ./secrets", theme::muted_style()),
            Span::styled("     · protect a directory", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  $ agentguard snapshot create", theme::muted_style()),
            Span::styled("      · save a recovery point", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  $ agentguard status", theme::muted_style()),
            Span::styled("              · check daemon health", theme::muted_style()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  ── Color guide ──",
            theme::heading_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", theme::muted_style()),
            Span::styled("●", theme::title_style()),
            Span::styled(" Orange", theme::muted_style()),
            Span::styled("  · active tab, interactive elements", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  ", theme::muted_style()),
            Span::styled("●", theme::heading_style()),
            Span::styled(" Purple", theme::muted_style()),
            Span::styled("  · section headers, navigation", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  ", theme::muted_style()),
            Span::styled("●", theme::accent_style()),
            Span::styled(" Emerald", theme::muted_style()),
            Span::styled(" · protected status, success", theme::muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  ", theme::muted_style()),
            Span::styled("●", theme::danger_style()),
            Span::styled(" Red", theme::muted_style()),
            Span::styled("     · errors and violations", theme::muted_style()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Press ", theme::muted_style()),
            Span::styled("h", theme::title_style()),
            Span::styled(" from any tab to return here.", theme::muted_style()),
        ]),
    ];

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}
