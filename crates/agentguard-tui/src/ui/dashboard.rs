//! Dashboard tab — overview with guardian spirit and activity cards.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::theme;

/// Guardian spirits unlocked by milestones.
const GUARDIANS: &[Guardian] = &[
    Guardian {
        name: "Fēnix",
        emoji: "🦅",
        xp: 0,
        lore: "Protector of new beginnings",
    },
    Guardian {
        name: "Lúnax",
        emoji: "🐺",
        xp: 500,
        lore: "Watches over your night sessions",
    },
    Guardian {
        name: "Aegis",
        emoji: "🦉",
        xp: 1500,
        lore: "Keeper of protected paths",
    },
    Guardian {
        name: "Kael",
        emoji: "🐉",
        xp: 5000,
        lore: "Guardian of the sacred files",
    },
    Guardian {
        name: "Solara",
        emoji: "🦄",
        xp: 15000,
        lore: "Light of the vault",
    },
    Guardian {
        name: "Zephyros",
        emoji: "🐲",
        xp: 50000,
        lore: "Elder of the kernel",
    },
];

struct Guardian {
    name: &'static str,
    emoji: &'static str,
    xp: u64,
    lore: &'static str,
}

fn current_guardian(xp: u64) -> &'static Guardian {
    GUARDIANS
        .iter()
        .rev()
        .find(|g| xp >= g.xp)
        .unwrap_or(&GUARDIANS[0])
}

fn next_guardian(xp: u64) -> Option<&'static Guardian> {
    GUARDIANS.iter().find(|g| g.xp > xp)
}

fn total_xp(state: &AppState) -> u64 {
    let incidents = state.daemon.incidents_count;
    let agents = state.agents.len() as u64;
    let paths = (state.daemon.protected_dirs.len() + state.daemon.protected_files.len()) as u64;
    // XP formula: incidents * 10 + agents * 100 + paths * 50
    incidents * 10 + agents * 100 + paths * 50
}

pub fn render(f: &mut Frame, state: &AppState, area: Rect) {
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);

    // ── Top: Guardian + XP bar ──
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(18), Constraint::Min(1)])
        .split(main[0]);

    render_guardian_card(f, top[0], state);
    render_xp_section(f, top[1], state);

    // ── Bottom: Stats cards ──
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(main[1]);

    render_stat_card(
        f,
        cards[0],
        "🛡",
        "Protected",
        &format!(
            "{} paths",
            state.daemon.protected_dirs.len() + state.daemon.protected_files.len()
        ),
        theme::PURPLE,
    );
    render_stat_card(
        f,
        cards[1],
        "🤖",
        "Agents",
        &format!("{} tracked", state.agents.len()),
        theme::PURPLE_BRIGHT,
    );
    let violation_style = if state.daemon.incidents_count > 0 {
        theme::DANGER
    } else {
        theme::PURPLE_DIM
    };
    render_stat_card(
        f,
        cards[2],
        "!",
        "Incidents",
        &format!("{} total", state.daemon.incidents_count),
        violation_style,
    );
    render_stat_card(
        f,
        cards[3],
        "💾",
        "Snapshots",
        &format!("{} saved", state.snapshots.len()),
        theme::PURPLE_BRIGHT,
    );
}

fn render_guardian_card(f: &mut Frame, area: Rect, state: &AppState) {
    let xp = total_xp(state);
    let guardian = current_guardian(xp);

    let block = Block::default()
        .title(" Guardian ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PURPLE))
        .style(Style::default().bg(theme::SURFACE));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = vec![
        Line::from(vec![
            Span::styled(
                guardian.emoji,
                Style::default()
                    .fg(theme::PURPLE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(guardian.name, theme::title_style()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(guardian.lore, theme::muted_style())]),
    ];

    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
}

fn render_xp_section(f: &mut Frame, area: Rect, state: &AppState) {
    let xp = total_xp(state);
    let guardian = current_guardian(xp);
    let next = next_guardian(xp);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PURPLE_DIM))
        .style(Style::default().bg(theme::SURFACE));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    // Title
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("XP ", theme::muted_style()),
            Span::styled(format!("{}", xp), theme::title_style()),
            Span::styled(
                format!("    Guardian: {}", guardian.name),
                theme::accent_style(),
            ),
        ])),
        chunks[0],
    );

    // XP bar
    if let Some(n) = next {
        let pct = if n.xp > guardian.xp {
            ((xp - guardian.xp) as f64 / (n.xp - guardian.xp) as f64).min(1.0)
        } else {
            1.0
        };
        let bar_width = (inner.width as f64 * pct) as u16;
        let filled = "█".repeat(bar_width as usize);
        f.render_widget(
            Paragraph::new(Span::styled(&filled, Style::default().fg(theme::PURPLE))),
            chunks[1],
        );
        f.render_widget(
            Paragraph::new(format!(
                "Next: {} ({}) — {} XP needed",
                n.emoji,
                n.name,
                n.xp - xp
            ))
            .style(theme::muted_style()),
            chunks[2],
        );
    } else {
        f.render_widget(
            Paragraph::new("Max level — all guardians unlocked!")
                .style(Style::default().fg(theme::PURPLE_BRIGHT)),
            chunks[2],
        );
    }
}

fn render_stat_card(f: &mut Frame, area: Rect, icon: &str, label: &str, value: &str, color: Color) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(theme::SURFACE));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = vec![
        Line::from(vec![Span::styled(
            icon,
            Style::default().add_modifier(Modifier::BOLD),
        )])
        .alignment(Alignment::Center),
        Line::from(""),
        Line::from(vec![Span::styled(
            value,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )])
        .alignment(Alignment::Center),
        Line::from(vec![Span::styled(label, theme::muted_style())]).alignment(Alignment::Center),
    ];

    f.render_widget(Paragraph::new(lines), inner);
}
