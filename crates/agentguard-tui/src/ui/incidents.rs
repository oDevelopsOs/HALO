//! Incidents tab — formatted security event cards with optional filtering.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::theme;

pub fn render(f: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    // Filter indicator
    if state.filter_active {
        let filter = Paragraph::new(format!(" Filter: {} (Esc to clear)", state.filter_text))
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        f.render_widget(filter, chunks[0]);
    }

    let count = state.daemon.incidents_count;
    let block = Block::default()
        .title(format!(" Incidents — {count} events "))
        .borders(Borders::ALL)
        .border_style(theme::BORDER);

    let content = if state.incidents.is_empty()
        || state
            .incidents
            .iter()
            .all(|s| s == "No incidents recorded yet.")
    {
        "No incidents yet. Your data is safe.\n\n1-6 tabs | r refresh | f filter | h help | q quit"
            .to_string()
    } else {
        format_incidents(&state.incidents, &state.filter_text)
    };

    let para = Paragraph::new(content).block(block);
    f.render_widget(para, chunks[1]);
}

fn format_incidents(lines: &[String], filter: &str) -> String {
    let mut output = String::new();

    for line in lines.iter().rev().take(40) {
        if line == "No incidents recorded yet." {
            continue;
        }

        // Parse JSON to extract fields
        let parsed: Option<serde_json::Value> = serde_json::from_str(line).ok();
        if let Some(ev) = parsed {
            let kind = ev["kind"].as_str().unwrap_or("unknown");
            let agent = ev["agent_name"].as_str().unwrap_or("-");
            let ts = ev["timestamp"].as_u64().unwrap_or(0);
            let path = ev["path"].as_str().unwrap_or("");
            let violation = ev["violation"].as_str().unwrap_or("");

            // Apply filter
            if !filter.is_empty() {
                let lf = filter.to_lowercase();
                if !kind.to_lowercase().contains(&lf)
                    && !agent.to_lowercase().contains(&lf)
                    && !path.to_lowercase().contains(&lf)
                {
                    continue;
                }
            }

            // Color by kind
            let (icon, _color) = match kind {
                "agent_detected" => ("A", Color::Cyan),
                "file_violation" => ("!", Color::Red),
                "dlp_violation" => ("K", Color::Yellow),
                "agent_sandboxed" => ("S", Color::Green),
                _ => ("*", Color::Gray),
            };

            let time = format_ts(ts);

            output.push_str(&format!("{icon} "));
            output.push_str(&format!("{:12}  ", agent));

            match kind {
                "agent_detected" => output.push_str("detected"),
                "file_violation" => output.push_str(&format!("{} → {}", violation, path)),
                "agent_sandboxed" => output.push_str(&format!(
                    "sandboxed (pid={})",
                    ev["sandbox_pid"].as_u64().unwrap_or(0)
                )),
                _ => output.push_str(kind),
            }

            output.push_str(&format!("  {}", time));
            output.push('\n');
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }

    if output.is_empty() && !filter.is_empty() {
        output = format!("No incidents match filter '{}'", filter);
    }

    output
}

fn format_ts(ts: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    match SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(ts)) {
        Some(t) => {
            let d = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let ago = now.saturating_sub(d);
            if ago < 60 {
                format!("{}s ago", ago)
            } else if ago < 3600 {
                format!("{}m ago", ago / 60)
            } else if ago < 86400 {
                format!("{}h ago", ago / 3600)
            } else {
                format!("{}d ago", ago / 86400)
            }
        }
        None => "?".to_string(),
    }
}
