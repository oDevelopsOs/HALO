//! Snapshots — lista de snapshots del vault.

use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::theme;

fn fmt_ts(secs: u64) -> String {
    let mins = secs / 60;
    let hours = mins / 60;
    let days = hours / 24;
    if days > 0 {
        format!("{days}d ago")
    } else if hours > 0 {
        format!("{hours}h ago")
    } else if mins > 0 {
        format!("{mins}m ago")
    } else {
        format!("{secs}s ago")
    }
}

fn fmt_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

pub fn render(f: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .title(format!(
            " Snapshots — {} stored ",
            state.snapshots.len()
        ))
        .borders(Borders::ALL)
        .border_style(theme::BORDER);

    if state.snapshots.is_empty() {
        let text = "No snapshots available.\n\nSnapshots are created automatically on violations\nand on daemon start (if configured).\n\nCreate one: agentguard snapshot create --label \"my-snapshot\"";
        let para = Paragraph::new(text)
            .style(theme::muted_style())
            .block(block);
        f.render_widget(para, area);
        return;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut items: Vec<ListItem> = Vec::new();
    items.push(
        ListItem::new(format!(
            "  {:<10}  {:<12}  {:<20}  {:<8}  SIZE",
            "ID", "AGE", "LABEL", "FILES"
        ))
        .style(theme::heading_style()),
    );

    for s in &state.snapshots {
        let short_id = if s.id.len() > 8 { &s.id[..8] } else { &s.id };
        let age = if s.timestamp > 0 && now > s.timestamp {
            fmt_ts(now - s.timestamp)
        } else {
            "now".to_string()
        };
        items.push(ListItem::new(format!(
            "  {short_id:<10}  {age:<12}  {:<20}  {:>5}   {}",
            s.label,
            s.files,
            fmt_size(s.total_size),
        )));
    }

    items.push(ListItem::new(""));
    items.push(
        ListItem::new("  [Enter] Create snapshot  [r] Restore latest  [Backspace] Cleanup old  q Quit")
            .style(theme::muted_style()),
    );

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}
