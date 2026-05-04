//! Zones — tabla de rutas protegidas.

use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

use crate::app::AppState;
use crate::theme;

pub fn render(f: &mut Frame, state: &AppState, area: Rect) {
    let dirs = &state.daemon.protected_dirs;
    let files = &state.daemon.protected_files;

    let block = Block::default()
        .title(format!(
            " Protected Zones — {} dirs, {} files ",
            dirs.len(),
            files.len()
        ))
        .borders(Borders::ALL)
        .border_style(theme::BORDER);

    let mut items: Vec<ListItem> = Vec::new();

    if !dirs.is_empty() {
        items.push(ListItem::new("  ── Directories ──").style(theme::heading_style()));
        for d in dirs {
            items.push(ListItem::new(format!("  📁 {d}")).style(theme::muted_style()));
        }
    }

    if !files.is_empty() {
        if !items.is_empty() {
            items.push(ListItem::new(""));
        }
        items.push(ListItem::new("  ── Files ──").style(theme::heading_style()));
        for f in files {
            items.push(ListItem::new(format!("  📄 {f}")).style(theme::muted_style()));
        }
    }

    if items.is_empty() {
        items.push(ListItem::new("  No protected paths configured.").style(theme::muted_style()));
        items.push(ListItem::new("  Use: agentguard protect <path>").style(theme::muted_style()));
    }

    items.push(ListItem::new(""));
    items.push(ListItem::new("  [Enter] Add path  [Delete] Remove  1-4 Switch tab  q Quit")
        .style(theme::muted_style()));

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}
