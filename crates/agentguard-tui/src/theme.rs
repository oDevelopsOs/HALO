//! Colores y estilos del tema AgentGuard oscuro.
//!
//! Especificación visual: fondo #0f0f0f, acento verde #22c55e,
//! rojo para violaciones, amarillo para alertas.

#![allow(dead_code)]

use ratatui::style::{Color, Modifier, Style};

pub const BG: Color = Color::Rgb(15, 15, 15);
pub const SURFACE: Color = Color::Rgb(26, 26, 26);
pub const ACCENT: Color = Color::Rgb(34, 197, 94);
pub const DANGER: Color = Color::Rgb(239, 68, 68);
pub const WARNING: Color = Color::Rgb(245, 158, 11);
pub const TEXT: Color = Color::Rgb(232, 232, 232);
pub const MUTED: Color = Color::Rgb(136, 136, 136);
pub const BORDER: Color = Color::Rgb(50, 50, 50);

pub fn title_style() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn heading_style() -> Style {
    Style::default().fg(TEXT).add_modifier(Modifier::BOLD)
}

pub fn muted_style() -> Style {
    Style::default().fg(MUTED)
}

pub fn danger_style() -> Style {
    Style::default().fg(DANGER).add_modifier(Modifier::BOLD)
}

#[allow(dead_code)]
pub fn warning_style() -> Style {
    Style::default().fg(WARNING)
}

pub fn accent_style() -> Style {
    Style::default().fg(ACCENT)
}
