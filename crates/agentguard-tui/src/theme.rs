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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bg_color_matches_spec() {
        assert_eq!(BG, Color::Rgb(15, 15, 15));
    }

    #[test]
    fn accent_color_is_green() {
        assert_eq!(ACCENT, Color::Rgb(34, 197, 94));
    }

    #[test]
    fn danger_color_is_red() {
        assert_eq!(DANGER, Color::Rgb(239, 68, 68));
    }

    #[test]
    fn warning_color_is_amber() {
        assert_eq!(WARNING, Color::Rgb(245, 158, 11));
    }

    #[test]
    fn title_style_has_bold_and_accent() {
        let s = title_style();
        assert!(s.add_modifier.contains(Modifier::BOLD));
        assert_eq!(s.fg, Some(ACCENT));
    }

    #[test]
    fn danger_style_has_bold_and_red() {
        let s = danger_style();
        assert!(s.add_modifier.contains(Modifier::BOLD));
        assert_eq!(s.fg, Some(DANGER));
    }

    #[test]
    fn muted_style_is_gray() {
        let s = muted_style();
        assert_eq!(s.fg, Some(MUTED));
        assert!(!s.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn heading_style_is_white_bold() {
        let s = heading_style();
        assert_eq!(s.fg, Some(TEXT));
        assert!(s.add_modifier.contains(Modifier::BOLD));
    }
}
