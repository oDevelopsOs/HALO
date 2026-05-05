//! Sistema de color AgentGuard — paleta SaaS moderna.
//!
//! Inspirado en Claude Code: fondo negro cálido, naranja terracota
//! como acento principal (alegría/energía), morado para títulos (premium),
//! y esmeralda para protección/éxito.

#![allow(dead_code)]

use ratatui::style::{Color, Modifier, Style};

pub const BG: Color = Color::Rgb(0x12, 0x11, 0x18);
pub const SURFACE: Color = Color::Rgb(0x1D, 0x1C, 0x25);
pub const ACCENT: Color = Color::Rgb(0xD9, 0x77, 0x57);
pub const PRIMARY: Color = Color::Rgb(0xA7, 0x8B, 0xFA);
pub const SUCCESS: Color = Color::Rgb(0x34, 0xD3, 0x99);
pub const DANGER: Color = Color::Rgb(0xF8, 0x71, 0x71);
pub const WARNING: Color = Color::Rgb(0xFB, 0xBF, 0x24);
pub const TEXT: Color = Color::Rgb(0xF0, 0xEE, 0xE6);
pub const MUTED: Color = Color::Rgb(0x8B, 0x8A, 0x92);
pub const BORDER: Color = Color::Rgb(0x2D, 0x2C, 0x35);

pub fn title_style() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn heading_style() -> Style {
    Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)
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
    Style::default().fg(SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bg_is_deep_purple_black() {
        assert_eq!(BG, Color::Rgb(0x12, 0x11, 0x18));
    }

    #[test]
    fn accent_is_terracotta_clay() {
        assert_eq!(ACCENT, Color::Rgb(0xD9, 0x77, 0x57));
    }

    #[test]
    fn primary_is_soft_purple() {
        assert_eq!(PRIMARY, Color::Rgb(0xA7, 0x8B, 0xFA));
    }

    #[test]
    fn success_is_emerald() {
        assert_eq!(SUCCESS, Color::Rgb(0x34, 0xD3, 0x99));
    }

    #[test]
    fn danger_is_soft_red() {
        assert_eq!(DANGER, Color::Rgb(0xF8, 0x71, 0x71));
    }

    #[test]
    fn warning_is_amber() {
        assert_eq!(WARNING, Color::Rgb(0xFB, 0xBF, 0x24));
    }

    #[test]
    fn title_style_has_bold_and_accent() {
        let s = title_style();
        assert!(s.add_modifier.contains(Modifier::BOLD));
        assert_eq!(s.fg, Some(ACCENT));
    }

    #[test]
    fn heading_style_has_bold_and_primary() {
        let s = heading_style();
        assert!(s.add_modifier.contains(Modifier::BOLD));
        assert_eq!(s.fg, Some(PRIMARY));
    }

    #[test]
    fn danger_style_has_bold_and_danger() {
        let s = danger_style();
        assert!(s.add_modifier.contains(Modifier::BOLD));
        assert_eq!(s.fg, Some(DANGER));
    }

    #[test]
    fn accent_style_uses_success() {
        let s = accent_style();
        assert_eq!(s.fg, Some(SUCCESS));
    }

    #[test]
    fn muted_style_is_muted() {
        let s = muted_style();
        assert_eq!(s.fg, Some(MUTED));
        assert!(!s.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn text_is_warm_off_white() {
        assert_eq!(TEXT, Color::Rgb(0xF0, 0xEE, 0xE6));
    }
}
