//! AgentGuard TUI theme — purple + orange accent system.
//!
//! Palette:
//!   Background: #0A0A0A (deep matte black)
//!   Surface:    #15141C (card surfaces)
//!   Purple:     #7C3AED (vibrant purple — interactive elements)
//!   Orange:     #F97316 (warm orange — warnings/violations, Claude-style)

use ratatui::style::{Color, Modifier, Style};

pub const BG: Color = Color::Rgb(0x0A, 0x0A, 0x0A);
pub const SURFACE: Color = Color::Rgb(0x15, 0x14, 0x1C);
pub const PURPLE: Color = Color::Rgb(0x7C, 0x3A, 0xED);
pub const PURPLE_DIM: Color = Color::Rgb(0x5B, 0x2A, 0xB5);
pub const PURPLE_BRIGHT: Color = Color::Rgb(0xA7, 0x8B, 0xFA);
#[allow(dead_code)]
pub const TEXT: Color = Color::Rgb(0xF8, 0xF8, 0xF8);
pub const MUTED: Color = Color::Rgb(0x6B, 0x6A, 0x72);
pub const ORANGE: Color = Color::Rgb(0xF9, 0x73, 0x16);
pub const ORANGE_DIM: Color = Color::Rgb(0xC2, 0x41, 0x0C);
pub const BORDER: Color = Color::Rgb(0x2D, 0x2C, 0x35);

pub fn title_style() -> Style {
    Style::default().fg(PURPLE).add_modifier(Modifier::BOLD)
}
pub fn heading_style() -> Style {
    Style::default()
        .fg(PURPLE_BRIGHT)
        .add_modifier(Modifier::BOLD)
}
pub fn muted_style() -> Style {
    Style::default().fg(MUTED)
}
pub fn danger_style() -> Style {
    Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
}
#[allow(dead_code)]
pub fn warning_style() -> Style {
    Style::default().fg(ORANGE_DIM)
}
pub fn accent_style() -> Style {
    Style::default().fg(PURPLE_BRIGHT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bg_is_deep_black() {
        assert_eq!(BG, Color::Rgb(0x0A, 0x0A, 0x0A));
    }
    #[test]
    fn purple_is_vibrant() {
        assert_eq!(PURPLE, Color::Rgb(0x7C, 0x3A, 0xED));
    }
    #[test]
    fn orange_is_warm() {
        assert_eq!(ORANGE, Color::Rgb(0xF9, 0x73, 0x16));
    }
    #[test]
    fn title_style_has_bold_and_purple() {
        let s = title_style();
        assert!(s.add_modifier.contains(Modifier::BOLD));
        assert_eq!(s.fg, Some(PURPLE));
    }
    #[test]
    fn heading_style_has_bold_and_bright() {
        let s = heading_style();
        assert!(s.add_modifier.contains(Modifier::BOLD));
        assert_eq!(s.fg, Some(PURPLE_BRIGHT));
    }
    #[test]
    fn accent_style_uses_bright() {
        let s = accent_style();
        assert_eq!(s.fg, Some(PURPLE_BRIGHT));
    }
    #[test]
    fn danger_style_uses_orange() {
        let s = danger_style();
        assert_eq!(s.fg, Some(ORANGE));
    }
}
