//! AgentGuard UI — stub de Fase 0.
//!
//! La implementación completa con Tauri v2 + Svelte está planeada para
//! Fase 4 (ver `.windsurf/plans/agentguard-implementation-4a29ac.md`).
//! Este crate existe ahora solo para reservar el nombre en el workspace
//! y garantizar que el CI lo compila desde el primer día.

/// Placeholder API. Se reemplazará por los Tauri commands reales.
pub fn placeholder() -> &'static str {
    "agentguard-ui stub"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_returns_known_string() {
        assert_eq!(placeholder(), "agentguard-ui stub");
    }
}
