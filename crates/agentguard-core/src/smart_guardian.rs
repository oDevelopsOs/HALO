//! SmartGuardian — orquestador de protección inteligente (v2.2).
//!
//! El SmartGuardian es el "cerebro" que coordina la detección de agentes IA,
//! la protección automática de workspaces y la sanitización de secretos en
//! prompts a LLMs.
//!
//! Principio: "fall-open" — mejor alertar que romper, sanitizar antes que bloquear.
//!
//! Capas de protección (Defense in Depth):
//!   1. Kernel Guard → bloquea borrado/renombrado de archivos críticos (Hard)
//!   2. Process Sandbox → Landlock + bwrap para agentes AI (Hard)
//!   3. Credential DLP → bloquea envío de credenciales a hosts no autorizados (Hard)
//!   4. Prompt Sanitizer → redacta secretos en prompts a LLMs (Smart)
//!   5. Behavioral Analysis → detecta patrones raros (Observation → Action)

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::config::{DlpAction, GuardianConfig, GuardianMode};
use crate::dlp::patterns::CompiledPattern;
use crate::dlp::redaction::RedactionEngine;
use crate::dlp::sanitizer::PromptSanitizer;
use crate::events::SecurityEvent;

#[derive(Clone)]
pub struct SmartGuardian {
    config: GuardianConfig,
    redaction_engine: Arc<RedactionEngine>,
}

impl SmartGuardian {
    pub fn new(config: GuardianConfig, patterns: Vec<CompiledPattern>) -> Self {
        let engine = RedactionEngine::new(patterns, config.redaction_style);
        Self {
            config,
            redaction_engine: Arc::new(engine),
        }
    }

    pub fn config(&self) -> &GuardianConfig {
        &self.config
    }

    pub fn redaction_engine(&self) -> &Arc<RedactionEngine> {
        &self.redaction_engine
    }

    pub fn mode(&self) -> GuardianMode {
        self.config.mode
    }

    pub fn is_sanitization_enabled(&self) -> bool {
        self.config.sanitization
    }

    pub fn auto_protect_workspaces(&self) -> bool {
        self.config.auto_protect_ai_workspaces
    }

    /// Crea un PromptSanitizer a partir del RedactionEngine interno.
    pub fn create_sanitizer(
        &self,
        events: Option<broadcast::Sender<SecurityEvent>>,
    ) -> PromptSanitizer {
        PromptSanitizer::new((*self.redaction_engine).clone(), events)
    }

    /// Determina la acción DLP efectiva según el modo del guardian.
    ///
    /// En modo Intelligent, degrada Block → Sanitize para endpoints LLM.
    /// En modo Strict, respeta la acción configurada (Block es Block).
    /// En modo Observation, todo pasa a Log.
    pub fn effective_dlp_action(&self, configured: DlpAction) -> DlpAction {
        match self.config.mode {
            GuardianMode::Observation => DlpAction::Log,
            GuardianMode::Intelligent => {
                if configured == DlpAction::Block {
                    DlpAction::Sanitize
                } else {
                    configured
                }
            }
            GuardianMode::Strict => configured,
        }
    }

    /// Devuelve true si el modo actual debería sanitizar (no bloquear).
    pub fn should_sanitize(&self, configured: DlpAction) -> bool {
        matches!(self.effective_dlp_action(configured), DlpAction::Sanitize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guardian() -> SmartGuardian {
        SmartGuardian::new(GuardianConfig::default(), Vec::new())
    }

    #[test]
    fn default_mode_is_intelligent() {
        let g = test_guardian();
        assert!(matches!(g.mode(), GuardianMode::Intelligent));
    }

    #[test]
    fn intelligent_mode_downgrades_block_to_sanitize() {
        let g = test_guardian();
        assert_eq!(
            g.effective_dlp_action(DlpAction::Block),
            DlpAction::Sanitize
        );
    }

    #[test]
    fn intelligent_mode_preserves_alert() {
        let g = test_guardian();
        assert_eq!(g.effective_dlp_action(DlpAction::Alert), DlpAction::Alert);
    }

    #[test]
    fn intelligent_mode_preserves_log() {
        let g = test_guardian();
        assert_eq!(g.effective_dlp_action(DlpAction::Log), DlpAction::Log);
    }

    #[test]
    fn intelligent_mode_preserves_sanitize() {
        let g = test_guardian();
        assert_eq!(
            g.effective_dlp_action(DlpAction::Sanitize),
            DlpAction::Sanitize
        );
    }

    #[test]
    fn observation_mode_downgrades_everything_to_log() {
        let cfg = GuardianConfig {
            mode: GuardianMode::Observation,
            ..GuardianConfig::default()
        };
        let g = SmartGuardian::new(cfg, Vec::new());
        assert_eq!(g.effective_dlp_action(DlpAction::Block), DlpAction::Log);
        assert_eq!(g.effective_dlp_action(DlpAction::Sanitize), DlpAction::Log);
    }

    #[test]
    fn strict_mode_respects_configured_action() {
        let cfg = GuardianConfig {
            mode: GuardianMode::Strict,
            ..GuardianConfig::default()
        };
        let g = SmartGuardian::new(cfg, Vec::new());
        assert_eq!(g.effective_dlp_action(DlpAction::Block), DlpAction::Block);
        assert_eq!(
            g.effective_dlp_action(DlpAction::Sanitize),
            DlpAction::Sanitize
        );
    }

    #[test]
    fn should_sanitize_detects_sanitize_action() {
        let g = test_guardian();
        assert!(g.should_sanitize(DlpAction::Block));
        assert!(!g.should_sanitize(DlpAction::Alert));
        assert!(!g.should_sanitize(DlpAction::Log));
        assert!(g.should_sanitize(DlpAction::Sanitize));
    }

    #[test]
    fn create_sanitizer_produces_working_instance() {
        let patterns = crate::dlp::patterns::compile_defaults().expect("defaults");
        let g = SmartGuardian::new(GuardianConfig::default(), patterns);
        let sanitizer = g.create_sanitizer(None);
        assert!(sanitizer.is_llm_request("api.openai.com"));
    }

    #[test]
    fn sanitization_flag_respected() {
        let cfg = GuardianConfig {
            sanitization: false,
            ..GuardianConfig::default()
        };
        let g = SmartGuardian::new(cfg, Vec::new());
        assert!(!g.is_sanitization_enabled());
    }
}
