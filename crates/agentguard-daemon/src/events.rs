//! Eventos de seguridad que viajan desde los guards (kernel/userspace) hasta
//! el loop principal del daemon.
//!
//! Estos tipos son la cara userspace-friendly de los structs FFI en
//! `agentguard_common`. Se mantienen separados porque:
//! - Aquí sí podemos usar `String`, `PathBuf`, `serde`.
//! - El JSON serializado en `incidents.jsonl` depende de este schema y
//!   está bajo control de versión semántico (schema v1).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Eventos emitidos por cualquier backend de protección.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecurityEvent {
    /// Intento de mutación sobre una ruta protegida.
    FileViolation {
        path: PathBuf,
        process: String,
        pid: u32,
        violation: ViolationKind,
        #[serde(default = "current_timestamp")]
        timestamp: u64,
    },

    /// Secreto detectado en tráfico saliente por el proxy DLP.
    DlpViolation {
        pattern_name: String,
        destination: String,
        process: String,
        pid: u32,
        #[serde(default = "current_timestamp")]
        timestamp: u64,
    },

    /// Error interno del daemon (ej: backend kernel caído).
    SystemError {
        message: String,
        #[serde(default = "current_timestamp")]
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    DeleteAttempt,
    WriteAttempt,
    RenameAttempt,
    CreateAttempt,
}

impl SecurityEvent {
    /// Timestamp UNIX del evento.
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::FileViolation { timestamp, .. }
            | Self::DlpViolation { timestamp, .. }
            | Self::SystemError { timestamp, .. } => *timestamp,
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_violation_roundtrips_json() {
        let ev = SecurityEvent::FileViolation {
            path: PathBuf::from("/tmp/zone/file.md"),
            process: "rogue-agent".into(),
            pid: 12345,
            violation: ViolationKind::DeleteAttempt,
            timestamp: 1_700_000_000,
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"kind\":\"file_violation\""));
        assert!(json.contains("\"violation\":\"delete_attempt\""));
        let back: SecurityEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.timestamp(), 1_700_000_000);
    }

    #[test]
    fn dlp_violation_does_not_contain_secret_value() {
        // Guardarrail: el schema JSON no tiene campo para el valor del secreto.
        // Si alguien añade uno, este test se rompe (y hay que revisar la rule
        // de security logging).
        let ev = SecurityEvent::DlpViolation {
            pattern_name: "OpenAI API Key".into(),
            destination: "https://api.openai.com/v1/chat".into(),
            process: "cursor".into(),
            pid: 42,
            timestamp: 0,
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(!json.contains("sk-"));
        assert!(!json.contains("secret"));
    }
}
