//! Abstracción sobre los backends de protección de filesystem.
//!
//! Dos implementaciones (en crates separados por SO):
//! - `agentguard-linux`: eBPF LSM (kernel-level) + userspace notify (fallback)
//! - `agentguard-windows`: NTFS DENY ACEs + Job Objects (Fase 4)
//! - `agentguard-windows`: NTFS DENY ACEs + Job Objects + AppContainer/LPAC (Fase 4+8)
//!
//! Cada crate de plataforma implementa el trait `KernelGuard`.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::mpsc;

use crate::events::SecurityEvent;

/// Errores del subsistema de guards.
#[derive(Debug, Error)]
pub enum GuardError {
    #[error("I/O error on {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("backend unavailable: {0}")]
    Unavailable(String),

    #[error("backend already running")]
    AlreadyRunning,

    #[error("backend internal error: {0}")]
    Internal(String),
}

/// Niveles de confianza de la protección ofrecida por un guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLevel {
    /// Kernel-level: el backend DENIEGA la operación antes de que ocurra.
    KernelDenial,
    /// Userspace watch: el backend solo OBSERVA. Detecta post-hoc.
    UserspaceObservation,
}

/// Contrato común para todos los backends de protección filesystem.
#[async_trait]
pub trait KernelGuard: Send + Sync {
    /// Etiqueta corta identificando el backend.
    fn backend_name(&self) -> &'static str;

    /// Nivel de protección ofrecido.
    fn protection_level(&self) -> ProtectionLevel;

    /// Añade una ruta protegida. El guard hace canonicalización.
    async fn add_protected_path(&mut self, path: &Path) -> Result<(), GuardError>;

    /// Elimina una ruta protegida. Idempotente.
    async fn remove_protected_path(&mut self, path: &Path) -> Result<(), GuardError>;

    /// Arranca el loop de escucha de eventos.
    async fn run(self: Box<Self>, tx: mpsc::Sender<SecurityEvent>) -> Result<(), GuardError>;
}
