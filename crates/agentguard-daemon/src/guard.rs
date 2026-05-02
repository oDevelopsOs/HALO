//! Abstracción sobre los backends de protección de filesystem.
//!
//! Dos implementaciones:
//! - [`userspace::UserspaceGuard`]: basada en `notify`, funciona en
//!   cualquier kernel. **No puede impedir** la operación — solo la
//!   detecta post-hoc. Útil como fallback o en dev.
//! - [`ebpf::EbpfGuard`] (feature `ebpf`, Linux + BPF LSM): intercepta
//!   syscalls en el kernel y las **bloquea antes** de que ocurran.
//!
//! El daemon selecciona en runtime según disponibilidad (ver
//! [`select_guard`]).

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
    /// Userspace watch: el backend solo OBSERVA. Detecta post-hoc y puede
    /// revertir (restaurar del vault), pero no previene.
    UserspaceObservation,
}

/// Contrato común para todos los backends de protección filesystem.
#[async_trait]
pub trait KernelGuard: Send + Sync {
    /// Etiqueta corta identificando el backend (para logs y métricas).
    fn backend_name(&self) -> &'static str;

    /// Nivel de protección ofrecido — es un contrato con el usuario.
    fn protection_level(&self) -> ProtectionLevel;

    /// Añade una ruta protegida. El guard hace canonicalización interna.
    async fn add_protected_path(&mut self, path: &Path) -> Result<(), GuardError>;

    /// Elimina una ruta protegida. Idempotente: si no estaba, no falla.
    async fn remove_protected_path(&mut self, path: &Path) -> Result<(), GuardError>;

    /// Arranca el loop de escucha de eventos. El future retorna cuando el
    /// remitente del canal se cierra o cuando ocurre un error fatal.
    async fn run(self: Box<Self>, tx: mpsc::Sender<SecurityEvent>) -> Result<(), GuardError>;
}

pub mod userspace;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;

/// Elige el mejor guard disponible para la plataforma actual.
///
/// Orden de preferencia:
/// 1. eBPF LSM (Linux, feature `ebpf`, kernel con `bpf` en
///    `/sys/kernel/security/lsm`).
/// 2. Userspace (`notify`) — funciona siempre.
pub async fn select_guard(
    protected_paths: &[PathBuf],
    protected_files: &[PathBuf],
) -> Result<Box<dyn KernelGuard>, GuardError> {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        match ebpf::EbpfGuard::try_load(protected_paths, protected_files).await {
            Ok(guard) => {
                tracing::info!(backend = "ebpf", "kernel-level protection active");
                return Ok(Box::new(guard));
            }
            Err(e) => {
                tracing::warn!(error = %e, "eBPF unavailable — falling back to userspace");
            }
        }
    }

    let guard = userspace::UserspaceGuard::new(protected_paths)?;
    tracing::warn!(
        backend = "userspace",
        level = "observation-only",
        "using userspace fallback — protection detects but does NOT block"
    );
    Ok(Box::new(guard))
}
