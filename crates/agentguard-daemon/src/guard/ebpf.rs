//! Backend eBPF LSM — protección kernel-level real.
//!
//! **Estado:** skeleton de Fase 1.5. La compilación del bytecode BPF y
//! `include_bytes_aligned!` se activan cuando se añada `aya` a las
//! dependencias y el `build.rs` compile `crates/agentguard-ebpf` con
//! `cargo +nightly build --target bpfel-unknown-none`.
//!
//! Este módulo existe para:
//! - Definir la API pública (`EbpfGuard::try_load`) que usa `select_guard`.
//! - Hacer el chequeo de `/sys/kernel/security/lsm` **ya** — si falta
//!   `bpf`, devolvemos `Unavailable` y el daemon cae al fallback.
//! - Dejar TODOs concretos por fase para la integración con aya.
//!
//! Requisitos para activar este backend:
//! - `feature = "ebpf"` al compilar el daemon.
//! - Kernel Linux ≥ 5.7 con `CONFIG_BPF_LSM=y`.
//! - `bpf` listado en `/sys/kernel/security/lsm`.
//! - Capabilities `CAP_BPF` + `CAP_SYS_ADMIN` en el proceso (systemd
//!   `AmbientCapabilities` en modo servicio).
//!
//! Ver `.windsurf/rules/03-ebpf-safety.md` para las reglas de seguridad
//! del código kernel-side (en `crates/agentguard-ebpf/`).

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::{GuardError, KernelGuard, ProtectionLevel};
use crate::events::SecurityEvent;

/// Backend eBPF LSM. Struct vacío mientras el loader aya no esté cableado.
#[derive(Debug)]
pub struct EbpfGuard {
    _paths: Vec<PathBuf>,
}

impl EbpfGuard {
    /// Intenta cargar los programas eBPF LSM y attachar los hooks.
    ///
    /// Retorna `GuardError::Unavailable` si:
    /// - El kernel no expone `/sys/kernel/security/lsm`.
    /// - `bpf` no está listado en los LSM activos.
    /// - (Futuro) El BTF del kernel no está disponible.
    /// - (Futuro) Faltan capabilities.
    pub async fn try_load(paths: &[PathBuf]) -> Result<Self, GuardError> {
        check_bpf_lsm_available()?;

        // TODO (Fase 1.5 completa): aquí va el pipeline real:
        //   1. Ensure `build.rs` del daemon ha producido file_guard.bpf.o
        //      y net_guard.bpf.o en OUT_DIR.
        //   2. aya::BpfLoader::new().btf(Btf::from_sys_fs().ok().as_ref())
        //        .load(include_bytes_aligned!(... file_guard.bpf.o))
        //   3. Lsm::load + attach para file_unlink, file_rename, file_open.
        //   4. Populate PROTECTED_PREFIXES array map con los paths.
        //   5. Abrir ring buffer FILE_EVENTS para consumo en `run`.
        //
        // Mientras llegamos ahí, devolvemos Unavailable para que el daemon
        // use el fallback userspace. Esto es coherente con la regla:
        // nunca engañar al usuario sobre el nivel de protección real.
        Err(GuardError::Unavailable(
            "eBPF backend scaffolded but not yet wired — awaiting aya \
             integration in build.rs + kernel_loader (see src/guard/ebpf.rs)"
                .into(),
        ))
        .map(|_: ()| EbpfGuard {
            _paths: paths.to_vec(),
        })
    }
}

#[async_trait]
impl KernelGuard for EbpfGuard {
    fn backend_name(&self) -> &'static str {
        "ebpf-lsm"
    }

    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::KernelDenial
    }

    async fn add_protected_path(&mut self, _path: &Path) -> Result<(), GuardError> {
        // TODO: actualizar PROTECTED_PREFIXES array map vía aya.
        Err(GuardError::Internal("ebpf backend not yet implemented".into()))
    }

    async fn remove_protected_path(&mut self, _path: &Path) -> Result<(), GuardError> {
        Err(GuardError::Internal("ebpf backend not yet implemented".into()))
    }

    async fn run(
        self: Box<Self>,
        _tx: mpsc::Sender<SecurityEvent>,
    ) -> Result<(), GuardError> {
        Err(GuardError::Internal("ebpf backend not yet implemented".into()))
    }
}

/// Verifica que el kernel tiene BPF LSM activo.
///
/// Esta función **sí funciona ya** — la parte que falta es solo la carga
/// de programas. Separarla nos permite tener un "¿es esta máquina
/// compatible?" sin depender de aya.
fn check_bpf_lsm_available() -> Result<(), GuardError> {
    let lsm_path = "/sys/kernel/security/lsm";
    let lsm = std::fs::read_to_string(lsm_path).map_err(|source| GuardError::Io {
        path: PathBuf::from(lsm_path),
        source,
    })?;
    if !lsm.split(',').any(|m| m.trim() == "bpf") {
        return Err(GuardError::Unavailable(format!(
            "kernel LSM list does not include 'bpf' (got {:?}). Add \
             lsm=...,bpf to the kernel cmdline or boot a kernel with \
             CONFIG_BPF_LSM=y",
            lsm.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El scaffold debe fallar siempre con Unavailable o Io.
    /// Cuando se implemente de verdad, actualizar este test.
    #[tokio::test]
    async fn try_load_is_unavailable_until_wired() {
        let err = EbpfGuard::try_load(&[]).await.unwrap_err();
        assert!(
            matches!(err, GuardError::Unavailable(_) | GuardError::Io { .. }),
            "unexpected error: {err:?}"
        );
    }
}
