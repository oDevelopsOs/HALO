//! Aplica restricciones Landlock al proceso llamante.
//!
//! Usado en modo `hybrid`: bwrap aísla el filesystem, Landlock añade una
//! capa adicional de restricción a nivel de kernel (sin necesidad de root).
//!
//! Requiere: kernel >= 5.13, crate `landlock` 0.4.
//! Solo disponible en Linux.
//!
//! ## Limitaciones conocidas
//!
//! * **Per-thread**: `restrict_self()` solo aplica al hilo actual. Otros hilos
//!   del mismo proceso no están restringidos. Si el agente es multi-threaded,
//!   los hilos secundarios conservan acceso completo al filesystem.
//!
//! * **Archivos ya abiertos**: cualquier file descriptor o memory mapping
//!   abierto antes de `restrict_self()` sigue siendo accesible. Esto incluye
//!   las shared libraries cargadas por el dynamic linker.

#[cfg(target_os = "linux")]
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LandlockError {
    #[error("Landlock not supported on this kernel")]
    NotSupported,
    #[error("Landlock ruleset creation failed: {0}")]
    RulesetCreation(String),
    #[error("Failed to add rule for {path}: {err}")]
    RuleAdd { path: String, err: String },
    #[error("Failed to restrict thread: {0}")]
    Restrict(String),
    #[error("Landlock partially enforced (older kernel, some access not restricted)")]
    PartiallyEnforced,
    #[error("Landlock not enforced (kernel does not support this ABI)")]
    NotEnforced,
}

/// Aplica un perfil Landlock al proceso actual:
/// - `rw_paths`: directorios con acceso lectura/escritura
/// - `ro_paths`: directorios con acceso solo lectura
/// - Todo lo demás: DENEGADO
pub fn apply_landlock_profile(rw_paths: &[&Path], ro_paths: &[&Path]) -> Result<(), LandlockError> {
    let abi = ABI::V3;

    let all_access = AccessFs::from_all(abi);
    let ruleset = Ruleset::default()
        .handle_access(all_access)
        .map_err(|e| LandlockError::RulesetCreation(e.to_string()))?
        .create()
        .map_err(|e| LandlockError::RulesetCreation(e.to_string()))?;

    // Añadir reglas rw y ro usando path_beneath_rules (conservando Result items)
    let ro_access = AccessFs::from_read(abi);
    let all_rules =
        path_beneath_rules(rw_paths, all_access).chain(path_beneath_rules(ro_paths, ro_access));

    let ruleset = ruleset
        .add_rules(all_rules)
        .map_err(|e| LandlockError::RuleAdd {
            path: "<paths>".into(),
            err: e.to_string(),
        })?;

    let status = ruleset
        .restrict_self()
        .map_err(|e| LandlockError::Restrict(e.to_string()))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("Landlock: fully enforced");
            Ok(())
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::warn!("Landlock: partially enforced (older kernel)");
            Err(LandlockError::PartiallyEnforced)
        }
        RulesetStatus::NotEnforced => {
            tracing::warn!("Landlock: not enforced (not supported)");
            Err(LandlockError::NotEnforced)
        }
    }
}
