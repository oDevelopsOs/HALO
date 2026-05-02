//! Módulo guard para Linux: expone el backend eBPF y el fallback userspace,
//! más la función `select_guard` que elige uno en runtime.

pub mod userspace;

#[cfg(feature = "ebpf")]
pub mod ebpf;

use std::path::PathBuf;

use agentguard_core::{GuardError, KernelGuard};

pub async fn select_guard(
    protected_paths: &[PathBuf],
    protected_files: &[PathBuf],
) -> Result<Box<dyn KernelGuard>, GuardError> {
    #[cfg(feature = "ebpf")]
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
    #[cfg(not(feature = "ebpf"))]
    {
        let _ = protected_files;
    }

    let guard = userspace::UserspaceGuard::new(protected_paths)?;
    tracing::warn!(
        backend = "userspace",
        level = "observation-only",
        "using userspace fallback — protection detects but does NOT block"
    );
    Ok(Box::new(guard))
}
