//! Módulo guard para Linux: expone el backend eBPF y el fallback userspace,
//! más la función `select_guard` que elige uno en runtime.

pub mod userspace;

pub mod agents;

#[cfg(feature = "ebpf")]
pub mod ebpf;

use std::path::PathBuf;

use agentguard_core::{GuardError, KernelGuard};

pub async fn select_guard(
    protected_paths: &[PathBuf],
    protected_files: &[PathBuf],
    dlp_enabled: bool,
) -> Result<Box<dyn KernelGuard>, GuardError> {
    #[cfg(feature = "ebpf")]
    {
        match ebpf::EbpfGuard::try_load(protected_paths, protected_files).await {
            Ok(mut guard) => {
                tracing::info!(backend = "ebpf", "kernel-level protection active");
                // If DLP proxy is enabled, activate network restriction at kernel level.
                // This blocks non-localhost outbound connections from ALL processes,
                // forcing traffic through the DLP proxy on 127.0.0.1.
                if dlp_enabled {
                    if let Err(e) = guard.set_network_restricted(true) {
                        tracing::warn!(error = %e, "failed to enable network restriction");
                    } else {
                        tracing::info!("ebpf network restriction enabled (DLP mode)");
                    }
                }
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
