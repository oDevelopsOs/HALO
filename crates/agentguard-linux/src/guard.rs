//! Módulo guard para Linux: expone el backend eBPF, el fallback userspace
//! (fanotify con FAN_DENY, o inotify observation-only como último recurso),
//! más la función `select_guard` que elige uno en runtime.

pub mod userspace;

#[cfg(target_os = "linux")]
pub mod fanotify;

pub mod agents;

#[cfg(feature = "ebpf")]
pub mod ebpf;

use std::path::{Path, PathBuf};

use agentguard_core::{GuardError, KernelGuard};

pub async fn select_guard(
    protected_paths: &[PathBuf],
    protected_files: &[PathBuf],
    _dlp_enabled: bool,
    agent_names: &[String],
) -> Result<Box<dyn KernelGuard>, GuardError> {
    #[cfg(feature = "ebpf")]
    {
        // ── Diagnostic: check WHY eBPF might fail ──────
        let lsm_list = std::fs::read_to_string("/sys/kernel/security/lsm")
            .unwrap_or_else(|_| "<unreadable>".into());
        let bpf_in_lsm = lsm_list.split(',').any(|m| m.trim() == "bpf");
        let bpffs_mounted = Path::new("/sys/fs/bpf").is_dir();

        if !bpf_in_lsm {
            tracing::warn!(
                lsm = %lsm_list.trim(),
                "eBPF LSM not available — 'bpf' missing from /sys/kernel/security/lsm. Add 'bpf' to kernel cmdline: lsm=...,bpf"
            );
        } else if !bpffs_mounted {
            tracing::warn!(
                "bpffs not mounted at /sys/fs/bpf. Mount it: mount -t bpffs bpffs /sys/fs/bpf"
            );
        } else {
            tracing::info!(
                lsm = %lsm_list.trim(),
                bpffs = true,
                "eBPF prerequisites met — attempting to load LSM programs"
            );
        }

        // Check for pinned BPF programs from a previous run — try recovery first
        if ebpf::pinned_programs_exist() {
            match ebpf::EbpfGuard::try_recover(protected_paths, protected_files).await {
                Ok(mut guard) => {
                    tracing::info!("eBPF recovered from pinned programs in /sys/fs/bpf/agentguard");
                    // Reset network restriction (may be stale from previous run)
                    let _ = guard.set_network_restricted(false);
                    let _ = guard.populate_bprm_agents(agent_names);
                    return Ok(Box::new(guard));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "BPF recovery failed — loading fresh bytecode");
                }
            }
        }

        match ebpf::EbpfGuard::try_load(protected_paths, protected_files).await {
            Ok(mut guard) => {
                tracing::info!(backend = "ebpf", "kernel-level protection active");
                // Reset network restriction (off by default, DLP proxy handles inspection)
                let _ = guard.set_network_restricted(false);
                if let Err(e) = guard.populate_bprm_agents(agent_names) {
                    tracing::warn!(error = %e, "failed to populate bprm agents — exec blocking disabled");
                } else if !agent_names.is_empty() {
                    tracing::info!(
                        count = agent_names.len(),
                        "bprm_check_security agents populated"
                    );
                }
                return Ok(Box::new(guard));
            }
            Err(e) => {
                tracing::warn!(error = %e, "eBPF unavailable — falling back to fanotify (userspace, blocking)");
            }
        }
    }
    #[cfg(not(feature = "ebpf"))]
    {
        let _ = protected_files;
        let _ = _dlp_enabled;
        let _ = agent_names;
    }

    // ── Fallback: fanotify with FAN_DENY (blocks write-opens) ──
    #[cfg(target_os = "linux")]
    {
        match fanotify::FanotifyGuard::new(protected_paths) {
            Ok(guard) => {
                tracing::info!(
                    backend = "fanotify",
                    paths = protected_paths.len(),
                    "using fanotify userspace guard — blocking write-opens on protected paths"
                );
                return Ok(Box::new(guard));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "fanotify unavailable — falling back to inotify (observation-only)"
                );
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = protected_files;
    }

    // ── Last resort: inotify observation-only ──
    let guard = userspace::UserspaceGuard::new(protected_paths)?;
    tracing::warn!(
        backend = "userspace-inotify",
        level = "observation-only",
        "using inotify userspace fallback — protection detects but does NOT block"
    );
    Ok(Box::new(guard))
}
