//! Backend macOS — chflags uchg + FSEvents watcher + process detection.
//!
//! Estrategia de protección (Fase 5):
//!
//! 1. **chflags uchg** (degraded): aplica immutable flag a directorios protegidos.
//!    Cualquier proceso del usuario puede deshacerlo con `chflags nouchg`,
//!    por eso se considera protección "degraded". El daemon avisa al usuario
//!    al arrancar.
//!
//! 2. **FSEvents watcher** (via `notify`): monitoriza cambios en directorios
//!    protegidos. Emite eventos post-hoc (no puede denegar).
//!
//! 3. **Detección de procesos**: usa `libc::proc_listallpids` para enumerar
//!    procesos y matchear contra patrones de agente AI.
//!
//! Plan futuro: Endpoint Security Framework System Extension para protección
//! real a nivel de kernel (requiere entitlement de Apple).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use notify::Watcher;
use tokio::sync::mpsc;
#[cfg(target_os = "macos")]
use tracing::info;
use tracing::warn;

use agentguard_core::config::AgentProcess;
use agentguard_core::{GuardError, KernelGuard, ProtectionLevel, SecurityEvent, ViolationKind};

/// Intervalo de escaneo de procesos agente (milisegundos).
#[cfg(target_os = "macos")]
const PROCESS_SCAN_INTERVAL_MS: u64 = 5_000;
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
const PROCESS_SCAN_INTERVAL_MS: u64 = 5_000;

/// Backend macOS con chflags, FSEvents y detección de agentes.
pub struct MacOsGuard {
    protected_paths: HashSet<PathBuf>,
    agent_patterns: Vec<AgentProcess>,
    tracked_pids: HashSet<u32>,
}

impl std::fmt::Debug for MacOsGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOsGuard")
            .field("paths", &self.protected_paths.len())
            .field("agent_patterns", &self.agent_patterns.len())
            .field("tracked_pids", &self.tracked_pids.len())
            .finish_non_exhaustive()
    }
}

impl MacOsGuard {
    #[cfg(target_os = "macos")]
    pub fn new(paths: &[PathBuf], agent_patterns: Vec<AgentProcess>) -> Result<Self, GuardError> {
        let mut canonical = HashSet::new();
        for p in paths {
            match canonicalize(p) {
                Ok(c) => {
                    protect_with_chflags(&c)?;
                    canonical.insert(c);
                }
                Err(e) => {
                    warn!(path = ?p, error = %e, "skipping protected path");
                }
            }
        }

        info!(
            paths = canonical.len(),
            patterns = agent_patterns.len(),
            "macOS guard initialized (chflags uchg + FSEvents) — degraded mode"
        );
        warn!("macOS protection is in degraded mode (chflags). EndpointSecurity requires Apple entitlement for kernel-level deny.");

        Ok(Self {
            protected_paths: canonical,
            agent_patterns,
            tracked_pids: HashSet::new(),
        })
    }

    #[cfg(not(target_os = "macos"))]
    pub fn new(_paths: &[PathBuf], agent_patterns: Vec<AgentProcess>) -> Result<Self, GuardError> {
        warn!("MacOsGuard is a stub on this platform — no protection available");
        Ok(Self {
            protected_paths: HashSet::new(),
            agent_patterns,
            tracked_pids: HashSet::new(),
        })
    }
}

#[async_trait]
impl KernelGuard for MacOsGuard {
    fn backend_name(&self) -> &'static str {
        "macos-chflags"
    }

    fn protection_level(&self) -> ProtectionLevel {
        #[cfg(target_os = "macos")]
        {
            ProtectionLevel::UserspaceObservation
        }
        #[cfg(not(target_os = "macos"))]
        {
            ProtectionLevel::UserspaceObservation
        }
    }

    async fn add_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        #[cfg(target_os = "macos")]
        {
            let c = canonicalize(path)?;
            protect_with_chflags(&c)?;
            self.protected_paths.insert(c);
            info!(path = ?path, "added macOS-protected path (chflags uchg)");
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = path;
            Err(GuardError::Unavailable(
                "MacOsGuard is a stub on this platform".into(),
            ))
        }
    }

    async fn remove_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        #[cfg(target_os = "macos")]
        {
            let c = canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            unprotect_chflags(&c)?;
            self.protected_paths.remove(&c);
            info!(path = ?path, "removed macOS chflags protection");
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = path;
            Ok(())
        }
    }

    async fn run(mut self: Box<Self>, tx: mpsc::Sender<SecurityEvent>) -> Result<(), GuardError> {
        #[cfg(target_os = "macos")]
        {
            let paths = std::mem::take(&mut self.protected_paths);
            let patterns = std::mem::take(&mut self.agent_patterns);
            let mut tracked = std::mem::take(&mut self.tracked_pids);

            // FSEvents watcher
            let (notify_tx, notify_rx) =
                std::sync::mpsc::channel::<notify::Result<notify::Event>>();
            let mut watcher = notify::recommended_watcher(move |res| {
                let _ = notify_tx.send(res);
            })
            .map_err(|e| GuardError::Internal(format!("FSEvents watcher init: {e}")))?;

            for path in &paths {
                match watcher.watch(path, notify::RecursiveMode::Recursive) {
                    Ok(()) => info!(path = ?path, "watching (macOS FSEvents)"),
                    Err(e) => warn!(path = ?path, error = %e, "cannot watch path"),
                }
            }

            let watch_tx = tx.clone();
            let watch_handle = tokio::task::spawn_blocking(move || {
                while let Ok(res) = notify_rx.recv() {
                    match res {
                        Ok(event) => {
                            for ev in translate_notify_event(event) {
                                if watch_tx.blocking_send(ev).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "FSEvents watcher error");
                        }
                    }
                }
            });

            // Procesos — solo en macOS con libc
            let scan_tx = tx.clone();
            let scan_handle = tokio::spawn(async move {
                loop {
                    scan_and_detect_agents(&patterns, &mut tracked, &scan_tx);
                    tokio::time::sleep(std::time::Duration::from_millis(PROCESS_SCAN_INTERVAL_MS))
                        .await;
                }
            });

            info!("macOS guard event listener started (chflags + FSEvents)");

            let _ = tokio::join!(watch_handle, scan_handle);
            drop(watcher);
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            warn!("MacOsGuard is a stub on this platform — event loop not started");
            let _ = tx;
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// ── macOS chflags ──────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "macos")]
fn protect_with_chflags(path: &Path) -> Result<(), GuardError> {
    let status = std::process::Command::new("chflags")
        .arg("uchg")
        .arg(path)
        .status()
        .map_err(|e| GuardError::Internal(format!("chflags uchg failed for {path:?}: {e}")))?;

    if !status.success() {
        return Err(GuardError::Internal(format!(
            "chflags uchg failed for {path:?}: exit code {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn unprotect_chflags(path: &Path) -> Result<(), GuardError> {
    let status = std::process::Command::new("chflags")
        .arg("nouchg")
        .arg(path)
        .status()
        .map_err(|e| GuardError::Internal(format!("chflags nouchg failed for {path:?}: {e}")))?;

    if !status.success() {
        warn!(path = ?path, "chflags nouchg failed — may already be unprotected");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// ── Detección de procesos agente (macOS) ──────────────────────
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "macos")]
fn scan_and_detect_agents(
    patterns: &[AgentProcess],
    tracked: &mut HashSet<u32>,
    tx: &mpsc::Sender<SecurityEvent>,
) {
    let current_pid = unsafe { libc::getpid() as u32 };

    // Obtener todos los PIDs del sistema
    let mut buffer_size = 4096;
    let mut pids: Vec<libc::pid_t> = Vec::new();

    loop {
        pids.resize(buffer_size, 0);
        let count = unsafe {
            libc::proc_listallpids(
                pids.as_mut_ptr() as *mut _,
                (buffer_size * std::mem::size_of::<libc::pid_t>()) as i32,
            )
        };
        if count < 0 {
            warn!("proc_listallpids failed");
            return;
        }
        let num = count as usize / std::mem::size_of::<libc::pid_t>();
        if num < buffer_size {
            pids.truncate(num);
            break;
        }
        buffer_size *= 2;
    }

    for &pid in &pids {
        let pid_u32 = pid as u32;
        if pid_u32 == 0 || pid_u32 == current_pid || tracked.contains(&pid_u32) {
            continue;
        }

        let mut path_buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let path_len = unsafe {
            libc::proc_pidpath(pid, path_buf.as_mut_ptr() as *mut _, path_buf.len() as u32)
        };
        if path_len <= 0 {
            continue;
        }
        path_buf.truncate(path_len as usize);
        let path_str = String::from_utf8_lossy(&path_buf);
        let exe_name = Path::new(path_str.as_ref())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if matches_agent(patterns, exe_name) {
            tracked.insert(pid_u32);
            info!(pid = pid_u32, exe = %exe_name, "detected AI agent process on macOS");
            let _ = tx.blocking_send(SecurityEvent::SystemError {
                message: format!("AI agent detected: {exe_name} (pid {pid_u32})"),
                timestamp: unix_ts(),
            });
        }
    }

    // Limpiar PIDs muertos
    tracked.retain(|&pid| {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<libc::proc_bsdinfo>() as i32,
            )
        };
        result > 0
    });
}

#[cfg(target_os = "macos")]
fn matches_agent(patterns: &[AgentProcess], exe_name: &str) -> bool {
    let lower = exe_name.to_lowercase();
    patterns.iter().any(|p| {
        let name_lower = p.name.to_lowercase();
        lower.contains(&name_lower)
            || p.r#match
                .exe_any
                .iter()
                .any(|e| lower.contains(&e.to_lowercase()))
    })
}

// ═══════════════════════════════════════════════════════════════
// ── Platform-independent helpers ──────────────────────────────
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "macos")]
fn translate_notify_event(ev: notify::Event) -> Vec<SecurityEvent> {
    use notify::event::{ModifyKind, RemoveKind};
    use notify::EventKind;

    let kind = match ev.kind {
        EventKind::Remove(RemoveKind::File) | EventKind::Remove(RemoveKind::Folder) => {
            ViolationKind::DeleteAttempt
        }
        EventKind::Modify(ModifyKind::Name(_)) => ViolationKind::RenameAttempt,
        EventKind::Modify(ModifyKind::Data(_)) => ViolationKind::WriteAttempt,
        EventKind::Create(_) => ViolationKind::CreateAttempt,
        _ => return Vec::new(),
    };

    ev.paths
        .into_iter()
        .map(|path| SecurityEvent::FileViolation {
            path,
            process: "<unknown>".to_string(),
            pid: 0,
            violation: kind,
            timestamp: unix_ts(),
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn canonicalize(p: &Path) -> Result<PathBuf, GuardError> {
    std::fs::canonicalize(p).map_err(|source| GuardError::Io {
        path: p.to_path_buf(),
        source,
    })
}

#[cfg(target_os = "macos")]
fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_name_is_macos() {
        let guard = MacOsGuard::new(&[], vec![]).expect("new");
        assert_eq!(guard.backend_name(), "macos-chflags");
    }

    #[test]
    fn protection_level_is_userspace() {
        let guard = MacOsGuard::new(&[], vec![]).expect("new");
        assert_eq!(
            guard.protection_level(),
            ProtectionLevel::UserspaceObservation
        );
    }

    #[test]
    fn matches_common_ai_agents() {
        let _patterns = [
            AgentProcess {
                name: "cursor".into(),
                r#match: Default::default(),
            },
            AgentProcess {
                name: "claude".into(),
                r#match: Default::default(),
            },
        ];

        #[cfg(target_os = "macos")]
        {
            assert!(matches_agent(&patterns, "Cursor"));
            assert!(matches_agent(&patterns, "Claude"));
            assert!(!matches_agent(&patterns, "Terminal"));
        }
        #[cfg(not(target_os = "macos"))]
        {
            // On non-macOS, matches_agent is not available — test the struct creation
        }
    }

    #[test]
    fn new_creates_guard_on_any_platform() {
        let guard = MacOsGuard::new(&[], vec![]).expect("new");
        assert_eq!(guard.protected_paths.len(), 0);
        assert_eq!(guard.tracked_pids.len(), 0);
    }
}
