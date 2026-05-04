//! IPC server — socket Unix / Named Pipe para que CLI y UI se comuniquen
//! con el daemon en runtime.
//!
//! Protocolo: JSON-line (una línea JSON por comando, una por respuesta).
//! El cliente envía un `IpcCommand` serializado, el servidor responde
//! con un `IpcResponse`.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use agentguard_common::{IpcCommand, IpcResponse, SandboxedAgent, SnapshotInfo};
use serde_json;
use tokio::sync::oneshot;

use crate::config::Config;
use crate::vault::Vault;

/// Tipo de callback para lanzar un agente en sandbox.
/// Inyectado por el daemon específico de cada plataforma.
pub type LaunchAgentFn = Arc<
    dyn Fn(String, String, Vec<String>, Option<String>) -> Result<u32, String> + Send + Sync,
>;

/// Máximo de líneas a leer del log de incidentes (evita OOM).
const INCIDENTS_MAX_LINES: usize = 500;

/// Helper: adquiere el lock de lectura del config, manejando poison.
fn read_config(cfg: &RwLock<Config>) -> Result<RwLockReadGuard<'_, Config>, String> {
    cfg.read().map_err(|e| format!("config lock poisoned: {e}"))
}

/// Helper: adquiere el lock de escritura del config, manejando poison.
fn write_config(cfg: &RwLock<Config>) -> Result<RwLockWriteGuard<'_, Config>, String> {
    cfg.write().map_err(|e| format!("config lock poisoned: {e}"))
}

/// Estado compartido accesible desde el servidor IPC.
pub struct IpcServer {
    vault: Arc<Vault>,
    config: RwLock<Config>,
    guard_backend: String,
    protection_level: String,
    runtime: tokio::runtime::Runtime,
    incidents_log: Option<PathBuf>,
    paused: Arc<AtomicBool>,
    /// v2.1: callback para lanzar agentes en sandbox.
    launch_agent: Option<LaunchAgentFn>,
    /// v2.1: sandbox mode string.
    sandbox_mode: String,
    /// v2.1: system capabilities report.
    capabilities: String,
    /// v2.1: active sandboxes list (for count).
    active_sandboxes: Arc<RwLock<Vec<SandboxedAgent>>>,
    /// v2.1: incidents counter.
    incidents_count: Arc<AtomicU64>,
}

impl IpcServer {
    /// Constructor legacy — sin log de incidentes ni control de pausa.
    pub fn new(
        vault: Vault,
        config: Config,
        guard_backend: &str,
        protection_level: &str,
    ) -> Result<Self, std::io::Error> {
        Self::builder(vault, config, guard_backend, protection_level).build()
    }

    /// Builder fluido con opciones adicionales.
    pub fn builder(
        vault: Vault,
        config: Config,
        guard_backend: &str,
        protection_level: &str,
    ) -> IpcServerBuilder {
        IpcServerBuilder {
            vault,
            config,
            guard_backend: guard_backend.to_string(),
            protection_level: protection_level.to_string(),
            incidents_log: None,
            paused: Arc::new(AtomicBool::new(false)),
            launch_agent: None,
            sandbox_mode: String::new(),
            capabilities: String::new(),
            active_sandboxes: Arc::new(RwLock::new(Vec::new())),
            incidents_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Expone el flag de pausa para que el loop principal lo consulte.
    pub fn paused(&self) -> Arc<AtomicBool> {
        self.paused.clone()
    }

    /// Arranca el listener. Retorna un handle para shutdown.
    pub fn start(self, socket_path: PathBuf) -> Result<IpcShutdown, std::io::Error> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(&socket_path);

        #[cfg(unix)]
        let listener = {
            let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = std::fs::metadata(&socket_path)?;
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&socket_path, perms)?;
            }
            listener
        };
        #[cfg(not(unix))]
        let listener = {
            compile_error!("IPC server only supported on Unix (Linux/macOS) for now");
        };

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let sp = socket_path.clone();

        std::thread::spawn(move || {
            tracing::info!(path = %sp.display(), "IPC server listening");

            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept error");
                        continue;
                    }
                };
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
                self.handle_connection(&mut stream);
            }

            let _ = std::fs::remove_file(&sp);
            tracing::info!("IPC server stopped");
        });

        Ok(IpcShutdown {
            tx: Some(shutdown_tx),
            socket_path,
        })
    }

    fn handle_connection(&self, stream: &mut (impl Read + Write)) {
        let mut reader = BufReader::new(&mut *stream);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            _ => {}
        }

        let cmd: IpcCommand = match serde_json::from_str(line.trim()) {
            Ok(c) => c,
            Err(e) => {
                let _ = write_response(
                    stream,
                    &IpcResponse::Error {
                        message: format!("invalid command: {e}"),
                    },
                );
                return;
            }
        };

        let response = self.execute(cmd);
        let _ = write_response(stream, &response);
    }

    fn execute(&self, cmd: IpcCommand) -> IpcResponse {
        match cmd {
            IpcCommand::Ping => IpcResponse::Pong,

            IpcCommand::Status => {
                let cfg = match read_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => return IpcResponse::Error { message: e },
                };
                IpcResponse::StatusData {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    guard_backend: self.guard_backend.clone(),
                    protection_level: self.protection_level.clone(),
                    dlp_enabled: cfg.dlp.enabled,
                    paused: self.paused.load(Ordering::SeqCst),
                    protected_dirs: cfg
                        .protected_dirs
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect(),
                    protected_files: cfg
                        .protected_files
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect(),
                    sandbox_mode: Some(self.sandbox_mode.clone()),
                    active_sandboxes: self
                        .active_sandboxes
                        .read()
                        .map(|l| l.len() as u32)
                        .unwrap_or(0),
                    capabilities: Some(self.capabilities.clone()),
                    incidents_count: self.incidents_count.load(Ordering::SeqCst),
                }
            }

            IpcCommand::Protect { path, watch_only } => {
                let mut cfg = match write_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => return IpcResponse::Error { message: e },
                };
                let canonical = match std::fs::canonicalize(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        return IpcResponse::Error {
                            message: format!("cannot resolve path {path}: {e}"),
                        };
                    }
                };

                let canonical_str = canonical.display().to_string();
                if watch_only {
                    if !cfg.protected_files.iter().any(|p| p.display().to_string() == canonical_str) {
                        cfg.protected_files.push(canonical.clone());
                    }
                } else {
                    if !cfg.protected_dirs.iter().any(|p| p.display().to_string() == canonical_str) {
                        cfg.protected_dirs.push(canonical.clone());
                    }
                }
                drop(cfg);

                IpcResponse::Ok {
                    message: format!("path {path} added to config\nrestart daemon to persist and apply"),
                }
            }

            IpcCommand::Unprotect { path } => {
                let mut cfg = match write_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => return IpcResponse::Error { message: e },
                };
                let canonical = std::fs::canonicalize(&path)
                    .unwrap_or_else(|_| PathBuf::from(&path));
                let canonical_str = canonical.display().to_string();

                let dirs_before = cfg.protected_dirs.len();
                let files_before = cfg.protected_files.len();
                cfg.protected_dirs.retain(|p| p.display().to_string() != canonical_str);
                cfg.protected_files.retain(|p| p.display().to_string() != canonical_str);
                let removed = (dirs_before + files_before)
                    - (cfg.protected_dirs.len() + cfg.protected_files.len());
                drop(cfg);

                if removed == 0 {
                    return IpcResponse::Error {
                        message: format!("path {path} is not currently protected"),
                    };
                }

                IpcResponse::Ok {
                    message: format!("path {path} removed from config\nrestart daemon to persist"),
                }
            }

            IpcCommand::SnapshotCreate { label } => {
                let dirs = match read_config(&self.config) {
                    Ok(c) => c.protected_dirs.clone(),
                    Err(e) => return IpcResponse::Error { message: e },
                };
                match self.runtime.block_on(
                    self.vault.create_snapshot(&dirs, &label),
                ) {
                    Ok(snapshot) => IpcResponse::Ok {
                        message: format!(
                            "snapshot {} created ({} files, {} bytes)",
                            snapshot.id,
                            snapshot.files.len(),
                            snapshot.total_size
                        ),
                    },
                    Err(e) => IpcResponse::Error {
                        message: format!("snapshot failed: {e}"),
                    },
                }
            }

            IpcCommand::SnapshotList => match self
                .runtime
                .block_on(self.vault.list())
            {
                Ok(snapshots) => IpcResponse::SnapshotList {
                    snapshots: snapshots
                        .into_iter()
                        .map(|s| SnapshotInfo {
                            id: s.id,
                            timestamp: s.timestamp,
                            label: s.label,
                            files: s.files.len(),
                            total_size: s.total_size,
                        })
                        .collect(),
                },
                Err(e) => IpcResponse::Error {
                    message: format!("list failed: {e}"),
                },
            },

            IpcCommand::SnapshotRestore { id, yes } => {
                if !yes {
                    return IpcResponse::Error {
                        message: "use --yes to confirm restore".to_string(),
                    };
                }
                match self.runtime.block_on(self.vault.restore(&id)) {
                    Ok(()) => IpcResponse::Ok {
                        message: format!("snapshot {id} restored"),
                    },
                    Err(e) => IpcResponse::Error {
                        message: format!("restore failed: {e}"),
                    },
                }
            }

            IpcCommand::SnapshotCleanup { keep_days } => {
                match self.runtime.block_on(self.vault.cleanup(keep_days)) {
                    Ok(count) => IpcResponse::Ok {
                        message: format!(
                            "cleanup: removed {count} snapshots (kept last {keep_days} days)"
                        ),
                    },
                    Err(e) => IpcResponse::Error {
                        message: format!("cleanup failed: {e}"),
                    },
                }
            }

            IpcCommand::Incidents { last } => {
                let log_path = match &self.incidents_log {
                    Some(p) => p.clone(),
                    None => {
                        return IpcResponse::Incidents {
                            lines: vec!["incidents log not configured — run the daemon first".into()],
                        };
                    }
                };

                match std::fs::read_to_string(&log_path) {
                    Ok(content) => {
                        let all_lines: Vec<&str> = content.lines().collect();
                        let limit = last.unwrap_or(usize::MAX).min(INCIDENTS_MAX_LINES);
                        let start = all_lines.len().saturating_sub(limit);
                        let lines: Vec<String> = all_lines
                            .into_iter()
                            .skip(start)
                            .map(|s| s.to_string())
                            .collect();
                        IpcResponse::Incidents { lines }
                    }
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::NotFound => IpcResponse::Incidents {
                            lines: vec!["no incidents recorded yet".into()],
                        },
                        _ => IpcResponse::Error {
                            message: format!("failed to read incidents log: {e}"),
                        },
                    },
                }
            }

            IpcCommand::Pause { minutes } => {
                self.paused.store(true, Ordering::SeqCst);
                if minutes > 0 {
                    let paused_flag = self.paused.clone();
                    self.runtime.spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(minutes * 60)).await;
                        paused_flag.store(false, Ordering::SeqCst);
                        tracing::info!(minutes, "auto-resume: protection re-enabled");
                    });
                }
                let suffix = if minutes == 0 {
                    " (no auto-resume)".to_string()
                } else {
                    format!(" (auto-resume in {minutes} min)")
                };
                IpcResponse::Ok {
                    message: format!("protection paused{suffix}"),
                }
            }

            IpcCommand::Resume => {
                self.paused.store(false, Ordering::SeqCst);
                IpcResponse::Ok {
                    message: "protection resumed".into(),
                }
            }

            IpcCommand::LaunchAgent {
                exe,
                cwd,
                extra_args,
                mode_override,
            } => match &self.launch_agent {
                Some(launch_fn) => match launch_fn(exe, cwd, extra_args, mode_override) {
                    Ok(pid) => IpcResponse::AgentLaunched { sandbox_pid: pid },
                    Err(e) => IpcResponse::Error { message: e },
                },
                None => IpcResponse::Error {
                    message: "sandbox launcher not available on this platform"
                        .to_string(),
                },
            },

            IpcCommand::AddProtectedPath { path } => {
                let mut cfg = match write_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => return IpcResponse::Error { message: e },
                };
                let canonical = match std::fs::canonicalize(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        return IpcResponse::Error {
                            message: format!("cannot resolve path {path}: {e}"),
                        };
                    }
                };
                if !cfg
                    .protected_dirs
                    .iter()
                    .any(|p| p.display().to_string() == canonical.display().to_string())
                {
                    cfg.protected_dirs.push(canonical);
                }
                drop(cfg);
                IpcResponse::Ok {
                    message: format!("path {path} is now protected"),
                }
            }
        }
    }
}

/// Builder para IpcServer con opciones adicionales.
pub struct IpcServerBuilder {
    vault: Vault,
    config: Config,
    guard_backend: String,
    protection_level: String,
    incidents_log: Option<PathBuf>,
    paused: Arc<AtomicBool>,
    launch_agent: Option<LaunchAgentFn>,
    sandbox_mode: String,
    capabilities: String,
    active_sandboxes: Arc<RwLock<Vec<SandboxedAgent>>>,
    incidents_count: Arc<AtomicU64>,
}

impl IpcServerBuilder {
    pub fn incidents_log(mut self, path: PathBuf) -> Self {
        self.incidents_log = Some(path);
        self
    }

    pub fn paused(mut self, paused: Arc<AtomicBool>) -> Self {
        self.paused = paused;
        self
    }

    /// v2.1: inyecta el callback para lanzar agentes en sandbox.
    pub fn launch_agent_fn(mut self, f: LaunchAgentFn) -> Self {
        self.launch_agent = Some(f);
        self
    }

    /// v2.1: configura el modo de sandbox activo.
    pub fn sandbox_mode(mut self, mode: String) -> Self {
        self.sandbox_mode = mode;
        self
    }

    /// v2.1: reporte de capacidades del sistema.
    pub fn capabilities(mut self, caps: String) -> Self {
        self.capabilities = caps;
        self
    }

    /// v2.1: lista compartida de sandboxes activos.
    pub fn active_sandboxes(mut self, list: Arc<RwLock<Vec<SandboxedAgent>>>) -> Self {
        self.active_sandboxes = list;
        self
    }

    /// v2.1: contador compartido de incidentes.
    pub fn incidents_count(mut self, counter: Arc<AtomicU64>) -> Self {
        self.incidents_count = counter;
        self
    }

    pub fn build(self) -> Result<IpcServer, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(IpcServer {
            vault: Arc::new(self.vault),
            config: RwLock::new(self.config),
            guard_backend: self.guard_backend,
            protection_level: self.protection_level,
            runtime,
            incidents_log: self.incidents_log,
            paused: self.paused,
            launch_agent: self.launch_agent,
            sandbox_mode: self.sandbox_mode,
            capabilities: self.capabilities,
            active_sandboxes: self.active_sandboxes,
            incidents_count: self.incidents_count,
        })
    }
}

/// Handle que permite parar el servidor IPC limpiamente.
pub struct IpcShutdown {
    tx: Option<oneshot::Sender<()>>,
    socket_path: PathBuf,
}

impl IpcShutdown {
    pub fn shutdown(mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for IpcShutdown {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

fn write_response(stream: &mut impl Write, response: &IpcResponse) -> std::io::Result<()> {
    let json = serde_json::to_string(response)
        .map_err(std::io::Error::other)?;
    writeln!(stream, "{json}")?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use tempfile::TempDir;

    #[test]
    fn ping_returns_pong() {
        let tmp = TempDir::new().expect("tmp");
        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "test-backend", "userspace").expect("ipc");

        let resp = server.execute(IpcCommand::Ping);
        assert!(matches!(resp, IpcResponse::Pong));
    }

    #[test]
    fn status_returns_config_info() {
        let tmp = TempDir::new().expect("tmp");
        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "ebpf-lsm", "kernel-level").expect("ipc");

        match server.execute(IpcCommand::Status) {
            IpcResponse::StatusData {
                guard_backend,
                protection_level,
                ..
            } => {
                assert_eq!(guard_backend, "ebpf-lsm");
                assert_eq!(protection_level, "kernel-level");
            }
            other => panic!("expected StatusData, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_restore_without_yes_rejects() {
        let tmp = TempDir::new().expect("tmp");
        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "test", "userspace").expect("ipc");

        let resp = server.execute(IpcCommand::SnapshotRestore {
            id: "nope".into(),
            yes: false,
        });
        match resp {
            IpcResponse::Error { message } => assert!(message.contains("--yes")),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[test]
    fn pause_and_resume_toggle_flag() {
        let tmp = TempDir::new().expect("tmp");
        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "test", "userspace").expect("ipc");

        assert!(!server.paused.load(Ordering::SeqCst));
        server.execute(IpcCommand::Pause { minutes: 5 });
        assert!(server.paused.load(Ordering::SeqCst));
        server.execute(IpcCommand::Resume);
        assert!(!server.paused.load(Ordering::SeqCst));
    }

    #[test]
    fn incidents_without_log_path_returns_info() {
        let tmp = TempDir::new().expect("tmp");
        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "test", "userspace").expect("ipc");

        match server.execute(IpcCommand::Incidents { last: None }) {
            IpcResponse::Incidents { lines } => {
                assert!(lines[0].contains("not configured"));
            }
            other => panic!("expected Incidents, got {other:?}"),
        }
    }

    #[test]
    fn incidents_reads_log_file() {
        let tmp = TempDir::new().expect("tmp");
        let log_path = tmp.path().join("incidents.jsonl");
        std::fs::write(
            &log_path,
            "{\"kind\":\"file_violation\",\"path\":\"/tmp/a\"}\n{\"kind\":\"dlp_violation\"}\n",
        )
        .expect("write log");

        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::builder(vault, config, "test", "userspace")
            .incidents_log(log_path)
            .build()
            .expect("ipc");

        match server.execute(IpcCommand::Incidents { last: None }) {
            IpcResponse::Incidents { lines } => {
                assert_eq!(lines.len(), 2);
                assert!(lines[0].contains("file_violation"));
                assert!(lines[1].contains("dlp_violation"));
            }
            other => panic!("expected Incidents, got {other:?}"),
        }
    }

    #[test]
    fn incidents_respects_last_limit() {
        let tmp = TempDir::new().expect("tmp");
        let log_path = tmp.path().join("incidents.jsonl");
        std::fs::write(
            &log_path,
            "line1\nline2\nline3\nline4\nline5\n",
        )
        .expect("write log");

        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::builder(vault, config, "test", "userspace")
            .incidents_log(log_path)
            .build()
            .expect("ipc");

        match server.execute(IpcCommand::Incidents { last: Some(3) }) {
            IpcResponse::Incidents { lines } => {
                assert_eq!(lines.len(), 3);
                assert!(lines[0].contains("line3"));
                assert!(lines[2].contains("line5"));
            }
            other => panic!("expected Incidents, got {other:?}"),
        }
    }

    #[test]
    fn protect_adds_path_to_config_memory() {
        let tmp = TempDir::new().expect("tmp");
        let sub = tmp.path().join("testdir");
        std::fs::create_dir(&sub).expect("mkdir");
        let mut config = config::Config::default().resolve().expect("config");
        config.protected_dirs.clear();
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "test", "userspace").expect("ipc");

        let path_str = sub.display().to_string();
        server.execute(IpcCommand::Protect {
            path: path_str.clone(),
            watch_only: false,
        });

        let cfg = read_config(&server.config).expect("read config");
        assert!(cfg.protected_dirs.iter().any(|p| p.display().to_string() == path_str));
    }
}
