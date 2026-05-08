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

use agentguard_common::{
    AgentInfo, IpcCommand, IpcEvent, IpcResponse, RuleInfo, SandboxedAgent, SessionInfo,
    SnapshotInfo,
};
use serde_json;
use tokio::sync::broadcast;
use tokio::sync::oneshot;

use crate::config::Config;
use crate::events::SecurityEvent;
use crate::vault::Vault;

/// Tipo de callback para lanzar un agente en sandbox.
/// Inyectado por el daemon específico de cada plataforma.
pub type LaunchAgentFn =
    Arc<dyn Fn(String, String, Vec<String>, Option<String>) -> Result<u32, String> + Send + Sync>;

/// Máximo de líneas a leer del log de incidentes (evita OOM).
#[allow(dead_code)]
const INCIDENTS_MAX_LINES: usize = 500;

/// Helper: adquiere el lock de lectura del config, manejando poison.
#[allow(dead_code)]
fn read_config(cfg: &RwLock<Config>) -> Result<RwLockReadGuard<'_, Config>, String> {
    cfg.read().map_err(|e| format!("config lock poisoned: {e}"))
}

/// Helper: adquiere el lock de escritura del config, manejando poison.
#[allow(dead_code)]
fn write_config(cfg: &RwLock<Config>) -> Result<RwLockWriteGuard<'_, Config>, String> {
    cfg.write()
        .map_err(|e| format!("config lock poisoned: {e}"))
}

/// Estado compartido accesible desde el servidor IPC.
#[allow(dead_code)]
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
    /// Fase 5: database handle.
    db: Option<Arc<crate::db::Database>>,
    /// Fase 6: event bus for push notifications.
    event_tx: Option<broadcast::Sender<SecurityEvent>>,
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
            db: None,
            event_tx: None,
        }
    }

    /// Expone el flag de pausa para que el loop principal lo consulte.
    pub fn paused(&self) -> Arc<AtomicBool> {
        self.paused.clone()
    }

    /// Arranca el listener. Retorna un handle para shutdown.
    /// En Unix usa Unix domain sockets (con permisos 0600).
    /// En Windows usa Named Pipes (vía pipe_name).
    pub fn start(self, socket_path: PathBuf) -> Result<IpcShutdown, std::io::Error> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        #[cfg(unix)]
        let _ = std::fs::remove_file(&socket_path);

        #[cfg(unix)]
        {
            use std::os::unix::net::UnixListener;
            let listener = {
                use std::os::unix::fs::PermissionsExt;
                let listener = UnixListener::bind(&socket_path)?;
                let mut perms = std::fs::metadata(&socket_path)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&socket_path, perms)?;
                listener
            };

            let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
            let sp = socket_path.clone();

            std::thread::spawn(move || {
                tracing::info!(path = %sp.display(), "IPC server listening");

                for stream in listener.incoming() {
                    if shutdown_rx.try_recv().is_ok() {
                        break;
                    }
                    let mut stream = match stream {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "accept error");
                            continue;
                        }
                    };
                    self.handle_connection_unix(&mut stream);
                }

                let _ = std::fs::remove_file(&sp);
                tracing::info!("IPC server stopped");
            });

            Ok(IpcShutdown {
                tx: Some(shutdown_tx),
                socket_path,
            })
        }

        #[cfg(windows)]
        {
            self.start_named_pipe_windowed(socket_path.to_string_lossy().to_string())
        }

        #[cfg(not(any(unix, windows)))]
        {
            tracing::warn!("IPC server not supported on this platform");
            let (shutdown_tx, _) = oneshot::channel::<()>();
            Ok(IpcShutdown {
                tx: Some(shutdown_tx),
                socket_path,
            })
        }
    }

    /// Implementación de Named Pipe en Windows.
    #[cfg(windows)]
    fn start_named_pipe_windowed(self, pipe_name: String) -> Result<IpcShutdown, std::io::Error> {
        start_named_pipe_server(self, pipe_name)
    }

    /// Unix-specific connection handler: uses try_clone() to spawn
    /// a writer thread for Subscribe, keeping the accept loop free.
    #[cfg(unix)]
    fn handle_connection_unix(&self, stream: &mut std::os::unix::net::UnixStream) {
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

        match cmd {
            IpcCommand::Subscribe { .. } => {
                let Some(ref event_tx) = self.event_tx else {
                    let _ = write_response(
                        stream,
                        &IpcResponse::Error {
                            message: "event bus not available on this daemon".into(),
                        },
                    );
                    return;
                };

                // Clone the stream for the writer thread
                let mut event_rx = event_tx.subscribe();
                match stream.try_clone() {
                    Ok(mut writer) => {
                        // Spawn a dedicated thread so the accept loop stays free.
                        // This thread only accesses event_rx (no &self on IpcServer).
                        std::thread::spawn(move || {
                            loop {
                                match event_rx.blocking_recv() {
                                    Ok(se) => {
                                        let ipc_event = security_to_ipc_event(&se);
                                        if write_json_line(&mut writer, &ipc_event).is_err() {
                                            break;
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        tracing::warn!(skipped = n, "IPC event subscriber lagging");
                                    }
                                    Err(broadcast::error::RecvError::Closed) => break,
                                }
                            }
                            tracing::debug!("IPC event stream closed");
                        });
                    }
                    Err(e) => {
                        let _ = write_response(
                            stream,
                            &IpcResponse::Error {
                                message: format!("failed to clone stream for events: {e}"),
                            },
                        );
                    }
                }
            }
            IpcCommand::Unsubscribe => {
                let _ = write_response(
                    stream,
                    &IpcResponse::Ok {
                        message: "unsubscribed".into(),
                    },
                );
            }
            _ => {
                let response = self.execute(cmd);
                let _ = write_response(stream, &response);
            }
        }
    }

    /// Generic handler for non-Unix platforms (Windows Named Pipes via impl Read + Write).
    #[allow(dead_code)]
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

        match cmd {
            IpcCommand::Subscribe { .. } => {
                let _ = write_response(
                    stream,
                    &IpcResponse::Error {
                        message: "event stream not supported on this platform".into(),
                    },
                );
            }
            IpcCommand::Unsubscribe => {
                let _ = write_response(
                    stream,
                    &IpcResponse::Ok {
                        message: "unsubscribed".into(),
                    },
                );
            }
            _ => {
                let response = self.execute(cmd);
                let _ = write_response(stream, &response);
            }
        }
    }

    #[allow(dead_code)]
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
                    if !cfg
                        .protected_files
                        .iter()
                        .any(|p| p.display().to_string() == canonical_str)
                    {
                        cfg.protected_files.push(canonical.clone());
                    }
                } else {
                    if !cfg
                        .protected_dirs
                        .iter()
                        .any(|p| p.display().to_string() == canonical_str)
                    {
                        cfg.protected_dirs.push(canonical.clone());
                    }
                }
                drop(cfg);

                IpcResponse::Ok {
                    message: format!(
                        "path {path} added to config\nrestart daemon to persist and apply"
                    ),
                }
            }

            IpcCommand::Unprotect { path } => {
                let mut cfg = match write_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => return IpcResponse::Error { message: e },
                };
                let canonical =
                    std::fs::canonicalize(&path).unwrap_or_else(|_| PathBuf::from(&path));
                let canonical_str = canonical.display().to_string();

                let dirs_before = cfg.protected_dirs.len();
                let files_before = cfg.protected_files.len();
                cfg.protected_dirs
                    .retain(|p| p.display().to_string() != canonical_str);
                cfg.protected_files
                    .retain(|p| p.display().to_string() != canonical_str);
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
                match self
                    .runtime
                    .block_on(self.vault.create_snapshot(&dirs, &label))
                {
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

            IpcCommand::SnapshotList => match self.runtime.block_on(self.vault.list()) {
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
                            lines: vec![
                                "incidents log not configured — run the daemon first".into()
                            ],
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
                    message: "sandbox launcher not available on this platform".to_string(),
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
                let canonical_str = canonical.display().to_string();
                if !cfg
                    .protected_dirs
                    .iter()
                    .any(|p| p.display().to_string() == canonical_str)
                {
                    cfg.protected_dirs.push(canonical);
                }
                drop(cfg);

                // Also persist to database if available
                if let Some(ref db) = self.db {
                    let _ = db.add_rule(&canonical_str, "dir", false);
                }

                IpcResponse::Ok {
                    message: format!("path {path} is now protected"),
                }
            }
            // ── Fase 5: Agent queries ──
            IpcCommand::AgentsList => match &self.db {
                Some(db) => match db.list_agent_stats() {
                    Ok(stats) => {
                        let agents: Vec<AgentInfo> = stats
                            .into_iter()
                            .map(|s| AgentInfo {
                                agent_name: s.agent_name,
                                first_seen: s.first_seen,
                                last_seen: s.last_seen,
                                total_sessions: s.total_sessions,
                                total_violations: s.total_violations,
                                total_sandbox_seconds: s.total_sandbox_seconds,
                            })
                            .collect();
                        IpcResponse::AgentsList { agents }
                    }
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                },
                None => IpcResponse::Error {
                    message: "database not available".into(),
                },
            },
            IpcCommand::AgentsShow { name } => match &self.db {
                Some(db) => {
                    let agent = db.get_agent_stats(&name).unwrap_or(None);
                    let sessions = db
                        .list_agent_sessions(50)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|s| s.agent_name == name)
                        .map(|s| SessionInfo {
                            id: s.id,
                            agent_name: s.agent_name,
                            pid: s.pid,
                            sandbox_mode: s.sandbox_mode,
                            started_at: s.started_at,
                            ended_at: s.ended_at,
                            total_seconds: s.total_seconds,
                            violation_count: s.violation_count,
                        })
                        .collect();
                    match agent {
                        Some(a) => IpcResponse::AgentsShow {
                            agent: AgentInfo {
                                agent_name: a.agent_name,
                                first_seen: a.first_seen,
                                last_seen: a.last_seen,
                                total_sessions: a.total_sessions,
                                total_violations: a.total_violations,
                                total_sandbox_seconds: a.total_sandbox_seconds,
                            },
                            sessions,
                        },
                        None => IpcResponse::Error {
                            message: format!("agent '{}' not found", name),
                        },
                    }
                }
                None => IpcResponse::Error {
                    message: "database not available".into(),
                },
            },
            IpcCommand::RulesList => match &self.db {
                Some(db) => match db.list_rules() {
                    Ok(rules) => {
                        let rules: Vec<RuleInfo> = rules
                            .into_iter()
                            .map(|r| RuleInfo {
                                path: r.path,
                                kind: r.kind,
                                added_at: r.added_at,
                                watch_only: r.watch_only,
                            })
                            .collect();
                        IpcResponse::RulesList { rules }
                    }
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                },
                None => IpcResponse::Error {
                    message: "database not available".into(),
                },
            },
            IpcCommand::Stats => {
                let violations_24h = self
                    .db
                    .as_ref()
                    .and_then(|db| db.count_incidents_since(86400).ok())
                    .unwrap_or(0);
                let agents_tracked = self
                    .db
                    .as_ref()
                    .and_then(|db| db.list_agent_stats().ok())
                    .map(|a| a.len() as u64)
                    .unwrap_or(0);
                IpcResponse::StatsData {
                    total_incidents: self.incidents_count.load(Ordering::SeqCst),
                    violations_24h,
                    agents_tracked,
                }
            }
            IpcCommand::IncidentsFilter {
                kind,
                agent_name,
                from_ts,
                to_ts,
                limit,
            } => {
                match &self.db {
                    Some(db) => {
                        let filter = crate::db::IncidentFilter {
                            kind: kind.clone(),
                            agent_name: agent_name.clone(),
                            from_timestamp: from_ts,
                            to_timestamp: to_ts,
                            limit: limit.or(Some(100)),
                        };
                        match db.query_incidents(&filter) {
                            Ok(records) => {
                                let lines: Vec<String> = records
                                    .into_iter()
                                    .map(|r| {
                                        serde_json::to_string(&serde_json::json!({
                                            "kind": r.kind,
                                            "agent_name": r.agent_name,
                                            "timestamp": r.timestamp,
                                            "path": r.path,
                                            "violation": r.violation,
                                            "process": r.process,
                                        }))
                                        .unwrap_or_default()
                                    })
                                    .collect();
                                IpcResponse::Incidents { lines }
                            }
                            Err(e) => IpcResponse::Error {
                                message: e.to_string(),
                            },
                        }
                    }
                    None => {
                        // Fallback: read from JSONL log
                        IpcResponse::Error { message: "database not available — use 'agentguard incidents' for legacy access".into() }
                    }
                }
            }
            // Subscribe/Unsubscribe are handled in handle_connection before execute.
            // These arms exist only for exhaustiveness; they are never reached.
            IpcCommand::Subscribe { .. } => IpcResponse::Error {
                message: "Subscribe must be handled at connection level".into(),
            },
            IpcCommand::Unsubscribe => IpcResponse::Error {
                message: "Unsubscribe must be handled at connection level".into(),
            },
            IpcCommand::SmartSuggest => {
                let cfg = match read_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => return IpcResponse::Error { message: e },
                };
                let suggestions =
                    crate::smart_protect::generate_smart_suggestions(&cfg.smart_protection);
                let suggestion_infos: Vec<agentguard_common::SuggestionInfo> = suggestions
                    .iter()
                    .map(|s| agentguard_common::SuggestionInfo {
                        path: s.path.display().to_string(),
                        group: s.group.clone(),
                        reason: s.reason.clone(),
                        risk_level: s.risk_level.to_string(),
                        size_bytes: s.size_bytes,
                        contains_secrets: s.contains_secrets,
                        is_git_repo: s.is_git_repo,
                        active_agents: s.active_agents.clone(),
                    })
                    .collect();
                IpcResponse::SmartSuggestions {
                    suggestions: suggestion_infos,
                }
            }
            IpcCommand::SmartApply { paths } => {
                let mut cfg = match write_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => return IpcResponse::Error { message: e },
                };
                let mut added = 0usize;
                for path_str in &paths {
                    let p = PathBuf::from(path_str);
                    let canonical = match std::fs::canonicalize(&p) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let canonical_str = canonical.display().to_string();
                    if !cfg
                        .protected_dirs
                        .iter()
                        .any(|d| d.display().to_string() == canonical_str)
                    {
                        cfg.protected_dirs.push(canonical.clone());
                        added += 1;
                    }
                }
                drop(cfg);
                IpcResponse::Ok {
                    message: format!("{} paths protected (restart daemon to apply)", added),
                }
            }
            IpcCommand::ProfilesList => {
                let cfg = match read_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => return IpcResponse::Error { message: e },
                };
                let profiles: Vec<agentguard_common::ProfileInfo> = cfg
                    .smart_protection
                    .profiles
                    .iter()
                    .map(|p| agentguard_common::ProfileInfo {
                        name: p.name.clone(),
                        path_count: p.paths.len(),
                        enabled: true,
                        is_auto: p.auto,
                    })
                    .collect();
                IpcResponse::ProfilesList { profiles }
            }
        }
    }
}

// ── Windows Named Pipe support ──────────────────────────────────────────

#[cfg(windows)]
mod named_pipe {
    use super::*;
    use std::io::{Read, Write};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    /// Wrapper que implementa Read + Write para handles de Named Pipe.
    pub struct PipeStream {
        handle: HANDLE,
    }

    impl PipeStream {
        pub unsafe fn from_raw_handle(handle: HANDLE) -> Self {
            Self { handle }
        }
    }

    impl Read for PipeStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut bytes_read = 0u32;
            unsafe { ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None) }
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:?}")))?;
            Ok(bytes_read as usize)
        }
    }

    impl Write for PipeStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut bytes_written = 0u32;
            unsafe { WriteFile(self.handle, Some(buf), Some(&mut bytes_written), None) }
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:?}")))?;
            Ok(bytes_written as usize)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Drop for PipeStream {
        fn drop(&mut self) {
            unsafe {
                let _ = DisconnectNamedPipe(self.handle);
                let _ = CloseHandle(self.handle);
            }
        }
    }

    pub fn run_pipe_server(
        server: IpcServer,
        pipe_name: String,
    ) -> Result<IpcShutdown, std::io::Error> {
        let full_name = format!(r"\\.\pipe\{}", pipe_name);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let sp = PathBuf::from(pipe_name);

        std::thread::spawn(move || {
            tracing::info!(pipe = %full_name, "IPC server listening (Named Pipe)");

            loop {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }

                let name_wide: Vec<u16> =
                    full_name.encode_utf16().chain(std::iter::once(0)).collect();

                let pipe_handle: HANDLE = unsafe {
                    let h = CreateNamedPipeW(
                        windows::core::PCWSTR(name_wide.as_ptr()),
                        PIPE_ACCESS_DUPLEX,
                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                        PIPE_UNLIMITED_INSTANCES,
                        4096,
                        4096,
                        0,
                        None,
                    );
                    if h == INVALID_HANDLE_VALUE {
                        tracing::error!("CreateNamedPipeW failed");
                        break;
                    }
                    h
                };

                let connected = unsafe {
                    match ConnectNamedPipe(pipe_handle, None) {
                        Ok(()) => true,
                        Err(e) => e == ERROR_PIPE_CONNECTED.into(),
                    }
                };

                if !connected {
                    unsafe {
                        let _ = CloseHandle(pipe_handle);
                    }
                    continue;
                }

                if shutdown_rx.try_recv().is_ok() {
                    unsafe {
                        let _ = CloseHandle(pipe_handle);
                    }
                    break;
                }

                let mut stream = unsafe { PipeStream::from_raw_handle(pipe_handle) };
                server.handle_connection(&mut stream);
            }

            tracing::info!("IPC server stopped");
        });

        Ok(IpcShutdown {
            tx: Some(shutdown_tx),
            socket_path: sp,
        })
    }
}

#[cfg(windows)]
fn start_named_pipe_server(
    server: IpcServer,
    pipe_name: String,
) -> Result<IpcShutdown, std::io::Error> {
    named_pipe::run_pipe_server(server, pipe_name)
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
    /// Fase 5
    db: Option<Arc<crate::db::Database>>,
    /// Fase 6: event bus for push notifications.
    event_tx: Option<broadcast::Sender<SecurityEvent>>,
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

    /// Fase 5: attach database handle.
    pub fn database(mut self, db: Arc<crate::db::Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Fase 6: attach event bus for push notifications.
    pub fn event_bus(mut self, tx: broadcast::Sender<SecurityEvent>) -> Self {
        self.event_tx = Some(tx);
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
            db: self.db,
            event_tx: self.event_tx,
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

#[allow(dead_code)]
fn write_response(stream: &mut impl Write, response: &IpcResponse) -> std::io::Result<()> {
    write_json_line(stream, response)
}

#[allow(dead_code)]
fn write_json_line(stream: &mut impl Write, value: &impl serde::Serialize) -> std::io::Result<()> {
    let json = serde_json::to_string(value).map_err(std::io::Error::other)?;
    writeln!(stream, "{json}")?;
    stream.flush()?;
    Ok(())
}

fn security_to_ipc_event(event: &SecurityEvent) -> IpcEvent {
    match event {
        SecurityEvent::AgentDetected {
            pid,
            agent_name,
            cwd,
            mode,
            timestamp,
        } => IpcEvent::AgentSpawned {
            agent_name: agent_name.clone(),
            pid: *pid,
            sandbox_pid: None,
            mode: mode.clone(),
            cwd: cwd.display().to_string(),
            timestamp: *timestamp,
        },
        SecurityEvent::AgentSandboxed {
            original_pid,
            sandbox_pid,
            agent_name,
            cwd,
            timestamp,
        } => IpcEvent::AgentSpawned {
            agent_name: agent_name.clone(),
            pid: *original_pid,
            sandbox_pid: Some(*sandbox_pid),
            mode: "sandbox".into(),
            cwd: cwd.display().to_string(),
            timestamp: *timestamp,
        },
        SecurityEvent::FileViolation {
            path,
            process,
            pid: _,
            violation,
            timestamp,
        } => IpcEvent::ViolationDetected {
            kind: "file_violation".into(),
            agent_name: Some(process.clone()),
            path: Some(path.display().to_string()),
            violation: Some(format!("{violation:?}")),
            detail: format!("{process} attempted {violation:?} on {}", path.display()),
            timestamp: *timestamp,
        },
        SecurityEvent::DlpViolation {
            pattern_name,
            destination,
            process,
            pid: _,
            timestamp,
        } => IpcEvent::ViolationDetected {
            kind: "dlp_violation".into(),
            agent_name: Some(process.clone()),
            path: Some(destination.clone()),
            violation: Some(pattern_name.clone()),
            detail: format!("{process} leaked {pattern_name} to {destination}"),
            timestamp: *timestamp,
        },
        SecurityEvent::DlpRedaction {
            pattern_name,
            destination,
            process,
            pid: _,
            redaction_count,
            timestamp,
        } => IpcEvent::ViolationDetected {
            kind: "dlp_redaction".into(),
            agent_name: Some(process.clone()),
            path: Some(destination.clone()),
            violation: Some(pattern_name.clone()),
            detail: format!(
                "{process} had {redaction_count} occurrence(s) of {pattern_name} redacted when sending to {destination}"
            ),
            timestamp: *timestamp,
        },
        SecurityEvent::SystemError { message, timestamp } => IpcEvent::ViolationDetected {
            kind: "system_error".into(),
            agent_name: None,
            path: None,
            violation: None,
            detail: message.clone(),
            timestamp: *timestamp,
        },
    }
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
        std::fs::write(&log_path, "line1\nline2\nline3\nline4\nline5\n").expect("write log");

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

        let path_str = std::fs::canonicalize(&sub)
            .expect("canonicalize")
            .display()
            .to_string();
        server.execute(IpcCommand::Protect {
            path: path_str.clone(),
            watch_only: false,
        });

        let cfg = read_config(&server.config).expect("read config");
        assert!(cfg
            .protected_dirs
            .iter()
            .any(|p| p.display().to_string() == path_str));
    }
}
