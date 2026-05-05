//! AgentGuard daemon — entry point para Linux.
//!
//! Fase 2: daemon completo con eBPF LSM + userspace fallback, DLP proxy
//! HTTPS MITM, IPC server, vault de snapshots y loop principal de eventos.
//!
//! Señales:
//! - SIGTERM / SIGINT → graceful shutdown (limpia socket, cierra proxy)
//! - SIGUSR1 → reload config (pending — Fase 3)

use std::path::PathBuf;

#[cfg(unix)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(unix)]
use std::sync::{Arc, RwLock};

#[cfg(unix)]
use agentguard_common::SandboxedAgent;
#[cfg(unix)]
use agentguard_core::ca::LocalCa;
#[cfg(unix)]
use agentguard_core::config::Config;
#[cfg(unix)]
use agentguard_core::dlp::patterns::compile_all;
#[cfg(unix)]
use agentguard_core::dlp::tls::LeafIssuer;
#[cfg(unix)]
use agentguard_core::dlp::DlpProxy;
#[cfg(unix)]
use agentguard_core::events::{SecurityEvent, ViolationKind};
#[cfg(unix)]
use agentguard_core::ipc_server::IpcServer;
#[cfg(unix)]
use agentguard_core::vault::Vault;
#[cfg(unix)]
use agentguard_linux::guard::select_guard;

#[cfg(unix)]
use anyhow::{Context, Result};
use clap::Parser;
#[cfg(unix)]
use tokio::sync::mpsc;
#[cfg(unix)]
use tracing::{error, info, warn};
#[cfg(unix)]
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "agentguard-linux",
    version = env!("CARGO_PKG_VERSION"),
    about = "AgentGuard — kernel-level protection daemon for Linux"
)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(long = "protect", value_name = "PATH")]
    protect: Vec<PathBuf>,
}

#[cfg(unix)]
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,agentguard_core=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(unix)]
fn default_config_path() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/etc/agentguard/config.toml");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("config.toml"))
}

#[cfg(unix)]
fn default_vault_dir() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/var/lib/agentguard/vault");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("vault"))
        .unwrap_or_else(|| PathBuf::from("vault"))
}

#[cfg(unix)]
fn default_ca_dir() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/var/lib/agentguard/ca");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("ca"))
        .unwrap_or_else(|| PathBuf::from("ca"))
}

#[cfg(unix)]
fn default_ipc_socket_path() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/var/run/agentguard.sock");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("agentguard.sock"))
        .unwrap_or_else(|| PathBuf::from("agentguard.sock"))
}

#[cfg(unix)]
fn incidents_log_path() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/var/log/agentguard/incidents.jsonl");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("incidents.jsonl"))
        .unwrap_or_else(|| PathBuf::from("incidents.jsonl"))
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "AgentGuard Linux daemon starting"
    );

    // ── Config ──────────────────────────────────────────────
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let mut config = if config_path.is_file() {
        info!(path = ?config_path, "loading config");
        Config::from_path(&config_path)
            .with_context(|| format!("loading config from {config_path:?}"))?
    } else {
        warn!(path = ?config_path, "config not found, using defaults");
        Config::default()
    };
    config = config.resolve()?;

    for p in &args.protect {
        config.protected_dirs.push(p.clone());
    }

    info!(
        protected_dirs = config.protected_dirs.len(),
        protected_files = config.protected_files.len(),
        dlp_enabled = config.dlp.enabled,
        "config loaded"
    );

    // ── Vault ───────────────────────────────────────────────
    let vault_dir = if config.vault.vault_dir.as_os_str().is_empty() {
        default_vault_dir()
    } else {
        config.vault.vault_dir.clone()
    };
    let vault = Vault::with_dir(&vault_dir).with_context(|| format!("vault at {vault_dir:?}"))?;
    info!(path = ?vault.root(), "vault ready");

    if config.vault.snapshot_on_start && !config.protected_dirs.is_empty() {
        match vault
            .create_snapshot(&config.protected_dirs, "startup")
            .await
        {
            Ok(s) => info!(id = %s.id, files = s.files.len(), "startup snapshot created"),
            Err(e) => warn!(error = %e, "startup snapshot failed"),
        }
    }

    // ── CA (HTTPS MITM) ─────────────────────────────────────
    let ca_dir = default_ca_dir();
    let ca = LocalCa::load_or_generate(&ca_dir).with_context(|| format!("CA at {ca_dir:?}"))?;
    let leaf_issuer =
        LeafIssuer::new(&ca).with_context(|| "failed to initialize TLS leaf certificate issuer")?;
    info!(
        cert_path = ?ca.cert_path(),
        "CA root ready — HTTPS MITM enabled for DLP proxy"
    );

    // ── v2.1: Sandbox capabilities ─────────────────────────
    let sandbox_caps = agentguard_linux::sandbox::SandboxLauncher::check_capabilities();
    let effective_mode = sandbox_caps.effective_mode(&config.sandbox.modo_por_defecto);
    info!(
        capabilities = %sandbox_caps.report(),
        requested_mode = %config.sandbox.modo_por_defecto,
        effective_mode,
        "sandbox capabilities checked"
    );
    if effective_mode != config.sandbox.modo_por_defecto {
        warn!(
            "requested mode '{}' not available, using '{}'",
            config.sandbox.modo_por_defecto, effective_mode
        );
        if !sandbox_caps.bwrap_available {
            warn!("to enable sandbox mode: sudo apt install bubblewrap");
        }
    }

    // ── Guard (eBPF o userspace) ────────────────────────────
    let guard = select_guard(&config.protected_dirs, &config.protected_files).await?;
    let guard_backend_name = guard.backend_name().to_string();
    let guard_level = format!("{:?}", guard.protection_level());
    info!(
        backend = %guard_backend_name,
        level = %guard_level,
        "protection backend ready"
    );

    // ── Canal de eventos ────────────────────────────────────
    let (event_tx, mut event_rx) = mpsc::channel::<SecurityEvent>(256);

    let guard_event_tx = event_tx.clone();
    let guard_task = tokio::spawn(async move {
        if let Err(e) = guard.run(guard_event_tx).await {
            error!(error = %e, "protection backend crashed");
        }
    });

    // ── Agent scanner (/proc) ───────────────────────────────
    let agent_patterns = config.agent_processes.clone();
    if !agent_patterns.is_empty() {
        let scan_tx = event_tx.clone();
        tokio::spawn(agentguard_linux::guard::agents::scan_loop(
            agent_patterns,
            scan_tx,
        ));
        info!(
            count = config.agent_processes.len(),
            "agent process scanner started"
        );
    } else {
        info!("no agent process patterns configured — scanner disabled");
    }

    // ── v2.1: Process watcher (eBPF tracepoint) ─────────────
    #[cfg(feature = "ebpf")]
    {
        if !config.agent_detection.known_agents.is_empty() && config.sandbox.auto_detectar_agentes {
            let watcher_config = config.clone();
            let watcher_tx = event_tx.clone();
            let watcher_cfg = Arc::new(tokio::sync::RwLock::new(watcher_config));
            tokio::spawn(async move {
                match agentguard_linux::process_watcher::ProcessWatcher::load(
                    &watcher_cfg.read().await,
                ) {
                    Ok(watcher) => watcher.run(watcher_cfg, watcher_tx).await,
                    Err(e) => {
                        warn!(
                            error = %e,
                            "ProcessWatcher eBPF failed — agent detection via /proc scanner only"
                        );
                    }
                }
            });
            info!(
                agents = config.agent_detection.known_agents.len(),
                "process watcher (eBPF tracepoint) started"
            );
        }
    }

    // ── DLP proxy ───────────────────────────────────────────
    let dlp_handle = if config.dlp.enabled {
        let custom: Vec<(String, String)> = config
            .dlp
            .custom_patterns
            .iter()
            .map(|p| (p.name.clone(), p.regex.clone()))
            .collect();
        match compile_all(&custom) {
            Ok(patterns) => {
                let action = config.dlp_action()?;
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.dlp.proxy_port);
                let proxy = DlpProxy::new(patterns, action)
                    .with_events(event_tx.clone())
                    .with_tls(leaf_issuer.clone());
                match proxy.start(addr).await {
                    Ok(h) => {
                        info!(addr = %h.local_addr(), action = ?action, "DLP proxy started");
                        Some(h)
                    }
                    Err(e) => {
                        error!(error = %e, "DLP proxy failed to start — continuing without DLP");
                        None
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "DLP pattern compilation failed");
                None
            }
        }
    } else {
        info!("DLP disabled in config");
        None
    };

    // ── IPC server ──────────────────────────────────────────
    let log_path = incidents_log_path();
    let paused = Arc::new(AtomicBool::new(false));

    // v2.1: shared state for sandbox tracking and incident counting
    let active_sandboxes: Arc<RwLock<Vec<SandboxedAgent>>> = Arc::new(RwLock::new(Vec::new()));
    let incidents_counter = Arc::new(AtomicU64::new(0));

    let ipc_server = IpcServer::builder(
        vault.clone(),
        config.clone(),
        &guard_backend_name,
        &guard_level,
    )
    .incidents_log(log_path.clone())
    .paused(paused.clone())
    .sandbox_mode(effective_mode.to_string())
    .capabilities(sandbox_caps.report())
    .active_sandboxes(active_sandboxes.clone())
    .incidents_count(incidents_counter.clone())
    .launch_agent_fn(Arc::new({
        let cfg = config.clone();
        move |exe, cwd, _extra_args, mode_override| {
            let cfg = cfg.clone();
            let mode = mode_override.unwrap_or_else(|| cfg.sandbox.modo_por_defecto.clone());
            let use_landlock = cfg!(target_os = "linux") && mode == "hybrid";
            let project_dir = PathBuf::from(cwd);
            let launcher = agentguard_linux::sandbox::SandboxLauncher::new(cfg);
            let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio: {e}"))?;
            rt.block_on(launcher.launch(&exe, &project_dir, use_landlock))
                .map_err(|e| format!("sandbox: {e}"))
        }
    }))
    .build()
    .with_context(|| "failed to create IPC server")?;
    let ipc_socket_path = default_ipc_socket_path();
    let ipc_handle = match ipc_server.start(ipc_socket_path.clone()) {
        Ok(h) => {
            info!(path = %ipc_socket_path.display(), "IPC server started");
            Some(h)
        }
        Err(e) => {
            error!(error = %e, "IPC server failed to start — continuing without IPC");
            None
        }
    };

    drop(event_tx); // los clones los mantienen guard + dlp

    // ── Main loop ───────────────────────────────────────────
    info!(path = %log_path.display(), "incidents log ready");

    let vault_for_events = vault.clone();
    let snapshot_on_violation = config.on_violation.snapshot_on_violation;
    let violation_paths = config.protected_dirs.clone();
    let sandboxes_for_events = active_sandboxes.clone();
    let counter_for_events = incidents_counter.clone();
    let alerts_enabled = config.alerts.desktop_notifications;

    info!("entering main loop (SIGTERM / ctrl-c to quit)");

    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to register SIGTERM handler");
            return Err(anyhow::anyhow!("SIGTERM handler unavailable"));
        }
    };

    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                if paused.load(Ordering::SeqCst) {
                    // Protection paused — log but don't react
                    tracing::debug!(kind = ?event, "event received while paused");
                    persist_incident(&log_path, &event).await;
                    counter_for_events.fetch_add(1, Ordering::SeqCst);
                } else {
                    persist_incident(&log_path, &event).await;
                    counter_for_events.fetch_add(1, Ordering::SeqCst);
                    handle_event(
                        &vault_for_events,
                        snapshot_on_violation,
                        &violation_paths,
                        event,
                        &sandboxes_for_events,
                        alerts_enabled,
                    ).await;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received — shutting down");
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received — shutting down");
                break;
            }
            else => break,
        }
    }

    info!("AgentGuard daemon shutting down");
    guard_task.abort();
    if let Some(h) = dlp_handle {
        h.shutdown();
    }
    if let Some(h) = ipc_handle {
        h.shutdown();
    }
    let _ = std::fs::remove_file(default_ipc_socket_path());
    info!("shutdown complete");
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    println!("agentguard-linux: this daemon only runs on Linux.");
    println!("On this platform, use: agentguard-windows");
}

#[cfg(unix)]
async fn persist_incident(log_path: &std::path::Path, event: &SecurityEvent) {
    let entry = match serde_json::to_string(event) {
        Ok(json) => format!("{json}\n"),
        Err(e) => {
            error!(error = %e, "failed to serialize incident");
            return;
        }
    };
    match tokio::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)
        .await
    {
        Ok(mut f) => {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut f, entry.as_bytes()).await {
                error!(error = %e, "failed to write incident to log");
            }
        }
        Err(e) => error!(error = %e, "failed to open incidents log for append"),
    }
}

#[cfg(unix)]
async fn handle_event(
    vault: &Vault,
    snapshot_on_violation: bool,
    protected_paths: &[PathBuf],
    event: SecurityEvent,
    active_sandboxes: &RwLock<Vec<SandboxedAgent>>,
    alerts_enabled: bool,
) {
    match &event {
        SecurityEvent::FileViolation {
            path,
            process,
            pid,
            violation,
            ..
        } => {
            let action = match violation {
                ViolationKind::DeleteAttempt => "DELETE",
                ViolationKind::WriteAttempt => "WRITE",
                ViolationKind::RenameAttempt => "RENAME",
                ViolationKind::CreateAttempt => "CREATE",
            };
            warn!(
                action,
                path = ?path,
                process = %process,
                pid,
                "filesystem violation detected"
            );

            if snapshot_on_violation && !protected_paths.is_empty() {
                match vault.create_snapshot(protected_paths, "on-violation").await {
                    Ok(s) => info!(id = %s.id, "reactive snapshot created"),
                    Err(e) => error!(error = %e, "reactive snapshot failed"),
                }
            }
        }
        SecurityEvent::DlpViolation {
            pattern_name,
            destination,
            process,
            ..
        } => {
            warn!(
                pattern = %pattern_name,
                destination = %destination,
                process = %process,
                "DLP violation detected"
            );
        }
        SecurityEvent::SystemError { message, .. } => {
            error!(message = %message, "system error from guard");
        }
        SecurityEvent::AgentDetected {
            pid,
            agent_name,
            cwd,
            mode,
            ..
        } => {
            info!(
                pid,
                agent = %agent_name,
                cwd = %cwd.display(),
                mode = %mode,
                "AI agent detected in protected directory"
            );
            if alerts_enabled && mode != "monitor" {
                send_desktop_notification(
                    &format!("AgentGuard: {agent_name} detected"),
                    &format!("'{agent_name}' (pid {pid}) was detected in a protected directory and will be sandboxed"),
                );
            }
        }
        SecurityEvent::AgentSandboxed {
            original_pid,
            sandbox_pid,
            agent_name,
            cwd,
            timestamp,
        } => {
            info!(
                original_pid,
                sandbox_pid,
                agent = %agent_name,
                cwd = %cwd.display(),
                "agent sandboxed successfully"
            );

            // Añadir a la lista de sandboxes activos
            if let Ok(mut sandboxes) = active_sandboxes.write() {
                sandboxes.push(SandboxedAgent {
                    original_pid: *original_pid,
                    sandbox_pid: *sandbox_pid,
                    agent_name: agent_name.clone(),
                    cwd: cwd.display().to_string(),
                    mode: agentguard_common::SandboxMode::Sandbox,
                    started_at: *timestamp,
                });
                // Limpiar sandboxes cuyos procesos ya murieron
                sandboxes.retain(|s| unsafe { libc::kill(s.sandbox_pid as i32, 0) == 0 });
            }

            if alerts_enabled {
                send_desktop_notification(
                    &format!("AgentGuard: {agent_name} sandboxed"),
                    &format!(
                        "'{agent_name}' is now running in a sandbox inside {:?}",
                        cwd
                    ),
                );
            }
        }
    }
}

#[cfg(unix)]
fn send_desktop_notification(summary: &str, body: &str) {
    let result = notify_rust::Notification::new()
        .summary(summary)
        .body(body)
        .appname("AgentGuard")
        .timeout(notify_rust::Timeout::Milliseconds(5000))
        .show();
    match result {
        Ok(_) => tracing::debug!(summary, "desktop notification sent"),
        Err(e) => tracing::warn!(error = %e, "failed to send desktop notification"),
    }
}
