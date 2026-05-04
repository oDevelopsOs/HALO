//! AgentGuard daemon — entry point para macOS.
//!
//! Fase 5: daemon con chflags uchg (degraded) + FSEvents watcher +
//! detección de procesos, DLP proxy, IPC server, y vault de snapshots.
//!
//! En Linux, este binario compila como stub que informa que solo
//! está disponible en macOS.

use tracing_subscriber::EnvFilter;

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,agentguard_core=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    init_tracing();
    tracing::warn!("agentguard-macos is only available on macOS");
    tracing::info!("Use agentguard-linux on this platform instead");
    println!("agentguard-macos: this daemon only runs on macOS.");
    println!("On this platform, use: agentguard-linux");
}

// ── macOS implementation ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod guard;

#[cfg(target_os = "macos")]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "macos")]
use std::sync::Arc;

#[cfg(target_os = "macos")]
use agentguard_core::ca::LocalCa;
#[cfg(target_os = "macos")]
use agentguard_core::config::Config;
#[cfg(target_os = "macos")]
use agentguard_core::dlp::patterns::compile_all;
#[cfg(target_os = "macos")]
use agentguard_core::dlp::tls::LeafIssuer;
#[cfg(target_os = "macos")]
use agentguard_core::dlp::DlpProxy;
#[cfg(target_os = "macos")]
use agentguard_core::events::{SecurityEvent, ViolationKind};
#[cfg(target_os = "macos")]
use agentguard_core::ipc_server::IpcServer;
#[cfg(target_os = "macos")]
use agentguard_core::vault::Vault;

#[cfg(target_os = "macos")]
use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use clap::Parser;
#[cfg(target_os = "macos")]
use tokio::sync::mpsc;
#[cfg(target_os = "macos")]
use tracing::{error, info, warn};

#[cfg(target_os = "macos")]
#[derive(Parser, Debug)]
#[command(
    name = "agentguard-macos",
    version = env!("CARGO_PKG_VERSION"),
    about = "AgentGuard — filesystem protection daemon for macOS"
)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(long = "protect", value_name = "PATH")]
    protect: Vec<PathBuf>,
}

#[cfg(target_os = "macos")]
fn default_config_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("config.toml"))
}

#[cfg(target_os = "macos")]
fn default_vault_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("vault"))
        .unwrap_or_else(|| PathBuf::from("vault"))
}

#[cfg(target_os = "macos")]
fn default_ca_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("ca"))
        .unwrap_or_else(|| PathBuf::from("ca"))
}

#[cfg(target_os = "macos")]
fn default_ipc_socket_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("agentguard.sock"))
        .unwrap_or_else(|| PathBuf::from("agentguard.sock"))
}

#[cfg(target_os = "macos")]
fn incidents_log_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("incidents.jsonl"))
        .unwrap_or_else(|| PathBuf::from("incidents.jsonl"))
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "AgentGuard macOS daemon starting"
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
    info!(cert_path = ?ca.cert_path(), "CA root ready");

    // ── Guard (macOS: chflags + FSEvents) ───────────────────
    let guard = guard::MacOsGuard::new(&config.protected_dirs, config.agent_processes.clone())
        .context("failed to initialize macOS guard")?;
    let guard_backend_name = "macOS chflags + FSEvents".to_string();
    let guard_level = "userspace-degraded".to_string();
    warn!("macOS protection is DEGRADED: chflags uchg can be reversed by any user process");

    // ── Canal de eventos ────────────────────────────────────
    let (event_tx, mut event_rx) = mpsc::channel::<SecurityEvent>(256);
    let guard_event_tx = event_tx.clone();
    let guard_task = tokio::spawn(async move {
        if let Err(e) = guard.run(guard_event_tx).await {
            error!(error = %e, "protection backend crashed");
        }
    });

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
                        info!(addr = %h.local_addr(), "DLP proxy started");
                        Some(h)
                    }
                    Err(e) => {
                        error!(error = %e, "DLP proxy failed");
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
        info!("DLP disabled");
        None
    };

    // ── IPC server ──────────────────────────────────────────
    let log_path = incidents_log_path();
    let paused = Arc::new(AtomicBool::new(false));
    let ipc_server = IpcServer::builder(
        vault.clone(),
        config.clone(),
        &guard_backend_name,
        &guard_level,
    )
    .incidents_log(log_path.clone())
    .paused(paused.clone())
    .sandbox_mode("monitor".to_string())
    .capabilities("chflags=yes FSEvents=yes sandbox=N/A".to_string())
    .build()
    .with_context(|| "failed to create IPC server")?;
    let ipc_socket_path = default_ipc_socket_path();
    let ipc_handle = match ipc_server.start(ipc_socket_path.clone()) {
        Ok(h) => {
            info!(path = %ipc_socket_path.display(), "IPC server started");
            Some(h)
        }
        Err(e) => {
            error!(error = %e, "IPC server failed");
            None
        }
    };
    drop(event_tx);

    // ── Main loop ───────────────────────────────────────────
    info!(path = %log_path.display(), "entering main loop");
    let vault_for_events = vault.clone();
    let snapshot_on_violation = config.on_violation.snapshot_on_violation;
    let violation_paths = config.protected_dirs.clone();

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                if paused.load(Ordering::SeqCst) {
                    persist_incident(&log_path, &event).await;
                } else {
                    persist_incident(&log_path, &event).await;
                    handle_event(&vault_for_events, snapshot_on_violation, &violation_paths, event).await;
                }
            }
            _ = tokio::signal::ctrl_c() => { info!("SIGINT — shutting down"); break; }
            _ = sigterm.recv() => { info!("SIGTERM — shutting down"); break; }
            else => break,
        }
    }
    info!("shutting down");
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

#[cfg(target_os = "macos")]
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
                error!(error = %e, "failed to write incident");
            }
        }
        Err(e) => error!(error = %e, "failed to open incidents log"),
    }
}

#[cfg(target_os = "macos")]
async fn handle_event(
    vault: &Vault,
    snapshot_on_violation: bool,
    protected_paths: &[PathBuf],
    event: SecurityEvent,
) {
    match &event {
        SecurityEvent::FileViolation {
            path,
            process,
            pid,
            violation,
            ..
        } => {
            warn!(action = ?violation, path = ?path, process = %process, pid, "filesystem violation detected");
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
            warn!(pattern = %pattern_name, destination = %destination, process = %process, "DLP violation detected");
        }
        SecurityEvent::SystemError { message, .. } => {
            error!(message = %message, "system error from guard");
        }
        SecurityEvent::AgentDetected {
            pid,
            agent_name,
            cwd,
            ..
        } => {
            info!(pid, agent = %agent_name, cwd = %cwd.display(), "AI agent detected");
        }
        SecurityEvent::AgentSandboxed { .. } => {
            info!("agent sandboxed (not supported on macOS — monitor only)");
        }
    }
}
