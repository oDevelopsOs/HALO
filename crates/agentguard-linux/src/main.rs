//! AgentGuard daemon — entry point para Linux.
//!
//! Fase 2: daemon completo con eBPF LSM + userspace fallback, DLP proxy
//! HTTPS MITM, IPC server, vault de snapshots y loop principal de eventos.
//!
//! Señales:
//! - SIGTERM / SIGINT → graceful shutdown (limpia socket, cierra proxy)
//! - SIGUSR1 → reload config (pending — Fase 3)

mod guard;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use agentguard_core::ca::LocalCa;
use agentguard_core::config::Config;
use agentguard_core::dlp::patterns::compile_all;
use agentguard_core::dlp::tls::LeafIssuer;
use agentguard_core::dlp::DlpProxy;
use agentguard_core::events::{SecurityEvent, ViolationKind};
use agentguard_core::ipc_server::IpcServer;
use agentguard_core::vault::Vault;
use guard::select_guard;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
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

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,agentguard_core=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

fn default_config_path() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/etc/agentguard/config.toml");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("config.toml"))
}

fn default_vault_dir() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/var/lib/agentguard/vault");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("vault"))
        .unwrap_or_else(|| PathBuf::from("vault"))
}

fn default_ca_dir() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/var/lib/agentguard/ca");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("ca"))
        .unwrap_or_else(|| PathBuf::from("ca"))
}

fn default_ipc_socket_path() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/var/run/agentguard.sock");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("agentguard.sock"))
        .unwrap_or_else(|| PathBuf::from("agentguard.sock"))
}

fn incidents_log_path() -> PathBuf {
    use nix::unistd::Uid;
    if Uid::effective().is_root() {
        return PathBuf::from("/var/log/agentguard/incidents.jsonl");
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("incidents.jsonl"))
        .unwrap_or_else(|| PathBuf::from("incidents.jsonl"))
}

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
    let vault = Vault::with_dir(&vault_dir)
        .with_context(|| format!("vault at {vault_dir:?}"))?;
    info!(path = ?vault.root(), "vault ready");

    if config.vault.snapshot_on_start && !config.protected_dirs.is_empty() {
        match vault.create_snapshot(&config.protected_dirs, "startup").await {
            Ok(s) => info!(id = %s.id, files = s.files.len(), "startup snapshot created"),
            Err(e) => warn!(error = %e, "startup snapshot failed"),
        }
    }

    // ── CA (HTTPS MITM) ─────────────────────────────────────
    let ca_dir = default_ca_dir();
    let ca = LocalCa::load_or_generate(&ca_dir)
        .with_context(|| format!("CA at {ca_dir:?}"))?;
    let leaf_issuer = LeafIssuer::new(&ca)
        .with_context(|| "failed to initialize TLS leaf certificate issuer")?;
    info!(
        cert_path = ?ca.cert_path(),
        "CA root ready — HTTPS MITM enabled for DLP proxy"
    );

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
                let addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.dlp.proxy_port);
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
    let ipc_server = IpcServer::new(
        vault.clone(),
        config.clone(),
        &guard_backend_name,
        &guard_level,
    )
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
    let log_path = incidents_log_path();
    info!(path = %log_path.display(), "incidents log ready");

    let vault_for_events = vault.clone();
    let snapshot_on_violation = config.on_violation.snapshot_on_violation;
    let violation_paths = config.protected_dirs.clone();

    info!("entering main loop (SIGTERM / ctrl-c to quit)");

    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to register SIGTERM handler");
            return Err(anyhow::anyhow!("SIGTERM handler unavailable"));
        }
    };

    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                persist_incident(&log_path, &event).await;
                handle_event(
                    &vault_for_events,
                    snapshot_on_violation,
                    &violation_paths,
                    event,
                ).await;
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
                match vault
                    .create_snapshot(protected_paths, "on-violation")
                    .await
                {
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
    }
}
