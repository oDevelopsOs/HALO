//! AgentGuard daemon — entry point.
//!
//! Este binario es el núcleo del sistema. Carga (en Linux) los programas
//! eBPF LSM, arranca el proxy DLP, expone un socket IPC para la CLI y la
//! UI, y gestiona el vault de snapshots.
//!
//! El scaffolding de Fase 0 solo inicializa logging y bloquea a la espera
//! de `SIGTERM` / `SIGINT`. Los módulos reales se van añadiendo en las
//! siguientes fases según el plan.

use std::path::PathBuf;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use agentguard_daemon::dlp::patterns::compile_all;
use agentguard_daemon::dlp::tls::LeafIssuer;
use agentguard_daemon::dlp::DlpProxy;
use agentguard_daemon::ipc_server::IpcServer;
use agentguard_daemon::{select_guard, Config, LocalCa, SecurityEvent, Vault, ViolationKind};
use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "agentguard-daemon",
    version = env!("CARGO_PKG_VERSION"),
    about = "AgentGuard — kernel-level protection daemon",
)]
struct Args {
    /// Path al archivo de configuración. Si no se indica, se busca en
    /// `/etc/agentguard/config.toml` (modo root) o `~/.agentguard/config.toml`
    /// (modo usuario).
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Añade un path protegido en caliente (override del config).
    #[arg(long = "protect", value_name = "PATH")]
    protect: Vec<PathBuf>,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,agentguard_daemon=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn default_config_path() -> PathBuf {
    #[cfg(unix)]
    {
        use nix::unistd::Uid;
        if Uid::effective().is_root() {
            return PathBuf::from("/etc/agentguard/config.toml");
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("config.toml"))
}

fn default_vault_dir() -> PathBuf {
    #[cfg(unix)]
    {
        use nix::unistd::Uid;
        if Uid::effective().is_root() {
            return PathBuf::from("/var/lib/agentguard/vault");
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("vault"))
        .unwrap_or_else(|| PathBuf::from("vault"))
}

fn default_ca_dir() -> PathBuf {
    #[cfg(unix)]
    {
        use nix::unistd::Uid;
        if Uid::effective().is_root() {
            return PathBuf::from("/var/lib/agentguard/ca");
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("ca"))
        .unwrap_or_else(|| PathBuf::from("ca"))
}

fn default_ipc_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        use nix::unistd::Uid;
        if Uid::effective().is_root() {
            return PathBuf::from("/var/run/agentguard.sock");
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("agentguard.sock"))
        .unwrap_or_else(|| PathBuf::from("agentguard.sock"))
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "AgentGuard daemon starting"
    );

    // Cargar config: archivo si existe, sino defaults.
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

    // Overrides CLI
    for p in &args.protect {
        config.protected_dirs.push(p.clone());
    }

    info!(
        protected_dirs = config.protected_dirs.len(),
        protected_files = config.protected_files.len(),
        dlp_enabled = config.dlp.enabled,
        "config loaded"
    );

    // Vault
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

    // CA root local (Fase 2.2): cargar o generar. Se usará en Fase 2.3
    // cuando el proxy DLP soporte HTTPS MITM. Por ahora solo la preparamos.
    let ca_dir = default_ca_dir();
    let ca = LocalCa::load_or_generate(&ca_dir).with_context(|| format!("CA at {ca_dir:?}"))?;
    let leaf_issuer =
        LeafIssuer::new(&ca).with_context(|| "failed to initialize TLS leaf certificate issuer")?;
    info!(
        cert_path = ?ca.cert_path(),
        "CA root ready — HTTPS MITM enabled for DLP proxy"
    );

    // Seleccionar guard (eBPF si está disponible, sino userspace).
    let guard = select_guard(&config.protected_dirs, &config.protected_files).await?;
    let guard_backend_name = guard.backend_name().to_string();
    let guard_level = format!("{:?}", guard.protection_level());
    info!(
        backend = %guard_backend_name,
        level = %guard_level,
        "protection backend ready"
    );

    // Canal de eventos compartido entre guard + DLP proxy → loop principal.
    let (event_tx, mut event_rx) = mpsc::channel::<SecurityEvent>(256);

    let guard_event_tx = event_tx.clone();
    let guard_task = tokio::spawn(async move {
        if let Err(e) = guard.run(guard_event_tx).await {
            error!(error = %e, "protection backend crashed");
        }
    });

    // DLP proxy (si habilitado en config).
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

    // IPC server (Fase 2.6): socket para CLI y UI.
    let ipc_server = IpcServer::new(
        vault.clone(),
        config.clone(),
        &guard_backend_name,
        &guard_level,
    );
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

    drop(event_tx); // el clon lo mantienen guard + dlp; cuando todos cierren, el rx se cierra.

    info!("entering main loop (ctrl-c to quit)");
    let vault_for_events = vault.clone();
    let snapshot_on_violation = config.on_violation.snapshot_on_violation;
    let violation_paths = config.protected_dirs.clone();
    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                handle_event(&vault_for_events, snapshot_on_violation, &violation_paths, event).await;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c received");
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
    Ok(())
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
