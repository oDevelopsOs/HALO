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

use agentguard_daemon::{Config, Vault};
use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};
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

    // TODO (Fase 1.6): kernel_loader::load
    // TODO (Fase 2.1): dlp_proxy::start
    // TODO (Fase 2.6): ipc_server::start

    info!("entering main loop (ctrl-c to quit)");
    tokio::signal::ctrl_c().await?;
    info!("AgentGuard daemon shutting down");
    Ok(())
}
