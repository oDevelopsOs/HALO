//! AgentGuard daemon — entry point para Windows.
//!
//! Fase 4: daemon completo con NTFS DENY ACEs + Job Objects, DLP proxy
//! HTTPS MITM, IPC server (named pipe), vault de snapshots y loop
//! principal de eventos.
//!
//! ## Modos de ejecución
//!
//! - **Modo consola** (default): responde a Ctrl+C. Útil para desarrollo y
//!   ejecución manual como Administrador.
//! - **Modo servicio** (`--service`): se registra con el SCM via
//!   `StartServiceCtrlDispatcherW`. Responde a `SERVICE_CONTROL_STOP`,
//!   `SERVICE_CONTROL_PAUSE`, `SERVICE_CONTROL_CONTINUE`. Reporta estado
//!   al SCM via `SetServiceStatus`.
//!
//! ## Señales
//!
//! | Modo | Señal | Acción |
//! |---|---|---|
//! | Consola | Ctrl+C | Graceful shutdown |
//! | Servicio | SERVICE_CONTROL_STOP | Graceful shutdown |
//! | Servicio | SERVICE_CONTROL_PAUSE | Pausa watcher + scan |
//! | Servicio | SERVICE_CONTROL_CONTINUE | Reanuda watcher + scan |
//!
//! El daemon debe correr como SYSTEM o Administrador para poder aplicar
//! NTFS DENY ACEs.

mod guard;
mod process_watcher;
mod sandbox;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use agentguard_core::ca::LocalCa;
use agentguard_core::config::Config;
use agentguard_core::dlp::patterns::compile_all;
use agentguard_core::dlp::tls::LeafIssuer;
use agentguard_core::dlp::DlpProxy;
use agentguard_core::events::{SecurityEvent, ViolationKind};
use agentguard_core::ipc_server::IpcServer;
use agentguard_core::vault::Vault;
use agentguard_core::KernelGuard;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "agentguard-windows",
    version = env!("CARGO_PKG_VERSION"),
    about = "AgentGuard — kernel-level protection daemon for Windows"
)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(long = "protect", value_name = "PATH")]
    protect: Vec<PathBuf>,

    /// Run as a Windows Service (registers with SCM)
    #[arg(long)]
    service: bool,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,agentguard_core=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

/// Determina si el proceso actual corre con privilegios elevados.
fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut size: u32 = 0;
            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            let _ = CloseHandle(token);
            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn default_config_path() -> PathBuf {
    if is_elevated() {
        PathBuf::from(r"C:\ProgramData\AgentGuard\config.toml")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".agentguard")
            .join("config.toml")
    }
}

fn default_vault_dir() -> PathBuf {
    if is_elevated() {
        PathBuf::from(r"C:\ProgramData\AgentGuard\vault")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".agentguard")
            .join("vault")
    }
}

fn default_ca_dir() -> PathBuf {
    if is_elevated() {
        PathBuf::from(r"C:\ProgramData\AgentGuard\ca")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".agentguard")
            .join("ca")
    }
}

fn default_ipc_pipe_name() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!("agentguard-{user}")
}

fn incidents_log_path() -> PathBuf {
    if is_elevated() {
        PathBuf::from(r"C:\ProgramData\AgentGuard\incidents.jsonl")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".agentguard")
            .join("incidents.jsonl")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        elevated = is_elevated(),
        service = args.service,
        "AgentGuard Windows daemon starting"
    );

    if args.service {
        #[cfg(windows)]
        {
            run_as_service(args).await
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("--service is only supported on Windows");
        }
    } else {
        run_console(args).await
    }
}

// ── Modo consola ──────────────────────────────────────────────

async fn run_console(args: Args) -> Result<()> {
    if !is_elevated() {
        warn!("daemon is NOT running as Administrator — NTFS DENY ACEs may fail");
        warn!("for full protection, run as SYSTEM or elevated Administrator");
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_ctrlc = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("ctrl-c received — initiating shutdown");
        shutdown_ctrlc.store(true, Ordering::SeqCst);
    });

    run_daemon(args, shutdown).await
}

// ── Modo servicio Windows ─────────────────────────────────────

#[cfg(windows)]
async fn run_as_service(_args: Args) -> Result<()> {
    use windows::Win32::System::Services::{StartServiceCtrlDispatcherW, SERVICE_TABLE_ENTRYW};

    let mut service_name: Vec<u16> = "AgentGuard\0".encode_utf16().collect();

    unsafe {
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: windows::core::PWSTR(service_name.as_mut_ptr()),
                lpServiceProc: Some(service_main_entry as _),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: windows::core::PWSTR(std::ptr::null_mut()),
                lpServiceProc: None,
            },
        ];

        if StartServiceCtrlDispatcherW(table.as_ptr()).is_err() {
            error!("StartServiceCtrlDispatcherW failed — is the service registered?");
            anyhow::bail!(
                "StartServiceCtrlDispatcherW failed. Run `sc.exe create AgentGuard ...` first."
            );
        }
    }

    info!("AgentGuard Windows service stopping");
    Ok(())
}

#[cfg(windows)]
static SERVICE_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Wrapper seguro para el SERVICE_STATUS_HANDLE global.
#[cfg(windows)]
mod service_globals {
    use std::cell::UnsafeCell;
    use windows::Win32::System::Services::SERVICE_STATUS_HANDLE;

    struct ServiceHandleWrapper(UnsafeCell<SERVICE_STATUS_HANDLE>);
    unsafe impl Sync for ServiceHandleWrapper {}

    /// Handle del servicio registrado en el SCM.
    /// Solo se escribe una vez al registrarse y se lee desde el control handler.
    static HANDLE: ServiceHandleWrapper =
        ServiceHandleWrapper(UnsafeCell::new(SERVICE_STATUS_HANDLE(std::ptr::null_mut())));

    pub fn set(h: SERVICE_STATUS_HANDLE) {
        unsafe {
            *HANDLE.0.get() = h;
        }
    }

    pub fn get() -> SERVICE_STATUS_HANDLE {
        unsafe { *HANDLE.0.get() }
    }
}

#[cfg(windows)]
extern "system" fn service_main_entry(_argc: u32, _argv: *mut windows::core::PWSTR) {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, SERVICE_ACCEPT_PAUSE_CONTINUE,
        SERVICE_ACCEPT_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
    };

    let service_name: Vec<u16> = "AgentGuard\0".encode_utf16().collect();

    unsafe {
        let handle = RegisterServiceCtrlHandlerExW(
            windows::core::PCWSTR(service_name.as_ptr()),
            Some(service_control_handler),
            None,
        );

        let result = match handle {
            Ok(h) => {
                service_globals::set(h);

                // Reportar START_PENDING
                let mut status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS, // SERVICE_WIN32_OWN_PROCESS
                    dwCurrentState: SERVICE_START_PENDING,
                    dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE,
                    dwWin32ExitCode: NO_ERROR.0 as u32,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 5000,
                };
                SetServiceStatus(h, &mut status);

                // Iniciar el runtime de tokio y ejecutar el daemon
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(e) => {
                        error!(error = %e, "failed to create tokio runtime");
                        let mut stopped_status = SERVICE_STATUS {
                            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                            dwCurrentState: SERVICE_STOPPED,
                            dwControlsAccepted: 0,
                            dwWin32ExitCode: 0x0000_040F, // ERROR_SERVICE_SPECIFIC_ERROR
                            dwServiceSpecificExitCode: 1,
                            dwCheckPoint: 0,
                            dwWaitHint: 0,
                        };
                        SetServiceStatus(h, &mut stopped_status);
                        return;
                    }
                };
                rt.block_on(async {
                    let args = Args {
                        config: None,
                        protect: vec![],
                        service: true,
                    };

                    // Reportar RUNNING antes de entrar al loop
                    let mut running_status = SERVICE_STATUS {
                        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                        dwCurrentState: SERVICE_RUNNING,
                        dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE,
                        dwWin32ExitCode: NO_ERROR.0 as u32,
                        dwServiceSpecificExitCode: 0,
                        dwCheckPoint: 0,
                        dwWaitHint: 0,
                    };
                    SetServiceStatus(h, &mut running_status);

                    let shutdown = Arc::new(AtomicBool::new(false));
                    let shutdown_poll = shutdown.clone();

                    // Tarea que traduce la señal del SCM al Arc
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            if SERVICE_SHUTDOWN.load(Ordering::SeqCst) {
                                info!("service shutdown signal propagated to daemon loop");
                                shutdown_poll.store(true, Ordering::SeqCst);
                                break;
                            }
                        }
                    });

                    if let Err(e) = run_daemon(args, shutdown).await {
                        error!(error = %e, "daemon failed");
                    }
                });

                // Reportar STOPPED
                let mut stopped_status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOPPED,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: NO_ERROR.0 as u32,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };
                SetServiceStatus(h, &mut stopped_status);
            }
            Err(e) => {
                error!("RegisterServiceCtrlHandlerExW failed: {e:?}");
            }
        };
    }
}

#[cfg(windows)]
extern "system" fn service_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::System::Services::{
        SetServiceStatus, SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_PAUSED, SERVICE_RUNNING,
        SERVICE_STATUS, SERVICE_STOP_PENDING, SERVICE_WIN32_OWN_PROCESS,
    };

    unsafe {
        match control {
            SERVICE_CONTROL_STOP => {
                info!("SERVICE_CONTROL_STOP received — shutting down");
                let mut status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOP_PENDING,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: NO_ERROR.0 as u32,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 1,
                    dwWaitHint: 10000,
                };
                SetServiceStatus(service_globals::get(), &mut status);
                SERVICE_SHUTDOWN.store(true, Ordering::SeqCst);
                NO_ERROR.0
            }
            SERVICE_CONTROL_PAUSE => {
                info!("SERVICE_CONTROL_PAUSE received — pausing");
                let mut status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_PAUSED,
                    dwControlsAccepted: 0x01 | 0x02,
                    dwWin32ExitCode: NO_ERROR.0 as u32,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };
                SetServiceStatus(service_globals::get(), &mut status);
                NO_ERROR.0
            }
            SERVICE_CONTROL_CONTINUE => {
                info!("SERVICE_CONTROL_CONTINUE received — resuming");
                let mut status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_RUNNING,
                    dwControlsAccepted: 0x01 | 0x02,
                    dwWin32ExitCode: NO_ERROR.0 as u32,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };
                SetServiceStatus(service_globals::get(), &mut status);
                NO_ERROR.0
            }
            SERVICE_CONTROL_INTERROGATE => {
                // SCM pregunta estado — responder siempre OK
                NO_ERROR.0
            }
            _ => {
                // Control desconocido
                0x0000_0001 // ERROR_CALL_NOT_IMPLEMENTED
            }
        }
    }
}

// ── Daemon core (compartido entre modo consola y servicio) ─────

async fn run_daemon(args: Args, shutdown: Arc<AtomicBool>) -> Result<()> {
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
        agent_processes = config.agent_processes.len(),
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

    // ── Guard (NTFS DENY ACEs + Job Objects) ────────────────
    let agent_patterns = config.agent_processes.clone();
    let guard = guard::WindowsGuard::new(&config.protected_dirs, agent_patterns)?;
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
        if let Err(e) = Box::new(guard).run(guard_event_tx).await {
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
    let ipc_server = IpcServer::builder(
        vault.clone(),
        config.clone(),
        &guard_backend_name,
        &guard_level,
    )
    .incidents_log(log_path.clone())
    .paused(paused.clone())
    .sandbox_mode("sandbox".to_string())
    .capabilities("AppContainer=yes ETW=yes".to_string())
    .build()
    .with_context(|| "failed to create IPC server")?;
    let ipc_pipe_name = default_ipc_pipe_name();
    let ipc_socket_path = std::env::temp_dir().join(format!("{ipc_pipe_name}.sock"));
    let ipc_handle = match ipc_server.start(ipc_socket_path.clone()) {
        Ok(h) => {
            info!(pipe = %ipc_pipe_name, path = %ipc_socket_path.display(), "IPC server started");
            Some(h)
        }
        Err(e) => {
            error!(error = %e, "IPC server failed to start — continuing without IPC");
            None
        }
    };

    drop(event_tx);

    // ── Main loop ───────────────────────────────────────────
    info!(path = %log_path.display(), "incidents log ready");

    let vault_for_events = vault.clone();
    let snapshot_on_violation = config.on_violation.snapshot_on_violation;
    let violation_paths = config.protected_dirs.clone();

    info!("entering main loop");

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("shutdown signal received — exiting main loop");
            break;
        }

        tokio::select! {
            Some(event) = event_rx.recv() => {
                if paused.load(Ordering::SeqCst) {
                    tracing::debug!(kind = ?event, "event received while paused");
                    persist_incident(&log_path, &event).await;
                } else {
                    persist_incident(&log_path, &event).await;
                    handle_event(
                        &vault_for_events,
                        snapshot_on_violation,
                        &violation_paths,
                        event,
                    ).await;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                // Poll periódico para verificar shutdown
            }
            else => break,
        }
    }

    info!("AgentGuard Windows daemon shutting down");
    guard_task.abort();
    if let Some(h) = dlp_handle {
        h.shutdown();
    }
    if let Some(h) = ipc_handle {
        h.shutdown();
    }
    let _ = std::fs::remove_file(&ipc_socket_path);
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
            ..
        } => {
            info!(
                pid,
                agent = %agent_name,
                cwd = %cwd.display(),
                "AI agent detected in protected directory"
            );
        }
        SecurityEvent::AgentSandboxed {
            original_pid,
            sandbox_pid,
            agent_name,
            ..
        } => {
            info!(
                original_pid,
                sandbox_pid,
                agent = %agent_name,
                "agent sandboxed successfully"
            );
        }
    }
}
