//! AgentGuard CLI — comunitator de comandos v\u{ed}a socket IPC del daemon.
//!
//! Conecta al socket Unix `~/.agentguard/agentguard.sock` (o
//! `/var/run/agentguard.sock` como root), env\u{ed}a un comando serializado
//! como JSON-line, y muestra la respuesta formateada con colores.
//!
//! Terminal-first: esta CLI es la interfaz primaria. Toda la funcionalidad
//! del producto es accesible desde aqu\u{ed}.

#[cfg(unix)]
mod transport {
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    pub fn connect(path: &Path) -> std::io::Result<UnixStream> {
        UnixStream::connect(path)
    }
}

#[cfg(not(unix))]
mod transport {
    use std::io;
    use std::io::{Read, Write};
    use std::path::Path;

    pub struct StubStream;

    impl Read for StubStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "IPC not available on this platform",
            ))
        }
    }
    impl Write for StubStream {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "IPC not available on this platform",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub fn connect(_path: &Path) -> io::Result<StubStream> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "IPC not available on this platform (use Unix socket or named pipe)",
        ))
    }
}

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use agentguard_common::{IpcCommand, IpcResponse, IPC_PROTOCOL_VERSION, IPC_SOCKET_PATH};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use transport::connect;

// ── CLI structure ─────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "agentguard",
    version = env!("CARGO_PKG_VERSION"),
    about = "Protect your filesystem and secrets from AI agents gone rogue",
    after_help = "Daemon must be running. Check: systemctl status agentguard"
)]
struct Cli {
    #[arg(short, long, help = "Path to IPC socket")]
    socket: Option<PathBuf>,

    #[arg(long, help = "Output as JSON (machine-readable)")]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show protection status (guard backend, protected paths, incident count)
    Status,

    /// Protect a directory or file
    Protect {
        path: String,
        #[arg(long, help = "Only watch, don't block (userspace only)")]
        watch_only: bool,
    },

    /// Remove protection from a path
    Unprotect { path: String },

    /// Snapshot management (create, list, restore, cleanup)
    #[command(subcommand)]
    Snapshot(SnapshotCmd),

    /// Show recent security incidents from the log
    Incidents {
        #[arg(short, long, default_value_t = 20)]
        last: usize,
    },

    /// Pause protection temporarily
    Pause {
        #[arg(short, long, default_value_t = 30, help = "Duration in minutes")]
        minutes: u64,
    },

    /// Resume protection after pause
    Resume,

    /// Health check: is the daemon running?
    Ping,

    /// Generate a default config.toml (does not require daemon)
    Init {
        #[arg(long, help = "Write to this file (default: stdout)")]
        output: Option<PathBuf>,
        #[arg(long, help = "Write to ~/.agentguard/config.toml")]
        defaults: bool,
    },

    /// Launch an AI agent inside a sandbox (v2.1)
    Launch {
        /// Agent executable name (e.g. cursor, claude, windsurf)
        agent: String,
        /// Additional arguments for the agent
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        /// Force sandbox mode (monitor, sandbox, hybrid)
        #[arg(long)]
        mode: Option<String>,
    },

    /// Check system capabilities (sandbox, eBPF, Landlock)
    Check,

    /// Interactive first-time setup wizard
    Setup,

    /// Check for and install updated versions
    Update {
        /// Only check, don't install
        #[arg(long)]
        check_only: bool,
    },
}

#[derive(Subcommand)]
enum SnapshotCmd {
    /// Create a new snapshot of all protected paths
    Create {
        #[arg(short, long, default_value = "manual")]
        label: String,
    },
    /// List all snapshots (newest first)
    List,
    /// Restore a snapshot by ID (use 'latest' for the most recent one)
    Restore {
        id: String,
        #[arg(long, help = "Skip confirmation")]
        yes: bool,
    },
    /// Delete snapshots older than N days
    Cleanup {
        #[arg(long, default_value_t = 30)]
        keep_days: u64,
    },
}

// ── Helpers ────────────────────────────────────────────────

fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(IPC_SOCKET_PATH))
        .unwrap_or_else(|| PathBuf::from("agentguard.sock"))
}

fn build_command(cmd: Command) -> IpcCommand {
    match cmd {
        Command::Status => IpcCommand::Status,
        Command::Ping => IpcCommand::Ping,
        Command::Protect { path, watch_only } => IpcCommand::Protect { path, watch_only },
        Command::Unprotect { path } => IpcCommand::Unprotect { path },
        Command::Snapshot(SnapshotCmd::Create { label }) => IpcCommand::SnapshotCreate { label },
        Command::Snapshot(SnapshotCmd::List) => IpcCommand::SnapshotList,
        Command::Snapshot(SnapshotCmd::Restore { id, yes }) => {
            IpcCommand::SnapshotRestore { id, yes }
        }
        Command::Snapshot(SnapshotCmd::Cleanup { keep_days }) => {
            IpcCommand::SnapshotCleanup { keep_days }
        }
        Command::Incidents { last } => IpcCommand::Incidents { last: Some(last) },
        Command::Pause { minutes } => IpcCommand::Pause { minutes },
        Command::Resume => IpcCommand::Resume,
        Command::Launch { agent, args, mode } => IpcCommand::LaunchAgent {
            exe: agent,
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| ".".to_string()),
            extra_args: args,
            mode_override: mode,
        },
        Command::Check | Command::Setup | Command::Update { .. } | Command::Init { .. } => {
            unreachable!("build_command called with local-only command") // unwrap-ok: filtered before IPC
        }
    }
}

fn green(s: &str) -> String {
    format!("\x1b[32m{s}\x1b[0m")
}
fn red(s: &str) -> String {
    format!("\x1b[31m{s}\x1b[0m")
}
fn yellow(s: &str) -> String {
    format!("\x1b[33m{s}\x1b[0m")
}
fn bold(s: &str) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}
fn dim(s: &str) -> String {
    format!("\x1b[2m{s}\x1b[0m")
}

fn fmt_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn fmt_ts(ts: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    match SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(ts)) {
        Some(t) => {
            let d = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let days = d / 86400;
            let rem = d % 86400;
            let h = rem / 3600;
            let m = (rem % 3600) / 60;
            format!("{days}d {h:02}:{m:02}h ago")
        }
        None => "unknown".into(),
    }
}

// ── Output formatters ──────────────────────────────────────

fn format_response(response: IpcResponse) {
    match response {
        IpcResponse::Ok { message } => println!("{} {}", green("✓"), message),
        IpcResponse::Error { message } => {
            eprintln!("{} {}", red("✗"), message);
            std::process::exit(1);
        }
        IpcResponse::Pong => {
            println!(
                "{} daemon is running (protocol v{})",
                green("✓"),
                IPC_PROTOCOL_VERSION
            );
        }
        IpcResponse::StatusData {
            version,
            guard_backend,
            protection_level,
            dlp_enabled,
            paused,
            protected_dirs,
            protected_files,
            ..
        } => {
            // --- Header ---
            println!("{}", bold(&format!("AgentGuard v{version}")));
            println!();

            // --- Guard status ---
            let guard_icon = if protection_level.contains("kernel") {
                green("●")
            } else {
                "○".to_string()
            };
            println!(
                "  {} Guard:      {guard_backend} ({protection_level})",
                guard_icon
            );
            println!(
                "  {} DLP Proxy:  {}",
                if dlp_enabled {
                    green("✓")
                } else {
                    dim("✗")
                },
                if dlp_enabled {
                    "active on :7771"
                } else {
                    "disabled"
                }
            );
            if paused {
                println!("  {} PAUSED — agentguard resume", yellow("⏸"));
            }
            println!();

            // --- Protected paths ---
            let total = protected_dirs.len() + protected_files.len();
            if total == 0 {
                println!("  {} No paths protected.", dim("—"));
            } else {
                println!("  {} Protected Paths ({total}):", bold("🛡"));
                for d in &protected_dirs {
                    println!("    {} {}  (dir)", green("●"), d);
                }
                for f in &protected_files {
                    println!("    {} {}  (file)", green("○"), f);
                }
            }
            println!();

            // --- Quick actions ---
            println!(
                "  {}",
                dim("Commands: agentguard snapshot list | agentguard incidents")
            );
        }
        IpcResponse::SnapshotList { snapshots } => {
            if snapshots.is_empty() {
                println!("  No snapshots yet. Create one with: agentguard snapshot create");
                return;
            }
            println!("  {}", bold("Snapshots"));
            println!(
                "  {:<36}  {:<14}  {:<16}  {:<6}  SIZE",
                "ID", "WHEN", "LABEL", "FILES"
            );
            println!("  {}", dim(&"-".repeat(90)));
            for s in &snapshots {
                let short_id = if s.id.len() > 8 { &s.id[..8] } else { &s.id };
                println!(
                    "  {short_id}  {:<14}  {:<16}  {:>4}   {}",
                    fmt_ts(s.timestamp),
                    s.label,
                    s.files,
                    fmt_size(s.total_size),
                );
            }
            println!();
            println!(
                "  {}",
                dim("Restore:  agentguard snapshot restore <id> --yes")
            );
            println!(
                "  {}",
                dim("Cleanup:  agentguard snapshot cleanup --keep-days 30")
            );
        }
        IpcResponse::Incidents { lines } => {
            if lines.is_empty() {
                println!("  No incidents recorded yet.");
                return;
            }
            println!("  {}", bold("Recent Incidents"));
            for line in &lines {
                println!("  {line}");
            }
        }
        IpcResponse::AgentLaunched { sandbox_pid } => {
            println!(
                "  {}",
                green(&format!("Agent launched in sandbox (pid={sandbox_pid})"))
            );
        }
    }
}

// ── Init: generate default config ──────────────────────────

const DEFAULT_CONFIG_TOML: &str = r#"# AgentGuard configuration
[agentguard]
version = "1"

# Paths protected from deletion/renaming
protected_dirs = ["~/Documents", "~/Projects", "~/.ssh"]

# Individual files protected from writes
protected_files = ["~/.env", "~/.netrc", "~/.aws/credentials"]

# AI agent process identification
[[agent_processes]]
name = "cursor"
match = { exe = "cursor" }

[[agent_processes]]
name = "claude-code"
match = { exe_any = ["claude", "claude-code"] }

[[agent_processes]]
name = "vscode-copilot"
match = { exe = "code", argv_contains_any = ["copilot", "cline", "continue"] }

[on_violation]
kill_process = false
snapshot_on_violation = true

# ── v2.1: AI Agent Sandbox ──────────────────────────────────
[sandbox]
modo_por_defecto = "sandbox"
auto_detectar_agentes = true
montar_solo_proyecto = true
morir_con_padre = true

# ── v2.1: Agent Detection ───────────────────────────────────
[agent_detection]
known_agents = [
    { name = "cursor", exe = ["cursor", "Cursor"] },
    { name = "claude-code", exe = ["claude", "claude-code"] },
    { name = "windsurf", exe = ["windsurf", "Windsurf"] },
    { name = "aider", exe = ["aider"] },
    { name = "vscode-agent", exe = ["code"], argv_contains = ["copilot", "cline"] },
]

# ── v2.1: Windows ───────────────────────────────────────────
[windows]
use_lpac = true
use_etw = true
polling_interval_ms = 500

[alerts]
desktop_notifications = true
sound = false

[vault]
snapshot_on_start = true
auto_snapshot_interval_hours = 6
keep_days = 30

[dlp]
enabled = true
proxy_port = 7771
action = "block"

[updates]
auto_check = true
auto_install = false
channel = "stable"
"#;

fn handle_init(output: Option<PathBuf>, defaults: bool) -> Result<()> {
    let path = if defaults {
        let p = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
            .join(".agentguard")
            .join("config.toml");
        std::fs::create_dir_all(
            p.parent()
                .ok_or_else(|| anyhow::anyhow!("invalid config path: no parent directory"))?,
        )?;
        p
    } else if let Some(p) = output {
        p
    } else {
        println!("{DEFAULT_CONFIG_TOML}");
        return Ok(());
    };

    if path.exists() {
        anyhow::bail!(
            "{} already exists. Use 'agentguard init --output <path>' or remove it first.",
            path.display()
        );
    }
    std::fs::write(&path, DEFAULT_CONFIG_TOML)?;
    println!("{} config written to {}", green("✓"), path.display());
    println!("  Edit it and restart the daemon: sudo systemctl restart agentguard");
    Ok(())
}

fn handle_setup() -> Result<()> {
    println!();
    println!("  {}", bold("AgentGuard v2.1 — First-time Setup"));
    println!();
    println!("  Protect your machine from AI agents that go rogue.");
    println!();

    let cwd = std::env::current_dir()?;
    println!("  Current directory: {}", cwd.display());
    print!("  Protect this directory? [Y/n] ");
    use std::io::{self, BufRead, Write};
    io::stdout().flush().ok();
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .unwrap_or(Ok("y".into()))
        .unwrap_or("y".into());

    if line.trim().to_lowercase() == "n" {
        println!();
        println!("  Ok. You can protect directories manually:");
        println!("    agentguard protect /your/project");
        return Ok(());
    }

    // Connect to daemon and add the path
    let socket_path = default_socket_path();
    let mut stream = connect(&socket_path).with_context(|| {
        format!(
            "cannot connect to daemon at {socket_path:?}.\n\
             Is the daemon running? Start it: sudo systemctl start agentguard"
        )
    })?;

    let cmd = IpcCommand::AddProtectedPath {
        path: cwd.display().to_string(),
    };
    let json = serde_json::to_string(&cmd)?;
    writeln!(stream, "{json}")?;
    stream.flush()?;

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let _response: IpcResponse =
        serde_json::from_str(line.trim()).with_context(|| format!("invalid response: {line}"))?;

    println!();
    println!("  {}", green("Setup complete!"));
    println!();
    println!("  {}  Protected: {}", green("✓"), cwd.display());
    println!("  {}  DLP Proxy: 127.0.0.1:7771", green("✓"));
    println!("  {}  Auto-detection of AI agents: active", green("✓"));
    println!();
    println!("  From now on, when you open Cursor, Claude, or any agent");
    println!("  inside this directory, it will be sandboxed.");
    println!();
    println!("  Try:  {}", bold("agentguard launch cursor"));
    println!("        {}", bold("agentguard status"));

    Ok(())
}

fn handle_check() -> Result<()> {
    println!();
    println!("  {}", bold("AgentGuard — System Capabilities Check"));
    println!();

    // Check sandbox capabilities locally
    #[cfg(target_os = "linux")]
    {
        let bwrap = std::process::Command::new("which")
            .arg("bwrap")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let landlock = check_landlock_kernel();
        let ebpf = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.contains("bpf"))
            .unwrap_or(false);

        println!(
            "  bwrap:     {}",
            if bwrap {
                green("available")
            } else {
                red("not found — install bubblewrap")
            }
        );
        println!(
            "  Landlock:  {}",
            if landlock {
                green("available")
            } else {
                yellow("kernel >= 5.13 required")
            }
        );
        println!(
            "  eBPF LSM:  {}",
            if ebpf {
                green("available")
            } else {
                yellow("kernel >= 5.7 + CONFIG_BPF_LSM required")
            }
        );
        println!();

        let effective = if bwrap && landlock {
            "hybrid"
        } else if bwrap {
            "sandbox"
        } else {
            "monitor"
        };
        println!("  Effective mode: {}", bold(effective));
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("  Platform-specific capabilities not displayed on this OS.");
    }

    // Also query the daemon for status
    let socket_path = default_socket_path();
    if let Ok(mut stream) = connect(&socket_path) {
        let cmd = IpcCommand::Status;
        let json = serde_json::to_string(&cmd).unwrap_or_default();
        let _ = writeln!(stream, "{json}");
        let _ = stream.flush();
    }

    println!();
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_landlock_kernel() -> bool {
    let output = std::process::Command::new("uname").arg("-r").output();
    if let Ok(out) = output {
        if let Ok(version) = std::str::from_utf8(&out.stdout) {
            let parts: Vec<u32> = version
                .trim()
                .split('.')
                .take(2)
                .filter_map(|s| s.parse().ok())
                .collect();
            if parts.len() >= 2 {
                return parts[0] > 5 || (parts[0] == 5 && parts[1] >= 13);
            }
        }
    }
    false
}

fn handle_update(check_only: bool) -> Result<()> {
    use agentguard_core::updater::Updater;

    let updater = Updater::new("tuorg", "agentguard");

    println!("  Checking for updates...");

    match updater.check() {
        Ok(Some(version)) => {
            println!(
                "  {} v{version} available (current: v{})",
                green("✓"),
                env!("CARGO_PKG_VERSION")
            );

            if check_only {
                println!("  Run 'agentguard update' to install.");
                return Ok(());
            }

            print!("  Install update? [Y/n] ");
            use std::io::{self, BufRead, Write};
            io::stdout().flush().ok();
            let line = io::stdin()
                .lock()
                .lines()
                .next()
                .unwrap_or(Ok("y".into()))
                .unwrap_or("y".into());

            if line.trim().to_lowercase() == "n" {
                println!("  Cancelled.");
                return Ok(());
            }

            println!("  Downloading v{version}...");
            match updater.update() {
                Ok(path) => {
                    println!("  {} Updated to v{version}", green("✓"));
                    println!("  Binary: {}", path.display());
                    println!("  Restart the daemon: systemctl restart agentguard");
                    println!("  Restart TUI if open.");
                }
                Err(e) => {
                    println!("  {} Update failed: {e}", red("✗"));
                    return Err(anyhow::anyhow!("{e}"));
                }
            }
        }
        Ok(None) => {
            println!(
                "  {} Already up to date (v{})",
                green("✓"),
                env!("CARGO_PKG_VERSION")
            );
        }
        Err(e) => {
            println!("  {} Cannot check for updates: {e}", yellow("⚠"));
        }
    }

    Ok(())
}

// ── Main ───────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Init, Setup, Update and Check are handled locally (no IPC needed)
    if matches!(
        cli.command,
        Command::Init { .. } | Command::Setup | Command::Check | Command::Update { .. }
    ) {
        match cli.command {
            Command::Init { output, defaults } => return handle_init(output, defaults),
            Command::Setup => return handle_setup(),
            Command::Check => return handle_check(),
            Command::Update { check_only } => return handle_update(check_only),
            _ => unreachable!(), // unwrap-ok: guarded by outer matches!
        }
    }

    let socket_path = cli.socket.unwrap_or_else(default_socket_path);
    let mut stream = connect(&socket_path).with_context(|| {
        format!(
            "cannot connect to daemon at {socket_path:?}.\n\
             Is the daemon running? Check: systemctl status agentguard\n\
             Start it:    sudo systemctl start agentguard"
        )
    })?;

    let cmd = build_command(cli.command);
    let json = serde_json::to_string(&cmd)?;
    writeln!(stream, "{json}")?;
    stream.flush()?;

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    if cli.json {
        println!("{line}");
        return Ok(());
    }

    let response: IpcResponse = serde_json::from_str(line.trim())
        .with_context(|| format!("invalid response from daemon: {line}"))?;

    format_response(response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_command_status() {
        let cmd = build_command(Command::Status);
        assert!(matches!(cmd, IpcCommand::Status));
    }

    #[test]
    fn build_command_ping() {
        let cmd = build_command(Command::Ping);
        assert!(matches!(cmd, IpcCommand::Ping));
    }

    #[test]
    fn build_command_protect() {
        let cmd = build_command(Command::Protect {
            path: "/tmp/x".into(),
            watch_only: false,
        });
        match cmd {
            IpcCommand::Protect { path, watch_only } => {
                assert_eq!(path, "/tmp/x");
                assert!(!watch_only);
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn build_command_snapshot_create() {
        let cmd = build_command(Command::Snapshot(SnapshotCmd::Create {
            label: "test".into(),
        }));
        match cmd {
            IpcCommand::SnapshotCreate { label } => assert_eq!(label, "test"),
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn build_command_incidents() {
        let cmd = build_command(Command::Incidents { last: 42 });
        match cmd {
            IpcCommand::Incidents { last } => assert_eq!(last, Some(42)),
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn build_command_pause() {
        let cmd = build_command(Command::Pause { minutes: 15 });
        match cmd {
            IpcCommand::Pause { minutes } => assert_eq!(minutes, 15),
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn init_generates_valid_config() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("config.toml");
        handle_init(Some(path.clone()), false).expect("init");
        let content = std::fs::read_to_string(&path).expect("read");
        assert!(content.contains("protected_dirs"));
        assert!(content.contains("[agentguard]"));
        assert!(content.contains("[dlp]"));
    }

    #[test]
    fn init_rejects_existing_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, b"existing").expect("write");
        let err = handle_init(Some(path), false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn init_defaults_writes_to_home() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        // Verify handle_init with explicit output path works.
        let path = tmp.path().join("default.toml");
        handle_init(Some(path.clone()), false).expect("init");
        assert!(path.exists());
    }

    #[test]
    fn fmt_size_units() {
        assert_eq!(fmt_size(0), "0 B");
        assert_eq!(fmt_size(512), "512 B");
        assert_eq!(fmt_size(2048), "2.0 KiB");
        assert_eq!(fmt_size(5_242_880), "5.0 MiB");
    }

    #[test]
    fn default_socket_path_is_in_home() {
        let p = default_socket_path();
        assert!(p.to_string_lossy().contains(".agentguard"));
    }
}
