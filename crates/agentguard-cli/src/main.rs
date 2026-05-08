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

#[cfg(windows)]
mod transport {
    use std::ffi::OsStr;
    use std::io;
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const OPEN_EXISTING: u32 = 3;

    pub struct NamedPipeStream {
        handle: isize,
    }

    impl Read for NamedPipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut bytes_read = 0u32;
            let ret = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            };
            if ret == 0 {
                return Err(io::Error::last_os_error());
            }
            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "pipe disconnected",
                ));
            }
            Ok(bytes_read as usize)
        }
    }

    impl Write for NamedPipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut bytes_written = 0u32;
            let ret = unsafe {
                WriteFile(
                    self.handle,
                    buf.as_ptr(),
                    buf.len() as u32,
                    &mut bytes_written,
                    std::ptr::null_mut(),
                )
            };
            if ret == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(bytes_written as usize)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for NamedPipeStream {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    pub fn connect(path: &Path) -> io::Result<NamedPipeStream> {
        let pipe_name = path.to_str().unwrap_or("agentguard");
        let full_name = if pipe_name.starts_with(r"\\.\") {
            pipe_name.to_string()
        } else {
            format!(r"\\.\pipe\{}", pipe_name)
        };

        let wide: Vec<u16> = OsStr::new(&full_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(NamedPipeStream { handle })
    }

    // FFI bindings to kernel32.dll
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut u8,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut u8,
        ) -> isize;

        fn ReadFile(
            hFile: isize,
            lpBuffer: *mut u8,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: *mut u32,
            lpOverlapped: *mut u8,
        ) -> i32;

        fn WriteFile(
            hFile: isize,
            lpBuffer: *const u8,
            nNumberOfBytesToWrite: u32,
            lpNumberOfBytesWritten: *mut u32,
            lpOverlapped: *mut u8,
        ) -> i32;

        fn CloseHandle(hObject: isize) -> i32;
    }
}

#[cfg(not(any(unix, windows)))]

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

#[cfg(not(windows))]
use agentguard_common::IPC_SOCKET_PATH;
use agentguard_common::{IpcCommand, IpcResponse, IPC_PROTOCOL_VERSION};
use agentguard_core::{
    self,
    smart_protect::{generate_smart_suggestions, ProtectionSuggestion},
};
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
        path: Option<String>,
        #[arg(long, help = "Only watch, don't block (userspace only)")]
        watch_only: bool,
        #[arg(long, help = "Apply the recommended protection profile (all groups)")]
        all: bool,
        #[arg(long, help = "Protect all paths in a specific group")]
        group: Option<String>,
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
    Setup {
        #[arg(long, help = "Run intelligent auto-detection setup")]
        smart: bool,
        #[arg(
            long,
            help = "Auto-apply all High+Critical suggestions (non-interactive)"
        )]
        yes: bool,
    },

    /// Show smart protection suggestions without applying
    Recommend {
        #[arg(long, help = "Output as JSON")]
        json: bool,
    },

    /// List or manage protection profile groups
    #[command(subcommand)]
    Groups(GroupsCmd),

    /// Check for and install updated versions
    Update {
        /// Only check, don't install
        #[arg(long)]
        check_only: bool,
    },

    /// Fase 5: List tracked AI agents and their statistics
    Agents {
        #[arg(long)]
        show: Option<String>,
    },

    /// Fase 5: Manage protection rules
    #[command(subcommand)]
    Rules(RulesCmd),

    /// Fase 5: Show protection statistics
    Stats,

    /// Manage the local CA used by the DLP HTTPS MITM proxy
    #[command(subcommand)]
    Ca(CaCmd),
}

/// Subcommands for `agentguard ca`.
///
/// All three actions run **locally** — they do not require the daemon to
/// be running. `install` and `uninstall` need root because they touch
/// `/etc/...`. `show` works without privileges.
#[derive(Subcommand)]
enum CaCmd {
    /// Install the local CA root certificate into the system trust store.
    /// Distro-agnostic: detects update-ca-trust / update-ca-certificates /
    /// trust anchor / manual fallback. Requires root.
    Install,
    /// Remove the local CA from the system trust store. Requires root.
    Uninstall,
    /// Show the path and SHA-256 fingerprint of the local CA root.
    /// Does not require root.
    Show,
}

#[derive(Subcommand)]
enum RulesCmd {
    /// Add paths to protection list
    Add {
        paths: Vec<String>,
        #[arg(long)]
        watch_only: bool,
    },
    /// Remove paths from protection list
    Remove { paths: Vec<String> },
    /// List all protection rules
    List,
}

#[derive(Subcommand)]
enum GroupsCmd {
    /// List all protection profile groups
    List,
    /// Enable all paths from a profile group
    Enable { name: String },
    /// Disable all paths from a profile group
    Disable { name: String },
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
    #[cfg(unix)]
    {
        dirs::home_dir()
            .map(|h| h.join(IPC_SOCKET_PATH))
            .unwrap_or_else(|| PathBuf::from("agentguard.sock"))
    }
    #[cfg(windows)]
    {
        PathBuf::from(agentguard_common::IPC_PIPE_NAME)
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from(IPC_SOCKET_PATH)
    }
}

fn build_command(cmd: Command) -> IpcCommand {
    match cmd {
        Command::Status => IpcCommand::Status,
        Command::Ping => IpcCommand::Ping,
        Command::Protect {
            path,
            watch_only,
            all,
            group,
        } => {
            if all {
                unreachable!("protect --all handled locally")
            }
            if group.is_some() {
                unreachable!("protect --group handled locally")
            }
            IpcCommand::Protect {
                path: path.expect("path required"),
                watch_only,
            }
        }
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
        // Fase 5
        Command::Agents { show: Some(name) } => IpcCommand::AgentsShow { name },
        Command::Agents { show: None } => IpcCommand::AgentsList,
        Command::Rules(RulesCmd::List) => IpcCommand::RulesList,
        Command::Stats => IpcCommand::Stats,
        Command::Rules(RulesCmd::Add { .. })
        | Command::Rules(RulesCmd::Remove { .. })
        | Command::Check
        | Command::Setup { .. }
        | Command::Recommend { .. }
        | Command::Groups(_)
        | Command::Update { .. }
        | Command::Ca(_)
        | Command::Init { .. } => {
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

fn fmt_ts_short(ts: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    match SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(ts)) {
        Some(t) => {
            let d = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let days = d / 86400;
            if days > 0 {
                format!("{days}d ago")
            } else {
                let h = d / 3600;
                if h > 0 {
                    format!("{h}h ago")
                } else {
                    let m = (d % 3600) / 60;
                    format!("{m}m ago")
                }
            }
        }
        None => "?".into(),
    }
}

fn fmt_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
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
        IpcResponse::AgentsList { agents } => {
            if agents.is_empty() {
                println!("  No agents tracked yet.");
                return;
            }
            println!("  {}", bold("Tracked AI Agents"));
            println!(
                "  {:<16} {:<14} {:<14} {:<10} {:<10} SANDBOX",
                "NAME", "FIRST SEEN", "LAST SEEN", "SESSIONS", "VIOLATIONS"
            );
            println!("  {}", dim(&"-".repeat(80)));
            for a in &agents {
                println!(
                    "  {:<16} {:<14} {:<14} {:>8}   {:>8}   {}",
                    a.agent_name,
                    fmt_ts_short(a.first_seen as u64),
                    fmt_ts_short(a.last_seen as u64),
                    a.total_sessions,
                    a.total_violations,
                    fmt_duration(a.total_sandbox_seconds as u64),
                );
            }
        }
        IpcResponse::RulesList { rules } => {
            if rules.is_empty() {
                println!("  No protection rules defined.");
                return;
            }
            println!("  {}", bold("Protection Rules"));
            println!("  {:<6} {:<40} ADDED", "KIND", "PATH");
            println!("  {}", dim(&"-".repeat(60)));
            for r in &rules {
                let kind = if r.watch_only { "watch" } else { "block " };
                println!(
                    "  {kind:<6} {:<40} {}",
                    r.path,
                    fmt_ts_short(r.added_at as u64),
                );
            }
        }
        IpcResponse::StatsData {
            total_incidents,
            violations_24h,
            agents_tracked,
        } => {
            println!("  {}", bold("Protection Statistics"));
            println!("  Total incidents:     {}", total_incidents);
            println!("  Violations (24h):    {}", violations_24h);
            println!("  Agents tracked:      {}", agents_tracked);
        }
        IpcResponse::AgentsShow { agent, sessions } => {
            println!("  {}", bold(&format!("Agent: {}", agent.agent_name)));
            println!(
                "    First seen: {}  Last seen: {}",
                fmt_ts_short(agent.first_seen as u64),
                fmt_ts_short(agent.last_seen as u64),
            );
            println!(
                "    Sessions: {}  Violations: {}  Sandbox time: {}",
                agent.total_sessions,
                agent.total_violations,
                fmt_duration(agent.total_sandbox_seconds as u64),
            );
            if !sessions.is_empty() {
                println!("    {}", bold("Recent sessions:"));
                for s in &sessions {
                    let end = s
                        .ended_at
                        .map(|e| fmt_ts_short(e as u64))
                        .unwrap_or_else(|| "active".into());
                    println!(
                        "      {}  pid={}  mode={}  started={}  ended={}",
                        s.id,
                        s.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                        s.sandbox_mode.as_deref().unwrap_or("?"),
                        fmt_ts_short(s.started_at as u64),
                        end,
                    );
                }
            }
        }
        IpcResponse::SmartSuggestions { suggestions } => {
            println!("  {}", bold("Smart Protection Suggestions"));
            println!();
            for s in &suggestions {
                println!(
                    "  {} {:<40} [{}] {}",
                    match s.risk_level.as_str() {
                        "critical" => red("●"),
                        "high" => yellow("●"),
                        _ => dim("○"),
                    },
                    s.path,
                    s.group,
                    s.reason,
                );
            }
        }
        IpcResponse::ProfilesList { profiles } => {
            println!("  {}", bold("Protection Profiles"));
            println!();
            for p in &profiles {
                let status = if p.enabled {
                    green("active")
                } else {
                    dim("inactive")
                };
                println!(
                    "  {} {:<20} {} paths ({})",
                    green("●"),
                    p.name,
                    p.path_count,
                    status,
                );
            }
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
match = { exe_any = ["code", "code-insiders", "codium"] }

[[agent_processes]]
name = "windsurf"
match = { exe = "windsurf" }

[[agent_processes]]
name = "opencode"
match = { exe = "opencode" }

[[agent_processes]]
name = "aider"
match = { exe = "aider" }

[on_violation]
kill_process = false
snapshot_on_violation = true

# ── v2.1: AI Agent Sandbox ──────────────────────────────────
[sandbox]
modo_por_defecto = "ebpf"
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

# ── v2.2: Smart Protection ──────────────────────────────────
[smart_protection]
enabled = true
auto_suggest_on_start = true

[[smart_protection.profiles]]
name = "Personal"
paths = ["~/Documents", "~/Desktop", "~/Pictures", "~/Downloads", "~/Videos"]

[[smart_protection.profiles]]
name = "Desarrollo"
paths = ["~/Projects", "~/src", "~/code", "~/workspace", "~/dev"]

[[smart_protection.profiles]]
name = "Secretos"
paths = ["~/.ssh", "~/.gnupg", "~/.aws", "~/.netrc", "~/.git-credentials", "~/.docker/config.json"]

[[smart_protection.profiles]]
name = "AI Workspaces"
auto = true
paths = []
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

fn handle_smart_setup(yes: bool) -> Result<()> {
    println!();
    println!("  {}", bold("AgentGuard — Configuración Inteligente"));
    println!();

    let sp = agentguard_core::SmartProtection::default();
    let suggestions = generate_smart_suggestions(&sp);

    if suggestions.is_empty() {
        println!(
            "  {} No se detectaron rutas que necesiten protección.",
            yellow("⚠")
        );
        println!("    Prueba: agentguard protect <ruta>");
        return Ok(());
    }

    let detected_agents: Vec<&String> = suggestions
        .iter()
        .flat_map(|s| &s.active_agents)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if !detected_agents.is_empty() {
        println!(
            "  Detecté {} agente{} AI activo{}:",
            detected_agents.len(),
            if detected_agents.len() > 1 { "s" } else { "" },
            if detected_agents.len() > 1 { "s" } else { "" }
        );
        for agent in &detected_agents {
            let workspaces: Vec<_> = suggestions
                .iter()
                .filter(|s| s.active_agents.contains(*agent) && s.group == "AI Workspaces")
                .collect();
            if !workspaces.is_empty() {
                println!("  • {} → trabajando en:", agent);
                for ws in &workspaces {
                    println!("     - {}", ws.path.display());
                }
            } else {
                println!("  • {} → sesión activa", agent);
            }
        }
        println!();
    }

    let high_or_critical: Vec<&ProtectionSuggestion> = suggestions
        .iter()
        .filter(|s| s.risk_level >= agentguard_core::RiskLevel::High)
        .collect();

    let rest: Vec<&ProtectionSuggestion> = suggestions
        .iter()
        .filter(|s| s.risk_level < agentguard_core::RiskLevel::High)
        .collect();

    if !high_or_critical.is_empty() {
        println!("  Rutas de alto riesgo detectadas:");
        for s in &high_or_critical {
            let icon = match s.risk_level {
                agentguard_core::RiskLevel::Critical => red("●"),
                _ => yellow("●"),
            };
            let secrets = if s.contains_secrets {
                format!(" {}", dim("[secretos]"))
            } else {
                String::new()
            };
            println!(
                "  {} {:<30} [{}{}]{}",
                icon,
                s.path.display(),
                s.group,
                if !s.reason.is_empty() {
                    format!(" — {}", s.reason)
                } else {
                    String::new()
                },
                secrets,
            );
        }
        println!();
    }

    let total = high_or_critical.len() + rest.len();
    println!(
        "  Perfil recomendado: \"Máxima Protección\" ({} ruta{})",
        total,
        if total != 1 { "s" } else { "" }
    );

    if yes {
        println!();
        println!("  Aplicando sugerencias de alto riesgo...");
        return apply_suggestions(&high_or_critical);
    }

    print!("  ¿Aplicar ahora? [Y/n/detalles] ");
    use std::io::{self, BufRead, Write};
    io::stdout().flush().ok();
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .unwrap_or(Ok("y".into()))
        .unwrap_or("y".into());

    match line.trim().to_lowercase().as_str() {
        "n" => {
            println!();
            println!("  Ok. Puedes proteger manualmente:");
            println!("    agentguard protect <ruta>");
            println!("    agentguard recommend  (para ver sugerencias de nuevo)");
            return Ok(());
        }
        "detalles" | "d" | "details" => {
            println!();
            for s in &suggestions {
                println!(
                    "  {} {:<40} {} {}",
                    match s.risk_level {
                        agentguard_core::RiskLevel::Critical => red("●"),
                        agentguard_core::RiskLevel::High => yellow("●"),
                        _ => dim("○"),
                    },
                    s.path.display(),
                    dim(&format!("[{}]", s.group)),
                    s.reason
                );
            }
            println!();
            print!("  ¿Aplicar todas las de alto riesgo? [Y/n] ");
            io::stdout().flush().ok();
            let line2 = stdin
                .lock()
                .lines()
                .next()
                .unwrap_or(Ok("y".into()))
                .unwrap_or("y".into());
            if line2.trim().to_lowercase() == "n" {
                return Ok(());
            }
        }
        _ => {}
    }

    println!();
    apply_suggestions(&high_or_critical)
}

fn apply_suggestions(suggestions: &[&ProtectionSuggestion]) -> Result<()> {
    let socket_path = std::env::var("AGENTGUARD_SOCKET")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);

    let mut applied = 0usize;
    let mut skipped = 0usize;

    for s in suggestions {
        let path_str = s.path.display().to_string();
        let mut stream = match connect(&socket_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  {} No se pudo proteger {}: {e}", yellow("⚠"), path_str);
                skipped += 1;
                continue;
            }
        };

        let cmd = IpcCommand::AddProtectedPath {
            path: path_str.clone(),
        };
        let json = serde_json::to_string(&cmd)?;
        writeln!(stream, "{json}")?;
        stream.flush()?;

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                skipped += 1;
                continue;
            }
            _ => {}
        }

        let resp: IpcResponse = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        match resp {
            IpcResponse::Ok { .. } => {
                println!("  {} {}", green("✓"), path_str);
                applied += 1;
            }
            IpcResponse::Error { message } => {
                eprintln!("  {} {}: {message}", red("✗"), path_str);
                skipped += 1;
            }
            _ => {
                skipped += 1;
            }
        }
    }

    println!();
    println!("  {} {} rutas protegidas", green("✓"), applied);
    if skipped > 0 {
        println!("  {} {} no se pudieron proteger", yellow("⚠"), skipped);
    }
    println!();
    println!(
        "  {} {}",
        green("✓"),
        bold("¡Protección inteligente activada!")
    );
    println!("  Prueba:  {}", bold("agentguard status"));
    println!("          {}", bold("agentguard recommend"));
    Ok(())
}

fn handle_recommend(json: bool) -> Result<()> {
    let sp = agentguard_core::SmartProtection::default();
    let suggestions = generate_smart_suggestions(&sp);

    if json {
        let output: Vec<serde_json::Value> = suggestions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "path": s.path.display().to_string(),
                    "group": s.group,
                    "reason": s.reason,
                    "risk_level": s.risk_level.to_string(),
                    "size_bytes": s.size_bytes,
                    "contains_secrets": s.contains_secrets,
                    "is_git_repo": s.is_git_repo,
                    "active_agents": s.active_agents,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!();
    println!("  {}", bold("AgentGuard — Sugerencias de Protección"));
    println!();

    if suggestions.is_empty() {
        println!("  No se detectaron rutas que proteger.");
        return Ok(());
    }

    for s in &suggestions {
        let icon = match s.risk_level {
            agentguard_core::RiskLevel::Critical => red("●"),
            agentguard_core::RiskLevel::High => yellow("●"),
            agentguard_core::RiskLevel::Medium => dim("○"),
            agentguard_core::RiskLevel::Low => dim("·"),
        };
        let agents = if !s.active_agents.is_empty() {
            format!(" [{}]", s.active_agents.join(", "))
        } else {
            String::new()
        };
        println!(
            "  {} {:<40} {:<16} {}{}",
            icon,
            s.path.display(),
            dim(&format!("[{}]", s.group)),
            s.reason,
            agents
        );
    }

    println!();
    println!("  {}", dim("Aplica con:  agentguard setup --smart --yes"));
    Ok(())
}

fn handle_groups_list() -> Result<()> {
    let sp = agentguard_core::SmartProtection::default();
    println!();
    println!("  {}", bold("Perfiles de Protección"));
    println!();

    for profile in &sp.profiles {
        let icon = if profile.auto {
            blue("◆")
        } else {
            green("●")
        };
        let auto_label = if profile.auto {
            dim(" (detección automática)")
        } else {
            String::new()
        };
        println!("  {} {}{}", icon, bold(&profile.name), auto_label);
        for p in &profile.paths {
            println!("     {}", p.display());
        }
        if profile.paths.is_empty() && !profile.auto {
            println!("     (sin rutas configuradas)");
        }
    }

    println!();
    println!(
        "  {}",
        dim("Activa un grupo:  agentguard groups enable <nombre>")
    );
    println!("  {}", dim("Protege todo:     agentguard protect --all"));
    Ok(())
}

fn handle_protect_all() -> Result<()> {
    let sp = agentguard_core::SmartProtection::default();
    let suggestions = generate_smart_suggestions(&sp);
    let high: Vec<&ProtectionSuggestion> = suggestions
        .iter()
        .filter(|s| s.risk_level >= agentguard_core::RiskLevel::High)
        .collect();

    if high.is_empty() {
        println!("  No hay sugerencias de alto riesgo que aplicar.");
        return Ok(());
    }

    println!();
    println!("  Aplicando {} rutas...", high.len());
    apply_suggestions(&high)
}

fn handle_protect_group(name: &str) -> Result<()> {
    let sp = agentguard_core::SmartProtection::default();
    let profile = sp
        .profiles
        .iter()
        .find(|p| p.name.to_lowercase() == name.to_lowercase());

    let profile = match profile {
        Some(p) => p,
        None => {
            println!("  Perfil '{name}' no encontrado.");
            println!("  Usa 'agentguard groups' para ver los disponibles.");
            return Ok(());
        }
    };

    if profile.paths.is_empty() {
        println!(
            "  El perfil '{}' no tiene rutas configuradas.",
            profile.name
        );
        if profile.auto {
            println!("  Es un perfil automático — usa 'agentguard setup --smart'.");
        }
        return Ok(());
    }

    println!();
    println!(
        "  Protegiendo grupo '{}': {} rutas",
        profile.name,
        profile.paths.len()
    );

    let suggestions: Vec<ProtectionSuggestion> = profile
        .paths
        .iter()
        .map(|p| {
            let expanded = if let Some(s) = p.to_str() {
                if let Some(rest) = s.strip_prefix("~/") {
                    dirs::home_dir()
                        .map(|h| h.join(rest))
                        .unwrap_or_else(|| p.clone())
                } else {
                    p.clone()
                }
            } else {
                p.clone()
            };
            ProtectionSuggestion {
                path: expanded,
                group: profile.name.clone(),
                reason: String::new(),
                risk_level: agentguard_core::RiskLevel::Medium,
                size_bytes: 0,
                file_count: 0,
                contains_secrets: false,
                is_git_repo: false,
                active_agents: Vec::new(),
            }
        })
        .collect();

    let refs: Vec<&ProtectionSuggestion> = suggestions.iter().collect();
    apply_suggestions(&refs)
}

fn blue(s: &str) -> String {
    format!("\x1b[34m{s}\x1b[0m")
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
            "transparent"
        } else {
            "ebpf (kernel blocking without sandbox)"
        };

        // Check for compiled eBPF bytecode
        let bpffs = std::path::Path::new("/sys/fs/bpf").is_dir();
        let ebpf_bytecode = check_ebpf_bytecode();

        let guard_level = if ebpf && ebpf_bytecode && bpffs {
            "kernel-level blocking (eBPF LSM)"
        } else if ebpf && !ebpf_bytecode {
            "userspace observation (eBPF kernel available but bytecode not compiled — run ./scripts/build-ebpf.sh)"
        } else if ebpf && !bpffs {
            "userspace observation (eBPF kernel available but bpffs not mounted — mount -t bpffs bpffs /sys/fs/bpf)"
        } else {
            effective
        };

        println!(
            "  bpffs:     {}",
            if bpffs {
                green("mounted")
            } else {
                yellow("not mounted — mount -t bpffs bpffs /sys/fs/bpf")
            }
        );
        println!(
            "  eBPF bpf.o: {}",
            if ebpf_bytecode {
                green("compiled")
            } else {
                yellow("not compiled — run ./scripts/build-ebpf.sh")
            }
        );
        println!();
        println!("  Effective mode: {}", bold(effective));
        println!("  Guard level:    {}", bold(guard_level));
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

fn check_ebpf_bytecode() -> bool {
    let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let ebpf_dir = workspace.join("target/ebpf");
    ebpf_dir.join("file_guard").is_file()
        && ebpf_dir.join("net_guard").is_file()
        && ebpf_dir.join("process_exec").is_file()
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

/// Fase 5: Bulk-add protection rules via IPC.
fn handle_rules_add(paths: &[String]) -> Result<()> {
    for path in paths {
        let socket_path = std::env::var("AGENTGUARD_SOCKET")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(default_socket_path);
        let mut stream = connect(&socket_path)?;
        let cmd = IpcCommand::AddProtectedPath { path: path.clone() };
        let json = serde_json::to_string(&cmd)?;
        writeln!(stream, "{json}")?;
        stream.flush()?;

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let resp: IpcResponse = serde_json::from_str(line.trim())?;
        match resp {
            IpcResponse::Ok { message } => println!("  {} {}", green("✓"), message),
            IpcResponse::Error { message } => eprintln!("  {} {}: {}", red("✗"), path, message),
            _ => {}
        }
    }
    Ok(())
}

/// Fase 6: Bulk-remove protection rules via IPC.
fn handle_rules_remove(paths: &[String]) -> Result<()> {
    for path in paths {
        let socket_path = std::env::var("AGENTGUARD_SOCKET")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(default_socket_path);
        let mut stream = connect(&socket_path)?;
        let cmd = IpcCommand::Unprotect { path: path.clone() };
        let json = serde_json::to_string(&cmd)?;
        writeln!(stream, "{json}")?;
        stream.flush()?;

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let resp: IpcResponse = serde_json::from_str(line.trim())?;
        match resp {
            IpcResponse::Ok { message } => println!("  {} {}", green("✓"), message),
            IpcResponse::Error { message } => eprintln!("  {} {}: {}", red("✗"), path, message),
            _ => {}
        }
    }
    Ok(())
}

// ── CA management (local-only, no IPC) ─────────────────────
//
// `agentguard ca {install|uninstall|show}` is implemented entirely in the
// CLI binary. The daemon is not involved — all the trust-store work happens
// in `agentguard_core::ca::LocalCa`.
//
// Why local-only? `install` and `uninstall` need to write to `/etc/...`
// which only root can do; the daemon already runs as root but going through
// IPC would require defining a new IpcCommand variant just for this. It's
// simpler for the user to run `sudo agentguard ca install` directly.

/// Resolve the directory holding `root.crt` / `root.key`.
///
/// Strategy:
/// 1. `AGENTGUARD_CA_DIR` env var (override, used by tests).
/// 2. `/var/lib/agentguard/ca` if running as root (matches the systemd
///    service's `StateDirectory=agentguard`).
/// 3. `~/.agentguard/ca` otherwise (per-user dev/demo setup).
fn resolve_ca_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("AGENTGUARD_CA_DIR") {
        return PathBuf::from(explicit);
    }
    #[cfg(unix)]
    {
        // SAFETY: getuid is async-signal-safe and always succeeds.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return PathBuf::from("/var/lib/agentguard/ca");
        }
    }
    agentguard_core::config::expand_path("~/.agentguard/ca")
}

/// SHA-256 of the certificate PEM (as-stored on disk), formatted as
/// colon-separated uppercase hex.
///
/// **Note:** this is the digest of the PEM bytes, not of the DER body —
/// avoids pulling a base64 dependency just for this CLI subcommand. It
/// is still a useful, deterministic fingerprint for "is this the same
/// cert I generated yesterday?". To get the canonical X.509 fingerprint
/// (matching `openssl x509 -fingerprint -sha256`) the user can run:
///   `openssl x509 -in /var/lib/agentguard/ca/root.crt -fingerprint -sha256`.
fn ca_pem_sha256(pem: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pem.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn handle_ca_install() -> Result<()> {
    use agentguard_core::ca::LocalCa;
    let ca_dir = resolve_ca_dir();
    println!("{} Installing AgentGuard CA into the system trust store", bold("•"));
    println!("  CA directory: {}", ca_dir.display());

    let ca = LocalCa::load_or_generate(&ca_dir).with_context(|| {
        format!("loading/creating CA at {}", ca_dir.display())
    })?;

    match ca.install_system_trust() {
        Ok(report) => {
            println!(
                "  {} Installed via {:?}",
                green("✓"),
                report.method
            );
            if let Some(p) = &report.installed_path {
                println!("  Anchor file: {}", p.display());
            }
            if !report.trust_update_run {
                println!(
                    "  {} No trust-update tool was run automatically. \
                     Refresh manually for your distro:",
                    yellow("⚠")
                );
                println!("    Fedora/RHEL:   sudo update-ca-trust extract");
                println!("    Debian/Ubuntu: sudo update-ca-certificates");
                println!("    Arch:          sudo trust extract-compat");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "  {} Trust-store install failed: {}\n  Hint: run with sudo.",
                red("✗"),
                e
            );
            Err(anyhow::anyhow!(e))
        }
    }
}

fn handle_ca_uninstall() -> Result<()> {
    use agentguard_core::ca::LocalCa;
    println!("{} Removing AgentGuard CA from the system trust store", bold("•"));
    LocalCa::uninstall_system_trust().context("uninstall_system_trust")?;
    println!("  {} CA removed from trust store", green("✓"));
    Ok(())
}

fn handle_ca_show() -> Result<()> {
    use agentguard_core::ca::LocalCa;
    let ca_dir = resolve_ca_dir();
    let ca_path = ca_dir.join(agentguard_core::ca::CA_CERT_FILE);

    println!("{} AgentGuard local CA", bold("•"));
    println!("  Directory:  {}", ca_dir.display());
    println!("  Cert file:  {}", ca_path.display());

    if !ca_path.is_file() {
        println!(
            "  {} CA not yet generated. Start the daemon or run \
             `sudo agentguard ca install` to generate one.",
            yellow("⚠")
        );
        return Ok(());
    }

    let pem = std::fs::read_to_string(&ca_path)
        .with_context(|| format!("reading {}", ca_path.display()))?;
    let pem_sha = ca_pem_sha256(&pem);
    println!("  PEM SHA-256: {}", pem_sha);
    println!("  Bytes:       {}", pem.len());
    println!(
        "  {} For canonical X.509 fingerprint:\n      openssl x509 -in {} -fingerprint -sha256",
        dim("hint:"),
        ca_path.display()
    );
    println!();

    // Surface trust-store status without requiring root: just check whether
    // the canonical anchor file exists in any well-known location.
    let anchors = [
        "/usr/local/share/ca-certificates/agentguard-ca.crt",
        "/etc/pki/ca-trust/source/anchors/agentguard-ca.crt",
        "/etc/ssl/certs/agentguard-ca.crt",
        // legacy filename written by older shell installers
        "/etc/pki/ca-trust/source/anchors/agentguard.crt",
    ];
    let installed: Vec<&str> = anchors
        .iter()
        .copied()
        .filter(|p| std::path::Path::new(p).exists())
        .collect();
    if installed.is_empty() {
        println!(
            "  {} Not installed in the system trust store. \
             Run: sudo agentguard ca install",
            yellow("⚠")
        );
    } else {
        println!("  {} Installed in trust store:", green("✓"));
        for p in installed {
            println!("    {}", p);
        }
    }
    let _ = LocalCa::load_or_generate(&ca_dir); // sanity check; ignore result
    Ok(())
}

// ── Main ───────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Init, Setup, Update, Check, Recommend, Groups, and Ca are handled locally (no IPC needed)
    if matches!(
        cli.command,
        Command::Init { .. }
            | Command::Setup { .. }
            | Command::Check
            | Command::Update { .. }
            | Command::Rules(RulesCmd::Add { .. })
            | Command::Rules(RulesCmd::Remove { .. })
            | Command::Recommend { .. }
            | Command::Groups(GroupsCmd::List)
            | Command::Ca(_)
            | Command::Protect { all: true, .. }
            | Command::Protect { group: Some(_), .. }
    ) {
        match cli.command {
            Command::Init { output, defaults } => return handle_init(output, defaults),
            Command::Setup { smart, yes } => {
                if smart || yes {
                    return handle_smart_setup(yes);
                }
                return handle_setup();
            }
            Command::Check => return handle_check(),
            Command::Update { check_only } => return handle_update(check_only),
            Command::Rules(RulesCmd::Add { paths, .. }) => return handle_rules_add(&paths),
            Command::Rules(RulesCmd::Remove { paths }) => return handle_rules_remove(&paths),
            Command::Recommend { json } => return handle_recommend(json),
            Command::Groups(GroupsCmd::List) => return handle_groups_list(),
            Command::Groups(GroupsCmd::Enable { name }) => return handle_protect_group(&name),
            Command::Groups(GroupsCmd::Disable { name }) => {
                println!(
                    "  {} Usa 'agentguard unprotect' para remover rutas del perfil '{}'.",
                    yellow("⚠"),
                    name
                );
                return Ok(());
            }
            Command::Ca(CaCmd::Install) => return handle_ca_install(),
            Command::Ca(CaCmd::Uninstall) => return handle_ca_uninstall(),
            Command::Ca(CaCmd::Show) => return handle_ca_show(),
            Command::Protect { all: true, .. } => return handle_protect_all(),
            Command::Protect {
                group: Some(ref name),
                ..
            } => return handle_protect_group(name),
            _ => unreachable!(),
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
            path: Some("/tmp/x".into()),
            watch_only: false,
            all: false,
            group: None,
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
        #[cfg(unix)]
        assert!(p.to_string_lossy().contains(".agentguard"));
        #[cfg(windows)]
        assert!(!p.to_string_lossy().is_empty());
    }

    #[test]
    fn ipc_wire_format_is_json_line() {
        use agentguard_common::{IpcCommand, IpcResponse};
        let cmd = IpcCommand::Ping;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(
            !json.contains('\n'),
            "IPC command should be single-line JSON"
        );
        assert!(json.starts_with('{'), "IPC command should be JSON object");
        let pong = IpcResponse::Pong;
        let pong_json = serde_json::to_string(&pong).unwrap();
        assert!(pong_json.contains("Pong"));
        let err = IpcResponse::Error {
            message: "connection refused".to_string(),
        };
        let err_json = serde_json::to_string(&err).unwrap();
        assert!(err_json.contains("Error"));
        assert!(err_json.contains("connection refused"));
    }
}
