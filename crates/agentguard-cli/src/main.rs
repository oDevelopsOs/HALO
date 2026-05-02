//! AgentGuard CLI — comunitator de comandos vía socket IPC del daemon.
//!
//! Conecta al socket Unix `~/.agentguard/agentguard.sock` (o
//! `/var/run/agentguard.sock` como root), envía un comando serializado
//! como JSON-line, y muestra la respuesta formateada.

#[cfg(unix)]
mod transport {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    pub type Stream = UnixStream;

    pub fn connect(path: &Path) -> std::io::Result<UnixStream> {
        UnixStream::connect(path)
    }
}

#[cfg(not(unix))]
mod transport {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::path::Path;

    pub type Stream = TcpStream;

    pub fn connect(path: &Path) -> std::io::Result<TcpStream> {
        TcpStream::connect(path)
    }
}

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use agentguard_common::{
    IpcCommand, IpcResponse, SnapshotInfo, IPC_SOCKET_PATH, IPC_PROTOCOL_VERSION,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use transport::connect;

#[derive(Parser)]
#[command(
    name = "agentguard",
    version = env!("CARGO_PKG_VERSION"),
    about = "Protect your filesystem and secrets from AI agents gone rogue"
)]
struct Cli {
    /// Path al socket IPC del daemon. Por defecto: ~/.agentguard/agentguard.sock
    #[arg(short, long)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show current protection status.
    Status,
    /// Protect a path.
    Protect {
        path: String,
        #[arg(long)]
        watch_only: bool,
    },
    /// Remove protection from a path.
    Unprotect { path: String },
    /// Snapshot management.
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// Show recent security incidents.
    Incidents {
        #[arg(short, long, default_value_t = 20)]
        last: usize,
    },
    /// Pause protection temporarily.
    Pause {
        #[arg(short, long, default_value_t = 30)]
        minutes: u64,
    },
    /// Resume protection after a pause.
    Resume,
    /// Check if daemon is running.
    Ping,
}

#[derive(Subcommand)]
enum SnapshotCmd {
    Create {
        #[arg(short, long, default_value = "manual")]
        label: String,
    },
    List,
    Restore {
        id: String,
        #[arg(long)]
        yes: bool,
    },
    Cleanup {
        #[arg(long, default_value_t = 30)]
        keep_days: u64,
    },
}

fn default_socket_path() -> PathBuf {
    // Per-user socket: ~/.agentguard/agentguard.sock
    // Si se ejecuta como root, el socket está en /var/run/agentguard.sock.
    // Pero normalmente el CLI se ejecuta como el mismo usuario que el daemon.
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
        Command::Snapshot(SnapshotCmd::Create { label }) => {
            IpcCommand::SnapshotCreate { label }
        }
        Command::Snapshot(SnapshotCmd::List) => IpcCommand::SnapshotList,
        Command::Snapshot(SnapshotCmd::Restore { id, yes }) => {
            IpcCommand::SnapshotRestore { id, yes }
        }
        Command::Snapshot(SnapshotCmd::Cleanup { keep_days }) => {
            IpcCommand::SnapshotCleanup { keep_days }
        }
        Command::Incidents { last } => IpcCommand::Incidents { last },
        Command::Pause { minutes } => IpcCommand::Pause { minutes },
        Command::Resume => IpcCommand::Resume,
    }
}

fn format_response(response: IpcResponse) {
    match response {
        IpcResponse::Ok { message } => {
            println!("\u{2705} {message}");
        }
        IpcResponse::Error { message } => {
            eprintln!("\u{274C} {message}");
            std::process::exit(1);
        }
        IpcResponse::Pong => {
            println!("\u{2705} daemon is running (protocol v{IPC_PROTOCOL_VERSION})");
        }
        IpcResponse::StatusData {
            version,
            guard_backend,
            protection_level,
            dlp_enabled,
            protected_dirs,
            protected_files,
        } => {
            println!("AgentGuard {version}");
            println!("  Guard:      {guard_backend} ({protection_level})");
            println!("  DLP:        {dlp_enabled}");
            println!("  Dirs:       {}", protected_dirs.join(", "));
            if !protected_files.is_empty() {
                println!("  Files:      {}", protected_files.join(", "));
            }
        }
        IpcResponse::SnapshotList { snapshots } => {
            if snapshots.is_empty() {
                println!("No snapshots.");
                return;
            }
            for s in &snapshots {
                let ts = chrono(s.timestamp);
                println!(
                    "  {id}  {ts}  {label:12}  {files:4} files  {size:>8} bytes",
                    id = s.id,
                    ts = ts,
                    label = s.label,
                    files = s.files,
                    size = s.total_size,
                );
            }
        }
        IpcResponse::Incidents { lines } => {
            for line in lines {
                println!("{line}");
            }
        }
    }
}

fn chrono(ts: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    match SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(ts)) {
        Some(t) => {
            let dt = t.duration_since(UNIX_EPOCH).unwrap_or_default();
            let secs = dt.as_secs();
            let days = secs / 86400;
            let hours = (secs % 86400) / 3600;
            let mins = (secs % 3600) / 60;
            format!("{days:3}d {hours:02}:{mins:02}")
        }
        None => "unknown".into(),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let socket_path = cli.socket.unwrap_or_else(default_socket_path);

    let mut stream = connect(&socket_path)
        .with_context(|| format!("connect to daemon at {socket_path:?}. Is agentguard-daemon running?"))?;

    let cmd = build_command(cli.command);
    let json = serde_json::to_string(&cmd)?;
    writeln!(stream, "{json}")?;
    stream.flush()?;

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let response: IpcResponse = serde_json::from_str(line.trim())
        .with_context(|| format!("invalid response from daemon: {line}"))?;

    format_response(response);
    Ok(())
}
