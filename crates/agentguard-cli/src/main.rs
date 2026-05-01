//! AgentGuard CLI — wrapper del socket IPC del daemon.
//!
//! Scaffold de Fase 0: solo parsea el subcomando y lo imprime. Cada
//! comando se irá conectando al daemon en Fase 3.1 (ver plan).

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentguard",
    version = env!("CARGO_PKG_VERSION"),
    about = "Protect your filesystem and secrets from AI agents gone rogue"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show current protection status.
    Status,
    /// Protect a directory or file.
    Protect {
        path: String,
        #[arg(long)]
        watch_only: bool,
    },
    /// Remove protection from a path.
    Unprotect { path: String },
    /// Snapshot management.
    Snapshot {
        #[command(subcommand)]
        action: SnapshotCmd,
    },
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // TODO (Fase 3.1): conectar al socket IPC y enviar el comando real.
    match cli.command {
        Command::Status => println!("(stub) status: daemon no conectado aún"),
        Command::Protect { path, watch_only } => {
            println!("(stub) protect path={path} watch_only={watch_only}");
        }
        Command::Unprotect { path } => println!("(stub) unprotect {path}"),
        Command::Snapshot { action } => match action {
            SnapshotCmd::Create { label } => println!("(stub) snapshot create label={label}"),
            SnapshotCmd::List => println!("(stub) snapshot list"),
            SnapshotCmd::Restore { id, yes } => println!("(stub) snapshot restore {id} yes={yes}"),
            SnapshotCmd::Cleanup { keep_days } => {
                println!("(stub) snapshot cleanup keep_days={keep_days}");
            }
        },
        Command::Incidents { last } => println!("(stub) incidents last={last}"),
        Command::Pause { minutes } => println!("(stub) pause minutes={minutes}"),
        Command::Resume => println!("(stub) resume"),
    }

    Ok(())
}
