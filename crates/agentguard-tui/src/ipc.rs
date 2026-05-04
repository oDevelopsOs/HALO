//! Cliente IPC para comunicarse con el daemon AgentGuard.
//!
//! Usa el mismo protocolo JSON-line que la CLI.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use agentguard_common::{IpcCommand, IpcResponse, SnapshotInfo};
use anyhow::Context;

pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    fn connect(&self) -> Result<std::os::unix::net::UnixStream, anyhow::Error> {
        std::os::unix::net::UnixStream::connect(&self.socket_path)
            .with_context(|| {
                format!(
                    "cannot connect to daemon at {}. Is agentguard running?",
                    self.socket_path.display()
                )
            })
    }

    pub fn send(&self, cmd: IpcCommand) -> Result<IpcResponse, anyhow::Error> {
        let mut stream = self.connect()?;
        let json = serde_json::to_string(&cmd)?;
        writeln!(stream, "{json}")?;
        stream.flush()?;

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        serde_json::from_str(line.trim())
            .with_context(|| format!("invalid response: {line}"))
    }

    // ── Convenience methods ──────────────────────────────────────────────

    pub fn status(&self) -> Result<IpcResponse, anyhow::Error> {
        self.send(IpcCommand::Status)
    }

    pub fn incidents(&self, last: usize) -> Result<Vec<String>, anyhow::Error> {
        match self.send(IpcCommand::Incidents {
            last: Some(last),
        })? {
            IpcResponse::Incidents { lines } => Ok(lines),
            IpcResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            other => anyhow::bail!("unexpected response: {other:?}"),
        }
    }

    pub fn snapshots(&self) -> Result<Vec<SnapshotInfo>, anyhow::Error> {
        match self.send(IpcCommand::SnapshotList)? {
            IpcResponse::SnapshotList { snapshots } => Ok(snapshots),
            IpcResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            other => anyhow::bail!("unexpected response: {other:?}"),
        }
    }

    pub fn protect_path(&self, path: &str) -> Result<(), anyhow::Error> {
        match self.send(IpcCommand::AddProtectedPath {
            path: path.to_string(),
        })? {
            IpcResponse::Ok { .. } => Ok(()),
            IpcResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => Ok(()),
        }
    }

    pub fn pause(&self, minutes: u64) -> Result<(), anyhow::Error> {
        match self.send(IpcCommand::Pause { minutes })? {
            IpcResponse::Ok { .. } => Ok(()),
            IpcResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => Ok(()),
        }
    }

    pub fn resume(&self) -> Result<(), anyhow::Error> {
        match self.send(IpcCommand::Resume)? {
            IpcResponse::Ok { .. } => Ok(()),
            IpcResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => Ok(()),
        }
    }

    pub fn create_snapshot(&self, label: &str) -> Result<(), anyhow::Error> {
        match self.send(IpcCommand::SnapshotCreate {
            label: label.to_string(),
        })? {
            IpcResponse::Ok { .. } => Ok(()),
            IpcResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => Ok(()),
        }
    }

    pub fn restore_snapshot(&self, id: &str) -> Result<(), anyhow::Error> {
        match self.send(IpcCommand::SnapshotRestore {
            id: id.to_string(),
            yes: true,
        })? {
            IpcResponse::Ok { .. } => Ok(()),
            IpcResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => Ok(()),
        }
    }
}

pub fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".agentguard").join("agentguard.sock"))
        .unwrap_or_else(|| PathBuf::from("agentguard.sock"))
}
