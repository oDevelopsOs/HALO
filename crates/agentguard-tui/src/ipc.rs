//! Cliente IPC para comunicarse con el daemon AgentGuard.
//!
//! Usa el mismo protocolo JSON-line que la CLI.
//! Unix sockets en Linux.

#![allow(dead_code)]

use std::path::PathBuf;

#[cfg(unix)]
use anyhow::Context;
#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};

use agentguard_common::{IpcCommand, IpcResponse, SnapshotInfo};

pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    #[cfg(not(unix))]
    pub fn send(&self, _cmd: IpcCommand) -> Result<IpcResponse, anyhow::Error> {
        anyhow::bail!("IPC not available on this platform");
    }

    #[cfg(unix)]
    pub fn send(&self, cmd: IpcCommand) -> Result<IpcResponse, anyhow::Error> {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "cannot connect to daemon at {}. Is agentguard running?",
                self.socket_path.display()
            )
        })?;
        let json = serde_json::to_string(&cmd)?;
        writeln!(stream, "{json}")?;
        stream.flush()?;

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        serde_json::from_str(line.trim()).with_context(|| format!("invalid response: {line}"))
    }

    // ── Convenience methods ──────────────────────────────────────────────

    pub fn status(&self) -> Result<IpcResponse, anyhow::Error> {
        self.send(IpcCommand::Status)
    }

    pub fn incidents(&self, last: usize) -> Result<Vec<String>, anyhow::Error> {
        match self.send(IpcCommand::Incidents { last: Some(last) })? {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_has_socket_path() {
        let client = IpcClient::new(PathBuf::from("/tmp/test.sock"));
        assert_eq!(
            client.socket_path,
            PathBuf::from("/tmp/test.sock")
        );
    }

    #[test]
    fn default_socket_path_ends_with_agentguard_sock() {
        let p = default_socket_path();
        assert!(p.ends_with("agentguard.sock"), "got: {p:?}");
    }

    #[test]
    fn status_command_serializes() {
        let cmd = IpcCommand::Status;
        let json = serde_json::to_string(&cmd).expect("serialize");
        let parsed: IpcCommand = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(parsed, IpcCommand::Status));
    }

    #[test]
    fn pause_command_roundtrips() {
        let cmd = IpcCommand::Pause { minutes: 30 };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let parsed: IpcCommand = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            IpcCommand::Pause { minutes } => assert_eq!(minutes, 30),
            other => panic!("expected Pause, got {other:?}"),
        }
    }

    #[test]
    fn protect_command_roundtrips() {
        let cmd = IpcCommand::AddProtectedPath {
            path: "/tmp/test".into(),
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let parsed: IpcCommand = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            IpcCommand::AddProtectedPath { path } => assert_eq!(path, "/tmp/test"),
            other => panic!("expected AddProtectedPath, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_create_roundtrips() {
        let cmd = IpcCommand::SnapshotCreate {
            label: "test-label".into(),
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let parsed: IpcCommand = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            IpcCommand::SnapshotCreate { label } => assert_eq!(label, "test-label"),
            other => panic!("expected SnapshotCreate, got {other:?}"),
        }
    }

    #[test]
    fn response_status_data_deserializes() {
        let json = r#"{"status":"Ok","data":{"message":"ok"}}"#;
        let resp: IpcResponse = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(resp, IpcResponse::Ok { .. }));
    }

    #[test]
    fn response_error_deserializes() {
        let json = r#"{"status":"Error","data":{"message":"something broke"}}"#;
        let resp: IpcResponse = serde_json::from_str(json).expect("deserialize");
        match resp {
            IpcResponse::Error { message } => assert_eq!(message, "something broke"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn response_incidents_deserializes() {
        let json = r#"{"status":"Incidents","data":{"lines":["line1","line2"]}}"#;
        let resp: IpcResponse = serde_json::from_str(json).expect("deserialize");
        match resp {
            IpcResponse::Incidents { lines } => assert_eq!(lines.len(), 2),
            other => panic!("expected Incidents, got {other:?}"),
        }
    }

    #[test]
    fn response_snapshot_list_deserializes() {
        let json = r#"{"status":"SnapshotList","data":{"snapshots":[]}}"#;
        let resp: IpcResponse = serde_json::from_str(json).expect("deserialize");
        match resp {
            IpcResponse::SnapshotList { snapshots } => assert_eq!(snapshots.len(), 0),
            other => panic!("expected SnapshotList, got {other:?}"),
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_send_returns_error() {
        let client = IpcClient::new(PathBuf::from("any.sock"));
        let result = client.send(IpcCommand::Ping);
        assert!(result.is_err());
    }
}
