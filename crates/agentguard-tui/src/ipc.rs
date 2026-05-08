//! Cliente IPC para comunicarse con el daemon AgentGuard.
//!
//! Protocolo JSON-line. Unix sockets + request/response + event stream.
//!
//! Fase 6: conexión de eventos lazy. No se abre hasta que el primer status()
//! confirma que el daemon está vivo. Así evitamos deadlock con el IpcServer.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use anyhow::Context;
#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};

use agentguard_common::{AgentInfo, IpcCommand, IpcEvent, IpcResponse, SnapshotInfo};

pub struct IpcClient {
    socket_path: PathBuf,
    event_tx: std_mpsc::Sender<IpcEvent>,
    event_rx: std_mpsc::Receiver<IpcEvent>,
    connected: Arc<AtomicBool>,
    events_started: Arc<AtomicBool>,
}

impl IpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        let (event_tx, event_rx) = std_mpsc::channel::<IpcEvent>();
        Self {
            socket_path,
            event_tx,
            event_rx,
            connected: Arc::new(AtomicBool::new(false)),
            events_started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Lanza el hilo de eventos push (Subscribe) — llamado una sola vez
    /// después de confirmar que el daemon responde.
    pub fn start_event_stream(&self) {
        if self.events_started.swap(true, Ordering::SeqCst) {
            return; // already started
        }

        let conn_flag = self.connected.clone();
        let event_tx = self.event_tx.clone();
        let path = self.socket_path.clone();

        #[cfg(unix)]
        {
            std::thread::spawn(move || {
                let mut backoff = Duration::from_secs(2);
                loop {
                    match connect_and_subscribe_unix(&path) {
                        Ok(stream) => {
                            conn_flag.store(true, Ordering::SeqCst);
                            backoff = Duration::from_secs(2);
                            read_event_stream(stream, &event_tx);
                            conn_flag.store(false, Ordering::SeqCst);
                            event_tx
                                .send(IpcEvent::Disconnected {
                                    reason: "connection lost".into(),
                                })
                                .ok();
                        }
                        Err(e) => {
                            conn_flag.store(false, Ordering::SeqCst);
                            event_tx
                                .send(IpcEvent::Disconnected {
                                    reason: format!("{e}"),
                                })
                                .ok();
                        }
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            });
        }

        #[cfg(not(unix))]
        {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(1));
                let _ = event_tx.send(IpcEvent::Disconnected {
                    reason: "IPC not available on this platform".into(),
                });
            });
        }
    }

    /// Non-blocking: returns any pending push events.
    pub fn try_recv_events(&self) -> Vec<IpcEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }
        events
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
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

    pub fn agents(&self) -> Result<Vec<AgentInfo>, anyhow::Error> {
        match self.send(IpcCommand::AgentsList)? {
            IpcResponse::AgentsList { agents } => Ok(agents),
            IpcResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            other => anyhow::bail!("unexpected response: {other:?}"),
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

// ── Event stream helpers (Unix) ─────────────────────────────────────────

#[cfg(unix)]
fn connect_and_subscribe_unix(
    path: &PathBuf,
) -> Result<std::os::unix::net::UnixStream, anyhow::Error> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(path).with_context(|| {
        format!(
            "cannot connect to daemon at {}. Is agentguard running?",
            path.display()
        )
    })?;
    let cmd = IpcCommand::Subscribe { events: vec![] };
    let json = serde_json::to_string(&cmd)?;
    writeln!(stream, "{json}")?;
    stream.flush()?;
    Ok(stream)
}

#[cfg(unix)]
fn read_event_stream(
    mut stream: std::os::unix::net::UnixStream,
    event_tx: &std_mpsc::Sender<IpcEvent>,
) {
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if let Ok(event) = serde_json::from_str::<IpcEvent>(line.trim()) {
                    if event_tx.send(event).is_err() {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    let _ = event_tx.send(IpcEvent::Disconnected {
        reason: "daemon socket closed".into(),
    });
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
        assert!(client.socket_path.to_string_lossy().contains("test.sock"));
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
    fn subscribe_command_serializes() {
        let cmd = IpcCommand::Subscribe { events: vec![] };
        let json = serde_json::to_string(&cmd).expect("serialize");
        assert!(json.contains("Subscribe"));
    }

    #[test]
    fn events_not_started_by_default() {
        let client = IpcClient::new(PathBuf::from("/tmp/test.sock"));
        assert!(!client.events_started.load(Ordering::SeqCst));
    }

    #[test]
    fn start_event_stream_sets_flag() {
        let client = IpcClient::new(PathBuf::from("/tmp/test.sock"));
        client.start_event_stream();
        assert!(client.events_started.load(Ordering::SeqCst));
    }

    #[test]
    fn start_event_stream_is_idempotent() {
        let client = IpcClient::new(PathBuf::from("/tmp/test.sock"));
        client.start_event_stream();
        client.start_event_stream();
        // shouldn't panic or double-spawn
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_send_returns_error() {
        let client = IpcClient::new(PathBuf::from("any.sock"));
        let result = client.send(IpcCommand::Ping);
        assert!(result.is_err());
    }
}
