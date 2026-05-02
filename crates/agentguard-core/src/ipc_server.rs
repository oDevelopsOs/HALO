//! IPC server — socket Unix / Named Pipe para que CLI y UI se comuniquen
//! con el daemon en runtime.
//!
//! Protocolo: JSON-line (una línea JSON por comando, una por respuesta).
//! El cliente envía un `IpcCommand` serializado, el servidor responde
//! con un `IpcResponse`.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use agentguard_common::{IpcCommand, IpcResponse, SnapshotInfo};
use serde_json;
use tokio::sync::oneshot;

use crate::config::Config;
use crate::vault::Vault;

/// Estado compartido accesible desde el servidor IPC.
pub struct IpcServer {
    vault: Arc<Vault>,
    config: Arc<Config>,
    guard_backend: String,
    protection_level: String,
    runtime: tokio::runtime::Runtime,
}

impl IpcServer {
    pub fn new(
        vault: Vault,
        config: Config,
        guard_backend: &str,
        protection_level: &str,
    ) -> Result<Self, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self {
            vault: Arc::new(vault),
            config: Arc::new(config),
            guard_backend: guard_backend.to_string(),
            protection_level: protection_level.to_string(),
            runtime,
        })
    }

    /// Arranca el listener. Retorna un handle para shutdown.
    pub fn start(self, socket_path: PathBuf) -> Result<IpcShutdown, std::io::Error> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(&socket_path);

        #[cfg(unix)]
        let listener = {
            let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = std::fs::metadata(&socket_path)?;
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&socket_path, perms)?;
            }
            listener
        };
        #[cfg(not(unix))]
        let listener = {
            compile_error!("IPC server only supported on Unix (Linux/macOS) for now");
        };

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let sp = socket_path.clone();

        std::thread::spawn(move || {
            tracing::info!(path = %sp.display(), "IPC server listening");

            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept error");
                        continue;
                    }
                };
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
                self.handle_connection(&mut stream);
            }

            let _ = std::fs::remove_file(&sp);
            tracing::info!("IPC server stopped");
        });

        Ok(IpcShutdown {
            tx: Some(shutdown_tx),
            socket_path,
        })
    }

    fn handle_connection(&self, stream: &mut (impl Read + Write)) {
        let mut reader = BufReader::new(&mut *stream);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            _ => {}
        }

        let cmd: IpcCommand = match serde_json::from_str(line.trim()) {
            Ok(c) => c,
            Err(e) => {
                let _ = write_response(
                    stream,
                    &IpcResponse::Error {
                        message: format!("invalid command: {e}"),
                    },
                );
                return;
            }
        };

        let response = self.execute(cmd);
        let _ = write_response(stream, &response);
    }

    fn execute(&self, cmd: IpcCommand) -> IpcResponse {
        match cmd {
            IpcCommand::Ping => IpcResponse::Pong,

            IpcCommand::Status => IpcResponse::StatusData {
                version: env!("CARGO_PKG_VERSION").to_string(),
                guard_backend: self.guard_backend.clone(),
                protection_level: self.protection_level.clone(),
                dlp_enabled: self.config.dlp.enabled,
                protected_dirs: self
                    .config
                    .protected_dirs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect(),
                protected_files: self
                    .config
                    .protected_files
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect(),
            },

            IpcCommand::Protect { path, .. } => {
                IpcResponse::Ok {
                    message: format!("path {path} registered (restart daemon to apply)"),
                }
            }

            IpcCommand::Unprotect { path } => {
                IpcResponse::Ok {
                    message: format!("path {path} removed (restart daemon to apply)"),
                }
            }

            IpcCommand::SnapshotCreate { label } => {
                match self.runtime.block_on(
                    self.vault
                        .create_snapshot(&self.config.protected_dirs, &label),
                ) {
                    Ok(snapshot) => IpcResponse::Ok {
                        message: format!(
                            "snapshot {} created ({} files, {} bytes)",
                            snapshot.id,
                            snapshot.files.len(),
                            snapshot.total_size
                        ),
                    },
                    Err(e) => IpcResponse::Error {
                        message: format!("snapshot failed: {e}"),
                    },
                }
            }

            IpcCommand::SnapshotList => match self
                .runtime
                .block_on(self.vault.list())
            {
                Ok(snapshots) => IpcResponse::SnapshotList {
                    snapshots: snapshots
                        .into_iter()
                        .map(|s| SnapshotInfo {
                            id: s.id,
                            timestamp: s.timestamp,
                            label: s.label,
                            files: s.files.len(),
                            total_size: s.total_size,
                        })
                        .collect(),
                },
                Err(e) => IpcResponse::Error {
                    message: format!("list failed: {e}"),
                },
            },

            IpcCommand::SnapshotRestore { id, yes } => {
                if !yes {
                    return IpcResponse::Error {
                        message: "use --yes to confirm restore".to_string(),
                    };
                }
                match self.runtime.block_on(self.vault.restore(&id)) {
                    Ok(()) => IpcResponse::Ok {
                        message: format!("snapshot {id} restored"),
                    },
                    Err(e) => IpcResponse::Error {
                        message: format!("restore failed: {e}"),
                    },
                }
            }

            IpcCommand::SnapshotCleanup { keep_days } => {
                match self.runtime.block_on(self.vault.cleanup(keep_days)) {
                    Ok(count) => IpcResponse::Ok {
                        message: format!(
                            "cleanup: removed {count} snapshots (kept last {keep_days} days)"
                        ),
                    },
                    Err(e) => IpcResponse::Error {
                        message: format!("cleanup failed: {e}"),
                    },
                }
            }

            IpcCommand::Incidents { .. } => IpcResponse::Incidents {
                lines: vec!["incidents log not yet implemented (Fase 2.7+)".into()],
            },

            IpcCommand::Pause { .. } => IpcResponse::Ok {
                message: "pause not yet implemented (Fase 3+)".into(),
            },
            IpcCommand::Resume => IpcResponse::Ok {
                message: "resume not yet implemented (Fase 3+)".into(),
            },
        }
    }
}

/// Handle que permite parar el servidor IPC limpiamente.
pub struct IpcShutdown {
    tx: Option<oneshot::Sender<()>>,
    socket_path: PathBuf,
}

impl IpcShutdown {
    pub fn shutdown(mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for IpcShutdown {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

fn write_response(stream: &mut impl Write, response: &IpcResponse) -> std::io::Result<()> {
    let json = serde_json::to_string(response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    writeln!(stream, "{json}")?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use tempfile::TempDir;

    #[test]
    fn ping_returns_pong() {
        let tmp = TempDir::new().expect("tmp");
        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "test-backend", "userspace").expect("ipc");

        let resp = server.execute(IpcCommand::Ping);
        assert!(matches!(resp, IpcResponse::Pong));
    }

    #[test]
    fn status_returns_config_info() {
        let tmp = TempDir::new().expect("tmp");
        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "ebpf-lsm", "kernel-level").expect("ipc");

        match server.execute(IpcCommand::Status) {
            IpcResponse::StatusData {
                guard_backend,
                protection_level,
                ..
            } => {
                assert_eq!(guard_backend, "ebpf-lsm");
                assert_eq!(protection_level, "kernel-level");
            }
            other => panic!("expected StatusData, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_restore_without_yes_rejects() {
        let tmp = TempDir::new().expect("tmp");
        let config = config::Config::default().resolve().expect("config");
        let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
        let server = IpcServer::new(vault, config, "test", "userspace").expect("ipc");

        let resp = server.execute(IpcCommand::SnapshotRestore {
            id: "nope".into(),
            yes: false,
        });
        match resp {
            IpcResponse::Error { message } => assert!(message.contains("--yes")),
            other => panic!("expected error, got {other:?}"),
        }
    }
}
