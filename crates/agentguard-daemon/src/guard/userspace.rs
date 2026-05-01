//! Backend userspace basado en `notify` (inotify/FSEvent/ReadDirectoryChangesW).
//!
//! **Limitación importante:** este backend solo **observa** — los eventos
//! llegan *después* de que la syscall se haya completado. No puede impedir
//! un `unlink`. Su valor reside en:
//!
//! 1. Funcionar en cualquier kernel (sin BPF LSM).
//! 2. Disparar el *restore* del vault inmediatamente tras una violación.
//! 3. Permitir desarrollo y tests sin necesidad de VM con BPF.
//!
//! Cuando el daemon corre con este backend, el log de arranque deja claro
//! que la protección es "observation-only" (ver `select_guard`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use notify::event::{ModifyKind, RemoveKind};
use notify::{recommended_watcher, Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use super::{GuardError, KernelGuard, ProtectionLevel};
use crate::events::{SecurityEvent, ViolationKind};

/// Guard que usa `notify` para observar rutas protegidas.
pub struct UserspaceGuard {
    /// Rutas canonicalizadas a observar. Usamos `HashSet` para dedup.
    paths: HashSet<PathBuf>,
}

impl UserspaceGuard {
    /// Crea un guard con un conjunto inicial de rutas.
    pub fn new(paths: &[PathBuf]) -> Result<Self, GuardError> {
        let mut canonical = HashSet::new();
        for p in paths {
            match canonicalize(p) {
                Ok(c) => {
                    canonical.insert(c);
                }
                Err(e) => {
                    tracing::warn!(path = ?p, error = %e, "skipping protected path");
                }
            }
        }
        Ok(Self { paths: canonical })
    }

    /// Vista de las rutas activas (para tests y diagnóstico).
    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.paths.iter()
    }
}

#[async_trait]
impl KernelGuard for UserspaceGuard {
    fn backend_name(&self) -> &'static str {
        "userspace-notify"
    }

    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::UserspaceObservation
    }

    async fn add_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        let c = canonicalize(path)?;
        self.paths.insert(c);
        Ok(())
    }

    async fn remove_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        let c = canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        self.paths.remove(&c);
        Ok(())
    }

    async fn run(
        self: Box<Self>,
        out_tx: mpsc::Sender<SecurityEvent>,
    ) -> Result<(), GuardError> {
        // Canal notify→tokio. `notify` corre en su propio hilo y no es
        // async-aware, así que usamos un `std::sync::mpsc` y lo puenteamos.
        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

        let mut watcher = recommended_watcher(move |res| {
            // `send` puede fallar si el receptor se cerró — lo ignoramos.
            let _ = notify_tx.send(res);
        })
        .map_err(|e| GuardError::Internal(format!("watcher init: {e}")))?;

        for path in &self.paths {
            match watcher.watch(path, RecursiveMode::Recursive) {
                Ok(()) => tracing::info!(path = ?path, "watching (userspace)"),
                Err(e) => tracing::warn!(path = ?path, error = %e, "cannot watch path"),
            }
        }

        // Procesado en un hilo bloqueante para no bloquear el runtime.
        let handle = tokio::task::spawn_blocking(move || {
            while let Ok(res) = notify_rx.recv() {
                match res {
                    Ok(event) => {
                        for ev in translate(event) {
                            // Best-effort: si el receptor tokio está cerrado,
                            // salimos del loop.
                            if out_tx.blocking_send(ev).is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "notify watcher error");
                    }
                }
            }
        });

        handle
            .await
            .map_err(|e| GuardError::Internal(format!("blocking task join: {e}")))?;

        // watcher se dropea aquí; deja de observar.
        drop(watcher);
        Ok(())
    }
}

/// Convierte un evento de `notify` en cero-o-más `SecurityEvent`.
///
/// Solo nos interesan: delete, rename (modify name), y create/modify en
/// archivos dentro de zonas protegidas (esto último porque el write
/// detection es parte del contrato).
fn translate(ev: Event) -> Vec<SecurityEvent> {
    let kind = match ev.kind {
        EventKind::Remove(RemoveKind::File) | EventKind::Remove(RemoveKind::Folder) => {
            ViolationKind::DeleteAttempt
        }
        EventKind::Modify(ModifyKind::Name(_)) => ViolationKind::RenameAttempt,
        EventKind::Modify(ModifyKind::Data(_)) => ViolationKind::WriteAttempt,
        EventKind::Create(_) => ViolationKind::CreateAttempt,
        _ => return Vec::new(),
    };

    ev.paths
        .into_iter()
        .map(|path| SecurityEvent::FileViolation {
            path,
            // `notify` no nos da el proceso — esto es una limitación
            // conocida del fallback. En el backend eBPF sí lo sabremos.
            process: "<unknown>".to_string(),
            pid: 0,
            violation: kind,
            timestamp: current_timestamp(),
        })
        .collect()
}

fn canonicalize(p: &Path) -> Result<PathBuf, GuardError> {
    std::fs::canonicalize(p).map_err(|source| GuardError::Io {
        path: p.to_path_buf(),
        source,
    })
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn detects_file_deletion() {
        let tmp = TempDir::new().expect("tempdir");
        let zone = tmp.path().to_path_buf();
        let file = zone.join("target.txt");
        std::fs::write(&file, b"bye").expect("write");

        let guard = Box::new(UserspaceGuard::new(&[zone.clone()]).expect("guard"));
        assert_eq!(guard.protection_level(), ProtectionLevel::UserspaceObservation);

        let (tx, mut rx) = mpsc::channel(32);
        let handle = tokio::spawn(guard.run(tx));

        // Dar tiempo a que el watcher se instale
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::remove_file(&file).expect("remove");

        // Esperar el evento
        let ev = timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timeout waiting for event")
            .expect("channel closed");

        match ev {
            SecurityEvent::FileViolation {
                path, violation, ..
            } => {
                assert!(path.ends_with("target.txt"));
                // notify puede reportar Remove o ModifyName según plataforma
                assert!(matches!(
                    violation,
                    ViolationKind::DeleteAttempt
                        | ViolationKind::RenameAttempt
                        | ViolationKind::WriteAttempt
                ));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // Cerrar el canal para que el guard termine limpiamente
        drop(rx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn add_and_remove_are_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        let p = tmp.path().to_path_buf();
        let mut guard = UserspaceGuard::new(&[]).expect("guard");

        guard.add_protected_path(&p).await.expect("add");
        guard.add_protected_path(&p).await.expect("add again");
        assert_eq!(guard.paths().count(), 1);

        guard.remove_protected_path(&p).await.expect("remove");
        guard.remove_protected_path(&p).await.expect("remove again");
        assert_eq!(guard.paths().count(), 0);
    }

    #[tokio::test]
    async fn ignores_nonexistent_paths_at_construction() {
        let guard =
            UserspaceGuard::new(&[PathBuf::from("/definitely/does/not/exist")]).expect("guard");
        // No debe fallar: solo emite warning. El set queda vacío.
        assert_eq!(guard.paths().count(), 0);
    }
}
