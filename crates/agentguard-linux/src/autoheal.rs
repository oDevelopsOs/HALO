//! inotify-based auto-heal daemon for binary displacement.
//!
//! When an AI agent binary is displaced (original moved to `.<name>.real`,
//! AgentGuard shim placed as `name`), package managers like npm, pip, or
//! cargo may overwrite the shim when updating the agent. The auto-heal
//! daemon watches the directories containing displaced binaries and
//! automatically restores the shim.
//!
//! ## Workflow:
//!
//! 1. Watch directories from DisplacementDb for file events
//! 2. When a known agent file is created/modified:
//!    a. Check if it's already an AgentGuard shim (magic bytes)
//!    b. If not: move new file to `.<name>.real`, copy shim to `name`
//!    c. Log the auto-heal event
//! 3. Reaction time: <50ms (inotify is synchronous with the VFS)

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::displacement::{is_agentguard_shim, DisplacementDb};

use notify::Watcher;

/// Auto-heal watcher that monitors agent binary directories.
pub struct AutoHealWatcher {
    /// Path to the compiled AgentGuard shim binary.
    shim_binary: PathBuf,
    /// Reference to the displacement database.
    db: Arc<RwLock<DisplacementDb>>,
    /// Map of watched directory paths to their agent filenames.
    watched: HashMap<PathBuf, Vec<String>>,
    /// Debounce: minimum time between healing the same file.
    last_healed: HashMap<PathBuf, std::time::Instant>,
}

impl AutoHealWatcher {
    /// Min time between heals for the same file (prevents loops).
    const HEAL_COOLDOWN: Duration = Duration::from_secs(2);

    /// Create a new auto-heal watcher.
    ///
    /// # Arguments
    /// * `shim_binary` - Path to the compiled AgentGuard shim binary.
    /// * `db` - The displacement database (shared).
    pub fn new(shim_binary: PathBuf, db: Arc<RwLock<DisplacementDb>>) -> Self {
        Self {
            shim_binary,
            db,
            watched: HashMap::new(),
            last_healed: HashMap::new(),
        }
    }

    /// Populate watched directories from the displacement database.
    pub async fn refresh_watches(&mut self) {
        let db = self.db.read().await;
        let by_dir = db.agent_names_by_dir();
        self.watched = by_dir.into_iter().collect();
        tracing::info!(
            dirs = self.watched.len(),
            "Auto-heal: watching directories for shim restoration"
        );
    }

    /// Check if a path is a known agent that should be protected.
    fn is_known_agent(&self, path: &Path) -> bool {
        let parent = match path.parent() {
            Some(p) => p,
            None => return false,
        };
        let filename = match path.file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => return false,
        };

        self.watched
            .get(parent)
            .map(|agents| agents.iter().any(|a| a == &filename))
            .unwrap_or(false)
    }

    /// Try to heal a file: if it's not a shim, displace it.
    async fn try_heal(&mut self, path: &Path) {
        // Check cooldown
        let now = std::time::Instant::now();
        if let Some(last) = self.last_healed.get(path) {
            if now.duration_since(*last) < Self::HEAL_COOLDOWN {
                return;
            }
        }

        // Skip if already a shim
        if is_agentguard_shim(path) {
            return;
        }

        // Skip if the file doesn't exist (may have been deleted)
        if !path.exists() {
            return;
        }

        // Compute the real binary path
        let parent = match path.parent() {
            Some(p) => p,
            None => return,
        };
        let name = match path.file_name() {
            Some(n) => n.to_string_lossy(),
            None => return,
        };
        let real_path = parent.join(format!(".{}.real", name));

        tracing::info!(
            path = %path.display(),
            real = %real_path.display(),
            "Auto-heal: agent binary modified — restoring shim"
        );

        // Move the new binary to .real (may be an updated version)
        if let Err(e) = tokio::fs::rename(path, &real_path).await {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Auto-heal: failed to move updated binary to .real"
            );
            return;
        }

        // Copy the shim to the original path
        if let Err(e) = tokio::fs::copy(&self.shim_binary, path).await {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "Auto-heal: failed to copy shim — attempting rollback"
            );
            // Rollback: move .real back
            let _ = tokio::fs::rename(&real_path, path).await;
            return;
        }

        // Restore permissions from the .real binary
        if let Ok(meta) = tokio::fs::metadata(&real_path).await {
            let _ = tokio::fs::set_permissions(path, meta.permissions()).await;
        }

        // Update the displacement database entry
        {
            let mut db = self.db.write().await;
            if let Some(entry) = db.entries.iter_mut().find(|e| e.real_path == real_path) {
                // The real path changed (new version), update the reference
                // and compute new shim hash
                if let Ok(shim_hash) = compute_shim_hash(&self.shim_binary).await {
                    entry.shim_hash = shim_hash;
                }
            }
            let _ = db.save();
        }

        self.last_healed.insert(path.to_path_buf(), now);

        tracing::info!(
            path = %path.display(),
            "Auto-heal: shim restored successfully"
        );
    }

    /// Start the auto-heal event loop.
    ///
    /// Runs indefinitely, watching directories for file modifications.
    /// Should be spawned as a tokio task.
    pub async fn run(mut self) -> Result<(), anyhow::Error> {
        // Refresh watches on start
        self.refresh_watches().await;

        if self.watched.is_empty() {
            tracing::info!("Auto-heal: no displaced binaries to watch");
            // Wait for database changes (poll periodically)
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                self.refresh_watches().await;
                if !self.watched.is_empty() {
                    break;
                }
            }
        }

        // Use std::sync::mpsc for the watcher callback (called from a non-tokio thread)
        let (event_tx, event_rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let _ = event_tx.send(res);
        })
        .map_err(|e| anyhow::anyhow!("Failed to create file watcher: {}", e))?;

        // Watch all directories from the displacement database
        for dir in self.watched.keys() {
            match watcher.watch(dir, notify::RecursiveMode::NonRecursive) {
                Ok(()) => tracing::info!(dir = %dir.display(), "Auto-heal: watching"),
                Err(e) => {
                    tracing::warn!(dir = %dir.display(), error = %e, "Auto-heal: cannot watch")
                }
            }
        }

        tracing::info!("Auto-heal watcher started");

        // Bridge std::sync::mpsc → tokio::sync::mpsc via spawn_blocking
        let (tokio_tx, mut tokio_rx) = tokio::sync::mpsc::channel::<notify::Event>(256);

        tokio::task::spawn_blocking(move || {
            while let Ok(res) = event_rx.recv() {
                match res {
                    Ok(event) => {
                        if tokio_tx.blocking_send(event).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "File watcher error");
                    }
                }
            }
        });

        // Main event loop using tokio channel
        loop {
            tokio::select! {
                Some(event) = tokio_rx.recv() => {
                    for path in &event.paths {
                        let should_heal = matches!(
                            event.kind,
                            notify::EventKind::Create(_)
                                | notify::EventKind::Modify(notify::event::ModifyKind::Data(_))
                                | notify::EventKind::Modify(notify::event::ModifyKind::Any)
                        );

                        if should_heal && self.is_known_agent(path) {
                            self.try_heal(path).await;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    // Periodically refresh watches (in case of DB changes)
                    self.refresh_watches().await;
                }
                else => break,
            }
        }

        Ok(())
    }
}

/// Compute a SHA256 hash of the shim binary (async, using spawn_blocking).
async fn compute_shim_hash(shim_path: &Path) -> Result<String, anyhow::Error> {
    let path = shim_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use sha2::{Digest, Sha256};
        let mut file = fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok::<_, anyhow::Error>(format!("{:x}", hasher.finalize()))
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_autoheal_creates_empty_watches() {
        let _db_path = std::env::temp_dir().join("agentguard_test_autoheal_empty.json");
        let db = Arc::new(RwLock::new(DisplacementDb::load_or_create()));
        let watcher = AutoHealWatcher::new(PathBuf::from("/usr/bin/agentguard-shim"), db);
        assert!(watcher.watched.is_empty());
    }

    #[tokio::test]
    async fn test_is_known_agent() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("db.json");

        let mut db = DisplacementDb::empty(db_path);
        db.record(
            dir.path().join("claude"),
            dir.path().join(".claude.real"),
            "claude-code".into(),
            "hash".into(),
        );

        let mut watcher = AutoHealWatcher::new(
            PathBuf::from("/usr/bin/agentguard-shim"),
            Arc::new(RwLock::new(db)),
        );
        watcher.refresh_watches().await;

        assert!(watcher.is_known_agent(&dir.path().join("claude")));
        assert!(!watcher.is_known_agent(&dir.path().join("unknown")));
    }

    #[test]
    fn test_shim_hash_computation() {
        // Test that hash computation works (requires tokio runtime)
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(compute_shim_hash(Path::new("/bin/ls")));
        // ls should exist and be readable
        if Path::new("/bin/ls").exists() {
            assert!(result.is_ok());
            let hash = result.unwrap();
            assert_eq!(hash.len(), 64); // SHA256 hex is 64 chars
        }
    }
}
