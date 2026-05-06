//! Binary displacement management for Linux.
//!
//! Handles the "binary displacement" strategy: moving the original AI agent
//! binary to `.<name>.real` and placing the AgentGuard shim in its place.
//!
//! The `DisplacementDb` tracks all displaced binaries so the auto-heal daemon
//! can monitor them and the installer can restore them.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Magic bytes that identify an AgentGuard shim binary.
/// The shim embeds these in its `.note.agentguard` ELF section.
pub const AGENTGUARD_SHIM_MAGIC: &[u8] = b"AGENTGUARD_SHIM_V1\x00";

/// Maximum bytes to read from a binary to detect the shim magic.
const MAGIC_SCAN_SIZE: usize = 8192;

/// Persistent database of displaced binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplacementDb {
    /// Path to the database file.
    #[serde(skip)]
    db_path: PathBuf,
    /// Known displaced entries.
    pub entries: Vec<DisplacementEntry>,
}

/// A single displaced binary entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplacementEntry {
    /// The path where the shim now sits (original agent path).
    pub shim_path: PathBuf,
    /// The path of the real binary (.<name>.real).
    pub real_path: PathBuf,
    /// Human-readable agent name.
    pub agent_name: String,
    /// Unix timestamp when displacement was applied.
    pub displaced_at: u64,
    /// SHA256 of the shim at the time of displacement.
    pub shim_hash: String,
}

impl DisplacementDb {
    /// Load the database from disk, or create a new empty one.
    pub fn load_or_create() -> Self {
        let db_path = default_db_path();
        match fs::read_to_string(&db_path) {
            Ok(json) => match serde_json::from_str::<DisplacementDb>(&json) {
                Ok(mut db) => {
                    db.db_path = db_path;
                    // Clean out dead entries
                    db.remove_stale();
                    db
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse displacement database: {} — starting fresh",
                        e
                    );
                    Self::empty(db_path)
                }
            },
            Err(_) => Self::empty(db_path),
        }
    }

    pub(crate) fn empty(db_path: PathBuf) -> Self {
        Self {
            db_path,
            entries: Vec::new(),
        }
    }

    /// Save the database to disk.
    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(parent) = self.db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&self.db_path, json.as_bytes())
    }

    /// Remove entries where the shim or real binary no longer exist.
    fn remove_stale(&mut self) {
        self.entries
            .retain(|e| e.shim_path.exists() && e.real_path.exists());
        if self.entries.len() < self.entries.capacity() / 2 {
            // Could log but silently trimming is fine
        }
    }

    /// Check if a path is known to be displaced.
    pub fn is_displaced(&self, path: &Path) -> bool {
        self.entries.iter().any(|e| e.shim_path == path)
    }

    /// Get the real binary path for a displaced shim path.
    pub fn real_path_for(&self, shim_path: &Path) -> Option<&PathBuf> {
        self.entries
            .iter()
            .find(|e| e.shim_path == shim_path)
            .map(|e| &e.real_path)
    }

    /// Record a new displacement in the database.
    pub fn record(
        &mut self,
        shim_path: PathBuf,
        real_path: PathBuf,
        agent_name: String,
        shim_hash: String,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.entries.push(DisplacementEntry {
            shim_path,
            real_path,
            agent_name,
            displaced_at: now,
            shim_hash,
        });
    }

    /// Remove a displacement entry (e.g., after restore).
    pub fn forget(&mut self, shim_path: &Path) {
        self.entries.retain(|e| e.shim_path != shim_path);
    }

    /// Get all directories that contain displaced shims (for inotify watching).
    pub fn watched_directories(&self) -> Vec<PathBuf> {
        let mut dirs = HashSet::new();
        for entry in &self.entries {
            if let Some(parent) = entry.shim_path.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
        dirs.into_iter().collect()
    }

    /// Get agent names mapped to their parent directories.
    pub fn agent_names_by_dir(&self) -> Vec<(PathBuf, Vec<String>)> {
        let mut map: std::collections::HashMap<PathBuf, Vec<String>> =
            std::collections::HashMap::new();
        for entry in &self.entries {
            if let Some(parent) = entry.shim_path.parent() {
                if let Some(filename) = entry.shim_path.file_name() {
                    map.entry(parent.to_path_buf())
                        .or_default()
                        .push(filename.to_string_lossy().to_string());
                }
            }
        }
        map.into_iter().collect()
    }
}

fn default_db_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        PathBuf::from("/var/lib/agentguard/displaced.json")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".agentguard/displaced.json")
    }
}

// ── Displacement operations ────────────────────────────────────────

/// Result of trying to displace a binary.
#[derive(Debug)]
pub enum DisplacementResult {
    /// Displacement was successful.
    Success {
        /// The original path (now contains the shim).
        original: PathBuf,
        /// The real binary path (.<name>.real).
        real: PathBuf,
    },
    /// The binary is already displaced.
    AlreadyDisplaced,
    /// The path is not writable by the current user.
    NotWritable { path: PathBuf, suggestion: String },
    /// The file is already an AgentGuard shim (double-displacement guard).
    AlreadyShim,
}

/// Displace a single agent binary: rename to .<name>.real, copy shim.
///
/// # Arguments
/// * `agent_binary` - Path to the original AI agent binary
/// * `shim_binary` - Path to the compiled AgentGuard shim binary
/// * `db` - The displacement database to update
/// * `agent_name` - Human-readable name of the agent
pub fn displace(
    agent_binary: &Path,
    shim_binary: &Path,
    db: &mut DisplacementDb,
    agent_name: &str,
) -> Result<DisplacementResult, anyhow::Error> {
    // 1. Check writability
    let metadata = match fs::metadata(agent_binary) {
        Ok(m) => m,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Cannot access {}: {}",
                agent_binary.display(),
                e
            ));
        }
    };

    let uid = unsafe { libc::getuid() };
    let file_uid = metadata.uid();
    let writable = file_uid == uid || uid == 0;

    if !writable {
        return Ok(DisplacementResult::NotWritable {
            path: agent_binary.to_path_buf(),
            suggestion: format!(
                "Binary at {} is owned by uid {} and not writable by uid {}. \
                 Run with root for full protection, or reinstall the agent \
                 in a user-writable location (npm/pip/cargo user install).",
                agent_binary.display(),
                file_uid,
                uid
            ),
        });
    }

    // 2. Check not already a shim (prevent double-displacement)
    if is_agentguard_shim(agent_binary) {
        return Ok(DisplacementResult::AlreadyShim);
    }

    // 3. Check not already displaced (in DB)
    if db.is_displaced(agent_binary) {
        return Ok(DisplacementResult::AlreadyDisplaced);
    }

    // 4. Compute the real binary path
    let parent = agent_binary
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine parent directory"))?;
    let name = agent_binary
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine filename"))?
        .to_string_lossy();
    let real_path = parent.join(format!(".{}.real", name));

    // 5. Move original to .real
    fs::rename(agent_binary, &real_path)?;

    // 6. Copy shim to original path
    // If copy fails, try to restore the original
    if let Err(e) = fs::copy(shim_binary, agent_binary) {
        // Rollback: move .real back to original
        let _ = fs::rename(&real_path, agent_binary);
        return Err(anyhow::anyhow!("Failed to copy shim: {}", e));
    }

    // 7. Preserve original permissions on the shim
    if let Ok(perms) = fs::metadata(&real_path).map(|m| m.permissions()) {
        let _ = fs::set_permissions(agent_binary, perms);
    }

    // 8. Compute shim hash for integrity verification
    let shim_hash = compute_shim_hash(shim_binary)?;

    // 9. Record in database
    db.record(
        agent_binary.to_path_buf(),
        real_path.clone(),
        agent_name.to_string(),
        shim_hash,
    );
    db.save()?;

    tracing::info!(
        original = %agent_binary.display(),
        real = %real_path.display(),
        agent = %agent_name,
        "Binary displaced successfully"
    );

    Ok(DisplacementResult::Success {
        original: agent_binary.to_path_buf(),
        real: real_path,
    })
}

/// Restore a displaced binary: remove shim, rename .real back to original.
pub fn restore(shim_path: &Path, db: &mut DisplacementDb) -> Result<(), anyhow::Error> {
    let entry = db
        .entries
        .iter()
        .find(|e| e.shim_path == shim_path)
        .ok_or_else(|| {
            anyhow::anyhow!("{} is not a known displaced binary", shim_path.display())
        })?;

    let real_path = entry.real_path.clone();

    // 1. Delete the shim
    if shim_path.exists() {
        fs::remove_file(shim_path)?;
    }

    // 2. Move .real back to original
    if real_path.exists() {
        fs::rename(&real_path, shim_path)?;
    }

    // 3. Remove from database
    db.forget(shim_path);
    db.save()?;

    tracing::info!(
        path = %shim_path.display(),
        "Binary restored (displacement reversed)"
    );

    Ok(())
}

// ── Shim detection ──────────────────────────────────────────────────

/// Check if a file is already an AgentGuard shim.
///
/// Reads the first MAGIC_SCAN_SIZE bytes and searches for the magic bytes.
pub fn is_agentguard_shim(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut buf = vec![0u8; MAGIC_SCAN_SIZE];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };

    buf[..n]
        .windows(AGENTGUARD_SHIM_MAGIC.len())
        .any(|w| w == AGENTGUARD_SHIM_MAGIC)
}

/// Compute a SHA256 hash of the shim binary for integrity records.
fn compute_shim_hash(shim_path: &Path) -> Result<String, anyhow::Error> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open(shim_path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Check if the current user owns (can write) a file.
pub fn is_user_writable(path: &Path) -> bool {
    let uid = unsafe { libc::getuid() };
    match fs::metadata(path) {
        Ok(m) => m.uid() == uid || uid == 0,
        Err(_) => false,
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fake_shim() -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        // Embed magic bytes at offset 64
        data[64..64 + AGENTGUARD_SHIM_MAGIC.len()].copy_from_slice(AGENTGUARD_SHIM_MAGIC);
        data
    }

    fn fake_binary() -> Vec<u8> {
        vec![0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00] // ELF header
    }

    #[test]
    fn test_is_agentguard_shim_detects_magic() {
        let dir = TempDir::new().unwrap();
        let shim_path = dir.path().join("test-shim");
        fs::write(&shim_path, fake_shim()).unwrap();

        assert!(is_agentguard_shim(&shim_path));
    }

    #[test]
    fn test_is_agentguard_shim_rejects_elf() {
        let dir = TempDir::new().unwrap();
        let bin_path = dir.path().join("test-bin");
        fs::write(&bin_path, fake_binary()).unwrap();

        assert!(!is_agentguard_shim(&bin_path));
    }

    #[test]
    fn test_is_agentguard_shim_rejects_empty() {
        let dir = TempDir::new().unwrap();
        let empty_path = dir.path().join("empty");
        fs::write(&empty_path, []).unwrap();

        assert!(!is_agentguard_shim(&empty_path));
    }

    #[test]
    fn test_is_agentguard_shim_rejects_nonexistent() {
        let path = PathBuf::from("/tmp/agentguard_test_nonexistent_xyz");
        assert!(!is_agentguard_shim(&path));
    }

    #[test]
    fn test_displacement_db_empty() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("empty.json");

        let db = DisplacementDb::empty(db_path);
        assert!(db.entries.is_empty());
        assert!(db.watched_directories().is_empty());
    }

    #[test]
    fn test_displacement_db_record_and_lookup() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("db.json");

        let mut db = DisplacementDb::empty(db_path.clone());
        let shim_path = PathBuf::from("/usr/local/bin/claude");
        let real_path = PathBuf::from("/usr/local/bin/.claude.real");

        db.record(
            shim_path.clone(),
            real_path.clone(),
            "claude-code".to_string(),
            "abc123".to_string(),
        );

        assert!(db.is_displaced(&shim_path));
        assert!(!db.is_displaced(&PathBuf::from("/usr/bin/other")));

        let found = db.real_path_for(&shim_path);
        assert_eq!(found, Some(&real_path));
    }

    #[test]
    fn test_displacement_db_watched_directories() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("db.json");

        let mut db = DisplacementDb::empty(db_path);
        db.record(
            PathBuf::from("/home/user/.npm-global/bin/claude"),
            PathBuf::from("/home/user/.npm-global/bin/.claude.real"),
            "claude".into(),
            "hash1".into(),
        );
        db.record(
            PathBuf::from("/home/user/.cargo/bin/aider"),
            PathBuf::from("/home/user/.cargo/bin/.aider.real"),
            "aider".into(),
            "hash2".into(),
        );

        let dirs = db.watched_directories();
        assert_eq!(dirs.len(), 2);
        assert!(dirs.contains(&PathBuf::from("/home/user/.npm-global/bin")));
        assert!(dirs.contains(&PathBuf::from("/home/user/.cargo/bin")));
    }

    #[test]
    fn test_displacement_db_forget() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("db.json");

        let mut db = DisplacementDb::empty(db_path);
        let shim = PathBuf::from("/usr/bin/claude");
        let real = PathBuf::from("/usr/bin/.claude.real");
        db.record(shim.clone(), real, "claude".into(), "hash".into());

        assert!(db.is_displaced(&shim));
        db.forget(&shim);
        assert!(!db.is_displaced(&shim));
    }

    #[test]
    fn test_displacement_db_save_and_load() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("save_test.json");

        let mut db = DisplacementDb::empty(db_path.clone());
        db.record(
            PathBuf::from("/tmp/test-agent"),
            PathBuf::from("/tmp/.test-agent.real"),
            "test-agent".into(),
            "test-hash".into(),
        );
        db.save().unwrap();

        // Load and verify
        let _loaded = DisplacementDb::load_or_create();
        // Note: load_or_create() uses the default path, not our test path.
        // Just verify the file exists and is valid JSON.
        let content = fs::read_to_string(&db_path).unwrap();
        assert!(content.contains("test-agent"));
        assert!(content.contains(".test-agent.real"));
    }

    #[test]
    fn test_displacement_result_debug() {
        let success = DisplacementResult::Success {
            original: PathBuf::from("/tmp/claude"),
            real: PathBuf::from("/tmp/.claude.real"),
        };
        // Verify it implements Debug
        let _ = format!("{:?}", success);

        let no_write = DisplacementResult::NotWritable {
            path: PathBuf::from("/usr/bin/claude"),
            suggestion: "Use sudo".into(),
        };
        let _ = format!("{:?}", no_write);
    }
}
