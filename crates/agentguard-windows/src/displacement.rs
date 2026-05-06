//! Windows binary displacement — same pattern as Linux but for .exe files.
//!
//! (Wired into the installer; dead_code warnings suppressed for daemon-side utilities.)

#![allow(dead_code)]
//!
//! Moves the original AI agent .exe to `.<name>.real.exe` and copies the
//! AgentGuard launcher (agentguard-windows.exe) in its place.
//!
//! When IFEO is not available (no admin), binary displacement ensures the
//! launcher is invoked regardless of how the agent is launched (double-click,
//! terminal, absolute path, etc.).

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SHIM_MAGIC: &[u8] = b"AGENTGUARD_SHIM_V1\x00";
const MAGIC_SCAN_BYTES: usize = 8192;

/// Persistent database of displaced binaries (same format as Linux).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DisplacementDb {
    #[serde(skip)]
    db_path: PathBuf,
    pub entries: Vec<DisplacementEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplacementEntry {
    pub shim_path: PathBuf,
    pub real_path: PathBuf,
    pub agent_name: String,
    pub displaced_at: u64,
    pub shim_hash: String,
}

impl DisplacementDb {
    pub fn load_or_create() -> Self {
        let db_path = default_db_path();
        match std::fs::read_to_string(&db_path) {
            Ok(json) => match serde_json::from_str::<DisplacementDb>(&json) {
                Ok(mut db) => {
                    db.db_path = db_path;
                    db.remove_stale();
                    db
                }
                Err(_) => Self::empty(db_path),
            },
            Err(_) => Self::empty(db_path),
        }
    }

    pub fn empty(db_path: PathBuf) -> Self {
        Self {
            db_path,
            entries: Vec::new(),
        }
    }

    fn remove_stale(&mut self) {
        self.entries
            .retain(|e| e.shim_path.exists() && e.real_path.exists());
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&self.db_path, json)
    }

    pub fn is_displaced(&self, path: &Path) -> bool {
        self.entries.iter().any(|e| e.shim_path == path)
    }

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

    pub fn forget(&mut self, shim_path: &Path) {
        self.entries.retain(|e| e.shim_path != shim_path);
    }

    pub fn watched_directories(&self) -> Vec<PathBuf> {
        let mut dirs = HashSet::new();
        for entry in &self.entries {
            if let Some(parent) = entry.shim_path.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
        dirs.into_iter().collect()
    }

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
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from(r"C:\"))
        .join(".agentguard/displaced.json")
}

/// Check if a file is already an AgentGuard launcher shim.
pub fn is_agentguard_shim(path: &Path) -> bool {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = vec![0u8; MAGIC_SCAN_BYTES];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    buf[..n].windows(SHIM_MAGIC.len()).any(|w| w == SHIM_MAGIC)
}

/// Check if the current user can write a file (Windows: just check existence).
pub fn is_user_writable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

/// Displace a single Windows agent .exe.
pub fn displace(
    agent_binary: &Path,
    launcher_path: &Path,
    db: &mut DisplacementDb,
    agent_name: &str,
) -> Result<(), anyhow::Error> {
    if is_agentguard_shim(agent_binary) {
        anyhow::bail!("{} is already an AgentGuard shim", agent_binary.display());
    }
    if db.is_displaced(agent_binary) {
        anyhow::bail!("{} is already displaced", agent_binary.display());
    }

    let parent = agent_binary
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine parent directory"))?;
    let name = agent_binary
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("cannot determine filename"))?
        .to_string_lossy();
    let real_path = parent.join(format!(".{}.real.exe", name));

    // Move original to .real.exe
    std::fs::rename(agent_binary, &real_path)?;

    // Copy launcher to original path
    if let Err(e) = std::fs::copy(launcher_path, agent_binary) {
        let _ = std::fs::rename(&real_path, agent_binary);
        return Err(anyhow::anyhow!("copy launcher: {}", e));
    }

    // SHA256 hash for integrity
    let shim_hash = compute_hash(launcher_path)?;

    db.record(
        agent_binary.to_path_buf(),
        real_path,
        agent_name.to_string(),
        shim_hash,
    );
    db.save()?;

    Ok(())
}

/// Restore a displaced binary.
pub fn restore(shim_path: &Path, db: &mut DisplacementDb) -> Result<(), anyhow::Error> {
    let entry = db
        .entries
        .iter()
        .find(|e| e.shim_path == shim_path)
        .ok_or_else(|| anyhow::anyhow!("{} is not displaced", shim_path.display()))?;

    if shim_path.exists() {
        std::fs::remove_file(shim_path)?;
    }
    if entry.real_path.exists() {
        std::fs::rename(&entry.real_path, shim_path)?;
    }
    db.forget(shim_path);
    db.save()?;
    Ok(())
}

fn compute_hash(path: &Path) -> Result<String, anyhow::Error> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
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

/// Known agent executables to look for.
pub const KNOWN_WIN_AGENTS: &[&str] = &[
    "claude.exe",
    "claude-code.exe",
    "cursor.exe",
    "windsurf.exe",
    "aider.exe",
    "opencode.exe",
    "code.exe",
    "codium.exe",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_shim_detects_magic() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.exe");
        let mut data = vec![0u8; 4096];
        data[64..64 + SHIM_MAGIC.len()].copy_from_slice(SHIM_MAGIC);
        std::fs::write(&path, data).unwrap();
        assert!(is_agentguard_shim(&path));
    }

    #[test]
    fn test_is_shim_rejects_normal_exe() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.exe");
        std::fs::write(&path, b"MZ\x90\x00").unwrap();
        assert!(!is_agentguard_shim(&path));
    }

    #[test]
    fn test_db_record_and_lookup() {
        let shim = PathBuf::from(r"C:\Users\test\claude.exe");
        let real = PathBuf::from(r"C:\Users\test\.claude.real.exe");
        let mut db = DisplacementDb::empty(PathBuf::from("test.json"));
        db.record(shim.clone(), real.clone(), "claude".into(), "hash".into());
        assert!(db.is_displaced(&shim));
        assert!(!db.is_displaced(&PathBuf::from("other.exe")));
    }

    #[test]
    fn test_db_forget() {
        let shim = PathBuf::from(r"C:\test.exe");
        let real = PathBuf::from(r"C:\.test.real.exe");
        let mut db = DisplacementDb::empty(PathBuf::from("test.json"));
        db.record(shim.clone(), real, "test".into(), "hash".into());
        db.forget(&shim);
        assert!(!db.is_displaced(&shim));
    }
}
