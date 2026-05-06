//! Local SQLite database — Fase 5.
//!
//! Replaces flat-file storage (incidents.jsonl, manifest.json per snapshot)
//! with a single ACID-compliant SQLite database.
//!
//! ## Schema (8 tables):
//!
//! - `incidents`       — indexed security events (replaces incidents.jsonl)
//! - `agent_sessions`  — per-agent session tracking (start/end/violations)
//! - `agent_stats`     — aggregated per-agent statistics
//! - `rules`           — protection rules (paths, kind, watch_only)
//! - `config_history`  — audit trail of config changes
//! - `snapshot_index`  — fast snapshot listing without reading manifests
//! - `displacements`   — binary displacement registry
//! - `ota_version`     — OTA profile version tracking
//!
//! ## Migrations:
//!
//! Schema version is stored in `PRAGMA user_version`.
//! On first run, all tables are created. On version bump, migrations run.
//!
//! ## File location:
//!
//! - Linux root:   `/var/lib/agentguard/data/agentguard.db` (0600)
//! - Linux user:   `~/.agentguard/data/agentguard.db`       (0600)
//! - Windows:      `%PROGRAMDATA%\AgentGuard\data\agentguard.db`

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection};

// ── Database handle ────────────────────────────────────────────────

/// Thread-safe database handle.
pub struct Database {
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

impl Database {
    /// Open (or create) the database at the default path for this platform.
    pub fn open_default() -> Result<Self, DbError> {
        let path = default_db_path();
        Self::open(&path)
    }

    /// Open (or create) the database at the given path.
    /// Creates parent directories with 0700 permissions.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        // Run migrations
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        run_migrations(&conn, version)?;

        // Set restrictive file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        tracing::info!(
            path = %path.display(),
            schema_version = version + 1,
            "database opened"
        );

        Ok(Self {
            conn: Mutex::new(conn),
            db_path: path.to_path_buf(),
        })
    }

    /// Execute a closure with the database connection.
    pub fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, DbError>,
    ) -> Result<T, DbError> {
        let conn = self.conn.lock().map_err(|_| DbError::LockPoisoned)?;
        f(&conn)
    }

    /// Path to the database file.
    pub fn path(&self) -> &Path {
        &self.db_path
    }
}

// ── Schema & Migrations ───────────────────────────────────────────

const LATEST_SCHEMA_VERSION: i64 = 1;

fn run_migrations(conn: &Connection, current_version: i64) -> Result<(), DbError> {
    if current_version < 1 {
        create_initial_schema(conn)?;
    }
    // Future: if current_version < 2 { migrate_v1_to_v2(conn)?; }
    conn.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION)?;
    Ok(())
}

fn create_initial_schema(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "
        -- Security events (replaces incidents.jsonl)
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            kind        TEXT    NOT NULL,
            agent_name  TEXT,
            agent_pid   INTEGER,
            path        TEXT,
            violation   TEXT,
            process     TEXT,
            details     TEXT,
            session_id  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_ts    ON incidents(timestamp);
        CREATE INDEX IF NOT EXISTS idx_incidents_agent ON incidents(agent_name);
        CREATE INDEX IF NOT EXISTS idx_incidents_kind  ON incidents(kind);

        -- Agent sessions
        CREATE TABLE IF NOT EXISTS agent_sessions (
            id              TEXT PRIMARY KEY,
            agent_name      TEXT NOT NULL,
            pid             INTEGER,
            cwd             TEXT,
            sandbox_mode    TEXT DEFAULT 'monitor',
            started_at      INTEGER NOT NULL,
            ended_at        INTEGER,
            total_seconds   INTEGER,
            violation_count INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_agent  ON agent_sessions(agent_name);
        CREATE INDEX IF NOT EXISTS idx_sessions_active ON agent_sessions(ended_at) WHERE ended_at IS NULL;

        -- Aggregated agent statistics
        CREATE TABLE IF NOT EXISTS agent_stats (
            agent_name           TEXT PRIMARY KEY,
            first_seen           INTEGER,
            last_seen            INTEGER,
            total_sessions       INTEGER DEFAULT 0,
            total_violations     INTEGER DEFAULT 0,
            total_sandbox_seconds INTEGER DEFAULT 0
        );

        -- Protection rules (paths + kind)
        CREATE TABLE IF NOT EXISTS rules (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            path       TEXT NOT NULL UNIQUE,
            kind       TEXT NOT NULL,
            added_at   INTEGER NOT NULL,
            watch_only INTEGER DEFAULT 0
        );

        -- Config change history
        CREATE TABLE IF NOT EXISTS config_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            changed_at INTEGER NOT NULL,
            config_json TEXT NOT NULL
        );

        -- Snapshot metadata index
        CREATE TABLE IF NOT EXISTS snapshot_index (
            id               TEXT PRIMARY KEY,
            label            TEXT,
            created_at       INTEGER NOT NULL,
            file_count       INTEGER DEFAULT 0,
            total_bytes      INTEGER DEFAULT 0,
            compressed_bytes INTEGER DEFAULT 0
        );

        -- Binary displacement registry
        CREATE TABLE IF NOT EXISTS displacements (
            shim_path    TEXT PRIMARY KEY,
            real_path    TEXT NOT NULL,
            agent_name   TEXT,
            displaced_at INTEGER,
            shim_hash    TEXT
        );

        -- OTA profile version
        CREATE TABLE IF NOT EXISTS ota_version (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        ",
    )?;

    tracing::info!("database schema v1 created");
    Ok(())
}

// ── Public API: Incidents ─────────────────────────────────────────

impl Database {
    /// Insert a security event.
    pub fn insert_incident(&self, event: &IncidentRecord) -> Result<i64, DbError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO incidents (timestamp, kind, agent_name, agent_pid, path, violation, process, details, session_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    event.timestamp,
                    event.kind,
                    event.agent_name,
                    event.agent_pid,
                    event.path,
                    event.violation,
                    event.process,
                    event.details,
                    event.session_id,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Query incidents with optional filters.
    pub fn query_incidents(&self, filter: &IncidentFilter) -> Result<Vec<IncidentRecord>, DbError> {
        self.with_conn(|conn| {
            let mut sql = String::from(
                "SELECT id, timestamp, kind, agent_name, agent_pid, path, violation, process, details, session_id
                 FROM incidents WHERE 1=1"
            );
            let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(ref kind) = filter.kind {
                sql.push_str(" AND kind = ?");
                params_vec.push(Box::new(kind.clone()));
            }
            if let Some(ref agent) = filter.agent_name {
                sql.push_str(" AND agent_name = ?");
                params_vec.push(Box::new(agent.clone()));
            }
            if let Some(ts_from) = filter.from_timestamp {
                sql.push_str(" AND timestamp >= ?");
                params_vec.push(Box::new(ts_from));
            }
            if let Some(ts_to) = filter.to_timestamp {
                sql.push_str(" AND timestamp <= ?");
                params_vec.push(Box::new(ts_to));
            }
            sql.push_str(" ORDER BY timestamp DESC");
            if let Some(limit) = filter.limit {
                sql.push_str(&format!(" LIMIT {}", limit));
            }

            let param_refs: Vec<&dyn rusqlite::types::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(param_refs.as_slice(), |row| {
                Ok(IncidentRecord {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    kind: row.get(2)?,
                    agent_name: row.get(3)?,
                    agent_pid: row.get(4)?,
                    path: row.get(5)?,
                    violation: row.get(6)?,
                    process: row.get(7)?,
                    details: row.get(8)?,
                    session_id: row.get(9)?,
                })
            })?;

            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
    }

    /// Get incident count (optionally filtered by last N seconds).
    pub fn count_incidents_since(&self, seconds: u64) -> Result<u64, DbError> {
        self.with_conn(|conn| {
            let cutoff = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                - seconds;
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM incidents WHERE timestamp >= ?1",
                params![cutoff as i64],
                |r| r.get(0),
            )?)
        })
    }
}

// ── Public API: Agent Sessions ────────────────────────────────────

impl Database {
    /// Start a new agent session.
    pub fn start_agent_session(&self, session: &AgentSession) -> Result<(), DbError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO agent_sessions (id, agent_name, pid, cwd, sandbox_mode, started_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![session.id, session.agent_name, session.pid, session.cwd, session.sandbox_mode, session.started_at],
            )?;

            // Upsert agent_stats
            conn.execute(
                "INSERT INTO agent_stats (agent_name, first_seen, last_seen, total_sessions)
                 VALUES (?1, ?2, ?2, 1)
                 ON CONFLICT(agent_name) DO UPDATE SET
                     last_seen = ?2,
                     total_sessions = total_sessions + 1",
                params![session.agent_name, session.started_at],
            )?;
            Ok(())
        })
    }

    /// End an agent session.
    pub fn end_agent_session(&self, session_id: &str, ended_at: i64) -> Result<(), DbError> {
        self.with_conn(|conn| {
            let started: Option<i64> = conn.query_row(
                "SELECT started_at FROM agent_sessions WHERE id = ?1",
                params![session_id],
                |r| r.get(0),
            )?;
            let total = started.map(|s| (ended_at - s).max(0)).unwrap_or(0);

            conn.execute(
                "UPDATE agent_sessions SET ended_at = ?1, total_seconds = ?2 WHERE id = ?3",
                params![ended_at, total, session_id],
            )?;

            // Update agent_stats
            conn.execute(
                "UPDATE agent_stats SET total_sandbox_seconds = total_sandbox_seconds + ?1
                 WHERE agent_name = (SELECT agent_name FROM agent_sessions WHERE id = ?2)",
                params![total, session_id],
            )?;
            Ok(())
        })
    }

    /// Increment violation count for a session.
    pub fn increment_session_violations(&self, session_id: &str) -> Result<(), DbError> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE agent_sessions SET violation_count = violation_count + 1 WHERE id = ?1",
                params![session_id],
            )?;
            conn.execute(
                "UPDATE agent_stats SET total_violations = total_violations + 1
                 WHERE agent_name = (SELECT agent_name FROM agent_sessions WHERE id = ?1)",
                params![session_id],
            )?;
            Ok(())
        })
    }

    /// List recent agent sessions.
    pub fn list_agent_sessions(&self, limit: u32) -> Result<Vec<AgentSession>, DbError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, agent_name, pid, cwd, sandbox_mode, started_at, ended_at, total_seconds, violation_count
                 FROM agent_sessions ORDER BY started_at DESC LIMIT ?1"
            )?;
            let rows = stmt.query_map(params![limit], |row| {
                Ok(AgentSession {
                    id: row.get(0)?,
                    agent_name: row.get(1)?,
                    pid: row.get(2)?,
                    cwd: row.get(3)?,
                    sandbox_mode: row.get(4)?,
                    started_at: row.get(5)?,
                    ended_at: row.get(6)?,
                    total_seconds: row.get(7)?,
                    violation_count: row.get(8)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
        })
    }

    /// Get statistics for a specific agent.
    pub fn get_agent_stats(&self, agent_name: &str) -> Result<Option<AgentStats>, DbError> {
        self.with_conn(|conn| {
            let result = conn.query_row(
                "SELECT agent_name, first_seen, last_seen, total_sessions, total_violations, total_sandbox_seconds
                 FROM agent_stats WHERE agent_name = ?1",
                params![agent_name],
                |row| {
                    Ok(AgentStats {
                        agent_name: row.get(0)?,
                        first_seen: row.get(1)?,
                        last_seen: row.get(2)?,
                        total_sessions: row.get(3)?,
                        total_violations: row.get(4)?,
                        total_sandbox_seconds: row.get(5)?,
                    })
                },
            );
            match result {
                Ok(s) => Ok(Some(s)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
    }

    /// List all known agent stats.
    pub fn list_agent_stats(&self) -> Result<Vec<AgentStats>, DbError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT agent_name, first_seen, last_seen, total_sessions, total_violations, total_sandbox_seconds
                 FROM agent_stats ORDER BY last_seen DESC"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(AgentStats {
                    agent_name: row.get(0)?,
                    first_seen: row.get(1)?,
                    last_seen: row.get(2)?,
                    total_sessions: row.get(3)?,
                    total_violations: row.get(4)?,
                    total_sandbox_seconds: row.get(5)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
        })
    }
}

// ── Public API: Rules ─────────────────────────────────────────────

impl Database {
    /// Add a protection rule.
    pub fn add_rule(&self, path: &str, kind: &str, watch_only: bool) -> Result<(), DbError> {
        let now = unix_ts();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO rules (path, kind, added_at, watch_only) VALUES (?1, ?2, ?3, ?4)",
                params![path, kind, now, watch_only as i32],
            )?;
            Ok(())
        })
    }

    /// Remove a protection rule.
    pub fn remove_rule(&self, path: &str) -> Result<bool, DbError> {
        self.with_conn(|conn| {
            let n = conn.execute("DELETE FROM rules WHERE path = ?1", params![path])?;
            Ok(n > 0)
        })
    }

    /// List all protection rules.
    pub fn list_rules(&self) -> Result<Vec<RuleRecord>, DbError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, path, kind, added_at, watch_only FROM rules ORDER BY added_at DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(RuleRecord {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    kind: row.get(2)?,
                    added_at: row.get(3)?,
                    watch_only: row.get::<_, i32>(4)? != 0,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
        })
    }
}

// ── Public API: Misc ──────────────────────────────────────────────

impl Database {
    /// Save config snapshot for audit trail.
    pub fn save_config_snapshot(&self, config_json: &str) -> Result<(), DbError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO config_history (changed_at, config_json) VALUES (?1, ?2)",
                params![unix_ts(), config_json],
            )?;
            Ok(())
        })
    }

    /// Add snapshot metadata to index.
    pub fn index_snapshot(
        &self,
        id: &str,
        label: &str,
        file_count: u32,
        total_bytes: u64,
        compressed_bytes: u64,
    ) -> Result<(), DbError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO snapshot_index (id, label, created_at, file_count, total_bytes, compressed_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, label, unix_ts(), file_count, total_bytes as i64, compressed_bytes as i64],
            )?;
            Ok(())
        })
    }

    /// List snapshots from index.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotRecord>, DbError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, label, created_at, file_count, total_bytes, compressed_bytes
                 FROM snapshot_index ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(SnapshotRecord {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    created_at: row.get(2)?,
                    file_count: row.get(3)?,
                    total_bytes: row.get(4)?,
                    compressed_bytes: row.get(5)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
        })
    }

    /// Store OTA version.
    pub fn set_ota_version(&self, version: u64) -> Result<(), DbError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO ota_version (key, value) VALUES ('current', ?1)",
                params![version.to_string()],
            )?;
            Ok(())
        })
    }

    /// Get OTA version.
    pub fn get_ota_version(&self) -> Result<u64, DbError> {
        self.with_conn(|conn| {
            let result = conn.query_row(
                "SELECT value FROM ota_version WHERE key = 'current'",
                [],
                |r| r.get::<_, String>(0),
            );
            match result {
                Ok(s) => Ok(s.parse().unwrap_or(0)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
                Err(e) => Err(e.into()),
            }
        })
    }

    /// Import legacy incidents from JSONL file.
    pub fn import_jsonl(&self, path: &Path) -> Result<u64, DbError> {
        if !path.exists() {
            return Ok(0);
        }
        let content = std::fs::read_to_string(path)?;

        let count = self.with_conn(|conn| {
            let mut n = 0u64;
            for line in content.lines() {
                if line.trim().is_empty() { continue; }
                if let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) {
                    let kind = ev["kind"].as_str().unwrap_or("unknown");
                    let ts = ev["timestamp"].as_u64().unwrap_or(0) as i64;
                    let agent = ev["agent_name"].as_str();
                    let pid = ev["pid"].as_u64().map(|p| p as i64);
                    let path_s = ev["path"].as_str();
                    let violation = ev["violation"].as_str();
                    let process = ev["process"].as_str();
                    let details = if ev.get("details").is_some() { Some(ev["details"].to_string()) } else { None };

                    conn.execute(
                        "INSERT OR IGNORE INTO incidents (timestamp, kind, agent_name, agent_pid, path, violation, process, details)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![ts, kind, agent, pid, path_s, violation, process, details],
                    )?;
                    n += 1;
                }
            }
            Ok(n)
        })?;

        // Rename imported file to .imported
        let imported = path.with_extension("jsonl.imported");
        let _ = std::fs::rename(path, &imported);

        tracing::info!(count, "imported legacy incidents from JSONL");
        Ok(count)
    }
}

// ── Types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IncidentRecord {
    pub id: Option<i64>,
    pub timestamp: i64,
    pub kind: String,
    pub agent_name: Option<String>,
    pub agent_pid: Option<i64>,
    pub path: Option<String>,
    pub violation: Option<String>,
    pub process: Option<String>,
    pub details: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct IncidentFilter {
    pub kind: Option<String>,
    pub agent_name: Option<String>,
    pub from_timestamp: Option<i64>,
    pub to_timestamp: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AgentSession {
    pub id: String,
    pub agent_name: String,
    pub pid: Option<i64>,
    pub cwd: Option<String>,
    pub sandbox_mode: Option<String>,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub total_seconds: Option<i64>,
    pub violation_count: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AgentStats {
    pub agent_name: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub total_sessions: i64,
    pub total_violations: i64,
    pub total_sandbox_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct RuleRecord {
    pub id: i64,
    pub path: String,
    pub kind: String,
    pub added_at: i64,
    pub watch_only: bool,
}

#[derive(Debug, Clone)]
pub struct SnapshotRecord {
    pub id: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub file_count: u32,
    pub total_bytes: i64,
    pub compressed_bytes: i64,
}

// ── Error type ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database lock poisoned")]
    LockPoisoned,
}

// ── Helpers ────────────────────────────────────────────────────────

fn unix_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn default_db_path() -> PathBuf {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return PathBuf::from("/var/lib/agentguard/data/agentguard.db");
        }
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".agentguard/data/agentguard.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = Database::open(&path).unwrap();
        (db, dir)
    }

    #[test]
    fn test_open_creates_db() {
        let (db, _dir) = test_db();
        assert!(db.path().exists());
    }

    #[test]
    fn test_insert_and_query_incident() {
        let (db, _dir) = test_db();
        db.insert_incident(&IncidentRecord {
            id: None,
            timestamp: 1000,
            kind: "agent_detected".into(),
            agent_name: Some("windsurf".into()),
            agent_pid: Some(1234),
            path: Some("/proc".into()),
            violation: None,
            process: Some("windsurf".into()),
            details: None,
            session_id: None,
        })
        .unwrap();

        let results = db.query_incidents(&IncidentFilter::default()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_name.as_deref(), Some("windsurf"));
    }

    #[test]
    fn test_query_filter_by_kind() {
        let (db, _dir) = test_db();
        db.insert_incident(&IncidentRecord {
            id: None,
            timestamp: 1,
            kind: "file_violation".into(),
            agent_name: None,
            agent_pid: None,
            path: None,
            violation: Some("write".into()),
            process: None,
            details: None,
            session_id: None,
        })
        .unwrap();
        db.insert_incident(&IncidentRecord {
            id: None,
            timestamp: 2,
            kind: "agent_detected".into(),
            agent_name: None,
            agent_pid: None,
            path: None,
            violation: None,
            process: None,
            details: None,
            session_id: None,
        })
        .unwrap();

        let filter = IncidentFilter {
            kind: Some("file_violation".into()),
            ..Default::default()
        };
        let results = db.query_incidents(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].violation.as_deref(), Some("write"));
    }

    #[test]
    fn test_agent_sessions() {
        let (db, _dir) = test_db();
        db.start_agent_session(&AgentSession {
            id: "sess-1".into(),
            agent_name: "claude".into(),
            pid: Some(100),
            cwd: Some("/tmp".into()),
            sandbox_mode: Some("sandbox".into()),
            started_at: 1000,
            ended_at: None,
            total_seconds: None,
            violation_count: None,
        })
        .unwrap();

        db.end_agent_session("sess-1", 1100).unwrap();
        db.increment_session_violations("sess-1").unwrap();

        let stats = db.get_agent_stats("claude").unwrap().unwrap();
        assert_eq!(stats.total_sessions, 1);
        assert_eq!(stats.total_violations, 1);
        assert_eq!(stats.total_sandbox_seconds, 100);
    }

    #[test]
    fn test_rules_crud() {
        let (db, _dir) = test_db();
        db.add_rule("/tmp/test", "dir", false).unwrap();
        db.add_rule("/tmp/test2", "file", true).unwrap();

        let rules = db.list_rules().unwrap();
        assert_eq!(rules.len(), 2);

        assert!(db.remove_rule("/tmp/test").unwrap());
        let rules = db.list_rules().unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_count_incidents_since() {
        let (db, _dir) = test_db();
        let now = unix_ts();
        db.insert_incident(&IncidentRecord {
            id: None,
            timestamp: now,
            kind: "test".into(),
            agent_name: None,
            agent_pid: None,
            path: None,
            violation: None,
            process: None,
            details: None,
            session_id: None,
        })
        .unwrap();
        db.insert_incident(&IncidentRecord {
            id: None,
            timestamp: now - 10000,
            kind: "test".into(),
            agent_name: None,
            agent_pid: None,
            path: None,
            violation: None,
            process: None,
            details: None,
            session_id: None,
        })
        .unwrap();

        let count = db.count_incidents_since(5).unwrap();
        assert!(count <= 1);
    }

    #[test]
    fn test_ota_version() {
        let (db, _dir) = test_db();
        assert_eq!(db.get_ota_version().unwrap(), 0);
        db.set_ota_version(42).unwrap();
        assert_eq!(db.get_ota_version().unwrap(), 42);
    }

    #[test]
    fn test_snapshot_index() {
        let (db, _dir) = test_db();
        db.index_snapshot("abc", "test", 10, 1000, 500).unwrap();
        let snaps = db.list_snapshots().unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].id, "abc");
        assert_eq!(snaps[0].compressed_bytes, 500);
    }
}
