//! Anonymous telemetry for seccomp USER_NOTIF syscalls — Fase 3.
//!
//! When the daemon receives a USER_NOTIF notification for an unknown syscall,
//! it can record the event and periodically batch-report it to the backend.
//! This data feeds the OTA pipeline to improve seccomp profiles.
//!
//! ## Privacy:
//!
//! Telemetry is OPT-IN (disabled by default). When enabled:
//! - Agent names are hashed (SHA256 truncated to 8 hex chars).
//! - No file paths, PIDs, UIDs, or IP addresses are ever sent.
//! - Only: syscall_number + agent_name_hash + agentguard_version + kernel_version.
//! - Events are batched and sent at most once per hour.

use std::io::Read;
use std::sync::Mutex;

use serde::Serialize;

/// A single anonymous telemetry event.
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryEvent {
    /// Syscall number that triggered USER_NOTIF.
    pub syscall_nr: i64,
    /// SHA256(agent_name)[..8] — anonymized.
    pub agent_hash: String,
    /// AgentGuard daemon version.
    pub agentguard_version: String,
    /// Linux kernel version string (uname -r).
    pub kernel_version: String,
    /// Unix timestamp when the event occurred.
    pub timestamp: u64,
}

/// Batches telemetry events and flushes them to the backend.
pub struct TelemetryBatcher {
    enabled: bool,
    endpoint: String,
    max_batch: usize,
    events: Mutex<Vec<TelemetryEvent>>,
    /// Unique syscall numbers seen (for feedback to seccomp profile).
    pending_syscalls: Mutex<Vec<i64>>,
}

impl TelemetryBatcher {
    /// Create a new telemetry batcher.
    ///
    /// If `endpoint` is empty, telemetry is disabled.
    pub fn new(endpoint: String, max_batch: usize) -> Self {
        let enabled = !endpoint.is_empty();
        if enabled {
            tracing::info!(
                endpoint = %endpoint,
                max_batch,
                "telemetry enabled — anonymous syscall reports"
            );
        } else {
            tracing::info!("telemetry disabled (no endpoint configured)");
        }

        Self {
            enabled,
            endpoint,
            max_batch,
            events: Mutex::new(Vec::new()),
            pending_syscalls: Mutex::new(Vec::new()),
        }
    }

    /// Record an unknown syscall for later batch reporting.
    ///
    /// If telemetry is disabled, this is a no-op.
    pub fn record_unknown_syscall(&self, syscall_nr: i64, agent_name: &str) {
        if !self.enabled {
            return;
        }

        let agent_hash = hash_agent_name(agent_name);
        let event = TelemetryEvent {
            syscall_nr,
            agent_hash,
            agentguard_version: env!("CARGO_PKG_VERSION").to_string(),
            kernel_version: get_kernel_version(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };

        if let Ok(mut events) = self.events.lock() {
            events.push(event);

            if events.len() >= self.max_batch {
                tracing::debug!(count = events.len(), "telemetry batch threshold reached");
            }
        }

        // Track unique syscall number for feedback loop
        if let Ok(mut pending) = self.pending_syscalls.lock() {
            if !pending.contains(&syscall_nr) {
                pending.push(syscall_nr);
            }
        }
    }

    /// Flush pending events to the backend.
    ///
    /// Returns the number of events sent, or 0 if none were pending.
    pub fn flush(&self) -> Result<usize, anyhow::Error> {
        if !self.enabled {
            return Ok(0);
        }

        let events: Vec<TelemetryEvent> = {
            let mut guard = self
                .events
                .lock()
                .map_err(|e| anyhow::anyhow!("telemetry mutex poisoned: {}", e))?;
            if guard.is_empty() {
                return Ok(0);
            }
            std::mem::take(&mut *guard)
        };

        let count = events.len();
        let body_json = serde_json::to_string(&events)?;

        match ureq::agent()
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header(
                "User-Agent",
                &format!("agentguard-telemetry/{}", env!("CARGO_PKG_VERSION")),
            )
            .send(&body_json)
        {
            Ok(response) => {
                let status = response.status().as_u16();
                if (200..300).contains(&status) {
                    tracing::debug!(count, "telemetry flushed successfully");
                    Ok(count)
                } else {
                    let mut err_body = String::new();
                    let _ = response
                        .into_body()
                        .as_reader()
                        .read_to_string(&mut err_body);
                    tracing::warn!(
                        count,
                        status,
                        error = %err_body,
                        "telemetry backend rejected batch — events dropped"
                    );
                    Ok(0)
                }
            }
            Err(e) => {
                tracing::warn!(
                    count,
                    error = %e,
                    "telemetry flush failed — events dropped"
                );
                Ok(0)
            }
        }
    }

    /// Drain and return unique pending syscall numbers for profile feedback.
    ///
    /// This is called periodically to promote unknown-but-safe syscalls
    /// to the seccomp allowlist.
    pub fn take_pending_syscalls(&self) -> Vec<i64> {
        let mut guard = match self.pending_syscalls.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        std::mem::take(&mut *guard)
    }
}

/// Hash an agent name for anonymization.
///
/// Uses SHA256 and takes the first 8 hex characters.
fn hash_agent_name(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..4]) // first 4 bytes = 8 hex chars
}

/// Get the kernel version string.
fn get_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_disabled_when_no_endpoint() {
        let batcher = TelemetryBatcher::new(String::new(), 50);
        assert!(!batcher.enabled);
        assert_eq!(batcher.flush().unwrap(), 0);
    }

    #[test]
    fn test_telemetry_enabled_with_endpoint() {
        let batcher = TelemetryBatcher::new("http://localhost:9999".into(), 50);
        assert!(batcher.enabled);
    }

    #[test]
    fn test_record_and_flush() {
        let batcher = TelemetryBatcher::new("http://localhost:9999".into(), 2);
        batcher.record_unknown_syscall(425, "claude-code");
        batcher.record_unknown_syscall(426, "cursor");

        // Flush should attempt HTTP POST (will fail since no server)
        // But it should clear the batch
        let result = batcher.flush();
        // The flush will fail because there's no server, but it shouldn't panic
        let _ = result;

        // After flush, queue should be empty
        let guard = batcher.events.lock().unwrap();
        assert!(guard.is_empty());
    }

    #[test]
    fn test_hash_agent_name_consistent() {
        let h1 = hash_agent_name("claude-code");
        let h2 = hash_agent_name("claude-code");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 8);
    }

    #[test]
    fn test_hash_agent_name_different_agents() {
        let h1 = hash_agent_name("claude-code");
        let h2 = hash_agent_name("cursor");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_disable_ignores_records() {
        let batcher = TelemetryBatcher::new(String::new(), 10);
        batcher.record_unknown_syscall(999, "test-agent");
        let guard = batcher.events.lock().unwrap();
        assert!(guard.is_empty());
    }
}
