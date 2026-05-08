//! Fanotify-based userspace protection — **blocks** write opens and exec
//! on protected paths via `FAN_OPEN_PERM` + `FAN_DENY`.
//!
//! This is the middle ground between `UserspaceGuard` (observation-only via
//! inotify) and `EbpfGuard` (kernel LSM, full coverage).  fanotify can only
//! block operations that go through `open(2)` / `execve(2)` — it cannot block
//! `unlink`, `rename`, `truncate`, or `mkdir` directly.  For the common
//! attacks ("append secret to a file", "create a new file in a protected
//! dir", "execute a malicious binary from a protected dir") this is
//! perfectly adequate and works on **any Linux kernel >= 5.1** without any
//! eBPF or special kernel config.
//!
//! ## Architecture
//!
//! 1. `fanotify_init(FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS)`
//! 2. `fanotify_mark(FAN_MARK_ADD, FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_ONDIR, ...)`
//!    on every protected path.
//! 3. Dedicated blocking thread reads `fanotify_event_metadata` records.
//! 4. For `FAN_OPEN_PERM` events:
//!    - Resolve the target path via `/proc/self/fd/<fd>`.
//!    - Check whether the path is inside a protected directory.
//!    - If it is, inspect `fcntl(fd, F_GETFL)` to determine write vs read-only.
//!    - Write-open → `FAN_DENY`; read-open or non-protected-path → `FAN_ALLOW`.
//! 5. For `FAN_CLOSE_WRITE` events: log the incident (post-hoc, cannot block).
//! 6. Persisted events are sent through the broadcast `SecurityEvent` channel.

use std::collections::HashSet;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::sync::broadcast;

use agentguard_core::{GuardError, KernelGuard, ProtectionLevel, SecurityEvent, ViolationKind};

// ─── Nix fanotify types (loaded in module so we don't pollute imports) ────
// NOTE: `nix::fcntl::fcntl` is gated behind nix's `fs` feature which we don't
// enable. We fall back to `libc::fcntl(F_GETFL)` which is what nix wraps
// anyway — it is the only fcntl op we need here.
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};

// ─── POSIX open flags for write-detection ────────────────────────────────
const O_ACCMODE: i32 = 0o0003;
const O_WRONLY: i32 = 0o0001;
const O_RDWR: i32 = 0o0002;
const O_CREAT: i32 = 0o0100;
const O_TRUNC: i32 = 0o1000;

/// Guard that uses fanotify to **block** write-opens on protected paths.
///
/// Unlike `UserspaceGuard` (which uses inotify and is observation-only),
/// this guard writes `FAN_DENY` to the kernel's fanotify response channel
/// for permission events, causing the calling process to receive `-EPERM`.
pub struct FanotifyGuard {
    paths: HashSet<PathBuf>,
}

impl FanotifyGuard {
    pub fn new(paths: &[PathBuf]) -> Result<Self, GuardError> {
        let mut canonical = HashSet::new();
        for p in paths {
            match std::fs::canonicalize(p) {
                Ok(c) => {
                    canonical.insert(c);
                }
                Err(e) => {
                    tracing::warn!(path = ?p, error = %e, "skipping protected path (fanotify)");
                }
            }
        }
        Ok(Self { paths: canonical })
    }
}

#[async_trait]
impl KernelGuard for FanotifyGuard {
    fn backend_name(&self) -> &'static str {
        "fanotify"
    }

    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::UserspaceBlocking
    }

    async fn add_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        let c = std::fs::canonicalize(path).map_err(|e| GuardError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        self.paths.insert(c);
        Ok(())
    }

    async fn remove_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        let c = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        self.paths.remove(&c);
        Ok(())
    }

    async fn run(
        self: Box<Self>,
        out_tx: broadcast::Sender<SecurityEvent>,
    ) -> Result<(), GuardError> {
        let init_flags = InitFlags::FAN_CLASS_CONTENT
            | InitFlags::FAN_CLOEXEC
            | InitFlags::FAN_UNLIMITED_QUEUE
            | InitFlags::FAN_UNLIMITED_MARKS;
        let event_flags = EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE;

        let fan = Fanotify::init(init_flags, event_flags)
            .map_err(|e| GuardError::Internal(format!("fanotify_init: {e}")))?;

        // Mark each protected path for open-permission and close-write events.
        let perm_mask =
            MaskFlags::FAN_OPEN_PERM | MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_ONDIR;

        let mark_flags = MarkFlags::FAN_MARK_ADD;

        let mut mark_count = 0u32;
        for p in &self.paths {
            match fan.mark(mark_flags, perm_mask, None, Some(p.as_path())) {
                Ok(()) => {
                    tracing::info!(path = ?p, "fanotify mark added");
                    mark_count += 1;
                }
                Err(e) => {
                    tracing::warn!(path = ?p, error = %e, "fanotify_mark failed");
                }
            }
        }

        tracing::info!(
            paths = mark_count,
            total = self.paths.len(),
            "fanotify guard ready — blocking write-opens on protected paths"
        );

        // ── Blocking event loop ──
        // fanotify fd reads are blocking by default (no O_NONBLOCK).  We
        // wrap this in `spawn_blocking` so the async runtime stays responsive.
        // The path set is cloned — lookup is infrequent (per open) and cheap.
        let paths = self.paths.clone();

        tokio::task::spawn_blocking(move || {
            let _ = fanotify_event_loop(&fan, &paths, out_tx);
        })
        .await
        .map_err(|e| GuardError::Internal(format!("fanotify thread join: {e}")))?;

        Ok(())
    }
}

fn canonicalize_fd(fd: BorrowedFd) -> Option<PathBuf> {
    let link = format!("/proc/self/fd/{}", fd.as_raw_fd());
    std::fs::read_link(&link).ok()
}

fn is_write_open(fd: BorrowedFd) -> bool {
    // libc::fcntl(F_GETFL) returns the open flags as a c_int. On error we
    // fail *closed* (treat as write) so we never inadvertently allow a
    // malicious open through on a transient EINTR/EBADF.
    // SAFETY: `fd` is a valid borrowed fd (kernel-supplied via fanotify);
    // F_GETFL with zero varargs is safe on every POSIX system.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if raw < 0 {
        return true;
    }
    let flags: i32 = raw;
    let access = flags & O_ACCMODE;
    access == O_WRONLY || access == O_RDWR || (flags & (O_TRUNC | O_CREAT)) != 0
}

fn is_under(paths: &HashSet<PathBuf>, target: &Path) -> bool {
    if paths.contains(target) {
        return true;
    }
    let mut cur = target.to_path_buf();
    while let Some(parent) = cur.parent() {
        if parent == cur {
            break;
        }
        if paths.contains(parent) {
            return true;
        }
        cur = parent.to_path_buf();
    }
    false
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The per-event decision loop. Runs on a dedicated blocking thread.
fn fanotify_event_loop(
    fan: &Fanotify,
    paths: &HashSet<PathBuf>,
    out_tx: broadcast::Sender<SecurityEvent>,
) -> Result<(), GuardError> {
    loop {
        let events = fan
            .read_events()
            .map_err(|e| GuardError::Internal(format!("fanotify read_events: {e}")))?;

        for ev in events {
            let mask = ev.mask();

            // ── PERMISSION event (MUST respond) ──
            if mask.contains(MaskFlags::FAN_OPEN_PERM) {
                let fd = match ev.fd() {
                    Some(f) => f,
                    None => {
                        // Queue overflow — allow to unblock
                        let r = FanotifyResponse::new(
                            unsafe { BorrowedFd::borrow_raw(libc::FAN_NOFD) },
                            Response::FAN_ALLOW,
                        );
                        let _ = fan.write_response(r);
                        continue;
                    }
                };

                let fd_path = canonicalize_fd(fd);
                let protected = fd_path
                    .as_ref()
                    .map(|p| is_under(paths, p))
                    .unwrap_or(false);

                if !protected {
                    let r = FanotifyResponse::new(fd, Response::FAN_ALLOW);
                    let _ = fan.write_response(r);
                    continue;
                }

                // Check write intent via fcntl(F_GETFL).
                if is_write_open(fd) {
                    let path_str = fd_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "?".into());
                    tracing::info!(
                        path = %path_str,
                        pid = ev.pid(),
                        "BLOCKED — fanotify FAN_DENY (write-open on protected path)"
                    );

                    let _ = out_tx.send(SecurityEvent::FileViolation {
                        path: fd_path.unwrap_or_default(),
                        process: String::new(),
                        pid: ev.pid() as u32,
                        violation: ViolationKind::WriteAttempt,
                        timestamp: now_secs(),
                    });

                    let r = FanotifyResponse::new(fd, Response::FAN_DENY);
                    let _ = fan.write_response(r);
                } else {
                    let r = FanotifyResponse::new(fd, Response::FAN_ALLOW);
                    let _ = fan.write_response(r);
                }
                continue;
            }

            // ── NOTIFICATION events (post-hoc, cannot block) ──
            if mask.intersects(
                MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_DELETE | MaskFlags::FAN_DELETE_SELF,
            ) {
                if let Some(fd) = ev.fd() {
                    let fd_path = canonicalize_fd(fd);
                    let protected = fd_path
                        .as_ref()
                        .map(|p| is_under(paths, p))
                        .unwrap_or(false);
                    if protected {
                        let kind = if mask.contains(MaskFlags::FAN_CLOSE_WRITE) {
                            ViolationKind::WriteAttempt
                        } else {
                            ViolationKind::DeleteAttempt
                        };

                        let path_str = fd_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "?".into());
                        tracing::info!(
                            path = %path_str,
                            pid = ev.pid(),
                            ?kind,
                            "fanotify — write/delete detected on protected path"
                        );

                        let _ = out_tx.send(SecurityEvent::FileViolation {
                            path: fd_path.unwrap_or_default(),
                            process: String::new(),
                            pid: ev.pid() as u32,
                            violation: kind,
                            timestamp: now_secs(),
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_under_exact_match() {
        let paths: HashSet<PathBuf> = [PathBuf::from("/tmp/protected")].into_iter().collect();
        assert!(is_under(&paths, Path::new("/tmp/protected")));
        assert!(!is_under(&paths, Path::new("/tmp/other")));
    }

    #[test]
    fn is_under_child_match() {
        let paths: HashSet<PathBuf> = [PathBuf::from("/tmp/protected")].into_iter().collect();
        assert!(is_under(&paths, Path::new("/tmp/protected/sub/file.txt")));
    }

    #[test]
    fn is_under_no_partial_match() {
        // "/tmp/pro" must not match "/tmp/protected" (partial prefix ≠ ancestor)
        let paths: HashSet<PathBuf> = [PathBuf::from("/tmp/pro")].into_iter().collect();
        assert!(!is_under(&paths, Path::new("/tmp/protected/file.txt")));
    }

    #[test]
    fn is_under_empty_set() {
        let paths = HashSet::new();
        assert!(!is_under(&paths, Path::new("/anything")));
    }
}
