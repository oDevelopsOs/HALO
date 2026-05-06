//! seccomp USER_NOTIF handler — receives syscall notifications from
//! the kernel and responds with allow/deny decisions.
//!
//! When a seccomp-BPF filter uses SECCOMP_RET_USER_NOTIF, the kernel
//! pauses the syscall and sends a notification through a file descriptor
//! obtained via SECCOMP_FILTER_FLAG_NEW_LISTENER. The daemon reads
//! these notifications, classifies the syscall, and sends back a response.
//!
//! ## Fail-safe:
//!
//! If the daemon dies (fd closes), the kernel releases all pending
//! syscalls with ENOSYS. The agent may crash but will NOT execute
//! dangerous syscalls. systemd RestartSec=100ms limits exposure.

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::sync::Arc;

    use tokio::io::unix::AsyncFd;
    use tokio::sync::RwLock;

    use super::super::seccomp::{SyscallDecision, ALWAYS_KILL_SYSCALLS};

    // ── Kernel structs (uapi/linux/seccomp.h) ────────────────

    #[repr(C)]
    struct SeccompData {
        nr: i32,
        arch: u32,
        instruction_pointer: u64,
        args: [u64; 6],
    }

    #[repr(C)]
    struct SeccompNotif {
        id: u64,
        pid: u32,
        flags: u32,
        data: SeccompData,
    }

    #[repr(C)]
    struct SeccompNotifResp {
        id: u64,
        val: i64,
        error: i32,
        flags: u32,
    }

    // ── ioctl commands ────────────────────────────────────────

    const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xC0502100;
    const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xC0182101;

    /// Decision profile for seccomp notifications.
    ///
    /// Can be updated at runtime (e.g., via OTA profiles in Phase 3).
    #[derive(Debug, Clone, Default)]
    pub struct SeccompDecisionProfile {
        /// Syscall numbers that should be allowed.
        pub allow: Vec<i64>,
        /// Syscall numbers that should be denied with ENOSYS.
        pub deny_enosys: Vec<i64>,
        /// Syscall numbers that should be denied with EPERM.
        pub deny_eperm: Vec<i64>,
    }

    impl SeccompDecisionProfile {
        /// Classify a syscall number and return the decision.
        pub fn classify(&self, syscall_nr: i64) -> SyscallDecision {
            if self.allow.contains(&syscall_nr) {
                return SyscallDecision::Allow;
            }
            if self.deny_enosys.contains(&syscall_nr) {
                return SyscallDecision::DenyEnosys;
            }
            if self.deny_eperm.contains(&syscall_nr) {
                return SyscallDecision::DenyEperm;
            }
            // Unknown syscall → Allow (fail-open for new/ambiguous syscalls).
            // Telemetry records these for the OTA pipeline to improve profiles.
            SyscallDecision::Allow
        }
    }

    /// Handler for seccomp USER_NOTIF events.
    pub struct SeccompNotifier {
        notif_fd: OwnedFd,
        telemetry: Option<std::sync::Arc<crate::telemetry::TelemetryBatcher>>,
        /// External notifier fds from sandboxed agents (populated via FD broker).
        agent_fds: Arc<std::sync::Mutex<Vec<std::os::fd::OwnedFd>>>,
    }

    impl SeccompNotifier {
        /// Create a new notifier from the fd returned by seccomp filter installation.
        pub fn new(fd: OwnedFd) -> Self {
            Self {
                notif_fd: fd,
                telemetry: None,
                agent_fds: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        /// Set the shared agent fds list (from FD broker).
        pub fn with_agent_fds(
            mut self,
            fds: Arc<std::sync::Mutex<Vec<std::os::fd::OwnedFd>>>,
        ) -> Self {
            self.agent_fds = fds;
            self
        }

        /// Enable telemetry reporting for unknown syscalls.
        pub fn with_telemetry(
            mut self,
            batcher: std::sync::Arc<crate::telemetry::TelemetryBatcher>,
        ) -> Self {
            self.telemetry = Some(batcher);
            self
        }

        /// Run the notification handling loop.
        ///
        /// This function runs forever, reading notifications from the kernel
        /// and sending back allow/deny decisions. It should be spawned as a
        /// tokio task.
        pub async fn run(
            self,
            profile: Arc<RwLock<SeccompDecisionProfile>>,
        ) -> Result<(), anyhow::Error> {
            let raw_fd = self.notif_fd.as_raw_fd();

            // Wrap the fd in tokio's AsyncFd for async I/O
            // The notifier fd becomes readable when a notification is pending
            let async_fd = AsyncFd::new(self.notif_fd)
                .map_err(|e| anyhow::anyhow!("AsyncFd for seccomp notifier: {}", e))?;

            tracing::info!("Seccomp USER_NOTIF handler started");

            loop {
                // Wait for the fd to become readable
                let mut guard = async_fd
                    .readable()
                    .await
                    .map_err(|e| anyhow::anyhow!("seccomp notifier readable error: {}", e))?;

                // Drain all pending notifications
                loop {
                    let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };

                    let ret = unsafe {
                        libc::ioctl(raw_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif as *mut _)
                    };

                    if ret < 0 {
                        let err = unsafe { *libc::__errno_location() };
                        if err == libc::ENOENT {
                            // Agent process died — exit the notification loop
                            tracing::debug!("Seccomp notifier: agent process died (ENOENT)");
                            return Ok(());
                        }
                        // EAGAIN / EWOULDBLOCK means no more notifications
                        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                            break;
                        }
                        tracing::warn!(
                            error = err,
                            "Seccomp notifier: ioctl(NOTIF_RECV) unexpected error"
                        );
                        break;
                    }

                    let syscall_nr = notif.data.nr as i64;
                    let pid = notif.pid;

                    // Skip always-kill syscalls (should never reach here — they
                    // are killed in the BPF filter, but defense in depth)
                    if ALWAYS_KILL_SYSCALLS.contains(&syscall_nr) {
                        tracing::error!(
                            pid = pid,
                            syscall = syscall_nr,
                            "ALWAYS_KILL syscall reached USER_NOTIF — this is a filter bug. Killing process."
                        );
                        // Respond with kill simulation (error with a fatal signal)
                        let resp = SeccompNotifResp {
                            id: notif.id,
                            val: 0,
                            error: -(libc::ENOSYS),
                            flags: 0,
                        };
                        unsafe {
                            let _ =
                                libc::ioctl(raw_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp as *const _);
                        }
                        continue;
                    }

                    // Classify the syscall
                    let (decision, is_unknown) = {
                        let prof = profile.read().await;
                        let known = prof.allow.contains(&syscall_nr)
                            || prof.deny_enosys.contains(&syscall_nr)
                            || prof.deny_eperm.contains(&syscall_nr);
                        (prof.classify(syscall_nr), !known)
                    };

                    // Record unknown syscall for telemetry (Fase 3 OTA pipeline)
                    if is_unknown {
                        if let Some(ref telemetry) = self.telemetry {
                            let agent_name = read_agent_comm(pid);
                            telemetry.record_unknown_syscall(syscall_nr, &agent_name);
                        }
                    }

                    let error_code = match decision {
                        SyscallDecision::Allow => {
                            tracing::debug!(pid = pid, syscall = syscall_nr, "seccomp: ALLOW");
                            0
                        }
                        SyscallDecision::DenyEnosys => {
                            tracing::warn!(
                                pid = pid,
                                syscall = syscall_nr,
                                "seccomp: DENY (ENOSYS)"
                            );
                            -(libc::ENOSYS)
                        }
                        SyscallDecision::DenyEperm => {
                            tracing::warn!(
                                pid = pid,
                                syscall = syscall_nr,
                                "seccomp: DENY (EPERM)"
                            );
                            -(libc::EPERM)
                        }
                    };

                    // Build the response
                    let resp = SeccompNotifResp {
                        id: notif.id,
                        val: 0,
                        error: error_code,
                        flags: 0,
                    };

                    let send_ret =
                        unsafe { libc::ioctl(raw_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp as *const _) };

                    if send_ret < 0 {
                        let err = unsafe { *libc::__errno_location() };
                        if err == libc::ENOENT {
                            // Process died between notification and response
                            tracing::debug!(
                                pid = pid,
                                "seccomp: agent process died before response"
                            );
                            continue;
                        }
                        tracing::error!(
                            error = err,
                            pid = pid,
                            "seccomp: ioctl(NOTIF_SEND) failed"
                        );
                    }
                }

                // Clear the readiness guard
                guard.clear_ready();

                // Also drain agent notifier fds (from sandboxed agents)
                let agent_fds_to_check: Vec<std::os::fd::OwnedFd> = {
                    if let Ok(mut fds) = self.agent_fds.lock() {
                        std::mem::take(&mut *fds)
                    } else {
                        Vec::new()
                    }
                };

                let mut still_alive = Vec::new();
                for agent_fd in agent_fds_to_check {
                    match drain_single_notifier_fd(agent_fd.as_raw_fd(), &profile, &self.telemetry)
                    {
                        Ok(true) => still_alive.push(agent_fd),
                        Ok(false) => {
                            tracing::debug!("agent notifier fd closed (agent died)");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "agent notifier drain error");
                            still_alive.push(agent_fd);
                        }
                    }
                }

                // Put alive fds back
                if let Ok(mut fds) = self.agent_fds.lock() {
                    *fds = still_alive;
                }
            }
        }
    }

    /// Read /proc/<pid>/comm to get the process name for telemetry.
    fn read_agent_comm(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    /// Drain notifications from a single notifier fd.
    /// Returns Ok(true) if the fd is still alive, Ok(false) if the agent died.
    fn drain_single_notifier_fd(
        fd: std::os::fd::RawFd,
        profile: &Arc<RwLock<SeccompDecisionProfile>>,
        telemetry: &Option<std::sync::Arc<crate::telemetry::TelemetryBatcher>>,
    ) -> Result<bool, anyhow::Error> {
        let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };

        let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif as *mut _) };

        if ret < 0 {
            let err = unsafe { *libc::__errno_location() };
            if err == libc::ENOENT {
                return Ok(false); // agent died
            }
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                return Ok(true); // no pending notifications, fd still alive
            }
            anyhow::bail!("ioctl(NOTIF_RECV) unexpected error: errno {err}");
        }

        let syscall_nr = notif.data.nr as i64;

        if ALWAYS_KILL_SYSCALLS.contains(&syscall_nr) {
            let resp = SeccompNotifResp {
                id: notif.id,
                val: 0,
                error: -(libc::ENOSYS),
                flags: 0,
            };
            unsafe {
                let _ = libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp as *const _);
            }
            return Ok(true);
        }

        let (decision, is_unknown) = {
            let prof = profile.blocking_read();
            let known = prof.allow.contains(&syscall_nr)
                || prof.deny_enosys.contains(&syscall_nr)
                || prof.deny_eperm.contains(&syscall_nr);
            (prof.classify(syscall_nr), !known)
        };

        if is_unknown {
            if let Some(ref telemetry) = telemetry {
                let agent_name = read_agent_comm(notif.pid);
                telemetry.record_unknown_syscall(syscall_nr, &agent_name);
            }
        }

        let error_code = match decision {
            SyscallDecision::Allow => 0,
            SyscallDecision::DenyEnosys => -(libc::ENOSYS),
            SyscallDecision::DenyEperm => -(libc::EPERM),
        };

        let resp = SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: error_code,
            flags: 0,
        };

        let send_ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp as *const _) };

        if send_ret < 0 {
            let err = unsafe { *libc::__errno_location() };
            if err == libc::ENOENT {
                return Ok(false);
            }
            tracing::warn!(error = err, "ioctl(NOTIF_SEND) failed for agent fd");
        }

        Ok(true)
    }

    /// Spawn the seccomp notifier as a tokio task.
    ///
    /// Returns the join handle. The task runs until the notifier fd is closed
    /// or the daemon shuts down.
    pub fn spawn_notifier(
        notif_fd: OwnedFd,
        profile: Arc<RwLock<SeccompDecisionProfile>>,
    ) -> tokio::task::JoinHandle<Result<(), anyhow::Error>> {
        let notifier = SeccompNotifier::new(notif_fd);
        tokio::spawn(async move { notifier.run(profile).await })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_default_profile_classify_unknown() {
            let profile = SeccompDecisionProfile::default();
            // Unknown syscalls are now allowed (fail-open for new syscalls)
            // Telemetry records these for the OTA pipeline
            assert_eq!(profile.classify(9999), SyscallDecision::Allow);
        }

        #[test]
        fn test_profile_classify_allow() {
            let profile = SeccompDecisionProfile {
                allow: vec![libc::SYS_read],
                ..Default::default()
            };
            assert_eq!(profile.classify(libc::SYS_read), SyscallDecision::Allow);
        }

        #[test]
        fn test_profile_classify_deny_enosys() {
            let profile = SeccompDecisionProfile {
                deny_enosys: vec![libc::SYS_io_uring_setup],
                ..Default::default()
            };
            assert_eq!(
                profile.classify(libc::SYS_io_uring_setup),
                SyscallDecision::DenyEnosys
            );
        }

        #[test]
        fn test_profile_classify_deny_eperm() {
            let profile = SeccompDecisionProfile {
                deny_eperm: vec![libc::SYS_ptrace],
                ..Default::default()
            };
            assert_eq!(
                profile.classify(libc::SYS_ptrace),
                SyscallDecision::DenyEperm
            );
        }

        #[test]
        fn test_profile_allow_takes_priority() {
            // Allow should take priority over deny
            let profile = SeccompDecisionProfile {
                allow: vec![42],
                deny_enosys: vec![42],
                deny_eperm: vec![42],
            };
            assert_eq!(profile.classify(42), SyscallDecision::Allow);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod stub_impl {
    use std::os::fd::OwnedFd;
    use std::sync::Arc;

    use tokio::sync::RwLock;

    #[derive(Debug, Clone, Default)]
    pub struct SeccompDecisionProfile;

    pub fn spawn_notifier(
        _notif_fd: OwnedFd,
        _profile: Arc<RwLock<SeccompDecisionProfile>>,
    ) -> tokio::task::JoinHandle<Result<(), anyhow::Error>> {
        tokio::spawn(async { Ok(()) })
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(not(target_os = "linux"))]
pub use stub_impl::*;
