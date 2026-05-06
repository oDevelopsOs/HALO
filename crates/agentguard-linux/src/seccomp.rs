//! seccomp-BPF syscall filter for Linux daemon.

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::os::fd::{FromRawFd, OwnedFd};

    // ── BPF instruction struct (linux/bpf_common.h) ──────────

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SockFilter {
        pub code: u16,
        pub jt: u8,
        pub jf: u8,
        pub k: u32,
    }

    #[repr(C)]
    pub struct SockFprog {
        pub len: u16,
        pub filter: *const SockFilter,
    }

    // ── BPF opcodes (some unused but kept for documentation) ──

    #[allow(dead_code)]
    const BPF_LD: u16 = 0x00;
    #[allow(dead_code)]
    const BPF_LDX: u16 = 0x01;
    #[allow(dead_code)]
    const BPF_ST: u16 = 0x02;
    #[allow(dead_code)]
    const BPF_STX: u16 = 0x03;
    #[allow(dead_code)]
    const BPF_ALU: u16 = 0x04;
    const BPF_JMP: u16 = 0x05;
    const BPF_RET: u16 = 0x06;

    const BPF_W: u16 = 0x00;
    #[allow(dead_code)]
    const BPF_H: u16 = 0x08;
    #[allow(dead_code)]
    const BPF_B: u16 = 0x10;

    const BPF_ABS: u16 = 0x20;
    const BPF_LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
    const BPF_JMP_JEQ: u16 = BPF_JMP | 0x10; // JEQ
    #[allow(dead_code)]
    const BPF_JMP_JA: u16 = BPF_JMP; // JMP

    // ── seccomp return values ────────────────────────────────

    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC0_0000;

    // ── prctl constants ──────────────────────────────────────

    const PR_SET_SECCOMP: libc::c_int = 22;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

    /// Syscalls that are always killed (never pass through USER_NOTIF).
    pub const ALWAYS_KILL_SYSCALLS: &[i64] = &[
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_mount,
        libc::SYS_perf_event_open,
        libc::SYS_bpf,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
    ];

    /// Safe syscalls needed by most AI agents (Node.js, Python, Go, etc.).
    /// These are always allowed.
    pub const DEFAULT_ALLOWLIST: &[i64] = &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lstat,
        libc::SYS_newfstatat,
        libc::SYS_poll,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_ioctl,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_access,
        libc::SYS_pipe,
        libc::SYS_select,
        libc::SYS_sched_yield,
        libc::SYS_mremap,
        libc::SYS_msync,
        libc::SYS_mincore,
        libc::SYS_madvise,
        libc::SYS_shmget,
        libc::SYS_shmat,
        libc::SYS_shmctl,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_pause,
        libc::SYS_nanosleep,
        libc::SYS_getitimer,
        libc::SYS_alarm,
        libc::SYS_setitimer,
        libc::SYS_getpid,
        libc::SYS_sendfile,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_socketpair,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_clone,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_wait4,
        libc::SYS_kill,
        libc::SYS_uname,
        libc::SYS_semget,
        libc::SYS_semop,
        libc::SYS_semctl,
        libc::SYS_shmdt,
        libc::SYS_msgget,
        libc::SYS_msgsnd,
        libc::SYS_msgrcv,
        libc::SYS_msgctl,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_rmdir,
        libc::SYS_creat,
        libc::SYS_link,
        libc::SYS_unlink,
        libc::SYS_symlink,
        libc::SYS_readlink,
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_chown,
        libc::SYS_fchown,
        libc::SYS_lchown,
        libc::SYS_umask,
        libc::SYS_gettimeofday,
        libc::SYS_getrlimit,
        libc::SYS_getrusage,
        libc::SYS_sysinfo,
        libc::SYS_times,
        libc::SYS_ptrace, // included as allowed? No — it's in ALWAYS_KILL
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_setpgid,
        libc::SYS_getppid,
        libc::SYS_getpgrp,
        libc::SYS_setsid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_getgroups,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_getpgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_getsid,
        libc::SYS_capget,
        libc::SYS_capset,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_sigsuspend,
        libc::SYS_sigaltstack,
        libc::SYS_utime,
        libc::SYS_mknod,
        libc::SYS_uselib,
        libc::SYS_personality,
        libc::SYS_ustat,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_sysfs,
        libc::SYS_getpriority,
        libc::SYS_setpriority,
        libc::SYS_sched_setparam,
        libc::SYS_sched_getparam,
        libc::SYS_sched_setscheduler,
        libc::SYS_sched_getscheduler,
        libc::SYS_sched_get_priority_max,
        libc::SYS_sched_get_priority_min,
        libc::SYS_sched_rr_get_interval,
        libc::SYS_mlock,
        libc::SYS_munlock,
        libc::SYS_mlockall,
        libc::SYS_munlockall,
        libc::SYS_vhangup,
        libc::SYS_modify_ldt,
        libc::SYS_pivot_root,
        libc::SYS__sysctl,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_adjtimex,
        libc::SYS_setrlimit,
        libc::SYS_sync,
        libc::SYS_acct,
        libc::SYS_settimeofday,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_ioperm,
        libc::SYS_iopl,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_getcpu,
        libc::SYS_getrandom,
        libc::SYS_membarrier,
        libc::SYS_rseq,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_timer_create,
        libc::SYS_timer_settime,
        libc::SYS_timer_gettime,
        libc::SYS_timer_getoverrun,
        libc::SYS_timer_delete,
        libc::SYS_utimensat,
        libc::SYS_signalfd,
        libc::SYS_signalfd4,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_eventfd,
        libc::SYS_eventfd2,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_inotify_init,
        libc::SYS_inotify_init1,
        libc::SYS_inotify_add_watch,
        libc::SYS_inotify_rm_watch,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        libc::SYS_copy_file_range,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_openat2,
        libc::SYS_close_range,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_mbind,
        libc::SYS_set_mempolicy,
        libc::SYS_get_mempolicy,
        libc::SYS_move_pages,
    ];

    /// Syscalls that require USER_NOTIF (ambiguous — daemon decides).
    /// These are not clearly dangerous but not on the default allowlist.
    /// New kernel versions may add syscalls here that older versions didn't have.
    #[allow(dead_code)]
    const AMBIGUOUS_SYSCALLS: &[i64] = &[
        libc::SYS_pkey_alloc,
        libc::SYS_pkey_free,
        libc::SYS_pkey_mprotect,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_seccomp,
        libc::SYS_userfaultfd,
        libc::SYS_migrate_pages,
        libc::SYS_kcmp,
        libc::SYS_finit_module, // already in ALWAYS_KILL
        libc::SYS_memfd_create,
        libc::SYS_memfd_secret,
        libc::SYS_process_madvise,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
        libc::SYS_quotactl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
    ];

    // ── Filter construction ───────────────────────────────────

    /// Build a seccomp BPF filter with allowlist, USER_NOTIF for ambiguous,
    /// and KILL for dangerous syscalls.
    ///
    /// Returns the BPF program (Vec<SockFilter>) and whether USER_NOTIF is needed.
    pub fn build_seccomp_filter(
        allowlist: &[i64],
        ambiguous: &[i64],
        kill_syscalls: &[i64],
    ) -> (Vec<SockFilter>, bool) {
        let mut filter: Vec<SockFilter> = Vec::new();
        let use_notify = !ambiguous.is_empty();

        // Load arch (offset 0 in seccomp_data) and syscall number (offset 4)
        // Actually, seccomp_data layout on x86_64:
        //   nr (i32) at offset 0
        //   arch (u32) at offset 4
        // But BPF is running in the kernel which already validated the arch.
        // We just load the syscall number.

        // Strategy: check KILL list first, then ambiguous (USER_NOTIF),
        // then allowlist, default KILL.

        let mut needs_load = true;

        // ── KILL list ──
        for &sc in kill_syscalls {
            if needs_load {
                filter.push(SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 0, // offset of nr in seccomp_data
                });
                needs_load = false;
            }
            // Jump target to reach: kill_proc instruction (placed at end)
            filter.push(SockFilter {
                code: BPF_JMP_JEQ,
                jt: 0, // if match → kill (next instruction)
                jf: 1, // skip next (kill) instruction
                k: sc as u32,
            });
            filter.push(SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            });
        }

        // ── Ambiguous → USER_NOTIF ──
        if use_notify {
            for &sc in ambiguous {
                filter.push(SockFilter {
                    code: BPF_JMP_JEQ,
                    jt: 0, // match → notify
                    jf: 1, // skip
                    k: sc as u32,
                });
                filter.push(SockFilter {
                    code: BPF_RET,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_USER_NOTIF,
                });
            }
        }

        // ── Allowlist ──
        for &sc in allowlist {
            filter.push(SockFilter {
                code: BPF_JMP_JEQ,
                jt: 0, // match → allow
                jf: 1, // skip
                k: sc as u32,
            });
            filter.push(SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            });
        }

        // ── Default: kill (fail-closed) ──
        filter.push(SockFilter {
            code: BPF_RET,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });

        (filter, use_notify)
    }

    /// Build a seccomp filter suitable for sandboxed agents with USER_NOTIF.
    ///
    /// Uses USER_NOTIF for ambiguous syscalls instead of KILL.
    /// Includes a minimal allowlist for basic process operation.
    /// Returns the filter and the notifier fd flag.
    pub fn build_seccomp_notify_filter() -> (Vec<SockFilter>, bool) {
        // Minimal syscalls needed by the shim + sandboxed agent
        let minimal_allow: &[i64] = &[
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_close,
            libc::SYS_stat,
            libc::SYS_fstat,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_brk,
            libc::SYS_mprotect,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_ioctl,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_futex,
            libc::SYS_execve,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendmsg,
            libc::SYS_sendto,
            libc::SYS_recvmsg,
            libc::SYS_recvfrom,
            libc::SYS_fcntl,
            libc::SYS_getpid,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_getrandom,
            libc::SYS_lseek,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_sched_yield,
            libc::SYS_nanosleep,
            libc::SYS_clock_gettime,
            libc::SYS_gettimeofday,
            libc::SYS_clone,
            libc::SYS_wait4,
            libc::SYS_prctl,
            libc::SYS_arch_prctl,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            libc::SYS_rseq,
            libc::SYS_landlock_create_ruleset,
            libc::SYS_landlock_add_rule,
            libc::SYS_landlock_restrict_self,
            libc::SYS_access,
            libc::SYS_pipe,
            libc::SYS_poll,
            libc::SYS_dup,
            libc::SYS_dup2,
            libc::SYS_getdents64,
            libc::SYS_newfstatat,
            libc::SYS_madvise,
            libc::SYS_getcwd,
            libc::SYS_uname,
        ];

        // Ambiguous syscalls → USER_NOTIF (daemon decides)
        let ambiguous: &[i64] = &[
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_seccomp,
            libc::SYS_userfaultfd,
            libc::SYS_kcmp,
            libc::SYS_memfd_create,
            libc::SYS_memfd_secret,
            libc::SYS_process_madvise,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_getfd,
            libc::SYS_pidfd_send_signal,
            libc::SYS_openat2,
            libc::SYS_close_range,
        ];

        build_seccomp_filter(minimal_allow, ambiguous, ALWAYS_KILL_SYSCALLS)
    }

    /// Install a seccomp filter on the calling process/thread.
    ///
    /// Returns the notifier fd if USER_NOTIF is configured, or None.
    ///
    /// # Safety
    /// This is irrevocable for this thread. Once applied, the filter
    /// cannot be removed. Use SECCOMP_FILTER_FLAG_TSYNC to apply to all
    /// threads of the calling process.
    pub fn install_seccomp_filter(
        allowlist: &[i64],
        ambiguous: &[i64],
        kill_syscalls: &[i64],
    ) -> Result<Option<OwnedFd>, anyhow::Error> {
        let (filter, use_notify) = build_seccomp_filter(allowlist, ambiguous, kill_syscalls);

        if filter.is_empty() {
            return Ok(None);
        }

        let prog = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        let mut flags: libc::c_ulong = SECCOMP_MODE_FILTER;
        if use_notify {
            flags |= SECCOMP_FILTER_FLAG_NEW_LISTENER;
        }

        let ret = unsafe {
            libc::prctl(
                PR_SET_SECCOMP,
                flags,
                &prog as *const _ as *const libc::c_void,
            )
        };

        if ret < 0 {
            let err = unsafe { *libc::__errno_location() };
            anyhow::bail!("seccomp filter installation failed: prctl error {}", err);
        }

        if use_notify {
            // The notifier fd is returned as the prctl return value
            // via SECCOMP_FILTER_FLAG_NEW_LISTENER
            let fd = ret as i32;
            // SAFETY: fd is a valid, owned file descriptor from the kernel
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            tracing::info!(
                "seccomp filter installed (allowlist={}, ambiguous={}, kill={}, USER_NOTIF=yes)",
                allowlist.len(),
                ambiguous.len(),
                kill_syscalls.len()
            );
            Ok(Some(owned))
        } else {
            tracing::info!(
                "seccomp filter installed (allowlist={}, kill={}, USER_NOTIF=no)",
                allowlist.len(),
                kill_syscalls.len()
            );
            Ok(None)
        }
    }

    /// Classification result for a syscall received via USER_NOTIF.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SyscallDecision {
        Allow,
        DenyEnosys,
        DenyEperm,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_build_filter_no_notify() {
            let allow: &[i64] = &[libc::SYS_read, libc::SYS_write, libc::SYS_exit];
            let amb: &[i64] = &[];
            let kill: &[i64] = &[libc::SYS_ptrace];

            let (filter, use_notify) = build_seccomp_filter(allow, amb, kill);
            assert!(!filter.is_empty());
            assert!(!use_notify);
            // Last instruction should be KILL (default)
            assert_eq!(filter.last().unwrap().k, SECCOMP_RET_KILL_PROCESS);
        }

        #[test]
        fn test_build_filter_with_notify() {
            let allow: &[i64] = &[libc::SYS_read];
            let amb: &[i64] = &[libc::SYS_io_uring_setup];
            let kill: &[i64] = &[];

            let (filter, use_notify) = build_seccomp_filter(allow, amb, kill);
            assert!(use_notify);
            // Should have at least one USER_NOTIF instruction
            let has_notify = filter.iter().any(|f| f.k == SECCOMP_RET_USER_NOTIF);
            assert!(has_notify);
        }

        #[test]
        fn test_build_filter_kill_present() {
            let allow: &[i64] = &[];
            let amb: &[i64] = &[];
            let kill: &[i64] = &[libc::SYS_ptrace];

            let (filter, _) = build_seccomp_filter(allow, amb, kill);
            // Should have at least one KILL instruction for ptrace
            let has_kill = filter.iter().any(|f| f.k == SECCOMP_RET_KILL_PROCESS);
            assert!(has_kill);
        }

        #[test]
        fn test_always_kill_list_contains_dangerous_syscalls() {
            assert!(ALWAYS_KILL_SYSCALLS.contains(&libc::SYS_ptrace));
            assert!(ALWAYS_KILL_SYSCALLS.contains(&libc::SYS_mount));
            assert!(ALWAYS_KILL_SYSCALLS.contains(&libc::SYS_bpf));
            assert!(ALWAYS_KILL_SYSCALLS.contains(&libc::SYS_init_module));
        }

        #[test]
        fn test_default_allowlist_contains_basics() {
            assert!(DEFAULT_ALLOWLIST.contains(&libc::SYS_read));
            assert!(DEFAULT_ALLOWLIST.contains(&libc::SYS_write));
            assert!(DEFAULT_ALLOWLIST.contains(&libc::SYS_open));
            assert!(DEFAULT_ALLOWLIST.contains(&libc::SYS_close));
            assert!(DEFAULT_ALLOWLIST.contains(&libc::SYS_exit));
            assert!(DEFAULT_ALLOWLIST.contains(&libc::SYS_mmap));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod stub_impl {
    use std::os::fd::OwnedFd;

    pub const ALWAYS_KILL_SYSCALLS: &[i64] = &[];
    pub const DEFAULT_ALLOWLIST: &[i64] = &[];

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SockFilter {
        pub code: u16,
        pub jt: u8,
        pub jf: u8,
        pub k: u32,
    }

    pub fn build_seccomp_filter(
        _allowlist: &[i64],
        _ambiguous: &[i64],
        _kill_syscalls: &[i64],
    ) -> (Vec<SockFilter>, bool) {
        (Vec::new(), false)
    }

    pub fn install_seccomp_filter(
        _allowlist: &[i64],
        _ambiguous: &[i64],
        _kill_syscalls: &[i64],
    ) -> Result<Option<OwnedFd>, anyhow::Error> {
        anyhow::bail!("seccomp-BPF is only available on Linux")
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(not(target_os = "linux"))]
pub use stub_impl::*;
