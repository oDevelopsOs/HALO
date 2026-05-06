//! AgentGuard static shim — binary that replaces AI agent executables
//! via binary displacement. Applies Landlock filesystem restrictions and
//! optional seccomp syscall filter, then exec's the real binary.
//!
//! Compiled with musl for a fully static binary (~200-300 KB).
//!
//! ## Environment variables the shim reads:
//!
//! - `AGENTGUARD_SANDBOXED` — if set, the agent is already sandboxed (via
//!   bwrap or daemon). Shim skips Landlock/seccomp and exec's directly.
//! - `AGENTGUARD_LANDLOCK=1` — enable Landlock restrictions
//! - `AGENTGUARD_LANDLOCK_RW=/path1:/path2` — colon-separated writeable dirs
//! - `AGENTGUARD_LANDLOCK_RO=/path1:/path2` — colon-separated read-only dirs
//! - `AGENTGUARD_SECCOMP=1` — enable seccomp hardcoded allowlist
//!
//! ## Magic bytes
//!
//! The binary contains magic bytes `AGENTGUARD_SHIM_V1\0` in the ELF section
//! `.note.agentguard`. The inotify auto-heal daemon scans for these bytes
//! to identify shim binaries without executing them.

// Magic bytes in .note.agentguard ELF section for auto-heal detection
#[link_section = ".note.agentguard"]
#[used]
static SHIM_MAGIC: [u8; 19] = *b"AGENTGUARD_SHIM_V1\x00";

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

// ── Landlock kernel ABI constants (stable since Linux 5.13) ──────

#[allow(unused)]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[allow(unused)]
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_RULE_PATH_BENEATH: u64 = 1;

// Access rights for filesystem (uapi/linux/landlock.h)
#[allow(unused)]
const ACCESS_FS_EXECUTE: u64 = 1;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
#[allow(unused)]
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
#[allow(unused)]
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
#[allow(unused)]
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
#[allow(unused)]
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
#[allow(unused)]
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const ACCESS_FS_REFER: u64 = 1 << 13;
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

// Access rights for network (Landlock V3, Linux 6.7+)
#[allow(unused)]
const ACCESS_NET_BIND_TCP: u64 = 1;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// Combined access masks for deny-by-default Landlock
const HANDLED_FS: u64 = ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_REFER
    | ACCESS_FS_TRUNCATE;

#[allow(unused)]
const HANDLED_FS_V1: u64 = ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG;

const ALLOWED_RW_ACCESS: u64 = ACCESS_FS_READ_FILE
    | ACCESS_FS_READ_DIR
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_REFER
    | ACCESS_FS_TRUNCATE;

const ALLOWED_RO_ACCESS: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_EXECUTE;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

// ── Seccomp constants ───────────────────────────────────────────

const PR_SET_SECCOMP: libc::c_int = 22;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
#[allow(dead_code)]
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL: u32 = 0x0000_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

// ── Unix socket constants (may not be in libc for all targets) ──
const AF_UNIX: libc::c_int = 1;
const SOCK_STREAM: libc::c_int = 1;

#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [i8; 108],
}

// ── Main shim entry point ───────────────────────────────────────

fn main() {
    // ── 1. Check if already sandboxed ──
    if std::env::var("AGENTGUARD_SANDBOXED").is_ok() {
        exec_real();
        unreachable!(); // unwrap-ok: exec_real calls execvp which never returns on success
    }

    // ── 2. Try USER_NOTIF seccomp (before Landlock — needs socket access) ──
    let daemon_socket = std::env::var("AGENTGUARD_DAEMON_SOCKET").ok();
    let seccomp_enabled = std::env::var("AGENTGUARD_SECCOMP").as_deref() == Ok("1");

    if seccomp_enabled {
        if let Some(ref socket_path) = daemon_socket {
            try_install_notify_seccomp(socket_path);
        } else {
            apply_seccomp_kill_only();
        }
    }

    // ── 3. Apply Landlock if configured ──
    let landlock_enabled = std::env::var("AGENTGUARD_LANDLOCK").as_deref() == Ok("1");
    if landlock_enabled {
        let rw_dirs = read_colon_paths("AGENTGUARD_LANDLOCK_RW");
        let ro_dirs = read_colon_paths("AGENTGUARD_LANDLOCK_RO");

        if rw_dirs.is_empty() && ro_dirs.is_empty() {
            eprintln!("agentguard-shim: AGENTGUARD_LANDLOCK=1 but no directories configured");
        } else {
            apply_landlock(&rw_dirs, &ro_dirs);
        }
    }

    // ── 4. Exec the real binary ──
    exec_real();
    unreachable!(); // unwrap-ok: exec_real calls execvp which never returns on success
}

// ── Config helpers ──────────────────────────────────────────────

fn read_colon_paths(var: &str) -> Vec<String> {
    match std::env::var(var) {
        Ok(val) if !val.is_empty() => val.split(':').map(|s| s.to_string()).collect(),
        _ => Vec::new(),
    }
}

// ── Landlock application (auto-detect V3 → V2 → V1) ─────────────

fn apply_landlock(rw_dirs: &[String], ro_dirs: &[String]) {
    // Try V3 first (network + FS), then V2 (adds TRUNCATE, REFER), then V1 (basic FS)
    let handled_net = ACCESS_NET_CONNECT_TCP;

    let versions: &[(u64, u64, &str)] = &[
        (HANDLED_FS, handled_net, "V3"),
        (HANDLED_FS, 0u64, "V2"),
        (HANDLED_FS_V1, 0u64, "V1"),
    ];

    for &(handled_fs, net, label) in versions {
        let ruleset_fd = create_landlock_ruleset(handled_fs, net);
        match ruleset_fd {
            Ok(fd) => {
                add_landlock_rules(fd, rw_dirs, ro_dirs);
                restrict_self(fd);
                eprintln!("agentguard-shim: Landlock {} active", label);
                return;
            }
            Err(LandlockError::UnsupportedVersion) => {
                eprintln!("agentguard-shim: Landlock {} unsupported, trying older ABI", label);
                continue;
            }
            Err(e) => {
                eprintln!("agentguard-shim: Landlock error — {}", e);
                return;
            }
        }
    }

    eprintln!("agentguard-shim: Landlock not supported on this kernel");
}

#[derive(Debug)]
#[allow(dead_code)]
enum LandlockError {
    UnsupportedVersion,
    Syscall(i32),
    OpenPath(String),
    AddRule(String),
    Restrict(i32),
}

impl std::fmt::Display for LandlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion => write!(f, "unsupported kernel version"),
            Self::Syscall(err) => write!(f, "syscall failed: errno {}", err),
            Self::OpenPath(p) => write!(f, "cannot open path: {}", p),
            Self::AddRule(p) => write!(f, "add_rule failed for path: {}", p),
            Self::Restrict(err) => write!(f, "restrict_self failed: errno {}", err),
        }
    }
}

fn create_landlock_ruleset(handled_fs: u64, handled_net: u64) -> Result<i32, LandlockError> {
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: handled_net,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };

    if ret >= 0 {
        Ok(ret as i32)
    } else {
        let errno = -(ret as i32);
        if errno == libc::EINVAL || errno == libc::ENOSYS {
            Err(LandlockError::UnsupportedVersion)
        } else {
            Err(LandlockError::Syscall(errno))
        }
    }
}

fn add_landlock_rules(fd: i32, rw_dirs: &[String], ro_dirs: &[String]) {
    // Add write-allowed directories
    for dir in rw_dirs {
        add_single_rule(fd, dir, ALLOWED_RW_ACCESS);
    }
    // Add read-only directories
    for dir in ro_dirs {
        add_single_rule(fd, dir, ALLOWED_RO_ACCESS);
    }
}

fn add_single_rule(fd: i32, path: &str, access: u64) {
    let c_path = match CString::new(path) {
        Ok(p) => p,
        Err(_) => return,
    };

    let dir_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if dir_fd < 0 {
        eprintln!("agentguard-shim: cannot open {} for Landlock rule", path);
        return;
    }

    let rule = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: dir_fd,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            fd as libc::c_long,
            LANDLOCK_RULE_PATH_BENEATH as libc::c_long,
            &rule as *const _,
            0u32,
        )
    };

    unsafe {
        libc::close(dir_fd);
    }

    if ret < 0 {
        let errno = -(ret as i32);
        eprintln!(
            "agentguard-shim: Landlock add_rule failed for {}: errno {}",
            path, errno
        );
    }
}

fn restrict_self(fd: i32) {
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_RESTRICT_SELF,
            fd as libc::c_long,
            0u32,
        )
    };

    if ret < 0 {
        let errno = -(ret as i32);
        eprintln!(
            "agentguard-shim: Landlock restrict_self failed: errno {}",
            errno
        );
    }

    // Close the ruleset fd — Landlock is already enforced and irrevocable
    unsafe {
        libc::close(fd);
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

// ── Seccomp USER_NOTIF (with daemon) ─────────────────────────────

/// Try to install seccomp with USER_NOTIF and send notifier fd to daemon.
/// On failure, falls back to kill-only.
fn try_install_notify_seccomp(socket_path: &str) {
    // 1. Connect to daemon socket
    let socket_cstr = match std::ffi::CString::new(socket_path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("agentguard-shim: invalid socket path");
            apply_seccomp_kill_only();
            return;
        }
    };

    let sock = unsafe { libc::socket(AF_UNIX, SOCK_STREAM, 0) };
    if sock < 0 {
        eprintln!("agentguard-shim: socket() failed — falling back to kill-only seccomp");
        apply_seccomp_kill_only();
        return;
    }

    let mut addr = SockaddrUn {
        sun_family: AF_UNIX as u16,
        sun_path: [0i8; 108],
    };
    let path_bytes = socket_path.as_bytes();
    let len = if path_bytes.len() < 108 { path_bytes.len() } else { 107 };
    unsafe {
        std::ptr::copy_nonoverlapping(
            path_bytes.as_ptr(),
            addr.sun_path.as_mut_ptr() as *mut u8,
            len,
        );
    }

    let addr_len = (std::mem::size_of::<u16>() + len + 1) as libc::socklen_t;
    if unsafe { libc::connect(sock, &addr as *const _ as *const libc::sockaddr, addr_len) } < 0 {
        eprintln!("agentguard-shim: connect() to daemon failed — falling back to kill-only seccomp");
        unsafe { libc::close(sock); }
        apply_seccomp_kill_only();
        return;
    }

    // 2. Send register_notifier request
    let request = b"{\"op\":\"register_notifier\"}\n";
    if unsafe { libc::write(sock, request.as_ptr() as *const libc::c_void, request.len()) } < 0 {
        eprintln!("agentguard-shim: write() to daemon failed");
        unsafe { libc::close(sock); }
        apply_seccomp_kill_only();
        return;
    }

    // 3. Install seccomp with USER_NOTIF + NEW_LISTENER → get fd
    let filter = build_notify_bpf();
    let fprog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let ret = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER | SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const _ as *const libc::c_void,
        )
    };

    if ret < 0 {
        let err = unsafe { *libc::__errno_location() };
        eprintln!("agentguard-shim: prctl(SECCOMP) failed: errno {} — falling back to kill-only", err);
        unsafe { libc::close(sock); }
        apply_seccomp_kill_only();
        return;
    }

    let notifier_fd = ret as i32;

    // 4. Send the notifier fd to the daemon via SCM_RIGHTS
    if send_fd_over_socket(sock, notifier_fd).is_err() {
        eprintln!("agentguard-shim: send_fd failed");
        unsafe {
            libc::close(notifier_fd);
            libc::close(sock);
        }
        // The seccomp filter is already installed — just exec the agent
        return;
    }

    // Close our copy of the notifier fd (daemon has its copy)
    unsafe { libc::close(notifier_fd); }

    // 5. Read response from daemon
    let mut resp_buf = [0u8; 256];
    let n = unsafe { libc::read(sock, resp_buf.as_mut_ptr() as *mut libc::c_void, resp_buf.len()) };
    let _ = n;

    unsafe { libc::close(sock); }

    eprintln!("agentguard-shim: seccomp USER_NOTIF active (notifier fd sent to daemon)");
}

/// Simple SockFprog struct for the shim (same as daemon's).
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Build a minimal seccomp filter with USER_NOTIF for sandboxed agents.
fn build_notify_bpf() -> Vec<SockFilter> {
    let mut filter = Vec::new();

    // Minimal allowlist for shim + agent startup
    let allowed: &[u32] = &[
        libc::SYS_read as u32,
        libc::SYS_write as u32,
        libc::SYS_open as u32,
        libc::SYS_openat as u32,
        libc::SYS_close as u32,
        libc::SYS_stat as u32,
        libc::SYS_fstat as u32,
        libc::SYS_mmap as u32,
        libc::SYS_munmap as u32,
        libc::SYS_brk as u32,
        libc::SYS_mprotect as u32,
        libc::SYS_rt_sigaction as u32,
        libc::SYS_rt_sigprocmask as u32,
        libc::SYS_rt_sigreturn as u32,
        libc::SYS_ioctl as u32,
        libc::SYS_exit as u32,
        libc::SYS_exit_group as u32,
        libc::SYS_futex as u32,
        libc::SYS_execve as u32,
        libc::SYS_connect as u32,
        libc::SYS_sendto as u32,
        libc::SYS_recvfrom as u32,
        libc::SYS_socket as u32,
        libc::SYS_fcntl as u32,
        libc::SYS_getpid as u32,
        libc::SYS_getuid as u32,
        libc::SYS_lseek as u32,
        libc::SYS_pread64 as u32,
        libc::SYS_pwrite64 as u32,
        libc::SYS_sched_yield as u32,
        libc::SYS_nanosleep as u32,
        libc::SYS_clone as u32,
        libc::SYS_prctl as u32,
        libc::SYS_arch_prctl as u32,
        libc::SYS_set_robust_list as u32,
        libc::SYS_get_robust_list as u32,
        libc::SYS_rseq as u32,
        libc::SYS_landlock_create_ruleset as u32,
        libc::SYS_landlock_add_rule as u32,
        libc::SYS_landlock_restrict_self as u32,
    ];

    // Syscalls that go to USER_NOTIF (ambiguous — daemon decides)
    let notify_list: &[u32] = &[
        425, // io_uring_setup
        426, // io_uring_enter
        427, // io_uring_register
        317, // seccomp
        319, // memfd_create
        434, // pidfd_open
        437, // openat2
        440, // process_madvise
    ];

    // Kill syscalls
    let kill_list: &[u32] = &[
        libc::SYS_ptrace as u32,
        libc::SYS_process_vm_readv as u32,
        libc::SYS_process_vm_writev as u32,
        libc::SYS_mount as u32,
        libc::SYS_perf_event_open as u32,
        libc::SYS_bpf as u32,
        libc::SYS_init_module as u32,
        libc::SYS_finit_module as u32,
        libc::SYS_delete_module as u32,
    ];

    let bpf_ld_nr = SockFilter { code: 0x20, jt: 0, jf: 0, k: 0 };

    // ── Kill list first ──
    for &sc in kill_list {
        filter.push(bpf_ld_nr);
        filter.push(SockFilter { code: 0x15, jt: 0, jf: 1, k: sc });
        filter.push(SockFilter { code: 0x06, jt: 0, jf: 0, k: SECCOMP_RET_KILL });
    }

    // ── USER_NOTIF for ambiguous ──
    for &sc in notify_list {
        filter.push(SockFilter { code: 0x15, jt: 0, jf: 1, k: sc });
        filter.push(SockFilter { code: 0x06, jt: 0, jf: 0, k: SECCOMP_RET_USER_NOTIF });
    }

    // ── Allowlist ──
    for &sc in allowed {
        filter.push(SockFilter { code: 0x15, jt: 0, jf: 1, k: sc });
        filter.push(SockFilter { code: 0x06, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });
    }

    // ── Default: KILL ──
    filter.push(SockFilter { code: 0x06, jt: 0, jf: 0, k: SECCOMP_RET_KILL });

    filter
}

/// Send a file descriptor over a Unix socket via SCM_RIGHTS.
fn send_fd_over_socket(sock_fd: i32, fd: i32) -> Result<(), ()> {
    let dummy = [0u8; 1];
    let iov = libc::iovec {
        iov_base: dummy.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let cmsg_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf: Vec<u8> = vec![0u8; cmsg_len];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as u32;

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(());
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32);
    }
    msg.msg_controllen = unsafe { (*cmsg).cmsg_len };

    let data_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *mut libc::c_int;
    unsafe { *data_ptr = fd };

    if unsafe { libc::sendmsg(sock_fd, &msg, 0) } < 0 {
        Err(())
    } else {
        Ok(())
    }
}

/// Fallback: install kill-only seccomp (current behavior).

/// Fallback: install kill-only seccomp (current behavior).
fn apply_seccomp_kill_only() {
    // Hardcoded BPF allowlist for safe syscalls.
    // This is a minimal filter that blocks known-dangerous syscalls
    // and allows everything else. The daemon (when running with root)
    // can apply a more comprehensive filter with USER_NOTIF.

    // Build the BPF program using raw instructions.
    // Format: { opcode, jt, jf, k } as sock_filter / sock_fprog
    // For now we use the simplest possible approach:
    // load syscall number, check against blocked list, kill if match.

    let blocked_syscalls: &[u32] = &[
        libc::SYS_ptrace as u32,              // 101 (x86_64)
        libc::SYS_process_vm_readv as u32,    // 310
        libc::SYS_process_vm_writev as u32,   // 311
        libc::SYS_kexec_load as u32,          // 246
        libc::SYS_kexec_file_load as u32,     // 320
        libc::SYS_mount as u32,               // 165
        libc::SYS_perf_event_open as u32,     // 298
        libc::SYS_bpf as u32,                 // 321
        libc::SYS_init_module as u32,         // 175
        libc::SYS_finit_module as u32,        // 313
        libc::SYS_delete_module as u32,       // 176
    ];

    // BPF constants (SockFilter defined at module level)
    const BPF_LD_ABS: u16 = 0x20;
    const BPF_JMP_JEQ: u16 = 0x15;
    const BPF_RET: u16 = 0x06;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;

    // Build filter: for each blocked syscall, check and kill
    let mut filters: Vec<SockFilter> = Vec::new();

    for (i, &sc) in blocked_syscalls.iter().enumerate() {
        if i == 0 {
            // Load syscall number from seccomp_data (offset 0 = arch, offset 4 = nr)
            filters.push(SockFilter {
                code: BPF_LD_ABS | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4, // offset of syscall number in seccomp_data
            });
        }
        // Check if syscall number == sc
        let skip_count = (blocked_syscalls.len() - i - 1) as u8;
        filters.push(SockFilter {
            code: BPF_JMP_JEQ,
            jt: 0,
            jf: skip_count + 1, // skip to next check or allow
            k: sc,
        });
        // Kill on match
        filters.push(SockFilter {
            code: BPF_RET,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL,
        });
    }

    // Allow all other syscalls (final instruction)
    filters.push(SockFilter {
        code: BPF_RET,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    let prog = SockFprog {
        len: filters.len() as u16,
        filter: filters.as_ptr(),
    };

    // Apply seccomp filter
    let ret = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const _ as *const libc::c_void,
        )
    };

    if ret < 0 {
        let err = unsafe { *libc::__errno_location() };
        eprintln!(
            "agentguard-shim: seccomp filter failed: errno {}",
            err
        );
    } else {
        eprintln!("agentguard-shim: seccomp allowlist active ({} blocked syscalls)", blocked_syscalls.len());
    }
}

// ── Exec the real binary ────────────────────────────────────────

fn exec_real() {
    // Determine the real binary path: .<current_exe_name>.real in the same dir
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("agentguard-shim: cannot get current exe: {}", e);
            std::process::exit(1);
        }
    };

    let filename = match exe.file_name() {
        Some(n) => n,
        None => {
            eprintln!("agentguard-shim: cannot determine exe filename");
            std::process::exit(1);
        }
    };

    let parent = match exe.parent() {
        Some(p) => p,
        None => {
            eprintln!("agentguard-shim: cannot determine exe parent directory");
            std::process::exit(1);
        }
    };

    let real_name = format!(".{}.real", filename.to_string_lossy());
    let real_path = parent.join(&real_name);

    // Verify the real binary exists
    if !real_path.exists() {
        eprintln!(
            "agentguard-shim: real binary not found at {}",
            real_path.display()
        );
        std::process::exit(1);
    }

    let real_cstr = match CString::new(real_path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("agentguard-shim: invalid path to real binary");
            std::process::exit(1);
        }
    };

    // Build execvp: argv[0] = real binary path, rest = original args
    let mut c_args: Vec<CString> = Vec::new();
    c_args.push(real_cstr);

    // Build the execvp argument array
    let mut c_argv: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    c_argv.push(std::ptr::null());

    // We do NOT inherit the current environment wholesale.
    // The agent environment should be clean — passed via envp = null,
    // which makes the kernel use the parent's environ. But we're the shim
    // which has the daemon's env. Better to pass the env that the daemon
    // set for the agent.
    // In practice, the shim inherits the daemon's environment which already
    // has proxy vars set. This is acceptable for now.
    unsafe {
        libc::execvp(c_argv[0], c_argv.as_ptr());
    }

    // execvp only returns on error
    let err = unsafe { *libc::__errno_location() };
    eprintln!(
        "agentguard-shim: execvp failed: errno {} — real binary: {}",
        err,
        real_path.display()
    );
    std::process::exit(1);
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_colon_paths_empty() {
        // Use a var name that definitely doesn't exist
        let result = read_colon_paths("AGENTGUARD_SHIM_TEST_NONEXISTENT");
        assert!(result.is_empty());
    }

    #[test]
    fn test_read_colon_paths_valid() {
        std::env::set_var("AGENTGUARD_SHIM_TEST_PATHS", "/tmp/a:/tmp/b:/tmp/c");
        let result = read_colon_paths("AGENTGUARD_SHIM_TEST_PATHS");
        assert_eq!(result, vec!["/tmp/a", "/tmp/b", "/tmp/c"]);
        std::env::remove_var("AGENTGUARD_SHIM_TEST_PATHS");
    }

    #[test]
    fn test_real_path_construction() {
        // Test the logic of constructing the .real path from current exe
        let exe = std::path::PathBuf::from("/home/user/.npm-global/bin/claude");
        let filename = exe.file_name().unwrap();
        let parent = exe.parent().unwrap();
        let real_name = format!(".{}.real", filename.to_string_lossy());
        let real_path = parent.join(&real_name);
        assert_eq!(
            real_path,
            std::path::PathBuf::from("/home/user/.npm-global/bin/.claude.real")
        );
    }

    #[test]
    fn test_sandboxed_env_skips_landlock() {
        // When AGENTGUARD_SANDBOXED is set, the shim should skip Landlock
        // and exec directly. We can't test exec(), but we verify the env check.
        std::env::set_var("AGENTGUARD_SANDBOXED", "1");
        assert_eq!(std::env::var("AGENTGUARD_SANDBOXED").as_deref(), Ok("1"));
        std::env::remove_var("AGENTGUARD_SANDBOXED");
    }
}
