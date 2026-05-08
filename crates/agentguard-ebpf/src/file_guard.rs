//! eBPF LSM hooks — filesystem protection (inode-based).
//!
//! Instead of calling `bpf_d_path` (not available in most LSM hooks),
//! we identify protected directories and files by their (dev, inode) pair.
//!
//! Userspace resolves paths to inodes at daemon startup and populates
//! the BPF maps. The kernel-side only does hashmap lookups — no path
//! string manipulation, which satisfies the verifier on all kernels >= 5.7.
//!
//! Hooks protected:
//!   inode_unlink, inode_rmdir, inode_rename,
//!   file_open, file_truncate,
//!   inode_symlink, inode_create, inode_mkdir, inode_mknod,
//!   inode_link, inode_setattr (v1 + v2 kernel 6.2+), bprm_check_security

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{HashMap, RingBuf},
    programs::LsmContext,
    EbpfContext,
};

use agentguard_common::{EventType, FileEvent, COMM_LEN, MAX_PREFIX_LEN};

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

/// Key: ((dev as u64) << 32) | (ino as u64 & 0xFFFF_FFFF)
/// Value: 1 = protected
#[map]
static PROTECTED_DIR_INODES: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(8192, 0);

/// Individual files protected against writes/opens.
#[map]
static PROTECTED_FILE_INODES: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(8192, 0);

#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ---------------------------------------------------------------------------
// Kernel struct offsets — resolved at load time via OFFSETS map
// ---------------------------------------------------------------------------

/// Runtime offsets passed by userspace from /sys/kernel/btf/vmlinux.
/// indices: 0=i_ino_offset, 1=i_sb_offset, 2=s_dev_offset,
///          3=f_inode_offset, 4=d_parent_offset, 5=d_inode_offset,
///          6=f_flags_offset (struct file::f_flags)
#[map]
static OFFSETS: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::<u64>::with_max_entries(12, 0);

/// Default offsets (kernel 4.x fallback) — overridden at load time.
const DFL_I_INO: u64 = 8;
const DFL_I_SB: u64 = 24;
const DFL_S_DEV: u64 = 0;
const DFL_F_INODE: u64 = 32;   // 0x20
const DFL_D_PARENT: u64 = 24;  // 0x18
const DFL_D_INODE: u64 = 48;   // 0x30
const DFL_F_FLAGS: u64 = 0xa8; // struct file::f_flags on kernel 5.15-6.x

// ---------------------------------------------------------------------------
// POSIX open(2) flags — identical across all Linux kernels & architectures
// ---------------------------------------------------------------------------

const O_ACCMODE: i32 = 0o0003;
const O_RDONLY:  i32 = 0o0000;
const O_WRONLY:  i32 = 0o0001;
const O_RDWR:    i32 = 0o0002;
const O_CREAT:   i32 = 0o0100;
const O_TRUNC:   i32 = 0o1000;

/// Upper bound on any plausible kernel struct-field offset (4 KB >> anything we
/// touch: `d_inode` ~= 48, `f_flags` ~= 0xa8, `i_ino` ~= 8, etc.).
///
/// Kernel 6.x verifier forbids pointer arithmetic with an *unbounded* scalar
/// when the pointer has `PTR_TRUSTED` (every LSM hook ctx arg does). The
/// compiler can't prove a map-loaded `u64` is bounded, so we clamp it
/// explicitly. This turns `trusted_ptr + unbounded` into `trusted_ptr + [0..4096)`
/// which the verifier accepts.
const MAX_STRUCT_OFFSET: u64 = 4096;

#[inline(always)]
fn off(idx: u32, fallback: u64) -> u64 {
    let v = OFFSETS.get(idx).copied().unwrap_or(fallback);
    // Bound the value so the verifier can track `ptr + v` on trusted pointers.
    if v >= MAX_STRUCT_OFFSET {
        fallback & (MAX_STRUCT_OFFSET - 1)
    } else {
        v
    }
}

// ---------------------------------------------------------------------------
// inode key helper
// ---------------------------------------------------------------------------

/// Build a 64-bit key from (dev, ino) for the inode at `inode_ptr`.
/// Returns `None` if the pointer is null or reads fail.
fn inode_key(inode_ptr: u64) -> Option<u64> {
    if inode_ptr == 0 {
        return None;
    }
    let io = off(0, DFL_I_INO);
    let so = off(1, DFL_I_SB);
    let doff = off(2, DFL_S_DEV);
    let ino: u64 =
        unsafe { bpf_probe_read_kernel((inode_ptr + io) as *const u64) }.ok()?;
    let sb: u64 =
        unsafe { bpf_probe_read_kernel((inode_ptr + so) as *const u64) }.ok()?;
    if sb == 0 {
        return None;
    }
    let dev: u32 = unsafe { bpf_probe_read_kernel((sb + doff) as *const u32) }.ok()?;
    Some(((dev as u64) << 32) | (ino & 0xFFFF_FFFF))
}

/// Check if a given inode key is in the protected dirs map.
fn is_dir_protected(key: u64) -> bool {
    unsafe { PROTECTED_DIR_INODES.get(&key) }
        .map(|v| *v == 1)
        .unwrap_or(false)
}

/// Check if a given inode key is in the protected files map.
fn is_file_protected(key: u64) -> bool {
    unsafe { PROTECTED_FILE_INODES.get(&key) }
        .map(|v| *v == 1)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// LSM hooks — deletion/rename (check parent dir inode)
// ---------------------------------------------------------------------------

/// `inode_unlink(dir_inode, dentry)` — invoked for every `unlink(2)` /
/// `unlinkat(2)`. `file_unlink` is NOT a real LSM hook (historical naming
/// confusion) — the kernel's BTF only exports `bpf_lsm_inode_unlink`.
#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileDelete, true)
}

#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileDelete, true)
}

fn try_deny_protected(ctx: &LsmContext, ev_type: EventType, _use_dir: bool) -> i32 {
    // arg(0) = dir_inode for file_unlink/inode_rmdir/inode_symlink/inode_create/inode_mkdir/inode_mknod
    // arg(1) = dentry
    let dir_ptr: u64 = unsafe { ctx.arg(0) };
    let key = match inode_key(dir_ptr) {
        Some(k) => k,
        None => return 0,
    };
    if is_dir_protected(key) {
        emit_event(ctx, ev_type);
        return -1; // -EPERM
    }
    0
}

// ── Rename (check old dir + new dir) ──────────────────────────

/// `inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags)` — the
/// canonical hook for any `rename(2)` / `renameat2(2)`. `file_rename` is
/// NOT a kernel LSM hook; removing the spurious declaration silences the
/// `Unknown BTF type` warning on load.
#[lsm(hook = "inode_rename")]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    try_deny_rename(&ctx)
}

fn try_deny_rename(ctx: &LsmContext) -> i32 {
    // inode_rename(old_dir, old_dentry, new_dir, new_dentry)
    let old_dir: u64 = unsafe { ctx.arg(0) };
    if let Some(key) = inode_key(old_dir) {
        if is_dir_protected(key) {
            emit_event(ctx, EventType::FileRename);
            return -1;
        }
    }

    let new_dir: u64 = unsafe { ctx.arg(2) };
    if let Some(key) = inode_key(new_dir) {
        if is_dir_protected(key) {
            emit_event(ctx, EventType::FileRename);
            return -1;
        }
    }
    0
}

// ── Create/symlink/mkdir/mknod (check parent dir) ─────────────

#[lsm(hook = "inode_symlink")]
pub fn inode_symlink(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileWrite, true)
}

#[lsm(hook = "inode_create")]
pub fn inode_create(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileWrite, true)
}

#[lsm(hook = "inode_mkdir")]
pub fn inode_mkdir(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileWrite, true)
}

#[lsm(hook = "inode_mknod")]
pub fn inode_mknod(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileWrite, true)
}

// ── Link (check old dir + new dir) ────────────────────────────

#[lsm(hook = "inode_link")]
pub fn inode_link(ctx: LsmContext) -> i32 {
    // inode_link(old_dir, old_dentry, new_dir, new_dentry)
    let old_dir: u64 = unsafe { ctx.arg(0) };
    if let Some(key) = inode_key(old_dir) {
        if is_dir_protected(key) {
            emit_event(&ctx, EventType::FileWrite);
            return -1;
        }
    }
    let new_dir: u64 = unsafe { ctx.arg(2) };
    if let Some(key) = inode_key(new_dir) {
        if is_dir_protected(key) {
            emit_event(&ctx, EventType::FileWrite);
            return -1;
        }
    }
    0
}

// ── setattr (check file inode + parent dir) ───────────────────
//
// Kernel 6.2 changed the signature of `inode_setattr` to take `mnt_idmap`
// as arg0, shifting the dentry to arg1. We ship BOTH versions and let
// userspace pick the one matching the running kernel's BTF signature.
//
//   v1 (kernel ≤6.1): inode_setattr(dentry, iattr)
//   v2 (kernel ≥6.2): inode_setattr(mnt_idmap, dentry, iattr)

#[inline(always)]
fn try_deny_setattr(ctx: &LsmContext, dentry: u64) -> i32 {
    if dentry == 0 {
        return 0;
    }
    let dio = off(5, DFL_D_INODE);
    let inode: u64 = match unsafe {
        bpf_probe_read_kernel((dentry + dio) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if let Some(key) = inode_key(inode) {
        if is_file_protected(key) || is_dir_protected(key) {
            emit_event(ctx, EventType::FileWrite);
            return -1;
        }
    }
    0
}

#[lsm(hook = "inode_setattr")]
pub fn inode_setattr(ctx: LsmContext) -> i32 {
    // v1: arg(0) = dentry
    let dentry: u64 = unsafe { ctx.arg(0) };
    try_deny_setattr(&ctx, dentry)
}

/// Kernel 6.2+ variant — attached by userspace only when BTF of
/// `bpf_lsm_inode_setattr` reports `mnt_idmap` as arg0.
#[lsm(hook = "inode_setattr")]
pub fn inode_setattr_v2(ctx: LsmContext) -> i32 {
    // v2: arg(0) = mnt_idmap, arg(1) = dentry
    let dentry: u64 = unsafe { ctx.arg(1) };
    try_deny_setattr(&ctx, dentry)
}

// ── file_open / file_truncate ──────────────────────────────────

/// `file_open` is reached for **every** `open(2)` system call against a file,
/// including read-only opens (`cat`, `ls -l`, editors reading previews, etc.).
/// Denying every protected-file open would render the system unusable.
///
/// We therefore inspect `struct file::f_flags` (resolved via BTF at load time
/// or via the `DFL_F_FLAGS` kernel-5.15+/6.x fallback) and only proceed with
/// the deny path when the open is for **write**:
///   - access mode `O_WRONLY` or `O_RDWR`
///   - or the open carries `O_TRUNC` (intended truncation)
///   - or the open carries `O_CREAT` (intended creation under the parent dir)
///
/// Pure read-only opens (`O_RDONLY`, no `O_TRUNC`/`O_CREAT`) are always allowed.
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    try_deny_file_open_write(&ctx, EventType::FileWrite)
}

/// `file_truncate` is **always** destructive: caller intends to shrink/zero
/// the file. Block unconditionally on protected files/dirs.
#[lsm(hook = "file_truncate")]
pub fn file_truncate(ctx: LsmContext) -> i32 {
    try_deny_file_op(&ctx, EventType::FileWrite)
}

/// Variant of `try_deny_file_op` that first checks `file->f_flags` and only
/// continues with deny-checks when the open is for write/create/truncate.
fn try_deny_file_open_write(ctx: &LsmContext, ev_type: EventType) -> i32 {
    // arg(0) = struct file *
    let file: u64 = unsafe { ctx.arg(0) };
    if file == 0 {
        return 0;
    }

    // Read f_flags. If the read fails (offset wrong on this kernel),
    // fail open (return 0) rather than randomly denying.
    let ffo = off(6, DFL_F_FLAGS);
    let flags: i32 = match unsafe { bpf_probe_read_kernel::<i32>((file + ffo) as *const _) } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let access_mode = flags & O_ACCMODE;
    let is_write = access_mode == O_WRONLY
        || access_mode == O_RDWR
        || (flags & O_TRUNC) != 0
        || (flags & O_CREAT) != 0;

    let _ = O_RDONLY; // keep the constant in the binary for readability/grepping
    if !is_write {
        // Read-only open of a protected file is allowed.
        return 0;
    }

    try_deny_file_op(ctx, ev_type)
}

fn try_deny_file_op(ctx: &LsmContext, ev_type: EventType) -> i32 {
    // arg(0) = struct file *
    let file: u64 = unsafe { ctx.arg(0) };
    if file == 0 {
        return 0;
    }

    let fo = off(3, DFL_F_INODE);
    let inode: u64 =
        match unsafe { bpf_probe_read_kernel::<u64>((file + fo) as *const _) } {
            Ok(v) => v,
            Err(_) => return 0,
        };

    if let Some(key) = inode_key(inode) {
        if is_file_protected(key) {
            emit_event(ctx, ev_type);
            return -1;
        }
        if is_dir_protected(key) {
            emit_event(ctx, ev_type);
            return -1;
        }
    }

    // Also check parent directory via dentry chain (inode-based)
    // file->f_path = path { mnt: *mut vfsmount at offset 8, dentry: *mut dentry at offset 16 }
    let mnt: u64 = match unsafe { bpf_probe_read_kernel::<u64>((file + 8) as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let dentry: u64 = match unsafe { bpf_probe_read_kernel::<u64>((file + 16) as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if mnt != 0 && dentry != 0 {
        let dpo = off(4, DFL_D_PARENT);
        let dio = off(5, DFL_D_INODE);
        // Read dentry->d_parent
        let parent: u64 =
            match unsafe { bpf_probe_read_kernel((dentry + dpo) as *const u64) } {
                Ok(v) => v,
                Err(_) => 0,
            };
        if parent != 0 {
            // d_parent->d_inode
            let parent_inode: u64 =
                match unsafe { bpf_probe_read_kernel((parent + dio) as *const u64) } {
                    Ok(v) => v,
                    Err(_) => 0,
                };
            if let Some(key) = inode_key(parent_inode) {
                if is_dir_protected(key) {
                    emit_event(ctx, ev_type);
                    return -1;
                }
            }
        }
    }

    // All checks passed — allow
    0
}

// ---------------------------------------------------------------------------
// bprm_check_security — block AI agent exec
// ---------------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[map]
static KNOWN_AGENTS_BPRM: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(128, 0);

fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = FNV_OFFSET;
    for &byte in data.iter() {
        if byte == 0 {
            break;
        }
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let bprm: *const u8 = match unsafe { ctx.arg::<*const u8>(0) } {
        p if !p.is_null() => p,
        _ => return 0,
    };

    // bprm->file at offset 0x20 (32)
    let file_ptr: *const *const u8 = unsafe { (bprm.add(32)) as *const *const u8 };
    let file = match unsafe { bpf_probe_read_kernel(file_ptr) } {
        Ok(f) if !f.is_null() => f,
        _ => return 0,
    };

    // Read filename from file->f_path.dentry->d_name
    // WITHOUT bpf_d_path (not allowed in LSM hooks)
    //
    // struct file { f_path: path }  → offset 0x08
    // struct path { mnt: *vfsmount, dentry: *dentry } → dentry at offset 0x08 within path
    // So file->f_path.dentry = *(file + 0x10)
    let dentry_ptr: *const *const u8 = unsafe { (file.add(16)) as *const *const u8 };
    let dentry = match unsafe { bpf_probe_read_kernel(dentry_ptr) } {
        Ok(d) if !d.is_null() => d,
        _ => return 0,
    };

    // struct dentry { ... d_name: qstr ... }
    // d_name at offset 0x20 (32)
    // struct qstr { name: *const u8 (offset 0), len: u32 (offset 8) }
    let name_ptr: *const *const u8 = unsafe { (dentry.add(32)) as *const *const u8 };
    let name = match unsafe { bpf_probe_read_kernel(name_ptr) } {
        Ok(n) if !n.is_null() => n,
        _ => return 0,
    };

    let len_ptr: *const u32 = unsafe { (dentry.add(40)) as *const u32 };
    let name_len = match unsafe { bpf_probe_read_kernel(len_ptr) } {
        Ok(l) if l > 0 && (l as usize) < MAX_PREFIX_LEN => l as usize,
        _ => return 0,
    };

    let mut path_buf: [u8; MAX_PREFIX_LEN] = [0u8; MAX_PREFIX_LEN];
    // Bounded loop with compile-time constant upper bound so the verifier can
    // prove every indexed write is in [0, MAX_PREFIX_LEN). name_len is
    // already clamped to (0, MAX_PREFIX_LEN) above.
    for i in 0..MAX_PREFIX_LEN {
        if i >= name_len {
            break;
        }
        match unsafe { bpf_probe_read_kernel(name.add(i) as *const u8) } {
            Ok(b) => path_buf[i] = b,
            Err(_) => break,
        }
    }

    let hash = fnv1a_hash(&path_buf);
    if let Some(val) = unsafe { KNOWN_AGENTS_BPRM.get(&hash) } {
        if *val == 1 {
            emit_bprm_event(&ctx, &path_buf, name_len as u32);
            return -1;
        }
    }

    return 0;
}

fn emit_bprm_event(ctx: &LsmContext, path: &[u8; MAX_PREFIX_LEN], path_len: u32) {
    if let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) {
        unsafe {
            let event = &mut *entry.as_mut_ptr();
            event.pid = ctx.pid();
            event.uid = ctx.uid();
            event.event_type = EventType::NetworkSend;
            event.path_len = path_len;
            // Fixed-size memcpy — the verifier proves both sides are exactly
            // MAX_PREFIX_LEN bytes so no bounds tracking is needed.
            event.path = *path;
            if let Ok(comm) = bpf_get_current_comm() {
                // `bpf_get_current_comm()` always returns a TASK_COMM_LEN-sized
                // buffer. Do a fixed-size copy so the verifier can bound it.
                let src: &[u8; COMM_LEN] = &*(comm.as_ptr() as *const [u8; COMM_LEN]);
                event.comm = *src;
            }
        }
        entry.submit(0);
    }
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

fn emit_event(ctx: &LsmContext, ev_type: EventType) {
    if let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) {
        unsafe {
            let event = &mut *entry.as_mut_ptr();
            event.pid = ctx.pid();
            event.uid = ctx.uid();
            event.event_type = ev_type;
            event.path_len = 0;
            event.path = [0u8; MAX_PREFIX_LEN];
            if let Ok(comm) = bpf_get_current_comm() {
                // Fixed-size copy — see note in emit_bprm_event.
                let src: &[u8; COMM_LEN] = &*(comm.as_ptr() as *const [u8; COMM_LEN]);
                event.comm = *src;
            }
        }
        entry.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
