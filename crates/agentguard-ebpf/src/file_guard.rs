//! eBPF LSM hooks — filesystem protection.
//!
//! Intercepta `file_unlink`, `inode_rmdir`, `inode_rename`, `file_open`
//! y compara la ruta contra mapas de prefijos y archivos protegidos.
//! Si hay match → -EPERM (denegado) + evento en ring buffer.
//!
//! Requisitos: kernel ≥ 5.10, CONFIG_BPF_LSM=y, bpf en /sys/kernel/security/lsm.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_d_path, bpf_get_current_comm, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{Array, RingBuf},
    programs::LsmContext,
    EbpfContext,
};

use agentguard_common::{
    EventType, FileEvent, PathPrefix, COMM_LEN, MAX_PREFIXES, MAX_PREFIX_LEN,
};

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

#[map]
static PROTECTED_PREFIXES: Array<PathPrefix> =
    Array::<PathPrefix>::with_max_entries(MAX_PREFIXES, 0);

#[map]
static PREFIX_COUNT: Array<u32> = Array::<u32>::with_max_entries(1, 0);

#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static PROTECTED_WRITE_PATHS: Array<PathPrefix> =
    Array::<PathPrefix>::with_max_entries(MAX_PREFIXES, 0);

#[map]
static WRITE_PATH_COUNT: Array<u32> = Array::<u32>::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// LSM hooks
// ---------------------------------------------------------------------------

#[lsm(hook = "file_unlink")]
pub fn file_unlink(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileDelete)
}

#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileDelete)
}

#[lsm(hook = "inode_rename")]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    try_deny_rename(&ctx)
}

#[lsm(hook = "file_rename")]
pub fn file_rename(ctx: LsmContext) -> i32 {
    try_deny_rename(&ctx)
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    try_deny_write(&ctx)
}

// ── Nuevos hooks: cierran vectores de bypass ──────────────────────

#[lsm(hook = "inode_symlink")]
pub fn inode_symlink(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileWrite)
}

#[lsm(hook = "inode_create")]
pub fn inode_create(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileWrite)
}

#[lsm(hook = "inode_mkdir")]
pub fn inode_mkdir(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileWrite)
}

#[lsm(hook = "inode_mknod")]
pub fn inode_mknod(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileWrite)
}

#[lsm(hook = "inode_link")]
pub fn inode_link(ctx: LsmContext) -> i32 {
    let mut path_buf = [0u8; MAX_PREFIX_LEN];
    let path_len = match resolve_path_from_args(&ctx, 1, 2, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    if is_protected_prefix(&path_buf, path_len) {
        send_file_event(&ctx, EventType::FileWrite, &path_buf, path_len);
        return -1;
    }
    0
}

// inode_setattr(dentry, attr) — solo dentry, sin dir.
// Verificar contra write paths (archivos individuales protegidos).
#[lsm(hook = "inode_setattr")]
pub fn inode_setattr(ctx: LsmContext) -> i32 {
    try_deny_setattr(&ctx)
}

#[lsm(hook = "file_truncate")]
pub fn file_truncate(ctx: LsmContext) -> i32 {
    try_deny_write(&ctx)
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

#[repr(C)]
struct KernelPath {
    mnt: u64,
    dentry: u64,
}

/// Resuelve ruta para hooks con layout (dir_inode, dentry) como
/// `file_unlink` e `inode_rmdir`.
fn resolve_path(ctx: &LsmContext, out: &mut [u8; MAX_PREFIX_LEN]) -> Result<u32, i64> {
    resolve_path_from_args(ctx, 0, 1, out)
}

/// Resuelve ruta desde argumentos LSM arbitrarios.
///
/// `dir_arg`   = índice del argumento `struct inode *` del directorio.
/// `dentry_arg` = índice del argumento `struct dentry *` del objetivo.
fn resolve_path_from_args(
    ctx: &LsmContext,
    dir_arg: usize,
    dentry_arg: usize,
    out: &mut [u8; MAX_PREFIX_LEN],
) -> Result<u32, i64> {
    let dir_ptr: u64 = unsafe { ctx.arg(dir_arg) };
    let dentry: u64 = unsafe { ctx.arg(dentry_arg) };

    // aya-ebpf 0.1: bpf_probe_read_kernel<T>(src) -> Result<T, c_long>
    let mnt: u64 = unsafe { bpf_probe_read_kernel::<u64>(dir_ptr as *const u64) }
        .map_err(|e| e as i64)?;

    let synth = KernelPath { mnt, dentry };
    let ret = unsafe {
        bpf_d_path(
            &synth as *const _ as *mut _,
            out.as_mut_ptr() as *mut _,
            out.len() as u32,
        )
    };
    if ret < 0 {
        return Err(ret as i64);
    }
    Ok(ret as u32)
}

/// Resuelve ruta desde `file_open` (arg 0 = struct file *).
/// Lee `file->f_path.mnt` y `file->f_path.dentry` (offset 8 y 16 en x86_64).
fn resolve_path_from_file(ctx: &LsmContext, out: &mut [u8; MAX_PREFIX_LEN]) -> Result<u32, i64> {
    let file: u64 = unsafe { ctx.arg(0) };
    let f_path_ptr = file.wrapping_add(8);

    let mnt: u64 =
        unsafe { bpf_probe_read_kernel::<u64>(f_path_ptr as *const u64) }
            .map_err(|e| e as i64)?;

    let dentry: u64 =
        unsafe { bpf_probe_read_kernel::<u64>(f_path_ptr.wrapping_add(8) as *const u64) }
            .map_err(|e| e as i64)?;

    let synth = KernelPath { mnt, dentry };
    let ret = unsafe {
        bpf_d_path(
            &synth as *const _ as *mut _,
            out.as_mut_ptr() as *mut _,
            out.len() as u32,
        )
    };
    if ret < 0 {
        Err(ret as i64)
    } else {
        Ok(ret as u32)
    }
}

// ---------------------------------------------------------------------------
// Protection logic
// ---------------------------------------------------------------------------

fn is_protected_prefix(path: &[u8; MAX_PREFIX_LEN], path_len: u32) -> bool {
    let count = match PREFIX_COUNT.get(0) {
        Some(c) => *c,
        None => return false,
    };
    if count == 0 {
        return false;
    }
    let effective = count.min(MAX_PREFIXES);

    for i in 0..MAX_PREFIXES {
        if i >= effective {
            break;
        }
        let prefix = match PROTECTED_PREFIXES.get(i) {
            Some(p) => p,
            None => continue,
        };
        if prefix.len == 0 || prefix.len > path_len {
            continue;
        }
        let plen = (prefix.len as usize).min(MAX_PREFIX_LEN);
        if path[..plen] == prefix.bytes[..plen] {
            // Requerir que el prefijo termine en límite de componente:
            //   - path_len == prefix.len  → match exacto del directorio en sí
            //   - path[plen] == b'/'      → el prefijo es un directorio padre
            if path_len == prefix.len || (plen < path_len as usize && path[plen] == b'/') {
                return true;
            }
        }
    }
    false
}

fn is_write_protected(path: &[u8; MAX_PREFIX_LEN], path_len: u32) -> bool {
    let count = match WRITE_PATH_COUNT.get(0) {
        Some(c) => *c,
        None => return false,
    };
    if count == 0 {
        return false;
    }
    let effective = count.min(MAX_PREFIXES);

    for i in 0..MAX_PREFIXES {
        if i >= effective {
            break;
        }
        let entry = match PROTECTED_WRITE_PATHS.get(i) {
            Some(p) => p,
            None => continue,
        };
        if entry.len != path_len {
            continue;
        }
        let plen = (path_len as usize).min(MAX_PREFIX_LEN);
        if path[..plen] == entry.bytes[..plen] {
            return true;
        }
    }
    false
}

fn try_deny_protected(ctx: &LsmContext, ev_type: EventType) -> i32 {
    let mut path_buf = [0u8; MAX_PREFIX_LEN];
    let path_len = match resolve_path(ctx, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    if is_protected_prefix(&path_buf, path_len) {
        send_file_event(ctx, ev_type, &path_buf, path_len);
        return -1;
    }
    0
}

/// Bloquea el rename si la ruta origen O la ruta destino están bajo
/// un prefijo protegido.
fn try_deny_rename(ctx: &LsmContext) -> i32 {
    let mut path_buf = [0u8; MAX_PREFIX_LEN];

    // Resolver ruta origen — arg(0)=old_dir, arg(1)=old_dentry
    let src_len = match resolve_path_from_args(ctx, 0, 1, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    if is_protected_prefix(&path_buf, src_len) {
        send_file_event(ctx, EventType::FileRename, &path_buf, src_len);
        return -1;
    }

    // Resolver ruta destino — arg(2)=new_dir, arg(3)=new_dentry
    let tgt_len = match resolve_path_from_args(ctx, 2, 3, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    if is_protected_prefix(&path_buf, tgt_len) {
        send_file_event(ctx, EventType::FileRename, &path_buf, tgt_len);
        return -1;
    }
    0
}

fn try_deny_write(ctx: &LsmContext) -> i32 {
    let mut path_buf = [0u8; MAX_PREFIX_LEN];
    let path_len = match resolve_path_from_file(ctx, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    if is_write_protected(&path_buf, path_len) {
        send_file_event(ctx, EventType::FileWrite, &path_buf, path_len);
        return -1;
    }
    0
}

/// Resuelve la ruta desde un solo dentry (sin dir inode).
/// Lee `mnt` desde los primeros 8 bytes del dentry como fallback;
/// `bpf_d_path` usa principalmente la cadena de dentries para resolver.
fn resolve_path_from_dentry(ctx: &LsmContext, dentry_arg: usize, out: &mut [u8; MAX_PREFIX_LEN]) -> Result<u32, i64> {
    let dentry: u64 = unsafe { ctx.arg(dentry_arg) };

    let mnt: u64 = unsafe { bpf_probe_read_kernel::<u64>(dentry as *const u64) }
        .map_err(|e| e as i64)?;

    let synth = KernelPath { mnt, dentry };
    let ret = unsafe {
        bpf_d_path(&synth as *const _ as *mut _, out.as_mut_ptr() as *mut _, out.len() as u32)
    };
    if ret < 0 { Err(ret as i64) } else { Ok(ret as u32) }
}

fn try_deny_setattr(ctx: &LsmContext) -> i32 {
    let mut path_buf = [0u8; MAX_PREFIX_LEN];
    let path_len = match resolve_path_from_dentry(ctx, 0, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    if is_protected_prefix(&path_buf, path_len)
        || is_write_protected(&path_buf, path_len)
    {
        send_file_event(ctx, EventType::FileWrite, &path_buf, path_len);
        return -1;
    }
    0
}

fn send_file_event(
    ctx: &LsmContext,
    ev_type: EventType,
    path: &[u8; MAX_PREFIX_LEN],
    path_len: u32,
) {
    if let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) {
        unsafe {
            let event = &mut *entry.as_mut_ptr();
            event.pid = ctx.pid();
            event.uid = ctx.uid();
            event.event_type = ev_type;
            event.path_len = path_len;
            let n = (path_len as usize).min(MAX_PREFIX_LEN);
            event.path[..n].copy_from_slice(&path[..n]);
            if let Ok(comm) = bpf_get_current_comm() {
                let m = comm.len().min(COMM_LEN);
                event.comm[..m].copy_from_slice(&comm[..m]);
            }
        }
        entry.submit(0);
    }
    // Si reserve() devuelve None, el evento se pierde.
    // La detección de overflow se hace en userspace (batch counter).
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
