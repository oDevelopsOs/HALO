//! eBPF LSM hooks — filesystem protection.
//!
//! Intercepta `file_unlink`, `file_rename`, `file_open` y compara la ruta
//! contra mapas de prefijos y archivos protegidos.
//! Si hay match → -EPERM (denegado) + evento en ring buffer.
//!
//! Requisitos: kernel \u{2265} 5.10, CONFIG_BPF_LSM=y, bpf en /sys/kernel/security/lsm.

#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_comm, bpf_probe_read_kernel, gen::bpf_d_path},
    macros::{lsm, map},
    maps::{Array, RingBuf},
    programs::LsmContext,
    BpfContext,
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

/// Archivos individuales protegidos contra escritura (Fase 1.6).
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

#[lsm(hook = "file_rename")]
pub fn file_rename(ctx: LsmContext) -> i32 {
    try_deny_protected(&ctx, EventType::FileRename)
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
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

/// Resuelve ruta desde `file_unlink` / `file_rename` (arg 0=dir, arg 1=dentry).
fn resolve_path(ctx: &LsmContext, out: &mut [u8; MAX_PREFIX_LEN]) -> Result<u32, i64> {
    let dir_ptr: u64 = ctx.arg(0);
    let dentry: u64 = ctx.arg(1);

    let mut mnt: u64 = 0;
    let probe_ret = unsafe {
        bpf_probe_read_kernel(
            &mut mnt as *mut _ as *mut _,
            core::mem::size_of::<u64>() as u32,
            dir_ptr as *const _,
        )
    };
    if probe_ret < 0 {
        return Err(probe_ret as i64);
    }

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
    let file: u64 = ctx.arg(0);
    // struct file: f_path (struct path) en offset 8.
    let f_path_ptr = file.wrapping_add(8);

    let mut mnt: u64 = 0;
    let r = unsafe {
        bpf_probe_read_kernel(
            &mut mnt as *mut _ as *mut _,
            core::mem::size_of::<u64>() as u32,
            f_path_ptr as *const _,
        )
    };
    if r < 0 { return Err(r as i64); }

    let mut dentry: u64 = 0;
    let r = unsafe {
        bpf_probe_read_kernel(
            &mut dentry as *mut _ as *mut _,
            core::mem::size_of::<u64>() as u32,
            f_path_ptr.wrapping_add(8) as *const _,
        )
    };
    if r < 0 { return Err(r as i64); }

    let synth = KernelPath { mnt, dentry };
    let ret = unsafe {
        bpf_d_path(
            &synth as *const _ as *mut _,
            out.as_mut_ptr() as *mut _,
            out.len() as u32,
        )
    };
    if ret < 0 { Err(ret as i64) } else { Ok(ret as u32) }
}

// ---------------------------------------------------------------------------
// Protection logic
// ---------------------------------------------------------------------------

/// Prefijo protegido (directorios) — O(N) sobre N \u{2264} MAX_PREFIXES.
fn is_protected_prefix(path: &[u8; MAX_PREFIX_LEN], path_len: u32) -> bool {
    let count = match PREFIX_COUNT.get(0) {
        Some(c) => *c,
        None => return false,
    };
    if count == 0 { return false; }
    let effective = count.min(MAX_PREFIXES);

    for i in 0..MAX_PREFIXES {
        if i >= effective { break; }
        let prefix = match PROTECTED_PREFIXES.get(i) {
            Some(p) => p, None => continue,
        };
        if prefix.len == 0 || prefix.len > path_len { continue; }
        let plen = (prefix.len as usize).min(MAX_PREFIX_LEN);
        if path[..plen] == prefix.bytes[..plen] { return true; }
    }
    false
}

/// Archivo concreto (coincidencia exacta) — O(N).
fn is_write_protected(path: &[u8; MAX_PREFIX_LEN], path_len: u32) -> bool {
    let count = match WRITE_PATH_COUNT.get(0) {
        Some(c) => *c, None => return false,
    };
    if count == 0 { return false; }
    let effective = count.min(MAX_PREFIXES);

    for i in 0..MAX_PREFIXES {
        if i >= effective { break; }
        let entry = match PROTECTED_WRITE_PATHS.get(i) {
            Some(p) => p, None => continue,
        };
        if entry.len != path_len { continue; }
        let plen = (path_len as usize).min(MAX_PREFIX_LEN);
        if path[..plen] == entry.bytes[..plen] { return true; }
    }
    false
}

fn try_deny_protected(ctx: &LsmContext, ev_type: EventType) -> i32 {
    let mut path_buf = [0u8; MAX_PREFIX_LEN];
    let path_len = match resolve_path(ctx, &mut path_buf) {
        Ok(n) => n, Err(_) => return 0,
    };
    if is_protected_prefix(&path_buf, path_len) {
        send_file_event(ctx, ev_type, &path_buf, path_len);
        return -1; // EPERM
    }
    0
}

fn try_deny_write(ctx: &LsmContext) -> i32 {
    let mut path_buf = [0u8; MAX_PREFIX_LEN];
    let path_len = match resolve_path_from_file(ctx, &mut path_buf) {
        Ok(n) => n, Err(_) => return 0,
    };
    if is_write_protected(&path_buf, path_len) {
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
            bpf_get_current_comm(event.comm.as_mut_ptr() as *mut _, COMM_LEN as u32);
        }
        entry.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
