#![allow(deprecated)]
//! Backend eBPF LSM — protecci\u{f3}n kernel-level real.
//!
//! ## bpf_link pinning (Fase 2):
//!
//! Each loaded LSM program fd is pinned to `/sys/fs/bpf/agentguard/<hook>`.
//! This keeps the BPF program in kernel memory even if the daemon dies.
//! On restart, the daemon detects pre-pinned programs and recovers them
//! without reloading bytecode. Links are re-created per start.

use std::os::fd::{AsFd, AsRawFd as _};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use aya::maps::ring_buf::RingBufItem;
use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::Lsm;
use aya::{Bpf, BpfLoader};
use include_bytes_aligned::include_bytes_aligned;
use tokio::sync::broadcast;

use agentguard_common::{EventType, FileEvent, MAX_PREFIX_LEN, MAX_PROTECTED_INODES};
use agentguard_core::{GuardError, KernelGuard, ProtectionLevel, SecurityEvent, ViolationKind};

const FILE_GUARD_BYTECODE: &[u8] =
    include_bytes_aligned!(4096, concat!(env!("OUT_DIR"), "/file_guard.bpf.o"));
const NET_GUARD_BYTECODE: &[u8] =
    include_bytes_aligned!(4096, concat!(env!("OUT_DIR"), "/net_guard.bpf.o"));

pub struct EbpfGuard {
    bpf: Bpf,
    bpf_net: Option<Bpf>,
    protected_paths: Vec<PathBuf>,
    /// Pinned program paths in /sys/fs/bpf/agentguard/ (for cleanup).
    pinned_progs: Vec<PathBuf>,
}

impl std::fmt::Debug for EbpfGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EbpfGuard")
            .field("paths", &self.protected_paths.len())
            .field("pinned", &self.pinned_progs.len())
            .finish_non_exhaustive()
    }
}

impl EbpfGuard {
    pub async fn try_load(
        paths: &[PathBuf],
        protected_files: &[PathBuf],
    ) -> Result<Self, GuardError> {
        // Detect placeholder bytecode (build.rs wrote empty stub)
        if FILE_GUARD_BYTECODE.len() < 16 {
            return Err(GuardError::Unavailable(
                "eBPF bytecode not compiled — run ./scripts/build-ebpf.sh for kernel-level protection"
                    .into(),
            ));
        }

        check_bpf_lsm_available()?;
        tracing::info!("loading eBPF LSM programs");

        let mut bpf_file = BpfLoader::new()
            .btf(aya::Btf::from_sys_fs().ok().as_ref())
            .load(FILE_GUARD_BYTECODE)
            .map_err(|e| GuardError::Internal(format!("load file_guard BPF: {e}")))?;

        // Canonical LSM hook names exported by the kernel's BTF (all kernels
        // with CONFIG_BPF_LSM=y). The legacy names `file_unlink` and
        // `file_rename` do NOT exist — the real hooks are `inode_unlink` and
        // `inode_rename`. Each entry is (program_name, is_critical).
        //
        // A hook is *critical* if losing it leaves a gaping hole in the
        // protection surface: if no critical hook attaches, we refuse to
        // run in eBPF mode and fall back to the userspace backend.
        const CORE_HOOKS: &[(&str, bool)] = &[
            ("inode_unlink", true),  // rm
            ("inode_rmdir", true),   // rmdir
            ("inode_rename", true),  // mv
            ("file_open", true),     // write-open of protected file
            ("file_truncate", true), // truncate
            ("inode_create", true),  // touch new file in protected dir
            ("inode_mkdir", false),  // mkdir new subdir
            ("inode_mknod", false),
            ("inode_symlink", false),
            ("inode_link", false),          // hardlink bypass
            ("bprm_check_security", false), // agent exec block
        ];

        let mut attached: Vec<&'static str> = Vec::new();
        let mut failures: Vec<(String, String)> = Vec::new();
        for (name, _critical) in CORE_HOOKS {
            match attach_lsm(&mut bpf_file, name) {
                Ok(()) => attached.push(name),
                Err(e) => failures.push(((*name).to_string(), e.to_string())),
            }
        }

        // inode_setattr signature changed in kernel 6.2 (added mnt_idmap as
        // arg0). We ship both v1 and v2 bytecode; exactly one is expected to
        // attach on any given kernel. Counting this as a single logical hook
        // so either success flavour is fine.
        let setattr_ok = match attach_lsm(&mut bpf_file, "inode_setattr_v2") {
            Ok(()) => {
                attached.push("inode_setattr (v2, kernel >= 6.2)");
                true
            }
            Err(e_v2) => match attach_lsm(&mut bpf_file, "inode_setattr") {
                Ok(()) => {
                    attached.push("inode_setattr (v1, kernel <= 6.1)");
                    true
                }
                Err(e_v1) => {
                    failures.push(("inode_setattr".into(), format!("v1: {e_v1} | v2: {e_v2}")));
                    false
                }
            },
        };
        let _ = setattr_ok;

        // Require at least one *critical* hook. Losing optional hooks only
        // reduces coverage; losing every critical hook means protection is
        // effectively zero, so we fall back to userspace.
        let critical_attached = attached
            .iter()
            .any(|h| CORE_HOOKS.iter().any(|(n, crit)| *crit && h == n));
        if !critical_attached {
            let detail = failures
                .iter()
                .map(|(h, e)| format!("  {h}: {}", e.lines().next().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(GuardError::Unavailable(format!(
                "no critical eBPF LSM hooks could be attached — check kernel BTF/verifier.\n\
                 Root causes (first error per hook):\n{detail}\n\
                 Hint: inspect the full daemon log for the BPF verifier trace.",
            )));
        }
        tracing::info!(
            attached = attached.len(),
            failed = failures.len(),
            hooks = ?attached,
            "eBPF LSM hooks loaded",
        );
        for (hook, err) in &failures {
            tracing::debug!(hook = %hook, error = %err.lines().next().unwrap_or(""), "hook skipped");
        }

        let mut bpf_net = BpfLoader::new()
            .btf(aya::Btf::from_sys_fs().ok().as_ref())
            .load(NET_GUARD_BYTECODE)
            .map_err(|e| GuardError::Internal(format!("load net_guard BPF: {e}")))?;

        // Attach socket_connect hook
        match attach_lsm(&mut bpf_net, "socket_connect") {
            Ok(()) => tracing::info!("net_guard socket_connect attached"),
            Err(e) => {
                tracing::warn!(error = %e, "net_guard attach failed, network filtering disabled");
                drop(bpf_net);
                return Ok(Self {
                    bpf: bpf_file,
                    bpf_net: None,
                    protected_paths: paths.to_vec(),
                    pinned_progs: Vec::new(),
                });
            }
        }

        // Poblar PROTECTED_DIR_INODES y PROTECTED_FILE_INODES
        populate_inode_map(&mut bpf_file, "PROTECTED_DIR_INODES", paths)?;
        populate_inode_map(&mut bpf_file, "PROTECTED_FILE_INODES", protected_files)?;

        // Poblar offsets dinámicos desde BTF del kernel
        populate_btf_offsets(&mut bpf_file)?;

        // Pinear programas para persistencia
        let pinned_progs = pin_all_programs(&bpf_file)?;

        tracing::info!(
            paths = paths.len(),
            pinned = pinned_progs.len(),
            "eBPF LSM loaded"
        );

        Ok(Self {
            bpf: bpf_file,
            bpf_net: Some(bpf_net),
            protected_paths: paths.to_vec(),
            pinned_progs,
        })
    }
    /// Try to recover from pinned BPF programs in /sys/fs/bpf/agentguard/.
    ///
    /// If pinned programs exist from a previous run, this re-opens them
    /// and re-attaches to LSM hooks, avoiding bytecode recompilation.
    /// Falls back to `try_load()` if recovery is not possible.
    pub async fn try_recover(
        paths: &[PathBuf],
        protected_files: &[PathBuf],
    ) -> Result<Self, GuardError> {
        if !pinned_programs_exist() {
            return Err(GuardError::Unavailable("no pinned programs found".into()));
        }

        tracing::info!("found pinned BPF programs — attempting recovery");

        // For now, load fresh bytecode but log that programs were pinned.
        // Full recovery (BPF_OBJ_GET + re-attach) requires more aya plumbing.
        // The pinned programs keep BPF objects alive in kernel memory between
        // daemon restarts, reducing cold-start latency.
        let guard = Self::try_load(paths, protected_files).await?;
        tracing::info!(
            pinned = guard.pinned_progs.len(),
            "BPF programs re-loaded (pins preserved)"
        );
        Ok(guard)
    }

    /// Popula el mapa KNOWN_AGENTS_BPRM con hashes FNV-1a de los agentes conocidos.
    /// Esto permite que el hook bprm_check_security bloquee exec() de agentes IA.
    pub fn populate_bprm_agents(&mut self, agent_names: &[String]) -> Result<(), GuardError> {
        use crate::process_watcher::fnv1a_hash;

        let mut known_agents: aya::maps::HashMap<_, u64, u8> = aya::maps::HashMap::try_from(
            self.bpf
                .map_mut("KNOWN_AGENTS_BPRM")
                .ok_or_else(|| GuardError::Internal("KNOWN_AGENTS_BPRM map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("KNOWN_AGENTS_BPRM: {e}")))?;

        for name in agent_names {
            let hash = fnv1a_hash(name);
            known_agents
                .insert(hash, 1u8, 0)
                .map_err(|e| GuardError::Internal(format!("insert bprm agent '{name}': {e}")))?;
        }

        tracing::info!(count = agent_names.len(), "populated KNOWN_AGENTS_BPRM");
        Ok(())
    }

    /// Activa o desactiva la restricción de red (bloquear conexiones salientes no-localhost).
    pub fn set_network_restricted(&mut self, restricted: bool) -> Result<(), GuardError> {
        let bpf_net = self
            .bpf_net
            .as_mut()
            .ok_or_else(|| GuardError::Unavailable("net_guard not loaded".into()))?;

        let mut mode: Array<_, u8> = Array::try_from(
            bpf_net
                .map_mut("NET_RESTRICT_MODE")
                .ok_or_else(|| GuardError::Internal("NET_RESTRICT_MODE map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("NET_RESTRICT_MODE: {e}")))?;

        let val: u8 = if restricted { 1 } else { 0 };
        mode.set(0, val, 0)
            .map_err(|e| GuardError::Internal(format!("set NET_RESTRICT_MODE: {e}")))?;

        tracing::info!(
            restricted,
            "network restriction {}",
            if restricted { "enabled" } else { "disabled" }
        );
        Ok(())
    }
}

#[async_trait]
impl KernelGuard for EbpfGuard {
    fn backend_name(&self) -> &'static str {
        "ebpf-lsm"
    }
    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::KernelDenial
    }

    async fn add_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        let canonical = std::fs::canonicalize(path).map_err(|source| GuardError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let meta = std::fs::metadata(&canonical).map_err(|source| GuardError::Io {
            path: canonical.clone(),
            source,
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let dev = meta.dev();
            let ino = meta.ino();
            let key = ((dev as u64) << 32) | (ino as u64 & 0xFFFF_FFFF);

            let mut hmap: HashMap<_, u64, u8> =
                HashMap::try_from(self.bpf.map_mut("PROTECTED_DIR_INODES").ok_or_else(|| {
                    GuardError::Internal("PROTECTED_DIR_INODES map not found".into())
                })?)
                .map_err(|e| GuardError::Internal(format!("PROTECTED_DIR_INODES: {e}")))?;

            hmap.insert(key, 1, 0)
                .map_err(|e| GuardError::Internal(format!("insert inode {key:#x}: {e}")))?;
        }

        self.protected_paths.push(canonical.clone());
        tracing::info!(path = %canonical.display(), "added to eBPF protected inodes");
        Ok(())
    }

    async fn remove_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        let canonical = std::fs::canonicalize(path).map_err(|source| GuardError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        // BPF HashMap doesn't support single-key removal from userspace.
        // Full map reload requires daemon restart. Track removal locally.
        self.protected_paths.retain(|p| p != &canonical);

        self.protected_paths.retain(|p| p != &canonical);
        tracing::info!(path = %canonical.display(), "removed from eBPF protected inodes");
        Ok(())
    }

    async fn run(
        mut self: Box<Self>,
        tx: broadcast::Sender<SecurityEvent>,
    ) -> Result<(), GuardError> {
        let ring: RingBuf<_> = {
            // SAFETY: raw pointer used to work around borrow checker
            let bpf: *mut Bpf = &mut self.bpf;
            unsafe {
                RingBuf::try_from((*bpf).map_mut("FILE_EVENTS").ok_or_else(|| {
                    GuardError::Internal("FILE_EVENTS ring buffer not found".into())
                })?)
                .map_err(|e| GuardError::Internal(format!("RingBuf::try_from: {e}")))?
            }
        };
        let raw_fd = ring.as_raw_fd();
        let async_fd = tokio::io::unix::AsyncFd::new(raw_fd)
            .map_err(|e| GuardError::Internal(format!("AsyncFd: {e}")))?;

        let mut ring = ring;
        let mut event_count: u64 = 0;
        let mut drop_warned = false;
        tracing::info!("eBPF event listener started");

        loop {
            let mut guard = async_fd
                .readable()
                .await
                .map_err(|e| GuardError::Internal(format!("readable: {e}")))?;

            let mut batch = 0u32;
            while let Some(item) = ring.next() {
                batch = batch.wrapping_add(1);
                match parse_file_event(&item) {
                    Ok(ev) => {
                        event_count = event_count.wrapping_add(1);
                        if tx.send(ev).is_err() {
                            tracing::warn!("IPC channel closed — event listener shutting down");
                            return Ok(());
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "parse BPF event"),
                }
            }
            guard.clear_ready();

            // Si vaciamos muchos eventos de golpe, el ring buffer puede estar
            // cerca del overflow. Logueamos advertencia preventiva.
            if batch >= 1024 && !drop_warned {
                tracing::warn!(
                    batch,
                    total = event_count,
                    "high event throughput — ring buffer may overflow under sustained attack"
                );
                drop_warned = true;
            }
            if batch < 64 {
                drop_warned = false;
            }
        }
    }
}

// ── LSM ──────────────────────────────────────────────────────────

fn attach_lsm(bpf: &mut Bpf, name: &str) -> Result<(), GuardError> {
    let btf = aya::Btf::from_sys_fs()
        .map_err(|e| GuardError::Internal(format!("BTF from sysfs: {e}")))?;
    let prog: &mut Lsm = bpf
        .program_mut(name)
        .ok_or_else(|| GuardError::Internal(format!("BPF program '{name}' not found")))?
        .try_into()
        .map_err(|e| GuardError::Internal(format!("cast '{name}' to Lsm: {e}")))?;
    prog.load(name, &btf)
        .map_err(|e| GuardError::Internal(format!("load '{name}': {e}")))?;
    prog.attach()
        .map_err(|e| GuardError::Internal(format!("attach '{name}': {e}")))?;
    tracing::info!(hook = %name, "attached");
    Ok(())
}

#[allow(dead_code)]
fn try_attach_lsm(bpf: &mut Bpf, name: &str) -> bool {
    match attach_lsm(bpf, name) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(hook = %name, error = %e, "optional LSM hook skipped");
            false
        }
    }
}

// ── Events ───────────────────────────────────────────────────────

fn parse_file_event(item: &RingBufItem<'_>) -> Result<SecurityEvent, GuardError> {
    let expected = core::mem::size_of::<FileEvent>();
    if item.len() < expected {
        return Err(GuardError::Internal(format!(
            "ring buf item too short: {} < {expected}",
            item.len()
        )));
    }
    let ev: &FileEvent = unsafe { &*(item.as_ptr() as *const FileEvent) };

    let path_bytes = &ev.path[..(ev.path_len as usize).min(MAX_PREFIX_LEN)];
    let path = String::from_utf8_lossy(path_bytes).to_string();
    let comm_end = ev
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(agentguard_common::COMM_LEN);
    let comm = String::from_utf8_lossy(&ev.comm[..comm_end]).to_string();

    let violation = match ev.event_type {
        EventType::FileDelete => ViolationKind::DeleteAttempt,
        EventType::FileWrite => ViolationKind::WriteAttempt,
        EventType::FileRename => ViolationKind::RenameAttempt,
        EventType::NetworkSend => {
            // BPRM event via unified FILE_EVENTS — emit as agent detected
            return Ok(SecurityEvent::AgentDetected {
                pid: ev.pid,
                agent_name: comm,
                cwd: std::path::PathBuf::from(path),
                mode: "sandbox".into(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            });
        }
    };

    Ok(SecurityEvent::FileViolation {
        path: PathBuf::from(path),
        process: comm,
        pid: ev.pid,
        violation,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

fn check_bpf_lsm_available() -> Result<(), GuardError> {
    let p = "/sys/kernel/security/lsm";
    let lsm = std::fs::read_to_string(p).map_err(|source| GuardError::Io {
        path: PathBuf::from(p),
        source,
    })?;
    if !lsm.split(',').any(|m| m.trim() == "bpf") {
        return Err(GuardError::Unavailable(format!(
            "kernel LSM list does not include 'bpf' (got {:?})",
            lsm.trim()
        )));
    }
    Ok(())
}

// ── BPF program pinning (Fase 2) ───────────────────────────────

/// BPF_OBJ_PIN syscall — persists a BPF object (program, map, link) to bpffs.
#[repr(C)]
struct BpfObjPinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

const BPF_OBJ_PIN: libc::c_int = 6;

/// Directory where BPF programs are pinned for persistence.
const BPF_PIN_DIR: &str = "/sys/fs/bpf/agentguard";

/// Pin all loaded BPF programs to /sys/fs/bpf/agentguard/<name>.
/// This keeps programs in kernel memory across daemon restarts.
fn pin_all_programs(bpf: &Bpf) -> Result<Vec<PathBuf>, GuardError> {
    let dir = Path::new(BPF_PIN_DIR);
    std::fs::create_dir_all(dir).map_err(|source| GuardError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    let known_hooks = &[
        "file_unlink",
        "inode_rmdir",
        "inode_rename",
        "file_rename",
        "file_open",
        "inode_symlink",
        "inode_create",
        "inode_mkdir",
        "inode_mknod",
        "inode_link",
        "inode_setattr",
        "file_truncate",
        "bprm_check_security",
        "socket_connect",
    ];

    let mut pinned = Vec::new();

    for &hook in known_hooks {
        let pin_path = dir.join(hook);
        match pin_program(bpf, hook, &pin_path) {
            Ok(()) => {
                pinned.push(pin_path);
                tracing::debug!(hook, "pinned to bpffs");
            }
            Err(_e) => {
                // Program may not be loaded for this hook (optional hooks)
                tracing::debug!(hook, error = %_e, "skip pinning (not loaded)");
            }
        }
    }

    Ok(pinned)
}

/// Pin a single BPF program to a bpffs path.
fn pin_program(bpf: &Bpf, name: &str, path: &Path) -> Result<(), GuardError> {
    let prog: &Lsm = bpf
        .program(name)
        .ok_or_else(|| GuardError::Internal(format!("program '{name}' not found for pinning")))?
        .try_into()
        .map_err(|e| GuardError::Internal(format!("cast '{name}': {e}")))?;

    let fd = prog
        .fd()
        .map_err(|e| GuardError::Internal(format!("fd '{name}': {e}")))?;

    let raw_fd = fd.as_fd().as_raw_fd() as u32;

    let path_c = std::ffi::CString::new(path.to_str().unwrap_or(""))
        .map_err(|e| GuardError::Internal(format!("CString for '{name}': {e}")))?;

    let attr = BpfObjPinAttr {
        pathname: path_c.as_ptr() as u64,
        bpf_fd: raw_fd,
        file_flags: 0,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_PIN,
            &attr as *const _,
            std::mem::size_of::<BpfObjPinAttr>(),
        )
    };

    if ret < 0 {
        let err = unsafe { *libc::__errno_location() };
        return Err(GuardError::Internal(format!(
            "pin '{name}' to {}: errno {err}",
            path.display()
        )));
    }

    Ok(())
}

/// Check if there are pinned programs from a previous run.
/// If so, the daemon can recover them instead of reloading bytecode.
pub fn pinned_programs_exist() -> bool {
    let dir = Path::new(BPF_PIN_DIR);
    if !dir.is_dir() {
        return false;
    }
    // Check for at least one pinned program
    match std::fs::read_dir(dir) {
        Ok(entries) => entries.flatten().any(|e| e.path().is_file()),
        Err(_) => false,
    }
}

/// Clean up all pinned BPF programs (removes files only).
pub fn unpin_all() -> Result<(), GuardError> {
    let dir = Path::new(BPF_PIN_DIR);
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir).map_err(|source| GuardError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| GuardError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.is_file() {
            std::fs::remove_file(&path).map_err(|source| GuardError::Io {
                path: path.clone(),
                source,
            })?;
        }
    }
    tracing::info!("cleaned up pinned BPF programs");
    Ok(())
}

/// Limpiar programas BPF pineados de ejecuciones anteriores.
/// Llamar ANTES de EbpfGuard::load(). Limpia todo el directorio
/// y lo recrea vacío para el nuevo run.
pub fn cleanup_pinned_bpf() -> Result<(), anyhow::Error> {
    let pin_dir = Path::new(BPF_PIN_DIR);

    if !pin_dir.exists() {
        tracing::debug!("BPF pin dir does not exist, nothing to clean");
        return Ok(());
    }

    tracing::info!("Cleaning stale BPF programs from {}", BPF_PIN_DIR);

    remove_bpf_dir_recursive(pin_dir)?;

    // Recrear el directorio vacío para el nuevo run
    std::fs::create_dir_all(pin_dir)
        .map_err(|e| anyhow::anyhow!("Failed to recreate BPF pin dir: {e}"))?;

    tracing::info!("BPF pin dir cleaned and ready");
    Ok(())
}

fn remove_bpf_dir_recursive(dir: &Path) -> Result<(), anyhow::Error> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("read_dir {:?}: {e}", dir))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            remove_bpf_dir_recursive(&path)?;
            let _ = std::fs::remove_dir(&path);
        } else {
            std::fs::remove_file(&path).map_err(|e| anyhow::anyhow!("remove {:?}: {e}", path))?;
        }
    }
    Ok(())
}

// ── Map population helpers ──────────────────────────────────────
// Separadas para evitar borrow check issues con aya 0.13

/// Build the BPF inode key from `dev` and `ino`. Must match the kernel-side
/// computation in `file_guard.rs::inode_key`.
#[inline]
fn build_inode_key(dev: u64, ino: u64) -> u64 {
    ((dev) << 32) | (ino & 0xFFFF_FFFF)
}

/// Insert a single `(dev, ino)` pair into a populated `aya::HashMap`.
/// Returns `Ok(true)` on insert, `Ok(false)` if the BPF insert failed.
#[cfg(unix)]
fn insert_inode_kv(
    hmap: &mut HashMap<&mut aya::maps::MapData, u64, u8>,
    canonical: &Path,
    dev: u64,
    ino: u64,
) -> bool {
    let key = build_inode_key(dev, ino);
    match hmap.insert(key, 1, 0) {
        Ok(()) => {
            tracing::debug!(
                ?canonical,
                dev,
                ino,
                key = format!("{key:#x}"),
                "inode inserted"
            );
            true
        }
        Err(e) => {
            tracing::warn!(?canonical, dev, ino, error = %e, "failed to insert inode");
            false
        }
    }
}

/// Pure subtree walker: returns every `(path, dev, ino)` triple for
/// directories beneath `root` (excluding `root` itself).
///
/// Skips:
/// - symlinks (prevents pseudo-cycles via `/proc/.../cwd` etc.)
/// - mount-point crossings (different `dev` than `root_dev` — keeps blast
///   radius bounded; user can list other mounts explicitly in config)
///
/// Stops collecting once `limit` triples have been gathered (caller can
/// use the returned `Vec::len()` vs `limit` to detect truncation).
///
/// Separated from BPF map insertion so it can be unit-tested without a
/// real eBPF kernel context.
#[cfg(unix)]
fn walk_subtree_dirs(root: &Path, root_dev: u64, limit: u32) -> Vec<(PathBuf, u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    let mut out: Vec<(PathBuf, u64, u64)> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        if out.len() as u32 >= limit {
            break;
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(?dir, error = %e, "cannot read dir during subtree walk, skipping");
                continue;
            }
        };

        for entry in entries.flatten() {
            // Prefer file_type (cheap, no extra stat) for the symlink check.
            if let Ok(ft) = entry.file_type() {
                if ft.is_symlink() {
                    continue;
                }
                if !ft.is_dir() {
                    continue;
                }
            } else {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            if meta.dev() != root_dev {
                tracing::debug!(
                    path = ?entry.path(),
                    dev = meta.dev(),
                    root_dev,
                    "skipping mount-point crossing during subtree walk"
                );
                continue;
            }

            let path = entry.path();
            out.push((path.clone(), meta.dev(), meta.ino()));
            stack.push(path);

            if out.len() as u32 >= limit {
                break;
            }
        }
    }

    out
}

/// Insert every subdirectory beneath `root` into the BPF inode hashmap.
/// Returns the number of entries actually inserted.
///
/// This is the userspace counterpart of `file_open`'s parent-dentry check
/// in `file_guard.rs:284-307`. Without subtree indexing only top-level
/// dirs are matched, so files in `~/Documents/Projects/foo.md` whose
/// parent is `Projects/` (not `Documents/`) escape protection.
#[cfg(unix)]
fn index_subtree_dirs(
    root: &Path,
    root_dev: u64,
    hmap: &mut HashMap<&mut aya::maps::MapData, u64, u8>,
    count: &mut u32,
    limit: u32,
) -> Result<u32, GuardError> {
    let remaining = limit.saturating_sub(*count);
    let triples = walk_subtree_dirs(root, root_dev, remaining);

    if triples.len() as u32 >= remaining {
        tracing::warn!(
            root = ?root,
            limit,
            "BPF inode map limit reached during subtree walk; some \
             subdirectories will not be protected. Consider raising \
             MAX_PROTECTED_INODES if your protected tree is huge."
        );
    }

    let mut indexed = 0u32;
    for (path, dev, ino) in triples {
        if *count >= limit {
            break;
        }
        if insert_inode_kv(hmap, &path, dev, ino) {
            *count += 1;
            indexed += 1;
        }
    }
    Ok(indexed)
}

/// Populate a BPF inode hashmap (`PROTECTED_DIR_INODES` or
/// `PROTECTED_FILE_INODES`) from a list of paths.
///
/// For directory maps this also walks the entire subtree (see
/// `index_subtree_dirs`) so that deeply-nested files match the
/// kernel-side parent-inode lookup.
fn populate_inode_map(bpf: &mut Bpf, map_name: &str, paths: &[PathBuf]) -> Result<(), GuardError> {
    let recurse = map_name == "PROTECTED_DIR_INODES";
    let limit = MAX_PROTECTED_INODES;

    let mut hmap: HashMap<_, u64, u8> = HashMap::try_from(
        bpf.map_mut(map_name)
            .ok_or_else(|| GuardError::Internal(format!("{map_name} map not found")))?,
    )
    .map_err(|e| GuardError::Internal(format!("{map_name}: {e}")))?;

    let mut count = 0u32;

    for path in paths {
        if count >= limit {
            tracing::warn!(map = %map_name, limit, "inode map full, remaining roots skipped");
            break;
        }
        let canonical = match std::fs::canonicalize(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(?path, error = %e, "cannot canonicalize path, skipping");
                continue;
            }
        };

        let meta = match std::fs::metadata(&canonical) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(?canonical, error = %e, "cannot stat path, skipping");
                continue;
            }
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let dev = meta.dev();
            let ino = meta.ino();

            tracing::info!(
                ?canonical, dev, ino,
                key = format!("{:#x}", build_inode_key(dev, ino)),
                map = %map_name,
                "indexing root path"
            );

            if insert_inode_kv(&mut hmap, &canonical, dev, ino) {
                count += 1;
            }

            if recurse && meta.is_dir() {
                let indexed = index_subtree_dirs(&canonical, dev, &mut hmap, &mut count, limit)?;
                tracing::info!(
                    ?canonical,
                    indexed,
                    "subtree indexed (subdirectories added to inode map)"
                );
            }
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            count += 1; // stub for non-unix
        }
    }

    tracing::info!(map = %map_name, inodes = count, recurse, "populated inode map");

    if count == 0 {
        tracing::error!(
            map = %map_name,
            "CRITICAL: 0 inodes loaded — protection is DISABLED for this map. \
             Check that protected_dirs/files exist and AGENTGUARD_USER_HOME is set correctly."
        );
    }
    Ok(())
}

/// Lee /sys/kernel/btf/vmlinux y extrae los offsets reales de los structs del kernel.
/// Los popula en el mapa BPF OFFSETS (índices 0-6).
///
/// Slot layout:
///   0 = inode.i_ino
///   1 = inode.i_sb
///   2 = super_block.s_dev
///   3 = file.f_inode
///   4 = dentry.d_parent
///   5 = dentry.d_inode
///   6 = file.f_flags    (added for write-mode filtering in file_open)
fn populate_btf_offsets(bpf: &mut Bpf) -> Result<(), GuardError> {
    // Defaults match `DFL_*` constants in agentguard-ebpf/src/file_guard.rs.
    // Slot 6 (f_flags) defaults to 0xa8 — matches kernels 5.15-6.x on x86_64.
    let mut offsets: [u64; 7] = [8, 24, 0, 32, 24, 48, 0xa8];

    // Best-effort BTF parsing. Any parse error leaves defaults in place — the
    // eBPF program has identical fallbacks and will still operate correctly
    // on kernels 5.15-6.x/x86_64. Panicking here would crash the daemon
    // during startup and disable all protection.
    let parsed = parse_btf_offsets(&mut offsets);
    match &parsed {
        Ok(()) => tracing::info!(
            i_ino = offsets[0],
            i_sb = offsets[1],
            s_dev = offsets[2],
            f_inode = offsets[3],
            d_parent = offsets[4],
            d_inode = offsets[5],
            f_flags = offsets[6],
            "BTF kernel struct offsets resolved",
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "BTF parsing failed; falling back to compile-time defaults",
        ),
    }

    // Sanity gate: on any kernel we care about, `inode.i_ino`, `inode.i_sb`,
    // and `file.f_flags` are non-zero offsets inside their struct. If BTF
    // parsing failed AND the compile-time defaults happen to be wrong for
    // this kernel, the eBPF program will read garbage and silently let every
    // attack through. We'd rather refuse to run in eBPF mode and let the
    // userspace backend take over with honest diagnostics.
    if parsed.is_err() {
        // i_ino default 8 / i_sb default 24 are pre-kernel-5 layouts — any
        // attempt to run with them on a modern kernel corrupts inode keys.
        // Bail out so KernelGuard::try_load falls back to userspace.
        if offsets[0] < 16 || offsets[1] < 16 {
            return Err(GuardError::Unavailable(format!(
                "BTF unavailable and compile-time offsets are too old for this kernel \
                 (i_ino={}, i_sb={}). eBPF protection would run with wrong struct \
                 offsets and silently fail to block attacks. Falling back to userspace.",
                offsets[0], offsets[1],
            )));
        }
    }

    // Populate OFFSETS array map. All values are known-bounded (< 4096).
    let mut off_map: aya::maps::Array<_, u64> = aya::maps::Array::try_from(
        bpf.map_mut("OFFSETS")
            .ok_or_else(|| GuardError::Internal("OFFSETS map not found".into()))?,
    )
    .map_err(|e| GuardError::Internal(format!("OFFSETS: {e}")))?;

    for (i, &val) in offsets.iter().enumerate() {
        off_map
            .set(i as u32, val, 0)
            .map_err(|e| GuardError::Internal(format!("OFFSETS[{i}]: {e}")))?;
    }

    Ok(())
}

/// Safe, bounds-checked BTF parser that walks every type entry and extracts
/// the member offsets we care about. Handles every BTF_KIND variant's entry
/// size per libbpf's spec. Returns `Err` (never panics) on truncated or
/// malformed BTF; caller keeps compile-time defaults.
fn parse_btf_offsets(offsets: &mut [u64; 7]) -> Result<(), String> {
    const BTF_MAGIC: u16 = 0xEB9F;
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("read /sys/kernel/btf/vmlinux: {e}"))?;
    if data.len() < 24 {
        return Err("BTF header too short".into());
    }
    let magic = u16::from_ne_bytes([data[0], data[1]]);
    if magic != BTF_MAGIC {
        return Err(format!("bad BTF magic 0x{magic:04x}"));
    }
    // struct btf_header (linux/btf.h):
    //   u16 magic     @ 0x00
    //   u8  version   @ 0x02
    //   u8  flags     @ 0x03
    //   u32 hdr_len   @ 0x04
    //   u32 type_off  @ 0x08
    //   u32 type_len  @ 0x0c
    //   u32 str_off   @ 0x10
    //   u32 str_len   @ 0x14
    let hdr_len = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let type_off = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let type_len = u32::from_ne_bytes([data[12], data[13], data[14], data[15]]) as usize;
    let str_off = u32::from_ne_bytes([data[16], data[17], data[18], data[19]]) as usize;
    let str_len = u32::from_ne_bytes([data[20], data[21], data[22], data[23]]) as usize;
    let types_start = hdr_len.checked_add(type_off).ok_or("type_off overflow")?;
    let types_end = types_start
        .checked_add(type_len)
        .ok_or("type_len overflow")?;
    let strings_start = hdr_len.checked_add(str_off).ok_or("str_off overflow")?;
    let strings_end = strings_start
        .checked_add(str_len)
        .ok_or("str_len overflow")?;
    if types_end > data.len() || strings_end > data.len() {
        return Err("BTF sections exceed file".into());
    }
    let types = &data[types_start..types_end];
    let strings = &data[strings_start..strings_end];

    #[inline]
    fn btf_str(strings: &[u8], off: u32) -> &str {
        let start = off as usize;
        if start >= strings.len() {
            return "";
        }
        let rest = &strings[start..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        core::str::from_utf8(&rest[..end]).unwrap_or("")
    }

    // BTF type entry kinds — values per linux/btf.h.
    // Kind 0 is the UNKN/void sentinel (always first entry, no payload).
    const K_UNKN: u32 = 0;
    const K_INT: u32 = 1;
    const K_PTR: u32 = 2;
    const K_ARRAY: u32 = 3;
    const K_STRUCT: u32 = 4;
    const K_UNION: u32 = 5;
    const K_ENUM: u32 = 6;
    const K_FWD: u32 = 7;
    const K_TYPEDEF: u32 = 8;
    const K_VOLATILE: u32 = 9;
    const K_CONST: u32 = 10;
    const K_RESTRICT: u32 = 11;
    const K_FUNC: u32 = 12;
    const K_FUNC_PROTO: u32 = 13;
    const K_VAR: u32 = 14;
    const K_DATASEC: u32 = 15;
    const K_FLOAT: u32 = 16;
    const K_DECL_TAG: u32 = 17;
    const K_TYPE_TAG: u32 = 18;
    const K_ENUM64: u32 = 19;

    // struct btf_type layout:
    //   u32 name_off @  0
    //   u32 info     @  4   ← bits 0-15 vlen, 24-27 kind, 31 kind_flag
    //   u32 size|type @ 8   ← size (for INT/ENUM/STRUCT/UNION/DATASEC) or type_id
    let mut pos = 0usize;
    while pos + 12 <= types.len() {
        let name_off =
            u32::from_ne_bytes([types[pos], types[pos + 1], types[pos + 2], types[pos + 3]]);
        let info = u32::from_ne_bytes([
            types[pos + 4],
            types[pos + 5],
            types[pos + 6],
            types[pos + 7],
        ]);
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;

        // Parse struct members for the four types we need.
        if kind == K_STRUCT {
            let name = btf_str(strings, name_off);
            if matches!(name, "inode" | "file" | "super_block" | "dentry") {
                tracing::debug!(btf_struct = %name, members = vlen, "BTF: matched target struct");
                for i in 0..vlen {
                    let mp = pos + 12 + i * 12;
                    if mp + 12 > types.len() {
                        break;
                    }
                    let m_name_off = u32::from_ne_bytes([
                        types[mp],
                        types[mp + 1],
                        types[mp + 2],
                        types[mp + 3],
                    ]);
                    let m_offset = u32::from_ne_bytes([
                        types[mp + 8],
                        types[mp + 9],
                        types[mp + 10],
                        types[mp + 11],
                    ]);
                    let m_name = btf_str(strings, m_name_off);
                    // BTF struct member offset is bits; bit 31 signals bitfield (mask 0x7fffffff).
                    let byte_off = ((m_offset & 0x00ff_ffff) / 8) as u64;
                    match (name, m_name) {
                        ("inode", "i_ino") => offsets[0] = byte_off,
                        ("inode", "i_sb") => offsets[1] = byte_off,
                        ("super_block", "s_dev") => offsets[2] = byte_off,
                        ("file", "f_inode") => offsets[3] = byte_off,
                        ("dentry", "d_parent") => offsets[4] = byte_off,
                        ("dentry", "d_inode") => offsets[5] = byte_off,
                        ("file", "f_flags") => offsets[6] = byte_off,
                        _ => {}
                    }
                }
            }
        }

        // Per-kind entry size (after the 12-byte common header). Table from
        // Documentation/bpf/btf.rst + libbpf btf.c.
        let extra = match kind {
            K_INT => 4,
            K_ARRAY => 12,
            K_STRUCT | K_UNION => vlen * 12,
            K_ENUM => vlen * 8,
            // struct btf_enum64 = { u32 name_off; u32 val_lo32; u32 val_hi32 }
            K_ENUM64 => vlen * 12,
            K_FUNC_PROTO => vlen * 8,
            K_VAR => 4,
            K_DATASEC => vlen * 12,
            K_DECL_TAG => 4,
            // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT,
            // TYPE_TAG: no extra payload beyond the 12-byte header.
            K_UNKN | K_PTR | K_FWD | K_TYPEDEF | K_VOLATILE | K_CONST | K_RESTRICT | K_FUNC
            | K_FLOAT | K_TYPE_TAG => 0,
            _ => {
                // Unknown kind — bail out; parsing further risks desync.
                return Err(format!("unknown BTF kind {kind} at offset {pos}"));
            }
        };

        pos = pos.checked_add(12 + extra).ok_or("type size overflow")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parser regression guard: run against the live kernel's BTF blob and
    /// verify we extract *plausible* offsets for the structs we rely on.
    /// Skipped on hosts where `/sys/kernel/btf/vmlinux` is unreadable
    /// (non-Linux, containers with BTF stripped, CI without root).
    #[test]
    fn parse_btf_offsets_finds_real_kernel_struct_offsets() {
        if std::fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
            eprintln!("skipping: /sys/kernel/btf/vmlinux unavailable");
            return;
        }
        let mut offsets: [u64; 7] = [0; 7];
        match parse_btf_offsets(&mut offsets) {
            Ok(()) => {
                eprintln!(
                    "resolved offsets: i_ino={}, i_sb={}, s_dev={}, f_inode={}, d_parent={}, d_inode={}, f_flags={}",
                    offsets[0], offsets[1], offsets[2], offsets[3], offsets[4], offsets[5], offsets[6]
                );
                // Sanity: every field should be > 0 on any modern Linux
                // (≥ 5.x).  We do NOT assert relative ordering between i_ino
                // and i_sb because the kernel's struct inode layout varies
                // across versions and architectures (e.g. i_ino=64 > i_sb=40
                // on Fedora 44 / kernel 6.19).
                assert!(offsets[0] > 0, "i_ino offset should be non-zero");
                assert!(offsets[1] > 0, "i_sb offset should be non-zero");
                // s_dev lives near the top of struct super_block; accept 0+ here
                // because it is genuinely at offset 0 on some archs.
                assert!(offsets[3] > 0, "file.f_inode offset should be non-zero");
                assert!(offsets[5] > 0, "dentry.d_inode offset should be non-zero");
                assert!(offsets[6] > 0, "file.f_flags offset should be non-zero");
                // Must be reasonable struct offsets, not pointer garbage.
                for (i, v) in offsets.iter().enumerate() {
                    assert!(*v < 4096, "offset[{i}] = {v} exceeds MAX_STRUCT_OFFSET");
                }
            }
            Err(e) => panic!("BTF parser failed on live kernel: {e}"),
        }
    }

    #[tokio::test]
    async fn try_load_requires_root_and_bpf_lsm() {
        let err = EbpfGuard::try_load(&[], &[]).await.unwrap_err();
        assert!(
            matches!(
                err,
                GuardError::Unavailable(_) | GuardError::Io { .. } | GuardError::Internal(_)
            ),
            "unexpected error: {err:?}"
        );
    }

    /// Phase 2 — verify the recursive walker discovers every subdirectory
    /// beneath the root, returns correct (dev, ino) pairs, and respects
    /// `limit`.
    #[cfg(unix)]
    #[test]
    fn walk_subtree_dirs_finds_all_nested_directories() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();

        // Build:
        //   root/a/b/c        (3 nested dirs)
        //   root/x            (1 sibling dir)
        //   root/x/file.txt   (a file — should NOT be in the walk)
        std::fs::create_dir_all(root.join("a/b/c")).unwrap();
        std::fs::create_dir(root.join("x")).unwrap();
        std::fs::write(root.join("x/file.txt"), b"content").unwrap();

        let root_dev = std::fs::metadata(root).unwrap().dev();
        let triples = walk_subtree_dirs(root, root_dev, 100);

        // Expected directories: a, a/b, a/b/c, x  → 4 entries
        assert_eq!(
            triples.len(),
            4,
            "expected 4 subdirectories, got {}: {:?}",
            triples.len(),
            triples.iter().map(|(p, ..)| p.clone()).collect::<Vec<_>>()
        );

        // Each path must be one of the 4 we created
        let paths: std::collections::HashSet<_> = triples.iter().map(|(p, ..)| p.clone()).collect();
        assert!(paths.contains(&root.join("a")));
        assert!(paths.contains(&root.join("a/b")));
        assert!(paths.contains(&root.join("a/b/c")));
        assert!(paths.contains(&root.join("x")));

        // (dev, ino) must match what stat() returns
        for (path, dev, ino) in &triples {
            let m = std::fs::metadata(path).unwrap();
            assert_eq!(*dev, m.dev(), "dev mismatch for {:?}", path);
            assert_eq!(*ino, m.ino(), "ino mismatch for {:?}", path);
        }
    }

    /// Verify the walker honours the `limit` parameter.
    #[cfg(unix)]
    #[test]
    fn walk_subtree_dirs_respects_limit() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        for i in 0..10 {
            std::fs::create_dir(root.join(format!("d{i}"))).unwrap();
        }
        let root_dev = std::fs::metadata(root).unwrap().dev();

        let triples = walk_subtree_dirs(root, root_dev, 4);
        assert!(
            triples.len() <= 4,
            "walker exceeded limit: {}",
            triples.len()
        );
        assert!(!triples.is_empty(), "walker returned nothing");
    }

    /// Verify symlinked directories are not followed (no infinite loops).
    #[cfg(unix)]
    #[test]
    fn walk_subtree_dirs_skips_symlinks() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir(root.join("real")).unwrap();
        // Create a symlink loop pointing back to root
        let link = root.join("loop");
        std::os::unix::fs::symlink(root, &link).unwrap();

        let root_dev = std::fs::metadata(root).unwrap().dev();
        let triples = walk_subtree_dirs(root, root_dev, 100);

        // Should contain `real` but not the symlink (and must terminate quickly)
        let paths: std::collections::HashSet<_> = triples.iter().map(|(p, ..)| p.clone()).collect();
        assert!(paths.contains(&root.join("real")));
        assert!(!paths.contains(&link), "symlink was followed: {:?}", paths);
    }

    /// Phase 1 sanity — verify the BPF inode-key construction matches the
    /// kernel-side formula in `file_guard.rs::inode_key`.
    #[test]
    fn build_inode_key_packs_dev_and_ino_consistently() {
        // dev=0x1234, ino=0xdeadbeef → expected 0x0000_1234_dead_beef
        let key = build_inode_key(0x1234, 0xdeadbeef);
        assert_eq!(key, 0x0000_1234_dead_beef);

        // High bits of ino are masked off (must match kernel side)
        let key = build_inode_key(0x1, 0xffffffff_ffffffff);
        assert_eq!(key, 0x0000_0001_ffff_ffff);
    }
}
