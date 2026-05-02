//! Backend eBPF LSM — protección kernel-level real.
//!
//! Requisitos para activar:
//! - `feature = "ebpf"` al compilar.
//! - Bytecode eBPF pre-compilado con `scripts/build-ebpf.sh`.
//! - Kernel Linux ≥ 5.10 con `CONFIG_BPF_LSM=y`.

use std::path::{Path, PathBuf};

use aya::maps::ring_buf::RingBufItem;
use aya::maps::{Array, RingBuf};
use aya::programs::Lsm;
use aya::{Bpf, BpfLoader};
use async_trait::async_trait;
use tokio::sync::mpsc;

use agentguard_common::{EventType, FileEvent, PathPrefix, MAX_PREFIXES, MAX_PREFIX_LEN};
use agentguard_core::{GuardError, KernelGuard, ProtectionLevel, SecurityEvent, ViolationKind};

/// Bytecodes eBPF embebidos en el binario del daemon.
const FILE_GUARD_BYTECODE: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/file_guard.bpf.o"));
const NET_GUARD_BYTECODE: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net_guard.bpf.o"));

/// Backend eBPF LSM con los programas cargados y attachados al kernel.
pub struct EbpfGuard {
    bpf: Bpf,
    protected_paths: Vec<PathBuf>,
}

impl std::fmt::Debug for EbpfGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EbpfGuard")
            .field("paths", &self.protected_paths.len())
            .finish_non_exhaustive()
    }
}

impl EbpfGuard {
    /// Intenta cargar los programas eBPF LSM y attachar los hooks.
    pub async fn try_load(paths: &[PathBuf], protected_files: &[PathBuf]) -> Result<Self, GuardError> {
        check_bpf_lsm_available()?;

        tracing::info!("loading eBPF LSM programs");

        // 1. Cargar file_guard
        let mut bpf_file = BpfLoader::new()
            .btf(aya::Btf::from_sys_fs().ok().as_ref())
            .load(FILE_GUARD_BYTECODE)
            .map_err(|e| GuardError::Internal(format!("load file_guard BPF: {e}")))?;

        // Attachar los hooks LSM de filesystem
        attach_lsm(&mut bpf_file, "file_unlink")?;
        attach_lsm(&mut bpf_file, "file_rename")?;
        attach_lsm(&mut bpf_file, "file_open")?;

        // 2. Cargar net_guard
        let bpf_net = BpfLoader::new()
            .btf(aya::Btf::from_sys_fs().ok().as_ref())
            .load(NET_GUARD_BYTECODE)
            .map_err(|e| GuardError::Internal(format!("load net_guard BPF: {e}")))?;

        drop(bpf_net);

        // 3. Poblar el mapa PROTECTED_PREFIXES
        populate_prefixes(&mut bpf_file, paths)?;

        // 4. Poblar PROTECTED_WRITE_PATHS
        populate_write_paths(&mut bpf_file, protected_files)?;

        tracing::info!(paths = paths.len(), "eBPF LSM programs loaded — kernel-level protection active");

        Ok(Self { bpf: bpf_file, protected_paths: paths.to_vec() })
    }
}

#[async_trait]
impl KernelGuard for EbpfGuard {
    fn backend_name(&self) -> &'static str { "ebpf-lsm" }
    fn protection_level(&self) -> ProtectionLevel { ProtectionLevel::KernelDenial }

    async fn add_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        let canonical = std::fs::canonicalize(path).map_err(|source| GuardError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let count_map: Array<&mut aya::maps::MapData, u32> =
            Array::try_from(self.bpf.map_mut("PREFIX_COUNT").ok_or_else(|| {
                GuardError::Internal("PREFIX_COUNT map not found".into())
            })?)
            .map_err(|e| GuardError::Internal(format!("open PREFIX_COUNT: {e}")))?;

        let count = count_map.get(&0, 0).map_err(|e| GuardError::Internal(format!("read PREFIX_COUNT: {e}")))?;

        if count >= MAX_PREFIXES {
            return Err(GuardError::Internal(format!("max protected prefixes reached ({MAX_PREFIXES})")));
        }

        let bytes = canonical.as_os_str().as_encoded_bytes();
        if bytes.len() > MAX_PREFIX_LEN {
            return Err(GuardError::Internal(format!("path {canonical:?} exceeds MAX_PREFIX_LEN ({MAX_PREFIX_LEN})")));
        }
        let prefix = PathPrefix::from_bytes(bytes).ok_or_else(|| {
            GuardError::Internal(format!("path too long: {canonical:?}"))
        })?;

        let prefixes_map: Array<&mut aya::maps::MapData, PathPrefix> =
            Array::try_from(self.bpf.map_mut("PROTECTED_PREFIXES").ok_or_else(|| {
                GuardError::Internal("PROTECTED_PREFIXES map not found".into())
            })?)
            .map_err(|e| GuardError::Internal(format!("open PROTECTED_PREFIXES: {e}")))?;

        prefixes_map.set(count, prefix, 0).map_err(|e| GuardError::Internal(format!("set PROTECTED_PREFIXES: {e}")))?;

        count_map.set(0, count + 1, 0).map_err(|e| GuardError::Internal(format!("update PREFIX_COUNT: {e}")))?;

        self.protected_paths.push(path.to_path_buf());
        tracing::info!(path = ?canonical, "added eBPF-protected prefix");
        Ok(())
    }

    async fn remove_protected_path(&mut self, _path: &Path) -> Result<(), GuardError> {
        Err(GuardError::Internal(
            "runtime path removal not implemented in eBPF backend. Remove the path from config.toml and restart the daemon.".into(),
        ))
    }

    async fn run(mut self: Box<Self>, tx: mpsc::Sender<SecurityEvent>) -> Result<(), GuardError> {
        let ring_buf: RingBuf<&mut aya::maps::MapData> =
            RingBuf::try_from(self.bpf.map_mut("FILE_EVENTS").ok_or_else(|| {
                GuardError::Internal("FILE_EVENTS ring buffer not found".into())
            })?)
            .map_err(|e| GuardError::Internal(format!("open FILE_EVENTS: {e}")))?;

        let mut poll = ring_buf.into_poll().map_err(|e| GuardError::Internal(format!("poll FILE_EVENTS: {e}")))?;

        tracing::info!("eBPF event listener started");

        loop {
            let items = poll.poll_wait().map_err(|e| GuardError::Internal(format!("poll_wait: {e}")))?;

            for item in items {
                match parse_file_event(&item) {
                    Ok(ev) => { let _ = tx.send(ev).await; }
                    Err(e) => { tracing::warn!(error = %e, "failed to parse BPF file event"); }
                }
            }
        }
    }
}

fn attach_lsm(bpf: &mut Bpf, name: &str) -> Result<(), GuardError> {
    let prog: &mut Lsm = bpf
        .program_mut(name)
        .ok_or_else(|| GuardError::Internal(format!("BPF program '{name}' not found")))?
        .try_into()
        .map_err(|e| GuardError::Internal(format!("cast '{name}' to Lsm: {e}")))?;

    prog.load(name).map_err(|e| GuardError::Internal(format!("load LSM '{name}': {e}")))?;
    prog.attach().map_err(|e| GuardError::Internal(format!("attach LSM '{name}': {e}")))?;

    tracing::info!(hook = %name, "eBPF LSM hook attached");
    Ok(())
}

fn populate_prefixes(bpf: &mut Bpf, paths: &[PathBuf]) -> Result<(), GuardError> {
    let mut prefixes_map: Array<&mut aya::maps::MapData, PathPrefix> =
        Array::try_from(
            bpf.map_mut("PROTECTED_PREFIXES")
                .ok_or_else(|| GuardError::Internal("PROTECTED_PREFIXES map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("open PROTECTED_PREFIXES: {e}")))?;

    let mut count_map: Array<&mut aya::maps::MapData, u32> =
        Array::try_from(
            bpf.map_mut("PREFIX_COUNT")
                .ok_or_else(|| GuardError::Internal("PREFIX_COUNT map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("open PREFIX_COUNT: {e}")))?;

    let mut written: u32 = 0;
    for path in paths {
        if written >= MAX_PREFIXES { break; }
        let canonical = std::fs::canonicalize(path).map_err(|source| GuardError::Io {
            path: path.clone(),
            source,
        })?;
        let bytes = canonical.as_os_str().as_encoded_bytes();
        if bytes.len() > MAX_PREFIX_LEN {
            tracing::warn!(?canonical, "path exceeds MAX_PREFIX_LEN, skipping");
            continue;
        }
        let prefix = PathPrefix::from_bytes(bytes).ok_or_else(|| {
            GuardError::Internal(format!("path too long: {canonical:?}"))
        })?;
        prefixes_map.set(written, prefix, 0).map_err(|e| GuardError::Internal(format!("set PROTECTED_PREFIXES[{written}]: {e}")))?;
        written += 1;
    }
    count_map.set(0, written, 0).map_err(|e| GuardError::Internal(format!("set PREFIX_COUNT: {e}")))?;

    tracing::info!(prefixes = written, "populated eBPF PROTECTED_PREFIXES map");
    Ok(())
}

fn populate_write_paths(bpf: &mut Bpf, files: &[PathBuf]) -> Result<(), GuardError> {
    let mut write_map: Array<&mut aya::maps::MapData, PathPrefix> =
        Array::try_from(
            bpf.map_mut("PROTECTED_WRITE_PATHS")
                .ok_or_else(|| GuardError::Internal("PROTECTED_WRITE_PATHS map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("open PROTECTED_WRITE_PATHS: {e}")))?;

    let mut count_map: Array<&mut aya::maps::MapData, u32> =
        Array::try_from(
            bpf.map_mut("WRITE_PATH_COUNT")
                .ok_or_else(|| GuardError::Internal("WRITE_PATH_COUNT map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("open WRITE_PATH_COUNT: {e}")))?;

    let mut written: u32 = 0;
    for path in files {
        if written >= MAX_PREFIXES { break; }
        let canonical = std::fs::canonicalize(path).map_err(|source| GuardError::Io {
            path: path.clone(),
            source,
        })?;
        let bytes = canonical.as_os_str().as_encoded_bytes();
        if bytes.len() > MAX_PREFIX_LEN {
            tracing::warn!(?canonical, "file path exceeds MAX_PREFIX_LEN, skipping");
            continue;
        }
        let entry = PathPrefix::from_bytes(bytes).ok_or_else(|| {
            GuardError::Internal(format!("file path too long: {canonical:?}"))
        })?;
        write_map.set(written, entry, 0).map_err(|e| {
            GuardError::Internal(format!("set PROTECTED_WRITE_PATHS[{written}]: {e}"))
        })?;
        written += 1;
    }
    count_map.set(0, written, 0).map_err(|e| {
        GuardError::Internal(format!("set WRITE_PATH_COUNT: {e}"))
    })?;

    tracing::info!(files = written, "populated eBPF PROTECTED_WRITE_PATHS map");
    Ok(())
}

fn parse_file_event(item: &RingBufItem<'_>) -> Result<SecurityEvent, GuardError> {
    let expected = core::mem::size_of::<FileEvent>();
    if item.len() < expected {
        return Err(GuardError::Internal(format!("ring buffer item too short: {} < {expected}", item.len())));
    }
    let ev: &FileEvent = unsafe { &*(item.as_ptr() as *const FileEvent) };

    let path_bytes = &ev.path[..(ev.path_len as usize).min(MAX_PREFIX_LEN)];
    let path = String::from_utf8_lossy(path_bytes).to_string();

    let comm_end = ev.comm.iter().position(|&b| b == 0).unwrap_or(agentguard_common::COMM_LEN);
    let comm = String::from_utf8_lossy(&ev.comm[..comm_end]).to_string();

    let violation = match ev.event_type {
        EventType::FileDelete => ViolationKind::DeleteAttempt,
        EventType::FileWrite => ViolationKind::WriteAttempt,
        EventType::FileRename => ViolationKind::RenameAttempt,
        EventType::NetworkSend => {
            return Err(GuardError::Internal("NetworkSend event in file guard ring buffer".into()));
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
    let lsm_path = "/sys/kernel/security/lsm";
    let lsm = std::fs::read_to_string(lsm_path).map_err(|source| GuardError::Io {
        path: PathBuf::from(lsm_path),
        source,
    })?;
    if !lsm.split(',').any(|m| m.trim() == "bpf") {
        return Err(GuardError::Unavailable(format!(
            "kernel LSM list does not include 'bpf' (got {:?}). Add lsm=...,bpf to the kernel cmdline or boot a kernel with CONFIG_BPF_LSM=y",
            lsm.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn try_load_requires_root_and_bpf_lsm() {
        let err = EbpfGuard::try_load(&[], &[]).await.unwrap_err();
        assert!(
            matches!(err, GuardError::Unavailable(_) | GuardError::Io { .. }),
            "unexpected error: {err:?}"
        );
    }
}
