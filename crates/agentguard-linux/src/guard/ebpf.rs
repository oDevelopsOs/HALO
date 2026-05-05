//! Backend eBPF LSM — protecci\u{f3}n kernel-level real.

use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use aya::maps::ring_buf::RingBufItem;
use aya::maps::{Array, RingBuf};
use aya::programs::Lsm;
use aya::{Bpf, BpfLoader};
use include_bytes_aligned::include_bytes_aligned;
use tokio::sync::mpsc;

use agentguard_common::{EventType, FileEvent, PathPrefix, MAX_PREFIXES, MAX_PREFIX_LEN};
use agentguard_core::{GuardError, KernelGuard, ProtectionLevel, SecurityEvent, ViolationKind};

const FILE_GUARD_BYTECODE: &[u8] =
    include_bytes_aligned!(4096, concat!(env!("OUT_DIR"), "/file_guard.bpf.o"));
const NET_GUARD_BYTECODE: &[u8] =
    include_bytes_aligned!(4096, concat!(env!("OUT_DIR"), "/net_guard.bpf.o"));

pub struct EbpfGuard {
    bpf: Bpf,
    bpf_net: Option<Bpf>,
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
    pub async fn try_load(
        paths: &[PathBuf],
        protected_files: &[PathBuf],
    ) -> Result<Self, GuardError> {
        check_bpf_lsm_available()?;
        tracing::info!("loading eBPF LSM programs");

        let mut bpf_file = BpfLoader::new()
            .btf(aya::Btf::from_sys_fs().ok().as_ref())
            .load(FILE_GUARD_BYTECODE)
            .map_err(|e| GuardError::Internal(format!("load file_guard BPF: {e}")))?;

        // Attachar todos los hooks LSM
        attach_lsm(&mut bpf_file, "file_unlink")?;
        attach_lsm(&mut bpf_file, "inode_rmdir")?;
        attach_lsm(&mut bpf_file, "inode_rename")?;
        try_attach_lsm(&mut bpf_file, "file_rename");
        attach_lsm(&mut bpf_file, "file_open")?;
        // Nuevos hooks — cierre de bypass
        attach_lsm(&mut bpf_file, "inode_symlink")?;
        attach_lsm(&mut bpf_file, "inode_create")?;
        attach_lsm(&mut bpf_file, "inode_mkdir")?;
        attach_lsm(&mut bpf_file, "inode_mknod")?;
        attach_lsm(&mut bpf_file, "inode_link")?;
        try_attach_lsm(&mut bpf_file, "inode_setattr"); // depende de kernel >= 5.12
        attach_lsm(&mut bpf_file, "file_truncate")?;
        try_attach_lsm(&mut bpf_file, "bprm_check_security"); // optional: kernel >= 5.7

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
                });
            }
        }

        // Poblar PROTECTED_PREFIXES
        populate_prefixes_inner(&mut bpf_file, paths)?;

        // Poblar PROTECTED_WRITE_PATHS
        populate_write_paths_inner(&mut bpf_file, protected_files)?;

        tracing::info!(paths = paths.len(), "eBPF LSM loaded");

        Ok(Self {
            bpf: bpf_file,
            bpf_net: Some(bpf_net),
            protected_paths: paths.to_vec(),
        })
    }
    /// Devuelve Some si el network guard está activo.
    pub fn network_guard_active(&self) -> bool {
        self.bpf_net.is_some()
    }

    /// Popula el mapa KNOWN_AGENTS_BPRM con hashes FNV-1a de los agentes conocidos.
    /// Esto permite que el hook bprm_check_security bloquee exec() de agentes IA.
    pub fn populate_bprm_agents(&self, agent_names: &[String]) -> Result<(), GuardError> {
        use agentguard_linux::process_watcher::fnv1a_hash;

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

    async fn add_protected_path(&mut self, _path: &Path) -> Result<(), GuardError> {
        Err(GuardError::Internal(
            "runtime add not implemented: modify config.toml and restart".into(),
        ))
    }

    async fn remove_protected_path(&mut self, _path: &Path) -> Result<(), GuardError> {
        Err(GuardError::Internal(
            "runtime remove not implemented: modify config.toml and restart".into(),
        ))
    }

    async fn run(mut self: Box<Self>, tx: mpsc::Sender<SecurityEvent>) -> Result<(), GuardError> {
        let ring: RingBuf<_> = RingBuf::try_from(
            self.bpf
                .map_mut("FILE_EVENTS")
                .ok_or_else(|| GuardError::Internal("FILE_EVENTS ring buffer not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("RingBuf::try_from: {e}")))?;

        let raw_fd = ring.as_raw_fd();
        let async_fd = tokio::io::unix::AsyncFd::new(raw_fd)
            .map_err(|e| GuardError::Internal(format!("AsyncFd: {e}")))?;

        let mut ring = ring;
        let mut event_count: u64 = 0;
        let mut drop_warned = false;
        tracing::info!("eBPF event listener started");

        // Spawn BPRM event reader (bprm_check_security blocks agent exec)
        if let Ok(mut bprm_ring) = self
            .bpf
            .map_mut("BPRM_EVENTS")
            .and_then(|m| RingBuf::try_from(m).ok())
        {
            let bprm_tx = tx.clone();
            tokio::task::spawn_blocking(move || loop {
                while let Some(item) = bprm_ring.next() {
                    if let Some(ev) = parse_bprm_event(&item) {
                        let _ = bprm_tx.blocking_send(ev);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            });
            tracing::info!("BPRM event reader started");
        }

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
                        if tx.send(ev).await.is_err() {
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

fn try_attach_lsm(bpf: &mut Bpf, name: &str) {
    match attach_lsm(bpf, name) {
        Ok(()) => {}
        Err(e) => tracing::warn!(hook = %name, error = %e, "optional hook skipped"),
    }
}

// ── Events ───────────────────────────────────────────────────────

fn parse_bprm_event(item: &RingBufItem<'_>) -> Option<SecurityEvent> {
    let expected = core::mem::size_of::<FileEvent>();
    if item.len() < expected {
        return None;
    }
    let ev: &FileEvent = unsafe { &*(item.as_ptr() as *const FileEvent) };

    // Only process events with NetworkSend marker (bprm events)
    if ev.event_type != EventType::NetworkSend {
        return None;
    }

    let path_bytes = &ev.path[..(ev.path_len as usize).min(MAX_PREFIX_LEN)];
    let path = String::from_utf8_lossy(path_bytes).to_string();
    let comm_end = ev
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(agentguard_common::COMM_LEN);
    let comm = String::from_utf8_lossy(&ev.comm[..comm_end]).to_string();

    Some(SecurityEvent::AgentDetected {
        pid: ev.pid,
        agent_name: comm,
        cwd: std::path::PathBuf::from(path),
        mode: "sandbox".into(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

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
            return Err(GuardError::Internal("NetworkSend in file guard".into()))
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

// ── Map population helpers ──────────────────────────────────────
// Separadas para evitar borrow check issues con aya 0.13

fn populate_prefixes_inner(bpf: &mut Bpf, paths: &[PathBuf]) -> Result<(), GuardError> {
    // Prefixes first, then count — sequential borrows
    let mut written: u32 = 0;
    {
        let mut prefixes: Array<_, PathPrefix> = Array::try_from(
            bpf.map_mut("PROTECTED_PREFIXES")
                .ok_or_else(|| GuardError::Internal("PROTECTED_PREFIXES map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("PROTECTED_PREFIXES: {e}")))?;

        for path in paths {
            if written >= MAX_PREFIXES {
                break;
            }
            let canonical = std::fs::canonicalize(path).map_err(|source| GuardError::Io {
                path: path.clone(),
                source,
            })?;
            let bytes = canonical.as_os_str().as_encoded_bytes();
            if bytes.len() > MAX_PREFIX_LEN {
                tracing::warn!(?canonical, "path exceeds MAX_PREFIX_LEN, skipping");
                continue;
            }
            let prefix = PathPrefix::from_bytes(bytes)
                .ok_or_else(|| GuardError::Internal(format!("path too long: {canonical:?}")))?;
            prefixes
                .set(written, prefix, 0)
                .map_err(|e| GuardError::Internal(format!("set prefixes[{written}]: {e}")))?;
            written += 1;
        }
    } // prefixes dropped here — releases mutable borrow on bpf

    {
        let mut count: Array<_, u32> = Array::try_from(
            bpf.map_mut("PREFIX_COUNT")
                .ok_or_else(|| GuardError::Internal("PREFIX_COUNT map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("PREFIX_COUNT: {e}")))?;
        count
            .set(0, written, 0)
            .map_err(|e| GuardError::Internal(format!("set PREFIX_COUNT: {e}")))?;
    }

    tracing::info!(prefixes = written, "populated PROTECTED_PREFIXES");
    Ok(())
}

fn populate_write_paths_inner(bpf: &mut Bpf, files: &[PathBuf]) -> Result<(), GuardError> {
    let mut written: u32 = 0;
    {
        let mut wmap: Array<_, PathPrefix> =
            Array::try_from(bpf.map_mut("PROTECTED_WRITE_PATHS").ok_or_else(|| {
                GuardError::Internal("PROTECTED_WRITE_PATHS map not found".into())
            })?)
            .map_err(|e| GuardError::Internal(format!("PROTECTED_WRITE_PATHS: {e}")))?;

        for path in files {
            if written >= MAX_PREFIXES {
                break;
            }
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
            wmap.set(written, entry, 0)
                .map_err(|e| GuardError::Internal(format!("set write_paths[{written}]: {e}")))?;
            written += 1;
        }
    }

    {
        let mut wcount: Array<_, u32> = Array::try_from(
            bpf.map_mut("WRITE_PATH_COUNT")
                .ok_or_else(|| GuardError::Internal("WRITE_PATH_COUNT map not found".into()))?,
        )
        .map_err(|e| GuardError::Internal(format!("WRITE_PATH_COUNT: {e}")))?;
        wcount
            .set(0, written, 0)
            .map_err(|e| GuardError::Internal(format!("set WRITE_PATH_COUNT: {e}")))?;
    }

    tracing::info!(files = written, "populated PROTECTED_WRITE_PATHS");
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
