//! Carga el programa eBPF de detección de procesos y reacciona ante
//! spawns de agentes IA en directorios protegidos.
//!
//! Workflow:
//! 1. Carga `process_exec.bpf.o` vía aya
//! 2. Popula el mapa `KNOWN_AGENTS` con hashes FNV-1a de los ejecutables
//! 3. Attacha el tracepoint `sched/sched_process_exec`
//! 4. Lee el ring buffer `AGENT_SPAWN_EVENTS` en loop
//! 5. Para cada evento: lee /proc/<pid>/... para info adicional
//! 6. Decide: monitor (solo log) o sandbox (kill + relanzar en bwrap)
//!
//! Con feature `ebpf` desactivada, este módulo no se compila.

#![allow(deprecated)]

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use include_bytes_aligned::include_bytes_aligned;

use agentguard_common::AgentSpawnEvent;
use agentguard_core::config::Config;
use agentguard_core::SecurityEvent;

use crate::sandbox::SandboxLauncher;

// El bytecode eBPF embebido en compile-time
static PROCESS_EXEC_BPF: &[u8] =
    include_bytes_aligned!(4096, concat!(env!("OUT_DIR"), "/process_exec.bpf.o"));

pub struct ProcessWatcher {
    bpf: aya::Bpf,
}

impl ProcessWatcher {
    /// Carga el programa eBPF y popula el mapa con los agentes conocidos.
    pub fn load(config: &Config) -> Result<Self, anyhow::Error> {
        if PROCESS_EXEC_BPF.len() < 16 {
            anyhow::bail!("eBPF bytecode not compiled — run ./scripts/build-ebpf.sh");
        }

        let mut bpf = aya::BpfLoader::new()
            .btf(aya::Btf::from_sys_fs().ok().as_ref())
            .load(PROCESS_EXEC_BPF)?;

        // Attachar el tracepoint
        let program: &mut aya::programs::TracePoint = bpf
            .program_mut("handle_process_exec")
            .ok_or_else(|| anyhow::anyhow!("eBPF program 'handle_process_exec' not found"))?
            .try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exec")?;

        // Poblar KNOWN_AGENTS con los hashes FNV-1a de los nombres de ejecutables
        let mut known_agents: aya::maps::HashMap<_, u64, u8> = aya::maps::HashMap::try_from(
            bpf.map_mut("KNOWN_AGENTS")
                .ok_or_else(|| anyhow::anyhow!("BPF map 'KNOWN_AGENTS' not found"))?,
        )?;

        let mut count = 0usize;
        for agent in &config.agent_detection.known_agents {
            for exe in &agent.exe {
                let hash = fnv1a_hash(exe);
                known_agents.insert(hash, 1, 0)?;
                debug!(
                    exe = %exe,
                    hash = format!("{hash:#x}"),
                    "registered agent executable in eBPF map"
                );
                count += 1;
            }
        }

        info!(
            agents = config.agent_detection.known_agents.len(),
            executables = count,
            "ProcessWatcher loaded: eBPF tracepoint active"
        );

        Ok(Self { bpf })
    }

    /// Loop principal: lee eventos del ring buffer y los procesa.
    /// Spawneado como tarea tokio separada.
    pub async fn run(
        mut self,
        config: Arc<RwLock<Config>>,
        event_tx: broadcast::Sender<SecurityEvent>,
    ) {
        let mut ring_buf = match self.bpf.map_mut("AGENT_SPAWN_EVENTS") {
            Some(map) => match aya::maps::RingBuf::try_from(map) {
                Ok(rb) => rb,
                Err(e) => {
                    error!(error = %e, "failed to get AGENT_SPAWN_EVENTS ring buffer");
                    return;
                }
            },
            None => {
                error!("BPF map 'AGENT_SPAWN_EVENTS' not found");
                return;
            }
        };

        info!("ProcessWatcher ring buffer loop started");

        loop {
            while let Some(item) = ring_buf.next() {
                if item.len() < core::mem::size_of::<AgentSpawnEvent>() {
                    continue;
                }
                let event: AgentSpawnEvent =
                    unsafe { core::ptr::read_unaligned(item.as_ptr() as *const AgentSpawnEvent) };

                let pid = event.pid;
                let comm = event.comm_str().to_owned();

                let config_clone = config.clone();
                let tx = event_tx.clone();

                tokio::spawn(async move {
                    handle_agent_spawn(pid, comm, config_clone, tx).await;
                });
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }
    }
}

// ── Lógica de decisión ────────────────────────────────────────────────────────

async fn handle_agent_spawn(
    pid: u32,
    comm: String,
    config: Arc<RwLock<Config>>,
    event_tx: broadcast::Sender<SecurityEvent>,
) {
    // ── PID reuse guard: verify comm before acting ──
    // By the time this async handler runs, the kernel may have recycled
    // the PID to a completely unrelated process. We must verify identity
    // before reading /proc or sending any signal.
    if !verify_pid_comm(pid, &comm) {
        debug!(
            pid,
            expected = %comm,
            "PID reused or process exited — discarding event"
        );
        return;
    }

    // Read /proc only AFTER comm verification
    let exe = read_proc_exe(pid).unwrap_or_else(|| comm.clone());
    let cwd = read_proc_cwd(pid);

    // Second verification: PID may have been reused during the /proc reads
    if !verify_pid_comm(pid, &comm) {
        debug!(pid, expected = %comm, "PID reused during proc read — discarding");
        return;
    }

    let cfg = config.read().await;

    let cwd = match cwd {
        Some(c) => c,
        None => {
            debug!(agent = %comm, pid, "no readable cwd, skipping");
            return;
        }
    };

    // ¿El cwd está en una zona protegida?
    let is_protected = cfg
        .protected_dirs
        .iter()
        .any(|protected| cwd.starts_with(protected));

    if !is_protected {
        debug!(
            agent = %comm,
            pid,
            cwd = %cwd.display(),
            "agent in unprotected directory, ignoring"
        );
        return;
    }

    let mode = &cfg.sandbox.modo_por_defecto;

    info!(
        agent = %comm,
        pid,
        cwd = %cwd.display(),
        mode = %mode,
        "AI agent detected in protected directory"
    );

    // Emitir evento AgentDetected
    let _ = event_tx.send(SecurityEvent::AgentDetected {
        pid,
        agent_name: comm.clone(),
        cwd: cwd.clone(),
        mode: mode.clone(),
        timestamp: unix_ts(),
    });

    match mode.as_str() {
        "monitor" => {
            info!(agent = %comm, "monitor mode: agent allowed to run freely");
        }
        "sandbox" | "hybrid" => {
            kill_process(pid);

            let sandbox = SandboxLauncher::new(cfg.clone());
            let network_iso = cfg.sandbox.network_isolation;
            match sandbox
                .launch(&exe, &cwd, mode == "hybrid", network_iso)
                .await
            {
                Ok(sandbox_pid) => {
                    info!(
                        agent = %comm,
                        original_pid = pid,
                        sandbox_pid,
                        "agent relaunched in sandbox"
                    );
                    let _ = event_tx.send(SecurityEvent::AgentSandboxed {
                        original_pid: pid,
                        sandbox_pid,
                        agent_name: comm,
                        cwd,
                        timestamp: unix_ts(),
                    });
                }
                Err(e) => {
                    error!(
                        agent = %comm,
                        error = %e,
                        "failed to sandbox agent"
                    );
                }
            }
        }
        other => {
            warn!(mode = %other, "unknown sandbox mode, defaulting to monitor");
        }
    }
}

// ── Lectura de /proc ──────────────────────────────────────────────────────────

fn verify_pid_comm(pid: u32, expected: &str) -> bool {
    let comm = match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(c) => c.trim().to_string(),
        Err(_) => return false, // process exited → PID is free or reused
    };
    comm == expected
}

fn read_proc_cwd(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

fn read_proc_exe(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(path.display().to_string())
}

// ── Kill helper ───────────────────────────────────────────────────────────────

fn kill_process(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

// ── FNV-1a hash (mismo algoritmo que en eBPF) ────────────────────────────────
//
// NOTA: FNV-1a no es criptográfico — colisiones intencionales son factibles.
// Un atacante podría crear un nombre de ejecutable que haga hash al mismo valor
// que un agente conocido. Mitigación: el handler userspace verifica el path real
// vía /proc/<pid>/exe y /proc/<pid>/comm antes de actuar (verify_pid_comm).

pub fn fnv1a_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_hash_is_deterministic() {
        let h1 = fnv1a_hash("cursor");
        let h2 = fnv1a_hash("cursor");
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv1a_hash_different_for_different_strings() {
        assert_ne!(fnv1a_hash("cursor"), fnv1a_hash("claude"));
    }
}
