//! eBPF tracepoint `sched/sched_process_exec` — detección de agentes IA.
//!
//! Se dispara cada vez que un proceso llama a execve/execveat con éxito.
//! Busca el nombre del ejecutable (comm) en el mapa KNOWN_AGENTS (FNV-1a hash)
//! y emite un AgentSpawnEvent al ring buffer si hay coincidencia.
//!
//! Overhead: ~0.3 µs por exec en kernels 5.15+.
//!
//! Requisitos: kernel ≥ 5.10, CONFIG_TRACEPOINTS=y (siempre presente).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_comm,
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};
use agentguard_common::AgentSpawnEvent;

// ── BPF maps ─────────────────────────────────────────────────────────────────

/// Mapa de agentes conocidos: hash FNV-1a del comm → 1.
/// Poblado desde userspace con los nombres de config.toml.
#[map]
static KNOWN_AGENTS: HashMap<u64, u8> = HashMap::with_max_entries(128, 0);

/// Ring buffer de eventos hacia userspace (512 KiB).
#[map]
static AGENT_SPAWN_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

// ── Tracepoint handler ───────────────────────────────────────────────────────

#[tracepoint(name = "sched/sched_process_exec")]
pub fn handle_process_exec(ctx: TracePointContext) -> i32 {
    match try_handle_exec(&ctx) {
        Ok(_) => 0,
        Err(_) => 0, // fail-open: cualquier error se ignora
    }
}

fn try_handle_exec(ctx: &TracePointContext) -> Result<(), i64> {
    // Leer comm (nombre del proceso, máx 16 bytes)
    let mut comm = [0u8; 16];
    match bpf_get_current_comm() {
        Ok(c) => comm = c,
        Err(_) => return Ok(()),
    }

    // Hash FNV-1a del comm para búsqueda O(1) en el mapa
    let hash = fnv1a_hash_bytes(&comm);

    // ¿Es un agente conocido?
    if unsafe { KNOWN_AGENTS.get(&hash).is_none() } {
        return Ok(());
    }

    // Reservar entrada en el ring buffer
    if let Some(mut entry) = AGENT_SPAWN_EVENTS.reserve::<AgentSpawnEvent>(0) {
        let event = entry.as_mut_ptr();

        unsafe {
            (*event).pid = (ctx.pid() & 0xFFFF_FFFF) as u32;
            (*event).uid = (ctx.uid() & 0xFFFF_FFFF) as u32;
            (*event).ppid = 0; // no disponible sin bpf_get_current_task + CO-RE
                              // el userspace lo rellena vía /proc/<pid>/stat

            // Copiar comm al evento
            core::ptr::copy_nonoverlapping(
                comm.as_ptr(),
                (*event).comm.as_mut_ptr(),
                16,
            );

            // exe_path, cwd, argv: no disponibles en este contexto eBPF.
            // Se rellenan desde userspace vía /proc/<pid>/...
            core::ptr::write_bytes((*event).exe_path.as_mut_ptr(), 0, 256);
            core::ptr::write_bytes((*event).cwd.as_mut_ptr(), 0, 256);
            core::ptr::write_bytes((*event).argv.as_mut_ptr(), 0, 128);
        }

        entry.submit(0);
    }

    Ok(())
}

// ── FNV-1a hash ──────────────────────────────────────────────────────────────

fn fnv1a_hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        if b == 0 {
            break;
        }
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
