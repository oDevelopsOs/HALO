//! eBPF LSM hooks — network protection.
//!
//! Intercepta `socket_connect` de procesos de agentes de IA conocidos.
//! En Fase 2.8 la detección de contenido real la hace el proxy DLP
//! userspace; este hook puede bloquear conexiones de procesos no
//! autorizados a hosts externos si se configura una lista blanca.

#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_comm, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
    BpfContext,
};

use agentguard_common::{EventType, NetworkEvent, COMM_LEN};

/// Ring buffer para eventos de red.
#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0); // 2 MiB

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    // Fase 2.8+: aquí se poblará un mapa hash con los TIDs de procesos
    // agentes conocidos (detectados por el daemon). Si el proceso actual
    // está en ese mapa y el destino no está en la lista blanca, se
    // deniega con -EPERM y se emite evento.
    //
    // Por ahora, permitimos todo. La detección de contenido (API keys etc.)
    // la hace el proxy DLP userspace vía MITM TLS (Fase 2.3).
    let _ = &ctx;
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
