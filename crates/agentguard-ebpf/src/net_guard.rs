#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{lsm, map},
    maps::{Array, RingBuf},
    programs::LsmContext,
};

use agentguard_common::NetworkEvent;

/// Flag: 0 = permissive (allow all), 1 = block external connections
#[map]
static NET_RESTRICT_MODE: Array<u8> = Array::with_max_entries(1, 0);

/// Ring buffer para emitir NetworkEvent al userspace
#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);

/// AF_INET
const AF_INET: u16 = 2;
/// 127.0.0.1 in network byte order (0x7F000001 → big-endian u32 = 0x0100007F)
const LOCALHOST_IPV4_BE: u32 = 0x0100_007F_u32;

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    // Fail-open: if anything goes wrong, allow the connection
    let restricted = match NET_RESTRICT_MODE.get(0) {
        Some(r) => *r,
        None => return 0,
    };
    if restricted == 0 {
        return 0;
    }

    // Read sockaddr pointer (arg 1 in socket_connect LSM hook)
    let addr_ptr: *const u8 = unsafe { ctx.arg(1) };
    if addr_ptr.is_null() {
        return 0;
    }

    // Read sin_family (first 2 bytes of sockaddr)
    let _family: u16 = match unsafe { core::ptr::read_unaligned(addr_ptr as *const u16) } {
        f if f == AF_INET => f,
        _ => return 0, // Non-IPv4: allow (fail-open for IPv6, Unix sockets)
    };

    // Read sin_addr (offset 4 in sockaddr_in: 2 family + 2 port)
    let addr: u32 = unsafe { core::ptr::read_unaligned(addr_ptr.add(4) as *const u32) };

    // Allow connections to localhost (DLP proxy or daemon IPC)
    if addr == LOCALHOST_IPV4_BE {
        return 0;
    }

    // Emit network event to userspace via ring buffer
    if let Some(mut entry) = NET_EVENTS.reserve::<NetworkEvent>(0) {
        let ptr: *mut NetworkEvent = entry.as_mut_ptr();
        unsafe {
            (*ptr).pid = bpf_get_current_pid_tgid() as u32;
            (*ptr).uid = bpf_get_current_uid_gid() as u32;
            (*ptr).data_len = 8;
            // Store address bytes for userspace to decode
            let data = &mut (*ptr).data;
            data[0] = (addr >> 24) as u8;
            data[1] = (addr >> 16) as u8;
            data[2] = (addr >> 8) as u8;
            data[3] = addr as u8;
            data[4] = 0;
            data[5] = 0;
            data[6] = 0;
            data[7] = 0;
            // Fill comm
            if let Ok(comm) = bpf_get_current_comm() {
                (*ptr).comm = comm;
            }
        }
        entry.submit(0);
    }

    // Block non-localhost connections when network restriction is active
    -1 // -EPERM
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
