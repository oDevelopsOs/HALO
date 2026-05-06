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
/// AF_INET6
const AF_INET6: u16 = 10;
/// 127.0.0.1 in network byte order (0x7F000001 → big-endian u32 = 0x0100007F)
const LOCALHOST_IPV4_BE: u32 = 0x0100_007F_u32;
/// ::1 in network byte order (last 4 bytes of IPv6 ::1)
const LOCALHOST_IPV6_LAST4: u32 = 0x0100_0000_u32;
/// IPv6 address size in bytes
const IPV6_ADDR_LEN: usize = 16;

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
    let family: u16 = unsafe { core::ptr::read_unaligned(addr_ptr as *const u16) };

    if family == AF_INET {
        // IPv4: read sin_addr at offset 4
        let addr: u32 = unsafe { core::ptr::read_unaligned(addr_ptr.add(4) as *const u32) };
        if addr == LOCALHOST_IPV4_BE {
            return 0;
        }
        // Block non-localhost IPv4
        emit_net_event(addr, 0);
        return -1;
    }

    if family == AF_INET6 {
        // IPv6: read sin6_addr at offset 8
        // Check if last 4 bytes match ::1 pattern (0:0:0:0:0:0:0:1)
        let last4: u32 = unsafe { core::ptr::read_unaligned(addr_ptr.add(20) as *const u32) };
        if last4 == LOCALHOST_IPV6_LAST4 {
            // Also verify first 12 bytes are zero (true ::1)
            let mut is_localhost = true;
            for i in 0..3 {
                let word: u32 = unsafe { core::ptr::read_unaligned(addr_ptr.add(8 + i * 4) as *const u32) };
                if word != 0 {
                    is_localhost = false;
                    break;
                }
            }
            if is_localhost {
                return 0;
            }
        }
        // Block non-localhost IPv6
        emit_net_event(0, last4);
        return -1;
    }

    // Non-IPv4/IPv6: allow (fail-open for Unix sockets, other families)
    return 0;
}

/// Emit a network block event to the ring buffer.
fn emit_net_event(addr_hint: u32, addr_extra: u32) {

/// Emit a network block event to the ring buffer.
fn emit_net_event(addr_hint: u32, addr_extra: u32) {
    if let Some(mut entry) = NET_EVENTS.reserve::<NetworkEvent>(0) {
        let ptr: *mut NetworkEvent = entry.as_mut_ptr();
        unsafe {
            (*ptr).pid = bpf_get_current_pid_tgid() as u32;
            (*ptr).uid = bpf_get_current_uid_gid() as u32;
            (*ptr).data_len = 8;
            let data = &mut (*ptr).data;
            data[0] = (addr_hint >> 24) as u8;
            data[1] = (addr_hint >> 16) as u8;
            data[2] = (addr_hint >> 8) as u8;
            data[3] = addr_hint as u8;
            data[4] = (addr_extra >> 24) as u8;
            data[5] = (addr_extra >> 16) as u8;
            data[6] = (addr_extra >> 8) as u8;
            data[7] = addr_extra as u8;
            if let Ok(comm) = bpf_get_current_comm() {
                (*ptr).comm = comm;
            }
        }
        entry.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
