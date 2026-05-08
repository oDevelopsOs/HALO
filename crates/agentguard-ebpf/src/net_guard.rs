#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel,
    },
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

    // Use bpf_probe_read_kernel for ALL sockaddr reads —
    // the verifier rejects direct access beyond struct sockaddr (16 bytes).
    let family: u16 = match unsafe {
        bpf_probe_read_kernel::<u16>(addr_ptr as *const u16)
    } {
        Ok(f) => f,
        Err(_) => return 0,
    };

    if family == 2 {
        // AF_INET: read sin_addr at offset 4
        let addr: u32 = match unsafe {
            bpf_probe_read_kernel::<u32>(addr_ptr.add(4) as *const u32)
        } {
            Ok(a) => a,
            Err(_) => return 0,
        };
        if addr == 0x0100_007F_u32 {
            return 0; // 127.0.0.1
        }
        emit_net_event(addr, 0);
        return -1;
    }

    if family == 10 {
        // AF_INET6: read sin6_addr at offset 8 (16 bytes)
        // Check ::1 pattern: first 12 bytes = 0, last 4 bytes = 0x0100_0000
        let word0: u32 = match unsafe {
            bpf_probe_read_kernel::<u32>(addr_ptr.add(8) as *const u32)
        } {
            Ok(w) => w,
            Err(_) => return 0,
        };
        let word1: u32 = match unsafe {
            bpf_probe_read_kernel::<u32>(addr_ptr.add(12) as *const u32)
        } {
            Ok(w) => w,
            Err(_) => return 0,
        };
        let word2: u32 = match unsafe {
            bpf_probe_read_kernel::<u32>(addr_ptr.add(16) as *const u32)
        } {
            Ok(w) => w,
            Err(_) => return 0,
        };
        let last4: u32 = match unsafe {
            bpf_probe_read_kernel::<u32>(addr_ptr.add(20) as *const u32)
        } {
            Ok(w) => w,
            Err(_) => return 0,
        };

        if word0 == 0 && word1 == 0 && word2 == 0 && last4 == 0x0100_0000_u32 {
            return 0; // ::1 localhost IPv6
        }
        emit_net_event(0, last4);
        return -1;
    }

    // Non-IPv4/IPv6: allow (fail-open for Unix sockets, other families)
    return 0;
}

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
