#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
};

#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    let _ = &ctx;
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
