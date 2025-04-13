#![no_std]
#![no_main]

use {
    aya_ebpf::{
        bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
        macros::{classifier, map},
        maps::{Array, RingBuf},
        programs::TcContext,
    },
    aya_log_ebpf::{debug, error},
    core::{mem, net::Ipv4Addr, ptr},
    wf_common::{
        ebpf_helpers::{extract_headers, has_entry, ContextRef},
        Flags, FILTER_LEN,
    },
};

#[map]
static ALLOW_DST_PORTS: Array<Option<u16>> = Array::with_max_entries(FILTER_LEN, 0);
#[map]
static ALLOW_DST_IP: Array<Option<Ipv4Addr>> = Array::with_max_entries(FILTER_LEN, 0);
#[map]
static ALLOW_SRC_IP: Array<Option<Ipv4Addr>> = Array::with_max_entries(FILTER_LEN, 0);
#[map]
static ALLOW_SRC_PORTS: Array<Option<u16>> = Array::with_max_entries(FILTER_LEN, 0);
#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024u32, 0);
#[map]
static FLAGS: Array<Flags> = Array::with_max_entries(1, 0);

#[classifier]
pub fn wf_tc(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let flags = FLAGS.get(0).cloned().unwrap_or_default();
    let Ok((ip_header_offset, src_ip, dst_ip, src_port, dst_port)) = extract_headers(
        &ContextRef {
            data: ctx.data(),
            data_end: ctx.data_end(),
        },
        flags,
    ) else {
        return Ok(TC_ACT_PIPE);
    };

    if !should_capture(src_ip, dst_ip, src_port, dst_port) {
        return Ok(TC_ACT_PIPE);
    }

    debug!(
        &ctx,
        "captured UDP packet {}:{}->{}:{}",
        src_ip.to_bits(),
        src_port,
        dst_ip.to_bits(),
        dst_port
    );
    const MTU: usize = 1500;
    const U16_SIZE: usize = mem::size_of::<u16>();
    const SIZE: usize = U16_SIZE + MTU;

    match RING_BUF.reserve::<[u8; SIZE]>(0) {
        Some(mut event) => {
            let len = ctx.data_end() - ctx.data();

            // We check if packet len is greater than our reserved buffer size
            if aya_ebpf::check_bounds_signed(len as i64, 1, 1500) == false {
                event.discard(0);
                return Ok(TC_ACT_PIPE);
            }

            unsafe {
                let dst_buf = event.as_mut_ptr() as *mut u8;
                // we first save into the buffer the packet length.
                // Useful on userspace to retrieve the correct amount of bytes and not some bytes not part of the packet.
                ptr::write_unaligned(dst_buf as *mut u16, len as u16);

                // We copy the entire content of the packet to the remaining part of the buffer
                // black_box is needed because LLVM is too smart and erases the bounds checks
                // if it is not present
                let data_start = core::hint::black_box(ctx.data());
                let data_end = core::hint::black_box(ctx.data_end());
                let mut write_offset = U16_SIZE;
                for read_offset in ip_header_offset..MTU {
                    if data_start + read_offset + 1 > data_end {
                        break;
                    }
                    *dst_buf.byte_add(write_offset) = *((data_start + read_offset) as *const u8);
                    write_offset += 1;
                }
                event.submit(0);
            }
        }
        None => {
            error!(&ctx, "Cannot reserve space in ring buffer.");
        }
    };

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

fn should_capture(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> bool {
    has_entry(&ALLOW_SRC_IP, src_ip, Ipv4Addr::UNSPECIFIED)
        && has_entry(&ALLOW_DST_IP, dst_ip, Ipv4Addr::UNSPECIFIED)
        && has_entry(&ALLOW_DST_PORTS, dst_port, 0)
        && has_entry(&ALLOW_SRC_PORTS, src_port, 0)
}
