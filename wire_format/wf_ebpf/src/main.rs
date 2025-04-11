#![no_std]
#![no_main]

use {
    aya_ebpf::{
        bindings::xdp_action,
        check_bounds_signed,
        macros::{map, xdp},
        maps::{Array, RingBuf},
        programs::XdpContext,
    },
    aya_log_ebpf::{debug, error},
    core::{mem, net::Ipv4Addr, ptr},
    network_types::{
        eth::{EthHdr, EtherType},
        ip::{IpProto, Ipv4Hdr},
        udp::UdpHdr,
    },
    wf_common::FILTER_LEN,
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

#[xdp]
pub fn wf_ebpf(ctx: XdpContext) -> u32 {
    match try_xdpdump(&ctx) {
        Ok(ret) => ret,
        Err(_) => {
            error!(&ctx, "got error in XDP program!");
            xdp_action::XDP_ABORTED
        }
    }
}

unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

fn has_entry<T: Eq>(haystack: &Array<Option<T>>, needle: T, wildcard: T) -> bool {
    for idx in 0..FILTER_LEN {
        match haystack.get(idx) {
            Some(v) => {
                if let Some(v) = v {
                    if *v == needle || *v == wildcard {
                        return true;
                    }
                }
            }
            None => return false,
        }
    }
    false
}

fn should_capture(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> bool {
    has_entry(&ALLOW_SRC_IP, src_ip, Ipv4Addr::UNSPECIFIED)
        && has_entry(&ALLOW_DST_IP, dst_ip, Ipv4Addr::UNSPECIFIED)
        && has_entry(&ALLOW_DST_PORTS, dst_port, 0)
        && has_entry(&ALLOW_SRC_PORTS, src_port, 0)
}

fn try_xdpdump(ctx: &XdpContext) -> Result<u32, ()> {
    // Search for IPv4 packets only
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

    // Search for UDP only
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let src_ip = Ipv4Addr::from_bits(unsafe { u32::from_be((*ipv4hdr).src_addr) });
    let dst_ip = Ipv4Addr::from_bits(unsafe { u32::from_be((*ipv4hdr).dst_addr) });
    let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    let src_port = unsafe { u16::from_be((*udphdr).source) };
    let dst_port = unsafe { u16::from_be((*udphdr).dest) };

    if !should_capture(src_ip, dst_ip, src_port, dst_port) {
        return Ok(xdp_action::XDP_PASS);
    }

    debug!(
        ctx,
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
                return Ok(xdp_action::XDP_PASS);
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
                for read_offset in 0..MTU {
                    let write_offset = read_offset + 2;

                    if data_start + read_offset + 1 > data_end {
                        break;
                    }
                    *dst_buf.byte_add(write_offset) = *((data_start + read_offset) as *const u8);
                }
                event.submit(0);
            }
        }
        None => {
            error!(ctx, "Cannot reserve space in ring buffer.");
        }
    };

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
