#![no_std]
#![no_main]

use {
    crate::helpers::{ptr_at, ExtractError},
    agave_xdp_ebpf::FirewallConfig,
    aya_ebpf::{
        bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS},
        macros::{map, xdp},
        maps::Array,
        programs::XdpContext,
    },
    aya_log_ebpf::info,
    core::ptr,
    helpers::{has_frags, ExtractedHeader},
};

mod helpers;

/// Set to 1 from user space at load time to control whether we must drop multi-frags packets
#[unsafe(no_mangle)]
static AGAVE_XDP_DROP_MULTI_FRAGS: u8 = 0;

/// Ports on which to enact firewalling
#[map]
static FIREWALL_CONFIG: Array<FirewallConfig> = Array::with_max_entries(1, 0);

#[xdp]
pub fn agave_xdp(ctx: XdpContext) -> u32 {
    if drop_frags() && has_frags(&ctx) {
        // We're not actually dropping any valid frames here. See
        // https://lore.kernel.org/netdev/20251021173200.7908-2-alessandro.d@gmail.com
        return XDP_DROP;
    }
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

#[inline]
fn drop_frags() -> bool {
    // SAFETY: This variable is only ever modified at load time, we need the volatile read to
    // prevent the compiler from optimizing it away.
    unsafe { ptr::read_volatile(&AGAVE_XDP_DROP_MULTI_FRAGS) == 1 }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ExtractError> {
    let Some(config) = FIREWALL_CONFIG.get(0) else {
        return Ok(XDP_PASS);
    };
    let mut action = XDP_PASS;
    let header = match ExtractedHeader::from_context(&ctx) {
        Ok(header) => header,
        Err(ExtractError::Ipv6 | ExtractError::NotUdp) => return Ok(XDP_PASS),
        // encountered a packet we could not parse
        _ => return Err(ExtractError::Drop),
    };

    if header.dst_port < config.solana_min_port || header.dst_port > config.solana_max_port {
        return Ok(XDP_PASS);
    }
    // drop things from "reserved" ports
    if header.src_port < 1024 {
        action = XDP_DROP;
    } else if header.dst_ip != config.my_ip {
        action = XDP_DROP;
    } else {
        if header.dst_port == config.tpu_vote {
            if header.payload_len < 300 {
                action = XDP_DROP;
            }
        } else if header.dst_port == config.turbine {
            if header.payload_len < 1200 {
                action = XDP_DROP;
            }
        } else if header.dst_port == config.repair {
            if header.payload_len < 96 {
                action = XDP_DROP;
            }
        } else if header.dst_port == config.gossip {
            if header.payload_len < 96 {
                action = XDP_DROP;
            }

            let tag: u8 = unsafe { *ptr_at(&ctx, header.payload_offset)? };
            if tag != 5 {
                action = XDP_DROP;
            }
        }
    }

    info!(
        &ctx,
        "SRC: {}:{}, DST PORT:{}, ACTION: {}",
        header.src_ip,
        header.src_port,
        header.dst_port,
        action
    );

    Ok(action)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // This is so that if we accidentally panic anywhere the verifier will refuse to load the
    // program as it'll detect an infinite loop.
    #[allow(clippy::empty_loop)]
    loop {}
}
