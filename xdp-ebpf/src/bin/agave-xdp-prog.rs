#![no_std]
#![no_main]

use {
    crate::helpers::{get_or_default, has_quic_fixed_bit, ExtractError},
    agave_xdp_ebpf::FirewallConfig,
    aya_ebpf::{
        bindings::xdp_action::{XDP_DROP, XDP_PASS},
        helpers::gen::bpf_xdp_get_buff_len,
        macros::{map, xdp},
        maps::Array,
        programs::XdpContext,
    },
    aya_log_ebpf::{error, info},
    core::net::Ipv4Addr,
    helpers::ExtractedHeader,
};

mod helpers;

/// Ports on which to enact firewalling.
#[map]
static FIREWALL_CONFIG: Array<FirewallConfig> = Array::with_max_entries(1, 0);

#[xdp]
pub fn agave_xdp(ctx: XdpContext) -> u32 {
    let Some(config) = FIREWALL_CONFIG.get(0) else {
        return XDP_PASS;
    };
    if config.drop_frags && has_frags(&ctx) {
        // We're not actually dropping any valid frames here. See
        // https://lore.kernel.org/netdev/20251021173200.7908-2-alessandro.d@gmail.com
        return XDP_DROP;
    }
    let _firewall_decision = apply_xdp_firewall(ctx, config);
    // TODO: this should be replaced with actual return from the firewall
    XDP_PASS
}

#[inline]
pub fn has_frags(ctx: &XdpContext) -> bool {
    #[allow(clippy::arithmetic_side_effects)]
    let linear_len = ctx.data_end() - ctx.data();
    // Safety: generated binding is unsafe, but static verifier guarantees ctx.ctx is valid.
    let buf_len = unsafe { bpf_xdp_get_buff_len(ctx.ctx) as usize };
    linear_len < buf_len
}

fn apply_xdp_firewall(ctx: XdpContext, config: &FirewallConfig) -> u32 {
    // if configuration is invalid/incomplete, we abort firewalling
    if config.my_ip == Ipv4Addr::UNSPECIFIED {
        return XDP_PASS;
    }
    let mut drop_reason = "";
    let header = match ExtractedHeader::from_context(&ctx) {
        Ok(header) => header,
        Err(ExtractError::NotUdp) => return XDP_PASS,
        Err(ExtractError::NotSupported) => return XDP_PASS,
        // encountered a packet we could not parse
        _ => {
            error!(&ctx, "FIREWALL could not parse packet");
            return XDP_DROP;
        }
    };

    if header.dst_port < config.solana_min_port || header.dst_port > config.solana_max_port {
        // do not touch packets targeting ports outside of solana range
        return XDP_PASS;
    }
    // drop things from "reserved" ports
    if header.src_port < 1024 {
        drop_reason = "port: reserved";
    } else if header.dst_ip != config.my_ip {
        drop_reason = "IP: wrong destination";
    } else {
        let first_byte: u8 = get_or_default(&ctx, header.payload_offset);
        if header.dst_port == config.tpu_vote {
            if header.payload_len < 64 {
                drop_reason = "vote: too short";
            }
        } else if header.dst_port == config.turbine {
            // turbine port receives shreds
            if header.payload_len < 1200 {
                drop_reason = "turbine: too short";
            }
        } else if (header.dst_port == config.tpu_quic)
            || (header.dst_port == config.tpu_vote_quic)
            || (header.dst_port == config.tpu_forwards_quic)
        {
            // these ports receive via QUIC
            if !has_quic_fixed_bit(first_byte) {
                drop_reason = "TPU QUIC: not QUIC packet";
            }
        } else if header.dst_port == config.repair {
            // repair port receives shreds
            if header.payload_len < 1200 {
                drop_reason = "repair: too short";
            }
        } else if header.dst_port == config.serve_repair {
            if header.payload_len < 64 {
                drop_reason = "serve_repair: too short";
            }
        } else if header.dst_port == config.ancestor_repair {
            if header.payload_len < 64 {
                drop_reason = "ancestor_repair: too short";
            }
        } else if header.dst_port == config.gossip {
            if header.payload_len < 132 {
                drop_reason = "gossip: too short";
            }
            if first_byte > 5 {
                drop_reason = "gossip: fingerprint";
            }
        } else if config
            .deny_ingress_ports
            .iter()
            .copied()
            .find(|&port| port == header.dst_port)
            .is_some()
        {
            // some ports are only used to send data
            drop_reason = "port: tx only"
        }
    }
    if drop_reason.is_empty() {
        XDP_PASS
    } else {
        info!(
            &ctx,
            "DROP: SRC: {}:{}, DST PORT:{}, REASON: {}",
            header.src_ip,
            header.src_port,
            header.dst_port,
            drop_reason
        );
        XDP_DROP
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // This is so that if we accidentally panic anywhere the verifier will refuse to load the
    // program as it'll detect an infinite loop.
    #[allow(clippy::empty_loop)]
    loop {}
}
