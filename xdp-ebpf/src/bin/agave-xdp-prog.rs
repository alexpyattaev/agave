#![no_std]
#![no_main]

use {
    crate::helpers::{get_or_default, has_quic_fixed_bit, ExtractError},
    agave_xdp_ebpf::{DecisionEvent, FirewallConfig, FirewallDecision},
    aya_ebpf::{
        bindings::xdp_action::{XDP_DROP, XDP_PASS},
        helpers::gen::bpf_xdp_get_buff_len,
        macros::{map, xdp},
        maps::{Array, RingBuf},
        programs::XdpContext,
    },
    core::{net::Ipv4Addr, ptr},
    helpers::ExtractedHeader,
};

mod helpers;

/// Ports on which to enact firewalling.
#[map]
static FIREWALL_CONFIG: Array<FirewallConfig> = Array::with_max_entries(1, 0);

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(4096 * 64, 0);

#[xdp]
pub fn agave_xdp(ctx: XdpContext) -> u32 {
    // If we can not load config we just pass everything
    let Some(config) = FIREWALL_CONFIG.get(0) else {
        return XDP_PASS;
    };
    // Workaround for buggy drivers - not really part of the firewall
    if config.drop_frags && has_frags(&ctx) {
        // We're not actually dropping any valid frames here. See
        // https://lore.kernel.org/netdev/20251021173200.7908-2-alessandro.d@gmail.com
        return XDP_DROP;
    }
    // if configuration is invalid/incomplete, we pass everything
    if config.my_ip == Ipv4Addr::UNSPECIFIED {
        return XDP_PASS;
    }

    let header = match ExtractedHeader::from_context(&ctx) {
        Ok(header) => header,
        Err(ExtractError::NotUdp) => return XDP_PASS,
        Err(ExtractError::NotSupported) => return XDP_PASS,
        // encountered a packet we could not parse
        _ => {
            //error!(&ctx, "FIREWALL could not parse packet");
            return XDP_PASS;
        }
    };

    if outside_valid_port_range(header.dst_port, config) {
        return XDP_PASS;
    }

    let decision = apply_xdp_firewall(&ctx, &header, config);
    //info!(&ctx, ".");
    report_decision(&ctx, header.dst_port, decision);
    if matches!(decision, FirewallDecision::Pass) {
        return XDP_PASS;
    }
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

#[inline]
fn outside_valid_port_range(dst_port: u16, config: &FirewallConfig) -> bool {
    dst_port < config.solana_min_port || dst_port > config.solana_max_port
}

/// Core protocol-specific logic of the firewall for Agave
fn apply_xdp_firewall(
    ctx: &XdpContext,
    header: &ExtractedHeader,
    config: &FirewallConfig,
) -> FirewallDecision {
    // drop things from "reserved" ports
    if header.src_port < 1024 {
        return FirewallDecision::ReservedPort;
    }
    if header.dst_ip != config.my_ip {
        return FirewallDecision::IpWrongDestination;
    }

    let first_byte: u8 = get_or_default(&ctx, header.payload_offset);
    if header.dst_port == config.tpu_vote {
        if header.payload_len < 64 {
            return FirewallDecision::VoteTooShort;
        }
    }
    if header.dst_port == config.turbine {
        // turbine port receives shreds
        if header.payload_len < 1200 {
            return FirewallDecision::TurbineTooShort;
        }
    }
    if (header.dst_port == config.tpu_quic)
        || (header.dst_port == config.tpu_vote_quic)
        || (header.dst_port == config.tpu_forwards_quic)
    {
        // these ports receive via QUIC
        if !has_quic_fixed_bit(first_byte) {
            return FirewallDecision::NotQuicPacket;
        }
    }
    if header.dst_port == config.repair {
        if header.payload_len < 132 {
            return FirewallDecision::RepairTooShort;
        }
        if (first_byte < 6) || (first_byte > 11) {
            return FirewallDecision::RepairFingerprint;
        }
    }
    if header.dst_port == config.serve_repair {
        if header.payload_len < 132 {
            return FirewallDecision::ServeRepairTooShort;
        }
        if (first_byte < 6) || (first_byte > 11) {
            return FirewallDecision::RepairFingerprint;
        }
    }
    if header.dst_port == config.ancestor_repair {
        if header.payload_len < 132 {
            return FirewallDecision::AncestorRepairTooShort;
        }
        if (first_byte < 6) || (first_byte > 11) {
            return FirewallDecision::RepairFingerprint;
        }
    }
    if header.dst_port == config.gossip {
        if header.payload_len < 132 {
            return FirewallDecision::GossipTooShort;
        }
        if first_byte > 5 {
            return FirewallDecision::GossipFingerprint;
        }
    }
    if config
        .deny_ingress_ports
        .iter()
        .copied()
        .find(|&port| port == header.dst_port)
        .is_some()
    {
        // some ports are only used to send data
        return FirewallDecision::TxOnlyPort;
    }
    FirewallDecision::Pass
}

fn report_decision(ctx: &XdpContext, dst_port: u16, decision: FirewallDecision) {
    let event = DecisionEvent {
        dst_port: dst_port as u64,
        decision,
    };

    RING_BUF.output(&event, 0);
    // let Some(mut slot) = RING_BUF.reserve::<DecisionEvent>(0) else {
    //     return;
    // };

    // unsafe {
    //     ptr::write_unaligned(slot.as_mut_ptr(), event);
    // }
    // slot.submit(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // This is so that if we accidentally panic anywhere the verifier will refuse to load the
    // program as it'll detect an infinite loop.
    #[allow(clippy::empty_loop)]
    loop {}
}
