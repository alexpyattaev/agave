#![no_std]
#![no_main]

use {
    crate::helpers::{get_or_default, has_quic_fixed_bit, ExtractError},
    agave_xdp_ebpf::{DecisionEvent, FirewallConfig, FirewallDecision, DECISION_EVENT_SIZE},
    aya_ebpf::{
        bindings::xdp_action::{XDP_DROP, XDP_PASS},
        helpers::gen::bpf_xdp_get_buff_len,
        macros::{map, xdp},
        maps::{Array, RingBuf},
        programs::XdpContext,
    },
    aya_log_ebpf::{error, info},
    core::{net::Ipv4Addr, ptr},
    helpers::ExtractedHeader,
};

mod helpers;

/// Ports on which to enact firewalling.
#[map]
static FIREWALL_CONFIG: Array<FirewallConfig> = Array::with_max_entries(1, 0);

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

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
    // if configuration is invalid/incomplete, we abort firewalling
    if config.my_ip == Ipv4Addr::UNSPECIFIED {
        return XDP_PASS;
    }
    let header = match ExtractedHeader::from_context(&ctx) {
        Ok(header) => header,
        Err(ExtractError::NotUdp) => return XDP_PASS,
        Err(ExtractError::NotSupported) => return XDP_PASS,
        // encountered a packet we could not parse
        _ => {
            error!(&ctx, "FIREWALL could not parse packet");
            return XDP_PASS;
        }
    };
    if outside_valid_port_range(header.dst_port, config) {
        return XDP_PASS;
    }
    let decision = apply_xdp_firewall(&ctx, &header, config);
    print_decision(&ctx, header.dst_port, decision);
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

fn apply_xdp_firewall(
    ctx: &XdpContext,
    header: &ExtractedHeader,
    config: &FirewallConfig,
) -> FirewallDecision {
    let mut drop_reason = FirewallDecision::Pass;

    // drop things from "reserved" ports
    if header.src_port < 1024 {
        drop_reason = FirewallDecision::ReservedPort;
    } else if header.dst_ip != config.my_ip {
        drop_reason = FirewallDecision::IpWrongDestination;
    } else {
        let first_byte: u8 = get_or_default(&ctx, header.payload_offset);
        if header.dst_port == config.tpu_vote {
            if header.payload_len < 64 {
                drop_reason = FirewallDecision::VoteTooShort;
            }
        } else if header.dst_port == config.turbine {
            // turbine port receives shreds
            if header.payload_len < 1200 {
                drop_reason = FirewallDecision::TurbineTooShort;
            }
        } else if (header.dst_port == config.tpu_quic)
            || (header.dst_port == config.tpu_vote_quic)
            || (header.dst_port == config.tpu_forwards_quic)
        {
            // these ports receive via QUIC
            if !has_quic_fixed_bit(first_byte) {
                drop_reason = FirewallDecision::NotQuicPacket;
            }
        } else if header.dst_port == config.repair {
            if header.payload_len < 132 {
                drop_reason = FirewallDecision::RepairTooShort;
            }
            if (first_byte < 6) || (first_byte > 11) {
                drop_reason = FirewallDecision::RepairFingerprint;
            }
        } else if header.dst_port == config.serve_repair {
            if header.payload_len < 132 {
                drop_reason = FirewallDecision::ServeRepairTooShort;
            }
            if (first_byte < 6) || (first_byte > 11) {
                drop_reason = FirewallDecision::RepairFingerprint;
            }
        } else if header.dst_port == config.ancestor_repair {
            if header.payload_len < 132 {
                drop_reason = FirewallDecision::AncestorRepairTooShort;
            }
            if (first_byte < 6) || (first_byte > 11) {
                drop_reason = FirewallDecision::RepairFingerprint;
            }
        } else if header.dst_port == config.gossip {
            if header.payload_len < 132 {
                drop_reason = FirewallDecision::GossipTooShort;
            }
            if first_byte > 5 {
                drop_reason = FirewallDecision::GossipFingerprint;
            }
        } else if config
            .deny_ingress_ports
            .iter()
            .copied()
            .find(|&port| port == header.dst_port)
            .is_some()
        {
            // some ports are only used to send data
            drop_reason = FirewallDecision::TxOnlyPort;
        }
    }
    drop_reason
}

fn print_decision(ctx: &XdpContext, dst_port: u16, decision: FirewallDecision) {
    let event = DecisionEvent { dst_port, decision };

    match RING_BUF.reserve::<[u8; DECISION_EVENT_SIZE]>(0) {
        Some(mut slot) => {
            let dst_buf = slot.as_mut_ptr() as *mut DecisionEvent;
            unsafe {
                ptr::write_unaligned(dst_buf, event);
            }
            slot.submit(0);
        }
        None => {
            error!(ctx, "Ring buffer full");
        }
    }
    //info!(ctx, "DROP:  DST PORT:{}, REASON: {}", dst_port, decision,);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // This is so that if we accidentally panic anywhere the verifier will refuse to load the
    // program as it'll detect an infinite loop.
    #[allow(clippy::empty_loop)]
    loop {}
}
