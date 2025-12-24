#![cfg_attr(
    not(feature = "agave-unstable-api"),
    deprecated(
        since = "3.1.0",
        note = "This crate has been marked for formal inclusion in the Agave Unstable API. From \
                v4.0.0 onward, the `agave-unstable-api` crate feature must be specified to \
                acknowledge use of an interface that may break without warning."
    )
)]
// Activate some of the Rust 2024 lints to make the future migration easier.
#![warn(if_let_rescope)]
#![warn(keyword_idents_2024)]
#![warn(rust_2024_incompatible_pat)]
#![warn(tail_expr_drop_order)]
#![warn(unsafe_attr_outside_unsafe)]
#![warn(unsafe_op_in_unsafe_fn)]
#![no_std]

use core::net::Ipv4Addr;

#[cfg(all(target_os = "linux", not(target_arch = "bpf")))]
#[unsafe(no_mangle)]
pub static AGAVE_XDP_EBPF_PROGRAM: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/agave-xdp-prog"));

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FirewallConfig {
    pub deny_ingress_ports: [u16; 7],
    pub tpu_vote: u16,
    pub tpu_quic: u16,
    pub tpu_forwards_quic: u16,
    pub tpu_vote_quic: u16,
    pub turbine: u16,
    pub repair: u16,
    pub serve_repair: u16,
    pub ancestor_repair: u16,
    pub gossip: u16,
    pub solana_min_port: u16,
    pub solana_max_port: u16,
    pub my_ip: Ipv4Addr,
    pub drop_frags: bool,
}
impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            deny_ingress_ports: [0; 7],
            tpu_vote: 0,
            tpu_quic: 0,
            tpu_forwards_quic: 0,
            tpu_vote_quic: 0,
            turbine: 0,
            repair: 0,
            serve_repair: 0,
            ancestor_repair: 0,
            gossip: 0,
            solana_min_port: 0,
            solana_max_port: 0,
            my_ip: Ipv4Addr::UNSPECIFIED,
            drop_frags: false,
        }
    }
}

#[cfg(all(target_os = "linux", not(target_arch = "bpf")))]
unsafe impl aya::Pod for FirewallConfig {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FirewallDecision {
    Pass,

    RepairTooShort,
    AncestorRepairTooShort,
    RepairFingerprint,
    ServeRepairTooShort,

    GossipFingerprint,
    GossipTooShort,

    IpWrongDestination,
    ReservedPort,
    TxOnlyPort,

    NotQuicPacket,
    TpuQuicTooShort,
    TpuVoteQuicTooShort,

    TurbineTooShort,

    VoteTooShort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DecisionEvent {
    pub dst_port: u64,
    pub decision: FirewallDecision,
}

pub const DECISION_EVENT_SIZE: usize = core::mem::size_of::<DecisionEvent>();
