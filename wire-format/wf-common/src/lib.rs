#![no_std]
use {
    core::net::Ipv4Addr,
    network_types::ip::{IpProto, Ipv4Hdr},
};
pub const FILTER_LEN: u32 = 32;

#[derive(Clone, Copy)]
#[repr(u64)]
pub enum Flags {
    Default = 0,
    OnlyGre = 1,
    StripGre = 2,
}

impl Default for Flags {
    fn default() -> Self {
        Self::Default
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Flags {}

#[cfg(not(feature = "user"))]
pub mod ebpf_helpers;

pub fn parse_ip_header(ipv4hdr: *const Ipv4Hdr) -> (Ipv4Addr, Ipv4Addr, IpProto) {
    let src_ip = Ipv4Addr::from_bits(unsafe { u32::from_be((*ipv4hdr).src_addr) });
    let dst_ip = Ipv4Addr::from_bits(unsafe { u32::from_be((*ipv4hdr).dst_addr) });
    let ip_proto = unsafe { (*ipv4hdr).proto };
    (src_ip, dst_ip, ip_proto)
}
