use {
    crate::{Flags, FILTER_LEN},
    aya_ebpf::maps::Array,
    core::{mem, net::Ipv4Addr},
    network_types::{
        eth::{EthHdr, EtherType},
        ip::{IpProto, Ipv4Hdr},
        udp::UdpHdr,
    },
};

pub struct ContextRef {
    pub data: usize,
    pub data_end: usize,
}

const GRE_HDR_LEN: usize = 4;
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &ContextRef, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data;
    let end = ctx.data_end;
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

pub fn has_entry<T: Eq>(haystack: &Array<Option<T>>, needle: T, wildcard: T) -> bool {
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

fn parse_ip_header(ipv4hdr: *const Ipv4Hdr) -> (Ipv4Addr, Ipv4Addr, IpProto) {
    let src_ip = Ipv4Addr::from_bits(unsafe { u32::from_be((*ipv4hdr).src_addr) });
    let dst_ip = Ipv4Addr::from_bits(unsafe { u32::from_be((*ipv4hdr).dst_addr) });
    let ip_proto = unsafe { (*ipv4hdr).proto };
    (src_ip, dst_ip, ip_proto)
}

pub fn extract_headers(
    ctx: &ContextRef,
    flags: Flags,
) -> Result<(usize, Ipv4Addr, Ipv4Addr, u16, u16, usize), ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Err(()),
    }
    let mut ip_header_offset = EthHdr::LEN;
    let mut ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, ip_header_offset)? };
    let (src_ip, dst_ip, ip_proto) = parse_ip_header(ipv4hdr);
    let (src_ip, dst_ip) = match (ip_proto, flags) {
        (IpProto::Udp, Flags::Default) | (IpProto::Udp, Flags::StripGre) => (src_ip, dst_ip),
        (IpProto::Gre, Flags::OnlyGre) => {
            ip_header_offset = EthHdr::LEN + Ipv4Hdr::LEN + GRE_HDR_LEN;

            ipv4hdr = unsafe { ptr_at(&ctx, ip_header_offset)? };
            let (src_ip, dst_ip, ip_proto) = parse_ip_header(ipv4hdr);
            if !matches!(ip_proto, IpProto::Udp) {
                return Err(());
            }
            (src_ip, dst_ip)
        }
        (IpProto::Gre, Flags::StripGre) => {
            ip_header_offset = EthHdr::LEN + Ipv4Hdr::LEN + GRE_HDR_LEN;

            ipv4hdr = unsafe { ptr_at(&ctx, ip_header_offset)? };
            let (src_ip, dst_ip, ip_proto) = parse_ip_header(ipv4hdr);
            if !matches!(ip_proto, IpProto::Udp) {
                return Err(());
            }
            (src_ip, dst_ip)
        }
        _ => {
            return Err(());
        }
    };
    let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, ip_header_offset + Ipv4Hdr::LEN)? };
    let src_port = unsafe { u16::from_be((*udphdr).source) };
    let dst_port = unsafe { u16::from_be((*udphdr).dest) };
    let len = unsafe { (u16::from_be((*udphdr).len) as usize) + 20 };

    Ok((ip_header_offset, src_ip, dst_ip, src_port, dst_port, len))
}
