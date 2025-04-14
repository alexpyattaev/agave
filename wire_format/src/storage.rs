use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant, SystemTime};

use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;

pub trait WritePackets {
    fn write_packets<W: std::io::Write>(
        &mut self,
        writer: &mut PcapNgWriter<W>,
    ) -> anyhow::Result<()>;
}

#[derive(Default)]
pub(crate) struct DumbStorage(Vec<EnhancedPacketBlock<'static>>);

pub fn epb_from_bytes(bytes: &[u8]) -> EnhancedPacketBlock<'static> {
    EnhancedPacketBlock {
        interface_id: 0,
        timestamp: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap(),
        original_len: bytes.len() as u32,
        data: Cow::Owned(bytes.to_owned()),
        options: vec![],
    }
}

impl DumbStorage {
    pub(crate) fn try_retain(&mut self, bytes: &[u8], size: usize) -> bool {
        if self.0.len() < size {
            self.0.push(epb_from_bytes(bytes));
            true
        } else {
            false
        }
    }
}
impl WritePackets for DumbStorage {
    fn write_packets<W: std::io::Write>(
        &mut self,
        writer: &mut PcapNgWriter<W>,
    ) -> anyhow::Result<()> {
        let interface = InterfaceDescriptionBlock {
            linktype: pcap_file::DataLink::IPV4,
            snaplen: 1500,
            options: vec![],
        };
        writer.write_pcapng_block(interface)?;
        for p in self.0.drain(..) {
            writer.write_pcapng_block(p)?;
        }
        Ok(())
    }
}

pub fn hexdump(bytes: &[u8]) -> anyhow::Result<()> {
    hxdmp::hexdump(bytes, &mut std::io::stderr())?;
    std::io::stderr().write_all(b"\n")?;
    Ok(())
}

#[derive(Default)]
pub struct Monitor<const WINDOW_MS: u64 = 1000> {
    pub packets: VecDeque<(Instant, usize)>,
    pub bytes_stored: usize,
}
impl<const WINDOW_MS: u64> Monitor<WINDOW_MS> {
    pub fn push(&mut self, bytes: usize) {
        self.packets.push_back((Instant::now(), bytes));
        self.bytes_stored += bytes;
    }

    pub fn rate_bps(&mut self) -> Option<f64> {
        self.evict();
        let num = self.packets.len();
        if num == 0 {
            return None;
        };
        let dt = Duration::from_millis(WINDOW_MS).as_secs_f64();
        Some((self.bytes_stored * 8) as f64 / dt)
    }
    pub fn evict(&mut self) {
        loop {
            let Some(oldest) = self.packets.front() else {
                return;
            };
            if oldest.0.elapsed() > Duration::from_millis(WINDOW_MS) {
                let pkt = self.packets.pop_front().unwrap();
                self.bytes_stored -= pkt.1;
            } else {
                break;
            }
        }
    }
    pub fn rate_pps(&mut self) -> Option<f64> {
        self.evict();
        let num = self.packets.len();
        if num == 0 {
            return None;
        };
        let dt = Duration::from_millis(WINDOW_MS).as_secs_f64();
        Some(num as f64 / dt)
    }
}

pub fn fetch_dest(buf: &[u8]) -> (Ipv4Addr, u16) {
    let mut ip = [0u8; 4];
    ip.as_mut().copy_from_slice(&buf[16..16 + 4]);
    let ip: u32 = u32::from_be_bytes(ip);
    let ip = Ipv4Addr::from_bits(ip);

    let mut dst_port = [0u8; 2];
    dst_port.as_mut().copy_from_slice(&buf[20 + 2..20 + 4]);
    let dst_port = u16::from_be_bytes(dst_port);

    (ip, dst_port)
}
