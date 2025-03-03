use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::Write;
use std::net::Ipv4Addr;

use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::simple_packet::SimplePacketBlock;
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};

pub(crate) fn write_packet<W: std::io::Write>(
    data: &[u8],
    writer: &mut PcapNgWriter<W>,
) -> anyhow::Result<()> {
    let packet = SimplePacketBlock {
        original_len: data.len() as u32,
        data: Cow::Borrowed(data),
    };

    writer.write_block(&packet.into_block())?;
    Ok(())
}

pub trait WritePackets {
    fn write_packets<W: std::io::Write>(
        &mut self,
        writer: &mut PcapNgWriter<W>,
    ) -> anyhow::Result<()>;
}

#[derive(Default)]
pub(crate) struct DumbStorage(Vec<Box<[u8]>>);

impl DumbStorage {
    pub(crate) fn try_retain(&mut self, bytes: &[u8], size: usize) -> bool {
        if self.0.len() < size {
            let bytes = bytes.to_owned().into_boxed_slice();
            self.0.push(bytes);

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
        for p in self.0.iter() {
            write_packet(p, writer)?
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
pub struct Monitor {
    pub packets: VecDeque<EnhancedPacketBlock<'static>>,
    pub bytes_stored: usize,
}
impl Monitor {
    pub fn try_retain(&mut self, bytes: &[u8], size: usize) -> bool {
        self.packets.push_back(EnhancedPacketBlock {
            original_len: bytes.len() as u32,
            data: Cow::from(bytes.to_owned()),
            interface_id: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap(),
            options: vec![],
        });
        self.bytes_stored += bytes.len();
        if self.packets.len() > size {
            let p = self.packets.pop_front().unwrap();
            self.bytes_stored -= p.original_len as usize;
        }
        true
    }

    pub fn rate_bps(&self) -> Option<f32> {
        let oldest = self.packets.front()?;
        let newest = self.packets.back()?;
        if oldest == newest {
            return None;
        }
        let dt = newest.timestamp - oldest.timestamp;
        let dt_secs = dt.as_secs_f32();
        Some((self.bytes_stored * 8) as f32 / dt_secs)
    }
    pub fn rate_pps(&self) -> Option<f32> {
        let oldest = self.packets.front()?;
        let newest = self.packets.back()?;
        if oldest == newest {
            return None;
        }
        let dt = newest.timestamp - oldest.timestamp;
        let num = self.packets.len() as f32;
        let dt_secs = dt.as_secs_f32();
        Some(num / dt_secs)
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
