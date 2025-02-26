use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::Write;

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
        if self.packets.len() > size {
            self.packets.pop_front();
        }
        true
    }

    pub fn rate(&self) -> Option<f32> {
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
