use std::borrow::Cow;

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
