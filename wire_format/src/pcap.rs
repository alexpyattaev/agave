use std::borrow::Cow;

use pcap_file::pcapng::blocks::simple_packet::SimplePacketBlock;
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};

pub fn write_packet<W: std::io::Write>(
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
    fn write_packets<W: std::io::Write>(&self, writer: &mut PcapNgWriter<W>) -> anyhow::Result<()>;
}
