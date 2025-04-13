#![allow(dead_code)]
use std::{
    ffi::CStr,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{
    storage::{fetch_dest, hexdump, DumbStorage, WritePackets},
    Stats,
};
use anyhow::Context;
use log::{debug, error, info};
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::PcapNgWriter;
use solana_ledger::shred::{wire::get_shred_size, ShredVariant};
use solana_ledger::shred::{CodingShredHeader, Shred};

mod speed_meter;
pub use speed_meter::*;
mod logger;
pub use logger::*;

#[derive(Default)]
struct TurbineInventory {
    merkle_code: DumbStorage,
    merkle_code_resigned: DumbStorage,
    merkle_data: DumbStorage,
    merkle_data_resigned: DumbStorage,
}

impl TurbineInventory {
    fn try_retain(&mut self, _shred: &Shred, bytes: &[u8], size_hint: usize) -> bool {
        let variant = solana_ledger::shred::layout::get_shred_variant(bytes).unwrap();
        match variant {
            ShredVariant::MerkleCode {
                proof_size: _,
                chained: _,
                resigned: true,
            } => self.merkle_code_resigned.try_retain(bytes, size_hint),
            ShredVariant::MerkleCode {
                proof_size: _,
                chained: _,
                resigned: false,
            } => self.merkle_code.try_retain(bytes, size_hint),
            ShredVariant::MerkleData {
                proof_size: _,
                chained: _,
                resigned: true,
            } => self.merkle_data_resigned.try_retain(bytes, size_hint),
            ShredVariant::MerkleData {
                proof_size: _,
                chained: _,
                resigned: false,
            } => self.merkle_data.try_retain(bytes, size_hint),
            _ => false,
        }
    }

    fn dump_to_files(&mut self, filename: PathBuf) -> anyhow::Result<()> {
        macro_rules! write_thing {
            ($name:ident) => {
                Self::write_file(
                    &mut self.$name,
                    filename.clone(),
                    concat!(stringify!($name), ".pcap"),
                )?;
            };
        }
        write_thing!(merkle_code);
        write_thing!(merkle_code_resigned);
        write_thing!(merkle_data);
        write_thing!(merkle_data_resigned);
        Ok(())
    }

    fn write_file(
        store: &mut impl WritePackets,
        mut filename: PathBuf,
        suffix: &str,
    ) -> anyhow::Result<()> {
        filename.push(suffix);
        let file_out = std::fs::File::create(&filename)
            .with_context(|| format!("opening file {filename:?}"))?;
        let mut writer = PcapNgWriter::new(file_out).context("pcap writer creation")?;

        store
            .write_packets(&mut writer)
            .context("storing packets into pcap file")
    }
}

fn parse_turbine(bytes: &[u8]) -> anyhow::Result<Shred> {
    let shred = Shred::new_from_serialized_shred(bytes.to_owned())
        .map_err(|_e| anyhow::anyhow!("Can not deserialize"))?;
    shred
        .sanitize()
        .map_err(|_e| anyhow::anyhow!("Failed sanitize"))?;
    Ok(shred)
}

fn serialize(pkt: &Shred) -> Vec<u8> {
    pkt.payload().to_vec()
}

fn get_coding_header(pkt: &Shred) -> Option<CodingShredHeader> {
    match pkt {
        Shred::ShredCode(shred_code) => match shred_code {
            solana_ledger::shred::shred_code::ShredCode::Merkle(shred_code) => {
                Some(shred_code.coding_header.clone())
            }
            _ => None,
        },
        _ => None,
    }
}

pub fn capture_turbine(
    _ifname: &CStr,
    bind_ip: Ipv4Addr,
    port: u16,
    pcap_filename: PathBuf,
    size_hint: usize,
) -> anyhow::Result<Stats> {
    //let leader_schedule = get_leader_schedule()?;
    info!("Binding the capture socket");
    let socket = rscap::linux::l4::L4Socket::new(rscap::linux::l4::L4Protocol::Udp)
        .context("L4 socket creation")?;
    socket
        .bind(&SocketAddrV4::new(bind_ip, port))
        .context("bind should not fail")?;
    let mut buf = vec![0; 2048];
    let mut stats = Stats::default();
    let mut inventory = TurbineInventory::default();
    info!("Capturing turbine packets");
    let mut ignored = 0;
    let mut last_report = Instant::now();
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let len = socket.recv(&mut buf).context("socket RX")?;
        let buf = &buf[..len];

        let (dst_ip, dst_port) = fetch_dest(&buf);
        // skip packets that socket filter let through
        if (dst_ip != bind_ip) || (dst_port != port) {
            ignored += 1;
            continue;
        }
        let mut src_ip = [0u8; 4];
        src_ip.as_mut().copy_from_slice(&buf[12..12 + 4]);
        let src_ip: u32 = u32::from_be_bytes(src_ip);
        let src_ip = Ipv4Addr::from_bits(src_ip);
        stats.captured += 1;
        let data_slice = &buf[20 + 8..];

        //let layers = parse_layers!(slice, Ip, (Udp, Raw));
        let Ok(pkt) = parse_turbine(data_slice) else {
            continue;
        };
        //hack to get valid length of packet
        let ser = serialize(&pkt);
        if ser.len() != data_slice.len() {
            println!(
                "{:?} {} {}!={}",
                src_ip,
                pkt.slot(),
                ser.len(),
                data_slice.len()
            );
        }
        stats.valid += 1;
        if inventory.try_retain(&pkt, &data_slice[0..ser.len()], size_hint) {
            stats.retained += 1;
        }
        if last_report.elapsed() > Duration::from_millis(500) {
            last_report = Instant::now();
            println!("Retained {} packets so far...", stats.retained);
        }
    }

    // Ack the command to exit the capture
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    inventory
        .dump_to_files(pcap_filename)
        .context("Saving files failed")?;
    dbg!(ignored);
    Ok(stats)
}

#[derive(Default, Debug)]
struct Counter {
    coding_shreds: usize,
    data_shreds: usize,
    merkle_shreds: usize,
    legacy_shreds: usize,
    zero_bytes: usize,
    total_bytes: usize,
}

pub fn validate_turbine(filename: PathBuf) -> anyhow::Result<Stats> {
    let mut stats = Stats::default();
    let file_in =
        std::fs::File::open(&filename).with_context(|| format!("opening file {filename:?}"))?;
    let mut reader = PcapNgReader::new(file_in).context("pcap reader creation")?;
    let mut counter = Counter::default();
    loop {
        let Some(block) = reader.next_block() else {
            break;
        };
        let block = block?;
        let data = match block {
            pcap_file::pcapng::Block::Packet(ref block) => {
                &block.data[0..block.original_len as usize]
            }
            pcap_file::pcapng::Block::SimplePacket(ref block) => {
                &block.data[0..block.original_len as usize]
            }
            pcap_file::pcapng::Block::EnhancedPacket(ref block) => {
                &block.data[0..block.original_len as usize]
            }
            _ => {
                debug!("Skipping unknown block in pcap file");
                continue;
            }
        };
        // Check if IP header is present
        let pkt_payload = if data[0] == 69 {
            &data[20 + 8..]
        } else {
            &data[0..]
        };

        stats.captured += 1;
        match parse_turbine(pkt_payload) {
            Ok(pkt) => {
                stats.valid += 1;
                if pkt.merkle_root().is_ok() {
                    counter.merkle_shreds += 1;
                } else {
                    counter.legacy_shreds += 1;
                }
                println!(
                    "id={id:?} type={typ:?} Code? {is_code} FEC idx{fec}",
                    is_code = pkt.is_code(),
                    fec = pkt.fec_set_index(),
                    id = pkt.id(),
                    typ = pkt.shred_type()
                );
                if pkt.is_data() {
                    counter.data_shreds += 1;
                } else {
                    counter.coding_shreds += 1;
                }
                stats.retained += 1;
            }
            Err(e) => {
                error!(
                    "Found packet {} that failed to parse with error {e}",
                    stats.captured
                );
                error!("Problematic packet bytes:");
                hexdump(pkt_payload)?;
            }
        }
    }
    dbg!(counter);
    Ok(stats)
}

fn detect_repair_nonce(data: &[u8]) -> Option<(&[u8], Option<u32>)> {
    let shred_end = get_shred_size(data)?;
    let shred = data.get(..shred_end)?;
    let offset = data.len().checked_sub(4)?;
    if offset < shred_end {
        return Some((shred, None));
    }
    let nonce = <[u8; 4]>::try_from(data.get(offset..)?).ok()?;
    let nonce = u32::from_le_bytes(nonce);
    Some((shred, Some(nonce)))
}
