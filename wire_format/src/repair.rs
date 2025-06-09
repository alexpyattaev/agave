#![allow(dead_code)]
use std::{
    ffi::CStr,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{
    storage::{fetch_dest, hexdump, DumbStorage, Monitor, WritePackets},
    Stats,
};
pub mod speed_meter;
pub use speed_meter::*;

use anyhow::Context;
use bincode::Options;
use log::{debug, error, info};
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::{blocks::interface_description::InterfaceDescriptionBlock, PcapNgWriter};
use std::fs::File;

#[derive(Default)]
struct RepairInventory {
    window_index: DumbStorage,
    highest_window_index: DumbStorage,
    orphan: DumbStorage,
    ancestor: DumbStorage,
    pong: DumbStorage,
}

impl RepairInventory {
    fn try_retain(&mut self, pkt: &RepairProtocol, bytes: &[u8], size: usize) -> bool {
        match pkt {
            RepairProtocol::LegacyWindowIndex => todo!(),
            RepairProtocol::LegacyHighestWindowIndex => todo!(),
            RepairProtocol::LegacyOrphan => todo!(),
            RepairProtocol::LegacyWindowIndexWithNonce => todo!(),
            RepairProtocol::LegacyHighestWindowIndexWithNonce => todo!(),
            RepairProtocol::LegacyOrphanWithNonce => todo!(),
            RepairProtocol::LegacyAncestorHashes => todo!(),
            RepairProtocol::Pong(_pong) => self.pong.try_retain(bytes, size),
            RepairProtocol::WindowIndex {
                header: _,
                slot: _,
                shred_index: _,
            } => self.window_index.try_retain(bytes, size),
            RepairProtocol::HighestWindowIndex {
                header: _,
                slot: _,
                shred_index: _,
            } => self.highest_window_index.try_retain(bytes, size),
            RepairProtocol::Orphan { header: _, slot: _ } => self.orphan.try_retain(bytes, size),
            RepairProtocol::AncestorHashes { header: _, slot: _ } => {
                self.ancestor.try_retain(bytes, size)
            }
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
        write_thing!(window_index);
        write_thing!(highest_window_index);
        write_thing!(orphan);
        write_thing!(ancestor);
        write_thing!(pong);
        Ok(())
    }

    fn write_file(
        store: &mut impl WritePackets,
        mut filename: PathBuf,
        suffix: &str,
    ) -> anyhow::Result<()> {
        filename.push(suffix);
        let file_out =
            File::create(&filename).with_context(|| format!("opening file {filename:?}"))?;
        let mut writer = PcapNgWriter::new(file_out).context("pcap writer creation")?;

        let interface = InterfaceDescriptionBlock {
            linktype: pcap_file::DataLink::IPV4,
            snaplen: 2048,
            options: vec![],
        };
        writer.write_pcapng_block(interface)?;
        store
            .write_packets(&mut writer)
            .context("storing packets into pcap file")
    }
}

use solana_core::repair::serve_repair::RepairProtocol;
fn parse_repair(bytes: &[u8]) -> anyhow::Result<RepairProtocol> {
    let pkt: RepairProtocol = bincode::options()
        .with_limit(bytes.len() as u64)
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)?;
    Ok(pkt)
}

pub fn capture_repair(
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
    let mut inventory = RepairInventory::default();
    info!("Capturing turbine packets");
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let len = socket.recv(&mut buf).context("socket RX")?;
        let buf = &buf[..len];

        let (dst_ip, dst_port) = fetch_dest(&buf);
        // skip packets that socket filter let through
        if dst_ip != bind_ip || dst_port != port {
            continue;
        }
        stats.captured += 1;
        let data_slice = &buf[20 + 8..];

        //let layers = parse_layers!(slice, Ip, (Udp, Raw));
        let Ok(pkt) = parse_repair(data_slice) else {
            continue;
        };
        stats.valid += 1;
        if inventory.try_retain(&pkt, data_slice, size_hint) {
            stats.retained += 1;
        }
    }

    // Ack the command to exit the capture
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    inventory
        .dump_to_files(pcap_filename)
        .context("Saving files failed")?;
    Ok(stats)
}

#[derive(Default, Debug)]
struct Counter {
    legacy: usize,
    window_index: usize,
    highest_window_index: usize,
    orphan: usize,
    ancestor: usize,
    pong: usize,
}

pub fn validate_repair(filename: PathBuf) -> anyhow::Result<Stats> {
    let mut stats = Stats::default();
    let file_in = File::open(&filename).with_context(|| format!("opening file {filename:?}"))?;
    let mut reader = PcapNgReader::new(file_in).context("pcap reader creation")?;
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
        match parse_repair(pkt_payload) {
            Ok(_) => {
                stats.valid += 1;
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
    Ok(stats)
}

pub fn monitor_repair(bind_ip: Ipv4Addr, port: u16) -> anyhow::Result<Stats> {
    let socket = rscap::linux::l4::L4Socket::new(rscap::linux::l4::L4Protocol::Udp)
        .context("L4 socket creation")?;
    socket
        .bind(&SocketAddrV4::new(bind_ip, port))
        .context("bind should not fail")?;
    let mut buf = vec![0; 2048];
    let mut stats = Stats::default();

    let mut rate: Monitor<1000> = Monitor::default();
    let mut last_report = Instant::now();
    let mut counter = Counter::default();
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let len = socket.recv(&mut buf).context("socket RX")?;
        let buf = &buf[0..len];
        let (dst_ip, dst_port) = fetch_dest(&buf);
        // skip packets that socket filter let through
        if dst_ip != bind_ip || dst_port != port {
            continue;
        }
        stats.captured += 1;
        let data_slice = &buf[20 + 8..];

        let pkt = match parse_repair(data_slice) {
            Ok(pkt) => pkt,
            Err(_) => {
                continue;
            }
        };
        rate.push(data_slice.len());
        match pkt {
            RepairProtocol::LegacyWindowIndex => counter.legacy += 1,
            RepairProtocol::LegacyHighestWindowIndex => counter.legacy += 1,
            RepairProtocol::LegacyOrphan => counter.legacy += 1,
            RepairProtocol::LegacyWindowIndexWithNonce => counter.legacy += 1,
            RepairProtocol::LegacyHighestWindowIndexWithNonce => counter.legacy += 1,
            RepairProtocol::LegacyOrphanWithNonce => counter.legacy += 1,
            RepairProtocol::LegacyAncestorHashes => counter.legacy += 1,
            RepairProtocol::Pong(_) => counter.pong += 1,
            RepairProtocol::WindowIndex {
                header: _,
                slot: _,
                shred_index: _,
            } => counter.window_index += 1,
            RepairProtocol::HighestWindowIndex {
                header: _,
                slot: _,
                shred_index: _,
            } => counter.highest_window_index += 1,
            RepairProtocol::Orphan { header: _, slot: _ } => counter.orphan += 1,
            RepairProtocol::AncestorHashes { header: _, slot: _ } => counter.ancestor += 1,
        }
        stats.valid += 1;
        if last_report.elapsed() > Duration::from_millis(1000) {
            last_report = Instant::now();
            println!("{}: {:?}", last_report.elapsed().as_secs(), counter);
            let rate = rate.rate_pps().unwrap_or(0.0);
            println!("Repair data rate is {:?} pps", rate);
        }
    }
    dbg!(counter);
    // Ack the command to exit the capture
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(stats)
}
