use std::{
    ffi::CStr,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{
    storage::{hexdump, DumbStorage, Monitor, WritePackets},
    Stats,
};
use anyhow::Context;
use log::{debug, error, info};
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::{blocks::interface_description::InterfaceDescriptionBlock, PcapNgWriter};
use solana_ledger::shred::Shred;
use solana_ledger::shred::ShredVariant;
use std::fs::File;

#[derive(Default)]
struct TurbineInventory {
    legacy_code: DumbStorage,
    legacy_data: DumbStorage,
    merkle_code: DumbStorage,
    merkle_code_resigned: DumbStorage,
    merkle_data: DumbStorage,
    merkle_data_resigned: DumbStorage,
}

impl TurbineInventory {
    fn try_retain(&mut self, _shred: &Shred, bytes: &[u8], size_hint: usize) -> bool {
        let variant = solana_ledger::shred::layout::get_shred_variant(bytes).unwrap();
        match variant {
            ShredVariant::LegacyCode => self.legacy_code.try_retain(bytes, size_hint),
            ShredVariant::LegacyData => self.legacy_data.try_retain(bytes, size_hint),
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
        write_thing!(legacy_code);
        write_thing!(legacy_code);
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

fn parse_turbine(bytes: &[u8]) -> anyhow::Result<Shred> {
    //Todo: maybe sigverify this?
    Ok(Shred::new_from_serialized_shred(bytes.to_owned())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?)
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
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let len = socket.recv(&mut buf).context("socket RX")?;
        stats.captured += 1;
        let slice = &buf[20 + 8..len];

        //let layers = parse_layers!(slice, Ip, (Udp, Raw));
        let Ok(pkt) = parse_turbine(slice) else {
            continue;
        };
        stats.valid += 1;
        if inventory.try_retain(&pkt, slice, size_hint) {
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
    coding_shreds: usize,
    data_shreds: usize,
    merkle_shreds: usize,
    legacy_shreds: usize,
}

pub fn validate_turbine(filename: PathBuf) -> anyhow::Result<Stats> {
    let mut stats = Stats::default();
    let file_in = File::open(&filename).with_context(|| format!("opening file {filename:?}"))?;
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

pub fn monitor_turbine(bind_ip: Ipv4Addr, port: u16) -> anyhow::Result<Stats> {
    let socket = rscap::linux::l4::L4Socket::new(rscap::linux::l4::L4Protocol::Udp)
        .context("L4 socket creation")?;
    socket
        .bind(&SocketAddrV4::new(bind_ip, port))
        .context("bind should not fail")?;
    let mut buf = vec![0; 2048];
    let mut stats = Stats::default();

    let mut rate = Monitor::default();
    let mut last_report = Instant::now();
    let counter = Counter::default();
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let len = socket.recv(&mut buf).context("socket RX")?;
        let valid_buf = &buf[0..len];
        stats.captured += 1;
        let slice = &valid_buf[20 + 8..];

        let pkt = match parse_turbine(slice) {
            Ok(pkt) => pkt,
            Err(_) => {
                continue;
            }
        };
        if pkt.sanitize().is_err() {
            continue;
        }
        rate.try_retain(slice, slice.len());
        stats.valid += 1;
        if last_report.elapsed() > Duration::from_millis(1000) {
            last_report = Instant::now();
            println!("{}: {:?}", last_report.elapsed().as_secs(), counter);
            let rate = rate.rate().unwrap_or(0.0);
            println!("Turbine data rate is {:?} pps", rate);
        }
    }
    // Ack the command to exit the capture
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(stats)
}
