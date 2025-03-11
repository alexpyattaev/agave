use std::{
    ffi::CStr,
    io::{BufWriter, Write},
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{
    storage::{fetch_dest, hexdump, DumbStorage, Monitor, WritePackets},
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
        write_thing!(legacy_data);
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

pub fn monitor_turbine(bind_ip: Ipv4Addr, port: u16, output: PathBuf) -> anyhow::Result<Stats> {
    let mut logfile = BufWriter::new(std::fs::File::create(output)?);

    let socket = rscap::linux::l4::L4Socket::new(rscap::linux::l4::L4Protocol::Udp)
        .context("L4 socket creation")?;
    socket
        .bind(&SocketAddrV4::new(bind_ip, port))
        .context("bind should not fail")?;
    let mut buf = vec![0; 2048];
    let mut stats = Stats::default();

    let mut rate = Monitor::default();
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

        let pkt = match parse_turbine(data_slice) {
            Ok(pkt) => pkt,
            Err(_) => {
                continue;
            }
        };
        if pkt.sanitize().is_err() {
            continue;
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();
        {
            write!(
                logfile,
                "SHRED_RX:{}:{}:{}:{timestamp}\n",
                pkt.slot(),
                pkt.index(),
                pkt.fec_set_index(),
            )?;
        }
        if pkt.merkle_root().is_ok() {
            counter.merkle_shreds += 1;
        } else {
            counter.legacy_shreds += 1;
        }
        if pkt.is_code() {
            counter.coding_shreds += 1;
        } else {
            counter.data_shreds += 1;
        }
        counter.zero_bytes += data_slice.iter().filter(|&e| *e == 0).count();
        counter.total_bytes += data_slice.len();
        rate.try_retain(data_slice, data_slice.len());
        stats.valid += 1;
        if last_report.elapsed() > Duration::from_millis(1000) {
            last_report = Instant::now();
            println!("{}: {:?}", last_report.elapsed().as_secs(), counter);
            let rate = rate.rate_pps().unwrap_or(0.0);
            println!("Turbine data rate is {:?} pps", rate);
            println!(
                "Turbine zeros rate is {}/{}",
                counter.zero_bytes, counter.total_bytes
            );
            println!(
                "Merkle:{} Legacy: {} Coding: {} Data: {}",
                counter.merkle_shreds,
                counter.legacy_shreds,
                counter.coding_shreds,
                counter.data_shreds
            );
        }
    }
    // Ack the command to exit the capture
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    logfile.flush()?;
    Ok(stats)
}
