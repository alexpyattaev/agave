use {
    crate::{
        storage::{DumbStorage, WritePackets},
        Stats,
    },
    anyhow::Context,
    log::{debug, error},
    pcap_file::pcapng::{PcapNgBlock, PcapNgReader, PcapNgWriter},
    serde::Serialize,
    solana_gossip::{crds_data::CrdsData, crds_value::CrdsValue, protocol::Protocol},
    solana_sanitize::Sanitize,
    std::{
        borrow::Cow,
        ffi::CStr,
        fs::File,
        io::Write,
        net::{Ipv4Addr, SocketAddrV4},
        path::PathBuf,
        time::{Duration, Instant},
    },
    strum::EnumCount,
};

fn parse_gossip(bytes: &[u8]) -> bincode::Result<Protocol> {
    solana_perf::packet::deserialize_from_with_limit(bytes)
}

fn _serialize<T: Serialize>(pkt: T) -> Vec<u8> {
    bincode::serialize(&pkt).unwrap()
}

type CrdsCounts = [usize; CrdsData::COUNT];

#[derive(Default)]
pub struct CrdsCaptures {
    crds_types: CrdsCounts,
    packets: Vec<Box<[u8]>>,
}

/// This will try to capture new and rare CRDS values until cost of doing so is not too high,
/// trying to roughly match the provided size hint. This can be expected to capture more than
/// size hint provided by about a factor of 3.
impl CrdsCaptures {
    fn try_retain(&mut self, crds: &[CrdsValue], bytes: &[u8], size: usize) -> bool {
        let counts = Self::count_crds(crds);
        let mut profit = 0.0;
        // count "profit" for getting more rare CRDS types
        for (&have, &new) in self.crds_types.iter().zip(counts.iter()) {
            if have == 0 {
                // pretty much always store never-before-seen CRDS types
                profit += 100.0;
            } else {
                // else become less and less interested as we capture more samples
                profit += new as f32 / have as f32;
            }
        }
        let cost_to_store = self.packets.len() as f32 / size as f32;
        /*println!(
            "Have {} packets, cost is {cost_to_store}, profit is {profit}",
            self.packets.len()
        );*/
        if profit > cost_to_store {
            self.packets.push(bytes.to_owned().into_boxed_slice());
            true
        } else {
            false
        }
    }

    fn count_crds(crds: &[CrdsValue]) -> CrdsCounts {
        let mut counts = CrdsCounts::default();
        for v in crds {
            counts[v.data().ordinal()] += 1;
        }
        counts
    }
}
impl WritePackets for CrdsCaptures {
    fn write_packets<W: std::io::Write>(
        &mut self,
        writer: &mut PcapNgWriter<W>,
    ) -> anyhow::Result<()> {
        for p in self.packets.iter() {
            crate::storage::write_packet(p, writer)?
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct GossipInventory {
    ping: DumbStorage,
    pong: DumbStorage,
    prune: DumbStorage,
    pull_request: DumbStorage,
    pull_response: CrdsCaptures,
    push: CrdsCaptures,
}

impl GossipInventory {
    fn try_retain(&mut self, pkt: &Protocol, bytes: &[u8], size: usize) -> bool {
        match pkt {
            Protocol::PingMessage(_) => self.ping.try_retain(bytes, size),
            Protocol::PullRequest(_crds_filter, _crds_value) => {
                self.pull_request.try_retain(bytes, size)
            }
            Protocol::PullResponse(_pubkey, crds_values) => {
                self.pull_response
                    .try_retain(crds_values.as_slice(), bytes, size)
            }
            Protocol::PushMessage(_pubkey, crds_values) => {
                self.push.try_retain(crds_values.as_slice(), bytes, size)
            }
            Protocol::PruneMessage(_pubkey, _prune_data) => self.prune.try_retain(bytes, size),
            Protocol::PongMessage(_pong) => self.pong.try_retain(bytes, size),
        }
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
        store
            .write_packets(&mut writer)
            .context("storing packets into pcap file")
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
        write_thing!(ping);
        write_thing!(pong);
        write_thing!(prune);
        write_thing!(pull_request);
        write_thing!(pull_response);
        write_thing!(push);
        Ok(())
    }
}

pub fn capture_gossip(
    _ifname: &CStr,
    bind_ip: Ipv4Addr,
    port: u16,
    pcap_filename: PathBuf,
    size_hint: usize,
) -> anyhow::Result<Stats> {
    let socket = rscap::linux::l4::L4Socket::new(rscap::linux::l4::L4Protocol::Udp)
        .context("L4 socket creation")?;
    socket
        .bind(&SocketAddrV4::new(bind_ip, port))
        .context("bind should not fail")?;
    let mut buf = vec![0; 2048];
    let mut stats = Stats::default();
    let mut inventory = GossipInventory::default();
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let len = socket.recv(&mut buf).context("socket RX")?;
        stats.captured += 1;
        let slice = &buf[20 + 8..len];

        //let layers = parse_layers!(slice, Ip, (Udp, Raw));
        let Ok(pkt) = parse_gossip(slice) else {
            continue;
        };
        if pkt.sanitize().is_err() {
            continue;
        }
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

pub fn validate_gossip(filename: PathBuf) -> anyhow::Result<Stats> {
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
        let pkt_payload = &data[0..];
        stats.captured += 1;
        match parse_gossip(pkt_payload) {
            Ok(pkt) => {
                stats.valid += 1;
                if pkt.sanitize().is_err() {
                    error!("Sanitize failed for packet {}!", stats.captured);
                    error!("Original packet bytes:");
                    hexdump(pkt_payload)?;
                }
                let reconstructed_bytes = _serialize(pkt);
                if reconstructed_bytes != pkt_payload {
                    error!("Reserialization failed for packet {}!", stats.captured);
                    error!("Original packet bytes:");
                    hexdump(pkt_payload)?;
                    error!("Reserialized bytes:");
                    hexdump(&reconstructed_bytes)?;
                } else {
                    stats.retained += 1;
                }
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

fn hexdump(bytes: &[u8]) -> anyhow::Result<()> {
    hxdmp::hexdump(bytes, &mut std::io::stderr())?;
    std::io::stderr().write_all(b"\n")?;
    Ok(())
}

use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use std::collections::VecDeque;

#[derive(Default)]
pub struct Monitor {
    packets: VecDeque<EnhancedPacketBlock<'static>>,
}
impl Monitor {
    fn try_retain(&mut self, bytes: &[u8], size: usize) -> bool {
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

    fn rate(&self) -> f32 {
        let oldest = self.packets.front().unwrap();
        let newest = self.packets.back().unwrap();
        if oldest == newest {
            return 0.0;
        }
        let dt = newest.timestamp - oldest.timestamp;
        let num = self.packets.len() as f32;
        let dt_secs = dt.as_secs_f32();
        num / dt_secs
    }
}

#[derive(Default)]
pub struct GossipMonitor {
    //ping: VecDeque<Box<[u8]>>,
    //pong: VecDeque<Box<[u8]>>,
    //prune: VecDeque<Box<[u8]>>,
    //pull_request: DumbStorage,
    //pull_response: CrdsCaptures,
    all: Monitor,
    push: Monitor,
    push_node_info: Monitor,
}
impl WritePackets for Monitor {
    fn write_packets<W: std::io::Write>(
        &mut self,
        writer: &mut PcapNgWriter<W>,
    ) -> anyhow::Result<()> {
        for packet in self.packets.drain(..) {
            writer.write_block(&packet.into_block())?;
        }
        Ok(())
    }
}

impl GossipMonitor {
    fn try_retain(&mut self, pkt: &Protocol, bytes: &[u8], size: usize) -> bool {
        match pkt {
            Protocol::PushMessage(_pubkey, crds_values) => {
                if crds_values.iter().any(|e| match e.data() {
                    CrdsData::NodeInstance(_) => true,
                    _ => false,
                }) {
                    self.push_node_info.try_retain(bytes, size)
                } else {
                    self.push.try_retain(bytes, size)
                }
            }
            _ => self.all.try_retain(bytes, size),
        }
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
        store
            .write_packets(&mut writer)
            .context("storing packets into pcap file")
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
        write_thing!(push);
        Ok(())
    }
}

use rscap::linux::addr::L2Protocol;

pub fn monitor_gossip(
    bind_ip: Ipv4Addr,
    port: u16,
    pcap_filename: PathBuf,
    size_hint: usize,
) -> anyhow::Result<Stats> {
    /*let socket = rscap::linux::l3::L3Socket::new().context("L3 socket creation")?;
    let iface = rscap::Interface::new("bond0")?;
    socket
        .bind(iface, L2Protocol::Ip)
        .context("bind should not fail")?;
    return Ok(Stats::default());*/
    let socket = rscap::linux::l4::L4Socket::new(rscap::linux::l4::L4Protocol::Udp)
        .context("L4 socket creation")?;
    socket
        .bind(&SocketAddrV4::new(bind_ip, port))
        .context("bind should not fail")?;
    let mut buf = vec![0; 2048];
    let mut stats = Stats::default();
    let mut monitor = GossipMonitor::default();

    let mut last_report = Instant::now();
    let mut capturing = false;
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let len = socket.recv(&mut buf).context("socket RX")?;
        stats.captured += 1;
        let slice = &buf[20 + 8..len];

        //let layers = parse_layers!(slice, Ip, (Udp, Raw));
        let Ok(pkt) = parse_gossip(slice) else {
            continue;
        };
        if pkt.sanitize().is_err() {
            continue;
        }
        stats.valid += 1;
        if monitor.try_retain(&pkt, slice, size_hint) {
            stats.retained += 1;
        }
        if last_report.elapsed() > Duration::from_millis(500) {
            last_report = Instant::now();
            let rate = monitor.push.rate();
            println!("Current gossip rate is {:?}", rate);
            if rate > 10000.0 {
                println!("Peak starting!");

                capturing = true;
            } else {
                if capturing {
                    println!("Caught peak!");
                    break;
                }
            }
        }
    }
    // Ack the command to exit the capture
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    monitor
        .dump_to_files(pcap_filename)
        .context("Saving files failed")?;
    Ok(stats)
}
