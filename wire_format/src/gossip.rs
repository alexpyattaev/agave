#![allow(dead_code)]
use {
    crate::{
        storage::{fetch_dest, hexdump, DumbStorage, Monitor, WritePackets},
        Stats,
    },
    anyhow::Context,
    aya::maps::{MapData, RingBuf},
    indicatif::{MultiProgress, ProgressBar, ProgressStyle},
    log::{debug, error},
    pcap_file::pcapng::{
        blocks::interface_description::InterfaceDescriptionBlock, PcapNgBlock, PcapNgReader,
        PcapNgWriter,
    },
    pcap_file_tokio::pcap::{PcapPacket, PcapWriter},
    serde::Serialize,
    solana_gossip::{crds_data::CrdsData, crds_value::CrdsValue, protocol::Protocol},
    solana_pubkey::Pubkey,
    solana_sanitize::Sanitize,
    std::{
        collections::HashMap,
        ffi::CStr,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        path::PathBuf,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
    strum::EnumCount,
    tokio::io::{unix::AsyncFd, BufWriter},
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
        let file_out = std::fs::File::create(&filename)
            .with_context(|| format!("opening file {filename:?}"))?;
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
        let buf = &buf[..len];
        let (dst_ip, dst_port) = fetch_dest(&buf);
        // skip packets that socket filter let through
        if dst_ip != bind_ip || dst_port != port {
            continue;
        }
        stats.captured += 1;
        let data_slice = &buf[20 + 8..len];

        //let layers = parse_layers!(slice, Ip, (Udp, Raw));
        let Ok(pkt) = parse_gossip(data_slice) else {
            continue;
        };
        if pkt.sanitize().is_err() {
            continue;
        }
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
    origins: HashMap<Pubkey, u64>,
    senders: HashMap<Pubkey, u64>,
    crds_types: CrdsCounts,
}
const CRDS_NAMES: [&str; 14] = [
    "LegacyContactInfo",
    "Vote",
    "LowestSlot",
    "LegacySnapshotHashes",
    "AccountsHashes",
    "EpochSlots",
    "LegacyVersion",
    "Version",
    "NodeInstance",
    "DuplicateShred",
    "SnapshotHashes",
    "ContactInfo",
    "RestartLastVotedForkSlots",
    "RestartHeaviestFork",
];
impl Counter {
    fn count_gossip(&mut self, pkt: &Protocol) {
        match pkt {
            Protocol::PushMessage(pubkey, crds_values) => {
                /*if (*pubkey
                    != Pubkey::from_str("2EAmentSLNvroEijzUG3UCAXmmxcsaCD6CuKXEsUGa6P").unwrap())
                {
                    return;
                }*/
                if crds_values.iter().any(|e| {
                    self.crds_types[e.data().ordinal()] += 1;
                    match e.data() {
                        CrdsData::NodeInstance(nodeinst) => {
                            let e = self.origins.entry(nodeinst.from).or_default();

                            *e += 1;
                            true
                        }
                        _ => false,
                    }
                }) {
                    let e = self.senders.entry(*pubkey).or_default();
                    *e += 1;
                    //dbg!(&pkt);
                } else {
                }
            }
            _ => {}
        }
    }
}
pub fn validate_gossip(filename: PathBuf) -> anyhow::Result<Stats> {
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
        match parse_gossip(pkt_payload) {
            Ok(pkt) => {
                stats.valid += 1;
                if pkt.sanitize().is_err() {
                    error!("Sanitize failed for packet {}!", stats.captured);
                    error!("Original packet bytes:");
                    hexdump(pkt_payload)?;
                }
                counter.count_gossip(&pkt);
                //dbg!(&pkt);
                /*let reconstructed_bytes = _serialize(pkt);
                if reconstructed_bytes != pkt_payload {
                    error!("Reserialization failed for packet {}!", stats.captured);
                    error!("Original packet bytes:");
                    hexdump(pkt_payload)?;
                    error!("Reserialized bytes:");
                    hexdump(&reconstructed_bytes)?;
                    break;
                } else {
                    stats.retained += 1;
                }*/
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
    dbg!(counter.senders.len());
    for (t, cnt) in CRDS_NAMES.iter().zip(counter.crds_types.iter()) {
        println!("{t}: {cnt}");
    }
    dbg!(counter.origins.len());
    Ok(stats)
}

#[derive(Default)]
pub struct GossipMonitor {
    // All invalid packets
    invalid: Monitor,
    // All valid packets
    valid: Monitor,
    // All push packets
    push: Monitor,
    // All prune packets
    prune: Monitor,
    // Ping and Pong
    pingpong: Monitor,
    // Whatever is not covered above
    others: Monitor,
    // CRDS stats
    //  ContactInfo and LegacyContactInfo packets (i.e. the whole point of gossip)
    crds_contact_info: Monitor,
    crds_epoch_slots: Monitor,
    crds_node_instance: Monitor,
    crds_vote: Monitor,
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
                dbg!(_pubkey);
                for cv in crds_values {
                    self.try_retain_crds(cv);
                }
                self.push.try_retain(bytes, size);
            }
            Protocol::PullResponse(_pubkey, crds_values) => {
                dbg!(_pubkey);
                for cv in crds_values {
                    self.try_retain_crds(cv);
                }
            }
            Protocol::PruneMessage(_pubkey, _) => {
                dbg!(_pubkey);
                self.prune.try_retain(bytes, size);
            }
            Protocol::PingMessage(_) | Protocol::PongMessage(_) => {
                self.pingpong.try_retain(bytes, size);
            }
            _ => {
                self.others.try_retain(bytes, size);
            }
        }
        self.valid.try_retain(bytes, size)
    }

    fn try_retain_crds(&mut self, cv: &CrdsValue) {
        let ser = bincode::serialize(cv.data()).unwrap();
        if cv.label().pubkey()
            != Pubkey::from_str_const("DmCowGH9DUHYCetfGaWzPzYCi455yDxewcycdyWuPLjx")
        {
            return;
        }
        dbg!(cv.label());
        match cv.data() {
            CrdsData::EpochSlots(_esi, _es) => {
                self.crds_epoch_slots.try_retain(&ser, ser.len());
            }
            CrdsData::Vote(_, _) => {
                self.crds_vote.try_retain(&ser, ser.len());
            }
            CrdsData::ContactInfo(_) | CrdsData::LegacyContactInfo(_) => {
                self.crds_contact_info.try_retain(&ser, ser.len());
            }
            CrdsData::NodeInstance(_) => {
                self.crds_node_instance.try_retain(&ser, ser.len());
            }
            _ => {}
        }
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
        write_thing!(prune);
        write_thing!(invalid);
        write_thing!(valid);
        Ok(())
    }
}

pub async fn gossip_capture(
    async_fd: &mut AsyncFd<RingBuf<MapData>>,
    filename: PathBuf,
) -> anyhow::Result<()> {
    let file_out = tokio::fs::File::create(filename)
        .await
        .expect("Error creating file out");

    // BufWriter to avoid a syscall per write. BufWriter will manage that for us and reduce the amound of syscalls.
    let stream = BufWriter::with_capacity(1024 * 256, file_out);
    let mut pcap_writer = PcapWriter::new(stream).await.expect("Error writing file");
    loop {
        // wait till it is ready to read and read
        let mut guard = async_fd.readable_mut().await.unwrap();
        let rb = guard.get_inner_mut();

        while let Some(read) = rb.next() {
            let ptr = read.as_ptr();

            // retrieve packet len first then packet data
            let size = unsafe { std::ptr::read_unaligned::<u16>(ptr as *const u16) };
            let data = unsafe { std::slice::from_raw_parts(ptr.byte_add(2), size.into()) };

            let ts = SystemTime::now().duration_since(UNIX_EPOCH)?;

            let packet = PcapPacket::new(ts, size as u32, data);
            pcap_writer.write_packet(&packet).await?;
        }

        guard.clear_ready();
    }
}

trait MonitorCommand {
    fn setup<T>(cfg: T) -> Self;
    async fn process_packet<R>(&mut self) -> anyhow::Result<R>;
}
use iocraft::prelude::*;

pub struct GossipLogger {}

pub async fn gossip_log_metadata(
    async_fd: &mut AsyncFd<RingBuf<MapData>>,
    size_hint: usize,
) -> anyhow::Result<()> {
    let m = MultiProgress::new();
    let sty = ProgressStyle::with_template(
        "[{elapsed_precise}] {bar:80.cyan/blue} {pos:>7}/{len:7} {msg}",
    )
    .unwrap()
    .progress_chars("##-");

    let n = 1000;
    let new_pb = |msg| {
        let rate = m.add(ProgressBar::new(n));
        rate.set_style(sty.clone());
        rate.set_message(msg);
        rate
    };
    let rate_gossip = new_pb("All glacier");
    let rate_junk = new_pb("Junk");
    let rate_prune = new_pb("Prune");
    let rate_ping = new_pb("Ping & Pong");
    let rate_contact_info = new_pb("CRDS: ContactInfo");
    let rate_votes = new_pb("CRDS: Vote");
    let rate_epoch_slots = new_pb("CRDS: EpochSlots");
    let rate_node_instance = new_pb("CRDS: NodeInstance");

    //Allocate buffer big enough for any valid datagram
    let mut monitor = GossipMonitor::default();
    let mut last_report = Instant::now();
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        // wait till it is ready to read and read
        let mut guard = async_fd.readable_mut().await.unwrap();
        let rb = guard.get_inner_mut();

        while let Some(read) = rb.next() {
            let ptr = read.as_ptr();

            // retrieve packet len first then packet data
            let size = unsafe { std::ptr::read_unaligned::<u16>(ptr as *const u16) };
            let data = unsafe { std::slice::from_raw_parts(ptr.byte_add(2), size.into()) };

            let Ok(pkt) = parse_gossip(&data[20 + 8..]) else {
                monitor.invalid.try_retain(&data, size_hint);
                continue;
            };
            if pkt.sanitize().is_err() {
                monitor.invalid.try_retain(&data, size_hint);
                continue;
            }
            //let ts = SystemTime::now().duration_since(UNIX_EPOCH)?;
            monitor.try_retain(&pkt, &data, size_hint);

            fn set_pos(pb: &ProgressBar, rate_bps: Option<f32>) {
                pb.set_position((rate_bps.unwrap_or_default() / 1e6) as u64);
            }
            if last_report.elapsed() > Duration::from_millis(500) {
                last_report = Instant::now();
                set_pos(&rate_junk, monitor.invalid.rate_bps());
                set_pos(&rate_gossip, monitor.valid.rate_bps());
                set_pos(&rate_votes, monitor.crds_vote.rate_bps());
                set_pos(&rate_prune, monitor.prune.rate_bps());
                set_pos(&rate_contact_info, monitor.crds_contact_info.rate_bps());
                set_pos(&rate_epoch_slots, monitor.crds_epoch_slots.rate_bps());
                set_pos(&rate_node_instance, monitor.crds_node_instance.rate_bps());
                set_pos(&rate_ping, monitor.pingpong.rate_bps());
            }
        }
        guard.clear_ready();
    }
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}
