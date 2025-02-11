use {
    crate::{pcap::WritePackets, Stats},
    anyhow::Context,
    pcap_file::pcapng::PcapNgWriter,
    serde::Serialize,
    solana_gossip::{crds_data::CrdsData, crds_value::CrdsValue, protocol::Protocol},
    solana_sanitize::Sanitize,
    std::{
        ffi::CStr,
        fs::File,
        net::{Ipv4Addr, SocketAddrV4},
        path::PathBuf,
    },
    strum::EnumCount,
};

pub fn parse_gossip(bytes: &[u8]) -> bincode::Result<Protocol> {
    solana_perf::packet::deserialize_from_with_limit(bytes)
}

pub fn _serialize<T: Serialize>(pkt: T) -> Vec<u8> {
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
    fn write_packets<W: std::io::Write>(&self, writer: &mut PcapNgWriter<W>) -> anyhow::Result<()> {
        for p in self.packets.iter() {
            crate::pcap::write_packet(&p, writer)?
        }
        Ok(())
    }
}

#[derive(Default)]
struct DumbStorage(Vec<Box<[u8]>>);

impl DumbStorage {
    fn try_retain(&mut self, bytes: &[u8], size: usize) -> bool {
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
    fn write_packets<W: std::io::Write>(&self, writer: &mut PcapNgWriter<W>) -> anyhow::Result<()> {
        for p in self.0.iter() {
            crate::pcap::write_packet(&p, writer)?
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
        store: &impl WritePackets,
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
    fn dump_to_files(&self, filename: PathBuf) -> anyhow::Result<()> {
        macro_rules! write_thing {
            ($name:ident) => {
                Self::write_file(
                    &self.$name,
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
    // TODO: switch to AF-packet eventually
    //let iface = rscap::Interface::new(ifname).expect("Interface bond0 should exist");
    let socket = rscap::linux::l4::L4Socket::new(rscap::linux::l4::L4Protocol::Udp)
        .context("L4 socket creation")?;
    socket
        .bind(&SocketAddrV4::new(bind_ip, port))
        .context("bind should not fail")?;
    /*let socket = rscap::Sniffer::new_with_size(iface, 524288 * 4).expect("Sniffer should get made");
    let i: rscap::filter::BpfInstruction;
    let filter = vec![];
    let filter = rscap::filter::PacketFilter::from_vec(filter);
    socket.activate(filter);*/
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
