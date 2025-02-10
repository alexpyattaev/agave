use {
    crate::Stats,
    anyhow::Context,
    serde::Serialize,
    solana_gossip::protocol::Protocol,
    solana_sanitize::Sanitize,
    std::{
        ffi::CStr,
        net::{Ipv4Addr, SocketAddrV4},
        path::PathBuf,
    },
};

pub fn parse_gossip(bytes: &[u8]) -> bincode::Result<Protocol> {
    solana_perf::packet::deserialize_from_with_limit(bytes)
}

pub fn _serialize<T: Serialize>(pkt: T) -> Vec<u8> {
    bincode::serialize(&pkt).unwrap()
}

#[derive(Default)]
pub struct GossipInventory {
    pings: Vec<Box<[u8]>>,
    pongs: Vec<Box<[u8]>>,
    pull_requests: Vec<Box<[u8]>>,
    pull_responses: Vec<Box<[u8]>>,
    push: Vec<Box<[u8]>>,
    prune: Vec<Box<[u8]>>,
}

impl GossipInventory {
    fn try_retain(&mut self, pkt: &Protocol, bytes: &[u8]) -> bool {
        match pkt {
            Protocol::PingMessage(_) => {
                if self.pings.len() < 64 {
                    let bytes = bytes.to_owned().into_boxed_slice();
                    self.pings.push(bytes);

                    return true;
                }
            }
            Protocol::PullRequest(crds_filter, crds_value) => {
                if self.pull_requests.len() < 64 {
                    let bytes = bytes.to_owned().into_boxed_slice();
                    self.pull_requests.push(bytes);

                    return true;
                }
            }
            Protocol::PullResponse(pubkey, crds_values) => {
                if self.pull_responses.len() < 64 {
                    let bytes = bytes.to_owned().into_boxed_slice();
                    self.pull_responses.push(bytes);

                    return true;
                } else {
                    //TODO add CRDS based entropy filtering
                }
            }
            Protocol::PushMessage(pubkey, crds_values) => {
                if self.push.len() < 64 {
                    let bytes = bytes.to_owned().into_boxed_slice();
                    self.push.push(bytes);

                    return true;
                } else {
                    //TODO add CRDS based entropy filtering
                }
            }
            Protocol::PruneMessage(pubkey, prune_data) => {
                if self.prune.len() < 64 {
                    let bytes = bytes.to_owned().into_boxed_slice();
                    self.prune.push(bytes);

                    return true;
                }
            }
            Protocol::PongMessage(pong) => {
                if self.pongs.len() < 64 {
                    let bytes = bytes.to_owned().into_boxed_slice();
                    self.pongs.push(bytes);

                    return true;
                }
            }
        }
        false
    }
    fn dump_to_file(&self, filename: PathBuf) -> anyhow::Result<()> {
        println!("Not saving any files yet!");
        Ok(())
    }
}

pub fn capture_gossip(
    _ifname: &CStr,
    bind_ip: Ipv4Addr,
    port: u16,
    pcap_filename: PathBuf,
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
        if inventory.try_retain(&pkt, slice) {
            stats.retained += 1;
        }
    }
    inventory.dump_to_file(pcap_filename)?;
    Ok(stats)
}
