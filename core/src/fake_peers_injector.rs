use {
    solana_gossip::{
        cluster_info::ClusterInfo,
        contact_info::{ContactInfo, Protocol},
        crds::GossipRoute,
        crds_data::CrdsData,
        crds_value::CrdsValue,
    },
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    solana_time_utils::timestamp,
    std::{
        collections::HashMap,
        net::{IpAddr, SocketAddr},
        path::PathBuf,
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(15);

#[derive(serde::Deserialize)]
struct PeerEntry {
    keypair: Vec<u8>,
    stake_lamports: u64,
    ip: IpAddr,
    base_port: u16,
}

#[derive(serde::Deserialize)]
struct FakePeersFile {
    peers: Vec<PeerEntry>,
}

pub struct FakePeersInjector {
    thread: JoinHandle<()>,
}

impl FakePeersInjector {
    pub fn new(
        path: PathBuf,
        cluster_info: Arc<ClusterInfo>,
        extra_staked_nodes: Arc<RwLock<HashMap<Pubkey, u64>>>,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let thread = Builder::new()
            .name("solFakePeers".to_string())
            .spawn(move || {
                while !exit.load(Ordering::Relaxed) {
                    Self::inject(&path, &cluster_info, &extra_staked_nodes);
                    thread::sleep(REFRESH_INTERVAL);
                }
            })
            .expect("spawn fake-peers thread");
        Self { thread }
    }

    fn inject(
        path: &PathBuf,
        cluster_info: &Arc<ClusterInfo>,
        extra_staked_nodes: &Arc<RwLock<HashMap<Pubkey, u64>>>,
    ) {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                warn!("fake-peers: could not read {path:?}: {e}");
                return;
            }
        };
        let file: FakePeersFile = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(e) => {
                warn!("fake-peers: parse error in {path:?}: {e}");
                return;
            }
        };
        let shred_version = cluster_info.my_shred_version();
        let now = timestamp();
        let mut new_stakes = HashMap::with_capacity(file.peers.len());
        let mut crds = cluster_info.gossip.crds.write().unwrap();
        for peer in &file.peers {
            let keypair = match Keypair::try_from(peer.keypair.as_slice()) {
                Ok(k) => k,
                Err(e) => {
                    warn!("fake-peers: bad keypair bytes, skipping: {e}");
                    continue;
                }
            };
            let pubkey = keypair.pubkey();
            let mut ci = ContactInfo::new(pubkey, now, shred_version);
            let ip = peer.ip;
            let p = peer.base_port;
            // Port offsets from ContactInfo::new_with_socketaddr convention.
            let _ = ci.set_gossip(SocketAddr::new(ip, p + 1));
            let _ = ci.set_tvu(Protocol::UDP, SocketAddr::new(ip, p + 2));
            let _ = ci.set_tvu(Protocol::QUIC, SocketAddr::new(ip, p + 3));
            let _ = ci.set_serve_repair(Protocol::QUIC, SocketAddr::new(ip, p + 4));
            let _ = ci.set_tpu(Protocol::QUIC, SocketAddr::new(ip, p + 6));
            let _ = ci.set_tpu_vote(Protocol::UDP, SocketAddr::new(ip, p + 7));
            let _ = ci.set_serve_repair(Protocol::UDP, SocketAddr::new(ip, p + 8));
            let _ = ci.set_tpu_vote(Protocol::QUIC, SocketAddr::new(ip, p + 9));
            let _ = ci.set_tpu_forwards(Protocol::QUIC, SocketAddr::new(ip, p + 11));
            let _ = ci.set_rpc(SocketAddr::new(ip, 8899));
            let val = CrdsValue::new(CrdsData::ContactInfo(ci), &keypair);
            if let Err(e) = crds.insert(val, now, GossipRoute::LocalMessage) {
                trace!("fake-peers: crds insert {pubkey}: {e:?}");
            }
            new_stakes.insert(pubkey, peer.stake_lamports);
        }
        drop(crds);
        *extra_staked_nodes.write().unwrap() = new_stakes;
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread.join()
    }
}
