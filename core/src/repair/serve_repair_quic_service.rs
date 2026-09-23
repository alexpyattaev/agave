//! Serves repair requests that arrive over QUIC.
//!
//! Deliberately a separate loop from [`crate::repair::serve_repair_service`]:
//! the UDP path is built around a blocking batch receive and its own ping/pong
//! address validation, neither of which applies here. Requests arrive already
//! attested by the TLS handshake, one per bidirectional stream, and the
//! responses go back on the stream they came from.

use {
    crate::repair::serve_repair::{ServeRepair, ServeRepairStats},
    agave_repair_transport::{
        KnownPeers, KnownPeersSender,
        endpoint::{InboundRepairRequest, RepairQuicServer},
    },
    bytes::Bytes,
    crossbeam_channel::{Receiver, RecvTimeoutError},
    log::error,
    solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    solana_net_utils::SocketAddrSpace,
    solana_packet::Meta,
    solana_perf::packet::BytesPacket,
    std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::runtime::Handle,
};

/// How often the set of pubkeys we are willing to serve is refreshed from
/// gossip. Admission is membership only, so a stale snapshot merely delays
/// serving a node that just joined.
const KNOWN_PEERS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

const STATS_REPORT_INTERVAL: Duration = Duration::from_secs(2);

/// How long the serve loop blocks waiting for a request before checking `exit`.
const RECV_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct ServeRepairQuicService {
    thread_hdls: Vec<JoinHandle<()>>,
    server: RepairQuicServer,
    runtime: Handle,
}

impl ServeRepairQuicService {
    pub(crate) fn new(
        serve_repair: ServeRepair,
        server: RepairQuicServer,
        requests: Receiver<InboundRepairRequest>,
        known_peers_sender: KnownPeersSender,
        cluster_info: Arc<ClusterInfo>,
        socket_addr_space: SocketAddrSpace,
        runtime: Handle,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let t_serve =
            Self::spawn_serve_loop(serve_repair, requests, socket_addr_space, exit.clone());
        let t_known_peers = Self::spawn_known_peers_loop(cluster_info, known_peers_sender, exit);
        Self {
            thread_hdls: vec![t_serve, t_known_peers],
            server,
            runtime,
        }
    }

    fn spawn_serve_loop(
        serve_repair: ServeRepair,
        requests: Receiver<InboundRepairRequest>,
        socket_addr_space: SocketAddrSpace,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        Builder::new()
            .name("solSrvRepQuic".to_string())
            .spawn(move || {
                let mut stats = ServeRepairStats::default();
                let mut last_report = Instant::now();
                while !exit.load(Ordering::Relaxed) {
                    match requests.recv_timeout(RECV_TIMEOUT) {
                        Ok(request) => Self::serve_request(
                            &serve_repair,
                            &socket_addr_space,
                            &mut stats,
                            request,
                        ),
                        Err(RecvTimeoutError::Timeout) => (),
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    if last_report.elapsed() > STATS_REPORT_INTERVAL {
                        serve_repair.report_reset_stats(&mut stats);
                        last_report = Instant::now();
                    }
                }
            })
            .expect("spawning the QUIC repair serve loop must succeed")
    }

    fn serve_request(
        serve_repair: &ServeRepair,
        socket_addr_space: &SocketAddrSpace,
        stats: &mut ServeRepairStats,
        request: InboundRepairRequest,
    ) {
        let InboundRepairRequest {
            peer_pubkey,
            peer_address,
            bytes,
            responder,
        } = request;
        let mut meta = Meta::default();
        meta.size = bytes.len();
        meta.set_socket_addr(&peer_address);
        meta.set_remote_pubkey(peer_pubkey);
        let packet = BytesPacket::new(bytes, meta);
        let Some(response) = serve_repair.handle_quic_request(packet, socket_addr_space, stats)
        else {
            // Dropping the responder finishes the stream with no frames, which
            // the requester sees the same way it sees a blockstore miss.
            return;
        };
        let payloads: Vec<Bytes> = response
            .iter()
            .filter(|packet| !packet.meta().discard())
            .map(|packet| packet.to_bytes_packet().buffer().clone())
            .collect();
        responder.respond(payloads);
    }

    fn spawn_known_peers_loop(
        cluster_info: Arc<ClusterInfo>,
        known_peers_sender: KnownPeersSender,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        Builder::new()
            .name("solRepQuicPeers".to_string())
            .spawn(move || {
                while !exit.load(Ordering::Relaxed) {
                    let peers: KnownPeers = cluster_info
                        .tvu_peers(|node: &ContactInfo| *node.pubkey())
                        .into_iter()
                        .collect();
                    if known_peers_sender.send(Arc::new(peers)).is_err() {
                        error!("repair QUIC server is gone, stopping known peers refresh");
                        break;
                    }
                    thread::sleep(KNOWN_PEERS_REFRESH_INTERVAL);
                }
            })
            .expect("spawning the QUIC repair known peers loop must succeed")
    }

    pub(crate) fn join(self) -> thread::Result<()> {
        self.server.stop();
        self.thread_hdls
            .into_iter()
            .try_for_each(JoinHandle::join)?;
        self.runtime.block_on(self.server.join());
        Ok(())
    }
}
