//! Public handles for the repair QUIC transport.
//!
//! Client and server are separate types on separate endpoints and separate
//! sockets, as in `agave-votor-transport`: the requester's traffic pattern has
//! nothing in common with the server's, and keeping them apart means either can
//! be disabled without touching the other.
use {
    crate::{
        HANDSHAKE_BURST, HANDSHAKE_GLOBAL_RATE, HANDSHAKE_WORKERS_PER_ENDPOINT, KnownPeersReceiver,
        MAX_ENDPOINTS, MAX_INBOUND_CONNECTIONS, MAX_INFLIGHT_HANDSHAKES, MAX_RESPONSES_PER_REQUEST,
        client::ClientLoop,
        error::Error,
        server::{AcceptLoop, ServerLoop, new_event_channel},
        stats::{ClientStats, ServerStats},
        transport::{new_client_config, new_server_config},
    },
    arc_swap::ArcSwap,
    bytes::Bytes,
    crossbeam_channel::{Receiver, Sender, bounded},
    log::{error, warn},
    solana_keypair::{Keypair, Signer},
    solana_net_utils::{SocketAddrSpace, quic_socket::QuicSocket, token_bucket::TokenBucket},
    solana_perf::packet::PacketBatch,
    solana_pubkey::Pubkey,
    solana_tls_utils::NotifyKeyUpdate,
    std::{
        collections::HashSet,
        net::SocketAddr,
        sync::{Arc, Mutex, TryLockError},
        time::Duration,
    },
    tokio::{
        runtime::Handle,
        sync::{mpsc, oneshot, watch},
        task::JoinSet,
        time::{Instant, timeout_at},
    },
    tokio_util::sync::CancellationToken,
};

pub(crate) const ENDPOINT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Outbound requests buffered between the repair threads and the client loop.
const REQUEST_CHANNEL_CAP: usize = 4096;

/// Set of peers the client is currently not dialing, published for the repair
/// threads to consult before choosing a transport.
pub type PeerBackoffView = Arc<ArcSwap<crate::KnownPeers>>;

/// One repair request that arrived over QUIC, with the handle used to answer it.
pub struct InboundRepairRequest {
    /// TLS-attested identity of the requester. This is what replaces repair's
    /// ping/pong address validation, so the serve path must reject any request
    /// whose signed `sender` disagrees with it.
    pub peer_pubkey: Pubkey,
    pub peer_address: SocketAddr,
    pub bytes: Bytes,
    pub responder: Responder,
}

/// Write handle for the stream a request arrived on.
///
/// Dropping it finishes the stream with zero frames, which the requester reads
/// as an empty response - semantically identical to a blockstore miss.
pub struct Responder(oneshot::Sender<Vec<Bytes>>);

impl Responder {
    pub(crate) fn new() -> (Self, oneshot::Receiver<Vec<Bytes>>) {
        let (sender, receiver) = oneshot::channel();
        (Self(sender), receiver)
    }

    /// Answer the request with all of its response payloads at once.
    ///
    /// Non-blocking, and safe to call from a synchronous thread. Payloads
    /// beyond [`MAX_RESPONSES_PER_REQUEST`] are not written.
    pub fn respond(self, payloads: Vec<Bytes>) {
        debug_assert!(
            payloads.len() <= MAX_RESPONSES_PER_REQUEST,
            "a repair request cannot produce more than {MAX_RESPONSES_PER_REQUEST} responses",
        );
        // The receiver is gone only if the stream died, which is not our problem.
        let _ = self.0.send(payloads);
    }
}

/// One repair request to be sent over QUIC.
pub struct OutboundRepairRequest {
    pub peer: Pubkey,
    pub peer_address: SocketAddr,
    pub bytes: Bytes,
    /// Bounds how much the peer may write back on this stream.
    pub num_expected_responses: u8,
    /// Where this exchange's responses go. Carried per request, so the client
    /// needs no demultiplexing: shred repair, ancestor hashes and block-id
    /// repair each pass a clone of their own existing response channel.
    pub responses: Sender<PacketBatch>,
}

/// Inbound half of the transport: accepts connections and hands requests to the
/// repair serve loop.
pub struct RepairQuicServer {
    cancel: CancellationToken,
    /// Spawned event-loop tasks. We must join these so a panic that tokio would
    /// otherwise swallow is surfaced.
    task_handles: JoinSet<()>,
    /// Identity rotation sender kept here so we control when the channel closes.
    key_updater: Arc<KeyUpdateNotifier>,
    ban_sender: BanSender,
    /// Exposed so integration tests can assert on them.
    #[cfg(any(test, feature = "dev-context-only-utils"))]
    pub server_stats: Arc<ServerStats>,
    #[cfg(any(test, feature = "dev-context-only-utils"))]
    runtime_handle: Handle,
}

impl RepairQuicServer {
    /// Spawns the accept and control loops on `runtime`.
    ///
    /// `sockets` back the inbound direction; more than one is only useful with
    /// SO_REUSEPORT, and one is what the validator uses. Requests flow into
    /// `requests`, and `known_peers` gates admission: we only serve peers gossip
    /// has told us about.
    pub fn spawn(
        runtime: &Handle,
        keypair: &Keypair,
        sockets: Vec<QuicSocket>,
        requests: Sender<InboundRepairRequest>,
        known_peers: KnownPeersReceiver,
        socket_addr_space: SocketAddrSpace,
        cancel: CancellationToken,
    ) -> Result<Self, Error> {
        assert!(!sockets.is_empty(), "Must have sockets provided");
        assert!(
            sockets.len() <= MAX_ENDPOINTS,
            "Number of QUIC endpoints must be at most {MAX_ENDPOINTS}"
        );
        let stats = Arc::new(ServerStats::default());
        let (ban_command_sender, ban_commands) = mpsc::channel(BAN_CHANNEL_CAPACITY);
        let ban_sender = BanSender(ban_command_sender);
        let num_listeners = 1;
        let (key_updater, mut listeners) = KeyUpdateNotifier::make_with_listeners(num_listeners);
        let key_updater = Arc::new(key_updater);
        let server_key_updates = listeners.pop().expect("one listener was requested");

        // Queue and rate limits are global budgets split across the endpoints,
        // so the config has to know how many there will be.
        let num_endpoints = sockets.len();
        let server_config = new_server_config(keypair, num_endpoints);
        let endpoints = {
            // Endpoint::new requires the runtime context.
            let _guard = runtime.enter();
            sockets
                .into_iter()
                .map(|socket| {
                    socket
                        .into_endpoint(Some(server_config.clone()))
                        .map_err(Error::Endpoint)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let mut task_handles = JoinSet::new();
        let (events_sender, events_receiver) = new_event_channel();
        // Every budget constant is divided across the accept loops so the
        // aggregate is what the constant says. A zero share would build a
        // zero-capacity TokenBucket, which panics on first use - hence
        // MAX_ENDPOINTS.
        let num_accept_loops = num_endpoints
            .checked_mul(HANDSHAKE_WORKERS_PER_ENDPOINT)
            .expect("HANDSHAKE_WORKERS_PER_ENDPOINT should be small");
        let handshake_burst = HANDSHAKE_BURST
            .checked_div(num_accept_loops as u64)
            .expect("num_accept_loops is nonzero");
        let max_inflight_handshakes = MAX_INFLIGHT_HANDSHAKES
            .checked_div(num_accept_loops)
            .expect("num_accept_loops is nonzero: sockets asserted non-empty, workers const > 0");
        let rate_limiter = TokenBucket::new(
            handshake_burst,
            handshake_burst,
            HANDSHAKE_GLOBAL_RATE as f64 / num_accept_loops as f64,
        );
        for endpoint in &endpoints {
            for _ in 0..HANDSHAKE_WORKERS_PER_ENDPOINT {
                let accept = AcceptLoop::new(
                    endpoint.clone(),
                    events_sender.clone(),
                    stats.clone(),
                    cancel.clone(),
                    socket_addr_space,
                    rate_limiter.clone(),
                    max_inflight_handshakes,
                );
                task_handles.spawn_on(accept.run(), runtime);
            }
        }
        #[cfg(any(test, feature = "dev-context-only-utils"))]
        let server_stats = stats.clone();
        let server = ServerLoop::new(
            requests,
            ban_commands,
            known_peers,
            endpoints,
            events_sender,
            events_receiver,
            server_key_updates,
            stats,
            cancel.clone(),
        );
        task_handles.spawn_on(server.run(), runtime);

        Ok(Self {
            cancel,
            task_handles,
            key_updater,
            ban_sender,
            #[cfg(any(test, feature = "dev-context-only-utils"))]
            server_stats,
            #[cfg(any(test, feature = "dev-context-only-utils"))]
            runtime_handle: runtime.clone(),
        })
    }

    pub fn key_updater(&self) -> Arc<KeyUpdateNotifier> {
        self.key_updater.clone()
    }

    /// Obtain a sender for requesting temporary peer bans.
    pub fn ban_sender(&self) -> BanSender {
        self.ban_sender.clone()
    }

    /// Signal all loops to stop without waiting for them. Idempotent.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// Stops the server and joins all internal tasks.
    pub async fn join(mut self) {
        self.stop_and_join_tasks().await;
    }

    async fn stop_and_join_tasks(&mut self) {
        self.stop();
        join_tasks("RepairQuicServer", &mut self.task_handles).await;
    }
}

// This exists to ensure we are not allowing tokio to silently swallow panics in tests.
#[cfg(any(test, feature = "dev-context-only-utils"))]
impl Drop for RepairQuicServer {
    fn drop(&mut self) {
        // join() was called, or we are already panicking
        if self.task_handles.is_empty() || std::thread::panicking() {
            return;
        }
        if Handle::try_current().is_ok() {
            debug_assert!(false, "RepairQuicServer dropped without calling join()");
            return;
        }
        let handle = self.runtime_handle.clone();
        handle.block_on(self.stop_and_join_tasks());
    }
}

/// Outbound half of the transport: dials peers and runs repair exchanges.
pub struct RepairQuicClient {
    cancel: CancellationToken,
    task_handles: JoinSet<()>,
    key_updater: Arc<KeyUpdateNotifier>,
    requests: mpsc::Sender<OutboundRepairRequest>,
    backoff_view: PeerBackoffView,
    stats: Arc<ClientStats>,
    #[cfg(any(test, feature = "dev-context-only-utils"))]
    runtime_handle: Handle,
}

impl RepairQuicClient {
    pub fn spawn(
        runtime: &Handle,
        keypair: &Keypair,
        socket: QuicSocket,
        cancel: CancellationToken,
    ) -> Result<Self, Error> {
        let stats = Arc::new(ClientStats::default());
        let num_listeners = 1;
        let (key_updater, mut listeners) = KeyUpdateNotifier::make_with_listeners(num_listeners);
        let key_updater = Arc::new(key_updater);
        let client_key_updates = listeners.pop().expect("one listener was requested");
        let (requests, request_receiver) = mpsc::channel(REQUEST_CHANNEL_CAP);
        let backoff_view: PeerBackoffView = Arc::new(ArcSwap::from_pointee(HashSet::default()));

        let mut endpoint = {
            let _guard = runtime.enter();
            socket.into_endpoint(None).map_err(Error::Endpoint)?
        };
        endpoint.set_default_client_config(new_client_config(keypair));

        let mut task_handles = JoinSet::new();
        let client = ClientLoop::new(
            endpoint,
            keypair.pubkey(),
            request_receiver,
            client_key_updates,
            backoff_view.clone(),
            cancel.clone(),
            stats.clone(),
        );
        task_handles.spawn_on(client.run(), runtime);

        Ok(Self {
            cancel,
            task_handles,
            key_updater,
            requests,
            backoff_view,
            stats,
            #[cfg(any(test, feature = "dev-context-only-utils"))]
            runtime_handle: runtime.clone(),
        })
    }

    pub fn key_updater(&self) -> Arc<KeyUpdateNotifier> {
        self.key_updater.clone()
    }

    /// Queue one repair request. Non-blocking and callable from a synchronous
    /// thread; a full queue drops the request, which repair re-requests anyway.
    pub fn try_send(&self, request: OutboundRepairRequest) {
        match self.requests.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                crate::client::record_request_dropped(&self.stats, "request queue full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                crate::client::record_request_dropped(&self.stats, "client loop has exited");
            }
        }
    }

    /// Whether this peer is currently unusable over QUIC and should be repaired
    /// from over UDP instead. Cheap enough to call per request.
    pub fn is_backing_off(&self, peer: &Pubkey) -> bool {
        self.backoff_view.load().contains(peer)
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }

    pub async fn join(mut self) {
        self.stop_and_join_tasks().await;
    }

    async fn stop_and_join_tasks(&mut self) {
        self.stop();
        join_tasks("RepairQuicClient", &mut self.task_handles).await;
    }
}

#[cfg(any(test, feature = "dev-context-only-utils"))]
impl Drop for RepairQuicClient {
    fn drop(&mut self) {
        if self.task_handles.is_empty() || std::thread::panicking() {
            return;
        }
        if Handle::try_current().is_ok() {
            debug_assert!(false, "RepairQuicClient dropped without calling join()");
            return;
        }
        let handle = self.runtime_handle.clone();
        handle.block_on(self.stop_and_join_tasks());
    }
}

/// Join every top-level loop under one shared deadline.
async fn join_tasks(name: &str, task_handles: &mut JoinSet<()>) {
    let deadline = Instant::now()
        .checked_add(ENDPOINT_SHUTDOWN_TIMEOUT)
        .expect("We are adding a small const duration");
    loop {
        match timeout_at(deadline, task_handles.join_next()).await {
            Ok(Some(join_result)) => {
                join_result.expect("endpoint task did not exit cleanly");
            }
            Ok(None) => break,
            Err(_elapsed) => {
                error!("{name} teardown timed out.");
                debug_assert!(false, "repair transport teardown timeout");
                break;
            }
        }
    }
}

/// Create the channel carrying inbound requests to the repair serve loop.
pub fn new_request_channel() -> (Sender<InboundRepairRequest>, Receiver<InboundRepairRequest>) {
    bounded(MAX_INBOUND_CONNECTIONS)
}

pub struct KeyUpdateNotifier {
    sender: watch::Sender<Keypair>,
    ack_sender: crossbeam_channel::Sender<()>,
    /// Every transport loop acknowledges here. Holding the lock ensures only one
    /// update can be in progress at a time.
    acks: Mutex<crossbeam_channel::Receiver<()>>,
}

impl KeyUpdateNotifier {
    /// Builds the notifier together with one listener per transport loop.
    pub(crate) fn make_with_listeners(num_listeners: usize) -> (Self, Vec<KeyUpdateListener>) {
        assert!(num_listeners > 0, "a notifier needs at least one listener");
        // The initial value is never observed.
        let (sender, _receiver) = watch::channel(Keypair::new_from_array([0; 32]));
        // Each loop acknowledges exactly once per update.
        let (ack_sender, acks) = bounded(num_listeners);
        let notifier = Self {
            sender,
            ack_sender,
            acks: Mutex::new(acks),
        };
        let listeners = (0..num_listeners)
            .map(|_| KeyUpdateListener {
                receiver: notifier.sender.subscribe(),
                ack: notifier.ack_sender.clone(),
            })
            .collect();
        (notifier, listeners)
    }
}

impl NotifyKeyUpdate for KeyUpdateNotifier {
    /// Publishes `keypair` to the transport loops and blocks until all have ack'd.
    ///
    /// Rejects the update outright if an update is already in progress.
    fn update_key(&self, keypair: &Keypair) -> Result<(), Box<dyn std::error::Error>> {
        let acks = match self.acks.try_lock() {
            Ok(acks) => acks,
            Err(TryLockError::WouldBlock) => {
                return Err("an identity update is already in progress".into());
            }
            // The validator aborts on panic, so nothing observes a poisoned lock.
            // Never continue here, a stale ack would make the next update return
            // before the transport has adopted it.
            Err(TryLockError::Poisoned(err)) => {
                unreachable!("ack receiver was poisoned while an update was in flight: {err}")
            }
        };
        self.sender
            .send(keypair.insecure_clone())
            .map_err(|_| -> Box<dyn std::error::Error> {
                "repair quic transport has shut down; identity update rejected".into()
            })?;
        for _ in 0..acks
            .capacity()
            .expect("ack channel is bounded to the number of listeners")
        {
            acks.recv()
                .expect("ack channel cannot disconnect while the notifier holds a sender");
        }
        Ok(())
    }
}

/// Bundles key update reception and ACK channels.
/// These should only be constructed by [`KeyUpdateNotifier`].
pub(crate) struct KeyUpdateListener {
    pub(crate) receiver: watch::Receiver<Keypair>,
    pub(crate) ack: crossbeam_channel::Sender<()>,
}

/// Command to temporarily ban a peer.
pub(crate) struct BanCommand {
    pub peer: Pubkey,
    pub duration: Duration,
}

/// Cloneable handle for requesting temporary peer bans on the server.
#[derive(Clone)]
pub struct BanSender(mpsc::Sender<BanCommand>);

/// Ban channel capacity. Sized generously (bans are rare and small) so the
/// channel never drops a ban request.
const BAN_CHANNEL_CAPACITY: usize = 1024;

impl BanSender {
    /// Request that `peer` be banned (which also closes its connection) for
    /// `duration`. Non-blocking: the request is dropped with a warning if the
    /// ban channel is full or was closed.
    pub fn ban(&self, peer: Pubkey, duration: Duration) {
        match self.0.try_send(BanCommand { peer, duration }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("Ban channel full, dropping ban request for peer={peer}");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("Ban channel closed: we must be exiting");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{KnownPeers, PEER_FAILURES_BEFORE_BACKOFF},
        solana_net_utils::sockets::bind_to_localhost_unique,
        std::thread::sleep,
        tokio::runtime::{Builder, Runtime},
    };

    fn make_runtime_for_tests() -> Runtime {
        Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("tokio multi-thread runtime")
    }

    /// Serves every request by echoing the request bytes back `num_responses`
    /// times, so a test can tell an answered exchange from a dropped one.
    struct EchoServer {
        server: RepairQuicServer,
        address: SocketAddr,
        keypair: Keypair,
        requests: Receiver<InboundRepairRequest>,
        known_peers: watch::Sender<Arc<KnownPeers>>,
    }

    impl EchoServer {
        fn spawn(rt: &Runtime, known: &[Pubkey]) -> Self {
            let keypair = Keypair::new();
            let socket = bind_to_localhost_unique().expect("bind server socket");
            let address = socket.local_addr().expect("server local addr");
            let (requests_sender, requests) = new_request_channel();
            let known_peers = watch::Sender::new(Arc::new(known.iter().copied().collect()));
            let server = RepairQuicServer::spawn(
                rt.handle(),
                &keypair,
                vec![QuicSocket::Kernel(socket)],
                requests_sender,
                known_peers.subscribe(),
                SocketAddrSpace::Unspecified,
                CancellationToken::new(),
            )
            .expect("RepairQuicServer::spawn");
            Self {
                server,
                address,
                keypair,
                requests,
                known_peers,
            }
        }

        fn serve_one(&self, num_responses: usize) -> InboundRepairRequest {
            let request = self
                .requests
                .recv_timeout(Duration::from_secs(5))
                .expect("server should receive the request");
            let responses = vec![request.bytes.clone(); num_responses];
            // Take the responder out without moving the request fields the
            // caller wants to assert on.
            let InboundRepairRequest {
                peer_pubkey,
                peer_address,
                bytes,
                responder,
            } = request;
            responder.respond(responses);
            InboundRepairRequest {
                peer_pubkey,
                peer_address,
                bytes,
                responder: Responder::new().0,
            }
        }
    }

    fn spawn_client(rt: &Runtime, keypair: &Keypair) -> RepairQuicClient {
        let socket = bind_to_localhost_unique().expect("bind client socket");
        RepairQuicClient::spawn(
            rt.handle(),
            keypair,
            QuicSocket::Kernel(socket),
            CancellationToken::new(),
        )
        .expect("RepairQuicClient::spawn")
    }

    fn request(
        peer: Pubkey,
        peer_address: SocketAddr,
        num_expected_responses: u8,
        responses: Sender<PacketBatch>,
    ) -> OutboundRepairRequest {
        OutboundRepairRequest {
            peer,
            peer_address,
            bytes: Bytes::from_static(b"repair request"),
            num_expected_responses,
            responses,
        }
    }

    /// The full path: dial, attest both ways, one stream per request, and all
    /// of an `Orphan`-sized response coming back on that one stream.
    #[test]
    fn exchange_round_trip_carries_every_response() {
        let rt = make_runtime_for_tests();
        let client_keypair = Keypair::new();
        let server = EchoServer::spawn(&rt, &[client_keypair.pubkey()]);
        let client = spawn_client(&rt, &client_keypair);

        let (responses_sender, responses) = bounded(4);
        client.try_send(request(
            server.keypair.pubkey(),
            server.address,
            MAX_RESPONSES_PER_REQUEST as u8,
            responses_sender,
        ));

        let served = server.serve_one(MAX_RESPONSES_PER_REQUEST);
        assert_eq!(
            served.peer_pubkey,
            client_keypair.pubkey(),
            "the server must see the TLS-attested identity of the requester",
        );
        assert_eq!(&served.bytes[..], b"repair request");

        let batch = responses
            .recv_timeout(Duration::from_secs(5))
            .expect("responses should come back on the request's own stream");
        assert_eq!(
            batch.len(),
            MAX_RESPONSES_PER_REQUEST,
            "every response of one exchange must arrive in one batch",
        );
        for packet in batch.iter() {
            assert_eq!(
                packet.meta().socket_addr(),
                server.address,
                "responses must be attributed to the peer we asked",
            );
        }
        assert!(
            !client.is_backing_off(&server.keypair.pubkey()),
            "a peer that answered must not be in backoff",
        );

        rt.block_on(client.join());
        rt.block_on(server.server.join());
    }

    /// A peer gossip has not told us about gets no service, and is refused
    /// before it can occupy a connection slot.
    #[test]
    fn unknown_peer_is_refused() {
        let rt = make_runtime_for_tests();
        let client_keypair = Keypair::new();
        let no_known_peers = [];
        let server = EchoServer::spawn(&rt, &no_known_peers);
        let client = spawn_client(&rt, &client_keypair);

        let (responses_sender, responses) = bounded(4);
        client.try_send(request(
            server.keypair.pubkey(),
            server.address,
            1,
            responses_sender,
        ));

        assert!(
            server
                .requests
                .recv_timeout(Duration::from_secs(2))
                .is_err(),
            "an unknown peer's request must never reach the serve loop",
        );
        assert!(
            responses.recv_timeout(Duration::from_millis(100)).is_err(),
            "a refused peer must not produce responses",
        );
        // Admitting the peer makes the very next request work, which is what
        // makes a gossip partition recoverable rather than sticky.
        server
            .known_peers
            .send(Arc::new([client_keypair.pubkey()].into_iter().collect()))
            .expect("known-peers receiver alive");
        let (responses_sender, responses) = bounded(4);
        client.try_send(request(
            server.keypair.pubkey(),
            server.address,
            1,
            responses_sender,
        ));
        server.serve_one(1);
        assert_eq!(
            responses
                .recv_timeout(Duration::from_secs(5))
                .expect("an admitted peer must be served")
                .len(),
            1
        );

        rt.block_on(client.join());
        rt.block_on(server.server.join());
    }

    /// Dialing a pubkey that the server cannot prove it holds must fail, and
    /// repeated failures must park the peer so the caller falls back to UDP.
    #[test]
    fn wrong_attested_identity_is_rejected_then_backed_off() {
        let rt = make_runtime_for_tests();
        let client_keypair = Keypair::new();
        let server = EchoServer::spawn(&rt, &[client_keypair.pubkey()]);
        let client = spawn_client(&rt, &client_keypair);
        let impostor = Keypair::new().pubkey();

        for _ in 0..PEER_FAILURES_BEFORE_BACKOFF {
            let (responses_sender, _responses) = bounded(4);
            client.try_send(request(impostor, server.address, 1, responses_sender));
            // Each attempt has to resolve before the next one counts.
            sleep(Duration::from_millis(200));
        }
        assert!(
            server
                .requests
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "a connection to the wrong identity must never carry a request",
        );
        assert!(
            client.is_backing_off(&impostor),
            "a peer that keeps failing must be parked so repair falls back to UDP",
        );

        rt.block_on(client.join());
        rt.block_on(server.server.join());
    }
}
