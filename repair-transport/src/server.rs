//! Inbound (server) direction: we accept connections and serve repair requests.
use {
    crate::{
        CONN_EVENT_CHANNEL_CAP, GLOBAL_RATE_BYTES_PER_SECOND, GLOBAL_RATE_CAP_WINDOW,
        HANDSHAKE_TIMEOUT, KnownPeersReceiver, MAX_REQUEST_BYTES, MAX_UNSTAKED_INBOUND_CONNECTIONS,
        METRICS_INTERVAL, MIN_STREAM_COST, PEER_RATE_BYTES_PER_SECOND, PEER_RATE_CAP_WINDOW,
        REQUEST_READ_TIMEOUT, RESPONSE_TIMEOUT, UNSTAKED_GLOBAL_HEADROOM_DIVISOR, close_codes,
        endpoint::{BanCommand, InboundRepairRequest, KeyUpdateListener, Responder},
        error::{Error, stream_codes},
        framing::encode_responses,
        stats::{self, ServerStats, record_server_error},
        transport::new_server_config,
    },
    arc_swap::ArcSwap,
    bytes::Bytes,
    crossbeam_channel::{Sender, TrySendError},
    log::{debug, error, info},
    quinn::{Connecting, Connection, Endpoint, RecvStream, SendStream},
    solana_keypair::Signer,
    solana_net_utils::{SocketAddrSpace, banlist::Banlist, token_bucket::TokenBucket},
    solana_pubkey::{Pubkey, PubkeyHasherBuilder},
    solana_tls_utils::get_remote_pubkey,
    std::{
        collections::{HashMap, hash_map::Entry},
        net::{IpAddr, SocketAddr},
        sync::{Arc, atomic::Ordering},
        time::Duration,
    },
    tokio::{
        sync::mpsc,
        task::JoinSet,
        time::{Instant, MissedTickBehavior, interval, sleep, timeout},
    },
    tokio_util::sync::CancellationToken,
};

/// Capacity of a bucket refilling at `rate` bytes per second that may bank up
/// to `window` worth of refill, never less than two minimum-cost streams.
fn bucket_capacity(rate: u64, window: Duration) -> u64 {
    ((rate as f64 * window.as_secs_f64()).ceil() as u64).max(MIN_STREAM_COST.saturating_mul(2))
}

/// A peer's byte budget together with the stake class it was sized for.
///
/// A bucket's refill rate is fixed at construction, so when the peer's stake
/// changes the whole budget is swapped, carrying the remaining tokens over.
pub(crate) struct PeerBudget {
    bucket: TokenBucket,
    /// Refill rate, in bytes per second.
    rate: u64,
    /// Bucket capacity, in bytes.
    cap: u64,
    staked: bool,
}

impl PeerBudget {
    /// Rate and class for `stake` out of `total_stake`. Unstaked peers get the
    /// flat per-peer rate; staked peers get their stake share of the global
    /// rate, never less than an unstaked peer.
    fn rate_for(stake: u64, total_stake: u64) -> (u64, bool) {
        if stake == 0 || total_stake == 0 {
            return (PEER_RATE_BYTES_PER_SECOND, false);
        }
        let share = u128::from(GLOBAL_RATE_BYTES_PER_SECOND)
            .saturating_mul(u128::from(stake))
            .checked_div(u128::from(total_stake))
            .expect("total_stake is nonzero");
        let rate = u64::try_from(share)
            .unwrap_or(u64::MAX)
            .max(PEER_RATE_BYTES_PER_SECOND);
        (rate, true)
    }

    fn new(stake: u64, total_stake: u64, carried_tokens: Option<u64>) -> Self {
        let (rate, staked) = Self::rate_for(stake, total_stake);
        // The bucket starts full and refills at the sustained rate, so its
        // capacity is both the burst a peer may bank while idle and, since the
        // entry outlives the connection, the most a reconnect can recover.
        let cap = bucket_capacity(rate, PEER_RATE_CAP_WINDOW);
        let initial = carried_tokens.map_or(cap, |tokens| tokens.min(cap));
        Self {
            bucket: TokenBucket::new(initial, cap, rate as f64),
            rate,
            cap,
            staked,
        }
    }

    fn sized_for(&self, stake: u64, total_stake: u64) -> bool {
        Self::rate_for(stake, total_stake) == (self.rate, self.staked)
    }
}

/// Everything we track about one peer that is independent of its connection.
///
/// The budget deliberately outlives the connection: if it were created on
/// admission, a peer that drained its budget could reconnect for a free refill.
pub(crate) struct PeerEntry {
    /// At most one connection per peer; a redial replaces it.
    connection: Option<Connection>,
    budget: Arc<ArcSwap<PeerBudget>>,
}

impl PeerEntry {
    /// Resize the budget if the peer's stake moved it to a different rate.
    fn refresh_budget(&self, stake: u64, total_stake: u64) {
        let current = self.budget.load();
        if !current.sized_for(stake, total_stake) {
            let carried = current.bucket.current_tokens();
            self.budget
                .store(Arc::new(PeerBudget::new(stake, total_stake, Some(carried))));
        }
    }
}

/// The server-wide byte budget shared by every connection.
pub(crate) struct GlobalBudget {
    bucket: TokenBucket,
    /// Tokens that must remain in `bucket` before an unstaked peer is served.
    unstaked_floor: u64,
}

impl GlobalBudget {
    fn new() -> Self {
        let cap = bucket_capacity(GLOBAL_RATE_BYTES_PER_SECOND, GLOBAL_RATE_CAP_WINDOW);
        let unstaked_floor = (cap / UNSTAKED_GLOBAL_HEADROOM_DIVISOR).max(MIN_STREAM_COST);
        Self {
            bucket: TokenBucket::new(cap, cap, GLOBAL_RATE_BYTES_PER_SECOND as f64),
            unstaked_floor,
        }
    }
}

/// Event reported to the [`ServerLoop`].
pub(crate) enum InboundConnectionEvent {
    /// A TLS handshake completed and yielded a valid, authenticated peer.
    Accepted {
        peer: Pubkey,
        connection: Connection,
    },
    /// An inbound connection terminated.
    Closed { peer: Pubkey, stable_id: usize },
}

fn is_invalid_remote_address(
    remote_addr: SocketAddr,
    local_ip: Option<IpAddr>,
    socket_addr_space: SocketAddrSpace,
) -> bool {
    remote_addr.is_ipv6()
        || remote_addr.ip().is_multicast()
        || (matches!(socket_addr_space, SocketAddrSpace::Global)
            && local_ip == Some(remote_addr.ip()))
        || !socket_addr_space.check(&remote_addr)
}

/// AcceptLoop pulls connection attempts off its endpoint, runs the server
/// side of the TLS handshake, then spawns a task that awaits the client's reply.
/// This coarsely bounds the number of cores that can be dedicated
/// to handshake work to the number of accept loops.
pub(crate) struct AcceptLoop {
    endpoint: Endpoint,
    events_sender: mpsc::Sender<InboundConnectionEvent>,
    stats: Arc<ServerStats>,
    cancel: CancellationToken,
    socket_addr_space: SocketAddrSpace,
    /// Paces how fast this endpoint *starts* handshakes.
    handshake_rate_limiter: TokenBucket,
    /// Bounds the number of in-flight handshakes for this endpoint.
    max_inflight_handshakes: usize,
}

impl AcceptLoop {
    pub(crate) fn new(
        endpoint: Endpoint,
        events_sender: mpsc::Sender<InboundConnectionEvent>,
        stats: Arc<ServerStats>,
        cancel: CancellationToken,
        socket_addr_space: SocketAddrSpace,
        handshake_rate_limiter: TokenBucket,
        max_inflight_handshakes: usize,
    ) -> Self {
        Self {
            endpoint,
            events_sender,
            stats,
            cancel,
            socket_addr_space,
            handshake_rate_limiter,
            max_inflight_handshakes,
        }
    }

    pub(crate) async fn run(self) {
        let Self {
            endpoint,
            events_sender,
            stats,
            cancel,
            socket_addr_space,
            handshake_rate_limiter,
            max_inflight_handshakes,
        } = self;

        // Timer to reopen the admission of Incoming from Endpoint after limiter was exhausted.
        let mut accept_gate = Box::pin(sleep(Duration::ZERO));
        let mut rate_limited = false;

        // In-flight handshake tasks. We use this to be notified whenever any of the
        // per-peer admission tasks complete and to track total count.
        let mut handshakes = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                // Handshake task finished: this potentially reopens the accept arm below.
                Some(joined) = handshakes.join_next(), if !handshakes.is_empty() => {
                    joined.expect("AcceptLoop: handshake task panicked");
                }
                _ = &mut accept_gate, if rate_limited => {
                    rate_limited = false;
                }
                // Pull the next attempt only while the rate limit allows and we
                // have a free handshake task slot. We never call `accept()` faster
                // than the limiter permits, nor run more than `max_inflight_handshakes`
                // handshakes at once.
                incoming = endpoint.accept(),
                    if !rate_limited && handshakes.len() < max_inflight_handshakes =>
                {
                    let Some(incoming) = incoming else {
                        info!("Repair accept loop exiting: endpoint closed.");
                        break;
                    };
                    // We always serve the attempt we already pulled, but we close
                    // the accept gate if we do not have tokens to serve the next one.
                    rate_limited = match handshake_rate_limiter.consume_tokens(1) {
                        Ok(0) => true,
                        Ok(_) => false,
                        Err(_) => {
                            debug_assert!(false, "AcceptLoop woke up too early");
                            true
                        },
                    };
                    if rate_limited {
                        let wait_us = handshake_rate_limiter
                            .us_to_have_tokens(1)
                            .expect("bucket capacity > 1")
                            .saturating_add(1);
                        let deadline = Instant::now()
                            .checked_add(Duration::from_micros(wait_us))
                            .expect("accept-gate deadline should never overflow");
                        accept_gate.as_mut().reset(deadline);
                        stats.handshake_rate_limited.fetch_add(1, Ordering::Relaxed);
                    }
                    let remote_addr = incoming.remote_address();
                    debug!("Incoming repair connection from {remote_addr}.");
                    if is_invalid_remote_address(
                        remote_addr,
                        incoming.local_ip(),
                        socket_addr_space,
                    ) {
                        incoming.ignore();
                        continue;
                    }
                    // Run the server side of the handshake (CPU-bound crypto).
                    let connecting = match incoming.accept() {
                        Ok(connecting) => connecting,
                        Err(e) => {
                            record_server_error(&Error::from(e), &stats);
                            continue;
                        }
                    };
                    stats.handshakes_started.fetch_add(1, Ordering::Relaxed);
                    // Track the spawned task so the accept guard's `handshakes.len()`
                    // check bounds the in-flight handshakes.
                    handshakes.spawn(wait_for_complete_handshake(
                        connecting,
                        events_sender.clone(),
                        stats.clone(),
                    ));
                }
            }
        }
    }
}

/// Wait for an inbound TLS handshake to complete. This mostly just
/// awaits the client's reply (network-bound), and enforces handshake timeouts.
async fn wait_for_complete_handshake(
    connecting: Connecting,
    events_sender: mpsc::Sender<InboundConnectionEvent>,
    stats: Arc<ServerStats>,
) {
    let connection = match timeout(HANDSHAKE_TIMEOUT, connecting).await {
        Ok(Ok(connection)) => {
            stats.handshakes_completed.fetch_add(1, Ordering::Relaxed);
            connection
        }
        Ok(Err(e)) => {
            record_server_error(&Error::from(e), &stats);
            return;
        }
        Err(_elapsed) => {
            stats.handshake_timed_out.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let remote_addr = connection.remote_address();
    let Some(peer) = get_remote_pubkey(&connection) else {
        close_codes::INVALID_IDENTITY.close(&connection);
        record_server_error(&Error::InvalidIdentity(remote_addr), &stats);
        return;
    };
    let _ = events_sender
        .send(InboundConnectionEvent::Accepted { peer, connection })
        .await;
}

/// Serve one request/response exchange on a freshly accepted bidirectional stream.
///
/// Response bytes are charged to the peer's budget here, which is the whole
/// reason no cost model has to be threaded into the repair service: on a bidi
/// stream the transport sees exactly what the request cost to serve.
async fn serve_stream(
    peer: Pubkey,
    remote_addr: SocketAddr,
    mut send: SendStream,
    mut recv: RecvStream,
    requests: Sender<InboundRepairRequest>,
    budget: Arc<PeerBudget>,
    global: Arc<GlobalBudget>,
    stats: Arc<ServerStats>,
) {
    let request = match timeout(REQUEST_READ_TIMEOUT, recv.read_to_end(MAX_REQUEST_BYTES)).await {
        Ok(Ok(bytes)) if !bytes.is_empty() => Bytes::from(bytes),
        _ => {
            stats.request_read_failed.fetch_add(1, Ordering::Relaxed);
            let _ = send.reset(stream_codes::BAD_REQUEST);
            return;
        }
    };
    let (responder, responses) = Responder::new();
    let request = InboundRepairRequest {
        peer_pubkey: peer,
        peer_address: remote_addr,
        bytes: request,
        responder,
    };
    match requests.try_send(request) {
        Ok(()) => {
            stats.requests_received.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Full(_)) => {
            stats
                .requests_dropped_channel_full
                .fetch_add(1, Ordering::Relaxed);
            let _ = send.reset(stream_codes::OVERLOADED);
            return;
        }
        Err(TrySendError::Disconnected(_)) => {
            debug!("repair serve channel disconnected; dropping request from {peer}");
            let _ = send.reset(stream_codes::OVERLOADED);
            return;
        }
    }
    // A dropped responder resolves to an empty response, which the requester
    // reads as a blockstore miss - the same thing UDP repair does by staying silent.
    let payloads = match timeout(RESPONSE_TIMEOUT, responses).await {
        Ok(Ok(payloads)) => payloads,
        Ok(Err(_)) | Err(_) => Vec::new(),
    };
    let mut chunks = encode_responses(&payloads);
    let response_bytes: usize = chunks.iter().map(Bytes::len).sum();
    budget
        .bucket
        .consume_tokens_saturating(response_bytes as u64);
    global
        .bucket
        .consume_tokens_saturating(response_bytes as u64);
    if !chunks.is_empty() && send.write_all_chunks(&mut chunks).await.is_err() {
        return;
    }
    stats
        .responses_sent
        .fetch_add(payloads.len() as u64, Ordering::Relaxed);
    stats
        .response_bytes_sent
        .fetch_add(response_bytes as u64, Ordering::Relaxed);
    let _ = send.finish();
}

/// How long a connection must stop accepting streams, or `None` if it may
/// take another one.
///
/// Staked peers may drain the global budget down to one stream's worth;
/// unstaked peers stop at `unstaked_floor`, so they only ever consume what
/// staked peers left unused. `stable_id` spreads out the wake-ups of
/// connections throttled on the shared bucket.
fn throttle_for(
    budget: &PeerBudget,
    global: &GlobalBudget,
    stable_id: usize,
    stats: &ServerStats,
) -> Option<Duration> {
    let peer_wait_us = (budget.bucket.current_tokens() < MIN_STREAM_COST).then(|| {
        stats.peer_rate_limited.fetch_add(1, Ordering::Relaxed);
        budget
            .bucket
            .us_to_have_tokens(MIN_STREAM_COST)
            .expect("peer bucket capacity exceeds the per-stream floor")
    });
    let global_floor = if budget.staked {
        MIN_STREAM_COST
    } else {
        global.unstaked_floor
    };
    let global_wait_us = (global.bucket.current_tokens() < global_floor).then(|| {
        let counter = if budget.staked {
            &stats.global_rate_limited_staked
        } else {
            &stats.global_rate_limited_unstaked
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let wait_us = global
            .bucket
            .us_to_have_tokens(global_floor)
            .expect("global bucket capacity exceeds the unstaked floor");
        // Up to 10% jitter, so connections parked on the shared bucket do not
        // all wake on the same tick.
        let jitter_percent = (stable_id % 10) as u64;
        wait_us.saturating_add(wait_us.saturating_mul(jitter_percent) / 100)
    });
    peer_wait_us
        .max(global_wait_us)
        .map(|wait_us| Duration::from_micros(wait_us.saturating_add(1)))
}

fn read_gate_deadline(wait: Duration) -> Instant {
    Instant::now()
        .checked_add(wait)
        .expect("read-gate deadline should never overflow")
}

/// Per-connection accept loop for an admitted inbound connection.
pub(crate) struct ConnectionServer {
    connection: Connection,
    peer: Pubkey,
    remote_addr: SocketAddr,
    requests: Sender<InboundRepairRequest>,
    budget: Arc<ArcSwap<PeerBudget>>,
    global: Arc<GlobalBudget>,
    events_sender: mpsc::Sender<InboundConnectionEvent>,
    stats: Arc<ServerStats>,
    cancel: CancellationToken,
}

impl ConnectionServer {
    async fn run(self) {
        let Self {
            connection,
            peer,
            remote_addr,
            requests,
            budget,
            global,
            events_sender,
            stats,
            cancel,
        } = self;
        let stable_id = connection.stable_id();
        let mut streams = JoinSet::new();
        // Closed while the peer, or the server as a whole, is over budget. We
        // simply stop calling `accept_bi`, and QUIC's own MAX_STREAMS flow
        // control applies the backpressure for us: no close, no ban, and the
        // peer recovers with no state change once the buckets refill. Starts
        // closed so the first stream is gated like every other one.
        let mut read_gate = Box::pin(sleep(Duration::ZERO));
        let mut throttled = true;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                Some(joined) = streams.join_next(), if !streams.is_empty() => {
                    joined.expect("ConnectionServer: stream task panicked");
                }
                _ = &mut read_gate, if throttled => {
                    match throttle_for(&budget.load(), &global, stable_id, &stats) {
                        Some(wait) => read_gate.as_mut().reset(read_gate_deadline(wait)),
                        None => throttled = false,
                    }
                }
                stream = connection.accept_bi(), if !throttled => {
                    let (send, recv) = match stream {
                        Ok(stream) => stream,
                        Err(e) => {
                            record_server_error(&Error::from(e), &stats);
                            break;
                        }
                    };
                    // Charge the admission floor for the stream we just took, so a
                    // peer that opens streams and writes nothing still drains its
                    // own budget, and the server's.
                    let budget = budget.load_full();
                    budget.bucket.consume_tokens_saturating(MIN_STREAM_COST);
                    global.bucket.consume_tokens_saturating(MIN_STREAM_COST);
                    if let Some(wait) = throttle_for(&budget, &global, stable_id, &stats) {
                        throttled = true;
                        read_gate.as_mut().reset(read_gate_deadline(wait));
                    }
                    streams.spawn(serve_stream(
                        peer,
                        remote_addr,
                        send,
                        recv,
                        requests.clone(),
                        budget,
                        global.clone(),
                        stats.clone(),
                    ));
                }
            }
        }
        // Tell the control loop this connection died. In-flight stream tasks are
        // aborted by dropping the JoinSet: their peer is gone either way.
        let _ = events_sender
            .send(InboundConnectionEvent::Closed { peer, stable_id })
            .await;
    }
}

/// Inbound control loop: owns the connection table and registers authenticated
/// connections handed over by [`AcceptLoop`].
pub(crate) struct ServerLoop {
    requests: Sender<InboundRepairRequest>,
    /// Temporary per-peer banlist.
    banlist: Banlist<Pubkey>,
    /// Inbound ban commands `(peer, duration)`.
    ban_receiver: mpsc::Receiver<BanCommand>,
    /// Pubkeys gossip knows about; admission requires membership.
    known_peers: KnownPeersReceiver,
    /// Identity-rotation notification channel.
    key_updates: KeyUpdateListener,
    /// Endpoints that handle connections. On identity rotation we need to
    /// configure them with the updated TLS config.
    endpoints: Vec<Endpoint>,
    peer_state: HashMap<Pubkey, PeerEntry, PubkeyHasherBuilder>,
    connection_tasks: JoinSet<()>,
    events_sender: mpsc::Sender<InboundConnectionEvent>,
    events_receiver: mpsc::Receiver<InboundConnectionEvent>,
    stats: Arc<ServerStats>,
    cancel: CancellationToken,
    global: Arc<GlobalBudget>,
}

impl ServerLoop {
    pub(crate) fn new(
        requests: Sender<InboundRepairRequest>,
        ban_receiver: mpsc::Receiver<BanCommand>,
        known_peers: KnownPeersReceiver,
        endpoints: Vec<Endpoint>,
        events_sender: mpsc::Sender<InboundConnectionEvent>,
        events_receiver: mpsc::Receiver<InboundConnectionEvent>,
        key_updates: KeyUpdateListener,
        stats: Arc<ServerStats>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            requests,
            banlist: Banlist::default(),
            ban_receiver,
            known_peers,
            key_updates,
            endpoints,
            peer_state: HashMap::with_hasher(PubkeyHasherBuilder::default()),
            connection_tasks: JoinSet::new(),
            events_sender,
            events_receiver,
            stats,
            cancel,
            global: Arc::new(GlobalBudget::new()),
        }
    }

    /// Counts the peers from which we currently hold a connection, as
    /// `(staked, unstaked)`.
    fn connected_peers(&self) -> (u64, u64) {
        self.peer_state
            .values()
            .filter(|entry| entry.connection.is_some())
            .fold((0, 0), |(staked, unstaked), entry| {
                if entry.budget.load().staked {
                    (staked.saturating_add(1), unstaked)
                } else {
                    (staked, unstaked.saturating_add(1))
                }
            })
    }

    pub(crate) async fn run(mut self) {
        let mut metrics = interval(METRICS_INTERVAL);
        metrics.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut known_peers = self.known_peers.clone();
        let mut identity_receiver = self.key_updates.receiver.clone();

        info!("Repair QUIC transport server ready.");
        loop {
            tokio::select! {
                Some(event) = self.events_receiver.recv() => self.handle_event(event),
                maybe_ban = self.ban_receiver.recv() => {
                    let Some(BanCommand { peer, duration }) = maybe_ban else {
                        error!("ServerLoop: ban_receiver closed while running, exiting.");
                        debug_assert!(false, "ban_receiver closed while running");
                        break;
                    };
                    self.apply_ban(peer, duration);
                }
                changed = identity_receiver.changed() => {
                    if changed.is_err() {
                        error!("ServerLoop: identity channel closed while running, exiting.");
                        debug_assert!(false, "identity channel closed while running");
                        break;
                    }
                    let keypair = identity_receiver.borrow_and_update().insecure_clone();
                    let server_config = new_server_config(&keypair, self.endpoints.len());
                    for endpoint in &self.endpoints {
                        endpoint.set_server_config(Some(server_config.clone()));
                    }
                    let total_closed = self.close_all(close_codes::IDENTITY_CHANGED);
                    self.stats
                        .connection_closed_identity_changed
                        .fetch_add(total_closed, Ordering::Relaxed);
                    info!(
                        "repair server applied new identity {} ({total_closed} connection(s) \
                         closed)",
                        keypair.pubkey()
                    );
                    // Never blocks, and a dropped ack only matters at shutdown,
                    // when the updater is gone anyway.
                    let _ = self.key_updates.ack.try_send(());
                }
                changed = known_peers.changed() => {
                    if changed.is_err() {
                        error!("ServerLoop: known-peers channel closed while running, exiting.");
                        debug_assert!(false, "known-peers channel closed while running");
                        break;
                    }
                    self.apply_known_peers();
                }
                _ = metrics.tick() => {
                    let (staked, unstaked) = self.connected_peers();
                    self.stats.report(staked, unstaked);
                    self.banlist.prune();
                    // Reclaim entries, but keep a depleted bucket as a tombstone so
                    // reconnecting does not hand the peer a fresh budget.
                    self.peer_state.retain(|_, entry| {
                        let budget = entry.budget.load();
                        entry.connection.is_some() || budget.bucket.current_tokens() < budget.cap
                    });
                }
                _ = self.cancel.cancelled() => break,
                Some(joined) = self.connection_tasks.join_next() => {
                    joined.expect("ServerLoop: connection task panicked");
                }
            }
        }
        self.close_all(close_codes::NORMAL_CLOSE);
    }

    /// Close every inbound connection and return how many were closed.
    fn close_all(&self, close_code: close_codes::Spec) -> u64 {
        self.peer_state
            .values()
            .filter_map(|entry| entry.connection.as_ref())
            .inspect(|connection| close_code.close(connection))
            .count() as u64
    }

    /// Resize budgets to the latest stakes, and close connections whose peer
    /// gossip no longer knows about.
    ///
    /// A peer that loses its stake keeps its connection and simply counts as
    /// unstaked from now on, so the unstaked pool may briefly exceed its cap;
    /// new unstaked admissions wait until it drains.
    fn apply_known_peers(&mut self) {
        let known = self.known_peers.borrow().clone();
        let mut closed = 0u64;
        for (peer, entry) in self.peer_state.iter() {
            match known.stake(peer) {
                Some(stake) => entry.refresh_budget(stake, known.total_stake()),
                None => {
                    if let Some(connection) = entry.connection.as_ref() {
                        close_codes::NOT_ADMITTED.close(connection);
                        closed = closed.saturating_add(1);
                    }
                }
            }
        }
        self.stats
            .connection_closed_unknown_peer
            .fetch_add(closed, Ordering::Relaxed);
    }

    /// Apply the ban command and close any open connection from that peer.
    fn apply_ban(&mut self, peer: Pubkey, timeout: Duration) {
        self.banlist.ban(peer, timeout);
        if let Some(connection) = self
            .peer_state
            .get(&peer)
            .and_then(|entry| entry.connection.as_ref())
        {
            close_codes::BANNED.close(connection);
            self.stats
                .connection_closed_banned
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn handle_event(&mut self, event: InboundConnectionEvent) {
        match event {
            InboundConnectionEvent::Accepted { peer, connection } => {
                self.maybe_admit_connection(peer, connection)
            }
            // The entry is kept as a tombstone for the rate limiter; the metrics
            // tick reclaims it once the budget has refilled.
            InboundConnectionEvent::Closed { peer, stable_id } => {
                if let Some(entry) = self.peer_state.get_mut(&peer)
                    && entry
                        .connection
                        .as_ref()
                        .is_some_and(|connection| connection.stable_id() == stable_id)
                {
                    entry.connection = None;
                }
            }
        }
    }

    /// Admission checks for a freshly handshaked inbound connection.
    fn maybe_admit_connection(&mut self, peer: Pubkey, connection: Connection) {
        let remote_addr = connection.remote_address();
        if self.banlist.is_banned(&peer) {
            debug!("Banned peer {peer} attempted a connection from {remote_addr}, rejected");
            close_codes::BANNED.close(&connection);
            record_server_error(&Error::Banned(peer), &self.stats);
            return;
        }
        // Repair over QUIC serves anyone gossip knows about, which is both wider
        // than votor's closed peer list and narrower than UDP repair's "anyone
        // who answers a ping". A peer missing from our CRDS falls back to UDP.
        let (stake, total_stake) = {
            let known = self.known_peers.borrow();
            (known.stake(&peer), known.total_stake())
        };
        let Some(stake) = stake else {
            debug!("Unknown peer {peer} attempted a connection from {remote_addr}, rejected");
            close_codes::NOT_ADMITTED.close(&connection);
            record_server_error(&Error::NotAdmitted(peer), &self.stats);
            return;
        };
        // Staked peers are always admitted: the epoch stake set bounds how many
        // there can be. Unstaked peers share a fixed pool, and a redial of a
        // live connection does not need a new slot.
        let is_redial = self
            .peer_state
            .get(&peer)
            .is_some_and(|entry| entry.connection.is_some());
        if stake == 0 && !is_redial {
            let (_staked, unstaked) = self.connected_peers();
            if unstaked >= MAX_UNSTAKED_INBOUND_CONNECTIONS as u64 {
                close_codes::TOO_MANY_CONNECTIONS.close(&connection);
                record_server_error(&Error::TooManyConnections, &self.stats);
                return;
            }
        }

        let budget = match self.peer_state.entry(peer) {
            Entry::Vacant(slot) => {
                let budget = Arc::new(ArcSwap::from_pointee(PeerBudget::new(
                    stake,
                    total_stake,
                    None,
                )));
                slot.insert(PeerEntry {
                    connection: Some(connection.clone()),
                    budget: budget.clone(),
                });
                budget
            }
            Entry::Occupied(mut slot) => {
                let entry = slot.get_mut();
                entry.refresh_budget(stake, total_stake);
                // A redial replaces: a restarting validator must not be locked
                // out for a full idle timeout by its own stale connection. The
                // budget survives because it lives in the entry, not the
                // connection, which is what makes replacing safe.
                if let Some(previous) = entry.connection.replace(connection.clone()) {
                    close_codes::REPLACED.close(&previous);
                    self.stats
                        .connection_replaced
                        .fetch_add(1, Ordering::Relaxed);
                }
                Arc::clone(&entry.budget)
            }
        };
        let (staked, unstaked) = self.connected_peers();
        stats::record_connection_count(
            &self.stats.peak_unique_peers,
            staked.saturating_add(unstaked),
        );
        debug!("Admitted repair connection from {peer} ({remote_addr})");
        self.connection_tasks.spawn(
            ConnectionServer {
                connection,
                peer,
                remote_addr,
                requests: self.requests.clone(),
                budget,
                global: self.global.clone(),
                events_sender: self.events_sender.clone(),
                stats: self.stats.clone(),
                cancel: self.cancel.clone(),
            }
            .run(),
        );
    }
}

/// Build the event channel shared by the accept loops and the control loop.
pub(crate) fn new_event_channel() -> (
    mpsc::Sender<InboundConnectionEvent>,
    mpsc::Receiver<InboundConnectionEvent>,
) {
    mpsc::channel(CONN_EVENT_CHANNEL_CAP)
}

#[cfg(test)]
mod tests {
    use {super::*, std::net::Ipv4Addr};

    #[test]
    fn staked_rate_is_stake_share_with_unstaked_floor() {
        let total_stake = 1_000;
        assert_eq!(
            PeerBudget::rate_for(0, total_stake),
            (PEER_RATE_BYTES_PER_SECOND, false)
        );
        assert_eq!(
            PeerBudget::rate_for(100, total_stake),
            (GLOBAL_RATE_BYTES_PER_SECOND / 10, true)
        );
        let dust_stake = 1;
        assert_eq!(
            PeerBudget::rate_for(dust_stake, total_stake),
            (PEER_RATE_BYTES_PER_SECOND, true),
            "a tiny stake never gets less than an unstaked peer",
        );
    }

    /// Unstaked peers stop at the headroom floor of the global budget, staked
    /// peers drain it down to a single stream.
    #[test]
    fn global_budget_serves_staked_peers_first() {
        let stats = ServerStats::default();
        let total_stake = 1_000;
        let staked = PeerBudget::new(100, total_stake, None);
        let unstaked = PeerBudget::new(0, total_stake, None);
        let global = GlobalBudget::new();
        let stable_id = 0;

        assert_eq!(throttle_for(&staked, &global, stable_id, &stats), None);
        assert_eq!(throttle_for(&unstaked, &global, stable_id, &stats), None);

        // Leave half the unstaked floor: refilling past it takes far longer
        // than this test runs.
        let tokens = global.bucket.current_tokens();
        global
            .bucket
            .consume_tokens(tokens - global.unstaked_floor / 2)
            .expect("bucket holds what it just reported");
        assert_eq!(
            throttle_for(&staked, &global, stable_id, &stats),
            None,
            "staked peers keep drawing on what unstaked peers may not touch",
        );
        assert!(
            throttle_for(&unstaked, &global, stable_id, &stats).is_some(),
            "unstaked peers wait until staked demand leaves headroom",
        );

        global
            .bucket
            .consume_tokens_saturating(global.bucket.current_tokens());
        assert!(
            throttle_for(&staked, &global, stable_id, &stats).is_some(),
            "an empty global budget throttles staked peers too",
        );
        assert_eq!(
            stats.global_rate_limited_unstaked.load(Ordering::Relaxed),
            1
        );
        assert_eq!(stats.global_rate_limited_staked.load(Ordering::Relaxed), 1);
        assert_eq!(stats.peer_rate_limited.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn remote_address_filter_honors_socket_addr_space() {
        let public = SocketAddr::from(([1, 2, 3, 4], 8000));
        let private = SocketAddr::from(([10, 0, 0, 1], 8000));
        let localhost = SocketAddr::from((Ipv4Addr::LOCALHOST, 8000));

        assert!(!is_invalid_remote_address(
            public,
            None,
            SocketAddrSpace::Global,
        ));
        for addr in [private, localhost] {
            assert!(is_invalid_remote_address(
                addr,
                None,
                SocketAddrSpace::Global,
            ));
            assert!(!is_invalid_remote_address(
                addr,
                Some(addr.ip()),
                SocketAddrSpace::Unspecified,
            ));
        }
        assert!(is_invalid_remote_address(
            public,
            Some(public.ip()),
            SocketAddrSpace::Global,
        ));
    }
}
