//! Inbound (server) direction: we accept connections and serve repair requests.
use {
    crate::{
        CONN_EVENT_CHANNEL_CAP, HANDSHAKE_TIMEOUT, KnownPeersReceiver, MAX_INBOUND_CONNECTIONS,
        MAX_REQUEST_BYTES, METRICS_INTERVAL, MIN_STREAM_COST, PEER_RATE_BYTES_PER_SECOND,
        PEER_RATE_CAP_WINDOW, REQUEST_READ_TIMEOUT, RESPONSE_TIMEOUT, close_codes,
        endpoint::{BanCommand, InboundRepairRequest, KeyUpdateListener, Responder},
        error::{Error, stream_codes},
        framing::encode_responses,
        stats::{self, ServerStats, record_server_error},
        transport::new_server_config,
    },
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

/// Everything we track about one peer that is independent of its connection.
///
/// The rate limiter deliberately outlives the connection: if it were created on
/// admission, a peer that drained its budget could reconnect for a free refill.
pub(crate) struct PeerEntry {
    /// At most one connection per peer; a redial replaces it.
    connection: Option<Connection>,
    rate_limiter: Arc<TokenBucket>,
}

/// Event reported to the [`ServerLoop`].
pub(crate) enum InboundConnectionEvent {
    /// A TLS handshake completed and yielded a valid, authenticated peer.
    Accepted {
        peer: Pubkey,
        connection: Connection,
    },
    /// An inbound connection terminated. `stable_id` identifies the connection.
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
                // Rate gate refilled: allow pulling connection attempts.
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
        // Handshake has timed out
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
    rate_limiter: Arc<TokenBucket>,
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
    rate_limiter.consume_tokens_saturating(response_bytes as u64);
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

/// Per-connection accept loop for an admitted inbound connection.
pub(crate) struct ConnectionServer {
    connection: Connection,
    peer: Pubkey,
    remote_addr: SocketAddr,
    requests: Sender<InboundRepairRequest>,
    rate_limiter: Arc<TokenBucket>,
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
            rate_limiter,
            events_sender,
            stats,
            cancel,
        } = self;
        let stable_id = connection.stable_id();
        let mut streams = JoinSet::new();
        // Closed while the peer is over budget. We simply stop calling
        // `accept_bi`, and QUIC's own MAX_STREAMS flow control applies the
        // backpressure for us: no close, no ban, and the peer recovers with no
        // state change once the bucket refills.
        let mut read_gate = Box::pin(sleep(Duration::ZERO));
        let mut throttled = false;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                Some(joined) = streams.join_next(), if !streams.is_empty() => {
                    joined.expect("ConnectionServer: stream task panicked");
                }
                _ = &mut read_gate, if throttled => {
                    throttled = false;
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
                    // own budget.
                    rate_limiter.consume_tokens_saturating(MIN_STREAM_COST);
                    if rate_limiter.current_tokens() < MIN_STREAM_COST {
                        throttled = true;
                        let wait_us = rate_limiter
                            .us_to_have_tokens(MIN_STREAM_COST)
                            .expect("bucket capacity exceeds the per-stream floor")
                            .saturating_add(1);
                        let deadline = Instant::now()
                            .checked_add(Duration::from_micros(wait_us))
                            .expect("read-gate deadline should never overflow");
                        read_gate.as_mut().reset(deadline);
                        stats.peer_rate_limited.fetch_add(1, Ordering::Relaxed);
                    }
                    streams.spawn(serve_stream(
                        peer,
                        remote_addr,
                        send,
                        recv,
                        requests.clone(),
                        rate_limiter.clone(),
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
    /// Cloned into spawned tasks.
    events_sender: mpsc::Sender<InboundConnectionEvent>,
    events_receiver: mpsc::Receiver<InboundConnectionEvent>,
    stats: Arc<ServerStats>,
    cancel: CancellationToken,
    /// Bucket capacity, in bytes.
    peer_rate_cap: u64,
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
        // The bucket starts full and refills at the sustained rate, so its
        // capacity is both the burst a peer may bank while idle and, since the
        // entry outlives the connection, the most a reconnect can recover.
        let peer_rate_cap = ((PEER_RATE_BYTES_PER_SECOND as f64
            * PEER_RATE_CAP_WINDOW.as_secs_f64())
        .ceil() as u64)
            .max(MIN_STREAM_COST.saturating_mul(2));
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
            peer_rate_cap,
        }
    }

    /// Counts the peers from which we currently hold a connection.
    fn total_peers(&self) -> u64 {
        self.peer_state
            .values()
            .filter(|entry| entry.connection.is_some())
            .count() as u64
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
                    self.close_unknown_peers();
                }
                _ = metrics.tick() => {
                    self.stats.report(self.total_peers());
                    self.banlist.prune();
                    // Reclaim entries, but keep a depleted bucket as a tombstone so
                    // reconnecting does not hand the peer a fresh budget.
                    let cap = self.peer_rate_cap;
                    self.peer_state.retain(|_, entry| {
                        entry.connection.is_some() || entry.rate_limiter.current_tokens() < cap
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

    /// Close connections whose peer gossip no longer knows about.
    fn close_unknown_peers(&mut self) {
        let known = self.known_peers.borrow().clone();
        let mut closed = 0u64;
        for (peer, entry) in self.peer_state.iter() {
            let Some(connection) = entry.connection.as_ref() else {
                continue;
            };
            if known.contains(peer) {
                continue;
            }
            close_codes::NOT_ADMITTED.close(connection);
            closed = closed.saturating_add(1);
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
        if !self.known_peers.borrow().contains(&peer) {
            debug!("Unknown peer {peer} attempted a connection from {remote_addr}, rejected");
            close_codes::NOT_ADMITTED.close(&connection);
            record_server_error(&Error::NotAdmitted(peer), &self.stats);
            return;
        }
        if !self.peer_state.contains_key(&peer)
            && self.total_peers() as usize >= MAX_INBOUND_CONNECTIONS
        {
            close_codes::TOO_MANY_CONNECTIONS.close(&connection);
            record_server_error(&Error::TooManyConnections, &self.stats);
            return;
        }

        let rate_limiter = match self.peer_state.entry(peer) {
            Entry::Vacant(slot) => {
                let rate_limiter = Arc::new(TokenBucket::new(
                    self.peer_rate_cap,
                    self.peer_rate_cap,
                    PEER_RATE_BYTES_PER_SECOND as f64,
                ));
                slot.insert(PeerEntry {
                    connection: Some(connection.clone()),
                    rate_limiter: rate_limiter.clone(),
                });
                rate_limiter
            }
            Entry::Occupied(mut slot) => {
                let entry = slot.get_mut();
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
                Arc::clone(&entry.rate_limiter)
            }
        };
        stats::record_connection_count(&self.stats.peak_unique_peers, self.total_peers());
        debug!("Admitted repair connection from {peer} ({remote_addr})");
        self.connection_tasks.spawn(
            ConnectionServer {
                connection,
                peer,
                remote_addr,
                requests: self.requests.clone(),
                rate_limiter,
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
