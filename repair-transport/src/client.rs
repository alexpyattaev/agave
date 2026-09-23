//! Outbound (client) direction: we dial peers and request repairs from them.
use {
    crate::{
        METRICS_INTERVAL, PEER_BACKOFF, PEER_FAILURES_BEFORE_BACKOFF, RECONCILE_INTERVAL,
        RESPONSE_TIMEOUT, close_codes,
        endpoint::{KeyUpdateListener, OutboundRepairRequest, PeerBackoffView},
        error::Error,
        framing::{decode_responses, max_response_bytes},
        stats::{self, ClientStats, record_client_error},
        transport::new_client_config,
    },
    bytes::Bytes,
    crossbeam_channel::TrySendError,
    log::{debug, error, info, warn},
    quinn::{Connection, Endpoint},
    solana_keypair::{Keypair, Signer},
    solana_packet::Meta,
    solana_perf::packet::{BytesPacket, BytesPacketBatch},
    solana_pubkey::{Pubkey, PubkeyHasherBuilder},
    solana_tls_utils::{get_remote_pubkey, socket_addr_to_quic_server_name},
    std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, atomic::Ordering},
        time::Duration,
    },
    tokio::{
        sync::mpsc,
        task::JoinSet,
        time::{Instant, MissedTickBehavior, interval, timeout},
    },
    tokio_util::sync::CancellationToken,
};

/// Upper bound on a single handshake attempt, enforced inside the connect task.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Requests we hold for a peer whose handshake has not completed yet. Repair
/// re-requests on its own timer, so a deep queue would only deliver stale
/// requests; anything over this is dropped and re-requested later.
const MAX_PENDING_REQUESTS_PER_PEER: usize = 16;

enum PeerState {
    /// Handshake in progress; requests wait here rather than behind a lock.
    Connecting {
        address: SocketAddr,
        pending: Vec<OutboundRepairRequest>,
    },
    Established {
        connection: Connection,
        address: SocketAddr,
    },
    /// Repeatedly unreachable over QUIC: the caller repairs from this peer over
    /// UDP until the backoff expires. Without this, a peer that advertises a
    /// firewalled port burns a full `REPAIR_REQUEST_TIMEOUT_MS` per attempt.
    Backoff { until: Instant },
}

struct PeerSlot {
    state: PeerState,
    consecutive_failures: u32,
}

/// Outcome of a dial attempt, reported back to the control loop.
struct HandshakeOutcome {
    peer: Pubkey,
    connection: Option<Connection>,
}

/// Outcome of one request/response exchange.
struct ExchangeOutcome {
    peer: Pubkey,
    succeeded: bool,
}

/// What [`ClientLoop::handle_request`] decided to do, once the connection table
/// borrow it was taken under has been released.
enum Next {
    Send(Connection, OutboundRepairRequest),
    Dial(OutboundRepairRequest),
    Drop(OutboundRepairRequest),
    Queued,
}

/// Open and authenticate a new connection to `peer` at `addr`.
///
/// The attested-identity check is the client half of the bidirectional
/// attestation: a server that answers on the advertised address but cannot
/// prove it holds `peer`'s key is not a peer we will repair from.
async fn connect(
    endpoint: Endpoint,
    peer: Pubkey,
    addr: SocketAddr,
    stats: Arc<ClientStats>,
) -> HandshakeOutcome {
    let attempt = async {
        let server_name = socket_addr_to_quic_server_name(addr);
        let connection = endpoint.connect(addr, &server_name)?.await?;
        let attested = get_remote_pubkey(&connection).ok_or(Error::InvalidIdentity(addr))?;
        if attested != peer {
            close_codes::INVALID_IDENTITY.close(&connection);
            return Err(Error::WrongIdentity {
                expected: peer,
                attested,
                address: addr,
            });
        }
        Ok(connection)
    };
    let connection = match timeout(HANDSHAKE_TIMEOUT, attempt).await {
        Ok(Ok(connection)) => Some(connection),
        Ok(Err(e)) => {
            debug!("Repair connection attempt to ({peer}, {addr}) failed: {e:?}");
            record_client_error(&e, &stats);
            None
        }
        Err(_elapsed) => {
            debug!("Repair connection attempt to ({peer}, {addr}) timed out");
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            None
        }
    };
    HandshakeOutcome { peer, connection }
}

/// Run one request/response exchange on its own bidirectional stream.
async fn exchange(
    connection: &Connection,
    request: &OutboundRepairRequest,
    stats: &ClientStats,
) -> Result<(), Error> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&request.bytes).await?;
    // A failure here surfaces on the read below, where it is reported once.
    let _ = send.finish();

    let num_expected = request.num_expected_responses as usize;
    let limit = max_response_bytes(num_expected);
    let body = match timeout(RESPONSE_TIMEOUT, recv.read_to_end(limit)).await {
        Ok(result) => result?,
        Err(_elapsed) => return Err(Error::Timeout(request.peer)),
    };
    let payloads = decode_responses(Bytes::from(body), num_expected)?;
    if payloads.is_empty() {
        // An empty response is a blockstore miss, which repair already handles.
        return Ok(());
    }
    let batch: BytesPacketBatch = payloads
        .into_iter()
        .map(|payload| {
            let mut meta = Meta::default();
            meta.size = payload.len();
            meta.set_socket_addr(&request.peer_address);
            // Marks the response as TLS-attested, which lets the repair
            // services tell a QUIC response apart from a UDP one.
            meta.set_remote_pubkey(request.peer);
            BytesPacket::new(payload, meta)
        })
        .collect();
    let num_packets = batch.len() as u64;
    match request.responses.try_send(batch.into()) {
        Ok(()) => {
            stats
                .responses_received
                .fetch_add(num_packets, Ordering::Relaxed);
        }
        Err(TrySendError::Full(_)) => {
            stats
                .responses_dropped_channel_full
                .fetch_add(num_packets, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => {
            debug!("repair response channel disconnected");
        }
    }
    Ok(())
}

async fn run_exchange(
    connection: Connection,
    request: OutboundRepairRequest,
    stats: Arc<ClientStats>,
) -> ExchangeOutcome {
    let peer = request.peer;
    match exchange(&connection, &request, &stats).await {
        Ok(()) => ExchangeOutcome {
            peer,
            succeeded: true,
        },
        Err(e) => {
            debug!("Repair exchange with {peer} failed: {e:?}");
            // Malformed framing is not a transient fault: the peer is broken or
            // hostile, and nothing it sends on this connection can be trusted.
            if matches!(e, Error::Framing(_)) {
                close_codes::PROTOCOL_VIOLATION.close(&connection);
            }
            record_client_error(&e, &stats);
            ExchangeOutcome {
                peer,
                succeeded: false,
            }
        }
    }
}

/// Outbound control loop: owns the connection table and the circuit breaker.
pub(crate) struct ClientLoop {
    endpoint: Endpoint,
    local_pubkey: Pubkey,
    requests: mpsc::Receiver<OutboundRepairRequest>,
    key_updates: KeyUpdateListener,
    peers: HashMap<Pubkey, PeerSlot, PubkeyHasherBuilder>,
    handshakes: JoinSet<HandshakeOutcome>,
    exchanges: JoinSet<ExchangeOutcome>,
    /// Published so the repair threads can route around unusable peers without
    /// taking a lock on the hot path.
    backoff_view: PeerBackoffView,
    cancel: CancellationToken,
    stats: Arc<ClientStats>,
}

impl ClientLoop {
    pub(crate) fn new(
        endpoint: Endpoint,
        local_pubkey: Pubkey,
        requests: mpsc::Receiver<OutboundRepairRequest>,
        key_updates: KeyUpdateListener,
        backoff_view: PeerBackoffView,
        cancel: CancellationToken,
        stats: Arc<ClientStats>,
    ) -> Self {
        Self {
            endpoint,
            local_pubkey,
            requests,
            key_updates,
            peers: HashMap::with_hasher(PubkeyHasherBuilder::default()),
            handshakes: JoinSet::new(),
            exchanges: JoinSet::new(),
            backoff_view,
            cancel,
            stats,
        }
    }

    pub(crate) async fn run(mut self) {
        let mut metrics_timer = interval(METRICS_INTERVAL);
        metrics_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut reconcile_timer = interval(RECONCILE_INTERVAL);
        reconcile_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        info!("Repair QUIC transport client ready.");
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                changed = self.key_updates.receiver.changed() => {
                    if changed.is_err() {
                        // Unreachable: the endpoint holds the sender for our lifetime.
                        error!("ClientLoop: identity channel closed while running, exiting.");
                        debug_assert!(false, "identity channel closed while running");
                        break;
                    }
                    let keypair = self.key_updates.receiver.borrow_and_update().insecure_clone();
                    self.apply_identity_change(keypair);
                }
                Some(joined) = self.handshakes.join_next() => {
                    let outcome = joined.expect("ClientLoop: handshake task panicked");
                    self.handle_handshake_outcome(outcome);
                }
                Some(joined) = self.exchanges.join_next() => {
                    let outcome = joined.expect("ClientLoop: exchange task panicked");
                    self.handle_exchange_outcome(outcome);
                }
                maybe_request = self.requests.recv() => {
                    let Some(request) = maybe_request else {
                        debug_assert!(
                            self.cancel.is_cancelled(),
                            "request channel closed before cancel signal is given"
                        );
                        break;
                    };
                    self.handle_request(request);
                }
                _ = reconcile_timer.tick() => self.reconcile(),
                _ = metrics_timer.tick() => {
                    let in_backoff = self.backoff_view.load().len() as u64;
                    self.stats.report(self.total_connections(), in_backoff);
                }
            }
        }
    }

    fn total_connections(&self) -> u64 {
        self.peers
            .values()
            .filter(|slot| matches!(slot.state, PeerState::Established { .. }))
            .count() as u64
    }

    /// Rebuild the client TLS config against the new identity, swap it into the
    /// quinn endpoint and drop everything that was established under the old one.
    fn apply_identity_change(&mut self, keypair: Keypair) {
        self.local_pubkey = keypair.pubkey();
        self.endpoint
            .set_default_client_config(new_client_config(&keypair));
        // Dropping the JoinSets aborts in-flight work started under the old identity.
        self.handshakes = JoinSet::new();
        self.exchanges = JoinSet::new();
        let closed = self
            .peers
            .drain()
            .filter(|(_peer, slot)| {
                if let PeerState::Established { connection, .. } = &slot.state {
                    close_codes::IDENTITY_CHANGED.close(connection);
                    true
                } else {
                    false
                }
            })
            .count() as u64;
        self.stats
            .connection_closed_identity_changed
            .fetch_add(closed, Ordering::Relaxed);
        self.publish_backoff_view();
        // Never blocks, and a dropped ack only matters at shutdown, when the
        // updater is gone anyway.
        let _ = self.key_updates.ack.try_send(());
        info!(
            "repair client identity changed to {} ({closed} connection(s) closed)",
            self.local_pubkey
        );
    }

    fn drop_request(&self, request: OutboundRepairRequest) {
        drop(request);
        self.stats.requests_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn handle_request(&mut self, request: OutboundRepairRequest) {
        let peer = request.peer;
        let address = request.peer_address;
        if peer == self.local_pubkey {
            debug_assert!(false, "repair request addressed to ourselves");
            self.drop_request(request);
            return;
        }
        // The table borrow is released before acting, so the decision is made
        // here and carried out below.
        let next = match self.peers.get_mut(&peer) {
            Some(slot) => match &mut slot.state {
                PeerState::Established {
                    connection,
                    address: current,
                } if *current == address => Next::Send(connection.clone(), request),
                PeerState::Established {
                    connection,
                    address: current,
                } => {
                    info!("ClientLoop: peer {peer} moved from {current} to {address}, redialing");
                    close_codes::PEER_MOVED.close(connection);
                    self.stats
                        .connection_closed_peer_moved
                        .fetch_add(1, Ordering::Relaxed);
                    Next::Dial(request)
                }
                PeerState::Connecting {
                    address: current,
                    pending,
                } if *current == address => {
                    if pending.len() < MAX_PENDING_REQUESTS_PER_PEER {
                        pending.push(request);
                        Next::Queued
                    } else {
                        Next::Drop(request)
                    }
                }
                // The address changed mid-handshake: let the in-flight attempt
                // resolve and re-dial on the next request for this peer.
                PeerState::Connecting { .. } => Next::Drop(request),
                PeerState::Backoff { until } if *until > Instant::now() => Next::Drop(request),
                PeerState::Backoff { .. } => Next::Dial(request),
            },
            None => Next::Dial(request),
        };
        match next {
            Next::Send(connection, request) => self.spawn_exchange(connection, request),
            Next::Dial(request) => self.start_connect(peer, address, Some(request)),
            Next::Drop(request) => self.drop_request(request),
            Next::Queued => {}
        }
    }

    fn spawn_exchange(&mut self, connection: Connection, request: OutboundRepairRequest) {
        self.stats.requests_sent.fetch_add(1, Ordering::Relaxed);
        self.exchanges
            .spawn(run_exchange(connection, request, self.stats.clone()));
    }

    fn start_connect(
        &mut self,
        peer: Pubkey,
        address: SocketAddr,
        request: Option<OutboundRepairRequest>,
    ) {
        let consecutive_failures = self
            .peers
            .get(&peer)
            .map(|slot| slot.consecutive_failures)
            .unwrap_or(0);
        self.peers.insert(
            peer,
            PeerSlot {
                state: PeerState::Connecting {
                    address,
                    pending: request.into_iter().collect(),
                },
                consecutive_failures,
            },
        );
        self.handshakes.spawn(connect(
            self.endpoint.clone(),
            peer,
            address,
            self.stats.clone(),
        ));
        self.publish_backoff_view();
    }

    fn handle_handshake_outcome(&mut self, outcome: HandshakeOutcome) {
        let HandshakeOutcome { peer, connection } = outcome;
        let Some(slot) = self.peers.get_mut(&peer) else {
            // Identity rotation wiped the table while this was in flight.
            if let Some(connection) = connection {
                close_codes::IDENTITY_CHANGED.close(&connection);
            }
            return;
        };
        let PeerState::Connecting { address, pending } = &mut slot.state else {
            debug_assert!(
                false,
                "handshake completed for a peer that was not Connecting"
            );
            return;
        };
        let address = *address;
        let pending = std::mem::take(pending);
        let established = match connection {
            Some(connection) => {
                slot.consecutive_failures = 0;
                slot.state = PeerState::Established {
                    connection: connection.clone(),
                    address,
                };
                Some(connection)
            }
            None => {
                let failures = slot.consecutive_failures.saturating_add(1);
                slot.consecutive_failures = failures;
                slot.state = Self::failure_state(failures);
                None
            }
        };
        for request in pending {
            match &established {
                Some(connection) => self.spawn_exchange(connection.clone(), request),
                None => self.drop_request(request),
            }
        }
        self.publish_backoff_view();
    }

    fn handle_exchange_outcome(&mut self, outcome: ExchangeOutcome) {
        let ExchangeOutcome { peer, succeeded } = outcome;
        let Some(slot) = self.peers.get_mut(&peer) else {
            return;
        };
        if succeeded {
            slot.consecutive_failures = 0;
            return;
        }
        let failures = slot.consecutive_failures.saturating_add(1);
        slot.consecutive_failures = failures;
        // A failed exchange on a live connection usually means the connection
        // itself is gone; reconcile would notice eventually, but the breaker has
        // to trip on time for the caller to fall back to UDP.
        let tripped = failures >= PEER_FAILURES_BEFORE_BACKOFF;
        if tripped {
            if let PeerState::Established { connection, .. } = &slot.state {
                close_codes::NORMAL_CLOSE.close(connection);
            }
            slot.state = Self::failure_state(failures);
        }
        if tripped {
            self.publish_backoff_view();
        }
    }

    /// Where a peer lands after a failure: retried immediately until it has
    /// failed enough times to be considered unusable.
    fn failure_state(consecutive_failures: u32) -> PeerState {
        if consecutive_failures >= PEER_FAILURES_BEFORE_BACKOFF {
            PeerState::Backoff {
                until: Instant::now()
                    .checked_add(PEER_BACKOFF)
                    .expect("backoff deadline should never overflow"),
            }
        } else {
            PeerState::Backoff {
                until: Instant::now(),
            }
        }
    }

    /// Expire backoffs and reap connections that died underneath us.
    fn reconcile(&mut self) {
        let now = Instant::now();
        let mut lost = 0u64;
        self.peers.retain(|peer, slot| match &slot.state {
            PeerState::Established { connection, .. } => {
                let Some(reason) = connection.close_reason() else {
                    return true;
                };
                debug!("ClientLoop: connection to {peer} was closed: {reason}");
                lost = lost.saturating_add(1);
                false
            }
            // Drop the entry entirely once the backoff has expired: the next
            // request for this peer dials fresh, and forgetting the failure
            // count is what lets a recovered peer come straight back.
            PeerState::Backoff { until } => *until > now,
            PeerState::Connecting { .. } => true,
        });
        self.stats
            .connection_lost
            .fetch_add(lost, Ordering::Relaxed);
        stats::record_connection_count(&self.stats.peak_connections, self.total_connections());
        self.publish_backoff_view();
    }

    /// Republish the set of peers the caller should not route QUIC repair to.
    fn publish_backoff_view(&self) {
        let now = Instant::now();
        let in_backoff: crate::KnownPeers = self
            .peers
            .iter()
            .filter(|(_peer, slot)| match slot.state {
                PeerState::Backoff { until } => until > now,
                PeerState::Connecting { .. } | PeerState::Established { .. } => false,
            })
            .map(|(peer, _slot)| *peer)
            .collect();
        self.backoff_view.store(Arc::new(in_backoff));
    }
}

/// Report a request that never reached the client loop.
pub(crate) fn record_request_dropped(stats: &ClientStats, reason: &str) {
    warn!("repair QUIC request dropped: {reason}");
    stats.requests_dropped.fetch_add(1, Ordering::Relaxed);
}
