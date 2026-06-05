//! Inbound (server) direction: we-accept, receive-only.

use {
    crate::{
        ALLOWLIST_CHECK_INTERVAL, ALPENGLOW_ALPN, BANLIST_PRUNE_INTERVAL, CONN_EVENT_CHANNEL_CAP,
        HANDSHAKE_GLOBAL_RATE, MAX_INBOUND_CONNECTIONS_PER_PEER, METRICS_INTERVAL,
        PEER_RATE_LIMIT_BURST, PEER_RATE_LIMIT_BURST_DOS,
        allowlist::Allowlist,
        close_codes,
        endpoint::Datagram,
        error::Error,
        stats::{self, QuicDatagramStats, add, record_error},
        transport::{IdentitySnapshot, new_server_config},
    },
    arrayvec::ArrayVec,
    crossbeam_channel::{Sender, TrySendError},
    log::{debug, info, warn},
    quinn::{Connection, Endpoint, Incoming},
    solana_net_utils::{banlist::Banlist, token_bucket::TokenBucket},
    solana_pubkey::{Pubkey, PubkeyHasherBuilder},
    solana_tls_utils::get_remote_pubkey,
    std::{
        collections::{HashMap, hash_map::Entry},
        net::SocketAddr,
        sync::{Arc, atomic::Ordering},
        time::Duration,
    },
    tokio::{
        spawn,
        sync::{mpsc, watch},
        time::{Instant, MissedTickBehavior, interval, sleep},
    },
    tokio_util::sync::CancellationToken,
};

/// State for one peer
pub(crate) struct PeerEntry {
    connections: ArrayVec<Connection, MAX_INBOUND_CONNECTIONS_PER_PEER>,
    rate_limiter: Arc<TokenBucket>,
}

/// Event reported by an accept or read task to the inbound control loop.
pub(crate) enum InboundEvent {
    /// A TLS handshake completed and yielded an authenticated peer.
    Accepted {
        peer: Pubkey,
        connection: Connection,
        generation: u64,
    },
    /// An inbound (we-accepted) connection ended. The read loop reports this
    /// so the control loop can reap the table slot.
    Closed {
        peer: Pubkey,
        generation: u64,
        stable_id: usize,
    },
    /// The ingress traffic shaping bucket was drained by a sustained flood.
    FloodDetected { peer: Pubkey },
}

/// An inbound accept: run the handshake and hand the connection (plus its
/// attested pubkey) to the control loop for admission.
pub(crate) struct ServerConnection {
    pub(crate) incoming: Incoming,
    pub(crate) generation: u64,
    pub(crate) events: mpsc::Sender<InboundEvent>,
    pub(crate) stats: Arc<QuicDatagramStats>,
}

impl ServerConnection {
    async fn run(self) {
        let remote_addr = self.incoming.remote_address();
        let connection = match async { self.incoming.accept()?.await }.await {
            Ok(connection) => connection,
            Err(e) => {
                record_error(&Error::from(e), &self.stats);
                return;
            }
        };
        let Some(peer) = get_remote_pubkey(&connection) else {
            close_codes::INVALID_IDENTITY.close(&connection);
            record_error(&Error::InvalidIdentity(remote_addr), &self.stats);
            return;
        };
        // Hand the connection to the loop for admission control checks
        let _ = self
            .events
            .send(InboundEvent::Accepted {
                peer,
                connection,
                generation: self.generation,
            })
            .await;
    }
}

/// Drive the per-connection read loop for an incoming connection.
/// Returns when the connection closes. On exit it reliably reports
/// [`InboundEvent::Closed`] so the control loop can reap the table entry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_datagram_loop(
    connection: Connection,
    peer: Pubkey,
    remote_addr: SocketAddr,
    generation: u64,
    ingress: Sender<Datagram>,
    allowlist: Arc<dyn Allowlist>,
    banlist: Arc<Banlist<Pubkey>>,
    rate_limiter: Arc<TokenBucket>,
    events: mpsc::Sender<InboundEvent>,
    stats: Arc<QuicDatagramStats>,
) {
    let stable_id = connection.stable_id();
    // Use the same bucket to be reused for both shaping and flood control
    const RATE_LIMIT_WATERMARK: u64 = PEER_RATE_LIMIT_BURST_DOS - PEER_RATE_LIMIT_BURST;
    let mut allowlist_check = interval(ALLOWLIST_CHECK_INTERVAL);
    allowlist_check.tick().await; // skip the immediate first fire
    loop {
        tokio::select! {
            result = connection.read_datagram() => {
                match result {
                    Ok(bytes) => {
                        // Banlist check happens AFTER the read so a ban that
                        // lands while we're awaiting can't let a follow-up
                        // datagram leak through to ingress.
                        if banlist.is_banned(&peer) {
                            close_codes::BANNED.close(&connection);
                            break;
                        }
                        match rate_limiter.consume_tokens(1) {
                            // normal operation
                            Ok(remaining) if remaining > RATE_LIMIT_WATERMARK => {}
                            // drop excess packets if peer exceeds normal rate
                            Ok(_) => {
                                drop(bytes);
                                stats.datagram_rate_limited.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            // peer drained bucket dry - kick them
                            Err(_) => {
                                drop(bytes);
                                let _ = events
                                    .send(InboundEvent::FloodDetected { peer })
                                    .await;
                                break;
                            }
                        }

                        match ingress.try_send(Datagram {
                            peer_pubkey: peer,
                            peer_address: remote_addr,
                            message: bytes,
                        }) {
                            Ok(()) => {
                                stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Full(_)) => {
                                stats
                                    .datagram_ingress_dropped_channel_full
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                debug!("ingress disconnected; reader for {peer} exiting");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // The peer (or we) closed this inbound, or it timed
                        // out. Record and exit; the control loop reaps the
                        // table slot from the `Closed` event below.
                        record_error(&Error::from(e), &stats);
                        break;
                    }
                }
            }
            _ = allowlist_check.tick() => {
                if !allowlist.allow(&peer) {
                    close_codes::NOT_ADMITTED.close(&connection);
                    stats.connection_evicted_allowlist.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                if banlist.is_banned(&peer) {
                    close_codes::BANNED.close(&connection);
                    break;
                }
            }
        }
    }
    // Send the notification to control that this connection died.
    let _ = events
        .send(InboundEvent::Closed {
            peer,
            generation,
            stable_id,
        })
        .await;
}

/// Inbound control loop: we-accept, receive-only.
pub(crate) struct InboundLoop {
    pub(crate) endpoint: Endpoint,
    /// Identity-rotation counter
    pub(crate) generation: u64,
    pub(crate) ingress: Sender<Datagram>,
    /// Policy to instantly ban all packets from a Pubkey
    pub(crate) banlist: Arc<Banlist<Pubkey>>,
    /// Policy for which peers may occupy a slot or retain a connection.
    pub(crate) allowlist: Arc<dyn Allowlist>,
    pub(crate) identity_rx: watch::Receiver<Option<Arc<IdentitySnapshot>>>,
    /// Per-peer accepted receive-only connection state, owned solely by this
    /// loop.
    pub(crate) peer_state: HashMap<Pubkey, PeerEntry, PubkeyHasherBuilder>,
    /// Channel for read tasks to report their lifetime events.
    pub(crate) events_tx: mpsc::Sender<InboundEvent>,
    /// Channel for read tasks to report their lifetime events.
    pub(crate) events_rx: mpsc::Receiver<InboundEvent>,
    pub(crate) stats: Arc<QuicDatagramStats>,
    pub(crate) shutdown: CancellationToken,
    /// Sustained datagrams-per-second each peer is allowed to send.
    pub(crate) max_datagrams_per_second_per_peer: f64,
}

impl InboundLoop {
    pub(crate) fn new(
        endpoint: Endpoint,
        ingress: Sender<Datagram>,
        banlist: Arc<Banlist<Pubkey>>,
        allowlist: Arc<dyn Allowlist>,
        identity_rx: watch::Receiver<Option<Arc<IdentitySnapshot>>>,
        stats: Arc<QuicDatagramStats>,
        shutdown: CancellationToken,
        max_datagrams_per_second_per_peer: f64,
    ) -> Self {
        let (events_tx, events_rx) = mpsc::channel::<InboundEvent>(CONN_EVENT_CHANNEL_CAP);
        Self {
            endpoint,
            generation: 0,
            ingress,
            banlist,
            allowlist,
            identity_rx,
            peer_state: HashMap::with_hasher(PubkeyHasherBuilder::default()),
            events_tx,
            events_rx,
            stats,
            shutdown,
            max_datagrams_per_second_per_peer,
        }
    }

    /// Live inbound connections (each pubkey may hold several).
    fn connection_count(&self) -> u64 {
        self.peer_state
            .values()
            .map(|e| e.connections.len())
            .sum::<usize>() as u64
    }

    /// Remove the connection with the given `stable_id` from `peer`'s inbound
    /// set. Keeps the `PeerEntry` so the rate limiter state survives a reconnect.
    /// Entries are reclaimed by the prune task once the rate limiter has refilled.
    fn reap_connection(&mut self, peer: &Pubkey, stable_id: usize) {
        if let Entry::Occupied(mut slot) = self.peer_state.entry(*peer) {
            slot.get_mut()
                .connections
                .retain(|c| c.stable_id() != stable_id);
        }
    }

    pub(crate) async fn run(mut self) {
        let mut prune = interval(BANLIST_PRUNE_INTERVAL);
        prune.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut metrics = interval(METRICS_INTERVAL);
        metrics.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // We pace how fast we pull connection attempts off the endpoint.
        // This prevents quinn from burning CPU resources processing initial
        // keys for handshakes we would not be able to process.
        let mut accept_gate = Box::pin(sleep(Duration::ZERO));
        // Gate starts open.
        let mut accept_allowed = true;

        // TODO: this flag is a workaround for some local-cluster tests that are a
        // nightmare to refactor. But they really should be.
        let mut id_closed = false;
        loop {
            tokio::select! {
                biased;
                changed = self.identity_rx.changed(), if !id_closed => {
                    if changed.is_err() {
                        warn!("identity rotation channel closed; inbound loop running without rotation support");
                        id_closed = true;
                        continue;
                    }
                    let snap = self.identity_rx.borrow_and_update().clone();
                    if let Some(snap) = snap {
                        self.apply_identity_change(snap);
                    }
                }
                // Lifecycle results keep the table coherent; drained above
                // accept so a flood of inbounds can't starve the reaping of
                // dead connections.
                Some(event) = self.events_rx.recv() => self.handle_event(event),
                // Metrics are quite handy to have even if we are flooded with incoming.
                _ = metrics.tick() => stats::report_server(&self.stats, self.connection_count()),
                // Accept gate timer expired, re-open accept
                _ = &mut accept_gate, if !accept_allowed => {
                    accept_allowed = true;
                }
                // We admit Initial only when we're done with everything important.
                maybe_incoming = self.endpoint.accept(), if accept_allowed => {
                    let Some(incoming) = maybe_incoming else { break };
                    self.maybe_accept_connection(incoming);
                    // Shut the gate for one inter-arrival gap so handshake starts
                    // stay bounded by HANDSHAKE_GLOBAL_RATE; the timer branch
                    // above re-opens it.
                    const HANDSHAKE_SLEEP:Duration = Duration::from_micros((1e6 / HANDSHAKE_GLOBAL_RATE)as u64);
                    accept_gate
                        .as_mut()
                        .reset(Instant::now().checked_add(HANDSHAKE_SLEEP).expect("add with bounded operand should never overflow"));
                    accept_allowed = false;
                }
                // When idle we can take care of bookkeeping.
                _ = prune.tick() => {
                    self.banlist.prune();
                    // Reclaim empty connection slots
                    self.peer_state.retain(|_, e| {
                        !e.connections.is_empty()
                            || e.rate_limiter.current_tokens() < PEER_RATE_LIMIT_BURST_DOS
                    });
                }
                // Shutdown is never done in a hurry
                _ = self.shutdown.cancelled() => break,
            }
        }
    }

    /// Rebuild the server TLS config against the new identity, swap it into the
    /// quinn endpoint, and evict the inbound table so peers re-handshake.
    fn apply_identity_change(&mut self, snap: Arc<IdentitySnapshot>) {
        let server_config =
            new_server_config(snap.cert.clone(), snap.key.clone_key(), ALPENGLOW_ALPN);
        self.endpoint.set_server_config(Some(server_config));
        // Bump first so any in-flight accept that completes after this point is
        // dropped at the event boundary (its event carries the old generation).
        self.generation = self.generation.wrapping_add(1);
        let evicted = self
            .peer_state
            .drain()
            .flat_map(|(_, entry)| entry.connections)
            .inspect(|connection| close_codes::IDENTITY_ROTATED.close(connection))
            .count() as u64;
        self.stats
            .connection_evicted_identity_rotated
            .fetch_add(evicted, Ordering::Relaxed);
        info!(
            "inbound identity rotated to {} ({} connection(s) evicted)",
            snap.pubkey, evicted
        );
    }

    /// Apply a connection-lifecycle event.
    fn handle_event(&mut self, event: InboundEvent) {
        match event {
            // Stale Accepted: close the connection.
            InboundEvent::Accepted {
                generation,
                connection,
                ..
            } if generation != self.generation => {
                close_codes::IDENTITY_ROTATED.close(&connection);
                self.stats
                    .connection_evicted_identity_rotated
                    .fetch_add(1, Ordering::Relaxed);
            }
            // Relevant Accepted
            InboundEvent::Accepted {
                peer, connection, ..
            } => self.maybe_admit_connection(peer, connection),
            // Stale Closed: no-op, table entry already gone.
            InboundEvent::Closed { generation, .. } if generation != self.generation => {}
            // Relevant Closed
            InboundEvent::Closed {
                peer, stable_id, ..
            } => self.reap_connection(&peer, stable_id),
            // Flood detected: close all connections but keep the entry as a
            // tombstone so the depleted rate limiter persists on reconnect.
            InboundEvent::FloodDetected { peer } => {
                if let Some(entry) = self.peer_state.get_mut(&peer) {
                    for connection in entry.connections.drain(..) {
                        close_codes::BANNED.close(&connection);
                    }
                    add(&self.stats.connection_lost);
                }
            }
        }
    }

    /// Performs the admission control checks of incoming connection, if
    /// they pass spawns the task to handle the handshake and serve connection.
    /// Caller is responsible for rate-limiting via the accept gate in `run`.
    fn maybe_accept_connection(&mut self, incoming: Incoming) {
        let remote_addr = incoming.remote_address();
        if remote_addr.is_ipv6() || remote_addr.ip().is_multicast() {
            incoming.ignore();
            return;
        }
        // TODO: add Retry challenge here.
        spawn(
            ServerConnection {
                incoming,
                generation: self.generation,
                events: self.events_tx.clone(),
                stats: self.stats.clone(),
            }
            .run(),
        );
    }

    /// Admission checks for a freshly handshaked inbound (we-accepted,
    /// receive-only) connection. The split-direction model has no lex-pubkey
    /// tiebreaker: we accept an inbound from any admitted peer regardless of
    /// pubkey ordering, and install it into the receive-only `peer_state` map.
    fn maybe_admit_connection(&mut self, peer: Pubkey, connection: Connection) {
        if self.banlist.is_banned(&peer) {
            close_codes::BANNED.close(&connection);
            record_error(&Error::Banned(peer), &self.stats);
            return;
        }
        if !self.allowlist.allow(&peer) {
            close_codes::NOT_ADMITTED.close(&connection);
            record_error(&Error::NotAdmitted(peer), &self.stats);
            return;
        }
        let remote_addr = connection.remote_address();
        let rate_limiter = match self.peer_state.entry(peer) {
            Entry::Vacant(slot) => {
                let rate_limiter = Arc::new(TokenBucket::new(
                    PEER_RATE_LIMIT_BURST_DOS,
                    PEER_RATE_LIMIT_BURST_DOS,
                    self.max_datagrams_per_second_per_peer,
                ));
                let mut connections = ArrayVec::new();
                connections.push(connection.clone());
                slot.insert(PeerEntry {
                    connections,
                    rate_limiter: rate_limiter.clone(),
                });
                rate_limiter
            }
            Entry::Occupied(mut slot) => {
                let entry = slot.get_mut();
                match entry.connections.try_push(connection.clone()) {
                    Ok(()) => Arc::clone(&entry.rate_limiter),
                    Err(_) => {
                        close_codes::TABLE_FULL.close(&connection);
                        record_error(&Error::TableFull, &self.stats);
                        return;
                    }
                }
            }
        };
        self.stats.record_connection_count(self.connection_count());
        // The read loop reports [`InboundEvent::Closed`] when it exits so this
        // loop can reap the table slot.
        spawn(read_datagram_loop(
            connection,
            peer,
            remote_addr,
            self.generation,
            self.ingress.clone(),
            self.allowlist.clone(),
            self.banlist.clone(),
            rate_limiter,
            self.events_tx.clone(),
            self.stats.clone(),
        ));
    }
}
