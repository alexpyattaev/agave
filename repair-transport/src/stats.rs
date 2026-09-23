use {
    crate::error::Error,
    quinn::ConnectionError,
    solana_metrics::datapoint_info,
    std::sync::atomic::{AtomicU64, Ordering},
};

/// Counters for the outbound (we-request) direction.
#[derive(Default)]
pub struct ClientStats {
    /// High-water mark of live connections over the reporting period.
    pub(crate) peak_connections: AtomicU64,
    /// Requests handed to a peer on a fresh stream.
    pub(crate) requests_sent: AtomicU64,
    /// Requests dropped before reaching a stream: no connection yet, peer in
    /// backoff, or the per-peer pending queue was full.
    pub(crate) requests_dropped: AtomicU64,
    /// Response packets delivered to the caller's channel.
    pub(crate) responses_received: AtomicU64,
    /// Responses dropped because the caller's channel was full.
    pub(crate) responses_dropped_channel_full: AtomicU64,
    /// Exchanges that failed on the stream (write, read, reset, or timeout).
    pub(crate) exchange_failed: AtomicU64,
    /// Responses rejected by the framing decoder.
    pub(crate) response_malformed: AtomicU64,
    /// A connection ended through an expected teardown path.
    pub(crate) connection_lost: AtomicU64,
    /// A connect attempt failed: setup error, protocol fault, or wrong identity.
    pub(crate) connect_failed: AtomicU64,
    /// Peers currently parked in backoff, i.e. served over UDP instead.
    pub(crate) peers_in_backoff: AtomicU64,
    /// Connections closed because the peer's gossip address changed.
    pub(crate) connection_closed_peer_moved: AtomicU64,
    /// Connections closed because the local identity changed.
    pub(crate) connection_closed_identity_changed: AtomicU64,
}

/// Counters for the inbound (we-serve) direction.
#[derive(Default)]
pub struct ServerStats {
    /// High-water mark of live table entries over the reporting period.
    pub(crate) peak_unique_peers: AtomicU64,
    /// Requests delivered to the serve loop.
    pub(crate) requests_received: AtomicU64,
    /// Requests dropped because the serve channel was full.
    pub(crate) requests_dropped_channel_full: AtomicU64,
    /// Streams reset because the request could not be read.
    pub(crate) request_read_failed: AtomicU64,
    /// Response frames written back to peers.
    pub(crate) responses_sent: AtomicU64,
    /// Bytes written back to peers.
    pub(crate) response_bytes_sent: AtomicU64,
    /// Times a peer's budget ran dry and we stopped reading its streams.
    pub(crate) peer_rate_limited: AtomicU64,
    /// A connection ended through an expected teardown path.
    pub(crate) connection_lost: AtomicU64,
    /// A connection failed abnormally during accept, handshake, or read.
    pub(crate) connection_failed: AtomicU64,
    /// Inbound handshakes we began TLS work for.
    pub(crate) handshakes_started: AtomicU64,
    /// Inbound TLS handshakes that completed and yielded an authenticated peer.
    pub(crate) handshakes_completed: AtomicU64,
    /// Handshake refused because the peer is not permitted: unknown to gossip,
    /// or currently banned.
    pub handshake_rejected_unauthorized: AtomicU64,
    /// Handshake refused due to a resource limit: connection table full.
    pub(crate) handshake_rejected_overload: AtomicU64,
    /// Inbound attempts shed because the global handshake rate limit was
    /// exhausted (and the accept gate was closed until it refills).
    pub(crate) handshake_rate_limited: AtomicU64,
    /// Handshakes that did not complete within `HANDSHAKE_TIMEOUT`.
    pub(crate) handshake_timed_out: AtomicU64,
    /// Connections retired because the same pubkey dialed us again.
    pub(crate) connection_replaced: AtomicU64,
    /// Connections closed because the peer left gossip.
    pub(crate) connection_closed_unknown_peer: AtomicU64,
    /// Connections closed because the peer was banned.
    pub connection_closed_banned: AtomicU64,
    /// Connections closed because the local identity changed.
    pub(crate) connection_closed_identity_changed: AtomicU64,
}

/// Raise a peak-occupancy high-water mark to `count` if it is higher.
pub(crate) fn record_connection_count(peak: &AtomicU64, count: u64) {
    peak.fetch_max(count, Ordering::Relaxed);
}

/// Route an outbound-direction error into the client counters.
pub(crate) fn record_client_error(err: &Error, stats: &ClientStats) {
    match err {
        Error::Connection(
            ConnectionError::ApplicationClosed(_)
            | ConnectionError::ConnectionClosed(_)
            | ConnectionError::LocallyClosed
            | ConnectionError::Reset
            | ConnectionError::TimedOut,
        ) => {
            stats.connection_lost.fetch_add(1, Ordering::Relaxed);
        }
        Error::Connect(_)
        | Error::Connection(
            ConnectionError::TransportError(_)
            | ConnectionError::VersionMismatch
            | ConnectionError::CidsExhausted,
        )
        | Error::InvalidIdentity(_)
        | Error::WrongIdentity { .. } => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        }
        Error::Framing(_) => {
            stats.response_malformed.fetch_add(1, Ordering::Relaxed);
        }
        Error::Write(_) | Error::Read(_) | Error::Timeout(_) => {
            stats.exchange_failed.fetch_add(1, Ordering::Relaxed);
        }
        Error::NotAdmitted(_)
        | Error::Banned(_)
        | Error::TooManyConnections
        | Error::Endpoint(_) => {
            debug_assert!(false, "outbound direction does not produce {err:?}");
        }
    }
}

/// Route an inbound-direction error into the server counters.
pub(crate) fn record_server_error(err: &Error, stats: &ServerStats) {
    match err {
        Error::Connection(
            ConnectionError::ApplicationClosed(_)
            | ConnectionError::ConnectionClosed(_)
            | ConnectionError::LocallyClosed
            | ConnectionError::Reset
            | ConnectionError::TimedOut,
        ) => {
            stats.connection_lost.fetch_add(1, Ordering::Relaxed);
        }
        Error::Connection(
            ConnectionError::TransportError(_)
            | ConnectionError::VersionMismatch
            | ConnectionError::CidsExhausted,
        )
        | Error::InvalidIdentity(_) => {
            stats.connection_failed.fetch_add(1, Ordering::Relaxed);
        }
        Error::Read(_) | Error::Write(_) | Error::Timeout(_) => {
            stats.request_read_failed.fetch_add(1, Ordering::Relaxed);
        }
        Error::NotAdmitted(_) | Error::Banned(_) => {
            stats
                .handshake_rejected_unauthorized
                .fetch_add(1, Ordering::Relaxed);
        }
        Error::TooManyConnections => {
            stats
                .handshake_rejected_overload
                .fetch_add(1, Ordering::Relaxed);
        }
        Error::Connect(_)
        | Error::Framing(_)
        | Error::WrongIdentity { .. }
        | Error::Endpoint(_) => {
            debug_assert!(false, "inbound direction does not produce {err:?}");
        }
    }
}

/// Read and reset a counter, returns the old value.
fn swap(metric: &AtomicU64) -> i64 {
    metric.swap(0, Ordering::Relaxed) as i64
}

/// Re-baseline the peak to the current value, returns the peak over period just observed.
fn take_peak(peak: &AtomicU64, live: u64) -> i64 {
    peak.swap(live, Ordering::Relaxed).max(live) as i64
}

impl ClientStats {
    /// Emit and reset the outbound counters.
    pub(crate) fn report(&self, live_connections: u64, peers_in_backoff: u64) {
        // Snapshot and reset every counter unconditionally, *before* `datapoint_info!`
        // so we do not end up with huge values here when operator changes log level.
        let connections_peak = take_peak(&self.peak_connections, live_connections);
        self.peers_in_backoff
            .store(peers_in_backoff, Ordering::Relaxed);
        let requests_sent = swap(&self.requests_sent);
        let requests_dropped = swap(&self.requests_dropped);
        let responses_received = swap(&self.responses_received);
        let responses_dropped_channel_full = swap(&self.responses_dropped_channel_full);
        let exchange_failed = swap(&self.exchange_failed);
        let response_malformed = swap(&self.response_malformed);
        let connect_failed = swap(&self.connect_failed);
        let connection_lost = swap(&self.connection_lost);
        let connection_closed_peer_moved = swap(&self.connection_closed_peer_moved);
        let connection_closed_identity_changed = swap(&self.connection_closed_identity_changed);
        datapoint_info!(
            "repair_quic_client",
            ("connections_peak", connections_peak, i64),
            ("peers_in_backoff", peers_in_backoff as i64, i64),
            ("requests_sent", requests_sent, i64),
            ("requests_dropped", requests_dropped, i64),
            ("responses_received", responses_received, i64),
            (
                "responses_dropped_channel_full",
                responses_dropped_channel_full,
                i64
            ),
            ("exchange_failed", exchange_failed, i64),
            ("response_malformed", response_malformed, i64),
            ("connect_failed", connect_failed, i64),
            ("connection_lost", connection_lost, i64),
            (
                "connection_closed_peer_moved",
                connection_closed_peer_moved,
                i64
            ),
            (
                "connection_closed_identity_changed",
                connection_closed_identity_changed,
                i64
            ),
        );
    }
}

impl ServerStats {
    /// Emit and reset the inbound counters.
    pub(crate) fn report(&self, live_connections: u64) {
        // Snapshot-and-reset every counter unconditionally, *before* `datapoint_info!`.
        let unique_peers_peak = take_peak(&self.peak_unique_peers, live_connections);
        let requests_received = swap(&self.requests_received);
        let requests_dropped_channel_full = swap(&self.requests_dropped_channel_full);
        let request_read_failed = swap(&self.request_read_failed);
        let responses_sent = swap(&self.responses_sent);
        let response_bytes_sent = swap(&self.response_bytes_sent);
        let peer_rate_limited = swap(&self.peer_rate_limited);
        let handshakes_started = swap(&self.handshakes_started);
        let handshakes_completed = swap(&self.handshakes_completed);
        let connection_failed = swap(&self.connection_failed);
        let connection_lost = swap(&self.connection_lost);
        let handshake_rejected_unauthorized = swap(&self.handshake_rejected_unauthorized);
        let handshake_rejected_overload = swap(&self.handshake_rejected_overload);
        let handshake_rate_limited = swap(&self.handshake_rate_limited);
        let handshake_timed_out = swap(&self.handshake_timed_out);
        let connection_replaced = swap(&self.connection_replaced);
        let connection_closed_unknown_peer = swap(&self.connection_closed_unknown_peer);
        let connection_closed_banned = swap(&self.connection_closed_banned);
        let connection_closed_identity_changed = swap(&self.connection_closed_identity_changed);
        datapoint_info!(
            "repair_quic_server",
            ("unique_peers_peak", unique_peers_peak, i64),
            ("requests_received", requests_received, i64),
            (
                "requests_dropped_channel_full",
                requests_dropped_channel_full,
                i64
            ),
            ("request_read_failed", request_read_failed, i64),
            ("responses_sent", responses_sent, i64),
            ("response_bytes_sent", response_bytes_sent, i64),
            ("peer_rate_limited", peer_rate_limited, i64),
            ("handshakes_started", handshakes_started, i64),
            ("handshakes_completed", handshakes_completed, i64),
            ("connection_failed", connection_failed, i64),
            ("connection_lost", connection_lost, i64),
            (
                "handshake_rejected_unauthorized",
                handshake_rejected_unauthorized,
                i64
            ),
            (
                "handshake_rejected_overload",
                handshake_rejected_overload,
                i64
            ),
            ("handshake_rate_limited", handshake_rate_limited, i64),
            ("handshake_timed_out", handshake_timed_out, i64),
            ("connection_replaced", connection_replaced, i64),
            (
                "connection_closed_unknown_peer",
                connection_closed_unknown_peer,
                i64
            ),
            ("connection_closed_banned", connection_closed_banned, i64),
            (
                "connection_closed_identity_changed",
                connection_closed_identity_changed,
                i64
            ),
        );
    }
}
