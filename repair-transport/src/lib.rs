//! QUIC transport for Solana repair traffic.
//!
//! Repair is a request/response protocol, so every exchange gets its own
//! bidirectional stream: the requester writes one repair request and finishes
//! its side, the server writes 0..=[`MAX_RESPONSES_PER_REQUEST`] length-prefixed
//! responses back on the same stream and finishes. There is no demultiplexing
//! to do and no MTU ceiling on a response.
//!
//! Peer identity is attested by TLS in both directions (self-signed ed25519
//! certificates, as everywhere else in the validator), which is what lets this
//! transport drop repair's ping/pong address-validation entirely.
#![cfg(feature = "agave-unstable-api")]

pub mod endpoint;
pub mod error;

pub(crate) mod client;
pub(crate) mod framing;
pub(crate) mod server;
pub(crate) mod stats;
pub(crate) mod transport;

pub(crate) use error::close_codes;
use {
    solana_packet::PACKET_DATA_SIZE,
    solana_pubkey::{Pubkey, PubkeyHasherBuilder},
    std::{collections::HashSet, sync::Arc, time::Duration},
    tokio::sync::watch,
};

/// Pubkeys we are willing to serve repair for. Inbound admission is membership
/// only: the address is attested by the connection itself.
pub type KnownPeers = HashSet<Pubkey, PubkeyHasherBuilder>;

/// Readers clone the Arc and release the watch lock immediately.
pub type KnownPeersSnapshot = Arc<KnownPeers>;

pub type KnownPeersSender = watch::Sender<KnownPeersSnapshot>;

pub type KnownPeersReceiver = watch::Receiver<KnownPeersSnapshot>;

/// Largest number of response packets a single repair request can produce.
///
/// The authoritative version of this lives in
/// `solana_core::repair::serve_repair::MAX_ORPHAN_REPAIR_RESPONSES`; this is a
/// deliberate copy to keep `solana-core` out of this crate's dependencies.
pub const MAX_RESPONSES_PER_REQUEST: usize = 11;

/// Repair requests never exceed one packet.
pub const MAX_REQUEST_BYTES: usize = PACKET_DATA_SIZE;

/// Length prefix carried before each response payload on the wire.
pub(crate) const RESPONSE_LENGTH_PREFIX_BYTES: usize = 2;

/// Largest response frame (payload plus its length prefix).
pub(crate) const MAX_RESPONSE_FRAME_BYTES: usize =
    PACKET_DATA_SIZE.saturating_add(RESPONSE_LENGTH_PREFIX_BYTES);

/// Byte budget granted to each peer per second, in both directions.
/// Placeholder pending measurement: 1 Mbps is ~103 shred responses/second,
/// which is far above what a healthy peer asks of a single server.
pub const PEER_RATE_BYTES_PER_SECOND: u64 = 125_000;

/// Bucket capacity, i.e. how much budget a peer can bank while idle.
/// The bucket outlives the connection precisely so that reconnecting does not
/// refill it, so this also bounds what a reconnect can recover.
pub const PEER_RATE_CAP_WINDOW: Duration = Duration::from_secs(10);

/// Minimum budget charged for accepting a stream, whatever the peer then does
/// with it. Mirrors `MIN_RESPONSE_SIZE` on the UDP serve path so that opening
/// streams and writing nothing still drains the opener's own budget.
pub(crate) const MIN_STREAM_COST: u64 = (PACKET_DATA_SIZE + 4) as u64;

/// Concurrent inbound streams allowed per connection. This is what bounds how
/// much work a throttled peer can leave parked on us, and (at high RTT) what
/// bounds an honest peer's request rate.
pub const MAX_CONCURRENT_STREAMS_PER_PEER: u32 = 64;

/// Upper bound on peers holding an inbound connection at once. Sized to a few
/// times the validator set: unlike votor, repair admits anyone gossip knows.
pub const MAX_INBOUND_CONNECTIONS: usize = 4096;

/// Capacity of the channel carrying connection lifecycle events, sized so the
/// whole connection table can churn at once without blocking a reader task.
pub(crate) const CONN_EVENT_CHANNEL_CAP: usize = MAX_INBOUND_CONNECTIONS;

/// Hard timeout on reading one request off an accepted stream.
pub(crate) const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Hard timeout on a whole outbound exchange once the stream is open. Well
/// above `REPAIR_REQUEST_TIMEOUT_MS`, since the requester re-requests on its
/// own schedule and this only exists to reclaim the stream.
pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Sustained rate at which we start inbound TLS handshakes (handshakes/second),
/// consulted before `Endpoint::accept()` so it bounds when we begin handshake
/// crypto at all.
///
/// This is a ceiling, not a rate we sustain. Whenever attempts stop completing
/// promptly [`MAX_INFLIGHT_HANDSHAKES`] may get saturated first, so the achievable
/// rate is [`HANDSHAKE_DRAIN_RATE`]. Size queues from that constant, not this one.
pub const HANDSHAKE_GLOBAL_RATE: usize = 2000;

/// Burst of inbound handshakes tolerated above allowed rate before new attempts
/// are shed. Chosen to align with 200ms at [`HANDSHAKE_GLOBAL_RATE`].
pub(crate) const HANDSHAKE_BURST: u64 = 400;

/// How many instances of `AcceptLoop` to spawn per server endpoint. This
/// controls the max number of cores we dedicate to TLS handshakes, per endpoint.
pub(crate) const HANDSHAKE_WORKERS_PER_ENDPOINT: usize = 1;

/// Hard timeout for an inbound handshake, enforced regardless of what the peer
/// sends. ~1s suffices for a 300ms-RTT handshake with no packet loss, so we use
/// 2s to have margin for losses and retransmits.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum inbound handshakes allowed in flight; once reached we stop pulling
/// new ones off the endpoint. Sized to the most handshakes the rate limiter can
/// admit within one [`HANDSHAKE_TIMEOUT`], so admission is governed by the rate
/// limiter rather than by this cap.
pub const MAX_INFLIGHT_HANDSHAKES: usize =
    HANDSHAKE_GLOBAL_RATE * HANDSHAKE_TIMEOUT.as_millis() as usize / 1000;

/// Rate at which the accept loops actually take connection attempts off the
/// endpoints under sustained load (handshakes/second).
pub(crate) const HANDSHAKE_DRAIN_RATE: usize = {
    let inflight_bound = MAX_INFLIGHT_HANDSHAKES * 1000 / (HANDSHAKE_TIMEOUT.as_millis() as usize);
    if inflight_bound < HANDSHAKE_GLOBAL_RATE {
        inflight_bound
    } else {
        HANDSHAKE_GLOBAL_RATE
    }
};

/// Longest an inbound attempt that we are going to serve may sit queued inside
/// quinn before an accept loop reaches it. A deeper queue does not admit more
/// handshakes (the drain rate is fixed), it only adds latency to the attempts we
/// do serve, so we keep it short and let the excess be shed by quinn.
pub(crate) const MAX_INCOMING_DELAY: Duration =
    Duration::from_millis(HANDSHAKE_BURST * 1000 / HANDSHAKE_GLOBAL_RATE as u64);

/// Consecutive outbound failures against one peer before we stop dialing it and
/// let the caller fall back to UDP repair.
pub const PEER_FAILURES_BEFORE_BACKOFF: u32 = 2;

/// How long a peer stays in backoff. Long enough that a firewalled peer costs a
/// handful of attempts per minute, short enough to recover from a restart.
pub const PEER_BACKOFF: Duration = Duration::from_secs(10);

/// How often the client reconciles its connection table (expiring backoffs,
/// reaping dead connections).
pub(crate) const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

/// How often endpoint metrics are reported.
pub(crate) const METRICS_INTERVAL: Duration = Duration::from_secs(1);

/// ALPN protocol identifier for repair over QUIC.
pub(crate) const REPAIR_ALPN: &[u8] = b"solana-repair-v1";

/// Maximum reasonable number of QUIC endpoints to allow.
pub const MAX_ENDPOINTS: usize = 8;
