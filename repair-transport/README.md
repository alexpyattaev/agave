# agave-repair-transport

QUIC transport for repair traffic (shred repair, ancestor hashes, block-id
repair). It runs alongside UDP repair, never instead of it, and is gated on
`agave-unstable-api`.

This document explains why the transport looks the way it does. Most choices
below were made against a concrete failure mode, either from UDP repair or from
the first QUIC repair implementation, and the reasoning is the part that is not
recoverable from the code.

## Background

UDP repair has three structural problems:

- **Responses are untyped.** A shred repair response is
  `data_shred_bytes || nonce_u32_le`. The only thing telling a receiver what
  kind of response it got is which socket it arrived on, which is why repair
  needs separate `repair`, `ancestor_hashes_requests` and `block_id_repair`
  sockets.
- **Senders are unauthenticated.** A signed request covers `sender`,
  `recipient`, `timestamp` and `nonce`, but not the source address, so any
  observed request can be replayed from anywhere for the full 10 minute
  `SIGNED_REPAIR_TIME_WINDOW`. One ~130 byte `Orphan` request yields up to 11
  full packets, so a replay is a reflected-amplification primitive. Ping/pong
  address validation is the only thing stopping that, and it costs an RTT on
  first contact.
- **Loss is expensive.** A lost UDP response costs a full
  `REPAIR_REQUEST_TIMEOUT_MS` (150 ms) re-request cycle plus peer
  re-selection.

A QUIC repair path existed from #33057 (2023) until #10460 (2026), when it was
deleted as dead code: `get_repair_protocol()` had been hard-wired to UDP since
#34523 and nothing ever noticed. Beyond being unreachable, it had unbounded task
spawn per connection, no handshake rate limit, `KeyLogFile` enabled, huge
datagram buffers, `try_send(..).unwrap()`, a single channel error closing the
whole endpoint, and an async `RwLock` on the hot path. Several decisions below
exist specifically so this crate cannot rot the same way.

`agave-votor-transport` is the structural reference: its accept loop, handshake
budgeting, identity rotation and teardown discipline are copied closely. It is
not reusable directly, because it is broadcast-only, datagram-only,
unidirectional and closed-membership, and repair is none of those.
`solana-streamer`'s QUIC server is deliberately not used either: its
staked/unstaked stream-throttling machinery solves a TPU ingest problem, not a
request/response one. Stake still matters here, but as a share of response
bytes rather than of stream counts (see below).

## Wire format: one bidirectional stream per exchange

The requester opens a bidi stream, writes one raw repair request (at most
`PACKET_DATA_SIZE`) and finishes its side. The server writes
0..=`MAX_RESPONSES_PER_REQUEST` (11) frames back on the same stream, each a
little-endian `u16` length followed by the payload, then FIN. All wire-format
code is in `framing.rs`.

Why streams and not datagrams:

- **Correlation is free.** The response returns on the stream that carried the
  request, so there is nothing to demultiplex and no per-response-class
  endpoints. The old datagram design needed three sockets for exactly this.
- **No MTU ceiling.** Repaired data shreds (1203 B + 4 B nonce) fit a 1280-MTU
  QUIC datagram with ~13 bytes to spare; coding shreds would not. Streams make
  that margin irrelevant.
- **Loss recovery is QUIC's.** A lost packet is retransmitted in ~1 RTT instead
  of costing a 150 ms re-request.

Why `u16` length prefixes: a repair response never exceeds one packet. The
implementation this replaces spent a bincode fixint `u64` on the same job.

Why zero frames is a valid response: dropping a `Responder` finishes the stream
empty, and the requester reads that as a blockstore miss. That is exactly what
UDP repair does by staying silent, so the serve path needs no new "not found"
signal.

Every byte the decoder sees is peer-controlled, so `decode_responses` rejects
rather than asserts and is fuzzed for panics. Framing violations close the
connection with `PROTOCOL_VIOLATION`: a peer that mis-frames is broken or
hostile, and nothing else it sends on that connection can be trusted.

### Stream direction is enforced by quinn, not by us

The server allows `MAX_CONCURRENT_STREAMS_PER_PEER` bidi streams from the peer;
the client allows zero. Uni streams and datagrams are disabled on both sides.
So a server that tries to open a stream to a requester is refused by QUIC flow
control, rather than by code that has to notice and close it after the fact.

Receive windows come straight from the protocol: the server's per-stream window
is one request (`MAX_REQUEST_BYTES`), the client's is 11 full frames. Read caps
are clamped the same way, so a peer-supplied `num_expected_responses` can never
size an unbounded read.

0-RTT is disabled on both sides. Early data is replayable, which is precisely
the property this transport exists to remove.

## Identity replaces ping/pong

Both sides present self-signed ed25519 certificates
(`solana_tls_utils::new_dummy_x509_certificate`), and `get_remote_pubkey`
extracts the attested pubkey. The transport stamps it into
`Meta::remote_pubkey` on every packet it hands to core, and that field is how
core tells a QUIC packet from a UDP one (the UDP path never sets it). No new
`PacketFlags` bit and no revived `RemoteRequest` type were needed.

That attestation is what lets QUIC repair skip ping/pong entirely, but only
because of a check that lives in core: `ServeRepair::decode_request` **rejects**
any request whose signed `sender` disagrees with the attested pubkey
(`RepairVerifyError::PubkeyMismatch`). The old implementation only logged this.
Without the rejection, QUIC would reintroduce the replay/amplification hole
that ping/pong closes on UDP, just with TLS wrapped around it. The check and the
ping skip are one change; neither is safe alone.

The client side is symmetric: after the handshake it verifies the server
attested the pubkey it meant to dial (`Error::WrongIdentity`). A server that
answers on an advertised address but cannot prove it holds that peer's key is
not a peer we repair from.

Pings are never sent over QUIC, so a ping arriving on the QUIC path is a buggy
or hostile peer. Core drops it rather than answering: the pong would go out
over UDP to an address nobody validated, which is a free amplification lever.
This is why `ShredFetchStage` gained a `ShredIngress::RepairQuic` variant with
no socket to pong on, and why `ancestor_hashes_service` drops pings carrying a
remote pubkey. A `Pong` request over QUIC is rejected as malformed for the same
reason.

## Server

### Admission

Order: address filter, handshake, banlist, gossip membership, unstaked
connection cap.

- **Pre-handshake address filter.** IPv6, multicast, our own IP (on
  `SocketAddrSpace::Global`) and anything `SocketAddrSpace` rejects are
  dropped with `incoming.ignore()` before any crypto, so nothing is sent back.
- **Handshake budget.** Copied from votor. A token bucket
  (`HANDSHAKE_GLOBAL_RATE`, `HANDSHAKE_BURST`) gates when `accept()` is even
  called, `MAX_INFLIGHT_HANDSHAKES` bounds concurrent handshakes, and every
  handshake has a hard `HANDSHAKE_TIMEOUT` regardless of what the peer sends.
  `MAX_INFLIGHT_HANDSHAKES` is sized to what the limiter can admit in one
  timeout, so the limiter governs admission and the cap only matters when
  handshakes stall. quinn's incoming queue is sized from the *drain* rate over
  `MAX_INCOMING_DELAY`: a deeper queue admits nothing more, it only adds
  latency to the attempts we do serve.
- **All budgets are divided across accept loops.** That keeps the aggregate
  equal to what the constant says. `MAX_ENDPOINTS` exists because a zero share
  would build a zero-capacity `TokenBucket`, which panics on first use.
- **Gossip membership.** A peer must be in the `KnownPeers` snapshot to be
  served, and connections from peers that drop out of gossip are closed. The
  snapshot is the pubkeys from `ClusterInfo::tvu_peers`, each tagged with its
  stake in the root bank's epoch stakes, refreshed every second. This is wider
  than votor's closed peer list and narrower than UDP repair, which serves
  anyone who answers a ping. A node not yet in our CRDS falls back to UDP,
  which is still there.
- **Stake comes in with membership.** Core pushes stakes through the same
  watch channel instead of the crate reading `StakedNodes`. That keeps
  streamer and runtime out of this crate, and avoids `StakedNodes`'s startup
  hole: it is only populated by a service the TPU starts, well after the repair
  server is already accepting connections.
- **Staked peers are always admitted; unstaked peers share
  `MAX_UNSTAKED_INBOUND_CONNECTIONS` (500).** Gossip membership is free to
  forge, so on its own it does not bound the table; stake is the only
  Sybil-resistant signal we have. The staked population is already bounded by
  the epoch stake set, so it needs no cap and no eviction, and no number of
  unstaked identities can push a staked peer out. Unstaked peers (RPC nodes,
  fresh validators) get a fixed pool on a first-come basis. A redial of a live
  connection does not need a new slot. A peer that loses its stake at an epoch
  boundary keeps its connection and is simply counted as unstaked, so the pool
  can briefly overshoot; new unstaked admissions wait until it drains.

### One connection per pubkey, and redial replaces

A second connection from the same pubkey replaces the first (closed with
`REPLACED`) rather than being refused. Refusing would lock a restarting
validator out for a full idle timeout behind its own stale connection.
Replacement is only safe because of the next point.

### The per-peer budget outlives the connection

Each peer has one `TokenBucket` denominated in bytes, with capacity
`PEER_RATE_CAP_WINDOW` worth of its rate. It lives in the `PeerEntry`, not the
connection, and the entry is kept as a
tombstone after the connection closes until the bucket has refilled. If the
bucket were created on admission, a peer that drained it would simply reconnect
for a free refill, making the whole QoS story a no-op against anyone willing to
redial. This is the same retain rule votor uses, and it matters more here
because the bucket is the main per-peer protection rather than a backstop.

The rate depends on stake. Unstaked peers get a flat
`PEER_RATE_BYTES_PER_SECOND`. Staked peers get their stake share of
`GLOBAL_RATE_BYTES_PER_SECOND`, never less than an unstaked peer. Repair demand
from staked peers scales with stake, so a flat rate would either starve large
validators or hand every small one a budget it cannot use. The floor
keeps a small validator that is catching up from being worse off than an RPC
node. A bucket's rate is fixed at construction, so when stakes move at an
epoch boundary the budget is swapped through an `ArcSwap`, carrying the
remaining tokens over so the swap is never a refill.

### A global budget, staked first

The per-peer buckets bound each peer, but not their sum, and the sum is what
the server actually pays for in bandwidth and blockstore reads. So there is
one more `TokenBucket` (`GLOBAL_RATE_BYTES_PER_SECOND`, capacity
`GLOBAL_RATE_CAP_WINDOW` worth) shared by every connection, and every stream is
charged to both its peer's bucket and this one.

Staked and unstaked peers see different floors on the shared bucket. A staked
peer may take a stream as long as one `MIN_STREAM_COST` is left. An unstaked
peer may only take one while a `1 / UNSTAKED_GLOBAL_HEADROOM_DIVISOR` share of
the capacity is still unused. Because the staked rates add up to roughly
the global rate, staked demand at its entitled level keeps the bucket below the unstaked
floor and unstaked peers wait. When staked peers ask for less, the bucket
refills past the floor and unstaked peers are served from what is left. This
gives a strict priority without a scheduler or a second queue: the gate is the
same "stop calling `accept_bi`" backpressure as the per-peer one. A connection
parked on the global bucket wakes after a short per-connection jitter, so
throttled connections do not all retry at the same moment.

QUIC keeps its own global budget rather than sharing the UDP serve path's.
UDP's bucket is local to its listen thread, and coupling the two would let a
flood on either transport starve the other. The node-wide repair egress is
therefore the sum of the two caps.

Charging is two-stage:

- `MIN_STREAM_COST` (one packet plus nonce, mirroring UDP's
  `MIN_RESPONSE_SIZE`) is charged when a stream is accepted, so a peer that
  opens streams and writes nothing still drains its own budget.
- The actual encoded response bytes are charged when the response is written.

Charging actual response bytes in the transport is what spared core from
threading a cost model through `ServeRepair`: on a bidi stream the transport
sees exactly what each request cost to answer.

When a peer is over budget the connection simply stops calling `accept_bi`.
QUIC's `MAX_STREAMS` flow control then applies backpressure: no close, no ban,
and the peer recovers with no state change once the bucket refills. Closing
would cost both sides a handshake and, for an honest peer catching up, would
convert a brief burst into a reconnect storm. `MAX_CONCURRENT_STREAMS_PER_PEER`
bounds how much work a throttled peer can leave parked on us.

### Serving is non-blocking

`Responder::respond` is a `oneshot` send, safe from a synchronous thread and
never blocking. The old implementation used `blocking_send` onto a
flow-controlled stream, which let one slow peer stall the serve thread. Request
handoff to core is `try_send` into a bounded channel; a full channel resets the
stream with `OVERLOADED`, and the requester re-requests on its own timer, as
with any lost UDP response.

### Core uses a separate serve loop

`core::repair::serve_repair_quic_service` runs its own thread instead of
feeding UDP's `run_listen`. The UDP loop is built around a blocking batch
receive (a QUIC request would wait up to 1 s whenever UDP is idle) and its own
ping/pong handling, neither of which applies. Both loops share `ServeRepair`'s
decode, verification and `handle_repair`, so acceptance rules are not
duplicated; only the batching and ping machinery differ.

## Client

### Routing is data, not a selector enum

`ServeRepair` returns `RepairTarget::{Udp(addr), Quic { pubkey, addr,
num_expected_responses }}`, resolved per peer from gossip, instead of reviving a
global `Protocol` selector. The previous QUIC path became invisible dead code
precisely because the selector was a hard-wired enum nobody exercised. UDP
remains a hard requirement for a peer to be selected at all, so QUIC is always a
per-peer upgrade, never a floor.

### Per-peer circuit breaker

`PEER_FAILURES_BEFORE_BACKOFF` consecutive connect or exchange failures put a
peer in backoff for `PEER_BACKOFF`, during which callers route it over UDP. The
backoff set is published through an `ArcSwap`, so `is_backing_off` is a
lock-free load cheap enough to call per request. Without this, a peer that
advertises a firewalled QUIC port burns a full repair timeout on every
attempt, forever. That failure mode is what the placeholder port described
below was originally invented to paper over.

### Connection setup never blocks sending

Requests for a peer that is still handshaking queue on that peer (at most
`MAX_PENDING_REQUESTS_PER_PEER`), so a slow handshake to one peer never blocks
requests to others. The queue is short on purpose: repair re-requests on its own
timer, so a deep queue would only deliver stale requests. A peer whose gossip
address changes is redialed (`PEER_MOVED`).

### Responses reuse the UDP acceptance path

The 4-byte nonce stays in QUIC responses, which are therefore byte-identical to
UDP ones. `OutboundRepairRequest::responses` is a clone of the existing response
channel for that repair kind (shred, ancestor hashes, block id), so QUIC
responses enter the pipeline at the same point as UDP ones and go through the
same `verify_repair_nonce` / `register_response` / `verify_response` path.

This is structural, not conservative. `verify_response` is reachable only
through `register_response`, which also enforces expiry and the
`num_expected_responses` decrement (an `Orphan` legitimately consumes up to 11
responses against one nonce). Every repair bug in that area so far has been an
acceptance-criteria bug, so a second, stream-correlated acceptance
implementation would invite the same class again. Stream correlation is used
only for routing, timeouts and the circuit breaker.

Carrying the response channel per request also means the client needs no
demultiplexing, and one client serves all three repair kinds.

## Gossip advertisement

The QUIC repair address uses the existing `serve_repair(Protocol::QUIC)`
contact-info slot. Every node already advertises port `1` there as a
placeholder, kept so legacy nodes do not conclude a node has no repair ports.
This crate treats port 1 as "not serving" (`UNADVERTISED_REPAIR_QUIC_PORT` in
core), and the validator overwrites it with the real port only after the server
is bound and running. So a non-placeholder port means "I am serving now", and no
gossip wire change, new socket tag or version gating is needed. Version gating
was rejected outright because it breaks on other clients.

## Sockets, runtime and rotation

- **Client and server are separate endpoints on separate sockets.** Their
  traffic patterns share nothing, and either can be disabled independently.
- **The client socket is not the UDP `repair` socket.** That socket has an
  AF_XDP TX path spoofing its source port, and running quinn on it would be a
  connection-ID and path-validation mess. UDP repair, including its XDP sender,
  is untouched and remains the fallback leg.
- **One server endpoint.** The votor measurement found extra endpoints buy
  nothing at nominal load (2.7% total spread across 1/2/4 endpoints), so there
  is no knob. The API takes a `Vec` so SO_REUSEPORT fan-out stays possible.
- **Own tokio runtime.** Repair QUIC gets a small dedicated runtime so its
  handshake crypto cannot starve, or be starved by, other async work.
- **Identity rotation** follows votor: `KeyUpdateNotifier` pushes the new key
  to each loop and blocks until all ack, the loops rebuild TLS configs and close
  connections established under the old identity (`IDENTITY_CHANGED`). Both
  server and client notifiers are registered in `KeyUpdaterType`; missing one
  would keep serving repair under the old certificate until connections idle
  out.
- **Teardown** is idempotent `stop()` plus consuming `join()` under one shared
  deadline. `Drop` only exists under `cfg(test, dev-context-only-utils)`, to
  catch tests that forget `join()` and would otherwise let tokio swallow a
  panic.

Close codes and stream reset codes are wire format: adding one is fine,
changing an existing value is a protocol break, and
`test_close_codes_are_frozen` guards that.

## Rollout: `--repair-quic off|enabled|required`

Hidden flag, default `off`.

- `enabled` brings up both endpoints, advertises the port, and repairs over
  QUIC from peers that advertise it, falling back to UDP per peer.
- `required` ignores the circuit breaker for peers advertising QUIC. It exists
  so tests can prove the QUIC path was actually used. Without it, every QUIC
  test silently passes over UDP, which is how the old path rotted unnoticed for
  years.

When the flag is eventually retired it must move into
`validator/src/cli.rs::deprecated_arguments()`.

## Open questions

These are deliberately unresolved in the prototype and should be settled with
measurements before the default flips.

- **Does it win at all?** The hypothesis is a tail-latency win (p95/p99 of
  request-to-insert) only where UDP response loss is material; p50 should be no
  better, since QUIC pays a handshake on first contact. Measured UDP response
  loss (accepted responses vs. sent) is the falsifier: if it is under ~0.5%,
  latency cannot be the justification, and the case has to stand on per-peer
  fairness and the removed amplification surface instead.
- **One stream per request at catch-up rates.** A catching-up node can emit up
  to `MAX_REPAIR_LENGTH` requests per `REPAIR_MS` iteration. Stream-open rate
  at that load is unmeasured; batching several requests per stream is the
  escape hatch.
- **Constants are placeholders.** `PEER_RATE_BYTES_PER_SECOND`,
  `PEER_RATE_CAP_WINDOW`, `GLOBAL_RATE_BYTES_PER_SECOND`,
  `UNSTAKED_GLOBAL_HEADROOM_DIVISOR` and `MAX_UNSTAKED_INBOUND_CONNECTIONS` need
  sizing from measured honest catch-up bursts.
- **No leader multiplier.** The UDP path charges 10x per byte while we are
  leader; the QUIC global budget does not, so a leader pays full QUIC repair
  egress during its slots.
- **No minimum stake.** Any non-zero stake counts as staked, so dust-staked
  identities bypass the unstaked connection cap at the cost of a vote account
  each. Their per-peer rate is the floor, but they get
  staked priority on the global budget. If this shows up in
  practice, swqos-style reclassification of very low stake as unstaked is the
  fix.
- **Read amplification is not priced.** The budget charges bytes written, but
  `ParentAndFecSetCount` / `FecSetRoot` can read ~220 KB of
  `double_merkle_meta` to return ~1.2 KB, and `AncestorHashes` walks up to 30
  slot metas. A per-variant cost estimate in core would close this.
- **Bootstrap.** A node that is not yet in our CRDS cannot be served over QUIC.
  It falls back to UDP, but this should be confirmed on fresh and restarted
  nodes.
