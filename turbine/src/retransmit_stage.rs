//! The `retransmit_stage` retransmits shreds between validators

use {
    crate::{
        XdpSender,
        addr_cache::AddrCache,
        cluster_nodes::{
            ClusterNodes, ClusterNodesCache, DATA_PLANE_FANOUT, Error, MAX_NUM_TURBINE_HOPS,
        },
    },
    agave_votor::event::VotorEvent,
    agave_votor_messages::migration::MigrationStatus,
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError, bounded},
    lru::LruCache,
    rand::Rng,
    rayon::{ThreadPool, ThreadPoolBuilder, prelude::*},
    solana_clock::Slot,
    solana_gossip::cluster_info::ClusterInfo,
    solana_leader_schedule::NUM_CONSECUTIVE_LEADER_SLOTS,
    solana_ledger::{
        leader_schedule_cache::LeaderScheduleCache,
        shred::{self, ShredFlags, ShredId, ShredType},
    },
    solana_measure::measure::Measure,
    solana_perf::deduper::Deduper,
    solana_pubkey::Pubkey,
    solana_rpc::{
        max_slots::MaxSlots, rpc_subscriptions::RpcSubscriptions,
        slot_status_notifier::SlotStatusNotifier,
    },
    solana_rpc_client_api::response::SlotUpdate,
    solana_runtime::{
        bank::{Bank, MAX_LEADER_SCHEDULE_STAKES},
        bank_forks::BankForks,
    },
    solana_streamer::sendmmsg::{SendPktsError, multi_target_send},
    solana_time_utils::timestamp,
    std::{
        collections::{HashMap, HashSet},
        net::{SocketAddr, UdpSocket},
        ops::AddAssign,
        sync::{
            Arc, Mutex, RwLock,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

const MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_NUM_BITS: u64 = 637_534_199; // 76MB
const DEDUPER_RESET_CYCLE: Duration = Duration::from_secs(5 * 60);
// Minimum number of shreds to use rayon parallel iterators for the
// speculative address-cache precompute (see cache_retransmit_addrs).
const PAR_ITER_MIN_NUM_SHREDS: usize = 2;
// How often the housekeeping thread runs periodic maintenance (metrics
// submission cadence check, deduper reset check, address-cache precompute).
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_millis(50);
// How long a retransmit worker sleeps after finding no work, rather than
// blocking on the channel — keeps wake latency low and bounded.
const WORKER_IDLE_SLEEP: Duration = Duration::from_millis(1);

const _: () = const {
    // From https://github.com/anza-xyz/agave/pull/1735#discussion_r1644899183:
    // 1. There must be at least two epochs because near an epoch boundary you might receive
    //    shreds from the other side of the epoch boundary.
    // 2. It does not make sense to have capacity more than the number of epoch-stakes in Bank.
    assert!(CLUSTER_NODES_CACHE_NUM_EPOCH_CAP >= 2);
    assert!(CLUSTER_NODES_CACHE_NUM_EPOCH_CAP <= MAX_LEADER_SCHEDULE_STAKES as usize);
};
const CLUSTER_NODES_CACHE_NUM_EPOCH_CAP: usize = MAX_LEADER_SCHEDULE_STAKES as usize;
const CLUSTER_NODES_CACHE_TTL: Duration = Duration::from_secs(5);

// Output of fn process_shred(...).
struct RetransmitShredOutput {
    shred: ShredId,
    // If the shred has ShredFlags::LAST_SHRED_IN_SLOT.
    last_shred_in_slot: bool,
    // This node's distance from the turbine root.
    root_distance: u8,
    // Number of nodes the shred was retransmitted to.
    num_nodes: usize,
    // Addresses the shred was sent to if there was a cache miss.
    addrs: Option<Box<[SocketAddr]>>,
}

#[derive(Default)]
pub(crate) struct RetransmitSlotStats {
    asof: u64,   // Latest timestamp struct was updated.
    outset: u64, // 1st shred retransmit timestamp.
    // Maximum code and data indices observed.
    pub(crate) max_index_code: u32,
    pub(crate) max_index_data: u32,
    // If any of the shreds had ShredFlags::LAST_SHRED_IN_SLOT.
    pub(crate) last_shred_in_slot: bool,
    // Number of shreds sent and received at different
    // distances from the turbine broadcast root.
    pub(crate) num_shreds_received: [usize; MAX_NUM_TURBINE_HOPS],
    num_shreds_sent: [usize; MAX_NUM_TURBINE_HOPS],
    // Root distance and socket-addresses the shreds were sent to if there was
    // a cache miss.
    pub(crate) addrs: Vec<(ShredId, /*root_distance:*/ u8, Box<[SocketAddr]>)>,
}

// Counters and per-slot bookkeeping shared by every retransmit worker and
// the housekeeping thread. Fields workers touch on the hot path are plain
// atomics; slot_stats is a Mutex since LruCache mutates its internal LRU
// order on every access (a RwLock would not help).
struct RetransmitStats {
    addr_cache_hit: AtomicUsize,
    addr_cache_miss: AtomicUsize,
    num_nodes: AtomicUsize,
    num_addrs_failed: AtomicUsize,
    num_shreds_dropped_xdp_full: AtomicUsize,
    num_loopback_errs: AtomicUsize,
    num_shreds: AtomicUsize,
    num_shreds_skipped: AtomicUsize,
    retransmit_total: AtomicU64,
    compute_turbine_peers_total: AtomicU64,
    unknown_shred_slot_leader: AtomicUsize,
    slot_stats: Mutex<LruCache<Slot, RetransmitSlotStats>>,
}

struct RetransmitNotifiers {
    rpc_subscriptions: Option<Arc<RpcSubscriptions>>,
    slot_status_notifier: Option<SlotStatusNotifier>,
    migration_status: Arc<MigrationStatus>,
    votor_event_sender: Sender<VotorEvent>,
}

// Everything a retransmit worker or the housekeeping thread needs, owned
// once and shared via a single Arc. Every piece here is either internally
// synchronized already (ShredDeduper, LeaderScheduleCache,
// ClusterNodesCache, BankForks) or wrapped here (AddrCache, RetransmitStats,
// pending_first_shred_event).
struct RetransmitShared {
    bank_forks: Arc<RwLock<BankForks>>,
    leader_schedule_cache: Arc<LeaderScheduleCache>,
    cluster_info: Arc<ClusterInfo>,
    cluster_nodes_cache: ClusterNodesCache<RetransmitStage>,
    shred_deduper: ShredDeduper,
    addr_cache: RwLock<AddrCache>,
    stats: RetransmitStats,
    max_slots: Arc<MaxSlots>,
    notifiers: RetransmitNotifiers,
    pending_first_shred_event: Mutex<Option<VotorEvent>>,
}

struct ShredDeduper<const K: usize = 2> {
    deduper: Deduper<K, /*shred:*/ [u8]>,
    shred_id_filter: Deduper<K, (ShredId, /*0..MAX_DUPLICATE_COUNT:*/ usize)>,
}

impl<const K: usize> ShredDeduper<K> {
    fn new<R: Rng>(rng: &mut R, num_bits: u64) -> Self {
        Self {
            deduper: Deduper::new(rng, num_bits),
            shred_id_filter: Deduper::new(rng, num_bits),
        }
    }

    fn maybe_reset<R: Rng>(&self, rng: &mut R, false_positive_rate: f64, reset_cycle: Duration) {
        self.deduper
            .maybe_reset(rng, false_positive_rate, reset_cycle);
        self.shred_id_filter
            .maybe_reset(rng, false_positive_rate, reset_cycle);
    }

    // Returns true if the shred is duplicate and should be discarded.
    #[must_use]
    fn dedup(&self, key: ShredId, shred: &[u8], max_duplicate_count: usize) -> bool {
        // Shreds in the retransmit stage:
        //   * don't have repair nonce (repaired shreds are not retransmitted).
        //   * are already resigned by this node as the retransmitter.
        //   * have their leader's signature verified.
        // Therefore in order to dedup shreds, it suffices to compare:
        //    (signature, slot, shred-index, shred-type)
        // Because ShredCommonHeader already includes all of the above tuple,
        // the rest of the payload can be skipped.
        // In order to detect duplicate blocks across cluster, we retransmit
        // max_duplicate_count different shreds for each ShredId.
        shred::layout::get_common_header_bytes(shred)
            .map(|header| self.deduper.dedup(header))
            .unwrap_or(true)
            || (0..max_duplicate_count).all(|i| self.shred_id_filter.dedup(&(key, i)))
    }
}

enum RetransmitSocket<'a> {
    Socket(&'a UdpSocket),
    Xdp(&'a XdpSender),
    Multihomed {
        sockets: &'a [UdpSocket],
        interface_offset: usize,
        sockets_per_interface: usize,
        thread_index: usize,
    },
}

impl<'a> RetransmitSocket<'a> {
    pub fn new(
        thread_index: usize,
        retransmit_sockets: &'a [UdpSocket],
        xdp_sender: Option<&'a XdpSender>,
        cluster_info: &'a ClusterInfo,
    ) -> Self {
        if let Some(sender) = xdp_sender {
            RetransmitSocket::Xdp(sender)
        } else if cluster_info.bind_ip_addrs().multihoming_enabled() {
            let sockets_per_interface =
                retransmit_sockets.len() / cluster_info.bind_ip_addrs().len();
            let active_index = cluster_info.bind_ip_addrs().active_index();
            let interface_offset = sockets_per_interface.saturating_mul(active_index);

            RetransmitSocket::Multihomed {
                sockets: retransmit_sockets,
                interface_offset,
                sockets_per_interface,
                thread_index,
            }
        } else {
            let socket: &UdpSocket = &retransmit_sockets[thread_index % retransmit_sockets.len()];
            RetransmitSocket::Socket(socket)
        }
    }

    pub fn get_socket(&self) -> &'a UdpSocket {
        match self {
            RetransmitSocket::Socket(socket) => socket,
            RetransmitSocket::Multihomed {
                sockets,
                interface_offset,
                sockets_per_interface,
                thread_index,
            } => {
                let socket_index = interface_offset + (thread_index % sockets_per_interface);
                &sockets[socket_index]
            }
            RetransmitSocket::Xdp(_) => {
                unreachable!("get_socket() should not be called for XDP variants")
            }
        }
    }
}

// Retransmits a single shred to all downstream nodes. Called directly by a
// retransmit worker for every shred it pulls off the queue: dedup, look up
// (or compute) turbine addresses, send, then fold the result into the
// shared stats/addr-cache state. Fire-and-forget — nothing is returned.
#[allow(clippy::too_many_arguments)]
fn process_shred(
    shred: shred::Payload,
    worker_index: usize,
    retransmit_sockets: &[UdpSocket],
    xdp_sender: Option<&XdpSender>,
    shared: &RetransmitShared,
) {
    let Some(key) = shred::layout::get_shred_id(shred.as_ref()) else {
        return;
    };
    let (working_bank, root_bank) = {
        let bank_forks = shared.bank_forks.read().unwrap();
        (bank_forks.working_bank(), bank_forks.root_bank())
    };
    shared
        .max_slots
        .retransmit
        .fetch_max(key.slot(), Ordering::Relaxed);
    if key.slot() < root_bank.slot()
        || shared
            .shred_deduper
            .dedup(key, shred.as_ref(), MAX_DUPLICATE_COUNT)
    {
        shared
            .stats
            .num_shreds_skipped
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    let socket_addr_space = shared.cluster_info.socket_addr_space();
    let mut compute_turbine_peers = Measure::start("turbine_start");
    let (root_distance, addrs, cache_hit) =
        if let Some((root_distance, addrs)) = shared.addr_cache.read().unwrap().get(&key) {
            shared.stats.addr_cache_hit.fetch_add(1, Ordering::Relaxed);
            (root_distance, addrs.to_vec(), true)
        } else {
            let Some(slot_leader) = shared
                .leader_schedule_cache
                .slot_leader_at(key.slot(), Some(&working_bank))
            else {
                shared
                    .stats
                    .unknown_shred_slot_leader
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };
            let cluster_nodes = shared.cluster_nodes_cache.get(
                key.slot(),
                &root_bank,
                &working_bank,
                &shared.cluster_info,
            );
            let Ok((root_distance, addrs)) = cluster_nodes
                .get_retransmit_addrs(&slot_leader.id, &key, DATA_PLANE_FANOUT, socket_addr_space)
                .inspect_err(|err| match err {
                    Error::Loopback { .. } => {
                        shared
                            .stats
                            .num_loopback_errs
                            .fetch_add(1, Ordering::Relaxed);
                    }
                })
            else {
                return;
            };
            shared.stats.addr_cache_miss.fetch_add(1, Ordering::Relaxed);
            (root_distance, addrs, false)
        };
    compute_turbine_peers.stop();
    shared
        .stats
        .compute_turbine_peers_total
        .fetch_add(compute_turbine_peers.as_us(), Ordering::Relaxed);

    let last_shred_in_slot = shred::wire::get_flags(shred.as_ref())
        .map(|flags| flags.contains(ShredFlags::LAST_SHRED_IN_SLOT))
        .unwrap_or_default();

    let socket = RetransmitSocket::new(
        worker_index,
        retransmit_sockets,
        xdp_sender,
        &shared.cluster_info,
    );
    let mut retransmit_time = Measure::start("retransmit_to");
    let num_addrs = addrs.len();
    let num_nodes = match socket {
        RetransmitSocket::Xdp(sender) => {
            let mut sent = num_addrs;
            if num_addrs > 0
                && let Err(e) = sender.try_send(key.index() as usize, addrs.clone(), shred.bytes)
            {
                log::warn!("xdp channel full: {e:?}");
                shared
                    .stats
                    .num_shreds_dropped_xdp_full
                    .fetch_add(num_addrs, Ordering::Relaxed);
                sent = 0;
            }
            sent
        }
        RetransmitSocket::Socket(_) | RetransmitSocket::Multihomed { .. } => {
            let socket = socket.get_socket();
            match multi_target_send(socket, shred, &addrs) {
                Ok(()) => num_addrs,
                Err(SendPktsError::IoError(ioerr, num_failed)) => {
                    error!(
                        "retransmit_to multi_target_send error: {ioerr:?}, \
                         {num_failed}/{num_addrs} packets failed"
                    );
                    num_addrs - num_failed
                }
            }
        }
    };
    retransmit_time.stop();
    shared
        .stats
        .num_addrs_failed
        .fetch_add(num_addrs - num_nodes, Ordering::Relaxed);
    shared
        .stats
        .num_nodes
        .fetch_add(num_nodes, Ordering::Relaxed);
    shared
        .stats
        .retransmit_total
        .fetch_add(retransmit_time.as_us(), Ordering::Relaxed);
    shared.stats.num_shreds.fetch_add(1, Ordering::Relaxed);

    let out = RetransmitShredOutput {
        shred: key,
        last_shred_in_slot,
        root_distance,
        num_nodes,
        addrs: (!cache_hit).then(|| addrs.into_boxed_slice()),
    };
    shared.stats.record_shred(
        out,
        root_bank.slot(),
        &shared.addr_cache,
        &shared.notifiers,
        &shared.pending_first_shred_event,
    );
}

// Main loop for a single persistent retransmit worker. Pulls shreds off a
// clone of the upstream channel (used directly as an SPMC work queue) and
// retransmits them one at a time. Never blocks on the channel: an empty
// channel is handled with a short sleep instead of a blocking recv, since
// retransmit is latency critical and we don't want a worker parked/woken by
// the OS scheduler on the hot path.
fn retransmit_worker_loop(
    worker_index: usize,
    retransmit_receiver: Receiver<Vec<shred::Payload>>,
    retransmit_sockets: Arc<Vec<UdpSocket>>,
    xdp_sender: Option<XdpSender>,
    shared: Arc<RetransmitShared>,
) {
    loop {
        match retransmit_receiver.try_recv() {
            Ok(shreds) => {
                for shred in shreds {
                    process_shred(
                        shred,
                        worker_index,
                        &retransmit_sockets,
                        xdp_sender.as_ref(),
                        &shared,
                    );
                }
            }
            Err(TryRecvError::Empty) => thread::sleep(WORKER_IDLE_SLEEP),
            Err(TryRecvError::Disconnected) => return,
        }
    }
}

// Speculatively precomputes turbine tree and caches retransmit addresses.
// Runs on its own small rayon pool, decoupled from the retransmit worker
// pool, driven by the housekeeping thread on a fixed cadence rather than
// opportunistically whenever the (now worker-owned) channel looks empty.
fn cache_retransmit_addrs(
    thread_pool: &ThreadPool,
    addr_cache: &RwLock<AddrCache>,
    bank_forks: &RwLock<BankForks>,
    leader_schedule_cache: &LeaderScheduleCache,
    cluster_info: &ClusterInfo,
    cluster_nodes_cache: &ClusterNodesCache<RetransmitStage>,
) {
    let shreds = addr_cache
        .write()
        .unwrap()
        .get_shreds(thread_pool.current_num_threads() * 4);
    if shreds.is_empty() {
        return;
    }
    let (working_bank, root_bank) = {
        let bank_forks = bank_forks.read().unwrap();
        (bank_forks.working_bank(), bank_forks.root_bank())
    };
    let cache: HashMap<Slot, (Pubkey, Arc<ClusterNodes<RetransmitStage>>)> = shreds
        .iter()
        .map(ShredId::slot)
        .collect::<HashSet<Slot>>()
        .into_iter()
        .filter_map(|slot: Slot| {
            let slot_leader = leader_schedule_cache.slot_leader_at(slot, Some(&working_bank))?;
            let cluster_nodes =
                cluster_nodes_cache.get(slot, &root_bank, &working_bank, cluster_info);
            Some((slot, (slot_leader.id, cluster_nodes)))
        })
        .collect();
    if cache.is_empty() {
        return;
    }
    let socket_addr_space = cluster_info.socket_addr_space();
    let get_retransmit_addrs = |shred: ShredId| {
        let (slot_leader, cluster_nodes) = cache.get(&shred.slot())?;
        let (root_distance, addrs) = cluster_nodes
            .get_retransmit_addrs(slot_leader, &shred, DATA_PLANE_FANOUT, socket_addr_space)
            .ok()?;
        Some((shred, (root_distance, addrs.into_boxed_slice())))
    };
    // Only the metadata read (get_shreds, above) and the final inserts
    // (below) hold the addr_cache write lock; the expensive parallel
    // computation itself runs unlocked so it never blocks retransmit
    // workers' addr_cache reads.
    if shreds.len() < PAR_ITER_MIN_NUM_SHREDS {
        let mut addr_cache = addr_cache.write().unwrap();
        for (shred, entry) in shreds.into_iter().filter_map(get_retransmit_addrs) {
            addr_cache.put(&shred, entry);
        }
    } else {
        let entries: Vec<_> = thread_pool.install(|| {
            shreds
                .into_par_iter()
                .filter_map(get_retransmit_addrs)
                .collect()
        });
        let mut addr_cache = addr_cache.write().unwrap();
        for (shred, entry) in entries {
            addr_cache.put(&shred, entry);
        }
    }
}

// Low-frequency, cross-cutting duties that no longer have a natural home on
// any single retransmit worker: periodic stats submission, deduper reset
// checks, votor first-shred-event retries, and the speculative
// address-cache precompute. `shutdown_rx` is a dedicated shutdown channel
// (see RetransmitStage::join) rather than the shred work queue, so this
// thread never competes with workers for real shreds.
fn housekeeping_loop(
    shutdown_rx: Receiver<()>,
    shared: Arc<RetransmitShared>,
    precompute_pool: ThreadPool,
    is_xdp: bool,
) {
    let mut since = Instant::now();
    loop {
        match shutdown_rx.recv_timeout(HOUSEKEEPING_INTERVAL) {
            Err(RecvTimeoutError::Timeout) => (),
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        }

        {
            let mut pending = shared.pending_first_shred_event.lock().unwrap();
            if let Some(event) = pending.take()
                && let Err(TrySendError::Full(event)) =
                    shared.notifiers.votor_event_sender.try_send(event)
            {
                *pending = Some(event);
            }
        }

        shared.shred_deduper.maybe_reset(
            &mut rand::rng(),
            DEDUPER_FALSE_POSITIVE_RATE,
            DEDUPER_RESET_CYCLE,
        );

        let (working_bank, root_bank) = {
            let bank_forks = shared.bank_forks.read().unwrap();
            (bank_forks.working_bank(), bank_forks.root_bank())
        };

        cache_retransmit_addrs(
            &precompute_pool,
            &shared.addr_cache,
            &shared.bank_forks,
            &shared.leader_schedule_cache,
            &shared.cluster_info,
            &shared.cluster_nodes_cache,
        );

        shared.stats.maybe_submit(
            &mut since,
            &root_bank,
            &working_bank,
            &shared.cluster_info,
            &shared.cluster_nodes_cache,
            is_xdp,
        );
    }
}

/// Service to retransmit messages received from other peers in turbine.
pub struct RetransmitStage {
    worker_handles: Vec<JoinHandle<()>>,
    housekeeping_handle: JoinHandle<()>,
    // Held only to signal the housekeeping thread to exit on join(); never
    // sent on.
    housekeeping_shutdown: Sender<()>,
}

impl RetransmitStage {
    /// Construct the RetransmitStage.
    ///
    /// Key arguments:
    /// * `retransmit_sockets` - Sockets to use for transmission of shreds
    /// * `max_slots` - Structure to keep track of the Turbine progress
    /// * `bank_forks` - Reference to the BankForks structure
    /// * `leader_schedule_cache` - The leader schedule to verify shreds
    /// * `cluster_info` - This structure needs to be updated and populated by the bank and via gossip.
    /// * `retransmit_receiver` - Receive channel for batches of shreds to be retransmitted.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bank_forks: Arc<RwLock<BankForks>>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        cluster_info: Arc<ClusterInfo>,
        retransmit_sockets: Arc<Vec<UdpSocket>>,
        retransmit_receiver: Receiver<Vec<shred::Payload>>,
        max_slots: Arc<MaxSlots>,
        rpc_subscriptions: Option<Arc<RpcSubscriptions>>,
        slot_status_notifier: Option<SlotStatusNotifier>,
        xdp_sender: Option<XdpSender>,
        votor_event_sender: Sender<VotorEvent>,
    ) -> Self {
        let migration_status = bank_forks.read().unwrap().migration_status();
        let cluster_nodes_cache = ClusterNodesCache::<RetransmitStage>::new(
            CLUSTER_NODES_CACHE_NUM_EPOCH_CAP,
            CLUSTER_NODES_CACHE_TTL,
        );
        let mut rng = rand::rng();
        let shred_deduper = ShredDeduper::new(&mut rng, DEDUPER_NUM_BITS);

        let shared = Arc::new(RetransmitShared {
            bank_forks: Arc::clone(&bank_forks),
            leader_schedule_cache,
            cluster_info: Arc::clone(&cluster_info),
            cluster_nodes_cache,
            shred_deduper,
            addr_cache: RwLock::new(AddrCache::with_capacity(/*capacity:*/ 4)),
            stats: RetransmitStats::new(),
            max_slots,
            notifiers: RetransmitNotifiers {
                rpc_subscriptions,
                slot_status_notifier,
                migration_status,
                votor_event_sender,
            },
            pending_first_shred_event: Mutex::new(None),
        });

        let num_workers = retransmit_sockets.len();
        let worker_handles = (0..num_workers)
            .map(|index| {
                let retransmit_receiver = retransmit_receiver.clone();
                let retransmit_sockets = Arc::clone(&retransmit_sockets);
                let xdp_sender = xdp_sender.clone();
                let shared = Arc::clone(&shared);
                Builder::new()
                    .name(format!("solRetransWk{index:02}"))
                    .spawn(move || {
                        retransmit_worker_loop(
                            index,
                            retransmit_receiver,
                            retransmit_sockets,
                            xdp_sender,
                            shared,
                        )
                    })
                    .unwrap()
            })
            .collect();

        let (housekeeping_shutdown, shutdown_rx) = bounded::<()>(0);
        let precompute_pool = ThreadPoolBuilder::new()
            .num_threads(num_workers)
            .thread_name(|i| format!("solRetransPre{i:02}"))
            .build()
            .unwrap();
        let is_xdp = xdp_sender.is_some();
        let housekeeping_handle = Builder::new()
            .name("solRetransHk".to_string())
            .spawn(move || housekeeping_loop(shutdown_rx, shared, precompute_pool, is_xdp))
            .unwrap();

        Self {
            worker_handles,
            housekeeping_handle,
            housekeeping_shutdown,
        }
    }

    pub fn join(self) -> thread::Result<()> {
        let Self {
            worker_handles,
            housekeeping_handle,
            housekeeping_shutdown,
        } = self;
        drop(housekeeping_shutdown);
        for handle in worker_handles {
            handle.join()?;
        }
        housekeeping_handle.join()
    }
}

impl AddAssign for RetransmitSlotStats {
    fn add_assign(&mut self, other: Self) {
        let Self {
            asof,
            outset,
            max_index_code,
            max_index_data,
            last_shred_in_slot,
            num_shreds_received,
            num_shreds_sent,
            mut addrs,
        } = other;
        self.asof = self.asof.max(asof);
        self.max_index_code = self.max_index_code.max(max_index_code);
        self.max_index_data = self.max_index_data.max(max_index_data);
        self.last_shred_in_slot |= last_shred_in_slot;
        self.outset = if self.outset == 0 {
            outset
        } else {
            self.outset.min(outset)
        };
        if self.addrs.len() < addrs.len() {
            std::mem::swap(&mut self.addrs, &mut addrs);
        }
        self.addrs.append(&mut addrs);
        for k in 0..MAX_NUM_TURBINE_HOPS {
            self.num_shreds_received[k] += num_shreds_received[k];
            self.num_shreds_sent[k] += num_shreds_sent[k];
        }
    }
}

impl RetransmitStats {
    const SLOT_STATS_CACHE_CAPACITY: usize = 750;

    fn new() -> Self {
        Self {
            addr_cache_hit: AtomicUsize::default(),
            addr_cache_miss: AtomicUsize::default(),
            num_nodes: AtomicUsize::default(),
            num_addrs_failed: AtomicUsize::default(),
            num_shreds_dropped_xdp_full: AtomicUsize::default(),
            num_loopback_errs: AtomicUsize::default(),
            num_shreds: AtomicUsize::default(),
            num_shreds_skipped: AtomicUsize::default(),
            retransmit_total: AtomicU64::default(),
            compute_turbine_peers_total: AtomicU64::default(),
            unknown_shred_slot_leader: AtomicUsize::default(),
            // Cache capacity is manually enforced by `SLOT_STATS_CACHE_CAPACITY`
            slot_stats: Mutex::new(LruCache::<Slot, RetransmitSlotStats>::unbounded()),
        }
    }

    fn maybe_submit(
        &self,
        since: &mut Instant,
        root_bank: &Bank,
        working_bank: &Bank,
        cluster_info: &ClusterInfo,
        cluster_nodes_cache: &ClusterNodesCache<RetransmitStage>,
        is_xdp: bool,
    ) {
        const SUBMIT_CADENCE: Duration = Duration::from_secs(2);
        if since.elapsed() < SUBMIT_CADENCE {
            return;
        }
        *since = Instant::now();
        cluster_nodes_cache
            .get(root_bank.slot(), root_bank, working_bank, cluster_info)
            .submit_metrics("cluster_nodes_retransmit", timestamp());
        datapoint_info!(
            "retransmit-stage",
            "is_xdp" => is_xdp.to_string(),
            ("num_nodes", self.num_nodes.swap(0, Ordering::Relaxed), i64),
            (
                "num_addrs_failed",
                self.num_addrs_failed.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "num_shreds_dropped_xdp_full",
                self.num_shreds_dropped_xdp_full.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "num_loopback_errs",
                self.num_loopback_errs.swap(0, Ordering::Relaxed),
                i64
            ),
            ("num_shreds", self.num_shreds.swap(0, Ordering::Relaxed), i64),
            (
                "num_shreds_skipped",
                self.num_shreds_skipped.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "retransmit_total",
                self.retransmit_total.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "addr_cache_hit",
                self.addr_cache_hit.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "addr_cache_miss",
                self.addr_cache_miss.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "compute_turbine",
                self.compute_turbine_peers_total.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "unknown_shred_slot_leader",
                self.unknown_shred_slot_leader.swap(0, Ordering::Relaxed),
                i64
            ),
        );
    }

    // Folds the result of retransmitting a single shred into the shared
    // per-slot stats and address cache. Called inline by whichever worker
    // just retransmitted the shred — there is no separate aggregation step.
    fn record_shred(
        &self,
        out: RetransmitShredOutput,
        root: Slot,
        addr_cache: &RwLock<AddrCache>,
        notifiers: &RetransmitNotifiers,
        pending_first_shred_event: &Mutex<Option<VotorEvent>>,
    ) {
        let now = timestamp();
        let slot = out.shred.slot();
        let mut delta = RetransmitSlotStats::default();
        delta.record(now, out);
        addr_cache.write().unwrap().record(slot, &mut delta);

        let mut slot_stats = self.slot_stats.lock().unwrap();
        match slot_stats.get_mut(&slot) {
            None => {
                if slot > root {
                    notify_subscribers(slot, delta.outset, notifiers, pending_first_shred_event);
                }
                slot_stats.put(slot, delta);
            }
            Some(entry) => *entry += delta,
        }
        while slot_stats.len() > Self::SLOT_STATS_CACHE_CAPACITY {
            // Pop and submit metrics for the slot which was updated least
            // recently. At this point the node most likely will not receive
            // and retransmit any more shreds for this slot.
            match slot_stats.pop_lru() {
                Some((slot, stats)) => stats.submit(slot),
                None => break,
            }
        }
    }
}

impl RetransmitSlotStats {
    fn record(&mut self, now: u64, out: RetransmitShredOutput) {
        self.outset = if self.outset == 0 {
            now
        } else {
            self.outset.min(now)
        };
        self.asof = self.asof.max(now);
        let max_index = match out.shred.shred_type() {
            ShredType::Code => &mut self.max_index_code,
            ShredType::Data => &mut self.max_index_data,
        };
        *max_index = (*max_index).max(out.shred.index());
        self.last_shred_in_slot |= out.last_shred_in_slot;
        self.num_shreds_received[usize::from(out.root_distance)] += 1;
        self.num_shreds_sent[usize::from(out.root_distance)] += out.num_nodes;
        if let Some(addrs) = out.addrs {
            self.addrs.push((out.shred, out.root_distance, addrs));
        }
    }

    fn submit(&self, slot: Slot) {
        let num_shreds: usize = self.num_shreds_received.iter().sum();
        let num_nodes: usize = self.num_shreds_sent.iter().sum();
        let elapsed_millis = self.asof.saturating_sub(self.outset);
        datapoint_info!(
            "retransmit-stage-slot-stats",
            ("slot", slot, i64),
            ("outset_timestamp", self.outset, i64),
            ("elapsed_millis", elapsed_millis, i64),
            ("num_shreds", num_shreds, i64),
            ("num_nodes", num_nodes, i64),
            ("num_shreds_received_root", self.num_shreds_received[0], i64),
            (
                "num_shreds_received_1st_layer",
                self.num_shreds_received[1],
                i64
            ),
            (
                "num_shreds_received_2nd_layer",
                self.num_shreds_received[2],
                i64
            ),
            (
                "num_shreds_received_3rd_layer",
                self.num_shreds_received[3],
                i64
            ),
            ("num_shreds_sent_root", self.num_shreds_sent[0], i64),
            ("num_shreds_sent_1st_layer", self.num_shreds_sent[1], i64),
            ("num_shreds_sent_2nd_layer", self.num_shreds_sent[2], i64),
            ("num_shreds_sent_3rd_layer", self.num_shreds_sent[3], i64),
        );
    }
}

// Notifies subscribers of shreds received from a new slot.
fn notify_subscribers(
    slot: Slot,
    timestamp: u64, // When the first shred in the slot was received.
    notifiers: &RetransmitNotifiers,
    pending_first_shred_event: &Mutex<Option<VotorEvent>>,
) {
    if let Some(rpc_subscriptions) = notifiers.rpc_subscriptions.as_ref() {
        let slot_update = SlotUpdate::FirstShredReceived { slot, timestamp };
        rpc_subscriptions.notify_slot_update(slot_update);
        datapoint_info!("retransmit-first-shred", ("slot", slot, i64));
    }
    if let Some(slot_status_notifier) = notifiers.slot_status_notifier.as_ref() {
        slot_status_notifier
            .read()
            .unwrap()
            .notify_first_shred_received(slot);
    }

    if notifiers.migration_status.should_send_votor_event(slot)
        && slot.is_multiple_of(NUM_CONSECUTIVE_LEADER_SLOTS.get() as u64)
    {
        match notifiers
            .votor_event_sender
            .try_send(VotorEvent::FirstShred(slot))
        {
            Ok(()) => (),
            Err(TrySendError::Full(event)) => {
                error!(
                    "Votor event channel is backed up len {}, something is wrong",
                    notifiers.votor_event_sender.len(),
                );
                // Only the latest first shred notification matters, requeue
                *pending_first_shred_event.lock().unwrap() = Some(event);
            }
            Err(TrySendError::Disconnected(_)) => {
                info!("Votor event channel disconnected, we are shutting down")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        rand::SeedableRng,
        rand_chacha::ChaChaRng,
        solana_entry::entry::create_ticks,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_ledger::shred::{ProcessShredsStats, ReedSolomonCache, Shredder},
    };

    fn get_keypair() -> Keypair {
        const KEYPAIR: &str = "Fcc2HUvRC7Dv4GgehTziAremzRvwDw5miYu8Ahuu1rsGjA\
            5eCn55pXiSkEPcuqviV41rJxrFpZDmHmQkZWfoYYS";
        bs58::decode(KEYPAIR)
            .into_vec()
            .as_deref()
            .map(Keypair::try_from)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn test_shred_deduper() {
        let keypair = get_keypair();
        let entries = create_ticks(10, 1, Hash::new_unique());
        let rsc = ReedSolomonCache::default();
        let make_shreds_for_slot = |slot, parent, code_index| {
            let shredder = Shredder::new(slot, parent, 1, 0).unwrap();
            shredder.entries_to_merkle_shreds_for_tests(
                &keypair,
                &entries,
                true,
                // chained_merkle_root
                Hash::new_from_array(rand::rng().random()),
                0,
                code_index,
                &rsc,
                &mut ProcessShredsStats::default(),
            )
        };

        let mut rng = ChaChaRng::from_seed([0xa5; 32]);
        let shred_deduper = ShredDeduper::<2>::new(&mut rng, /*num_bits:*/ 640_007);

        // make a set of shreds for slot 5 with parent slot 4
        let (shreds_data_5_4, shreds_code_5_4) = make_shreds_for_slot(5, 4, 0);
        // make a set of shreds for slot 5 with parent slot 3
        let (shreds_data_5_3, _shreds_code_5_3) = make_shreds_for_slot(5, 3, 0);
        // make a set of shreds for slot 5 with parent slot 2
        let (shreds_data_5_2, _shreds_code_5_2) = make_shreds_for_slot(5, 2, 0);
        // pick a shred for tests
        let shred = shreds_data_5_4.last().unwrap().clone();
        // unique shred should pass
        assert!(
            !shred_deduper.dedup(shred.id(), shred.payload(), MAX_DUPLICATE_COUNT),
            "First time shred X => Not dup because it is the only shred"
        );
        // duplicate shred blocked
        assert!(
            shred_deduper.dedup(shred.id(), shred.payload(), MAX_DUPLICATE_COUNT),
            "
            Second time shred X => Dup because common header is duplicate
            "
        );
        // Pick a shred with same index as `shred` but different parent offset
        let shred_dup = shreds_data_5_3.last().unwrap().clone();
        // first shred passed through
        assert!(
            !shred_deduper.dedup(shred_dup.id(), shred_dup.payload(), MAX_DUPLICATE_COUNT),
            "First time seeing shred X with different parent slot (3 instead of 4) => Not dup \
             because common header is unique & shred ID only seen once"
        );
        // then blocked
        assert!(
            shred_deduper.dedup(shred_dup.id(), shred_dup.payload(), MAX_DUPLICATE_COUNT),
            "Second time seeing shred X with parent slot 3 => Dup because common header is not \
             unique & shred ID seen twice"
        );

        let shred_dup2 = shreds_data_5_2.last().unwrap().clone();

        assert!(
            shred_deduper.dedup(shred_dup2.id(), shred_dup2.payload(), MAX_DUPLICATE_COUNT),
            "First time seeing shred X with parent slot 2 => Dup because common header is unique \
             but shred ID seen twice already"
        );

        /* Coding shreds */

        // Pick a coding shred at index 4 based off FEC set index 0
        let shred = shreds_code_5_4[4].clone();
        // Coding passes
        assert!(
            !shred_deduper.dedup(shred.id(), shred.payload(), MAX_DUPLICATE_COUNT),
            "
           First time seeing coding shred Y => Not dup because common header & shred ID are unique"
        );
        // then blocked
        assert!(
            shred_deduper.dedup(shred.id(), shred.payload(), MAX_DUPLICATE_COUNT),
            "
            Second time seeing coding shred Y => Dup because common header is dup
            "
        );

        // Make a coding shred at index 4 based off FEC set index 2
        let (_, shreds_code_invalid) = make_shreds_for_slot(5, 4, 2);

        let shred_inv_code_1 = shreds_code_invalid[2].clone();
        assert_eq!(
            shred.index(),
            shred_inv_code_1.index(),
            "we want a shred with same index but different FEC set index"
        );
        // 2nd unique coding passes
        assert!(
            !shred_deduper.dedup(
                shred_inv_code_1.id(),
                shred_inv_code_1.payload(),
                MAX_DUPLICATE_COUNT
            ),
            "First time seeing shred Y w/ changed header (FEC Set index 2) => Not dup because \
             common header is unique & shred ID only seen once"
        );
        // same again is blocked
        assert!(
            shred_deduper.dedup(
                shred_inv_code_1.id(),
                shred_inv_code_1.payload(),
                MAX_DUPLICATE_COUNT
            ),
            "
           Second time seeing shred Y w/ changed header (FEC Set index 2) => Dup because common \
             header is not unique & shred ID seen twice "
        );
        // Make a coding shred at index 4 based off FEC set index 3
        let (_, shreds_code_invalid) = make_shreds_for_slot(5, 4, 3);

        let shred_inv_code_2 = shreds_code_invalid[1].clone();
        assert_eq!(
            shred.index(),
            shred_inv_code_2.index(),
            "we want a shred with same index but different FEC set index"
        );
        assert!(
            shred_deduper.dedup(
                shred_inv_code_2.id(),
                shred_inv_code_2.payload(),
                MAX_DUPLICATE_COUNT
            ),
            "
           First time seeing shred Y w/ changed header (FEC Set index 3)=>Dup because common \
             header is unique but shred ID seen twice already"
        );
    }
}
