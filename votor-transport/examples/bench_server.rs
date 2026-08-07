//! Votor-transport server under load, for CPU measurement.
//!
//! Runs a single [`QuicDatagramEndpoint`] whose inbound side is backed by
//! `--num-endpoints` SO_REUSEPORT sockets, admits `--num-peers` deterministic
//! load-generator identities, and drains the ingress channel. Sockets are
//! configured exactly as `solana_gossip::node` configures the real votor
//! server sockets.
//!
//! Prints `SERVER <pubkey> <addr> pid=<pid>` once listening, then one `STAT`
//! line per second. Attach `perf stat -p <pid>` for the window of interest;
//! `bench_endpoint_scaling.sh` does that.
//!
//! Run with:
//! ```text
//! cargo run --release --example bench_server \
//!     --features agave-unstable-api,dev-context-only-utils -- --num-endpoints 4
//! ```
use {
    agave_votor_transport::endpoint::QuicDatagramEndpoint,
    crossbeam_channel::{TryRecvError, bounded},
    solana_keypair::Signer,
    solana_net_utils::sockets::{SocketConfiguration, bind_more_with_config, bind_to_with_config},
    std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::Duration,
    },
    tokio::{runtime::Builder, sync::watch},
    tokio_util::sync::CancellationToken,
};

mod common;
use common::{Args, client_keypair, server_keypair};

/// Ingress channel capacity, mirrors `solana_core`'s `MAX_ALPENGLOW_PACKET_NUM`.
const INGRESS_CAP: usize = 10_000;
/// Matches `QUIC_CONTROL_TRAFFIC_BUFFER_SIZE` in `solana_gossip::node`.
const QUIC_CONTROL_TRAFFIC_BUFFER_SIZE: usize = 4 * 1024 * 1024;

const PPS: usize = 50;

/// How long the consumer sleeps once it finds the ingress channel empty, instead
/// of parking on a blocking `recv`.
///
/// A blocking `recv` parks whenever the queue drains, so the wake rate tracked
/// the producers: at 100k datagrams/s the consumer cost ~2us per datagram, three
/// orders of magnitude above the counter increment it actually performs, and
/// nearly all of it futex and scheduler overhead. Worse for a benchmark, that
/// overhead shrank as inbound endpoints were added -- more producers interleave,
/// so the queue empties less often -- which showed up as the endpoint count
/// making the server cheaper when the transport itself was flat.
///
/// A fixed wake cadence decouples consumer cost from producer smoothness. At
/// 100k datagrams/s this batches ~100 datagrams per wake, well inside
/// `INGRESS_CAP`.
const DRAIN_IDLE_SLEEP: Duration = Duration::from_millis(1);

fn main() {
    env_logger::init();
    let args = Args::from_env();
    let num_endpoints: usize = args.get("num-endpoints", 1);
    let num_peers: usize = args.get("num-peers", 2000);
    let port: u16 = args.get("port", 0);
    let worker_threads: usize = args.get("worker-threads", 8);
    let run_secs: u64 = args.get("run-secs", 60);

    let runtime = Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("votor-bench-srv")
        .enable_all()
        .build()
        .expect("tokio multi-thread runtime");

    // `primarily_read_quic`: the receive side keeps the system default, only the
    // (small) control-traffic send side is enlarged.
    let inbound_config =
        SocketConfiguration::default().send_buffer_size(QUIC_CONTROL_TRAFFIC_BUFFER_SIZE);
    let outbound_config =
        SocketConfiguration::default().recv_buffer_size(QUIC_CONTROL_TRAFFIC_BUFFER_SIZE);
    let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let primary = bind_to_with_config(localhost, port, inbound_config).expect("bind votor server");
    let inbound_sockets = bind_more_with_config(primary, num_endpoints, inbound_config)
        .expect("SO_REUSEPORT bind of inbound sockets");
    assert_eq!(
        inbound_sockets.len(),
        num_endpoints,
        "kernel must grant all {num_endpoints} SO_REUSEPORT sockets"
    );
    let addr = inbound_sockets[0]
        .local_addr()
        .expect("server local addr from first inbound socket");
    let outbound_socket =
        bind_to_with_config(localhost, 0, outbound_config).expect("bind votor client socket");

    // Peers are admitted by pubkey; addresses stay `None` so the outbound loop
    // never dials back and the measurement covers the receive path only.
    let peer_list: HashMap<_, _> = (0..num_peers)
        .map(|i| (client_keypair(i).pubkey(), None))
        .collect();
    let (peer_list_sender, peer_list_receiver) = watch::channel(Arc::new(peer_list));

    let (ingress_sender, ingress_receiver) = bounded(INGRESS_CAP);
    let keypair = server_keypair();
    let cancel = CancellationToken::new();
    let (_egress, endpoint) = QuicDatagramEndpoint::spawn(
        runtime.handle(),
        &keypair,
        inbound_sockets,
        outbound_socket,
        ingress_sender,
        peer_list_receiver,
        PPS,
        cancel,
    )
    .expect("QuicDatagramEndpoint::spawn");

    // Consumer standing in for BLS sigverify: counts and drops. Kept off the
    // tokio runtime so its cost shows up as a distinct thread in the profile.
    let drained = Arc::new(AtomicU64::new(0));
    let drained_bytes = Arc::new(AtomicU64::new(0));
    let drainer = {
        let drained = drained.clone();
        let drained_bytes = drained_bytes.clone();
        thread::Builder::new()
            .name("votor-bench-drain".into())
            .spawn(move || {
                loop {
                    match ingress_receiver.try_recv() {
                        Ok(datagram) => {
                            drained.fetch_add(1, Ordering::Relaxed);
                            drained_bytes
                                .fetch_add(datagram.message.len() as u64, Ordering::Relaxed);
                        }
                        Err(TryRecvError::Empty) => thread::sleep(DRAIN_IDLE_SLEEP),
                        Err(TryRecvError::Disconnected) => break,
                    }
                }
            })
            .expect("spawn ingress drain thread")
    };

    println!(
        "SERVER {} {addr} pid={}",
        keypair.pubkey(),
        std::process::id()
    );
    println!(
        "CONFIG num_endpoints={num_endpoints} num_peers={num_peers}  \
         worker_threads={worker_threads}"
    );

    let mut prev_drained = 0u64;
    let mut prev_bytes = 0u64;
    for tick in 0..run_secs {
        thread::sleep(Duration::from_secs(1));
        let now_drained = drained.load(Ordering::Relaxed);
        let now_bytes = drained_bytes.load(Ordering::Relaxed);
        println!(
            "STAT t={tick} rx_per_s={} bytes_per_s={} rx_total={now_drained}",
            now_drained.saturating_sub(prev_drained),
            now_bytes.saturating_sub(prev_bytes),
        );
        prev_drained = now_drained;
        prev_bytes = now_bytes;
    }

    runtime.block_on(endpoint.join());
    drop(peer_list_sender);
    drainer.join().expect("ingress drain thread");
    println!("DONE rx_total={}", drained.load(Ordering::Relaxed));
}
