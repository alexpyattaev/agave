//! Votor-transport server under load, for CPU measurement.
//!
//! Runs a single [`QuicDatagramEndpoint`] whose inbound side is backed by
//! `--num-endpoints` SO_REUSEPORT sockets, admits `--num-peers` deterministic
//! load-generator identities, and drains the ingress channel. Sockets are
//! configured exactly as `solana_gossip::node` configures the real votor
//! server sockets.
//!
//! Prints `SERVER <pubkey> <addr>` once listening, then one `STAT` line per
//! second.
use {
    agave_votor_transport::{MAX_ALPENGLOW_VOTE_ACCOUNTS, endpoint::QuicDatagramEndpoint},
    clap::Parser,
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
use common::{
    DATAGRAMS_PER_SECOND_PER_PEER, QUIC_CONTROL_TRAFFIC_BUFFER_SIZE, client_keypair, server_keypair,
};

/// Ingress channel capacity, mirrors `solana_core`'s `MAX_ALPENGLOW_PACKET_NUM`.
const INGRESS_CAP: usize = 10_000;

#[derive(Parser)]
struct Cli {
    /// SO_REUSEPORT sockets backing the inbound side.
    #[arg(long, default_value_t = 1)]
    num_endpoints: usize,
    /// Load-generator identities to admit.
    #[arg(long, default_value_t = MAX_ALPENGLOW_VOTE_ACCOUNTS)]
    num_peers: usize,
    #[arg(long, default_value_t = 8)]
    worker_threads: usize,
    /// Exit after this long, so a run cannot outlive its harness.
    #[arg(long, default_value_t = 60)]
    run_secs: u64,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let runtime = Builder::new_multi_thread()
        .worker_threads(cli.worker_threads)
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
    let primary = bind_to_with_config(localhost, 0, inbound_config).expect("bind votor server");
    let inbound_sockets = bind_more_with_config(primary, cli.num_endpoints, inbound_config)
        .expect("SO_REUSEPORT bind of inbound sockets");
    assert_eq!(
        inbound_sockets.len(),
        cli.num_endpoints,
        "kernel must grant all {} SO_REUSEPORT sockets",
        cli.num_endpoints
    );
    let addr = inbound_sockets[0]
        .local_addr()
        .expect("server local addr from first inbound socket");
    let outbound_socket =
        bind_to_with_config(localhost, 0, outbound_config).expect("bind votor client socket");

    // Peers are admitted by pubkey; addresses stay `None` so the outbound loop
    // never dials back and the measurement covers the receive path only.
    let peer_list: HashMap<_, _> = (0..cli.num_peers)
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
        DATAGRAMS_PER_SECOND_PER_PEER,
        cancel,
    )
    .expect("QuicDatagramEndpoint::spawn");

    // Consumer standing in for BLS sigverify: counts and drops. Kept off the
    // tokio runtime so its cost shows up as a distinct thread in the profile.
    let drained = Arc::new(AtomicU64::new(0));
    let drainer = {
        let drained = drained.clone();
        thread::Builder::new()
            .name("votor-bench-drain".into())
            .spawn(move || {
                loop {
                    match ingress_receiver.try_recv() {
                        Ok(_datagram) => {
                            drained.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
                        Err(TryRecvError::Disconnected) => break,
                    }
                }
            })
            .expect("spawn ingress drain thread")
    };

    println!("SERVER {} {addr}", keypair.pubkey());

    let mut prev_drained = 0;
    for tick in 0..cli.run_secs {
        thread::sleep(Duration::from_secs(1));
        let rx_total = drained.load(Ordering::Relaxed);
        println!(
            "STAT t={tick} rx_per_s={} rx_total={rx_total}",
            rx_total.saturating_sub(prev_drained),
        );
        prev_drained = rx_total;
    }

    runtime.block_on(endpoint.join());
    drop(peer_list_sender);
    drainer.join().expect("ingress drain thread");
}
