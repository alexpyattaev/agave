//! Load generator for `bench_server`.
//!
//! Opens `--num-clients` QUIC connections, each with its own votor identity and
//! the production client transport config, then sends `--pps` datagrams per
//! second on every connection. Connections are multiplexed over `--num-sockets`
//! quinn endpoints: the server keys peers by pubkey, not source address, so one
//! UDP socket can carry many identities and the generator stays cheap enough not
//! to starve the process under measurement.
//!
//! Prints `CONNECTED <n>` once every connection is up, then `TX` lines while
//! sending.
//!
//! Run with:
//! ```text
//! cargo run --release --example bench_loadgen \
//!     --features agave-unstable-api,dev-context-only-utils -- \
//!     --server-addr 127.0.0.1:9000 --server-pubkey <pubkey>
//! ```
use {
    agave_votor_transport::transport::new_client_config,
    bytes::Bytes,
    quinn::{Connection, Endpoint},
    solana_net_utils::sockets::{SocketConfiguration, bind_to_with_config},
    solana_pubkey::Pubkey,
    solana_tls_utils::{get_remote_pubkey, socket_addr_to_quic_server_name},
    std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    },
    tokio::{
        runtime::Builder,
        task::JoinSet,
        time::{MissedTickBehavior, interval, interval_at, sleep},
    },
};

mod common;
use common::{Args, client_keypair};

/// Matches `QUIC_CONTROL_TRAFFIC_BUFFER_SIZE` in `solana_gossip::node`.
const QUIC_CONTROL_TRAFFIC_BUFFER_SIZE: usize = 4 * 1024 * 1024;
/// Handshakes started concurrently. The server admits 2000/s globally with a
/// burst of 400, so staying well under that keeps the connect phase clean.
const CONNECT_CONCURRENCY: usize = 128;
/// Attempts per client before giving up on the connect phase.
const CONNECT_ATTEMPTS: usize = 5;

fn main() {
    env_logger::init();
    let args = Args::from_env();
    let server_addr: SocketAddr = args.require("server-addr");
    let server_pubkey: Pubkey = args.require("server-pubkey");
    let num_clients: usize = args.get("num-clients", 2000);
    let pps: usize = args.get("pps", 50);
    let duration_secs: u64 = args.get("duration-secs", 20);
    let num_sockets: usize = args.get("num-sockets", 8);
    let send_tasks: usize = args.get("send-tasks", 16);
    let payload_bytes: usize = args.get("payload-bytes", 160);
    let worker_threads: usize = args.get("worker-threads", 16);

    let runtime = Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("votor-bench-gen")
        .enable_all()
        .build()
        .expect("tokio multi-thread runtime");

    runtime.block_on(async move {
        let socket_config =
            SocketConfiguration::default().recv_buffer_size(QUIC_CONTROL_TRAFFIC_BUFFER_SIZE);
        let endpoints: Vec<Endpoint> = (0..num_sockets)
            .map(|_| {
                let socket = bind_to_with_config(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, socket_config)
                    .expect("bind load generator UDP socket");
                Endpoint::new(
                    quinn::EndpointConfig::default(),
                    None,
                    socket,
                    Arc::new(quinn::TokioRuntime),
                )
                .expect("quinn client endpoint")
            })
            .collect();

        let connections =
            connect_all(&endpoints, server_addr, server_pubkey, num_clients, pps).await;
        assert_eq!(
            connections.len(),
            num_clients,
            "connect phase must establish every client connection"
        );
        println!("CONNECTED {}", connections.len());

        let sent = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        // Surfaces the first send failure so a run that silently loses its
        // connections cannot be mistaken for a clean measurement.
        let reported = Arc::new(AtomicBool::new(false));
        let payload = Bytes::from(vec![0xA5u8; payload_bytes]);
        let period = Duration::from_secs(1)
            .checked_div(pps as u32)
            .expect("pps is nonzero");

        let mut senders = JoinSet::new();
        let shards: Vec<Vec<Connection>> = (0..send_tasks)
            .map(|shard| {
                connections
                    .iter()
                    .skip(shard)
                    .step_by(send_tasks)
                    .cloned()
                    .collect()
            })
            .collect();
        let start = tokio::time::Instant::now();
        for (shard_index, shard) in shards.into_iter().enumerate() {
            // Stagger shard phases so the aggregate send rate is smooth rather
            // than `num_clients` datagrams every `period`.
            let offset = period
                .checked_mul(shard_index as u32)
                .and_then(|d| d.checked_div(send_tasks as u32))
                .expect("period fits");
            let payload = payload.clone();
            let sent = sent.clone();
            let failed = failed.clone();
            let reported = reported.clone();
            senders.spawn(async move {
                let mut tick = interval_at(start.checked_add(offset).expect("offset fits"), period);
                tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    let mut ok = 0u64;
                    let mut err = 0u64;
                    for connection in &shard {
                        match connection.send_datagram(payload.clone()) {
                            Ok(()) => ok = ok.saturating_add(1),
                            Err(e) => {
                                if !reported.swap(true, Ordering::Relaxed) {
                                    println!(
                                        "SEND_ERROR {e} close_reason={:?}",
                                        connection.close_reason()
                                    );
                                }
                                err = err.saturating_add(1);
                            }
                        }
                    }
                    sent.fetch_add(ok, Ordering::Relaxed);
                    failed.fetch_add(err, Ordering::Relaxed);
                }
            });
        }

        let mut report = interval(Duration::from_secs(1));
        report.set_missed_tick_behavior(MissedTickBehavior::Delay);
        report.tick().await;
        let mut prev_sent = 0u64;
        for t in 0..duration_secs {
            report.tick().await;
            let now_sent = sent.load(Ordering::Relaxed);
            println!(
                "TX t={t} tx_per_s={} tx_total={now_sent} tx_failed={}",
                now_sent.saturating_sub(prev_sent),
                failed.load(Ordering::Relaxed),
            );
            prev_sent = now_sent;
        }
        senders.abort_all();
        println!(
            "DONE tx_total={} tx_failed={}",
            sent.load(Ordering::Relaxed),
            failed.load(Ordering::Relaxed)
        );
    });
}

/// Establish one connection per client identity, retrying transient failures.
async fn connect_all(
    endpoints: &[Endpoint],
    server_addr: SocketAddr,
    server_pubkey: Pubkey,
    num_clients: usize,
    pps: usize,
) -> Vec<Connection> {
    let server_name = socket_addr_to_quic_server_name(server_addr);
    let mut established = Vec::with_capacity(num_clients);
    let mut in_flight = JoinSet::new();
    let mut next = 0usize;
    // Round-robins clients over the sockets without a `%`, which clippy rejects
    // for a divisor it cannot prove nonzero.
    let mut endpoints = endpoints.iter().cycle();
    while next < num_clients || !in_flight.is_empty() {
        while next < num_clients && in_flight.len() < CONNECT_CONCURRENCY {
            let endpoint = endpoints
                .next()
                .expect("cycle over a non-empty slice")
                .clone();
            let config = new_client_config(&client_keypair(next), pps);
            let server_name = server_name.clone();
            in_flight.spawn(async move {
                for attempt in 0..CONNECT_ATTEMPTS {
                    if attempt > 0 {
                        sleep(Duration::from_millis(200)).await;
                    }
                    let Ok(connecting) =
                        endpoint.connect_with(config.clone(), server_addr, &server_name)
                    else {
                        continue;
                    };
                    let Ok(connection) = connecting.await else {
                        continue;
                    };
                    assert_eq!(
                        get_remote_pubkey(&connection),
                        Some(server_pubkey),
                        "server must present the expected votor identity"
                    );
                    return Some(connection);
                }
                None
            });
            next = next.saturating_add(1);
        }
        if let Some(joined) = in_flight.join_next().await {
            let connection = joined
                .expect("connect task must not panic")
                .expect("client must connect within the attempt budget");
            established.push(connection);
        }
    }
    established
}
