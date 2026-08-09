//! Load generator for `bench_server`.
//!
//! Opens `--num-clients` QUIC connections, each with its own votor identity and
//! the production client transport config, then sends
//! DATAGRAMS_PER_SECOND_PER_PEER datagrams per second on every connection.
//! Connections are multiplexed over `--num-sockets` quinn endpoints: the server
//! keys peers by pubkey, not source address, so one UDP socket can carry many
//! identities.

#![allow(clippy::arithmetic_side_effects)]
use {
    agave_votor_transport::{MAX_ALPENGLOW_VOTE_ACCOUNTS, transport::new_client_config},
    bytes::Bytes,
    clap::Parser,
    futures::{StreamExt, stream},
    quinn::{Connection, Endpoint, EndpointConfig, TokioRuntime},
    solana_net_utils::sockets::{SocketConfiguration, bind_to_with_config},
    solana_pubkey::Pubkey,
    solana_tls_utils::{get_remote_pubkey, socket_addr_to_quic_server_name},
    std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        process::exit,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    },
    tokio::{
        runtime::Builder,
        task::JoinSet,
        time::{Instant, MissedTickBehavior, interval, interval_at, sleep},
    },
};

mod common;
use common::{DATAGRAMS_PER_SECOND_PER_PEER, QUIC_CONTROL_TRAFFIC_BUFFER_SIZE, client_keypair};

/// Handshakes started concurrently. The server admits 2000/s globally with a
/// burst of 400, so staying well under that keeps the connect phase clean.
const CONNECT_CONCURRENCY: usize = 128;
/// Attempts per client before giving up on the connect phase.
const CONNECT_ATTEMPTS: usize = 5;
const RETRY_DELAY: Duration = Duration::from_millis(200);

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    server_addr: SocketAddr,
    #[arg(long)]
    server_pubkey: Pubkey,
    #[arg(long, default_value_t = MAX_ALPENGLOW_VOTE_ACCOUNTS)]
    num_clients: usize,
    #[arg(long, default_value_t = 256)]
    num_sockets: usize,
    /// Tasks the connections are sharded over for sending.
    #[arg(long, default_value_t = 16)]
    send_tasks: usize,
    #[arg(long, default_value_t = 160)]
    payload_bytes: usize,
    #[arg(long, default_value_t = 16)]
    worker_threads: usize,
    #[arg(long, default_value_t = 20)]
    duration_secs: u64,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let runtime = Builder::new_multi_thread()
        .worker_threads(cli.worker_threads)
        .thread_name("votor-bench-gen")
        .enable_all()
        .build()
        .expect("tokio multi-thread runtime");

    runtime.block_on(async move {
        let socket_config =
            SocketConfiguration::default().recv_buffer_size(QUIC_CONTROL_TRAFFIC_BUFFER_SIZE);
        let endpoints: Vec<Endpoint> = (0..cli.num_sockets)
            .map(|_| {
                let socket = bind_to_with_config(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, socket_config)
                    .expect("bind load generator UDP socket");
                Endpoint::new(
                    EndpointConfig::default(),
                    None,
                    socket,
                    Arc::new(TokioRuntime),
                )
                .expect("quinn client endpoint")
            })
            .collect();

        let connections = connect_all(
            &endpoints,
            cli.server_addr,
            cli.server_pubkey,
            cli.num_clients,
        )
        .await;
        println!("CONNECTED {}", connections.len());

        let sent = Arc::new(AtomicU64::new(0));
        let payload = Bytes::from(vec![0xA5u8; cli.payload_bytes]);
        let period = Duration::from_secs(1) / DATAGRAMS_PER_SECOND_PER_PEER as u32;

        let mut senders = JoinSet::new();
        let start = Instant::now();
        let shard_size = cli.num_clients.div_ceil(cli.send_tasks).max(1);
        for (shard_index, shard) in connections.chunks(shard_size).enumerate() {
            let shard = shard.to_vec();
            let payload = payload.clone();
            let sent = sent.clone();
            // Stagger send phases so the aggregate send rate is smooth.
            let offset = period * shard_index as u32 / cli.send_tasks as u32;
            senders.spawn(async move {
                let mut tick = interval_at(start + offset, period);
                tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    for connection in &shard {
                        // Every failure mode here (connection lost, datagrams
                        // disabled, payload too large) invalidates the run, and
                        // a panicking task would only stall its own shard.
                        connection
                            .send_datagram(payload.clone())
                            .unwrap_or_else(|err| {
                                eprintln!("send_datagram failed: {err}");
                                exit(1)
                            });
                    }
                    sent.fetch_add(shard.len() as u64, Ordering::Relaxed);
                }
            });
        }

        let mut report = interval(Duration::from_secs(1));
        report.set_missed_tick_behavior(MissedTickBehavior::Delay);
        report.tick().await;
        let mut prev_sent = 0;
        for t in 0..cli.duration_secs {
            report.tick().await;
            let tx_total = sent.load(Ordering::Relaxed);
            println!(
                "TX t={t} tx_per_s={} tx_total={tx_total}",
                tx_total.saturating_sub(prev_sent),
            );
            prev_sent = tx_total;
        }
        senders.abort_all();
    });
}

/// Establish one connection per client identity, retrying transient failures.
///
/// `buffer_unordered` bounds how many handshakes are in flight, which is what
/// keeps the connect phase under the server's global handshake rate limit.
async fn connect_all(
    endpoints: &[Endpoint],
    server_addr: SocketAddr,
    server_pubkey: Pubkey,
    num_clients: usize,
) -> Vec<Connection> {
    let server_name = socket_addr_to_quic_server_name(server_addr);
    stream::iter((0..num_clients).zip(endpoints.iter().cycle()))
        .map(|(index, endpoint)| {
            let server_name = server_name.clone();
            async move {
                let config =
                    new_client_config(&client_keypair(index), DATAGRAMS_PER_SECOND_PER_PEER);
                for attempt in 0..CONNECT_ATTEMPTS {
                    if attempt > 0 {
                        sleep(RETRY_DELAY).await;
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
                    return connection;
                }
                panic!("client {index} did not connect in {CONNECT_ATTEMPTS} attempts");
            }
        })
        .buffer_unordered(CONNECT_CONCURRENCY)
        .collect()
        .await
}
