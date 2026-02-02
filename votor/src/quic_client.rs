use {
    quinn::Endpoint,
    solana_clock::DEFAULT_MS_PER_SLOT,
    solana_keypair::Keypair,
    solana_runtime::bank::MAX_ALPENGLOW_VOTE_ACCOUNTS,
    solana_tls_utils::NotifyKeyUpdate,
    solana_tpu_client_next::{
        connection_workers_scheduler::{
            build_client_config, setup_endpoint, BindTarget, StakeIdentity,
        },
        transaction_batch::TransactionBatch,
        workers_cache::{shutdown_worker, WorkersCache, WorkersCacheError},
        ConnectionWorkersSchedulerError, SendTransactionStats,
    },
    std::{io, net::SocketAddr, sync::Arc, time::Duration},
    tokio::{runtime::Runtime, sync::watch},
    tokio_util::sync::CancellationToken,
};

/// Channel size for the tpu-client-next workers.
/// This essentially buffers messages which are not yet sent on the wire.
/// Keeping this small ensures that if some network-layer backlog accumulates,
/// we get errors sooner.
const WORKER_CHANNEL_SIZE: usize = 8;

/// How many times to attempt to reconnect to a given validator before giving up.
/// Disabled to uplevel connection errors here sooner.
const MAX_RECONNECT_ATTEMPTS: usize = 0;

/// QUIC connection setup timeout. Needs to be long enough to accommodate
/// longest RTT link on the internet + possible packet loss.
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Reporting interval for stats reported by tpu-client-next
const QUIC_STATS_REPORTING_INTERVAL: Duration = Duration::from_millis(DEFAULT_MS_PER_SLOT);

/// Number of threads to use for the QUIC runtime sending BLS messages.
const QUIC_RUNTIME_THREADS: usize = 4;

/// QUIC sender for Votor based on tpu-client-next crate
/// uses low-level access to WorkersCache to ensure we
/// can track the status of connections in more detail
pub struct VotorQuicClient {
    workers: WorkersCache,
    endpoint: Endpoint,
    update_identity_receiver: watch::Receiver<Option<StakeIdentity>>,
    stats: Arc<SendTransactionStats>,
    runtime_handle: tokio::runtime::Handle,
    cancel: CancellationToken,
}

impl VotorQuicClient {
    /// Spawns a runtime configured for vote sending
    pub fn spawn_runtime() -> io::Result<Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(QUIC_RUNTIME_THREADS)
            .enable_all()
            .build()
    }

    pub fn new(
        runtime_handle: tokio::runtime::Handle,
        bind: BindTarget,
        stake_identity: StakeIdentity,
        cancel: CancellationToken,
    ) -> Result<(Self, UpdateHandler), ConnectionWorkersSchedulerError> {
        let (update_identity_sender, update_identity_receiver) = watch::channel(None);
        let tokio_guard = runtime_handle.enter();
        let endpoint = setup_endpoint(bind, Some(stake_identity))?;
        let workers = WorkersCache::new(MAX_ALPENGLOW_VOTE_ACCOUNTS * 2, cancel.clone());

        let stats = Arc::new(SendTransactionStats::default());
        runtime_handle.spawn(stats.clone().report_to_influxdb(
            "VotorSender",
            QUIC_STATS_REPORTING_INTERVAL,
            cancel.clone(),
        ));
        drop(tokio_guard);
        Ok((
            Self {
                workers,
                endpoint,
                stats,
                update_identity_receiver,
                runtime_handle,
                cancel,
            },
            UpdateHandler(update_identity_sender),
        ))
    }

    /// Broadcasts the provided buffer to the peers
    pub fn send_message_to_peers(&mut self, buf: Vec<u8>, peers: impl Iterator<Item = SocketAddr>) {
        if self.cancel.is_cancelled() {
            // avoid spamming errors and new workers during shutdown
            return;
        }
        self.check_for_identity_update();
        let tokio_guard = self.runtime_handle.enter();
        // clone on TransactionBatch is cheap (compared to cloning the buf)
        let txs_batch = TransactionBatch::new(vec![buf]);
        for peer in peers {
            debug!("Sending message to peer: {peer}");
            if let Some(old_worker) = self.workers.ensure_worker(
                peer,
                &self.endpoint,
                WORKER_CHANNEL_SIZE,
                true,
                MAX_RECONNECT_ATTEMPTS,
                QUIC_HANDSHAKE_TIMEOUT,
                self.stats.clone(),
            ) {
                info!("Reestablishing connection to {peer}");
                shutdown_worker(old_worker)
            }
            match self
                .workers
                .try_send_transactions_to_address(&peer, txs_batch.clone())
            {
                Ok(_) => {}
                Err(WorkersCacheError::FullChannel) => {
                    warn!("Failed to send BLS message to {peer}: peer not reading messages");
                }
                Err(WorkersCacheError::ReceiverDropped) => {
                    warn!("Failed to send BLS message to {peer}: peer connection refused");
                }
                Err(e) => {
                    warn!("Failed to send BLS message to {peer}: {e:?}");
                }
            }
        }
        drop(tokio_guard);
    }

    fn check_for_identity_update(&mut self) {
        let tokio_guard = self.runtime_handle.enter();
        // we can ignore error case here since it corresponds to shutdown scenario
        if !self.update_identity_receiver.has_changed().unwrap_or(false) {
            return;
        }

        let client_config =
            build_client_config(self.update_identity_receiver.borrow_and_update().as_ref());
        self.endpoint.set_default_client_config(client_config);
        // Flush workers since they are handling connections created
        // with outdated certificate.
        self.workers.flush();
        drop(tokio_guard);
        info!("Updated QUIC client certificate.");
    }
}

pub struct UpdateHandler(watch::Sender<Option<StakeIdentity>>);

impl NotifyKeyUpdate for UpdateHandler {
    fn update_key(&self, key: &Keypair) -> Result<(), Box<dyn std::error::Error>> {
        Ok(self
            .0
            .send(Some(StakeIdentity::new(key)))
            .map_err(Box::new)?)
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::quic_client::VotorQuicClient,
        solana_bls_signatures::keypair,
        solana_clock::NUM_CONSECUTIVE_LEADER_SLOTS,
        solana_gossip::cluster_info::DEFAULT_NUM_TVU_RECEIVE_SOCKETS,
        solana_keypair::Keypair,
        solana_net_utils::sockets::bind_to_localhost_unique,
        solana_runtime::bank::MAX_ALPENGLOW_VOTE_ACCOUNTS,
        solana_signer::Signer,
        solana_streamer::{
            nonblocking::simple_qos::SimpleQosConfig,
            quic::{spawn_simple_qos_server, QuicStreamerConfig, SpawnServerResult},
            streamer::StakedNodes,
        },
        solana_tls_utils::NotifyKeyUpdate,
        solana_tpu_client_next::connection_workers_scheduler::{BindTarget, StakeIdentity},
        std::{
            collections::HashMap,
            num::{NonZeroU32, NonZeroUsize},
            sync::{Arc, RwLock},
            time::{Duration, Instant},
        },
        tokio::runtime::{Builder, Runtime},
        tokio_util::sync::CancellationToken,
    };

    #[test]
    fn test_quic_identity_update() {
        agave_logger::setup();
        let keypair = Keypair::new();
        let staked_keypair = Keypair::new();

        // Bind to a random UDP port
        let listener_socket = bind_to_localhost_unique().unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();

        let cancel = CancellationToken::new();
        let bind = BindTarget::Socket(bind_to_localhost_unique().unwrap());
        let runtime = VotorQuicClient::spawn_runtime().unwrap();
        let (mut quic_sender, key_updater) = VotorQuicClient::new(
            runtime.handle().clone(),
            bind,
            StakeIdentity::new(&keypair),
            cancel.clone(),
        )
        .unwrap();

        let staked_nodes: Arc<RwLock<StakedNodes>> = Arc::new(RwLock::new(StakedNodes::new(
            Arc::new(HashMap::from([(staked_keypair.pubkey(), 1000u64)])),
            HashMap::default(), // overrides
        )));
        let (sender, receiver) = crossbeam_channel::bounded(100);
        let SpawnServerResult {
            endpoints: _,
            thread: quic_server_thread,
            key_updater: _,
        } = spawn_simple_qos_server(
            "AlpenglowLocalClusterTest",
            "quic_client_test",
            [listener_socket],
            &Keypair::new(),
            sender,
            staked_nodes,
            QuicStreamerConfig::default_for_tests(),
            SimpleQosConfig::default(),
            cancel.clone(),
        )
        .unwrap();
        // make sure the server is up and running before sending packets
        std::thread::sleep(Duration::from_secs(1));

        let sent_message = vec![1, 2, 3, 4];
        quic_sender.send_message_to_peers(sent_message.clone(), vec![listener_addr].into_iter());
        // wait for 1 second to make sure we DO NOT receive any packets (since we are sending as unstaked)
        assert!(receiver.recv_timeout(Duration::from_secs(1)).is_err());
        // update the keypair to be staked and try again
        key_updater.update_key(&staked_keypair).unwrap();
        quic_sender.send_message_to_peers(sent_message.clone(), vec![listener_addr].into_iter());
        let packets = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let received_message = packets.first().expect("Must have packets received");
        assert_eq!(
            received_message.data(..).unwrap(),
            sent_message,
            "must have received what we have sent"
        );
        cancel.cancel();
        quic_server_thread.join().unwrap();
    }

    #[test]
    fn test_fanout() {
        agave_logger::setup();
        let n = MAX_ALPENGLOW_VOTE_ACCOUNTS;
        let keypairs = (0..n).map(|_| Keypair::new()).collect::<Vec<_>>();

        let keypair = keypairs[0].insecure_clone();
        // Bind to a random UDP port
        let listener_sockets = (0..n)
            .map(|_| solana_net_utils::bind_to_localhost().unwrap())
            .collect::<Vec<_>>();
        let listener_addrs = listener_sockets
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect::<Vec<_>>();

        let cancel = CancellationToken::new();

        let bind = BindTarget::Socket(solana_net_utils::bind_to_localhost().unwrap());
        let runtime = VotorQuicClient::spawn_runtime().unwrap();
        let (mut quic_sender, key_updater) = VotorQuicClient::new(
            runtime.handle().clone(),
            bind,
            StakeIdentity::new(&keypair),
            cancel.clone(),
        )
        .unwrap();

        let staked_nodes: Arc<RwLock<StakedNodes>> = Arc::new(RwLock::new(StakedNodes::new(
            Arc::new(HashMap::from_iter(
                keypairs.iter().map(|kp| (kp.pubkey(), 1000)),
            )),
            HashMap::default(), // overrides
        )));
        let (sender, receiver) = crossbeam_channel::bounded(MAX_ALPENGLOW_VOTE_ACCOUNTS);
        //let server_rt = Builder::new_multi_thread().enable_all().build().unwrap();

        // for keypair in keypairs {
        //     // server_rt.spawn(async{

        //     //     solana_streamer::nonblocking::quic::spawn_server
        //     // });
        // }
        let servers = keypairs
            .iter()
            .zip(listener_sockets.into_iter())
            .map(|(keypair, listener_socket)| {
                let result = spawn_simple_qos_server(
                    "AlpenglowLocalClusterTest",
                    "quic_client_test",
                    [listener_socket],
                    &Keypair::new(),
                    sender.clone(),
                    staked_nodes.clone(),
                    QuicStreamerConfig {
                        max_connections_per_ipaddr_per_min: 32,
                        num_threads: NonZeroUsize::new(2).unwrap(),
                        ..Default::default()
                    },
                    SimpleQosConfig::default(),
                    cancel.clone(),
                )
                .unwrap();
                result
            })
            .collect::<Vec<_>>();

        // make sure the server is up and running before sending packets
        std::thread::sleep(Duration::from_secs(2));

        let sent_message = vec![1, 2, 3, 4];
        quic_sender.send_message_to_peers(sent_message.clone(), listener_addrs.iter().cloned());
        std::thread::sleep(Duration::from_secs(2));

        let t0 = Instant::now();
        quic_sender.send_message_to_peers(sent_message.clone(), listener_addrs.iter().cloned());

        let mut num_received = 0;
        'outer: loop {
            let packets = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
            for received_message in packets.into_iter() {
                assert_eq!(
                    received_message.data(..).unwrap(),
                    sent_message,
                    "must have received what we have sent"
                );
                num_received += 1;
                info!("Received message {num_received}");
                if num_received == servers.len() {
                    break 'outer;
                }
            }
        }
        println!("Received all messages in {}ms", t0.elapsed().as_millis());
        cancel.cancel();
    }
}
