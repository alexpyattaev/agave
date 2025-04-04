use {
    crate::{
        bpf_controls::*, cluster_probes::Ports, gossip::*, turbine::TurbineLogger, WireProtocol,
    },
    anyhow::Context,
    aya::maps::{Array, MapData, RingBuf},
    clap::{Parser, Subcommand},
    log::{error, info, warn},
    std::{
        net::{IpAddr, Ipv4Addr},
        ops::ControlFlow,
        path::PathBuf,
        time::Duration,
    },
    tokio::io::unix::AsyncFd,
};
#[derive(Debug, Subcommand)]
pub enum MonitorCommand {
    LogMetadata {
        #[arg()]
        protocol: WireProtocol,
    },
    LogGossipInvalidSenders,
    Bitrate {
        #[arg()]
        protocol: WireProtocol,
    },
    Capture {
        #[arg()]
        protocol: WireProtocol,
        #[arg(short, long, default_value_t = 512)]
        /// Rough number of pacekts to capture (exact number will depend on the protocol)
        size_hint: usize,
        /// Only capture when rate is above given value in PPS
        #[arg(short, long, default_value_t = 10000)]
        threshold_rate: usize,
    },
}

pub async fn start_monitor(
    interface: network_interface::NetworkInterface,
    ports: Ports,
    command: MonitorCommand,
    output: PathBuf,
) -> anyhow::Result<()> {
    // element!(MainMenu).fullscreen().await.unwrap();
    // return Ok(());
    let mut bpf_controls = BpfControls::new(&interface.name)?;
    info!("Monitor set up on interface {}", &interface.name);
    // Allow all senders
    bpf_controls.allow_src_ip(Ipv4Addr::UNSPECIFIED)?;
    bpf_controls.allow_src_port(0)?;

    bpf_controls.allow_dst_ip(v4(ports.gossip.ip()))?;
    match command {
        MonitorCommand::LogGossipInvalidSenders => {
            let mut logger = MysteryCRDSLogger::new(ports.shred_version, output.clone());
            bpf_controls.allow_dst_port(ports.gossip.port())?;
            process_packet_flow(&mut bpf_controls, &mut logger).await?;

            info!("Gossip monitoring done");
        }
        MonitorCommand::LogMetadata { protocol } => match protocol {
            WireProtocol::Gossip => {
                bpf_controls.allow_dst_port(ports.gossip.port())?;
                //gossip_log_metadata(&mut bpf_controls.rx_ring, size_hint).await;
                todo!();
            }
            WireProtocol::Turbine => {
                let turbine_port = ports.turbine.expect("Turbine port is required").port();
                let repair_port = ports.repair.expect("Repair port is required").port();

                let mut logger = TurbineLogger::new(output, turbine_port, repair_port).await?;

                info!("Turbine + Repair capture starting");
                bpf_controls.allow_dst_port(turbine_port)?;
                bpf_controls.allow_dst_port(repair_port)?;
                process_packet_flow(&mut bpf_controls, &mut logger).await?;
            }
            WireProtocol::Repair => todo!(),
        },
        MonitorCommand::Bitrate { protocol } => match protocol {
            WireProtocol::Gossip => {
                let mut monitor = GossipBitrateMonitor::new();
                bpf_controls.allow_dst_port(ports.gossip.port())?;
                process_packet_flow(&mut bpf_controls, &mut monitor).await?;
            }
            WireProtocol::Turbine => {}
            WireProtocol::Repair => todo!(),
        },
        MonitorCommand::Capture {
            size_hint,
            threshold_rate,
            protocol,
        } => {
            dbg!(size_hint, threshold_rate, protocol);
            todo!()
        }
    }
    bpf_controls.reset_dst()?;
    Ok(())
}

pub trait PacketLogger {
    fn handle_pkt(&mut self, wire_bytes: &[u8]) -> ControlFlow<()>;
    async fn finalize(&mut self) -> anyhow::Result<()>;
}

pub async fn process_packet_flow(
    bpf_controls: &mut BpfControls,
    handler: &mut impl PacketLogger,
) -> anyhow::Result<()> {
    'outer: while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        // wait till it is ready to read
        let guard =
            tokio::time::timeout(Duration::from_secs(1), bpf_controls.rx_ring.readable_mut()).await;
        let mut guard = match guard {
            Ok(guard) => guard?,
            Err(_) => {
                continue;
            }
        };
        let rb = guard.get_inner_mut();
        while let Some(read) = rb.next() {
            if crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
                break 'outer;
            }
            let ptr = read.as_ptr();

            // retrieve packet len first then packet data
            let size = unsafe { std::ptr::read_unaligned::<u16>(ptr as *const u16) };
            let wire_bytes = unsafe { std::slice::from_raw_parts(ptr.byte_add(2), size.into()) };

            if let ControlFlow::Break(_) = handler.handle_pkt(wire_bytes) {
                break 'outer;
            }
        }
        guard.clear_ready();
    }
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    bpf_controls.reset_dst().expect("BPF shutdown fail!");
    info!("Termination acknowledged, finalizing");
    handler.finalize().await
}
