use {
    crate::{
        bpf_controls::*,
        cluster_probes::Ports,
        gossip,
        turbine::{self, TurbineLogger},
        Direction, WireProtocol,
    },
    anyhow::Context as _,
    clap::Subcommand,
    log::{error, info},
    std::{
        io::Write,
        net::{IpAddr, Ipv4Addr},
        ops::ControlFlow,
        path::PathBuf,
        time::Duration,
    },
    wf_common::Flags,
};

#[derive(Debug, Subcommand)]
pub enum MonitorCommand {
    LogMetadata {
        #[arg()]
        protocol: WireProtocol,
    },
    LogGossipInvalidSenders,
    Bitrate {
        #[arg(short, long)]
        report_metrics: bool,
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
    bpf_flags: Flags,
    ports: Ports,
    command: MonitorCommand,
    output: PathBuf,
    direction: Direction,
) -> anyhow::Result<()> {
    // element!(MainMenu).fullscreen().await.unwrap();
    // return Ok(());
    bump_rlimit();
    let mut bpf_controls = match direction {
        Direction::Inbound => {
            let mut bpf_controls = BpfControls::new_ingress(&interface.name)?;
            info!("Ingress monitor set up on interface {}", &interface.name);
            bpf_controls.set_flags(bpf_flags)?;
            // Allow all senders
            bpf_controls.allow_src_ip(Ipv4Addr::UNSPECIFIED)?;
            bpf_controls.allow_src_port(0)?;
            // only capture packets to me, not stuff i might forward
            bpf_controls.allow_dst_ip(v4(ports.gossip.ip()))?;
            bpf_controls
        }
        Direction::Outbound => {
            let mut bpf_controls = BpfControls::new_egress(&interface.name)?;
            info!("Egress monitor set up on interface {}", &interface.name);
            bpf_controls.set_flags(bpf_flags)?;
            // Allow all destinations
            bpf_controls.allow_dst_ip(Ipv4Addr::UNSPECIFIED)?;
            bpf_controls.allow_dst_port(0)?;
            // only capture packets from my own IP not forwarded
            bpf_controls.allow_src_ip(v4(ports.gossip.ip()))?;
            bpf_controls
        }
        Direction::Both => {
            anyhow::bail!("Capturing in both directions not supported yet")
        }
    };

    match command {
        MonitorCommand::LogGossipInvalidSenders => {
            let mut logger = gossip::MysteryCRDSLogger::new(ports.shred_version, output.clone());
            match direction {
                Direction::Inbound => bpf_controls.allow_dst_port(ports.gossip.port())?,
                Direction::Outbound => bpf_controls.allow_src_port(ports.gossip.port())?,
                Direction::Both => todo!(),
            }
            process_packet_flow(&mut bpf_controls, &mut logger).await?;

            info!("Gossip monitoring done");
        }
        MonitorCommand::LogMetadata { protocol } => match protocol {
            WireProtocol::Gossip => {
                //bpf_controls.allow_dst_port(ports.gossip.port())?;
                //gossip_log_metadata(&mut bpf_controls.rx_ring, size_hint).await;
                todo!();
            }
            WireProtocol::Turbine => {
                let turbine_port = ports.turbine.context("Turbine port is required")?.port();

                info!("Turbine + Repair capture starting");
                let mut logger = match direction {
                    Direction::Inbound => {
                        let repair_port = ports.repair.context("Repair port is required")?.port();
                        let logger =
                            TurbineLogger::new_with_file_writer(output, turbine_port, repair_port)
                                .await?;
                        bpf_controls.allow_dst_port(turbine_port)?;
                        bpf_controls.allow_dst_port(repair_port)?;
                        logger
                    }
                    Direction::Outbound => {
                        let repair_port = ports
                            .serve_repair
                            .context("Repair port is required")?
                            .port();
                        let logger =
                            TurbineLogger::new_with_file_writer(output, turbine_port, repair_port)
                                .await?;
                        bpf_controls.allow_src_port(turbine_port)?;
                        bpf_controls.allow_src_port(repair_port)?;
                        logger
                    }
                    Direction::Both => todo!(),
                };
                process_packet_flow(&mut bpf_controls, &mut logger).await?;
            }
            WireProtocol::Repair => todo!(),
        },
        MonitorCommand::Bitrate {
            protocol,
            report_metrics,
        } => {
            if report_metrics {
                solana_metrics::set_host_id(ports.pubkey.to_string());
            };
            match protocol {
                WireProtocol::Gossip => {
                    let metrics = if report_metrics {
                        Some(match direction {
                            Direction::Inbound => "gossip_rates_inbound",
                            Direction::Outbound => "gossip_rates_outbound",
                            Direction::Both => todo!(),
                        })
                    } else {
                        None
                    };
                    let mut monitor = gossip::BitrateMonitor::new(metrics);
                    match direction {
                        Direction::Inbound => bpf_controls.allow_dst_port(ports.gossip.port())?,
                        Direction::Outbound => bpf_controls.allow_src_port(ports.gossip.port())?,
                        Direction::Both => todo!(),
                    }
                    process_packet_flow(&mut bpf_controls, &mut monitor).await?;
                }
                WireProtocol::Turbine => {
                    let turbine_port = ports.turbine.expect("Turbine port is required").port();
                    let metrics = if report_metrics {
                        Some(match direction {
                            Direction::Inbound => "turbine_rates_inbound",
                            Direction::Outbound => "turbine_rates_outbound",
                            Direction::Both => todo!(),
                        })
                    } else {
                        None
                    };
                    let mut monitor = turbine::BitrateMonitor::new(metrics);
                    match direction {
                        Direction::Inbound => {
                            let repair_port =
                                ports.repair.context("Repair port is required")?.port();
                            println!("Opening ingress ports {turbine_port} and {repair_port}");
                            bpf_controls.allow_dst_port(turbine_port)?;
                            bpf_controls.allow_dst_port(repair_port)?;
                        }
                        Direction::Outbound => {
                            let repair_port = ports
                                .serve_repair
                                .context("Repair port is required")?
                                .port();
                            bpf_controls.allow_src_port(turbine_port)?;
                            bpf_controls.allow_src_port(repair_port)?;
                        }
                        Direction::Both => todo!(),
                    };
                    process_packet_flow(&mut bpf_controls, &mut monitor).await?;
                }
                WireProtocol::Repair => todo!("Repair not yet supported"),
            }
        }
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

pub async fn detect_repair_shreds(
    interface: network_interface::NetworkInterface,
    bpf_flags: Flags,
    port_range: &[u16],
    dst_ip: IpAddr,
) -> anyhow::Result<Option<u16>> {
    let mut bpf_controls = BpfControls::new_ingress(&interface.name)?;
    info!("Monitor set up on interface {}", &interface.name);
    // Allow all senders
    bpf_controls.allow_src_ip(Ipv4Addr::UNSPECIFIED)?;
    bpf_controls.allow_src_port(0)?;
    bpf_controls.set_flags(bpf_flags)?;
    let (mut logger, mut rx) = TurbineLogger::new_with_channel(0, 0)?;
    let timeout = Duration::from_secs(1);
    let mut result = 0;
    for port in port_range.iter().cloned() {
        bpf_controls.reset_dst()?;
        info!("Probing for repair packets on port {port}...");
        bpf_controls.allow_dst_ip(v4(dst_ip))?;
        bpf_controls.allow_dst_port(port)?;
        tokio::select! {
           res =  tokio::time::timeout(timeout, rx.recv())=> {
               match res{
                   Ok(shred) => {
                       if let Some(shred) = shred {
                           bpf_controls.reset_dst()?;
                           std::io::stdout().write_all(&shred)?;
                           result = port;
                       }
                       else{
                           anyhow::bail!("Channel closed wtf");
                       }
                       break;
                   },
                   Err(_) => {
                       continue;
                   }
               }
           },
               _ = process_packet_flow(&mut bpf_controls, &mut logger) => {}
        }
    }
    bpf_controls.reset_dst()?;
    logger.finalize().await?;
    if result != 0 {
        info!("Found repair traffic on port {result}");
        return Ok(Some(result));
    }
    error!("Could not find repair shreds anywhere in {:?}!", port_range);
    return Ok(None);
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
