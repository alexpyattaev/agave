use {
    crate::{cluster_probes::Ports, gossip::*, ui, WireProtocol},
    anyhow::Context,
    aya::{
        include_bytes_aligned,
        maps::{Array, MapData, RingBuf},
        programs::{Xdp, XdpFlags},
        Ebpf,
    },
    aya_log::EbpfLogger,
    clap::{Parser, Subcommand},
    log::{error, info, warn},
    std::{
        i64::MIN,
        net::{IpAddr, Ipv4Addr},
        ops::DerefMut,
        path::PathBuf,
        time::Duration,
    },
    tokio::{
        io::unix::AsyncFd,
        sync::mpsc::{channel, Receiver, Sender},
    },
    tokio_util::sync::CancellationToken,
    wf_common::FILTER_LEN,
};
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CliCommand {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    LogMetadata {
        #[arg()]
        protocol: WireProtocol,
        #[arg(short, long, default_value_t = 1024)]
        /// Rough number of pacekts to capture (exact number will depend on the protocol)
        size_hint: usize,
    },
    LogGossipInvalidSenders {
        #[arg(short, long, default_value_t = 150)]
        /// min number of seconds to monitor for
        min_time: u64,
    },
    Bitrate,
    Exit,
    Stop,
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

fn read_cli(cli_sender: Sender<Command>) -> anyhow::Result<()> {
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let mut rl = rustyline::DefaultEditor::new()?;

        let readline = rl.readline(">> ");
        let input_line = match readline {
            Ok(line) => line,
            Err(_) => break,
        };
        rl.add_history_entry(&input_line)?;
        let cmd = match CliCommand::try_parse_from(
            std::iter::once("").chain(input_line.split(" ").map(|e| e.trim())),
        ) {
            Ok(cmd) => cmd.command,
            Err(e) => {
                println!("Invalid input provided, {e}");
                continue;
            }
        };
        cli_sender.try_send(cmd)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::From)]
struct PortPod(Option<u16>);

unsafe impl aya::Pod for PortPod {}
#[derive(Clone, Copy, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::From)]
struct IpPod(Option<Ipv4Addr>);

unsafe impl aya::Pod for IpPod {}

struct BpfControls {
    _bpf: aya::Ebpf,
    rx_ring: AsyncFd<RingBuf<MapData>>,
    src_port: Array<MapData, PortPod>,
    dst_port: Array<MapData, PortPod>,
    src_ip: Array<MapData, IpPod>,
    dst_ip: Array<MapData, IpPod>,
}

impl BpfControls {
    fn allow<T, V>(map: &mut Array<MapData, T>, new: V) -> anyhow::Result<()>
    where
        T: aya::Pod + DerefMut<Target = Option<V>>,
        T: From<Option<V>>,
        V: Eq + Clone,
    {
        for idx in 0..FILTER_LEN {
            let v = map.get(&idx, 0)?;
            {
                if let Some(v) = v.deref() {
                    // already present
                    if *v == new.clone() {
                        return Ok(());
                    }
                } else {
                    map.set(idx, T::from(Some(new)), 0)?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }
    fn deny_all<T, V>(map: &mut Array<MapData, T>) -> anyhow::Result<()>
    where
        T: aya::Pod,
        T: From<Option<V>>,
    {
        for idx in 0..FILTER_LEN {
            map.set(idx, T::from(None), 0)?;
        }
        Ok(())
    }
    fn allow_src_ip(&mut self, new: Ipv4Addr) -> anyhow::Result<()> {
        Self::allow(&mut self.src_ip, new)
    }
    fn allow_dst_ip(&mut self, new: Ipv4Addr) -> anyhow::Result<()> {
        Self::allow(&mut self.dst_ip, new)
    }
    fn allow_src_port(&mut self, new: u16) -> anyhow::Result<()> {
        Self::allow(&mut self.src_port, new)
    }
    fn allow_dst_port(&mut self, new: u16) -> anyhow::Result<()> {
        Self::allow(&mut self.dst_port, new)
    }
    fn reset_dst(&mut self) -> anyhow::Result<()> {
        Self::deny_all(&mut self.dst_ip)?;
        Self::deny_all(&mut self.dst_port)
    }
    fn new(ifname: &str) -> anyhow::Result<Self> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            error!("remove limit on locked memory failed, ret is: {}", ret);
        }
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        #[cfg(debug_assertions)]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../wf_ebpf/target/bpfel-unknown-none/debug/wf-ebpf"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../wf_ebpf/target/bpfel-unknown-none/release/wf-ebpf"
        ))?;
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        let program: &mut Xdp = bpf
            .program_mut("wf_ebpf")
            .expect("Program should have entrypoint wf_ebpf")
            .try_into()?;
        program.load()?;
        program
            .attach(ifname, XdpFlags::default())
            .context("failed to attach the XDP program")?;

        let src_ports = Array::try_from(bpf.take_map("ALLOW_SRC_PORTS").unwrap()).unwrap();
        let dst_ports = Array::try_from(bpf.take_map("ALLOW_DST_PORTS").unwrap()).unwrap();
        let dst_ip = Array::try_from(bpf.take_map("ALLOW_DST_IP").unwrap()).unwrap();
        let src_ip = Array::try_from(bpf.take_map("ALLOW_SRC_IP").unwrap()).unwrap();
        let rx_ring = RingBuf::try_from(bpf.take_map("RING_BUF").unwrap()).unwrap();
        Ok(BpfControls {
            _bpf: bpf,
            rx_ring: AsyncFd::new(rx_ring)?,
            src_port: src_ports,
            dst_port: dst_ports,
            src_ip,
            dst_ip,
        })
    }
}
fn v4(a: IpAddr) -> Ipv4Addr {
    match a {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        IpAddr::V6(_ipv6_addr) => panic!(),
    }
}

pub async fn start_monitor(
    interface: network_interface::NetworkInterface,
    ports: Ports,
    output: PathBuf,
) -> anyhow::Result<()> {
    info!(
        "Monitor set up on interface {}. Type 'help' for info.",
        &interface.name
    );
    let mut bpf_controls = BpfControls::new(&interface.name)?;
    // Allow all senders
    bpf_controls.allow_src_ip(Ipv4Addr::UNSPECIFIED)?;
    bpf_controls.allow_src_port(0)?;
    let (cli_input_tx, cli_input_rx) = channel(128);

    let mut scope = tokio::task::JoinSet::new();
    scope.spawn_blocking(|| read_cli(cli_input_tx));
    scope.spawn(executor(cli_input_rx, bpf_controls, ports, output));
    while let Some(res) = scope.join_next().await {
        res??;
    }
    Ok(())
}

async fn executor(
    mut cmd_rx: Receiver<Command>,
    mut bpf_controls: BpfControls,
    ports: Ports,
    output: PathBuf,
) -> anyhow::Result<()> {
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let Some(cmd) = cmd_rx.recv().await else {
            break;
        };

        dbg!(&cmd);
        match cmd {
            Command::LogGossipInvalidSenders { min_time } => {
                bpf_controls.allow_dst_ip(v4(ports.gossip.ip()))?;
                bpf_controls.allow_dst_port(ports.gossip.port())?;
                let cancel = CancellationToken::new();

                let cap_thread = gossip_log_invalid_senders(
                    &mut bpf_controls.rx_ring,
                    &output,
                    cancel.clone(),
                    Duration::from_secs(min_time),
                    ports.shred_version,
                );

                tokio::select! {
                    result = cap_thread =>{println!("{result:?}");},
                    _= cmd_rx.recv()=>{}
                }
                cancel.cancel();
                println!("Gossip monitoring done");
                bpf_controls.reset_dst()?;
            }
            Command::LogMetadata {
                size_hint,
                protocol,
            } => match protocol {
                WireProtocol::Gossip => {
                    bpf_controls.allow_dst_ip(v4(ports.gossip.ip()))?;
                    bpf_controls.allow_dst_port(ports.gossip.port())?;

                    let cap_thread = gossip_log_metadata(&mut bpf_controls.rx_ring, size_hint);
                    tokio::select! {
                        _ = cap_thread =>{},
                        _= cmd_rx.recv()=>{}
                    }
                    println!("Gossip monitoring done");
                    bpf_controls.reset_dst()?;
                }
                WireProtocol::Turbine => {}
                WireProtocol::Repair => todo!(),
            },
            Command::Bitrate => todo!(),
            Command::Exit => break,
            Command::Stop => {
                println!("Already stopped");
            }
            Command::Capture {
                size_hint,
                threshold_rate,
                protocol,
            } => {
                dbg!(size_hint, threshold_rate, protocol);
                todo!()
            }
        }
    }
    crate::EXIT.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

pub async fn process_packet_flow(
    async_fd: &mut AsyncFd<RingBuf<MapData>>,
    mut handle_pkt: impl FnMut(&[u8]),
) -> anyhow::Result<()> {
    //Allocate buffer big enough for any valid datagram
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        // wait till it is ready to read and read
        let mut guard = async_fd.readable_mut().await.unwrap();
        let rb = guard.get_inner_mut();

        while let Some(read) = rb.next() {
            let ptr = read.as_ptr();

            // retrieve packet len first then packet data
            let size = unsafe { std::ptr::read_unaligned::<u16>(ptr as *const u16) };
            let data = unsafe { std::slice::from_raw_parts(ptr.byte_add(2), size.into()) };

            handle_pkt(data);
        }
        guard.clear_ready();
    }
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}
