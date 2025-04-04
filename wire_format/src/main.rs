#![allow(clippy::arithmetic_side_effects)]
use {
    crate::gossip::*,
    anyhow::Context,
    clap::{Parser, Subcommand, ValueEnum},
    cluster_probes::{find_validator_ports, Ports},
    log::{error, info},
    monitor::{start_monitor, MonitorCommand},
    network_interface::{NetworkInterface, NetworkInterfaceConfig},
    std::{fs::File, net::SocketAddr, path::PathBuf, sync::atomic::AtomicBool, time::Duration},
    turbine::validate_turbine,
};

mod bpf_controls;
mod cluster_probes;
mod gossip;
mod monitor;
mod repair;
mod storage;
mod turbine;
mod ui;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum WireProtocol {
    Gossip,
    Turbine,
    Repair,
}

#[derive(Parser)]
#[command(version, about,  long_about = None)]
struct Cli {
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long, default_value = ".wire_format.json")]
    config: PathBuf,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Direction {
    /// Capture incoming traffic with eBPF
    Inbound,
    /// Capture outbound traffic with TC eBPF
    Outbound,
    /// Capture in both directions
    Both,
}

#[derive(Subcommand)]
enum Commands {
    Discover {
        #[arg(short, long)]
        /// Gossip socket of the local validator (to fetch metadata and for interface bind)
        gossip_addr: SocketAddr,
        #[arg(short, long, default_value = "120")]
        /// Timeout for discovery of turbine and repair ports. set to 0 to ony work with gossip
        discovery_timeout_sec: u64,
    },
    Monitor {
        /*  #[arg(short, long, value_enum, default_value_t=Direction::Inbound)]
        ///Defines which direction to capture.
        direction: Direction,*/
        #[arg(short, long, default_value = "monitor_data")]
        /// Directory for files to write. Existing contents may be destroyed!
        output: PathBuf,
        #[command(subcommand)]
        command: MonitorCommand,
    },
    Parse {
        #[arg(value_enum)]
        protocol: WireProtocol,
        #[arg()]
        input: PathBuf,
    },
}

pub static EXIT: AtomicBool = AtomicBool::new(false);
async fn sig_handler() {
    loop {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for event");
        println!("Received termination siganal");
        EXIT.store(true, std::sync::atomic::Ordering::Relaxed);
        // Wait for workers to ack that they are exiting
        tokio::time::sleep(Duration::from_secs(10)).await;

        if crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
            println!("Timed out waiting for capture to stop, aborting!");
            std::process::exit(1);
        }
    }
}
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    solana_logger::setup_with_default("info");
    tokio::spawn(sig_handler());
    let cli = Cli::parse();
    match cli.command {
        Commands::Discover {
            gossip_addr,
            discovery_timeout_sec,
        } => {
            let ports =
                find_validator_ports(gossip_addr, Duration::from_secs(discovery_timeout_sec))
                    .await
                    .context("Lookup validator ports")?;
            dbg!(&ports);
            let configfile = File::create(&cli.config)?;
            serde_json::to_writer_pretty(configfile, &ports)?;
            info!("Written ports to {:?}", &cli.config);
        }
        Commands::Monitor { output, command } => {
            let configfile = File::open(&cli.config)
                .context("Config file not found, create it with discover command")?;
            let ports: Ports =
                serde_json::from_reader(configfile).context("Config file is invalid")?;
            info!("Loaded ports from {:?}", &cli.config);
            let bind_interface = {
                let network_interfaces = NetworkInterface::show()?;
                network_interfaces
                    .iter()
                    .find(|itf| itf.addr.iter().any(|addr| addr.ip() == ports.gossip.ip()))
                    .ok_or(anyhow::anyhow!("No interface found with specified IP!"))?
                    .clone()
            };

            let _ = std::fs::create_dir(&output);
            start_monitor(bind_interface, ports, command, output).await?;
        }
        Commands::Parse { input, protocol } => match protocol {
            WireProtocol::Gossip => {
                let stats = validate_gossip(input)?;
                if stats.captured == stats.retained {
                    info!(
                        "All clear, no errors, validated {} packets!",
                        stats.retained
                    );
                    std::process::exit(0);
                } else {
                    error!(
                        "Validation failed for {} packets of {} in the dataset",
                        stats.captured - stats.retained,
                        stats.captured
                    );
                    std::process::exit(1);
                }
            }
            WireProtocol::Turbine => {
                let stats = validate_turbine(input)?;
                dbg!(stats);
            }
            WireProtocol::Repair => {
                todo!()
            }
        },
    }
    std::process::exit(0);
}

#[derive(Debug, Default)]
pub struct Stats {
    pub captured: usize,
    pub valid: usize,
    pub retained: usize,
}
