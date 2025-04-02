#![allow(clippy::arithmetic_side_effects)]
use {
    crate::gossip::*,
    anyhow::Context,
    clap::{Parser, Subcommand, ValueEnum},
    cluster_probes::find_validator_ports,
    log::{error, info},
    monitor::start_monitor,
    network_interface::{NetworkInterface, NetworkInterfaceConfig},
    std::{net::SocketAddr, path::PathBuf, sync::atomic::AtomicBool, time::Duration},
    turbine::validate_turbine,
};

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
    Monitor {
        #[arg(short, long)]
        /// Gossip socket of the local validator (to fetch metadata and for interface bind)
        gossip_addr: SocketAddr,
        #[arg(short, long, value_enum, default_value_t=Direction::Inbound)]
        ///Defines which direction to capture.
        direction: Direction,
        #[arg(short, long, default_value = "monitor_data")]
        /// Directory for files to write. Existing contents may be destroyed!
        output: PathBuf,

        #[arg(short, long, default_value = "60")]
        /// Timeout for discovery of turbine and repair ports. set to 0 to ony work with gossip
        discovery_timeout_sec: u64,
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
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for event");
    println!("Received termination siganl");
    EXIT.store(true, std::sync::atomic::Ordering::Relaxed);
    // Wait for workers to ack that they are exiting
    tokio::time::sleep(Duration::from_secs(5)).await;

    if crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        println!("Timed out waiting for capture to stop, aborting!");
        std::process::exit(1);
    }
}
use iocraft::prelude::*;
#[component]
fn Menu(mut hooks: Hooks) -> impl Into<AnyElement<'static>> {
    let mut speeds =
        hooks.use_state::<Vec<(String, f32)>, _>(|| vec![("Speed".to_owned(), 0.0); 2]);
    hooks.use_future(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut speeds = speeds.write();
            for s in speeds.iter_mut() {
                s.1 += 1.0;
            }
        }
    });

    element! {
        View(border_style: BorderStyle::Round, border_color: Color::Cyan ) {
            ui::RateDisplay(rates:speeds.read().clone(), )
        }
    }
}
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    solana_logger::setup_with_default_filter();
    tokio::spawn(sig_handler());
    let cli = Cli::parse();
    // element!(Menu).render_loop().await.unwrap();
    // return Ok(());
    // println!("done!");
    match cli.command {
        Commands::Monitor {
            gossip_addr,
            direction,
            output,
            discovery_timeout_sec,
        } => {
            let bind_interface = {
                let network_interfaces = NetworkInterface::show()?;
                network_interfaces
                    .iter()
                    .find(|itf| itf.addr.iter().any(|addr| addr.ip() == gossip_addr.ip()))
                    .ok_or(anyhow::anyhow!("No interface found with specified IP!"))?
                    .clone()
            };
            info!("Binding to interface {}", &bind_interface.name);

            if direction == Direction::Outbound {
                todo!("Outbound capture is not supported yet");
            }
            let _ = std::fs::create_dir(&output);
            let ports =
                find_validator_ports(gossip_addr, Duration::from_secs(discovery_timeout_sec))
                    .await
                    .context("Lookup validator ports")?;
            dbg!(&ports);
            /*let ports = Ports {
                gossip: gossip_addr,
                repair: "1.1.1.1:1111".parse().unwrap(),
                tpu: None,
                tpu_quic: None,
                tpu_vote: None,
                turbine: "1.1.1.1:2222".parse().unwrap(),
            };*/
            start_monitor(bind_interface, ports, output).await?;
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
