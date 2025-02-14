#![allow(clippy::arithmetic_side_effects)]
use {
    crate::gossip::*,
    anyhow::Context,
    clap::{Parser, Subcommand, ValueEnum},
    cluster_probes::find_turbine_port,
    log::{error, info},
    signal_hook::{consts::SIGINT, iterator::Signals},
    std::{
        error::Error,
        ffi::CString,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::atomic::AtomicBool,
        thread,
        time::Duration,
    },
    turbine::capture_turbine,
};

mod cluster_probes;
mod gossip;
mod storage;
mod turbine;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum WireProtocol {
    Gossip,
    Turbine,
}

#[derive(Parser)]
#[command(version, about,  long_about = None)]
struct Cli {
    #[arg(short, long)]
    verbose: bool,
    #[arg(value_enum)]
    protocol: WireProtocol,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Monitor {
        #[arg(short, long)]
        ip_addr: Ipv4Addr,
        #[arg(short, long, default_value_t = 8001)]
        gossip_port: u16,
        /// Directory with pcap files to write. Existing ontents will be destroyed!
        #[arg(short, long, default_value = "monitor_captures")]
        output: PathBuf,
        /// Rough number of pacekts to capture (exact number will depend on the protocol)
        #[arg(short, long, default_value_t = 10000)]
        size_hint: usize,
    },
    Capture {
        #[arg(short, long, default_value = "bond0")]
        interface: String,
        #[arg(short, long)]
        ip_addr: Ipv4Addr,
        #[arg(short, long, default_value_t = 8001)]
        gossip_port: u16,
        #[arg(short, long)]
        /// Directory with pcap files to write. Existing ontents will be destroyed!
        output: PathBuf,
        #[arg(short, long, default_value_t = 512)]
        /// Rough number of pacekts to capture (exact number will depend on the protocol)
        size_hint: usize,
    },
    Parse {
        #[arg()]
        input: PathBuf,
    },
}

pub static EXIT: AtomicBool = AtomicBool::new(false);

fn main() -> Result<(), Box<dyn Error>> {
    solana_logger::setup_with("info,solana_metrics=error");
    let mut signals = Signals::new([SIGINT])?;

    thread::spawn(move || {
        if let Some(sig) = signals.forever().next() {
            println!("Received signal {:?}", sig);
            EXIT.store(true, std::sync::atomic::Ordering::Relaxed);
            // Wait for workers to ack that they are exiting
            thread::sleep(Duration::from_secs(1));

            if crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
                println!("Timed out waiting for capture to stop, aborting!");
                std::process::exit(1);
            }
        }
    });
    let cli = Cli::parse();

    match cli.command {
        Commands::Monitor {
            ip_addr,
            gossip_port,
            output,
            size_hint,
        } => {
            let _ = std::fs::create_dir(&output);
            let t = std::time::Instant::now();
            let stats = monitor_gossip(ip_addr, gossip_port, output, size_hint)
                .context("Monitor failed")?;
            let time = t.elapsed();
            println!(
                "Captured {} packets ({} valid) over {:?}, {} pps",
                stats.captured,
                stats.valid,
                time,
                (stats.valid as f64 / time.as_secs_f64()) as u64
            );
        }
        Commands::Capture {
            interface,
            ip_addr,
            gossip_port: port,
            output,
            size_hint,
        } => {
            let interface = CString::new(interface).unwrap();
            let t = std::time::Instant::now();
            let _ = std::fs::create_dir(&output);
            let stats = match cli.protocol {
                WireProtocol::Gossip => {
                    capture_gossip(&interface, ip_addr, port, output, size_hint)
                        .context("Capture failed")?
                }
                WireProtocol::Turbine => {
                    let gossip_entrypoint = SocketAddr::new(IpAddr::V4(ip_addr), port);
                    let port = find_turbine_port(gossip_entrypoint)?;
                    println!("Got port {port}");
                    capture_turbine(&interface, ip_addr, port, output, size_hint)
                        .context("capture failed")?
                }
            };

            let time = t.elapsed();
            println!(
                "Captured {} packets ({} valid) over {:?}, {} pps",
                stats.captured,
                stats.valid,
                time,
                (stats.valid as f64 / time.as_secs_f64()) as u64
            );
        }
        Commands::Parse { input } => match cli.protocol {
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
            WireProtocol::Turbine => todo!(),
        },
    }
    //let s = serde_json::to_string_pretty(&p).unwrap();
    //println!("hi {s}");
    //let e = epoch_slots();
    //println!("epochslots {}", &e);
    //let d: Protocol = serde_json::from_str(&e).unwrap();
    //dbg!(d);
    std::process::exit(0);
}

#[derive(Debug, Default)]
pub struct Stats {
    pub captured: usize,
    pub valid: usize,
    pub retained: usize,
}
