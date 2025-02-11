#![allow(clippy::arithmetic_side_effects)]
use {
    crate::gossip::*,
    anyhow::Context,
    clap::{Parser, Subcommand, ValueEnum},
    signal_hook::{consts::SIGINT, iterator::Signals},
    std::{
        error::Error, ffi::CString, net::Ipv4Addr, path::PathBuf, sync::atomic::AtomicBool, thread,
        time::Duration,
    },
    turbine::find_turbine_port,
};

mod gossip;
mod pcap;
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
    Capture {
        #[arg(short, long)]
        interface: String,
        #[arg(short, long)]
        ip_addr: Ipv4Addr,
        #[arg(short, long, default_value_t = 8001)]
        port: u16,
        #[arg(short, long)]
        /// Directory with pcap files to write. Existing ontents will be destroyed!
        output: PathBuf,
        #[arg(short, long, default_value_t = 512)]
        /// Rough number of pacekts to capture (exact number will depend on the protocol)
        size_hint: usize,
    },
    Parse {
        #[arg(short, long)]
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
        Commands::Capture {
            interface,
            ip_addr,
            port,
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
                    let port = find_turbine_port("9KTG5wAR4KYFdwVDbpHAqAzjn5K5wNGvajG8Y1ki6zpt")?;
                    println!("Got port {port}");
                    //capture_turbine()
                    Stats::default()
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
        Commands::Parse { input } => todo!("Parsing mode is coming up"),
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
