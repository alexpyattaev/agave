#![allow(clippy::arithmetic_side_effects)]
use {
    crate::gossip::*,
    clap::{Parser, Subcommand, ValueEnum},
    signal_hook::{consts::SIGINT, iterator::Signals},
    std::{
        error::Error, ffi::CString, net::Ipv4Addr, path::PathBuf, sync::atomic::AtomicBool, thread,
        time::Duration,
    },
};

mod gossip;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum WireProtocol {
    Gossip,
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
        output: PathBuf,
    },
    Parse {
        #[arg(short, long)]
        input: PathBuf,
    },
}

pub static EXIT: AtomicBool = AtomicBool::new(false);

fn main() -> Result<(), Box<dyn Error>> {
    let mut signals = Signals::new([SIGINT])?;

    thread::spawn(move || {
        if let Some(sig) = signals.forever().next() {
            println!("Received signal {:?}", sig);
            EXIT.store(true, std::sync::atomic::Ordering::Relaxed);
            thread::sleep(Duration::from_secs(1));
            println!("Timed out waiting for process exit, aborting!");
            std::process::exit(1);
        }
    });
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture {
            interface,
            ip_addr,
            port,
            output,
        } => {
            let interface = CString::new(interface).unwrap();
            let t = std::time::Instant::now();
            let stats = match cli.protocol {
                WireProtocol::Gossip => {
                    capture_gossip(&interface, ip_addr, port, output).expect("Capture failed")
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
        Commands::Parse { input } => todo!(),
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
