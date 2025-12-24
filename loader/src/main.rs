use std::{net::Ipv4Addr, time::Duration};

use agave_xdp::{device::NetworkDevice, load_xdp_program};
use agave_xdp_ebpf::FirewallConfig;
use clap::Parser;

#[derive(Debug, clap::Parser)]
struct Cli {
    #[arg(short, long, default_value_t = String::from("bond0"))]
    interface: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    solana_logger::setup_with_default_filter();

    let cli = Cli::parse();
    let interface = &cli.interface;
    let dev = NetworkDevice::new(interface).unwrap();
    let firewall_config = FirewallConfig {
        deny_ingress_ports: [0; 7],
        tpu_vote: 8002,
        tpu_quic: 0,
        tpu_forwards_quic: 0,
        tpu_vote_quic: 0,
        turbine: 0,
        repair: 0,
        serve_repair: 0,
        ancestor_repair: 0,
        gossip: 8000,
        solana_min_port: 8000,
        solana_max_port: 8050,
        my_ip: Ipv4Addr::new(64, 130, 63, 75),
        drop_frags: false,
    };
    load_xdp_program(&dev, Some(firewall_config)).unwrap();
    tokio::time::sleep(Duration::from_secs(60)).await;
}
