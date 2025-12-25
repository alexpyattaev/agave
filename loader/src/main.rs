use std::{net::Ipv4Addr, time::Duration};

use agave_xdp::{device::NetworkDevice, load_xdp_program};
use agave_xdp_ebpf::FirewallConfig;
use clap::Parser;

#[derive(Debug, clap::Parser)]
struct Cli {
    #[arg(short, long)]
    interface: String,
    #[arg(long)]
    my_ip: Ipv4Addr,
    #[arg(long)]
    gossip_port: u16,
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
        gossip: cli.gossip_port,
        solana_min_port: 8000,
        solana_max_port: 8050,
        my_ip: cli.my_ip,
        strip_gre: true,
        drop_frags: false,
    };
    let ebpf = load_xdp_program(&dev, Some(firewall_config)).unwrap();
    tokio::time::sleep(Duration::from_secs(60)).await;
}
