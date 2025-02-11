use anyhow::Context;
use log::info;
use solana_streamer::socket::SocketAddrSpace;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use solana_gossip::gossip_service::discover;

pub fn find_turbine_port(gossip_entrypoint: SocketAddr) -> anyhow::Result<u16> {
    let spy_gossip_addr = get_gossip_address(&gossip_entrypoint)?;

    let shred_version = get_shred_version(&gossip_entrypoint)?;

    let discover_timeout = Duration::from_secs(60);
    info!("Looking for TVU address via gossip, this can take a minute");
    let (_all_peers, validators) = discover(
        None,
        Some(&gossip_entrypoint),
        None,
        discover_timeout,
        None,                     // find_nodes_by_pubkey
        Some(&gossip_entrypoint), // find_node_by_gossip_addr
        Some(&spy_gossip_addr),   // my_gossip_addr
        shred_version,
        SocketAddrSpace::new(true),
    )?;
    let me = validators
        .into_iter()
        .find(|ci| {
            ci.gossip()
                .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                == gossip_entrypoint
        })
        .ok_or(anyhow::anyhow!("Discover did not find the right validator"))?;

    dbg!(&me);
    let tvu = me
        .tvu(solana_gossip::contact_info::Protocol::UDP)
        .ok_or_else(|| anyhow::anyhow!("No TVU port published"))?;
    Ok(tvu.port())
}

fn get_gossip_address(entrypoint: &SocketAddr) -> anyhow::Result<SocketAddr> {
    info!("Allocating gossip address");
    let ip = solana_net_utils::get_public_ip_addr(entrypoint)
        .map_err(|e| anyhow::anyhow!(e))
        .context("contact cluster entrypoint")?;

    let port =
        solana_net_utils::find_available_port_in_range(IpAddr::V4(Ipv4Addr::UNSPECIFIED), (0, 1))
            .context("unable to find an available gossip port")?;
    Ok(SocketAddr::new(ip, port))
}

fn get_shred_version(entrypoint: &SocketAddr) -> anyhow::Result<u16> {
    info!("Getting shred version");
    match solana_net_utils::get_cluster_shred_version(entrypoint) {
        Err(err) => {
            anyhow::bail!("get_cluster_shred_version failed: {entrypoint}, {err}");
        }
        Ok(0) => {
            anyhow::bail!("entrypoint {entrypoint} returned shred-version zero");
        }
        Ok(shred_version) => {
            info!("obtained shred-version {shred_version} from entrypoint: {entrypoint}");
            Ok(shred_version)
        }
    }
}
