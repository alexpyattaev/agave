use anyhow::Context;
use log::info;
use solana_pubkey::Pubkey;
use solana_streamer::socket::SocketAddrSpace;
use std::collections::HashMap;
use std::io::{prelude::*, BufReader};
use std::str::FromStr;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use solana_gossip::gossip_service::discover;

/// Finds the turbine port on a given gossip endpoint
pub(crate) fn find_turbine_port(gossip_peer_address: SocketAddr) -> anyhow::Result<u16> {
    let spy_gossip_addr =
        get_gossip_address(&gossip_peer_address).context("get new gossip address")?;

    let shred_version = get_shred_version(&gossip_peer_address).context("get shred version")?;

    let discover_timeout = Duration::from_secs(60);
    info!("Looking for TVU address via gossip, this can take a minute");
    let (_all_peers, validators) = discover(
        None,
        Some(&gossip_peer_address),
        None,
        discover_timeout,
        None,                       // find_nodes_by_pubkey
        Some(&gossip_peer_address), // find_node_by_gossip_addr
        Some(&spy_gossip_addr),     // my_gossip_addr
        shred_version,
        SocketAddrSpace::new(true),
    )?;
    let me = validators
        .into_iter()
        .find(|ci| {
            ci.gossip()
                .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                == gossip_peer_address
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

pub(crate) fn _get_leader_schedule() -> anyhow::Result<HashMap<u64, Pubkey>> {
    info!("Fetching leader schedule");
    let child = std::process::Command::new("solana")
        .args(["-um", "leader-schedule"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("Could not call solana cli")?;
    let output = child
        .wait_with_output()
        .context("wait for leader schedule to be fetched")?;
    let reader: BufReader<_> = std::io::BufReader::new(std::io::Cursor::new(output.stdout));
    let mut schedule = HashMap::with_capacity(2000);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (slot, key) = line
            .split_once(' ')
            .ok_or_else(|| anyhow::anyhow!("invalid format"))?;
        let slot: u64 = slot.trim().parse()?;
        let key = key.trim();
        let key = Pubkey::from_str(key)?;
        schedule.insert(slot, key);
    }
    Ok(schedule)
}

/*
pub fn process_leader_schedule(
    rpc_client: &RpcClient,
    config: &CliConfig,
    epoch: Option<Epoch>,
) -> ProcessResult {
    let epoch_info = rpc_client.get_epoch_info()?;
    let epoch = epoch.unwrap_or(epoch_info.epoch);
    if epoch > epoch_info.epoch.saturating_add(1) {
        return Err(format!("Epoch {epoch} is more than one epoch in the future").into());
    }

    let epoch_schedule = rpc_client.get_epoch_schedule()?;
    let first_slot_in_epoch = epoch_schedule.get_first_slot_in_epoch(epoch);

    let leader_schedule = rpc_client.get_leader_schedule(Some(first_slot_in_epoch))?;
    if leader_schedule.is_none() {
        return Err(
            format!("Unable to fetch leader schedule for slot {first_slot_in_epoch}").into(),
        );
    }
    let leader_schedule = leader_schedule.unwrap();

    let mut leader_per_slot_index = Vec::new();
    for (pubkey, leader_slots) in leader_schedule.iter() {
        for slot_index in leader_slots.iter() {
            if *slot_index >= leader_per_slot_index.len() {
                leader_per_slot_index.resize(slot_index.saturating_add(1), "?");
            }
            leader_per_slot_index[*slot_index] = pubkey;
        }
    }

    let mut leader_schedule_entries = vec![];
    for (slot_index, leader) in leader_per_slot_index.iter().enumerate() {
        leader_schedule_entries.push(CliLeaderScheduleEntry {
            slot: first_slot_in_epoch.saturating_add(slot_index as u64),
            leader: leader.to_string(),
        });
    }

    Ok(config.output_format.formatted_string(&CliLeaderSchedule {
        epoch,
        leader_schedule_entries,
    }))
}
*/
