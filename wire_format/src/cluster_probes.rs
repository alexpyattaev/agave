#![allow(dead_code)]
use anyhow::Context;
use log::info;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Ports {
    pub shred_version: u16,
    pub gossip: SocketAddr,
    pub repair: Option<SocketAddr>,
    pub tpu: Option<SocketAddr>,
    pub tpu_quic: Option<SocketAddr>,
    pub tpu_vote: Option<SocketAddr>,
    pub turbine: Option<SocketAddr>,
}
/// Finds the turbine port on a given gossip endpoint
pub async fn find_validator_ports(
    gossip_address: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<Ports> {
    let info = solana_net_utils::get_echo_server_info(&gossip_address).await?;

    let shred_version = info
        .shred_version
        .context("Shred version not provided by entrypoint!")?;
    if timeout.is_zero() {
        let ports = Ports {
            shred_version,
            turbine: None,
            repair: None,
            gossip: gossip_address,
            tpu: None,
            tpu_quic: None,
            tpu_vote: None,
        };
        return Ok(ports);
    }
    info!("Cluster's shred version is {}", &shred_version);
    info!("Looking for TVU address via gossip, this can take a minute");
    let (_all_peers, validators) = discover(
        None,
        Some(&gossip_address),
        None,
        timeout,
        None,                  // find_nodes_by_pubkey
        Some(&gossip_address), // find_node_by_gossip_addr
        None,                  // my_gossip_addr
        shred_version,
        SocketAddrSpace::new(true),
    )?;
    let me = validators
        .into_iter()
        .find(|ci| {
            ci.gossip()
                .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                == gossip_address
        })
        .ok_or(anyhow::anyhow!("Discover did not find the right validator"))?;

    dbg!(&me);
    let turbine = me.tvu(solana_gossip::contact_info::Protocol::UDP);
    let repair = me.repair(solana_gossip::contact_info::Protocol::UDP);

    let tpu = me.tpu(solana_gossip::contact_info::Protocol::UDP);
    let tpu_quic = me.tpu(solana_gossip::contact_info::Protocol::QUIC);
    let tpu_vote = me.tpu(solana_gossip::contact_info::Protocol::UDP);
    let ports = Ports {
        shred_version,
        turbine,
        repair,
        gossip: gossip_address,
        tpu,
        tpu_quic,
        tpu_vote,
    };
    info!("Fetched the port information: {:?}", &ports);
    Ok(ports)
}

fn get_gossip_address(ip: IpAddr) -> anyhow::Result<SocketAddr> {
    let port =
        solana_net_utils::find_available_port_in_range(IpAddr::V4(Ipv4Addr::UNSPECIFIED), (0, 1))
            .context("unable to find an available gossip port")?;
    Ok(SocketAddr::new(ip, port))
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
