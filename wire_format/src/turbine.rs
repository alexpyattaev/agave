use std::{
    ffi::CStr,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
};

use anyhow::{bail, Context};
use log::info;
use solana_ledger::shred::Shred;
use solana_ledger::shred::ShredVariant;

use crate::{cluster_probes::get_leader_schedule, storage::DumbStorage, Stats};

#[derive(Default)]
struct TurbineInventory {
    legacy_code: DumbStorage,
    legacy_data: DumbStorage,
    merkle_code: DumbStorage,
    merkle_data: DumbStorage,
}
impl TurbineInventory {
    fn try_retain(&mut self, shred: &Shred, bytes: &[u8], size_hint: usize) -> bool {
        let variant = solana_ledger::shred::layout::get_shred_variant(bytes).unwrap();
        match variant {
            ShredVariant::LegacyCode => self.legacy_code.try_retain(bytes, size_hint),
            ShredVariant::LegacyData => self.legacy_data.try_retain(bytes, size_hint),
            ShredVariant::MerkleCode {
                proof_size,
                chained,
                resigned,
            } => todo!(),
            ShredVariant::MerkleData {
                proof_size,
                chained,
                resigned,
            } => todo!(),
        }
        return false;
    }
    fn dump_to_files(&self, filename: PathBuf) -> anyhow::Result<()> {
        /*macro_rules! write_thing {
            ($name:ident) => {
                Self::write_file(
                    &self.$name,
                    filename.clone(),
                    concat!(stringify!($name), ".pcap"),
                )?;
            };
        }
        write_thing!(ping);
        write_thing!(pong);
        write_thing!(prune);
        write_thing!(pull_request);
        write_thing!(pull_response);
        write_thing!(push);*/
        Ok(())
    }
}

fn parse_turbine(bytes: &[u8]) -> anyhow::Result<Shred> {
    //Todo: maybe sigverify this?
    Ok(Shred::new_from_serialized_shred(bytes.to_owned())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?)
}

pub fn capture_turbine(
    _ifname: &CStr,
    bind_ip: Ipv4Addr,
    port: u16,
    pcap_filename: PathBuf,
    size_hint: usize,
) -> anyhow::Result<Stats> {
    //let leader_schedule = get_leader_schedule()?;
    info!("Binding the capture socket");
    let socket = rscap::linux::l4::L4Socket::new(rscap::linux::l4::L4Protocol::Udp)
        .context("L4 socket creation")?;
    socket
        .bind(&SocketAddrV4::new(bind_ip, port))
        .context("bind should not fail")?;
    let mut buf = vec![0; 2048];
    let mut stats = Stats::default();
    let mut inventory = TurbineInventory::default();
    while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        let len = socket.recv(&mut buf).context("socket RX")?;
        stats.captured += 1;
        let slice = &buf[20 + 8..len];

        //let layers = parse_layers!(slice, Ip, (Udp, Raw));
        let Ok(pkt) = parse_turbine(slice) else {
            continue;
        };
        stats.valid += 1;
        if inventory.try_retain(&pkt, slice, size_hint) {
            stats.retained += 1;
        }
    }
    // Ack the command to exit the capture
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    inventory
        .dump_to_files(pcap_filename)
        .context("Saving files failed")?;
    Ok(stats)
}
