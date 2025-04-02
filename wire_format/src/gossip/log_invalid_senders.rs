#![allow(dead_code)]
use {
    super::{parse_gossip, CrdsCounts},
    aya::maps::{MapData, RingBuf},
    serde::Serialize,
    solana_gossip::{crds_data::CrdsData, crds_value::CrdsValue, protocol::Protocol},
    solana_pubkey::Pubkey,
    solana_sanitize::Sanitize,
    std::{
        collections::{hash_map::Entry, HashMap, HashSet},
        io::Write,
        path::Path,
        time::{Duration, Instant},
    },
    tokio::io::unix::AsyncFd,
    tokio_util::sync::CancellationToken,
};
#[derive(Default, Clone, Serialize)]
struct Stat {
    push: usize,
    pull_response: usize,
    crds_stats: CrdsCounts,
    shred_versions: Vec<u16>,
}
#[derive(Default)]
struct MysteryCrdsLogger {
    senders: HashMap<Pubkey, Stat>,
    shred_version: u16,
}
impl MysteryCrdsLogger {
    fn dump_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let mut path = path.to_path_buf();
        path.push("mystery.json");
        println!("Saving captured abusers into {:?}", &path);
        let mut file = std::fs::File::create(path)?;
        let new_map: HashMap<_, _> = self
            .senders
            .iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        serde_json::to_writer_pretty(&mut file, &new_map)?;
        println!("Saving completed");
        file.flush()?;
        Ok(())
    }
    fn try_retain_crds(&mut self, cv: CrdsValue, push: bool) -> bool {
        let from = cv.label().pubkey();
        let entry = self.senders.entry(from);
        match cv.data() {
            CrdsData::EpochSlots(_esi, _es) => {}
            CrdsData::Vote(_, _) => {}
            CrdsData::ContactInfo(ci) => {
                if ci.shred_version() != self.shred_version {
                    let entry = entry.or_default();
                    if !entry
                        .shred_versions
                        .iter()
                        .any(|&v| v == ci.shred_version())
                    {
                        entry.shred_versions.push(ci.shred_version());
                    }
                    if push {
                        entry.push += 1;
                    } else {
                        entry.pull_response += 1;
                    }
                    entry.crds_stats[cv.data().ordinal()] += 1;
                    return true;
                }
            }
            CrdsData::LegacyContactInfo(_) => {}
            CrdsData::NodeInstance(_) => {}
            _ => {}
        }
        if let Entry::Occupied(mut entry) = entry {
            let entry = entry.get_mut();
            if push {
                entry.push += 1;
            } else {
                entry.pull_response += 1;
            }
            entry.crds_stats[cv.data().ordinal()] += 1;
            return true;
        }
        false
    }

    pub fn analyze(&mut self, pkt: Protocol) -> usize {
        let mut total = 0;
        match pkt {
            Protocol::PushMessage(_pubkey, crds_values) => {
                for cv in crds_values {
                    if self.try_retain_crds(cv, true) {
                        total += 1;
                    }
                }
            }
            Protocol::PullResponse(_pubkey, crds_values) => {
                for cv in crds_values {
                    if self.try_retain_crds(cv, false) {
                        total += 1;
                    }
                }
            }
            Protocol::PruneMessage(_pubkey, _) => {}
            Protocol::PingMessage(_) | Protocol::PongMessage(_) => {}
            _ => {}
        }
        total
    }
}
pub async fn gossip_log_invalid_senders(
    async_fd: &mut AsyncFd<RingBuf<MapData>>,
    path: &Path,
    cancel: CancellationToken,
    min_time: Duration,
    shred_version: u16,
) -> anyhow::Result<()> {
    println!("Start catching stuff");
    //Allocate buffer big enough for any valid datagram
    let mut monitor = MysteryCrdsLogger::default();
    monitor.shred_version = shred_version;
    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut last_num_abusers = 0;
    let mut num_abuse_crds = 0;
    'outer: while !crate::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        if cancel.is_cancelled() {
            break;
        }
        // wait till it is ready to read and read
        let mut guard = async_fd.readable_mut().await.unwrap();
        let rb = guard.get_inner_mut();

        while let Some(read) = rb.next() {
            let ptr = read.as_ptr();

            // retrieve packet len first then packet data
            let size = unsafe { std::ptr::read_unaligned::<u16>(ptr as *const u16) };
            let data = unsafe { std::slice::from_raw_parts(ptr.byte_add(2), size.into()) };

            let Ok(pkt) = parse_gossip(&data[14 + 20 + 8..]) else {
                continue;
            };
            if pkt.sanitize().is_err() {
                continue;
            }
            num_abuse_crds += monitor.analyze(pkt);

            if last_report.elapsed() > Duration::from_millis(1000) {
                last_report = Instant::now();
                let num_abusers = monitor.senders.len();
                println!("Caught {num_abusers} abusers, {num_abuse_crds}/second",);
                num_abuse_crds = 0;
                if last_num_abusers == num_abusers {
                    if start.elapsed() > min_time {
                        break 'outer;
                    }
                }
                last_num_abusers = num_abusers;
            }
        }
        guard.clear_ready();
    }
    crate::EXIT.store(false, std::sync::atomic::Ordering::Relaxed);
    monitor.dump_to_file(path)?;
    Ok(())
}
