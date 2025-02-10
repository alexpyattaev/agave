#![allow(dead_code)]
use {
    super::{parse_gossip, CrdsCounts},
    crate::monitor::PacketLogger,
    anyhow::Context,
    log::info,
    serde::Serialize,
    solana_gossip::{crds_data::CrdsData, crds_value::CrdsValue, protocol::Protocol},
    solana_pubkey::Pubkey,
    solana_sanitize::Sanitize,
    std::{
        collections::{hash_map::Entry, HashMap},
        ops::ControlFlow,
        path::PathBuf,
        time::{Duration, Instant},
    },
    tokio::io::AsyncWriteExt,
};
#[derive(Default, Clone, Serialize)]
struct Stat {
    push: usize,
    pull_response: usize,
    crds_stats: CrdsCounts,
    shred_versions: Vec<u16>,
}

pub struct MysteryCRDSLogger {
    shred_version: u16,
    path: PathBuf,
    senders: HashMap<Pubkey, Stat>,
    forwarders: HashMap<Pubkey, Stat>,
    last_report: Instant,
    last_batch: usize,
}
impl MysteryCRDSLogger {
    pub fn new(shred_version: u16, path: PathBuf) -> Self {
        Self {
            shred_version,
            path,
            senders: Default::default(),
            forwarders: Default::default(),
            last_report: Instant::now(),
            last_batch: 0,
        }
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

const FILENAME: &str = "gossip-invalid-senders.json";

impl PacketLogger for MysteryCRDSLogger {
    async fn finalize(&mut self) -> anyhow::Result<()> {
        self.path.push(FILENAME);
        let mut file = tokio::fs::File::create(&self.path)
            .await
            .context("could not open file fow writing")?;
        info!("Saving captured abusers into {:?}", &self.path);
        let new_map: HashMap<_, _> = self
            .senders
            .iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let json = serde_json::to_string_pretty(&new_map).context("serialize failed")?;
        file.write_all(json.as_bytes()).await?;
        info!("Saving completed");
        file.flush().await?;
        Ok(())
    }
    fn handle_pkt(&mut self, wire_bytes: &[u8]) -> ControlFlow<()> {
        let Ok(pkt) = parse_gossip(&wire_bytes[20 + 8..]) else {
            return ControlFlow::Continue(());
        };
        if pkt.sanitize().is_err() {
            return ControlFlow::Continue(());
        }
        self.last_batch += self.analyze(pkt);

        if self.last_report.elapsed() > Duration::from_millis(1000) {
            self.last_report = Instant::now();
            let num_abusers = self.senders.len();
            println!("Caught {num_abusers} abusers, {}/second", self.last_batch);
            self.last_batch = 0;
        }
        ControlFlow::Continue(())
    }
}
