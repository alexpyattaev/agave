use std::{
    collections::HashMap,
    ops::ControlFlow,
    time::{Duration, Instant},
};

use crate::{monitor::PacketLogger, storage::Monitor, ui::*};
use crossbeam_channel::Sender;
use iocraft::prelude::*;
use solana_gossip::{crds_data::CrdsData, crds_value::CrdsValue, protocol::Protocol};
use solana_pubkey::Pubkey;
use solana_sanitize::Sanitize;
use tokio::io::AsyncWriteExt;

use super::parse_gossip;
impl PacketLogger for BitrateMonitor {
    fn handle_pkt(&mut self, wire_bytes: &[u8]) -> std::ops::ControlFlow<()> {
        let data = &wire_bytes[20 + 8..];
        let Ok(pkt) = parse_gossip(data) else {
            self.invalid.push(data.len());
            return ControlFlow::Continue(());
        };
        if pkt.sanitize().is_err() {
            self.invalid.push(data.len());
            return ControlFlow::Continue(());
        }
        //let ts = SystemTime::now().duration_since(UNIX_EPOCH)?;
        self.try_retain(&pkt, &data);
        let last_report = self.last_report.as_mut().unwrap();
        if last_report.elapsed() > Duration::from_millis(500) {
            *last_report = Instant::now();

            if let Some(metrics_category) = self.metrics_category {
                self.send_metrics(metrics_category);
            } else {
                let reports = self.feed_gui();
                if self.channel.as_ref().unwrap().try_send(reports).is_err() {
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }

    async fn finalize(&mut self) -> anyhow::Result<()> {
        drop(self.channel.take());
        let mut f = tokio::fs::File::create("got_epoch_slots.txt").await?;
        f.write_all("{\n".as_bytes()).await?;
        for (pk, num) in self.all_epoch_slots.iter() {
            f.write_all(
                format!(
                    r#""{pk}":{num},
        "#
                )
                .as_bytes(),
            )
            .await?;
        }
        f.write_all("}\n".as_bytes()).await?;
        f.flush().await?;
        // allow UI to kill itself
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }
}

#[derive(Default)]
pub struct BitrateMonitor {
    // All invalid packets
    invalid: Monitor,
    // All valid packets
    valid: Monitor,
    // All push packets
    push: Monitor,
    // All pull request packets
    pull_request: Monitor,
    // All pull responses
    pull_response: Monitor,
    // All prune packets
    prune: Monitor,
    // Ping and Pong
    pingpong: Monitor,
    // CRDS stats
    //  ContactInfo and LegacyContactInfo packets (i.e. the whole point of gossip)
    crds_contact_info: Monitor,
    crds_epoch_slots: Monitor,
    crds_node_instance: Monitor,
    crds_duplicate_shred: Monitor,
    crds_snapshot_hashes: Monitor,
    crds_version: Monitor,
    crds_other: Monitor,
    crds_vote: Monitor,

    channel: Option<Sender<RateDisplayItems>>,
    last_report: Option<Instant>,
    metrics_category: Option<&'static str>,
    all_epoch_slots: HashMap<Pubkey, usize>,
}

impl BitrateMonitor {
    pub fn new(metrics_category: Option<&'static str>) -> Self {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let me = Self {
            channel: Some(tx),
            last_report: Some(Instant::now()),
            metrics_category,
            ..Default::default()
        };
        if metrics_category.is_none() {
            tokio::spawn(async move {
                let mut elem = element! {
                    ContextProvider(value: Context::owned(RatesMonitorChannel(rx))) {
                        RatesMonitorMenu
                    }
                };
                elem.render_loop().await.expect("UI should exit cleanly");
            });
        }

        me
    }

    fn send_metrics(&mut self, metrics_category: &'static str) {
        macro_rules! bps {
            ($x:ident) => {
                (self.$x.rate_bps().unwrap_or_default() as f64)
            };
        }
        macro_rules! pps {
            ($x:ident) => {
                (self.$x.rate_pps().unwrap_or_default() as f64)
            };
        }
        solana_metrics::datapoint_info!(
            metrics_category,
            ("crds_contact_info", bps!(crds_contact_info), f64),
            ("crds_contact_info_pps", pps!(crds_contact_info), f64),
            ("crds_epoch_slots", bps!(crds_epoch_slots), f64),
            ("crds_epoch_slots_pps", pps!(crds_epoch_slots), f64),
            ("crds_node_instance", bps!(crds_node_instance), f64),
            ("crds_node_instance_pps", pps!(crds_node_instance), f64),
            ("crds_other", bps!(crds_other), f64),
            ("crds_other_pps", pps!(crds_other), f64),
            ("crds_vote", bps!(crds_vote), f64),
            ("crds_vote_pps", pps!(crds_vote), f64),
            ("crds_snapshot_hashes", bps!(crds_snapshot_hashes), f64),
            ("crds_snapshot_hashes_pps", pps!(crds_snapshot_hashes), f64),
            ("crds_version", bps!(crds_version), f64),
            ("crds_version_pps", pps!(crds_version), f64),
            ("crds_dup_shred", bps!(crds_duplicate_shred), f64),
            ("crds_dup_shred_pps", pps!(crds_duplicate_shred), f64),
            ("junk", bps!(invalid), f64),
            ("junk_pps", pps!(invalid), f64),
            ("pingpong", bps!(pingpong), f64),
            ("pingpong_pps", pps!(pingpong), f64),
            ("pull_request", bps!(pull_request), f64),
            ("pull_request", pps!(pull_request), f64),
            ("pull_response", bps!(pull_response), f64),
            ("pull_response", pps!(pull_response), f64),
            ("push", bps!(push), f64),
            ("push_pps", pps!(push), f64),
            ("prune", bps!(prune), f64),
            ("prune_pps", pps!(prune), f64),
            ("valid", bps!(valid), f64),
            ("valid_pps", pps!(valid), f64),
        );
    }
    fn feed_gui(&mut self) -> Vec<(String, f64)> {
        fn row(l: &str, m: &mut Monitor) -> (String, f64) {
            (l.to_owned(), m.rate_bps().unwrap_or(0.0) / 1e6)
        }
        vec![
            row("All Gossip", &mut self.valid),
            row("Junk", &mut self.invalid),
            row("Prune", &mut self.prune),
            row("Push", &mut self.push),
            row("Pull Request", &mut self.pull_request),
            row("Pull Response", &mut self.pull_response),
            row("Ping & Pong", &mut self.pingpong),
            row("CRDS: ContactInfo", &mut self.crds_contact_info),
            row("CRDS: Vote", &mut self.crds_vote),
            row("CRDS: EpochSlots", &mut self.crds_epoch_slots),
            row("CRDS: NodeInstance", &mut self.crds_node_instance),
            row("CRDS: DuplicateShred", &mut self.crds_duplicate_shred),
            row("CRDS: SnapshotHashes", &mut self.crds_snapshot_hashes),
            row("CRDS: Version", &mut self.crds_version),
            row("CRDS: Other", &mut self.crds_other),
        ]
    }
    fn try_retain(&mut self, pkt: &Protocol, bytes: &[u8]) {
        match pkt {
            Protocol::PushMessage(_pubkey, crds_values) => {
                for cv in crds_values {
                    self.try_retain_crds(cv);
                }
                self.push.push(bytes.len());
            }
            Protocol::PullResponse(_pubkey, crds_values) => {
                self.pull_response.push(bytes.len());
                for cv in crds_values {
                    self.try_retain_crds(cv);
                }
            }
            Protocol::PruneMessage(_pubkey, _) => {
                self.prune.push(bytes.len());
            }
            Protocol::PingMessage(_) | Protocol::PongMessage(_) => {
                self.pingpong.push(bytes.len());
            }
            Protocol::PullRequest(_, value) => {
                self.pull_request.push(bytes.len());
                self.try_retain_crds(value);
            }
        }
        self.valid.push(bytes.len());
    }

    fn try_retain_crds(&mut self, cv: &CrdsValue) {
        let ser = bincode::serialize(cv.data()).unwrap();
        match cv.data() {
            CrdsData::EpochSlots(_esi, _es) => {
                self.crds_epoch_slots.push(ser.len());
                *self.all_epoch_slots.entry(cv.label().pubkey()).or_default() += 1;
            }
            CrdsData::Vote(_, _) => {
                self.crds_vote.push(ser.len());
            }
            CrdsData::ContactInfo(_) | CrdsData::LegacyContactInfo(_) => {
                self.crds_contact_info.push(ser.len());
            }
            CrdsData::NodeInstance(_) => {
                self.crds_node_instance.push(ser.len());
            }
            CrdsData::DuplicateShred(_, _) => {
                self.crds_duplicate_shred.push(ser.len());
            }
            CrdsData::SnapshotHashes(_) => {
                self.crds_snapshot_hashes.push(ser.len());
            }
            CrdsData::Version(_) | CrdsData::LegacyVersion(_) => {
                self.crds_version.push(ser.len());
            }
            _ => {
                self.crds_other.push(ser.len());
            }
        }
    }
}
