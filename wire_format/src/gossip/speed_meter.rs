use std::{
    f32,
    ops::ControlFlow,
    time::{Duration, Instant},
};

use crate::{monitor::PacketLogger, storage::Monitor, ui::*};
use crossbeam_channel::Sender;
use iocraft::prelude::*;
use solana_gossip::{crds_data::CrdsData, crds_value::CrdsValue, protocol::Protocol};
use solana_sanitize::Sanitize;

use super::parse_gossip;
impl PacketLogger for BitrateMonitor {
    fn handle_pkt(&mut self, wire_bytes: &[u8]) -> std::ops::ControlFlow<()> {
        let data = &wire_bytes[14 + 20 + 8..];
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

            if self.report_metrics {
                self.send_metrics();
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
    // All prune packets
    prune: Monitor,
    // Ping and Pong
    pingpong: Monitor,
    // Whatever is not covered above
    others: Monitor,
    // CRDS stats
    //  ContactInfo and LegacyContactInfo packets (i.e. the whole point of gossip)
    crds_contact_info: Monitor,
    crds_epoch_slots: Monitor,
    crds_node_instance: Monitor,
    crds_other: Monitor,
    crds_vote: Monitor,

    channel: Option<Sender<RateDisplayItems>>,
    last_report: Option<Instant>,
    report_metrics: bool,
}

impl BitrateMonitor {
    pub fn new(report_metrics: bool) -> Self {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let me = Self {
            channel: Some(tx),
            last_report: Some(Instant::now()),
            report_metrics,
            ..Default::default()
        };
        if !report_metrics {
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

    fn send_metrics(&mut self) {
        macro_rules! bps {
            ($x:ident) => {
                (self.$x.rate_bps().unwrap_or_default() as f64)
            };
        }
        solana_metrics::datapoint_info!(
            "gossip_bitrates",
            ("crds_contact_info", bps!(crds_contact_info), f64),
            ("crds_epoch_slots", bps!(crds_epoch_slots), f64),
            ("crds_node_instance", bps!(crds_node_instance), f64),
            ("crds_other", bps!(crds_other), f64),
            ("crds_vote", bps!(crds_vote), f64),
            ("junk", bps!(invalid), f64),
            ("pingpong", bps!(pingpong), f64),
            ("prune", bps!(prune), f64),
            ("valid", bps!(valid), f64),
        );
        macro_rules! pps {
            ($x:ident) => {
                (self.$x.rate_pps().unwrap_or_default() as f64)
            };
        }
        solana_metrics::datapoint_info!(
            "gossip_packet_rates",
            ("crds_contact_info", pps!(crds_contact_info), f64),
            ("crds_epoch_slots", pps!(crds_epoch_slots), f64),
            ("crds_node_instance", pps!(crds_node_instance), f64),
            ("crds_other", pps!(crds_other), f64),
            ("crds_vote", pps!(crds_vote), f64),
            ("junk", pps!(invalid), f64),
            ("pingpong", pps!(pingpong), f64),
            ("prune", pps!(prune), f64),
            ("valid", pps!(valid), f64),
        );
    }
    fn feed_gui(&mut self) -> Vec<(String, f32)> {
        fn row(l: &str, m: &mut Monitor) -> (String, f32) {
            (l.to_owned(), m.rate_bps().unwrap_or(0.0) / 1e6)
        }
        vec![
            row("All Gossip", &mut self.valid),
            row("Junk", &mut self.invalid),
            row("Prune", &mut self.prune),
            row("Ping & Pong", &mut self.pingpong),
            row("CRDS: ContactInfo", &mut self.crds_contact_info),
            row("CRDS: Vote", &mut self.crds_vote),
            row("CRDS: EpochSlots", &mut self.crds_epoch_slots),
            row("CRDS: NodeInstance", &mut self.crds_node_instance),
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
            _ => {
                self.others.push(bytes.len());
            }
        }
        self.valid.push(bytes.len());
    }

    fn try_retain_crds(&mut self, cv: &CrdsValue) {
        let ser = bincode::serialize(cv.data()).unwrap();
        match cv.data() {
            CrdsData::EpochSlots(_esi, _es) => {
                self.crds_epoch_slots.push(ser.len());
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
            _ => {
                self.crds_other.push(ser.len());
            }
        }
    }
}
