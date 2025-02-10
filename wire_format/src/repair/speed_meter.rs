use std::{
    ops::ControlFlow,
    time::{Duration, Instant},
};

use super::parse_repair;
use crate::{monitor::PacketLogger, storage::Monitor, ui::*};
use crossbeam_channel::Sender;
use iocraft::prelude::*;
use solana_core::repair::serve_repair::RepairProtocol;

#[derive(Default)]
pub struct BitrateMonitor {
    window_index: Monitor,
    highest_window_index: Monitor,
    orphan: Monitor,
    ancestor: Monitor,
    pong: Monitor,
    // All invalid packets
    invalid: Monitor,
    // All valid repair
    repairs: Monitor,

    channel: Option<Sender<RateDisplayItems>>,
    last_report: Option<Instant>,
    metrics_category: Option<&'static str>,
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

    fn maybe_report(&mut self) -> ControlFlow<(), ()> {
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

    fn feed_gui(&mut self) -> Vec<(String, f64)> {
        fn row(l: &str, m: &mut Monitor) -> (String, f64) {
            (l.to_owned(), m.rate_bps().unwrap_or(0.0) / 1e6)
        }
        vec![
            row("All Repair", &mut self.repairs),
            row("Junk", &mut self.invalid),
            row("Window Index", &mut self.window_index),
        ]
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
            ("everything", bps!(repairs), f64),
            ("everything_pps", pps!(repairs), f64),
            ("junk", bps!(invalid), f64),
            ("junk_pps", pps!(invalid), f64),
        );
    }
}

#[allow(dead_code, unused_variables)]
impl PacketLogger for BitrateMonitor {
    fn handle_pkt(&mut self, wire_bytes: &[u8]) -> std::ops::ControlFlow<()> {
        let data_slice = &wire_bytes[20 + 8..];
        let data_bytes = data_slice.len();
        println!("Got {data_bytes} in packet");
        let pkt = match parse_repair(&data_slice) {
            Ok(pkt) => pkt,
            Err(_) => {
                self.invalid.push(data_bytes);
                return self.maybe_report();
            }
        };
        // if pkt.sanitize().is_err() {
        //     self.invalid.push(data_bytes);
        //     return ControlFlow::Continue(());
        // }
        self.repairs.push(data_bytes);

        match pkt {
            RepairProtocol::LegacyWindowIndex => {}
            RepairProtocol::LegacyHighestWindowIndex => {}
            RepairProtocol::LegacyOrphan => {}
            RepairProtocol::LegacyWindowIndexWithNonce => {}
            RepairProtocol::LegacyHighestWindowIndexWithNonce => {}
            RepairProtocol::LegacyOrphanWithNonce => {}
            RepairProtocol::LegacyAncestorHashes => {}
            RepairProtocol::Pong(pong) => {}
            RepairProtocol::WindowIndex {
                header,
                slot,
                shred_index,
            } => {}
            RepairProtocol::HighestWindowIndex {
                header,
                slot,
                shred_index,
            } => {}
            RepairProtocol::Orphan { header, slot } => {}
            RepairProtocol::AncestorHashes { header, slot } => {}
        }
        self.maybe_report()
    }

    async fn finalize(&mut self) -> anyhow::Result<()> {
        drop(self.channel.take());
        // allow UI to kill itself
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }
}
