use std::{
    f32,
    ops::ControlFlow,
    time::{Duration, Instant},
};

use crate::{monitor::PacketLogger, storage::Monitor, ui::*};
use crossbeam_channel::Sender;
use iocraft::prelude::*;

use super::{detect_repair_nonce, parse_turbine};

#[derive(Default)]
pub struct BitrateMonitor {
    // All invalid packets
    invalid: Monitor,
    // All valid packets in turbine tree
    turbine: Monitor,
    // Rate over repair
    repairs: Monitor,
    coding_shreds: Monitor,
    data_shreds: Monitor,
    zero_bytes: Monitor,
    total_bytes: Monitor,

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
    fn feed_gui(&mut self) -> Vec<(String, f32)> {
        fn row(l: &str, m: &mut Monitor) -> (String, f32) {
            (l.to_owned(), m.rate_bps().unwrap_or(0.0) / 1e6)
        }
        vec![
            row("All turbine", &mut self.turbine),
            row("Junk", &mut self.invalid),
            row("All repairs", &mut self.repairs),
            row("Coding shreds", &mut self.coding_shreds),
            row("Data shreds", &mut self.data_shreds),
            row("Zero bytes", &mut self.zero_bytes),
        ]
    }
    fn send_metrics(&mut self, metrics_category: &'static str) {
        macro_rules! bps {
            ($x:ident) => {
                (self.$x.rate_bps().unwrap_or_default() as f64)
            };
        }
        solana_metrics::datapoint_info!(
            metrics_category,
            ("everything", bps!(turbine), f64),
            ("junk", bps!(invalid), f64),
            ("repairs", bps!(repairs), f64),
            ("coding", bps!(coding_shreds), f64),
            ("data", bps!(data_shreds), f64),
            ("zero_bytes", bps!(zero_bytes), f64),
        );
        macro_rules! pps {
            ($x:ident) => {
                (self.$x.rate_pps().unwrap_or_default() as f64)
            };
        }
        solana_metrics::datapoint_info!(
            "turbine_packet_rates",
            ("everything", pps!(turbine), f64),
            ("junk", pps!(invalid), f64),
            ("repairs", pps!(repairs), f64),
            ("coding", pps!(coding_shreds), f64),
            ("data", pps!(data_shreds), f64),
        );
    }
}

impl PacketLogger for BitrateMonitor {
    fn handle_pkt(&mut self, wire_bytes: &[u8]) -> std::ops::ControlFlow<()> {
        let data_slice = &wire_bytes[20 + 8..];
        let Some((data_slice, nonce)) = detect_repair_nonce(data_slice) else {
            return ControlFlow::Continue(());
        };
        let data_bytes = data_slice.len();
        let pkt = match parse_turbine(&data_slice) {
            Ok(pkt) => pkt,
            Err(_) => {
                self.invalid.push(data_bytes);
                return ControlFlow::Continue(());
            }
        };
        if pkt.sanitize().is_err() {
            self.invalid.push(data_bytes);
            return ControlFlow::Continue(());
        }
        if nonce.is_some() {
            self.repairs.push(data_bytes);
        } else {
            self.turbine.push(data_bytes);
        }
        if pkt.is_code() {
            self.coding_shreds.push(data_bytes);
        } else {
            self.data_shreds.push(data_bytes);
        }
        self.zero_bytes
            .push(data_slice.iter().filter(|&e| *e == 0).count());

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
        // allow UI to kill itself
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }
}
