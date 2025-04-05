use std::{
    f32,
    ops::ControlFlow,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use crate::{monitor::PacketLogger, storage::Monitor, ui};
use crossbeam_channel::{Sender, TryRecvError};
use iocraft::prelude::*;
use solana_gossip::{crds_data::CrdsData, crds_value::CrdsValue, protocol::Protocol};
use solana_sanitize::Sanitize;

use super::parse_gossip;
pub type RateDisplayItems = Vec<(String, f32)>;
struct GossipMonitorChannel(crossbeam_channel::Receiver<RateDisplayItems>);

#[component]
fn GossipMonitorMenu(mut hooks: Hooks) -> impl Into<AnyElement<'static>> {
    let mut rates =
        hooks.use_state::<Vec<(String, f32)>, _>(|| vec![("Waiting for data".to_owned(), 0.0)]);
    let mut should_exit = hooks.use_state(|| false);
    let chan = hooks.use_context::<GossipMonitorChannel>().0.clone();
    hooks.use_future(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let pkt = match chan.try_recv() {
                Ok(pkt) => pkt,
                Err(TryRecvError::Empty) => continue,
                Err(TryRecvError::Disconnected) => {
                    should_exit.set(true);
                    break;
                }
            };
            let mut rates_guard = rates.write();
            *rates_guard = pkt;
        }
    });
    if should_exit.get() || crate::EXIT.load(Ordering::Relaxed) {
        let mut system = hooks.use_context_mut::<SystemContext>();
        system.exit();
    }

    element! {
        ui::RateDisplay(rates:rates.read().clone(), units:"Mbps")
    }
}

impl PacketLogger for GossipBitrateMonitor {
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

            fn row(l: &str, m: &mut Monitor) -> (String, f32) {
                (l.to_owned(), m.rate_bps().unwrap_or(f32::NAN) / 1e6)
            }
            let reports = vec![
                row("All Gossip", &mut self.valid),
                row("Junk", &mut self.invalid),
                row("Prune", &mut self.prune),
                row("Ping & Pong", &mut self.pingpong),
                row("CRDS: ContactInfo", &mut self.crds_contact_info),
                row("CRDS: Vote", &mut self.crds_vote),
                row("CRDS: EpochSlots", &mut self.crds_epoch_slots),
                row("CRDS: NodeInstance", &mut self.crds_node_instance),
            ];
            if self.channel.as_ref().unwrap().try_send(reports).is_err() {
                return ControlFlow::Break(());
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
pub struct GossipBitrateMonitor {
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
    crds_vote: Monitor,

    channel: Option<Sender<RateDisplayItems>>,
    last_report: Option<Instant>,
}

impl GossipBitrateMonitor {
    pub fn new() -> Self {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let me = Self {
            channel: Some(tx),
            last_report: Some(Instant::now()),
            ..Default::default()
        };
        tokio::spawn(async move {
            let mut elem = element! {
                ContextProvider(value: Context::owned(GossipMonitorChannel(rx))) {
                    GossipMonitorMenu
                }
            };
            elem.render_loop().await.expect("UI should exit cleanly");
        });

        me
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
            _ => {}
        }
    }
}
