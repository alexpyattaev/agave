#![allow(dead_code)]
use std::{io::Write, ops::ControlFlow, path::PathBuf};

use crate::monitor::PacketLogger;
use anyhow::Context;
use log::info;
use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc::Receiver,
    sync::mpsc::Sender,
};

use super::{detect_repair_nonce, get_coding_header, parse_turbine};

pub struct TurbineLogger {
    turbine_port: u16,
    repair_port: u16,
    num_captured: usize,
    chan: Option<Sender<Vec<u8>>>,
    writer: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl TurbineLogger {
    pub async fn new_with_file_writer(
        mut output: PathBuf,
        turbine_port: u16,
        repair_port: u16,
    ) -> anyhow::Result<Self> {
        output.push("time_log.csv");
        let (tx, rx) = tokio::sync::mpsc::channel(1024 * 1024);
        let mut writer = BufWriter::with_capacity(64 * 1024 * 1024, File::create(&output).await?);
        writer
            .write(b"event_type:slot_number:index:fec_index:shreds_in_batch:us_since_epoch\n")
            .await?;
        async fn write_worker(
            mut writer: BufWriter<File>,
            mut rx: Receiver<Vec<u8>>,
        ) -> anyhow::Result<()> {
            while let Some(pkt) = rx.recv().await {
                writer.write(pkt.as_ref()).await?;
            }
            writer.flush().await?;
            Ok(())
        }
        let jh = tokio::spawn(write_worker(writer, rx));
        info!("Logging arrival pattern into {output:?}");
        Ok(TurbineLogger {
            turbine_port,
            repair_port,
            num_captured: 0,
            chan: Some(tx),
            writer: Some(jh),
        })
    }
    pub fn new_with_channel(
        turbine_port: u16,
        repair_port: u16,
    ) -> anyhow::Result<(Self, Receiver<Vec<u8>>)> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024 * 1024);
        Ok((
            TurbineLogger {
                turbine_port,
                repair_port,
                num_captured: 0,
                chan: Some(tx),
                writer: None,
            },
            rx,
        ))
    }
}

impl PacketLogger for TurbineLogger {
    fn handle_pkt(&mut self, wire_bytes: &[u8]) -> std::ops::ControlFlow<()> {
        // let udp_hdr = &wire_bytes[20..(20 + 8)];
        // let dst_port = u16::from_be_bytes(udp_hdr[2..4].try_into().unwrap());
        // TODO: validate that repair packets are coming over repair port
        let data_slice = &wire_bytes[20 + 8..];
        let Some((data_slice, nonce)) = detect_repair_nonce(data_slice) else {
            return ControlFlow::Continue(());
        };
        let event_type = if nonce.is_none() { "SHRED" } else { "REPAIR" };

        let pkt = match parse_turbine(data_slice) {
            Ok(pkt) => pkt,
            Err(_) => {
                return ControlFlow::Continue(());
            }
        };
        if pkt.sanitize().is_err() {
            return ControlFlow::Continue(());
        }
        let coding_header = get_coding_header(&pkt);
        let shreds_in_batch = match coding_header {
            Some(ch) => ch.num_coding_shreds + ch.num_data_shreds,
            None => 0,
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let mut buf = Vec::with_capacity(128);
        write!(
            &mut buf,
            "{event_type}:{slot}:{idx}:{fecidx}:{shreds_in_batch}:{timestamp}\n",
            slot = pkt.slot(),
            idx = pkt.index(),
            fecidx = pkt.fec_set_index(),
        )
        .unwrap();

        self.num_captured += 1;
        if self.num_captured % 10000 == 0 {
            info!("Logged {} packets", self.num_captured);
        }
        if let Err(_e) = self.chan.as_mut().unwrap().try_send(buf) {
            return ControlFlow::Break(());
        };
        ControlFlow::Continue(())
    }

    async fn finalize(&mut self) -> anyhow::Result<()> {
        // signal the writer that no more packets are coming
        drop(self.chan.take());
        if let Some(writer) = self.writer.take() {
            info!("Flushing file to disk...");
            writer.await.context("Writer should not panic!")??;
        }
        Ok(())
    }
}
