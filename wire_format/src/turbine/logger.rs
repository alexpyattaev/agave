#![allow(dead_code)]
use crate::monitor::PacketLogger;
use anyhow::Context;
use log::info;
use network_types::ip::Ipv4Hdr;
use std::{mem::MaybeUninit, ops::ControlFlow, path::PathBuf};
use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc::{Receiver, Sender},
};

use super::{detect_repair_nonce, parse_turbine};

pub struct TurbineLogger {
    turbine_port: u16,
    repair_port: u16,
    num_captured: usize,
    chan: Option<Sender<TurbineLogEntry>>,
    output_file_name: PathBuf,
    writer: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

#[derive(Debug, Clone, Copy, wincode::SchemaWrite)]
pub struct TurbineLogEntry {
    us_since_epoch: u64,
    slot_number: u64,
    index: u32,
    sender_ip: u32,
    is_repair: bool,
}

async fn write_worker(
    mut writer: BufWriter<File>,
    mut rx: Receiver<TurbineLogEntry>,
) -> anyhow::Result<()> {
    let mut buf = [MaybeUninit::uninit(); 512];
    while let Some(pkt) = rx.recv().await {
        let wrote = wincode::serialize_into(&pkt, &mut buf)?;
        let init_buf = unsafe { std::mem::transmute::<_, &[u8]>(&buf[0..wrote]) };
        writer.write_all(init_buf).await?;
    }
    // channel closed → flush and exit
    writer.flush().await?;
    Ok(())
}

impl TurbineLogger {
    async fn new_writer(&mut self) -> anyhow::Result<()> {
        let mut path = self.output_file_name.clone();
        path.set_file_name(format!(
            "{}_{}.bin",
            path.file_name().unwrap().to_string_lossy(),
            self.num_captured
        ));
        info!("Logging arrival pattern into {path:?}");
        let writer = BufWriter::with_capacity(64 * 1024 * 1024, File::create(&path).await?);

        let (tx, rx) = tokio::sync::mpsc::channel(1024 * 1024);
        let jh = tokio::spawn(write_worker(writer, rx));
        self.writer = Some(jh);
        self.chan = Some(tx);
        Ok(())
    }

    pub async fn new_with_file_writer(
        mut output: PathBuf,
        turbine_port: u16,
        repair_port: u16,
    ) -> anyhow::Result<Self> {
        output.push("time_log_");
        let mut logger = TurbineLogger {
            turbine_port,
            repair_port,
            num_captured: 0,
            chan: None,
            output_file_name: output,
            writer: None,
        };
        logger.new_writer().await?;
        Ok(logger)
    }
    pub fn new_with_channel(
        turbine_port: u16,
        repair_port: u16,
    ) -> anyhow::Result<(Self, Receiver<TurbineLogEntry>)> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024 * 1024);
        Ok((
            TurbineLogger {
                turbine_port,
                repair_port,
                num_captured: 0,
                chan: Some(tx),
                output_file_name: PathBuf::new(),
                writer: None,
            },
            rx,
        ))
    }
}

impl PacketLogger for TurbineLogger {
    async fn handle_pkt(&mut self, wire_bytes: &[u8]) -> std::ops::ControlFlow<()> {
        let ip_hdr = &wire_bytes[0..20];
        let ip_hdr_ptr = ip_hdr.as_ptr() as *const Ipv4Hdr;
        let (src_ip, _dst_ip, _ip_proto) = wf_common::parse_ip_header(ip_hdr_ptr);
        // let udp_hdr = &wire_bytes[20..(20 + 8)];
        // let dst_port = u16::from_be_bytes(udp_hdr[2..4].try_into().unwrap());
        // TODO: validate that repair packets are coming over repair port
        let data_slice = &wire_bytes[20 + 8..];
        let Some((data_slice, nonce)) = detect_repair_nonce(data_slice) else {
            return ControlFlow::Continue(());
        };
        let is_repair = nonce.is_some();

        let pkt = match parse_turbine(data_slice) {
            Ok(pkt) => pkt,
            Err(_) => {
                return ControlFlow::Continue(());
            }
        };
        if pkt.sanitize().is_err() {
            return ControlFlow::Continue(());
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let fec_set_index = pkt.fec_set_index();
        let unique_index =
            fec_set_index * 64 + pkt.index() - fec_set_index + if pkt.is_code() { 32 } else { 0 };
        let log_entry = TurbineLogEntry {
            us_since_epoch: timestamp,
            slot_number: pkt.slot(),
            index: unique_index,
            sender_ip: src_ip.to_bits(),
            is_repair,
        };

        self.num_captured += 1;
        if self.num_captured % 10000 == 0 {
            info!("Logged {} packets", self.num_captured);
        }
        if let Err(_e) = self.chan.as_mut().unwrap().try_send(log_entry) {
            return ControlFlow::Break(());
        };
        if self.writer.is_some() && (self.num_captured % (1024 * 1024 * 64) == 0) {
            info!("Rotating log file after {} packets", self.num_captured);
            self.new_writer().await.unwrap();
        }

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
