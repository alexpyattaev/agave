use std::{path::PathBuf, process::Command};

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the debug target (release is default)
    #[clap(long)]
    pub debug: bool,
}

/// Build the project
fn build_project(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if !opts.debug {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build our ebpf program and the project
pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(
        BuildOptions {
            target: opts.bpf_target,
            debug: opts.debug,
        },
        PathBuf::from("wf_ebpf"),
    )
    .context("Error while building eBPF XDP program")?;
    build_ebpf(
        BuildOptions {
            target: opts.bpf_target,
            debug: opts.debug,
        },
        PathBuf::from("wf_tc"),
    )
    .context("Error while building eBPF TC program")?;
    build_project(&opts).context("Error while building userspace application")?;
    Ok(())
}
