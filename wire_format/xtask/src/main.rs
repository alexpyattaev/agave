mod build;
mod build_ebpf;
mod run;

use std::{path::PathBuf, process::exit};

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildXdp(build_ebpf::Options),
    BuildTc(build_ebpf::Options),
    Build(build::Options),
    Run(run::Options),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildXdp(opts) => build_ebpf::build_ebpf(opts, PathBuf::from("wf_ebpf")),
        BuildTc(opts) => build_ebpf::build_ebpf(opts, PathBuf::from("wf_tc")),
        Run(opts) => run::run(opts),
        Build(opts) => build::build(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
