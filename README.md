<p align="center">
  <a href="https://anza.xyz">
    <img alt="Anza" src="https://i.postimg.cc/VkKTnMM9/agave-logo-talc-1.png" width="250" />
  </a>
</p>

[![Agave validator](https://img.shields.io/crates/v/agave-validator.svg)](https://crates.io/crates/agave-validator)
[![Agave documentation](https://docs.rs/agave-validator/badge.svg)](https://docs.rs/agave-validator)
[![Build status](https://badge.buildkite.com/b2b925facfdbb575573084bb4b7e1f1ce7f395239672941bf7.svg?branch=master)](https://buildkite.com/anza/agave-secondary)
[![Release status](https://github.com/anza-xyz/agave/actions/workflows/release.yml/badge.svg)](https://github.com/anza-xyz/agave/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/anza-xyz/agave/branch/master/graph/badge.svg)](https://codecov.io/gh/anza-xyz/agave)

# Building

## **1. Install rustc, cargo and rustfmt.**

```bash
$ curl https://sh.rustup.rs -sSf | sh
$ source $HOME/.cargo/env
$ rustup component add rustfmt
```

The `rust-toolchain.toml` file pins a specific rust version and ensures that
cargo commands run with that version. Note that cargo will automatically install
the correct version if it is not already installed.

On Linux systems you may need to install libssl-dev, pkg-config, zlib1g-dev, protobuf etc.

On Ubuntu:
```bash
$ sudo apt-get update
$ sudo apt-get install libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang cmake make libprotobuf-dev protobuf-compiler libclang-dev
```

On Fedora:
```bash
$ sudo dnf install openssl-devel systemd-devel pkg-config zlib-devel llvm clang cmake make protobuf-devel protobuf-compiler perl-core clang-devel
```

## **2. Download the source code.**

```bash
$ git clone https://github.com/anza-xyz/agave.git
$ cd agave
```

## **3. Build.**

```bash
$ ./cargo build
```

> [!NOTE]
> Note that this builds a debug version that is **not suitable for running a testnet or mainnet validator**. Please read [the install guide](https://docs.anza.xyz/cli/install#build-from-source) for instructions to build a release version for test and production uses.

## **4. Grant capabilities for XDP (Linux-only).**

XDP transmit is enabled on Linux by default and requires extra capabilities. After building, grant them to the validator binary:

```bash
$ sudo setcap 'cap_net_admin,cap_net_raw+eip' <path-to-agave-validator-binary>
```

For XDP zero-copy mode (`--xdp-zero-copy`), additional capabilities are needed:

```bash
$ sudo setcap 'cap_net_admin,cap_net_raw,cap_bpf,cap_perfmon+eip' <path-to-agave-validator-binary>
```

# Testing

**Run the test suite:**

```bash
$ ./cargo nextest run --profile ci  --cargo-profile ci --config-file .config/nextest.toml
```

### Starting a local testnet

Start your own testnet locally, instructions are in the [online docs](https://docs.anza.xyz/clusters/benchmark).

### Accessing the remote development cluster

* `devnet` - stable public cluster for development accessible via
devnet.solana.com. Runs 24/7. Learn more about the [public clusters](https://docs.anza.xyz/clusters)

# Benchmarking

First, install the nightly build of rustc. `cargo bench` requires the use of the
unstable features only available in the nightly build.

```bash
$ rustup install nightly
```

Run the benchmarks:

```bash
$ cargo +nightly bench
```

# Profiling with Tracy

`agave-validator` can be built with an on-demand [Tracy](https://github.com/wolfpld/tracy)
client. Nothing is collected until a Tracy GUI connects, and the client only
listens on localhost, so remote hosts are reached through an SSH tunnel.

**Build** (frame pointers give usable sampled callstacks). `RUSTFLAGS` replaces
the `rustflags` in `.cargo/config.toml`, so `target-cpu` has to be repeated:

```bash
$ RUSTFLAGS="-Ctarget-cpu=x86-64-v2 -C force-frame-pointers=yes" ./cargo build --profile release-with-debug --features tracy -p agave-validator --bin agave-validator
```

**Prepare the host** (Linux, not persistent across reboots). This allows
unprivileged perf events and makes the scheduler tracepoints readable, which
Tracy needs for sampling and context switch tracing:

```bash
$ sudo ./scripts/tracy-host-setup.sh
# when done profiling
$ sudo ./scripts/tracy-host-setup.sh --revert
```

**Run** the validator as usual. The client listens on `127.0.0.1:8086`
(override with the `TRACY_PORT` env var). CPU sampling defaults to 10 kHz per
core, which produces a lot of data on a busy validator; consider lowering it,
e.g. `TRACY_SAMPLING_HZ=1000`.

**Connect** from your workstation:

```bash
$ ssh -N -L 8086:localhost:8086 <validator-host>
```

then open the Tracy GUI and connect to `127.0.0.1:8086`. The GUI version must
match the protocol of the `tracy-client` crate in `Cargo.toml` (`tracy-client`
0.19.x requires Tracy v0.14.1), see the
[version table](https://github.com/nagisa/rust_tracy_client/tree/main/tracy-client#version-support-table).

Each replay pass over a slot shows as a `replay_slot` zone on the
`solReplayStage` / `solReplayFork*` threads, with the slot number as the zone
value. A frame is marked each time replay freezes a bank, so a frame spans from
one frozen slot to the next, and a `slot <n> frozen` message is logged at the
same point. Profiling adds overhead while the GUI is connected.

# Release Process

The release process for this project is described [here](RELEASE.md).

# Code coverage

To generate code coverage statistics:

```bash
$ scripts/coverage.sh
$ open target/cov/lcov-local/index.html
```

Why coverage? While most see coverage as a code quality metric, we see it primarily as a developer
productivity metric. When a developer makes a change to the codebase, presumably it's a *solution* to
some problem.  Our unit-test suite is how we encode the set of *problems* the codebase solves. Running
the test suite should indicate that your change didn't *infringe* on anyone else's solutions. Adding a
test *protects* your solution from future changes. Say you don't understand why a line of code exists,
try deleting it and running the unit-tests. The nearest test failure should tell you what problem
was solved by that code. If no test fails, go ahead and submit a Pull Request that asks, "what
problem is solved by this code?" On the other hand, if a test does fail and you can think of a
better way to solve the same problem, a Pull Request with your solution would most certainly be
welcome! Likewise, if rewriting a test can better communicate what code it's protecting, please
send us that patch!
