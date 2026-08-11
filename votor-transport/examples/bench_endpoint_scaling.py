#!/usr/bin/env python3
"""Measure votor-transport server CPU cost as a function of inbound endpoint count.

For each endpoint count: start `bench_server`, bring up `bench_loadgen`, let the
traffic settle, then run `perf stat` against both processes for exactly
--perf-secs seconds.

Server and load generator are pinned to disjoint physical cores so the generator
cannot steal cycles from the process under measurement. SMT siblings share
execution units, so a sibling counts as the same core for this purpose.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_BIN = REPO_ROOT / "target/release/examples/bench_server"
LOADGEN_BIN = REPO_ROOT / "target/release/examples/bench_loadgen"

SERVER_EVENTS = (
    "task-clock",
    "context-switches",
    "cpu-migrations",
    "cycles",
    "instructions",
)
LOADGEN_EVENTS = ("task-clock", "context-switches")

# Ceiling on the connect phase, which the server's own clock has to cover.
CONNECT_BUDGET_SECS = 60
# Must match `DATAGRAMS_PER_SECOND_PER_PEER` in examples/common/mod.rs.
DATAGRAMS_PER_SECOND_PER_PEER = 50


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--endpoints", type=int, nargs="+", default=[1, 2, 4, 8])
    p.add_argument("--num-clients", type=int, default=2000)
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--perf-secs", type=int, default=10)
    p.add_argument("--settle-secs", type=int, default=3)
    p.add_argument(
        "--num-sockets",
        type=int,
        default=256,
        help="source ports to use for the generator to spread connections over",
    )
    p.add_argument("--server-cpus", default="0-11")
    p.add_argument(
        "--server-worker-threads",
        type=int,
        default=8,
    )
    p.add_argument("--loadgen-cpus", default="12-23")
    p.add_argument("--loadgen-worker-threads", type=int, default=14)
    p.add_argument("--rust-log", default="error")
    p.add_argument("--out-dir", type=Path)
    return p.parse_args()


def expand_cpus(spec: str) -> list[int]:
    cpus = []
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            cpus.extend(range(int(lo), int(hi) + 1))
        else:
            cpus.append(int(part))
    return cpus


def warn_on_shared_cores(server_cpus: str, loadgen_cpus: str) -> None:
    loadgen = set(expand_cpus(loadgen_cpus))
    for cpu in expand_cpus(server_cpus):
        siblings = Path(
            f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        )
        if not siblings.exists():
            continue
        shared = loadgen.intersection(expand_cpus(siblings.read_text().strip()))
        if shared:
            print(
                f"WARNING: server ({cpu}) and loadgen ({sorted(shared)}) share cores!",
                file=sys.stderr,
            )
            return


class Bench:
    # binary pinned with taskset, stdout and stderr captured to a log.
    def __init__(self, name, argv, cpus, log_path, env):
        self.name = name
        self.log_path = log_path
        self._log = log_path.open("w")
        self.proc = subprocess.Popen(
            ["taskset", "-c", cpus, *[str(a) for a in argv]],
            stdout=self._log,
            stderr=subprocess.STDOUT,
            env=env,
        )

    def alive(self):
        return self.proc.poll() is None

    def wait_for(self, prefix, timeout):
        """Block until the binary prints a line starting with `prefix`."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in read_complete_lines(self.log_path):
                if line.startswith(prefix):
                    return line
            if not self.alive():
                raise RuntimeError(
                    f"{self.name} exited before printing {prefix!r}, see {self.log_path}"
                )
            time.sleep(0.1)
        raise RuntimeError(
            f"{self.name} did not print {prefix!r} within {timeout}s, see {self.log_path}"
        )

    def stop(self):
        if self.alive():
            self.proc.terminate()
        self.proc.wait()
        self._log.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()


def read_complete_lines(path):
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    return lines[:-1] if not text.endswith("\n") else lines


def samples(path, prefix):
    """Per-second `key=value` samples a bench binary has printed so far."""
    found = []
    for line in read_complete_lines(path):
        fields = line.split()
        if fields and fields[0] == prefix:
            found.append({k: int(v) for k, v in (f.split("=", 1) for f in fields[1:])})
    return found


def latest(path, prefix):
    found = samples(path, prefix)
    if not found:
        raise RuntimeError(f"no {prefix} lines in {path} yet")
    return found[-1]


def window_rate(before, after, total_key):
    """Steady-state rate over a whole number of the binary's own report ticks."""
    ticks = after["t"] - before["t"]
    return (after[total_key] - before[total_key]) / ticks if ticks else 0.0


def perf_stat(pid, events, secs, log_path):
    """Counters for `secs` of `pid`'s execution, keyed by event name."""
    with log_path.open("w") as log:
        _ = subprocess.run(
            [
                "perf",
                "stat",
                "-x,",
                "-e",
                ",".join(events),
                "-p",
                str(pid),
                "--",
                "sleep",
                str(secs),
            ],
            stdout=subprocess.DEVNULL,
            stderr=log,
            check=True,
        )
    counters = {}
    for line in log_path.read_text().splitlines():
        value, _unit, event = (line.split(",") + ["", "", ""])[:3]
        try:
            counters[event] = float(value)
        except ValueError:
            continue
    return counters


def emit(kind, record, out_dir):
    line = kind + " " + " ".join(f"{k}={v}" for k, v in record.items())
    print(line, flush=True)
    with (out_dir / "summary.txt").open("a") as f:
        f.write(line + "\n")
    with (out_dir / "results.jsonl").open("a") as f:
        f.write(json.dumps({"kind": kind, **record}) + "\n")


def start_server(args, endpoints, log_path, env, run_secs):
    argv = [
        SERVER_BIN,
        "--num-endpoints",
        endpoints,
        "--num-peers",
        args.num_clients,
        "--worker-threads",
        args.server_worker_threads,
        "--run-secs",
        run_secs,
    ]
    server = Bench("bench_server", argv, args.server_cpus, log_path, env)
    try:
        _, pubkey, addr = server.wait_for("SERVER ", timeout=30).split()
    except BaseException:
        # The caller only gets to `with` the server once it is up, so a failed
        # startup has to reap the process here or it outlives the sweep.
        server.stop()
        raise
    return server, pubkey, addr


def run_load(args, endpoints, rep, out_dir, env):
    tag = f"ep{endpoints}_rep{rep}"
    loadgen_secs = args.settle_secs + args.perf_secs + 10
    # The server's clock starts before the connect phase and the generator's does
    # not, so its budget covers the connect wait as well or it can exit from
    # under the perf window.
    server_secs = CONNECT_BUDGET_SECS + loadgen_secs + 30

    server, pubkey, addr = start_server(
        args, endpoints, out_dir / f"server_{tag}.log", env, server_secs
    )
    argv = [
        LOADGEN_BIN,
        "--server-addr",
        addr,
        "--server-pubkey",
        pubkey,
        "--num-clients",
        args.num_clients,
        "--num-sockets",
        args.num_sockets,
        "--worker-threads",
        args.loadgen_worker_threads,
        "--duration-secs",
        loadgen_secs,
    ]
    with (
        server,
        Bench(
            "bench_loadgen",
            argv,
            args.loadgen_cpus,
            out_dir / f"loadgen_{tag}.log",
            env,
        ) as loadgen,
    ):
        loadgen.wait_for("CONNECTED ", timeout=CONNECT_BUDGET_SECS)
        time.sleep(args.settle_secs)

        rx_before = latest(server.log_path, "STAT")
        # Both processes are sampled over the same window, so the two CPU
        # numbers are comparable and their sum is the whole cost of the traffic.
        with ThreadPoolExecutor(2) as pool:
            srv_perf = pool.submit(
                perf_stat,
                server.proc.pid,
                SERVER_EVENTS,
                args.perf_secs,
                out_dir / f"perf_{tag}.txt",
            )
            gen_perf = pool.submit(
                perf_stat,
                loadgen.proc.pid,
                LOADGEN_EVENTS,
                args.perf_secs,
                out_dir / f"perf_loadgen_{tag}.txt",
            )
            counters, gen_counters = srv_perf.result(), gen_perf.result()
        rx_after = latest(server.log_path, "STAT")
        if not loadgen.alive():
            raise RuntimeError(
                f"bench_loadgen died during the perf window, see {loadgen.log_path}"
            )

    pkts = window_rate(rx_before, rx_after, "rx_total") * args.perf_secs
    # Slowest full second inside the window, which catches a dip the window
    # average would smooth over.
    min_rx_per_s = min(
        (
            s["rx_per_s"]
            for s in samples(server.log_path, "STAT")
            if rx_before["t"] < s["t"] <= rx_after["t"]
        ),
        default=0,
    )

    cpu_seconds = counters.get("task-clock", 0.0) / 1000
    gen_cpu_seconds = gen_counters.get("task-clock", 0.0) / 1000
    cycles = counters.get("cycles", 0)
    instructions = counters.get("instructions", 0)

    def per_pkt(total):
        return total / pkts if pkts else 0.0

    emit(
        "RESULT",
        {
            "endpoints": endpoints,
            "cpus_busy": round(cpu_seconds / args.perf_secs, 3),
            "ipc": round(instructions / cycles, 2) if cycles else 0.0,
            "ctxsw_per_pkt": round(per_pkt(counters.get("context-switches", 0)), 4),
            "migrations": round(counters.get("cpu-migrations", 0)),
            "gen_cpu_seconds": round(gen_cpu_seconds, 3),
            "gen_ctxsw_per_pkt": round(
                per_pkt(gen_counters.get("context-switches", 0)), 4
            ),
            "min_rx_per_s": f"{min_rx_per_s} "
            f"({args.num_clients * DATAGRAMS_PER_SECOND_PER_PEER})",
        },
        out_dir,
    )


def main():
    args = parse_args()
    warn_on_shared_cores(args.server_cpus, args.loadgen_cpus)
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "-p",
            "agave-votor-transport",
            "--features",
            "agave-unstable-api,dev-context-only-utils",
            "--examples",
        ],
        cwd=REPO_ROOT,
        check=True,
    )

    out_dir = args.out_dir or Path(tempfile.mkdtemp(prefix="votor-endpoint-bench-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    # Reusing an out-dir must not silently interleave this sweep's rows with an
    # older one's, which is easy to miss once the field names have drifted.
    for stale in ("summary.txt", "results.jsonl"):
        (out_dir / stale).unlink(missing_ok=True)
    print(f"results -> {out_dir}")
    env = dict(os.environ)
    env.pop("SOLANA_METRICS_CONFIG", None)
    env["RUST_LOG"] = args.rust_log

    for rep in range(1, args.repeats + 1):
        for endpoints in args.endpoints:
            run_load(args, endpoints, rep, out_dir, env)
            time.sleep(2)


if __name__ == "__main__":
    main()
