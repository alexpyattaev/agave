#!/usr/bin/env bash
# Measure votor-transport server CPU cost as a function of inbound endpoint count.
#
# For each endpoint count: start `bench_server`, bring up `bench_loadgen` with
# --num-clients connections at --pps each, let traffic settle, then run
# `perf stat` against the server PID for exactly --perf-secs seconds.
#
# Server and load generator are pinned to disjoint physical cores so the
# generator cannot steal cycles from the process under measurement. SMT siblings
# share execution units, so a sibling counts as the same core for this purpose.
set -euo pipefail

# Keep the run off whatever metrics DB the shell points at, and out of the
# `datapoint_info!` path entirely: with SOLANA_METRICS_CONFIG set, the metrics
# agent serializes points, which drags in a hasher that panics unless something
# in the build enables `solana-sha256-hasher/sha2`. Unsetting it also makes CPU
# numbers independent of the operator's environment.
unset SOLANA_METRICS_CONFIG

ENDPOINT_COUNTS=${ENDPOINT_COUNTS:-"1 2 4"}
NUM_CLIENTS=${NUM_CLIENTS:-2000}
PPS=${PPS:-50}
PERF_SECS=${PERF_SECS:-10}
SETTLE_SECS=${SETTLE_SECS:-3}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-160}
# Source ports the generator spreads its connections over. The kernel picks the
# receiving SO_REUSEPORT socket by hashing the 4-tuple, and source port is the
# only part that varies here, so this is the granularity at which load can be
# split across the server's inbound endpoints. At 8 it is coarse enough to leave
# one of 4 endpoints idle outright; keep it well above MAX_ENDPOINTS (8).
NUM_SOCKETS=${NUM_SOCKETS:-256}
# CPU pinning, sized for this box: AMD EPYC 9275F, 24 physical cores / 48
# threads, one socket, one NUMA node, SMT siblings paired as N and N+24.
#
# Only the low thread of each core is used and 24-47 are left out entirely --
# putting the generator on an SMT sibling of a server core shares that core's
# execution units and pollutes the measurement as badly as sharing the core.
# Thread counts are matched to core counts so neither side oversubscribes.
SERVER_CPUS=${SERVER_CPUS:-0-9}
SERVER_WORKER_THREADS=${SERVER_WORKER_THREADS:-8} # + drain thread + main = 10
LOADGEN_CPUS=${LOADGEN_CPUS:-10-23}
LOADGEN_WORKER_THREADS=${LOADGEN_WORKER_THREADS:-14}
REPEATS=${REPEATS:-1}
OUT_DIR=${OUT_DIR:-$(mktemp -d -t votor-endpoint-bench-XXXXXX)}

# Expand a taskset-style cpu spec ("0-9", "0,2,4", "0-3,8") to one cpu per line.
expand_cpus() {
  local part start end c
  local -a parts
  IFS=',' read -ra parts <<<"$1"
  for part in "${parts[@]}"; do
    if [[ $part == *-* ]]; then
      start=${part%-*}
      end=${part#*-}
      for ((c = start; c <= end; c++)); do echo "$c"; done
    else
      echo "$part"
    fi
  done
}

# The pinning above is hardcoded to one machine's topology, so verify it rather
# than trusting it: warn (do not fail) if any server core has an SMT sibling in
# the generator's set. Non-fatal because a skewed run is still worth having as
# long as the operator knows the isolation is imperfect.
check_sibling_overlap() {
  local cpu sibling gen_cpu
  local -a gen_cpus
  mapfile -t gen_cpus < <(expand_cpus "$LOADGEN_CPUS")
  for cpu in $(expand_cpus "$SERVER_CPUS"); do
    local siblings_file="/sys/devices/system/cpu/cpu$cpu/topology/thread_siblings_list"
    [[ -r $siblings_file ]] || continue
    for sibling in $(expand_cpus "$(<"$siblings_file")"); do
      ((sibling == cpu)) && continue
      for gen_cpu in "${gen_cpus[@]}"; do
        if ((gen_cpu == sibling)); then
          echo "WARNING: server cpu $cpu and loadgen cpu $sibling are SMT siblings;" \
            "they share execution units, so the generator will perturb the measurement" >&2
          return
        fi
      done
    done
  done
}
check_sibling_overlap

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SERVER_BIN="$REPO_ROOT/target/release/examples/bench_server"
LOADGEN_BIN="$REPO_ROOT/target/release/examples/bench_loadgen"

if [[ ! -x $SERVER_BIN || ! -x $LOADGEN_BIN ]]; then
  echo "building bench examples..." >&2
  cargo build --release -p agave-votor-transport \
    --features agave-unstable-api,dev-context-only-utils --examples
fi

# The generator needs enough runway for connect + settle + the perf window.
WINDOWS=1
[[ ${PER_THREAD:-0} == 1 ]] && WINDOWS=2
LOADGEN_SECS=$((SETTLE_SECS + WINDOWS * PERF_SECS + 10))
SERVER_SECS=$((LOADGEN_SECS + 25))

mkdir -p "$OUT_DIR"
echo "results -> $OUT_DIR"

run_one() {
  local endpoints=$1 rep=$2
  local tag="ep${endpoints}_rep${rep}"
  local srv_log="$OUT_DIR/server_$tag.log"
  local gen_log="$OUT_DIR/loadgen_$tag.log"
  local perf_log="$OUT_DIR/perf_$tag.txt"

  RUST_LOG=${RUST_LOG:-error} taskset -c "$SERVER_CPUS" \
    "$SERVER_BIN" \
    --num-endpoints "$endpoints" \
    --num-peers "$NUM_CLIENTS" \
    --worker-threads "$SERVER_WORKER_THREADS" \
    --run-secs "$SERVER_SECS" >"$srv_log" 2>&1 &
  local srv_wrapper=$!

  # Wait for the SERVER line, which carries the real pid, addr and pubkey.
  local waited=0
  while ! grep -q '^SERVER ' "$srv_log" 2>/dev/null; do
    sleep 0.1
    waited=$((waited + 1))
    if ((waited > 300)); then
      echo "server failed to start; see $srv_log" >&2
      cat "$srv_log" >&2
      kill "$srv_wrapper" 2>/dev/null || true
      return 1
    fi
  done
  local srv_pid srv_addr srv_pubkey
  srv_pubkey=$(awk '/^SERVER /{print $2; exit}' "$srv_log")
  srv_addr=$(awk '/^SERVER /{print $3; exit}' "$srv_log")
  srv_pid=$(awk '/^SERVER /{sub(/^pid=/, "", $4); print $4; exit}' "$srv_log")

  RUST_LOG=${RUST_LOG:-error} taskset -c "$LOADGEN_CPUS" \
    "$LOADGEN_BIN" \
    --server-addr "$srv_addr" \
    --server-pubkey "$srv_pubkey" \
    --num-clients "$NUM_CLIENTS" \
    --pps "$PPS" \
    --num-sockets "$NUM_SOCKETS" \
    --payload-bytes "$PAYLOAD_BYTES" \
    --worker-threads "$LOADGEN_WORKER_THREADS" \
    --duration-secs "$LOADGEN_SECS" >"$gen_log" 2>&1 &
  local gen_pid=$!

  waited=0
  while ! grep -q '^CONNECTED ' "$gen_log" 2>/dev/null; do
    sleep 0.1
    waited=$((waited + 1))
    if ((waited > 600)); then
      echo "load generator failed to connect; see $gen_log" >&2
      tail -20 "$gen_log" >&2
      kill "$gen_pid" "$srv_pid" 2>/dev/null || true
      return 1
    fi
  done

  sleep "$SETTLE_SECS"
  perf stat -p "$srv_pid" \
    -e task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions \
    -- sleep "$PERF_SECS" 2>"$perf_log" || true
  # Optional second window: where the CPU time lands across threads. Kept
  # separate because perf cannot report aggregate and per-thread at once.
  if [[ ${PER_THREAD:-0} == 1 ]]; then
    perf stat --per-thread -p "$srv_pid" -e task-clock \
      -- sleep "$PERF_SECS" 2>"$OUT_DIR/perthread_$tag.txt" || true
  fi

  kill "$gen_pid" 2>/dev/null || true
  kill "$srv_pid" 2>/dev/null || true
  wait "$gen_pid" 2>/dev/null || true
  wait "$srv_wrapper" 2>/dev/null || true

  local cpu_secs cpu_util rx_med rx_min status
  cpu_secs=$(awk '/task-clock/{gsub(/,/, "", $1); printf "%.3f", $1 / 1000}' "$perf_log")
  cpu_util=$(awk '/task-clock/{for (i = 1; i <= NF; i++) if ($i == "CPUs") print $(i - 1)}' "$perf_log")
  # Median and minimum received rate over the seconds that carried traffic.
  # Zero-rate samples are ramp-up and post-kill, not part of the measurement.
  # The first and last traffic-carrying seconds are partial (traffic starts and
  # stops mid-second), so they are dropped before looking for a real dip.
  local rates
  rates=$(sed -n 's/.*rx_per_s=\([0-9]*\).*/\1/p' "$srv_log" | awk '$1 > 0' |
    awk '{v[NR] = $1} END {for (i = 2; i < NR; i++) print v[i]}' | sort -n)
  rx_med=$(printf '%s\n' "$rates" | awk '{v[NR] = $1} END {if (NR) print v[int((NR + 1) / 2)]; else print 0}')
  rx_min=$(printf '%s\n' "$rates" | head -1)

  # A run whose offered load collapsed mid-window measures nothing useful.
  status=ok
  local expected=$((NUM_CLIENTS * PPS))
  if grep -q '^SEND_ERROR' "$gen_log"; then
    status=SUSPECT_send_errors
  elif [[ -z ${rx_min:-} ]] || ((rx_min < expected * 95 / 100)); then
    status=SUSPECT_rate_dip
  fi

  local line="RESULT endpoints=$endpoints rep=$rep cpu_seconds=$cpu_secs cpus_busy=$cpu_util"
  line+=" median_rx_per_s=$rx_med min_rx_per_s=${rx_min:-0} status=$status"
  printf '%s\n' "$line" | tee -a "$OUT_DIR/summary.txt"
}

for rep in $(seq 1 "$REPEATS"); do
  for endpoints in $ENDPOINT_COUNTS; do
    run_one "$endpoints" "$rep"
    sleep 2
  done
done

echo
echo "=== summary (perf window: ${PERF_SECS}s, ${NUM_CLIENTS} clients x ${PPS} pps," \
  "${NUM_SOCKETS} source ports) ==="
cat "$OUT_DIR/summary.txt"
