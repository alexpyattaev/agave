#!/usr/bin/env bash
# Measure votor-transport server CPU cost as a function of inbound endpoint count.
#
# For each endpoint count: start `bench_server`, bring up `bench_loadgen` with
# --num-clients connections at --pps each, let traffic settle, then run
# `perf stat` against the server PID for exactly --perf-secs seconds.
#
# The generator is measured over the same window, and so is the machine as a
# whole. On loopback much of the linux IP receive stack runs in NET_RX
# softirq in the *sender's* context (RPS is off, so `netif_rx` enqueues to the
# sending CPU's backlog), which bills it to the generator rather than to the
# server. The server process number is therefore a lower bound on what the same
# traffic costs behind a real NIC; watch how gen_ns_per_pkt moves with endpoint
# count too, since part of the effect under study lives there.
#
# Server and load generator are pinned to disjoint physical cores so the
# generator cannot steal cycles from the process under measurement. SMT siblings
# share execution units, so a sibling counts as the same core for this purpose.
set -euo pipefail

# perf renders counters with locale-specific digit grouping. Pin the locale to C.
export LC_ALL=C

# Keep the run off whatever metrics DB the shell points at.
unset SOLANA_METRICS_CONFIG

# For the same reason, do not inherit RUST_LOG. At `info` the server emits one
# `Admitted connection` line per peer - thousands of formatted writes inside the
# process under measurement - so an operator whose shell exports RUST_LOG=info
# would silently measure the logger. Set BENCH_RUST_LOG to debug a run.
BENCH_RUST_LOG=${BENCH_RUST_LOG:-error}

ENDPOINT_COUNTS=${ENDPOINT_COUNTS:-"1 2 4"}
NUM_CLIENTS=${NUM_CLIENTS:-2000}
PPS=${PPS:-50}
PERF_SECS=${PERF_SECS:-10}
SETTLE_SECS=${SETTLE_SECS:-3}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-160}
# Source ports the generator spreads its connections over. Source port is the
# only part that varies here, so this is the granularity at which load can be
# split across the server's inbound endpoints, keep it well above MAX_ENDPOINTS (8).
NUM_SOCKETS=${NUM_SOCKETS:-256}
# CPU pinning, sized for this box: AMD EPYC 9275F, 24 physical cores / 48
# threads, one socket, one NUMA node, SMT siblings paired as N and N+24.
#
# Only the low thread of each core is used and 24-47 are left out entirely -
# putting the generator on an SMT sibling of a server core shares that core's
# execution units and pollutes the measurement as badly as sharing the core.
# Thread counts are matched to core counts so neither side oversubscribes.
SERVER_CPUS=${SERVER_CPUS:-0-9}
SERVER_WORKER_THREADS=${SERVER_WORKER_THREADS:-8} # + drain thread + main = 10
LOADGEN_CPUS=${LOADGEN_CPUS:-10-23}
LOADGEN_WORKER_THREADS=${LOADGEN_WORKER_THREADS:-14}
REPEATS=${REPEATS:-1}
# Per endpoint count, also measure the server with no traffic at all. CPU cost
# as a function of endpoint count has a fixed part (drivers, drain cadence,
# runtime) and a per-packet part; without the intercept the two cannot be told
# apart.
BASELINE=${BASELINE:-1}
OUT_DIR=${OUT_DIR:-$(mktemp -d -t votor-endpoint-bench-XXXXXX)}

# Votor hardcodes its per-peer ingress limit. Offering more than that
# measures the token bucket shedding packets and then the flood-ban path, not
# the receive path.
SERVER_PEER_PPS=50

if ((PPS > SERVER_PEER_PPS)); then
  echo "PPS=$PPS exceeds the server's hardcoded per-peer limit of $SERVER_PEER_PPS;" >&2
fi

CLK_TCK=$(getconf CLK_TCK)

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

# The pinning above is hardcoded to one machine's topology. This will cause bench
# to issue warnings on incompatible hardware.
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

# Always rebuild.
cargo build --release -p agave-votor-transport \
  --features agave-unstable-api,dev-context-only-utils --examples

# The generator needs enough runway for connect + settle + the perf window.
WINDOWS=1
[[ ${PER_THREAD:-0} == 1 ]] && WINDOWS=2
LOADGEN_SECS=$((SETTLE_SECS + WINDOWS * PERF_SECS + 10))
# The server's own clock starts before the connect phase, which the generator's
# does not, so its budget has to cover the connect wait as well or it can exit
# from under the perf window.
CONNECT_BUDGET_SECS=60
SERVER_SECS=$((CONNECT_BUDGET_SECS + LOADGEN_SECS + 30))

mkdir -p "$OUT_DIR"
echo "results -> $OUT_DIR"

# Newest per-second sample from a bench binary's log, as "<tick> <total>". The
# binaries print monotonic totals once a second, so sampling the newest one on
# each side of the perf window bounds a whole number of ticks.
#
# Tick and total must come from the same line in one pass: reading them with two
# awk invocations races the writer, and a line landing in between yields a tick
# count one higher than the packet delta -- an exact 10/11 rate deficit that
# looks like the server shedding 9% of the load. Requiring both fields also
# makes a torn trailing line skip rather than parse as zero.
last_sample() {
  local file=$1 prefix=$2 total_field=$3
  awk -v prefix="$prefix" -v total_field="$total_field" '
    $1 == prefix {
      tick = ""
      total = ""
      for (i = 2; i <= NF; i++) {
        split($i, kv, "=")
        if (kv[1] == "t") tick = kv[2]
        else if (kv[1] == total_field) total = kv[2]
      }
      if (tick != "" && total != "") {
        last_tick = tick
        last_total = total
      }
    }
    END { print last_tick + 0, last_total + 0 }
  ' "$file"
}

# A single perf counter by event name, empty when perf did not record it.
perf_counter() {
  awk -v event="$2" '
    {
      for (i = 1; i <= NF; i++) {
        if ($i != event) continue
        gsub(/,/, "", $1)
        if ($1 ~ /^[0-9.]+$/) print $1
        exit
      }
    }
  ' "$1"
}

# Machine-wide busy and softirq jiffies. The receive stack the server does not
# get billed for still shows up here, so a machine total brackets the run even
# though it cannot be attributed.
cpu_busy_snapshot() {
  awk '$1 == "cpu" { total = 0; for (i = 2; i <= NF; i++) total += $i; print total - $5 - $6, $8; exit }' /proc/stat
}

# Populated by start_server.
SRV_PID=""
SRV_ADDR=""
SRV_PUBKEY=""
SRV_WRAPPER=""

start_server() {
  local endpoints=$1 srv_log=$2

  RUST_LOG="$BENCH_RUST_LOG" taskset -c "$SERVER_CPUS" \
    "$SERVER_BIN" \
    --num-endpoints "$endpoints" \
    --num-peers "$NUM_CLIENTS" \
    --worker-threads "$SERVER_WORKER_THREADS" \
    --run-secs "$SERVER_SECS" >"$srv_log" 2>&1 &
  SRV_WRAPPER=$!

  # Wait for the SERVER line, which carries the real pid, addr and pubkey.
  local waited=0
  while ! grep -q '^SERVER ' "$srv_log" 2>/dev/null; do
    sleep 0.1
    waited=$((waited + 1))
    if ((waited > 300)); then
      echo "server failed to start; see $srv_log" >&2
      cat "$srv_log" >&2
      kill "$SRV_WRAPPER" 2>/dev/null || true
      return 1
    fi
  done
  SRV_PUBKEY=$(awk '/^SERVER /{print $2; exit}' "$srv_log")
  SRV_ADDR=$(awk '/^SERVER /{print $3; exit}' "$srv_log")
  SRV_PID=$(awk '/^SERVER /{sub(/^pid=/, "", $4); print $4; exit}' "$srv_log")
}

stop_server() {
  kill "$SRV_PID" 2>/dev/null || true
  wait "$SRV_WRAPPER" 2>/dev/null || true
}

# Server alone, no traffic: the fixed cost of standing up `endpoints` inbound
# endpoints and idling.
run_baseline() {
  local endpoints=$1 rep=$2
  local tag="ep${endpoints}_rep${rep}"
  local srv_log="$OUT_DIR/baseline_server_$tag.log"
  local perf_log="$OUT_DIR/baseline_perf_$tag.txt"

  start_server "$endpoints" "$srv_log" || return 1
  sleep "$SETTLE_SECS"
  perf stat -p "$SRV_PID" \
    -e task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions \
    -- sleep "$PERF_SECS" 2>"$perf_log" || true
  local alive=yes
  kill -0 "$SRV_PID" 2>/dev/null || alive=no
  stop_server

  local cpu_secs ctxsw insn status
  cpu_secs=$(perf_counter "$perf_log" msec)
  ctxsw=$(perf_counter "$perf_log" context-switches)
  insn=$(perf_counter "$perf_log" instructions)
  status=ok
  [[ -z $cpu_secs ]] && status=SUSPECT_no_perf
  [[ $alive == no ]] && status=SUSPECT_server_exited

  local line
  line=$(awk -v ep="$endpoints" -v rep="$rep" -v msec="${cpu_secs:-0}" \
    -v ctxsw="${ctxsw:-0}" -v insn="${insn:-0}" -v secs="$PERF_SECS" -v status="$status" 'BEGIN {
      printf "BASELINE endpoints=%d rep=%d cpu_seconds=%.3f cpu_per_s=%.4f", ep, rep, msec / 1000, msec / 1000 / secs
      printf " ctxsw_per_s=%.0f insn_per_s=%.0f status=%s", ctxsw / secs, insn / secs, status
    }')
  printf '%s\n' "$line" | tee -a "$OUT_DIR/summary.txt"
}

run_one() {
  local endpoints=$1 rep=$2
  local tag="ep${endpoints}_rep${rep}"
  local srv_log="$OUT_DIR/server_$tag.log"
  local gen_log="$OUT_DIR/loadgen_$tag.log"
  local perf_log="$OUT_DIR/perf_$tag.txt"
  local gen_perf_log="$OUT_DIR/perf_loadgen_$tag.txt"

  start_server "$endpoints" "$srv_log" || return 1

  RUST_LOG="$BENCH_RUST_LOG" taskset -c "$LOADGEN_CPUS" \
    "$LOADGEN_BIN" \
    --server-addr "$SRV_ADDR" \
    --server-pubkey "$SRV_PUBKEY" \
    --num-clients "$NUM_CLIENTS" \
    --pps "$PPS" \
    --num-sockets "$NUM_SOCKETS" \
    --payload-bytes "$PAYLOAD_BYTES" \
    --worker-threads "$LOADGEN_WORKER_THREADS" \
    --duration-secs "$LOADGEN_SECS" >"$gen_log" 2>&1 &
  local gen_pid=$!

  local waited=0
  while ! grep -q '^CONNECTED ' "$gen_log" 2>/dev/null; do
    sleep 0.1
    waited=$((waited + 1))
    if ((waited > 10 * CONNECT_BUDGET_SECS)); then
      echo "load generator failed to connect; see $gen_log" >&2
      tail -20 "$gen_log" >&2
      kill "$gen_pid" 2>/dev/null || true
      stop_server
      return 1
    fi
  done

  sleep "$SETTLE_SECS"

  # Bracket the window with the newest per-second totals from both sides. The
  # tick counters come from the same lines, so packets and elapsed ticks are
  # always consistent with each other and the derived rate is unaffected by
  # where the window edges fall between prints.
  local tick_before rx_before gen_tick_before tx_before machine_before
  read -r tick_before rx_before < <(last_sample "$srv_log" STAT rx_total)
  read -r gen_tick_before tx_before < <(last_sample "$gen_log" TX tx_total)
  machine_before=$(cpu_busy_snapshot)

  perf stat -p "$SRV_PID" \
    -e task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions \
    -- sleep "$PERF_SECS" 2>"$perf_log" &
  local perf_srv=$!
  # The generator's own CPU is where loopback bills the receive stack, so it is
  # part of the measurement rather than a diagnostic.
  perf stat -p "$gen_pid" -e task-clock,context-switches \
    -- sleep "$PERF_SECS" 2>"$gen_perf_log" &
  local perf_gen=$!
  wait "$perf_srv" || true
  wait "$perf_gen" || true

  local machine_after tick_after rx_after gen_tick_after tx_after
  machine_after=$(cpu_busy_snapshot)
  read -r tick_after rx_after < <(last_sample "$srv_log" STAT rx_total)
  read -r gen_tick_after tx_after < <(last_sample "$gen_log" TX tx_total)

  local alive=yes
  kill -0 "$SRV_PID" 2>/dev/null || alive=no

  # Optional second window: where the CPU time lands across threads. Kept
  # separate because perf cannot report aggregate and per-thread at once.
  if [[ ${PER_THREAD:-0} == 1 ]]; then
    perf stat --per-thread -p "$SRV_PID" -e task-clock \
      -- sleep "$PERF_SECS" 2>"$OUT_DIR/perthread_$tag.txt" || true
  fi

  kill "$gen_pid" 2>/dev/null || true
  wait "$gen_pid" 2>/dev/null || true
  stop_server

  # Slowest full second inside the window, which catches a dip that the window
  # average would smooth over.
  local rx_min
  rx_min=$(awk -v lo="$tick_before" -v hi="$tick_after" '
    $1 == "STAT" {
      tick = ""; rate = ""
      for (i = 2; i <= NF; i++) {
        split($i, kv, "=")
        if (kv[1] == "t") tick = kv[2]
        else if (kv[1] == "rx_per_s") rate = kv[2]
      }
      if (tick != "" && rate != "" && tick > lo && tick <= hi && (min == "" || rate < min)) min = rate
    }
    END { print (min == "" ? 0 : min) }
  ' "$srv_log")

  # The generator reports only its first send failure, which is enough to know
  # the offered load stopped being what was asked for.
  local send_errors=no
  grep -q '^SEND_ERROR' "$gen_log" && send_errors=yes

  local cpu_msec ctxsw cycles insn migrations gen_cpu_msec gen_ctxsw
  cpu_msec=$(perf_counter "$perf_log" msec)
  ctxsw=$(perf_counter "$perf_log" context-switches)
  cycles=$(perf_counter "$perf_log" cycles)
  insn=$(perf_counter "$perf_log" instructions)
  migrations=$(perf_counter "$perf_log" cpu-migrations)
  gen_cpu_msec=$(perf_counter "$gen_perf_log" msec)
  gen_ctxsw=$(perf_counter "$gen_perf_log" context-switches)

  local line
  line=$(awk \
    -v ep="$endpoints" -v rep="$rep" \
    -v rx_delta="$((rx_after - rx_before))" -v ticks="$((tick_after - tick_before))" \
    -v tx_delta="$((tx_after - tx_before))" -v gen_ticks="$((gen_tick_after - gen_tick_before))" \
    -v secs="$PERF_SECS" -v nominal="$((NUM_CLIENTS * PPS))" \
    -v cpu_msec="${cpu_msec:-}" -v ctxsw="${ctxsw:-0}" -v cycles="${cycles:-0}" \
    -v insn="${insn:-0}" -v migrations="${migrations:-0}" \
    -v gen_cpu_msec="${gen_cpu_msec:-}" -v gen_ctxsw="${gen_ctxsw:-0}" \
    -v machine_before="$machine_before" -v machine_after="$machine_after" \
    -v clk_tck="$CLK_TCK" -v alive="$alive" -v send_errors="$send_errors" \
    -v rx_min="$rx_min" '
    function per_pkt(total) { return pkts > 0 ? total / pkts : 0 }
    BEGIN {
      split(machine_before, mb, " ")
      split(machine_after, ma, " ")
      machine_cpu = (ma[1] - mb[1]) / clk_tck
      softirq_cpu = (ma[2] - mb[2]) / clk_tck

      # Steady-state rates over a whole number of ticks, scaled to the window.
      rx_per_s = ticks > 0 ? rx_delta / ticks : 0
      tx_per_s = gen_ticks > 0 ? tx_delta / gen_ticks : 0
      pkts = rx_per_s * secs
      offered = tx_per_s * secs

      cpu = cpu_msec / 1000
      gen_cpu = gen_cpu_msec / 1000

      printf "RESULT endpoints=%d rep=%d pkts=%.0f offered=%.0f rx_per_s=%.0f", ep, rep, pkts, offered, rx_per_s
      printf " cpu_seconds=%.3f cpus_busy=%.3f", cpu, cpu / secs
      printf " ns_per_pkt=%.1f insn_per_pkt=%.1f cycles_per_pkt=%.1f", per_pkt(cpu * 1e9), per_pkt(insn), per_pkt(cycles)
      printf " ipc=%.2f ctxsw_per_pkt=%.4f migrations=%d", (cycles > 0 ? insn / cycles : 0), per_pkt(ctxsw), migrations
      printf " gen_cpu_seconds=%.3f gen_ns_per_pkt=%.1f gen_ctxsw_per_pkt=%.4f", gen_cpu, per_pkt(gen_cpu * 1e9), per_pkt(gen_ctxsw)
      printf " machine_cpu_seconds=%.3f softirq_seconds=%.3f", machine_cpu, softirq_cpu
      printf " min_rx_per_s=%d", rx_min

      status = "ok"
      if (cpu_msec == "" || gen_cpu_msec == "") status = "SUSPECT_no_perf"
      else if (alive == "no") status = "SUSPECT_server_exited"
      else if (send_errors == "yes") status = "SUSPECT_send_errors"
      else if (offered < nominal * 0.98) status = "SUSPECT_generator_sag"
      else if (pkts < offered * 0.98) status = "SUSPECT_server_dropping"
      printf " status=%s", status
    }')
  printf '%s\n' "$line" | tee -a "$OUT_DIR/summary.txt"
}

for rep in $(seq 1 "$REPEATS"); do
  for endpoints in $ENDPOINT_COUNTS; do
    if [[ $BASELINE == 1 ]]; then
      run_baseline "$endpoints" "$rep"
      sleep 2
    fi
    run_one "$endpoints" "$rep"
    sleep 2
  done
done

echo
echo "=== summary (perf window: ${PERF_SECS}s, ${NUM_CLIENTS} clients x ${PPS} pps," \
  "${NUM_SOCKETS} source ports) ==="
cat "$OUT_DIR/summary.txt"
