#!/usr/bin/env bash
#
# Relax host permissions so an unprivileged agave-validator built with the
# `tracy` feature can collect sampling, context switch and kernel callstack
# data. Changes are not persistent and are undone by a reboot or `--revert`.
#
# Usage: sudo ./scripts/tracy-host-setup.sh [--revert]
#

set -e

STATE_FILE=/run/agave-tracy-setup.prev
TRACEFS=/sys/kernel/tracing
SYSCTLS=(
  # perf events (incl. tracepoints) for unprivileged processes
  "kernel.perf_event_paranoid=-1"
  # kernel symbol addresses in sampled callstacks
  "kernel.kptr_restrict=0"
)
# Tracy reads the sched tracepoint ids to set up context switch tracing
TRACEFS_DIRS=(
  "$TRACEFS"
  "$TRACEFS/events"
  "$TRACEFS/events/sched"
  "$TRACEFS/events/sched/sched_switch"
  "$TRACEFS/events/sched/sched_waking"
)
TRACEFS_FILES=(
  "$TRACEFS/events/sched/sched_switch/id"
  "$TRACEFS/events/sched/sched_waking/id"
)

usage() {
  echo "Usage: sudo $0 [--revert]"
  exit 1
}

if [[ $EUID -ne 0 ]]; then
  echo "Error: must be run as root"
  usage
fi

if [[ $(uname) != Linux ]]; then
  echo "Error: Linux only"
  exit 1
fi

revert() {
  if [[ ! -f $STATE_FILE ]]; then
    echo "Error: $STATE_FILE not found, nothing to revert"
    exit 1
  fi
  while read -r kind value target; do
    case $kind in
      sysctl)
        sysctl -w "$target=$value"
        ;;
      mode)
        chmod "$value" "$target"
        echo "chmod $value $target"
        ;;
    esac
  done <"$STATE_FILE"
  rm "$STATE_FILE"
}

setup() {
  if [[ -f $STATE_FILE ]]; then
    echo "Error: $STATE_FILE exists, setup already applied. Run with --revert first"
    exit 1
  fi

  if ! mountpoint -q "$TRACEFS"; then
    mount -t tracefs nodev "$TRACEFS"
    echo "mounted tracefs at $TRACEFS"
  fi

  local state=()
  for kv in "${SYSCTLS[@]}"; do
    local key=${kv%%=*}
    state+=("sysctl $(sysctl -n "$key") $key")
  done
  for path in "${TRACEFS_DIRS[@]}" "${TRACEFS_FILES[@]}"; do
    state+=("mode $(stat -c %a "$path") $path")
  done
  printf '%s\n' "${state[@]}" >"$STATE_FILE"

  for kv in "${SYSCTLS[@]}"; do
    sysctl -w "$kv"
  done
  for dir in "${TRACEFS_DIRS[@]}"; do
    chmod a+rx "$dir"
    echo "chmod a+rx $dir"
  done
  for file in "${TRACEFS_FILES[@]}"; do
    chmod a+r "$file"
    echo "chmod a+r $file"
  done
  echo "Previous values saved to $STATE_FILE, undo with: sudo $0 --revert"
}

case $1 in
  "")
    setup
    ;;
  --revert)
    revert
    ;;
  *)
    usage
    ;;
esac
