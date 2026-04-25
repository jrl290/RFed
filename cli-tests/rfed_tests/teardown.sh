#!/usr/bin/env bash
# teardown.sh — Stop rfed test process.

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_BASE="${RFED_TEST_RUN_DIR:-$TEST_DIR}"
PID_DIR="$RUN_BASE/.pids"

stop_pid() {
  local name="$1"
  local pidfile="$PID_DIR/$name.pid"
  if [ -f "$pidfile" ]; then
    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      echo "[teardown] stopping $name (pid $pid)..."
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    else
      echo "[teardown] $name (pid $pid) already stopped"
    fi
    rm -f "$pidfile"
  else
    echo "[teardown] no pidfile for $name"
  fi
}

stop_pid rfed
stop_pid rnsd_backbone
stop_pid netem_proxy

# Belt-and-suspenders: kill by matching cmdline in case pidfiles are stale/wrong.
pkill -f "rfed.*rfed_tests" 2>/dev/null && echo "[teardown] killed stray rfed" || true
pkill -f "RNS/Utilities/rnsd.py.*rnsd_backbone" 2>/dev/null && echo "[teardown] killed stray backbone rnsd" || true
pkill -f "netem_proxy.py" 2>/dev/null && echo "[teardown] killed stray netem proxy" || true

echo "[teardown] done"
