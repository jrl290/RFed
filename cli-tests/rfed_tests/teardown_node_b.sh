#!/usr/bin/env bash
# teardown_node_b.sh — Stop rfed Node B.

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_BASE="${RFED_TEST_RUN_DIR:-$TEST_DIR}"
PID_DIR="$RUN_BASE/.pids"
DATA_B="$RUN_BASE/rfed_data_b"

if [ -f "$PID_DIR/rfed_b.pid" ]; then
  pid=$(cat "$PID_DIR/rfed_b.pid")
  if kill -0 "$pid" 2>/dev/null; then
    echo "[teardown-b] stopping Node B (pid $pid)..."
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  else
    echo "[teardown-b] Node B (pid $pid) already stopped"
  fi
  rm -f "$PID_DIR/rfed_b.pid"
else
  echo "[teardown-b] no pidfile for Node B"
fi

pkill -f "rfed.*$DATA_B" 2>/dev/null && echo "[teardown-b] killed stray Node B" || true
echo "[teardown-b] done"
