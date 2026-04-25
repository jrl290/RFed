#!/usr/bin/env bash
# teardown_backup_nodes.sh — Stop backup-test rfed nodes.

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_BASE="${RFED_TEST_RUN_DIR:-$TEST_DIR}"
PID_DIR="$RUN_BASE/.pids"
DATA_BP="$RUN_BASE/rfed_data_backup_primary"
DATA_BN="$RUN_BASE/rfed_data_backup_node"

for NAME in rfed_backup_node rfed_backup_primary; do
  PIDFILE="$PID_DIR/${NAME}.pid"
  if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
    kill "$PID" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "[teardown-backup] stopped $NAME (pid $PID)"
  fi
done

pkill -f "rfed.*$DATA_BP" 2>/dev/null || true
pkill -f "rfed.*$DATA_BN" 2>/dev/null || true
sleep 0.5
