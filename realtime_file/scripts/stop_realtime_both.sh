#!/usr/bin/env bash
# scripts/stop_realtime_both.sh
# ==============================================================================
# Gracefully stops the live NIDS pipelines, flushes logs, merges captured raw
# PCAP chunks, and generates all evaluation / journal-ready reports.
# ==============================================================================

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
PY="$ROOT_DIR/.venv/bin/python"

if [ "${1:-}" = "--drain" ]; then
    shift
    exec "$PY" "$ROOT_DIR/scripts/stop_and_drain.py" "$@"
fi

pkill -TERM -f "live_supervisor.py" 2>/dev/null || true
sleep 3
pkill -KILL -f "live_supervisor.py" 2>/dev/null || true
if [ -f "$ROOT_DIR/logs/pids.env" ]; then
    # shellcheck disable=SC1091
    source "$ROOT_DIR/logs/pids.env"
    for pid in "${NIDS_PID:-}" "${APP_PID:-}" "${UNIFIED_PID:-}" "${WORKER_PID:-}" "${SURI_PID:-}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    sleep 3
    for pid in "${NIDS_PID:-}" "${APP_PID:-}" "${UNIFIED_PID:-}" "${WORKER_PID:-}" "${SURI_PID:-}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
fi

RUN_DIR="$(cat "$ROOT_DIR/data/runs/latest_run.txt" 2>/dev/null || true)"
ATTACKER_ARG=""
if [ -n "${1:-}" ]; then
    ATTACKER_ARG="--attacker-ip $1"
fi

if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
    echo "Generating full journal report for $RUN_DIR ..."
    "$PY" "$ROOT_DIR/scripts/analyze_live_run.py" \
        --run-dir "$RUN_DIR" \
        --merge-pcap \
        $ATTACKER_ARG
fi

"$PY" "$ROOT_DIR/evaluate_nids.py" prompt-dump >/dev/null 2>&1 || true
"$PY" "$ROOT_DIR/scripts/summarize_live_test.py" \
    --suricata-fast-log "$ROOT_DIR/data/live_b/suricata_logs/fast.log" \
    >/dev/null 2>&1 || true

echo "✓ Stopped and reports generated in ${RUN_DIR:-data/results/}"
