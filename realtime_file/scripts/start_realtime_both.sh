#!/usr/bin/env bash
# scripts/start_realtime_both.sh
# ==============================================================================
# Cleanly resets all previous live/eval artifacts and starts BOTH live NIDS
# approaches simultaneously without requiring sudo (uses dumpcap via wireshark
# group + Suricata continuous pcap mode):
#   - Approach A : nids_web.py (port 5000) — dumpcap -> NFStream -> R1 + SHAP + R3
#   - Approach B : Suricata + live_b_worker.py + main_unified.py (20s windows)
#                  + app.py SOC dashboard (port 5001)
# ==============================================================================

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IFACE="${IFACE:-wlp0s20f3}"
OLLAMA_URL="${OLLAMA_URL:-https://presenting-characteristics-kathy-anybody.trycloudflare.com}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5:1.5b}"
PKL="${PKL:-universal_nids_output.pkl}"
PY="$ROOT_DIR/.venv/bin/python"

echo "════════════════════════════════════════════════════════════════════"
echo "  🛡️  Starting Full Real-Time NIDS (Approach A + Approach B)"
echo "════════════════════════════════════════════════════════════════════"
echo "  Interface : $IFACE"
echo "  Ollama    : $OLLAMA_URL ($OLLAMA_MODEL)"
echo "  Model PKL : $PKL"
echo "════════════════════════════════════════════════════════════════════"

# 1. Stop any leftover user-owned live pipeline processes
for pat in "nids_web.py" "main_unified.py" "live_b_worker.py" "app.py" "dumpcap -i $IFACE" "suricata -c /etc/suricata/suricata.yaml -r"; do
    pkill -f "$pat" 2>/dev/null || true
done
sleep 1

# 2. Remove ALL previous data so this run is completely clean
echo "-- Cleaning all previous run data --"
rm -f "$ROOT_DIR/nids_history.json" "$ROOT_DIR/nids_history.json.tmp"
rm -rf "$ROOT_DIR/data/cicflow_csv"/* \
       "$ROOT_DIR/data/results"/* \
       "$ROOT_DIR/data/chunks"/* \
       "$ROOT_DIR/data/live_b" \
       "$ROOT_DIR/data/runs"/* \
       "$ROOT_DIR/logs"/*.log \
       "$ROOT_DIR/logs/pids.env" \
       /tmp/test_nids.pcap /tmp/test_cic.csv /tmp/test_fifo* /tmp/test_nw.log /tmp/test_run_verify 2>/dev/null || true

mkdir -p "$ROOT_DIR/data/cicflow_csv" \
         "$ROOT_DIR/data/results/eval" \
         "$ROOT_DIR/data/chunks" \
         "$ROOT_DIR/data/live_b/raw_5s" \
         "$ROOT_DIR/data/live_b/suri_in" \
         "$ROOT_DIR/data/live_b/suricata_logs" \
         "$ROOT_DIR/data/runs" \
         "$ROOT_DIR/logs"

: > "$ROOT_DIR/data/results/unified_alerts.jsonl"
: > "$ROOT_DIR/data/live_b/suricata_logs/eve.json"
: > "$ROOT_DIR/data/live_b/suricata_logs/fast.log"
echo "  ✓ Previous state wiped cleanly"

# 3. Pre-warm remote Ollama GPU so first live flows hit warm VRAM
echo "-- Checking & warming remote Ollama ($OLLAMA_URL) --"
if ! curl -sf --max-time 15 "$OLLAMA_URL/api/tags" >/dev/null; then
    echo "❌ Ollama unreachable at $OLLAMA_URL"
    exit 1
fi
curl -sf --max-time 60 "$OLLAMA_URL/api/generate" \
    -d "{\"model\":\"$OLLAMA_MODEL\",\"prompt\":\"Reply {\\\"ok\\\":true}\",\"stream\":false,\"format\":\"json\",\"keep_alive\":\"1h\"}" \
    >/dev/null || true
echo "  ✓ Ollama warm and ready"

# 4. Start Suricata in continuous pcap directory mode (Approach B)
echo "-- Starting Suricata (continuous PCAP mode, user-space) --"
nohup suricata -c /etc/suricata/suricata.yaml \
    -r "$ROOT_DIR/data/live_b/suri_in" \
    --pcap-file-continuous --pcap-file-delete \
    -l "$ROOT_DIR/data/live_b/suricata_logs" \
    --set unix-command.enabled=no \
    > "$ROOT_DIR/logs/suricata_stdout.log" 2>&1 &
SURI_PID=$!

for i in $(seq 1 55); do
    if grep -q "Engine started" "$ROOT_DIR/data/live_b/suricata_logs/suricata.log" 2>/dev/null; then
        echo "  ✓ Suricata ready after ${i}s (PID $SURI_PID)"
        break
    fi
    if ! kill -0 "$SURI_PID" 2>/dev/null; then
        echo "❌ Suricata exited early. Check logs/suricata_stdout.log"
        exit 1
    fi
    sleep 1
done

# 5. Start Approach B PCAP->Suricata/CICFlowMeter worker
nohup "$PY" -u "$ROOT_DIR/scripts/live_b_worker.py" \
    --mirror-dir "$ROOT_DIR/data/live_b/raw_5s" \
    --suri-in "$ROOT_DIR/data/live_b/suri_in" \
    --csv-dir "$ROOT_DIR/data/cicflow_csv" \
    --batch-chunks 4 --batch-seconds 20 \
    > "$ROOT_DIR/logs/live_b_worker.log" 2>&1 &
WORKER_PID=$!
echo "  ✓ live_b_worker started (PID $WORKER_PID)"

# 6. Start Approach B main_unified.py --mode live
nohup "$PY" -u "$ROOT_DIR/main_unified.py" \
    --mode live \
    --config "$ROOT_DIR/config/settings_live.yaml" \
    --nids_pkl "$ROOT_DIR/$PKL" \
    --cicflow_csv "$ROOT_DIR/data/cicflow_csv/" \
    --dataset CICIDS2017 \
    --ollama_url "$OLLAMA_URL" \
    --ollama_model "$OLLAMA_MODEL" \
    --window_seconds 20 \
    > "$ROOT_DIR/logs/main_unified_live.log" 2>&1 &
UNIFIED_PID=$!
echo "  ✓ main_unified.py (Approach B) starting (PID $UNIFIED_PID)"

# 7. Start Approach B SOC dashboard (app.py on port 5001)
PORT=5001 nohup "$PY" -u "$ROOT_DIR/app.py" \
    > "$ROOT_DIR/logs/app_5001.log" 2>&1 &
APP_PID=$!
echo "  ✓ app.py dashboard starting on http://localhost:5001 (PID $APP_PID)"

# 8. Start Approach A (nids_web.py on port 5000, dumpcap backend mirroring 5s chunks to Approach B)
nohup "$PY" -u "$ROOT_DIR/nids_web.py" \
    --iface "$IFACE" \
    --pkl "$ROOT_DIR/$PKL" \
    --ollama-url "$OLLAMA_URL" \
    --ollama-model "$OLLAMA_MODEL" \
    --port 5000 \
    --fresh \
    --shap-mode xgb \
    --capture-backend dumpcap \
    --rotate-sec 5 \
    --mirror-dir "$ROOT_DIR/data/live_b/raw_5s" \
    --exclude "port 5001" \
    > "$ROOT_DIR/logs/nids_web_5000.log" 2>&1 &
NIDS_PID=$!
echo "  ✓ nids_web.py (Approach A) starting on http://localhost:5000 (PID $NIDS_PID)"

cat > "$ROOT_DIR/logs/pids.env" <<EOF
SURI_PID=$SURI_PID
WORKER_PID=$WORKER_PID
UNIFIED_PID=$UNIFIED_PID
APP_PID=$APP_PID
NIDS_PID=$NIDS_PID
EOF

# Wait for Approach A & B web dashboards + model load
for i in $(seq 1 35); do
    if curl -sf http://localhost:5000/api/stats >/dev/null 2>&1 && curl -sf http://localhost:5001/data >/dev/null 2>&1; then
        echo "  ✓ Both dashboards live after ${i}s"
        break
    fi
    sleep 1
done

echo
echo "════════════════════════════════════════════════════════════════════"
echo "  ALL SERVICES RUNNING"
echo "  Approach A UI : http://localhost:5000"
echo "  Approach B UI : http://localhost:5001"
echo "  Active Run    : $(cat "$ROOT_DIR/data/runs/latest_run.txt" 2>/dev/null || echo pending)"
echo "════════════════════════════════════════════════════════════════════"
