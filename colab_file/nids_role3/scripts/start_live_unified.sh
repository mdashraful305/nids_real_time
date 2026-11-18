#!/usr/bin/env bash
# scripts/start_live_unified.sh
# ==============================================================================
# Master Launcher for Live Time-Windowed NIDS Pipeline (main_unified.py + app.py)
# ==============================================================================

set -e

PROJECT_DIR="/home/ashraf/nids_r1_2_3"
cd "$PROJECT_DIR"

echo "=================================================="
echo "  🛡️  Starting Live Time-Windowed NIDS Pipeline"
echo "=================================================="

# 1. Ensure required directories exist
mkdir -p /tmp/raw_pcap /tmp/raw_pcap/processed data/cicflow_csv data/results logs

# 2. Check Python virtual environment
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment .venv not found in $PROJECT_DIR"
    exit 1
fi
source .venv/bin/activate

# 3. Check Ollama server
if ! curl -s http://localhost:11434/api/tags >/dev/null; then
    echo "❌ Ollama service is not reachable on http://localhost:11434"
    echo "   Please start it in another terminal: ollama serve"
    exit 1
fi
echo "✓ Ollama server is active"

# 4. Check model file
if [ ! -f "universal_nids_output.pkl" ]; then
    echo "❌ Model file universal_nids_output.pkl not found!"
    exit 1
fi
echo "✓ universal_nids_output.pkl found"

# Cleanup function on Ctrl+C or exit
cleanup() {
    echo -e "\nShutting down background processes..."
    kill $(jobs -p) 2>/dev/null || true
    echo "✓ Stopped."
}
trap cleanup EXIT INT TERM

# 5. Start tcpdump in background (needs sudo)
echo "Starting tcpdump packet capture on /tmp/raw_pcap/ (rotates every 60s)..."
sudo tcpdump -i any -Z root -w /tmp/raw_pcap/live_capture_%Y%m%d%H%M%S.pcap -G 60 >/dev/null 2>&1 &
TCPDUMP_PID=$!
echo "✓ tcpdump running (PID: $TCPDUMP_PID)"

# 6. Start flow processor daemon in background
echo "Starting Flow Processor Daemon..."
bash scripts/flow_processor.sh >/dev/null 2>&1 &
FLOW_PROC_PID=$!
echo "✓ flow_processor running (PID: $FLOW_PROC_PID)"

# 7. Start SOC Web Dashboard (app.py) in background
echo "Starting SOC Web Dashboard (app.py) on http://localhost:5000..."
python app.py >logs/app_web.log 2>&1 &
APP_PID=$!
echo "✓ app.py running (PID: $APP_PID)"

sleep 2

# 8. Start main_unified.py in foreground
echo "Starting Live Unified Pipeline (main_unified.py)..."
echo "Press Ctrl+C to stop all services."
echo "=================================================="

python main_unified.py --mode live --nids_pkl universal_nids_output.pkl --cicflow_csv data/cicflow_csv/
