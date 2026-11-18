#!/usr/bin/env bash
# scripts/launch_approach_a.sh
# ==============================================================================
# One-shot launcher for Approach A (nids_web.py) — the standalone live NIDS
# dashboard. Handles sudo, self-exclusion BPF, and all preflight checks.
#
# Usage:
#   bash scripts/launch_approach_a.sh
#   bash scripts/launch_approach_a.sh --iface eth0  # override interface
# ==============================================================================

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IFACE="${1:-wlp0s20f3}"
[[ "$IFACE" == "--iface" ]] && IFACE="${2:-wlp0s20f3}"

echo "══════════════════════════════════════════════════════"
echo "  🛡️  NIDS Live Dashboard — Approach A"
echo "══════════════════════════════════════════════════════"
echo "  Interface : $IFACE"
echo "  Model     : universal_nids_output.pkl"
echo "  Ollama    : http://localhost:11434 (qwen2.5:1.5b)"
echo "  Dashboard : http://localhost:5000"
echo "══════════════════════════════════════════════════════"
echo

# Preflight checks
source .venv/bin/activate

if [ ! -f "universal_nids_output.pkl" ]; then
    echo "❌ Model file universal_nids_output.pkl not found!"
    exit 1
fi
echo "✓ Model file found"

if ! curl -s --max-time 3 http://localhost:11434/api/tags > /dev/null; then
    echo "❌ Ollama not reachable. Start it with: ollama serve &"
    exit 1
fi
echo "✓ Ollama reachable"

# Clean previous state
rm -f nids_history.json
mkdir -p data/results data/cicflow_csv
echo "✓ Previous state cleared"
echo

# Fix ownership of data dirs (may have been created by previous sudo runs)
echo "Fixing data directory ownership..."
sudo chown -R "$(id -u):$(id -g)" data/ 2>/dev/null || true
echo "✓ Ownership fixed"
echo

echo "Starting nids_web.py with sudo (you may be prompted for password)..."
echo "  Press Ctrl+C to stop"
echo

# Fix ownership first (the sudo prompt covers both operations)
sudo chown -R "$(id -u):$(id -g)" "$ROOT_DIR/data/" 2>/dev/null || true

sudo "$ROOT_DIR/.venv/bin/python" "$ROOT_DIR/nids_web.py" \
  --iface "$IFACE" \
  --pkl universal_nids_output.pkl \
  --ollama-url http://localhost:11434 \
  --ollama-model qwen2.5:1.5b
