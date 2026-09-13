#!/usr/bin/env bash
# scripts/process_pcap.sh
# ==============================================================================
# Helper script executed by tcpdump's -z flag after rotating a PCAP file.
# Processes the rotated PCAP with CICFlowMeter to generate 52-feature flow statistics.
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP_FILE="$1"
OUTPUT_DIR="$ROOT_DIR/data/cicflow_csv"
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
PROCESS_SCRIPT="$ROOT_DIR/scripts/pcap_to_flow.py"

echo "Processing rotated PCAP: $PCAP_FILE"
mkdir -p "$OUTPUT_DIR"

# Run Python flow generator on the rotated PCAP file
BASENAME=$(basename "$PCAP_FILE")
OUT_CSV="$OUTPUT_DIR/${BASENAME%.pcap}_flows.csv"
if "$PYTHON_BIN" "$PROCESS_SCRIPT" "$PCAP_FILE" "$OUT_CSV" >/dev/null 2>&1; then
    echo "Successfully generated flow CSV for $PCAP_FILE"
    # Ensure generated CSV is readable by the pipeline user
    chmod 644 "$OUTPUT_DIR"/*.csv 2>/dev/null || true
else
    echo "Python flow generator failed to process $PCAP_FILE"
fi
