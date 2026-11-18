#!/usr/bin/env bash
# scripts/process_pcap.sh
# ==============================================================================
# Helper script executed by tcpdump's -z flag after rotating a PCAP file.
# Processes the rotated PCAP with CICFlowMeter to generate 52-feature flow statistics.
# ==============================================================================

set -euo pipefail

PCAP_FILE="$1"
OUTPUT_DIR="/home/ashraf/nids_r1_2_3/data/cicflow_csv"
PYTHON_BIN="/home/ashraf/nids_r1_2_3/.venv/bin/python"
PROCESS_SCRIPT="/home/ashraf/nids_r1_2_3/scripts/pcap_to_flow.py"

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
