#!/usr/bin/env bash
# scripts/flow_processor.sh
# ==============================================================================
# NIDS Background Flow Processor Daemon.
# Monitors data/raw_pcap/ for completed (rotated) PCAP files, processes them
# with CICFlowMeter, and moves them to data/raw_pcap/processed/.
#
# Bypasses AppArmor limitations on tcpdump -z execution.
# ==============================================================================

set -uo pipefail

PCAP_DIR="/tmp/raw_pcap"
OUTPUT_DIR="/home/ashraf/nids_r1_2_3/data/cicflow_csv"
JAR="/home/ashraf/nids_r1_2_3/tools/CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
PROCESSED_DIR="$PCAP_DIR/processed"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$PROCESSED_DIR"

# Use Java 11 (recommended for JNI/native library compatibility)
JAVA_CMD="/usr/lib/jvm/java-11-openjdk-amd64/bin/java"
if [ ! -x "$JAVA_CMD" ]; then
    JAVA_CMD="java"
fi

echo "=================================================="
echo "  NIDS Flow Processor Daemon Started"
echo "  Monitoring: $PCAP_DIR/"
echo "  Output CSV: $OUTPUT_DIR/"
echo "  Processed : $PROCESSED_DIR/"
echo "=================================================="

while true; do
    # Find all pcap files in raw_pcap
    mapfile -t PCAPS < <(find "$PCAP_DIR" -maxdepth 1 -name "*.pcap" -type f 2>/dev/null | sort)
    
    for PCAP in "${PCAPS[@]}"; do
        BASENAME=$(basename "$PCAP")
        
        # Ignore capture.pcap and live_capture.pcap (current active tcpdump file name)
        if [ "$BASENAME" = "live_capture.pcap" ] || [ "$BASENAME" = "capture.pcap" ]; then
            continue
        fi
        
        # Check if the file is still being written to (modified within the last 5 seconds)
        MOD_TIME=$(stat -c %Y "$PCAP")
        NOW=$(date +%s)
        DIFF=$((NOW - MOD_TIME))
        if [ "$DIFF" -lt 5 ]; then
            # File is still active, wait until tcpdump finishes rotating it
            continue
        fi
        
        # Verify if another daemon run has already processed/moved this file
        if [ ! -f "$PCAP" ]; then
            continue
        fi

        echo "Found rotated PCAP: $BASENAME"
        echo "  -> Running CICFlowMeter..."
        
        # Copy to a temporary location to bypass AppArmor ownership limitations
        # Append process ID ($$) to ensure unique filename under concurrency, keeping the .pcap extension
        TEMP_PCAP="/tmp/flow_proc_${BASENAME%.pcap}_$$.pcap"
        if cp "$PCAP" "$TEMP_PCAP" 2>/dev/null; then
            chmod 644 "$TEMP_PCAP" 2>/dev/null || true

            # Run Python flow generator on the rotated PCAP file copy
            OUT_CSV="$OUTPUT_DIR/${BASENAME%.pcap}_flows.csv"
            ERR_LOG=$(mktemp)
            if /home/ashraf/nids_r1_2_3/.venv/bin/python /home/ashraf/nids_r1_2_3/scripts/pcap_to_flow.py "$TEMP_PCAP" "$OUT_CSV" >"$ERR_LOG" 2>&1; then
                rm -f "$TEMP_PCAP" "$ERR_LOG"
                # Move to processed directory to avoid re-processing
                if [ -f "$PCAP" ]; then
                    mv "$PCAP" "$PROCESSED_DIR/" 2>/dev/null || true
                fi
                echo "  ✓ Successfully generated flow CSV for $BASENAME"
                
                # Ensure generated CSV is readable by pipeline
                chmod 644 "$OUTPUT_DIR"/*.csv 2>/dev/null || true
            else
                rm -f "$TEMP_PCAP"
                echo "  ❌ Python flow generator failed to process $BASENAME"
                echo "  Error details:"
                cat "$ERR_LOG" | sed 's/^/    /'
                rm -f "$ERR_LOG"
                # Move to processed/failed directory to avoid locking
                if [ -f "$PCAP" ]; then
                    mv "$PCAP" "$PROCESSED_DIR/${BASENAME}.failed" 2>/dev/null || true
                fi
            fi
        else
            echo "  ⚠️ File already moved or processed by a concurrent daemon run."
            rm -f "$TEMP_PCAP" 2>/dev/null || true
        fi
        echo "--------------------------------------------------"
    done
    sleep 3
done
