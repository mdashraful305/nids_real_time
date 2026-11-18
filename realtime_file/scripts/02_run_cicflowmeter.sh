#!/usr/bin/env bash
# scripts/02_run_cicflowmeter.sh
# ================================
# Run CICFlowMeter on all pcap files in data/raw_pcap/
# to generate 52-feature CSV files in data/cicflow_csv/
#
# Usage:
#   bash scripts/02_run_cicflowmeter.sh
#   bash scripts/02_run_cicflowmeter.sh data/raw_pcap/Monday-WorkingHours.pcap
#
# Prerequisites:
#   - Java 11+  (java -version)
#   - CICFlowMeter JAR in /opt/CICFlowMeter/ or set CICFLOW_JAR env var
#   - Download: https://github.com/ahlashkari/CICFlowMeter/releases

set -euo pipefail

PCAP_DIR="data/raw_pcap"
OUTPUT_DIR="data/cicflow_csv"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  NIDS Role 3 — Step 2: pcap → CICFlowMeter CSV  ${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}\n"

# ── find CICFlowMeter JAR ─────────────────────────────────────────────────────
if [ -n "${CICFLOW_JAR:-}" ]; then
    JAR="$CICFLOW_JAR"
elif [ -f "/opt/CICFlowMeter/CICFlowMeter.jar" ]; then
    JAR="/opt/CICFlowMeter/CICFlowMeter.jar"
elif [ -f "$(dirname "$0")/../tools/CICFlowMeter.jar" ]; then
    JAR="$(dirname "$0")/../tools/CICFlowMeter.jar"
else
    echo -e "${RED}❌ CICFlowMeter.jar not found.${NC}"
    echo ""
    echo "  Option 1 — set env var:"
    echo "    export CICFLOW_JAR=/path/to/CICFlowMeter.jar"
    echo ""
    echo "  Option 2 — place JAR at:"
    echo "    /opt/CICFlowMeter/CICFlowMeter.jar"
    echo ""
    echo "  Download: https://github.com/ahlashkari/CICFlowMeter/releases"
    echo ""
    echo "  Alternative — use CICFlowMeter Docker image:"
    echo "    docker run --rm -v \$(pwd)/data:/data \\
        seclab/cicflowmeter:latest \\
        /data/raw_pcap/Monday-WorkingHours.pcap \\
        /data/cicflow_csv/"
    exit 1
fi

# ── check Java ────────────────────────────────────────────────────────────────
if ! command -v java &>/dev/null; then
    echo -e "${RED}❌ Java not found. Install Java 11+:${NC}"
    echo "   sudo apt install openjdk-11-jdk"
    exit 1
fi

JAVA_VER=$(java -version 2>&1 | head -1)
echo -e "  Java       : ${GREEN}$JAVA_VER${NC}"
echo -e "  CICFlowMeter JAR : $JAR\n"

# ── find pcap files ───────────────────────────────────────────────────────────
if [ $# -ge 1 ]; then
    PCAP_FILES=("$1")
else
    mapfile -t PCAP_FILES < <(find "$PCAP_DIR" -name "*.pcap" -o -name "*.pcapng" 2>/dev/null | sort)
fi

if [ ${#PCAP_FILES[@]} -eq 0 ]; then
    echo -e "${RED}❌ No pcap files found in $PCAP_DIR${NC}"
    echo "   Run scripts/01_replay_pcap.sh first, or place pcap files in $PCAP_DIR/"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
PROCESSED=0; FAILED=0

for PCAP in "${PCAP_FILES[@]}"; do
    BASENAME=$(basename "$PCAP" .pcap)
    BASENAME="${BASENAME%.pcapng}"
    OUT_CSV="$OUTPUT_DIR/${BASENAME}_flows.csv"

    echo -e "${CYAN}Processing: $PCAP${NC}"

    if [ -f "$OUT_CSV" ]; then
        echo -e "  ${YELLOW}⚠  CSV already exists — skipping: $OUT_CSV${NC}"
        ((PROCESSED++)) || true
        continue
    fi

    # CICFlowMeter writes to a directory — we redirect the output
    TEMP_OUT="$OUTPUT_DIR/.tmp_${BASENAME}"
    mkdir -p "$TEMP_OUT"

    if java -jar "$JAR" "$PCAP" "$TEMP_OUT" 2>&1 | tail -3; then
        # CICFlowMeter names the file based on the pcap name
        GENERATED=$(find "$TEMP_OUT" -name "*.csv" | head -1)
        if [ -n "$GENERATED" ]; then
            mv "$GENERATED" "$OUT_CSV"
            rm -rf "$TEMP_OUT"
            N_ROWS=$(wc -l < "$OUT_CSV")
            echo -e "  ${GREEN}✓ Generated: $OUT_CSV  ($N_ROWS rows)${NC}"
            ((PROCESSED++)) || true
        else
            echo -e "  ${RED}❌ No CSV generated in $TEMP_OUT${NC}"
            ((FAILED++)) || true
        fi
    else
        echo -e "  ${RED}❌ CICFlowMeter failed on $PCAP${NC}"
        ((FAILED++)) || true
    fi
    echo ""
done

echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "  Processed : ${GREEN}$PROCESSED${NC}  |  Failed : ${RED}$FAILED${NC}"
echo -e "  CSV files : $OUTPUT_DIR/"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""
echo "  Next step:"
echo "    python main_offline.py"
