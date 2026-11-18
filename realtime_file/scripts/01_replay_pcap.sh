#!/usr/bin/env bash
# scripts/01_replay_pcap.sh
# ==========================
# Replay all CICIDS2017 pcap files in data/raw_pcap/ through Suricata
# in offline mode to generate eve.json logs in data/eve_logs/
#
# Usage:
#   bash scripts/01_replay_pcap.sh
#   bash scripts/01_replay_pcap.sh data/raw_pcap/Monday-WorkingHours.pcap
#
# Output:
#   data/eve_logs/<pcap_name>/eve.json

set -euo pipefail

PCAP_DIR="data/raw_pcap"
OUTPUT_BASE="data/eve_logs"
SURICATA_CONF="/etc/suricata/suricata.yaml"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  NIDS Role 3 — Step 1: Replay pcap → Suricata   ${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}\n"

# ── pre-flight ────────────────────────────────────────────────────────────────
if ! command -v suricata &>/dev/null; then
    echo -e "${RED}❌ Suricata not found.${NC}"
    echo "   Install: sudo apt install suricata"
    exit 1
fi

if [ ! -f "$SURICATA_CONF" ]; then
    echo -e "${YELLOW}⚠  Suricata config not found at $SURICATA_CONF${NC}"
    echo "   Using Suricata defaults (no custom rules)"
    CONF_FLAG=""
else
    CONF_FLAG="-c $SURICATA_CONF"
    echo -e "${GREEN}✓ Suricata config: $SURICATA_CONF${NC}"
fi

# ── find pcap files ───────────────────────────────────────────────────────────
if [ $# -ge 1 ]; then
    # Single pcap provided as argument
    PCAP_FILES=("$1")
else
    mapfile -t PCAP_FILES < <(find "$PCAP_DIR" -name "*.pcap" -o -name "*.pcapng" 2>/dev/null | sort)
fi

if [ ${#PCAP_FILES[@]} -eq 0 ]; then
    echo -e "${RED}❌ No pcap files found in $PCAP_DIR${NC}"
    echo ""
    echo "  Place CICIDS2017 pcap files in $PCAP_DIR/"
    echo "  Download from: https://www.unb.ca/cic/datasets/ids-2017.html"
    echo "  (Monday-WorkingHours.pcap, Tuesday-WorkingHours.pcap, etc.)"
    exit 1
fi

echo -e "  Found ${CYAN}${#PCAP_FILES[@]}${NC} pcap file(s):\n"
for f in "${PCAP_FILES[@]}"; do
    SIZE=$(du -sh "$f" 2>/dev/null | cut -f1 || echo "?")
    echo "    $f  ($SIZE)"
done
echo ""

# ── process each pcap ─────────────────────────────────────────────────────────
mkdir -p "$OUTPUT_BASE"
PROCESSED=0
FAILED=0

for PCAP in "${PCAP_FILES[@]}"; do
    BASENAME=$(basename "$PCAP" .pcap)
    BASENAME="${BASENAME%.pcapng}"
    OUT_DIR="$OUTPUT_BASE/$BASENAME"
    mkdir -p "$OUT_DIR"

    echo -e "${CYAN}Processing: $PCAP${NC}"
    echo -e "  Output dir: $OUT_DIR"

    if [ -f "$OUT_DIR/eve.json" ]; then
        echo -e "  ${YELLOW}⚠  eve.json already exists — skipping (delete to re-run)${NC}"
        ((PROCESSED++)) || true
        continue
    fi

    # Run Suricata offline
    if suricata \
        -r "$PCAP" \
        -l "$OUT_DIR" \
        $CONF_FLAG \
        --set outputs.1.eve-log.enabled=yes \
        --set outputs.1.eve-log.filename=eve.json \
        -v 2>&1 | tail -5; then

        EVE_PATH="$OUT_DIR/eve.json"
        if [ -f "$EVE_PATH" ]; then
            N_LINES=$(wc -l < "$EVE_PATH")
            N_ALERTS=$(grep -c '"event_type":"alert"' "$EVE_PATH" 2>/dev/null || echo 0)
            echo -e "  ${GREEN}✓ Generated: $EVE_PATH${NC}"
            echo -e "     Events: $N_LINES  |  Alerts: $N_ALERTS"
            ((PROCESSED++)) || true
        else
            echo -e "  ${RED}❌ eve.json not generated — check Suricata logs${NC}"
            ((FAILED++)) || true
        fi
    else
        echo -e "  ${RED}❌ Suricata failed on $PCAP${NC}"
        ((FAILED++)) || true
    fi
    echo ""
done

# ── summary ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "  Processed : ${GREEN}$PROCESSED${NC}  |  Failed : ${RED}$FAILED${NC}"
echo -e "  Eve logs  : $OUTPUT_BASE/"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""
echo "  Next step:"
echo "    bash scripts/02_run_cicflowmeter.sh"
