#!/usr/bin/env bash
# scripts/start_capture.sh
# ==============================================================================
# Wraps tcpdump with the self-exclusion capture filter baked in, so it can't
# be forgotten. The Aug 13 live test's noisiest problem — Suricata correctly
# flagging this host's own Ollama-tunnel traffic, which then cascaded into
# repeated wrong LLM verdicts — traced back to exactly this: a plain
# `sudo tcpdump ...` copy-pasted without the
# `$(python scripts/print_capture_filter.py ...)` part. Use this script
# instead of typing tcpdump directly for Approach B's Terminal 2.
#
# Usage
# -----
#   bash scripts/start_capture.sh
#   bash scripts/start_capture.sh --iface wlp0s20f3 --rotate 20 --port 5001 --ollama-url http://localhost:11434
#   bash scripts/start_capture.sh --no-filter          # capture everything, no exclusion
# ==============================================================================

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IFACE="any"
ROTATE=20
PORT=5001
OLLAMA_URL="http://localhost:11434"
NO_FILTER=0
PCAP_DIR="/tmp/raw_pcap"

while [ $# -gt 0 ]; do
    case "$1" in
        --iface) IFACE="$2"; shift 2 ;;
        --rotate) ROTATE="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --ollama-url) OLLAMA_URL="$2"; shift 2 ;;
        --no-filter) NO_FILTER=1; shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

mkdir -p "$PCAP_DIR"

if [ "$NO_FILTER" -eq 1 ]; then
    echo "⚠  --no-filter: capturing everything, including this pipeline's own traffic."
    FILTER=""
else
    FILTER="$("$ROOT_DIR/.venv/bin/python" "$ROOT_DIR/scripts/print_capture_filter.py" --port "$PORT" --ollama-url "$OLLAMA_URL")"
    echo "Capture filter (excluding self-traffic):"
    echo "  $FILTER"
fi

echo
echo "Starting: sudo tcpdump -i $IFACE -Z root -w $PCAP_DIR/live_capture_%Y%m%d%H%M%S.pcap -G $ROTATE"
echo

exec sudo tcpdump -i "$IFACE" -Z root \
    -w "$PCAP_DIR/live_capture_%Y%m%d%H%M%S.pcap" -G "$ROTATE" \
    $FILTER
