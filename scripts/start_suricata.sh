#!/usr/bin/env bash
# scripts/start_suricata.sh
# ==============================================================================
# Starts Suricata with the same self-exclusion filter as start_capture.sh.
#
# Suricata captures independently via its own af-packet socket — it does
# NOT read from tcpdump's output, so start_capture.sh's filter has zero
# effect on what Suricata sees. Without this, Suricata keeps alerting on
# this pipeline's own Ollama-tunnel traffic (ET HUNTING TryCloudFlare, etc.)
# regardless of whether the tcpdump filter is applied, and that noise still
# reaches Role 3 via eve.json. Use this script for Terminal 1, not a bare
# `sudo suricata ...` command.
#
# Usage
# -----
#   bash scripts/start_suricata.sh --iface wlp0s20f3
#   bash scripts/start_suricata.sh --iface wlp0s20f3 --port 5001 --ollama-url http://localhost:11434
#   bash scripts/start_suricata.sh --iface wlp0s20f3 --no-filter
# ==============================================================================

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IFACE=""
PORT=5001
OLLAMA_URL="http://localhost:11434"
NO_FILTER=0

while [ $# -gt 0 ]; do
    case "$1" in
        --iface) IFACE="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --ollama-url) OLLAMA_URL="$2"; shift 2 ;;
        --no-filter) NO_FILTER=1; shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [ -z "$IFACE" ]; then
    echo "Usage: $0 --iface <interface> [--port 5001] [--ollama-url http://localhost:11434] [--no-filter]"
    echo "(Suricata needs a real interface name, not 'any' — see README.md)"
    exit 1
fi

if [ "$NO_FILTER" -eq 1 ]; then
    echo "⚠  --no-filter: Suricata will see everything, including this pipeline's own traffic."
    FILTER=""
else
    FILTER="$("$ROOT_DIR/.venv/bin/python" "$ROOT_DIR/scripts/print_capture_filter.py" --port "$PORT" --ollama-url "$OLLAMA_URL")"
    echo "Capture filter (excluding self-traffic):"
    echo "  $FILTER"
fi

sudo -n /usr/bin/rm -f /var/log/suricata/eve.json
sudo -n "$ROOT_DIR/.venv/bin/python" -c "
import os
p = '/var/run/suricata.pid'
if os.path.exists(p):
    os.remove(p)
    print('removed stale pidfile')
"

echo
echo "Starting: sudo suricata -c /etc/suricata/suricata.yaml -i $IFACE -l /var/log/suricata -D $FILTER"
echo

sudo suricata -c /etc/suricata/suricata.yaml -i "$IFACE" -l /var/log/suricata -D $FILTER

sleep 2
tail -20 /var/log/suricata/suricata.log
