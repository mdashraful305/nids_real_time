#!/usr/bin/env bash
# scripts/reset_live_state.sh
# ==============================================================================
# Stops all live-pipeline processes (tcpdump, Suricata, main_unified.py,
# app.py, nids_web.py, flow_processor.sh) and clears all live-capture state
# (pcaps, flow CSVs, unified_alerts.jsonl, nids_history.json, Suricata logs),
# so you can start a completely fresh attack-simulation run at any time.
#
# Does NOT touch: Ollama (left running), data/results/*.md or other saved
# report/analysis files from previous runs — only live-capture state.
#
# Requires the passwordless-sudo setup from README.md ("Passwordless sudo
# for the capture tools"). Safe to run even if nothing is currently running.
#
# Usage: bash scripts/reset_live_state.sh
# ==============================================================================

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="$ROOT_DIR/.venv/bin/python"
cd "$ROOT_DIR"

echo "=================================================="
echo "  Resetting live NIDS pipeline state"
echo "=================================================="

echo
echo "-- Stopping pipeline processes --"

sudo -n "$VENV_PYTHON" - <<'PYEOF'
import subprocess, signal, os, time

def pids_matching(pattern):
    out = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True).stdout
    return [int(p) for p in out.split() if p]

# tcpdump's AppArmor profile blocks external signals even from root; unload
# the profile, kill, then reload so future tcpdump runs stay normally
# confined. See "AppArmor" in README.md's Troubleshooting table.
tcpdump_pids = pids_matching("tcpdump -i")
if tcpdump_pids:
    subprocess.run(["apparmor_parser", "-R", "/etc/apparmor.d/usr.bin.tcpdump"], capture_output=True)
    time.sleep(0.3)
    for pid in tcpdump_pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    time.sleep(0.3)
    subprocess.run(["apparmor_parser", "-r", "/etc/apparmor.d/usr.bin.tcpdump"], capture_output=True)
    print(f"  ✓ tcpdump stopped ({len(tcpdump_pids)} process(es))")
else:
    print("  - tcpdump not running")

for label, pattern in [
    ("suricata",       "suricata -c"),
    ("main_unified.py","main_unified.py"),
    ("app.py",         r"[/ ]app\.py"),
    ("nids_web.py",    "nids_web.py"),
    ("flow_processor.sh", "flow_processor.sh"),
]:
    pids = pids_matching(pattern)
    if pids:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        print(f"  ✓ {label} stopped ({len(pids)} process(es))")
    else:
        print(f"  - {label} not running")
PYEOF

sleep 1

echo
echo "-- Clearing capture state --"

sudo -n "$VENV_PYTHON" - <<'PYEOF'
import glob, os

removed = 0
for pattern in [
    "/tmp/raw_pcap/*.pcap",
    "/tmp/raw_pcap/processed/*.pcap",
    "/tmp/raw_pcap/processed/*.failed",
    "/tmp/flow_proc_*.pcap",
    "/var/log/suricata/eve.json",
    "/var/log/suricata/fast.log",
    "/var/log/suricata/stats.log",
    "/var/run/suricata.pid",
]:
    for f in glob.glob(pattern):
        try:
            os.remove(f)
            removed += 1
        except OSError:
            pass
print(f"  ✓ removed {removed} file(s) (stray pcaps + Suricata logs)")
PYEOF

mkdir -p /tmp/raw_pcap/processed "$ROOT_DIR/data/cicflow_csv" "$ROOT_DIR/data/results"

rm -f "$ROOT_DIR"/data/cicflow_csv/*.csv
: > "$ROOT_DIR"/data/results/unified_alerts.jsonl
rm -f "$ROOT_DIR"/nids_history.json

echo "  ✓ flow CSVs cleared"
echo "  ✓ unified_alerts.jsonl truncated"
echo "  ✓ nids_history.json removed"

echo
echo "-- Status --"
df -h / | tail -1
free -h | head -2
ollama_code=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://localhost:11434/api/tags 2>/dev/null)
if [ "$ollama_code" = "200" ]; then
    echo "  Ollama: reachable"
else
    echo "  Ollama: NOT reachable (http $ollama_code) — run 'ollama serve' yourself before starting the pipelines"
fi

echo
echo "=================================================="
echo "  Clean. Ready for a fresh run — see RUN_LOCALLY.md"
echo "=================================================="
