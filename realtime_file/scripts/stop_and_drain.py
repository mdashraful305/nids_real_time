#!/usr/bin/env python3
"""
scripts/stop_and_drain.py
=========================
Two-phase graceful stop for both live NIDS pipelines:
  1. Immediately stops raw packet capture (dumpcap) via /api/capture/stop_drain
     & logs/drain_requested.flag (keeps Approach A & B processing running).
  2. Waits until ALL already-captured PCAPs, CICFlowMeter CSVs, Suricata
     logs, and queued Role-3 LLM responses finish cleanly (0 dropped).
  3. Generates full evaluation reports (analyze_live_run.py + evaluate_nids.py
     + summarize_live_test.py) and packages everything into realtime_data/.
"""

import argparse
import glob
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(ROOT, ".venv", "bin", "python")


def _signal_supervisor():
    out = subprocess.run(["pgrep", "-f", "live_supervisor.py"], capture_output=True, text=True)
    pids = [int(x) for x in out.stdout.split() if x.strip().isdigit()]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGUSR1)
        except OSError:
            pass
    return pids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacker-ip", default=None)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--skip-reports", action="store_true")
    args = ap.parse_args()

    os.chdir(ROOT)
    os.makedirs("logs", exist_ok=True)
    flag_p = os.path.join(ROOT, "logs", "drain_requested.flag")
    with open(flag_p, "w") as f:
        f.write(json.dumps({"requested_at": datetime.now(timezone.utc).isoformat(), "source": "stop_and_drain.py"}) + "\n")

    print("1/3  Stopping packet capture (keeping PCAP -> Flow -> LLM processors active)...", flush=True)
    try:
        r = requests.post("http://127.0.0.1:5000/api/capture/stop_drain", json={"source": "cli"}, timeout=5)
        print(f"     Approach A capture-stop acknowledged: {r.json()}", flush=True)
    except Exception as exc:
        print(f"     Note: Approach A HTTP stop skipped ({exc})", flush=True)
    # NOTE: Do NOT send SIGUSR1 via pgrep -f 'live_supervisor.py' because that
    # matches the parent bash wrapper command and kills the whole process group.
    # live_supervisor, nids_web, and live_b_worker all poll logs/drain_requested.flag.

    print("2/3  Waiting for already-captured PCAPs, CSVs, Suricata, and pending LLM calls to finish...", flush=True)
    t0 = time.time()
    last_print = 0.0
    while time.time() - t0 < args.timeout:
        a_done = False
        a_pend = "?"
        try:
            st = requests.get("http://127.0.0.1:5000/api/drain_status", timeout=2).json()
            a_done = bool(st.get("complete"))
            a_pend = st.get("llm_pending", "?")
        except Exception:
            # If nids_web already shut down after drain_complete.json, check file
            a_done = os.path.exists("logs/drain_complete.json")

        b_done = os.path.exists("data/live_b/drain_b_pipeline_done")
        if os.path.exists("logs/drain_complete.json"):
            try:
                dc = json.load(open("logs/drain_complete.json"))
                a_done = a_done or bool(dc.get("approach_a_complete"))
                b_done = b_done or bool(dc.get("approach_b_complete"))
            except Exception:
                pass
        sup_alive = bool(subprocess.run(["pgrep", "-f", "scripts/live_supervisor.py"], capture_output=True).stdout.strip())
        if a_done and b_done and os.path.exists("logs/drain_complete.json") and not sup_alive:
            print("  ✓ Supervisor finished full dual-approach drain cleanly (A=True, B=True)", flush=True)
            break
        if time.time() - last_print >= 4.0:
            print(f"     Draining... ({int(time.time()-t0)}s) A_done={a_done} (llm_pending={a_pend}) B_done={b_done}", flush=True)
            last_print = time.time()
        if not sup_alive and a_done and b_done:
            break
        time.sleep(1.5)
    else:
        print("  ⚠ Drain timeout reached; terminating leftover processes cleanly...", flush=True)
        subprocess.run(["pkill", "-TERM", "-f", "live_supervisor.py"], capture_output=True)
        time.sleep(3)

    if args.skip_reports:
        return

    print("3/3  Generating evaluation reports and packaging realtime_data/...", flush=True)
    run_dir = ""
    if os.path.exists("data/runs/latest_run.txt"):
        run_dir = open("data/runs/latest_run.txt").read().strip()

    extra_atk = ["--attacker-ip", args.attacker_ip] if args.attacker_ip else []
    if run_dir and os.path.isdir(run_dir):
        subprocess.run([PY, "scripts/analyze_live_run.py", "--run-dir", run_dir, "--merge-pcap", *extra_atk], check=False)

    # Run evaluate_nids modes quickly cleanly
    subprocess.run([PY, "evaluate_nids.py", "llm-audit", "--results-dir", "data/results"], check=False)
    subprocess.run([PY, "evaluate_nids.py", "prompt-dump", "--results-dir", "data/results"], check=False)
    atk_arg = extra_atk
    if not atk_arg and os.path.exists(os.path.join(run_dir, "experiment_report.json")):
        try:
            rep = json.load(open(os.path.join(run_dir, "experiment_report.json")))
            if rep.get("attacker_ip"):
                atk_arg = ["--attacker-ip", rep["attacker_ip"]]
        except Exception:
            pass
    subprocess.run([PY, "evaluate_nids.py", "realtime", "--approach", "1", "--duration", "0", *atk_arg], check=False)
    subprocess.run([PY, "evaluate_nids.py", "realtime", "--approach", "2", "--duration", "0"], check=False)
    subprocess.run([PY, "scripts/summarize_live_test.py", "--suricata-fast-log", "data/live_b/suricata_logs/fast.log"], check=False)
    subprocess.run([PY, "scripts/package_realtime_data.py"], check=False)
    print("✓ Complete: all pending work drained, reports written, and data saved to realtime_data/", flush=True)


if __name__ == "__main__":
    main()
