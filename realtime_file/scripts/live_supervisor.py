#!/usr/bin/env python3
"""
scripts/live_supervisor.py
==========================
Foreground process supervisor for BOTH live NIDS pipelines (Approach A + B)
without requiring sudo (uses dumpcap via wireshark group + Suricata
continuous PCAP directory mode).

Startup order ensures Suricata receives a real live PCAP immediately so its
flow-manager thread never times out on an empty directory:
  1. Clean all previous live/evaluation data
  2. Warm remote Ollama GPU
  3. Start Approach A (nids_web.py on :5000, dumpcap 5s segments -> mirror)
  4. Start live_b_worker.py (mirrors 5s segments -> suri_in & 20s CSVs)
  5. Wait for first non-empty PCAP segment in suri_in (pinging LAN gateway if idle)
  6. Start Suricata continuous mode (loads rules once, processes suri_in)
  7. Start Approach B core (main_unified.py --mode live, 20s windows)
  8. Start Approach B dashboard (app.py on :5001)
  9. Write logs/ready.json and monitor children until SIGINT/SIGTERM
"""

import argparse
import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(ROOT, ".venv", "bin", "python")
sys.path.insert(0, ROOT)
from src.utils.resilient_dns import install_resilient_dns


def _clean_previous():
    # Stop any leftover user-owned processes
    for pat in ("nids_web.py", "main_unified.py", "live_b_worker.py", "app.py",
                "dumpcap -i", "suricata -c /etc/suricata/suricata.yaml -r"):
        subprocess.run(["pkill", "-f", pat], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)

    for rel in ("nids_history.json", "nids_history.json.tmp"):
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            os.remove(p)

    for d in ("data/cicflow_csv", "data/results", "data/chunks", "data/live_b", "data/runs", "logs", "realtime_data"):
        full = os.path.join(ROOT, d)
        if os.path.isdir(full):
            shutil.rmtree(full, ignore_errors=True)

    for p in glob.glob("/tmp/test_*"):
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                os.remove(p)
            except OSError:
                pass

    for d in (
        "data/cicflow_csv",
        "data/results/eval",
        "data/chunks",
        "data/live_b/raw_5s",
        "data/live_b/suri_in",
        "data/live_b/suricata_logs",
        "data/runs",
        "logs",
    ):
        os.makedirs(os.path.join(ROOT, d), exist_ok=True)

    for f in (
        "data/results/unified_alerts.jsonl",
        "data/live_b/suricata_logs/eve.json",
        "data/live_b/suricata_logs/fast.log",
    ):
        open(os.path.join(ROOT, f), "w").close()


def _wait_http(url, timeout=45):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="wlp0s20f3")
    ap.add_argument("--ollama-url", default="https://presenting-characteristics-kathy-anybody.trycloudflare.com")
    ap.add_argument("--ollama-model", default="qwen2.5:1.5b")
    ap.add_argument("--pkl", default="universal_nids_output.pkl")
    args = ap.parse_args()

    os.chdir(ROOT)
    print("════════════════════════════════════════════════════════════════════", flush=True)
    print("  🛡️  NIDS Live Supervisor (Approach A + Approach B)", flush=True)
    print("════════════════════════════════════════════════════════════════════", flush=True)

    _clean_previous()
    print("  ✓ All previous run data cleaned", flush=True)

    install_resilient_dns()

    # Warm remote Ollama (populates shared logs/ollama_dns_cache.json too)
    ok = False
    for attempt in range(1, 6):
        try:
            r = requests.get(f"{args.ollama_url}/api/tags", timeout=15)
            if r.status_code == 200:
                ok = True
                break
        except Exception as exc:
            print(f"  ⚠ Ollama tags attempt {attempt}/3: {exc}", flush=True)
            time.sleep(2)
    if not ok:
        print(f"  ❌ Ollama unreachable at {args.ollama_url}", flush=True)
        sys.exit(1)

    try:
        requests.post(
            f"{args.ollama_url}/api/generate",
            json={"model": args.ollama_model, "prompt": 'Reply {"ok":true}',
                  "stream": False, "format": "json", "keep_alive": "1h"},
            timeout=60,
        )
    except Exception:
        pass
    print(f"  ✓ Ollama warm ({args.ollama_url}, model={args.ollama_model})", flush=True)

    children = {}
    logs = {}

    def _spawn(name, cmd, env=None):
        lf = open(os.path.join(ROOT, "logs", f"{name}.log"), "w", buffering=1)
        logs[name] = lf
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=lf, stderr=subprocess.STDOUT, env=full_env)
        children[name] = p
        print(f"  ▶ Started {name} (PID {p.pid})", flush=True)
        return p

    stopping = [False]
    draining = [False]
    drain_sig_flag = [False]

    def _on_sigusr1(_sig=None, _frm=None):
        drain_sig_flag[0] = True

    def _shutdown(_sig=None, _frm=None):
        if stopping[0]:
            return
        stopping[0] = True
        print("\n  Stopping all live services...", flush=True)
        for name in ("nids_web_5000", "app_5001", "main_unified_live", "live_b_worker", "suricata"):
            p = children.get(name)
            if p and p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass
        time.sleep(3.0)
        for name, p in children.items():
            if p and p.poll() is None:
                try:
                    p.kill()
                except Exception:
                    pass
        for lf in logs.values():
            try:
                lf.close()
            except Exception:
                pass
        sys.exit(0)

    def _drain_and_stop(_sig=None, _frm=None):
        if draining[0] or stopping[0]:
            return
        draining[0] = True
        print("\n════════════════════════════════════════════════════════════════════", flush=True)
        print("  ⏳ TWO-PHASE DRAIN: stopping packet capture, keeping analysis running...", flush=True)
        flag_p = os.path.join(ROOT, "logs", "drain_requested.flag")
        if not os.path.exists(flag_p):
            with open(flag_p, "w") as f:
                f.write(json.dumps({"requested_at": datetime.now(timezone.utc).isoformat(), "source": "supervisor"}) + "\n")

        # 1. Tell Approach A & live_b_worker to stop capture & flush
        try:
            requests.post("http://127.0.0.1:5000/api/capture/stop_drain", json={"source": "supervisor"}, timeout=5)
        except Exception:
            p_a = children.get("nids_web_5000")
            if p_a and p_a.poll() is None and hasattr(signal, "SIGUSR1"):
                p_a.send_signal(signal.SIGUSR1)

        # 2. Wait for live_b_worker to forward every mirrored PCAP and flush final CSV
        b_worker_done = os.path.join(ROOT, "data/live_b/drain_b_worker_done")
        t_w = time.time()
        while time.time() - t_w < 720:
            if os.path.exists(b_worker_done):
                break
            p_bw = children.get("live_b_worker")
            if p_bw and p_bw.poll() is not None:
                break
            time.sleep(1.0)
        print("  ✓ Capture stopped & all PCAP/CSV batches flushed", flush=True)

        # 3. Wait until Suricata finishes every remaining file in suri_in, then stop Suricata cleanly
        suri_in = os.path.join(ROOT, "data/live_b/suri_in")
        t_s = time.time()
        while time.time() - t_s < 120:
            rem = [f for f in (os.listdir(suri_in) if os.path.isdir(suri_in) else []) if not f.endswith(".tmp")]
            if not rem:
                break
            time.sleep(0.5)
        time.sleep(2.0)
        p_suri = children.get("suricata")
        if p_suri and p_suri.poll() is None:
            p_suri.terminate()
            try:
                p_suri.wait(timeout=8)
            except Exception:
                p_suri.kill()
        try:
            with open(os.path.join(ROOT, "data/live_b/drain_suri_done"), "w") as sf:
                sf.write(datetime.now(timezone.utc).isoformat() + "\n")
        except OSError:
            pass
        print("  ✓ Suricata finished all captured PCAPs", flush=True)

        # 4. Wait for Approach B main_unified_live AND Approach A Role 3 queue drain
        b_pipe_done = os.path.join(ROOT, "data/live_b/drain_b_pipeline_done")
        t_all = time.time()
        a_complete = False
        b_complete = False
        t_last_log = 0.0
        while time.time() - t_all < 600:
            if not b_complete:
                p_b = children.get("main_unified_live")
                if os.path.exists(b_pipe_done) or (p_b and p_b.poll() is not None):
                    b_complete = True
                    print("  ✓ Approach B drained all CSVs & LLM windows", flush=True)
            if not a_complete:
                try:
                    st = requests.get("http://127.0.0.1:5000/api/drain_status", timeout=3).json()
                    if st.get("complete"):
                        a_complete = True
                        print("  ✓ Approach A drained all flows & Role 3 LLM queue", flush=True)
                except Exception:
                    p_a = children.get("nids_web_5000")
                    if p_a and p_a.poll() is not None:
                        a_complete = True
            if a_complete and b_complete:
                break
            if time.time() - t_last_log >= 10.0:
                print(f"  ⏳ Drain wait: approach_a_complete={a_complete}, approach_b_complete={b_complete}", flush=True)
                t_last_log = time.time()
            time.sleep(2.0)

        with open(os.path.join(ROOT, "logs", "drain_complete.json"), "w") as f:
            json.dump({
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "approach_a_complete": a_complete,
                "approach_b_complete": b_complete,
            }, f, indent=2)
        print("  ✓ FULL DRAIN COMPLETE — shutting down services cleanly", flush=True)
        print("════════════════════════════════════════════════════════════════════", flush=True)
        _shutdown()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, _on_sigusr1)

    # 1. Start Approach A (nids_web.py on port 5000)
    _spawn("nids_web_5000", [
        PY, "-u", "nids_web.py",
        "--iface", args.iface,
        "--pkl", args.pkl,
        "--ollama-url", args.ollama_url,
        "--ollama-model", args.ollama_model,
        "--port", "5000",
        "--fresh",
        "--shap-mode", "xgb",
        "--capture-backend", "dumpcap",
        "--rotate-sec", "5",
        "--mirror-dir", "data/live_b/raw_5s",
        "--exclude", "port 5001",
    ])
    if not _wait_http("http://127.0.0.1:5000/api/stats", timeout=45):
        print("  ❌ nids_web.py failed to start on :5000", flush=True)
        _shutdown()
    print("  ✓ Approach A dashboard live on http://localhost:5000", flush=True)

    # 2. Start live_b_worker
    _spawn("live_b_worker", [
        PY, "-u", "scripts/live_b_worker.py",
        "--mirror-dir", "data/live_b/raw_5s",
        "--suri-in", "data/live_b/suri_in",
        "--csv-dir", "data/cicflow_csv",
        "--batch-chunks", "4",
        "--batch-seconds", "20",
    ])

    # 3. Ensure at least one non-empty PCAP reaches suri_in before launching Suricata
    #    (Suricata continuous dir mode times out FM#01 if dir stays empty >60s at boot)
    print("  ⏳ Waiting for first live 5s PCAP chunk...", flush=True)
    subprocess.run(["ping", "-c", "2", "-W", "1", "192.168.1.1"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    while time.time() - t0 < 20:
        files = [f for f in glob.glob("data/live_b/suri_in/*.pcap*") if not f.endswith(".tmp")]
        if files:
            print(f"  ✓ First live chunk ready in suri_in ({os.path.basename(files[0])})", flush=True)
            break
        time.sleep(0.5)

    # 4. Start Suricata continuous mode (-k none disables NIC TX checksum false positives)
    _spawn("suricata", [
        "suricata", "-k", "none",
        "-c", "/etc/suricata/suricata.yaml",
        "-r", os.path.join(ROOT, "data/live_b/suri_in"),
        "--pcap-file-continuous", "--pcap-file-delete",
        "-l", os.path.join(ROOT, "data/live_b/suricata_logs"),
        "--set", "unix-command.enabled=no",
        "--set", "stream.checksum-validation=no",
        "--set", f"threshold-file={os.path.join(ROOT, 'config/suricata_threshold.conf')}",
    ])
    suri_log = os.path.join(ROOT, "data/live_b/suricata_logs/suricata.log")
    suri_ok = False
    t0 = time.time()
    while time.time() - t0 < 60:
        if os.path.exists(suri_log):
            txt = open(suri_log, errors="replace").read()
            if "Engine started" in txt:
                suri_ok = True
                break
        if children["suricata"].poll() is not None:
            break
        time.sleep(1.0)
    print(f"  {'✓' if suri_ok else '⚠'} Suricata status: {'Engine started' if suri_ok else 'check logs/suricata.log'}", flush=True)

    # 5. Start Approach B core (main_unified.py) & dashboard (app.py on :5001)
    _spawn("main_unified_live", [
        PY, "-u", "main_unified.py",
        "--mode", "live",
        "--config", "config/settings_live.yaml",
        "--nids_pkl", args.pkl,
        "--cicflow_csv", "data/cicflow_csv/",
        "--dataset", "CICIDS2017",
        "--ollama_url", args.ollama_url,
        "--ollama_model", args.ollama_model,
        "--window_seconds", "20",
    ])
    _spawn("app_5001", [PY, "-u", "app.py"], env={"PORT": "5001"})
    _wait_http("http://127.0.0.1:5001/data", timeout=25)
    print("  ✓ Approach B dashboard live on http://localhost:5001", flush=True)

    run_dir = ""
    latest_txt = os.path.join(ROOT, "data/runs/latest_run.txt")
    if os.path.exists(latest_txt):
        run_dir = open(latest_txt).read().strip()

    ready_info = {
        "ready_ts_utc": datetime.now(timezone.utc).isoformat(),
        "run_dir": run_dir,
        "iface": args.iface,
        "ollama_url": args.ollama_url,
        "ollama_model": args.ollama_model,
        "approach_a_url": "http://localhost:5000",
        "approach_b_url": "http://localhost:5001",
        "pids": {k: v.pid for k, v in children.items()},
        "suricata_started": suri_ok,
    }
    with open(os.path.join(ROOT, "logs/ready.json"), "w") as f:
        json.dump(ready_info, f, indent=2)

    print("════════════════════════════════════════════════════════════════════", flush=True)
    print("  READY FOR LIVE SIMULATION", flush=True)
    print(f"  Run dir: {run_dir}", flush=True)
    print("════════════════════════════════════════════════════════════════════", flush=True)

    # Supervise forever while daemon runs (also watch logs/drain_requested.flag triggered from dashboards)
    flag_p = os.path.join(ROOT, "logs", "drain_requested.flag")
    while not stopping[0]:
        if (drain_sig_flag[0] or os.path.exists(flag_p)) and not draining[0]:
            _drain_and_stop()
            break
        for name, p in list(children.items()):
            rc = p.poll()
            if rc is not None and not draining[0]:
                print(f"  ⚠ Child {name} exited with code {rc}", flush=True)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
