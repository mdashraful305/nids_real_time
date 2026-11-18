#!/usr/bin/env python3
"""
scripts/live_b_worker.py
========================
Feeds Approach B (Suricata continuous + python-cicflowmeter -> data/cicflow_csv/)
from the closed 5-second PCAP chunks mirrored by nids_web.py's dumpcap reader.

For each closed 5s chunk in --mirror-dir:
  1. Immediately copies it into --suri-in so Suricata (continuous mode)
     generates eve.json / fast.log events without root privileges.
  2. Batches up to --batch-chunks (default 4 => 20s) or --batch-seconds (20s),
     merges via mergecap, and extracts CICFlowMeter CSVs atomically into
     --csv-dir for main_unified.py --mode live.
"""

import argparse
import glob
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


def main():
    ap = argparse.ArgumentParser(description="Approach B PCAP dispatcher for live mode")
    ap.add_argument("--mirror-dir", default="data/live_b/raw_5s")
    ap.add_argument("--suri-in", default="data/live_b/suri_in")
    ap.add_argument("--csv-dir", default="data/cicflow_csv")
    ap.add_argument("--batch-chunks", type=int, default=4)
    ap.add_argument("--batch-seconds", type=float, default=20.0)
    args = ap.parse_args()

    os.makedirs(args.mirror_dir, exist_ok=True)
    os.makedirs(args.suri_in, exist_ok=True)
    os.makedirs(args.csv_dir, exist_ok=True)

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    py_exe = os.path.join(root_dir, ".venv", "bin", "python")
    if not os.path.exists(py_exe):
        py_exe = sys.executable
    pcap_to_flow = os.path.join(root_dir, "scripts", "pcap_to_flow.py")
    mergecap = shutil.which("mergecap")

    running = [True]
    drain_mode = [False]

    def _stop(_sig, _frm):
        running[0] = False

    def _drain(_sig, _frm):
        drain_mode[0] = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, _drain)

    seen = set()
    pending = []
    batch_start = None
    seq = 0
    drain_flag_file = os.path.join(root_dir, "logs", "drain_requested.flag")
    a_done_flag = os.path.join(args.mirror_dir, "drain_a_pcaps_done")
    b_done_flag = os.path.join(root_dir, "data", "live_b", "drain_b_worker_done")
    busy_flag   = os.path.join(root_dir, "data", "live_b", "worker_busy")
    try:
        if os.path.exists(busy_flag):
            os.remove(busy_flag)
    except OSError:
        pass

    print(f"✓ live_b_worker watching {args.mirror_dir} -> Suricata({args.suri_in}) + CSV({args.csv_dir})", flush=True)

    def _ingest_new_files():
        nonlocal batch_start
        files = sorted(
            f for f in glob.glob(os.path.join(args.mirror_dir, "*.pcap*"))
            if not f.endswith(".tmp")
        )
        added = 0
        for path in files:
            if path in seen:
                continue
            seen.add(path)
            added += 1
            # Forward immediately to Suricata continuous input dir
            if os.path.getsize(path) > 24:
                base = os.path.basename(path)
                tmp_suri = os.path.join(args.suri_in, base + ".tmp")
                dst_suri = os.path.join(args.suri_in, base)
                try:
                    shutil.copy2(path, tmp_suri)
                    os.replace(tmp_suri, dst_suri)
                except Exception as exc:
                    print(f"  ⚠ suri copy failed ({base}): {exc}", flush=True)
            if batch_start is None:
                batch_start = time.time()
            pending.append(path)
        return added

    def _flush_batch():
        nonlocal pending, batch_start, seq
        if not pending:
            return
        nonempty = [p for p in pending if os.path.exists(p) and os.path.getsize(p) > 24]
        to_remove = list(pending)
        pending = []
        batch_start = None
        if not nonempty:
            for p in to_remove:
                try:
                    os.remove(p)
                except OSError:
                    pass
            return

        seq += 1
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_csv = os.path.join(args.csv_dir, f"live_{ts}_{seq:04d}_flows.csv")

        fd, tmp_pcap = tempfile.mkstemp(prefix="b_batch_", suffix=".pcap")
        os.close(fd)
        try:
            with open(busy_flag, "w") as bf:
                bf.write(f"{seq}\n")
        except OSError:
            pass
        try:
            if len(nonempty) == 1 or not mergecap:
                shutil.copy2(nonempty[0], tmp_pcap)
            else:
                res = subprocess.run(
                    [mergecap, "-F", "pcap", "-w", tmp_pcap, *nonempty],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                if res.returncode != 0 or not os.path.exists(tmp_pcap) or os.path.getsize(tmp_pcap) <= 24:
                    print(f"  ⚠ mergecap failed: {res.stderr.strip()}", flush=True)
                    return

            res = subprocess.run(
                [py_exe, pcap_to_flow, tmp_pcap, out_csv],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if res.returncode == 0 and os.path.exists(out_csv):
                print(f"  ✓ Batch #{seq:04d} ({len(nonempty)} segs) -> {os.path.basename(out_csv)}", flush=True)
            else:
                print(f"  ⚠ pcap_to_flow failed on batch #{seq:04d}: {res.stdout} {res.stderr}", flush=True)
        finally:
            try:
                if os.path.exists(busy_flag):
                    os.remove(busy_flag)
            except OSError:
                pass
            try:
                os.remove(tmp_pcap)
            except OSError:
                pass
            for p in to_remove:
                try:
                    os.remove(p)
                except OSError:
                    pass

    drain_detected_at = None
    while running[0]:
        if os.path.exists(drain_flag_file) or drain_mode[0]:
            if not drain_mode[0]:
                drain_mode[0] = True
                print("  ⏳ live_b_worker drain mode active: waiting for final Approach A PCAP chunks...", flush=True)
            if drain_detected_at is None:
                drain_detected_at = time.time()

        _ingest_new_files()

        if pending and (
            len(pending) >= args.batch_chunks
            or (batch_start is not None and (time.time() - batch_start) >= args.batch_seconds)
        ):
            _flush_batch()

        if drain_mode[0]:
            a_done = os.path.exists(a_done_flag)
            timed_out = (time.time() - drain_detected_at) > 90.0
            if a_done or timed_out:
                # Final sweep of mirror_dir
                _ingest_new_files()
                break

        time.sleep(0.5)

    _flush_batch()
    try:
        os.makedirs(os.path.dirname(b_done_flag), exist_ok=True)
        with open(b_done_flag, "w") as f:
            f.write(datetime.now(timezone.utc).isoformat() + "\n")
    except OSError:
        pass
    print("  ✓ live_b_worker drained all PCAPs -> Suricata & CICFlow CSV", flush=True)


if __name__ == "__main__":
    main()
