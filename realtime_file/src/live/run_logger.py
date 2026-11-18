"""
src/live/run_logger.py
======================
Append-only, per-run experiment log for the live NIDS (nids_web.py).

Why this exists
---------------
nids_web.py's nids_history.json is a UI snapshot: it keeps only the last
500 flows (deque) and never records flows whose UI update was suppressed
by the 5-second repeat-alert de-duplication. Scoring a live experiment
from that file silently truncates and biases the result (a 30-minute run
with a SYN flood produces far more than 500 flows, and the suppressed
flows are exactly the attack flows).

This logger writes EVERY flow and EVERY Role-3 call to line-buffered JSONL
files in a dedicated run directory, plus operator phase markers (ground
truth for "which attack was running when"), so a run can be scored
completely and reproducibly afterwards by scripts/analyze_live_run.py.

Run directory layout (data/runs/<run_id>/):
    run_meta.json   — CLI args, model info, Ollama endpoint, BPF filter,
                      host IP/network, hardware, start/stop time
    flows.jsonl     — one record per NFStream flow (Role 1 + heuristic +
                      full class distribution + 52-feature vector + timing)
    r3.jsonl        — one record per Role-3 (LLM) call (verdict, latency,
                      queue wait, raw response, error if any)
    phases.jsonl    — operator markers: {"phase": "...", "event": "start"|"stop"}
    capture.pcap    — (optional) raw packet record written by dumpcap, so
                      the exact traffic can be replayed offline later
"""

import json
import os
import threading
import time
from datetime import datetime, timezone


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


class RunLogger:
    def __init__(self, run_dir, chown_fn=None):
        self.run_dir = run_dir
        os.makedirs(run_dir, exist_ok=True)
        self._chown = chown_fn or (lambda p: None)
        self._chown(os.path.dirname(run_dir.rstrip("/")) or ".")
        self._chown(run_dir)
        self._locks = {}
        self._files = {}
        self.counts = {"flows": 0, "r3": 0, "phases": 0}
        for name in ("flows", "r3", "phases"):
            path = os.path.join(run_dir, f"{name}.jsonl")
            # line-buffered: each record hits the OS as soon as it is written,
            # so a crash / Ctrl+C loses at most the record being written.
            self._files[name] = open(path, "a", buffering=1)
            self._locks[name] = threading.Lock()
            self._chown(path)

    def path(self, name):
        return os.path.join(self.run_dir, name)

    def _write(self, name, record):
        line = json.dumps(record, default=_json_default)
        with self._locks[name]:
            self._files[name].write(line + "\n")
            self.counts[name] += 1

    def log_flow(self, record):
        self._write("flows", record)

    def log_r3(self, record):
        self._write("r3", record)

    def log_phase(self, phase, event, note="", source=""):
        rec = {
            "ts_utc": utc_now_iso(),
            "epoch": time.time(),
            "phase": phase,
            "event": event,
            "note": note,
            "source": source,
        }
        self._write("phases", rec)
        return rec

    def write_meta(self, meta):
        path = self.path("run_meta.json")
        with open(path, "w") as f:
            json.dump(meta, f, indent=2, default=_json_default)
        self._chown(path)

    def update_meta(self, **kw):
        path = self.path("run_meta.json")
        try:
            with open(path) as f:
                meta = json.load(f)
        except Exception:
            meta = {}
        meta.update(kw)
        self.write_meta(meta)

    def close(self):
        for name, f in self._files.items():
            with self._locks[name]:
                try:
                    f.flush()
                    f.close()
                except Exception:
                    pass


def _json_default(o):
    try:
        import numpy as np
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        if isinstance(o, np.ndarray):
            return o.tolist()
        if isinstance(o, np.str_):
            return str(o)
    except ImportError:
        pass
    if isinstance(o, set):
        return sorted(o)
    return str(o)
