#!/usr/bin/env python3
"""
nids_web.py — Real-time NIDS Web Dashboard
==========================================
Role 1 (ML) + Role 3 (LLM) run on ALL  flows so you can compare both verdicts.

Architecture:
  NFStream ──► Role 1 (instant) ──► SSE → browser (R1 result appears immediately)
                    │
                    └──► LLM queue (background, non-blocking)
                              │
                              ▼
                        Role 3 (Ollama) ──► SSE → browser (R3 result appears when done)

Usage:
  # Run web dashboard (live capture — needs root)
  sudo .venv/bin/python nids_web.py

  # From a PCAP file (no root needed — for testing)
  python nids_web.py --pcap /tmp/raw_pcap/processed/some.pcap

  # Then open: http://localhost:5000
"""

import sys, os, time, json, uuid, argparse, threading, shutil, subprocess, signal, atexit, glob
from collections import deque, defaultdict
from datetime import datetime, timezone
from queue import Queue, PriorityQueue, Full, Empty
import itertools

# ── Register UniversalEnsemble before joblib.load ─────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from src.engine.universal_ensemble import UniversalEnsemble  # noqa: F401
except ImportError:
    pass

from src.utils.capture_filter import build_self_exclusion_bpf
from src.utils.resilient_dns import install_resilient_dns as _install_resilient_dns
from src.live.behavioral_guard import (
    StatefulBehavioralDetector,
    is_attack_verdict,
    normalize_llm_verdict,
)
from src.live.fast_pcap_extractor import extract_flows_from_pcap

try:
    import numpy as np
    import joblib
    import requests
    from nfstream import NFStreamer
    from flask import Flask, Response, render_template_string, jsonify, request
except ImportError as e:
    _py = sys.executable
    _is_sudo = os.environ.get("SUDO_USER") is not None
    _in_venv = (hasattr(sys, "real_prefix")
                or sys.base_prefix != sys.prefix
                or "VIRTUAL_ENV" in os.environ)
    print("=" * 70)
    print(f"❌ Missing package: {e}")
    print("=" * 70)
    print(f"  This Python : {_py}")
    print(f"  Running under sudo : {_is_sudo}   In a venv : {_in_venv}")
    print()
    if "nfstream" in str(e):
        if _is_sudo and not _in_venv:
            # THE common cause: sudo used system python, not the venv where
            # nfstream was pip-installed. nids_web needs root to sniff, so the
            # fix is to run the VENV's python under sudo, not system python.
            print("  CAUSE: you ran `sudo python nids_web.py`, so sudo used the")
            print("  SYSTEM python — not your venv, where nfstream is installed.")
            print()
            print("  FIX (run the venv's python under sudo):")
            print("      sudo .venv/bin/python nids_web.py --iface <iface> ...")
            print()
            print("  Or grant capture capability once, then run WITHOUT sudo:")
            print("      sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python*")
            print("      .venv/bin/python nids_web.py --iface <iface> ...")
        else:
            print("  Install nfstream into THIS interpreter, plus its libpcap dep:")
            print("      sudo apt-get install -y libpcap-dev")
            print(f"      {_py} -m pip install nfstream")
        print()
        print("  Alternative — you do NOT need nfstream at all. The other live")
        print("  path uses tcpdump + Java CICFlowMeter + main_unified --mode live")
        print("  + app.py, and produces training-matched features. See")
        print("  REALTIME_GUIDE.md (Approach B).")
    else:
        print(f"      {_py} -m pip install flask nfstream joblib numpy requests")
    print("=" * 70)
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# SHARED STATE
# ══════════════════════════════════════════════════════════════════════════════

FLOWS       = deque(maxlen=5000)     # up to 5000 flows in nids_history.json (RunLogger stores ALL flows unbounded)
FLOWS_LOCK  = threading.Lock()
SSE_CLIENTS = []                     # list of SSE queue objects, one per browser tab
SSE_LOCK    = threading.Lock()
LLM_QUEUE   = PriorityQueue(maxsize=2000)    # pending flows for LLM analysis
LLM_QUEUE_COUNTER = itertools.count()        # tie-breaker for priority queue

DRAIN_LOCK  = threading.Lock()
DRAIN_STATE = {
    "requested": False,
    "capture_stopped": False,
    "pcaps_done": False,
    "r1_done": False,
    "llm_done": False,
    "complete": False,
    "requested_at": None,
    "completed_at": None,
}

STATS = {
    "total":      0,
    "attacks_r1": 0,
    "attacks_r3": 0,
    "agree":      0,
    "disagree":   0,
    "llm_pending":0,
}
STATS_LOCK = threading.Lock()

BENIGN_LABELS = {"Benign", "BENIGN", "benign", "Normal", "normal"}

def load_state():
    global FLOWS, STATS
    if os.path.exists("nids_history.json"):
        try:
            with open("nids_history.json", "r") as f:
                data = json.load(f)
                with FLOWS_LOCK:
                    FLOWS = deque(data.get("flows", []), maxlen=5000)
                STATS.update(data.get("stats", {}))
                
            with STATS_LOCK:
                STATS["llm_pending"] = 0
                
            enqueued = 0
            with FLOWS_LOCK:
                snapshot = list(FLOWS)
            for rec in snapshot:
                if rec.get("agreement") == "pending":
                    flow_text = format_flow_for_llm(rec)
                    r1_label = rec.get("r1_label", "")
                    is_attack = r1_label not in BENIGN_LABELS
                    if r1_label == "DoS/Flood (Heuristics)":
                        priority = 0
                    elif is_attack:
                        priority = 1
                    else:
                        priority = 2
                    try:
                        LLM_QUEUE.put_nowait((priority, next(LLM_QUEUE_COUNTER), rec["id"], flow_text, rec))
                        enqueued += 1
                    except Full:
                        pass
                        
            with STATS_LOCK:
                STATS["llm_pending"] += enqueued

            print(f"  ✓ Loaded history: {len(FLOWS)} flows ({enqueued} pending queued for LLM)\n")
        except Exception as e:
            print(f"  ⚠ Failed to load history: {e}\n")

def state_saver_worker():
    while True:
        time.sleep(2)
        try:
            with STATS_LOCK:
                s = dict(STATS)
            with FLOWS_LOCK:
                fl = list(FLOWS)
            tmp_path = "nids_history.json.tmp"
            with open(tmp_path, "w") as f:
                json.dump({"flows": fl, "stats": s}, f)
            os.replace(tmp_path, "nids_history.json")
            _fix_ownership("nids_history.json")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# ROLE 1 — ML Model
# ══════════════════════════════════════════════════════════════════════════════

def load_model(pkl_path, shap_mode="xgb", pcap_extractor="fast"):
    out      = joblib.load(pkl_path)
    ensemble = out["ensemble"]
    le       = out["label_encoder"]
    feats    = out["sub_features"]["CICIDS2017"]

    # FIX: use CICIDS2017's own scaler (out["sub_scalers"]["CICIDS2017"]),
    # not the deprecated single global "whichever dataset was inserted
    # first" scaler (out["scaler"]). The old code used the global one —
    # it only happened to be correct because CICIDS2017 is trained first
    # in the training notebook, which is a coincidence of run order, not
    # something this file can rely on.
    sub_scalers = out.get("sub_scalers") or {}
    scaler = sub_scalers.get("CICIDS2017")
    if scaler is None:
        scaler = out.get("scaler")
        print("  ⚠ No out['sub_scalers']['CICIDS2017'] in this pickle — "
              "falling back to the legacy global out['scaler']. This is "
              "only correct if CICIDS2017 was the first dataset trained "
              "into it; re-export the model to get a per-dataset scaler.")

    # Warn once, at startup, about which of this model's features NFStream
    # cannot supply and nflow_to_vec() must approximate or leave at zero.
    #
    # BUG FIX: the previous set used internal snake_case aliases
    # ("fwd_header_len") instead of the canonical names stored in feats
    # ("Fwd Header Length"), so the intersection was always empty and
    # this warning NEVER fired — silently hiding the data-quality gap.
    #
    # Status after nflow_to_vec() fixes:
    #   Fwd Header Length     → ESTIMATED  (src2dst_packets × 20)
    #   Init_Win_bytes_forward → zero       (TCP SYN window, not in NFStream)
    #   Init_Win_bytes_backward → zero      (TCP SYN window, not in NFStream)
    #   Active/Idle stats     → zero        (training median = 0, so CORRECT)
    always_zero = {
        "Init_Win_bytes_forward",   # TCP initial window — not in NFStream
        "Init_Win_bytes_backward",  # TCP initial window — not in NFStream
    }
    always_estimated = {
        "Fwd Header Length",  # estimated as src2dst_packets × 20
    }
    if pcap_extractor == "fast":
        print("  ✓ Feature extractor: fast packet-aligned dpkt (extracts real TCP Init_Win, "
              "payload sizes, act_data_pkt_fwd, min_seg_size_forward, Fwd Header Length)")
    else:
        zero_filled  = [f for f in feats if f in always_zero]
        estimated    = [f for f in feats if f in always_estimated]
        if zero_filled:
            pct = 100 * len(zero_filled) / max(1, len(feats))
            print(f"  ⚠  {len(zero_filled)}/{len(feats)} ({pct:.0f}%) features "
                  f"unavailable from NFStream → permanently zero: {sorted(zero_filled)}\n"
                  f"     training_median(Init_Win_bytes_forward)=251, IQR=8193 "
                  f"→ scaled(0)=−0.031 (negligible impact)")
        if estimated:
            print(f"  ℹ  {len(estimated)} feature(s) estimated from NFStream proxies: "
                  f"{sorted(estimated)}\n"
                  f"     Fwd Header Length = src2dst_packets × 20 (TCP min header)")

    explainers = None
    if shap_mode != "none":
        try:
            import shap
            model = ensemble.sub_models["CICIDS2017"]
            xgb_base = None
            rf_base = None
            w_xgb = 1.0
            w_rf = 0.0

            if hasattr(model, 'xgb_model') and hasattr(model, 'rf_model'):
                w_xgb = getattr(model, 'w_xgb', 0.5)
                w_rf = getattr(model, 'w_rf', 0.5)

                # Extract XGB
                if hasattr(model.xgb_model, 'calibrated_classifiers_'):
                    clf = model.xgb_model.calibrated_classifiers_[0]
                    if hasattr(clf, 'estimator'): xgb_base = clf.estimator
                    elif hasattr(clf, 'base_estimator'): xgb_base = clf.base_estimator
                else:
                    xgb_base = model.xgb_model

                if shap_mode == "full":
                    # Extract RF only when full hybrid SHAP is explicitly requested
                    # (TreeExplainer on 450-tree RF adds ~390 MB RAM and ~747 ms/flow)
                    if hasattr(model.rf_model, 'calibrated_classifiers_'):
                        clf = model.rf_model.calibrated_classifiers_[0]
                        if hasattr(clf, 'estimator'): rf_base = clf.estimator
                        elif hasattr(clf, 'base_estimator'): rf_base = clf.base_estimator
                    else:
                        rf_base = model.rf_model
            else:
                if hasattr(model, 'calibrated_classifiers_'):
                    clf = model.calibrated_classifiers_[0]
                    if hasattr(clf, 'estimator'): xgb_base = clf.estimator
                    elif hasattr(clf, 'base_estimator'): xgb_base = clf.base_estimator
                else:
                    xgb_base = model

            explainer_xgb = shap.TreeExplainer(xgb_base) if xgb_base is not None else None
            explainer_rf = shap.TreeExplainer(rf_base) if (rf_base is not None and shap_mode == "full") else None

            explainers = (explainer_xgb, explainer_rf, w_xgb, w_rf)
        except Exception as e:
            print(f"  ⚠ SHAP init failed: {e}")

    return ensemble, le, scaler, feats, explainers

def nflow_to_vec(f, feats):
    dur_ms = f.bidirectional_duration_ms or 1e-3
    dur_s  = dur_ms / 1000.0
    raw = {
        # Keys MUST match model's CICFlowMeter column names exactly —
        # raw.get(ft, 0) is a direct lookup; any snake_case alias → 0
        "Destination Port":              f.dst_port,
        "Flow Duration":                 dur_ms * 1000,
        "Total Fwd Packets":             f.src2dst_packets,
        "Total Backward Packets":        f.dst2src_packets,
        "Total Length of Fwd Packets":   f.src2dst_bytes,
        "Total Length of Bwd Packets":   f.dst2src_bytes,
        "Fwd Packet Length Max":         f.src2dst_max_ps,
        "Fwd Packet Length Min":         f.src2dst_min_ps,
        "Fwd Packet Length Mean":        f.src2dst_mean_ps,
        "Fwd Packet Length Std":         f.src2dst_stddev_ps,
        "Bwd Packet Length Max":         f.dst2src_max_ps,
        "Bwd Packet Length Min":         f.dst2src_min_ps,
        "Bwd Packet Length Mean":        f.dst2src_mean_ps,
        "Flow Bytes/s":                  f.bidirectional_bytes   / dur_s,
        "Flow Packets/s":                f.bidirectional_packets / dur_s,
        "Flow IAT Mean":                 f.bidirectional_mean_piat_ms   * 1000,
        "Flow IAT Std":                  f.bidirectional_stddev_piat_ms * 1000,
        "Flow IAT Max":                  f.bidirectional_max_piat_ms    * 1000,
        "Flow IAT Min":                  f.bidirectional_min_piat_ms    * 1000,
        "Fwd IAT Mean":                  f.src2dst_mean_piat_ms   * 1000,
        "Fwd IAT Std":                   f.src2dst_stddev_piat_ms * 1000,
        "Fwd IAT Min":                   f.src2dst_min_piat_ms    * 1000,
        "Bwd IAT Total":                 f.dst2src_duration_ms    * 1000,
        "Bwd IAT Mean":                  f.dst2src_mean_piat_ms   * 1000,
        "Bwd IAT Std":                   f.dst2src_stddev_piat_ms * 1000,
        "Bwd IAT Max":                   f.dst2src_max_piat_ms    * 1000,
        "Bwd IAT Min":                   f.dst2src_min_piat_ms    * 1000,
        "Fwd PSH Flags":                 f.src2dst_psh_packets,
        "Fwd URG Flags":                 f.src2dst_urg_packets,
        # FIX: Fwd Header Length was hardcoded to 0, but training_median=64
        # and IQR=104, so zero scaled to (0−64)/104 = −0.615 — a significant
        # negative shift that biased every flow toward the Benign class.
        # CICFlowMeter stores the TOTAL TCP header length across all forward
        # packets. TCP minimum header = 20 bytes, so src2dst_packets × 20 is
        # a conservative lower-bound estimate that is far better than zero.
        # For ~3 packets: 3×20=60 ≈ training_median=64 → scaled ≈ −0.04 ✓
        "Fwd Header Length":             getattr(f, "fwd_header_bytes", f.src2dst_packets * 20),
        "Bwd Packets/s":                 f.dst2src_packets       / dur_s,
        "Min Packet Length":             f.bidirectional_min_ps,
        "Max Packet Length":             f.bidirectional_max_ps,
        "Packet Length Mean":            f.bidirectional_mean_ps,
        "Packet Length Variance":        f.bidirectional_stddev_ps ** 2,
        "FIN Flag Count":                f.bidirectional_fin_packets,
        "RST Flag Count":                f.bidirectional_rst_packets,
        "PSH Flag Count":                f.bidirectional_psh_packets,
        "ACK Flag Count":                f.bidirectional_ack_packets,
        "URG Flag Count":                f.bidirectional_urg_packets,
        "CWE Flag Count":                f.bidirectional_cwr_packets,
        "Down/Up Ratio":                 (f.dst2src_packets / f.src2dst_packets if f.src2dst_packets > 0 else 0),
        "Init_Win_bytes_forward":        getattr(f, "init_win_bytes_fwd", 0),
        "Init_Win_bytes_backward":       getattr(f, "init_win_bytes_bwd", 0),
        "act_data_pkt_fwd":              getattr(f, "act_data_pkt_fwd", f.src2dst_packets),
        "min_seg_size_forward":          getattr(f, "min_seg_size_fwd", 20 if f.protocol == 6 else (8 if f.protocol == 17 else 0)),
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
        "Idle Mean":   0, "Idle Std":   0,
    }
    return np.array([float(raw.get(ft, 0)) for ft in feats], dtype=np.float32)

_PROBA_LOG_PATH = "data/results/role1_proba_debug.jsonl"
os.makedirs(os.path.dirname(_PROBA_LOG_PATH), exist_ok=True)

# FIX: when running under sudo, files/dirs created by root become
# inaccessible to the regular user later (cleanup, analysis scripts).
# Detect SUDO_USER and chown everything we create back to the real user.
_SUDO_UID = int(os.environ.get("SUDO_UID", 0)) or None
_SUDO_GID = int(os.environ.get("SUDO_GID", 0)) or None

def _fix_ownership(path):
    """If running under sudo, chown path back to the real user."""
    if _SUDO_UID and _SUDO_GID:
        try:
            os.chown(path, _SUDO_UID, _SUDO_GID)
        except OSError:
            pass

# Fix ownership of data directories created by previous sudo runs
if _SUDO_UID:
    for d in ["data", "data/results", "data/cicflow_csv"]:
        if os.path.isdir(d):
            _fix_ownership(d)

_proba_log_lock = threading.Lock()

# Features that are permanently zero-filled in nflow_to_vec() because
# NFStream cannot supply them at flow level. Used by the SHAP debug log to
# flag cases where a fabricated zero has non-trivial influence on the
# prediction — the signal we want to surface before publishing results.
#
# BUG FIX: previous set used snake_case aliases ("fwd_header_len") that
# never matched the canonical feature names ("Fwd Header Length") stored
# in feats, so the SHAP log column was always empty.  Canonical names used
# below.  "Fwd Header Length" is now ESTIMATED rather than zero-filled, so
# it is excluded from this set.
_ALWAYS_ZERO_FEATURES = {
    "Init_Win_bytes_forward",   # TCP SYN window — not exposed by NFStream
    "Init_Win_bytes_backward",  # TCP SYN window — not exposed by NFStream
    # Active/Idle stats: training_median = 0 for all → zero IS the median value
}


def _log_role1_proba(flow, le, proba, top_idx, top_label, top_conf,
                      feats=None, signed_benign=None):
    """
    Append the full per-class probability distribution for this flow to a
    JSONL debug log, and print a one-line console flag for anything
    non-trivial (a non-Benign class scoring meaningfully, or the top two
    classes sitting close together) so borderline/wrong calls are visible
    live instead of only discoverable after the fact by grepping the file.

    If feats/signed_benign are provided (SIGNED SHAP contribution toward
    the Benign class specifically, not the absolute-value/cross-class
    average role1_run() already returns to its caller for the UI), also
    records which of the permanently zero-filled features (see
    _ALWAYS_ZERO_FEATURES) are actually pushing this flow toward Benign,
    and by how much relative to the flow's genuine (non-fabricated)
    features — the direct test of whether zero-filling is degrading live
    verdicts, rather than inferring it from training-data statistics.
    """
    classes = le.classes_
    row_probs = proba[0]
    dist = {str(c): round(float(p) * 100, 2) for c, p in zip(classes, row_probs)}

    order = sorted(dist.items(), key=lambda kv: kv[1], reverse=True)
    second_label, second_conf = order[1] if len(order) > 1 else (None, 0.0)

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": flow.src_ip, "src_port": flow.src_port,
        "dst_ip": flow.dst_ip, "dst_port": flow.dst_port,
        "top_label": top_label, "top_conf": top_conf,
        "second_label": second_label, "second_conf": second_conf,
        "distribution": dist,
    }

    if feats is not None and signed_benign is not None:
        # Positive SHAP value on the Benign class = pushes toward Benign.
        pairs = sorted(
            zip(feats, (float(v) for v in signed_benign)),
            key=lambda fv: fv[1], reverse=True,
        )
        zero_set = set() if hasattr(flow, "init_win_bytes_fwd") else _ALWAYS_ZERO_FEATURES
        zero_feature_push = {
            f: round(v, 4) for f, v in pairs if f in zero_set
        }
        real_feature_top5 = [
            (f, round(v, 4)) for f, v in pairs if f not in zero_set
        ][:5]
        zero_total = sum(zero_feature_push.values())
        real_total = sum(v for _f, v in real_feature_top5)
        record["shap_toward_benign"] = {
            "always_zero_features": zero_feature_push,
            "always_zero_total_push": round(zero_total, 4),
            "top5_real_features": real_feature_top5,
            "top5_real_total_push": round(real_total, 4),
        }
        if zero_total > 0 and zero_total > real_total:
            _rl_print(
                f"  🧪 zero-filled features outweigh real ones pushing "
                f"toward Benign: {flow.src_ip}:{flow.dst_port} → "
                f"fabricated={zero_total:.3f} vs real_top5={real_total:.3f} "
                f"({zero_feature_push})"
            )

    try:
        with _proba_log_lock:
            with open(_PROBA_LOG_PATH, "a") as f:
                f.write(json.dumps(record) + "\n")
            _fix_ownership(_PROBA_LOG_PATH)
    except OSError as exc:
        print(f"  ⚠ could not write {_PROBA_LOG_PATH}: {exc}")

    # Flag live: any non-Benign class scoring >10%, even if it lost, OR the
    # top two classes within 15 points of each other (a genuinely close call).
    non_benign_notable = [
        (c, p) for c, p in dist.items() if c != "Benign" and p > 10.0
    ]
    close_call = second_label is not None and (top_conf - second_conf) < 15.0
    if non_benign_notable or close_call:
        flags = ", ".join(f"{c}={p}%" for c, p in non_benign_notable) or "n/a"
        _rl_print(
            f"  🔎 proba flag {flow.src_ip}:{flow.dst_port} → "
            f"top={top_label}({top_conf}%) 2nd={second_label}({second_conf}%) "
            f"notable_non_benign=[{flags}]"
        )


def role1_run(flow, ensemble, le, scaler, feats, explainers=None):
    row   = nflow_to_vec(flow, feats).reshape(1, -1)
    if scaler is not None:
        # FIX: the old code did `try: row = scaler.transform(row) except:
        # pass` — on any shape mismatch it silently fed UNSCALED values to
        # a model trained on scaled input, with no warning, producing a
        # confident but meaningless prediction. That's the exact bug
        # UniversalEnsemble.transform() was rewritten to prevent
        # elsewhere in this pipeline. Fail loud instead: the caller
        # (nfstream_thread) already wraps this call in try/except and
        # just logs+skips the flow, so raising here costs one flow, not
        # a silently-wrong classification.
        n_expected = getattr(scaler, "n_features_in_", row.shape[1])
        if row.shape[1] != n_expected:
            raise ValueError(
                f"role1_run: feature vector has {row.shape[1]} columns but "
                f"the scaler expects {n_expected} — refusing to predict on "
                f"unscaled input. Check feats/nflow_to_vec against the "
                f"scaler this model was actually trained with."
            )
        row = scaler.transform(row)
    proba = ensemble.predict_proba_from_dataset(row, "CICIDS2017")
    idx   = int(proba.argmax())
    label = le.inverse_transform([idx])[0]
    conf  = round(float(proba[0, idx]) * 100, 1)

    top_features = []
    signed_benign = None
    if explainers is not None:
        explainer_xgb, explainer_rf, w_xgb, w_rf = explainers
        try:
            vals_xgb = np.zeros(len(feats))
            vals_rf = np.zeros(len(feats))
            # DIAGNOSTIC: signed contribution toward the Benign class
            # specifically — the existing top_features below is abs-value
            # and averaged across ALL classes, which tells the UI "what
            # mattered" but can't say whether a feature pushed toward or
            # away from Benign. This is what actually tests whether the
            # permanently zero-filled features (_ALWAYS_ZERO_FEATURES,
            # NFStream can't supply them) are dragging otherwise-correct
            # verdicts toward Benign, rather than just being unused noise.
            signed_benign_xgb = np.zeros(len(feats))
            signed_benign_rf = np.zeros(len(feats))
            benign_class_idx = (
                list(le.classes_).index("Benign") if "Benign" in le.classes_ else None
            )

            if explainer_xgb is not None:
                shap_vals = explainer_xgb.shap_values(row)
                if isinstance(shap_vals, list):
                    vals_xgb = np.mean([np.abs(sv[0]) for sv in shap_vals], axis=0)
                    if benign_class_idx is not None and benign_class_idx < len(shap_vals):
                        signed_benign_xgb = np.asarray(shap_vals[benign_class_idx][0])
                elif isinstance(shap_vals, np.ndarray):
                    if len(shap_vals.shape) == 3:
                        vals_xgb = np.abs(shap_vals[0]).mean(axis=1)
                        if benign_class_idx is not None and benign_class_idx < shap_vals.shape[2]:
                            signed_benign_xgb = shap_vals[0, :, benign_class_idx]
                    else:
                        vals_xgb = np.abs(shap_vals[0])

            if explainer_rf is not None:
                shap_vals = explainer_rf.shap_values(row)
                if isinstance(shap_vals, list):
                    vals_rf = np.mean([np.abs(sv[0]) for sv in shap_vals], axis=0)
                    if benign_class_idx is not None and benign_class_idx < len(shap_vals):
                        signed_benign_rf = np.asarray(shap_vals[benign_class_idx][0])
                elif isinstance(shap_vals, np.ndarray):
                    if len(shap_vals.shape) == 3:
                        vals_rf = np.abs(shap_vals[0]).mean(axis=1)
                        if benign_class_idx is not None and benign_class_idx < shap_vals.shape[2]:
                            signed_benign_rf = shap_vals[0, :, benign_class_idx]
                    else:
                        vals_rf = np.abs(shap_vals[0])

            vals = (w_xgb * vals_xgb) + (w_rf * vals_rf)
            if benign_class_idx is not None:
                signed_benign = (w_xgb * signed_benign_xgb) + (w_rf * signed_benign_rf)

            if np.sum(vals) > 0:
                top_indices = np.argsort(vals)[-3:][::-1]
                top_features = [(feats[i], round(float(vals[i]), 4)) for i in top_indices]
        except Exception:
            pass

    # DIAGNOSTIC: is the model confidently wrong, or genuinely borderline?
    # Every live test so far has had zero non-benign verdicts straight from
    # the model (only the heuristic has ever fired) — this records the FULL
    # probability distribution, not just the winning label, so we can tell
    # those two failure modes apart: near-uniform/second-place-close-behind
    # means a threshold/calibration issue; Benign sitting near 100% while
    # everything else is near 0% means the model genuinely doesn't
    # recognize this flow shape (feature drift), a different problem.
    _log_role1_proba(flow, le, proba, idx, label, conf,
                      feats=feats, signed_benign=signed_benign)

    return label, conf, top_features

def _benign_index_in_submodel(ensemble, le):
    """Index of the Benign class in the CICIDS2017 SUB-model's own label
    space (what the XGB explainer's class axis uses), not the universal one."""
    try:
        sub_le = ensemble.sub_le["CICIDS2017"]
        lm = getattr(ensemble, "label_map", {}) or {}
        for i, c in enumerate(sub_le.classes_):
            if str(lm.get(c, c)) in BENIGN_LABELS or str(c) in BENIGN_LABELS:
                return i
    except Exception:
        pass
    classes = [str(c) for c in le.classes_]
    return classes.index("Benign") if "Benign" in classes else None


def role1_batch(flows, ensemble, le, scaler, feats, explainers=None,
                shap_mode="xgb"):
    """
    Vectorised Role 1 for a micro-batch of flows.

    PERFORMANCE FIX (measured on this host, i7 / 8 threads, no GPU):
      per-flow role1_run():  RF predict_proba 42 ms + RF TreeSHAP 747 ms
                             + XGB TreeSHAP 6 ms  ≈ 834 ms / flow
    → the capture thread could classify ~1 flow/s, so any scan or flood
      built an hours-long backlog and every latency figure became an
      artefact of queueing. Here the whole batch is scored with ONE
      predict_proba call (RF/XGB cost is dominated by per-call overhead,
      not per-row work), and SHAP is taken from the XGBoost half of the
      hybrid (TreeSHAP on 450-tree RF is the 747 ms term). The class
      decision itself is unchanged: it is still the full XGB+RF weighted
      ensemble. Only the *explanation* source changes, and it is
      recorded in run_meta.json as shap_source="xgb_component".
    """
    vecs = np.vstack([nflow_to_vec(f, feats) for f in flows])
    X = vecs
    if scaler is not None:
        n_expected = getattr(scaler, "n_features_in_", X.shape[1])
        if X.shape[1] != n_expected:
            raise ValueError(
                f"role1_batch: feature vector has {X.shape[1]} columns but "
                f"the scaler expects {n_expected} — refusing to predict on "
                f"unscaled input."
            )
        X = scaler.transform(X)
    proba = ensemble.predict_proba_from_dataset(X, "CICIDS2017")
    classes = [str(c) for c in le.classes_]

    shap_abs = signed_benign = None
    if shap_mode == "xgb" and explainers is not None and explainers[0] is not None:
        try:
            sv = explainers[0].shap_values(X)
            arr = np.stack(sv, axis=-1) if isinstance(sv, list) else np.asarray(sv)
            if arr.ndim == 2:
                arr = arr[:, :, None]
            shap_abs = np.abs(arr).mean(axis=2)
            b = _benign_index_in_submodel(ensemble, le)
            if b is not None and arr.shape[2] > b:
                signed_benign = arr[:, :, b]
        except Exception as exc:
            _rl_print(f"  ⚠ batch SHAP failed: {exc}")

    out = []
    for i in range(len(flows)):
        idx = int(proba[i].argmax())
        label = str(le.inverse_transform([idx])[0])
        conf = round(float(proba[i, idx]) * 100, 1)
        top = []
        if shap_abs is not None and shap_abs[i].sum() > 0:
            ti = np.argsort(shap_abs[i])[-3:][::-1]
            top = [(feats[j], round(float(shap_abs[i, j]), 4)) for j in ti]
        top_signed = []
        if signed_benign is not None:
            si = np.argsort(np.abs(signed_benign[i]))[-3:][::-1]
            top_signed = [(feats[j], round(float(signed_benign[i, j]), 4)) for j in si]
        out.append({
            "label": label, "conf": conf, "top": top, "top_signed": top_signed, "idx": idx,
            "proba_row": proba[i:i + 1],
            "dist": {c: round(float(p) * 100, 2) for c, p in zip(classes, proba[i])},
            "vec": vecs[i],
            "signed_benign": None if signed_benign is None else signed_benign[i],
        })
    return out


_RL_STATE = {"t": 0.0, "n": 0, "dropped": 0}
_RL_LOCK = threading.Lock()


def _rl_print(msg, per_sec=3):
    """Rate-limited console print: a flood can emit thousands of flagged
    flows per second, and printing each one stalls the capture loop."""
    with _RL_LOCK:
        now = time.time()
        if now - _RL_STATE["t"] >= 1.0:
            if _RL_STATE["dropped"]:
                print(f"  … {_RL_STATE['dropped']} similar console lines suppressed")
            _RL_STATE.update(t=now, n=0, dropped=0)
        if _RL_STATE["n"] < per_sec:
            _RL_STATE["n"] += 1
            print(msg)
        else:
            _RL_STATE["dropped"] += 1


# ══════════════════════════════════════════════════════════════════════════════
# ROLE 3 — LLM Analyst (Optimized for Sub-Second CPU Inference)
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are a network security analyst in a real-time NIDS.
Output ONLY a JSON object matching this exact schema, nothing else:
{
  "verdict": "attack" or "suspicious" or "benign",
  "attack_type": "DoS" or "PortScan" or "Brute Force" or "Web Attack" or "Bot" or "DDoS" or "Normal" or "Unknown",
  "confidence": integer 0 to 100,
  "explanation": "One clear sentence citing specific flow rate, port, HTTP/flag, or signed SHAP evidence.",
  "recommended_action": "Recommended action to mitigate the threat or monitor safely."
}

Decision rules:
- Use "attack" ONLY when there is clear malicious behavior: high flow rate (>20 flows in 15s), multi-port probing (>10 distinct_dst_ports -> attack_type="PortScan"), high-rate SYN/flood to 1-3 ports (attack_type="DoS"), repeated HTTP probes/requests (attack_type="Web Attack"), repeated auth-port connections (attack_type="Brute Force"), or a Role 1 Behavioral/Heuristic verdict.
- Use "benign" when Role 1 predicts Benign AND 15s behavioral rates are low (<=5 flows, <=2 destination ports), especially for LAN discovery/control traffic (ICMP, IGMP, mDNS port 5353, SSDP port 1900, DHCP, NTP) or normal single connections.
- Note on signed SHAP: SHAP listed as "supporting Benign" pushed the ML classifier AWAY from attack, NOT toward an attack. Never label a low-rate Benign flow as PortScan merely because Destination Port supports Benign."""

_HTTP_TLS = threading.local()


def _get_http_session():
    sess = getattr(_HTTP_TLS, "session", None)
    if sess is None:
        sess = requests.Session()
        _HTTP_TLS.session = sess
    return sess


def role3_run_detailed(flow_text, ollama_url, model, timeout=60):
    """Same request as role3_run, but returns (verdict|None, raw_text, error)
    so every LLM call can be audited (parse failures, timeouts, HTTP errors)
    instead of collapsing all failure modes into None."""
    _install_resilient_dns()
    raw = None
    sess = _get_http_session()
    payload = {
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": flow_text,
        "stream": False,
        "format": "json",
        "keep_alive": "1h",
        "options": {"temperature": 0.0, "num_predict": 400},
    }
    for attempt in range(2):
        try:
            resp = sess.post(f"{ollama_url}/api/generate", json=payload, timeout=timeout)
            if resp.status_code != 200:
                return None, resp.text[:500], f"http_{resp.status_code}"
            body = resp.json()
            raw = body.get("response", "{}")
            v = json.loads(raw) if isinstance(raw, str) else raw
            if not isinstance(v, dict):
                return None, str(raw)[:2000], "parse_not_object"
            v.setdefault("verdict", "unknown")
            v.setdefault("attack_type", "Unknown")
            v.setdefault("confidence", 0)
            v.setdefault("explanation", "No explanation provided.")
            v.setdefault("recommended_action", "")
            normalize_llm_verdict(v)
            v["_ollama_eval_count"] = body.get("eval_count")
            v["_ollama_total_duration_ms"] = (body.get("total_duration") or 0) / 1e6
            return v, raw if isinstance(raw, str) else json.dumps(raw), None
        except requests.Timeout:
            return None, raw, "timeout"
        except json.JSONDecodeError:
            return None, (raw or "")[:2000] if isinstance(raw, str) else raw, "parse_json_error"
        except requests.exceptions.ConnectionError as exc:
            if attempt == 0:
                time.sleep(0.5)
                continue
            return None, raw, f"exception:{type(exc).__name__}:{exc}"
        except Exception as exc:
            return None, raw, f"exception:{type(exc).__name__}:{exc}"


def role3_run(fid, flow_text, ollama_url, model, timeout=15):
    try:
        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": model, 
                "system": SYSTEM_PROMPT,
                "prompt": flow_text, 
                "stream": False,
                "format": "json",       # Native JSON mode (drastically faster)
                "keep_alive": "1h",     # Keep model locked in RAM
                "options": {
                    "temperature": 0.0, # Greedy decoding (faster)
                    "num_predict": 400  # Hard cap on generated tokens
                }
            },
            timeout=timeout,
        )
        if resp.status_code != 200: return None
        v = resp.json().get("response", "{}")
        if isinstance(v, str): v = json.loads(v)
        
        v.setdefault("verdict", "unknown")
        v.setdefault("attack_type", "Unknown")
        v.setdefault("confidence", 0)
        v.setdefault("explanation", "No explanation provided.")
        v.setdefault("recommended_action", "")
        v["verdict"] = str(v["verdict"]).lower()
        return v
    except Exception:
        return None

def format_flow_for_llm(rec):
    ctx = rec.get("behavioral_ctx") or {}
    is_ctrl = bool(ctx.get("is_control"))
    role_desc = (
        "LAN discovery/control packet (multicast/ICMP/broadcast)" if is_ctrl
        else ("HTTP application traffic" if ctx.get("http_requests", 0) > 0 or rec.get("dst_port") in (80, 443, 8000, 8080, 8443) else "unicast network flow")
    )
    r1_lbl = rec.get("r1_label", "Benign")
    r1_is_atk = r1_lbl not in BENIGN_LABELS

    base_text = (
        f"Network flow:\n"
        f"  {rec['src_ip']}:{rec['src_port']} -> {rec['dst_ip']}:{rec['dst_port']} [{rec['protocol']}]\n"
        f"  Traffic role: {role_desc}\n"
        f"  Duration: {rec['duration_ms']/1000:.3f}s  Packets: {rec['packets']}  Bytes: {rec['bytes']}  HTTP_reqs: {ctx.get('http_requests', 0)}\n"
        f"  Flags: FIN={rec['fin_flags']} SYN={rec['syn_flags']} RST={rec['rst_flags']} "
        f"PSH={rec['psh_flags']} ACK={rec['ack_flags']}\n"
        f"  15s source activity: flows={ctx.get('flows_15s', 1)}  distinct_dst_ports={ctx.get('ports_15s', 1)}  "
        f"half_open_syns={ctx.get('half_open_15s', 0)}  web_flows_30s={ctx.get('web_flows_30s', 0)}  web_http_reqs_30s={ctx.get('web_http_reqs_30s', 0)}\n"
        f"  Role 1 verdict: {r1_lbl} ({rec['r1_conf']}%)\n"
    )
    signed = rec.get("r1_shap_signed")
    if signed:
        if r1_is_atk:
            shap_str = ", ".join(f"{f} ({v:+.2f})" for f, v in signed)
            base_text += f"  Role 2 SHAP evidence: {shap_str}\n"
        else:
            benign_push = [(f, v) for f, v in signed if v > 0]
            atk_push = [(f, -v) for f, v in signed if v < 0]
            if benign_push:
                base_text += "  Role 2 SHAP evidence supporting Benign: " + ", ".join(f"{f} (+{v:.2f})" for f, v in benign_push) + "\n"
            if atk_push:
                base_text += "  Role 2 SHAP evidence opposing Benign: " + ", ".join(f"{f} (-{v:.2f})" for f, v in atk_push) + "\n"
    elif rec.get("r1_shap"):
        shap_str = ", ".join([f"{f}={v}" for f, v in rec["r1_shap"]])
        base_text += f"  Role 2 SHAP features: {shap_str}\n"

    base_text += "Classify this flow."
    return base_text

# ══════════════════════════════════════════════════════════════════════════════
# SSE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def push_event(event_type: str, data: dict):
    """Push an SSE event to all connected browser tabs."""
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with SSE_LOCK:
        dead = []
        for q in SSE_CLIENTS:
            try:
                q.put_nowait(msg)
            except Full:
                dead.append(q)
        for q in dead:
            SSE_CLIENTS.remove(q)

def agreement_status(r1_label, r3_verdict):
    """Classify agreement between Role 1 and Role 3."""
    if r3_verdict is None:
        return "pending"
    r1_attack = r1_label not in BENIGN_LABELS
    r3_attack = is_attack_verdict(r3_verdict.get("verdict"))
    if r1_attack and r3_attack:   return "agree_attack"
    if not r1_attack and not r3_attack: return "agree_benign"
    return "disagree"

# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND THREADS
# ══════════════════════════════════════════════════════════════════════════════

RUN_LOGGER = None          # set in main(): src.live.run_logger.RunLogger
ENQ_TIME = {}              # fid -> epoch when queued for Role 3
FLOW_INBOX = Queue(maxsize=500000)   # capture reader -> Role 1 batcher


def llm_worker(ollama_url, model, timeout):
    """Background thread: dequeue flows, run Ollama, push SSE update,
    and append a full audit record of the call to r3.jsonl."""
    while True:
        item = LLM_QUEUE.get()
        if item is None or item[2] is None:
            LLM_QUEUE.task_done()
            break
        priority, count, fid, flow_text, rec = item
        t_start = time.time()
        r3, raw, err = role3_run_detailed(flow_text, ollama_url, model, timeout)
        t_end = time.time()
        t_enq = ENQ_TIME.pop(fid, None)

        with STATS_LOCK:
            STATS["llm_pending"] = max(0, STATS["llm_pending"] - 1)
            if r3:
                r3_atk = is_attack_verdict(r3.get("verdict"))
                r1_atk = rec["r1_label"] not in BENIGN_LABELS
                if r3_atk: STATS["attacks_r3"] += 1
                if r1_atk == r3_atk: STATS["agree"] += 1
                else:                STATS["disagree"] += 1

        agreement = agreement_status(rec["r1_label"], r3)
        with FLOWS_LOCK:
            for f in FLOWS:
                if f["id"] == fid:
                    f["r3_verdict"]    = r3.get("verdict")     if r3 else "error"
                    f["r3_attack_type"]= r3.get("attack_type") if r3 else "Unknown"
                    f["r3_conf"]       = r3.get("confidence")  if r3 else 0
                    f["r3_explanation"]= r3.get("explanation") if r3 else f"LLM error: {err}"
                    f["r3_action"]     = r3.get("recommended_action") if r3 else ""
                    f["agreement"]     = agreement
                    break

        if RUN_LOGGER is not None:
            try:
                RUN_LOGGER.log_r3({
                    "id": fid,
                    "src_ip": rec.get("src_ip"), "src_port": rec.get("src_port"),
                    "dst_ip": rec.get("dst_ip"), "dst_port": rec.get("dst_port"),
                    "protocol": rec.get("protocol"),
                    "r1_label": rec.get("r1_label"), "r1_conf": rec.get("r1_conf"),
                    "priority": priority,
                    "t_enqueued": t_enq, "t_start": t_start, "t_end": t_end,
                    "queue_wait_ms": round((t_start - t_enq) * 1000, 1) if t_enq else None,
                    "latency_ms": round((t_end - t_start) * 1000, 1),
                    "status": "ok" if r3 else "error",
                    "error": err,
                    "verdict": r3.get("verdict") if r3 else None,
                    "raw_verdict": r3.get("raw_verdict") if r3 else None,
                    "attack_type": r3.get("attack_type") if r3 else None,
                    "confidence": r3.get("confidence") if r3 else None,
                    "explanation": r3.get("explanation") if r3 else None,
                    "recommended_action": r3.get("recommended_action") if r3 else None,
                    "ollama_eval_count": r3.get("_ollama_eval_count") if r3 else None,
                    "ollama_total_duration_ms": r3.get("_ollama_total_duration_ms") if r3 else None,
                    "agreement": agreement,
                    "prompt": flow_text,
                    "raw_response": (raw[:2000] if isinstance(raw, str) else raw),
                })
            except Exception as exc:
                _rl_print(f"  ⚠ r3 log failed: {exc}")

        push_event("r3_update", {
            "id":           fid,
            "r3_verdict":   r3.get("verdict")     if r3 else "error",
            "r3_attack_type": r3.get("attack_type") if r3 else "Unknown",
            "r3_conf":      r3.get("confidence")  if r3 else 0,
            "r3_explanation": r3.get("explanation") if r3 else f"LLM error: {err}",
            "r3_action":    r3.get("recommended_action") if r3 else "",
            "agreement":    agreement,
            "stats":        dict(STATS),
        })
        LLM_QUEUE.task_done()


BEHAVIORAL_DETECTOR = StatefulBehavioralDetector(window_sec=15.0, web_window_sec=30.0)
ALERT_STATE = {}  # Tracks last alert time: (src_ip, r1_label) -> float capture-epoch
SERVER_REPLY_R3_STATE = {}  # Rate-limits Role-3 queuing for repetitive flood server replies


def check_cross_flow_attack(flow, t_recv=None):
    """Evaluate generalizable Role-1 stateful behavioral rules using capture time."""
    first_ms = getattr(flow, "bidirectional_first_seen_ms", None)
    ts_s = (first_ms / 1000.0) if first_ms else (t_recv or time.time())
    return BEHAVIORAL_DETECTOR.observe(
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        dst_port=flow.dst_port,
        protocol=flow.protocol,
        ts_s=ts_s,
        src_port=getattr(flow, "src_port", 0),
        syn=getattr(flow, "bidirectional_syn_packets", 0),
        ack=getattr(flow, "bidirectional_ack_packets", 0),
        rst=getattr(flow, "bidirectional_rst_packets", 0),
        payload_bytes=getattr(flow, "bidirectional_bytes", 0),
        total_bytes=getattr(flow, "bidirectional_bytes", 0),
        http_requests=getattr(flow, "http_requests", 0),
    )


DUMPCAP_PROC = None
STOP_CAPTURE = threading.Event()
ACTIVE_PHASE = {"phase": None, "started_at": None, "history": []}
PHASE_LOCK   = threading.Lock()


def _has_raw_capture_cap():
    if os.geteuid() == 0:
        return True
    try:
        import socket
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.close()
        return True
    except Exception:
        return False


def _nfstream_reader(streamer):
    """Producer: pull flows from NFStream as fast as they are exported, so
    the meter processes never block on the (slower) classifier."""
    try:
        for flow in streamer:
            FLOW_INBOX.put((flow, time.time()))
    except Exception as stream_err:
        print(f"  NFStream stream error: {stream_err}", file=sys.stderr)
        if "Unable to activate source" in str(stream_err):
            print("💡 TIP: live capture needs root or CAP_NET_RAW.", file=sys.stderr)
    finally:
        FLOW_INBOX.put(None)


def _dumpcap_capture_reader(iface, bpf_filter, raw_chunks_dir, pcaps_dir,
                            mirror_dir=None, rotate_sec=5, pcap_extractor="fast"):
    """Capture live traffic with dumpcap (works unprivileged for users in
    the 'wireshark' group) writing classic PCAP segments every `rotate_sec`
    seconds, and extract flows for Role 1/2/3 while optionally mirroring
    closed segments to Approach B."""
    global DUMPCAP_PROC
    os.makedirs(raw_chunks_dir, exist_ok=True)
    os.makedirs(pcaps_dir, exist_ok=True)
    if mirror_dir:
        os.makedirs(mirror_dir, exist_ok=True)

    cmd = ["dumpcap", "-i", iface, "-P", "-b", f"duration:{int(rotate_sec)}",
           "-w", os.path.join(raw_chunks_dir, "cap.pcap")]
    if bpf_filter:
        cmd.extend(["-f", bpf_filter])

    try:
        DUMPCAP_PROC = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
        )
    except Exception as exc:
        print(f"\n❌ Failed to start dumpcap: {exc}", file=sys.stderr)
        FLOW_INBOX.put(None)
        return

    time.sleep(0.5)
    if DUMPCAP_PROC.poll() is not None:
        err = DUMPCAP_PROC.stderr.read() if DUMPCAP_PROC.stderr else ""
        print(f"\n❌ dumpcap exited immediately ({DUMPCAP_PROC.returncode}): {err}",
              file=sys.stderr)
        FLOW_INBOX.put(None)
        return

    print(f"  ✓ dumpcap live capture active on {iface} (PID {DUMPCAP_PROC.pid}, "
          f"{rotate_sec}s PCAP segments, extractor={pcap_extractor})")

    def _process_segment(seg_path):
        base = os.path.basename(seg_path)
        archived = os.path.join(pcaps_dir, base)
        try:
            shutil.move(seg_path, archived)
        except Exception:
            return
        if mirror_dir:
            try:
                tmp_dst = os.path.join(mirror_dir, base + ".tmp")
                dst = os.path.join(mirror_dir, base)
                shutil.copy2(archived, tmp_dst)
                os.replace(tmp_dst, dst)
            except Exception as exc:
                _rl_print(f"  ⚠ mirror copy failed for {base}: {exc}")
        try:
            if os.path.getsize(archived) <= 24:
                return
            if pcap_extractor == "fast":
                flows = extract_flows_from_pcap(archived, idle_timeout_s=5.0, active_timeout_s=120.0)
                flows.sort(key=lambda fl: fl.bidirectional_first_seen_ms)
                t_now = time.time()
                for flow in flows:
                    FLOW_INBOX.put((flow, t_now))
            else:
                st = NFStreamer(
                    source=archived,
                    statistical_analysis=True,
                    idle_timeout=5, active_timeout=120,
                    decode_tunnels=False, accounting_mode=0,
                )
                for flow in st:
                    FLOW_INBOX.put((flow, time.time()))
        except Exception as exc:
            _rl_print(f"  ⚠ segment extract error ({base}): {exc}")

    try:
        while not STOP_CAPTURE.is_set():
            if os.path.exists("logs/drain_requested.flag"):
                with DRAIN_LOCK:
                    DRAIN_STATE["requested"] = True
                    DRAIN_STATE["requested_at"] = DRAIN_STATE["requested_at"] or datetime.now(timezone.utc).isoformat()
                STOP_CAPTURE.set()
                break
            files = sorted(glob.glob(os.path.join(raw_chunks_dir, "*.pcap*")))
            # All files except the newest active one are closed and flushed by dumpcap
            if len(files) > 1:
                for seg in files[:-1]:
                    if STOP_CAPTURE.is_set():
                        break
                    _process_segment(seg)
            if DUMPCAP_PROC.poll() is not None and not STOP_CAPTURE.is_set():
                err = DUMPCAP_PROC.stderr.read() if DUMPCAP_PROC.stderr else ""
                print(f"  ⚠ dumpcap stopped unexpectedly: {err}", file=sys.stderr)
                break
            time.sleep(0.5)
    finally:
        if DUMPCAP_PROC is not None and DUMPCAP_PROC.poll() is None:
            try:
                DUMPCAP_PROC.terminate()
                DUMPCAP_PROC.wait(timeout=5)
            except Exception:
                try:
                    DUMPCAP_PROC.kill()
                except Exception:
                    pass
        with DRAIN_LOCK:
            DRAIN_STATE["capture_stopped"] = True
        for seg in sorted(glob.glob(os.path.join(raw_chunks_dir, "*.pcap*"))):
            _process_segment(seg)
        if mirror_dir:
            try:
                done_flag = os.path.join(mirror_dir, "drain_a_pcaps_done")
                with open(done_flag, "w") as f:
                    f.write(datetime.now(timezone.utc).isoformat() + "\n")
            except Exception:
                pass
        with DRAIN_LOCK:
            DRAIN_STATE["pcaps_done"] = True
        push_event("drain_update", _drain_snapshot())
        FLOW_INBOX.put(None)


def _drain_snapshot():
    with DRAIN_LOCK:
        snap = dict(DRAIN_STATE)
    with STATS_LOCK:
        snap["llm_pending"] = STATS.get("llm_pending", 0)
        snap["total_flows"] = STATS.get("total", 0)
    snap["flow_inbox_size"] = FLOW_INBOX.qsize()
    snap["llm_queue_size"] = LLM_QUEUE.qsize()
    snap["b_pipeline_done"] = os.path.exists("data/live_b/drain_b_pipeline_done") or os.path.exists("logs/drain_complete.json")
    snap["both_complete"] = bool(snap.get("complete")) and bool(snap["b_pipeline_done"])
    return snap


def nfstream_thread(source, ensemble, le, scaler, feats, explainers,
                    ollama_url, model, llm_timeout, bpf_filter=None,
                    shap_mode="xgb", batch_max=512, llm_enabled=True,
                    capture_backend="auto", rotate_sec=5, mirror_dir=None,
                    run_dir=None, pcap_extractor="fast", llm_workers=None):
    """Capture reader -> micro-batched Role 1 -> SSE -> Role 3 LLM queue.
    When capture stops cleanly, drains every queued flow and every pending
    LLM call to completion before marking drain_complete."""
    is_pcap_file = os.path.isfile(source)
    use_dumpcap = False
    if not is_pcap_file:
        if capture_backend == "dumpcap":
            use_dumpcap = True
        elif capture_backend == "auto" and not _has_raw_capture_cap():
            use_dumpcap = True

    if use_dumpcap:
        base_dir = run_dir or "data/runs/live_default"
        raw_chunks_dir = os.path.join(base_dir, "raw_chunks")
        pcaps_dir = os.path.join(base_dir, "pcaps")
        threading.Thread(
            target=_dumpcap_capture_reader,
            args=(source, bpf_filter, raw_chunks_dir, pcaps_dir, mirror_dir, rotate_sec, pcap_extractor),
            daemon=True,
        ).start()
    elif is_pcap_file and pcap_extractor == "fast":
        def _fast_pcap_reader():
            t_now = time.time()
            for flow in sorted(extract_flows_from_pcap(source, 5.0, 120.0), key=lambda fl: fl.bidirectional_first_seen_ms):
                FLOW_INBOX.put((flow, t_now))
            with DRAIN_LOCK:
                DRAIN_STATE["capture_stopped"] = True
                DRAIN_STATE["pcaps_done"] = True
            FLOW_INBOX.put(None)
        threading.Thread(target=_fast_pcap_reader, daemon=True).start()
    else:
        try:
            streamer = NFStreamer(
                source=source,
                statistical_analysis=True,
                # CICIDS2017 CICFlowMeter config: flow timeout 120 s, activity
                # timeout 5 s (Engelen et al., IEEE SPW 2021). Do not change
                # without re-checking against the training pipeline.
                idle_timeout=5, active_timeout=120,
                decode_tunnels=False, accounting_mode=0,
                bpf_filter=bpf_filter,
            )
        except Exception as e:
            print(f"\n❌ NFStream failed to open capture source '{source}': {e}", file=sys.stderr)
            print("💡 Live capture needs root or CAP_NET_RAW on the interpreter, or --capture-backend dumpcap.", file=sys.stderr)
            return

        threading.Thread(target=_nfstream_reader, args=(streamer,), daemon=True).start()

    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP", 58: "ICMPv6"}
    done = False
    while not done:
        item = FLOW_INBOX.get()
        if item is None:
            break
        batch = [item]
        while len(batch) < batch_max:
            try:
                nxt = FLOW_INBOX.get_nowait()
            except Empty:
                break
            if nxt is None:
                done = True
                break
            batch.append(nxt)

        t0 = time.time()
        try:
            results = role1_batch([b[0] for b in batch], ensemble, le, scaler,
                                  feats, explainers, shap_mode)
        except Exception as exc:
            print(f"  Role 1 batch error ({len(batch)} flows): {exc}", file=sys.stderr)
            continue
        t1 = time.time()
        amort_ms = (t1 - t0) * 1000 / len(batch)

        for (flow, t_recv), r in zip(batch, results):
            try:
                _handle_flow(flow, t_recv, r, t0, t1, amort_ms, len(batch),
                             le, feats, proto_map, llm_enabled)
            except Exception as exc:
                _rl_print(f"  Flow error: {exc}")

    # Phase 2 drain completion: flush all pending Role 3 LLM work cleanly
    with DRAIN_LOCK:
        DRAIN_STATE["r1_done"] = True
    push_event("drain_update", _drain_snapshot())

    if llm_enabled and llm_workers:
        print(f"  ⏳ Approach A Role 1 finished; draining {LLM_QUEUE.qsize()} queued Role 3 LLM calls...", flush=True)
        for _ in llm_workers:
            LLM_QUEUE.put((999, next(LLM_QUEUE_COUNTER), None, None, None))
        for wt in llm_workers:
            wt.join(timeout=600)

    with DRAIN_LOCK:
        DRAIN_STATE["llm_done"] = True
        DRAIN_STATE["complete"] = True
        DRAIN_STATE["completed_at"] = datetime.now(timezone.utc).isoformat()
    try:
        with STATS_LOCK:
            s = dict(STATS)
        with FLOWS_LOCK:
            fl = list(FLOWS)
        with open("nids_history.json.tmp", "w") as f:
            json.dump({"flows": fl, "stats": s}, f)
        os.replace("nids_history.json.tmp", "nids_history.json")
        if RUN_LOGGER is not None:
            RUN_LOGGER.update_meta(
                drain_completed=True,
                end_ts_utc=datetime.now(timezone.utc).isoformat(),
                end_epoch=time.time(),
                counts=dict(RUN_LOGGER.counts),
                final_stats=s,
            )
    except Exception:
        pass
    print("  ✓ Approach A drain complete (all PCAPs, flows, and LLM responses finished)", flush=True)
    push_event("drain_update", _drain_snapshot())


def _handle_flow(flow, t_recv, r, t0, t1, amort_ms, batch_n, le, feats,
                 proto_map, llm_enabled):
    model_label, model_conf = r["label"], r["conf"]
    try:
        _log_role1_proba(flow, le, r["proba_row"], r["idx"], model_label,
                         model_conf, feats=feats, signed_benign=r["signed_benign"])
    except Exception:
        pass

    r1_label, r1_conf = model_label, model_conf
    heuristic_attack, behavioral_ctx = check_cross_flow_attack(flow, t_recv=t_recv)
    if heuristic_attack:
        r1_label, r1_conf = heuristic_attack, 100.0
    is_attack = r1_label not in BENIGN_LABELS

    first_seen_ms = getattr(flow, "bidirectional_first_seen_ms", None)
    cap_sec = (first_seen_ms / 1000.0) if first_seen_ms else t_recv

    suppressed = False
    suppress_reason = None
    if is_attack:
        alert_key = (flow.src_ip, r1_label)
        if cap_sec - ALERT_STATE.get(alert_key, -1e9) < 5:
            suppressed = True
            suppress_reason = "skipped_ui_suppressed"
        else:
            ALERT_STATE[alert_key] = cap_sec
    elif behavioral_ctx.get("is_server_reply"):
        rep_key = (flow.src_ip, flow.src_port, flow.dst_ip)
        if cap_sec - SERVER_REPLY_R3_STATE.get(rep_key, -1e9) < 5.0:
            suppressed = True
            suppress_reason = "skipped_server_reply_throttle"
        else:
            SERVER_REPLY_R3_STATE[rep_key] = cap_sec

    fid = str(uuid.uuid4())[:8]
    proto = proto_map.get(flow.protocol, str(flow.protocol))
    last_seen = getattr(flow, "bidirectional_last_seen_ms", None)

    full = {
        "id": fid,
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "t_recv": t_recv, "t_r1_start": t0, "t_r1_done": t1,
        "flow_first_seen_ms": first_seen_ms,
        "flow_last_seen_ms": last_seen,
        "export_to_verdict_ms": round(t1 * 1000 - last_seen, 1) if last_seen else None,
        "recv_to_verdict_ms": round((t1 - t_recv) * 1000, 2),
        "r1_batch_size": batch_n,
        "r1_ms_per_flow": round(amort_ms, 3),
        "src_ip": flow.src_ip, "src_port": flow.src_port,
        "dst_ip": flow.dst_ip, "dst_port": flow.dst_port,
        "protocol": proto, "ip_version": getattr(flow, "ip_version", None),
        "application_name": getattr(flow, "application_name", None),
        "duration_ms": flow.bidirectional_duration_ms,
        "packets": flow.bidirectional_packets, "bytes": flow.bidirectional_bytes,
        "src2dst_packets": flow.src2dst_packets, "dst2src_packets": flow.dst2src_packets,
        "syn": flow.bidirectional_syn_packets, "fin": flow.bidirectional_fin_packets,
        "rst": flow.bidirectional_rst_packets, "psh": flow.bidirectional_psh_packets,
        "ack": flow.bidirectional_ack_packets,
        "http_requests": getattr(flow, "http_requests", 0),
        "model_label": model_label, "model_conf": model_conf,
        "model_is_attack": model_label not in BENIGN_LABELS,
        "heuristic_label": heuristic_attack,
        "behavioral_ctx": behavioral_ctx,
        "r1_label": r1_label, "r1_conf": r1_conf, "r1_is_attack": is_attack,
        "r1_dist": r["dist"],
        "r1_shap_top": r["top"],
        "r1_shap_signed": r.get("top_signed"),
        "features": {ft: float(v) for ft, v in zip(feats, r["vec"])},
        "ui_suppressed": suppressed,
    }

    if suppressed:
        with STATS_LOCK:
            STATS["total"] += 1
            if is_attack:
                STATS["attacks_r1"] += 1
        full["r3_status"] = suppress_reason or "skipped_ui_suppressed"
        if RUN_LOGGER is not None:
            RUN_LOGGER.log_flow(full)
        return

    rec = {
        "id":           fid,
        "timestamp":    full["ts_utc"],
        "src_ip":       flow.src_ip,   "src_port": flow.src_port,
        "dst_ip":       flow.dst_ip,   "dst_port": flow.dst_port,
        "protocol":     proto,
        "duration_ms":  flow.bidirectional_duration_ms,
        "packets":      flow.bidirectional_packets,
        "bytes":        flow.bidirectional_bytes,
        "fin_flags":    flow.bidirectional_fin_packets,
        "syn_flags":    flow.bidirectional_syn_packets,
        "rst_flags":    flow.bidirectional_rst_packets,
        "psh_flags":    flow.bidirectional_psh_packets,
        "ack_flags":    flow.bidirectional_ack_packets,
        "r1_label":     r1_label,
        "r1_conf":      r1_conf,
        "r1_shap":      r["top"],
        "r1_shap_signed": r.get("top_signed"),
        "behavioral_ctx": behavioral_ctx,
        "r1_is_attack": is_attack,
        "r3_verdict":   None, "r3_attack_type": None, "r3_conf": None,
        "r3_explanation": None, "r3_action": None,
        "agreement":    "pending",
    }
    with FLOWS_LOCK:
        FLOWS.appendleft(rec)
    with STATS_LOCK:
        STATS["total"] += 1
        if is_attack: STATS["attacks_r1"] += 1
    push_event("new_flow", {"flow": rec, "stats": dict(STATS)})

    if not llm_enabled:
        full["r3_status"] = "llm_disabled"
    else:
        flow_text = format_flow_for_llm(rec)
        if r1_label == "DoS/Flood (Heuristics)":
            priority = 0
        elif is_attack:
            priority = 1
        else:
            priority = 2
        try:
            ENQ_TIME[fid] = time.time()
            LLM_QUEUE.put_nowait((priority, next(LLM_QUEUE_COUNTER), fid, flow_text, rec))
            with STATS_LOCK:
                STATS["llm_pending"] += 1
            full["r3_status"] = "queued"
        except Full:
            ENQ_TIME.pop(fid, None)
            full["r3_status"] = "dropped_queue_full"
    if RUN_LOGGER is not None:
        RUN_LOGGER.log_flow(full)


# ══════════════════════════════════════════════════════════════════════════════
# FLASK APP
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NIDS Live Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:       #0a0e1a;
      --surface:  #111827;
      --surface2: #1a2234;
      --border:   #1e2d45;
      --accent:   #3b82f6;
      --green:    #10b981;
      --red:      #ef4444;
      --yellow:   #f59e0b;
      --purple:   #8b5cf6;
      --cyan:     #06b6d4;
      --text:     #e2e8f0;
      --muted:    #64748b;
      --font:     'Inter', sans-serif;
      --mono:     'JetBrains Mono', monospace;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: var(--font);
           min-height: 100vh; overflow-x: hidden; }

    /* ── Header ── */
    .header {
      background: linear-gradient(135deg, #0f1729 0%, #1a2440 100%);
      border-bottom: 1px solid var(--border);
      padding: 16px 24px;
      display: flex; align-items: center; gap: 16px;
    }
    .header .logo {
      width: 36px; height: 36px;
      background: linear-gradient(135deg, var(--accent), var(--purple));
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 18px;
    }
    .header h1 { font-size: 18px; font-weight: 700; color: #fff; }
    .header .subtitle { font-size: 12px; color: var(--muted); margin-top: 2px; }
    .status-dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--green); margin-left: auto;
      box-shadow: 0 0 8px var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
    .status-text { font-size: 12px; color: var(--green); }

    /* ── Stats Cards ── */
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr));
             gap: 12px; padding: 16px 24px; }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 16px;
      transition: border-color .2s, transform .2s, background .2s;
      cursor: pointer;
    }
    .card.active { border-color: var(--accent); background: rgba(59, 130, 246, 0.1); box-shadow: 0 0 10px rgba(59, 130, 246, 0.2); }
    .card:hover { border-color: var(--accent); transform: translateY(-2px); }
    .card .label { font-size: 11px; color: var(--muted); text-transform: uppercase;
                   letter-spacing: .08em; font-weight: 500; }
    .card .value { font-size: 28px; font-weight: 700; margin-top: 4px;
                   font-family: var(--mono); }
    .card.blue  .value { color: var(--accent); }
    .card.red   .value { color: var(--red); }
    .card.green .value { color: var(--green); }
    .card.yellow .value { color: var(--yellow); }
    .card.purple .value { color: var(--purple); }

    /* ── Layout ── */
    .main { display: grid; grid-template-columns: 1fr 360px; gap: 16px;
            padding: 0 24px 24px; }
    @media(max-width:900px){ .main { grid-template-columns: 1fr; } }

    /* ── Panel ── */
    .panel {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; overflow: hidden;
    }
    .panel-header {
      padding: 14px 18px; border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 8px;
      font-size: 13px; font-weight: 600; color: #fff;
    }
    .panel-header .badge {
      margin-left: auto; background: var(--surface2);
      color: var(--muted); font-size: 11px; padding: 2px 8px;
      border-radius: 100px; font-family: var(--mono);
    }

    /* ── Flow Table ── */
    .flow-list { max-height: calc(100vh - 280px); overflow-y: auto;
                 scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
    .flow-item {
      padding: 12px 18px; border-bottom: 1px solid var(--border);
      animation: slideIn .3s ease;
      cursor: pointer; transition: background .15s;
    }
    .flow-item:hover { background: var(--surface2); }
    @keyframes slideIn { from { opacity:0; transform:translateY(-8px); } to { opacity:1; transform:none; } }
    .flow-top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .flow-ip { font-family: var(--mono); font-size: 12px; color: var(--cyan); }
    .flow-proto { font-size: 10px; background: var(--surface2); color: var(--muted);
                  padding: 1px 6px; border-radius: 4px; }
    .flow-stats { font-size: 11px; color: var(--muted); margin-top: 4px; }

    /* ── Verdict Comparison Row ── */
    .verdict-row { display: grid; grid-template-columns: 1fr 1fr 80px;
                   gap: 8px; margin-top: 8px; }
    .verdict-box {
      background: var(--surface2); border-radius: 8px; padding: 8px 10px;
      border: 1px solid var(--border);
    }
    .verdict-box .role-label { font-size: 10px; color: var(--muted);
                                font-weight: 600; text-transform: uppercase;
                                letter-spacing: .08em; }
    .verdict-box .verdict-label { font-size: 13px; font-weight: 600;
                                   margin-top: 2px; font-family: var(--mono); }
    .verdict-box .conf { font-size: 11px; color: var(--muted); margin-top: 1px; }
    .agreement-box {
      border-radius: 8px; padding: 8px; display: flex;
      flex-direction: column; align-items: center; justify-content: center;
      gap: 4px; font-size: 11px; font-weight: 600; text-align: center;
    }
    .agreement-box .icon { font-size: 20px; }

    /* Agreement states */
    .ag-agree_attack  { background: rgba(239,68,68,.15);  color: var(--red);    border: 1px solid rgba(239,68,68,.3); }
    .ag-agree_benign  { background: rgba(16,185,129,.12); color: var(--green);  border: 1px solid rgba(16,185,129,.3); }
    .ag-disagree      { background: rgba(245,158,11,.15); color: var(--yellow); border: 1px solid rgba(245,158,11,.3); }
    .ag-pending       { background: rgba(99,102,241,.1);  color: var(--purple); border: 1px solid rgba(99,102,241,.3); }

    /* Verdict colours */
    .lbl-attack,.lbl-suspicious { color: var(--red); }
    .lbl-benign,.lbl-normal     { color: var(--green); }
    .lbl-pending                { color: var(--purple); }
    .lbl-unknown,.lbl-error     { color: var(--muted); }

    /* ── Explanation Panel ── */
    .explanation-panel { max-height: calc(100vh - 280px); overflow-y: auto;
                         padding: 14px 18px; }
    .exp-item { margin-bottom: 16px; }
    .exp-item .exp-header { font-size: 11px; color: var(--muted); margin-bottom: 6px;
                             font-family: var(--mono); }
    .exp-item .exp-text {
      font-size: 13px; line-height: 1.6; color: var(--text);
      background: var(--surface2); border-radius: 8px; padding: 10px 12px;
      border-left: 3px solid var(--accent);
    }
    .exp-item .exp-action {
      font-size: 12px; margin-top: 6px; color: var(--cyan);
      display: flex; align-items: flex-start; gap: 6px;
    }

    /* ── Disagreement highlight ── */
    .flow-item.has-disagree { border-left: 3px solid var(--yellow); }
    .flow-item.has-attack   { border-left: 3px solid var(--red); }

    /* ── Phase Marker Bar ── */
    .phase-bar {
      display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
      padding: 10px 24px; background: var(--surface); border-bottom: 1px solid var(--border);
      font-size: 12px;
    }
    .phase-btn {
      background: var(--surface2); color: var(--text); border: 1px solid var(--border);
      border-radius: 6px; padding: 5px 10px; font-size: 11px; font-weight: 600;
      cursor: pointer; transition: border-color .15s, background .15s;
    }
    .phase-btn:hover { border-color: var(--accent); }
    .phase-btn.active { background: rgba(59,130,246,.2); border-color: var(--accent); color: #fff; }
    .phase-btn.stop { border-color: rgba(239,68,68,.4); color: var(--red); }
    .phase-badge {
      margin-left: auto; font-family: var(--mono); font-size: 11px;
      padding: 4px 10px; border-radius: 100px; background: var(--surface2);
      border: 1px solid var(--border); color: var(--cyan);
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
  </style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="logo">🛡️</div>
  <div>
    <h1>NIDS Live Dashboard</h1>
    <div class="subtitle">Role 1 (ML Model) vs Role 3 (LLM Analyst) — Real-time comparison</div>
  </div>
  <div class="status-dot" id="statusDot"></div>
  <div class="status-text" id="statusText">Connecting…</div>
</div>

<!-- Experiment Phase Bar (optional ground-truth markers for thesis log) -->
<div class="phase-bar">
  <span style="color:var(--muted);font-weight:600;">Phase Marker:</span>
  <button class="phase-btn" onclick="startPhase('benign_baseline')">Benign Baseline</button>
  <button class="phase-btn" onclick="startPhase('portscan')">PortScan (nmap)</button>
  <button class="phase-btn" onclick="startPhase('bruteforce')">Brute Force (hydra)</button>
  <button class="phase-btn" onclick="startPhase('dos')">DoS / Flood (hping3)</button>
  <button class="phase-btn" onclick="startPhase('web_attack')">Web Attack (nikto)</button>
  <button class="phase-btn stop" onclick="stopPhase()">Stop Phase</button>
  <button class="phase-btn stop" id="stopDrainBtn" onclick="stopCaptureDrain()" style="background:rgba(239,68,68,.12);margin-left:8px;">⏹ Stop Capture &amp; Drain</button>
  <span class="phase-badge" id="drainBadge" style="display:none;color:var(--yellow);"></span>
  <span class="phase-badge" id="phaseBadge">Phase: untagged</span>
</div>

<!-- Stats -->
<div class="stats">
  <div class="card blue active" data-filter="total">
    <div class="label">Total Flows</div>
    <div class="value" id="statTotal">0</div>
  </div>
  <div class="card red" data-filter="ml_attacks">
    <div class="label">ML Attacks (R1)</div>
    <div class="value" id="statR1">0</div>
  </div>
  <div class="card purple" data-filter="llm_attacks">
    <div class="label">LLM Attacks (R3)</div>
    <div class="value" id="statR3">0</div>
  </div>
  <div class="card green" data-filter="agree">
    <div class="label">Both Agree</div>
    <div class="value" id="statAgree">0</div>
  </div>
  <div class="card yellow" data-filter="disagree">
    <div class="label">Disagree ⚠️</div>
    <div class="value" id="statDisagree">0</div>
  </div>
  <div class="card blue" data-filter="pending">
    <div class="label">LLM Pending</div>
    <div class="value" id="statPending">0</div>
  </div>
</div>

<!-- Main content -->
<div class="main">

  <!-- Flow feed -->
  <div class="panel">
    <div class="panel-header">
      📡 Live Flow Feed
      <select id="attackTypeFilter" style="margin-left: 16px; background: var(--surface2); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 4px 8px; font-size: 12px; outline: none; cursor: pointer;">
        <option value="All">All Attack Types</option>
      </select>
      <span class="badge" id="flowCount">0 flows</span>
    </div>
    <div class="flow-list" id="flowList"></div>
  </div>

  <!-- Explanations -->
  <div class="panel">
    <div class="panel-header">
      💬 LLM Explanations
    </div>
    <div class="explanation-panel" id="explPanel">
      <p style="color:var(--muted);font-size:13px;padding:8px 0">
        Explanations from Role 3 will appear here when the LLM analyses a flow…
      </p>
    </div>
  </div>

</div>

<script>
const agLabel = {
  agree_attack:  ['🚨', 'Both: Attack'],
  agree_benign:  ['✅', 'Both: Benign'],
  disagree:      ['⚠️', 'Disagree!'],
  pending:       ['⏳', 'LLM Pending'],
};

function labelClass(v) {
  if (!v) return 'lbl-pending';
  const l = v.toLowerCase();
  return `lbl-${l in {attack:1,suspicious:1,benign:1,normal:1,pending:1} ? l : 'unknown'}`;
}

function renderVerdict(box, roleLabel, verdict, conf, isPending) {
  const vlabel  = isPending ? 'Pending…' : (verdict || 'N/A');
  const cls     = isPending ? 'lbl-pending' : labelClass(verdict);
  box.innerHTML = `
    <div class="role-label">${roleLabel}</div>
    <div class="verdict-label ${cls}">${vlabel}</div>
    <div class="conf">${isPending ? '' : `${conf ?? '—'}%`}</div>
  `;
}

function renderFlow(rec) {
  const ag    = rec.agreement || 'pending';
  const [icon, agText] = agLabel[ag] || ['❓','Unknown'];
  const isAttack   = rec.r1_is_attack;
  const isDisagree = ag === 'disagree';

  const el = document.createElement('div');
  el.className = `flow-item${isDisagree ? ' has-disagree' : isAttack ? ' has-attack' : ''}`;
  el.dataset.id = rec.id;
  el.innerHTML = `
    <div class="flow-top">
      <span class="flow-ip">${rec.src_ip}:${rec.src_port} → ${rec.dst_ip}:${rec.dst_port}</span>
      <span class="flow-proto">${rec.protocol}</span>
    </div>
    <div class="flow-stats">${(rec.duration_ms/1000).toFixed(2)}s · ${rec.packets} pkts · ${rec.bytes} B</div>
    <div class="verdict-row">
      <div class="verdict-box" data-r1></div>
      <div class="verdict-box" data-r3></div>
      <div class="agreement-box ag-${ag}">
        <div class="icon">${icon}</div>
        <div>${agText}</div>
      </div>
    </div>
  `;

  const r1box = el.querySelector('[data-r1]');
  const r3box = el.querySelector('[data-r3]');
  renderVerdict(r1box, '🤖 Role 1 — ML', rec.r1_label, rec.r1_conf, false);
  renderVerdict(r3box, '💬 Role 3 — LLM', rec.r3_verdict, rec.r3_conf, rec.r3_verdict === null);

  el.addEventListener('click', () => showExplanation(rec));
  return el;
}

function showExplanation(rec) {
  const panel = document.getElementById('explPanel');
  if (!rec.r3_explanation) {
    panel.innerHTML = `<p style="color:var(--muted);font-size:13px;padding:8px 0">LLM explanation pending for this flow…</p>`;
    return;
  }
  const ag = rec.agreement || 'pending';
  panel.innerHTML = `
    <div class="exp-item">
      <div class="exp-header">${rec.src_ip}:${rec.src_port} → ${rec.dst_ip}:${rec.dst_port} [${rec.protocol}]</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;">
        <div style="background:var(--surface2);border-radius:8px;padding:10px;border:1px solid var(--border);">
          <div style="font-size:10px;color:var(--muted);font-weight:600;text-transform:uppercase">🤖 Role 1 — ML Model</div>
          <div style="font-size:16px;font-weight:700;margin-top:4px" class="${labelClass(rec.r1_label)}">${rec.r1_label}</div>
          <div style="font-size:12px;color:var(--muted)">${rec.r1_conf}% confidence</div>
          ${rec.r1_shap && rec.r1_shap.length > 0 ? `<div style="font-size:11px;color:var(--muted);margin-top:6px;border-top:1px solid var(--border);padding-top:4px;"><b>Top Features (SHAP):</b><br>${rec.r1_shap.map(f => `<span style="color:var(--cyan)">${f[0]}</span>: ${f[1]}`).join('<br>')}</div>` : ''}
        </div>
        <div style="background:var(--surface2);border-radius:8px;padding:10px;border:1px solid var(--border);">
          <div style="font-size:10px;color:var(--muted);font-weight:600;text-transform:uppercase">💬 Role 3 — LLM</div>
          <div style="font-size:16px;font-weight:700;margin-top:4px" class="${labelClass(rec.r3_verdict)}">${rec.r3_verdict ?? '—'} ${rec.r3_attack_type ? '('+rec.r3_attack_type+')' : ''}</div>
          <div style="font-size:12px;color:var(--muted)">${rec.r3_conf ?? '—'}% confidence</div>
        </div>
      </div>
      <div class="exp-text">${rec.r3_explanation || 'No explanation provided.'}</div>
      ${rec.r3_action ? `<div class="exp-action">→ <span>${rec.r3_action}</span></div>` : ''}
      ${ag==='disagree' ? `<div style="margin-top:8px;padding:8px 12px;background:rgba(245,158,11,.1);border-radius:8px;font-size:12px;color:var(--yellow)">⚠️ <strong>Disagreement detected!</strong> ML and LLM differ — review manually.</div>` : ''}
    </div>
  `;
}

function updateStats(stats) {
  document.getElementById('statTotal').textContent   = stats.total;
  document.getElementById('statR1').textContent      = stats.attacks_r1;
  document.getElementById('statR3').textContent      = stats.attacks_r3;
  document.getElementById('statAgree').textContent   = stats.agree;
  document.getElementById('statDisagree').textContent= stats.disagree;
  document.getElementById('statPending').textContent = stats.llm_pending;
}

// ── SSE ──────────────────────────────────────────────────────────────────────
const flows   = {};  // id → record
const flowList = document.getElementById('flowList');
let flowCount  = 0;

const attackTypes = new Set();
let activeCardFilter = 'total'; // default

function updateAttackTypeDropdown(label) {
  if (!label) return;
  const lower = label.toLowerCase();
  if (lower === 'benign' || lower === 'normal' || lower === 'unknown') return;
  if (!attackTypes.has(label)) {
    attackTypes.add(label);
    const sel = document.getElementById('attackTypeFilter');
    const opt = document.createElement('option');
    opt.value = label;
    opt.textContent = label;
    sel.appendChild(opt);
  }
}

function updateElementVisibility(f, el) {
  const typeFilter = document.getElementById('attackTypeFilter').value;
  let matchCard = false;
  if (activeCardFilter === 'total') matchCard = true;
  else if (activeCardFilter === 'ml_attacks') matchCard = f.r1_is_attack;
  else if (activeCardFilter === 'llm_attacks') matchCard = (f.r3_verdict === 'attack' || f.r3_verdict === 'suspicious');
  else if (activeCardFilter === 'agree') matchCard = (f.agreement === 'agree_attack' || f.agreement === 'agree_benign');
  else if (activeCardFilter === 'disagree') matchCard = (f.agreement === 'disagree');
  else if (activeCardFilter === 'pending') matchCard = (f.agreement === 'pending');
  else if (activeCardFilter === 'any_attack') matchCard = (f.r1_is_attack || f.r3_verdict === 'attack' || f.r3_verdict === 'suspicious');

  let matchType = true;
  if (typeFilter !== 'All') {
    matchType = (f.r1_label === typeFilter || f.r3_attack_type === typeFilter);
  }
  
  if (matchCard && matchType) {
    el.style.display = '';
  } else {
    el.style.display = 'none';
  }
}

function updateVisibleCount() {
  let visibleCount = 0;
  for (const el of flowList.children) {
    if (el.style.display !== 'none') visibleCount++;
  }
  document.getElementById('flowCount').textContent = `${visibleCount} flows`;
}

function applyFilters() {
  for (const el of flowList.children) {
    const f = flows[el.dataset.id];
    if (f) updateElementVisibility(f, el);
  }
  updateVisibleCount();
}

document.getElementById('attackTypeFilter').addEventListener('change', applyFilters);

document.querySelectorAll('.card').forEach(card => {
  card.addEventListener('click', () => {
    document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
    card.classList.add('active');
    activeCardFilter = card.dataset.filter;
    applyFilters();
  });
});

const sse = new EventSource('/stream');

sse.addEventListener('new_flow', e => {
  const {flow, stats} = JSON.parse(e.data);
  flows[flow.id] = flow;
  updateAttackTypeDropdown(flow.r1_label);
  updateAttackTypeDropdown(flow.r3_attack_type);
  
  const el = renderFlow(flow);
  flowList.insertBefore(el, flowList.firstChild);
  updateElementVisibility(flow, el);
  
  flowCount++;
  updateVisibleCount();
  updateStats(stats);
  // Keep DOM under 1000 items
  while (flowList.children.length > 1000) {
    const last = flowList.lastChild;
    delete flows[last.dataset.id];
    flowList.removeChild(last);
  }
});

sse.addEventListener('r3_update', e => {
  const d = JSON.parse(e.data);
  if (flows[d.id]) {
    Object.assign(flows[d.id], {
      r3_verdict: d.r3_verdict, r3_attack_type: d.r3_attack_type,
      r3_conf: d.r3_conf, r3_explanation: d.r3_explanation,
      r3_action: d.r3_action,
      agreement: d.agreement,
    });
    updateAttackTypeDropdown(d.r3_attack_type);
  }
  updateStats(d.stats);

  const el = flowList.querySelector(`[data-id="${d.id}"]`);
  if (!el) return;

  const r3box = el.querySelector('[data-r3]');
  const agBox = el.querySelector('.agreement-box');
  if (r3box) renderVerdict(r3box, '💬 Role 3 — LLM', d.r3_verdict, d.r3_conf, false);

  const [icon, txt] = agLabel[d.agreement] || ['❓',''];
  if (agBox) {
    agBox.className = `agreement-box ag-${d.agreement}`;
    agBox.querySelector('.icon').textContent = icon;
    agBox.lastElementChild.textContent = txt;
  }
  el.className = `flow-item${d.agreement==='disagree' ? ' has-disagree' : (flows[d.id]?.r1_is_attack ? ' has-attack' : '')}`;
  if (flows[d.id]) updateElementVisibility(flows[d.id], el);
  updateVisibleCount();
});

function renderPhase(p) {
  const b = document.getElementById('phaseBadge');
  b.textContent = p && p.phase ? `Phase: ${p.phase} (active)` : 'Phase: untagged';
}
function startPhase(name) {
  fetch('/api/phase/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({phase: name, source: 'dashboard'})
  }).then(r=>r.json()).then(renderPhase);
}
function stopPhase() {
  fetch('/api/phase/stop', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({source: 'dashboard'})
  }).then(r=>r.json()).then(renderPhase);
}
sse.addEventListener('phase_update', e => renderPhase(JSON.parse(e.data)));
fetch('/api/phase').then(r=>r.json()).then(renderPhase);

function renderDrain(d) {
  const b = document.getElementById('drainBadge');
  const btn = document.getElementById('stopDrainBtn');
  if (!b || !d) return;
  if (!d.requested && !d.capture_stopped && !d.complete) return;
  b.style.display = 'inline-block';
  if (d.both_complete || (d.complete && d.b_pipeline_done)) {
    b.style.color = 'var(--green)';
    b.textContent = '✓ Dual Drain Complete (A=✓ B=✓)';
    if (btn) { btn.disabled = true; btn.textContent = '✓ Drained'; }
  } else {
    b.style.color = 'var(--yellow)';
    b.textContent = `⏳ Draining… A=${d.complete?'✓':'…'} (llm_q=${d.llm_pending||0}) | B=${d.b_pipeline_done?'✓':'…'}`;
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Draining…'; }
  }
}
function stopCaptureDrain() {
  fetch('/api/capture/stop_drain', {method: 'POST'})
    .then(r => r.json()).then(renderDrain);
}
sse.addEventListener('drain_update', e => renderDrain(JSON.parse(e.data)));
setInterval(() => {
  fetch('/api/drain_status').then(r=>r.json()).then(renderDrain).catch(()=>{});
}, 2500);

sse.onopen = () => {
  document.getElementById('statusDot').style.background = 'var(--green)';
  document.getElementById('statusText').textContent = 'Live';
};
sse.onerror = () => {
  document.getElementById('statusDot').style.background = 'var(--red)';
  document.getElementById('statusText').textContent = 'Disconnected';
};

// Load history on page load
fetch('/api/flows').then(r=>r.json()).then(data => {
  data.forEach(rec => {
    flows[rec.id] = rec;
    updateAttackTypeDropdown(rec.r1_label);
    updateAttackTypeDropdown(rec.r3_attack_type);
    const el = renderFlow(rec);
    flowList.appendChild(el);
    updateElementVisibility(rec, el);
    flowCount++;
  });
  updateVisibleCount();
});
fetch('/api/stats').then(r=>r.json()).then(updateStats);
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/stream")
def stream():
    """SSE endpoint — each browser tab gets its own queue."""
    q = Queue(maxsize=200)
    with SSE_LOCK:
        SSE_CLIENTS.append(q)

    def gen():
        yield "data: connected\n\n"
        try:
            while True:
                msg = q.get(timeout=30)
                yield msg
        except Exception:
            pass
        finally:
            with SSE_LOCK:
                if q in SSE_CLIENTS:
                    SSE_CLIENTS.remove(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/flows")
def api_flows():
    with FLOWS_LOCK:
        return jsonify(list(FLOWS)[:500])


@app.route("/api/stats")
def api_stats():
    with STATS_LOCK:
        return jsonify(dict(STATS))


@app.route("/api/phase", methods=["GET"])
def api_phase_status():
    with PHASE_LOCK:
        return jsonify(dict(ACTIVE_PHASE))


@app.route("/api/phase/start", methods=["POST"])
def api_phase_start():
    data = request.get_json(silent=True) or {}
    phase = str(data.get("phase") or "untagged").strip()
    note = str(data.get("note") or "").strip()
    source = str(data.get("source") or "api").strip()
    with PHASE_LOCK:
        if ACTIVE_PHASE["phase"]:
            if RUN_LOGGER is not None:
                RUN_LOGGER.log_phase(ACTIVE_PHASE["phase"], "stop", note="auto-closed by next phase", source=source)
            ACTIVE_PHASE["history"].append({
                "phase": ACTIVE_PHASE["phase"], "event": "stop", "ts": datetime.now(timezone.utc).isoformat()
            })
        ACTIVE_PHASE["phase"] = phase
        ACTIVE_PHASE["started_at"] = datetime.now(timezone.utc).isoformat()
        ACTIVE_PHASE["history"].append({"phase": phase, "event": "start", "ts": ACTIVE_PHASE["started_at"]})
        if RUN_LOGGER is not None:
            RUN_LOGGER.log_phase(phase, "start", note=note, source=source)
        snap = dict(ACTIVE_PHASE)
    push_event("phase_update", snap)
    return jsonify(snap)


def _trigger_capture_stop_drain(source="api"):
    with DRAIN_LOCK:
        DRAIN_STATE["requested"] = True
        DRAIN_STATE["requested_at"] = DRAIN_STATE["requested_at"] or datetime.now(timezone.utc).isoformat()
    os.makedirs("logs", exist_ok=True)
    try:
        with open("logs/drain_requested.flag", "w") as f:
            f.write(json.dumps({"requested_at": datetime.now(timezone.utc).isoformat(), "source": source}) + "\n")
    except OSError:
        pass
    STOP_CAPTURE.set()
    if DUMPCAP_PROC is not None and DUMPCAP_PROC.poll() is None:
        try:
            DUMPCAP_PROC.terminate()
        except Exception:
            pass
    snap = _drain_snapshot()
    push_event("drain_update", snap)
    return snap


@app.route("/api/capture/stop_drain", methods=["POST"])
def api_stop_capture_drain():
    data = request.get_json(silent=True) or {}
    return jsonify(_trigger_capture_stop_drain(source=str(data.get("source") or "dashboard")))


@app.route("/api/drain_status", methods=["GET"])
def api_drain_status():
    return jsonify(_drain_snapshot())


@app.route("/api/phase/stop", methods=["POST"])
def api_phase_stop():
    data = request.get_json(silent=True) or {}
    note = str(data.get("note") or "").strip()
    source = str(data.get("source") or "api").strip()
    with PHASE_LOCK:
        prev = ACTIVE_PHASE["phase"]
        if prev:
            if RUN_LOGGER is not None:
                RUN_LOGGER.log_phase(prev, "stop", note=note, source=source)
            ACTIVE_PHASE["history"].append({
                "phase": prev, "event": "stop", "ts": datetime.now(timezone.utc).isoformat()
            })
        ACTIVE_PHASE["phase"] = None
        ACTIVE_PHASE["started_at"] = None
        snap = dict(ACTIVE_PHASE)
    push_event("phase_update", snap)
    return jsonify(snap)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def _collect_hardware():
    import platform
    hw = {
        "hostname": platform.node(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }
    try:
        import psutil
        hw["ram_gb"] = round(psutil.virtual_memory().total / (1024 ** 3), 2)
    except Exception:
        pass
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line:
                    hw["cpu_model"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    return hw


def main():
    global RUN_LOGGER
    _install_resilient_dns()
    ap = argparse.ArgumentParser(description="NIDS Web Dashboard — Role 1 vs Role 3")
    ap.add_argument("--iface",        default="wlp0s20f3")
    ap.add_argument("--pcap",         default=None)
    ap.add_argument("--pkl",          default="universal_nids_output.pkl")
    ap.add_argument("--ollama-url", "--ollama", dest="ollama_url",
                    default="http://localhost:11434")
    ap.add_argument("--ollama-model", "--model", dest="ollama_model",
                    default="qwen2.5:1.5b")
    ap.add_argument("--llm-timeout",  type=int, default=60)
    ap.add_argument("--port",         type=int, default=5000)
    ap.add_argument("--no-llm",       action="store_true")
    ap.add_argument("--fresh",        action="store_true",
                    help="Ignore/clear any previous nids_history.json and start clean.")
    ap.add_argument("--run-id",       default=None,
                    help="Experiment run identifier (default: live_<UTC timestamp>).")
    ap.add_argument("--run-dir",      default=None,
                    help="Directory for complete per-run logs (default: data/runs/<run-id>).")
    ap.add_argument("--shap-mode",    choices=["xgb", "full", "none"], default="xgb",
                    help="SHAP explainer mode: xgb (fast, default), full (XGB+RF), none.")
    ap.add_argument("--capture-backend", choices=["auto", "nfstream", "dumpcap"], default="auto",
                    help="Live packet capture backend (auto falls back to dumpcap if unprivileged).")
    ap.add_argument("--pcap-extractor", choices=["auto", "fast", "nfstream"], default="auto",
                    help="Flow extractor for closed dumpcap/pcap files (fast=dpkt CIC-aligned, default with dumpcap).")
    ap.add_argument("--rotate-sec",   type=int, default=5,
                    help="dumpcap PCAP rotation interval in seconds (default: 5).")
    ap.add_argument("--mirror-dir",   default=None,
                    help="Optional directory to mirror closed dumpcap PCAP chunks (for Approach B).")
    ap.add_argument(
        "--no-exclude-self", action="store_true",
        help=(
            "Capture this pipeline's own traffic too (dashboard access on "
            "--port, and this host's own WAN-bound traffic — Ollama calls, "
            "DNS lookups, anything else outbound to the internet). Off by "
            "default: that traffic is capture noise, not attacker traffic."
        ),
    )
    ap.add_argument(
        "--exclude", action="append", default=[],
        help=(
            "Extra BPF clause to also exclude from capture, e.g. "
            "--exclude 'host 192.168.1.50'. Repeatable."
        ),
    )
    args = ap.parse_args()

    from src.live.run_logger import RunLogger
    from src.utils.capture_filter import get_own_network

    run_id = args.run_id or ("live_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
    run_dir = args.run_dir or os.path.join("data", "runs", run_id)
    RUN_LOGGER = RunLogger(run_dir, chown_fn=_fix_ownership)
    os.makedirs(os.path.dirname(os.path.join("data", "runs", "latest_run.txt")), exist_ok=True)
    with open(os.path.join("data", "runs", "latest_run.txt"), "w") as f:
        f.write(run_dir + "\n")
    _fix_ownership(os.path.join("data", "runs", "latest_run.txt"))

    own_ip, own_net = get_own_network()
    source = args.pcap if args.pcap else args.iface
    is_local_ollama = "localhost" in args.ollama_url or "127.0.0.1" in args.ollama_url

    if args.pcap:
        effective_backend = "pcap"
    elif args.capture_backend == "auto":
        effective_backend = "nfstream" if _has_raw_capture_cap() else "dumpcap"
    else:
        effective_backend = args.capture_backend

    effective_extractor = (
        ("fast" if (effective_backend == "dumpcap" or bool(args.pcap)) else "nfstream")
        if args.pcap_extractor == "auto" else args.pcap_extractor
    )

    print("\n" + "═"*60)
    print("  NIDS Web Dashboard — Role 1 (ML) vs Role 3 (LLM)")
    print("═"*60)
    print(f"  Run Dir : {run_dir}")
    print(f"  PKL     : {args.pkl}")
    print(f"  Source  : {source}  (backend={effective_backend})")
    print(f"  Host IP : {own_ip}  (LAN={own_net})")
    print(f"  Ollama  : {args.ollama_url}  model={args.ollama_model}"
          f"  ({'local' if is_local_ollama else 'custom/3rd-party'})")
    print(f"  LLM     : {'disabled' if args.no_llm else 'enabled (ALL flows sent to LLM for comparison)'}")
    print(f"  SHAP    : {args.shap_mode}")
    print(f"  Web UI  : http://localhost:{args.port}")
    print("═"*60 + "\n")

    # Load model
    print("  Loading model…")
    ensemble, le, scaler, feats, explainers = load_model(args.pkl, shap_mode=args.shap_mode, pcap_extractor=effective_extractor)
    print("  ✓ Model loaded\n")

    # Load history state (skip when --fresh)
    if args.fresh:
        if os.path.exists("nids_history.json"):
            os.remove("nids_history.json")
        print("  ✓ Fresh state (--fresh)\n")
    else:
        load_state()
    
    # Start state saver thread
    threading.Thread(target=state_saver_worker, daemon=True).start()

    # Check Ollama
    llm_ok = False
    if not args.no_llm:
        try:
            r = requests.get(f"{args.ollama_url}/api/tags", timeout=10)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models",[])]
                base   = args.ollama_model.split(":")[0]
                llm_ok = any(base in m for m in models)
        except Exception:
            pass

        if llm_ok:
            print(f"  ✓ Ollama ready ({args.ollama_model})\n")
        else:
            is_local = "localhost" in args.ollama_url or "127.0.0.1" in args.ollama_url
            if not is_local:
                print(f"  ⚠ Could not verify model on remote Ollama ({args.ollama_url}).")
                print(f"    Proceeding anyway since it is a remote endpoint...\n")
                llm_ok = True
            else:
                print(f"  ⚠ Ollama not reachable — Role 3 will be skipped\n"
                      f"    Start with: ollama serve && ollama pull {args.ollama_model}\n")

    llm_worker_threads = []
    if llm_ok:
        for _ in range(4):
            t = threading.Thread(
                target=llm_worker,
                args=(args.ollama_url, args.ollama_model, args.llm_timeout),
                daemon=True,
            )
            t.start()
            llm_worker_threads.append(t)

    # Capture filter
    capture_src = args.pcap if args.pcap else args.iface
    bpf_filter = None
    if not args.no_exclude_self and not args.pcap:
        bpf_filter = build_self_exclusion_bpf(args.port, args.ollama_url, args.exclude)
        print(f"  Capture filter: excluding self-traffic ({bpf_filter})\n")

    RUN_LOGGER.write_meta({
        "run_id": run_id,
        "run_dir": run_dir,
        "start_ts_utc": datetime.now(timezone.utc).isoformat(),
        "start_epoch": time.time(),
        "pkl": args.pkl,
        "source": source,
        "iface": None if args.pcap else args.iface,
        "capture_backend": effective_backend,
        "pcap_extractor": effective_extractor,
        "rotate_sec": args.rotate_sec if effective_backend == "dumpcap" else None,
        "host_ip": own_ip,
        "host_network": own_net,
        "ollama_url": args.ollama_url,
        "ollama_model": args.ollama_model,
        "ollama_is_local": is_local_ollama,
        "llm_enabled": bool(llm_ok and not args.no_llm),
        "shap_source": ("xgb_component" if args.shap_mode == "xgb" else ("xgb_rf_weighted" if args.shap_mode == "full" else "none")),
        "bpf_filter": bpf_filter,
        "classes": [str(c) for c in le.classes_],
        "n_features": len(feats),
        "features": list(feats),
        "hardware": _collect_hardware(),
    })

    def _shutdown():
        STOP_CAPTURE.set()
        if DUMPCAP_PROC is not None and DUMPCAP_PROC.poll() is None:
            try:
                DUMPCAP_PROC.terminate()
                DUMPCAP_PROC.wait(timeout=3)
            except Exception:
                pass
        try:
            with STATS_LOCK:
                s = dict(STATS)
            with FLOWS_LOCK:
                fl = list(FLOWS)
            with open("nids_history.json.tmp", "w") as f:
                json.dump({"flows": fl, "stats": s}, f)
            os.replace("nids_history.json.tmp", "nids_history.json")
        except Exception:
            pass
        if RUN_LOGGER is not None:
            RUN_LOGGER.update_meta(
                end_ts_utc=datetime.now(timezone.utc).isoformat(),
                end_epoch=time.time(),
                counts=dict(RUN_LOGGER.counts),
                final_stats=dict(STATS),
            )
            RUN_LOGGER.close()

    atexit.register(_shutdown)

    def _handle_sig(signum, frame):
        _shutdown()
        sys.exit(0)

    def _handle_drain_sig(signum, frame):
        _trigger_capture_stop_drain(source="SIGUSR1")

    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, _handle_drain_sig)

    t = threading.Thread(
        target=nfstream_thread,
        args=(capture_src, ensemble, le, scaler, feats, explainers,
              args.ollama_url, args.ollama_model, args.llm_timeout, bpf_filter,
              args.shap_mode, 512, bool(llm_ok and not args.no_llm),
              effective_backend, args.rotate_sec, args.mirror_dir, run_dir,
              effective_extractor, llm_worker_threads),
        daemon=True,
    )
    t.start()

    # Start Flask (threaded so SSE works properly)
    app.run(host="0.0.0.0", port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
