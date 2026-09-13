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

import sys, os, time, json, uuid, argparse, threading
from collections import deque, defaultdict
from datetime import datetime, timezone
from queue import Queue, PriorityQueue, Full
import itertools

# ── Register UniversalEnsemble before joblib.load ─────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from src.engine.universal_ensemble import UniversalEnsemble  # noqa: F401
except ImportError:
    pass

from src.utils.capture_filter import build_self_exclusion_bpf

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

FLOWS       = deque(maxlen=500)      # last 500 flows (for page-reload history)
SSE_CLIENTS = []                     # list of SSE queue objects, one per browser tab
SSE_LOCK    = threading.Lock()
LLM_QUEUE   = PriorityQueue(maxsize=100)     # pending flows for LLM analysis
LLM_QUEUE_COUNTER = itertools.count()        # tie-breaker for priority queue

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
                FLOWS = deque(data.get("flows", []), maxlen=500)
                STATS.update(data.get("stats", {}))
                
            with STATS_LOCK:
                STATS["llm_pending"] = 0
                
            enqueued = 0
            for rec in FLOWS:
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
            try:
                fl = list(FLOWS)
            except RuntimeError:
                continue
            with open("nids_history.json", "w") as f:
                json.dump({"flows": fl, "stats": s}, f)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# ROLE 1 — ML Model
# ══════════════════════════════════════════════════════════════════════════════

def load_model(pkl_path):
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
    # cannot supply and nflow_to_vec() therefore hardcodes to 0 on every
    # single flow. Silently zero-filling with no visibility into how much
    # of the vector is fake is exactly the failure mode
    # min_feature_coverage/_report_feature_coverage exist to catch
    # elsewhere in this pipeline — this is the same check for this file.
    always_zero = {
        "fwd_header_len", "init_fwd_win_byts", "init_bwd_win_byts",
        "active_mean", "active_std", "active_max", "active_min",
        "idle_mean", "idle_std",
    }
    zero_filled = [f for f in feats if f in always_zero]
    if zero_filled:
        pct = 100 * len(zero_filled) / max(1, len(feats))
        print(f"  ⚠ {len(zero_filled)}/{len(feats)} ({pct:.0f}%) of this "
              f"model's features are not available from NFStream and are "
              f"zero-filled on every flow, always: {sorted(zero_filled)}")

    explainers = None
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
                
            # Extract RF
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
        explainer_rf = shap.TreeExplainer(rf_base) if rf_base is not None else None
        
        explainers = (explainer_xgb, explainer_rf, w_xgb, w_rf)
    except Exception as e:
        print(f"  ⚠ SHAP init failed: {e}")

    return ensemble, le, scaler, feats, explainers

def nflow_to_vec(f, feats):
    dur_ms = f.bidirectional_duration_ms or 1e-3
    dur_s  = dur_ms / 1000.0
    raw = {
        "Destination Port": f.dst_port,
        "flow_duration":    dur_ms * 1000,
        "tot_fwd_pkts":     f.src2dst_packets,
        "tot_bwd_pkts":     f.dst2src_packets,
        "totlen_fwd_pkts":  f.src2dst_bytes,
        "totlen_bwd_pkts":  f.dst2src_bytes,
        "fwd_pkt_len_max":  f.src2dst_max_ps,
        "fwd_pkt_len_min":  f.src2dst_min_ps,
        "fwd_pkt_len_mean": f.src2dst_mean_ps,
        "fwd_pkt_len_std":  f.src2dst_stddev_ps,
        "bwd_pkt_len_max":  f.dst2src_max_ps,
        "bwd_pkt_len_min":  f.dst2src_min_ps,
        "bwd_pkt_len_mean": f.dst2src_mean_ps,
        "flow_byts_s":      f.bidirectional_bytes   / dur_s,
        "flow_pkts_s":      f.bidirectional_packets / dur_s,
        "bwd_pkts_s":       f.dst2src_packets       / dur_s,
        "flow_iat_mean":    f.bidirectional_mean_piat_ms   * 1000,
        "flow_iat_std":     f.bidirectional_stddev_piat_ms * 1000,
        "flow_iat_max":     f.bidirectional_max_piat_ms    * 1000,
        "flow_iat_min":     f.bidirectional_min_piat_ms    * 1000,
        "fwd_iat_mean":     f.src2dst_mean_piat_ms   * 1000,
        "fwd_iat_std":      f.src2dst_stddev_piat_ms * 1000,
        "fwd_iat_min":      f.src2dst_min_piat_ms    * 1000,
        "bwd_iat_tot":      f.dst2src_duration_ms    * 1000,
        "bwd_iat_mean":     f.dst2src_mean_piat_ms   * 1000,
        "bwd_iat_std":      f.dst2src_stddev_piat_ms * 1000,
        "bwd_iat_max":      f.dst2src_max_piat_ms    * 1000,
        "bwd_iat_min":      f.dst2src_min_piat_ms    * 1000,
        "fwd_psh_flags":    f.src2dst_psh_packets,
        "fwd_urg_flags":    f.src2dst_urg_packets,
        "fwd_header_len":   0,
        "fin_flag_cnt":     f.bidirectional_fin_packets,
        "rst_flag_cnt":     f.bidirectional_rst_packets,
        "psh_flag_cnt":     f.bidirectional_psh_packets,
        "ack_flag_cnt":     f.bidirectional_ack_packets,
        "urg_flag_cnt":     f.bidirectional_urg_packets,
        "cwe_flag_count":   f.bidirectional_cwr_packets,
        "pkt_len_min":      f.bidirectional_min_ps,
        "pkt_len_max":      f.bidirectional_max_ps,
        "pkt_len_mean":     f.bidirectional_mean_ps,
        "pkt_len_var":      f.bidirectional_stddev_ps ** 2,
        "down_up_ratio":    (f.dst2src_bytes / f.src2dst_bytes if f.src2dst_bytes > 0 else 0),
        "init_fwd_win_byts": 0, "init_bwd_win_byts": 0,
        "fwd_act_data_pkts": f.src2dst_packets,
        "fwd_seg_size_min":  f.src2dst_min_ps,
        "active_mean": 0, "active_std": 0, "active_max": 0, "active_min": 0,
        "idle_mean":   0, "idle_std":   0,
    }
    return np.array([float(raw.get(ft, 0)) for ft in feats], dtype=np.float32)

_PROBA_LOG_PATH = "data/results/role1_proba_debug.jsonl"
os.makedirs(os.path.dirname(_PROBA_LOG_PATH), exist_ok=True)
_proba_log_lock = threading.Lock()

# Same set load_model() warns about at startup — permanently zero-filled
# because NFStream can't supply them. Tracked here too so the SHAP debug
# log can directly show whether these fabricated zeros are pushing the
# verdict toward Benign, rather than just being unused/irrelevant inputs.
_ALWAYS_ZERO_FEATURES = {
    "fwd_header_len", "init_fwd_win_byts", "init_bwd_win_byts",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std",
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
        zero_feature_push = {
            f: round(v, 4) for f, v in pairs if f in _ALWAYS_ZERO_FEATURES
        }
        real_feature_top5 = [
            (f, round(v, 4)) for f, v in pairs if f not in _ALWAYS_ZERO_FEATURES
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
            print(
                f"  🧪 zero-filled features outweigh real ones pushing "
                f"toward Benign: {flow.src_ip}:{flow.dst_port} → "
                f"fabricated={zero_total:.3f} vs real_top5={real_total:.3f} "
                f"({zero_feature_push})"
            )

    try:
        with _proba_log_lock:
            with open(_PROBA_LOG_PATH, "a") as f:
                f.write(json.dumps(record) + "\n")
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
        print(
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

# ══════════════════════════════════════════════════════════════════════════════
# ROLE 3 — LLM Analyst (Optimized for Sub-Second CPU Inference)
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are a network security analyst.
Output ONLY JSON matching this exact format, nothing else:
{
  "verdict": "attack" or "suspicious" or "benign",
  "attack_type": "DoS" or "PortScan" or "Brute Force" or "Web Attack" or "Bot" or "DDoS" or "Normal" or "Unknown",
  "confidence": integer 0 to 100,
  "explanation": "A full explanation of why this verdict was chosen based on the flow features and SHAP values.",
  "recommended_action": "Recommended action to take to mitigate the threat."
}"""

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
    base_text = (
        f"Network flow:\n"
        f"  {rec['src_ip']}:{rec['src_port']} → {rec['dst_ip']}:{rec['dst_port']} [{rec['protocol']}]\n"
        f"  Duration: {rec['duration_ms']/1000:.3f}s   Packets: {rec['packets']}   Bytes: {rec['bytes']}\n"
        f"  FIN={rec['fin_flags']} SYN={rec['syn_flags']} RST={rec['rst_flags']} "
        f"PSH={rec['psh_flags']} ACK={rec['ack_flags']}\n"
        f"  Role 1 ML says: {rec['r1_label']} ({rec['r1_conf']}%)\n"
    )
    if rec.get('r1_shap'):
        shap_str = ", ".join([f"{f}={v}" for f, v in rec['r1_shap']])
        base_text += f"  Top features driving ML verdict: {shap_str}\n"
    
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
    r3_attack  = r3_verdict.get("verdict") in ("attack", "suspicious")
    if r1_attack and r3_attack:   return "agree_attack"
    if not r1_attack and not r3_attack: return "agree_benign"
    return "disagree"

# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND THREADS
# ══════════════════════════════════════════════════════════════════════════════

def llm_worker(ollama_url, model, timeout):
    """Background thread: dequeue flows, run Ollama, push SSE update."""
    while True:
        item = LLM_QUEUE.get()
        if item is None:
            break
        priority, count, fid, flow_text, rec = item
        r3 = role3_run(fid, flow_text, ollama_url, model, timeout)

        with STATS_LOCK:
            STATS["llm_pending"] = max(0, STATS["llm_pending"] - 1)
            if r3:
                r3_atk = r3.get("verdict") in ("attack", "suspicious")
                r1_atk = rec["r1_label"] not in BENIGN_LABELS
                if r3_atk: STATS["attacks_r3"] += 1
                if r1_atk == r3_atk: STATS["agree"] += 1
                else:                STATS["disagree"] += 1

        # Update the stored flow record
        for f in FLOWS:
            if f["id"] == fid:
                f["r3_verdict"]    = r3.get("verdict")     if r3 else "error"
                f["r3_attack_type"]= r3.get("attack_type") if r3 else "Unknown"
                f["r3_conf"]       = r3.get("confidence")  if r3 else 0
                f["r3_explanation"]= r3.get("explanation") if r3 else "Error connecting to LLM."
                f["r3_action"]     = r3.get("recommended_action") if r3 else ""
                f["agreement"]     = agreement_status(f["r1_label"], r3)
                break

        push_event("r3_update", {
            "id":           fid,
            "r3_verdict":   r3.get("verdict")     if r3 else "error",
            "r3_attack_type": r3.get("attack_type") if r3 else "Unknown",
            "r3_conf":      r3.get("confidence")  if r3 else 0,
            "r3_explanation": r3.get("explanation") if r3 else "Error connecting to LLM.",
            "r3_action":    r3.get("recommended_action") if r3 else "",
            "agreement":    agreement_status(rec["r1_label"], r3),
            "stats":        dict(STATS),
        })
        LLM_QUEUE.task_done()


IP_STATE = defaultdict(lambda: {'ports': set(), 'flow_count': 0, 'window_start': 0.0})
ALERT_STATE = {}  # Tracks last alert time: (src_ip, r1_label) -> float timestamp

def check_cross_flow_attack(flow):
    """
    Cross-flow heuristic over a fixed 10s ROLLING window per source IP.

    Previously this reset only after a 10s *idle* gap (time since the last
    flow), not on a wall-clock schedule. A source that stays continuously
    active — e.g. repeated dashboard polling long after the actual scan
    ended — never goes idle, so 'ports' only ever grew and, once it crossed
    the 20-port threshold during a real scan, every later flow from that
    source kept inheriting the "PortScan (Heuristics)" label regardless of
    what it actually looked like. Resetting on a fixed window start (not on
    idle) bounds the state to what happened in the last 10s, matching what
    the label claims.
    """
    now = time.time()
    state = IP_STATE[flow.src_ip]
    if now - state['window_start'] > 10:
        state['ports'] = set()
        state['flow_count'] = 0
        state['window_start'] = now
    state['ports'].add(flow.dst_port)
    state['flow_count'] += 1

    if len(state['ports']) > 20:
        return "PortScan (Heuristics)"
    if state['flow_count'] > 100:
        return "DoS/Flood (Heuristics)"
    return None


def nfstream_thread(source, ensemble, le, scaler, feats, explainers,
                    ollama_url, model, llm_timeout, bpf_filter=None):
    """Main capture thread: NFStream → Role 1 → SSE → LLM queue."""
    try:
        streamer = NFStreamer(
            source=source,
            statistical_analysis=True,
            idle_timeout=30, active_timeout=120,
            decode_tunnels=False, accounting_mode=0,
            bpf_filter=bpf_filter,
        )
    except Exception as e:
        print(f"\n❌ NFStream failed to open capture source '{source}': {e}", file=sys.stderr)
        if "Unable to activate source" in str(e) or "Permission" in str(e):
            print("💡 TIP: Sniffing live traffic requires root privileges or CAP_NET_RAW capability.", file=sys.stderr)
            print("   Run with sudo: sudo ./venv/bin/python nids_web.py ...", file=sys.stderr)
            print("   Or set capabilities: sudo setcap cap_net_raw,cap_net_admin+eip ./venv/bin/python3.14\n", file=sys.stderr)
        return

    proto_map = {6: "TCP", 17: "UDP"}

    try:
        for flow in streamer:
            try:
                r1_label, r1_conf, r1_top_features = role1_run(flow, ensemble, le, scaler, feats, explainers)
                
                # --- OVERRIDE WITH HEURISTICS ---
                heuristic_attack = check_cross_flow_attack(flow)
                if heuristic_attack:
                    r1_label = heuristic_attack
                    r1_conf = 100.0
                    
                is_attack = r1_label not in BENIGN_LABELS
                
                # --- SUPPRESS REPEATED ALERTS ---
                if is_attack:
                    now = time.time()
                    alert_key = (flow.src_ip, r1_label)
                    if now - ALERT_STATE.get(alert_key, 0) < 5:
                        # Update stats silently and skip UI update to prevent screen flooding
                        with STATS_LOCK:
                            STATS["total"] += 1
                            STATS["attacks_r1"] += 1
                        continue
                    ALERT_STATE[alert_key] = now
                    
                fid  = str(uuid.uuid4())[:8]
                ts   = datetime.now(timezone.utc).isoformat()
                proto = proto_map.get(flow.protocol, str(flow.protocol))

                rec = {
                    "id":           fid,
                    "timestamp":    ts,
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
                    "r1_shap":      r1_top_features,
                    "r1_is_attack": is_attack,
                    "r3_verdict":   None,
                    "r3_attack_type": None,
                    "r3_conf":      None,
                    "r3_explanation": None,
                    "r3_action":    None,
                    "agreement":    "pending",
                }
                FLOWS.appendleft(rec)

                with STATS_LOCK:
                    STATS["total"] += 1
                    if is_attack: STATS["attacks_r1"] += 1

                push_event("new_flow", {"flow": rec, "stats": dict(STATS)})

                # Queue for Role 3 (ALL flows — so you can compare both verdicts)
                flow_text = format_flow_for_llm(rec)
                try:
                    if r1_label == "DoS/Flood (Heuristics)":
                        priority = 0
                    elif is_attack:
                        priority = 1
                    else:
                        priority = 2
                    LLM_QUEUE.put_nowait((priority, next(LLM_QUEUE_COUNTER), fid, flow_text, rec))
                    with STATS_LOCK:
                        STATS["llm_pending"] += 1
                except Full:
                    pass   # LLM queue full — skip this flow's R3 analysis

            except Exception as exc:
                print(f"  Flow error: {exc}", file=sys.stderr)
    except Exception as stream_err:
        print(f"  NFStream stream error: {stream_err}", file=sys.stderr)
        if "Unable to activate source" in str(stream_err):
            print("💡 TIP: Live interface packet sniffing requires root/sudo privileges or CAP_NET_RAW capability.", file=sys.stderr)

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
  updateElementVisibility(flows[d.id], el);
  updateVisibleCount();
});

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
    return jsonify(list(FLOWS))


@app.route("/api/stats")
def api_stats():
    return jsonify(dict(STATS))


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
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

    print("\n" + "═"*60)
    print("  NIDS Web Dashboard — Role 1 (ML) vs Role 3 (LLM)")
    print("═"*60)
    print(f"  PKL     : {args.pkl}")
    source = args.pcap if args.pcap else args.iface
    print(f"  Source  : {source}")
    is_local_ollama = "localhost" in args.ollama_url or "127.0.0.1" in args.ollama_url
    print(f"  Ollama  : {args.ollama_url}  model={args.ollama_model}"
          f"  ({'local' if is_local_ollama else 'custom/3rd-party'})")
    print(f"  LLM     : {'disabled' if args.no_llm else 'enabled (ALL flows sent to LLM for comparison)'}")
    print(f"  Web UI  : http://localhost:{args.port}")
    print("═"*60 + "\n")

    # Load model
    print("  Loading model…")
    ensemble, le, scaler, feats, explainers = load_model(args.pkl)
    print("  ✓ Model loaded\n")

    # Load history state
    load_state()
    
    # Start state saver thread
    threading.Thread(target=state_saver_worker, daemon=True).start()

    # Check Ollama
    llm_ok = False
    if not args.no_llm:
        try:
            r = requests.get(f"{args.ollama_url}/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models",[])]
                base   = args.ollama_model.split(":")[0]
                llm_ok = any(base in m for m in models)
        except Exception:
            pass

        if llm_ok:
            print(f"  ✓ Ollama ready ({args.ollama_model})\n")
        else:
            # For remote 3rd party URLs, allow bypassing strict verification
            is_local = "localhost" in args.ollama_url or "127.0.0.1" in args.ollama_url
            if not is_local:
                print(f"  ⚠ Could not verify model on remote Ollama ({args.ollama_url}).")
                print(f"    Proceeding anyway since it is a remote endpoint...\n")
                llm_ok = True
            else:
                print(f"  ⚠ Ollama not reachable — Role 3 will be skipped\n"
                      f"    Start with: ollama serve && ollama pull {args.ollama_model}\n")

    # Start LLM workers (4 threads for parallel sub-second CPU processing)
    if llm_ok:
        for _ in range(4):
            t = threading.Thread(
                target=llm_worker,
                args=(args.ollama_url, args.ollama_model, args.llm_timeout),
                daemon=True,
            )
            t.start()

    # Start NFStream capture thread
    capture_src = args.pcap if args.pcap else args.iface
    bpf_filter = None
    if not args.no_exclude_self and not args.pcap:
        bpf_filter = build_self_exclusion_bpf(args.port, args.ollama_url, args.exclude)
        print(f"  Capture filter: excluding self-traffic ({bpf_filter})\n")
    t = threading.Thread(
        target=nfstream_thread,
        args=(capture_src, ensemble, le, scaler, feats, explainers,
              args.ollama_url, args.ollama_model, args.llm_timeout, bpf_filter),
        daemon=True,
    )
    t.start()

    # Start Flask (threaded so SSE works properly)
    app.run(host="0.0.0.0", port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
