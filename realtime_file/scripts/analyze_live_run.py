#!/usr/bin/env python3
"""
scripts/analyze_live_run.py
===========================
Comprehensive post-run analyzer for real-time NIDS experiments.
Reads the complete append-only RunLogger artifacts in data/runs/<run_id>/
(flows.jsonl, r3.jsonl, phases.jsonl, run_meta.json) PLUS Approach B's
unified_alerts.jsonl and Suricata eve.json / fast.log, and produces:

  - <run_dir>/experiment_report.json
  - <run_dir>/EXPERIMENT_REPORT.md
  - data/results/eval/live_full_report.json
  - data/results/LIVE_FULL_REPORT.md

Covers everything required for the journal paper:
  1. Approach A complete (unclipped) flow counts, Role 1 model-only vs
     Role 1 + heuristics vs Role 3 LLM vs Agreement/Disagreement
  2. Per-phase (or auto-segmented attack burst) detection, hit counts,
     time-to-first-alert, and benign-side false positives
  3. Benign baseline FPR (%) and alerts/hour per role
  4. Approach B (Suricata + CICFlowMeter + Decision Engine) window & alert summary
  5. End-to-end latency distributions (mean, std, p50, p95, p99, max) for
     Role 1 batch, capture-to-verdict, Role 3 LLM round-trip, queue wait,
     and Ollama GPU eval duration
  6. LLM parse/error audit (valid JSON vs timeout vs HTTP error vs verdict counts)
  7. Live train-vs-deploy feature drift against the model's RobustScaler
"""

import argparse
import glob
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.engine.universal_ensemble import UniversalEnsemble  # noqa: F401,E402
from src.live.behavioral_guard import is_attack_verdict, normalize_llm_verdict  # noqa: E402

BENIGN_LABELS = {"", "benign", "normal", "none", "unknown"}


def _is_attack_label(lbl):
    return str(lbl or "").strip().lower() not in BENIGN_LABELS


def _is_attack_r3(verdict):
    return is_attack_verdict(verdict)


def _percentiles(vals):
    if not vals:
        return {"n": 0}
    arr = np.asarray(vals, dtype=float)
    return {
        "n": int(len(arr)),
        "mean": round(float(arr.mean()), 3),
        "std": round(float(arr.std()), 3),
        "min": round(float(arr.min()), 3),
        "p50": round(float(np.percentile(arr, 50)), 3),
        "p95": round(float(np.percentile(arr, 95)), 3),
        "p99": round(float(np.percentile(arr, 99)), 3),
        "max": round(float(arr.max()), 3),
    }


def _read_jsonl(path):
    rows = []
    if not path or not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def _detect_attacker_ip(flows, host_ip=None):
    counts = Counter()
    for f in flows:
        src = f.get("src_ip", "")
        if not src or src == host_ip or src.startswith("127."):
            continue
        if src.startswith(("192.168.", "10.", "172.")):
            counts[src] += 1
    if not counts:
        return None, {}
    return counts.most_common(1)[0][0], dict(counts.most_common(10))


def _flow_time_s(f):
    fs = f.get("flow_first_seen_ms")
    if fs:
        return float(fs) / 1000.0
    return float(f.get("t_r1_done") or 0.0)


def _segment_bursts(flows, attacker_ip, gap_sec=20.0):
    def _is_multicast(ip):
        return not ip or ip.startswith(("224.", "239.", "255.", "ff"))

    atk = sorted(
        [
            f for f in flows
            if (f.get("src_ip") == attacker_ip or f.get("dst_ip") == attacker_ip)
            and not _is_multicast(f.get("dst_ip", ""))
            and str(f.get("protocol")) != "2"
        ],
        key=_flow_time_s,
    )
    if not atk:
        return []
    bursts = []
    cur = [atk[0]]
    for f in atk[1:]:
        if (_flow_time_s(f) - _flow_time_s(cur[-1])) > gap_sec:
            bursts.append(cur)
            cur = [f]
        else:
            cur.append(f)
    bursts.append(cur)

    labeled = []
    port80_idx = 0
    for i, b in enumerate(bursts, 1):
        ports = {f.get("dst_port") for f in b if f.get("src_ip") == attacker_ip}
        n_flows = len(b)
        if 22 in ports and len(ports) <= 5:
            guess = "Brute Force (SSH)"
        elif 21 in ports and len(ports) <= 5:
            guess = "Brute Force (FTP)"
        elif len(ports) > 15:
            guess = f"PortScan ({len(ports)} ports)"
        elif ports & {80, 443, 8080, 8443}:
            port80_idx += 1
            syns = sum(f.get("syn", 0) for f in b)
            acks = sum(f.get("ack", 0) for f in b)
            if n_flows >= 500 or (n_flows >= 50 and acks <= syns * 0.1):
                guess = "DoS / SYN Flood"
            elif port80_idx == 1 and n_flows >= 100 and syns > acks:
                guess = "DoS / Flood"
            else:
                guess = "Web Attack / Scan"
        else:
            guess = f"Traffic burst #{i} (ports={sorted(ports)[:5]})"
        labeled.append({
            "phase": guess,
            "t_start": min(_flow_time_s(f) for f in b),
            "t_end": max(_flow_time_s(f) for f in b),
            "t_r1_first": min(f.get("t_r1_done", 0) for f in b),
            "flows": b,
            "ports_count": len(ports),
        })
    return labeled


def _build_phases(phases_log, flows, attacker_ip, gap_sec=20.0):
    bursts = _segment_bursts(flows, attacker_ip, gap_sec=gap_sec)
    for b in bursts:
        b["source"] = "auto_burst"
    return bursts


def _feature_drift(flows, pkl_path):
    if not flows or not os.path.exists(pkl_path):
        return None
    sample_vecs = [f["features"] for f in flows if isinstance(f.get("features"), dict)]
    if not sample_vecs:
        return None
    import joblib
    out = joblib.load(pkl_path)
    feats = out["sub_features"]["CICIDS2017"]
    scaler = (out.get("sub_scalers") or {}).get("CICIDS2017") or out.get("scaler")
    if scaler is None or not hasattr(scaler, "center_"):
        return None
    X = np.array([[row.get(ft, 0.0) for ft in feats] for row in sample_vecs], dtype=np.float64)
    dep_med = np.nanmedian(X, axis=0)
    drifted = []
    for i, ft in enumerate(feats):
        tr_m = float(scaler.center_[i])
        tr_s = float(scaler.scale_[i])
        dp_m = float(dep_med[i])
        ratio = None
        if abs(tr_m) > 1e-9 and abs(dp_m) > 1e-9:
            ratio = dp_m / tr_m
            if np.isfinite(ratio) and abs(np.log10(abs(ratio))) >= 1.0:
                drifted.append({"feature": ft, "train_median": tr_m, "live_median": dp_m, "ratio": round(ratio, 3)})
        elif tr_s > 1e-9:
            z = abs(dp_m - tr_m) / tr_s
            if z >= 10.0:
                drifted.append({"feature": ft, "train_median": tr_m, "live_median": dp_m, "z_iqr": round(z, 2)})
    return {
        "n_flows_checked": len(X),
        "n_features": len(feats),
        "n_drifted_10x": len(drifted),
        "drifted_features": drifted[:15],
    }


def _merge_pcaps(run_dir):
    pcaps_dir = os.path.join(run_dir, "pcaps")
    out_pcap = os.path.join(run_dir, "capture.pcap")
    if not os.path.isdir(pcaps_dir):
        return None
    chunks = sorted(
        p for p in glob.glob(os.path.join(pcaps_dir, "*.pcap*"))
        if os.path.getsize(p) > 24
    )
    if not chunks:
        return None
    import shutil
    mergecap = shutil.which("mergecap")
    if mergecap:
        res = subprocess.run([mergecap, "-F", "pcap", "-w", out_pcap, *chunks],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0 and os.path.exists(out_pcap):
            return {"path": out_pcap, "chunks": len(chunks), "bytes": os.path.getsize(out_pcap)}
    return {"chunks": len(chunks), "bytes": sum(os.path.getsize(c) for c in chunks)}


def main():
    ap = argparse.ArgumentParser(description="Analyze a complete live NIDS run for journal reporting.")
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--attacker-ip", default=None)
    ap.add_argument("--pkl", default="universal_nids_output.pkl")
    ap.add_argument("--alerts", default="data/results/unified_alerts.jsonl")
    ap.add_argument("--eve", default="data/live_b/suricata_logs/eve.json")
    ap.add_argument("--fast-log", default="data/live_b/suricata_logs/fast.log")
    ap.add_argument("--gap", type=float, default=20.0)
    ap.add_argument("--merge-pcap", action="store_true")
    args = ap.parse_args()

    run_dir = args.run_dir
    if not run_dir:
        latest = os.path.join(ROOT, "data", "runs", "latest_run.txt")
        if os.path.exists(latest):
            run_dir = open(latest).read().strip()
    if not run_dir or not os.path.isdir(run_dir):
        print("✗ Run directory not found. Pass --run-dir data/runs/<run_id>", file=sys.stderr)
        sys.exit(1)

    meta = {}
    meta_path = os.path.join(run_dir, "run_meta.json")
    if os.path.exists(meta_path):
        meta = json.load(open(meta_path))

    flows = _read_jsonl(os.path.join(run_dir, "flows.jsonl"))
    r3_rows = _read_jsonl(os.path.join(run_dir, "r3.jsonl"))
    phases_log = _read_jsonl(os.path.join(run_dir, "phases.jsonl"))
    r3_by_id = {r["id"]: r for r in r3_rows if "id" in r}

    host_ip = meta.get("host_ip")
    attacker_ip = args.attacker_ip
    lan_sources = {}
    if not attacker_ip:
        attacker_ip, lan_sources = _detect_attacker_ip(flows, host_ip=host_ip)

    # Duration
    if flows:
        ts_list = [f.get("t_r1_done") for f in flows if f.get("t_r1_done")]
        t0 = meta.get("start_epoch") or min(ts_list)
        t1 = max(ts_list)
        dur_s = max(1.0, t1 - t0)
    else:
        dur_s = 1.0
    dur_h = dur_s / 3600.0

    # Overall Approach A summary
    n_total = len(flows)
    r1_model_atk = sum(1 for f in flows if f.get("model_is_attack"))
    r1_total_atk = sum(1 for f in flows if f.get("r1_is_attack"))
    r1_heur_atk = sum(1 for f in flows if f.get("heuristic_label"))
    ui_suppressed = sum(1 for f in flows if f.get("ui_suppressed"))
    r1_label_counts = Counter(f.get("r1_label") for f in flows)
    model_label_counts = Counter(f.get("model_label") for f in flows)

    # Role 3 audit
    r3_ok = [r for r in r3_rows if r.get("status") == "ok"]
    r3_err = [r for r in r3_rows if r.get("status") != "ok"]
    r3_atk = sum(1 for r in r3_ok if _is_attack_r3(r.get("verdict")))
    r3_verdict_counts = Counter(r.get("verdict") for r in r3_ok)
    r3_err_counts = Counter(r.get("error") for r in r3_err)
    ag_counts = Counter(r.get("agreement") for r in r3_ok)

    # Latencies
    r1_flow_lat = [f["r1_ms_per_flow"] for f in flows if f.get("r1_ms_per_flow") is not None]
    recv_to_v = [f["recv_to_verdict_ms"] for f in flows if f.get("recv_to_verdict_ms") is not None]
    r3_lat = [r["latency_ms"] for r in r3_ok if r.get("latency_ms") is not None]
    r3_wait = [r["queue_wait_ms"] for r in r3_ok if r.get("queue_wait_ms") is not None]
    r3_gpu = [r["ollama_total_duration_ms"] for r in r3_ok if r.get("ollama_total_duration_ms") is not None]

    # Split attacker vs reply-to-attacker vs pure benign-background
    atk_flows = [f for f in flows if attacker_ip and f.get("src_ip") == attacker_ip]
    reply_flows = [f for f in flows if attacker_ip and f.get("src_ip") != attacker_ip and f.get("dst_ip") == attacker_ip]
    bg_flows = [f for f in flows if attacker_ip and f.get("src_ip") != attacker_ip and f.get("dst_ip") != attacker_ip]
    bg_r1_fp = sum(1 for f in bg_flows if f.get("r1_is_attack"))
    bg_r1_model_fp = sum(1 for f in bg_flows if f.get("model_is_attack"))
    bg_r3_obs = [r3_by_id[f["id"]] for f in bg_flows if f.get("id") in r3_by_id and r3_by_id[f["id"]].get("status") == "ok"]
    bg_r3_fp = sum(1 for r in bg_r3_obs if _is_attack_r3(r.get("verdict")))

    # Per-phase / per-burst breakdown
    phase_entries = _build_phases(phases_log, flows, attacker_ip, gap_sec=args.gap)
    phase_reports = []
    for ph in phase_entries:
        pflows = ph["flows"]
        if not pflows:
            continue
        p_t0 = ph["t_start"]
        p_r1_hits = [f for f in pflows if f.get("r1_is_attack")]
        p_m_hits = [f for f in pflows if f.get("model_is_attack")]
        p_r3_done = [r3_by_id[f["id"]] for f in pflows if f.get("id") in r3_by_id and r3_by_id[f["id"]].get("status") == "ok"]
        p_r3_hits = [r for r in p_r3_done if _is_attack_r3(r.get("verdict"))]
        tta_r1 = round(min(f["t_r1_done"] for f in p_r1_hits) - p_t0, 2) if p_r1_hits else None
        tta_r3 = round(min(r["t_end"] for r in p_r3_hits) - p_t0, 2) if p_r3_hits else None
        phase_reports.append({
            "phase": ph["phase"],
            "source": ph["source"],
            "start_utc": datetime.fromtimestamp(ph["t_start"], timezone.utc).isoformat(),
            "end_utc": datetime.fromtimestamp(ph["t_end"], timezone.utc).isoformat(),
            "duration_s": round(ph["t_end"] - ph["t_start"], 2),
            "flows": len(pflows),
            "role1_model_hits": len(p_m_hits),
            "role1_total_hits": len(p_r1_hits),
            "role1_hit_pct": round(100 * len(p_r1_hits) / max(1, len(pflows)), 1),
            "role1_top_labels": dict(Counter(f.get("r1_label") for f in p_r1_hits).most_common(5)),
            "role3_evaluated": len(p_r3_done),
            "role3_hits": len(p_r3_hits),
            "role3_hit_pct": round(100 * len(p_r3_hits) / max(1, len(p_r3_done)), 1),
            "time_to_first_alert_r1_s": tta_r1,
            "time_to_first_alert_r3_s": tta_r3,
        })

    # Approach B summary
    alerts_b = _read_jsonl(args.alerts)
    b_summary = None
    if alerts_b:
        b_summary = {
            "windows": len(alerts_b),
            "role1_attack_windows": sum(1 for a in alerts_b if str(a.get("role1_verdict")) == "attack"),
            "role3_attack_windows": sum(1 for a in alerts_b if str(a.get("role3_verdict")) in ("attack", "suspicious")),
            "final_attack_windows": sum(1 for a in alerts_b if str(a.get("final_verdict")) in ("attack", "suspicious")),
            "severity_counts": dict(Counter(str(a.get("severity")) for a in alerts_b)),
            "role3_error_windows": sum(1 for a in alerts_b if str(a.get("role3_verdict")) == "error"),
        }

    # Suricata eve.json summary
    suri_summary = None
    if os.path.exists(args.eve):
        suri_alerts = 0
        suri_events = 0
        sigs = Counter()
        with open(args.eve, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                suri_events += 1
                if ev.get("event_type") == "alert":
                    suri_alerts += 1
                    sigs[(ev.get("alert") or {}).get("signature", "?")] += 1
        suri_summary = {
            "total_events": suri_events,
            "alert_events": suri_alerts,
            "top_signatures": sigs.most_common(15),
        }

    pcap_info = _merge_pcaps(run_dir) if args.merge_pcap else None
    drift = _feature_drift(flows, args.pkl)

    report = {
        "run_id": meta.get("run_id") or os.path.basename(run_dir),
        "run_dir": run_dir,
        "meta": meta,
        "duration_seconds": round(dur_s, 1),
        "attacker_ip": attacker_ip,
        "lan_source_counts": lan_sources,
        "approach_a": {
            "flows_total": n_total,
            "ui_suppressed_flows": ui_suppressed,
            "role1_model_only_attacks": r1_model_atk,
            "role1_heuristic_attacks": r1_heur_atk,
            "role1_combined_attacks": r1_total_atk,
            "role1_model_labels": dict(model_label_counts),
            "role1_combined_labels": dict(r1_label_counts),
            "attacker_flows": len(atk_flows),
            "reply_to_attacker_flows": len(reply_flows),
            "attacker_r1_hits": sum(1 for f in atk_flows if f.get("r1_is_attack")),
            "attacker_r1_model_hits": sum(1 for f in atk_flows if f.get("model_is_attack")),
            "benign_background": {
                "flows": len(bg_flows),
                "role1_model_fp": bg_r1_model_fp,
                "role1_combined_fp": bg_r1_fp,
                "role1_fpr_pct": round(100 * bg_r1_fp / max(1, len(bg_flows)), 3),
                "role1_alerts_per_hour": round(bg_r1_fp / dur_h, 1),
                "role3_evaluated": len(bg_r3_obs),
                "role3_fp": bg_r3_fp,
                "role3_fpr_pct": round(100 * bg_r3_fp / max(1, len(bg_r3_obs)), 3),
                "role3_alerts_per_hour": round(bg_r3_fp / dur_h, 1),
            },
        },
        "role3_llm_audit": {
            "total_calls": len(r3_rows),
            "ok": len(r3_ok),
            "errors": len(r3_err),
            "valid_json_pct": round(100 * len(r3_ok) / max(1, len(r3_rows)), 2),
            "error_breakdown": dict(r3_err_counts),
            "verdict_counts": dict(r3_verdict_counts),
            "attacks_or_suspicious": r3_atk,
            "agreement_counts": dict(ag_counts),
        },
        "latencies_ms": {
            "role1_amortized_per_flow": _percentiles(r1_flow_lat),
            "capture_to_verdict": _percentiles(recv_to_v),
            "role3_llm_roundtrip": _percentiles(r3_lat),
            "role3_queue_wait": _percentiles(r3_wait),
            "ollama_server_total_duration": _percentiles(r3_gpu),
        },
        "phases": phase_reports,
        "approach_b": b_summary,
        "suricata": suri_summary,
        "feature_drift": drift,
        "raw_pcap": pcap_info,
    }

    out_json = os.path.join(run_dir, "experiment_report.json")
    with open(out_json, "w") as f:
        json.dump(report, f, indent=2, default=str)

    os.makedirs(os.path.join(ROOT, "data", "results", "eval"), exist_ok=True)
    with open(os.path.join(ROOT, "data", "results", "eval", "live_full_report.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Render Markdown summary
    md = [
        f"# Live Experiment Report — `{report['run_id']}`",
        "",
        f"- **Duration**: {report['duration_seconds']} s ({dur_h:.2f} h)",
        f"- **Host**: `{meta.get('host_ip')}` (`{meta.get('iface')}`, backend `{meta.get('capture_backend')}`)",
        f"- **Detected Attacker IP**: `{attacker_ip}`",
        f"- **Ollama**: `{meta.get('ollama_url')}` | model `{meta.get('ollama_model')}` ({'local' if meta.get('ollama_is_local') else 'remote tunnel'})",
        f"- **SHAP source**: `{meta.get('shap_source')}`",
        "",
        "## 1. Approach A (`nids_web.py`) — Complete Flow Log",
        f"- Total flows captured: **{n_total}** ({ui_suppressed} UI-suppressed during bursts, all preserved in `flows.jsonl`)",
        f"- Role 1 (ML model alone) attacks: **{r1_model_atk}** | Heuristic overrides: **{r1_heur_atk}** | Combined R1 attacks: **{r1_total_atk}**",
        f"- Role 3 (LLM) evaluated: **{len(r3_rows)}** | Valid JSON: **{len(r3_ok)}** ({report['role3_llm_audit']['valid_json_pct']}%) | Errors: **{len(r3_err)}** | LLM Attack/Suspicious: **{r3_atk}**",
        f"- Agreement counts: `{dict(ag_counts)}`",
        "",
        "## 2. Per-Phase / Per-Attack Detection",
        "",
        "| Phase / Attack | Source | Flows | R1 Model Hits | R1+Heur Hits (%) | R3 Eval | R3 Hits (%) | TTA R1 (s) | TTA R3 (s) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for p in phase_reports:
        md.append(
            f"| {p['phase']} | {p['source']} | {p['flows']} | {p['role1_model_hits']} | "
            f"{p['role1_total_hits']} ({p['role1_hit_pct']}%) | {p['role3_evaluated']} | "
            f"{p['role3_hits']} ({p['role3_hit_pct']}%) | {p['time_to_first_alert_r1_s']} | {p['time_to_first_alert_r3_s']} |"
        )

    bg = report["approach_a"]["benign_background"]
    md += [
        "",
        "## 3. Benign-Side False Positives",
        f"- Non-attacker flows observed: **{bg['flows']}**",
        f"- Role 1 (ML+Heur) FP: **{bg['role1_combined_fp']}** (FPR **{bg['role1_fpr_pct']}%**, **{bg['role1_alerts_per_hour']}/h**) [ML-only FP: {bg['role1_model_fp']}]",
        f"- Role 3 (LLM) FP: **{bg['role3_fp']}/{bg['role3_evaluated']}** (FPR **{bg['role3_fpr_pct']}%**, **{bg['role3_alerts_per_hour']}/h**)",
        "",
        "## 4. Latency Breakdown (ms)",
        "",
        "| Stage | N | Mean | p50 | p95 | p99 | Max |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, st in report["latencies_ms"].items():
        if st.get("n"):
            md.append(f"| {name} | {st['n']} | {st['mean']} | {st['p50']} | {st['p95']} | {st['p99']} | {st['max']} |")

    if b_summary:
        md += [
            "",
            "## 5. Approach B (Unified Suricata + CICFlowMeter + Decision Engine)",
            f"- Windows evaluated: **{b_summary['windows']}**",
            f"- Role 1 attack windows: **{b_summary['role1_attack_windows']}** | Role 3 attack windows: **{b_summary['role3_attack_windows']}** | Final attack windows: **{b_summary['final_attack_windows']}**",
            f"- Severity distribution: `{b_summary['severity_counts']}`",
        ]
    if suri_summary:
        md += [
            "",
            "## 6. Suricata Alerts",
            f"- Total EVE events: **{suri_summary['total_events']}** | Alert events: **{suri_summary['alert_events']}**",
        ]
        for sig, cnt in suri_summary["top_signatures"][:10]:
            md.append(f"  - `{cnt}x` {sig}")
    if drift:
        md += [
            "",
            "## 7. Live Train-vs-Deploy Feature Drift Check",
            f"- Flows checked: **{drift['n_flows_checked']}** | Features >=10x shifted vs training RobustScaler: **{drift['n_drifted_10x']}/{drift['n_features']}**",
        ]
        for d in drift["drifted_features"][:10]:
            md.append(f"  - `{d['feature']}`: train_med={d['train_median']:.4g}, live_med={d['live_median']:.4g}")

    md_text = "\n".join(md) + "\n"
    out_md = os.path.join(run_dir, "EXPERIMENT_REPORT.md")
    with open(out_md, "w") as f:
        f.write(md_text)
    with open(os.path.join(ROOT, "data", "results", "LIVE_FULL_REPORT.md"), "w") as f:
        f.write(md_text)

    print(md_text)
    print(f"✓ Saved JSON -> {out_json}")
    print(f"✓ Saved MD   -> {out_md}")


if __name__ == "__main__":
    main()
