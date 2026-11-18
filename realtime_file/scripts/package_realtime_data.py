#!/usr/bin/env python3
"""
scripts/package_realtime_data.py
================================
Packages ALL artifacts from the real-time NIDS simulation (PCAPs, CSVs,
JSON/JSONL logs, Suricata logs, Approach B chunks, evaluation reports, and
service logs) into `<root>/realtime_data/` for journal writing and archival.
"""

import csv
import glob
import json
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "realtime_data")


def _export_flows_csv(flows_jsonl, out_csv):
    if not os.path.exists(flows_jsonl):
        return 0
    first_meta = [
        "id", "ts_utc", "t_recv", "t_r1_start", "t_r1_done",
        "flow_first_seen_ms", "flow_last_seen_ms",
        "export_to_verdict_ms", "recv_to_verdict_ms",
        "r1_batch_size", "r1_ms_per_flow",
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "ip_version", "application_name",
        "duration_ms", "packets", "bytes", "src2dst_packets", "dst2src_packets",
        "syn", "fin", "rst", "psh", "ack",
        "model_label", "model_conf", "model_is_attack",
        "heuristic_label", "r1_label", "r1_conf", "r1_is_attack",
        "ui_suppressed", "r3_status", "r1_shap_top",
    ]
    feature_cols = None
    n = 0
    with open(flows_jsonl, encoding="utf-8", errors="replace") as src, \
         open(out_csv, "w", newline="", encoding="utf-8") as dst:
        w = None
        for line in src:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            feats = rec.get("features") or {}
            if feature_cols is None:
                feature_cols = list(feats.keys())
                w = csv.writer(dst)
                w.writerow(first_meta + feature_cols)
            row = [
                json.dumps(rec.get(k)) if k == "r1_shap_top" else rec.get(k, "")
                for k in first_meta
            ] + [feats.get(c, "") for c in feature_cols]
            w.writerow(row)
            n += 1
    return n


def _export_r3_csv(r3_jsonl, out_csv):
    if not os.path.exists(r3_jsonl):
        return 0
    cols = [
        "id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "r1_label", "r1_conf", "priority",
        "t_enqueued", "t_start", "t_end",
        "queue_wait_ms", "latency_ms",
        "ollama_eval_count", "ollama_total_duration_ms",
        "status", "error", "verdict", "attack_type", "confidence",
        "agreement", "explanation", "recommended_action",
    ]
    n = 0
    with open(r3_jsonl, encoding="utf-8", errors="replace") as src, \
         open(out_csv, "w", newline="", encoding="utf-8") as dst:
        w = csv.writer(dst)
        w.writerow(cols)
        for line in src:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            w.writerow([rec.get(c, "") for c in cols])
            n += 1
    return n


def _export_b_alerts_csv(alerts_jsonl, out_csv):
    if not os.path.exists(alerts_jsonl):
        return 0
    cols = [
        "timestamp", "severity", "suppressed",
        "final_verdict", "attack_type", "confidence",
        "role1_verdict", "role1_attack_type", "role1_confidence",
        "role3_verdict", "role3_attack_type", "role3_confidence",
        "agree", "conflict",
        "src_ip", "src_port", "dst_ip", "dst_port",
        "n_flows", "n_attacks", "attack_fraction", "dataset_routed",
        "shap_top_features", "role3_explanation", "recommended_action",
    ]
    n = 0
    with open(alerts_jsonl, encoding="utf-8", errors="replace") as src, \
         open(out_csv, "w", newline="", encoding="utf-8") as dst:
        w = csv.writer(dst)
        w.writerow(cols)
        for line in src:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ff = rec.get("flow_features") or {}
            row = []
            for c in cols:
                if c in rec:
                    val = rec[c]
                    row.append(json.dumps(val) if isinstance(val, (list, dict)) else val)
                else:
                    row.append(ff.get(c, ""))
            w.writerow(row)
            n += 1
    return n


def _copy_if_exists(src, dst):
    if os.path.exists(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        return True
    return False


def main():
    latest_txt = os.path.join(ROOT, "data", "runs", "latest_run.txt")
    if not os.path.exists(latest_txt):
        raise SystemExit("data/runs/latest_run.txt not found")
    run_dir = open(latest_txt).read().strip()
    if not os.path.isabs(run_dir):
        run_dir = os.path.join(ROOT, run_dir)

    if os.path.exists(OUT):
        shutil.rmtree(OUT)

    for sub in (
        "pcaps/segments",
        "csv/cicflow_csv",
        "json/suricata",
        "chunks",
        "reports/eval",
        "logs",
    ):
        os.makedirs(os.path.join(OUT, sub), exist_ok=True)

    # 1. PCAPs (full merged capture + all 200 segments)
    _copy_if_exists(os.path.join(run_dir, "capture.pcap"), os.path.join(OUT, "pcaps", "capture_full.pcap"))
    n_pcaps = 0
    for p in sorted(glob.glob(os.path.join(run_dir, "pcaps", "*.pcap*"))):
        shutil.copy2(p, os.path.join(OUT, "pcaps", "segments", os.path.basename(p)))
        n_pcaps += 1

    # 2. CSVs (CICFlowMeter CSVs + flattened exports of Approach A & B)
    n_cic = 0
    for p in sorted(glob.glob(os.path.join(ROOT, "data", "cicflow_csv", "*.csv"))):
        shutil.copy2(p, os.path.join(OUT, "csv", "cicflow_csv", os.path.basename(p)))
        n_cic += 1
    n_a_csv = _export_flows_csv(os.path.join(run_dir, "flows.jsonl"), os.path.join(OUT, "csv", "approach_a_flows.csv"))
    n_r3_csv = _export_r3_csv(os.path.join(run_dir, "r3.jsonl"), os.path.join(OUT, "csv", "approach_a_r3.csv"))
    n_b_csv = _export_b_alerts_csv(os.path.join(ROOT, "data", "results", "unified_alerts.jsonl"), os.path.join(OUT, "csv", "approach_b_alerts.csv"))

    # 3. JSON / JSONL / Suricata logs
    for fname in ("run_meta.json", "flows.jsonl", "r3.jsonl", "phases.jsonl"):
        _copy_if_exists(os.path.join(run_dir, fname), os.path.join(OUT, "json", fname))
    _copy_if_exists(os.path.join(ROOT, "nids_history.json"), os.path.join(OUT, "json", "nids_history.json"))
    _copy_if_exists(os.path.join(ROOT, "data", "results", "unified_alerts.jsonl"), os.path.join(OUT, "json", "unified_alerts.jsonl"))
    _copy_if_exists(os.path.join(ROOT, "data", "results", "role1_proba_debug.jsonl"), os.path.join(OUT, "json", "role1_proba_debug.jsonl"))
    for sfile in ("eve.json", "fast.log", "stats.log", "suricata.log"):
        _copy_if_exists(os.path.join(ROOT, "data", "live_b", "suricata_logs", sfile), os.path.join(OUT, "json", "suricata", sfile))

    # 4. Approach B LLM prompt chunks
    n_chunks = 0
    for p in sorted(glob.glob(os.path.join(ROOT, "data", "chunks", "*"))):
        if os.path.isfile(p):
            shutil.copy2(p, os.path.join(OUT, "chunks", os.path.basename(p)))
            n_chunks += 1

    # 5. Reports + evaluate_nids outputs + live config
    _copy_if_exists(os.path.join(run_dir, "EXPERIMENT_REPORT.md"), os.path.join(OUT, "reports", "EXPERIMENT_REPORT.md"))
    _copy_if_exists(os.path.join(run_dir, "experiment_report.json"), os.path.join(OUT, "reports", "experiment_report.json"))
    _copy_if_exists(os.path.join(ROOT, "data", "results", "LIVE_FULL_REPORT.md"), os.path.join(OUT, "reports", "LIVE_FULL_REPORT.md"))
    _copy_if_exists(os.path.join(ROOT, "data", "results", "LIVE_TEST_SUMMARY.md"), os.path.join(OUT, "reports", "LIVE_TEST_SUMMARY.md"))
    _copy_if_exists(os.path.join(ROOT, "config", "settings_live.yaml"), os.path.join(OUT, "reports", "settings_live.yaml"))
    for p in sorted(glob.glob(os.path.join(ROOT, "data", "results", "eval", "*"))):
        if os.path.isfile(p):
            shutil.copy2(p, os.path.join(OUT, "reports", "eval", os.path.basename(p)))

    # 6. Service logs
    for p in sorted(glob.glob(os.path.join(ROOT, "logs", "*"))):
        if os.path.isfile(p):
            shutil.copy2(p, os.path.join(OUT, "logs", os.path.basename(p)))

    # 7. Manifest
    manifest = f"""# Real-Time NIDS Simulation Dataset (`realtime_data/`)

Run ID: `{os.path.basename(run_dir)}`

## Folder Layout
- `pcaps/`
  - `capture_full.pcap` — merged raw capture on live interface (`segments/` combined via `mergecap`)
  - `segments/` — `{n_pcaps}` individual 5-second classic PCAP segments
- `csv/`
  - `cicflow_csv/` — `{n_cic}` CICFlowMeter 82-column flow CSVs extracted for Approach B
  - `approach_a_flows.csv` — `{n_a_csv}` complete per-flow records (metadata, verdicts, top SHAP, all 52 features)
  - `approach_a_r3.csv` — `{n_r3_csv}` Role-3 LLM evaluation rows (verdict, raw verdict, latency, queue wait, error status)
  - `approach_b_alerts.csv` — `{n_b_csv}` Approach-B 20-second window decision-engine rows
- `json/`
  - `run_meta.json`, `flows.jsonl`, `r3.jsonl`, `phases.jsonl` — complete append-only Approach-A run logs
  - `nids_history.json` — Approach-A dashboard snapshot
  - `unified_alerts.jsonl` — Approach-B window-level decision-engine output
  - `role1_proba_debug.jsonl` — per-flow full class probability distribution & SHAP benign-push diagnostics
  - `suricata/` — Suricata 7.0.3 `eve.json`, `fast.log`, `stats.log`, `suricata.log`
- `chunks/` — `{n_chunks}` Approach-B plain-text window chunks fed to Role 3
- `reports/` — `EXPERIMENT_REPORT.md`, `experiment_report.json`, `LIVE_FULL_REPORT.md`, `LIVE_TEST_SUMMARY.md`, `settings_live.yaml`, and `eval/` (`evaluate_nids.py` reports)
- `logs/` — runtime service logs (`nids_web_5000.log`, `main_unified_live.log`, `live_b_worker.log`, `suricata_stdout.log`, `app_5001.log`, `ready.json`, `drain_complete.json`)
"""
    with open(os.path.join(OUT, "MANIFEST.md"), "w") as f:
        f.write(manifest)

    print(f"✓ Packaged all simulation data into {OUT}")
    print(f"  pcaps={n_pcaps}, cicflow_csv={n_cic}, a_flows_csv={n_a_csv}, r3_csv={n_r3_csv}, b_alerts_csv={n_b_csv}, chunks={n_chunks}")


if __name__ == "__main__":
    main()
