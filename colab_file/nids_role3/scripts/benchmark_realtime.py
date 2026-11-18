#!/usr/bin/env python3
"""
scripts/benchmark_realtime.py
=============================
Measure the real-time performance of the deployed system, stage by stage, and
emit the latency / throughput tables the thesis needs (Part D).

WHAT IT MEASURES, AND WHY THESE STAGES
--------------------------------------
The two deployment paths share the same detection stages; they differ only in
how flows arrive and how results are shown:

  LIVE  (nids_web.py)   packets --NFStream--> Role1 --> SHAP --> LLM queue --> SSE
  BATCH (main_unified)  CIC CSV --> Role1 --> LLM (pooled) --> ThesisEvaluator
        (app.py just RENDERS the batch results — it does no detection, so its
         only "performance" number is dashboard serve latency, reported
         separately.)

So the measurable units, independent of which app drives them, are:

  Stage            what it is                              real-time budget
  ---------------  --------------------------------------  ----------------
  Role 1           one flow: vectorise + scale + predict   sub-millisecond
  Role 2 (SHAP)    per-flow feature attribution            milliseconds
  Role 3 (LLM)     one window through Ollama               seconds
  Decision merge   combine the three verdicts              microseconds
  Dashboard serve  app.py read_jsonl + jsonify             milliseconds

Timing them directly (rather than scraping a live run) makes the numbers
reproducible and lets the report state exactly what hardware produced them.

Role 1 is timed two ways, because both matter and mean different things:
  * batch=1  -> the LIVE per-flow latency (nids_web classifies one flow at a
    time as NFStream emits it). This is the number to quote for "time to first
    verdict".
  * large batch -> the BATCH throughput (main_unified classifies a whole
    window at once). This is the number for "flows/second sustained".

USAGE
-----
    python scripts/benchmark_realtime.py \
        --universal_pkl universal_nids_output.pkl \
        --flows data/cicflow_csv_labelled/CICIDS2017_friday_flows.csv \
        --alerts data/results/alerts_friday.jsonl \
        --ollama http://localhost:11434 --model qwen2.5:1.5b \
        --n 2000 --out data/results/realtime_benchmark.json

Any input that is missing (no Ollama, no alerts file, no SHAP) is reported as
"n/a" rather than aborting, so a partial machine still produces a partial table.
"""

import os
import sys
import json
import time
import argparse
import statistics as st
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np                                       # noqa: E402
import pandas as pd                                      # noqa: E402

from src.engine.universal_ensemble import UniversalEnsemble    # noqa: F401,E402
from src.engine.nids_config import install_pickle_shims        # noqa: E402
from src.ingestion.cicflow_reader import (                     # noqa: E402
    build_feature_lookup, resolve_feature,
)

install_pickle_shims(verbose=False)


def parse_args():
    p = argparse.ArgumentParser(description="Real-time performance benchmark.")
    p.add_argument("--universal_pkl", required=True)
    p.add_argument("--flows", required=True,
                   help="A labelled flow CSV to draw sample flows from.")
    p.add_argument("--dataset", default="CICIDS2017")
    p.add_argument("--alerts", default=None,
                   help="A unified_alerts.jsonl for the app.py serve benchmark.")
    p.add_argument("--ollama", default=None,
                   help="Ollama URL, e.g. http://localhost:11434. Omit to skip "
                        "the LLM timing.")
    p.add_argument("--model", default="qwen2.5:1.5b")
    p.add_argument("--n", type=int, default=1000,
                   help="Sample flows to time Role 1 / SHAP on (default 1000).")
    p.add_argument("--llm_calls", type=int, default=10,
                   help="LLM windows to time (default 10; each takes seconds).")
    p.add_argument("--out", default=None)
    return p.parse_args()


def _stats(samples_ms):
    """mean / p50 / p95 / max over a list of millisecond timings."""
    if not samples_ms:
        return {"n": 0, "mean_ms": None, "p50_ms": None,
                "p95_ms": None, "max_ms": None}
    s = sorted(samples_ms)
    pct = lambda p: s[min(len(s) - 1, int(p / 100 * len(s)))]   # noqa: E731
    return {
        "n": len(s),
        "mean_ms": round(st.mean(s), 4),
        "p50_ms": round(pct(50), 4),
        "p95_ms": round(pct(95), 4),
        "max_ms": round(max(s), 4),
    }


def build_matrix(df, ens, ds, n):
    """Align n sample flows into the model's feature matrix, inf-clean."""
    feats = list(ens.sub_features[ds])
    df = df.head(n).copy()
    df.columns = df.columns.str.strip()
    lookup = build_feature_lookup(df.columns)
    resolved = {f: resolve_feature(f, lookup) for f in feats}
    X = np.zeros((len(df), len(feats)), dtype=np.float32)
    for i, f in enumerate(feats):
        c = resolved.get(f)
        if c is not None:
            v = pd.to_numeric(df[c], errors="coerce")
            v = v.replace([np.inf, -np.inf], np.nan).fillna(0)
            X[:, i] = v.values
    X = np.nan_to_num(X, nan=0.0, posinf=1e15, neginf=-1e15)
    np.clip(X, -1e15, 1e15, out=X)
    try:
        X = ens.transform(X, ds)
    except Exception:
        pass
    return X.astype(np.float32)


def bench_role1_perflow(ens, ds, X):
    """LIVE latency: classify ONE flow at a time (nids_web path)."""
    times = []
    for i in range(len(X)):
        row = X[i:i + 1]
        t = time.perf_counter()
        ens.predict_proba_from_dataset(row, ds)
        times.append((time.perf_counter() - t) * 1000)
    return _stats(times)


def bench_role1_batch(ens, ds, X, window=1000):
    """BATCH throughput: classify a whole window at once (main_unified path)."""
    times = []
    for start in range(0, len(X), window):
        chunk = X[start:start + window]
        if len(chunk) == 0:
            continue
        t = time.perf_counter()
        ens.predict_proba_from_dataset(chunk, ds)
        dt = time.perf_counter() - t
        times.append(dt / len(chunk) * 1000)   # per-flow ms within the batch
    return _stats(times)


def bench_shap(ens, ds, X, n=200):
    """Per-flow SHAP attribution time (Role 2). Returns None if shap absent."""
    try:
        import shap
    except ImportError:
        return None, "shap not installed"
    model = ens.sub_models.get(ds)
    print(f"        (sub-model type: {type(model).__name__})")
    # The sub-model may be a WeightedHybridEnsemble (holds an XGBoost in
    # .xgb_model and an RF in .rf_model), a plain XGB(RF)Classifier, or a
    # Booster. TreeExplainer wants a single tree model / Booster. Gather every
    # tree-ish object we can reach, in order of preference, and try each.
    candidates = []
    for attr in ("xgb_model", "rf_model", "estimator", "base_estimator"):
        inner = getattr(model, attr, None)
        if inner is not None:
            candidates.append(inner)
    candidates.append(model)
    # add the Booster of any candidate that exposes one
    for m in list(candidates):
        getb = getattr(m, "get_booster", None)
        if callable(getb):
            try:
                candidates.append(getb())
            except Exception:
                pass
    explainer = None
    last_err = "no candidate worked"
    for m in candidates:
        try:
            explainer = shap.TreeExplainer(m)
            print(f"        (SHAP on {type(m).__name__})")
            break
        except Exception as exc:
            last_err = f"{type(m).__name__}: {str(exc)[:40]}"
    if explainer is None:
        return None, f"explainer build failed: {last_err}"
    times = []
    for i in range(min(n, len(X))):
        row = X[i:i + 1]
        t = time.perf_counter()
        try:
            explainer.shap_values(row)
        except Exception:
            return None, "shap_values failed"
        times.append((time.perf_counter() - t) * 1000)
    return _stats(times), None


def bench_llm(ollama_url, model, n_calls):
    """Per-window LLM latency (Role 3). Returns None if Ollama unreachable."""
    import urllib.request
    prompt = (
        "You are a network security analyst. A 60-second window shows: "
        "3 Suricata alerts (ET SCAN Potential SSH Scan), 40 flows to port 22 "
        "from one source. Classify as attack/suspicious/benign with a one-line "
        "reason. Respond as JSON: {\"verdict\":..., \"reason\":...}"
    )
    times = []
    for _ in range(n_calls):
        body = json.dumps({
            "model": model, "prompt": prompt, "stream": False,
            "options": {"num_predict": 400, "temperature": 0.1},
        }).encode()
        req = urllib.request.Request(
            ollama_url.rstrip("/") + "/api/generate", data=body,
            headers={"Content-Type": "application/json"},
        )
        t = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                r.read()
        except Exception as exc:
            return None, f"ollama call failed: {str(exc)[:50]}"
        times.append((time.perf_counter() - t) * 1000)
    return _stats(times), None


def bench_decision_merge(X, ens, ds, n=1000):
    """Per-window decision-engine merge time."""
    from src.engine.decision_engine import DecisionEngine
    # DecisionEngine only reads cfg.min_alert_severity via getattr; a bare
    # object with no such attribute falls back to the default.
    eng = DecisionEngine(cfg=object())
    r1 = {"Predicted_Label": "DoS", "Confidence": 99.0, "n_flows": 500,
          "n_attacks": 480}
    r3 = {"verdict": "attack", "attack_type": "DoS", "confidence": 90,
          "explanation": "x", "key_indicators": []}
    times = []
    for _ in range(n):
        t = time.perf_counter()
        eng.merge(role1_result=r1, role2_data={"shap_top_features": []},
                  role3_verdict=r3, flow_features=r1)
        times.append((time.perf_counter() - t) * 1000)
    return _stats(times)


def bench_dashboard(alerts_path, n=20):
    """app.py serve latency: read_jsonl + jsonify equivalent."""
    if not alerts_path or not os.path.exists(alerts_path):
        return None, "alerts file not found"
    times = []
    for _ in range(n):
        t = time.perf_counter()
        rows = []
        with open(alerts_path, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        pass
        json.dumps(rows)          # the jsonify serialization cost
        times.append((time.perf_counter() - t) * 1000)
    return _stats(times), len(rows)


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("=" * 70)
    print("  REAL-TIME PERFORMANCE BENCHMARK")
    print("=" * 70)

    import joblib
    import platform
    print(f"  host    : {platform.platform()}")
    print(f"  python  : {platform.python_version()}")
    print(f"  model   : {args.universal_pkl}")
    o = joblib.load(args.universal_pkl)
    ens = o["ensemble"]
    ds = args.dataset

    # Pin every sub-model to CPU. The models were trained with device="cuda";
    # left as-is, each single-flow predict on a CPU host rebuilds state and
    # pays a GPU->CPU fallback, inflating the LIVE per-flow latency by ~100x.
    # Setting device=cpu once measures the true inference cost. (On a GPU host
    # you would instead leave cuda set — state that with the numbers.)
    for _m in ens.sub_models.values():
        for _target in (_m, getattr(_m, "xgb_model", None),
                        getattr(_m, "rf_model", None)):
            if _target is not None and hasattr(_target, "set_params"):
                try:
                    _target.set_params(device="cpu")
                except Exception:
                    pass

    print(f"  flows   : {args.flows}")
    df = pd.read_csv(args.flows, nrows=args.n * 2, low_memory=False)
    X = build_matrix(df, ens, ds, args.n)
    print(f"  timing on {len(X):,} sample flows\n")

    results = {"generated_at": datetime.now().isoformat(),
               "host": platform.platform(),
               "n_flows": int(len(X)), "dataset": ds}

    print("  [1/6] Role 1 — per-flow (LIVE, nids_web) ...")
    results["role1_perflow"] = bench_role1_perflow(ens, ds, X)

    print("  [2/6] Role 1 — batched (BATCH, main_unified) ...")
    results["role1_batched"] = bench_role1_batch(ens, ds, X)

    print("  [3/6] Role 2 — SHAP per flow ...")
    shap_stats, shap_err = bench_shap(ens, ds, X)
    results["role2_shap"] = shap_stats or {"error": shap_err}

    print("  [4/6] Decision engine — merge ...")
    results["decision_merge"] = bench_decision_merge(X, ens, ds)

    print("  [5/6] Role 3 — LLM per window ...")
    if args.ollama:
        llm_stats, llm_err = bench_llm(args.ollama, args.model, args.llm_calls)
        results["role3_llm"] = llm_stats or {"error": llm_err}
    else:
        results["role3_llm"] = {"skipped": "no --ollama given"}

    print("  [6/6] Dashboard — app.py serve ...")
    dash_stats, dash_info = bench_dashboard(args.alerts)
    results["dashboard_serve"] = dash_stats or {"error": dash_info}
    if isinstance(dash_info, int):
        results["dashboard_serve"]["alerts_rendered"] = dash_info

    # ── derived throughput headline ──────────────────────────────────────────
    r1b = results["role1_batched"]
    if r1b.get("mean_ms"):
        results["role1_throughput_flows_per_s"] = round(1000 / r1b["mean_ms"], 1)

    # ── print the comparison table ───────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  LATENCY TABLE  (milliseconds)")
    print("=" * 70)
    print(f"  {'Stage':<34}{'mean':>9}{'p50':>9}{'p95':>9}{'max':>9}")
    print("  " + "-" * 66)
    rows = [
        ("Role 1  per-flow  (live)",      "role1_perflow"),
        ("Role 1  per-flow  (batched)",   "role1_batched"),
        ("Role 2  SHAP / flow",           "role2_shap"),
        ("Decision merge / window",       "decision_merge"),
        ("Role 3  LLM / window",          "role3_llm"),
        ("Dashboard serve (app.py)",      "dashboard_serve"),
    ]
    for label, key in rows:
        s = results.get(key, {})
        if s.get("mean_ms") is None or "mean_ms" not in s:
            note = s.get("error") or s.get("skipped") or "n/a"
            print(f"  {label:<34}{note:>36}")
        else:
            print(f"  {label:<34}{s['mean_ms']:>9.3f}{s['p50_ms']:>9.3f}"
                  f"{s['p95_ms']:>9.3f}{s['max_ms']:>9.3f}")

    if "role1_throughput_flows_per_s" in results:
        print(f"\n  Role 1 batch throughput : "
              f"{results['role1_throughput_flows_per_s']:,.0f} flows/s")

    print("\n  DEPLOYMENT-MODE COMPARISON")
    print("  " + "-" * 66)
    print("  LIVE  (nids_web.py) : Role1 per-flow + SHAP happen inline per")
    print("        flow; the LLM runs in a background queue, so the SOC sees a")
    print("        Role-1 verdict in ~the per-flow time above and the LLM note")
    print("        seconds later. Time-to-first-verdict = Role1 per-flow (live).")
    print("  BATCH (main_unified -> app.py) : Role1 runs on a whole window at")
    print("        once (batched column); app.py only renders the finished")
    print("        alerts, at the dashboard-serve latency above.")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".",
                    exist_ok=True)
        json.dump(results, open(args.out, "w"), indent=2)
        print(f"\n  saved: {args.out}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
