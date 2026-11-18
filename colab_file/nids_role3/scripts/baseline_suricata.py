#!/usr/bin/env python3
"""
scripts/baseline_suricata.py
=============================
Baseline 1: Suricata alone, scored on the SAME 60-second windows and the SAME
ground truth as the fusion pipeline.

WHY THIS MATTERS
----------------
The first question any reviewer asks a "ML + LLM + IDS" paper is: why not just
use the signature IDS you already run? This answers it with numbers. A window
is flagged "attack" if Suricata raised >= --min-alerts alerts in it; ground
truth is the flows' majority label in that window, exactly as ThesisEvaluator
computes it. The output row drops straight into the baselines table next to
Role1 / Role3 / Combined.

It reuses the pipeline's own window logic so the comparison is apples-to-apples:
- eve.json time range and 60s windows from log_chunker
- per-window flow ground truth from cicflow_reader.label_summary
- the SAME +offset alignment prepare_cic_flows already baked into the flow file

USAGE
-----
    python scripts/baseline_suricata.py \
        --eve   data/eve_logs/friday/friday_eve.json \
        --flows data/cicflow_csv_labelled/CICIDS2017_friday_flows.csv \
        --window 60 --min-alerts 1 \
        --out data/results/baseline_suricata_friday.json
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np                                       # noqa: E402
import pandas as pd                                      # noqa: E402

from src.engine.label_map import to_family, BENIGN_FAMILY   # noqa: E402


def parse_args():
    p = argparse.ArgumentParser(description="Suricata-alone baseline.")
    p.add_argument("--eve", default=None, help="This day's eve.json.")
    p.add_argument("--flows", default=None,
                   help="This day's labelled flow CSV (from prepare_cic_flows).")
    p.add_argument("--pool-dir", default=None,
                   help="Pool the 4 per-day baseline_suricata_*_fixed.json results in this directory.")
    p.add_argument("--window", type=int, default=60, help="Window seconds.")
    p.add_argument("--min-alerts", type=int, default=1,
                   help="Alerts in a window to call it 'attack' (default 1).")
    p.add_argument("--gt-threshold", type=float, default=None,
                   help="Attack-flow fraction threshold for window ground truth "
                        "(e.g. 0.03 to match Track B's 3% threshold; omit for majority >0.5).")
    p.add_argument("--out", default=None)
    return p.parse_args()


def load_alert_times(eve_path):
    """Return sorted epoch-seconds of every Suricata ALERT event."""
    times = []
    with open(eve_path, "r", errors="replace") as fh:
        for line in fh:
            if '"event_type":"alert"' not in line and '"event_type": "alert"' not in line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event_type") != "alert":
                continue
            t = e.get("timestamp")
            if not t:
                continue
            try:
                times.append(datetime.fromisoformat(t).astimezone(timezone.utc).timestamp())
            except ValueError:
                continue
    times.sort()
    return np.asarray(times)


def robust_eve_range(alert_epochs, all_epochs):
    """Bulk time span, ignoring stray events >30 days from the median."""
    if len(all_epochs) == 0:
        return None, None
    med = np.median(all_epochs)
    core = all_epochs[np.abs(all_epochs - med) <= 30 * 86400]
    if len(core) == 0:
        return None, None
    return float(core.min()), float(core.max())


def all_event_times(eve_path):
    ts = []
    with open(eve_path, "r", errors="replace") as fh:
        for line in fh:
            try:
                t = json.loads(line).get("timestamp")
            except Exception:
                continue
            if not t:
                continue
            try:
                ts.append(datetime.fromisoformat(t).astimezone(timezone.utc).timestamp())
            except ValueError:
                continue
    return np.asarray(sorted(ts))


def pool_daily_results(pool_dir, gt_threshold=0.03, out_path=None):
    """Aggregate per-day fixed Suricata JSONs across Tuesday-Friday into one pooled report."""
    days = ["tuesday", "wednesday", "thursday", "friday"]
    per_day = {}
    tp = fp = fn = tn = n_win = 0
    for day in days:
        p = os.path.join(pool_dir, f"baseline_suricata_{day}_fixed.json")
        with open(p, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        tp += int(d["tp"])
        fp += int(d["fp"])
        fn += int(d["fn"])
        tn += int(d["tn"])
        n_win += int(d["windows_with_gt"])
        per_day[day] = {
            k: d[k] for k in (
                "windows_with_gt", "tp", "fp", "fn", "tn",
                "precision_pct", "recall_pct", "f1_pct", "fpr_pct", "accuracy_pct",
            )
        }
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / n_win if n_win else 0.0
    out = {
        "baseline": "suricata_alone_pooled",
        "gt_threshold": gt_threshold,
        "windows_with_gt": n_win,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision_pct": round(prec * 100, 2),
        "recall_pct": round(rec * 100, 2),
        "f1_pct": round(f1 * 100, 2),
        "fpr_pct": round(fpr * 100, 2),
        "accuracy_pct": round(acc * 100, 2),
        "per_day": per_day,
    }
    print("=" * 68)
    print("  POOLED SURICATA-ALONE BASELINE (Tuesday-Friday)")
    print("=" * 68)
    print(f"  windows_with_gt={n_win} | gt_threshold={gt_threshold}")
    print(f"  tp={tp}  fp={fp}  fn={fn}  tn={tn}")
    print(f"  Precision {prec*100:6.2f}%  Recall {rec*100:6.2f}%  F1 {f1*100:6.2f}%  "
          f"FPR {fpr*100:6.2f}%  Acc {acc*100:6.2f}%")
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"  saved: {out_path}")
    print("=" * 68)
    return 0


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if args.pool_dir:
        thr = args.gt_threshold if args.gt_threshold is not None else 0.03
        return pool_daily_results(args.pool_dir, gt_threshold=thr, out_path=args.out)

    if not args.eve or not args.flows:
        raise ValueError("Provide --pool-dir or both --eve and --flows.")

    print("=" * 68)
    print("  BASELINE: SURICATA ALONE")
    print("=" * 68)

    print(f"  eve   : {args.eve}")
    all_ep = all_event_times(args.eve)
    alert_ep = load_alert_times(args.eve)
    print(f"    {len(all_ep):,} events, {len(alert_ep):,} alerts")

    t0, t1 = robust_eve_range(alert_ep, all_ep)
    if t0 is None:
        print("  XX no usable event timestamps"); return 1

    print(f"  flows : {args.flows}")
    fdf = pd.read_csv(args.flows, usecols=lambda c: c.strip() in ("Timestamp", "Label"),
                      low_memory=False)
    fdf.columns = fdf.columns.str.strip()
    fts = pd.to_datetime(fdf["Timestamp"], format="ISO8601", utc=True, errors="coerce")
    fdf = fdf.loc[fts.notna()].copy()
    # Force ns resolution before int64: a datetime64[us] column casts to
    # MICROseconds, and dividing by 1e9 then puts every flow near epoch 0,
    # producing a nonsensical multi-century window grid.
    fep = fts.dropna().values.astype("datetime64[ns]").astype("int64") / 1e9
    print(f"    {len(fdf):,} flows")

    # Window grid over the union, matching the pipeline.
    start = min(t0, float(fep.min()))
    end = max(t1, float(fep.max()))
    W = args.window
    n_win = int(np.ceil((end - start) / W))
    print(f"  windows: {n_win} x {W}s  "
          f"({datetime.utcfromtimestamp(start):%H:%M} .. "
          f"{datetime.utcfromtimestamp(end):%H:%M})")

    win_of = lambda ep: ((ep - start) // W).astype(int)   # noqa: E731

    # Suricata prediction per window: alert count >= threshold.
    alert_win = win_of(alert_ep) if len(alert_ep) else np.array([], dtype=int)
    alert_count = np.bincount(alert_win, minlength=n_win) if len(alert_win) else np.zeros(n_win, int)
    pred_attack = alert_count >= args.min_alerts

    # Ground truth per window: attack-flow fraction >= gt_threshold (or >0.5 majority).
    fdf["w"] = win_of(fep)
    is_benign = fdf["Label"].map(lambda l: to_family(l) == BENIGN_FAMILY)
    gt_attack = np.zeros(n_win, dtype=bool)
    gt_has = np.zeros(n_win, dtype=bool)
    for w, g in fdf.groupby("w"):
        if w < 0 or w >= n_win:
            continue
        gt_has[w] = True
        ben = int(is_benign.loc[g.index].sum())
        atk = len(g) - ben
        if args.gt_threshold is None:
            gt_attack[w] = atk > ben
        else:
            gt_attack[w] = (atk / len(g)) >= args.gt_threshold if len(g) > 0 else False

    # Score only windows that HAVE ground truth (a flow fell in them).
    m = gt_has
    tp = int(np.sum(pred_attack[m] & gt_attack[m]))
    fp = int(np.sum(pred_attack[m] & ~gt_attack[m]))
    fn = int(np.sum(~pred_attack[m] & gt_attack[m]))
    tn = int(np.sum(~pred_attack[m] & ~gt_attack[m]))

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / m.sum() if m.sum() else 0.0

    print("\n  ── SURICATA-ALONE (vs ground truth) ──────────────────────")
    print(f"    windows w/ GT : {int(m.sum())}   (attack {int(gt_attack[m].sum())}, "
          f"benign {int((~gt_attack[m]).sum())})")
    print(f"    tp={tp}  fp={fp}  fn={fn}  tn={tn}")
    print(f"    Precision {prec*100:6.2f}%   Recall {rec*100:6.2f}%   "
          f"F1 {f1*100:6.2f}%   FPR {fpr*100:6.2f}%   Acc {acc*100:6.2f}%")

    if tp + fn == 0:
        print("    ! no attack windows with ground truth -- recall undefined; "
              "check flow/eve alignment.")

    out = {
        "baseline": "suricata_alone", "eve": args.eve, "flows": args.flows,
        "window_seconds": W, "min_alerts": args.min_alerts,
        "gt_threshold": args.gt_threshold if args.gt_threshold is not None else 0.5,
        "windows_with_gt": int(m.sum()),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision_pct": round(prec*100, 2), "recall_pct": round(rec*100, 2),
        "f1_pct": round(f1*100, 2), "fpr_pct": round(fpr*100, 2),
        "accuracy_pct": round(acc*100, 2),
    }
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(out, open(args.out, "w"), indent=2)
        print(f"\n  saved: {args.out}")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
