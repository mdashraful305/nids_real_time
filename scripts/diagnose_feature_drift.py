#!/usr/bin/env python3
"""
scripts/diagnose_feature_drift.py
==================================
Explain why Role 1 predicts benign on windows that are demonstrably attacks.

THE OBSERVATION
───────────────
A real Track B run produced:

    Role1 only  92.6%  prec 0.0%  rec 0.0%  (tp=0 tn=225 fp=0 fn=18)

Every one of the 18 true attack windows was called benign, and no benign
window was ever flagged — Role 1 emitted a single class. The same sub-model
scores 99.85% on its own held-out CICIDS2017 test split, and the ground truth
is correct: the 18 attack windows fall exactly on CICIDS2017's documented
PortScan (13:55-15:29) and DDoS (15:56-16:16) periods once the +6h offset is
applied. Feature coverage was 52/52 by name.

So the names line up and the labels line up. What is left is the VALUES.

THE HYPOTHESIS THIS SCRIPT TESTS
────────────────────────────────
The sub-model was trained on the Kaggle MachineLearningCVE release of
CICIDS2017 — features pre-extracted by CIC with the Java CICFlowMeter.
Deployment feeds it features extracted locally by python-cicflowmeter from the
raw pcap. Matching column NAMES do not imply matching UNITS or definitions:
Java CICFlowMeter reports Flow Duration in MICROSECONDS, several
python-cicflowmeter builds report seconds. A 10^6 scale error survives the
name match, survives the coverage gate, and then RobustScaler — fitted on
microsecond-scale training data — maps every deployed value to approximately
its own centre. Every flow then looks average, i.e. benign, with high
confidence.

HOW IT TESTS IT WITHOUT THE TRAINING DATA
─────────────────────────────────────────
RobustScaler stores, per feature:
    center_ = the MEDIAN of the training data
    scale_  = the IQR of the training data
That is a free, exact summary of the training distribution, already inside the
pkl. Comparing the deployed median against center_ feature by feature localises
the mismatch precisely, with no need to reload any training set.

A ratio near 1 means the feature is on the training scale. A ratio near 10^6,
10^-6, 10^3 or 10^-3 is a unit mismatch. A ratio that is wild and unpatterned
means the feature means something different in the two extractors.

USAGE
─────
    python scripts/diagnose_feature_drift.py \
        --universal_pkl universal_nids_output.pkl \
        --flow_csv data/cicflow_csv_labelled/Friday-WorkingHours_flows.csv \
        --dataset CICIDS2017

Add --sample 200000 to bound memory on a large CSV (default 300k rows).
"""

import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np                                              # noqa: E402
import pandas as pd                                             # noqa: E402

from src.engine.universal_ensemble import UniversalEnsemble      # noqa: F401,E402
from src.engine.nids_config import install_pickle_shims          # noqa: E402
from src.engine.label_map import to_family, BENIGN_FAMILY        # noqa: E402
from src.ingestion.cicflow_reader import (                       # noqa: E402
    build_feature_lookup, resolve_feature,
)

install_pickle_shims()

# Ratios recognisable as unit errors rather than genuine distribution shift.
_KNOWN_UNIT_FACTORS = {
    1e-9: "ns -> s", 1e-6: "us -> s",  1e-3: "ms -> s",
    1e9:  "s -> ns", 1e6:  "s -> us",  1e3:  "s -> ms",
    8.0: "bytes -> bits", 0.125: "bits -> bytes",
}


def parse_args():
    p = argparse.ArgumentParser(
        description="Diagnose train/deploy feature drift for a sub-model."
    )
    p.add_argument("--universal_pkl", required=True)
    p.add_argument("--flow_csv", required=True)
    p.add_argument("--dataset", default="CICIDS2017")
    p.add_argument("--sample", type=int, default=300_000,
                   help="Rows to read from the CSV (default 300000).")
    p.add_argument("--out", default=None,
                   help="Optional path for a JSON report.")
    p.add_argument("--top", type=int, default=25,
                   help="How many worst-drifted features to print (default 25).")
    return p.parse_args()


def _nearest_unit_factor(ratio: float):
    """Return a label if `ratio` is close to a recognised unit conversion."""
    if not np.isfinite(ratio) or ratio <= 0:
        return None
    for factor, name in _KNOWN_UNIT_FACTORS.items():
        if 0.5 <= ratio / factor <= 2.0:
            return name
    return None


def main():
    args = parse_args()
    # Windows consoles are cp1252; keep box-drawing output portable.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ds = args.dataset

    print("=" * 74)
    print("  FEATURE DRIFT DIAGNOSIS — why Role 1 predicts one class")
    print("=" * 74)

    import joblib
    print(f"  loading model : {args.universal_pkl}")
    out = joblib.load(args.universal_pkl)
    ens = out["ensemble"]

    if ds not in ens.sub_features:
        print(f"  ✗ '{ds}' is not a sub-model. Available: "
              f"{list(ens.sub_features)}")
        return 1

    feats = list(ens.sub_features[ds])
    scaler = (getattr(ens, "sub_scalers", None) or {}).get(ds) or out.get("scaler")
    if scaler is None or not hasattr(scaler, "center_"):
        print("  ✗ No RobustScaler with center_/scale_ stored for this "
              "sub-model — cannot compare against the training distribution.\n"
              "    Re-export the model with sub_scalers (see COLAB_SETUP.md "
              "Step 5).")
        return 1

    print(f"  sub-model     : {ds}  ({len(feats)} features)")
    # RANDOM sample, not the head. CIC day files are a concatenation of capture
    # segments, so the first N rows are one attack type: reading the head of the
    # Friday file gives the DDoS segment alone and its feature medians are not
    # the day's. That looks exactly like drift.
    print(f"  loading flows : {args.flow_csv}")
    df = pd.read_csv(args.flow_csv, low_memory=False)
    df.columns = df.columns.str.strip()
    if args.sample and len(df) > args.sample:
        df = df.sample(n=args.sample, random_state=42).reset_index(drop=True)
        print(f"                  random sample of {args.sample:,} rows "
              f"(seed 42)")

    # CIC writes literal "Infinity" in Flow Bytes/s and Flow Packets/s for
    # zero-duration flows. Left in place these reach the scaler and raise
    # "Input X contains infinity", and they also poison the medians below.
    num = df.select_dtypes(include=[np.number]).columns
    n_inf = int(np.isinf(df[num].to_numpy(dtype="float64", na_value=0.0)).sum())
    if n_inf:
        print(f"                  {n_inf:,} infinite values replaced with 0 "
              f"(CIC emits Infinity for zero-duration flows)")
        df[num] = df[num].replace([np.inf, -np.inf], np.nan).fillna(0)
    print(f"                  {len(df):,} rows, {len(df.columns)} columns")

    # Resolve exactly as the pipeline does, so this measures what Role 1 sees.
    lookup = build_feature_lookup(df.columns)
    resolved = {f: resolve_feature(f, lookup) for f in feats}
    missing = [f for f, c in resolved.items() if c is None]
    print(f"  name coverage : {len(feats) - len(missing)}/{len(feats)}")
    if missing:
        print(f"    unresolved: {missing[:10]}")

    centre = np.asarray(scaler.center_, dtype=float)
    spread = np.asarray(scaler.scale_, dtype=float)

    rows = []
    for i, feat in enumerate(feats):
        col = resolved.get(feat)
        if col is None:
            rows.append({"feature": feat, "status": "MISSING"})
            continue
        vals = pd.to_numeric(df[col], errors="coerce")
        vals = vals.replace([np.inf, -np.inf], np.nan).dropna()
        if vals.empty:
            rows.append({"feature": feat, "status": "EMPTY"})
            continue

        dep_med = float(vals.median())
        dep_iqr = float(vals.quantile(0.75) - vals.quantile(0.25))
        tr_med, tr_iqr = float(centre[i]), float(spread[i])

        # Ratio of medians where both are non-trivial; fall back to IQR, which
        # is the better signal for features whose median is legitimately 0
        # (flag counts, packet-length minimums on one-packet flows).
        if abs(tr_med) > 1e-9 and abs(dep_med) > 1e-9:
            ratio, basis = dep_med / tr_med, "median"
        elif tr_iqr > 1e-9 and dep_iqr > 1e-9:
            ratio, basis = dep_iqr / tr_iqr, "iqr"
        else:
            ratio, basis = float("nan"), "degenerate"

        # How far the deployed median sits from the training centre, measured
        # in training IQRs — this is literally the scaled value Role 1 receives.
        z = (dep_med - tr_med) / tr_iqr if tr_iqr > 1e-9 else float("nan")

        rows.append({
            "feature": feat, "status": "ok", "basis": basis,
            "train_median": tr_med, "deploy_median": dep_med,
            "train_iqr": tr_iqr, "deploy_iqr": dep_iqr,
            "ratio": ratio, "scaled_offset_iqr": z,
            "unit_hint": _nearest_unit_factor(ratio),
        })

    ok = [r for r in rows if r["status"] == "ok"]
    if not ok:
        print("  ✗ No comparable features.")
        return 1

    def _severity(r):
        v = r["ratio"]
        return abs(np.log10(abs(v))) if np.isfinite(v) and v not in (0,) else 0.0

    ok.sort(key=_severity, reverse=True)
    drifted = [r for r in ok if _severity(r) >= 1.0]     # >= 10x off
    unit_sus = [r for r in ok if r["unit_hint"]]

    print(f"\n  ── WORST-DRIFTED FEATURES (top {args.top}) ─────────────────")
    print(f"  {'feature':<30}{'train med':>13}{'deploy med':>13}"
          f"{'ratio':>12}  hint")
    for r in ok[:args.top]:
        hint = r["unit_hint"] or ""
        print(f"  {r['feature'][:29]:<30}{r['train_median']:>13.4g}"
              f"{r['deploy_median']:>13.4g}{r['ratio']:>12.4g}  {hint}")

    print(f"\n  ── SUMMARY ──────────────────────────────────────────────────")
    print(f"    features compared        : {len(ok)}")
    print(f"    drifted >= 10x           : {len(drifted)}")
    print(f"    look like unit errors    : {len(unit_sus)}")
    if unit_sus:
        kinds = {}
        for r in unit_sus:
            kinds[r["unit_hint"]] = kinds.get(r["unit_hint"], 0) + 1
        for k, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
            print(f"      {k:<20} {n} feature(s)")

    # ── the decisive check: what does the model actually predict? ────────────
    print(f"\n  ── PREDICTION SANITY CHECK ──────────────────────────────────")
    aligned = np.zeros((len(df), len(feats)), dtype=np.float32)
    for i, feat in enumerate(feats):
        col = resolved.get(feat)
        if col is not None:
            v = pd.to_numeric(df[col], errors="coerce")
            v = v.replace([np.inf, -np.inf], np.nan).fillna(0)
            aligned[:, i] = v.values
    # Clip to a finite magnitude BEFORE scaling, not float32.max. RobustScaler
    # computes (X - center) / scale, so a value near float32.max divided by a
    # small IQR overflows back to inf and the scaler rejects it -- which is the
    # line the Colab traceback died on. 1e15 is far above any real CIC feature
    # yet leaves headroom against overflow.
    _CLIP = 1e15
    aligned = np.nan_to_num(aligned, nan=0.0, posinf=_CLIP, neginf=-_CLIP)
    np.clip(aligned, -_CLIP, _CLIP, out=aligned)
    try:
        scaled = ens.transform(aligned, ds)
    except Exception:
        scaled = scaler.transform(aligned)
    # Belt and suspenders: clean anything the scaling still produced so
    # predict_proba never sees a non-finite value.
    scaled = np.nan_to_num(np.asarray(scaled, dtype=np.float32),
                           nan=0.0, posinf=0.0, neginf=0.0)

    proba = ens.predict_proba_from_dataset(scaled, ds)
    pred = np.asarray(ens.le_universal.inverse_transform(np.argmax(proba, axis=1)))
    conf = proba.max(axis=1)

    pred_counts = pd.Series(pred).value_counts()
    print("    Role 1 predicted class distribution:")
    for lbl, n in pred_counts.head(8).items():
        print(f"      {str(lbl):<22} {n:>8,}  ({n/len(pred)*100:5.2f}%)")
    print(f"    mean confidence: {conf.mean()*100:.1f}%")

    truth_note = ""
    rec = None
    if "Label" in df.columns:
        true_fam = df["Label"].map(lambda l: to_family(l))
        true_atk = (true_fam.notna() & (true_fam != BENIGN_FAMILY))
        pred_atk = pred != BENIGN_FAMILY
        print(f"\n    TRUE attack flows in sample : {int(true_atk.sum()):>8,} "
              f"({true_atk.mean()*100:5.2f}%)")
        print(f"    PRED attack flows           : {int(pred_atk.sum()):>8,} "
              f"({pred_atk.mean()*100:5.2f}%)")
        if true_atk.sum() > 0:
            rec = (pred_atk & true_atk).sum() / true_atk.sum()
            print(f"    flow-level recall           : {rec*100:5.2f}%")
            truth_note = (
                "Role 1 is blind to attacks it was trained to detect."
                if rec < 0.10 else
                "Role 1 does detect attacks at flow level — the window-level "
                "aggregation is the problem, not the model."
            )
            print(f"    -> {truth_note}")

    print(f"\n  ── INTERPRETATION ───────────────────────────────────────────")
    # Recall is measured, the ratio heuristic is inferred. When labels are
    # present, recall decides -- otherwise a run showing 99.78% recall still
    # printed "drift CONFIRMED" because five features tripped a loose
    # bits<->bytes match on ratios between 0.15 and 0.45.
    if truth_note and rec >= 0.80:
        print("    NO ACTIONABLE DRIFT. Role 1 recovers "
              f"{rec * 100:.2f}% of attack flows, so the feature scales are")
        print("    close enough for the model to work. Any ratios flagged above")
        print("    are distribution differences, not unit errors -- do not")
        print("    'correct' them.")
    elif len(unit_sus) >= 3 or len(drifted) >= len(ok) * 0.3:
        print("    Train/deploy feature drift CONFIRMED. The sub-model is being")
        print("    fed values on a different scale from the ones it was fitted")
        print("    on, so RobustScaler maps everything near its own centre and")
        print("    every flow looks average — i.e. benign — at high confidence.")
        print()
        print("    FIX (in order of preference)")
        print("    1. Re-extract features with the SAME tool CIC used: the Java")
        print("       CICFlowMeter in tools/CICFlowMeterV3-0.0.4-SNAPSHOT.jar.")
        print("       Units and definitions then match the training data by")
        print("       construction. This is the only option that needs no")
        print("       assumption about what each column means.")
        print("    2. Retrain the CICIDS2017 sub-model on features extracted by")
        print("       the SAME extractor used at deployment. Also correct, and")
        print("       removes the dependency on CIC's pre-extracted CSVs, but")
        print("       your accuracy is then not comparable to published numbers.")
        print("    3. Apply per-feature unit corrections using the hints above.")
        print("       Cheapest, but every correction is a guess about semantics")
        print("       and must be stated in Limitations.")
    else:
        print("    Feature scales broadly match the training distribution, so")
        print("    unit drift does NOT explain the behaviour. Look next at the")
        print("    window-level aggregation and the class-imbalance threshold.")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump({
                "dataset": ds, "flow_csv": args.flow_csv,
                "n_rows": int(len(df)),
                "n_features": len(feats),
                "n_drifted_10x": len(drifted),
                "n_unit_suspect": len(unit_sus),
                "predicted_distribution": {str(k): int(v)
                                            for k, v in pred_counts.items()},
                "features": rows,
            }, fh, indent=2, default=str)
        print(f"\n  Report written: {args.out}")

    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
