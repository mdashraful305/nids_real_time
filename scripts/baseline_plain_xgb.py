#!/usr/bin/env python3
"""
scripts/baseline_plain_xgb.py
=============================
Baseline 2: a PLAIN XGBoost with NO preprocessing pipeline — no correlation
pruning, no mutual-information feature selection, no SMOTE. Same dataset, same
stratified 80/20 split, same model family as Role 1.

WHY
---
Track A shows the full pipeline (prune -> select -> scale -> SMOTE) reaching
macro-F1 97.34% on CICIDS2017. A reviewer will ask: does that preprocessing
actually earn its place, or would a vanilla XGBoost do just as well? This
answers it with a number. If plain XGB is close, say so honestly; if it is
worse on the rare classes (where SMOTE + selection matter), that gap IS the
justification for the pipeline.

It is deliberately minimal: numeric coercion, drop inf/na, label-encode,
stratified split, XGBoost with library defaults. Nothing else.

USAGE
-----
    python scripts/baseline_plain_xgb.py \
        --data_dir ../data/CICIDS2017/ \
        --label_col Label \
        --out data/results/baseline_plain_xgb.json

`--data_dir` is a directory of the CICIDS2017 CSVs (the same files training
used). Add --max_rows to subsample on a small machine.
"""

import os
import sys
import glob
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np                                       # noqa: E402
import pandas as pd                                      # noqa: E402


def parse_args():
    p = argparse.ArgumentParser(description="Plain-XGBoost baseline.")
    p.add_argument("--data_dir", required=True,
                   help="Directory of CICIDS2017 CSVs (recursively searched).")
    p.add_argument("--label_col", default="Label")
    p.add_argument("--test_size", type=float, default=0.20)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max_rows", type=int, default=None,
                   help="Optional stratified subsample cap for a small host.")
    p.add_argument("--min_class", type=int, default=100,
                   help="Drop classes with fewer than this many rows (a "
                        "stratified split needs at least 2). Default 100.")
    p.add_argument("--out", default=None)
    return p.parse_args()


def load_all(data_dir, label_col):
    files = sorted(glob.glob(os.path.join(data_dir, "**", "*.csv"), recursive=True))
    if not files:
        raise FileNotFoundError(f"No CSVs under {data_dir}")
    frames = []
    for f in files:
        df = None
        for enc in ("utf-8", "cp1252", "latin-1"):
            try:
                df = pd.read_csv(f, low_memory=False, encoding=enc,
                                 on_bad_lines="skip")
                break
            except UnicodeDecodeError:
                continue
        if df is None or df.empty:
            continue
        df.columns = df.columns.str.strip()
        frames.append(df)
        print(f"    {os.path.basename(f):<52} {len(df):>9,} rows")
    return pd.concat(frames, ignore_index=True)


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder
    from sklearn.metrics import accuracy_score, f1_score, classification_report
    import xgboost as xgb

    print("=" * 70)
    print("  BASELINE 2: PLAIN XGBoost (no prune / no select / no SMOTE)")
    print("=" * 70)

    print(f"  loading {args.data_dir}")
    df = load_all(args.data_dir, args.label_col)
    print(f"  total {len(df):,} rows, {len(df.columns)} columns")

    lc = None
    for c in df.columns:
        if c.strip().lower() == args.label_col.strip().lower():
            lc = c; break
    if lc is None:
        print(f"  XX no '{args.label_col}' column"); return 1

    y_raw = df[lc].astype(str).str.strip()
    X = df.drop(columns=[lc])

    # numeric only, inf/na -> 0 (the ONLY cleaning; no feature engineering)
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    keep_cols = X.columns[X.nunique() > 1]           # drop constant columns
    X = X[keep_cols]
    print(f"  features used : {X.shape[1]} (all non-constant numeric columns)")

    # drop ultra-rare classes so a stratified split is possible
    vc = y_raw.value_counts()
    keep = vc[vc >= args.min_class].index
    mask = y_raw.isin(keep)
    X, y_raw = X[mask], y_raw[mask]
    print(f"  classes       : {len(keep)}  (dropped {len(vc) - len(keep)} "
          f"with <{args.min_class} rows)")

    if args.max_rows and len(X) > args.max_rows:
        idx, _ = train_test_split(np.arange(len(X)), train_size=args.max_rows,
                                  stratify=y_raw, random_state=args.seed)
        X, y_raw = X.iloc[idx], y_raw.iloc[idx]
        print(f"  subsampled to : {len(X):,} rows")

    le = LabelEncoder()
    y = le.fit_transform(y_raw)

    Xtr, Xte, ytr, yte = train_test_split(
        X.values.astype(np.float32), y, test_size=args.test_size,
        stratify=y, random_state=args.seed)
    print(f"  split         : {len(Xtr):,} train / {len(Xte):,} test\n")

    print("  training plain XGBoost (library defaults) ...")
    clf = xgb.XGBClassifier(
        n_estimators=300, max_depth=8, learning_rate=0.1,
        tree_method="hist", eval_metric="mlogloss",
        random_state=args.seed, n_jobs=-1,
    )
    try:
        clf.set_params(device="cuda")
    except Exception:
        pass
    clf.fit(Xtr, ytr)

    y_pred = clf.predict(Xte)
    acc = accuracy_score(yte, y_pred)
    mf1 = f1_score(yte, y_pred, average="macro", zero_division=0)
    wf1 = f1_score(yte, y_pred, average="weighted", zero_division=0)

    print("\n  ── PLAIN XGBoost (test set) ──────────────────────────────")
    print(f"    Accuracy    : {acc*100:.2f}%")
    print(f"    Macro-F1    : {mf1*100:.2f}%")
    print(f"    Weighted-F1 : {wf1*100:.2f}%")
    print("\n  vs Track A full pipeline (CICIDS2017): acc 99.87%  macro-F1 97.34%")
    print("  Interpretation: a large macro-F1 gap here (rare classes) is what")
    print("  the correlation-pruning + MI-selection + SMOTE pipeline buys you;")
    print("  a small gap means the preprocessing is optional on this dataset.")

    rep = classification_report(yte, y_pred, labels=range(len(le.classes_)),
                                target_names=[str(c) for c in le.classes_],
                                zero_division=0, output_dict=True)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".",
                    exist_ok=True)
        json.dump({
            "baseline": "plain_xgboost",
            "n_features": int(X.shape[1]),
            "n_classes": int(len(le.classes_)),
            "n_train": int(len(Xtr)), "n_test": int(len(Xte)),
            "accuracy_pct": round(acc*100, 2),
            "macro_f1_pct": round(mf1*100, 2),
            "weighted_f1_pct": round(wf1*100, 2),
            "per_class": rep,
            "compare_full_pipeline": {"accuracy_pct": 99.87, "macro_f1_pct": 97.34},
        }, open(args.out, "w"), indent=2)
        print(f"\n  saved: {args.out}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
