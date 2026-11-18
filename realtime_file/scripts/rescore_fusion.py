#!/usr/bin/env python3
"""
scripts/rescore_fusion.py
=========================
Recompute the fusion ablation (Role1 / Role3 / Combined) for EVERY fusion mode
from an already-completed Track B run, WITHOUT re-running Role 1 or the LLM.

WHY
---
The fusion mode changes only the final merge — a microsecond step — yet
re-running main_unified.py to try another mode repeats the ~16-minute Role 1 +
LLM pass. That pass is deterministic given the inputs, and thesis_evaluator
already writes every window's RAW verdicts to thesis_per_window_*.csv:

    gt_binary, gt_family, role1_raw, role3_raw

so the Combined verdict for any mode is a pure function of those columns. This
script applies each mode's merge rule to them and prints one ablation table per
mode, plus bootstrap CIs and a McNemar test — in seconds.

Run Track B ONCE per day (any mode), then this for all modes.

USAGE
-----
    python scripts/rescore_fusion.py \
        --per_window data/results/thesis_per_window_20260801_XXXX.csv \
        --modes or,role1_gated,and \
        --suspicious_is_attack 0 \
        --bootstrap 2000 --out data/results/fusion_compare.json

Give several --per_window files (or a glob) to pool multiple days.
"""

import os
import sys
import json
import glob
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np                                       # noqa: E402
import pandas as pd                                      # noqa: E402

from src.evaluator.stats import bootstrap_ci, mcnemar_test   # noqa: E402


def parse_args():
    p = argparse.ArgumentParser(description="Recompute fusion modes offline.")
    p.add_argument("--per_window", nargs="+", required=True,
                   help="One or more thesis_per_window_*.csv (globs allowed).")
    p.add_argument("--modes", default="or,role1_gated,and")
    p.add_argument("--suspicious_is_attack", type=int, default=0,
                   help="1 to count 'suspicious' as an attack positive "
                        "(default 0).")
    p.add_argument("--bootstrap", type=int, default=2000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default=None)
    return p.parse_args()


def merge_verdict(r1: str, r3: str, mode: str) -> str:
    """Same logic as decision_engine._final_verdict, on raw verdicts."""
    r1 = (r1 or "missing").lower()
    r3 = (r3 or "missing").lower()
    # suppression: both benign/missing => benign
    if r1 in ("benign", "missing") and r3 in ("benign", "missing"):
        return "benign"

    if mode == "or":
        for v in ("attack", "suspicious"):
            if r1 == v or r3 == v:
                return v
        return "benign"

    if mode == "and":
        if r1 == "attack" and r3 == "attack":
            return "attack"
        if r1 in ("attack", "suspicious") and r3 in ("attack", "suspicious"):
            return "suspicious"
        if r1 == "attack" or r3 == "attack":
            return "suspicious"
        return "benign"

    # role1_gated
    if r1 == "attack":
        return "attack"
    if r1 == "suspicious":
        return "suspicious"
    if r1 == "missing" and r3 == "attack":
        return "attack"
    if r3 in ("attack", "suspicious"):
        return "suspicious"
    return "benign"


def to_binary(verdict: str, suspicious_is_attack: bool) -> int:
    positives = ("attack", "suspicious") if suspicious_is_attack else ("attack",)
    return 1 if str(verdict).lower() in positives else 0


def confusion(y_true, y_pred):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / len(y_true) if len(y_true) else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                precision=round(prec * 100, 2), recall=round(rec * 100, 2),
                f1=round(f1 * 100, 2), fpr=round(fpr * 100, 2),
                accuracy=round(acc * 100, 2))


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    files = []
    for pat in args.per_window:
        files.extend(sorted(glob.glob(pat)))
    files = [f for f in files if os.path.exists(f)]
    if not files:
        print("  XX no per-window CSVs matched"); return 1

    frames = [pd.read_csv(f) for f in files]
    df = pd.concat(frames, ignore_index=True)

    # Role 1's verdict comes from role1_PRED (the evaluator's authoritative
    # binary, which used the correct benign set), NOT role1_raw. role1_raw is
    # written from the decision engine's alert.role1_verdict, which was poisoned
    # by a benign-label set missing "Benign" — it read every benign window as
    # attack. role1_pred was always correct, so using it here recovers the true
    # fusion from EXISTING per-window CSVs with no Track B re-run. Role 1 never
    # emits "suspicious", so a binary verdict is a faithful raw verdict for it.
    if "role1_pred" not in df.columns or "role3_raw" not in df.columns:
        miss = {"gt_binary", "role1_pred", "role3_raw"} - set(df.columns)
        print(f"  XX CSV missing columns {miss}.")
        print("     Re-run Track B with the current thesis_evaluator.py.")
        return 1
    df["role1_use"] = df["role1_pred"]        # correct
    df["role3_use"] = df["role3_raw"]         # LLM verdict, unaffected by the bug

    susp = bool(args.suspicious_is_attack)
    print("=" * 70)
    print("  FUSION-MODE COMPARISON  (recomputed offline, no LLM re-run)")
    print("=" * 70)
    print(f"  windows : {len(df):,}  from {len(files)} file(s)")
    print(f"  suspicious counts as attack : {susp}")

    y_true = df["gt_binary"].map(lambda v: 1 if str(v).lower() == "attack" else 0).to_numpy()
    y_r1 = df["role1_use"].map(lambda v: to_binary(v, susp)).to_numpy()
    y_r3 = df["role3_use"].map(lambda v: to_binary(v, susp)).to_numpy()

    n_attack = int(y_true.sum()); n_benign = int((y_true == 0).sum())
    print(f"  ground truth : {n_attack} attack / {n_benign} benign windows")
    if n_attack == 0 or n_benign == 0:
        print("  !  one class only — precision/FPR are not measurements here.")

    report = {"files": files, "n_windows": int(len(df)),
              "suspicious_is_attack": susp,
              "gt_attack": n_attack, "gt_benign": n_benign,
              "role1_only": confusion(y_true, y_r1),
              "role3_only": confusion(y_true, y_r3),
              "modes": {}}

    def _print_row(name, m, ci=None):
        line = (f"  {name:<16}{m['accuracy']:>7.1f}{m['precision']:>8.1f}"
                f"{m['recall']:>8.1f}{m['f1']:>8.1f}{m['fpr']:>8.1f}")
        print(line)
        print(f"  {'':<16}(tp={m['tp']} fp={m['fp']} fn={m['fn']} tn={m['tn']})")

    print(f"\n  {'method':<16}{'Acc':>7}{'Prec':>8}{'Rec':>8}{'F1':>8}{'FPR':>8}")
    print("  " + "-" * 55)
    _print_row("Role1 only", report["role1_only"])
    _print_row("Role3 only", report["role3_only"])

    for mode in [m.strip() for m in args.modes.split(",")]:
        y_comb = np.array([
            to_binary(merge_verdict(r1, r3, mode), susp)
            for r1, r3 in zip(df["role1_use"], df["role3_use"])
        ])
        cm = confusion(y_true, y_comb)
        try:
            ci = bootstrap_ci(y_true, y_comb, n_resamples=args.bootstrap, seed=args.seed)
        except Exception:
            ci = None
        try:
            mc = mcnemar_test(y_true, y_r1, y_comb)
        except Exception:
            mc = None
        report["modes"][mode] = {"combined": cm, "ci": ci, "mcnemar_vs_role1": mc}
        print()
        _print_row(f"Combined[{mode}]", cm)
        if ci and ci.get("f1_score"):
            f = ci["f1_score"]
            print(f"  {'':<16}F1 95% CI {f['lo']:.1f}-{f['hi']:.1f}")
        if mc:
            sig = "SIGNIFICANT" if mc.get("p_value", 1) < 0.05 else "n.s."
            print(f"  {'':<16}McNemar vs Role1: p={mc.get('p_value'):.4g} [{sig}]")

    print("\n  READING IT")
    print("  ----------")
    print("  Compare each Combined[...] FPR against Role3-only FPR. 'or' should")
    print("  match Role3's high FPR (fusion inherits false alarms); 'role1_gated'")
    print("  should match Role1's low FPR while keeping recall >= Role1. That")
    print("  contrast is the evidence that the merge rule matters.")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        json.dump(report, open(args.out, "w"), indent=2, default=str)
        print(f"\n  saved: {args.out}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
