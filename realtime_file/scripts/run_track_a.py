#!/usr/bin/env python3
"""
scripts/run_track_a.py
=======================
TRACK A — evaluate the universal (schema-routed) model on ALL THREE datasets.

This is the experiment that substantiates "one model covering CICIDS2017,
UNSW-NB15 and NSL-KDD". It uses each dataset's own held-out test split, which
already exists inside the per-dataset pkls, so it needs no new data capture
and no Suricata/Ollama — only the model files.

Produces, per dataset:
  • accuracy / macro-F1 / weighted-F1 in universal label space
  • per-class precision / recall / F1 / support
  • bootstrap 95% CIs on the headline metrics
  • the confusion matrix
and across datasets:
  • a single comparison table
  • a routing-integrity check (does each dataset route to its own sub-model?)


A NOTE ON CROSS-DATASET TRANSFER
────────────────────────────────
Training on CICIDS2017 and testing on UNSW-NB15 is NOT possible with these
models, and this script does not pretend otherwise.

The three datasets share zero feature columns after mutual-information
selection — "Flow Duration" vs "dur" vs "duration" are different measurements
with different units, and the notebook's own docstring records the overlap as
0 columns. That is precisely why the universal model is a router rather than
a single classifier. Feeding UNSW-NB15 vectors to the CICIDS2017 sub-model
would produce numbers, but they would be numbers about noise.

Genuine cross-dataset generalisation would require retraining on a
common feature space (e.g. re-extracting all three from raw pcaps with one
tool). That is a separate experiment, and worth stating in Limitations rather
than approximating badly here.


USAGE
─────
    python scripts/run_track_a.py \
        --universal_pkl universal_nids_output.pkl \
        --cicids_pkl    nids_cicids_output.pkl \
        --unsw_pkl      nids_unsw_output.pkl \
        --nslkdd_pkl    nids_nslkdd_output.pkl \
        --out           data/results/track_a

Any dataset whose pkl is omitted is skipped and reported as such — the output
always states which datasets it actually covers, so a partial run cannot be
mistaken for a complete one.
"""

import os
import sys
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

# Import BEFORE joblib.load so the pickled class resolves to the module path.
from src.engine.universal_ensemble import UniversalEnsemble  # noqa: F401
from src.engine.label_map import UNIVERSAL_LABEL_MAP, unmapped_labels
from src.evaluator.stats import bootstrap_ci, format_ci
from src.engine.nids_config import install_pickle_shims

# A pkl produced by dumping a raw run_nids() result still contains the
# notebook's NIDSConfig, pickled as __main__.NIDSConfig. Register a stand-in
# so those files load here instead of raising AttributeError.
install_pickle_shims()


def parse_args():
    p = argparse.ArgumentParser(description="Track A: 3-dataset evaluation")
    p.add_argument("--universal_pkl", default="universal_nids_output.pkl")
    p.add_argument("--cicids_pkl", default=None)
    p.add_argument("--unsw_pkl", default=None)
    p.add_argument("--nslkdd_pkl", default=None)
    p.add_argument("--out", default="data/results/track_a")
    p.add_argument("--bootstrap", type=int, default=2000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max_test", type=int, default=None,
                   help="Subsample each test set to at most N rows "
                        "(stratified) to bound runtime. Omit to use all.")
    p.add_argument("--allow_unscaled", action="store_true",
                   help="Proceed for datasets with no stored scaler. Results "
                        "so obtained are NOT reportable — see "
                        "scripts/export_sub_scalers.md.")
    return p.parse_args()


def _load(path, label):
    import joblib
    if not path:
        return None
    if not os.path.exists(path):
        print(f"  ! {label}: {path} not found — skipping")
        return None
    print(f"  loading {label}: {path}")
    return joblib.load(path)


def _stratified_subsample(y, max_n, seed):
    if max_n is None or len(y) <= max_n:
        return np.arange(len(y))
    rng = np.random.default_rng(seed)
    idx = []
    classes, counts = np.unique(y, return_counts=True)
    frac = max_n / len(y)
    for c, cnt in zip(classes, counts):
        c_idx = np.flatnonzero(y == c)
        take = max(1, int(round(cnt * frac)))
        idx.append(rng.choice(c_idx, size=min(take, len(c_idx)), replace=False))
    return np.sort(np.concatenate(idx))


def evaluate_dataset(ens, ds_name, out_pkl, args) -> dict:
    """Score one dataset's held-out test split through the universal model."""
    from sklearn.metrics import (
        accuracy_score, f1_score, classification_report, confusion_matrix,
    )

    data   = out_pkl["data"]
    X_test = np.asarray(data["X_test"])
    y_test = np.asarray(data["y_test"])
    le_sub = data["label_encoder"]

    keep = _stratified_subsample(y_test, args.max_test, args.seed)
    X_test, y_test = X_test[keep], y_test[keep]

    # X_test in the per-dataset pkl is ALREADY scaled (the notebook scales
    # before the train/val/test split is stored), so do not scale again.
    proba   = ens.predict_proba_from_dataset(X_test, ds_name)
    y_pred_i = np.argmax(proba, axis=1)

    y_true_raw = le_sub.inverse_transform(y_test)
    y_true = np.array([UNIVERSAL_LABEL_MAP.get(l, l) for l in y_true_raw])
    y_pred = np.array(ens.le_universal.inverse_transform(y_pred_i))

    unmapped = unmapped_labels(set(y_true_raw))
    if unmapped:
        print(f"    ! labels with no taxonomy entry: {unmapped}")

    labels = sorted(set(y_true) | set(y_pred))
    acc  = accuracy_score(y_true, y_pred)
    mf1  = f1_score(y_true, y_pred, average="macro", zero_division=0, labels=labels)
    wf1  = f1_score(y_true, y_pred, average="weighted", zero_division=0, labels=labels)

    # binary attack-vs-benign view, for CIs comparable to the Track B table
    yb_true = (y_true != "Benign").astype(int)
    yb_pred = (y_pred != "Benign").astype(int)

    # A test split with no benign rows makes precision/F1/FPR arithmetic
    # identities rather than measurements: fp=tn=0 gives precision=1, F1=100%
    # and FPR=0 for a model that only ever answers "attack". This is the same
    # degeneracy that made the old Track B report claim 100% — guard it here
    # too, and label the numbers rather than printing them bare.
    n_benign_true = int((yb_true == 0).sum())
    n_attack_true = int((yb_true == 1).sum())
    degenerate = n_benign_true == 0 or n_attack_true == 0
    if degenerate:
        missing = "benign" if n_benign_true == 0 else "attack"
        print(f"    ⚠  DEGENERATE binary split: {n_benign_true:,} benign / "
              f"{n_attack_true:,} attack rows — no {missing} class present.")
        print(f"       Binary precision/F1/FPR below are NOT measurements and "
              f"must not be reported. Multiclass accuracy/macro-F1 are unaffected.")

    ci = bootstrap_ci(yb_true, yb_pred,
                      n_resamples=args.bootstrap, seed=args.seed)

    rep = classification_report(
        y_true, y_pred, labels=labels, zero_division=0, output_dict=True,
    )
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    print(f"    n_test={len(y_test):,}  accuracy={acc*100:.2f}%  "
          f"macro-F1={mf1*100:.2f}%  weighted-F1={wf1*100:.2f}%")
    _tag = "  [DEGENERATE - do not report]" if degenerate else ""
    print(f"    binary attack detection: F1 {format_ci(ci['f1_score'])}{_tag}")
    print(f"    {'':<4}                  Recall {format_ci(ci['recall'])}")
    print(f"    {'':<4}                  FPR    {format_ci(ci['fpr'])}")

    return {
        "dataset": ds_name,
        "n_test": int(len(y_test)),
        "n_features": int(X_test.shape[1]),
        "classes_present": labels,
        # recorded so a downstream reader can tell a real metric from an
        # artefact of an all-one-class split without re-deriving it
        "binary_n_benign": n_benign_true,
        "binary_n_attack": n_attack_true,
        "binary_degenerate": bool(degenerate),
        "accuracy_pct": round(acc * 100, 2),
        "macro_f1_pct": round(mf1 * 100, 2),
        "weighted_f1_pct": round(wf1 * 100, 2),
        "binary_attack_detection_ci": ci,
        "per_class": rep,
        "confusion_matrix": {"labels": labels, "matrix": cm.tolist()},
        "unmapped_labels": unmapped,
        "subsampled": args.max_test is not None and len(keep) < len(data["y_test"]),
    }


def main():
    args = parse_args()
    print("=" * 72)
    print("  TRACK A — universal model across all available datasets")
    print("=" * 72)

    uni = _load(args.universal_pkl, "universal model")
    if uni is None:
        print("\n  Cannot proceed without the universal model pkl.")
        return 1
    ens = uni["ensemble"]

    print("\n" + ens.describe())

    missing_scalers = [ds for ds in ens.datasets if not ens.has_scaler(ds)]
    if missing_scalers and not args.allow_unscaled:
        print(
            f"\n  NOTE: no stored scaler for {missing_scalers}.\n"
            "  Track A uses the pre-scaled X_test arrays from each dataset's "
            "own pkl, so this does\n"
            "  not affect the numbers below — but Track B (live/offline "
            "capture) DOES need them.\n"
            "  See scripts/export_sub_scalers.md before running Track B on "
            "anything but CICIDS2017."
        )

    sources = {
        "CICIDS2017": args.cicids_pkl,
        "UNSW-NB15":  args.unsw_pkl,
        "NSL-KDD":    args.nslkdd_pkl,
    }

    print("\n  Loading per-dataset test splits ...")
    loaded = {ds: _load(p, ds) for ds, p in sources.items()}

    results, skipped = {}, []
    for ds, out_pkl in loaded.items():
        if out_pkl is None:
            skipped.append(ds)
            continue
        if ds not in ens.sub_models:
            print(f"  ! {ds}: no sub-model in the universal pkl — skipping")
            skipped.append(ds)
            continue
        print(f"\n  ── {ds} " + "─" * (60 - len(ds)))
        try:
            results[ds] = evaluate_dataset(ens, ds, out_pkl, args)
        except Exception as exc:
            print(f"    FAILED: {exc}")
            skipped.append(ds)

    if not results:
        print("\n  No dataset could be evaluated. Nothing written.")
        return 1

    # ── routing integrity ────────────────────────────────────────────────────
    print("\n  ── ROUTING INTEGRITY " + "─" * 47)
    routing = {}
    for ds, out_pkl in loaded.items():
        if out_pkl is None or ds not in ens.sub_models:
            continue
        feats = list(out_pkl["data"]["feature_names"])
        routed = ens._get_matching_dataset(feats)
        ok = routed == ds
        routing[ds] = {"routed_to": routed, "correct": bool(ok),
                       "coverage": ens.route_report(feats)}
        print(f"    {ds:<12} -> {str(routed):<12} "
              f"{'OK' if ok else 'MISROUTED'}")

    # ── comparison table ─────────────────────────────────────────────────────
    print("\n  ── CROSS-DATASET COMPARISON " + "─" * 40)
    print(f"    {'Dataset':<12}{'n_test':>10}{'Acc':>9}{'MacroF1':>10}{'WgtF1':>9}")
    for ds, r in results.items():
        print(f"    {ds:<12}{r['n_test']:>10,}{r['accuracy_pct']:>8.2f}%"
              f"{r['macro_f1_pct']:>9.2f}%{r['weighted_f1_pct']:>8.2f}%")
    if skipped:
        print(f"\n    NOT EVALUATED: {', '.join(skipped)}")
        print("    Chapter 5 must scope its claims to the datasets above.")

    # ── save ─────────────────────────────────────────────────────────────────
    os.makedirs(args.out, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    payload = {
        "generated_at": datetime.now().isoformat(),
        "track": "A — per-dataset evaluation of the schema-routed universal model",
        "datasets_evaluated": list(results.keys()),
        "datasets_skipped": skipped,
        "bootstrap_resamples": args.bootstrap,
        "seed": args.seed,
        "routing_integrity": routing,
        "results": results,
        "note_on_cross_dataset_transfer": (
            "Not performed. The three datasets share zero feature columns "
            "after mutual-information selection, so a model trained on one "
            "cannot be applied to another without retraining on a common "
            "feature space. Report this in Limitations rather than "
            "approximating it."
        ),
    }
    path = os.path.join(args.out, f"track_a_{ts}.json")
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    print(f"\n  Saved: {path}")

    try:
        import pandas as pd
        rows = [{
            "Dataset": ds,
            "n_test": r["n_test"],
            "Accuracy %": r["accuracy_pct"],
            "Macro F1 %": r["macro_f1_pct"],
            "Weighted F1 %": r["weighted_f1_pct"],
            "Attack F1 %": r["binary_attack_detection_ci"]["f1_score"]["point"],
            "Attack F1 CI lo": r["binary_attack_detection_ci"]["f1_score"]["lo"],
            "Attack F1 CI hi": r["binary_attack_detection_ci"]["f1_score"]["hi"],
        } for ds, r in results.items()]
        csv_path = os.path.join(args.out, f"track_a_summary_{ts}.csv")
        pd.DataFrame(rows).to_csv(csv_path, index=False)
        print(f"  Saved: {csv_path}   (paste straight into Chapter 5)")
    except Exception as exc:
        print(f"  (summary CSV not written: {exc})")

    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
