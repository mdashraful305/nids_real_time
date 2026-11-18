#!/usr/bin/env python3
"""
scripts/recompute_fair_baselines.py
===================================
Reproducible fair comparison between library-default plain XGBoost (no SMOTE,
no tuning) and the tuned hybrid pipeline (from evaluation_results.pkl) on the
identical pre-SMOTE training core and held-out test splits across CICIDS2017,
UNSW-NB15, and NSL-KDD.

Writes:
  - <base_dir>/plain_xgb_baseline_fair.csv
  - <base_dir>/perclass_recall_baseline_check.csv
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb
from sklearn.metrics import accuracy_score, f1_score, recall_score

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NIDS_ROLE3_DIR = os.path.dirname(SCRIPT_DIR)
COLAB_DIR = os.path.dirname(NIDS_ROLE3_DIR)
sys.path.insert(0, NIDS_ROLE3_DIR)

from src.engine.label_map import UNIVERSAL_LABEL_MAP  # noqa: E402


def _load_merged_map():
    mp_csv = os.path.join(COLAB_DIR, "label_mapping_table.csv")
    if os.path.exists(mp_csv):
        df_m = pd.read_csv(mp_csv)
        return dict(zip(df_m["Native label"].astype(str), df_m["Merged (shared) family"].astype(str)))
    return dict(UNIVERSAL_LABEL_MAP)


_MERGED_MAP = _load_merged_map()


def _merge(labels):
    return np.array([_MERGED_MAP.get(str(x), str(x)) for x in labels])


def main():
    print(f"Environment: Python {sys.version.split()[0]} | XGBoost {xgb.__version__} (CPU) | scikit-learn {sklearn.__version__}", flush=True)
    fair_rows = []
    recall_rows = []

    for ds_name in ["CICIDS2017", "UNSW-NB15", "NSL-KDD"]:
        cache_pkl = os.path.join(COLAB_DIR, "cache", ds_name, "processed_fixed_full.pkl")
        eval_pkl = os.path.join(COLAB_DIR, "results", ds_name, "evaluation_results.pkl")
        data = joblib.load(cache_pkl)
        er = joblib.load(eval_pkl)

        le = data["label_encoder"]
        Xtr = data.get("X_train_pre_smote", data["X_train"])
        ytr = data.get("y_train_pre_smote", data["y_train"])
        Xte = data["X_test"]
        yte = data["y_test"]
        n_classes = int(data["n_classes"])
        yph_idx = np.asarray(er["results"]["hybrid"]["y_pred"])

        print(f"\n[{ds_name}] fitting library-default XGBoost on {len(Xtr):,} train rows, {n_classes} classes...", flush=True)
        base = xgb.XGBClassifier(
            tree_method="hist",
            random_state=42,
            verbosity=0,
            n_jobs=-1,
            **(
                {"objective": "multi:softprob", "num_class": n_classes, "eval_metric": "mlogloss"}
                if n_classes > 2
                else {"objective": "binary:logistic", "eval_metric": "logloss"}
            ),
        )
        base.fit(Xtr, ytr)
        yp_idx = base.predict(Xte)

        yte_nat = le.inverse_transform(yte)
        yp_nat = le.inverse_transform(yp_idx)
        yph_nat = le.inverse_transform(yph_idx)

        for space, (yt, yd, yh) in [
            ("native", (yte_nat, yp_nat, yph_nat)),
            ("merged (shared)", (_merge(yte_nat), _merge(yp_nat), _merge(yph_nat))),
        ]:
            acc_d = round(accuracy_score(yt, yd) * 100, 2)
            f1_d = round(f1_score(yt, yd, average="macro", zero_division=0) * 100, 2)
            acc_h = round(accuracy_score(yt, yh) * 100, 2)
            f1_h = round(f1_score(yt, yh, average="macro", zero_division=0) * 100, 2)
            fair_rows.append({
                "Dataset": ds_name,
                "Model": "Plain XGBoost (default)",
                "Label space": space,
                "Accuracy %": acc_d,
                "Macro-F1 %": f1_d,
            })
            fair_rows.append({
                "Dataset": ds_name,
                "Model": "Tuned pipeline (hybrid)",
                "Label space": space,
                "Accuracy %": acc_h,
                "Macro-F1 %": f1_h,
            })
            print(f"  {space:<16} | default acc={acc_d:.2f}% mf1={f1_d:.2f}% | tuned acc={acc_h:.2f}% mf1={f1_h:.2f}%", flush=True)

        rec_def = recall_score(yte, yp_idx, average=None, zero_division=0) * 100
        rec_tun = recall_score(yte, yph_idx, average=None, zero_division=0) * 100
        sup = np.bincount(yte, minlength=n_classes)
        ds_rec_rows = []
        for idx_c, cname in enumerate(le.classes_):
            rd = round(float(rec_def[idx_c]), 1)
            rt = round(float(rec_tun[idx_c]), 1)
            ds_rec_rows.append({
                "Dataset": ds_name,
                "Class": str(cname),
                "Support": int(sup[idx_c]),
                "Recall default %": rd,
                "Recall tuned %": rt,
                "Delta (tuned-default)": round(rt - rd, 1),
            })
        ds_rec_rows.sort(key=lambda r: r["Support"])
        recall_rows.extend(ds_rec_rows)

    fair_df = pd.DataFrame(fair_rows).sort_values(["Dataset", "Label space", "Model"])
    rec_df = pd.DataFrame(recall_rows)

    fair_out = os.path.join(COLAB_DIR, "plain_xgb_baseline_fair.csv")
    rec_out = os.path.join(COLAB_DIR, "perclass_recall_baseline_check.csv")
    fair_df.to_csv(fair_out, index=False)
    rec_df.to_csv(rec_out, index=False)
    print("\n" + fair_df.to_string(index=False), flush=True)
    print("\n--- Per-class recall diagnostics (native label space) ---", flush=True)
    print(rec_df.to_string(index=False), flush=True)
    print(f"\nSaved {fair_out}", flush=True)
    print(f"Saved {rec_out}", flush=True)


if __name__ == "__main__":
    main()
