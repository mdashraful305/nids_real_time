#!/usr/bin/env python3
"""
scripts/verify_tuned_models_cpu.py
==================================
Re-scores the saved Colab-trained tuned XGBoost and Weighted Hybrid models
(xgboost_fixed.pkl + random_forest_fixed.pkl with validation weights) locally on
CPU against the saved held-out test splits in processed_fixed_full.pkl.

Confirms that the saved tuned models reproduce Colab evaluation_results.pkl
predictions and macro-F1 scores identically on CPU (e.g. CICIDS2017 91.02% XGBoost
and 91.15% hybrid).
"""

import os
import sys
import warnings
import joblib
import numpy as np
import sklearn
import xgboost as xgb
from sklearn.metrics import accuracy_score, f1_score

warnings.filterwarnings("ignore", category=UserWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COLAB_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

VALIDATION_WEIGHTS = {
    "CICIDS2017": (0.501, 0.499),
    "NSL-KDD": (0.502, 0.498),
    "UNSW-NB15": (0.510, 0.490),
}


def main():
    print(f"Environment: Python {sys.version.split()[0]} | XGBoost {xgb.__version__} (CPU) | scikit-learn {sklearn.__version__}", flush=True)
    for ds in ["CICIDS2017", "NSL-KDD", "UNSW-NB15"]:
        cache = joblib.load(os.path.join(COLAB_DIR, "cache", ds, "processed_fixed_full.pkl"))
        er = joblib.load(os.path.join(COLAB_DIR, "results", ds, "evaluation_results.pkl"))
        xm = joblib.load(os.path.join(COLAB_DIR, "models", ds, "xgboost_fixed.pkl"))
        rm = joblib.load(os.path.join(COLAB_DIR, "models", ds, "random_forest_fixed.pkl"))
        try:
            xm.set_params(device="cpu")
        except Exception:
            pass

        Xte, yte = cache["X_test"], cache["y_test"]
        res = er.get("results", er)
        yx_ref = np.asarray(res["xgboost"]["y_pred"])
        yh_ref = np.asarray(res["hybrid"]["y_pred"])

        px = xm.predict_proba(Xte)
        pr = rm.predict_proba(Xte)
        yx = np.argmax(px, axis=1)
        wx, wr = VALIDATION_WEIGHTS[ds]
        yh = np.argmax(wx * px + wr * pr, axis=1)

        acc_x = accuracy_score(yte, yx) * 100.0
        f1_x = f1_score(yte, yx, average="macro", zero_division=0) * 100.0
        acc_h = accuracy_score(yte, yh) * 100.0
        f1_h = f1_score(yte, yh, average="macro", zero_division=0) * 100.0
        match_x = np.mean(yx == yx_ref) * 100.0
        match_h = np.mean(yh == yh_ref) * 100.0

        print(f"\n[{ds}] (n_test={len(yte):,}, weights={wx:.3f}/{wr:.3f})", flush=True)
        print(f"  Tuned XGBoost (CPU 3.3.0): acc={acc_x:.4f}% ({acc_x:.2f}%) | macro-F1={f1_x:.4f}% ({f1_x:.2f}%) | pred_match_colab={match_x:.4f}%", flush=True)
        print(f"  Tuned Hybrid  (CPU 3.3.0): acc={acc_h:.4f}% ({acc_h:.2f}%) | macro-F1={f1_h:.4f}% ({f1_h:.2f}%) | pred_match_colab={match_h:.4f}%", flush=True)


if __name__ == "__main__":
    main()
