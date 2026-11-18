#!/usr/bin/env python3
"""
scripts/eval_cross_dataset_transfer.py
======================================
Zero-shot binary transfer experiment between CICIDS2017 and UNSW-NB15 across
12 homologous flow features (Table C.4), testing in-domain baselines and both
source-fitted and target-fitted RobustScaler transforms.

Writes:
  - <colab_dir>/cross_dataset_transfer.csv
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COLAB_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

# Exact 12 homologous features present in both selected feature schemas
FEATURE_PAIRS = [
    ("Flow Duration", "dur"),
    ("Total Fwd Packets", "spkts"),
    ("Total Backward Packets", "dpkts"),
    ("Total Length of Fwd Packets", "sbytes"),
    ("Total Length of Bwd Packets", "dbytes"),
    ("Flow Packets/s", "rate"),
    ("Fwd Packet Length Mean", "smean"),
    ("Bwd Packet Length Mean", "dmean"),
    ("Fwd IAT Mean", "sinpkt"),
    ("Bwd IAT Mean", "dinpkt"),
    ("Init_Win_bytes_forward", "swin"),
    ("Init_Win_bytes_backward", "dwin"),
]


def _load_shared(ds_name, col_idx):
    p = joblib.load(os.path.join(COLAB_DIR, "cache", ds_name, "processed_fixed_full.pkl"))
    fnames = list(p["feature_names"])
    cols = [pair[col_idx] for pair in FEATURE_PAIRS]
    indices = [fnames.index(c) for c in cols]
    scaler = p["scaler"]
    # Invert training-split RobustScaler to obtain unscaled physical values
    # on pre-SMOTE train and test splits before fitting fresh 12-feature scalers.
    Xtr = scaler.inverse_transform(p.get("X_train_pre_smote", p["X_train"]))[:, indices]
    Xte = scaler.inverse_transform(p["X_test"])[:, indices]
    le = p["label_encoder"]
    benign_name = "BENIGN" if ds_name == "CICIDS2017" else "Normal"
    benign_id = int(list(le.classes_).index(benign_name))
    ytr = (np.asarray(p.get("y_train_pre_smote", p["y_train"])) != benign_id).astype(int)
    yte = (np.asarray(p["y_test"]) != benign_id).astype(int)
    return Xtr, ytr, Xte, yte


def _score(yt, yp):
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) else 0.0
    return {
        "Accuracy %": round(accuracy_score(yt, yp) * 100.0, 2),
        "Binary F1 %": round(f1_score(yt, yp, pos_label=1, zero_division=0) * 100.0, 2),
        "Macro-F1 %": round(f1_score(yt, yp, average="macro", zero_division=0) * 100.0, 2),
        "Precision %": round(precision_score(yt, yp, pos_label=1, zero_division=0) * 100.0, 2),
        "Recall %": round(recall_score(yt, yp, pos_label=1, zero_division=0) * 100.0, 2),
        "FPR %": round(fpr, 2),
    }


def main():
    print(f"Environment: Python {sys.version.split()[0]} | XGBoost {xgb.__version__} (CPU) | scikit-learn {sklearn.__version__}", flush=True)
    Xtr_c, ytr_c, Xte_c, yte_c = _load_shared("CICIDS2017", 0)
    Xtr_u, ytr_u, Xte_u, yte_u = _load_shared("UNSW-NB15", 1)

    sc_c = RobustScaler().fit(Xtr_c)
    sc_u = RobustScaler().fit(Xtr_u)

    clf_c = xgb.XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        tree_method="hist", random_state=42, verbosity=0, n_jobs=-1,
        objective="binary:logistic", eval_metric="logloss",
    ).fit(sc_c.transform(Xtr_c), ytr_c)

    clf_u = xgb.XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        tree_method="hist", random_state=42, verbosity=0, n_jobs=-1,
        objective="binary:logistic", eval_metric="logloss",
    ).fit(sc_u.transform(Xtr_u), ytr_u)

    rows = [
        {"Transfer setting": "CICIDS2017 -> CICIDS2017 (in-domain, 12 shared features)", **_score(yte_c, clf_c.predict(sc_c.transform(Xte_c)))},
        {"Transfer setting": "CICIDS2017 -> UNSW-NB15 (zero-shot, source scaler)", **_score(yte_u, clf_c.predict(sc_c.transform(Xte_u)))},
        {"Transfer setting": "CICIDS2017 -> UNSW-NB15 (zero-shot, target RobustScaler)", **_score(yte_u, clf_c.predict(sc_u.transform(Xte_u)))},
        {"Transfer setting": "UNSW-NB15 -> UNSW-NB15 (in-domain, 12 shared features)", **_score(yte_u, clf_u.predict(sc_u.transform(Xte_u)))},
        {"Transfer setting": "UNSW-NB15 -> CICIDS2017 (zero-shot, source scaler)", **_score(yte_c, clf_u.predict(sc_u.transform(Xte_c)))},
        {"Transfer setting": "UNSW-NB15 -> CICIDS2017 (zero-shot, target RobustScaler)", **_score(yte_c, clf_u.predict(sc_c.transform(Xte_c)))},
    ]
    df = pd.DataFrame(rows)
    print(df.to_string(index=False))
    out_path = os.path.join(COLAB_DIR, "cross_dataset_transfer.csv")
    df.to_csv(out_path, index=False)
    print(f"\nSaved {out_path}")


if __name__ == "__main__":
    main()
