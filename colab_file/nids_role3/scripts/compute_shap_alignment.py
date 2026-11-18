#!/usr/bin/env python3
"""
scripts/compute_shap_alignment.py
=================================
Computes Gain/Gini vs. TreeSHAP and L1-normalised Hybrid SHAP alignment metrics
(top-15 overlap % and Spearman rank correlation rho) across CICIDS2017,
UNSW-NB15, and NSL-KDD.

If local model pickles (colab_file/models/<ds>/{xgboost,random_forest}_fixed.pkl)
are present, exports feature_importance_gain_gini.csv; otherwise reads that CSV
directly so all Table 8 / Figure 5-7 statistics remain reproducible from Git.

Writes:
  - <colab_dir>/feature_importance_gain_gini.csv (when model pkls exist)
  - <colab_dir>/hybrid_shap_alignment_summary.csv
  - <colab_dir>/hybrid_shap_overlap.csv (updated with L1-normalised overlaps)
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from scipy.stats import spearmanr

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COLAB_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

VALIDATION_WEIGHTS = {
    "CICIDS2017": (0.501, 0.499),
    "NSL-KDD": (0.502, 0.498),
    "UNSW-NB15": (0.510, 0.490),
}


def main():
    print(f"Environment: Python {sys.version.split()[0]} (CPU post-hoc alignment)", flush=True)
    ov_path = os.path.join(COLAB_DIR, "hybrid_shap_overlap.csv")
    ov_df = pd.read_csv(ov_path).set_index("Dataset") if os.path.exists(ov_path) else None
    gain_gini_csv = os.path.join(COLAB_DIR, "feature_importance_gain_gini.csv")

    gg_frames = []
    use_cached_gg = False
    # Check whether local model pickles are available to extract raw Gain/Gini
    all_pkls_present = all(
        os.path.exists(os.path.join(COLAB_DIR, "models", ds, "xgboost_fixed.pkl"))
        and os.path.exists(os.path.join(COLAB_DIR, "models", ds, "random_forest_fixed.pkl"))
        and os.path.exists(os.path.join(COLAB_DIR, "cache", ds, "processed_fixed_full.pkl"))
        for ds in ["CICIDS2017", "NSL-KDD", "UNSW-NB15"]
    )
    if not all_pkls_present:
        if not os.path.exists(gain_gini_csv):
            raise FileNotFoundError(f"Neither model pickles nor {gain_gini_csv} exist.")
        use_cached_gg = True
        gg_all = pd.read_csv(gain_gini_csv)

    summary_rows = []
    for ds in ["CICIDS2017", "NSL-KDD", "UNSW-NB15"]:
        shap_df = pd.read_csv(os.path.join(COLAB_DIR, f"hybrid_shap_{ds}.csv"))
        if not use_cached_gg:
            meta = joblib.load(os.path.join(COLAB_DIR, "cache", ds, "processed_fixed_full.pkl"))
            cols = list(meta["feature_names"])
            xgb_m = joblib.load(os.path.join(COLAB_DIR, "models", ds, "xgboost_fixed.pkl"))
            rf_m = joblib.load(os.path.join(COLAB_DIR, "models", ds, "random_forest_fixed.pkl"))
            gg_ds = pd.DataFrame({
                "Dataset": ds,
                "feature": cols,
                "xgb_gain": xgb_m.feature_importances_.astype(float),
                "rf_gini": rf_m.feature_importances_.astype(float),
            })
            gg_frames.append(gg_ds)
        else:
            gg_ds = gg_all[gg_all["Dataset"] == ds].copy()
            cols = list(gg_ds["feature"])

        shap_idx = shap_df.set_index("feature").loc[cols]
        gg_idx = gg_ds.set_index("feature").loc[cols]

        sx = shap_idx["shap_xgboost_only"].values.astype(float)
        sh_naive = shap_idx["shap_hybrid_weighted"].values.astype(float)
        if ov_df is not None and ds in ov_df.index:
            w_xgb = float(ov_df.loc[ds, "w_xgb"])
            w_rf = float(ov_df.loc[ds, "w_rf"])
        else:
            w_xgb, w_rf = VALIDATION_WEIGHTS[ds]

        # Algebraic recovery of RF TreeSHAP magnitude: sh_naive = w_xgb*sx + w_rf*sr
        sr = np.maximum(0.0, (sh_naive - w_xgb * sx) / w_rf)
        sx_sum = float(sx.sum())
        sr_sum = float(sr.sum())

        sx_l1 = sx / sx_sum
        sr_l1 = sr / sr_sum
        sh_l1 = w_xgb * sx_l1 + w_rf * sr_l1

        x_imp = gg_idx["xgb_gain"].values.astype(float)
        r_imp = gg_idx["rf_gini"].values.astype(float)

        def _top15(arr):
            return {cols[i] for i in np.argsort(arr)[::-1][:15]}

        top_sx = _top15(sx)
        top_sr = _top15(sr)
        top_l1 = _top15(sh_l1)
        top_gain = _top15(x_imp)
        top_gini = _top15(r_imp)

        summary_rows.append({
            "Dataset": ds,
            "w_xgb": w_xgb,
            "w_rf": w_rf,
            "sum_abs_xgb_shap": round(sx_sum, 3),
            "sum_abs_rf_shap": round(sr_sum, 3),
            "scale_ratio_xgb_to_rf": round(sx_sum / sr_sum, 1),
            "l1_hyb_vs_xgb_shap_top15_n": len(top_l1 & top_sx),
            "l1_hyb_vs_xgb_shap_top15_pct": round(len(top_l1 & top_sx) / 15.0 * 100.0, 1),
            "l1_hyb_vs_xgb_shap_rho": round(float(spearmanr(sh_l1, sx).statistic), 3),
            "l1_hyb_vs_rf_shap_top15_n": len(top_l1 & top_sr),
            "l1_hyb_vs_rf_shap_top15_pct": round(len(top_l1 & top_sr) / 15.0 * 100.0, 1),
            "l1_hyb_vs_rf_shap_rho": round(float(spearmanr(sh_l1, sr).statistic), 3),
            "xgb_gain_vs_xgb_shap_top15_n": len(top_gain & top_sx),
            "xgb_gain_vs_xgb_shap_top15_pct": round(len(top_gain & top_sx) / 15.0 * 100.0, 1),
            "xgb_gain_vs_xgb_shap_rho": round(float(spearmanr(sx, x_imp).statistic), 3),
            "rf_gini_vs_xgb_shap_top15_n": len(top_gini & top_sx),
            "rf_gini_vs_xgb_shap_top15_pct": round(len(top_gini & top_sx) / 15.0 * 100.0, 1),
            "rf_gini_vs_xgb_shap_rho": round(float(spearmanr(sx, r_imp).statistic), 3),
            "rf_gini_vs_rf_shap_top15_n": len(top_gini & top_sr),
            "rf_gini_vs_rf_shap_top15_pct": round(len(top_gini & top_sr) / 15.0 * 100.0, 1),
            "rf_gini_vs_rf_shap_rho": round(float(spearmanr(sr, r_imp).statistic), 3),
        })

    if not use_cached_gg:
        pd.concat(gg_frames, ignore_index=True).to_csv(gain_gini_csv, index=False)
        print(f"Saved {gain_gini_csv}")

    out_csv = os.path.join(COLAB_DIR, "hybrid_shap_alignment_summary.csv")
    out_df = pd.DataFrame(summary_rows)
    out_df.to_csv(out_csv, index=False)
    # Keep hybrid_shap_overlap.csv synchronised with L1-normalised overlaps
    ov_clean = pd.DataFrame([
        {
            "Dataset": r["Dataset"],
            "w_xgb": r["w_xgb"],
            "w_rf": r["w_rf"],
            "top15_overlap_pct": r["l1_hyb_vs_xgb_shap_top15_pct"],
            "spearman_rho": r["l1_hyb_vs_xgb_shap_rho"],
        }
        for r in summary_rows
    ])
    ov_clean.to_csv(ov_path, index=False)
    print(f"Saved {out_csv}")
    print(f"Updated {ov_path}")
    print(out_df.to_string(index=False))


if __name__ == "__main__":
    main()
