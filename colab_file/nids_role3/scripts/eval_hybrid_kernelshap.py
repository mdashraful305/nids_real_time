#!/usr/bin/env python3
"""
scripts/eval_hybrid_kernelshap.py
=================================
Evaluates true composite-ensemble KernelSHAP directly on the Weighted Hybrid
probability output:

    P_hybrid(X) = w_xgb * P_xgb(X) + w_rf * P_rf(X)

using a training-split k-means background (no test-set leakage), and compares
its global and per-flow attributions against Role 2's XGBoost TreeSHAP and
Table 8's L1-normalised Hybrid TreeSHAP across CICIDS2017, NSL-KDD, and
UNSW-NB15.

Also audits local per-flow faithfulness on a 50-flow sample of the 182
CICIDS2017 test flows where XGBoost and the Weighted Hybrid disagree (0.0361%).

Writes:
  - colab_file/hybrid_kernelshap_summary.csv
  - colab_file/nids_role3/data/results/posthoc_logs/eval_hybrid_kernelshap_output.txt
"""

import os
import sys
import time
import warnings
import joblib
import numpy as np
import pandas as pd
import shap
import sklearn
import xgboost as xgb
from scipy.stats import spearmanr, kendalltau

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NIDS_DIR = os.path.dirname(SCRIPT_DIR)
COLAB_DIR = os.path.dirname(NIDS_DIR)

VALIDATION_WEIGHTS = {
    "CICIDS2017": (0.501, 0.499),
    "NSL-KDD": (0.502, 0.498),
    "UNSW-NB15": (0.510, 0.490),
}

N_BG_POOL = 5000
N_BG_CLUSTERS = 30
N_EVAL_FLOWS = 100
N_KERNEL_SAMPLES = 200
N_DISCORDANT_CICIDS = 50


def _to_3d(sv):
    """Normalise SHAP output to shape (n_samples, n_features, n_classes)."""
    if isinstance(sv, list):
        return np.stack(sv, axis=-1)
    arr = np.asarray(sv)
    if arr.ndim == 2:
        return arr[:, :, None]
    return arr


def _topk_set(arr, cols, k):
    return {cols[i] for i in np.argsort(arr)[::-1][:k]}


def _local_metrics(ks_3d, tx_3d, pred_classes, cols):
    """Per-flow attribution agreement on each flow's hybrid-predicted class."""
    rhos, top1_hit, top3_ov, top5_ov = [], [], [], []
    for i in range(ks_3d.shape[0]):
        c = int(pred_classes[i])
        a = np.abs(ks_3d[i, :, c])
        b = np.abs(tx_3d[i, :, c])
        if np.std(a) > 0 and np.std(b) > 0:
            r = float(spearmanr(a, b).statistic)
            if not np.isnan(r):
                rhos.append(r)
        top1_hit.append(1.0 if int(np.argmax(a)) == int(np.argmax(b)) else 0.0)
        t3a, t3b = _topk_set(a, cols, 3), _topk_set(b, cols, 3)
        t5a, t5b = _topk_set(a, cols, 5), _topk_set(b, cols, 5)
        top3_ov.append(len(t3a & t3b) / 3.0 * 100.0)
        top5_ov.append(len(t5a & t5b) / 5.0 * 100.0)
    return {
        "local_spearman_mean": round(float(np.mean(rhos)) if rhos else 0.0, 3),
        "local_spearman_median": round(float(np.median(rhos)) if rhos else 0.0, 3),
        "local_top1_match_pct": round(float(np.mean(top1_hit) * 100.0), 1),
        "local_top3_overlap_pct": round(float(np.mean(top3_ov)), 1),
        "local_top5_overlap_pct": round(float(np.mean(top5_ov)), 1),
    }


def main():
    log_lines = []

    def emit(msg=""):
        print(msg, flush=True)
        log_lines.append(msg)

    emit("=" * 78)
    emit("  COMPOSITE HYBRID KERNELSHAP FAITHFULNESS EVALUATION (NO RETRAINING)")
    emit("=" * 78)
    emit(
        f"Environment: Python {sys.version.split()[0]} | XGBoost {xgb.__version__} (CPU) | "
        f"scikit-learn {sklearn.__version__} | SHAP {shap.__version__}"
    )
    emit(
        f"Protocol: KernelExplainer on P_hybrid = w_xgb*P_xgb + w_rf*P_rf | "
        f"bg=kmeans({N_BG_CLUSTERS}) from train-pre-SMOTE (seed=42) | "
        f"n_eval={N_EVAL_FLOWS} | nsamples={N_KERNEL_SAMPLES}"
    )

    summary_rows = []

    for ds in ["CICIDS2017", "NSL-KDD", "UNSW-NB15"]:
        np.random.seed(42)
        rng = np.random.RandomState(42)

        cache = joblib.load(os.path.join(COLAB_DIR, "cache", ds, "processed_fixed_full.pkl"))
        sd = joblib.load(os.path.join(COLAB_DIR, "models", ds, "shap_data.pkl"))
        xm = joblib.load(os.path.join(COLAB_DIR, "models", ds, "xgboost_fixed.pkl"))
        rm = joblib.load(os.path.join(COLAB_DIR, "models", ds, "random_forest_fixed.pkl"))
        er = joblib.load(os.path.join(COLAB_DIR, "results", ds, "evaluation_results.pkl"))
        shap_csv = pd.read_csv(os.path.join(COLAB_DIR, f"hybrid_shap_{ds}.csv")).set_index("feature")

        try:
            xm.set_params(device="cpu", n_jobs=-1)
        except Exception:
            pass
        try:
            rm.set_params(n_jobs=-1)
        except Exception:
            pass

        cols = list(cache["feature_names"])
        w_xgb, w_rf = VALIDATION_WEIGHTS[ds]

        def hyb_proba(X, _xm=xm, _rm=rm, _wx=w_xgb, _wr=w_rf):
            X_arr = np.asarray(X, dtype=np.float32)
            return _wx * _xm.predict_proba(X_arr) + _wr * _rm.predict_proba(X_arr)

        # Training-split background only (zero test leakage)
        X_tr_bg = cache.get("X_train_pre_smote", cache["X_train"])
        if len(X_tr_bg) > N_BG_POOL:
            bg_idx = rng.choice(len(X_tr_bg), N_BG_POOL, replace=False)
            X_tr_bg = X_tr_bg[bg_idx]
        bg = shap.kmeans(X_tr_bg, N_BG_CLUSTERS)

        # Exact same saved test sample as offline Role 2 SHAP
        X_eval = np.asarray(sd["X_sample"][:N_EVAL_FLOWS], dtype=np.float32)
        p_eval_hyb = hyb_proba(X_eval)
        y_eval_hyb = np.argmax(p_eval_hyb, axis=1)

        # 1. XGBoost TreeSHAP (Role 2) on exact same 100 flows
        t0 = time.perf_counter()
        te_xgb = shap.TreeExplainer(xm)
        sv_tx = _to_3d(te_xgb.shap_values(X_eval))
        dt_tx = (time.perf_counter() - t0) / len(X_eval) * 1000.0

        # 2. Composite Hybrid KernelSHAP directly on P_hybrid(X)
        np.random.seed(42)
        t1 = time.perf_counter()
        ke = shap.KernelExplainer(hyb_proba, bg)
        sv_ks = _to_3d(ke.shap_values(X_eval, nsamples=N_KERNEL_SAMPLES, silent=True))
        dt_ks = (time.perf_counter() - t1) / len(X_eval) * 1000.0

        # Global importance vectors (mean |phi| across samples and classes)
        g_ks = np.abs(sv_ks).mean(axis=(0, 2))
        g_tx_100 = np.abs(sv_tx).mean(axis=(0, 2))

        # Compare also against full-300 Table 8 vectors
        sx_300 = shap_csv.loc[cols, "shap_xgboost_only"].values.astype(float)
        sh_naive = shap_csv.loc[cols, "shap_hybrid_weighted"].values.astype(float)
        sr_300 = np.maximum(0.0, (sh_naive - w_xgb * sx_300) / w_rf)
        sh_l1_300 = w_xgb * (sx_300 / sx_300.sum()) + w_rf * (sr_300 / sr_300.sum())

        top15_ks = _topk_set(g_ks, cols, 15)
        top10_ks = _topk_set(g_ks, cols, 10)
        top15_tx100 = _topk_set(g_tx_100, cols, 15)
        top10_tx100 = _topk_set(g_tx_100, cols, 10)
        top15_tx300 = _topk_set(sx_300, cols, 15)
        top15_l1_300 = _topk_set(sh_l1_300, cols, 15)
        top15_sr300 = _topk_set(sr_300, cols, 15)

        loc = _local_metrics(sv_ks, sv_tx, y_eval_hyb, cols)

        row = {
            "Dataset": ds,
            "Slice": f"test_sample_n{N_EVAL_FLOWS}",
            "n_flows": N_EVAL_FLOWS,
            "w_xgb": w_xgb,
            "w_rf": w_rf,
            "kernelshap_ms_per_flow": round(dt_ks, 2),
            "xgb_treeshap_ms_per_flow": round(dt_tx, 2),
            "latency_ratio_ks_to_tx": round(dt_ks / max(dt_tx, 1e-6), 1),
            "global_vs_xgb100_top15_n": len(top15_ks & top15_tx100),
            "global_vs_xgb100_top15_pct": round(len(top15_ks & top15_tx100) / 15.0 * 100.0, 1),
            "global_vs_xgb100_top10_pct": round(len(top10_ks & top10_tx100) / 10.0 * 100.0, 1),
            "global_vs_xgb100_rho": round(float(spearmanr(g_ks, g_tx_100).statistic), 3),
            "global_vs_xgb100_tau": round(float(kendalltau(g_ks, g_tx_100).statistic), 3),
            "global_vs_xgb300_top15_pct": round(len(top15_ks & top15_tx300) / 15.0 * 100.0, 1),
            "global_vs_xgb300_rho": round(float(spearmanr(g_ks, sx_300).statistic), 3),
            "global_vs_l1hyb300_top15_pct": round(len(top15_ks & top15_l1_300) / 15.0 * 100.0, 1),
            "global_vs_l1hyb300_rho": round(float(spearmanr(g_ks, sh_l1_300).statistic), 3),
            "global_vs_rf300_top15_pct": round(len(top15_ks & top15_sr300) / 15.0 * 100.0, 1),
            "global_vs_rf300_rho": round(float(spearmanr(g_ks, sr_300).statistic), 3),
            **loc,
        }
        summary_rows.append(row)

        top5_ks_names = [f"{cols[i]} ({g_ks[i]:.4f})" for i in np.argsort(g_ks)[::-1][:5]]
        top5_tx_names = [f"{cols[i]} ({g_tx_100[i]:.4f})" for i in np.argsort(g_tx_100)[::-1][:5]]

        emit(f"\n[{ds}] (n={N_EVAL_FLOWS}, weights={w_xgb:.3f}/{w_rf:.3f})")
        emit(f"  Latency: Hybrid KernelSHAP = {dt_ks:.1f} ms/flow | XGB TreeSHAP = {dt_tx:.2f} ms/flow ({row['latency_ratio_ks_to_tx']}x slower)")
        emit(f"  Global Top-5 (Hybrid KernelSHAP prob) : {', '.join(top5_ks_names)}")
        emit(f"  Global Top-5 (XGB TreeSHAP log-odds)  : {', '.join(top5_tx_names)}")
        emit(f"  Global vs XGB TreeSHAP (same 100)     : Top-15 {row['global_vs_xgb100_top15_n']}/15 ({row['global_vs_xgb100_top15_pct']}%), Top-10 {row['global_vs_xgb100_top10_pct']}%, rho={row['global_vs_xgb100_rho']:.3f}, tau={row['global_vs_xgb100_tau']:.3f}")
        emit(f"  Global vs L1-Hybrid TreeSHAP (300)    : Top-15 {row['global_vs_l1hyb300_top15_pct']}%, rho={row['global_vs_l1hyb300_rho']:.3f}")
        emit(f"  Global vs RF TreeSHAP (300)           : Top-15 {row['global_vs_rf300_top15_pct']}%, rho={row['global_vs_rf300_rho']:.3f}")
        emit(f"  Per-flow (predicted class) faithfulness: mean rho={loc['local_spearman_mean']:.3f} (median {loc['local_spearman_median']:.3f}), Top-1 match={loc['local_top1_match_pct']}%, Top-3 overlap={loc['local_top3_overlap_pct']}%, Top-5 overlap={loc['local_top5_overlap_pct']}%")

        # Extra audit on CICIDS2017 discordant flows (where XGBoost != Hybrid)
        if ds == "CICIDS2017":
            res = er.get("results", er)
            yx_all = np.asarray(res["xgboost"]["y_pred"])
            yh_all = np.asarray(res["hybrid"]["y_pred"])
            disc_idx = np.where(yx_all != yh_all)[0]
            rng_d = np.random.RandomState(42)
            pick = rng_d.choice(disc_idx, size=min(N_DISCORDANT_CICIDS, len(disc_idx)), replace=False)
            X_disc = np.asarray(cache["X_test"][pick], dtype=np.float32)
            y_disc_hyb = yh_all[pick]

            sv_tx_d = _to_3d(te_xgb.shap_values(X_disc))
            np.random.seed(42)
            t2 = time.perf_counter()
            sv_ks_d = _to_3d(ke.shap_values(X_disc, nsamples=N_KERNEL_SAMPLES, silent=True))
            dt_ks_d = (time.perf_counter() - t2) / len(X_disc) * 1000.0

            g_ks_d = np.abs(sv_ks_d).mean(axis=(0, 2))
            g_tx_d = np.abs(sv_tx_d).mean(axis=(0, 2))
            t15_d = len(_topk_set(g_ks_d, cols, 15) & _topk_set(g_tx_d, cols, 15))
            rho_d = float(spearmanr(g_ks_d, g_tx_d).statistic)
            loc_d = _local_metrics(sv_ks_d, sv_tx_d, y_disc_hyb, cols)

            drow = {
                "Dataset": "CICIDS2017",
                "Slice": f"discordant_n{len(pick)}_of_{len(disc_idx)}",
                "n_flows": len(pick),
                "w_xgb": w_xgb,
                "w_rf": w_rf,
                "kernelshap_ms_per_flow": round(dt_ks_d, 2),
                "xgb_treeshap_ms_per_flow": round(dt_tx, 2),
                "latency_ratio_ks_to_tx": round(dt_ks_d / max(dt_tx, 1e-6), 1),
                "global_vs_xgb100_top15_n": t15_d,
                "global_vs_xgb100_top15_pct": round(t15_d / 15.0 * 100.0, 1),
                "global_vs_xgb100_top10_pct": round(len(_topk_set(g_ks_d, cols, 10) & _topk_set(g_tx_d, cols, 10)) / 10.0 * 100.0, 1),
                "global_vs_xgb100_rho": round(rho_d, 3),
                "global_vs_xgb100_tau": round(float(kendalltau(g_ks_d, g_tx_d).statistic), 3),
                "global_vs_xgb300_top15_pct": np.nan,
                "global_vs_xgb300_rho": np.nan,
                "global_vs_l1hyb300_top15_pct": np.nan,
                "global_vs_l1hyb300_rho": np.nan,
                "global_vs_rf300_top15_pct": np.nan,
                "global_vs_rf300_rho": np.nan,
                **loc_d,
            }
            summary_rows.append(drow)
            emit(f"\n[CICIDS2017 DISCORDANT SLICE: {len(pick)}/{len(disc_idx)} flows where XGBoost != Hybrid (0.0361% of test)]")
            emit(f"  Global on discordant flows (KS vs XGB): Top-15 {t15_d}/15 ({drow['global_vs_xgb100_top15_pct']}%), rho={rho_d:.3f}")
            emit(f"  Per-flow (hybrid-predicted class)     : mean rho={loc_d['local_spearman_mean']:.3f} (median {loc_d['local_spearman_median']:.3f}), Top-1 match={loc_d['local_top1_match_pct']}%, Top-3 overlap={loc_d['local_top3_overlap_pct']}%, Top-5 overlap={loc_d['local_top5_overlap_pct']}%")

    out_csv = os.path.join(COLAB_DIR, "hybrid_kernelshap_summary.csv")
    pd.DataFrame(summary_rows).to_csv(out_csv, index=False)
    emit(f"\nSaved summary CSV: {out_csv}")

    out_log = os.path.join(NIDS_DIR, "data", "results", "posthoc_logs", "eval_hybrid_kernelshap_output.txt")
    os.makedirs(os.path.dirname(out_log), exist_ok=True)
    with open(out_log, "w", encoding="utf-8") as fh:
        fh.write("\n".join(log_lines) + "\n")
    emit(f"Saved archived log: {out_log}")
    emit("=" * 78)


if __name__ == "__main__":
    main()
