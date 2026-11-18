"""
src/evaluator/stats.py
=======================
Significance testing and uncertainty quantification for the ablation table.

WHY THIS IS NOT OPTIONAL
────────────────────────
The thesis's central claim is that fusing Role 1 and Role 3 beats either
alone. The evidence offered for it was three point estimates in a table, from
a set of a few hundred windows, with no interval and no test. At that sample
size a two- or three-point difference in F1 is well inside sampling noise, so
a bare comparison of point estimates cannot support the claim either way.

Two things fix that, both computed from data already collected:

  • BOOTSTRAP CONFIDENCE INTERVALS — resample the per-window predictions with
    replacement, recompute the metric, and report the 2.5th/97.5th
    percentiles. Turns "F1 = 94.1" into "F1 = 94.1 (95% CI 91.2-96.6)".

  • McNEMAR'S TEST — the correct test for two classifiers evaluated on the
    SAME samples. It ignores the cases where both methods agree and asks
    only whether the disagreements are lopsided. A paired test is required
    here; an unpaired comparison of two accuracies would discard the pairing
    and understate significance.

McNemar is preferred over a t-test on per-fold accuracies because there are
no folds — this is a single pass over one capture, and the unit of analysis
is the window.
"""

from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np


# ── metric helpers ───────────────────────────────────────────────────────────

def _confusion(y_true: np.ndarray, y_pred: np.ndarray) -> Tuple[int, int, int, int]:
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    return tp, tn, fp, fn


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    """
    Binary metrics. Undefined quantities are returned as NaN rather than 0.0
    or 100.0 — an FPR computed with no negatives is not "0% false positives",
    it is unmeasured, and rounding it to a flattering number is how the
    earlier reports came to claim a perfect false-positive rate.
    """
    tp, tn, fp, fn = _confusion(y_true, y_pred)
    n = tp + tn + fp + fn

    precision = tp / (tp + fp) if (tp + fp) else np.nan
    recall    = tp / (tp + fn) if (tp + fn) else np.nan
    fpr       = fp / (fp + tn) if (fp + tn) else np.nan
    accuracy  = (tp + tn) / n if n else np.nan
    if np.isnan(precision) or np.isnan(recall) or (precision + recall) == 0:
        f1 = np.nan
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "accuracy":  accuracy * 100 if not np.isnan(accuracy) else np.nan,
        "precision": precision * 100 if not np.isnan(precision) else np.nan,
        "recall":    recall * 100 if not np.isnan(recall) else np.nan,
        "f1_score":  f1 * 100 if not np.isnan(f1) else np.nan,
        "fpr":       fpr * 100 if not np.isnan(fpr) else np.nan,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }


# ── bootstrap ────────────────────────────────────────────────────────────────

def bootstrap_ci(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    n_resamples: int = 2000,
    alpha: float = 0.05,
    seed: int = 42,
    metrics: Sequence[str] = ("accuracy", "precision", "recall", "f1_score", "fpr"),
) -> Dict[str, Dict[str, float]]:
    """
    Percentile bootstrap CIs for each metric.

    Resamples WINDOWS (the unit of analysis), not flows, so the interval
    reflects the actual sample size of the evaluation — which for a single
    capture is a few hundred, not the hundreds of thousands of flows.

    `seed` is fixed so a rerun reproduces the same interval; report it.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    n = len(y_true)
    if n == 0:
        return {m: {"lo": np.nan, "hi": np.nan, "point": np.nan} for m in metrics}

    rng = np.random.default_rng(seed)
    samples = {m: [] for m in metrics}

    for _ in range(n_resamples):
        idx = rng.integers(0, n, size=n)
        vals = compute_metrics(y_true[idx], y_pred[idx])
        for m in metrics:
            v = vals[m]
            if not (isinstance(v, float) and np.isnan(v)):
                samples[m].append(v)

    point = compute_metrics(y_true, y_pred)
    out = {}
    for m in metrics:
        arr = np.asarray(samples[m], dtype=float)
        if arr.size < max(30, n_resamples * 0.1):
            # metric was undefined in most resamples -> no usable interval
            out[m] = {
                "point": point[m], "lo": np.nan, "hi": np.nan,
                "n_valid_resamples": int(arr.size),
            }
            continue
        out[m] = {
            "point": round(float(point[m]), 2),
            "lo": round(float(np.percentile(arr, 100 * alpha / 2)), 2),
            "hi": round(float(np.percentile(arr, 100 * (1 - alpha / 2))), 2),
            "n_valid_resamples": int(arr.size),
        }
    return out


# ── McNemar ──────────────────────────────────────────────────────────────────

def mcnemar_test(
    y_true: Sequence[int],
    y_pred_a: Sequence[int],
    y_pred_b: Sequence[int],
    exact_threshold: int = 25,
) -> Dict[str, float]:
    """
    McNemar's test for two classifiers on the SAME samples.

    Builds the discordant counts:
        b = A correct, B wrong
        c = A wrong,   B correct
    and tests whether b and c differ more than chance allows.

    Uses the exact binomial test when b + c is small (the chi-square
    approximation is unreliable there, and with a few hundred windows it
    often is), otherwise the continuity-corrected chi-square.

    Returns p_value plus the raw counts, so the direction of the effect is
    visible and not just its significance.
    """
    y_true   = np.asarray(y_true, dtype=int)
    y_pred_a = np.asarray(y_pred_a, dtype=int)
    y_pred_b = np.asarray(y_pred_b, dtype=int)

    a_ok = y_pred_a == y_true
    b_ok = y_pred_b == y_true

    n_both  = int(np.sum(a_ok & b_ok))
    n_a     = int(np.sum(a_ok & ~b_ok))     # only A correct
    n_b     = int(np.sum(~a_ok & b_ok))     # only B correct
    n_none  = int(np.sum(~a_ok & ~b_ok))

    n_disc = n_a + n_b
    if n_disc == 0:
        return {
            "p_value": 1.0, "statistic": 0.0, "method": "no_discordant_pairs",
            "only_a_correct": 0, "only_b_correct": 0,
            "both_correct": n_both, "both_wrong": n_none,
            "significant_at_0.05": False,
        }

    if n_disc <= exact_threshold:
        # exact two-sided binomial with p = 0.5
        from math import comb
        k = min(n_a, n_b)
        tail = sum(comb(n_disc, i) for i in range(0, k + 1)) / (2 ** n_disc)
        p = min(1.0, 2 * tail)
        method = "exact_binomial"
        stat = float(k)
    else:
        stat = (abs(n_a - n_b) - 1) ** 2 / n_disc
        p = _chi2_sf_1df(stat)
        method = "chi2_continuity_corrected"

    return {
        "p_value": round(float(p), 6),
        "statistic": round(float(stat), 4),
        "method": method,
        "only_a_correct": n_a,
        "only_b_correct": n_b,
        "both_correct": n_both,
        "both_wrong": n_none,
        "n_discordant": n_disc,
        "significant_at_0.05": bool(p < 0.05),
    }


def _chi2_sf_1df(x: float) -> float:
    """
    Survival function of chi-square with 1 df, = erfc(sqrt(x/2)).

    Implemented via math.erfc so the evaluator does not require scipy — the
    project's requirements.txt does not list it, and adding a dependency for
    one closed-form expression is not worth the deployment friction.
    """
    from math import erfc, sqrt
    if x <= 0:
        return 1.0
    return float(erfc(sqrt(x / 2.0)))


def format_ci(block: Dict[str, float], unit: str = "%") -> str:
    """Render 'F1 = 94.10% (95% CI 91.20-96.60)' for a report table."""
    if block is None:
        return "n/a"
    pt = block.get("point")
    lo, hi = block.get("lo"), block.get("hi")
    if pt is None or (isinstance(pt, float) and np.isnan(pt)):
        return "undefined"
    if lo is None or (isinstance(lo, float) and np.isnan(lo)):
        return f"{pt:.2f}{unit} (CI n/a)"
    return f"{pt:.2f}{unit} (95% CI {lo:.2f}-{hi:.2f})"
