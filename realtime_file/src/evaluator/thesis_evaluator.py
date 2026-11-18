"""
src/evaluator/thesis_evaluator.py
===================================
Publishable-result evaluator for the unified NIDS pipeline. Computes
everything needed for the thesis results section that the existing
src/evaluator/evaluator.py (Role-3-only) does not cover:

  1. ABLATION TABLE — Role1-only vs Role3-only vs Combined (decision
     engine) precision/recall/F1/FPR against ground truth. This is the
     evidence that integrating the three roles actually helps, which is
     the core claim of the thesis — without this table there is no
     quantitative support for "the combination is better than either
     part alone".

  2. PER-ATTACK-FAMILY ACCURACY for each of the three methods, so you
     can show (for example) "Role1 alone misses slow multi-step attacks
     that Role3 catches" or vice versa, with numbers.

  3. LATENCY STATISTICS — Role1 per-flow inference time (mean/p95) and
     Role3 per-LLM-call latency (mean/p95), separately from cache hits
     and auto-benign-skipped windows (which have ~0 latency and would
     otherwise make the LLM look artificially fast if averaged in).

  4. CONFLICT / AGREEMENT statistics — how often Role1 and Role3
     disagreed, and what the decision engine resolved conflicts to.

  5. THROUGHPUT — windows/hour and flows/sec, plus peak memory (RSS),
     directly answering "does this scale" for the methodology section.

Usage
-----
evaluator = ThesisEvaluator(cfg)

# call once per window that HAS ground truth (chunk.ground_truth non-empty)
evaluator.add_window(
    chunk=chunk, r1=r1, r3=r3, alert=alert,
    role1_latency_s=role1_latency,   # None if Role1 did not run
)

# call once at the very end
report = evaluator.generate_report(wall_clock_seconds=total_time)
evaluator.save_report(report)
"""

import os
import json
import csv
from datetime import datetime
from collections import defaultdict
from typing import Optional, Dict, List

import numpy as np
import pandas as pd

from src.utils.logger import get_logger

log = get_logger(__name__)

from src.engine.label_map import (
    UNIVERSAL_LABEL_MAP, to_family, NO_LABEL_SENTINELS,
    UNMATCHED_LABEL, BENIGN_FAMILY, unmapped_labels, attack_window_verdict,
)

# Majority vote (0.5) is the old, always-available fallback if
# config.evaluation.attack_window_threshold is absent. See that setting in
# config/settings.yaml for why 0.5 misses low-volume attacks and why 0.0
# ("any attack flow") is not the fix either.
DEFAULT_ATTACK_WINDOW_THRESHOLD = 0.5

BENIGN_LABELS = {"BENIGN", "benign", "normal", "Normal", "Benign"}


class DegenerateEvaluationError(RuntimeError):
    """
    Raised when the evaluation set cannot support the metrics being computed.

    This exists because of a real failure that produced publishable-looking
    but meaningless results: the flow CSV had no Label column, the reader
    substituted {"UNKNOWN": n}, and "UNKNOWN" was scored as a positive. Every
    ground-truth window became an attack window, so tn=fp=0 and the report
    read precision=100.0 / fpr=0.0 / combined accuracy=100.0 — all of which
    are arithmetic identities of an all-positive test set, not measurements.

    A precision or FPR figure computed with zero negatives is not a weak
    result, it is an undefined one. Fail rather than emit it.
    """

# LABEL_TO_FAMILY is now an alias onto the shared taxonomy in
# src/engine/label_map.py, which the training notebook imports as well. The
# previous local copy carried the comment "Must stay in sync with
# UNIVERSAL_LABEL_MAP in the training notebook" while nothing enforced it,
# and it had already drifted: it listed CICIDS2017 labels only, so no
# UNSW-NB15 or NSL-KDD attack family could ever be scored.
LABEL_TO_FAMILY = UNIVERSAL_LABEL_MAP


_BOX_TO_ASCII = str.maketrans({
    "═": "=", "─": "-", "│": "|", "•": "*", "→": "->", "⚠": "!",
    "✓": "OK", "✗": "X", "±": "+/-", "–": "-", "—": "-",
})


def _p(text: str = "") -> None:
    """
    print() that survives a non-UTF-8 console.

    The report is drawn with box-drawing characters, which a Windows cp1252
    console cannot encode — generate_report() raised UnicodeEncodeError and
    took the whole evaluation with it AFTER all the work was done. Degrade the
    glyphs rather than lose the results.
    """
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.translate(_BOX_TO_ASCII).encode(
            "ascii", "replace").decode("ascii"))


def _peak_rss_mb() -> tuple:
    """
    Portable peak resident-set size in MB.

    The original implementation used `resource.getrusage()`, which is POSIX
    only and raised ImportError on Windows — so the evaluator could not be
    run or tested outside Colab. Returns (value_mb, method) so the report can
    state how the figure was obtained rather than implying one number is
    comparable across platforms.
    """
    try:
        import psutil            # most accurate, cross-platform
        return psutil.Process(os.getpid()).memory_info().rss / (1024 ** 2), "psutil_rss"
    except Exception:
        pass
    try:
        import resource          # POSIX
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux reports KB, macOS reports bytes
        import sys as _sys
        rss_mb = rss / (1024 ** 2) if _sys.platform == "darwin" else rss / 1024
        return rss_mb, "resource_ru_maxrss"
    except Exception:
        pass
    try:
        import tracemalloc       # last resort: Python heap only, not true RSS
        if tracemalloc.is_tracing():
            return tracemalloc.get_traced_memory()[1] / (1024 ** 2), "tracemalloc_peak"
    except Exception:
        pass
    return 0.0, "unavailable"


def _drop_unlabelled(gt: Dict[str, int]) -> Dict[str, int]:
    """
    Remove sentinels that mean "we do not know", so they can never be counted
    as a class. UNMATCHED comes from the ground-truth join; UNKNOWN is the
    legacy sentinel the old cicflow_reader fallback emitted and is rejected
    here defensively in case an old labelled CSV is still lying around.
    """
    return {
        lbl: cnt for lbl, cnt in gt.items()
        if lbl not in (UNMATCHED_LABEL, "UNKNOWN")
    }


def _gt_to_binary(gt: Dict[str, int], threshold: float = DEFAULT_ATTACK_WINDOW_THRESHOLD) -> str:
    gt = _drop_unlabelled(gt)
    if not gt:
        return "unknown"
    total  = sum(gt.values())
    benign = sum(cnt for lbl, cnt in gt.items() if lbl in BENIGN_LABELS)
    attack = total - benign
    return "attack" if attack_window_verdict(attack, total, threshold) else "benign"


def _gt_to_family(gt: Dict[str, int], threshold: float = DEFAULT_ATTACK_WINDOW_THRESHOLD) -> str:
    """
    Family label for a window, consistent with _gt_to_binary.

    CONSISTENCY FIX
    ───────────────
    This used to pick the largest NON-benign family regardless of how small it
    was, while _gt_to_binary used a majority vote. A window holding 3,000
    benign flows and 13 Bot flows was therefore binary="benign" but
    family="Bot". In a real run that produced `Bot: 95` windows in the
    per-family table against only 18 attack windows in the ablation — so the
    "Bot" row was reporting accuracy on windows that are benign by the very
    definition being scored, and the two tables could not be read together.

    The family must agree with the binary label it is broken down by: both
    now go through the SAME threshold via attack_window_verdict(), passed in
    from the same place (ThesisEvaluator.attack_window_threshold), so they
    can never independently drift the way the old hardcoded 0.5-vs-nonzero
    split once did.
    """
    gt = _drop_unlabelled(gt)
    if not gt:
        return "Unknown"
    if _gt_to_binary(gt, threshold) == "benign":
        return "Benign"
    counts = {LABEL_TO_FAMILY.get(l, l): c for l, c in gt.items() if l not in BENIGN_LABELS}
    if not counts:
        return "Benign"
    return max(counts, key=counts.get)


def _label_to_binary(label: Optional[str]) -> str:
    if label is None:
        return "missing"
    return "benign" if label in BENIGN_LABELS else "attack"


def _verdict_to_binary(verdict: Optional[str], suspicious_is_attack: bool = None) -> str:
    """
    Map a role/combined verdict to the binary attack/benign used for P/R/F1.

    Whether "suspicious" counts as a positive is a real modelling choice and
    is now explicit, controlled by $NIDS_SUSPICIOUS_IS_ATTACK (default False):

      False (default): only a committed "attack" is a positive; "suspicious"
        means "escalated for a human to glance at" and is NOT counted as a
        detection. This is what makes the role1_gated fusion mode measurable —
        when Role 1 says benign and Role 3 raises an alarm, the window becomes
        "suspicious", which does NOT inflate the attack FPR but is still shown
        for review. With the old always-attack rule, role1_gated collapsed to
        OR and fusion could never beat Role 1.

      True: legacy behaviour — "suspicious" is scored as an attack. Use only if
        you deliberately want the high-recall / high-FPR reading.

    Apply the SAME setting to every role so Role1/Role3/Combined stay
    comparable.
    """
    if verdict is None:
        return "missing"
    if suspicious_is_attack is None:
        import os
        suspicious_is_attack = os.environ.get(
            "NIDS_SUSPICIOUS_IS_ATTACK", "0"
        ).lower() in ("1", "true", "yes")
    positives = ("attack", "suspicious") if suspicious_is_attack else ("attack",)
    return "attack" if verdict in positives else "benign"


class _MethodStats:
    """Confusion-matrix + per-family accumulator for ONE method (Role1,
    Role3, or Combined), compared against ground truth."""

    def __init__(self):
        self.tp = self.tn = self.fp = self.fn = 0
        self.family_total   = defaultdict(int)
        self.family_correct = defaultdict(int)

    def add(self, gt_binary: str, pred_binary: str, gt_family: str):
        if gt_binary == "unknown" or pred_binary == "missing":
            return
        gt_attack   = gt_binary == "attack"
        pred_attack = pred_binary == "attack"
        if gt_attack and pred_attack:       self.tp += 1
        elif not gt_attack and not pred_attack: self.tn += 1
        elif not gt_attack and pred_attack: self.fp += 1
        else:                               self.fn += 1

        self.family_total[gt_family] += 1
        if gt_attack == pred_attack:
            self.family_correct[gt_family] += 1

    def metrics(self) -> dict:
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0
        recall    = self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)
        n         = self.tp + self.tn + self.fp + self.fn
        accuracy  = (self.tp + self.tn) / n if n > 0 else 0.0
        fpr       = self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0
        return {
            "accuracy":  round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall":    round(recall * 100, 2),
            "f1_score":  round(f1 * 100, 2),
            "fpr":       round(fpr * 100, 2),
            "tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn,
        }

    def per_family_table(self) -> pd.DataFrame:
        rows = []
        for fam in sorted(self.family_total):
            total = self.family_total[fam]
            correct = self.family_correct[fam]
            rows.append({
                "Family": fam, "Windows": total, "Correct": correct,
                "Accuracy %": round(correct / total * 100, 1) if total else 0.0,
            })
        return pd.DataFrame(rows)


class ThesisEvaluator:
    """
    Accumulates Role1-only, Role3-only, and Combined predictions against
    ground truth across all windows, plus latency/throughput stats, and
    produces the ablation table + full report needed for publication.
    """

    def __init__(self, cfg, dataset_name: Optional[str] = None,
                 bootstrap_resamples: int = 2000, seed: int = 42):
        self.results_dir = cfg.paths.results_dir
        os.makedirs(self.results_dir, exist_ok=True)

        # See config/settings.yaml: config.evaluation.attack_window_threshold.
        # Read once here rather than at each add() call so a report always
        # records the exact threshold it was scored under (see generate_report).
        self.attack_window_threshold = getattr(
            getattr(cfg, "evaluation", None), "attack_window_threshold",
            DEFAULT_ATTACK_WINDOW_THRESHOLD,
        )

        # Which sub-model / capture this run evaluated. Recorded in the report
        # so a three-dataset thesis cannot silently pool results from
        # different schemas into one table.
        self.dataset_name = dataset_name or "unspecified"
        self.bootstrap_resamples = bootstrap_resamples
        self.seed = seed

        self.role1_stats    = _MethodStats()
        self.role3_stats     = _MethodStats()
        self.combined_stats = _MethodStats()

        # Paired per-window outcomes, needed for bootstrap CIs and McNemar.
        # Point estimates alone cannot support "fusion beats either role" at
        # a few hundred windows; the paired vectors are what make a
        # significance test possible.
        self._y_true:     List[int] = []
        self._y_role1:    List[int] = []
        self._y_role3:    List[int] = []
        self._y_combined: List[int] = []
        self._families:   List[str] = []
        self._unmapped_seen: set = set()

        self.role1_latencies: List[float] = []   # seconds, PER-WINDOW batch inference
        self.role1_flow_counts: List[int] = []   # n_flows in the same window, index-aligned
                                                  # with role1_latencies — needed because a
                                                  # single Role1 call classifies ALL flows in
                                                  # a window in one batch, so "per-window" time
                                                  # divided by 1 massively overstates true
                                                  # per-flow cost. Normalise using this instead
                                                  # of quoting the raw per-window latency as if
                                                  # it were per-flow.
        self.llm_latencies:   List[float] = []   # seconds, REAL LLM calls only
        self.n_cache_hits   = 0
        self.n_auto_benign  = 0
        self.n_llm_calls    = 0
        self.n_conflicts    = 0
        self.n_agreements   = 0
        self.n_windows_with_gt = 0
        self.n_windows_total   = 0
        self.n_flows_total     = 0

        self._rows_for_csv = []

    def add_window(
        self,
        chunk,
        r1: Optional[dict],
        r3: Optional[dict],
        alert,
        role1_latency_s: Optional[float] = None,
        is_llm_cache_hit: bool = False,
        is_auto_benign: bool = False,
    ) -> None:
        """
        Call once per processed window (whether or not it has ground
        truth — non-ground-truth windows still count toward throughput
        and conflict/latency stats, just not toward the ablation table).
        """
        self.n_windows_total += 1

        if r1 is not None:
            self.n_flows_total += r1.get("n_flows", 0)
        if role1_latency_s is not None:
            self.role1_latencies.append(role1_latency_s)
            self.role1_flow_counts.append(r1.get("n_flows", 0) if r1 else 0)

        if is_llm_cache_hit:
            self.n_cache_hits += 1
        elif is_auto_benign:
            self.n_auto_benign += 1
        elif r3 is not None and not r3.get("_skipped") and not r3.get("_error"):
            self.n_llm_calls += 1
            llm_s = r3.get("_llm_seconds")
            if llm_s is not None:
                self.llm_latencies.append(llm_s)

        if getattr(alert, "conflict", False):
            self.n_conflicts += 1
        if getattr(alert, "agree", False):
            self.n_agreements += 1

        gt = getattr(chunk, "ground_truth", {}) or {}
        if not gt:
            return   # no ground truth for this window — skip ablation table

        # Surface labels the shared taxonomy does not recognise. An unmapped
        # label is not merely cosmetic: it is not "Benign", so it silently
        # becomes an ATTACK in the binary table.
        for lbl in unmapped_labels(gt.keys()):
            if lbl not in self._unmapped_seen:
                self._unmapped_seen.add(lbl)
                log.warning(
                    "Ground-truth label %r has no entry in "
                    "src/engine/label_map.UNIVERSAL_LABEL_MAP — it will be "
                    "scored as an attack and shown as its own family. Add it "
                    "if that is wrong.", lbl,
                )

        gt_binary = _gt_to_binary(gt, self.attack_window_threshold)
        if gt_binary == "unknown":
            return   # all labels were UNMATCHED/UNKNOWN — no evidence here

        self.n_windows_with_gt += 1
        gt_family = _gt_to_family(gt, self.attack_window_threshold)

        r1_binary = _label_to_binary(r1.get("Predicted_Label")) if r1 else "missing"
        r3_binary = _verdict_to_binary(r3.get("verdict")) if r3 else "missing"
        combined_binary = _verdict_to_binary(getattr(alert, "final_verdict", None))

        self.role1_stats.add(gt_binary, r1_binary, gt_family)
        self.role3_stats.add(gt_binary, r3_binary, gt_family)
        self.combined_stats.add(gt_binary, combined_binary, gt_family)

        # Paired vectors for bootstrap + McNemar. A method that produced no
        # prediction is recorded as 0 (benign) so the three vectors stay
        # index-aligned; _MethodStats already excludes it from the point
        # estimates, and the CSV below records "missing" so the distinction
        # survives into the appendix.
        self._y_true.append(1 if gt_binary == "attack" else 0)
        self._y_role1.append(1 if r1_binary == "attack" else 0)
        self._y_role3.append(1 if r3_binary == "attack" else 0)
        self._y_combined.append(1 if combined_binary == "attack" else 0)
        self._families.append(gt_family)

        # RAW (attack/suspicious/benign) verdicts, kept so scripts/rescore_fusion.py
        # can recompute any fusion mode WITHOUT re-running the LLM. The binary
        # columns above collapse "suspicious", which the re-score needs.
        r1_raw = getattr(alert, "role1_verdict", r1_binary)
        r3_raw = getattr(alert, "role3_verdict", "missing" if r3 is None else "benign")

        self._rows_for_csv.append({
            "dataset": self.dataset_name,
            "window_start": str(chunk.window_start),
            "gt_binary": gt_binary, "gt_family": gt_family,
            "role1_pred": r1_binary, "role3_pred": r3_binary,
            "combined_pred": combined_binary,
            "role1_raw": r1_raw, "role3_raw": r3_raw,
            "severity": getattr(alert, "severity", ""),
            "conflict": getattr(alert, "conflict", False),
        })

    # ── report generation ────────────────────────────────────────────────────

    def _per_flow_latency_ms(self) -> float:
        """
        Honest per-flow latency: total Role1 time / total flows classified,
        NOT the raw per-window latency (which conflates 'time to classify
        one window's worth of flows' with 'time to classify one flow' —
        a window with 667 flows batched in 270ms is 0.40ms/flow, not 270ms).
        """
        total_time  = sum(self.role1_latencies)
        total_flows = sum(self.role1_flow_counts)
        if total_flows == 0:
            return 0.0
        return round(total_time / total_flows * 1000, 4)

    def _assert_evaluable(self) -> None:
        """
        Refuse to emit an ablation table the numbers cannot support.

        Checks, in order of how badly they mislead:
          1. No ground-truth windows at all.
          2. Zero negatives (tn+fp==0) — precision and FPR are then undefined
             and will print as a flattering 100.0 / 0.0. This is exactly the
             failure mode that produced the earlier bogus reports.
          3. Zero positives (tp+fn==0) — recall undefined.
        """
        if self.n_windows_with_gt == 0:
            raise DegenerateEvaluationError(
                "No window carried ground truth, so no ablation table can be "
                "computed.\nAttach real labels first:\n"
                "    python scripts/label_flows.py --flow_csv ... "
                "--cic_labels ... --out ...\n"
                "then point --flow_dir at the labelled directory."
            )

        for name, stats in (
            ("Role1", self.role1_stats),
            ("Role3", self.role3_stats),
            ("Combined", self.combined_stats),
        ):
            n_neg = stats.tn + stats.fp
            n_pos = stats.tp + stats.fn
            if n_neg == 0 and n_pos == 0:
                continue   # method never fired; metrics() already returns zeros
            if n_neg == 0:
                raise DegenerateEvaluationError(
                    f"{name}: the evaluation set contains ZERO benign windows "
                    f"(tn+fp=0, tp+fn={n_pos}).\n"
                    "Precision and FPR are undefined on an all-positive set and "
                    "would print as 100.0% / 0.0% — an arithmetic identity, not "
                    "a measurement.\n"
                    "Most likely cause: ground-truth labels are missing or all "
                    "flows were tagged UNMATCHED, so every window defaulted to "
                    "'attack'. Check the join report written next to your "
                    "labelled CSV (<name>.join_report.json) — the match rate "
                    "and label distribution will show it.\n"
                    "If the capture genuinely has no benign minutes, evaluate "
                    "against a capture that does; a detector cannot be shown to "
                    "have a low false-positive rate on data with no negatives."
                )
            if n_pos == 0:
                raise DegenerateEvaluationError(
                    f"{name}: the evaluation set contains ZERO attack windows "
                    f"(tp+fn=0, tn+fp={n_neg}). Recall is undefined."
                )

    def _bootstrap_block(self) -> dict:
        """Percentile bootstrap CIs for each method's metrics."""
        from src.evaluator.stats import bootstrap_ci

        if not self._y_true:
            return {"note": "no ground-truth windows — no intervals computed"}

        out = {
            "method": "percentile bootstrap over windows",
            "n_resamples": self.bootstrap_resamples,
            "seed": self.seed,
            "n_windows": len(self._y_true),
        }
        for name, preds in (
            ("role1_only", self._y_role1),
            ("role3_only", self._y_role3),
            ("combined",   self._y_combined),
        ):
            out[name] = bootstrap_ci(
                self._y_true, preds,
                n_resamples=self.bootstrap_resamples, seed=self.seed,
            )
        return out

    def _significance_block(self) -> dict:
        """
        Paired McNemar tests. Combined-vs-Role1 is THE test for the thesis's
        central claim; without it, "the combination is better" rests on a
        difference between two point estimates on the same few hundred
        windows, which is not evidence either way.
        """
        from src.evaluator.stats import mcnemar_test

        if not self._y_true:
            return {"note": "no ground-truth windows — no tests computed"}

        return {
            "test": "McNemar (paired, same windows)",
            "combined_vs_role1": mcnemar_test(
                self._y_true, self._y_combined, self._y_role1
            ),
            "combined_vs_role3": mcnemar_test(
                self._y_true, self._y_combined, self._y_role3
            ),
            "role1_vs_role3": mcnemar_test(
                self._y_true, self._y_role1, self._y_role3
            ),
            "interpretation": (
                "'only_a_correct' counts windows the FIRST-named method got "
                "right and the second did not. A significant p with "
                "only_a_correct > only_b_correct supports the first method "
                "being better on this data."
            ),
        }

    def generate_report(self, wall_clock_seconds: Optional[float] = None) -> dict:
        self._assert_evaluable()
        peak_rss_mb, rss_method = _peak_rss_mb()

        def _latency_block(latencies: List[float], unit_name: str) -> dict:
            if not latencies:
                return {"n": 0, "mean_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "max_s": 0.0}
            arr = np.array(latencies)
            return {
                "n": len(arr),
                "mean_s": round(float(arr.mean()), 3),
                "p50_s":  round(float(np.percentile(arr, 50)), 3),
                "p95_s":  round(float(np.percentile(arr, 95)), 3),
                "max_s":  round(float(arr.max()), 3),
            }

        report = {
            "generated_at": datetime.now().isoformat(),
            "attack_window_threshold": self.attack_window_threshold,
            "dataset": self.dataset_name,
            "windows_total": self.n_windows_total,
            "windows_with_ground_truth": self.n_windows_with_gt,
            "flows_total": self.n_flows_total,

            # ── uncertainty + significance ─────────────────────────────────
            # Point estimates alone cannot support the thesis's central claim
            # ("combining the roles beats either alone") at a few hundred
            # windows. The CIs say how precisely each number is known; the
            # McNemar tests say whether the differences between methods are
            # distinguishable from chance on THESE paired samples.
            "uncertainty": self._bootstrap_block(),
            "significance": self._significance_block(),

            # ── ABLATION TABLE — the core thesis result ────────────────────
            "ablation": {
                "role1_only": self.role1_stats.metrics(),
                "role3_only": self.role3_stats.metrics(),
                "combined":   self.combined_stats.metrics(),
            },

            # ── per-family breakdown, one table per method ─────────────────
            "per_family": {
                "role1_only": self.role1_stats.per_family_table().to_dict(orient="records"),
                "role3_only": self.role3_stats.per_family_table().to_dict(orient="records"),
                "combined":   self.combined_stats.per_family_table().to_dict(orient="records"),
            },

            # ── LLM call efficiency ─────────────────────────────────────────
            "llm_efficiency": {
                "llm_calls":       self.n_llm_calls,
                "cache_hits":      self.n_cache_hits,
                "auto_benign":     self.n_auto_benign,
                "total_windows":   self.n_windows_total,
                "llm_call_rate_pct": round(
                    self.n_llm_calls / max(1, self.n_windows_total) * 100, 1
                ),
            },

            # ── latency ─────────────────────────────────────────────────────
            # IMPORTANT: role1_per_window is the time for ONE Role1 call,
            # which classifies ALL flows in that window in a single batch —
            # this is NOT the per-flow cost. role1_per_flow_normalised divides
            # total Role1 time by total flows actually processed, giving the
            # honest per-flow figure (what "microsecond-level inference"
            # claims should be measured against).
            "latency": {
                "role1_per_window":  _latency_block(self.role1_latencies, "window"),
                "role1_per_flow_normalised_ms": self._per_flow_latency_ms(),
                "role3_per_llm_call": _latency_block(self.llm_latencies, "window"),
            },

            # ── agreement / conflict ────────────────────────────────────────
            "agreement": {
                "n_conflicts":   self.n_conflicts,
                "n_agreements":  self.n_agreements,
                "conflict_rate_pct": round(
                    self.n_conflicts / max(1, self.n_windows_total) * 100, 1
                ),
            },

            # ── throughput / resource usage ─────────────────────────────────
            "performance": {
                "wall_clock_seconds": wall_clock_seconds,
                "windows_per_hour": (
                    round(self.n_windows_total / (wall_clock_seconds / 3600), 1)
                    if wall_clock_seconds else None
                ),
                "flows_per_second": (
                    round(self.n_flows_total / wall_clock_seconds, 1)
                    if wall_clock_seconds else None
                ),
                "peak_rss_mb": round(peak_rss_mb, 1),
                "peak_rss_method": rss_method,
            },
        }

        self._print_report(report)
        return report

    def save_report(self, report: dict) -> None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        json_path = os.path.join(self.results_dir, f"thesis_report_{ts}.json")
        with open(json_path, "w") as fh:
            json.dump(report, fh, indent=2)

        csv_path = os.path.join(self.results_dir, f"thesis_per_window_{ts}.csv")
        if self._rows_for_csv:
            pd.DataFrame(self._rows_for_csv).to_csv(csv_path, index=False)

        _p(f"\n  Thesis results saved:")
        _p(f"    Summary (ablation, latency, etc): {json_path}")
        if self._rows_for_csv:
            _p(f"    Per-window detail (for appendix): {csv_path}")

    @staticmethod
    def _print_report(report: dict) -> None:
        _p("\n" + "═" * 72)
        _p("  THESIS EVALUATION REPORT")
        _p("═" * 72)
        _p(
            f"  Windows: {report['windows_total']}  "
            f"(with ground truth: {report['windows_with_ground_truth']})   "
            f"Flows: {report['flows_total']:,}"
        )

        _p(f"  Dataset: {report.get('dataset', 'unspecified')}")

        _p("\n  ── ABLATION TABLE (vs ground truth) ──────────────────────")
        _p(f"  {'Method':<14}{'Acc':>8}{'Prec':>8}{'Recall':>8}{'F1':>8}{'FPR':>8}")
        for name, key in [("Role1 only", "role1_only"),
                           ("Role3 only", "role3_only"),
                           ("Combined",   "combined")]:
            m = report["ablation"][key]
            _p(
                f"  {name:<14}{m['accuracy']:>7.1f}%{m['precision']:>7.1f}%"
                f"{m['recall']:>7.1f}%{m['f1_score']:>7.1f}%{m['fpr']:>7.1f}%"
            )
            _p(f"  {'':<14}"
                  f"(tp={m['tp']} tn={m['tn']} fp={m['fp']} fn={m['fn']})")

        unc = report.get("uncertainty", {})
        if "role1_only" in unc:
            _p(f"\n  ── 95% CONFIDENCE INTERVALS "
                  f"({unc['n_resamples']} bootstrap resamples, "
                  f"n={unc['n_windows']} windows, seed={unc['seed']}) ──")
            from src.evaluator.stats import format_ci
            for name, key in [("Role1 only", "role1_only"),
                               ("Role3 only", "role3_only"),
                               ("Combined",   "combined")]:
                b = unc.get(key, {})
                _p(f"    {name:<12} F1 {format_ci(b.get('f1_score'))}")
                _p(f"    {'':<12} Rec {format_ci(b.get('recall'))}   "
                      f"FPR {format_ci(b.get('fpr'))}")

        sig = report.get("significance", {})
        if "combined_vs_role1" in sig:
            _p("\n  ── McNEMAR (paired, same windows) ─────────────────────")
            for label, key in [("Combined vs Role1", "combined_vs_role1"),
                                ("Combined vs Role3", "combined_vs_role3"),
                                ("Role1    vs Role3", "role1_vs_role3")]:
                t = sig[key]
                verdict = "SIGNIFICANT" if t["significant_at_0.05"] else "n.s."
                _p(f"    {label}: p={t['p_value']:.4g}  [{verdict}]  "
                      f"(only-first={t['only_a_correct']}, "
                      f"only-second={t['only_b_correct']}, {t['method']})")

        eff = report["llm_efficiency"]
        _p(f"\n  LLM calls: {eff['llm_calls']}  |  Cache hits: {eff['cache_hits']}  "
              f"|  Auto-benign: {eff['auto_benign']}  |  Call rate: {eff['llm_call_rate_pct']}%")

        lat = report["latency"]
        _p(
            f"  Role1 latency  per-window (mean/p95): "
            f"{lat['role1_per_window']['mean_s']*1000:.1f}ms / {lat['role1_per_window']['p95_s']*1000:.1f}ms"
        )
        _p(f"  Role1 latency  per-flow (normalised): {lat['role1_per_flow_normalised_ms']:.3f}ms")
        _p(
            f"  Role3 LLM latency (mean/p95): "
            f"{lat['role3_per_llm_call']['mean_s']:.1f}s / {lat['role3_per_llm_call']['p95_s']:.1f}s"
        )

        agr = report["agreement"]
        _p(f"\n  Conflicts: {agr['n_conflicts']} ({agr['conflict_rate_pct']}%)  "
              f"|  Agreements: {agr['n_agreements']}")

        perf = report["performance"]
        if perf["wall_clock_seconds"]:
            _p(
                f"\n  Wall clock: {perf['wall_clock_seconds']/60:.1f} min  "
                f"|  Throughput: {perf['windows_per_hour']} windows/hr, "
                f"{perf['flows_per_second']} flows/s  "
                f"|  Peak RSS: {perf['peak_rss_mb']:.0f} MB"
            )
        _p("═" * 72 + "\n")
