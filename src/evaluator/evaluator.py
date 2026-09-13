"""
src/evaluator/evaluator.py
===========================
Compare LLM verdicts against CICIDS2017 ground truth labels and generate
a full evaluation report with precision, recall, F1, confusion matrix,
and per-attack-type breakdown.

Usage
-----
evaluator = Evaluator(cfg)
evaluator.add_result(chunk, verdict)        # call for each chunk
report    = evaluator.generate_report()     # call at the end
evaluator.save_report("data/results/")
"""

import os
import json
import csv
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict

import pandas as pd
import numpy as np

from src.utils.logger import get_logger

log = get_logger(__name__)

# CICIDS2017 label → binary (attack or benign)
BENIGN_LABELS = {"BENIGN", "benign", "normal", "Normal"}

# Map CICIDS2017 multi-class labels to coarse attack family
LABEL_TO_FAMILY = {
    "BENIGN":                     "Normal",
    "DoS Hulk":                   "DoS",
    "DoS GoldenEye":              "DoS",
    "DoS slowloris":              "DoS",
    "DoS Slowhttptest":           "DoS",
    "DDoS":                       "DDoS",
    "PortScan":                   "PortScan",
    "FTP-Patator":                "Brute Force",
    "SSH-Patator":                "Brute Force",
    "Web Attack – Brute Force":   "Web Attack Brute Force",
    "Web Attack – XSS":           "Web Attack XSS",
    "Web Attack – Sql Injection": "Web Attack SQL Injection",
    "Bot":                        "Bot",
    "Infiltration":               "Infiltration",
    "Heartbleed":                 "Heartbleed",
}


def _gt_to_binary(gt: Dict[str, int]) -> str:
    """
    Convert a ground_truth dict (label→count) to 'attack' or 'benign'.
    If the majority of flows in the window are attacks → 'attack'.
    """
    if not gt:
        return "unknown"
    total   = sum(gt.values())
    benign  = sum(cnt for lbl, cnt in gt.items() if lbl in BENIGN_LABELS)
    attacks = total - benign
    return "benign" if benign >= attacks else "attack"


def _gt_to_family(gt: Dict[str, int]) -> str:
    """Return the dominant attack family in a window's ground truth."""
    if not gt:
        return "Unknown"
    attack_counts = {
        LABEL_TO_FAMILY.get(lbl, lbl): cnt
        for lbl, cnt in gt.items()
        if lbl not in BENIGN_LABELS
    }
    if not attack_counts:
        return "Normal"
    return max(attack_counts, key=attack_counts.get)


class ChunkResult:
    """Result for one analysed chunk."""
    __slots__ = [
        "chunk_index", "window_start", "window_end",
        "ground_truth", "gt_binary", "gt_family",
        "llm_verdict", "llm_attack_type", "llm_confidence",
        "llm_explanation", "llm_indicators", "llm_action",
        "llm_seconds", "correct",
    ]

    def __init__(self, chunk, verdict: dict):
        from src.chunker.log_chunker import WindowChunk
        self.chunk_index   = chunk.chunk_index
        self.window_start  = chunk.window_start
        self.window_end    = chunk.window_end
        self.ground_truth  = chunk.ground_truth
        self.gt_binary     = _gt_to_binary(chunk.ground_truth)
        self.gt_family     = _gt_to_family(chunk.ground_truth)

        self.llm_verdict      = verdict.get("verdict",            "error")
        self.llm_attack_type  = verdict.get("attack_type",        "Unknown")
        self.llm_confidence   = verdict.get("confidence",         0)
        self.llm_explanation  = verdict.get("explanation",        "")
        self.llm_indicators   = verdict.get("key_indicators",     [])
        self.llm_action       = verdict.get("recommended_action", "")
        self.llm_seconds      = verdict.get("_llm_seconds",       0)

        # Binary correctness: LLM said attack/suspicious when GT is attack,
        # or LLM said benign when GT is benign
        llm_bin = "attack" if self.llm_verdict in ("attack", "suspicious") else "benign"
        self.correct = (llm_bin == self.gt_binary) if self.gt_binary != "unknown" else None

    def to_dict(self) -> dict:
        return {
            "chunk_index":      self.chunk_index,
            "window_start":     str(self.window_start),
            "window_end":       str(self.window_end),
            "gt_binary":        self.gt_binary,
            "gt_family":        self.gt_family,
            "gt_labels":        json.dumps(self.ground_truth),
            "llm_verdict":      self.llm_verdict,
            "llm_attack_type":  self.llm_attack_type,
            "llm_confidence":   self.llm_confidence,
            "llm_explanation":  self.llm_explanation,
            "llm_indicators":   ", ".join(self.llm_indicators),
            "llm_action":       self.llm_action,
            "llm_seconds":      self.llm_seconds,
            "correct":          self.correct,
        }


class Evaluator:
    """
    Collects ChunkResults and produces a comprehensive evaluation report.

    Parameters
    ----------
    cfg : Config object from config_loader.load_config()
    """

    def __init__(self, cfg):
        self.results: List[ChunkResult] = []
        self.attack_verdicts = set(getattr(cfg.evaluation, "attack_verdicts",
                                           ["attack", "suspicious"]))
        self.benign_verdicts = set(getattr(cfg.evaluation, "benign_verdicts",
                                           ["benign"]))
        self.results_dir = cfg.paths.results_dir
        os.makedirs(self.results_dir, exist_ok=True)

    def add_result(self, chunk, verdict: dict) -> ChunkResult:
        """Add one chunk's verdict. Returns the ChunkResult for immediate use."""
        result = ChunkResult(chunk, verdict)
        self.results.append(result)
        return result

    def generate_report(self) -> dict:
        """
        Compute all metrics and return a report dict.
        Also prints a formatted summary to the console.
        """
        if not self.results:
            log.warning("No results to evaluate.")
            return {}

        evaluated = [r for r in self.results if r.gt_binary != "unknown"]
        total      = len(self.results)
        n_eval     = len(evaluated)
        n_errors   = sum(1 for r in self.results if r.llm_verdict == "error")

        # ── binary metrics ────────────────────────────────────────────────────
        y_true, y_pred = [], []
        for r in evaluated:
            y_true.append(1 if r.gt_binary == "attack" else 0)
            y_pred.append(1 if r.llm_verdict in self.attack_verdicts else 0)

        y_true = np.array(y_true)
        y_pred = np.array(y_pred)

        tp = int(((y_true == 1) & (y_pred == 1)).sum())
        tn = int(((y_true == 0) & (y_pred == 0)).sum())
        fp = int(((y_true == 0) & (y_pred == 1)).sum())
        fn = int(((y_true == 1) & (y_pred == 0)).sum())

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)
        accuracy  = (tp + tn) / n_eval if n_eval > 0 else 0.0
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # ── per-family breakdown ──────────────────────────────────────────────
        family_stats: Dict[str, dict] = defaultdict(lambda: {"total": 0, "correct": 0})
        for r in evaluated:
            family_stats[r.gt_family]["total"]   += 1
            family_stats[r.gt_family]["correct"] += int(r.correct or 0)

        family_df = pd.DataFrame([
            {
                "Attack Family": family,
                "Total Windows": d["total"],
                "Correct":       d["correct"],
                "Accuracy %":    round(d["correct"] / d["total"] * 100, 1) if d["total"] else 0,
            }
            for family, d in sorted(family_stats.items())
        ])

        # ── timing ────────────────────────────────────────────────────────────
        llm_times  = [r.llm_seconds for r in self.results if r.llm_seconds > 0]
        avg_time   = float(np.mean(llm_times)) if llm_times else 0.0
        total_time = float(np.sum(llm_times))

        # ── confidence calibration ───────────────────────────────────────────
        correct_conf   = [r.llm_confidence for r in evaluated if r.correct]
        incorrect_conf = [r.llm_confidence for r in evaluated if r.correct is False]
        avg_conf_correct   = float(np.mean(correct_conf))   if correct_conf   else 0.0
        avg_conf_incorrect = float(np.mean(incorrect_conf)) if incorrect_conf else 0.0

        report = {
            "generated_at":        datetime.now().isoformat(),
            "total_chunks":        total,
            "evaluated_chunks":    n_eval,
            "error_chunks":        n_errors,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "accuracy":            round(accuracy  * 100, 2),
            "precision":           round(precision * 100, 2),
            "recall":              round(recall    * 100, 2),
            "f1_score":            round(f1        * 100, 2),
            "false_positive_rate": round(fpr       * 100, 2),
            "avg_llm_seconds":     round(avg_time,  2),
            "total_llm_seconds":   round(total_time, 2),
            "avg_confidence_correct":   round(avg_conf_correct,   1),
            "avg_confidence_incorrect": round(avg_conf_incorrect, 1),
            "per_family": family_df.to_dict(orient="records"),
        }

        self._print_report(report, family_df)
        return report

    def save_report(self, report: dict) -> None:
        """Save full results CSV + summary JSON to results_dir."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Full per-chunk CSV
        csv_path = os.path.join(self.results_dir, f"evaluation_report_{ts}.csv")
        rows = [r.to_dict() for r in self.results]
        pd.DataFrame(rows).to_csv(csv_path, index=False)
        log.info("Per-chunk results → %s", csv_path)

        # Summary JSON
        json_path = os.path.join(self.results_dir, f"summary_{ts}.json")
        with open(json_path, "w") as fh:
            json.dump(report, fh, indent=2)
        log.info("Summary report    → %s", json_path)

        print(f"\n  Results saved:")
        print(f"    CSV  : {csv_path}")
        print(f"    JSON : {json_path}")

    # ── internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _print_report(report: dict, family_df: pd.DataFrame) -> None:
        sep = "═" * 60
        print(f"\n{sep}")
        print("  LLM ANALYST EVALUATION REPORT")
        print(sep)
        print(f"  Chunks analysed : {report['evaluated_chunks']:>5}  "
              f"(errors: {report['error_chunks']})")
        print(f"  Accuracy        : {report['accuracy']:>6.2f} %")
        print(f"  Precision       : {report['precision']:>6.2f} %")
        print(f"  Recall          : {report['recall']:>6.2f} %")
        print(f"  F1 score        : {report['f1_score']:>6.2f} %")
        print(f"  False pos rate  : {report['false_positive_rate']:>6.2f} %")
        print(f"  Avg LLM time    : {report['avg_llm_seconds']:>5.1f} s / chunk")
        print(f"  Confidence ✓    : {report['avg_confidence_correct']:>5.1f}   "
              f"Confidence ✗ : {report['avg_confidence_incorrect']:.1f}")
        print(f"  TP={report['tp']}  TN={report['tn']}  "
              f"FP={report['fp']}  FN={report['fn']}")
        print(f"\n  Per-attack-family accuracy:")
        print(f"  {'Attack Family':<30} {'Windows':>8} {'Correct':>8} {'Accuracy':>10}")
        print("  " + "-" * 58)
        for _, row in family_df.iterrows():
            print(
                f"  {row['Attack Family']:<30} "
                f"{row['Total Windows']:>8} "
                f"{row['Correct']:>8} "
                f"{row['Accuracy %']:>9.1f}%"
            )
        print(sep + "\n")
