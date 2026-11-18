#!/usr/bin/env python3
"""
scripts/compare_llm_models.py
=============================
Build the "does a bigger LLM help?" table: qwen2.5:1.5b vs qwen2.5:7b (or any
two models), comparing BOTH detection quality and runtime. This substantiates
the claim that the small model is sufficient — a useful negative result.

WHAT YOU RUN FIRST
------------------
The same Track B day twice, once per model, keeping each report:

    # 1.5b
    export NIDS_FUSION_MODE=role1_gated
    ollama pull qwen2.5:1.5b
    #   set ollama.model: qwen2.5:1.5b  in config/settings.yaml
    python main_unified.py --mode offline --nids_pkl ... \
        --eve_dir /content/eve_friday/ --flow_dir data/flow_friday/ \
        --dataset CICIDS2017 --workers 4 --db_dir /content/c1
    cp $(ls -t data/results/thesis_report_*.json | head -1) data/results/report_1.5b.json

    # 7b  (edit config ollama.model: qwen2.5:7b, then)
    ollama pull qwen2.5:7b
    python main_unified.py --mode offline ...  --db_dir /content/c2
    cp $(ls -t data/results/thesis_report_*.json | head -1) data/results/report_7b.json

THEN
----
    python scripts/compare_llm_models.py \
        --a data/results/report_1.5b.json --a_name "qwen2.5:1.5b" \
        --b data/results/report_7b.json   --b_name "qwen2.5:7b" \
        --out data/results/llm_model_compare.json

It reads Role3-only detection metrics and the Role3 LLM latency from each
report and prints the comparison. (Role 1 is identical across the two runs —
only the LLM changed — so any Role3 / latency difference is the model effect.)
"""

import os
import sys
import json
import argparse


def parse_args():
    p = argparse.ArgumentParser(description="Compare two LLM models' Track B runs.")
    p.add_argument("--a", required=True, help="thesis_report_*.json for model A.")
    p.add_argument("--b", required=True, help="thesis_report_*.json for model B.")
    p.add_argument("--a_name", default="model_A")
    p.add_argument("--b_name", default="model_B")
    p.add_argument("--out", default=None)
    return p.parse_args()


def load(path):
    with open(path, errors="replace") as fh:
        return json.load(fh)


def pull(rep):
    """Extract the Role3 detection + LLM latency numbers from a thesis report."""
    abl = rep.get("ablation", {})
    r3 = abl.get("role3_only", {})
    comb = abl.get("combined", {})
    lat = rep.get("latency", {}).get("role3_per_llm_call", {})
    eff = rep.get("llm_efficiency", {})
    return {
        "role3_precision": r3.get("precision"),
        "role3_recall": r3.get("recall"),
        "role3_f1": r3.get("f1_score"),
        "role3_fpr": r3.get("fpr"),
        "combined_f1": comb.get("f1_score"),
        "combined_fpr": comb.get("fpr"),
        "llm_mean_s": lat.get("mean_s"),
        "llm_p95_s": lat.get("p95_s"),
        "llm_calls": eff.get("llm_calls"),
        "windows": rep.get("windows_total"),
        "wall_min": round(rep.get("performance", {}).get("wall_clock_seconds", 0)
                          / 60, 1) if rep.get("performance") else None,
    }


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    A, B = pull(load(args.a)), pull(load(args.b))
    na, nb = args.a_name, args.b_name

    print("=" * 74)
    print("  LLM MODEL COMPARISON  (same Track B day, only the LLM changed)")
    print("=" * 74)

    def row(label, key, fmt="{}", suffix=""):
        va = A.get(key); vb = B.get(key)
        sa = fmt.format(va) if va is not None else "n/a"
        sb = fmt.format(vb) if vb is not None else "n/a"
        print(f"  {label:<28}{sa+suffix:>18}{sb+suffix:>18}")

    print(f"  {'metric':<28}{na:>18}{nb:>18}")
    print("  " + "-" * 64)
    print("  -- Role 3 (LLM) detection --")
    row("Precision", "role3_precision", "{:.1f}", "%")
    row("Recall", "role3_recall", "{:.1f}", "%")
    row("F1", "role3_f1", "{:.1f}", "%")
    row("FPR", "role3_fpr", "{:.1f}", "%")
    print("  -- Combined (role gated) --")
    row("Combined F1", "combined_f1", "{:.1f}", "%")
    row("Combined FPR", "combined_fpr", "{:.1f}", "%")
    print("  -- Runtime --")
    row("LLM latency mean", "llm_mean_s", "{:.1f}", "s")
    row("LLM latency p95", "llm_p95_s", "{:.1f}", "s")
    row("LLM calls", "llm_calls", "{}")
    row("Wall clock", "wall_min", "{}", " min")

    # headline: accuracy delta vs runtime cost
    if A.get("role3_f1") is not None and B.get("role3_f1") is not None:
        d_f1 = B["role3_f1"] - A["role3_f1"]
        print(f"\n  Role3 F1 change {na} -> {nb}: {d_f1:+.1f} points")
    if A.get("llm_mean_s") and B.get("llm_mean_s"):
        ratio = B["llm_mean_s"] / A["llm_mean_s"]
        print(f"  LLM latency cost {nb} vs {na}: {ratio:.2f}x")
        print("\n  Reading: if the F1 change is small but the latency ratio is")
        print("  large, the small model is the right operational choice — the")
        print("  bigger model costs more for negligible detection gain.")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".",
                    exist_ok=True)
        json.dump({na: A, nb: B}, open(args.out, "w"), indent=2)
        print(f"\n  saved: {args.out}")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
