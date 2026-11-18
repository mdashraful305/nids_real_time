#!/usr/bin/env python3
"""
scripts/audit_llm_model_compare.py
==================================
Reconciles window-level Role 3 verdict distributions (attack / suspicious /
benign) for Track B Friday replay across qwen2.5:1.5b (pw_friday.csv) and
qwen2.5:7b (thesis_per_window_20261115_082651.csv), verifying llm_model_compare.json.

Writes:
  - <results_dir>/llm_model_audit_friday.json
"""

import os
import json
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NIDS_ROLE3_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(NIDS_ROLE3_DIR, "data", "results")


def audit_df(df):
    raw_counts = df["role3_raw"].value_counts(dropna=False).to_dict()
    ct = pd.crosstab(df["gt_binary"], df["role3_raw"], dropna=False)
    gt_breakdown = {
        str(gt): {str(col): int(ct.loc[gt, col]) for col in ct.columns}
        for gt in ct.index
    }
    return {
        "windows": int(len(df)),
        "role3_raw_counts": {str(k): int(v) for k, v in raw_counts.items()},
        "gt_vs_role3_raw": gt_breakdown,
    }


def main():
    df_15b = pd.read_csv(os.path.join(RESULTS_DIR, "pw_friday.csv"))
    df_7b = pd.read_csv(os.path.join(RESULTS_DIR, "thesis_per_window_20261115_082651.csv"))
    cmp_meta = json.load(open(os.path.join(RESULTS_DIR, "llm_model_compare.json"), encoding="utf-8"))

    out = {
        "qwen2.5:1.5b": {
            "source_csv": "pw_friday.csv",
            "metrics": cmp_meta.get("qwen2.5:1.5b", {}),
            **audit_df(df_15b),
        },
        "qwen2.5:7b": {
            "source_csv": "thesis_per_window_20261115_082651.csv",
            "metrics": cmp_meta.get("qwen2.5:7b", {}),
            **audit_df(df_7b),
        },
    }
    out_path = os.path.join(RESULTS_DIR, "llm_model_audit_friday.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"Saved {out_path}")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
