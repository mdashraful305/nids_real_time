#!/usr/bin/env python3
"""
scripts/plot_severity_distribution.py
======================================
Figure 5.3 — distribution of final severity levels across the evaluated
windows. No new experiment: reads the same unified_alerts.jsonl the fusion
tables were built from and plots how many windows the decision engine assigned
each severity (NONE / LOW / MEDIUM / HIGH).

Pass one or more alert logs (e.g. Wednesday + Friday) to pool them, matching
the Wed+Fri pooling used for the T3 fusion table.

USAGE
-----
python scripts/plot_severity_distribution.py \
    --alerts data/results/alerts_wednesday.jsonl data/results/alerts_friday.jsonl \
    --out data/results/severity_distribution_chart.png
"""

import os
import sys
import json
import glob
import argparse
from collections import Counter


SEV_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH"]
# colour-blind-safe, prints legibly in greyscale too (light -> dark = low -> high)
SEV_COLOR = {"NONE": "#9ecae1", "LOW": "#6baed6",
             "MEDIUM": "#fd8d3c", "HIGH": "#d7301f"}

# Decision-engine conflict-resolution matrix (severity), copied here so the
# plot is self-contained and does not depend on a possibly-stale decision
# engine on the runtime. Keys: (role1_verdict, role3_verdict).
_RESOLUTION = {
    ("attack", "attack"): "HIGH", ("attack", "suspicious"): "HIGH",
    ("attack", "benign"): "MEDIUM", ("attack", "missing"): "HIGH",
    ("suspicious", "attack"): "MEDIUM", ("suspicious", "suspicious"): "MEDIUM",
    ("suspicious", "benign"): "LOW", ("suspicious", "missing"): "LOW",
    ("benign", "attack"): "MEDIUM", ("benign", "suspicious"): "LOW",
    ("benign", "benign"): "NONE", ("benign", "missing"): "NONE",
    ("missing", "attack"): "MEDIUM", ("missing", "suspicious"): "LOW",
    ("missing", "benign"): "NONE", ("missing", "missing"): "NONE",
}


def _recompute_severity(r1_pred, r3_raw):
    """Correct severity from the CORRECT role1_pred + raw role3 verdict, via the
    decision-engine matrix. Bypasses the stored `severity`, which is poisoned
    when the runtime's decision_engine.py lacks the 'Benign' label fix (every
    benign window then reads as a Role-1 attack -> HIGH)."""
    r1 = str(r1_pred).strip().lower()
    r3 = str(r3_raw).strip().lower()
    if r1 not in ("attack", "suspicious", "benign", "missing"):
        r1 = "benign"
    if r3 not in ("attack", "suspicious", "benign", "missing"):
        r3 = "benign"
    return _RESOLUTION.get((r1, r3), "NONE")


def parse_args():
    p = argparse.ArgumentParser(description="Plot severity distribution (Fig 5.3).")
    p.add_argument("--alerts", nargs="+", required=True,
                   help="One or more inputs (globs allowed). Accepts EITHER "
                        "unified_alerts.jsonl files OR the per-window "
                        "thesis_per_window / pw_*.csv files — both carry a "
                        "'severity' column/field.")
    p.add_argument("--out", default="data/results/severity_distribution_chart.png")
    p.add_argument("--title", default=None,
                   help="Override the chart title.")
    p.add_argument("--percent", action="store_true",
                   help="Label bars with percentages instead of counts.")
    p.add_argument("--recompute", action="store_true",
                   help="Ignore the stored 'severity' column and recompute it "
                        "from role1_pred + role3_raw via the decision-engine "
                        "matrix. Use this when the stored severity is ~all HIGH "
                        "(stale decision_engine.py 'Benign' bug). CSV inputs "
                        "only.")
    return p.parse_args()


def load(paths, recompute=False):
    """Return a list of severity strings from either .jsonl alert logs or the
    per-window .csv files. With recompute=True, derive severity from the
    correct role1_pred + role3_raw columns instead of the stored value."""
    files = []
    for pat in paths:
        files.extend(sorted(glob.glob(pat)))
    files = [f for f in files if os.path.exists(f)]
    sevs = []
    for f in files:
        if f.lower().endswith(".csv"):
            import pandas as pd
            df = pd.read_csv(f)
            cols = {c.strip().lower(): c for c in df.columns}
            if recompute:
                need = {"role1_pred", "role3_raw"}
                if not need.issubset(cols):
                    print(f"    ! {os.path.basename(f)} lacks {need - set(cols)} "
                          f"— cannot recompute; skipped")
                    continue
                sevs.extend(_recompute_severity(r1, r3) for r1, r3 in
                            zip(df[cols["role1_pred"]], df[cols["role3_raw"]]))
            elif "severity" in cols:
                sevs.extend(df[cols["severity"]].astype(str).tolist())
            else:
                print(f"    ! no 'severity' column in {os.path.basename(f)} — skipped")
        else:
            with open(f, errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        sevs.append(str(json.loads(line).get("severity", "NONE")))
                    except Exception:
                        continue
    return sevs, files


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    sevs, files = load(args.alerts, recompute=args.recompute)
    if not sevs:
        print("  XX no severity values loaded — check the --alerts paths"); return 1

    counts = Counter(str(s).strip().upper() for s in sevs)
    # keep only known levels; anything unexpected is folded into NONE
    ordered = {s: counts.get(s, 0) for s in SEV_ORDER}
    total = sum(ordered.values())

    print(f"  loaded {total:,} windows from {len(files)} file(s)")
    for s in SEV_ORDER:
        n = ordered[s]
        print(f"    {s:<7} {n:>6,}  ({n/total*100:5.1f}%)")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(6, 4))
    xs = SEV_ORDER
    ys = [ordered[s] for s in xs]
    bars = ax.bar(xs, ys, color=[SEV_COLOR[s] for s in xs],
                  edgecolor="black", linewidth=0.6)

    for b, s in zip(bars, xs):
        n = ordered[s]
        label = f"{n/total*100:.1f}%" if args.percent else f"{n:,}"
        ax.text(b.get_x() + b.get_width() / 2, b.get_height(),
                label, ha="center", va="bottom", fontsize=10)

    ax.set_xlabel("Final severity level")
    ax.set_ylabel("Number of windows")
    ax.set_title(args.title or
                 "Final severity distribution ")
    ax.set_ylim(0, max(ys) * 1.15 if ys else 1)
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    fig.savefig(args.out, dpi=200)
    # also emit the underlying numbers so the caption/text can cite them exactly
    js = os.path.splitext(args.out)[0] + ".json"
    json.dump({"total": total, "counts": ordered,
               "percent": {s: round(ordered[s]/total*100, 1) for s in SEV_ORDER},
               "files": files}, open(js, "w"), indent=2)
    print(f"\n  ✓ figure: {args.out}")
    print(f"  ✓ numbers: {js}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
