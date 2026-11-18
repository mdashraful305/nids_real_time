#!/usr/bin/env python3
"""
scripts/case_study.py
=====================
Pull one (or a few) fully-worked alert(s) from a Track B run for the
qualitative case-study section (thesis 5.9): the SHAP features that drove the
ML verdict, the LLM's explanation, the merged SOC narrative, the recommended
action, and the ground-truth label of that window.

WHY
---
The quantitative tables show THAT the system works; the case study shows HOW a
single alert is produced and why it is trustworthy — the concrete evidence for
the "explainable" claim. This extracts a real one from unified_alerts.jsonl so
you are not paraphrasing from memory.

By default it picks the highest-confidence HIGH-severity attack alert that has
BOTH a SHAP feature list and a non-empty LLM explanation (the most complete
example). Use --attack_type to target a specific family, or --n for several.

USAGE
-----
    python scripts/case_study.py \
        --alerts data/results/alerts_friday.jsonl \
        --n 1 --out data/results/case_study.md
"""

import os
import sys
import json
import argparse


def parse_args():
    p = argparse.ArgumentParser(description="Extract worked case-study alerts.")
    p.add_argument("--alerts", required=True, help="A unified_alerts.jsonl.")
    p.add_argument("--n", type=int, default=1, help="How many to extract.")
    p.add_argument("--severity", default="HIGH",
                   help="Minimum severity to consider (default HIGH).")
    p.add_argument("--attack_type", default=None,
                   help="Only this attack family, e.g. DoS / PortScan / DDoS.")
    p.add_argument("--out", default=None, help="Write a Markdown block here.")
    return p.parse_args()


SEV_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def load(path):
    rows = []
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def score(a):
    """Completeness score: prefer alerts that have every explanation field."""
    s = 0
    if a.get("shap_top_features"):
        s += 2
    if (a.get("role3_explanation") or a.get("llm_explanation")):
        s += 2
    if a.get("soc_explanation"):
        s += 1
    if a.get("recommended_action"):
        s += 1
    s += float(a.get("confidence", 0)) / 100.0
    return s


def fmt(a, i):
    L = []
    L.append(f"### Case {i}: {a.get('attack_type', '?')}  "
             f"({a.get('severity', '?')})")
    L.append("")
    L.append(f"- **Timestamp**: {a.get('timestamp', '?')}")
    L.append(f"- **Final verdict**: {a.get('final_verdict', '?')}  "
             f"(confidence {a.get('confidence', '?')}%)")
    L.append(f"- **Role 1 (ML)**: {a.get('role1_verdict', '?')} → "
             f"{a.get('role1_attack_type', '?')}  "
             f"(conf {a.get('role1_confidence', '?')}%)")
    L.append(f"- **Role 3 (LLM)**: {a.get('role3_verdict', '?')} → "
             f"{a.get('role3_attack_type', '?')}  "
             f"(conf {a.get('role3_confidence', '?')}%)")
    if a.get("conflict"):
        L.append(f"- **Conflict**: roles disagreed")
    L.append("")
    shap = a.get("shap_top_features") or []
    if shap:
        L.append("**Role 2 — top SHAP features driving the ML verdict:**")
        for f in shap[:8]:
            if isinstance(f, (list, tuple)) and len(f) == 2:
                L.append(f"  - `{f[0]}` = {f[1]}")
            else:
                L.append(f"  - `{f}`")
        L.append("")
    expl = a.get("role3_explanation") or a.get("llm_explanation")
    if expl:
        L.append("**Role 3 — LLM explanation:**")
        L.append(f"> {expl.strip()}")
        L.append("")
    ki = a.get("key_indicators") or []
    if ki:
        L.append("**Key indicators (LLM):** " + ", ".join(str(k) for k in ki))
        L.append("")
    if a.get("soc_explanation"):
        L.append("**Merged SOC explanation:**")
        L.append(f"> {a['soc_explanation'].strip()}")
        L.append("")
    if a.get("recommended_action"):
        L.append(f"**Recommended action:** {a['recommended_action'].strip()}")
        L.append("")
    return "\n".join(L)


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    rows = load(args.alerts)
    print(f"  loaded {len(rows):,} alerts from {args.alerts}")

    min_sev = SEV_ORDER.get(args.severity.upper(), 3)
    cand = [a for a in rows
            if SEV_ORDER.get(str(a.get("severity", "NONE")).upper(), 0) >= min_sev
            and str(a.get("final_verdict", "")).lower() in ("attack", "suspicious")]
    if args.attack_type:
        cand = [a for a in cand
                if str(a.get("attack_type", "")).lower()
                == args.attack_type.lower()]

    if not cand:
        print("  XX no alert matched. Loosen --severity or drop --attack_type.")
        print("     Severities present:",
              sorted({a.get("severity") for a in rows}))
        print("     Attack types present:",
              sorted({a.get("attack_type") for a in rows}))
        return 1

    cand.sort(key=score, reverse=True)
    picked = cand[:args.n]

    blocks = [fmt(a, i + 1) for i, a in enumerate(picked)]
    text = "\n---\n\n".join(blocks)
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)

    # warn if the best pick still lacks explanation fields (LLM was off, etc.)
    top = picked[0]
    if not (top.get("shap_top_features") and
            (top.get("role3_explanation") or top.get("llm_explanation"))):
        print("\n  !  The best available alert is missing SHAP and/or LLM text.")
        print("     If SHAP is empty, Role 2 was not active in that run; if the")
        print("     LLM text is empty, Ollama was gated/skipped for that window.")
        print("     Re-run one day with Ollama up and SHAP enabled for a fully")
        print("     worked example.")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".",
                    exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write("# Qualitative case study (thesis 5.9)\n\n")
            fh.write(text + "\n")
        print(f"\n  saved: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
