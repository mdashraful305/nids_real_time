#!/usr/bin/env python3
"""
scripts/detection_summary.py
=============================
Build a role x attack-type summary table from the two files nids_web.py
already produces:

  nids_history.json    — raw per-flow record, Role 1 (ML) run on EVERY flow,
                          Role 3 (LLM) run on EVERY flow, side by side, for
                          comparing the two roles directly.
  unified_alerts.jsonl  — post-fusion alert stream (one JSON object per line):
                          the single verdict actually surfaced after combining
                          Role 1 + Role 3 (+ suppression/severity logic).

These two files answer different questions, so this script keeps them
separate rather than merging rows:
  - nids_history.json  -> "when R1 and R3 both looked at the same flow, what
                           did each say, and how often did they agree?"
  - unified_alerts.jsonl -> "what did the system actually alert on, by
                           attack type and severity, after fusion/suppression?"

USAGE
-----
    python scripts/detection_summary.py \
        --history nids_history.json \
        --alerts  unified_alerts.jsonl

    # see the raw field names each record contributed (debug field mapping)
    python scripts/detection_summary.py --inspect

    # write the computed summary as JSON too
    python scripts/detection_summary.py --out data/results/detection_summary.json
"""

import os
import sys
import json
import argparse
from collections import defaultdict


BENIGN_LABELS = {"benign", "normal", "none", ""}
# role1_verdict == "unknown" with confidence 0.0 in unified_alerts.jsonl means
# Role 1 did not run on that alert at all (e.g. a log-only Role 3 verdict) —
# NOT a genuine "Role 1 said unknown" classification. Counting it as a real
# label would silently pollute the Role 1 attack-type breakdown.
NO_ROLE1_DATA = {("unknown", 0.0), ("unknown", 0), (None, None)}


def parse_args():
    p = argparse.ArgumentParser(description="Role x attack-type detection summary.")
    p.add_argument("--history", default="nids_history.json")
    p.add_argument("--alerts", default="unified_alerts.jsonl")
    p.add_argument("--out", default=None, help="Optional path to also save JSON summary.")
    p.add_argument("--inspect", action="store_true",
                   help="Print raw keys seen in each source instead of the summary.")
    return p.parse_args()


# ── loading ──────────────────────────────────────────────────────────────────

def load_history(path):
    if not os.path.exists(path):
        print(f"  !  {path} not found — skipping history-based section.")
        return []
    try:
        d = json.load(open(path, errors="replace"))
    except Exception as e:
        print(f"  !  could not parse {path}: {e}")
        return []
    flows = d.get("flows", d if isinstance(d, list) else [])
    return flows


def load_alerts(path):
    if not os.path.exists(path):
        print(f"  !  {path} not found — skipping alerts-based section.")
        return []
    out = []
    with open(path, errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"  !  {path}:{i} — skipping malformed line")
    return out


# ── normalisation ────────────────────────────────────────────────────────────

def norm_label(label):
    """Fold benign spellings together; keep attack labels as-is."""
    if label is None:
        return "Benign"
    s = str(label).strip()
    return "Benign" if s.lower() in BENIGN_LABELS else s


def history_role_calls(rec):
    """
    -> (role1_label, role1_conf, role3_label, role3_conf, agreement)
    Prefers the more specific *_attack_type-style field where the schema
    has one; nids_history.json's Role 3 side uses r3_attack_type for this
    ("Normal", "PortScan", ...) with r3_verdict as the coarser benign/attack
    call, so attack_type is the one that matches Role 1's r1_label grain.
    """
    r1_label = rec.get("r1_label")
    r1_conf = rec.get("r1_conf")
    r3_label = rec.get("r3_attack_type") or rec.get("r3_verdict")
    r3_conf = rec.get("r3_conf")
    agreement = rec.get("agreement", "pending")
    return (norm_label(r1_label) if r1_label is not None else None,
            r1_conf,
            norm_label(r3_label) if r3_label is not None else None,
            r3_conf,
            agreement)


def alert_role_calls(rec):
    """
    -> (role1_label, role1_conf, role3_label, role3_conf, agree, conflict,
        final_label, final_conf, severity, suppressed)
    role1_attack_type/role1_confidence == ("unknown", 0.0) means Role 1 did
    not contribute to this alert (see NO_ROLE1_DATA) — reported as None,
    not as a real "unknown" verdict.
    """
    r1_label = rec.get("role1_attack_type") or rec.get("role1_verdict")
    r1_conf = rec.get("role1_confidence")
    if (str(r1_label).lower() if r1_label is not None else None, r1_conf) in \
            {(a, b) for a, b in NO_ROLE1_DATA if a is not None}:
        r1_label, r1_conf = None, None

    r3_label = rec.get("role3_attack_type") or rec.get("role3_verdict")
    r3_conf = rec.get("role3_confidence")

    final_label = rec.get("attack_type") or rec.get("final_verdict")
    final_conf = rec.get("confidence")

    return (
        norm_label(r1_label) if r1_label is not None else None, r1_conf,
        norm_label(r3_label) if r3_label is not None else None, r3_conf,
        rec.get("agree"), rec.get("conflict"),
        norm_label(final_label) if final_label is not None else None, final_conf,
        rec.get("severity"), rec.get("suppressed"),
    )


# ── inspect mode ─────────────────────────────────────────────────────────────

def inspect(history, alerts):
    print("=" * 74)
    print("  FIELD INSPECTION")
    print("=" * 74)
    if history:
        keys = sorted(set().union(*(r.keys() for r in history)))
        print(f"\n  nids_history.json — {len(history)} flow records")
        print(f"  keys: {keys}")
        print(f"  sample: {json.dumps(history[0], indent=2)[:800]}")
    if alerts:
        keys = sorted(set().union(*(r.keys() for r in alerts)))
        print(f"\n  unified_alerts.jsonl — {len(alerts)} alert records")
        print(f"  keys: {keys}")
        print(f"  sample: {json.dumps(alerts[0], indent=2)[:800]}")
    print("=" * 74)


# ── aggregation ──────────────────────────────────────────────────────────────

def new_role_stats():
    return {"count": 0, "conf_sum": 0.0, "conf_n": 0}


def add_call(table, attack_type, role, label, conf):
    if label is None:
        return
    key = (attack_type, role)
    st = table[key]
    st["count"] += 1
    if isinstance(conf, (int, float)):
        st["conf_sum"] += float(conf)
        st["conf_n"] += 1


def summarise_history(history):
    table = defaultdict(new_role_stats)
    agreement_counts = defaultdict(int)
    total = len(history)

    for rec in history:
        r1_label, r1_conf, r3_label, r3_conf, agreement = history_role_calls(rec)
        add_call(table, r1_label, "Role1 (ML)", r1_label, r1_conf)
        add_call(table, r3_label, "Role3 (LLM)", r3_label, r3_conf)
        agreement_counts[agreement] += 1

    return table, agreement_counts, total


def summarise_alerts(alerts):
    table = defaultdict(new_role_stats)
    final_counts = defaultdict(new_role_stats)
    agree_n = conflict_n = suppressed_n = 0
    severity_counts = defaultdict(int)
    total = len(alerts)

    for rec in alerts:
        (r1_label, r1_conf, r3_label, r3_conf,
         agree, conflict, final_label, final_conf,
         severity, suppressed) = alert_role_calls(rec)

        add_call(table, r1_label, "Role1 (ML)", r1_label, r1_conf)
        add_call(table, r3_label, "Role3 (LLM)", r3_label, r3_conf)
        add_call(final_counts, final_label, "Final (fused)", final_label, final_conf)

        if agree is True:
            agree_n += 1
        elif conflict is True:
            conflict_n += 1
        if suppressed:
            suppressed_n += 1
        severity_counts[severity or "UNKNOWN"] += 1

    return table, final_counts, agree_n, conflict_n, suppressed_n, severity_counts, total


# ── printing ─────────────────────────────────────────────────────────────────

def print_role_attack_table(title, table):
    print(f"\n  {title}")
    print(f"  {'attack_type':<28}{'role':<16}{'count':>8}{'avg_conf':>10}")
    print("  " + "-" * 62)
    rows = sorted(table.items(), key=lambda kv: (kv[0][0] or "", kv[0][1] or ""))
    for (attack_type, role), st in rows:
        avg_conf = round(st["conf_sum"] / st["conf_n"], 1) if st["conf_n"] else "-"
        print(f"  {str(attack_type):<28}{str(role):<16}{st['count']:>8}{str(avg_conf):>10}")
    if not rows:
        print("  (no records)")


def to_json_table(table):
    return [
        {"attack_type": at, "role": role, "count": st["count"],
         "avg_confidence": round(st["conf_sum"] / st["conf_n"], 1) if st["conf_n"] else None}
        for (at, role), st in sorted(table.items(), key=lambda kv: (kv[0][0] or "", kv[0][1] or ""))
    ]


def main():
    args = parse_args()
    history = load_history(args.history)
    alerts = load_alerts(args.alerts)

    if args.inspect:
        inspect(history, alerts)
        return 0

    out = {"history": {}, "alerts": {}}

    print("=" * 74)
    print("  DETECTION SUMMARY — Role x Attack Type")
    print("=" * 74)
    print(f"  history file : {args.history}  ({len(history)} flows)")
    print(f"  alerts file  : {args.alerts}  ({len(alerts)} alerts)")

    # ── nids_history.json section: R1 vs R3 on the SAME flows ──────────────
    if history:
        table, agreement_counts, total = summarise_history(history)
        print_role_attack_table(
            "PER-FLOW COMPARISON (nids_history.json) — Role 1 vs Role 3, same flows",
            table,
        )
        print(f"\n  agreement breakdown (of {total} flows):")
        for k, v in sorted(agreement_counts.items(), key=lambda kv: -kv[1]):
            pct = round(100 * v / total, 1) if total else 0
            print(f"    {k:<16}{v:>6}  ({pct}%)")

        out["history"] = {
            "total_flows": total,
            "role_attack_table": to_json_table(table),
            "agreement_counts": dict(agreement_counts),
        }

    # ── unified_alerts.jsonl section: fused/suppressed alert stream ────────
    if alerts:
        table, final_table, agree_n, conflict_n, suppressed_n, severity_counts, total = \
            summarise_alerts(alerts)
        print_role_attack_table(
            "\n  CONTRIBUTING ROLES (unified_alerts.jsonl) — R1/R3 inputs into each alert",
            table,
        )
        print_role_attack_table(
            "FINAL FUSED VERDICT (unified_alerts.jsonl) — what was actually alerted",
            final_table,
        )
        print(f"\n  of {total} alerts: agree={agree_n} conflict={conflict_n} "
              f"suppressed={suppressed_n}")
        print("\n  severity breakdown:")
        for sev, n in sorted(severity_counts.items(), key=lambda kv: -kv[1]):
            pct = round(100 * n / total, 1) if total else 0
            print(f"    {sev:<12}{n:>6}  ({pct}%)")

        out["alerts"] = {
            "total_alerts": total,
            "role_attack_table": to_json_table(table),
            "final_verdict_table": to_json_table(final_table),
            "agree": agree_n, "conflict": conflict_n, "suppressed": suppressed_n,
            "severity_counts": dict(severity_counts),
        }

    print("\n" + "=" * 74)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        json.dump(out, open(args.out, "w"), indent=2)
        print(f"  saved: {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
