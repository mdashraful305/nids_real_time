#!/usr/bin/env python3
"""
scripts/detection_matrix.py  (v3 — split by approach)
=========================================================
Your codebase has TWO SEPARATE detection pipelines that happen to write
JSON to disk in similar shapes. This script keeps them visibly separate
instead of merging them into one matrix, because merging was hiding which
approach actually caught what:

  APPROACH 1 — nids_web.py (real-time, per-flow)
      Source file : nids_history.json
      Role 1  = ML model scored on ONE NFStream flow (r1_label)
      Heuristic = check_cross_flow_attack() override (labels ending
                  "(Heuristics)") — a rule, not the ML model
      Role 3  = per-flow Ollama LLM classifier (r3_attack_type)
      Suricata = NOT part of this pipeline at all. nids_web.py never reads
                 eve.json. Any Suricata column shown under Approach 1 here
                 is THIS SCRIPT correlating flow timestamps against an
                 eve.json you separately point it at — an external cross-
                 check, not something nids_web.py itself does.

  APPROACH 2 — main_unified.py (offline/live, windowed)
      Source file : unified_alerts.jsonl
      Role 1  = ML model scored on ALL flows in a time window, reduced to
                one dominant verdict (role1_attack_type)
      Heuristic = same "(Heuristics)" label convention, if your Role 1
                  output uses it here too
      Role 3  = Ollama LOG ANALYST reading Suricata+flow text for the
                whole window (role3_attack_type) — a different LLM role
                than Approach 1's per-flow classifier, even though both
                are called "Role 3"
      Suricata = chunk.has_alert genuinely feeds THIS pipeline (LLM-
                 gating decision), but is discarded before the alert is
                 written — confirmed by reading unified_pipeline.py's
                 engine.merge() call, which never receives it. So even
                 here, the eve.json matching this script does is a
                 reconstruction after the fact, not a field the pipeline
                 itself persisted.

Both approaches get their own printed table AND their own JSON block, so
you can see e.g. "Approach 1 caught PortScan via the cross-flow heuristic
but Approach 2's windowed Role 1 missed it" as a real distinction instead
of one blended cell.

A COMBINED "caught by ANY approach" table is printed last as a summary,
clearly labeled as a union, not a new data source.

USAGE
-----
    python scripts/detection_matrix.py \\
        --history nids_history.json \\
        --alerts  unified_alerts.jsonl \\
        --eve     /path/to/eve.json

    python scripts/detection_matrix.py --history-only   # Approach 1 only
    python scripts/detection_matrix.py --alerts-only     # Approach 2 only
"""

import os
import sys
import re
import json
import bisect
import argparse
from datetime import datetime, timezone
from collections import defaultdict


BENIGN_LABELS = {"benign", "normal", "none", "unknown", ""}
HEURISTIC_SUFFIX = re.compile(r"\s*\(Heuristics\)\s*$", re.IGNORECASE)

COL_ML = "Role 1 (ML)"
COL_HEUR = "Cross-Flow Heuristic"
COL_LLM = "Role 3 (LLM)"
COL_SURICATA = "Suricata (external corr.)"
COLUMNS = [COL_ML, COL_HEUR, COL_LLM, COL_SURICATA]

APPROACH_1 = "APPROACH 1 — nids_web.py (real-time, per-flow)"
APPROACH_2 = "APPROACH 2 — main_unified.py (windowed, Suricata+CICFlowMeter+LLM log analyst)"

ALERT_EVENT_TYPE = "alert"

SURICATA_CATEGORY_KEYWORDS = [
    (("port scan", "portscan", "network scan", "potential ssh scan", "scan"), "PortScan"),
    (("denial of service", " dos ", "ddos", "flood"),            "DoS"),
    (("brute force", "brute-force", "successful admin login",
      "successful user privilege gain"),                        "Brute Force"),
    (("web application attack", "sql injection", "sqli",
      "cross site scripting", " xss ", "web attack"),            "Web Attack"),
    (("trojan", "malware", "command and control", " c2 "),       "Malware"),
    (("exploit", "shellcode", "attempted admin"),                "Exploit"),
]


def parse_args():
    p = argparse.ArgumentParser(description="Attack-type x detector Hit/Miss matrix, split by approach.")
    p.add_argument("--history", default="nids_history.json")
    p.add_argument("--alerts", default="unified_alerts.jsonl")
    p.add_argument("--eve", default=None)
    p.add_argument("--time-tolerance", type=float, default=5.0)
    p.add_argument("--window-seconds", type=float, default=30.0)
    p.add_argument("--history-only", action="store_true", help="Only show Approach 1.")
    p.add_argument("--alerts-only", action="store_true", help="Only show Approach 2.")
    p.add_argument("--out", default=None)
    p.add_argument("--inspect", action="store_true")
    p.add_argument("--inspect-suricata", action="store_true")
    return p.parse_args()


# ── loading ──────────────────────────────────────────────────────────────────

def load_history(path):
    if not os.path.exists(path):
        print(f"  !  {path} not found — skipping Approach 1.")
        return []
    try:
        d = json.load(open(path, errors="replace"))
    except Exception as e:
        print(f"  !  could not parse {path}: {e}")
        return []
    return d.get("flows", d if isinstance(d, list) else [])


def load_alerts(path):
    if not os.path.exists(path):
        print(f"  !  {path} not found — skipping Approach 2.")
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


def _parse_ts(ts_str):
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("+0000", "+00:00"))
    except ValueError:
        try:
            return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _load_eve_file(path):
    events, bad = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if raw.get("event_type") != ALERT_EVENT_TYPE:
                continue
            alert = raw.get("alert") or {}
            events.append({
                "timestamp": _parse_ts(raw.get("timestamp", "")),
                "src_ip":    raw.get("src_ip", ""),
                "dest_ip":   raw.get("dest_ip", ""),
                "signature": alert.get("signature", ""),
                "category":  alert.get("category", ""),
                "severity":  alert.get("severity"),
            })
    if bad:
        print(f"  !  {path}: skipped {bad} malformed line(s)")
    return events


def load_eve(path):
    if path is None:
        return []
    if not os.path.exists(path):
        print(f"  !  {path} not found — Suricata column will be empty.")
        return []
    if os.path.isdir(path):
        files = sorted(f for f in os.listdir(path) if f.endswith(".json"))
        events = []
        for fname in files:
            events.extend(_load_eve_file(os.path.join(path, fname)))
    else:
        events = _load_eve_file(path)
    events = [e for e in events if e["timestamp"] is not None]
    events.sort(key=lambda e: e["timestamp"])
    print(f"  ✓ loaded {len(events)} Suricata alert event(s) from {path}")
    return events


def build_ts_index(events):
    return [e["timestamp"] for e in events]


def events_in_range(events, timestamps, start, end):
    lo = bisect.bisect_left(timestamps, start)
    hi = bisect.bisect_right(timestamps, end)
    return events[lo:hi]


def map_suricata_category(event):
    blob = f"{event.get('category', '')} {event.get('signature', '')}".lower()
    for keywords, attack_type in SURICATA_CATEGORY_KEYWORDS:
        if any(kw in blob for kw in keywords):
            return attack_type
    return None


# ── label handling ──────────────────────────────────────────────────────────

def is_benign(label):
    return label is None or str(label).strip().lower() in BENIGN_LABELS


def split_heuristic(label):
    if label is None:
        return None, False
    s = str(label).strip()
    m = HEURISTIC_SUFFIX.search(s)
    if m:
        return s[:m.start()].strip(), True
    return s, False


def parse_record_ts(rec):
    ts = rec.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


# ── per-approach matrix building ─────────────────────────────────────────────

def new_cell():
    return {"hit": False, "conf_sum": 0.0, "conf_n": 0, "seen": False, "notes": set()}


def record_call(matrix, seen_attacks, attack_type, column, is_attack, conf):
    if attack_type is None:
        return
    seen_attacks.add(attack_type)
    cell = matrix[(attack_type, column)]
    cell["seen"] = True
    if is_attack:
        cell["hit"] = True
        if isinstance(conf, (int, float)):
            cell["conf_sum"] += float(conf)
            cell["conf_n"] += 1


def process_ml_llm(matrix, seen_attacks, ml_label, ml_conf, llm_label, llm_conf):
    ml_base, ml_is_heur = split_heuristic(ml_label)
    llm_base, _ = split_heuristic(llm_label)
    ml_attack = ml_base is not None and not is_benign(ml_base)
    llm_attack = llm_base is not None and not is_benign(llm_base)

    this_record_attacks = set()
    if ml_attack:
        this_record_attacks.add(ml_base)
    if llm_attack:
        this_record_attacks.add(llm_base)

    for attack_type in this_record_attacks:
        if ml_base is not None:
            col = COL_HEUR if ml_is_heur else COL_ML
            matches = ml_attack and ml_base.lower() == attack_type.lower()
            record_call(matrix, seen_attacks, attack_type, col, matches, ml_conf)
            other_col = COL_ML if ml_is_heur else COL_HEUR
            matrix[(attack_type, other_col)]["seen"] = True
        if llm_base is not None:
            matches = llm_attack and llm_base.lower() == attack_type.lower()
            record_call(matrix, seen_attacks, attack_type, COL_LLM, matches, llm_conf)
        else:
            matrix[(attack_type, COL_LLM)]["seen"] = True

    return this_record_attacks


def match_suricata(rec, events, timestamps, half_window_s, ip_source):
    ts = parse_record_ts(rec)
    if ts is None or not events:
        return []
    start = ts.fromtimestamp(ts.timestamp() - half_window_s, tz=ts.tzinfo)
    end = ts.fromtimestamp(ts.timestamp() + half_window_s, tz=ts.tzinfo)
    candidates = events_in_range(events, timestamps, start, end)
    src_ip, dst_ip = ip_source(rec)
    out = []
    for e in candidates:
        if src_ip or dst_ip:
            if e["src_ip"] not in (src_ip, dst_ip, "") and e["dest_ip"] not in (src_ip, dst_ip, ""):
                continue
        out.append(e)
    return out


def apply_suricata_matches(matrix, seen_attacks, attack_types_this_record, matched_events,
                            unmapped_categories):
    if not matched_events:
        for at in attack_types_this_record:
            matrix[(at, COL_SURICATA)]["seen"] = True
        return
    for e in matched_events:
        mapped = map_suricata_category(e)
        if mapped is None:
            unmapped_categories[(e.get("category", ""), e.get("signature", ""))] += 1
            continue
        seen_attacks.add(mapped)
        cell = matrix[(mapped, COL_SURICATA)]
        cell["seen"] = True
        cell["hit"] = True
        sev = e.get("severity")
        if sev is not None:
            cell["notes"].add(f"sev{sev}")
    for at in attack_types_this_record:
        matrix[(at, COL_SURICATA)]["seen"] = True


def build_approach1_matrix(history, eve_events, timestamps, time_tolerance):
    matrix = defaultdict(new_cell)
    seen_attacks = set()
    unmapped = defaultdict(int)
    for rec in history:
        ml_label = rec.get("r1_label")
        ml_conf = rec.get("r1_conf")
        llm_label = rec.get("r3_attack_type") or rec.get("r3_verdict")
        llm_conf = rec.get("r3_conf")
        attack_types = process_ml_llm(matrix, seen_attacks, ml_label, ml_conf, llm_label, llm_conf)

        matched = match_suricata(
            rec, eve_events, timestamps, time_tolerance,
            ip_source=lambda r: (r.get("src_ip"), r.get("dst_ip")),
        )
        apply_suricata_matches(matrix, seen_attacks, attack_types, matched, unmapped)
    return matrix, sorted(seen_attacks), unmapped


def build_approach2_matrix(alerts, eve_events, timestamps, window_seconds):
    matrix = defaultdict(new_cell)
    seen_attacks = set()
    unmapped = defaultdict(int)
    for rec in alerts:
        ml_label = rec.get("role1_attack_type") or rec.get("role1_verdict")
        ml_conf = rec.get("role1_confidence")
        if str(ml_label).lower() == "unknown" and (ml_conf in (0, 0.0, None)):
            ml_label, ml_conf = None, None
        llm_label = rec.get("role3_attack_type") or rec.get("role3_verdict")
        llm_conf = rec.get("role3_confidence")
        attack_types = process_ml_llm(matrix, seen_attacks, ml_label, ml_conf, llm_label, llm_conf)

        def _ip_source(r):
            ff = r.get("flow_features") or {}
            return ff.get("src_ip"), ff.get("dst_ip")

        matched = match_suricata(rec, eve_events, timestamps, window_seconds / 2.0, _ip_source)
        apply_suricata_matches(matrix, seen_attacks, attack_types, matched, unmapped)
    return matrix, sorted(seen_attacks), unmapped


# ── printing ─────────────────────────────────────────────────────────────────

def cell_text(matrix, attack_type, column):
    cell = matrix.get((attack_type, column))
    if cell is None or not cell["seen"]:
        return "-"
    if cell["hit"]:
        if column == COL_SURICATA:
            note = ",".join(sorted(cell["notes"])) if cell["notes"] else ""
            return f"Hit{(' — ' + note) if note else ''}"
        if cell["conf_n"]:
            return f"Hit — {round(cell['conf_sum'] / cell['conf_n'], 1)}%"
        return "Hit"
    return "Miss"


def print_matrix(title, matrix, attack_types):
    print(f"\n  {title}")
    print("  " + "-" * len(title))
    if not attack_types:
        print("  (no non-benign attack types found)")
        return
    col_w = 26
    print(f"  {'Attack Type':<20}" + "".join(f"{c:<{col_w}}" for c in COLUMNS))
    print("  " + "-" * (20 + col_w * len(COLUMNS)))
    for at in attack_types:
        row = "".join(f"{cell_text(matrix, at, c):<{col_w}}" for c in COLUMNS)
        print(f"  {at:<20}{row}")


def print_unmapped(unmapped):
    if not unmapped:
        return
    print("\n  Unmapped Suricata categories seen (not counted above):")
    for (cat, sig), n in sorted(unmapped.items(), key=lambda kv: -kv[1])[:10]:
        print(f"    x{n:<4} category={cat!r}  signature={sig!r}")


def to_json_matrix(matrix, attack_types):
    out = []
    for at in attack_types:
        row = {"attack_type": at}
        for c in COLUMNS:
            cell = matrix.get((at, c))
            if cell is None or not cell["seen"]:
                row[c] = None
            elif cell["hit"]:
                row[c] = round(cell["conf_sum"] / cell["conf_n"], 1) if cell["conf_n"] else "hit"
            else:
                row[c] = "miss"
        out.append(row)
    return out


def union_summary(m1, at1, m2, at2):
    """Combined 'caught by ANY approach' view — clearly a derived union,
    not a third data source."""
    all_types = sorted(set(at1) | set(at2))
    print(f"\n  COMBINED — caught by ANY approach (union of Approach 1 + Approach 2)")
    print("  " + "-" * 70)
    if not all_types:
        print("  (nothing to summarise)")
        return
    print(f"  {'Attack Type':<20}{'Approach 1':<14}{'Approach 2':<14}{'Either':<10}")
    print("  " + "-" * 58)
    for at in all_types:
        a1_hit = any(m1.get((at, c), {}).get("hit") for c in COLUMNS)
        a2_hit = any(m2.get((at, c), {}).get("hit") for c in COLUMNS)
        either = "YES" if (a1_hit or a2_hit) else "NO"
        print(f"  {at:<20}{('YES' if a1_hit else 'no'):<14}{('YES' if a2_hit else 'no'):<14}{either:<10}")


def main():
    args = parse_args()

    if args.inspect_suricata:
        events = load_eve(args.eve)
        for e in events[:10]:
            print(json.dumps({**e, "timestamp": str(e["timestamp"])}, indent=2))
        return 0

    history = [] if args.alerts_only else load_history(args.history)
    alerts = [] if args.history_only else load_alerts(args.alerts)

    if args.inspect:
        if history:
            print("history keys:", sorted(set().union(*(r.keys() for r in history))))
        if alerts:
            print("alerts keys:", sorted(set().union(*(r.keys() for r in alerts))))
        return 0

    print("=" * 100)
    print("  DETECTION COVERAGE — split by approach")
    print("=" * 100)
    print(f"  history: {args.history} ({len(history)} flows)   "
          f"alerts: {args.alerts} ({len(alerts)} alerts)")

    eve_events = load_eve(args.eve) if args.eve else []
    timestamps = build_ts_index(eve_events)

    out = {}

    m1 = at1 = un1 = None
    if history:
        m1, at1, un1 = build_approach1_matrix(history, eve_events, timestamps, args.time_tolerance)
        print_matrix(APPROACH_1, m1, at1)
        print_unmapped(un1)
        out["approach_1"] = to_json_matrix(m1, at1)

    m2 = at2 = un2 = None
    if alerts:
        m2, at2, un2 = build_approach2_matrix(alerts, eve_events, timestamps, args.window_seconds)
        print_matrix(APPROACH_2, m2, at2)
        print_unmapped(un2)
        out["approach_2"] = to_json_matrix(m2, at2)

    if m1 is not None and m2 is not None:
        union_summary(m1, at1, m2, at2)

    print(f"\n  Suricata matching (both approaches, external correlation by this "
          f"script — see docstring): time_tolerance={args.time_tolerance}s (flows), "
          f"window={args.window_seconds}s (fused alerts, approximate)")
    print("\n" + "=" * 100)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        json.dump(out, open(args.out, "w"), indent=2)
        print(f"  saved: {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
