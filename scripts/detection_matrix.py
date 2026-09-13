#!/usr/bin/env python3
"""
scripts/detection_matrix.py  (v2 — real Suricata matching)
=============================================================
Hit/Miss coverage matrix — rows = attack type, columns = detector — built
from THREE sources now:

    nids_history.json     — per-flow Role 1 (ML) + Role 3 (LLM) verdicts
    unified_alerts.jsonl   — per-window fused Role 1 + Role 3 verdicts
    eve.json (Suricata)    — real alert.signature / alert.category events

WHAT CHANGED FROM v1
----------------------
v1's "Suricata" column was a plain text search for the word "suricata"
inside LLM explanation fields — a guess, not a verdict. This version reads
the actual eve.json alert events (same parsing suricata_reader.py uses:
event_type, timestamp, src_ip, dest_ip, alert.signature, alert.category)
and matches them against your flow/alert records directly.

WHY MATCHING IS APPROXIMATE, AND WHERE
----------------------------------------
Neither nids_history.json nor unified_alerts.jsonl stores a Suricata
signature/category or a shared event ID — there is nothing to join on
except time (and IP, when available). Concretely:

  nids_history.json flows
      Each flow has one "timestamp" (when NFStream closed it) and real
      src_ip/dst_ip. A Suricata alert is matched if it falls within
      --time-tolerance seconds of the flow's timestamp AND (when the
      alert has IPs) shares src_ip or dst_ip with the flow. This is a
      fairly tight, fairly reliable match.

  unified_alerts.jsonl alerts
      Each alert has ONE "timestamp" — not a window_start/window_end
      pair (main_unified.py's UnifiedAlert.to_dict() does not expose the
      window boundaries the alert was actually built from; only the
      single timestamp survives to this file). This script cannot
      recover the true window edges, so it approximates the window as
      [timestamp - window_seconds/2, timestamp + window_seconds/2] and
      matches Suricata alerts falling inside that estimated span, using
      alert.flow_features.src_ip/dst_ip for an IP match when present.
      --window-seconds should match cfg.chunker.window_seconds from
      config/settings.yaml for this to be meaningfully accurate — pass
      it explicitly if you're not using the default.
      THIS IS AN APPROXIMATION. If you need exact window matching, the
      real fix is upstream: have UnifiedAlert.to_dict() (in
      src/engine/decision_engine.py) also emit window_start/window_end,
      then this script can do exact range matching instead of guessing.

  Suricata category -> attack type
      eve.json alerts carry a signature/category string (e.g. "Attempted
      Denial of Service", "ET SCAN Potential SSH Scan"), not one of your
      model's attack_type labels. SURICATA_CATEGORY_KEYWORDS below is a
      best-effort keyword mapping to fold common Suricata categories into
      the same attack-type vocabulary as Role 1/Role 3, so they land in
      the same matrix row. Any Suricata alert that matches NO keyword is
      still counted (so it isn't silently dropped) and listed separately
      under "unmapped Suricata categories seen" at the end of the run —
      check that list and extend the keyword table if something relevant
      is being missed.

USAGE
-----
    python scripts/detection_matrix.py \\
        --history nids_history.json \\
        --alerts  unified_alerts.jsonl \\
        --eve     /path/to/eve.json \\
        --time-tolerance 5 \\
        --window-seconds 30

    python scripts/detection_matrix.py --eve /path/to/eve.json --inspect-suricata
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
COL_SURICATA = "Suricata (eve.json)"
COLUMNS = [COL_ML, COL_HEUR, COL_LLM, COL_SURICATA]

# Suricata event types that carry an "alert" block. Same set
# suricata_reader.KEEP_EVENT_TYPES restricts loading to, minus dns/http/tls
# which don't represent an attack verdict on their own.
ALERT_EVENT_TYPE = "alert"

# Best-effort keyword -> attack-type mapping for Suricata's free-text
# category/signature. Checked in order (first match wins), on the
# lowercased "category signature" string. Extend as needed for your
# ruleset — these are common ET-Open style categories, not exhaustive.
SURICATA_CATEGORY_KEYWORDS = [
    (("port scan", "portscan", "network scan"),                 "PortScan"),
    (("denial of service", " dos ", "ddos", "flood"),            "DoS"),
    (("brute force", "brute-force", "successful admin login",
      "successful user privilege gain"),                        "Brute Force"),
    (("web application attack", "sql injection", "sqli",
      "cross site scripting", " xss ", "web attack"),            "Web Attack"),
    (("trojan", "malware", "command and control", " c2 "),       "Malware"),
    (("exploit", "shellcode", "attempted admin"),                "Exploit"),
]


def parse_args():
    p = argparse.ArgumentParser(description="Attack-type x detector Hit/Miss matrix.")
    p.add_argument("--history", default="nids_history.json")
    p.add_argument("--alerts", default="unified_alerts.jsonl")
    p.add_argument("--eve", default=None,
                   help="Path to a Suricata eve.json file OR a directory of .json files.")
    p.add_argument("--time-tolerance", type=float, default=5.0,
                   help="Seconds of slack when matching a Suricata alert to a single-"
                        "timestamp flow record (nids_history.json). Default: 5.")
    p.add_argument("--window-seconds", type=float, default=30.0,
                   help="Approximate window width to reconstruct around a "
                        "unified_alerts.jsonl alert's single timestamp, since the "
                        "real window_start/window_end aren't stored there. Should "
                        "match cfg.chunker.window_seconds. Default: 30.")
    p.add_argument("--out", default=None)
    p.add_argument("--inspect", action="store_true")
    p.add_argument("--inspect-suricata", action="store_true",
                   help="Print sample parsed Suricata alert events and exit.")
    return p.parse_args()


# ── loading: history / alerts (unchanged from v1) ───────────────────────────

def load_history(path):
    if not os.path.exists(path):
        print(f"  !  {path} not found — skipping.")
        return []
    try:
        d = json.load(open(path, errors="replace"))
    except Exception as e:
        print(f"  !  could not parse {path}: {e}")
        return []
    return d.get("flows", d if isinstance(d, list) else [])


def load_alerts(path):
    if not os.path.exists(path):
        print(f"  !  {path} not found — skipping.")
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


# ── loading: eve.json (mirrors suricata_reader.py's parsing, standalone) ────

def _parse_ts(ts_str):
    """Same approach as suricata_reader._parse_timestamp: ISO-8601 with
    Suricata's '+0000'-style offset, falling back to a naive UTC parse."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("+0000", "+00:00"))
    except ValueError:
        try:
            return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc)
        except Exception:
            return None


def _load_eve_file(path):
    events = []
    bad = 0
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
                "timestamp":  _parse_ts(raw.get("timestamp", "")),
                "src_ip":     raw.get("src_ip", ""),
                "dest_ip":    raw.get("dest_ip", ""),
                "signature":  alert.get("signature", ""),
                "category":   alert.get("category", ""),
                "severity":   alert.get("severity"),
            })
    if bad:
        print(f"  !  {path}: skipped {bad} malformed line(s)")
    return events


def load_eve(path):
    """Accepts a single eve.json file or a directory of them. Returns
    alert-type events only, sorted by timestamp, with None-timestamp
    events dropped (matches suricata_reader.build_sorted_timestamps)."""
    if path is None:
        return []
    if not os.path.exists(path):
        print(f"  !  {path} not found — Suricata column will be empty.")
        return []

    if os.path.isdir(path):
        files = sorted(f for f in os.listdir(path) if f.endswith(".json"))
        if not files:
            print(f"  !  no .json files in {path} — Suricata column will be empty.")
            return []
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
    """Best-effort category/signature -> attack_type. Returns None if no
    keyword matched (caller tracks these separately, doesn't drop them)."""
    blob = f"{event.get('category', '')} {event.get('signature', '')}".lower()
    for keywords, attack_type in SURICATA_CATEGORY_KEYWORDS:
        if any(kw in blob for kw in keywords):
            return attack_type
    return None


# ── label handling (unchanged from v1) ───────────────────────────────────────

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


# ── matrix accumulation ──────────────────────────────────────────────────────

def new_cell():
    return {"hit": False, "conf_sum": 0.0, "conf_n": 0, "seen": False, "notes": set()}


def record_call(matrix, seen_attacks, attack_type, column, is_attack, conf, note=None):
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
        if note:
            cell["notes"].add(note)


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


def match_suricata_for_history(rec, events, timestamps, tolerance_s):
    ts = parse_record_ts(rec)
    if ts is None or not events:
        return []
    start = ts.fromtimestamp(ts.timestamp() - tolerance_s, tz=ts.tzinfo)
    end = ts.fromtimestamp(ts.timestamp() + tolerance_s, tz=ts.tzinfo)
    candidates = events_in_range(events, timestamps, start, end)
    src_ip, dst_ip = rec.get("src_ip"), rec.get("dst_ip")
    out = []
    for e in candidates:
        if src_ip or dst_ip:
            if e["src_ip"] not in (src_ip, dst_ip, "") and e["dest_ip"] not in (src_ip, dst_ip, ""):
                continue
        out.append(e)
    return out


def match_suricata_for_alert(rec, events, timestamps, window_s):
    ts = parse_record_ts(rec)
    if ts is None or not events:
        return []
    half = window_s / 2.0
    start = ts.fromtimestamp(ts.timestamp() - half, tz=ts.tzinfo)
    end = ts.fromtimestamp(ts.timestamp() + half, tz=ts.tzinfo)
    candidates = events_in_range(events, timestamps, start, end)
    ff = rec.get("flow_features") or {}
    src_ip, dst_ip = ff.get("src_ip"), ff.get("dst_ip")
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
        # still mark "seen" for whatever attack types this record already
        # established, so a Miss (Suricata looked, found nothing relevant)
        # is distinguishable from "-" (no Suricata data at all for this row)
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

    # attack types from ML/LLM that Suricata data covered this time window
    # for, but didn't itself flag -> Miss, not "-"
    for at in attack_types_this_record:
        matrix[(at, COL_SURICATA)]["seen"] = True


def build_matrix(history, alerts, eve_events, time_tolerance, window_seconds):
    matrix = defaultdict(new_cell)
    seen_attacks = set()
    unmapped_categories = defaultdict(int)
    timestamps = build_ts_index(eve_events)

    for rec in history:
        ml_label = rec.get("r1_label")
        ml_conf = rec.get("r1_conf")
        llm_label = rec.get("r3_attack_type") or rec.get("r3_verdict")
        llm_conf = rec.get("r3_conf")
        attack_types_this_record = process_ml_llm(
            matrix, seen_attacks, ml_label, ml_conf, llm_label, llm_conf)

        matched = match_suricata_for_history(rec, eve_events, timestamps, time_tolerance)
        apply_suricata_matches(matrix, seen_attacks, attack_types_this_record,
                                matched, unmapped_categories)

    for rec in alerts:
        ml_label = rec.get("role1_attack_type") or rec.get("role1_verdict")
        ml_conf = rec.get("role1_confidence")
        if str(ml_label).lower() == "unknown" and (ml_conf in (0, 0.0, None)):
            ml_label, ml_conf = None, None
        llm_label = rec.get("role3_attack_type") or rec.get("role3_verdict")
        llm_conf = rec.get("role3_confidence")
        attack_types_this_record = process_ml_llm(
            matrix, seen_attacks, ml_label, ml_conf, llm_label, llm_conf)

        matched = match_suricata_for_alert(rec, eve_events, timestamps, window_seconds)
        apply_suricata_matches(matrix, seen_attacks, attack_types_this_record,
                                matched, unmapped_categories)

    return matrix, sorted(seen_attacks), unmapped_categories


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
            avg = round(cell["conf_sum"] / cell["conf_n"], 1)
            return f"Hit — {avg}%"
        return "Hit"
    return "Miss"


def print_matrix(matrix, attack_types):
    if not attack_types:
        print("  (no non-benign attack types found)")
        return
    col_w = 26
    print(f"\n  {'Attack Type':<20}" + "".join(f"{c:<{col_w}}" for c in COLUMNS))
    print("  " + "-" * (20 + col_w * len(COLUMNS)))
    for at in attack_types:
        row = "".join(f"{cell_text(matrix, at, c):<{col_w}}" for c in COLUMNS)
        print(f"  {at:<20}{row}")


def to_json(matrix, attack_types):
    out = []
    for at in attack_types:
        row = {"attack_type": at}
        for c in COLUMNS:
            cell = matrix.get((at, c))
            if cell is None or not cell["seen"]:
                row[c] = None
            elif cell["hit"]:
                row[c] = (round(cell["conf_sum"] / cell["conf_n"], 1)
                           if cell["conf_n"] else "hit")
            else:
                row[c] = "miss"
        out.append(row)
    return out


def main():
    args = parse_args()

    if args.inspect_suricata:
        events = load_eve(args.eve)
        for e in events[:10]:
            print(json.dumps({**e, "timestamp": str(e["timestamp"])}, indent=2))
        return 0

    history = load_history(args.history)
    alerts = load_alerts(args.alerts)

    if args.inspect:
        if history:
            print("history keys:", sorted(set().union(*(r.keys() for r in history))))
        if alerts:
            print("alerts keys:", sorted(set().union(*(r.keys() for r in alerts))))
        return 0

    print("=" * 100)
    print("  DETECTION COVERAGE MATRIX — Attack Type x Detector")
    print("=" * 100)
    print(f"  history: {args.history} ({len(history)} flows)   "
          f"alerts: {args.alerts} ({len(alerts)} alerts)")

    eve_events = load_eve(args.eve) if args.eve else []
    if args.eve and not eve_events:
        print("  (no Suricata data loaded — Suricata column will read '-' throughout)")

    matrix, attack_types, unmapped = build_matrix(
        history, alerts, eve_events, args.time_tolerance, args.window_seconds)
    print_matrix(matrix, attack_types)

    print(f"\n  Suricata matching: time_tolerance={args.time_tolerance}s "
          f"(per-flow), window={args.window_seconds}s (per fused alert, "
          f"APPROXIMATE — see script docstring)")

    if unmapped:
        print("\n  Suricata alert categories seen but NOT mapped to an attack_type "
              "(not counted in the matrix above — extend SURICATA_CATEGORY_KEYWORDS "
              "if any of these should count):")
        for (cat, sig), n in sorted(unmapped.items(), key=lambda kv: -kv[1])[:15]:
            print(f"    x{n:<4} category={cat!r}  signature={sig!r}")

    print("\n" + "=" * 100)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        json.dump({
            "matrix": to_json(matrix, attack_types),
            "unmapped_suricata_categories": [
                {"category": c, "signature": s, "count": n}
                for (c, s), n in unmapped.items()
            ],
        }, open(args.out, "w"), indent=2)
        print(f"  saved: {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
