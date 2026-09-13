#!/usr/bin/env python3
"""
scripts/summarize_live_test.py
===============================
Reads whatever the live pipelines actually produced (nids_history.json for
Approach A, data/results/unified_alerts.jsonl for Approach B, optionally
Suricata's fast.log) and writes ONE clean markdown page — a single detection
table per attack, not a raw data dump — for the thesis deployability section.

Designed for the SMALL attack runs in ATTACKER_COMMANDS.md (a few dozen to a
few hundred flows per attack, not the 1000-port scans / --flood floods from
earlier testing that generated hundreds of thousands of flows for what is
just supposed to be a "yes it detects this" demonstration).

How attacks are told apart
---------------------------
Approach A's flows carry real per-flow IPs/ports, so this script:
  1. auto-detects the attacker IP (the most common LAN source IP in
     nids_history.json flows that isn't this host itself),
  2. groups that IP's flows into "bursts" (a new burst starts after a
     configurable quiet gap — default 20s — matching one attack command
     each, if you leave gaps between attacks per ATTACKER_COMMANDS.md),
  3. labels each burst PortScan / Brute Force / DoS / Web Attack from its
     destination port(s) — port 22 -> Brute Force, >15 distinct ports ->
     PortScan, single-port high-volume -> DoS/Web Attack, disambiguated
     between those two by which one came first if there are exactly two
     (matches ATTACKER_COMMANDS.md's nmap/hping3/hydra/nikto order: the
     first port-80 burst is hping3/DoS, the second is nikto/Web Attack).
  4. cross-references each burst's time window against Approach B's
     unified_alerts.jsonl (window-level verdicts) and, if present,
     Suricata's fast.log (signature-level evidence).

This is a best-effort classifier for a *known, controlled* 4-attack test
sequence, not a general traffic classifier — say so in the output rather
than presenting it as more certain than it is.

Usage
-----
    python scripts/summarize_live_test.py
    python scripts/summarize_live_test.py --attacker 192.168.1.194 --gap 15
    python scripts/summarize_live_test.py --out data/results/my_test.md
"""

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone, timedelta

import pandas as pd


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", default=None, help="This NIDS host's own IP (auto-detected if omitted)")
    p.add_argument("--attacker", default=None, help="Attacker IP (auto-detected if omitted)")
    p.add_argument("--nids-history", default="nids_history.json")
    p.add_argument("--unified-alerts", default="data/results/unified_alerts.jsonl")
    p.add_argument("--suricata-fast-log", default="/var/log/suricata/fast.log")
    p.add_argument("--gap", type=float, default=20.0,
                    help="Seconds of quiet before a new attack 'burst' starts (default 20)")
    p.add_argument("--out", default="data/results/LIVE_TEST_SUMMARY.md")
    return p.parse_args()


BENIGN_WORDS = {"", "benign", "normal", "none", "unknown"}


def own_ip():
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from src.utils.capture_filter import get_own_network
        ip, _net = get_own_network()
        return ip
    except Exception:
        return None


def load_history_flows(path):
    if not os.path.exists(path):
        return []
    try:
        d = json.load(open(path))
        return d.get("flows", [])
    except Exception:
        return []


def load_unified_alerts(path):
    if not os.path.exists(path):
        return []
    rows = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def detect_attacker_ip(flows, target_ip):
    candidates = Counter()
    for f in flows:
        for ip in (f.get("src_ip"), f.get("dst_ip")):
            if not ip or ip == target_ip or ip == "127.0.0.1":
                continue
            if ip.startswith(("224.", "239.", "255.", "ff02:")):
                continue
            candidates[ip] += 1
    if not candidates:
        return None
    return candidates.most_common(1)[0][0]


def cluster_bursts(flows, attacker_ip, gap_seconds):
    """Group an IP's flows into time-contiguous bursts separated by >gap_seconds of quiet."""
    involved = [f for f in flows if f.get("src_ip") == attacker_ip or f.get("dst_ip") == attacker_ip]
    if not involved:
        return []
    involved.sort(key=lambda f: f["timestamp"])
    bursts = []
    current = [involved[0]]
    prev_t = datetime.fromisoformat(involved[0]["timestamp"])
    for f in involved[1:]:
        t = datetime.fromisoformat(f["timestamp"])
        if (t - prev_t).total_seconds() > gap_seconds:
            bursts.append(current)
            current = []
        current.append(f)
        prev_t = t
    bursts.append(current)
    return bursts


def label_burst(flows, attacker_ip, position_among_ambiguous):
    dst_ports = [f["dst_port"] for f in flows if f.get("src_ip") == attacker_ip]
    n_ports = len(set(dst_ports))
    n_flows = len(flows)
    if dst_ports and Counter(dst_ports).most_common(1)[0][0] == 22:
        return "Brute Force"
    if n_ports > 15:
        return "PortScan"
    if 80 in dst_ports:
        # Ambiguous: could be DoS (hping3) or Web Attack (nikto), both hit
        # port 80. Disambiguate by arrival order, matching
        # ATTACKER_COMMANDS.md's nmap -> hping3 -> hydra -> nikto sequence.
        return "DoS" if position_among_ambiguous == 0 else "Web Attack"
    return f"Other (port {dst_ports[0] if dst_ports else '?'})"


def assign_alerts_to_nearest_burst(alerts, bursts, attacker_ip, pad_seconds=60):
    """
    Assign each Approach-B alert to its single NEAREST burst (by distance to
    the burst's [start, end] span), not to every burst within some padding —
    with attacks only ~45s apart (see ATTACKER_COMMANDS.md) and Approach B's
    own processing lag needing real padding, independent per-burst overlap
    checks let the same alert double-count against several different bursts.

    Alerts whose own src_ip/dst_ip actually match the attacker are STRONGLY
    preferred over merely-nearby ones — window-level alerts only carry one
    representative flow's endpoint, and an unrelated window that happens to
    land near a burst in time (ambient traffic, or — see
    COLAB_SETUP.md's "Bonus" section and the capture-filter troubleshooting
    in README.md — the pipeline's own uncaptured-filter traffic) is not
    evidence about that burst just because the clock lines up.

    Returns {burst_index: [alerts]}.
    """
    by_burst = {i: [] for i in range(len(bursts))}
    for a in alerts:
        ts = a.get("timestamp")
        if not ts:
            continue
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        is_attacker_endpoint = a.get("src_ip") == attacker_ip or a.get("dst_ip") == attacker_ip
        effective_pad = pad_seconds if is_attacker_endpoint else min(pad_seconds, 15)
        best_i, best_dist = None, None
        for i, (_label, start, end, _burst) in enumerate(bursts):
            if start <= t <= end:
                dist = 0.0
            elif t > end:
                dist = (t - end).total_seconds()
            else:
                continue  # alert before this burst even started — not this burst's
            if dist > effective_pad:
                continue
            if best_dist is None or dist < best_dist:
                best_i, best_dist = i, dist
        if best_i is not None:
            by_burst[best_i].append((is_attacker_endpoint, a))

    # Within each burst, if any attacker-endpoint alerts exist, drop the
    # merely-nearby ones entirely rather than let them compete for "top".
    result = {}
    for i, tagged in by_burst.items():
        attacker_matched = [a for is_match, a in tagged if is_match]
        result[i] = attacker_matched if attacker_matched else [a for _is_match, a in tagged]
    return result


_FAST_LOG_TS_RE = re.compile(r"^(\d{2})/(\d{2})/(\d{4})-(\d{2}):(\d{2}):(\d{2})\.(\d+)")


def parse_fast_log(path, attacker_ip, start, end, utc_offset_hours):
    """
    Suricata fast.log line count for this attacker within [start, end].
    fast.log timestamps have no timezone marker — they're local time — so
    this converts each line's timestamp to UTC using utc_offset_hours before
    comparing against start/end (which come from nids_history.json's
    timezone-aware ISO timestamps).
    """
    if not path or not os.path.exists(path):
        return 0
    count = 0
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                if attacker_ip not in line:
                    continue
                m = _FAST_LOG_TS_RE.match(line)
                if not m:
                    continue
                mo, day, year, hh, mm, ss, _frac = m.groups()
                local_t = datetime(int(year), int(mo), int(day), int(hh), int(mm), int(ss))
                t = local_t.replace(tzinfo=timezone(timedelta(hours=utc_offset_hours))).astimezone(timezone.utc)
                if start <= t <= end:
                    count += 1
    except OSError:
        return 0
    return count


def summarize_role1(flows):
    labels = Counter(f.get("r1_label", "Unknown") for f in flows)
    n_flagged = sum(1 for f in flows if f.get("r1_is_attack"))
    top_label = None
    top_conf = 0
    for f in flows:
        if f.get("r1_is_attack") and f.get("r1_conf", 0) >= top_conf:
            top_conf = f.get("r1_conf", 0)
            top_label = f.get("r1_label")
    return n_flagged, len(flows), top_label, top_conf, labels


def main():
    args = parse_args()
    target_ip = args.target or own_ip() or "this host"

    a_flows = load_history_flows(args.nids_history)
    b_alerts = load_unified_alerts(args.unified_alerts)

    if not a_flows and not b_alerts:
        print("No data found in either nids_history.json or unified_alerts.jsonl — nothing to summarize.")
        sys.exit(1)

    attacker_ip = args.attacker or detect_attacker_ip(a_flows, target_ip)
    if not attacker_ip:
        print("Could not auto-detect an attacker IP from nids_history.json flows.")
        print("Pass --attacker <ip> explicitly.")
        sys.exit(1)

    utc_offset_hours = round(
        (datetime.now() - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds() / 3600
    )

    bursts = cluster_bursts(a_flows, attacker_ip, args.gap)

    # Label bursts, tracking order among port-80 (DoS/Web Attack) bursts
    # separately so the first-seen one becomes DoS, second becomes Web Attack.
    labelled = []
    port80_seen = 0
    for burst in bursts:
        dst_ports = [f["dst_port"] for f in burst if f.get("src_ip") == attacker_ip]
        is_port80_ambiguous = bool(dst_ports) and 80 in dst_ports and Counter(dst_ports).most_common(1)[0][0] != 22 and len(set(dst_ports)) <= 15
        label = label_burst(burst, attacker_ip, port80_seen if is_port80_ambiguous else 0)
        if is_port80_ambiguous:
            port80_seen += 1
        start = datetime.fromisoformat(burst[0]["timestamp"])
        end = datetime.fromisoformat(burst[-1]["timestamp"])
        labelled.append((label, start, end, burst))

    lines = []
    lines.append("# Live attack detection — summary")
    lines.append("")
    lines.append(f"**Target (NIDS host):** {target_ip}  ")
    lines.append(f"**Attacker (auto-detected):** {attacker_ip}  ")
    lines.append(f"**Attack bursts found:** {len(labelled)} (grouped by >{args.gap:.0f}s quiet gaps)  ")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append(
        "Attack type is inferred from destination port and arrival order "
        "(see script docstring) — a best-effort labelling for this "
        "project's known 4-attack test sequence, not a general classifier."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Detection table")
    lines.append("")
    lines.append("| Attack | Window (local) | Flows | Approach A (heuristic/ML) | Approach B (window verdict) | Suricata signatures |")
    lines.append("|---|---|---|---|---|---|")

    alerts_by_burst = assign_alerts_to_nearest_burst(b_alerts, labelled, attacker_ip)

    for i, (label, start, end, burst) in enumerate(labelled):
        n_flagged, n_total, top_label, top_conf, _dist = summarize_role1(burst)
        a_cell = (
            f"**{'YES' if n_flagged else 'NO'}** — {top_label} @ {top_conf:.0f}% ({n_flagged}/{n_total} flows)"
            if n_flagged else f"NO ({n_total} flows, all Benign)"
        )

        overlapping = alerts_by_burst.get(i, [])
        non_benign = [a for a in overlapping if a.get("final_verdict") not in BENIGN_WORDS
                      and a.get("attack_type", "").lower() not in BENIGN_WORDS]
        if non_benign:
            top = max(non_benign, key=lambda a: a.get("confidence", 0))
            b_cell = f"**YES** — {top.get('attack_type')} @ {top.get('confidence')}% ({top.get('severity')})"
        elif overlapping:
            b_cell = f"NO ({len(overlapping)} window(s), all benign)"
        else:
            b_cell = "no window observed in range"

        suri_count = parse_fast_log(args.suricata_fast_log, attacker_ip, start, end, utc_offset_hours)
        suri_cell = f"{suri_count} alert line(s)" if suri_count else "0 / not available"

        window_str = f"{start.strftime('%H:%M:%S')}–{end.strftime('%H:%M:%S')}"
        lines.append(f"| {label} | {window_str} | {len(burst)} | {a_cell} | {b_cell} | {suri_cell} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Notes for the thesis write-up")
    lines.append("")
    lines.append("- **Detected** means at least one flow/window in that attack's time range got a non-benign verdict — report the exact confidence/label from the table, not just yes/no.")
    lines.append("- Approach B's window may lag the attack by up to ~90s (pcap rotation + processing) — windows are matched with that padding.")
    lines.append("- Suricata counts are line-matches on the attacker's IP in `fast.log` within the burst window; treat as indicative (fast.log has no timezone marker).")
    lines.append("- If a burst's label looks wrong (e.g. port-80 order swapped), rerun with `--gap` adjusted or pass `--attacker` explicitly — the clustering assumes clean gaps between attacks per ATTACKER_COMMANDS.md.")
    lines.append("")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        fh.write("\n".join(lines))

    print(f"Wrote {args.out}")
    print()
    print("\n".join(lines[:20]))


if __name__ == "__main__":
    main()
