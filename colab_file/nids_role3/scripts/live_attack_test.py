#!/usr/bin/env python3
"""
scripts/live_attack_test.py
===========================
Drive real attacks against a target while nids_web.py is capturing, and build
the live-detection table for the deployability section: attack -> detected?,
which role fired, confidence, time-to-alert.

HOW IT WORKS
------------
nids_web.py persists every classified flow to nids_history.json (and serves
/api/flows). This script, for each attack:
  1. snapshots the current flow set,
  2. launches the attack command,
  3. waits --settle seconds for NFStream + Role 1 + the LLM queue to catch up,
  4. snapshots again and reports the NEW flows involving the target, with their
     Role 1 verdict, confidence, and how long after attack start they appeared.

It does NOT itself sniff packets — nids_web is the detector under test; this is
the attacker + scorer around it. Run nids_web.py FIRST, in another terminal,
capturing the interface the attacks traverse.

SAFETY / AUTHORISATION
----------------------
Only run against a host you own or are explicitly authorised to test (your own
VM / lab target). The attack commands need sudo. This is standard authorised
security testing of your own NIDS; do not point it at anything else.

USAGE
-----
    # terminal 1
    sudo python nids_web.py --iface eth0 ...

    # terminal 2
    sudo python scripts/live_attack_test.py \
        --target 10.0.0.5 \
        --history nids_history.json \
        --settle 25 \
        --out data/results/live_attack_results.json

Add --dry_run to print the commands without executing (to review first).
Override any command with --nmap/--hping3/--hydra/--nikto "full command".
"""

import os
import sys
import json
import time
import shlex
import argparse
import subprocess
from datetime import datetime, timezone


def parse_args():
    p = argparse.ArgumentParser(description="Live attack detection test vs nids_web.")
    p.add_argument("--target", required=True, help="Authorised target IP.")
    p.add_argument("--history", default="nids_history.json",
                   help="nids_web.py state file to read detections from.")
    p.add_argument("--settle", type=int, default=25,
                   help="Seconds to wait after each attack for detection.")
    p.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt")
    p.add_argument("--dry_run", action="store_true")
    p.add_argument("--out", default=None)
    # per-attack command overrides (else sensible defaults are built)
    p.add_argument("--nmap", default=None)
    p.add_argument("--hping3", default=None)
    p.add_argument("--hydra", default=None)
    p.add_argument("--nikto", default=None)
    p.add_argument("--only", default=None,
                   help="Comma list to run a subset: nmap,hping3,hydra,nikto")
    return p.parse_args()


def default_attacks(a):
    t = a.target
    return {
        "PortScan (nmap)":   a.nmap   or f"nmap -sS -p 1-1000 {t}",
        "DoS (hping3)":      a.hping3 or f"hping3 -S --flood -c 2000 -p 80 {t}",
        "Brute Force (hydra)": a.hydra or (
            f"hydra -l root -P {a.wordlist} -t 4 -f ssh://{t}"),
        "Web Attack (nikto)": a.nikto or f"nikto -h http://{t}",
    }


def load_flows(path):
    if not os.path.exists(path):
        return []
    try:
        d = json.load(open(path, errors="replace"))
    except Exception:
        return []
    return d.get("flows", d if isinstance(d, list) else [])


def flow_key(f):
    return (f.get("src_ip"), f.get("dst_ip"), f.get("src_port"),
            f.get("dst_port"), f.get("timestamp") or f.get("time"))


def involves_target(f, target):
    return target in (str(f.get("src_ip")), str(f.get("dst_ip")))


def summarise_new(before_keys, after, target):
    """New target-related flows and whether any was flagged an attack."""
    new = [f for f in after
           if flow_key(f) not in before_keys and involves_target(f, target)]
    flagged = [f for f in new
               if str(f.get("r1_verdict", f.get("verdict", ""))).lower()
               not in ("benign", "", "normal")]
    return new, flagged


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    attacks = default_attacks(args)
    if args.only:
        want = {s.strip().lower() for s in args.only.split(",")}
        attacks = {k: v for k, v in attacks.items()
                   if any(w in k.lower() for w in want)}

    print("=" * 74)
    print("  LIVE ATTACK DETECTION TEST  (vs nids_web.py)")
    print("=" * 74)
    print(f"  target  : {args.target}")
    print(f"  history : {args.history}")
    print(f"  settle  : {args.settle}s\n")

    if not os.path.exists(args.history) and not args.dry_run:
        print(f"  !  {args.history} not found. Is nids_web.py running and")
        print(f"     writing history? Start it first, then re-run this.")

    results = []
    for name, cmd in attacks.items():
        print(f"  ── {name} ──")
        print(f"     $ {cmd}")
        if args.dry_run:
            results.append({"attack": name, "command": cmd, "dry_run": True})
            continue

        before = load_flows(args.history)
        before_keys = {flow_key(f) for f in before}
        t0 = time.time()
        t0_iso = datetime.now(timezone.utc).isoformat()

        try:
            subprocess.run(shlex.split(cmd), timeout=args.settle + 60,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            print(f"     !  tool not installed — skipping")
            results.append({"attack": name, "command": cmd,
                            "error": "tool not installed"})
            continue

        time.sleep(args.settle)
        after = load_flows(args.history)
        new, flagged = summarise_new(before_keys, after, args.target)

        detected = len(flagged) > 0
        # time-to-alert: earliest flagged flow timestamp minus attack start
        tta = None
        if flagged:
            try:
                ts = [datetime.fromisoformat(
                        str(f.get("timestamp") or f.get("time"))).timestamp()
                      for f in flagged if (f.get("timestamp") or f.get("time"))]
                if ts:
                    tta = round(min(ts) - t0, 1)
            except Exception:
                tta = None
        first_role = "Role1" if detected else "-"
        top = max(flagged, key=lambda f: float(f.get("r1_confidence",
                  f.get("confidence", 0)) or 0), default=None)

        print(f"     new target flows : {len(new)}   flagged attack : {len(flagged)}")
        print(f"     DETECTED         : {'YES' if detected else 'NO'}"
              + (f"   first role: {first_role}" if detected else ""))
        if top:
            print(f"     top verdict      : "
                  f"{top.get('r1_verdict', top.get('verdict', '?'))} "
                  f"@ {top.get('r1_confidence', top.get('confidence', '?'))}%")
        if tta is not None:
            print(f"     time-to-alert    : ~{tta}s")
        print()

        results.append({
            "attack": name, "command": cmd, "start": t0_iso,
            "new_target_flows": len(new), "flagged_attack": len(flagged),
            "detected": detected, "first_role": first_role,
            "time_to_alert_s": tta,
            "top_verdict": (top.get("r1_verdict", top.get("verdict"))
                            if top else None),
            "top_confidence": (top.get("r1_confidence", top.get("confidence"))
                               if top else None),
        })

    # ── table ────────────────────────────────────────────────────────────────
    print("=" * 74)
    print("  LIVE DETECTION SUMMARY")
    print(f"  {'attack':<22}{'detected':>10}{'role':>8}{'conf':>8}{'TTA(s)':>9}")
    print("  " + "-" * 57)
    for r in results:
        if r.get("dry_run"):
            continue
        print(f"  {r['attack']:<22}"
              f"{('YES' if r.get('detected') else 'NO'):>10}"
              f"{str(r.get('first_role', '-')):>8}"
              f"{str(r.get('top_confidence', '-')):>8}"
              f"{str(r.get('time_to_alert_s', '-')):>9}")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".",
                    exist_ok=True)
        json.dump({"target": args.target, "settle_s": args.settle,
                   "results": results}, open(args.out, "w"), indent=2)
        print(f"\n  saved: {args.out}")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
