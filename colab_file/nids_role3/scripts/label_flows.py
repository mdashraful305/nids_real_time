#!/usr/bin/env python3
"""
scripts/label_flows.py
======================
One-time offline step: attach REAL CIC ground-truth labels to the flow CSV
produced locally by CICFlowMeter, so the evaluation pipeline has something
honest to score against.

Run this ONCE per capture. The pipeline then consumes the labelled CSV and
never has to guess.

WHY
───
CICFlowMeter is a feature extractor and emits no Label column. The pipeline
previously filled that gap with {"UNKNOWN": n}, which the evaluator scored
as a positive — making every ground-truth window an attack window, and
turning precision/FPR into arithmetic artefacts (tn=0, fp=0). See
src/ingestion/ground_truth.py for the full explanation and join method.

WHAT YOU NEED
─────────────
The **GeneratedLabelledFlows / TrafficLabelling_** release of CICIDS2017
(https://www.unb.ca/cic/datasets/ids-2017.html). NOT "MachineLearningCVE" —
that release strips the IP columns and cannot be 5-tuple joined.

    data/cic_labels/friday/
        Friday-WorkingHours-Morning.pcap_ISCX.csv
        Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
        Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

USAGE
─────
    python scripts/label_flows.py \
        --flow_csv   data/cicflow_csv/Friday-WorkingHours_flows.csv \
        --cic_labels data/cic_labels/friday/ \
        --out        data/cicflow_csv_labelled/Friday-WorkingHours_flows.csv

Writes alongside the CSV a <name>.join_report.json recording match rate and
the empirically calibrated timezone offset — both are methodology numbers
worth quoting in the thesis, and the offset feeds Phase 2.
"""

import os
import sys
import json
import argparse

# make `src` importable when run as scripts/label_flows.py from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd  # noqa: E402

from src.ingestion.cicflow_reader import load_cicflow_file  # noqa: E402
from src.ingestion.ground_truth import GroundTruthLabeller, UNMATCHED  # noqa: E402


def parse_args():
    p = argparse.ArgumentParser(
        description="Join CIC ground-truth labels onto locally extracted flows."
    )
    p.add_argument("--flow_csv", required=True,
                   help="Local CICFlowMeter CSV (unlabelled).")
    p.add_argument("--cic_labels", required=True,
                   help="Directory of official *_ISCX.csv labelled files.")
    p.add_argument("--out", required=True,
                   help="Output path for the labelled CSV.")
    p.add_argument("--tolerance", type=float, default=120.0,
                   help="Max seconds between CIC and local timestamp when "
                        "disambiguating a reused 5-tuple (default 120).")
    p.add_argument("--offset", type=float, default=None,
                   help="Force a timezone offset in seconds (cic_ts - our_ts). "
                        "Omit to calibrate it empirically (recommended).")
    p.add_argument("--drop_unmatched", action="store_true",
                   help="Drop unmatched flows from the output entirely instead "
                        "of keeping them tagged UNMATCHED.")
    p.add_argument("--min_match_rate", type=float, default=50.0,
                   help="Abort if match rate falls below this percentage "
                        "(default 50). Guards against joining the wrong day's "
                        "labels.")
    return p.parse_args()


def main():
    args = parse_args()

    print("═" * 72)
    print("  GROUND-TRUTH LABEL JOIN")
    print("═" * 72)
    print(f"  Flows  : {args.flow_csv}")
    print(f"  Labels : {args.cic_labels}")
    print(f"  Output : {args.out}")

    print("\n  Loading local flows ...")
    flows = load_cicflow_file(args.flow_csv)
    print(f"    {len(flows):,} flows, {len(flows.columns)} columns")

    if "Label" in flows.columns:
        print("\n  ⚠  Input already has a Label column — it will be overwritten "
              "by the join.")

    print("\n  Building CIC label index ...")
    labeller = GroundTruthLabeller(args.cic_labels, tolerance_seconds=args.tolerance)

    labelled, report = labeller.label_flows(flows, offset_seconds=args.offset)
    print(report.summary())

    # ── restore the ORIGINAL timestamp strings ───────────────────────────────
    # load_cicflow_file() parses Timestamp into datetimes. This script does not
    # call set_flow_utc_offset(), so naive local times were read as UTC and
    # would be written back as "...+00:00" — tz-aware and six hours wrong.
    # The pipeline can only apply an offset to NAIVE timestamps, so that baked
    # in the misalignment permanently and tripped the overlap guard with no way
    # to correct it downstream.
    #
    # Writing the untouched source strings keeps the labelled CSV byte-identical
    # to the input apart from the Label column, so the pipeline's timezone
    # auto-detection behaves exactly as it does on the raw file.
    _ts_src = None
    for cand in ("timestamp", "Timestamp", "flow_start"):
        try:
            _ts_src = pd.read_csv(args.flow_csv, usecols=[cand], low_memory=False)[cand]
            break
        except (ValueError, KeyError):
            continue

    if _ts_src is None:
        print("\n  ⚠  Could not re-read the original timestamp column; the output "
              "will carry parsed UTC timestamps. Check the pipeline's overlap "
              "report before trusting any fusion result.")
    elif len(_ts_src) != len(labelled):
        print(f"\n  ⚠  Row-count mismatch restoring timestamps "
              f"({len(_ts_src):,} source vs {len(labelled):,} labelled) — "
              "leaving parsed timestamps in place.")
    else:
        labelled["Timestamp"] = _ts_src.values
        print(f"  ✓ Original timestamp strings preserved "
              f"(e.g. {_ts_src.iloc[0]!r}) so the pipeline can apply the "
              f"timezone offset itself")

    if report.match_rate * 100 < args.min_match_rate:
        print(
            f"\n  ✗ ABORT: match rate {report.match_rate * 100:.2f}% is below "
            f"--min_match_rate {args.min_match_rate}%.\n"
            "    Likely causes:\n"
            "      • CIC label files are for a different day than this capture\n"
            "      • MachineLearningCVE release used (no IP columns)\n"
            "      • CICFlowMeter run over a filtered/truncated pcap\n"
            "    Nothing was written."
        )
        sys.exit(1)

    if args.drop_unmatched:
        before = len(labelled)
        labelled = labelled[labelled["Label"] != UNMATCHED].copy()
        print(f"\n  Dropped {before - len(labelled):,} UNMATCHED flows "
              f"({len(labelled):,} remain)")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    labelled.to_csv(args.out, index=False)
    print(f"\n  ✓ Labelled CSV written: {args.out} "
          f"({os.path.getsize(args.out) / 1e6:.1f} MB)")

    report_path = os.path.splitext(args.out)[0] + ".join_report.json"
    payload = report.to_dict()
    payload["flow_csv"] = args.flow_csv
    payload["cic_labels_dir"] = args.cic_labels
    payload["dropped_unmatched"] = bool(args.drop_unmatched)
    with open(report_path, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"  ✓ Join report written  : {report_path}")

    print("\n  NEXT STEPS")
    print("  ──────────")
    print(f"  1. Quote the match rate ({report.match_rate * 100:.2f}%) in your "
          "methodology section.")
    print(f"  2. The calibrated offset is {report.offset_seconds / 3600:+.3f} h "
          f"({report.offset_seconds:+.0f} s).")
    print("     Set this as `cicflow.timestamp_offset_seconds` in "
          "config/settings.yaml (Phase 2)")
    print("     so Role 1 flows and Role 3 Suricata events land in the SAME "
          "60-second window.")
    print("  3. Re-run the pipeline with --flow_dir pointing at the labelled "
          "directory.")
    print("═" * 72)


if __name__ == "__main__":
    main()
