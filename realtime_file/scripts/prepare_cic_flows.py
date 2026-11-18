#!/usr/bin/env python3
"""
scripts/prepare_cic_flows.py
=============================
Build offline evaluation flow files directly from CIC's own labelled CSVs, one
per capture day. No pcap extraction, no label join.

WHY THIS REPLACES THE EXTRACTION STEP
-------------------------------------
The CICIDS2017 sub-model was trained on features whose names are snake_case
(`flow_duration`, `fwd_pkt_len_min`, `init_bwd_win_byts`) and whose durations
are in MICROSECONDS (training median for flow_duration: 50,600).

Three possible offline flow sources:

  python-cicflowmeter CSV  durations in SECONDS, lengths include L2/L3/L4
                           headers. Measured drift: flow_duration ratio 6e-7,
                           fwd_pkt_len_min 2 -> 71. Role 1 collapsed to a
                           single class: 0.00% recall on 75,884 attack flows
                           at 99.9% confidence. UNUSABLE.

  Java CICFlowMeter        correct units, but needs a headless CLI class, the
                           jnetpcap native library, and hours of CPU on an
                           8.8 GB pcap under a session that can die at any time.

  CIC labelled CSVs        the SAME extractor that produced the training set.
                           Units and definitions match by construction. Labels
                           already present. Costs seconds.
                           <- this script

Verified: all 25 sampled trained feature names resolve against CIC's headers
through cicflow_reader's normaliser + alias map, so the pipeline consumes these
files unchanged.

ONE FILE PER DAY, AND WHY IT MATTERS
------------------------------------
Each CICIDS2017 day is a separate capture with its own clock, and Role 3 reads
Suricata output that only exists for days whose pcap you actually ran.
Concatenating all days into one file would (a) apply a single alignment offset
to five different clocks, and (b) invite fusion metrics on days where Role 3
has no input at all.

So: each day is aligned independently against its own eve.json and written
separately. The summary states, per day, whether fusion can be scored or only
Role 1.

THE TIMESTAMP PROBLEM THIS SOLVES
---------------------------------
CIC writes timestamps in 12-hour clock WITHOUT AM/PM: 13:55 appears as
"7/7/2017 1:55". Parsed naively, every afternoon flow lands 12 hours early --
which is why the 5-tuple label join calibrated an offset of -21.006 h rather
than a clean timezone value.

Repair: CICIDS2017 was captured during working hours (roughly 08:00-18:00
local), so any parsed hour below 8 is an afternoon time and 12 hours are added.
This is specific to this capture and is stated as such.

USAGE
-----
    # every day found in the directory
    python scripts/prepare_cic_flows.py \
        --cic_labels data/cic_labels/ \
        --eve_dir    data/eve_logs/ \
        --out_dir    data/cicflow_csv_labelled/

    # one day, with a single unnamed eve.json
    python scripts/prepare_cic_flows.py \
        --cic_labels data/cic_labels/ --days friday \
        --eve_dir data/eve_logs/eve.json --eve_day friday \
        --out_dir data/cicflow_csv_labelled/
"""

import os
import sys
import glob
import json
import argparse
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd                                       # noqa: E402

from src.engine.label_map import to_family                # noqa: E402

# CICIDS2017 working-hours capture window, local time. Used only to
# disambiguate CIC's 12-hour timestamps.
CAPTURE_FIRST_HOUR = 8

# CIC ships one CSV per capture segment; several segments share a day, and each
# DAY is one continuous capture with its own clock.
DAY_ORDER = ["monday", "tuesday", "wednesday", "thursday", "friday"]


def parse_args():
    p = argparse.ArgumentParser(
        description="Build offline flows from CIC labelled CSVs (no pcap)."
    )
    p.add_argument("--cic_labels", required=True,
                   help="Directory of *_ISCX.csv labelled files (searched "
                        "recursively).")
    p.add_argument("--out_dir", required=True,
                   help="Directory for the per-day CSVs.")
    p.add_argument("--eve_dir", default=None,
                   help="Suricata eve.json file, or a directory of them. The "
                        "day is taken from the filename or path.")
    p.add_argument("--eve_day", default=None,
                   help="Day to attribute an eve.json whose name carries no "
                        "day (e.g. a bare 'eve.json').")
    p.add_argument("--days", default=None,
                   help="Comma-separated subset, e.g. 'friday,tuesday'. "
                        "Default: every day found.")
    p.add_argument("--offset_hours", type=float, default=None,
                   help="Force the shift applied to every day instead of "
                        "calibrating per day against eve.json.")
    p.add_argument("--no_ampm_fix", action="store_true",
                   help="Skip the 12-hour timestamp repair. Only if your copy "
                        "already has 24-hour times.")
    return p.parse_args()


def day_of(path: str) -> str:
    # Basename only. Matching the whole path made
    # cic_labels/friday/Monday-WorkingHours.pcap_ISCX.csv ambiguous: the path
    # contains both "friday" and "monday", so the answer depended on
    # DAY_ORDER rather than on the file.
    low = os.path.basename(path).lower()
    for d in DAY_ORDER:
        if d in low:
            return d
    return "unknown"


def _find_col(df, *names):
    norm = {c.strip().lower(): c for c in df.columns}
    for n in names:
        c = norm.get(n.strip().lower())
        if c:
            return c
    return None


def _read_csv_any_encoding(path: str):
    # cp1252 BEFORE latin-1: the en dash in "Web Attack - XSS" is byte 0x96,
    # which latin-1 decodes to a C1 control instead of U+2013 and never raises,
    # silently corrupting the label so the whole Web Attack family drops out of
    # per-family accuracy.
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return pd.read_csv(path, low_memory=False, encoding=enc,
                               on_bad_lines="skip")
        except UnicodeDecodeError:
            continue
    return None


def index_cic_by_day(path: str, days=None) -> dict:
    """
    Return {day: [csv paths]} WITHOUT reading them.

    Two reasons this does not return DataFrames:
      * Memory. Holding all five days at once is ~2.8M rows x 85 columns and
        ran the machine out of memory. Each day is loaded, written and freed
        inside process_day(), so peak usage is one day.
      * Duplicates. A file can appear under more than one directory --
        cic_labels/friday/ here holds all eight files while cic_labels/monday/
        holds Monday again. Loading both silently doubled Monday's flow count.
        De-duplicating by basename fixes that; day comes from the filename.
    """
    files = sorted(glob.glob(os.path.join(path, "**", "*.csv"), recursive=True))
    if not files:
        raise FileNotFoundError(f"No CSVs under {path}")

    seen, groups, dupes = {}, {}, []
    for f in files:
        base = os.path.basename(f)
        if base in seen:
            dupes.append((base, f))
            continue
        seen[base] = f
        d = day_of(f)
        if days and d not in days:
            continue
        groups.setdefault(d, []).append(f)

    if dupes:
        print(f"    de-duplicated {len(dupes)} repeated file(s) "
              f"(same name in more than one directory):")
        for base, f in dupes[:5]:
            print(f"      skipped {os.path.relpath(f, path)}  "
                  f"(already have {os.path.relpath(seen[base], path)})")

    for d in DAY_ORDER + ["unknown"]:
        for f in groups.get(d, []):
            print(f"    [{d:<9}] {os.path.basename(f)}")

    return {d: groups[d] for d in DAY_ORDER + ["unknown"] if d in groups}


def load_day(paths: list):
    """Read one day's CSVs, normalising Timestamp/Label per file."""
    frames = []
    for f in paths:
        df = _read_csv_any_encoding(f)
        if df is None or df.empty:
            print(f"    ! unreadable, skipped: {os.path.basename(f)}")
            continue
        df.columns = df.columns.str.strip()

        # Normalise per file, before any concat. CIC is not consistent across
        # segments, and a header differing by one character becomes an all-NaN
        # column after concat.
        ts_c = _find_col(df, "Timestamp", "Time stamp", "TimeStamp", "Time")
        lb_c = _find_col(df, "Label", "label", "Class")
        if ts_c is None or lb_c is None:
            print(f"    XX  {os.path.basename(f)}: missing "
                  f"{'Timestamp' if ts_c is None else 'Label'} -- SKIPPED")
            continue
        ren = {}
        if ts_c != "Timestamp":
            ren[ts_c] = "Timestamp"
        if lb_c != "Label":
            ren[lb_c] = "Label"
        if ren:
            print(f"          renamed {ren}")
            df = df.rename(columns=ren)

        df["__src"] = os.path.basename(f)
        print(f"      loaded {os.path.basename(f):<52} {len(df):>9,} rows")
        frames.append(df)
    if not frames:
        return None
    return pd.concat(frames, ignore_index=True)


# CIC is inconsistent across segments: some files are d/m/Y, some m/d/Y, some
# carry seconds and some do not, and a few use AM/PM. One pandas call with one
# convention silently returns NaT for whatever does not match it.
_TS_FORMATS = [
    "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",    "%m/%d/%Y %H:%M",
    "%d/%m/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p",
    "%d/%m/%Y %I:%M %p",    "%m/%d/%Y %I:%M %p",
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
]


def parse_cic_timestamps(series: pd.Series, ampm_fix: bool) -> pd.Series:
    raw = series.astype(str).str.strip()
    ts = pd.to_datetime(raw, format="mixed", dayfirst=True, errors="coerce")

    # Recover whatever the first convention missed, reporting what each pass
    # rescued so the fallback can never quietly reinterpret the whole file.
    if ts.isna().any():
        for fmt in _TS_FORMATS:
            miss = ts.isna()
            if not miss.any():
                break
            retry = pd.to_datetime(raw[miss], format=fmt, errors="coerce")
            n = int(retry.notna().sum())
            if n:
                print(f"    recovered {n:,} timestamps with format '{fmt}'")
                ts.loc[miss] = retry

    # Distinguish EMPTY from MALFORMED. They are not the same failure:
    #   empty     -> blank padding rows; CIC files carry them (the Thursday
    #                morning file reads 458,968 rows, of which 288,602 are
    #                blank). Dropping them yields exactly the published label
    #                counts, so this is correct, not data loss.
    #   malformed -> a real value in a format we do not handle. That IS a bug
    #                and must stop the run.
    blank_tokens = {"", "nan", "NaN", "NaT", "None", "null", "-"}
    is_blank = raw.isin(blank_tokens) | raw.isna()
    n_blank = int((ts.isna() & is_blank).sum())
    n_malformed = int((ts.isna() & ~is_blank).sum())

    if n_blank:
        print(f"    dropped {n_blank:,} rows with an EMPTY timestamp "
              f"(blank padding, not a parse failure)")
    if n_malformed:
        print(f"    ! {n_malformed:,} timestamps have a value that no known "
              f"format parses")
        print(f"      sample raw values: "
              f"{raw[ts.isna() & ~is_blank].head(5).tolist()}")

    # The 12-hour repair MUST run before returning. An earlier edit placed the
    # return above this block, which skipped it silently: Monday came out as
    # 01:00-12:59 instead of 08:55-17:01, and Friday's calibrated offset went
    # from +3h to +11h with a 12h/8h span mismatch.
    if ampm_fix:
        early = ts.dt.hour < CAPTURE_FIRST_HOUR
        n = int(early.sum())
        if n:
            print(f"    12-hour repair: +12h on {n:,} rows with hour < "
                  f"{CAPTURE_FIRST_HOUR}")
            ts = ts.where(~early, ts + pd.Timedelta(hours=12))
    return ts, n_malformed


def eve_time_range(eve_path: str):
    """
    Time span of a Suricata eve.json, robust to events from other runs.

    Plain min/max is not safe here. A real Friday eve.json reported
    2017-07-07 11:59 .. 2026-07-05 17:10 -- a 78,845-hour span -- because a
    later live-mode run had appended to the same file. That single stray event
    made the calibrated offset meaningless and would have put every flow in
    the wrong window.

    A pcap replay covers hours, so events far from the bulk of the file belong
    to a different capture. Anything more than 30 days from the median is
    excluded, and the exclusion is reported rather than hidden.
    """
    stamps = []
    with open(eve_path, "r", errors="replace") as fh:
        for line in fh:
            try:
                t = json.loads(line).get("timestamp")
            except Exception:
                continue
            if not t:
                continue
            try:
                stamps.append(datetime.fromisoformat(t).astimezone(timezone.utc))
            except ValueError:
                continue
    if not stamps:
        return None, None

    stamps.sort()
    median = stamps[len(stamps) // 2]
    window = timedelta(days=30)
    core = [d for d in stamps if abs(d - median) <= window]
    n_out = len(stamps) - len(core)
    if n_out:
        print(f"    !  {n_out:,}/{len(stamps):,} events lie >30 days from the "
              f"bulk of {os.path.basename(eve_path)} and were ignored")
        print(f"       (raw span {stamps[0]} .. {stamps[-1]})")
        print(f"       This file has events from more than one run. Regenerate "
              f"it from the pcap alone before trusting fusion results.")
    if not core:
        return None, None
    return core[0], core[-1]


def process_day(day: str, df: pd.DataFrame, args, eve_map: dict):
    """Align one day's flows and write them out. Returns a summary dict."""
    print(f"\n  == {day.upper()} ==  {len(df):,} flows")

    ts_col = _find_col(df, "Timestamp")
    lb_col = _find_col(df, "Label")
    if ts_col is None or lb_col is None:
        print("    XX  needs Timestamp and Label columns. This looks like the "
              "MachineLearningCVE release; use GeneratedLabelledFlows.")
        return None

    ts, n_malformed = parse_cic_timestamps(df[ts_col], not args.no_ampm_fix)

    # Attribute unparsed timestamps to their source file. A whole file failing
    # is a format problem worth fixing, not a few malformed rows worth
    # dropping, and the two are indistinguishable from a total alone.
    bad = ts.isna()
    if bad.any() and "__src" in df.columns:
        for src, n in df.loc[bad, "__src"].value_counts().items():
            tot = int((df["__src"] == src).sum())
            pct = n / tot * 100
            flag = "  <-- ENTIRE FILE" if pct > 99 else ""
            print(f"      unparsed: {src:<52} {n:>9,}/{tot:,} "
                  f"({pct:.1f}%){flag}")
            # Always show what failed. Restricting this to whole-file failures
            # meant a 62.9% failure printed a count and nothing actionable.
            failing = df.loc[bad & (df["__src"] == src), ts_col].head(4).tolist()
            good = df.loc[~bad & (df["__src"] == src), ts_col].head(2).tolist()
            print(f"        failing values: {failing}")
            if good:
                print(f"        parsed values : {good}")

    kept = int((~bad).sum())
    # Refuse only on MALFORMED values. Refusing on blanks rejected a Thursday
    # whose 458,968 surviving rows already matched the published CICIDS2017
    # label counts exactly.
    if n_malformed > len(df) * 0.01:
        print(f"    XX  {n_malformed:,} rows carry an unparseable timestamp "
              f"value ({n_malformed / len(df) * 100:.1f}%). Refusing to write "
              f"this day -- add the format shown above.")
        return None
    print(f"    kept {kept:,}/{len(df):,} rows with usable timestamps")

    df = df.loc[~bad].copy()
    ts = ts.dropna()
    if "__src" in df.columns:
        df = df.drop(columns=["__src"])
    print(f"    as written : {ts.min()} .. {ts.max()}")

    # Each day is its own capture with its own clock, so each needs its own
    # eve.json to align against. Days without one remain usable for Role-1-only
    # evaluation, where absolute time never enters the metric.
    eve = eve_map.get(day)
    fusion_ready = False
    if args.offset_hours is not None:
        shift = timedelta(hours=args.offset_hours)
        print(f"    offset     : forced {args.offset_hours:+.3f} h")
        fusion_ready = True
    elif eve:
        e0, e1 = eve_time_range(eve)
        if e0 is None:
            print(f"    !  no timestamps in {eve}; writing as UTC")
            shift = timedelta(0)
        else:
            shift = e0 - ts.min().tz_localize(timezone.utc)
            print(f"    eve        : {e0} .. {e1}")
            print(f"    offset     : calibrated "
                  f"{shift.total_seconds() / 3600:+.3f} h")
            fusion_ready = True
            span_c = (ts.max() - ts.min()).total_seconds()
            span_e = (e1 - e0).total_seconds()
            if span_e > 0 and not (0.8 <= span_c / span_e <= 1.25):
                print(f"    !  span mismatch: flows {span_c / 3600:.2f}h vs "
                      f"events {span_e / 3600:.2f}h - may not be the same "
                      f"capture")
                fusion_ready = False
    else:
        shift = timedelta(0)
        print("    offset     : none (no eve.json for this day)")
        print("                 ROLE-1 EVALUATION ONLY - Role 3 reads Suricata")
        print("                 output, which needs this day's pcap.")

    aligned = ts.dt.tz_localize(timezone.utc) + shift
    df["Timestamp"] = aligned.dt.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    if ts_col != "Timestamp":
        df = df.drop(columns=[ts_col])
    if lb_col != "Label":
        df = df.rename(columns={lb_col: "Label"})
    df["Label"] = df["Label"].astype(str).str.strip()

    counts = df["Label"].value_counts()
    n_attack = int(sum(n for lbl, n in counts.items()
                       if to_family(lbl) not in (None, "Benign")))
    for lbl, n in counts.items():
        print(f"      {str(lbl)[:34]:<36} {n:>9,}  -> {to_family(lbl)}")

    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, f"CICIDS2017_{day}_flows.csv")
    df.to_csv(out_path, index=False)
    print(f"    OK  {out_path}  ({len(df):,} flows, "
          f"{os.path.getsize(out_path) / 1e6:.1f} MB)")

    # Monday is benign-only by design, so it cannot support precision or FPR on
    # its own - flag it rather than let it silently produce 0/0 metrics.
    if n_attack == 0:
        print("    !  benign-only day: fine as negatives, but precision and "
              "FPR are undefined on this day alone.")

    return {
        "day": day, "path": out_path, "flows": len(df),
        "benign": len(df) - n_attack, "attack": n_attack,
        "fusion_ready": fusion_ready,
        "families": sorted({to_family(lbl) for lbl in counts.index
                            if to_family(lbl) not in (None, "Benign")}),
    }


def build_eve_map(args) -> dict:
    eve_map = {}
    if not args.eve_dir:
        return eve_map
    cands = ([args.eve_dir] if os.path.isfile(args.eve_dir)
             else sorted(glob.glob(os.path.join(args.eve_dir, "**", "*.json"),
                                   recursive=True)))
    for c in cands:
        eve_map.setdefault(day_of(c), c)
    if args.eve_day and "unknown" in eve_map:
        eve_map[args.eve_day.lower()] = eve_map.pop("unknown")
    named = sorted(k for k in eve_map if k != "unknown")
    print(f"\n  eve.json found for: {named or 'none'}")
    if "unknown" in eve_map:
        print("  !  an eve.json carries no day in its name; pass --eve_day to "
              "attribute it, otherwise that day is Role-1 only.")
    return eve_map


def main():
    args = parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("=" * 74)
    print("  OFFLINE FLOWS FROM CIC LABELLED CSVs  (per day, no pcap)")
    print("=" * 74)

    eve_map = build_eve_map(args)
    days = ([d.strip().lower() for d in args.days.split(",")]
            if args.days else None)

    print(f"\n[1/2] Loading {args.cic_labels}")
    groups = index_cic_by_day(args.cic_labels, days)
    if not groups:
        print("  XX  no CSVs matched")
        return 1

    print("\n[2/2] Aligning and writing, one file per day")
    import gc
    results = []
    for d, paths in groups.items():
        df = load_day(paths)
        if df is None:
            continue
        r = process_day(d, df, args, eve_map)
        if r:
            results.append(r)
        del df
        gc.collect()          # one day at a time; five at once exhausts RAM
    if not results:
        return 1

    print("\n" + "=" * 74)
    print(f"  {'day':<11}{'flows':>11}{'benign':>11}{'attack':>10}  "
          f"{'fusion':<8}families")
    tot = ta = tb = 0
    for r in results:
        tot += r["flows"]
        ta += r["attack"]
        tb += r["benign"]
        print(f"  {r['day']:<11}{r['flows']:>11,}{r['benign']:>11,}"
              f"{r['attack']:>10,}  {'yes' if r['fusion_ready'] else 'NO':<8}"
              f"{', '.join(r['families']) or '-'}")
    print(f"  {'TOTAL':<11}{tot:>11,}{tb:>11,}{ta:>10,}")

    fusion_days = [r["day"] for r in results if r["fusion_ready"]]
    print(f"\n  Track B (fusion) can run on : {fusion_days or 'NONE'}")
    print(f"  Role-1 evaluation can run on: all {len(results)} day(s)")
    if len(fusion_days) < len(results):
        print("\n  Days without eve.json cannot be scored for fusion: Role 3")
        print("  reads Suricata output, which needs that day's raw pcap. Run")
        print("  Suricata on those pcaps, or scope Track B to the days you")
        print("  have and state that scope explicitly.")

    summary = os.path.join(args.out_dir, "prepare_summary.json")
    with open(summary, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\n  Summary: {summary}")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
