"""
src/ingestion/ground_truth.py
==============================
Attaches REAL ground-truth labels to CICFlowMeter flows by joining them
against the CIC-published labelled CSVs for CICIDS2017.

WHY THIS MODULE EXISTS
──────────────────────
The flow CSVs produced locally (python-cicflowmeter / CICFlowMeterV3 run
over the raw pcap) carry NO Label column — CICFlowMeter is a feature
extractor, not a labeller. Before this module existed, the pipeline hit
this fallback in cicflow_reader.label_summary():

    if "Label" not in df.columns:
        return {"UNKNOWN": len(df)}

...and ThesisEvaluator then classified the literal string "UNKNOWN" as
"attack" (it is not in BENIGN_LABELS). The consequence was that EVERY
ground-truth window was scored as a positive, giving tn=0 and fp=0, and
therefore precision=100% and FPR=0% as pure arithmetic artefacts of an
all-positive test set. "Combined accuracy = 100%" was simply the score
for always answering "attack".

This module replaces that guess with a real label, derived by joining on
the network 5-tuple plus timestamp against the official CIC labels.

THE JOIN
────────
Two-stage, self-calibrating:

  Stage 0 (calibration) — the local flow CSV and the CIC CSV disagree on
      timezone (the local capture was processed on a UTC+6 machine; CIC's
      published timestamps are in the original capture's local time). We
      do NOT hardcode an offset. Instead we take flows whose 5-tuple is
      UNIQUE in the CIC file, compute (cic_ts - our_ts) for each, and use
      the median as the empirical offset. This is reported and is itself
      a methodology number worth quoting.

  Stage 1 (unique 5-tuple)   — unambiguous, no time needed.
  Stage 2 (ambiguous 5-tuple)— port reuse means one 5-tuple maps to
      several CIC rows; disambiguate by nearest timestamp after applying
      the Stage-0 offset, within `tolerance_seconds`.

Flows that match nothing are labelled UNMATCHED and are EXCLUDED from
evaluation — never silently coerced to benign or attack. The match rate
is returned so it can be reported honestly.

DIRECTIONALITY
──────────────
CICFlowMeter assigns "source" to whichever host sent the first packet, and
that assignment can differ between two runs over the same pcap. Each
5-tuple is therefore looked up in both orientations
(src,sport,dst,dport) and (dst,dport,src,sport).

WHICH CIC FILES YOU NEED
────────────────────────
Use the **GeneratedLabelledFlows / TrafficLabelling_** release, NOT the
"MachineLearningCVE" release. MachineLearningCVE strips the IP columns
(it begins at " Destination Port"), so a 5-tuple join is impossible with
it. This module raises a clear error if the IP columns are absent.

    Friday-WorkingHours-Morning.pcap_ISCX.csv
    Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
    Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

USAGE
─────
    from src.ingestion.ground_truth import GroundTruthLabeller

    gt = GroundTruthLabeller("data/cic_labels/friday/")
    labelled_df, report = gt.label_flows(flows_df)
    print(report.summary())
"""

import os
import glob
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.utils.logger import get_logger

log = get_logger(__name__)

UNMATCHED = "UNMATCHED"


class CalibrationError(RuntimeError):
    """
    Raised when the timezone offset between the local flows and the CIC
    labels cannot be established from the data.

    Deliberately fatal. The predecessor of this code silently defaulted to a
    0-second offset on failure, which is the single worst option available:
    the join still "succeeds", every ambiguous 5-tuple resolves to the wrong
    label or to UNMATCHED, and nothing downstream indicates the labels are
    fiction. Prefer a stopped run to a plausible-looking wrong one.
    """

# Column-name variants across the CIC labelled releases. The published
# CSVs have a leading space on most headers; we strip before matching.
_CIC_COLUMN_CANDIDATES = {
    "src_ip":    ["Source IP", "Src IP", "SourceIP"],
    "src_port":  ["Source Port", "Src Port", "SourcePort"],
    "dst_ip":    ["Destination IP", "Dst IP", "DestinationIP"],
    "dst_port":  ["Destination Port", "Dst Port", "DestinationPort"],
    "protocol":  ["Protocol"],
    "timestamp": ["Timestamp"],
    "label":     ["Label"],
}

# CIC publishes timestamps in several inconsistent formats across files.
_CIC_TS_FORMATS = [
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
]


@dataclass
class JoinReport:
    """Everything a reviewer will ask about the labelling step."""
    n_flows: int = 0
    n_cic_rows: int = 0
    n_matched_unique: int = 0        # Stage 1
    n_matched_time: int = 0          # Stage 2
    n_unmatched: int = 0
    offset_seconds: float = 0.0      # empirically calibrated
    offset_n_samples: int = 0
    offset_mad_seconds: float = 0.0  # median absolute deviation -> confidence
    tolerance_seconds: float = 0.0
    label_counts: Dict[str, int] = field(default_factory=dict)

    @property
    def n_matched(self) -> int:
        return self.n_matched_unique + self.n_matched_time

    @property
    def match_rate(self) -> float:
        return self.n_matched / self.n_flows if self.n_flows else 0.0

    def to_dict(self) -> dict:
        return {
            "n_flows": self.n_flows,
            "n_cic_rows": self.n_cic_rows,
            "n_matched": self.n_matched,
            "n_matched_unique_5tuple": self.n_matched_unique,
            "n_matched_by_timestamp": self.n_matched_time,
            "n_unmatched": self.n_unmatched,
            "match_rate_pct": round(self.match_rate * 100, 2),
            "calibrated_offset_seconds": round(self.offset_seconds, 1),
            "calibrated_offset_hours": round(self.offset_seconds / 3600, 3),
            "offset_n_samples": self.offset_n_samples,
            "offset_mad_seconds": round(self.offset_mad_seconds, 1),
            "tolerance_seconds": self.tolerance_seconds,
            "label_counts": self.label_counts,
        }

    def summary(self) -> str:
        lines = [
            "",
            "  ── GROUND-TRUTH JOIN REPORT " + "─" * 40,
            f"    Local flows           : {self.n_flows:,}",
            f"    CIC labelled rows     : {self.n_cic_rows:,}",
            f"    Matched (unique 5-tup): {self.n_matched_unique:,}",
            f"    Matched (by timestamp): {self.n_matched_time:,}",
            f"    UNMATCHED (excluded)  : {self.n_unmatched:,}",
            f"    MATCH RATE            : {self.match_rate * 100:.2f}%",
            f"    Calibrated tz offset  : {self.offset_seconds / 3600:+.3f} h "
            f"({self.offset_seconds:+.0f} s, n={self.offset_n_samples:,}, "
            f"MAD={self.offset_mad_seconds:.1f}s)",
        ]
        if self.label_counts:
            lines.append("    Label distribution:")
            total = sum(self.label_counts.values())
            for lbl, cnt in sorted(
                self.label_counts.items(), key=lambda kv: -kv[1]
            ):
                lines.append(
                    f"      {lbl:<28} {cnt:>10,}  ({cnt / total * 100:5.2f}%)"
                )
        lines.append("  " + "─" * 68)
        return "\n".join(lines)


def _resolve_columns(df: pd.DataFrame) -> Dict[str, str]:
    """Map our canonical keys onto whatever the CIC file actually uses."""
    stripped = {c.strip(): c for c in df.columns}
    resolved = {}
    for key, candidates in _CIC_COLUMN_CANDIDATES.items():
        for cand in candidates:
            if cand in stripped:
                resolved[key] = stripped[cand]
                break
    return resolved


def _parse_cic_timestamp(value) -> Optional[datetime]:
    if pd.isna(value):
        return None
    s = str(value).strip()
    if not s:
        return None
    for fmt in _CIC_TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _as_naive_utc(ts) -> Optional[float]:
    """Return POSIX seconds for a timestamp, handling tz-aware and naive."""
    if ts is None or pd.isna(ts):
        return None
    if isinstance(ts, np.datetime64):
        ts = pd.Timestamp(ts)
    if isinstance(ts, pd.Timestamp):
        ts = ts.to_pydatetime()
    if not isinstance(ts, datetime):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.timestamp()


class GroundTruthLabeller:
    """
    Joins locally-extracted CICFlowMeter flows to the official CIC labels.

    Parameters
    ----------
    cic_label_dir     : directory holding *_ISCX.csv labelled files
    tolerance_seconds : max |cic_ts - (our_ts + offset)| accepted in Stage 2
    """

    def __init__(
        self,
        cic_label_dir: str,
        tolerance_seconds: float = 120.0,
        min_calibration_samples: int = 20,
    ):
        self.cic_label_dir     = cic_label_dir
        self.tolerance_seconds = tolerance_seconds
        self.min_calibration_samples = min_calibration_samples
        # key -> list of (posix_seconds, label)
        self._index: Dict[Tuple, List[Tuple[float, str]]] = defaultdict(list)
        self._n_cic_rows = 0
        self._loaded = False

    # ── loading ──────────────────────────────────────────────────────────────

    def load(self) -> "GroundTruthLabeller":
        if self._loaded:
            return self

        if not os.path.isdir(self.cic_label_dir):
            raise FileNotFoundError(
                f"CIC label directory not found: {self.cic_label_dir}\n"
                "Download the GeneratedLabelledFlows / TrafficLabelling_ release "
                "from https://www.unb.ca/cic/datasets/ids-2017.html and place the "
                "*_ISCX.csv files there. The MachineLearningCVE release will NOT "
                "work: it strips the IP columns needed for a 5-tuple join."
            )

        paths = sorted(glob.glob(os.path.join(self.cic_label_dir, "*.csv")))
        if not paths:
            raise FileNotFoundError(
                f"No CSV files in {self.cic_label_dir}"
            )

        for path in paths:
            self._load_one(path)

        if not self._index:
            raise ValueError(
                f"Loaded {len(paths)} CIC file(s) from {self.cic_label_dir} but "
                "built an empty index — check the files actually contain "
                "Source IP / Destination IP / Label columns."
            )

        log.info(
            "Ground-truth index built: %d distinct 5-tuples from %d CIC rows",
            len(self._index), self._n_cic_rows,
        )
        self._loaded = True
        return self

    def _load_one(self, path: str) -> None:
        df = None
        # cp1252 BEFORE latin-1. The CIC CSVs are Windows-1252, where the en
        # dash in "Web Attack – XSS" is byte 0x96. latin-1 decodes 0x96 to the
        # C1 control U+0096 rather than U+2013, so the label no longer matches
        # any taxonomy entry and the whole Web Attack family silently drops out
        # of per-family accuracy (observed as 'Web Attack � XSS'). Trying
        # utf-8 first is still correct — it fails loudly on 0x96 — but latin-1
        # must never win ahead of cp1252, because latin-1 never raises.
        for enc in ("utf-8", "cp1252", "latin-1"):
            try:
                df = pd.read_csv(
                    path, low_memory=False, encoding=enc, on_bad_lines="skip"
                )
                if enc != "utf-8":
                    log.info("%s decoded as %s", os.path.basename(path), enc)
                break
            except UnicodeDecodeError:
                continue
        if df is None or df.empty:
            log.warning("Could not read CIC label file: %s", path)
            return

        cols = _resolve_columns(df)
        required = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "label")
        missing = [k for k in required if k not in cols]
        if missing:
            raise ValueError(
                f"{os.path.basename(path)} is missing required column(s): "
                f"{missing}.\nThis is almost certainly the 'MachineLearningCVE' "
                "release, which strips IP columns. Use the "
                "'GeneratedLabelledFlows' / 'TrafficLabelling_' release instead."
            )

        has_ts = "timestamp" in cols
        if not has_ts:
            log.warning(
                "%s has no Timestamp column — Stage-2 disambiguation disabled "
                "for its rows", os.path.basename(path)
            )

        labels = df[cols["label"]].astype(str).str.strip()
        src_ip = df[cols["src_ip"]].astype(str).str.strip()
        dst_ip = df[cols["dst_ip"]].astype(str).str.strip()
        src_pt = pd.to_numeric(df[cols["src_port"]], errors="coerce")
        dst_pt = pd.to_numeric(df[cols["dst_port"]], errors="coerce")
        proto  = pd.to_numeric(df[cols["protocol"]], errors="coerce")

        if has_ts:
            ts_parsed = df[cols["timestamp"]].apply(_parse_cic_timestamp)
            ts_secs = ts_parsed.apply(
                lambda t: t.replace(tzinfo=timezone.utc).timestamp()
                if t is not None else np.nan
            ).to_numpy(dtype=float)
        else:
            ts_secs = np.full(len(df), np.nan, dtype=float)

        n_added = 0
        for sip, spt, dip, dpt, pr, ts, lbl in zip(
            src_ip.to_numpy(), src_pt.to_numpy(), dst_ip.to_numpy(),
            dst_pt.to_numpy(), proto.to_numpy(), ts_secs, labels.to_numpy(),
        ):
            if pd.isna(spt) or pd.isna(dpt) or pd.isna(pr):
                continue
            key = (sip, int(spt), dip, int(dpt), int(pr))
            self._index[key].append((float(ts), str(lbl)))
            n_added += 1

        self._n_cic_rows += n_added
        log.info(
            "  %s: indexed %d rows, labels=%s",
            os.path.basename(path), n_added,
            dict(labels.value_counts().head(8)),
        )

    # ── key extraction from OUR flows ────────────────────────────────────────

    @staticmethod
    def _our_keys(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Build forward and reverse 5-tuple keys for our flow DataFrame.
        Accepts either the raw python-cicflowmeter names or the canonical
        CIC names that cicflow_reader's alias map produces.
        """
        def pick(*names):
            for n in names:
                if n in df.columns:
                    return df[n]
            raise KeyError(
                f"None of {names} present in flow DataFrame. Columns: "
                f"{list(df.columns)[:15]}..."
            )

        # Accept every spelling the readers can produce. cicflow_reader's
        # alias map normalises dst_port to the CICIDS2017 training feature
        # name "Destination Port" but leaves src_port as "Src Port", so a
        # fixed two-name lookup here missed the destination column entirely.
        # Reuse the CIC candidate lists and add the raw snake_case names.
        sip = pick(*_CIC_COLUMN_CANDIDATES["src_ip"], "src_ip") \
            .astype(str).str.strip().to_numpy()
        dip = pick(*_CIC_COLUMN_CANDIDATES["dst_ip"], "dst_ip") \
            .astype(str).str.strip().to_numpy()
        spt = pd.to_numeric(
            pick(*_CIC_COLUMN_CANDIDATES["src_port"], "src_port"), errors="coerce"
        ).to_numpy()
        dpt = pd.to_numeric(
            pick(*_CIC_COLUMN_CANDIDATES["dst_port"], "dst_port"), errors="coerce"
        ).to_numpy()
        pr  = pd.to_numeric(
            pick("Protocol", "protocol"), errors="coerce"
        ).to_numpy()

        fwd = np.empty(len(df), dtype=object)
        rev = np.empty(len(df), dtype=object)
        for i in range(len(df)):
            if np.isnan(spt[i]) or np.isnan(dpt[i]) or np.isnan(pr[i]):
                fwd[i] = rev[i] = None
                continue
            s, d, p = int(spt[i]), int(dpt[i]), int(pr[i])
            fwd[i] = (sip[i], s, dip[i], d, p)
            rev[i] = (dip[i], d, sip[i], s, p)
        return fwd, rev

    def _lookup(self, fwd, rev) -> Optional[List[Tuple[float, str]]]:
        if fwd is not None:
            hit = self._index.get(fwd)
            if hit:
                return hit
        if rev is not None:
            hit = self._index.get(rev)
            if hit:
                return hit
        return None

    # ── the join ─────────────────────────────────────────────────────────────

    def label_flows(
        self,
        flows_df: pd.DataFrame,
        offset_seconds: Optional[float] = None,
    ) -> Tuple[pd.DataFrame, JoinReport]:
        """
        Return (flows_df + 'Label' column, JoinReport).

        offset_seconds : if None, calibrated empirically from unique-5-tuple
                         matches (recommended). Pass a number to force it.
        """
        self.load()

        report = JoinReport(
            n_flows=len(flows_df),
            n_cic_rows=self._n_cic_rows,
            tolerance_seconds=self.tolerance_seconds,
        )
        if flows_df.empty:
            out = flows_df.copy()
            out["Label"] = pd.Series(dtype=str)
            return out, report

        fwd_keys, rev_keys = self._our_keys(flows_df)

        our_ts = None
        for ts_col in ("Timestamp", "timestamp"):
            if ts_col in flows_df.columns:
                our_ts = np.array(
                    [_as_naive_utc(t) for t in flows_df[ts_col].to_numpy()],
                    dtype=object,
                )
                break

        # ── Stage 0: calibrate the offset from unambiguous matches ──────────
        if offset_seconds is None:
            offset_seconds, n_samp, mad = self._calibrate_offset(
                fwd_keys, rev_keys, our_ts
            )
            report.offset_n_samples = n_samp
            report.offset_mad_seconds = mad
        report.offset_seconds = float(offset_seconds)

        log.info(
            "Ground-truth join: applying offset %+.1f s (%.3f h) to local "
            "timestamps before matching",
            offset_seconds, offset_seconds / 3600,
        )

        # ── Stage 1 + 2 ──────────────────────────────────────────────────────
        labels = np.empty(len(flows_df), dtype=object)
        for i in range(len(flows_df)):
            candidates = self._lookup(fwd_keys[i], rev_keys[i])
            if not candidates:
                labels[i] = UNMATCHED
                report.n_unmatched += 1
                continue

            distinct = {lbl for _, lbl in candidates}
            if len(distinct) == 1:
                labels[i] = candidates[0][1]
                report.n_matched_unique += 1
                continue

            # ambiguous: same 5-tuple, different labels at different times
            t = our_ts[i] if our_ts is not None else None
            if t is None:
                labels[i] = UNMATCHED
                report.n_unmatched += 1
                continue

            target = t + offset_seconds
            best_lbl, best_gap = None, float("inf")
            for cts, lbl in candidates:
                if np.isnan(cts):
                    continue
                gap = abs(cts - target)
                if gap < best_gap:
                    best_gap, best_lbl = gap, lbl
            if best_lbl is not None and best_gap <= self.tolerance_seconds:
                labels[i] = best_lbl
                report.n_matched_time += 1
            else:
                labels[i] = UNMATCHED
                report.n_unmatched += 1

        out = flows_df.copy()
        out["Label"] = labels
        report.label_counts = (
            pd.Series(labels).value_counts().to_dict()
        )
        return out, report

    def _calibrate_offset(
        self, fwd_keys, rev_keys, our_ts, max_samples: int = 20000
    ) -> Tuple[float, int, float]:
        """
        Empirically derive (cic_ts - our_ts) from flows whose 5-tuple maps to
        exactly ONE CIC row with a parseable timestamp. Median is robust to
        the minority of flows CICFlowMeter times differently.

        Returns (median_offset_seconds, n_samples, median_abs_deviation).
        """
        if our_ts is None:
            raise CalibrationError(
                "Local flows have no usable Timestamp column, so the "
                "timezone offset between them and the CIC labels cannot be "
                "calibrated.\n"
                "Pass --offset explicitly if you know it, but be aware that "
                "an uncalibrated join silently mislabels every flow whose "
                "5-tuple is reused."
            )

        deltas = []
        n = len(fwd_keys)
        # stride so we sample across the whole capture, not just its head
        stride = max(1, n // max_samples)
        for i in range(0, n, stride):
            t = our_ts[i]
            if t is None:
                continue
            candidates = self._lookup(fwd_keys[i], rev_keys[i])
            if not candidates or len(candidates) != 1:
                continue
            cts = candidates[0][0]
            if np.isnan(cts):
                continue
            deltas.append(cts - t)

        if len(deltas) < self.min_calibration_samples:
            raise CalibrationError(
                f"Offset calibration found only {len(deltas)} unambiguous "
                f"5-tuple matches (need {self.min_calibration_samples}).\n"
                "Refusing to fall back to a 0-second offset: if the two "
                "sources really are 6 hours apart, a 0 offset silently sends "
                "every ambiguous flow to UNMATCHED and mislabels the rest, "
                "which is how the earlier all-positive evaluation set arose.\n"
                "Likely causes:\n"
                "  • the CIC label files are for a different day than this capture\n"
                "  • the 'MachineLearningCVE' release was used (no IP columns)\n"
                "  • the pcap was filtered before CICFlowMeter ran\n"
                "Pass --offset <seconds> to override deliberately."
            )

        arr = np.array(deltas, dtype=float)
        median = float(np.median(arr))
        mad = float(np.median(np.abs(arr - median)))
        log.info(
            "Offset calibrated from %d unambiguous 5-tuple matches: "
            "%+.1f s (MAD %.1f s)", len(arr), median, mad,
        )
        if mad > 60:
            log.warning(
                "Offset MAD is %.1f s — the two sources disagree on time in a "
                "way a constant offset does not explain. Inspect before "
                "trusting the labels.", mad,
            )
        return median, len(arr), mad
