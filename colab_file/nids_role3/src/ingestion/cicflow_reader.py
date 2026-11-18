"""
src/ingestion/cicflow_reader.py
================================
Parse CICFlowMeter CSV output files.

PERFORMANCE FIX (v2)
─────────────────────
The old filter_by_window() built a full boolean mask over the entire
DataFrame for every window (O(n) per call, O(chunks * n) total). With
561,816 flows and ~600 windows that is ~337 million comparisons.

Fix: filter_by_window_fast() sorts the DataFrame by Timestamp ONCE
(callers should sort once up front — load_cicflow_directory already
does this) and uses np.searchsorted (binary search) to slice the
window in O(log n) per call instead of O(n).

The old filter_by_window() (boolean mask) is kept for backward
compatibility; log_chunker.py and unified_pipeline.py now use the
fast path.

MEMORY FIX (v3)
─────────────────
load_cicflow_file() now downcasts float64 numeric columns to float32
after loading (measured ~38% memory reduction, and matches the
float32 dtype the ML models already expect at inference time — see
_predict_universal() / _predict_single() in unified_pipeline.py, which
cast to np.float32 anyway). This is not the primary bottleneck at
your scale (~0.45 GB full-size) but is essentially free to apply.
"""

import os
import pandas as pd
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from src.utils.logger import get_logger

log = get_logger(__name__)

# Sentinel written by src/ingestion/ground_truth.GroundTruthLabeller for flows
# that could not be joined to an official CIC label. Kept in sync there.
# Such flows are EXCLUDED from ground truth rather than coerced to a class.
UNMATCHED_LABEL = "UNMATCHED"

# ── column name normalisation ────────────────────────────────────────────────
# Maps every schema we might read onto the CANONICAL CICIDS2017 / CICFlowMeter-V3
# names that the models were trained on.
#
# WHY THE FULL MAP IS NEEDED
# ──────────────────────────
# The previous version of this dict covered 16 names, and the ones that mattered
# listed spellings the actual CSV does not use — it had "total_fwd_packets"
# while python-cicflowmeter emits "tot_fwd_pkts", and "init_win_bytes_forward"
# while the CSV has "init_fwd_win_byts". Anything unmapped fell through to
# _predict_universal(), which zero-fills missing features and only required a
# 30% match to proceed. The result was Role 1 confidently classifying vectors
# that were mostly 0.0 — silently, with no warning anywhere.
#
# Keys are lower-cased and stripped before lookup, so both " Flow Duration"
# (CIC's published CSVs have leading spaces) and "flow_duration"
# (python-cicflowmeter) resolve to the same canonical name.
COLUMN_ALIASES = {
    # ── identity / metadata ──────────────────────────────────────────────────
    "timestamp":                  "Timestamp",
    "flow_start":                 "Timestamp",
    "label":                      "Label",
    "src_ip":                     "Src IP",
    "source ip":                  "Src IP",
    "source_ip":                  "Src IP",
    "dst_ip":                     "Dst IP",
    "destination ip":             "Dst IP",
    "destination_ip":             "Dst IP",
    "src_port":                   "Src Port",
    "source port":                "Src Port",
    "dst_port":                   "Destination Port",
    "destination port":           "Destination Port",
    "protocol":                   "Protocol",
    "flow_id":                    "Flow ID",
    "flow id":                    "Flow ID",

    # ── duration / rates ─────────────────────────────────────────────────────
    "flow_duration":              "Flow Duration",
    "flow duration":              "Flow Duration",
    "flow_byts_s":                "Flow Bytes/s",
    "flow bytes/s":               "Flow Bytes/s",
    "flow_pkts_s":                "Flow Packets/s",
    "flow packets/s":             "Flow Packets/s",
    "fwd_pkts_s":                 "Fwd Packets/s",
    "fwd packets/s":              "Fwd Packets/s",
    "bwd_pkts_s":                 "Bwd Packets/s",
    "bwd packets/s":              "Bwd Packets/s",

    # ── packet / byte counts ─────────────────────────────────────────────────
    "tot_fwd_pkts":               "Total Fwd Packets",
    "total fwd packets":          "Total Fwd Packets",
    "total_fwd_packets":          "Total Fwd Packets",
    "tot_bwd_pkts":               "Total Backward Packets",
    "total backward packets":     "Total Backward Packets",
    "total_backward_packets":     "Total Backward Packets",
    "totlen_fwd_pkts":            "Total Length of Fwd Packets",
    "total length of fwd packets": "Total Length of Fwd Packets",
    "totlen_bwd_pkts":            "Total Length of Bwd Packets",
    "total length of bwd packets": "Total Length of Bwd Packets",

    # ── per-direction packet lengths ─────────────────────────────────────────
    "fwd_pkt_len_max":            "Fwd Packet Length Max",
    "fwd packet length max":      "Fwd Packet Length Max",
    "fwd_pkt_len_min":            "Fwd Packet Length Min",
    "fwd packet length min":      "Fwd Packet Length Min",
    "fwd_pkt_len_mean":           "Fwd Packet Length Mean",
    "fwd packet length mean":     "Fwd Packet Length Mean",
    "fwd_pkt_len_std":            "Fwd Packet Length Std",
    "fwd packet length std":      "Fwd Packet Length Std",
    "bwd_pkt_len_max":            "Bwd Packet Length Max",
    "bwd packet length max":      "Bwd Packet Length Max",
    "bwd_pkt_len_min":            "Bwd Packet Length Min",
    "bwd packet length min":      "Bwd Packet Length Min",
    "bwd_pkt_len_mean":           "Bwd Packet Length Mean",
    "bwd packet length mean":     "Bwd Packet Length Mean",
    "bwd_pkt_len_std":            "Bwd Packet Length Std",
    "bwd packet length std":      "Bwd Packet Length Std",

    # ── aggregate packet lengths ─────────────────────────────────────────────
    # NOTE the asymmetry in CIC's own naming: min/max use "Packet Length",
    # mean/std/variance use "Packet Length" too but Min/Max are prefixed.
    "pkt_len_max":                "Max Packet Length",
    "max packet length":          "Max Packet Length",
    "pkt_len_min":                "Min Packet Length",
    "min packet length":          "Min Packet Length",
    "pkt_len_mean":               "Packet Length Mean",
    "packet length mean":         "Packet Length Mean",
    "pkt_len_std":                "Packet Length Std",
    "packet length std":          "Packet Length Std",
    "pkt_len_var":                "Packet Length Variance",
    "packet length variance":     "Packet Length Variance",
    "pkt_size_avg":               "Average Packet Size",
    "average packet size":        "Average Packet Size",

    # ── headers / segments ───────────────────────────────────────────────────
    "fwd_header_len":             "Fwd Header Length",
    "fwd header length":          "Fwd Header Length",
    "fwd header length.1":        "Fwd Header Length.1",
    "bwd_header_len":             "Bwd Header Length",
    "bwd header length":          "Bwd Header Length",
    "fwd_seg_size_min":           "min_seg_size_forward",
    "min_seg_size_forward":       "min_seg_size_forward",
    "fwd_seg_size_avg":           "Avg Fwd Segment Size",
    "avg fwd segment size":       "Avg Fwd Segment Size",
    "bwd_seg_size_avg":           "Avg Bwd Segment Size",
    "avg bwd segment size":       "Avg Bwd Segment Size",
    "fwd_act_data_pkts":          "act_data_pkt_fwd",
    "act_data_pkt_fwd":           "act_data_pkt_fwd",

    # ── inter-arrival times ──────────────────────────────────────────────────
    "flow_iat_mean":              "Flow IAT Mean",
    "flow iat mean":              "Flow IAT Mean",
    "flow_iat_std":               "Flow IAT Std",
    "flow iat std":               "Flow IAT Std",
    "flow_iat_max":               "Flow IAT Max",
    "flow iat max":               "Flow IAT Max",
    "flow_iat_min":               "Flow IAT Min",
    "flow iat min":               "Flow IAT Min",
    "fwd_iat_tot":                "Fwd IAT Total",
    "fwd iat total":              "Fwd IAT Total",
    "fwd_iat_mean":               "Fwd IAT Mean",
    "fwd iat mean":               "Fwd IAT Mean",
    "fwd_iat_std":                "Fwd IAT Std",
    "fwd iat std":                "Fwd IAT Std",
    "fwd_iat_max":                "Fwd IAT Max",
    "fwd iat max":                "Fwd IAT Max",
    "fwd_iat_min":                "Fwd IAT Min",
    "fwd iat min":                "Fwd IAT Min",
    "bwd_iat_tot":                "Bwd IAT Total",
    "bwd iat total":              "Bwd IAT Total",
    "bwd_iat_mean":               "Bwd IAT Mean",
    "bwd iat mean":               "Bwd IAT Mean",
    "bwd_iat_std":                "Bwd IAT Std",
    "bwd iat std":                "Bwd IAT Std",
    "bwd_iat_max":                "Bwd IAT Max",
    "bwd iat max":                "Bwd IAT Max",
    "bwd_iat_min":                "Bwd IAT Min",
    "bwd iat min":                "Bwd IAT Min",

    # ── TCP flags ────────────────────────────────────────────────────────────
    "fwd_psh_flags":              "Fwd PSH Flags",
    "fwd psh flags":              "Fwd PSH Flags",
    "bwd_psh_flags":              "Bwd PSH Flags",
    "bwd psh flags":              "Bwd PSH Flags",
    "fwd_urg_flags":              "Fwd URG Flags",
    "fwd urg flags":              "Fwd URG Flags",
    "bwd_urg_flags":              "Bwd URG Flags",
    "bwd urg flags":              "Bwd URG Flags",
    "fin_flag_cnt":               "FIN Flag Count",
    "fin flag count":             "FIN Flag Count",
    "syn_flag_cnt":               "SYN Flag Count",
    "syn flag count":             "SYN Flag Count",
    "rst_flag_cnt":               "RST Flag Count",
    "rst flag count":             "RST Flag Count",
    "psh_flag_cnt":               "PSH Flag Count",
    "psh flag count":             "PSH Flag Count",
    "ack_flag_cnt":               "ACK Flag Count",
    "ack flag count":             "ACK Flag Count",
    "urg_flag_cnt":               "URG Flag Count",
    "urg flag count":             "URG Flag Count",
    "ece_flag_cnt":               "ECE Flag Count",
    "ece flag count":             "ECE Flag Count",
    # python-cicflowmeter's cwr_flag_count corresponds to CIC's "CWE Flag Count"
    # (CIC's own header is a long-standing typo for the CWR flag).
    "cwr_flag_count":             "CWE Flag Count",
    "cwe flag count":             "CWE Flag Count",
    "cwr_flag_cnt":               "CWE Flag Count",
    "down_up_ratio":              "Down/Up Ratio",
    "down/up ratio":              "Down/Up Ratio",

    # ── window sizes ─────────────────────────────────────────────────────────
    "init_fwd_win_byts":          "Init_Win_bytes_forward",
    "init_win_bytes_forward":     "Init_Win_bytes_forward",
    "init_bwd_win_byts":          "Init_Win_bytes_backward",
    "init_win_bytes_backward":    "Init_Win_bytes_backward",

    # ── active / idle ────────────────────────────────────────────────────────
    "active_mean":                "Active Mean",
    "active mean":                "Active Mean",
    "active_std":                 "Active Std",
    "active std":                 "Active Std",
    "active_max":                 "Active Max",
    "active max":                 "Active Max",
    "active_min":                 "Active Min",
    "active min":                 "Active Min",
    "idle_mean":                  "Idle Mean",
    "idle mean":                  "Idle Mean",
    "idle_std":                   "Idle Std",
    "idle std":                   "Idle Std",
    "idle_max":                   "Idle Max",
    "idle max":                   "Idle Max",
    "idle_min":                   "Idle Min",
    "idle min":                   "Idle Min",

    # ── bulk-transfer averages ───────────────────────────────────────────────
    "fwd_byts_b_avg":             "Fwd Avg Bytes/Bulk",
    "fwd avg bytes/bulk":         "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg":             "Fwd Avg Packets/Bulk",
    "fwd avg packets/bulk":       "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg":           "Fwd Avg Bulk Rate",
    "fwd avg bulk rate":          "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg":             "Bwd Avg Bytes/Bulk",
    "bwd avg bytes/bulk":         "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg":             "Bwd Avg Packets/Bulk",
    "bwd avg packets/bulk":       "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg":           "Bwd Avg Bulk Rate",
    "bwd avg bulk rate":          "Bwd Avg Bulk Rate",

    # ── subflows ─────────────────────────────────────────────────────────────
    "subflow_fwd_pkts":           "Subflow Fwd Packets",
    "subflow fwd packets":        "Subflow Fwd Packets",
    "subflow_fwd_byts":           "Subflow Fwd Bytes",
    "subflow fwd bytes":          "Subflow Fwd Bytes",
    "subflow_bwd_pkts":           "Subflow Bwd Packets",
    "subflow bwd packets":        "Subflow Bwd Packets",
    "subflow_bwd_byts":           "Subflow Bwd Bytes",
    "subflow bwd bytes":          "Subflow Bwd Bytes",
}

CHUNK_FEATURES = [
    # Both spellings listed: cicflow_reader emits "Destination Port"
    # (the CICIDS2017 training feature name); CIC labelled releases and
    # older CICFlowMeter builds emit "Dst Port". Display code keeps
    # whichever is present, so listing both costs nothing.
    "Src IP", "Src Port", "Dst IP", "Destination Port", "Dst Port", "Protocol",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Bwd Packet Length Max",
    "Flow Bytes/s", "Flow Packets/s",
    "Init_Win_bytes_backward", "Init_Win_bytes_forward",
    "Fwd PSH Flags", "Bwd PSH Flags", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count",
    "Label",
]


# ── Timezone alignment ───────────────────────────────────────────────────────
# CICFlowMeter writes NAIVE local wall-clock timestamps (no offset marker).
# Suricata writes ISO-8601 WITH an offset (e.g. "...T17:59:39.599128+0600").
#
# The previous code stamped the naive CICFlowMeter value as UTC:
#     datetime.strptime(...).replace(tzinfo=timezone.utc)
# On a UTC+6 machine that makes each flow appear SIX HOURS LATER than the
# Suricata event describing the very same packets. Consequences observed on
# the CICIDS2017 Friday capture:
#   • chunker spanned min(eve)=11:59Z .. max(flow)=02:02Z = 842 windows
#     instead of ~483, with 615 of them containing zero flows;
#   • in every window that did have flows, Role 1 and Role 3 were describing
#     traffic six hours apart, so all agreement/conflict statistics measured
#     the offset rather than model disagreement.
#
# Fix: interpret the naive value in the capture machine's timezone. Set
# `_FLOW_UTC_OFFSET` via set_flow_utc_offset() — the pipeline auto-detects it
# from the offset Suricata recorded in eve.json, since both artefacts came
# from the same machine processing the same pcap.
_FLOW_UTC_OFFSET: timedelta = timedelta(0)


def set_flow_utc_offset(offset: timedelta) -> None:
    """
    Set the UTC offset used to interpret naive CICFlowMeter timestamps.

    Module-level rather than per-call because the parse function is invoked
    from pandas .apply() inside sqlite_store.build_flow_index(), where
    threading an argument through would mean changing the chunked-read path
    as well. Set it once, before any flow loading.
    """
    global _FLOW_UTC_OFFSET
    _FLOW_UTC_OFFSET = offset
    log.info(
        "CICFlowMeter naive timestamps will be interpreted as UTC%+.2fh",
        offset.total_seconds() / 3600,
    )


def get_flow_utc_offset() -> timedelta:
    return _FLOW_UTC_OFFSET


def normalise_feature_name(name: str) -> str:
    """
    Reduce a feature name to a canonical comparison key.

    Needed on BOTH sides of the match, not just the incoming CSV. The models
    were trained from the Kaggle MachineLearningCVE release of CICIDS2017,
    whose headers carry leading spaces (" Flow Duration", " Destination
    Port"). If the pkl stored those names verbatim, exact string equality
    against a cleaned CSV column matches nothing — and the pipeline's response
    to "no match" was to zero-fill and predict anyway.

    Collapses: case, surrounding whitespace, underscores/hyphens/spaces,
    and the "/s" vs "_s" rate suffix. Deliberately conservative — it must not
    merge two genuinely different features.

        " Flow Duration"   -> "flowduration"
        "flow_duration"    -> "flowduration"
        "Flow Bytes/s"     -> "flowbytess"
        "flow_byts_s"      -> "flowbytss"     (differs -> alias map handles it)
    """
    if name is None:
        return ""
    s = str(name).strip().lower()
    for ch in (" ", "_", "-", ".", "/"):
        s = s.replace(ch, "")
    return s


def build_feature_lookup(available_columns) -> dict:
    """
    Map normalised feature name -> actual column name present in the data.

    Each column is registered under BOTH its own normalised name and the
    normalised form of its canonical alias, so a model trained on
    "Total Fwd Packets" resolves against a DataFrame that still calls the
    column "tot_fwd_pkts". Registering only the column's own name leaves the
    two vocabularies unable to meet: normalise("Total Fwd Packets") is
    "totalfwdpackets" while normalise("tot_fwd_pkts") is "totfwdpkts", and
    nothing bridges them.

    Use with resolve_feature() to align a model's trained feature list to
    whatever the current DataFrame calls those columns.
    """
    lookup = {}
    for col in available_columns:
        lookup.setdefault(normalise_feature_name(col), col)
        canonical = COLUMN_ALIASES.get(str(col).strip().lower())
        if canonical:
            lookup.setdefault(normalise_feature_name(canonical), col)
    return lookup


def resolve_feature(model_feature: str, lookup: dict) -> Optional[str]:
    """
    Find the column in the data corresponding to a model's trained feature
    name, tolerating whitespace/case/separator differences, and falling back
    through COLUMN_ALIASES for genuinely different spellings.
    """
    direct = lookup.get(normalise_feature_name(model_feature))
    if direct is not None:
        return direct
    alias = COLUMN_ALIASES.get(str(model_feature).strip().lower())
    if alias is not None:
        return lookup.get(normalise_feature_name(alias))
    return None


def _parse_cicflow_timestamp(ts_str: str) -> Optional[datetime]:
    """
    Parse CICFlowMeter timestamp strings (multiple known formats).

    Naive values are interpreted in the timezone set by
    set_flow_utc_offset() — NOT blindly as UTC. Values that already carry an
    offset are respected as-is.
    """
    if pd.isna(ts_str) or not str(ts_str).strip():
        return None
    ts_str = str(ts_str).strip()

    # Some CICFlowMeter builds emit ISO-8601 with an explicit offset.
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is not None:
            return dt
    except ValueError:
        pass

    formats = [
        "%m/%d/%Y %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            naive = datetime.strptime(ts_str, fmt)
            return naive.replace(tzinfo=timezone(_FLOW_UTC_OFFSET))
        except ValueError:
            continue
    log.debug("Could not parse CICFlow timestamp: %s", ts_str)
    return None


def load_cicflow_file(path: str) -> pd.DataFrame:
    """Load a single CICFlowMeter CSV into a cleaned DataFrame."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"CICFlowMeter CSV not found: {path}")

    log.info("Loading CICFlowMeter CSV: %s", path)

    df = None
    for enc in ["utf-8", "latin-1", "cp1252"]:
        try:
            df = pd.read_csv(path, low_memory=False, encoding=enc, on_bad_lines="skip")
            break
        except UnicodeDecodeError:
            continue

    if df is None or df.empty:
        raise ValueError(f"Could not read CSV: {path}")

    df.columns = df.columns.str.strip()

    rename_map = {}
    for col in df.columns:
        alias = COLUMN_ALIASES.get(col.lower().strip())
        if alias and alias != col:
            rename_map[col] = alias
    if rename_map:
        df = df.rename(columns=rename_map)
        log.debug("Renamed columns: %s", rename_map)

    if "Timestamp" in df.columns:
        df["Timestamp"] = df["Timestamp"].apply(_parse_cicflow_timestamp)
    else:
        log.warning("No Timestamp column found in %s — time-window matching will be disabled", path)
        df["Timestamp"] = None

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

    # MEMORY FIX: downcast float64 -> float32. The ML models cast to
    # float32 at inference time anyway (see unified_pipeline.py), so
    # this loses no precision that mattered and saves ~35-40% memory
    # on the numeric columns, which are the bulk of a CICFlowMeter CSV.
    float_cols = df.select_dtypes(include=["float64"]).columns.tolist()
    if float_cols:
        df[float_cols] = df[float_cols].astype(np.float32)

    if "Label" in df.columns:
        df["Label"] = df["Label"].astype(str).str.strip()

    log.info(
        "Loaded %d flows, %d columns from %s",
        len(df), len(df.columns), os.path.basename(path),
    )
    return df


def load_cicflow_directory(directory: str) -> pd.DataFrame:
    """Load and merge all CSV files in a directory, sorted by Timestamp."""
    csv_files = sorted(
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.endswith(".csv")
    )
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {directory}")

    frames = []
    for path in csv_files:
        try:
            frames.append(load_cicflow_file(path))
        except Exception as exc:
            log.warning("Skipping %s: %s", path, exc)

    if not frames:
        raise ValueError(f"No valid CSV files loaded from {directory}")

    df = pd.concat(frames, ignore_index=True)

    # IMPORTANT: sort + reset index so filter_by_window_fast's positional
    # searchsorted results map directly to .iloc[] correctly.
    if "Timestamp" in df.columns:
        df = df.sort_values("Timestamp", na_position="last").reset_index(drop=True)

    log.info(
        "Merged %d flows from %d files in %s",
        len(df), len(frames), directory,
    )
    return df


def filter_by_window(
    df: pd.DataFrame,
    window_start: datetime,
    window_end: datetime,
) -> pd.DataFrame:
    """
    LEGACY O(n) boolean-mask window filter — kept for backward compatibility.
    For repeated windowing over the same large DataFrame in a loop, use
    filter_by_window_fast() instead, which is O(log n) per call.
    """
    if "Timestamp" not in df.columns or df["Timestamp"].isna().all():
        return df.head(0)

    mask = (df["Timestamp"] >= window_start) & (df["Timestamp"] <= window_end)
    return df[mask].copy()


# ── FAST O(log n) window filter (performance fix) ─────────────────────────────

def filter_by_window_fast(
    df: pd.DataFrame,
    window_start: datetime,
    window_end: datetime,
    _sorted_ts_cache: dict = {},
) -> pd.DataFrame:
    """
    O(log n) window filter using np.searchsorted binary search.

    REQUIRES df to already be sorted by "Timestamp" ascending — this is
    guaranteed by load_cicflow_directory(), which sorts + resets the
    index before returning.

    Caches the extracted numpy timestamp array per DataFrame id() so
    repeated calls in a loop (one per chunk window) do not re-extract
    the column on every call.

    Parameters
    ----------
    df           : pd.DataFrame — already sorted by Timestamp, index reset
    window_start : datetime
    window_end   : datetime

    Returns
    -------
    pd.DataFrame — positional slice of df within [window_start, window_end]
    """
    if "Timestamp" not in df.columns or df["Timestamp"].isna().all():
        return df.head(0)

    key = id(df)
    ts = _sorted_ts_cache.get(key)
    if ts is None or len(ts) != len(df):
        # Convert to naive numpy datetime64 array once; cache by df identity.
        ts = df["Timestamp"].to_numpy()
        _sorted_ts_cache.clear()   # avoid unbounded growth across many DataFrames
        _sorted_ts_cache[key] = ts

    # np.searchsorted requires comparable dtypes — pandas Timestamp objects
    # compare fine against python datetime via the underlying object array.
    lo = np.searchsorted(ts, window_start, side="left")
    hi = np.searchsorted(ts, window_end,   side="right")
    return df.iloc[lo:hi]


def get_top_flows(
    df: pd.DataFrame,
    n: int = 15,
    sort_by: str = "Total Fwd Packets",
) -> pd.DataFrame:
    """Return top-N flows sorted by a feature (default: most active flows)."""
    if sort_by in df.columns:
        return df.nlargest(n, sort_by)
    return df.head(n)


def label_summary(df: pd.DataFrame, strict: bool = True) -> dict:
    """
    Return a dict of label → count for the given DataFrame slice.

    CORRECTNESS FIX — do not invent ground truth
    ────────────────────────────────────────────
    This function used to return {"UNKNOWN": len(df)} when the flow CSV had
    no Label column. That silently turned "we have no ground truth" into a
    ground-truth value, and because "UNKNOWN" is not in ThesisEvaluator's
    BENIGN_LABELS it was then scored as a POSITIVE. Every evaluated window
    became an attack window, producing tn=0 / fp=0 and therefore
    precision=100% and FPR=0% as arithmetic artefacts rather than
    measurements.

    Raw CICFlowMeter output never carries labels — it is a feature
    extractor. Labels must be joined in beforehand via
    src/ingestion/ground_truth.GroundTruthLabeller (see scripts/label_flows.py).

    strict=True  (default) : raise, so a mislabelled run cannot silently
                             produce publishable-looking numbers.
    strict=False           : return {} — "no ground truth for this window",
                             which ThesisEvaluator correctly excludes from
                             the ablation table. Use for live mode, where
                             ground truth genuinely does not exist.

    Rows labelled UNMATCHED by the ground-truth join are dropped here: a
    flow we could not match is not evidence for or against anything, and
    must not be counted as either class.
    """
    # An empty window genuinely has no ground truth. That is a legitimate
    # state (quiet minute), not a configuration error — do not raise.
    if df is None or len(df) == 0:
        return {}

    if "Label" not in df.columns:
        if strict:
            raise ValueError(
                "Flow data has no 'Label' column — refusing to fabricate "
                "ground truth.\n"
                "Raw CICFlowMeter CSVs are unlabelled by design. Attach real "
                "labels first:\n"
                "    python scripts/label_flows.py \\\n"
                "        --flow_csv  data/cicflow_csv/<capture>_flows.csv \\\n"
                "        --cic_labels data/cic_labels/<day>/ \\\n"
                "        --out       data/cicflow_csv_labelled/<capture>_flows.csv\n"
                "Then point --flow_dir at the labelled directory. For live "
                "mode (no ground truth exists), call with strict=False."
            )
        return {}

    counts = df["Label"].value_counts().to_dict()
    counts.pop(UNMATCHED_LABEL, None)
    return counts
