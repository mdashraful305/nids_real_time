"""
src/ingestion/sqlite_store.py
==============================
Disk-backed streaming index for Suricata eve.json events and CICFlowMeter
flow CSVs, built specifically to fix the OOM problem the previous
in-memory fixes did not fully solve.

WHY THE PREVIOUS FIX WASN'T ENOUGH
────────────────────────────────────
The earlier memory fix assumed plain Suricata "flow" records (which are
never read downstream) made up 85-95% of a typical eve.json, so filtering
them out would shrink memory ~10x. That assumption does NOT hold for a
CICIDS2017 replay: the dataset is dominated by DoS/DDoS/HTTP-flood and
brute-force traffic, which generates enormous numbers of "alert" and
"http" events — the very types that ARE kept. In that case the filter
removes little or nothing, and the event list still grows unbounded with
file size, which is why 8 GB was still exceeded.

THE ACTUAL FIX
────────────────
No approach that loads "all events" or "all flows" into a Python list
can have a memory ceiling independent of file size — the ceiling will
always be proportional to however many events happen to be alerts/http/
etc, which is data-dependent and out of our control.

The only design with a genuine memory ceiling is one where the full
dataset never sits in RAM at all. This module streams eve.json and the
CICFlowMeter CSV into a SQLite database on disk (batched inserts, so
peak RAM during indexing is O(batch_size), not O(file size)), with an
index on timestamp. Each 30-second window then queries ONLY the rows
that fall in that window (typically a few hundred to a few thousand
rows) via an indexed range query — bounded by window density, not by
total file size, no matter how many events there are or what types they
are.

Usage
-----
from src.ingestion.sqlite_store import (
    build_event_index, build_flow_index,
    query_events_window, query_flows_window,
    get_time_range,
)

n_events, dropped, bad = build_event_index("data/eve_logs/", "data/.cache/events.db")
n_flows                = build_flow_index("data/cicflow_csv/", "data/.cache/flows.db")

t_start, t_end = get_time_range("data/.cache/events.db")
# ... for each window:
events = query_events_window("data/.cache/events.db", win_start, win_end)
flows  = query_flows_window("data/.cache/flows.db",  win_start, win_end)
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd

from src.utils.logger import get_logger
from src.ingestion.suricata_reader import (
    _parse_timestamp, _clean_event, KEEP_EVENT_TYPES,
)
from src.ingestion.cicflow_reader import (
    COLUMN_ALIASES, _parse_cicflow_timestamp,
)

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# EVENTS (Suricata eve.json)
# ══════════════════════════════════════════════════════════════════════════════

def build_event_index(
    eve_dir_or_file: str,
    db_path: str,
    keep_types: Optional[frozenset] = KEEP_EVENT_TYPES,
    batch_size: int = 20_000,
) -> Tuple[int, int, int]:
    """
    Stream eve.json file(s) line-by-line into a SQLite table indexed by
    timestamp. Peak RAM during this call is O(batch_size), NOT O(total
    number of events) — this is what actually bounds memory, unlike the
    previous approach which still depended on how many events matched
    keep_types.

    Parameters
    ----------
    eve_dir_or_file : str  — directory of *.json files, or a single file
    db_path         : str  — output SQLite file (overwritten if it exists)
    keep_types      : frozenset[str] | None — event types to index.
                      None means index everything (still memory-bounded,
                      since data lives on disk either way — this only
                      controls what gets kept/dropped, not peak RAM).
    batch_size      : int  — rows per INSERT batch / commit

    Returns
    -------
    (total_indexed, dropped_by_type_filter, bad_json_lines)
    """
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=MEMORY")   # no -wal/-shm sidecars
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("CREATE TABLE events (ts REAL, event_type TEXT, payload TEXT)")

    if os.path.isdir(eve_dir_or_file):
        paths = sorted(
            os.path.join(eve_dir_or_file, f)
            for f in os.listdir(eve_dir_or_file) if f.endswith(".json")
        )
        if not paths:
            raise FileNotFoundError(f"No .json files found in {eve_dir_or_file}")
    else:
        paths = [eve_dir_or_file]

    batch = []
    total = 0
    dropped = 0
    bad = 0

    for path in paths:
        log.info("Indexing %s ...", path)
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

                etype = raw.get("event_type", "unknown")
                if keep_types is not None and etype not in keep_types:
                    dropped += 1
                    continue

                ts = _parse_timestamp(raw.get("timestamp", ""))
                if ts is None:
                    continue

                cleaned = _clean_event(raw)
                # payload stores everything except the python datetime
                # object (not JSON serialisable) — timestamp is
                # reconstructed from the indexed `ts` column on read.
                payload = {k: v for k, v in cleaned.items() if k != "timestamp"}
                batch.append((ts.timestamp(), etype, json.dumps(payload)))
                total += 1

                if len(batch) >= batch_size:
                    conn.executemany("INSERT INTO events VALUES (?,?,?)", batch)
                    conn.commit()
                    batch.clear()

    if batch:
        conn.executemany("INSERT INTO events VALUES (?,?,?)", batch)
        conn.commit()

    log.info("Building timestamp index on events table ...")
    conn.execute("CREATE INDEX idx_events_ts ON events(ts)")
    conn.commit()
    conn.close()

    log.info(
        "Indexed %d events (%d dropped by type filter, %d bad JSON lines) -> %s",
        total, dropped, bad, db_path,
    )
    return total, dropped, bad


def query_events_window(
    db_path: str,
    window_start: datetime,
    window_end: datetime,
) -> List[dict]:
    """
    Return only the events whose timestamp falls in [window_start, window_end].
    Uses the indexed `ts` column — O(log n + k) where k is the number of
    rows in this window, NOT the total number of events in the database.
    """
    conn = sqlite3.connect(db_path)
    try:
        lo = window_start.timestamp()
        hi = window_end.timestamp()
        rows = conn.execute(
            # Half-open [lo, hi) for the same reason as the flows query below:
            # an alert landing exactly on a boundary was counted in two windows.
            "SELECT ts, event_type, payload FROM events "
            "WHERE ts >= ? AND ts < ? ORDER BY ts",
            (lo, hi),
        ).fetchall()
    finally:
        conn.close()

    events = []
    for ts, etype, payload in rows:
        e = json.loads(payload)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        e["timestamp"] = dt
        e.setdefault("timestamp_str", dt.isoformat())
        events.append(e)
    return events


# ══════════════════════════════════════════════════════════════════════════════
# FLOWS (CICFlowMeter CSV)
# ══════════════════════════════════════════════════════════════════════════════

def build_flow_index(
    flow_dir_or_file: str,
    db_path: str,
    chunksize: int = 50_000,
) -> int:
    """
    Stream CICFlowMeter CSV file(s) into a SQLite table using pandas'
    chunked CSV reader, so peak RAM is O(chunksize rows), not O(total
    flow count). Adds a `_ts_epoch` REAL column (indexed) for fast
    windowed range queries.

    Parameters
    ----------
    flow_dir_or_file : str — directory of *.csv files, or a single file
    db_path          : str — output SQLite file (overwritten if exists)
    chunksize        : int — rows read from CSV per batch

    Returns
    -------
    total rows indexed
    """
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=MEMORY")   # no -wal/-shm sidecars
    conn.execute("PRAGMA synchronous=OFF")

    if os.path.isdir(flow_dir_or_file):
        paths = sorted(
            os.path.join(flow_dir_or_file, f)
            for f in os.listdir(flow_dir_or_file) if f.endswith(".csv")
        )
        if not paths:
            raise FileNotFoundError(f"No .csv files found in {flow_dir_or_file}")
    else:
        paths = [flow_dir_or_file]

    first_write = True
    total = 0

    for path in paths:
        log.info("Indexing %s ...", path)
        for chunk_df in pd.read_csv(
            path, chunksize=chunksize, low_memory=True, on_bad_lines="skip"
        ):
            chunk_df.columns = chunk_df.columns.str.strip()

            rename_map = {}
            for col in chunk_df.columns:
                alias = COLUMN_ALIASES.get(col.lower().strip())
                if alias and alias != col:
                    rename_map[col] = alias
            if rename_map:
                chunk_df = chunk_df.rename(columns=rename_map)

            if "Timestamp" in chunk_df.columns:
                parsed = chunk_df["Timestamp"].apply(_parse_cicflow_timestamp)
                chunk_df["_ts_epoch"] = parsed.apply(
                    lambda d: d.timestamp() if d is not None else None
                )
                # Store Timestamp as ISO text (sqlite/pandas default) —
                # reconstructed from _ts_epoch on read instead, so the
                # exact stored format here does not matter.
                chunk_df["Timestamp"] = parsed.apply(
                    lambda d: d.isoformat() if d is not None else None
                )
            else:
                chunk_df["_ts_epoch"] = None

            # Strip inf/-inf BEFORE the float32 cast. CIC writes the string
            # "Infinity" in Flow Bytes/s and Flow Packets/s for zero-duration
            # flows; read as float it becomes np.inf, and the RobustScaler in
            # Role 1 then raises "Input X contains infinity", disabling Role 1
            # for the whole run. cicflow_reader.load_cicflow_file already does
            # this for the in-memory path; the streaming indexer did not, so
            # every CIC-sourced run lost Role 1.
            num_cols = chunk_df.select_dtypes(include=["number"]).columns
            if len(num_cols):
                chunk_df[num_cols] = chunk_df[num_cols].replace(
                    [np.inf, -np.inf], np.nan
                ).fillna(0)
            # FIX: _ts_epoch (Unix epoch seconds, ~1.5e9) must stay float64.
            # float32 only has ~7 significant decimal digits, which at this
            # magnitude is a precision step of ~128 SECONDS (confirmed:
            # 200 distinct epoch values 0.5s apart collapsed to 2 distinct
            # float32 values). Every flow's timestamp was silently snapped
            # onto a 128s grid that has nothing to do with the 60s window
            # grid used everywhere else in this pipeline, scrambling which
            # window each flow (and its ground-truth Label) lands in —
            # while the total row COUNT stayed correct, masking the bug.
            # This column was caught by the blanket float64->float32 cast
            # below, which is only meant to shrink the feature columns.
            float_cols = chunk_df.select_dtypes(include=["float64"]).columns
            float_cols = float_cols.drop("_ts_epoch", errors="ignore")
            if len(float_cols):
                chunk_df[float_cols] = chunk_df[float_cols].astype("float32")

            if "Label" in chunk_df.columns:
                chunk_df["Label"] = chunk_df["Label"].astype(str).str.strip()

            chunk_df.to_sql(
                "flows", conn,
                if_exists="replace" if first_write else "append",
                index=False,
            )
            first_write = False
            total += len(chunk_df)

    log.info("Building timestamp index on flows table ...")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(_ts_epoch)")
    conn.commit()
    conn.close()

    log.info("Indexed %d flows -> %s", total, db_path)
    return total


def query_flows_window(
    db_path: str,
    window_start: datetime,
    window_end: datetime,
) -> pd.DataFrame:
    """
    Return only the flow rows whose Timestamp falls in
    [window_start, window_end], using the indexed `_ts_epoch` column.
    """
    conn = sqlite3.connect(db_path)
    try:
        lo = window_start.timestamp()
        hi = window_end.timestamp()
        df = pd.read_sql_query(
            # Half-open [lo, hi): BETWEEN is inclusive on BOTH ends, so a flow
            # whose timestamp fell exactly on a window boundary was returned for
            # the window ending there AND the one starting there. CICFlowMeter
            # stamps at 1-second resolution, so boundary collisions are common,
            # and the duplicates inflated the reported flow count above the
            # number of flows that actually exist in the CSV.
            "SELECT * FROM flows WHERE _ts_epoch >= ? AND _ts_epoch < ? "
            "ORDER BY _ts_epoch",
            conn, params=(lo, hi),
        )
    finally:
        conn.close()

    if "_ts_epoch" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["_ts_epoch"], unit="s", utc=True)
        df = df.drop(columns=["_ts_epoch"])
    return df


# ══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_time_range(db_path: str, table: str = "events") -> Tuple[Optional[datetime], Optional[datetime]]:
    """Return (min_timestamp, max_timestamp) for a SQLite table without
    loading any rows — a single indexed MIN/MAX aggregate query."""
    ts_col = "ts" if table == "events" else "_ts_epoch"
    conn = sqlite3.connect(db_path)
    try:
        lo, hi = conn.execute(f"SELECT MIN({ts_col}), MAX({ts_col}) FROM {table}").fetchone()
    finally:
        conn.close()
    if lo is None:
        return None, None
    return (
        datetime.fromtimestamp(lo, tz=timezone.utc),
        datetime.fromtimestamp(hi, tz=timezone.utc),
    )


def get_row_count(db_path: str, table: str = "events") -> int:
    """Return row count for a table without loading any rows into RAM."""
    conn = sqlite3.connect(db_path)
    try:
        (count,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    finally:
        conn.close()
    return count
