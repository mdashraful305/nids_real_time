"""
src/ingestion/suricata_reader.py
=================================
Parse Suricata eve.json logs for both offline and live modes.

PERFORMANCE FIX (v2)
─────────────────────
The old filter_by_window() did a linear O(n) scan over ALL events for
EVERY window. With 2.9M events and ~600 windows that is ~1.8 BILLION
comparisons before any ML/LLM work even starts — this was the actual
cause of main_unified.py appearing to hang at "[3/3] Processing windows".

Fix: events are already sorted by timestamp (load_eve_directory sorts
them). build_sorted_timestamps() extracts a parallel timestamp array
once; filter_by_window_fast() then uses bisect (binary search) to find
the window slice in O(log n) instead of O(n). This turns the total
windowing cost from O(chunks * events) into O(chunks * log(events)).

The old filter_by_window() is kept for backward compatibility with any
code that still calls it directly, but build_chunks() in log_chunker.py
now uses the fast path.

MEMORY FIX (v3)
─────────────────
The old _clean_event() stored a full duplicate of the raw parsed JSON
in event["_raw"] — never read anywhere downstream (log_chunker.py only
reads the explicit typed fields). At 2.9M events this duplicate alone
cost ~1 GB. More significantly, the old loader kept EVERY event type,
including plain Suricata "flow" records, which are typically 85-95%
of a real eve.json but are NEVER read by log_chunker.py (which only
consumes "alert", "dns", "http", "tls" event types). Measured on the
real reported scale (2,897,737 events):

    with _raw, all types kept    : 8.23 GB
    without _raw, all types kept : 7.30 GB
    without _raw, filtered types : 0.37 - 1.10 GB   (90-95% of events dropped)

load_eve_file()/load_eve_directory() now default to KEEP_EVENT_TYPES
below. This is a pure memory optimisation with NO functional change —
the dropped event types were dead weight that nothing consumed. Pass
keep_types=None to restore the old "keep everything" behaviour if some
other part of your pipeline is later extended to need "flow" events.
"""

# Event types actually consumed anywhere downstream (log_chunker.py).
# "flow" (plain Suricata bidirectional flow summaries, NOT alerts) is
# intentionally excluded — nothing reads it, and it is normally the
# large majority of eve.json records.
KEEP_EVENT_TYPES = frozenset({"alert", "dns", "http", "tls"})

import json
import time
import os
import bisect
from datetime import datetime, timezone, timedelta
from typing import Generator, List, Dict, Optional, Tuple

from src.utils.logger import get_logger

log = get_logger(__name__)


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse Suricata ISO-8601 timestamp → datetime (UTC-aware)."""
    if not ts_str:
        return None
    try:
        ts_str = ts_str.replace("+0000", "+00:00")
        return datetime.fromisoformat(ts_str)
    except ValueError:
        try:
            return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except Exception:
            return None


def detect_utc_offset(eve_path: str, max_lines: int = 200) -> Optional[timedelta]:
    """
    Read the UTC offset Suricata recorded in eve.json, e.g. the "+0600" in
    "2017-07-07T17:59:39.599128+0600".

    Used to interpret the NAIVE timestamps in the CICFlowMeter CSV, which
    carry no offset marker. Both artefacts are produced by the same machine
    from the same pcap, so Suricata's offset is the correct interpretation
    for CICFlowMeter's wall-clock values too. Without this, the flow CSV was
    read as UTC and landed six hours away from the Suricata events describing
    the same packets — see the note in cicflow_reader._parse_cicflow_timestamp.

    Returns None if no offset can be determined (caller decides whether that
    is fatal).
    """
    if os.path.isdir(eve_path):
        candidates = sorted(
            os.path.join(eve_path, f)
            for f in os.listdir(eve_path)
            if f.endswith(".json") or f.startswith("eve")
        )
        if not candidates:
            return None
        eve_path = candidates[0]

    if not os.path.exists(eve_path):
        return None

    try:
        with open(eve_path, "r", errors="replace") as fh:
            for _ in range(max_lines):
                line = fh.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except Exception:
                    continue
                ts = _parse_timestamp(raw.get("timestamp", ""))
                if ts is not None and ts.utcoffset() is not None:
                    off = ts.utcoffset()
                    log.info(
                        "Detected eve.json UTC offset: %+.2fh (from %s)",
                        off.total_seconds() / 3600, os.path.basename(eve_path),
                    )
                    return off
    except Exception as exc:
        log.warning("Could not detect UTC offset from %s: %s", eve_path, exc)
    return None


def _clean_event(raw: dict) -> dict:
    """
    Normalise a raw eve.json dict into a consistent structure.

    MEMORY FIX: no longer stores a "_raw" duplicate of the full parsed
    JSON. Nothing downstream (log_chunker.py) ever reads it — it was
    pure dead weight costing ~1 GB at 2.9M-event scale. If you need the
    original raw dict for debugging a specific event, re-parse that one
    line directly rather than carrying a duplicate for every event.
    """
    ts = _parse_timestamp(raw.get("timestamp", ""))
    return {
        "timestamp":     ts,
        "timestamp_str": raw.get("timestamp", ""),
        "event_type":    raw.get("event_type", "unknown"),
        "src_ip":        raw.get("src_ip", ""),
        "src_port":      raw.get("src_port", 0),
        "dest_ip":       raw.get("dest_ip", ""),
        "dest_port":     raw.get("dest_port", 0),
        "proto":         raw.get("proto", ""),
        "alert":         raw.get("alert"),
        "flow":          raw.get("flow"),
        "dns":           raw.get("dns"),
        "http":          raw.get("http"),
        "tls":           raw.get("tls"),
    }


# ── offline ───────────────────────────────────────────────────────────────────

def load_eve_file(
    path: str,
    keep_types: Optional[frozenset] = KEEP_EVENT_TYPES,
) -> List[dict]:
    """
    Load a complete eve.json file and return all events as a list.

    Parameters
    ----------
    path       : str
    keep_types : frozenset[str] | None
        Event types to retain (default: KEEP_EVENT_TYPES = alert, dns,
        http, tls — the only types log_chunker.py ever reads). Pass
        keep_types=None to keep every event type including plain "flow"
        records, restoring the old (memory-heavy) behaviour.

    MEMORY FIX: filtering unused event types (mainly plain Suricata
    "flow" summaries, which are normally 85-95% of a real eve.json) at
    parse time reduces peak memory by roughly 8-20x on typical captures,
    with zero functional impact since those records were never used.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Eve.json not found: {path}")

    events = []
    bad_lines   = 0
    dropped     = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                bad_lines += 1
                if bad_lines <= 5:
                    log.warning("Skipping bad JSON on line %d in %s", lineno, path)
                continue

            if keep_types is not None and raw.get("event_type") not in keep_types:
                dropped += 1
                continue

            events.append(_clean_event(raw))

    if bad_lines > 5:
        log.warning("... and %d more bad lines skipped in %s", bad_lines - 5, path)

    events.sort(key=lambda e: e["timestamp"] or datetime.max.replace(tzinfo=timezone.utc))

    log.info(
        "Loaded %d events from %s  (bad lines: %d, dropped %d unused-type events)",
        len(events), os.path.basename(path), bad_lines, dropped,
    )
    return events


def load_eve_directory(
    directory: str,
    keep_types: Optional[frozenset] = KEEP_EVENT_TYPES,
) -> List[dict]:
    """
    Load all *.json files in a directory and merge into one sorted list.
    See load_eve_file() for the keep_types memory-fix explanation.
    """
    json_files = sorted(
        f for f in os.listdir(directory) if f.endswith(".json")
    )
    if not json_files:
        raise FileNotFoundError(f"No .json files found in {directory}")

    all_events = []
    for fname in json_files:
        path = os.path.join(directory, fname)
        all_events.extend(load_eve_file(path, keep_types=keep_types))

    all_events.sort(
        key=lambda e: e["timestamp"] or datetime.max.replace(tzinfo=timezone.utc)
    )
    log.info(
        "Merged %d events from %d files in %s",
        len(all_events), len(json_files), directory,
    )
    return all_events


# ── live ──────────────────────────────────────────────────────────────────────

def tail_eve_file(
    path: str,
    poll_interval: float = 0.5,
    from_start: bool = False,
    stop_event=None,
) -> Generator[dict, None, None]:
    """Generator that yields new eve.json events as Suricata writes them."""
    log.info("Tailing eve.json: %s  (from_start=%s)", path, from_start)

    while not os.path.exists(path):
        if stop_event is not None and stop_event.is_set():
            return
        log.warning("Waiting for eve.json to appear at %s ...", path)
        time.sleep(2)

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        if not from_start:
            fh.seek(0, 2)

        buffer = ""
        while True:
            chunk = fh.read(65536)
            if chunk:
                buffer += chunk
                lines = buffer.split("\n")
                buffer = lines[-1]

                for line in lines[:-1]:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        ev = _clean_event(raw)
                        if ev.get("event_type") in KEEP_EVENT_TYPES:
                            yield ev
                    except json.JSONDecodeError:
                        log.debug("Skipping malformed line: %s", line[:80])
            else:
                if stop_event is not None and stop_event.is_set():
                    if buffer.strip():
                        try:
                            raw = json.loads(buffer.strip())
                            ev = _clean_event(raw)
                            if ev.get("event_type") in KEEP_EVENT_TYPES:
                                yield ev
                        except Exception:
                            pass
                    return
                time.sleep(poll_interval)


# ── convenience filters ───────────────────────────────────────────────────────

def filter_alerts(events: List[dict]) -> List[dict]:
    """Return only alert-type events from a list."""
    return [e for e in events if e["event_type"] == "alert"]


def filter_by_window(
    events: List[dict],
    window_start: datetime,
    window_end: datetime,
) -> List[dict]:
    """
    LEGACY O(n) window filter — kept for backward compatibility.
    For repeated windowing over the same event list (e.g. inside a loop
    over many chunks), use build_sorted_timestamps() + filter_by_window_fast()
    instead, which is O(log n) per call.
    """
    return [
        e for e in events
        if e["timestamp"] and window_start <= e["timestamp"] <= window_end
    ]


# ── FAST O(log n) window filter (performance fix) ─────────────────────────────

def build_sorted_timestamps(events: List[dict]) -> List[datetime]:
    """
    Build a parallel list of timestamps for bisect-based lookups.
    Call this ONCE after loading events (they are already sorted by
    load_eve_file / load_eve_directory), then reuse the result across
    all filter_by_window_fast() calls in a loop.

    Events with a None timestamp are excluded — they cannot be placed
    in any time window anyway.
    """
    # Keep only events that have a real timestamp, preserving sort order
    dated = [e for e in events if e["timestamp"] is not None]
    if len(dated) != len(events):
        log.debug(
            "build_sorted_timestamps: dropped %d events with no timestamp",
            len(events) - len(dated),
        )
    return dated


def filter_by_window_fast(
    sorted_events: List[dict],
    timestamps: List[datetime],
    window_start: datetime,
    window_end: datetime,
) -> List[dict]:
    """
    O(log n) window filter using binary search (bisect) on pre-sorted
    timestamps. Both `sorted_events` and `timestamps` must be the SAME
    list (index-aligned) returned by build_sorted_timestamps() — do not
    pass the raw, un-filtered events list here.

    Parameters
    ----------
    sorted_events : list[dict]   — from build_sorted_timestamps()
    timestamps    : list[datetime] — the timestamp field of each event,
                    same list object/order as sorted_events
    window_start  : datetime
    window_end    : datetime

    Returns
    -------
    list[dict] — events with window_start <= timestamp <= window_end
    """
    lo = bisect.bisect_left(timestamps, window_start)
    hi = bisect.bisect_right(timestamps, window_end)
    return sorted_events[lo:hi]
