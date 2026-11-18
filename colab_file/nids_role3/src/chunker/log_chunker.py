"""
src/chunker/log_chunker.py
===========================
Merge Suricata eve.json events and CICFlowMeter flows into plain-text
"chunks" that the LLM can read and reason about.

PERFORMANCE FIX (v2)
─────────────────────
build_chunks() previously called the O(n) filter_by_window() once per
window for BOTH events and flows. With 2.9M events / 561K flows and
~600 windows this produced well over a billion comparisons before any
ML/LLM work started — the actual cause of the pipeline appearing to
hang at "[3/3] Processing windows".

Fix: build the bisect index for events ONCE before the loop
(build_sorted_timestamps), and rely on cicflow_reader's cached
searchsorted array for flows. Both are now O(log n) per window,
turning total windowing cost from O(chunks * n) into
O(chunks * log n) — a reduction from ~10^9 to ~10^4 comparisons on
the dataset sizes seen in practice.

MEMORY FIX (v4) — SQLite-backed streaming mode
──────────────────────────────────────────────
build_chunks() above still loads the full events list and flows
DataFrame into RAM before building any chunks — fast, but peak memory
scales with total file size (which is data-dependent: for datasets
dominated by alerts/http rather than plain "flow" records, e.g. a
CICIDS2017 DoS/DDoS replay, this can still exceed 8 GB).

build_chunks_streaming() is a generator that fetches ONE window's data
at a time from a SQLite index (see src/ingestion/sqlite_store.py),
using an indexed timestamp range query. Peak RAM is bounded by how
much data falls in a single window (typically KB-MB), independent of
total file size or event-type distribution. Use this on memory-
constrained machines; see unified_pipeline.py's low_memory parameter.
"""

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

import pandas as pd

from src.ingestion.suricata_reader import (
    build_sorted_timestamps,
    filter_by_window_fast as eve_filter_window_fast,
)
from src.ingestion.cicflow_reader import (
    filter_by_window_fast as flow_filter_window_fast,
    get_top_flows,
    label_summary,
)
from src.utils.logger import get_logger

log = get_logger(__name__)

DISPLAY_FEATURES = [
    # Both spellings listed: cicflow_reader emits "Destination Port"
    # (the CICIDS2017 training feature name); CIC labelled releases and
    # older CICFlowMeter builds emit "Dst Port". Display code keeps
    # whichever is present, so listing both costs nothing.
    "Src IP", "Src Port", "Dst IP", "Destination Port", "Dst Port", "Protocol",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Init_Win_bytes_backward", "SYN Flag Count", "FIN Flag Count",
    "RST Flag Count", "Flow Bytes/s", "Label",
]


# ── data class ────────────────────────────────────────────────────────────────

@dataclass
class WindowChunk:
    """One time-window chunk ready to be sent to the LLM."""
    window_start:    datetime
    window_end:      datetime
    chunk_index:     int
    eve_events:      List[dict]        = field(default_factory=list)
    flow_rows:       pd.DataFrame      = field(default_factory=pd.DataFrame)
    ground_truth:    Dict[str, int]    = field(default_factory=dict)
    chunk_text:      str               = ""
    source_file:     str               = ""
    has_alert:       bool              = False   # set by build_chunks for LLM gating


# ── text formatter ────────────────────────────────────────────────────────────

def format_chunk_text(chunk: WindowChunk, include_label: bool = True) -> str:
    """Render a WindowChunk into the plain-text string sent to the LLM."""
    lines = []

    lines.append("=" * 68)
    lines.append(f"LOG WINDOW #{chunk.chunk_index:04d}")
    lines.append(
        f"Time range : {chunk.window_start.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        f" → {chunk.window_end.strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    lines.append(
        f"Suricata alerts : {len([e for e in chunk.eve_events if e['event_type']=='alert']):>4}  "
        f"| Network flows : {len(chunk.flow_rows):>5}"
    )
    if include_label and chunk.ground_truth:
        gt_str = ", ".join(f"{lbl}={cnt}" for lbl, cnt in chunk.ground_truth.items())
        lines.append(f"Ground truth    : {gt_str}")
    lines.append("=" * 68)

    alerts = [e for e in chunk.eve_events if e["event_type"] == "alert"]
    if alerts:
        lines.append(f"\nSURICATA ALERTS ({len(alerts)}):")
        lines.append("-" * 60)
        for a in alerts:
            sig   = a.get("alert", {}) or {}
            ts    = a["timestamp_str"][:19] if a["timestamp_str"] else "?"
            sid   = sig.get("signature_id", "?")
            sname = sig.get("signature",    "unknown signature")
            sev   = sig.get("severity",     "?")
            cat   = sig.get("category",     "")
            lines.append(f"  [{ts}] SID:{sid} (sev={sev}) {sname}")
            if cat:
                lines.append(f"    category : {cat}")
            lines.append(
                f"    {a['src_ip']}:{a['src_port']} → "
                f"{a['dest_ip']}:{a['dest_port']}  proto={a['proto']}"
            )
    else:
        lines.append("\nSURICATA ALERTS: none in this window")

    meta_events = [
        e for e in chunk.eve_events
        if e["event_type"] in ("dns", "http", "tls") and len(lines) < 80
    ]
    if meta_events:
        lines.append(f"\nPROTOCOL METADATA ({len(meta_events)} events, showing first 5):")
        lines.append("-" * 60)
        for e in meta_events[:5]:
            etype = e["event_type"].upper()
            if etype == "DNS":
                dns = e.get("dns") or {}
                lines.append(
                    f"  DNS  {e['src_ip']} queried {dns.get('rrname','?')} "
                    f"type={dns.get('rrtype','?')}"
                )
            elif etype == "HTTP":
                http = e.get("http") or {}
                lines.append(
                    f"  HTTP {e['src_ip']}:{e['src_port']} → "
                    f"{e['dest_ip']} | {http.get('http_method','?')} "
                    f"{http.get('hostname','?')}{http.get('url','')[:60]}"
                )
            elif etype == "TLS":
                tls = e.get("tls") or {}
                lines.append(
                    f"  TLS  {e['src_ip']} → {e['dest_ip']} "
                    f"SNI={tls.get('sni','?')} version={tls.get('version','?')}"
                )

    if not chunk.flow_rows.empty:
        lines.append(f"\nNETWORK FLOWS — top {len(chunk.flow_rows)} by packet count:")
        lines.append("-" * 60)

        display_cols = [c for c in DISPLAY_FEATURES if c in chunk.flow_rows.columns]
        if not include_label and "Label" in display_cols:
            display_cols.remove("Label")

        for _, row in chunk.flow_rows.iterrows():
            parts = []
            for col in display_cols:
                val = row.get(col, "")
                if isinstance(val, float):
                    parts.append(f"{col}={val:.1f}")
                else:
                    parts.append(f"{col}={val}")
            lines.append("  " + "  ".join(parts))
    else:
        lines.append("\nNETWORK FLOWS: none matched this time window")

    lines.append("\nCONTEXT SUMMARY:")
    lines.append("-" * 60)

    if alerts:
        sig_names = list({(a.get("alert") or {}).get("signature", "?") for a in alerts})
        lines.append(f"  Unique signatures : {', '.join(sig_names[:5])}")

    if not chunk.flow_rows.empty:
        if "Src IP" in chunk.flow_rows.columns:
            unique_src = chunk.flow_rows["Src IP"].nunique()
            lines.append(f"  Unique source IPs : {unique_src}")
        # cicflow_reader normalises dst_port to "Destination Port" (the
        # CICIDS2017 training feature name). Checking only "Dst Port" silently
        # dropped the top-ports line from the LLM prompt — no error, just a
        # weaker Role 3 input, which is exactly the kind of degradation that
        # never shows up as a failure.
        _dport = next(
            (c for c in ("Destination Port", "Dst Port", "dst_port")
             if c in chunk.flow_rows.columns),
            None,
        )
        if _dport:
            top_ports = chunk.flow_rows[_dport].value_counts().head(5).index.tolist()
            lines.append(f"  Top dest ports    : {top_ports}")
        if "Protocol" in chunk.flow_rows.columns:
            protos = chunk.flow_rows["Protocol"].value_counts().to_dict()
            lines.append(f"  Protocols         : {protos}")

    lines.append("=" * 68)
    return "\n".join(lines)


# ── chunker ───────────────────────────────────────────────────────────────────

class LogChunker:
    """Split events + flows into time-windowed WindowChunk objects."""

    def __init__(
        self,
        window_seconds: int   = 30,
        max_flows:      int   = 15,
        max_alerts:     int   = 20,
        save_to_disk:   bool  = True,
        chunks_dir:     str   = "data/chunks",
        include_label:  bool  = True,
        require_ground_truth: bool = True,
    ):
        self.window_seconds = window_seconds
        self.max_flows      = max_flows
        self.max_alerts     = max_alerts
        self.save_to_disk   = save_to_disk
        self.chunks_dir     = chunks_dir
        self.include_label  = include_label
        # Whether missing labels are an ERROR (offline evaluation: yes — a run
        # with no ground truth must not silently produce an ablation table) or
        # simply expected (live monitoring: ground truth does not exist).
        # NOTE: deliberately separate from include_label, which controls
        # whether labels are shown to the LLM and must stay False offline to
        # prevent ground-truth leakage into Role 3's prompt.
        self.require_ground_truth = require_ground_truth

        if save_to_disk:
            os.makedirs(chunks_dir, exist_ok=True)

    # ── offline (FAST — bisect/searchsorted, O(log n) per window) ────────────

    def build_chunks(
        self,
        events:   List[dict],
        flows_df: pd.DataFrame,
    ) -> List[WindowChunk]:
        """
        Build all time-window chunks from a full offline dataset held
        ENTIRELY IN MEMORY. Fast (O(log n) per window via bisect), but
        peak RAM scales with total file size — see build_chunks_streaming()
        for a memory-bounded alternative on machines with limited RAM.

        Uses O(log n) bisect / searchsorted lookups instead of O(n)
        linear scans — see module docstring for why this matters at
        million-event scale.
        """
        if not events:
            log.warning("No Suricata events — chunks will contain only flow data")

        # Build the bisect index for events ONCE (not per-window)
        sorted_events    = build_sorted_timestamps(events)
        event_timestamps = [e["timestamp"] for e in sorted_events]

        ts_list = list(event_timestamps)
        if "Timestamp" in flows_df.columns:
            ts_list += flows_df["Timestamp"].dropna().tolist()

        if not ts_list:
            raise ValueError(
                "No valid timestamps found in events or flows. "
                "Check your eve.json and CICFlowMeter CSV files."
            )

        t_start = min(ts_list)
        t_end   = max(ts_list)
        delta   = timedelta(seconds=self.window_seconds)

        n_windows_est = max(1, int((t_end - t_start).total_seconds() / self.window_seconds))
        log.info(
            "Building ~%d chunks: %s → %s  (window=%ds)  [fast O(log n) mode]",
            n_windows_est,
            t_start.strftime("%H:%M:%S"),
            t_end.strftime("%H:%M:%S"),
            self.window_seconds,
        )

        chunks = []
        current = t_start
        idx = 0

        while current < t_end:
            win_end = current + delta

            win_events = eve_filter_window_fast(
                sorted_events, event_timestamps, current, win_end
            )
            alerts_in_win  = [e for e in win_events if e["event_type"] == "alert"]
            others_in_win  = [e for e in win_events if e["event_type"] != "alert"]
            win_events_capped = alerts_in_win[:self.max_alerts] + others_in_win

            win_flows = flow_filter_window_fast(flows_df, current, win_end)
            top_flows = get_top_flows(win_flows, n=self.max_flows)
            gt        = label_summary(win_flows, strict=self.require_ground_truth)

            chunk = WindowChunk(
                window_start = current,
                window_end   = win_end,
                chunk_index  = idx,
                eve_events   = win_events_capped,
                flow_rows    = top_flows,
                ground_truth = gt,
                has_alert    = len(alerts_in_win) > 0,
            )
            chunk.chunk_text = format_chunk_text(chunk, include_label=self.include_label)

            if self.save_to_disk:
                self._save_chunk(chunk)

            chunks.append(chunk)
            current = win_end
            idx    += 1

            if idx % 200 == 0:
                log.info("  ... %d/%d chunks built", idx, n_windows_est)

        log.info("Built %d chunks from dataset", len(chunks))
        return chunks

    # ── offline (MEMORY-BOUNDED — SQLite-backed streaming) ────────────────────

    def build_chunks_streaming(
        self,
        events_db_path: str,
        flows_db_path:  Optional[str],
    ):
        """
        Generator version of build_chunks() that never holds the full
        event/flow dataset in memory. Each window is fetched from a
        SQLite index (built by src/ingestion/sqlite_store.py) with an
        indexed range query, so peak RAM is bounded by how much data
        falls in ONE window — typically a few hundred KB to a few MB —
        regardless of total file size or how the data is distributed
        across event types.

        Use this instead of build_chunks() when the eve.json / CSV are
        too large to fit in RAM (the symptom: the process is killed by
        the OS OOM killer while loading events/flows).

        Parameters
        ----------
        events_db_path : str — SQLite file from build_event_index()
        flows_db_path  : str | None — SQLite file from build_flow_index(),
                         or None if no CICFlowMeter data is available

        Yields
        ------
        WindowChunk, one at a time, in chronological order.
        """
        from src.ingestion.sqlite_store import (
            query_events_window, query_flows_window, get_time_range,
        )

        t_start, t_end = get_time_range(events_db_path, table="events")
        if flows_db_path and os.path.exists(flows_db_path):
            f_start, f_end = get_time_range(flows_db_path, table="flows")
            if f_start and (t_start is None or f_start < t_start):
                t_start = f_start
            if f_end and (t_end is None or f_end > t_end):
                t_end = f_end

        if t_start is None or t_end is None:
            raise ValueError(
                "No valid timestamps found in the indexed events/flows. "
                "Check that build_event_index()/build_flow_index() ran successfully."
            )

        delta = timedelta(seconds=self.window_seconds)
        n_windows_est = max(1, int((t_end - t_start).total_seconds() / self.window_seconds))
        log.info(
            "Streaming ~%d chunks from SQLite: %s → %s  (window=%ds)  [memory-bounded mode]",
            n_windows_est,
            t_start.strftime("%H:%M:%S"),
            t_end.strftime("%H:%M:%S"),
            self.window_seconds,
        )

        current = t_start
        idx = 0

        while current < t_end:
            win_end = current + delta

            win_events = query_events_window(events_db_path, current, win_end)
            alerts_in_win  = [e for e in win_events if e["event_type"] == "alert"]
            others_in_win  = [e for e in win_events if e["event_type"] != "alert"]
            win_events_capped = alerts_in_win[:self.max_alerts] + others_in_win

            if flows_db_path and os.path.exists(flows_db_path):
                win_flows = query_flows_window(flows_db_path, current, win_end)
            else:
                win_flows = pd.DataFrame()

            top_flows = get_top_flows(win_flows, n=self.max_flows) if not win_flows.empty else win_flows
            gt        = label_summary(win_flows, strict=self.require_ground_truth) if not win_flows.empty else {}

            chunk = WindowChunk(
                window_start = current,
                window_end   = win_end,
                chunk_index  = idx,
                eve_events   = win_events_capped,
                flow_rows    = top_flows,
                ground_truth = gt,
                has_alert    = len(alerts_in_win) > 0,
            )
            chunk.chunk_text = format_chunk_text(chunk, include_label=self.include_label)

            if self.save_to_disk:
                self._save_chunk(chunk)

            yield chunk

            current = win_end
            idx    += 1

            if idx % 200 == 0:
                log.info("  ... %d/%d chunks streamed", idx, n_windows_est)

        log.info("Streamed %d chunks total (memory-bounded mode)", idx)

    # ── live ──────────────────────────────────────────────────────────────────

    def build_single_chunk(
        self,
        events:      List[dict],
        flows_df:    pd.DataFrame,
        chunk_index: int,
        window_start: datetime,
        window_end:   datetime,
    ) -> WindowChunk:
        """Build one chunk from a live event buffer (small N, O(n) is fine here)."""
        alerts   = [e for e in events if e["event_type"] == "alert"]
        others   = [e for e in events if e["event_type"] != "alert"]
        capped   = alerts[:self.max_alerts] + others

        top_flows = get_top_flows(flows_df, n=self.max_flows) if not flows_df.empty else flows_df

        chunk = WindowChunk(
            window_start = window_start,
            window_end   = window_end,
            chunk_index  = chunk_index,
            eve_events   = capped,
            flow_rows    = top_flows,
            ground_truth = {},
            has_alert    = len(alerts) > 0,
        )
        chunk.chunk_text = format_chunk_text(chunk, include_label=False)

        if self.save_to_disk:
            self._save_chunk(chunk)

        return chunk

    # ── internal ──────────────────────────────────────────────────────────────

    def _save_chunk(self, chunk: WindowChunk) -> None:
        fname = os.path.join(
            self.chunks_dir,
            f"chunk_{chunk.chunk_index:04d}_{chunk.window_start.strftime('%H%M%S')}.txt"
        )
        with open(fname, "w", encoding="utf-8") as fh:
            fh.write(chunk.chunk_text)
