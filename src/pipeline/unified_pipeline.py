"""
src/pipeline/unified_pipeline.py  (v3 — performance fix)
==========================================================
Handles TWO pkl formats (universal ensemble / single-dataset) exactly
as before. This version adds the two fixes needed to make offline mode
finish in minutes instead of hours on large CICIDS2017 captures:

FIX 2 — LLM gating (skip Role 3 when it is obviously not needed)
───────────────────────────────────────────────────────────────
Calling the LLM on every single 30-second window is wasteful: most
CICIDS2017 traffic (e.g. the Friday capture) is benign, and a window
with no Suricata alert AND no Role 1 attack flag has nothing for the
LLM to usefully add. Such windows are now auto-classified as benign
WITHOUT calling Ollama, cutting the number of LLM calls by roughly
70-90% on typical benchmark captures.

FIX 3 — parallel LLM calls for the windows that DO need analysis
───────────────────────────────────────────────────────────────
The remaining windows (has_alert OR Role1 flagged an attack) are
submitted to a ThreadPoolExecutor so multiple Ollama requests run
concurrently instead of strictly one after another. This requires
Ollama to be started with OLLAMA_NUM_PARALLEL >= num_workers, e.g.:
    export OLLAMA_NUM_PARALLEL=4 && ollama serve
If Ollama only serves one request at a time, this fix has no effect
(also no harm) — set num_workers=1 in that case.
"""

import os
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import numpy as np
import pandas as pd

from src.utils.logger              import get_logger
from src.ingestion.suricata_reader import (
    load_eve_directory, tail_eve_file, KEEP_EVENT_TYPES,
)
from src.ingestion.cicflow_reader  import (
    load_cicflow_directory,
    filter_by_window_fast as flow_filter_window_fast,
    get_top_flows,
    build_feature_lookup,
    resolve_feature,
)
from src.chunker.log_chunker       import LogChunker
from src.llm.ollama_analyst        import OllamaAnalyst
from src.engine.decision_engine    import (
    DecisionEngine, UnifiedAlert, SEVERITY_HIGH, SEVERITY_MEDIUM
)
from src.evaluator.thesis_evaluator import ThesisEvaluator

log = get_logger(__name__)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False


def _c(text, colour):
    if not _COLOR:
        return str(text)
    m = {
        "red":    Fore.RED,
        "yellow": Fore.YELLOW,
        "green":  Fore.GREEN,
        "cyan":   Fore.CYAN,
        "bold":   Style.BRIGHT,
    }
    return m.get(colour, "") + str(text) + Style.RESET_ALL


# Sentinel Role-3 verdict used when a window is skipped (Fix 2)
_SKIPPED_VERDICT_TEMPLATE = {
    "verdict":            "benign",
    "attack_type":        "Normal",
    "confidence":         90,
    "key_indicators":     [],
    "explanation":        "No Suricata alert and no ML flag in this window — LLM analysis skipped for speed.",
    "recommended_action": "None",
    "_skipped":           True,
}


class UnifiedPipeline:
    """
    Orchestrates Role 1 + Role 2 + Role 3 and feeds results to the
    decision engine.

    Parameters
    ----------
    cfg      : Config from load_config()
    nids_out : dict | None
        Loaded by load_nids_output() in main_unified.py.
        Accepts both universal pkl (Format A) and single-dataset pkl
        (Format B). Pass None to run Role 3 only.
    """

    def __init__(self, cfg, nids_out: Optional[dict] = None):
        self.cfg      = cfg
        self.nids_out = nids_out
        self.analyst  = OllamaAnalyst(cfg)
        self.engine   = DecisionEngine(cfg)
        self.chunker  = LogChunker(
            window_seconds = cfg.chunker.window_seconds,
            max_flows      = cfg.chunker.max_flows_per_chunk,
            max_alerts     = cfg.chunker.max_alerts_per_chunk,
            save_to_disk   = cfg.chunker.save_chunks_to_disk,
            chunks_dir     = cfg.paths.chunks_dir,
            # include_label=False prevents ground-truth leaking into the LLM
            # prompt. require_ground_truth=True is a SEPARATE guarantee: an
            # offline evaluation run must fail loudly rather than fabricate
            # labels, because fabricated labels silently produce a 100%-
            # accuracy ablation table. Live mode flips this in run_live().
            include_label        = False,
            require_ground_truth = True,
        )

        # ── Role 1 state ──────────────────────────────────────────────────────
        self._role1_ready   = False
        self._is_universal  = False

        # Minimum fraction of a model's trained features that must actually be
        # present in the incoming flows before Role 1 is allowed to predict.
        # The old value was 0.3, which permitted a prediction from a vector
        # that was 70% zeros. Overridable via config for datasets where a
        # couple of features genuinely cannot be reproduced.
        self._min_feature_coverage = float(
            getattr(getattr(cfg, "role1", None), "min_feature_coverage", 0.90)
        )
        self._coverage_reported = set()   # dataset -> reported once

        # ── routing / scaling state (Phase 4) ─────────────────────────────────
        # Route is resolved ONCE per run, not per window, so it cannot drift
        # mid-capture. _forced_dataset comes from --dataset.
        self._forced_dataset  = None
        self._routed_dataset  = None
        self._route_warned    = False
        self._scaler_warned   = False
        # Opt-in escape hatch for legacy pkls with no per-dataset scalers.
        self._allow_unscaled  = False

        self._ensemble       = None    # UniversalEnsemble instance
        self._best_model     = None    # single-dataset model
        self._threshold       = 0.5

        self._scaler         = None
        self._le             = None
        self._feature_names  = []
        self._results        = {}
        self._benign_labels  = {"BENIGN", "benign", "normal", "Normal", "Benign"}

        # ── train/deploy feature-drift detection ─────────────────────────────
        # Matching feature NAMES do not imply matching values. The sub-model
        # was fitted on CIC's pre-extracted CICIDS2017 features (Java
        # CICFlowMeter, durations in MICROSECONDS, lengths excluding headers);
        # a local python-cicflowmeter run reports seconds and includes headers.
        # Name coverage was 52/52 and the run completed normally while Role 1
        # predicted Benign for 100% of flows at 99.9% confidence, missing all
        # 75,884 attack flows in the sample. Nothing failed — it just answered
        # one class. Detect it instead of reporting it as a result.
        self._drift_buffer   = []
        self._drift_rows     = 0
        self._drift_checked  = False
        self._drift_min_rows = 5000

        if nids_out:
            self._setup_role1(nids_out)

        os.makedirs(cfg.paths.results_dir, exist_ok=True)
        self._alert_log = os.path.join(
            cfg.paths.results_dir, "unified_alerts.jsonl"
        )
        self._alert_log_lock = threading.Lock()

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC — offline
    # ══════════════════════════════════════════════════════════════════════════

    def run_offline(
        self,
        eve_dir:     Optional[str] = None,
        flow_dir:    Optional[str] = None,
        quick:       bool          = False,
        num_workers: int           = 4,
        skip_llm_on_benign: bool   = True,
        keep_all_event_types: bool = False,
        low_memory:  bool          = True,
        db_dir:      Optional[str] = None,
    ) -> List[UnifiedAlert]:
        """
        Parameters
        ----------
        eve_dir, flow_dir : override data directories
        quick             : process only the first 20 windows
        num_workers       : how many windows to analyse with the LLM
                            concurrently (Fix 3). Requires Ollama to be
                            started with OLLAMA_NUM_PARALLEL >= this value
                            for real speedup; set to 1 to disable.
        skip_llm_on_benign: if True (default), windows with no Suricata
                            alert AND no Role 1 attack flag are classified
                            benign WITHOUT calling the LLM (Fix 2).
        keep_all_event_types: MEMORY FIX opt-out. If False (default),
                            only "alert"/"dns"/"http"/"tls" Suricata
                            event types are loaded (plain "flow" records
                            are dropped at parse time — nothing reads
                            them downstream). Only affects low_memory=False.
        low_memory        : MEMORY FIX (v4, default True). If True, events
                            and flows are indexed into a SQLite database
                            on disk (batched, bounded RAM) and windows are
                            streamed one at a time from indexed range
                            queries — peak RAM depends on how much data
                            falls in a single window, NOT on total file
                            size or event-type distribution. This is the
                            correct choice whenever the process has been
                            killed by the OS OOM killer while loading
                            events/flows. Set to False only for small
                            datasets where the faster (but RAM-hungry)
                            in-memory path (build_chunks()) is preferable.
        db_dir            : where to put the SQLite index files when
                            low_memory=True. Defaults to
                            <results_dir>/.cache/
        """
        if low_memory:
            return self._run_offline_streaming(
                eve_dir=eve_dir, flow_dir=flow_dir, quick=quick,
                num_workers=num_workers, skip_llm_on_benign=skip_llm_on_benign,
                db_dir=db_dir,
            )

        print(_c("\n" + "═" * 64, "bold"))
        print(_c("  UNIFIED NIDS — OFFLINE EVALUATION (all 3 roles)", "bold"))
        print(_c("  Mode: IN-MEMORY (fast, RAM scales with file size)", "bold"))
        role1_status = (
            f"✓ active ({'universal' if self._is_universal else 'single-dataset'})"
            if self._role1_ready else "✗ skipped (pkl not loaded)"
        )
        print(f"  Role 1+2 : {role1_status}")
        print(f"  LLM gating (Fix 2) : {'enabled' if skip_llm_on_benign else 'disabled'}")
        print(f"  Parallel workers (Fix 3) : {num_workers}")
        print(f"  Low-memory event loading : {'disabled (--keep_all_event_types)' if keep_all_event_types else 'enabled'}")
        print(_c("═" * 64 + "\n", "bold"))

        eve_dir  = eve_dir  or self.cfg.paths.eve_logs_dir
        flow_dir = flow_dir or self.cfg.paths.cicflow_csv_dir

        # ── load Suricata events ───────────────────────────────────────────────
        print("[1/3] Loading Suricata events ...")
        t0 = time.time()
        keep_types = None if keep_all_event_types else KEEP_EVENT_TYPES
        events = load_eve_directory(eve_dir, keep_types=keep_types)
        print(f"  ✓ {len(events):,} events  ({time.time()-t0:.1f}s)\n")

        # ── load CICFlowMeter flows ────────────────────────────────────────────
        print("[2/3] Loading CICFlowMeter flows ...")
        t0 = time.time()
        try:
            flows_df = load_cicflow_directory(flow_dir)
            print(f"  ✓ {len(flows_df):,} flows  ({time.time()-t0:.1f}s)\n")
        except Exception:
            print(f"  ⚠  No CICFlowMeter CSV in {flow_dir}")
            print("     Role 1 per-flow prediction will be skipped.\n")
            flows_df = pd.DataFrame()

        # ── build windows (now O(log n) per window — see log_chunker.py) ──────
        print("[3/3] Building time windows (fast bisect/searchsorted mode) ...")
        t0 = time.time()
        chunks = self.chunker.build_chunks(events, flows_df)
        print(f"  ✓ {len(chunks):,} windows built in {time.time()-t0:.1f}s\n")

        if quick:
            chunks = chunks[:20]
            print(f"  ⚡ Quick mode: {len(chunks)} windows\n")

        # ── Step A: run Role 1 (cheap, ms-level) synchronously for ALL chunks,
        #    and decide which chunks actually need the LLM (Fix 2) ─────────────
        print("Running Role 1 (ML) on all windows and gating Role 3 (LLM) calls ...")
        role1_cache = {}   # chunk_index -> (r1, r2)
        needs_llm   = []   # list of chunk indices that will call the LLM
        t0 = time.time()

        for chunk in chunks:
            r1, r2 = None, None
            if self._role1_ready and not flows_df.empty:
                win_flows = flow_filter_window_fast(
                    flows_df, chunk.window_start, chunk.window_end
                )
                r1, r2 = self._run_role1_on_window(win_flows, chunk.chunk_index)
            role1_cache[chunk.chunk_index] = (r1, r2)

            r1_flagged = r1 is not None and r1.get("Predicted_Label") not in self._benign_labels
            call_llm = (not skip_llm_on_benign) or chunk.has_alert or r1_flagged
            if call_llm:
                needs_llm.append(chunk.chunk_index)

        skipped = len(chunks) - len(needs_llm)
        print(
            f"  ✓ Role 1 done in {time.time()-t0:.1f}s. "
            f"LLM will run on {len(needs_llm)}/{len(chunks)} windows "
            f"({skipped} skipped as obviously benign)\n"
        )

        # ── Step B: run Role 3 (LLM) only on the windows that need it,
        #    in parallel using a thread pool (Fix 3) ───────────────────────────
        chunk_by_index = {c.chunk_index: c for c in chunks}
        llm_results    = {}   # chunk_index -> r3 dict

        if needs_llm:
            print(f"Analysing {len(needs_llm)} windows with Ollama "
                  f"({num_workers} parallel worker(s)) ...")
            t0 = time.time()

            def _analyse_one(idx: int):
                c = chunk_by_index[idx]
                return idx, self.analyst.analyse(c.chunk_text, c.chunk_index)

            if num_workers <= 1:
                for idx in needs_llm:
                    i, r3 = _analyse_one(idx)
                    llm_results[i] = r3
                    if len(llm_results) % 10 == 0:
                        print(f"  [{len(llm_results)}/{len(needs_llm)}] analysed")
            else:
                with ThreadPoolExecutor(max_workers=num_workers) as pool:
                    futures = {pool.submit(_analyse_one, idx): idx for idx in needs_llm}
                    done = 0
                    for future in as_completed(futures):
                        idx, r3 = future.result()
                        llm_results[idx] = r3
                        done += 1
                        if done % 10 == 0 or done == len(needs_llm):
                            elapsed = time.time() - t0
                            eta = (elapsed / done) * (len(needs_llm) - done)
                            print(f"  [{done}/{len(needs_llm)}] analysed  "
                                  f"ETA={eta/60:.1f}min")

            print(f"  ✓ LLM analysis done in {(time.time()-t0)/60:.1f} min\n")

        # ── Step C: merge Role1 + Role3 (or the skip sentinel) via decision engine
        alerts = []
        for chunk in chunks:
            r1, r2 = role1_cache[chunk.chunk_index]
            r3 = llm_results.get(chunk.chunk_index)
            if r3 is None:
                r3 = dict(_SKIPPED_VERDICT_TEMPLATE)

            alert = self.engine.merge(
                role1_result  = r1,
                role2_data    = r2,
                role3_verdict = r3,
                flow_features = r1 or {},
            )
            alerts.append(alert)
            self._append_alert(alert)

        self._print_summary(alerts)
        return alerts

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC — offline, MEMORY-BOUNDED streaming path (default, Fix v4)
    # ══════════════════════════════════════════════════════════════════════════

    def _run_offline_streaming(
        self,
        eve_dir:     Optional[str] = None,
        flow_dir:    Optional[str] = None,
        quick:       bool          = False,
        num_workers: int           = 4,
        skip_llm_on_benign: bool   = True,
        db_dir:      Optional[str] = None,
    ) -> List[UnifiedAlert]:
        """
        Memory-bounded offline evaluation. Never holds the full events
        list or flows DataFrame in RAM — instead:

          1. Streams eve.json / CICFlowMeter CSV into a SQLite index on
             disk (batched inserts -> bounded RAM during indexing,
             regardless of total file size).
          2. Streams one WindowChunk at a time from indexed range
             queries (src/chunker/log_chunker.py build_chunks_streaming).
          3. Runs Role 1 (ms-level) immediately per window.
          4. Submits only the windows that need Role 3 (LLM) to a
             BOUNDED thread pool — at most ~2*num_workers windows are
             ever held in memory at once, not the whole dataset.
          5. Writes + discards each alert as soon as it is ready.

        This is the correct path for any machine where the in-memory
        path (run_offline with low_memory=False) is killed by the OS
        OOM killer while loading events/flows — which can happen
        regardless of dataset size, since RAM use there depends on how
        many events happen to be alerts/http/etc, not just file size.
        """
        from concurrent.futures import wait, FIRST_COMPLETED
        from src.ingestion.sqlite_store import (
            build_event_index, build_flow_index, query_flows_window,
        )

        print(_c("\n" + "═" * 64, "bold"))
        print(_c("  UNIFIED NIDS — OFFLINE EVALUATION (all 3 roles)", "bold"))
        print(_c("  Mode: MEMORY-BOUNDED STREAMING (SQLite-backed, default)", "bold"))
        role1_status = (
            f"✓ active ({'universal' if self._is_universal else 'single-dataset'})"
            if self._role1_ready else "✗ skipped (pkl not loaded)"
        )
        print(f"  Role 1+2 : {role1_status}")
        print(f"  LLM gating : {'enabled' if skip_llm_on_benign else 'disabled'}")
        print(f"  Parallel workers : {num_workers}  (max ~{num_workers*2} windows held in RAM at once)")
        print(_c("═" * 64 + "\n", "bold"))

        # ── FIX: never mix results from different runs ─────────────────────────
        # unified_alerts.jsonl was previously opened in append mode with no
        # reset, so every offline run's results accumulated on top of all
        # previous runs' (including runs with different models, before/after
        # bugfixes, etc). Any diagnostic reading that file would silently mix
        # data from multiple, incompatible runs. Each offline run now starts
        # from a clean file; the previous run's data is archived (never
        # deleted) with a timestamp so nothing is lost.
        if os.path.exists(self._alert_log) and os.path.getsize(self._alert_log) > 0:
            archive_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            archive_path = self._alert_log.replace(
                ".jsonl", f"_archived_{archive_ts}.jsonl"
            )
            os.rename(self._alert_log, archive_path)
            print(f"  ℹ  Previous run's alerts archived → {os.path.basename(archive_path)}")
        # start this run's log fresh
        open(self._alert_log, "w").close()

        eve_dir  = eve_dir  or self.cfg.paths.eve_logs_dir
        flow_dir = flow_dir or self.cfg.paths.cicflow_csv_dir
        # SQLite MUST live on LOCAL disk, never on a Google Drive FUSE mount.
        # WAL mode needs shared-memory (.db-shm) and byte-range locks that FUSE
        # does not implement correctly; on Drive this produced "no such table:
        # events" and, worse, silent partial reads — query_flows_window
        # returned only a handful of rows, so a Friday with ~484 attack-bearing
        # windows was scored as 2. Default to a per-run local temp dir; only
        # honour an explicit --db_dir if it is not under /content/drive.
        if db_dir and "/content/drive" in db_dir.replace("\\", "/"):
            print(_c(f"  ⚠  --db_dir {db_dir} is on Google Drive; SQLite is "
                     "unreliable there. Using local disk instead.", "yellow"))
            db_dir = None
        if not db_dir:
            import tempfile
            db_dir = tempfile.mkdtemp(prefix="nids_cache_")
        os.makedirs(db_dir, exist_ok=True)
        events_db = os.path.join(db_dir, "events.db")
        flows_db  = os.path.join(db_dir, "flows.db")
        # Remove any stale db + its WAL sidecars so a previous run cannot leak
        # rows or a half-checkpointed table into this one.
        for _base in (events_db, flows_db):
            for _suffix in ("", "-wal", "-shm"):
                _p = _base + _suffix
                if os.path.exists(_p):
                    os.remove(_p)
        print(f"  SQLite cache: {db_dir}  (local disk)")

        # ── Step 0: align timezones BEFORE anything parses a timestamp ────────
        # CICFlowMeter emits naive local wall-clock times; Suricata emits
        # ISO-8601 with an explicit offset. Reading the naive values as UTC
        # put the two sources six hours apart on this capture, so Role 1 and
        # Role 3 were fused across windows describing different traffic.
        # Both artefacts come from the same machine and pcap, so Suricata's
        # recorded offset is the correct interpretation for both.
        self._align_timezones(eve_dir)

        # ── Step 1: index events into SQLite (batched, bounded RAM) ────────────
        print("[1/3] Indexing Suricata events into SQLite (streaming, bounded RAM) ...")
        t0 = time.time()
        n_events, n_dropped, n_bad = build_event_index(eve_dir, events_db)
        print(
            f"  ✓ {n_events:,} events indexed  "
            f"({n_dropped:,} dropped by type filter, {n_bad:,} bad lines)  "
            f"({time.time()-t0:.1f}s)\n"
        )

        # ── Step 2: index flows into SQLite (batched, bounded RAM) ─────────────
        print("[2/3] Indexing CICFlowMeter flows into SQLite (streaming, bounded RAM) ...")
        t0 = time.time()
        have_flows = False
        try:
            n_flows = build_flow_index(flow_dir, flows_db)
            have_flows = n_flows > 0
            print(f"  ✓ {n_flows:,} flows indexed  ({time.time()-t0:.1f}s)\n")
        except Exception as exc:
            print(f"  ⚠  No CICFlowMeter CSV in {flow_dir}: {exc}")
            print("     Role 1 per-flow prediction will be skipped.\n")

        # ── Step 2b: refuse to fuse sources that do not describe the same time
        if have_flows:
            self._assert_time_overlap(events_db, flows_db)
            print()

        # ── Step 3: stream windows, run Role1 immediately, LLM via bounded pool
        print("[3/3] Streaming windows: Role 1 immediate, Role 3 via bounded pool ...")
        t0 = time.time()

        chunk_gen = self.chunker.build_chunks_streaming(
            events_db, flows_db if have_flows else None
        )

        alerts: List[UnifiedAlert] = []
        in_flight = {}   # future -> (chunk, r1, r2, sig_key, role1_latency)
        max_in_flight = max(2, num_workers * 2)
        processed  = 0
        llm_calls  = 0
        cache_hits = 0

        # ── THESIS RESULT COLLECTION ─────────────────────────────────────────
        # Accumulates the ablation table (Role1-only vs Role3-only vs Combined),
        # latency stats, and per-family accuracy against ground truth (the
        # Label column already extracted per-window into chunk.ground_truth).
        # See src/evaluator/thesis_evaluator.py for what this produces.
        # Tag the report with the sub-model actually used, so a three-dataset
        # thesis cannot pool results from different schemas into one table.
        thesis_eval = ThesisEvaluator(
            self.cfg,
            dataset_name=(
                self._forced_dataset or self._routed_dataset or "auto"
            ),
        )
        run_start_wall = time.time()

        # ── Signature cache (FIX for alert-dense captures) ─────────────────────
        # On a capture where a Suricata alert fires in nearly every window (e.g.
        # a sustained DoS/DDoS burst repeats the SAME signature for minutes),
        # the has_alert gate alone barely reduces LLM calls — almost every
        # window "has an alert" even though it is the SAME alert repeating.
        # This cache reuses the most recent LLM verdict for a given
        # (dominant src_ip, dominant signature) pair within sig_cache_ttl
        # seconds, avoiding a fresh LLM call for what is functionally the
        # same event repeating window after window.
        sig_cache     = {}   # (src_ip, signature) -> (r3_dict, window_start)
        sig_cache_ttl = max(60, self.cfg.chunker.window_seconds * 6)

        def _window_signature_key(chunk):
            """Identify the dominant (src_ip, alert signature) for this
            window, used to detect repeated identical alert bursts."""
            alerts_in_chunk = [e for e in chunk.eve_events if e["event_type"] == "alert"]
            if not alerts_in_chunk:
                return None
            from collections import Counter
            pairs = [
                (e.get("src_ip", ""), (e.get("alert") or {}).get("signature", ""))
                for e in alerts_in_chunk
            ]
            (top_pair, _count), = Counter(pairs).most_common(1)
            return top_pair

        def _submit_llm(pool, chunk, r1, r2, sig_key, role1_latency):
            nonlocal llm_calls
            fut = pool.submit(self.analyst.analyse, chunk.chunk_text, chunk.chunk_index)
            in_flight[fut] = (chunk, r1, r2, sig_key, role1_latency)
            llm_calls += 1

        def _finalise(chunk_c, r1, r2, r3, sig_key, role1_latency,
                       from_cache=False, is_auto_benign=False):
            nonlocal processed
            alert = self.engine.merge(
                role1_result=r1, role2_data=r2,
                role3_verdict=r3, flow_features=r1 or {},
            )
            alerts.append(alert)
            self._append_alert(alert)
            thesis_eval.add_window(
                chunk=chunk_c, r1=r1, r3=r3, alert=alert,
                role1_latency_s=role1_latency,
                is_llm_cache_hit=from_cache,
                is_auto_benign=is_auto_benign,
            )
            processed += 1
            if sig_key is not None and not from_cache:
                sig_cache[sig_key] = (r3, chunk_c.window_start)
            if processed % 20 == 0:
                elapsed = time.time() - t0
                print(
                    f"  [{processed}] windows finalised  ({elapsed:.1f}s elapsed, "
                    f"{llm_calls} LLM calls, {cache_hits} signature-cache hits)"
                )

        def _drain_completed(block: bool = False):
            if not in_flight:
                return
            if block:
                done, _ = wait(list(in_flight.keys()), return_when=FIRST_COMPLETED)
            else:
                done = [f for f in in_flight if f.done()]
            for fut in done:
                chunk_c, r1, r2, sig_key, role1_latency = in_flight.pop(fut)
                try:
                    r3 = fut.result()
                except Exception as exc:
                    log.warning("LLM call failed for chunk %d: %s", chunk_c.chunk_index, exc)
                    r3 = dict(_SKIPPED_VERDICT_TEMPLATE)
                    r3["explanation"] = f"LLM call failed: {exc}"
                _finalise(chunk_c, r1, r2, r3, sig_key, role1_latency)

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            for i, chunk in enumerate(chunk_gen):
                if quick and i >= 20:
                    break

                r1, r2 = None, None
                role1_latency = None
                if self._role1_ready and have_flows:
                    win_flows = query_flows_window(
                        flows_db, chunk.window_start, chunk.window_end
                    )
                    _t_r1 = time.perf_counter()
                    r1, r2 = self._run_role1_on_window(win_flows, chunk.chunk_index)
                    role1_latency = time.perf_counter() - _t_r1

                r1_flagged = r1 is not None and r1.get("Predicted_Label") not in self._benign_labels
                call_llm = (not skip_llm_on_benign) or chunk.has_alert or r1_flagged

                if call_llm:
                    sig_key = _window_signature_key(chunk)

                    # signature-cache check: same dominant alert seen recently?
                    cached_entry = sig_cache.get(sig_key) if sig_key is not None else None
                    if cached_entry is not None:
                        cached_r3, cached_at = cached_entry
                        age = (chunk.window_start - cached_at).total_seconds()
                        if 0 <= age <= sig_cache_ttl:
                            r3 = dict(cached_r3)
                            r3["explanation"] = (
                                r3.get("explanation", "")
                                + f" [cached verdict — identical signature seen {age:.0f}s ago]"
                            )
                            cache_hits += 1
                            _finalise(chunk, r1, r2, r3, sig_key, role1_latency, from_cache=True)
                            _drain_completed(block=False)
                            continue

                    # backpressure: don't let the in-flight set grow unbounded
                    while len(in_flight) >= max_in_flight:
                        _drain_completed(block=True)
                    _submit_llm(pool, chunk, r1, r2, sig_key, role1_latency)
                else:
                    r3 = dict(_SKIPPED_VERDICT_TEMPLATE)
                    _finalise(chunk, r1, r2, r3, None, role1_latency, is_auto_benign=True)

                # opportunistically drain finished futures without blocking
                _drain_completed(block=False)

            # drain whatever is still in flight after the generator is exhausted
            while in_flight:
                _drain_completed(block=True)

        wall_clock = time.time() - run_start_wall
        print(
            f"  ✓ Streaming complete: {processed} windows in {(time.time()-t0)/60:.1f} min  "
            f"({llm_calls} LLM calls, {cache_hits} signature-cache hits, "
            f"{processed - llm_calls - cache_hits} auto-benign)\n"
        )

        self._print_summary(alerts)

        # ── THESIS RESULT GENERATION ──────────────────────────────────────────
        # Produces the ablation table (Role1-only vs Role3-only vs Combined),
        # per-family accuracy, latency stats, and throughput — everything
        # listed as "still needed" for the results section. Only meaningful
        # for windows where chunk.ground_truth was non-empty (i.e. the
        # CICFlowMeter CSV had a Label column, as with the CICIDS2017 Friday
        # capture); on unlabeled real traffic the ablation numbers will be
        # empty/zero but latency/throughput/conflict stats still populate.
        thesis_report = thesis_eval.generate_report(wall_clock_seconds=wall_clock)
        thesis_eval.save_report(thesis_report)

        return alerts

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC — live  (unchanged: live windows are small, gating/parallelism
    #                 are not needed at live cadence)
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _rep_endpoint_fields(row) -> dict:
        """
        Pull src/dst IP:port off a single flow row (e.g. the window's
        representative flow) for display, tolerating the column-name
        variants CICFlowMeter/NFStream output uses. Returns None for any
        field that isn't present rather than raising — callers (the
        dashboard) already treat None/missing as "unknown".

        Casts to plain str/int explicitly: pandas/numpy scalar types
        (numpy.int64 etc.) aren't JSON-serialisable, and _append_alert's
        json.dumps has no custom encoder — an unguarded numpy value here
        would raise inside a bare try/except that just logs a warning,
        silently dropping the whole alert, not just this field.
        """
        def get(*names):
            for n in names:
                if n in row.index and pd.notna(row[n]):
                    return row[n]
            return None

        ip1, port1 = get("Src IP", "src_ip"), get("Src Port", "src_port")
        ip2, port2 = get("Dst IP", "dst_ip"), get("Destination Port", "dst_port")
        return {
            "src_ip":   str(ip1) if ip1 is not None else None,
            "src_port": int(port1) if port1 is not None else None,
            "dst_ip":   str(ip2) if ip2 is not None else None,
            "dst_port": int(port2) if port2 is not None else None,
        }

    @staticmethod
    def _window_verdict(wf: pd.DataFrame, live_mode: bool, live_confidence_threshold: float = 90.0):
        """
        Decide the window's dominant label and representative flow from a
        DataFrame that already has Predicted_Label/Confidence/Is_Attack
        columns. Returns (dominant_label, rep_row, live_override: bool).

        MAJORITY vote (attack iff attack flows outnumber benign) is the
        offline/evaluation rule — see the long comment where this used to
        live: at ~1,400 flows/window and a ~0.06% per-flow FPR, "any attack
        flow" produced a 70%+ window-level false-positive rate, so majority
        was the fix, and offline callers (which measure against that exact
        ground truth) must keep using it unchanged.

        Live windows are nowhere near that size — tens to a couple hundred
        flows, not ~1,400 — so the same per-flow FPR produces a much lower
        expected false-positive COUNT per window, and a single flow the
        model is itself very confident about (>=live_confidence_threshold)
        is a materially stronger signal than "any attack flow at any
        confidence". live_mode=True lets a lone high-confidence attack flow
        surface as the window's verdict even when it's outvoted by a larger
        batch of unrelated flows sharing the same capture tick (e.g. ambient
        traffic) — this is what a real hydra-vs-CICIDS2017 brute-force
        detection looked like in practice: 5/5 flows at 98%+ confidence,
        correctly classified by Role 1, but invisible in the window log
        because majority vote against a much larger unrelated batch called
        the window "benign".
        """
        n_attack_flows = int(wf["Is_Attack"].sum())
        n_flows = len(wf)
        window_is_attack = n_attack_flows > (n_flows - n_attack_flows)

        high_conf_attack = None
        if live_mode and not window_is_attack and n_attack_flows > 0:
            attack_rows = wf[wf["Is_Attack"]]
            best = attack_rows.loc[attack_rows["Confidence"].idxmax()]
            if best["Confidence"] >= live_confidence_threshold:
                high_conf_attack = best

        if window_is_attack:
            attack_rows = wf[wf["Is_Attack"]]
            dominant_label = attack_rows["Predicted_Label"].mode().iloc[0]
            rep = attack_rows.loc[attack_rows["Confidence"].idxmax()]
            return dominant_label, rep, False
        if high_conf_attack is not None:
            return high_conf_attack["Predicted_Label"], high_conf_attack, True

        benign_rows = wf[~wf["Is_Attack"]]
        dominant_label = (benign_rows["Predicted_Label"].mode().iloc[0]
                          if not benign_rows.empty
                          else wf["Predicted_Label"].mode().iloc[0])
        rep = wf.loc[wf["Confidence"].idxmax()]
        return dominant_label, rep, False

    @staticmethod
    def _cross_flow_heuristic(win_flows: pd.DataFrame) -> Optional[dict]:
        """
        Complementary per-source-IP pattern check within a single live window.

        Role 1's per-flow ML classifier is trained on CICIDS2017's WAN-latency
        flows; real LAN attack traffic (near-instant SYN/RST port scans, huge
        floods of millisecond-duration connections) can look nothing like that
        distribution and score confidently Benign despite being an obvious
        scan or flood by volume alone. This does not replace Role 1 — it's a
        second, cheap signal fed into the same decision engine, and only ever
        used when Role 1 didn't already call the window an attack.
        """
        src_col  = "Src IP" if "Src IP" in win_flows.columns else None
        port_col = "Destination Port" if "Destination Port" in win_flows.columns else None
        if src_col is None or port_col is None or win_flows.empty:
            return None

        best = None  # (src_ip, label, score, n_flows, n_ports, group)
        for src_ip, g in win_flows.groupby(src_col):
            n_flows = len(g)
            n_ports = g[port_col].nunique()
            if n_ports > 20:
                label, score = "PortScan (Heuristics)", n_ports
            elif n_flows > 100:
                label, score = "DoS/Flood (Heuristics)", n_flows
            else:
                continue
            if best is None or score > best[2]:
                best = (src_ip, label, score, n_flows, n_ports, g)

        if best is None:
            return None
        src_ip, label, _score, n_flows, n_ports, g = best
        return {
            "Predicted_Label": label,
            "Confidence":      100.0,
            "n_flows":         n_flows,
            "n_attacks":       n_flows,
            "attack_fraction": 1.0,
            "dataset_routed":  "heuristic",
            "n_ports":         n_ports,
            **UnifiedPipeline._rep_endpoint_fields(g.iloc[0]),
        }

    def run_live(self, cicflow_csv: Optional[str] = None) -> None:
        import signal
        import sys

        print(_c("\n" + "═" * 64, "bold"))
        print(_c("  UNIFIED NIDS — LIVE MONITORING", "bold"))
        role1_status = (
            f"✓ active ({'universal' if self._is_universal else 'single-dataset'})"
            if self._role1_ready else "✗ skipped (pkl not loaded)"
        )
        print(f"  Role 1+2 : {role1_status}")
        print(_c("  Ctrl-C to stop\n", "cyan"))

        from src.ingestion.cicflow_reader import load_cicflow_file

        live_flows_df = pd.DataFrame()
        flow_dir      = None
        loaded_files  = set()

        if cicflow_csv:
            if os.path.isdir(cicflow_csv):
                flow_dir = cicflow_csv
                print(f"  ✓ CICFlowMeter: watching {flow_dir} for new flow CSVs")
            else:
                try:
                    live_flows_df = load_cicflow_file(cicflow_csv)
                    print(f"  ✓ CICFlowMeter: {len(live_flows_df):,} flows")
                except Exception as exc:
                    print(f"  ⚠  CICFlowMeter not loaded: {exc}")

        def refresh_flow_dir() -> pd.DataFrame:
            """
            Pick up new CICFlowMeter CSVs written by flow_processor.sh since last
            check. Returns just the newly-loaded rows.

            Live flow CSVs always lag real time (tcpdump's -G rotation delay +
            CICFlowMeter run time), so a flow's own Timestamp column is usually
            already behind the wall-clock window that produced it. Matching newly
            *arrived* files to the current wall-clock window (like the offline
            pipeline matches historical files) would silently drop almost every
            flow. Instead, score whatever rows just arrived, independent of the
            embedded Timestamp.
            """
            nonlocal live_flows_df
            if not flow_dir:
                return pd.DataFrame()
            try:
                current = {
                    f for f in os.listdir(flow_dir) if f.endswith(".csv")
                }
            except OSError as exc:
                log.warning("refresh_flow_dir: could not list %s: %s", flow_dir, exc)
                return pd.DataFrame()
            new_files = sorted(current - loaded_files)
            # DIAGNOSTIC: this is the line that would have caught the live-test
            # bug directly — if loaded_files isn't actually excluding files it
            # already loaded, new_files stays close to len(current) forever
            # instead of shrinking to just what's genuinely new each cycle.
            log.debug(
                "refresh_flow_dir: dir has %d csv(s), loaded_files=%d, "
                "new_files=%d%s",
                len(current), len(loaded_files), len(new_files),
                f" {new_files}" if len(new_files) <= 5 else
                f" (first 5: {new_files[:5]})",
            )
            if not new_files:
                return pd.DataFrame()
            new_frames = []
            failed = []
            for fname in new_files:
                try:
                    new_frames.append(load_cicflow_file(os.path.join(flow_dir, fname)))
                    loaded_files.add(fname)
                except Exception as exc:
                    # FIX: this used to be print()-only, which never reaches
                    # logs/nids_role3.log (that file only captures the `log`
                    # module's output) — a run could silently fail to load
                    # every single new file, every cycle, with zero trace in
                    # the persisted log. This is very likely what produced
                    # "R1=missing" for 18 straight minutes in the Aug 21 live
                    # test: if new_frames ends up empty here, win_flows is
                    # empty, and Role 1 is silently skipped for that window —
                    # with nothing on disk explaining why.
                    log.warning("refresh_flow_dir: failed to load %s: %s", fname, exc)
                    print(f"  ⚠  Skipping flow CSV {fname}: {exc}")
                    failed.append(fname)
            if failed:
                log.warning(
                    "refresh_flow_dir: %d/%d new file(s) failed to load this cycle: %s",
                    len(failed), len(new_files), failed,
                )
            if not new_frames:
                return pd.DataFrame()
            new_flows_df = pd.concat(new_frames, ignore_index=True)
            live_flows_df = pd.concat([live_flows_df, new_flows_df], ignore_index=True)
            if "Timestamp" in live_flows_df.columns:
                live_flows_df = live_flows_df.sort_values(
                    "Timestamp", na_position="last"
                ).reset_index(drop=True)
            print(
                f"  ✓ CICFlowMeter: +{len(new_flows_df):,} flows "
                f"from {len(new_files):,} new CSV(s) (total {len(live_flows_df):,})"
            )
            log.info(
                "refresh_flow_dir: +%d flows from %d new CSV(s), live_flows_df total=%d",
                len(new_flows_df), len(new_files), len(live_flows_df),
            )
            return new_flows_df

        buffer       = []
        buffer_lock  = threading.Lock()
        chunk_index  = [0]
        running      = [True]

        def sigint(sig, frame):
            running[0] = False
            print(_c("\n  Stopping ...", "yellow"))
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint)

        def window_loop():
            while running[0]:
                time.sleep(self.cfg.chunker.window_seconds)
                if not running[0]:
                    break
                try:
                    _window_loop_iteration()
                except Exception as exc:
                    # FIX: this used to be uncaught — a single bad window
                    # (e.g. one malformed flow value, one downstream
                    # library edge case) silently killed this ENTIRE
                    # background thread for the rest of the process. No
                    # further alerts of ANY kind (Role 1, Role 3, or
                    # fused) would ever be produced again, with nothing
                    # to show for it but a scrollable traceback — this is
                    # the confirmed cause of "Role 1 goes silent for the
                    # rest of the session" seen in earlier live tests.
                    # One bad window should cost one window, not the rest
                    # of the run.
                    log.error(
                        "window_loop: uncaught exception this cycle (chunk "
                        "#%04d) — window skipped, monitoring continues: %s",
                        chunk_index[0], exc, exc_info=True,
                    )
                    print(_c(
                        f"  ⚠ window_loop error (chunk #{chunk_index[0]:04d}, "
                        f"monitoring continues): {exc}", "red",
                    ))

        def _window_loop_iteration():
                new_flows = refresh_flow_dir()
                now       = datetime.now(timezone.utc)
                win_start = now - timedelta(seconds=self.cfg.chunker.window_seconds)
                with buffer_lock:
                    batch = list(buffer)
                    buffer.clear()

                if flow_dir:
                    win_flows = new_flows
                elif not live_flows_df.empty:
                    win_flows = flow_filter_window_fast(live_flows_df, win_start, now)
                else:
                    win_flows = pd.DataFrame()

                if not batch and win_flows.empty:
                    return

                chunk = self.chunker.build_single_chunk(
                    events       = batch,
                    flows_df     = live_flows_df,
                    chunk_index  = chunk_index[0],
                    window_start = win_start,
                    window_end   = now,
                )
                r3 = self.analyst.analyse(
                    chunk.chunk_text, chunk.chunk_index
                )
                r1, r2 = None, None
                if self._role1_ready and not win_flows.empty:
                    r1, r2 = self._run_role1_on_window(
                        win_flows, chunk_index[0], live_mode=True
                    )
                elif not win_flows.empty:
                    log.warning(
                        "window_loop: win_flows has %d rows but self._role1_ready "
                        "is False — Role 1 will not run this window",
                        len(win_flows),
                    )
                else:
                    # DIAGNOSTIC: this is the direct point where "R1=missing"
                    # gets decided. If this fires repeatedly while flow CSVs
                    # are visibly still arriving on disk, the problem is
                    # upstream in refresh_flow_dir() silently failing to
                    # produce usable rows — check its own new log lines first.
                    log.debug(
                        "window_loop: win_flows empty this cycle (chunk #%04d) "
                        "— Role 1 skipped",
                        chunk_index[0],
                    )
                if not win_flows.empty and (
                    r1 is None or r1.get("Predicted_Label") in self._benign_labels
                ):
                    heuristic = self._cross_flow_heuristic(win_flows)
                    if heuristic:
                        r1 = heuristic
                        print(_c(
                            f"  ⚡ Cross-flow heuristic: {heuristic['Predicted_Label']} — "
                            f"{heuristic['src_ip']} ({heuristic['n_flows']} flows"
                            + (f", {heuristic['n_ports']} ports)" if heuristic.get("n_ports") else ")"),
                            "yellow",
                        ))
                alert = self.engine.merge(r1, r2, r3, r1 or {})
                self._print_alert_live(alert)
                self._append_alert(alert)
                chunk_index[0] += 1

        t = threading.Thread(target=window_loop, daemon=True)
        t.start()

        for event in tail_eve_file(
            self.cfg.paths.live_eve_json,
            poll_interval = self.cfg.live.poll_interval_seconds,
            from_start    = False,
        ):
            if not running[0]:
                break
            with buffer_lock:
                buffer.append(event)

    # ══════════════════════════════════════════════════════════════════════════
    # TIMEZONE ALIGNMENT + OVERLAP VALIDATION
    # ══════════════════════════════════════════════════════════════════════════

    # ══════════════════════════════════════════════════════════════════════════
    # TRAIN/DEPLOY FEATURE-DRIFT DETECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _accumulate_drift_sample(self, raw: np.ndarray, ds: str, ds_feats) -> None:
        """Collect raw feature rows until there are enough to judge, then check."""
        self._drift_buffer.append(np.asarray(raw, dtype=np.float64))
        self._drift_rows += len(raw)
        if self._drift_rows < self._drift_min_rows:
            return
        self._drift_checked = True
        try:
            sample = np.vstack(self._drift_buffer)
        finally:
            self._drift_buffer = []
        self._check_feature_drift(sample, ds, list(ds_feats))

    def _check_feature_drift(self, sample: np.ndarray, ds: str, ds_feats) -> None:
        """
        Compare deployed feature medians against the training medians.

        RobustScaler stores center_ (training median) and scale_ (training
        IQR) per feature, so the training distribution is already available
        inside the model — no need to reload any training set.

        A feature whose deployed median sits many training-IQRs away from the
        training median is one the model has never seen values like. When that
        happens broadly, every scaled row lands near the origin, every flow
        looks average, and the model returns its majority class with high
        confidence. That is indistinguishable from "quiet network" in the
        output, which is exactly why it has to be caught here.
        """
        scaler = (getattr(self._ensemble, "sub_scalers", None) or {}).get(ds) \
            if self._ensemble is not None else None
        scaler = scaler or self._scaler
        if scaler is None or not hasattr(scaler, "center_"):
            return

        centre = np.asarray(scaler.center_, dtype=float)
        spread = np.asarray(scaler.scale_, dtype=float)
        if len(centre) != sample.shape[1]:
            return

        with np.errstate(all="ignore"):
            dep_med = np.nanmedian(sample, axis=0)

        drifted = []
        for i, feat in enumerate(ds_feats):
            tr_m, tr_s, dp_m = centre[i], spread[i], dep_med[i]
            if not np.isfinite(dp_m):
                continue
            # Ratio catches order-of-magnitude unit errors; the IQR offset
            # catches shifts on features whose median is legitimately 0.
            if abs(tr_m) > 1e-9 and abs(dp_m) > 1e-9:
                ratio = dp_m / tr_m
                if np.isfinite(ratio) and abs(np.log10(abs(ratio))) >= 1.0:
                    drifted.append((feat, tr_m, dp_m, ratio))
            elif tr_s > 1e-9:
                z = abs(dp_m - tr_m) / tr_s
                if z >= 10.0:
                    drifted.append((feat, tr_m, dp_m, float("nan")))

        frac = len(drifted) / max(1, len(ds_feats))
        if frac < 0.20:
            log.info("Feature-drift check for %s: %d/%d features drifted — OK",
                     ds, len(drifted), len(ds_feats))
            return

        print(_c(
            f"\n  ⚠  TRAIN/DEPLOY FEATURE DRIFT: {len(drifted)}/{len(ds_feats)} "
            f"features for '{ds}' are 10x+ off the distribution the model was "
            f"fitted on.",
            "red",
        ))
        for feat, tr_m, dp_m, ratio in sorted(
            drifted, key=lambda r: -abs(np.log10(abs(r[3]))) if np.isfinite(r[3]) else 0
        )[:8]:
            r = f"{ratio:.3g}" if np.isfinite(ratio) else "n/a"
            print(f"       {feat[:28]:<30} train={tr_m:<12.6g} "
                  f"deploy={dp_m:<12.6g} ratio={r}")
        print(_c(
            "     Feature NAMES match but VALUES do not. The usual cause is a\n"
            "     different extractor: CIC's Java CICFlowMeter reports durations\n"
            "     in microseconds and lengths excluding headers, while\n"
            "     python-cicflowmeter reports seconds and includes headers.\n"
            "     Role 1 will collapse to its majority class at high confidence.\n"
            "     Run: python scripts/diagnose_feature_drift.py --help\n"
            "     Role 1 is DISABLED for this run — an ablation table where\n"
            "     Role 1 answers one class is not a measurement of Role 1.",
            "yellow",
        ))
        log.error("Feature drift for %s: %d/%d features drifted; Role1 disabled",
                  ds, len(drifted), len(ds_feats))
        self._role1_ready = False

    def _align_timezones(self, eve_dir: str) -> None:
        """
        Decide how to interpret the naive CICFlowMeter timestamps.

        Priority:
          1. explicit config `cicflow.timestamp_utc_offset_hours` (a number)
          2. auto-detect from the offset Suricata wrote into eve.json
          3. UTC, with a loud warning — this is the old broken behaviour
        """
        from src.ingestion.suricata_reader import detect_utc_offset
        from src.ingestion.cicflow_reader import set_flow_utc_offset

        configured = None
        cicflow_cfg = getattr(self.cfg, "cicflow", None) or getattr(
            self.cfg, "cicflowmeter", None
        )
        if cicflow_cfg is not None:
            configured = getattr(cicflow_cfg, "timestamp_utc_offset_hours", None)

        if configured is not None and str(configured).lower() != "auto":
            offset = timedelta(hours=float(configured))
            print(f"[0/3] Timezone: using configured flow offset UTC"
                  f"{offset.total_seconds()/3600:+.2f}h")
            set_flow_utc_offset(offset)
            return

        detected = detect_utc_offset(eve_dir)
        if detected is not None:
            print(f"[0/3] Timezone: detected UTC{detected.total_seconds()/3600:+.2f}h "
                  f"from eve.json — applying to naive CICFlowMeter timestamps")
            set_flow_utc_offset(detected)
            return

        print(_c(
            "[0/3] Timezone: could not detect an offset from eve.json — "
            "falling back to UTC.\n"
            "      If your CICFlowMeter CSV holds LOCAL wall-clock times, flows "
            "and Suricata\n"
            "      events will land in different windows and the fusion results "
            "will be\n"
            "      meaningless. Set cicflow.timestamp_utc_offset_hours in "
            "config/settings.yaml.",
            "yellow",
        ))
        set_flow_utc_offset(timedelta(0))

    def _assert_time_overlap(
        self, events_db: str, flows_db: str, min_overlap_pct: float = 80.0
    ) -> None:
        """
        Verify Suricata events and CICFlowMeter flows actually cover the same
        wall-clock period before fusing them window by window.

        This check exists because its absence let a six-hour offset run to
        completion and produce a full report: the chunker spanned
        min(eve_start) .. max(flow_end) = 842 windows, 615 of which held zero
        flows, and every window that did hold flows paired them with Suricata
        events from a different part of the day.
        """
        from src.ingestion.sqlite_store import get_time_range

        try:
            e_start, e_end = get_time_range(events_db, table="events")
            f_start, f_end = get_time_range(flows_db, table="flows")
        except Exception as exc:
            log.warning("Could not verify time overlap: %s", exc)
            return

        if not all((e_start, e_end, f_start, f_end)):
            log.warning("Incomplete time ranges — overlap check skipped.")
            return

        ov_start, ov_end = max(e_start, f_start), min(e_end, f_end)
        overlap_s = max(0.0, (ov_end - ov_start).total_seconds())
        flow_span = max(1e-9, (f_end - f_start).total_seconds())
        eve_span  = max(1e-9, (e_end - e_start).total_seconds())
        pct = overlap_s / min(flow_span, eve_span) * 100

        print(f"  Suricata events : {e_start} → {e_end}")
        print(f"  CICFlow flows   : {f_start} → {f_end}")
        print(f"  Overlap         : {overlap_s/3600:.2f}h "
              f"({pct:.1f}% of the shorter span)")

        if pct < min_overlap_pct:
            raise ValueError(
                f"Suricata events and CICFlowMeter flows overlap by only "
                f"{pct:.1f}% (need >= {min_overlap_pct}%).\n"
                f"  events : {e_start} .. {e_end}\n"
                f"  flows  : {f_start} .. {f_end}\n"
                f"  gap between starts: "
                f"{(f_start - e_start).total_seconds()/3600:+.2f}h\n"
                "Fusing them window-by-window would pair unrelated traffic and "
                "produce agreement/conflict statistics that measure the "
                "misalignment rather than the models.\n"
                "Most likely a timezone problem: CICFlowMeter writes naive "
                "local times while Suricata writes an explicit offset. Set "
                "cicflow.timestamp_utc_offset_hours in config/settings.yaml "
                "(the gap above is usually exactly the offset you need)."
            )

    # ══════════════════════════════════════════════════════════════════════════
    # ROLE 1 SETUP — detects pkl format (unchanged from previous version)
    # ══════════════════════════════════════════════════════════════════════════

    def _setup_role1(self, nids_out: dict) -> None:
        try:
            if "sub_models" in nids_out and "ensemble" in nids_out:
                self._is_universal  = True
                self._ensemble      = nids_out["ensemble"]
                self._le            = nids_out["label_encoder"]
                self._scaler        = nids_out.get("scaler")
                self._feature_names = nids_out.get("feature_names", [])
                self._results       = nids_out.get("results", {})
                self._role1_ready   = True

                # Per-dataset scalers may live at the top level of the pkl
                # (newer exports) rather than on the unpickled ensemble, which
                # predates the attribute entirely.
                sub_scalers = nids_out.get("sub_scalers") or {}
                if sub_scalers and not getattr(self._ensemble, "sub_scalers", None):
                    self._ensemble.sub_scalers = sub_scalers
                if not getattr(self._ensemble, "sub_scalers", None):
                    self._ensemble.sub_scalers = {}

                log.info(
                    "Role1 ready (universal): datasets=%s  classes=%d",
                    nids_out.get("datasets_used"),
                    len(self._le.classes_),
                )
                print(f"  ✓ Role 1 ready: UniversalEnsemble")
                print(f"    Datasets : {nids_out.get('datasets_used')}")

                missing_scalers = [
                    ds for ds in self._ensemble.datasets
                    if not self._ensemble.has_scaler(ds)
                ]
                if missing_scalers:
                    print(_c(
                        f"    ⚠  No per-dataset scaler for: "
                        f"{', '.join(missing_scalers)}\n"
                        "       Each sub-model was trained on data scaled by "
                        "its own RobustScaler; this pkl stores only one\n"
                        "       global scaler, so routing to any other dataset "
                        "previously fed the model unscaled input via a\n"
                        "       swallowed exception. Re-export with "
                        "'sub_scalers' (see scripts/export_sub_scalers.md).",
                        "yellow",
                    ))
                else:
                    print(f"    Scalers  : per-dataset ✓ "
                          f"({len(self._ensemble.datasets)}/"
                          f"{len(self._ensemble.datasets)})")
                print(f"    Classes  : {list(self._le.classes_)}")

            elif "models" in nids_out and "data" in nids_out:
                data    = nids_out["data"]
                models  = nids_out["models"]
                results = nids_out.get("results", {})

                scored = {
                    k: v for k, v in results.items()
                    if isinstance(v, dict) and "macro_f1" in v
                }
                best_name = (
                    max(scored, key=lambda k: scored[k]["macro_f1"])
                    if scored else list(models.keys())[0]
                )

                self._is_universal  = False
                self._best_model    = models[best_name]
                self._scaler        = data["scaler"]
                self._le            = data["label_encoder"]
                self._feature_names = data["feature_names"]
                self._results       = results
                self._threshold     = results.get("best_threshold", 0.5)
                self._role1_ready   = True

                log.info(
                    "Role1 ready (single): model=%s  features=%d  threshold=%.2f",
                    best_name, len(self._feature_names), self._threshold,
                )
                print(f"  ✓ Role 1 ready: {best_name} (single-dataset)")
                print(f"    Features  : {len(self._feature_names)}")
                print(f"    Classes   : {list(self._le.classes_)}")
                print(f"    Threshold : {self._threshold:.2f}")

            else:
                print(f"  ⚠  Unknown pkl structure — keys: {list(nids_out.keys())}")
                print("     pkl may have been saved with an older version.")

        except Exception as exc:
            log.warning("Could not set up Role1: %s", exc)
            print(f"  ⚠  Role 1 setup failed: {exc}")
            self._role1_ready = False

    # ══════════════════════════════════════════════════════════════════════════
    # ROLE 1 INFERENCE (unchanged)
    # ══════════════════════════════════════════════════════════════════════════

    def _run_role1_on_window(self, window_flows: pd.DataFrame, window_idx: int, live_mode: bool = False):
        if window_flows.empty:
            return None, None
        try:
            if self._is_universal:
                return self._predict_universal(window_flows, window_idx, live_mode=live_mode)
            else:
                return self._predict_single(window_flows, window_idx, live_mode=live_mode)
        except Exception as exc:
            log.warning("Role1 inference error on window %d: %s", window_idx, exc)
            return None, None

    def _report_feature_coverage(self, ds, ds_feats, missing, coverage) -> None:
        """
        Print the feature-coverage situation ONCE per dataset, listing what is
        missing. Silence here is what let a mostly-zero feature vector look
        like a confident prediction: nothing in the logs distinguished "the
        model saw the traffic" from "the model saw zeros".
        """
        if ds in self._coverage_reported:
            return
        self._coverage_reported.add(ds)

        pct = coverage * 100
        if not missing:
            print(f"  ✓ Feature coverage for {ds}: "
                  f"{len(ds_feats)}/{len(ds_feats)} (100.0%)")
            return

        colour = "yellow" if coverage >= self._min_feature_coverage else "red"
        print(_c(
            f"  {'⚠' if coverage >= self._min_feature_coverage else '✗'}  "
            f"Feature coverage for {ds}: "
            f"{len(ds_feats) - len(missing)}/{len(ds_feats)} ({pct:.1f}%) — "
            f"{len(missing)} feature(s) will be zero-filled:",
            colour,
        ))
        for f in missing[:15]:
            print(_c(f"       · {f}", colour))
        if len(missing) > 15:
            print(_c(f"       · ... and {len(missing) - 15} more", colour))

        if coverage < self._min_feature_coverage:
            print(_c(
                f"     Below the {self._min_feature_coverage*100:.0f}% minimum — "
                f"Role 1 is DISABLED for {ds} rather than predicting on mostly "
                "zeros.\n"
                "     Add the missing names to COLUMN_ALIASES in "
                "src/ingestion/cicflow_reader.py, or re-extract flows with "
                "CICFlowMeterV3\n"
                "     (tools/CICFlowMeterV3-0.0.4-SNAPSHOT.jar), which emits "
                "canonical CIC column names directly.",
                "red",
            ))
        log.warning(
            "Feature coverage %s: %.1f%% (%d missing: %s)",
            ds, pct, len(missing), missing[:10],
        )

    def set_routing(self, dataset: Optional[str] = None,
                    allow_unscaled: bool = False) -> None:
        """
        Pin Role 1 to a named sub-model and/or permit unscaled prediction.

        Evaluation runs should always pin the dataset: which sub-model scores
        a capture is a property of that capture's schema, and recording it
        explicitly is what makes the number reproducible. Auto-routing remains
        available but now refuses to pick anything below 60% feature coverage
        instead of falling back to dict order.
        """
        self._forced_dataset = dataset
        self._allow_unscaled = bool(allow_unscaled)
        if dataset:
            print(f"  Role 1 route: PINNED to {dataset} (--dataset)")
        if allow_unscaled:
            print(_c(
                "  ⚠  --allow_unscaled is set: Role 1 may predict without the "
                "scaler its sub-model was trained with.\n"
                "     Any metric produced under this flag is not reportable.",
                "yellow",
            ))

    def _resolve_route(self, ensemble, columns) -> Optional[str]:
        """
        Decide which sub-model scores this window, once per run.

        `--dataset` pins the route explicitly, which is what an evaluation run
        should do: routing is a property of the capture's schema, not of an
        individual window, and re-deriving it per window invites the route to
        drift mid-run.
        """
        if self._forced_dataset:
            if self._forced_dataset not in ensemble.sub_models:
                raise ValueError(
                    f"--dataset {self._forced_dataset!r} is not in this model "
                    f"({', '.join(ensemble.datasets)})."
                )
            return self._forced_dataset

        ds = ensemble._get_matching_dataset(list(columns))
        if ds is None:
            if not self._route_warned:
                self._route_warned = True
                print(_c(
                    "  ✗  No sub-model matches this capture's feature schema.\n"
                    f"     Coverage per dataset: "
                    f"{ensemble.route_report(list(columns))}\n"
                    "     Role 1 disabled. Pass --dataset to force a route if "
                    "you are certain of the schema.",
                    "red",
                ))
        return ds

    def _predict_universal(self, window_flows: pd.DataFrame, window_idx: int, live_mode: bool = False):
        ensemble = self._ensemble

        if self._routed_dataset is None:
            self._routed_dataset = self._resolve_route(
                ensemble, window_flows.columns
            )
            if self._routed_dataset is not None:
                cov = ensemble.route_report(list(window_flows.columns))
                print(f"  → Role 1 routed to sub-model: "
                      f"{self._routed_dataset}  (coverage {cov})")
        ds = self._routed_dataset
        if ds is None:
            return None, None

        ds_feats = ensemble.sub_features[ds]

        # ── feature-coverage gate ────────────────────────────────────────────
        # Previously this required only a 30% match and zero-filled the rest,
        # silently. Combined with an incomplete column-alias map, that meant
        # Role 1 was classifying vectors in which most features were 0.0 while
        # still reporting high confidence. 30% is not a threshold at which a
        # prediction means anything; report the gap once and refuse below 90%.
        # Resolve each trained feature to whatever this DataFrame calls it,
        # tolerating the leading spaces / underscores / case differences
        # between the CIC release the model was trained on and CICFlowMeter's
        # own output. Exact string equality was matching almost nothing.
        lookup   = build_feature_lookup(window_flows.columns)
        resolved = {f: resolve_feature(f, lookup) for f in ds_feats}
        missing  = [f for f, c in resolved.items() if c is None]
        n_match  = len(ds_feats) - len(missing)
        coverage = n_match / len(ds_feats) if ds_feats else 0.0

        self._report_feature_coverage(ds, ds_feats, missing, coverage)

        if coverage < self._min_feature_coverage:
            log.debug(
                "Window %d: feature coverage %.1f%% (%d/%d) for %s is below "
                "the %.0f%% minimum — skipping Role1",
                window_idx, coverage * 100, n_match, len(ds_feats), ds,
                self._min_feature_coverage * 100,
            )
            return None, None

        aligned = np.zeros((len(window_flows), len(ds_feats)), dtype=np.float32)
        for i, feat in enumerate(ds_feats):
            col = resolved.get(feat)
            if col is not None:
                vals = pd.to_numeric(window_flows[col], errors="coerce").fillna(0)
                aligned[:, i] = vals.values

        # Compare the RAW (pre-scaling) distribution against the one the
        # scaler was fitted on, before any prediction is trusted.
        if not self._drift_checked:
            self._accumulate_drift_sample(aligned, ds, ds_feats)

        # Scale with the ROUTED dataset's own scaler.
        #
        # This was:
        #     try: aligned = self._scaler.transform(aligned)
        #     except Exception: pass
        # with self._scaler being the single scaler the notebook saved from
        # whichever dataset was listed first. Routing anywhere else raised a
        # shape mismatch, the bare except swallowed it, and the sub-model was
        # handed RAW UNSCALED values while still returning a confident
        # probability. Nothing anywhere recorded that it had happened.
        try:
            aligned = ensemble.transform(
                aligned, ds, allow_unscaled=self._allow_unscaled
            )
        except (KeyError, ValueError) as exc:
            if not self._scaler_warned:
                self._scaler_warned = True
                # Legacy pkl: a single global scaler, usable only if its width
                # matches this route. Try it, and say so plainly either way.
                if self._scaler is not None:
                    try:
                        aligned = self._scaler.transform(aligned)
                        print(_c(
                            f"  ⚠  No per-dataset scaler for {ds}; used the "
                            "pkl's single global scaler (widths matched).\n"
                            "     Re-export the model with sub_scalers to "
                            "remove this ambiguity — see Phase 4 notes in\n"
                            "     src/engine/universal_ensemble.py.",
                            "yellow",
                        ))
                    except Exception:
                        print(_c(
                            f"  ✗  Cannot scale features for {ds}: {exc}\n"
                            "     Role 1 DISABLED for this run rather than "
                            "predicting on unscaled input.",
                            "red",
                        ))
                        self._role1_ready = False
                        return None, None
                else:
                    print(_c(f"  ✗  Cannot scale features for {ds}: {exc}", "red"))
                    self._role1_ready = False
                    return None, None
            else:
                if self._scaler is None:
                    return None, None
                try:
                    aligned = self._scaler.transform(aligned)
                except Exception:
                    return None, None

        uni_proba = ensemble.predict_proba_from_dataset(aligned, ds)
        max_proba = uni_proba.max(axis=1)
        y_pred    = uni_proba.argmax(axis=1)
        labels    = self._le.inverse_transform(y_pred)

        wf = window_flows.copy()
        wf["Predicted_Label"] = labels
        wf["Confidence"]      = (max_proba * 100).round(1)
        wf["Is_Attack"]       = ~pd.Series(labels).isin(self._benign_labels).values

        # WINDOW VERDICT — see _window_verdict() for the majority-vote-vs-
        # live-high-confidence-override rationale.
        n_attack_flows = int(wf["Is_Attack"].sum())
        n_flows = len(wf)
        dominant_label, rep, live_override = self._window_verdict(wf, live_mode)

        r1 = {
            "Predicted_Label": dominant_label,
            "Confidence":      float(rep["Confidence"]),
            "n_flows":         n_flows,
            "n_attacks":       n_attack_flows,
            "attack_fraction": round(n_attack_flows / max(1, n_flows), 4),
            "dataset_routed":  ds,
            **self._rep_endpoint_fields(rep),
        }
        if live_override:
            r1["live_override"] = True
        r2 = self._role2_universal(
            aligned[list(wf.index).index(rep.name)], ds
        )
        return r1, r2

    def _predict_single(self, window_flows: pd.DataFrame, window_idx: int, live_mode: bool = False):
        lookup   = build_feature_lookup(window_flows.columns)
        resolved = {f: resolve_feature(f, lookup) for f in self._feature_names}
        missing  = [f for f, c in resolved.items() if c is None]
        coverage = (
            1.0 - len(missing) / len(self._feature_names)
            if self._feature_names else 0.0
        )
        self._report_feature_coverage(
            "single-model", self._feature_names, missing, coverage
        )
        if coverage < self._min_feature_coverage:
            log.debug(
                "Window %d: feature coverage %.1f%% below the %.0f%% minimum "
                "— skipping Role1",
                window_idx, coverage * 100, self._min_feature_coverage * 100,
            )
            return None, None

        wf = window_flows.copy()
        # rename resolved columns to the exact names the model expects, then
        # zero-fill only what genuinely could not be resolved
        rename = {c: f for f, c in resolved.items() if c is not None and c != f}
        if rename:
            wf = wf.rename(columns=rename)
        for col in missing:
            wf[col] = 0.0

        X = wf[self._feature_names].copy()
        X = X.replace([float("inf"), float("-inf")], 0).fillna(0)
        X_scaled = self._scaler.transform(X.values.astype("float32"))

        proba     = self._best_model.predict_proba(X_scaled)
        max_proba = proba.max(axis=1)
        y_pred    = proba.argmax(axis=1).copy()

        benign_classes = [c for c in self._le.classes_ if c in self._benign_labels]
        if benign_classes:
            bidx = list(self._le.classes_).index(benign_classes[0])
            y_pred[max_proba < self._threshold] = bidx

        labels = self._le.inverse_transform(y_pred)
        wf["Predicted_Label"] = labels
        wf["Confidence"]      = (max_proba * 100).round(1)
        wf["Is_Attack"]       = ~pd.Series(labels).isin(self._benign_labels).values

        # WINDOW VERDICT — see _window_verdict() for the majority-vote-vs-
        # live-high-confidence-override rationale.
        n_attack_flows = int(wf["Is_Attack"].sum())
        n_flows = len(wf)
        dominant_label, rep, live_override = self._window_verdict(wf, live_mode)

        r1 = {
            "Predicted_Label": dominant_label,
            "Confidence":      float(rep["Confidence"]),
            "n_flows":         n_flows,
            "n_attacks":       n_attack_flows,
            "attack_fraction": round(n_attack_flows / max(1, n_flows), 4),
            **self._rep_endpoint_fields(rep),
        }
        if live_override:
            r1["live_override"] = True
        r2 = self._role2_single(
            X_scaled[list(wf.index).index(rep.name)]
        )
        return r1, r2

    def _role2_universal(self, x_sample: np.ndarray, ds_name: str) -> dict:
        try:
            model    = self._ensemble.sub_models[ds_name]
            ds_feats = self._ensemble.sub_features[ds_name]
            imp      = model.feature_importances_
            top_idx  = np.argsort(imp)[-5:][::-1]
            top_feat = [ds_feats[i] for i in top_idx if i < len(ds_feats)]
        except Exception:
            top_feat = []
        return {"shap_top_features": top_feat, "llm_explanation": ""}

    def _role2_single(self, x_sample: np.ndarray) -> dict:
        try:
            imp      = self._best_model.feature_importances_
            top_idx  = np.argsort(imp)[-5:][::-1]
            top_feat = [self._feature_names[i] for i in top_idx]
        except Exception:
            top_feat = []
        return {"shap_top_features": top_feat, "llm_explanation": ""}

    # ══════════════════════════════════════════════════════════════════════════
    # OUTPUT HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _append_alert(self, alert: UnifiedAlert) -> None:
        """Thread-safe append — multiple LLM worker results can complete
        close together even though the final merge loop is single-threaded;
        the lock is kept for safety if this is ever called concurrently."""
        try:
            with self._alert_log_lock:
                with open(self._alert_log, "a") as fh:
                    fh.write(json.dumps(alert.to_dict()) + "\n")
        except Exception as exc:
            log.warning("Could not write alert: %s", exc)

    def _print_alert_live(self, alert: UnifiedAlert) -> None:
        if alert.suppressed:
            return
        ts     = datetime.now().strftime("%H:%M:%S")
        sev    = alert.severity
        colour = (
            "red"    if sev == SEVERITY_HIGH   else
            "yellow" if sev == SEVERITY_MEDIUM else
            "green"
        )
        print(_c(f"\n{'─' * 64}", "bold"))
        print(
            f"  {alert.colour_code()}  [{ts}]  "
            + _c(f"{sev}", colour)
            + f"  │  {alert.attack_type}"
            + f"  │  conf={alert.confidence}%"
            + (f"  │  ⚠ CONFLICT" if alert.conflict else "")
        )
        if alert.soc_explanation:
            words, line = alert.soc_explanation.split(), "  "
            for w in words:
                if len(line) + len(w) + 1 > 64:
                    print(line)
                    line = "  " + w + " "
                else:
                    line += w + " "
            if line.strip():
                print(line)
        if alert.recommended_action and alert.is_alert:
            print(_c(f"  → {alert.recommended_action}", "cyan"))

    def _print_summary(self, alerts: List[UnifiedAlert]) -> None:
        n_high  = sum(1 for a in alerts if a.severity == SEVERITY_HIGH)
        n_med   = sum(1 for a in alerts if a.severity == SEVERITY_MEDIUM)
        n_conf  = sum(1 for a in alerts if a.conflict)
        n_agree = sum(1 for a in alerts if a.agree)
        n_skip  = sum(1 for a in alerts if getattr(a, "_role3_skipped", False))
        print(_c("\n" + "═" * 64, "bold"))
        print(_c("  UNIFIED PIPELINE COMPLETE", "bold"))
        print("═" * 64)
        print(f"  Total windows : {len(alerts)}")
        print(_c(f"  HIGH alerts   : {n_high}", "red"))
        print(_c(f"  MEDIUM alerts : {n_med}", "yellow"))
        print(f"  Conflicts     : {n_conf}  (roles disagreed)")
        print(f"  Agreements    : {n_agree}  (roles agreed)")
        print(f"  Alert log     : {self._alert_log}")
        print("═" * 64 + "\n")
