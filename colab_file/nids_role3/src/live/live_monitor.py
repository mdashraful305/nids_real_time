"""
src/live/live_monitor.py
=========================
Real-time Role 3 monitor.

  1. Tails Suricata's eve.json as it is written
  2. Optionally reads live CICFlowMeter CSV output
  3. Every window_seconds → builds a chunk → sends to Ollama
  4. Prints colour-coded SOC alerts to the console
  5. Appends LLM verdicts to a JSON-lines file (EveBox-compatible)
  6. Optionally POSTs verdict to a webhook URL

Usage (from main_live.py)
--------------------------
monitor = LiveMonitor(cfg)
monitor.run()   # blocks forever, Ctrl-C to stop
"""

import json
import os
import sys
import time
import signal
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional

import pandas as pd

from src.ingestion.suricata_reader import tail_eve_file, filter_by_window
from src.ingestion.cicflow_reader  import load_cicflow_file, filter_by_window as flow_filter
from src.chunker.log_chunker       import LogChunker
from src.llm.ollama_analyst        import OllamaAnalyst
from src.utils.logger              import get_logger

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False

log = get_logger(__name__)

# ── colour helpers ────────────────────────────────────────────────────────────

def _c(text: str, colour: str) -> str:
    if not _COLOR:
        return text
    colours = {
        "red":    Fore.RED,
        "yellow": Fore.YELLOW,
        "green":  Fore.GREEN,
        "cyan":   Fore.CYAN,
        "white":  Fore.WHITE,
        "bold":   Style.BRIGHT,
    }
    return colours.get(colour, "") + text + Style.RESET_ALL


class LiveMonitor:
    """
    Continuously monitors Suricata eve.json and sends log windows to Ollama.

    Parameters
    ----------
    cfg : Config object from config_loader.load_config()
    """

    def __init__(self, cfg):
        self.cfg             = cfg
        self.eve_path        = cfg.paths.live_eve_json
        self.window_seconds  = cfg.chunker.window_seconds
        self.poll_interval   = cfg.live.poll_interval_seconds
        self.alert_verdicts  = set(cfg.live.alert_on_verdicts)
        self.verdict_json    = cfg.live.output_verdict_json
        self.webhook_url     = cfg.live.webhook_url

        self.chunker  = LogChunker(
            window_seconds = self.window_seconds,
            max_flows      = cfg.chunker.max_flows_per_chunk,
            max_alerts     = cfg.chunker.max_alerts_per_chunk,
            save_to_disk   = cfg.chunker.save_chunks_to_disk,
            chunks_dir     = cfg.paths.chunks_dir,
            include_label  = False,   # no ground truth in live mode
            # Live traffic has no labels by definition — absence is expected,
            # not a misconfiguration, so do not raise.
            require_ground_truth = False,
        )
        self.analyst = OllamaAnalyst(cfg)

        # Live CICFlowMeter CSV (optional — may not always be available)
        self._cicflow_df: Optional[pd.DataFrame] = None
        self._cicflow_lock = threading.Lock()

        # Internal state
        self._event_buffer = []
        self._buffer_lock  = threading.Lock()
        self._chunk_index  = 0
        self._running      = False

        os.makedirs(os.path.dirname(self.verdict_json), exist_ok=True)

    # ── public ────────────────────────────────────────────────────────────────

    def run(self, cicflow_csv: Optional[str] = None) -> None:
        """
        Start the live monitor. Blocks until Ctrl-C.

        Parameters
        ----------
        cicflow_csv : str or None
            Path to a live CICFlowMeter CSV (optional).
            If provided, flow features are merged into each chunk.
        """
        self._running = True
        signal.signal(signal.SIGINT, self._handle_sigint)

        print(_c("\n" + "═" * 64, "bold"))
        print(_c("  NIDS ROLE 3 — LIVE LLM MONITOR", "bold"))
        print(_c("═" * 64, "bold"))
        print(f"  Eve.json   : {self.eve_path}")
        print(f"  Model      : {self.cfg.ollama.model}")
        print(f"  Window     : {self.window_seconds} s")
        print(f"  Verdicts   : {self.verdict_json}")
        print(_c("  Press Ctrl-C to stop\n", "cyan"))

        # Pre-flight checks
        if not self.analyst.check_connection():
            print(_c("  ❌ Ollama not reachable. Start with: ollama serve", "red"))
            print(_c(f"  ❌ Pull model:  ollama pull {self.cfg.ollama.model}", "red"))
            sys.exit(1)

        print(_c(f"  ✓ Ollama connected ({self.cfg.ollama.model})", "green"))

        # Optional: load CICFlowMeter CSV in a background thread
        if cicflow_csv:
            t = threading.Thread(
                target=self._load_cicflow_background,
                args=(cicflow_csv,), daemon=True,
            )
            t.start()

        # Start the windowing timer in a separate thread
        timer_thread = threading.Thread(
            target=self._window_loop, daemon=True
        )
        timer_thread.start()

        # Main thread: tail eve.json and fill the buffer
        self._tail_loop()

    # ── internal ──────────────────────────────────────────────────────────────

    def _tail_loop(self) -> None:
        """Continuously read new eve.json events into the buffer."""
        log.info("Tailing %s", self.eve_path)
        for event in tail_eve_file(
            self.eve_path,
            poll_interval=self.poll_interval,
            from_start=False,
        ):
            if not self._running:
                break
            with self._buffer_lock:
                self._event_buffer.append(event)

    def _window_loop(self) -> None:
        """Every window_seconds, process the accumulated buffer."""
        while self._running:
            time.sleep(self.window_seconds)
            if not self._running:
                break
            self._process_window()

    def _process_window(self) -> None:
        """Drain the event buffer, build a chunk, and analyse it."""
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.window_seconds)
        window_end   = now

        with self._buffer_lock:
            batch = list(self._event_buffer)
            self._event_buffer.clear()

        if not batch:
            log.debug("Empty window — no events in last %d s", self.window_seconds)
            return

        # Get CICFlowMeter flows for this window (if available)
        flows_df = pd.DataFrame()
        with self._cicflow_lock:
            if self._cicflow_df is not None and not self._cicflow_df.empty:
                flows_df = flow_filter(self._cicflow_df, window_start, window_end)

        # Build chunk
        chunk = self.chunker.build_single_chunk(
            events       = batch,
            flows_df     = flows_df,
            chunk_index  = self._chunk_index,
            window_start = window_start,
            window_end   = window_end,
        )
        self._chunk_index += 1

        # Analyse
        verdict = self.analyst.analyse(chunk.chunk_text, chunk.chunk_index)

        # Display
        self._display_verdict(chunk, verdict)

        # Persist
        self._append_verdict_json(chunk, verdict)

        # Webhook
        if self.webhook_url and verdict.get("verdict") in self.alert_verdicts:
            self._post_webhook(chunk, verdict)

    def _display_verdict(self, chunk, verdict: dict) -> None:
        """Print a colour-coded summary to the console."""
        v       = verdict.get("verdict", "error")
        atype   = verdict.get("attack_type", "?")
        conf    = verdict.get("confidence", 0)
        expl    = verdict.get("explanation", "")
        action  = verdict.get("recommended_action", "")
        ts      = chunk.window_end.strftime("%H:%M:%S")
        n_alerts = len([e for e in chunk.eve_events if e["event_type"] == "alert"])

        colour = "red" if v == "attack" else "yellow" if v == "suspicious" else "green"
        icon   = "🚨" if v == "attack" else "⚠️ " if v == "suspicious" else "✅"

        print(_c(f"\n{'─'*64}", "white"))
        print(
            f"  {icon}  [{ts}]  "
            + _c(v.upper(), colour)
            + f"  │  {atype}  │  confidence={conf}%"
            + f"  │  alerts={n_alerts}"
        )
        if expl:
            # Word-wrap at 62 chars
            words, line = expl.split(), "  "
            for w in words:
                if len(line) + len(w) + 1 > 62:
                    print(line); line = "  " + w + " "
                else:
                    line += w + " "
            if line.strip():
                print(line)

        if action and v in self.alert_verdicts:
            print(_c(f"  → ACTION: {action}", "cyan"))

        if verdict.get("_error"):
            print(_c(f"  ⚠ LLM error: {verdict.get('_error_detail','')}", "yellow"))

    def _append_verdict_json(self, chunk, verdict: dict) -> None:
        """Append one verdict as a JSON-lines entry to the output file."""
        record = {
            "timestamp":    chunk.window_end.isoformat(),
            "chunk_index":  chunk.chunk_index,
            "window_start": chunk.window_start.isoformat(),
            "window_end":   chunk.window_end.isoformat(),
            "n_alerts":     len([e for e in chunk.eve_events if e["event_type"] == "alert"]),
            "n_flows":      len(chunk.flow_rows),
            **{k: v for k, v in verdict.items() if not k.startswith("_")},
        }
        try:
            with open(self.verdict_json, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception as exc:
            log.warning("Could not write verdict JSON: %s", exc)

    def _post_webhook(self, chunk, verdict: dict) -> None:
        """POST verdict to a webhook URL (e.g. Slack, EveBox, custom SIEM)."""
        import requests as req
        try:
            payload = {
                "text": (
                    f"🚨 NIDS Alert — {verdict.get('attack_type','?')} "
                    f"(confidence={verdict.get('confidence')}%)\n"
                    f"{verdict.get('explanation','')}\n"
                    f"Action: {verdict.get('recommended_action','')}"
                )
            }
            req.post(self.webhook_url, json=payload, timeout=5)
        except Exception as exc:
            log.warning("Webhook POST failed: %s", exc)

    def _load_cicflow_background(self, path: str) -> None:
        """Load CICFlowMeter CSV in the background without blocking the main loop."""
        try:
            from src.ingestion.cicflow_reader import load_cicflow_file
            df = load_cicflow_file(path)
            with self._cicflow_lock:
                self._cicflow_df = df
            log.info("CICFlowMeter CSV loaded: %d flows from %s", len(df), path)
        except Exception as exc:
            log.warning("Could not load CICFlowMeter CSV: %s", exc)

    def _handle_sigint(self, sig, frame) -> None:
        """Graceful shutdown on Ctrl-C."""
        print(_c("\n\n  Shutting down live monitor ...", "yellow"))
        self._running = False
        print(f"  Chunks analysed : {self._chunk_index}")
        print(f"  Verdicts saved  : {self.verdict_json}")
        sys.exit(0)
