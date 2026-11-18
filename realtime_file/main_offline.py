"""
main_offline.py
================
Phase 1 — Offline CICIDS2017 evaluation pipeline.

Steps:
  1. Load Suricata eve.json from data/eve_logs/
  2. Load CICFlowMeter CSV from data/cicflow_csv/
  3. Build time-windowed chunks
  4. Send each chunk to Ollama
  5. Compare verdict against CICIDS2017 ground truth
  6. Generate and save evaluation report

Run:
  python main_offline.py
  python main_offline.py --eve_dir data/eve_logs/monday/  --flow_dir data/cicflow_csv/monday/
  python main_offline.py --quick   (process only first 50 chunks for a fast sanity check)
"""

import argparse
import sys
import os
import time

from src.utils.config_loader import load_config
from src.utils.logger        import get_logger
from src.ingestion.suricata_reader import load_eve_directory, load_eve_file
from src.ingestion.cicflow_reader  import load_cicflow_directory, load_cicflow_file
from src.chunker.log_chunker       import LogChunker
from src.llm.ollama_analyst        import OllamaAnalyst
from src.evaluator.evaluator       import Evaluator

log = get_logger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="NIDS Role 3 — Offline LLM analyst evaluation on CICIDS2017"
    )
    parser.add_argument(
        "--config", default="config/settings.yaml",
        help="Path to settings.yaml (default: config/settings.yaml)"
    )
    parser.add_argument(
        "--eve_dir", default=None,
        help="Override eve_logs directory from settings.yaml"
    )
    parser.add_argument(
        "--eve_file", default=None,
        help="Use a single eve.json file instead of a directory"
    )
    parser.add_argument(
        "--flow_dir", default=None,
        help="Override cicflow_csv directory from settings.yaml"
    )
    parser.add_argument(
        "--flow_file", default=None,
        help="Use a single CICFlowMeter CSV instead of a directory"
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Process only the first 50 chunks (fast sanity check)"
    )
    parser.add_argument(
        "--no_save_chunks", action="store_true",
        help="Do not save chunk .txt files to disk"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # ── config ────────────────────────────────────────────────────────────────
    cfg = load_config(args.config)
    log.info("Config loaded: model=%s  window=%ds", cfg.ollama.model, cfg.chunker.window_seconds)

    # ── pre-flight: check Ollama ───────────────────────────────────────────────
    analyst = OllamaAnalyst(cfg)
    print("\n" + "═" * 64)
    print("  NIDS ROLE 3 — OFFLINE EVALUATION")
    print("═" * 64)
    print(f"  Ollama model : {cfg.ollama.model}")
    print(f"  Window size  : {cfg.chunker.window_seconds} s")
    print(f"  Quick mode   : {args.quick}")
    print("═" * 64 + "\n")

    print("[1/5] Checking Ollama connection ...")
    if not analyst.check_connection():
        print("  ❌ Ollama not reachable!")
        print(f"  1) Start Ollama : ollama serve")
        print(f"  2) Pull model   : ollama pull {cfg.ollama.model}")
        sys.exit(1)
    print(f"  ✓ Ollama ready ({cfg.ollama.model})\n")

    # ── Step 1: load Suricata events ──────────────────────────────────────────
    print("[2/5] Loading Suricata eve.json ...")
    eve_dir  = args.eve_dir  or cfg.paths.eve_logs_dir
    eve_file = args.eve_file

    if eve_file:
        events = load_eve_file(eve_file)
    elif os.path.isdir(eve_dir):
        events = load_eve_directory(eve_dir)
    else:
        print(f"  ❌ Eve.json directory not found: {eve_dir}")
        print("  Run scripts/01_replay_pcap.sh first to generate eve.json")
        sys.exit(1)

    alert_count = sum(1 for e in events if e["event_type"] == "alert")
    print(f"  ✓ {len(events):,} events  ({alert_count:,} alerts)\n")

    # ── Step 2: load CICFlowMeter flows ───────────────────────────────────────
    print("[3/5] Loading CICFlowMeter flows ...")
    flow_dir  = args.flow_dir  or cfg.paths.cicflow_csv_dir
    flow_file = args.flow_file

    if flow_file:
        from src.ingestion.cicflow_reader import load_cicflow_file
        flows_df = load_cicflow_file(flow_file)
    elif os.path.isdir(flow_dir) and any(f.endswith(".csv") for f in os.listdir(flow_dir)):
        flows_df = load_cicflow_directory(flow_dir)
    else:
        print(f"  ⚠  No CICFlowMeter CSVs found in {flow_dir}")
        print("     Chunks will contain Suricata alerts only (no flow features)")
        import pandas as pd
        flows_df = pd.DataFrame()

    if not flows_df.empty:
        label_col = "Label" if "Label" in flows_df.columns else None
        n_classes = flows_df[label_col].nunique() if label_col else 0
        print(f"  ✓ {len(flows_df):,} flows  ({n_classes} unique labels)\n")
    else:
        print("  ⚠  No flow data — continuing without CICFlowMeter features\n")

    # ── Step 3: build chunks ──────────────────────────────────────────────────
    print("[4/5] Building time-windowed chunks ...")
    chunker = LogChunker(
        window_seconds = cfg.chunker.window_seconds,
        max_flows      = cfg.chunker.max_flows_per_chunk,
        max_alerts     = cfg.chunker.max_alerts_per_chunk,
        save_to_disk   = cfg.chunker.save_chunks_to_disk and not args.no_save_chunks,
        chunks_dir     = cfg.paths.chunks_dir,
        include_label  = True,   # show ground truth in offline mode
    )
    all_chunks = chunker.build_chunks(events, flows_df)

    if args.quick:
        all_chunks = all_chunks[:50]
        print(f"  ⚡ Quick mode: processing first {len(all_chunks)} chunks\n")
    else:
        print(f"  ✓ {len(all_chunks):,} chunks built\n")

    # ── Step 4: analyse each chunk ────────────────────────────────────────────
    print("[5/5] Analysing chunks with Ollama LLM ...")
    print(f"  (this will take ~{len(all_chunks) * cfg.ollama.timeout_seconds / 60:.1f} min max)\n")

    evaluator  = Evaluator(cfg)
    t_pipeline = time.time()

    for i, chunk in enumerate(all_chunks):
        verdict = analyst.analyse(chunk.chunk_text, chunk.chunk_index)
        result  = evaluator.add_result(chunk, verdict)

        # Running progress print every 10 chunks
        if (i + 1) % 10 == 0 or i == 0:
            correct_so_far = sum(
                1 for r in evaluator.results
                if r.correct and r.gt_binary != "unknown"
            )
            total_eval = sum(
                1 for r in evaluator.results
                if r.gt_binary != "unknown"
            )
            acc_so_far = correct_so_far / total_eval * 100 if total_eval else 0
            elapsed    = time.time() - t_pipeline
            eta        = (elapsed / (i + 1)) * (len(all_chunks) - i - 1)
            print(
                f"  [{i+1:>4}/{len(all_chunks)}]  "
                f"verdict={verdict.get('verdict','?'):<12}  "
                f"acc={acc_so_far:.1f}%  "
                f"ETA={eta/60:.1f}min"
            )

    # ── Step 5: report ────────────────────────────────────────────────────────
    report = evaluator.generate_report()
    evaluator.save_report(report)

    print(f"\n  Total pipeline time : {(time.time() - t_pipeline) / 60:.1f} min")
    print("  Done. Open data/results/ to view the evaluation report.")


if __name__ == "__main__":
    main()
