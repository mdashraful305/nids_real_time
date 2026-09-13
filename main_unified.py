"""
main_unified.py  (v3 — performance fix)
=========================================
Unified NIDS pipeline — Role 1 + Role 2 + Role 3.

CHANGES vs v3.1
─────────────────
v3.1 dropped unused Suricata event types ("flow" records) to reduce
memory. That fix assumed those records were the majority of a typical
eve.json — which does NOT hold for CICIDS2017 replays, where DoS/DDoS/
HTTP-flood traffic generates huge numbers of "alert"/"http" events
instead (the types that ARE kept). For datasets like that, the v3.1
fix could remove little or nothing, and RAM use still scaled with file
size.

This version (v4) adds a genuinely memory-BOUNDED streaming mode that
works regardless of event-type distribution or file size:

  --low_memory / --no_low_memory   (default: --low_memory, i.e. ON)
                        When ON (default), events and flows are first
                        indexed into a SQLite database on disk (batched
                        inserts, bounded RAM during indexing) and then
                        windows are streamed ONE AT A TIME from indexed
                        range queries. Peak RAM depends on how much data
                        falls in a single window (typically KB-MB), NOT
                        on total file size. Use --no_low_memory only for
                        small datasets where you want the faster (but
                        RAM-hungry) old in-memory path.

  --db_dir PATH         Where to put the SQLite index files when
                        --low_memory is on. Default: <results_dir>/.cache/

This version also adds the CLI flags for the offline-mode PERFORMANCE
fix implemented in src/pipeline/unified_pipeline.py and
src/chunker/log_chunker.py:

  --workers N          Number of Ollama calls to run concurrently in
                        offline mode (default: 4). Requires Ollama to
                        be started with OLLAMA_NUM_PARALLEL >= N for
                        real speedup. Set to 1 for strictly sequential
                        (safe default if you are not sure Ollama
                        supports parallel requests on your machine).

  --no_llm_gating       Disable Fix 2 (skip-LLM-on-obviously-benign).
                        By default, windows with no Suricata alert AND
                        no Role 1 attack flag are auto-classified as
                        benign WITHOUT calling the LLM. Pass this flag
                        to force the LLM to analyse every window
                        (slower, but matches the old v1/v2 behaviour
                        exactly for reproducibility comparisons).

Everything else (pkl format detection, error messages, live mode,
dashboard mode) is unchanged from v2.

HOW TO USE
──────────
  # 1. Install dependencies (once)
  pip install -r requirements.txt

  # 2. (Recommended) let Ollama serve requests in parallel
  export OLLAMA_NUM_PARALLEL=4
  ollama serve &

  # 3. Offline evaluation — fast mode (default)
  python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl

  # 3b. Offline evaluation — quick sanity check on first 20 windows
  python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl --quick

  # 3c. Offline evaluation — old slow behaviour (every window through LLM,
  #     strictly sequential) for exact reproducibility with earlier runs
  python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl \\
      --no_llm_gating --workers 1

  # 4. Live monitoring
  python main_unified.py --mode live --nids_pkl universal_nids_output.pkl

  # 5. Dashboard
  python main_unified.py --mode dashboard
  python main_unified.py --mode dashboard --detail 5
  python main_unified.py --mode dashboard --html
"""

import argparse
import sys
import os

# ═══════════════════════════════════════════════════════════════════════════════
# CRITICAL — import UniversalEnsemble BEFORE joblib.load()
# ───────────────────────────────────────────────────────────────────────────────
# joblib uses the class's fully-qualified module path to reconstruct objects.
# This import registers  src.engine.universal_ensemble.UniversalEnsemble
# in the current process so joblib can find it when loading the pkl.
# Removing or moving this import will break pkl loading with:
#   "Can't get attribute 'UniversalEnsemble' on <module '__main__'>"
# ═══════════════════════════════════════════════════════════════════════════════
try:
    from src.engine.universal_ensemble import UniversalEnsemble  # noqa: F401
    _ue_imported = True
except ImportError as _ue_err:
    _ue_imported = False
    print(f"  ⚠  UniversalEnsemble import failed: {_ue_err}")
    print("     Make sure src/engine/universal_ensemble.py exists.")

from src.utils.config_loader       import load_config
from src.utils.logger              import get_logger
from src.pipeline.unified_pipeline import UnifiedPipeline
from src.dashboard.soc_dashboard   import SOCDashboard
from src.llm.ollama_analyst        import OllamaAnalyst

log = get_logger(__name__)


def parse_args():
    p = argparse.ArgumentParser(
        description="Unified NIDS — Role 1 + Role 2 + Role 3 integrated"
    )
    p.add_argument(
        "--mode", choices=["offline", "live", "dashboard"],
        default="offline",
        help="offline | live | dashboard",
    )
    p.add_argument("--config", default="config/settings.yaml")
    p.add_argument(
        "--nids_pkl", default=None,
        help="Path to universal_nids_output.pkl (from Colab notebook)"
    )
    p.add_argument("--eve_dir",     default=None)
    p.add_argument("--flow_dir",    default=None)
    p.add_argument("--cicflow_csv", default=None)
    p.add_argument("--quick",       action="store_true",
                   help="Process only first 20 windows")

    # ── Role 1 routing (Phase 4) ─────────────────────────────────────────────
    p.add_argument(
        "--dataset", default=None,
        choices=["CICIDS2017", "UNSW-NB15", "NSL-KDD"],
        help="Pin Role 1 to a specific sub-model instead of auto-routing by "
             "feature schema. Evaluation runs should ALWAYS pin this: the "
             "route is a property of the capture, and stating it makes the "
             "result reproducible and reviewable. Auto-routing now requires "
             ">=60%% feature coverage and refuses to guess below that.",
    )
    p.add_argument(
        "--allow_unscaled", action="store_true",
        help="Proceed even when the routed sub-model has no stored scaler. "
             "OFF by default: each sub-model was trained on its own "
             "RobustScaler output, so unscaled input yields a confident but "
             "meaningless prediction. Results obtained with this flag are not "
             "reportable.",
    )

    # ── NEW performance flags ────────────────────────────────────────────────
    p.add_argument(
        "--workers", type=int, default=4,
        help=(
            "Offline mode only: number of Ollama calls to run concurrently "
            "(default: 4). Requires 'export OLLAMA_NUM_PARALLEL=<N>' before "
            "'ollama serve' for real speedup. Use --workers 1 for strictly "
            "sequential processing."
        ),
    )
    p.add_argument(
        "--no_llm_gating", action="store_true",
        help=(
            "Disable the skip-LLM-on-obviously-benign optimisation. "
            "By default, windows with no Suricata alert and no Role 1 "
            "attack flag are classified benign without calling the LLM. "
            "Pass this flag to force LLM analysis on every window."
        ),
    )
    p.add_argument(
        "--keep_all_event_types", action="store_true",
        help=(
            "Only used with --no_low_memory. By default only "
            "'alert'/'dns'/'http'/'tls' Suricata event types are loaded "
            "into memory. Pass this to load every event type as before."
        ),
    )
    p.add_argument(
        "--low_memory", dest="low_memory", action="store_true", default=True,
        help=(
            "(Default: ON) Stream events/flows through a SQLite index on "
            "disk instead of loading them fully into RAM. Peak memory is "
            "bounded by a single window's data, independent of total file "
            "size or event-type distribution. Use this if the process is "
            "being killed by the OS OOM killer."
        ),
    )
    p.add_argument(
        "--no_low_memory", dest="low_memory", action="store_false",
        help=(
            "Disable streaming mode and use the faster but RAM-hungry "
            "in-memory path instead (fine for small datasets)."
        ),
    )
    p.add_argument(
        "--db_dir", default=None,
        help="Directory for the SQLite index files when --low_memory is on "
             "(default: <results_dir>/.cache/)",
    )

    p.add_argument(
        "--ollama_url", "--ollama-url", dest="ollama_url", default=None,
        help=(
            "Ollama-compatible LLM endpoint for Role 3. Overrides "
            "ollama.url from --config. Omit to use the local Ollama server "
            "at the URL configured in config/settings.yaml (default "
            "http://localhost:11434); pass a URL to point at a remote/3rd-"
            "party server speaking the same Ollama API instead."
        ),
    )
    p.add_argument(
        "--ollama_model", "--ollama-model", dest="ollama_model", default=None,
        help="Overrides ollama.model from --config.",
    )
    p.add_argument(
        "--window_seconds", "--window-seconds", dest="window_seconds",
        type=int, default=None,
        help=(
            "Overrides chunker.window_seconds from --config (default 60s). "
            "Live mode only reads new flow CSVs once per window tick, so "
            "this is the single biggest lever on live time-to-alert — pair "
            "with a matching (or smaller) tcpdump -G rotation interval, "
            "since a flow can't be processed until its pcap has rotated "
            "AND a window tick has run. Leave at 60 for offline Track A/B "
            "runs — that's the window size cited in the thesis "
            "methodology; only override for live testing."
        ),
    )

    p.add_argument("--detail",      type=int, default=None,
                   help="Show alert detail #N (dashboard mode)")
    p.add_argument("--min_severity", default="LOW",
                   choices=["NONE","LOW","MEDIUM","HIGH"])
    p.add_argument("--html", action="store_true",
                   help="Generate HTML report (dashboard mode)")
    return p.parse_args()


def load_nids_output(pkl_path: str):
    """
    Load the NIDS pkl with clear error messages for each failure mode.

    Requires:
      1. src/engine/universal_ensemble.py exists and is importable
      2. xgboost and scikit-learn are installed locally
      3. The pkl was saved in Colab AFTER importing UniversalEnsemble
         from src.engine.universal_ensemble (not from __main__)
    """
    if not pkl_path:
        return None

    if not os.path.exists(pkl_path):
        print(f"\n  ❌ pkl not found: {pkl_path}")
        print("  Fix: copy the file from Google Drive to this folder:")
        print(f"       cp /path/to/drive/{os.path.basename(pkl_path)} .")
        return None

    if not _ue_imported:
        print("\n  ❌ Cannot load pkl: UniversalEnsemble not importable.")
        print("  Fix: make sure src/engine/universal_ensemble.py exists.")
        return None

    try:
        import joblib
        print(f"\n  Loading pkl: {pkl_path} ...")
        out = joblib.load(pkl_path)

        if "sub_models" in out and "ensemble" in out:
            print(f"  ✓ Universal ensemble pkl loaded")
            print(f"    Datasets  : {out.get('datasets_used', '?')}")
            print(f"    Classes   : {out.get('universal_classes', '?')}")
            print(f"    Sub-models: {list(out.get('sub_models', {}).keys())}")
        elif "models" in out and "data" in out:
            print(f"  ✓ Single-dataset pkl loaded")
            print(f"    Features  : {len(out['data'].get('feature_names', []))}")
            print(f"    Classes   : {list(out['data']['label_encoder'].classes_)}")
        else:
            print(f"  ⚠  Unknown pkl structure — keys: {list(out.keys())}")
            print("  The pkl may have been saved with an older version.")
            return None

        return out

    except ModuleNotFoundError as exc:
        missing = str(exc).replace("No module named '","").rstrip("'").split(".")[0]
        print(f"\n  ❌ Missing package: {missing}")
        print(f"  Fix: pip install {missing}")
        if missing == "xgboost":
            print("  The pkl contains XGBoost models which require xgboost installed locally.")
            print("  Full command:  pip install xgboost scikit-learn imbalanced-learn")
        return None

    except AttributeError as exc:
        if "UniversalEnsemble" in str(exc) or "WeightedHybridEnsemble" in str(exc):
            cls_name = "UniversalEnsemble" if "Universal" in str(exc) else "WeightedHybridEnsemble"
            print(f"\n  ❌ Class path mismatch: {exc}")
            print(f"\n  The pkl was saved with {cls_name} defined in Colab __main__.")
            print("  You need to re-save the pkl from Colab with the class imported")
            print("  from the shared module BEFORE calling train_universal_model().")
            print()
            print("  In your Colab notebook, add this BEFORE Cell 9:")
            print("  ─────────────────────────────────────────────────")
            print("  import sys")
            print("  sys.path.insert(0, '/content/drive/MyDrive/nids_role3_clean')")
            print("  from src.engine.universal_ensemble import UniversalEnsemble")
            print("  # Now run Cell 9 (train_universal_model) and Cell 10 (save)")
            print("  ─────────────────────────────────────────────────")
        else:
            print(f"\n  ❌ AttributeError loading pkl: {exc}")
        return None

    except Exception as exc:
        print(f"\n  ⚠  Could not load pkl: {exc}")
        return None


def main():
    args = parse_args()
    cfg  = load_config(args.config)

    if args.ollama_url:
        cfg.ollama.url = args.ollama_url
    if args.ollama_model:
        cfg.ollama.model = args.ollama_model
    if args.window_seconds:
        cfg.chunker.window_seconds = args.window_seconds

    is_local_ollama = "localhost" in cfg.ollama.url or "127.0.0.1" in cfg.ollama.url

    print("\n" + "═"*64)
    print("  UNIFIED NIDS PIPELINE")
    print(f"  Mode        : {args.mode.upper()}")
    print(f"  Ollama URL  : {cfg.ollama.url}  ({'local' if is_local_ollama else 'custom/3rd-party'})")
    print(f"  Ollama model: {cfg.ollama.model}")
    print(f"  Window size : {cfg.chunker.window_seconds}s")
    if args.mode == "offline":
        print(f"  Workers     : {args.workers}")
        print(f"  LLM gating  : {'disabled' if args.no_llm_gating else 'enabled'}")
        print(f"  Memory mode : {'streaming (SQLite, bounded RAM)' if args.low_memory else 'in-memory (fast, RAM scales with file size)'}")
    print("═"*64 + "\n")

    # ── load pkl (enables Role 1 + 2) ────────────────────────────────────────
    nids_out = None
    if args.mode in ("offline", "live"):
        if args.nids_pkl:
            nids_out = load_nids_output(args.nids_pkl)
        if nids_out is None:
            print("\n  ℹ  Role-3-only mode (LLM log analyst)")
            print("  To enable Role 1+2 follow these steps:")
            print()
            print("  STEP 1 — install packages locally:")
            print("    pip install xgboost scikit-learn imbalanced-learn")
            print()
            print("  STEP 2 — in Colab, add before Cell 9 (universal model cell):")
            print("    import sys")
            print("    sys.path.insert(0, '/content/drive/MyDrive/nids_role3_clean')")
            print("    from src.engine.universal_ensemble import UniversalEnsemble")
            print()
            print("  STEP 3 — re-run Cell 9 and Cell 10 in Colab to save new pkl")
            print()
            print("  STEP 4 — copy pkl here and run:")
            print("    python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl\n")

    # ── offline mode ─────────────────────────────────────────────────────────
    if args.mode == "offline":
        analyst = OllamaAnalyst(cfg)
        if not analyst.check_connection():
            print(f"  ❌ Ollama not reachable.")
            print(f"     Start: ollama serve")
            print(f"     Pull : ollama pull {cfg.ollama.model}")
            sys.exit(1)
        print(f"  ✓ Ollama ready ({cfg.ollama.model})\n")

        if args.workers > 1:
            print(
                "  ℹ  Tip: for real parallel speedup, make sure Ollama was "
                f"started with:  export OLLAMA_NUM_PARALLEL={args.workers}  "
                "before 'ollama serve'\n"
            )

        pipeline = UnifiedPipeline(cfg, nids_out)
        pipeline.set_routing(
            dataset        = args.dataset,
            allow_unscaled = args.allow_unscaled,
        )
        pipeline.run_offline(
            eve_dir              = args.eve_dir,
            flow_dir             = args.flow_dir,
            quick                = args.quick,
            num_workers          = args.workers,
            skip_llm_on_benign   = not args.no_llm_gating,
            keep_all_event_types = args.keep_all_event_types,
            low_memory           = args.low_memory,
            db_dir               = args.db_dir,
        )
        dashboard = SOCDashboard(cfg)
        dashboard.show_summary(
            os.path.join(cfg.paths.results_dir, "unified_alerts.jsonl"),
            min_severity = args.min_severity,
        )
        dashboard.generate_html_report()

    # ── live mode ─────────────────────────────────────────────────────────────
    elif args.mode == "live":
        analyst = OllamaAnalyst(cfg)
        if not analyst.check_connection():
            print(f"  ❌ Ollama not reachable.")
            sys.exit(1)
        print(f"  ✓ Ollama ready ({cfg.ollama.model})\n")
        pipeline = UnifiedPipeline(cfg, nids_out)
        pipeline.set_routing(
            dataset        = args.dataset,
            allow_unscaled = args.allow_unscaled,
        )
        pipeline.run_live(cicflow_csv=args.cicflow_csv)

    # ── dashboard mode ────────────────────────────────────────────────────────
    elif args.mode == "dashboard":
        alerts_file = os.path.join(cfg.paths.results_dir, "unified_alerts.jsonl")
        dashboard   = SOCDashboard(cfg)
        if args.detail:
            dashboard.show_detail(alerts_file, args.detail)
        elif args.html:
            dashboard.generate_html_report(alerts_file)
        else:
            dashboard.show_summary(alerts_file, min_severity=args.min_severity)


if __name__ == "__main__":
    main()
