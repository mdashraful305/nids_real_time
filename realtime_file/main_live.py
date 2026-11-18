"""
main_live.py
=============
Phase 2 — Real-time LLM log analyst on your live network.

Connects to:
  - Suricata eve.json (tailed in real time)
  - CICFlowMeter CSV (optional, loaded if --cicflow_csv provided)

Run:
  python main_live.py
  python main_live.py --cicflow_csv /tmp/cicflow_live.csv
  python main_live.py --eve_json /var/log/suricata/eve.json --window 60
"""

import argparse
import sys

from src.utils.config_loader import load_config
from src.utils.logger        import get_logger
from src.live.live_monitor   import LiveMonitor

log = get_logger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="NIDS Role 3 — Real-time LLM analyst on live Suricata stream"
    )
    parser.add_argument(
        "--config", default="config/settings.yaml",
        help="Path to settings.yaml (default: config/settings.yaml)"
    )
    parser.add_argument(
        "--eve_json", default=None,
        help="Override live eve.json path from settings.yaml"
    )
    parser.add_argument(
        "--cicflow_csv", default=None,
        help="Optional: path to live CICFlowMeter CSV output"
    )
    parser.add_argument(
        "--window", type=int, default=None,
        help="Override window size in seconds (default: from settings.yaml)"
    )
    parser.add_argument(
        "--model", default=None,
        help="Override Ollama model name (e.g. qwen2.5:7b)"
    )
    parser.add_argument(
        "--from_start", action="store_true",
        help="Read eve.json from the beginning (replays past events)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    cfg  = load_config(args.config)

    # Apply CLI overrides
    if args.eve_json:
        cfg.paths.live_eve_json = args.eve_json
    if args.window:
        cfg.chunker.window_seconds = args.window
    if args.model:
        cfg.ollama.model = args.model

    monitor = LiveMonitor(cfg)
    monitor.run(cicflow_csv=args.cicflow_csv)


if __name__ == "__main__":
    main()
