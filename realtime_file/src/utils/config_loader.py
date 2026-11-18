"""
src/utils/config_loader.py
Load and expose settings.yaml as a simple dot-access object.
"""

import yaml
import os
from pathlib import Path


class Config:
    """Recursive dot-access wrapper around a YAML dict."""

    def __init__(self, d: dict):
        for k, v in d.items():
            setattr(self, k, Config(v) if isinstance(v, dict) else v)

    def get(self, key, default=None):
        return getattr(self, key, default)


def load_config(path: str = "config/settings.yaml") -> Config:
    """
    Load config/settings.yaml and return a Config object.

    Usage
    -----
    from src.utils.config_loader import load_config
    cfg = load_config()
    print(cfg.ollama.model)
    print(cfg.chunker.window_seconds)
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"Config file not found: {config_path.resolve()}\n"
            "Make sure you are running from the project root (nids_role3/)."
        )
    with open(config_path, "r") as f:
        raw = yaml.safe_load(f)
    return Config(raw)
