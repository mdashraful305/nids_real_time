"""
src/utils/logger.py
Shared logging setup — import get_logger() in every module.
"""

import logging
import os
from datetime import datetime


def get_logger(name: str, log_file: str = "logs/nids_role3.log") -> logging.Logger:
    """
    Return a named logger that writes to both console and a log file.

    Usage
    -----
    from src.utils.logger import get_logger
    log = get_logger(__name__)
    log.info("Something happened")
    """
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    if logger.handlers:          # avoid duplicate handlers on re-import
        return logger

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console — INFO and above
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File — DEBUG and above
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger
