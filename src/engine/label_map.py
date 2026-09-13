"""
src/engine/label_map.py
========================
THE single source of truth for the universal attack taxonomy across
CICIDS2017, UNSW-NB15 and NSL-KDD.

WHY THIS FILE EXISTS
────────────────────
This map was previously defined twice: once in the training notebook
(`UNIVERSAL_LABEL_MAP`, used to build the universal label encoder) and again
in `src/evaluator/thesis_evaluator.py` (`LABEL_TO_FAMILY`, used to score
results). The evaluator's copy carried a comment reading "Must stay in sync
with UNIVERSAL_LABEL_MAP in the training notebook" — which is an admission
that nothing enforced it.

They had already drifted. The evaluator's copy held CICIDS2017 labels only,
so per-family accuracy for UNSW-NB15 (Fuzzers, Analysis, Backdoor, Exploits,
Generic, Reconnaissance, Shellcode, Worms) and NSL-KDD (neptune, smurf,
satan, ipsweep, ...) could not be computed at all — every such window would
fall through `LABEL_TO_FAMILY.get(l, l)` and appear as its own raw label.

Import from here in BOTH places:

    # notebook Cell 1, replacing the inline dict
    from src.engine.label_map import UNIVERSAL_LABEL_MAP

    # evaluator
    from src.engine.label_map import UNIVERSAL_LABEL_MAP, to_family

Changing a mapping here changes training and evaluation together, which is
the only way the two can be compared.
"""

from typing import Dict, Optional

# Sentinels meaning "no ground truth", never a class.
UNMATCHED_LABEL = "UNMATCHED"
UNKNOWN_LABEL   = "UNKNOWN"      # legacy; emitted by the old broken fallback
NO_LABEL_SENTINELS = frozenset({UNMATCHED_LABEL, UNKNOWN_LABEL})

BENIGN_FAMILY = "Benign"

UNIVERSAL_LABEL_MAP: Dict[str, str] = {
    # ── BENIGN ────────────────────────────────────────────────────────────────
    "BENIGN":                     "Benign",
    "Benign":                     "Benign",
    "benign":                     "Benign",
    "Normal":                     "Benign",
    "normal":                     "Benign",

    # ── DoS ───────────────────────────────────────────────────────────────────
    "DoS Hulk":                   "DoS",
    "DoS GoldenEye":              "DoS",
    "DoS slowloris":              "DoS",
    "DoS Slowhttptest":           "DoS",
    "DoS":                        "DoS",
    "Generic":                    "DoS",
    "neptune":                    "DoS",
    "back":                       "DoS",
    "land":                       "DoS",
    "pod":                        "DoS",
    "smurf":                      "DoS",
    "teardrop":                   "DoS",
    "apache2":                    "DoS",
    "mailbomb":                   "DoS",
    "processtable":               "DoS",
    "udpstorm":                   "DoS",

    # ── DDoS ──────────────────────────────────────────────────────────────────
    "DDoS":                       "DDoS",

    # ── PortScan / Reconnaissance ─────────────────────────────────────────────
    "PortScan":                   "PortScan",
    "Reconnaissance":             "PortScan",
    "ipsweep":                    "PortScan",
    "nmap":                       "PortScan",
    "portsweep":                  "PortScan",
    "satan":                      "PortScan",
    "mscan":                      "PortScan",
    "saint":                      "PortScan",

    # ── Brute Force ───────────────────────────────────────────────────────────
    "FTP-Patator":                "Brute Force",
    "SSH-Patator":                "Brute Force",
    "Brute Force":                "Brute Force",
    "guess_passwd":               "Brute Force",

    # ── Web Attack ────────────────────────────────────────────────────────────
    # CIC ships these with an EN DASH (U+2013), and some redistributions
    # normalise it to a hyphen. Both spellings are listed: a mismatch here
    # silently drops the entire Web Attack family from per-family accuracy.
    "Web Attack – Brute Force":  "Web Attack",
    "Web Attack – XSS":          "Web Attack",
    "Web Attack – Sql Injection": "Web Attack",
    "Web Attack - Brute Force":   "Web Attack",
    "Web Attack - XSS":           "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",
    # Mojibake spellings. The CIC CSVs are cp1252/latin-1 encoded, so the
    # en-dash byte 0x96 becomes U+FFFD when read as UTF-8 with errors
    # replaced. Observed in a real Track A run as:
    #   labels with no taxonomy entry: ['Web Attack � Brute Force', ...]
    # An unmapped label is excluded from per-family accuracy and drags macro-F1
    # down, so accept the corrupted forms rather than lose the family. The
    # underlying encoding is also fixed in load_cic_labels(); these remain as
    # a safety net for pkls trained before that fix.
    "Web Attack � Brute Force":  "Web Attack",
    "Web Attack � XSS":          "Web Attack",
    "Web Attack � Sql Injection": "Web Attack",
    "Web Attack \x96 Brute Force":    "Web Attack",
    "Web Attack \x96 XSS":            "Web Attack",
    "Web Attack \x96 Sql Injection":  "Web Attack",
    "Web Attack":                 "Web Attack",
    "Exploits":                   "Web Attack",
    "phf":                        "Web Attack",
    "imap":                       "Web Attack",
    "multihop":                   "Web Attack",
    "warezmaster":                "Web Attack",
    "warezclient":                "Web Attack",
    "xlock":                      "Web Attack",
    "xsnoop":                     "Web Attack",
    "snmpgetattack":              "Web Attack",
    "snmpguess":                  "Web Attack",
    "httptunnel":                 "Web Attack",
    "named":                      "Web Attack",
    "sendmail":                   "Web Attack",
    "worm":                       "Web Attack",

    # ── Infiltration / Backdoor / privilege escalation ────────────────────────
    "Infiltration":               "Infiltration",
    "Backdoor":                   "Infiltration",
    "Backdoors":                  "Infiltration",
    "rootkit":                    "Infiltration",
    "buffer_overflow":            "Infiltration",
    "loadmodule":                 "Infiltration",
    "perl":                       "Infiltration",
    "ps":                         "Infiltration",
    "xterm":                      "Infiltration",
    "sqlattack":                  "Infiltration",
    "ftp_write":                  "Infiltration",
    "spy":                        "Infiltration",

    # ── Bot ───────────────────────────────────────────────────────────────────
    "Bot":                        "Bot",

    # ── remaining UNSW-NB15 / CICIDS2017 categories ───────────────────────────
    "Heartbleed":                 "Heartbleed",
    "Analysis":                   "Analysis",
    "Fuzzers":                    "Fuzzers",
    "Shellcode":                  "Shellcode",
    "Worms":                      "Worms",
}


def to_family(label: Optional[str]) -> Optional[str]:
    """
    Map a raw dataset label to its universal family.

    Returns None for the no-ground-truth sentinels so callers cannot
    accidentally score them as a class — the failure that produced an
    all-positive evaluation set. Unrecognised labels are returned unchanged
    so they show up in per-family tables as themselves rather than vanishing.
    """
    if label is None:
        return None
    s = str(label).strip()
    if s in NO_LABEL_SENTINELS or not s:
        return None
    return UNIVERSAL_LABEL_MAP.get(s, s)


def attack_window_verdict(attack_count: int, total_count: int, threshold: float) -> bool:
    """
    Single source of truth for turning a window's (attack flow count, total
    flow count) into a binary "is this window an attack" call.

    Used identically in two places that must never disagree:
      - ground truth       : src/evaluator/thesis_evaluator._gt_to_binary
      - Role 1's own verdict: the window-verdict block in
                              src/pipeline/unified_pipeline.py

    threshold=0.5 is majority vote (attack flows must outnumber benign).
    threshold=0.0 (or anything <= 0) is "any attack flow present". Neither
    extreme is generally right — see config.evaluation.attack_window_threshold
    in config/settings.yaml for the measured failure mode of each and how to
    calibrate a value in between for your own data.
    """
    if total_count <= 0:
        return False
    return (attack_count / total_count) >= threshold


def is_benign(label: Optional[str]) -> bool:
    return to_family(label) == BENIGN_FAMILY


def known_families() -> set:
    return set(UNIVERSAL_LABEL_MAP.values())


def unmapped_labels(labels) -> list:
    """
    Labels with no entry in the map — call this after loading a new dataset.
    Anything returned here will be treated as its own family and, more
    importantly, as an ATTACK (since it is not Benign), so silent drift here
    corrupts the binary ablation table too.
    """
    out = []
    for l in labels:
        s = str(l).strip()
        if s in NO_LABEL_SENTINELS or not s:
            continue
        if s not in UNIVERSAL_LABEL_MAP:
            out.append(s)
    return sorted(set(out))
