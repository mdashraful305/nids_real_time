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

TAXONOMY POLICY (v4 — semantic harmonisation)
─────────────────────────────────────────────
Native labels are reported as PRIMARY results per dataset. This shared map is
the SECONDARY coarse view for cross-dataset reporting, and it follows two
rules so it survives review:

  1. Only merge families that are behaviourally identical AND occur in >=2
     datasets: Benign, DoS, Brute Force, PortScan, Web Attack (and DDoS,
     kept separate from DoS by choice).
  2. Everything dataset-unique is PASSTHROUGH (maps to itself) — never folded
     into an unrelated bucket just to shrink the class count. A single-dataset
     label dressed as a shared family is what invites reviewer criticism.

Fixed from the earlier draft (all semantically wrong or lossy):
    Backdoor        : Infiltration  -> Backdoor           (Infiltration is broader)
    Exploits        : Web Attack     -> Exploits           (exploits are not web-only)
    Generic         : DoS            -> Generic            (distinct UNSW family)
    Reconnaissance  : PortScan       -> Reconnaissance     (broader than port scan)
    snmpguess       : Web Attack     -> Brute Force        (community-string guessing)
    warezclient     : Web Attack     -> Unauthorized Access (R2L, not web)
    warezmaster     : Web Attack     -> Unauthorized Access (R2L, not web)

Because each sub-model trains on NATIVE labels, editing this map costs no
retraining — only the merged-space reporting cells need to be re-run.
"""

from typing import Dict, Optional

# Sentinels meaning "no ground truth", never a class.
UNMATCHED_LABEL = "UNMATCHED"
UNKNOWN_LABEL   = "UNKNOWN"      # legacy; emitted by the old broken fallback
NO_LABEL_SENTINELS = frozenset({UNMATCHED_LABEL, UNKNOWN_LABEL})

BENIGN_FAMILY = "Benign"

UNIVERSAL_LABEL_MAP: Dict[str, str] = {
    # ── genuinely shared (>=2 datasets, same behaviour) ──
    "BENIGN": "Benign", "Normal": "Benign", "normal": "Benign",
    "DoS GoldenEye": "DoS", "DoS Hulk": "DoS", "DoS Slowhttptest": "DoS",
    "DoS slowloris": "DoS", "DoS": "DoS",
    "apache2": "DoS", "back": "DoS", "neptune": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "mailbomb": "DoS", "processtable": "DoS", "DDoS": "DDoS",
    "FTP-Patator": "Brute Force", "SSH-Patator": "Brute Force",
    "guess_passwd": "Brute Force", "snmpguess": "Brute Force",
    "PortScan": "PortScan", "ipsweep": "PortScan", "nmap": "PortScan",
    "portsweep": "PortScan", "mscan": "PortScan", "saint": "PortScan",
    "satan": "PortScan",
    "Web Attack � Brute Force": "Web Attack", "Web Attack � XSS": "Web Attack",
    # ── dataset-unique: passthrough, NOT forced into a shared bucket ──
    "Bot": "Bot", "Analysis": "Analysis", "Backdoor": "Backdoor",
    "Exploits": "Exploits", "Generic": "Generic", "Fuzzers": "Fuzzers",
    "Reconnaissance": "Reconnaissance", "Shellcode": "Shellcode",
    "warezclient": "Unauthorized Access", "warezmaster": "Unauthorized Access",
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
