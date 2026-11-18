"""
src/engine/decision_engine.py
==============================
Unified decision engine — merges verdicts from all three roles and
produces a single authoritative alert with a severity level.

FIX APPLIED (this version)
────────────────────────────
_best_attack_type() previously picked whichever role's attack_type had
a HIGHER fixed priority number (ATTACK_PRIORITY dict below), regardless
of which role was actually correct. Since "Brute Force" (priority 4)
ranks above "PortScan" (3) and "Bot" (2), a biased LLM guess of
"Brute Force" would silently override Role1's correct, calibrated
"PortScan"/"Bot" label on every window — this is why every alert in
the dashboard showed "Brute Force" regardless of the real attack.

Fix: trust Role1 (the calibrated ML classifier) for the SPECIFIC
attack type whenever Role1 detected an attack. Only fall back to
Role3's (LLM) attack_type guess when Role1 is missing or says benign.
Role3's TEXT explanation and verdict/severity contribution are
unaffected by this change — only which label is DISPLAYED as the
attack type changes.

Conflict resolution matrix (severity) — UNCHANGED
──────────────────────────────────────────────────
Role1 verdict | Role3 verdict | Outcome
─────────────────────────────────────────────────────────────────
attack        | attack        → HIGH    — confirmed by both paths
attack        | suspicious    → HIGH    — Role1 strong signal
attack        | benign        → MEDIUM  — flow-level attack, no log context
suspicious    | attack        → MEDIUM  — log context found attack, flow borderline
suspicious    | suspicious    → MEDIUM  — both uncertain, review
suspicious    | benign        → LOW     — weak signal only
benign        | attack        → MEDIUM  — log analyst caught something Role1 missed
benign        | suspicious    → LOW     — watch list
benign        | benign        → NONE    — suppress, not an attack
error / missing role          → use the available role only

Role 2 does NOT change the verdict — it only adds the explanation text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from src.utils.logger import get_logger
from src.live.behavioral_guard import normalize_llm_verdict

log = get_logger(__name__)

# ── severity levels ───────────────────────────────────────────────────────────
SEVERITY_NONE   = "NONE"
SEVERITY_LOW    = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH   = "HIGH"

SEVERITY_ORDER = {SEVERITY_NONE: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2, SEVERITY_HIGH: 3}

# ── attack-type precedence ───────────────────────────────────────────────────
# NOTE: this is now ONLY used as a last-resort tiebreak when BOTH roles agree
# on which one is "more specific" but neither is preferred by the FIX above
# (i.e. when Role1 has no verdict at all). It is NOT used to override a valid
# Role1 attack_type — see _best_attack_type().
ATTACK_PRIORITY = {
    "Normal":                     0,
    "Unknown":                    1,
    "Bot":                        2,
    "PortScan":                   3,
    "Brute Force":                4,
    "FTP-Patator":                4,
    "SSH-Patator":                4,
    "Web Attack Brute Force":     5,
    "Web Attack XSS":             5,
    "Web Attack SQL Injection":   6,
    "Infiltration":               7,
    "DoS":                        7,
    "DDoS":                       8,
    "Heartbleed":                 9,
}

# Conflict resolution table
_RESOLUTION = {
    ("attack",     "attack"):     (SEVERITY_HIGH,   False),
    ("attack",     "suspicious"): (SEVERITY_HIGH,   False),
    ("attack",     "benign"):     (SEVERITY_MEDIUM, False),
    ("attack",     "missing"):    (SEVERITY_HIGH,   False),
    ("suspicious", "attack"):     (SEVERITY_MEDIUM, False),
    ("suspicious", "suspicious"): (SEVERITY_MEDIUM, False),
    ("suspicious", "benign"):     (SEVERITY_LOW,    False),
    ("suspicious", "missing"):    (SEVERITY_LOW,    False),
    ("benign",     "attack"):     (SEVERITY_MEDIUM, False),
    ("benign",     "suspicious"): (SEVERITY_LOW,    False),
    ("benign",     "benign"):     (SEVERITY_NONE,   True),
    ("benign",     "missing"):    (SEVERITY_NONE,   True),
}


# ── output dataclass ──────────────────────────────────────────────────────────

@dataclass
class UnifiedAlert:
    """Single authoritative alert produced by the decision engine."""

    timestamp:          str   = ""
    severity:           str   = SEVERITY_NONE
    suppressed:         bool  = False

    final_verdict:      str   = "benign"       # attack | suspicious | benign
    attack_type:        str   = "Normal"
    confidence:         int   = 0              # 0-100, average of contributing roles

    role1_verdict:      str   = "unknown"
    role1_attack_type:  str   = "Unknown"
    role1_confidence:   float = 0.0
    role3_verdict:      str   = "missing"
    role3_attack_type:  str   = "Unknown"
    role3_confidence:   int   = 0

    shap_top_features:  List[str] = field(default_factory=list)
    llm_explanation:    str   = ""
    role3_explanation:  str   = ""

    soc_explanation:    str   = ""
    recommended_action: str   = ""
    key_indicators:      List[str] = field(default_factory=list)

    flow_features:      Dict[str, Any] = field(default_factory=dict)
    conflict:            bool  = False
    agree:                bool  = False

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @property
    def is_alert(self) -> bool:
        return self.severity in (SEVERITY_MEDIUM, SEVERITY_HIGH)

    def colour_code(self) -> str:
        return {
            SEVERITY_HIGH:   "🔴",
            SEVERITY_MEDIUM: "🟡",
            SEVERITY_LOW:    "🔵",
            SEVERITY_NONE:   "⚪",
        }.get(self.severity, "⚪")


# ── engine ────────────────────────────────────────────────────────────────────

class DecisionEngine:
    """
    Merges outputs from all three NIDS roles into a UnifiedAlert.
    """

    def __init__(self, cfg):
        self.min_alert_severity = getattr(cfg, "min_alert_severity", SEVERITY_LOW)
        # BUG THIS FIXES: this set used to be {"BENIGN","benign","normal",
        # "Normal"} and was MISSING "Benign" — the exact label the universal
        # ensemble emits (universal label space capitalises it). Every benign
        # window was therefore read as Role1=attack, which poisoned both the
        # Combined verdict and the stored role1_verdict, giving Combined FPR
        # 100% while Role 1's own table (which used a DIFFERENT, correct set in
        # thesis_evaluator) showed FPR 0%. Kept as a fast local set that now
        # matches the evaluator; is_benign() below is the shared authority.
        self.benign_labels = {"BENIGN", "Benign", "benign", "normal", "Normal", "Normal."}
        # Fusion strategy for the binary verdict — see _final_verdict().
        # Priority: explicit cfg.fusion_mode > $NIDS_FUSION_MODE > default.
        import os as _os
        mode = (getattr(cfg, "fusion_mode", None)
                or _os.environ.get("NIDS_FUSION_MODE")
                or "role1_gated")
        mode = str(mode).lower()
        if mode not in ("or", "and", "role1_gated"):
            mode = "role1_gated"
        self.fusion_mode = mode

    # ── public ────────────────────────────────────────────────────────────────

    def merge(
        self,
        role1_result:  Optional[dict] = None,
        role2_data:    Optional[dict] = None,
        role3_verdict: Optional[dict] = None,
        flow_features: Optional[dict] = None,
    ) -> UnifiedAlert:
        alert = UnifiedAlert(
            timestamp     = datetime.now(timezone.utc).isoformat(),
            flow_features = flow_features or {},
        )

        # ── Role 1 ────────────────────────────────────────────────────────────
        r1_binary = "missing"
        if role1_result:
            label = str(role1_result.get("Predicted_Label",
                        role1_result.get("predicted_label", "BENIGN")))
            r1_binary = "benign" if label in self.benign_labels else "attack"
            alert.role1_verdict     = r1_binary
            alert.role1_attack_type = label
            alert.role1_confidence  = float(role1_result.get("Confidence",
                                            role1_result.get("confidence", 0)))

        # ── Role 2 ────────────────────────────────────────────────────────────
        if role2_data:
            alert.shap_top_features = role2_data.get("shap_top_features", [])
            alert.llm_explanation   = role2_data.get("llm_explanation", "")

        # ── Role 3 ────────────────────────────────────────────────────────────
        r3_binary = "missing"
        if role3_verdict and not role3_verdict.get("_error"):
            r3_norm   = normalize_llm_verdict(dict(role3_verdict))
            r3_raw    = str(r3_norm.get("verdict", "benign")).lower()
            r3_binary = r3_raw if r3_raw in ("attack", "suspicious", "benign") else "benign"
            alert.role3_verdict     = r3_binary
            alert.role3_attack_type = r3_norm.get("attack_type", "Unknown")
            alert.role3_confidence  = int(r3_norm.get("confidence", 0))
            alert.role3_explanation = r3_norm.get("explanation", "")
            alert.key_indicators    = r3_norm.get("key_indicators", [])

        # ── conflict resolution ───────────────────────────────────────────────
        severity, suppressed = self._resolve(r1_binary, r3_binary)
        alert.severity   = severity
        alert.suppressed = suppressed

        # ── final verdict ─────────────────────────────────────────────────────
        alert.final_verdict = self._final_verdict(r1_binary, r3_binary, suppressed)
        alert.attack_type   = self._best_attack_type(alert)
        alert.confidence    = self._avg_confidence(alert)
        alert.conflict      = self._is_conflict(r1_binary, r3_binary)
        alert.agree         = (r1_binary == r3_binary and r1_binary != "missing")

        # ── merged SOC explanation ────────────────────────────────────────────
        alert.soc_explanation    = self._build_soc_explanation(alert, r1_binary, r3_binary)
        alert.recommended_action = self._best_action(role3_verdict)

        log.debug(
            "Decision: R1=%s R3=%s → %s %s (conflict=%s)",
            r1_binary, r3_binary, severity, alert.final_verdict, alert.conflict,
        )
        return alert

    # ── internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve(r1: str, r3: str):
        key = (r1, r3)
        if r1 == "missing" and r3 == "missing":
            return SEVERITY_NONE, True
        if r1 == "missing":
            solo_map = {"attack": SEVERITY_HIGH, "suspicious": SEVERITY_LOW, "benign": SEVERITY_NONE}
            sev = solo_map.get(r3, SEVERITY_NONE)
            return sev, (sev == SEVERITY_NONE)
        if r3 == "missing":
            solo_map = {"attack": SEVERITY_HIGH, "suspicious": SEVERITY_MEDIUM, "benign": SEVERITY_NONE}
            sev = solo_map.get(r1, SEVERITY_NONE)
            return sev, (sev == SEVERITY_NONE)
        return _RESOLUTION.get(key, (SEVERITY_LOW, False))

    def _final_verdict(self, r1: str, r3: str, suppressed: bool) -> str:
        """
        Combine the two binary verdicts. The mode is chosen by self.fusion_mode
        (cfg.fusion_mode or $NIDS_FUSION_MODE), so the ablation can compare
        strategies without editing code.

        WHY THIS IS CONFIGURABLE
        ------------------------
        On a CICIDS2017 replay Suricata over-fires (~99% window FPR), and Role 3
        reads those alerts, so Role 3 alone flags almost every window. Under the
        original OR rule ("attack if EITHER role says attack") Combined inherits
        that FPR and can never beat Role 1 — fusion looks strictly harmful. The
        point of fusion is the opposite: let the precise flow-level detector
        (Role 1) decide attack/benign, and let the log analyst (Role 3) ADD
        context or catch what Role 1 missed, without manufacturing false alarms.

        Modes:
          "or"          attack if either says attack (original; max recall,
                        inherits Role 3's false positives).
          "and"         attack only if BOTH agree (max precision, lower recall).
          "role1_gated" (default, recommended) Role 1 owns the attack/benign
                        call. If Role 1 says benign but Role 3 says attack, the
                        window is "suspicious" (surfaced for review) rather than
                        "attack" — so Role 3 cannot inflate the attack FPR, but
                        its catches are not silently dropped. Role-3-only signals
                        on a Role-1 benign window are exactly the ones a human
                        should glance at, which is what "suspicious" is for.
        """
        if suppressed:
            return "benign"

        mode = self.fusion_mode
        if mode == "or":
            for v in ("attack", "suspicious"):
                if r1 == v or r3 == v:
                    return v
            return "benign"

        if mode == "and":
            if r1 == "attack" and r3 == "attack":
                return "attack"
            if r1 in ("attack", "suspicious") and r3 in ("attack", "suspicious"):
                return "suspicious"
            # a lone attack signal from one role is downgraded to suspicious
            if r1 == "attack" or r3 == "attack":
                return "suspicious"
            return "benign"

        # role1_gated (default)
        if r1 == "attack":
            return "attack"                      # Role 1 is the precise caller
        if r1 == "suspicious":
            return "suspicious"
        # r1 is benign or missing here
        if r1 == "missing" and r3 == "attack":
            return "attack"                      # no flow verdict: trust Role 3
        if r3 in ("attack", "suspicious"):
            return "suspicious"                  # Role 1 benign + Role 3 alarm
        return "benign"

    @staticmethod
    def _best_attack_type(alert: "UnifiedAlert") -> str:
        """
        FIX: trust Role1's specific attack_type whenever Role1 detected
        an attack (Role1 is the calibrated, validated ML classifier —
        it should not be silently overridden by a potentially biased LLM
        guess just because that guess happens to have a higher fixed
        priority number in ATTACK_PRIORITY).

        Only fall back to Role3's attack_type when Role1 has no useful
        label (missing, "Unknown", or "Normal" while Role3 says attack —
        e.g. Role1 had insufficient flow data for this window but Role3
        caught something from the Suricata log context).
        """
        r1_type = alert.role1_attack_type
        r3_type = alert.role3_attack_type

        r1_useful = alert.role1_verdict == "attack" and r1_type not in ("Unknown", "Normal", "")
        if r1_useful:
            return r1_type

        r3_useful = r3_type not in ("Unknown", "Normal", "")
        if r3_useful:
            return r3_type

        return r1_type or r3_type or "Unknown"

    @staticmethod
    def _avg_confidence(alert: UnifiedAlert) -> int:
        confs = []
        if alert.role1_confidence > 0:
            confs.append(alert.role1_confidence)
        if alert.role3_confidence > 0:
            confs.append(alert.role3_confidence)
        return int(sum(confs) / len(confs)) if confs else 0

    @staticmethod
    def _is_conflict(r1: str, r3: str) -> bool:
        if r1 in ("missing", "unknown") or r3 in ("missing", "unknown"):
            return False
        attack_set = {"attack", "suspicious"}
        return (r1 in attack_set) != (r3 in attack_set)

    @staticmethod
    def _build_soc_explanation(alert: UnifiedAlert, r1: str, r3: str) -> str:
        parts = []

        if alert.agree:
            parts.append(
                f"Both Role1 (ML model) and Role3 (log analyst) classify this as "
                f"{alert.final_verdict.upper()}."
            )
        elif alert.conflict:
            parts.append(
                f"Conflict: Role1 (ML) says {r1}, Role3 (log analyst) says {r3}. "
                f"Manual review recommended."
            )
        else:
            role = "Role1 (ML)" if r3 == "missing" else "Role3 (log analyst)"
            parts.append(f"Single-source verdict from {role}: {alert.final_verdict.upper()}.")

        if alert.role3_explanation:
            parts.append(alert.role3_explanation)
        elif alert.llm_explanation:
            parts.append(alert.llm_explanation)

        if alert.shap_top_features:
            parts.append(
                f"Top ML features: {', '.join(alert.shap_top_features[:4])}."
            )

        return " ".join(parts)

    @staticmethod
    def _best_action(role3_verdict: Optional[dict]) -> str:
        if role3_verdict and not role3_verdict.get("_error"):
            action = role3_verdict.get("recommended_action", "")
            if action:
                return action
        return "Review raw logs in EveBox and correlate with SHAP feature values."
