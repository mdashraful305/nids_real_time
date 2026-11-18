#!/usr/bin/env python3
"""
evaluate_nids.py
================================================================================
ONE evaluation entry point for the tri-role NIDS, covering offline replay and
both real-time approaches with a single, consistent metric set — written to
close the gaps the peer-review dossier raised. It orchestrates the project's
existing `src/` modules (identical across the offline and realtime bundles);
it does not re-implement the pipeline, so its numbers match main_unified.py /
nids_web.py exactly, plus the measurements those two never reported.

Run it from the project root (the folder containing `src/`, `config/`,
`universal_nids_output.pkl`).

────────────────────────────────────────────────────────────────────────────────
MODES
────────────────────────────────────────────────────────────────────────────────
  offline        Track-B style replay: Suricata eve.json + CICFlowMeter CSV,
                 all three roles, ablation table (Role1 / Role3 / Combined),
                 bootstrap CIs, McNemar, per-family, latency percentiles,
                 LLM parse-failure audit. Wraps UnifiedPipeline.run_offline.

  realtime       Live capture. Two approaches, selected with --approach:
                   1  NFStream inline per-flow (nids_web.py path)
                   2  tcpdump→CICFlowMeter rotated pcap (main_unified --mode live)
                 Produces the same flow/verdict log both dashboards write, then
                 scores it here so Approach 1 and Approach 2 are reported with
                 ONE metric definition instead of two incomparable ones.

  benign-fpr     The measurement the dossier said was missing: run the live
                 pipeline (either approach) against benign-only traffic for a
                 fixed duration and report the live false-positive rate and
                 alert VOLUME of Role 1, Role 3 and Suricata. A detector's low
                 FPR cannot be claimed without this.

  latency        Stage-by-stage latency with mean / p50 / p95 / p99 / std for
                 Role 1 (batched + per-flow), Role 2 SHAP, Role 3 LLM, decision
                 merge — with the host hardware recorded alongside.

  prompt-dump    Write the EXACT Role 3 system prompt, user-prompt template,
                 decoding parameters and JSON schema to a file for the paper's
                 reproducibility appendix. No capture needed.

  llm-audit      Forensic breakdown of a Role 3 run: of N windows, how many
                 produced valid JSON, how many hit a parse error, how many were
                 genuine benign/attack verdicts. This is what explains a recall
                 "collapse" (parse failures defaulting to benign) vs a real
                 model difference — the 7B-vs-1.5B question.

Every mode writes a timestamped JSON under <results_dir>/eval/ and prints a
human-readable summary. --hardware is captured into every report.
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

# Project root on path so `src.*` imports resolve regardless of CWD.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Register the pickled classes BEFORE any joblib.load of the model.
try:
    from src.engine.universal_ensemble import UniversalEnsemble  # noqa: F401
    from src.engine.weighted_hybrid import WeightedHybridEnsemble  # noqa: F401
except Exception:
    pass


# ══════════════════════════════════════════════════════════════════════════════
# SHARED: the EXACT Role 3 prompt + decoding config, in ONE place.
# This is the single source of truth the dossier asked for. main_unified.py uses
# src/llm/ollama_analyst.py; nids_web.py has its own inline copy. Both are
# reproduced verbatim here so the paper's appendix can cite one file.
# ══════════════════════════════════════════════════════════════════════════════

from src.llm.ollama_analyst import SYSTEM_PROMPT as ROLE3_SYSTEM_PROMPT  # noqa: E402

ROLE3_DECODING = {
    "temperature": 0.1,          # config/settings.yaml ollama.temperature
    "top_p": 0.9,
    "repeat_penalty": 1.1,
    "num_predict": 600,          # ollama.max_tokens
    "format": "json",            # native JSON mode (nids_web path)
    "stream": False,
    "timeout_seconds": 180,      # ollama.timeout_seconds
    "retry_attempts": 3,
    "window_seconds": 60,        # chunker.window_seconds (offline default)
    "note": "Offline (main_unified) uses src/llm/ollama_analyst.py which sends "
            "the system prompt via Ollama's 'system' field and parses the first "
            "JSON object out of the response, filling missing keys with defaults "
            "(verdict→suspicious). The live dashboard (nids_web.py) uses "
            "Ollama format=json with temperature 0.0. Record which path produced "
            "any reported number.",
}


# ══════════════════════════════════════════════════════════════════════════════
# helpers
# ══════════════════════════════════════════════════════════════════════════════

def _p(msg=""):
    print(msg, flush=True)


def capture_hardware() -> dict:
    """Host facts for the reproducibility section. Recorded in every report."""
    def _try(cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True,
                                           stderr=subprocess.DEVNULL).strip()
        except Exception:
            return None

    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_model": _try("lscpu | grep 'Model name' | sed 's/.*: *//'")
                     or platform.processor(),
        "cpu_count_logical": os.cpu_count(),
        "ram_total": _try("grep MemTotal /proc/meminfo"),
        "gpu": _try("nvidia-smi --query-gpu=name,memory.total,driver_version "
                    "--format=csv,noheader") or "none / CPU-only",
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }


def percentiles(samples_ms):
    """mean / p50 / p95 / p99 / std / max over a list of millisecond samples."""
    import numpy as np
    if not samples_ms:
        return {"n": 0}
    a = np.asarray(samples_ms, dtype=float)
    return {
        "n": int(a.size),
        "mean_ms": round(float(a.mean()), 4),
        "std_ms": round(float(a.std()), 4),
        "p50_ms": round(float(np.percentile(a, 50)), 4),
        "p95_ms": round(float(np.percentile(a, 95)), 4),
        "p99_ms": round(float(np.percentile(a, 99)), 4),
        "max_ms": round(float(a.max()), 4),
    }


def load_config(path):
    from src.utils.config_loader import load_config as _lc
    return _lc(path)


def load_model(pkl_path):
    import joblib
    if not os.path.exists(pkl_path):
        _p(f"  ✗ model pkl not found: {pkl_path}")
        sys.exit(2)
    return joblib.load(pkl_path)


def write_report(results_dir, mode, report):
    out_dir = os.path.join(results_dir, "eval")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"eval_{mode}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    _p(f"\n  ✓ report → {path}")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# MODE: offline
# ══════════════════════════════════════════════════════════════════════════════

def run_offline(args):
    """Track-B offline replay via the existing UnifiedPipeline, then surface the
    metrics the pipeline already computes PLUS the LLM parse-failure audit the
    dossier wanted. The pipeline writes a thesis_report_*.json; we read the
    freshest one and fold in the audit."""
    from src.pipeline.unified_pipeline import UnifiedPipeline
    from src.llm.ollama_analyst import OllamaAnalyst

    cfg = load_config(args.config)
    if args.ollama_url:
        cfg.ollama.url = args.ollama_url
    if args.ollama_model:
        cfg.ollama.model = args.ollama_model
    if args.window_seconds:
        cfg.chunker.window_seconds = args.window_seconds

    nids_out = load_model(args.pkl)

    is_local = "localhost" in cfg.ollama.url or "127.0.0.1" in cfg.ollama.url
    _p("═" * 70)
    _p("  UNIFIED NIDS — OFFLINE EVALUATION (evaluate_nids.py)")
    _p(f"  Ollama : {cfg.ollama.url} ({'local' if is_local else 'REMOTE/3rd-party'})"
       f"  model={cfg.ollama.model}")
    if not is_local:
        _p("  ⚠  Remote Ollama endpoint: the LLM is NOT on the capture host. Any "
           "Role-3 latency you report from this run includes a network hop and must "
           "be labelled as such in the paper.")
    _p(f"  Window : {cfg.chunker.window_seconds}s   Fusion: "
       f"{os.environ.get('NIDS_FUSION_MODE', 'role1_gated')}")
    _p("═" * 70)

    analyst = OllamaAnalyst(cfg)
    if not args.no_llm and not analyst.check_connection():
        _p("  ✗ Ollama not reachable — start it or pass --no-llm to skip Role 3.")
        if not args.allow_offline_without_llm:
            sys.exit(2)

    pipe = UnifiedPipeline(cfg, nids_out)
    pipe.set_routing(dataset=args.dataset, allow_unscaled=args.allow_unscaled)
    t0 = time.time()
    pipe.run_offline(
        eve_dir=args.eve_dir,
        flow_dir=args.flow_dir,
        quick=args.quick,
        num_workers=args.workers,
        skip_llm_on_benign=not args.no_llm_gating,
        low_memory=not args.no_low_memory,
        db_dir=args.db_dir,
    )
    wall = time.time() - t0

    # Pull the freshest thesis report the pipeline just wrote.
    import glob
    reports = sorted(glob.glob(os.path.join(cfg.paths.results_dir,
                                            "thesis_report_*.json")),
                     key=os.path.getmtime)
    thesis = json.load(open(reports[-1])) if reports else {}

    # LLM parse-failure audit from the per-window CSV + alerts jsonl.
    audit = _llm_audit_from_results(cfg.paths.results_dir)

    report = {
        "mode": "offline",
        "hardware": capture_hardware(),
        "role3_prompt": {"system_prompt": ROLE3_SYSTEM_PROMPT,
                         "decoding": ROLE3_DECODING,
                         "endpoint": cfg.ollama.url,
                         "endpoint_is_local": is_local,
                         "model": cfg.ollama.model},
        "wall_clock_seconds": round(wall, 1),
        "thesis_report_file": reports[-1] if reports else None,
        "ablation": thesis.get("ablation"),
        "uncertainty": thesis.get("uncertainty"),
        "significance": thesis.get("significance"),
        "latency": thesis.get("latency"),
        "llm_parse_audit": audit,
        "fusion_mode": os.environ.get("NIDS_FUSION_MODE", "role1_gated"),
        "reviewer_note_role1_gated": (
            "role1_gated's binary output equals Role 1's by construction, so a "
            "McNemar p=1 vs Role 1 is a mathematical identity, not a statistical "
            "finding. Report it as an implementation check, not evidence."
        ),
    }
    _print_offline_summary(report)
    write_report(cfg.paths.results_dir, "offline", report)


def _llm_audit_from_results(results_dir):
    """Classify every stored Role-3 verdict in unified_alerts.jsonl: valid JSON
    vs error/skip, and the verdict distribution. This is what distinguishes a
    genuine recall difference from a parser defaulting to benign."""
    path = os.path.join(results_dir, "unified_alerts.jsonl")
    if not os.path.exists(path):
        return {"note": "unified_alerts.jsonl not found"}
    n = 0
    verdicts = Counter()
    errors = 0
    skipped = 0
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
        except Exception:
            continue
        n += 1
        r3 = str(a.get("role3_verdict", "missing"))
        verdicts[r3] += 1
        expl = (a.get("role3_explanation") or "").lower()
        if "failed" in expl or "error" in expl:
            errors += 1
        if "skipped" in expl:
            skipped += 1
    return {
        "windows_scored": n,
        "role3_verdict_distribution": dict(verdicts),
        "llm_error_windows": errors,
        "llm_skipped_windows": skipped,
        "interpretation": (
            "If a model shows near-zero recall AND a large error/skip count, the "
            "'collapse' is a parsing/formatting failure (verdict defaulted), not the "
            "model missing attacks. Compare error_windows across 1.5B vs 7B before "
            "attributing a recall drop to model capacity."
        ),
    }


def _print_offline_summary(report):
    abl = report.get("ablation") or {}
    _p("\n  ── Ablation (Role1 / Role3 / Combined) ──")
    for k in ("role1_only", "role3_only", "combined"):
        m = abl.get(k, {})
        if m:
            _p(f"    {k:<12} P={m.get('precision')}%  R={m.get('recall')}%  "
               f"F1={m.get('f1_score')}%  FPR={m.get('fpr')}%  "
               f"(tp={m.get('tp')} tn={m.get('tn')} fp={m.get('fp')} fn={m.get('fn')})")
    aud = report.get("llm_parse_audit", {})
    _p(f"\n  ── LLM audit ── windows={aud.get('windows_scored')}  "
       f"errors={aud.get('llm_error_windows')}  skipped={aud.get('llm_skipped_windows')}")
    _p(f"    verdicts: {aud.get('role3_verdict_distribution')}")


# ══════════════════════════════════════════════════════════════════════════════
# MODE: realtime  (approach 1 = NFStream, approach 2 = CICFlowMeter rotation)
# ══════════════════════════════════════════════════════════════════════════════

def run_realtime(args):
    """Launch the correct live path for the chosen approach, let it run for
    --duration seconds, then score the flow/verdict log it produced with ONE
    metric definition so Approach 1 and Approach 2 are directly comparable."""
    if args.approach == 1:
        _p("  Approach 1 — NFStream inline per-flow (nids_web.py).")
        _p("  Start capture in another terminal, e.g.:")
        _p(f"     sudo .venv/bin/python nids_web.py --iface {args.iface} "
           f"--pkl {args.pkl} --ollama-url {args.ollama_url or 'http://localhost:11434'}")
        _p("  It writes nids_history.json continuously. This mode scores that file.")
        hist = args.history or "nids_history.json"
        _wait_for(hist, args.duration)
        report = _score_history(hist, approach=1, attacker_ip=args.attacker_ip,
                                target_ip=args.target_ip)
    else:
        _p("  Approach 2 — tcpdump → CICFlowMeter rotation (main_unified --mode live).")
        _p("  Start the 4 terminals from REALTIME_GUIDE.md (Suricata, capture, "
           "flow_processor, main_unified --mode live). This mode scores the "
           "unified_alerts.jsonl that pipeline writes.")
        alerts = args.alerts or "data/results/unified_alerts.jsonl"
        _wait_for(alerts, args.duration)
        report = _score_unified_alerts(alerts, approach=2)

    report["hardware"] = capture_hardware()
    if args.approach == 1:
        try:
            import nids_web as _nw
            a1_prompt = getattr(_nw, "SYSTEM_PROMPT", ROLE3_SYSTEM_PROMPT)
        except Exception:
            a1_prompt = ROLE3_SYSTEM_PROMPT
        report["role3_prompt"] = {"system_prompt": a1_prompt,
                                  "decoding": {"format": "json", "temperature": 0.0, "num_predict": 400}}
    else:
        report["role3_prompt"] = {"system_prompt": ROLE3_SYSTEM_PROMPT,
                                  "decoding": ROLE3_DECODING}
    _p(json.dumps({k: v for k, v in report.items()
                   if k not in ("per_attack",)}, indent=2, default=str)[:2000])
    rd = args.results_dir or "data/results"
    write_report(rd, f"realtime_approach{args.approach}", report)


def _wait_for(path, duration):
    _p(f"  Observing '{path}' for {duration}s ...")
    end = time.time() + duration
    while time.time() < end:
        time.sleep(min(10, max(1, end - time.time())))
    if not os.path.exists(path):
        _p(f"  ⚠  {path} never appeared — is the capture running and writing it?")


def _score_history(hist_path, approach, attacker_ip=None, target_ip=None):
    """Score Approach 1 complete log (flows.jsonl + r3.jsonl when available via
    data/runs/latest_run.txt) or fallback to nids_history.json UI snapshot."""
    from src.live.behavioral_guard import is_attack_verdict

    flows = []
    source_name = hist_path
    latest_txt = os.path.join("data", "runs", "latest_run.txt")
    if os.path.exists(latest_txt):
        run_dir = open(latest_txt).read().strip()
        fl_path = os.path.join(run_dir, "flows.jsonl")
        r3_path = os.path.join(run_dir, "r3.jsonl")
        if os.path.exists(fl_path):
            source_name = fl_path
            r3_by_id = {}
            if os.path.exists(r3_path):
                with open(r3_path, encoding="utf-8", errors="replace") as rf:
                    for ln in rf:
                        ln = ln.strip()
                        if not ln:
                            continue
                        try:
                            rr = json.loads(ln)
                            r3_by_id[rr.get("id")] = rr
                        except Exception:
                            pass
            with open(fl_path, encoding="utf-8", errors="replace") as ff:
                for ln in ff:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                    except Exception:
                        continue
                    rr = r3_by_id.get(rec.get("id"))
                    if rr:
                        rec["r3_verdict"] = rr.get("verdict")
                    flows.append(rec)

    if not flows:
        if not os.path.exists(hist_path):
            return {"mode": "realtime", "approach": approach,
                    "error": f"{hist_path} not found"}
        data = json.load(open(hist_path))
        flows = data.get("flows", [])

    total = len(flows)
    atk_flows = [f for f in flows
                 if (attacker_ip is None or f.get("src_ip") == attacker_ip)]

    def _is_attack_r1(f):
        return bool(f.get("r1_is_attack"))

    def _is_attack_r3(f):
        return is_attack_verdict(f.get("r3_verdict"))

    r1_model_hits = sum(1 for f in atk_flows if f.get("model_is_attack"))
    r1_hits = sum(1 for f in atk_flows if _is_attack_r1(f))
    r3_eval = [f for f in atk_flows if f.get("r3_verdict") not in (None, "", "pending", "error")]
    r3_hits = sum(1 for f in r3_eval if _is_attack_r3(f))
    r3_on_r1_atk = [f for f in r3_eval if _is_attack_r1(f)]
    r3_hits_on_r1_atk = sum(1 for f in r3_on_r1_atk if _is_attack_r3(f))
    ui_suppressed = sum(1 for f in atk_flows if f.get("ui_suppressed"))

    # benign-side false positives: pure non-attacker flows (exclude target replies back to attacker)
    ben_flows = [f for f in flows
                 if attacker_ip is not None
                 and f.get("src_ip") != attacker_ip
                 and f.get("dst_ip") != attacker_ip]
    r1_fp = sum(1 for f in ben_flows if _is_attack_r1(f))
    ben_r3_eval = [f for f in ben_flows if f.get("r3_verdict") not in (None, "", "pending", "error")]
    r3_fp = sum(1 for f in ben_r3_eval if _is_attack_r3(f))

    return {
        "mode": "realtime",
        "approach": approach,
        "data_source": source_name,
        "metric_definition": (
            "Per-flow over complete Approach A log. 'hit' = flow received a non-benign verdict. "
            "Role 3 evaluates un-suppressed transition/sampling flows (`evaluated`) rather than every redundant flood packet (`ui_suppressed`)."
        ),
        "attacker_ip": attacker_ip,
        "flows_total": total,
        "attacker_flows": len(atk_flows),
        "role1": {
            "model_only_hits": r1_model_hits,
            "hits": r1_hits,
            "hit_rate_pct": round(100 * r1_hits / max(1, len(atk_flows)), 2),
        },
        "role3": {
            "evaluated": len(r3_eval),
            "hits": r3_hits,
            "hit_rate_pct": round(100 * r3_hits / max(1, len(r3_eval)), 2),
            "evaluated_on_r1_attacks": len(r3_on_r1_atk),
            "hits_on_r1_attacks": r3_hits_on_r1_atk,
            "agreement_on_r1_attacks_pct": round(100 * r3_hits_on_r1_atk / max(1, len(r3_on_r1_atk)), 2) if r3_on_r1_atk else None,
            "ui_suppressed_skipped": ui_suppressed,
        },
        "benign_side": {
            "benign_flows_observed": len(ben_flows),
            "role1_false_positive_flows": r1_fp,
            "role3_evaluated": len(ben_r3_eval),
            "role3_false_positive_flows": r3_fp,
            "role3_fpr_pct": round(100 * r3_fp / max(1, len(ben_r3_eval)), 2),
        },
    }


def _score_unified_alerts(alerts_path, approach):
    """Score main_unified's unified_alerts.jsonl (window-level)."""
    if not os.path.exists(alerts_path):
        return {"mode": "realtime", "approach": approach,
                "error": f"{alerts_path} not found"}
    n = 0
    r1_attack = r3_attack = combined_attack = 0
    sev = Counter()
    for line in open(alerts_path):
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
        except Exception:
            continue
        n += 1
        if str(a.get("role1_verdict")) == "attack":
            r1_attack += 1
        if str(a.get("role3_verdict")) in ("attack", "suspicious"):
            r3_attack += 1
        if str(a.get("final_verdict")) in ("attack", "suspicious"):
            combined_attack += 1
        sev[str(a.get("severity"))] += 1
    return {
        "mode": "realtime",
        "approach": approach,
        "metric_definition": "Window-level counts from the decision engine's "
                             "unified_alerts.jsonl.",
        "windows": n,
        "role1_attack_windows": r1_attack,
        "role3_attack_windows": r3_attack,
        "combined_attack_windows": combined_attack,
        "severity_distribution": dict(sev),
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODE: benign-fpr   (the measurement the dossier said was missing)
# ══════════════════════════════════════════════════════════════════════════════

def run_benign_fpr(args):
    """Score an ATTACK-FREE capture: every non-benign verdict is a false positive.
    Reports Role 1 / Role 3 / Suricata false-positive RATE and alert VOLUME per
    hour, which is what the paper needs to make any low-FPR claim and to size the
    SOC alert-fatigue argument."""
    src = args.alerts or args.history
    if not src or not os.path.exists(src):
        _p("  ✗ provide --alerts <unified_alerts.jsonl> or --history "
           "<nids_history.json> from an ATTACK-FREE capture.")
        sys.exit(2)

    duration_h = max(args.duration, 1) / 3600.0

    if src.endswith(".jsonl"):
        n = 0
        r1_fp = r3_fp = 0
        for line in open(src):
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except Exception:
                continue
            n += 1
            if str(a.get("role1_verdict")) == "attack":
                r1_fp += 1
            if str(a.get("role3_verdict")) in ("attack", "suspicious"):
                r3_fp += 1
        unit, total = "windows", n
        r1 = {"false_positive_windows": r1_fp,
              "fpr_pct": round(100 * r1_fp / max(1, n), 3),
              "alerts_per_hour": round(r1_fp / duration_h, 1)}
        r3 = {"false_positive_windows": r3_fp,
              "fpr_pct": round(100 * r3_fp / max(1, n), 3),
              "alerts_per_hour": round(r3_fp / duration_h, 1)}
    else:
        data = json.load(open(src))
        flows = data.get("flows", [])
        total = len(flows)
        r1_fp = sum(1 for f in flows if f.get("r1_is_attack"))
        r3_fp = sum(1 for f in flows
                    if str(f.get("r3_verdict") or "").lower() in ("attack", "suspicious"))
        unit = "flows"
        r1 = {"false_positive_flows": r1_fp,
              "fpr_pct": round(100 * r1_fp / max(1, total), 3),
              "alerts_per_hour": round(r1_fp / duration_h, 1)}
        r3 = {"false_positive_flows": r3_fp,
              "fpr_pct": round(100 * r3_fp / max(1, total), 3),
              "alerts_per_hour": round(r3_fp / duration_h, 1)}

    suricata = None
    if args.eve:
        suricata = _suricata_fp_from_eve(args.eve, duration_h)

    report = {
        "mode": "benign-fpr",
        "hardware": capture_hardware(),
        "capture_is_attack_free": True,
        "duration_seconds": args.duration,
        "unit": unit,
        "total_observed": total,
        "role1": r1,
        "role3": r3,
        "suricata": suricata,
        "role3_prompt": {"system_prompt": ROLE3_SYSTEM_PROMPT,
                         "decoding": ROLE3_DECODING},
        "interpretation": (
            "On attack-free traffic every non-benign verdict is a false positive. "
            "alerts_per_hour sizes the SOC alert-fatigue argument directly (e.g. a "
            "Role-3 rate of N/hour over a benign day). A low Role-1 FPR here is the "
            "evidence needed to claim Role 1 is a precise gate."
        ),
    }
    _p(json.dumps({k: report[k] for k in ("role1", "role3", "suricata", "unit",
                                          "total_observed")}, indent=2, default=str))
    rd = args.results_dir or "data/results"
    write_report(rd, "benign_fpr", report)


def _suricata_fp_from_eve(eve_path, duration_h):
    """Count Suricata alerts in an attack-free eve.json (all are FPs here)."""
    if not os.path.exists(eve_path):
        return {"error": f"{eve_path} not found"}
    n_alerts = 0
    sigs = Counter()
    for line in open(eve_path, errors="replace"):
        line = line.strip()
        if not line or '"event_type"' not in line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("event_type") == "alert":
            n_alerts += 1
            sigs[(e.get("alert") or {}).get("signature", "?")] += 1
    return {
        "false_positive_alerts": n_alerts,
        "alerts_per_hour": round(n_alerts / duration_h, 1),
        "top_signatures": sigs.most_common(10),
        "note": "Disclose the ruleset (ET Open / default / custom) and whether it was "
                "tuned to the testbed subnet alongside this number.",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODE: latency
# ══════════════════════════════════════════════════════════════════════════════

def run_latency(args):
    """Stage-by-stage latency with mean/p50/p95/p99/std. Role 1 batched and
    per-flow, Role 2 SHAP, Role 3 LLM (if reachable), decision merge."""
    import numpy as np
    nids_out = load_model(args.pkl)
    ens = nids_out["ensemble"]
    ds = args.dataset or (nids_out.get("datasets_used") or ["CICIDS2017"])[0]
    feats = nids_out["sub_features"][ds]
    scaler = (nids_out.get("sub_scalers") or {}).get(ds) or nids_out.get("scaler")

    # synthetic feature matrix on the right scale (or load a flow CSV if given)
    if args.flows and os.path.exists(args.flows):
        from src.ingestion.cicflow_reader import (load_cicflow_file,
                                                  build_feature_lookup, resolve_feature)
        df = load_cicflow_file(args.flows)
        lookup = build_feature_lookup(df.columns)
        X = np.zeros((min(len(df), args.n), len(feats)), dtype=np.float32)
        for i, f in enumerate(feats):
            col = resolve_feature(f, lookup)
            if col is not None:
                X[:, i] = np.nan_to_num(df[col].values[:X.shape[0]])
    else:
        rng = np.random.default_rng(42)
        X = rng.random((args.n, len(feats)), dtype=np.float32)
    if scaler is not None:
        try:
            X = scaler.transform(X)
        except Exception:
            pass

    report = {"mode": "latency", "hardware": capture_hardware(),
              "dataset_route": ds, "n_samples": int(X.shape[0]), "stages": {}}

    # Role 1 per-flow
    per_flow = []
    for i in range(min(args.n, X.shape[0])):
        row = X[i:i + 1]
        t = time.perf_counter()
        ens.predict_proba_from_dataset(row, ds)
        per_flow.append((time.perf_counter() - t) * 1000)
    report["stages"]["role1_per_flow"] = percentiles(per_flow)

    # Role 1 batched (per-flow cost within a 1000-row batch)
    batched = []
    bs = 1000
    for start in range(0, X.shape[0], bs):
        chunk = X[start:start + bs]
        if not len(chunk):
            break
        t = time.perf_counter()
        ens.predict_proba_from_dataset(chunk, ds)
        batched.append((time.perf_counter() - t) * 1000 / len(chunk))
    report["stages"]["role1_batched_per_flow"] = percentiles(batched)

    # Role 2 SHAP (hybrid-aware if the sub-model is a hybrid)
    try:
        import shap
        sub = ens.sub_models[ds]
        xgb_m = getattr(sub, "xgb_model", sub)
        expl = shap.TreeExplainer(xgb_m)
        shap_t = []
        for i in range(min(200, X.shape[0])):
            t = time.perf_counter()
            expl.shap_values(X[i:i + 1])
            shap_t.append((time.perf_counter() - t) * 1000)
        report["stages"]["role2_shap"] = percentiles(shap_t)
    except Exception as e:
        report["stages"]["role2_shap"] = {"error": str(e)}

    # Role 3 LLM (optional)
    if args.ollama_url and not args.no_llm:
        report["stages"]["role3_llm"] = _bench_llm(args.ollama_url,
                                                   args.ollama_model or "qwen2.5:1.5b",
                                                   n_calls=args.llm_calls)

    _p(json.dumps(report["stages"], indent=2, default=str))
    rd = args.results_dir or "data/results"
    write_report(rd, "latency", report)


def _bench_llm(url, model, n_calls=20):
    import requests
    sample = ("=" * 40 + "\nLOG WINDOW\nSuricata alerts: 0 | flows: 3\n"
              "flow 10.0.0.5:51000 -> 10.0.0.9:80 TCP dur=0.2s pkts=6\n" + "=" * 40)
    lat = []
    errs = 0
    for _ in range(n_calls):
        t = time.perf_counter()
        try:
            r = requests.post(f"{url}/api/generate",
                              json={"model": model, "system": ROLE3_SYSTEM_PROMPT,
                                    "prompt": sample, "stream": False, "format": "json",
                                    "options": {"temperature": 0.1, "num_predict": 600}},
                              timeout=180)
            if r.status_code != 200:
                errs += 1
            lat.append((time.perf_counter() - t) * 1000)
        except Exception:
            errs += 1
    out = percentiles(lat)
    out["errors"] = errs
    out["model"] = model
    out["endpoint"] = url
    out["endpoint_is_local"] = "localhost" in url or "127.0.0.1" in url
    return out


# ══════════════════════════════════════════════════════════════════════════════
# MODE: prompt-dump
# ══════════════════════════════════════════════════════════════════════════════

def run_prompt_dump(args):
    rd = args.results_dir or "data/results"
    os.makedirs(os.path.join(rd, "eval"), exist_ok=True)
    txt = os.path.join(rd, "eval", "role3_prompt_disclosure.txt")
    with open(txt, "w") as fh:
        fh.write("Role 3 (LLM analyst) — full prompt & decoding disclosure\n")
        fh.write("=" * 68 + "\n\nSYSTEM PROMPT (verbatim):\n")
        fh.write(ROLE3_SYSTEM_PROMPT + "\n\n")
        fh.write("USER PROMPT:\n  the rendered log-window text from "
                 "src/chunker/log_chunker.format_chunk_text() — Suricata alerts, "
                 "protocol metadata, and the top-N flows for the window, with NO "
                 "ground-truth label (include_label=False offline to prevent leakage).\n\n")
        fh.write("DECODING / SCHEMA:\n")
        fh.write(json.dumps(ROLE3_DECODING, indent=2) + "\n")
    _p(f"  ✓ prompt disclosure → {txt}")
    _p("\n" + ROLE3_SYSTEM_PROMPT)


# ══════════════════════════════════════════════════════════════════════════════
# MODE: llm-audit
# ══════════════════════════════════════════════════════════════════════════════

def run_llm_audit(args):
    rd = args.results_dir or "data/results"
    audit = _llm_audit_from_results(rd)
    audit["mode"] = "llm-audit"
    audit["hardware"] = capture_hardware()
    _p(json.dumps(audit, indent=2, default=str))
    write_report(rd, "llm_audit", audit)


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        description="Unified NIDS evaluation (offline + both real-time approaches "
                    "+ benign FPR + latency + prompt/LLM audit).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("mode", choices=["offline", "realtime", "benign-fpr",
                                    "latency", "prompt-dump", "llm-audit"])
    # shared
    p.add_argument("--config", default="config/settings.yaml")
    p.add_argument("--pkl", default="universal_nids_output.pkl")
    p.add_argument("--dataset", default=None,
                   choices=["CICIDS2017", "UNSW-NB15", "NSL-KDD"])
    p.add_argument("--results-dir", dest="results_dir", default=None)
    p.add_argument("--ollama-url", dest="ollama_url", default=None)
    p.add_argument("--ollama-model", dest="ollama_model", default=None)
    p.add_argument("--no-llm", action="store_true")
    # offline
    p.add_argument("--eve-dir", dest="eve_dir", default=None)
    p.add_argument("--flow-dir", dest="flow_dir", default=None)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--window-seconds", dest="window_seconds", type=int, default=None)
    p.add_argument("--quick", action="store_true")
    p.add_argument("--no-llm-gating", dest="no_llm_gating", action="store_true")
    p.add_argument("--no-low-memory", dest="no_low_memory", action="store_true")
    p.add_argument("--db-dir", dest="db_dir", default=None)
    p.add_argument("--allow-unscaled", dest="allow_unscaled", action="store_true")
    p.add_argument("--allow-offline-without-llm", dest="allow_offline_without_llm",
                   action="store_true")
    # realtime / benign
    p.add_argument("--approach", type=int, choices=[1, 2], default=2,
                   help="1=NFStream inline (nids_web.py), 2=CICFlowMeter rotation "
                        "(main_unified --mode live)")
    p.add_argument("--iface", default="wlp0s20f3")
    p.add_argument("--duration", type=int, default=300,
                   help="seconds to observe the capture before scoring")
    p.add_argument("--history", default=None, help="nids_history.json (approach 1)")
    p.add_argument("--alerts", default=None, help="unified_alerts.jsonl (approach 2 / benign)")
    p.add_argument("--eve", default=None, help="eve.json for Suricata FPR (benign mode)")
    p.add_argument("--attacker-ip", dest="attacker_ip", default=None)
    p.add_argument("--target-ip", dest="target_ip", default=None)
    # latency
    p.add_argument("--flows", default=None, help="flow CSV to drive latency bench")
    p.add_argument("--n", type=int, default=2000)
    p.add_argument("--llm-calls", dest="llm_calls", type=int, default=20)
    return p


def main():
    args = build_parser().parse_args()
    dispatch = {
        "offline": run_offline,
        "realtime": run_realtime,
        "benign-fpr": run_benign_fpr,
        "latency": run_latency,
        "prompt-dump": run_prompt_dump,
        "llm-audit": run_llm_audit,
    }
    dispatch[args.mode](args)


if __name__ == "__main__":
    main()
