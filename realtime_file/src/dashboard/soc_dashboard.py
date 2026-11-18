"""
src/dashboard/soc_dashboard.py
================================
SOC dashboard — reads the unified_alerts.jsonl produced by the unified
pipeline and renders a live console summary or a static report.

Also provides push_to_evebox() to forward high-severity alerts to EveBox
via its HTTP API (if configured).

Usage
-----
# Show live summary of latest alerts
dashboard = SOCDashboard(cfg)
dashboard.show_summary("data/results/unified_alerts.jsonl")

# Watch for new alerts (like tail -f)
dashboard.watch("data/results/unified_alerts.jsonl")

# Push one alert to EveBox
dashboard.push_to_evebox(alert_dict)
"""

import json
import os
import time
from datetime import datetime
from typing import List, Optional

from src.utils.logger import get_logger

log = get_logger(__name__)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False


def _c(text: str, colour: str) -> str:
    if not _COLOR:
        return text
    m = {
        "red":    Fore.RED,
        "yellow": Fore.YELLOW,
        "green":  Fore.GREEN,
        "cyan":   Fore.CYAN,
        "white":  Fore.WHITE,
        "bold":   Style.BRIGHT,
        "dim":    Style.DIM,
    }
    return m.get(colour, "") + str(text) + Style.RESET_ALL


SEVERITY_COLOR = {
    "HIGH":   "red",
    "MEDIUM": "yellow",
    "LOW":    "cyan",
    "NONE":   "dim",
}

VERDICT_ICON = {
    "attack":     "🔴",
    "suspicious": "🟡",
    "benign":     "🟢",
    "error":      "⚠️ ",
}


class SOCDashboard:
    """
    Reads unified_alerts.jsonl and presents a SOC-friendly view.

    Parameters
    ----------
    cfg : Config from load_config()
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.evebox_url = getattr(cfg.live, "webhook_url", "")

    # ── public ────────────────────────────────────────────────────────────────

    def show_summary(
        self,
        alerts_jsonl: Optional[str] = None,
        top_n: int = 30,
        min_severity: str = "LOW",
    ) -> None:
        """
        Print a formatted table of the latest unified alerts.

        Parameters
        ----------
        alerts_jsonl  : path to unified_alerts.jsonl
        top_n         : show the last N alerts
        min_severity  : filter out below this severity (NONE|LOW|MEDIUM|HIGH)
        """
        alerts_jsonl = alerts_jsonl or os.path.join(
            self.cfg.paths.results_dir, "unified_alerts.jsonl"
        )
        alerts = self._load_alerts(alerts_jsonl)

        sev_order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        min_sev   = sev_order.get(min_severity, 0)
        alerts    = [a for a in alerts if sev_order.get(a.get("severity", "NONE"), 0) >= min_sev]
        alerts    = alerts[-top_n:]

        print(_c("\n" + "═"*80, "bold"))
        print(_c("  SOC DASHBOARD — UNIFIED NIDS ALERTS", "bold"))
        print(_c(f"  Source: {alerts_jsonl}", "dim"))
        print(_c("═"*80, "bold"))

        if not alerts:
            print("  No alerts found matching criteria.\n")
            return

        # Header row
        print(
            f"  {'#':>4}  {'Time':<10}  {'Sev':<8}  {'Verdict':<12}  "
            f"{'Attack type':<28}  {'R1':<10}  {'R3':<10}  {'Conf':>5}  {'⚠'}"
        )
        print("  " + "─"*78)

        n_high = n_med = n_conflict = 0
        for idx, a in enumerate(alerts, 1):
            sev     = a.get("severity", "NONE")
            verdict = a.get("final_verdict", "?")
            atype   = a.get("attack_type", "Unknown")[:27]
            r1      = a.get("role1_verdict", "—")[:9]
            r3      = a.get("role3_verdict", "—")[:9]
            conf    = a.get("confidence", 0)
            conflict= "⚠" if a.get("conflict") else ""
            ts_raw  = a.get("timestamp", "")[:19].replace("T", " ")
            icon    = VERDICT_ICON.get(verdict, "?")
            colour  = SEVERITY_COLOR.get(sev, "white")

            row = (
                f"  {idx:>4}  {ts_raw:<10}  "
                + _c(f"{sev:<8}", colour)
                + f"  {icon} {verdict:<10}  {atype:<28}  "
                f"{r1:<10}  {r3:<10}  {conf:>4}%  {conflict}"
            )
            print(row)

            if sev == "HIGH":   n_high += 1
            if sev == "MEDIUM": n_med  += 1
            if conflict:        n_conflict += 1

        print("  " + "─"*78)
        print(
            f"\n  Showing {len(alerts)} alerts  |  "
            + _c(f"HIGH: {n_high}", "red") + "  "
            + _c(f"MEDIUM: {n_med}", "yellow") + f"  "
            + f"Conflicts: {n_conflict}"
        )
        print(_c("═"*80 + "\n", "bold"))

    def show_detail(self, alerts_jsonl: str, index: int) -> None:
        """
        Print full detail for one alert by its row index (1-based).

        Parameters
        ----------
        alerts_jsonl : str  — path to jsonl file
        index        : int  — 1-based row number from show_summary()
        """
        alerts = self._load_alerts(alerts_jsonl)
        if index < 1 or index > len(alerts):
            print(f"  Index {index} out of range (1–{len(alerts)})")
            return

        a = alerts[index - 1]
        sev    = a.get("severity", "NONE")
        colour = SEVERITY_COLOR.get(sev, "white")

        print(_c("\n" + "═"*70, "bold"))
        print(_c(f"  ALERT DETAIL — #{index}", "bold"))
        print(_c("═"*70, "bold"))

        def row(label, value, col=None):
            v = _c(str(value), col) if col else str(value)
            print(f"  {label:<26}: {v}")

        row("Timestamp",        a.get("timestamp", "")[:19].replace("T", " "))
        row("Severity",         sev, colour)
        row("Final verdict",    a.get("final_verdict", "?"))
        row("Attack type",      a.get("attack_type", "?"))
        row("Confidence",       f"{a.get('confidence', 0)}%")
        row("Conflict",         "YES ⚠" if a.get("conflict") else "No",
            "yellow" if a.get("conflict") else None)
        row("Roles agree",      "Yes" if a.get("agree") else "No")
        print()
        row("Role 1 verdict",   f"{a.get('role1_verdict','—')}  "
                                f"(type={a.get('role1_attack_type','?')}  "
                                f"conf={a.get('role1_confidence',0):.0f}%)")
        row("Role 3 verdict",   f"{a.get('role3_verdict','—')}  "
                                f"(type={a.get('role3_attack_type','?')}  "
                                f"conf={a.get('role3_confidence',0)}%)")
        print()
        row("SHAP top features", ", ".join(a.get("shap_top_features", [])[:5]))
        print()
        print(_c("  SOC Explanation:", "bold"))
        expl = a.get("soc_explanation", "")
        words, line = expl.split(), "  "
        for w in words:
            if len(line) + len(w) + 1 > 70:
                print(line); line = "  " + w + " "
            else: line += w + " "
        if line.strip(): print(line)
        print()
        print(_c("  Recommended action:", "bold"))
        print(f"  {a.get('recommended_action', '')}")
        print()
        if a.get("role3_explanation"):
            print(_c("  Role 3 (log analyst) explanation:", "bold"))
            print(f"  {a['role3_explanation']}")
        print(_c("═"*70 + "\n", "bold"))

    def watch(
        self,
        alerts_jsonl: Optional[str] = None,
        poll_interval: float = 2.0,
    ) -> None:
        """
        Live-tail unified_alerts.jsonl and print new alerts as they arrive.
        Blocks until Ctrl-C.

        Parameters
        ----------
        alerts_jsonl   : path to jsonl file
        poll_interval  : seconds between file polls
        """
        import signal, sys

        alerts_jsonl = alerts_jsonl or os.path.join(
            self.cfg.paths.results_dir, "unified_alerts.jsonl"
        )

        print(_c("\n  Watching unified alerts ...", "cyan"))
        print(_c(f"  File: {alerts_jsonl}", "dim"))
        print(_c("  Ctrl-C to stop\n", "dim"))

        def handler(sig, frame):
            print(_c("\n  Stopped.", "yellow"))
            sys.exit(0)
        signal.signal(signal.SIGINT, handler)

        pos = 0
        while True:
            try:
                if os.path.exists(alerts_jsonl):
                    with open(alerts_jsonl) as fh:
                        fh.seek(pos)
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                a = json.loads(line)
                                self._print_live_alert(a)
                            except json.JSONDecodeError:
                                pass
                        pos = fh.tell()
            except Exception as exc:
                log.debug("Watch error: %s", exc)
            time.sleep(poll_interval)

    def generate_html_report(
        self,
        alerts_jsonl: Optional[str] = None,
        out_path: Optional[str] = None,
    ) -> str:
        """
        Generate a standalone HTML report from unified_alerts.jsonl.

        Parameters
        ----------
        alerts_jsonl : str  — path to jsonl
        out_path     : str  — where to save the HTML (default: results_dir)

        Returns
        -------
        str — path to the generated HTML file
        """
        alerts_jsonl = alerts_jsonl or os.path.join(
            self.cfg.paths.results_dir, "unified_alerts.jsonl"
        )
        out_path = out_path or os.path.join(
            self.cfg.paths.results_dir,
            f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
        )
        alerts = self._load_alerts(alerts_jsonl)

        sev_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for a in alerts:
            sev_count[a.get("severity", "NONE")] = sev_count.get(a.get("severity","NONE"), 0) + 1

        rows_html = ""
        for i, a in enumerate(reversed(alerts[-200:]), 1):
            sev    = a.get("severity", "NONE")
            badge  = {"HIGH": "danger", "MEDIUM": "warning", "LOW": "info", "NONE": "secondary"}.get(sev, "secondary")
            conf   = a.get("confidence", 0)
            ts     = a.get("timestamp", "")[:19].replace("T", " ")
            rows_html += f"""
            <tr class="{'table-danger' if sev=='HIGH' else 'table-warning' if sev=='MEDIUM' else ''}">
              <td>{i}</td>
              <td>{ts}</td>
              <td><span class="badge bg-{badge}">{sev}</span></td>
              <td>{a.get('final_verdict','?')}</td>
              <td>{a.get('attack_type','?')}</td>
              <td>{a.get('role1_verdict','—')}</td>
              <td>{a.get('role3_verdict','—')}</td>
              <td>{conf}%</td>
              <td>{'⚠' if a.get('conflict') else ''}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NIDS Unified Alert Report</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="p-4">
<h1>NIDS Unified Alert Report</h1>
<p class="text-muted">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
   &nbsp;|&nbsp; Source: {alerts_jsonl}</p>
<div class="row mb-4">
  <div class="col-md-3"><div class="card text-bg-danger"><div class="card-body">
    <h5>HIGH</h5><h2>{sev_count.get('HIGH',0)}</h2></div></div></div>
  <div class="col-md-3"><div class="card text-bg-warning"><div class="card-body">
    <h5>MEDIUM</h5><h2>{sev_count.get('MEDIUM',0)}</h2></div></div></div>
  <div class="col-md-3"><div class="card text-bg-info"><div class="card-body">
    <h5>LOW</h5><h2>{sev_count.get('LOW',0)}</h2></div></div></div>
  <div class="col-md-3"><div class="card text-bg-light"><div class="card-body">
    <h5>Total</h5><h2>{len(alerts)}</h2></div></div></div>
</div>
<table class="table table-sm table-hover table-bordered">
<thead class="table-dark">
  <tr><th>#</th><th>Time</th><th>Severity</th><th>Verdict</th>
      <th>Attack type</th><th>Role 1</th><th>Role 3</th><th>Conf</th><th>Conflict</th></tr>
</thead>
<tbody>{rows_html}</tbody>
</table>
</body></html>"""

        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"  ✓ HTML report saved → {out_path}")
        return out_path

    def push_to_evebox(self, alert: dict) -> bool:
        """
        POST a unified alert to EveBox HTTP API as an eve.json-compatible event.
        Only called for HIGH/MEDIUM severity.

        Parameters
        ----------
        alert : dict — alert.to_dict() from UnifiedAlert

        Returns
        -------
        bool — True if successfully posted
        """
        if not self.evebox_url:
            return False
        try:
            import requests
            eve_event = {
                "timestamp":  alert.get("timestamp", ""),
                "event_type": "unified_nids_alert",
                "alert": {
                    "action":    "allowed",
                    "gid":       1,
                    "signature_id": 9999001,
                    "signature": (
                        f"NIDS-UNIFIED: {alert.get('attack_type','?')} "
                        f"[severity={alert.get('severity','?')}]"
                    ),
                    "category":    alert.get("attack_type", "Unknown"),
                    "severity":    1 if alert.get("severity") == "HIGH" else 2,
                },
                "nids_unified": alert,
            }
            r = requests.post(self.evebox_url, json=eve_event, timeout=5)
            return r.status_code < 300
        except Exception as exc:
            log.warning("EveBox push failed: %s", exc)
            return False

    # ── internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _load_alerts(path: str) -> List[dict]:
        if not os.path.exists(path):
            return []
        alerts = []
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return alerts

    def _print_live_alert(self, a: dict) -> None:
        sev    = a.get("severity", "NONE")
        colour = SEVERITY_COLOR.get(sev, "white")
        if sev == "NONE":
            return
        icon   = VERDICT_ICON.get(a.get("final_verdict", "?"), "?")
        ts     = a.get("timestamp", "")[:19].replace("T", " ")
        print(
            f"\n  {icon}  [{ts}]  "
            + _c(f"{sev}", colour)
            + f"  │  {a.get('attack_type','?')}"
            + f"  │  conf={a.get('confidence',0)}%"
            + (f"  │  ⚠ CONFLICT" if a.get("conflict") else "")
        )
        expl = a.get("soc_explanation", "")
        if expl:
            print(f"  {expl[:110]}")
        action = a.get("recommended_action", "")
        if action:
            print(_c(f"  → {action}", "cyan"))
