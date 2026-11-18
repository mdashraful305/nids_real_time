"""
src/live/behavioral_guard.py
============================
Shared Role-1 stateful protocol/behavioral detector + Role-3 canonical verdict
normalizer used identically across Approach A (nids_web.py) and Approach B
(src/pipeline/unified_pipeline.py).

Design guarantees:
  1. Uses packet capture timestamps (not wall-clock `time.time()`) so processing
     backlog during floods never artificially resets 10s counters and drops bursts.
  2. O(1) amortized sliding-window eviction via per-source deque + running counters.
  3. Zero hardcoded IP addresses — operates purely on flow tuple behavior and
     standard protocol ports / TCP flags / HTTP request counts.
"""

from collections import Counter, defaultdict, deque
import ipaddress
from typing import Any, Dict, Optional, Tuple


AUTH_PORTS = frozenset({21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900})
WEB_PORTS = frozenset({80, 443, 8000, 8080, 8081, 8443, 8888})
LAN_CONTROL_PORTS = frozenset({67, 68, 123, 546, 547, 1900, 5353, 5355})

_VERDICT_ATTACK_ALIASES = {
    "attack": None,
    "malicious": None,
    "threat": None,
    "intrusion": None,
    "dos": "DoS",
    "ddos": "DDoS",
    "flood": "DoS",
    "portscan": "PortScan",
    "port scan": "PortScan",
    "port_scan": "PortScan",
    "scan": "PortScan",
    "brute force": "Brute Force",
    "brute_force": "Brute Force",
    "bruteforce": "Brute Force",
    "web attack": "Web Attack",
    "web_attack": "Web Attack",
    "bot": "Bot",
    "infiltration": "Infiltration",
    "heartbleed": "Heartbleed",
    "exploits": "Exploits",
    "fuzzers": "Fuzzers",
    "reconnaissance": "Reconnaissance",
    "analysis": "Analysis",
    "shellcode": "Shellcode",
}
_VERDICT_SUSPICIOUS_ALIASES = {"suspicious", "anomaly", "anomalous", "warning", "alert", "uncertain"}
_VERDICT_BENIGN_ALIASES = {"benign", "normal", "safe", "clean", "legitimate", "ok"}


def normalize_llm_verdict(raw_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Normalize LLM JSON verdict fields to canonical {attack, suspicious, benign, error}.
    Preserves `raw_verdict` for transparency and fills `attack_type` when an
    LLM places the attack class name inside the `verdict` key (e.g. `"verdict": "DoS"`)."""
    if raw_obj is None or not isinstance(raw_obj, dict):
        return raw_obj

    v_raw = str(raw_obj.get("verdict", "unknown")).strip()
    v_low = v_raw.lower()
    raw_obj.setdefault("raw_verdict", v_low)

    atype = str(raw_obj.get("attack_type") or "Unknown").strip() or "Unknown"

    if v_low in _VERDICT_ATTACK_ALIASES:
        inferred = _VERDICT_ATTACK_ALIASES[v_low]
        raw_obj["verdict"] = "attack"
        if inferred and atype.lower() in ("unknown", "normal", "none", "benign", ""):
            raw_obj["attack_type"] = inferred
    elif v_low in _VERDICT_SUSPICIOUS_ALIASES:
        raw_obj["verdict"] = "suspicious"
    elif v_low in _VERDICT_BENIGN_ALIASES:
        raw_obj["verdict"] = "benign"
    elif v_low == "error":
        raw_obj["verdict"] = "error"
    else:
        # Substring fallback for messy small-LLM outputs like "attack (DoS)"
        if "attack" in v_low or "dos" in v_low or "scan" in v_low or "brute" in v_low or "flood" in v_low:
            raw_obj["verdict"] = "attack"
        elif "benign" in v_low or "normal" in v_low:
            raw_obj["verdict"] = "benign"
        else:
            raw_obj["verdict"] = v_low

    return raw_obj


def is_attack_verdict(verdict_str: Optional[str]) -> bool:
    if not verdict_str:
        return False
    low = str(verdict_str).strip().lower()
    if low in ("attack", "suspicious"):
        return True
    return low in _VERDICT_ATTACK_ALIASES or low in _VERDICT_SUSPICIOUS_ALIASES


def is_multicast_or_control(src_ip: str, dst_ip: str, dst_port: int, protocol: Any) -> bool:
    """Return True for routine LAN discovery/control traffic (mDNS/SSDP/IGMP/ICMP/DHCP/NTP)."""
    p_str = str(protocol).strip().upper()
    if p_str in ("1", "2", "58", "ICMP", "ICMPV6", "IGMP"):
        return True
    if int(dst_port or 0) in LAN_CONTROL_PORTS:
        return True
    for ip_s in (dst_ip, src_ip):
        if not ip_s:
            continue
        try:
            addr = ipaddress.ip_address(ip_s)
            if addr.is_multicast or addr.is_unspecified or ip_s == "255.255.255.255":
                return True
        except ValueError:
            pass
    return False


class StatefulBehavioralDetector:
    """Capture-timestamp sliding-window behavioral detector for streaming flows."""

    def __init__(self, window_sec: float = 15.0, web_window_sec: float = 30.0):
        self.window_sec = float(window_sec)
        self.web_window_sec = float(web_window_sec)
        self._ip_windows: Dict[str, dict] = {}
        self._web_windows: Dict[Tuple[str, str, int], dict] = {}
        self._auth_windows: Dict[Tuple[str, str, int], deque] = defaultdict(deque)
        self._last_label_until: Dict[Tuple[str, str], float] = {}

    def _get_ip_state(self, src_ip: str) -> dict:
        st = self._ip_windows.get(src_ip)
        if st is None:
            st = {
                "events": deque(),  # (ts_s, dst_port, is_half_open)
                "ports": Counter(),
                "half_open": 0,
            }
            self._ip_windows[src_ip] = st
        return st

    def _evict_ip(self, st: dict, now_s: float) -> None:
        cutoff = now_s - self.window_sec
        ev = st["events"]
        ports = st["ports"]
        while ev and ev[0][0] < cutoff:
            _, dp, ho = ev.popleft()
            ports[dp] -= 1
            if ports[dp] <= 0:
                del ports[dp]
            if ho:
                st["half_open"] -= 1

    def observe(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: Any,
        ts_s: float,
        src_port: int = 0,
        syn: int = 0,
        ack: int = 0,
        rst: int = 0,
        payload_bytes: int = 0,
        total_bytes: int = 0,
        http_requests: int = 0,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Update sliding windows with one flow and return (heuristic_label_or_None, context)."""
        dp = int(dst_port or 0)
        sp = int(src_port or 0)
        is_server_reply = (0 < sp < 1024 and dp >= 1024 and syn > 0 and ack > 0)
        is_ctrl = is_multicast_or_control(src_ip, dst_ip, dp, protocol)

        st = self._get_ip_state(src_ip)
        self._evict_ip(st, ts_s)

        if is_server_reply:
            return None, {
                "flows_15s": len(st["events"]),
                "ports_15s": len([p for p in st["ports"] if p > 0]),
                "half_open_15s": st["half_open"],
                "web_flows_30s": 0,
                "web_http_reqs_30s": 0,
                "auth_flows_30s": 0,
                "http_requests": int(http_requests or 0),
                "is_control": True,
                "is_server_reply": True,
            }

        # Half-open SYN/RST probe/flood with zero L7 payload
        is_half_open = int((syn > 0) and (ack <= 1) and (payload_bytes == 0))
        st["events"].append((ts_s, dp, is_half_open))
        st["ports"][dp] += 1
        if is_half_open:
            st["half_open"] += 1

        n_flows = len(st["events"])
        n_ports = len([p for p in st["ports"] if p > 0])
        n_half_open = st["half_open"]

        # Web sliding window per (src_ip, dst_ip, dst_port)
        web_flows = 0
        web_http_reqs = 0
        if dp in WEB_PORTS and not is_ctrl:
            wkey = (src_ip, dst_ip, dp)
            wst = self._web_windows.get(wkey)
            if wst is None:
                wst = {"events": deque(), "http_reqs": 0}
                self._web_windows[wkey] = wst
            wev = wst["events"]
            cutoff_w = ts_s - self.web_window_sec
            while wev and wev[0][0] < cutoff_w:
                _, hr = wev.popleft()
                wst["http_reqs"] -= hr
            hr_i = int(http_requests or 0)
            wev.append((ts_s, hr_i))
            wst["http_reqs"] += hr_i
            web_flows = len(wev)
            web_http_reqs = wst["http_reqs"]

        # Auth brute-force sliding window
        auth_flows = 0
        if dp in AUTH_PORTS and not is_ctrl and (syn > 0 or total_bytes > 0):
            akey = (src_ip, dst_ip, dp)
            aq = self._auth_windows[akey]
            cutoff_a = ts_s - self.web_window_sec
            while aq and aq[0] < cutoff_a:
                aq.popleft()
            aq.append(ts_s)
            auth_flows = len(aq)

        label = None
        if not is_ctrl:
            if n_ports > 20 and int(dp or 0) > 0:
                label = "PortScan (Heuristics)"
            elif dp in WEB_PORTS and ((web_flows >= 20 and web_http_reqs >= 40) or (web_flows >= 30 and payload_bytes > 0 and ack > 1 and n_half_open < 25)):
                label = "Web Attack (Heuristics)"
            elif n_flows > 100 or n_half_open >= 25:
                label = "DoS/Flood (Heuristics)"
            elif dp in AUTH_PORTS and auth_flows >= 10:
                label = "Brute Force (Heuristics)"
            else:
                # Hysteresis latch (3 s capture-time grace while ongoing burst finishes)
                for cand in ("DoS/Flood (Heuristics)", "PortScan (Heuristics)"):
                    if self._last_label_until.get((src_ip, cand), -1.0) >= ts_s:
                        # Only extend flood latch onto flows heading to a recent target or same protocol
                        if cand == "DoS/Flood (Heuristics)" and syn > 0 and payload_bytes == 0:
                            label = cand
                            break
                        if cand == "PortScan (Heuristics)" and is_half_open:
                            label = cand
                            break

        if label is not None:
            self._last_label_until[(src_ip, label)] = ts_s + 3.0

        ctx = {
            "flows_15s": n_flows,
            "ports_15s": n_ports,
            "half_open_15s": n_half_open,
            "web_flows_30s": web_flows,
            "web_http_reqs_30s": web_http_reqs,
            "auth_flows_30s": auth_flows,
            "http_requests": int(http_requests or 0),
            "is_control": is_ctrl,
        }
        return label, ctx


def detect_window_behavioral(win_flows) -> Optional[dict]:
    """Batch-window equivalent for Approach B (DataFrame of CICFlowMeter flows).
    Covers PortScan, DoS/Flood (volume or half-open SYN storm), Web Attack/Scan,
    and Brute Force without touching benign mDNS/control flows."""
    if win_flows is None or win_flows.empty:
        return None
    src_col = "Src IP" if "Src IP" in win_flows.columns else ("src_ip" if "src_ip" in win_flows.columns else None)
    dst_col = "Dst IP" if "Dst IP" in win_flows.columns else ("dst_ip" if "dst_ip" in win_flows.columns else None)
    port_col = next((c for c in ("Destination Port", "Dst Port", "dst_port") if c in win_flows.columns), None)
    if not src_col or not port_col:
        return None

    syn_col = next((c for c in ("SYN Flag Count", "syn_flag_cnt") if c in win_flows.columns), None)
    ack_col = next((c for c in ("ACK Flag Count", "ack_flag_cnt") if c in win_flows.columns), None)
    proto_col = next((c for c in ("Protocol", "protocol") if c in win_flows.columns), None)
    sport_col = next((c for c in ("Src Port", "src_port") if c in win_flows.columns), None)

    best = None  # (priority, score, src_ip, label, n_flows, n_ports, rep_row)
    for src_ip, g in win_flows.groupby(src_col):
        # Filter out pure multicast/control rows from counting as attacks
        dports = g[port_col].fillna(0).astype(int)
        if proto_col and dst_col:
            non_ctrl_mask = [
                not is_multicast_or_control(str(src_ip), str(di), int(dp), pr)
                for di, dp, pr in zip(g[dst_col], dports, g[proto_col])
            ]
            g_eff = g[non_ctrl_mask]
        else:
            g_eff = g
        if g_eff.empty:
            continue

        n_flows = len(g_eff)
        eff_ports = g_eff[port_col].fillna(0).astype(int)
        n_ports = int(eff_ports.nunique())

        # Exclude server replies originating from a well-known listening port (e.g. :80 -> many ephemeral client ports)
        # from being misclassified as a PortScan.
        scan_ports = n_ports
        if sport_col and sport_col in g_eff.columns:
            s_ports = g_eff[sport_col].fillna(0).astype(int)
            non_server_reply = g_eff[~((s_ports < 1024) & (eff_ports >= 1024))]
            scan_ports = int(non_server_reply[port_col].fillna(0).astype(int).nunique()) if not non_server_reply.empty else 0

        n_half_open = 0
        mean_ack = 0.0
        if syn_col and ack_col:
            syns = g_eff[syn_col].fillna(0)
            acks = g_eff[ack_col].fillna(0)
            n_half_open = int(((syns > 0) & (acks <= 1)).sum())
            mean_ack = float(acks.mean()) if len(acks) else 0.0

        top_dp = int(eff_ports.mode().iloc[0])
        cnt_top = int((eff_ports == top_dp).sum())

        label = None
        score = 0
        if scan_ports > 20:
            label, score = "PortScan (Heuristics)", 100000 + scan_ports
        elif top_dp in WEB_PORTS and cnt_top >= 20 and n_flows < 250 and n_half_open < (0.5 * n_flows) and mean_ack >= 1.5:
            label, score = "Web Attack (Heuristics)", 50000 + cnt_top
        elif n_flows > 100 or n_half_open >= 25:
            label, score = "DoS/Flood (Heuristics)", max(n_flows, n_half_open * 10)
        elif top_dp in WEB_PORTS and cnt_top >= 20:
            label, score = "Web Attack (Heuristics)", cnt_top
        elif top_dp in AUTH_PORTS and cnt_top >= 10:
            label, score = "Brute Force (Heuristics)", cnt_top

        if label and (best is None or score > best[0]):
            row = g_eff.iloc[0]
            best = (score, src_ip, label, n_flows, n_ports, row)

    if best is None:
        return None
    _, src_ip, label, n_flows, n_ports, row = best
    dst_ip = str(row[dst_col]) if dst_col and dst_col in row.index else None
    dport = int(row[port_col]) if port_col in row.index else None
    sport = int(row[sport_col]) if sport_col and sport_col in row.index else None
    return {
        "Predicted_Label": label,
        "Confidence": 100.0,
        "n_flows": n_flows,
        "n_attacks": n_flows,
        "attack_fraction": 1.0,
        "dataset_routed": "heuristic",
        "n_ports": n_ports,
        "src_ip": str(src_ip),
        "src_port": sport,
        "dst_ip": dst_ip,
        "dst_port": dport,
    }
