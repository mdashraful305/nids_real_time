"""
src/live/fast_pcap_extractor.py
===============================
Fast dpkt-based CICIDS2017-aligned bidirectional flow extractor for closed
5-second PCAP segments emitted by dumpcap.

Why this exists (measured on this host vs NFStream):
  - NFStream on a 27 MB SYN-flood PCAP batch took ~200 s sequentially, causing
    >100 s capture-to-verdict backlog; dpkt parses 444k packets in ~4.5 s.
  - NFStream cannot expose Init_Win_bytes_forward / Init_Win_bytes_backward
    (zero-filling pushed attacker SHAP toward Benign by +0.573 on average) and
    conflated min_seg_size_forward with total IP packet length (60 B vs 20 B)
    and packet payload lengths with wire lengths.
  - Exposes the full NFStream attribute interface expected by nids_web.py PLUS
    tcp header sizes, Init_Win_bytes_{forward,backward}, payload-only size stats,
    act_data_pkt_fwd, and per-flow HTTP request counts.
"""

from dataclasses import dataclass, field
from typing import List
import os
import socket

import dpkt
import numpy as np


_HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC")
_WELL_KNOWN_APPS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "TLS", 445: "SMB", 546: "DHCPv6", 547: "DHCPv6", 1900: "SSDP",
    3306: "MySQL", 3389: "RDP", 5353: "mDNS", 5432: "PostgreSQL", 8080: "HTTP",
}


@dataclass
class ExtractedFlow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    ip_version: int
    application_name: str
    bidirectional_first_seen_ms: int
    bidirectional_last_seen_ms: int
    bidirectional_duration_ms: float
    bidirectional_packets: int
    bidirectional_bytes: int
    src2dst_packets: int
    src2dst_bytes: int
    dst2src_packets: int
    dst2src_bytes: int
    src2dst_max_ps: float
    src2dst_min_ps: float
    src2dst_mean_ps: float
    src2dst_stddev_ps: float
    dst2src_max_ps: float
    dst2src_min_ps: float
    dst2src_mean_ps: float
    bidirectional_min_ps: float
    bidirectional_max_ps: float
    bidirectional_mean_ps: float
    bidirectional_stddev_ps: float
    bidirectional_mean_piat_ms: float
    bidirectional_stddev_piat_ms: float
    bidirectional_max_piat_ms: float
    bidirectional_min_piat_ms: float
    src2dst_mean_piat_ms: float
    src2dst_stddev_piat_ms: float
    src2dst_min_piat_ms: float
    dst2src_duration_ms: float
    dst2src_mean_piat_ms: float
    dst2src_stddev_piat_ms: float
    dst2src_max_piat_ms: float
    dst2src_min_piat_ms: float
    src2dst_psh_packets: int
    src2dst_urg_packets: int
    bidirectional_fin_packets: int
    bidirectional_syn_packets: int
    bidirectional_rst_packets: int
    bidirectional_psh_packets: int
    bidirectional_ack_packets: int
    bidirectional_urg_packets: int
    bidirectional_cwr_packets: int
    # Packet-header CICIDS2017 extensions
    fwd_header_bytes: int
    init_win_bytes_fwd: int
    init_win_bytes_bwd: int
    act_data_pkt_fwd: int
    min_seg_size_fwd: int
    http_requests: int


def _open_pcap_reader(path: str):
    fh = open(path, "rb")
    magic = fh.read(4)
    fh.seek(0)
    if magic in (b"\x0a\x0d\x0d\x0a",):
        return fh, dpkt.pcapng.Reader(fh)
    return fh, dpkt.pcap.Reader(fh)


def _guess_app(proto: int, sport: int, dport: int, http_reqs: int, pay_bytes: int) -> str:
    if http_reqs > 0:
        return "HTTP"
    if proto == 1:
        return "ICMP"
    if proto == 58:
        return "ICMPv6"
    if proto == 2:
        return "IGMP"
    for p in (dport, sport):
        if p in (80, 443, 8000, 8080) and pay_bytes == 0:
            continue
        if p in _WELL_KNOWN_APPS:
            return _WELL_KNOWN_APPS[p]
    return {6: "TCP", 17: "UDP"}.get(proto, f"IP/{proto}")


def _decode_packet(buf: bytes):
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None
    l3 = eth.data
    if isinstance(l3, dpkt.ip.IP):
        ip_ver = 4
        src_ip = socket.inet_ntoa(l3.src)
        dst_ip = socket.inet_ntoa(l3.dst)
        proto = int(l3.p)
        ip_hdr = int(l3.hl) * 4
        ip_total = int(l3.len)
        l4 = l3.data
    elif isinstance(l3, dpkt.ip6.IP6):
        ip_ver = 6
        src_ip = socket.inet_ntop(socket.AF_INET6, l3.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, l3.dst)
        proto = int(l3.nxt)
        ip_hdr = 40
        ip_total = 40 + int(l3.plen)
        l4 = l3.data
    else:
        return None

    sport = dport = hdr_len = pay_len = flags = 0
    win = -1
    http_hit = 0
    if proto == 6 and isinstance(l4, dpkt.tcp.TCP):
        sport, dport = int(l4.sport), int(l4.dport)
        hdr_len = int(l4.off) * 4
        pay_len = max(0, ip_total - ip_hdr - hdr_len)
        flags = int(l4.flags)
        win = int(l4.win)
        if pay_len > 0 and dport in (80, 8000, 8080, 443):
            payload_head = bytes(l4.data[:6])
            if payload_head[:4] in _HTTP_METHODS or payload_head.startswith(b"DELETE"):
                http_hit = 1
    elif proto == 17 and isinstance(l4, dpkt.udp.UDP):
        sport, dport = int(l4.sport), int(l4.dport)
        hdr_len = 8
        pay_len = max(0, int(l4.ulen) - 8)
    else:
        pay_len = max(0, ip_total - ip_hdr)

    return src_ip, sport, dst_ip, dport, proto, ip_ver, hdr_len, pay_len, flags, win, http_hit


def extract_flows_from_pcap(
    pcap_path: str,
    idle_timeout_s: float = 5.0,
    active_timeout_s: float = 120.0,
) -> List[ExtractedFlow]:
    """Extract CICIDS2017-aligned flows from a closed PCAP/PCAPNG file."""
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) <= 24:
        return []

    active = {}
    completed = []
    idle_us = idle_timeout_s * 1e6
    active_us = active_timeout_s * 1e6

    fh, reader = _open_pcap_reader(pcap_path)
    try:
        for ts, buf in reader:
            pkt = _decode_packet(buf)
            if pkt is None:
                continue
            src_ip, sport, dst_ip, dport, proto, ip_ver, hdr_len, pay_len, flags, win, http_hit = pkt
            ts_us = float(ts) * 1e6
            ep_a = (src_ip, sport)
            ep_b = (dst_ip, dport)
            fkey = (ep_a, ep_b, proto) if ep_a <= ep_b else (ep_b, ep_a, proto)

            st = active.get(fkey)
            if st is not None:
                if (ts_us - st["last_us"] > idle_us) or (ts_us - st["first_us"] > active_us):
                    completed.append(st)
                    st = None

            if st is None:
                st = {
                    "src_ip": src_ip, "src_port": sport,
                    "dst_ip": dst_ip, "dst_port": dport,
                    "protocol": proto, "ip_version": ip_ver,
                    "first_us": ts_us, "last_us": ts_us,
                    "fwd_ts": [], "bwd_ts": [], "all_ts": [],
                    "fwd_lens": [], "bwd_lens": [], "all_lens": [],
                    "fwd_hdr": 0, "min_seg_fwd": None,
                    "win_fwd": -1, "win_bwd": -1,
                    "fwd_psh": 0, "fwd_urg": 0,
                    "fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 0, "urg": 0, "cwr": 0,
                    "act_data_fwd": 0, "http_reqs": 0,
                }
                active[fkey] = st

            is_fwd = (src_ip == st["src_ip"] and sport == st["src_port"])
            st["last_us"] = max(st["last_us"], ts_us)
            st["all_ts"].append(ts_us)
            st["all_lens"].append(pay_len)
            st["http_reqs"] += http_hit

            if proto == 6:
                if flags & dpkt.tcp.TH_FIN: st["fin"] += 1
                if flags & dpkt.tcp.TH_SYN: st["syn"] += 1
                if flags & dpkt.tcp.TH_RST: st["rst"] += 1
                if flags & dpkt.tcp.TH_PUSH: st["psh"] += 1
                if flags & dpkt.tcp.TH_ACK: st["ack"] += 1
                if flags & dpkt.tcp.TH_URG: st["urg"] += 1
                if flags & dpkt.tcp.TH_CWR: st["cwr"] += 1

            if is_fwd:
                st["fwd_ts"].append(ts_us)
                st["fwd_lens"].append(pay_len)
                st["fwd_hdr"] += hdr_len
                if hdr_len > 0:
                    st["min_seg_fwd"] = hdr_len if st["min_seg_fwd"] is None else min(st["min_seg_fwd"], hdr_len)
                if st["win_fwd"] == -1 and win >= 0:
                    st["win_fwd"] = win
                if pay_len > 0:
                    st["act_data_fwd"] += 1
                if proto == 6 and (flags & dpkt.tcp.TH_PUSH):
                    st["fwd_psh"] += 1
                if proto == 6 and (flags & dpkt.tcp.TH_URG):
                    st["fwd_urg"] += 1
            else:
                st["bwd_ts"].append(ts_us)
                st["bwd_lens"].append(pay_len)
                if st["win_bwd"] == -1 and win >= 0:
                    st["win_bwd"] = win
    finally:
        fh.close()

    completed.extend(active.values())
    out: List[ExtractedFlow] = []
    for st in completed:
        dur_us = max(0.0, st["last_us"] - st["first_us"])
        dur_ms = dur_us / 1000.0
        fl = np.asarray(st["fwd_lens"], dtype=float)
        bl = np.asarray(st["bwd_lens"], dtype=float) if st["bwd_lens"] else None
        al = np.asarray(st["all_lens"], dtype=float)

        all_ts_s = sorted(st["all_ts"])
        fwd_ts_s = sorted(st["fwd_ts"])
        bwd_ts_s = sorted(st["bwd_ts"])
        all_iat_ms = np.diff(all_ts_s) / 1000.0 if len(all_ts_s) > 1 else None
        fwd_iat_ms = np.diff(fwd_ts_s) / 1000.0 if len(fwd_ts_s) > 1 else None
        bwd_iat_ms = np.diff(bwd_ts_s) / 1000.0 if len(bwd_ts_s) > 1 else None
        bwd_dur_ms = ((bwd_ts_s[-1] - bwd_ts_s[0]) / 1000.0) if len(bwd_ts_s) > 1 else 0.0

        n_fwd = len(fl)
        n_bwd = len(bl) if bl is not None else 0
        n_all = len(al)
        tot_f = int(fl.sum())
        tot_b = int(bl.sum()) if bl is not None else 0

        out.append(ExtractedFlow(
            src_ip=st["src_ip"], src_port=st["src_port"],
            dst_ip=st["dst_ip"], dst_port=st["dst_port"],
            protocol=st["protocol"], ip_version=st["ip_version"],
            application_name=_guess_app(st["protocol"], st["src_port"], st["dst_port"], st["http_reqs"], tot_f + tot_b),
            bidirectional_first_seen_ms=int(round(st["first_us"] / 1000.0)),
            bidirectional_last_seen_ms=int(round(st["last_us"] / 1000.0)),
            bidirectional_duration_ms=round(dur_ms, 3),
            bidirectional_packets=n_all,
            bidirectional_bytes=tot_f + tot_b,
            src2dst_packets=n_fwd,
            src2dst_bytes=tot_f,
            dst2src_packets=n_bwd,
            dst2src_bytes=tot_b,
            src2dst_max_ps=float(fl.max()),
            src2dst_min_ps=float(fl.min()),
            src2dst_mean_ps=float(fl.mean()),
            src2dst_stddev_ps=float(fl.std(ddof=1)) if n_fwd > 1 else 0.0,
            dst2src_max_ps=float(bl.max()) if n_bwd else 0.0,
            dst2src_min_ps=float(bl.min()) if n_bwd else 0.0,
            dst2src_mean_ps=float(bl.mean()) if n_bwd else 0.0,
            bidirectional_min_ps=float(al.min()),
            bidirectional_max_ps=float(al.max()),
            bidirectional_mean_ps=float(al.mean()),
            bidirectional_stddev_ps=float(al.std(ddof=1)) if n_all > 1 else 0.0,
            bidirectional_mean_piat_ms=float(all_iat_ms.mean()) if all_iat_ms is not None else 0.0,
            bidirectional_stddev_piat_ms=float(all_iat_ms.std(ddof=1)) if all_iat_ms is not None and len(all_iat_ms) > 1 else 0.0,
            bidirectional_max_piat_ms=float(all_iat_ms.max()) if all_iat_ms is not None else 0.0,
            bidirectional_min_piat_ms=float(all_iat_ms.min()) if all_iat_ms is not None else 0.0,
            src2dst_mean_piat_ms=float(fwd_iat_ms.mean()) if fwd_iat_ms is not None else 0.0,
            src2dst_stddev_piat_ms=float(fwd_iat_ms.std(ddof=1)) if fwd_iat_ms is not None and len(fwd_iat_ms) > 1 else 0.0,
            src2dst_min_piat_ms=float(fwd_iat_ms.min()) if fwd_iat_ms is not None else 0.0,
            dst2src_duration_ms=round(bwd_dur_ms, 3),
            dst2src_mean_piat_ms=float(bwd_iat_ms.mean()) if bwd_iat_ms is not None else 0.0,
            dst2src_stddev_piat_ms=float(bwd_iat_ms.std(ddof=1)) if bwd_iat_ms is not None and len(bwd_iat_ms) > 1 else 0.0,
            dst2src_max_piat_ms=float(bwd_iat_ms.max()) if bwd_iat_ms is not None else 0.0,
            dst2src_min_piat_ms=float(bwd_iat_ms.min()) if bwd_iat_ms is not None else 0.0,
            src2dst_psh_packets=st["fwd_psh"],
            src2dst_urg_packets=st["fwd_urg"],
            bidirectional_fin_packets=st["fin"],
            bidirectional_syn_packets=st["syn"],
            bidirectional_rst_packets=st["rst"],
            bidirectional_psh_packets=st["psh"],
            bidirectional_ack_packets=st["ack"],
            bidirectional_urg_packets=st["urg"],
            bidirectional_cwr_packets=st["cwr"],
            fwd_header_bytes=st["fwd_hdr"],
            init_win_bytes_fwd=st["win_fwd"],
            init_win_bytes_bwd=st["win_bwd"],
            act_data_pkt_fwd=st["act_data_fwd"],
            min_seg_size_fwd=st["min_seg_fwd"] if st["min_seg_fwd"] is not None else 0,
            http_requests=st["http_reqs"],
        ))
    return out
