"""
src/utils/resilient_dns.py
==========================
Shared DNS-resilience helper for remote Ollama endpoints (e.g. Cloudflare
tunnels) on networks whose local stub resolver intermittently returns EAI_AGAIN
([Errno -3] Temporary failure in name resolution).

How it works:
  1. Wraps socket.getaddrinfo once per process.
  2. Every successful public lookup updates an in-memory cache (and an optional
     process-shared JSON file under logs/ollama_dns_cache.json).
  3. Only if system DNS fails with socket.gaierror, falls back to cached
     addresses (pre-loaded from disk if present) or a standard HTTPS DoH A
     query against 1.1.1.1.
"""

import json
import os
import socket
import threading

_LOCK = threading.Lock()
_CACHE = {}
_INSTALLED = False
_ORIG_GETADDRINFO = None
_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "logs",
    "ollama_dns_cache.json",
)


def _load_disk_cache():
    if not os.path.exists(_CACHE_FILE):
        return
    try:
        with open(_CACHE_FILE) as f:
            data = json.load(f)
        for host, ips in data.items():
            if isinstance(ips, list) and ips:
                _CACHE.setdefault(host, ips)
    except Exception:
        pass


def _save_disk_cache():
    try:
        os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
        tmp = _CACHE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_CACHE, f)
        os.replace(tmp, _CACHE_FILE)
    except Exception:
        pass


def _doh_lookup(host):
    """Fallback A-record lookup via Cloudflare 1.1.1.1 DNS-over-HTTPS."""
    try:
        import requests
        r = requests.get(
            "https://1.1.1.1/dns-query",
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=5,
        )
        if r.status_code == 200:
            ips = [
                ans["data"]
                for ans in r.json().get("Answer", [])
                if ans.get("type") == 1 and ans.get("data")
            ]
            if ips:
                return ips
    except Exception:
        pass
    return []


def _to_addrinfo(ips, port, type_, proto):
    socktype = type_ or socket.SOCK_STREAM
    p = proto or (socket.IPPROTO_TCP if socktype == socket.SOCK_STREAM else 0)
    pnum = int(port) if port else 0
    return [
        (socket.AF_INET, socktype, p, "", (ip, pnum))
        for ip in ips
    ]


def install_resilient_dns():
    """Install process-wide resilient getaddrinfo wrapper (idempotent)."""
    global _INSTALLED, _ORIG_GETADDRINFO
    with _LOCK:
        if _INSTALLED:
            return
        _ORIG_GETADDRINFO = socket.getaddrinfo
        _load_disk_cache()

        def _resilient_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            try:
                res = _ORIG_GETADDRINFO(host, port, family, type, proto, flags)
                if res and host and host not in ("localhost", "127.0.0.1", "::1"):
                    ips = []
                    for item in res:
                        if item[0] == socket.AF_INET and item[4]:
                            ip = item[4][0]
                            if ip not in ips:
                                ips.append(ip)
                    if ips:
                        with _LOCK:
                            if _CACHE.get(host) != ips:
                                _CACHE[host] = ips
                                _save_disk_cache()
                return res
            except socket.gaierror:
                if not host or host in ("localhost", "127.0.0.1", "::1"):
                    raise
                with _LOCK:
                    ips = list(_CACHE.get(host, []))
                if not ips:
                    ips = _doh_lookup(host)
                    if ips:
                        with _LOCK:
                            _CACHE[host] = ips
                            _save_disk_cache()
                if ips:
                    return _to_addrinfo(ips, port, type, proto)
                raise

        socket.getaddrinfo = _resilient_getaddrinfo
        _INSTALLED = True
