"""
src/utils/capture_filter.py
============================
Builds a BPF filter (same syntax for tcpdump and NFStream's bpf_filter) that
excludes a live NIDS pipeline's own traffic from capture: loopback (dashboard
access, local tooling), this host's own WAN-bound traffic (Ollama calls —
local or remote — DNS lookups, and any other outbound internet chatter), and
the dashboard's own port.

Without this, a live capture on the same box that also runs its own
dashboard or LLM calls sees that traffic mixed into the flow data being
analysed — e.g. a browser polling the dashboard from an otherwise-attacking
IP can dominate that source's flow count and skew both the ML input and the
cross-flow heuristics.

Why subnet-based, not a resolved IP: a Cloudflare-tunnelled Ollama endpoint
(see COLAB_SETUP.md's "Bonus" section) doesn't have one stable IP — it's
served from a rotating pool of Cloudflare edge nodes, so resolving the
hostname once and excluding that single address only catches some of the
traffic; a later request can land on a different edge IP and show up as an
unrelated-looking flow (typically to a `34.x`/`104.x`/etc. IP on port 443,
often getting a plausible-looking-but-wrong attack label from Role 3, since
that window's context genuinely doesn't look like anything in particular).
Excluding by "traffic between this host and anything outside its own LAN"
instead is stable regardless of which edge IP a given request lands on, and
is safe for this project's attacker-on-the-LAN test setup specifically: the
attacker's traffic is always LAN-to-LAN with the target, and only this
pipeline's own infrastructure calls (Ollama, DNS, OS/package updates, etc.)
go out to the WAN.

Shared by nids_web.py (passed directly to NFStreamer) and
scripts/print_capture_filter.py (printed for use in a tcpdump command line).
"""

import ipaddress
import socket
import subprocess
import sys
from urllib.parse import urlparse


def get_own_network():
    """
    Returns (own_ip, own_network) for the interface currently used for
    outbound traffic, e.g. ("192.168.1.169", "192.168.1.0/24") — used to
    tell "this host's own WAN calls" (always noise here) apart from "LAN
    traffic with a potential attacker" (always kept). own_network is None
    if it can't be determined (own_ip may still be set); callers should
    fall back to host-specific exclusion in that case.
    """
    own_ip = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            own_ip = s.getsockname()[0]
    except OSError:
        return None, None

    try:
        out = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            for i, tok in enumerate(parts):
                if tok == "inet" and i + 1 < len(parts):
                    cidr = parts[i + 1]
                    if cidr.startswith(own_ip + "/"):
                        net = ipaddress.ip_network(cidr, strict=False)
                        return own_ip, str(net)
    except Exception:
        pass
    return own_ip, None


def build_self_exclusion_bpf(dashboard_port, ollama_url, extra_excludes=None):
    """
    Returns a BPF filter string excluding:
      - 127.0.0.1 (loopback — local dashboard access, local tooling)
      - the dashboard's own port
      - this host's own WAN-bound traffic (Ollama — local or remote via a
        rotating-IP tunnel, DNS, anything else outbound to the internet),
        by subnet if this host's own LAN network could be determined,
        else by the Ollama host's resolved IP specifically as a fallback
      - any extra "host X" / "port N" clauses passed in

    extra_excludes: iterable of extra BPF clauses to OR in
    (e.g. "host 192.168.1.50" for a known monitoring box).
    """
    clauses = ["host 127.0.0.1"]
    if dashboard_port:
        clauses.append(f"port {dashboard_port}")

    own_ip, own_net = get_own_network()
    if own_ip and own_net:
        clauses.append(
            f"(src host {own_ip} and not dst net {own_net}) or "
            f"(dst host {own_ip} and not src net {own_net})"
        )
    else:
        # Couldn't determine our own LAN — fall back to excluding just the
        # Ollama host's resolved IP (misses other edge IPs a CDN-fronted
        # tunnel might rotate through, but better than nothing).
        parsed = urlparse(ollama_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if host and host not in ("localhost", "127.0.0.1"):
            try:
                ip = socket.gethostbyname(host)
                clauses.append(f"(host {ip} and port {port})")
            except socket.gaierror:
                # FIX: this must go to stderr, not stdout. Both callers
                # (print_capture_filter.py's own final print(), and
                # start_capture.sh/start_suricata.sh's `$(...)` capture of
                # its stdout) treat this function's return value as the
                # literal BPF filter text. A stdout warning here would get
                # concatenated into that string, handing tcpdump/Suricata
                # an invalid filter — in the rare case this fallback branch
                # fires (own LAN undetectable AND Ollama host unresolvable),
                # the previous behavior would have silently broken exactly
                # the self-exclusion filter this module exists to provide.
                print(f"  ⚠ Could not resolve Ollama host '{host}' to exclude it from capture",
                      file=sys.stderr)
        elif host in ("localhost", "127.0.0.1") and port:
            clauses.append(f"port {port}")

    for extra in (extra_excludes or []):
        clauses.append(extra)

    return "not (" + " or ".join(clauses) + ")"
